//! 主动核查执行器。
//!
//! 被动审计有原理性盲区：「上游是否把本次数据存下来、在**别的请求**里回吐」
//! 在单次响应里看不到，只能主动注入随机标记再发独立请求验证。
//!
//! 流程：[`aiguard_core::inspect::build_check_plan`] 生成计划 → 分波执行——
//! seed 先行（verify 依赖它注册的 nonce），其余步骤**并发**（限流 [`PROBE_CONCURRENCY`]）
//! 经**真实代理路径**发出（curl --proxy 指向本地 MITM 端口，绝不旁路）→ 响应侧
//! 自动还原/审计、按 `probe_id` 归集 → step8 主动回显比对 → 风险矩阵 →
//! Markdown 报告落盘。
//!
//! 并发是刻意设计：真实 AI 客户端在模型并行调用多个工具后本来就是并发发请求的；
//! 多轮核查也允许并发，若上游在并发压力下把 A 轮的 nonce 吐进 B 轮的响应，
//! 那正是要抓的记忆残留。
//!
//! 关键语义：**「没测到」≠「没问题」**。语义依赖成功响应的步骤（seed/verify/
//! toolcall/stream/web3）若收到 4xx/5xx（如缺凭据的 401），视为**无有效回执**，
//! 不建 key —— 让矩阵判定 INCONCLUSIVE，而不是把 401 响应"没有异常"读成健康。
//! step9_error 的错误触发器本身就是测量错误响应的，4xx/5xx 是它的有效回执。

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use aiguard_core::audit::{short_hash, Finding, Severity};
use aiguard_core::inspect::{
    aggregate_matrix, build_check_plan, render_markdown_report, steps_of, CheckProfile, CheckStep,
    RiskMatrix,
};
use futures::StreamExt;
use serde::Serialize;

use crate::state::{safe_err, AppState, FindingMeta};

/// 并发上限：无依赖的核查步骤并行发出（真实 AI 客户端在模型并行调用多个工具后
/// 本来就会并发发请求），但突发太高会触发渠道限速 / 被上游当成攻击。
const PROBE_CONCURRENCY: usize = 6;

/// 单步执行结果。
#[derive(Debug, Clone, Serialize)]
pub struct LinkCheckStep {
    pub step: String,
    pub probe_id: String,
    pub status: u16,
    /// 是否构成有效回执（参与矩阵的"已覆盖"判定）
    pub valid_receipt: bool,
    pub note: String,
}

/// 一轮核查的完整结果。
#[derive(Debug, Clone, Serialize)]
pub struct LinkCheckResult {
    pub matrix: RiskMatrix,
    pub steps: Vec<LinkCheckStep>,
    /// Markdown 报告全文（前端可直接预览）
    pub report: String,
    /// 报告落盘路径
    pub report_path: String,
    pub total: usize,
    /// 无有效回执的步骤数
    pub failed: usize,
}

/// 执行一轮核查扫描。
///
/// **并行执行**：只有 `step3_seed` 必须先行（verify 要靠它注册的 nonce 判定），
/// 其余步骤相互独立、全部并发发出——真实 AI 客户端在模型并行调用多个工具后
/// 本来就是并发发请求的，串行核查既慢、也测不出并发下的会话与审计正确性。
/// 多轮核查同样允许并发：各轮按各自的 `probe_id` 归集，互不干扰；若上游真的
/// 在并发压力下把 A 轮的 nonce 吐进 B 轮的响应，那正是要抓的记忆残留。
///
/// 签名全 owned：整条 future 是 `'static`（并发 Future + Tauri 命令宏都要求）。
pub async fn run_link_check(
    state: std::sync::Arc<AppState>,
    target_host: String,
    path: String,
    model: String,
    profile: String,
    auth_header: Option<String>,
) -> Result<LinkCheckResult, String> {
    let host = normalize_host(&target_host);
    if host.is_empty() {
        return Err("探测目标域名不能为空".to_string());
    }
    let prof = match profile.as_str() {
        "web3" => CheckProfile::Web3,
        "full" => CheckProfile::Full,
        _ => CheckProfile::General,
    };
    let plan = build_check_plan(&model, &path, prof);
    if plan.is_empty() {
        return Err("核查计划为空".to_string());
    }

    let port = match state.config.read() {
        Ok(c) => c.proxy_port,
        Err(poisoned) => poisoned.into_inner().proxy_port,
    };
    let proxy_addr = format!("http://127.0.0.1:{}", port);
    let auth = auth_header.unwrap_or_default().trim().to_string();

    // 分波执行：seed 先行（串行 1 条），其余并发
    let (seeds, rest) = partition_plan(&plan);
    let mut results: Vec<LinkCheckStep> = Vec::new();
    for step in &seeds {
        results.push(run_step(&state, step, &host, &proxy_addr, &auth).await);
    }
    results.extend(
        run_steps_concurrent(state.clone(), rest, host.clone(), proxy_addr.clone(), auth.clone())
            .await,
    );

    // 并发完成顺序不定：按计划顺序重排，保证前端展示稳定
    let order: HashMap<&str, usize> = plan
        .iter()
        .enumerate()
        .map(|(i, p)| (p.probe_id.as_str(), i))
        .collect();
    results.sort_by_key(|r| order.get(r.probe_id.as_str()).copied().unwrap_or(usize::MAX));

    // 等写线程把核查产生的审计事件落库（批量窗口 50ms，留足余量）
    tokio::time::sleep(Duration::from_millis(900)).await;

    // 归集：audit_events 里带本计划 probe_id 的发现
    let ids: HashSet<&str> = plan.iter().map(|p| p.probe_id.as_str()).collect();
    let evs = state.store.fetch_audit_events(0, 1000, None, None)?;
    let mut by_probe: HashMap<String, Vec<Finding>> = HashMap::new();
    for ev in evs {
        if ids.contains(ev.probe_id.as_str()) {
            let sev = Severity::parse(&ev.severity).unwrap_or(Severity::Low);
            by_probe
                .entry(ev.probe_id.clone())
                .or_default()
                .push(Finding::new(&ev.signal_type, sev, &ev.evidence, "probe_auto"));
        }
    }

    // 有效回执集合
    let sent: HashSet<String> = results
        .iter()
        .filter(|r| r.valid_receipt)
        .map(|r| r.probe_id.clone())
        .collect();

    let mut by_step: HashMap<String, Vec<Finding>> = HashMap::new();
    for item in &plan {
        if !sent.contains(&item.probe_id) {
            continue;
        }
        by_step
            .entry(item.step.clone())
            .or_default()
            .extend(by_probe.remove(&item.probe_id).unwrap_or_default());
    }

    let expected = steps_of(&plan);
    let matrix = aggregate_matrix(&by_step, &expected);

    // 报告落盘（core::render_markdown_report 已对自由文本二次脱敏）
    let generated_at = local_time_string();
    let report = render_markdown_report(&host, &model, &matrix, &by_step, &generated_at);
    let fname = aiguard_core::inspect::report_file_name(&generated_at.replace([' ', ':'], "_"));
    let report_path = state.data_dir.join(&fname);
    // 带 UTF-8 BOM 落盘：正文是中文 Markdown，报告通常被用户双击用记事本 / WPS 打开，
    // 无 BOM 时部分 Windows 编辑器会按系统代码页猜测（中文变乱码）。
    let mut report_bytes = Vec::with_capacity(report.len() + 3);
    report_bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    report_bytes.extend_from_slice(report.as_bytes());
    std::fs::write(&report_path, &report_bytes).map_err(|e| safe_err(&e))?;

    let failed = results.iter().filter(|r| !r.valid_receipt).count();
    Ok(LinkCheckResult {
        matrix,
        steps: results,
        report,
        report_path: report_path.display().to_string(),
        total: plan.len(),
        failed,
    })
}

/// 执行单个核查步骤。
async fn run_step(
    state: &std::sync::Arc<AppState>,
    step: &CheckStep,
    target_host: &str,
    proxy_addr: &str,
    auth_header: &str,
) -> LinkCheckStep {
    // 请求头：内容类型 + 核查内部头（MITM 注册后剥离）+ 步骤自带头
    let mut headers: Vec<(String, String)> = vec![
        ("content-type".to_string(), "application/json".to_string()),
        (
            aiguard_core::inspect::MARKER_HEADER.to_string(),
            step.nonces.join(","),
        ),
        (
            aiguard_core::inspect::CHECK_HEADER.to_string(),
            step.probe_id.clone(),
        ),
    ];
    let mut path = step.path.clone();
    let mut step_has_auth = false;
    for (k, v) in &step.headers {
        match k.as_str() {
            "_path_override" => path = v.clone(),
            "authorization" | "x-api-key" => {
                step_has_auth = true;
                headers.push((k.clone(), v.clone()));
            }
            _ => headers.push((k.clone(), v.clone())),
        }
    }
    // 全局凭据：仅当步骤没有自带假凭据（auth_check 的意义就是注入假 key）时附加
    if !step_has_auth && !auth_header.is_empty() {
        headers.push(("authorization".to_string(), auth_header.to_string()));
    }

    let url = format!("https://{}{}", target_host, path);
    let (status, body) = match curl_post(&url, &step.body, &headers, proxy_addr, 25).await {
        Ok(x) => x,
        Err(e) => {
            return LinkCheckStep {
                step: step.step.clone(),
                probe_id: step.probe_id.clone(),
                status: 0,
                valid_receipt: false,
                note: format!("发送失败: {}", safe_err(&e)),
            };
        }
    };

    // step9_error 的测量对象就是错误响应，其余步骤语义依赖成功响应
    let expect_success = step.step != "step9_error";
    let valid_receipt = if expect_success { status < 400 } else { true };

    // step8：主动回显比对（响应侧不知道期望值，必须由执行器比对）
    if step.step == "step8_toolcall" && valid_receipt {
        if let Some(expected) = &step.expected {
            let findings = aiguard_core::audit::scan_tool_call_rewrite(expected, &body);
            if !findings.is_empty() {
                let meta = FindingMeta {
                    sid: format!("check:{}", step.probe_id),
                    host: target_host.to_string(),
                    method: "POST".to_string(),
                    path: path.clone(),
                    request_hash: short_hash(&step.body),
                    response_hash: short_hash(&body),
                    probe_id: step.probe_id.clone(),
                };
                state.record_findings(findings, &meta);
            }
        }
    }

    let note = if valid_receipt {
        format!("HTTP {}", status)
    } else {
        format!("HTTP {}（依赖成功响应，视为无回执）", status)
    };
    LinkCheckStep {
        step: step.step.clone(),
        probe_id: step.probe_id.clone(),
        status,
        valid_receipt,
        note,
    }
}

/// 用系统 curl 经本地代理发一个 POST（CONNECT + TLS 全由 curl 处理；
/// `-k` 跳过自签 CA 校验——MITM 证书本就是本地生成的）。
async fn curl_post(
    url: &str,
    body: &str,
    headers: &[(String, String)],
    proxy_addr: &str,
    timeout_secs: u64,
) -> Result<(u16, String), String> {
    let tmp = std::env::temp_dir().join(format!(
        "aiguard_probe_body_{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::write(&tmp, body.as_bytes()).map_err(|e| safe_err(&e))?;

    let mut cmd = std::process::Command::new(curl_command_name());
    cmd.arg("-s")
        .arg("-k")
        .arg("--proxy")
        .arg(proxy_addr)
        .arg("--max-time")
        .arg(timeout_secs.to_string())
        .arg("-X")
        .arg("POST")
        .arg("--data-binary")
        .arg(format!("@{}", tmp.display()))
        // 末行附 HTTP 状态码，便于与响应体分离
        .arg("-w")
        .arg("\n%{http_code}")
        .arg(url);
    for (k, v) in headers {
        cmd.arg("-H").arg(format!("{}: {}", k, v));
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW：主动核查绝不闪黑窗
    }

    let out = tokio::task::spawn_blocking(move || cmd.output())
        .await
        .map_err(|e| safe_err(&e))?
        // spawn 失败（典型：系统没装 curl）时裸 io error 不可读，包一层说明依赖
        .map_err(|e| curl_spawn_err(&e))?;

    let _ = std::fs::remove_file(&tmp);

    // 响应体按 UTF-8 有损解码（HTTP 正文可能就是非 UTF-8 二进制，不能按系统代码页解）；
    // curl 自身的报错文案走控制台代码页解码。
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr: String = crate::console::decode_console(&out.stderr)
        .trim()
        .chars()
        .take(160)
        .collect();
    let (body, code_str) = match stdout.rfind('\n') {
        Some(i) => (stdout[..i].to_string(), stdout[i + 1..].trim().to_string()),
        None => (stdout.clone(), String::new()),
    };
    let status: u16 = code_str.parse().unwrap_or(0);
    if status == 0 {
        // 连不上代理 / 代理拒绝 / TLS 全挂：没有回执
        let msg = if stderr.is_empty() {
            format!("curl exit={}", out.status)
        } else {
            stderr
        };
        return Err(msg);
    }
    Ok((status, body))
}

/// 主动核查发出的请求由系统 curl 执行：Windows 用系统自带的 curl.exe
/// （Win10 1803+ 在 System32 自带），其余平台走 PATH 里的 curl——
/// macOS / Linux 上没有 curl.exe，硬编码会让主动核查在非 Windows 平台必然失败。
fn curl_command_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "curl.exe"
    } else {
        "curl"
    }
}

/// 执行系统 curl 的 io 失败包装：裸 io error（如 "program not found"）看不出
/// 与主动核查的关系，包一层说明「主动核查依赖系统 PATH 中的 curl」。
fn curl_spawn_err(e: &std::io::Error) -> String {
    format!(
        "启动系统 curl 失败（{}）。主动核查依赖系统 PATH 中的 curl 命令发送核查请求，请确认已安装 curl 并可在终端直接运行",
        safe_err(e)
    )
}

/// 归一化目标域名：去 scheme、去路径、去端口、转小写。
fn normalize_host(input: &str) -> String {
    let s = input.trim().to_lowercase();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(&s);
    s.split(['/', '?', ':']).next().unwrap_or("").to_string()
}

/// 把计划分成两波：必须先行的 seed（verify 的判定依赖它注册的 nonce）与其余可并发的步骤。
fn partition_plan(plan: &[CheckStep]) -> (Vec<CheckStep>, Vec<CheckStep>) {
    let mut seeds = Vec::new();
    let mut rest = Vec::new();
    for step in plan {
        if step.step == "step3_seed" {
            seeds.push(step.clone());
        } else {
            rest.push(step.clone());
        }
    }
    (seeds, rest)
}

/// 并发执行一批相互独立的核查步骤。
///
/// 全 owned 签名（Item = `CheckStep` 而非 `&CheckStep`）：闭包参数一旦是引用，
/// HRTB 推导会退化（"FnOnce is not general enough"，Tauri 命令宏处报错）；
/// owned 数据让每个并发 Future 天然 `'static`。
async fn run_steps_concurrent(
    state: std::sync::Arc<AppState>,
    steps: Vec<CheckStep>,
    host: String,
    proxy_addr: String,
    auth: String,
) -> Vec<LinkCheckStep> {
    futures::stream::iter(steps)
        .map(move |step| {
            let state = state.clone();
            let host = host.clone();
            let proxy_addr = proxy_addr.clone();
            let auth = auth.clone();
            async move { run_step(&state, &step, &host, &proxy_addr, &auth).await }
        })
        .buffer_unordered(PROBE_CONCURRENCY)
        .collect()
        .await
}

/// 本地时间字符串（UTC；civil_from_days 算法，零依赖）。
fn local_time_string() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y, mo, d, h, m, s
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiguard_core::inspect::CheckProfile;

    #[test]
    fn test_curl_command_name_platform() {
        // Windows 走 System32 自带的 curl.exe；其余平台走 PATH 里的 curl
        if cfg!(target_os = "windows") {
            assert_eq!(curl_command_name(), "curl.exe");
        } else {
            assert_eq!(curl_command_name(), "curl");
        }
    }

    #[test]
    fn test_normalize_host() {
        assert_eq!(normalize_host("api.openai.com"), "api.openai.com");
        assert_eq!(normalize_host("https://api.openai.com/v1"), "api.openai.com");
        assert_eq!(normalize_host("API.DeepSeek.COM:443"), "api.deepseek.com");
        assert_eq!(normalize_host("http://x.cn/path?q=1"), "x.cn");
        assert_eq!(normalize_host(""), "");
    }

    #[test]
    fn test_local_time_shape() {
        let t = local_time_string();
        // 2026-01-01 00:00:00 之后的产物：长度与分隔符形态固定
        assert_eq!(t.len(), 19);
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[10..11], " ");
    }

    #[test]
    fn test_partition_plan_seeds_first() {
        let plan = build_check_plan("m", "/v1/chat/completions", CheckProfile::Full);
        let (seeds, rest) = partition_plan(&plan);
        // seed 只有 1 条，其余全部可并发
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].step, "step3_seed");
        assert_eq!(seeds.len() + rest.len(), plan.len());
        // rest 不含任何 seed
        assert!(rest.iter().all(|s| s.step != "step3_seed"));
        // rest 里包含 verify（它在 seed 之后即可，与 toolcall/error/stream 无依赖）
        assert!(rest.iter().any(|s| s.step == "step3_verify"));
        assert!(rest.iter().any(|s| s.step == "step8_toolcall"));
        assert!(rest.iter().any(|s| s.step == "step11_web3"));
    }
}
