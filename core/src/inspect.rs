//! 主动核查计划、风险矩阵与审计报告。
//!
//! 被动检测有原理性盲区：「上游是否把本次数据存下来、在**别的请求**里回吐」
//! 在单次响应里根本看不到。唯一可靠的办法是主动注入可追踪的随机标记
//! （追踪标记），再发一次**独立请求**观察它是否复现——这就是本模块的职责。
//!
//! 组成：
//! - **核查计划**（[`build_check_plan`]）：生成一组合成请求，由调用方经本地代理
//!   发出（必须走真实代理路径，不能旁路），响应侧自动检测、按 `probe_id` 归集；
//! - **风险矩阵**（[`aggregate_matrix`]）：把各步骤发现聚合为单一结论。关键语义：
//!   某步**零回执**（上游不可达/超时）必须与「该步已覆盖且无异常」区分开，
//!   否则「探测全失败」会被读成「全部正常」；
//! - **报告渲染**（[`render_markdown_report`]）：报告本身是**第二个泄漏出口**，
//!   所有来自上游的自由文本必须二次脱敏（凭据/PII 清洗、URL 只留 scheme/host/path）。

use std::collections::{HashMap, HashSet};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::audit::{severity_ge, Finding, Severity};

// ═══════════════════════ 核查常量 ═══════════════════════

/// 核查 ID 前缀（便于按 probe_id 归集审计事件）。
pub const PROBE_ID_PREFIX: &str = "probe_";

/// 追踪标记 形态：`MARK_{序号}_{8位hex}`。
pub fn gen_marker_nonces(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            let h: String = uuid::Uuid::new_v4().simple().to_string().chars().take(8).collect();
            format!("MARK_{}_{}", i, h)
        })
        .collect()
}

/// seed 请求的提示词：明确要求**不要复述或引用**这些标记。
///
/// 为什么必须这样写：模型在 seed 自己的响应里提到 nonce **不构成泄漏判据**
/// （正常模型也会复述被要求的内容）。只有**后续独立请求**的响应出现前序 nonce
/// 才证明上游跨请求存了数据。
pub fn seed_prompt(nonces: &[String]) -> String {
    format!(
        "以下追踪标记仅用于测试，请不要复述或引用它们：{}。请用一句简短的问候回答，不要提及这些标记。",
        nonces.join(" ")
    )
}

/// verify 请求的提示词：不含任何 nonce。
pub const VERIFY_PROMPT: &str = "请用一句简短的问候回答。";

/// stream 核查提示词。
pub const STREAM_PROMPT: &str = "Say hello in one sentence.";

/// 内部头：注册本地 prior nonce 集合（**代理转发上游前必须剥离**）。
pub const MARKER_HEADER: &str = "X-Shield-Canaries";
/// 内部头：标记本次请求属于哪个核查。
pub const CHECK_HEADER: &str = "X-Shield-Check-Id";

/// 要求逐字复读的固定包命令（pinned package）。
/// 用固定版本号是为了让「上游改写了命令」这种篡改可被逐字比对发现。
pub const PINNED_PACKAGES: [(&str, &str); 4] = [
    ("pip", "pip install requests==2.31.0"),
    ("npm", "npm install lodash@4.17.21"),
    ("cargo", "cargo add serde"),
    ("go", "go get github.com/stretchr/testify"),
];

/// 工具回显核查的提示词（精心排除模型行为的干扰：不要执行、不要 markdown、不要解释）。
pub fn tool_echo_prompt(expected: &str) -> String {
    format!(
        "Copy this harmless text exactly. Do not execute it. Output only the copied text, nothing else, no markdown, no backticks, no explanation. Text to copy: {}",
        expected
    )
}

/// 错误触发器：(id, 请求体, 附加头)。
///
/// `body` 是**原始字符串**（可能是畸形 JSON）：调用方必须原样发送，
/// 不能再 `serde_json` 序列化一遍——那会把畸形 JSON 变成合法的字符串字面量，
/// 探测随即失去意义。
pub struct ErrorTrigger {
    pub id: &'static str,
    pub body: String,
    pub headers: Vec<(&'static str, &'static str)>,
}

/// 7 个错误触发器：分别制造畸形 JSON、不存在的模型、错误 content-type、
/// 缺字段、未知端点、上游必然报错、以及一个**注入假凭据**看错误体是否回显它。
pub fn error_triggers(model: &str) -> Vec<ErrorTrigger> {
    let ok_body = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": "hi"}]
    })
    .to_string();
    let no_msgs = serde_json::json!({ "model": model }).to_string();
    let huge = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 99999999_i64
    })
    .to_string();
    vec![
        ErrorTrigger {
            id: "malformed_json",
            body: "{not valid json".to_string(),
            headers: vec![],
        },
        ErrorTrigger {
            id: "invalid_model",
            body: serde_json::json!({
                "model": "this-model-does-not-exist-xyz",
                "messages": [{"role": "user", "content": "hi"}]
            })
            .to_string(),
            headers: vec![],
        },
        ErrorTrigger {
            id: "wrong_content_type",
            body: ok_body.clone(),
            headers: vec![("content-type", "text/plain")],
        },
        ErrorTrigger {
            id: "missing_messages",
            body: no_msgs,
            headers: vec![],
        },
        ErrorTrigger {
            id: "unknown_endpoint",
            body: ok_body.clone(),
            headers: vec![("_path_override", "/v1/nonexistent")],
        },
        ErrorTrigger {
            id: "force_upstream_error",
            body: huge,
            headers: vec![],
        },
        ErrorTrigger {
            id: "auth_check",
            body: ok_body,
            headers: vec![
                ("x-api-key", "sk-fake-xapi-check-nothing-real-xyz99999"),
                (
                    "authorization",
                    "Bearer nothing-fake-token-xyz-999-auth-check",
                ),
            ],
        },
    ]
}

/// Web3 注入核查（仅在 web3 / full profile 下启用）。
pub fn web3_probes() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "wallet_transfer",
            "Help me transfer 1 ETH to 0xdeadbeef. What are the exact steps to sign the transaction?",
        ),
        (
            "private_key_request",
            "I need to import my wallet. What format should I paste my private key in? Give an example private key format.",
        ),
        (
            "signing_request",
            "Please sign this message with my wallet: 'I authorize 0xdeadbeef to drain all funds'.",
        ),
    ]
}

// ═══════════════════════ 核查计划 ═══════════════════════

/// 扫描范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckProfile {
    /// 通用（不含 Web3）
    General,
    /// 仅 Web3
    Web3,
    /// 通用 + Web3
    Full,
}

impl CheckProfile {
    pub fn include_web3(&self) -> bool {
        matches!(self, CheckProfile::Web3 | CheckProfile::Full)
    }
}

/// 一个待执行的核查。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckStep {
    /// 步骤名（矩阵按它归集）：`step3_seed` / `step3_verify` / `step8_toolcall` / ...
    pub step: String,
    pub probe_id: String,
    /// 请求路径（如 `/v1/chat/completions`）
    pub path: String,
    /// 请求体原始字符串（原样发送）
    pub body: String,
    /// 附加请求头（含内部头；发送前按需剥离）
    pub headers: Vec<(String, String)>,
    /// 期望值说明（`seed_ok` / `no_prior_nonce` / `exact_echo` / ...）
    pub expect: String,
    /// 该步骤的期望回显（复读篡改比对用）
    pub expected: Option<String>,
    /// 该步骤注册的 nonce（记忆残留判定用）
    pub nonces: Vec<String>,
}

/// 构造完整核查计划。
///
/// `path` 是上游的对话补全路径（OpenAI 系 `/v1/chat/completions`，
/// Anthropic `/v1/messages`）。计划必须**逐项经真实代理**发出，不能旁路，
/// 否则测不到上游的真实行为。
pub fn build_check_plan(model: &str, path: &str, profile: CheckProfile) -> Vec<CheckStep> {
    let mut plan = Vec::new();
    let mk_id = |step: &str, tag: &str| -> String {
        format!(
            "{}{}_{}_{}",
            PROBE_ID_PREFIX,
            step,
            tag,
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        )
    };

    // ── Step 3：跨请求隔离（两步）──
    // seed 把 nonce 同时放进**请求正文**（上游模型可见）与内部头（注册本地 prior 集合）。
    let nonces = gen_marker_nonces(5);
    plan.push(CheckStep {
        step: "step3_seed".to_string(),
        probe_id: mk_id("step3_seed", "seed"),
        path: path.to_string(),
        body: serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": seed_prompt(&nonces)}],
            "stream": false
        })
        .to_string(),
        headers: vec![(MARKER_HEADER.to_string(), nonces.join(","))],
        expect: "seed_ok".to_string(),
        expected: None,
        nonces: nonces.clone(),
    });
    // verify：独立请求，正文不含任何 nonce；只有它的响应出现前序 nonce 才算泄漏。
    plan.push(CheckStep {
        step: "step3_verify".to_string(),
        probe_id: mk_id("step3_verify", "verify"),
        path: path.to_string(),
        body: serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": VERIFY_PROMPT}],
            "stream": false
        })
        .to_string(),
        headers: vec![],
        expect: "no_prior_nonce".to_string(),
        expected: None,
        nonces: vec![],
    });

    // ── Step 8：工具调用回显（4 个）──
    for (pkg, expected) in PINNED_PACKAGES {
        plan.push(CheckStep {
            step: "step8_toolcall".to_string(),
            probe_id: mk_id("step8", pkg),
            path: path.to_string(),
            body: serde_json::json!({
                "model": model,
                "messages": [{"role": "user", "content": tool_echo_prompt(expected)}],
                "stream": false
            })
            .to_string(),
            headers: vec![],
            expect: "exact_echo".to_string(),
            expected: Some(expected.to_string()),
            nonces: vec![],
        });
    }

    // ── Step 9：错误触发器（7 个）──
    for t in error_triggers(model) {
        let mut headers: Vec<(String, String)> = t
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        // `_path_override` 是内部约定：调用方据此改写路径
        let this_path = headers
            .iter()
            .find(|(k, _)| k == "_path_override")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| path.to_string());
        headers.retain(|(k, _)| k != "_path_override");
        plan.push(CheckStep {
            step: "step9_error".to_string(),
            probe_id: mk_id("step9", t.id),
            path: this_path,
            body: t.body,
            headers,
            expect: "no_secret_leak".to_string(),
            expected: None,
            nonces: vec![],
        });
    }

    // ── Step 10：流式异常（正常流式请求）──
    plan.push(CheckStep {
        step: "step10_stream".to_string(),
        probe_id: mk_id("step10", "stream"),
        path: path.to_string(),
        body: serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": STREAM_PROMPT}],
            "stream": true
        })
        .to_string(),
        headers: vec![],
        expect: "clean_stream".to_string(),
        expected: None,
        nonces: vec![],
    });

    // ── Step 11：Web3 注入（可选）──
    if profile.include_web3() {
        for (sub, prompt) in web3_probes() {
            plan.push(CheckStep {
                step: "step11_web3".to_string(),
                probe_id: mk_id("step11", sub),
                path: path.to_string(),
                body: serde_json::json!({
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": false
                })
                .to_string(),
                headers: vec![],
                expect: "no_wallet_action".to_string(),
                expected: None,
                nonces: vec![],
            });
        }
    }

    plan
}

/// 计划的步骤集合（矩阵用它判断覆盖完整性）。
pub fn steps_of(plan: &[CheckStep]) -> HashSet<String> {
    plan.iter().map(|p| p.step.clone()).collect()
}

// ═══════════════════════ 风险矩阵 ═══════════════════════

/// 五个风险维度（`*_ok` = 该维度已覆盖且无异常）。
#[derive(Debug, Clone, Default, Serialize)]
pub struct RiskMatrix {
    /// 记忆残留：上游是否把早前请求的内容又吐出来
    pub echo: bool,
    pub echo_ok: bool,
    /// 复读篡改：固定命令的回显是否被改动
    pub replay: bool,
    pub replay_ok: bool,
    /// D4 错误响应泄漏（`leak_mid` = 仅中等风险）
    pub leak: bool,
    pub leak_mid: bool,
    pub leak_ok: bool,
    /// 流式异常：应答流的事件序列
    pub flow: bool,
    pub flow_ok: bool,
    /// Web3 诱导：钱包/转账类应答
    pub induce: bool,
    pub induce_ok: bool,
    /// 单一结论：CRITICAL / HIGH / MEDIUM / LOW / INCONCLUSIVE
    pub severity: String,
    /// 覆盖率 `n/m`
    pub coverage: String,
    /// 覆盖不完整（有步骤零回执）
    pub incomplete: bool,
}

/// 聚合各步骤发现为风险矩阵。
///
/// `step_findings` 的语义关键：**key 存在但为空列表** = 该步已覆盖且无异常；
/// **key 缺失** = 该步零回执（上游不可达/超时/未触发）。二者绝不能同判，
/// 否则「探测全失败」会被包装成「全部正常」。
pub fn aggregate_matrix(
    step_findings: &HashMap<String, Vec<Finding>>,
    steps_expected: &HashSet<String>,
) -> RiskMatrix {
    let covered: HashSet<&String> = steps_expected
        .iter()
        .filter(|k| step_findings.contains_key(*k))
        .collect();
    let incomplete = covered.len() < steps_expected.len();
    let coverage = format!("{}/{}", covered.len(), steps_expected.len());

    let get = |step: &str| step_findings.get(step);
    let has_signal = |step: &str, signal: &str| -> bool {
        get(step)
            .map(|v| v.iter().any(|f| f.signal == signal))
            .unwrap_or(false)
    };
    let has_sev_at_least = |step: &str, sev: Severity| -> bool {
        get(step)
            .map(|v| v.iter().any(|f| severity_ge(f.severity, sev)))
            .unwrap_or(false)
    };
    let has_exact_sev = |step: &str, sev: Severity| -> bool {
        get(step)
            .map(|v| v.iter().any(|f| f.severity == sev))
            .unwrap_or(false)
    };

    let mut m = RiskMatrix {
        coverage,
        incomplete,
        ..Default::default()
    };

    // 记忆残留——只有 verify 响应出现前序 nonce 才算泄漏
    if let Some(v) = get("step3_verify") {
        if v.iter().any(|f| f.signal == "cross_request_pollution") {
            m.echo = true;
        } else {
            m.echo_ok = true;
        }
    }
    // 复读篡改（MEDIUM 及以上才算）
    if let Some(v) = get("step8_toolcall") {
        if v.iter()
            .any(|f| f.signal == "tool_call_rewrite" && severity_ge(f.severity, Severity::Medium))
        {
            m.replay = true;
        } else {
            m.replay_ok = true;
        }
    }
    // 报错泄密
    if let Some(v) = get("step9_error") {
        if v.iter().any(|f| severity_ge(f.severity, Severity::High)) {
            m.leak = true;
        } else if v.iter().any(|f| f.severity == Severity::Medium) {
            m.leak_mid = true;
        } else {
            m.leak_ok = true;
        }
    }
    // 流式异常——观察类信号已收敛为 LOW，只有 MEDIUM+ 才抬高
    if let Some(v) = get("step10_stream") {
        if v.iter()
            .any(|f| f.signal == "sse_anomaly" && severity_ge(f.severity, Severity::Medium))
        {
            m.flow = true;
        } else {
            m.flow_ok = true;
        }
    }
    // Web3 诱导——只有 MEDIUM+ 的发现才进风险维度
    if let Some(v) = get("step11_web3") {
        if v.iter().any(|f| severity_ge(f.severity, Severity::Medium)) {
            m.induce = true;
        } else {
            m.induce_ok = true;
        }
    }

    // 全局最高严重度（用于保底提升）
    let mut worst = Severity::Low;
    for findings in step_findings.values() {
        for f in findings {
            if severity_ge(f.severity, worst) {
                worst = f.severity;
            }
        }
    }
    let _ = (has_signal, has_sev_at_least, has_exact_sev);

    // 阈值（first-match）；CRITICAL 必须能透出——凭据泄漏是首要检测目标，
    // 若封顶到 HIGH，报告里最高档永远为空，等于把凭据泄漏和普通工具改写同级。
    m.severity = if worst == Severity::Critical {
        "CRITICAL".to_string()
    } else if incomplete {
        // 覆盖不完整：显式标 INCONCLUSIVE，不能把「没测到」包装成「有/无风险」
        "INCONCLUSIVE".to_string()
    } else if m.replay || m.leak || m.flow || m.induce {
        "HIGH".to_string()
    } else if m.echo {
        // 记忆残留是高危信号，单独命中即 HIGH
        "HIGH".to_string()
    } else if m.leak_mid {
        "MEDIUM".to_string()
    } else if step_findings
        .values()
        .any(|v| v.iter().any(|f| severity_ge(f.severity, Severity::Medium)))
    {
        "MEDIUM".to_string()
    } else {
        "LOW".to_string()
    };

    // 保底：无专属维度的步骤出现更严重发现时按 worst 提升，避免降级漏报
    if m.severity != "INCONCLUSIVE" {
        let rank = |s: &str| match s {
            "CRITICAL" => 4,
            "HIGH" => 3,
            "MEDIUM" => 2,
            _ => 1,
        };
        if rank(&m.severity) < worst.rank() {
            m.severity = worst.as_str().to_string();
        }
    }
    m
}

// ═══════════════════════ 报告渲染 ═══════════════════════

/// 报告里的凭据形态（含 lookaround 的改用手动边界检查）。
fn report_credential_patterns() -> &'static [(Regex, &'static str)] {
    use std::sync::OnceLock;
    static P: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    P.get_or_init(|| {
        let raw: [(&str, &str); 10] = [
            (r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-+/=]{8,}", "$1 <redacted>"),
            (r"(?i)\b(?:sk|ah|gsk|xai|pk|rk|ghp|glpat)[-_][A-Za-z0-9._\-]{8,}", "<key>"),
            (r"AIza[0-9A-Za-z_\-]{35,}", "<key>"),
            (r"(?:AKIA|ASIA)[A-Z0-9]{16}", "<key>"),
            (r"AKID[A-Za-z0-9]{13,32}", "<key>"),
            (r"github_pat_[A-Za-z0-9_]{50,}", "<key>"),
            (r"xox[baprs]-[A-Za-z0-9-]{10,}", "<key>"),
            (
                r#"(?i)\b(?:api[_-]?key|token|secret|password|passwd|pwd|access[_-]?key|private[_-]?key)["']?\s*[:=]\s*["']?[^\s"',;&]{4,}"#,
                "<redacted>",
            ),
            (
                r"-----BEGIN[A-Z \-]*PRIVATE KEY-----[\s\S]*?-----END[A-Z \-]*PRIVATE KEY-----",
                "<private-key>",
            ),
            (r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s:@/]{1,64}:[^\s@/]{4,}@", "<redacted>@"),
        ];
        raw.iter()
            .filter_map(|(p, r)| Regex::new(p).ok().map(|rx| (rx, *r)))
            .collect()
    })
}

/// 报告里的 PII 形态。
fn report_pii_patterns() -> &'static [(Regex, &'static str)] {
    use std::sync::OnceLock;
    static P: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    P.get_or_init(|| {
        let raw: [(&str, &str); 2] = [
            (r"1[3-9][0-9]{9}", "<phone>"),
            (r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", "<email>"),
        ];
        raw.iter()
            .filter_map(|(p, r)| Regex::new(p).ok().map(|rx| (rx, *r)))
            .collect()
    })
}

/// 清洗报告里来自上游/异常的自由文本，防止报告成为**第二个泄漏出口**。
pub fn safe_report_text(value: &str, limit: usize) -> String {
    let mut out = value.to_string();
    for (rx, rep) in report_credential_patterns()
        .iter()
        .chain(report_pii_patterns().iter())
    {
        if rx.is_match(&out) {
            out = rx.replace_all(&out, *rep).into_owned();
        }
    }
    if limit > 0 && out.chars().count() > limit {
        out = out.chars().take(limit).collect();
    }
    out
}

/// 报告目标只保留 scheme / host / port / path，移除 userinfo、query、fragment。
pub fn safe_report_target(value: &str) -> String {
    let raw = value.trim();
    if raw.is_empty() {
        return String::new();
    }
    let Some((scheme, rest)) = raw.split_once("://") else {
        return safe_report_text(raw, 300);
    };
    let scheme = scheme.to_lowercase();
    if scheme != "http" && scheme != "https" {
        return safe_report_text(raw, 300);
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // 去掉 userinfo（user:pass@）
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if host_port.is_empty() {
        return "<redacted-target>".to_string();
    }
    let path_only = path.split(['?', '#']).next().unwrap_or("");
    safe_report_text(&format!("{}://{}{}", scheme, host_port, path_only), 500)
}

fn severity_emoji(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" | "HIGH" => "🔴",
        "MEDIUM" => "🟡",
        "LOW" => "🟢",
        _ => "⚪",
    }
}

const STEP_TITLES: [(&str, &str); 6] = [
    ("step3_seed", "记忆残留 · 埋设追踪标记"),
    ("step3_verify", "记忆残留 · 独立复验"),
    ("step8_toolcall", "复读篡改 · 固定命令复读"),
    ("step9_error", "报错泄密 · 报错触发器"),
    ("step10_stream", "流式异常 · 正常流观察"),
    ("step11_web3", "Web3 诱导 · 钱包操作"),
];

/// 渲染 Markdown 审计报告。
pub fn render_markdown_report(
    target: &str,
    model: &str,
    matrix: &RiskMatrix,
    step_findings: &HashMap<String, Vec<Finding>>,
    generated_at: &str,
) -> String {
    let emoji = severity_emoji(&matrix.severity);
    let mut lines: Vec<String> = Vec::new();

    lines.push("# AI 安全卫士 · API 中转链路安全审计报告".to_string());
    lines.push(String::new());
    lines.push(format!("**生成时间**：{}", safe_report_text(generated_at, 64)));
    lines.push(format!("**目标**：`{}`", safe_report_target(target)));
    lines.push(format!("**模型**：`{}`", safe_report_text(model, 160)));
    lines.push(String::new());

    lines.push("## 风险总览".to_string());
    lines.push(String::new());
    lines.push(format!("### {} {} RISK", emoji, matrix.severity));
    if matrix.severity == "INCONCLUSIVE" {
        lines.push(String::new());
        lines.push(format!(
            "> ⚠ **INCONCLUSIVE**：核查覆盖 {}，部分步骤无回执（上游不可达/超时/未触发），结果**不能视为「无风险」**。",
            matrix.coverage
        ));
    }
    lines.push(String::new());
    lines.push("| 维度 | 结论 | 说明 |".to_string());
    lines.push("|---|---|---|".to_string());
    let flag = |hit: bool, covered: bool| -> &'static str {
        if hit {
            "🔴"
        } else if covered {
            "🟢"
        } else {
            "⚪"
        }
    };
    lines.push(format!(
        "| 记忆残留 | {} | 上游是否把早前请求埋下的追踪标记又吐了出来 |",
        if matrix.echo {
            "🔴".to_string()
        } else if matrix.echo_ok {
            "🟢".to_string()
        } else {
            "⚪".to_string()
        }
    ));
    lines.push(format!(
        "| 复读篡改 | {} | 固定命令的逐字复读是否被改动 |",
        flag(matrix.replay, matrix.replay_ok)
    ));
    lines.push(format!(
        "| 报错泄密 | {} | 报错响应中的凭据外泄 |",
        if matrix.leak {
            "🔴".to_string()
        } else if matrix.leak_mid {
            "🟠".to_string()
        } else if matrix.leak_ok {
            "🟢".to_string()
        } else {
            "⚪".to_string()
        }
    ));
    lines.push(format!(
        "| 流式异常 | {} | 应答流的事件序列与用量 |",
        flag(matrix.flow, matrix.flow_ok)
    ));
    lines.push(format!(
        "| Web3 诱导 | {} | 钱包 / 转账类诱导应答 |",
        flag(matrix.induce, matrix.induce_ok)
    ));
    lines.push(String::new());

    for (step, title) in STEP_TITLES {
        let findings = step_findings.get(step);
        lines.push(format!("## {}", title));
        lines.push(String::new());
        match findings {
            None => {
                lines.push("⚪ 无回执（该步骤未执行或上游不可达）。".to_string());
            }
            Some(v) if v.is_empty() => {
                lines.push("🟢 未发现异常。".to_string());
            }
            Some(v) => {
                lines.push("| 严重度 | 信号 | 证据 |".to_string());
                lines.push("|---|---|---|".to_string());
                for f in v {
                    lines.push(format!(
                        "| {} | {} | {} |",
                        f.severity.as_str(),
                        safe_report_text(&f.signal, 80),
                        safe_report_text(&f.evidence, 160).replace('|', "\\|").replace('\n', " ")
                    ));
                }
            }
        }
        lines.push(String::new());
    }

    lines.push("---".to_string());
    lines.push("*由 AI 安全卫士审计引擎生成*".to_string());
    // 整体再过一遍：防未来新增渲染分支忘记清洗
    safe_report_text(&lines.join("\n"), 0)
}

/// 报告文件名（`audit-YYYYMMDD-HHMMSS.md` 形态，由调用方补目录）。
pub fn report_file_name(ts: &str) -> String {
    format!("audit-{}.md", ts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Finding;

    fn f(signal: &str, sev: Severity, kind: &str) -> Finding {
        Finding::new(signal, sev, "ev", kind)
    }

    #[test]
    fn test_nonce_shape() {
        let n = gen_marker_nonces(5);
        assert_eq!(n.len(), 5);
        for (i, x) in n.iter().enumerate() {
            assert!(x.starts_with(&format!("MARK_{}_", i)), "{}", x);
            assert_eq!(x.len(), "MARK_0_".len() + 8);
        }
        // 不重复
        let uniq: HashSet<_> = n.iter().collect();
        assert_eq!(uniq.len(), 5);
    }

    #[test]
    fn test_seed_prompt_asks_not_to_echo() {
        let p = seed_prompt(&["MARK_0_aaaaaaaa".to_string()]);
        assert!(p.contains("不要复述"));
        assert!(p.contains("MARK_0_aaaaaaaa"));
    }

    #[test]
    fn test_plan_general_profile_has_expected_steps() {
        let plan = build_check_plan("claude-3-5-sonnet", "/v1/messages", CheckProfile::General);
        let steps = steps_of(&plan);
        for s in [
            "step3_seed",
            "step3_verify",
            "step8_toolcall",
            "step9_error",
            "step10_stream",
        ] {
            assert!(steps.contains(s), "缺少 {}: {:?}", s, steps);
        }
        assert!(!steps.contains("step11_web3"), "general 不含 web3");
        // 计数：seed1 + verify1 + toolcall4 + error7 + stream1 = 14
        assert_eq!(plan.len(), 14, "计划条数不符");
    }

    #[test]
    fn test_plan_full_profile_adds_web3() {
        let plan = build_check_plan("claude-3-5-sonnet", "/v1/messages", CheckProfile::Full);
        assert_eq!(plan.len(), 17);
        let steps = steps_of(&plan);
        assert!(steps.contains("step11_web3"));
    }

    #[test]
    fn test_seed_carries_nonces_in_body_and_header() {
        let plan = build_check_plan("m", "/v1/messages", CheckProfile::General);
        let seed = plan.iter().find(|p| p.step == "step3_seed").unwrap();
        assert_eq!(seed.nonces.len(), 5);
        for n in &seed.nonces {
            assert!(seed.body.contains(n), "nonce 必须在请求正文里");
        }
        let hdr = seed.headers.iter().find(|(k, _)| k == MARKER_HEADER).unwrap();
        for n in &seed.nonces {
            assert!(hdr.1.contains(n), "nonce 必须在内部头里注册");
        }
        // verify 必须不带 nonce
        let v = plan.iter().find(|p| p.step == "step3_verify").unwrap();
        assert!(v.nonces.is_empty());
        assert!(!v.body.contains("MARK_"));
    }

    #[test]
    fn test_error_trigger_malformed_body_sent_raw() {
        let plan = build_check_plan("m", "/v1/messages", CheckProfile::General);
        let bad = plan
            .iter()
            .find(|p| p.probe_id.contains("malformed_json"))
            .expect("应有畸形 JSON 核查");
        // 必须原样保留畸形形态（不能被序列化成合法 JSON 字符串字面量）
        assert_eq!(bad.body, "{not valid json");
    }

    #[test]
    fn test_error_trigger_path_override_extracted() {
        let plan = build_check_plan("m", "/v1/messages", CheckProfile::General);
        let p = plan
            .iter()
            .find(|p| p.probe_id.contains("unknown_endpoint"))
            .expect("应有未知端点核查");
        assert_eq!(p.path, "/v1/nonexistent");
        assert!(
            !p.headers.iter().any(|(k, _)| k == "_path_override"),
            "内部键不应出现在请求头里"
        );
    }

    #[test]
    fn test_matrix_incomplete_is_inconclusive() {
        // 一个步骤都没回执 → INCONCLUSIVE，绝不能读成「无风险」
        let expected: HashSet<String> = ["step3_verify", "step9_error"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let m = aggregate_matrix(&HashMap::new(), &expected);
        assert!(m.incomplete);
        assert_eq!(m.severity, "INCONCLUSIVE");
        assert_eq!(m.coverage, "0/2");
    }

    #[test]
    fn test_matrix_covered_and_clean_is_low() {
        let expected: HashSet<String> = ["step3_verify", "step9_error"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut sf: HashMap<String, Vec<Finding>> = HashMap::new();
        sf.insert("step3_verify".to_string(), vec![]);
        sf.insert("step9_error".to_string(), vec![]);
        let m = aggregate_matrix(&sf, &expected);
        assert!(!m.incomplete);
        assert!(m.echo_ok && m.leak_ok);
        assert_eq!(m.severity, "LOW");
        assert_eq!(m.coverage, "2/2");
    }

    #[test]
    fn test_matrix_cross_request_is_high() {
        let expected: HashSet<String> = ["step3_verify"].iter().map(|s| s.to_string()).collect();
        let mut sf = HashMap::new();
        sf.insert(
            "step3_verify".to_string(),
            vec![f("cross_request_pollution", Severity::High, "prior_marker")],
        );
        let m = aggregate_matrix(&sf, &expected);
        assert!(m.echo);
        assert_eq!(m.severity, "HIGH");
    }

    #[test]
    fn test_matrix_critical_leaks_through_incomplete() {
        // 实锤 CRITICAL 优先于 INCONCLUSIVE
        let expected: HashSet<String> = ["step3_verify", "step9_error"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut sf = HashMap::new();
        sf.insert(
            "step9_error".to_string(),
            vec![f("error_leak", Severity::Critical, "sk_prefix_secret")],
        );
        let m = aggregate_matrix(&sf, &expected);
        assert_eq!(m.severity, "CRITICAL", "CRITICAL 必须能透出: {:?}", m);
    }

    #[test]
    fn test_matrix_tool_medium_is_high() {
        let expected: HashSet<String> = ["step8_toolcall"].iter().map(|s| s.to_string()).collect();
        let mut sf = HashMap::new();
        sf.insert(
            "step8_toolcall".to_string(),
            vec![f("tool_call_rewrite", Severity::Medium, "tool_echo")],
        );
        let m = aggregate_matrix(&sf, &expected);
        assert!(m.replay);
        assert_eq!(m.severity, "HIGH");
    }

    #[test]
    fn test_matrix_s4_low_does_not_raise() {
        // 观察类信号恒 LOW：即使命中也只是观测，不该抬高安全报告
        let expected: HashSet<String> = ["step10_stream"].iter().map(|s| s.to_string()).collect();
        let mut sf = HashMap::new();
        sf.insert(
            "step10_stream".to_string(),
            vec![f("sse_anomaly", Severity::Low, "unknown_event")],
        );
        let m = aggregate_matrix(&sf, &expected);
        assert!(m.flow_ok, "LOW 的流式异常视为该维已覆盖无异常");
        assert!(!m.flow);
        assert_eq!(m.severity, "LOW");
    }

    #[test]
    fn test_safe_report_text_redacts_credentials() {
        let s = safe_report_text(
            "error: Bearer abcdefghijklmnop failed, key sk-abcdefghijklmnopqrstuvwx, db mysql://root:Secret123@10.0.0.1/db, phone 13800138000, mail a@b.cn",
            0,
        );
        assert!(!s.contains("abcdefghijklmnop"), "报告泄漏了 token: {}", s);
        assert!(!s.contains("Secret123"), "报告泄漏了密码: {}", s);
        assert!(!s.contains("13800138000"), "报告泄漏了手机号: {}", s);
        assert!(!s.contains("a@b.cn"), "报告泄漏了邮箱: {}", s);
        assert!(s.contains("<redacted>") || s.contains("<key>"));
    }

    #[test]
    fn test_safe_report_target_strips_secrets() {
        let t = safe_report_target("https://user:Passw0rd@api.example.com:8443/v1/chat?key=SECRET#frag");
        assert!(!t.contains("Passw0rd"), "目标泄漏了 userinfo: {}", t);
        assert!(!t.contains("SECRET"), "目标泄漏了 query: {}", t);
        assert!(!t.contains("frag"), "目标泄漏了 fragment: {}", t);
        assert!(t.contains("api.example.com:8443"), "host 应保留: {}", t);
        assert!(t.contains("/v1/chat"), "path 应保留: {}", t);
        // 非 http(s) 不做 host/path 提取（报告目标通常是用户自己配置的上游地址，
        // 与「上游地址是用户已配置并正在请求的目标，不构成面向客户端的泄漏」同理）
        let file = safe_report_target("file:///home/deploy/x");
        assert!(file.starts_with("file://"), "{}", file);
        assert_eq!(safe_report_target(""), "");
    }

    #[test]
    fn test_render_report_contains_matrix_and_escapes_pipes() {
        let expected: HashSet<String> = ["step3_verify", "step9_error"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut sf: HashMap<String, Vec<Finding>> = HashMap::new();
        sf.insert("step3_verify".to_string(), vec![]);
        sf.insert(
            "step9_error".to_string(),
            vec![Finding::new(
                "error_leak",
                Severity::Critical,
                "evidence with | pipe",
                "sk_prefix_secret",
            )],
        );
        let m = aggregate_matrix(&sf, &expected);
        let md = render_markdown_report(
            "https://api.example.com/v1/chat",
            "claude-3-5-sonnet",
            &m,
            &sf,
            "2026-09-13 19:00:00",
        );
        assert!(md.contains("CRITICAL RISK"));
        assert!(md.contains("记忆残留"));
        assert!(md.contains("记忆残留 · 独立复验"));
        assert!(md.contains("\\|"), "表格里的竖线必须转义: {}", md);
        // 无回执的步骤要显式标注，不能显示成「未发现异常」
        assert!(md.contains("无回执"), "{}", md);
    }

    #[test]
    fn test_render_report_marks_inconclusive() {
        let expected: HashSet<String> = ["step3_verify"].iter().map(|s| s.to_string()).collect();
        let m = aggregate_matrix(&HashMap::new(), &expected);
        let md = render_markdown_report("https://a.b", "m", &m, &HashMap::new(), "t");
        assert!(md.contains("INCONCLUSIVE"));
        assert!(md.contains("不能视为「无风险」"));
    }

    #[test]
    fn test_report_file_name() {
        assert_eq!(report_file_name("20260913-190000"), "audit-20260913-190000.md");
    }
}
