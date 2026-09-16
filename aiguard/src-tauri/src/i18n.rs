//! 后端文案表：**只覆盖离开窗口的界面**（系统托盘菜单 / 托盘提示 / 桌面通知）。
//!
//! 窗口内的界面文案由前端 `src/i18n.ts` 负责，两边唯一的交点是 kv `ui.language`。
//!
//! 三条硬性约定：
//! 1. 表里每个 key 必须**同时**给出中英文——`test_table_is_complete_and_unique`
//!    会强制这一点（漏了英文不会编译失败，只会静默显示中文，必须靠测试兜住）；
//! 2. 信号展示名以 `aiguard_core::audit::SIGNAL_CATALOG` 为唯一真相，
//!    本表的英文名必须覆盖其全部条目（同样由测试守护）；
//! 3. 这里的所有文案都只允许拼接**严重度 / 信号名 / 域名 / 计数**，
//!    绝不接受 evidence —— 托盘与通知都是「离开应用」的信息面。

use crate::store::{now_secs_f64, AuditEventRow};

// ═══════════════════════ 界面语言 ═══════════════════════

/// 界面语言。窗口内（前端）与窗口外（托盘 / 通知）共用同一取值，落盘于 kv `ui.language`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Zh,
    En,
}

impl Default for Language {
    fn default() -> Self {
        Language::Zh
    }
}

impl Language {
    pub fn as_str(self) -> &'static str {
        match self {
            Language::Zh => "zh",
            Language::En => "en",
        }
    }

    /// 解析语言标识；任何无法识别的取值一律回退中文（不报错，界面语言不值得中断启动）。
    pub fn parse(s: &str) -> Language {
        if s.trim().eq_ignore_ascii_case("en") {
            Language::En
        } else {
            Language::Zh
        }
    }
}

impl serde::Serialize for Language {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

// ═══════════════════════ 文案表 ═══════════════════════

/// (key, 中文, English)。`{}` 为顺序占位符，由 [`fmt`] 按位置替换。
const TABLE: &[(&str, &str, &str)] = &[
    // —— 应用名 ——
    ("app.name", "AI 安全卫士", "AI Guard"),
    // —— 托盘菜单 ——
    ("tray.status.on", "状态：守护中", "Status: protecting"),
    ("tray.status.off", "状态：未开启", "Status: off"),
    ("tray.toggle.pause", "暂停守护", "Pause protection"),
    ("tray.toggle.resume", "开启守护", "Start protection"),
    ("tray.show", "显示主窗口", "Show window"),
    ("tray.events", "最近事件", "Recent events"),
    ("tray.events.none", "暂无安全事件", "No security events"),
    ("tray.quit", "退出", "Quit"),
    // —— 托盘提示 ——
    ("tray.tip.on", "{} · 守护中", "{} · protecting"),
    ("tray.tip.off", "{} · 守护未开启", "{} · not protecting"),
    ("tray.tip.counts", "活跃会话 {} · 已记录事件 {}", "{} active sessions · {} events recorded"),
    // —— 相对时间 ——
    ("time.now", "刚刚", "just now"),
    ("time.minutes", "{} 分钟前", "{} min ago"),
    ("time.hours", "{} 小时前", "{} h ago"),
    // —— 严重度 ——
    ("sev.critical", "严重", "Critical"),
    ("sev.high", "高危", "High"),
    ("sev.medium", "中危", "Medium"),
    ("sev.low", "提示", "Info"),
    // —— 布尔 ——
    ("bool.yes", "是", "yes"),
    ("bool.no", "否", "no"),
    // —— 桌面通知：安全事件 ——
    ("notify.title", "{} · {}事件", "{} · {} event"),
    ("notify.body.count", "发现 {} 条安全事件", "{} security events detected"),
    ("notify.body.single", "「{}」风险", "{} risk"),
    ("notify.body.multi", "「{}」等 {} 类风险", "{} and {} more risk types"),
    ("notify.body.total", "（共 {} 条）", " ({} total)"),
    // —— 桌面通知：守护开关失败（托盘 / 快捷键没有提示位，只能靠通知） ——
    ("notify.guard.fail.title", "{} · 守护开关未生效", "{} · protection toggle failed"),
    // —— 桌面通知：快捷键触发应急切断 ——
    ("notify.panic.title", "{} · 应急切断已执行", "{} · emergency cutoff done"),
    (
        "notify.panic.body",
        "已清空 {} 个会话 / {} 条映射；守护已关闭：{}；根证书：{}",
        "Cleared {} sessions / {} mappings; protection disabled: {}; root certificate: {}",
    ),
    ("cert.all", "已从全部信任库撤销", "removed from all trust stores"),
    ("cert.partial", "已部分撤销", "partially removed"),
    ("cert.none", "未撤销", "not removed"),
    ("cert.absent", "未在本机找到证书", "certificate not found on this device"),
    // —— 桌面通知：通道自检 ——
    ("notify.test.title", "{} · 测试通知", "{} · test notification"),
    (
        "notify.test.body",
        "系统通知通道可用。出现高危事件时（且主窗口不在前台）会以这种方式提醒你。",
        "Notification channel works. High-risk events will reach you this way while the window is in the background.",
    ),
    // —— 桌面通知：发现新版本 ——
    ("notify.update.title", "{} · 发现新版本 {}", "{} · new version {}"),
    (
        "notify.update.body",
        "当前版本 {}。可在设置页的「更新检查」查看发布说明与下载地址。",
        "You are running {}. See Settings → Update check for release notes and the download link.",
    ),
];

/// 信号语义名 → 英文展示名。中文展示名以 core 的 SIGNAL_CATALOG 为唯一真相。
/// 覆盖度由 `test_signal_labels_cover_catalog` 强制。
///
/// ⚠ 这里的英文必须与前端词典（`src/i18n-dict-ui.ts` / `src/i18n-dict-backend.ts` 里
/// 那 7 条中文展示名对应的译文）**逐字一致**——两边分别服务「窗口外」（托盘 / 系统通知）
/// 与「窗口内」（信号卡片），一旦漂移，同一个信号会在两处显示不同的英文名。
/// 这条约束由 `scripts/i18n_check.mjs` 的「信号英文名跨进程一致性」检查兜住。
///
/// 另注：措辞必须由 SIGNAL_CATALOG 的中文原样对应，不能改用
/// "Response injection" / "Cross-request memory" 这类贴近参照项目的说法
/// （对应中文「响应投毒 / 跨请求污染」在命名规范里是禁止的）。
const SIGNAL_EN: &[(&str, &str)] = &[
    ("error_leak", "Error leakage"),
    ("identity_swap", "Model swap"),
    ("tool_call_rewrite", "Replay tampering"),
    ("sse_anomaly", "Stream anomaly"),
    ("response_poison", "Response smuggling"),
    ("cross_request_pollution", "Memory residue"),
    ("dangerous_action", "High-risk commands"),
    ("tool_call_injection", "Tool-call injection"),
    ("locker_access", "Locker access"),
];

// ═══════════════════════ 取词与格式化 ═══════════════════════

/// 取一条文案。未知 key 原样返回 key 本身——宁可界面上出现一个可疑的标识符，
/// 也不要静默变成空串（那样连"漏了文案"都看不出来）。
pub fn tr(lang: Language, key: &str) -> String {
    match TABLE.iter().find(|(k, _, _)| *k == key) {
        Some((_, zh, en)) => match lang {
            Language::Zh => (*zh).to_string(),
            Language::En => (*en).to_string(),
        },
        None => key.to_string(),
    }
}

/// 按位置替换 `{}`。参数少于占位符时，多出来的 `{}` 保持原样（不 panic）。
pub fn fmt(pattern: &str, args: &[String]) -> String {
    let mut out = String::with_capacity(pattern.len() + 32);
    let mut rest = pattern;
    let mut i = 0;
    while let Some(pos) = rest.find("{}") {
        out.push_str(&rest[..pos]);
        match args.get(i) {
            Some(a) => out.push_str(a),
            None => out.push_str("{}"),
        }
        i += 1;
        rest = &rest[pos + 2..];
    }
    out.push_str(rest);
    out
}

/// 严重度展示名（未知取值原样返回）。
pub fn severity_label(lang: Language, severity: &str) -> String {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => tr(lang, "sev.critical"),
        "HIGH" => tr(lang, "sev.high"),
        "MEDIUM" => tr(lang, "sev.medium"),
        "LOW" => tr(lang, "sev.low"),
        other => other.to_string(),
    }
}

/// 信号展示名：中文取 core 的权威表，英文取本文件的映射（未知信号原样返回标识符）。
pub fn signal_label(lang: Language, signal: &str) -> String {
    match lang {
        Language::Zh => aiguard_core::audit::signal_name(signal).to_string(),
        Language::En => SIGNAL_EN
            .iter()
            .find(|(k, _)| *k == signal)
            .map(|(_, v)| (*v).to_string())
            .unwrap_or_else(|| signal.to_string()),
    }
}

/// 相对时间（秒 → 人类可读）。
pub fn relative_time(lang: Language, secs: u64) -> String {
    if secs < 60 {
        tr(lang, "time.now")
    } else if secs < 3600 {
        fmt(&tr(lang, "time.minutes"), &[(secs / 60).to_string()])
    } else {
        fmt(&tr(lang, "time.hours"), &[(secs / 3600).to_string()])
    }
}

/// 托盘提示：状态 + 计数。
pub fn tray_tip(lang: Language, enabled: bool, active_sessions: usize, recent_events: usize) -> String {
    let name = tr(lang, "app.name");
    if !enabled {
        return fmt(&tr(lang, "tray.tip.off"), &[name]);
    }
    let head = fmt(&tr(lang, "tray.tip.on"), &[name]);
    let counts = fmt(
        &tr(lang, "tray.tip.counts"),
        &[active_sessions.to_string(), recent_events.to_string()],
    );
    // 两行：第一行是状态，第二行是计数（托盘提示支持换行，比一行塞满可读）
    format!("{}\n{}", head, counts)
}

/// 托盘「最近事件」一行：相对时间 · 严重度 · 信号展示名 · 域名。
/// **只使用脱敏后的元信息**，绝不拼 evidence。
pub fn tray_event_line(lang: Language, ev: &AuditEventRow) -> String {
    let ago = (now_secs_f64() - ev.ts).max(0.0) as u64;
    let host = if ev.host.trim().is_empty() {
        "-"
    } else {
        ev.host.as_str()
    };
    format!(
        "{} · {} {} · {}",
        relative_time(lang, ago),
        severity_label(lang, &ev.severity),
        signal_label(lang, &ev.signal_type),
        host
    )
}

/// 生成桌面通知文案（纯函数，便于单测）。
///
/// **只使用严重度与信号展示名**，绝不拼接 `evidence`——通知会出现在系统通知中心，
/// 属于「离开应用」的信息面，必须与审计日志同样保持脱敏。
pub fn notify_text(lang: Language, events: &[AuditEventRow], top_rank: u8) -> (String, String) {
    let severity = match top_rank {
        4 => "CRITICAL",
        3 => "HIGH",
        2 => "MEDIUM",
        _ => "LOW",
    };
    let host = events
        .iter()
        .map(|e| e.host.as_str())
        .find(|h| !h.trim().is_empty())
        .unwrap_or("");
    let mut names: Vec<String> = Vec::new();
    for e in events {
        let n = signal_label(lang, &e.signal_type);
        // 展示名可能取不到（未知 signal_type）→ 返回空串。
        // 必须在 push 之前滤掉：否则 names = [""] 长度为 1，会绕过下面的
        // names.is_empty() 分支，拼出「」风险 · host（共 N 条）这种空书名号文案。
        if n.trim().is_empty() {
            continue;
        }
        if !names.contains(&n) {
            names.push(n);
        }
    }
    let mut body = if names.is_empty() {
        fmt(&tr(lang, "notify.body.count"), &[events.len().to_string()])
    } else if names.len() > 1 {
        fmt(
            &tr(lang, "notify.body.multi"),
            &[names[0].clone(), names.len().to_string()],
        )
    } else {
        fmt(&tr(lang, "notify.body.single"), &[names[0].clone()])
    };
    if !host.is_empty() {
        body.push_str(&format!(" · {}", host));
    }
    body.push_str(&fmt(
        &tr(lang, "notify.body.total"),
        &[events.len().to_string()],
    ));
    let title = fmt(
        &tr(lang, "notify.title"),
        &[tr(lang, "app.name"), severity_label(lang, severity)],
    );
    (title, body)
}

/// 发现新版本时的通知文案。
pub fn update_notify(lang: Language, current: &str, latest: &str) -> (String, String) {
    let title = fmt(
        &tr(lang, "notify.update.title"),
        &[tr(lang, "app.name"), latest.to_string()],
    );
    let body = fmt(&tr(lang, "notify.update.body"), &[current.to_string()]);
    (title, body)
}

/// 证书撤销的**稳定代号** → 文案 key。
///
/// ⚠ `PanicReport::cert_state` 是**稳定代号**（`all` / `partial` / `none` / `absent`，
/// 见 commands.rs 里的字段注释），**不是文案 key**。原先这里直接
/// `tr(lang, cert_state)`，于是 `tr(lang, "all")` 查不到表、按约定原样返回代号本身，
/// 系统通知里就出现「根证书：all」/「root certificate: partial」——**中英双语都错**。
/// 而且原有的 `test_panic_notify_shapes` 传的是 `"cert.partial"`，一个生产代码
/// 永远不会产出的值，正好把这条路径遮住了。
///
/// 映射放在这里而不是让 `cert_state_of` 直接返回 key：代号是领域状态，
/// 跨进程（`PanicReport` 会序列化给前端）应当保持与语言无关。
pub fn cert_state_key(state: &str) -> Option<&'static str> {
    match state {
        "all" => Some("cert.all"),
        "partial" => Some("cert.partial"),
        "none" => Some("cert.none"),
        "absent" => Some("cert.absent"),
        _ => None,
    }
}

/// 应急切断完成通知（快捷键触发时唯一的结果通道——没有窗口可回显）。
pub fn panic_notify(
    lang: Language,
    sessions: usize,
    mappings: usize,
    guard_disabled: bool,
    cert_state: &str,
) -> (String, String) {
    let title = fmt(
        &tr(lang, "notify.panic.title"),
        &[tr(lang, "app.name")],
    );
    // 未知代号原样返回，不编造文案（与 tr 的约定一致：宁可露出可疑标识符，也不静默糊弄）
    let cert = match cert_state_key(cert_state) {
        Some(key) => tr(lang, key),
        None => cert_state.to_string(),
    };
    let body = fmt(
        &tr(lang, "notify.panic.body"),
        &[
            sessions.to_string(),
            mappings.to_string(),
            tr(lang, if guard_disabled { "bool.yes" } else { "bool.no" }),
            cert,
        ],
    );
    (title, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::AuditEventRow;
    use std::collections::HashSet;

    fn row(sev: &str, signal: &str, host: &str) -> AuditEventRow {
        AuditEventRow {
            seq: 0,
            ts: now_secs_f64() - 125.0,
            sid: "conv:api.openai.com:chat-1".into(),
            host: host.into(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            signal_type: signal.into(),
            severity: sev.into(),
            evidence: "sk_prefix_secret len=29 sha256=abcdef0123456789".into(),
            request_hash: "a1b2c3d4e5f60718".into(),
            response_hash: "1122334455667788".into(),
            probe_id: String::new(),
            // 迁移新增列的默认值
            user_label: "none".into(),
            label_ts: 0.0,
            rule_id: String::new(),
            rule_ver: String::new(),
        }
    }

    /// 每个 key 都必须同时有两语言文案，且 key 唯一、占位符数量一致。
    #[test]
    fn test_table_is_complete_and_unique() {
        let mut seen: HashSet<&str> = HashSet::new();
        for (key, zh, en) in TABLE {
            assert!(seen.insert(key), "文案 key 重复: {}", key);
            assert!(!zh.trim().is_empty(), "{} 缺少中文文案", key);
            assert!(!en.trim().is_empty(), "{} 缺少英文文案", key);
            assert_eq!(
                zh.matches("{}").count(),
                en.matches("{}").count(),
                "{} 的中英文占位符数量不一致（会导致 fmt 错位）",
                key
            );
        }
    }

    /// 信号英文名必须覆盖 core 的全部信号，且中文名与 core 权威表逐字一致。
    #[test]
    fn test_signal_labels_cover_catalog() {
        for (signal, zh_name, _desc, _impl) in aiguard_core::audit::SIGNAL_CATALOG {
            let en = signal_label(Language::En, signal);
            assert_ne!(en, *signal, "信号 {} 缺少英文展示名", signal);
            assert_eq!(
                signal_label(Language::Zh, signal),
                *zh_name,
                "信号 {} 的中文名必须与 core 权威表一致",
                signal
            );
        }
        assert_eq!(
            SIGNAL_EN.len(),
            aiguard_core::audit::SIGNAL_CATALOG.len(),
            "英文信号名表与 core 信号数量不一致"
        );
    }

    #[test]
    fn test_language_parse_falls_back_to_zh() {
        assert_eq!(Language::parse("en"), Language::En);
        assert_eq!(Language::parse(" EN "), Language::En);
        assert_eq!(Language::parse("zh"), Language::Zh);
        assert_eq!(Language::parse(""), Language::Zh);
        assert_eq!(Language::parse("klingon"), Language::Zh);
        assert_eq!(Language::default(), Language::Zh);
    }

    #[test]
    fn test_fmt_handles_missing_args_without_panic() {
        assert_eq!(fmt("a{}b{}", &["1".into(), "2".into()]), "a1b2");
        assert_eq!(fmt("a{}b{}", &["1".into()]), "a1b{}");
        assert_eq!(fmt("no placeholder", &[]), "no placeholder");
    }

    #[test]
    fn test_relative_time_buckets() {
        assert_eq!(relative_time(Language::Zh, 5), "刚刚");
        assert_eq!(relative_time(Language::Zh, 120), "2 分钟前");
        assert_eq!(relative_time(Language::Zh, 7200), "2 小时前");
        assert_eq!(relative_time(Language::En, 120), "2 min ago");
    }

    #[test]
    fn test_tray_tip_both_languages() {
        let zh = tray_tip(Language::Zh, true, 3, 2);
        assert!(zh.contains("守护中"), "{}", zh);
        assert!(zh.contains("活跃会话 3"), "{}", zh);
        let off = tray_tip(Language::Zh, false, 0, 0);
        assert!(off.contains("守护未开启"), "{}", off);
        assert!(!off.contains("活跃会话"), "关闭状态不必再报计数: {}", off);

        let en = tray_tip(Language::En, true, 3, 2);
        assert!(en.contains("protecting"), "{}", en);
        assert!(en.contains("3 active sessions"), "{}", en);
    }

    #[test]
    fn test_tray_event_line_is_evidence_free_and_readable() {
        let line = tray_event_line(Language::Zh, &row("HIGH", "response_poison", "api.openai.com"));
        assert!(line.contains("分钟前"), "应给出相对时间: {}", line);
        assert!(line.contains("高危"), "应给出严重度中文: {}", line);
        assert!(line.contains("响应夹带"), "应给出信号中文展示名: {}", line);
        assert!(line.contains("api.openai.com"));
        // 托盘文案会显示在系统菜单里，属"离开应用"的信息面，脱敏要求与日志同级
        assert!(!line.contains("sk_prefix_secret"), "托盘文案不得含 evidence: {}", line);
        assert!(!line.contains("sha256"));

        let en = tray_event_line(Language::En, &row("HIGH", "response_poison", "api.openai.com"));
        assert!(en.contains("High"), "{}", en);
        // 英文展示名以 SIGNAL_EN 为准，必须与前端词典逐字一致
        // （跨进程一致性由 scripts/i18n_check.mjs 对账）。
        assert!(en.contains("Response smuggling"), "{}", en);
        assert!(!en.contains("sk_prefix_secret"));
    }

    #[test]
    fn test_tray_event_line_edge_cases() {
        // 无域名：用占位符补齐，不留下空着的分隔段
        let no_host = tray_event_line(Language::Zh, &row("LOW", "dangerous_action", ""));
        assert!(no_host.contains(" · -"), "无域名应显示占位符: {}", no_host);
        assert!(no_host.contains("提示"), "LOW 应显示为提示: {}", no_host);

        // 很久以前：切到小时
        let mut old = row("CRITICAL", "error_leak", "api.deepseek.com");
        old.ts = now_secs_f64() - 7200.0;
        let ol = tray_event_line(Language::Zh, &old);
        assert!(ol.contains("小时前"), "{}", ol);
        assert!(ol.contains("严重"), "{}", ol);

        // 时钟回拨 / 未来时间戳：不能出现负数时间，也不能 panic
        let mut future = row("HIGH", "identity_swap", "claude.ai");
        future.ts = now_secs_f64() + 600.0;
        assert!(tray_event_line(Language::Zh, &future).contains("刚刚"));
    }

    #[test]
    fn test_notify_text_is_evidence_free_in_both_languages() {
        let events = vec![
            row("CRITICAL", "error_leak", "api.openai.com"),
            row("HIGH", "response_poison", "api.openai.com"),
        ];
        for lang in [Language::Zh, Language::En] {
            let (title, body) = notify_text(lang, &events, 4);
            assert!(title.contains("AI"), "{}", title);
            assert!(body.contains("api.openai.com"), "{}", body);
            assert!(body.contains("2"), "应带上总条数: {}", body);
            assert!(!body.contains("sk_prefix_secret"), "通知不得含 evidence: {}", body);
            assert!(!body.contains("sha256"), "{}", body);
        }
        let (zh_title, _) = notify_text(Language::Zh, &events, 4);
        assert!(zh_title.contains("严重"), "{}", zh_title);
        let (en_title, _) = notify_text(Language::En, &events, 4);
        assert!(en_title.contains("Critical"), "{}", en_title);
    }

    #[test]
    fn test_notify_text_single_and_empty_name_paths() {
        // 未知信号（展示名取不到）→ 走"若干条安全事件"分支，不能拼出空书名号
        let unknown = vec![row("MEDIUM", "", "api.moonshot.cn")];
        let (_, body) = notify_text(Language::Zh, &unknown, 2);
        assert!(!body.contains("「」"), "不能出现空的书名号: {}", body);
        assert!(body.contains("api.moonshot.cn"), "{}", body);

        let single = vec![row("HIGH", "identity_swap", "claude.ai")];
        let (_, body) = notify_text(Language::Zh, &single, 3);
        assert!(body.contains("模型偷换"), "{}", body);
    }

    #[test]
    fn test_panic_notify_shapes() {
        // ⚠ 这里传的必须是 `cert_state_of` 真会产出的**代号**（all/partial/none/absent），
        // 不是文案 key。曾经传 "cert.partial" 这种生产路径永不产出的值，
        // 于是把「代号被当成 key 直接查表、查不到原样返回」这个 bug 遮住了。
        let (title, body) = panic_notify(Language::Zh, 3, 7, true, "partial");
        assert!(title.contains("应急切断"), "{}", title);
        assert!(body.contains("3"), "{}", body);
        assert!(body.contains("7"), "{}", body);
        assert!(body.contains("部分撤销"), "{}", body);

        let (_, en) = panic_notify(Language::En, 1, 2, false, "none");
        assert!(en.contains("no"), "守护未关闭应显示 no: {}", en);
        assert!(en.contains("not removed"), "{}", en);

        // 未知代号：原样返回，不编造文案
        let (_, odd) = panic_notify(Language::Zh, 0, 0, false, "wat");
        assert!(odd.contains("wat"), "未知代号应原样露出: {}", odd);
    }

    /// **跨文件不变量**：`commands::cert_state_of` 产出的每个代号，
    /// 都必须能在 `cert_state_key` 里找到对应文案。
    ///
    /// 这条测试存在的唯一理由：代号产生在 commands.rs、映射在 i18n.rs，
    /// 只改一边不会编译失败、不会有运行时异常，只会让系统通知里出现
    /// 「根证书：all」这种半成品文案。真实漏过一次。
    #[test]
    fn test_every_produced_cert_state_has_a_label() {
        // 覆盖 cert_state_of 的全部四个分支
        let produced = [
            crate::commands::cert_state_of(true, true, ""),          // all
            crate::commands::cert_state_of(true, false, ""),         // partial
            crate::commands::cert_state_of(false, true, ""),         // partial
            crate::commands::cert_state_of(false, false, "未找到"),  // absent
            crate::commands::cert_state_of(false, false, "其它原因"), // none
        ];
        for code in produced {
            let key = cert_state_key(code)
                .unwrap_or_else(|| panic!("cert_state_of 产出的代号 {:?} 没有对应文案", code));
            // 光有映射还不够：key 本身必须在 TABLE 里，否则 tr 仍会原样返回 key
            assert_ne!(
                tr(Language::En, key),
                key,
                "代号 {:?} 映射到的 key {:?} 不在 TABLE 中",
                code,
                key
            );
            assert_ne!(tr(Language::Zh, key), key, "同上（中文）");
        }
    }

    /// 反向守卫：`cert_state_key` 的映射表不能有永远走不到的条目。
    /// 否则 TABLE 里会留下没人用的 cert.* 文案，日后被误当成「还有别的状态」。
    #[test]
    fn test_cert_state_key_has_no_dead_entries() {
        let all_codes = ["all", "partial", "none", "absent"];
        for code in all_codes {
            assert!(
                cert_state_key(code).is_some(),
                "cert_state_key 漏了代号 {}",
                code
            );
        }
        // 每个 cert.* key 都必须由某个代号可达
        for key in ["cert.all", "cert.partial", "cert.none", "cert.absent"] {
            assert!(
                all_codes.iter().any(|c| cert_state_key(c) == Some(key)),
                "文案 {} 没有任何代号可达（死条目）",
                key
            );
        }
    }

    #[test]
    fn test_update_notify_shapes() {
        let (title, body) = update_notify(Language::Zh, "0.1.0", "0.2.0");
        assert!(title.contains("新版本 0.2.0"), "{}", title);
        assert!(body.contains("0.1.0"), "{}", body);
        let (en_title, en_body) = update_notify(Language::En, "0.1.0", "0.2.0");
        assert!(en_title.contains("new version 0.2.0"), "{}", en_title);
        assert!(en_body.contains("0.1.0"), "{}", en_body);
        // 文案里绝不能出现域名之类的本机信息位
        assert!(!en_body.contains("http"), "{}", en_body);
    }

    #[test]
    fn test_unknown_key_returns_key_itself() {
        assert_eq!(tr(Language::En, "no.such.key"), "no.such.key");
    }
}
