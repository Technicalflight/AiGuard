//! Tauri v2 命令层：仪表盘 / 日志 / 规则（编辑 + 自定义）/ 白名单 / 防护中心 / 守护开关 / CA 管理。

use std::sync::Arc;

use aiguard_core::audit::SIGNAL_CATALOG;
use aiguard_core::detector::{default_rule_specs, Detector, RuleSpec};
use aiguard_core::secure::RestoreLimits;
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};

use crate::proxy_config;
use crate::state::{
    safe_err, AppState, AuditConfig, BlacklistEntry, WhitelistEntry, WhitelistKind, KV_BLACKLIST,
    KV_WHITELIST,
};
use crate::store::RequestLog;

/// 仪表盘统计数据。
#[derive(Debug, Clone, Serialize)]
pub struct DashboardStats {
    pub total_requests: i64,
    pub total_scrubbed: i64,
    pub total_blocked: i64,
    pub active_sessions: i64,
    pub guard_enabled: bool,
    pub mode: String,
    pub uptime_secs: u64,
    pub restore_enabled: bool,
}

/// 获取仪表盘数据。
#[tauri::command]
pub fn get_dashboard(state: State<'_, Arc<AppState>>) -> Result<DashboardStats, String> {
    let (total_requests, total_scrubbed, total_blocked, _db_sessions) = state.store.stats()?;
    // 「活跃会话」口径必须与首页的活跃会话列表一致：取**内存态**当前会话数，
    // 而不是请求日志里出现过的历史会话数（后者只增不减，两个数字会对不上）。
    let active_sessions = state.active_sessions().len() as i64;
    let (guard_enabled, mode, uptime_secs, restore_enabled) = {
        let config = state.config.read().map_err(|e| e.to_string())?;
        (
            config.enabled,
            config.mode.as_str().to_string(),
            state.started_at.elapsed().as_secs(),
            config.restore_enabled,
        )
    };
    Ok(DashboardStats {
        total_requests,
        total_scrubbed,
        total_blocked,
        active_sessions,
        guard_enabled,
        mode,
        uptime_secs,
        restore_enabled,
    })
}

/// 列出最近 n 条请求日志（不含任何原文）。
#[tauri::command]
pub fn list_requests(
    state: State<'_, Arc<AppState>>,
    limit: Option<i64>,
) -> Result<Vec<RequestLog>, String> {
    state.store.list_requests(limit.unwrap_or(50))
}

// ─────────────────────────── 规则（编辑 / 自定义 / 恢复默认） ───────────────────────────

/// 获取全部规则规格（内置 + 自定义）。规则中心渲染与编辑的单一数据源。
#[tauri::command]
pub fn get_rules(state: State<'_, Arc<AppState>>) -> Result<Vec<RuleSpec>, String> {
    load_specs(&state)
}

/// 编辑规则：`enabled` / `action` / `regex` / `name` 任意组合（None = 不改）。
/// 正则非法时返回 Err（保存前经 Detector::from_specs 校验），不落盘、不生效。
#[tauri::command]
pub fn set_rule(
    state: State<'_, Arc<AppState>>,
    id: String,
    enabled: Option<bool>,
    action: Option<String>,
    regex: Option<String>,
    name: Option<String>,
) -> Result<(), String> {
    let mut specs = load_specs(&state)?;
    let spec = specs
        .iter_mut()
        .find(|s| s.id == id)
        .ok_or_else(|| format!("规则不存在: {}", id))?;
    if let Some(v) = enabled {
        spec.enabled = v;
    }
    if let Some(v) = action {
        if !matches!(v.as_str(), "mask" | "block" | "warn") {
            return Err(format!("未知动作: {}", v));
        }
        spec.action = v;
    }
    if let Some(v) = regex {
        spec.regex = v;
    }
    if let Some(v) = name {
        let trimmed = v.trim().to_string();
        if trimmed.is_empty() {
            return Err("规则名称不能为空".to_string());
        }
        spec.name = trimmed;
    }
    save_specs(&state, specs)
}

/// 新增自定义规则，返回更新后的完整规则列表。
/// `tag` 为占位符标签（可选，仅字母数字下划线，自动转大写；缺省 CUSTOM）。
#[tauri::command]
pub fn add_custom_rule(
    state: State<'_, Arc<AppState>>,
    name: String,
    regex: String,
    action: String,
    tag: Option<String>,
) -> Result<Vec<RuleSpec>, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("规则名称不能为空".to_string());
    }
    if regex.trim().is_empty() {
        return Err("正则表达式不能为空".to_string());
    }
    if !matches!(action.as_str(), "mask" | "block" | "warn") {
        return Err(format!("未知动作: {}", action));
    }
    let mut tag_clean: String = tag
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>()
        .to_ascii_uppercase();
    if tag_clean.is_empty() {
        tag_clean = "CUSTOM".to_string();
    }
    let id = format!(
        "custom.{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let spec = RuleSpec {
        id,
        tag: tag_clean,
        name: name.to_string(),
        regex: regex.trim().to_string(),
        action,
        enabled: true,
        builtin: false,
    };
    let mut specs = load_specs(&state)?;
    specs.push(spec);
    save_specs(&state, specs.clone())?;
    Ok(specs)
}

/// 删除自定义规则（内置规则不可删除，可编辑或恢复默认）。
#[tauri::command]
pub fn delete_rule(state: State<'_, Arc<AppState>>, id: String) -> Result<(), String> {
    if !id.starts_with("custom.") {
        return Err("内置规则不可删除，可编辑或恢复默认".to_string());
    }
    let mut specs = load_specs(&state)?;
    let before = specs.len();
    specs.retain(|s| s.id != id);
    if specs.len() == before {
        return Err(format!("规则不存在: {}", id));
    }
    save_specs(&state, specs)
}

/// 恢复内置规则为默认正则 / 动作 / 开关（仅内置规则）。
#[tauri::command]
pub fn reset_rule(state: State<'_, Arc<AppState>>, id: String) -> Result<(), String> {
    let default = aiguard_core::detector::builtin_spec_by_id(&id)
        .ok_or_else(|| "仅内置规则支持恢复默认".to_string())?;
    let mut specs = load_specs(&state)?;
    let pos = specs
        .iter()
        .position(|s| s.id == id)
        .ok_or_else(|| format!("规则不存在: {}", id))?;
    specs[pos] = default;
    save_specs(&state, specs)
}

// ─────────────────────────── 白名单（不拦截；脱敏由条目开关决定） ───────────────────────────

/// 获取全部白名单条目。
#[tauri::command]
pub fn get_whitelist(state: State<'_, Arc<AppState>>) -> Result<Vec<WhitelistEntry>, String> {
    Ok(match state.whitelist.read() {
        Ok(w) => w.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    })
}

/// 新增白名单条目。`kind`: "domain"（域名）| "process"（可执行文件 / 文件夹）。
/// 命中白名单 → 不执行拦截；`scrub` 决定是否仍执行脱敏。返回更新后的列表。
#[tauri::command]
pub fn add_whitelist_entry(
    state: State<'_, Arc<AppState>>,
    kind: String,
    pattern: String,
    scrub: bool,
) -> Result<Vec<WhitelistEntry>, String> {
    let wk = WhitelistKind::from_str(&kind).ok_or_else(|| format!("未知白名单类型: {}", kind))?;
    let pattern = pattern.trim().to_string();
    if pattern.is_empty() {
        return Err("白名单内容不能为空".to_string());
    }
    let pattern = match wk {
        WhitelistKind::Domain => pattern.to_ascii_lowercase(),
        WhitelistKind::Process => pattern,
    };
    let mut list = state
        .whitelist
        .read()
        .map_err(|e| e.to_string())?
        .clone();
    if list
        .iter()
        .any(|e| e.kind == wk && e.pattern.eq_ignore_ascii_case(&pattern))
    {
        return Err("该条目已存在".to_string());
    }
    let entry = WhitelistEntry {
        id: format!("wl.{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
        kind: wk,
        pattern,
        scrub,
    };
    list.push(entry);
    persist_whitelist(&state, list)
}

/// 更新白名单条目（`pattern` / `scrub`，None = 不改）。返回更新后的列表。
#[tauri::command]
pub fn update_whitelist_entry(
    state: State<'_, Arc<AppState>>,
    id: String,
    pattern: Option<String>,
    scrub: Option<bool>,
) -> Result<Vec<WhitelistEntry>, String> {
    let mut list = state
        .whitelist
        .read()
        .map_err(|e| e.to_string())?
        .clone();
    let entry = list
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or_else(|| format!("白名单条目不存在: {}", id))?;
    if let Some(p) = pattern {
        let p = p.trim().to_string();
        if p.is_empty() {
            return Err("白名单内容不能为空".to_string());
        }
        entry.pattern = if entry.kind == WhitelistKind::Domain {
            p.to_ascii_lowercase()
        } else {
            p
        };
    }
    if let Some(s) = scrub {
        entry.scrub = s;
    }
    persist_whitelist(&state, list)
}

/// 删除白名单条目。返回更新后的列表。
#[tauri::command]
pub fn remove_whitelist_entry(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<Vec<WhitelistEntry>, String> {
    let mut list = state
        .whitelist
        .read()
        .map_err(|e| e.to_string())?
        .clone();
    let before = list.len();
    list.retain(|e| e.id != id);
    if list.len() == before {
        return Err(format!("白名单条目不存在: {}", id));
    }
    persist_whitelist(&state, list)
}

// ─────────── 黑名单（命中即强制拦截，优先级最高） ───────────

/// 获取全部黑名单条目。
#[tauri::command]
pub fn get_blacklist(state: State<'_, Arc<AppState>>) -> Result<Vec<BlacklistEntry>, String> {
    Ok(match state.blacklist.read() {
        Ok(b) => b.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    })
}

/// 新增黑名单条目。`kind`: "domain" | "process"；`action`: "block"（403 拦截）| "mask"（强制脱敏）。
/// 命中黑名单 → 强制执行所选动作（覆盖检测规则与白名单）。返回更新后的列表。
#[tauri::command]
pub fn add_blacklist_entry(
    state: State<'_, Arc<AppState>>,
    kind: String,
    pattern: String,
    action: String,
) -> Result<Vec<BlacklistEntry>, String> {
    let bk = WhitelistKind::from_str(&kind).ok_or_else(|| format!("未知黑名单类型: {}", kind))?;
    let action = match action.as_str() {
        "block" | "mask" => action,
        _ => "block".to_string(),
    };
    let pattern = pattern.trim().to_string();
    if pattern.is_empty() {
        return Err("黑名单内容不能为空".to_string());
    }
    let pattern = match bk {
        WhitelistKind::Domain => pattern.to_ascii_lowercase(),
        WhitelistKind::Process => pattern,
    };
    let mut list = state
        .blacklist
        .read()
        .map_err(|e| e.to_string())?
        .clone();
    if list
        .iter()
        .any(|e| e.kind == bk && e.pattern.eq_ignore_ascii_case(&pattern))
    {
        return Err("该条目已存在".to_string());
    }
    let entry = BlacklistEntry {
        id: format!("bl.{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
        kind: bk,
        pattern,
        action,
    };
    list.push(entry);
    persist_blacklist(&state, list)
}

/// 删除黑名单条目。返回更新后的列表。
#[tauri::command]
pub fn remove_blacklist_entry(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<Vec<BlacklistEntry>, String> {
    let mut list = state
        .blacklist
        .read()
        .map_err(|e| e.to_string())?
        .clone();
    let before = list.len();
    list.retain(|e| e.id != id);
    if list.len() == before {
        return Err(format!("黑名单条目不存在: {}", id));
    }
    persist_blacklist(&state, list)
}

// ─────────────────────────── 防护中心（防护信号审计） ───────────────────────────

use std::collections::HashMap as CmdHashMap;

/// 单个防护点的展示信息（含持久化命中数）。
#[derive(Debug, Clone, Serialize)]
pub struct SecurityPoint {
    /// 语义信号名（配置开关 / 日志关联的键）
    pub signal: String,
    pub name: String,
    pub desc: String,
    pub enabled: bool,
    /// 是否有实现（依赖主动核查的两个信号当前 false）
    pub implemented: bool,
    /// 历史命中次数（持久化，按信号聚合）
    pub hits: i64,
}

/// 前端「安全策略」视图 = 审计配置 + 还原参数的合并快照。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityPolicyView {
    pub enabled: bool,
    /// 信号开关（按语义信号名）
    pub signals: CmdHashMap<String, bool>,
    /// 入库门槛（LOW/MEDIUM/HIGH/CRITICAL）
    pub severity_floor: String,
    /// 审计事件保留天数（0 = 永久）
    pub retention_days: i64,
    /// 主动核查开关
    pub probes_enabled: bool,
    pub max_buffer_size: usize,
    pub max_placeholder_len: usize,
    pub session_ttl_secs: u64,
    pub clear_session_on_stream_end: bool,
}

impl SecurityPolicyView {
    fn from(cfg: AuditConfig, limits: RestoreLimits) -> Self {
        SecurityPolicyView {
            enabled: cfg.enabled,
            signals: cfg.signals,
            severity_floor: cfg.severity_floor,
            retention_days: cfg.retention_days,
            probes_enabled: cfg.probes_enabled,
            max_buffer_size: limits.max_buffer_size,
            max_placeholder_len: limits.max_placeholder_len,
            session_ttl_secs: limits.session_ttl_secs,
            clear_session_on_stream_end: limits.clear_session_on_stream_end,
        }
    }

    fn split(self) -> (AuditConfig, RestoreLimits) {
        let audit = AuditConfig {
            enabled: self.enabled,
            signals: self.signals,
            severity_floor: self.severity_floor,
            retention_days: self.retention_days,
            probes_enabled: self.probes_enabled,
        };
        let limits = RestoreLimits {
            max_buffer_size: self.max_buffer_size,
            max_placeholder_len: self.max_placeholder_len,
            session_ttl_secs: self.session_ttl_secs,
            clear_session_on_stream_end: self.clear_session_on_stream_end,
        };
        (audit, limits)
    }
}

/// 获取各防护信号的开关状态与命中统计。
#[tauri::command]
pub fn get_security_points(state: State<'_, Arc<AppState>>) -> Result<Vec<SecurityPoint>, String> {
    let cfg = state.audit_config();
    let persisted = state.store.audit_signal_counts()?;
    // audit_events 的 signal_type 就是语义信号名，直接聚合计数
    let mut by_signal: CmdHashMap<String, i64> = CmdHashMap::new();
    for (signal, n) in persisted {
        *by_signal.entry(signal).or_insert(0) += n;
    }

    Ok(SIGNAL_CATALOG
        .iter()
        .map(|(signal, name, desc, implemented)| SecurityPoint {
            signal: signal.to_string(),
            name: name.to_string(),
            desc: desc.to_string(),
            enabled: cfg.signal_enabled(signal),
            implemented: *implemented,
            hits: by_signal.get(*signal).copied().unwrap_or(0),
        })
        .collect())
}

/// 读取当前安全策略（审计配置 + 还原参数）。
#[tauri::command]
pub fn get_security_policy(
    state: State<'_, Arc<AppState>>,
) -> Result<SecurityPolicyView, String> {
    Ok(SecurityPolicyView::from(
        state.audit_config(),
        state.restore_limits_snapshot(),
    ))
}

/// 保存安全策略：参数越界会被夹紧到安全区间后落盘并热更新。
#[tauri::command]
pub fn set_security_policy(
    state: State<'_, Arc<AppState>>,
    policy: SecurityPolicyView,
) -> Result<SecurityPolicyView, String> {
    let (mut audit, mut limits) = policy.split();
    // 参数夹紧，避免「关掉所有上限」的危险配置
    limits.max_buffer_size = limits.max_buffer_size.clamp(4 * 1024, 64 * 1024 * 1024);
    limits.max_placeholder_len = limits.max_placeholder_len.clamp(16, 4096);
    limits.session_ttl_secs = limits.session_ttl_secs.min(7 * 24 * 3600);
    // 入库门槛只允许合法枚举
    if !matches!(
        audit.severity_floor.to_ascii_uppercase().as_str(),
        "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    ) {
        audit.severity_floor = "MEDIUM".to_string();
    }
    audit.severity_floor = audit.severity_floor.to_ascii_uppercase();
    audit.retention_days = audit.retention_days.clamp(0, 365);

    let audit = state.apply_audit_config(audit)?;
    let limits = state.apply_restore_limits(limits)?;
    // 保留天数变化立即生效（后台写线程下一轮 prune 会按新天数执行）
    let _ = state.store.prune_audit_events(audit.retention_days);
    Ok(SecurityPolicyView::from(audit, limits))
}

/// 列出最近 n 条防护命中日志（不含原文）。
#[tauri::command]
pub fn list_security_events(
    state: State<'_, Arc<AppState>>,
    limit: Option<i64>,
) -> Result<Vec<crate::store::AuditEventRow>, String> {
    state
        .store
        .fetch_audit_events_desc(limit.unwrap_or(100))
}

// ─────────────────────────── 日志分页 ───────────────────────────

/// 分页结果（请求页 / 审计页共用）。
#[derive(Debug, Clone, Serialize)]
pub struct LogPage<T: serde::Serialize> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

const LOG_PAGE_SIZE_MAX: i64 = 100;

/// 分页列出请求日志（请求页）。
#[tauri::command]
pub fn list_requests_page(
    state: State<'_, Arc<AppState>>,
    page: Option<i64>,
    page_size: Option<i64>,
    action: Option<String>,
) -> Result<LogPage<crate::store::RequestLog>, String> {
    let page = page.unwrap_or(1).max(1);
    let page_size = page_size.unwrap_or(20).clamp(1, LOG_PAGE_SIZE_MAX);
    let offset = (page - 1) * page_size;
    let act = action.as_deref().filter(|s| !s.is_empty() && *s != "all");
    let (items, total) =
        state
            .store
            .list_requests_page(offset, page_size, act, None, None)?;
    Ok(LogPage {
        items,
        total,
        page,
        page_size,
    })
}

/// 分页列出审计日志（审计页，按日期可选筛选）。
#[tauri::command]
pub fn list_audit_page(
    state: State<'_, Arc<AppState>>,
    page: Option<i64>,
    page_size: Option<i64>,
    from_ts: Option<i64>,
    to_ts: Option<i64>,
) -> Result<LogPage<crate::store::RequestLog>, String> {
    let page = page.unwrap_or(1).max(1);
    let page_size = page_size.unwrap_or(20).clamp(1, LOG_PAGE_SIZE_MAX);
    let offset = (page - 1) * page_size;
    let (items, total) = state.store.list_requests_page(
        offset,
        page_size,
        None,
        from_ts.filter(|v| *v > 0),
        to_ts.filter(|v| *v > 0),
    )?;
    Ok(LogPage {
        items,
        total,
        page,
        page_size,
    })
}

// ─────────────────────────── 日志定期清理 ───────────────────────────

/// 日志清理设置（天数，0 = 永久保留）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupSettings {
    /// 直通记录保留天数（默认 1，优先清理）
    pub passthrough_days: i64,
    /// 已脱敏记录保留天数（默认 30）
    pub mask_days: i64,
    /// 已拦截记录保留天数（默认 90）
    pub block_days: i64,
}

impl Default for CleanupSettings {
    fn default() -> Self {
        CleanupSettings {
            passthrough_days: 1,
            mask_days: 30,
            block_days: 90,
        }
    }
}

const KV_CLEANUP_PASSTHROUGH: &str = "cleanup.passthrough_days";
const KV_CLEANUP_MASK: &str = "cleanup.mask_days";
const KV_CLEANUP_BLOCK: &str = "cleanup.block_days";

/// 读取清理设置（kv 缺省时返回默认值）。
fn load_cleanup_settings(state: &Arc<AppState>) -> Result<CleanupSettings, String> {
    let mut s = CleanupSettings::default();
    if let Some(v) = state.store.kv_get(KV_CLEANUP_PASSTHROUGH)? {
        s.passthrough_days = v.parse().unwrap_or(s.passthrough_days);
    }
    if let Some(v) = state.store.kv_get(KV_CLEANUP_MASK)? {
        s.mask_days = v.parse().unwrap_or(s.mask_days);
    }
    if let Some(v) = state.store.kv_get(KV_CLEANUP_BLOCK)? {
        s.block_days = v.parse().unwrap_or(s.block_days);
    }
    Ok(s)
}

/// 读取日志清理设置。
#[tauri::command]
pub fn get_cleanup_settings(
    state: State<'_, Arc<AppState>>,
) -> Result<CleanupSettings, String> {
    load_cleanup_settings(&state)
}

/// 保存日志清理设置并立即执行一次清理。
#[tauri::command]
pub fn set_cleanup_settings(
    state: State<'_, Arc<AppState>>,
    passthrough_days: i64,
    mask_days: i64,
    block_days: i64,
) -> Result<CleanupSettings, String> {
    // 上限 3650 天（约 10 年），0 = 永久保留
    let clamp = |v: i64| v.clamp(0, 3650);
    let s = CleanupSettings {
        passthrough_days: clamp(passthrough_days),
        mask_days: clamp(mask_days),
        block_days: clamp(block_days),
    };
    state
        .store
        .kv_set(KV_CLEANUP_PASSTHROUGH, &s.passthrough_days.to_string())?;
    state.store.kv_set(KV_CLEANUP_MASK, &s.mask_days.to_string())?;
    state.store.kv_set(KV_CLEANUP_BLOCK, &s.block_days.to_string())?;
    run_cleanup(&state)?;
    Ok(s)
}

/// 清理结果明细（按动作分类）。
#[derive(Debug, Clone, Serialize, Default)]
pub struct CleanupResult {
    pub passthrough: usize,
    pub mask: usize,
    pub block: usize,
    pub audit: usize,
    pub total: usize,
}

/// 按当前设置立即清理（请求日志按动作分类 + 审计事件按保留策略）。
/// 返回分类删除明细；0 条 = 日志均在各自保留期内。
pub fn run_cleanup(state: &Arc<AppState>) -> Result<CleanupResult, String> {
    let settings = load_cleanup_settings(state)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let removed =
        state
            .store
            .prune_request_logs(now, settings.passthrough_days, settings.mask_days, settings.block_days)?;
    let audit_days = {
        let cfg = state.audit.read().map_err(|e| e.to_string())?;
        cfg.retention_days
    };
    let audit_removed = state.store.prune_audit_events(audit_days)?;
    Ok(CleanupResult {
        passthrough: removed[0],
        mask: removed[1],
        block: removed[2],
        audit: audit_removed,
        total: removed[0] + removed[1] + removed[2],
    })
}

/// 手动触发一次日志清理。
#[tauri::command]
pub fn cleanup_logs_now(state: State<'_, Arc<AppState>>) -> Result<CleanupResult, String> {
    run_cleanup(&state)
}

/// 清空全部请求日志（所有动作类型，不含审计事件）。返回删除条数。
#[tauri::command]
pub fn clear_request_logs(state: State<'_, Arc<AppState>>) -> Result<usize, String> {
    state.store.clear_request_logs()
}

/// 清空指定动作类型的请求日志（passthrough = 直通 / mask = 已脱敏 / block = 已拦截）。
#[tauri::command]
pub fn clear_request_logs_by_action(
    state: State<'_, Arc<AppState>>,
    action: String,
) -> Result<usize, String> {
    match action.as_str() {
        "passthrough" | "mask" | "block" => state.store.clear_request_logs_by_action(&action),
        _ => Err(format!("未知的日志类型: {}", action)),
    }
}

/// 清空防护日志（同时设置写线程 cutoff：队列中更早的事件将被丢弃）。
#[tauri::command]
pub fn clear_security_events(
    state: State<'_, Arc<AppState>>,
) -> Result<(usize, f64), String> {
    let (removed, cutoff) = state.store.clear_audit_events()?;
    state.audit_writer.set_cutoff(cutoff);
    Ok((removed, cutoff))
}

/// 清空全部内存会话映射（应急：一键切断所有已建立的占位符映射）。
#[tauri::command]
pub fn clear_sessions(state: State<'_, Arc<AppState>>) -> Result<usize, String> {
    let ids = state.vault.session_ids();
    let n = ids.len();
    for id in ids {
        state.vault.clear_session(&id);
    }
    Ok(n)
}

/// 列出当前活跃会话：域名 / 进程 / 占位符数量 / 最后活动时间。
///
/// 数据来自**内存态元信息 + 映射表**，只含域名、客户端可执行文件路径与时间戳，
/// 不含任何原文与请求正文。排序：最后活动时间倒序（最近活跃的在前）。
#[tauri::command]
pub fn list_active_sessions(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<crate::state::ActiveSessionRow>, String> {
    Ok(state.active_sessions())
}

/// 应急：切断**单个**会话（销毁该会话的全部原文↔占位符映射），返回被销毁的映射条数。
#[tauri::command]
pub fn clear_one_session(
    state: State<'_, Arc<AppState>>,
    session: String,
) -> Result<usize, String> {
    let n = state.vault.session_count(&session);
    state.vault.clear_session(&session);
    Ok(n)
}

// ─────────────────────────── 主动核查 ───────────────────────────

/// 运行一轮主动核查：计划生成 → 经真实代理发送 → 归集发现 → 风险矩阵 → 报告落盘。
///
/// 每步请求都会携带核查内部头（MITM 注册 marker 后剥离），响应侧自动审计并按
/// `probe_id` 归集；`auth_header` 为可选的 `Authorization` 头（核查需要真实可用
/// 凭据，否则语义依赖成功响应的步骤会被判 INCONCLUSIVE）。
#[tauri::command]
pub async fn run_link_check(
    state: State<'_, Arc<AppState>>,
    target_host: String,
    path: String,
    model: String,
    profile: String,
    auth_header: Option<String>,
) -> Result<crate::link_check::LinkCheckResult, String> {
    // 全 owned 交接：核查 future 必须是 'static（内部步骤并发）
    crate::link_check::run_link_check(
        state.inner().clone(),
        target_host,
        path,
        model,
        profile,
        auth_header,
    )
    .await
}

// ─────────────────────────── 守护开关 / CA ───────────────────────────

/// 开启守护前的端口预检：本地代理端口必须处于「本应用正在监听」状态。
///
/// 三种结论：
/// - `ready`：本进程正在监听 → 放行；
/// - `occupied`：被**其它程序**占用 → 说明本地代理压根没起来（端口冲突），
///   此时若开启守护，系统代理会指向一个第三方进程（或直接连不上），必须拦下；
/// - `free`：没有监听者 → 代理线程启动失败/已退出，同样不能开启。
fn precheck_proxy_port(state: &Arc<AppState>) -> Result<(), String> {
    let port = match state.config.read() {
        Ok(c) => c.proxy_port,
        Err(poisoned) => poisoned.into_inner().proxy_port,
    };
    let st = crate::security::port_state(port);
    match st.state.as_str() {
        "ready" => {
            // 令牌开启时额外提醒：浏览器经 PAC 无法携带凭据，会导致网页全部 407
            let require_token = match state.access.read() {
                Ok(a) => a.require_token,
                Err(poisoned) => poisoned.into_inner().require_token,
            };
            if require_token {
                log::warn!(
                    "已开启本地代理令牌校验：浏览器经 PAC 无法携带凭据，网页流量将收到 407"
                );
            }
            Ok(())
        }
        "occupied" => Err(format!(
            "无法开启守护：{}。请关闭该程序，或在设置中更换代理端口后重试。",
            st.detail
        )),
        _ => Err(format!(
            "无法开启守护：本地代理未在运行（127.0.0.1:{} 未被监听）。请重启应用后再试。",
            port
        )),
    }
}

/// 开启守护：系统代理模式写 PAC + 设置 Windows 系统代理；
/// hosts 模式不设置系统代理，改由提权写入 hosts 域名块（DNS 层引导到 443 透明代理）。
#[tauri::command]
pub fn enable_guard(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    apply_guard_enabled(state.inner(), true)
}

/// 关闭守护：系统代理模式还原 Windows 代理设置；
/// hosts 模式移除 hosts 域名块（块存在即清理，不依赖模式状态，防残留）。
#[tauri::command]
pub fn disable_guard(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    apply_guard_enabled(state.inner(), false)
}

/// 应用守护开关（Tauri 命令层与系统托盘共用同一实现，避免两条路径行为漂移）。
pub fn apply_guard_enabled(state: &Arc<AppState>, enabled: bool) -> Result<(), String> {
    if enabled {
        enable_guard_inner(state)
    } else {
        disable_guard_inner(state)
    }
}

fn enable_guard_inner(state: &Arc<AppState>) -> Result<(), String> {
    let mode = {
        let mut config = match state.config.write() {
            Ok(c) => c,
            Err(poisoned) => poisoned.into_inner(),
        };
        config.enabled = true;
        config.mode.as_str().to_string()
    };
    // 端口占用预检：本地代理必须已在监听，且占用者就是本应用。
    // 否则开启守护只会把系统流量导向一个不存在的代理 → 全网断网（用户视角"开了就上不了网"）。
    if let Err(e) = precheck_proxy_port(state) {
        // 预检失败时回滚开关，避免留下「已开启但代理不可用」的假状态
        match state.config.write() {
            Ok(mut config) => config.enabled = false,
            Err(poisoned) => poisoned.into_inner().enabled = false,
        }
        return Err(e);
    }
    if mode == "hosts_file" {
        let block = crate::hosts::build_block(crate::state::AI_HOSTS);
        let msg = crate::hosts::apply_hosts_block(true, &block)?;
        log::info!("hosts 模式启用: {}", msg);
        state.store.kv_set("guard.enabled", "1")?;
        // 动态启动 443 透明层（幂等；无需重启应用）
        crate::transparent::spawn_if_needed(state)?;
        crate::hosts::flush_dns_cache();
        return Ok(());
    }
    // 系统代理模式：指向本地 PAC HTTP 服务（file:// PAC 在 Chromium 下获取不可靠）
    proxy_config::set_system_proxy_pac(&proxy_config::pac_http_url())?;
    state.store.kv_set("guard.enabled", "1")?;
    Ok(())
}

fn disable_guard_inner(state: &Arc<AppState>) -> Result<(), String> {
    let mode = {
        let mut config = match state.config.write() {
            Ok(c) => c,
            Err(poisoned) => poisoned.into_inner(),
        };
        config.enabled = false;
        config.mode.as_str().to_string()
    };
    if mode == "hosts_file" {
        let block = crate::hosts::build_block(crate::state::AI_HOSTS);
        if crate::hosts::hosts_block_exists() {
            crate::hosts::apply_hosts_block(false, &block)?;
        }
        state.store.kv_set("guard.enabled", "0")?;
        crate::transparent::request_stop();
        crate::hosts::flush_dns_cache();
        return Ok(());
    }
    proxy_config::disable_system_proxy()?;
    // 防御：非 hosts 模式下若仍有残留块（如模式状态错乱遗留），一并清理
    if crate::hosts::hosts_block_exists() {
        let block = crate::hosts::build_block(crate::state::AI_HOSTS);
        crate::hosts::apply_hosts_block(false, &block)?;
        crate::hosts::flush_dns_cache();
    }
    state.store.kv_set("guard.enabled", "0")?;
    Ok(())
}

/// 切换拦截模式（system_proxy / hosts_file）。
/// 若守护已开启，会同步应用/移除对应模式需要的系统级改动
/// （系统代理注册表、hosts 域名块——后者需要管理员授权）。
#[tauri::command]
pub fn set_proxy_mode(
    state: State<'_, Arc<AppState>>,
    mode: String,
) -> Result<String, String> {
    let new_mode = match mode.as_str() {
        "system_proxy" => crate::state::ProxyMode::SystemProxy,
        "hosts_file" => crate::state::ProxyMode::HostsFile,
        _ => return Err(format!("未知的拦截模式: {}", mode)),
    };
    let (old_mode, guard_enabled, _port) = {
        let mut config = match state.config.write() {
            Ok(c) => c,
            Err(poisoned) => poisoned.into_inner(),
        };
        let old = config.mode.as_str().to_string();
        config.mode = new_mode;
        (old, config.enabled, config.proxy_port)
    };
    state
        .store
        .kv_set("guard.mode", &mode)?;

    if old_mode == mode {
        return Ok("模式未变化".to_string());
    }

    // ── 幂等清理反向模式的系统级残留（不依赖 old_mode 的正确性）──
    let hosts_block = crate::hosts::build_block(crate::state::AI_HOSTS);
    match mode.as_str() {
        // 切到系统代理：无论守护开关，都把可能残留的 hosts 块删掉（存在才提权）
        "system_proxy" => {
            if crate::hosts::hosts_block_exists() {
                crate::hosts::apply_hosts_block(false, &hosts_block)?;
            }
        }
        // 切到 hosts 模式：移除系统代理设置（幂等）
        "hosts_file" => {
            proxy_config::disable_system_proxy()?;
        }
        _ => {}
    }
    // hosts 增删后清 DNS 缓存，否则系统/浏览器仍解析到旧地址（模式切换"不生效"）
    crate::hosts::flush_dns_cache();

    if !guard_enabled {
        return Ok("模式已保存（守护未开启，系统级改动将在开启守护时生效）".to_string());
    }

    // ── 守护开启中：应用新模式的系统级改动（含透明层动态启停）──
    match mode.as_str() {
        "system_proxy" => {
            proxy_config::set_system_proxy_pac(&proxy_config::pac_http_url())?;
            crate::transparent::request_stop();
            crate::hosts::flush_dns_cache();
            Ok("已切换到系统代理模式".to_string())
        }
        "hosts_file" => {
            let msg = crate::hosts::apply_hosts_block(true, &hosts_block)?;
            crate::transparent::spawn_if_needed(&state)?;
            crate::hosts::flush_dns_cache();
            Ok(format!("已切换到 hosts 模式。{}", msg))
        }
        _ => Ok("模式已保存".to_string()),
    }
}

/// 安装根证书到当前用户信任存储（certutil -user 免 UAC）。
#[tauri::command]
pub fn install_ca(app: tauri::AppHandle) -> Result<String, String> {
    let cert_path = ca_cert_path(&app)?;
    if !cert_path.exists() {
        return Err("CA 证书尚未生成，请先重启应用".to_string());
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let output = std::process::Command::new("certutil")
            .args(["-user", "-addstore", "Root"])
            .arg(cert_path.as_os_str())
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW：GUI 应用绝不闪黑窗
            .output()
            .map_err(|e| format!("启动 certutil 失败: {}", e))?;
        if output.status.success() {
            Ok(format!("根证书已安装到当前用户存储: {}", cert_path.display()))
        } else {
            // certutil 的报错是系统代码页（中文 Windows = GBK），必须按代码页解码
            let (stdout, stderr) = crate::console::decode_output(&output);
            let msg: String = if stderr.trim().is_empty() { stdout } else { stderr }
                .trim()
                .chars()
                .take(200)
                .collect();
            Err(format!("certutil 失败: {}", msg))
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = cert_path;
        Err("当前平台尚未实现一键安装，请手动信任 ca.cer".to_string())
    }
}

/// CA 证书状态。
#[derive(Debug, Clone, Serialize)]
pub struct CaStatus {
    pub cert_path: String,
    pub installed_hint: String,
}

/// 获取 CA 证书路径与状态提示。
#[tauri::command]
pub fn get_ca_status(app: tauri::AppHandle) -> Result<CaStatus, String> {
    let cert_path = ca_cert_path(&app)?;
    let installed = cert_path.exists();
    Ok(CaStatus {
        cert_path: cert_path.display().to_string(),
        installed_hint: if installed {
            "证书文件已生成，如尚未安装请点击「安装根证书」".to_string()
        } else {
            "证书文件将在应用启动时自动生成".to_string()
        },
    })
}

/// 证书在系统信任库中的安装检测结果。
#[derive(Debug, Clone, Serialize)]
pub struct CaTrustStatus {
    /// 是否已在系统信任库中检测到本应用的 CA
    pub trusted: bool,
    /// 检测到的安装位置（"本机信任库（所有用户）" / "当前用户信任库"）
    pub locations: Vec<String>,
    /// 人类可读的检测结论
    pub detail: String,
}

/// 把 PowerShell 脚本编码为 `-EncodedCommand` 参数（UTF-16LE + Base64）。
///
/// 必须用它而不是 `-Command` 传脚本：tokio 传参会把脚本里的 `"` 转义成 `\"`，
/// 而 Windows PowerShell 5.1 的命令行解析器不按预期处理 `\"`，多行脚本中的
/// 中文 CN 比较会在这层悄悄失效（脚本跑通但匹配数为 0）。`-EncodedCommand`
/// 是单个纯 ASCII Base64 参数，无引号无编码歧义。
fn ps_encode_command(script: &str) -> String {
    use base64::Engine as _;
    let utf16le: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(utf16le)
}

/// 查询系统信任库中本应用 CA 的计数：返回 (LocalMachine 数, CurrentUser 数, 当前用户库总数)。
///
/// **直接读注册表**，绝不走 `Cert:` PSDrive——证书提供器（Security 模块）在某些
/// GUI 子进程环境里会加载失败，`Get-ChildItem Cert:\...` 被 SilentlyContinue 吞成
/// 空集合（曾导致已安装证书被误报未安装）。而注册表 provider 是 PowerShell 核心，
/// 永不缺失：`CurrentUser\Root` 存储对应
/// `HKCU:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates`，**每个子键名
/// 就是证书的 SHA-1 指纹**，与本应用 CA 文件算出的指纹直接比对。
/// 指纹在 Rust 侧计算（SHA-1 of DER，与 Windows Thumbprint 同源同值）。
async fn query_trust_counters(cert_path: &std::path::Path) -> Result<(usize, usize, usize), String> {
    let expect = expect_thumbprint(cert_path)?;
    let script = format!(
        r#"$ErrorActionPreference = 'SilentlyContinue'
$expected = '{expect}'
$cu = @(Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates' -ErrorAction SilentlyContinue | Where-Object {{ $_.PSChildName -eq $expected }}).Count
$lm = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates' -ErrorAction SilentlyContinue | Where-Object {{ $_.PSChildName -eq $expected }}).Count
$total = @(Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates' -ErrorAction SilentlyContinue).Count
Write-Output "LM=$lm"
Write-Output "CU=$cu"
Write-Output "TOTAL=$total""#,
        expect = expect
    );

    let mut cmd = tokio::process::Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        &ps_encode_command(&script),
    ])
    .creation_flags(0x0800_0000) // CREATE_NO_WINDOW：GUI 应用中绝不闪黑窗
    .kill_on_drop(true) // 超时丢弃 Future 时连带杀掉子进程
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());

    let out = tokio::time::timeout(std::time::Duration::from_secs(20), cmd.output())
        .await
        .map_err(|_| "检测超时，请重试".to_string())?
        .map_err(|e| safe_err(&e))?;

    let stdout = crate::console::decode_console(&out.stdout);
    let mut lm = 0usize;
    let mut cu = 0usize;
    let mut total = 0usize;
    let mut parsed = false;
    for line in stdout.lines() {
        if let Some(v) = line.strip_prefix("LM=") {
            lm = v.trim().parse().unwrap_or(0);
            parsed = true;
        } else if let Some(v) = line.strip_prefix("CU=") {
            cu = v.trim().parse().unwrap_or(0);
            parsed = true;
        } else if let Some(v) = line.strip_prefix("TOTAL=") {
            total = v.trim().parse().unwrap_or(0);
        }
    }
    if !parsed {
        // PowerShell 本身失败（被策略拦截等），与「未安装」区分开。
        // 报错文案是系统代码页（中文 Windows = GBK），必须按代码页解码后再展示。
        let err: String = crate::console::decode_console(&out.stderr)
            .trim()
            .chars()
            .take(160)
            .collect();
        return Err(format!("检测失败: {}", if err.is_empty() { "无法启动检测".to_string() } else { err }));
    }
    Ok((lm, cu, total))
}

/// 计算证书文件的 Windows 指纹（SHA-1 of DER，大写 hex，与
/// `X509Certificate2.Thumbprint` 及注册表子键名同值）。
fn expect_thumbprint(cert_path: &std::path::Path) -> Result<String, String> {
    let pem = std::fs::read_to_string(cert_path)
        .map_err(|e| format!("读取 CA 证书失败: {}", safe_err(&e)))?;
    let b64: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| format!("CA 证书 PEM 解码失败: {}", safe_err(&e)))?;
    use sha1::{Digest as _, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(&der);
    Ok(hex::encode_upper(hasher.finalize()))
}

/// 检测根证书是否已成功安装到 Windows 系统信任库。
#[tauri::command]
pub async fn check_ca_trust(app: tauri::AppHandle) -> Result<CaTrustStatus, String> {
    let cert_path = ca_cert_path(&app)?;
    if !cert_path.exists() {
        return Err("CA 证书尚未生成，请先重启应用".to_string());
    }
    let (lm, cu, _total) = query_trust_counters(&cert_path).await?;
    let mut locations = Vec::new();
    if lm > 0 {
        locations.push("本机信任库（所有用户）".to_string());
    }
    if cu > 0 {
        locations.push("当前用户信任库".to_string());
    }
    let trusted = !locations.is_empty();
    let detail = if trusted {
        format!(
            "已在「{}」中找到本应用 CA，拦截 HTTPS 流量即时生效（无需管理员权限）。",
            locations.join("、")
        )
    } else {
        format!(
            "系统信任库中未找到「{}」，请点击「安装根证书」后重新检测。",
            crate::state::CA_COMMON_NAME
        )
    };
    Ok(CaTrustStatus { trusted, locations, detail })
}

#[cfg(test)]
mod ca_trust_tests {
    use super::*;

    #[test]
    fn test_ps_encode_command_roundtrip() {
        use base64::Engine as _;
        let script = "Write-Output \"LM=$lm\"\n$cn = 'AI 安全卫士 Local CA'";
        let b64 = ps_encode_command(script);
        // 解码回 UTF-16LE 再转字符串，验证无损
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .expect("base64 应可解码");
        let units: Vec<u16> = raw
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let decoded = String::from_utf16(&units).expect("UTF-16 应可解码");
        assert_eq!(decoded, script);
    }

    #[tokio::test]
    async fn test_query_trust_counters_channel() {
        // 生成一把临时 CA 验证「文件→指纹→注册表枚举」通道健康：
        // 临时 CA 未安装进信任库，预期 LM=0/CU=0，但解析与 TOTAL 必须正常。
        let dir = std::env::temp_dir().join(format!("aiguard_ca_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        crate::state::ensure_ca(&dir).expect("临时 CA 生成应成功");
        let cert_path = dir.join("ca.cer");
        let (lm, cu, total) = query_trust_counters(&cert_path)
            .await
            .expect("检测通道应可用");
        println!("trust counters: LM={}, CU={}, TOTAL={}", lm, cu, total);
        assert!(total > 0, "当前用户根库注册表枚举不应为空（通道异常）");
        assert_eq!(lm + cu, 0, "临时 CA 不应已安装进信任库");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 证书撤销代号必须覆盖四种结局（窗口外文案据此取词）。
    #[test]
    fn test_cert_state_of() {
        assert_eq!(cert_state_of(true, true, ""), "all");
        assert_eq!(cert_state_of(true, false, "已从当前用户信任库移除"), "partial");
        assert_eq!(cert_state_of(false, true, "已从本机信任库移除"), "partial");
        assert_eq!(
            cert_state_of(false, false, "系统信任库中未找到本应用 CA（无需撤销）"),
            "absent"
        );
        assert_eq!(
            cert_state_of(false, false, "本机信任库移除失败（需管理员权限）：拒绝访问"),
            "none"
        );
    }

    #[test]
    fn test_expect_thumbprint_format() {
        // 指纹必须为 40 位大写 hex（与 Windows Thumbprint / 注册表子键名同形）
        let dir = std::env::temp_dir().join(format!("aiguard_tp_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        crate::state::ensure_ca(&dir).expect("临时 CA 生成应成功");
        let tp = expect_thumbprint(&dir.join("ca.cer")).expect("指纹计算应成功");
        assert_eq!(tp.len(), 40);
        assert!(tp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
        std::fs::remove_dir_all(&dir).ok();
    }
}

// ─────────────────────────── 内部辅助 ───────────────────────────

/// CA 证书路径：应用数据目录/ca.cer
fn ca_cert_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(dir.join("ca.cer"))
}

/// 白名单变更：持久化到 kv + 热更新内存副本。
fn persist_whitelist(
    state: &Arc<AppState>,
    list: Vec<WhitelistEntry>,
) -> Result<Vec<WhitelistEntry>, String> {
    let json = serde_json::to_string(&list).map_err(|e| safe_err(&e))?;
    state.store.kv_set(KV_WHITELIST, &json)?;
    // 先落盘再换内存副本，Mutex/RwLock 中毒时降级取内部值（绝不让前端看到内部错误）
    match state.whitelist.write() {
        Ok(mut w) => *w = list.clone(),
        Err(poisoned) => *poisoned.into_inner() = list.clone(),
    }
    Ok(list)
}

/// 黑名单持久化（落盘 → 换内存副本，模式同白名单）。
fn persist_blacklist(
    state: &Arc<AppState>,
    list: Vec<BlacklistEntry>,
) -> Result<Vec<BlacklistEntry>, String> {
    let json = serde_json::to_string(&list).map_err(|e| safe_err(&e))?;
    state.store.kv_set(KV_BLACKLIST, &json)?;
    match state.blacklist.write() {
        Ok(mut b) => *b = list.clone(),
        Err(poisoned) => *poisoned.into_inner() = list.clone(),
    }
    Ok(list)
}

/// 从 kv 读取规则规格；首次启动写入内置默认规格。
fn load_specs(state: &Arc<AppState>) -> Result<Vec<RuleSpec>, String> {
    if let Some(json) = state.store.kv_get("rules.specs")? {
        if let Ok(specs) = serde_json::from_str::<Vec<RuleSpec>>(&json) {
            return Ok(specs);
        }
        log::warn!("kv 中的规则规格损坏，回退为内置默认");
    }
    let specs = default_rule_specs();
    let json = serde_json::to_string(&specs).map_err(|e| e.to_string())?;
    state.store.kv_set("rules.specs", &json)?;
    Ok(specs)
}

/// 保存规则规格：先经 Detector::from_specs 校验（正则非法则 Err），再落盘 + 热重建。
fn save_specs(state: &Arc<AppState>, specs: Vec<RuleSpec>) -> Result<(), String> {
    let detector = Detector::from_specs(&specs)?;
    let json = serde_json::to_string(&specs).map_err(|e| safe_err(&e))?;
    state.store.kv_set("rules.specs", &json)?;
    let arc = Arc::new(detector);
    match state.detector.write() {
        Ok(mut g) => *g = arc,
        Err(poisoned) => *poisoned.into_inner() = arc,
    }
    Ok(())
}

/// 启动时按 kv 持久化的规则规格重建 Detector（main.rs setup 调用）。
pub fn init_rules(state: &Arc<AppState>) {
    match load_specs(state).and_then(|specs| Detector::from_specs(&specs)) {
        Ok(detector) => {
            let arc = Arc::new(detector);
            match state.detector.write() {
                Ok(mut g) => *g = arc,
                Err(poisoned) => *poisoned.into_inner() = arc,
            }
        }
        Err(e) => {
            log::warn!("持久化规则加载失败，使用内置默认规则: {}", safe_err(&e));
            let arc = Arc::new(Detector::with_default_rules());
            match state.detector.write() {
                Ok(mut g) => *g = arc,
                Err(poisoned) => *poisoned.into_inner() = arc,
            }
        }
    }
}

/// 确保启动时恢复守护开关 / 拦截模式 / 还原开关（由 main.rs setup 调用）。
pub fn restore_config(state: &Arc<AppState>) {
    if let Ok(Some(v)) = state.store.kv_get("guard.enabled") {
        let enabled = v == "1";
        match state.config.write() {
            Ok(mut config) => config.enabled = enabled,
            Err(poisoned) => poisoned.into_inner().enabled = enabled,
        }
    }
    if let Ok(Some(v)) = state.store.kv_get("guard.mode") {
        let mode = match v.as_str() {
            "hosts_file" => crate::state::ProxyMode::HostsFile,
            _ => crate::state::ProxyMode::SystemProxy,
        };
        match state.config.write() {
            Ok(mut config) => config.mode = mode,
            Err(poisoned) => poisoned.into_inner().mode = mode,
        }
    }
    if let Ok(Some(v)) = state.store.kv_get("restore.enabled") {
        let enabled = v == "1";
        match state.config.write() {
            Ok(mut config) => config.restore_enabled = enabled,
            Err(poisoned) => poisoned.into_inner().restore_enabled = enabled,
        }
    }
}

/// 设置「响应还原」开关：开启时 AI 回复中的占位符在本机还原为原文再交给客户端；
/// 关闭时响应原样透传（占位符保留），脱敏与审计不受影响。
#[tauri::command]
pub fn set_restore_enabled(state: State<'_, Arc<AppState>>, enabled: bool) -> Result<(), String> {
    match state.config.write() {
        Ok(mut config) => config.restore_enabled = enabled,
        Err(poisoned) => poisoned.into_inner().restore_enabled = enabled,
    }
    state
        .store
        .kv_set("restore.enabled", if enabled { "1" } else { "0" })?;
    Ok(())
}

// ═══════════════════════ 一键应急切断 ═══════════════════════

/// 应急切断结果：**逐项回报**，任何一项没做成都明确列出来，绝不静默通过。
#[derive(Debug, Clone, Default, Serialize)]
pub struct PanicReport {
    /// 被销毁的会话数
    pub sessions_cleared: usize,
    /// 被覆写销毁的映射条数
    pub mappings_cleared: usize,
    /// 被擦除的请求正文采样条数
    pub samples_wiped: usize,
    /// 守护是否已成功关闭
    pub guard_disabled: bool,
    /// 关闭守护的结论（失败时给出原因与后续动作）
    pub guard_note: String,
    /// 是否已从当前用户信任库移除 CA
    pub cert_user_removed: bool,
    /// 是否已从本机信任库移除 CA（需管理员权限）
    pub cert_machine_removed: bool,
    /// 证书撤销的结论
    pub cert_note: String,
    /// 证书撤销结果的**稳定代号**：all / partial / none / absent。
    /// 窗口外的文案（快捷键触发的系统通知）要按语言取词，靠中文结论文本嗅探太脆。
    pub cert_state: String,
    /// 需要用户注意的补充说明
    pub notes: Vec<String>,
}

/// 由三要素推出证书撤销状态的稳定代号。
fn cert_state_of(user: bool, machine: bool, note: &str) -> &'static str {
    match (user, machine) {
        (true, true) => "all",
        (true, false) | (false, true) => "partial",
        (false, false) if note.contains("未找到") => "absent",
        (false, false) => "none",
    }
}

/// 一键应急切断：清空全部内存映射 + 关闭守护 + 从系统信任库撤销根证书。
///
/// 三步**各自独立**推进：任何一步失败都不会中断后续步骤（用户按这个按钮时
/// 最需要的是"能做的都做掉"），失败项在报告里逐条列出。
#[tauri::command]
pub async fn emergency_cutoff(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<PanicReport, String> {
    Ok(emergency_cutoff_owned(app, state.inner().clone()).await)
}

/// 一键应急切断的**自有参数**实现：Tauri 命令与全局快捷键共用同一条路径。
///
/// 全局快捷键的回调里只有 `AppHandle` 与 `Arc<AppState>`（拿不到 `State<'_, _>` 那种
/// 带生命周期的借用），因此必须把实现抽成自有参数版本——否则快捷键路径就得复刻一遍
/// 三步逻辑，两条路径迟早漂移（"菜单点了管用、快捷键不管用"这类问题最难查）。
pub async fn emergency_cutoff_owned(app: tauri::AppHandle, st: Arc<AppState>) -> PanicReport {
    let mut report = PanicReport::default();

    // ① 清空全部内存态：映射表（逐字段零化覆写）/ 请求正文采样 / 会话对齐 / 追踪标记
    let (sessions, mappings, samples) = st.purge_all_memory();
    report.sessions_cleared = sessions;
    report.mappings_cleared = mappings;
    report.samples_wiped = samples;

    // ② 关闭守护：系统代理 / hosts 引导 / 443 透明层
    match apply_guard_enabled(&st, false) {
        Ok(()) => {
            report.guard_disabled = true;
            report.guard_note = "守护已关闭，系统代理与 hosts 引导已还原".to_string();
        }
        Err(e) => {
            report.guard_note = format!("关闭守护未完全成功：{}", e);
            report.notes.push(
                "守护可能仍为开启状态，请到「设置 → 拦截模式」确认并手动关闭".to_string(),
            );
        }
    }

    // ③ 从系统信任库撤销 CA（用户库免 UAC；本机库需要管理员）
    match ca_cert_path(&app) {
        Ok(cert_path) if cert_path.exists() => {
            match tokio::task::spawn_blocking(move || revoke_ca_from_trust(&cert_path)).await {
                Ok(Ok((user, machine, note))) => {
                    report.cert_user_removed = user;
                    report.cert_machine_removed = machine;
                    report.cert_note = note;
                }
                Ok(Err(e)) => {
                    report.cert_note = format!("证书撤销失败：{}", e);
                    report.notes.push("根证书仍在系统信任库中，请手动删除后再关闭守护".to_string());
                }
                Err(e) => {
                    report.cert_note = format!("证书撤销任务异常：{}", safe_err(&e));
                }
            }
        }
        Ok(_) => report.cert_note = "未找到 CA 证书文件，无需撤销".to_string(),
        Err(e) => report.cert_note = format!("无法定位 CA 证书：{}", e),
    }
    report.cert_state = cert_state_of(
        report.cert_user_removed,
        report.cert_machine_removed,
        &report.cert_note,
    )
    .to_string();
    report
        .notes
        .push("证书与私钥文件已保留在本机；重新开启守护前需重新「安装根证书」".to_string());

    // 应急动作不落任何原文；仅记录一条结论性日志便于自查
    log::warn!(
        "已执行一键应急切断：销毁会话 {} / 映射 {} / 请求采样 {}；守护关闭={}；证书移除 用户库={} 本机库={}",
        report.sessions_cleared,
        report.mappings_cleared,
        report.samples_wiped,
        report.guard_disabled,
        report.cert_user_removed,
        report.cert_machine_removed
    );
    report
}

/// 从系统信任库撤销本应用 CA。
///
/// 先读注册表确认"到底装在哪"（子键名即指纹），再只对存在的库执行删除——
/// 不先查就删，会把「本来就没装」误报成「删除失败」。
/// 返回 (用户库已移除, 本机库已移除, 结论文案)。
fn revoke_ca_from_trust(cert_path: &std::path::Path) -> Result<(bool, bool, String), String> {
    let thumbprint = expect_thumbprint(cert_path)?;
    let (in_machine, in_user) = cert_present_sync(&thumbprint);
    if !in_machine && !in_user {
        return Ok((false, false, "系统信任库中未找到本应用 CA（无需撤销）".to_string()));
    }
    let mut parts: Vec<String> = Vec::new();
    let mut user_removed = false;
    let mut machine_removed = false;
    if in_user {
        match run_certutil_delstore(true, &thumbprint) {
            Ok(()) => {
                user_removed = true;
                parts.push("已从当前用户信任库移除".to_string());
            }
            Err(e) => parts.push(format!("当前用户信任库移除失败：{}", e)),
        }
    }
    if in_machine {
        match run_certutil_delstore(false, &thumbprint) {
            Ok(()) => {
                machine_removed = true;
                parts.push("已从本机信任库移除".to_string());
            }
            Err(e) => parts.push(format!("本机信任库移除失败（需管理员权限）：{}", e)),
        }
    }
    Ok((user_removed, machine_removed, parts.join("；")))
}

/// 查询指定指纹的证书是否存在于（本机信任库, 当前用户信任库）——同步版。
///
/// 与 [`query_trust_counters`] 同源（读注册表子键，不用 `Cert:` PSDrive），
/// 但走 `std::process`，供应急路径在阻塞线程里同步调用。
fn cert_present_sync(thumbprint: &str) -> (bool, bool) {
    let script = format!(
        r#"$ErrorActionPreference = 'SilentlyContinue'
$expected = '{tp}'
$lm = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates' -ErrorAction SilentlyContinue | Where-Object {{ $_.PSChildName -eq $expected }}).Count
$cu = @(Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates' -ErrorAction SilentlyContinue | Where-Object {{ $_.PSChildName -eq $expected }}).Count
Write-Output "LM=$lm"
Write-Output "CU=$cu""#,
        tp = thumbprint
    );
    let mut cmd = std::process::Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        &ps_encode_command(&script),
    ]);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            log::warn!("信任库查询失败（按未安装处理）: {}", safe_err(&e));
            return (false, false);
        }
    };
    let mut in_machine = false;
    let mut in_user = false;
    for line in crate::console::decode_console(&out.stdout).lines() {
        if let Some(v) = line.strip_prefix("LM=") {
            in_machine = v.trim().parse::<usize>().unwrap_or(0) > 0;
        } else if let Some(v) = line.strip_prefix("CU=") {
            in_user = v.trim().parse::<usize>().unwrap_or(0) > 0;
        }
    }
    (in_machine, in_user)
}

/// `certutil [-user] -delstore Root <指纹>`；失败时返回按系统代码页解码后的报错。
fn run_certutil_delstore(user_store: bool, thumbprint: &str) -> Result<(), String> {
    let mut cmd = std::process::Command::new("certutil");
    if user_store {
        cmd.arg("-user");
    }
    cmd.args(["-delstore", "Root", thumbprint]);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("启动 certutil 失败: {}", safe_err(&e)))?;
    if out.status.success() {
        return Ok(());
    }
    let (stdout, stderr) = crate::console::decode_output(&out);
    let msg: String = if stderr.trim().is_empty() { stdout } else { stderr }
        .trim()
        .chars()
        .take(160)
        .collect();
    Err(if msg.is_empty() {
        "certutil 返回失败（未见错误详情）".to_string()
    } else {
        msg
    })
}

// ═══════════════════════ 桌面通知 ═══════════════════════

/// 读取桌面通知配置（默认开启、门槛 HIGH）。
#[tauri::command]
pub fn get_notify_config(
    state: State<'_, Arc<AppState>>,
) -> Result<crate::state::NotifyConfig, String> {
    Ok(state.notify_config())
}

/// 保存桌面通知配置；门槛值非法时回退 HIGH（避免"误配成全量推送"）。
#[tauri::command]
pub fn set_notify_config(
    state: State<'_, Arc<AppState>>,
    config: crate::state::NotifyConfig,
) -> Result<crate::state::NotifyConfig, String> {
    let mut cfg = config;
    if crate::state::severity_rank(&cfg.severity_floor) == 0 {
        cfg.severity_floor = "HIGH".to_string();
    }
    state.apply_notify_config(cfg)
}

/// 发一条测试通知：验证系统通知通道是否可用（固定文案，不含任何真实数据）。
#[tauri::command]
pub fn test_notification(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_notification::NotificationExt;
    app.notification()
        .builder()
        .title("AI 安全卫士 · 测试通知")
        .body("系统通知通道可用。出现高危事件时（且主窗口不在前台）会以这种方式提醒你。")
        .show()
        .map_err(|e| format!("发送失败：{}", safe_err(&e)))
}

// ═══════════════════════ 界面语言 ═══════════════════════

/// 读取界面语言（"zh" / "en"）。
#[tauri::command]
pub fn get_language(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    Ok(state.language().as_str().to_string())
}

/// 切换界面语言。
///
/// 除了落盘，还必须**立刻重建托盘菜单**——托盘与通知是"窗口外"的界面，
/// 不同步换语言就会出现"窗口已经是英文、右键菜单还是中文"的割裂。
/// 窗口标题同理（任务栏悬停 / Alt+Tab 里可见），一并同步。
#[tauri::command]
pub fn set_language(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
    language: String,
) -> Result<String, String> {
    let lang = crate::i18n::Language::parse(&language);
    let saved = state.apply_language(lang)?;
    crate::refresh_tray(&app);
    crate::sync_window_title(&app);
    Ok(saved.as_str().to_string())
}

// ═══════════════════════ 首次运行向导 ═══════════════════════

/// 首次运行向导状态。
#[derive(Debug, Clone, Serialize)]
pub struct OnboardingState {
    /// 是否已完成向导
    pub completed: bool,
    /// 完成时所处的向导版本（用于将来"步骤变了要重看一遍"的判断）
    pub completed_version: String,
    /// 当前向导版本
    pub version: String,
    /// 当前应用版本
    pub app_version: String,
}

fn onboarding_state(state: &Arc<AppState>) -> OnboardingState {
    let completed = state
        .store
        .kv_get(crate::state::KV_SETUP_COMPLETED)
        .ok()
        .flatten()
        .map(|v| v == "1")
        .unwrap_or(false);
    let completed_version = state
        .store
        .kv_get(crate::state::KV_SETUP_VERSION)
        .ok()
        .flatten()
        .unwrap_or_default();
    OnboardingState {
        completed,
        completed_version,
        version: crate::state::SETUP_VERSION.to_string(),
        app_version: crate::state::current_version(),
    }
}

/// 读取首次运行向导状态（前端据此决定是否在启动时展示向导）。
#[tauri::command]
pub fn get_onboarding_state(
    state: State<'_, Arc<AppState>>,
) -> Result<OnboardingState, String> {
    Ok(onboarding_state(&state))
}

/// 标记向导已完成（走完最后一步，或用户主动跳过）。
#[tauri::command]
pub fn complete_onboarding(
    state: State<'_, Arc<AppState>>,
) -> Result<OnboardingState, String> {
    state
        .store
        .kv_set(crate::state::KV_SETUP_COMPLETED, "1")?;
    state
        .store
        .kv_set(crate::state::KV_SETUP_VERSION, crate::state::SETUP_VERSION)?;
    Ok(onboarding_state(&state))
}

/// 重置向导状态（设置页「重新运行首次向导」）。
#[tauri::command]
pub fn reset_onboarding(state: State<'_, Arc<AppState>>) -> Result<OnboardingState, String> {
    state
        .store
        .kv_set(crate::state::KV_SETUP_COMPLETED, "0")?;
    Ok(onboarding_state(&state))
}

// ═══════════════════════ 全局快捷键 ═══════════════════════

/// 快捷键状态（界面展示用）。
///
/// 这里刻意**不返回成品文案**：注册失败的结论句要按界面语言来写，交给前端生成；
/// `failure` 只承载系统/解析器给出的技术原因（那是诊断信息，原样透传更利于排查）。
#[derive(Debug, Clone, Serialize)]
pub struct ShortcutState {
    pub config: crate::state::ShortcutConfig,
    /// 可选的键位预设（快捷键是全局抢占，只让用户从白名单里挑）
    pub presets: Vec<String>,
    /// 当前两个键位是否都已真正注册到系统
    pub registered: bool,
    /// 技术原因（注册失败 / 解析失败时非空）
    pub failure: String,
}

fn shortcut_of(s: &str) -> Result<tauri_plugin_global_shortcut::Shortcut, String> {
    use std::str::FromStr;
    tauri_plugin_global_shortcut::Shortcut::from_str(s).map_err(|e| e.to_string())
}

/// 按配置注册两个快捷键；任一失败都会撤掉已注册的部分，不留半套状态。
pub(crate) fn register_shortcuts(
    app: &tauri::AppHandle,
    cfg: &crate::state::ShortcutConfig,
) -> Result<(), String> {
    use tauri_plugin_global_shortcut::GlobalShortcutExt;
    let a = shortcut_of(&cfg.toggle_guard)?;
    let b = shortcut_of(&cfg.panic)?;
    let gs = app.global_shortcut();
    gs.register(a).map_err(|e| e.to_string())?;
    if let Err(e) = gs.register(b) {
        // 第二个没注册上就把第一个也摘掉：宁可两个都没生效，也不要"按了一个管用、
        // 另一个没反应"这种无法解释的半套状态。
        let _ = gs.unregister(a);
        return Err(e.to_string());
    }
    Ok(())
}

/// 注销两个快捷键（幂等：本来就没注册也算成功）。
fn unregister_shortcuts(app: &tauri::AppHandle, cfg: &crate::state::ShortcutConfig) {
    use tauri_plugin_global_shortcut::GlobalShortcutExt;
    let gs = app.global_shortcut();
    if let Ok(a) = shortcut_of(&cfg.toggle_guard) {
        let _ = gs.unregister(a);
    }
    if let Ok(b) = shortcut_of(&cfg.panic) {
        let _ = gs.unregister(b);
    }
}

fn shortcut_state(app: &tauri::AppHandle, state: &Arc<AppState>) -> ShortcutState {
    use tauri_plugin_global_shortcut::GlobalShortcutExt;
    let config = state.shortcut_config();
    let mut registered = false;
    let mut failure = String::new();
    if config.enabled {
        match (shortcut_of(&config.toggle_guard), shortcut_of(&config.panic)) {
            (Ok(a), Ok(b)) => {
                let gs = app.global_shortcut();
                registered = gs.is_registered(a) && gs.is_registered(b);
            }
            (Err(e), _) => failure = e,
            (_, Err(e)) => failure = e,
        }
    }
    ShortcutState {
        config,
        presets: crate::state::SHORTCUT_PRESETS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        registered,
        failure,
    }
}

/// 读取快捷键状态。
#[tauri::command]
pub fn get_shortcut_state(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<ShortcutState, String> {
    Ok(shortcut_state(&app, &state))
}

/// 保存快捷键配置：校验 → 摘掉旧键位 → 注册新键位；**注册失败整体回滚**。
///
/// 回滚是硬要求：否则用户会得到一份"设置里写着已启用、按键却毫无反应"的配置，
/// 而且下一次启动还会照着它再失败一遍。
///
/// 声明为 `async` 是必要的：插件的注册/注销会通过 `run_on_main_thread` 回主线程执行
/// 并同步等待结果；同步命令本身就跑在主线程上，会直接把主线程锁死。
#[tauri::command]
pub async fn set_shortcut_config(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
    config: crate::state::ShortcutConfig,
) -> Result<ShortcutState, String> {
    let st = state.inner().clone();
    let cfg = config.normalized()?;
    let old = st.shortcut_config();

    unregister_shortcuts(&app, &old);
    if cfg.enabled {
        if let Err(e) = register_shortcuts(&app, &cfg) {
            // 装回旧配置（含"旧配置本身是关闭"的情况，此时什么都不注册）
            if old.enabled {
                let _ = register_shortcuts(&app, &old);
            }
            return Err(e);
        }
    }
    st.apply_shortcut_config(cfg)?;
    crate::refresh_tray(&app);
    Ok(shortcut_state(&app, &st))
}

// ═══════════════════════ 更新检查 ═══════════════════════

/// 更新检查状态（配置 + 最近结果 + 当前版本）。
#[derive(Debug, Clone, Serialize)]
pub struct UpdateState {
    pub config: crate::state::UpdateConfig,
    pub status: crate::state::UpdateStatus,
    pub current_version: String,
}

fn update_state(state: &Arc<AppState>) -> UpdateState {
    UpdateState {
        config: state.update_config(),
        status: state.update_status(),
        current_version: crate::state::current_version(),
    }
}

/// 读取更新检查状态。
#[tauri::command]
pub fn get_update_state(state: State<'_, Arc<AppState>>) -> Result<UpdateState, String> {
    Ok(update_state(&state))
}

/// 保存更新检查配置。总开关默认关闭；关闭时**任何自动检查都不会发起网络请求**。
#[tauri::command]
pub fn set_update_config(
    state: State<'_, Arc<AppState>>,
    config: crate::state::UpdateConfig,
) -> Result<UpdateState, String> {
    let cfg = config.normalized()?;
    state.apply_update_config(cfg)?;
    Ok(update_state(&state))
}

/// 立即检查一次更新。
///
/// 即使用户把自动检查关着也允许调用——这是**用户明确点击**发起的动作，
/// 不构成"默认上报"；自动检查则严格受总开关约束。
#[tauri::command]
pub async fn check_update(state: State<'_, Arc<AppState>>) -> Result<UpdateState, String> {
    let st = state.inner().clone();
    run_update_check(&st).await;
    Ok(update_state(&st))
}

/// 执行一次更新检查并落盘结果。
///
/// **任何失败都折叠进 `UpdateStatus`**（不返回 Err）：更新检查是整个应用里最不重要
/// 的功能，绝不能因为它抛错而让界面弹红字、或影响任何其它流程。
pub async fn run_update_check(state: &Arc<AppState>) -> crate::state::UpdateStatus {
    let cfg = state.update_config();
    let mut status = crate::state::UpdateStatus {
        checked_at: crate::store::now_secs_f64() as i64,
        current: crate::state::current_version(),
        ..Default::default()
    };
    match fetch_latest_release(&cfg.repo).await {
        Ok(v) => {
            let tag = v
                .get("tag_name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            status.latest = tag.trim_start_matches('v').to_string();
            status.has_update = crate::state::version_is_newer(&tag, &status.current);
            status.release_name = v
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            status.release_url = v
                .get("html_url")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            status.published_at = v
                .get("published_at")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            status.failed = false;
            status.note = String::new();
        }
        Err(e) => {
            status.failed = true;
            status.note = e;
        }
    }
    if let Err(e) = state.apply_update_status(status.clone()) {
        log::warn!("更新检查结果落盘失败: {}", e);
    }
    status
}

/// 请求 GitHub Releases API 取最新发布。
///
/// 隐私约束（这是本功能存在的全部前提）：
/// - 只发**一个 GET**，不带任何本机数据（不传令牌、不传机器码、不传使用统计）；
/// - 连 `User-Agent` 也只写应用名与版本号（GitHub 强制要求 UA，不写会被拒）；
/// - 只有在总开关打开、或用户明确点击「立即检查」时才会走到这里。
async fn fetch_latest_release(repo: &str) -> Result<serde_json::Value, String> {
    use hyper::body::to_bytes;
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
    const MAX_BODY: usize = 512 * 1024;

    let uri = format!("https://api.github.com/repos/{}/releases/latest", repo);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().build(https);

    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri)
        .header(
            hyper::header::USER_AGENT,
            format!("aiguard/{}", crate::state::current_version()),
        )
        .header(hyper::header::ACCEPT, "application/vnd.github+json")
        .body(hyper::Body::empty())
        .map_err(|e| format!("构造请求失败: {}", safe_err(&e)))?;

    let resp = tokio::time::timeout(TIMEOUT, client.request(req))
        .await
        .map_err(|_| "请求超时（15 秒），请检查网络或代理设置".to_string())?
        .map_err(|e| format!("请求失败: {}", safe_err(&e)))?;

    let code = resp.status();
    let body = tokio::time::timeout(TIMEOUT, to_bytes(resp.into_body()))
        .await
        .map_err(|_| "读取响应超时".to_string())?
        .map_err(|e| format!("读取响应失败: {}", safe_err(&e)))?;

    if !code.is_success() {
        return Err(match code.as_u16() {
            404 => "更新源未找到（仓库不存在或尚未发布 Release）".to_string(),
            403 => "更新源拒绝了本次请求（可能触发了 GitHub 的访问频率限制）".to_string(),
            c => format!("更新源返回 HTTP {}", c),
        });
    }
    if body.len() > MAX_BODY {
        return Err("更新源响应异常（超出预期大小）".to_string());
    }
    serde_json::from_slice(&body).map_err(|e| format!("解析更新源响应失败: {}", safe_err(&e)))
}

#[cfg(test)]
mod update_tests {
    use crate::state::{version_is_newer, UpdateConfig, DEFAULT_UPDATE_REPO};

    #[test]
    fn test_version_is_newer() {
        assert!(version_is_newer("0.2.0", "0.1.0"));
        assert!(version_is_newer("v0.1.1", "0.1.0"));
        assert!(version_is_newer("1.0.0", "0.99.99"));
        assert!(!version_is_newer("0.1.0", "0.1.0"));
        assert!(!version_is_newer("0.1.0", "0.2.0"));
        // 段数不齐时缺失段按 0 处理
        assert!(version_is_newer("0.1.1", "0.1"));
        assert!(!version_is_newer("0.1", "0.1.0"));
        // 预发布后缀只比主版本段
        assert!(!version_is_newer("1.0.0-beta.1", "1.0.0"));
        // 乱七八糟的输入不能 panic
        assert!(!version_is_newer("", ""));
        assert!(version_is_newer("2", "1"));
    }

    #[test]
    fn test_update_config_defaults_are_private() {
        let cfg = UpdateConfig::default();
        // 默认必须是关闭的：隐私工具不允许"未经开启就对外通信"
        assert!(!cfg.enabled, "更新检查必须默认关闭");
        assert_eq!(cfg.repo, DEFAULT_UPDATE_REPO);
        let bad = UpdateConfig {
            enabled: true,
            repo: "not-a-repo".to_string(),
        };
        assert!(bad.normalized().is_err(), "非 owner/name 形式应被拒绝");
        let bad2 = UpdateConfig {
            enabled: true,
            repo: "a/b/c".to_string(),
        };
        assert!(bad2.normalized().is_err());
        let ok = UpdateConfig {
            enabled: true,
            repo: " Owner/Name.js ".to_string(),
        };
        assert_eq!(ok.normalized().unwrap().repo, "Owner/Name.js");
    }
}

#[cfg(test)]
mod shortcut_tests {
    use crate::state::{
        normalize_accelerator, ShortcutConfig, DEFAULT_SHORTCUT_PANIC, DEFAULT_SHORTCUT_TOGGLE,
    };

    #[test]
    fn test_normalize_accelerator_accepts_presets() {
        assert_eq!(normalize_accelerator("Ctrl+Alt+G").unwrap(), "Ctrl+Alt+G");
        // 大小写与顺序无关，但输出稳定（顺序按用户输入，修饰键统一规范写法）
        assert_eq!(normalize_accelerator("ctrl + alt + g").unwrap(), "Ctrl+Alt+G");
        assert_eq!(normalize_accelerator("Shift+Ctrl+Alt+G").unwrap(), "Shift+Ctrl+Alt+G");
    }

    #[test]
    fn test_normalize_accelerator_rejects_bad_input() {
        // 没有主键：这正是插件解析器会放过的"看起来像快捷键"的坏输入
        assert!(normalize_accelerator("Ctrl+Alt").is_err());
        // 没有修饰键：会全局吞掉一个普通字母
        assert!(normalize_accelerator("G").is_err());
        assert!(normalize_accelerator("").is_err());
        // 修饰键重复
        assert!(normalize_accelerator("Ctrl+Ctrl+G").is_err());
        // 白名单之外
        assert!(normalize_accelerator("Ctrl+Alt+Q").is_err());
        assert!(normalize_accelerator("Ctrl+Alt+1").is_err());
    }

    #[test]
    fn test_shortcut_config_rejects_duplicate_bindings() {
        let dup = ShortcutConfig {
            enabled: true,
            toggle_guard: "Ctrl+Alt+G".to_string(),
            panic: "Ctrl+Alt+G".to_string(),
        };
        assert!(dup.normalized().is_err(), "两个动作撞键必须被拒绝");

        // 修饰键书写顺序不同，但物理键位相同 → 同样算撞键。
        // 这正是「比较用规范序、输出按用户输入序」这个设计的用途：
        // 若直接比字符串，"Alt+Ctrl+G" 会溜过检查，两个动作绑到同一个热键上。
        let reordered = ShortcutConfig {
            enabled: true,
            toggle_guard: "Ctrl+Alt+G".to_string(),
            panic: "Alt+Ctrl+G".to_string(),
        };
        assert!(
            reordered.normalized().is_err(),
            "修饰键顺序不同但键位相同，也必须被拒绝"
        );

        let d = ShortcutConfig::default();
        assert!(d.enabled);
        assert_eq!(d.toggle_guard, DEFAULT_SHORTCUT_TOGGLE);
        assert_eq!(d.panic, DEFAULT_SHORTCUT_PANIC);
        assert!(d.clone().normalized().is_ok(), "默认键位必须自身合法");
        // 默认两个键位不能撞
        assert_ne!(DEFAULT_SHORTCUT_TOGGLE, DEFAULT_SHORTCUT_PANIC);
    }
}

// ═══════════════════════ 本机安全加固 ═══════════════════════

/// 本机安全加固状态（全部为**只读评估**；任何一项检查失败都降级为「未知」而不报错）。
#[derive(Debug, Clone, Serialize)]
pub struct HardeningStatus {
    /// 本地代理端口的实时占用情况
    pub proxy_port: crate::security::PortState,
    /// PAC 服务端口（浏览器取 PAC 用）的实时占用情况
    pub pac_port: crate::security::PortState,
    /// 代理是否强制只接受本机回环连接（恒为 true，属纵深防御）
    pub loopback_only: bool,
    /// 是否要求代理级请求携带令牌
    pub require_token: bool,
    /// 令牌掩码提示（只显示前后各 4 位，绝不明文回传全部）
    pub token_hint: String,
    /// 令牌是否已生成可用
    pub token_ready: bool,
    /// 原文映射与请求采样是否做内存擦除（恒为 true）
    pub memory_wipe: bool,
    /// 当前活动会话数（映射表规模，仅供参考）
    pub active_sessions: i64,
    /// 是否检测到调试器附加
    pub debugger_detected: bool,
    /// CA 私钥落盘保护："encrypted" | "plaintext" | "absent"
    pub key_at_rest: String,
    /// CA 私钥文件路径
    pub key_path: String,
    /// 数据目录权限范围："user_only" | "shared" | "unknown"
    pub data_dir_scope: String,
    /// 数据目录权限细节
    pub data_dir_detail: String,
    /// 已审计到的代理客户端进程
    pub client_processes: Vec<String>,
    /// 启动自检提示（端口 / 私钥 / 目录权限的中文结论）
    pub startup_notes: Vec<String>,
}

/// 取「本机安全加固」综合状态（供设置页展示）。
///
/// 内部会枚举 TCP 监听表并执行 `icacls`（阻塞式系统调用），因此声明为 async 并
/// 丢到阻塞线程池——否则同步命令会在主线程上卡住界面。
#[tauri::command]
pub async fn get_hardening_status(
    state: State<'_, Arc<AppState>>,
) -> Result<HardeningStatus, String> {
    let app = state.inner().clone();
    let proxy_port = match app.config.read() {
        Ok(c) => c.proxy_port,
        Err(poisoned) => poisoned.into_inner().proxy_port,
    };
    let access = match app.access.read() {
        Ok(a) => a.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    let key_path = app.data_dir.join("ca.key");
    let data_dir = app.data_dir.clone();
    // 与首页「当前活跃会话」同口径：内存态当前会话数
    let active_sessions = app.active_sessions().len() as i64;
    let debugger_detected = app.debugger_seen();
    let client_processes = app.client_processes();
    let startup_notes = app.startup_notes_snapshot();

    let key_path_probe = key_path.clone();
    let (acl, proxy_state, pac_state, key_at_rest) = tokio::task::spawn_blocking(move || {
        (
            crate::security::data_dir_acl(&data_dir),
            crate::security::port_state(proxy_port),
            crate::security::port_state(crate::proxy_config::PAC_HTTP_PORT),
            crate::security::ca_key_at_rest(&key_path_probe),
        )
    })
    .await
    .map_err(|e| format!("加固自检失败: {}", safe_err(&e)))?;

    let key_at_rest = match key_at_rest {
        crate::security::KeyAtRest::Encrypted => "encrypted",
        crate::security::KeyAtRest::Plaintext => "plaintext",
        crate::security::KeyAtRest::Absent => "absent",
    }
    .to_string();

    Ok(HardeningStatus {
        proxy_port: proxy_state,
        pac_port: pac_state,
        loopback_only: true,
        require_token: access.require_token,
        token_hint: mask_token(&access.token),
        token_ready: access.has_token(),
        memory_wipe: true,
        active_sessions,
        debugger_detected,
        key_at_rest,
        key_path: key_path.display().to_string(),
        data_dir_scope: acl.scope,
        data_dir_detail: acl.detail,
        client_processes,
        startup_notes,
    })
}

/// 实时检测指定端口（默认取当前代理端口）的占用情况——供开启守护前的预检。
#[tauri::command]
pub fn check_proxy_port(state: State<'_, Arc<AppState>>) -> Result<crate::security::PortState, String> {
    let port = match state.config.read() {
        Ok(c) => c.proxy_port,
        Err(poisoned) => poisoned.into_inner().proxy_port,
    };
    Ok(crate::security::port_state(port))
}

/// 取本地代理令牌**明文**（仅用户主动点击「查看」时调用；用于配置 CLI/SDK）。
#[tauri::command]
pub fn get_proxy_token(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    match state.access.read() {
        Ok(a) => Ok(a.token.clone()),
        Err(poisoned) => Ok(poisoned.into_inner().token.clone()),
    }
}

/// 重新生成本地代理令牌（旧令牌立即失效）。
#[tauri::command]
pub fn regenerate_proxy_token(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let token = crate::state::generate_proxy_token();
    state.store.kv_set(
        crate::state::KV_PROXY_TOKEN,
        &crate::security::encode_secret_for_store(&token),
    )?;
    match state.access.write() {
        Ok(mut a) => a.token = token.clone(),
        Err(poisoned) => poisoned.into_inner().token = token.clone(),
    }
    Ok(token)
}

/// 设置是否要求代理级请求携带令牌（默认关闭：浏览器经 PAC 无法携带凭据）。
#[tauri::command]
pub fn set_require_token(
    state: State<'_, Arc<AppState>>,
    enabled: bool,
) -> Result<bool, String> {
    state
        .store
        .kv_set(crate::state::KV_REQUIRE_TOKEN, if enabled { "1" } else { "0" })?;
    match state.access.write() {
        Ok(mut a) => a.require_token = enabled,
        Err(poisoned) => poisoned.into_inner().require_token = enabled,
    }
    Ok(enabled)
}

/// 令牌掩码（只露前后各 4 位，长度不足时全掩）。
fn mask_token(token: &str) -> String {
    let n = token.chars().count();
    if n == 0 {
        return "(未生成)".to_string();
    }
    if n <= 12 {
        return "•".repeat(n);
    }
    let head: String = token.chars().take(4).collect();
    let tail: String = token.chars().skip(n - 4).collect();
    format!("{}{}{}", head, "•".repeat(8), tail)
}

#[cfg(test)]
mod hardening_tests {
    use super::mask_token;

    #[test]
    fn test_mask_token_shape() {
        assert_eq!(mask_token(""), "(未生成)");
        assert_eq!(mask_token("abcdefgh"), "••••••••");
        let m = mask_token("0123456789abcdef0123456789abcdef");
        assert!(m.starts_with("0123"));
        assert!(m.ends_with("cdef"));
        assert!(!m.contains("456789ab"), "中间段必须被掩码");
    }
}
