//! 应用全局状态、CA 生成与配置。

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use aiguard_core::audit::SIGNAL_CATALOG;
use aiguard_core::detector::Detector;
use aiguard_core::vault::Vault;
use serde::{Deserialize, Serialize};

pub use aiguard_core::secure::RestoreLimits;

use crate::i18n::Language;
use crate::store::{now_secs_f64, AuditEventRow, AuditWriter};

/// 拦截模式。当前仅实现系统代理 + PAC，其余枚举预留。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyMode {
    /// 系统代理 + PAC 文件（默认推荐）
    SystemProxy,
    /// hosts 文件模式（规划中）
    HostsFile,
    /// TUN 虚拟网卡模式（规划中）
    Tun,
}

impl ProxyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProxyMode::SystemProxy => "system_proxy",
            ProxyMode::HostsFile => "hosts_file",
            ProxyMode::Tun => "tun",
        }
    }

    #[allow(dead_code)]
    pub fn from_str(s: &str) -> ProxyMode {
        match s {
            "hosts_file" => ProxyMode::HostsFile,
            "tun" => ProxyMode::Tun,
            _ => ProxyMode::SystemProxy,
        }
    }
}

/// 应用配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// 本地代理监听端口
    pub proxy_port: u16,
    pub mode: ProxyMode,
    /// 守护总开关
    pub enabled: bool,
    /// 是否把 AI 回复中的占位符还原为原文后再交给客户端。
    /// 关闭时响应原样透传（占位符保留），审计与脱敏不受影响。
    #[serde(default = "default_true")]
    pub restore_enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Config {
            proxy_port: 8888,
            mode: ProxyMode::SystemProxy,
            enabled: false,
            restore_enabled: true,
        }
    }
}

/// 受守护的 AI 域名列表（只对这些域名做 MITM，其余直通）。
/// 注意：proxy_config.rs 里写入 PAC 文件的域名列表必须与此保持一致。
/// 除各厂商 **API 域名**外，还收录了**网页端对话域名**——网页版（如
/// chat.deepseek.com）的对话请求走的不是 api.* 域名，不收录则网页对话完全不被守护。
/// PAC 按精确主机名匹配：新增域名时请把实际发起请求的主机名完整列出。
pub const AI_HOSTS: &[&str] = &[
    // ── API 域名（SDK / CLI / 自建应用）──
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.deepseek.com",
    "api.moonshot.cn",
    "dashscope.aliyuncs.com",
    "api.mistral.ai",
    "open.bigmodel.cn",
    "api.lingyiwanwu.com",
    "api.baichuan-ai.com",
    // ── 网页端对话域名（浏览器里的网页助手）──
    "chat.deepseek.com",
    "chatgpt.com",
    "chat.openai.com",
    "claude.ai",
    "kimi.moonshot.cn",
    "www.kimi.com",
    "chatglm.cn",
    "www.tongyi.com",
    "tongyi.aliyun.com",
    "yiyan.baidu.com",
    "www.doubao.com",
    "yuanbao.tencent.com",
    "chat.mistral.ai",
];

/// AI 厂商的**注册域后缀**：命中后缀的**全部子域**（含动态分配的上传/CDN 子域，
/// 如 DeepSeek 文件上传的 `hf-xxxx.deepseek.com`）都纳入守护，但代理对其
/// **只透传不脱敏**（multipart/二进制内容不做替换），保证上传等功能正常。
/// 后缀必须以 `.` 开头；裸注册域由匹配逻辑自动覆盖。
pub const AI_HOST_SUFFIXES: &[&str] = &[
    ".deepseek.com",
    ".openai.com",
    ".anthropic.com",
    ".generativelanguage.googleapis.com",
    ".moonshot.cn",
    ".dashscope.aliyuncs.com",
    ".mistral.ai",
    ".bigmodel.cn",
    ".lingyiwanwu.com",
    ".baichuan-ai.com",
    ".chatgpt.com",
    ".claude.ai",
    ".chatglm.cn",
    ".tongyi.com",
    ".yiyan.baidu.com",
    ".doubao.com",
    ".yuanbao.tencent.com",
];

/// 是否为受守护的 AI 域名：精确清单 + 注册域后缀匹配。
/// `x.deepseek.com` 命中后缀；`evil-deepseek.com` 不命中（连字符非点）。
pub fn is_ai_host(host: &str) -> bool {
    is_ai_host_exact(host) || is_ai_host_suffix(host)
}

/// 是否命中**精确域名清单**（对话/API 主域）——这些域名的请求做内容脱敏。
pub fn is_ai_host_exact(host: &str) -> bool {
    let host = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .to_ascii_lowercase();
    AI_HOSTS.contains(&host.as_str())
}

/// 是否命中**注册域后缀**（含动态上传/CDN 子域）——这些域名的请求仅透传，
/// 不做内容脱敏（multipart/二进制/base64 不适用替换，避免破坏文件）。
pub fn is_ai_host_suffix(host: &str) -> bool {
    let host = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .to_ascii_lowercase();
    AI_HOST_SUFFIXES
        .iter()
        .any(|s| host == &s[1..] || host.ends_with(s))
}

#[cfg(test)]
mod host_tests {
    use super::*;

    #[test]
    fn test_is_ai_host_includes_web_hosts() {
        // API 域名
        assert!(is_ai_host("api.deepseek.com"));
        assert!(is_ai_host("api.openai.com:443"));
        // 网页端对话域名（网页版对话请求的主机名不是 api.*）
        assert!(is_ai_host("chat.deepseek.com"));
        assert!(is_ai_host("CHATGPT.COM"));
        assert!(is_ai_host("claude.ai"));
        assert!(is_ai_host("www.kimi.com"));
        // 非 AI 域名与近邻域不误伤
        assert!(!is_ai_host("www.baidu.com"));
        assert!(!is_ai_host("evil-chat.deepseek.com.attacker.com"));
    }

    #[test]
    fn test_exact_vs_suffix_scope() {
        // 精确清单 = 脱敏目标（对话/API 主域）
        assert!(is_ai_host_exact("chat.deepseek.com"));
        assert!(is_ai_host_exact("api.deepseek.com"));
        // 后缀子域 = 仅透传（上传/CDN 动态子域，multipart/base64 不做替换）
        assert!(!is_ai_host_exact("hf-di1q.deepseek.com"));
        assert!(is_ai_host("hf-di1q.deepseek.com"));
        assert!(is_ai_host("hf-abc.deepseek.com"));
        // 裸注册域归后缀规则覆盖
        assert!(is_ai_host("deepseek.com"));
        assert!(!is_ai_host_exact("deepseek.com"));
        // 近邻域双向不误伤
        assert!(!is_ai_host("evil-deepseek.com"));
        assert!(!is_ai_host_exact("evil-deepseek.com"));
    }
}

// ─────────── 白名单 ───────────

/// 白名单条目类型：域名 / 进程（可执行文件或所在文件夹）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WhitelistKind {
    Domain,
    Process,
}

impl WhitelistKind {
    pub fn from_str(s: &str) -> Option<WhitelistKind> {
        match s {
            "domain" => Some(WhitelistKind::Domain),
            "process" => Some(WhitelistKind::Process),
            _ => None,
        }
    }
}

/// 白名单条目。
///
/// 语义：命中白名单的流量**不执行拦截**（请求侧 Block 规则降级为脱敏）；
/// 是否继续脱敏由 `scrub` 决定——`scrub = false` 时流量完全直通（不脱敏、不拦截）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub id: String,
    pub kind: WhitelistKind,
    pub pattern: String,
    /// 是否仍执行脱敏（用户决定）
    pub scrub: bool,
}

// ─────────── 黑名单 ───────────

/// 黑名单条目默认动作（旧持久化条目无 action 字段时回退）。
fn default_blacklist_action() -> String {
    "block".to_string()
}

/// 黑名单条目。语义：命中后**强制执行所选动作**（覆盖检测规则动作），优先级最高。
/// kind 复用 WhitelistKind（domain / process）；action = "block"（403 拦截）| "mask"（强制脱敏，Block 规则降级）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistEntry {
    pub id: String,
    pub kind: WhitelistKind,
    pub pattern: String,
    #[serde(default = "default_blacklist_action")]
    pub action: String,
}

/// 域名白名单匹配：精确相等，或 host 为 pattern 的子域名（`x.<pattern>`）。
pub fn domain_matches(pattern: &str, host: &str) -> bool {
    let pat = pattern.trim().to_ascii_lowercase();
    let host = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .to_ascii_lowercase();
    if pat.is_empty() || host.is_empty() {
        return false;
    }
    host == pat || host.ends_with(&format!(".{}", pat))
}

/// 进程白名单匹配（大小写不敏感）：
/// exe 完整路径精确匹配 / 目录前缀匹配 / 仅文件名匹配。
pub fn process_path_matches(pattern: &str, exe_path: &str) -> bool {
    let pat = pattern.trim().to_ascii_lowercase();
    let exe = exe_path.trim().to_ascii_lowercase();
    if pat.is_empty() || exe.is_empty() {
        return false;
    }
    let pat = pat.trim_end_matches(['\\', '/']);
    if exe == pat {
        return true;
    }
    if exe.starts_with(&format!("{}\\", pat)) || exe.starts_with(&format!("{}/", pat)) {
        return true;
    }
    if !pat.contains('\\') && !pat.contains('/') && exe.ends_with(&format!("\\{}", pat)) {
        return true;
    }
    false
}

/// emit 给前端的事件载荷（不包含任何原文）。
#[derive(Debug, Clone, Serialize)]
pub struct PiiEvent {
    pub session: String,
    pub kind: String,
    pub host: String,
    pub action: String,
    pub ts: String,
}

// ═══════════════════════ 审计配置 ═══════════════════════

/// kv key：审计配置
pub const KV_AUDIT_CONFIG: &str = "audit.config";
/// kv key：还原管道参数
pub const KV_RESTORE_LIMITS: &str = "restore.limits";

/// 审计配置（防护信号开关 + 入库门槛 + 保留策略 + 核查开关）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// 审计总开关
    pub enabled: bool,
    /// 信号开关（按语义信号名；依赖主动核查的两个信号按设计恒为关闭）
    pub signals: HashMap<String, bool>,
    /// 入库门槛（LOW/MEDIUM/HIGH/CRITICAL，默认 MEDIUM：LOW 是兼容性观察，不进默认视图）
    pub severity_floor: String,
    /// 审计事件保留天数（0 = 永久）
    pub retention_days: i64,
    /// 主动核查开关
    pub probes_enabled: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        let mut signals = HashMap::new();
        for (code, _, _, implemented) in SIGNAL_CATALOG {
            signals.insert(code.to_string(), implemented);
        }
        AuditConfig {
            enabled: true,
            signals,
            severity_floor: "MEDIUM".to_string(),
            retention_days: 7,
            probes_enabled: false,
        }
    }
}

impl AuditConfig {
    /// 该信号是否启用（依赖主动核查的两个信号无实现，恒 false）。
    pub fn signal_enabled(&self, signal: &str) -> bool {
        if !self.enabled {
            return false;
        }
        self.signals.get(signal).copied().unwrap_or(false)
    }

    fn floor_rank(&self) -> u8 {
        match self.severity_floor.to_ascii_uppercase().as_str() {
            "CRITICAL" => 4,
            "HIGH" => 3,
            "MEDIUM" => 2,
            "LOW" => 1,
            _ => 2,
        }
    }

    /// 该严重度是否达到入库门槛。
    pub fn allows(&self, severity: &str) -> bool {
        let rank = match severity {
            "CRITICAL" => 4,
            "HIGH" => 3,
            "MEDIUM" => 2,
            _ => 1,
        };
        rank >= self.floor_rank()
    }
}

/// 请求上下文（供响应侧审计做回声抑制 / 模型偷换对比）。
#[derive(Debug, Clone, Default)]
pub struct ReqInfo {
    /// 请求体里的 model 字段（模型偷换的基准真相）
    pub model: Option<String>,
    /// 请求体文本前段（回声抑制用；截断到 64KB）
    pub body_text: String,
    /// 请求体哈希
    pub hash: String,
    /// 主动核查标记（内部头剥离后记录，随发现上报）
    pub probe_id: String,
    /// 本次请求注册的 追踪标记（记忆残留的 prior 集合要排除它们）
    pub markers: Vec<String>,
}

const REQ_CTX_KEEP_SECS: u64 = 600;
const MARKER_TTL_SECS: f64 = 3600.0;
const MARKER_MAX: usize = 500;
/// 会话元信息（域名 / 进程 / 最后活动）的保留时长：超过则从活跃列表淘汰。
const SESSION_META_KEEP_SECS: u64 = 1800;
/// 托盘「最近事件」保留条数。
pub const RECENT_EVENT_MAX: usize = 8;
/// 两次桌面通知之间的最短间隔（同一批发现只弹一次，并防上游刷屏）。
const NOTIFY_MIN_INTERVAL_SECS: u64 = 3;
/// 请求体文本回声抑制采样上限。
pub const REQ_ECHO_SAMPLE_MAX: usize = 64 * 1024;

/// 严重度排序值（通知门槛比较用；未知一律 0）。
pub fn severity_rank(s: &str) -> u8 {
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

/// 从会话 key 中还原域名（best-effort）。
///
/// `derive_session` 生成的会话 key 形态：`conv:<host>:<id>` / `hdr:<host>:<value>` /
/// `key:<host>:<hash>`，兜底为 `ip:port`（无域名）。只用于界面展示。
pub fn host_from_session_key(session: &str) -> String {
    let mut it = session.splitn(3, ':');
    let kind = it.next().unwrap_or("");
    if !matches!(kind, "conv" | "hdr" | "key") {
        return String::new();
    }
    it.next().unwrap_or("").trim().to_string()
}

/// 会话元信息（**只含元信息**：域名、客户端可执行文件路径、最后活动时间）。
#[derive(Debug, Clone)]
pub struct SessionMeta {
    pub host: String,
    pub process: Option<String>,
    pub last_seen: Instant,
}

/// 活跃会话行（界面展示：域名 / 进程 / 占位符数量 / 最后活动时间）。
#[derive(Debug, Clone, Serialize)]
pub struct ActiveSessionRow {
    /// 会话标识（内部派生：对话 id / 会话头 / 密钥哈希 / 客户端地址）。
    /// 界面只展示其尾部短标识，不把完整标识铺在屏幕上。
    pub session: String,
    pub host: String,
    /// 客户端可执行文件完整路径（解析不到时为空串）
    pub process: String,
    /// 该会话内已建立的占位符映射条数
    pub placeholders: usize,
    /// 最后活动距今秒数
    pub idle_secs: u64,
    /// 是否在途（请求已发出、响应未回；TTL 清理会跳过它）
    pub pinned: bool,
}

/// kv key：桌面通知配置
pub const KV_NOTIFY_CONFIG: &str = "notify.config";

/// 桌面通知配置（拦截 / 高危事件弹系统通知；可选，默认开启、门槛 HIGH）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotifyConfig {
    pub enabled: bool,
    /// 触发通知的最低严重度（LOW / MEDIUM / HIGH / CRITICAL）
    pub severity_floor: String,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        NotifyConfig {
            enabled: true,
            severity_floor: "HIGH".to_string(),
        }
    }
}

impl NotifyConfig {
    /// 该严重度是否达到通知门槛（总开关关闭 / 门槛非法时恒 false）。
    pub fn allows(&self, severity: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let floor = severity_rank(&self.severity_floor);
        floor > 0 && severity_rank(severity) >= floor
    }
}

// ═══════════════════════ 界面语言 ═══════════════════════

/// kv key：界面语言（"zh" / "en"）。前端与后端共用，切换后托盘 / 通知同步跟随。
pub const KV_UI_LANGUAGE: &str = "ui.language";

// ═══════════════════════ 首次运行向导 ═══════════════════════

/// kv key：首次运行向导是否已完成（"1"/"0"）。
pub const KV_SETUP_COMPLETED: &str = "setup.completed";
/// kv key：已完成向导的版本号。版本升级后可据此决定是否重放向导。
pub const KV_SETUP_VERSION: &str = "setup.version";
/// 当前向导版本（步骤集合发生实质变化时递增）。
pub const SETUP_VERSION: &str = "1";

// ═══════════════════════ 全局快捷键 ═══════════════════════

/// kv key：全局快捷键配置
pub const KV_SHORTCUT_CONFIG: &str = "shortcut.config";

/// 默认「开关守护」快捷键。
pub const DEFAULT_SHORTCUT_TOGGLE: &str = "Ctrl+Alt+G";
/// 默认「一键应急切断」快捷键。
pub const DEFAULT_SHORTCUT_PANIC: &str = "Ctrl+Alt+X";

/// 可选的快捷键预设。快捷键是**全局抢占**按键——把任意字符串直接交给注册接口，
/// 等于让一次误配置就把用户的某个常用组合彻底吞掉，因此只提供白名单预设。
pub const SHORTCUT_PRESETS: &[&str] = &[
    "Ctrl+Alt+G",
    "Ctrl+Alt+H",
    "Ctrl+Alt+J",
    "Ctrl+Alt+K",
    "Ctrl+Alt+L",
    "Ctrl+Alt+X",
    "Ctrl+Alt+Y",
    "Ctrl+Shift+G",
    "Ctrl+Shift+X",
    "Ctrl+Alt+Shift+G",
    "Ctrl+Alt+Shift+X",
];

/// 全局快捷键配置（默认开启，键位取 `Ctrl+Alt+` 系——与常见应用冲突概率最低）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ShortcutConfig {
    pub enabled: bool,
    /// 开关守护
    pub toggle_guard: String,
    /// 一键应急切断
    pub panic: String,
}

impl Default for ShortcutConfig {
    fn default() -> Self {
        ShortcutConfig {
            enabled: true,
            toggle_guard: DEFAULT_SHORTCUT_TOGGLE.to_string(),
            panic: DEFAULT_SHORTCUT_PANIC.to_string(),
        }
    }
}

impl ShortcutConfig {
    /// 校验并规范化：预设白名单内、且两个动作不能撞键。
    pub fn normalized(mut self) -> Result<ShortcutConfig, String> {
        self.toggle_guard = normalize_accelerator(&self.toggle_guard)?;
        self.panic = normalize_accelerator(&self.panic)?;
        // ⚠ 撞键判定必须用**与书写顺序无关**的标识。
        // normalize_accelerator 的输出保留了用户输入顺序，所以 "Alt+Ctrl+G" 与
        // "Ctrl+Alt+G" 是两个不同的字符串、却是同一个物理键位——直接比字符串会漏判，
        // 两个动作绑到同一个热键上（注册时一个会静默失效）。
        if accelerator_identity(&self.toggle_guard) == accelerator_identity(&self.panic) {
            return Err("两个动作不能使用同一个快捷键".to_string());
        }
        Ok(self)
    }
}

/// 修饰键的规范顺序：`Ctrl → Alt → Shift → Super`。
///
/// **只用于比较**（白名单匹配、撞键判定），不改变 `normalize_accelerator` 的输出顺序——
/// 输出按用户输入顺序，保证「同一输入恒得同一输出」。
fn canonical_mod_order(mods: &[&'static str]) -> Vec<&'static str> {
    const ORDER: [&str; 4] = ["Ctrl", "Alt", "Shift", "Super"];
    ORDER.iter().copied().filter(|m| mods.contains(m)).collect()
}

/// 把**已规范化**的加速键（`normalize_accelerator` 的产物）折叠成与书写顺序无关的标识。
///
/// 调用前必须先过 `normalize_accelerator`——这里不做合法性校验，只重排修饰键顺序。
fn accelerator_identity(canon: &str) -> String {
    let mut parts: Vec<&str> = canon.split('+').map(str::trim).collect();
    let key = parts.pop().unwrap_or("");
    let mods: Vec<&'static str> = parts
        .iter()
        .filter_map(|p| match *p {
            "Ctrl" => Some("Ctrl"),
            "Alt" => Some("Alt"),
            "Shift" => Some("Shift"),
            "Super" => Some("Super"),
            _ => None,
        })
        .collect();
    format!("{}+{}", canonical_mod_order(&mods).join("+"), key)
}

/// 把用户给的加速键字符串规范化成 `Ctrl+Alt+G` 形态；不在预设白名单内则报错。
pub fn normalize_accelerator(raw: &str) -> Result<String, String> {
    let mut mods: Vec<&'static str> = Vec::new();
    let mut key: Option<String> = None;
    let parts: Vec<&str> = raw.split('+').map(str::trim).filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return Err("快捷键不能为空".to_string());
    }
    for (i, p) in parts.iter().enumerate() {
        let is_last = i == parts.len() - 1;
        let lower = p.to_ascii_lowercase();
        let m = match lower.as_str() {
            "ctrl" | "control" => Some("Ctrl"),
            "alt" => Some("Alt"),
            "shift" => Some("Shift"),
            "super" | "win" | "meta" => Some("Super"),
            _ => None,
        };
        match m {
            Some(m) => {
                if !is_last {
                    if mods.contains(&m) {
                        return Err(format!("修饰键重复: {}", raw));
                    }
                    mods.push(m);
                } else {
                    // 允许 "Ctrl+Alt+" 这类写法把修饰键写在末尾？不允许——末段必须是主键，
                    // 否则 "Ctrl+Alt" 会被当成一个可用快捷键，实际按不出来。
                    return Err(format!("快捷键缺少主键: {}", raw));
                }
            }
            None => {
                if !is_last {
                    return Err(format!("无法识别的修饰键: {}", p));
                }
                let up = p.to_ascii_uppercase();
                let ok = (up.len() == 1 && up.chars().all(|c| c.is_ascii_alphanumeric()))
                    || (up.len() >= 2
                        && up.len() <= 3
                        && up.starts_with('F')
                        && up[1..].parse::<u8>().map(|n| (1..=12).contains(&n)).unwrap_or(false));
                if !ok {
                    return Err(format!("无法识别的主键: {}", p));
                }
                key = Some(up);
            }
        }
    }
    if mods.is_empty() {
        return Err("快捷键必须至少包含一个修饰键（Ctrl / Alt / Shift / Super）".to_string());
    }
    let Some(key) = key else {
        return Err(format!("快捷键缺少主键: {}", raw));
    };
    let canon = format!("{}+{}", mods.join("+"), key);
    // 白名单按**规范顺序**匹配：修饰键的书写顺序不影响语义，
    // 所以 "Shift+Ctrl+Alt+G" 与预设里的 "Ctrl+Alt+Shift+G" 是同一个键位，必须一并放行。
    // （输出仍用上面的 canon，保持用户输入顺序。）
    let canonical = format!("{}+{}", canonical_mod_order(&mods).join("+"), key);
    if !SHORTCUT_PRESETS.contains(&canonical.as_str()) {
        return Err(format!("不支持的快捷键组合: {}（请从预设中选择）", canon));
    }
    Ok(canon)
}

// ═══════════════════════ 更新检查 ═══════════════════════

/// kv key：更新检查配置
pub const KV_UPDATE_CONFIG: &str = "update.config";
/// kv key：最近一次更新检查结果（JSON，仅在检查过之后存在）
pub const KV_UPDATE_STATUS: &str = "update.status";

/// 更新检查配置。
///
/// **默认整体关闭，且关闭时绝不发起任何网络请求**——这是一个隐私工具，
/// 任何"未经开启就对外通信"的行为都不可接受。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UpdateConfig {
    /// 是否启用更新检查（默认 false：不开则一次请求都不发）
    pub enabled: bool,
    /// 更新源仓库（`owner/name`，走 GitHub Releases API）
    pub repo: String,
}

/// 默认更新源仓库。
pub const DEFAULT_UPDATE_REPO: &str = "Technicalflight/aiguard";

impl Default for UpdateConfig {
    fn default() -> Self {
        UpdateConfig {
            enabled: false,
            repo: DEFAULT_UPDATE_REPO.to_string(),
        }
    }
}

impl UpdateConfig {
    /// 校验并规范化仓库标识（只允许 `owner/name` 两个 ASCII 段）。
    pub fn normalized(mut self) -> Result<UpdateConfig, String> {
        self.repo = self.repo.trim().to_string();
        let segs: Vec<&str> = self.repo.split('/').collect();
        let ok = segs.len() == 2
            && segs.iter().all(|s| {
                !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            });
        if !ok {
            return Err("更新源需要是 owner/name 形式（仅字母数字与 - _ .）".to_string());
        }
        Ok(self)
    }
}

/// 最近一次更新检查的结果（只读展示，不含任何本机信息）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct UpdateStatus {
    /// 检查时间（Unix 秒；0 = 从未检查）
    pub checked_at: i64,
    /// 当前版本
    pub current: String,
    /// 上游最新版本（去掉前导 v）
    pub latest: String,
    /// 是否有新版本
    pub has_update: bool,
    /// 发布标题
    pub release_name: String,
    /// 发布页面地址
    pub release_url: String,
    /// 发布时间（原样字符串）
    pub published_at: String,
    /// 结论说明（检查失败时为错误原因）
    pub note: String,
    /// 本次结果是否为失败
    pub failed: bool,
}

// ═══════════════════════ 关闭行为 ═══════════════════════

/// kv key：主窗关闭行为
pub const KV_CLOSE_BEHAVIOR: &str = "close.behavior";

/// 主窗关闭行为。
///
/// 点下关闭按钮（自绘标题栏 ✕ / Alt+F4 / 任务栏关闭都汇入同一条
/// `CloseRequested` 路径）时应用该行为：
/// - `Ask`（默认）：弹前端询问窗「退出程序 / 最小化到托盘」，勾「记住选择」后写回本配置；
/// - `Exit` / `Tray`：不再询问，直接按所选行为执行。
///
/// 序列化成小写字符串存 kv，前端用同一组字面量。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloseBehavior {
    /// 每次关闭时询问
    #[default]
    Ask,
    /// 直接退出程序（走托盘「退出」同一条清理路径）
    Exit,
    /// 直接最小化到托盘
    Tray,
}

impl CloseBehavior {
    pub fn as_str(self) -> &'static str {
        match self {
            CloseBehavior::Ask => "ask",
            CloseBehavior::Exit => "exit",
            CloseBehavior::Tray => "tray",
        }
    }

    /// 从 kv / 前端传来的字面量解析；非法值一律回退 Ask（宁可多问一次，
    /// 也不要让一份手改的 kv 让「点关闭毫无反应」）。
    pub fn parse(raw: &str) -> CloseBehavior {
        match raw.trim().to_ascii_lowercase().as_str() {
            "exit" => CloseBehavior::Exit,
            "tray" => CloseBehavior::Tray,
            _ => CloseBehavior::Ask,
        }
    }
}

impl Serialize for CloseBehavior {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CloseBehavior {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(CloseBehavior::parse(&raw))
    }
}

/// 当前应用版本（编译期确定）。
pub fn current_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// 版本号比较：`a` 是否比 `b` 新。按 `.` 分段逐段比数字，非数字段退化为字符串比较。
pub fn version_is_newer(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        s.trim()
            .trim_start_matches('v')
            .split(['-', '+'])
            .next()
            .unwrap_or("")
            .to_string()
    };
    let (an, bn) = (norm(a), norm(b));
    let pa: Vec<&str> = an.split('.').collect();
    let pb: Vec<&str> = bn.split('.').collect();
    for i in 0..pa.len().max(pb.len()) {
        let x = pa.get(i).copied().unwrap_or("0");
        let y = pb.get(i).copied().unwrap_or("0");
        match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(nx), Ok(ny)) => {
                if nx != ny {
                    return nx > ny;
                }
            }
            _ => {
                if x != y {
                    return x > y;
                }
            }
        }
    }
    false
}

/// 生成桌面通知文案 —— 已迁至 [`crate::i18n::notify_text`]。
///
/// 迁走的理由：所有**离开窗口**的文案（托盘菜单 / 托盘提示 / 桌面通知）必须集中在
/// 一处，才能保证每加一条文案都同时补齐中英文；散落在各模块里必然漏。
/// 纯函数与脱敏约束（只含严重度 / 信号展示名 / 域名，绝不拼 `evidence`）原样保留。

/// 淘汰过期请求上下文，**淘汰前覆写**其中的请求正文采样（含脱敏前原文）。
fn purge_req_ctx(m: &mut HashMap<String, (Instant, ReqInfo)>, now: Instant) {
    let expired: Vec<String> = m
        .iter()
        .filter(|(_, (t, _))| now.duration_since(*t).as_secs() >= REQ_CTX_KEEP_SECS)
        .map(|(k, _)| k.clone())
        .collect();
    for k in expired {
        if let Some((_, mut info)) = m.remove(&k) {
            aiguard_core::mem::wipe_string(&mut info.body_text);
        }
    }
}

/// 全局共享状态。
pub struct AppState {
    /// 检测引擎（请求侧脱敏主链路；RwLock 支持运行时热更新规则）
    pub detector: RwLock<Arc<Detector>>,
    /// 保险柜配置（响应侧访问告警读键名用；请求侧引擎在 Detector.locker 内）
    pub locker: RwLock<aiguard_core::locker::LockerConfig>,
    /// 原文 ↔ 占位符映射表（仅内存；Arc 共享给还原管道）
    pub vault: Arc<Vault>,
    /// 还原管道参数
    pub restore_limits: RwLock<RestoreLimits>,
    /// 审计配置
    pub audit: RwLock<AuditConfig>,
    /// 审计事件异步写入口
    pub audit_writer: AuditWriter,
    /// 追踪标记 注册表：nonce → 注册时间（记忆残留核查用）
    pub marker_registry: Mutex<HashMap<String, f64>>,
    /// 请求上下文：client addr → (最近时间, 请求信息)
    pub req_ctx: Mutex<HashMap<String, (Instant, ReqInfo)>>,
    /// 请求侧会话缓存：client addr -> (写入时间, session)
    pub addr_sessions: RwLock<HashMap<String, (Instant, String)>>,
    /// 会话元信息：session -> (域名 / 进程 / 首次与最后活动时间)
    pub session_meta: RwLock<HashMap<String, SessionMeta>>,
    /// 最近安全事件（托盘「最近事件」用；只含脱敏后的元信息）
    pub recent_events: RwLock<VecDeque<AuditEventRow>>,
    /// 桌面通知配置
    pub notify: RwLock<NotifyConfig>,
    /// 上次桌面通知时间（防刷屏）
    notify_last: Mutex<Option<Instant>>,
    /// 界面语言（前端切换后写回这里，托盘 / 通知据此取词）
    pub language: RwLock<Language>,
    /// 全局快捷键配置
    pub shortcut: RwLock<ShortcutConfig>,
    /// 更新检查配置
    pub update: RwLock<UpdateConfig>,
    /// 最近一次更新检查结果
    pub update_status: RwLock<UpdateStatus>,
    /// 主窗关闭行为（每次询问 / 直接退出 / 直接最小化到托盘）
    pub close_behavior: RwLock<CloseBehavior>,
    /// 受守护连接的标记：client addr -> 最近一次 AI 域名请求时间
    pub guarded_addrs: RwLock<HashMap<String, Instant>>,
    /// SQLite 日志存储
    pub store: crate::store::Store,
    /// 应用配置
    pub config: RwLock<Config>,
    /// 本地代理访问控制（loopback 强制 + 可选令牌）
    pub access: RwLock<AccessControl>,
    /// 白名单
    pub whitelist: RwLock<Vec<WhitelistEntry>>,
    /// 黑名单（命中即强制拦截）
    pub blacklist: RwLock<Vec<BlacklistEntry>>,
    /// 客户端进程解析缓存：client port -> (解析时间, exe 路径)
    pub proc_cache: std::sync::Mutex<HashMap<u16, (std::time::Instant, Option<String>)>>,
    /// 已见过的代理客户端进程（本进程生命周期内去重，用于首次审计上报）
    pub seen_client_procs: Mutex<HashSet<String>>,
    /// 是否检测到调试器附加（启动 + 周期检查；仅告警，不阻断）
    pub debugger_detected: AtomicBool,
    /// 启动自检结论（端口 / 私钥 / 目录权限的简明中文提示，界面直接展示）
    pub startup_notes: RwLock<Vec<String>>,
    /// 守护的 AI 域名集合
    #[allow(dead_code)]
    pub ai_hosts: HashSet<&'static str>,
    /// Tauri AppHandle（用于向前端 emit 事件，setup 阶段注入）
    pub app_handle: RwLock<Option<tauri::AppHandle>>,
    /// 代理启动时间
    pub started_at: Instant,
    /// 数据目录（审计报告落盘用，预留）
    #[allow(dead_code)]
    pub data_dir: PathBuf,
}

/// kv key：白名单持久化
pub const KV_WHITELIST: &str = "whitelist.entries";
/// kv key：黑名单持久化
pub const KV_BLACKLIST: &str = "blacklist.entries";
/// kv key：本地代理是否要求令牌（"1"/"0"）
pub const KV_REQUIRE_TOKEN: &str = "guard.require_token";
/// kv key：本地代理令牌（32 位 hex，首次启动生成）
pub const KV_PROXY_TOKEN: &str = "guard.proxy_token";

/// 本地代理访问控制。
///
/// 默认**只按 loopback 放行**（代理端口本身只绑 127.0.0.1）；
/// `require_token` 为可选加严：要求客户端在代理级请求（CONNECT / absolute-form）
/// 携带 `Proxy-Authorization: Basic <任意用户名>:<令牌>`。
///
/// 说明：浏览器经 PAC 拿到的是无凭据的 `PROXY 127.0.0.1:port`，**无法携带令牌**，
/// 因此该开关适合"只有 CLI/SDK 走代理"的场景；默认关闭。
#[derive(Debug, Clone, Default)]
pub struct AccessControl {
    pub require_token: bool,
    pub token: String,
}

impl AccessControl {
    /// 令牌是否已生成且可用。
    pub fn has_token(&self) -> bool {
        self.token.len() >= 16
    }

    /// 恒定时间比较（避免按字节提前返回泄漏令牌长度/前缀）。
    pub fn token_matches(&self, candidate: &str) -> bool {
        let a = self.token.as_bytes();
        let b = candidate.as_bytes();
        if a.is_empty() || a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for i in 0..a.len() {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }
}

/// 生成新的本地代理令牌（32 位 hex）。
pub fn generate_proxy_token() -> String {
    let mut s = String::new();
    for _ in 0..4 {
        s.push_str(&uuid::Uuid::new_v4().simple().to_string()[..8]);
    }
    s
}

impl AppState {
    pub fn new(store: crate::store::Store, db_path: &PathBuf, data_dir: PathBuf) -> AppState {
        let whitelist: Vec<WhitelistEntry> = store
            .kv_get(KV_WHITELIST)
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();
        let blacklist: Vec<BlacklistEntry> = store
            .kv_get(KV_BLACKLIST)
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();
        let mut audit = store
            .kv_get(KV_AUDIT_CONFIG)
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str::<AuditConfig>(&json).ok())
            .unwrap_or_default();
        // 版本演进：存量配置里没有的新信号键，按目录默认值补齐
        // （不覆盖用户已显式设置过的开关）
        for (code, _, _, implemented) in SIGNAL_CATALOG {
            audit.signals.entry(code.to_string()).or_insert(implemented);
        }
        let restore_limits = store
            .kv_get(KV_RESTORE_LIMITS)
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str::<RestoreLimits>(&json).ok())
            .unwrap_or_default();
        let notify = store
            .kv_get(KV_NOTIFY_CONFIG)
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str::<NotifyConfig>(&json).ok())
            .unwrap_or_default();
        let language = Language::parse(
            &store
                .kv_get(KV_UI_LANGUAGE)
                .ok()
                .flatten()
                .unwrap_or_default(),
        );
        // 快捷键 / 更新检查：读回来的配置也走一遍规范化，非法值直接回退默认
        // （旧版本残留或手改 kv 都可能塞进一份不可用的键位，启动时不该被它拖垮）
        let shortcut = store
            .kv_get(KV_SHORTCUT_CONFIG)
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str::<ShortcutConfig>(&json).ok())
            .unwrap_or_default()
            .normalized()
            .unwrap_or_default();
        let update = store
            .kv_get(KV_UPDATE_CONFIG)
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str::<UpdateConfig>(&json).ok())
            .unwrap_or_default();
        let update_status = store
            .kv_get(KV_UPDATE_STATUS)
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str::<UpdateStatus>(&json).ok())
            .unwrap_or_default();
        // 关闭行为：非法值回退 Ask（parse 内置兜底，宁可多问一次也不静默失效）
        let close_behavior = CloseBehavior::parse(
            &store
                .kv_get(KV_CLOSE_BEHAVIOR)
                .ok()
                .flatten()
                .unwrap_or_default(),
        );
        // 审计事件后台写线程（独立连接，不阻塞流量路径）
        let audit_writer = AuditWriter::spawn(db_path).unwrap_or_else(|e| {
            log::error!("审计写线程启动失败（审计事件将无法落库）: {}", e);
            let fallback = data_dir.join("audit-fallback.db");
            AuditWriter::spawn(&fallback).expect("降级审计写线程必须能启动")
        });
        // 本地代理令牌：不存在则生成并落盘（首次启动）。
        // 落盘用 DPAPI 加密（`enc:<hex>`），旧版明文会自动迁移；解密失败则重新生成
        // ——宁可使旧令牌失效，也不静默退回明文。
        let token = match store.kv_get(KV_PROXY_TOKEN).ok().flatten() {
            Some(raw) if !raw.trim().is_empty() => {
                let (plain, need_migrate) = crate::security::decode_secret_from_store(&raw);
                if plain.len() < 16 {
                    log::warn!("本地代理令牌不可用（无法解密或不合法），将重新生成");
                    let t = generate_proxy_token();
                    if let Err(e) =
                        store.kv_set(KV_PROXY_TOKEN, &crate::security::encode_secret_for_store(&t))
                    {
                        log::warn!("本地代理令牌落盘失败: {}", safe_err(&e));
                    }
                    t
                } else {
                    if need_migrate {
                        if let Err(e) = store.kv_set(
                            KV_PROXY_TOKEN,
                            &crate::security::encode_secret_for_store(&plain),
                        ) {
                            log::warn!("本地代理令牌加密迁移失败: {}", safe_err(&e));
                        }
                    }
                    plain
                }
            }
            _ => {
                let t = generate_proxy_token();
                if let Err(e) =
                    store.kv_set(KV_PROXY_TOKEN, &crate::security::encode_secret_for_store(&t))
                {
                    log::warn!("本地代理令牌落盘失败: {}", safe_err(&e));
                }
                t
            }
        };
        let require_token = store
            .kv_get(KV_REQUIRE_TOKEN)
            .ok()
            .flatten()
            .map(|v| v == "1")
            .unwrap_or(false);
        let access = AccessControl {
            require_token,
            token,
        };
        AppState {
            detector: RwLock::new(Arc::new(Detector::with_default_rules())),
            locker: RwLock::new(aiguard_core::locker::LockerConfig::default()),
            vault: Arc::new(Vault::new()),
            restore_limits: RwLock::new(restore_limits),
            audit: RwLock::new(audit),
            audit_writer,
            marker_registry: Mutex::new(HashMap::new()),
            req_ctx: Mutex::new(HashMap::new()),
            addr_sessions: RwLock::new(HashMap::new()),
            session_meta: RwLock::new(HashMap::new()),
            recent_events: RwLock::new(VecDeque::new()),
            notify: RwLock::new(notify),
            notify_last: Mutex::new(None),
            language: RwLock::new(language),
            shortcut: RwLock::new(shortcut),
            update: RwLock::new(update),
            update_status: RwLock::new(update_status),
            close_behavior: RwLock::new(close_behavior),
            guarded_addrs: RwLock::new(HashMap::new()),
            store,
            config: RwLock::new(Config::default()),
            access: RwLock::new(access),
            whitelist: RwLock::new(whitelist),
            blacklist: RwLock::new(blacklist),
            proc_cache: std::sync::Mutex::new(HashMap::new()),
            seen_client_procs: Mutex::new(HashSet::new()),
            debugger_detected: AtomicBool::new(false),
            startup_notes: RwLock::new(Vec::new()),
            ai_hosts: AI_HOSTS.iter().copied().collect(),
            app_handle: RwLock::new(None),
            started_at: Instant::now(),
            data_dir,
        }
    }

    /// 当前审计配置快照（poison 时降级取内部值，绝不 panic）。
    pub fn audit_config(&self) -> AuditConfig {
        match self.audit.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 当前还原管道参数快照。
    pub fn restore_limits_snapshot(&self) -> RestoreLimits {
        match self.restore_limits.read() {
            Ok(l) => l.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 保存审计配置：落盘 + 热更新（依赖主动核查的信号强制关闭）。
    pub fn apply_audit_config(&self, cfg: AuditConfig) -> Result<AuditConfig, String> {
        let mut cfg = cfg;
        for (code, _, _, implemented) in SIGNAL_CATALOG {
            if !implemented {
                cfg.signals.insert(code.to_string(), false);
            }
        }
        let json = serde_json::to_string(&cfg).map_err(|e| safe_err(&e))?;
        self.store.kv_set(KV_AUDIT_CONFIG, &json)?;
        match self.audit.write() {
            Ok(mut g) => *g = cfg.clone(),
            Err(poisoned) => *poisoned.into_inner() = cfg.clone(),
        }
        Ok(cfg)
    }

    /// 保存还原管道参数。
    pub fn apply_restore_limits(&self, limits: RestoreLimits) -> Result<RestoreLimits, String> {
        let mut l = limits;
        l.max_buffer_size = l.max_buffer_size.clamp(4 * 1024, 64 * 1024 * 1024);
        l.max_placeholder_len = l.max_placeholder_len.clamp(16, 4096);
        let json = serde_json::to_string(&l).map_err(|e| safe_err(&e))?;
        self.store.kv_set(KV_RESTORE_LIMITS, &json)?;
        match self.restore_limits.write() {
            Ok(mut g) => *g = l.clone(),
            Err(poisoned) => *poisoned.into_inner() = l.clone(),
        }
        Ok(l)
    }

    /// 当前检测引擎快照。
    pub fn detector_snapshot(&self) -> Arc<Detector> {
        match self.detector.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 保险柜凭据值条目的键名清单（响应侧点名告警用）。
    pub fn locker_keys(&self) -> Vec<String> {
        let cfg = match self.locker.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        cfg.entries
            .iter()
            .filter(|e| e.enabled && e.kind == "value")
            .map(|e| e.name.clone())
            .collect()
    }

    /// 保险柜路径保护条目清单（响应侧访问告警用）。
    pub fn locker_paths(&self) -> Vec<String> {
        let cfg = match self.locker.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        cfg.entries
            .iter()
            .filter(|e| e.enabled && e.kind == "path")
            .map(|e| e.value.clone())
            .collect()
    }

    /// 记录请求侧使用的会话（供响应侧对齐）。
    pub fn remember_session(&self, client_addr: &str, session: &str) {
        if let Ok(mut m) = self.addr_sessions.write() {
            if m.len() > 512 {
                let now = Instant::now();
                m.retain(|_, (t, _)| now.duration_since(*t).as_secs() < REQ_CTX_KEEP_SECS);
            }
            m.insert(
                client_addr.to_string(),
                (Instant::now(), session.to_string()),
            );
        }
    }

    /// 取出该连接最近一次请求使用的会话（无则回退为 addr 派生）。
    pub fn session_for_addr(&self, client_addr: &str) -> String {
        match self.addr_sessions.read() {
            Ok(m) => m
                .get(client_addr)
                .filter(|(t, _)| t.elapsed().as_secs() < REQ_CTX_KEEP_SECS)
                .map(|(_, s)| s.clone())
                .unwrap_or_else(|| session_key_from_client_addr(client_addr)),
            Err(poisoned) => poisoned
                .into_inner()
                .get(client_addr)
                .filter(|(t, _)| t.elapsed().as_secs() < REQ_CTX_KEEP_SECS)
                .map(|(_, s)| s.clone())
                .unwrap_or_else(|| session_key_from_client_addr(client_addr)),
        }
    }

    /// 记录一次会话活动（域名 / 客户端进程归属 + 最后活动时间）。
    ///
    /// **只保存元信息**：域名、可执行文件路径、时间戳，绝不涉及请求正文与原文。
    pub fn note_session_activity(&self, session: &str, host: &str, process: Option<&str>) {
        if session.trim().is_empty() {
            return;
        }
        let now = Instant::now();
        let mut guard = match self.session_meta.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // 超量时先按空闲时长淘汰，避免长时间运行后无界增长
        if guard.len() > 512 {
            guard.retain(|_, m| now.duration_since(m.last_seen).as_secs() < SESSION_META_KEEP_SECS);
        }
        match guard.get_mut(session) {
            Some(m) => {
                m.last_seen = now;
                if !host.trim().is_empty() {
                    m.host = host.trim().to_string();
                }
                if let Some(p) = process {
                    m.process = Some(p.to_string());
                }
            }
            None => {
                guard.insert(
                    session.to_string(),
                    SessionMeta {
                        host: host.trim().to_string(),
                        process: process.map(|p| p.to_string()),
                        last_seen: now,
                    },
                );
            }
        }
    }

    /// 活跃会话快照：合并「会话元信息」与「映射表」两个来源，按最后活动时间倒序。
    ///
    /// 两个来源缺一不可：元信息覆盖**所有**经过代理的 AI 请求（含 0 命中的直通请求），
    /// 映射表覆盖**已建立占位符**的会话（含只由响应侧还原触发的会话）。
    pub fn active_sessions(&self) -> Vec<ActiveSessionRow> {
        let now = Instant::now();
        let mut rows: Vec<ActiveSessionRow> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        {
            let guard = match self.session_meta.read() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            for (session, meta) in guard.iter() {
                let idle_meta = now.duration_since(meta.last_seen).as_secs();
                if idle_meta >= SESSION_META_KEEP_SECS {
                    continue;
                }
                seen.insert(session.clone());
                rows.push(ActiveSessionRow {
                    session: session.clone(),
                    host: if meta.host.is_empty() {
                        host_from_session_key(session)
                    } else {
                        meta.host.clone()
                    },
                    process: meta.process.clone().unwrap_or_default(),
                    placeholders: self.vault.session_count(session),
                    // 映射表里的 touch 更贴近真实活动（响应侧还原也会刷新），优先取它
                    idle_secs: self
                        .vault
                        .idle_for(session)
                        .map(|d| d.as_secs())
                        .unwrap_or(idle_meta),
                    pinned: self.vault.is_pinned(session),
                });
            }
        }
        for session in self.vault.session_ids() {
            if seen.contains(&session) {
                continue;
            }
            rows.push(ActiveSessionRow {
                session: session.clone(),
                host: host_from_session_key(&session),
                process: String::new(),
                placeholders: self.vault.session_count(&session),
                idle_secs: self
                    .vault
                    .idle_for(&session)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                pinned: self.vault.is_pinned(&session),
            });
        }
        rows.sort_by_key(|r| r.idle_secs);
        rows
    }

    /// 应急：清空**全部内存态**（映射表 / 请求正文采样 / 会话对齐 / 追踪标记 / 进程缓存）。
    ///
    /// 返回 (销毁的会话数, 覆写的映射条数, 擦除的请求采样条数)。
    /// 承载原文的两张表由 [`Vault::clear_session`] 逐字段零化覆写后释放。
    pub fn purge_all_memory(&self) -> (usize, usize, usize) {
        let ids = self.vault.session_ids();
        let mut mappings = 0usize;
        for id in &ids {
            mappings += self.vault.session_count(id);
            self.vault.clear_session(id);
        }
        let mut samples = 0usize;
        if let Ok(mut m) = self.req_ctx.lock() {
            samples = m.len();
            for (_, (_, mut info)) in m.drain() {
                aiguard_core::mem::wipe_string(&mut info.body_text);
            }
        }
        if let Ok(mut m) = self.addr_sessions.write() {
            m.clear();
        }
        if let Ok(mut m) = self.guarded_addrs.write() {
            m.clear();
        }
        if let Ok(mut m) = self.session_meta.write() {
            m.clear();
        }
        if let Ok(mut m) = self.marker_registry.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.proc_cache.lock() {
            m.clear();
        }
        (ids.len(), mappings, samples)
    }

    /// 当前桌面通知配置快照。
    pub fn notify_config(&self) -> NotifyConfig {
        match self.notify.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 保存桌面通知配置：落盘 + 热更新。
    pub fn apply_notify_config(&self, cfg: NotifyConfig) -> Result<NotifyConfig, String> {
        let json = serde_json::to_string(&cfg).map_err(|e| safe_err(&e))?;
        self.store.kv_set(KV_NOTIFY_CONFIG, &json)?;
        match self.notify.write() {
            Ok(mut g) => *g = cfg.clone(),
            Err(poisoned) => *poisoned.into_inner() = cfg.clone(),
        }
        Ok(cfg)
    }

    /// 当前界面语言快照。
    pub fn language(&self) -> Language {
        match self.language.read() {
            Ok(g) => *g,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// 保存界面语言：落盘 + 热更新（托盘菜单与桌面通知立即跟随）。
    pub fn apply_language(&self, lang: Language) -> Result<Language, String> {
        self.store.kv_set(KV_UI_LANGUAGE, lang.as_str())?;
        match self.language.write() {
            Ok(mut g) => *g = lang,
            Err(poisoned) => *poisoned.into_inner() = lang,
        }
        Ok(lang)
    }

    /// 当前全局快捷键配置快照。
    pub fn shortcut_config(&self) -> ShortcutConfig {
        match self.shortcut.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 保存全局快捷键配置（**只落盘 + 更新内存**；真正注册到系统由命令层负责，
    /// 因为注册需要 AppHandle，且注册失败必须整体回滚配置）。
    pub fn apply_shortcut_config(&self, cfg: ShortcutConfig) -> Result<ShortcutConfig, String> {
        let json = serde_json::to_string(&cfg).map_err(|e| safe_err(&e))?;
        self.store.kv_set(KV_SHORTCUT_CONFIG, &json)?;
        match self.shortcut.write() {
            Ok(mut g) => *g = cfg.clone(),
            Err(poisoned) => *poisoned.into_inner() = cfg.clone(),
        }
        Ok(cfg)
    }

    /// 当前更新检查配置快照。
    pub fn update_config(&self) -> UpdateConfig {
        match self.update.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 保存更新检查配置（落盘 + 热更新）。
    pub fn apply_update_config(&self, cfg: UpdateConfig) -> Result<UpdateConfig, String> {
        let json = serde_json::to_string(&cfg).map_err(|e| safe_err(&e))?;
        self.store.kv_set(KV_UPDATE_CONFIG, &json)?;
        match self.update.write() {
            Ok(mut g) => *g = cfg.clone(),
            Err(poisoned) => *poisoned.into_inner() = cfg.clone(),
        }
        Ok(cfg)
    }

    /// 最近一次更新检查结果快照。
    pub fn update_status(&self) -> UpdateStatus {
        match self.update_status.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 记录一次更新检查结果（落盘 + 热更新）。
    pub fn apply_update_status(&self, st: UpdateStatus) -> Result<UpdateStatus, String> {
        let json = serde_json::to_string(&st).map_err(|e| safe_err(&e))?;
        self.store.kv_set(KV_UPDATE_STATUS, &json)?;
        match self.update_status.write() {
            Ok(mut g) => *g = st.clone(),
            Err(poisoned) => *poisoned.into_inner() = st.clone(),
        }
        Ok(st)
    }

    /// 当前主窗关闭行为快照。
    pub fn close_behavior(&self) -> CloseBehavior {
        match self.close_behavior.read() {
            Ok(g) => *g,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// 保存主窗关闭行为（落盘 + 热更新）。CloseRequested 分流与设置页共用同一份。
    pub fn apply_close_behavior(&self, b: CloseBehavior) -> Result<CloseBehavior, String> {
        self.store.kv_set(KV_CLOSE_BEHAVIOR, b.as_str())?;
        match self.close_behavior.write() {
            Ok(mut g) => *g = b,
            Err(poisoned) => *poisoned.into_inner() = b,
        }
        Ok(b)
    }

    /// 最近安全事件快照（最新在前）。
    pub fn recent_events_snapshot(&self) -> Vec<AuditEventRow> {
        match self.recent_events.read() {
            Ok(v) => v.iter().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().iter().cloned().collect(),
        }
    }

    /// 达到门槛的安全事件弹系统通知。
    ///
    /// 三条克制规则：
    /// 1. 主窗口在前台时不打扰（用户正看着界面，界面里本就有实时告警）；
    /// 2. 同一批只弹一条（取批内最高严重度），并做最小间隔限流；
    /// 3. 通知内容只含严重度 / 信号中文名 / 域名，**绝不带 evidence**。
    ///
    /// 任何失败只记日志，绝不影响审计落库与流量处理。
    fn dispatch_notification(&self, events: &[AuditEventRow]) {
        if events.is_empty() {
            return;
        }
        let cfg = self.notify_config();
        // 批内最高严重度达标才弹（总开关与门槛合法性由 allows 统一判定）
        let top = events
            .iter()
            .map(|e| e.severity.as_str())
            .max_by_key(|s| severity_rank(s))
            .unwrap_or("LOW");
        if !cfg.allows(top) {
            return;
        }
        let top_rank = severity_rank(top);
        let guard = match self.app_handle.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(handle) = guard.as_ref() else {
            return;
        };
        {
            use tauri::Manager;
            if let Some(win) = handle.get_webview_window("main") {
                if win.is_focused().unwrap_or(false) {
                    return;
                }
            }
        }
        {
            let mut last = match self.notify_last.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(t) = *last {
                if t.elapsed().as_secs() < NOTIFY_MIN_INTERVAL_SECS {
                    return;
                }
            }
            *last = Some(Instant::now());
        }
        let (title, body) = crate::i18n::notify_text(self.language(), events, top_rank);
        use tauri_plugin_notification::NotificationExt;
        if let Err(e) = handle.notification().builder().title(title).body(body).show() {
            log::warn!("系统通知发送失败（不影响审计记录）: {}", safe_err(&e));
        }
    }

    /// 记录请求上下文（model / 正文采样 / 哈希），供响应侧审计。
    ///
    /// `body_text` 是**脱敏前的请求正文采样**（含原文），因此覆盖写与淘汰时
    /// 必须先做内存擦除（见 [`aiguard_core::mem`]），避免原文残留在堆上。
    pub fn remember_req_info(&self, client_addr: &str, info: ReqInfo) {
        if let Ok(mut m) = self.req_ctx.lock() {
            let now = Instant::now();
            if m.len() > 512 {
                purge_req_ctx(&mut m, now);
            }
            if let Some((_, mut old)) = m.remove(client_addr) {
                aiguard_core::mem::wipe_string(&mut old.body_text);
            }
            m.insert(client_addr.to_string(), (now, info));
        }
    }

    /// 取出该连接最近一次请求的信息（无则默认空）。
    pub fn req_info_for(&self, client_addr: &str) -> ReqInfo {
        let take = |m: &HashMap<String, (Instant, ReqInfo)>| -> Option<ReqInfo> {
            m.get(client_addr)
                .filter(|(t, _)| t.elapsed().as_secs() < REQ_CTX_KEEP_SECS)
                .map(|(_, i)| i.clone())
        };
        match self.req_ctx.lock() {
            Ok(m) => take(&m).unwrap_or_default(),
            Err(poisoned) => take(&poisoned.into_inner()).unwrap_or_default(),
        }
    }

    /// 周期清理过期的请求上下文（含请求正文采样**内存擦除**），返回清理条数。
    pub fn purge_expired_req_ctx(&self) -> usize {
        if let Ok(mut m) = self.req_ctx.lock() {
            let before = m.len();
            purge_req_ctx(&mut m, Instant::now());
            return before - m.len();
        }
        0
    }

    /// 记录一个代理客户端进程（exe 完整路径）。
    ///
    /// 返回 `true` 表示**本进程生命周期内首次见到**（调用方可据此只上报一次）。
    /// 仅作审计展示，不参与任何放行判定。
    pub fn note_client_process(&self, exe: String) -> bool {
        if exe.trim().is_empty() {
            return false;
        }
        if let Ok(mut set) = self.seen_client_procs.lock() {
            set.insert(exe)
        } else {
            false
        }
    }

    /// 已见过的代理客户端进程列表（审计/界面展示用；按首次出现顺序）。
    pub fn client_processes(&self) -> Vec<String> {
        match self.seen_client_procs.lock() {
            Ok(set) => set.iter().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().iter().cloned().collect(),
        }
    }

    /// 记录一次调试器检测结果。返回 `true` 表示**本次是新发现**（用于只告警一次）。
    pub fn note_debugger_state(&self, attached: bool) -> bool {
        if attached && !self.debugger_detected.swap(true, Ordering::Relaxed) {
            return true;
        }
        false
    }

    /// 当前是否处于「检测到调试器」状态。
    pub fn debugger_seen(&self) -> bool {
        self.debugger_detected.load(Ordering::Relaxed)
    }

    /// 追加一条启动自检提示（中文，界面直接展示）。
    pub fn push_startup_note(&self, note: String) {
        let note = note.trim().to_string();
        if note.is_empty() {
            return;
        }
        log::info!("强制加固自检: {}", note);
        match self.startup_notes.write() {
            Ok(mut v) => {
                if v.len() < 16 {
                    v.push(note);
                }
            }
            Err(poisoned) => {
                let mut v = poisoned.into_inner();
                if v.len() < 16 {
                    v.push(note);
                }
            }
        }
    }

    /// 启动自检提示快照。
    pub fn startup_notes_snapshot(&self) -> Vec<String> {
        match self.startup_notes.read() {
            Ok(v) => v.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }


    /// 标记该连接承载了受守护的 AI 流量。
    pub fn mark_guarded(&self, client_addr: &str) {
        if let Ok(mut m) = self.guarded_addrs.write() {
            let now = Instant::now();
            if m.len() > 512 {
                m.retain(|_, t| now.duration_since(*t).as_secs() < REQ_CTX_KEEP_SECS);
            }
            m.insert(client_addr.to_string(), now);
        }
    }

    /// 该连接最近 10 分钟内是否承载过受守护流量。
    pub fn is_guarded(&self, client_addr: &str) -> bool {
        match self.guarded_addrs.read() {
            Ok(m) => m
                .get(client_addr)
                .map(|t| t.elapsed().as_secs() < REQ_CTX_KEEP_SECS)
                .unwrap_or(false),
            Err(poisoned) => poisoned
                .into_inner()
                .get(client_addr)
                .map(|t| t.elapsed().as_secs() < REQ_CTX_KEEP_SECS)
                .unwrap_or(false),
        }
    }

    /// 注册 追踪标记（核查 seed 请求注入的标记）。
    pub fn register_markers(&self, nonces: &[String]) {
        let now = now_secs_f64();
        let mut reg = match self.marker_registry.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        for n in nonces {
            let n = n.trim();
            if !n.is_empty() {
                reg.insert(n.to_string(), now);
            }
        }
        reg.retain(|_, ts| now - *ts < MARKER_TTL_SECS);
        if reg.len() > MARKER_MAX {
            let mut items: Vec<(String, f64)> =
                reg.iter().map(|(k, v)| (k.clone(), *v)).collect();
            items.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            let overflow = reg.len() - MARKER_MAX;
            for (k, _) in items.into_iter().take(overflow) {
                reg.remove(&k);
            }
        }
    }

    /// 取出全部**在册** nonce 作为 prior 集合（可剔除本次请求自己的）。
    pub fn prior_markers(&self, exclude: &[String]) -> HashSet<String> {
        let now = now_secs_f64();
        let reg = match self.marker_registry.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        reg.iter()
            .filter(|(k, ts)| now - *ts < MARKER_TTL_SECS && !exclude.iter().any(|e| e == *k))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// 落库一批审计发现：按信号开关与入库门槛过滤后交给后台写线程。
    ///
    /// 严格**只告警不改写**：这里只做记录，绝不修改响应内容。
    pub fn record_findings(
        &self,
        findings: Vec<aiguard_core::audit::Finding>,
        meta: &FindingMeta,
    ) -> usize {
        let cfg = self.audit_config();
        if !cfg.enabled {
            return 0;
        }
        let ts = now_secs_f64();
        let mut events: Vec<AuditEventRow> = Vec::new();
        for f in findings {
            // 开关按语义信号名过滤
            if !cfg.signal_enabled(&f.signal) {
                continue;
            }
            // 入库门槛：LOW 的兼容性观察默认不进视图
            if !cfg.allows(f.severity.as_str()) {
                continue;
            }
            events.push(AuditEventRow {
                seq: 0,
                ts,
                sid: meta.sid.clone(),
                host: meta.host.clone(),
                method: meta.method.clone(),
                path: meta.path.clone(),
                signal_type: f.signal.clone(),
                severity: f.severity.as_str().to_string(),
                evidence: f.evidence.clone(),
                request_hash: meta.request_hash.clone(),
                response_hash: meta.response_hash.clone(),
                probe_id: meta.probe_id.clone(),
            });
        }
        let n = events.len();
        if n > 0 {
            self.audit_writer.enqueue_batch(events.clone());
            // 托盘「最近事件」环形缓冲（最新在前）
            {
                let mut v = match self.recent_events.write() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                for ev in events.iter().rev() {
                    v.push_front(ev.clone());
                }
                while v.len() > RECENT_EVENT_MAX {
                    v.pop_back();
                }
            }
            // 实时告警给前端（payload 为同一脱敏结构，不含原文）
            for ev in events.iter() {
                self.emit_event("security-alert", ev.clone());
            }
            // 达到门槛时弹系统通知（仅在窗口未聚焦；任何失败都不影响落库）
            self.dispatch_notification(&events);
        }
        n
    }

    /// 若策略开启「流结束即清理」，销毁该会话映射（多轮对话场景应关闭）。
    pub fn clear_session_if(&self, session: &str, enabled: bool) {
        if enabled {
            self.vault.clear_session(session);
        }
    }

    /// 向前端 emit 事件（AppHandle 未就绪时静默跳过）。
    pub fn emit_event<S: Serialize + Clone>(&self, event: &str, payload: S) {
        if let Ok(guard) = self.app_handle.read() {
            if let Some(handle) = guard.as_ref() {
                use tauri::Emitter;
                let _ = handle.emit(event, payload);
            }
        }
    }
}

/// 写一批审计事件的便捷入口。
pub trait AuditWriterBatch {
    fn enqueue_batch(&self, rows: Vec<AuditEventRow>);
}

impl AuditWriterBatch for AuditWriter {
    fn enqueue_batch(&self, rows: Vec<AuditEventRow>) {
        for r in rows {
            self.enqueue(r);
        }
    }
}

/// 审计事件的路由元信息（哪条请求产生的发现）。
#[derive(Debug, Clone, Default)]
pub struct FindingMeta {
    pub sid: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub request_hash: String,
    pub response_hash: String,
    pub probe_id: String,
}

/// 把内部错误转成**不含堆栈细节**的短消息（绝不向前端/API 泄漏内部信息）。
pub fn safe_err<E: std::fmt::Display>(e: &E) -> String {
    let s = e.to_string();
    let first = s.lines().next().unwrap_or("internal error");
    let trimmed: String = first.chars().take(200).collect();
    if trimmed.is_empty() {
        "internal error".to_string()
    } else {
        trimmed
    }
}

/// 由请求上下文派生**会话 key**。
///
/// 优先级：请求体里的会话标识字段 > 会话类请求头 > `authorization` 哈希 > 客户端地址。
/// 刻意**不使用** TCP 连接作为会话（连接复用会导致跨请求污染）。
pub fn derive_session(
    host: &str,
    header: impl Fn(&str) -> Option<String>,
    body: Option<&serde_json::Value>,
    client_addr: &str,
) -> String {
    const BODY_KEYS: [&str; 5] = [
        "conversation_id",
        "session_id",
        "thread_id",
        "previous_response_id",
        "user",
    ];
    if let Some(v) = body {
        for k in BODY_KEYS {
            if let Some(s) = v.get(k).and_then(|x| x.as_str()) {
                let s = s.trim();
                if !s.is_empty() {
                    return format!("conv:{}:{}", host, s);
                }
            }
        }
    }
    for h in ["x-session-id", "x-conversation-id", "openai-conversation-id"] {
        if let Some(v) = header(h) {
            let v = v.trim();
            if !v.is_empty() {
                return format!("hdr:{}:{}", host, v);
            }
        }
    }
    if let Some(auth) = header("authorization") {
        if !auth.trim().is_empty() {
            return format!("key:{}:{}", host, hash_body(auth.as_bytes()));
        }
    }
    session_key_from_client_addr(client_addr)
}

/// 本地 CA 的主题 CN（生成、安装、系统信任库检测三处共用，必须一致）。
pub const CA_COMMON_NAME: &str = "AI 安全卫士 Local CA";

/// 生成本地 CA 根证书并保存到应用数据目录。
/// 返回 (证书 PEM 路径, 私钥 PEM 路径)。
///
/// 私钥**经 DPAPI（当前用户）加密落盘**；DPAPI 不可用时回退明文并告警。
/// 证书与私钥都以磁盘文件为唯一真相（应用重启不换 CA，保证已安装的信任条目不失配）。
pub fn ensure_ca(app_data_dir: &PathBuf) -> anyhow::Result<(PathBuf, PathBuf)> {
    let cert_path = app_data_dir.join("ca.cer");
    let key_path = app_data_dir.join("ca.key");
    if cert_path.exists() && key_path.exists() {
        return Ok((cert_path, key_path));
    }
    fs::create_dir_all(app_data_dir)?;

    let key_pair = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![])?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, CA_COMMON_NAME);
    let cert = params.self_signed(&key_pair)?;

    fs::write(&cert_path, cert.pem())?;
    let mut pem = key_pair.serialize_pem();
    let saved = crate::security::save_ca_key(&key_path, &pem);
    // 私钥 PEM 用完即擦（rcgen 内部的密钥对象不可控，此处只清我们持有的副本）
    aiguard_core::mem::wipe_string(&mut pem);
    match saved {
        Ok(true) => log::info!("CA 私钥已用 DPAPI 加密落盘（仅当前用户可解）"),
        Ok(false) => log::warn!("CA 私钥以明文落盘（DPAPI 不可用）"),
        Err(e) => return Err(anyhow::anyhow!("CA 私钥落盘失败: {}", safe_err(&e))),
    }
    Ok((cert_path, key_path))
}

/// 会话 key：客户端地址 ip:port 字符串（derive_session 的兜底）。
pub fn session_key_from_client_addr(addr: &str) -> String {
    addr.to_string()
}

/// 计算请求体哈希（sha256 hex 前 16 位）——日志绝不落原文。
pub fn hash_body(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(body);
    let out = hasher.finalize();
    hex::encode(&out[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiguard_core::audit::{signal_name, severity_str, Severity};

    #[test]
    fn test_domain_matches() {
        assert!(domain_matches("api.openai.com", "api.openai.com"));
        assert!(domain_matches("api.openai.com", "API.OPENAI.COM:443"));
        assert!(domain_matches("openai.com", "api.openai.com"));
        assert!(!domain_matches(
            "api.openai.com",
            "evil-api.openai.com.evil.com"
        ));
        assert!(!domain_matches("openai.com", "notopenai.com"));
        assert!(!domain_matches("", "api.openai.com"));
    }

    #[test]
    fn test_process_path_matches() {
        assert!(process_path_matches(r"C:\Tools\curl.exe", r"C:\Tools\curl.exe"));
        assert!(process_path_matches(r"c:\tools\curl.exe", r"C:\TOOLS\CURL.EXE"));
        assert!(process_path_matches(
            r"C:\Program Files\MyApp",
            r"C:\Program Files\MyApp\bin\worker.exe"
        ));
        assert!(process_path_matches("python.exe", r"D:\envs\py\python.exe"));
        assert!(!process_path_matches(r"C:\Tools\curl.exe", r"C:\Other\curl.exe"));
        assert!(!process_path_matches("python.exe", r"D:\envs\py\python3.exe"));
        assert!(!process_path_matches("", r"C:\x.exe"));
    }

    #[test]
    fn test_audit_config_defaults_and_gates() {
        let cfg = AuditConfig::default();
        // 依赖主动核查的两个信号无实现，恒为关闭
        assert!(!cfg.signal_enabled("tool_call_rewrite"));
        assert!(!cfg.signal_enabled("cross_request_pollution"));
        assert!(cfg.signal_enabled("error_leak"));
        assert!(cfg.signal_enabled("dangerous_action"));
        // 入库门槛默认 MEDIUM：LOW 挡在默认视图外
        assert!(cfg.allows("MEDIUM"));
        assert!(cfg.allows("CRITICAL"));
        assert!(!cfg.allows("LOW"));
        let mut off = AuditConfig::default();
        off.enabled = false;
        assert!(!off.signal_enabled("error_leak"));
    }

    #[test]
    fn test_audit_config_serde_partial_fill() {
        let cfg: AuditConfig =
            serde_json::from_str(r#"{"severity_floor":"LOW","retention_days":0}"#).unwrap();
        assert_eq!(cfg.severity_floor, "LOW");
        assert_eq!(cfg.retention_days, 0);
        assert!(cfg.signal_enabled("response_poison"), "缺失字段应回退默认值");
        assert!(!cfg.signal_enabled("tool_call_rewrite"));
    }

    #[test]
    fn test_signal_catalog_shape() {
        assert_eq!(signal_name("dangerous_action"), "高危指令");
        assert_eq!(signal_name("tool_call_injection"), "工具注入");
        assert_eq!(signal_name("locker_access"), "保险柜访问");
        assert_eq!(signal_name("error_leak"), "报错泄密");
        assert_eq!(signal_name("cross_request_pollution"), "记忆残留");
        assert_eq!(severity_str(Severity::Critical), "CRITICAL");
        assert_eq!(SIGNAL_CATALOG.len(), 9);
    }

    #[test]
    fn test_marker_registry_semantics() {
        let dir = std::env::temp_dir().join(format!("aiguard_state_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let store = crate::store::Store::open(&db).unwrap();
        let st = AppState::new(store, &db, dir.clone());
        st.register_markers(&[
            "MARK_0_aaaaaaaa".to_string(),
            "MARK_1_bbbbbbbb".to_string(),
        ]);
        assert_eq!(st.prior_markers(&[]).len(), 2);
        let prior2 = st.prior_markers(&["MARK_0_aaaaaaaa".to_string()]);
        assert_eq!(prior2.len(), 1);
        assert!(prior2.contains("MARK_1_bbbbbbbb"));
        // 空串不注册
        st.register_markers(&["  ".to_string()]);
        assert_eq!(st.prior_markers(&[]).len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 代理令牌必须跨进程持久，且在 kv 里以 DPAPI 密文存放（不得出现明文）。
    #[test]
    fn test_proxy_token_persists_and_is_encrypted_at_rest() {
        let dir = std::env::temp_dir().join(format!("aiguard_tok_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");

        let (token, raw) = {
            let store = crate::store::Store::open(&db).unwrap();
            let st = AppState::new(store, &db, dir.clone());
            let t = match st.access.read() {
                Ok(a) => a.token.clone(),
                Err(p) => p.into_inner().token.clone(),
            };
            let raw = st.store.kv_get(KV_PROXY_TOKEN).unwrap().unwrap_or_default();
            (t, raw)
        };
        assert!(token.len() >= 16, "令牌应为 32 位 hex，实际 {:?}", token);
        if cfg!(target_os = "windows") {
            assert!(
                raw.starts_with("enc:"),
                "令牌必须以 DPAPI 密文落库，实际前缀 {:?}",
                &raw[..raw.len().min(8)]
            );
            assert!(!raw.contains(&token), "落库内容不得包含明文令牌");
        }

        // 重新打开同一 DB：令牌必须完全一致（否则用户配好的 CLI 会随机失效）
        let store2 = crate::store::Store::open(&db).unwrap();
        let st2 = AppState::new(store2, &db, dir.clone());
        let token2 = match st2.access.read() {
            Ok(a) => a.token.clone(),
            Err(p) => p.into_inner().token.clone(),
        };
        assert_eq!(token2, token, "令牌必须跨进程持久且可解回原文");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 代理令牌比较必须严格（长度不同 / 内容不同一律 false），恒定时间实现不外泄前缀。
    #[test]
    fn test_access_token_matches_is_strict() {
        let a = AccessControl {
            require_token: true,
            token: "0123456789abcdef0123456789abcdef".to_string(),
        };
        assert!(a.has_token());
        assert!(a.token_matches("0123456789abcdef0123456789abcdef"));
        assert!(!a.token_matches("0123456789abcdef0123456789abcdee"));
        assert!(!a.token_matches("0123456789abcdef0123456789abcde"));
        assert!(!a.token_matches(""));
        let empty = AccessControl::default();
        assert!(!empty.has_token());
        assert!(!empty.token_matches(""));
    }

    // ─────────── 活跃会话 / 应急清空 / 桌面通知 ───────────

    fn temp_state() -> (Arc<AppState>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("aiguard_st_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let store = crate::store::Store::open(&db).unwrap();
        (Arc::new(AppState::new(store, &db, dir.clone())), dir)
    }

    #[test]
    fn test_host_from_session_key() {
        assert_eq!(
            host_from_session_key("conv:chat.deepseek.com:abc-123"),
            "chat.deepseek.com"
        );
        assert_eq!(host_from_session_key("hdr:api.openai.com:t-1"), "api.openai.com");
        assert_eq!(host_from_session_key("key:api.moonshot.cn:9f8e7d6c"), "api.moonshot.cn");
        // 兜底形态（ip:port）没有域名，返回空串而不是把地址当域名
        assert_eq!(host_from_session_key("127.0.0.1:54321"), "");
    }

    #[test]
    fn test_active_sessions_join_meta_and_vault() {
        let (st, dir) = temp_state();
        // 会话 A：元信息 + 2 条映射
        st.vault.get_or_create("conv:api.openai.com:chat-1", "a@b.cn", "EMAIL");
        st.vault.get_or_create("conv:api.openai.com:chat-1", "13800138000", "PHONE");
        st.note_session_activity(
            "conv:api.openai.com:chat-1",
            "api.openai.com",
            Some(r"C:\Tools\curl.exe"),
        );
        // 会话 B：只有映射（元信息缺失，域名靠会话 key 还原）
        st.vault.get_or_create("hdr:api.moonshot.cn:t-9", "c@d.cn", "EMAIL");
        // 会话 C：只有元信息（0 命中的直通请求也必须出现在活跃列表里）
        st.note_session_activity("conv:chat.deepseek.com:c-2", "chat.deepseek.com", None);

        let rows = st.active_sessions();
        assert_eq!(rows.len(), 3, "三个来源都应被合并: {:?}", rows);
        let a = rows.iter().find(|r| r.host == "api.openai.com").expect("会话 A");
        assert_eq!(a.placeholders, 2);
        assert_eq!(a.process, r"C:\Tools\curl.exe");
        assert!(!a.pinned);
        let b = rows.iter().find(|r| r.host == "api.moonshot.cn").expect("会话 B");
        assert_eq!(b.placeholders, 1);
        assert!(b.process.is_empty());
        let c = rows
            .iter()
            .find(|r| r.host == "chat.deepseek.com")
            .expect("会话 C");
        assert_eq!(c.placeholders, 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_session_meta_is_pruned_when_expired() {
        let (st, dir) = temp_state();
        st.note_session_activity("conv:api.openai.com:x", "api.openai.com", None);
        assert_eq!(st.active_sessions().len(), 1);
        // 把最后活动时间人为拨到保留期之外，活跃列表必须把它淘汰
        {
            let mut g = st.session_meta.write().unwrap();
            let m = g.get_mut("conv:api.openai.com:x").unwrap();
            m.last_seen = Instant::now() - std::time::Duration::from_secs(SESSION_META_KEEP_SECS + 60);
        }
        assert!(st.active_sessions().is_empty(), "过期会话不应出现在活跃列表");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_purge_all_memory_clears_everything() {
        let (st, dir) = temp_state();
        st.vault.get_or_create("s1", "13800138000", "PHONE");
        st.vault.get_or_create("s2", "a@b.cn", "EMAIL");
        st.note_session_activity("s1", "api.openai.com", None);
        st.register_markers(&["MARK_0_aaaaaaaa".to_string()]);
        st.remember_session("127.0.0.1:5000", "s1");
        st.mark_guarded("127.0.0.1:5000");
        let info = ReqInfo {
            model: Some("gpt-4o".into()),
            body_text: "以 13800138000 脱敏前的原文".into(),
            hash: "h".into(),
            probe_id: String::new(),
            markers: Vec::new(),
        };
        st.remember_req_info("127.0.0.1:5000", info);

        let (sessions, mappings, samples) = st.purge_all_memory();
        assert_eq!(sessions, 2);
        assert_eq!(mappings, 2);
        assert_eq!(samples, 1, "请求正文采样也必须被清空");
        assert_eq!(st.vault.session_total(), 0);
        assert!(st.active_sessions().is_empty());
        assert!(st.prior_markers(&[]).is_empty(), "追踪标记必须清空");
        assert!(!st.is_guarded("127.0.0.1:5000"), "受守护连接标记必须清空");
        // 会话对齐缓存被清空 → 回退为 addr 派生
        assert_eq!(st.session_for_addr("127.0.0.1:5000"), "127.0.0.1:5000");
        assert_eq!(st.req_info_for("127.0.0.1:5000").body_text, "");
        // 幂等：再清一次什么都不剩
        assert_eq!(st.purge_all_memory(), (0, 0, 0));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_notify_config_gate_and_persistence() {
        let (st, dir) = temp_state();
        // 默认：开启，门槛 HIGH
        let cfg = st.notify_config();
        assert!(cfg.enabled && cfg.severity_floor == "HIGH");
        assert!(cfg.allows("HIGH") && cfg.allows("CRITICAL"));
        assert!(!cfg.allows("MEDIUM") && !cfg.allows("LOW"));
        // 关闭总开关 → 任何级别都不通知
        let mut off = NotifyConfig::default();
        off.enabled = false;
        assert!(!off.allows("CRITICAL"));
        // 门槛非法 → 不通知（避免"误配成全量推送"）
        let bad = NotifyConfig {
            enabled: true,
            severity_floor: String::new(),
        };
        assert!(!bad.allows("CRITICAL"));

        st.apply_notify_config(NotifyConfig {
            enabled: true,
            severity_floor: "MEDIUM".to_string(),
        })
        .expect("落盘应成功");
        assert!(st.notify_config().allows("MEDIUM"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
