/**
 * Tauri invoke / listen 封装。
 * 在纯浏览器环境（无 window.__TAURI_INTERNALS__，如 `npm run dev` 直接打开）
 * 自动切换为 MOCK 数据，保证 UI 完整可预览。
 */

// ─────────── 环境检测 ───────────

function isTauri(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof (window as any).__TAURI_INTERNALS__ !== "undefined"
  );
}

async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

// ─────────── 类型（与 src-tauri store::RequestLog / commands 对齐） ───────────

export interface RequestLog {
  id: number;
  ts: string;
  host: string;
  path: string;
  session: string;
  kinds: string; // JSON 数组字符串，如 ["PHONE"]
  action: string; // mask / block / warn / passthrough
  req_hash: string;
  blocked: number;
}

export interface DashboardStats {
  total_requests: number;
  total_scrubbed: number;
  total_blocked: number;
  active_sessions: number;
  guard_enabled: boolean;
  mode: string;
  uptime_secs: number;
  restore_enabled: boolean;
}

/** 设置「响应还原」开关：关闭时 AI 回复中的占位符不还原（原样显示）。 */
export async function setRestoreEnabled(enabled: boolean): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("set_restore_enabled", { enabled });
}

// ─────────── 日志分页与清理 ───────────

export interface LogPage<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface CleanupSettings {
  passthrough_days: number;
  mask_days: number;
  block_days: number;
}

/** 分页列出请求日志（请求页）。action: "mask" | "block" | 空/“all” = 全部。 */
export async function listRequestsPage(
  page: number,
  pageSize: number,
  action?: string
): Promise<LogPage<RequestLog>> {
  if (!isTauri()) {
    // 浏览器预览：从 MOCK 日志切片
    const filtered = action
      ? MOCK_LOGS.filter((l) => (action === "block" ? l.blocked === 1 || l.action === "block" : l.action === action))
      : MOCK_LOGS;
    const start = (page - 1) * pageSize;
    return {
      items: filtered.slice(start, start + pageSize),
      total: filtered.length,
      page,
      page_size: pageSize,
    };
  }
  return tauriInvoke<LogPage<RequestLog>>("list_requests_page", {
    page,
    pageSize,
    action: action && action !== "all" ? action : null,
  });
}

/** 分页列出审计日志（审计页）。fromTs/toTs：Unix 秒范围（可空）。 */
export async function listAuditPage(
  page: number,
  pageSize: number,
  fromTs?: number,
  toTs?: number
): Promise<LogPage<RequestLog>> {
  if (!isTauri()) {
    const filtered =
      fromTs && toTs
        ? MOCK_LOGS.filter((l) => {
            const t = Number(l.ts);
            return t >= fromTs && t < toTs;
          })
        : MOCK_LOGS;
    const start = (page - 1) * pageSize;
    return {
      items: filtered.slice(start, start + pageSize),
      total: filtered.length,
      page,
      page_size: pageSize,
    };
  }
  return tauriInvoke<LogPage<RequestLog>>("list_audit_page", {
    page,
    pageSize,
    fromTs: fromTs ?? null,
    toTs: toTs ?? null,
  });
}

/** 读取日志清理设置（天数，0 = 永久保留）。 */
export async function getCleanupSettings(): Promise<CleanupSettings> {
  if (!isTauri()) return { passthrough_days: 1, mask_days: 30, block_days: 90 };
  return tauriInvoke<CleanupSettings>("get_cleanup_settings");
}

/** 保存日志清理设置并立即执行一次清理。 */
export async function setCleanupSettings(s: CleanupSettings): Promise<CleanupSettings> {
  if (!isTauri()) return s;
  return tauriInvoke<CleanupSettings>("set_cleanup_settings", {
    passthroughDays: s.passthrough_days,
    maskDays: s.mask_days,
    blockDays: s.block_days,
  });
}

/** 手动触发一次日志清理，返回分类删除明细。 */
export interface CleanupResult {
  passthrough: number;
  mask: number;
  block: number;
  audit: number;
  total: number;
}

export async function cleanupLogsNow(): Promise<CleanupResult> {
  if (!isTauri()) return { passthrough: 0, mask: 0, block: 0, audit: 0, total: 0 };
  return tauriInvoke<CleanupResult>("cleanup_logs_now");
}

/** 清空全部请求日志（不含审计事件）。返回删除条数。 */
export async function clearRequestLogs(): Promise<number> {
  if (!isTauri()) return 0;
  return tauriInvoke<number>("clear_request_logs");
}

/** 清空指定类型的请求日志：passthrough = 直通 / mask = 已脱敏 / block = 已拦截。 */
export async function clearRequestLogsByAction(action: string): Promise<number> {
  if (!isTauri()) return 0;
  return tauriInvoke<number>("clear_request_logs_by_action", { action });
}

/** 切换拦截模式（system_proxy / hosts_file）。守护开启时会应用系统级改动（hosts 需 UAC）。 */
export async function setProxyMode(mode: string): Promise<string> {
  if (!isTauri()) return "（浏览器预览：模拟切换成功）";
  return tauriInvoke<string>("set_proxy_mode", { mode });
}

export interface RuleSpec {
  id: string;
  /** 占位符标签（如 IDCARD；自定义规则为用户定义标签） */
  tag: string;
  name: string;
  regex: string;
  /** mask / block / warn */
  action: string;
  enabled: boolean;
  /** 内置规则不可删除，可编辑 / 恢复默认 */
  builtin: boolean;
}

export interface WhitelistEntry {
  id: string;
  /** domain = 域名；process = 可执行文件 / 文件夹 */
  kind: "domain" | "process";
  pattern: string;
  /** 是否仍执行脱敏（不拦截始终成立） */
  scrub: boolean;
}

export interface BlacklistEntry {
  id: string;
  /** domain = 域名；process = 可执行文件 / 文件夹（复用白名单类型） */
  kind: "domain" | "process";
  pattern: string;
  /** 命中动作：block = 403 拦截；mask = 强制脱敏（Block 规则降级） */
  action: string;
}

export interface CaStatus {
  cert_path: string;
  installed_hint: string;
}

/** 证书在系统信任库中的安装检测结果 */
export interface CaTrustStatus {
  /** 是否已检测到本应用 CA */
  trusted: boolean;
  /** 安装位置（"本机信任库（所有用户）" / "当前用户信任库"） */
  locations: string[];
  /** 人类可读的检测结论 */
  detail: string;
}

export interface PiiEventPayload {
  session: string;
  kind: string;
  host: string;
  action: string;
  ts: string;
}

// ─────────── 防护中心（防护信号审计）类型 ───────────

export interface SecurityPoint {
  /** 语义信号名（配置开关 / 日志关联的键） */
  signal: string;
  name: string;
  desc: string;
  enabled: boolean;
  /** 是否有实现（依赖主动核查的两个信号当前 false） */
  implemented: boolean;
  /** 历史命中次数（落库，按信号聚合） */
  hits: number;
}

export interface SecurityPolicy {
  /** 审计总开关 */
  enabled: boolean;
  /** 信号开关（按语义信号名） */
  signals: Record<string, boolean>;
  /** 入库门槛（LOW/MEDIUM/HIGH/CRITICAL） */
  severity_floor: string;
  /** 审计事件保留天数（0 = 永久） */
  retention_days: number;
  /** 主动核查开关 */
  probes_enabled: boolean;
  max_buffer_size: number;
  max_placeholder_len: number;
  session_ttl_secs: number;
  clear_session_on_stream_end: boolean;
}

export interface SecurityEventRow {
  seq: number;
  /** Unix 秒（含小数） */
  ts: string;
  sid: string;
  host: string;
  method: string;
  path: string;
  /** 信号名（error_leak / identity_swap / ...） */
  signal_type: string;
  severity: string;
  evidence: string;
  probe_id: string;
  request_hash: string;
  response_hash: string;
}

// ─────────── MOCK 数据（纯浏览器预览用） ───────────

const MOCK_STATS: DashboardStats = {
  total_requests: 128,
  total_scrubbed: 34,
  total_blocked: 3,
  active_sessions: 5,
  guard_enabled: true,
  mode: "system_proxy",
  uptime_secs: 7325,
  restore_enabled: true,
};

const MOCK_LOGS: RequestLog[] = [
  { id: 128, ts: "1749705600", host: "api.openai.com", path: "/v1/chat/completions", session: "127.0.0.1:52411", kinds: '["PHONE","EMAIL"]', action: "mask", req_hash: "a1b2c3d4e5f60718", blocked: 0 },
  { id: 127, ts: "1749705480", host: "api.anthropic.com", path: "/v1/messages", session: "127.0.0.1:52390", kinds: '["IDCARD"]', action: "block", req_hash: "9f8e7d6c5b4a3210", blocked: 1 },
  { id: 126, ts: "1749705300", host: "api.deepseek.com", path: "/chat/completions", session: "127.0.0.1:52364", kinds: '["APIKEY"]', action: "mask", req_hash: "1122334455667788", blocked: 0 },
  { id: 125, ts: "1749705100", host: "dashscope.aliyuncs.com", path: "/api/v1/services/aigc", session: "127.0.0.1:52341", kinds: "[]", action: "passthrough", req_hash: "", blocked: 0 },
  { id: 124, ts: "1749704920", host: "api.moonshot.cn", path: "/v1/chat/completions", session: "127.0.0.1:52318", kinds: '["BANKCARD"]', action: "mask", req_hash: "deadbeefcafebabe", blocked: 0 },
  { id: 123, ts: "1749704700", host: "api.openai.com", path: "/v1/embeddings", session: "127.0.0.1:52301", kinds: "[]", action: "passthrough", req_hash: "", blocked: 0 },
  { id: 122, ts: "1749704400", host: "open.bigmodel.cn", path: "/api/paas/v4/chat", session: "127.0.0.1:52286", kinds: '["IP"]', action: "warn", req_hash: "0f1e2d3c4b5a6978", blocked: 0 },
];

const MOCK_RULES: RuleSpec[] = [
  { id: "builtin.idcard", tag: "IDCARD", name: "身份证号", regex: "[1-9]\\d{5}(19|20)\\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])\\d{3}[\\dXx]", action: "mask", enabled: true, builtin: true },
  { id: "builtin.phone", tag: "PHONE", name: "手机号", regex: "1[3-9]\\d{9}", action: "mask", enabled: true, builtin: true },
  { id: "builtin.bankcard", tag: "BANKCARD", name: "银行卡号", regex: "\\d{16,19}", action: "mask", enabled: true, builtin: true },
  { id: "builtin.email", tag: "EMAIL", name: "邮箱", regex: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", action: "mask", enabled: true, builtin: true },
  { id: "builtin.apikey", tag: "APIKEY", name: "API 密钥", regex: "sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}", action: "mask", enabled: true, builtin: true },
  { id: "builtin.ip", tag: "IP", name: "IP 地址", regex: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", action: "warn", enabled: true, builtin: true },
  { id: "custom.demo0001", tag: "PROJECT", name: "内部项目代号", regex: "阿尔法计划|贝塔计划", action: "mask", enabled: true, builtin: false },
];

const MOCK_WHITELIST: WhitelistEntry[] = [
  { id: "wl.demo0001", kind: "domain", pattern: "api.deepseek.com", scrub: true },
  { id: "wl.demo0002", kind: "process", pattern: "C:\\Program Files\\JetBrains\\IntelliJ IDEA", scrub: false },
];

const MOCK_CA: CaStatus = {
  cert_path: "C:\\Users\\me\\AppData\\Roaming\\com.technicalflight.aiguard\\ca.cer",
  installed_hint: "证书文件已生成，如尚未安装请点击「安装根证书」",
};

const MOCK_BLACKLIST: BlacklistEntry[] = [];

const MOCK_CA_TRUST: CaTrustStatus = {
  trusted: true,
  locations: ["当前用户信任库"],
  detail: "已在系统信任库中找到「AI 安全卫士 Local CA」，拦截 HTTPS 流量无需再确认",
};

const MOCK_SECURITY_POINTS: SecurityPoint[] = [
  { signal: "error_leak", name: "报错泄密", desc: "上游返回报错时，把接口密钥、环境变量、内部路径等敏感信息一并带给了调用方", enabled: true, implemented: true, hits: 3 },
  { signal: "identity_swap", name: "模型偷换", desc: "应答声称的模型与实际请求的不一致（只比对模型家族，不纠缠版本号）", enabled: true, implemented: true, hits: 1 },
  { signal: "tool_call_rewrite", name: "复读篡改", desc: "主动核查要求逐字复读固定命令，检验中转是否偷偷改动（需运行主动核查）", enabled: false, implemented: false, hits: 0 },
  { signal: "sse_anomaly", name: "流式异常", desc: "应答流里出现未知事件、用量计数回退等迹象（观察类信号，默认只记录不告警）", enabled: true, implemented: true, hits: 0 },
  { signal: "response_poison", name: "响应夹带", desc: "应答里藏有隐形控制字符、渲染即外发的链接，或凭空出现他人的访问凭据", enabled: true, implemented: true, hits: 5 },
  { signal: "cross_request_pollution", name: "记忆残留", desc: "上游把早前请求里埋下的追踪标记又吐了出来，说明它在存储会话内容（需运行主动核查）", enabled: false, implemented: false, hits: 0 },
  { signal: "dangerous_action", name: "高危指令", desc: "应答中出现删库、擦盘、下载即执行等破坏性命令的典型形态（只记录，不做拦截）", enabled: true, implemented: true, hits: 7 },
];

const MOCK_SECURITY_POLICY: SecurityPolicy = {
  enabled: true,
  signals: {
    error_leak: true,
    identity_swap: true,
    tool_call_rewrite: false,
    sse_anomaly: true,
    response_poison: true,
    cross_request_pollution: false,
    dangerous_action: true,
  },
  severity_floor: "MEDIUM",
  retention_days: 7,
  probes_enabled: false,
  max_buffer_size: 1048576,
  max_placeholder_len: 128,
  session_ttl_secs: 1800,
  clear_session_on_stream_end: false,
};

const MOCK_SECURITY_EVENTS: SecurityEventRow[] = [
  { seq: 9, ts: "1749705600", sid: "conv:api.openai.com:chat-88", host: "api.openai.com", method: "POST", path: "/v1/chat/completions", signal_type: "response_poison", severity: "HIGH", evidence: "hidden_unicode: U+202E (count=1) [双向覆盖符]", probe_id: "", request_hash: "a1b2c3d4e5f60718", response_hash: "1122334455667788" },
  { seq: 8, ts: "1749705480", sid: "conv:api.openai.com:chat-88", host: "api.openai.com", method: "POST", path: "/v1/chat/completions", signal_type: "response_poison", severity: "MEDIUM", evidence: "credential_echo:github_token len=37 sha256=deadbeefcafebabe", probe_id: "", request_hash: "a1b2c3d4e5f60718", response_hash: "1122334455667788" },
  { seq: 7, ts: "1749705360", sid: "key:api.deepseek.com:9f8e7d6c", host: "api.deepseek.com", method: "POST", path: "/chat/completions", signal_type: "dangerous_action", severity: "LOW", evidence: "递归删除根目录/家目录: rm -rf /", probe_id: "", request_hash: "1122334455667788", response_hash: "deadbeefcafebabe" },
  { seq: 6, ts: "1749705240", sid: "hdr:api.moonshot.cn:t-42", host: "api.moonshot.cn", method: "POST", path: "/v1/chat/completions", signal_type: "identity_swap", severity: "HIGH", evidence: "model_mismatch: req=gpt-4o resp=claude-3-5-sonnet", probe_id: "", request_hash: "0f1e2d3c4b5a6978", response_hash: "9f8e7d6c5b4a3210" },
  { seq: 5, ts: "1749705120", sid: "conv:api.openai.com:chat-87", host: "api.openai.com", method: "POST", path: "/v1/chat/completions", signal_type: "error_leak", severity: "CRITICAL", evidence: "sk_prefix_secret len=29 sha256=abcdef0123456789", probe_id: "", request_hash: "5a5b5c5d5e5f6061", response_hash: "6263646566676869" },
];

// ─────────── 对外 API ───────────

export async function getDashboard(): Promise<DashboardStats> {
  if (!isTauri()) return { ...MOCK_STATS };
  return tauriInvoke<DashboardStats>("get_dashboard");
}

export async function listRequests(limit = 50): Promise<RequestLog[]> {
  if (!isTauri()) return MOCK_LOGS.slice(0, limit);
  return tauriInvoke<RequestLog[]>("list_requests", { limit });
}

export async function getRules(): Promise<RuleSpec[]> {
  if (!isTauri()) return MOCK_RULES.map((r) => ({ ...r }));
  return tauriInvoke<RuleSpec[]>("get_rules");
}

export async function setRule(
  id: string,
  patch: { enabled?: boolean; action?: string; regex?: string; name?: string }
): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("set_rule", { id, ...patch });
}

export async function addCustomRule(
  name: string,
  regex: string,
  action: string,
  tag?: string
): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("add_custom_rule", { name, regex, action, tag });
}

export async function deleteRule(id: string): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("delete_rule", { id });
}

export async function resetRule(id: string): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("reset_rule", { id });
}

export async function getWhitelist(): Promise<WhitelistEntry[]> {
  if (!isTauri()) return MOCK_WHITELIST.map((w) => ({ ...w }));
  return tauriInvoke<WhitelistEntry[]>("get_whitelist");
}

export async function addWhitelistEntry(
  kind: "domain" | "process",
  pattern: string,
  scrub: boolean
): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("add_whitelist_entry", { kind, pattern, scrub });
}

export async function updateWhitelistEntry(
  id: string,
  patch: { pattern?: string; scrub?: boolean }
): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("update_whitelist_entry", { id, ...patch });
}

export async function removeWhitelistEntry(id: string): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("remove_whitelist_entry", { id });
}

// ─────────── 黑名单（命中即强制拦截，优先级最高） ───────────

export async function getBlacklist(): Promise<BlacklistEntry[]> {
  if (!isTauri()) return MOCK_BLACKLIST.map((b) => ({ ...b }));
  return tauriInvoke<BlacklistEntry[]>("get_blacklist");
}

export async function addBlacklistEntry(
  kind: "domain" | "process",
  pattern: string,
  action: string
): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("add_blacklist_entry", { kind, pattern, action });
}

export async function removeBlacklistEntry(id: string): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("remove_blacklist_entry", { id });
}

// ─────────── 系统文件对话框（黑 / 白名单的 exe / 文件夹选择） ───────────

/**
 * 调用系统资源管理器选择路径。返回所选完整路径；取消返回 null。
 * kind = "exe" → 单选可执行文件；kind = "folder" → 单选文件夹。
 * 纯浏览器预览环境返回 null。
 */
export async function pickPath(kind: "exe" | "folder"): Promise<string | null> {
  if (!isTauri()) return null;
  const { open } = await import("@tauri-apps/plugin-dialog");
  if (kind === "folder") {
    const r = await open({ directory: true, multiple: false, title: "选择文件夹" });
    return typeof r === "string" ? r : null;
  }
  const r = await open({
    multiple: false,
    title: "选择可执行文件",
    filters: [
      { name: "可执行文件", extensions: ["exe"] },
      { name: "所有文件", extensions: ["*"] },
    ],
  });
  return typeof r === "string" ? r : null;
}

export async function enableGuard(): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("enable_guard");
}

export async function disableGuard(): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("disable_guard");
}

export async function installCa(): Promise<string> {
  if (!isTauri()) return "（浏览器预览：模拟安装成功）";
  return tauriInvoke<string>("install_ca");
}

export async function getCaStatus(): Promise<CaStatus> {
  if (!isTauri()) return { ...MOCK_CA };
  return tauriInvoke<CaStatus>("get_ca_status");
}

/** 检测根证书是否已成功安装到 Windows 系统信任库。 */
export async function checkCaTrust(): Promise<CaTrustStatus> {
  if (!isTauri()) return { ...MOCK_CA_TRUST };
  return tauriInvoke<CaTrustStatus>("check_ca_trust");
}

/** 订阅 pii-detected 实时事件（浏览器环境返回空函数）。 */
export async function onPiiDetected(
  handler: (payload: PiiEventPayload) => void
): Promise<() => void> {
  if (!isTauri()) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  const unlisten = await listen<PiiEventPayload>("pii-detected", (e) => {
    handler(e.payload);
  });
  return unlisten;
}

// ─────────── 防护中心 API ───────────

export async function getSecurityPoints(): Promise<SecurityPoint[]> {
  if (!isTauri()) return MOCK_SECURITY_POINTS.map((p) => ({ ...p }));
  return tauriInvoke<SecurityPoint[]>("get_security_points");
}

export async function getSecurityPolicy(): Promise<SecurityPolicy> {
  if (!isTauri()) return { ...MOCK_SECURITY_POLICY };
  return tauriInvoke<SecurityPolicy>("get_security_policy");
}

export async function setSecurityPolicy(policy: SecurityPolicy): Promise<SecurityPolicy> {
  if (!isTauri()) return policy;
  return tauriInvoke<SecurityPolicy>("set_security_policy", { policy });
}

export async function listSecurityEvents(limit = 100): Promise<SecurityEventRow[]> {
  if (!isTauri()) return MOCK_SECURITY_EVENTS.slice(0, limit);
  return tauriInvoke<SecurityEventRow[]>("list_security_events", { limit });
}

export async function clearSecurityEvents(): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("clear_security_events");
}

/** 应急：清空全部内存会话映射，返回被清理的会话数。 */
export async function clearSessions(): Promise<number> {
  if (!isTauri()) return 0;
  return tauriInvoke<number>("clear_sessions");
}

// ─────────── 主动核查 ───────────

export interface LinkCheckStep {
  step: string;
  probe_id: string;
  status: number;
  /** 是否构成有效回执（错误响应对语义依赖成功响应的步骤视为无效） */
  valid_receipt: boolean;
  note: string;
}

export interface CheckMatrix {
  echo: boolean;
  echo_ok: boolean;
  replay: boolean;
  replay_ok: boolean;
  leak: boolean;
  leak_mid: boolean;
  leak_ok: boolean;
  flow: boolean;
  flow_ok: boolean;
  induce: boolean;
  induce_ok: boolean;
  /** CRITICAL / HIGH / MEDIUM / LOW / INCONCLUSIVE */
  severity: string;
  /** 覆盖率 n/m */
  coverage: string;
  incomplete: boolean;
}

export interface LinkCheckResult {
  matrix: CheckMatrix;
  steps: LinkCheckStep[];
  /** Markdown 报告全文 */
  report: string;
  report_path: string;
  total: number;
  failed: number;
}

/** 运行一轮主动核查（每步请求都经真实代理发出）。 */
export async function runLinkCheck(params: {
  targetHost: string;
  path: string;
  model: string;
  profile: string;
  authHeader?: string;
}): Promise<LinkCheckResult> {
  if (!isTauri()) throw new Error("主动核查需要在桌面应用中运行");
  return tauriInvoke<LinkCheckResult>("run_link_check", {
    targetHost: params.targetHost,
    path: params.path,
    model: params.model,
    profile: params.profile,
    authHeader: params.authHeader ? params.authHeader : null,
  });
}

/** 订阅 security-alert 实时事件（浏览器环境返回空函数）。 */
export async function onSecurityAlert(
  handler: (payload: SecurityEventRow) => void
): Promise<() => void> {
  if (!isTauri()) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  const unlisten = await listen<SecurityEventRow>("security-alert", (e) => {
    handler(e.payload);
  });
  return unlisten;
}

// ─────────── 本机安全加固 ───────────

/** 单个端口的占用情况。 */
export interface PortState {
  port: number;
  /** ready = 本应用正在监听；free = 空闲；occupied = 被其它进程占用 */
  state: "ready" | "free" | "occupied" | string;
  owner_pid?: number;
  owner_exe?: string;
  detail: string;
}

/** 本机安全加固综合状态（设置页展示用）。 */
export interface HardeningStatus {
  proxy_port: PortState;
  pac_port: PortState;
  /** 是否只接受本机回环连接（恒 true） */
  loopback_only: boolean;
  /** 是否要求代理级请求携带令牌 */
  require_token: boolean;
  /** 令牌掩码提示 */
  token_hint: string;
  token_ready: boolean;
  /** 原文映射与请求采样是否做内存擦除（恒 true） */
  memory_wipe: boolean;
  active_sessions: number;
  debugger_detected: boolean;
  /** encrypted | plaintext | absent */
  key_at_rest: string;
  key_path: string;
  /** user_only | shared | unknown */
  data_dir_scope: string;
  data_dir_detail: string;
  /** 已被审计到的代理客户端进程 */
  client_processes: string[];
  /** 启动自检提示 */
  startup_notes: string[];
}

const MOCK_HARDENING: HardeningStatus = {
  proxy_port: { port: 8888, state: "ready", owner_pid: 12345, detail: "本应用正在监听 127.0.0.1:8888" },
  pac_port: { port: 8889, state: "ready", owner_pid: 12345, detail: "本应用正在监听 127.0.0.1:8889" },
  loopback_only: true,
  require_token: false,
  token_hint: "9f3a••••••••c1d2",
  token_ready: true,
  memory_wipe: true,
  active_sessions: 5,
  debugger_detected: false,
  key_at_rest: "encrypted",
  key_path: "C:\\Users\\me\\AppData\\Roaming\\com.technicalflight.aiguard\\ca.key",
  data_dir_scope: "user_only",
  data_dir_detail: "仅当前用户 / SYSTEM / 管理员",
  client_processes: [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\System32\\curl.exe",
  ],
  startup_notes: [
    "本地代理已就绪：本应用正在监听 127.0.0.1:8888",
    "CA 私钥已用 DPAPI 加密落盘（仅当前用户可解密）。",
  ],
};

/** 取「本机安全加固」综合状态。 */
export async function getHardeningStatus(): Promise<HardeningStatus> {
  if (!isTauri()) return { ...MOCK_HARDENING };
  return tauriInvoke<HardeningStatus>("get_hardening_status");
}

/** 实时检测当前代理端口的占用情况。 */
export async function checkProxyPort(): Promise<PortState> {
  if (!isTauri())
    return { port: 8888, state: "ready", owner_pid: 12345, detail: "本应用正在监听 127.0.0.1:8888" };
  return tauriInvoke<PortState>("check_proxy_port");
}

/** 取本地代理令牌明文（仅用户主动点击「查看」时调用）。 */
export async function getProxyToken(): Promise<string> {
  if (!isTauri()) return "9f3a1b2c3d4e5f60718293a4b5c6d7e8";
  return tauriInvoke<string>("get_proxy_token");
}

/** 重新生成本地代理令牌（旧令牌立即失效）。 */
export async function regenerateProxyToken(): Promise<string> {
  if (!isTauri()) return "00000000000000000000000000000000";
  return tauriInvoke<string>("regenerate_proxy_token");
}

/** 设置是否要求代理级请求携带令牌（默认关闭）。 */
export async function setRequireToken(enabled: boolean): Promise<boolean> {
  if (!isTauri()) return enabled;
  return tauriInvoke<boolean>("set_require_token", { enabled });
}

// ─────────── 当前活跃会话 ───────────

/** 活跃会话行：域名 / 进程 / 占位符数量 / 最后活动时间（全部来自内存态，不含原文）。 */
export interface ActiveSession {
  /** 会话标识（内部派生）；界面只展示尾部短标识 */
  session: string;
  host: string;
  /** 客户端可执行文件完整路径（解析不到时为空串） */
  process: string;
  /** 该会话内已建立的占位符映射条数 */
  placeholders: number;
  /** 最后活动距今秒数 */
  idle_secs: number;
  /** 请求已发出、响应未回（TTL 清理会跳过它） */
  pinned: boolean;
}

const MOCK_ACTIVE_SESSIONS: ActiveSession[] = [
  {
    session: "conv:chat.deepseek.com:9f3a-77bc",
    host: "chat.deepseek.com",
    process: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    placeholders: 4,
    idle_secs: 12,
    pinned: true,
  },
  {
    session: "key:api.deepseek.com:a1b2c3d4",
    host: "api.deepseek.com",
    process: "C:\\Windows\\System32\\curl.exe",
    placeholders: 2,
    idle_secs: 96,
    pinned: false,
  },
  {
    session: "hdr:api.moonshot.cn:t-42",
    host: "api.moonshot.cn",
    process: "",
    placeholders: 1,
    idle_secs: 540,
    pinned: false,
  },
];

/** 列出当前活跃会话（按最后活动时间倒序）。 */
export async function listActiveSessions(): Promise<ActiveSession[]> {
  if (!isTauri()) return MOCK_ACTIVE_SESSIONS.map((s) => ({ ...s }));
  return tauriInvoke<ActiveSession[]>("list_active_sessions");
}

/** 应急：切断单个会话（销毁其全部映射），返回被销毁的映射条数。 */
export async function clearOneSession(session: string): Promise<number> {
  if (!isTauri()) return 0;
  return tauriInvoke<number>("clear_one_session", { session });
}

// ─────────── 一键应急切断 ───────────

/** 应急切断结果：逐项回报，未做成的项会在 notes 里说明。 */
export interface PanicReport {
  sessions_cleared: number;
  mappings_cleared: number;
  samples_wiped: number;
  guard_disabled: boolean;
  guard_note: string;
  cert_user_removed: boolean;
  cert_machine_removed: boolean;
  cert_note: string;
  notes: string[];
}

const MOCK_PANIC: PanicReport = {
  sessions_cleared: 3,
  mappings_cleared: 7,
  samples_wiped: 3,
  guard_disabled: true,
  guard_note: "守护已关闭，系统代理与 hosts 引导已还原",
  cert_user_removed: true,
  cert_machine_removed: false,
  cert_note: "已从当前用户信任库移除",
  notes: ["证书与私钥文件已保留在本机；重新开启守护前需重新「安装根证书」"],
};

/** 一键应急切断：清空全部内存映射 + 关闭守护 + 从系统信任库撤销根证书。 */
export async function emergencyCutoff(): Promise<PanicReport> {
  if (!isTauri()) return { ...MOCK_PANIC, notes: [...MOCK_PANIC.notes] };
  return tauriInvoke<PanicReport>("emergency_cutoff");
}

// ─────────── 桌面通知 ───────────

/** 桌面通知配置：拦截 / 高危事件弹系统通知（可选）。 */
export interface NotifyConfig {
  enabled: boolean;
  /** 触发通知的最低严重度：LOW / MEDIUM / HIGH / CRITICAL */
  severity_floor: string;
}

const MOCK_NOTIFY: NotifyConfig = { enabled: true, severity_floor: "HIGH" };

export async function getNotifyConfig(): Promise<NotifyConfig> {
  if (!isTauri()) return { ...MOCK_NOTIFY };
  return tauriInvoke<NotifyConfig>("get_notify_config");
}

export async function setNotifyConfig(config: NotifyConfig): Promise<NotifyConfig> {
  if (!isTauri()) return config;
  return tauriInvoke<NotifyConfig>("set_notify_config", { config });
}

/** 发一条测试通知，用于验证系统通知通道是否可用。 */
export async function testNotification(): Promise<void> {
  if (!isTauri()) return;
  return tauriInvoke<void>("test_notification");
}

// ─────────── 界面语言 ───────────
//
// 语言是**前后端共用**的一份状态：窗口内文案由前端 i18n.ts 负责，
// 托盘菜单 / 桌面通知由后端 i18n.rs 负责，两边都读 kv `ui.language`。
// 因此切换语言必须走后端命令（顺带重建托盘），不能只改前端模块变量。

/** 界面语言标识。后端对无法识别的取值一律回退 "zh"，不会报错。 */
export type LanguageCode = "zh" | "en";

const MOCK_LANGUAGE: LanguageCode = "zh";

export async function getLanguage(): Promise<LanguageCode> {
  if (!isTauri()) return MOCK_LANGUAGE;
  const v = await tauriInvoke<string>("get_language");
  return v === "en" ? "en" : "zh";
}

/** 切换界面语言：落盘 + 立刻重建托盘菜单，返回后端实际保存的取值。 */
export async function setLanguage(language: LanguageCode): Promise<LanguageCode> {
  if (!isTauri()) return language;
  const v = await tauriInvoke<string>("set_language", { language });
  return v === "en" ? "en" : "zh";
}

// ─────────── 首次运行向导 ───────────

/**
 * 首次运行向导状态。
 *
 * `version` / `completed_version` 用于「步骤集合变了要重看一遍」：
 * 两者不一致时应当重新展示向导，而不是只看 `completed`。
 */
export interface OnboardingState {
  completed: boolean;
  completed_version: string;
  version: string;
  app_version: string;
}

const MOCK_ONBOARDING: OnboardingState = {
  completed: true,
  completed_version: "1",
  version: "1",
  app_version: "0.1.0",
};

/**
 * 浏览器预览模式下的向导状态。
 *
 * 默认返回「已完成」——否则每次 `npm run dev` 改别的页面都得先点一次「跳过向导」。
 * 想看向导本身，在地址后加 `?wizard=1` 即可（只在无 Tauri 的预览环境生效）。
 */
function mockOnboarding(): OnboardingState {
  const wantWizard =
    typeof window !== "undefined" && window.location.search.includes("wizard=1");
  return { ...MOCK_ONBOARDING, completed: !wantWizard };
}

/** 读取向导状态（前端据此决定启动时是否展示向导）。 */
export async function getOnboardingState(): Promise<OnboardingState> {
  if (!isTauri()) return mockOnboarding();
  return tauriInvoke<OnboardingState>("get_onboarding_state");
}

/** 标记向导已完成（走完最后一步，或用户主动跳过）。 */
export async function completeOnboarding(): Promise<OnboardingState> {
  if (!isTauri()) return { ...mockOnboarding(), completed: true };
  return tauriInvoke<OnboardingState>("complete_onboarding");
}

/** 重置向导状态，供设置页「重新运行首次向导」使用。 */
export async function resetOnboarding(): Promise<OnboardingState> {
  if (!isTauri()) return { ...mockOnboarding(), completed: false };
  return tauriInvoke<OnboardingState>("reset_onboarding");
}

// ─────────── 全局快捷键 ───────────

/**
 * 快捷键配置。
 *
 * 键位只允许从后端 `SHORTCUT_PRESETS` 白名单里挑——全局快捷键是**抢占式**的，
 * 放开任意字符串等于让一次误配置吞掉用户某个常用组合。前端的下拉选项
 * 必须直接用 `ShortcutState.presets`，不要自己另写一份常量。
 */
export interface ShortcutConfig {
  enabled: boolean;
  /** 开关守护 */
  toggle_guard: string;
  /** 一键应急切断 */
  panic: string;
}

/**
 * 快捷键状态。
 *
 * `failure` 是**技术原因**（解析器 / 系统给出的原文），不是给用户看的结论句——
 * 结论句要按当前语言在前端拼，诊断原文原样透传更利于排查。
 */
export interface ShortcutState {
  config: ShortcutConfig;
  presets: string[];
  /** 两个键位是否都真正注册到了系统 */
  registered: boolean;
  failure: string;
}

const MOCK_SHORTCUT: ShortcutState = {
  config: { enabled: true, toggle_guard: "Ctrl+Alt+G", panic: "Ctrl+Alt+X" },
  presets: [
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
  ],
  registered: true,
  failure: "",
};

export async function getShortcutState(): Promise<ShortcutState> {
  if (!isTauri()) return { ...MOCK_SHORTCUT, config: { ...MOCK_SHORTCUT.config } };
  return tauriInvoke<ShortcutState>("get_shortcut_state");
}

/**
 * 保存快捷键配置。
 *
 * 后端保证**失败整体回滚**：注册不上就退回旧键位并返回 Err，
 * 不会留下「设置里写着已启用、按键却毫无反应」的半套状态。
 * 因此调用方拿到 Err 时只需提示失败并重新拉取状态，无需自己回滚。
 */
export async function setShortcutConfig(config: ShortcutConfig): Promise<ShortcutState> {
  if (!isTauri()) return { ...MOCK_SHORTCUT, config: { ...config } };
  return tauriInvoke<ShortcutState>("set_shortcut_config", { config });
}

// ─────────── 更新检查 ───────────

/**
 * 更新检查配置。
 *
 * **默认关闭**：这是一个隐私工具，「未经开启就对外通信」不可接受。
 * 关闭时后端不会发起任何网络请求（手动点「立即检查」除外）。
 */
export interface UpdateConfig {
  enabled: boolean;
  /** 更新源仓库，`owner/name` 形式（走 GitHub Releases API） */
  repo: string;
}

/** 最近一次更新检查结果（只读展示，不含任何本机信息）。 */
export interface UpdateStatus {
  /** 检查时间（Unix 秒；0 = 从未检查） */
  checked_at: number;
  current: string;
  latest: string;
  has_update: boolean;
  release_name: string;
  release_url: string;
  published_at: string;
  /** 结论说明（检查失败时为错误原因） */
  note: string;
  failed: boolean;
}

export interface UpdateState {
  config: UpdateConfig;
  status: UpdateStatus;
  current_version: string;
}

const MOCK_UPDATE: UpdateState = {
  config: { enabled: false, repo: "Technicalflight/aiguard" },
  status: {
    checked_at: 0,
    current: "0.1.0",
    latest: "",
    has_update: false,
    release_name: "",
    release_url: "",
    published_at: "",
    note: "",
    failed: false,
  },
  current_version: "0.1.0",
};

function cloneUpdateState(s: UpdateState): UpdateState {
  return { config: { ...s.config }, status: { ...s.status }, current_version: s.current_version };
}

export async function getUpdateState(): Promise<UpdateState> {
  if (!isTauri()) return cloneUpdateState(MOCK_UPDATE);
  return tauriInvoke<UpdateState>("get_update_state");
}

/** 保存更新检查配置。关闭总开关后，后端的定时检查会一次请求都不发。 */
export async function setUpdateConfig(config: UpdateConfig): Promise<UpdateState> {
  if (!isTauri()) return cloneUpdateState({ ...MOCK_UPDATE, config: { ...config } });
  return tauriInvoke<UpdateState>("set_update_config", { config });
}

/**
 * 立即检查一次更新。
 *
 * 即使用户把自动检查关着也允许调用——这是**用户明确点击**发起的动作，
 * 不构成「默认上报」。后端把任何失败都折叠进 `UpdateStatus`（不抛 Err），
 * 因此这里不会因为网络不通而抛异常，失败看 `status.failed` / `status.note`。
 */
export async function checkUpdate(): Promise<UpdateState> {
  if (!isTauri()) return cloneUpdateState(MOCK_UPDATE);
  return tauriInvoke<UpdateState>("check_update");
}
