import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import {
  DashboardStats,
  PiiEventPayload,
  RequestLog,
  RuleSpec,
  WhitelistEntry,
  BlacklistEntry,
  CaStatus,
  CaTrustStatus,
  CleanupSettings,
  HardeningStatus,
  PortState,
  SecurityEventRow,
  SecurityPoint,
  SecurityPolicy,
  LinkCheckResult,
  ActiveSession,
  PanicReport,
  NotifyConfig,
  getCaStatus,
  checkCaTrust,
  getHardeningStatus,
  checkProxyPort,
  getProxyToken,
  regenerateProxyToken,
  setRequireToken,
  setRestoreEnabled,
  listActiveSessions,
  clearOneSession,
  emergencyCutoff,
  getNotifyConfig,
  setNotifyConfig,
  testNotification,
  listRequestsPage,
  listAuditPage,
  getCleanupSettings,
  setCleanupSettings,
  cleanupLogsNow,
  clearRequestLogs,
  clearRequestLogsByAction,
  setProxyMode,
  getDashboard,
  getRules,
  getWhitelist,
  getSecurityPoints,
  getSecurityPolicy,
  setSecurityPolicy as apiSetSecurityPolicy,
  listSecurityEvents,
  clearSecurityEvents,
  clearSessions,
  runLinkCheck,
  onSecurityAlert,
  setRule as apiSetRule,
  addCustomRule,
  deleteRule,
  resetRule,
  addWhitelistEntry,
  updateWhitelistEntry,
  removeWhitelistEntry,
  getBlacklist,
  addBlacklistEntry,
  removeBlacklistEntry,
  pickPath,
  enableGuard,
  disableGuard,
  installCa,
  listRequests,
  onPiiDetected,
  getLanguage,
  setLanguage,
  getOnboardingState,
  completeOnboarding,
  resetOnboarding,
  getShortcutState,
  setShortcutConfig,
  getUpdateState,
  setUpdateConfig,
  checkUpdate,
  getCloseBehavior,
  setCloseBehavior,
  confirmClose,
  onCloseRequested,
  testRegex,
  exportRules,
  importRulesPreview,
  importRulesApply,
  getRulePreset,
  applyRulePreset,
  getSemanticConfig,
  setSemanticConfig,
  getLockerConfig,
  setLockerConfig,
  getCustomHosts,
  setCustomHosts,
  type RegexHit,
  type ImportPreview,
  type SemanticConfig,
  type LockerConfig,
  type LockerEntry,
  type ShortcutState,
  type ShortcutConfig,
  type UpdateState,
  type CloseBehavior,
} from "./api";
import { t, tb, useI18n, applyLang, type Lang } from "./i18n";

// ─────────── 环境检测（标题栏窗口控制仅 Tauri 内可用） ───────────

function isTauri(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof (window as any).__TAURI_INTERNALS__ !== "undefined"
  );
}

/**
 * 找最近的滚动祖先（overflow-y: auto/scroll）。
 * 浮层（下拉/日历）的展开方向必须按它的边界判断——
 * 超出滚动容器可视范围的部分会被裁切，window 高度不算数。
 */
function getScrollParent(el: HTMLElement | null): HTMLElement | null {
  let p = el?.parentElement ?? null;
  while (p) {
    const oy = getComputedStyle(p).overflowY;
    if (oy === "auto" || oy === "scroll") return p;
    p = p.parentElement;
  }
  return null;
}

// ─────────── 通用小组件 ───────────

function ShieldIcon({ stroke = "#0e8a5f", size = 36 }: { stroke?: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <path
        d="M12 3l7 3v5c0 4.4-2.9 8.3-7 9.5C7.9 19.3 5 15.4 5 11V6l7-3z"
        stroke={stroke}
        strokeWidth="1.7"
        strokeLinejoin="round"
      />
      <path
        d="M9 11.5l2.2 2.2L15.5 9.5"
        stroke={stroke}
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** 窄导航栏图标（stroke 用 currentColor，颜色由 CSS 控制） */
function RailIcon({ name }: { name: string }) {
  const common = {
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.6,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };
  switch (name) {
    case "home":
      return (
        <svg {...common}>
          <path d="M4 10.5L12 4l8 6.5V19a1 1 0 0 1-1 1h-5v-5h-4v5H5a1 1 0 0 1-1-1v-8.5z" />
        </svg>
      );
    case "requests":
      return (
        <svg {...common}>
          <path d="M3 12h4l2.5-6 4 12 2.5-6h5" />
        </svg>
      );
    case "rules":
      return (
        <svg {...common}>
          <path d="M5 8h9M18 8h1M5 16h1M10 16h9" />
          <circle cx="16" cy="8" r="2.2" />
          <circle cx="8" cy="16" r="2.2" />
        </svg>
      );
    case "audit":
      return (
        <svg {...common}>
          <path d="M6 3h9l4 4v14H6z" />
          <path d="M9 12h6M9 16h6M9 8h3" />
        </svg>
      );
    case "security":
      return (
        <svg {...common}>
          <path d="M12 3l7 3v5c0 4.4-2.9 8.3-7 9.5C7.9 19.3 5 15.4 5 11V6l7-3z" />
          <path d="M12 8.5v4M12 15.2v.1" />
        </svg>
      );
    default:
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="3" />
          <path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.2 5.2l2.1 2.1M16.7 16.7l2.1 2.1M18.8 5.2l-2.1 2.1M7.3 16.7l-2.1 2.1" />
        </svg>
      );
  }
}

function Toggle({ on, onChange }: { on: boolean; onChange: () => void }) {
  return <button className={`toggle ${on ? "on" : ""}`} onClick={onChange} aria-pressed={on} />;
}

// ─────────── 自定义下拉（替代原生 select，全自绘面板） ───────────

export interface DropdownOption {
  value: string;
  label: string;
}

/**
 * 规则命中动作的下拉项。
 *
 * 必须是**函数**而不是模块级常量：文案要按"当前界面语言"求值，
 * 写成模块级常量就会在首次 import 时被求值并冻结——之后切换语言，
 * 这一处永远停在下标语言上（这类 bug 只在切语言后才看得见，极难发现）。
 */
function actionOptions(): DropdownOption[] {
  return [
    { value: "mask", label: t("脱敏") },
    { value: "block", label: t("拦截") },
    { value: "warn", label: t("仅提醒") },
  ];
}

function ChevronDown() {
  return (
    <svg viewBox="0 0 12 12" fill="none">
      <path d="M2.5 4.5L6 8l3.5-3.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg viewBox="0 0 12 12" fill="none">
      <path d="M2.5 6.5L5 9l4.5-5.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Dropdown({
  value,
  options,
  onChange,
  disabled = false,
}: {
  value: string;
  options: DropdownOption[];
  onChange: (v: string) => void;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [up, setUp] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const toggle = () => {
    if (disabled) return;
    if (!open && ref.current) {
      // 按最近滚动容器（内容区 / 弹窗）的真实边界决定展开方向：
      // 下方放不下且上方更宽裕时向上弹出，避免面板被滚动容器裁切
      const r = ref.current.getBoundingClientRect();
      const sc = getScrollParent(ref.current);
      const bounds = sc
        ? sc.getBoundingClientRect()
        : { top: 0, bottom: window.innerHeight };
      const menuH = options.length * 35 + 12;
      const spaceBelow = bounds.bottom - r.bottom - 8;
      const spaceAbove = r.top - bounds.top - 8;
      setUp(spaceBelow < menuH && spaceAbove > spaceBelow);
    }
    setOpen((v) => !v);
  };

  const cur = options.find((o) => o.value === value);
  return (
    <div className={`dd ${open ? "open" : ""} ${disabled ? "disabled" : ""}`} ref={ref}>
      <button type="button" className="dd-btn" onClick={toggle} disabled={disabled}>
        <span>{cur?.label ?? value}</span>
        <ChevronDown />
      </button>
      {open && (
        <div className={`dd-menu ${up ? "up" : ""}`}>
          {options.map((o) => (
            <div
              key={o.value}
              className={`dd-opt ${o.value === value ? "sel" : ""}`}
              onClick={() => {
                onChange(o.value);
                setOpen(false);
              }}
            >
              <span>{o.label}</span>
              {o.value === value && <CheckIcon />}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─────────── 自定义弹窗 ───────────

function Modal({
  title,
  onClose,
  children,
  footer,
  wide,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
  /** 宽体弹窗（名单管理等含表格 / 表单行的内容） */
  wide?: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="modal-mask"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className={wide ? "modal modal-wide" : "modal"}>
        <div className="modal-head">
          <span className="modal-title">{title}</span>
          <button type="button" className="modal-x" onClick={onClose} title={t("关闭")}>
            <svg width="11" height="11" viewBox="0 0 10 10">
              <path d="M1.4 1.4l7.2 7.2M8.6 1.4L1.4 8.6" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
            </svg>
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

// ─────────── 关闭询问弹窗 ───────────

/**
 * 主窗口关闭询问。
 *
 * 后端拦截了所有关闭路径（自绘标题栏 ✕、Alt+F4、任务栏关闭），
 * 行为为「每次询问」时发 close-requested 事件到这里。
 * 勾选「记住我的选择」时先落盘偏好、再执行动作；动作成功后窗口隐藏或
 * 进程退出，onDone 主要服务于取消路径（ESC / 遮罩 / ✕）的收尾。
 */
function CloseAskModal({ onDone }: { onDone: () => void }) {
  const [remember, setRemember] = useState(false);
  const [busy, setBusy] = useState(false);
  // busy 的同步镜像：close 由 Modal 的 ESC/遮罩回调触发，闭包可能拿到旧 state
  const busyRef = useRef(false);

  // busy 期间禁止取消，避免「点了退出又立刻取消」的竞态
  const close = useCallback(() => {
    if (busyRef.current) return;
    onDone();
  }, [onDone]);

  const act = async (action: "exit" | "tray") => {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    try {
      if (remember) await setCloseBehavior(action);
      await confirmClose(action);
      // tray：窗口此刻已隐藏，但只是隐藏不是销毁——React 状态原样保留，
      // 必须在这里收掉弹窗；否则从托盘 show 回来时 Modal 还挂在 busy 态，
      // 整个弹窗点不动也关不掉（按钮全 disabled、close 被 busyRef 挡住）。
      // exit：进程即将退出，这行大概率执行不到（IPC 不回包），仅作兜底。
      if (action === "tray") onDone();
    } catch (e) {
      busyRef.current = false;
      setBusy(false);
      console.error(t("操作失败："), e);
      // 失败保持弹窗打开，用户可重试或按 ✕ 取消（窗口保持打开）
    }
  };

  return (
    <Modal
      title={t("关闭 AI 安全卫士")}
      onClose={close}
      footer={
        <>
          <button className="btn" disabled={busy} onClick={() => void act("tray")}>
            {t("最小化到托盘")}
          </button>
          <button className="btn primary" disabled={busy} onClick={() => void act("exit")}>
            {t("退出程序")}
          </button>
        </>
      }
    >
      <div style={{ lineHeight: 1.7 }}>
        {t("你正在关闭主窗口。退出程序会还原系统代理并停止守护；最小化到托盘则继续在后台运行。")}
      </div>
      <label
        style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 14, cursor: "pointer" }}
      >
        <input
          type="checkbox"
          checked={remember}
          onChange={(e) => setRemember(e.target.checked)}
          style={{ accentColor: "#0E8A5F" }}
        />
        <span>{t("记住我的选择，不再询问")}</span>
      </label>
    </Modal>
  );
}

// ─────────── 自定义日期选择（替代 input[type=date]） ───────────

function dpWeek(): string[] {
  return [t("一"), t("二"), t("三"), t("四"), t("五"), t("六"), t("日")];
}

function fmtDate(d: Date): string {
  const p = (x: number) => String(x).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function DatePicker({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [open, setOpen] = useState(false);
  const [up, setUp] = useState(false);
  const [view, setView] = useState<Date>(() => (value ? new Date(`${value}T00:00:00`) : new Date()));
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const toggle = () => {
    if (!open) {
      setView(value ? new Date(`${value}T00:00:00`) : new Date());
      if (ref.current) {
        // 同 Dropdown：按最近滚动容器的边界判断展开方向
        const r = ref.current.getBoundingClientRect();
        const sc = getScrollParent(ref.current);
        const bounds = sc
          ? sc.getBoundingClientRect()
          : { top: 0, bottom: window.innerHeight };
        const menuH = 340;
        const spaceBelow = bounds.bottom - r.bottom - 8;
        const spaceAbove = r.top - bounds.top - 8;
        setUp(spaceBelow < menuH && spaceAbove > spaceBelow);
      }
    }
    setOpen((v) => !v);
  };

  const y = view.getFullYear();
  const m = view.getMonth();
  const lead = (new Date(y, m, 1).getDay() + 6) % 7; // 周一为一周起点
  const daysInMonth = new Date(y, m + 1, 0).getDate();
  const prevDays = new Date(y, m, 0).getDate();
  const today = fmtDate(new Date());

  const cells: { date: Date; cur: boolean }[] = [];
  for (let i = lead - 1; i >= 0; i--) cells.push({ date: new Date(y, m - 1, prevDays - i), cur: false });
  for (let d = 1; d <= daysInMonth; d++) cells.push({ date: new Date(y, m, d), cur: true });
  let next = 1;
  while (cells.length % 7 !== 0) cells.push({ date: new Date(y, m + 1, next++), cur: false });

  return (
    <div className={`dp ${open ? "open" : ""}`} ref={ref}>
      <button type="button" className={`dp-btn ${value ? "" : "placeholder"}`} onClick={toggle}>
        <span>{value || t("选择日期")}</span>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
          <rect x="3.5" y="5" width="17" height="16" rx="2.5" />
          <path d="M3.5 10h17M8 2.8V6.5M16 2.8V6.5" />
        </svg>
      </button>
      {open && (
        <div className={`dp-panel ${up ? "up" : ""}`}>
          <div className="dp-head">
            <button type="button" className="dp-nav" onClick={() => setView(new Date(y, m - 1, 1))} title={t("上个月")}>
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M7.5 2.5L4 6l3.5 3.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
            <span className="dp-month">
              {y} {t("年")} {m + 1} {t("月")}
            </span>
            <button type="button" className="dp-nav" onClick={() => setView(new Date(y, m + 1, 1))} title={t("下个月")}>
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M4.5 2.5L8 6l-3.5 3.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
          </div>
          <div className="dp-week">
            {dpWeek().map((w) => (
              <span key={w}>{w}</span>
            ))}
          </div>
          <div className="dp-grid">
            {cells.map((c, i) => {
              const ds = fmtDate(c.date);
              return (
                <button
                  type="button"
                  key={i}
                  className={`dp-cell ${c.cur ? "" : "out"} ${ds === value ? "sel" : ""} ${ds === today ? "today" : ""}`}
                  onClick={() => {
                    onChange(ds);
                    setOpen(false);
                  }}
                >
                  {c.date.getDate()}
                </button>
              );
            })}
          </div>
          <div className="dp-foot">
            <a
              onClick={() => {
                onChange("");
                setOpen(false);
              }}
            >
              {t("清除筛选")}
            </a>
          </div>
        </div>
      )}
    </div>
  );
}

function Badge({ text, tone }: { text: string; tone: "green" | "amber" | "red" | "gray" }) {
  // tb()：这里的文案有的来自前端 t()（已是当前语言），有的直接来自后端（中文）。
  // tb() 对不含中文的输入原样返回，因此两种来源都可以安全地过一遍。
  return <span className={`badge ${tone}`}>{tb(text)}</span>;
}

/**
 * 加固项一行：状态点 + 标题 + 说明 + 右侧操作。
 * tone：green = 已生效 / amber = 建议关注 / red = 存在风险。
 */
function HardenLine({
  tone,
  title,
  desc,
  children,
}: {
  tone: "green" | "amber" | "red";
  title: string;
  desc: string;
  children?: ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: 10,
        padding: "13px 0",
        borderTop: "1px solid var(--line)",
      }}
    >
      <span className={`sec-dot ${tone}`} style={{ marginTop: 6 }} aria-hidden />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 500 }}>{tb(title)}</div>
        <div className="muted" style={{ marginTop: 4, wordBreak: "break-all" }}>
          {tb(desc)}
        </div>
      </div>
      {children ? <div style={{ flexShrink: 0 }}>{children}</div> : null}
    </div>
  );
}

/** 敏感信息类型的展示名（按当前语言求值，理由见 actionOptions）。 */
function kindLabel(kind: string): string {
  switch (kind) {
    case "IDCARD":
      return t("身份证");
    case "PHONE":
      return t("手机号");
    case "BANKCARD":
      return t("银行卡");
    case "EMAIL":
      return t("邮箱");
    case "APIKEY":
      return "API Key";
    case "IP":
      return "IP";
    default:
      return kind;
  }
}

function KindBadge({ kind }: { kind: string }) {
  return <Badge text={kindLabel(kind)} tone="amber" />;
}

type Tone = "green" | "amber" | "red" | "gray";

/** 处理结果徽标的文案与配色（按当前语言求值，理由见 actionOptions）。 */
function actionLabel(action: string): { text: string; tone: Tone } {
  switch (action) {
    case "mask":
      return { text: t("已脱敏"), tone: "green" };
    case "block":
      return { text: t("已拦截"), tone: "red" };
    case "warn":
      return { text: t("仅提醒"), tone: "amber" };
    case "passthrough":
      return { text: t("直通"), tone: "gray" };
    default:
      return { text: action, tone: "gray" };
  }
}

function ActionBadge({ action }: { action: string }) {
  const a = actionLabel(action);
  return <Badge text={a.text} tone={a.tone} />;
}

function formatTs(ts: string): string {
  const n = Number(ts);
  if (!n || Number.isNaN(n)) return ts;
  const d = new Date(n * 1000);
  const p = (x: number) => String(x).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function formatUptime(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return `${h}${t("小时")}${m}${t("分")}${s}${t("秒")}`;
}

function parseKinds(kinds: string): string[] {
  try {
    const arr = JSON.parse(kinds);
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

/** 拦截模式的展示名（按当前语言求值，理由见 actionOptions）。 */
function modeLabel(mode: string): string {
  switch (mode) {
    case "hosts_file":
      return t("hosts 模式");
    case "tun":
      return t("TUN 模式");
    default:
      return t("系统代理 + PAC");
  }
}

/** 累计守护天数：以首次运行日为第 1 天（localStorage 持久化） */
function guardDays(): number {
  try {
    const KEY = "aiguard.guard_since";
    let since = Number(localStorage.getItem(KEY));
    if (!since || Number.isNaN(since)) {
      since = Date.now();
      localStorage.setItem(KEY, String(since));
    }
    return Math.max(1, Math.floor((Date.now() - since) / 86400000) + 1);
  } catch {
    return 1;
  }
}

// ─────────── 自定义标题栏：窗口控制按钮 ───────────

type WinAction = "min" | "max" | "close";

function WindowControls() {
  const [inTauri, setInTauri] = useState(false);
  useEffect(() => {
    setInTauri(isTauri());
  }, []);

  // 纯浏览器预览（npm run dev 直开）没有窗口系统，隐藏三个按钮
  if (!inTauri) return null;

  const act = async (a: WinAction) => {
    try {
      const { getCurrentWindow } = await import("@tauri-apps/api/window");
      const w = getCurrentWindow();
      if (a === "min") await w.minimize();
      else if (a === "max") await w.toggleMaximize();
      else await w.close();
    } catch (e) {
      console.error(t("窗口控制失败"), e);
    }
  };

  return (
    <div className="tb-controls">
      <button className="wc" title={t("最小化")} onClick={() => void act("min")}>
        <svg width="10" height="10" viewBox="0 0 10 10">
          <path d="M1 5.3h8" stroke="currentColor" strokeWidth="1.1" strokeLinecap="round" />
        </svg>
      </button>
      <button className="wc" title={t("最大化 / 还原")} onClick={() => void act("max")}>
        <svg width="10" height="10" viewBox="0 0 10 10">
          <rect x="1.2" y="1.2" width="7.6" height="7.6" rx="1.2" stroke="currentColor" strokeWidth="1.1" fill="none" />
        </svg>
      </button>
      <button className="wc close" title={t("关闭")} onClick={() => void act("close")}>
        <svg width="10" height="10" viewBox="0 0 10 10">
          <path d="M1.4 1.4l7.2 7.2M8.6 1.4L1.4 8.6" stroke="currentColor" strokeWidth="1.1" strokeLinecap="round" />
        </svg>
      </button>
    </div>
  );
}

// ─────────── 首页弹幕：拦截 / 脱敏数据流（关键信息以 * 打码展示） ───────────

type TickerItem = { kind: string; sample: string; host: string; action: string };

/** 各类型的打码样例（原文从不落盘，展示的本来就是打码形态） */
const MASK_SAMPLES: Record<string, string[]> = {
  IDCARD: ["1101**********01X", "3101**********22", "4403**********45"],
  PHONE: ["138****5678", "186****3021", "150****8899"],
  BANKCARD: ["6222****1234", "6217****8866", "4392**9012"],
  EMAIL: ["z****@163.com", "l****@gmail.com", "w****@qq.com"],
  APIKEY: ["sk-****9a3f", "sk-****2b8e", "AKIA****Q4H2"],
  IP: ["192.168.*.*", "10.0.*.*", "172.16.*.*"],
};

function buildTickerItems(logs: RequestLog[]): TickerItem[] {
  const items: TickerItem[] = [];
  // 旧 → 新，最多取最近 14 条命中；无命中时返回空（不展示任何演示数据）
  for (const l of [...logs].reverse()) {
    const kinds = parseKinds(l.kinds);
    if (kinds.length === 0) continue;
    for (const k of kinds) {
      const samples = MASK_SAMPLES[k] ?? ["******"];
      items.push({
        kind: k,
        sample: samples[items.length % samples.length],
        host: l.host,
        action: l.action,
      });
    }
  }
  return items.slice(-14);
}

function TickerPill({ item }: { item: TickerItem }) {
  const tone =
    item.action === "block"
      ? "var(--danger)"
      : item.action === "warn"
        ? "var(--warn)"
        : "var(--brand)";
  const actionText = actionLabel(item.action).text;
  return (
    <span className="ticker-pill">
      <span className="fdot" style={{ background: tone }} />
      <span>
        <b>{kindLabel(item.kind)}</b>{" "}
        <span className="mono">{item.sample}</span>
      </span>
      <span className="ticker-sep">·</span>
      <span>{item.host}</span>
      <span className="ticker-sep">·</span>
      <span style={{ color: tone }}>{actionText}</span>
    </span>
  );
}

function TickerBar({ logs }: { logs: RequestLog[] }) {
  const items = buildTickerItems(logs);
  if (items.length === 0) {
    // 暂无真实命中：保留占位弹性空间，不展示任何演示数据
    return <div className="home-ticker" aria-hidden="true" />;
  }
  const rowA = items.filter((_, i) => i % 2 === 0);
  const rowB = items.filter((_, i) => i % 2 === 1);
  return (
    <div className="home-ticker" aria-hidden="true">
      {[rowA, rowB].map((row, ri) =>
        row.length === 0 ? null : (
          <div className={`ticker-row ${ri === 1 ? "rev" : ""}`} key={ri}>
            {[0, 1].map((copy) => (
              <span className="ticker-seg" key={copy}>
                {row.map((it, i) => (
                  <TickerPill key={i} item={it} />
                ))}
              </span>
            ))}
          </div>
        )
      )}
    </div>
  );
}

// ─────────── 页面：守护首页 ───────────

function HomeShieldArt({ off }: { off: boolean }) {
  return (
    <div className={`home-art ${off ? "off" : ""}`}>
      <svg className="art" viewBox="0 0 460 380" fill="none">
        <defs>
          <linearGradient id="shg" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#17a874" />
            <stop offset="1" stopColor="#0b7350" />
          </linearGradient>
        </defs>
        <ellipse cx="230" cy="342" rx="150" ry="16" fill="#0f1714" opacity="0.07" />
        <rect x="112" y="52" width="236" height="236" rx="30" fill="#eef4f1" transform="rotate(45 230 170)" />
        <rect x="138" y="78" width="184" height="184" rx="26" fill="#e2efe9" transform="rotate(45 230 170)" />
        <rect x="164" y="104" width="132" height="132" rx="22" fill="#d5e8df" transform="rotate(45 230 170)" />
        <path d="M28 96h62l18 18" stroke="#cfe3da" strokeWidth="2" />
        <circle cx="28" cy="96" r="3.5" fill="#cfe3da" />
        <path d="M432 118h-56l-14 14" stroke="#cfe3da" strokeWidth="2" />
        <circle cx="432" cy="118" r="3.5" fill="#cfe3da" />
        <path d="M48 236h58l16-16" stroke="#d8e8e0" strokeWidth="2" />
        <circle cx="48" cy="236" r="3.5" fill="#d8e8e0" />
        <path d="M414 252h-52l-14-14" stroke="#d8e8e0" strokeWidth="2" />
        <circle cx="414" cy="252" r="3.5" fill="#d8e8e0" />
        <g>
          <path
            className="shield-fill"
            d="M230 96l58 22v52c0 34-24 61-58 72-34-11-58-38-58-72v-52l58-22z"
            fill="url(#shg)"
          />
          <path
            className="shield-fill-2"
            d="M230 108l48 18v44c0 28-20 51-48 61-28-10-48-33-48-61v-44l48-18z"
            fill="none"
            stroke="rgba(255,255,255,0.35)"
            strokeWidth="2"
          />
          <path d="M206 172l17 17 32-34" stroke="#ffffff" strokeWidth="8" strokeLinecap="round" strokeLinejoin="round" />
        </g>
      </svg>
      <div className="float-chip fc-1">
        <span className="fdot" style={{ background: "var(--brand)" }} />
        {t("手机号 · 已脱敏")}
      </div>
      <div className="float-chip fc-2">
        <span className="fdot" style={{ background: "var(--danger)" }} />
        {t("身份证 · 已拦截")}
      </div>
      <div className="float-chip fc-3">
        <span className="fdot" style={{ background: "var(--brand)" }} />
        {t("API Key · 已脱敏")}
      </div>
    </div>
  );
}

// ─────────── 页面：首页 ───────────

/** 会话标识的短展示：只取尾段（上游对话 id 这类内容不整串铺在界面上）。 */
function sessionTail(session: string): string {
  const parts = session.split(":");
  const tail = parts.length > 2 ? parts[parts.length - 1] : session;
  return tail.length > 14 ? `${tail.slice(0, 8)}…${tail.slice(-4)}` : tail;
}

/** 进程展示名：只取可执行文件名（完整路径在 title 里给）。 */
function procName(path: string): string {
  if (!path) return "";
  const seg = path.split(/[\\/]/).filter(Boolean);
  return seg.length ? seg[seg.length - 1] : path;
}

/** 最后活动时间的人类可读形式。 */
function formatIdle(secs: number): string {
  if (secs < 5) return t("刚刚");
  if (secs < 60) return `${secs}${t(" 秒前")}`;
  if (secs < 3600) return `${Math.floor(secs / 60)}${t(" 分钟前")}`;
  return `${Math.floor(secs / 3600)}${t(" 小时前")}`;
}

/**
 * 当前活跃会话：域名 / 进程 / 占位符数量 / 最后活动时间。
 * 数据全部来自内存态（不含原文），可对单个会话执行「切断」。
 */
function ActiveSessionsCard({
  sessions,
  onRefresh,
  onNavigate,
}: {
  sessions: ActiveSession[];
  onRefresh: () => void;
  onNavigate: (p: "audit" | "settings") => void;
}) {
  const [busy, setBusy] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const cut = async (s: ActiveSession) => {
    setBusy(s.session);
    setMsg("");
    setErr("");
    try {
      const n = await clearOneSession(s.session);
      setMsg(`${t("已切断 ")}${s.host || sessionTail(s.session)}${t(" 会话，销毁 ")}${n}${t(" 条映射")}`);
      onRefresh();
    } catch (e) {
      setErr(`${t("切断失败：")}${errMsg(e)}`);
    }
    setBusy("");
  };

  const totalMaps = sessions.reduce((acc, s) => acc + s.placeholders, 0);

  return (
    <div className="card card-pad sess-card">
      <div className="sess-head">
        <div>
          <div className="sess-title">{t("当前活跃会话")}</div>
          <div className="muted" style={{ marginTop: 4 }}>
            {sessions.length > 0
              ? `${sessions.length}${t(" 个会话 · 已建立 ")}${totalMaps}${t(" 条原文↔占位符映射（仅存于本机内存）")}`
              : t("尚未有 AI 请求经过本机代理")}
          </div>
        </div>
        <button className="btn mini" onClick={onRefresh}>
          {t("刷新")}
        </button>
      </div>

      {(msg || err) && (
        <div className={err ? "notice error" : "notice"} style={{ marginTop: 10 }} role="status">
          <span>{err || msg}</span>
        </div>
      )}

      {sessions.length === 0 ? (
        <div className="sess-empty">
          {t("开启守护后，发往 AI 服务的请求会在这里按会话聚合；每个会话的原文只在本机内存中与占位符对应。")}
        </div>
      ) : (
        <div className="sess-table">
          <div className="sess-row sess-row-head">
            <span>{t("域名")}</span>
            <span>{t("发起进程")}</span>
            <span className="sess-num">{t("占位符")}</span>
            <span>{t("最后活动")}</span>
            <span />
          </div>
          {sessions.map((s) => (
            <div className="sess-row" key={s.session}>
              <span className="sess-host" title={s.session}>
                {s.host || t("（未知域名）")}
                {s.pinned && <span className="sess-pin" title={t("请求已发出、响应未回")}>{t("在途")}</span>}
              </span>
              <span className="sess-proc" title={s.process || t("未识别到发起进程")}>
                {s.process ? procName(s.process) : <span className="muted">{t("未识别")}</span>}
              </span>
              <span className="sess-num">{s.placeholders}</span>
              <span className="muted">{formatIdle(s.idle_secs)}</span>
              <span style={{ textAlign: "right" }}>
                <button
                  className="btn mini"
                  disabled={busy === s.session}
                  onClick={() => void cut(s)}
                  title={t("销毁该会话的原文↔占位符映射（会把该会话的后续回复中的占位符还原为原文的能力一并切断）")}
                >
                  {busy === s.session ? t("切断中…") : t("切断")}
                </button>
              </span>
            </div>
          ))}
        </div>
      )}

      <div className="sess-foot">
        {t("「切断」销毁的是本机内存里该会话的映射：之后该会话的回复中若仍带占位符将无法还原；")}
        <a onClick={() => onNavigate("audit")}>{t("查看审计日志")}</a> {t("或在")}
        <a onClick={() => onNavigate("settings")}>{t("设置")}</a> {t("中应急切断全部。")}
      </div>
    </div>
  );
}

/**
 * 一键应急切断：清空全部内存映射 + 关闭守护 + 从系统信任库撤销根证书。
 * 三步各自独立推进，结果逐项回报。
 */
function PanicButton({ onDone }: { onDone: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState<PanicReport | null>(null);
  const [err, setErr] = useState("");

  const run = async () => {
    setRunning(true);
    setErr("");
    try {
      const r = await emergencyCutoff();
      setReport(r);
      onDone();
    } catch (e) {
      setErr(errMsg(e));
    }
    setRunning(false);
  };

  return (
    <>
      <button className="cta danger" onClick={() => setConfirming(true)}>
        {t("一键应急切断")}
      </button>

      {confirming && !report && (
        <Modal
          title={t("确认执行应急切断？")}
          onClose={() => (running ? undefined : setConfirming(false))}
          footer={
            <>
              <button className="btn" disabled={running} onClick={() => setConfirming(false)}>
                {t("取消")}
              </button>
              <button className="btn danger" disabled={running} onClick={() => void run()}>
                {running ? t("执行中…") : t("立即执行")}
              </button>
            </>
          }
        >
          <div style={{ lineHeight: 1.7 }}>
            {t("将依次执行以下三步，立即生效：")}
            <ol style={{ margin: "8px 0 0 18px", padding: 0 }}>
              <li>{t("清空本机内存中的全部原文↔占位符映射与请求正文采样；")}</li>
              <li>{t("关闭守护，还原系统代理与 hosts 引导；")}</li>
              <li>{t("从系统信任库撤销本应用的根证书。")}</li>
            </ol>
            <div className="notice" style={{ marginTop: 12, alignItems: "flex-start" }}>
              <span>
                {t("撤销证书后，本机将不再能解密 AI 流量；重新开启守护前需要先「安装根证书」。")}{" "}{t("证书与私钥文件会保留在本机。")}
              </span>
            </div>
            {err && (
              <div className="notice error" style={{ marginTop: 10 }}>
                <span>{err}</span>
              </div>
            )}
          </div>
        </Modal>
      )}

      {report && (
        <Modal
          title={t("应急切断已执行")}
          onClose={() => {
            setReport(null);
            setConfirming(false);
          }}
          footer={
            <button
              className="btn primary"
              onClick={() => {
                setReport(null);
                setConfirming(false);
              }}
            >
              {t("知道了")}
            </button>
          }
        >
          <div className="panic-report">
            <HardenLine
              tone="green"
              title={`${t("内存映射已清空（")}${report.sessions_cleared}${t(" 个会话 / ")}${report.mappings_cleared}${t(" 条映射）")}`}
              desc={`${t("同时擦除请求正文采样 ")}${report.samples_wiped}${t(" 条；销毁时逐字段零化覆写")}`}
            />
            <HardenLine
              tone={report.guard_disabled ? "green" : "red"}
              title={report.guard_disabled ? t("守护已关闭") : t("守护未能关闭")}
              desc={tb(report.guard_note)}
            />
            <HardenLine
              tone={
                report.cert_user_removed || report.cert_machine_removed
                  ? "green"
                  // 这里比对的是**后端返回的中文原文**，不能过 t()：英文模式下
                  // t() 会返回英文，跟后端的中文永远比不相等，证书状态就会被误判成红色。
                  : report.cert_note.includes("未找到")
                    ? "amber"
                    : "red"
              }
              title={
                report.cert_user_removed && report.cert_machine_removed
                  ? t("根证书已从全部信任库撤销")
                  : report.cert_user_removed || report.cert_machine_removed
                    ? t("根证书已部分撤销")
                    : t("根证书未撤销")
              }
              desc={tb(report.cert_note)}
            />
            {report.notes.length > 0 && (
              <ul className="panic-notes">
                {report.notes.map((n, i) => (
                  <li key={i}>{tb(n)}</li>
                ))}
              </ul>
            )}
          </div>
        </Modal>
      )}
    </>
  );
}

function HomePage({
  stats,
  logs,
  sessions,
  guardEnabled,
  onToggleGuard,
  onSessionsRefresh,
  onNavigate,
}: {
  stats: DashboardStats | null;
  logs: RequestLog[];
  sessions: ActiveSession[];
  guardEnabled: boolean;
  onToggleGuard: () => void;
  onSessionsRefresh: () => void;
  onNavigate: (p: "requests" | "rules" | "audit" | "settings") => void;
}) {
  const s = stats;
  const modeName = modeLabel(s?.mode ?? "system_proxy");
  return (
    <div className="page page-home">
      <div className="home-top">
        <div className="home-main">
          <div className="home-days">
            {t("已守护")}<b>{guardDays()}</b>{t("天")}
            {s && <span className="home-uptime">{t("本次运行")} {formatUptime(s.uptime_secs)}</span>}
          </div>
          <h1 className="home-title">
            {guardEnabled ? t("AI 安全卫士正在保护您的数据") : t("守护未开启，敏感信息可能随请求出网")}
          </h1>
          <div className="home-sub">
            {guardEnabled ? t("敏感信息在本机完成检测与还原，原文永不出网") : t("点击下方按钮立即开启，全程仅需数秒")}
          </div>
          <div className="home-cta-row">
            {!guardEnabled ? (
              <button className="cta" onClick={onToggleGuard}>
                {t("立即开启守护")}
              </button>
            ) : (
              <button className="cta ghost" onClick={onToggleGuard}>
                {t("运行中 · 暂停守护")}
              </button>
            )}
            <PanicButton onDone={onSessionsRefresh} />
            <span className="badge green">{modeName}</span>
          </div>
          <div className="home-tip">
            <div className="home-tip-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                <circle cx="12" cy="12" r="9" stroke="#0e8a5f" strokeWidth="1.6" />
                <path d="M12 8v4.5" stroke="#0e8a5f" strokeWidth="1.6" strokeLinecap="round" />
                <circle cx="12" cy="15.8" r="1" fill="#0e8a5f" />
              </svg>
              {t("本机脱敏 · 数据不出网")}
            </div>
            <div className="home-tip-body">
              {t("检测与还原全部在本机完成：命中即替换为占位符发往 AI 服务，响应到达后再还原展示；日志仅记录命中类型与哈希。")}
            </div>
            <div className="home-tip-links">
              <a onClick={() => onNavigate("rules")}>{t("查看检测规则")}</a>
              <a onClick={() => onNavigate("audit")}>{t("查看审计日志")}</a>
            </div>
          </div>
        </div>
        <HomeShieldArt off={!guardEnabled} />
      </div>

      {/* 弹幕：拦截 / 脱敏数据流（打码胶囊，两行反向滚动） */}
      <TickerBar logs={logs} />

      <div className="home-stats">
        <div className="home-stat">
          <span className="home-stat-value">{s?.total_requests ?? 0}</span>
          <span className="home-stat-label">{t("今日请求")}</span>
        </div>
        <div className="home-stat">
          <span className="home-stat-value" style={{ color: "var(--brand)" }}>
            {s?.total_scrubbed ?? 0}
          </span>
          <span className="home-stat-label">{t("已脱敏")}</span>
        </div>
        <div className="home-stat">
          <span className="home-stat-value" style={{ color: "var(--danger)" }}>
            {s?.total_blocked ?? 0}
          </span>
          <span className="home-stat-label">{t("已拦截")}</span>
        </div>
        <div className="home-stat">
          <span className="home-stat-value">{s?.active_sessions ?? 0}</span>
          <span className="home-stat-label">{t("活跃会话")}</span>
        </div>
      </div>

      <ActiveSessionsCard
        sessions={sessions}
        onRefresh={onSessionsRefresh}
        onNavigate={(p) => onNavigate(p)}
      />

      <div className="home-foot">
        <div className="quick-row">
          <button className="quick" onClick={() => onNavigate("settings")}>
            <span className="quick-ico">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 3l7 3v5c0 4.4-2.9 8.3-7 9.5C7.9 19.3 5 15.4 5 11V6l7-3z" />
                <path d="M9.5 12l2 2 3.5-4" />
              </svg>
            </span>
            {t("安装证书")}
          </button>
          <button className="quick" onClick={() => onNavigate("requests")}>
            <span className="quick-ico">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <path d="M3 12h4l2.5-6 4 12 2.5-6h5" />
              </svg>
            </span>
            {t("实时请求")}
          </button>
          <button className="quick" onClick={() => onNavigate("rules")}>
            <span className="quick-ico">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
                <path d="M5 8h9M18 8h1M5 16h1M10 16h9" />
                <circle cx="16" cy="8" r="2.2" />
                <circle cx="8" cy="16" r="2.2" />
              </svg>
            </span>
            {t("规则中心")}
          </button>
          <button className="quick" onClick={() => onNavigate("audit")}>
            <span className="quick-ico">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <path d="M6 3h9l4 4v14H6z" />
                <path d="M9 12h6M9 16h6M9 8h3" />
              </svg>
            </span>
            {t("审计日志")}
          </button>
        </div>
        <div className="home-meta">
          <div>{t("版本：0.1.0")}</div>
          <div>{t("模式：")}{modeName}</div>
        </div>
      </div>
    </div>
  );
}

// ─────────── 页面：实时请求 ───────────

type RequestFilter = "all" | "mask" | "block";

function RequestsPage() {
  const [filter, setFilter] = useState<RequestFilter>("all");
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<RequestLog[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [detail, setDetail] = useState<RequestLog | null>(null);
  const [rules, setRules] = useState<RuleSpec[]>([]);
  const PAGE_SIZE = 20;

  // 命中规则详情：打开弹窗需要 tag → 规则 的映射，进入页面时拉取一次
  useEffect(() => {
    getRules()
      .then(setRules)
      .catch(() => {});
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await listRequestsPage(page, PAGE_SIZE, filter);
      setItems(r.items);
      setTotal(r.total);
    } catch {
      // 浏览器预览走 MOCK
    } finally {
      setLoading(false);
    }
  }, [page, filter]);

  useEffect(() => {
    void load();
  }, [load]);

  const switchFilter = (f: RequestFilter) => {
    setFilter(f);
    setPage(1); // 切换筛选回到第一页
  };

  /** 按命中类型找到对应规则（优先启用的） */
  const ruleOf = (tag: string): RuleSpec | undefined => {
    const hit = rules.filter((r) => r.tag === tag);
    return hit.find((r) => r.enabled) ?? hit[0];
  };

  return (
    <div className="page-pad">
      <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
        <button className={`chip ${filter === "all" ? "active" : ""}`} onClick={() => switchFilter("all")}>
          {t("全部")}
        </button>
        <button className={`chip ${filter === "mask" ? "active" : ""}`} onClick={() => switchFilter("mask")}>
          {t("已脱敏")}
        </button>
        <button className={`chip ${filter === "block" ? "active" : ""}`} onClick={() => switchFilter("block")}>
          {t("已拦截")}
        </button>
        <span style={{ flex: 1 }} />
        <button className="btn mini" onClick={() => void load()} disabled={loading}>
          {loading ? t("加载中…") : t("刷新")}
        </button>
      </div>
      <div className="card">
        {items.length === 0 ? (
          <div className="empty">
            <div className="empty-icon">
              <ShieldIcon size={24} />
            </div>
            {t("暂无拦截记录，守护静默运行中")}
          </div>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>{t("时间")}</th>
                <th>{t("域名")}</th>
                <th>{t("路径")}</th>
                <th>{t("命中类型")}</th>
                <th>{t("动作")}</th>
                <th>{t("哈希")}</th>
                <th style={{ width: 60 }}>{t("详情")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((l) => (
                <tr
                  key={l.id}
                  className="row-clickable"
                  title={t("查看脱敏流程详情")}
                  onClick={() => setDetail(l)}
                >
                  <td className="hit-time">{formatTs(l.ts)}</td>
                  <td>{l.host}</td>
                  <td className="muted">{l.path}</td>
                  <td>
                    {parseKinds(l.kinds).length === 0 ? (
                      <span className="muted">—</span>
                    ) : (
                      parseKinds(l.kinds).map((k, i) => <KindBadge key={i} kind={k} />)
                    )}
                  </td>
                  <td>
                    <ActionBadge action={l.action} />
                  </td>
                  <td className="muted mono">{l.req_hash || "—"}</td>
                  <td>
                    <button
                      className="btn mini"
                      onClick={(e) => {
                        e.stopPropagation();
                        setDetail(l);
                      }}
                    >
                      {t("详情")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <Pager page={page} pageSize={PAGE_SIZE} total={total} onPage={setPage} />

      {detail && (
        <Modal title={t("请求处理详情")} onClose={() => setDetail(null)}>
          <RequestDetail log={detail} rules={rules} ruleOf={ruleOf} />
        </Modal>
      )}
    </div>
  );
}

/** 分页控件（上一页 / 下一页 / 页码信息） */
function Pager({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (p: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="pager">
      <button className="btn mini" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        {t("上一页")}
      </button>
      <span className="muted">
        {t("第")} {page} / {pages} {t("页 · 共")} {total} {t("条")}
      </span>
      <button className="btn mini" disabled={page >= pages} onClick={() => onPage(page + 1)}>
        {t("下一页")}
      </button>
    </div>
  );
}

/** 请求详情：基本信息 + 命中规则 + 脱敏流程（原文不落盘，仅展示类型与占位符形态） */
function RequestDetail({
  log,
  rules,
  ruleOf,
}: {
  log: RequestLog;
  rules: RuleSpec[];
  ruleOf: (tag: string) => RuleSpec | undefined;
}) {
  const kinds = parseKinds(log.kinds);
  const isBlock = log.blocked === 1 || log.action === "block";
  const enabledRules = rules.filter((r) => r.enabled);

  return (
    <div>
      {/* 基本信息 */}
      <div className="detail-grid">
        <div><span className="detail-k">{t("时间")}</span><span>{formatTs(log.ts)}</span></div>
        <div><span className="detail-k">{t("处理结果")}</span><ActionBadge action={log.action} /></div>
        <div><span className="detail-k">{t("目标域名")}</span><span>{log.host}</span></div>
        <div><span className="detail-k">{t("请求路径")}</span><span className="mono">{log.path}</span></div>
        <div><span className="detail-k">{t("会话标识")}</span><span className="mono">{log.session || "—"}</span></div>
        <div><span className="detail-k">{t("请求指纹")}</span><span className="mono">{log.req_hash || "—"}</span></div>
      </div>

      {/* 命中规则 */}
      <div className="detail-section-title">{t("命中规则（")}{kinds.length}{t("）")}</div>
      {kinds.length === 0 ? (
        <div className="muted">{t("本次请求未命中敏感信息规则，原样直通。")}</div>
      ) : (
        <div className="rule-hit-list">
          {kinds.map((tag, i) => {
            const r = ruleOf(tag);
            return (
              <div className="rule-hit" key={i}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <KindBadge kind={tag} />
                  <span style={{ fontWeight: 500 }}>
                    {r ? tb(r.name) : t("规则详情不可用（规则已被删除）")}
                  </span>
                  <Badge
                    text={r ? (r.action === "block" ? t("拦截") : t("替换为占位符")) : "—"}
                    tone={r ? (r.action === "block" ? "red" : "green") : "gray"}
                  />
                </div>
                {r && (
                  <div className="muted mono" style={{ marginTop: 6, wordBreak: "break-all" }}>
                    {t("匹配形态：")}{r.regex}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* 脱敏流程 */}
      <div className="detail-section-title">{t("脱敏流程")}</div>
      <div className="flow">
        <div className="flow-step">
          <div className="flow-dot">1</div>
          <div className="flow-body">
            <div className="flow-title">{t("请求进入本机代理")}</div>
            <div className="muted">{t("浏览器 / 应用发往")} {log.host} {t("的请求被本地代理接管，正文在本机内存中检测。")}</div>
          </div>
        </div>
        <div className="flow-step">
          <div className="flow-dot">2</div>
          <div className="flow-body">
            <div className="flow-title">{t("敏感信息检测（")}{kinds.length} {t("类命中）")}</div>
            <div className="muted">
              {t("检测引擎按启用的规则逐条匹配（")}{enabledRules.length} {t("条规则生效），配合校验器（身份证校验位 / 银行卡 Luhn 等）剔除误报。")}
            </div>
          </div>
        </div>
        {isBlock ? (
          <div className="flow-step">
            <div className="flow-dot danger">3</div>
            <div className="flow-body">
              <div className="flow-title">{t("请求被拦截，AI 服务未收到任何内容")}</div>
              <div className="muted">{t("命中「拦截」级规则，本次请求被直接终止（返回 403），原文也不会写日志。")}</div>
            </div>
          </div>
        ) : (
          <>
            <div className="flow-step">
              <div className="flow-dot">3</div>
              <div className="flow-body">
                <div className="flow-title">{t("原文替换为占位符（在本机内存完成）")}</div>
                <div className="muted" style={{ marginTop: 4 }}>
                  {t("每类命中内容被替换为会话级占位符，形态如下（末尾 8 位随机码仅本会话有效）：")}
                </div>
                <div className="flow-sample mono">
                  {kinds.length > 0 ? (
                    kinds.map((tag, i) => (
                      <div key={i}>
                        {t("原文（不落盘）→ [[PII:")}{tag}:a1b2c3d4]]
                      </div>
                    ))
                  ) : (
                    <div>[[PII:TAG:a1b2c3d4]]</div>
                  )}
                </div>
              </div>
            </div>
            <div className="flow-step">
              <div className="flow-dot">4</div>
              <div className="flow-body">
                <div className="flow-title">{t("脱敏后的请求转发 AI 服务")}</div>
                <div className="muted">{t("AI 服务只能看到占位符，无法获得真实内容（本次请求指纹：")}{log.req_hash || "—"}{t("）。")}</div>
              </div>
            </div>
            <div className="flow-step">
              <div className="flow-dot">5</div>
              <div className="flow-body">
                <div className="flow-title">{t("响应到达后在本机还原展示")}</div>
                <div className="muted">
                  {t("AI 回复中引用的占位符按本机内存映射表还原后交付应用；映射仅存内存，随会话过期自动销毁。")}
                </div>
              </div>
            </div>
          </>
        )}
      </div>

      <div className="muted" style={{ marginTop: 12, fontSize: 12 }}>
        {t("隐私说明：日志仅记录时间 / 域名 / 命中类型与请求指纹；请求原文、占位符与映射关系均不落盘。")}
      </div>
    </div>
  );
}

// ─────────── 页面：规则中心（编辑 / 自定义 / 白名单） ───────────

/** 统一错误文案：Tauri 后端返回字符串，浏览器环境可能是 Error 对象 */
/**
 * 错误对象 → 可展示文案。
 *
 * 后端所有失败路径都是 `Err(String)` 且内容是中文，因此这里统一过一遍 tb()：
 * 英文模式下会按后端词典翻译（含 `绑定 443 端口失败（…）: 拒绝访问` 这种
 * 「模板 + 内层原因」的组合，内层原因会被递归翻译）；词典里没有的片段保持中文。
 * 中文模式下 tb() 原样返回，零开销。
 */
function errMsg(e: unknown): string {
  if (typeof e === "string") return tb(e);
  if (e instanceof Error) return tb(e.message);
  return tb(String(e));
}

// ─────────── 规则工具箱组件（执行顺序可视化 / 预设 / 测试器 / 导入导出） ───────────

/**
 * 规则执行顺序可视化：黑名单 → 白名单 → 检测规则 三层流水线。
 * 把原本只在文档里的优先级规则画进 UI：每层显示当前条数与一句话语义，
 * 箭头表达「上一层定结果，下一层才轮到」的短路关系。
 * 黑 / 白名单节点可点击 → 弹出对应名单的管理弹窗（页面不再重复铺两块名单区）。
 */
function PriorityFlow({
  bl,
  wl,
  rules,
  enabled,
  onOpen,
}: {
  bl: number;
  wl: number;
  rules: number;
  enabled: number;
  onOpen: (list: "black" | "white") => void;
}) {
  const nodes: {
    key: "black" | "white" | "rules";
    dot: string;
    name: string;
    count: string;
    desc: string;
  }[] = [
    {
      key: "black",
      dot: "#B23B3B",
      name: t("黑名单"),
      count: t("条数：") + bl,
      desc: t("命中即强制执行所选动作（拦截请求 / 强制脱敏），优先于一切"),
    },
    {
      key: "white",
      dot: "#0E8A5F",
      name: t("白名单"),
      count: t("条数：") + wl,
      desc: t("命中则不拦截；关闭「仍执行脱敏」的条目完全直通"),
    },
    {
      key: "rules",
      dot: "#35618F",
      name: t("检测规则"),
      count: t("启用中：") + `${enabled} / ${rules}`,
      desc: t("按正则命中逐条处理：脱敏为占位符 / 拦截请求 / 仅告警"),
    },
  ];
  return (
    <div className="card card-pad">
      <div style={{ display: "flex", alignItems: "stretch", gap: 0, flexWrap: "wrap" }}>
        {nodes.map((n, i) => {
          const clickable = n.key !== "rules";
          const inner = (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span className={`sec-dot ${i === 0 ? "red" : i === 1 ? "green" : "amber"}`} aria-hidden />
                <span style={{ fontWeight: 600 }}>{tb(n.name)}</span>
                <span className="muted" style={{ fontSize: 12 }}>{n.count}</span>
                {clickable && <span className="flow-node-chip">{t("管理")}</span>}
              </div>
              <div className="muted" style={{ marginTop: 6, fontSize: 12, lineHeight: 1.6 }}>{tb(n.desc)}</div>
            </>
          );
          return (
            <div key={n.key} style={{ display: "flex", alignItems: "stretch", flex: "1 1 220px", minWidth: 0 }}>
              {i > 0 && (
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    padding: "0 10px",
                    color: "var(--muted, #8a938f)",
                    flexShrink: 0,
                  }}
                  aria-hidden
                >
                  <svg width="18" height="12" viewBox="0 0 18 12">
                    <path d="M1 6h13M10 1.5L15 6l-5 4.5" stroke="currentColor" strokeWidth="1.4" fill="none" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
              )}
              {clickable ? (
                <button
                  type="button"
                  className="flow-node-btn"
                  onClick={() => onOpen(n.key as "black" | "white")}
                >
                  {inner}
                </button>
              ) : (
                <div
                  style={{
                    flex: 1,
                    minWidth: 0,
                    border: "1px solid var(--line)",
                    borderRadius: 8,
                    padding: "10px 12px",
                  }}
                >
                  {inner}
                </div>
              )}
            </div>
          );
        })}
      </div>
      <div className="muted" style={{ marginTop: 10, fontSize: 12 }}>
        {t("请求进入守护域名时按此顺序评估：黑名单命中即定结果并短路，白名单命中决定是否拦截，最后由检测规则按正则逐条处理正文。点击名单节点管理对应名单。")}
      </div>
    </div>
  );
}

/** 三档预设的说明文案（与 core::detector 的映射一一对应）。 */
const PRESET_DESCS: Record<string, () => string> = {
  conservative: () =>
    t("只守身份证、银行卡、API 密钥三类最高危（全部脱敏），其余关闭——打扰最小。"),
  balanced: () =>
    t("内置默认：身份证 / 手机号 / 银行卡 / 邮箱 / API 密钥脱敏，IP 关闭（避免版本号误伤）。"),
  aggressive: () =>
    t("全部六类启用，身份证 / 银行卡 / API 密钥升级为拦截（宁可拦下含高危信息的整条请求）。"),
};

/**
 * 内置规则预设卡片：保守 / 均衡 / 激进三档一键切换。
 * 应用前弹确认（会覆盖内置规则的开关与动作）；档位由后端比对判定，
 * 用户手动改过任何内置规则即显示「自定义」。
 */
function RulePresetCard({ onChanged }: { onChanged: () => void }) {
  const [preset, setPreset] = useState<string>("");
  const [pending, setPending] = useState<"conservative" | "balanced" | "aggressive" | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        setPreset(await getRulePreset());
      } catch (e) {
        setErr(errMsg(e));
      }
    })();
  }, []);

  const apply = async () => {
    if (!pending) return;
    setBusy(true);
    setErr("");
    try {
      await applyRulePreset(pending);
      setPreset(pending);
      setMsg(
        pending === "conservative"
          ? t("已应用「保守」预设")
          : pending === "aggressive"
          ? t("已应用「激进」预设")
          : t("已应用「均衡」预设")
      );
      setPending(null);
      onChanged();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const isCur = (p: string) => preset === p;
  const options: { key: "conservative" | "balanced" | "aggressive"; label: string }[] = [
    { key: "conservative", label: t("保守") },
    { key: "balanced", label: t("均衡") },
    { key: "aggressive", label: t("激进") },
  ];

  return (
    <div className="card card-pad">
      <HardenLine
        tone="green"
        title={t("内置规则预设")}
        desc={t("一键切换内置规则的开关与动作；自定义规则与黑 / 白名单不受影响，正则不改动。")}
      >
        <div style={{ display: "flex", gap: 6 }}>
          {options.map((o) => (
            <button
              key={o.key}
              className={`btn mini ${isCur(o.key) ? "primary" : ""}`}
              disabled={busy}
              onClick={() => setPending(o.key)}
            >
              {o.label}
            </button>
          ))}
        </div>
      </HardenLine>
      {options.map((o) => (
        <div key={o.key} className="muted" style={{ padding: "7px 0 0", fontSize: 12.5, lineHeight: 1.6 }}>
          <span style={{ fontWeight: 500, color: isCur(o.key) ? "var(--brand, #0E8A5F)" : undefined }}>
            {isCur(o.key) ? "● " : "○ "}
          </span>
          {`${o.label}${t("：")}${PRESET_DESCS[o.key]()}`}
        </div>
      ))}
      {preset === "custom" && (
        <div className="muted" style={{ paddingTop: 8, fontSize: 12.5 }}>
          {t("当前为自定义配置（手动改过内置规则的开关或动作）；应用任一预设会覆盖这些改动。")}
        </div>
      )}
      {msg && <div className="muted" style={{ paddingTop: 8 }}>{msg}</div>}
      {err && <div className="form-err" style={{ marginTop: 10 }}>{err}</div>}

      {pending && (
        <Modal title={t("应用内置规则预设")} onClose={() => !busy && setPending(null)}>
          <div style={{ lineHeight: 1.7 }}>
            {`${t("将把内置规则的开关与动作覆盖为「")}${options.find((o) => o.key === pending)?.label ?? pending}${t("」档：")}${PRESET_DESCS[pending]()}`}
          </div>
          <div className="muted" style={{ marginTop: 10, fontSize: 12.5 }}>
            {t("自定义规则与黑 / 白名单不受影响；随后可在规则列表里继续单独微调。")}
          </div>
          <div className="modal-foot" style={{ marginTop: 16, display: "flex", justifyContent: "flex-end", gap: 8 }}>
            <button className="btn" disabled={busy} onClick={() => setPending(null)}>
              {t("取消")}
            </button>
            <button className="btn primary" disabled={busy} onClick={() => void apply()}>
              {t("应用")}
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

/** FNV-1a 哈希 → 8 位 hex。测试器用它给每个命中生成稳定的假占位符尾缀（纯本地计算）。 */
function fnv8hex(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/**
 * 正则测试器：输入正则 + 样本 → 高亮命中 + 实时预览替换结果。
 * 走后端 test_regex（与线上引擎同一 regex crate），测试即线上行为；
 * 浏览器预览模式用 JS RegExp 近似模拟。防抖 250ms。
 */
function RegexTesterCard({ onApplyToForm }: { onApplyToForm: (regex: string, tag: string) => void }) {
  const [regex, setRegex] = useState("");
  const [tag, setTag] = useState("");
  const [sample, setSample] = useState("");
  const [hits, setHits] = useState<RegexHit[] | null>(null);
  const [err, setErr] = useState("");
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    if (!regex.trim() || !sample) {
      setHits(null);
      setErr("");
      return;
    }
    const timer = setTimeout(() => {
      setTesting(true);
      testRegex(regex, sample)
        .then((r) => {
          setHits(r);
          setErr("");
        })
        .catch((e) => {
          setHits(null);
          setErr(errMsg(e));
        })
        .finally(() => setTesting(false));
    }, 250);
    return () => clearTimeout(timer);
  }, [regex, sample]);

  const tagUp = (tag.trim() || "CUSTOM").toUpperCase();
  // 样本分段：命中段高亮 / 替换预览用同一份切分
  const segments: { text: string; hit: RegexHit | null }[] = [];
  if (sample && hits) {
    let cursor = 0;
    // H2T：按「字符偏移」取段需要 Array.from 切（JS 字符串索引是 UTF-16 码元）
    const chars = Array.from(sample);
    for (const h of hits) {
      if (h.start > cursor) segments.push({ text: chars.slice(cursor, h.start).join(""), hit: null });
      segments.push({ text: chars.slice(h.start, h.start + h.len).join(""), hit: h });
      cursor = h.start + h.len;
    }
    if (cursor < chars.length) segments.push({ text: chars.slice(cursor).join(""), hit: null });
  }

  return (
    <div className="card card-pad">
      <HardenLine
        tone="green"
        title={t("正则测试器")}
        desc={t("与线上引擎同一套正则语义（Unicode \\b、不支持前后瞻）；测试通过后可一键填入下方新增规则。")}
      />
      <div className="form-grid" style={{ marginTop: 10 }}>
        <label className="field" style={{ gridColumn: "1 / -1" }}>
          <span className="field-label">{t("正则表达式")}</span>
          <input
            className="input mono"
            value={regex}
            spellCheck={false}
            onChange={(e) => setRegex(e.target.value)}
            placeholder={t("如：阿尔法计划|贝塔计划")}
          />
        </label>
        <label className="field">
          <span className="field-label">{t("占位符标签（可选）")}</span>
          <input
            className="input"
            value={tag}
            spellCheck={false}
            onChange={(e) => setTag(e.target.value)}
            placeholder={t("默认 CUSTOM")}
          />
        </label>
        <div className="field" style={{ alignSelf: "end" }}>
          <button
            className="btn"
            disabled={!regex.trim() || !hits || hits.length === 0}
            onClick={() => onApplyToForm(regex, tagUp)}
          >
            {t("填入新增规则")}
          </button>
        </div>
        <label className="field" style={{ gridColumn: "1 / -1" }}>
          <span className="field-label">{t("测试样本")}</span>
          <textarea
            className="input mono"
            rows={4}
            maxLength={20000}
            value={sample}
            spellCheck={false}
            onChange={(e) => setSample(e.target.value)}
            placeholder={t("粘贴一段可能包含敏感信息的文本，实时查看命中与脱敏效果")}
            style={{ resize: "vertical" }}
          />
        </label>
      </div>

      {err && <div className="form-err" style={{ marginTop: 8 }}>{err}</div>}
      {sample && !err && (
        <>
          <div className="muted" style={{ marginTop: 10, fontSize: 12.5 }}>
            {testing
              ? t("测试中…")
              : hits === null
              ? t("输入正则与样本后自动测试")
              : `${t("命中：")}${hits.length}`}
          </div>
          {hits && hits.length > 0 && (
            <>
              <div className="muted" style={{ marginTop: 8, fontSize: 12 }}>{t("命中高亮")}</div>
              <div
                className="mono"
                style={{
                  marginTop: 4,
                  padding: "10px 12px",
                  border: "1px solid var(--line)",
                  borderRadius: 8,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  lineHeight: 1.7,
                  maxHeight: 180,
                  overflowY: "auto",
                }}
              >
                {segments.map((s, i) =>
                  s.hit ? (
                    <mark
                      key={i}
                      title={t("占位符标签")}
                      style={{
                        background: "rgba(14, 138, 95, 0.14)",
                        color: "inherit",
                        borderRadius: 3,
                        padding: "1px 2px",
                      }}
                    >
                      {s.text}
                    </mark>
                  ) : (
                    <span key={i}>{s.text}</span>
                  )
                )}
              </div>
              <div className="muted" style={{ marginTop: 8, fontSize: 12 }}>{t("替换结果预览")}</div>
              <div
                className="mono"
                style={{
                  marginTop: 4,
                  padding: "10px 12px",
                  border: "1px solid var(--line)",
                  borderRadius: 8,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  lineHeight: 1.7,
                  maxHeight: 180,
                  overflowY: "auto",
                }}
              >
                {segments.map((s, i) =>
                  s.hit ? (
                    <span key={i} style={{ color: "var(--brand, #0E8A5F)" }}>
                      {`[[PII:${tagUp}:${fnv8hex(`${tagUp}:${s.hit.text}`)}]]`}
                    </span>
                  ) : (
                    <span key={i}>{s.text}</span>
                  )
                )}
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}

/**
 * 规则导入 / 导出 / 分享：JSON 规则包（format = aiguard.rules，v1）。
 * 导出 = 全部规则（含内置的改动）+ 白名单 + 黑名单；导入 = 合并模式
 * （规则按 id 更新 / 追加，名单按 kind+pattern 去重追加，不删除任何现有条目），
 * 先读文件出预览，确认后才落库。导出的文件即分享载体。
 */
function RulesTransferCard({ onChanged }: { onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [preview, setPreview] = useState<ImportPreview | null>(null);

  const doExport = async () => {
    setBusy(true);
    setMsg("");
    setErr("");
    try {
      const path = await pickPath("rules-save");
      if (!path) return; // 用户取消
      const st = await exportRules(path);
      setMsg(
        `${t("已导出：")}${st.path}${t("（")}${t("规则")}${st.rules} / ${t("白名单")}${st.whitelist} / ${t("黑名单")}${st.blacklist}${t("）")}`
      );
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const doImport = async () => {
    setBusy(true);
    setMsg("");
    setErr("");
    try {
      const path = await pickPath("rules-open");
      if (!path) return; // 用户取消
      const p = await importRulesPreview(path);
      setPreview(p);
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const applyImport = async () => {
    if (!preview) return;
    setBusy(true);
    setErr("");
    try {
      const st = await importRulesApply(preview.bundle);
      setMsg(
        `${t("导入完成：")} ${t("规则新增")}${st.rules_new} / ${t("规则更新")}${st.rules_update} / ${t("白名单新增")}${st.whitelist_new} / ${t("黑名单新增")}${st.blacklist_new}`
      );
      setPreview(null);
      onChanged();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card card-pad">
      <HardenLine
        tone="green"
        title={t("导入 / 导出规则包")}
        desc={t("JSON 格式，可直接分享给他人（社区规则包）。导出包含全部规则与名单配置，不含任何流量数据；导入为合并模式，不删除现有配置。")}
      >
        <div style={{ display: "flex", gap: 6 }}>
          <button className="btn mini" disabled={busy} onClick={() => void doImport()}>
            {t("导入")}
          </button>
          <button className="btn mini" disabled={busy} onClick={() => void doExport()}>
            {t("导出")}
          </button>
        </div>
      </HardenLine>
      {msg && <div className="muted" style={{ paddingTop: 8, wordBreak: "break-all" }}>{msg}</div>}
      {err && <div className="form-err" style={{ marginTop: 10 }}>{err}</div>}

      {preview && (
        <Modal title={t("确认导入规则包")} onClose={() => !busy && setPreview(null)}>
          <div style={{ lineHeight: 1.8 }}>
            <div>{`${t("规则新增")}${t("：")}${preview.rules_new} ${t("条")}`}</div>
            <div>{`${t("规则更新")}${t("：")}${preview.rules_update} ${t("条")}`}</div>
            <div>{`${t("白名单新增")}${t("：")}${preview.whitelist_new} ${t("条")}`}</div>
            <div>{`${t("黑名单新增")}${t("：")}${preview.blacklist_new} ${t("条")}`}</div>
          </div>
          <div className="muted" style={{ marginTop: 10, fontSize: 12.5, lineHeight: 1.6 }}>
            {t("合并导入不会删除任何现有条目；已存在的规则按 ID 更新为包内版本。正则非法的规则包会在预览阶段被拒绝。")}
          </div>
          <div className="modal-foot" style={{ marginTop: 16, display: "flex", justifyContent: "flex-end", gap: 8 }}>
            <button className="btn" disabled={busy} onClick={() => setPreview(null)}>
              {t("取消")}
            </button>
            <button className="btn primary" disabled={busy} onClick={() => void applyImport()}>
              {t("导入")}
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ─────────── 语义检测卡片（熵值 / 姓名 / 地址 / 机构 / 产品代号白名单） ───────────

/** 语义检测流水线：正则层之后的第二级引擎，每级独立开关，命中恒为脱敏。 */
function SemanticCard() {
  const [cfg, setCfg] = useState<SemanticConfig | null>(null);
  const [termsText, setTermsText] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    getSemanticConfig()
      .then((c) => {
        setCfg(c);
        setTermsText(c.terms.join("\n"));
      })
      .catch((e) => setErr(errMsg(e)));
  }, []);

  const save = async (next: SemanticConfig) => {
    setBusy(true);
    setErr("");
    setNotice("");
    try {
      const saved = await setSemanticConfig(next);
      setCfg(saved);
      setTermsText(saved.terms.join("\n"));
      setNotice(t("已保存并即时生效"));
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  if (!cfg) {
    return <div className="card card-pad muted">{t("加载中…")}</div>;
  }

  // 展示名与说明存中文原文，渲染走 tb()（i18n:check 对变量渲染点的硬规矩）
  const rows: { key: "entropy" | "person" | "org" | "address"; name: string; desc: string }[] = [
    {
      key: "address",
      name: t("地址"),
      desc: t("行政区划词典锚定省市区结构，或「街道 + 门牌号」强结构；默认开启"),
    },
    {
      key: "person",
      name: t("中文姓名"),
      desc: t("百家姓 + 称谓 / 自称等上下文触发才报；裸姓名与常见词不报，宁可漏报不误伤"),
    },
    {
      key: "org",
      name: t("机构名 / 学校名"),
      desc: t("大学 / 医院 / 银行 / 公司等强后缀锚定，代词与方位词前缀自动排除"),
    },
    {
      key: "entropy",
      name: t("高熵串"),
      desc: t("无法归类的凭据形态（混合大小写与数字）；哈希校验和与 UUID 不报，默认关闭"),
    },
  ];

  return (
    <div className="card card-pad">
      <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.7, marginBottom: 14 }}>
        {t("语义检测在正则规则之后执行，命中恒为脱敏（不拦截）。当前为纯启发式实现，不依赖任何模型；ONNX 模型加载留作后续可选能力。")}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {rows.map((r) => (
          <div key={r.key} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Toggle on={cfg[r.key]} onChange={() => !busy && void save({ ...cfg, [r.key]: !cfg[r.key] })} />
            <span style={{ fontWeight: 500, whiteSpace: "nowrap" }}>{tb(r.name)}</span>
            <span className="muted" style={{ fontSize: 12, lineHeight: 1.5 }}>{tb(r.desc)}</span>
          </div>
        ))}
      </div>
      <div style={{ marginTop: 16 }}>
        <span className="field-label">{t("产品代号白名单（每行一个词条，命中即脱敏）")}</span>
        <textarea
          className="input mono"
          rows={4}
          value={termsText}
          onChange={(e) => setTermsText(e.target.value)}
          placeholder={t("每行一个词条")}
          style={{ width: "100%", marginTop: 6, resize: "vertical" }}
        />
        <div style={{ marginTop: 8, display: "flex", gap: 8, alignItems: "center" }}>
          <button className="btn primary" disabled={busy} onClick={() => void save({ ...cfg, terms: termsText.split("\n") })}>
            {t("保存白名单")}
          </button>
          <span className="muted" style={{ fontSize: 12 }}>
            {cfg.terms.length} {t("条")}
          </span>
        </div>
      </div>
      {notice && <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>{notice}</div>}
      {err && <div className="form-err">{err}</div>}
    </div>
  );
}

// ─────────── 保险柜卡片（用户录入敏感值的出站防护 + 访问告警） ───────────

/** 值打码展示：仅保留首尾各 2 字符，其余以星号替代（防肩窥）。 */
function maskValue(v: string): string {
  if (v.length <= 6) return "*".repeat(v.length);
  const hidden = Math.min(v.length - 4, 12);
  return v.slice(0, 2) + "*".repeat(hidden) + v.slice(-2);
}

/** 保险柜：出站请求凡命中凭据值条目即按动作脱敏或拦截；模型命令点名键名、
 * 引用受保护文件 / 文件夹或指向内置保护对象时产生访问告警。
 * 路径条目支持从资源管理器选择（文件 / 文件夹）或手输通配模式。 */
function LockerCard() {
  const [cfg, setCfg] = useState<LockerConfig | null>(null);
  const [draft, setDraft] = useState<LockerEntry[]>([]);
  // 新增条目类型：file / dir 都落为 path 条目（kind），仅决定浏览器的打开方式
  const [newKind, setNewKind] = useState<"value" | "file" | "dir">("value");
  const [newName, setNewName] = useState("");
  const [newValue, setNewValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [err, setErr] = useState("");
  const isPathKind = newKind !== "value";

  const browse = async () => {
    const p = await pickPath(newKind === "dir" ? "folder" : "file");
    if (p) setNewValue(p);
  };

  useEffect(() => {
    getLockerConfig()
      .then((c) => {
        setCfg(c);
        setDraft(c.entries);
      })
      .catch((e) => setErr(errMsg(e)));
  }, []);

  const save = async (entries: LockerEntry[]) => {
    setBusy(true);
    setErr("");
    setNotice("");
    try {
      const saved = await setLockerConfig({ entries });
      setCfg(saved);
      setDraft(saved.entries);
      setNotice(t("已保存并即时生效"));
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  // 所有操作即时落盘（与语义检测卡一致）——「添加只进内存、另点保存才生效」
  // 曾被用户当成丢失：切页重载后端返回空，条目凭空消失。
  const add = async () => {
    if (busy) return;
    const name = newName.trim();
    const value = newValue.trim();
    if (isPathKind) {
      if (!value) {
        setErr(t("请填入文件或文件夹路径"));
        return;
      }
      // 路径条目键名可空（后端自动取路径尾段）
      setNewName("");
      setNewValue("");
      await save([...draft, { name, value, action: "mask", enabled: true, kind: "path" }]);
      return;
    }
    if (!name || !value) {
      setErr(t("键名与值都要填"));
      return;
    }
    if (value.length < 8) {
      setErr(t("值至少 8 个字符，过短的值会误伤正常文本"));
      return;
    }
    setNewName("");
    setNewValue("");
    await save([...draft, { name, value, action: "mask", enabled: true, kind: "value" }]);
  };

  if (!cfg) {
    return <div className="card card-pad muted">{t("加载中…")}</div>;
  }

  return (
    <div className="card card-pad">
      <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.7, marginBottom: 14 }}>
        {t("保险柜存你录入的敏感值（密钥、口令等）：出站请求凡命中即按条目动作脱敏或拦截，模型只见到占位符；模型下发命令点名键名或读取 .env、SSH 私钥、环境变量等保护对象时产生访问告警。")}
        <br />
        {t("文件 / 文件夹条目产生访问告警（代理不执行命令，无法阻止本地读取，但「谁在碰」全程可见）；路径支持通配，如 *.pem 保护全部同名扩展文件。")}
      </div>
      {draft.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 14 }}>
          {draft.map((e, i) => (
            <div key={`locker-row-${i}`} style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <Toggle
                on={e.enabled}
                onChange={() => {
                  if (busy) return;
                  const n = [...draft];
                  n[i] = { ...e, enabled: !e.enabled };
                  void save(n);
                }}
              />
              <span
                className="muted"
                style={{ fontSize: 11, border: "1px solid var(--border, #ddd)", borderRadius: 4, padding: "1px 6px", whiteSpace: "nowrap" }}
              >
                {e.kind === "path" ? t("路径") : t("值")}
              </span>
              <span style={{ fontWeight: 500, whiteSpace: "nowrap" }}>{tb(e.name)}</span>
              <span className="muted mono" style={{ fontSize: 12 }}>
                {e.kind === "path" ? e.value : maskValue(e.value)}
              </span>
              {e.kind !== "path" && (
                <span style={{ marginLeft: "auto", display: "flex", gap: 6, alignItems: "center" }}>
                  <button
                    className={"btn" + (e.action === "mask" ? " primary" : "")}
                    disabled={busy || !e.enabled}
                    style={{ padding: "2px 10px", fontSize: 12 }}
                    onClick={() => {
                      const n = [...draft];
                      n[i] = { ...e, action: "mask" };
                      void save(n);
                    }}
                  >
                    {t("脱敏")}
                  </button>
                  <button
                    className={"btn" + (e.action === "block" ? " primary" : "")}
                    disabled={busy || !e.enabled}
                    style={{ padding: "2px 10px", fontSize: 12 }}
                    onClick={() => {
                      const n = [...draft];
                      n[i] = { ...e, action: "block" };
                      void save(n);
                    }}
                  >
                    {t("拦截")}
                  </button>
                </span>
              )}
              <button
                className="btn"
                disabled={busy}
                style={{ padding: "2px 10px", fontSize: 12, marginLeft: e.kind === "path" ? "auto" : 0 }}
                onClick={() => {
                  if (busy) return;
                  void save(draft.filter((_, j) => j !== i));
                }}
              >
                {t("删除")}
              </button>
            </div>
          ))}
        </div>
      )}
      <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
        <span className="muted" style={{ fontSize: 12 }}>{t("新增类型")}</span>
        <button
          className={"btn" + (newKind === "value" ? " primary" : "")}
          disabled={busy}
          style={{ padding: "2px 10px", fontSize: 12 }}
          onClick={() => setNewKind("value")}
        >
          {t("凭据值")}
        </button>
        <button
          className={"btn" + (newKind === "file" ? " primary" : "")}
          disabled={busy}
          style={{ padding: "2px 10px", fontSize: 12 }}
          onClick={() => setNewKind("file")}
        >
          {t("文件")}
        </button>
        <button
          className={"btn" + (newKind === "dir" ? " primary" : "")}
          disabled={busy}
          style={{ padding: "2px 10px", fontSize: 12 }}
          onClick={() => setNewKind("dir")}
        >
          {t("文件夹")}
        </button>
      </div>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <input
          className="input"
          style={{ width: 180 }}
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          placeholder={isPathKind ? t("名称（选填，默认取路径）") : t("键名")}
          disabled={busy}
        />
        <input
          className="input mono"
          style={{ flex: 1, minWidth: 220 }}
          value={newValue}
          onChange={(e) => setNewValue(e.target.value)}
          placeholder={isPathKind ? t("文件或文件夹路径，支持通配，如 D:\\secrets 或 *.pem") : t("值")}
          disabled={busy}
        />
        {isPathKind && (
          <button className="btn" disabled={busy} onClick={() => void browse()}>
            {t("浏览…")}
          </button>
        )}
        <button className="btn" disabled={busy} onClick={() => void add()}>
          {t("添加")}
        </button>
        <span className="muted" style={{ fontSize: 12 }}>
          {draft.length} {t("条")}
        </span>
      </div>
      {notice && <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>{notice}</div>}
      {err && <div className="form-err">{err}</div>}
    </div>
  );
}

function RulesPage() {
  const [rules, setRules] = useState<RuleSpec[]>([]);
  const [wl, setWl] = useState<WhitelistEntry[]>([]);
  // 编辑态（自定义弹窗）
  const [editTarget, setEditTarget] = useState<RuleSpec | null>(null);
  const [editDraft, setEditDraft] = useState({ name: "", regex: "", action: "mask" });
  const [editErr, setEditErr] = useState("");
  // 新增自定义规则
  const [newRule, setNewRule] = useState({ name: "", tag: "", regex: "", action: "mask" });
  const [newErr, setNewErr] = useState("");
  // 白名单新增表单
  const [wlForm, setWlForm] = useState<{ kind: "domain" | "process"; pattern: string; scrub: boolean }>({
    kind: "domain",
    pattern: "",
    scrub: true,
  });
  const [wlErr, setWlErr] = useState("");
  // 黑名单（命中后强制执行所选动作）
  const [bl, setBl] = useState<BlacklistEntry[]>([]);
  const [blForm, setBlForm] = useState<{
    kind: "domain" | "process";
    pattern: string;
    action: string;
  }>({
    kind: "domain",
    pattern: "",
    action: "block",
  });
  const [blErr, setBlErr] = useState("");
  // 名单管理弹窗：从「执行顺序」卡片的节点打开（页面不再重复铺两块名单区）
  const [listModal, setListModal] = useState<null | "black" | "white">(null);

  const refresh = useCallback(async () => {
    try {
      const [rs, w, b] = await Promise.all([getRules(), getWhitelist(), getBlacklist()]);
      setRules(rs);
      setWl(w);
      setBl(b);
    } catch {
      // 浏览器预览模式走 MOCK
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // ── 规则操作 ──
  const toggleEnabled = async (r: RuleSpec) => {
    setRules((prev) => prev.map((x) => (x.id === r.id ? { ...x, enabled: !r.enabled } : x)));
    try {
      await apiSetRule(r.id, { enabled: !r.enabled });
    } catch {
      /* 浏览器预览模式 */
    }
  };

  const changeAction = async (r: RuleSpec, action: string) => {
    setRules((prev) => prev.map((x) => (x.id === r.id ? { ...x, action } : x)));
    try {
      await apiSetRule(r.id, { action });
    } catch {
      /* 浏览器预览模式 */
    }
  };

  const startEdit = (r: RuleSpec) => {
    setEditTarget(r);
    setEditDraft({ name: r.name, regex: r.regex, action: r.action });
    setEditErr("");
  };

  const saveEdit = async () => {
    if (!editTarget) return;
    setEditErr("");
    try {
      await apiSetRule(editTarget.id, {
        name: editDraft.name,
        regex: editDraft.regex,
        action: editDraft.action,
      });
      setEditTarget(null);
      await refresh();
    } catch (e) {
      setEditErr(errMsg(e));
    }
  };

  const addRule = async () => {
    setNewErr("");
    try {
      await addCustomRule(newRule.name, newRule.regex, newRule.action, newRule.tag || undefined);
      setNewRule({ name: "", tag: "", regex: "", action: "mask" });
      await refresh();
    } catch (e) {
      setNewErr(errMsg(e));
    }
  };

  const removeRule = async (id: string) => {
    try {
      await deleteRule(id);
      await refresh();
    } catch {
      /* 浏览器预览模式 */
    }
  };

  const resetBuiltin = async (id: string) => {
    try {
      await resetRule(id);
      await refresh();
    } catch {
      /* 浏览器预览模式 */
    }
  };

  // ── 白名单操作 ──
  const addWl = async () => {
    setWlErr("");
    try {
      await addWhitelistEntry(wlForm.kind, wlForm.pattern, wlForm.scrub);
      setWlForm((f) => ({ ...f, pattern: "" }));
      await refresh();
    } catch (e) {
      setWlErr(errMsg(e));
    }
  };

  const toggleWlScrub = async (w: WhitelistEntry) => {
    try {
      await updateWhitelistEntry(w.id, { scrub: !w.scrub });
      await refresh();
    } catch {
      /* 浏览器预览模式 */
    }
  };

  const removeWl = async (id: string) => {
    try {
      await removeWhitelistEntry(id);
      await refresh();
    } catch {
      /* 浏览器预览模式 */
    }
  };

  // ── 黑名单操作 ──
  const addBl = async () => {
    setBlErr("");
    try {
      await addBlacklistEntry(blForm.kind, blForm.pattern, blForm.action);
      setBlForm((f) => ({ ...f, pattern: "" }));
      await refresh();
    } catch (e) {
      setBlErr(errMsg(e));
    }
  };

  const removeBl = async (id: string) => {
    try {
      await removeBlacklistEntry(id);
      await refresh();
    } catch {
      /* 浏览器预览模式 */
    }
  };

  // ── 系统文件对话框（exe / 文件夹浏览选择，回填输入框） ──
  const browse = async (target: "wl" | "bl", pick: "exe" | "folder") => {
    const p = await pickPath(pick);
    if (!p) return; // 用户取消
    if (target === "wl") setWlForm((f) => ({ ...f, kind: "process", pattern: p }));
    else setBlForm((f) => ({ ...f, kind: "process", pattern: p }));
  };

  return (
    <div className="page-pad">
      <div className="notice" style={{ marginBottom: 14 }}>
        <ShieldIcon size={18} />
        {t("内置规则可编辑、可恢复默认；支持新增自定义规则、导入导出规则包。")}
      </div>

      {/* ── 执行顺序（优先级可视化） ── */}
      <div className="section-title" style={{ marginTop: 0 }}>
        {t("执行顺序")}
      </div>
      <PriorityFlow
        bl={bl.length}
        wl={wl.length}
        rules={rules.length}
        enabled={rules.filter((r) => r.enabled).length}
        onOpen={(list) => setListModal(list)}
      />

      {/* ── 内置规则预设 ── */}
      <div className="section-title">{t("内置规则预设")}</div>
      <RulePresetCard onChanged={() => void refresh()} />

      {/* ── 检测规则 ── */}
      <div className="section-title" style={{ marginTop: 0 }}>
        {t("检测规则")}
      </div>
      <div className="rule-grid">
        {rules.map((r) => (
          <div className="card rule-card" key={r.id}>
            <div className="rule-head">
              <span className="rule-name">{tb(r.name)}</span>
              <Toggle on={r.enabled} onChange={() => toggleEnabled(r)} />
            </div>
            <div style={{ display: "flex", gap: 6, marginBottom: 8 }}>
              <Badge text={r.builtin ? t("内置") : t("自定义")} tone={r.builtin ? "gray" : "green"} />
              <Badge text={r.tag} tone="amber" />
            </div>
            <div className="rule-regex" title={r.regex}>
              {r.regex}
            </div>
            <div className="rule-foot">
              <Dropdown value={r.action} options={actionOptions()} onChange={(v) => changeAction(r, v)} />
              <div style={{ display: "flex", gap: 6 }}>
                <button className="btn mini" onClick={() => startEdit(r)}>
                  {t("编辑")}
                </button>
                {r.builtin ? (
                  <button className="btn mini" onClick={() => resetBuiltin(r.id)}>
                    {t("恢复默认")}
                  </button>
                ) : (
                  <button className="btn mini danger" onClick={() => removeRule(r.id)}>
                    {t("删除")}
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* ── 正则测试器 ── */}
      <div className="section-title">{t("正则测试器")}</div>
      <RegexTesterCard
        onApplyToForm={(regex, tag) => {
          setNewRule((f) => ({ ...f, regex, tag: tag === "CUSTOM" ? "" : tag }));
          setNewErr("");
        }}
      />

      {/* ── 新增自定义规则 ── */}
      <div className="section-title">{t("新增自定义规则")}</div>
      <div className="card card-pad">
        <div className="form-grid">
          <label className="field">
            <span className="field-label">{t("规则名称 *")}</span>
            <input
              className="input"
              value={newRule.name}
              onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
              placeholder={t("如：内部项目代号")}
            />
          </label>
          <label className="field">
            <span className="field-label">{t("占位符标签（可选，字母/数字/下划线）")}</span>
            <input
              className="input"
              value={newRule.tag}
              onChange={(e) => setNewRule({ ...newRule, tag: e.target.value })}
              placeholder={t("默认 CUSTOM")}
            />
          </label>
          <label className="field" style={{ gridColumn: "1 / -1" }}>
            <span className="field-label">{t("正则表达式 *")}</span>
            <input
              className="input mono"
              value={newRule.regex}
              onChange={(e) => setNewRule({ ...newRule, regex: e.target.value })}
              placeholder={t("如：阿尔法计划|贝塔计划")}
            />
          </label>
          <div className="field">
            <span className="field-label">{t("命中动作")}</span>
            <Dropdown
              value={newRule.action}
              options={actionOptions()}
              onChange={(v) => setNewRule({ ...newRule, action: v })}
            />
          </div>
          <div className="field" style={{ alignSelf: "end" }}>
            <button className="btn primary" onClick={addRule}>
              {t("添加规则")}
            </button>
          </div>
        </div>
        {newErr && <div className="form-err">{newErr}</div>}
      </div>

      {/* ── 导入 / 导出规则包 ── */}
      <div className="section-title">{t("导入 / 导出")}</div>
      <RulesTransferCard onChanged={() => void refresh()} />

      {/* ── 语义检测流水线 ── */}
      <div className="section-title">{t("语义检测")}</div>
      <SemanticCard />

      {/* ── 保险柜（用户录入敏感值出站防护） ── */}
      <div className="section-title">{t("保险柜")}</div>
      <LockerCard />

      {/* ── 黑名单管理弹窗（执行顺序卡片节点打开） ── */}
      {listModal === "black" && (
        <Modal
          wide
          title={t("黑名单（强制执行所选动作 · 优先级最高）")}
          onClose={() => setListModal(null)}
        >
          {bl.length === 0 ? (
            <div className="empty">{t("黑名单为空 —— 所有守护域名流量按检测规则处理")}</div>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>{t("类型")}</th>
                  <th>{t("内容")}</th>
                  <th>{t("命中动作")}</th>
                  <th style={{ textAlign: "right" }}>{t("操作")}</th>
                </tr>
              </thead>
              <tbody>
                {bl.map((b) => (
                  <tr key={b.id}>
                    <td>
                      <Badge text={b.kind === "domain" ? t("域名") : t("进程")} tone="gray" />
                    </td>
                    <td
                      className="mono"
                      style={{ maxWidth: 380, overflow: "hidden", textOverflow: "ellipsis" }}
                      title={b.pattern}
                    >
                      {b.pattern}
                    </td>
                    <td>
                      <ActionBadge action={b.action} />
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button className="btn mini danger" onClick={() => removeBl(b.id)}>
                        {t("删除")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div style={{ padding: "12px 0", borderTop: "1px solid var(--line)" }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <Dropdown
                value={blForm.kind}
                options={[
                  { value: "domain", label: t("域名") },
                  { value: "process", label: t("进程（exe / 文件夹）") },
                ]}
                onChange={(v) => setBlForm({ ...blForm, kind: v as "domain" | "process" })}
              />
              <Dropdown
                value={blForm.action}
                options={[
                  { value: "block", label: t("命中即拦截") },
                  { value: "mask", label: t("强制脱敏") },
                ]}
                onChange={(v) => setBlForm({ ...blForm, action: v })}
              />
              <input
                className="input"
                style={{ flex: 1, minWidth: 200, width: "auto" }}
                value={blForm.pattern}
                placeholder={
                  blForm.kind === "domain"
                    ? t("如 untrusted-ai.example.com（子域名一并生效）")
                    : t("浏览选择 exe / 文件夹，或直接粘贴完整路径")
                }
                onChange={(e) => setBlForm({ ...blForm, pattern: e.target.value })}
              />
              {blForm.kind === "process" && (
                <>
                  <button className="btn" onClick={() => void browse("bl", "exe")}>
                    {t("浏览文件…")}
                  </button>
                  <button className="btn" onClick={() => void browse("bl", "folder")}>
                    {t("浏览文件夹…")}
                  </button>
                </>
              )}
              <button className="btn primary" onClick={addBl}>
                {t("添加")}
              </button>
            </div>
            {blErr && <div className="form-err">{blErr}</div>}
          </div>
          <div className="muted" style={{ fontSize: 12, lineHeight: 1.6, paddingBottom: 10 }}>
            {t("TCP 连接表将来源端口反解为进程路径后匹配；无法识别进程的连接按不在名单处理。")}
          </div>
        </Modal>
      )}

      {/* ── 白名单管理弹窗（执行顺序卡片节点打开） ── */}
      {listModal === "white" && (
        <Modal
          wide
          title={t("白名单（不拦截 · 脱敏可选）")}
          onClose={() => setListModal(null)}
        >
          {wl.length === 0 ? (
            <div className="empty">{t("白名单为空 —— 所有守护域名流量均按规则脱敏 / 拦截")}</div>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>{t("类型")}</th>
                  <th>{t("内容")}</th>
                  <th>{t("仍执行脱敏")}</th>
                  <th style={{ textAlign: "right" }}>{t("操作")}</th>
                </tr>
              </thead>
              <tbody>
                {wl.map((w) => (
                  <tr key={w.id}>
                    <td>
                      <Badge text={w.kind === "domain" ? t("域名") : t("进程")} tone="gray" />
                    </td>
                    <td
                      className="mono"
                      style={{ maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis" }}
                      title={w.pattern}
                    >
                      {w.pattern}
                    </td>
                    <td>
                      <Toggle on={w.scrub} onChange={() => toggleWlScrub(w)} />
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button className="btn mini danger" onClick={() => removeWl(w.id)}>
                        {t("删除")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div style={{ padding: "12px 0", borderTop: "1px solid var(--line)" }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <Dropdown
                value={wlForm.kind}
                options={[
                  { value: "domain", label: t("域名") },
                  { value: "process", label: t("进程（exe / 文件夹）") },
                ]}
                onChange={(v) => setWlForm({ ...wlForm, kind: v as "domain" | "process" })}
              />
              <input
                className="input"
                style={{ flex: 1, minWidth: 220, width: "auto" }}
                value={wlForm.pattern}
                placeholder={
                  wlForm.kind === "domain"
                    ? t("如 api.openai.com（子域名一并生效）")
                    : t("浏览选择 exe / 文件夹，或直接粘贴完整路径")
                }
                onChange={(e) => setWlForm({ ...wlForm, pattern: e.target.value })}
              />
              {wlForm.kind === "process" && (
                <>
                  <button className="btn" onClick={() => void browse("wl", "exe")}>
                    {t("浏览文件…")}
                  </button>
                  <button className="btn" onClick={() => void browse("wl", "folder")}>
                    {t("浏览文件夹…")}
                  </button>
                </>
              )}
              <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
                <Toggle on={wlForm.scrub} onChange={() => setWlForm({ ...wlForm, scrub: !wlForm.scrub })} />
                <span className="muted">{t("仍执行脱敏")}</span>
              </label>
              <button className="btn primary" onClick={addWl}>
                {t("添加")}
              </button>
            </div>
            {wlErr && <div className="form-err">{wlErr}</div>}
          </div>
          <div className="muted" style={{ fontSize: 12, lineHeight: 1.6, paddingBottom: 10 }}>
            {t("TCP 连接表将来源端口反解为进程路径后匹配；无法识别进程的连接按不在名单处理。")}
          </div>
        </Modal>
      )}

      {/* 编辑规则弹窗 */}
      {editTarget && (
        <Modal
          title={`${t("编辑规则 · ")}${tb(editTarget.name)}`}
          onClose={() => setEditTarget(null)}
          footer={
            <>
              <button className="btn" onClick={() => setEditTarget(null)}>
                {t("取消")}
              </button>
              <button className="btn primary" onClick={saveEdit}>
                {t("保存修改")}
              </button>
            </>
          }
        >
          <label className="field">
            <span className="field-label">{t("规则名称")}</span>
            <input
              className="input"
              value={editDraft.name}
              onChange={(e) => setEditDraft({ ...editDraft, name: e.target.value })}
            />
          </label>
          <label className="field">
            <span className="field-label">{t("正则表达式")}</span>
            <input
              className="input mono"
              value={editDraft.regex}
              onChange={(e) => setEditDraft({ ...editDraft, regex: e.target.value })}
            />
          </label>
          <div className="field">
            <span className="field-label">{t("命中动作")}</span>
            <Dropdown
              value={editDraft.action}
              options={actionOptions()}
              onChange={(v) => setEditDraft({ ...editDraft, action: v })}
            />
          </div>
          {editErr && <div className="form-err">{editErr}</div>}
          {editTarget.builtin && <div className="muted">{t("内置规则可修改，修改后可随时在卡片上「恢复默认」。")}</div>}
        </Modal>
      )}
    </div>
  );
}

// ─────────── 页面：防护中心（防护信号审计） ───────────

/** 信号 → 卡片色调（凭据类偏红，观察类偏琥珀） */
const SEC_TONE: Record<string, "red" | "amber" | "green"> = {
  error_leak: "red",
  identity_swap: "red",
  cross_request_pollution: "red",
  tool_call_injection: "red",
  locker_access: "amber",
  tool_call_rewrite: "amber",
  sse_anomaly: "amber",
  response_poison: "amber",
  dangerous_action: "amber",
};

/** 入库门槛选项（按当前语言求值，理由见 actionOptions）。 */
function severityFloors(): { value: string; label: string }[] {
  return [
    { value: "LOW", label: t("LOW（全部入库，含兼容性观察）") },
    { value: "MEDIUM", label: t("MEDIUM（推荐：LOW 只做记录不进视图）") },
    { value: "HIGH", label: t("HIGH（只看高危）") },
    { value: "CRITICAL", label: t("CRITICAL（只看实锤泄漏）") },
  ];
}

/** 桌面通知的触发门槛（比入库门槛更保守：通知会离开应用，默认只看高危）。 */
function notifyFloors(): { value: string; label: string }[] {
  return [
    { value: "CRITICAL", label: t("仅实锤泄漏（CRITICAL）") },
    { value: "HIGH", label: t("高危及以上（HIGH / CRITICAL，推荐）") },
    { value: "MEDIUM", label: t("中危及以上（较吵）") },
  ];
}

function SecurityPage() {
  const [points, setPoints] = useState<SecurityPoint[]>([]);
  const [policy, setPolicy] = useState<SecurityPolicy | null>(null);
  const [events, setEvents] = useState<SecurityEventRow[]>([]);
  const [err, setErr] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  // 高级参数草稿（数字类，需手动保存）
  const [draft, setDraft] = useState({
    max_buffer_size: 1048576,
    max_placeholder_len: 128,
    session_ttl_secs: 1800,
    retention_days: 7,
  });
  // 主动核查
  const [checkRunning, setCheckRunning] = useState(false);
  const [checkResult, setCheckResult] = useState<LinkCheckResult | null>(null);
  const [checkErr, setCheckErr] = useState("");
  const [checkDraft, setCheckDraft] = useState({
    targetHost: "api.openai.com",
    path: "/v1/chat/completions",
    model: "gpt-4o-mini",
    profile: "general",
    authHeader: "",
  });

  const refresh = useCallback(async () => {
    try {
      const [ps, pol, evs] = await Promise.all([
        getSecurityPoints(),
        getSecurityPolicy(),
        listSecurityEvents(100),
      ]);
      setPoints(ps);
      setPolicy(pol);
      setEvents(evs);
      setDraft({
        max_buffer_size: pol.max_buffer_size,
        max_placeholder_len: pol.max_placeholder_len,
        session_ttl_secs: pol.session_ttl_secs,
        retention_days: pol.retention_days,
      });
    } catch {
      // 浏览器预览模式走 MOCK
    }
  }, []);

  useEffect(() => {
    void refresh();
    // 实时告警：新事件到达时刷新列表
    let unlisten: (() => void) | undefined;
    onSecurityAlert((payload) => {
      setEvents((prev) => [payload, ...prev].slice(0, 100));
      void refresh();
    }).then((fn) => {
      unlisten = fn;
    });
    return () => unlisten?.();
  }, [refresh]);

  /** 改策略：先本地乐观更新，再落盘 */
  const patchPolicy = async (patch: Partial<SecurityPolicy>) => {
    if (!policy) return;
    const next = { ...policy, ...patch };
    setPolicy(next);
    setErr("");
    try {
      const saved = await apiSetSecurityPolicy(next);
      setPolicy(saved);
      await refresh();
    } catch (e) {
      setErr(errMsg(e));
      await refresh();
    }
  };

  /** 切换单个信号开关（key = 语义信号名） */
  const toggleSignal = (signal: string, enabled: boolean) => {
    if (!policy) return;
    void patchPolicy({
      signals: { ...policy.signals, [signal]: enabled },
    });
  };

  const saveAdvanced = async () => {
    if (!policy) return;
    await patchPolicy({
      max_buffer_size: Number(draft.max_buffer_size) || policy.max_buffer_size,
      max_placeholder_len: Number(draft.max_placeholder_len) || policy.max_placeholder_len,
      session_ttl_secs: Number(draft.session_ttl_secs) || 0,
      retention_days: Math.max(0, Number(draft.retention_days) || 0),
    });
  };

  const totalHits = points.reduce((s, p) => s + p.hits, 0);
  const enabledCount = points.filter((p) => p.enabled).length;
  const pendingCheck = points.filter((p) => !p.implemented).length;
  /** 信号名 → 展示名（日志表用） */
  const signalNameOf = Object.fromEntries(points.map((p) => [p.signal, p.name]));

  const runCheck = async () => {
    setCheckRunning(true);
    setCheckErr("");
    try {
      const r = await runLinkCheck({
        targetHost: checkDraft.targetHost,
        path: checkDraft.path,
        model: checkDraft.model,
        profile: checkDraft.profile,
        authHeader: checkDraft.authHeader,
      });
      setCheckResult(r);
      await refresh();
    } catch (e) {
      setCheckErr(errMsg(e));
    } finally {
      setCheckRunning(false);
    }
  };

  return (
    <div className="page-pad">
      <div className="notice" style={{ marginBottom: 14 }}>
        <ShieldIcon size={18} />
        {t("被动审计只记录、不改写响应：发现按严重度分层入库，证据只含类型 / 长度 / 摘要，绝不保存原文")}
      </div>

      <div className="sec-summary">
        <div className="sec-sum-item">
          <span className="sec-sum-value">{totalHits}</span>
          <span className="sec-sum-label">{t("累计命中")}</span>
        </div>
        <div className="sec-sum-item">
          <span className="sec-sum-value" style={{ color: "var(--brand)" }}>
            {enabledCount}
          </span>
          <span className="sec-sum-label">{t("已启用信号")}</span>
        </div>
        <div className="sec-sum-item">
          <span className="sec-sum-value">{pendingCheck > 0 ? `${t("待核查 ×")}${pendingCheck}` : t("已齐备")}</span>
          <span className="sec-sum-label">{t("主动核查依赖")}</span>
        </div>
        <div className="sec-actions">
          <button className="btn mini" onClick={() => void clearSecurityEvents().then(refresh)}>
            {t("清空命中日志")}
          </button>
          <button
            className="btn mini"
            onClick={() => void clearSessions().then(() => refresh())}
            title={t("立即销毁全部内存中的占位符映射（应急）")}
          >
            {t("清空会话映射")}
          </button>
        </div>
      </div>

      {err && <div className="form-err">{err}</div>}

      <div className="sec-grid">
        {points.map((p) => (
          <div className={`card sec-card ${p.enabled ? "" : "off"}`} key={p.signal}>
            <div className="sec-card-head">
              <span className={`sec-dot ${SEC_TONE[p.signal] ?? "amber"}`} aria-hidden />
              <span className="sec-name">{tb(p.name)}</span>
              {policy && (
                <Toggle on={p.enabled} onChange={() => toggleSignal(p.signal, !p.enabled)} />
              )}
            </div>
            <div className="sec-desc">{tb(p.desc)}</div>
            <div className="sec-hits">
              {t("命中")} <b>{p.hits}</b> {t("次")}
              {!p.implemented && <span className="muted"> {t("· 需主动核查")}</span>}
            </div>
          </div>
        ))}
      </div>

      {policy && (
        <div className="card card-pad" style={{ marginTop: 16 }}>
          <div
            style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer" }}
            onClick={() => setShowAdvanced((v) => !v)}
          >
            <span style={{ fontWeight: 500 }}>{t("高级参数")}</span>
            <span className="muted">{showAdvanced ? t("收起") : t("展开")}</span>
          </div>
          {showAdvanced && (
            <div style={{ marginTop: 14 }} className="form-grid">
              <label className="field">
                <span className="field-label">{t("还原单段缓冲上限（字节，4096 ~ 64MiB）")}</span>
                <input
                  className="input mono"
                  type="number"
                  value={draft.max_buffer_size}
                  onChange={(e) => setDraft({ ...draft, max_buffer_size: Number(e.target.value) })}
                />
              </label>
              <label className="field">
                <span className="field-label">{t("占位符最大长度（字节）")}</span>
                <input
                  className="input mono"
                  type="number"
                  value={draft.max_placeholder_len}
                  onChange={(e) => setDraft({ ...draft, max_placeholder_len: Number(e.target.value) })}
                />
              </label>
              <label className="field">
                <span className="field-label">{t("会话映射空闲过期（秒）")}</span>
                <input
                  className="input mono"
                  type="number"
                  value={draft.session_ttl_secs}
                  onChange={(e) => setDraft({ ...draft, session_ttl_secs: Number(e.target.value) })}
                />
              </label>
              <label className="field">
                <span className="field-label">{t("审计事件保留天数（0 = 永久）")}</span>
                <input
                  className="input mono"
                  type="number"
                  value={draft.retention_days}
                  onChange={(e) => setDraft({ ...draft, retention_days: Number(e.target.value) })}
                />
              </label>
              {/* 含 Dropdown 的字段不能用 label 包裹：label 的隐式关联会把点击空白转发给下拉按钮 */}
              <div className="field" style={{ gridColumn: "1 / -1" }}>
                <span className="field-label">{t("入库门槛（低于该严重度的发现只做记录，不进日志视图）")}</span>
                <Dropdown
                  value={policy.severity_floor}
                  options={severityFloors()}
                  onChange={(v) => void patchPolicy({ severity_floor: v })}
                />
              </div>
              <div className="field" style={{ alignSelf: "end" }}>
                <button className="btn primary" onClick={() => void saveAdvanced()}>
                  {t("保存高级参数")}
                </button>
              </div>
              <div className="field" style={{ alignSelf: "end" }}>
                <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
                  <Toggle
                    on={policy.clear_session_on_stream_end}
                    onChange={() =>
                      void patchPolicy({ clear_session_on_stream_end: !policy.clear_session_on_stream_end })
                    }
                  />
                  <span className="muted">{t("流结束后立即清空该会话映射（多轮对话请关闭）")}</span>
                </label>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ─────────── 主动核查 ─────────── */}
      <div className="card card-pad" style={{ marginTop: 16 }}>
        <div
          style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}
        >
          <span style={{ fontWeight: 500 }}>{t("主动核查")}</span>
          <button
            className="btn primary"
            disabled={checkRunning || !policy?.enabled}
            onClick={() => void runCheck()}
          >
            {checkRunning ? t("核查中…") : t("开始核查")}
          </button>
        </div>
        <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
          {t("注入随机标记并独立验证「上游是否跨请求存储数据」等被动检测看不到的风险；每步请求都会经真实代理发出，需要目标渠道可访问且有有效凭据，否则相关维度会标记为未覆盖。")}
        </div>
        <div className="form-grid" style={{ marginTop: 12 }}>
          <label className="field">
            <span className="field-label">{t("目标域名")}</span>
            <input
              className="input mono"
              value={checkDraft.targetHost}
              onChange={(e) => setCheckDraft({ ...checkDraft, targetHost: e.target.value })}
              placeholder="api.openai.com"
            />
          </label>
          <div className="field">
            <span className="field-label">{t("补全路径")}</span>
            <Dropdown
              value={checkDraft.path}
              options={[
                { value: "/v1/chat/completions", label: t("/v1/chat/completions（OpenAI 兼容）") },
                { value: "/v1/messages", label: t("/v1/messages（Anthropic）") },
              ]}
              onChange={(v) => setCheckDraft({ ...checkDraft, path: v })}
            />
          </div>
          <label className="field">
            <span className="field-label">{t("模型名")}</span>
            <input
              className="input mono"
              value={checkDraft.model}
              onChange={(e) => setCheckDraft({ ...checkDraft, model: e.target.value })}
              placeholder="gpt-4o-mini"
            />
          </label>
          <div className="field">
            <span className="field-label">{t("扫描范围")}</span>
            <Dropdown
              value={checkDraft.profile}
              options={[
                { value: "general", label: t("通用") },
                { value: "full", label: t("完整（含 Web3 注入）") },
              ]}
              onChange={(v) => setCheckDraft({ ...checkDraft, profile: v })}
            />
          </div>
          <label className="field" style={{ gridColumn: "1 / -1" }}>
            <span className="field-label">{t("凭据头 Authorization（可选；auth_check 触发器不受影响）")}</span>
            <input
              className="input mono"
              type="password"
              value={checkDraft.authHeader}
              onChange={(e) => setCheckDraft({ ...checkDraft, authHeader: e.target.value })}
              placeholder="Bearer sk-..."
            />
          </label>
        </div>
        {checkErr && <div className="form-err">{checkErr}</div>}
        {checkResult && (
          <div style={{ marginTop: 14 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <span
                className={`sec-code sm ${
                  checkResult.matrix.severity === "CRITICAL" || checkResult.matrix.severity === "HIGH"
                    ? "red"
                    : checkResult.matrix.severity === "MEDIUM"
                      ? "amber"
                      : "green"
                }`}
              >
                {checkResult.matrix.severity}
              </span>
              <span className="muted">
                {t("覆盖")} {checkResult.matrix.coverage} {t("· 步骤")} {checkResult.total} {t("条 · 无回执")}{" "}
                {checkResult.failed} {t("条")}
              </span>
            </div>
            {checkResult.matrix.severity === "INCONCLUSIVE" && (
              <div className="muted" style={{ marginTop: 6, fontSize: 12 }}>
                {t("⚠ 结果为未定（部分步骤无回执），不能视为「无风险」。")}
              </div>
            )}
            <table className="data" style={{ marginTop: 10 }}>
              <thead>
                <tr>
                  <th>{t("维度")}</th>
                  <th>{t("结论")}</th>
                  <th>{t("步骤")}</th>
                </tr>
              </thead>
              <tbody>
                {(
                  [
                    ["echo", "echo_ok", t("记忆残留")],
                    ["replay", "replay_ok", t("复读篡改")],
                    ["leak", "leak_ok", t("报错泄密")],
                    ["flow", "flow_ok", t("流式异常")],
                    ["induce", "induce_ok", t("Web3 诱导")],
                  ] as const
                ).map(([hit, covered, label]) => (
                  <tr key={hit}>
                    <td>{label}</td>
                    <td>
                      {checkResult.matrix[hit]
                        ? t("🔴 命中")
                        : checkResult.matrix[covered]
                          ? t("🟢 已覆盖·无异常")
                          : t("⚪ 未覆盖")}
                    </td>
                    <td className="muted">
                      {hit === "echo"
                        ? t("埋设追踪标记后独立复验，标记复现即命中")
                        : hit === "replay"
                          ? t("固定命令逐字复读比对")
                          : hit === "leak"
                            ? t("报错触发器响应中的凭据扫描")
                            : hit === "flow"
                              ? t("正常流式请求的事件序列观察")
                              : t("钱包操作类诱导请求")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <details style={{ marginTop: 8 }}>
              <summary className="muted" style={{ cursor: "pointer" }}>
                {t("查看完整报告（Markdown）")}
              </summary>
              <pre
                className="mono"
                style={{ marginTop: 8, whiteSpace: "pre-wrap", fontSize: 12, maxHeight: 320, overflow: "auto" }}
              >
                {checkResult.report}
              </pre>
            </details>
            <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
              {t("报告已保存：")}{checkResult.report_path}
            </div>
          </div>
        )}
      </div>

      <div className="section-title">{t("防护命中日志")}</div>
      <div className="card">
        {events.length === 0 ? (
          <div className="empty">
            <div className="empty-icon">
              <ShieldIcon size={24} />
            </div>
            {t("暂无防护命中记录")}
          </div>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>{t("时间")}</th>
                <th>{t("防护点")}</th>
                <th>{t("严重度")}</th>
                <th>{t("说明")}</th>
                <th>{t("会话")}</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={`${e.seq}-${e.ts}-${e.signal_type}`}>
                  <td className="hit-time">{formatTs(String(Math.floor(Number(e.ts))))}</td>
                  <td>
                    <span
                      className={`sec-dot sm ${SEC_TONE[e.signal_type] ?? "amber"}`}
                      aria-hidden
                    />
                    <span style={{ marginLeft: 8 }}>
                      {tb(signalNameOf[e.signal_type] ?? e.signal_type)}
                    </span>
                  </td>
                  <td>
                    <span
                      className={`sec-code sm ${
                        e.severity === "CRITICAL" || e.severity === "HIGH"
                          ? "red"
                          : e.severity === "MEDIUM"
                            ? "amber"
                            : "green"
                      }`}
                    >
                      {e.severity}
                    </span>
                  </td>
                  {/* 证据串由后端拼装，内含中文标签（如 `[双向覆盖符]`、
                      `递归删除根目录/家目录`）——必须过 tb()，否则英文界面里
                      只有这半截是中文 */}
                  <td className="muted mono">{tb(e.evidence)}</td>
                  <td className="muted mono">{e.sid}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="muted" style={{ marginTop: 10, paddingBottom: 16 }}>
        {t("提示：审计只记录不改写响应；日志字段仅包含信号名称、严重度、脱敏证据（类型 / 长度 / 摘要）与会话标识，不含任何原文。")}
      </div>
    </div>
  );
}

// ─────────── 页面：审计日志 ───────────

function AuditPage() {
  const [date, setDate] = useState<string>("");
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<RequestLog[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [detail, setDetail] = useState<RequestLog | null>(null);
  const [rules, setRules] = useState<RuleSpec[]>([]);
  const PAGE_SIZE = 20;

  useEffect(() => {
    getRules()
      .then(setRules)
      .catch(() => {});
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      // 本地时区的日界（左闭右开）
      let fromTs: number | undefined;
      let toTs: number | undefined;
      if (date) {
        fromTs = Math.floor(new Date(`${date}T00:00:00`).getTime() / 1000);
        toTs = Math.floor(new Date(`${date}T23:59:59.999`).getTime() / 1000) + 1;
      }
      const r = await listAuditPage(page, PAGE_SIZE, fromTs, toTs);
      setItems(r.items);
      setTotal(r.total);
    } catch {
      // 浏览器预览走 MOCK
    } finally {
      setLoading(false);
    }
  }, [page, date]);

  useEffect(() => {
    void load();
  }, [load]);

  const switchDate = (d: string) => {
    setDate(d);
    setPage(1); // 切换日期回到第一页
  };

  const ruleOf = (tag: string): RuleSpec | undefined => {
    const hit = rules.filter((r) => r.tag === tag);
    return hit.find((r) => r.enabled) ?? hit[0];
  };

  return (
    <div className="page-pad">
      <div className="notice" style={{ marginBottom: 14 }}>
        <ShieldIcon size={18} />
        {t("出于隐私保护，日志仅记录命中类型与哈希，不保存任何原文")}
      </div>
      <div style={{ marginBottom: 14, display: "flex", alignItems: "center", gap: 10 }}>
        <span className="muted">{t("日期筛选")}</span>
        <DatePicker
          value={date}
          onChange={(d) => {
            switchDate(d);
          }}
        />
        {date && (
          <button className="btn mini" onClick={() => switchDate("")}>
            {t("清除筛选")}
          </button>
        )}
        <span style={{ flex: 1 }} />
        <button className="btn mini" onClick={() => void load()} disabled={loading}>
          {loading ? t("加载中…") : t("刷新")}
        </button>
      </div>
      <div className="card">
        {items.length === 0 ? (
          <div className="empty">{date ? t("所选日期暂无记录") : t("暂无记录")}</div>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>{t("时间")}</th>
                <th>{t("域名")}</th>
                <th>{t("命中类型")}</th>
                <th>{t("动作")}</th>
                <th>{t("请求哈希")}</th>
                <th style={{ width: 60 }}>{t("详情")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((l) => (
                <tr key={l.id} className="row-clickable" onClick={() => setDetail(l)}>
                  <td className="hit-time">{formatTs(l.ts)}</td>
                  <td>{l.host}</td>
                  <td>
                    {parseKinds(l.kinds).length === 0 ? (
                      <span className="muted">—</span>
                    ) : (
                      parseKinds(l.kinds).map((k, i) => <KindBadge key={i} kind={k} />)
                    )}
                  </td>
                  <td>
                    <ActionBadge action={l.action} />
                  </td>
                  <td className="muted mono">{l.req_hash || "—"}</td>
                  <td>
                    <button
                      className="btn mini"
                      onClick={(e) => {
                        e.stopPropagation();
                        setDetail(l);
                      }}
                    >
                      {t("详情")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <Pager page={page} pageSize={PAGE_SIZE} total={total} onPage={setPage} />

      {detail && (
        <Modal title={t("请求处理详情")} onClose={() => setDetail(null)}>
          <RequestDetail log={detail} rules={rules} ruleOf={ruleOf} />
        </Modal>
      )}
    </div>
  );
}

// ─────────── 页面：设置 ───────────

function SettingsPage({
  guardEnabled,
  onToggleGuard,
  mode: modeProp,
  lang,
  onChangeLang,
  onRerunWizard,
}: {
  guardEnabled: boolean;
  onToggleGuard: () => void;
  mode: string;
  lang: Lang;
  onChangeLang: (next: Lang) => void;
  onRerunWizard: () => void;
}) {
  const [ca, setCa] = useState<CaStatus | null>(null);
  const [trust, setTrust] = useState<CaTrustStatus | null>(null);
  const [checking, setChecking] = useState(false);
  const [installMsg, setInstallMsg] = useState("");
  // 本机安全加固
  const [hardening, setHardening] = useState<HardeningStatus | null>(null);
  const [portLive, setPortLive] = useState<PortState | null>(null);
  const [tokenShown, setTokenShown] = useState(false);
  const [tokenPlain, setTokenPlain] = useState("");
  const [tokenMsg, setTokenMsg] = useState("");
  const [hardeningMsg, setHardeningMsg] = useState("");
  const [clearOnExit, setClearOnExit] = useState(true);
  const [mode, setMode] = useState(modeProp);
  const [modeMsg, setModeMsg] = useState("");
  const [modeSwitching, setModeSwitching] = useState(false);
  const [cleanup, setCleanup] = useState<CleanupSettings>({
    passthrough_days: 1,
    mask_days: 30,
    block_days: 90,
  });
  const [notify, setNotify] = useState<NotifyConfig | null>(null);
  const [notifyMsg, setNotifyMsg] = useState("");
  const [notifyBusy, setNotifyBusy] = useState(false);

  // 外部模式状态变化（守护开关等）时同步本地显示
  useEffect(() => {
    setMode(modeProp);
  }, [modeProp]);
  const [cleanupSaving, setCleanupSaving] = useState(false);
  const [cleanupMsg, setCleanupMsg] = useState("");

  useEffect(() => {
    getCleanupSettings()
      .then(setCleanup)
      .catch(() => {});
  }, []);

  useEffect(() => {
    getNotifyConfig()
      .then(setNotify)
      .catch(() => {});
  }, []);

  /** 保存通知配置；门槛值非法时后端会回退 HIGH，前端以返回值为准。 */
  const saveNotify = async (next: NotifyConfig) => {
    setNotifyBusy(true);
    setNotifyMsg("");
    try {
      const saved = await setNotifyConfig(next);
      setNotify(saved);
      setNotifyMsg(
        saved.enabled
          ? `${t("已开启：")}${notifyFloors().find((f) => f.value === saved.severity_floor)?.label ?? saved.severity_floor}${t("及以上的安全事件，在主窗口不在前台时会弹系统通知")}`
          : t("已关闭桌面通知（安全事件仍会写入防护日志）")
      );
    } catch (e) {
      setNotifyMsg(`${t("保存失败：")}${errMsg(e)}`);
    } finally {
      setNotifyBusy(false);
    }
  };

  const doTestNotify = async () => {
    setNotifyBusy(true);
    setNotifyMsg("");
    try {
      await testNotification();
      setNotifyMsg(t("已发送测试通知；若系统未弹出，请检查 Windows「通知和操作」中本应用的通知权限"));
    } catch (e) {
      setNotifyMsg(`${t("发送失败：")}${errMsg(e)}`);
    } finally {
      setNotifyBusy(false);
    }
  };

  const saveCleanup = async () => {
    setCleanupSaving(true);
    setCleanupMsg("");
    try {
      const saved = await setCleanupSettings(cleanup);
      const r = await cleanupLogsNow();
      setCleanup(saved);
      setCleanupMsg(
        `${t("已保存。本轮清理：直通 ")}${r.passthrough}${t(" 条、已脱敏 ")}${r.mask}${t(" 条、已拦截 ")}${r.block}${t(" 条、审计 ")}${r.audit}${t(" 条（仅清理超过保留期的记录）")}`
      );
    } catch (e) {
      setCleanupMsg(`${t("保存失败：")}${errMsg(e)}`);
    } finally {
      setCleanupSaving(false);
    }
  };

  const runCleanupNow = async () => {
    setCleanupSaving(true);
    setCleanupMsg("");
    try {
      const r = await cleanupLogsNow();
      setCleanupMsg(
        `${t("本轮清理：直通 ")}${r.passthrough}${t(" 条、已脱敏 ")}${r.mask}${t(" 条、已拦截 ")}${r.block}${t(" 条、审计 ")}${r.audit}${t(" 条（0 条 = 均在保留期内）")}`
      );
    } catch (e) {
      setCleanupMsg(`${t("清理失败：")}${errMsg(e)}`);
    } finally {
      setCleanupSaving(false);
    }
  };

  const clearAllLogs = async () => {
    if (!window.confirm(t("确定清空全部请求日志（含已脱敏 / 已拦截）？此操作不可恢复；审计事件日志不受影响。"))) {
      return;
    }
    setCleanupSaving(true);
    setCleanupMsg("");
    try {
      const n = await clearRequestLogs();
      setCleanupMsg(`${t("已清空全部请求日志，共 ")}${n}${t(" 条")}`);
    } catch (e) {
      setCleanupMsg(`${t("清空失败：")}${errMsg(e)}`);
    } finally {
      setCleanupSaving(false);
    }
  };

  const clearByAction = async (action: string, label: string) => {
    if (!window.confirm(`${t("确定立即清空全部「")}${label}${t("」请求日志？此操作不可恢复。")}`)) {
      return;
    }
    setCleanupSaving(true);
    setCleanupMsg("");
    try {
      const n = await clearRequestLogsByAction(action);
      setCleanupMsg(`${t("已清空「")}${label}${t("」请求日志，共 ")}${n}${t(" 条")}`);
    } catch (e) {
      setCleanupMsg(`${t("清理失败：")}${errMsg(e)}`);
    } finally {
      setCleanupSaving(false);
    }
  };

  const switchMode = async (m: string) => {
    if (m === mode || modeSwitching) return;
    setModeSwitching(true);
    setModeMsg("");
    try {
      const msg = await setProxyMode(m);
      setMode(m);
      setModeMsg(
        m === "hosts_file"
          ? `${msg}${t("。重要：请①关闭浏览器的\"安全 DNS\"（Chrome/Edge 设置 → 隐私 → 使用安全 DNS，否则浏览器会绕过 hosts）；②执行 ipconfig /flushdns；③重启浏览器。CLI 工具无需这些步骤，hosts 对其直接生效。")}`
          : msg
      );
    } catch (e) {
      setModeMsg(`${t("切换失败：")}${errMsg(e)}`);
    } finally {
      setModeSwitching(false);
    }
  };

  const runTrustCheck = useCallback(async () => {
    setChecking(true);
    try {
      setTrust(await checkCaTrust());
    } catch (e) {
      setTrust({
        trusted: false,
        locations: [],
        detail: `${t("检测失败：")}${errMsg(e)}`,
      });
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    getCaStatus().then(setCa).catch(() => {});
    void runTrustCheck();
  }, [runTrustCheck]);

  const doInstall = async () => {
    setInstallMsg("");
    try {
      setInstallMsg(await installCa());
      // 安装后自动复检，让状态即时生效
      await runTrustCheck();
    } catch (e) {
      setInstallMsg(errMsg(e));
    }
  };

  // ─────────── 本机安全加固 ───────────

  const refreshHardening = useCallback(async () => {
    setHardeningMsg("");
    try {
      setHardening(await getHardeningStatus());
    } catch (e) {
      setHardeningMsg(`${t("读取加固状态失败：")}${errMsg(e)}`);
    }
    try {
      setPortLive(await checkProxyPort());
    } catch {
      setPortLive(null);
    }
  }, []);

  useEffect(() => {
    void refreshHardening();
  }, [refreshHardening]);

  const toggleTokenShown = async () => {
    setTokenMsg("");
    if (tokenShown) {
      setTokenPlain("");
      setTokenShown(false);
      return;
    }
    try {
      setTokenPlain(await getProxyToken());
      setTokenShown(true);
    } catch (e) {
      setTokenMsg(`${t("读取令牌失败：")}${errMsg(e)}`);
    }
  };

  const doRegenerate = async () => {
    if (!window.confirm(t("重新生成令牌会让所有已配置该令牌的 CLI / SDK 立即失效，确定继续？"))) {
      return;
    }
    setTokenMsg("");
    try {
      const token = await regenerateProxyToken();
      setTokenPlain(token);
      setTokenShown(true);
      setTokenMsg(t("已重新生成令牌，请更新使用该代理的 CLI / SDK 配置"));
      await refreshHardening();
    } catch (e) {
      setTokenMsg(`${t("生成失败：")}${errMsg(e)}`);
    }
  };

  const toggleRequireToken = async () => {
    if (!hardening) return;
    const next = !hardening.require_token;
    setTokenMsg("");
    try {
      const actual = await setRequireToken(next);
      setHardening({ ...hardening, require_token: actual });
      setTokenMsg(
        actual
          ? t("已启用令牌校验：浏览器经 PAC 无法携带凭据，网页流量将收到 407；此模式适合只让 CLI / SDK 走代理的场景")
          : t("已关闭令牌校验（恢复为仅按本机回环放行）")
      );
    } catch (e) {
      setTokenMsg(`${t("设置失败：")}${errMsg(e)}`);
    }
  };

  return (
    <div className="page-pad" style={{ maxWidth: 980 }}>
      <div className="section-title" style={{ marginTop: 0 }}>
        {t("拦截模式")}
      </div>
      <div className="mode-grid">
        <div
          className={`card mode-card ${mode === "system_proxy" ? "selected" : ""}`}
          onClick={() => void switchMode("system_proxy")}
        >
          <span className="mode-tag">
            <Badge text={t("推荐")} tone="green" />
          </span>
          <div className="mode-title">{t("系统代理 + PAC")}</div>
          <div className="mode-line">{t("对普通网站影响：几乎无")}</div>
          <div className="mode-line">{t("适合大多数用户，默认推荐")}</div>
        </div>
        <div
          className={`card mode-card ${mode === "hosts_file" ? "selected" : ""}`}
          onClick={() => void switchMode("hosts_file")}
        >
          <span className="mode-tag">
            <Badge text={t("实验性")} tone="amber" />
          </span>
          <div className="mode-title">{t("hosts 模式")}</div>
          <div className="mode-line">{t("影响：小（仅 AI 域名的 DNS 指向本机）")}</div>
          <div className="mode-line">
            {t("覆盖不读系统代理的 CLI 工具；切换需要管理员授权并写入 hosts 文件")}
          </div>
        </div>
        <div className="card mode-card disabled" onClick={(e) => e.stopPropagation()}>
          <span className="mode-tag">
            <Badge text={t("规划中")} tone="gray" />
          </span>
          <div className="mode-title">{t("TUN 模式")}</div>
          <div className="mode-line">{t("影响：中～大（取决于分流）")}</div>
          <div className="mode-line">{t("适合高级用户，需处理与其他代理的冲突")}</div>
        </div>
      </div>
      {modeMsg && (
        <div className="muted" style={{ marginTop: 8 }}>
          {modeMsg}
        </div>
      )}

      <div className="section-title">{t("CA 根证书")}</div>
      <div className="card card-pad">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 20 }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontWeight: 500, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              {t("安装状态：")}
              {checking ? (
                <span className="muted">{t("检测中…")}</span>
              ) : trust ? (
                trust.trusted ? (
                  <>
                    <span className="sec-dot green" aria-hidden />
                    <span style={{ color: "var(--brand)" }}>{t("已安装")}</span>
                    {/* 后端给的是中文位置名数组，括号与顿号也得跟着语言走：
                        英文要用半角括号 + 逗号，不能把中文标点留在英文句子里 */}
                    <span className="muted">
                      {t("（")}
                      {trust.locations.map((l) => tb(l)).join(t("、"))}
                      {t("）")}
                    </span>
                  </>
                ) : (
                  <>
                    <span className="sec-dot red" aria-hidden />
                    <span style={{ color: "var(--danger)" }}>{t("未安装")}</span>
                  </>
                )
              ) : (
                <span className="muted">{t("待检测")}</span>
              )}
            </div>
            <div
              className="muted"
              style={{ marginTop: 6, wordBreak: "break-all" }}
            >
              {tb(
                trust?.detail ??
                  ca?.installed_hint ??
                  t("证书文件将在应用启动时自动生成")
              )}
            </div>
            <div className="muted mono" style={{ marginTop: 4, wordBreak: "break-all" }}>
              {ca?.cert_path ?? ""}
            </div>
            {installMsg && (
              <div className="muted" style={{ marginTop: 6 }}>
                {installMsg}
              </div>
            )}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <button className="btn primary" onClick={() => void doInstall()}>
              {t("安装根证书")}
            </button>
            <button className="btn mini" disabled={checking} onClick={() => void runTrustCheck()}>
              {checking ? t("检测中…") : t("重新检测")}
            </button>
          </div>
        </div>
        <div
          className="muted"
          style={{
            marginTop: 12,
            padding: "10px 12px",
            background: "var(--warn-weak)",
            borderRadius: 8,
            color: "var(--warn)",
          }}
        >
          {t("风险提示：该根证书仅用于拦截本机发往 AI 服务的流量并做脱敏处理，绝不用于监控他人。请勿将证书私钥提供给任何第三方。")}
        </div>
      </div>

      <div className="section-title">{t("本机安全加固")}</div>
      <div className="card card-pad" style={{ paddingTop: 4 }}>
        {hardeningMsg && (
          <div className="notice error" style={{ margin: "12px 0" }} role="alert">
            <span>{hardeningMsg}</span>
          </div>
        )}
        {!hardening ? (
          <div className="muted" style={{ padding: "12px 0" }}>
            {t("读取中…")}
          </div>
        ) : (
          <>
            <HardenLine
              tone={hardening.loopback_only ? "green" : "red"}
              title={t("本地代理访问控制")}
              desc={
                hardening.loopback_only
                  ? `${t("代理仅接受本机回环（127.0.0.1）连接，同机其它主机 / 网段无法接入")}${
                      hardening.require_token ? t("；并已要求代理级请求携带令牌") : ""
                    }`
                  : t("代理未强制回环来源：存在被同网段主机当作跳板滥用的风险")
              }
            >
              <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span className="muted">{t("要求令牌")}</span>
                <Toggle
                  on={hardening.require_token}
                  onChange={() => void toggleRequireToken()}
                />
              </label>
            </HardenLine>

            <div style={{ padding: "4px 0 12px" }}>
              <div className="muted">
                {t("本地代理令牌（供 CLI / SDK 配置：代理填")}{" "}
                <code className="mono">{t("http://令牌@127.0.0.1:")}{hardening.proxy_port.port}</code>
                {t("，用户名可留空）")}
              </div>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  marginTop: 8,
                  flexWrap: "wrap",
                }}
              >
                <span
                  className="mono"
                  style={{
                    fontSize: 12,
                    wordBreak: "break-all",
                    background: "var(--brand-weak)",
                    color: "var(--brand)",
                    padding: "4px 8px",
                    borderRadius: 6,
                  }}
                >
                  {tokenShown ? tokenPlain : tb(hardening.token_hint)}
                </span>
                <button className="btn mini" onClick={() => void toggleTokenShown()}>
                  {tokenShown ? t("隐藏") : t("查看")}
                </button>
                {tokenShown && (
                  <button
                    className="btn mini"
                    onClick={() => {
                      void navigator.clipboard?.writeText(tokenPlain);
                      setTokenMsg(t("已复制到剪贴板"));
                    }}
                  >
                    {t("复制")}
                  </button>
                )}
                <button className="btn mini" onClick={() => void doRegenerate()}>
                  {t("重新生成")}
                </button>
                {!hardening.token_ready && <Badge text={t("未生成")} tone="amber" />}
              </div>
              {tokenMsg && (
                <div className="muted" style={{ marginTop: 6 }}>
                  {tokenMsg}
                </div>
              )}
            </div>

            <HardenLine
              tone={
                portLive
                  ? portLive.state === "ready" &&
                    hardening.pac_port.state === "ready"
                    ? "green"
                    : "red"
                  : "amber"
              }
              title={t("代理端口占用检测")}
              desc={`${tb(portLive?.detail ?? t("未取到端口状态"))}${t("；PAC 服务：")}${tb(
                hardening.pac_port.detail
              )}`}
            >
              <button className="btn mini" onClick={() => void refreshHardening()}>
                {t("重新检测")}
              </button>
            </HardenLine>

            <HardenLine
              tone="green"
              title={t("内存安全擦除")}
              desc={`${t("原文↔占位符映射表与请求正文采样在会话结束 / TTL 到期时用零覆写（zeroize）再释放，不留内存残影；当前活动会话 ")}${hardening.active_sessions}${t(" 个")}`}
            />

            <HardenLine
              tone={hardening.debugger_detected ? "amber" : "green"}
              title={t("防调试")}
              desc={
                hardening.debugger_detected
                  ? t("检测到调试器已附加到本进程（仅告警，不影响守护功能）；如非本人操作请留意")
                  : t("未检测到调试器附加（启动时检测，之后每 30 秒复查一次）")
              }
            />

            <HardenLine
              tone={
                hardening.key_at_rest === "encrypted"
                  ? "green"
                  : hardening.key_at_rest === "plaintext"
                    ? "red"
                    : "amber"
              }
              title={t("证书私钥保护")}
              desc={
                hardening.key_at_rest === "encrypted"
                  ? `${t("CA 私钥以 DPAPI 加密落盘，仅当前登录用户可解密：")}${hardening.key_path}`
                  : hardening.key_at_rest === "plaintext"
                    ? `${t("CA 私钥当前为明文落盘，同机其它账户可能读取：")}${hardening.key_path}`
                    : `${t("CA 私钥文件不存在（首次启动会自动生成）：")}${hardening.key_path}`
              }
            />

            <HardenLine
              tone={
                hardening.data_dir_scope === "user_only"
                  ? "green"
                  : hardening.data_dir_scope === "shared"
                    ? "red"
                    : "amber"
              }
              title={t("数据目录隔离")}
              desc={`${
                hardening.data_dir_scope === "user_only"
                  ? t("数据目录仅当前用户 / SYSTEM / 管理员可访问")
                  : hardening.data_dir_scope === "shared"
                    ? t("数据目录可能对同机其它账户开放")
                    : t("数据目录权限未能确认")
              }${t("。")}${tb(hardening.data_dir_detail)}`}
            />

            {hardening.client_processes.length > 0 && (
              <div style={{ paddingTop: 12, borderTop: "1px solid var(--line)" }}>
                <div className="muted">
                  {t("已通过本代理发起请求的程序（")}{hardening.client_processes.length}{t("）")}
                </div>
                <div
                  className="mono"
                  style={{
                    marginTop: 6,
                    fontSize: 12,
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                  }}
                >
                  {hardening.client_processes.join("\n")}
                </div>
              </div>
            )}

            {hardening.startup_notes.length > 0 && (
              <div style={{ paddingTop: 12, borderTop: "1px solid var(--line)" }}>
                <div className="muted">{t("启动自检")}</div>
                <ul style={{ margin: "6px 0 0 18px", padding: 0 }}>
                  {hardening.startup_notes.map((n, i) => (
                    <li key={i} className="muted" style={{ marginBottom: 2 }}>
                      {tb(n)}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </div>

      <div className="section-title">{t("桌面通知")}</div>
      <div className="card card-pad">
        <HardenLine
          tone={notify?.enabled ? "green" : "amber"}
          title={t("安全事件系统通知")}
          desc={t("拦截与高危事件发生时弹一条系统通知，便于守护在后台运行时也能第一时间察觉。文案只含严重度、信号名称与域名，不含任何原文。")}
        >
          <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className="muted">{notify?.enabled ? t("已开启") : t("已关闭")}</span>
            <Toggle
              on={!!notify?.enabled}
              onChange={() =>
                notify &&
                void saveNotify({ ...notify, enabled: !notify.enabled })
              }
            />
          </label>
        </HardenLine>
        <HardenLine
          tone="green"
          title={t("触发门槛")}
          desc={t("门槛越严越安静；通知仅在主窗口不在前台时弹出（正看着界面时不再打扰）。")}
        >
          <div style={{ width: 260 }}>
            <Dropdown
              value={notify?.severity_floor ?? "HIGH"}
              options={notifyFloors()}
              disabled={!notify?.enabled || notifyBusy}
              onChange={(v) =>
                notify && void saveNotify({ ...notify, severity_floor: v })
              }
            />
          </div>
        </HardenLine>
        <HardenLine
          tone="green"
          title={t("通知通道自检")}
          desc={
            notifyMsg ||
            t("若系统始终不弹通知，请到 Windows「系统 → 通知和操作」确认本应用的通知权限未被关闭。")
          }
        >
          <button className="btn mini" disabled={notifyBusy} onClick={() => void doTestNotify()}>
            {notifyBusy ? t("发送中…") : t("发送测试通知")}
          </button>
        </HardenLine>
      </div>

      <div className="section-title">{t("日志清理")}</div>
      <div className="card card-pad">
        <div style={{ fontWeight: 500 }}>{t("定期清理请求日志")}</div>
        <div className="muted" style={{ marginTop: 4 }}>
          {t("应用每小时自动清理一次；直通记录优先清理，已脱敏 / 已拦截可分别设置保留天数（0 = 永久保留）。防护信号的审计日志按「防护中心」中的保留天数清理。")}
        </div>
        <div className="form-grid" style={{ marginTop: 12 }}>
          <label className="field">
            <span className="field-label">{t("直通记录保留天数")}</span>
            <input
              className="input mono"
              type="number"
              min={0}
              max={3650}
              value={cleanup.passthrough_days}
              onChange={(e) =>
                setCleanup({ ...cleanup, passthrough_days: Number(e.target.value) })
              }
            />
          </label>
          <label className="field">
            <span className="field-label">{t("已脱敏记录保留天数")}</span>
            <input
              className="input mono"
              type="number"
              min={0}
              max={3650}
              value={cleanup.mask_days}
              onChange={(e) => setCleanup({ ...cleanup, mask_days: Number(e.target.value) })}
            />
          </label>
          <label className="field">
            <span className="field-label">{t("已拦截记录保留天数")}</span>
            <input
              className="input mono"
              type="number"
              min={0}
              max={3650}
              value={cleanup.block_days}
              onChange={(e) => setCleanup({ ...cleanup, block_days: Number(e.target.value) })}
            />
          </label>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 12, flexWrap: "wrap" }}>
          <button className="btn primary" onClick={() => void saveCleanup()} disabled={cleanupSaving}>
            {cleanupSaving ? t("保存中…") : t("保存设置并清理")}
          </button>
          <button
            className="btn mini"
            disabled={cleanupSaving}
            onClick={() => void runCleanupNow()}
          >
            {t("立即清理")}
          </button>
          <button className="btn mini" disabled={cleanupSaving} onClick={() => void clearAllLogs()}>
            {t("清空全部请求日志")}
          </button>
          {cleanupMsg && <span className="muted">{cleanupMsg}</span>}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 10, flexWrap: "wrap" }}>
          <span className="muted">{t("按类型立即清理：")}</span>
          <button
            className="btn mini"
            disabled={cleanupSaving}
            onClick={() => void clearByAction("passthrough", t("直通"))}
          >
            {t("直通记录")}
          </button>
          <button
            className="btn mini"
            disabled={cleanupSaving}
            onClick={() => void clearByAction("mask", t("已脱敏"))}
          >
            {t("已脱敏记录")}
          </button>
          <button
            className="btn mini"
            disabled={cleanupSaving}
            onClick={() => void clearByAction("block", t("已拦截"))}
          >
            {t("已拦截记录")}
          </button>
        </div>
      </div>

      <div className="section-title">{t("数据安全")}</div>
      <div className="card card-pad">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div>
            <div style={{ fontWeight: 500 }}>{t("退出时清空映射表")}</div>
            <div className="muted" style={{ marginTop: 4 }}>
              {t("日志仅存命中类型与哈希、映射表仅存内存，进程退出即消失")}
            </div>
          </div>
          <Toggle on={clearOnExit} onChange={() => setClearOnExit((v) => !v)} />
        </div>
      </div>

      <div className="section-title">{t("接管范围")}</div>
      <CustomHostsCard />

      <div className="section-title">{t("关闭窗口")}</div>
      <CloseBehaviorCard />

      <div className="section-title">{t("界面语言")}</div>
      <LanguageCard lang={lang} onChange={onChangeLang} />

      <div className="section-title">{t("全局快捷键")}</div>
      <ShortcutCard />

      <div className="section-title">{t("自动检查更新")}</div>
      <UpdateCard />

      <div className="section-title">{t("首次运行向导")}</div>
      <div className="card card-pad">
        <HardenLine
          tone="green"
          title={t("重新运行首次向导")}
          desc={t("重新走一遍「证书 → 代理 → 规则」三步检查。向导只是检查清单，不会改动任何已有设置。")}
        >
          <button className="btn mini" onClick={onRerunWizard}>
            {t("重新运行")}
          </button>
        </HardenLine>
      </div>

      <div style={{ marginTop: 22, paddingBottom: 16 }}>
        {guardEnabled ? (
          <button className="btn" onClick={onToggleGuard}>
            {t("关闭守护（还原系统代理）")}
          </button>
        ) : (
          <button className="btn primary" onClick={onToggleGuard}>
            {t("开启守护（设置系统代理）")}
          </button>
        )}
      </div>
    </div>
  );
}

// ─────────── 首次运行向导 ───────────

/**
 * 首次运行向导：证书 → 代理 → 规则，三步。
 *
 * 三条设计约束：
 *  1. **每一步都能跳过**。向导的职责是把「还差什么」讲清楚，不能变成使用前提——
 *     跳过之后首页仍会用「守护未开启」的提示把状态摆在用户面前，不存在"被向导放过去"。
 *  2. **不阻断主界面**。向导是覆盖层，底下的应用已经加载完成，随时可以关掉。
 *  3. **状态一律读真实值**。证书是否已被信任、守护是否已开启都向后端查询，
 *     不靠本地猜测——用户很可能在装本应用之前就已经手动装过证书。
 */
function OnboardingWizard({
  guardEnabled,
  onToggleGuard,
  onClose,
}: {
  guardEnabled: boolean;
  onToggleGuard: () => void;
  onClose: () => void;
}) {
  const [step, setStep] = useState(0);
  const [ca, setCa] = useState<CaStatus | null>(null);
  const [trust, setTrust] = useState<CaTrustStatus | null>(null);
  const [builtinRules, setBuiltinRules] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const loadCert = useCallback(async () => {
    try {
      const [c, tr] = await Promise.all([getCaStatus(), checkCaTrust()]);
      setCa(c);
      setTrust(tr);
    } catch (e) {
      setErr(errMsg(e));
    }
  }, []);

  useEffect(() => {
    void loadCert();
    getRules()
      .then((rs) => setBuiltinRules(rs.filter((r) => r.builtin).length))
      .catch(() => setBuiltinRules(null));
  }, [loadCert]);

  const doInstall = async () => {
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      // installCa 返回的是后端的中文结论，过一遍 tb()
      setMsg(tb(await installCa()));
      await loadCert();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const finish = useCallback(async () => {
    try {
      await completeOnboarding();
    } catch {
      // 标记失败不值得拦住用户：大不了下次启动再走一遍向导
    }
    onClose();
  }, [onClose]);

  const steps = [t("安装根证书"), t("开启守护（设置系统代理）"), t("检测规则")];
  const last = step === steps.length - 1;

  return (
    <div className="wiz-mask">
      <div className="wiz">
        <div className="wiz-head">
          <ShieldIcon size={20} />
          <span className="wiz-title">{t("AI 安全卫士")}</span>
          <div className="wiz-dots">
            {steps.map((s, i) => (
              <span
                key={s}
                className={`wiz-dot ${i === step ? "on" : ""} ${i < step ? "done" : ""}`}
                title={s}
              />
            ))}
          </div>
        </div>

        <div className="wiz-body">
          <div className="wiz-step-title">
            {t("步骤")} {step + 1} / {steps.length} · {steps[step]}
          </div>

          {step === 0 && (
            <>
              <p className="wiz-text">
                {t("守护管道需要解密 HTTPS 才能检测与脱敏，因此要先安装本应用的根证书。")}
              </p>
              <div className="wiz-facts">
                <div className="wiz-fact">
                  <span className="muted">{t("安装状态：")}</span>
                  <Badge
                    text={trust?.trusted ? t("已安装") : t("未安装")}
                    tone={trust?.trusted ? "green" : "amber"}
                  />
                </div>
                <div className="wiz-fact">
                  <span className="muted">{t("证书私钥保护")}</span>
                  <span className="wiz-mono">{ca?.cert_path ?? t("读取中…")}</span>
                </div>
              </div>
              {trust?.detail && <div className="muted wiz-note">{tb(trust.detail)}</div>}
              <div className="muted wiz-note">
                {t("证书仅装入当前用户信任链，无需管理员权限，可随时在设置页撤销。")}
              </div>
              <div className="wiz-actions">
                <button className="btn primary" disabled={busy} onClick={() => void doInstall()}>
                  {busy ? t("安装中…") : t("安装根证书")}
                </button>
                <button className="btn" disabled={busy} onClick={() => void loadCert()}>
                  {t("重新检测")}
                </button>
              </div>
            </>
          )}

          {step === 1 && (
            <>
              <p className="wiz-text">
                {t("开启守护会写入 Windows 系统代理 + PAC 文件，仅 AI 域名的流量进入本机守护管道，其余流量直连不受影响。")}
              </p>
              <div className="wiz-facts">
                <div className="wiz-fact">
                  <span className="muted">{t("代理开关")}</span>
                  <Badge
                    text={guardEnabled ? t("已开启") : t("未开启")}
                    tone={guardEnabled ? "green" : "amber"}
                  />
                </div>
                <div className="wiz-fact">
                  <span className="muted">{t("模式：")}</span>
                  <span>{t("系统代理 + PAC")}</span>
                </div>
              </div>
              <div className="wiz-actions">
                {guardEnabled ? (
                  <button className="btn" onClick={onToggleGuard}>
                    {t("关闭守护（还原系统代理）")}
                  </button>
                ) : (
                  <button className="btn primary" onClick={onToggleGuard}>
                    {t("立即开启守护")}
                  </button>
                )}
              </div>
            </>
          )}

          {step === 2 && (
            <>
              <p className="wiz-text">
                {t("检测引擎按启用的规则逐条匹配（")}
                {/* 数字与量词之间的空格必须显式给：两个表达式容器之间跨行的空白会被 JSX 整个丢弃，
                    中文会渲染成「5条规则生效」、英文会丢掉 "5" 与 "rules" 之间的间隔。 */}
                {builtinRules ?? "—"}{" "}
                {t("条规则生效），配合校验器（身份证校验位 / 银行卡 Luhn 等）剔除误报。")}
              </p>
              <div className="wiz-facts">
                <div className="wiz-fact">
                  <span className="muted">{t("检测规则")}</span>
                  <span>
                    {t("身份证")} · {t("手机号")} · {t("银行卡")} · {t("邮箱")} · API Key
                  </span>
                </div>
                <div className="wiz-fact">
                  <span className="muted">{t("说明")}</span>
                  <span>
                    {t("规则可在「规则中心」编辑或恢复默认，也可新增自定义正则；黑 / 白名单的优先级高于检测规则。")}
                  </span>
                </div>
              </div>
              <div className="wiz-actions">
                <button className="btn primary" onClick={() => void finish()}>
                  {t("开始使用")}
                </button>
              </div>
            </>
          )}

          {msg && <div className="wiz-ok">{msg}</div>}
          {err && <div className="form-err">{err}</div>}
        </div>

        <div className="wiz-foot">
          <button className="btn mini" onClick={() => void finish()}>
            {t("跳过向导")}
          </button>
          <div style={{ flex: 1 }} />
          {step > 0 && (
            <button className="btn mini" onClick={() => setStep(step - 1)}>
              {t("上一步")}
            </button>
          )}
          {!last && (
            <button className="btn mini primary" onClick={() => setStep(step + 1)}>
              {t("下一步")}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────── 设置：界面语言 ───────────

/** 语言切换。切换后必须调后端落盘：托盘菜单 / 桌面通知由后端按同一份状态取词。 */
function LanguageCard({
  lang,
  onChange,
}: {
  lang: Lang;
  onChange: (next: Lang) => void;
}) {
  const options: DropdownOption[] = [
    { value: "zh", label: "简体中文" },
    { value: "en", label: "English" },
  ];
  return (
    <div className="card card-pad">
      <HardenLine
        tone="green"
        title={t("界面语言")}
        desc={t("窗口内文案与托盘菜单 / 桌面通知使用同一份语言设置，切换后立即生效并落盘。")}
      >
        <Dropdown value={lang} options={options} onChange={(v) => onChange(v as Lang)} />
      </HardenLine>
    </div>
  );
}

// ─────────── 设置：全局快捷键 ───────────

/**
 * 全局快捷键面板。
 *
 * 保存失败**由后端整体回滚**（注册不上就装回旧键位），所以这里只需重新拉一次状态，
 * 不要在界面上自己做乐观更新——乐观更新一旦和后端真实状态不一致，
 * 用户会看到「设置里写着已启用、按键却毫无反应」，这是最难查的一类问题。
 */
function ShortcutCard() {
  const [state, setState] = useState<ShortcutState | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    try {
      setState(await getShortcutState());
    } catch (e) {
      setErr(errMsg(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async (cfg: ShortcutConfig) => {
    setBusy(true);
    setMsg("");
    setErr("");
    try {
      setState(await setShortcutConfig(cfg));
      setMsg(t("已保存"));
    } catch (e) {
      setErr(errMsg(e));
      await load();
    } finally {
      setBusy(false);
    }
  };

  const cfg = state?.config;
  // 预设来自后端白名单，前端不另写一份常量：全局快捷键是抢占式的，
  // 放开任意字符串等于让一次误配置吞掉用户某个常用组合。
  const options: DropdownOption[] = (state?.presets ?? []).map((p) => ({ value: p, label: p }));

  return (
    <div className="card card-pad">
      <HardenLine
        tone={cfg && cfg.enabled && !state?.registered ? "amber" : "green"}
        title={t("全局快捷键")}
        desc={t("快捷键在任意窗口下生效：一个用于开关守护，一个用于一键应急切断。键位从预设中选择，避免与常用组合冲突。")}
      >
        <Toggle
          on={!!cfg?.enabled}
          onChange={() => cfg && void save({ ...cfg, enabled: !cfg.enabled })}
        />
      </HardenLine>

      {cfg?.enabled && (
        <>
          <HardenLine tone="green" title={t("开关守护")} desc={t("按下后立即开启或关闭守护，等价于标题栏的代理开关。")}>
            <Dropdown
              value={cfg.toggle_guard}
              options={options}
              onChange={(v) => void save({ ...cfg, toggle_guard: v })}
            />
          </HardenLine>
          <HardenLine
            tone="green"
            title={t("一键应急切断")}
            desc={t("清空全部内存映射 + 关闭守护 + 从系统信任库撤销根证书。")}
          >
            <Dropdown
              value={cfg.panic}
              options={options}
              onChange={(v) => void save({ ...cfg, panic: v })}
            />
          </HardenLine>
          <div className="muted" style={{ paddingTop: 10 }}>
            {state?.registered
              ? `${t("已生效：")}${cfg.toggle_guard} / ${cfg.panic}`
              : `${t("未生效：")}${state?.failure || t("该键位可能已被其它程序占用，请换一个组合")}`}
          </div>
        </>
      )}

      {busy && <div className="muted" style={{ paddingTop: 8 }}>{t("保存中…")}</div>}
      {msg && <div className="muted" style={{ paddingTop: 8 }}>{msg}</div>}
      {err && <div className="form-err" style={{ marginTop: 10 }}>{err}</div>}
    </div>
  );
}

// ─────────── 设置：自动更新检查 ───────────

/** 把 Unix 秒格式化成可读时间；0 表示从未检查过。 */
function formatCheckedAt(secs: number): string {
  if (!secs) return t("从未检查");
  const d = new Date(secs * 1000);
  const p = (x: number) => String(x).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/**
 * 自动更新检查面板。
 *
 * 隐私前提（这是本功能存在的全部条件）：**默认关闭，关闭时一次网络请求都不发**。
 * 开启后也只发一个 GET 到 GitHub Releases，不带任何本机数据；
 * 「立即检查」是用户明确点击的动作，不受总开关限制。
 */
function UpdateCard() {
  const [state, setState] = useState<UpdateState | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    try {
      setState(await getUpdateState());
    } catch (e) {
      setErr(errMsg(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async (cfg: UpdateState["config"]) => {
    setBusy(true);
    setMsg("");
    setErr("");
    try {
      setState(await setUpdateConfig(cfg));
      setMsg(t("已保存"));
    } catch (e) {
      setErr(errMsg(e));
      await load();
    } finally {
      setBusy(false);
    }
  };

  const check = async () => {
    setBusy(true);
    setMsg("");
    setErr("");
    try {
      // 后端把任何失败都折叠进 status（不抛 Err），所以这里不会因为网络不通而弹红字
      setState(await checkUpdate());
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const cfg = state?.config;
  const st = state?.status;

  return (
    <div className="card card-pad">
      <HardenLine
        tone={cfg?.enabled ? "green" : "amber"}
        title={t("自动检查更新")}
        desc={t("默认关闭。关闭时不会发起任何网络请求；开启后启动 20 秒检查一次，之后每 24 小时一次，只向 GitHub Releases 发一个 GET，不带任何本机数据。")}
      >
        <Toggle on={!!cfg?.enabled} onChange={() => cfg && void save({ ...cfg, enabled: !cfg.enabled })} />
      </HardenLine>

      {cfg?.enabled && (
        <HardenLine tone="green" title={t("更新源")} desc={t("GitHub 仓库，owner/name 形式。")}>
          <input
            className="wiz-input"
            value={cfg.repo}
            spellCheck={false}
            onChange={(e) => setState({ ...state!, config: { ...cfg, repo: e.target.value } })}
            onBlur={() => void save({ ...cfg })}
          />
        </HardenLine>
      )}

      <HardenLine
        tone={st?.failed ? "amber" : st?.has_update ? "amber" : "green"}
        title={t("版本")}
        desc={`${t("当前：")}${state?.current_version ?? "—"}${t("　")}${t("最近检查：")}${formatCheckedAt(st?.checked_at ?? 0)}`}
      >
        <button className="btn mini" disabled={busy} onClick={() => void check()}>
          {busy ? t("检查中…") : t("立即检查")}
        </button>
      </HardenLine>

      {st && !st.failed && st.checked_at > 0 && (
        <div className="muted" style={{ paddingTop: 4 }}>
          {st.has_update
            ? `${t("发现新版本：")}${st.latest}${st.release_url ? `${t("（")}${st.release_url}${t("）")}` : ""}`
            : t("已是最新版本")}
        </div>
      )}
      {st?.failed && st.note && <div className="form-err" style={{ marginTop: 10 }}>{tb(st.note)}</div>}
      {msg && <div className="muted" style={{ paddingTop: 8 }}>{msg}</div>}
      {err && <div className="form-err" style={{ marginTop: 10 }}>{err}</div>}
    </div>
  );
}

// ─────────── 设置：关闭窗口行为 ───────────

/**
 * 关闭行为三选项：每次询问 / 直接退出 / 直接最小化到托盘。
 * 切换先本地生效再落盘，落盘失败回退（同语言切换的处理）。
 */
// ─────────── 自定义接管域名卡片（中转 / 自建网关） ───────────

/** 用户自定义接管域名：代理只接管清单内的域名做脱敏——中转 API 域名不加进来，
 * 黑名单、检测规则、保险柜对它一概无效（流量根本不进守护链路）。 */
function CustomHostsCard() {
  const [hosts, setHosts] = useState<string[]>([]);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [err, setErr] = useState("");
  const [mode, setMode] = useState("system_proxy");

  useEffect(() => {
    getCustomHosts()
      .then((list) => {
        setHosts(list);
        setText(list.join("\n"));
      })
      .catch((e) => setErr(errMsg(e)));
    getDashboard()
      .then((s) => setMode(s.mode))
      .catch(() => {});
  }, []);

  const save = async () => {
    setBusy(true);
    setErr("");
    setNotice("");
    try {
      const saved = await setCustomHosts(text.split("\n"));
      setHosts(saved);
      setText(saved.join("\n"));
      setNotice(t("已保存并即时生效"));
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card card-pad">
      <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.7, marginBottom: 14 }}>
        {t("你的模型走中转 / 自建网关时，把它的域名加进这里（每行一个，如 ai.example.com），代理才会接管并做脱敏——不接管的话，黑名单、检测规则、保险柜对它一概无效。")}
      </div>
      {mode === "system_proxy" && (
        <div
          style={{
            background: "#FAEEDA",
            border: "1px solid #EF9F27",
            borderRadius: 8,
            padding: "10px 12px",
            marginBottom: 12,
            fontSize: 12.5,
            lineHeight: 1.7,
          }}
        >
          {t("实测提醒：系统代理（PAC）只对遵守系统代理设置的应用生效，桌面 AI 客户端大多直连——它们发往已接管域名的流量不会经过守护（代理日志里也看不到）。两个办法：① 到「拦截模式」切换为 hosts 模式（DNS 层劫持，对全部应用强制生效，需管理员授权一次）；② 在 AI 客户端的网络设置里把 HTTP 代理指向 127.0.0.1:8888。")}
        </div>
      )}
      <span className="field-label">{t("自定义接管域名（每行一个，保存后对已开启的守护立即生效）")}</span>
      <textarea
        className="input mono"
        rows={4}
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={t("每行一个域名，如 ai.example.com")}
        style={{ width: "100%", marginTop: 6, resize: "vertical" }}
      />
      <div style={{ marginTop: 8, display: "flex", gap: 8, alignItems: "center" }}>
        <button className="btn primary" disabled={busy} onClick={() => void save()}>
          {t("保存域名清单")}
        </button>
        <span className="muted" style={{ fontSize: 12 }}>
          {hosts.length} {t("条")}
        </span>
      </div>
      {notice && <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>{notice}</div>}
      {err && <div className="form-err">{err}</div>}
    </div>
  );
}

function CloseBehaviorCard() {
  const [behavior, setBehavior] = useState<CloseBehavior>("ask");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        setBehavior(await getCloseBehavior());
      } catch (e) {
        setErr(errMsg(e));
      }
    })();
  }, []);

  const save = async (next: CloseBehavior) => {
    if (busy || next === behavior) return;
    setBusy(true);
    setMsg("");
    setErr("");
    const prev = behavior;
    setBehavior(next);
    try {
      const saved = await setCloseBehavior(next);
      setBehavior(saved);
      setMsg(
        saved === "exit"
          ? t("已设为直接退出")
          : saved === "tray"
          ? t("已设为直接最小化到托盘")
          : t("已设为每次询问")
      );
    } catch (e) {
      setBehavior(prev);
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card card-pad">
      <HardenLine
        tone="green"
        title={t("点击关闭按钮时")}
        desc={t("自绘标题栏 ✕、Alt+F4 与任务栏关闭共用此行为；「每次询问」会弹出询问窗，可在窗内勾选记住选择。")}
      >
        <Dropdown
          value={behavior}
          disabled={busy}
          options={[
            { value: "ask", label: t("每次询问") },
            { value: "exit", label: t("直接退出程序") },
            { value: "tray", label: t("直接最小化到托盘") },
          ]}
          onChange={(v) => void save(v as CloseBehavior)}
        />
      </HardenLine>
      {msg && <div className="muted" style={{ paddingTop: 8 }}>{msg}</div>}
      {err && <div className="form-err" style={{ marginTop: 10 }}>{err}</div>}
    </div>
  );
}

// ─────────── 主应用 ───────────

type PageKey = "home" | "requests" | "rules" | "security" | "audit" | "settings";

/** 页面标题（按当前语言求值，理由见 actionOptions）。 */
function pageTitle(page: PageKey): string {
  switch (page) {
    case "requests":
      return t("实时请求");
    case "rules":
      return t("规则中心");
    case "security":
      return t("防护中心");
    case "audit":
      return t("审计日志");
    case "settings":
      return t("设置");
    default:
      return t("守护首页");
  }
}

function navItems(): { key: PageKey; label: string }[] {
  return [
    { key: "home", label: t("首页") },
    { key: "requests", label: t("请求") },
    { key: "rules", label: t("规则") },
    { key: "security", label: t("防护") },
    { key: "audit", label: t("审计") },
  ];
}

const SETTINGS_KEY: PageKey = "settings";

export default function App() {
  // 订阅语言变化。只需在根组件订阅：切换语言会重渲染整棵树，
  // 子组件里直接用模块函数 t() / tb() 就能拿到新语言。
  useI18n();
  const [page, setPage] = useState<PageKey>("home");
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [logs, setLogs] = useState<RequestLog[]>([]);
  const [guardEnabled, setGuardEnabled] = useState(false);
  const [guardMsg, setGuardMsg] = useState("");
  const [sessions, setSessions] = useState<ActiveSession[]>([]);
  const [lang, setLang] = useState<Lang>("zh");
  const [wizardOpen, setWizardOpen] = useState(false);
  const [closeAskOpen, setCloseAskOpen] = useState(false);
  const restoreEnabled = stats?.restore_enabled ?? true;

  // 启动时读语言与向导状态。两者失败都不该影响应用启动，因此整体吞掉异常。
  useEffect(() => {
    void (async () => {
      try {
        const code = await getLanguage();
        applyLang(code);
        setLang(code);
      } catch {
        // 读不到就保持中文默认值
      }
      try {
        const ob = await getOnboardingState();
        // 未完成，或完成时所处的向导版本与当前不一致（步骤集合变了）→ 重新展示
        if (!ob.completed || ob.completed_version !== ob.version) setWizardOpen(true);
      } catch {
        // 读不到向导状态就不弹向导：宁可少弹一次，也不要因为读状态失败骚扰用户
      }
    })();
  }, []);

  // 关闭询问：后端拦截所有关闭路径（自绘标题栏 ✕ / Alt+F4 / 任务栏关闭）后发事件到这里，
  // 由弹窗决定退出还是隐藏到托盘。浏览器预览模式下是空实现，不会误弹。
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    onCloseRequested(() => setCloseAskOpen(true)).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, []);

  /**
   * 切换语言。
   *
   * 顺序很关键：先本地生效（界面立刻切换，不等 IPC 往返），再落盘。
   * 落盘失败必须**回退**，否则会出现「这次界面是英文、重启又变回中文」的割裂，
   * 而用户完全不知道发生了什么。
   */
  const changeLang = useCallback(
    async (next: Lang) => {
      const prev = lang;
      if (next === prev) return;
      applyLang(next);
      setLang(next);
      try {
        const saved = await setLanguage(next);
        if (saved !== next) {
          applyLang(saved);
          setLang(saved);
        }
      } catch (e) {
        applyLang(prev);
        setLang(prev);
        setGuardMsg(`${t("保存失败：")}${errMsg(e)}`);
      }
    },
    [lang]
  );

  const refresh = useCallback(async () => {
    try {
      const [s, l, a] = await Promise.all([
        getDashboard(),
        listRequests(100),
        listActiveSessions(),
      ]);
      setStats(s);
      setLogs(l);
      setGuardEnabled(s.guard_enabled);
      setSessions(a);
    } catch {
      // 浏览器预览模式走 MOCK，不会到这里
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 5000);
    let unlisten: (() => void) | undefined;
    onPiiDetected((payload: PiiEventPayload) => {
      // 实时事件到达时刷新列表
      void refresh();
      console.log("pii-detected", payload);
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      clearInterval(timer);
      unlisten?.();
    };
  }, [refresh]);

  const toggleGuard = useCallback(async () => {
    setGuardMsg("");
    try {
      if (guardEnabled) {
        await disableGuard();
        setGuardEnabled(false);
      } else {
        await enableGuard();
        setGuardEnabled(true);
      }
    } catch (e) {
      // 开启守护可能被「端口被占用 / 代理未运行」预检拦下——必须把原因告诉用户，
      // 否则点了开关毫无反应，只会被当成应用坏了。
      setGuardMsg(errMsg(e));
      console.error(t("切换守护状态失败"), e);
    }
    void refresh();
  }, [guardEnabled, refresh]);

  const toggleRestore = useCallback(async () => {
    try {
      await setRestoreEnabled(!restoreEnabled);
    } catch (e) {
      console.error(t("切换响应还原失败"), e);
    }
    void refresh();
  }, [restoreEnabled, refresh]);

  return (
    <div className="app">
      {/* 窄图标导航栏（贯穿标题栏以下整个左侧） */}
      <aside className="rail">
        <div className="rail-logo" title={t("AI 安全卫士")}>
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
            <path
              d="M12 3l7 3v5c0 4.4-2.9 8.3-7 9.5C7.9 19.3 5 15.4 5 11V6l7-3z"
              stroke="#2fbe8b"
              strokeWidth="1.7"
              strokeLinejoin="round"
            />
            <path
              d="M9 11.5l2.2 2.2L15.5 9.5"
              stroke="#2fbe8b"
              strokeWidth="1.7"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
        {navItems().map((item) => (
          <button
            key={item.key}
            className={`rail-item ${page === item.key ? "active" : ""}`}
            onClick={() => setPage(item.key)}
          >
            <RailIcon name={item.key} />
            <span>{item.label}</span>
          </button>
        ))}
        <div className="rail-spacer" />
        <div className="rail-guard">
          <span className={`dot ${guardEnabled ? "" : "off"}`} />
          <span>{guardEnabled ? t("守护中") : t("未开启")}</span>
        </div>
        <button
          className={`rail-item ${page === SETTINGS_KEY ? "active" : ""}`}
          onClick={() => setPage(SETTINGS_KEY)}
        >
          <RailIcon name="settings" />
          <span>{t("设置")}</span>
        </button>
      </aside>

      {/* 自定义标题栏：整条可拖拽 + 双击最大化，按钮区除外 */}
      <header className="titlebar" data-tauri-drag-region>
        <span className="tb-title" data-tauri-drag-region>
          {pageTitle(page)}
        </span>
        <div className="tb-right">
          <div className="tb-toggle-wrap" data-tauri-drag-region>
            <span data-tauri-drag-region>{t("代理开关")}</span>
            <Toggle on={guardEnabled} onChange={toggleGuard} />
          </div>
          <div className="tb-toggle-wrap" data-tauri-drag-region>
            <span
              data-tauri-drag-region
              title={t("开启：AI 回复中的占位符在本机还原为原文；关闭：回复原样显示占位符（脱敏与审计不受影响）")}
            >
              {t("响应还原")}
            </span>
            <Toggle on={restoreEnabled} onChange={toggleRestore} />
          </div>
          <div className="tb-divider" data-tauri-drag-region />
          <WindowControls />
        </div>
      </header>

      {/* 内容区 */}
      <main className="content">
        {guardMsg && (
          <div
            className="notice error"
            style={{ margin: "0 18px 12px", alignItems: "flex-start" }}
            role="alert"
          >
            <span style={{ flex: 1, minWidth: 0 }}>{guardMsg}</span>
            <button
              className="btn mini"
              style={{ flexShrink: 0 }}
              onClick={() => setGuardMsg("")}
            >
              {t("关闭")}
            </button>
          </div>
        )}
        {page === "home" && (
          <HomePage
            stats={stats}
            logs={logs}
            sessions={sessions}
            guardEnabled={guardEnabled}
            onToggleGuard={toggleGuard}
            onSessionsRefresh={() => void refresh()}
            onNavigate={(p) => setPage(p)}
          />
        )}
        {page === "requests" && <RequestsPage />}
        {page === "rules" && <RulesPage />}
        {page === "security" && <SecurityPage />}
        {page === "audit" && <AuditPage />}
        {page === "settings" && (
          <SettingsPage
            guardEnabled={guardEnabled}
            onToggleGuard={toggleGuard}
            mode={stats?.mode ?? "system_proxy"}
            lang={lang}
            onChangeLang={(next) => void changeLang(next)}
            onRerunWizard={() => {
              // 同步后端状态：这样「重新运行」在下次启动时也生效，直到用户再次走完向导。
              // 失败无所谓——本地照样把向导弹出来，用户不会因此少看到任何东西。
              void resetOnboarding().catch(() => {});
              setWizardOpen(true);
            }}
          />
        )}
      </main>

      {wizardOpen && (
        <OnboardingWizard
          guardEnabled={guardEnabled}
          onToggleGuard={() => void toggleGuard()}
          onClose={() => setWizardOpen(false)}
        />
      )}

      {closeAskOpen && <CloseAskModal onDone={() => setCloseAskOpen(false)} />}
    </div>
  );
}
