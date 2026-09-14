//! 流式还原状态机（核心难点）。
//!
//! 响应方向（SSE）中，占位符 `[[PII:IDCARD:8f3a2b1c]]` 可能被 TCP/chunk 切开，
//! 也可能被模型**改写形态**（多/少反斜杠转义、把方括号剥掉），因此需要：
//!
//! 1. **按通道独立缓冲**：正文增量与工具参数增量各占一个通道。共用一个缓冲会让
//!    上一个字段没闭合的占位符被拼进下一个字段（内容错位 / 吞字段）；
//! 2. **尾部残缺扣留**：末尾可能是 `[`、`[[`、`[[PII:`、`[[PII:TAG:8f3a` 这类半截
//!    形态时扣留不发，等下一个 chunk；超过上限则按普通文本吐出，防无限缓冲；
//! 3. **三层形态容错**：严格 `[[PII:TAG:hex]]` → 转义（方括号前带 `\`）→ 宽松
//!    （方括号被剥）。宽松遍**不走后缀索引**，因为裸 token 可能只是被切开的残片；
//! 4. **绝不猜**：查不到原文就原样保留并计入 `unresolved`，让上层看得见
//!    「有占位符没还原」。对随机后缀做推算 = 编造用户从未输入过的数据，禁止；
//! 5. **JSON 字符串转义**：还原目标是工具参数（`arguments` / `partial_json`）时，
//!    原文里的引号、换行、反斜杠必须按 JSON 字符串规则转义，否则客户端解析失败；
//! 6. **安全兜底**：本模块不 panic、不返回 Err，异常路径一律降级为「少输出」，
//!    并提供缓冲熔断。

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use regex::{Captures, Regex};

use crate::vault::{PLACEHOLDER_PREFIX, PLACEHOLDER_SUFFIX, Vault};

/// 默认通道名（非结构化场景共用一个通道）。
pub const DEFAULT_CHANNEL: &str = "default";

/// 严格 + 转义形态：`[[PII:TAG:hex]]`，每个方括号前允许 0~3 个反斜杠。
/// `(?:\\{0,3}\[){2}` 同时覆盖 `[[` 与 `\[\[` / `\\[\\[` 等模型转义写法。
fn rx_strict() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| {
        Regex::new(
            r"(?:\\{0,3}\[){2}PII:([A-Za-z0-9_]{1,32}):([0-9a-fA-F]{8})(?:\\{0,3}\]){2}",
        )
        .expect("严格占位符正则必须可编译")
    })
}

/// 宽松形态：方括号数量 0~2（模型把 `[[ ]]` 剥掉甚至写残）。
fn rx_loose() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| {
        Regex::new(
            r"(?:\\{0,3}\[){0,2}PII:([A-Za-z0-9_]{1,32}):([0-9a-fA-F]{8})(?:\\{0,3}\]){0,2}",
        )
        .expect("宽松占位符正则必须可编译")
    })
}

/// 占位符解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// 精确命中本会话映射，输出原文
    Restored(String),
    /// 靠形态容错（后缀反查）救回：是成功路径，但说明模型在改写占位符
    RestoredDegraded(String),
    /// 查不到映射：原样输出占位符（绝不猜，安全兜底）
    Unknown,
    /// 判定为攻击（跨会话换芯等）：用给定标记替换，不输出原文
    Blocked(String),
}

/// 还原计数（供上层生成可见事件）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RestoreStats {
    /// 成功还原的占位符数
    pub restored: usize,
    /// 查不到映射、原样保留的占位符数（>0 说明用户会看到占位符）
    pub unresolved: usize,
    /// 靠形态容错 / 后缀反查救回的数量（模型在改写输出格式的前兆）
    pub degraded: usize,
    /// 被安全策略阻断的数量
    pub blocked: usize,
}

/// 是否为形如 `[[PII:...]]` 的完整占位符字面量。
pub fn is_pii_placeholder(s: &str) -> bool {
    s.starts_with(PLACEHOLDER_PREFIX)
        && s.ends_with(PLACEHOLDER_SUFFIX)
        && s.len() > PLACEHOLDER_PREFIX.len() + PLACEHOLDER_SUFFIX.len()
}

/// 把原文转成「JSON 字符串内部」的转义形态（去掉包裹的双引号）。
fn json_escape_inside(orig: &str) -> String {
    match serde_json::to_string(orig) {
        // 序列化结果首尾各一个 `"`（单字节），按字节裁剪安全
        Ok(js) if js.len() >= 2 => js[1..js.len() - 1].to_string(),
        _ => orig.to_string(),
    }
}

/// 尾部是否「像残缺的占位符」（用于决定扣留多少字节）。
fn looks_like_partial_ph(tail: &str) -> bool {
    let core: String = tail.chars().filter(|c| *c != '\\' && *c != '[').collect();
    if core.is_empty() {
        return true; // 纯 "[" / "\[" 序列
    }
    let Some(rest) = core.strip_prefix("PII:") else {
        // 也可能是 "P" / "PI" / "PII" / "PII:" 的前缀
        return "PII:".starts_with(&core);
    };
    let (tag, hex) = match rest.split_once(':') {
        Some((t, h)) => (t, Some(h)),
        None => (rest, None),
    };
    if !tag
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return false;
    }
    match hex {
        Some(h) => h.chars().all(|c| c.is_ascii_hexdigit()) && h.len() <= 8,
        None => true,
    }
}

/// 返回 `buf` 末尾「可能是残缺占位符」的字节数（0 = 可全部输出）。
fn partial_tail_len(buf: &str, max_ph_len: usize) -> usize {
    let n = buf.len();
    if n == 0 {
        return 0;
    }
    let limit = n.min(max_ph_len.max(32));
    let floor = n - limit;
    // 从尾部往前吞掉「构成占位符的字符」，得到候选后缀的起点
    let bytes = buf.as_bytes();
    let mut start = n;
    while start > floor {
        let c = bytes[start - 1];
        if c == b'[' || c == b'\\' || c == b']' || c == b':' || c == b'_' || c.is_ascii_alphanumeric()
        {
            start -= 1;
        } else {
            break;
        }
    }
    if start == n {
        return 0;
    }
    let tail = &buf[start..];
    // 已闭合的形态不需要扣留
    let bare: String = tail.chars().filter(|c| *c != '\\').collect();
    if bare.starts_with("[[") && bare.ends_with("]]") {
        return 0;
    }
    if looks_like_partial_ph(tail) {
        n - start
    } else {
        0
    }
}

fn is_word_char(c: Option<char>) -> bool {
    matches!(c, Some(ch) if ch.is_ascii_alphanumeric() || ch == '_')
}

/// 带前瞻缓冲的流式还原器（按通道隔离）。
pub struct StreamingRestorer {
    /// channel -> 未确认的尾部缓冲
    pending: HashMap<String, String>,
    vault: Arc<Vault>,
    session: String,
    max_ph_len: usize,
    max_buf: usize,
    overflowed: bool,
    stats: RestoreStats,
}

impl StreamingRestorer {
    pub fn new(vault: Arc<Vault>, session: impl Into<String>) -> Self {
        StreamingRestorer {
            pending: HashMap::new(),
            vault,
            session: session.into(),
            // 最长合法占位符：[[PII:BANKCARD:<8hex>]] ≈ 22 字节；64 足够宽容
            max_ph_len: 64,
            max_buf: 1 << 20,
            overflowed: false,
            stats: RestoreStats::default(),
        }
    }

    /// 设定长度上限：占位符最大长度 / 单通道缓冲区最大长度。
    pub fn with_limits(mut self, max_ph_len: usize, max_buf: usize) -> Self {
        self.max_ph_len = max_ph_len.max(16);
        self.max_buf = max_buf.max(1024);
        self
    }

    /// 是否发生过缓冲熔断（调用方据此输出模糊占位符）。
    pub fn take_overflow(&mut self) -> bool {
        std::mem::take(&mut self.overflowed)
    }

    /// 当前累计的还原计数。
    pub fn stats(&self) -> RestoreStats {
        self.stats
    }

    /// 某通道是否还挂着未确认的尾巴（用于收尾补发判断）。
    pub fn has_pending(&self, channel: &str) -> bool {
        self.pending
            .get(channel)
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    }

    /// 喂入一段文本，按本会话映射还原（默认通道，非转义）。
    pub fn feed(&mut self, chunk: &str) -> String {
        let vault = self.vault.clone();
        let session = self.session.clone();
        self.feed_channel(DEFAULT_CHANNEL, chunk, false, |ph| {
            match vault.resolve(&session, ph) {
                Some(orig) => ResolveOutcome::Restored(orig),
                None => ResolveOutcome::Unknown,
            }
        })
    }

    /// 喂入一段文本，使用外部解析策略（默认通道，非转义）。
    pub fn feed_with<F>(&mut self, chunk: &str, resolve: F) -> String
    where
        F: FnMut(&str) -> ResolveOutcome,
    {
        self.feed_channel(DEFAULT_CHANNEL, chunk, false, resolve)
    }

    /// 按通道喂入一段文本。`escape=true` 表示该位置是 JSON 字符串内部。
    pub fn feed_channel<F>(
        &mut self,
        channel: &str,
        text: &str,
        escape: bool,
        mut resolve: F,
    ) -> String
    where
        F: FnMut(&str) -> ResolveOutcome,
    {
        let buf = self.pending.entry(channel.to_string()).or_default();
        // 缓冲熔断：宁可少输出，也不无限缓冲
        if buf.len() + text.len() > self.max_buf {
            buf.clear();
            self.overflowed = true;
            return String::new();
        }
        buf.push_str(text);

        let cut = buf.len() - partial_tail_len(buf, self.max_ph_len);
        if cut == 0 {
            return String::new();
        }
        let confirmed: String = buf[..cut].to_string();
        buf.drain(..cut);

        let stats = &mut self.stats;
        replace_all_forms(&confirmed, escape, &mut resolve, stats)
    }

    /// 处理一段文本并**立即输出**（final 语义，不扣留尾部）。
    /// 用于完整快照事件与整段模式：这些场景的文本已经到齐，不存在跨帧半截。
    /// 会先把该通道的历史残留拼接进来一并处理。
    pub fn feed_final<F>(&mut self, channel: &str, text: &str, escape: bool, mut resolve: F) -> String
    where
        F: FnMut(&str) -> ResolveOutcome,
    {
        let mut combined = self.pending.remove(channel).unwrap_or_default();
        if combined.len() + text.len() > self.max_buf {
            self.overflowed = true;
            return String::new();
        }
        combined.push_str(text);
        let stats = &mut self.stats;
        replace_all_forms(&combined, escape, &mut resolve, stats)
    }

    /// 流结束：把某通道残留一次性吐出（final：不再等后续 chunk）。
    pub fn finish_channel<F>(&mut self, channel: &str, escape: bool, mut resolve: F) -> String
    where
        F: FnMut(&str) -> ResolveOutcome,
    {
        let rest = match self.pending.remove(channel) {
            Some(r) if !r.is_empty() => r,
            _ => return String::new(),
        };
        let stats = &mut self.stats;
        replace_all_forms(&rest, escape, &mut resolve, stats)
    }

    /// 流结束时调用：吐出全部通道的残留缓冲（**不做还原**，兼容旧调用方）。
    /// 需要按形态还原残留时请改用 [`finish_channel`](Self::finish_channel)。
    pub fn finish(&mut self) -> String {
        let mut out = String::new();
        let mut keys: Vec<String> = self.pending.keys().cloned().collect();
        keys.sort();
        for k in keys {
            if let Some(v) = self.pending.remove(&k) {
                out.push_str(&v);
            }
        }
        out
    }
}

/// 三层形态替换：严格/转义 → 宽松。查不到原文一律原样保留并计数。
fn replace_all_forms<F>(text: &str, escape: bool, resolve: &mut F, stats: &mut RestoreStats) -> String
where
    F: FnMut(&str) -> ResolveOutcome,
{
    // ── 第一遍：严格 + 转义形态 ──
    let out = rx_strict()
        .replace_all(text, |caps: &Captures| {
            let whole = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            let canonical = canonical_of(caps);
            match resolve(&canonical) {
                ResolveOutcome::Restored(orig) => {
                    stats.restored += 1;
                    if whole != canonical {
                        // 靠形态容错（反斜杠转义）救回
                        stats.degraded += 1;
                    }
                    emit(&orig, escape)
                }
                ResolveOutcome::RestoredDegraded(orig) => {
                    stats.restored += 1;
                    stats.degraded += 1;
                    emit(&orig, escape)
                }
                ResolveOutcome::Blocked(marker) => {
                    stats.blocked += 1;
                    marker
                }
                ResolveOutcome::Unknown => {
                    stats.unresolved += 1;
                    whole.to_string()
                }
            }
        })
        .into_owned();

    if !out.contains("PII:") {
        return out;
    }

    // ── 第二遍：宽松形态（模型把方括号剥掉）──
    // 只认「查得到原文」的 token，且要求前后无 word 字符边界，绝不猜。
    let src = out;
    rx_loose()
        .replace_all(&src, |caps: &Captures| {
            let m = match caps.get(0) {
                Some(m) => m,
                None => return String::new(),
            };
            let whole = m.as_str();
            // 严格形态已由第一遍处理（无论成功或原样保留），跳过避免重复计数
            let bare: String = whole.chars().filter(|c| *c != '\\').collect();
            if bare.starts_with("[[") && bare.ends_with("]]") {
                return whole.to_string();
            }
            // 边界保护：前后紧邻 word 字符说明只是被切开的残片，不能替换
            let before = src[..m.start()].chars().next_back();
            let after = src[m.end()..].chars().next();
            if is_word_char(before) || is_word_char(after) {
                return whole.to_string();
            }
            let canonical = canonical_of(caps);
            match resolve(&canonical) {
                ResolveOutcome::Restored(orig) | ResolveOutcome::RestoredDegraded(orig) => {
                    stats.restored += 1;
                    stats.degraded += 1;
                    emit(&orig, escape)
                }
                ResolveOutcome::Blocked(marker) => {
                    stats.blocked += 1;
                    marker
                }
                ResolveOutcome::Unknown => {
                    stats.unresolved += 1;
                    whole.to_string()
                }
            }
        })
        .into_owned()
}

/// 由正则捕获组重建规范占位符 `[[PII:TAG:hex]]`（查询用）。
fn canonical_of(caps: &Captures) -> String {
    let tag = caps.get(1).map(|m| m.as_str()).unwrap_or("");
    let hex = caps.get(2).map(|m| m.as_str()).unwrap_or("");
    format!(
        "{}{}:{}{}",
        PLACEHOLDER_PREFIX,
        tag.to_ascii_uppercase(),
        hex.to_ascii_lowercase(),
        PLACEHOLDER_SUFFIX
    )
}

fn emit(orig: &str, escape: bool) -> String {
    if escape {
        json_escape_inside(orig)
    } else {
        orig.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;

    fn setup() -> (Arc<Vault>, String) {
        let vault = Arc::new(Vault::new());
        let ph = vault.get_or_create("s", "13800138000", "PHONE");
        (vault, ph)
    }

    #[test]
    fn test_complete_placeholder_single_chunk() {
        let (vault, ph) = setup();
        let mut r = StreamingRestorer::new(vault.clone(), "s");
        let out = r.feed(&format!("结果:{}", ph));
        assert_eq!(out, "结果:13800138000");
        assert_eq!(r.finish(), "");
        assert_eq!(r.stats().restored, 1);
    }

    #[test]
    fn test_placeholder_split_across_3_chunks() {
        let (vault, ph) = setup();
        let bytes = ph.as_bytes();
        let c1 = String::from_utf8(bytes[..6].to_vec()).unwrap();
        let c2 = String::from_utf8(bytes[6..12].to_vec()).unwrap();
        let c3 = String::from_utf8(bytes[12..].to_vec()).unwrap();
        let mut r = StreamingRestorer::new(vault.clone(), "s");
        let o1 = r.feed(&c1);
        assert_eq!(o1, "", "前缀被拆开时第一段不应输出");
        let o2 = r.feed(&c2);
        assert_eq!(o2, "", "中间段仍不应输出");
        let o3 = r.feed(&c3);
        assert_eq!(format!("{}{}{}", o1, o2, o3), "13800138000");
    }

    #[test]
    fn test_partial_prefix_held_back() {
        let (vault, ph) = setup();
        let mut r = StreamingRestorer::new(vault.clone(), "s");
        let o1 = r.feed("hello [");
        assert_eq!(o1, "hello ", "'[' 不应被提前输出");
        let o2 = r.feed(&format!("[{}", ph));
        assert_eq!(format!("{}{}", o1, o2), "hello [[13800138000");
    }

    #[test]
    fn test_unclosed_prefix_flushed_after_max_len() {
        let vault = Arc::new(Vault::new());
        let mut r = StreamingRestorer::new(vault, "s");
        let long_payload = "x".repeat(200);
        let o1 = r.feed(&format!("[[PII:{}", long_payload));
        assert!(o1.starts_with("[[PII:"), "超长未闭合前缀应原样输出");
        assert!(o1.contains("xxx"), "payload 也应输出");
        let o2 = r.feed(&format!("{}tail", long_payload));
        assert!(o2.contains("tail"), "后续内容正常输出");
    }

    #[test]
    fn test_unknown_placeholder_passthrough() {
        let vault = Arc::new(Vault::new());
        let mut r = StreamingRestorer::new(vault, "s");
        let out = r.feed("前 [[PII:FAKE:deadbeef]] 后");
        assert_eq!(out, "前 [[PII:FAKE:deadbeef]] 后", "未知占位符原样输出");
        assert_eq!(r.stats().unresolved, 1, "未还原必须计数且不重复计数");
    }

    #[test]
    fn test_two_placeholders_in_one_chunk() {
        let (vault, ph) = setup();
        let ph2 = vault.get_or_create("s", "user@example.com", "EMAIL");
        let mut r = StreamingRestorer::new(vault, "s");
        let out = r.feed(&format!("A{}B{}C", ph, ph2));
        assert_eq!(out, "A13800138000Buser@example.comC");
    }

    #[test]
    fn test_chinese_passthrough_split() {
        let vault = Arc::new(Vault::new());
        let mut r = StreamingRestorer::new(vault, "s");
        let o1 = r.feed("你好世");
        let o2 = r.feed("界");
        assert_eq!(format!("{}{}", o1, o2), "你好世界");
    }

    #[test]
    fn test_finish_flushes_remainder() {
        let (vault, _ph) = setup();
        let mut r = StreamingRestorer::new(vault, "s");
        r.feed("结尾 [[PI");
        let rest = r.finish();
        assert_eq!(rest, "[[PI", "finish 应吐出残留缓冲");
        let (vault2, ph2) = setup();
        let mut r2 = StreamingRestorer::new(vault2, "s");
        r2.feed(&ph2);
        assert_eq!(r2.finish(), "");
    }

    // ─────────── 通道隔离 ───────────

    #[test]
    fn test_channel_isolation_no_crosstalk() {
        let (vault, ph) = setup();
        let mut r = StreamingRestorer::new(vault, "s");
        let half = &ph[..14];
        let o1 = r.feed_channel("content:0", half, false, |_| ResolveOutcome::Unknown);
        assert_eq!(o1, "", "半截应被扣留");
        assert!(r.has_pending("content:0"));
        // 另一个通道来一段新文本：不得把 content 通道的尾巴拼进来
        let o2 = r.feed_channel("args:0", "{\"a\":1}", true, |_| ResolveOutcome::Unknown);
        assert_eq!(o2, "{\"a\":1}", "通道之间不得串扰: {}", o2);
        // content 通道补齐后正常还原
        let o3 = r.feed_channel("content:0", &ph[14..], false, |_| {
            ResolveOutcome::Restored("13800138000".to_string())
        });
        assert_eq!(o3, "13800138000");
    }

    #[test]
    fn test_finish_channel_restores_leftover() {
        let (vault, ph) = setup();
        let hex = ph[ph.rfind(':').unwrap() + 1..ph.len() - 2].to_string();
        let mut r = StreamingRestorer::new(vault, "s");
        // 无方括号的宽松形态：必须扣留等待可能到来的 "]]"
        let bare = format!("PII:PHONE:{}", hex);
        let o1 = r.feed_channel("content:0", &bare, false, |_| ResolveOutcome::Unknown);
        assert_eq!(o1, "", "无方括号形态需等待后续数据");
        assert!(r.has_pending("content:0"));
        // 流到此结束：残留必须还原后吐出
        let rest = r.finish_channel("content:0", false, |_| {
            ResolveOutcome::Restored("13800138000".to_string())
        });
        assert_eq!(rest, "13800138000");
        assert!(!r.has_pending("content:0"));
    }

    #[test]
    fn test_unresolved_partial_leftover_preserved() {
        // 真正还原不了的半截形态在流结束时必须原样吐出：不丢字、不编造
        let vault = Arc::new(Vault::new());
        let mut r = StreamingRestorer::new(vault, "s");
        let o1 = r.feed("tail [[PII:PHONE:");
        assert_eq!(o1, "tail ");
        assert_eq!(r.finish(), "[[PII:PHONE:");
    }

    // ─────────── 形态容错 ───────────

    #[test]
    fn test_escaped_form_restored() {
        let (vault, ph) = setup();
        let hex = ph[ph.rfind(':').unwrap() + 1..ph.len() - 2].to_string();
        let mut r = StreamingRestorer::new(vault, "s");
        let escaped = format!(r"\[\[PII:PHONE:{}]]", hex);
        let out = r.feed(&escaped);
        assert_eq!(out, "13800138000", "转义形态必须能还原: {}", out);
        assert_eq!(r.stats().degraded, 1, "靠容错救回要计入 degraded");
    }

    #[test]
    fn test_loose_form_restored() {
        let (vault, ph) = setup();
        let hex = ph[ph.rfind(':').unwrap() + 1..ph.len() - 2].to_string();
        let mut r = StreamingRestorer::new(vault, "s");
        let out = r.feed(&format!("见 PII:PHONE:{} 处", hex));
        assert_eq!(out, "见 13800138000 处", "剥掉方括号的形态必须能还原: {}", out);
        assert!(r.stats().degraded >= 1);
    }

    #[test]
    fn test_loose_form_respects_word_boundary() {
        let vault = Arc::new(Vault::new());
        let mut r = StreamingRestorer::new(vault, "s");
        let out = r.feed("xxPII:PHONE:8f3a2b1cxx");
        assert_eq!(out, "xxPII:PHONE:8f3a2b1cxx", "残片不得被替换: {}", out);
    }

    #[test]
    fn test_suffix_fallback_via_resolve() {
        let (vault, _ph) = setup();
        let mut r = StreamingRestorer::new(vault, "s");
        let out = r.feed_with("[[PII:MOBILE:deadbeef]]", |_| {
            ResolveOutcome::RestoredDegraded("13900139000".to_string())
        });
        assert_eq!(out, "13900139000");
        assert_eq!(r.stats().degraded, 1);
    }

    // ─────────── JSON 转义（真问题 1） ───────────

    #[test]
    fn test_escape_json_string_on_restore() {
        let vault = Arc::new(Vault::new());
        let orig = "say \"hi\"\nline2";
        let mut r = StreamingRestorer::new(vault, "s");
        let out = r.feed_channel(
            "args:0",
            "{\"sql\":\"[[PII:TEXT:8f3a2b1c]]\"}",
            true,
            |_| ResolveOutcome::Restored(orig.to_string()),
        );
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&out);
        assert!(parsed.is_ok(), "还原后必须是合法 JSON: {}", out);
        assert!(out.contains("\\\"hi\\\""), "引号必须被转义: {}", out);
        assert!(!out.contains('\n'), "换行必须被转义: {}", out);
    }

    #[test]
    fn test_no_escape_for_plain_text_channel() {
        let vault = Arc::new(Vault::new());
        let mut r = StreamingRestorer::new(vault, "s");
        let out = r.feed_channel("content:0", "x[[PII:TEXT:8f3a2b1c]]y", false, |_| {
            ResolveOutcome::Restored("a\"b".to_string())
        });
        assert_eq!(out, "xa\"by", "正文通道不应做 JSON 转义: {}", out);
    }

    // ─────────── 安全兜底 ───────────

    #[test]
    fn test_feed_with_blocked_outcome() {
        let vault = Arc::new(Vault::new());
        let mut r = StreamingRestorer::new(vault, "s");
        let out = r.feed_with("x [[PII:IDCARD:abcdef12]] y", |_| {
            ResolveOutcome::Blocked("[BLOCKED]".to_string())
        });
        assert_eq!(out, "x [BLOCKED] y");
        assert!(!out.contains("IDCARD"));
        assert_eq!(r.stats().blocked, 1);
    }

    #[test]
    fn test_buffer_overflow_fuses() {
        let vault = Arc::new(Vault::new());
        let mut r = StreamingRestorer::new(vault, "s").with_limits(64, 1024);
        let out = r.feed(&"a".repeat(4096));
        assert_eq!(out, "", "熔断时应不输出任何内部缓冲内容");
        assert!(r.take_overflow(), "熔断标记必须置位");
        assert!(!r.take_overflow(), "标记读取后应清除");
        let out2 = r.feed("ok");
        assert_eq!(out2, "ok");
    }

    #[test]
    fn test_is_pii_placeholder() {
        assert!(is_pii_placeholder("[[PII:PHONE:12345678]]"));
        assert!(!is_pii_placeholder("[[PII:"));
        assert!(!is_pii_placeholder("[[NOTPII:12345678]]"));
        assert!(!is_pii_placeholder("plain"));
    }
}
