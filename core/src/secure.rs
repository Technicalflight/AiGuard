//! 响应**还原**管道 + 审计上下文采集。
//!
//! 本模块只做两件事：
//! 1. **还原**：把模型响应里的占位符换回原文。结构化优先（帧负载能解析成 JSON 时
//!    按「文本槽位」还原，正文与工具参数各占一个通道），退化为整树还原，再退化为
//!    文本级还原；三层形态容错 + JSON 字符串转义 + 收尾补发见 [`crate::stream`]；
//! 2. **采集**：把审计所需的材料收集起来交给调用方——还原后的文本、SSE 事件视图、
//!    响应 model 字段。
//!
//! **本模块不改写、不阻断任何响应**：安全判断全部在 [`crate::audit`] 里以「只输出
//! 发现」的形式完成，由调用方决定如何处置。熔断（缓冲超限）只丢弃内容并置标志，
//! 不向响应里注入任何标记。

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::SseEventView;
use crate::sse::{event_prefix, get_slot, key_needs_escape, set_slot, text_slots, SseFrame, SseGate};
use crate::stream::{ResolveOutcome, StreamingRestorer, DEFAULT_CHANNEL};
use crate::vault::{placeholder_suffix, Vault};

/// 只为审计保留的还原后文本上限（字节）：超过即不再累积（防大响应吃内存）。
pub const AUDIT_TEXT_KEEP_MAX: usize = 256 * 1024;
/// 采集的 SSE 事件视图上限（防事件数爆炸）。
pub const AUDIT_EVENTS_MAX: usize = 5000;
/// 整树递归深度上限。
const MAX_TREE_DEPTH: usize = 24;

/// 还原管道参数。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RestoreLimits {
    /// 单段缓冲上限（字节）：超过即熔断丢弃
    pub max_buffer_size: usize,
    /// 占位符最大长度（字节）：`[[PII:` 之后超过此长度仍无 `]]` 就按普通文本处理
    pub max_placeholder_len: usize,
    /// 会话映射空闲过期（秒）：后台清理任务的依据
    pub session_ttl_secs: u64,
    /// 流结束即清理该会话映射（多轮对话场景应关闭）
    pub clear_session_on_stream_end: bool,
}

impl Default for RestoreLimits {
    fn default() -> Self {
        RestoreLimits {
            max_buffer_size: 1 << 20,
            max_placeholder_len: 128,
            session_ttl_secs: 30 * 60,
            clear_session_on_stream_end: false,
        }
    }
}

/// 管道产出：交给调用方做审计扫描 / 落库。
#[derive(Debug, Clone, Default)]
pub struct AuditContext {
    /// 还原后的模型输出文本（正文 + 思维链 + 工具参数），供报错泄密 / 响应夹带 / 记忆残留 / 高危指令扫描
    pub restored_text: String,
    /// SSE 事件视图，供流式异常扫描
    pub sse_events: Vec<SseEventView>,
    /// 响应里的 model 字段，供模型偷换对比
    pub response_model: Option<String>,
    /// 成功还原的占位符数（仅日志用）
    pub restored: usize,
    /// 未还原的占位符数（仅日志用，说明用户会看到占位符）
    pub unresolved: usize,
    /// 靠形态容错救回的数量（仅日志用）
    pub degraded: usize,
    /// 采集是否被上限截断
    pub truncated: bool,
    /// 是否发生过缓冲熔断
    pub overflowed: bool,
}

impl AuditContext {
    fn push_text(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        if self.restored_text.len() + s.len() > AUDIT_TEXT_KEEP_MAX {
            self.truncated = true;
            return;
        }
        self.restored_text.push_str(s);
    }

    fn push_event(&mut self, ev: SseEventView) {
        if self.sse_events.len() < AUDIT_EVENTS_MAX {
            self.sse_events.push(ev);
        }
    }

    fn set_model(&mut self, m: Option<&str>) {
        if self.response_model.is_none() {
            if let Some(v) = m {
                if !v.trim().is_empty() {
                    self.response_model = Some(v.to_string());
                }
            }
        }
    }
}

/// 响应还原管道。
pub struct ResponsePipeline {
    inner: StreamingRestorer,
    /// `Some` = SSE 模式（切帧）；`None` = 整段模式（非流式响应）
    gate: Option<SseGate>,
    vault: Arc<Vault>,
    session: String,
    ctx: AuditContext,
    /// channel -> (event 前缀, 该通道最后一个事件的 JSON)，收尾补发残留文本时做模板
    flush_tmpl: HashMap<String, (String, String)>,
    /// channel -> 该位置是否为 JSON 字符串内部
    channel_escape: HashMap<String, bool>,
}

impl ResponsePipeline {
    /// SSE 流式模式。
    pub fn new(vault: Arc<Vault>, session: impl Into<String>, limits: &RestoreLimits) -> Self {
        let session = session.into();
        let inner = StreamingRestorer::new(vault.clone(), session.clone())
            .with_limits(limits.max_placeholder_len, limits.max_buffer_size);
        ResponsePipeline {
            inner,
            gate: Some(SseGate::new(limits.max_buffer_size.max(4096))),
            vault,
            session,
            ctx: AuditContext::default(),
            flush_tmpl: HashMap::new(),
            channel_escape: HashMap::new(),
        }
    }

    /// 整段模式（非流式响应体）。
    pub fn raw(vault: Arc<Vault>, session: impl Into<String>, limits: &RestoreLimits) -> Self {
        let mut p = Self::new(vault, session, limits);
        p.gate = None;
        p
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    /// 取出采集到的审计上下文。
    pub fn take_context(&mut self) -> AuditContext {
        let st = self.inner.stats();
        let mut ctx = std::mem::take(&mut self.ctx);
        ctx.restored = st.restored;
        ctx.unresolved = st.unresolved;
        ctx.degraded = st.degraded;
        ctx
    }

    /// 喂入一段文本，返回**还原后**的内容。
    pub fn feed(&mut self, chunk: &str) -> String {
        let gate = match self.gate.as_mut() {
            Some(g) => g,
            None => {
                // 整段模式：能解析 JSON 就走结构化（顺带把 \uXXXX 重排成明文，
                // 否则审计扫描会被转义序列的十六进制尾巴粘住数字边界而漏检）
                if let Ok(mut v) = serde_json::from_str::<Value>(chunk) {
                    if v.is_object() || v.is_array() {
                        self.restore_tree(&mut v, None, 0);
                        self.collect_tree_text(&v);
                        self.ctx.push_text(&v.to_string());
                        return serde_json::to_string(&v).unwrap_or_else(|_| chunk.to_string());
                    }
                }
                let restored = self.restore_text(chunk);
                self.ctx.push_text(&restored);
                return restored;
            }
        };

        let frames = gate.push(chunk);
        let mut out = String::new();
        for f in frames {
            out.push_str(&self.process_frame(f));
        }
        out
    }

    /// 流结束：冲刷残留帧并**收尾补发**滞留的半截占位符。
    pub fn finish(&mut self) -> String {
        let mut out = String::new();
        if let Some(g) = self.gate.as_mut() {
            if let Some(f) = g.flush() {
                out.push_str(&self.process_frame(f));
            }
        }
        out.push_str(&self.flush_pending());
        let leftover = self.inner.finish();
        if !leftover.is_empty() {
            self.ctx.push_text(&leftover);
            out.push_str(&leftover);
        }
        out
    }

    // ─────────────────────── 内部：帧处理 ───────────────────────

    fn process_frame(&mut self, frame: SseFrame) -> String {
        let payload = match frame.data.as_deref() {
            Some(p) if !p.trim().is_empty() => p,
            _ => {
                // 合法的非 data 帧（`event:` / `id:` / 注释）：原样返回
                if frame.valid {
                    return frame.raw.clone();
                }
                // 帧状态机因超限强制吐出的松散片段：按文本还原，不丢内容
                let restored = self.restore_text(&frame.raw);
                self.ctx.push_text(&restored);
                return restored;
            }
        };

        let mut data: Value = match serde_json::from_str(payload) {
            Ok(v) => v,
            Err(_) => {
                // 非法 JSON（分片未拼完 / 上游本来就发了非 JSON）：文本级还原
                let restored = self.restore_text(payload);
                self.ctx.push_text(&restored);
                return rebuild_data_frame(&frame.raw, &restored);
            }
        };
        if !data.is_object() {
            return frame.raw.clone();
        }

        // 采集事件视图（流式异常只看 type/usage/signature，与占位符无关，用原始值即可）
        let event_type = frame
            .raw
            .lines()
            .find_map(|l| l.trim_end_matches(['\r', '\n']).strip_prefix("event:").map(|s| s.trim().to_string()));
        self.ctx.push_event(SseEventView {
            event_type,
            data: data.clone(),
        });
        // 采集响应 model（OpenAI 顶层 / Anthropic message_start / Responses response）
        self.ctx.set_model(
            data.get("model")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    data.get("message")
                        .and_then(|m| m.get("model"))
                        .and_then(|v| v.as_str())
                })
                .or_else(|| {
                    data.get("response")
                        .and_then(|r| r.get("model"))
                        .and_then(|v| v.as_str())
                }),
        );

        let slots = text_slots(&data);
        if slots.is_empty() {
            // 非增量事件（message_start / content_block_start / response.completed …）
            // 是完整快照，整树还原；快照里不会有跨帧半截占位符，故不扣留
            self.restore_tree(&mut data, None, 0);
            self.collect_tree_text(&data);
        } else {
            for slot in &slots {
                let text = get_slot(&data, &slot.path).unwrap_or("").to_string();
                let (restored, _) = self.restore_channel(&slot.channel, &text, slot.escape);
                // **无条件写回**：为空说明这段文本被扣留等后续 chunk，必须置空，
                // 否则原始占位符会被原样下发（之后还会重复补发一次）
                set_slot(&mut data, &slot.path, &restored);
                self.ctx.push_text(&restored);
            }
        }

        // 快照型事件（整值替换）在还原后要丢弃该通道的陈旧尾巴，
        // 否则会把 delta 追加到 done 之后（重复文本 / 完成后再来 delta）
        if let Some(ty) = data.get("type").and_then(|v| v.as_str()) {
            let snapshot = match ty {
                "response.output_text.done" => Some("content:0"),
                "response.reasoning_text.done" => Some("reason:0"),
                "response.function_call_arguments.done" => Some("args:0"),
                _ => None,
            };
            if let Some(ch) = snapshot {
                let _ = self.finish_channel(ch, false);
                self.flush_tmpl.remove(ch);
            }
        }

        let new_payload = match serde_json::to_string(&data) {
            Ok(s) => s,
            Err(_) => payload.to_string(),
        };
        let rebuilt = rebuild_data_frame(&frame.raw, &new_payload);

        // 只有真的滞留了半截占位符时才记模板（正常路径零额外序列化）
        let pending_channels: Vec<String> = self
            .channel_escape
            .keys()
            .filter(|ch| self.inner.has_pending(ch))
            .cloned()
            .collect();
        for ch in pending_channels {
            let prefix = event_prefix(&rebuilt).unwrap_or_default();
            self.flush_tmpl.insert(ch, (prefix, new_payload.clone()));
        }

        rebuilt
    }

    /// 文本级还原（非法 JSON / 非 data 负载的兜底路径）。
    fn restore_text(&mut self, text: &str) -> String {
        let (out, _) = self.restore_channel(DEFAULT_CHANNEL, text, false);
        out
    }

    /// 按通道还原：精确命中 → 后缀容错 → 未知（原样保留，绝不算推）。
    /// 通道的 escape 状态在此统一登记（收尾补发 flush_pending 依赖）。
    /// 返回 (还原后文本, 是否触发缓冲熔断)。
    fn restore_channel(&mut self, channel: &str, text: &str, escape: bool) -> (String, bool) {
        self.channel_escape
            .insert(channel.to_string(), escape);
        let vault = self.vault.clone();
        let session = self.session.clone();
        let mut out = self
            .inner
            .feed_channel(channel, text, escape, |ph| resolve_one(&vault, &session, ph));
        let overflowed = self.inner.take_overflow();
        if overflowed {
            self.ctx.overflowed = true;
            // 熔断：丢弃的内容不回吐，也不注入任何标记（本管道不改写响应）
            out.clear();
        }
        (out, overflowed)
    }

    /// 把某通道滞留的残留一次性还原吐出（收尾补发前调用）。
    fn finish_channel(&mut self, channel: &str, escape: bool) -> String {
        let vault = self.vault.clone();
        let session = self.session.clone();
        self.inner
            .finish_channel(channel, escape, |ph| resolve_one(&vault, &session, ph))
    }

    /// 收尾：把各通道滞留的残留文本还原输出。
    ///
    /// 有模板的槽位通道**克隆同通道最后一个事件做模板**补发（直接裸拼会破坏
    /// SSE 结构，克隆真实事件才能保证客户端 SDK 的字段校验通过）；整树/文本
    /// 通道没有模板，退化为裸文本输出——绝不能丢字。
    fn flush_pending(&mut self) -> String {
        let channels: Vec<String> = self.channel_escape.keys().cloned().collect();
        let mut out = String::new();
        for channel in channels {
            if !self.inner.has_pending(&channel) {
                self.flush_tmpl.remove(&channel);
                continue;
            }
            let escape = self.channel_escape.get(&channel).copied().unwrap_or(false);
            let restored = self.finish_channel(&channel, escape);
            if restored.is_empty() {
                self.flush_tmpl.remove(&channel);
                continue;
            }
            self.ctx.push_text(&restored);
            match self.flush_tmpl.remove(&channel) {
                Some((prefix, tmpl_json)) => match build_flush_event(&prefix, &tmpl_json, &channel, &restored) {
                    Some(evt) => out.push_str(&evt),
                    // 没有可用模板：退化为裸文本，至少不丢字
                    None => out.push_str(&restored),
                },
                // 无模板通道（整树 / 文本级）：裸文本输出
                None => out.push_str(&restored),
            }
        }
        out
    }

    /// 整树还原：字符串叶子逐个送入**流式通道**还原（工具参数字段按 JSON 转义）。
    ///
    /// 必须用流式通道（feed_channel）而不是一次性 feed_final：私有增量格式
    /// （如 DeepSeek 网页的 `data:{"v":"片段"}`）每帧只含增量片段，占位符可能被
    /// 拆在多帧之间——只有通道的跨帧扣留才能把它们拼齐还原。
    /// 同名字段（如连续的 `v` 帧）在通道内按序拼接，语义正确；完整快照事件
    /// 的叶子值本身完整，无 pending 残留。
    fn restore_tree(&mut self, v: &mut Value, key_hint: Option<&str>, depth: usize) {
        if depth > MAX_TREE_DEPTH {
            return;
        }
        match v {
            Value::String(s) => {
                let escape = key_hint.map(key_needs_escape).unwrap_or(false);
                let channel = format!("tree:{}", key_hint.unwrap_or("raw"));
                let old = std::mem::take(s);
                // 流式通道：跨帧扣留 + 溢出熔断都在 restore_channel 内统一处理。
                // 扣留（new 为空）时叶子必须置空——若把原值放回，残片会先原样发给
                // 客户端、拼接还原后原文又输出一遍，产生「残片+原文」双重混合体。
                // 仅在真熔断（缓冲溢出丢字）时才放回原值防丢字。
                let (new, overflowed) = self.restore_channel(&channel, &old, escape);
                *s = if overflowed && !old.is_empty() { old } else { new };
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.restore_tree(item, key_hint, depth + 1);
                }
            }
            Value::Object(map) => {
                let keys: Vec<String> = map.keys().cloned().collect();
                for k in keys {
                    if let Some(child) = map.get_mut(&k) {
                        self.restore_tree(child, Some(&k), depth + 1);
                    }
                }
            }
            _ => {}
        }
    }

    /// 把整树里的字符串叶子拼成审计文本（响应夹带 / 高危指令要扫的是模型实际输出的内容）。
    fn collect_tree_text(&mut self, v: &Value) {
        match v {
            Value::String(s) => self.ctx.push_text(s),
            Value::Array(arr) => {
                for item in arr {
                    self.collect_tree_text(item);
                }
            }
            Value::Object(map) => {
                for (k, child) in map {
                    // 只收集承载内容的字段，跳过协议字段
                    if matches!(
                        k.as_str(),
                        "usage"
                            | "id"
                            | "model"
                            | "type"
                            | "object"
                            | "created"
                            | "system_fingerprint"
                            | "role"
                            | "index"
                            | "stop_reason"
                            | "stop_sequence"
                            | "finish_reason"
                    ) {
                        continue;
                    }
                    self.collect_tree_text(child);
                }
            }
            _ => {}
        }
    }
}

/// 占位符解析：本会话精确命中 → 后缀容错（唯一候选）→ 未知。
fn resolve_one(vault: &Vault, session: &str, ph: &str) -> ResolveOutcome {
    if let Some(orig) = vault.resolve(session, ph) {
        return ResolveOutcome::Restored(orig);
    }
    if let Some(sfx) = placeholder_suffix(ph) {
        if let Some(real) = vault.lookup_by_suffix(&sfx) {
            if real != ph {
                if let Some(orig) = vault.resolve(session, &real) {
                    return ResolveOutcome::RestoredDegraded(orig);
                }
            }
        }
    }
    ResolveOutcome::Unknown
}

// ─────────────────────── 帧文本工具函数 ───────────────────────

/// 从 SSE 帧原文中取出 `data:` 负载（多行以 `\n` 连接）。
pub fn extract_data_payload(raw: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for line in raw.split_inclusive('\n') {
        let t = line.trim_end_matches('\n').trim_end_matches('\r');
        if let Some(rest) = t.strip_prefix("data:") {
            parts.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
        }
    }
    parts.join("\n")
}

/// 用新的负载替换帧里的 `data:` 行，其余行（`event:` / `id:` / 注释）原样保留。
fn rebuild_data_frame(raw: &str, new_payload: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut replaced = false;
    for line in raw.split_inclusive('\n') {
        let t = line.trim_end_matches('\n').trim_end_matches('\r');
        if !replaced && t.starts_with("data:") {
            out.push_str("data: ");
            out.push_str(new_payload);
            out.push('\n');
            replaced = true;
        } else {
            out.push_str(line);
        }
    }
    if !replaced {
        return raw.to_string();
    }
    out
}

/// 克隆模板事件，只保留该通道的残留文本后重新封装成一条 SSE 事件。
fn build_flush_event(
    event_prefix: &str,
    tmpl_json: &str,
    channel: &str,
    leftover: &str,
) -> Option<String> {
    let mut data: Value = serde_json::from_str(tmpl_json).ok()?;
    if !data.is_object() {
        return None;
    }
    let slots = text_slots(&data);
    let mut hit = false;
    for slot in &slots {
        if slot.channel == channel {
            if set_slot(&mut data, &slot.path, leftover) {
                hit = true;
            }
        } else {
            // 其余槽位清空，避免重复下发同一段文本
            set_slot(&mut data, &slot.path, "");
        }
    }
    if !hit {
        return None;
    }
    if let Some(choices) = data.get_mut("choices").and_then(|v| v.as_array_mut()) {
        for c in choices.iter_mut() {
            if let Some(o) = c.as_object_mut() {
                o.insert("finish_reason".to_string(), Value::Null);
            }
        }
    }
    let payload = serde_json::to_string(&data).ok()?;
    Some(format!("{}data: {}\n\n", event_prefix, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;

    fn limits() -> RestoreLimits {
        RestoreLimits::default()
    }

    fn pipe(vault: Arc<Vault>, session: &str) -> ResponsePipeline {
        ResponsePipeline::new(vault, session, &limits())
    }

    #[test]
    fn test_structured_slot_restore_and_collect() {
        let vault = Arc::new(Vault::new());
        let ph = vault.get_or_create("s", "13800138000", "PHONE");
        let mut p = pipe(vault, "s");
        let frame = format!(
            "data: {{\"model\":\"gpt-4o\",\"choices\":[{{\"delta\":{{\"content\":\"电话 {}\"}}}}]}}\n\n",
            ph
        );
        let out = p.feed(&frame);
        assert!(out.contains("13800138000"), "必须还原: {}", out);
        assert!(out.contains("data: "), "帧结构必须保留");
        let ctx = p.take_context();
        assert_eq!(ctx.response_model.as_deref(), Some("gpt-4o"));
        assert!(ctx.restored_text.contains("13800138000"), "采集到还原后文本");
        assert_eq!(ctx.sse_events.len(), 1);
        assert_eq!(ctx.restored, 1);
    }

    #[test]
    fn test_pipeline_never_modifies_semantics() {
        // 只告警不改写：管道输出必须是「还原后」的原样内容，不注入任何安全标记
        let vault = Arc::new(Vault::new());
        let mut p = pipe(vault, "s");
        let frame = "data: {\"choices\":[{\"delta\":{\"content\":\"<script>alert(1)</script> MARK_secret\"}}]}\n\n";
        let out = p.feed(frame);
        assert!(out.contains("<script>"), "不得剥离 HTML（只告警不改写）: {}", out);
        assert!(out.contains("MARK_secret"), "不得改写标记文本: {}", out);
    }

    #[test]
    fn test_text_level_fallback_for_non_json() {
        let vault = Arc::new(Vault::new());
        let ph = vault.get_or_create("s", "user@example.com", "EMAIL");
        let mut p = pipe(vault, "s");
        let out = p.feed(&format!("data: 联系 {} 谢谢\n\n", ph));
        assert!(out.contains("user@example.com"), "非法 JSON 也要还原: {}", out);
        assert!(p.take_context().restored_text.contains("user@example.com"));
    }

    #[test]
    fn test_raw_mode_restores_and_reorders_escapes() {
        let vault = Arc::new(Vault::new());
        let ph = vault.get_or_create("s", "user@example.com", "EMAIL");
        let mut p = ResponsePipeline::raw(vault, "s", &limits());
        // ensure_ascii 形态：中文被转义
        let body = format!("{{\"content\":\"\\u8054\\u7cfb {}\"}}", ph);
        let out = p.feed(&body);
        assert!(out.contains("user@example.com"), "整段模式要还原: {}", out);
        // 重新序列化后中文应变成明文（供审计扫描不受转义尾巴干扰）
        assert!(out.contains("联系"), "\\uXXXX 应重排为明文: {}", out);
    }

    #[test]
    fn test_channel_isolation() {
        let vault = Arc::new(Vault::new());
        let ph = vault.get_or_create("s", "13800138000", "PHONE");
        let mut p = pipe(vault.clone(), "s");
        // 正文槽位带半截占位符（被扣留）
        let half = &ph[..ph.len() - 2];
        let f1 = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n",
            half
        );
        assert_eq!(p.feed(&f1), "data: {\"choices\":[{\"delta\":{\"content\":\"\"}}]}\n\n");
        // 参数槽位的完整占位符应独立还原
        let f2 = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":\"{{\\\"p\\\":\\\"{}\\\"}}\"}}}}]}}}}]}}\n\n",
            ph
        );
        let out2 = p.feed(&f2);
        assert!(out2.contains("13800138000"), "参数通道独立还原: {}", out2);
    }

    #[test]
    fn test_deepseek_web_style_v_frames() {
        // DeepSeek 网页 SSE 形态：data:{"v":"增量"}（无空格、私有字段、无 model/type）。
        // 占位符被跨帧拆开（拆在 hex 中间）时也要在整树通道里还原。
        let vault = Arc::new(Vault::new());
        let ph = vault.get_or_create("s", "13822068066", "PHONE");
        assert!(ph.ends_with("]]"));
        // 拆分点：hex 第 5 位后（模拟 TCP 分片任意位置拆开）
        let cut = ph.len() - 10;
        let (head, tail) = (&ph[..cut], &ph[cut..]);
        let mut p = pipe(vault, "s");
        let f1 = format!("data:{{\"v\":\"你的电话号码显示为 {}\"}}\n\n", head);
        let f2 = format!("data:{{\"v\":\"{}，请确认。\"}}\n\n", tail);
        let out1 = p.feed(&f1);
        let out2 = p.feed(&f2);
        let ctx = p.take_context();
        let out = format!("{}{}", out1, out2);
        assert!(
            out.contains("13822068066"),
            "DeepSeek 网页帧形态必须还原: {}",
            out
        );
        assert!(!out.contains("[[PII:"), "不得残留占位符: {}", out);
        assert_eq!(ctx.restored, 1, "必须精确还原一次");
        assert_eq!(ctx.unresolved, 0);
    }

    #[test]
    fn test_deepseek_web_style_single_frame() {
        // 完整占位符在单帧内
        let vault = Arc::new(Vault::new());
        let ph = vault.get_or_create("s", "13822068066", "PHONE");
        let mut p = pipe(vault, "s");
        let out = p.feed(&format!("data:{{\"v\":\"号码是 {}。\"}}\n\n", ph));
        assert!(out.contains("13822068066"), "单帧整树还原: {}", out);
    }

    #[test]
    fn test_deepseek_realcase_end_to_end() {
        // 用户实测场景端到端：DeepSeek 会话在守护未生效窗口曾直连泄漏原文，
        // 服务端对话历史含原文 → 模型思考流会**同时复述**「本轮占位符」与「历史原文」。
        // 管道语义：占位符 → 还原原文；历史原文 → 原样透传；
        // 输出必须等于「对模型输出做线性占位符替换」的结果，绝不产生额外错位。
        let vault = Arc::new(Vault::new());
        let ph1 = vault.get_or_create("sess", "张三", "CUSTOM");
        let ph2 = vault.get_or_create("sess", "15611827034", "PHONE");
        let mut p = pipe(vault, "sess");

        // 模型思考输出（历史原文 + 本轮占位符混排，f1 尾部数字被帧边界切开）
        let f1 = format!(
            "data:{{\"v\":\"用户说你好，我叫{}张三，我的电话是{}15611\"}}\n\n",
            ph1, ph2
        );
        let f2 = "data:{\"v\":\"827034，请你告诉我，我的电话是多少？\"}\n\n";
        let out = format!("{}{}{}", p.feed(&f1), p.feed(&f2), p.finish());

        // 期望 = 对模型输出的线性占位符替换（管道必须透明）。
        // 管道输出是 SSE 帧结构，提取每帧的 v 值拼接后与线性替换结果精确对比。
        let model_text = format!(
            "用户说你好，我叫{}张三，我的电话是{}15611827034，请你告诉我，我的电话是多少？",
            ph1, ph2
        );
        let expected = model_text.replace(&ph1, "张三").replace(&ph2, "15611827034");
        let mut rendered = String::new();
        for line in out.lines() {
            if let Some(payload) = line.strip_prefix("data: ") {
                let v: Value = serde_json::from_str(payload).expect("帧必须是合法 JSON");
                rendered.push_str(v["v"].as_str().unwrap_or(""));
            }
        }
        assert_eq!(rendered, expected, "拼接后的可见文本必须等于线性替换结果");
        assert!(!rendered.contains("[[PII:"), "占位符必须全部还原: {}", rendered);
    }

    #[test]
    fn test_hold_frame_not_duplicated() {
        // 用户实测 bug 回归测试：跨帧占位符的「扣留帧」不得把残片原样下发——
        // 曾因熔断兜底把原值放回叶子，导致残片帧（原样）与还原帧（原文）
        // 先后输出，客户端拼接出「残片+原文」混合体。
        let vault = Arc::new(Vault::new());
        let ph = vault.get_or_create("sess", "张三", "CUSTOM");
        let cut = ph.len() - 10; // hex 中间拆开
        let mut p = pipe(vault, "sess");
        // 帧 1：占位符前缀（残缺尾）→ 必须整帧扣留（叶子置空）
        let f1 = format!("data:{{\"v\":\"用户说你好，我叫{}\"}}\n\n", &ph[..cut]);
        let out1 = p.feed(&f1);
        assert!(
            !out1.contains("[[PII:") && !out1.contains(&ph[..cut]),
            "扣留帧不得输出残片: {}",
            out1
        );
        // 帧 2：补全 + 历史原文引用（模型上下文含历史原文的场景）→ 还原 + 透传
        let f2 = format!(
            "data:{{\"v\":\"{}张三，你好\"}}\n\n",
            &ph[cut..]
        );
        let out2 = p.feed(&f2);
        let fin = p.finish();
        let all = format!("{}{}{}", out1, out2, fin);
        assert_eq!(
            all.matches("张三").count(),
            2,
            "恰好 = 还原 1 次 + 历史原文 1 次: {}",
            all
        );
        assert!(!all.contains("[[PII:"), "不得残留占位符: {}", all);
    }

    #[test]
    fn test_tool_args_json_escape() {
        let vault = Arc::new(Vault::new());
        let ph = vault.get_or_create("s", "say \"hi\"\nend", "TEXT");
        let mut p = pipe(vault, "s");
        let frame = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":\"{{\\\"q\\\":\\\"{}\\\"}}\"}}}}]}}}}]}}\n\n",
            ph
        );
        let out = p.feed(&frame);
        let payload = extract_data_payload(&out);
        let frame_json: Value = serde_json::from_str(&payload).expect("帧必须是合法 JSON");
        let args = frame_json["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .expect("arguments 应为字符串");
        let inner: Value = serde_json::from_str(args).expect("工具参数必须是合法 JSON");
        assert_eq!(inner["q"], "say \"hi\"\nend");
    }

    #[test]
    fn test_finish_clone_flush_event() {
        let vault = Arc::new(Vault::new());
        let ph = vault.get_or_create("s", "13900139000", "PHONE");
        let mut p = pipe(vault, "s");
        let hex = ph[ph.rfind(':').unwrap() + 1..ph.len() - 2].to_string();
        let bare = format!("PII:PHONE:{}", hex);
        let f1 = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":\"见 {}\"}}}}]}}\n\n",
            bare
        );
        let o1 = p.feed(&f1);
        assert!(!o1.contains("13900139000"), "扣留期间不应提前下发: {}", o1);
        let tail = p.finish();
        assert!(tail.contains("13900139000"), "补发帧必须带原文: {}", tail);
        assert!(tail.contains("data: "), "补发必须是完整事件: {}", tail);
        assert!(tail.ends_with("\n\n"), "补发帧必须以空行结束: {:?}", tail);
    }

    #[test]
    fn test_snapshot_discards_stale_delta() {
        // done 事件是整值替换：还原后要丢弃该通道的陈旧尾巴
        let vault = Arc::new(Vault::new());
        let mut p = pipe(vault, "s");
        let _ = p.feed(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial PII:PHONE:8f3a2b1c\"}\n\n",
        );
        let out = p.feed(
            "data: {\"type\":\"response.output_text.done\",\"text\":\"final text\"}\n\n",
        );
        assert!(out.contains("final text"), "{}", out);
        // 结束后补发不该再把陈旧尾巴吐出来
        let tail = p.finish();
        assert!(!tail.contains("8f3a2b1c"), "陈旧尾巴应被丢弃: {}", tail);
    }

    #[test]
    fn test_context_truncation_flag() {
        let vault = Arc::new(Vault::new());
        let mut p = pipe(vault, "s");
        let big = "a".repeat(AUDIT_TEXT_KEEP_MAX + 1000);
        let frame = format!("data: {{\"choices\":[{{\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n", big);
        let _ = p.feed(&frame);
        let ctx = p.take_context();
        assert!(ctx.truncated, "超限必须置截断标志");
        assert!(ctx.restored_text.len() <= AUDIT_TEXT_KEEP_MAX + 64);
    }

    #[test]
    fn test_overflow_does_not_inject_marker() {
        let vault = Arc::new(Vault::new());
        let mut l = limits();
        l.max_buffer_size = 4096;
        let mut p = ResponsePipeline::new(vault, "s", &l);
        let big = "a".repeat(9000);
        let out = p.feed(&big);
        assert!(!out.contains("[REDACTED]"), "管道不改写响应，不注入标记: {}", out);
    }

    #[test]
    fn test_suffix_fallback() {
        let vault = Arc::new(Vault::new());
        let ph = vault.get_or_create("s", "13800138000", "PHONE");
        let hex = ph[ph.rfind(':').unwrap() + 1..ph.len() - 2].to_string();
        let mut p = pipe(vault, "s");
        // 标签被模型改写，但保留了随机后缀
        let out = p.feed(&format!("data: [[PII:MOBILE:{}]]\n\n", hex));
        assert!(out.contains("13800138000"), "后缀容错应救回: {}", out);
    }

    #[test]
    fn test_unknown_placeholder_left_intact() {
        let vault = Arc::new(Vault::new());
        let mut p = pipe(vault, "s");
        let out = p.feed("data: 前 [[PII:FAKE:deadbeef]] 后\n\n");
        assert!(out.contains("[[PII:FAKE:deadbeef]]"), "未知占位符原样保留: {}", out);
        assert_eq!(p.take_context().unresolved, 1);
    }

    #[test]
    fn test_finish_empty_when_clean() {
        let vault = Arc::new(Vault::new());
        let ph = vault.get_or_create("s", "13800138000", "PHONE");
        let mut p = pipe(vault, "s");
        let _ = p.feed(&format!("data: {{\"choices\":[{{\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n", ph));
        assert_eq!(p.finish(), "");
    }
}
