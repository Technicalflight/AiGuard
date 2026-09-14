//! SSE 帧状态机（流式异常观察的实现载体）。
//!
//! 职责：
//! 1. 把 TCP 分片的原始字节流拼装为**完整 SSE 帧**（以空行 `\n\n` 或 `\r\n\r\n` 结尾）；
//! 2. 校验帧格式：每一行必须以 `data:` / `event:` / `id:` / `retry:` / `:` 起始，
//!    不符合规范的畸形帧一律标记为非法（由上层决定丢弃），防止畸形帧注入；
//! 3. 施加缓冲上限：未出现帧边界且缓冲超过 `max_backlog` 时，强制把当前内容作为
//!    松散片段吐出，避免无边界流（或恶意构造）把内存吃满。
//!
//! 本模块不做任何还原与净化，只负责「切帧 + 判合法」。

use serde_json::Value;

/// 帧的负载类型（供上层决定是否走结构化 JSON 校验）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameKind {
    /// 普通 `data:` 帧
    Data,
    /// 工具调用帧（`data:` 载荷中含 `tool_calls`）
    ToolCall,
    /// 结束标记（`data: [DONE]`）
    Done,
    /// 非 `data:` 帧（`event:` / `id:` / `retry:` 注释等）
    Other,
}

/// 一帧 SSE。
#[derive(Debug, Clone)]
pub struct SseFrame {
    /// 原始文本（含结尾空行）
    pub raw: String,
    /// `data:` 负载拼接结果（无 `data:` 行为 None）
    pub data: Option<String>,
    /// 负载类型
    pub kind: FrameKind,
    /// 是否通过 SSE 格式校验
    pub valid: bool,
}

/// 增量切帧器。
pub struct SseGate {
    buf: String,
    /// 缓冲上限（字节）：无边界可切时超过则强制吐出松散片段
    max_backlog: usize,
    /// 因超限被强制吐出的次数（上层记为流式异常观察）
    pub forced_flushes: usize,
    /// 是否已经出现过帧边界（用于识别「根本不是 SSE」的流）
    saw_boundary: bool,
}

impl SseGate {
    pub fn new(max_backlog: usize) -> Self {
        SseGate {
            buf: String::new(),
            max_backlog: max_backlog.max(1024),
            forced_flushes: 0,
            saw_boundary: false,
        }
    }

    /// 喂入一段文本，返回其中所有**完整**的帧。
    /// 末尾不完整的部分留在内部缓冲，等待下一次 `push`。
    pub fn push(&mut self, chunk: &str) -> Vec<SseFrame> {
        self.buf.push_str(chunk);
        let mut frames = Vec::new();
        loop {
            match find_boundary(&self.buf) {
                Some((idx, sep_len)) => {
                    let end = idx + sep_len;
                    let block: String = self.buf[..end].to_string();
                    self.buf.drain(..end);
                    self.saw_boundary = true;
                    frames.push(parse_frame(&block));
                }
                None => {
                    // 无帧边界且缓冲超限：若非 SSE（从未出现边界）或长度失控，
                    // 强制吐出，避免无限缓冲
                    if self.buf.len() > self.max_backlog {
                        self.forced_flushes += 1;
                        let block = std::mem::take(&mut self.buf);
                        frames.push(SseFrame {
                            data: None,
                            kind: FrameKind::Other,
                            valid: false,
                            raw: block,
                        });
                    }
                    break;
                }
            }
        }
        frames
    }

    /// 流结束：把残留缓冲作为最后一帧吐出（可能不完整）。
    pub fn flush(&mut self) -> Option<SseFrame> {
        if self.buf.is_empty() {
            return None;
        }
        let block = std::mem::take(&mut self.buf);
        Some(parse_frame(&block))
    }

    /// 是否观察到过帧边界（用于判断该流到底是不是 SSE）。
    pub fn saw_boundary(&self) -> bool {
        self.saw_boundary
    }

    pub fn pending_len(&self) -> usize {
        self.buf.len()
    }
}

/// 找到最早的帧分隔（`\n\n` 或 `\r\n\r\n`），返回 (起始下标, 分隔符长度)。
fn find_boundary(s: &str) -> Option<(usize, usize)> {
    let a = s.find("\n\n").map(|i| (i, 2usize));
    let b = s.find("\r\n\r\n").map(|i| (i, 4usize));
    match (a, b) {
        (Some(x), Some(y)) => {
            // 取更靠前的；位置相同时优先更长的分隔符
            if x.0 < y.0 || (x.0 == y.0 && x.1 > y.1) {
                Some(x)
            } else {
                Some(y)
            }
        }
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

/// 解析一个完整帧（block 含结尾空行）。
fn parse_frame(block: &str) -> SseFrame {
    let mut data_parts: Vec<&str> = Vec::new();
    let mut valid = true;
    let mut has_field = false;

    for line in block.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            has_field = true;
            data_parts.push(rest.strip_prefix(' ').unwrap_or(rest));
        } else if line.starts_with("event:")
            || line.starts_with("id:")
            || line.starts_with("retry:")
            || line.starts_with(':')
        {
            has_field = true;
        } else {
            // 不符合 SSE 字段规范
            valid = false;
        }
    }

    let (data, kind) = if data_parts.is_empty() {
        (None, FrameKind::Other)
    } else {
        let joined = data_parts.join("\n");
        let kind = if joined.trim() == "[DONE]" {
            FrameKind::Done
        } else if joined.contains("tool_calls") {
            FrameKind::ToolCall
        } else {
            FrameKind::Data
        };
        (Some(joined), kind)
    };

    SseFrame {
        raw: block.to_string(),
        data,
        kind,
        valid: valid && has_field,
    }
}

// ─────────────────────── 文本槽位（结构化还原） ───────────────────────

/// JSON 路径段：对象键或数组下标。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seg {
    Key(String),
    Idx(usize),
}

/// 帧内一个「可还原文本」的位置。
///
/// - `channel`：半截占位符按通道独立缓冲。正文增量与工具参数增量各占一个通道，
///   否则上一个字段没闭合的占位符会被拼进下一个字段（内容错位 / 吞字段）；
/// - `path`：写回时的定位路径；
/// - `escape`：该位置的字符串**本身是 JSON 文本**（`arguments` / `partial_json`），
///   还原进去的原文必须按 JSON 字符串规则转义，否则客户端解析工具参数直接失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSlot {
    pub channel: String,
    pub path: Vec<Seg>,
    pub escape: bool,
}

/// 需要按 JSON 字符串转义还原的字段名（其字符串内容是 JSON 文档）。
pub fn key_needs_escape(key: &str) -> bool {
    matches!(key, "arguments" | "partial_json")
}

fn push_slot(
    out: &mut Vec<TextSlot>,
    path: Vec<Seg>,
    channel: String,
    value: Option<&Value>,
    escape: bool,
) {
    if let Some(Value::String(s)) = value {
        if !s.is_empty() {
            out.push(TextSlot {
                channel,
                path,
                escape,
            });
        }
    }
}

/// 提取一帧负载里所有「增量文本槽位」。
///
/// 覆盖 OpenAI 兼容（`choices[].delta` 正文 / 思维链 / `tool_calls[].function.arguments`）、
/// Anthropic Messages（`content_block_delta.delta.text|partial_json|thinking`、
/// `content_block_start.content_block.text`）、Responses API（顶层 `delta` / `text`）
/// 与 Gemini `alt=sse`（`candidates[].content.parts[].text`）。
///
/// 返回空表示「没有已知的增量位置」，调用方应退回整树还原。
pub fn text_slots(data: &Value) -> Vec<TextSlot> {
    let mut out: Vec<TextSlot> = Vec::new();

    // ── OpenAI chat.completions 及兼容网关 ──
    if let Some(choices) = data.get("choices").and_then(|v| v.as_array()) {
        for (i, c) in choices.iter().enumerate() {
            // 旧版补全风格：choices[].text
            push_slot(
                &mut out,
                vec![
                    Seg::Key("choices".into()),
                    Seg::Idx(i),
                    Seg::Key("text".into()),
                ],
                format!("text:{}", i),
                c.get("text"),
                false,
            );
            for holder in ["delta", "message"] {
                let h = match c.get(holder) {
                    Some(h) => h,
                    None => continue,
                };
                let base = vec![
                    Seg::Key("choices".into()),
                    Seg::Idx(i),
                    Seg::Key(holder.into()),
                ];
                for (key, ch, esc) in [
                    ("content", format!("content:{}", i), false),
                    ("reasoning_content", format!("reason:{}", i), false),
                    ("reasoning", format!("reason:{}", i), false),
                ] {
                    let mut p = base.clone();
                    p.push(Seg::Key(key.into()));
                    push_slot(&mut out, p, ch, h.get(key), esc);
                }
                if let Some(tcs) = h.get("tool_calls").and_then(|v| v.as_array()) {
                    for (j, tc) in tcs.iter().enumerate() {
                        let idx = tc
                            .get("index")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(j as u64);
                        let args = tc.get("function").and_then(|f| f.get("arguments"));
                        let mut p = base.clone();
                        p.push(Seg::Key("tool_calls".into()));
                        p.push(Seg::Idx(j));
                        p.push(Seg::Key("function".into()));
                        p.push(Seg::Key("arguments".into()));
                        push_slot(&mut out, p, format!("args:{}", idx), args, true);
                    }
                }
            }
        }
    }

    // ── Anthropic Messages 流 ──
    if let Some(ty) = data.get("type").and_then(|v| v.as_str()) {
        let idx = data.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
        match ty {
            "content_block_delta" => {
                if let Some(d) = data.get("delta") {
                    for (key, ch, esc) in [
                        ("text", format!("content:{}", idx), false),
                        ("partial_json", format!("args:{}", idx), true),
                        ("thinking", format!("think:{}", idx), false),
                    ] {
                        push_slot(
                            &mut out,
                            vec![Seg::Key("delta".into()), Seg::Key(key.into())],
                            ch,
                            d.get(key),
                            esc,
                        );
                    }
                }
            }
            "content_block_start" => {
                if let Some(cb) = data.get("content_block") {
                    push_slot(
                        &mut out,
                        vec![
                            Seg::Key("content_block".into()),
                            Seg::Key("text".into()),
                        ],
                        format!("content:{}", idx),
                        cb.get("text"),
                        false,
                    );
                }
            }
            _ => {}
        }
    }

    // ── Responses API：顶层字符串增量 ──
    if let Some(Value::String(_)) = data.get("delta") {
        let esc = data
            .get("type")
            .and_then(|v| v.as_str())
            .map(|t| t.contains("function_call_arguments"))
            .unwrap_or(false);
        let ch = if esc {
            "args:0".to_string()
        } else {
            "content:0".to_string()
        };
        push_slot(&mut out, vec![Seg::Key("delta".into())], ch, data.get("delta"), esc);
    }
    if let Some(Value::String(_)) = data.get("text") {
        if data.get("type").is_some() {
            push_slot(
                &mut out,
                vec![Seg::Key("text".into())],
                "content:0".to_string(),
                data.get("text"),
                false,
            );
        }
    }

    // ── Gemini alt=sse ──
    if let Some(cands) = data.get("candidates").and_then(|v| v.as_array()) {
        for (i, c) in cands.iter().enumerate() {
            let parts = c
                .get("content")
                .and_then(|v| v.get("parts"))
                .and_then(|v| v.as_array());
            if let Some(parts) = parts {
                for (j, p) in parts.iter().enumerate() {
                    push_slot(
                        &mut out,
                        vec![
                            Seg::Key("candidates".into()),
                            Seg::Idx(i),
                            Seg::Key("content".into()),
                            Seg::Key("parts".into()),
                            Seg::Idx(j),
                            Seg::Key("text".into()),
                        ],
                        format!("gtext:{}:{}", i, j),
                        p.get("text"),
                        false,
                    );
                }
            }
        }
    }

    out
}

/// 按路径读取字符串槽位。
pub fn get_slot<'a>(data: &'a Value, path: &[Seg]) -> Option<&'a str> {
    let mut cur = data;
    for seg in path {
        cur = match seg {
            Seg::Key(k) => cur.get(k.as_str())?,
            Seg::Idx(i) => cur.get(*i)?,
        };
    }
    cur.as_str()
}

/// 按路径写回字符串槽位；路径失效或目标不是字符串时返回 false。
pub fn set_slot(data: &mut Value, path: &[Seg], v: &str) -> bool {
    let mut cur = data;
    for seg in path {
        cur = match seg {
            Seg::Key(k) => match cur.get_mut(k.as_str()) {
                Some(c) => c,
                None => return false,
            },
            Seg::Idx(i) => match cur.get_mut(*i) {
                Some(c) => c,
                None => return false,
            },
        };
    }
    if cur.is_string() {
        *cur = Value::String(v.to_string());
        true
    } else {
        false
    }
}

/// 从帧原文提取 `event:` 行（原样返回，含换行）。Anthropic / Responses 客户端依赖它判事件类型。
pub fn event_prefix(raw: &str) -> Option<String> {
    for line in raw.split_inclusive('\n') {
        let t = line.trim_end_matches('\n').trim_end_matches('\r');
        if t.starts_with("event:") {
            return Some(format!("{}\n", t));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_frame() {
        let mut g = SseGate::new(4096);
        let frames = g.push("data: {\"a\":1}\n\n");
        assert_eq!(frames.len(), 1);
        assert!(frames[0].valid);
        assert_eq!(frames[0].data.as_deref(), Some("{\"a\":1}"));
        assert_eq!(frames[0].kind, FrameKind::Data);
    }

    #[test]
    fn test_frame_split_across_chunks() {
        let mut g = SseGate::new(4096);
        assert!(g.push("data: {\"a\"").is_empty(), "半截帧不应吐出");
        let frames = g.push(":1}\n\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data.as_deref(), Some("{\"a\":1}"));
    }

    #[test]
    fn test_multiple_frames_one_chunk() {
        let mut g = SseGate::new(4096);
        let frames = g.push("data: a\n\ndata: b\n\ndata: [DONE]\n\n");
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[2].kind, FrameKind::Done);
    }

    #[test]
    fn test_crlf_boundary() {
        let mut g = SseGate::new(4096);
        let frames = g.push("data: x\r\n\r\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data.as_deref(), Some("x"));
    }

    #[test]
    fn test_malformed_frame_marked_invalid() {
        let mut g = SseGate::new(4096);
        let frames = g.push("GET / HTTP/1.1\r\nHost: evil\r\n\r\n");
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].valid, "非 SSE 字段行必须被判非法");
    }

    #[test]
    fn test_tool_call_frame_detected() {
        let mut g = SseGate::new(4096);
        let frames = g.push(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"{}\"}}]}}]}\n\n",
        );
        assert_eq!(frames[0].kind, FrameKind::ToolCall);
    }

    #[test]
    fn test_event_and_comment_frames_valid() {
        let mut g = SseGate::new(4096);
        let frames = g.push("event: ping\n\n: keep-alive\n\n");
        assert_eq!(frames.len(), 2);
        assert!(frames.iter().all(|f| f.valid));
        assert!(frames.iter().all(|f| f.data.is_none()));
    }

    #[test]
    fn test_backlog_guard_forces_flush() {
        let mut g = SseGate::new(1024);
        // 4096 字节、无帧边界的流 → 触发强制吐出，不无限缓冲
        let frames = g.push(&"x".repeat(4096));
        assert!(
            !frames.is_empty(),
            "无边界超长流必须强制吐出而不是无限缓冲"
        );
        assert!(g.forced_flushes >= 1);
        assert!(g.pending_len() < 4096);
    }

    #[test]
    fn test_flush_returns_tail() {
        let mut g = SseGate::new(4096);
        g.push("data: incomplete");
        let tail = g.flush().expect("残留应被吐出");
        assert_eq!(tail.data.as_deref(), Some("incomplete"));
        assert!(g.flush().is_none());
    }

    // ─────────── 文本槽位 ───────────

    #[test]
    fn test_text_slots_openai_delta() {
        let v: Value = serde_json::from_str(
            r#"{"choices":[{"delta":{"content":"hi","reasoning_content":"think"}}]}"#,
        )
        .unwrap();
        let slots = text_slots(&v);
        let chans: Vec<&str> = slots.iter().map(|s| s.channel.as_str()).collect();
        assert!(chans.contains(&"content:0"), "{:?}", chans);
        assert!(chans.contains(&"reason:0"), "{:?}", chans);
        assert!(slots.iter().all(|s| !s.escape));
    }

    #[test]
    fn test_text_slots_tool_args_need_escape() {
        let v: Value = serde_json::from_str(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":2,"function":{"arguments":"{\"a\""}}]}}]}"#,
        )
        .unwrap();
        let slots = text_slots(&v);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].channel, "args:2");
        assert!(slots[0].escape, "工具参数槽位必须转义");
    }

    #[test]
    fn test_text_slots_anthropic() {
        let v: Value = serde_json::from_str(
            r#"{"type":"content_block_delta","index":1,"delta":{"partial_json":"{\"q\""}}"#,
        )
        .unwrap();
        let slots = text_slots(&v);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].channel, "args:1");
        assert!(slots[0].escape);

        let v2: Value = serde_json::from_str(
            r#"{"type":"content_block_delta","index":0,"delta":{"text":"你好"}}"#,
        )
        .unwrap();
        let s2 = text_slots(&v2);
        assert_eq!(s2.len(), 1);
        assert_eq!(s2[0].channel, "content:0");
        assert!(!s2[0].escape);
    }

    #[test]
    fn test_text_slots_responses_and_gemini() {
        let r: Value =
            serde_json::from_str(r#"{"type":"response.output_text.delta","delta":"abc"}"#).unwrap();
        let sr = text_slots(&r);
        assert_eq!(sr.len(), 1);
        assert_eq!(sr[0].channel, "content:0");

        let ra: Value = serde_json::from_str(
            r#"{"type":"response.function_call_arguments.delta","delta":"{\"x\""}"#,
        )
        .unwrap();
        assert!(text_slots(&ra)[0].escape);

        let g: Value = serde_json::from_str(
            r#"{"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}"#,
        )
        .unwrap();
        let sg = text_slots(&g);
        assert_eq!(sg.len(), 1);
        assert_eq!(sg[0].channel, "gtext:0:0");
    }

    #[test]
    fn test_text_slots_empty_when_no_known_slot() {
        let v: Value = serde_json::from_str(r#"{"model":"gpt-4o","id":"x"}"#).unwrap();
        assert!(text_slots(&v).is_empty(), "无已知增量位置应返回空，交由整树还原");
    }

    #[test]
    fn test_slot_read_write_roundtrip() {
        let mut v: Value =
            serde_json::from_str(r#"{"choices":[{"delta":{"content":"old"}}]}"#).unwrap();
        let slots = text_slots(&v);
        assert_eq!(get_slot(&v, &slots[0].path), Some("old"));
        assert!(set_slot(&mut v, &slots[0].path, "new"));
        assert_eq!(get_slot(&v, &slots[0].path), Some("new"));
        // 路径失效
        let bad = vec![Seg::Key("nope".into())];
        assert!(!set_slot(&mut v, &bad, "x"));
        assert!(get_slot(&v, &bad).is_none());
    }

    #[test]
    fn test_event_prefix() {
        assert_eq!(
            event_prefix("event: content_block_delta\ndata: {}\n\n").as_deref(),
            Some("event: content_block_delta\n")
        );
        assert_eq!(event_prefix("data: {}\n\n"), None);
    }
}
