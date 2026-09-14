//! 原文 ↔ 占位符 映射表。
//!
//! - 仅存在于内存，进程退出即消失
//! - 以会话（session）隔离：同一原文在不同会话得到不同占位符
//! - 同一会话内同一原文 → 同一占位符（保证多轮对话中占位符一致）
//! - 每个会话带**空闲时间戳**，可按时长自动销毁（跨会话 / 跨请求的映射互不可见）
//! - **销毁即覆写**：映射被回收（TTL 到期 / 应急清空 / 流结束）时，原文与占位符
//!   两侧字典的键值都先做零化覆写再释放，避免原文残留在堆上（见 [`crate::mem`]）

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::mem::wipe_string;

/// 占位符前缀 / 后缀（与 stream 模块保持一致）。
pub const PLACEHOLDER_PREFIX: &str = "[[PII:";
pub const PLACEHOLDER_SUFFIX: &str = "]]";

/// 在途会话（请求已发出、响应未到）pin 的**硬上限**。
/// 超过此时长即使还 pin 着也强制回收：上游中途断连、连接被中间设备静默丢弃时
/// 响应可能永不到达，映射会带着原文永久驻留内存。
pub const PIN_HARD_LIMIT_SECS: u64 = 900;

/// 内存映射表：session -> 原文/占位符 双向字典。
pub struct Vault {
    /// session -> (原文 -> 占位符)
    forward: DashMap<String, HashMap<String, String>>,
    /// session -> (占位符 -> 原文)
    reverse: DashMap<String, HashMap<String, String>>,
    /// session -> 最近一次访问时间（TTL 清理依据）
    touched: DashMap<String, Instant>,
    /// session -> pin 时间（在途会话不被 TTL 清掉）
    pinned: DashMap<String, Instant>,
    /// 占位符后缀（8 位 hex）-> 占位符集合。
    /// 用于模型**改写标签但保留后缀**时的容错反查；只有一个候选时才算命中。
    suffix_index: DashMap<String, HashSet<String>>,
}

/// 从占位符字面量中取出 8 位 hex 后缀。
pub fn placeholder_suffix(ph: &str) -> Option<String> {
    let inner = ph
        .strip_prefix(PLACEHOLDER_PREFIX)?
        .strip_suffix(PLACEHOLDER_SUFFIX)?;
    let idx = inner.rfind(':')?;
    let sfx = &inner[idx + 1..];
    if sfx.is_empty() || !sfx.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(sfx.to_ascii_lowercase())
}

/// 取出某会话的整张映射表，**逐字段覆写**后释放（键值都可能含原文）。
fn wipe_session_map(store: &DashMap<String, HashMap<String, String>>, session: &str) {
    if let Some((mut key, mut map)) = store.remove(session) {
        wipe_string(&mut key);
        for (mut k, mut v) in map.drain() {
            wipe_string(&mut k);
            wipe_string(&mut v);
        }
    }
}

impl Vault {
    pub fn new() -> Vault {
        Vault {
            forward: DashMap::new(),
            reverse: DashMap::new(),
            touched: DashMap::new(),
            pinned: DashMap::new(),
            suffix_index: DashMap::new(),
        }
    }

    /// 把会话标记为「在途」：TTL 清理会跳过它（直到超过硬上限）。
    pub fn pin(&self, session: &str) {
        self.pinned.insert(session.to_string(), Instant::now());
    }

    /// 解除在途标记（响应结束 / 流结束）。
    pub fn unpin(&self, session: &str) {
        self.pinned.remove(session);
    }

    pub fn is_pinned(&self, session: &str) -> bool {
        self.pinned
            .get(session)
            .map(|t| t.elapsed().as_secs() < PIN_HARD_LIMIT_SECS)
            .unwrap_or(false)
    }

    /// 按后缀反查占位符：**只有一个候选时**才返回（歧义一律不猜）。
    pub fn lookup_by_suffix(&self, suffix: &str) -> Option<String> {
        let sfx = suffix.to_ascii_lowercase();
        let set = self.suffix_index.get(&sfx)?;
        if set.len() == 1 {
            set.iter().next().cloned()
        } else {
            None
        }
    }

    /// 记录一次会话访问（刷新 TTL）。
    pub fn touch(&self, session: &str) {
        self.touched.insert(session.to_string(), Instant::now());
    }

    /// 活跃会话数。
    pub fn session_total(&self) -> usize {
        self.reverse.len()
    }

    /// 全部会话 id 快照。
    pub fn session_ids(&self) -> Vec<String> {
        self.reverse.iter().map(|e| e.key().clone()).collect()
    }

    /// 空闲时间超过 `ttl` 的会话立即销毁；返回被销毁的会话 id 列表。
    /// **在途会话（已 pin）不会被清**——长生成可能超过 TTL，此时清掉会让响应侧
    /// 查不到映射，占位符原样漏给用户且不报错。超过硬上限仍强制回收。
    pub fn purge_expired(&self, ttl: Duration) -> Vec<String> {
        let now = Instant::now();
        let expired: Vec<String> = self
            .touched
            .iter()
            .filter(|e| {
                if now.duration_since(*e.value()) <= ttl {
                    return false;
                }
                if let Some(p) = self.pinned.get(e.key()) {
                    if now.duration_since(*p.value()) < Duration::from_secs(PIN_HARD_LIMIT_SECS) {
                        return false;
                    }
                }
                true
            })
            .map(|e| e.key().clone())
            .collect();
        for s in &expired {
            self.clear_session(s);
        }
        expired
    }

    /// 某会话的空闲时长（无记录时返回 None）。
    pub fn idle_for(&self, session: &str) -> Option<Duration> {
        self.touched.get(session).map(|t| t.elapsed())
    }

    /// 取得 `original` 在 `session` 内的占位符；不存在则创建。
    /// 同一 session 同一原文永远返回同一占位符。
    /// `tag` 为占位符标签（如 "PHONE"，自定义规则为用户定义标签）。
    pub fn get_or_create(&self, session: &str, original: &str, tag: &str) -> String {
        self.touch(session);
        if let Some(map) = self.forward.get(session) {
            if let Some(existing) = map.get(original) {
                return existing.clone();
            }
        }
        let placeholder = self.generate_unique_placeholder(session, tag);
        self.forward
            .entry(session.to_string())
            .or_default()
            .insert(original.to_string(), placeholder.clone());
        self.reverse
            .entry(session.to_string())
            .or_default()
            .insert(placeholder.clone(), original.to_string());
        // 登记后缀索引（模型改写标签时的容错反查依据）
        if let Some(sfx) = placeholder_suffix(&placeholder) {
            self.suffix_index
                .entry(sfx)
                .or_default()
                .insert(placeholder.clone());
        }
        placeholder
    }

    /// 由占位符还原原文（仅限同一会话）。
    pub fn resolve(&self, session: &str, placeholder: &str) -> Option<String> {
        let found = self
            .reverse
            .get(session)
            .and_then(|map| map.get(placeholder).cloned());
        // 只有真正命中才刷新 TTL，避免为不存在的会话留幽灵记录
        if found.is_some() {
            self.touch(session);
        }
        found
    }

    /// 清空指定会话的全部映射（含后缀索引与 pin 标记）。
    ///
    /// **销毁前逐字段覆写**：`forward`（原文 → 占位符）的键、`reverse`
    /// （占位符 → 原文）的值都是原文，必须先零化再释放。
    pub fn clear_session(&self, session: &str) {
        // 先按占位符列表回收后缀索引条目，再删映射本身
        let mut orphan_sfx: Vec<String> = Vec::new();
        for ph in self.placeholders_of(session) {
            if let Some(sfx) = placeholder_suffix(&ph) {
                let mut now_empty = false;
                if let Some(mut set) = self.suffix_index.get_mut(&sfx) {
                    set.remove(&ph);
                    now_empty = set.is_empty();
                }
                if now_empty {
                    orphan_sfx.push(sfx);
                }
            }
        }
        for sfx in orphan_sfx {
            // 可能已被其它会话重新占用，二次确认空集合才删
            let remove = self
                .suffix_index
                .get(&sfx)
                .map(|s| s.is_empty())
                .unwrap_or(false);
            if remove {
                self.suffix_index.remove(&sfx);
            }
        }
        // 承载原文的两张表：取出（所有权转移）→ 覆写 → 释放
        wipe_session_map(&self.forward, session);
        wipe_session_map(&self.reverse, session);
        self.touched.remove(session);
        self.pinned.remove(session);
    }

    /// 指定会话内的映射条数。
    pub fn session_count(&self, session: &str) -> usize {
        self.forward.get(session).map(|m| m.len()).unwrap_or(0)
    }

    /// 指定会话内全部占位符（用于整段响应的批量还原）。
    pub fn placeholders_of(&self, session: &str) -> Vec<String> {
        self.reverse
            .get(session)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// 指定会话内全部原文（用于放行「由本次还原产生」的命中，避免误报）。
    pub fn originals_of(&self, session: &str) -> Vec<String> {
        self.forward
            .get(session)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// 该文本是否为**本会话**已登记的原文（即确实是还原出来的，而非模型新泄漏）。
    pub fn is_known_original(&self, session: &str, text: &str) -> bool {
        self.forward
            .get(session)
            .map(|m| m.contains_key(text))
            .unwrap_or(false)
    }

    /// 哪些会话拥有该占位符（会话隔离 / 跨请求判定的依据）。
    /// 返回会话 id 列表，空表示任何会话都没有该占位符。
    pub fn sessions_containing(&self, placeholder: &str) -> Vec<String> {
        self.reverse
            .iter()
            .filter(|e| e.value().contains_key(placeholder))
            .map(|e| e.key().clone())
            .collect()
    }

    /// 生成 `[[PII:{tag}:{8位hex}]]` 格式、且不与该会话已有占位符冲突的占位符。
    /// 8 位 hex 碰撞概率极低，但仍循环重试保证会话内唯一。
    fn generate_unique_placeholder(&self, session: &str, tag: &str) -> String {
        loop {
            let uuid = uuid::Uuid::new_v4();
            let hex8: String = uuid.simple().to_string().chars().take(8).collect();
            let candidate =
                format!("{}{}:{}{}", PLACEHOLDER_PREFIX, tag, hex8, PLACEHOLDER_SUFFIX);
            let conflict = self
                .reverse
                .get(session)
                .map(|m| m.contains_key(&candidate))
                .unwrap_or(false);
            if !conflict {
                return candidate;
            }
        }
    }
}

impl Default for Vault {
    fn default() -> Self {
        Vault::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idempotent_same_original_same_placeholder() {
        let vault = Vault::new();
        let p1 = vault.get_or_create("s1", "13800138000", "PHONE");
        let p2 = vault.get_or_create("s1", "13800138000", "PHONE");
        assert_eq!(p1, p2, "同一会话同一原文必须得到同一占位符");
        assert!(p1.starts_with("[[PII:PHONE:"));
        assert!(p1.ends_with("]]"));
    }

    #[test]
    fn test_cross_session_isolation() {
        let vault = Vault::new();
        let p1 = vault.get_or_create("s1", "user@example.com", "EMAIL");
        let p2 = vault.get_or_create("s2", "user@example.com", "EMAIL");
        assert_ne!(p1, p2, "不同会话对同一原文应得到不同占位符");
        // s1 的占位符不能在 s2 中还原
        assert!(vault.resolve("s2", &p1).is_none());
        assert_eq!(
            vault.resolve("s1", &p1).as_deref(),
            Some("user@example.com")
        );
    }

    #[test]
    fn test_resolve() {
        let vault = Vault::new();
        let ph = vault.get_or_create("s1", "110101199003070572", "IDCARD");
        assert_eq!(
            vault.resolve("s1", &ph).as_deref(),
            Some("110101199003070572")
        );
        assert!(vault.resolve("s1", "[[PII:UNKNOWN:deadbeef]]").is_none());
    }

    #[test]
    fn test_custom_tag() {
        let vault = Vault::new();
        let ph = vault.get_or_create("s1", "阿尔法计划", "PROJECT");
        assert!(ph.starts_with("[[PII:PROJECT:"));
        assert_eq!(vault.resolve("s1", &ph).as_deref(), Some("阿尔法计划"));
    }

    #[test]
    fn test_clear_session() {
        let vault = Vault::new();
        let ph = vault.get_or_create("s1", "4242424242424242", "BANKCARD");
        assert_eq!(vault.session_count("s1"), 1);
        vault.clear_session("s1");
        assert_eq!(vault.session_count("s1"), 0);
        assert!(vault.resolve("s1", &ph).is_none());
        assert!(vault.idle_for("s1").is_none(), "清理后不应残留 TTL 记录");
    }

    #[test]
    fn test_clear_session_actively_wipes_originals() {
        // 销毁路径必须真的执行覆写：原文（forward 键 / reverse 值）各一次
        let before = crate::mem::wiped_string_count();
        let vault = Vault::new();
        vault.get_or_create("s1", "13800138000", "PHONE");
        let after_create = crate::mem::wiped_string_count();
        // 创建映射不触发覆写（计数器为进程级共享，其它用例并发时只可能更大）
        assert!(after_create >= before);
        vault.clear_session("s1");
        let after_clear = crate::mem::wiped_string_count();
        assert!(
            after_clear >= after_create + 2,
            "clear_session 必须覆写原文（forward 键 + reverse 值），实际增加 {}",
            after_clear - after_create
        );
        // TTL 过期走的是同一条清理路径
        vault.get_or_create("idle", "user@example.com", "EMAIL");
        let before_ttl = crate::mem::wiped_string_count();
        let purged = vault.purge_expired(Duration::from_secs(0));
        assert_eq!(purged.len(), 1);
        assert!(
            crate::mem::wiped_string_count() > before_ttl,
            "TTL 过期清理同样必须覆写原文"
        );
    }

    #[test]
    fn test_session_ids_and_total() {
        let vault = Vault::new();
        vault.get_or_create("a", "1@x.com", "EMAIL");
        vault.get_or_create("b", "2@x.com", "EMAIL");
        assert_eq!(vault.session_total(), 2);
        let mut ids = vault.session_ids();
        ids.sort();
        assert_eq!(ids, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn test_purge_expired_removes_idle_sessions() {
        let vault = Vault::new();
        let ph = vault.get_or_create("idle", "13800138000", "PHONE");
        vault.get_or_create("busy", "user@example.com", "EMAIL");
        // ttl = 0：所有会话都算「空闲超时」
        let purged = vault.purge_expired(Duration::from_secs(0));
        assert_eq!(purged.len(), 2, "ttl 为 0 时应清空全部会话");
        assert!(vault.resolve("idle", &ph).is_none());
        assert_eq!(vault.session_total(), 0);
        // ttl 很大：不清理
        vault.get_or_create("keep", "a@b.cn", "EMAIL");
        assert!(vault.purge_expired(Duration::from_secs(3600)).is_empty());
        assert_eq!(vault.session_total(), 1);
    }

    // ─────────── 后缀索引（标签改写容错） ───────────

    #[test]
    fn test_placeholder_suffix_parser() {
        assert_eq!(
            placeholder_suffix("[[PII:PHONE:8f3a2b1c]]").as_deref(),
            Some("8f3a2b1c")
        );
        assert_eq!(
            placeholder_suffix("[[PII:BANKCARD:AB12CD34]]").as_deref(),
            Some("ab12cd34")
        );
        assert!(placeholder_suffix("[[NOTPII:8f3a2b1c]]").is_none());
        assert!(placeholder_suffix("[[PII:PHONE:zzzzzzzz]]").is_none());
        assert!(placeholder_suffix("plain").is_none());
    }

    #[test]
    fn test_suffix_index_and_lookup() {
        let vault = Vault::new();
        let ph = vault.get_or_create("s1", "13800138000", "PHONE");
        let sfx = placeholder_suffix(&ph).unwrap();
        assert_eq!(sfx.len(), 8);
        // 唯一候选 → 可反查（大小写不敏感）
        assert_eq!(vault.lookup_by_suffix(&sfx).as_deref(), Some(ph.as_str()));
        assert_eq!(
            vault.lookup_by_suffix(&sfx.to_uppercase()).as_deref(),
            Some(ph.as_str())
        );
        // 清空会话后索引必须一并回收，否则会留下查不到原文的幽灵候选
        vault.clear_session("s1");
        assert!(vault.lookup_by_suffix(&sfx).is_none());
        assert!(vault.lookup_by_suffix("deadbeef").is_none());
    }

    #[test]
    fn test_suffix_ambiguity_not_guessed() {
        let vault = Vault::new();
        let a = vault.get_or_create("s1", "13800138000", "PHONE");
        let sfx = placeholder_suffix(&a).unwrap();
        // 人为塞入第二个同后缀候选，模拟碰撞
        vault
            .suffix_index
            .entry(sfx.clone())
            .or_default()
            .insert("[[PII:PHONE:xxxxxxxx]]".to_string());
        assert!(vault.lookup_by_suffix(&sfx).is_none(), "有歧义必须不猜");
    }

    // ─────────── 在途会话 pin ───────────

    #[test]
    fn test_is_pinned() {
        let vault = Vault::new();
        vault.get_or_create("s", "a@b.cn", "EMAIL");
        assert!(!vault.is_pinned("s"));
        vault.pin("s");
        assert!(vault.is_pinned("s"));
        vault.unpin("s");
        assert!(!vault.is_pinned("s"));
    }

    #[test]
    fn test_pin_protects_inflight_session_from_purge() {
        let vault = Vault::new();
        let ph = vault.get_or_create("inflight", "13800138000", "PHONE");
        vault.pin("inflight");
        // ttl = 0：所有会话都算「空闲超时」，但 pin 住的必须被跳过
        let purged = vault.purge_expired(Duration::from_secs(0));
        assert!(purged.is_empty(), "在途会话不应被清理: {:?}", purged);
        assert_eq!(
            vault.resolve("inflight", &ph).as_deref(),
            Some("13800138000"),
            "在途会话的映射必须还能还原"
        );
        // 解除 pin 后可正常回收
        vault.unpin("inflight");
        assert_eq!(vault.purge_expired(Duration::from_secs(0)).len(), 1);
        assert_eq!(vault.session_total(), 0);
        assert!(vault.resolve("inflight", &ph).is_none());
    }
}
