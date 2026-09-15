//! 保险柜：用户录入的敏感值清单，出站精确匹配 + 访问对象告警。
//!
//! 与占位符 Vault（会话级还原存储，core/src/vault.rs）不同，保险柜是
//! **用户显式录入的敏感值**：请求出站时凡命中清单值的文本按条目动作处理
//! （默认脱敏为占位符，可逐条改为直接拦截）。模型下发命令指向保护对象
//! （.env / SSH 私钥 / 环境变量）或点名保险柜键名时，由审计层
//! [`crate::audit::scan_locker_access`] 告警（观察类，不改写）。
//!
//! 存储说明：条目以配置 JSON 存本地库（与规则/名单同级保护）——能读到库的
//! 攻击者同样能读原始 .env，保险柜不降低本机安全水位；它的价值在
//! **数据出口管控**：模型服务商永远只见到占位符。

use serde::{Deserialize, Serialize};

/// 单条保险柜条目。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockerEntry {
    /// 键名（列表展示；模型命令点名键名时触发访问告警）
    pub name: String,
    /// 凭据值（出站精确匹配的靶子）或文件 / 文件夹路径（访问告警的靶子，按 kind）
    pub value: String,
    /// 命中动作：mask（脱敏占位符）| block（拦截请求）——仅凭据值条目有效
    pub action: String,
    pub enabled: bool,
    /// 条目类型：value（凭据值，出站脱敏 / 拦截）| path（文件 / 文件夹，访问告警）。
    /// 缺省 value（旧配置兼容）。路径条目只产生访问告警——代理不在命令执行路径上，
    /// 无法真正阻止本地读取；「碰了什么」可见是它提供的安全价值。
    #[serde(default = "default_kind")]
    pub kind: String,
}

fn default_kind() -> String {
    "value".to_string()
}

/// 保险柜配置（可序列化，KV 落盘）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockerConfig {
    #[serde(default)]
    pub entries: Vec<LockerEntry>,
}

/// 条目上限（防误操作灌入巨量条目拖慢出站扫描）。
const MAX_ENTRIES: usize = 200;
/// 键名上限（字符）。
const NAME_MAX: usize = 64;
/// 凭据值下限：过短的值（如 "abc"）会在正常文本里误伤，不值得保护。
const VALUE_MIN_CHARS: usize = 8;
/// 凭据值上限（字符）。
const VALUE_MAX_CHARS: usize = 4096;
/// 路径条目值下限（"*" 单字符无意义）与上限（字符）。
const PATH_MIN_CHARS: usize = 2;
const PATH_MAX_CHARS: usize = 1024;

/// 取路径 / 通配模式的展示键名：最后一段非空段（`D:\secrets\api.key` → `api.key`）。
fn path_tail(value: &str) -> String {
    value
        .split(['\\', '/'])
        .filter(|s| !s.is_empty())
        .next_back()
        .unwrap_or(value)
        .to_string()
}

impl LockerConfig {
    /// 就地清洗：trim、去空、短值丢弃、超长截断、类型 / 动作归一、按键名去重（保首个）。
    pub fn sanitize(&mut self) {
        let mut seen = std::collections::HashSet::new();
        let mut out: Vec<LockerEntry> = Vec::with_capacity(self.entries.len());
        for mut e in self.entries.drain(..) {
            e.name = e.name.trim().to_string();
            e.value = e.value.trim().to_string();
            e.kind = if e.kind == "path" { "path" } else { "value" }.to_string();
            let (min_chars, max_chars) = if e.kind == "path" {
                (PATH_MIN_CHARS, PATH_MAX_CHARS)
            } else {
                (VALUE_MIN_CHARS, VALUE_MAX_CHARS)
            };
            let vlen = e.value.chars().count();
            if e.value.is_empty() || vlen < min_chars {
                continue;
            }
            if vlen > max_chars {
                e.value = e.value.chars().take(max_chars).collect();
            }
            // 路径条目键名可空：自动取路径尾段（路径本身可作标签）；
            // 凭据值条目空名直接丢——键名会进告警 evidence，不能拿值充当
            if e.name.is_empty() {
                if e.kind == "path" {
                    e.name = path_tail(&e.value);
                } else {
                    continue;
                }
            }
            if e.name.chars().count() > NAME_MAX {
                e.name = e.name.chars().take(NAME_MAX).collect();
            }
            e.action = if e.kind == "path" || e.action != "block" {
                "mask".to_string()
            } else {
                "block".to_string()
            };
            if !seen.insert(e.name.clone()) {
                continue;
            }
            out.push(e);
            if out.len() >= MAX_ENTRIES {
                break;
            }
        }
        self.entries = out;
    }

    /// 是否有启用的条目（出站扫描 / 告警的总开关语义）。
    pub fn any_enabled(&self) -> bool {
        self.entries.iter().any(|e| e.enabled)
    }
}

/// 出站命中（字节偏移；与 [`crate::semantic`] 的 RawHit 同构，多带动作）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockerHit {
    pub start: usize,
    pub len: usize,
    pub action: crate::detector::Action,
}

/// 编译后的保险柜匹配器（只保留启用条目）。Clone 以便随 Detector 复制。
#[derive(Debug, Clone, Default)]
pub struct LockerEngine {
    /// (键名, 值, 动作)，仅启用条目。
    entries: Vec<(String, String, crate::detector::Action)>,
}

impl LockerEngine {
    pub fn disabled() -> LockerEngine {
        LockerEngine { entries: Vec::new() }
    }

    /// 由配置构建：只保留**凭据值**条目（路径条目不做出站匹配——路径字符串
    /// 出站无害且常见，纳入值匹配只会制造误报）。动作归一（block 之外一律按 Mask）。
    pub fn new(cfg: &LockerConfig) -> LockerEngine {
        let mut entries = Vec::new();
        for e in &cfg.entries {
            if !e.enabled || e.kind != "value" {
                continue;
            }
            let action = if e.action == "block" {
                crate::detector::Action::Block
            } else {
                crate::detector::Action::Mask
            };
            entries.push((e.name.clone(), e.value.clone(), action));
        }
        LockerEngine { entries }
    }

    pub fn is_disabled(&self) -> bool {
        self.entries.is_empty()
    }

    /// 凭据值条目的键名清单（响应侧点名告警用；路径条目走 [`LockerConfig`]
    /// 的路径清单，不在这里）。
    pub fn keys(&self) -> Vec<String> {
        self.entries.iter().map(|(n, _, _)| n.clone()).collect()
    }

    /// 启用条目值的精确子串匹配（字节偏移，允许重叠——排序去重交给调用方）。
    ///
    /// 值级精确匹配（区分大小写）：凭据是二进制形态的字符串，任何大小写/片段
    /// 归一化都会制造漏报或误报，宁窄勿宽。
    pub fn scan(&self, text: &str) -> Vec<LockerHit> {
        if self.entries.is_empty() || text.is_empty() {
            return Vec::new();
        }
        let mut hits = Vec::new();
        for (_, value, action) in &self.entries {
            let mut from = 0usize;
            while let Some(pos) = text[from..].find(value.as_str()) {
                let start = from + pos;
                hits.push(LockerHit {
                    start,
                    len: value.len(),
                    action: *action,
                });
                from = start + 1;
            }
        }
        hits
    }
}

/// 启用的路径保护条目清单（响应侧访问告警用）。
///
/// 匹配语义（朴素子串，宁可稍宽——告警是观察类）：
/// - 通配模式（`*.pem`）：取最后一个 `*` 之后的尾部（如 `.pem`），文本含该尾部即命中；
/// - 具体路径：按 `\` / `/` 分段，末两段相邻出现（任一分隔符风格）或
///   尾段独立出现（尾段 ≥3 字符防通用词误报）即命中——覆盖相对路径与
///   正反斜杠混用。
pub fn enabled_paths(cfg: &LockerConfig) -> Vec<String> {
    cfg.entries
        .iter()
        .filter(|e| e.enabled && e.kind == "path")
        .map(|e| e.value.clone())
        .collect()
}

/// 单条路径是否命中文本（见 [`enabled_paths`] 的匹配语义）。
pub fn path_hits_text(path: &str, text: &str) -> bool {
    let v = path.trim();
    if v.is_empty() || text.is_empty() {
        return false;
    }
    if let Some(star) = v.find('*') {
        let suffix = &v[star + 1..];
        return suffix.chars().count() >= 2 && text.contains(suffix);
    }
    let segs: Vec<&str> = v.split(['\\', '/']).filter(|s| !s.is_empty()).collect();
    match segs.len() {
        0 => false,
        1 => {
            let s = segs[0];
            s.chars().count() >= 3 && text.contains(s)
        }
        _ => {
            let prev = segs[segs.len() - 2];
            let tail = segs[segs.len() - 1];
            if text.contains(&format!("{}\\{}", prev, tail))
                || text.contains(&format!("{}/{}", prev, tail))
            {
                return true;
            }
            tail.chars().count() >= 3 && text.contains(tail)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, value: &str, action: &str, enabled: bool) -> LockerEntry {
        LockerEntry {
            name: name.to_string(),
            value: value.to_string(),
            action: action.to_string(),
            enabled,
            kind: "value".to_string(),
        }
    }

    fn path_entry(value: &str, enabled: bool) -> LockerEntry {
        LockerEntry {
            name: String::new(),
            value: value.to_string(),
            action: "mask".to_string(),
            enabled,
            kind: "path".to_string(),
        }
    }

    #[test]
    fn test_sanitize_drops_short_and_dedups() {
        let mut cfg = LockerConfig {
            entries: vec![
                entry("K1", "short", "mask", true),                    // 值 < 8 字符 → 丢
                entry("K2", "sk-1234567890abcdef", "weird", true),     // 动作归一为 mask
                entry("K2", "duplicate", "mask", true),                // 同名 → 丢后者
                entry("", "sk-1234567890abcdef", "mask", true),        // 空键名 → 丢
                entry("  K3  ", "  sk-abcdefghijklmnop  ", "block", true), // trim
            ],
        };
        cfg.sanitize();
        assert_eq!(cfg.entries.len(), 2);
        assert_eq!(cfg.entries[0].name, "K2");
        assert_eq!(cfg.entries[0].action, "mask");
        assert_eq!(cfg.entries[1].name, "K3");
        assert_eq!(cfg.entries[1].value, "sk-abcdefghijklmnop");
        assert_eq!(cfg.entries[1].action, "block");
    }

    #[test]
    fn test_sanitize_path_entries() {
        let mut cfg = LockerConfig {
            entries: vec![
                path_entry("D:\\secrets\\api.key", true),  // 键名自动取尾段
                path_entry("", true),                      // 空路径 → 丢
                path_entry("*", true),                     // 无后缀通配 → 丢（<2 字符）
                path_entry("*.pem", true),                 // 通配后缀
                entry("VAL", "normal-value-12345", "block", true),
            ],
        };
        cfg.sanitize();
        assert_eq!(cfg.entries.len(), 3);
        assert_eq!(cfg.entries[0].kind, "path");
        assert_eq!(cfg.entries[0].name, "api.key");
        assert_eq!(cfg.entries[0].action, "mask", "路径条目动作恒为告警");
        assert_eq!(cfg.entries[1].value, "*.pem");
        assert_eq!(cfg.entries[2].kind, "value", "未标 kind 的旧条目按凭据值处理");
        assert_eq!(cfg.entries[2].action, "block");
        // 路径条目不进出站引擎（keys 只含凭据值条目，出站匹配也不含路径）
        let engine = LockerEngine::new(&cfg);
        assert_eq!(engine.keys(), vec!["VAL".to_string()], "keys 只含凭据值条目");
        assert!(
            engine.scan("D:\\secrets\\api.key in text").is_empty(),
            "路径条目不应参与出站值匹配"
        );
        // 路径清单
        let paths = enabled_paths(&cfg);
        assert_eq!(paths, vec!["D:\\secrets\\api.key".to_string(), "*.pem".to_string()]);
    }

    #[test]
    fn test_path_hits_text_variants() {
        // 通配后缀：任一同名扩展文件引用
        assert!(path_hits_text("*.pem", "cat server.pem"));
        assert!(!path_hits_text("*.pem", "cat server.pfx"));
        // 双段相邻：正反斜杠两种风格都算
        assert!(path_hits_text("D:\\secrets\\api.key", "type D:\\secrets\\api.key"));
        assert!(path_hits_text("D:\\secrets\\api.key", "cat /d/secrets/api.key"));
        // 相对路径：尾段独立命中
        assert!(path_hits_text("D:\\secrets\\api.key", "cd secrets && cat ./api.key"));
        // 尾段过短（<3）且不相邻 → 不报（防通用词误报）
        assert!(!path_hits_text("D:\\app\\db", "open the db file"));
        // 相邻匹配不受尾段长度限制
        assert!(path_hits_text("D:\\app\\db", "open D:/app/db now"));
        // 完全无关文本
        assert!(!path_hits_text("D:\\secrets\\api.key", "nothing relevant here"));
    }

    #[test]
    fn test_scan_hits_with_action_and_disabled_skip() {
        let cfg = LockerConfig {
            entries: vec![
                entry("TOKEN", "s3cr3t-value-9999", "mask", true),
                entry("OFF", "disabled-value-777", "mask", false),
                entry("KEY", "AKIAIOSFODNN7EXAMPLE", "block", true),
            ],
        };
        let engine = LockerEngine::new(&cfg);
        assert_eq!(engine.entries.len(), 2);
        let text = "read AKIAIOSFODNN7EXAMPLE and s3cr3t-value-9999 twice s3cr3t-value-9999";
        let hits = engine.scan(text);
        assert_eq!(hits.len(), 3);
        assert!(hits.iter().any(|h| h.action == crate::detector::Action::Block));
        assert_eq!(
            hits.iter().filter(|h| h.action == crate::detector::Action::Mask).count(),
            2
        );
        // 精确匹配无命中
        assert!(engine.scan("nothing to see here").is_empty());
    }

    #[test]
    fn test_engine_disabled_and_keys() {
        let engine = LockerEngine::disabled();
        assert!(engine.is_disabled());
        assert!(engine.scan("anything at all").is_empty());
        let cfg = LockerConfig {
            entries: vec![entry("MY_KEY", "value-12345678", "mask", true)],
        };
        let engine = LockerEngine::new(&cfg);
        assert_eq!(engine.keys(), vec!["MY_KEY".to_string()]);
    }

    #[test]
    fn test_detector_integration_mask_and_block() {
        use crate::detector::{Action, Detector};
        let mut cfg = LockerConfig {
            entries: vec![
                entry("TOKEN", "s3cr3t-value-9999", "mask", true),
                // 值刻意避开内置正则形态（如 sk-/AKIA）：正则先入列占位是既定优先级
                entry("KEY", "my-vault-token-8888", "block", true),
            ],
        };
        cfg.sanitize();
        let detector = Detector::with_default_rules().with_locker(&cfg);
        let hits = detector.scan("contains my-vault-token-8888 inside");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].tag, "LOCKER");
        assert_eq!(hits[0].action, Action::Block);

        let hits = detector.scan("leak s3cr3t-value-9999 here");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].action, Action::Mask);
    }
}
