//! 敏感信息检测引擎。
//!
//! 规则以可序列化的 [`RuleSpec`] 描述（规则中心增删改/持久化的单一数据源），
//! 经 [`Detector::from_specs`] 编译为运行时检测器；支持正则命中 + 语义校验
//! （校验位 / Luhn / IP 段范围），`scrub` 把命中文本替换为调用方提供的占位符。
//!
//! 内置 6 类规则（身份证 / 手机号 / 银行卡 / 邮箱 / API Key / IP），
//! 同时支持用户自定义规则（自定义正则 + 自定义占位符标签）。

use regex::Regex;
use serde::{Deserialize, Serialize};

/// 内置敏感信息类型（用于展示名 / 占位符标签 / 内置校验器映射）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PiiKind {
    /// 中国大陆 18 位身份证号
    IdCardCn,
    /// 中国大陆 11 位手机号
    PhoneCn,
    /// 银行卡号（Luhn 校验）
    BankCard,
    /// 电子邮箱
    Email,
    /// API 密钥（sk-... / AKIA...）
    ApiKey,
    /// IPv4 地址
    IpAddress,
}

impl PiiKind {
    /// 占位符中的类型标签，如 `[[PII:IDCARD:...]]` 中的 `IDCARD`。
    pub fn tag(&self) -> &'static str {
        match self {
            PiiKind::IdCardCn => "IDCARD",
            PiiKind::PhoneCn => "PHONE",
            PiiKind::BankCard => "BANKCARD",
            PiiKind::Email => "EMAIL",
            PiiKind::ApiKey => "APIKEY",
            PiiKind::IpAddress => "IP",
        }
    }

    /// 从标签反解类型（仅内置 6 类；自定义规则无对应枚举）。
    pub fn from_tag(tag: &str) -> Option<PiiKind> {
        match tag {
            "IDCARD" => Some(PiiKind::IdCardCn),
            "PHONE" => Some(PiiKind::PhoneCn),
            "BANKCARD" => Some(PiiKind::BankCard),
            "EMAIL" => Some(PiiKind::Email),
            "APIKEY" => Some(PiiKind::ApiKey),
            "IP" => Some(PiiKind::IpAddress),
            _ => None,
        }
    }

    /// 前端展示用的中文名。
    pub fn display_name(&self) -> &'static str {
        match self {
            PiiKind::IdCardCn => "身份证号",
            PiiKind::PhoneCn => "手机号",
            PiiKind::BankCard => "银行卡号",
            PiiKind::Email => "邮箱",
            PiiKind::ApiKey => "API 密钥",
            PiiKind::IpAddress => "IP 地址",
        }
    }
}

/// 单条命中的处理动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 替换为占位符
    Mask,
    /// 直接拦截请求
    Block,
    /// 仅提醒不修改
    Warn,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Mask => "mask",
            Action::Block => "block",
            Action::Warn => "warn",
        }
    }

    pub fn from_str(s: &str) -> Action {
        match s {
            "block" => Action::Block,
            "warn" => Action::Warn,
            _ => Action::Mask,
        }
    }
}

/// 规则规格（可序列化）—— 规则中心增删改 / kv 持久化 / 运行时重建的统一载体。
///
/// - 内置规则 id 形如 `builtin.idcard`，`builtin = true`，不可删除、可编辑、可恢复默认；
/// - 自定义规则 id 形如 `custom.xxxxxxxx`，`builtin = false`，可删除。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSpec {
    pub id: String,
    /// 占位符标签（如 `IDCARD`；自定义规则可自定，将出现在 `[[PII:<TAG>:...]]` 中）
    pub tag: String,
    /// 展示名（前端规则卡片标题）
    pub name: String,
    /// 正则表达式源码
    pub regex: String,
    /// 处理动作：mask / block / warn
    pub action: String,
    pub enabled: bool,
    /// 是否内置规则
    pub builtin: bool,
    /// Block 动作的确认次数下限：同一请求中该规则的有效命中达到该次数才拦截，
    /// 否则只脱敏不拦截。默认 1。校验器类规则（身份证 / 银行卡 / IP）拦截时
    /// 运行时强制下限 2（见 [`compile_rule`]）。
    #[serde(default = "default_min_confirm")]
    pub min_confirm: u8,
}

/// `min_confirm` 的 serde 默认值（旧持久化 JSON / 旧前端载荷缺省时按 1 兜底）。
fn default_min_confirm() -> u8 {
    1
}

/// 编译后的运行时规则（内部结构，不对外暴露）。
#[derive(Clone)]
struct Rule {
    /// 规则 id（来源 [`RuleSpec::id`]，Block 闸门按规则聚合确认数用）
    id: String,
    tag: String,
    regex: Regex,
    validate: Option<fn(&str) -> bool>,
    /// 命中前后紧邻 ASCII 数字时拒绝（身份证/手机号/银行卡防长数字串误截）
    digit_adjacent: bool,
    action: Action,
    enabled: bool,
    /// Block 确认次数下限（校验器类规则拦截时编译期强制 ≥ 2）
    min_confirm: u32,
    /// 是否带语义校验器（身份证校验位 / Luhn / IPv4）
    validated: bool,
}

/// 一次命中记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// 占位符标签（自定义规则为用户定义标签）
    pub tag: String,
    /// 命中文本长度（字符数）
    pub text_len: usize,
    /// 命中起始位置（字符偏移）
    pub start: usize,
    pub action: Action,
    /// 命中来源规则 id（语义层为空串、保险柜为 "locker"）
    pub rule_id: String,
    /// 该规则的 Block 确认次数下限（语义 / 保险柜命中恒为 1）
    pub min_confirm: u32,
    /// 命中是否通过语义校验器（语义 / 保险柜命中为 false）
    pub validated: bool,
    /// 命中的保险柜条目键名（仅保险柜命中非空）。
    /// 供「凭据使用提醒」按条目聚合，只含键名、绝不含凭据值。
    pub locker_entry: Option<String>,
}

/// 内置标签 → 语义校验器映射。
fn builtin_validator(tag: &str) -> Option<fn(&str) -> bool> {
    match tag {
        "IDCARD" => Some(validate_id_card_cn),
        "BANKCARD" => Some(validate_luhn),
        "IP" => Some(validate_ipv4),
        _ => None,
    }
}

/// 内置标签 → 数字邻接检查映射。
fn builtin_digit_adjacent(tag: &str) -> bool {
    matches!(tag, "IDCARD" | "PHONE" | "BANKCARD")
}

/// 把单条规格编译为运行时规则；正则非法时返回 Err（规则中心保存前会以此校验）。
fn compile_rule(spec: &RuleSpec) -> Result<Rule, String> {
    let regex = Regex::new(&spec.regex)
        .map_err(|e| format!("规则「{}」的正则无效: {}", spec.name, e))?;
    let tag_upper = spec.tag.trim().to_ascii_uppercase();
    if tag_upper.is_empty() {
        return Err(format!("规则「{}」的标签不能为空", spec.name));
    }
    let validator = builtin_validator(&tag_upper);
    let action = Action::from_str(&spec.action);
    // Block 确认次数下限：校验器类规则（身份证 / 银行卡 / IP）拦截时强制 ≥ 2 ——
    // 正则浮出的命中已通过校验器，但 Luhn 等本身假通过率不可忽视（约 1/10），
    // 单命中直接拦截会造成批量误拦；未达标时命中照常脱敏不拦截。
    let min_confirm = if validator.is_some() && action == Action::Block {
        (spec.min_confirm as u32).max(2)
    } else {
        spec.min_confirm as u32
    };
    let digit_adjacent = builtin_digit_adjacent(&tag_upper);
    Ok(Rule {
        id: spec.id.clone(),
        tag: tag_upper,
        regex,
        validate: validator,
        digit_adjacent,
        action,
        enabled: spec.enabled,
        min_confirm,
        validated: validator.is_some(),
    })
}

/// 内置默认规则规格（6 类，全 enabled / mask）。
pub fn default_rule_specs() -> Vec<RuleSpec> {
    let mk = |id: &str, tag: &str, name: &str, regex: &str, enabled: bool| RuleSpec {
        id: id.to_string(),
        tag: tag.to_string(),
        name: name.to_string(),
        regex: regex.to_string(),
        action: "mask".to_string(),
        enabled,
        builtin: true,
        // 内置默认确认次数 1；校验器类规则的拦截下限由 compile_rule 编译期兜底（≥ 2）
        min_confirm: 1,
    };
    vec![
        // 身份证：6 位地区码 + 19/20 世纪年份 + 月 + 日 + 3 位顺序码 + 校验位
        mk(
            "builtin.idcard",
            "IDCARD",
            "身份证号",
            r"[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]",
            true,
        ),
        // 手机号：不用 \b（Rust regex 的 \b 是 Unicode 语义，中文紧邻数字时无法形成边界），
        // 改为在收集命中时做 ASCII 数字邻接检查
        mk("builtin.phone", "PHONE", "手机号", r"1[3-9]\d{9}", true),
        // 银行卡：16~19 位数字 + Luhn，同样用数字邻接检查替代 \b
        mk("builtin.bankcard", "BANKCARD", "银行卡号", r"\d{16,19}", true),
        // 邮箱
        mk(
            "builtin.email",
            "EMAIL",
            "邮箱",
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            true,
        ),
        // API Key：OpenAI 风格 sk- + 20 位以上字母数字；AWS AKIA + 16 位大写
        mk(
            "builtin.apikey",
            "APIKEY",
            "API 密钥",
            r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}",
            true,
        ),
        // IPv4：每段 1~3 位数字；语义校验过滤 300.1.1.1 与本机/广播地址。
        // **默认关闭**：形如 `1.2.3.4` 的版本号/序号在模型回答里太常见，
        // 全开会让用户看到自己的版本号被改成占位符（误伤代价 > 漏报收益）。
        // 需要内网 IP 防泄漏的用户可在规则页手动开启。
        mk("builtin.ip", "IP", "IP 地址", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", false),
    ]
}

/// 按 id 取内置默认规格（「恢复默认」用）。
pub fn builtin_spec_by_id(id: &str) -> Option<RuleSpec> {
    default_rule_specs().into_iter().find(|s| s.id == id)
}

// ═══════════════════════ 内置规则预设（保守 / 均衡 / 激进） ═══════════════════════

/// 预设档位字面量（前端 / 命令层共用同一组字符串）。
pub const PRESET_CONSERVATIVE: &str = "conservative";
pub const PRESET_BALANCED: &str = "balanced";
pub const PRESET_AGGRESSIVE: &str = "aggressive";
pub const PRESET_CUSTOM: &str = "custom";

/// 三档预设对内置规则的 (enabled, action) 映射，是「误伤打扰」与「防护强度」的权衡：
///
/// - **保守**：只守身份证 / 银行卡 / API Key 三类最高危（全部脱敏），其余关闭 ——
///   打扰最小，代价是手机号 / 邮箱等不再脱敏；
/// - **均衡**：内置默认 —— 五类启用（脱敏），IP 关闭（版本号 / 序号误伤大于漏报收益）；
/// - **激进**：全部六类启用，且身份证 / 银行卡 / API Key 升级为**拦截**
///   （宁可拦下含高危信息的整条请求），手机号 / 邮箱 / IP 维持脱敏。
///
/// 预设只改内置规则的开关与动作：正则、自定义规则、黑 / 白名单一律不动。
fn preset_table(preset: &str) -> &'static [(&'static str, bool, &'static str)] {
    match preset {
        PRESET_CONSERVATIVE => &[
            ("builtin.idcard", true, "mask"),
            ("builtin.bankcard", true, "mask"),
            ("builtin.apikey", true, "mask"),
            ("builtin.phone", false, "mask"),
            ("builtin.email", false, "mask"),
            ("builtin.ip", false, "mask"),
        ],
        PRESET_AGGRESSIVE => &[
            ("builtin.idcard", true, "block"),
            ("builtin.bankcard", true, "block"),
            ("builtin.apikey", true, "block"),
            ("builtin.phone", true, "mask"),
            ("builtin.email", true, "mask"),
            ("builtin.ip", true, "mask"),
        ],
        // 均衡 = 内置默认
        _ => &[
            ("builtin.idcard", true, "mask"),
            ("builtin.phone", true, "mask"),
            ("builtin.bankcard", true, "mask"),
            ("builtin.email", true, "mask"),
            ("builtin.apikey", true, "mask"),
            ("builtin.ip", false, "mask"),
        ],
    }
}

/// 把预设应用到规格列表（只改内置规则的 enabled / action，自定义规则原样保留）。
pub fn apply_preset_to_builtin(mut specs: Vec<RuleSpec>, preset: &str) -> Vec<RuleSpec> {
    for (id, enabled, action) in preset_table(preset) {
        if let Some(spec) = specs.iter_mut().find(|s| s.builtin && s.id == *id) {
            spec.enabled = *enabled;
            spec.action = action.to_string();
        }
    }
    specs
}

/// 判定规格列表当前所处的预设档位：与某一档的内置 (enabled, action) 全部一致即该档，
/// 否则 custom（用户改过任一内置规则的开关或动作）。档位判定不看正则改动。
pub fn preset_of_specs(specs: &[RuleSpec]) -> &'static str {
    for preset in [PRESET_CONSERVATIVE, PRESET_BALANCED, PRESET_AGGRESSIVE] {
        let expect = apply_preset_to_builtin(default_rule_specs(), preset);
        let matched = expect.iter().all(|e| {
            specs
                .iter()
                .find(|s| s.id == e.id)
                .map(|s| s.enabled == e.enabled && s.action == e.action)
                .unwrap_or(false)
        });
        if matched {
            return preset;
        }
    }
    PRESET_CUSTOM
}

// ═══════════════════════ 正则测试（规则中心测试器） ═══════════════════════

/// 单条命中（字符偏移，与 `Detector` 的统计口径一致）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegexHit {
    /// 命中起始（字符偏移，非字节）
    pub start: usize,
    /// 命中长度（字符数）
    pub len: usize,
    /// 命中文本
    pub text: String,
}

/// 独立编译给定正则并返回全部命中 —— 供规则中心的正则测试器使用。
/// 与线上引擎同一 regex crate：Unicode `\b` 语义、无 lookaround，测试结果即线上行为。
/// 注意：不含内置标签的语义校验（身份证校验位 / Luhn 等）——那是随标签附加的，
/// 测试器只验证正则本身。
pub fn regex_test_hits(regex_src: &str, sample: &str) -> Result<Vec<RegexHit>, String> {
    let re = Regex::new(regex_src).map_err(|e| format!("正则无效: {}", e))?;
    let mut hits = Vec::new();
    for mat in re.find_iter(sample) {
        let start = sample[..mat.start()].chars().count();
        let len = mat.as_str().chars().count();
        hits.push(RegexHit {
            start,
            len,
            text: mat.as_str().to_string(),
        });
    }
    Ok(hits)
}


/// 检测引擎。
/// `Clone` 成本很低（`regex::Regex` 内部是 Arc），便于共享给流式还原管道。
#[derive(Clone)]
pub struct Detector {
    rules: Vec<Rule>,
    /// 语义检测层（熵值 / 姓名 / 地址 / 机构 / 产品代号白名单）。
    /// 默认全关——由 `set_semantic` / `with_semantic` 显式启用。
    semantic: crate::semantic::SemanticEngine,
    /// 保险柜（用户录入敏感值的出站精确匹配）：动作按条目（Mask / Block）。
    /// 默认空——由 `set_locker` / `with_locker` 显式启用。
    locker: crate::locker::LockerEngine,
}

impl Detector {
    /// 由规格列表编译构建；任一正则非法即返回 Err。
    /// 语义层默认全关（需要时用 [`Detector::with_semantic`] 启用）。
    pub fn from_specs(specs: &[RuleSpec]) -> Result<Detector, String> {
        let mut rules = Vec::with_capacity(specs.len());
        for spec in specs {
            rules.push(compile_rule(spec)?);
        }
        Ok(Detector {
            rules,
            semantic: crate::semantic::SemanticEngine::disabled(),
            locker: crate::locker::LockerEngine::disabled(),
        })
    }

    /// 启用语义检测层（链式）：语义命中恒为 Mask，正则命中优先占位。
    pub fn with_semantic(mut self, cfg: &crate::semantic::SemanticConfig) -> Detector {
        self.set_semantic(cfg);
        self
    }

    /// 替换语义检测层配置（热更新路径用）。
    pub fn set_semantic(&mut self, cfg: &crate::semantic::SemanticConfig) {
        self.semantic = crate::semantic::SemanticEngine::new(cfg);
    }

    /// 启用保险柜（链式）：命中动作按条目（默认 Mask，可 Block）。
    pub fn with_locker(mut self, cfg: &crate::locker::LockerConfig) -> Detector {
        self.set_locker(cfg);
        self
    }

    /// 替换保险柜配置（热更新路径用）。
    pub fn set_locker(&mut self, cfg: &crate::locker::LockerConfig) {
        self.locker = crate::locker::LockerEngine::new(cfg);
    }

    /// 使用全部内置默认规则构建（enabled = true，action = Mask）。
    pub fn with_default_rules() -> Detector {
        Self::from_specs(&default_rule_specs()).expect("内置规则必须可编译")
    }

    /// 扫描文本，返回全部有效命中（已按 start 升序，不重叠）。
    pub fn scan(&self, text: &str) -> Vec<Hit> {
        self.collect_hits(text)
    }

    /// 凭据值命中条目名清单（去重），委托给保险柜引擎的轻量精确匹配。
    ///
    /// 供白名单直通路径使用：正文不做脱敏改写、仍需统计「哪些凭据值原样出站」，
    /// 以触发凭据轮换提醒。返回只含条目键名，绝不携带凭据值。
    pub fn scan_locker_names(&self, text: &str) -> Vec<String> {
        self.locker.scan_entry_names(text)
    }

    /// 扫描并用 `replace(原文, 标签)` 的返回值替换每个命中区间。
    /// 返回 (替换后的文本, 命中列表)。
    ///
    /// 重叠区间策略：按 start 排序后从左到右扫描，保留先出现的命中、跳过与其重叠的后出现命中。
    pub fn scrub<F>(&self, text: &str, mut replace: F) -> (String, Vec<Hit>)
    where
        F: FnMut(&str, &str) -> String,
    {
        let hits = self.collect_hits(text);
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize; // 已消费的字符偏移
        for hit in &hits {
            if hit.start < cursor {
                continue; // 与前一个命中重叠，跳过
            }
            let end = hit.start + hit.text_len;
            if end > text.chars().count() {
                continue; // 越界保护
            }
            // 未命中段原样保留
            let prefix: String = text.chars().skip(cursor).take(hit.start - cursor).collect();
            out.push_str(&prefix);
            // 命中段调用替换函数
            let original: String = text.chars().skip(hit.start).take(hit.text_len).collect();
            out.push_str(&replace(&original, &hit.tag));
            cursor = end;
        }
        // 尾部剩余文字
        let tail: String = text.chars().skip(cursor).collect();
        out.push_str(&tail);
        (out, hits)
    }

    /// 收集全部规则的命中，按 start 排序；重叠时保留先加入排序的（start 相同取更长者优先）。
    fn collect_hits(&self, text: &str) -> Vec<Hit> {
        let mut raw: Vec<Hit> = Vec::new();
        let char_len = text.chars().count();
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            for mat in rule.regex.find_iter(text) {
                let start = text[..mat.start()].chars().count();
                let text_len = mat.as_str().chars().count();
                if start >= char_len {
                    continue;
                }
                // 语义校验（如身份证校验位 / Luhn / IP 段）
                if let Some(validate) = rule.validate {
                    if !validate(mat.as_str()) {
                        continue;
                    }
                }
                // 数字邻接检查：身份证 / 手机号 / 银行卡命中的前一个或后一个字符
                // 若为 ASCII 数字，说明只是长数字串的片段，拒绝该命中
                if rule.digit_adjacent
                    && is_digit_adjacent(text.as_bytes(), mat.start(), mat.end())
                {
                    continue;
                }
                raw.push(Hit {
                    tag: rule.tag.clone(),
                    text_len,
                    start,
                    action: rule.action,
                    rule_id: rule.id.clone(),
                    min_confirm: rule.min_confirm,
                    validated: rule.validated,
                    locker_entry: None,
                });
            }
        }
        // 语义层追加（熵值 / 姓名 / 地址 / 机构 / 产品代号白名单）：
        // 恒 Mask；字节偏移转字符偏移后与正则命中一起参与排序去重。
        // sort_by 是稳定排序，正则命中先入列，同位冲突时正则优先。
        for h in self.semantic.hits(text) {
            let start = text[..h.start].chars().count();
            let text_len = text[h.start..h.start + h.len].chars().count();
            raw.push(Hit {
                tag: h.tag.to_string(),
                text_len,
                start,
                action: Action::Mask,
                // 语义命中恒 Mask，不参与 Block 确认闸门
                rule_id: String::new(),
                min_confirm: 1,
                validated: false,
                locker_entry: None,
            });
        }
        // 保险柜命中（用户录入敏感值的精确匹配）：动作按条目（默认 Mask，可 Block）。
        // 与语义层同为追加段，同位冲突时正则 / 语义优先。
        for h in self.locker.scan(text) {
            let start = text[..h.start].chars().count();
            let text_len = text[h.start..h.start + h.len].chars().count();
            raw.push(Hit {
                tag: "LOCKER".to_string(),
                text_len,
                start,
                action: h.action,
                // 保险柜是用户录入的精确值，零误报：不经 Block 确认闸门（min_confirm=1）
                rule_id: "locker".to_string(),
                min_confirm: 1,
                validated: false,
                // 条目键名随命中透出，供「凭据使用提醒」按条目聚合
                locker_entry: Some(h.name),
            });
        }
        // 按 start 升序；同起点时更长的命中优先，避免同一文本被两个规则各报一次后短者占用区间
        raw.sort_by(|a, b| a.start.cmp(&b.start).then(b.text_len.cmp(&a.text_len)));
        // 去重叠：保留先出现的
        let mut result: Vec<Hit> = Vec::new();
        let mut covered_until = 0usize;
        for hit in raw {
            if hit.start >= covered_until {
                covered_until = hit.start + hit.text_len;
                result.push(hit);
            }
        }
        result
    }
}

/// 检查命中文本的紧邻字符是否为 ASCII 数字（前一个或后一个）。
/// UTF-8 的多字节字符编码均 ≥ 0x80，因此按字节检查 ASCII 数字是安全的。
/// 返回 true 表示命中紧邻数字（应拒绝）。
fn is_digit_adjacent(bytes: &[u8], start: usize, end: usize) -> bool {
    let prev_is_digit = start > 0 && bytes[start - 1].is_ascii_digit();
    let next_is_digit = end < bytes.len() && bytes[end].is_ascii_digit();
    prev_is_digit || next_is_digit
}

/// 身份证 18 位加权校验。
///
/// 权重 [7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2]，模 11 映射 "10X98765432"。
pub fn validate_id_card_cn(id: &str) -> bool {
    let chars: Vec<char> = id.chars().collect();
    if chars.len() != 18 {
        return false;
    }
    let weights: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    let map = b"10X98765432";
    let mut sum: u32 = 0;
    for (i, ch) in chars.iter().take(17).enumerate() {
        let digit = match ch.to_digit(10) {
            Some(d) => d,
            None => return false,
        };
        sum += digit * weights[i];
    }
    let expect = map[(sum % 11) as usize] as char;
    let actual = chars[17].to_ascii_uppercase();
    actual == expect
}

/// 银行卡 Luhn 校验。
pub fn validate_luhn(num: &str) -> bool {
    let digits: Vec<u32> = num
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap_or(0))
        .collect();
    if digits.is_empty() {
        return false;
    }
    let mut sum = 0u32;
    // 从最右位开始，奇数位（1-based）直接累加，偶数位翻倍后减 9（若 >9）
    for (idx, d) in digits.iter().rev().enumerate() {
        if idx % 2 == 1 {
            let doubled = d * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        } else {
            sum += d;
        }
    }
    sum % 10 == 0
}

/// IPv4 校验：每段 ≤255；排除本机回环 / 未指定 / 广播地址避免误报。
pub fn validate_ipv4(ip: &str) -> bool {
    if ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "255.255.255.255" {
        return false;
    }
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        p.parse::<u16>()
            .map(|v| v <= 255)
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preset_apply_and_detect() {
        // 均衡 = 内置默认，且 preset_of_specs 能认出该档
        let balanced = apply_preset_to_builtin(default_rule_specs(), PRESET_BALANCED);
        assert_eq!(preset_of_specs(&balanced), PRESET_BALANCED);
        // 保守：身份证仍在守（mask），手机号 / 邮箱 / IP 关闭
        let conservative = apply_preset_to_builtin(balanced, PRESET_CONSERVATIVE);
        let idcard = conservative.iter().find(|s| s.id == "builtin.idcard").unwrap();
        assert!(idcard.enabled && idcard.action == "mask");
        for off in ["builtin.phone", "builtin.email", "builtin.ip"] {
            let s = conservative.iter().find(|x| x.id == off).unwrap();
            assert!(!s.enabled, "{} 应在保守档关闭", off);
        }
        assert_eq!(preset_of_specs(&conservative), PRESET_CONSERVATIVE);
        // 激进：高危三类升级为拦截，IP 重新开启
        let aggressive = apply_preset_to_builtin(default_rule_specs(), PRESET_AGGRESSIVE);
        let idcard_a = aggressive.iter().find(|s| s.id == "builtin.idcard").unwrap();
        assert_eq!(idcard_a.action, "block");
        let ip_a = aggressive.iter().find(|s| s.id == "builtin.ip").unwrap();
        assert!(ip_a.enabled && ip_a.action == "mask");
        assert_eq!(preset_of_specs(&aggressive), PRESET_AGGRESSIVE);
        // 用户改过任何一条内置规则 → custom；自定义规则不影响档位判定
        let mut tweaked = apply_preset_to_builtin(default_rule_specs(), PRESET_BALANCED);
        tweaked[0].action = "warn".to_string();
        assert_eq!(preset_of_specs(&tweaked), PRESET_CUSTOM);
        let with_custom = {
            let mut v = tweaked;
            v.push(RuleSpec {
                id: "custom.zz".into(),
                tag: "CUSTOM".into(),
                name: "自定义".into(),
                regex: "foo".into(),
                action: "block".into(),
                enabled: true,
                builtin: false,
                min_confirm: 1,
            });
            v
        };
        assert_eq!(preset_of_specs(&with_custom), PRESET_CUSTOM);
        // 预设不得动自定义规则
        let mixed = apply_preset_to_builtin(with_custom, PRESET_AGGRESSIVE);
        let cz = mixed.iter().find(|s| s.id == "custom.zz").unwrap();
        assert_eq!(cz.action, "block", "自定义规则的动作为必须保持不变");
    }

    #[test]
    fn test_regex_test_hits_char_offsets() {
        // 字符偏移（非字节）：中文每个字计 1
        let hits = regex_test_hits(r"\d+", "ab12中文34").unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].start, 2);
        assert_eq!(hits[0].len, 2);
        assert_eq!(hits[0].text, "12");
        assert_eq!(hits[1].start, 6); // a b 1 2 中 文 = 6 个字符
        assert_eq!(hits[1].text, "34");
        // 无命中 → 空列表；非法正则 → Err
        assert!(regex_test_hits(r"\d+", "abc").unwrap().is_empty());
        assert!(regex_test_hits("([", "x").is_err());
    }

    #[test]
    fn test_scrub_multi_tag_no_mutation() {
        // 用户实测场景：同一请求正文命中两类规则（自定义 CUSTOM + 内置 PHONE），
        // 替换后必须产生两个完整占位符，绝不允许出现「占位符缺闭合 + 原文残留」。
        let vault = crate::vault::Vault::new();
        let specs = vec![
            RuleSpec {
                id: "custom.1".into(),
                tag: "CUSTOM".into(),
                name: "自定义姓名".into(),
                regex: "张三".into(),
                action: "mask".into(),
                enabled: true,
                builtin: false,
                min_confirm: 1,
            },
            RuleSpec {
                id: "builtin.phone".into(),
                tag: "PHONE".into(),
                name: "手机号".into(),
                regex: r"1[3-9]\d{9}".into(),
                action: "mask".into(),
                enabled: true,
                builtin: true,
                min_confirm: 1,
            },
        ];
        let det = Detector::from_specs(&specs).unwrap();
        let text = "你好，我叫张三，我的电话是15611827034，请你告诉我，我的电话是多少？";
        let (out, hits) = det.scrub(text, |orig, tag| {
            vault.get_or_create("sess", orig, tag)
        });
        println!("scrub out = {}", out);
        assert_eq!(hits.len(), 2, "应命中 CUSTOM 与 PHONE 两类");
        let ph_custom = vault.get_or_create("sess", "张三", "CUSTOM");
        let ph_phone = vault.get_or_create("sess", "15611827034", "PHONE");
        assert!(out.contains(&ph_custom), "须含 CUSTOM 占位符: {}", out);
        assert!(out.contains(&ph_phone), "须含 PHONE 占位符: {}", out);
        assert!(!out.contains("张三"), "原文不得残留: {}", out);
        assert!(!out.contains("15611827034"), "原文不得残留: {}", out);
        // 占位符计数：原文两处 → 两个完整占位符
        assert_eq!(out.matches("[[PII:").count(), 2);
        assert_eq!(out.matches("]]").count(), 2);
    }

    #[test]
    fn test_id_card_valid() {
        // 手算验证：110101199003070572
        // 前 17 位 1,1,0,1,0,1,1,9,9,0,0,3,0,7,0,5,7
        // 加权和 = 7+9+0+5+0+4+2+9+54+0+0+27+0+35+0+20+14 = 186
        // 186 % 11 = 10 → map "10X98765432"[10] = '2' ✓
        assert!(validate_id_card_cn("110101199003070572"));
    }

    #[test]
    fn test_id_card_invalid_check_digit() {
        // 校验位错误（'2' 改为 '3'）→ 不命中
        let det = Detector::with_default_rules();
        let text = "我的身份证是110101199003070573请查收";
        let hits = det.scan(text);
        assert!(
            !hits.iter().any(|h| h.tag == "IDCARD"),
            "校验位错误的身份证不应命中"
        );
    }

    #[test]
    fn test_id_card_hit() {
        let det = Detector::with_default_rules();
        let text = "身份证号110101199003070572是有效的";
        let hits = det.scan(text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].tag, "IDCARD");
        assert_eq!(hits[0].start, 4);
        assert_eq!(hits[0].text_len, 18);
        assert_eq!(hits[0].action, Action::Mask);
    }

    #[test]
    fn test_luhn() {
        assert!(validate_luhn("4242424242424242"));
        assert!(!validate_luhn("4242424242424241"));
    }

    #[test]
    fn test_bank_card_hit() {
        let det = Detector::with_default_rules();
        let text = "卡号4242424242424242";
        let hits = det.scan(text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].tag, "BANKCARD");
        assert_eq!(hits[0].start, 2);
        assert_eq!(hits[0].text_len, 16);
    }

    #[test]
    fn test_phone_hit_and_boundary() {
        let det = Detector::with_default_rules();
        // 合法手机号命中
        let hits = det.scan("打我电话13800138000谢谢");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].tag, "PHONE");
        assert_eq!(hits[0].start, 4);
        assert_eq!(hits[0].text_len, 11);
        // 长数字中截取不命中（\b 边界保护）
        let hits2 = det.scan("订单号2380013800012345678");
        assert!(
            !hits2.iter().any(|h| h.tag == "PHONE"),
            "长数字内的 11 位片段不应命中手机号"
        );
    }

    #[test]
    fn test_email_hit() {
        let det = Detector::with_default_rules();
        let text = "发送到 user.name@example.com 即可";
        let hits = det.scan(text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].tag, "EMAIL");
        assert_eq!(hits[0].start, 4);
        assert_eq!(hits[0].text_len, "user.name@example.com".len());
    }

    #[test]
    fn test_api_key_hit() {
        let det = Detector::with_default_rules();
        let text = "key: sk-abc123ABC456def789GHI012 有泄露风险";
        let hits = det.scan(text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].tag, "APIKEY");
        // sk- + 24 位字母数字 = 27 字符
        assert_eq!(hits[0].text_len, 27);
    }

    #[test]
    fn test_api_key_akia() {
        let det = Detector::with_default_rules();
        let text = "aws key AKIAIOSFODNN7EXAMPLE inside";
        let hits = det.scan(text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].tag, "APIKEY");
        assert_eq!(hits[0].text_len, "AKIAIOSFODNN7EXAMPLE".len());
    }

    #[test]
    fn test_ip_hit_and_invalid() {
        assert!(validate_ipv4("8.8.8.8"));
        assert!(!validate_ipv4("300.1.1.1"));
        assert!(!validate_ipv4("127.0.0.1"));
        assert!(!validate_ipv4("0.0.0.0"));
        assert!(!validate_ipv4("255.255.255.255"));

        // IP 规则**默认关闭**（版本号 1.2.3.4 会被当 IP 误伤），
        // 默认规则集下不应命中
        let det = Detector::with_default_rules();
        assert!(
            det.scan("服务器 8.8.8.8 返回正常").is_empty(),
            "IP 默认关闭时不应命中"
        );
        assert!(
            det.scan("版本号 1.2.3.4 正常保留").is_empty(),
            "版本号形态不得被误伤"
        );

        // 手动开启 IP 规则后应正常工作，且校验器仍然过滤非法/保留地址
        let specs: Vec<RuleSpec> = default_rule_specs()
            .into_iter()
            .map(|mut s| {
                if s.id == "builtin.ip" {
                    s.enabled = true;
                }
                s
            })
            .collect();
        let det_on = Detector::from_specs(&specs).expect("内置规则必须可编译");
        let hits = det_on.scan("服务器 8.8.8.8 返回正常");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].tag, "IP");
        assert!(det_on.scan("坏地址 300.1.1.1 应忽略").is_empty());
    }

    #[test]
    fn test_builtin_ip_disabled_by_default() {
        let ip = default_rule_specs()
            .into_iter()
            .find(|s| s.id == "builtin.ip")
            .expect("IP 内置规则必须存在");
        assert!(!ip.enabled, "IP 规则默认应关闭");
    }

    #[test]
    fn test_scrub_mixed_phone_email() {
        let det = Detector::with_default_rules();
        let text = "联系张三 13800138000 或 zs@test.cn 确认";
        let (out, hits) = det.scrub(text, |_orig, tag| {
            format!("[[PII:{}:fake]]", tag)
        });
        assert_eq!(hits.len(), 2);
        assert!(hits[0].tag == "PHONE");
        assert!(hits[1].tag == "EMAIL");
        assert_eq!(
            out,
            "联系张三 [[PII:PHONE:fake]] 或 [[PII:EMAIL:fake]] 确认"
        );
    }

    #[test]
    fn test_scrub_preserves_non_pii_text() {
        let det = Detector::with_default_rules();
        let text = "你好，我的手机是13912345678，请回电。";
        let (out, hits) = det.scrub(text, |_, tag| format!("<{}>", tag));
        assert_eq!(hits.len(), 1);
        assert_eq!(out, "你好，我的手机是<PHONE>，请回电。");
    }

    #[test]
    fn test_scrub_overlap_keeps_first() {
        let det = Detector::with_default_rules();
        // 直接验证去重逻辑：同一文本两个规则命中同一段时只保留先排序者。
        let text = "13800138000";
        let (out, hits) = det.scrub(text, |orig, _| orig.to_string());
        // 仅手机号规则命中，原样返回
        assert_eq!(hits.len(), 1);
        assert_eq!(out, "13800138000");
    }

    // ─────────── 规则规格 / 自定义规则 ───────────

    #[test]
    fn test_default_specs_compile_and_builtin_flags() {
        let specs = default_rule_specs();
        assert_eq!(specs.len(), 6);
        assert!(specs.iter().all(|s| s.builtin));
        let det = Detector::from_specs(&specs).unwrap();
        assert_eq!(det.scan("a@b.com").len(), 1);
    }

    #[test]
    fn test_custom_rule_from_specs() {
        let mut specs = default_rule_specs();
        specs.push(RuleSpec {
            id: "custom.test01".to_string(),
            tag: "PROJECT".to_string(),
            name: "项目代号".to_string(),
            regex: "阿尔法计划".to_string(),
            action: "mask".to_string(),
            enabled: true,
            builtin: false,
            min_confirm: 1,
        });
        let det = Detector::from_specs(&specs).unwrap();
        let hits = det.scan("这是阿尔法计划的文档");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].tag, "PROJECT");
        let (out, _) = det.scrub("阿尔法计划启动", |o, tag| {
            format!("{{{}:{}}}", tag, o)
        });
        assert_eq!(out, "{PROJECT:阿尔法计划}启动");
    }

    #[test]
    fn test_invalid_regex_rejected() {
        let mut specs = default_rule_specs();
        specs[0].regex = "([bad".to_string();
        assert!(
            Detector::from_specs(&specs).is_err(),
            "非法正则必须返回 Err 而非 panic"
        );
    }

    #[test]
    fn test_edit_builtin_action_and_enabled() {
        // 编辑内置规则：手机号动作改为拦截
        let mut specs = default_rule_specs();
        specs
            .iter_mut()
            .find(|s| s.tag == "PHONE")
            .unwrap()
            .action = "block".to_string();
        let det = Detector::from_specs(&specs).unwrap();
        let hits = det.scan("打我电话13800138000谢谢");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].action, Action::Block);

        // 关闭邮箱规则后不再命中
        let mut specs = default_rule_specs();
        specs
            .iter_mut()
            .find(|s| s.tag == "EMAIL")
            .unwrap()
            .enabled = false;
        let det = Detector::from_specs(&specs).unwrap();
        assert!(det.scan("a@b.com").is_empty());
    }

    #[test]
    fn test_reset_to_default_restores_behavior() {
        // 修改后再「恢复默认」→ 行为回到默认
        let mut edited = default_rule_specs();
        edited.iter_mut().find(|s| s.tag == "PHONE").unwrap().regex =
            r"139\d{8}".to_string(); // 收窄
        let det = Detector::from_specs(&edited).unwrap();
        assert!(det.scan("13800138000").is_empty(), "收窄后的规则不应命中 138 号段");

        let restored = builtin_spec_by_id("builtin.phone").unwrap();
        assert_eq!(restored.regex, r"1[3-9]\d{9}");
        assert!(restored.enabled);
    }

    // ─────────── Block 确认闸门 ───────────

    #[test]
    fn test_rule_spec_serde_backward_compatible() {
        // 旧持久化 JSON（kv 里的 Vec<RuleSpec>）不含 min_confirm → serde default 兜底为 1
        let legacy = r#"[{"id":"builtin.idcard","tag":"IDCARD","name":"身份证号","regex":"\\d","action":"mask","enabled":true,"builtin":true}]"#;
        let specs: Vec<RuleSpec> = serde_json::from_str(legacy).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].min_confirm, 1);
    }

    #[test]
    fn test_compile_min_confirm_floor_for_validated_block() {
        // 编译期下限：校验器类规则（身份证 / 银行卡 / IP）拦截时 min_confirm ≥ 2；
        // 无校验器（apikey）与 Mask 动作（手机号）不受下限影响
        let aggressive = apply_preset_to_builtin(default_rule_specs(), PRESET_AGGRESSIVE);
        let det = Detector::from_specs(&aggressive).unwrap();
        let rules = &det.rules;
        let idcard = rules.iter().find(|r| r.id == "builtin.idcard").unwrap();
        assert_eq!(idcard.min_confirm, 2, "身份证（校验器 + Block）下限 2");
        let bankcard = rules.iter().find(|r| r.id == "builtin.bankcard").unwrap();
        assert_eq!(bankcard.min_confirm, 2, "银行卡（校验器 + Block）下限 2");
        let apikey = rules.iter().find(|r| r.id == "builtin.apikey").unwrap();
        assert_eq!(apikey.min_confirm, 1, "apikey 无校验器，不做下限提升");
        assert_eq!(apikey.validated, false);
        let phone = rules.iter().find(|r| r.id == "builtin.phone").unwrap();
        assert_eq!(phone.min_confirm, 1, "Mask 动作不提升下限");
        let idcard_spec = aggressive.iter().find(|s| s.id == "builtin.idcard").unwrap();
        assert_eq!(idcard_spec.min_confirm, 1, "规格本身保持用户值 1，下限只在编译期生效");
    }

    #[test]
    fn test_custom_block_rule_respects_spec_min_confirm() {
        // 自定义 Block 规则（无校验器 tag）：min_confirm = spec 值，不做提升
        let mut specs = default_rule_specs();
        specs.push(RuleSpec {
            id: "custom.blk01".to_string(),
            tag: "SECRET".to_string(),
            name: "项目代号".to_string(),
            regex: "阿尔法计划".to_string(),
            action: "block".to_string(),
            enabled: true,
            builtin: false,
            min_confirm: 3,
        });
        let det = Detector::from_specs(&specs).unwrap();
        let rule = det.rules.iter().find(|r| r.id == "custom.blk01").unwrap();
        assert_eq!(rule.min_confirm, 3);
        assert_eq!(rule.validated, false);
        // 命中透出 min_confirm / rule_id / validated
        let hits = det.scan("这是阿尔法计划的文档");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "custom.blk01");
        assert_eq!(hits[0].min_confirm, 3);
        assert_eq!(hits[0].validated, false);
    }
}
