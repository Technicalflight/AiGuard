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
}

/// 编译后的运行时规则（内部结构，不对外暴露）。
#[derive(Clone)]
struct Rule {
    tag: String,
    regex: Regex,
    validate: Option<fn(&str) -> bool>,
    /// 命中前后紧邻 ASCII 数字时拒绝（身份证/手机号/银行卡防长数字串误截）
    digit_adjacent: bool,
    action: Action,
    enabled: bool,
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
    let tag = spec.tag.trim().to_ascii_uppercase();
    if tag.is_empty() {
        return Err(format!("规则「{}」的标签不能为空", spec.name));
    }
    Ok(Rule {
        tag,
        regex,
        validate: builtin_validator(spec.tag.trim().to_ascii_uppercase().as_str()),
        digit_adjacent: builtin_digit_adjacent(spec.tag.trim().to_ascii_uppercase().as_str()),
        action: Action::from_str(&spec.action),
        enabled: spec.enabled,
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

/// 检测引擎。
/// `Clone` 成本很低（`regex::Regex` 内部是 Arc），便于共享给流式还原管道。
#[derive(Clone)]
pub struct Detector {
    rules: Vec<Rule>,
}

impl Detector {
    /// 由规格列表编译构建；任一正则非法即返回 Err。
    pub fn from_specs(specs: &[RuleSpec]) -> Result<Detector, String> {
        let mut rules = Vec::with_capacity(specs.len());
        for spec in specs {
            rules.push(compile_rule(spec)?);
        }
        Ok(Detector { rules })
    }

    /// 使用全部内置默认规则构建（enabled = true，action = Mask）。
    pub fn with_default_rules() -> Detector {
        Self::from_specs(&default_rule_specs()).expect("内置规则必须可编译")
    }

    /// 扫描文本，返回全部有效命中（已按 start 升序，不重叠）。
    pub fn scan(&self, text: &str) -> Vec<Hit> {
        self.collect_hits(text)
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
                });
            }
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
            },
            RuleSpec {
                id: "builtin.phone".into(),
                tag: "PHONE".into(),
                name: "手机号".into(),
                regex: r"1[3-9]\d{9}".into(),
                action: "mask".into(),
                enabled: true,
                builtin: true,
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
}
