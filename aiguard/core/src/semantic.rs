//! 语义检测层：正则规则之外的第二级引擎（启发式 NER + 熵值 + 白名单词表）。
//!
//! **定位：保守启发式，独立开关，全部默认保守。** 语义类信息（姓名 / 地址 / 机构名）
//! 无法用单一正则穷举，这里用「粗匹配正则 + 后置回调校验」的方式收敛误报——
//! 与项目现有哲学一致：形态可判的才报，判不准的宁可漏报。
//! 真正的 NER 模型（ONNX 量化）留作可选加载能力，当前为纯启发式、零模型依赖。
//!
//! - [`SemanticConfig`]: 三级流水线开关（熵值 / 姓名 / 机构 / 地址）+ 产品代号白名单；
//! - [`SemanticEngine`]: 编译后的检测引擎，产出字节偏移命中，
//!   由 [`crate::detector::Detector`] 统一转换为字符偏移 `Hit` 并做重叠去重
//!   （正则层先产出，稳定排序保证正则命中优先占位）。
//!
//! 语义层命中**恒为 Mask 动作**：启发式判不准意图，拦截的代价远大于脱敏。
//!
//! 误报控制策略（每类检测器独立说明见各常量注释）：
//! - 姓名：百家姓 + 1~2 汉字粗匹配，**必须有上下文触发**（称谓后缀 / 自称 / 指派动词），
//!   并排除常见词与行政区划名；
//! - 地址：行政区划词典（省级 + 主要城市）锚定的区县结构，或「街道 + 门牌号」强结构；
//! - 机构：强后缀词表锚定，前缀做代词 / 方位词清洗与黑名单校验；
//! - 熵值：高熵 token（≥3 类字符且 Shannon 熵达标），排除纯 hex（哈希 / git sha）
//!   与标准 UUID——这两类在对话中高频出现且不应被脱敏。

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// 语义检测层配置（持久化到 KV，前端「语义检测」卡片编辑）。
///
/// 默认值刻意保守：**地址开**（结构强、误报低），其余默认关——
/// 姓名 / 机构启发式与熵值检测的误报会直接改写用户文本，交由用户显式启用。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SemanticConfig {
    /// 高熵可疑串（无法归类的凭据形态）
    pub entropy: bool,
    /// 中文姓名启发式
    pub person: bool,
    /// 机构名 / 学校名启发式
    pub org: bool,
    /// 地址（行政区划 + 街道门牌）
    pub address: bool,
    /// 产品名 / 项目代号白名单（用户提供，命中即脱敏）
    pub terms: Vec<String>,
}

impl Default for SemanticConfig {
    fn default() -> Self {
        SemanticConfig {
            entropy: false,
            person: false,
            org: false,
            address: true,
            terms: Vec::new(),
        }
    }
}

impl SemanticConfig {
    /// 清洗：去空白、去重、截断超长词条、限制总数量。
    /// 保存前与加载后都应调用（幂等）。
    pub fn sanitize(&mut self) {
        self.terms.retain(|t| {
            let t = t.trim();
            !t.is_empty() && t.chars().count() <= 64
        });
        for t in &mut self.terms {
            *t = t.trim().to_string();
        }
        // 去重（保留首次出现）
        let mut seen: HashSet<String> = HashSet::new();
        self.terms.retain(|t| seen.insert(t.to_lowercase()));
        // 上限：白名单不是正则库，条目过多只拖慢匹配
        self.terms.truncate(500);
    }

    /// 是否有任何检测项处于开启状态（Detector 侧短路用）。
    pub fn any_enabled(&self) -> bool {
        self.entropy || self.person || self.org || self.address || !self.terms.is_empty()
    }
}

/// 语义层命中（字节偏移）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHit {
    /// 起始字节偏移
    pub start: usize,
    /// 长度（字节数）
    pub len: usize,
    /// 占位符标签（PERSON / ADDRESS / ORG / HIGH_ENTROPY / CUSTOM_TERM）
    pub tag: &'static str,
}

/// 编译好的语义检测引擎。编译失败的单项降级为不检测（永不 panic）。
#[derive(Clone)]
pub struct SemanticEngine {
    cfg: SemanticConfig,
    entropy_re: Option<Regex>,
    person_re: Option<Regex>,
    /// 姓名命中后紧跟称谓的锚定正则
    person_title_re: Option<Regex>,
    address_area_re: Option<Regex>,
    address_street_re: Option<Regex>,
    org_re: Option<Regex>,
}

// ─────────────────────────── 词表与模式 ───────────────────────────

/// 常见单姓（百家姓高频段）+ 复姓。拼成正则 alternation 时按字面量处理。
const SURNAMES: &[&str] = &[
    "李", "王", "张", "刘", "陈", "杨", "黄", "赵", "吴", "周", "徐", "孙", "马", "朱", "胡",
    "郭", "何", "林", "罗", "高", "郑", "梁", "谢", "宋", "唐", "许", "韩", "冯", "邓", "曹",
    "彭", "曾", "肖", "田", "董", "潘", "袁", "蔡", "蒋", "余", "于", "杜", "叶", "程", "苏",
    "魏", "吕", "丁", "任", "沈", "姚", "卢", "姜", "崔", "钟", "谭", "陆", "汪", "范", "金",
    "石", "廖", "贾", "夏", "韦", "付", "方", "白", "邹", "孟", "熊", "秦", "邱", "江", "尹",
    "薛", "闫", "段", "雷", "侯", "龙", "史", "陶", "黎", "贺", "顾", "毛", "郝", "龚", "邵",
    "万", "钱", "严", "覃", "武", "戴", "莫", "孔", "向", "汤",
];

const COMPOUND_SURNAMES: &[&str] = &[
    "欧阳", "司马", "上官", "诸葛", "东方", "皇甫", "令狐", "慕容", "司徒", "司空", "申屠",
    "公孙", "尉迟", "长孙", "宇文", "轩辕",
];

/// 姓名命中后紧跟的称谓（强触发）。
const TITLES_AFTER: &str = "(?:先生|女士|老师|经理|医生|律师|教授|博士|工程师|会计|护士|司机|书记|主任|院长|校长|总|工|姐|哥|叔|婶|姨)";

/// 姓名命中之前的上下文触发词（命中前 8 字符窗口内出现即视为指人）。
const CONTEXT_BEFORE: &str =
    "我叫|我是|本人|姓名|联系人|委托人|紧急联系人|申请人|负责人|经办人|监护人|家属|联系|联系一下|找|找到|问问|问一下|告诉|转告|请|让|帮|替|向|跟|和|给";

/// 姓名粗匹配排除：命中文本本身是这些常见词时不报。
const PERSON_BLOCKLIST: &[&str] = &[
    "人民", "人大", "大王", "小王", "老王", "大李", "小李", "老张", "小张", "老刘", "小刘",
    "马上", "王子", "公主", "王法", "王国", "长城", "长江", "黄河", "中山", "中西", "东方",
    "北方", "南方", "西安", "东安", "北海", "南海", "东海", "西山", "东山", "南山", "宁波",
    "上海", "北京", "南京", "武汉", "长沙", "重庆", "成都", "天津", "福州", "兰州", "郑州",
    "合肥", "南昌", "贵阳", "西宁", "银川", "大同", "天山", "泰山", "黄山", "恒山", "华山",
    "平安", "长安", "建安", "延安", "淮安", "宝安", "西安门", "天王", "天皇", "后王",
];

/// 省级行政区 + 主要城市（地址锚定词典；区县级不收录——规模失控且「XX区」结构已足够）。
const REGIONS: &[&str] = &[
    // 直辖市
    "北京", "天津", "上海", "重庆",
    // 省
    "河北", "山西", "辽宁", "吉林", "黑龙江", "江苏", "浙江", "安徽", "福建", "江西", "山东",
    "河南", "湖北", "湖南", "广东", "海南", "四川", "贵州", "云南", "陕西", "甘肃", "青海",
    // 自治区
    "内蒙古", "广西", "西藏", "宁夏", "新疆",
    // 特别行政区
    "香港", "澳门", "台湾",
    // 省会 / 自治区首府
    "石家庄", "太原", "呼和浩特", "沈阳", "长春", "哈尔滨", "南京", "杭州", "合肥", "福州",
    "南昌", "济南", "郑州", "武汉", "长沙", "广州", "南宁", "海口", "成都", "贵阳", "昆明",
    "拉萨", "西安", "兰州", "西宁", "银川", "乌鲁木齐",
    // 主要城市
    "深圳", "苏州", "青岛", "大连", "厦门", "宁波", "无锡", "佛山", "东莞", "珠海", "温州",
    "常州", "南通", "烟台", "潍坊", "泉州", "漳州", "徐州", "临沂", "保定", "廊坊", "惠州",
    "绍兴", "嘉兴", "金华", "台州", "洛阳", "襄阳", "宜昌", "岳阳",
];

/// 机构强后缀（出现即锚定；前缀另做清洗校验）。
const ORG_SUFFIXES: &str =
    "大学|学院|中学|小学|幼儿园|医院|银行|集团|公司|事务所|研究院|研究所|博物馆|出版社|大学城";

/// 机构前缀黑名单（剥掉首部功能字后，剩余前缀含这些词即拒绝）。
const ORG_PREFIX_BLOCKLIST: &[&str] = &[
    "我们", "你们", "他们", "她们", "咱们", "大家", "这家", "那家", "本市", "我省", "我县",
    "我区", "全国", "全省", "全市", "一个", "一家", "两家", "三家", "什么", "哪个", "哪家",
    "自己", "别人", "人家", "他的", "她的",
];

/// 地址区县结构中，命中之后紧跟这些字时视为非地址（上海市民 / 北京人口…）。
const AREA_SUFFIX_BAD: &str = "民人口话腔味式样风格";

// ─────────────────────────── 引擎 ───────────────────────────

impl SemanticEngine {
    /// 由配置构建；编译失败的单项降级为 None（该项不检测）。
    pub fn new(cfg: &SemanticConfig) -> SemanticEngine {
        // 复姓在前（长词优先，避免「欧」被单姓表截胡——单姓表里没有「欧」，保险起见仍前置）
        let person_alt = format!(
            "(?:{}|{})[一-龥]{{1,2}}",
            COMPOUND_SURNAMES.join("|"),
            SURNAMES.join("|")
        );
        SemanticEngine {
            cfg: cfg.clone(),
            entropy_re: Some(
                Regex::new(r"[A-Za-z0-9+/=_-]{16,128}").expect("熵值正则必须可编译"),
            ),
            person_re: Regex::new(&person_alt).ok(),
            person_title_re: Regex::new(&format!("^{}", TITLES_AFTER)).ok(),
            address_area_re: Some(
                Regex::new(&format!(
                    "(?:{})[一-龥]{{0,8}}(?:区|县|镇|乡|旗)",
                    REGIONS.join("|")
                ))
                .expect("区划正则必须可编译"),
            ),
            address_street_re: Some(
                Regex::new(r"[一-龥]{1,10}(?:大道|大街|路|街|道|巷)[0-9]{1,5}号")
                    .expect("街道正则必须可编译"),
            ),
            org_re: Some(Regex::new(&format!("[一-龥A-Za-z0-9]{{2,14}}(?:{})", ORG_SUFFIXES))
                .expect("机构正则必须可编译")),
        }
    }

    /// 全关的空引擎（测试 / 未配置时用）。
    pub fn disabled() -> SemanticEngine {
        SemanticEngine::new(&SemanticConfig::default())
    }

    /// 扫描文本，返回全部语义命中（字节偏移，未排序未去重——由调用方统一处理）。
    pub fn hits(&self, text: &str) -> Vec<RawHit> {
        let mut out: Vec<RawHit> = Vec::new();
        if !self.cfg.any_enabled() || text.is_empty() {
            return out;
        }
        if self.cfg.entropy {
            self.scan_entropy(text, &mut out);
        }
        if self.cfg.person {
            self.scan_person(text, &mut out);
        }
        if self.cfg.org {
            self.scan_org(text, &mut out);
        }
        if self.cfg.address {
            self.scan_address(text, &mut out);
        }
        if !self.cfg.terms.is_empty() {
            self.scan_terms(text, &mut out);
        }
        out
    }

    // ── 高熵 token ──

    fn scan_entropy(&self, text: &str, out: &mut Vec<RawHit>) {
        let Some(re) = &self.entropy_re else { return };
        for m in re.find_iter(text) {
            let s = m.as_str();
            if looks_like_high_entropy(s) {
                out.push(RawHit { start: m.start(), len: s.len(), tag: "HIGH_ENTROPY" });
            }
        }
    }

    // ── 中文姓名 ──

    fn scan_person(&self, text: &str, out: &mut Vec<RawHit>) {
        let Some(re) = &self.person_re else { return };
        for m in re.find_iter(text) {
            let s = m.as_str();
            // 排除常见词与行政区划名（地址层会处理后者）
            if PERSON_BLOCKLIST.contains(&s) || REGIONS.contains(&s) {
                continue;
            }
            let start = m.start();
            let end = m.end();
            // 强触发 1：命中后紧跟称谓
            let after: String = text[end..].chars().take(3).collect();
            let after_hit = self
                .person_title_re
                .as_ref()
                .map(|r| r.is_match(&after))
                .unwrap_or(false);
            // 强触发 2：命中前 8 个字符的窗口内出现指人上下文
            let chars_before = text[..start].chars().count();
            let skip = chars_before.saturating_sub(8);
            let before: String = text[..start].chars().skip(skip).collect();
            let ctx = CONTEXT_BEFORE.split('|').any(|w| before.contains(w));
            if after_hit || ctx {
                out.push(RawHit { start, len: s.len(), tag: "PERSON" });
            }
        }
    }

    // ── 机构名 ──

    fn scan_org(&self, text: &str, out: &mut Vec<RawHit>) {
        let Some(re) = &self.org_re else { return };
        // 功能字：逐个剥离命中首部，直到剩余前缀以实义开头
        let leading_fn: &[&str] = &[
            "在", "于", "从", "到", "去", "进", "出", "和", "与", "及", "或", "的", "了", "是",
            "有", "这", "那", "某", "各", "每", "该", "家", "间", "个", "所", "把", "被", "向",
            "对", "为", "以", "按", "据", "经", "由",
        ];
        for m in re.find_iter(text) {
            let s = m.as_str();
            // 剥掉后缀取前缀
            let prefix = ORG_SUFFIXES
                .split('|')
                .find(|suf| s.ends_with(suf))
                .map(|suf| &s[..s.len() - suf.len()])
                .unwrap_or(s);
            // 逐字剥离首部功能字
            let mut core = prefix;
            loop {
                let Some(ch) = core.chars().next() else { break };
                let ch = ch.to_string();
                if leading_fn.contains(&ch.as_str()) {
                    core = &core[ch.len()..];
                } else {
                    break;
                }
            }
            // 剩余前缀过短 / 含黑名单词 / 纯数字 → 拒
            if core.chars().count() < 2 {
                continue;
            }
            if ORG_PREFIX_BLOCKLIST.iter().any(|w| core.contains(w)) {
                continue;
            }
            if core.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            out.push(RawHit { start: m.start(), len: s.len(), tag: "ORG" });
        }
    }

    // ── 地址 ──

    fn scan_address(&self, text: &str, out: &mut Vec<RawHit>) {
        if let Some(re) = &self.address_area_re {
            for m in re.find_iter(text) {
                let s = m.as_str();
                // 命中后紧跟「民 / 人 / 口 / 话…」→ 上海市民 / 北京人口 类，拒
                let after = text[m.end()..].chars().next().map(|c| c.to_string());
                if after.as_deref().map(|c| AREA_SUFFIX_BAD.contains(c)).unwrap_or(false) {
                    continue;
                }
                // 命中内部含「区间 / 小区 / 社区间」类拼接陷阱：市场区间 / 老小区间——
                // 区词表锚定后这种几乎不可能，仅防御「区间」结尾
                if s.ends_with("区间") {
                    continue;
                }
                out.push(RawHit { start: m.start(), len: s.len(), tag: "ADDRESS" });
            }
        }
        if let Some(re) = &self.address_street_re {
            for m in re.find_iter(text) {
                out.push(RawHit { start: m.start(), len: m.as_str().len(), tag: "ADDRESS" });
            }
        }
    }

    // ── 产品代号白名单 ──

    fn scan_terms(&self, text: &str, out: &mut Vec<RawHit>) {
        for term in &self.cfg.terms {
            if term.is_empty() {
                continue;
            }
            let is_ascii_word = term.chars().all(|c| c.is_ascii_alphanumeric());
            if is_ascii_word {
                // ASCII 词条：大小写不敏感 + 词边界（前后不能是字母数字）
                let lower_term = term.to_lowercase();
                let lower_text = text.to_lowercase();
                let bytes = lower_text.as_bytes();
                let mut from = 0usize;
                while let Some(pos) = lower_text[from..].find(&lower_term) {
                    let s = from + pos;
                    let e = s + lower_term.len();
                    let word = |b: u8| b.is_ascii_alphanumeric();
                    let ok = (s == 0 || !word(bytes[s - 1])) && (e >= bytes.len() || !word(bytes[e]));
                    if ok {
                        out.push(RawHit { start: s, len: e - s, tag: "CUSTOM_TERM" });
                    }
                    from = s + lower_term.len();
                    if from >= lower_text.len() {
                        break;
                    }
                }
            } else {
                // 中文 / 混合词条：直接子串匹配
                for (pos, _) in text.match_indices(term.as_str()) {
                    out.push(RawHit { start: pos, len: term.len(), tag: "CUSTOM_TERM" });
                }
            }
        }
    }
}

/// 高熵判定：Shannon 熵 ≥ 3.3 bits/char、字符类别 ≥ 3（大写 / 小写 / 数字 / 其它）、
/// 排除纯 hex（MD5 / SHA / git sha 这类校验和不该被脱敏）与标准 UUID。
fn looks_like_high_entropy(s: &str) -> bool {
    // 标准 UUID / git sha 形态排除
    if s.len() == 36 && s.as_bytes()[8] == b'-' {
        return false;
    }
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_other = false;
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' => has_upper = true,
            b'a'..=b'z' => has_lower = true,
            b'0'..=b'9' => has_digit = true,
            _ => has_other = true,
        }
    }
    let classes = has_upper as usize + has_lower as usize + has_digit as usize + has_other as usize;
    if classes < 3 {
        return false;
    }
    // 纯 hex（大小写一致的全 hex 串）：哈希 / 校验和，不报
    let hexish = s.bytes().all(|b| b.is_ascii_hexdigit());
    if hexish {
        return false;
    }
    // Shannon 熵（按字节；对 base64 型 token 足够）
    let mut freq = [0usize; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let n = s.len() as f64;
    let entropy: f64 = freq
        .iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / n;
            -p * p.log2()
        })
        .sum();
    entropy >= 3.3
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(cfg: &SemanticConfig) -> SemanticEngine {
        SemanticEngine::new(cfg)
    }

    fn cfg(all: bool) -> SemanticConfig {
        SemanticConfig {
            entropy: all,
            person: all,
            org: all,
            address: all,
            terms: Vec::new(),
        }
    }

    // ── 配置 ──

    #[test]
    fn test_config_sanitize_and_default() {
        let mut c = SemanticConfig::default();
        assert!(c.address, "地址默认开");
        assert!(!c.person && !c.org && !c.entropy, "其余默认关");
        c.terms = vec!["  Atlas  ".to_string(), "atlas".to_string(), String::new(), "x".repeat(80)];
        c.sanitize();
        assert_eq!(c.terms, vec!["Atlas".to_string()], "trim + 大小写去重 + 过滤空/超长");
    }

    // ── 熵值 ──

    #[test]
    fn test_entropy_hits_and_skips() {
        let e = engine(&cfg(true));
        // sk- 风格 API key：三类字符 + 高熵 → 报
        let out = e.hits("my key is sk-Live9xQm2RtV8bN4cD6fG0hJ2kL4mN6pQ8rS0tUvWx");
        assert!(out.iter().any(|h| h.tag == "HIGH_ENTROPY"), "{:?}", out);
        // git sha（纯 hex 40）→ 不报
        let out2 = e.hits("commit a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0 fixed");
        assert!(out2.iter().all(|h| h.tag != "HIGH_ENTROPY"), "{:?}", out2);
        // UUID → 不报
        let out3 = e.hits("id 550e8400-e29b-41d4-a716-446655440000 done");
        assert!(out3.iter().all(|h| h.tag != "HIGH_ENTROPY"), "{:?}", out3);
        // 普通英文短语 → 不报
        let out4 = e.hits("hello world this is plain text");
        assert!(out4.iter().all(|h| h.tag != "HIGH_ENTROPY"), "{:?}", out4);
    }

    // ── 姓名 ──

    #[test]
    fn test_person_with_context() {
        let e = engine(&cfg(true));
        // 称谓后缀 → 报
        let out = e.hits("王建国先生说这个方案不错");
        assert!(out.iter().any(|h| h.tag == "PERSON"), "{:?}", out);
        // 自称触发 → 报
        let out2 = e.hits("我叫李明远，负责这个项目");
        assert!(out2.iter().any(|h| h.tag == "PERSON"), "{:?}", out2);
        // 裸姓名（无上下文）→ 保守不报
        let out3 = e.hits("王建国");
        assert!(out3.iter().all(|h| h.tag != "PERSON"), "{:?}", out3);
        // 常见词 → 不报
        let out4 = e.hits("马上出发");
        assert!(out4.iter().all(|h| h.tag != "PERSON"), "{:?}", out4);
    }

    // ── 地址 ──

    #[test]
    fn test_address_area_and_street() {
        let e = engine(&cfg(true));
        // 行政区划结构
        let out = e.hits("公司在北京市朝阳区，欢迎来玩");
        assert!(out.iter().any(|h| h.tag == "ADDRESS"), "{:?}", out);
        // 街道门牌
        let out2 = e.hits("寄到杭州市文一西路969号即可");
        assert!(out2.iter().any(|h| h.tag == "ADDRESS"), "{:?}", out2);
        // 上海市民 → 区划层不报
        let out3 = e.hits("上海市民请注意");
        assert!(out3.iter().all(|h| h.tag != "ADDRESS"), "{:?}", out3);
        // 市场区间 → 不报
        let out4 = e.hits("看下市场区间走势");
        assert!(out4.iter().all(|h| h.tag != "ADDRESS"), "{:?}", out4);
    }

    // ── 机构 ──

    #[test]
    fn test_org_suffix_anchor() {
        let e = engine(&cfg(true));
        let out = e.hits("他在北京大学读书");
        assert!(out.iter().any(|h| h.tag == "ORG"), "{:?}", out);
        let out2 = e.hits("腾讯公司和阿里集团合作");
        assert!(out2.iter().any(|h| h.tag == "ORG"), "{:?}", out2);
        // 代词前缀 → 不报
        let out3 = e.hits("我们公司很小");
        assert!(out3.iter().all(|h| h.tag != "ORG"), "{:?}", out3);
        let out4 = e.hits("这个公司靠谱");
        assert!(out4.iter().all(|h| h.tag != "ORG"), "{:?}", out4);
    }

    // ── 产品代号 ──

    #[test]
    fn test_custom_terms() {
        let mut c = cfg(false);
        c.terms = vec!["星舰计划".to_string(), "atlas".to_string()];
        let e = engine(&c);
        let out = e.hits("星舰计划的进度同步到 atlas 文档");
        let hits: Vec<&RawHit> = out.iter().filter(|h| h.tag == "CUSTOM_TERM").collect();
        assert_eq!(hits.len(), 2, "{:?}", out);
        // 词边界：atlas2 里的 atlas 不命中
        let out2 = e.hits("rename atlas2 to atlasv2");
        assert!(out2.iter().all(|h| h.tag != "CUSTOM_TERM"), "{:?}", out2);
        // 大小写不敏感
        let out3 = e.hits("see ATLAS board");
        assert!(out3.iter().any(|h| h.tag == "CUSTOM_TERM"), "{:?}", out3);
    }

    // ── 开关 ──

    #[test]
    fn test_all_disabled_no_hits() {
        let e = engine(&cfg(false));
        assert!(e.hits("王建国在北京大学工作，密钥 sk-Live9xQm2RtV8bN4cD6fG0hJ2kL4mN6pQ8rS0tUvWx").is_empty());
    }
}
