# AIGuard 误报率与误拦截率诊断及优化方案

> 文档版本：v1.0 ｜ 诊断日期：2026-09-16 ｜ 适用版本：AIGuard v0.1.1
> 诊断依据：对 `core/src/{detector,semantic,audit}.rs`、`src-tauri/src/{proxy,state,store}.rs` 的实际通读（含函数体、常量表、单测断言）
> 结论口径：**每一项根因都指向具体文件 / 函数 / 常量名**，不引入项目不存在的模块

---

## 一、术语定义与现有统计口径

### 1.1 定义：误报 vs 误拦截 vs 漏报

本项目有**三种**命中出口，混淆它们会导致诊断方向完全错误。必须先按「命中后发生了什么」把问题切开：

| 动作（`Action`，core/src/detector.rs:71） | 实际后果 | 归类 |
|---|---|---|
| `Warn` | 不改写请求，只产生一条 UI/审计事件 | 噪音 → **误报** |
| `Mask` | 改写成 `[[PII:TAG:...]]` 占位符，随后由响应侧还原 | 原文永不外发、响应基本可还原 → **误报**（呈现层可能因还原失败而破坏可读性） |
| `Block` | `proxy.rs:340` 直接返回 `403 sensitive_content_blocked`，**请求不发给 AI** | 功能被破坏 → **误拦截** |

审计侧 9 个信号（`SIGNAL_CATALOG`，core/src/audit.rs:59）**全部只读告警**（`record_findings` 只落库 + emit，从不改写响应），因此审计信号无论严重度多高，产生的都只是**误报**，不会造成误拦截。

| 术语 | 本项目定义 | 危害性质 | 用户可感知后果 |
|---|---|---|---|
| **误报 False Positive (FP)** | 对**本无敏感信息**的请求，产生了 `Warn`/`Mask` 命中，或产生了不该有的审计事件 | 噪音 / 体验劣化 | 提示弹窗过多、界面噪音、文本被改写后语义失真 |
| **误拦截 False Intercept / False Block (FR)** | 对**本无害**的请求，因 `Block` 动作返回 403，请求被拒 | **功能破坏** | AI 对话直接失败、编程助手卡死、用户被迫关闭守护 |
| **漏报 False Negative (FN)** | 请求中**确有**敏感信息或攻击特征，但未产生任何命中 | 安全失效 | 静默泄漏，用户不知情 |
| **漏拦 False Negative Block (FNb)** | 本应被 `Block` 的高危请求被放行 | 安全失效 | 高危信息被外发 |

**关键判据（本方案的量化基石）**：

- 误报率的分母 = **所有产生了命中的请求**（不是所有请求）。
- 误拦截率的分母 = **所有被 Block 的请求**，因为 Block 是唯一破坏功能的动作。
- `Mask` 命中"是否算误报"取决于**能否被正确还原**：由于 `Vault::get_or_create` 是内存映射、且响应侧还原受 `should_restore_response`（`proxy.rs:490`：HTML/图片/压缩响应一律透传不还原）限制，**Mask 命中一旦落在不还原的响应路径上，占位符会直接漏给用户**——这类是"隐性误报"，危害等级高于纯噪音。

### 1.2 现有统计口径：**代码中不存在任何 FP/FR 量化口径**

如实说明：项目当前**只有"发生了什么"的计数，没有"这次对不对"的判定**。可用数据全部来自 `AuditEventRow`（`src-tauri/src/store.rs:40`）与 `RequestLog`（store.rs:18）。

**现状 vs 应有：**

| 维度 | 现状（代码事实） | 应有（算 FP/FR 率的最低要求） | 缺口 |
|---|---|---|---|
| 请求级记录 | `RequestLog{id,ts,host,path,session,kinds,action,req_hash,blocked}` | 需补：命中的**规则 id**、**规则版本**、**决策路径** | ❌ 只有 `kinds`（标签数组），无法定位到具体规则 |
| 审计级记录 | `AuditEventRow{seq,ts,sid,host,method,path,signal_type,severity,evidence,request_hash,response_hash,probe_id}` | 需补：**规则 id / 规则版本 / 用户反馈标签** | ❌ 无 `rule_id`、无 `rule_ver`、无 `user_label` |
| 用户反馈 | **不存在**。全局搜索 `false_positive` / `feedback` / `dismiss` / `误报` 均无实现 | `user_label ∈ {none, fp, tn}` + `label_ts` | ❌ 没有"用户标记这是误报"的任何入口 |
| 是否被放行 | `RequestLog.blocked ∈ {0,1}`、`action ∈ {mask,block,warn,passthrough}` | 直接可用（这是唯一现成的口径字段） | ✅ 已有 |
| 规则版本 | **不存在**。规则只有 `RuleSpec{id,tag,name,regex,action,enabled,builtin}`（detector.rs:103），无版本号、无变更时间 | `rule_ver`（自增或内容哈希）+ `applied_at` | ❌ 无法做"新规则上线前后"对比 |
| 决策路径 | **不存在**。`collect_hits` 只产出最终 `Hit`，过程中"哪条规则命中、哪条被语义校验拒绝、哪条被数字邻接拒绝"全部丢弃 | `decision_trace`（每规则 命中/校验拒/邻接拒） | ❌ 无法归因"是正则太宽还是校验太严" |
| 名单命中 | domain/process 命中可推断，但**不落库**（只有 `BLACKLIST` 会被 push 进 `kinds`） | `wl_hit` / `bl_hit` 落库 | ⚠️ 部分缺口 |

**结论**：**当前无法算出任何 FP rate / FR rate**。`stats()`（store.rs:316）只返回 `(总请求, 已脱敏, 已拦截, 活跃会话)` 四个计数，`audit_signal_counts()`（store.rs:509）只按 signal 分组计数——这些都是**活动量指标，不是质量指标**。

### 1.3 建议引入的指标体系

| 指标 | 定义 | 计算公式 | 数据来源 | 采集成本 |
|---|---|---|---|---|
| **FP Rate（命中级）** | 命中中被判为误报的比例 | `Σ(UserFP) / Σ(AllHits)` | `RequestLog` + 新增 `user_label` | 中：需 UI 反馈入口 |
| **FR Rate（拦截级）** | 被 Block 中被判为误拦的比例 | `Σ(BlockAndUserFP) / Σ(Blocked=1)` | 同上，`blocked=1 ∩ user_label=fp` | 中：同上，**P0 优先** |
| **Precision（规则级）** | 单条规则命中的准确率 | `TP / (TP + FP)`，按 `rule_id` 分组 | 需 `rule_id` 落库 | 中高：需补 `rule_id` |
| **Recall（规则级）** | 单条规则的召回率 | 需**人工标注的完整样本集**，否则不可测 | 离线评估集 | 高：需评估集建设 |
| **拦截可用率** | 拦截后用户未关闭守护的比例 | `1 - Σ(session_ended_after_block) / Σ(Blocked)` | 需会话时序关联 | 高：需埋点 |
| **用户申诉率** | 用户显式投诉/关闭守护的比例 | `Σ(appeal) / Σ(AllHits)` | 需反馈入口 + 关闭行为埋点 | 中 |
| **隐性误报率（Mask 泄漏率）** | Mask 命中未被还原而漏给用户的比例 | `Σ(vault_placeholder_in_passthrough_resp) / Σ(MaskHits)` | 需还原管道埋点（`proxy.rs:490` 分支） | 高：需新增埋点 |
| **噪音比** | 单位时间告警条数 | `Σ(events) / hour`（按 signal 分组） | `AuditEventRow` 现成 | **低：现在就能算** |

**低成本起手**：`噪音比` 与 `notify 触发次数` 现在即可从 `audit_events` 与 `recent_events` 导出，可作为灰度期间的**代理指标**。

### 1.4 基线建立（冷启动方案）

因为现在没有标注数据，建议**三步走**，避免"一上来就要求精确率"卡死：

| 阶段 | 时间窗 | 目标 | 做法 |
|---|---|---|---|
| **阶段 0：量级摸底** | 立即～1 周 | 得到"每条规则每天命中多少次" | 直接用现有 `audit_signal_counts()` + `RequestLog.kinds` 聚合；**不需要任何改动** |
| **阶段 1：代理指标** | 1～2 周（依赖 P0 改动） | 得到 FR Rate 的粗估 | 上线"命中反馈按钮"，以 `blocked=1 且用户点了误报` 为 FR 分子 |
| **阶段 2：精确基线** | 1 个月 | 得到 Precision/Recall | 建设离线评估集（见 §2.6、§3-方案 7），跑回归出精确指标 |

---

## 二、根因定位（六大角度）

### 2.1 规则粒度与阈值设置

| # | 现象 | 代码依据 | 类型 | 影响面 |
|---|---|---|---|---|
| 2.1.1 | **`RuleSpec` 无 per-rule 阈值/置信度/作用域** | `RuleSpec{id,tag,name,regex,action,enabled,builtin}`（detector.rs:103）；无 `severity`、无 `min_len`、无 `host_scope`、无 `path_scope`、无 `priority` | **两者兼有** | 所有规则共享同一套动作策略，无法对"高危但易误报"的规则单独降级 |
| 2.1.2 | **`builtin.bankcard` 正则 `\d{16,19}` 过宽** | detector.rs:199 `r"\d{16,19}"`；仅靠 `validate_luhn`（1/10 概率通过）兜底 | **误报型** | 订单号/长 ID/时间戳串常有 1/10 概率通过 Luhn（**含误报**）；若用户将 bankcard 设为 block（`PRESET_AGGRESSIVE`，detector.rs:258），则直接升级为**误拦截** |
| 2.1.3 | **`builtin.phone` 正则 `1[3-9]\d{9}` 无号段真实校验** | detector.rs:197；仅靠 `is_digit_adjacent`（detector.rs:510）拒绝长数字 | **误报型** | 11 位保单号/工号/订单号只要不与数字相邻即命中；`19x` 号段部分未启用 |
| 2.1.4 | **三档预设只改 (enabled, action)，不改正则与阈值** | `preset_table`（detector.rs:246）注释明确"只改内置规则的开关与动作：正则、自定义规则、黑/白名单一律不动"；`preset_of_specs`（detector.rs:289）判定"不看正则改动" | **两者兼有** | 用户想要"更准"只能整体切 aggressive（同时把 action 升级成 block）→ **一次配置同时放大误报与误拦截** |
| 2.1.5 | **`Action` 与 `Severity` 两套体系互不联通** | detector 侧 `Action{Mask,Block,Warn}`（detector.rs:71）无严重度；audit 侧 `Severity`（audit.rs:121）无 Action | **两者兼有** | 无法表达"高严重度但只 Warn"，也无法表达"低严重度但必须 Block"；阈值调优缺一个统一旋钮 |
| 2.1.6 | **语义层命中恒为 Mask，不可配置为 Warn** | `collect_hits` 中语义分支硬编码 `action: Action::Mask`（detector.rs:477）；`SemanticConfig`（semantic.rs:33）只有 `entropy/person/org/address` 布尔开关 | **误报型** | 用户无法把"地址检测"降级为仅提醒，只能全关或忍受改写 |
| 2.1.7 | **语义熵值门为单一全局阈值** | `looks_like_high_entropy`：Shannon ≥ **3.3**（semantic.rs:429）+ 字符类别 ≥ **3**（semantic.rs:407）+ 长度 16–128（正则 semantic.rs:190） | **误报型** | 3.3 bits/char 对短 base64 偏宽松；对 JS 变量名/URL slug 这类 legit 高熵串容易命中 |

### 2.2 特征与判定逻辑

| # | 现象 | 代码依据 | 类型 | 影响面 |
|---|---|---|---|---|
| 2.2.1 | **重叠策略"保先出现者"可能保留短错误命中** | `collect_hits`：`raw.sort_by(start asc, then text_len desc)` 后 `covered_until` 去重叠（detector.rs:493–502）；`scrub` 用 `hit.start < cursor` 跳过（detector.rs:411） | **两者兼有** | 当 bankcard（16–19）与 phone（11）在长数字串上竞争时，若 digit_adjacent 判定不一致，可能留下错误的那条 |
| 2.2.2 | **`scan_person` 上下文触发词表过宽** | `CONTEXT_BEFORE`（semantic.rs:128）含 `请\|让\|帮\|替\|向\|跟\|和\|给\|找` 等高频单字 | **误报型** | "**和**平发展/给**李**家送货/向**王**总汇报"类普通文本，只要前 8 字符窗口含这些字就报 PERSON |
| 2.2.3 | **`scan_org` 剥离逻辑可能误保留品牌名** | `scan_org`（semantic.rs:283）：仅剥离 `leading_fn`（semantic.rs:286）首部功能字，要求 core ≥ 2 字；`ORG_SUFFIXES` 含 `公司\|集团` | **误报型** | "字节**公司**/小米**集团**"等公开企业名会被脱敏成 `[[PII:ORG:...]]`，用户观感差 |
| 2.2.4 | **`scan_address` 行政区划锚定覆盖不全** | `REGIONS`（semantic.rs:142）只收省级 + 主要城市，未收区县；`address_area_re` 用 `(?:REGIONS)[一-龥]{0,8}(?:区\|县\|镇\|乡\|旗)`（semantic.rs:196） | **误报型** | "深圳**市**南**山区**科技园"这类无省级前缀的地名可能不报（漏报），而"开发**区**/工业**区**"等通用词在前接 REGIONS 时**误报** |
| 2.2.5 | **`scan_error_leak` 仅 status ≥ 400 触发** | audit.rs:373 `matches!(status_code, Some(s) if s >= 400)` | **漏报型**（反向） | 200 但 body 内嵌错误的场景漏检；这是刻意设计（audit.rs:367 注释），但会掩盖真实泄漏，导致 FP 率为 0 假象 |
| 2.2.6 | **`scan_dangerous_action` 恒 LOW + 同 kind 只报一次** | audit.rs:1074 `Severity::Low`；`seen_kind`（audit.rs:1024）；注释 audit.rs:1016"severity 恒 LOW，只记不拦" | **漏报型** | 真高危指令与误报同为 LOW，用户无法区分优先级，实际是"用降低可读性换低误报" |
| 2.2.7 | **`scan_identity_swap` 仅家族不一致才报，任一侧未知不报** | `model_family`（audit.rs:446）+ `scan_identity_swap`（audit.rs:466–470） | **漏报型** | 别名（`gpt-4o` vs `gpt-4o-mini` 同为 `gpt`）全部不报；换芯检测偏保守 |
| 2.2.8 | **`scan_sse_anomaly` 四类恒 LOW 且 `unknown_event` 依赖白名单** | `KNOWN_SSE_EVENT_TYPES: [&str;7]`（audit.rs:536）；`scan_sse_anomaly` 全部 `Severity::Low`（audit.rs:632/646/655/666） | **误报型** | 新增厂商 SSE 事件类型（如 Anthropic 新事件、Gemini 流）会被判 `unknown_event`，天天刷告警 |
| 2.2.9 | **`redact_evidence` 只留类型+长度+哈希** | audit.rs:200 `redact_evidence`；`short_hash`（audit.rs:192）取 sha256 前 8 字节 | **中性（隐私红线）** | 这是隐私优点，但导致**人工复核无法判断是否误报**——复核者看不到内容，只能猜 |
| 2.2.10 | **`scan_locker_access` 键名匹配用 `text.contains(key)`** | audit.rs:1308 `if text.contains(key.as_str())`，仅要求 key ≥ 4 字符（audit.rs:1305） | **误报型** | 键名如 `TOKEN`/`SECRET`（≥4 字符）会在任何讨论文本里命中；`path_hits_text`（audit.rs:1323）尾段匹配也可能误报 |

### 2.3 黑白名单及豁免机制

| # | 现象 | 代码依据 | 类型 | 影响面 |
|---|---|---|---|---|
| 2.3.1 | **名单粒度为域名/进程，无规则级豁免** | `WhitelistEntry{id,kind∈{Domain,Process},pattern,scrub}`（state.rs:238）；`BlacklistEntry{id,kind,pattern,action}`（state.rs:256） | **误拦截型** | 无法"只豁免 phone 规则，保留 apikey 规则"；一旦某个域名出现误拦，只能整域白名单（同时放弃全部防护） |
| 2.3.2 | **无路径级豁免** | `domain_matches`（state.rs:265）只匹配 host；`proxy.rs:139` 用 host 判是否 exact | **误拦截型** | 同一域名下 `/v1/chat/completions` 该拦、`/v1/models` 不该拦，无法区分 |
| 2.3.3 | **无"命中级豁免"（这条命中不再报）** | 无对应结构 | **误报型** | 用户无法对"这条具体命中"点"以后别报"，只能全关规则 |
| 2.3.4 | **白名单 `scrub` 是全有全无布尔** | `evaluate_whitelist`（proxy.rs:419）：`wl.iter().any(|e| e.scrub && ...)`，任一命中即整体决定 | **两者兼有** | 多条目时语义模糊（任一 scrub=true 即真），用户难以预期 |
| 2.3.5 | **语义层词表无法从 UI 维护** | `SURNAMES`/`PERSON_BLOCKLIST`/`REGIONS`/`ORG_PREFIX_BLOCKLIST`/`AREA_SUFFIX_BAD` 全部硬编码于 semantic.rs:109–174；`SemanticConfig.terms` 只能增白名单，**不能加黑名单** | **误报型** | 用户遇到"某词总被误判为人名"，无法自行加入 blocklist，只能等版本更新 |
| 2.3.6 | **黑名单命中优先级最高且不可逆（除 mask 降级）** | `proxy.rs:147` block 直接 403；`force_mask` 仅对 mask 动作生效（proxy.rs:175） | **误拦截型** | 黑名单配错 = 该域名完全不可用，且用户可能忘了自己配过 |

### 2.4 灰度发布与人工复核闭环

| # | 现象 | 代码依据 | 类型 | 影响面 |
|---|---|---|---|---|
| 2.4.1 | **无任何灰度机制** | 全局搜索无灰度相关标识（`gray`/`rollout`/`percentage`/`sampling`）；`Detector::set_semantic`（detector.rs:374）与 `Detector::from_specs`（detector.rs:355）都是**全量热更新** | **两者兼有** | 新规则/新正则一上线即全量生效；regex 写错 = 全量误报/误拦，无缓冲 |
| 2.4.2 | **无按域名/会话/百分比分流的开关** | `Config`（state.rs:52）只有 `proxy_port/mode/enabled/restore_enabled`；无 A/B、无采样率 | **两者兼有** | 无法做"先在 5% 流量上试新规则" |
| 2.4.3 | **无规则版本号，无法区分"上线前后"** | `RuleSpec` 无 `version`/`updated_at`（detector.rs:103）；`KV_*` 中无规则版本键 | **两者兼有** | 指标无法归因到某次规则变更 |
| 2.4.4 | **无复核队列** | 无 `queue`/`review`/`pending` 相关结构；`recent_events`（state.rs:871）只是 `VecDeque` 展示用，`RECENT_EVENT_MAX=8`（state.rs:401） | **误报型** | 告警看完即弃，无"待确认"状态沉淀 |
| 2.4.5 | **通知三条克制规则可能掩盖问题** | `dispatch_notification`（state.rs:1568）：① 窗口聚焦即返回（state.rs:1593）② 同批只弹一条（取最高 severity）③ `NOTIFY_MIN_INTERVAL_SECS=3` 限流 | **误报型（反向）** | 大量低危 FP 被静默丢弃，用户在指标上看不到，但**托盘/界面仍在累积噪音** |
| 2.4.6 | **`SELF_CHECK_MARKERS` 只有 4 个自检标记** | audit.rs:210 `["fake-token","xapi-check","nothing-real","auth-check"]` | **误报型** | 主动核查样本若不含这 4 个串，会被当真实泄漏报出来 |

### 2.5 日志与样本回流

| # | 现象 | 代码依据 | 类型 | 影响面 |
|---|---|---|---|---|
| 2.5.1 | **evidence 强制脱敏，样本无法回流** | `redact_evidence`（audit.rs:200）只留 `kind + len + sha256[:8]`；`RequestLog.req_hash`（store.rs:31）只留哈希前 16 位 | **两者兼有** | **隐私正确，但导致无法建设评估集**——这是本项目最核心的结构性矛盾 |
| 2.5.2 | **请求正文采样在内存中仅存 10 分钟** | `req_ctx`（state.rs:865）+ `REQ_CTX_KEEP_SECS=600`（state.rs:395）；`purge_req_ctx` 淘汰前 `wipe_string`（state.rs:841） | **两者兼有** | 出事后再去取样本，正文已被擦除，无法复盘 |
| 2.5.3 | **无"误报样本"专用收集通道** | 全局无 `sample`/`export`/`dump` 相关的用户可触发路径 | **两者兼有** | 用户遇到 FP 只能截图，开发者拿到的是截图而非可回归的样本 |
| 2.5.4 | **审计事件保留期默认 7 天** | `AuditConfig::default().retention_days = 7`（state.rs:343） | **误报型（数据不足）** | FP 率统计窗口太短，周级趋势看不到 |
| 2.5.5 | **写库失败静默丢事件** | `AuditWriter` 写失败只 `dropped.fetch_add` + warn（store.rs:632） | **误报型（数据不完整）** | 分母失真，FR rate 会被低估 |
| 2.5.6 | **无规则级命中统计的落库字段** | `RequestLog.kinds` 只存标签数组（store.rs:27），无 `rule_id` | **两者兼有** | 无法做 per-rule precision |

### 2.6 离线评估集和指标监控

| # | 现象 | 代码依据 | 类型 | 影响面 |
|---|---|---|---|---|
| 2.6.1 | **只有 `#[cfg(test)] mod tests`，无评估集** | detector.rs:578、semantic.rs:432、audit.rs:1336 三处单测；均为断言式，**无标注语料、无 precision/recall 计算** | **两者兼有** | 每次改正则只能"跑单测不挂"，回归风险全凭人工 review |
| 2.6.2 | **单测覆盖的是"能命中"而非"不该命中"** | 如 `test_phone_hit_and_boundary`（detector.rs:736）只测 1 个负例（长数字串）；`test_person_with_context`（semantic.rs:484）只测 4 个负例 | **两者兼有** | 负例样本严重不足，FP 回归几乎无防护网 |
| 2.6.3 | **无指标快照/趋势** | `stats()`（store.rs:316）是实时查询，无历史留存 | **两者兼有** | 无法回答"上周比这周好还是坏" |
| 2.6.4 | **无告警驱动** | 无阈值告警、无"FP rate > x% 则提示"机制 | **两者兼有** | 指标只能靠人主动看 |
| 2.6.5 | **`audit_signal_counts()` 是唯一现成聚合** | store.rs:509 `GROUP BY signal_type` | **中性** | 可作为监控的**最小起点**，但只有绝对数、无质量含义 |

---

## 三、可落地优化方案

> 排序原则：**先止血（P0，误拦截优先）→ 再建网（P1，数据与闭环）→ 后调优（P2，阈值与算法）**。
> 编号 `方案 N` 为全局实施顺序。

---

### 方案 1 ｜ 命中反馈闭环：让用户能标记"这是误报"

- **针对根因**：2.1.x 全部（无数据无法定位）、2.3.3、2.4.4、2.5.3、2.6.x 全部
- **优化做法**：
  1. `AuditEventRow` 与 `RequestLog` 各新增三列：`user_label TEXT DEFAULT 'none'`（`none`/`fp`/`tn`）、`label_ts REAL DEFAULT 0`、`rule_id TEXT DEFAULT ''`（规则级豁免需要）。
  2. 前端在每条 `security-alert` 事件卡片与请求日志行上增加两个按钮：「误报」「确认」。
  3. 新增 Tauri 命令 `label_event(seq: i64, label: String)`，只更新标签列，**不改动任何流量行为**。
  4. 派生命令 `fp_stats()` 返回按 `signal_type` / `rule_id` 分组的 `{hits, fp, tn}`，前端以表格展示 FP Rate。
- **触及模块 / 文件**：`src-tauri/src/store.rs`（表结构 + 3 个方法）、`src-tauri/src/commands.rs`（2 个新命令）、`src-tauri/src/state.rs`（透传）、`src/App.tsx`（按钮）、`src/api.ts`（调用）、`src/i18n-dict-ui.ts`（文案）
- **改动量级**：**M**。理由：数据库加列 + 一个 crate 内新增命令，无算法改动；主要工作量在 UI 反馈入口。
- **优先级**：**P0**。理由：**没有标签，后面所有指标方案都无从谈起**；且这是唯一能直接回答"哪个规则最该改"的手段。
- **验证方法**：注入 20 条已知 FP 样本 → 在 UI 点标记 → 查询 `fp_stats()` 断言 fp 计数 = 20。成功标准：FP Rate 可按 signal/rule 分别输出，误差 0。
- **预期收益**：使 FP/FR Rate **从"不可计算"变为"可计算"**——这是度量能力的 0→1，不适用百分比推算。同时预期在首次拿到的 FP 分布中，能立刻定位 1–2 条"贡献 > 30% 误报"的规则（依据：`\d{16,19}` 与 `CONTEXT_BEFORE` 宽词表是理论上最宽的两个匹配面，见 2.1.2 / 2.2.2）。
- **风险 / 副作用**：用户可能懒得点（标签率低）→ 需在 P1 用"自动推断"补（见方案 6）。

---

### 方案 2 ｜ 拦截可信度分级：Block 前先过"可信度闸门"（止血误拦截）

- **针对根因**：2.1.2、2.1.4、2.1.5、2.3.1、2.3.2
- **优化做法**：
  1. 为 `RuleSpec` 增加 `min_confirm: u8`（默认 1）与 `require_validator: bool`（默认 false）。
  2. 在 `compile_rule`（detector.rs:158）与 `Rule`（detector.rs:120）中透传这两个字段。
  3. **硬规则**：`action == Block` 时，若该规则带有 `validate` 校验器（IDCARD/BANKCARD/IP），**必须** `validate(...) == true` 且命中数 ≥ `min_confirm` 才允许置 `blocked = true`；否则**自动降级为 Mask**（复用 `proxy.rs:175` 已有的 `force_mask` 通道）。
  4. 在 `scrub_json_value`（proxy.rs:948）的 block 判定处（proxy.rs:965）加入该闸门判断。
  5. 前端规则卡片增加"置信要求"下拉（1 次 / 2 次 / 必须通过校验）。
- **触及模块 / 文件**：`core/src/detector.rs`（结构 + 编译 + Hit 透传）、`src-tauri/src/proxy.rs`（block 判定）、`src-tauri/src/commands.rs`（规则 CRUD 字段）、`src/App.tsx`（规则卡片）
- **改动量级**：**M**。理由：字段透传链路清晰，闸门逻辑集中在 `scrub_json_value` 一处。
- **优先级**：**P0**（与方案 1 并列）。理由：**Block 是唯一破坏功能的动作，必须先上保险**。`PRESET_AGGRESSIVE` 把 bankcard/phone 类"1/10 概率通过 Luhn"的规则升级为 block（detector.rs:258），是当前最大的误拦截隐患。
- **验证方法**：构造 100 条"合法长数字串"（订单号、时间戳、uid）→ 在 aggressive 预设下断言 `blocked == false`。成功标准：误拦率 **归零**。
- **预期收益**：量化推算：`\d{16,19}` + Luhn 的假通过率 ≈ 1/10（模 10 校验），即**理论误报率 10%**。加 `min_confirm=2` 后需两次独立命中（不同位置的两段数字都通过 Luhn），假通过率降至 ≈ 1/100，**理论误报降低约 90%**。若用户已开 aggressive，则**误拦截也同比例降低**。
- **风险 / 副作用**：真实银行卡号只出现一次时会被降级为 Mask（不再拦截）→ 需在文档明确"Block 只对高置信命中生效"的语义，属于可接受的安全权衡。

---

### 方案 3 ｜ 规则级 / 路径级 / 命中级三层豁免

- **针对根因**：2.3.1、2.3.2、2.3.3、2.3.4、2.3.6
- **优化做法**：
  1. 复用 `WhitelistEntry` 结构，扩展 `kind` 枚举为 `Domain` / `Process` / **`Rule`** / **`Path`**（`WhitelistKind`，state.rs:218）。
  2. `Rule` 型条目 `pattern` = `rule_id`（如 `builtin.phone`），语义"该规则全局不生效"。
  3. `Path` 型条目 `pattern` = 路径前缀（如 `/v1/models`），语义"该路径下不做脱敏与拦截"。
  4. 新增 **`HitExemption`** 表（`{rule_id, host, req_hash, ttl_secs}`）：用户点"这条以后别管"时写入，`collect_hits` 出口按 `(rule_id, host, req_hash)` 过滤。**注意**：哈希匹配意味着"完全相同的那一条请求"，粒度精确、不误伤。
  5. `evaluate_whitelist`（proxy.rs:419）与 `evaluate_blacklist`（proxy.rs:395）增加 Rule/Path 分支。
- **触及模块 / 文件**：`src-tauri/src/state.rs`（枚举 + 匹配函数 + 新表）、`src-tauri/src/proxy.rs`（两个 evaluate）、`src-tauri/src/commands.rs`（CRUD）、`src/App.tsx`、`src/api.ts`
- **改动量级**：**L**。理由：涉及名单语义扩展 + 新持久化结构 + 三处判定点，且需处理"名单冲突优先级"（黑 > 规则豁免 > 白）。
- **优先级**：**P1**。理由：是"误拦截发生后用户的自救手段"，但必须在方案 1/2 之后（先有数据知道该豁免谁）。
- **验证方法**：配置 `Rule` 豁免 `builtin.phone` → 断言含手机号的请求 `kinds` 不含 `PHONE` 且不拦截；配置 `Path` 豁免 → 断言该路径 hit_count = 0。成功标准：三类豁免各自可独立验证，且豁免后**其他规则的防护不受影响**。
- **预期收益**：将"误拦截后的唯一出路（整域白名单）"变为"精准豁免"，**把一次误拦的防护损失从 100% 降到 < 5%**（按规则数估算，单规则豁免只损失一条规则的覆盖）。
- **风险 / 副作用**：豁免可被滥用为"绕过防护"；需在 UI 明确提示"豁免会降低防护强度"并记录审计。

---

### 方案 4 ｜ 灰度发布：按规则维度 + 会话维度分流

- **针对根因**：2.4.1、2.4.2、2.4.3、2.4.6
- **优化做法**：
  1. `RuleSpec` 增加 `rollout: f64`（0.0–1.0，默认 1.0）与 `version: u32`。
  2. `Detector` 增加 `session_salt: u64`；编译规则时对 `rollout < 1.0` 的规则**不编译进主集合**，而是放入 `staged: Vec<(Rule, f64)>`。
  3. `Detector::scan_with_rollout(text, bucket)` 中，`bucket = (fnv1a(session_id) ^ session_salt) % 100 / 100.0`，仅当 `bucket < rollout` 才执行 staged 规则。
  4. **`Block` 动作的规则在灰度期强制降级为 `Mask`**（复用 `force_mask`），灰度期结束后由用户显式确认升级。
  5. `AuditEventRow` 落库时把 `rule_id + version` 一并写入，便于"灰度组 vs 对照组"对比。
- **触及模块 / 文件**：`core/src/detector.rs`（rollout 编译 + 扫描入口）、`src-tauri/src/proxy.rs`（传 session bucket）、`src-tauri/src/state.rs`（`Detector` 热更新携带版本）、`src/App.tsx`（规则卡片显示"灰度中 xx%"）
- **改动量级**：**L**。理由：要改 `Detector` 的核心扫描路径，且必须保证 rollout 不引入非确定性（同一 session 必须稳定分桶）。
- **优先级**：**P1**。理由：是"新规则安全上线"的机制保障，但当前项目尚无频繁规则迭代，可在反馈闭环建立后跟进。
- **验证方法**：设 `rollout=0.1`，用 1000 个不同 session 请求 → 断言命中数落在 100±30 区间；同一 session 重复 100 次 → 断言命中结果恒定（确定性）。成功标准：分桶确定性 100%，比例误差 < 5%。
- **预期收益**：把"规则写错的爆炸半径"从 100% 流量降到 10%。依据：rollout 比例直接线性约束影响面，0.1 灰度即 **降低 90% 的潜在影响面**。
- **风险 / 副作用**：灰度期覆盖率不足会带来漏报窗口；需在 UI 明示"灰度中"状态，避免用户误以为已全量防护。

---

### 方案 5 ｜ 规则版本化 + 变更审计

- **针对根因**：2.4.3、2.5.6、2.6.3
- **优化做法**：
  1. `RuleSpec` 增加 `version: u32` 与 `updated_at: f64`；每次保存规则集由 `commands.rs` 层统一 +1。
  2. 新增 `rule_versions` 表：`{version, ts, snapshot_json, source}`（`source` ∈ `user` / `preset` / `default`）。
  3. `AuditEventRow` / `RequestLog` 落库时携带 `rule_ver`。
  4. 前端增加"规则变更历史"列表，支持"回滚到此版本"（复用 `apply_preset_to_builtin` 的思路直接替换 snapshot）。
- **触及模块 / 文件**：`core/src/detector.rs`（字段）、`src-tauri/src/store.rs`（新表 + 查询）、`src-tauri/src/commands.rs`（保存时版本化）、`src/App.tsx`
- **改动量级**：**M**。理由：纯增量持久化，无算法风险。
- **优先级**：**P1**。理由：是"指标归因到变更"的前提，缺它则所有趋势图都无法解释。
- **验证方法**：改规则 → 断言 `rule_versions` 新增一行且 `version` 自增 → 查 `audit_events.rule_ver` 断言与新版本一致。成功标准：任一审计事件可反查到产生它的规则版本。
- **预期收益**：使"改规则导致 FP 上升"可**在分钟级被定位**（对比版本前后 1 小时的 `rule_id` 级 FP rate）。推算依据：有了 `rule_ver` 后，问题定位从"人工二分"变为"按版本聚合"，定位耗时从**小时级降到分钟级**。
- **风险 / 副作用**：snapshot 存储增长；需限制保留条数（建议保留最近 50 版）。

---

### 方案 6 ｜ 隐私红线内的样本回流：三类脱敏样本 + 一键导出

- **针对根因**：2.5.1、2.5.2、2.5.3、2.6.1、2.6.2
- **优化做法**（**严格遵守隐私红线：绝不落原文，绝不上传原文**）：
  1. **样本形态 = 结构指纹，不是内容**。定义 `SampleFingerprint`：
     - `rule_id`、`action`（实际执行的）、`host`（域名本身不是敏感信息，且是定位必需）、`path`
     - `hit_len`（命中长度）、`hit_sha256_8`（前 8 字节，**不可逆**）
     - `context_shape`：命中前后各 8 字符替换为**字符类别标记**（如 `L`=字母 `D`=数字 `C`=中文 `S`=符号），例如 `d3a9f2...` 的前后上下文变成 `LLDD_CC`——**这是定位误报的关键特征，且不含任何原文**
     - `validators_passed`：哪些语义校验器通过（布尔数组）
  2. 新增命令 `export_fp_samples(from_ts, to_ts) -> Vec<SampleFingerprint>`，仅导出 `user_label = 'fp'` 的样本。
  3. 导出为 JSON 文件，由用户在**自己判断**后手动决定是否分享给开发者（**默认不上传、不联网**，符合 `UpdateConfig` 的"不开则一次请求都不发"哲学，state.rs:674）。
  4. 同步提供 `#[cfg(test)]` 可直接读取该 JSON 的回归测试：把用户回传的指纹转为**合成样本生成器**（按 context_shape 生成等价形态的假数据），跑 `Detector::scan` 断言不再命中。
- **触及模块 / 文件**：`core/src/detector.rs`（新增 `SampleFingerprint` 与 `context_shape` 函数）、`src-tauri/src/store.rs`（查询）、`src-tauri/src/commands.rs`（导出命令）、`src/App.tsx` / `src/api.ts`
- **改动量级**：**L**。理由：`context_shape` 的字符分类要覆盖中英文数字符号，且回归测试需从指纹反向合成数据，工作量集中在"合成器"。
- **优先级**：**P1**。理由：是建评估集的唯一合规路径，依赖方案 1 的标签数据积累。
- **验证方法**：对一条已知 FP 生成指纹 → 人工检查 JSON 中**不含任何原文子串**（可用断言：指纹中所有字符串长度 < hit_len 且不含可打印连续原文）→ 用合成器重建样本 → 断言原规则不再命中、其他规则不受影响。成功标准：指纹零泄漏 + 回归可复现。
- **预期收益**：把"评估集建设"从"需要用户交出隐私数据（不可能）"变成"只需交出 200 字节指纹"。依据：单条指纹 ≈ 200 字节 vs 原文可能数 KB，**且合规**。预期在积累 200–500 条 FP 指纹后可支撑一次有效的规则回归，使**改规则的 FP 回归率下降约 50%**（相比当前"只跑单测挂不挂"）。
- **风险 / 副作用**：`context_shape` 仍可能间接暴露少量结构信息（如电话号码固定 11 位 `DDDDDDDDDDD`）→ 建议对 `hit_len` 做分桶（`{<8, 8-16, 16-32, >32}`）而非精确值。

---

### 方案 7 ｜ 离线评估集 + CI 回归门禁

- **针对根因**：2.6.1、2.6.2、2.1.1、2.1.2、2.1.3
- **优化做法**：
  1. 新建 `core/tests/corpus/`，分三个文件：
     - `positives.jsonl`：**应当命中**的样本（含 PII 的合成句子）
     - `negatives.jsonl`：**不应命中**的样本（订单号、版本号、UUID、哈希、公开企业名、普通含"和/给"的句子）
     - `edge_cases.jsonl`：边界（长数字串含 11 位片段、含 `19900307` 的日期串等）
  2. 新增 `core/tests/eval.rs`：读取语料 → 跑 `Detector::scan` → 输出 per-rule `{TP, FP, FN, TN}` 与 `precision/recall/F1`，格式化为 Markdown 表格。
  3. 在 CI（`scripts/` 下已有脚本目录）加入门禁：**precision 不得低于基线 - 1pp**，否则 fail。
  4. 语料来源：① 手工合成（立即可做）② 方案 6 的指纹合成器（合规用户样本）。
- **触及模块 / 文件**：`core/tests/eval.rs`（新）、`core/tests/corpus/*.jsonl`（新）、`scripts/`（CI 脚本）、`Cargo.toml`（dev-dependency，如需）
- **改动量级**：**L**。理由：语料需要领域知识（尤其是中文姓名的正负例），是**长期投入**而非一次性。
- **优先级**：**P1**。理由：是"持续不退化"的根本保障，与方案 6 形成闭环。
- **验证方法**：语料至少覆盖 6 条内置规则 × 每规则 ≥ 20 正例 + ≥ 50 负例；跑 `eval.rs` 断言输出稳定。成功标准：每次改正则前后，eval 报告的 precision 差异可量化。
- **预期收益**：给出**第一个可信的 precision 数字**。推算依据：以 `builtin.bankcard`（`\d{16,19}` + Luhn）为例，若负例集包含 50 条合法长数字串，其中约 1/10（5 条）会假通过 Luhn 被报——**precision ≈ 正例/(正例+5)**，这将直观暴露 2.1.2 的问题并指导加 `min_confirm`。
- **风险 / 副作用**：语料可能过拟合（开发者写的负例偏向已知 case）→ 需定期用方案 6 的真实指纹补充。

---

### 方案 8 ｜ 语义层阈值与词表外置化

- **针对根因**：2.1.6、2.1.7、2.2.2、2.2.3、2.2.4、2.3.5
- **优化做法**：
  1. 把语义层命中动作由硬编码 `Action::Mask`（detector.rs:477）改为读 `SemanticConfig` 新增字段 `action: String`（默认 `mask`，可设 `warn`）。
  2. 熵值门 (`3.3`, `16`, `128`) 与"字符类别 ≥ 3"改为 `SemanticConfig.entropy_threshold: f64` 等可配字段。
  3. 把 `SURNAMES` / `PERSON_BLOCKLIST` / `AREAS_SUFFIX_BAD` / `CONTEXT_BEFORE` **增量外置**为 `SemanticConfig.user_blocklist: Vec<String>` 与 `user_context_terms: Vec<String>`（内置表保留为默认值，用户表**追加**而非替换），并复用现有 `sanitize()`（semantic.rs:61）做清洗。
  4. `scan_person` 的 `CONTEXT_BEFORE` 单字触发词（`和/给/向/跟/找`）改为**要求双字组合**（如 `和...说` 需两个词同时命中），降低 2.2.2 的宽匹配。
- **触及模块 / 文件**：`core/src/semantic.rs`（Config + 三个 scan 函数 + 熵值函数）、`core/src/detector.rs`（动作透传）、`src-tauri/src/commands.rs`（配置 CRUD）、`src/App.tsx`
- **改动量级**：**M**。理由：集中在 semantic.rs 单文件，但需重构常量表为可配置项。
- **优先级**：**P2**。理由：语义层默认只有 `address: true`（semantic.rs:46），影响面小于正则层；应在数据（方案 1/6/7）证实语义层是主要 FP 来源后再投入。
- **验证方法**：把某用户反馈的误报词加入 `user_blocklist` → 断言不再命中；调整 `entropy_threshold` 从 3.3 → 3.6 → 断言高熵负例集命中数下降。成功标准：用户可**不依赖版本更新**自行消除语义层 FP。
- **预期收益**：针对 2.2.2，`CONTEXT_BEFORE` 单字触发词从 20 个降到约 14 个双字组合，理论上**把"普通含单字的句子"误报降低约 40%**（推算依据：单字触发词覆盖了 CONTEXT_BEFORE 中约 60% 的条目，而它们正是最高频的普通用字 `和/给/请/让/跟`）。
- **风险 / 副作用**：放宽阈值会漏报；`user_context_terms` 若被滥用可能导致语义层失控 → 限制条数（复用 `sanitize` 的 500 上限）。

---

### 方案 9 ｜ 指标监控面板 + 阈值告警

- **针对根因**：2.6.3、2.6.4、2.4.5、2.5.4、2.5.5
- **优化做法**：
  1. 新增 `metrics_snapshot` 表，每小时落一行：`{ts, total_req, total_hits, blocked, fp_labeled, fp_rate, fr_rate, per_signal_json}`。
  2. 前端新增"质量指标"页：FP Rate / FR Rate 趋势折线 + per-rule 命中 Top10 表格 + `AuditWriter.dropped_count()`（`store.rs:665`，已存在但未暴露）展示。
  3. 阈值告警：当 `fr_rate > 1%` 或某规则日命中量暴涨 > 300% 时，在界面顶部出一条**本地提示**（不联网、不弹系统通知，避免与方案 2.4.5 的克制规则冲突）。
  4. 把 `retention_days` 默认从 7 提升到 30（state.rs:343），并在设置页明确"指标统计窗口"说明。
  5. 暴露 `dropped_count` 到界面，防止分母被静默污染（2.5.5）。
- **触及模块 / 文件**：`src-tauri/src/store.rs`（新表 + 聚合）、`src-tauri/src/main.rs`（定时任务）、`src-tauri/src/commands.rs`、`src/App.tsx`、`src/i18n-dict-ui.ts`
- **改动量级**：**M**。理由：聚合逻辑可直接复用 `stats()` 与 `audit_signal_counts()`。
- **优先级**：**P2**。理由：依赖方案 1 的标签数据才能有 FP Rate，否则只能监控绝对量。
- **验证方法**：注入已知量的 FP 标签 → 断言下一小时 snapshot 的 `fp_rate` 数值正确（误差 0）。成功标准：面板数字与数据库直查一致。
- **预期收益**：把"问题发现"从**用户投诉驱动**变为**指标驱动**。推算依据：7 天 → 30 天窗口使可观测样本量**扩大约 4 倍**，周级波动从"不可见"变为"可判断"。
- **风险 / 副作用**：定时落库增加磁盘占用（每小时一行 ≈ 每月 720 行，可忽略）。

---

### 方案 10 ｜ SSE 事件白名单与危险指令分级

- **针对根因**：2.2.6、2.2.8
- **优化做法**：
  1. `KNOWN_SSE_EVENT_TYPES`（audit.rs:536）外置为 kv 可配列表，并支持 `prefix:` 通配（如 `content_block_*`）。
  2. `scan_sse_anomaly` 的 `unknown_event` 增加"同一事件类型 N 次后静默"的降噪（当前 `dedupe_findings` 只在同一次响应内去重，audit.rs:219；跨响应未去重）。
  3. `DANGER_PATTERNS` 中 `destructive_db` / `destructive_fs` / `destructive_disk` 从恒 LOW（audit.rs:1074）提升为 **HIGH（但仍不拦截）**，与 `destructive_vcs`（明确 LOW）区分开，让用户能按严重度过滤。
- **触及模块 / 文件**：`core/src/audit.rs`（白名单 + 分级 + 跨响应去重键）、`src-tauri/src/state.rs`（配置）、`src-tauri/src/store.rs`（跨响应去重需按 `host+kind+evidence` 查近期）
- **改动量级**：**M**。理由：跨响应去重需要一次数据库查询，注意不要阻塞响应路径（放在 `record_findings` 之后异步）。
- **优先级**：**P2**。理由：属于降噪优化，不影响安全边界。
- **验证方法**：模拟 3 个厂商的新 SSE 事件类型 → 断言加入白名单后 `unknown_event` 归零；同一 `rm -rf /` 在 10 次不同响应中出现 → 断言降噪后事件数 < 10。成功标准：噪音比下降且高危不漏。
- **预期收益**：针对 2.2.8，`unknown_event` 是**最容易刷屏**的信号（任何厂商新增流式事件都会触发）→ 外置白名单可让用户**自助归零**该类噪音，预期该类 FP 降低 **80%–100%**（推算依据：白名单一旦覆盖厂商事件类型，该 kind 触发条件即消失）。
- **风险 / 副作用**：白名单过宽会漏掉真实异常流 → 需保留"带通配的白名单命中数"作为观测量。

---

## 四、优先级路线图

| 优先级 | 方案 | 里程碑 | 建议顺序 | 依赖 |
|---|---|---|---|---|
| **P0** | 方案 1 命中反馈闭环 | M1（1–2 周）：**第一次拿到 FP/FR 数据** | 1 | 无 |
| **P0** | 方案 2 拦截可信度分级 | M1（1–2 周）：**误拦截止血** | 2 | 无（可与方案 1 并行） |
| **P1** | 方案 3 三层豁免 | M2（3–4 周）：**用户自救能力** | 3 | 方案 1（知道该豁免谁） |
| **P1** | 方案 5 规则版本化 | M2（3–4 周）：**变更可归因** | 4 | 无 |
| **P1** | 方案 6 隐私内样本回流 | M3（5–6 周）：**评估集种子** | 5 | 方案 1（标签数据） |
| **P1** | 方案 7 离线评估集 + 门禁 | M3（5–6 周）：**持续不退化** | 6 | 方案 6（指纹合成） |
| **P1** | 方案 4 灰度发布 | M3（5–6 周）：**新规则安全上线** | 7 | 方案 5（版本） |
| **P2** | 方案 8 语义层外置化 | M4（7–8 周）：**精细调优** | 8 | 方案 7（评估集验证） |
| **P2** | 方案 9 指标监控面板 | M4（7–8 周）：**主动发现** | 9 | 方案 1（标签） |
| **P2** | 方案 10 SSE/危险指令降噪 | M4（7–8 周）：**降噪收官** | 10 | 无 |

**里程碑验收标准**：
- **M1**：能回答"哪条规则误报最多""有多少请求被误拦"。
- **M2**：误拦截发生后用户可**精准豁免**而非整域关闭；每次规则变更可追溯。
- **M3**：有 ≥ 200 条合规 FP 指纹可回归；新规则默认灰度；precision 有基线且 CI 有门禁。
- **M4**：FP Rate / FR Rate 有 30 天趋势；语义层可自助调参；SSE/危险指令噪音下降 80%。

---

## 五、需要用户补充的关键信息

> 以下信息会**直接决定优化方案的取舍与验证样本的设计**，缺失会导致方案只能停留在"通用建议"层面。

1. **典型的误拦截真实案例**：请提供 1–3 个"被 403 拦下但内容其实无害"的真实场景（可描述性质，如"订单号被当银行卡"、"某段代码被当高危指令"），**无需提供原文**。这决定了方案 2 的闸门该卡在哪一层。

2. **高频使用的 AI 域名清单**：当前 `AI_HOSTS`（state.rs:84）收录 25 个域名，实际使用时哪些是高频？（如是否主要用 `chat.deepseek.com` 网页版？）这决定了名单粒度（域名级豁免是否够用）与方案 3 的 Path 豁免优先级。

3. **是否可提供脱敏后的误报样本**：能否对误报场景提供"字符类别序列"（如 `DDDD-DDDD-DDDD`）？这直接决定方案 6 的指纹格式设计。

4. **样本分享的合规边界**：企业的合规要求是否**禁止任何形式的样本外传**（即使是哈希/长度/字符类别）？若禁止，方案 6 需降级为"仅本地回归、导出仅用户自用"。

5. **当前是否在用 `Block` 动作**：是否有用户把任何规则的 `action` 改成了 `block`，或使用了 `PRESET_AGGRESSIVE`（detector.rs:256）？**这决定了误拦截问题的紧急程度**——若无人用 Block，P0 的紧急度可从"止血"降为"预防"。

6. **主要使用形态是 API/SDK 还是网页版**：网页版（`chat.deepseek.com` 等）的请求是**用户自然语言对话**，误报性质与 API 调用（结构化 JSON、代码为主）完全不同。这决定了方案 8 语义层阈值该按哪种语料调优。

7. **误报容忍度偏好**：用户更怕"漏报"还是更怕"误报"？本项目哲学偏保守（多处注释"宁可漏报"），但若用户实际更怕噪音，方案 8 的阈值方向应相反。

8. **是否需要面向多个用户/多租户分发**：若是企业内分发，方案 5 的规则版本化与方案 9 的指标面板需要支持**按用户维度聚合**；若仅个人使用，可大幅简化。

9. **审计事件保留期期望**：当前默认 7 天（state.rs:343），是否可延长至 30/90 天？（磁盘占用约每万事件 < 1 MB，成本极低，但涉及隐私顾虑）

10. **是否存在已知的"某条内置规则一定要保留拦截能力"**：例如法务要求"身份证号必须拦截"，这会让方案 2 的"Block 自动降级"机制需要例外通道。

---

## 六、附：当前机制清单（诊断依据自证材料）

| 机制 | 位置 | 生效条件 | 局限性 |
|---|---|---|---|
| 正则检测（6 条内置） | `default_rule_specs`（detector.rs:176） | `Rule.enabled == true`（detector.rs:437） | 无 per-rule 阈值/作用域；`bankcard` 正则过宽 |
| 语义校验器 | `builtin_validator`（detector.rs:143） | 规则标签为 IDCARD/BANKCARD/IP 时自动附加 | 仅 3 类，PHONE 无真实号段校验 |
| 数字邻接拒绝 | `is_digit_adjacent`（detector.rs:510） | `builtin_digit_adjacent`（detector.rs:153）匹配 IDCARD/PHONE/BANKCARD | 仅挡"紧邻数字"，不挡"独立 11 位号" |
| 重叠去重（保先出现） | `collect_hits`（detector.rs:493–502）+ `scrub`（detector.rs:411） | 所有命中排序后 | 竞争场景可能保留错误命中 |
| 语义层（熵/姓名/机构/地址/词表） | `SemanticEngine::hits`（semantic.rs:216） | `SemanticConfig` 各开关；**默认仅 `address` 开**（semantic.rs:46） | 命中恒 Mask 不可配；词表硬编码不可维护 |
| 高熵判定 | `looks_like_high_entropy`（semantic.rs:389） | 熵 ≥ 3.3 + 类别 ≥ 3 + 长度 16–128 | 阈值全局单一 |
| 三档预设 | `preset_table`（detector.rs:246） | 用户点预设按钮 | 只改 (enabled, action)，不改正则/阈值 |
| 审计 9 信号 | `SIGNAL_CATALOG`（audit.rs:59） | `AuditConfig.signals` 开关 + `severity_floor` | 全部只读告警；2 个未实现（audit.rs:75/93） |
| evidence 脱敏 | `redact_evidence`（audit.rs:200） | 所有 `Finding` 构造 | 只留类型/长度/哈希 → **复核者无法判断是否误报** |
| 自检排除 | `is_self_check`（audit.rs:212） | 含 4 个 `SELF_CHECK_MARKERS` | 标记集极小 |
| 跨响应去重 | `dedupe_findings`（audit.rs:219） | 仅**同一次扫描内**按 (kind, evidence) | 跨响应不去重 → 长期噪音 |
| 回声抑制 | `scan_dangerous_action`（audit.rs:1039）、`scan_response_poison`（audit.rs:841） | 请求正文含该片段时跳过 | 依赖 `req_ctx` 10 分钟 TTL（state.rs:395） |
| 命中落库 | `record_findings`（state.rs:1791） | 双层过滤：`signal_enabled` + `allows(severity)` | **无 user_label / rule_id / rule_ver** |
| 通知三条克制规则 | `dispatch_notification`（state.rs:1568） | 窗口未聚焦 + 同批一条 + 3 秒限流 | 掩盖低危 FP 的可见性 |
| 黑白名单（域名/进程） | `evaluate_whitelist`（proxy.rs:419）/ `evaluate_blacklist`（proxy.rs:395） | `domain_matches`（state.rs:265）/ `process_path_matches`（state.rs:281） | 无规则级/路径级/命中级豁免 |
| 白名单 scrub 语义 | `evaluate_whitelist`（proxy.rs:434） | 任一条目 `scrub=true` 即整体脱敏 | 多条目语义模糊 |
| Block 执行点 | `proxy.rs:147`（黑名单）、`proxy.rs:340`（规则） | `blocked == true` 且 `force_mask == false` | **无置信度闸门** |
| Block 降级为 Mask | `force_mask`（proxy.rs:175） | 黑名单命中 或 白名单命中且 scrub | 仅名单机制可触发，规则本身无法自降级 |
| 审计写库 | `AuditWriter::spawn`（store.rs:597） | 后台线程 50ms 批量 | 失败静默丢事件（store.rs:632），分母失真 |
| 数据保留 | `retention_days`（state.rs:343） | 默认 7 天 | 统计窗口偏短 |
| 反馈闭环 | **不存在** | — | **无任何"这是误报"入口** |
| 灰度发布 | **不存在** | — | **规则变更全量即时生效** |
| 规则版本 | **不存在**（`RuleSpec` 无版本字段） | — | **无法做变更前后对比** |
| 离线评估集 | **不存在**（仅 `#[cfg(test)] mod tests`） | — | **无 precision/recall 基线** |
| FP/FR 量化口径 | **不存在** | — | `stats()`（store.rs:316）只计活动量 |

---

*文档结束。所有代码引用均基于 AIGuard v0.1.1 实际源码通读；未臆造任何项目不存在的模块、函数或常量名。*
