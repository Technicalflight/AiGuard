# 安全政策 / Security Policy

AiGuard 是一个**安全工具**：它处理的是你最敏感的数据，同时又在本机解密 HTTPS 流量。
因此它的漏洞影响面比一般应用更大，我们对安全报告的处理优先级也最高。

---

## 支持的版本

安全修复只针对**最新的发布版本**提供。请先用最新版本复现，再报告。

| 版本 | 是否支持安全更新 |
|---|---|
| 最新 Release（v0.1.x） | ✅ |
| 更早的版本 | ❌ 请先升级 |

项目处于早期开发阶段（v0.1.x），配置格式与内部接口仍在变化。

---

## 如何报告漏洞

> [!IMPORTANT]
> **请不要在公开 Issue、Discussion、PR 或任何社交媒体上披露安全漏洞。**
> 公开披露会让所有使用者在你修复之前暴露在风险中。

请使用以下**私下渠道**之一：

1. **GitHub Security Advisories（推荐）**
   <https://github.com/Technicalflight/AiGuard/security/advisories/new>
   —— 支持私下讨论、协作修复、申请 CVE。
2. 如果无法使用上述入口，可通过 <https://github.com/Technicalflight/AiGuard/issues> 开一个**不含任何细节**的
   Issue，只说「我有一个安全问题需要私下报告」，维护者会主动联系你建立私下渠道。

### 报告里请包含

| 项 | 说明 |
|---|---|
| 影响 | 攻击者能做什么？影响哪些用户？ |
| 复现步骤 | 尽可能小的可复现步骤或 PoC |
| 版本与环境 | 版本号、Windows 版本、相关配置 |
| 严重度评估 | 你的判断（如 CVSS），以及理由 |
| 建议修复 | 可选，但非常欢迎 |

**请不要**在报告里附带真实的身份证号、手机号、银行卡号或他人的个人数据。用你自己构造的假数据即可。

### 我们的响应

| 阶段 | 目标时间 |
|---|---|
| 确认收到 | 3 个工作日内 |
| 初步评估（是否成立、严重度） | 7 个工作日内 |
| 修复与发布 | 视严重度而定，会持续同步进展 |
| 公开致谢 | 修复发布后，除非你要求匿名 |

本项目由个人维护，时间线可能受个人安排影响；若超时未回复，欢迎在 Issue 区礼貌催办（不要带上细节）。

---

## 安全范围

### 属于范围内（欢迎报告）

- **脱敏绕过**：能让真实敏感信息以未被替换的形式到达上游 AI 服务。
- **还原泄漏**：占位符映射被跨会话复用、越权读取，或原文被写入日志 / SQLite / 崩溃转储 / 临时文件。
- **证书与私钥**：CA 私钥的保护（DPAPI 封装）可被绕过、可被同机低权限进程提取。
- **代理与网络**：守护管道的请求可被重定向到非预期上游；PAC / 系统代理配置可被利用来劫持非目标流量。
- **审计伪造**：能构造出「上游行为正常」的假审计结论，或让真实高危事件不产生记录。
- **权限提升**：从普通用户权限获得管理员权限，或绕过 hosts / 证书安装的权限检查。
- **拒绝服务**：远程输入可让守护管道崩溃、内存无限增长或卡死（如无限前瞻缓冲）。
- **注入**：上游返回的内容能在界面或系统层面执行代码（前端 XSS、命令注入等）。

### 不属于范围内

- 依赖 crate / npm 包的已知漏洞本身（请报告给上游；若**本项目以不安全的方式使用**了它，则属于范围内）。
- 需要攻击者已具备本机管理员权限、或已能读写本机内存的攻击场景。
- 安装包未做代码签名导致的 SmartScreen 提示（已知并已在 README 说明）。
- 启用了证书固定（pinning）的应用无法被拦截——这是**设计行为**，不是漏洞。
- 社会工程、物理访问、以及与本项目代码无关的第三方服务问题。
- 仅影响已停止维护版本的问题。

---

## 安全设计要点（供评估参考）

了解这些设计意图，有助于你判断某个现象是不是漏洞：

- 敏感原文**只存在于内存**的会话映射中（带 TTL 与在途锁定），日志与审计事件只含类型 / 长度 / 摘要 / 哈希。
- CA 私钥以 **DPAPI**（当前用户范围）封装后落盘。
- 所有对外通信（更新检查）**默认关闭**，关闭时一次请求都不发。
- 审计层是**只读**的：发现只记录，绝不改写响应内容。
- 名单匹配依赖本机 TCP 连接表反解进程；**无法反解时按「不在名单」处理**（fail-open，因为误拦会直接破坏用户正常上网）。
- 全局快捷键只接受预设白名单中的键位；注册失败整体回滚，不留半套状态。

---

## 安全港 / Safe Harbor

我们支持**善意的安全研究**：

- 只要你**不**访问、修改、删除不属于你的数据，**不**干扰他人使用，**不**公开披露未经修复的漏洞，
  我们不会对你采取法律行动，也不会向平台投诉。
- 请在测试时使用**你自己的设备与你自己构造的假数据**。
- 我们欢迎你在修复发布后公开你的研究成果，并会在此致谢。

---

## Security Policy (English)

AiGuard is a **security tool** that handles your most sensitive data while decrypting HTTPS locally, so the blast radius of a
vulnerability is larger than in a typical application. Security reports get our highest priority.

**Supported versions**: only the latest release (v0.1.x) receives security fixes.

**Reporting**: **do not disclose vulnerabilities in public issues, discussions, PRs or social media.** Use GitHub Security
Advisories at <https://github.com/Technicalflight/AiGuard/security/advisories/new>. If that is unavailable, open a public issue
containing **no details** and ask for a private channel.

**Please include**: impact, minimal reproduction steps, version and environment, your severity assessment, and optionally a
suggested fix. Never attach real personal data — use synthetic values you constructed yourself.

**Response targets**: acknowledgement within 3 business days, initial assessment within 7 business days, then fixes as severity
dictates. This is a personally maintained project, so timelines may slip; feel free to follow up politely (without details).

**In scope**: redaction bypass, restore/placeholder leakage, plaintext written to disk or logs, CA private-key protection bypass,
proxy/upstream redirection, audit forgery, privilege escalation, remote denial of service (including unbounded buffering), and
injection (XSS, command injection).

**Out of scope**: known upstream dependency CVEs (unless AiGuard uses them unsafely), attacks requiring pre-existing local admin
or memory access, SmartScreen prompts from unsigned installers, pinned-certificate apps being passed through (by design), and
social engineering or physical access.

**Safe harbor**: we support good-faith research. Do not access, modify or delete data that is not yours, do not disrupt others,
and do not publicly disclose unfixed issues — and we will not pursue legal action or file platform complaints. Test on your own
devices with synthetic data. We will credit you once a fix ships unless you ask to stay anonymous.
