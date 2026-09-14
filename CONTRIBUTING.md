# 贡献指南 / Contributing to AiGuard

感谢你愿意为 AiGuard 花时间。这是一个**安全工具**，所以它对「怎么改」比对「改了多少」更在意。
本文档说明参与方式、开发流程，以及几条**必须遵守**的硬规矩。

> 参与本项目即表示你同意遵守 [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)。
> 发现安全漏洞请**不要**开公开 Issue，按 [SECURITY.md](./SECURITY.md) 私下报告。

---

## 目录

- [一、你能贡献什么](#一你能贡献什么)
- [二、开发环境](#二开发环境)
- [三、提交前必须跑完的验收](#三提交前必须跑完的验收)
- [四、硬规矩（务必先读）](#四硬规矩务必先读)
- [五、代码风格](#五代码风格)
- [六、提交与 PR 流程](#六提交与-pr-流程)
- [Contributing (English)](#contributing-english)

---

## 一、你能贡献什么

| 类型 | 说明 | 入口 |
|---|---|---|
| 🐛 缺陷报告 | 复现步骤 + 版本 + 系统环境 + 期望行为 | [Bug report](https://github.com/Technicalflight/AiGuard/issues/new?template=bug_report.yml) |
| 💡 功能建议 | 描述**真实场景**，比「加个按钮」有用得多 | [Feature request](https://github.com/Technicalflight/AiGuard/issues/new?template=feature_request.yml) |
| 🧠 思路与设计讨论 | 代理架构、流式还原、名单匹配的取舍 | [Discussions](https://github.com/Technicalflight/AiGuard/discussions) |
| 🔐 安全设计 | 新检测维度、防绕过思路、威胁建模 | [Security advisories](https://github.com/Technicalflight/AiGuard/security/advisories/new) |
| 📖 文档与翻译 | 中英文措辞、截图、指南 | Pull Request |
| 🔧 代码 | 新检测规则、性能优化、界面打磨 | Pull Request |

**先讨论再动手**：任何会改变用户可见行为、配置格式或公开接口的改动，请先开 Issue 或 Discussion 达成一致，
避免你写完几百行之后发现方向不对。

---

## 二、开发环境

| 依赖 | 版本 |
|---|---|
| Windows | 10 / 11（x64）——**当前唯一受支持的目标平台** |
| Rust（MSVC 工具链） | 1.77+ |
| Node.js | 18+（CI 用 22） |
| WebView2 Runtime | Win11 一般自带 |

```bash
git clone https://github.com/Technicalflight/AiGuard.git
cd AiGuard
npm install
npm run tauri dev      # 开发模式（自动起 vite + cargo）
```

### 仓库结构

- `core/` —— 纯逻辑 crate（`aiguard-core`），**不依赖 Tauri 与代理框架**，因此可以脱离桌面环境独立测试。
  检测、映射、流式还原、审计信号、主动核查计划都在这里。
- `src-tauri/` —— 应用层：代理引擎、系统代理配置、进程识别、SQLite 存储、Tauri 命令。
- `src/` —— React 前端，全部界面在 `App.tsx`，设计系统在 `ui.css`。
- `scripts/` —— i18n 工具链与开发辅助脚本。

---

## 三、提交前必须跑完的验收

**改完不能只跑一个。** 全部跑完、全绿，才算改完：

```bash
npm run i18n:check      # 词典自检：键与调用点是否对齐、有无漏译（秒级）
npm run i18n:locale     # 窗口标题 / <html lang> 是否同步（stub DOM，无需浏览器）
npm run build           # tsc + vite 打包（类型错误在这里暴露）
cargo test --workspace  # Rust 全工作区测试（core + src-tauri，不要只跑 -p aiguard-core）
```

端到端界面扫描需要真浏览器（Playwright 与 Chrome 不在依赖里，属本地可选）：

```bash
npm run dev             # 另开一个终端，dev server 必须在跑
NODE_PATH=<node_modules 目录> AIGUARD_CHROMIUM=<chrome.exe 路径> npm run i18n:e2e
```

`i18n:e2e` 会打开 14 个界面（6 个导航页 + 5 个弹窗 + 向导 3 屏），扫描可见文本与
`title` / `placeholder` / `aria-label` / `alt` 属性里的残留中文，并校验数据面与原生面是否正常。

> `cargo check` 通过 ≠ 测试通过；`npm run build` 通过 ≠ i18n 自检通过。四件事互相独立，别互相替代。

---

## 四、硬规矩（务必先读）

这几条不是风格偏好，是这个项目踩过坑之后留下的防线。PR 里违反它们会被要求返工。

### 1. 新增检测器，必须**故意改坏一处**验证它真会报警

写完一个检测规则 / 断言 / 自检规则之后，**人为制造一次它应该捕获的违规**，确认它确实报错，再把违规改回去。
做不到「改坏就报警」的检测器，等于没写——它会安静地给你虚假的安全感。

### 2. 测试的输入值必须来自**真实生产路径**

测试里出现的字符串、枚举值、配置项，必须是生产代码真的会产出的值。
曾经有过一次事故：测试给某个字段传了生产**永远不会产生**的值，于是断言了一个不存在的契约，
整条路径被遮蔽了很久。写测试前先问：**这个值是谁产出的？**

### 3. 改完文件用 `git diff` 确认，不要靠「命令有没有输出」判断

长 `&&` 链会静默跳过中间失败环节，你会以为某一步没执行，实际它执行了。落盘之后一定用 `git diff` 复核。

### 4. 命名：禁止编号体系，展示名必须原创

- 禁止 `S1` / `G1` / `D1` 这类**编号**出现在代码、注释、界面文案、配置里。
- 用户可见的**展示名必须原创**：不要照搬参考项目或业界用滥的措辞。
- 禁止「主动探针 / canary / 金丝雀」这类词。本项目统一叫**「主动核查」**，注入的标记叫**「追踪标记」**。

### 5. 隐私红线：联网功能**默认必须关闭或静默**

任何新增的对外通信（更新检查、遥测、上报）默认必须是关闭的，且**关闭时一次请求都不发**。
隐私工具不允许「未经开启就对外通信」。这条没有例外。

### 6. 词典缺失宁可露中文，不可错译

i18n 词典以**中文原文为键**。查不到时回退中文，不要机翻、不要猜。宁可用户看到中文，也不要他看到一句错的英文。

---

## 五、代码风格

- **Rust**：`cargo fmt` 格式化；`cargo clippy` 尽量零告警。注释写**为什么**，不写「这里给 x 加 1」。
  重要约束（版本兼容、安全边界、踩过的坑）用注释留在现场——它们比文档更难丢失。
- **TypeScript / React**：`tsc` 严格模式；组件保持单一职责，状态提升到 `App.tsx` 顶层统一管理。
- **界面**：所有控件**自绘**，不引入会带出原生外观的组件库。新增样式写进 `ui.css`，并同步 `preview/` 设计稿。
- **文案**：界面文案一律走 `t()`，**实参必须是字面量**（`t("全部")`，不能 `t(someVar)`）——自检脚本靠字面量抽取词典。
  后端流进界面的字符串用 `tb()` 包一层。
- **提交信息**：`type(scope): 中文描述`，例如 `fix(i18n): 补齐弹窗内 3 处漏译`。
  type 用 `feat` / `fix` / `docs` / `test` / `chore` / `refactor` / `perf`。

---

## 六、提交与 PR 流程

1. **Fork** 仓库，从 `main` 拉出分支：`git checkout -b fix/rule-engine-ipv6`
2. 小步提交，每个提交只做一件事，便于回滚与审阅。
3. 跑完[第三节](#三提交前必须跑完的验收)的全部验收。
4. 发起 PR，并填好 PR 模板：**说明动机、改动范围、验证方式、影响面**。
5. 如果改动涉及界面，**附前后截图**。
6. 维护者可能会请你补测试或改命名——这不是刁难，见[第四节](#四硬规矩务必先读)。

PR 通过 CI（`.github/workflows/ci.yml`：前端构建 + 词典自检 + Rust 全工作区测试）后才会被合并。

---

## Contributing (English)

Thanks for taking the time to help. AiGuard is a **security tool**, so it cares more about *how* a change is made than *how much*
it changes. The essentials:

- **Discuss first.** Open an Issue or Discussion before implementing anything that changes user-visible behaviour, config formats
  or public interfaces.
- **Run the full acceptance suite** before submitting: `npm run i18n:check`, `npm run i18n:locale`, `npm run build`,
  `cargo test --workspace`. Passing one of them does not imply the others.
- **Every new detector must be verified by deliberately breaking something** and confirming it actually fires. A detector that
  cannot fail is not a detector.
- **Test inputs must come from real production paths** — never invent a value the production code can never produce.
- **Naming rules**: no numbered schemes (`S1` / `G1` / `D1`) in code, comments, UI or config; user-visible names must be original;
  avoid "probe / canary" jargon — this project says **active probe** and **trace marker**.
- **Privacy red line**: any new network activity must be off by default and silent — **zero requests while disabled**. No exceptions.
- **Missing translations fall back to Chinese**, never to a guessed English string.
- Report vulnerabilities privately per [SECURITY.md](./SECURITY.md), never in a public issue.

Commits follow `type(scope): description`. All contributions are accepted under the project's [AGPL-3.0 licence](./LICENSE).
