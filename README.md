<div align="center">

<img src="docs/logo.png" width="120" alt="AiGuard" />

# AiGuard

**敏感信息不出本机的 AI 流量守护工具**

在本地拦截发往 AI 服务的请求，自动把身份证、手机号、API Key 等敏感信息替换为可还原的占位符；
AI 回复到达后，在本地流式还原为真实数据 —— **原文永不出网、永不落盘**。

[![Rust](https://img.shields.io/badge/Rust-1.77%2B-DEA584?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-2-24C8D8?logo=tauri&logoColor=white)](https://tauri.app/)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=white)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D4?logo=windows11&logoColor=white)
![Platform](https://img.shields.io/badge/macOS-10.15%2B%20%28universal%29-000000?logo=apple&logoColor=white)
![Platform](https://img.shields.io/badge/Linux-x64%20%28deb%20%2F%20AppImage%29-FCC624?logo=linux&logoColor=black)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-important.svg?logo=gnu)](./LICENSE)
[![License: Commercial](https://img.shields.io/badge/License-Commercial%20Contact-white.svg?logo=github)](https://github.com/Technicalflight/AiGuard/issues)

**[简体中文](./README.md) &nbsp;·&nbsp; [English](./README.en.md)**

</div>
<div align="center"><a href="https://www.producthunt.com/products/aiguard?embed=true&amp;utm_source=badge-featured&amp;utm_medium=badge&amp;utm_campaign=badge-aiguard" target="_blank" rel="noopener noreferrer"><img alt="AiGuard - A local-first AI traffic guard | Product Hunt" width="250" height="54" src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=1252567&amp;theme=light&amp;t=1789578869778"></a></div>
> [!IMPORTANT]
> AiGuard 目前处于早期开发阶段（v0.1.x），配置格式与内部接口随时可能变化。项目基于 **AGPL-3.0** 开源——欢迎 Star、Issue 与 PR。

AiGuard 是一个**本地优先**的 AI 流量安全网关：以系统代理 + 自签根证书接管发往 AI 服务的 HTTPS 流量，在请求出网前完成敏感信息脱敏，在响应回程时完成流式还原，并全程只读审计上游行为。它不代理你的数据到任何第三方——**守护管道跑在你自己机器上**。

---

## ✨ 核心特性

### 🔁 本机 MITM 反向代理
- 基于 **系统代理 + PAC** 自动接管：仅 AI 域名流量进入守护管道，其余流量直连不受影响
- 覆盖 OpenAI / Anthropic / DeepSeek / Moonshot / 智谱 等主流 AI 服务的 **API 与网页端**域名
- 使用自签根证书解密 HTTPS，证书由设置页**一键安装**（装入当前用户级信任库，无需管理员权限），随时可撤销

### 🕵️ 请求侧敏感信息脱敏
- 内置 **6 类检测规则**：身份证 / 手机号 / 银行卡 / 邮箱 / API Key / IP 地址
- 每条规则可独立开关、可编辑正则、可改命中动作（脱敏 / 拦截 / 仅提醒），支持自定义正则扩展
- 命中内容替换为形如 `[[PII:PHONE:8f3a2b1c]]` 的**可还原占位符**后发往 AI 服务 —— AI 永远看不到真实数据

### 🔄 响应侧流式还原
- AI 回复（含 SSE 流式输出）中的占位符在本地**逐帧还原**为真实数据，用户无感知
- 前瞻缓冲处理占位符被 TCP 拆分到多个 chunk 的情况；多字节字符由增量 UTF-8 解码器拼接
- 按 content-type / content-encoding 设置门槛：JSON / SSE / 明文进管道，二进制与压缩流量原样透传

### 🛡️ 七大防护信号（只读审计 + 主动核查）
| 信号 | 说明 |
|---|---|
| 报错泄密 | 上游错误信息中夹带用户原文 |
| 模型偷换 | 请求与响应的模型身份不一致 |
| 复读篡改 | 响应中占位符被改写或残留 |
| 流式异常 | SSE 流完整性异常 |
| 响应夹带 | 响应中夹带与本次会话无关的内容 |
| 记忆残留 | 上游跨请求复用 / 存储了会话数据 |
| 高危指令 | 检测可能危害本机的指令注入 |

- **只读审计**：发现只记录、不改写响应；证据仅含类型 / 长度 / 摘要，按严重度门槛写入 SQLite
- **主动核查**：向会话注入追踪标记并独立验证「上游是否存储 / 回显数据」，输出多维风险矩阵

### 📋 黑名单 / 白名单
- **黑名单**：命中后强制执行所选动作（**403 拦截** 或 **强制脱敏**），优先级最高，覆盖规则与白名单
- **白名单**：命中的域名 / 程序不执行拦截（Block 规则降级为脱敏），「仍执行脱敏」开关决定直通或脱敏
- 进程名单支持**调用系统资源管理器选择 exe / 文件夹**，通过本机 TCP 连接表把请求反解到进程路径后匹配
  （exe 完整路径 / 所在文件夹前缀 / 仅文件名，三种匹配方式；识别失败的连接按不在名单处理）

### 🎨 桌面级自定义界面
- Tauri 2 自定义无边框窗口：42px 标题栏 + 64px 图标导航栏，深墨绿侧栏 + 守护绿设计系统
- 下拉、日历、弹窗、开关、滚动条**全部自绘**，无任何原生控件残留

### 🧭 首次运行向导（证书 → 代理 → 规则）
- 首次启动自动弹出三步向导：**安装根证书 → 开启守护 → 确认检测规则**
- 每一步都显示**真实状态**（证书是否已在信任库、守护是否已开启），不靠本地猜测
- **每一步都能跳过**：向导只是检查清单，不构成使用前提；设置页可随时「重新运行」
- 向导版本化：步骤集合发生实质变化时会自动重放一次，`setup.version` 记录完成时的版本

### ⌨️ 全局快捷键
- 两个动作可各自绑定键位：**开关守护** / **一键应急切断**，任意窗口下生效
- 键位只从**预设白名单**中挑选——全局快捷键是抢占式的，放开任意字符串等于让一次误配置吞掉用户某个常用组合
- 保存时校验「两个动作不能撞键」；**注册失败整体回滚**并提示原因，绝不留下「设置里写着已启用、按键却毫无反应」的半套状态
- 默认 `Ctrl+Alt+G` / `Ctrl+Alt+X`，可在设置页整体关闭

### 🌐 多语言（简体中文 / English）
- 界面语言在**设置页一键切换**，窗口内文案、系统托盘菜单、桌面通知共用同一份设置
- 词典以**中文原文为键**：改英文措辞不需要动任何调用点；后端返回的中文诊断由前端同一张表翻译，无需给 40 多个 Tauri 命令各加一轮语言参数
- 带 `{}` 的条目自动升级为「前缀 + 捕获组」规则，能逐层翻译 `绑定 443 端口失败（…）: 拒绝访问` 这类「模板 + 内层原因」
- 词典缺失的片段**回退中文**而不是输出错译；`npm run i18n:check` 把「调用点在用但词典没有」的键当成错误报出来

### 🔄 自动更新检查（默认关闭）
- **默认整体关闭，关闭时一次网络请求都不发**——隐私工具不允许「未经开启就对外通信」
- 开启后启动 20 秒检查一次、之后每 24 小时一次，只向 GitHub Releases 发**一个 GET**，不带任何本机数据（连 User-Agent 也只写应用名与版本）
- 更新源可改（`owner/name`）；「立即检查」是用户明确点击的动作，不受总开关限制
- 任何失败都折叠进状态字段展示，不会因为网络不通而弹红字或影响其它流程

---

## 🖼️ 运行界面

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/home.png" alt="守护首页" /></td>
    <td width="50%"><img src="docs/screenshots/rules.png" alt="规则中心" /></td>
  </tr>
  <tr>
    <td align="center"><sub>守护首页 · 已守护天数 / 实时脱敏流水 / 数据总览</sub></td>
    <td align="center"><sub>规则中心 · 检测规则卡片 + 黑 / 白名单</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/requests.png" alt="请求监控" /></td>
    <td width="50%"><img src="docs/screenshots/audit.png" alt="审计日志" /></td>
  </tr>
  <tr>
    <td align="center"><sub>请求监控 · 实时脱敏流水与详情</sub></td>
    <td align="center"><sub>审计日志 · 只读证据记录</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/settings.png" alt="系统设置" /></td>
    <td align="center"><sub>系统设置 · 拦截模式 / CA 根证书 / 数据安全</sub></td>
  </tr>
</table>

---

## 🔒 工作原理

```mermaid
flowchart LR
    A["本机 AI 应用<br/>桌面客户端 · CLI · IDE 插件"] -->|"① 请求经系统代理进入"| P

    subgraph P["AiGuard · 本机守护管道"]
        direction TB
        B["黑 / 白名单评估<br/>黑名单：拦截 或 强制脱敏<br/>白名单：Block 降级 / 直通"] --> C["规则引擎<br/>6 类 PII 检测"]
        C -->|"命中 → 替换为占位符"| V["Vault 会话映射<br/>原文仅存内存 · TTL · 在途锁定"]
        V --> D["转发脱敏后的请求"]
        D --> E["响应侧还原内核<br/>SSE 流式占位符还原"]
        E --> F["只读审计层<br/>7 大防护信号 · 证据脱敏"]
    end

    P -->|"② AI 看到的只有占位符"| U["上游 AI 服务"]
    U -->|"③ 含占位符的回复"| E
    P -->|"④ 还原为真实数据"| A
    F -->|"门槛以上的事件"| DB[("SQLite 审计库")]
```

**请求方向**：请求发往 AI 域名且 Content-Type 为 JSON 时，递归扫描所有字符串值，命中的原文替换为占位符。
同一会话内同一原文永远得到同一占位符，保证多轮对话一致性。

**响应方向**：AI 回复中的占位符在本机被还原为原文。SSE 流式响应中占位符可能被 TCP 拆到不同 chunk，
还原内核用前瞻缓冲处理：凑齐闭合符才查表还原，半截前缀扣留不发，超长未闭合内容直接放行（防恶意无限缓冲）。

> **隐私红线**：敏感原文只存在于本机内存的会话映射中（带 TTL 与在途锁定，可开启「退出时清空映射表」）；
> 日志与审计事件仅包含类型 / 长度 / 摘要 / 请求哈希，**任何环节不落盘原文、不上传任何数据**。

---

## 🚀 快速开始

### 环境要求

| 依赖 | 版本 |
|---|---|
| Windows | 10 / 11（x64） |
| macOS | 10.15+（universal：Apple Silicon 与 Intel 一体） |
| Linux | x64（deb / AppImage；需 WebKitGTK 4.1 运行库） |
| Rust（MSVC / Xcode CLT / gcc） | 1.77+ |
| Node.js | 18+ |
| WebView2 Runtime | Win11 一般自带 |

### 下载安装

前往 [Releases](https://github.com/Technicalflight/AiGuard/releases) 页面按平台下载：

| 平台 | 产物 |
|---|---|
| Windows | `*-setup.exe`（NSIS 向导）、`*.msi` |
| macOS | `*.dmg`（universal，Apple Silicon 与 Intel 通用） |
| Linux | `*.deb`、`*.AppImage` |

> [!NOTE]
> 安装包暂未做代码签名：Windows 首次运行可能出现 SmartScreen 提示，点「仍要运行」即可；
> macOS 首次打开请**右键 → 打开**（或在「系统设置 → 隐私与安全性」里放行）；
> Linux 的 AppImage 需要 `chmod +x` 后运行。

### 平台差异

守护核心（MITM 代理、脱敏、流式还原、审计、双语界面）在三个平台**完全一致**；
与操作系统打交道的部分按平台走原生通道：

| 能力 | Windows | macOS | Linux |
|---|---|---|---|
| 系统代理（PAC） | 注册表 + WinINET | `networksetup`（逐网络服务） | GNOME `gsettings` |
| 根证书信任 | `certutil -user`（当前用户库） | `security add-trusted-cert`（登录钥匙串） | NSS 用户库 / 系统信任库 |
| 根证书撤销 | `certutil -delstore` | `security delete-certificate` | 删除证书 + 重算信任库 |
| hosts 提权 | UAC（PowerShell RunAs） | osascript 授权框 | `pkexec`（退回 `sudo -n`） |
| CA 私钥落盘 | DPAPI 加密 | 钥匙串（文件只留指针） | **明文 + 0600**（无系统密钥库） |
| 数据目录权限检查 | `icacls` ACL | 权限位 | 权限位 |
| 调试器附加检测 | Win32 API | `sysctl`（P_TRACED） | `/proc` TracerPid |
| 进程归因 | 连接表 + 进程句柄 | `lsof` | `/proc/net/tcp` |
| DNS 缓存刷新 | `ipconfig /flushdns` | `dscacheutil` + mDNSResponder | `resolvectl` |

> [!IMPORTANT]
> Linux 桌面若无 `gsettings`（非 GNOME）或没有 polkit（`pkexec`），对应的系统能力会明确提示
> 需要手动完成——守护不会在「你以为已接管、实际明文直连」的状态下静默运行。
> 443 透明层（hosts 模式）在所有平台都需要管理员 / root 权限才能监听。

### 从源码运行

```bash
git clone https://github.com/Technicalflight/AiGuard.git
cd AiGuard
npm install
npm run tauri dev
```

### 构建安装包

```bash
npm run tauri build
# 产物位于 src-tauri/target/release/bundle/（Windows: nsis + msi）
```

按平台补充：

```bash
# macOS（universal：Apple Silicon + Intel 一体）
rustup target add aarch64-apple-darwin x86_64-apple-darwin
npm run tauri build -- --target universal-apple-darwin --bundles dmg

# Linux（deb + AppImage；需要 WebKitGTK 4.1 开发库）
sudo apt-get install -y libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf
npm run tauri build -- --bundles deb,appimage
```

### 跑测试与自检

```bash
cargo test --workspace   # Rust 全工作区单元测试（core + src-tauri）
npm run build            # 前端类型检查 + 打包
npm run i18n:check       # 词典自检：键与调用点是否对齐、有无漏译
```

---

## 📖 使用指南

1. **首次运行向导**：首次启动会自动弹出「证书 → 代理 → 规则」三步向导。每一步都会读取真实状态，
   也可以直接「跳过向导」——向导只是检查清单，跳过不影响任何功能；设置页可随时「重新运行」。
2. **安装根证书**：向导第一步，或进入「设置」→「CA 根证书」→「安装根证书」。守护管道需要解密 HTTPS
   才能检测 / 脱敏；证书仅影响本机当前用户信任链，可随时撤销。
3. **开启守护**：向导第二步，或打开标题栏「代理开关」，自动写入 Windows 系统代理 + PAC 文件
   （仅 AI 域名走本地代理）。
4. **确认检测规则**：向导第三步展示内置规则与名单优先级，可到「规则中心」按需调整。
5. **正常使用 AI 应用**：无需任何额外配置，敏感信息自动替换、回复自动还原。
6. **配置快捷键**：进入「设置」→「全局快捷键」，为「开关守护」和「一键应急切断」各选一个键位
   （从预设中挑，避免与常用组合冲突）。键位被其它程序占用时界面会显示「未生效」及原因。
7. **切换界面语言**：进入「设置」→「界面语言」选 English，窗口、托盘菜单与桌面通知同步切换。
8. **按需配置名单**：在「规则中心」添加黑 / 白名单。进程类名单点击「浏览文件…」/「浏览文件夹…」
   从资源管理器选择，也可以粘贴路径或填写域名。
9. **查看防护情况**：「请求页」看实时脱敏流水与详情，「审计页」看历史证据，「守护首页」看整体状态。
10. **自动更新检查（可选）**：进入「设置」→「自动检查更新」打开。**默认关闭，关闭时不会发起任何网络请求**；
    开启后每 24 小时向 GitHub Releases 查一次新版本，不带任何本机数据。也可以随时点「立即检查」手动查一次。

---

## 🧱 项目结构

```
AiGuard/
├── Cargo.toml               # workspace 根（core + src-tauri）
├── core/                    # Rust 纯逻辑层（aiguard-core，可独立 cargo test）
│   └── src/
│       ├── detector.rs      # 敏感信息检测引擎（正则 + 语义校验）
│       ├── vault.rs         # 原文 ↔ 占位符映射（会话隔离 + TTL，仅内存）
│       ├── stream.rs        # 流式还原状态机（前瞻缓冲，处理占位符被拆 chunk）
│       ├── sse.rs           # SSE 帧状态机（切帧 / 格式校验 / 缓冲上限）
│       ├── audit.rs         # 7 大防护信号纯检测层（只读，不改写响应）
│       ├── inspect.rs       # 主动核查计划、风险矩阵与审计报告
│       ├── secure.rs        # 还原管道 + 审计上下文采集
│       └── mem.rs           # 敏感内存主动擦除（销毁映射时覆写字节）
├── src-tauri/               # Tauri 2 应用层
│   └── src/
│       ├── main.rs          # 入口：打开存储 → 构建状态 → 生成 CA → 启动代理 → 注册命令 / 快捷键
│       ├── state.rs         # AppState、CA 生成、AI 域名表、黑/白名单、向导 / 快捷键 / 更新配置
│       ├── proxy.rs         # hudsucker MITM 引擎（脱敏 / 拦截 / 还原）
│       ├── transparent.rs   # hosts 模式透明拦截层（SNI 识别 → 动态签发 → 桥接本地代理）
│       ├── hosts.rs         # hosts 文件标记块写入 / 移除（三平台各自的提权通道）
│       ├── dns.rs           # 绕过系统解析器的 DNS 直查（hosts 模式配套）
│       ├── process.rs       # 客户端进程识别（连接表 → PID → 可执行文件路径）
│       ├── proxy_config.rs  # 三平台系统代理（注册表 / networksetup / gsettings）+ PAC 生成
│       ├── security.rs      # 本机安全加固：调试器检测、CA 私钥系统级保护、端口占用诊断
│       ├── store.rs         # SQLite 持久化：请求日志 / 审计事件 / kv 配置（不存原文）
│       ├── link_check.rs    # 主动核查执行器（追踪标记注入 + 回显验证）
│       ├── console.rs       # 外部命令输出解码（Windows 系统代码页 → UTF-8；unix 直读）
│       ├── i18n.rs          # 窗口外界面（托盘 / 通知）的中英文表，按 Language 取词
│       └── commands.rs      # Tauri 命令 + 事件
├── src/                     # React + TypeScript 前端（Vite）
│   ├── App.tsx              # 全部界面：首页 / 请求 / 规则 / 防护 / 审计 / 设置 + 首次运行向导
│   ├── api.ts               # Tauri 命令封装（含浏览器预览下的 MOCK 数据源）
│   ├── i18n.ts              # 多语言内核（t / tb / 语言订阅）
│   ├── i18n-dict-ui.ts      # 前端文案词典（键 = 中文原文）
│   ├── i18n-dict-backend.ts # 后端诊断文案词典（翻译 Err(String) 回到界面）
│   ├── i18n-dict-runtime.ts # 运行期才产生的中文（拼接串、系统回传）
│   └── ui.css               # 设计系统（自绘控件样式，与 preview/ 同源）
├── preview/                 # 静态界面设计稿（与 src/ui.css 同源，双击即开）
├── docs/                    # README 素材：logo、运行界面截图、i18n 审计记录
└── scripts/                 # 开发工具脚本
    ├── i18n_extract.mjs     # 把 App.tsx 的中文文案改写为 t(...) 并维护 UI 词典
    ├── i18n_rs_extract.mjs  # 抽取 Rust 侧会进界面的中文，维护 BACKEND 词典
    ├── i18n_merge.mjs       # 合并一批译文（自动排序、自动判断归属词典）
    ├── i18n_check.mjs       # 词典自检：键与调用点是否对齐、有无漏译
    ├── i18n_locale_check.mjs# 窗口标题与 <html lang> 同步自检
    ├── i18n_e2e.mjs         # 真浏览器端到端扫描（14 个界面 + 原生属性）
    └── rust_scan.mjs        # Rust 中文字面量扫描器（供上面几个脚本复用）
```

---

## ⚠️ 已知限制

- hosts 模式与 TUN 模式尚未实现（界面中标记「规划中」）。
- 启用了证书固定（pinning）的应用无法被拦截，会自动放行（不破坏其工作）。
- QUIC / HTTP3（UDP）流量不走系统代理，需在浏览器侧禁用 QUIC（如 `chrome://flags`）才能完整覆盖。
- 同一原文的占位符在不同会话间不同：跨会话的对话各自独立还原，请勿手动复制占位符到其他会话。
- **Linux** 无系统级密钥库可用时，CA 私钥以明文落盘并收紧到 0600（加固面板会如实显示为「明文」）；
  非 GNOME 桌面 / 无 polkit 环境下，系统代理与 hosts 提权需要按提示手动完成。

---

## 🛣️ Roadmap

- [x] 多语言界面（简体中文 / English）
- [x] 首次运行向导（证书 → 代理 → 规则）
- [x] 全局快捷键（开关守护 / 一键应急切断）
- [x] 自动更新检查（默认关闭，不默认上报）
- [ ] 更多内置检测规则（JWT、PEM 私钥、AWS Access Key、连接串密码等）
- [ ] 审计事件的进程归因与按渠道统计
- [ ] 出口代理支持（企业网络环境）
- [ ] 主动核查历史趋势报告

---

## 🤝 贡献 / Contributing

AiGuard 是一个**安全工具**，它欢迎的贡献不止于代码。以下任何一类都同样有价值：

| 类型 | 说明 |
|---|---|
| 🐛 **缺陷报告** | 复现步骤 + 版本 + 系统环境，越具体越好 |
| 💡 **功能建议** | 想解决的真实场景，比「加个按钮」更能帮助设计 |
| 🧠 **思路与设计讨论** | 代理架构、流式还原、名单匹配的取舍——先讨论再写代码 |
| 🔐 **安全设计** | 检测规则、防绕过思路、威胁建模、审计信号的新维度 |
| 📖 **文档与翻译** | 中英文措辞、截图、使用指南的改进 |
| 🔧 **代码贡献** | 新检测规则、性能优化、界面打磨 |

动手之前请先读 **[CONTRIBUTING.md](./CONTRIBUTING.md)**；参与本项目即表示你同意遵守 **[CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)**。

> [!WARNING]
> **发现安全漏洞请不要开公开 Issue**，按 **[SECURITY.md](./SECURITY.md)** 的私下渠道报告。

---

## 💬 社区联系 / Community

- **[GitHub Issues](https://github.com/Technicalflight/AiGuard/issues)** — 缺陷报告、功能建议、设计讨论的主要入口
- **[GitHub Discussions](https://github.com/Technicalflight/AiGuard/discussions)** — 开放式提问与经验分享
- **[Linux.Do](https://linux.do)** — 一个分享和讨论技术的社区

---

## 📦 开源支持 / Built on open source

AiGuard 站在这些优秀开源项目之上：

[Tauri](https://tauri.app) · [React](https://react.dev) · [Vite](https://vite.dev) · [TypeScript](https://www.typescriptlang.org) ·
[hudsucker](https://github.com/omjadas/hudsucker) · [hyper](https://hyper.rs) · [tokio](https://tokio.rs) ·
[rustls](https://github.com/rustls/rustls) · [rcgen](https://github.com/rustls/rcgen) · [rusqlite](https://github.com/rusqlite/rusqlite) ·
[serde](https://serde.rs) · [regex](https://github.com/rust-lang/regex) 以及 Rust 生态的众多 crate。

如果 AiGuard 用起来顺手，也欢迎去给这些上游项目点个 Star —— 它们同样值得。

---

## ☕ 赞助 / Sponsor

如果 AiGuard 对你有帮助，欢迎请作者喝杯咖啡或可乐 ☕🥤——每一杯都是持续开发的动力。

<p align="center">
  <img src="docs/sponsor-alipay.png" width="250" alt="支付宝收款码"/>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <img src="docs/sponsor-wechat.png" width="250" alt="微信收款码"/>
</p>
<p align="center"><sub>左：支付宝 Alipay &nbsp;·&nbsp; 右：微信 WeChat Pay</sub></p>

> [!WARNING]
> **赞助前请务必阅读**：赞助是**完全自愿**的感谢行为。**赞助不会提高或加快任何功能、缺陷修复或其他工作的实现优先级**——所有开发均按路线图与社区需求推进，与是否赞助、赞助多少完全无关。赞助仅代表感谢，不构成任何商业授权、优先支持或其他额外承诺。

---

## ⚠️ 免责声明

- 本项目为**学习研究性质**的安全工具，与文中提及的任何 AI 服务商均无关联。
- 请仅在你拥有合法授权的设备与网络环境中使用，并遵守当地法律法规与目标服务的用户协议；
  禁止用于监控他人流量或绕过他人设备的安全机制。
- 软件按「现状」提供，**不附带任何明示或默示的担保**；作者不对因使用本软件产生的任何后果负责。

---

## 许可证 / License

AiGuard is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**, available at <https://www.gnu.org/licenses/agpl-3.0.html> — see the [LICENSE](./LICENSE) file for the full text.

Use of AiGuard for **commercial purposes is permitted**, subject to full compliance with the terms and conditions of the AGPL-3.0 license — including its network-use clause: if you modify AiGuard and offer it as a network service, you must make the complete corresponding source code available to the users of that service.

Should you require a **commercial license** that provides an exemption from the AGPL-3.0 requirements (e.g. closed-source or internal deployment without the source-disclosure obligations), please open an issue at <https://github.com/Technicalflight/AiGuard/issues> to contact the author.

---

中文说明：本项目社区版采用 **AGPL-3.0** 许可证。你可以自由地使用、学习、修改和分发本项目（包括商业用途），但必须完整遵守 AGPL-3.0 全部条款——尤其是**网络服务条款**：修改后的版本若以网络服务形式提供给他人使用，必须向使用者提供完整的对应源代码。如需**豁免上述开源义务的商业授权**（如闭源部署、OEM 集成），请通过 [GitHub Issues](https://github.com/Technicalflight/AiGuard/issues) 联系作者洽谈。

Copyright © 2026 Technicalflight

---

## Star History

<a href="https://www.star-history.com/?repos=technicalflight%2Faiguard&type=date&legend=bottom-right">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=technicalflight/aiguard&type=date&theme=dark&legend=top-right" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=technicalflight/aiguard&type=date&legend=top-right" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=technicalflight/aiguard&type=date&legend=top-right" />
 </picture>
</a>
