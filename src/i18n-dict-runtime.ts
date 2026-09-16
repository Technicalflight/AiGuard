/**
 * 运行期产生的文案词典（中文原文 -> 英文）——**手工维护**，不由脚本抽取。
 *
 * ── 为什么需要第三本词典 ──
 * 前两本的键都来自**源码字面量**：
 *   - UI_DICT      ← App.tsx / api.ts 里的 t() 调用点（`i18n_extract.mjs` 抽取）
 *   - BACKEND_DICT ← Rust 的字符串字面量（`i18n_rs_extract.mjs` 抽取）
 * 但有一类中文**根本不在我们的源码里**，而是运行期由外部产生、再拼进诊断文案的：
 *   - Windows 系统错误原文（`io::Error` 的 Display，如 `拒绝访问。 (os error 5)`）
 *   - 外部命令的输出（certutil / icacls / netsh / hosts 写入结果等）
 *
 * 它们会被塞进 `{}` 模板的内层，例如：
 *   `绑定 443 端口失败（可能被其他程序占用）: 拒绝访问。 (os error 5)`
 * 模板本身在 BACKEND_DICT 里能翻，但内层是**递归翻译**的（见 i18n.ts 的 tb），
 * 内层词条缺失就会留下半中半英——本文件存在的唯一理由。
 *
 * ── 维护约定 ──
 *  1. 只增不改；新增条目请按「系统实际产出的原文」逐字写，不要改写措辞；
 *  2. 这类串是**开放集合**（系统语言不同、错误种类不同都会变），
 *     覆盖不到时保持原样是预期行为——宁可露出中文，也不要错译；
 *  3. 键长按 `buildFragments` 的规则需 ≥4 个汉字才会生效（见 i18n.ts）。
 *
 * 注意：这些条目**没有调用点**，所以 `scripts/i18n_check.mjs` 会跳过孤儿键检查，
 * 但仍会检查「有没有漏翻译」。
 */
export const RUNTIME_DICT: Record<string, string> = {
  // ── Windows 常见错误（zh-CN 原文；带句号的按系统实际形态收，另收不带句号的短形态兜底）──
  "拒绝访问。": "Access is denied.",
  "拒绝访问": "Access is denied",
  "系统找不到指定的文件。": "The system cannot find the file specified.",
  "系统找不到指定的路径。": "The system cannot find the path specified.",
  "另一个程序正在使用此文件，进程无法访问。": "The process cannot access the file because it is being used by another process.",
  "由于目标计算机积极拒绝，无法连接。": "No connection could be made because the target machine actively refused it.",
  "信号灯超时时间已到。": "The semaphore timeout period has expired.",
  "操作超时": "The operation timed out",
  "参数错误。": "The parameter is incorrect.",
  "文件名、目录名或卷标语法不正确。": "The filename, directory name, or volume label syntax is incorrect.",
  "磁盘空间不足。": "There is not enough space on the disk.",
  "设备未就绪。": "The device is not ready.",
  "请求的操作需要提升。": "The requested operation requires elevation.",
  "没有与网络连接相关的其他信息。": "No more information is available about the network connection.",
};
