/**
 * 从 Rust 侧抽取**会进入界面**的中文文案，生成 src/i18n-dict-backend.ts 的键骨架。
 *
 * 为什么前端要管后端的中文：后端所有 `#[tauri::command]` 的失败路径都是
 * `Err(String)`，前端拿到的是中文原文（如「绑定 443 端口失败（可能被其他程序占用）: ...」）。
 * 给 40 多个命令各加一轮语言参数既啰嗦又容易漏，所以这里改用「前端按同一张表翻译」，
 * 由 src/i18n.ts 的 tb() 完成（先跑带 {} 的规则，再做长片段替换）。
 *
 * 扫描口径（注释 / 测试模块 / 字符字面量 / 多行串的处理）全部在 `scripts/rust_scan.mjs`，
 * 与 `i18n_check.mjs` 共用，避免两边口径漂移。
 *
 * ⚠ 两个 crate 都要扫：信号名与信号描述定义在 `core/src/audit.rs`，它们**确实会回到界面**
 * （`get_signals` 返回 name/desc 给信号卡片）。只扫 src-tauri/src 会漏掉整批，
 * 表现为英文模式下信号卡片一半英文一半中文——曾经真的漏过。
 *
 * 用法：node scripts/i18n_rs_extract.mjs [输出词典.ts]
 */
import fs from "node:fs";
import { scanRustStrings, RUST_ROOTS } from "./rust_scan.mjs";

const OUT_DICT = process.argv[2] ?? "src/i18n-dict-backend.ts";

const found = scanRustStrings(RUST_ROOTS);
const sorted = [...found.keys()].sort((a, b) => a.localeCompare(b, "zh"));

/**
 * 写出词典骨架，**保留已有译文**。
 *
 * 这一点是硬要求：本脚本会把整本词典重写一遍，如果无脑写空值，
 * 一次「想看看有没有漏抽」的重跑就会把几百条译文清空，而且 git diff 里
 * 看起来只是「一堆字符串变空了」，很容易被顺手提交掉。
 * 因此已存在的键一律沿用原值，只为新出现的键留空。
 */
function readExisting(path) {
  if (!fs.existsSync(path)) return new Map();
  const src = fs.readFileSync(path, "utf8");
  const map = new Map();
  const re = /^\s*("(?:[^"\\]|\\.)*"):\s*("(?:[^"\\]|\\.)*"),\s*$/gm;
  for (const m of src.matchAll(re)) map.set(JSON.parse(m[1]), JSON.parse(m[2]));
  return map;
}

const existing = readExisting(OUT_DICT);
const fresh = sorted.filter((k) => !existing.has(k));
const kept = sorted.filter((k) => existing.has(k));
// 词典里有、但扫描不到了（调用点已删 / 文案已改）——报告出来，别让它们悄悄变成死条目
const stale = [...existing.keys()].filter((k) => !found.has(k));

const stub = [
  "/**",
  " * 后端文案词典（中文原文 -> 英文）。",
  " *",
  " * 键由 `scripts/i18n_rs_extract.mjs` 从 src-tauri/src 与 core/src 两个 crate 抽取，",
  " * **必须与后端产出的中文逐字一致**。",
  " * 覆盖范围：会随 `Err(String)` 回到界面的诊断文案，以及 core 里定义的信号名/信号描述。",
  " *   - 不含注释与 #[cfg(test)] 里的文案（永远不上界面）",
  " *   - 不含 i18n.rs（托盘 / 通知由后端自己按语言取词，表里已同时给出中英文）",
  " *",
  " * 带 `{}` 的条目会被 i18n.ts 升级为「前缀 + 捕获组」规则，",
  " * 用来翻译 `绑定 443 端口失败（可能被其他程序占用）: 拒绝访问` 这种「模板 + 内层原因」；",
  " * 内层原因会被递归翻译。{} 的个数两边必须一致，否则该条目会被忽略（不会错译）。",
  " *",
  " * 本表也顺带覆盖了一批只在 `log::` 里出现的文案。它们其实不上界面，",
  " * 保留的理由是「宁可多译、不可漏译」：日志文案与诊断文案常常是同一条中文，",
  " * 逐个甄别哪些会回到界面，比多写几行译文贵得多，而且漏判的代价是界面上露出中文。",
  " */",
  "export const BACKEND_DICT: Record<string, string> = {",
  ...sorted.map((k) => `  ${JSON.stringify(k)}: ${JSON.stringify(existing.get(k) ?? "")},`),
  "};",
  "",
].join("\n");
fs.writeFileSync(OUT_DICT, stub, "utf8");

console.log(
  `backend keys=${sorted.length}（沿用 ${kept.length} 条译文，新增待译 ${fresh.length} 条）-> ${OUT_DICT}`
);
if (fresh.length) for (const k of fresh) console.log(`    + ${JSON.stringify(k)}`);
if (stale.length) {
  console.log(`\n[注意] 词典里有但本次没扫到的 ${stale.length} 条（文案已改或调用点已删）：`);
  for (const k of stale) console.log(`    - ${JSON.stringify(k)}`);
}
