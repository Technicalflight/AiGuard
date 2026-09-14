/**
 * 从 Rust 侧抽取**会进入界面**的中文文案，生成 src/i18n-dict-backend.ts 的键骨架。
 *
 * 为什么前端要管后端的中文：后端所有 `#[tauri::command]` 的失败路径都是
 * `Err(String)`，前端拿到的是中文原文（如「绑定 443 端口失败（可能被其他程序占用）: ...」）。
 * 给 40 多个命令各加一轮语言参数既啰嗦又容易漏，所以这里改用「前端按同一张表翻译」，
 * 由 src/i18n.ts 的 tb() 完成（先跑带 {} 的规则，再做长片段替换）。
 *
 * 三处刻意排除：
 *  1. **注释**：注释里的中文永远不会出现在界面上；
 *  2. **#[cfg(test)] 模块**：测试断言里的中文同理；
 *  3. **src-tauri/src/i18n.rs**：托盘菜单 / 桌面通知的文案。那是「窗口外」的界面，
 *     后端自己按 Language 取词（表里已同时给出中英文），前端再收一份只会两边打架。
 *
 * 用法：node scripts/i18n_rs_extract.mjs [输出词典.ts]
 */
import fs from "node:fs";
import path from "node:path";

const OUT_DICT = process.argv[2] ?? "src/i18n-dict-backend.ts";
const ROOT = "src-tauri/src";
const CJK = /[\u4e00-\u9fff]/;

function walk(dir, acc = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name.endsWith(".rs")) acc.push(p);
  }
  return acc;
}

/** 去掉行注释与块注释（保留字符串字面量里的 // 与 /*）。 */
function stripComments(src) {
  let out = "";
  let i = 0;
  let inStr = false;
  let inChar = false;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (!inStr && !inChar && c === "/" && n === "/") {
      while (i < src.length && src[i] !== "\n") i++;
      continue;
    }
    if (!inStr && !inChar && c === "/" && n === "*") {
      i += 2;
      let depth = 1;
      while (i < src.length && depth > 0) {
        if (src[i] === "/" && src[i + 1] === "*") { depth++; i += 2; continue; }
        if (src[i] === "*" && src[i + 1] === "/") { depth--; i += 2; continue; }
        i++;
      }
      continue;
    }
    // Rust 原始字符串 r"..." / r#"..."#
    if (!inStr && !inChar && c === "r" && (n === '"' || n === "#")) {
      let j = i + 1;
      let hashes = 0;
      while (src[j] === "#") { hashes++; j++; }
      if (src[j] === '"') {
        const close = '"' + "#".repeat(hashes);
        const end = src.indexOf(close, j + 1);
        if (end > 0) { out += src.slice(i, end + close.length); i = end + close.length; continue; }
      }
    }
    if (!inStr && c === '"') { inStr = true; out += c; i++; continue; }
    if (inStr && c === "\\") { out += c + (n ?? ""); i += 2; continue; }
    if (inStr && c === '"') { inStr = false; out += c; i++; continue; }
    out += c;
    i++;
  }
  return out;
}

/**
 * 去掉 #[cfg(test)] 模块。
 *
 * 做法是括号配平：从 `mod` 之后的第一个 `{` 开始数到与之配对的 `}`。
 * 字符串与注释已在 stripComments 里处理过，所以这里可以安全地只数括号。
 */
function stripTestModules(src) {
  let out = src;
  for (;;) {
    const m = /#\[cfg\(test\)\]/.exec(out);
    if (!m) return out;
    const brace = out.indexOf("{", m.index);
    if (brace < 0) return out.slice(0, m.index);
    let depth = 0;
    let i = brace;
    for (; i < out.length; i++) {
      if (out[i] === "{") depth++;
      else if (out[i] === "}") {
        depth--;
        if (depth === 0) break;
      }
    }
    out = out.slice(0, m.index) + out.slice(i + 1);
  }
}

/**
 * 还原 Rust 字符串字面量里的转义。
 *
 * 必须做：抽取到的是**源码原文**，而运行时的文案已经过转义处理。
 * 例如源码 `format!("还原统计: sid=\"{}\" ...")` 运行时是 `还原统计: sid="{}" ...`；
 * 若把带反斜杠的源码形态当键，翻译永远匹配不上（而且不会报任何错）。
 */
function unescapeRust(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "\\") {
      out += s[i];
      continue;
    }
    const n = s[i + 1];
    switch (n) {
      case "n": out += "\n"; i++; break;
      case "r": out += "\r"; i++; break;
      case "t": out += "\t"; i++; break;
      case "0": out += "\0"; i++; break;
      case "\\": out += "\\"; i++; break;
      case '"': out += '"'; i++; break;
      case "'": out += "'"; i++; break;
      case "x": {
        const hex = s.slice(i + 2, i + 4);
        out += String.fromCharCode(parseInt(hex, 16) || 0);
        i += 3;
        break;
      }
      case "u": {
        const m = /^u\{([0-9a-fA-F]+)\}/.exec(s.slice(i + 1));
        if (m) {
          out += String.fromCodePoint(parseInt(m[1], 16));
          i += 1 + m[0].length;
        } else {
          out += n;
          i++;
        }
        break;
      }
      default:
        out += n ?? "";
        i++;
    }
  }
  return out;
}

const found = new Map(); // 文案 -> 出现次数
for (const f of walk(ROOT)) {
  if (path.basename(f) === "i18n.rs") continue;
  let src = stripComments(fs.readFileSync(f, "utf8"));
  src = stripTestModules(src);
  for (const m of src.matchAll(/"((?:[^"\\]|\\.)*)"/g)) {
    const t = unescapeRust(m[1]);
    if (!CJK.test(t)) continue;
    // 跳过含真实换行的字面量：那是 Rust 的多行串（内嵌 SQL、PAC 脚本模板等），
    // 属于内部实现，不可能作为诊断文案回到界面。
    if (t.includes("\n")) continue;
    found.set(t, (found.get(t) ?? 0) + 1);
  }
}

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

const stub = [
  "/**",
  " * 后端文案词典（中文原文 -> 英文）。",
  " *",
  " * 键由 `scripts/i18n_rs_extract.mjs` 从 src-tauri/src 抽取，**必须与后端产出的中文逐字一致**。",
  " * 覆盖范围：会随 `Err(String)` 回到界面的诊断文案。",
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
