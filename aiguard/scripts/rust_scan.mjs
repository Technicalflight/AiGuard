/**
 * Rust 源码中文文案扫描（抽取器与自检脚本共用，保证两边口径一致）。
 *
 * 之前两个脚本各写了一份，口径不同 → 自检报「348 条未覆盖」而抽取器只抽出 274 条，
 * 差值全是注释里的中文，让那条警告彻底失去意义。现在统一到这里。
 *
 * 排除规则（三处，缺一不可）：
 *  1. **注释**：注释里的中文永远不会出现在界面上；
 *  2. **#[cfg(test)] 模块**：测试断言里的中文同理；
 *  3. **含真实换行的字面量**：Rust 多行串（内嵌 SQL / PAC 脚本 / 正则原文），属内部实现。
 *
 * ⚠ 必须同时扫 `src-tauri/src` 与 `core/src` 两个 crate：7 个防护信号的展示名与描述
 * 定义在 `core/src/audit.rs`，它们会经 get_signals 回到界面（曾经漏过整批）。
 */
import fs from "node:fs";
import path from "node:path";

const CJK = /[\u4e00-\u9fff]/;

/** 默认扫描的 crate 根目录（相对于 aiguard/）。 */
export const RUST_ROOTS = ["src-tauri/src", "core/src"];

/** 这些文件的后端文案由后端自己按语言取词，前端不参与翻译。 */
const SKIP_FILES = new Set(["i18n.rs"]);

function walk(dir, acc = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name.endsWith(".rs")) acc.push(p);
  }
  return acc;
}

/**
 * 列出待扫描的 Rust 源文件（含 i18n.rs 本身）。
 *
 * `scanRustStrings` 会跳过 i18n.rs（它的文案由后端自己按语言取词，前端不参与翻译），
 * 但**检查 `tr()` 键名是否拼对**时必须反过来——i18n.rs 正是 TABLE 所在，
 * 而调用点散布在各文件里。所以单独导出这个列表。
 */
export function rustFiles(roots = RUST_ROOTS) {
  return roots.flatMap((r) => (fs.existsSync(r) ? walk(r) : []));
}

/**
 * 去掉行注释与块注释（保留字符串字面量里的 // 与 /*）。
 *
 * ⚠ 必须同时识别 **Rust 字符字面量**，否则 `'"'` 里的双引号会被当成字符串起点，
 * 把后面所有引号配对整体带偏——audit.rs 里就有
 * `matches!(c, ' ' | '\t' | '"' | '\'' | ...)`，实测导致 506 处「字符串跨行」假象，
 * 注释被当成代码、注释里的中文被抽进词典。
 *
 * 同时要区分字符字面量与**生命周期**（`&'a str` / `'static`）：后者只有前引号。
 * 判据是「`'` 之后 1 个字符就是收尾的 `'`」（`'x'`），或 `'\\` 开头（`'\n'` / `'\''`）。
 */
export function stripComments(src) {
  let out = "";
  let i = 0;
  let inStr = false;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (!inStr && c === "/" && n === "/") {
      while (i < src.length && src[i] !== "\n") i++;
      continue;
    }
    if (!inStr && c === "/" && n === "*") {
      i += 2;
      let depth = 1;
      while (i < src.length && depth > 0) {
        if (src[i] === "/" && src[i + 1] === "*") { depth++; i += 2; continue; }
        if (src[i] === "*" && src[i + 1] === "/") { depth--; i += 2; continue; }
        i++;
      }
      continue;
    }
    // 字符字面量：'x' / '\n' / '\'' / '\u{1F600}'
    if (!inStr && c === "'") {
      if (n === "\\") {
        let j = i + 2; // 反斜杠之后
        if (src[j] === "u") {
          const close = src.indexOf("}", j);
          j = close >= 0 ? close + 1 : j + 1;
        } else {
          j++; // 跳过被转义的字符
        }
        if (src[j] === "'") { out += src.slice(i, j + 1); i = j + 1; continue; }
      } else if (src[i + 2] === "'") {
        out += src.slice(i, i + 3);
        i += 3;
        continue;
      }
      // 其余是生命周期（&'a str / 'static），按普通代码继续
    }
    // Rust 原始字符串 r"..." / r#"..."#
    if (!inStr && c === "r" && (n === '"' || n === "#")) {
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
 * 做法是括号配平：从 `mod` 之后的第一个 `{` 开始数到与之配对的 `}`。
 * 字符串与注释已在 stripComments 里处理过，所以这里可以安全地只数括号。
 */
export function stripTestModules(src) {
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
export function unescapeRust(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "\\") { out += s[i]; continue; }
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

/**
 * 扫描所有 Rust crate，返回 文案 -> 出现次数。
 * @param {string[]} roots 相对 aiguard/ 的目录列表
 */
export function scanRustStrings(roots = RUST_ROOTS) {
  const found = new Map();
  for (const root of roots) {
    if (!fs.existsSync(root)) continue;
    for (const f of walk(root)) {
      if (SKIP_FILES.has(path.basename(f))) continue;
      let src = stripComments(fs.readFileSync(f, "utf8"));
      src = stripTestModules(src);
      for (const m of src.matchAll(/"((?:[^"\\]|\\.)*)"/g)) {
        const t = unescapeRust(m[1]);
        if (!CJK.test(t)) continue;
        if (t.includes("\n")) continue;
        found.set(t, (found.get(t) ?? 0) + 1);
      }
    }
  }
  return found;
}
