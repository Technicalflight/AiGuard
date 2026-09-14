/**
 * 多语言词典自检。
 *
 * 为什么需要它：词典以「中文原文」为键，键一旦与调用点差一个空格或标点，
 * 运行时就静默回退中文——不会报错、不会编译失败，只会在英文界面上露出中文。
 * 这个脚本把两侧对齐关系显式检查出来：
 *
 *   1. App.tsx 里所有 t("...") 的实参  ⊆  UI_DICT 的键；
 *   2. UI_DICT 里没有对应调用点的键（拼错 / 已删除的调用点留下的残骸）；
 *   3. src-tauri/src 的中文文案 ⊆ BACKEND_DICT 的键（后端文案的覆盖率，允许有缺口，
 *      只报告不报错——日志类文案本来就不上界面）；
 *   4. 值为空的条目（尚未翻译）；
 *   5. 「数字后碎片」的 JSX 空格（见下方 1b 节说明）。
 *
 * 用法：node scripts/i18n_check.mjs [--strict]
 *   默认：第 3 项只警告，其余视为错误；
 *   --strict：把后端覆盖率缺口也当成错误（发版前跑一次用）。
 */
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ts = require("typescript");

const STRICT = process.argv.includes("--strict");

// ─────────── 读取词典 ───────────

/** 从词典源码里取键值对。词典是纯字面量，用正则足够，不必真的求值。 */
function readDict(file) {
  const src = fs.readFileSync(file, "utf8");
  const map = new Map();
  const re = /^\s*("(?:[^"\\]|\\.)*"):\s*("(?:[^"\\]|\\.)*"),\s*$/gm;
  for (const m of src.matchAll(re)) map.set(JSON.parse(m[1]), JSON.parse(m[2]));
  return map;
}

const uiDict = readDict("src/i18n-dict-ui.ts");
const backendDict = readDict("src/i18n-dict-backend.ts");

// ─────────── 1. App.tsx 的调用点 ───────────

const appSrc = fs.readFileSync("src/App.tsx", "utf8");
const appSf = ts.createSourceFile("App.tsx", appSrc, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
const used = new Set();

(function walk(n) {
  if (
    ts.isCallExpression(n) &&
    ts.isIdentifier(n.expression) &&
    (n.expression.text === "t" || n.expression.text === "tf")
  ) {
    const a0 = n.arguments[0];
    if (a0 && (ts.isStringLiteral(a0) || ts.isNoSubstitutionTemplateLiteral(a0))) used.add(a0.text);
  }
  ts.forEachChild(n, walk);
})(appSf);

// ─────────── 1b. 「数字后碎片」的空格 ───────────
//
// 中文写「5 条」，英文写「5 rules」——两边都需要数字与量词之间有空格。
// 约定是：中文键不带前导空格，英文译文带前导空格，而空格由 JSX 侧提供。
// 但 JSX 有个反直觉的规则：两个表达式容器之间的纯空白，只要含换行就会被**整个丢弃**。
// 于是
//     {n}
//     {t(" 条")}      ← 渲染成 "5records"，且中文变成「5条」
// 这种写法不会报错、不会编译失败，只在界面上少一个空格。这里把它揪出来。
//
// 只检查「译文以空格开头」的键：这类键的定义就是「跟在数字后面」。
// 模板串里的 ${t(...)} 不受 JSX 空白规则影响，跳过。

const spacedFrags = new Set([...uiDict].filter(([, v]) => /^ /.test(v)).map(([k]) => k));
const fragSpaceIssues = [];

/**
 * 判断 `}` 所在的那个 JSX 表达式容器，内容是否是一个「只含空白的字符串字面量」，即 {" "}。
 * 从 `}` 往前配平花括号找到对应的 `{`，再整体比对——比正则扫前文可靠。
 */
function isWhitespaceLiteralContainer(src, closeBraceAt) {
  let depth = 0;
  for (let k = closeBraceAt; k >= 0; k--) {
    const c = src[k];
    if (c === "}") depth++;
    else if (c === "{") {
      depth--;
      if (depth === 0) {
        return /^\{\s*"\s+"\s*\}$/.test(src.slice(k, closeBraceAt + 1));
      }
    }
  }
  return false;
}

(function walk(n) {
  if (
    ts.isCallExpression(n) &&
    ts.isIdentifier(n.expression) &&
    (n.expression.text === "t" || n.expression.text === "tf") &&
    n.arguments.length >= 1 &&
    ts.isStringLiteral(n.arguments[0]) &&
    spacedFrags.has(n.arguments[0].text)
  ) {
    // 往前跳过空白，应停在包裹它的 JSX 表达式容器的 '{' 上
    let i = n.getStart(appSf) - 1;
    while (i >= 0 && /\s/.test(appSrc[i])) i--;
    if (appSrc[i] === "{") {
      // 再看 '{' 之前：是不是「另一个表达式容器 + 跨行空白」这种会被丢弃的情况
      let j = i - 1;
      let crossedNL = false;
      let hadSpace = false;
      while (j >= 0 && /\s/.test(appSrc[j])) {
        if (appSrc[j] === "\n") crossedNL = true;
        else hadSpace = true;
        j--;
      }
      const prevIsExpr = appSrc[j] === "}";
      // 同一行的 {n} {t(...)} 空格会被保留；跨行则必须显式 {" "}。
      // 而 {" "} 本身也是一个表达式容器，所以「前一个是空白字符串容器」要放行。
      const prevIsSpaceLiteral = prevIsExpr && isWhitespaceLiteralContainer(appSrc, j);
      if (prevIsExpr && !prevIsSpaceLiteral && (crossedNL || !hadSpace)) {
        const line = appSf.getLineAndCharacterOfPosition(n.getStart(appSf)).line + 1;
        fragSpaceIssues.push({ line, key: n.arguments[0].text });
      }
    }
  }
  ts.forEachChild(n, walk);
})(appSf);

// ─────────── 2. Rust 侧文案 ───────────

function walkDir(dir, acc = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walkDir(p, acc);
    else if (e.name.endsWith(".rs")) acc.push(p);
  }
  return acc;
}

const rustStrings = new Set();
for (const f of walkDir("src-tauri/src")) {
  if (path.basename(f) === "i18n.rs") continue;
  const src = fs.readFileSync(f, "utf8");
  for (const m of src.matchAll(/"((?:[^"\\]|\\.)*)"/g)) {
    if (/[\u4e00-\u9fff]/.test(m[1])) rustStrings.add(m[1]);
  }
}

// ─────────── 汇总 ───────────

const problems = [];
const warnings = [];

const missingInDict = [...used].filter((k) => !uiDict.has(k));
if (missingInDict.length) {
  problems.push(`App.tsx 用到但 UI_DICT 里没有的键（${missingInDict.length} 条）——英文模式下会露出中文：`);
  for (const k of missingInDict) problems.push(`    - ${JSON.stringify(k)}`);
}

const orphanKeys = [...uiDict.keys()].filter((k) => !used.has(k));
if (orphanKeys.length) {
  problems.push(`UI_DICT 里没有调用点的键（${orphanKeys.length} 条）——多半是键写错或调用点已删：`);
  for (const k of orphanKeys) problems.push(`    + ${JSON.stringify(k)}`);
}

if (fragSpaceIssues.length) {
  problems.push(
    `「数字后碎片」缺空格（${fragSpaceIssues.length} 处）——JSX 会丢弃跨行的表达式间空白，需要显式写 {" "}：`
  );
  for (const f of fragSpaceIssues) {
    problems.push(`    ~ App.tsx:${f.line}  ${JSON.stringify(f.key)}`);
  }
}

const rustMissing = [...rustStrings].filter((k) => !backendDict.has(k));
if (rustMissing.length) {
  const msg = `Rust 侧文案未进 BACKEND_DICT（${rustMissing.length}/${rustStrings.size} 条，日志类属正常）`;
  if (STRICT) {
    problems.push(msg + "：");
    for (const k of rustMissing) problems.push(`    ~ ${JSON.stringify(k)}`);
  } else {
    warnings.push(msg);
  }
}

/**
 * 有意留空的条目。
 *
 * 空值一般表示「还没翻译」，但有一类条目本来就该是空串：
 * 中文靠量词收尾（「当前活动会话 5 个」），英文不需要量词（"active sessions: 5"）。
 * 把它们显式列在这里，避免「未翻译」警告里混进永远消不掉的噪音——
 * 噪音一多，真正的漏译就没人看了。
 */
const INTENTIONALLY_EMPTY = new Set([" 个"]);

const untranslatedUi = [...uiDict]
  .filter(([k, v]) => v === "" && !INTENTIONALLY_EMPTY.has(k))
  .map(([k]) => k);
const untranslatedBackend = [...backendDict].filter(([, v]) => v === "").map(([k]) => k);
if (untranslatedUi.length) warnings.push(`UI_DICT 未翻译 ${untranslatedUi.length} 条：${untranslatedUi.slice(0, 10).map((k) => JSON.stringify(k)).join(", ")}`);
if (untranslatedBackend.length) warnings.push(`BACKEND_DICT 未翻译 ${untranslatedBackend.length} 条`);

// ─────────── 报告 ───────────

console.log(`UI_DICT: ${uiDict.size} 条（调用点 ${used.size} 个）`);
console.log(`BACKEND_DICT: ${backendDict.size} 条（Rust 侧中文 ${rustStrings.size} 条）`);
console.log(`「数字后碎片」需带空格: ${spacedFrags.size} 条（有问题的 ${fragSpaceIssues.length} 处）`);
for (const w of warnings) console.log(`\n[警告] ${w}`);
for (const p of problems) console.log(`\n[错误] ${p}`);

if (problems.length) {
  console.log(`\n失败：${problems.length} 项错误。`);
  process.exit(1);
}
console.log("\n通过。");
