/**
 * 多语言词典自检。
 *
 * 为什么需要它：词典以「中文原文」为键，键一旦与调用点差一个空格或标点，
 * 运行时就静默回退中文——不会报错、不会编译失败，只会在英文界面上露出中文。
 * 这个脚本把两侧对齐关系显式检查出来：
 *
 *   1. 前端（App.tsx / api.ts）里所有 t("...") 的实参  ⊆  UI_DICT 的键；
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
import { createRequire } from "node:module";
import { scanRustStrings, RUST_ROOTS } from "./rust_scan.mjs";

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
// 手工维护的运行期词典（系统错误原文等）。它的键本来就没有调用点，
// 所以只查「有没有漏翻译」，不参与孤儿键检查。
const runtimeDict = readDict("src/i18n-dict-runtime.ts");

// ─────────── 1. 前端调用点 ───────────
//
// 必须扫**所有**含 t() 调用的前端文件，不能只看 App.tsx：
// `src/api.ts` 的 pickPath 要把标题/过滤器名交给系统原生文件对话框
// （不经过 React 渲染），那几处 t() 是唯一的翻译点。
// 漏扫会让这些键被误判成「没有调用点的孤儿键」。

const FRONTEND_FILES = ["src/App.tsx", "src/api.ts"];
const used = new Set();

for (const file of FRONTEND_FILES) {
  const src = fs.readFileSync(file, "utf8");
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
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
  })(sf);
}

// ─────────── 1a. api.ts 的 MOCK 数据（只用于「孤儿键」判断）───────────
//
// api.ts 里的 MOCK 数据是在**模拟后端产出**：它们以裸中文字面量存在（如
// `"（浏览器预览：模拟切换成功）"`、`"内部项目代号"`、`"仅当前用户 / SYSTEM / 管理员"`），
// 运行时由 `tb()` 翻译，而不是 `t()`。所以这些键没有 t() 调用点是正常的。
//
// ⚠ 它们**只参与「孤儿键」判断，不参与「缺失」判断**：
// tb() 除了精确查表，还有「带 {} 的规则」与「长片段替换」两条路径，
// 大多数 MOCK 串是靠后两条覆盖的，按「必须精确命中词典」要求会误报一大片。
// 判据：api.ts 中**未被 t() 包住**的含中文字面量。

const tbInputs = new Set();

{
  const file = "src/api.ts";
  const src = fs.readFileSync(file, "utf8");
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);

  const wrapped = [];
  (function walk(n) {
    if (
      ts.isCallExpression(n) &&
      ts.isIdentifier(n.expression) &&
      (n.expression.text === "t" || n.expression.text === "tf")
    ) {
      for (const a of n.arguments) wrapped.push([a.getStart(sf), a.getEnd()]);
    }
    ts.forEachChild(n, walk);
  })(sf);

  (function walk(n) {
    if (ts.isStringLiteral(n) && /[\u4e00-\u9fff]/.test(n.text)) {
      const s = n.getStart(sf);
      const e = n.getEnd();
      if (!wrapped.some(([a, b]) => s >= a && e <= b)) tbInputs.add(n.text);
    }
    ts.forEachChild(n, walk);
  })(sf);
}

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

for (const file of FRONTEND_FILES) {
  const src = fs.readFileSync(file, "utf8");
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
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
      let i = n.getStart(sf) - 1;
      while (i >= 0 && /\s/.test(src[i])) i--;
      if (src[i] === "{") {
        // 再看 '{' 之前：是不是「另一个表达式容器 + 跨行空白」这种会被丢弃的情况
        let j = i - 1;
        let crossedNL = false;
        let hadSpace = false;
        while (j >= 0 && /\s/.test(src[j])) {
          if (src[j] === "\n") crossedNL = true;
          else hadSpace = true;
          j--;
        }
        const prevIsExpr = src[j] === "}";
        // 同一行的 {n} {t(...)} 空格会被保留；跨行则必须显式 {" "}。
        // 而 {" "} 本身也是一个表达式容器，所以「前一个是空白字符串容器」要放行。
        const prevIsSpaceLiteral = prevIsExpr && isWhitespaceLiteralContainer(src, j);
        if (prevIsExpr && !prevIsSpaceLiteral && (crossedNL || !hadSpace)) {
          const line = sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
          fragSpaceIssues.push({ file, line, key: n.arguments[0].text });
        }
      }
    }
    ts.forEachChild(n, walk);
  })(sf);
}

// ─────────── 2. Rust 侧文案 ───────────
//
// 扫描口径（注释 / #[cfg(test)] / 字符字面量 / 多行串）与抽取器共用
// `scripts/rust_scan.mjs`。此前两个脚本各写一份，口径不一致导致自检报的
// 覆盖率缺口里混着大量注释里的中文，那条警告因此失去意义。
// 两个 crate 都要扫：core/src/audit.rs 里定义着 7 个信号的展示名与描述。

const rustStrings = new Set(scanRustStrings(RUST_ROOTS).keys());

// ─────────── 2b. 信号英文名的跨进程一致性 ───────────
//
// 7 个防护信号的英文名存在于**两个互不可见的地方**：
//   - `src-tauri/src/i18n.rs` 的 SIGNAL_EN —— 服务「窗口外」（托盘菜单 / 系统通知）
//   - 前端词典里那 7 条中文展示名对应的译文 —— 服务「窗口内」（信号卡片）
// 两边一旦漂移，同一个信号会在托盘和主窗口显示不同的英文名。
// 中文展示名的唯一真相是 core 的 SIGNAL_CATALOG，所以这里拿它当锚点对账。

const signalMismatch = [];
{
  const coreSrc = fs.readFileSync("core/src/audit.rs", "utf8");
  const i18nSrc = fs.readFileSync("src-tauri/src/i18n.rs", "utf8");

  // SIG_XXX 常量 → 语义名
  const constMap = new Map();
  for (const m of coreSrc.matchAll(/pub const (SIG_\w+)\s*:\s*&str\s*=\s*"([^"]+)"\s*;/g)) {
    constMap.set(m[1], m[2]);
  }
  // SIGNAL_CATALOG：语义名 → 中文展示名
  const zhName = new Map();
  const cat = /SIGNAL_CATALOG[^=]*=\s*\[([\s\S]*?)\n\];/.exec(coreSrc);
  if (cat) {
    for (const m of cat[1].matchAll(/\(\s*(SIG_\w+)\s*,\s*"((?:[^"\\]|\\.)*)"\s*,/g)) {
      const key = constMap.get(m[1]);
      if (key) zhName.set(key, JSON.parse('"' + m[2] + '"'));
    }
  }
  // SIGNAL_EN：语义名 → 英文展示名
  const enName = new Map();
  const en = /const SIGNAL_EN[^=]*=\s*&\[([\s\S]*?)\n\];/.exec(i18nSrc);
  if (en) {
    for (const m of en[1].matchAll(/\(\s*"([^"]+)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)/g)) {
      enName.set(m[1], JSON.parse('"' + m[2] + '"'));
    }
  }

  if (!zhName.size || !enName.size) {
    warnings.push("信号名对账跳过：没能从 audit.rs / i18n.rs 解析出 SIGNAL_CATALOG 或 SIGNAL_EN");
  } else {
    const dict = new Map([...backendDict, ...runtimeDict, ...uiDict]);
    for (const [key, en] of enName) {
      const zh = zhName.get(key);
      if (!zh) {
        signalMismatch.push(`${key}: SIGNAL_CATALOG 里没有这个信号`);
        continue;
      }
      const frontend = dict.get(zh);
      if (frontend === undefined) {
        signalMismatch.push(`${key}（${zh}）: 前端词典里没有这条中文展示名`);
      } else if (frontend !== en) {
        signalMismatch.push(`${key}（${zh}）: i18n.rs 是 ${JSON.stringify(en)}，前端词典是 ${JSON.stringify(frontend)}`);
      }
    }
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

// 孤儿键 = 既不是 t() 调用点，也不是 api.ts 里会被 tb() 翻译的 MOCK 串，
// 也不是运行期词典里手工维护的条目。
const orphanKeys = [...uiDict.keys()].filter(
  (k) => !used.has(k) && !tbInputs.has(k) && !runtimeDict.has(k)
);
if (orphanKeys.length) {
  problems.push(`UI_DICT 里没有调用点的键（${orphanKeys.length} 条）——多半是键写错或调用点已删：`);
  for (const k of orphanKeys) problems.push(`    + ${JSON.stringify(k)}`);
}

if (fragSpaceIssues.length) {
  problems.push(
    `「数字后碎片」缺空格（${fragSpaceIssues.length} 处）——JSX 会丢弃跨行的表达式间空白，需要显式写 {" "}：`
  );
  for (const f of fragSpaceIssues) {
    problems.push(`    ~ ${f.file}:${f.line}  ${JSON.stringify(f.key)}`);
  }
}

if (signalMismatch.length) {
  problems.push(`信号英文名跨进程不一致（${signalMismatch.length} 处）——托盘/通知与主窗口会显示不同名字：`);
  for (const s of signalMismatch) problems.push(`    ~ ${s}`);
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
const untranslatedRuntime = [...runtimeDict].filter(([, v]) => v === "").map(([k]) => k);
if (untranslatedUi.length) warnings.push(`UI_DICT 未翻译 ${untranslatedUi.length} 条：${untranslatedUi.slice(0, 10).map((k) => JSON.stringify(k)).join(", ")}`);
if (untranslatedBackend.length) warnings.push(`BACKEND_DICT 未翻译 ${untranslatedBackend.length} 条`);
if (untranslatedRuntime.length) warnings.push(`RUNTIME_DICT 未翻译 ${untranslatedRuntime.length} 条`);

// ─────────── 报告 ───────────

console.log(`UI_DICT: ${uiDict.size} 条（调用点 ${used.size} 个）`);
console.log(`BACKEND_DICT: ${backendDict.size} 条（Rust 侧中文 ${rustStrings.size} 条）`);
console.log(`RUNTIME_DICT: ${runtimeDict.size} 条（手工维护，运行期系统文案）`);
console.log(`「数字后碎片」需带空格: ${spacedFrags.size} 条（有问题的 ${fragSpaceIssues.length} 处）`);
for (const w of warnings) console.log(`\n[警告] ${w}`);
for (const p of problems) console.log(`\n[错误] ${p}`);

if (problems.length) {
  console.log(`\n失败：${problems.length} 项错误。`);
  process.exit(1);
}
console.log("\n通过。");
