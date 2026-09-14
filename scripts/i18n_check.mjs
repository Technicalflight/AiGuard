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
import {
  scanRustStrings,
  RUST_ROOTS,
  rustFiles,
  stripComments,
  stripTestModules,
} from "./rust_scan.mjs";

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
//  - `src/api.ts` 的 pickPath 要把标题/过滤器名交给系统原生文件对话框
//    （不经过 React 渲染），那几处 t() 是唯一的翻译点。
//  - `src/i18n.ts` 的 syncDocumentLocale 要设置 `document.title`，
//    这也是一个不经过 React 渲染的翻译点（浏览器标签页标题）。
// 漏扫会让这些键被误判成「没有调用点的孤儿键」。

const FRONTEND_FILES = ["src/App.tsx", "src/api.ts", "src/i18n.ts"];
const used = new Set();

/**
 * `t()` / `tf()` 的实参必须是**字面量**。
 *
 * 为什么单独查这个：`t(key)` 是精确查表，查不到就回退中文。若实参是个变量
 * （比如把后端的 `"mask"` 当 key 传进去），查表必然落空 —— 而回退结果是
 * **中文原文**，也就是说界面上会原样显示 `mask` / `partial` 这种代号。
 *
 * ⚠ 这类缺陷 **e2e 扫描抓不到**：那个扫描找的是「残留中文」，而漏查表渲染出来的是
 * 英文/代号文本，跟正常的英文界面长得一模一样。所以只能在这里静态拦。
 * 后端刚发生过同类的真 bug（`tr(lang, cert_state)`，代号被当 key，中英双语都错），
 * 见 `i18n.rs` 的 `cert_state_key`。
 */
const tNonLiteral = [];

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
      else {
        const { line } = sf.getLineAndCharacterOfPosition(n.getStart(sf));
        tNonLiteral.push({
          file,
          line: line + 1,
          text: `${n.expression.text}(${a0 ? a0.getText(sf).slice(0, 50) : "<无实参>"})`,
        });
      }
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

// ─────────── 1c. 未包 t() 的中文（含中文标点）───────────
//
// 抽取器会把中文字面量机械包成 t()，但它**包不了**两类东西：
//   - JSX 表达式容器里渲染的**变量**（`{e.evidence}` / `{trust?.detail}`）；
//   - 拼接模板串里的**变量**部分。
// 这两类只能在调用点手写 tb()。漏了不会有任何报错、不会编译失败，
// 只在英文界面上露出中文——所以必须由自检兜住。
//
// ⚠ 正则必须包含**中文标点**，不能只查 [\u4e00-\u9fff]。真实踩过：
//     `}。${hardening.data_dir_detail}`
// 英文界面渲染成 `...administrators。Current user ...`——中文句号卡在英文句子中间。
// 纯标点片段在所有「只查汉字」的地方（抽取器 / 自检 / Rust 扫描）都是隐形的。
//
// 只查 App.tsx / i18n.ts：api.ts 的 MOCK 串是「模拟后端产出」，本来就该是裸中文，
// 运行时由 tb() 翻译（见 1a 节），在这里查会误报一大片。

const HAS_CJK =
  /[\u4e00-\u9fff\u3000-\u303f\ufe30-\ufe4f\uff01-\uff0f\uff1a-\uff20\uff3b-\uff40\uff5b-\uff65]/;

/**
 * 有意保持中文的裸串，不参与本项检查：
 *  - `简体中文`：语言自称，中文永远写作「简体中文」，不该翻；
 *  - `未找到`：**与后端中文做比较的判断值**（`report.cert_note.includes("未找到")`）。
 *    包成 `t("未找到")` 后，英文模式下 t() 返回 "Not found"，而 cert_note 仍是中文，
 *    includes 恒为 false → 证书状态被误判。这类值必须保持中文字面量。
 */
const UNWRAPPED_ALLOW = new Set(["简体中文", "未找到"]);

const unwrappedCjk = [];

for (const file of ["src/App.tsx", "src/i18n.ts"]) {
  const src = fs.readFileSync(file, "utf8");
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);

  const wrapped = [];
  (function walk(n) {
    if (
      ts.isCallExpression(n) &&
      ts.isIdentifier(n.expression) &&
      (n.expression.text === "t" || n.expression.text === "tf" || n.expression.text === "tb")
    ) {
      for (const a of n.arguments) wrapped.push([a.getStart(sf), a.getEnd()]);
    }
    ts.forEachChild(n, walk);
  })(sf);

  const inWrapped = (n) => {
    const s = n.getStart(sf);
    const e = n.getEnd();
    return wrapped.some(([a, b]) => s >= a && e <= b);
  };

  (function walk(n) {
    let text = null;
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) text = n.text;
    else if (ts.isTemplateHead(n) || ts.isTemplateMiddle(n) || ts.isTemplateTail(n))
      text = n.text;
    else if (ts.isJsxText(n)) text = n.text.trim();
    if (text && HAS_CJK.test(text) && !UNWRAPPED_ALLOW.has(text) && !inWrapped(n)) {
      const { line } = sf.getLineAndCharacterOfPosition(n.getStart(sf));
      unwrappedCjk.push({ file, line: line + 1, text });
    }
    ts.forEachChild(n, walk);
  })(sf);
}

// ─────────── 1d. 后端中文字段被裸渲染 ───────────
//
// 1c 只能查「字面量」。「后端流进来的字符串在渲染处忘了 tb()」是**另一类**漏译，
// 而且更难发现：词典里 100% 有译文、t() 调用点全绿、构建全绿，
// 只有把界面切到英文肉眼才看得见。实测这一类出现过 7 次
// （信号名 / 证据串 / CA 详情 / 端口状态 / 命中规则名 / 规则编辑标题）。
//
// 判据是**数据驱动**的：`api.ts` 的 MOCK 就是「后端产出的样本」，所以
//     「MOCK 里值含中文的字段名」 == 「运行时可能带中文的字段名」
// 把这些字段在 App.tsx 的 JSX 表达式里的渲染点找出来，排除已包 t()/tf()/tb() 的。
//
// ⚠ 已知的精度边界：字段名会与前端自造的数据撞名（如下拉选项的 `label`、
// 富文本的 `text`）。这类**确实不需要翻译**的渲染点走 RAW_FIELD_ALLOW 白名单，
// 每条都要写清为什么可以不翻——否则白名单会变成噪音垃圾桶。

const cjkFields = new Set();
{
  const src = fs.readFileSync("src/api.ts", "utf8");
  const sf = ts.createSourceFile("src/api.ts", src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const isCjkStr = (n) =>
    (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) && HAS_CJK.test(n.text);
  (function walk(n) {
    if (ts.isPropertyAssignment(n) && n.initializer) {
      const name =
        ts.isIdentifier(n.name) || ts.isStringLiteral(n.name) ? n.name.text : null;
      if (!name) {
        ts.forEachChild(n, walk);
        return;
      }
      // 字符串字段，或「字符串数组」字段（如 locations: ["当前用户信任库"]）
      if (isCjkStr(n.initializer)) cjkFields.add(name);
      else if (
        ts.isArrayLiteralExpression(n.initializer) &&
        n.initializer.elements.some(isCjkStr)
      )
        cjkFields.add(name);
    }
    ts.forEachChild(n, walk);
  })(sf);
}

/**
 * 明确不需要翻译的字段，整体豁免。
 * 只放行**语义上确定与语言无关**的字段，别把它当噪音垃圾桶。
 */
const RAW_FIELD_ALLOW = new Set([
  // 用户自己写的正则**原文**——翻译它等于改掉用户配置的语义
  "regex",
]);

const rawFieldRenders = [];
{
  const file = "src/App.tsx";
  const src = fs.readFileSync(file, "utf8");
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);

  const wrapped = [];
  (function walk(n) {
    if (
      ts.isCallExpression(n) &&
      ts.isIdentifier(n.expression) &&
      (n.expression.text === "t" || n.expression.text === "tf" || n.expression.text === "tb")
    ) {
      for (const a of n.arguments) wrapped.push([a.getStart(sf), a.getEnd()]);
    }
    ts.forEachChild(n, walk);
  })(sf);

  const inWrapped = (n) => {
    const s = n.getStart(sf);
    const e = n.getEnd();
    return wrapped.some(([a, b]) => s >= a && e <= b);
  };

  // 下面三类虽然出现了字段名，但**并不是在展示它的内容**，必须排除，
  // 否则规则会被误报淹没（实测这 3 条把 10 处命中压到 1 处真问题）。
  const isFormBinding = (n) => {
    const p = n.parent;
    return (
      !!p &&
      ts.isJsxExpression(p) &&
      !!p.parent &&
      ts.isJsxAttribute(p.parent) &&
      ["value", "defaultValue"].includes(p.parent.name.getText(sf))
    );
  };
  const isCondition = (n) => {
    const p = n.parent;
    if (!p) return false;
    if (ts.isConditionalExpression(p) && p.condition === n) return true;
    if (
      ts.isBinaryExpression(p) &&
      p.left === n &&
      (p.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
        p.operatorToken.kind === ts.SyntaxKind.BarBarToken)
    )
      return true;
    return ts.isPrefixUnaryExpression(p) && p.operator === ts.SyntaxKind.ExclamationToken;
  };
  /** 方法调用的接收者：`note.includes("未找到")` 是拿去做比较，不是展示。 */
  const isMethodReceiver = (n) => {
    const p = n.parent;
    return !!p && ts.isPropertyAccessExpression(p) && p.expression === n;
  };

  (function walk(n, inJsx) {
    const nowJsx = inJsx || ts.isJsxExpression(n);
    if (ts.isPropertyAccessExpression(n) && nowJsx) {
      const field = n.name.text;
      if (
        cjkFields.has(field) &&
        !RAW_FIELD_ALLOW.has(field) &&
        !inWrapped(n) &&
        !isFormBinding(n) &&
        !isCondition(n) &&
        !isMethodReceiver(n)
      ) {
        const { line } = sf.getLineAndCharacterOfPosition(n.getStart(sf));
        rawFieldRenders.push({ line: line + 1, text: n.getText(sf) });
      }
    }
    ts.forEachChild(n, (c) => walk(c, nowJsx));
  })(sf, false);
}

// ─────────── 2c. tr() 的字面量键必须在 TABLE 里 ───────────
//
// `i18n::tr(lang, key)` 查不到 key 时**原样返回 key 本身**（设计如此：宁可界面上
// 露出一个可疑标识符，也不要静默变成空串）。代价是**键名拼错不会有任何报错**——
// 托盘菜单里会直接显示 `tray.shwo`，而托盘不经过 React、e2e 扫描也扫不到它，
// 只有真去右键点托盘才看得见。
//
// 所以把每个 `tr(...)` 调用**实参里的字面量**全抓出来，逐个对 TABLE 点名。
// 用括号配平取整段实参，而不是正则 `tr("..."）`——因为代码里有
// `tr(if enabled { "tray.status.on" } else { "tray.status.off" })` 这种三元形式。
//
// ⚠ 精度边界：动态拼出来的键（如 `tr(&format!("cert.{}", code))`）抓不到。
// 那类要靠 Rust 侧的单测兜（见 `i18n.rs` 的
// `test_every_produced_cert_state_has_a_label`——真实漏过一次）。
const tableKeys = (() => {
  const src = fs.readFileSync("src-tauri/src/i18n.rs", "utf8");
  const m = src.match(/const TABLE[^=]*=\s*&\[([\s\S]*?)\n\];/);
  // ⚠ `\(\s*"` 而不是 `\("`：TABLE 里较长的条目被格式化成多行，
  // 键名单独占一行（如 notify.panic.body），紧跟 `(` 的写法抓不到它们。
  return m ? new Set([...m[1].matchAll(/\(\s*"([^"]+)"/g)].map((x) => x[1])) : new Set();
})();

/** 取 `src[i]` 处 `(` 匹配到的 `)` 的下标；不匹配返回 -1。 */
function matchParen(src, i) {
  let depth = 0;
  for (let j = i; j < src.length; j++) {
    const c = src[j];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return j;
    } else if (c === '"') {
      // 跳过字符串，避免键里出现括号时配平错位
      for (j++; j < src.length && src[j] !== '"'; j++) if (src[j] === "\\") j++;
    }
  }
  return -1;
}

const trKeyIssues = [];
let trLiteralCount = 0;
for (const file of rustFiles()) {
  const src = stripTestModules(stripComments(fs.readFileSync(file, "utf8")));
  // 匹配 `tr(`，排除 `as_str(` / `from_str(` 之类的后缀命中（要求前面不是标识符字符）
  for (const m of src.matchAll(/(?<![\w.])tr\(/g)) {
    const open = m.index + m[0].length - 1;
    const close = matchParen(src, open);
    if (close < 0) continue;
    const args = src.slice(open + 1, close);
    for (const lit of args.matchAll(/"([^"]*)"/g)) {
      const key = lit[1];
      // 只认「像 i18n 键」的实参（含点号、全小写），避免把别的字符串参数误判
      if (!/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/.test(key)) continue;
      trLiteralCount++;
      if (tableKeys.size && !tableKeys.has(key)) {
        const line = src.slice(0, m.index).split("\n").length;
        trKeyIssues.push({ file, line, key });
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

if (unwrappedCjk.length) {
  problems.push(
    `未包 t()/tb() 的中文（含标点，${unwrappedCjk.length} 处）——英文模式下会原样露出：`
  );
  for (const u of unwrappedCjk) {
    problems.push(`    ~ ${u.file}:${u.line}  ${JSON.stringify(u.text.slice(0, 60))}`);
  }
}

if (rawFieldRenders.length) {
  problems.push(
    `后端中文字段被裸渲染（${rawFieldRenders.length} 处）——词典里有译文但没人调用，英文模式下会露出中文：`
  );
  for (const r of rawFieldRenders) {
    problems.push(`    ~ src/App.tsx:${r.line}  ${r.text}`);
  }
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

if (trKeyIssues.length) {
  problems.push(
    `tr() 用到的键不在 i18n.rs 的 TABLE 里（${trKeyIssues.length} 处）——查不到会原样返回键名，界面/托盘上直接显示 ${JSON.stringify(trKeyIssues[0].key)} 这种标识符：`
  );
  for (const t of trKeyIssues) {
    problems.push(`    ~ ${t.file}:${t.line}  ${JSON.stringify(t.key)}`);
  }
}

if (tNonLiteral.length) {
  problems.push(
    `t() / tf() 的实参不是字面量（${tNonLiteral.length} 处）——查表必然落空，界面上会原样显示代号文本（e2e 扫描抓不到，因为那不是中文）：`
  );
  for (const t of tNonLiteral) problems.push(`    ~ ${t.file}:${t.line}  ${t.text}`);
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
console.log(
  `i18n TABLE: ${tableKeys.size} 条（tr() 字面量键 ${trLiteralCount} 处，未命中 ${trKeyIssues.length} 处）`
);
console.log(`t()/tf() 实参非字面量: ${tNonLiteral.length} 处（应为 0）`);
for (const w of warnings) console.log(`\n[警告] ${w}`);
for (const p of problems) console.log(`\n[错误] ${p}`);

if (problems.length) {
  console.log(`\n失败：${problems.length} 项错误。`);
  process.exit(1);
}
console.log("\n通过。");
