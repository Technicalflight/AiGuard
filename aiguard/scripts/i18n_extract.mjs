/**
 * 把 App.tsx 里的界面文案改写成 t("中文原文") 调用，并生成 src/i18n-dict-ui.ts 的键骨架。
 *
 * 为什么需要脚本：界面文案有 300 多条、散布在 3500 行 TSX 里，手工改写既慢又容易漏。
 *
 * 为什么用 TypeScript 官方编译器 API：本仓库已把 typescript 作为 devDependency
 * （`npm run build` 的 tsc 要用），因此解析器是**现成的、不新增任何依赖**。
 * 早期版本用手写状态机扫 TSX，结果在「JSX 元素闭合后如何退回代码上下文」上连踩两个坑
 * （`</svg>` 被当成开标签、多行 JSX 文本的换行被吃掉），改用 AST 后这类问题从根上消失。
 *
 * 用法：node scripts/i18n_extract.mjs [输入.tsx] [输出词典.ts]
 * 幂等：已经包在 t(...) / tf(...) 里的字面量会被识别并跳过，可反复运行。
 *
 * 改写规则（只动这四类，其余一律不碰）：
 *  1. 含中文的字符串字面量            "脱敏"            -> t("脱敏")
 *  2. 含中文的无插值模板串            `脱敏`            -> t("脱敏")
 *  3. 模板串里的中文片段              `失败：${e}`      -> `${t("失败：")}${e}`
 *  4. 含中文的 JSX 文本               文字              -> {t("文字")}
 * 刻意**不动**的：对象字面量的键、类型位置的字面量、import 的模块说明符——
 * 这些位置换成函数调用会直接变成语法错误。
 *
 * 词典键 = 运行时传给 t() 的那个字符串本身（用 JSON.stringify 落盘保证逐字一致）。
 */
import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ts = require("typescript");

const FILE = process.argv[2] ?? "src/App.tsx";
const OUT_DICT = process.argv[3] ?? "src/i18n-dict-ui.ts";

const CJK = /[\u4e00-\u9fff]/;
const keys = new Set();

/**
 * 永不翻译的字面量。
 *
 * 两类，都不是"漏了"，而是**故意保持中文原样**：
 *  1. 语言自称：`简体中文` / `English` 在任何语言下都该显示成它自己的写法，
 *     跟着界面语言翻译反而会让人认不出选项；
 *  2. 与后端中文做比较的判断值：`report.cert_note.includes("未找到")` 里的
 *     "未找到" 比的是后端返回的**中文原文**，包成 t() 之后英文模式下
 *     左边是英文、右边是中文，永远比不相等，逻辑会静默走错分支。
 */
const NEVER_TRANSLATE = new Set(["简体中文", "English", "未找到"]);

const src = fs.readFileSync(FILE, "utf8");

const sf = ts.createSourceFile(FILE, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);

// 解析失败就直接退出：宁可什么都不改，也不要往一个本来就编不过的文件里写东西
if (sf.parseDiagnostics && sf.parseDiagnostics.length > 0) {
  const first = sf.parseDiagnostics[0];
  const pos = sf.getLineAndCharacterOfPosition(first.start ?? 0);
  console.error(
    `解析失败（第 ${pos.line + 1} 行第 ${pos.character + 1} 列）：` +
      ts.flattenDiagnosticMessageText(first.messageText, " ")
  );
  process.exit(1);
}

/** 该节点是否已经位于 t(...) / tf(...) 调用内部（用于保证幂等）。 */
function alreadyWrapped(node) {
  let p = node.parent;
  while (p) {
    if (
      ts.isCallExpression(p) &&
      ts.isIdentifier(p.expression) &&
      (p.expression.text === "t" || p.expression.text === "tf")
    ) {
      return true;
    }
    p = p.parent;
  }
  return false;
}

/** 该字符串字面量是否处于「换成函数调用会变语法错误」的位置。 */
function isProtectedPosition(node) {
  const p = node.parent;
  if (!p) return true;
  // 对象 / 类的键、枚举成员、方法名
  if (
    (ts.isPropertyAssignment(p) ||
      ts.isPropertySignature(p) ||
      ts.isEnumMember(p) ||
      ts.isMethodDeclaration(p) ||
      ts.isMethodSignature(p) ||
      ts.isPropertyDeclaration(p)) &&
    p.name === node
  ) {
    return true;
  }
  // 类型位置：字面量类型、import 的模块说明符
  if (ts.isLiteralTypeNode(p)) return true;
  if (ts.isImportDeclaration(p) || ts.isExportDeclaration(p)) return true;
  if (ts.isExternalModuleReference(p)) return true;
  if (ts.isImportTypeNode(p)) return true;
  // case "x": 的判别值也不能包（case t("x"): 合法但没必要，且会绕开常量折叠）
  if (ts.isCaseClause(p) && p.expression === node) return true;
  return false;
}

/** JSX 属性里必须写成 title={t("关闭")}，不能写成 title=t("关闭")。 */
function isJsxAttributeInitializer(node) {
  const p = node.parent;
  return !!p && ts.isJsxAttribute(p) && p.initializer === node;
}

const edits = [];

function pushStringEdit(node) {
  if (!CJK.test(node.text)) return;
  if (NEVER_TRANSLATE.has(node.text)) return;
  if (alreadyWrapped(node) || isProtectedPosition(node)) return;
  keys.add(node.text);
  const lit = JSON.stringify(node.text);
  edits.push({
    start: node.getStart(sf),
    end: node.getEnd(),
    text: isJsxAttributeInitializer(node) ? `{t(${lit})}` : `t(${lit})`,
  });
}

/** 模板串的中文片段：只包字面量部分，插值表达式原样保留。 */
function pushTemplateParts(node) {
  // 区间口径（实测得出，TS 的模板片段节点把定界符也算在自身范围里）：
  //   TemplateHead   getStart() 指向开头反引号，getEnd() 在 `${` 之后
  //   TemplateMiddle getStart() 指向 `}`，      getEnd() 在 `${` 之后
  //   TemplateTail   getStart() 指向 `}`，      getEnd() 在收尾反引号之后
  // 于是字面量内容的区间是 [getStart()+1, getEnd()-2]（Head/Middle）
  // 或 [getStart()+1, getEnd()-1]（Tail），少扣或多扣一个字符都会产出坏代码。
  //
  // 替换文本一律是 `${t(...)}`——**包括 Tail**。模板串里的一切都是纯文本，
  // 只有写进 `${}` 才会被求值；把 Tail 直接换成 `t("...")` 不会报语法错误，
  // 但会在界面上原样显示出 t("...") 这串字符（第一版就是这么翻车的）。
  const head = node.head;
  if (CJK.test(head.text)) {
    keys.add(head.text);
    edits.push({
      start: head.getStart(sf) + 1,
      end: head.getEnd() - 2,
      text: `\${t(${JSON.stringify(head.text)})}`,
    });
  }
  for (const span of node.templateSpans) {
    const lit = span.literal;
    if (!CJK.test(lit.text)) continue;
    keys.add(lit.text);
    const isTail = lit.kind === ts.SyntaxKind.TemplateTail;
    edits.push({
      start: lit.getStart(sf) + 1,
      end: lit.getEnd() - (isTail ? 1 : 2),
      text: `\${t(${JSON.stringify(lit.text)})}`,
    });
  }
}

/**
 * JSX 文本节点。
 *
 * 关键坑：原文 `第一行\n  第二行` 在 JSX 里会被折叠成一个空格渲染；但改成
 * `{t("第一行")}\n  {t("第二行")}` 之后，两个表达式之间「含换行的空白」会被
 * JSX **整个丢掉**，渲染成「第一行第二行」。所以段间必须显式补 `{" "}`。
 */
function pushJsxTextEdit(node) {
  const raw = node.text;
  if (!CJK.test(raw)) return;
  const m = raw.match(/^(\s*)([\s\S]*?)(\s*)$/);
  const lead = m[1];
  const core = m[2];
  const tail = m[3];
  if (!CJK.test(core)) return;

  const parts = core.split(/(\n[ \t]*)/);
  const items = parts.map((p, idx) => {
    if (idx % 2 === 1) return { sep: true, raw: p, wrapped: false };
    if (p === "") return { sep: false, raw: "", wrapped: false };
    const mm = p.match(/^([ \t]*)([\s\S]*?)([ \t]*)$/);
    const mid = mm[2];
    if (!CJK.test(mid)) return { sep: false, raw: p, wrapped: false };
    keys.add(mid);
    return { sep: false, raw: mm[1] + `{t(${JSON.stringify(mid)})}` + mm[3], wrapped: true };
  });

  let body = "";
  for (let k = 0; k < items.length; k++) {
    const it = items[k];
    if (!it.sep) {
      body += it.raw;
      continue;
    }
    const prev = items[k - 1];
    const next = items[k + 1];
    body += prev && next && prev.wrapped && next.wrapped ? '{" "}' : it.raw;
  }
  // JSX 文本必须用 node.pos / node.end：getStart() 会跳过前导空白，
  // 用它做替换区间会把原文的缩进留在原地、再重复输出一份。
  edits.push({ start: node.pos, end: node.end, text: lead + body + tail });
}

function walk(node) {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    pushStringEdit(node);
  } else if (ts.isTemplateExpression(node)) {
    pushTemplateParts(node);
  } else if (ts.isJsxText(node)) {
    pushJsxTextEdit(node);
  }
  ts.forEachChild(node, walk);
}

walk(sf);

// 从后往前替换，避免前面的编辑让后面的下标失效
edits.sort((a, b) => b.start - a.start);
for (const e of edits) {
  if (e.start < 0 || e.end > src.length || e.start >= e.end) {
    throw new Error(`非法编辑范围 ${e.start}..${e.end}`);
  }
}
let out = src;
for (const e of edits) out = out.slice(0, e.start) + e.text + out.slice(e.end);

// ─────────── 后置校验 ───────────
// 上面那类「模板串里忘了 ${}」的错误不会让 tsc 报错，只会在界面上原样显示 t("...")，
// 所以必须自己查一遍：重新解析产物，确认
//   1. 产物仍然是合法 TSX；
//   2. 任何模板片段里都不含 t( —— 模板片段里的一切都是纯文本。
const outSf = ts.createSourceFile(FILE, out, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
const errs = outSf.parseDiagnostics ?? [];
if (errs.length > 0) {
  const first = errs[0];
  const pos = outSf.getLineAndCharacterOfPosition(first.start ?? 0);
  console.error(
    `改写产物无法解析（第 ${pos.line + 1} 行第 ${pos.character + 1} 列）：` +
      ts.flattenDiagnosticMessageText(first.messageText, " ")
  );
  process.exit(1);
}
(function verifyTemplates(n) {
  if (ts.isTemplateExpression(n)) {
    const bad = [n.head, ...n.templateSpans.map((s) => s.literal)].find((l) => l.text.includes("t("));
    if (bad) {
      const pos = outSf.getLineAndCharacterOfPosition(bad.getStart(outSf));
      console.error(
        `模板串里出现了未求值的 t(...)（第 ${pos.line + 1} 行）：` +
          JSON.stringify(bad.text) +
          "\n模板串里的一切都是纯文本，必须写成 ${t(...)}。"
      );
      process.exit(1);
    }
  }
  ts.forEachChild(n, verifyTemplates);
})(outSf);

fs.writeFileSync(FILE, out, "utf8");

const sorted = [...keys].sort((a, b) => a.localeCompare(b, "zh"));

/**
 * 合并写出词典：**保留已有译文，只为新出现的键留空**。
 *
 * 注意 `keys` 只是**这次新包上 t() 的**那些字面量（已包过的会被跳过），
 * 所以绝不能拿它直接覆盖整本词典——那样第一次重跑就会把已有译文全部清空，
 * 而且 git diff 只显示「一堆字符串变空了」，很容易被顺手提交。
 * 正确做法是把已有词典读进来，只追加新键。
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
for (const k of sorted) if (!existing.has(k)) existing.set(k, "");
const allKeys = [...existing.keys()].sort((a, b) => a.localeCompare(b, "zh"));

const stub = [
  "/**",
  " * 前端界面文案词典（中文原文 -> 英文）。",
  " *",
  " * 键由 `scripts/i18n_extract.mjs` 从 App.tsx 中抽取，**必须与调用点逐字一致**；",
  " * 落盘时统一用 JSON.stringify，保证与运行时传入 t() 的字符串完全相同。",
  " * 空字符串表示尚未翻译，英文模式下会原样回退中文（宁可露出中文，也不要错译）。",
  " *",
  " * 含 `{}` 的条目会被 i18n.ts 升级为「前缀 + 捕获组」规则，用于翻译",
  " * `发送失败: 请求超时` 这类拼出来的句子；两边的 {} 数量必须一致，否则该条目失效。",
  " *",
  " * 另一类需要留意的是「拼接碎片」：界面里有大量",
  " * `${t(\"本轮清理：直通 \")}${n}${t(\" 条、已脱敏 \")}${m}${t(\" 条\")}`",
  " * 这样的句子，键自带前导/尾随空格。翻译时必须把空格也安排对，",
  " * 否则英文会粘成 `passthrough5masked2`。本文件的统一做法是：",
  " * 前导空格留在译文里，让数字紧跟在冒号或介词之后。",
  " */",
  "export const UI_DICT: Record<string, string> = {",
  ...allKeys.map((k) => `  ${JSON.stringify(k)}: ${JSON.stringify(existing.get(k) ?? "")},`),
  "};",
  "",
].join("\n");
fs.writeFileSync(OUT_DICT, stub, "utf8");

console.log(
  `keys=${keys.size} edits=${edits.length}；词典共 ${allKeys.length} 条，本次新增待译 ${fresh.length} 条 -> ${OUT_DICT}`
);
if (fresh.length) for (const k of fresh) console.log(`    + ${JSON.stringify(k)}`);
