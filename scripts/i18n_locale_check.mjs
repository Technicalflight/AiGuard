/**
 * 语言切换对「浏览器原生属性」的影响验证（`document.title` / `<html lang>`）。
 *
 * 为什么单独测这个，而不是交给 `i18n_e2e.mjs`：
 * 这两个属性由 `applyLang` 里的 `syncDocumentLocale()` 写入，而它在 `applyLang`
 * **提前返回（语言没变）之前**被调用——这条路径是「首次加载时后端回传的语言正好
 * 等于默认值（zh）」才会走的。浏览器预览的 `get_language` 是常量 MOCK（zh），
 * 所以真实浏览器里**永远走不到「首屏就是英文」这条路径**，e2e 扫不到。
 * 只能把 `i18n.ts` 真打一份包，在 stub DOM 上跑。
 *
 * ⚠ 本测试的关键设计：起始状态故意设成**错误值**（title 是垃圾字符串、lang 是 xx）。
 * 如果起始值就设成期望值，那「同步跑过了」和「同步压根没跑」得到的结果一样，
 * 断言是空的——第一版就是这么写的，等于没测。踩过，别改回去。
 *
 * 运行：npm run i18n:locale
 * 退出码：0 = 通过；1 = 有断言失败。
 */
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function loadEsbuild() {
  try {
    return await import("esbuild");
  } catch {
    throw new Error(
      "未找到 esbuild。它通常是 vite 的传递依赖，若确实缺失请执行 `npm i -D esbuild`。"
    );
  }
}

const esbuild = await loadEsbuild();

const built = await esbuild.build({
  entryPoints: [path.join(ROOT, "src/i18n.ts")],
  bundle: true,
  format: "cjs",
  platform: "node",
  write: false,
  logLevel: "silent",
});
const code = built.outputFiles[0].text;

// stub 一个最小的 DOM：只实现 i18n.ts 会碰到的两个属性。
// 起始值故意是错的，见文件头说明。
const doc = {
  title: "‹未同步›",
  documentElement: { lang: "xx" },
};
globalThis.document = doc;

const mod = { exports: {} };
new Function("module", "exports", "require", code)(mod, mod.exports, () => {
  throw new Error("打包产物不应有运行时 require");
});
const i18n = mod.exports;

let failed = 0;
const check = (name, got, want) => {
  const ok = got === want;
  if (!ok) failed++;
  console.log(
    `${ok ? "  ok  " : "  FAIL"} ${name}\n        got  ${JSON.stringify(got)}\n        want ${JSON.stringify(want)}`
  );
};

/** 把两个原生属性重新弄脏，确保每段断言都在验证「真的同步了」。 */
function dirty() {
  doc.title = "‹未同步›";
  doc.documentElement.lang = "xx";
}

console.log("=== 首次加载：后端回传 zh（等于默认值 → 走 applyLang 的提前返回分支）===");
console.log("    （这是 e2e 覆盖不到的那条路径：预览模式下首屏永远是中文）");
dirty();
i18n.applyLang("zh");
check("document.title", doc.title, "AI 安全卫士");
check("html lang", doc.documentElement.lang, "zh-CN");

console.log("\n=== 首次加载：后端回传 en（语言变了，走监听器分支）===");
dirty();
i18n.applyLang("en");
check("document.title", doc.title, "AI Guard");
check("html lang", doc.documentElement.lang, "en");

console.log("\n=== 切回中文 ===");
dirty();
i18n.applyLang("zh");
check("document.title", doc.title, "AI 安全卫士");
check("html lang", doc.documentElement.lang, "zh-CN");

console.log("\n=== 重复应用同一语言（提前返回分支）仍须同步 ===");
dirty();
i18n.applyLang("en");
i18n.applyLang("en"); // 第二次应走提前返回，但同步不能因此被跳过
check("document.title（第二次）", doc.title, "AI Guard");
check("html lang（第二次）", doc.documentElement.lang, "en");

console.log("\n=== 监听器只在语言真的变化时触发 ===");
let fired = 0;
const off = i18n.subscribeLang(() => fired++);
i18n.applyLang("en"); // 无变化 → 不应触发
check("同语言重复 applyLang 触发次数", fired, 0);
i18n.applyLang("zh"); // 有变化 → 触发一次
check("切换语言触发次数", fired, 1);
off();
i18n.applyLang("en");
check("取消订阅后触发次数", fired, 1);

console.log(`\n${failed === 0 ? "全部通过" : `${failed} 项失败`}`);
process.exitCode = failed === 0 ? 0 : 1;
