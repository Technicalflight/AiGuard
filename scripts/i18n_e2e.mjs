/**
 * 端到端语言扫描：把真实界面切到英文，逐个界面扫 DOM 里残留的汉字。
 *
 * 为什么必须真跑：静态自检（`i18n_check.mjs`）只能证明「字面量都包了 t()」。
 * 运行时仍有两条路径会露中文，而且**不会有任何编译错误**：
 *  1. 后端返回的字符串在某处渲染时忘了过 `tb()`（词典里有译文，但没人调用）；
 *  2. 只在特定状态/分支下才渲染的文案（静态扫描看不到）。
 * 这两类只有把页面真渲染出来才能发现。历史上它们一共出现过 10 次。
 *
 * 用法：
 *   npm run dev            # 另开一个终端，dev server 必须在跑
 *   npm run i18n:e2e
 *
 * 依赖 Playwright（未列入 devDependencies，因为它体积大且只在需要时用）：
 *   npm i -D playwright && npx playwright install chromium
 * 或者用 NODE_PATH 指向一个已有的 Playwright 安装：
 *   NODE_PATH=/path/to/node_modules npm run i18n:e2e
 *
 * 环境变量：
 *   AIGUARD_URL       目标地址，默认 http://localhost:5173
 *   AIGUARD_CHROMIUM  Chromium 可执行文件路径（Playwright 自带浏览器版本对不上时用）
 *
 * 退出码：0 = 干净；1 = 有残留中文或数据面异常。
 */
import path from "node:path";
import { pathToFileURL } from "node:url";

const BASE = process.env.AIGUARD_URL ?? "http://localhost:5173";
const HAN = /[\u4e00-\u9fff]/;

/**
 * 解析 playwright 的 chromium。
 * 默认从项目依赖解析；解析不到时依次尝试 NODE_PATH 里的每个根目录
 * （这样既能 `npm i -D playwright`，也能复用别处已装好的 Playwright，不强制改依赖）。
 *
 * ⚠ playwright 是 CommonJS 包，`import()` 它拿到的是 `{ default: {...} }`——
 * 具名导出**不一定**被 cjs-module-lexer 识别出来，所以 `mod.chromium` 可能是
 * undefined（踩过：报 `Cannot read properties of undefined (reading 'launch')`）。
 * 必须同时看 `mod.default`。
 */
async function loadChromium() {
  const pick = (mod) => mod?.chromium ?? mod?.default?.chromium;

  try {
    const c = pick(await import("playwright"));
    if (c) return c;
  } catch {
    /* 继续尝试 NODE_PATH */
  }
  const roots = (process.env.NODE_PATH ?? "").split(path.delimiter).filter(Boolean);
  for (const root of roots) {
    try {
      const entry = path.join(root, "playwright", "index.js");
      const c = pick(await import(pathToFileURL(entry).href));
      if (c) return c;
    } catch {
      /* 试下一个 */
    }
  }
  throw new Error(
    "未找到 playwright。请执行 `npm i -D playwright && npx playwright install chromium`，" +
      "或用 NODE_PATH 指向已安装 playwright 的 node_modules 目录。"
  );
}

const chromium = await loadChromium();

/** 允许保持中文的例外。每条都要写清理由，否则白名单会变成噪音垃圾桶。 */
const ALLOW = [
  /^简体中文$/, // 语言自称：中文在语言列表里永远写作「简体中文」，不该翻
  /阿尔法计划\|贝塔计划/, // 用户自己写的规则正则原文，翻译它等于改掉用户配置的语义
  /^[\d\s.,:%/·—\-]*$/, // 纯数字/符号
];

// 先确认目标可达，否则下面会以一堆「元素找不到」的形式失败，误导方向。
try {
  const res = await fetch(BASE, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
} catch (e) {
  console.error(`✗ 无法访问 ${BASE}（${e.message}）。请先启动 dev server：npm run dev`);
  process.exit(1);
}

const browser = await chromium.launch(
  process.env.AIGUARD_CHROMIUM ? { executablePath: process.env.AIGUARD_CHROMIUM } : {}
);
const page = await browser.newPage({ viewport: { width: 1500, height: 1000 } });
// Playwright 默认 30s 太长：点不开的弹窗会各卡 30 秒（多个弹窗就是几分钟白等）。
// 本地 MOCK 页面 10s 足够，超时即真点不开，早失败早暴露。
page.setDefaultTimeout(10000);

const pageErrors = [];
page.on("pageerror", (e) => pageErrors.push(e.message));

let totalHits = 0;
let scanned = 0;

/**
 * 切到英文。
 * ⚠ 浏览器预览模式下 `get_language` 返回固定的 MOCK 值（zh），所以**每次页面重载后
 * 都要重新切一遍**，否则扫到的是中文模式，全是假阳性。
 */
async function switchToEnglish() {
  const n = await page.locator(".rail-item").count();
  await page.locator(".rail-item").nth(n - 1).click(); // 最后一项 = 设置
  await page.waitForTimeout(900);
  await page.locator('button:has-text("简体中文")').first().click();
  await page.waitForTimeout(300);
  await page.locator('.dd-opt:has-text("English")').click();
  await page.waitForTimeout(1300);
}

async function scan(label) {
  scanned++;
  // ⚠ innerText 不含折叠内容：<details> 收起时其正文对 innerText 是不可见的，
  // 会让「完整报告」这类大块文案整体逃过扫描。扫之前先把它们全展开。
  const opened = await page.evaluate(() => {
    const ds = [...document.querySelectorAll("details")];
    ds.forEach((d) => (d.open = true));
    return ds.length;
  });
  if (opened) await page.waitForTimeout(300);

  const { lines, attrs } = await page.evaluate(() => {
    const body = document.body.innerText.split("\n").map((s) => s.trim()).filter(Boolean);
    // ⚠ `innerText` **完全不含** title / placeholder / aria-label / alt：
    // 悬停提示、输入框占位符、无障碍标签都是用户可见（或辅助技术可读）的文案，
    // 但它们不进 innerText。只扫 innerText 会把这一整类漏掉——
    // 而它们恰恰最不容易被肉眼发现（要悬停才看得见）。
    const ATTRS = ["title", "placeholder", "aria-label", "alt"];
    const seen = new Set();
    const out = [];
    for (const el of document.querySelectorAll("[title],[placeholder],[aria-label],[alt]")) {
      for (const a of ATTRS) {
        const v = el.getAttribute(a);
        if (v && v.trim()) {
          const key = a + "|" + v.trim();
          if (!seen.has(key)) {
            seen.add(key);
            out.push(`${a}="${v.trim()}"`);
          }
        }
      }
    }
    return { lines: body, attrs: out };
  });

  const all = [...lines, ...attrs];
  const bad = all.filter((l) => HAN.test(l) && !ALLOW.some((re) => re.test(l)));
  totalHits += bad.length;
  console.log(
    `${bad.length ? "✗" : "✓"} ${label}  （${lines.length} 行 + ${attrs.length} 个属性，展开 ${opened} 个折叠块，命中 ${bad.length}）`
  );
  for (const b of bad.slice(0, 10)) console.log(`      ${JSON.stringify(b.slice(0, 150))}`);
  if (bad.length > 10) console.log(`      ... 另有 ${bad.length - 10} 行`);
}

// ── 数据面非空断言 ──
//
// 为什么 i18n 扫描脚本要管「有没有数据」：浏览器预览的数据是常量 MOCK，
// 任何「本该有数据却渲染成空态」都是真缺陷——不只是少看几行，它会**把 i18n
// 覆盖盲区藏起来**。真实踩过：RequestsPage 的默认筛选值就是 "all"，而
// listRequestsPage 的 MOCK 分支只判 `action` 的真值，于是 "all" 被当成真过滤器、
// 7 条 MOCK 日志一条都匹配不上，「全部」页恒为空表 → 「请求处理详情」弹窗
// 根本没有可点的行 → 那个弹窗从来没被扫到过。
// 所以：页面非空 = 弹窗可达 = i18n 覆盖完整。三者是同一条链。
const dataFailures = [];

async function expectRows(label, sel, min) {
  const n = await page.locator(sel).count();
  const ok = n >= min;
  if (!ok) dataFailures.push(`${label}: ${sel} = ${n}（期望 ≥ ${min}）`);
  console.log(`${ok ? "✓" : "✗"} 数据面 ${label}：${sel} = ${n}（期望 ≥ ${min}）`);
  return n;
}

async function gotoRail(i) {
  await page.locator(".rail-item").nth(i).click();
  await page.waitForTimeout(800);
}

// ── 主界面：逐页扫描 ──
await page.goto(BASE, { waitUntil: "networkidle" });
await page.waitForTimeout(2000);
await switchToEnglish();

// 浏览器原生面：`document.title` 与 `<html lang>` 不在 React 渲染树里，
// innerText 扫不到它们，但它们同样是用户可见/可被辅助技术读到的中文。
// 历史上这两处曾永远停在 index.html 的硬编码值（`applyLang` 的提前返回吃掉了
// 首次加载路径），所以必须单独断言。
const native = await page.evaluate(() => ({
  title: document.title,
  lang: document.documentElement.lang,
}));
console.log(`切英文后：${native.title} | lang=${native.lang}\n`);

const nativeFailures = [];
if (HAN.test(native.title)) nativeFailures.push(`document.title 仍是中文：${native.title}`);
if (native.lang !== "en") nativeFailures.push(`<html lang> 未同步：${native.lang}（期望 en）`);
for (const f of nativeFailures) console.log(`✗ ${f}`);
if (!nativeFailures.length) console.log("✓ 原生面：document.title / <html lang> 已随语言切换");
console.log("");

const railCount = await page.locator(".rail-item").count();
for (let i = 0; i < railCount; i++) {
  const name = await page.locator(".rail-item").nth(i).innerText();
  await page.locator(".rail-item").nth(i).click();
  await page.waitForTimeout(900);
  await scan(`[${i}] ${name.replace(/\s+/g, " ")}`);
}

// 逐页断言「该有数据的页面确实有数据」，顺带保证下面的弹窗一定点得开。
await gotoRail(1);
await expectRows("请求页", ".row-clickable", 1);
await gotoRail(2);
await expectRows("规则页", ".rule-foot", 1);
await gotoRail(4);
await expectRows("审计页", ".row-clickable", 1);
console.log("");

// ── 弹窗与详情面板（不在导航页里，必须点开才渲染）──
//
// 弹窗内容只在打开时才进 DOM，所以逐页扫 innerText 完全覆盖不到它们。
// 界面里共 5 个：应急切断（确认 / 已执行）、两处「请求处理详情」、规则编辑。

async function openAndScan(label, open) {
  try {
    await open();
  } catch (e) {
    console.log(`- ${label}（打开失败，跳过：${String(e.message).slice(0, 60)}）`);
    return;
  }
  await page.waitForTimeout(900);
  const modal = page.locator(".modal").first();
  if (!(await modal.count())) {
    console.log(`- ${label}（未出现弹窗，跳过）`);
    return;
  }
  await scan(label);
  const x = page.locator(".modal-x").first();
  if (await x.count()) await x.click();
  await page.waitForTimeout(500);
}

// 首页 → 一键应急切断：确认弹窗 → 执行 → 结果弹窗
await gotoRail(0);
await openAndScan("[弹窗] 应急切断 · 确认", async () => {
  await page.locator("button.cta.danger").first().click();
});
await openAndScan("[弹窗] 应急切断 · 已执行", async () => {
  await page.locator("button.cta.danger").first().click();
  await page.waitForTimeout(700);
  await page.locator(".modal-foot button.btn.danger").first().click();
});

// 请求页 → 点一行打开「请求处理详情」
await gotoRail(1);
await openAndScan("[弹窗] 请求处理详情（请求页）", async () => {
  await page.locator(".row-clickable").first().click();
});

// 规则页 → 编辑第一条规则
await gotoRail(2);
await openAndScan("[弹窗] 编辑规则", async () => {
  await page.locator(".rule-foot").first().locator("button.btn.mini").first().click();
});

// 审计页 → 点一行打开「请求处理详情」
await gotoRail(4);
await openAndScan("[弹窗] 请求处理详情（审计页）", async () => {
  await page.locator(".row-clickable").first().click();
});

// ── 首次运行向导（独立覆盖层，是最大的单块界面）──
//
// ⚠ 不能用 `?wizard=1`：那会重载页面，而浏览器 MOCK 的 get_language 是常量，
// 重载后语言被打回中文，扫到的一屏中文全是假阳性（踩过一次）。
// 改用设置页里的「重新运行」按钮——它**不重载**，语言保持不变。
await page.locator(".rail-item").nth(railCount - 1).click();
await page.waitForTimeout(900);
await page.locator('button:has-text("Run again")').first().click();
await page.waitForTimeout(1500);
await scan("[向导] 第 1 屏");

for (let step = 2; step <= 4; step++) {
  const next = page.locator(".wiz-foot .btn.mini.primary").first();
  if (!(await next.count())) break;
  await next.click();
  await page.waitForTimeout(800);
  await scan(`[向导] 第 ${step} 屏`);
}

console.log("");
if (pageErrors.length) {
  console.log(`⚠ 页面报错 ${pageErrors.length} 条：`);
  for (const e of pageErrors.slice(0, 5)) console.log(`   ${e.slice(0, 160)}`);
}
if (dataFailures.length) {
  console.log(`✗ 数据面异常 ${dataFailures.length} 处（预览数据缺失会让弹窗点不开、i18n 覆盖出盲区）：`);
  for (const f of dataFailures) console.log(`   ${f}`);
}
if (nativeFailures.length) {
  console.log(`✗ 原生面异常 ${nativeFailures.length} 处：`);
  for (const f of nativeFailures) console.log(`   ${f}`);
}
const clean = totalHits === 0 && dataFailures.length === 0 && nativeFailures.length === 0;
console.log(
  clean
    ? `结论：${scanned} 个界面英文模式下未发现残留中文，预览数据面与原生面均正常。`
    : `结论：${scanned} 个界面中，残留中文 ${totalHits} 行，数据面异常 ${dataFailures.length} 处，原生面异常 ${nativeFailures.length} 处。`
);

await browser.close();
process.exitCode = clean ? 0 : 1;
