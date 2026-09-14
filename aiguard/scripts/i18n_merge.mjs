/**
 * 把一批译文合并进词典文件。
 *
 * 为什么需要它：词典是**按中文排序**的，手工往中间插新条目既容易插错位置、
 * 也容易漏掉某个键。把「译文」写成独立 JSON 交给脚本合并，有三点好处：
 *   1. 排序由脚本保证，diff 干净；
 *   2. 译文可以分批交付，随时合并、随时重跑，不用重写整个词典文件；
 *   3. 每个键落在哪本词典由脚本判断，不用人工记。
 *
 * 用法：node scripts/i18n_merge.mjs <translations.json> [更多.json ...]
 *   JSON 形如 { "中文原文": "English", ... }
 *   已在词典里的键 → 就地更新；词典里没有的键 → 视为新增，进 UI_DICT
 *   （新增的键如果其实写错了，随后跑 `i18n_check.mjs` 会以
 *   「UI_DICT 里没有调用点的键」报出来，不会静默积压）。
 */
import fs from "node:fs";

const FILES = [
  { path: "src/i18n-dict-ui.ts", name: "UI_DICT" },
  { path: "src/i18n-dict-backend.ts", name: "BACKEND_DICT" },
];

/** 解析词典文件：取出头部注释（原样保留）与键值对。 */
function parseDict(path) {
  const src = fs.readFileSync(path, "utf8");
  const start = src.indexOf("export const ");
  const open = src.indexOf("{", start);
  const close = src.lastIndexOf("}");
  const header = src.slice(0, open + 1);
  const entries = new Map();
  const re = /^\s*("(?:[^"\\]|\\.)*"):\s*("(?:[^"\\]|\\.)*"),\s*$/gm;
  for (const m of src.slice(open, close).matchAll(re)) {
    entries.set(JSON.parse(m[1]), JSON.parse(m[2]));
  }
  return { header, entries };
}

function writeDict(path, header, entries) {
  const keys = [...entries.keys()].sort((a, b) => a.localeCompare(b, "zh"));
  const body = keys.map((k) => `  ${JSON.stringify(k)}: ${JSON.stringify(entries.get(k))},`).join("\n");
  fs.writeFileSync(path, `${header}\n${body}\n};\n`, "utf8");
}

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error("用法：node scripts/i18n_merge.mjs <translations.json> [更多.json ...]");
  process.exit(1);
}

const dicts = FILES.map((f) => ({ ...f, ...parseDict(f.path) }));
const pending = new Map(); // key -> { en, owner }
const fresh = []; // 词典里原本没有的键

for (const a of args) {
  const obj = JSON.parse(fs.readFileSync(a, "utf8"));
  for (const [k, en] of Object.entries(obj)) {
    if (typeof en !== "string") {
      console.error(`译文必须是字符串：${JSON.stringify(k)}`);
      process.exit(1);
    }
    if (pending.has(k)) {
      console.error(`同一个键被给了两次译文：${JSON.stringify(k)}`);
      process.exit(1);
    }
    const owner = dicts.find((d) => d.entries.has(k)) ?? dicts[0];
    if (!dicts.some((d) => d.entries.has(k))) fresh.push(k);
    pending.set(k, { en, owner });
  }
}

let added = 0;
let changed = 0;
for (const [k, { en, owner }] of pending) {
  const old = owner.entries.get(k);
  if (old === undefined) added++;
  else if (old !== en) changed++;
  owner.entries.set(k, en);
}

for (const d of dicts) writeDict(d.path, d.header, d.entries);

for (const d of dicts) {
  const total = d.entries.size;
  const empty = [...d.entries.values()].filter((v) => v === "").length;
  console.log(`${d.name}: ${total} 条（未翻译 ${empty} 条）`);
}
console.log(`本次合并：新增 ${added} 条，改写 ${changed} 条。`);
if (fresh.length) {
  console.log(`其中词典里原本没有、已作为新条目加入 UI_DICT 的 ${fresh.length} 条：`);
  for (const k of fresh) console.log(`    + ${JSON.stringify(k)}`);
}
