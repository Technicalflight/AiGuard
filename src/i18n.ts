/**
 * 界面文案的多语言内核。
 *
 * 设计取舍：**词典以中文原文为键**。
 * 理由（本项目实测）：
 *  1. 中文原文本身就是最稳定的标识——改英文措辞不需要动 App.tsx 里的任何调用点；
 *  2. 后端返回的诊断文案本身就是中文，前端可以拿同一张表直接翻译（见 tb），
 *     不必给 40 多个 Tauri 命令再加一轮语言参数。
 *
 * 两条查询路径：
 *  - t(中文)   ：前端自有文案，精确查表。
 *  - tb(后端串)：后端返回的中文诊断，先跑带占位符的规则（可嵌套），再做长片段替换。
 *
 * 三本词典合并成一张表：
 *  - UI_DICT      前端文案（键来自 App.tsx / api.ts 的 t() 调用点）
 *  - BACKEND_DICT 后端文案（键来自 Rust 字符串字面量）
 *  - RUNTIME_DICT 运行期产生的中文（系统错误原文、外部命令输出），手工维护
 *
 * 约束：本文件**不得** import 任何 React 组件或 api.ts（避免循环依赖）。
 */
import { useEffect, useState } from "react";
import { UI_DICT } from "./i18n-dict-ui";
import { BACKEND_DICT } from "./i18n-dict-backend";
import { RUNTIME_DICT } from "./i18n-dict-runtime";

export type Lang = "zh" | "en";

export function isLang(v: unknown): v is Lang {
  return v === "zh" || v === "en";
}

/** 语言在设置页里的自称：中文永远写作「简体中文」。 */
export function langName(l: Lang): string {
  return l === "en" ? "English" : "简体中文";
}

// ─────────── 语言状态（模块级 + 订阅） ───────────

let current: Lang = "zh";
const listeners = new Set<() => void>();

export function getLang(): Lang {
  return current;
}

export function subscribeLang(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/**
 * 把当前语言同步到**两个浏览器原生属性**。
 *
 * `<title>` 与 `<html lang>` 不在 React 的渲染范围内，所以不会随组件重渲染而更新：
 *  - 标题：浏览器预览模式下显示在标签页上；
 *  - `lang`：决定字体回退、断词规则，屏幕阅读器也靠它选发音，`:lang()` 选择器同样依赖它。
 *
 * ⚠ 必须在 `applyLang` 的**提前返回之前**调用。首次加载时后端返回的语言可能正好
 * 等于默认值（zh），提前返回会让这两个属性永远停在 `index.html` 里的硬编码值。
 */
function syncDocumentLocale(): void {
  if (typeof document === "undefined") return; // 非浏览器环境（自检脚本/SSR）直接跳过
  document.title = t("AI 安全卫士");
  document.documentElement.lang = current === "en" ? "en" : "zh-CN";
}

/**
 * 只改本地状态并通知订阅者；落盘由调用方（命令层）负责。
 * 通知是同步的，因此切换语言必须在 React 事件里调用。
 */
export function applyLang(next: Lang): void {
  const changed = next !== current;
  current = next;
  // 语言没变也要跑：首次加载（后端回传的语言 === 默认值）走的就是这条路。
  syncDocumentLocale();
  if (!changed) return;
  for (const fn of [...listeners]) fn();
}

// ─────────── 词典 ───────────

// 后者优先：RUNTIME 里的系统错误原文与前后端文案不会撞键，UI_DICT 放最后最安全。
const DICT: Record<string, string> = { ...BACKEND_DICT, ...RUNTIME_DICT, ...UI_DICT };

/** 前端文案：key 就是中文原文（中文模式下直接原样返回，零开销）。 */
export function t(key: string): string {
  if (current === "zh") return key;
  return DICT[key] ?? key;
}

/**
 * 「这段文本需要翻译吗」的判定：**汉字，或中文/全角标点**。
 *
 * ⚠ 只写 `[\u4e00-\u9fff]` 会漏掉纯标点片段——真实踩过：模板串里的 `。`
 * 让英文界面渲染出 `...administrators。Current user ...`。
 * 范围与 `scripts/i18n_extract.mjs` 的 CJK 保持一致（不含全角字母）。
 */
const HAS_CJK =
  /[\u4e00-\u9fff\u3000-\u303f\ufe30-\ufe4f\uff01-\uff0f\uff1a-\uff20\uff3b-\uff40\uff5b-\uff65]/;

/**
 * 带占位符的条目自动升级为规则：`{}` → 捕获组，替换时对捕获内容递归翻译。
 * 这样 `发送失败: 请求超时` 这类「前缀 + 内层中文」的组合能逐层翻干净。
 */
type Rule = { re: RegExp; en: string };

/** 占位符占位符：先替换成不可能出现的私有标记，正则转义后再换回捕获组。 */
const BRACE = "\u0000BRACE\u0000";

function buildRules(): Rule[] {
  const rules: Rule[] = [];
  for (const [zh, en] of Object.entries(DICT)) {
    if (!zh.includes("{}") || !en) continue;
    if (!HAS_CJK.test(zh)) continue;
    const n = (zh.match(/\{\}/g) ?? []).length;
    if (n !== (en.match(/\{\}/g) ?? []).length) continue; // 占位符数量不一致则不建规则
    const body = zh
      .split("{}")
      .join(BRACE)
      .replace(/[.*+?^${}()|[\]\\]/g, (m) => "\\" + m)
      .split(BRACE)
      .join("([\\s\\S]*?)");
    // 必须整串锚定：否则末尾的惰性捕获组会匹配空串，把实参吞掉
    rules.push({ re: new RegExp("^" + body + "$"), en });
  }
  // 更长的模式更具体，先匹配
  rules.sort((a, b) => b.re.source.length - a.re.source.length);
  return rules;
}

const RULES = buildRules();

/** 无占位符的条目做「长片段替换」；过短的片段（<4 个汉字）不参与，避免误伤。 */
function buildFragments(): [string, string][] {
  const frags: [string, string][] = [];
  for (const [zh, en] of Object.entries(DICT)) {
    if (!en || zh.includes("{}")) continue;
    const cjk = (zh.match(/[\u4e00-\u9fff]/g) ?? []).length;
    if (cjk < 4) continue;
    frags.push([zh, en]);
  }
  frags.sort((a, b) => b[0].length - a[0].length);
  return frags;
}

const FRAGMENTS = buildFragments();

/**
 * 翻译后端返回的中文诊断。中文模式原样返回；英文模式逐层翻译，
 * 表里没有的片段保持中文（宁可露出中文，也不要输出错译）。
 */
export function tb(text: string): string {
  if (current === "zh" || !text) return text;
  if (!HAS_CJK.test(text)) return text;

  const exact = DICT[text];
  if (exact) return exact;

  let out = text;
  for (const { re, en } of RULES) {
    if (!re.test(out)) continue;
    out = out.replace(re, (...args: unknown[]) => {
      let k = 0;
      return en.replace(/\{\}/g, () => tb(String(args[++k] ?? "")));
    });
    break;
  }
  for (const [zh, en] of FRAGMENTS) {
    if (out.includes(zh)) out = out.split(zh).join(en);
  }
  return out;
}

/** 供自检/开发使用：列出当前词典里尚未给出英文的条目。 */
export function untranslated(): string[] {
  return Object.entries(DICT)
    .filter(([, en]) => !en)
    .map(([zh]) => zh);
}

/** 供自检/开发使用：统计覆盖率。 */
export function dictSize(): { total: number; translated: number } {
  const entries = Object.entries(DICT);
  return { total: entries.length, translated: entries.filter(([, en]) => !!en).length };
}

// ─────────── React 绑定 ───────────

/**
 * 订阅语言变化。
 *
 * 只在 App 根组件调用即可：语言切换会重渲染整棵树，子组件里直接用 t()
 * （模块函数）就能拿到新语言，不需要每个组件都订阅。
 */
export function useI18n(): { lang: Lang; t: typeof t; tb: typeof tb } {
  const [, force] = useState(0);
  useEffect(() => {
    const un = subscribeLang(() => force((n) => n + 1));
    return () => {
      un();
    };
  }, []);
  return { lang: current, t, tb };
}
