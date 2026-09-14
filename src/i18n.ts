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
 * 约束：本文件**不得** import 任何 React 组件或 api.ts（避免循环依赖）。
 */
import { useEffect, useState } from "react";
import { UI_DICT } from "./i18n-dict-ui";
import { BACKEND_DICT } from "./i18n-dict-backend";

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
 * 只改本地状态并通知订阅者；落盘由调用方（命令层）负责。
 * 通知是同步的，因此切换语言必须在 React 事件里调用。
 */
export function applyLang(next: Lang): void {
  if (next === current) return;
  current = next;
  for (const fn of [...listeners]) fn();
}

// ─────────── 词典 ───────────

const DICT: Record<string, string> = { ...BACKEND_DICT, ...UI_DICT };

/** 前端文案：key 就是中文原文（中文模式下直接原样返回，零开销）。 */
export function t(key: string): string {
  if (current === "zh") return key;
  return DICT[key] ?? key;
}

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
    if (!/[\u4e00-\u9fff]/.test(zh)) continue;
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
  if (!/[\u4e00-\u9fff]/.test(text)) return text;

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
