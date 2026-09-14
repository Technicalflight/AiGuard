/// <reference types="vite/client" />

// 为什么需要这个文件：
//
// TypeScript 7 起，**纯副作用导入**（例如 `import "./ui.css"`）在解析不到模块声明时
// 会直接报错 TS2882；TypeScript 5.9 对同一份源码是容忍的。
// 归因方式：用旧版 tsc（5.9.3）与新版 tsc（7.0.2）分别编译同一份 src，
// 前者 exit 0、后者报 TS2882 —— 所以这是升级带来的新约束，不是既有缺陷。
//
// vite/client 里声明了 `declare module '*.css'`，以及图片、`?raw`、`?url`
// 等资源后缀的声明。引用它等于把这些资源导入的类型补齐，
// 也是 Vite 官方脚手架的默认做法。
//
// 注意：这个文件必须留在 `src/` 下——tsconfig.json 的 include 只有 ["src"]。
