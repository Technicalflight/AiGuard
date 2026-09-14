//! # aiguard-core
//!
//! AI 安全卫士核心逻辑 crate：只做纯逻辑，无 Tauri / 代理框架依赖。
//!
//! - [`detector`]: 敏感信息检测引擎（身份证 / 手机号 / 银行卡 / 邮箱 / API Key / IP）
//! - [`vault`]: 原文 ↔ 占位符映射表（会话隔离 + TTL，仅内存）
//! - [`stream`]: 流式还原状态机（SSE chunk 中占位符可能被拆开）
//! - [`sse`]: SSE 帧状态机（切帧 / 格式校验 / 缓冲上限）
//! - [`audit`]: 响应侧防护信号（被动扫描 + 严重度分层 + 去重聚合）
//! - [`inspect`]: 主动核查计划、风险矩阵与审计报告
//! - [`secure`]: 还原管道 + 审计上下文采集（只告警不改写）
//! - [`mem`]: 敏感内存主动擦除（原文映射销毁时覆写字节）

pub mod audit;
pub mod detector;
pub mod inspect;
pub mod mem;
pub mod secure;
pub mod sse;
pub mod stream;
pub mod vault;
