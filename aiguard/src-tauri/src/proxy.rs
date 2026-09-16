//! hudsucker 0.20 MITM 代理引擎。
//!
//! 重要事实：hudsucker 0.20 的 HttpHandler 工作在 hyper 0.14 上（经 `hudsucker::hyper`
//! 重导出），rustls 0.21 / http 0.2 类型同样经 hudsucker 重导出使用。
//!
//! **请求方向**（主链路，不改）：只对 AI 域名的 application/json 请求体做 PII 脱敏
//! （detector → vault 占位符），Block 规则仍然拦截；
//! **响应方向**：还原占位符（低延迟流式）并**采集审计上下文**，交给
//! [`aiguard_core::audit`] 的防护信号检测 —— **只告警，绝不改写响应**。
//!
//! 日志绝不落原文；任何内部错误只记录短消息，绝不透传给客户端。

use std::net::SocketAddr;
use std::sync::Arc;

use aiguard_core::detector::{Action, Detector};
use aiguard_core::secure::{ResponsePipeline, RestoreLimits};
use aiguard_core::vault::Vault;
use bytes::Bytes;
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::hyper::body::to_bytes;
use hudsucker::hyper::{Body, Method, Request, Response};
use hudsucker::{HttpContext, HttpHandler, Proxy, RequestOrResponse};

use crate::state::{self, safe_err, AppState, FindingMeta, PiiEvent, ReqInfo};
use serde_json::Value;

/// 内部头：核查标记（转发上游前剥离）。
const HDR_PROBE_ID: &str = "x-shield-check-id";
/// 内部头：追踪标记 注册（逗号分隔，转发上游前剥离）。
const HDR_CANARIES: &str = "x-shield-markers";

/// 每次请求都会构造一个 Handler 实例，持有全局状态引用。
/// HttpHandler 要求 Clone + Send + 'static；成员均为 Arc，直接 derive Clone。
#[derive(Clone)]
pub struct AiGuardHandler {
    pub state: Arc<AppState>,
}

#[async_trait::async_trait]
impl HttpHandler for AiGuardHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        self.process_request(ctx, req).await
    }

    /// CONNECT 隧道分流：**只对接管域名做 TLS 拦截**（MITM 需要客户端信任本地 CA），
    /// 其余域名直接透传隧道——客户端与真实服务器直接握手，不需要信任本地 CA。
    /// 之前默认全量拦截，导致非守护域名（如客户端自身的登录服务）连带 TLS 失败。
    async fn should_intercept(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        let host = req
            .uri()
            .host()
            .map(|h| h.to_string())
            .or_else(|| req.uri().authority().map(|a| a.to_string()))
            .unwrap_or_default();
        if host.is_empty() {
            return false;
        }
        self.state.is_ai_host(&host)
    }

    async fn handle_response(&mut self, ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        self.process_response(ctx, res).await
    }
}

impl AiGuardHandler {
    /// 请求方向处理（hudsucker 回调入口）。
    async fn process_request(&self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        self.dispatch_request(ctx.client_addr, req).await
    }

    /// 请求方向处理（真正实现）。
    ///
    /// 只依赖 `client_addr`（而非 `HttpContext`——它在 hudsucker 里是
    /// `#[non_exhaustive]`，本 crate 无法构造），因此单测可直接喂地址与请求，
    /// 覆盖「请求体必须原样转发」这类回归。
    async fn dispatch_request(
        &self,
        client_addr: SocketAddr,
        req: Request<Body>,
    ) -> RequestOrResponse {
        // ① 来源强制 loopback：代理只服务本机。监听地址本来就是 127.0.0.1，
        //    这里是**纵深防御**——一旦将来被改成 0.0.0.0、或被端口转发/隧道触达，
        //    也不会变成一个对局域网开放的 MITM 代理。
        if !client_addr.ip().is_loopback() {
            log::warn!("拒绝非本机来源的代理连接: {}", client_addr);
            return RequestOrResponse::Response(deny_response(
                403,
                "loopback_only",
                "AI Safety Guard: this local proxy only accepts loopback (127.0.0.1) connections.",
                false,
            ));
        }

        // ② 可选令牌校验（默认关闭）：仅对**代理级**请求要求凭据——CONNECT 隧道
        //    与 absolute-form 请求；MITM 之后的 origin-form 请求不再要求
        //    （隧道建立时已认证，浏览器不会在隧道内重发代理凭据）。
        let access = self.access_snapshot();
        if access.require_token {
            let proxy_level = req.method() == Method::CONNECT || req.uri().host().is_some();
            if proxy_level && !proxy_authorized(&req, &access) {
                log::warn!(
                    "代理令牌校验失败，已拒绝: {} {}",
                    req.method(),
                    req.uri().path()
                );
                return RequestOrResponse::Response(deny_response(
                    407,
                    "proxy_auth_required",
                    "AI Safety Guard: a valid Proxy-Authorization (Basic) token is required.",
                    true,
                ));
            }
        }

        let host = req
            .uri()
            .host()
            .map(|h| h.to_string())
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(|h| h.to_string())
            })
            .unwrap_or_default();

        // 非 AI 域名：直通，不做任何处理
        if !self.state.is_ai_host(&host) {
            return RequestOrResponse::Request(req);
        }

        // 后缀命中的动态子域（上传/CDN 等，如 hf-xxxx.deepseek.com）：
        // 纳入守护路由，但**完全透传**——multipart/base64 内容不适用脱敏替换，
        // 做内容扫描反而会破坏文件与上传流程。
        if !self.state.is_ai_host_exact(&host) {
            let path = req.uri().path().to_string();
            self.log_passthrough(&host, &path, client_addr);
            return RequestOrResponse::Request(req);
        }

        // 黑名单评估（优先级最高）：返回命中条目的动作（"block" | "mask"）
        let blacklist_action = self.evaluate_blacklist(client_addr, &host);
        if blacklist_action.as_deref() == Some("block") {
            let path = req.uri().path().to_string();
            self.log_request(&host, &path, "", &["BLACKLIST".to_string()], "block", "", true, "");
            self.emit("", &["BLACKLIST".to_string()], &host, "block");
            let resp = Response::builder()
                .status(403)
                .header("content-type", "application/json; charset=utf-8")
                .body(Body::from(
                    br#"{"error":{"code":"blacklisted_blocked","message":"AI Safety Guard: the request target is on the user's block list and was blocked without forwarding."}}"#.to_vec(),
                ))
                .unwrap_or_else(|_| Response::new(Body::from(Vec::new())));
            return RequestOrResponse::Response(resp);
        }

        // 白名单评估：黑名单命中（脱敏动作）时无视白名单（黑名单优先级更高）；
        // 命中 → 不执行拦截（Block 规则降级为脱敏）；
        // 若命中条目全部 scrub = false → 完全直通（不脱敏、不拦截）
        let (whitelisted, scrub_allowed) = if blacklist_action.is_some() {
            (false, true)
        } else {
            self.evaluate_whitelist(client_addr, &host)
        };
        if whitelisted && !scrub_allowed {
            let path = req.uri().path().to_string();
            // 完全直通 ≠ 放任凭据外发：B 路扫描（凭据值精确匹配，正文不改写）
            return self.bypass_passthrough_scan(req, &host, &path, client_addr).await;
        }
        // 名单对拦截动作的影响：黑名单（脱敏动作）或白名单（仍脱敏）命中时，
        // Block 规则降级为脱敏（不返回 403，仅替换占位符）
        let force_mask = blacklist_action.is_some() || (whitelisted && scrub_allowed);

        // 标记该连接承载了受守护流量：响应侧据此决定是否走还原+采集
        let addr_key = client_addr.to_string();
        self.state.mark_guarded(&addr_key);

        // 进程审计：记下是哪个可执行文件在用本代理（首次见到才记一条）
        self.audit_client_process(client_addr);

        // 核查内部头：注册 + 记录，然后**剥离**（绝不转发上游）
        let mut probe_id = String::new();
        let mut markers: Vec<String> = Vec::new();
        if let Some(v) = req.headers().get(HDR_PROBE_ID).and_then(|v| v.to_str().ok()) {
            probe_id = v.trim().to_string();
        }
        if let Some(v) = req.headers().get(HDR_CANARIES).and_then(|v| v.to_str().ok()) {
            markers = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !markers.is_empty() {
                self.state.register_markers(&markers);
            }
        }

        // 只处理 JSON 请求体
        let req_ct = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let is_json = req_ct.contains("application/json");
        let method = req.method().to_string();

        // 会话对齐所需的头信息（必须在 into_parts 之前取出）
        let mut hdrs: Vec<(String, String)> = Vec::new();
        for name in [
            "authorization",
            "x-session-id",
            "x-conversation-id",
            "openai-conversation-id",
        ] {
            if let Some(v) = req.headers().get(name).and_then(|v| v.to_str().ok()) {
                hdrs.push((name.to_string(), v.to_string()));
            }
        }

        let (mut parts, body) = req.into_parts();

        if !is_json {
            // ⚠ 非 JSON 请求（GET 空体 / multipart 文件上传 / 表单 / 二进制）：
            // **原始 body 必须原样透传**。曾经这里把 body 换成了空 Body，而浏览器
            // 声明的 Content-Length 仍是原始长度 → 上游永远等不到那批字节，
            // 网页端文件上传卡死在"上传中…"（实测 chat.deepseek.com 的
            // POST /api/v0/file/upload_file，multipart/form-data）。
            let path = parts.uri.path().to_string();
            log::info!(
                "请求透传（非 JSON 请求体，body 原样转发）: {} {} ct=\"{}\"",
                method,
                path,
                req_ct
            );
            parts.headers.remove(HDR_PROBE_ID);
            parts.headers.remove(HDR_CANARIES);
            let req = Request::from_parts(parts, body);
            self.log_passthrough(&host, &path, client_addr);
            return RequestOrResponse::Request(req);
        }

        let body_bytes = match to_bytes(body).await {
            Ok(b) => b,
            Err(e) => {
                // body 已被 to_bytes 消费且读取失败：无法再转发真实内容。
                // 必须去掉 content-length，否则上游仍按原长度等待字节 → 连接挂死。
                log::warn!("读取请求体失败: {}", safe_err(&e));
                parts.headers.remove("content-length");
                parts.headers.remove(HDR_PROBE_ID);
                parts.headers.remove(HDR_CANARIES);
                let req = Request::from_parts(parts, Body::from(Vec::new()));
                return RequestOrResponse::Request(req);
            }
        };
        let req_hash = state::hash_body(&body_bytes);
        let body_text = String::from_utf8_lossy(&body_bytes).to_string();

        match serde_json::from_slice::<Value>(&body_bytes) {
            Ok(mut json) => {
                // 会话 key：优先由对话/会话标识派生
                let session = state::derive_session(
                    &host,
                    |k| {
                        hdrs.iter()
                            .find(|(n, _)| n == k)
                            .map(|(_, v)| v.clone())
                    },
                    Some(&json),
                    &addr_key,
                );
                self.state.remember_session(&addr_key, &session);

                // 活跃会话元信息：域名 + 客户端进程 + 最后活动时间（界面「当前活跃会话」用）。
                // 进程解析走 30s 缓存，且此处已在 audit_client_process 里解过一次，命中缓存无额外开销。
                let client_exe = crate::process::client_exe_cached(&self.state, client_addr);
                self.state
                    .note_session_activity(&session, &host, client_exe.as_deref());

                // 请求上下文（模型偷换基准 model / 回声抑制样本 / 核查标记）
                let req_info = ReqInfo {
                    model: json
                        .get("model")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    body_text: truncate_chars(&body_text, state::REQ_ECHO_SAMPLE_MAX),
                    hash: req_hash.clone(),
                    probe_id: probe_id.clone(),
                    markers,
                };
                self.state.remember_req_info(&addr_key, req_info);

                // 递归脱敏全部 String 值
                let detector = self.state.detector_snapshot();
                let mut kinds: Vec<String> = Vec::new();
                let mut hit_count = 0usize;
                // Block 确认闸门：rule_id → (确认数, 所需次数)，达标才拦截
                let mut block_confirms: std::collections::HashMap<String, (u32, u32)> =
                    std::collections::HashMap::new();
                // 保险柜命中条目名（A 路使用提醒）与命中规则 id（反馈统计 per-rule 维度）
                let mut vault_entries: Vec<String> = Vec::new();
                let mut rule_ids: Vec<String> = Vec::new();
                scrub_json_value(
                    &mut json,
                    &detector,
                    &self.state.vault,
                    &session,
                    &mut kinds,
                    &mut block_confirms,
                    &mut hit_count,
                    force_mask,
                    &mut vault_entries,
                    &mut rule_ids,
                );
                let blocked = block_confirms
                    .values()
                    .any(|(count, need)| count >= need);

                // 黑名单脱敏动作命中：kinds 追加标记，前端可识别"黑名单命中的脱敏"
                if blacklist_action.is_some() {
                    kinds.push("BLACKLIST".to_string());
                }

                // 已建立映射 → 标记会话「在途」：长生成的耗时可能超过会话 TTL，
                // 若期间被后台清理，响应到达时查不到映射，占位符会静默漏给用户
                if hit_count > 0 {
                    self.state.vault.pin(&session);
                }

                // 工具注入：MCP / Function Calling 工具结果回传内容藏指令。
                // 在脱敏之后扫描（占位符已就位，evidence 才可安全落库）；
                // 信号开关与入库门槛由 record_findings 统一过滤。
                let inj_findings = aiguard_core::audit::scan_tool_call_injection(&json);
                if !inj_findings.is_empty() {
                    let meta = FindingMeta {
                        sid: session.clone(),
                        host: host.clone(),
                        method: String::new(),
                        path: String::new(),
                        request_hash: req_hash.clone(),
                        response_hash: String::new(),
                        probe_id: probe_id.clone(),
                    };
                    self.state.record_findings(inj_findings, &meta);
                }

                if blocked {
                    // 命中"拦截"规则：直接返回 403，不把请求发给 AI
                    self.state.vault.unpin(&session);
                    let path = parts.uri.path().to_string();
                    // Block 不算任何一路：请求未送达 AI 服务，凭据使用不计入
                    // （本分支尚未 stage，无需清理；同一连接的在途记录属于上一请求，
                    // 由其自身的响应完成点冲账）
                    self.log_request(
                        &host,
                        &path,
                        &session,
                        &kinds,
                        "block",
                        &req_hash,
                        true,
                        &rule_ids.join(","),
                    );
                    self.emit(&session, &kinds, &host, "block");
                    let resp = Response::builder()
                        .status(403)
                        .header("content-type", "application/json; charset=utf-8")
                        .body(Body::from(
                            br#"{"error":{"code":"sensitive_content_blocked","message":"AI Safety Guard: the request was blocked because it contains sensitive information protected by Block rules."}}"#.to_vec(),
                        ))
                        .unwrap_or_else(|_| Response::new(Body::from(Vec::new())));
                    return RequestOrResponse::Response(resp);
                }

                if hit_count == 0 {
                    // 无命中：原样透传（记录一条无命中日志）
                    let path = parts.uri.path().to_string();
                    let req = Request::from_parts(parts, Body::from(body_bytes.to_vec()));
                    self.log_request(&host, &path, &session, &[], "passthrough", &req_hash, false, "");
                    return RequestOrResponse::Request(req);
                }

                // A 路（脱敏放行）：命中的保险柜条目挂到连接级在途集合，
                // 响应完成时冲账进聚合器（见 `state::flush_vault_use`）
                if !vault_entries.is_empty() {
                    self.state
                        .stage_vault_use(&addr_key, state::VAULT_MASKED_PATH, vault_entries);
                }

                // 用脱敏后的 JSON 重建请求
                let new_body = serde_json::to_vec(&json).unwrap_or_else(|_| body_bytes.to_vec());
                // 诊断日志：head 为**脱敏后**的请求体（占位符形态，无原文），用于
                // 定位「模型看到占位符缺闭合/原文残留」一类替换错位问题
                let head: String = String::from_utf8_lossy(&new_body).chars().take(240).collect();
                log::info!(
                    "请求脱敏完成: session=\"{}\" kinds={:?} hits={} body_len={} head={}",
                    session, kinds, hit_count, new_body.len(), head
                );
                parts.headers.remove("content-length");
                parts.headers.remove(HDR_PROBE_ID);
                parts.headers.remove(HDR_CANARIES);
                let path = parts.uri.path().to_string();
                let req = Request::from_parts(parts, Body::from(new_body));
                self.log_request(
                    &host,
                    &path,
                    &session,
                    &kinds,
                    "mask",
                    &req_hash,
                    false,
                    &rule_ids.join(","),
                );
                self.emit(&session, &kinds, &host, "mask");
                RequestOrResponse::Request(req)
            }
            Err(_) => {
                // 解析失败：原样透传
                parts.headers.remove(HDR_PROBE_ID);
                parts.headers.remove(HDR_CANARIES);
                let path = parts.uri.path().to_string();
                let req = Request::from_parts(parts, Body::from(body_bytes.to_vec()));
                self.log_request(&host, &path, &addr_key, &[], "passthrough", &req_hash, false, "");
                RequestOrResponse::Request(req)
            }
        }
    }

    /// 黑名单评估（域名 / 进程）。命中 → 返回 Some(动作)（"block" | "mask"）。
    fn evaluate_blacklist(&self, client_addr: SocketAddr, host: &str) -> Option<String> {
        let bl = match self.state.blacklist.read() {
            Ok(b) => b.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        if bl.is_empty() {
            return None;
        }
        if let Some(e) = bl
            .iter()
            .find(|e| e.kind == state::WhitelistKind::Domain && state::domain_matches(&e.pattern, host))
        {
            return Some(e.action.clone());
        }
        if crate::process::client_in_process_blacklist(&self.state, client_addr) {
            return bl
                .iter()
                .find(|e| e.kind == state::WhitelistKind::Process)
                .map(|e| e.action.clone());
        }
        None
    }

    /// 白名单评估。返回 (是否命中白名单, 是否仍执行脱敏)。
    fn evaluate_whitelist(&self, client_addr: SocketAddr, host: &str) -> (bool, bool) {
        let wl = match self.state.whitelist.read() {
            Ok(w) => w.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        if wl.is_empty() {
            return (false, true);
        }
        let domain_hit = wl.iter().any(|e| {
            e.kind == state::WhitelistKind::Domain && state::domain_matches(&e.pattern, host)
        });
        let process_hit = crate::process::client_in_process_whitelist(&self.state, client_addr);
        if !(domain_hit || process_hit) {
            return (false, true);
        }
        let scrub = wl.iter().any(|e| {
            e.scrub
                && match e.kind {
                    state::WhitelistKind::Domain => domain_hit,
                    state::WhitelistKind::Process => process_hit,
                }
        });
        (true, scrub)
    }

    /// 响应方向处理。
    async fn process_response(&self, ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let client_addr = ctx.client_addr.to_string();
        let session = self.state.session_for_addr(&client_addr);
        let status = res.status().as_u16();
        let req_info = self.state.req_info_for(&client_addr);
        let content_type = res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        log::info!(
            "响应处理: status={} ct=\"{}\" session=\"{}\" guarded={} vault_n={} probe_id=\"{}\"",
            status,
            content_type,
            session,
            self.state.is_guarded(&client_addr),
            self.state.vault.session_count(&session),
            req_info.probe_id
        );

        // ── 报错泄密：4xx/5xx 才扫，与还原无关 ──
        if status >= 400 {
            // 错误响应同样视为「请求已完成」（正文读取 + 只读扫描后透传）：
            // 请求侧挂起的凭据使用在此冲账
            self.state.flush_vault_use(&client_addr);
            return self.scan_error_response(res, status, session, req_info).await;
        }

        let limits = self.restore_limits();
        let has_session = self.state.vault.session_count(&session) > 0;
        let guarded = self.state.is_guarded(&client_addr);

        if !has_session && !guarded {
            // 非受守护流量且本会话无映射：完全透传
            self.state.vault.unpin(&session);
            log::info!("响应透传（非受守护流量）: session=\"{}\"", session);
            // 白名单直通（B 路）流量不标记 guarded，其响应走这里——必须冲账
            self.state.flush_vault_use(&client_addr);
            return res;
        }

        // 还原管道只能处理**明文 JSON/SSE 文本**。HTML / 图片 / 字体 / JS 等静态
        // 资源、以及任何带压缩编码（gzip/br/deflate）的响应一律完全透传——
        // 管道按 UTF-8 文本处理会损坏二进制字节流（曾导致网页 HTML 被打坏无法打开）。
        let content_encoding = res
            .headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string());
        if !should_restore_response(&content_type, content_encoding.as_deref()) {
            self.state.vault.unpin(&session);
            log::info!(
                "响应透传（非文本或压缩响应）: ct=\"{}\" ce={:?}",
                content_type,
                content_encoding
            );
            // MVP 简化：这类响应在**响应头阶段**即透传、正文不进管道，无法等到
            // 正文流结束；此处视为响应完成并冲账在途凭据使用（偏差可接受：
            // 完成时刻略早于真实流结束，计数语义不变）
            self.state.flush_vault_use(&client_addr);
            return res;
        }

        let is_sse = content_type.to_ascii_lowercase().contains("text/event-stream");

        // 「响应还原」开关：关闭时管道照常处理（审计采集不受影响），
        // 但交给客户端的是**原始流**（占位符不还原）。
        let emit_restored = match self.state.config.read() {
            Ok(c) => c.restore_enabled,
            Err(poisoned) => poisoned.into_inner().restore_enabled,
        };

        if is_sse {
            self.restore_streaming(res, session, req_info, limits, emit_restored, client_addr)
                .await
        } else {
            self.restore_full(res, session, req_info, limits, emit_restored, client_addr)
                .await
        }
    }

    /// 报错泄密扫描（只读，透传原响应）。
    async fn scan_error_response(
        &self,
        res: Response<Body>,
        status: u16,
        session: String,
        req_info: ReqInfo,
    ) -> Response<Body> {
        let (parts, body) = res.into_parts();
        let headers_text = headers_text(&parts.headers);
        match to_bytes(body).await {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).to_string();
                let findings =
                    aiguard_core::audit::scan_error_leak(Some(status), &text, &headers_text);
                let response_hash = state::hash_body(&bytes);
                self.record(&findings, &session, &req_info, &response_hash);
                Response::from_parts(parts, Body::from(bytes.to_vec()))
            }
            Err(e) => {
                log::warn!("读取错误响应体失败: {}", safe_err(&e));
                Response::from_parts(parts, Body::from(Vec::new()))
            }
        }
    }

    /// SSE 流式还原 + 审计采集。
    ///
    /// `emit_restored=false`（响应还原开关关闭）时：管道照常处理（审计采集不受影响），
    /// 但交给客户端的是**还原前的原始流**（占位符保留）。
    async fn restore_streaming(
        &self,
        res: Response<Body>,
        session: String,
        req_info: ReqInfo,
        limits: RestoreLimits,
        emit_restored: bool,
        client_addr: String,
    ) -> Response<Body> {
        let (mut parts, body) = res.into_parts();
        parts.headers.remove("content-length");

        let clear_at_end = limits.clear_session_on_stream_end;
        let pipeline = ResponsePipeline::new(self.state.vault.clone(), session.clone(), &limits);
        let reassembler = Utf8Reassembler::new();
        let state = self.state.clone();

        let out_stream = futures::stream::unfold(
            (body, pipeline, reassembler, req_info, false),
            move |(mut body, mut pipeline, mut reass, req_info, done)| {
                let state = state.clone();
                let client_addr = client_addr.clone();
                async move {
                    if done {
                        return None;
                    }
                    match body.next().await {
                        Some(Ok(bytes)) => {
                            let text = reass.push(&bytes);
                            // 诊断日志（还原前）：此刻流里只有占位符形态、无原文，安全。
                            // 用于对比「模型原始输出」与「浏览器 EventStream 收到的内容」。
                            if text.contains("PII:") || text.contains("[[") {
                                log::info!(
                                    "还原前chunk: {}",
                                    truncate_chars(&text, 240)
                                );
                            }
                            if text.is_empty() {
                                return Some((
                                    Ok::<Bytes, Box<dyn std::error::Error + Send + Sync>>(
                                        Bytes::new(),
                                    ),
                                    (body, pipeline, reass, req_info, false),
                                ));
                            }
                            let out = pipeline.feed(&text);
                            // 响应还原开关关闭：交还原前文本（占位符保留），管道审计照常
                            let emit = if emit_restored { out } else { text };
                            Some((
                                Ok::<Bytes, Box<dyn std::error::Error + Send + Sync>>(Bytes::from(
                                    emit,
                                )),
                                (body, pipeline, reass, req_info, false),
                            ))
                        }
                        Some(Err(e)) => {
                            log::warn!("代理响应流错误: {}", safe_err(&e));
                            state.vault.unpin(pipeline.session());
                            // 流异常中断也视为「响应完成」：冲账在途凭据使用
                            state.flush_vault_use(&client_addr);
                            Some((
                                Err::<Bytes, Box<dyn std::error::Error + Send + Sync>>(Box::new(e)),
                                (body, pipeline, reass, req_info, true),
                            ))
                        }
                        None => {
                            let tail = reass.flush();
                            let mut final_out = pipeline.feed(&tail);
                            final_out.push_str(&pipeline.finish());
                            self_record(&state, &mut pipeline, &req_info, &final_out);
                            state.clear_session_if(pipeline.session(), clear_at_end);
                            state.vault.unpin(pipeline.session());
                            // SSE 正常结束 = 响应完成：冲账在途凭据使用（触发点）
                            state.flush_vault_use(&client_addr);
                            // 还原关闭时收尾补发也不下发（还原文本已进审计，不再给客户端）
                            let emit = if emit_restored {
                                final_out
                            } else if tail.is_empty() {
                                String::new()
                            } else {
                                tail
                            };
                            if emit.is_empty() {
                                None
                            } else {
                                Some((
                                    Ok::<Bytes, Box<dyn std::error::Error + Send + Sync>>(
                                        Bytes::from(emit),
                                    ),
                                    (body, pipeline, reass, req_info, true),
                                ))
                            }
                        }
                    }
                }
            },
        );

        let new_body = Body::wrap_stream(out_stream);
        Response::from_parts(parts, new_body)
    }

    /// 非 SSE 响应：collect 后整段还原 + 审计采集。
    ///
    /// `emit_restored=false`（响应还原开关关闭）时：管道照常处理（审计采集不受影响），
    /// 但交给客户端的是**原始文本**（占位符保留）。
    async fn restore_full(
        &self,
        res: Response<Body>,
        session: String,
        req_info: ReqInfo,
        limits: RestoreLimits,
        emit_restored: bool,
        client_addr: String,
    ) -> Response<Body> {
        let (mut parts, body) = res.into_parts();
        let clear_at_end = limits.clear_session_on_stream_end;
        match to_bytes(body).await {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).to_string();
                let mut pipeline =
                    ResponsePipeline::raw(self.state.vault.clone(), session.clone(), &limits);
                let mut out = pipeline.feed(&text);
                out.push_str(&pipeline.finish());
                self_record(&self.state, &mut pipeline, &req_info, &out);
                self.state.clear_session_if(pipeline.session(), clear_at_end);
                self.state.vault.unpin(pipeline.session());
                // 整段响应完成：冲账在途凭据使用（触发点）
                self.state.flush_vault_use(&client_addr);
                parts.headers.remove("content-length");
                let emit = if emit_restored { out } else { text };
                Response::from_parts(parts, Body::from(emit.into_bytes()))
            }
            Err(e) => {
                log::warn!("读取响应体失败: {}", safe_err(&e));
                self.state.vault.unpin(&session);
                // 读取失败同样按「响应已结束」冲账，避免在途记录滞留到 TTL
                self.state.flush_vault_use(&client_addr);
                Response::from_parts(parts, Body::from(Vec::new()))
            }
        }
    }

    /// 把还原管道采集的上下文交给各防护信号检测，发现落库。
    ///
    /// **只告警**：这里只做记录，发给客户端的内容不被修改。
    fn record(
        &self,
        findings: &[aiguard_core::audit::Finding],
        session: &str,
        req_info: &ReqInfo,
        response_hash: &str,
    ) {
        if findings.is_empty() {
            return;
        }
        let meta = FindingMeta {
            sid: session.to_string(),
            host: host_of_session(session),
            method: String::new(),
            path: String::new(),
            request_hash: req_info.hash.clone(),
            response_hash: response_hash.to_string(),
            probe_id: req_info.probe_id.clone(),
        };
        self.state.record_findings(findings.to_vec(), &meta);
    }

    /// 记录请求日志（不落原文）。
    ///
    /// `rule_id`：命中规则 id 的逗号连接串（反馈统计 per-rule 维度用；未命中传空串）。
    fn log_request(
        &self,
        host: &str,
        path: &str,
        session: &str,
        kinds: &[String],
        action: &str,
        req_hash: &str,
        blocked: bool,
        rule_id: &str,
    ) {
        let ts = now_ts();
        let kinds_json = serde_json::to_string(kinds).unwrap_or_else(|_| "[]".to_string());
        if let Err(e) = self.state.store.log_request(
            &ts, host, path, session, &kinds_json, action, req_hash, blocked, rule_id,
        ) {
            log::warn!("写日志失败: {}", safe_err(&e));
        }
    }

    /// 直通流量记一条无命中日志。
    fn log_passthrough(&self, host: &str, path: &str, client_addr: SocketAddr) {
        let session = self.state.session_for_addr(&client_addr.to_string());
        self.log_request(host, path, &session, &[], "passthrough", "", false, "");
    }

    /// 白名单完全直通路径（不脱敏、不拦截）的**凭据值精确扫描**（B 路）。
    ///
    /// 直通意味着请求正文**原样出网**——若正文里含保险柜凭据值，即「凭据已外发」，
    /// 需要最高优先级的轮换提醒。这里对请求体做一次逐条目 `contains` 精确匹配
    /// （不解析 JSON、不改写正文），命中条目名挂到连接级在途集合，响应完成时
    /// 冲账（见 [`AppState::flush_vault_use`]）。隐私：只记条目名，绝不含凭据值。
    ///
    /// 体量保护（两级）：
    /// - **缓冲上限 32MiB**：`content-length` 超限的请求不缓冲、不扫描、原样直通；
    ///   长度缺失或谎报（chunked / 声明小实际大）时用有界收集兜底，超限回 413
    ///   拒绝——绝不无上界缓冲客户端请求体；
    /// - **扫描上限 1MiB**：更大正文只缓冲转发、不扫描（逐条目 `contains` 的
    ///   成本 = 条目数 × 正文长，MiB 级正文 × ≤200 条会阻塞直通路径）；
    ///   AI 对话载荷是 KB 量级，此上限对真实流量无感。
    async fn bypass_passthrough_scan(
        &self,
        req: Request<Body>,
        host: &str,
        path: &str,
        client_addr: SocketAddr,
    ) -> RequestOrResponse {
        const BYPASS_BODY_CAP: usize = 32 * 1024 * 1024;
        const BYPASS_SCAN_CAP: usize = 1024 * 1024;
        let declared = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if declared.map(|len| len > BYPASS_BODY_CAP as u64).unwrap_or(false) {
            self.log_passthrough(host, path, client_addr);
            return RequestOrResponse::Request(req);
        }
        let (mut parts, body) = req.into_parts();
        match collect_body_capped(body, BYPASS_BODY_CAP).await {
            CollectedBody::Complete(bytes) => {
                if bytes.len() <= BYPASS_SCAN_CAP {
                    // lossy UTF-8：凭据值由用户录入（必然是 UTF-8 文本），二进制噪声
                    // 不会命中；bytes 仍按原样转发，不影响任何字节
                    let text = String::from_utf8_lossy(&bytes);
                    let detector = self.state.detector_snapshot();
                    let entries = detector.scan_locker_names(&text);
                    if !entries.is_empty() {
                        self.state.stage_vault_use(
                            &client_addr.to_string(),
                            state::VAULT_PLAINTEXT_PATH,
                            entries,
                        );
                    }
                } else {
                    // 超扫描上限：只转发不扫描（凭据提醒对此请求不生效）
                    log::debug!(
                        "直通请求体 {} 字节超扫描上限，跳过凭据扫描",
                        bytes.len()
                    );
                }
                self.log_passthrough(host, path, client_addr);
                RequestOrResponse::Request(Request::from_parts(
                    parts,
                    Body::from(bytes),
                ))
            }
            CollectedBody::TooLarge => {
                // 长度谎报 / chunked 超限：正文已被消费且无法重组，只能拒绝。
                // 拒绝理由不携带任何请求细节（隐私红线）。
                log::warn!("直通请求体超缓冲上限（长度缺失或谎报），已拒绝");
                RequestOrResponse::Response(deny_response(
                    413,
                    "payload_too_large",
                    "request body too large",
                    false,
                ))
            }
            CollectedBody::Failed(e) => {
                // body 已被消费且读取失败：与主链路同策略——去 content-length 后转发空体
                log::warn!("直通路径读取请求体失败: {}", safe_err(&e));
                parts.headers.remove("content-length");
                self.log_passthrough(host, path, client_addr);
                RequestOrResponse::Request(Request::from_parts(parts, Body::from(Vec::new())))
            }
        }
    }

    /// emit 命中事件给前端（请求侧 PII 主链路）。
    fn emit(&self, session: &str, kinds: &[String], host: &str, action: &str) {
        for kind in kinds {
            self.state.emit_event(
                "pii-detected",
                PiiEvent {
                    session: session.to_string(),
                    kind: kind.clone(),
                    host: host.to_string(),
                    action: action.to_string(),
                    ts: now_ts(),
                },
            );
        }
    }

    fn restore_limits(&self) -> RestoreLimits {
        match self.state.restore_limits.read() {
            Ok(l) => l.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 本地代理访问控制快照（loopback 强制 / 可选令牌）。
    fn access_snapshot(&self) -> state::AccessControl {
        match self.state.access.read() {
            Ok(a) => a.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 代理客户端进程审计：记录并首次上报是哪个程序在用代理。
    /// 解析失败（权限不足/非 Windows）时静默跳过——审计不参与放行判定。
    fn audit_client_process(&self, client_addr: SocketAddr) {
        let exe = crate::process::client_exe_cached(&self.state, client_addr);
        if let Some(exe) = exe {
            if self.state.note_client_process(exe.clone()) {
                log::info!("代理客户端进程（首次出现）: {}", exe);
            }
        }
    }
}

/// 有界请求体收集结果（零新依赖：`Body` 本身是 `Stream`，用已引入的
/// `futures::StreamExt` 逐块累加，累计长度超过 `cap` 立即停手）。
enum CollectedBody {
    /// 未超限，完整正文
    Complete(Vec<u8>),
    /// 超过缓冲上限（正文已被消费，调用方只能拒绝，不能重组转发）
    TooLarge,
    /// 读取失败（与 `to_bytes` 的错误语义一致）
    Failed(hudsucker::hyper::Error),
}

/// 有上界地收集体正文：防「无 content-length 的 chunked 巨体」或
/// 「谎报小长度实际巨大」的请求把内存打满。
async fn collect_body_capped(body: Body, cap: usize) -> CollectedBody {
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = body;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                if buf.len() + bytes.len() > cap {
                    return CollectedBody::TooLarge;
                }
                buf.extend_from_slice(&bytes);
            }
            Err(e) => return CollectedBody::Failed(e),
        }
    }
    CollectedBody::Complete(buf)
}

/// 本地代理拒绝响应（访问控制用）：不转发上游、不含任何原文。
fn deny_response(status: u16, code: &str, message: &str, challenge: bool) -> Response<Body> {
    let body = serde_json::json!({ "error": { "code": code, "message": message } }).to_string();
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8");
    if challenge {
        builder = builder.header("proxy-authenticate", "Basic realm=\"AI Safety Guard\"");
    }
    builder
        .body(Body::from(body.into_bytes()))
        .unwrap_or_else(|_| Response::new(Body::from(Vec::new())))
}

/// 校验 `Proxy-Authorization: Basic <base64(用户:口令)>` 中的口令是否为当前令牌。
///
/// 用户名随意（`curl -U :<token>` 亦可）；比较用恒定时间实现。
fn proxy_authorized(req: &Request<Body>, access: &state::AccessControl) -> bool {
    use base64::Engine as _;
    if !access.has_token() {
        return false;
    }
    let raw = match req
        .headers()
        .get("proxy-authorization")
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v.trim(),
        None => return false,
    };
    let b64 = match raw
        .strip_prefix("Basic ")
        .or_else(|| raw.strip_prefix("basic "))
    {
        Some(v) => v.trim(),
        None => return false,
    };
    let decoded = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let text = match String::from_utf8(decoded) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let candidate = text.split_once(':').map(|(_, p)| p).unwrap_or(text.as_str());
    access.token_matches(candidate)
}

/// 从会话 key 中提取 host 段（`conv:host:rest` / `hdr:host:x` / `key:host:h` / 原样）。
fn host_of_session(session: &str) -> String {
    session
        .split_once(':')
        .and_then(|(_, rest)| rest.split(':').next())
        .unwrap_or(session)
        .to_string()
}

/// 序列化响应头为文本（报错泄密扫描输入；上限见 `audit::HEADERS_SCAN_MAX`）。
fn headers_text(headers: &hudsucker::hyper::HeaderMap) -> String {
    let mut out = String::new();
    for (name, value) in headers.iter() {
        if out.len() > aiguard_core::audit::HEADERS_SCAN_MAX {
            break;
        }
        let v = String::from_utf8_lossy(value.as_bytes());
        out.push_str(&format!("{}: {}\n", name, v));
    }
    out
}

/// 收集还原管道的审计上下文并落库（流式 / 整段共用）。
fn self_record(
    state: &Arc<AppState>,
    pipeline: &mut ResponsePipeline,
    req_info: &ReqInfo,
    out_text: &str,
) {
    let ctx = pipeline.take_context();
    let response_hash = state::hash_body(out_text.as_bytes());
    // 还原统计诊断（info 级，仅受守护流量打印；定位"响应未还原"类问题用）
    log::info!(
        "还原统计: sid=\"{}\" restored={} unresolved={} degraded={} overflow={} collected_len={}",
        pipeline.session(),
        ctx.restored,
        ctx.unresolved,
        ctx.degraded,
        ctx.overflowed,
        ctx.restored_text.len()
    );
    let mut findings: Vec<aiguard_core::audit::Finding> = Vec::new();

    // 模型偷换（请求 model vs 响应 model）
    findings.extend(aiguard_core::audit::scan_identity_swap(
        req_info.model.as_deref(),
        ctx.response_model.as_deref(),
    ));
    // 流式异常
    findings.extend(aiguard_core::audit::scan_sse_anomaly(&ctx.sse_events));
    // 响应夹带（还原后文本 + 请求回声抑制）
    findings.extend(aiguard_core::audit::scan_response_poison(
        &ctx.restored_text,
        Some(&req_info.body_text),
    ));
    // 记忆残留（prior nonce 排除本次请求自己注册的）
    let prior = state.prior_markers(&req_info.markers);
    if !prior.is_empty() {
        let prior_list: Vec<String> = prior.into_iter().collect();
        findings.extend(aiguard_core::audit::scan_cross_request_pollution(
            &ctx.restored_text,
            &prior_list,
        ));
    }
    // 高危指令（还原后文本；工具参数也在其中）
    findings.extend(aiguard_core::audit::scan_dangerous_action(
        &ctx.restored_text,
        Some(&req_info.body_text),
    ));
    // 保险柜访问（模型命令指向保护对象 / 点名键名 / 引用受保护路径；只告警不改写）
    findings.extend(aiguard_core::audit::scan_locker_access(
        &ctx.restored_text,
        &state.locker_keys(),
        &state.locker_paths(),
    ));

    if findings.is_empty() {
        return;
    }
    let meta = FindingMeta {
        sid: pipeline.session().to_string(),
        host: host_of_session(pipeline.session()),
        method: String::new(),
        path: String::new(),
        request_hash: req_info.hash.clone(),
        response_hash,
        probe_id: req_info.probe_id.clone(),
    };
    state.record_findings(findings, &meta);
}

/// 判断响应是否应进入还原管道：仅「明文的 JSON/SSE/ndjson/plain 文本」；
/// 其余（HTML / 图片 / 二进制 / 任何压缩编码）完全透传。
/// SSE 未压缩时恒真；压缩响应一律透传（本管道不做解压还原）。
fn should_restore_response(content_type: &str, content_encoding: Option<&str>) -> bool {
    let compressed = match content_encoding {
        None => false,
        Some(ce) => {
            let c = ce.trim();
            !c.is_empty() && !c.eq_ignore_ascii_case("identity")
        }
    };
    if compressed {
        return false;
    }
    let ct = content_type.to_ascii_lowercase();
    ct.contains("application/json")
        || ct.contains("text/event-stream")
        || ct.contains("application/x-ndjson")
        || ct.contains("text/plain")
}

/// 按 char 边界截断字符串。
fn truncate_chars(s: &str, max_bytes: usize) -> String {    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max_bytes / 4).collect();
    while !t.is_empty() && !t.is_char_boundary(t.len()) {
        t.pop();
    }
    t
}

/// 递归脱敏 JSON 中所有 String 值。
/// `force_mask = true` 时 Block 规则命中也只脱敏不拦截（黑名单脱敏动作 / 白名单仍脱敏）。
///
/// Block 确认闸门：Block 只对达到确认次数的规则生效（`block_confirms` 按 rule_id 聚合
/// 确认数与所需次数；校验器类规则运行时下限 2，见 `compile_rule`）；未达标命中照常
/// 脱敏不拦截。黑名单 / 保险柜 Block 不经此闸（用户显式意图，零误报）。
///
/// 输出参数：
/// - `vault_entries`：命中的保险柜条目键名（去重，A 路使用提醒用）；
/// - `rule_ids`：命中的规则 id（去重，反馈统计 per-rule 维度落库用）。
fn scrub_json_value(
    value: &mut Value,
    detector: &Detector,
    vault: &Vault,
    session: &str,
    kinds: &mut Vec<String>,
    block_confirms: &mut std::collections::HashMap<String, (u32, u32)>,
    hit_count: &mut usize,
    force_mask: bool,
    vault_entries: &mut Vec<String>,
    rule_ids: &mut Vec<String>,
) {
    match value {
        Value::String(s) => {
            let (scrubbed, hits) =
                detector.scrub(s, |orig, tag| vault.get_or_create(session, orig, tag));
            if !hits.is_empty() {
                for h in &hits {
                    kinds.push(h.tag.clone());
                    // 保险柜命中：条目名进 A 路清单（隐私红线：只记键名，绝不含凭据值）
                    if let Some(name) = &h.locker_entry {
                        if !vault_entries.contains(name) {
                            vault_entries.push(name.clone());
                        }
                    }
                    // 规则 id（保险柜命中 rule_id="locker"，不计入规则统计维度）
                    if !h.rule_id.is_empty() && h.rule_id != "locker" && !rule_ids.contains(&h.rule_id) {
                        rule_ids.push(h.rule_id.clone());
                    }
                    if h.action == Action::Block && !force_mask {
                        // 按规则聚合确认数：达到所需次数才允许拦截
                        let e = block_confirms
                            .entry(h.rule_id.clone())
                            .or_insert((0, (h.min_confirm as u32).max(1)));
                        e.0 += 1;
                        e.1 = e.1.max(h.min_confirm as u32);
                    }
                }
                *hit_count += hits.len();
                *value = Value::String(scrubbed);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                scrub_json_value(v, detector, vault, session, kinds, block_confirms, hit_count, force_mask, vault_entries, rule_ids);
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                scrub_json_value(v, detector, vault, session, kinds, block_confirms, hit_count, force_mask, vault_entries, rule_ids);
            }
        }
        _ => {}
    }
}

/// 增量 UTF-8 解码器：中文等多字节字符可能被 TCP 拆到不同 chunk。
pub struct Utf8Reassembler {
    pending: Vec<u8>,
}

impl Utf8Reassembler {
    pub fn new() -> Utf8Reassembler {
        Utf8Reassembler { pending: Vec::new() }
    }

    pub fn push(&mut self, data: &[u8]) -> String {
        self.pending.extend_from_slice(data);
        let mut out = String::new();
        loop {
            match std::str::from_utf8(&self.pending) {
                Ok(s) => {
                    out.push_str(s);
                    self.pending.clear();
                    break;
                }
                Err(e) => {
                    let valid = e.valid_up_to();
                    if valid > 0 {
                        if let Ok(prefix) = std::str::from_utf8(&self.pending[..valid]) {
                            out.push_str(prefix);
                        }
                        self.pending.drain(..valid);
                    }
                    match e.error_len() {
                        None => break,
                        Some(_) => {
                            self.pending.remove(0);
                        }
                    }
                }
            }
        }
        out
    }

    pub fn flush(&mut self) -> String {
        let rest = String::from_utf8_lossy(&self.pending).to_string();
        self.pending.clear();
        rest
    }
}

impl Default for Utf8Reassembler {
    fn default() -> Self {
        Utf8Reassembler::new()
    }
}

/// 当前时间戳（Unix 秒）。
pub fn now_ts() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

#[cfg(test)]
mod response_gate_tests {
    use super::should_restore_response;

    #[test]
    fn test_restore_only_for_plain_text_json() {
        // 明文 JSON / SSE / ndjson / plain：还原
        assert!(should_restore_response("application/json", None));
        assert!(should_restore_response("text/event-stream;charset=UTF-8", None));
        assert!(should_restore_response("application/x-ndjson", None));
        assert!(should_restore_response("text/plain", None));
        // identity 编码等同未压缩
        assert!(should_restore_response("application/json", Some("identity")));
        // 压缩响应一律透传（管道不做解压还原）
        assert!(!should_restore_response("application/json", Some("gzip")));
        assert!(!should_restore_response("text/event-stream", Some("br")));
        assert!(!should_restore_response("application/json", Some("deflate")));
        // HTML / 图片 / 二进制：透传
        assert!(!should_restore_response("text/html; charset=utf-8", None));
        assert!(!should_restore_response("image/png", None));
        assert!(!should_restore_response("application/octet-stream", None));
        assert!(!should_restore_response("", None));
    }
}

#[cfg(test)]
mod request_body_tests {
    use super::*;
    use crate::store::Store;
    use hudsucker::hyper::body::to_bytes;

    /// 临时目录 + 默认内置规则的 AppState（与运行时一致的构造路径）。
    fn test_state() -> Arc<AppState> {
        let dir = std::env::temp_dir().join(format!("aiguard_proxy_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let store = Store::open(&db).unwrap();
        Arc::new(AppState::new(store, &db, dir))
    }

    /// 回归守护：multipart 文件上传的请求体必须**逐字节原样转发**。
    ///
    /// 曾经这里把 body 换成了空 Body，而浏览器声明的 `Content-Length` 仍是原始
    /// 长度 → 上游永远等不到那批字节，网页端文件上传卡死在「上传中…」
    /// （实测 chat.deepseek.com 的 `POST /api/v0/file/upload_file`）。
    #[tokio::test]
    async fn test_multipart_upload_body_forwarded_unchanged() {
        let handler = AiGuardHandler { state: test_state() };
        let addr: SocketAddr = "127.0.0.1:51001".parse().unwrap();

        let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"README.md\"\r\nContent-Type: text/markdown\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(b"# demo\r\n");
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let req = Request::builder()
            .method("POST")
            .uri("https://chat.deepseek.com/api/v0/file/upload_file")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header("content-length", body.len().to_string())
            .body(Body::from(body.clone()))
            .unwrap();

        let out = match handler.dispatch_request(addr, req).await {
            RequestOrResponse::Request(r) => r,
            RequestOrResponse::Response(_) => panic!("上传请求不应被拦截/改写为响应"),
        };
        let expected_len = body.len().to_string();
        let actual_len = out
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok());
        assert_eq!(
            actual_len,
            Some(expected_len.as_str()),
            "Content-Length 必须与原始请求体一致，否则上游会挂住等字节"
        );
        let got = to_bytes(out.into_body()).await.unwrap();
        assert_eq!(
            got.as_ref(),
            body.as_slice(),
            "multipart 请求体必须原样透传（含 boundary、CRLF、二进制字节）"
        );
    }

    /// 对照守护：JSON 请求体仍走脱敏主链路（修复不得把 JSON 也放行成透传）。
    #[tokio::test]
    async fn test_json_request_body_still_scrubbed() {
        let handler = AiGuardHandler { state: test_state() };
        let addr: SocketAddr = "127.0.0.1:51002".parse().unwrap();

        let payload = r#"{"model":"deepseek-chat","messages":[{"role":"user","content":"我的手机号是13800138000"}]}"#;
        let req = Request::builder()
            .method("POST")
            .uri("https://chat.deepseek.com/api/v0/chat/completion")
            .header("content-type", "application/json")
            .body(Body::from(payload.as_bytes().to_vec()))
            .unwrap();

        let out = match handler.dispatch_request(addr, req).await {
            RequestOrResponse::Request(r) => r,
            RequestOrResponse::Response(_) => panic!("内置规则动作是脱敏，不应返回 403"),
        };
        let got = to_bytes(out.into_body()).await.unwrap();
        let text = String::from_utf8_lossy(&got).to_string();
        assert!(
            text.contains("[[PII:PHONE:"),
            "JSON 请求体应被占位符脱敏，实际: {}",
            text
        );
        assert!(
            !text.contains("13800138000"),
            "原文不得残留，实际: {}",
            text
        );
    }

    /// 访问控制①：非本机回环来源的代理连接一律 403，绝不进入脱敏/转发链路。
    #[tokio::test]
    async fn test_non_loopback_client_rejected() {
        let handler = AiGuardHandler { state: test_state() };
        // 邻居网段地址（不是 127.0.0.1/::1）
        let addr: SocketAddr = "192.168.1.9:51003".parse().unwrap();
        let req = Request::builder()
            .method("GET")
            .uri("http://chat.deepseek.com/v1/models")
            .body(Body::from(Vec::new()))
            .unwrap();
        match handler.dispatch_request(addr, req).await {
            RequestOrResponse::Response(res) => {
                assert_eq!(res.status().as_u16(), 403, "非本机来源必须被拒绝");
            }
            RequestOrResponse::Request(_) => panic!("非本机来源不得放行"),
        }
    }

    /// 访问控制②：开启令牌后，代理级请求缺凭据 → 407 且带 challenge；带正确令牌 → 放行。
    #[tokio::test]
    async fn test_proxy_token_gate() {
        let state = test_state();
        {
            let mut a = state.access.write().unwrap();
            a.require_token = true;
        }
        let handler = AiGuardHandler { state: state.clone() };
        let addr: SocketAddr = "127.0.0.1:51004".parse().unwrap();

        // ① 无凭据 → 407 + Proxy-Authenticate
        let req = Request::builder()
            .method("GET")
            .uri("http://chat.deepseek.com/v1/models")
            .body(Body::from(Vec::new()))
            .unwrap();
        match handler.dispatch_request(addr, req).await {
            RequestOrResponse::Response(res) => {
                assert_eq!(res.status().as_u16(), 407);
                assert!(
                    res.headers().get("proxy-authenticate").is_some(),
                    "407 必须带 Proxy-Authenticate challenge"
                );
            }
            RequestOrResponse::Request(_) => panic!("缺凭据不得放行"),
        }

        // ② 错误令牌 → 仍 407
        let bad = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode("x:wrong-token-value")
        };
        let req = Request::builder()
            .method("GET")
            .uri("http://chat.deepseek.com/v1/models")
            .header("proxy-authorization", format!("Basic {}", bad))
            .body(Body::from(Vec::new()))
            .unwrap();
        match handler.dispatch_request(addr, req).await {
            RequestOrResponse::Response(res) => assert_eq!(res.status().as_u16(), 407),
            RequestOrResponse::Request(_) => panic!("错误令牌不得放行"),
        }

        // ③ 正确令牌 → 通过校验（非 AI 域名的代理级请求继续按常规链路处理）
        let token = state.access.read().unwrap().token.clone();
        let good = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(format!("x:{}", token))
        };
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/health")
            .header("proxy-authorization", format!("Basic {}", good))
            .body(Body::from(Vec::new()))
            .unwrap();
        match handler.dispatch_request(addr, req).await {
            RequestOrResponse::Request(_) => {}
            RequestOrResponse::Response(res) => {
                panic!("正确令牌不应被拒，实际状态 {}", res.status())
            }
        }
    }

    /// 进程审计去重：同一 exe 只有首次返回 true。
    #[test]
    fn test_note_client_process_dedupes() {
        let state = test_state();
        assert!(state.note_client_process("C:\\Tools\\curl.exe".to_string()));
        assert!(!state.note_client_process("C:\\Tools\\curl.exe".to_string()));
        assert!(!state.note_client_process("   ".to_string()));
        assert_eq!(state.client_processes().len(), 1);
    }

    /// 白名单完全直通路径（B 路）的凭据值扫描：正文不改写、原样转发，
    /// 但命中的保险柜条目名必须挂进在途集合，冲账后进入聚合器。
    #[tokio::test]
    async fn test_whitelist_bypass_scans_vault_entries() {
        let state = test_state();
        // 录入一条凭据值条目（值避开内置正则形态）
        let mut cfg = aiguard_core::locker::LockerConfig::default();
        cfg.entries.push(aiguard_core::locker::LockerEntry {
            name: "GH_TOKEN".to_string(),
            value: "ghp-vault-test-1234567890".to_string(),
            action: "mask".to_string(),
            enabled: true,
            kind: "value".to_string(),
        });
        cfg.sanitize();
        let specs = aiguard_core::detector::default_rule_specs();
        let detector = Detector::from_specs(&specs)
            .unwrap()
            .with_locker(&cfg);
        *state.detector.write().unwrap() = std::sync::Arc::new(detector);
        *state.locker.write().unwrap() = cfg.clone();
        // 白名单：域名完全直通（scrub = false）
        *state.whitelist.write().unwrap() = vec![state::WhitelistEntry {
            id: "wl-test".to_string(),
            kind: state::WhitelistKind::Domain,
            pattern: "chat.deepseek.com".to_string(),
            scrub: false,
        }];

        let handler = AiGuardHandler { state: state.clone() };
        let addr: SocketAddr = "127.0.0.1:51005".parse().unwrap();
        let payload = r#"{"q":"use ghp-vault-test-1234567890 directly"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("https://chat.deepseek.com/api/chat")
            .header("content-type", "application/json")
            .body(Body::from(payload.as_bytes().to_vec()))
            .unwrap();

        // 完全直通：请求必须原样返回（不脱敏、不拦截）
        let out = match handler.dispatch_request(addr, req).await {
            RequestOrResponse::Request(r) => r,
            RequestOrResponse::Response(res) => {
                panic!("白名单直通不应拦截，实际状态 {}", res.status())
            }
        };
        let got = to_bytes(out.into_body()).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&got).as_ref(),
            payload,
            "直通路径正文必须逐字节原样转发"
        );

        // 冲账 → 聚合器必须收到 B 路命中（条目名，而非凭据值）
        state.flush_vault_use(&addr.to_string());
        let masked = state.vault_notice_debug_state(state::VAULT_MASKED_PATH);
        let plain = state.vault_notice_debug_state(state::VAULT_PLAINTEXT_PATH);
        assert!(masked.is_empty(), "脱敏路径不应有记录");
        assert_eq!(plain, vec!["GH_TOKEN".to_string()], "B 路必须记录命中条目名");
    }

    /// B 路体量保护：声明 content-length 超 32MiB 的请求必须不缓冲、不扫描、原样直通。
    ///
    /// 正文实际很小且**含凭据值**——若超限判断失效（如反向），小正文仍会被缓冲扫描，
    /// B 路就会出现记录，本测试立即失败（非恒真断言）。
    #[tokio::test]
    async fn test_bypass_body_cap_skips_scan() {
        let state = test_state();
        let mut cfg = aiguard_core::locker::LockerConfig::default();
        cfg.entries.push(aiguard_core::locker::LockerEntry {
            name: "GH_TOKEN".to_string(),
            value: "ghp-vault-test-1234567890".to_string(),
            action: "mask".to_string(),
            enabled: true,
            kind: "value".to_string(),
        });
        cfg.sanitize();
        let specs = aiguard_core::detector::default_rule_specs();
        let detector = Detector::from_specs(&specs).unwrap().with_locker(&cfg);
        *state.detector.write().unwrap() = std::sync::Arc::new(detector);
        *state.locker.write().unwrap() = cfg.clone();
        *state.whitelist.write().unwrap() = vec![state::WhitelistEntry {
            id: "wl-cap".to_string(),
            kind: state::WhitelistKind::Domain,
            pattern: "chat.deepseek.com".to_string(),
            scrub: false,
        }];

        let handler = AiGuardHandler { state: state.clone() };
        let addr: SocketAddr = "127.0.0.1:51006".parse().unwrap();
        let payload = r#"{"q":"use ghp-vault-test-1234567890 directly"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("https://chat.deepseek.com/api/chat")
            .header("content-type", "application/json")
            .header("content-length", (32 * 1024 * 1024 + 1).to_string())
            .body(Body::from(payload.as_bytes().to_vec()))
            .unwrap();

        let out = match handler.dispatch_request(addr, req).await {
            RequestOrResponse::Request(r) => r,
            RequestOrResponse::Response(res) => {
                panic!("超限直通不应拦截，实际状态 {}", res.status())
            }
        };
        let got = to_bytes(out.into_body()).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&got).as_ref(),
            payload,
            "超限路径正文必须原样转发"
        );
        state.flush_vault_use(&addr.to_string());
        assert!(
            state.vault_notice_debug_state(state::VAULT_PLAINTEXT_PATH).is_empty(),
            "超限请求不得进入 B 路统计（非空说明超限仍被缓冲扫描）"
        );
        assert!(state.vault_notice_debug_state(state::VAULT_MASKED_PATH).is_empty());
    }

    /// Block 拦截的请求不得进入 A/B 凭据统计（凭据未送达 AI 服务，不计使用）；
    /// 但 per-rule 反馈统计的数据源要求 block 行仍落 rule_id。
    #[tokio::test]
    async fn test_block_403_does_not_stage_vault_entries() {
        let state = test_state();
        // 凭据条目 + 激进预设（银行卡 Block，确认数 2）
        let mut cfg = aiguard_core::locker::LockerConfig::default();
        cfg.entries.push(aiguard_core::locker::LockerEntry {
            name: "GH_TOKEN".to_string(),
            value: "ghp-vault-test-1234567890".to_string(),
            action: "mask".to_string(),
            enabled: true,
            kind: "value".to_string(),
        });
        cfg.sanitize();
        let specs = aiguard_core::detector::apply_preset_to_builtin(
            aiguard_core::detector::default_rule_specs(),
            aiguard_core::detector::PRESET_AGGRESSIVE,
        );
        let detector = Detector::from_specs(&specs).unwrap().with_locker(&cfg);
        *state.detector.write().unwrap() = std::sync::Arc::new(detector);
        *state.locker.write().unwrap() = cfg.clone();

        let handler = AiGuardHandler { state: state.clone() };
        let addr: SocketAddr = "127.0.0.1:51007".parse().unwrap();
        // 同一体：两张合法卡（触发 Block）+ 一个凭据值（若误 stage 会被本测试捕获）
        let payload = r#"{"messages":[{"role":"user","content":"卡号4242424242424242，另一张是5555555555554444，token=ghp-vault-test-1234567890"}]}"#;
        let req = Request::builder()
            .method("POST")
            .uri("https://chat.deepseek.com/v1/chat/completions")
            .header("content-type", "application/json")
            .body(Body::from(payload.as_bytes().to_vec()))
            .unwrap();

        match handler.dispatch_request(addr, req).await {
            RequestOrResponse::Response(res) => {
                assert_eq!(res.status().as_u16(), 403, "两张合法卡必须触发拦截")
            }
            RequestOrResponse::Request(_) => panic!("两张合法卡应触发 Block，不应放行"),
        }
        state.flush_vault_use(&addr.to_string());
        assert!(
            state.vault_notice_debug_state(state::VAULT_MASKED_PATH).is_empty(),
            "Block 请求的凭据命中不得进入 A 路统计"
        );
        assert!(
            state.vault_notice_debug_state(state::VAULT_PLAINTEXT_PATH).is_empty(),
            "Block 请求不得进入 B 路统计"
        );
        // per-rule 统计的数据源：block 行也落命中的规则 id
        let logs = state.store.list_requests(10).unwrap();
        assert_eq!(logs.len(), 1, "Block 请求应落一条 request_log");
        assert_eq!(logs[0].action, "block");
        assert!(
            logs[0].rule_id.contains("builtin.bankcard"),
            "block 行应落命中的规则 id，实际: {}",
            logs[0].rule_id
        );
    }
}

#[cfg(test)]
mod block_confirm_gate_tests {
    //! Block 确认闸门验收：只测纯函数 `scrub_json_value`，不构造 HttpContext。
    //! 误拦归零验收标准 —— 激进预设下，长数字串（订单号 / 时间戳 / uid）不得触发拦截。

    use super::*;
    use aiguard_core::detector::{apply_preset_to_builtin, default_rule_specs, PRESET_AGGRESSIVE};

    /// 激进预设检测器：银行卡 / 身份证 / API Key 均为 Block（银行卡带 Luhn 校验器）。
    fn aggressive_detector() -> Detector {
        let specs = apply_preset_to_builtin(default_rule_specs(), PRESET_AGGRESSIVE);
        Detector::from_specs(&specs).expect("内置规则必须可编译")
    }

    /// 对单个 JSON 体跑脱敏，返回是否拦截（与调用点聚合逻辑一致）。
    fn scrub_body(detector: &Detector, body: &mut Value) -> bool {
        let vault = Vault::new();
        let mut block_confirms: std::collections::HashMap<String, (u32, u32)> =
            std::collections::HashMap::new();
        let mut kinds: Vec<String> = Vec::new();
        let mut hit_count = 0usize;
        let mut vault_entries: Vec<String> = Vec::new();
        let mut rule_ids: Vec<String> = Vec::new();
        scrub_json_value(
            body,
            detector,
            &vault,
            "sess-gate",
            &mut kinds,
            &mut block_confirms,
            &mut hit_count,
            false,
            &mut vault_entries,
            &mut rule_ids,
        );
        block_confirms.values().any(|(count, need)| count >= need)
    }

    /// 确定性生成 100 条 16~17 位长数字串（订单号 / 时间戳 / uid 形态混合）。
    /// 多数 Luhn 不通过（正则浮出即被校验器过滤）；碰巧通过的也只出现一次
    /// （确认数 1 < 2），逐条构造请求体均不得拦截。
    fn long_digit_strings() -> Vec<String> {
        (0i64..100)
            .map(|i| match i % 3 {
                // 订单号形态：日期前缀 + 序号（16 位）
                0 => format!("20260916{:08}", i * 7919),
                // 时间戳形态（16 位）
                1 => format!("178{:013}", 1_000_000_000_000i64 + i * 104_729),
                // uid 形态（17 位）
                _ => format!("{:017}", 31_415_926_535_897_932i64 + i * 2_718_281_828i64),
            })
            .collect()
    }

    #[test]
    fn test_long_digit_strings_never_block() {
        let det = aggressive_detector();
        for s in long_digit_strings() {
            let mut body = serde_json::json!({
                "model": "deepseek-chat",
                "messages": [
                    { "role": "user", "content": format!("帮我查一下订单 {}", s) }
                ]
            });
            assert!(
                !scrub_body(&det, &mut body),
                "长数字串 {} 不得触发拦截（误拦归零）",
                s
            );
        }
    }

    #[test]
    fn test_two_valid_cards_block() {
        let det = aggressive_detector();
        // 两个不同合法卡号（Luhn 通过）在同一体内 → 确认数 2 ≥ 2 → 拦截；
        // 卡号前后不得紧邻 ASCII 数字（数字邻接检查）
        let mut body = serde_json::json!({
            "model": "deepseek-chat",
            "messages": [
                { "role": "user", "content": "卡号4242424242424242，另一张是5555555555554444，请查收" }
            ]
        });
        assert!(scrub_body(&det, &mut body), "两个合法卡号应达到确认次数并拦截");
    }

    #[test]
    fn test_single_valid_card_masks_without_block() {
        let det = aggressive_detector();
        let mut body = serde_json::json!({
            "model": "deepseek-chat",
            "messages": [
                { "role": "user", "content": "我的卡号是4111111111111111谢谢" }
            ]
        });
        assert!(!scrub_body(&det, &mut body), "单个合法卡号确认数 1 < 2，不得拦截");
        // 未达标命中照常脱敏
        let content = body["messages"][0]["content"].as_str().unwrap();
        assert!(
            content.contains("[[PII:BANKCARD:"),
            "未达标命中必须脱敏，实际: {}",
            content
        );
        assert!(!content.contains("4111111111111111"), "原文不得残留");
    }
}

/// 取 PEM 文本中第一段 base64 负载并解码为 DER。
fn pem_first_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    let b64: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("PEM 解码失败: {}", safe_err(&e)))
}

/// 本地 PAC HTTP 服务：浏览器 AutoConfigURL 指向 `http://127.0.0.1:8889/pac`。
///
/// 相比 file:// PAC，HTTP 获取 100% 可靠（Chromium 对 file:// PAC 偶发获取
/// 失败会回退直连/全局代理，导致守护"不生效"）。PAC 内容按守护开关状态
/// 实时生成——开关守护即时生效，无需改注册表或重启浏览器。
pub async fn run_pac_server(state: Arc<AppState>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", crate::proxy_config::PAC_HTTP_PORT))
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "PAC 服务绑定 {} 失败: {}",
                crate::proxy_config::PAC_HTTP_PORT,
                safe_err(&e)
            )
        })?;
    log::info!(
        "PAC 服务已启动 127.0.0.1:{}",
        crate::proxy_config::PAC_HTTP_PORT
    );

    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("PAC accept 失败: {}", safe_err(&e));
                continue;
            }
        };
        let st = state.clone();
        tokio::spawn(async move {
            // 读请求头块（忽略内容——浏览器只要 PAC 正文）
            let mut buf = [0u8; 4096];
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
                .await;
            let (enabled, port) = {
                let c = match st.config.read() {
                    Ok(c) => c,
                    Err(poisoned) => poisoned.into_inner(),
                };
                (c.enabled, c.proxy_port)
            };
            let body = crate::proxy_config::dynamic_pac_content(enabled, port, &st.custom_hosts_snapshot());
            // PAC 正文含中文注释，用 UTF-8 字节发送就必须声明 charset——
            // 否则 WinHTTP / 浏览器可能按系统代码页解码，注释变乱码。
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// 构建并启动本地 MITM 代理。
///
/// hudsucker 0.20 关键 API：类型走 `hudsucker::hyper` 重导出；
/// `RcgenAuthority::new(key, cert, cache) -> Result`（内部会校验私钥与证书匹配）；
/// `with_rustls_client()` 无参；`build()` 不返回 Result；`start(shutdown_future)` 接收 future。
///
/// **CA 以磁盘文件为唯一真相**：用户安装进系统信任库的必须就是代理签发用的这把
/// （此前曾发生启动时现场重新生成 CA、与已安装证书不一致导致浏览器不信任的问题）。
pub async fn run_proxy(state: Arc<AppState>) -> anyhow::Result<()> {
    let port = match state.config.read() {
        Ok(c) => c.proxy_port,
        Err(poisoned) => poisoned.into_inner().proxy_port,
    };

    // 加载（必要时生成）磁盘上的 CA 文件
    let key_path = state.data_dir.join("ca.key");
    let cert_path = state.data_dir.join("ca.cer");
    if !key_path.exists() || !cert_path.exists() {
        crate::state::ensure_ca(&state.data_dir)
            .map_err(|e| anyhow::anyhow!("CA 生成失败: {}", safe_err(&e)))?;
    }
    // 私钥**经 DPAPI 解密**读取（密文落盘；旧版明文会在读取时就地迁移为密文）
    let mut key_pem = crate::security::load_ca_key_pem(&key_path)
        .map_err(|e| anyhow::anyhow!("载入 CA 私钥失败: {}", safe_err(&e)))?;
    let cert_pem = std::fs::read_to_string(&cert_path)
        .map_err(|e| anyhow::anyhow!("读取 CA 证书失败: {}", safe_err(&e)))?;

    let private_key = hudsucker::rustls::PrivateKey(pem_first_der(&key_pem)?);
    // 私钥 PEM 文本用完立即擦除（DER 对象由 RcgenAuthority 持有，无法再触碰）
    aiguard_core::mem::wipe_string(&mut key_pem);
    let ca_cert = hudsucker::rustls::Certificate(pem_first_der(&cert_pem)?);
    let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
        .map_err(|e| anyhow::anyhow!("RcgenAuthority 构建失败: {}", safe_err(&e)))?;

    // 上游连接器：**DNS 直查公共服务器**（绕过系统 hosts）。
    // hosts 模式会把 AI 域名在系统 hosts 中指向 127.0.0.1，若代理转发上游时
    // 也走系统解析会连回自身形成回环（用户实测 502）。自定义解析器彻底规避。
    let mut http_connector = hudsucker::hyper::client::connect::HttpConnector::new_with_resolver(
        crate::dns::DirectDnsResolver,
    );
    // 关键：HttpConnector 默认 enforce_http=true，会把 https 目标直接拒绝
    // （invalid URL, scheme is not http → 502）。必须关闭，让 https 目标
    // 穿透到 hyper-rustls 的 TLS 分支。
    http_connector.enforce_http(false);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http_connector);
    let client = hudsucker::hyper::Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build(https);

    let handler = AiGuardHandler { state };

    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], port)))
        .with_client(client)
        .with_ca(ca)
        .with_http_handler(handler)
        .build();

    log::info!("AI 安全卫士代理已启动 127.0.0.1:{}", port);
    // start 接收一个永不完成的 future 作为 shutdown 信号；应用退出时由进程终止
    proxy
        .start(futures::future::pending::<()>())
        .await
        .map_err(|e| anyhow::anyhow!("代理运行错误: {}", safe_err(&e)))?;
    Ok(())
}
