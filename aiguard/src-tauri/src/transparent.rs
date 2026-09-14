//! hosts 模式的透明拦截层：监听 443，按 ClientHello 的 SNI 识别 AI 域名，
//! 用本地 CA 为该域名动态签发证书并终结 TLS，然后把明文 HTTP 请求
//! 改写为 **absolute-form** 桥接给本地 8888 代理 —— 后者的脱敏 / 审计 /
//! 上游转发逻辑全部复用，与系统代理模式共用同一条处理链路。
//!
//! 已知简化（对功能无影响的取舍）：
//! - 客户端 TLS 连接处理**单个请求**后关闭（转发头里追加 Connection: close），
//!   浏览器会自动对新请求重建连接；
//! - ClientHello 假定在单个 TLS record 内（主流浏览器均如此）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hudsucker::certificate_authority::{CertificateAuthority, RcgenAuthority};
use hudsucker::hyper::http::uri::Authority;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::state::{self, AppState};

const LISTEN_PORT: u16 = 443;
const HELLO_MAX: usize = 64 * 1024;
const HEAD_MAX: usize = 128 * 1024;

/// 443 透明层的停止标志（模式切离 hosts 时置位，循环自行退出）。
static TRANSPARENT_STOP: AtomicBool = AtomicBool::new(false);
/// 防止重复启动。
static TRANSPARENT_RUNNING: AtomicBool = AtomicBool::new(false);

/// 动态启动 443 透明层（幂等：已在运行则跳过）。
/// CA 从磁盘加载（与主代理同源），无需依赖 run_proxy 的构建过程。
pub fn spawn_if_needed(state: &Arc<AppState>) -> Result<(), String> {
    if TRANSPARENT_RUNNING.swap(true, Ordering::SeqCst) {
        return Ok(()); // 已在运行
    }
    TRANSPARENT_STOP.store(false, Ordering::SeqCst);
    let ca = build_ca(&state.data_dir)?;
    let ca: Arc<dyn CertificateAuthority + Send + Sync> = Arc::new(ca);
    let st = state.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(e) = run_transparent(st, ca).await {
            log::error!("hosts 模式透明代理退出: {}", e);
        }
        TRANSPARENT_RUNNING.store(false, Ordering::SeqCst);
    });
    Ok(())
}

/// 请求停止 443 透明层（循环在下一个 1s 检查点退出）。
pub fn request_stop() {
    TRANSPARENT_STOP.store(true, Ordering::SeqCst);
}

/// 从磁盘 CA 文件构建签发器（与 run_proxy 同源同钥）。
fn build_ca(data_dir: &std::path::Path) -> Result<RcgenAuthority, String> {
    let key_path = data_dir.join("ca.key");
    let cert_path = data_dir.join("ca.cer");
    // 私钥经 DPAPI 解密（密文落盘；明文旧文件会在读取时就地迁移）
    let mut key_pem =
        crate::security::load_ca_key_pem(&key_path).map_err(|e| format!("载入 CA 私钥失败: {}", e))?;
    let cert_pem = std::fs::read_to_string(&cert_path)
        .map_err(|e| format!("读取 CA 证书失败: {}", crate::state::safe_err(&e)))?;
    let private_key = hudsucker::rustls::PrivateKey(pem_to_der(&key_pem)?);
    aiguard_core::mem::wipe_string(&mut key_pem);
    let ca_cert = hudsucker::rustls::Certificate(pem_to_der(&cert_pem)?);
    RcgenAuthority::new(private_key, ca_cert, 1_000)
        .map_err(|e| format!("RcgenAuthority 构建失败: {}", crate::state::safe_err(&e)))
}

/// 取 PEM 文本中第一段 base64 负载并解码为 DER。
fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let b64: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| format!("PEM 解码失败: {}", e))
}

/// 启动 443 透明监听（仅 HostsFile 模式下调用）。
/// `ca` 与 8888 主代理共用同一把 CA（为 AI 域名动态签发终端证书）。
pub async fn run_transparent(
    state: Arc<AppState>,
    ca: Arc<dyn CertificateAuthority + Send + Sync>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", LISTEN_PORT))
        .await
        .map_err(|e| anyhow::anyhow!("绑定 443 端口失败（可能被其他程序占用）: {}", crate::state::safe_err(&e)))?;
    log::info!("hosts 模式透明代理已启动 127.0.0.1:443");

    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    ticker.tick().await; // 第一次 tick 立即返回，消费掉
    loop {
        // 每 1s 检查一次停止标志（模式切离 hosts 时优雅退出）
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = ticker.tick() => {
                if TRANSPARENT_STOP.load(Ordering::SeqCst) {
                    log::info!("hosts 模式透明代理已停止");
                    return Ok(());
                }
                continue;
            }
        };
        let (stream, peer) = match accepted {
            Ok(v) => v,
            Err(e) => {
                log::warn!("443 accept 失败: {}", crate::state::safe_err(&e));
                continue;
            }
        };
        // 纵深防御：443 只绑 127.0.0.1，非本机来源一律丢弃
        if !peer.ip().is_loopback() {
            log::warn!("拒绝非本机来源的 443 连接: {}", peer);
            drop(stream);
            continue;
        }
        let state = state.clone();
        let ca = ca.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(state, ca, stream).await {
                log::warn!("透明连接异常: {}", e);
            }
        });
    }
}

/// 单个 443 连接的处理：SNI 识别 → TLS 终结 → 改写请求行 → 桥接本地代理。
async fn handle_conn(
    state: Arc<AppState>,
    ca: Arc<dyn CertificateAuthority + Send + Sync>,
    mut stream: TcpStream,
) -> Result<(), String> {
    // 1. 读取并解析 ClientHello，提取 SNI
    let mut hello: Vec<u8> = Vec::new();
    let sni = loop {
        match try_sni(&hello) {
            SniStatus::NeedMore => {
                let mut b = [0u8; 4096];
                let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut b))
                    .await
                    .map_err(|_| "等待 ClientHello 超时".to_string())?
                    .map_err(|e| format!("读取失败: {}", e))?;
                if n == 0 {
                    return Err("连接在 ClientHello 前关闭".to_string());
                }
                hello.extend_from_slice(&b[..n]);
                if hello.len() > HELLO_MAX {
                    return Err("ClientHello 过大".to_string());
                }
            }
            SniStatus::Found(s) => break s,
            SniStatus::Invalid => return Err("非 TLS 流量".to_string()),
        }
    };

    // 2. 仅处理受守护的 AI 域名（hosts 清单外理论上无流量，防御性丢弃）
    if !state::is_ai_host(&sni) {
        return Err(format!("SNI 非 AI 域名: {}", sni));
    }

    // 3. 用本地 CA 为该 SNI 签发证书（hudsucker 的 RcgenAuthority 内部带缓存）
    let authority: Authority = sni
        .parse()
        .map_err(|e| format!("SNI 非法（{}）: {}", sni, e))?;
    let server_cfg = ca.gen_server_config(&authority).await;

    // 4. TLS 终结（把已读的 ClientHello 作为前缀回放给 acceptor）
    let prefixed = PrefixedStream::new(hello, stream);
    let acceptor = TlsAcceptor::from(server_cfg);
    let mut tls = acceptor
        .accept(prefixed)
        .await
        .map_err(|e| format!("TLS 握手失败: {}", e))?;

    // 5. 读取第一个请求头块（\r\n\r\n 之前），剩余字节（body 起始）记为 extra
    let (head, extra) = read_head(&mut tls).await?;

    // 6. 改写请求行（origin-form → absolute-form）并强制 Connection: close
    let rewritten = rewrite_request_head(&head, &sni)?;

    // 7. 连接本地代理（8888），写入改写后的头块 + body 起始字节
    let proxy_port = {
        let cfg = state.config.read().map_err(|e| e.to_string())?;
        cfg.proxy_port
    };
    let mut upstream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .map_err(|e| format!("连接本地代理失败: {}", e))?;
    upstream
        .write_all(rewritten.as_bytes())
        .await
        .map_err(|e| format!("写入代理失败: {}", e))?;
    if !extra.is_empty() {
        upstream
            .write_all(&extra)
            .await
            .map_err(|e| format!("写入请求体失败: {}", e))?;
    }

    // 8. 双向泵到任一侧关闭（Connection: close 已在头里声明，响应完即结束）
    log::info!(
        "透明桥接: {} https://{}{} → 127.0.0.1:{}",
        rewritten.split('\r').next().unwrap_or("").split(' ').next().unwrap_or("?"),
        sni,
        rewritten.split_once("\r\n").map(|(_, r)| r).unwrap_or(""),
        proxy_port
    );
    let bridged = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
    match bridged {
        Ok((up, down)) => {
            log::info!(
                "透明桥接结束: {} 上行 {} 字节 / 下行 {} 字节",
                sni, up, down
            );
        }
        Err(e) => {
            log::warn!("透明桥接错误: {} —— {}", sni, e);
        }
    }
    let _ = tls.shutdown().await;
    Ok(())
}

/// 客户端流：已读前缀（ClientHello）回放 + 剩余底层流。
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        PrefixedStream { prefix, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            buf.put_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// SNI 解析状态。
enum SniStatus {
    /// 数据不足，需要继续读取
    NeedMore,
    /// 成功提取 SNI
    Found(String),
    /// 非 TLS 或格式错误
    Invalid,
}

/// 尝试从缓冲区解析 ClientHello 的 SNI。
fn try_sni(buf: &[u8]) -> SniStatus {
    // TLS record: type(1)=0x16 version(2) length(2)
    if buf.len() < 5 {
        return SniStatus::NeedMore;
    }
    if buf[0] != 0x16 {
        return SniStatus::Invalid;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + rec_len {
        return SniStatus::NeedMore;
    }
    let rec = &buf[5..5 + rec_len];
    // handshake: type(1)=0x01 length(3)
    if rec.len() < 4 || rec[0] != 0x01 {
        return SniStatus::Invalid;
    }
    let hs_len = ((rec[1] as usize) << 16) | ((rec[2] as usize) << 8) | rec[3] as usize;
    if rec.len() < 4 + hs_len {
        return SniStatus::NeedMore;
    }
    let hs = &rec[4..4 + hs_len];
    // ClientHello: version(2) random(32) session_id vector ciphers vector compress vector extensions
    if hs.len() < 34 {
        return SniStatus::Invalid;
    }
    let mut p = 34usize; // 2 + 32
    if hs.len() < p + 1 {
        return SniStatus::Invalid;
    }
    let sid = hs[p] as usize;
    p += 1 + sid;
    if hs.len() < p + 2 {
        return SniStatus::Invalid;
    }
    let cipher_len = u16::from_be_bytes([hs[p], hs[p + 1]]) as usize;
    p += 2 + cipher_len;
    if hs.len() < p + 1 {
        return SniStatus::Invalid;
    }
    let comp_len = hs[p] as usize;
    p += 1 + comp_len;
    if hs.len() < p + 2 {
        return SniStatus::Invalid;
    }
    let ext_len = u16::from_be_bytes([hs[p], hs[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_len).min(hs.len());
    while p + 4 <= ext_end {
        let etype = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let elen = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        let edata = &hs[(p + 4)..(p + 4 + elen).min(hs.len())];
        if etype == 0x0000 && edata.len() >= 5 {
            // server_name_list: list_len(2) name_type(1)=0 name_len(2) name
            let nlen = u16::from_be_bytes([edata[3], edata[4]]) as usize;
            if edata.len() >= 5 + nlen {
                return SniStatus::Found(String::from_utf8_lossy(&edata[5..5 + nlen]).to_string());
            }
        }
        p += 4 + elen;
    }
    SniStatus::Invalid
}

/// 读取 HTTP 请求头块（到空行），返回 (头块含空行, 头块后的剩余字节)。
async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut head: Vec<u8> = Vec::new();
    let mut b = [0u8; 4096];
    loop {
        let n = s
            .read(&mut b)
            .await
            .map_err(|e| format!("读取请求失败: {}", e))?;
        if n == 0 {
            return Err("连接在请求头读完前关闭".to_string());
        }
        head.extend_from_slice(&b[..n]);
        if let Some(pos) = find_head_end(&head) {
            let extra = head.split_off(pos);
            return Ok((head, extra));
        }
        if head.len() > HEAD_MAX {
            return Err("请求头过大".to_string());
        }
    }
}

/// 定位 \r\n\r\n（头块结束），返回头块总长（含空行）。
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// 把 origin-form 请求行改写为 absolute-form（透明层终结 TLS 后，
/// 上游代理需要绝对地址才知道目标主机），并强制 Connection: close
/// （每条客户端 TLS 连接只服务一个请求，简化生命周期管理；
/// 浏览器会自动为新请求重建连接）。
fn rewrite_request_head(head: &[u8], sni: &str) -> Result<String, String> {
    let text = String::from_utf8_lossy(head);
    let (req_line, rest) = text
        .split_once("\r\n")
        .ok_or_else(|| "请求头缺少结束行".to_string())?;
    let mut parts = req_line.split(' ');
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    let new_target = if target.starts_with("https://") || target.starts_with("http://") {
        target
    } else if let Some(t) = target.strip_prefix('/') {
        format!("https://{}{}", sni, if t.is_empty() { String::from("/") } else { format!("/{}", t) })
    } else {
        format!("https://{}{}", sni, target)
    };

    let mut lines = vec![format!("{} {} {}", method, new_target, version)];
    let mut had_connection = false;
    for line in rest.lines() {
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("connection:") {
            lines.push("Connection: close".to_string());
            had_connection = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !had_connection {
        lines.push("Connection: close".to_string());
    }
    Ok(lines.join("\r\n") + "\r\n\r\n")
}
