//! 绕过系统解析器的 DNS 直查（hosts 模式的关键配套）。
//!
//! hosts 模式会把 AI 域名写入系统 hosts 指向 127.0.0.1；本地代理转发上游时
//! 如果也走系统解析，会解析到 127.0.0.1 形成回环（自己连自己 → 502）。
//! 本模块直接向公共 DNS 服务器发 UDP A 记录查询，**不经过系统解析器**，
//! 因此不受 hosts 影响，总能拿到真实 IP。
//!
//! 接入方式：实现 `tower_service::Service<Name>`（hyper 0.14 的 Resolve 是
//! sealed 别名，对所有 `Service<Name, Response: Iterator<SocketAddr>>` 自动
//! blanket 实现），再通过 `HttpConnector::set_resolver` 注入。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::task::{Context, Poll};
use std::time::Duration;

use hudsucker::hyper::client::connect::dns::Name;

/// 公共 DNS 服务器（国内优先，超时后依次降级）。
const DNS_SERVERS: [&str; 3] = ["223.5.5.5:53", "119.29.29.29:53", "8.8.8.8:53"];

/// 向公共 DNS 直查 A 记录，返回全部 IPv4 结果。
/// 先 UDP 查询（快），失败（超时/被拦截）后降级 TCP 53（运营商一般不拦 TCP）。
async fn query_a(host: &str) -> io::Result<Vec<IpAddr>> {
    let query = build_query(host)?;
    let mut buf = [0u8; 512];
    let mut last_err: Option<io::Error> = None;
    // ── 第一轮：UDP ──
    for server in DNS_SERVERS {
        match udp_query(server, &query, &mut buf).await {
            Ok(n) => {
                if let Some(ips) = parse_a_response(&buf[..n], 0xABCD) {
                    if !ips.is_empty() {
                        return Ok(ips);
                    }
                }
            }
            Err(e) => last_err = Some(e),
        }
    }
    // ── 第二轮：TCP（长度前缀帧）──
    for server in DNS_SERVERS {
        match tcp_query(server, &query).await {
            Ok(resp) => {
                if let Some(ips) = parse_a_response(&resp, 0xABCD) {
                    if !ips.is_empty() {
                        return Ok(ips);
                    }
                }
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "所有 DNS 服务器均不可达")))
}

/// UDP DNS 查询单次尝试。
async fn udp_query(server: &str, query: &[u8], buf: &mut [u8]) -> io::Result<usize> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(query, server).await?;
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(buf)).await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS UDP 查询超时"))??;
    Ok(n)
}

/// TCP DNS 查询单次尝试（2 字节长度前缀帧）。
async fn tcp_query(server: &str, query: &[u8]) -> io::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut s = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(server))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS TCP 连接超时"))??;
    let mut msg = Vec::with_capacity(query.len() + 2);
    msg.extend_from_slice(&(query.len() as u16).to_be_bytes());
    msg.extend_from_slice(query);
    tokio::time::timeout(Duration::from_secs(5), s.write_all(&msg))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS TCP 写入超时"))??;
    let mut lbuf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut lbuf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS TCP 读取超时"))??;
    let len = u16::from_be_bytes(lbuf) as usize;
    let mut buf = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS TCP 读取超时"))??;
    Ok(buf)
}

/// 构造标准 A 记录查询包（单 question）。
fn build_query(host: &str) -> io::Result<Vec<u8>> {
    let mut q = Vec::with_capacity(host.len() + 18);
    q.extend_from_slice(&[0xAB, 0xCD]); // 事务 ID
    q.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in host.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = label.len();
        if len > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "域名标签过长"));
        }
        q.push(len as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // 根标签
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    Ok(q)
}

/// 跳过 DNS 消息中的 name 字段（处理压缩指针），返回后续位置。
fn skip_name(buf: &[u8], mut p: usize) -> Option<usize> {
    loop {
        let l = *buf.get(p)?;
        if l == 0 {
            return Some(p + 1);
        }
        if l & 0xC0 == 0xC0 {
            return Some(p + 2); // 压缩指针占 2 字节
        }
        p += 1 + l as usize;
    }
}

/// 解析 DNS 响应中的 A 记录。
fn parse_a_response(buf: &[u8], expect_id: u16) -> Option<Vec<IpAddr>> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expect_id {
        return None;
    }
    let rcode = buf[3] & 0x0F;
    if rcode != 0 {
        return None;
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut p = 12usize;
    for _ in 0..qd {
        p = skip_name(buf, p)?;
        p += 4; // qtype + qclass
    }
    let mut ips = Vec::new();
    for _ in 0..an {
        p = skip_name(buf, p)?;
        if p + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let rdlen = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;
        p += 10;
        if rtype == 1 && rdlen == 4 && p + 4 <= buf.len() {
            ips.push(IpAddr::V4(std::net::Ipv4Addr::new(
                buf[p],
                buf[p + 1],
                buf[p + 2],
                buf[p + 3],
            )));
        }
        p += rdlen;
    }
    Some(ips)
}

/// hyper 连接器使用的解析器：绕过 hosts，直查公共 DNS。
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectDnsResolver;

impl tower_service::Service<Name> for DirectDnsResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let host = name.as_str().to_string();
        Box::pin(async move {
            // 直查公共 DNS；全部失败时回退系统解析（保证代理内非 AI 域名
            // 的透传健壮性——AI 域名在 hosts 劫持场景下直查总能成功，不会走回退）
            let ips = match query_a(&host).await {
                Ok(ips) if !ips.is_empty() => ips,
                _ => tokio::net::lookup_host((host.as_str(), 0))
                    .await
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("DNS 直查与系统解析均失败: {}", e),
                        )
                    })?
                    .map(|sa| sa.ip())
                    .collect::<Vec<_>>(),
            };
            Ok(ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, 0))
                .collect::<Vec<_>>()
                .into_iter())
        })
    }
}
