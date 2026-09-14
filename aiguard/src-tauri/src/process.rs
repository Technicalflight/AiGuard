//! 客户端进程识别（Windows）：把代理连接的 client ip:port 反解到 PID，再取 exe 完整路径，
//! 用于「进程白名单」（可执行文件 / 文件夹内所有程序）匹配。
//!
//! 原理：
//! 1. `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_CONNECTIONS)` 拿到本机全部 TCP 连接及归属 PID，
//!    找到 local == client_addr 且 remote == 127.0.0.1（即连到本代理）的行；
//! 2. `OpenProcess + QueryFullProcessImageNameW` 取进程 exe 完整路径；
//! 3. 结果按 client port 缓存 30s（连接期间端口与进程的映射不变，避免每请求一次系统调用）。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::state::{process_path_matches, AppState, WhitelistKind};

/// 进程解析缓存 TTL
const CACHE_TTL: Duration = Duration::from_secs(30);

/// 解析 client ip:port 对应进程的 exe 完整路径（带缓存）。
pub fn client_exe_cached(state: &AppState, client_addr: SocketAddr) -> Option<String> {
    let port = client_addr.port();
    if let Ok(cache) = state.proc_cache.lock() {
        if let Some((at, v)) = cache.get(&port) {
            if at.elapsed() < CACHE_TTL {
                return v.clone();
            }
        }
    }
    let resolved = resolve_client_exe(client_addr);
    if let Ok(mut cache) = state.proc_cache.lock() {
        cache.insert(port, (Instant::now(), resolved.clone()));
    }
    resolved
}

/// 客户端连接是否命中进程白名单。
/// 无进程类白名单条目时直接返回 false（不产生系统调用开销）。
pub fn client_in_process_whitelist(state: &AppState, client_addr: SocketAddr) -> bool {
    let whitelist = match state.whitelist.read() {
        Ok(w) => w,
        Err(_) => return false,
    };
    if !whitelist
        .iter()
        .any(|e| e.kind == WhitelistKind::Process)
    {
        return false;
    }
    let exe = match client_exe_cached(state, client_addr) {
        Some(e) => e,
        None => return false, // 解析失败（权限/非 Windows）→ 视为不在白名单
    };
    whitelist
        .iter()
        .any(|e| e.kind == WhitelistKind::Process && process_path_matches(&e.pattern, &exe))
}

/// 客户端连接是否命中进程黑名单（命中 → 强制拦截）。
/// 无进程类黑名单条目时直接返回 false（不产生系统调用开销）。
pub fn client_in_process_blacklist(state: &AppState, client_addr: SocketAddr) -> bool {
    let blacklist = match state.blacklist.read() {
        Ok(b) => b,
        Err(_) => return false,
    };
    if !blacklist
        .iter()
        .any(|e| e.kind == WhitelistKind::Process)
    {
        return false;
    }
    let exe = match client_exe_cached(state, client_addr) {
        Some(e) => e,
        None => return false, // 解析失败 → 视为不在黑名单（不误拦）
    };
    blacklist
        .iter()
        .any(|e| e.kind == WhitelistKind::Process && process_path_matches(&e.pattern, &exe))
}

// ─────────── Windows 实现 ───────────

/// 查找**正在监听**指定本地端口的进程 PID（端口占用诊断用）。
///
/// 与 [`find_pid_by_connection`] 同源：`GetExtendedTcpTable` +
/// `TCP_TABLE_OWNER_PID_LISTENER`，行布局一致（监听行 remote 字段为 0）。
/// 查不到返回 `None`（端口空闲，或该监听者属于其它用户而无法枚举）。
#[cfg(target_os = "windows")]
pub fn pid_listening_on(port: u16) -> Option<u32> {
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_LISTENER,
    };

    const AF_INET: u32 = 2;
    let mut size: u32 = 0;
    let rc = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if rc != ERROR_INSUFFICIENT_BUFFER && rc != 0 {
        return None;
    }
    if size == 0 || (size as usize) < 4 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let entries = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    for i in 0..entries {
        let o = 4 + i * 24;
        if o + 24 > buf.len() {
            break;
        }
        let lp = u32::from_le_bytes([buf[o + 8], buf[o + 9], buf[o + 10], buf[o + 11]]);
        let local_port = (((lp & 0xFF) as u16) << 8) | (((lp >> 8) & 0xFF) as u16);
        if local_port == port {
            return Some(u32::from_le_bytes([
                buf[o + 20],
                buf[o + 21],
                buf[o + 22],
                buf[o + 23],
            ]));
        }
    }
    None
}

/// Linux：解析 `/proc/net/tcp` + `/proc/net/tcp6` 找监听该端口的 socket inode，
/// 再在 `/proc/<pid>/fd` 里反查持有该 inode 的进程。
#[cfg(target_os = "linux")]
pub fn pid_listening_on(port: u16) -> Option<u32> {
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(table) else {
            continue;
        };
        // TCP_LISTEN == 0x0A
        let hit = parse_proc_net_tcp(&text)
            .into_iter()
            .find(|row| row.state == 0x0A && row.local.1 == port);
        if let Some(row) = hit {
            if let Some(pid) = pid_owning_socket(row.inode) {
                return Some(pid);
            }
        }
    }
    None
}

/// macOS：`lsof` 查监听该端口的进程。
///
/// `-nP` 关掉主机名/端口名反查（否则每行都要过一次 DNS）；`-sTCP:LISTEN`
/// 把匹配限于监听套接字。
#[cfg(target_os = "macos")]
pub fn pid_listening_on(port: u16) -> Option<u32> {
    let out = std::process::Command::new("/usr/sbin/lsof")
        .args(["-nP", "-t", &format!("-iTCP:{}", port), "-sTCP:LISTEN"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_lsof_pid_list(&crate::console::decode_console(&out.stdout))
}

/// 其它平台：查不到（返回 None 会让端口诊断退化为「bind 试探」）。
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub fn pid_listening_on(_port: u16) -> Option<u32> {
    None
}

#[cfg(target_os = "windows")]
pub fn resolve_client_exe(client_addr: SocketAddr) -> Option<String> {
    let pid = find_pid_by_connection(client_addr)?;
    exe_path_of_pid(pid)
}

/// Linux：在连接表里按「本端地址 == 客户端地址」找到那条连接，取 socket inode，
/// 再反查 PID。（同一 `ip:port` 不可能被两个进程同时持有，所以本地端匹配即唯一。）
#[cfg(target_os = "linux")]
pub fn resolve_client_exe(client_addr: SocketAddr) -> Option<String> {
    let std::net::IpAddr::V4(v4) = client_addr.ip() else {
        return None;
    };
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(table) else {
            continue;
        };
        let hit = parse_proc_net_tcp(&text)
            .into_iter()
            .find(|row| row.local == (v4, client_addr.port()));
        if let Some(row) = hit {
            return pid_owning_socket(row.inode).and_then(exe_path_of_pid);
        }
    }
    None
}

/// macOS：`lsof` 反查持有该本地端口的进程。
///
/// ⚠ 必须**剔除本进程自己**：代理侧那条连接的远端恰好就是客户端的 `ip:port`，
/// 所以 `lsof -iTCP@<client>` 会同时列出客户端与本代理。不剔除的话，
/// 进程黑白名单会把「代理自己」当成发起方——那是彻底错误的归因。
#[cfg(target_os = "macos")]
pub fn resolve_client_exe(client_addr: SocketAddr) -> Option<String> {
    // `-iTCP@host:port` 匹配「任一端等于该地址」的套接字——这正是必须剔除
    // 本进程的原因（见上面的注释）。
    let selector = format!("-iTCP@{}:{}", client_addr.ip(), client_addr.port());
    let out = std::process::Command::new("/usr/sbin/lsof")
        .args(["-nP", "-t", &selector])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let me = std::process::id();
    parse_lsof_pid_list(&crate::console::decode_console(&out.stdout))
        .filter(|pid| *pid != me)
        .and_then(exe_path_of_pid)
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub fn resolve_client_exe(_client_addr: SocketAddr) -> Option<String> {
    None
}

/// 在 TCP 连接表中查找 local == client_addr 且 remote == 127.0.0.1 的行，返回归属 PID。
#[cfg(target_os = "windows")]
fn find_pid_by_connection(client_addr: SocketAddr) -> Option<u32> {
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_CONNECTIONS,
    };

    const AF_INET: u32 = 2;
    let client_v4 = match client_addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => return None,
    };

    // 第一次调用取所需缓冲区大小
    let mut size: u32 = 0;
    let rc = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        )
    };
    if rc != ERROR_INSUFFICIENT_BUFFER && rc != 0 {
        return None;
    }
    if size == 0 || (size as usize) < 4 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        )
    };
    if rc != 0 {
        return None;
    }

    // 手工解析 MIB_TCPTABLE_OWNER_PID：
    // 头 4 字节 dwNumEntries，其后每行 24 字节：
    // dwState(0..4) dwLocalAddr(4..8) dwLocalPort(8..12) dwRemoteAddr(12..16)
    // dwRemotePort(16..20) dwOwningPid(20..24)；地址为网络字节序，端口存于低 16 位网络字节序
    let entries = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    for i in 0..entries {
        let o = 4 + i * 24;
        if o + 24 > buf.len() {
            break;
        }
        let local_ip = std::net::Ipv4Addr::new(buf[o + 4], buf[o + 5], buf[o + 6], buf[o + 7]);
        let lp = u32::from_le_bytes([buf[o + 8], buf[o + 9], buf[o + 10], buf[o + 11]]);
        let local_port = (((lp & 0xFF) as u16) << 8) | (((lp >> 8) & 0xFF) as u16);
        let remote_is_loopback = buf[o + 12] == 127;
        if local_ip == client_v4 && local_port == client_addr.port() && remote_is_loopback {
            return Some(u32::from_le_bytes([
                buf[o + 20],
                buf[o + 21],
                buf[o + 22],
                buf[o + 23],
            ]));
        }
    }
    None
}

/// PID → exe 完整路径（OpenProcess + QueryFullProcessImageNameW）。
#[cfg(target_os = "windows")]
pub fn exe_path_of_pid(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    // windows-sys 0.61 起 HANDLE 是 `*mut c_void`（0.52 时是 `isize`），
    // 所以失败判据从 `== 0` 改成空指针判断。
    if handle.is_null() {
        return None;
    }
    let mut buf16 = [0u16; 2048];
    let mut len: u32 = buf16.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf16.as_mut_ptr(), &mut len) };
    let _ = unsafe { CloseHandle(handle) };
    if ok == 0 || len == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf16[..len as usize]))
}

/// Linux：`/proc/<pid>/exe` 的符号链接目标（可执行文件完整路径）。
#[cfg(target_os = "linux")]
pub fn exe_path_of_pid(pid: u32) -> Option<String> {
    let path = std::fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
    Some(path.to_string_lossy().to_string())
}

/// macOS：`lsof -a -p <pid> -d txt -Fn` 里的 `n` 行即可执行文件完整路径。
///
/// ⚠ 必须配合 `-d txt` 使用：不加它时第一条 `n` 行往往是 cwd（`/`），
/// 解析出来的就不是 exe 路径了。
#[cfg(target_os = "macos")]
pub fn exe_path_of_pid(pid: u32) -> Option<String> {
    let out = std::process::Command::new("/usr/sbin/lsof")
        .args(["-nP", "-a", "-p", &pid.to_string(), "-d", "txt", "-Fn"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_lsof_name_line(&crate::console::decode_console(&out.stdout))
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub fn exe_path_of_pid(_pid: u32) -> Option<String> {
    None
}

// ─────────── 纯解析（所有平台都编译，测试在所有平台都跑） ───────────
//
// 解析与系统调用分开：`/proc/net/tcp` 的行格式与 `lsof` 的输出格式都是
// 「一旦写错就静默失准」的地方（进程黑名单会安静地永远不匹配），
// 所以这两段必须能在本机（Windows）被单测覆盖，不能只靠 CI 上看不见的真机。

/// `/proc/net/tcp{,6}` 的一行（只留我们关心的字段）。
///
/// `local_ip` 为 `None` 表示这行是 IPv6（tcp6 的地址写成 32 位 hex）：
/// 端口仍可用于匹配监听者，但「按客户端 v4 地址反查连接」只认 v4 行。
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcNetRow {
    local_ip: Option<std::net::Ipv4Addr>,
    local_port: u16,
    state: u16,
    inode: u64,
}

/// 解析 `/proc/net/tcp` 里的 32 位 IPv4（**小端书写**：`127.0.0.1` → `0100007F`）。
#[cfg(any(target_os = "linux", test))]
fn parse_proc_hex_v4(hex: &str) -> Option<std::net::Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(hex, 16).ok()?;
    let b = raw.to_le_bytes();
    Some(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
}

/// 解析 `/proc/net/tcp{,6}` 文本。
///
/// 行格式（空白分隔）：`sl local_address rem_address st tx:rx tr:when retrnsmt uid
/// timeout inode …`。地址与端口是十六进制；**解析不出的行直接跳过**——表里会混入
/// IPv6 形态与将来新增的列，不该因为一行读不懂就整表作废。
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_tcp(text: &str) -> Vec<ProcNetRow> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let Some((addr_hex, port_hex)) = f[1].split_once(':') else {
            continue;
        };
        let (Ok(local_port), Ok(state), Ok(inode)) = (
            u16::from_str_radix(port_hex, 16),
            u16::from_str_radix(f[3], 16),
            f[9].parse::<u64>(),
        ) else {
            continue;
        };
        out.push(ProcNetRow {
            local_ip: parse_proc_hex_v4(addr_hex),
            local_port,
            state,
            inode,
        });
    }
    out
}

/// Linux：在 `/proc/<pid>/fd` 里反查持有指定 socket inode 的进程。
///
/// 只看数字命名的 pid 目录；权限不足（其它用户的进程）直接跳过——
/// 进程归因本就是「尽力而为」，查不到就不匹配黑白名单，绝不误拦。
#[cfg(target_os = "linux")]
fn pid_owning_socket(inode: u64) -> Option<u32> {
    let target = format!("socket:[{}]", inode);
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{}/fd", pid)) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                if link.to_string_lossy() == target {
                    return Some(pid);
                }
            }
        }
    }
    None
}

/// `lsof -t` 的输出：每行一个 PID，取第一个能解析的。
#[cfg(any(target_os = "macos", test))]
fn parse_lsof_pid_list(text: &str) -> Option<u32> {
    text.lines()
        .map(str::trim)
        .find_map(|line| line.parse::<u32>().ok())
}

/// `lsof -Fn` 的输出：字段行用首字母标类型（`p`=PID / `f`=fd / `n`=名字），
/// 可执行文件路径就是第一条 `n` 行。
#[cfg(any(target_os = "macos", test))]
fn parse_lsof_name_line(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix('n') {
            let path = rest.trim();
            if !path.is_empty() {
                return Some(path.to_string());
            }
        }
    }
    None
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    /// 回归：windows-sys 0.52 → 0.61 时 `HANDLE` 由 `isize` 变成 `*mut c_void`，
    /// 失败判据随之从 `handle == 0` 改成 `handle.is_null()`。
    ///
    /// 这个判断一旦写反，`exe_path_of_pid` 会**永远返回 None**：不 panic、不报错，
    /// 只是进程黑/白名单静默失效（`resolve_client_exe` → 拿不到 exe 就匹配不上规则）。
    /// 这类「安静地不工作」正是最需要断言盯住的，所以这里直接拿当前进程当样本。
    #[test]
    fn test_exe_path_of_pid_resolves_self() {
        let exe = exe_path_of_pid(std::process::id())
            .expect("当前进程应能解析出自己的 exe 路径（通道异常）");
        assert!(
            exe.to_ascii_lowercase().ends_with(".exe"),
            "解析结果不像 exe 路径: {exe}"
        );
    }

    /// 无效 PID 必须干净地返回 None（而不是空串或 panic）。
    /// PID 0 是 OpenProcess 必然拒绝的取值，用来验证「打开失败」这一分支。
    #[test]
    fn test_exe_path_of_pid_rejects_invalid_pid() {
        assert!(exe_path_of_pid(0).is_none(), "PID 0 不应解析出路径");
    }
}

/// 解析层单测：**在所有平台都跑**。
///
/// 这两段解析写错不会有任何报错，只会让进程归因安静地失准
/// （`resolve_client_exe` 永远 None → 进程黑白名单形同不存在）。
/// 所以它们必须在开发机上就测到，而不是等 macOS / Linux 上的真机。
#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn test_parse_proc_hex_v4_is_little_endian() {
        // /proc/net/tcp 实测形态：127.0.0.1 写作 0100007F
        assert_eq!(
            parse_proc_hex_v4("0100007F"),
            Some(std::net::Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(
            parse_proc_hex_v4("00000000"),
            Some(std::net::Ipv4Addr::new(0, 0, 0, 0))
        );
        // IPv6 的 32 位 hex 地址 → 认不出 v4，返回 None（调用方跳过这一行）
        assert_eq!(parse_proc_hex_v4("00000000000000000000000001000000"), None);
        assert_eq!(parse_proc_hex_v4(""), None);
        assert_eq!(parse_proc_hex_v4("ZZZZZZZZ"), None);
    }

    #[test]
    fn test_parse_proc_net_tcp_reads_port_state_inode() {
        // 真实表头 + 三条：一条监听 8888（0A）、一条 443 监听、一条 IPv6 行
        let text = [
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
            "   0: 0100007F:22B8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1234567 1 ffff 100 0 0 10 0",
            "   1: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 7654321 1 ffff 100 0 0 10 0",
            "   2: 00000000000000000000000000000000:22B8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 9998887 1 ffff 100 0 0 10 0",
            "",
        ]
        .join("\n");
        let rows = parse_proc_net_tcp(&text);
        assert_eq!(rows.len(), 3, "三行都应解析出来");

        // 0x22B8 = 8888；0x0A = TCP_LISTEN
        assert_eq!(rows[0].local_port, 8888);
        assert_eq!(rows[0].state, 0x0A);
        assert_eq!(rows[0].inode, 1234567);
        assert_eq!(rows[0].local_ip, Some(std::net::Ipv4Addr::new(127, 0, 0, 1)));

        // 0x01BB = 443
        assert_eq!(rows[1].local_port, 443);

        // IPv6 行：端口仍能取到，但地址认不出 → local_ip 为 None
        assert_eq!(rows[2].local_port, 8888);
        assert_eq!(rows[2].local_ip, None);

        // 残缺行必须被跳过而不是 panic 或产出假数据
        assert!(parse_proc_net_tcp("  sl  local_address\n  0: garbage\n").is_empty());
        assert!(parse_proc_net_tcp("").is_empty());
    }

    #[test]
    fn test_parse_lsof_pid_list_takes_first_valid_pid() {
        assert_eq!(parse_lsof_pid_list("1234\n"), Some(1234));
        // lsof 偶尔会先打印告警行，必须跳过而不是整体失败
        assert_eq!(parse_lsof_pid_list("lsof: WARNING: can't stat()\n5678\n"), Some(5678));
        assert_eq!(parse_lsof_pid_list(""), None);
        assert_eq!(parse_lsof_pid_list("no digits here\n"), None);
    }

    #[test]
    fn test_parse_lsof_name_line_extracts_path() {
        // `lsof -a -p 42 -d txt -Fn` 的实测形态：因为有 `-d txt`，
        // 输出里只有文本段这一个 `n` 行，它就是可执行文件路径。
        // （不配合 `-d txt` 时第一条 `n` 往往是 cwd —— `/`，会解析错。）
        let text = "p42\nftxt\nn/Applications/AiGuard.app/Contents/MacOS/aiguard\n";
        assert_eq!(
            parse_lsof_name_line(text).as_deref(),
            Some("/Applications/AiGuard.app/Contents/MacOS/aiguard")
        );
        // 只有类型行、没有名字行 → None
        assert_eq!(parse_lsof_name_line("p42\nf1\n"), None);
        assert_eq!(parse_lsof_name_line(""), None);
    }
}
