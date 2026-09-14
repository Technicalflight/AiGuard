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

#[cfg(not(target_os = "windows"))]
pub fn pid_listening_on(_port: u16) -> Option<u32> {
    None
}

#[cfg(target_os = "windows")]
pub fn resolve_client_exe(client_addr: SocketAddr) -> Option<String> {
    let pid = find_pid_by_connection(client_addr)?;
    exe_path_of_pid(pid)
}

#[cfg(not(target_os = "windows"))]
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

#[cfg(not(target_os = "windows"))]
pub fn exe_path_of_pid(_pid: u32) -> Option<String> {
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
