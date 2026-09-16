//! 本机安全加固支撑：调试器检测、CA 私钥落盘保护（DPAPI）、端口占用诊断、
//! 数据目录权限评估。
//!
//! 全部实现遵循两条硬约束：
//! 1. **绝不因加固检查失败而阻断主流程**——检查不可用时降级为「未知/未启用」，
//!    并留下明确日志；
//! 2. **日志与返回值里不出现敏感原文**（私钥、令牌只报长度/是否可用）。

use std::path::Path;

/// 加密私钥文件的魔数头（明文 PEM 不含它 → 旧文件可被自动识别并迁移）。
pub const KEY_MAGIC: &[u8] = b"AIGUARD-DPAPI-1\n";

/// macOS 钥匙串指针文件的魔数头。
///
/// 这不是密文本身：文件里只有 `魔数 + 账户名 + 换行`，私钥真身存在 login keychain 里。
/// 这样私钥文件即使被同步/备份/误拷贝，读到的也只是一个账户名。
pub const KEYCHAIN_MAGIC: &[u8] = b"AIGUARD-KEYCHAIN-1\n";

// ─────────────────────────── 调试器检测 ───────────────────────────

/// 当前进程是否被调试器附加（Windows：IsDebuggerPresent + CheckRemoteDebuggerPresent）。
///
/// 仅作**检测与告警**，不做反调试对抗（本项目是安全工具，不是反破解程序；
/// 误杀自身调试需求比漏报更糟）。
#[cfg(target_os = "windows")]
pub fn debugger_attached() -> bool {
    // windows-sys 0.61 起 BOOL 归到 `windows_sys::core`，
    // `Win32::Foundation` 不再转发它。
    use windows_sys::core::BOOL;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        CheckRemoteDebuggerPresent, IsDebuggerPresent,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        if IsDebuggerPresent() != 0 {
            return true;
        }
        let mut remote: BOOL = 0;
        let ok = CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote);
        ok != 0 && remote != 0
    }
}

/// Linux：读 `/proc/self/status` 的 `TracerPid`（被 ptrace 附加时非 0）。
///
/// 与 Windows 侧同一定位：**只检测、只告警**，不做反调试对抗。
/// 读不到文件（受限容器等）一律降级为「未检测到」，绝不阻断主流程。
#[cfg(target_os = "linux")]
pub fn debugger_attached() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("TracerPid:") {
            return v.trim().parse::<u32>().map(|pid| pid != 0).unwrap_or(false);
        }
    }
    false
}

/// macOS：`sysctl(KERN_PROC_PID)` 取自身 `kinfo_proc`，看 `p_flag` 的 `P_TRACED` 位。
///
/// ⚠ `libc` **不导出** `kinfo_proc` 与 `P_TRACED`（只导出 `sysctl` 与那三个 mib 常量），
/// 所以这里按 darwin 64 位 ABI 手写布局：
/// - `kinfo_proc` 前 32 字节是 `extern_proc` 的三个指针（`p_un` 16 + `p_vmspace` 8 +
///   `p_sigacts` 8），**`p_flag` 落在偏移 32**（4 字节，本机字节序）；
/// - `P_TRACED = 0x0000_0800`（xnu `bsd/sys/proc.h`）。
///
/// 这是**检测与告警**用途，且全部失败分支都降级为「未检测到」——加固检查的通用原则
/// 是「失败降级、只告警不阻断」，也把未来 ABI 变动的影响锁死在「少报一次」上。
#[cfg(target_os = "macos")]
pub fn debugger_attached() -> bool {
    const P_FLAG_OFFSET: usize = 32;
    const P_TRACED: u32 = 0x0000_0800;

    let mut size: libc::size_t = 0;
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        std::process::id() as libc::c_int,
    ];
    // 第一次调用：只问需要多大的缓冲区
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size < P_FLAG_OFFSET + 4 {
        return false;
    }
    let mut buf = vec![0u8; size];
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return false;
    }
    match p_flag_from_kinfo_proc(&buf) {
        Some(flag) => flag & P_TRACED != 0,
        None => false,
    }
}

/// 从 `kinfo_proc` 原始字节里取 `p_flag`（偏移 32，本机字节序）；越界返回 `None`。
///
/// 独立成纯函数是为了能在 macOS 上单测这个偏移读取，而不是把它揉在 sysctl 里。
#[cfg(target_os = "macos")]
fn p_flag_from_kinfo_proc(buf: &[u8]) -> Option<u32> {
    const P_FLAG_OFFSET: usize = 32;
    if buf.len() < P_FLAG_OFFSET + 4 {
        return None;
    }
    Some(u32::from_ne_bytes([
        buf[P_FLAG_OFFSET],
        buf[P_FLAG_OFFSET + 1],
        buf[P_FLAG_OFFSET + 2],
        buf[P_FLAG_OFFSET + 3],
    ]))
}

/// 其它平台（本项目未发布）：不做额外检测。
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub fn debugger_attached() -> bool {
    false
}

// ─────────────────────────── DPAPI（用户级） ───────────────────────────

/// 用 DPAPI 以**当前用户**为范围加密数据（密文只能被同一用户账户解密）。
/// 失败返回 `None`（调用方回退明文 + 告警，绝不阻断）。
#[cfg(target_os = "windows")]
pub fn dpapi_protect(plain: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: plain.len() as u32,
        pbData: plain.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // CRYPTPROTECT_UI_FORBIDDEN：绝不弹窗（GUI 进程后台调用必须禁 UI）
    let ok = unsafe {
        CryptProtectData(
            &mut input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 || out.pbData.is_null() {
        return None;
    }
    let blob = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(out.pbData as *mut core::ffi::c_void);
    }
    Some(blob)
}

#[cfg(not(target_os = "windows"))]
pub fn dpapi_protect(_plain: &[u8]) -> Option<Vec<u8>> {
    None
}

/// DPAPI 解密（仅同一用户账户可解）。失败返回 `None`。
#[cfg(target_os = "windows")]
pub fn dpapi_unprotect(blob: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 || out.pbData.is_null() {
        return None;
    }
    let plain = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(out.pbData as *mut core::ffi::c_void);
    }
    Some(plain)
}

#[cfg(not(target_os = "windows"))]
pub fn dpapi_unprotect(_blob: &[u8]) -> Option<Vec<u8>> {
    None
}

// ─────────────────────────── CA 私钥落盘 ───────────────────────────

/// 私钥文件的落盘状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAtRest {
    /// 已由系统密钥库保护（Windows DPAPI / macOS 钥匙串）
    Encrypted,
    /// 明文 PEM 落盘
    Plaintext,
    /// 文件不存在
    Absent,
}

/// 私钥文件里实际存的是什么形态。
///
/// 三个平台各有一种，靠魔数区分——**纯函数，任何平台都可单测**：
/// 平台差异只在「取出真身」那一步，识别逻辑不掺平台条件。
#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyStorage {
    /// Windows：DPAPI 密文（魔数 + 密文）
    Dpapi,
    /// macOS：钥匙串指针（魔数 + 账户名，真身在 login keychain）
    Keychain(String),
    /// 明文 PEM
    Plain,
}

fn sniff_key_storage(bytes: &[u8]) -> KeyStorage {
    if bytes.starts_with(KEY_MAGIC) {
        return KeyStorage::Dpapi;
    }
    if let Some(rest) = bytes.strip_prefix(KEYCHAIN_MAGIC) {
        let account = String::from_utf8_lossy(rest).trim().to_string();
        if !account.is_empty() {
            return KeyStorage::Keychain(account);
        }
    }
    KeyStorage::Plain
}

/// 读取私钥文件的落盘保护状态（只看文件头魔数，不解密）。
pub fn ca_key_at_rest(key_path: &Path) -> KeyAtRest {
    match std::fs::read(key_path) {
        Ok(bytes) => match sniff_key_storage(&bytes) {
            KeyStorage::Dpapi | KeyStorage::Keychain(_) => KeyAtRest::Encrypted,
            KeyStorage::Plain => KeyAtRest::Plaintext,
        },
        Err(_) => KeyAtRest::Absent,
    }
}

/// 写出私钥文件，并在 unix 上把权限收紧到 0600。
///
/// 明文落盘是**兜底**（平台没有系统密钥库时）：此时文件权限就是唯一的防线，
/// 因此必须显式 `set_permissions`——`fs::write` 建出来的文件受 umask 影响，
/// 宽松 umask（如 000）下会默认 0666，同机其它账户可读。
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ── macOS 钥匙串（等价于 Windows 的 DPAPI「仅当前用户可解」） ──

/// 钥匙串条目的服务名（与 `tauri.conf.json` 的 identifier 对齐）。
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "com.technicalflight.aiguard.ca-key";

/// 把私钥写进 login keychain。
///
/// ⚠ 密钥经 `-w` 参数传入，在进程存活的那一瞬间会出现在 `ps` 的参数里。
/// 这是 `security` 命令行工具唯一支持的非交互传值方式（交互式提示在 GUI
/// 子进程里不可用）；同一台机器上的单用户桌面场景可接受，且窗口极短。
#[cfg(target_os = "macos")]
fn keychain_store(account: &str, secret: &str) -> Result<(), String> {
    // ⚠ `security` CLI 的 `-w` 对**含控制字符**（如换行）的值不保真：实测多行
    // PEM 裸存后 `find -w` 回来的是整串**十六进制编码**——CLI 输出层认不出
    // 「可打印单行」就转 hex，尾部换行剥几层都救不回来（首个 macOS CI 的
    // 往返测试连红三轮就是这个坑）。入库前先 base64 编码：纯 ASCII 单行，
    // CLI 原样存取；读取侧解码回原字节，多行 PEM 逐字节保真。
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
    let out = std::process::Command::new("security")
        .args([
            "add-generic-password",
            "-U", // 已存在则更新，保证幂等
            "-a",
            account,
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
            &encoded,
        ])
        .output()
        .map_err(|e| format!("无法调用 security 命令: {}", crate::state::safe_err(&e)))?;
    if out.status.success() {
        return Ok(());
    }
    let err = crate::console::decode_console(&out.stderr);
    let msg: String = err.trim().lines().next().unwrap_or("").chars().take(160).collect();
    Err(if msg.is_empty() {
        "security add-generic-password 失败（未见错误详情）".to_string()
    } else {
        msg
    })
}

#[cfg(target_os = "macos")]
fn keychain_load(account: &str) -> Option<String> {
    let out = std::process::Command::new("security")
        .args([
            "find-generic-password",
            "-a",
            account,
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // `security -w` 会在输出末尾追加一层换行：只剥这一层（值本身以 base64
    // 存储，末字符不会是换行，所以「剥一层」在任何 CLI 版本下都恰好剥干净）。
    let mut raw = crate::console::decode_console(&out.stdout);
    if raw.ends_with('\n') {
        raw.pop();
        if raw.ends_with('\r') {
            raw.pop();
        }
    }
    if raw.is_empty() {
        return None;
    }
    // keychain_store 写入的是 base64：解回原字节，多行 PEM 逐字节保真。
    // 解不开（外部写入 / 旧格式）就按原文返回——宁可原文，也不让读取
    // 失败把私钥弄丢。
    use base64::Engine as _;
    match base64::engine::general_purpose::STANDARD.decode(raw.as_bytes()) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => Some(text),
            Err(_) => Some(raw),
        },
        Err(_) => Some(raw),
    }
}

#[cfg(not(target_os = "macos"))]
fn keychain_load(_account: &str) -> Option<String> {
    None
}

/// 钥匙串条目的账户名：由私钥文件路径派生。
///
/// 用路径而不是固定串，是为了让「同一台机器上的多个数据目录（多份配置）」
/// 各存各的，不会互相覆盖。
#[cfg(target_os = "macos")]
fn keychain_account(key_path: &Path) -> String {
    use sha1::{Digest as _, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(key_path.to_string_lossy().as_bytes());
    format!("ca-{}", hex::encode(&hasher.finalize()[..6]))
}

/// 保存 CA 私钥：优先交给系统密钥库，不可用时回退明文 + 0600 并告警。
///
/// 平台分工：
/// - Windows → DPAPI（当前用户范围加密）
/// - macOS   → login keychain（文件里只留一个账户名指针）
/// - Linux   → 没有可靠的系统级密钥库（libsecret 需要桌面会话与守护进程，
///   服务端/最小安装上不存在），因此**如实**明文落盘 + 0600，
///   并由 `ca_key_at_rest` 把这一事实回报给加固面板。
///
/// 返回是否成功加密（`false` = 明文落盘）。
pub fn save_ca_key(key_path: &Path, pem: &str) -> std::io::Result<bool> {
    #[cfg(target_os = "windows")]
    {
        if let Some(blob) = dpapi_protect(pem.as_bytes()) {
            let mut buf = Vec::with_capacity(KEY_MAGIC.len() + blob.len());
            buf.extend_from_slice(KEY_MAGIC);
            buf.extend_from_slice(&blob);
            write_private_file(key_path, &buf)?;
            return Ok(true);
        }
        log::warn!("DPAPI 不可用，CA 私钥将以明文落盘（文件权限 0600）");
    }
    #[cfg(target_os = "macos")]
    {
        let account = keychain_account(key_path);
        if keychain_store(&account, pem).is_ok() {
            let mut pointer = KEYCHAIN_MAGIC.to_vec();
            pointer.extend_from_slice(account.as_bytes());
            pointer.push(b'\n');
            write_private_file(key_path, &pointer)?;
            return Ok(true);
        }
        log::warn!("钥匙串不可用，CA 私钥将以明文落盘（文件权限 0600）");
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        log::warn!("当前平台没有系统密钥库，CA 私钥以明文落盘，依赖文件权限 0600 保护");
    }
    write_private_file(key_path, pem.as_bytes())?;
    Ok(false)
}

/// 载入 CA 私钥 PEM（自动识别密文 / 钥匙串指针 / 明文）。
///
/// 明文文件会被**就地迁移**为平台密文形态（内容不变 → 证书指纹不变，
/// 已安装进系统信任库的 CA 不会失配）；迁移失败只告警，仍返回明文内容。
pub fn load_ca_key_pem(key_path: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("读取 CA 私钥失败: {}", crate::state::safe_err(&e)))?;
    match sniff_key_storage(&bytes) {
        KeyStorage::Dpapi => {
            let blob = &bytes[KEY_MAGIC.len()..];
            let plain = dpapi_unprotect(blob).ok_or_else(|| {
                anyhow::anyhow!("CA 私钥解密失败（密文由其它用户账户加密？请重新生成证书）")
            })?;
            let pem = String::from_utf8(plain)
                .map_err(|_| anyhow::anyhow!("CA 私钥内容不是合法 UTF-8"))?;
            Ok(pem)
        }
        KeyStorage::Keychain(account) => {
            let pem = keychain_load(&account).ok_or_else(|| {
                anyhow::anyhow!("从系统钥匙串读取 CA 私钥失败（条目被删除或钥匙串已锁定？请重新生成证书）")
            })?;
            Ok(pem)
        }
        KeyStorage::Plain => {
            let pem = String::from_utf8(bytes.clone())
                .map_err(|_| anyhow::anyhow!("CA 私钥内容不是合法 UTF-8"))?;
            match save_ca_key(key_path, &pem) {
                Ok(true) => log::info!("CA 私钥已就地迁移为系统密钥库保护（证书本身未变）"),
                Ok(false) => {}
                Err(e) => log::warn!("CA 私钥加密迁移失败（保留明文）: {}", crate::state::safe_err(&e)),
            }
            Ok(pem)
        }
    }
}

// ───────────────────── 落库密钥（代理令牌）的加密编码 ─────────────────────

/// DPAPI 密文在 kv 里的文本前缀。
const SECRET_ENC_PREFIX: &str = "enc:";

/// 把明文密钥编码为可落库字符串：DPAPI 可用时存 `enc:<hex(密文)>`，否则原样存。
pub fn encode_secret_for_store(plain: &str) -> String {
    match dpapi_protect(plain.as_bytes()) {
        Some(blob) => format!("{}{}", SECRET_ENC_PREFIX, hex::encode(blob)),
        None => plain.to_string(),
    }
}

/// 解码落库字符串。返回 `(明文, 是否为旧明文格式需要迁移为密文)`。
///
/// 解密失败（如 Windows 账户口令重置导致 DPAPI 密钥变化）返回空明文，
/// 由调用方按「令牌不可用」重新生成——宁可使旧令牌失效，也不静默降级。
pub fn decode_secret_from_store(stored: &str) -> (String, bool) {
    match stored.strip_prefix(SECRET_ENC_PREFIX) {
        Some(hexpart) => {
            let plain = hex::decode(hexpart)
                .ok()
                .and_then(|b| dpapi_unprotect(&b))
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default();
            (plain, false)
        }
        None => (stored.to_string(), true),
    }
}

// ─────────────────────────── 端口占用诊断 ───────────────────────────

/// 单个端口的占用情况。
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortState {
    pub port: u16,
    /// "ready"（本进程正在监听）/ "free"（空闲）/ "occupied"（被其它进程占用）
    pub state: String,
    /// 占用者 PID（可查到时）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_pid: Option<u32>,
    /// 占用者可执行文件名/路径（同权限内可查到时）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_exe: Option<String>,
    /// 人类可读说明（直接用于界面提示）
    pub detail: String,
}

impl PortState {
    pub fn is_problem(&self) -> bool {
        self.state == "occupied"
    }
}

/// 判断某本地端口当前由「谁」占用。
///
/// 方法：先看 TCP 监听表里有归属进程 → 与我们同 PID 视为就绪；
/// 没有监听者时再试 `bind` 一次（能绑上=空闲）。比单纯 bind 更能区分
/// 「自己已经在监听」与「被别人占了」。
pub fn port_state(port: u16) -> PortState {
    if let Some(pid) = crate::process::pid_listening_on(port) {
        let me = std::process::id();
        let exe = crate::process::exe_path_of_pid(pid);
        let name = exe
            .as_deref()
            .map(|p| {
                Path::new(p)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| p.to_string())
            })
            .unwrap_or_else(|| "未知进程".to_string());
        if pid == me {
            return PortState {
                port,
                state: "ready".to_string(),
                owner_pid: Some(pid),
                owner_exe: exe,
                detail: format!("本应用正在监听 127.0.0.1:{}", port),
            };
        }
        return PortState {
            port,
            state: "occupied".to_string(),
            owner_pid: Some(pid),
            owner_exe: exe,
            detail: format!(
                "127.0.0.1:{} 已被其它程序占用（PID {} {}）——请关闭该程序或改用其它端口",
                port, pid, name
            ),
        };
    }
    // 无监听者：再试绑定确认（TIME_WAIT 等边界情况也能给出结论）
    match std::net::TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => {
            drop(l);
            PortState {
                port,
                state: "free".to_string(),
                owner_pid: None,
                owner_exe: None,
                detail: format!("127.0.0.1:{} 空闲可用", port),
            }
        }
        Err(e) => PortState {
            port,
            state: "occupied".to_string(),
            owner_pid: None,
            owner_exe: None,
            detail: format!("127.0.0.1:{} 无法绑定：{}", port, crate::state::safe_err(&e)),
        },
    }
}

// ─────────────────────────── 数据目录权限 ───────────────────────────

/// 数据目录权限评估结果。
#[derive(Debug, Clone, serde::Serialize)]
pub struct DirAcl {
    /// "user_only" | "shared" | "unknown"
    pub scope: String,
    /// 人类可读的 ACE 摘要（已剔除路径与本地化页脚，直接用于界面展示）
    pub detail: String,
}

/// 一条访问控制项（主体 + 权限串）。
///
/// `icacls` 是 Windows 专有的：这里整段（含下面三条解析规则）只在 Windows 构建里
/// 参与编译，**但测试在所有平台都跑**——解析是纯文本逻辑，在 macOS / Linux 上
/// 同样能把「主体名含空格被截断」这类回归测出来。
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct AceEntry {
    subject: String,
    perms: String,
}

/// 从 `icacls` 输出文本里提取访问控制项。
///
/// 三条关键规则：
/// 1. **只保留含 `:(` 的行**——结尾的本地化页脚（`Successfully processed …` /
///    「已成功处理 1 个文件; 处理 0 个文件时失败」）没有权限串，被自然排除，
///    不再依赖英文文案匹配；
/// 2. `icacls` 会把**路径与第一个访问项写在同一条输出行**上
///    （`C:\path SUBJECT:(F)`），所以先剥掉 `path_prefix`（我们以 `icacls .`
///    调用，那里就是 `.`）；
/// 3. **主体名可以含空格**（`NT AUTHORITY\SYSTEM`、`Authenticated Users`、
///    `Mandatory Label\Medium Mandatory Level`），因此剥离路径之后必须
///    取**整段**作为主体——绝不能"取最后一个空白分词"（会把
///    `NT AUTHORITY\SYSTEM` 截成 `AUTHORITY\SYSTEM`）。
#[cfg(any(target_os = "windows", test))]
fn parse_ace_entries(text: &str, path_prefix: &str) -> Vec<AceEntry> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_end();
        let Some(pos) = line.find(":(") else {
            continue;
        };
        let head = line[..pos].trim_end();
        let head = if path_prefix.is_empty() {
            head
        } else {
            head.strip_prefix(path_prefix).unwrap_or(head).trim_start()
        };
        if head.is_empty() {
            continue;
        }
        out.push(AceEntry {
            subject: head.to_string(),
            perms: line[pos..].trim().to_string(),
        });
    }
    out
}

/// 是否为「宽泛主体」——可能包含同机其它登录账户的主体。
///
/// 必须按**完整主体名**判定：`CodexSandboxUsers` 以 `Users` 结尾但它是一个
/// 自定义沙箱组（子串匹配 "Users:" 会把它误判成"同机其它账户可访问"）。
#[cfg(any(target_os = "windows", test))]
fn is_broad_subject(subject: &str) -> bool {
    let s = subject.trim().trim_start_matches('\\').to_ascii_lowercase();
    let tail = s.rsplit('\\').next().unwrap_or(s.as_str());
    matches!(
        tail,
        "users" | "everyone" | "authenticated users" | "interactive"
    ) || matches!(s.as_str(), "everyone" | "authenticated users" | "interactive")
}

/// 权限串里是否含写权限。
///
/// 权限串形如 `(I)(OI)(CI)(F)`；同一括号内可能是逗号分隔的组合权限
/// （`(R,W)`），因此逐括号拆 token 判定，而不是子串匹配——
/// 子串匹配会把 `(NW)`（no-write-up，来自强制完整性标签）里的 `W` 误当写权限。
#[cfg(any(target_os = "windows", test))]
fn has_write(perms: &str) -> bool {
    for grp in perms.split('(').skip(1) {
        let inner = grp.split(')').next().unwrap_or("");
        for tok in inner.split(',') {
            if matches!(tok.trim(), "F" | "M" | "W") {
                return true;
            }
        }
    }
    false
}

/// 纯函数：从 `icacls` 文本判定数据目录权限范围（便于单测，不碰系统调用）。
///
/// `path_prefix` 是调用 `icacls` 时传入的路径（生产路径下是 `.`），
/// 用于剥掉 `icacls` 在首行重复回显的路径。
#[cfg(any(target_os = "windows", test))]
pub fn parse_icacls_text_with_prefix(text: &str, path_prefix: &str) -> DirAcl {
    let entries = parse_ace_entries(text, path_prefix);
    if entries.is_empty() {
        return DirAcl {
            scope: "unknown".to_string(),
            detail: "未能从 icacls 输出中识别访问控制项".to_string(),
        };
    }
    let summary: String = entries
        .iter()
        .take(6)
        .map(|e| format!("{}{}", e.subject, e.perms))
        .collect::<Vec<_>>()
        .join("、");
    let summary = if summary.chars().count() > 260 {
        summary.chars().take(260).collect::<String>() + "…"
    } else {
        summary
    };

    match entries
        .iter()
        .find(|e| is_broad_subject(&e.subject) && has_write(&e.perms))
    {
        Some(hit) => DirAcl {
            scope: "shared".to_string(),
            detail: format!(
                "存在带写权限的宽泛主体 {}{}；当前访问项：{}",
                hit.subject, hit.perms, summary
            ),
        },
        None => DirAcl {
            scope: "user_only".to_string(),
            detail: format!("当前访问项：{}", summary),
        },
    }
}

/// 便捷入口：生产路径以 `icacls .` 调用，首行路径即 `.`。
/// 仅在测试里作为「不带路径前缀」的调用形式使用。
#[cfg(test)]
pub fn parse_icacls_text(text: &str) -> DirAcl {
    parse_icacls_text_with_prefix(text, ".")
}

/// 读取并评估数据目录的权限范围（Windows：`icacls`；unix：权限位）。
pub fn data_dir_acl(dir: &Path) -> DirAcl {
    #[cfg(target_os = "windows")]
    {
        return windows_dir_acl(dir);
    }
    #[cfg(unix)]
    {
        return unix_dir_acl(dir);
    }
    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = dir;
        DirAcl {
            scope: "unknown".to_string(),
            detail: "当前平台未实现目录权限评估".to_string(),
        }
    }
}

/// 纯函数：由 unix 权限位判定数据目录范围（便于单测，不碰系统调用）。
///
/// 语义与 Windows 侧对齐，回答的是同一个问题：「本用户之外的账户能不能进来」。
/// **只要组或其它用户有任何一位权限就算 shared**，读写都算——数据目录里放着
/// CA 私钥、会话映射表与审计库，同机其它账户连读都不该有。
#[cfg(any(unix, test))]
pub fn parse_unix_mode(mode: u32) -> DirAcl {
    let bits = format!("{:04o}", mode & 0o7777);
    let symbolic = symbolic_mode(mode);
    if mode & 0o077 == 0 {
        DirAcl {
            scope: "user_only".to_string(),
            detail: format!("权限位 {}（{}）；同组与其它账户无任何权限", bits, symbolic),
        }
    } else {
        DirAcl {
            scope: "shared".to_string(),
            detail: format!(
                "权限位 {}（{}）：同组或其它账户可访问，建议 chmod 700 收紧",
                bits, symbolic
            ),
        }
    }
}

/// `0700` → `rwx------`（只看低 9 位；setuid/setgid/sticky 不参与判定）。
#[cfg(any(unix, test))]
fn symbolic_mode(mode: u32) -> String {
    const CHARS: [(u32, char); 9] = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    let mut out = String::with_capacity(9);
    for (bit, ch) in CHARS {
        out.push(if mode & bit != 0 { ch } else { '-' });
    }
    out
}

#[cfg(unix)]
fn unix_dir_acl(dir: &Path) -> DirAcl {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(dir) {
        Ok(md) => parse_unix_mode(md.permissions().mode()),
        Err(e) => DirAcl {
            scope: "unknown".to_string(),
            detail: format!("无法读取数据目录权限: {}", crate::state::safe_err(&e)),
        },
    }
}

/// Windows：`icacls` 在中文系统上输出的是**系统代码页（GBK）字节**，必须经
/// [`crate::console::decode_console`] 解码，否则本地化页脚会变成乱码方块。
/// 无法执行 `icacls` 时返回 unknown（不阻断）。
#[cfg(target_os = "windows")]
fn windows_dir_acl(dir: &Path) -> DirAcl {
    let out = match run_icacls(dir) {
        Ok(o) => o,
        Err(e) => {
            return DirAcl {
                scope: "unknown".to_string(),
                detail: format!("无法执行 icacls: {}", crate::state::safe_err(&e)),
            }
        }
    };
    let text = if out.status.success() {
        crate::console::decode_console(&out.stdout)
    } else {
        crate::console::decode_console(&out.stderr)
    };
    if text.trim().is_empty() {
        return DirAcl {
            scope: "unknown".to_string(),
            detail: "icacls 未返回内容（可能被安全软件拦截）".to_string(),
        };
    }
    // 正常形态：`icacls .` → 首行路径为 `.`。
    // 兜底：万一 icacls 回显了绝对路径（或换了输出风格），用调用时的路径再剥一次。
    let acl = parse_icacls_text_with_prefix(&text, ".");
    if acl.scope != "unknown" {
        return acl;
    }
    let dir_str = dir.display().to_string();
    if dir_str.is_empty() {
        return acl;
    }
    let fallback = parse_icacls_text_with_prefix(&text, &dir_str);
    if fallback.scope != "unknown" {
        return fallback;
    }
    acl
}

/// 执行 `icacls` 并返回其原始输出。
///
/// 以 `current_dir(dir)` + 参数 `.` 调用（而不是传绝对路径）：
/// `icacls` 会在首行回显路径，传 `.` 时那句话就是 `. SUBJECT:(F)`，
/// 主体可以无歧义地整段取出——绝对路径里可能含空格，文本上无法与主体切分。
/// `Command` 上禁止弹出控制台窗口（Windows GUI 子进程调用会闪黑框）。
#[cfg(target_os = "windows")]
fn run_icacls(dir: &Path) -> std::io::Result<std::process::Output> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let mut cmd = std::process::Command::new("icacls");
    cmd.current_dir(dir).arg(".").creation_flags(CREATE_NO_WINDOW);
    cmd.output()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_at_rest_detects_plaintext_and_absent() {
        let dir = std::env::temp_dir().join(format!("aiguard_sec_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("ca.key");
        assert_eq!(ca_key_at_rest(&key), KeyAtRest::Absent);
        std::fs::write(&key, "-----BEGIN PRIVATE KEY-----\nabc\n").unwrap();
        assert_eq!(ca_key_at_rest(&key), KeyAtRest::Plaintext);
        let mut buf = KEY_MAGIC.to_vec();
        buf.extend_from_slice(&[1, 2, 3]);
        std::fs::write(&key, &buf).unwrap();
        assert_eq!(ca_key_at_rest(&key), KeyAtRest::Encrypted);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_dpapi_roundtrip() {
        let plain = b"-----BEGIN PRIVATE KEY-----\nsecret-material\n";
        let blob = dpapi_protect(plain).expect("DPAPI 加密应可用（用户级）");
        assert_ne!(blob.as_slice(), plain.as_slice(), "密文不得等于明文");
        let back = dpapi_unprotect(&blob).expect("DPAPI 解密应可用");
        assert_eq!(back, plain);
        // 被篡改的密文必须解密失败而不是返回垃圾
        let mut bad = blob.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xFF;
        assert!(dpapi_unprotect(&bad).is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_save_and_load_ca_key_roundtrip_and_migration() {
        let dir = std::env::temp_dir().join(format!("aiguard_sec2_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("ca.key");
        let pem = "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----\n";

        // 明文（旧版本遗留）→ 载入时应自动迁移为密文
        std::fs::write(&key, pem).unwrap();
        let loaded = load_ca_key_pem(&key).expect("明文应可载入");
        assert_eq!(loaded, pem);
        assert_eq!(
            ca_key_at_rest(&key),
            KeyAtRest::Encrypted,
            "明文私钥必须被就地迁移为密文"
        );
        // 迁移后仍能读回同一内容（指纹不变）
        let again = load_ca_key_pem(&key).expect("密文应可载入");
        assert_eq!(again, pem);

        // 显式加密保存
        assert!(save_ca_key(&key, pem).unwrap());
        assert_eq!(load_ca_key_pem(&key).unwrap(), pem);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_port_state_for_current_process_or_free() {
        // 绑一个端口并持有 → 状态必须是 ready（自己）而不是 occupied
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        let st = port_state(port);
        assert!(
            st.state == "ready" || st.state == "occupied",
            "持有端口时不应判为空闲: {:?}",
            st.state
        );
        drop(l);
        let st2 = port_state(port);
        assert_eq!(st2.state, "free", "释放后应为空闲: {}", st2.detail);
    }

    #[test]
    fn test_debugger_detection_does_not_panic() {
        // 只要求可调用且不 panic（CI 与手工运行结果都可能不同）
        let _ = debugger_attached();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_secret_store_roundtrip_and_migration_flag() {
        let token = "0123456789abcdef0123456789abcdef";
        let enc = encode_secret_for_store(token);
        assert!(enc.starts_with("enc:"), "DPAPI 可用时应加密落库");
        assert!(!enc.contains(token), "落库内容不得含明文");
        let (plain, need_migrate) = decode_secret_from_store(&enc);
        assert_eq!(plain, token);
        assert!(!need_migrate, "密文不需要迁移");
        // 旧版明文形态：解出原文 + 标记需迁移
        let (plain2, need_migrate2) = decode_secret_from_store(token);
        assert_eq!(plain2, token);
        assert!(need_migrate2, "明文必须被标记为待迁移");
        // 密文被破坏 → 解不出内容（调用方据此重新生成，绝不静默降级）
        let (broken, _) = decode_secret_from_store("enc:00ff00ff");
        assert!(broken.is_empty());
    }

    #[test]
    fn test_data_dir_acl_returns_known_scope() {
        let acl = data_dir_acl(&std::env::temp_dir());
        assert!(
            acl.scope == "user_only" || acl.scope == "shared" || acl.scope == "unknown",
            "scope 取值必须受控: {}",
            acl.scope
        );
        // 中文 Windows 上曾经解出 U+FFFD 方块（GBK 页脚被当 UTF-8）
        assert!(
            !acl.detail.contains('\u{FFFD}'),
            "ACL 摘要不得含替换字符（编码回归）: {}",
            acl.detail
        );
    }

    /// 本机真实形态（`icacls .` 的实测输出）：首行 `. 主体:(权限)`，
    /// 后续 ACE 行有缩进。`CodexSandboxUsers` 以 Users 结尾但**不是**宽泛主体
    /// （旧实现按子串匹配 "Users:" 会误判成"同机其它账户可访问"）。
    #[test]
    fn test_parse_icacls_real_world_user_only() {
        let text = [
            r". simple\CodexSandboxUsers:(I)(OI)(CI)(RX)",
            r"  NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)",
            r"  BUILTIN\Administrators:(I)(OI)(CI)(F)",
            r"  SIMPLE\s1mple:(I)(OI)(CI)(F)",
            "",
            "已成功处理 1 个文件; 处理 0 个文件时失败",
        ]
        .join("\r\n");
        let acl = parse_icacls_text(&text);
        assert_eq!(acl.scope, "user_only", "实际: {}", acl.detail);
        assert!(
            acl.detail.contains(r"simple\CodexSandboxUsers:(I)(OI)(CI)(RX)"),
            "{}",
            acl.detail
        );
        assert!(acl.detail.contains(r"SIMPLE\s1mple:(I)(OI)(CI)(F)"), "{}", acl.detail);
        // 回归：主体名含空格时必须整段保留（曾被截成 "AUTHORITY\SYSTEM"）
        assert!(
            acl.detail.contains(r"NT AUTHORITY\SYSTEM:"),
            "含空格的主体被截断了: {}",
            acl.detail
        );
        // 路径前缀与本地化页脚都必须被剔除
        assert!(!acl.detail.contains("AppData"), "路径不应出现在摘要: {}", acl.detail);
        assert!(!acl.detail.contains("已成功处理"), "本地化页脚不应出现在摘要: {}", acl.detail);
    }

    /// 兜底形态：icacls 若回显绝对路径，用调用时的路径前缀剥掉。
    #[test]
    fn test_parse_icacls_absolute_path_prefix() {
        let dir = r"C:\Program Files\My App\data";
        let text = [
            format!(r"{dir} NT AUTHORITY\Authenticated Users:(OI)(CI)(M)"),
            r"                                                     SIMPLE\s1mple:(OI)(CI)(F)".to_string(),
        ]
        .join("\r\n");
        let acl = parse_icacls_text_with_prefix(&text, dir);
        assert_eq!(acl.scope, "shared", "实际: {}", acl.detail);
        assert!(
            acl.detail.contains(r"NT AUTHORITY\Authenticated Users:(OI)(CI)(M)"),
            "含空格的宽泛主体应被识别并整段保留: {}",
            acl.detail
        );
    }

    /// 真正的宽泛主体（BUILTIN\Users 带写权限）必须判为 shared。
    #[test]
    fn test_parse_icacls_detects_broad_writer() {
        let text = [
            r". BUILTIN\Administrators:(OI)(CI)(F)",
            r"  BUILTIN\Users:(OI)(CI)(F)",
        ]
        .join("\r\n");
        let acl = parse_icacls_text(&text);
        assert_eq!(acl.scope, "shared", "实际: {}", acl.detail);
        assert!(acl.detail.contains(r"BUILTIN\Users:(OI)(CI)(F)"), "{}", acl.detail);

        // Everyone 只读 → 不算共享可写
        let ro = parse_icacls_text(
            &[
                r". Everyone:(OI)(CI)(RX)",
                r"  SIMPLE\s1mple:(OI)(CI)(F)",
            ]
            .join("\r\n"),
        );
        assert_eq!(ro.scope, "user_only", "只读的 Everyone 不应判为共享: {}", ro.detail);
    }

    /// `(NW)`（no-write-up，强制完整性标签）不得被当成写权限。
    #[test]
    fn test_parse_icacls_ignores_no_write_up() {
        let text = [
            r". SIMPLE\s1mple:(OI)(CI)(F)",
            r"  Mandatory Label\Medium Mandatory Level:(OI)(CI)(NW)",
        ]
        .join("\r\n");
        let acl = parse_icacls_text(&text);
        assert_eq!(acl.scope, "user_only", "(NW) 不是写权限: {}", acl.detail);
    }

    #[test]
    fn test_parse_icacls_garbage_is_unknown() {
        assert_eq!(parse_icacls_text("").scope, "unknown");
        assert_eq!(parse_icacls_text("random text without acl").scope, "unknown");
    }

    /// unix 权限位判定：**只要组/其它账户有一位权限就是 shared**。
    ///
    /// 这里特意把「只读」的两种形态也钉住（`0704` 其它账户可读、`0750` 组可读）：
    /// 数据目录里有 CA 私钥、会话映射与审计库，同机其它账户连读都不该有。
    #[test]
    fn test_parse_unix_mode_scope() {
        let only = parse_unix_mode(0o700);
        assert_eq!(only.scope, "user_only", "{}", only.detail);
        assert!(only.detail.contains("0700"), "{}", only.detail);
        assert!(only.detail.contains("rwx------"), "{}", only.detail);

        assert_eq!(parse_unix_mode(0o704).scope, "shared", "其它账户可读也算共享");
        assert_eq!(parse_unix_mode(0o750).scope, "shared", "组可读也算共享");
        assert_eq!(parse_unix_mode(0o770).scope, "shared");
        assert_eq!(parse_unix_mode(0o777).scope, "shared");
        let shared = parse_unix_mode(0o750);
        assert!(shared.detail.contains("0750") && shared.detail.contains("rwxr-x---"), "{}", shared.detail);
    }

    /// 三种落盘形态必须靠魔数区分开——平台差异只在「取出真身」那一步。
    #[test]
    fn test_sniff_key_storage_distinguishes_three_forms() {
        assert_eq!(sniff_key_storage(KEY_MAGIC), KeyStorage::Dpapi);
        let mut dpapi = KEY_MAGIC.to_vec();
        dpapi.extend_from_slice(&[1, 2, 3]);
        assert_eq!(sniff_key_storage(&dpapi), KeyStorage::Dpapi);

        let mut pointer = KEYCHAIN_MAGIC.to_vec();
        pointer.extend_from_slice(b"ca-abcdef123456\n");
        assert_eq!(
            sniff_key_storage(&pointer),
            KeyStorage::Keychain("ca-abcdef123456".to_string())
        );

        // 只有魔数、没有账户名 → 认不出来，按明文处理。
        // 宁可当明文重读一次，也绝不能静默当成「已加密」（那会把私钥弄丢）。
        assert_eq!(sniff_key_storage(KEYCHAIN_MAGIC), KeyStorage::Plain);
        assert_eq!(
            sniff_key_storage(b"-----BEGIN PRIVATE KEY-----\n"),
            KeyStorage::Plain
        );
    }

    /// 钥匙串指针文件在加固面板里必须显示为「已加密」而不是「明文」。
    #[test]
    fn test_key_at_rest_reports_keychain_pointer_as_encrypted() {
        let dir = std::env::temp_dir().join(format!("aiguard_kc_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("ca.key");
        let mut pointer = KEYCHAIN_MAGIC.to_vec();
        pointer.extend_from_slice(b"ca-001122334455\n");
        std::fs::write(&key, &pointer).unwrap();
        assert_eq!(ca_key_at_rest(&key), KeyAtRest::Encrypted);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// unix：私钥文件权限必须是 0600。
    ///
    /// 平台没有系统密钥库时（Linux），文件权限是**唯一**防线；而 `fs::write` 建出来的
    /// 文件受 umask 影响，宽松 umask 下会默认 0666 → 同机其它账户可读。
    #[cfg(unix)]
    #[test]
    fn test_key_file_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("aiguard_mode_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("ca.key");
        let pem = "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----\n";
        let _ = save_ca_key(&key, pem);
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "私钥文件权限必须收紧到 0600，实际 {:04o}", mode);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// macOS：钥匙串往返（等价于 Windows 的 DPAPI 往返）。
    ///
    /// CI 上的钥匙串状态不可控（未解锁 / 无登录会话），因此存不进去就跳过——
    /// 与 GBK 那两条测试按代码页跳过是同一个道理。
    #[cfg(target_os = "macos")]
    #[test]
    fn test_keychain_roundtrip() {
        let account = "aiguard-test-roundtrip";
        let pem = "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----\n";
        if keychain_store(account, pem).is_err() {
            eprintln!("钥匙串不可用，跳过往返测试");
            return;
        }
        // 入库走 base64、读取侧解码：往返必须**逐字节**一致（含结尾换行）。
        // expect 先把「读不回」与「读回但不同」区分开。
        let loaded = keychain_load(account)
            .expect("刚写入的钥匙串条目应能读回（读取通道坏了）");
        assert_eq!(loaded, pem, "钥匙串往返后必须逐字节一致（含结尾换行）");
        let _ = std::process::Command::new("security")
            .args([
                "delete-generic-password",
                "-a",
                account,
                "-s",
                KEYCHAIN_SERVICE,
            ])
            .output();
    }
}
