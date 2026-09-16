//! 系统代理配置：把 PAC 地址写进操作系统，让浏览器只把 AI 域名交给本地守护代理。
//!
//! 三个平台各走原生通道：
//! - **Windows**：注册表 `HKCU\…\Internet Settings` 的 `AutoConfigURL` + 通知 WinINET 刷新
//! - **macOS**：`networksetup -setautoproxyurl / -setautoproxystate`（逐个网络服务）
//! - **Linux**：GNOME 的 `gsettings org.gnome.system.proxy`
//!
//! 三者的共同约定（刻意保持一致，避免"换个平台行为就变"）：
//! 1. **只用 PAC 模式，绝不设手动全局代理**。浏览器在 PAC 获取失败时会回退到
//!    手动代理，那会把清单外的域名也塞进本地代理而 502（Windows 侧踩过这个坑）。
//! 2. PAC 地址用**本地 HTTP 服务**而不是 `file://`：Chromium 对 file:// PAC
//!    偶发获取失败，同样触发回退。
//! 3. 关闭时只清我们自己写的那一项，不动用户原有的代理设置。

use std::fs;
use std::io::Write;
use std::path::Path;

/// 生成 PAC 文件内容。域名列表直接取自 state::AI_HOSTS，单一维护源。
///
/// 匹配规则与 is_ai_host 一致：精确清单 + **注册域后缀**（dnsDomainIs）——
/// 后者覆盖动态分配的子域（如 DeepSeek 文件上传的 `hf-xxxx.deepseek.com`）。
/// `custom_hosts` 为用户自定义接管域名（中转 API 等），按精确域名追加。
pub fn pac_content(port: u16, custom_hosts: &[String]) -> String {
    let proxy = format!("\"PROXY 127.0.0.1:{}\"", port);
    let mut exact: Vec<String> = crate::state::AI_HOSTS
        .iter()
        .map(|h| format!("host === \"{}\"", h))
        .collect();
    for h in custom_hosts {
        exact.push(format!("host === \"{}\"", h));
    }
    let suffixes: Vec<String> = crate::state::AI_HOST_SUFFIXES
        .iter()
        .map(|s| {
            format!(
                "dnsDomainIs(host, \"{}\") || host === \"{}\"",
                s,
                &s[1..]
            )
        })
        .collect();
    format!(
        r#"// AI 安全卫士 PAC 脚本 —— 仅将 AI 域名流量导向本地守护代理
function FindProxyForURL(url, host) {{
    if ({exact}) return {proxy};
    if ({sfx}) return {proxy};
    return "DIRECT";
}}
"#,
        exact = exact.join(" ||\n        "),
        sfx = suffixes.join(" ||\n        "),
        proxy = proxy
    )
}

/// 将 PAC 文件写入指定路径。
///
/// 生产路径已改为由常驻 PAC 服务按请求动态生成（内容随守护开关变化），
/// 这里保留「写盘」形态供测试与离线排查使用。
#[allow(dead_code)]
pub fn write_pac(path: &Path, port: u16) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut f = fs::File::create(path).map_err(|e| e.to_string())?;
    f.write_all(pac_content(port, &[]).as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub const PAC_HTTP_PORT: u16 = 8889;

pub fn pac_http_url() -> String {
    format!("http://127.0.0.1:{}/pac", PAC_HTTP_PORT)
}

/// 按守护开关状态动态生成 PAC 内容：
/// 守护关闭 → 全部直连；开启 → 仅 AI 域名走本地代理（含用户自定义接管域名）。
/// （PAC 服务每请求实时生成，开关守护 / 改域名清单即时生效，无需改系统设置。）
pub fn dynamic_pac_content(guard_enabled: bool, proxy_port: u16, custom_hosts: &[String]) -> String {
    if !guard_enabled {
        return "function FindProxyForURL(url, host) {\r\n    return \"DIRECT\";\r\n}"
            .to_string();
    }
    pac_content(proxy_port, custom_hosts)
}

// ═══════════════════════ 系统代理：开启 ═══════════════════════

/// 开启系统代理（PAC 模式）。失败时返回可直接展示给用户的中文原因。
pub fn set_system_proxy_pac(pac_url: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        return windows_set_pac(pac_url);
    }
    #[cfg(target_os = "macos")]
    {
        return macos_set_pac(pac_url);
    }
    #[cfg(target_os = "linux")]
    {
        return linux_set_pac(pac_url);
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = pac_url;
        Err("当前平台尚未实现系统代理设置，请手动把 PAC 地址配到浏览器".to_string())
    }
}

/// 关闭系统代理并还原我们改过的那一项。
pub fn disable_system_proxy() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        return windows_clear_pac();
    }
    #[cfg(target_os = "macos")]
    {
        return macos_clear_pac();
    }
    #[cfg(target_os = "linux")]
    {
        return linux_clear_pac();
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Ok(())
    }
}

// ─────────────────────────── Windows ───────────────────────────

#[cfg(target_os = "windows")]
const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// 通知 WinINET 配置已变更并立即刷新。
#[cfg(target_os = "windows")]
fn refresh_internet_settings() {
    // InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0)
    unsafe {
        windows_sys::Win32::Networking::WinInet::InternetSetOptionW(
            std::ptr::null_mut(),
            39, // INTERNET_OPTION_SETTINGS_CHANGED
            std::ptr::null_mut(),
            0,
        );
        windows_sys::Win32::Networking::WinInet::InternetSetOptionW(
            std::ptr::null_mut(),
            37, // INTERNET_OPTION_REFRESH
            std::ptr::null_mut(),
            0,
        );
    }
}

/// 写 `AutoConfigURL` 并显式关掉手动全局代理（`ProxyEnable=0`）。
///
/// 两者不能同时为真：浏览器在 PAC 异常时会回退到手动全局代理，
/// 导致清单外的域名也被塞进代理而 502。
#[cfg(target_os = "windows")]
fn windows_set_pac(pac_url: &str) -> Result<(), String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let settings = hkcu
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_SET_VALUE)
        .map_err(|e| e.to_string())?;
    settings
        .set_value("ProxyEnable", &0u32)
        .map_err(|e| e.to_string())?;
    let _ = settings.delete_value("ProxyServer");
    settings
        .set_value("AutoConfigURL", &pac_url.to_string())
        .map_err(|e| e.to_string())?;
    refresh_internet_settings();
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_clear_pac() -> Result<(), String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let settings = hkcu
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_SET_VALUE)
        .map_err(|e| e.to_string())?;
    settings
        .set_value("ProxyEnable", &0u32)
        .map_err(|e| e.to_string())?;
    let _ = settings.delete_value("AutoConfigURL");
    refresh_internet_settings();
    Ok(())
}

// ─────────────────────────── macOS ───────────────────────────

/// 解析 `networksetup -listallnetworkservices` 的输出。
///
/// 首行是说明文字（"An asterisk (*) denotes that a network service is disabled."），
/// 其余每行一个服务名；**以 `*` 开头表示该服务已停用**——对它调
/// `-setautoproxyurl` 会被 networksetup 拒绝，因此要跳过（而不是把 `*` 剥掉硬配）。
#[cfg(any(target_os = "macos", test))]
pub fn parse_networksetup_services(text: &str) -> Vec<String> {
    text.lines()
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(|l| l.to_string())
        .collect()
}

/// 生成「逐个网络服务开启 PAC」的命令行参数表。
///
/// 抽成纯函数是为了能在开发机（Windows）上单测参数顺序与引号形态——
/// `networksetup` 的服务名含空格（`Thunderbolt Bridge`），传参必须走独立 argv
/// 而不是拼成一整条 shell 串。
#[cfg(any(target_os = "macos", test))]
pub fn macos_set_pac_plan(services: &[String], pac_url: &str) -> Vec<Vec<String>> {
    let mut plan = Vec::new();
    for svc in services {
        plan.push(vec![
            "-setautoproxyurl".to_string(),
            svc.clone(),
            pac_url.to_string(),
        ]);
        plan.push(vec![
            "-setautoproxystate".to_string(),
            svc.clone(),
            "on".to_string(),
        ]);
    }
    plan
}

/// 生成「逐个网络服务关闭 PAC」的命令行参数表（只关状态，不清 URL，
/// 保留用户可自行改回）。
#[cfg(any(target_os = "macos", test))]
pub fn macos_clear_pac_plan(services: &[String]) -> Vec<Vec<String>> {
    services
        .iter()
        .map(|svc| {
            vec![
                "-setautoproxystate".to_string(),
                svc.clone(),
                "off".to_string(),
            ]
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn networksetup_services() -> Result<Vec<String>, String> {
    let out = std::process::Command::new("/usr/sbin/networksetup")
        .arg("-listallnetworkservices")
        .output()
        .map_err(|e| {
            format!(
                "无法调用 networksetup（系统代理设置不可用）: {}",
                crate::state::safe_err(&e)
            )
        })?;
    let text = crate::console::decode_console(&out.stdout);
    let services = parse_networksetup_services(&text);
    if services.is_empty() {
        return Err("未找到可用的网络服务（所有网络服务都处于停用状态？）".to_string());
    }
    Ok(services)
}

#[cfg(target_os = "macos")]
fn run_networksetup(args: &[String]) -> Result<(), String> {
    let out = std::process::Command::new("/usr/sbin/networksetup")
        .args(args)
        .output()
        .map_err(|e| format!("调用 networksetup 失败: {}", crate::state::safe_err(&e)))?;
    if out.status.success() {
        return Ok(());
    }
    let (stdout, stderr) = crate::console::decode_output(&out);
    let msg: String = if stderr.trim().is_empty() { stdout } else { stderr }
        .trim()
        .chars()
        .take(160)
        .collect();
    Err(if msg.is_empty() {
        format!("networksetup {} 失败", args.join(" "))
    } else {
        msg
    })
}

#[cfg(target_os = "macos")]
fn macos_set_pac(pac_url: &str) -> Result<(), String> {
    let services = networksetup_services()?;
    for args in macos_set_pac_plan(&services, pac_url) {
        run_networksetup(&args)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_clear_pac() -> Result<(), String> {
    let services = networksetup_services()?;
    for args in macos_clear_pac_plan(&services) {
        run_networksetup(&args)?;
    }
    Ok(())
}

// ─────────────────────────── Linux ───────────────────────────

/// GNOME 的代理设置路径（gsettings schema）。
#[cfg(target_os = "linux")]
const GNOME_PROXY_SCHEMA: &str = "org.gnome.system.proxy";

#[cfg(target_os = "linux")]
fn run_gsettings(args: &[&str]) -> Result<(), String> {
    let out = std::process::Command::new("gsettings")
        .args(args)
        .output()
        .map_err(|e| {
            format!(
                "无法调用 gsettings（桌面环境不是 GNOME？）: {}",
                crate::state::safe_err(&e)
            )
        })?;
    if out.status.success() {
        return Ok(());
    }
    let (stdout, stderr) = crate::console::decode_output(&out);
    let msg: String = if stderr.trim().is_empty() { stdout } else { stderr }
        .trim()
        .chars()
        .take(160)
        .collect();
    Err(if msg.is_empty() {
        "gsettings 执行失败".to_string()
    } else {
        msg
    })
}

/// Linux：GNOME 系桌面用 gsettings 配 PAC。
///
/// 若当前环境没有 gsettings（非 GNOME / 无桌面会话），明确报错并给出可操作的
/// 替代方案，而不是静默什么也不做——「守护开着但浏览器没走代理」是最糟的结局：
/// 用户以为受保护，实际明文直连。
#[cfg(target_os = "linux")]
fn linux_set_pac(pac_url: &str) -> Result<(), String> {
    run_gsettings(&["set", GNOME_PROXY_SCHEMA, "mode", "auto"])?;
    run_gsettings(&["set", GNOME_PROXY_SCHEMA, "autoconfig-url", pac_url])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_clear_pac() -> Result<(), String> {
    run_gsettings(&["set", GNOME_PROXY_SCHEMA, "mode", "none"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pac_content_contains_hosts_and_direct() {
        let pac = pac_content(8888, &[]);
        assert!(pac.contains("api.openai.com"));
        assert!(pac.contains("PROXY 127.0.0.1:8888"));
        assert!(pac.contains("DIRECT"));
        assert!(pac.contains("FindProxyForURL"));
    }

    #[test]
    fn test_write_pac() {
        let dir = std::env::temp_dir().join(format!("aiguard_pac_{}", uuid::Uuid::new_v4()));
        let pac = dir.join("aiguard.pac");
        write_pac(&pac, 8888).unwrap();
        let content = std::fs::read_to_string(&pac).unwrap();
        assert!(content.contains("api.anthropic.com"));
        // 网页端对话域名必须收录（网页版走的主机名不是 api.*）
        assert!(content.contains("chat.deepseek.com"));
        assert!(content.contains("chatgpt.com"));
        assert!(content.contains("claude.ai"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 守护关闭时 PAC 必须整体直连（否则关掉守护后浏览器仍在走已停的代理端口）。
    #[test]
    fn test_dynamic_pac_content_short_circuits_when_disabled() {
        let off = dynamic_pac_content(false, 8888, &[]);
        assert!(off.contains("DIRECT"));
        assert!(!off.contains("PROXY 127.0.0.1:8888"));
        let on = dynamic_pac_content(true, 8888, &[]);
        assert!(on.contains("PROXY 127.0.0.1:8888"));
    }

    /// `networksetup` 的服务名列表：首行说明与停用服务（`*` 开头）都要跳过。
    #[test]
    fn test_parse_networksetup_services() {
        let text = [
            "An asterisk (*) denotes that a network service is disabled.",
            "Wi-Fi",
            "Thunderbolt Bridge",
            "",
            "*Bluetooth PAN",
            "USB 10/100/1000 LAN",
        ]
        .join("\n");
        let got = parse_networksetup_services(&text);
        assert_eq!(
            got,
            vec![
                "Wi-Fi".to_string(),
                "Thunderbolt Bridge".to_string(),
                "USB 10/100/1000 LAN".to_string()
            ],
            "停用服务与首行说明都必须被剔除"
        );
        assert!(parse_networksetup_services("").is_empty());
    }

    /// macOS 参数表：每个服务两条命令，且服务名必须是**独立 argv**
    /// （含空格的服务名拼成一条串会被 networksetup 当成多个参数）。
    #[test]
    fn test_macos_set_pac_plan_argument_shape() {
        let services = vec!["Wi-Fi".to_string(), "Thunderbolt Bridge".to_string()];
        let plan = macos_set_pac_plan(&services, "http://127.0.0.1:8889/pac");
        assert_eq!(plan.len(), 4, "两个服务各两条命令");
        assert_eq!(
            plan[0],
            vec!["-setautoproxyurl", "Wi-Fi", "http://127.0.0.1:8889/pac"]
        );
        assert_eq!(plan[1], vec!["-setautoproxystate", "Wi-Fi", "on"]);
        assert_eq!(plan[2][1], "Thunderbolt Bridge", "含空格的服务名占一个参数位");
        assert_eq!(plan[3], vec!["-setautoproxystate", "Thunderbolt Bridge", "on"]);

        let clear = macos_clear_pac_plan(&services);
        assert_eq!(clear.len(), 2);
        assert_eq!(clear[0], vec!["-setautoproxystate", "Wi-Fi", "off"]);
    }
}
