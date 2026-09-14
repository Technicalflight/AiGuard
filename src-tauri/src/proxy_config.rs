//! Windows 系统代理配置：注册表写入 + PAC 文件生成。
//! 仅支持 Windows；其他平台调用会返回错误信息（前端按钮已隐藏/提示）。

use std::fs;
use std::io::Write;
use std::path::Path;

use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
use winreg::RegKey;

/// Internet Settings 注册表路径
const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// 生成 PAC 文件内容。域名列表直接取自 state::AI_HOSTS，单一维护源。
///
/// 匹配规则与 is_ai_host 一致：精确清单 + **注册域后缀**（dnsDomainIs）——
/// 后者覆盖动态分配的子域（如 DeepSeek 文件上传的 `hf-xxxx.deepseek.com`）。
pub fn pac_content(port: u16) -> String {
    let proxy = format!("\"PROXY 127.0.0.1:{}\"", port);
    let exact: Vec<String> = crate::state::AI_HOSTS
        .iter()
        .map(|h| format!("host === \"{}\"", h))
        .collect();
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
    f.write_all(pac_content(port).as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// 通知 WinINET 配置已变更并立即刷新。
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

/// 开启系统代理：**仅 PAC 模式**（写 AutoConfigURL，显式关闭手动全局代理）。
///
/// PAC 地址使用**本地 HTTP 服务**（`pac_http_url()`）而非 file:// ——
/// Chromium 对 file:// PAC 偶发获取失败会回退直连/全局代理，导致守护"不生效"。
/// 不能同时设置 ProxyEnable=1 + ProxyServer：浏览器在 PAC 异常时会回退到
/// 手动全局代理，导致清单外的域名也被塞进代理而 502。
pub fn set_system_proxy_pac(pac_url: &str) -> Result<(), String> {
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

pub const PAC_HTTP_PORT: u16 = 8889;

pub fn pac_http_url() -> String {
    format!("http://127.0.0.1:{}/pac", PAC_HTTP_PORT)
}

/// 按守护开关状态动态生成 PAC 内容：
/// 守护关闭 → 全部直连；开启 → 仅 AI 域名走本地代理。
/// （PAC 服务每请求实时生成，开关守护即时生效，无需改注册表。）
pub fn dynamic_pac_content(guard_enabled: bool, proxy_port: u16) -> String {
    if !guard_enabled {
        return "function FindProxyForURL(url, host) {\r\n    return \"DIRECT\";\r\n}"
            .to_string();
    }
    pac_content(proxy_port)
}

/// 关闭系统代理并还原注册表。
pub fn disable_system_proxy() -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pac_content_contains_hosts_and_direct() {
        let pac = pac_content(8888);
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
}
