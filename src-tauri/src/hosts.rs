//! hosts 文件管理：AI 域名 → 127.0.0.1 的标记块写入 / 移除。
//!
//! hosts 文件位于 System32 下，普通用户只读——写入需要 **管理员权限**：
//! 通过 `Start-Process -Verb RunAs` 弹 UAC，由提权的 PowerShell 执行临时脚本，
//! 结果写入临时文件供主进程校验。标记块格式保证幂等（先删旧块再写新块），
//! 且绝不触碰用户已有的其他 hosts 条目。

use std::os::windows::process::CommandExt;
use std::path::PathBuf;

pub const HOSTS_BEGIN: &str = "# >>> AI Safety Guard (do not remove)";
pub const HOSTS_END: &str = "# <<< AI Safety Guard";

/// 构建 hosts 标记块（每个 AI 域名一行 127.0.0.1）。
pub fn build_block(hosts: &[&str]) -> String {
    let mut lines = vec![HOSTS_BEGIN.to_string()];
    for h in hosts {
        lines.push(format!("127.0.0.1 {}", h));
    }
    lines.push(HOSTS_END.to_string());
    lines.join("\r\n")
}

/// 判断 hosts 内容中是否已存在标记块。
pub fn block_present(content: &str) -> bool {
    content.contains(HOSTS_BEGIN) && content.contains(HOSTS_END)
}

/// 系统 hosts 文件路径。
pub fn hosts_path() -> PathBuf {
    PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
}

/// 清空系统 DNS 缓存（`ipconfig /flushdns`，普通权限即可）。
///
/// hosts 块写入/删除后，系统与浏览器的 DNS 缓存仍指向旧地址，
/// 不清缓存会导致模式切换"不生效"（实测：用户需要重开代理开关才恢复）。
pub fn flush_dns_cache() {
    let _ = std::process::Command::new("ipconfig")
        .arg("/flushdns")
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output();
}

/// 读取 hosts 文件内容（普通用户可读）。
///
/// 用户常在 hosts 里写中文注释并以 **GBK** 保存，此时 `read_to_string` 会直接失败，
/// 报错还会误导成「可能需要管理员权限」。因此按字节读取后再按系统代码页解码。
pub fn read_hosts() -> Result<String, String> {
    crate::console::read_text_file(&hosts_path()).map_err(|e| {
        format!(
            "读取 hosts 文件失败（可能需要管理员权限）: {}",
            crate::state::safe_err(&e)
        )
    })
}

/// 检查 hosts 文件中是否已存在本应用的域名块（无需管理员权限）。
/// 用于决定是否需要弹 UAC 做清理——块不存在时跳过提权。
pub fn hosts_block_exists() -> bool {
    match read_hosts() {
        Ok(c) => block_present(&c),
        Err(_) => false,
    }
}

/// 以管理员权限（UAC）应用 hosts 标记块。
///
/// `enable = true` 写入 AI 域名块；`false` 移除已存在的块。
/// 通过临时 PowerShell 脚本 + `Start-Process -Verb RunAs -Wait` 执行，
/// 执行结果写临时文件供主进程读取校验。返回给用户的提示信息。
pub fn apply_hosts_block(enable: bool, block: &str) -> Result<String, String> {
    let temp = std::env::temp_dir();
    let block_file = temp.join("aiguard_hosts_block.txt");
    let script_file = temp.join("aiguard_hosts_setup.ps1");
    let result_file = temp.join("aiguard_hosts_result.txt");
    let hosts_file = hosts_path();

    // 1. 标记块内容
    std::fs::write(&block_file, block).map_err(|e| format!("写入临时块文件失败: {}", e))?;

    // 2. 提权脚本（UTF-8 BOM，PowerShell 5.1 按 BOM 识别编码；路径与域名全 ASCII）
    //
    // ⚠ 读写一律走 **Latin-1 字节映射**（`Encoding.GetEncoding(28591)`，1 字符 = 1 字节，
    // 无损往返）：旧实现用 `[Text.Encoding]::ASCII` 写回，会把用户 hosts 里的
    // 中文注释整片替换成 `?`（数据损坏）。用 Latin-1 时正则只匹配我们自己的 ASCII
    // 标记块，其余字节原封不动。
    // 注意：PowerShell 5.1 跑在 .NET Framework 上，`[Text.Encoding]::Latin1` 不存在，
    // 必须用 `GetEncoding(28591)`。
    let mode = if enable { "enable" } else { "disable" };
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
try {{
  $enc = [Text.Encoding]::GetEncoding(28591)
  $p = '{hosts}'
  $c = ''
  if (Test-Path $p) {{ $c = $enc.GetString([IO.File]::ReadAllBytes($p)) }}
  $pattern = '(?s)\r?\n?# >>> AI Safety Guard \(do not remove\).*?# <<< AI Safety Guard\r?\n?'
  $c = [regex]::Replace($c, $pattern, '')
  if ('{mode}' -eq 'enable') {{
    $block = $enc.GetString([IO.File]::ReadAllBytes('{block_file}'))
    $c = $c.TrimEnd() + "`r`n`r`n" + $block + "`r`n"
  }}
  [IO.File]::WriteAllBytes($p, $enc.GetBytes($c))
  'OK' | Out-File '{result_file}' -Encoding utf8
}} catch {{
  $_.Exception.Message | Out-File '{result_file}' -Encoding utf8
}}
"#,
        hosts = hosts_file.display(),
        mode = mode,
        block_file = block_file.display(),
        result_file = result_file.display(),
    );
    // UTF-8 BOM 前缀
    let mut script_bytes = vec![0xEF, 0xBB, 0xBF];
    script_bytes.extend_from_slice(script.as_bytes());
    std::fs::write(&script_file, script_bytes)
        .map_err(|e| format!("写入临时脚本失败: {}", e))?;

    // 清空旧结果
    let _ = std::fs::remove_file(&result_file);

    // 3. UAC 提权执行（阻塞等待提权进程结束；用户取消 UAC 会在这里报错）
    let launch = format!(
        "Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','{}'",
        script_file.display()
    );
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &launch])
        .output()
        .map_err(|e| format!("启动提权进程失败: {}", e))?;

    if !output.status.success() {
        // PowerShell 的报错是系统代码页（中文 Windows = GBK）：不解码的话
        // 「操作已被用户取消」永远匹配不到，用户会看到一串乱码方块而不是友好提示。
        let stderr = crate::console::decode_console(&output.stderr);
        if stderr.contains("canceled") || stderr.contains("操作已被用户取消") {
            return Err("已取消管理员授权，hosts 未修改".to_string());
        }
        let err: String = stderr.trim().chars().take(200).collect();
        return Err(format!(
            "提权执行失败: {}",
            if err.is_empty() { "无法启动提权进程".to_string() } else { err }
        ));
    }

    // 4. 校验结果（PowerShell 5.1 的 Out-File -Encoding utf8 会写入 BOM，须剥离）
    let raw_bytes = std::fs::read(&result_file).unwrap_or_default();
    let raw = crate::console::decode_console(&raw_bytes);
    let result = raw
        .trim_start_matches('\u{FEFF}')
        .trim()
        .to_string();
    if result != "OK" {
        return Err(format!("hosts 修改失败: {}", result));
    }

    // 5. 读取实际 hosts 内容回显状态
    let content = read_hosts()?;
    Ok(format!(
        "hosts 已{}（当前包含 AI 域名条目: {}）",
        if enable { "更新" } else { "还原" },
        if block_present(&content) { "存在" } else { "不存在" }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_block() {
        let b = build_block(&["chat.deepseek.com", "api.openai.com"]);
        assert!(b.starts_with(HOSTS_BEGIN));
        assert!(b.ends_with(HOSTS_END));
        assert!(b.contains("127.0.0.1 chat.deepseek.com"));
        assert!(b.contains("127.0.0.1 api.openai.com"));
    }

    #[test]
    fn test_block_present() {
        let b = build_block(&["chat.deepseek.com"]);
        assert!(block_present(&b));
        assert!(!block_present("# other content"));
    }
}
