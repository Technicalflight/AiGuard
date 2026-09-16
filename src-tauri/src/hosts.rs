//! hosts 文件管理：AI 域名 → 127.0.0.1 的标记块写入 / 移除。
//!
//! hosts 文件（Windows `%SystemRoot%\System32\drivers\etc\hosts`、unix `/etc/hosts`）
//! 对普通用户只读，写入必须**提权**：
//!
//! | 平台 | 提权通道 |
//! |---|---|
//! | Windows | `Start-Process -Verb RunAs` 弹 UAC，由提权后的 PowerShell 执行临时脚本 |
//! | macOS | `osascript -e 'do shell script … with administrator privileges'` |
//! | Linux | `pkexec`（桌面 polkit 弹窗），退回 `sudo -n`（已缓存凭据时可用） |
//!
//! 标记块格式保证幂等（先删旧块再写新块），且**绝不触碰用户已有的其他 hosts 条目**。

/// 标记块的起始行。
pub const HOSTS_BEGIN: &str = "# >>> AI Safety Guard (do not remove)";
/// 标记块的结束行。
pub const HOSTS_END: &str = "# <<< AI Safety Guard";

/// 构建 hosts 标记块（每个 AI 域名一行 127.0.0.1）。
///
/// 换行符沿用 Windows 惯例（CRLF）：unix 侧写入前会统一转成 LF
/// （见 [`apply_hosts_block`]），两边都不给用户的 hosts 引入奇怪的行尾。
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
pub fn hosts_path() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::path::PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::path::PathBuf::from("/etc/hosts")
    }
}

/// 清空系统 DNS 缓存。
///
/// hosts 块写入/删除后，系统与浏览器的 DNS 缓存仍指向旧地址，不清缓存会导致
/// 模式切换"不生效"（实测：用户需要重开代理开关才恢复）。
/// 全部是**尽力而为**：清不掉也不该让模式切换失败，因此忽略退出码。
pub fn flush_dns_cache() {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("ipconfig")
            .arg("/flushdns")
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("/usr/bin/dscacheutil")
            .arg("-flushcache")
            .output();
        let _ = std::process::Command::new("/usr/bin/killall")
            .args(["-HUP", "mDNSResponder"])
            .output();
    }
    #[cfg(target_os = "linux")]
    {
        // systemd-resolved 是当前主流；老发行版可能只有 systemd-resolve。
        // 两者都没有（无 systemd）时什么都不做——hosts 变更本身仍会生效，
        // 只是应用级缓存要多等一会儿。
        if std::process::Command::new("resolvectl")
            .arg("flush-caches")
            .output()
            .is_err()
        {
            let _ = std::process::Command::new("systemd-resolve")
                .arg("--flush-caches")
                .output();
        }
    }
}

/// 读取 hosts 文件内容（普通用户可读）。
///
/// 用户常在 hosts 里写中文注释，Windows 上还可能是 **GBK** 保存——此时
/// `read_to_string` 会直接失败，报错还会误导成「可能需要管理员权限」。
/// 因此按字节读取后再按系统代码页解码（unix 上 UTF-8 优先，等价于直读）。
pub fn read_hosts() -> Result<String, String> {
    crate::console::read_text_file(&hosts_path()).map_err(|e| {
        format!(
            "读取 hosts 文件失败（可能需要管理员权限）: {}",
            crate::state::safe_err(&e)
        )
    })
}

/// 检查 hosts 文件中是否已存在本应用的域名块（无需管理员权限）。
/// 用于决定是否需要提权做清理——块不存在时跳过提权。
pub fn hosts_block_exists() -> bool {
    match read_hosts() {
        Ok(c) => block_present(&c),
        Err(_) => false,
    }
}

/// 以管理员权限应用 hosts 标记块。
///
/// `enable = true` 写入 AI 域名块；`false` 移除已存在的块。
/// 返回给用户的提示信息。
pub fn apply_hosts_block(enable: bool, block: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        windows_apply_hosts_block(enable, block)
    }
    #[cfg(unix)]
    {
        unix_apply_hosts_block(enable, block)
    }
    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = (enable, block);
        Err("当前平台尚未实现 hosts 写入".to_string())
    }
}

/// 写入后统一回读校验，两个平台共用同一句结论文案。
fn verify_hosts_result(enable: bool, content: &str) -> String {
    format!(
        "hosts 已{}（当前包含 AI 域名条目: {}）",
        if enable { "更新" } else { "还原" },
        if block_present(content) { "存在" } else { "不存在" }
    )
}

// ═══════════════════════ Windows ═══════════════════════

/// 通过临时 PowerShell 脚本 + `Start-Process -Verb RunAs -Wait` 执行，
/// 执行结果写临时文件供主进程读取校验。
#[cfg(target_os = "windows")]
fn windows_apply_hosts_block(enable: bool, block: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;

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
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW：GUI 应用绝不闪黑窗
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
            if err.is_empty() {
                "无法启动提权进程".to_string()
            } else {
                err
            }
        ));
    }

    // 4. 校验结果（PowerShell 5.1 的 Out-File -Encoding utf8 会写入 BOM，须剥离）
    let raw_bytes = std::fs::read(&result_file).unwrap_or_default();
    let raw = crate::console::decode_console(&raw_bytes);
    let result = raw.trim_start_matches('\u{FEFF}').trim().to_string();
    if result != "OK" {
        return Err(format!("hosts 修改失败: {}", result));
    }

    // 5. 读取实际 hosts 内容回显状态
    let content = read_hosts()?;
    Ok(verify_hosts_result(enable, &content))
}

// ═══════════════════════ unix（macOS / Linux） ═══════════════════════

/// 在 unix 上修改 hosts 的脚本（以管理员身份执行）。
///
/// 参数：`$1` hosts 路径 · `$2` 新标记块文件 · `$3` `enable` / `disable`
///
/// 为什么是脚本而不是直接写：`/etc/hosts` 只有 root 可写，而 GUI 进程不是 root。
/// 脚本会被交给 osascript（macOS）或 pkexec（Linux）以管理员身份执行。
///
/// 两个刻意的写法：
/// - **用 awk 的 `index($0, marker)==1` 判断标记行，不用正则**：用户的 hosts 可能是
///   CRLF 结尾，正则里的 `$` 会因为这多出来的 `\r` 永不匹配 —— 结果是旧块删不掉、
///   每开一次守护就追加一块（静默失效最危险）。
/// - **最后用 `cat "$T" > "$H"` 而不是 `mv`**：保留原文件的 inode 与权限；
///   容器里 `/etc/hosts` 通常是 bind mount，`mv` 会直接失败。
#[cfg(any(unix, test))]
const UNIX_HOSTS_SCRIPT: &str = r#"set -e
H="$1"; B="$2"; MODE="$3"
T="$(mktemp)"
awk -v s='# >>> AI Safety Guard (do not remove)' -v e='# <<< AI Safety Guard' \
    'index($0,s)==1{skip=1} skip==0{print} index($0,e)==1{skip=0}' "$H" > "$T"
if [ "$MODE" = "enable" ]; then
  printf '\n' >> "$T"
  cat "$B" >> "$T"
fi
cat "$T" > "$H"
rm -f "$T"
"#;

/// 把块内容转成 unix 行尾并确保以换行结束（`cat` 追加时不会把下一行粘连）。
#[cfg(any(unix, test))]
fn unix_block_bytes(block: &str) -> Vec<u8> {
    let mut s = block.replace("\r\n", "\n");
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s.into_bytes()
}

/// 组装 osascript 的 `do shell script` 源。
///
/// 路径一律用单引号包住（macOS 的临时目录 `/var/folders/…` 不含引号，
/// 单引号足以抵御空格）。
#[cfg(any(target_os = "macos", test))]
pub fn macos_osascript_source(script: &str, hosts: &str, block_file: &str, enable: bool) -> String {
    format!(
        "do shell script \"/bin/sh '{}' '{}' '{}' {}\" with administrator privileges",
        script,
        hosts,
        block_file,
        if enable { "enable" } else { "disable" }
    )
}

#[cfg(unix)]
fn unix_apply_hosts_block(enable: bool, block: &str) -> Result<String, String> {
    let temp = std::env::temp_dir();
    let block_file = temp.join("aiguard_hosts_block.txt");
    let script_file = temp.join("aiguard_hosts_setup.sh");
    let hosts_file = hosts_path();

    std::fs::write(&block_file, unix_block_bytes(block))
        .map_err(|e| format!("写入临时块文件失败: {}", e))?;
    std::fs::write(&script_file, UNIX_HOSTS_SCRIPT)
        .map_err(|e| format!("写入临时脚本失败: {}", e))?;

    let hosts = hosts_file.display().to_string();
    let block_path = block_file.display().to_string();
    let script = script_file.display().to_string();

    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/bin/osascript")
            .args([
                "-e",
                &macos_osascript_source(&script, &hosts, &block_path, enable),
            ])
            .output()
            .map_err(|e| format!("启动提权进程失败: {}", crate::state::safe_err(&e)))?;
        if !out.status.success() {
            let (stdout, stderr) = crate::console::decode_output(&out);
            let msg = if stderr.trim().is_empty() { stdout } else { stderr };
            let msg = msg.trim();
            // osascript 取消授权时的原文（-128 / User canceled）不可靠地本地化，
            // 因此同时按关键字判断，避免把"用户取消"报成一串系统错误。
            if msg.contains("-128") || msg.to_ascii_lowercase().contains("cancel") {
                return Err("已取消管理员授权，hosts 未修改".to_string());
            }
            let brief: String = msg.chars().take(200).collect();
            return Err(format!(
                "提权执行失败: {}",
                if brief.is_empty() {
                    "无法启动提权进程".to_string()
                } else {
                    brief
                }
            ));
        }
    }
    #[cfg(target_os = "linux")]
    {
        run_linux_elevated(&script, &hosts, &block_path, enable)?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (script, hosts, block_path, enable);
        return Err("当前平台尚未实现 hosts 写入".to_string());
    }

    let content = read_hosts()?;
    Ok(verify_hosts_result(enable, &content))
}

/// Linux：优先 `pkexec`（桌面会弹 polkit 授权框），退回 `sudo -n`。
///
/// `sudo` 在 GUI 子进程里没有 TTY，只能走 `-n`（已缓存凭据或 NOPASSWD 时可用）。
/// 两条都不行时给出**可操作**的指引——绝不静默返回成功：
/// 「守护开着但域名没走代理」会让用户以为受保护，实际是明文直连。
#[cfg(target_os = "linux")]
fn run_linux_elevated(
    script: &str,
    hosts: &str,
    block_file: &str,
    enable: bool,
) -> Result<(), String> {
    let mode = if enable { "enable" } else { "disable" };
    let args = [script, hosts, block_file, mode];

    let pkexec = std::process::Command::new("pkexec")
        .arg("/bin/sh")
        .args(args)
        .output();
    match pkexec {
        Ok(out) if out.status.success() => return Ok(()),
        Ok(out) => {
            let (stdout, stderr) = crate::console::decode_output(&out);
            let msg = if stderr.trim().is_empty() { stdout } else { stderr };
            let msg = msg.trim();
            // polkit 在用户点「取消」时返回 126/127 并带 "Not authorized" / "dismissed"
            if msg.contains("Not authorized") || msg.contains("dismissed") || msg.contains("126")
            {
                return Err("已取消管理员授权，hosts 未修改".to_string());
            }
            log::warn!("pkexec 修改 hosts 失败，回退 sudo -n: {}", msg);
        }
        Err(e) => log::info!("本机没有 pkexec（{}），改用 sudo -n", crate::state::safe_err(&e)),
    }

    let out = std::process::Command::new("sudo")
        .arg("-n")
        .arg("/bin/sh")
        .args(args)
        .output()
        .map_err(|e| {
            format!(
                "既没有可用的 pkexec，也没有 sudo（{}）；请安装 polkit 或用管理员权限手动执行脚本",
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
        .take(200)
        .collect();
    Err(format!(
        "需要管理员权限（pkexec 与 sudo -n 均不可用）: {}",
        if msg.is_empty() {
            "请安装 polkit，或手动以 root 执行 /etc/hosts 的修改".to_string()
        } else {
            msg
        }
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

    /// 标记行的判定文本必须与脚本里写死的那两份**逐字一致**。
    ///
    /// 脚本是靠 awk 的 `index($0, marker)==1` 认标记的，两边字符串一旦漂移，
    /// 症状是"旧块删不掉、每开一次守护追加一块"——而不会有任何报错。
    #[test]
    fn test_script_markers_match_constants() {
        assert!(
            UNIX_HOSTS_SCRIPT.contains(HOSTS_BEGIN),
            "脚本里的起始标记与 HOSTS_BEGIN 不一致"
        );
        assert!(
            UNIX_HOSTS_SCRIPT.contains(HOSTS_END),
            "脚本里的结束标记与 HOSTS_END 不一致"
        );
    }

    /// 块内容转 unix 行尾，且必须以换行结束（否则 `cat` 追加会与后一行粘连）。
    #[test]
    fn test_unix_block_bytes_normalizes_line_endings() {
        let raw = build_block(&["chat.deepseek.com"]);
        assert!(raw.contains("\r\n"));
        let bytes = unix_block_bytes(&raw);
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains('\r'), "unix 侧不得留 CR");
        assert!(text.ends_with('\n'), "必须以换行结束");
        assert!(text.contains("127.0.0.1 chat.deepseek.com"));
    }

    #[test]
    fn test_macos_osascript_source_shape() {
        let src = macos_osascript_source("/tmp/a.sh", "/etc/hosts", "/tmp/b.txt", true);
        assert!(src.starts_with("do shell script \""), "{}", src);
        assert!(src.ends_with("\" with administrator privileges"), "{}", src);
        assert!(src.contains("/bin/sh '/tmp/a.sh' '/etc/hosts' '/tmp/b.txt' enable"), "{}", src);
        let off = macos_osascript_source("/tmp/a.sh", "/etc/hosts", "/tmp/b.txt", false);
        assert!(off.contains(" disable"), "{}", off);
    }

    /// 真跑一遍 unix 脚本（只在 unix 上）：验证「先删旧块再写新块」幂等，
    /// 且**用户原有的中文注释与条目一个字节都不能动**。
    ///
    /// 这条测试正是那个「正则 `$` 被 CRLF 的 `\r` 挡住」坑的守卫：
    /// 脚本对 CRLF 结尾的 hosts 也必须能正确删块。
    #[cfg(unix)]
    #[test]
    fn test_unix_script_is_idempotent_and_preserves_user_content() {
        let dir = std::env::temp_dir().join(format!("aiguard_hosts_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let hosts = dir.join("hosts");
        let block_file = dir.join("block.txt");
        let script_file = dir.join("apply.sh");

        // 故意用 CRLF 结尾 + 中文注释（模拟用户在 Windows 上编辑过又同步过来的文件）
        std::fs::write(
            &hosts,
            "127.0.0.1 localhost\r\n# 我的本地开发注释\r\n10.0.0.9 内部测试服\r\n",
        )
        .unwrap();
        std::fs::write(&script_file, UNIX_HOSTS_SCRIPT).unwrap();

        let run = |enable: bool, block: &str| {
            std::fs::write(&block_file, unix_block_bytes(block)).unwrap();
            let out = std::process::Command::new("/bin/sh")
                .arg(&script_file)
                .arg(&hosts)
                .arg(&block_file)
                .arg(if enable { "enable" } else { "disable" })
                .output()
                .expect("应能执行 /bin/sh");
            assert!(
                out.status.success(),
                "脚本执行失败: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };

        let block = build_block(&["chat.deepseek.com", "api.openai.com"]);
        run(true, &block);
        let after_first = std::fs::read_to_string(&hosts).unwrap();
        assert!(block_present(&after_first));
        assert!(after_first.contains("# 我的本地开发注释"), "用户注释被改动");
        assert!(after_first.contains("10.0.0.9 内部测试服"), "用户条目被改动");
        assert_eq!(after_first.matches(HOSTS_BEGIN).count(), 1);

        // 再写一次：必须仍然只有一块（幂等），不能越写越多
        run(true, &block);
        let after_second = std::fs::read_to_string(&hosts).unwrap();
        assert_eq!(
            after_second.matches(HOSTS_BEGIN).count(),
            1,
            "重复开启守护追加了第二块（旧块没删掉）：\n{}",
            after_second
        );

        // 关闭：块消失，用户内容仍在
        run(false, &block);
        let after_off = std::fs::read_to_string(&hosts).unwrap();
        assert!(!block_present(&after_off));
        assert!(after_off.contains("# 我的本地开发注释"));
        assert!(after_off.contains("10.0.0.9 内部测试服"));
        assert!(!after_off.contains("chat.deepseek.com"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
