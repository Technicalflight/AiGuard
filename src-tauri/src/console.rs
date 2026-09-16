//! 外部命令输出的编码解码。
//!
//! Windows 的原生命令行工具（`icacls` / `certutil` / `ipconfig` / Windows PowerShell 5.1）
//! 写进管道的是**系统代码页**字节（中文 Windows = GBK/936），**不是 UTF-8**。
//! 直接 `String::from_utf8_lossy` 会把本地化文案变成一串 U+FFFD 方块——
//! 典型受害者是 `icacls` 结尾那句「已处理 1 个文件；处理 0 个文件时失败」，
//! 以及 PowerShell 报错「操作已被用户取消」（这条还会让按内容匹配的分支彻底失效）。
//!
//! 解码顺序：**UTF-8 严格 → 控制台输出代码页(OEM) → ANSI(ACP) → lossy 兜底**。
//! 先试 UTF-8 是关键：GBK / Shift-JIS / Big5 这类双字节编码的字节序列几乎不可能
//! 通过 UTF-8 严格校验（尾字节范围与 UTF-8 续字节规则冲突），因此不会误判；
//! 反过来若先按 OEM 解，就会把我们自己写出的 UTF-8 输出打成乱码。

/// 按系统代码页解码一段外部命令输出。
pub fn decode_console(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    // ① 本身就是 UTF-8（含纯 ASCII）——覆盖 `chcp 65001`、curl 响应体、我们自己的输出
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    // ② 系统代码页：先控制台输出页（OEM），再 ANSI
    #[cfg(target_os = "windows")]
    {
        for cp in [oem_codepage(), ansi_codepage()] {
            if let Some(s) = codepage_to_string(bytes, cp) {
                // 出现替换字符说明这个代码页解错了，换下一个再试
                if !s.contains('\u{FFFD}') {
                    return s;
                }
            }
        }
    }
    // ③ 兜底：有损解码（宁可留方块，也绝不 panic / 丢整段输出）
    String::from_utf8_lossy(bytes).to_string()
}

/// 解码命令输出的便捷封装：`(stdout, stderr)`。
pub fn decode_output(out: &std::process::Output) -> (String, String) {
    (
        decode_console(&out.stdout),
        decode_console(&out.stderr),
    )
}

/// 读取文本文件并按系统代码页解码（用于 hosts 这类可能被用户以 GBK 保存的文件）。
pub fn read_text_file(path: &std::path::Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(decode_console(&bytes))
}

#[cfg(target_os = "windows")]
fn ansi_codepage() -> u32 {
    // SAFETY: GetACP 无参数、无副作用
    unsafe { windows_sys::Win32::Globalization::GetACP() }
}

#[cfg(target_os = "windows")]
fn oem_codepage() -> u32 {
    // SAFETY: GetOEMCP 无参数、无副作用
    unsafe { windows_sys::Win32::Globalization::GetOEMCP() }
}

/// 用指定代码页把字节转为 UTF-16 再转 String；失败返回 `None`。
#[cfg(target_os = "windows")]
fn codepage_to_string(bytes: &[u8], codepage: u32) -> Option<String> {
    use windows_sys::Win32::Globalization::MultiByteToWideChar;

    let len = i32::try_from(bytes.len()).ok()?;
    // 先问需要的宽字符数
    let need = unsafe {
        MultiByteToWideChar(
            codepage,
            0,
            bytes.as_ptr(),
            len,
            std::ptr::null_mut(),
            0,
        )
    };
    if need <= 0 {
        return None;
    }
    let mut buf = vec![0u16; need as usize];
    let got = unsafe {
        MultiByteToWideChar(
            codepage,
            0,
            bytes.as_ptr(),
            len,
            buf.as_mut_ptr(),
            need,
        )
    };
    if got <= 0 {
        return None;
    }
    buf.truncate(got as usize);
    Some(String::from_utf16_lossy(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pure_ascii_passthrough() {
        assert_eq!(decode_console(b"Successfully processed 1 files"), "Successfully processed 1 files");
    }

    #[test]
    fn test_utf8_output_is_not_mangled() {
        // 我们自己/现代工具写出的 UTF-8 必须原样保留（不能被 OEM 代码页毁掉）
        let s = "中文描述：数据目录权限正常";
        assert_eq!(decode_console(s.as_bytes()), s);
    }

    #[test]
    fn test_empty_is_empty() {
        assert_eq!(decode_console(b""), "");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_gbk_icacls_footer_is_decoded() {
        if ansi_codepage() != 936 && oem_codepage() != 936 {
            return; // 非中文 Windows：GBK 字节本来就该被解成别的字符，跳过
        }
        // 本机真实输出：「已成功处理 1 个文件; 处理 0 个文件时失败」的 GBK 字节。
        // 旧实现用 from_utf8_lossy 把它解成一串 U+FFFD 方块（截图里的乱码）。
        let gbk: Vec<u8> = vec![
            0xD2, 0xD1, 0xB3, 0xC9, 0xB9, 0xA6, 0xB4, 0xA6, 0xC0, 0xED, 0x20, 0x31, 0x20, 0xB8,
            0xF6, 0xCE, 0xC4, 0xBC, 0xFE, 0x3B, 0x20, 0xB4, 0xA6, 0xC0, 0xED, 0x20, 0x30, 0x20,
            0xB8, 0xF6, 0xCE, 0xC4, 0xBC, 0xFE, 0xCA, 0xB1, 0xCA, 0xA7, 0xB0, 0xDC,
        ];
        let decoded = decode_console(&gbk);
        assert_eq!(decoded, "已成功处理 1 个文件; 处理 0 个文件时失败");
        assert!(!decoded.contains('\u{FFFD}'), "不得残留替换字符: {}", decoded);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_gbk_powershell_error_is_decoded() {
        if ansi_codepage() != 936 && oem_codepage() != 936 {
            return;
        }
        // PowerShell 报错「操作已被用户取消」的 GBK 字节（hosts 提权分支按内容匹配它）
        let gbk: Vec<u8> = vec![
            0xB2, 0xD9, 0xD7, 0xF7, 0xD2, 0xD1, 0xB1, 0xBB, 0xD3, 0xC3, 0xBB, 0xA7, 0xC8, 0xA1,
            0xCF, 0xFB,
        ];
        let decoded = decode_console(&gbk);
        assert_eq!(decoded, "操作已被用户取消");
    }
}
