//! 敏感内存的主动擦除。
//!
//! 本项目在内存里持有**原文**（映射表、请求体采样）；`drop` 只归还分配器，
//! 字节仍留在堆上，可被同机进程的内存扫描 / 崩溃转储 / 换页文件读取捞走。
//! 因此在**销毁路径上**主动覆写：
//!
//! - [`vault::Vault::clear_session`](crate::vault::Vault::clear_session)：TTL 到期、
//!   应急清空、流结束回收三处都走它，原文与占位符两侧字典逐字段覆写；
//! - 代理侧的请求采样（`ReqInfo::body_text`）覆盖与淘汰时覆写。
//!
//! 覆写用 [`zeroize`]（内部是 `write_volatile` + 清理，编译器不能优化掉）。

use zeroize::Zeroize;

/// 已覆写的字符串计数（仅测试可见，用于断言擦除路径真的被执行）。
#[cfg(test)]
static WIPED_STRINGS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 就地覆写字符串内容（字节置零 + 长度归零）。
///
/// 只覆写**已初始化**的字节（`Vec::zeroize` 语义），随后长度置 0，
/// 因此字符串仍是合法 UTF-8（空串）。
pub fn wipe_string(s: &mut String) {
    #[cfg(test)]
    WIPED_STRINGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: `as_mut_vec` 的唯一要求是内容始终为合法 UTF-8。
    // `Vec::<u8>::zeroize` 先覆写 len 个字节、再 clear()（len = 0），
    // 返回后字符串长度为 0，必然是合法 UTF-8。
    unsafe { s.as_mut_vec() }.zeroize();
}

/// 就地覆写字节缓冲（长度归零）。
pub fn wipe_bytes(v: &mut Vec<u8>) {
    v.zeroize();
}

/// 覆写一个字符串集合并清空（用于淘汰前批量擦除）。
pub fn wipe_strings<I: IntoIterator<Item = String>>(items: I) {
    for mut s in items {
        wipe_string(&mut s);
    }
}

/// 测试用：当前已覆写的字符串计数。
#[cfg(test)]
pub fn wiped_string_count() -> usize {
    WIPED_STRINGS.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wipe_string_clears_content() {
        let mut s = String::from("13800138000");
        wipe_string(&mut s);
        assert!(s.is_empty(), "覆写后内容必须清空");
        // 仍可复用（合法空串）
        s.push_str("ok");
        assert_eq!(s, "ok");
    }

    #[test]
    fn test_wipe_string_multibyte_is_safe() {
        let mut s = String::from("阿尔法计划");
        wipe_string(&mut s);
        assert!(s.is_empty());
    }

    #[test]
    fn test_wipe_bytes_clears() {
        let mut v = vec![1u8, 2, 3, 4];
        wipe_bytes(&mut v);
        assert!(v.is_empty());
    }
}
