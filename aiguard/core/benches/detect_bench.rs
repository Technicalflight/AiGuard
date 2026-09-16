//! 请求侧检测性能基准（零第三方依赖，`harness = false` 手写计时）。
//!
//! 固定三类语料，分别计时 `Detector::scan` 与 `Detector::scrub`：
//! 1. 中文长文本约 4KB（姓名 / 地址 / 机构样例句——内置规则不命中，量「扫不中」的成本）；
//! 2. 约 8KB JSON（多字段混合：姓名 / 电话 / 邮箱 / 地址 / 备注，含少量真实命中）；
//! 3. 多命中混合语料（身份证 / 手机号 / 银行卡 / 邮箱 / URL 各若干，样例均合法可命中）。
//!
//! Detector 构造走与生产一致的默认规则路径（`with_default_rules`）；scrub 的替换
//! 回调用 `Vault::get_or_create`（与代理转发热路径同构）。每轮前清空 bench 会话，
//! 让占位符走完整创建路径，各轮相互独立。
//!
//! 运行 N 轮（默认 200，环境变量 `AIGUARD_BENCH_ROUNDS` 可调），输出各项
//! p50 / p99（毫秒，三位小数）。
//!
//! 门禁：设置 `AIGUARD_BENCH_MAX_P99_MS` 后，任一项 p99 超阈值即 exit(1)；
//! 未设置时只打印不失败。

use std::hint::black_box;
use std::time::Instant;

use aiguard_core::detector::Detector;
use aiguard_core::vault::Vault;

/// scrub 计时用的固定会话名（每轮清空，保证各轮独立、走完整占位符创建路径）。
const BENCH_SESSION: &str = "bench";

fn main() {
    let rounds = std::env::var("AIGUARD_BENCH_ROUNDS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(200);
    let max_p99 = std::env::var("AIGUARD_BENCH_MAX_P99_MS")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok());

    let det = Detector::with_default_rules();
    let vault = Vault::new();

    let cases: Vec<(&str, String)> = vec![
        ("chinese_text_4k", build_chinese_corpus()),
        ("json_mixed_8k", build_json_corpus()),
        ("multi_hit_mix", build_multi_hit_corpus()),
    ];

    println!(
        "请求侧检测性能基准：每项 {} 轮（AIGUARD_BENCH_ROUNDS 可调；语料构造与 Detector 初始化不计入计时）",
        rounds
    );
    println!(
        "{:<18} {:<6} {:>6} {:>12} {:>12}",
        "语料", "操作", "轮数", "p50(ms)", "p99(ms)"
    );

    let mut rows: Vec<(String, String, f64)> = Vec::new(); // (语料, 操作, p99)
    for (name, text) in &cases {
        // 预热：正则 / 多模式自动机缓存与内存页只热一次，不计时
        for _ in 0..5 {
            black_box(det.scan(black_box(text)));
        }

        let mut scan_ms = time_rounds(rounds, || {
            black_box(det.scan(black_box(text)));
        });
        let (p50, p99) = summarize(&mut scan_ms);
        report_row(name, "scan", rounds, p50, p99);
        rows.push((name.to_string(), "scan".to_string(), p99));

        let mut scrub_ms = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            vault.clear_session(BENCH_SESSION);
            let t = Instant::now();
            let _ = black_box(det.scrub(black_box(text), |orig, tag| {
                vault.get_or_create(BENCH_SESSION, orig, tag)
            }));
            scrub_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        let (p50, p99) = summarize(&mut scrub_ms);
        report_row(name, "scrub", rounds, p50, p99);
        rows.push((name.to_string(), "scrub".to_string(), p99));
    }

    match max_p99 {
        Some(max) => {
            let bad: Vec<_> = rows.iter().filter(|(_, _, p99)| *p99 > max).collect();
            if bad.is_empty() {
                println!("门禁通过：全部 p99 ≤ {:.3}ms", max);
            } else {
                for (name, op, p99) in &bad {
                    eprintln!(
                        "门禁失败：{} {} p99={:.3}ms > 阈值 {:.3}ms",
                        name, op, p99, max
                    );
                }
                std::process::exit(1);
            }
        }
        None => println!("未设置 AIGUARD_BENCH_MAX_P99_MS，仅打印不判定"),
    }
}

/// 计时 N 轮 `f`（毫秒）。f 内部已用 black_box 防优化器消隐。
fn time_rounds<F: FnMut()>(rounds: usize, mut f: F) -> Vec<f64> {
    let mut out = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let t = Instant::now();
        f();
        out.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    out
}

/// 最近邻法百分位：升序取第 ceil(p/100*n) 个（1 基）。
fn percentile(ms: &mut [f64], p: f64) -> f64 {
    if ms.is_empty() {
        return 0.0;
    }
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = ms.len();
    let idx = ((p / 100.0) * n as f64).ceil() as usize;
    ms[idx.clamp(1, n) - 1]
}

fn summarize(ms: &mut [f64]) -> (f64, f64) {
    (percentile(ms, 50.0), percentile(ms, 99.0))
}

fn report_row(name: &str, op: &str, rounds: usize, p50: f64, p99: f64) {
    println!(
        "{:<18} {:<6} {:>6} {:>12.3} {:>12.3}",
        name, op, rounds, p50, p99
    );
}

/// ① 中文长文本 ≥4KB：姓名 / 地址 / 机构样例句循环填充（不含内置规则可命中的串）。
fn build_chinese_corpus() -> String {
    let blocks = [
        "用户张伟家住北京市海淀区中关村大街27号，工作单位是北京华信智原科技有限公司。",
        "李娜的收件地址为上海市浦东新区世纪大道100号环球金融中心69层，快递由顺丰速运承运。",
        "家住广州市天河区体育西路103号的王强，向深圳前海微众银行提交了按揭申请材料。",
        "陈芳住在杭州市余杭区文一西路969号附近，户籍所在地是重庆市渝中区民生路28号。",
        "刘洋的工作单位是腾讯科技（深圳）有限公司，常住南京市建邺区江东中路369号。",
    ];
    let mut s = String::with_capacity(6 * 1024);
    let mut i = 0;
    while s.len() < 4 * 1024 {
        s.push_str(blocks[i % blocks.len()]);
        i += 1;
    }
    s
}

/// ② JSON 语料 ≥8KB：多字段混合（姓名 / 电话 / 邮箱 / 地址 / 备注），少量真实命中。
fn build_json_corpus() -> String {
    const PHONES: [&str; 4] = ["138", "139", "150", "186"];
    let record = |i: usize| -> String {
        let phone = format!("{}{:08}", PHONES[i % 4], i % 100_000_000);
        format!(
            r#"{{"id":"req-{i}","user":{{"name":"用户{i}","phone":"{phone}","email":"user{i}@example.com"}},"address":{{"province":"广东省","city":"深圳市","street":"南山区科技园南路{i}号"}},"meta":{{"channel":"web","client":"1.2.3","tags":["alpha","beta"]}},"notes":"订单备注：请尽快发货，如有问题请通过客服渠道联系，收件人可来电改期。","padding":"长自由文本字段，用来贴近真实请求正文里混排的说明文字与数字串 {i}，追加填充内容以撑起字段长度"}}"#
        )
    };
    let mut s = String::with_capacity(10 * 1024);
    s.push_str(r#"{"records":["#);
    let mut i = 0;
    while s.len() < 8 * 1024 {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&record(i));
        i += 1;
    }
    s.push_str("]}");
    s
}

/// GB 11643 身份证第 18 位校验码（bench 内自算，保证样例全部合法可命中）。
fn idcard_check_digit(prefix17: &str) -> char {
    const W: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const MAP: &[u8; 11] = b"10X98765432";
    let sum: u32 = prefix17
        .bytes()
        .enumerate()
        .map(|(i, b)| (b - b'0') as u32 * W[i])
        .sum();
    MAP[(sum % 11) as usize] as char
}

/// ③ 多命中混合语料：身份证 / 手机号 / 银行卡 / 邮箱 / URL 各若干（全部为合法样例）。
fn build_multi_hit_corpus() -> String {
    const AREAS: [&str; 4] = ["110101", "310104", "440305", "330106"];
    const BIRTHS: [&str; 4] = ["19900307", "19851226", "20010715", "19790211"];
    const PHONES: [&str; 4] = ["138", "139", "150", "186"];
    const BANKS: [&str; 3] = ["4242424242424242", "5555555555554444", "4111111111111111"];
    let block = |i: usize| -> String {
        let prefix17 = format!("{}{}{:03}", AREAS[i % 4], BIRTHS[i % 4], i % 1000);
        let idc = format!("{}{}", prefix17, idcard_check_digit(&prefix17));
        let phone = format!("{}{:08}", PHONES[i % 4], i % 100_000_000);
        let bank = BANKS[i % 3];
        let url = format!("https://example.com/u/{}/profile", i);
        format!(
            "客户档案{i}：身份证号{idc}，手机{phone}，银行卡{bank}，邮箱user{i}@example.com，个人主页{url}；"
        )
    };
    let mut s = String::with_capacity(12 * 1024);
    for i in 0..80 {
        s.push_str(&block(i));
    }
    s
}
