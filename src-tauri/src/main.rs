//! AI 安全卫士 —— Tauri v2 桌面应用入口。
//!
//! 启动流程：打开 SQLite 存储 → 构建 AppState → 生成 CA → 启动本地 MITM 代理
//! → 注册命令 → 显示窗口。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod console;
mod dns;
mod hosts;
mod i18n;
mod process;
mod link_check;
mod proxy;
mod proxy_config;
mod security;
mod state;
mod store;
mod transparent;

use std::sync::Arc;

use tauri::Manager;

use i18n::Language;
use state::{AppState, CloseBehavior};
use store::Store;

// ═══════════════════════ 系统托盘 ═══════════════════════

/// 托盘图标 ID（刷新菜单时按它取回托盘句柄）。
const TRAY_ID: &str = "main";

/// 窗口外提示的当前语言（托盘 / 通知共用后端文案表，窗口内由前端负责）。
fn current_language(state: &Arc<AppState>) -> Language {
    state.language()
}

/// 托盘提示文案（状态 + 计数）。
fn tray_tooltip(state: &Arc<AppState>) -> String {
    let enabled = match state.config.read() {
        Ok(c) => c.enabled,
        Err(poisoned) => poisoned.into_inner().enabled,
    };
    i18n::tray_tip(
        current_language(state),
        enabled,
        state.active_sessions().len(),
        state.recent_events_snapshot().len(),
    )
}

/// 构建托盘菜单：状态 / 快捷开关 / 显示主窗口 / 最近事件 / 退出。
fn build_tray_menu(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};

    let lang = current_language(state);
    let tr = |k: &str| i18n::tr(lang, k);

    let enabled = match state.config.read() {
        Ok(c) => c.enabled,
        Err(poisoned) => poisoned.into_inner().enabled,
    };
    let status = MenuItem::with_id(
        app,
        "status",
        tr(if enabled {
            "tray.status.on"
        } else {
            "tray.status.off"
        }),
        false,
        None::<&str>,
    )?;
    let toggle = MenuItem::with_id(
        app,
        "toggle",
        tr(if enabled {
            "tray.toggle.pause"
        } else {
            "tray.toggle.resume"
        }),
        true,
        None::<&str>,
    )?;
    let show = MenuItem::with_id(app, "show", tr("tray.show"), true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", tr("tray.quit"), true, None::<&str>)?;

    let events = Submenu::with_id(app, "events", tr("tray.events"), true)?;
    let recent = state.recent_events_snapshot();
    if recent.is_empty() {
        events.append(&MenuItem::with_id(
            app,
            "ev_none",
            tr("tray.events.none"),
            false,
            None::<&str>,
        )?)?;
    } else {
        for (i, ev) in recent.iter().take(6).enumerate() {
            events.append(&MenuItem::with_id(
                app,
                format!("ev_{}", i),
                i18n::tray_event_line(lang, ev),
                false,
                None::<&str>,
            )?)?;
        }
    }

    // 分隔线与各条目都必须先落到具名绑定：Menu::with_items 只借用它们的引用
    let sep_top = PredefinedMenuItem::separator(app)?;
    let sep_bottom = PredefinedMenuItem::separator(app)?;
    let items: Vec<&dyn IsMenuItem<tauri::Wry>> = vec![
        &status,
        &sep_top,
        &toggle,
        &show,
        &events,
        &sep_bottom,
        &quit,
    ];
    Menu::with_items(app, &items)
}

/// 托盘图标兜底：内置绘制（品牌绿圆底 + 白色对勾）。
/// 打包图标缺失时仍保证托盘可见——没有图标的托盘在 Windows 上是"隐形"的。
fn fallback_tray_icon() -> tauri::image::Image<'static> {
    const S: u32 = 32;
    let mut rgba = vec![0u8; (S * S * 4) as usize];
    let (cx, cy, r) = (15.5f32, 15.5f32, 14.5f32);
    // 点到线段距离，用于把对勾光栅化出来
    let seg = |px: f32, py: f32, ax: f32, ay: f32, bx: f32, by: f32| -> f32 {
        let (dx, dy) = (bx - ax, by - ay);
        let len2 = dx * dx + dy * dy;
        let t = if len2 <= f32::EPSILON {
            0.0
        } else {
            (((px - ax) * dx + (py - ay) * dy) / len2).clamp(0.0, 1.0)
        };
        let (ex, ey) = (ax + t * dx, ay + t * dy);
        ((px - ex).powi(2) + (py - ey).powi(2)).sqrt()
    };
    for y in 0..S {
        for x in 0..S {
            let px = x as f32 + 0.5;
            let py = y as f32 + 0.5;
            if ((px - cx).powi(2) + (py - cy).powi(2)).sqrt() > r {
                continue;
            }
            let on_check = seg(px, py, 9.5, 16.5, 14.0, 21.0) < 1.8
                || seg(px, py, 14.0, 21.0, 22.5, 11.5) < 1.8;
            let i = ((y * S + x) * 4) as usize;
            let (r_, g_, b_) = if on_check {
                (255u8, 255u8, 255u8)
            } else {
                (0x0E, 0x8A, 0x5F)
            };
            rgba[i] = r_;
            rgba[i + 1] = g_;
            rgba[i + 2] = b_;
            rgba[i + 3] = 255;
        }
    }
    tauri::image::Image::new_owned(rgba, S, S)
}

/// 显示并聚焦主窗口（托盘左键 / 菜单「显示主窗口」）。
fn show_main_window(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

/// 重建托盘菜单与提示（仅在状态 / 事件 / 语言变化时调用——菜单打开时重建会把它关掉）。
///
/// `pub(crate)`：切换界面语言与快捷键配置时，命令层需要立刻重建托盘菜单，
/// 否则会出现"窗口已经是英文、右键菜单还是中文"的割裂。
pub(crate) fn refresh_tray(app: &tauri::AppHandle) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    let state = app.state::<Arc<AppState>>();
    match build_tray_menu(app, state.inner()) {
        Ok(menu) => {
            if let Err(e) = tray.set_menu(Some(menu)) {
                log::debug!("托盘菜单刷新失败: {}", state::safe_err(&e));
            }
        }
        Err(e) => log::debug!("托盘菜单构建失败: {}", state::safe_err(&e)),
    }
    let _ = tray.set_tooltip(Some(tray_tooltip(state.inner())));
}

/// 把主窗口标题同步成当前语言的应用名。
///
/// ⚠ 窗口标题是**独立于前端渲染**的原生元素：`tauri.conf.json` 里的 `title` 只在
/// 窗口创建时生效一次，之后切语言不会自己变。它和托盘 / 系统通知同属「窗口外」界面，
/// 必须显式同步，否则会出现「托盘已是 AI Guard、任务栏悬停还是 AI 安全卫士」的割裂。
///
/// 本窗口是 `decorations: false`（无原生标题栏），所以标题只在**任务栏悬停**与
/// **Alt+Tab 切换器**里可见——仍然属于用户看得到的信息面。
pub(crate) fn sync_window_title(app: &tauri::AppHandle) {
    let Some(win) = app.get_webview_window("main") else {
        return;
    };
    let want = i18n::tr(app.state::<Arc<AppState>>().inner().language(), "app.name");
    // 只在真的变化时才 set_title：Windows 上每次都是一次 WM_SETTEXT，没必要无脑重设。
    if matches!(win.title(), Ok(cur) if cur == want) {
        return;
    }
    if let Err(e) = win.set_title(&want) {
        log::debug!("窗口标题同步失败: {}", state::safe_err(&e));
    }
}

/// 托盘状态签名：只有它变化了才重建菜单（避免 2 秒一次把展开的菜单关掉）。
/// 语言也在签名里——否则切语言后菜单会一直停在旧语言。
fn tray_signature(state: &Arc<AppState>) -> String {
    let enabled = match state.config.read() {
        Ok(c) => c.enabled,
        Err(poisoned) => poisoned.into_inner().enabled,
    };
    let recent = state.recent_events_snapshot();
    let newest = recent.first().map(|e| e.ts).unwrap_or(0.0);
    let shortcut = state.shortcut_config();
    format!(
        "{}|{}|{}|{}|{}|{}",
        enabled,
        recent.len(),
        newest,
        current_language(state).as_str(),
        shortcut.enabled,
        format!("{}+{}", shortcut.toggle_guard, shortcut.panic)
    )
}

/// 弹一条系统通知（任何失败只记日志，绝不影响调用方的业务流程）。
fn notify_user(app: &tauri::AppHandle, title: String, body: String) {
    use tauri_plugin_notification::NotificationExt;
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        log::warn!("系统通知发送失败: {}", state::safe_err(&e));
    }
}

/// 窗口外触发的守护开关（托盘菜单 / 全局快捷键共用同一条路径）。
///
/// 必须共用：否则"菜单点了管用、快捷键不管用"这类漂移问题极难发现，
/// 而这两条路径都只有系统托盘/通知这一个反馈面。
fn toggle_guard_outside(app: &tauri::AppHandle) {
    let state = app.state::<Arc<AppState>>();
    let st = state.inner().clone();
    let enabled = match st.config.read() {
        Ok(c) => c.enabled,
        Err(poisoned) => poisoned.into_inner().enabled,
    };
    let next = !enabled;
    match commands::apply_guard_enabled(&st, next) {
        Ok(()) => {
            log::info!(
                "窗口外切换守护：{}",
                if next { "开启" } else { "关闭" }
            );
            // 让开着的窗口立刻跟上（窗口不在前台时靠 5 秒轮询兜底）
            st.emit_event("guard-changed", next);
        }
        Err(e) => {
            log::warn!("窗口外切换守护失败: {}", e);
            // 托盘与快捷键都没有提示位，失败原因只能靠系统通知送达
            notify_user(
                app,
                i18n::fmt(
                    &i18n::tr(st.language(), "notify.guard.fail.title"),
                    &[i18n::tr(st.language(), "app.name")],
                ),
                e,
            );
        }
    }
    refresh_tray(app);
}

/// 全局快捷键分发。
///
/// 只在按下（`Pressed`）时触发：`Released` 也回调一次，不去重就会每条快捷键执行两遍
/// （应急切断执行两遍会白跑一轮提权/注册表操作，代价不小）。
fn handle_shortcut(app: &tauri::AppHandle, pressed: &tauri_plugin_global_shortcut::Shortcut) {
    use std::str::FromStr;

    let state = app.state::<Arc<AppState>>();
    let st = state.inner().clone();
    let cfg = st.shortcut_config();
    if !cfg.enabled {
        return;
    }
    let parse = |s: &str| tauri_plugin_global_shortcut::Shortcut::from_str(s).ok();
    let (Some(toggle), Some(panic)) = (parse(&cfg.toggle_guard), parse(&cfg.panic)) else {
        return;
    };
    if *pressed == toggle {
        log::info!("快捷键触发：切换守护");
        toggle_guard_outside(app);
    } else if *pressed == panic {
        log::warn!("快捷键触发：一键应急切断");
        let app2 = app.clone();
        // 切断里有提权与注册表操作，必须挪到异步运行时，绝不阻塞热键回调线程
        tauri::async_runtime::spawn(async move {
            let lang = st.language();
            let report = commands::emergency_cutoff_owned(app2.clone(), st).await;
            let (title, body) = i18n::panic_notify(
                lang,
                report.sessions_cleared,
                report.mappings_cleared,
                report.guard_disabled,
                &report.cert_state,
            );
            notify_user(&app2, title, body);
            refresh_tray(&app2);
        });
    }
}

/// 托盘菜单事件分发。
fn handle_tray_menu(app: &tauri::AppHandle, id: &str) {
    match id {
        "toggle" => toggle_guard_outside(app),
        "show" => show_main_window(app),
        "quit" => quit_app(app),
        _ => {}
    }
}

/// 退出应用：**必须**先还原系统级改动（系统代理 / hosts / 证书信任不动），
/// 否则系统代理会一直指向一个已退出的本地进程，所有浏览器请求全部失败。
///
/// 托盘「退出」、关闭行为为「直接退出」、询问窗里点「退出程序」三条路径
/// 都汇入这里——退出清理只允许存在这一份。
fn quit_app(app: &tauri::AppHandle) {
    let state = app.state::<Arc<AppState>>();
    if let Err(e) = commands::apply_guard_enabled(state.inner(), false) {
        log::warn!("退出前关闭守护失败: {}", e);
    }
    app.exit(0);
}

/// 主窗关闭请求分流：按 `close.behavior` 配置执行「询问 / 直接退出 / 直接托盘」。
///
/// 自绘标题栏 ✕（`w.close()`）、Alt+F4、任务栏关闭全部汇入 `CloseRequested`，
/// 这里是唯一需要分流的点。`Ask` 模式阻止默认关闭后 emit 给前端弹询问窗，
/// 用户的选择经 `confirm_close` 命令回来——窗口销毁后前端就没了，所以
/// 询问窗必须活在前端、由命令驱动后端动作。
fn handle_close_requested(
    app: &tauri::AppHandle,
    window: &tauri::Window,
    api: &tauri::CloseRequestApi,
) {
    let state = app.state::<Arc<AppState>>();
    let behavior = state.inner().close_behavior();
    match behavior {
        CloseBehavior::Exit => quit_app(app),
        CloseBehavior::Tray => {
            let _ = window.hide();
        }
        CloseBehavior::Ask => {
            state.inner().emit_event("close-requested", ());
        }
    }
    // 一律阻止默认关闭：Exit 路径由 quit_app 显式退出，其余路径窗口继续存活。
    api.prevent_close();
}

/// 启动自检：端口占用 / 私钥落盘保护 / 数据目录权限 / 调试器。
///
/// 全部结论只是**提示**（写入 `AppState::startup_notes` 供设置页展示），
/// 绝不允许任何一项失败导致应用启动失败——安全工具自身的可用性同样是安全要求。
fn run_startup_selfcheck(app_state: &Arc<AppState>) {
    let port = match app_state.config.read() {
        Ok(c) => c.proxy_port,
        Err(poisoned) => poisoned.into_inner().proxy_port,
    };
    let proxy = security::port_state(port);
    if proxy.is_problem() {
        let note = format!("本地代理端口异常：{}。守护功能将不可用。", proxy.detail);
        app_state.push_startup_note(note.clone());
        log::error!("{}", note);
    } else if proxy.state == "free" {
        let note = format!(
            "本地代理未在监听 127.0.0.1:{}（可能被防火墙/安全软件拦截）。请检查后重启应用。",
            port
        );
        app_state.push_startup_note(note.clone());
        log::error!("{}", note);
    } else {
        app_state.push_startup_note(format!("本地代理已就绪：{}", proxy.detail));
    }

    let pac = security::port_state(proxy_config::PAC_HTTP_PORT);
    if pac.is_problem() || pac.state == "free" {
        app_state.push_startup_note(format!(
            "PAC 服务端口 {} 异常（{}），浏览器可能无法获取代理配置。",
            proxy_config::PAC_HTTP_PORT,
            pac.detail
        ));
    }

    let key_path = app_state.data_dir.join("ca.key");
    match security::ca_key_at_rest(&key_path) {
        security::KeyAtRest::Encrypted => {
            app_state.push_startup_note("CA 私钥已用 DPAPI 加密落盘（仅当前用户可解密）。".into());
        }
        security::KeyAtRest::Plaintext => {
            let note = "CA 私钥当前为明文落盘（DPAPI 不可用），建议检查系统凭据服务。".to_string();
            app_state.push_startup_note(note.clone());
            log::warn!("{}", note);
        }
        security::KeyAtRest::Absent => {
            app_state.push_startup_note("CA 私钥文件不存在（首次启动会自动生成）。".into());
        }
    }

    // 目录权限的**逐条 ACE 明细**只在「本机安全加固」卡片里展示一次；
    // 自检列表里只留结论，避免把同一条超长 ACL 文本重复两遍。
    let acl = security::data_dir_acl(&app_state.data_dir);
    match acl.scope.as_str() {
        "shared" => {
            log::warn!("数据目录可能对同机其它账户开放：{}", acl.detail);
            app_state.push_startup_note(
                "数据目录存在可被同机其它账户写入的访问项（详见下方「数据目录隔离」）".into(),
            );
        }
        "user_only" => app_state
            .push_startup_note("数据目录权限：仅当前用户 / SYSTEM / 管理员可访问".into()),
        _ => app_state
            .push_startup_note("数据目录权限未能确认（icacls 不可用或被拦截）".into()),
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        // 全局快捷键：所有键位共用同一个 handler，由 handle_shortcut 按配置分发。
        // 只在 Pressed 触发——global-hotkey 对按下与抬起各回调一次，不去重会执行两遍。
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, shortcut, event| {
                    if event.state == tauri_plugin_global_shortcut::ShortcutState::Pressed {
                        handle_shortcut(app, shortcut);
                    }
                })
                .build(),
        )
        // 主窗关闭分流：自绘标题栏 ✕ / Alt+F4 / 任务栏关闭全部汇入同一条
        // CloseRequested，按「每次询问 / 直接退出 / 直接托盘」配置执行。
        .on_window_event(|window, event| {
            // WindowEvent 是 #[non_exhaustive]：跨 crate 匹配必须带 ..
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    handle_close_requested(window.app_handle(), window, api);
                }
            }
        })
        .setup(|app| {
            // 应用数据目录（存放 SQLite 与 CA 证书）
            let data_dir = app
                .path()
                .app_data_dir()
                .expect("无法获取应用数据目录");
            std::fs::create_dir_all(&data_dir).expect("无法创建应用数据目录");

            // SQLite 存储
            let db_path = data_dir.join("aiguard.db");
            let store = Store::open(&db_path).expect("无法打开 SQLite 存储");

            // 全局状态（内部启动审计事件后台写线程）
            let app_state = Arc::new(AppState::new(store, &db_path, data_dir.clone()));
            commands::restore_config(&app_state);
            // 按持久化规格重建检测引擎（自定义规则 / 编辑过的内置规则）
            commands::init_rules(&app_state);

            // CA 证书：无则生成
            if let Err(e) = state::ensure_ca(&data_dir) {
                log::warn!("CA 生成失败（拦截 HTTPS 前请先解决）: {}", e);
            }

            // 注入 AppHandle 用于事件 emit
            let handle_for_state = app.handle().clone();
            if let Ok(mut guard) = app_state.app_handle.write() {
                *guard = Some(handle_for_state);
            }

            // PAC HTTP 服务常驻（浏览器 AutoConfigURL 指向这里；内容按守护开关动态变化）
            {
                let pac_state = app_state.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = proxy::run_pac_server(pac_state).await {
                        log::error!("PAC 服务异常退出: {}", state::safe_err(&e));
                    }
                });
            }

            // 启动恢复：守护开启且为系统代理模式时，重设系统代理（指向本地 PAC 服务）
            {
                let c = match app_state.config.read() {
                    Ok(c) => c,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if c.enabled && c.mode == state::ProxyMode::SystemProxy {
                    if let Err(e) = proxy_config::set_system_proxy_pac(&proxy_config::pac_http_url())
                    {
                        log::warn!("启动恢复系统代理失败: {}", e);
                    }
                }
            }

            // hosts 模式 + 守护开启：随应用启动拉起 443 透明拦截层（幂等）
            {
                let c = match app_state.config.read() {
                    Ok(c) => c,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let need_transparent = c.enabled && c.mode == state::ProxyMode::HostsFile;
                if need_transparent {
                    if let Err(e) = transparent::spawn_if_needed(&app_state) {
                        log::error!("hosts 模式透明代理启动失败: {}", e);
                    }
                }
            }

            // 启动本地代理
            let proxy_state = app_state.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = proxy::run_proxy(proxy_state).await {
                    log::error!("代理异常退出: {}", state::safe_err(&e));
                }
            });

            // 会话映射过期清理（每 60s 扫一次；在途会话被 pin 保护，超硬上限仍回收）
            let ttl_state = app_state.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    let ttl = ttl_state.restore_limits_snapshot().session_ttl_secs;
                    let purged = ttl_state
                        .vault
                        .purge_expired(std::time::Duration::from_secs(ttl));
                    if !purged.is_empty() {
                        log::info!("会话映射过期清理：销毁 {} 个空闲会话", purged.len());
                    }
                    // 请求上下文（含**脱敏前**请求正文采样）同步做内存擦除
                    let n = ttl_state.purge_expired_req_ctx();
                    if n > 0 {
                        log::debug!("请求上下文过期清理：擦除 {} 条请求正文采样", n);
                    }
                }
            });

            // 启动自检：端口占用 / 私钥落盘保护 / 数据目录权限（延迟 3s 等代理完成 bind）
            {
                let sc_state = app_state.clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    run_startup_selfcheck(&sc_state);
                });
            }

            // 防调试：启动即检一次，其后每 30s 复查（仅告警，不阻断任何业务）
            {
                let dbg_state = app_state.clone();
                tauri::async_runtime::spawn(async move {
                    loop {
                        let attached = crate::security::debugger_attached();
                        if dbg_state.note_debugger_state(attached) {
                            log::warn!(
                                "检测到调试器附加：本进程正被调试（仅告警，守护功能不受影响）"
                            );
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    }
                });
            }

            // 日志定期清理（每小时执行一次：请求日志按动作保留天数、审计按保留策略）
            {
                let cleanup_state = app_state.clone();
                tauri::async_runtime::spawn(async move {
                    // 启动 5 分钟后先跑一轮，之后每小时一轮
                    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                    loop {
                        match commands::run_cleanup(&cleanup_state) {
                            Ok(r) if r.total > 0 => {
                                log::info!(
                                    "日志定期清理：删除请求日志 {} 条（直通 {} / 已脱敏 {} / 已拦截 {}）、审计事件 {} 条",
                                    r.total, r.passthrough, r.mask, r.block, r.audit
                                );
                            }
                            Ok(_) => {}
                            Err(e) => log::warn!("日志定期清理失败: {}", e),
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                    }
                });
            }

            // 系统托盘：状态展示 + 快捷开关 + 最近事件（图标缺失时用内置绘制兜底）
            {
                let menu = build_tray_menu(app.handle(), &app_state)?;
                let mut builder = tauri::tray::TrayIconBuilder::with_id(TRAY_ID)
                    .tooltip(tray_tooltip(&app_state))
                    .menu(&menu)
                    .show_menu_on_left_click(false)
                    .on_menu_event(|app, event| handle_tray_menu(app, event.id().as_ref()))
                    .on_tray_icon_event(|tray, event| {
                        use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            show_main_window(tray.app_handle());
                        }
                    });
                builder = match app.default_window_icon().cloned() {
                    Some(icon) => builder.icon(icon),
                    None => builder.icon(fallback_tray_icon()),
                };
                builder.build(app)?;
            }

            // 托盘刷新：只在「状态 / 最近事件」变化时重建菜单（2 秒一次轻量比对）
            {
                let tray_state = app_state.clone();
                let tray_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    let mut last = String::new();
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        let sig = tray_signature(&tray_state);
                        if sig != last {
                            last = sig;
                            refresh_tray(&tray_handle);
                        }
                    }
                });
            }

            // 挂载全局状态
            app.manage(app_state.clone());

            // 窗口标题按持久化语言初始化。
            // tauri.conf.json 里的 title 只覆盖默认语言，用户上次选英文的话这里要纠正过来。
            sync_window_title(app.handle());

            // 全局快捷键：按持久化配置注册（默认开启）。
            // 注册失败（键位被别的程序占用）只告警：设置页会显示"未生效"，
            // 绝不能让"某个键位抢不到"这种小事阻止整个应用启动。
            {
                let cfg = app_state.shortcut_config();
                if cfg.enabled {
                    match commands::register_shortcuts(app.handle(), &cfg) {
                        Ok(()) => log::info!(
                            "全局快捷键已注册：{} / {}",
                            cfg.toggle_guard,
                            cfg.panic
                        ),
                        Err(e) => log::warn!("全局快捷键注册失败（可在设置中换键位）: {}", e),
                    }
                }
            }

            // 更新检查：**只有用户在设置里打开后才启动**；打开时启动 20 秒后首查，
            // 之后每 24 小时一轮。关闭状态下这里一次网络请求都不会发出。
            {
                let up_state = app_state.clone();
                let up_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    // 延后到界面与代理都就绪之后，不跟启动路径抢资源
                    tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                    loop {
                        let cfg = up_state.update_config();
                        if cfg.enabled {
                            let before = up_state.update_status().latest;
                            let status = commands::run_update_check(&up_state).await;
                            if status.failed {
                                log::warn!("更新检查失败: {}", status.note);
                            } else if status.has_update {
                                log::info!(
                                    "发现新版本 {}（当前 {}）",
                                    status.latest,
                                    status.current
                                );
                                // 只有"这个版本号是第一次看到"时才弹通知，
                                // 否则每 24 小时都会拿同一个版本打扰用户一次
                                if before != status.latest {
                                    let (title, body) = i18n::update_notify(
                                        up_state.language(),
                                        &status.current,
                                        &status.latest,
                                    );
                                    notify_user(&up_handle, title, body);
                                }
                            }
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(24 * 3600)).await;
                    }
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_dashboard,
            commands::list_requests,
            commands::get_rules,
            commands::set_rule,
            commands::add_custom_rule,
            commands::delete_rule,
            commands::reset_rule,
            commands::get_whitelist,
            commands::add_whitelist_entry,
            commands::update_whitelist_entry,
            commands::remove_whitelist_entry,
            commands::get_blacklist,
            commands::add_blacklist_entry,
            commands::remove_blacklist_entry,
            commands::get_security_points,
            commands::get_security_policy,
            commands::set_security_policy,
            commands::list_security_events,
            commands::clear_security_events,
            commands::clear_sessions,
            commands::run_link_check,
            commands::enable_guard,
            commands::disable_guard,
            commands::install_ca,
            commands::get_ca_status,
            commands::check_ca_trust,
            commands::set_restore_enabled,
            commands::list_requests_page,
            commands::list_audit_page,
            commands::get_cleanup_settings,
            commands::set_cleanup_settings,
            commands::cleanup_logs_now,
            commands::clear_request_logs,
            commands::clear_request_logs_by_action,
            commands::set_proxy_mode,
            commands::get_hardening_status,
            commands::check_proxy_port,
            commands::get_proxy_token,
            commands::regenerate_proxy_token,
            commands::set_require_token,
            commands::list_active_sessions,
            commands::clear_one_session,
            commands::emergency_cutoff,
            commands::get_notify_config,
            commands::set_notify_config,
            commands::test_notification,
            commands::get_language,
            commands::set_language,
            commands::get_onboarding_state,
            commands::complete_onboarding,
            commands::reset_onboarding,
            commands::get_shortcut_state,
            commands::set_shortcut_config,
            commands::get_update_state,
            commands::set_update_config,
            commands::check_update,
            commands::get_close_behavior,
            commands::set_close_behavior,
            commands::confirm_close,
            commands::test_regex,
            commands::export_rules,
            commands::import_rules_preview,
            commands::import_rules_apply,
            commands::apply_rule_preset,
            commands::get_rule_preset,
        ])
        .run(tauri::generate_context!())
        .expect("AI 安全卫士启动失败");
}

#[cfg(test)]
mod tray_tests {
    use super::*;

    /// 托盘「最近事件」文案的所有断言（含脱敏约束与中英双语）已随文案迁到
    /// `crate::i18n::tests`——文案与其测试必须待在同一个文件里，
    /// 否则加一条文案时很容易只改一处、漏掉守护它的用例。
    #[test]
    fn test_tray_copy_lives_in_i18n_module() {
        let line = i18n::tray_event_line(
            Language::Zh,
            &store::AuditEventRow {
                seq: 0,
                ts: store::now_secs_f64() - 125.0,
                sid: "conv:api.openai.com:chat-1".into(),
                host: "api.openai.com".into(),
                method: "POST".into(),
                path: "/v1/chat/completions".into(),
                signal_type: "response_poison".into(),
                severity: "HIGH".into(),
                evidence: String::new(),
                request_hash: String::new(),
                response_hash: String::new(),
                probe_id: String::new(),
            },
        );
        assert!(line.contains("响应夹带"), "{}", line);
        assert!(line.contains("高危"), "{}", line);
    }

    /// 托盘签名必须把语言与快捷键配置都算进去，否则改了它们菜单不会刷新。
    #[test]
    fn test_tray_signature_covers_language_and_shortcuts() {
        let dir = std::env::temp_dir().join(format!("aiguard_sig_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let store = Store::open(&db).expect("临时库应可打开");
        let st = Arc::new(AppState::new(store, &db, dir.clone()));

        let a = tray_signature(&st);
        st.apply_language(Language::En).expect("语言落盘应成功");
        let b = tray_signature(&st);
        assert_ne!(a, b, "语言变化必须反映到托盘签名上");

        let mut cfg = st.shortcut_config();
        cfg.toggle_guard = "Ctrl+Alt+H".to_string();
        st.apply_shortcut_config(cfg).expect("快捷键落盘应成功");
        assert_ne!(b, tray_signature(&st), "快捷键变化必须反映到托盘签名上");

        std::fs::remove_dir_all(&dir).ok();
    }
}
