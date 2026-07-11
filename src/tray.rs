use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder, TrayIconEvent};
use crate::config::*;
use crate::{linfo, lerror, Args};

fn create_icon() -> Icon {
    let size = 32u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let cx = size as f32 / 2.0;
    let cy = size as f32 / 2.0;
    let radius = size as f32 / 2.0 - 2.0;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - cx;
            let dy = y as f32 - cy;
            let dist = (dx * dx + dy * dy).sqrt();
            if dist <= radius {
                let idx = (y * size + x) as usize * 4;
                let r = 76u8;
                let g = 175u8;
                let b = 80u8;
                let a = if dist > radius - 1.5 { (255.0 * (radius - dist + 1.5) / 1.5) as u8 } else { 255u8 };
                rgba[idx] = r;
                rgba[idx + 1] = g;
                rgba[idx + 2] = b;
                rgba[idx + 3] = a;
            }
        }
    }
    Icon::from_rgba(rgba, size, size).unwrap()
}

fn run_proxy_in_background(
    args: Args,
    cancel_token: CancellationToken,
    running: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            crate::cfproxy::clear_cfproxy_429_cooldowns();
            crate::cfproxy::init_cfproxy_domains();

            POOL_SIZE.store(args.pool_size, std::sync::atomic::Ordering::Relaxed);
            let dc_opt_map = crate::proxy::parse_cidr_pool(&args.dc_ips);

            let pool = Arc::new(crate::proxy::WsPool::new(cancel_token.clone()));

            let addr = format!("{}:{}", args.bind, args.port);
            let listener = match tokio::net::TcpListener::bind(&addr).await {
                Ok(l) => l,
                Err(e) => {
                    lerror!("не удалось открыть порт {}: {}", addr, e);
                    running.store(false, Ordering::SeqCst);
                    return;
                }
            };

            linfo!("  TG WS Proxy запущен");
            linfo!("  Адрес: {}", addr);
            running.store(true, Ordering::SeqCst);

            if let Err(e) = crate::proxy::run_proxy(
                pool,
                args.bind,
                args.port,
                dc_opt_map,
                cancel_token,
                listener,
            )
            .await
            {
                lerror!("прокси завершился с ошибкой: {}", e);
            }

            linfo!("прокси остановлен");
            running.store(false, Ordering::SeqCst);
        });
    });
}

pub fn start_tray(args: Args) {
    init_logging(args.verbose);
    init_file_logging(&args.log_file);

    // Секрет: CLI > config > авто-генерация
    if args.secret.len() == 32 && hex::decode(&args.secret).is_ok() {
        *PROXY_SECRET.write() = args.secret.clone();
    }

    let running = Arc::new(AtomicBool::new(false));
    let cancel_token = CancellationToken::new();

    // Запускаем прокси
    run_proxy_in_background(args, cancel_token.clone(), running.clone());

    let menu = Menu::new();

    let status_item = MenuItem::new("TG WS Proxy", true, None);
    status_item.set_enabled(false);
    menu.append(&status_item).ok();

    menu.append(&PredefinedMenuItem::separator()).ok();

    let stop_item = MenuItem::new("Остановить", true, None);
    menu.append(&stop_item).ok();

    let start_item = MenuItem::new("Запустить", true, None);
    menu.append(&start_item).ok();

    menu.append(&PredefinedMenuItem::separator()).ok();

    let exit_item = MenuItem::new("Выход", true, None);
    menu.append(&exit_item).ok();

    let icon = create_icon();
    let tray = TrayIconBuilder::new()
        .with_icon(icon)
        .with_menu(Box::new(menu))
        .with_tooltip("TG WS Proxy — запуск...")
        .build()
        .unwrap();

    std::thread::sleep(Duration::from_millis(500));
    if running.load(Ordering::SeqCst) {
        tray.set_tooltip(Some("TG WS Proxy — работает")).ok();
    } else {
        tray.set_tooltip(Some("TG WS Proxy — остановлен")).ok();
    }

    loop {
        std::thread::sleep(Duration::from_millis(50));

        // Обновляем tooltip при изменении статуса
        if running.load(Ordering::SeqCst) {
            tray.set_tooltip(Some("TG WS Proxy — работает")).ok();
        } else {
            tray.set_tooltip(Some("TG WS Proxy — остановлен")).ok();
        }

        // Обработка событий меню
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == stop_item.id() {
                if running.load(Ordering::SeqCst) {
                    linfo!("остановка прокси из трея");
                    cancel_token.cancel();
                }
            } else if event.id == start_item.id() {
                if !cancel_token.is_cancelled() {
                    // Если прокси не был остановлен — ничего не делаем
                } else {
                    // Создаём новый token и перезапускаем
                    // (пока не реализовано — выходим, пользователь перезапустит приложение)
                    linfo!("перезапуск после остановки пока не поддерживается");
                }
            } else if event.id == exit_item.id() {
                linfo!("выход из трея");
                if running.load(Ordering::SeqCst) {
                    cancel_token.cancel();
                }
                std::thread::sleep(Duration::from_millis(200));
                std::process::exit(0);
            }
        }

        // Обработка кликов по иконке
        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            match event {
                TrayIconEvent::DoubleClick { .. } => {
                    // Можно открыть окно статуса (пока ничего)
                }
                _ => {}
            }
        }
    }
}
