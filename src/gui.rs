use std::sync::atomic::Ordering;
use std::sync::Arc;
use eframe::egui;
use tokio_util::sync::CancellationToken;
use crate::config::*;
use crate::Args;

struct ProxyRunner {
    cancel_token: Option<CancellationToken>,
    running: bool,
}

impl ProxyRunner {
    fn new() -> Self {
        Self { cancel_token: None, running: false }
    }

    fn start(&mut self, args: &Args) {
        if self.running {
            return;
        }
        let cancel_token = CancellationToken::new();
        let token = cancel_token.clone();
        let bind = args.bind.clone();
        let port = args.port;
        let dc_ips = args.dc_ips.clone();
        let pool_size = args.pool_size;
        let verbose = args.verbose;
        let log_file = args.log_file.clone();
        let secret = args.secret.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                init_logging(verbose);
                init_file_logging(&log_file);

                if secret.len() == 32 && hex::decode(&secret).is_ok() {
                    *PROXY_SECRET.write() = secret;
                }

                crate::cfproxy::clear_cfproxy_429_cooldowns();
                crate::cfproxy::init_cfproxy_domains();

                POOL_SIZE.store(pool_size, Ordering::Relaxed);
                let dc_opt_map = crate::proxy::parse_cidr_pool(&dc_ips);

                let pool = Arc::new(crate::proxy::WsPool::new(token.clone()));

                let addr = format!("{}:{}", bind, port);
                let listener = match tokio::net::TcpListener::bind(&addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        crate::lerror!("не удалось открыть порт {}: {}", addr, e);
                        return;
                    }
                };

                crate::linfo!("  TG WS Proxy запущен на {}", addr);

                if let Err(e) = crate::proxy::run_proxy(
                    pool, bind, port, dc_opt_map, token, listener,
                )
                .await
                {
                    crate::lerror!("прокси завершился с ошибкой: {}", e);
                }

                crate::linfo!("прокси остановлен");
            });
        });

        self.cancel_token = Some(cancel_token);
        self.running = true;
    }

    fn stop(&mut self) {
        if let Some(ref token) = self.cancel_token {
            token.cancel();
        }
        self.running = false;
    }
}

impl Drop for ProxyRunner {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct ProxyApp {
    runner: ProxyRunner,
    args: Args,
}

impl ProxyApp {
    pub fn new(args: Args) -> Self {
        let mut app = Self {
            runner: ProxyRunner::new(),
            args,
        };
        app.runner.start(&app.args);
        app
    }
}

impl eframe::App for ProxyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // ----- Top panel: status bar -----
        egui::TopBottomPanel::top("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("TG WS Proxy");

                if self.runner.running {
                    ui.colored_label(egui::Color32::GREEN, "● РАБОТАЕТ");
                } else {
                    ui.colored_label(egui::Color32::RED, "● ОСТАНОВЛЕН");
                }

                let addr = format!("{}:{}", self.args.bind, self.args.port);
                ui.label(format!("Порт: {}", addr));
            });
        });

        // ----- Right panel: controls -----
        egui::SidePanel::right("controls")
            .resizable(false)
            .default_width(200.0)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(10.0);
                    ui.heading("Управление");
                    ui.separator();
                    ui.add_space(10.0);

                    if self.runner.running {
                        if ui.button("⏹ Остановить").clicked() {
                            self.runner.stop();
                        }
                    } else {
                        if ui.button("▶ Запустить").clicked() {
                            self.runner.start(&self.args);
                        }
                    }

                    ui.add_space(20.0);
                    ui.separator();
                    ui.add_space(10.0);

                    ui.label("Параметры:");

                    let mut bind = self.args.bind.clone();
                    ui.horizontal(|ui| {
                        ui.label("Bind:");
                        if ui.text_edit_singleline(&mut bind).lost_focus() {
                            self.args.bind = bind;
                        }
                    });

                    let mut port = self.args.port;
                    ui.horizontal(|ui| {
                        ui.label("Port:");
                        if ui.add(egui::DragValue::new(&mut port).range(1..=65535)).changed() {
                            self.args.port = port;
                        }
                    });

                    let mut pool = self.args.pool_size;
                    ui.horizontal(|ui| {
                        ui.label("Pool:");
                        if ui.add(egui::DragValue::new(&mut pool).range(1..=32)).changed() {
                            self.args.pool_size = pool;
                        }
                    });

                    ui.add_space(20.0);
                    if ui.button("Выход").clicked() {
                        self.runner.stop();
                        std::process::exit(0);
                    }
                });
            });

        // ----- Center panel: log -----
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Лог");
            ui.separator();

            let mut log_data: Vec<String> = {
                let guard = GUI_LOG.lock();
                guard.clone()
            };

            // Keep last 500 lines
            if log_data.len() > 500 {
                log_data.drain(0..log_data.len() - 500);
            }

            let log_text = log_data.join("\n");
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    ui.add_sized(
                        ui.available_size(),
                        egui::TextEdit::multiline(&mut log_text.as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(20)
                            .lock_focus(true),
                    );
                });

            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        });
    }
}
