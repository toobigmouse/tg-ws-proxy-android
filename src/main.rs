use std::path::PathBuf;
use std::sync::Arc;
use tgwsproxy::cfproxy;
use tgwsproxy::config::*;
use tgwsproxy::proxy::{parse_cidr_pool, run_proxy, WsPool};
use tgwsproxy::{linfo, lwarn, lerror};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[derive(serde::Deserialize, serde::Serialize)]
struct Config {
    bind: String,
    port: u16,
    secret: String,
    dc_ips: String,
    pool_size: i32,
    verbose: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".to_string(),
            port: 1443,
            secret: String::new(),
            dc_ips: String::new(),
            pool_size: 4,
            verbose: false,
        }
    }
}

struct Args {
    bind: String,
    port: u16,
    secret: String,
    dc_ips: String,
    pool_size: i32,
    verbose: bool,
}

fn config_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    let dir = exe.parent().unwrap_or(std::path::Path::new("."));
    dir.join("config.toml")
}

fn load_config() -> Config {
    let path = config_path();
    if !path.exists() {
        let cfg = Config::default();
        save_config(&cfg);
        println!("Создан config.toml: {}", path.display());
        return cfg;
    }

    match std::fs::read_to_string(&path) {
        Ok(content) => match toml::from_str(&content) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Ошибка парсинга config.toml: {}, использую значения по умолч.", e);
                Config::default()
            }
        },
        Err(e) => {
            eprintln!("Ошибка чтения config.toml: {}, использую значения по умолч.", e);
            Config::default()
        }
    }
}

fn save_config(cfg: &Config) {
    let path = config_path();
    match toml::to_string_pretty(cfg) {
        Ok(toml_str) => {
            std::fs::write(&path, &toml_str).ok();
        }
        Err(e) => {
            eprintln!("Ошибка сериализации config.toml: {}", e);
        }
    }
}

fn parse_args(config: &Config) -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    let mut bind = config.bind.clone();
    let mut port = config.port;
    let mut secret = config.secret.clone();
    let mut dc_ips = config.dc_ips.clone();
    let mut pool_size = config.pool_size;
    let mut verbose = config.verbose;

    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                i += 1;
                bind = args.get(i).cloned().unwrap_or(bind);
            }
            "--port" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(port);
            }
            "--secret" => {
                i += 1;
                secret = args.get(i).cloned().unwrap_or_default();
            }
            "--dc-ips" => {
                i += 1;
                dc_ips = args.get(i).cloned().unwrap_or_default();
            }
            "--pool-size" => {
                i += 1;
                pool_size = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(pool_size);
            }
            "--verbose" | "-v" => {
                verbose = true;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                eprintln!("Неизвестный аргумент: {}", args[i]);
                print_help();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    Args {
        bind,
        port,
        secret,
        dc_ips,
        pool_size,
        verbose,
    }
}

fn print_help() {
    eprintln!("TG WS Proxy — Windows port");
    eprintln!();
    eprintln!("Использование: tgwsproxy [опции]");
    eprintln!();
    eprintln!("Опции (переопределяют config.toml):");
    eprintln!("  --bind <IP>         адрес прослушивания (по умолч.: 127.0.0.1)");
    eprintln!("  --port <PORT>       порт (по умолч.: 1443)");
    eprintln!("  --secret <HEX>      секрет прокси (32 hex символа)");
    eprintln!("  --dc-ips <LIST>     IP датацентров: \"1:ip1,2:ip2,...\"");
    eprintln!("  --pool-size <N>     размер пула соединений (по умолч.: 4)");
    eprintln!("  --verbose, -v       подробное логирование");
    eprintln!("  --help, -h          эта справка");
    eprintln!();
    eprintln!("config.toml загружается автоматически из папки exe.");
    eprintln!("CLI-флаги переопределяют значения из config.toml.");
    eprintln!("Если secret не задан нигде — генерируется новый и сохраняется в config.toml.");
}

fn generate_and_save_secret(config: &mut Config) {
    let new_secret = hex::encode(rand::random::<[u8; 16]>());
    *PROXY_SECRET.write() = new_secret.clone();
    config.secret = new_secret;
    save_config(config);
    linfo!("сгенерирован новый секрет и сохранён в config.toml");
}

#[tokio::main]
async fn main() {
    let mut config = load_config();
    let args = parse_args(&config);

    init_logging(args.verbose);
    cfproxy::clear_cfproxy_429_cooldowns();

    // Секрет: CLI > config > авто-генерация
    if args.secret.len() == 32 && hex::decode(&args.secret).is_ok() {
        *PROXY_SECRET.write() = args.secret.clone();
        linfo!("секрет установлен из аргументов/конфига");
    } else if !args.secret.is_empty() {
        lwarn!("некорректный секрет (нужно 32 hex символа), генерирую новый");
        generate_and_save_secret(&mut config);
    } else {
        generate_and_save_secret(&mut config);
    }

    cfproxy::init_cfproxy_domains();

    POOL_SIZE.store(args.pool_size, std::sync::atomic::Ordering::Relaxed);

    let dc_opt_map = parse_cidr_pool(&args.dc_ips);

    let cancel_token = CancellationToken::new();
    let pool = Arc::new(WsPool::new(cancel_token.clone()));

    let addr = format!("{}:{}", args.bind, args.port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            lerror!("не удалось открыть порт {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    linfo!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    linfo!("  TG WS Proxy — Windows");
    linfo!("  Адрес: {}", addr);

    let cancel = cancel_token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        linfo!("получен Ctrl+C, завершение...");
        cancel.cancel();
    });

    if let Err(e) = run_proxy(pool, args.bind, args.port, dc_opt_map, cancel_token, listener).await {
        lerror!("прокси завершился с ошибкой: {}", e);
        std::process::exit(1);
    }

    linfo!("прокси остановлен");
}
