use std::sync::Arc;
use tgwsproxy::cfproxy;
use tgwsproxy::config::*;
use tgwsproxy::proxy::{parse_cidr_pool, run_proxy, WsPool};
use tgwsproxy::{linfo, lwarn, lerror};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

struct Args {
    bind: String,
    port: u16,
    secret: String,
    dc_ips: String,
    pool_size: i32,
    verbose: bool,
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    let mut bind = "127.0.0.1".to_string();
    let mut port: u16 = 1443;
    let mut secret = String::new();
    let mut dc_ips = String::new();
    let mut pool_size: i32 = 4;
    let mut verbose = false;

    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                i += 1;
                bind = args.get(i).cloned().unwrap_or(bind);
            }
            "--port" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(1443);
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
                pool_size = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(4);
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
    eprintln!("Опции:");
    eprintln!("  --bind <IP>         адрес прослушивания (по умолч.: 127.0.0.1)");
    eprintln!("  --port <PORT>       порт (по умолч.: 1443)");
    eprintln!("  --secret <HEX>      секрет прокси (32 hex символа)");
    eprintln!("  --dc-ips <LIST>     IP датацентров: \"1:ip1,2:ip2,...\"");
    eprintln!("  --pool-size <N>     размер пула соединений (по умолч.: 4)");
    eprintln!("  --verbose, -v       подробное логирование");
    eprintln!("  --help, -h          эта справка");
}

#[tokio::main]
async fn main() {
    let args = parse_args();

    init_logging(args.verbose);
    cfproxy::clear_cfproxy_429_cooldowns();

    if args.secret.len() == 32 && hex::decode(&args.secret).is_ok() {
        *PROXY_SECRET.write() = args.secret.clone();
        linfo!("секрет установлен из аргументов");
    } else if !args.secret.is_empty() {
        lwarn!("некорректный секрет (нужно 32 hex символа), использую значение по умолч.");
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
