use std::ffi::OsString;
use std::sync::Arc;
use crate::cfproxy;
use crate::config::*;
use crate::proxy::{parse_cidr_pool, run_proxy, WsPool};
use crate::{linfo, lerror, ldebug};
use once_cell::sync::Lazy;
use parking_lot::Mutex as ParkingMutex;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const SERVICE_NAME: &str = "TgWsProxy";

pub struct ServiceConfig {
    pub bind: String,
    pub port: u16,
    pub dc_ips: String,
    pub pool_size: i32,
    pub verbose: bool,
    pub log_file: String,
}

static SERVICE_CFG: Lazy<ParkingMutex<Option<ServiceConfig>>> =
    Lazy::new(|| ParkingMutex::new(None));

pub fn install_service(exe_path: &str) {
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Ошибка подключения к SCM: {}", e);
            std::process::exit(1);
        }
    };

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("TG WS Proxy"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::path::PathBuf::from(exe_path),
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    match manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG) {
        Ok(_) => {
            println!("Служба '{}' установлена.", SERVICE_NAME);
            println!("Запустите: sc start {}", SERVICE_NAME);
        }
        Err(e) => {
            eprintln!("Ошибка установки службы: {}", e);
            std::process::exit(1);
        }
    }
}

pub fn uninstall_service() {
    let manager_access = ServiceManagerAccess::CONNECT;
    let manager = match ServiceManager::local_computer(None::<&str>, manager_access) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Ошибка подключения к SCM: {}", e);
            std::process::exit(1);
        }
    };

    let service_access = ServiceAccess::DELETE;
    match manager.open_service(SERVICE_NAME, service_access) {
        Ok(service) => match service.delete() {
            Ok(_) => println!("Служба '{}' удалена.", SERVICE_NAME),
            Err(e) => {
                eprintln!("Ошибка удаления службы: {}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Служба '{}' не найдена: {}", SERVICE_NAME, e);
            std::process::exit(1);
        }
    }
}

/// Пытается запуститься как Windows Service.
/// Если процесс запущен SCM — блокируется навсегда (работает как служба).
/// Если процесс запущен вручную — возвращает ошибку, и main() запускает консольный режим.
pub fn try_run_as_service(cfg: ServiceConfig) {
    *SERVICE_CFG.lock() = Some(cfg);
    match service_dispatcher::start(SERVICE_NAME, service_main) {
        Ok(()) => {
            std::process::exit(0);
        }
        Err(e) => {
            ldebug!("не удалось запуститься как служба: {}", e);
        }
    }
}

extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let cfg = SERVICE_CFG.lock().take().expect("ServiceConfig не инициализирован");

    let cancel_token = CancellationToken::new();
    let cancel = cancel_token.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                cancel.cancel();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = match service_control_handler::register(SERVICE_NAME, event_handler) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Ошибка регистрации обработчика службы: {}", e);
            return;
        }
    };

    let running_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    };

    if let Err(e) = status_handle.set_service_status(running_status) {
        eprintln!("Ошибка установки статуса Running: {}", e);
        return;
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        init_logging(cfg.verbose);
        init_file_logging(&cfg.log_file);
        cfproxy::clear_cfproxy_429_cooldowns();
        cfproxy::init_cfproxy_domains();

        POOL_SIZE.store(cfg.pool_size, std::sync::atomic::Ordering::Relaxed);
        let dc_opt_map = parse_cidr_pool(&cfg.dc_ips);

        let pool = Arc::new(WsPool::new(cancel_token.clone()));

        let addr = format!("{}:{}", cfg.bind, cfg.port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                lerror!("не удалось открыть порт {}: {}", addr, e);
                let stopped = ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: ServiceState::Stopped,
                    controls_accepted: ServiceControlAccept::STOP,
                    exit_code: ServiceExitCode::Win32(1),
                    checkpoint: 0,
                    wait_hint: std::time::Duration::default(),
                    process_id: None,
                };
                status_handle.set_service_status(stopped).ok();
                return;
            }
        };

        linfo!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        linfo!("  TG WS Proxy — Windows Service");
        linfo!("  Адрес: {}", addr);

        if let Err(e) =
            run_proxy(pool, cfg.bind, cfg.port, dc_opt_map, cancel_token, listener).await
        {
            lerror!("прокси завершился с ошибкой: {}", e);
        }

        linfo!("прокси остановлен");
    });

    let stopped_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(stopped_status).ok();
}
