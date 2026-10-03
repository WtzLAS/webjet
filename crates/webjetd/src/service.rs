//! Running as a system service (§19.1): a Windows service (LocalSystem,
//! started after the Windows Time service), and on Unix the plain process
//! under systemd or launchd with SIGTERM/SIGINT handling. Also installs and
//! removes the Windows service.

#[cfg(windows)]
use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

pub type Shutdown = Pin<Box<dyn Future<Output = ()> + Send>>;

pub const SERVICE_NAME: &str = "webjetd";
pub const DISPLAY_NAME: &str = "Webjet agent";

/// Resolves when the process is asked to stop (Ctrl-C, SIGTERM).
pub fn signals() -> Shutdown {
    Box::pin(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    })
}

#[cfg(windows)]
pub mod windows {
    use super::*;
    use crate::config::Config;
    use std::ffi::OsString;
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceDependency, ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    static CONFIG: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    /// Hand the process to the service control manager.
    pub fn run_dispatcher(config: std::path::PathBuf) -> Result<()> {
        let _ = CONFIG.set(config);
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
        Ok(())
    }

    fn status(state: ServiceState, accept: ServiceControlAccept, code: u32, wait: Duration) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: wait,
            process_id: None,
        }
    }

    fn service_main(_args: Vec<OsString>) {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let tx = std::sync::Mutex::new(Some(tx));
        let handler = move |ev| -> ServiceControlHandlerResult {
            match ev {
                ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                    if let Some(t) = tx.lock().ok().and_then(|mut g| g.take()) {
                        let _ = t.send(());
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let Ok(h) = service_control_handler::register(SERVICE_NAME, handler) else { return };
        let _ = h.set_service_status(status(ServiceState::StartPending, ServiceControlAccept::empty(), 0, Duration::from_secs(30)));
        let cfg_path = CONFIG.get().cloned().unwrap_or_else(crate::config::default_config_path);
        let result = (|| -> Result<()> {
            let cfg = Config::load(Some(&cfg_path))?;
            crate::logging::init(&cfg);
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            let _ = h.set_service_status(status(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0, Duration::ZERO));
            rt.block_on(crate::agent::run_until(cfg, Box::pin(async move {
                let _ = rx.await;
            })))
        })();
        let code = match &result {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!("webjetd stopped: {e:#}");
                1
            }
        };
        let _ = h.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), code, Duration::ZERO));
    }

    /// Register webjetd as an automatic LocalSystem service that starts
    /// after the Windows Time service (§18.6).
    pub fn install(config: &std::path::Path) -> Result<()> {
        let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
        let exe = std::env::current_exe()?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments: vec![OsString::from("--config"), config.as_os_str().to_owned(), OsString::from("service")],
            dependencies: vec![ServiceDependency::Service(OsString::from("W32Time")), ServiceDependency::Service(OsString::from("Dnscache"))],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let s = m.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
        s.set_description("Webjet overlay network agent")?;
        s.start::<&str>(&[])?;
        println!("service {SERVICE_NAME} installed and started");
        Ok(())
    }

    /// Stop and remove the service and everything the agent configured.
    pub fn uninstall() -> Result<()> {
        let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let s = m.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)?;
        if s.query_status()?.current_state != ServiceState::Stopped {
            let _ = s.stop();
            for _ in 0..60 {
                if s.query_status()?.current_state == ServiceState::Stopped {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        s.delete()?;
        crate::platform::cleanup("Webjet");
        println!("service {SERVICE_NAME} removed");
        Ok(())
    }
}
