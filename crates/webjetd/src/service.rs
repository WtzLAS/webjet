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

/// Resolves when the process is asked to stop (Ctrl-C, SIGTERM).
pub fn signals() -> Shutdown {
    Box::pin(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
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
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    static CONFIG: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    /// The `webjet-signer` service (`webjetd signer-service`).
    pub const SIGNER_SERVICE_NAME: &str = "webjet-signer";

    static SIGNER: std::sync::OnceLock<(std::path::PathBuf, std::path::PathBuf)> =
        std::sync::OnceLock::new();

    define_windows_service!(ffi_signer_main, signer_main);

    /// Hand the process to the service control manager as the signer.
    pub fn run_signer_dispatcher(
        key: std::path::PathBuf,
        socket: std::path::PathBuf,
    ) -> Result<()> {
        let _ = SIGNER.set((key, socket));
        service_dispatcher::start(SIGNER_SERVICE_NAME, ffi_signer_main)?;
        Ok(())
    }

    fn signer_main(_args: Vec<OsString>) {
        let Some((h, rx)) = register(SIGNER_SERVICE_NAME) else {
            return;
        };
        let Some((key, socket)) = SIGNER.get().cloned() else {
            return;
        };
        let result = (|| -> Result<()> {
            let kp = crate::controller::signer::load_or_create_key(&key)?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let _ = h.set_service_status(status(
                ServiceState::Running,
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                0,
                Duration::ZERO,
            ));
            rt.block_on(crate::controller::signer::serve_until(
                &socket,
                kp,
                crate::ipc::Access::Private,
                async move {
                    let _ = rx.await;
                },
            ))
        })();
        let _ = h.set_service_status(status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            u32::from(result.is_err()),
            Duration::ZERO,
        ));
    }

    /// Hand the process to the service control manager.
    pub fn run_dispatcher(config: std::path::PathBuf) -> Result<()> {
        let _ = CONFIG.set(config);
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
        Ok(())
    }

    /// Register `name`'s control handler with the service control manager.
    /// The receiver fires on Stop, Shutdown or Preshutdown.
    fn register(
        name: &str,
    ) -> Option<(
        service_control_handler::ServiceStatusHandle,
        tokio::sync::oneshot::Receiver<()>,
    )> {
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
        let h = service_control_handler::register(name, handler).ok()?;
        Some((h, rx))
    }

    fn status(
        state: ServiceState,
        accept: ServiceControlAccept,
        code: u32,
        wait: Duration,
    ) -> ServiceStatus {
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
        let Some((h, rx)) = register(SERVICE_NAME) else {
            return;
        };
        let _ = h.set_service_status(status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            0,
            Duration::from_secs(30),
        ));
        let cfg_path = CONFIG
            .get()
            .cloned()
            .unwrap_or_else(crate::config::default_config_path);
        let result = (|| -> Result<()> {
            let cfg = Config::load(Some(&cfg_path))?;
            crate::logging::init(&cfg);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let _ = h.set_service_status(status(
                ServiceState::Running,
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                0,
                Duration::ZERO,
            ));
            rt.block_on(crate::agent::run_until(
                cfg,
                Box::pin(async move {
                    let _ = rx.await;
                }),
            ))
        })();
        let code = match &result {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!("webjetd stopped: {e:#}");
                1
            }
        };
        let _ = h.set_service_status(status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            code,
            Duration::ZERO,
        ));
    }
}
