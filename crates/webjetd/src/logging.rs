//! Logging setup (§19.6): structured JSON lines when `log_format = "json"`
//! (journald, the unified log or the Event Log collect stdout/stderr of the
//! service), human-readable text otherwise.

use crate::config::Config;

pub fn init(cfg: &Config) {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| cfg.log.clone());
    let f = tracing_subscriber::EnvFilter::new(filter);
    let r = if cfg.log_format.as_deref() == Some("json") {
        tracing_subscriber::fmt()
            .with_env_filter(f)
            .with_target(false)
            .json()
            .try_init()
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(f)
            .with_target(false)
            .try_init()
    };
    let _ = r;
    crate::tasks::install_panic_hook();
}
