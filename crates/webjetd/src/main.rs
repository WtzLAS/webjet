use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use webjetd::config::Config;

/// The Webjet agent. Setting up a node (`webjetctl local init`, `webjetctl local enroll`)
/// and installing the service (`webjetup`) are done by the other programs.
#[derive(Parser)]
#[command(name = "webjetd", version, about = "The Webjet agent")]
struct Cli {
    /// Path to webjetd.toml (default: /etc/webjet, /Library/Application
    /// Support/Webjet or %ProgramData%\Webjet). A path given here or in
    /// WEBJET_CONFIG must exist.
    #[arg(short, long, global = true, env = "WEBJET_CONFIG")]
    config: Option<PathBuf>,
    /// Override the data directory.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the agent in the foreground.
    Run,
    /// Hold a controller's signing key in this separate process (§19.2).
    /// Point the controller at it with `signer_socket` in `[controller]`.
    Signer {
        /// The signing key file (created when missing).
        #[arg(long, default_value = default_signer_key())]
        key: PathBuf,
        /// Unix socket, or named pipe on Windows.
        #[arg(long, default_value = default_signer_socket())]
        socket: PathBuf,
    },
    /// Run under the Windows service manager (the installed service's entry
    /// point; webjetup registers it).
    #[cfg(windows)]
    #[command(hide = true)]
    Service,
}

fn default_signer_key() -> &'static str {
    if cfg!(windows) {
        r"C:\ProgramData\webjet-signer\signing.key"
    } else {
        "/var/lib/webjet-signer/signing.key"
    }
}

fn default_signer_socket() -> &'static str {
    if cfg!(windows) {
        r"\\.\pipe\webjet-signer"
    } else {
        "/run/webjet/signer.sock"
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg_path = cli
        .config
        .clone()
        .unwrap_or_else(webjetd::config::default_config_path);
    match cli.cmd {
        #[cfg(windows)]
        Cmd::Service => return webjetd::service::windows::run_dispatcher(cfg_path),
        Cmd::Signer { key, socket } => return signer(&key, &socket),
        Cmd::Run => {}
    }
    if cli.config.is_some() && !cfg_path.exists() {
        anyhow::bail!("configuration file {} not found", cfg_path.display());
    }
    let mut cfg = Config::load(Some(&cfg_path))?;
    if let Some(d) = cli.data_dir {
        cfg.override_data_dir(d, cfg_path.exists());
    }
    webjetd::logging::init(&cfg);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(webjetd::agent::run(cfg))
}

/// `webjetd signer`: serve signatures with the key in `key` on `socket`.
fn signer(key: &std::path::Path, socket: &std::path::Path) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let kp = webjetd::controller::signer::load_or_create_key(key)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(webjetd::controller::signer::serve(socket, kp))
}
