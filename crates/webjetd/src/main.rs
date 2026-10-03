use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use webjetd::config::Config;

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
    /// Create the data directory of the first controller of a new network.
    Init {
        #[arg(long)]
        genesis: PathBuf,
        /// This node bootstraps the network (runs the first controller).
        #[arg(long, default_value_t = true)]
        bootstrap: bool,
    },
    /// Enroll (or re-key) this node with an enrollment string.
    Enroll { ticket: String },
    /// Run the agent in the foreground.
    Run,
    /// Run under the Windows service manager (used by the installed service).
    #[cfg(windows)]
    Service,
    /// Install webjetd as a Windows service (LocalSystem, automatic start).
    #[cfg(windows)]
    Install,
    /// Stop and remove the Windows service and the agent's system settings.
    #[cfg(windows)]
    Uninstall,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg_path = cli
        .config
        .clone()
        .unwrap_or_else(webjetd::config::default_config_path);
    #[cfg(windows)]
    match cli.cmd {
        Cmd::Service => return webjetd::service::windows::run_dispatcher(cfg_path),
        Cmd::Install => return webjetd::service::windows::install(&cfg_path),
        Cmd::Uninstall => return webjetd::service::windows::uninstall(),
        _ => {}
    }
    if cli.config.is_some() && !cfg_path.exists() {
        anyhow::bail!("configuration file {} not found", cfg_path.display());
    }
    let mut cfg = Config::load(Some(&cfg_path))?;
    if let Some(d) = cli.data_dir {
        cfg.data_dir = d;
        if !cfg_path.exists() {
            cfg.control_socket = if cfg!(windows) {
                webjetd::ipc::default_control()
            } else {
                cfg.data_dir.join("control.sock")
            };
        }
    }
    webjetd::logging::init(&cfg);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        match cli.cmd {
            Cmd::Init { genesis, bootstrap } => {
                webjetd::agent::init(&cfg, &std::fs::read(&genesis)?, bootstrap)
            }
            Cmd::Enroll { ticket } => webjetd::agent::enroll(&cfg, &ticket).await,
            Cmd::Run => webjetd::agent::run(cfg).await,
            #[cfg(windows)]
            _ => unreachable!(),
        }
    })
}
