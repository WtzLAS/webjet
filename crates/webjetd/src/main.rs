use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use webjetd::config::Config;

#[derive(Parser)]
#[command(name = "webjetd", version, about = "The Webjet agent")]
struct Cli {
    /// Path to webjetd.toml.
    #[arg(short, long, global = true, default_value = "/etc/webjet/webjetd.toml")]
    config: PathBuf,
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
    /// Run the agent.
    Run,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut cfg = Config::load(Some(&cli.config))?;
    if let Some(d) = cli.data_dir {
        cfg.data_dir = d;
        if !cli.config.exists() {
            cfg.control_socket = cfg.data_dir.join("control.sock");
        }
    }
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| cfg.log.clone());
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::new(filter)).with_target(false).init();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        match cli.cmd {
            Cmd::Init { genesis, bootstrap } => webjetd::agent::init(&cfg, &std::fs::read(&genesis)?, bootstrap),
            Cmd::Enroll { ticket } => webjetd::agent::enroll(&cfg, &ticket).await,
            Cmd::Run => webjetd::agent::run(cfg).await,
        }
    })
}
