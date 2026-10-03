//! webjet-signer: holds a controller's signing key in a separate process
//! (§19.2) and signs only tree heads and its own certificate requests.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use webjet_core::crypto::KeyPair;

#[derive(Parser)]
#[command(
    name = "webjet-signer",
    version,
    about = "Webjet controller signing service"
)]
struct Cli {
    /// The signing key file (created when missing).
    #[arg(long, default_value = default_key())]
    key: PathBuf,
    /// Unix socket, or named pipe on Windows.
    #[arg(long, default_value = default_socket())]
    socket: PathBuf,
}

fn default_key() -> &'static str {
    if cfg!(windows) {
        r"C:\ProgramData\webjet-signer\signing.key"
    } else {
        "/var/lib/webjet-signer/signing.key"
    }
}

fn default_socket() -> &'static str {
    if cfg!(windows) {
        r"\\.\pipe\webjet-signer"
    } else {
        "/run/webjet/signer.sock"
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    if !cli.key.exists() {
        let kp = KeyPair::generate();
        webjet_tools::write_private(&cli.key, &kp.seed()[..])?;
        tracing::info!("generated a new signing key at {}", cli.key.display());
    }
    let kp = webjet_tools::keypair_from(&std::fs::read(&cli.key)?)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(webjetd::controller::signer::serve(&cli.socket, kp))
}
