//! webjet-signer: holds a controller's signing key in a separate process
//! (§19.2) and signs only tree heads and its own certificate requests.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use webjet_core::crypto::KeyPair;

#[derive(Parser)]
#[command(name = "webjet-signer", version, about = "Webjet controller signing service")]
struct Cli {
    /// The signing key file (created when missing).
    #[arg(long, default_value = "/var/lib/webjet-signer/signing.key")]
    key: PathBuf,
    #[arg(long, default_value = "/run/webjet/signer.sock")]
    socket: PathBuf,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    let cli = Cli::parse();
    if !cli.key.exists() {
        let kp = KeyPair::generate();
        webjet_tools::write_private(&cli.key, &kp.seed()[..])?;
        tracing::info!("generated a new signing key at {}", cli.key.display());
    }
    let kp = webjet_tools::keypair_from(&std::fs::read(&cli.key)?)?;
    if let Some(d) = cli.socket.parent() {
        std::fs::create_dir_all(d)?;
    }
    webjetd::controller::signer::serve(&cli.socket, kp)
}
