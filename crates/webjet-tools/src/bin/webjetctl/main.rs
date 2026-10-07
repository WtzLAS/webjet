//! webjetctl: the Webjet command-line tool (§13). Three groups, by scope:
//!
//! - `network`: the whole network — its configuration, nodes, accounts,
//!   controllers, PSK and camouflage. Signs operations with an account key
//!   kept on this machine and submits them through the local webjetd.
//! - `local`: this machine and one node — setting it up (`init`, `enroll`),
//!   looking at it (`status`, `peers`, …) and the node's own configuration
//!   (`local config`, which overrides the network's for that node).
//! - `root`: the offline root and emergency revocation keys.

mod account;
mod agent;
mod cli;
mod conf;
mod controller;
mod local;
mod node;
mod output;
mod rollout;

use crate::{account::*, agent::*, cli::*, conf::*, controller::*, local::*, node::*, output::*};
use anyhow::Result;
use clap::Parser;
use serde_json::json;
use webjet_tools::*;
use webjetd::control::Request;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Root { dir, cmd } => {
            // Offline: no agent, no network. Blocking file and prompt work
            // runs off the async runtime's thread.
            let (dir, cmd) = (dir.clone(), cmd.clone());
            tokio::task::spawn_blocking(move || webjet_tools::root::run(&dir, cmd)).await??;
        }
        Cmd::Network { cmd } => network(&cli, cmd).await?,
        Cmd::Local { cmd } => local(&cli, cmd).await?,
    }
    Ok(())
}

pub(crate) async fn network(cli: &Cli, cmd: &NetworkCmd) -> Result<()> {
    match cmd {
        NetworkCmd::Account { cmd } => network_account(cli, cmd).await?,
        NetworkCmd::Node { cmd } => network_node(cli, cmd).await?,
        NetworkCmd::Psk {
            cmd: PskCmd::Rotate,
        } => {
            let a = load_account(cli).await?;
            let st = call(cli, Request::Status).await?;
            let (next, op) = ops::rotate_psk(&a, ops::psk_epoch(&st)?)?;
            let r = submit(cli, op).await?;
            report(
                cli,
                format!("PSK rotated to epoch {next} (entry {})", r["index"]),
                json!({"psk_epoch": next, "entry": entry(&r)}),
            );
        }
        NetworkCmd::Camouflage { cmd } => network_camouflage(cli, cmd).await?,
        NetworkCmd::Controller { cmd } => network_controller(cli, cmd).await?,
        NetworkCmd::Submit { file } => {
            let raw = read(file)?;
            eprintln!("{}", describe(&raw));
            let r = call(cli, Request::SubmitSigned { signed: raw }).await?;
            print(cli, &r);
        }
        NetworkCmd::Config { cmd } => network_config(cli, cmd).await?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// clap's own consistency checks (duplicate flags, bad defaults, …).
    #[test]
    fn the_command_line_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn a_new_node_gets_the_first_free_pool_address() {
        let info = serde_json::json!({
            "overlay_pool": ["10.7.0.0/29"],
            "used_ips": ["10.7.0.1", "10.7.0.3"],
            "resolver": ["10.7.0.2"],
        });
        assert_eq!(pick_ip(&info).unwrap(), "10.7.0.4");
        let full = serde_json::json!({
            "overlay_pool": ["10.7.0.0/30"],
            "used_ips": ["10.7.0.1"],
            "resolver": ["10.7.0.2"],
        });
        assert!(pick_ip(&full).is_err());
    }
}
