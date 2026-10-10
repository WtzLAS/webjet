//! `webjetctl local …`: this machine and its node.

use crate::{agent::*, cli::*, conf::*, output::*};
use anyhow::{Result, bail};
use std::path::{Path, PathBuf};
use webjet_tools::*;
use webjetd::control::Request;

/// The agent's configuration for `init` and `enroll`.
pub(crate) fn agent_config(
    config: Option<&Path>,
    data_dir: Option<PathBuf>,
) -> Result<webjetd::config::Config> {
    let path = config.map_or_else(webjetd::config::default_config_path, Path::to_path_buf);
    if config.is_some() && matches!(path.try_exists(), Ok(false)) {
        bail!("configuration file {} not found", path.display());
    }
    let mut cfg = webjetd::config::Config::load(Some(&path))?;
    if let Some(d) = data_dir {
        cfg.override_data_dir(d, path.exists());
    }
    Ok(cfg)
}

pub(crate) async fn local(cli: &Cli, cmd: &LocalCmd) -> Result<()> {
    match cmd {
        LocalCmd::Init {
            genesis,
            config,
            data_dir,
        } => {
            let cfg = agent_config(config.as_deref(), data_dir.clone())?;
            webjetd::agent::init(&cfg, &read(genesis)?, true)?;
        }
        LocalCmd::Enroll {
            string,
            config,
            data_dir,
        } => {
            let cfg = agent_config(config.as_deref(), data_dir.clone())?;
            webjetd::agent::enroll(&cfg, string).await?;
        }
        LocalCmd::Status => {
            let s = call(cli, Request::Status).await?;
            print(cli, &s);
        }
        LocalCmd::Peers => {
            let v = call(cli, Request::Peers).await?;
            if cli.json {
                print(cli, &v);
            } else {
                let mut rows = vec![vec![
                    "PEER".into(),
                    "TRANSPORT".into(),
                    "REMOTE".into(),
                    "RTT".into(),
                    "LOSS".into(),
                    "AGE".into(),
                ]];
                for h in v.as_array().cloned().unwrap_or_default() {
                    rows.push(vec![
                        h["peer"].as_str().unwrap_or("").into(),
                        h["transport"].as_str().unwrap_or("").into(),
                        h["remote"].as_str().unwrap_or("").into(),
                        format!("{:.1}ms", h["rtt_ms"].as_f64().unwrap_or(0.0)),
                        format!("{:.1}%", h["loss"].as_f64().unwrap_or(0.0) * 100.0),
                        format!("{}s", h["age_s"].as_u64().unwrap_or(0)),
                    ]);
                }
                print_table(&rows);
            }
        }
        LocalCmd::Sessions => print(cli, &call(cli, Request::Sessions).await?),
        LocalCmd::Conntrack => print(cli, &call(cli, Request::Conntrack).await?),
        LocalCmd::Proxy => print(cli, &call(cli, Request::Proxy).await?),
        LocalCmd::Topology => print(cli, &call(cli, Request::Topology).await?),
        LocalCmd::Ping {
            target,
            count,
            size,
        } => {
            // Names, ids and id prefixes are resolved here; addresses and
            // magic DNS names go to the agent as they are.
            let to = if target.parse::<std::net::IpAddr>().is_ok() {
                target.clone()
            } else {
                match node_id(cli, target).await {
                    // By address: every agent version takes that.
                    Ok(id) => nodes(cli)
                        .await?
                        .iter()
                        .find(|n| n["id"].as_str() == Some(&hex::encode(id)))
                        .and_then(|n| n["ips"][0].as_str())
                        .and_then(|ip| ip.split('/').next())
                        .map_or_else(|| target.clone(), String::from),
                    Err(_) => target.clone(),
                }
            };
            let v = call(
                cli,
                Request::Ping {
                    target: to,
                    count: Some(u64::from(*count)),
                    size: Some(u64::from(*size)),
                },
            )
            .await?;
            let replies = v["replies"].as_array().cloned().unwrap_or_default();
            let ok = replies.iter().filter(|r| r.is_number()).count();
            if cli.json {
                print(cli, &v);
            } else {
                for (i, r) in replies.iter().enumerate() {
                    match r.as_f64() {
                        Some(ms) => println!(
                            "reply from {}: seq={i} time={ms:.2} ms",
                            v["target"].as_str().unwrap_or("")
                        ),
                        None => println!("seq={i}: timeout"),
                    }
                }
            }
            if ok == 0 {
                bail!("no reply from {target}");
            }
        }
        LocalCmd::Metrics { all } => {
            let v = call(cli, Request::Metrics { all: *all }).await?;
            if cli.json {
                print(cli, &v);
            } else {
                print!("{}", v["openmetrics"].as_str().unwrap_or(""));
            }
        }
        LocalCmd::Inject { file } => {
            let raw = read(file)?;
            eprintln!("{}", describe(&raw));
            let r = call(cli, Request::SubmitSigned { signed: raw }).await?;
            print(cli, &r);
        }
        LocalCmd::Config { node, cmd } => local_config(cli, node.as_deref(), cmd).await?,
        LocalCmd::Controller { cmd } => local_controller(cli, cmd).await?,
    }
    Ok(())
}

pub(crate) async fn local_controller(cli: &Cli, cmd: &LocalControllerCmd) -> Result<()> {
    use webjetd::controller::recovery;
    let (r, what) = match cmd {
        LocalControllerCmd::ForceNewCluster {
            reason,
            min_version,
            config,
            data_dir,
        } => {
            let cfg = agent_config(config.as_deref(), data_dir.clone())?;
            recovery::ensure_stopped(&cfg).await?;
            (
                recovery::force_new_cluster(&cfg, *min_version, reason)?,
                "this controller is now the only voter of a new cluster",
            )
        }
        LocalControllerCmd::Restore {
            from,
            reason,
            min_version,
            replace,
            config,
            data_dir,
        } => {
            let cfg = agent_config(config.as_deref(), data_dir.clone())?;
            recovery::ensure_stopped(&cfg).await?;
            let pass = passphrase("WEBJET_BACKUP_PASSPHRASE", "snapshot passphrase")?;
            let snap = unseal(&pass, &read(from)?)?;
            (
                recovery::restore(&cfg, &snap, *min_version, *replace, reason)?,
                "restored the controller state; this node is the only voter of a new cluster",
            )
        }
    };
    report(
        cli,
        format!(
            "{what} (first entry {}, term {}{}{}).\nStart the agent, certify the controller's signing key if it has none (ops guide 2.4), and retire the lost controllers' keys (ops guide 2.9).",
            r.index,
            r.term,
            if r.jumped {
                ", above the versions nodes hold"
            } else {
                ""
            },
            if r.learners.is_empty() {
                String::new()
            } else {
                format!(", {} learners kept", r.learners.len())
            }
        ),
        serde_json::to_value(&r)?,
    );
    Ok(())
}
