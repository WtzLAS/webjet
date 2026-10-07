//! `webjetctl network node upgrade`: admin-signed remote upgrades.

use crate::{agent::*, cli::*, output::*};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use webjet_core::crypto::{self, Bytes32};
use webjet_core::types::now_ms;
use webjet_tools::upgrade;
use webjetd::control::Request;

pub(crate) struct Selection<'a> {
    pub(crate) names: &'a [String],
    pub(crate) tags: &'a [String],
    pub(crate) all: bool,
}

pub(crate) struct RolloutOpts<'a> {
    pub(crate) batch: usize,
    pub(crate) repo: &'a str,
    pub(crate) timeout: std::time::Duration,
    pub(crate) dry_run: bool,
    pub(crate) yes: bool,
}

/// The nodes a selection names, as rollout targets.
pub(crate) async fn upgrade_targets(
    cli: &Cli,
    sel: &Selection<'_>,
) -> Result<Vec<upgrade::Target>> {
    let all = nodes(cli).await?;
    let mut ids: Vec<Bytes32> = Vec::new();
    for v in &all {
        let Some(id) = v["id"].as_str().and_then(crypto::parse_hex32) else {
            continue;
        };
        let tagged = v["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|t| t.as_str().is_some_and(|t| sel.tags.iter().any(|x| x == t)));
        if v["valid"].as_bool() == Some(true) && (sel.all || tagged) {
            ids.push(id);
        }
    }
    for n in sel.names {
        let id = node_id(cli, n).await?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    if ids.is_empty() {
        bail!("no nodes selected (name them, or use --tag or --all)");
    }
    let ctl = call(cli, Request::Controller)
        .await
        .map_err(|e| anyhow!("can't read the controllers' Raft state: {e:#}"))?;
    let (roles, leader) = upgrade::raft_roles(&ctl);
    let me = call(cli, Request::Status)
        .await?
        .get("node_id")
        .and_then(|x| x.as_str())
        .and_then(crypto::parse_hex32);
    Ok(ids
        .into_iter()
        .map(|id| {
            let v = all
                .iter()
                .find(|v| v["id"].as_str() == Some(hex::encode(id).as_str()));
            upgrade::Target {
                id,
                name: v
                    .and_then(|v| v["name"].as_str())
                    .map_or_else(|| hex::encode(id), str::to_string),
                relay: v.and_then(|v| v["relay"].as_bool()).unwrap_or(false),
                voter: roles.get(&id).copied(),
                leader: leader == Some(id),
                me: me == Some(id),
            }
        })
        .collect())
}

pub(crate) fn confirm(question: &str) -> Result<()> {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        bail!("not confirmed: run with --yes to skip the question");
    }
    eprint!("{question} [yes]: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if matches!(answer.trim(), "yes" | "y") {
        Ok(())
    } else {
        bail!("cancelled")
    }
}

/// `webjetctl network node upgrade`.
pub(crate) async fn upgrade_nodes(
    cli: &Cli,
    version: &str,
    sel: &Selection<'_>,
    opts: &RolloutOpts<'_>,
) -> Result<()> {
    let tag = webjet_release::normalize_version(version);
    if !webjet_release::valid_tag(&tag) {
        bail!("{version:?} is not a release tag like v0.9.0");
    }
    let targets = upgrade_targets(cli, sel).await?;
    let stages = upgrade::stages(&targets, opts.batch);
    if !cli.json {
        println!("Upgrade to {tag}, in this order (each stage waits for the one before):");
        for (i, s) in stages.iter().enumerate() {
            let names: Vec<String> = s
                .iter()
                .map(|t| {
                    let role = match (t.leader, t.voter) {
                        (true, _) => " (controller, leader)",
                        (_, Some(true)) => " (controller, voter)",
                        (_, Some(false)) => " (controller, learner)",
                        _ if t.relay => " (relay)",
                        _ => "",
                    };
                    let me = if t.me { " (this node)" } else { "" };
                    format!("{}{role}{me}", t.name)
                })
                .collect();
            println!("  {:>2}. {}", i + 1, names.join(", "));
        }
    }
    if opts.dry_run {
        if cli.json {
            print(
                cli,
                &json!({"version": tag, "stages": stages.iter().map(|s| s.iter().map(|t| json!({"name": t.name, "node_id": hex::encode(t.id)})).collect::<Vec<_>>()).collect::<Vec<_>>()}),
            );
        }
        return Ok(());
    }
    let repo = opts.repo.to_string();
    let pin_tag = tag.clone();
    let (files, missing) =
        tokio::task::spawn_blocking(move || upgrade::pin_release(&repo, &pin_tag)).await??;
    if !missing.is_empty() {
        eprintln!(
            "note: {tag} has no files for {} yet; nodes on those platforms will refuse",
            missing.join(", ")
        );
    }
    if !opts.yes {
        confirm(&format!(
            "Upgrade {} node(s) to {tag}? Each restarts its agent",
            targets.len()
        ))?;
    }
    let a = load_account(cli).await?;
    let mut done: Vec<Value> = Vec::new();
    for (i, stage) in stages.iter().enumerate() {
        let mut waiting: Vec<(&upgrade::Target, String)> = Vec::new();
        for t in stage {
            let st = call(cli, Request::UpgradeStatus { node: Some(t.id) })
                .await
                .map_err(|e| {
                    anyhow!(
                        "{}: {e:#} (nodes before 0.9.0 can't be upgraded remotely: upgrade them with webjetup)",
                        t.name
                    )
                })?;
            if upgrade::progress(&st, &tag, "-") == upgrade::Progress::Done {
                if !cli.json {
                    println!(
                        "  {}: runs {} already",
                        t.name,
                        st["version"].as_str().unwrap_or("?")
                    );
                }
                done.push(json!({"name": t.name, "node_id": hex::encode(t.id), "result": "already", "version": st["version"]}));
                continue;
            }
            if st["remote"].as_bool() == Some(false) {
                bail!(
                    "{}: remote upgrades are turned off there ([upgrade] remote = false); stopped",
                    t.name
                );
            }
            if st["helper"].as_bool() != Some(true) {
                bail!(
                    "{}: no upgrade helper installed there (webjetup install sets it up); stopped",
                    t.name
                );
            }
            let req = upgrade::sign_request(&a.kp, &a.id, &t.id, &tag, &files, now_ms());
            let r = call(cli, Request::Upgrade { request: req })
                .await
                .map_err(|e| anyhow!("{}: {e:#}; stopped", t.name))?;
            let id = r["id"].as_str().unwrap_or_default().to_string();
            if !cli.json {
                println!(
                    "  {}: {} → {tag} queued",
                    t.name,
                    st["version"].as_str().unwrap_or("?")
                );
            }
            waiting.push((t, id));
        }
        let start = std::time::Instant::now();
        while !waiting.is_empty() {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let mut still = Vec::new();
            for (t, id) in waiting {
                // A node restarting doesn't answer for a while.
                let p = match call(cli, Request::UpgradeStatus { node: Some(t.id) }).await {
                    Ok(v) => upgrade::progress(&v, &tag, &id),
                    Err(e) => upgrade::Progress::Waiting(format!("{e:#}")),
                };
                match p {
                    upgrade::Progress::Done => {
                        if !cli.json {
                            println!("  {}: runs {tag}", t.name);
                        }
                        done.push(json!({"name": t.name, "node_id": hex::encode(t.id), "result": "upgraded", "version": tag}));
                    }
                    upgrade::Progress::Failed(e) => {
                        bail!(
                            "{}: {e}; stopped (stage {} of {})",
                            t.name,
                            i + 1,
                            stages.len()
                        )
                    }
                    upgrade::Progress::Waiting(why) => {
                        if start.elapsed() > opts.timeout {
                            bail!(
                                "{}: not done after {} min ({why}); stopped",
                                t.name,
                                opts.timeout.as_secs() / 60
                            );
                        }
                        still.push((t, id));
                    }
                }
            }
            waiting = still;
        }
    }
    report(
        cli,
        format!("{} node(s) run {tag}.", done.len()),
        json!({"version": tag, "nodes": done}),
    );
    Ok(())
}
