//! `network config` and `local config`: the configuration documents.

use crate::{agent::*, cli::*, output::*};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use webjet_core::crypto::{self, Bytes32};
use webjet_proto::{self as wp, AccountOp};
use webjet_tools::config::{
    self, ConfigFile, effective_from_json, network_from_tree, node_from_wire, render_effective,
    render_network, render_node,
};
use webjetd::control::Request;

pub(crate) async fn tree(cli: &Cli) -> Result<Value> {
    call(cli, Request::Tree).await
}

/// A wire value from a control reply; `None` for null.
pub(crate) fn from_json<T: serde::de::DeserializeOwned>(v: &Value) -> Result<Option<T>> {
    match v {
        Value::Null => Ok(None),
        v => Ok(Some(serde_json::from_value(v.clone())?)),
    }
}

pub(crate) fn show_doc(cli: &Cli, text: &str, doc: &ConfigFile) -> Result<()> {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(doc)?);
    } else {
        print!("{text}");
    }
    Ok(())
}

pub(crate) fn print_value(cli: &Cli, v: &toml::Value) -> Result<()> {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(v)?);
        return Ok(());
    }
    match v {
        toml::Value::String(s) => println!("{s}"),
        toml::Value::Table(t) => print!("{}", toml::to_string(t)?),
        other => println!("{other}"),
    }
    Ok(())
}

/// The directory a configuration file's relative paths are relative to.
pub(crate) fn base_dir(file: &Path) -> PathBuf {
    file.parent()
        .map(Path::to_path_buf)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Edit `text` in $VISUAL / $EDITOR. Returns the parsed result and the
/// file it is in (kept until the caller applied it), or `None` when nothing
/// changed.
pub(crate) fn edit_text(text: &str, name: &str) -> Result<Option<(ConfigFile, PathBuf)>> {
    // A new directory with a random name, only ours (0700): in a shared
    // temp directory another user could otherwise prepare the path and
    // swap the file between the editor and the signature. Kept when the
    // caller needs the file afterwards.
    let dir = tempfile::Builder::new()
        .prefix("webjetctl-")
        .tempdir()?
        .keep();
    let path = dir.join(name);
    std::fs::write(&path, text)?;
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| if cfg!(windows) { "notepad" } else { "vi" }.into());
    let mut words = editor.split_whitespace();
    let program = words.next().unwrap_or("vi");
    loop {
        let status = std::process::Command::new(program)
            .args(words.clone())
            .arg(&path)
            .status()
            .map_err(|e| anyhow!("can't start the editor {editor:?}: {e} (set EDITOR)"))?;
        if !status.success() {
            bail!("the editor failed; your file is {}", path.display());
        }
        let new = std::fs::read_to_string(&path)?;
        if new == text {
            let _ = std::fs::remove_dir_all(&dir);
            return Ok(None);
        }
        match ConfigFile::parse(&new) {
            Ok(f) => return Ok(Some((f, path))),
            Err(e) => {
                eprintln!("error: {e:#}");
                eprint!("Edit again? [Y/n] ");
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if answer.trim().eq_ignore_ascii_case("n") {
                    bail!(
                        "not applied; your file is {} (fix it and `apply` it)",
                        path.display()
                    );
                }
            }
        }
    }
}

/// Run an apply on an edited file: remove it on success, name it on failure.
pub(crate) async fn apply_edited<F: std::future::Future<Output = Result<()>>>(
    path: &Path,
    apply: F,
) -> Result<()> {
    match apply.await {
        Ok(()) => {
            if let Some(dir) = path.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
            Ok(())
        }
        Err(e) => Err(e.context(format!(
            "not applied; your edited file is {} (fix it and `apply` it)",
            path.display()
        ))),
    }
}

/// `network config apply`: the file's sections over the configuration in
/// force, as the next version. In refuse mode the network keeps its
/// camouflage certificate; a network without one gets a self-signed one,
/// whose key is stored with the controllers first so relays can serve it.
pub(crate) async fn apply_network(
    cli: &Cli,
    f: &ConfigFile,
    base: &Path,
    what: Option<&str>,
) -> Result<()> {
    let t = tree(cli).await?;
    let p = config::network_apply(f, &t, base)?;
    if let Some(n) = &p.note {
        eprintln!("note: {n}");
    }
    let a = load_account(cli).await?;
    let (version, domain) = (p.version, p.new_certificate_domain());
    let what = what.map_or_else(|| p.sections.join(", "), String::from);
    let mut ops = p.ops().into_iter().peekable();
    let mut entries = Vec::new();
    while let Some(op) = ops.next() {
        let r = submit(cli, a.sign(op)?).await?;
        entries.push(entry(&r));
        if ops.peek().is_some() {
            if !cli.json {
                println!(
                    "refuse mode: made a self-signed camouflage certificate for {} (key stored, entry {})",
                    domain.clone().unwrap_or_default(),
                    r["index"]
                );
            }
        } else {
            report(
                cli,
                format!(
                    "network configuration version {version} applied: {what} (entry {})",
                    r["index"]
                ),
                json!({
                    "applied": "network",
                    "version": version,
                    "changed": what,
                    "self_signed_camouflage": domain,
                    "entries": entries,
                }),
            );
        }
    }
    Ok(())
}

pub(crate) async fn network_config(cli: &Cli, cmd: &ConfigCmd) -> Result<()> {
    match cmd {
        ConfigCmd::Show { effective } => {
            if *effective {
                bail!("--effective is for a node: `webjetctl local config show --effective`");
            }
            let t = tree(cli).await?;
            show_doc(cli, &render_network(&t)?, &network_from_tree(&t, true)?)?;
        }
        ConfigCmd::Check { file } => {
            let f = ConfigFile::load(file)?;
            let from = f.base_version()?;
            config::network_wire(&f, from + 1, &base_dir(file))?;
            if let Some(n) = config::camouflage_note(&f) {
                eprintln!("note: {n}");
            }
            report(
                cli,
                format!(
                    "{} is valid: {} (sections left out stay as they are)",
                    file.display(),
                    f.sections().join(", ")
                ),
                json!({"valid": true, "file": file, "sections": f.sections(), "base_version": from}),
            );
            if let Ok(t) = tree(cli).await
                && let Some(now) = t["network_version"].as_u64()
                && now != from
            {
                eprintln!(
                    "note: made from version {from}, but version {now} is in force; apply will refuse it"
                );
            }
        }
        ConfigCmd::Apply { file } => {
            apply_network(cli, &ConfigFile::load(file)?, &base_dir(file), None).await?
        }
        ConfigCmd::Edit => {
            let t = tree(cli).await?;
            let Some((f, path)) = edit_text(&render_network(&t)?, "network.toml")? else {
                report(cli, "no changes", json!({"changed": false}));
                return Ok(());
            };
            apply_edited(&path, apply_network(cli, &f, Path::new("."), None)).await?;
        }
        ConfigCmd::Get { key } => {
            let t = tree(cli).await?;
            let doc = toml::Value::try_from(network_from_tree(&t, true)?)?;
            print_value(cli, config::get(&doc, key)?)?;
        }
        ConfigCmd::Set { key, value } => {
            let t = tree(cli).await?;
            let cur = network_from_tree(&t, false)?;
            let f =
                config::edit_network(&cur, |d| config::set(d, key, config::parse_value(value)))?;
            apply_network(cli, &f, Path::new("."), Some(&format!("{key} = {value}"))).await?;
        }
        ConfigCmd::Unset { key } => {
            let t = tree(cli).await?;
            let cur = network_from_tree(&t, false)?;
            // A section emptied by this (the last seed, the last key of
            // [limits.value] or [controllers], ...) is applied empty, not
            // left as it is.
            let f = config::edit_network(&cur, |d| config::unset(d, key))?;
            apply_network(cli, &f, Path::new("."), Some(&format!("{key} unset"))).await?;
        }
    }
    Ok(())
}

/// A node's configuration and what is in force for it.
pub(crate) struct NodeConf {
    pub(crate) id: Bytes32,
    pub(crate) name: String,
    pub(crate) current: Option<wp::NodeConfig>,
    pub(crate) effective: Value,
}

pub(crate) async fn node_conf(cli: &Cli, node: Option<&str>) -> Result<NodeConf> {
    let id = match node {
        Some(n) => node_id(cli, n).await?,
        None => {
            let st = call(cli, Request::Status).await?;
            crypto::parse_hex32(st["node_id"].as_str().unwrap_or(""))
                .ok_or_else(|| anyhow!("the agent didn't report its node id"))?
        }
    };
    let r = call(cli, Request::NodeConfig { node: Some(id) }).await?;
    Ok(NodeConf {
        id,
        name: r["name"].as_str().unwrap_or("").to_string(),
        current: from_json(&r["config"])?,
        effective: r["effective"].clone(),
    })
}

/// `local config apply`: the file is the node's whole configuration (an
/// empty one clears it), submitted as the next version.
pub(crate) async fn apply_node(cli: &Cli, n: &NodeConf, f: &ConfigFile) -> Result<()> {
    let Some(w) = config::node_apply(f, &n.id, &n.name, n.current.as_ref())? else {
        report(
            cli,
            format!(
                "{} has no configuration of its own; nothing to apply",
                n.name
            ),
            json!({"node": n.name, "node_id": hex::encode(n.id), "changed": false}),
        );
        return Ok(());
    };
    let version = w.version;
    let a = load_account(cli).await?;
    let op = AccountOp::SetNodeConfig(Box::new(wp::SetNodeConfig {
        config: Some(Box::new(w)),
    }));
    let r = submit(cli, a.sign(op)?).await?;
    let v = json!({
        "applied": "node",
        "node": n.name,
        "node_id": hex::encode(n.id),
        "version": version,
        "cleared": f.is_empty(),
        "entry": entry(&r),
    });
    if f.is_empty() {
        report(
            cli,
            format!("configuration of {} cleared (entry {})", n.name, r["index"]),
            v,
        );
    } else {
        report(
            cli,
            format!(
                "configuration of {} version {version} applied (entry {})",
                n.name, r["index"]
            ),
            v,
        );
    }
    Ok(())
}

pub(crate) async fn local_config(cli: &Cli, node: Option<&str>, cmd: &ConfigCmd) -> Result<()> {
    let n = node_conf(cli, node).await?;
    let own = node_from_wire(n.current.as_ref());
    match cmd {
        ConfigCmd::Show { effective: false } => {
            show_doc(cli, &render_node(&n.name, n.current.as_ref())?, &own)?;
        }
        ConfigCmd::Show { effective: true } => {
            show_doc(
                cli,
                &render_effective(&n.name, &n.effective)?,
                &effective_from_json(&n.effective)?,
            )?;
        }
        ConfigCmd::Check { file } => {
            let f = ConfigFile::load(file)?;
            f.to_node(&n.id, f.base_version()? + 1)?;
            report(
                cli,
                format!(
                    "{} is valid for a node's configuration (the controllers check the seeds and DNS names)",
                    file.display()
                ),
                json!({"valid": true, "file": file}),
            );
        }
        ConfigCmd::Apply { file } => apply_node(cli, &n, &ConfigFile::load(file)?).await?,
        ConfigCmd::Edit => {
            let text = render_node(&n.name, n.current.as_ref())?;
            let Some((f, path)) = edit_text(&text, &format!("{}.toml", n.name))? else {
                report(cli, "no changes", json!({"changed": false}));
                return Ok(());
            };
            apply_edited(&path, apply_node(cli, &n, &f)).await?;
        }
        ConfigCmd::Get { key } => {
            let doc = toml::Value::try_from(&own)?;
            match config::get(&doc, key) {
                Ok(v) => print_value(cli, v)?,
                Err(_) => {
                    let eff = toml::Value::try_from(effective_from_json(&n.effective)?)?;
                    let v = config::get(&eff, key)?;
                    eprintln!(
                        "({key} is not set for {}; this is the network's value)",
                        n.name
                    );
                    print_value(cli, v)?;
                }
            }
        }
        ConfigCmd::Set { key, value } => {
            let f = config::edit_doc(&own, |d| config::set(d, key, config::parse_value(value)))?;
            apply_node(cli, &n, &f).await?;
        }
        ConfigCmd::Unset { key } => {
            let f = config::edit_doc(&own, |d| config::unset(d, key))?;
            apply_node(cli, &n, &f).await?;
        }
    }
    Ok(())
}
