//! Account keys and talking to the local webjetd.

use crate::cli::*;
use anyhow::{Result, anyhow, bail};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use webjet_core::crypto::{self, Bytes32};
use webjet_proto::{self as wp};
use webjet_tools::*;
use webjetd::control::{Request, client};

pub(crate) fn key_dir(cli: &Cli) -> PathBuf {
    cli.keys.clone().unwrap_or_else(default_key_dir)
}

/// Unlock the account key to sign with. The account it signs for is the one
/// the network holds this key under: after `network account rekey` (or a
/// root-signed key change) the new key's `.pub` still carries the random
/// account ID `keygen` gave it, so the network's ID is used, and written
/// back to the `.pub` once.
pub(crate) async fn load_account(cli: &Cli) -> Result<Account> {
    let dir = key_dir(cli);
    let name = pick_account(&dir, cli.account.as_deref())?;
    let pass = passphrase(
        "WEBJET_ACCOUNT_PASSPHRASE",
        &format!("passphrase for account {name}"),
    )?;
    let mut a = Account::unlock(&dir, &name, &pass)?;
    // Without an agent the command fails at submit anyway, with its own error.
    let Ok(accts) = call(cli, Request::Accounts).await else {
        return Ok(a);
    };
    if let Some(x) = a.adopt_network_id(&accts)
        && x.saved
    {
        eprintln!(
            "note: this key belongs to account {}; {} updated with its account ID",
            x.name,
            x.path.display()
        );
    }
    Ok(a)
}

// ---------------------------------------------------------------- talking to webjetd

/// A controller's certificate request, from the local agent (`None`: this
/// node's own) or fetched from another node over the overlay.
pub(crate) async fn cert_request(cli: &Cli, node: Option<Bytes32>) -> Result<Vec<u8>> {
    let r = call(cli, Request::CertRequest { node }).await?;
    webjetd::state::unb64(r["request"].as_str().unwrap_or(""))
}

pub(crate) async fn call(cli: &Cli, req: Request) -> Result<Value> {
    // Agents before 0.7 printed ids as `{"b0": …}` word structs.
    Ok(legacy_ids(client::call(&cli.socket, &req).await?))
}

pub(crate) async fn submit(cli: &Cli, signed: Vec<u8>) -> Result<Value> {
    call(cli, Request::SubmitOp { signed }).await
}

pub(crate) async fn nodes(cli: &Cli) -> Result<Vec<Value>> {
    Ok(call(cli, Request::Nodes)
        .await?
        .as_array()
        .cloned()
        .unwrap_or_default())
}

/// A node by name, `name.<suffix>`, hex id (or a unique prefix of it) or key.
pub(crate) async fn node_id(cli: &Cli, name: &str) -> Result<Bytes32> {
    let suffix = call(cli, Request::Status)
        .await
        .ok()
        .and_then(|s| s["dns_suffix"].as_str().map(String::from));
    webjet_tools::find_id(&nodes(cli).await?, name, suffix.as_deref(), "node", |_| {
        false
    })
}

/// Node names by hex id, to label ids in JSON answers.
pub(crate) async fn node_names(cli: &Cli) -> Result<HashMap<String, String>> {
    Ok(nodes(cli)
        .await?
        .iter()
        .filter_map(|n| {
            Some((
                n["id"].as_str()?.to_string(),
                n["name"].as_str()?.to_string(),
            ))
        })
        .collect())
}

/// A valid account by name, hex id (or a unique prefix of it) or key.
pub(crate) async fn account_id(cli: &Cli, name: &str) -> Result<Bytes32> {
    let accts = call(cli, Request::Accounts).await?;
    webjet_tools::find_id(
        accts.as_array().map(Vec::as_slice).unwrap_or_default(),
        name,
        None,
        "valid account",
        |a| a["valid"].as_bool() != Some(true),
    )
}

/// Pick a free address from the overlay pool.
pub(crate) fn pick_ip(info: &Value) -> Result<String> {
    let used: Vec<String> = info["used_ips"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let resolver: Vec<String> = info["resolver"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    for p in info["overlay_pool"].as_array().cloned().unwrap_or_default() {
        let net: ipnet::IpNet = p.as_str().unwrap_or("").parse()?;
        for (i, h) in net.hosts().enumerate() {
            if i > 65536 {
                break;
            }
            let s = h.to_string();
            if !used.contains(&s) && !resolver.contains(&s) {
                return Ok(s);
            }
        }
    }
    bail!("the overlay pool is full")
}

pub(crate) async fn ticket(cli: &Cli, token: &[u8], controllers: &[String]) -> Result<String> {
    let info = call(cli, Request::EnrollInfo).await?;
    let mut ctls: Vec<wp::SeedAddr> = controllers
        .iter()
        .map(|c| parse_seed_addr(c))
        .collect::<Result<_>>()?;
    if ctls.is_empty() {
        for c in info["controllers"].as_array().cloned().unwrap_or_default() {
            let t = wp::Transport::parse(c["transport"].as_str().unwrap_or("tls"))
                .unwrap_or(wp::Transport::TcpTls);
            ctls.push(wp::SeedAddr {
                host: c["host"].as_str().map(String::from),
                port: c["port"].as_u64().unwrap_or(0) as u16,
                transport: t,
            });
        }
    }
    if ctls.is_empty() {
        bail!("no controller enrollment address known; pass --controller tls:host:port");
    }
    let t = wp::EnrollmentTicket {
        token: Some(token.to_vec()),
        root_key: Some(crypto::k32(
            &crypto::parse_key_b64(info["root_key"].as_str().unwrap_or(""))
                .ok_or_else(|| anyhow!("no root key"))?,
        )),
        controllers: Some(ctls),
        camouflage_domain: info["camouflage_domain"].as_str().map(String::from),
        camouflage_pin: info["camouflage_pin"]
            .as_str()
            .and_then(crypto::parse_hex32)
            .map(|p| crypto::k32(&p)),
    };
    Ok(webjetd::agent::encode_ticket(&t))
}
