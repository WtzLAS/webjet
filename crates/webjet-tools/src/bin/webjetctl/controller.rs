//! `webjetctl network camouflage …` and `network controller …`.

use crate::{agent::*, cli::*, output::*};
use anyhow::{Result, anyhow, bail};
use serde_json::json;
use std::path::Path;
use webjet_core::crypto::{self};
use webjet_proto::{self as wp, AccountOp};
use webjet_tools::*;
use webjetd::control::Request;

/// `webjetctl network camouflage …`: the AnyTLS camouflage secret and certificate.
pub(crate) async fn network_camouflage(cli: &Cli, cmd: &CamouflageCmd) -> Result<()> {
    match cmd {
        CamouflageCmd::SetSecret { key, site } => {
            let a = load_account(cli).await?;
            let k = read(key)?;
            if !String::from_utf8_lossy(&k).contains("PRIVATE KEY") {
                bail!("{} is not a PEM private key", key.display());
            }
            let op = wp::SetCamouflageSecret {
                private_key: Some(k),
                site: Some(site_bundle(site)?),
            };
            let r = submit(cli, a.sign(AccountOp::SetCamouflageSecret(Box::new(op)))?).await?;
            report(
                cli,
                format!("camouflage secret stored (entry {})", r["index"]),
                json!({"camouflage_secret": true, "entry": entry(&r)}),
            );
        }
        #[cfg(feature = "anytls")]
        CamouflageCmd::Selfsign {
            domain,
            cert_out,
            key_out,
        } => {
            let (cert, key) = webjet_net::anytls::self_signed(domain)?;
            let pem = format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                b64(&cert)
                    .as_bytes()
                    .chunks(64)
                    .map(|c| String::from_utf8_lossy(c).into_owned())
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            write_public(cert_out, pem.as_bytes())?;
            webjet_tools::write_secret(key_out, &key)?;
            report(
                cli,
                format!(
                    "self-signed certificate for {domain}: {} / {}",
                    cert_out.display(),
                    key_out.display()
                ),
                json!({"domain": domain, "cert_file": cert_out, "key_file": key_out}),
            );
        }
        #[cfg(not(feature = "anytls"))]
        CamouflageCmd::Selfsign { .. } => bail!("built without AnyTLS"),
    }
    Ok(())
}

/// `webjetctl network controller …`: certificates, snapshots and membership.
pub(crate) async fn network_controller(cli: &Cli, cmd: &ControllerCmd) -> Result<()> {
    match cmd {
        ControllerCmd::Certify { name, request } => {
            let id = node_id(cli, name).await?;
            let req = match request {
                Some(p) => read(p)?,
                None => cert_request(cli, Some(id)).await?,
            };
            let a = load_account(cli).await?;
            let accts = call(cli, Request::Accounts).await?;
            let record = accts
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .find(|x| x["id"].as_str() == Some(&hex::encode(a.id)))
                .and_then(|x| x["record"].as_str().map(String::from))
                .ok_or_else(|| anyhow!("account {} isn't known to the network", a.name))?;
            let record = webjetd::state::unb64(&record)?;
            let (cert, kid) = webjet_tools::certify(&req, Some(id), &a.kp, Some(record))?;
            let r = call(cli, Request::SubmitSigned { signed: cert }).await?;
            report(
                cli,
                format!(
                    "certified {name}'s signing key {} (added: {})",
                    hex::encode(kid),
                    r["added"]
                ),
                json!({"node": name, "node_id": hex::encode(id), "signing_key_id": hex::encode(kid), "added": r["added"]}),
            );
        }
        ControllerCmd::CertRequest { out, node } => {
            let target = match node {
                Some(nm) => Some(node_id(cli, nm).await?),
                None => None,
            };
            let raw = cert_request(cli, target).await?;
            write_public(out, &raw)?;
            report(
                cli,
                format!(
                    "certificate request → {} (sign it offline: webjetctl root controller sign)",
                    out.display()
                ),
                json!({"node_id": target.map(hex::encode), "request_file": out}),
            );
        }
        ControllerCmd::Snapshot { out } => {
            let a = load_account(cli).await?;
            let request = ops::snapshot_request(&a);
            let r = call(cli, Request::Snapshot { request }).await?;
            // It holds the PSKs and the camouflage key: wiped after use.
            let snap = zeroize::Zeroizing::new(webjetd::state::unb64(
                r["snapshot"].as_str().unwrap_or(""),
            )?);
            let pass = new_passphrase("WEBJET_BACKUP_PASSPHRASE", "passphrase for the snapshot")?;
            webjet_tools::write_secret(out, &seal(&pass, &snap)?)?;
            report(
                cli,
                format!(
                    "controller state at index {} ({} nodes) → {} (encrypted; it holds the PSKs and the camouflage key)",
                    r["last_index"],
                    r["nodes"],
                    out.display()
                ),
                json!({"file": out, "last_index": r["last_index"], "nodes": r["nodes"], "voters": r["voters"]}),
            );
        }
        ControllerCmd::List => {
            let v = call(cli, Request::Controller).await?;
            let names = node_names(cli).await.unwrap_or_default();
            print(cli, &with_node_names(v, &names));
        }
        ControllerCmd::AddLearner { name }
        | ControllerCmd::Promote { name }
        | ControllerCmd::Demote { name }
        | ControllerCmd::Remove { name } => {
            let change = match cmd {
                ControllerCmd::AddLearner { .. } => wp::MembershipChange::AddLearner,
                ControllerCmd::Promote { .. } => wp::MembershipChange::Promote,
                ControllerCmd::Demote { .. } => wp::MembershipChange::Demote,
                _ => wp::MembershipChange::Remove,
            };
            let a = load_account(cli).await?;
            let id = node_id(cli, name).await?;
            let r = submit(
                cli,
                a.sign(AccountOp::ChangeMembership(Box::new(
                    wp::ChangeMembership {
                        change,
                        node_id: Some(crypto::k32(&id)),
                    },
                )))?,
            )
            .await?;
            report(
                cli,
                format!("{change:?} {name} (entry {})", r["index"]),
                json!({"change": format!("{change:?}"), "node": name, "node_id": hex::encode(id), "entry": entry(&r)}),
            );
        }
    }
    Ok(())
}

pub(crate) fn site_bundle(p: &Path) -> Result<Vec<u8>> {
    if p.is_dir() {
        read(&p.join("index.html"))
    } else {
        read(p)
    }
}
