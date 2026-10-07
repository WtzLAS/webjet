//! `webjetctl network node …`: enrollment and node records.

use crate::{agent::*, cli::*, output::*, rollout::*};
use anyhow::Result;
use serde_json::json;
use webjet_core::crypto::{self, Bytes32};
use webjet_core::types::parse_roles;
use webjet_proto::{self as wp, AccountOp};
use webjet_tools::*;
use webjetd::control::Request;

/// `webjetctl network node …`: enrollment and node records.
pub(crate) async fn network_node(cli: &Cli, cmd: &NodeCmd) -> Result<()> {
    match cmd {
        NodeCmd::Upgrade {
            version,
            nodes,
            tag,
            all,
            batch,
            repo,
            timeout_minutes,
            dry_run,
            yes,
        } => {
            let sel = Selection {
                names: nodes,
                tags: tag,
                all: *all,
            };
            let opts = RolloutOpts {
                batch: *batch,
                repo,
                timeout: std::time::Duration::from_secs(timeout_minutes * 60),
                dry_run: *dry_run,
                yes: *yes,
            };
            return upgrade_nodes(cli, version, &sel, &opts).await;
        }
        NodeCmd::UpgradeStatus { nodes } => {
            let ids: Vec<Option<Bytes32>> = if nodes.is_empty() {
                vec![None]
            } else {
                let mut v = Vec::new();
                for n in nodes {
                    v.push(Some(node_id(cli, n).await?));
                }
                v
            };
            let mut out = Vec::new();
            for id in ids {
                out.push(match call(cli, Request::UpgradeStatus { node: id }).await {
                    Ok(v) => v,
                    Err(e) => json!({"node_id": id.map(hex::encode), "error": format!("{e:#}")}),
                });
            }
            let names = node_names(cli).await.unwrap_or_default();
            print(cli, &with_node_names(json!(out), &names));
            return Ok(());
        }
        NodeCmd::Enroll {
            owner,
            name,
            ip,
            roles,
            tags: tg,
            route,
            expires_hours,
            controller,
        } => {
            let roles = parse_roles(roles)?;
            let a = load_account(cli).await?;
            let owner_id = account_id(cli, owner).await?;
            let ips = if ip.is_empty() {
                vec![pick_ip(&call(cli, Request::EnrollInfo).await?)?]
            } else {
                ip.clone()
            };
            let token = crypto::random32();
            // Built before submitting: a bad --controller or a missing root
            // key must not leave a pending enrollment whose token is lost.
            let t = ticket(cli, &token, controller).await?;
            let th = crypto::token_hash(&token);
            let op = wp::CreateEnrollment {
                owner: Some(crypto::k32(&owner_id)),
                name: Some(name.clone()),
                overlay_ips: Some(overlay_ips(&ips)?),
                roles: Some(roles.wire()),
                control: roles.control,
                tags: Some(tags(tg)?),
                routes: Some(grants(route)?),
                token_hash: Some(crypto::k32(&th)),
                expires_at: expires_at(*expires_hours)?,
                identity_key: None,
                node_id: None,
            };
            let r = submit(cli, a.sign(AccountOp::CreateEnrollment(Box::new(op)))?).await?;
            if cli.json {
                print(
                    cli,
                    &json!({"node": name, "ips": ips, "entry": entry(&r), "enroll": t}),
                );
            } else {
                eprintln!(
                    "enrollment for {name} ({}) created (entry {}); on the node run:",
                    ips.join(", "),
                    r["index"]
                );
                println!("{t}");
            }
        }
        NodeCmd::List => {
            let v = nodes(cli).await?;
            if cli.json {
                print(cli, &json!(v));
            } else {
                let mut rows = vec![vec![
                    "NAME".into(),
                    "IPS".into(),
                    "ROLES".into(),
                    "TAGS".into(),
                    "OWNER".into(),
                    "VALID".into(),
                ]];
                for n in v {
                    let mut roles = Vec::new();
                    for r in ["data", "relay", "control"] {
                        if n[r].as_bool() == Some(true) {
                            roles.push(r);
                        }
                    }
                    if n["control"].as_bool() != Some(true)
                        && n["control_role"].as_bool() == Some(true)
                    {
                        // Granted, but the signing key isn't certified yet.
                        roles.push("control(uncertified)");
                    }
                    let j = |k: &str| {
                        n[k].as_array()
                            .cloned()
                            .unwrap_or_default()
                            .iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    rows.push(vec![
                        n["name"].as_str().unwrap_or("").into(),
                        j("ips"),
                        roles.join(","),
                        j("tags"),
                        n["owner"].as_str().unwrap_or("").into(),
                        n["valid"].to_string(),
                    ]);
                }
                print_table(&rows);
            }
        }
        NodeCmd::Show { name } => {
            let id = node_id(cli, name).await?;
            let n = nodes(cli)
                .await?
                .into_iter()
                .find(|n| n["id"].as_str() == Some(&hex::encode(id)))
                .unwrap_or_default();
            print(cli, &n);
        }
        NodeCmd::Update {
            name,
            roles,
            tags: tg,
            ip,
            route,
            no_routes,
            owner,
        } => {
            let roles = roles.as_deref().map(parse_roles).transpose()?;
            let a = load_account(cli).await?;
            let id = node_id(cli, name).await?;
            let owner = match owner {
                Some(o) => Some(crypto::k32(&account_id(cli, o).await?)),
                None => None,
            };
            let op = wp::UpdateNode {
                node_id: Some(crypto::k32(&id)),
                owner,
                set_overlay_ips: ip.is_some(),
                overlay_ips: ip.as_ref().map(|v| overlay_ips(v)).transpose()?,
                set_roles: roles.is_some(),
                roles: roles.map(|r| r.wire()),
                control: roles.map(|r| r.control),
                set_tags: tg.is_some(),
                tags: tg.as_ref().map(|t| tags(t)).transpose()?,
                set_routes: route.is_some() || *no_routes,
                routes: if *no_routes {
                    Some(vec![])
                } else {
                    route.as_ref().map(|r| grants(r)).transpose()?
                },
            };
            let r = submit(cli, a.sign(AccountOp::UpdateNode(Box::new(op)))?).await?;
            report(
                cli,
                format!("{name} updated (entry {})", r["index"]),
                json!({"node": name, "node_id": hex::encode(id), "updated": true, "entry": entry(&r)}),
            );
        }
        NodeCmd::Rename { name, new_name } => {
            let a = load_account(cli).await?;
            let id = node_id(cli, name).await?;
            let r = submit(cli, ops::rename_node(&a, &id, new_name)?).await?;
            report(
                cli,
                format!("{name} is now {new_name} (entry {})", r["index"]),
                json!({"node": new_name, "old_name": name, "node_id": hex::encode(id), "entry": entry(&r)}),
            );
        }
        NodeCmd::Revoke { name, reason } => {
            let a = load_account(cli).await?;
            let id = node_id(cli, name).await?;
            let r = submit(cli, ops::revoke_node(&a, &id, reason.as_deref())?).await?;
            report(
                cli,
                format!("{name} revoked (entry {})", r["index"]),
                json!({"node": name, "node_id": hex::encode(id), "revoked": true, "entry": entry(&r)}),
            );
        }
        NodeCmd::Rekey {
            name,
            revoke_old_now,
            expires_hours,
            controller,
        } => {
            let a = load_account(cli).await?;
            let id = node_id(cli, name).await?;
            let token = crypto::random32();
            // Before submitting: with --revoke-old-now a failure after the
            // submit would leave the node cut off without its new token.
            let t = ticket(cli, &token, controller).await?;
            let op = wp::RekeyNode {
                node_id: Some(crypto::k32(&id)),
                token_hash: Some(crypto::k32(&crypto::token_hash(&token))),
                expires_at: expires_at(*expires_hours)?,
                revoke_old_now: *revoke_old_now,
            };
            let r = submit(cli, a.sign(AccountOp::RekeyNode(Box::new(op)))?).await?;
            if cli.json {
                print(
                    cli,
                    &json!({"node": name, "node_id": hex::encode(id), "entry": entry(&r), "enroll": t}),
                );
            } else {
                eprintln!(
                    "re-key for {name} issued (entry {}); on the node run `webjetup enroll` (or `webjetctl enroll`) with:",
                    r["index"]
                );
                println!("{t}");
            }
        }
    }
    Ok(())
}
