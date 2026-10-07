//! `webjetctl network account …`: account keys and records.

use crate::{agent::*, cli::*, output::*};
use anyhow::{Result, anyhow, bail};
use serde_json::json;
use webjet_core::crypto::{self, KeyPair};
use webjet_core::types::now_ms;
use webjet_proto::{self as wp, AccountOp};
use webjet_tools::*;
use webjetd::control::Request;

/// `webjetctl network account …`: account keys and records.
pub(crate) async fn network_account(cli: &Cli, cmd: &AccountCmd) -> Result<()> {
    match cmd {
        AccountCmd::Keygen { name, pub_out } => {
            if !webjet_core::types::valid_name(name) {
                bail!("account names are [a-z0-9-]{{1,32}}");
            }
            let dir = key_dir(cli);
            let path = dir.join(format!("{name}.key"));
            if path.exists() {
                bail!("{} exists", path.display());
            }
            let pass = new_passphrase(
                "WEBJET_ACCOUNT_PASSPHRASE",
                &format!("new passphrase for account {name}"),
            )?;
            let kp = KeyPair::generate();
            let p = AccountPub {
                name: name.clone(),
                account_id: hex::encode(crypto::random32()),
                key: crypto::key_b64(&kp.public()),
            };
            write_private(&path, &seal(&pass, &kp.seed()[..])?)?;
            let pj = serde_json::to_vec_pretty(&p)?;
            write_public(&dir.join(format!("{name}.pub")), &pj)?;
            write_public(pub_out, &pj)?;
            report(
                cli,
                format!(
                    "account key for {name} created in {}; public part in {}",
                    dir.display(),
                    pub_out.display()
                ),
                json!({"account": name, "account_id": p.account_id, "key": p.key, "key_file": path, "pub_file": pub_out}),
            );
        }
        AccountCmd::Create { name, key } => {
            let a = load_account(cli).await?;
            let mut p = AccountPub::load(key)?;
            p.name = name.clone();
            let rec = account_record(&p, false, Some(a.id))?;
            let signed = a.kp.sign_obj(wp::msg_type::ACCOUNT_RECORD, &rec);
            let r = submit(
                cli,
                a.sign(AccountOp::PutAccount(Box::new(wp::PutAccount {
                    record: Some(signed),
                })))?,
            )
            .await?;
            report(
                cli,
                format!("account {name} created (entry {})", r["index"]),
                json!({"account": name, "account_id": p.account_id, "created": true, "entry": entry(&r)}),
            );
        }
        AccountCmd::Rekey { name, key } => {
            let a = load_account(cli).await?;
            let wanted = hex::encode(account_id(cli, name).await?);
            let accts = call(cli, Request::Accounts).await?;
            let cur = accts
                .as_array()
                .into_iter()
                .flatten()
                .find(|x| x["id"].as_str() == Some(&wanted))
                .ok_or_else(|| anyhow!("no valid account named {name}"))?;
            // The account's own name: `name` may be its id, an id prefix or
            // its key, and the record would otherwise be renamed to that.
            let account_name = cur["name"]
                .as_str()
                .ok_or_else(|| anyhow!("account {name} has no name"))?
                .to_string();
            if cur["admin"].as_bool() == Some(true) {
                bail!(
                    "{account_name} is an admin: only the root gives it a new key (`webjetctl root admin sign --name {account_name} --key <new>.pub --replaces <old>.pub`)"
                );
            }
            let id = cur["id"]
                .as_str()
                .and_then(crypto::parse_hex32)
                .ok_or_else(|| anyhow!("bad id"))?;
            let mut p = AccountPub::load(key)?;
            if p.key()? == a.kp.public() {
                bail!("that is your own key");
            }
            p.name = account_name.clone();
            p.account_id = hex::encode(id);
            let rec = account_record(&p, false, Some(a.id))?;
            let signed = a.kp.sign_obj(wp::msg_type::ACCOUNT_RECORD, &rec);
            let r = submit(
                cli,
                a.sign(AccountOp::PutAccount(Box::new(wp::PutAccount {
                    record: Some(signed),
                })))?,
            )
            .await?;
            // The public file now names the account it belongs to, so
            // later uses of it (`root admin sign`) find the account.
            write_public(key, &serde_json::to_vec_pretty(&p)?)?;
            report(
                cli,
                format!(
                    "account {account_name} has a new key (entry {}); the old key no longer signs. {} now carries the account's ID",
                    r["index"],
                    key.display()
                ),
                json!({"account": account_name, "account_id": hex::encode(id), "key": p.key, "rekeyed": true, "entry": entry(&r)}),
            );
        }
        AccountCmd::Revoke {
            name,
            reason,
            revoke_issued,
        } => {
            let a = load_account(cli).await?;
            let id = account_id(cli, name).await?;
            let t = wp::AccountTombstone {
                account_id: Some(crypto::k32(&id)),
                version: now_ms(),
                revoke_issued: *revoke_issued,
                reason: reason.clone(),
            };
            let signed = a.kp.sign_obj(wp::msg_type::ACCOUNT_TOMBSTONE, &t);
            let r = submit(
                cli,
                a.sign(AccountOp::TombstoneAccount(Box::new(
                    wp::TombstoneAccount {
                        tombstone: Some(signed),
                    },
                )))?,
            )
            .await?;
            report(
                cli,
                format!("account {name} revoked (entry {})", r["index"]),
                json!({"account": name, "account_id": hex::encode(id), "revoked": true, "entry": entry(&r)}),
            );
        }
        AccountCmd::List => {
            let v = call(cli, Request::Accounts).await?;
            if cli.json {
                print(cli, &v);
            } else {
                // Which accounts this machine can sign as.
                let dir = key_dir(cli);
                let local = account_names(&dir).unwrap_or_default();
                let default = pick_account(&dir, cli.account.as_deref()).ok();
                let mut rows = vec![vec![
                    "NAME".into(),
                    "ADMIN".into(),
                    "VALID".into(),
                    "HERE".into(),
                    "KEY".into(),
                ]];
                for a in v.as_array().cloned().unwrap_or_default() {
                    let name = a["name"].as_str().unwrap_or("").to_string();
                    let here = if default.as_ref() == Some(&name) {
                        "*"
                    } else if local.contains(&name) {
                        "key"
                    } else {
                        ""
                    };
                    rows.push(vec![
                        name,
                        a["admin"].to_string(),
                        a["valid"].to_string(),
                        here.into(),
                        a["key"].as_str().unwrap_or("").into(),
                    ]);
                }
                print_table(&rows);
            }
        }
        AccountCmd::Use { name, clear } => {
            let dir = key_dir(cli);
            let file = dir.join(DEFAULT_ACCOUNT_FILE);
            if *clear {
                set_default_account(&dir, None)?;
                report(
                    cli,
                    format!("no default account ({} removed)", file.display()),
                    json!({"default": null, "file": file}),
                );
            } else if let Some(n) = name {
                set_default_account(&dir, Some(n))?;
                report(
                    cli,
                    format!("default account: {n} ({})", file.display()),
                    json!({"default": n, "file": file}),
                );
            } else {
                let default = default_account(&dir)?;
                let only = match &default {
                    Some(_) => None,
                    None => Some(pick_account(&dir, None)),
                };
                if cli.json {
                    print(
                        cli,
                        &json!({
                            "default": default,
                            "file": file,
                            "override": cli.account,
                            "only_key": only.as_ref().and_then(|r| r.as_ref().ok()),
                            "error": only.as_ref().and_then(|r| r.as_ref().err().map(|e| e.to_string())),
                        }),
                    );
                    return Ok(());
                }
                if let Some(a) = &cli.account {
                    println!("--account / WEBJET_ACCOUNT overrides it here: {a}");
                }
                match (default, only) {
                    (Some(n), _) => println!("default account: {n} ({})", file.display()),
                    (None, Some(Ok(n))) => println!("no default set; using the only key: {n}"),
                    (None, Some(Err(e))) => println!("no default account: {e}"),
                    (None, None) => {}
                }
            }
        }
    }
    Ok(())
}
