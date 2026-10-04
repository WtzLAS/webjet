//! `webjetctl root`: the offline part that holds the root and emergency
//! revocation keys (§5). It never talks to the network; files move on
//! removable media.

use crate::*;
use anyhow::{Result, anyhow, bail};
use clap::Subcommand;
use std::path::{Path, PathBuf};
use webjet_core::crypto::{self, KeyPair};
use webjet_core::types::{net_to_cidr, now_ms, parse_net};
use webjet_proto::{self as wp, Decodable, Encodable, msg_type as mt};

/// The directory `root` commands use unless `--dir` says otherwise.
pub const DEFAULT_DIR: &str = "./webjet-root";

#[derive(Subcommand, Clone)]
pub enum RootCmd {
    /// Create the root and emergency revocation keys.
    Init,
    /// Write an encrypted backup of both keys.
    Backup {
        #[arg(long)]
        out: PathBuf,
    },
    /// Restore the keys from a backup.
    Restore {
        #[arg(long)]
        from: PathBuf,
    },
    /// Print the public keys.
    Show,
    /// Admin accounts: sign (create) and revoke
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
    /// Build the genesis file.
    Genesis {
        #[arg(long)]
        overlay_pool: Vec<String>,
        #[arg(long)]
        admin: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Controller certificates: sign requests, retire keys
    Controller {
        #[command(subcommand)]
        cmd: ControllerCmd,
    },
    /// Revoke a normal account without an admin
    Account {
        #[command(subcommand)]
        cmd: AccountCmd,
    },
    /// Revoke a node with the emergency key (no controller needed)
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// Sign a StateVersion for a release (runbook 11).
    StateVersion {
        #[command(subcommand)]
        cmd: StateVersionCmd,
    },
}

#[derive(Subcommand, Clone)]
pub enum AdminCmd {
    /// Sign an admin account record (root-issued).
    Sign {
        #[arg(long)]
        name: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Revoke an admin account (root- or emergency-signed).
    Revoke {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        revoke_issued: bool,
        #[arg(long, default_value = "root")]
        with: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand, Clone)]
pub enum ControllerCmd {
    /// Sign a controller's certificate request.
    Sign {
        request: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Retire a controller signing key (runbook 10).
    Retire {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        last_valid_version: u64,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, default_value = "root")]
        with: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand, Clone)]
pub enum AccountCmd {
    /// Revoke an account (runbook 8, admin unavailable or compromised).
    Revoke {
        /// The account's public file.
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        revoke_issued: bool,
        #[arg(long, default_value = "root")]
        with: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand, Clone)]
pub enum NodeCmd {
    /// An offline node tombstone (runbook 8, no controller majority).
    Revoke {
        /// Node id (hex).
        #[arg(long)]
        node: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, default_value = "emergency")]
        with: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand, Clone)]
pub enum StateVersionCmd {
    Sign {
        #[arg(long)]
        version: u32,
        #[arg(long, default_value = "1")]
        min_wire_protocol: u16,
        #[arg(long)]
        min_node_software: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
}

struct Keys {
    root: KeyPair,
    emergency: KeyPair,
}

fn root_path(dir: &Path) -> PathBuf {
    dir.join("root.key.enc")
}
fn emergency_path(dir: &Path) -> PathBuf {
    dir.join("emergency.key.enc")
}

fn load_keys(dir: &Path) -> Result<Keys> {
    let pass = passphrase("WEBJET_ROOT_PASSPHRASE", "root key passphrase")?;
    let root = keypair_from(&unseal(&pass, &read(&root_path(dir))?)?)?;
    let emergency = keypair_from(&unseal(&pass, &read(&emergency_path(dir))?)?)?;
    Ok(Keys { root, emergency })
}

fn pick<'a>(k: &'a Keys, with: &str) -> Result<&'a KeyPair> {
    match with {
        "root" => Ok(&k.root),
        "emergency" => Ok(&k.emergency),
        w => bail!("--with must be root or emergency, got {w}"),
    }
}

/// Run one `webjetctl root` command with the keys in `dir`.
pub fn run(dir: &Path, cmd: RootCmd) -> Result<()> {
    match cmd {
        RootCmd::Init => {
            if root_path(dir).exists() {
                bail!("{} already holds keys", dir.display());
            }
            let pass =
                new_passphrase("WEBJET_ROOT_PASSPHRASE", "new passphrase for the root keys")?;
            let root = KeyPair::generate();
            let emergency = KeyPair::generate();
            write_private(&root_path(dir), &seal(&pass, &root.seed()[..])?)?;
            write_private(&emergency_path(dir), &seal(&pass, &emergency.seed()[..])?)?;
            let cert = root.sign_obj(
                mt::EMERGENCY_KEY_CERT,
                &wp::EmergencyKeyCert {
                    key: Some(crypto::k32(&emergency.public())),
                },
            );
            write_public(&dir.join("emergency.cert"), &cert)?;
            println!("root key:      {}", crypto::key_b64(&root.public()));
            println!("emergency key: {}", crypto::key_b64(&emergency.public()));
            println!("Back both up now: webjetctl root backup --out <media>");
        }
        RootCmd::Backup { out } => {
            let k = load_keys(dir)?;
            let pass = new_passphrase("WEBJET_BACKUP_PASSPHRASE", "passphrase for the backup")?;
            let mut plain = k.root.seed().to_vec();
            plain.extend_from_slice(&k.emergency.seed()[..]);
            write_private(&out, &seal(&pass, &plain)?)?;
            println!("backup written to {}", out.display());
        }
        RootCmd::Restore { from } => {
            let pass = passphrase("WEBJET_BACKUP_PASSPHRASE", "backup passphrase")?;
            let plain = unseal(&pass, &read(&from)?)?;
            if plain.len() != 64 {
                bail!("damaged backup");
            }
            let newpass =
                new_passphrase("WEBJET_ROOT_PASSPHRASE", "new passphrase for the root keys")?;
            write_private(&root_path(dir), &seal(&newpass, &plain[..32])?)?;
            write_private(&emergency_path(dir), &seal(&newpass, &plain[32..])?)?;
            let root = keypair_from(&plain[..32])?;
            let emergency = keypair_from(&plain[32..])?;
            let cert = root.sign_obj(
                mt::EMERGENCY_KEY_CERT,
                &wp::EmergencyKeyCert {
                    key: Some(crypto::k32(&emergency.public())),
                },
            );
            write_public(&dir.join("emergency.cert"), &cert)?;
            println!("restored root key {}", crypto::key_b64(&root.public()));
        }
        RootCmd::Show => {
            let k = load_keys(dir)?;
            println!("root key:      {}", crypto::key_b64(&k.root.public()));
            println!("emergency key: {}", crypto::key_b64(&k.emergency.public()));
        }
        RootCmd::Admin {
            cmd: AdminCmd::Sign { name, key, out },
        } => {
            let k = load_keys(dir)?;
            let mut p = AccountPub::load(&key)?;
            p.name = name;
            let rec = account_record(&p, true, None)?;
            write_public(&out, &k.root.sign_obj(mt::ACCOUNT_RECORD, &rec))?;
            println!("signed admin account {} → {}", p.name, out.display());
        }
        RootCmd::Admin {
            cmd:
                AdminCmd::Revoke {
                    key,
                    reason,
                    revoke_issued,
                    with,
                    out,
                },
        }
        | RootCmd::Account {
            cmd:
                AccountCmd::Revoke {
                    key,
                    reason,
                    revoke_issued,
                    with,
                    out,
                },
        } => {
            let k = load_keys(dir)?;
            let p = AccountPub::load(&key)?;
            let t = wp::AccountTombstone {
                account_id: Some(crypto::k32(&p.id()?)),
                version: now_ms(),
                revoke_issued,
                reason,
            };
            write_public(&out, &pick(&k, &with)?.sign_obj(mt::ACCOUNT_TOMBSTONE, &t))?;
            println!(
                "account tombstone for {} → {} (submit with `webjetctl submit`, or inject on any node)",
                p.name,
                out.display()
            );
        }
        RootCmd::Genesis {
            overlay_pool,
            admin,
            out,
        } => {
            let k = load_keys(dir)?;
            if overlay_pool.is_empty() {
                bail!("--overlay-pool is required");
            }
            let pool: Vec<wp::Cidr> = overlay_pool
                .iter()
                .map(|p| Ok(net_to_cidr(&parse_net(p)?)))
                .collect::<Result<_>>()?;
            let admin_raw = read(&admin)?;
            let v = crypto::open_expect(&admin_raw, mt::ACCOUNT_RECORD, &[k.root.public()])?;
            let rec: wp::AccountRecord = v.decode()?;
            if !rec.admin {
                bail!("{} is not an admin account", admin.display());
            }
            let cert = k.root.sign_obj(
                mt::EMERGENCY_KEY_CERT,
                &wp::EmergencyKeyCert {
                    key: Some(crypto::k32(&k.emergency.public())),
                },
            );
            let g = wp::Genesis {
                root_key: Some(crypto::k32(&k.root.public())),
                emergency_cert: Some(cert),
                first_admin: Some(admin_raw),
                overlay_pool: Some(pool),
                created_at: now_ms(),
            };
            let bytes = g.encode_bytes();
            webjet_core::store::open_genesis(&bytes)?;
            write_public(&out, &bytes)?;
            println!(
                "genesis written to {} (root key {})",
                out.display(),
                crypto::key_b64(&k.root.public())
            );
        }
        RootCmd::Controller {
            cmd: ControllerCmd::Sign { request, out },
        } => {
            let k = load_keys(dir)?;
            let raw = read(&request)?;
            let v = crypto::open_envelope(&raw)?;
            let c = wp::SigningKeyCert::decode_bytes(&v.body)?;
            let (cert, kid) = crate::certify(&raw, None, &k.root, None)
                .with_context(|| request.display().to_string())?;
            println!(
                "controller node: {}",
                hex::encode(crypto::opt_k32(&c.controller))
            );
            println!(
                "signing key:     {}",
                crypto::key_b64(&crypto::opt_k32(&c.signing_key))
            );
            println!("key id:          {}", hex::encode(kid));
            write_public(&out, &cert)?;
            println!("certificate → {}", out.display());
        }
        RootCmd::Controller {
            cmd:
                ControllerCmd::Retire {
                    key_id,
                    last_valid_version,
                    reason,
                    with,
                    out,
                },
        } => {
            let k = load_keys(dir)?;
            let id = crypto::parse_hex32(&key_id)
                .ok_or_else(|| anyhow!("--key-id must be 64 hex characters"))?;
            let t = wp::SigningKeyTombstone {
                signing_key_id: Some(crypto::k32(&id)),
                last_valid_version,
                reason,
            };
            write_public(
                &out,
                &pick(&k, &with)?.sign_obj(mt::SIGNING_KEY_TOMBSTONE, &t),
            )?;
            println!("key tombstone → {}", out.display());
        }
        RootCmd::Node {
            cmd:
                NodeCmd::Revoke {
                    node,
                    reason,
                    with,
                    out,
                },
        } => {
            let k = load_keys(dir)?;
            let id = crypto::parse_hex32(&node).ok_or_else(|| {
                anyhow!("--node must be the node id (64 hex characters; see `webjetctl node list`)")
            })?;
            // A high version beats any record version the controllers may hold.
            let t = wp::Tombstone {
                node_id: Some(crypto::k32(&id)),
                version: now_ms(),
                reason,
            };
            write_public(&out, &pick(&k, &with)?.sign_obj(mt::TOMBSTONE, &t))?;
            println!(
                "node tombstone → {} (inject on any node: `webjetctl inject`)",
                out.display()
            );
        }
        RootCmd::StateVersion {
            cmd:
                StateVersionCmd::Sign {
                    version,
                    min_wire_protocol,
                    min_node_software,
                    out,
                },
        } => {
            let k = load_keys(dir)?;
            let sv = wp::StateVersion {
                version,
                state_machine: version,
                emit: Some(vec![]),
                accept: Some(vec![]),
                min_wire_protocol,
                min_node_software,
            };
            write_public(&out, &k.root.sign_obj(mt::STATE_VERSION, &sv))?;
            println!("state version {version} → {}", out.display());
        }
    }
    Ok(())
}
