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
        /// Replace keys that are in the directory already.
        #[arg(long)]
        force: bool,
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
    /// Sign a StateVersion for a release (ops guide 3.4).
    StateVersion {
        #[command(subcommand)]
        cmd: StateVersionCmd,
    },
}

/// An account named by its public file or by its account ID (hex): the
/// ID is what tombstones and key changes refer to.
fn account_ref(r: &Path) -> Result<(String, crypto::Bytes32)> {
    if let Some(id) = r.to_str().and_then(crypto::parse_hex32) {
        return Ok((hex::encode(id), id));
    }
    let p = AccountPub::load(r)?;
    Ok((p.name.clone(), p.id()?))
}

#[derive(Subcommand, Clone)]
pub enum AdminCmd {
    /// Sign an admin account record (root-issued).
    Sign {
        #[arg(long)]
        name: String,
        #[arg(long)]
        key: PathBuf,
        /// Give an existing account this new key instead (lost or
        /// compromised key): its old `.pub` file or its account ID (hex,
        /// `webjetctl --json network account list`). It keeps its name,
        /// devices and the accounts it created.
        #[arg(long)]
        replaces: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Revoke an admin account (root- or emergency-signed).
    Revoke {
        /// The account's public file, or its account ID (hex).
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
    /// Retire a controller signing key (ops guide 2.9).
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
    /// Revoke an account (ops guide 1.3, 4.2: no admin, or a compromised one).
    Revoke {
        /// The account's public file, or its account ID (hex).
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
    /// An offline node tombstone (ops guide 4.2, no controller majority).
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

/// The root's certificate for the emergency key (the genesis carries one).
fn emergency_cert(root: &KeyPair, emergency: &KeyPair) -> Vec<u8> {
    root.sign_obj(
        mt::EMERGENCY_KEY_CERT,
        &wp::EmergencyKeyCert {
            key: Some(crypto::k32(&emergency.public())),
        },
    )
}

/// `webjetctl root init`: new root and emergency keys.
fn init(dir: &Path) -> Result<()> {
    if root_path(dir).exists() {
        bail!("{} already holds keys", dir.display());
    }
    let pass = new_passphrase("WEBJET_ROOT_PASSPHRASE", "new passphrase for the root keys")?;
    let root = KeyPair::generate();
    let emergency = KeyPair::generate();
    write_private(&root_path(dir), &seal(&pass, &root.seed()[..])?)?;
    write_private(&emergency_path(dir), &seal(&pass, &emergency.seed()[..])?)?;
    write_public(
        &dir.join("emergency.cert"),
        &emergency_cert(&root, &emergency),
    )?;
    println!("root key:      {}", crypto::key_b64(&root.public()));
    println!("emergency key: {}", crypto::key_b64(&emergency.public()));
    println!("Back both up now: webjetctl root backup --out <media>");
    Ok(())
}

/// `webjetctl root restore`: both keys from a backup, under a new passphrase.
/// Keys already in `dir` are replaced only with `force`: restoring the
/// wrong backup would otherwise destroy them.
fn restore(dir: &Path, from: &Path, force: bool) -> Result<()> {
    let pass = passphrase("WEBJET_BACKUP_PASSPHRASE", "backup passphrase")?;
    let plain = unseal(&pass, &read(from)?)?;
    if plain.len() != 64 {
        bail!("damaged backup");
    }
    let root = keypair_from(&plain[..32])?;
    let emergency = keypair_from(&plain[32..])?;
    if !force && (root_path(dir).exists() || emergency_path(dir).exists()) {
        bail!(
            "{} holds keys already; the backup's root key is {} \
             (--force replaces them; back them up first if they matter)",
            dir.display(),
            crypto::key_b64(&root.public())
        );
    }
    let newpass = new_passphrase("WEBJET_ROOT_PASSPHRASE", "new passphrase for the root keys")?;
    write_private(&root_path(dir), &seal(&newpass, &plain[..32])?)?;
    write_private(&emergency_path(dir), &seal(&newpass, &plain[32..])?)?;
    write_public(
        &dir.join("emergency.cert"),
        &emergency_cert(&root, &emergency),
    )?;
    println!("restored root key {}", crypto::key_b64(&root.public()));
    Ok(())
}

/// `webjetctl root genesis`: the network's genesis, with the first admin.
fn genesis(dir: &Path, overlay_pool: &[String], admin: &Path, out: &Path) -> Result<()> {
    let k = load_keys(dir)?;
    if overlay_pool.is_empty() {
        bail!("--overlay-pool is required");
    }
    let pool: Vec<wp::Cidr> = overlay_pool
        .iter()
        .map(|p| Ok(net_to_cidr(&parse_net(p)?)))
        .collect::<Result<_>>()?;
    let admin_raw = read(admin)?;
    let v = crypto::open_expect(&admin_raw, mt::ACCOUNT_RECORD, &[k.root.public()])?;
    let rec: wp::AccountRecord = v.decode()?;
    if !rec.admin {
        bail!("{} is not an admin account", admin.display());
    }
    let cert = emergency_cert(&k.root, &k.emergency);
    let g = wp::Genesis {
        root_key: Some(crypto::k32(&k.root.public())),
        emergency_cert: Some(cert),
        first_admin: Some(admin_raw),
        overlay_pool: Some(pool),
        created_at: now_ms(),
    };
    let bytes = g.encode_bytes();
    webjet_core::store::open_genesis(&bytes)?;
    write_public(out, &bytes)?;
    println!(
        "genesis written to {} (root key {})",
        out.display(),
        crypto::key_b64(&k.root.public())
    );
    Ok(())
}

/// Run one `webjetctl root` command with the keys in `dir`.
pub fn run(dir: &Path, cmd: RootCmd) -> Result<()> {
    match cmd {
        RootCmd::Init => init(dir)?,
        RootCmd::Backup { out } => {
            let k = load_keys(dir)?;
            let pass = new_passphrase("WEBJET_BACKUP_PASSPHRASE", "passphrase for the backup")?;
            let mut plain = Zeroizing::new(Vec::with_capacity(64));
            plain.extend_from_slice(&k.root.seed()[..]);
            plain.extend_from_slice(&k.emergency.seed()[..]);
            write_secret(&out, &seal(&pass, &plain)?)?;
            println!("backup written to {}", out.display());
        }
        RootCmd::Restore { from, force } => restore(dir, &from, force)?,
        RootCmd::Show => {
            let k = load_keys(dir)?;
            println!("root key:      {}", crypto::key_b64(&k.root.public()));
            println!("emergency key: {}", crypto::key_b64(&k.emergency.public()));
        }
        RootCmd::Admin {
            cmd:
                AdminCmd::Sign {
                    name,
                    key,
                    replaces,
                    out,
                },
        } => {
            let k = load_keys(dir)?;
            let mut p = AccountPub::load(&key)?;
            p.name = name;
            if let Some(r) = &replaces {
                p.account_id = hex::encode(account_ref(Path::new(r))?.1);
            }
            let rec = account_record(&p, true, None)?;
            write_public(&out, &k.root.sign_obj(mt::ACCOUNT_RECORD, &rec))?;
            if replaces.is_some() {
                write_public(&key, &serde_json::to_vec_pretty(&p)?)?;
                println!(
                    "signed a new key for admin account {} → {} ({} now carries the account's ID)",
                    p.name,
                    out.display(),
                    key.display()
                );
            } else {
                println!("signed admin account {} → {}", p.name, out.display());
            }
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
            let (who, id) = account_ref(&key)?;
            let t = wp::AccountTombstone {
                account_id: Some(crypto::k32(&id)),
                version: now_ms(),
                revoke_issued,
                reason,
            };
            write_public(&out, &pick(&k, &with)?.sign_obj(mt::ACCOUNT_TOMBSTONE, &t))?;
            println!(
                "account tombstone for {} → {} (submit with `webjetctl network submit`, or inject on any node)",
                who,
                out.display()
            );
        }
        RootCmd::Genesis {
            overlay_pool,
            admin,
            out,
        } => genesis(dir, &overlay_pool, &admin, &out)?,
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
                anyhow!("--node must be the node id (64 hex characters; see `webjetctl network node list`)")
            })?;
            // A high version beats any record version the controllers may hold.
            let t = wp::Tombstone {
                node_id: Some(crypto::k32(&id)),
                version: now_ms(),
                reason,
            };
            write_public(&out, &pick(&k, &with)?.sign_obj(mt::TOMBSTONE, &t))?;
            println!(
                "node tombstone → {} (inject on any node: `webjetctl local inject`)",
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
