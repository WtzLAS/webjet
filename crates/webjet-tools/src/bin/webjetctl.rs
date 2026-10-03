//! webjetctl: the Webjet command-line tool (§13).
//!
//! - setting up this machine: `init` (first controller), `enroll`
//! - this node: `status`, `peers`, `sessions`, `metrics`, `ping`, `inject`
//! - administration: signs operations with an account key kept on this
//!   machine and submits them through the local webjetd's control channel
//! - `root`: the offline root and emergency revocation keys

use anyhow::{Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use webjet_core::crypto::{self, Bytes32, KeyPair};
use webjet_core::types::{now_ms, parse_roles};
use webjet_proto::{self as wp, AccountOp};
use webjet_tools::*;
use webjetd::control::client;

#[derive(Parser)]
#[command(name = "webjetctl", version, about = "Webjet administration")]
struct Cli {
    /// webjetd's control socket.
    #[arg(
        long,
        global = true,
        env = "WEBJET_SOCKET",
        default_value = "/run/webjet/control.sock"
    )]
    socket: PathBuf,
    /// Directory with account keys.
    #[arg(long, global = true, env = "WEBJET_KEYS")]
    keys: Option<PathBuf>,
    /// The account to sign with (defaults to the only key in the key directory).
    #[arg(long, global = true, env = "WEBJET_ACCOUNT")]
    account: Option<String>,
    /// Print raw JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make this machine the first controller of a new network (runbook 1):
    /// creates the agent's data directory from the genesis file. Start the
    /// agent afterwards.
    Init {
        /// The genesis file from `webjetctl root genesis`.
        #[arg(long)]
        genesis: PathBuf,
        /// webjetd.toml to read the data directory from (default: the
        /// platform's, see docs/configuration.md).
        #[arg(short, long, env = "WEBJET_CONFIG")]
        config: Option<PathBuf>,
        /// Override the data directory.
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Enroll (or re-key) this machine with an enrollment string from
    /// `node enroll` or `node rekey`. Restart the agent afterwards (webjetup
    /// enroll does both). On the first controller, run it while the agent
    /// runs: the agent itself answers the enrollment.
    Enroll {
        string: String,
        /// webjetd.toml to read the data directory and key storage from.
        #[arg(short, long, env = "WEBJET_CONFIG")]
        config: Option<PathBuf>,
        /// Override the data directory.
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// This node's state, tree version and alarms.
    Status,
    /// Hop sessions to neighbors.
    Peers,
    /// End-to-end sessions and circuits.
    Sessions,
    /// This node's metrics in OpenMetrics text (`--all` on a controller:
    /// every node's latest report, as Prometheus scrapes it).
    Metrics {
        #[arg(long)]
        all: bool,
    },
    /// Ping a node (by name or overlay address) through the overlay.
    Ping {
        target: String,
        #[arg(short, long, default_value_t = 3)]
        count: u16,
    },
    /// Accounts: create key pairs, add, list and revoke accounts
    Account {
        #[command(subcommand)]
        cmd: AccountCmd,
    },
    /// Nodes: enrollment strings, list, show, update, rename, revoke, re-key
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// The network's access policy (apply, check, show)
    Policy {
        #[command(subcommand)]
        cmd: ApplyCmd,
    },
    /// Magic DNS settings: suffix, resolver address, records, forwarding
    Dns {
        #[command(subcommand)]
        cmd: ApplyCmd,
    },
    /// The seed list nodes use to find the network
    Seeds {
        #[command(subcommand)]
        cmd: ApplyCmd,
    },
    /// Network-wide resource limits (§16.2)
    Limits {
        #[command(subcommand)]
        cmd: ApplyCmd,
    },
    /// Transport priorities, camouflage and padding
    Transport {
        #[command(subcommand)]
        cmd: ApplyCmd,
    },
    /// The network's pre-shared key
    Psk {
        #[command(subcommand)]
        cmd: PskCmd,
    },
    /// The AnyTLS camouflage certificate key and website
    Camouflage {
        #[command(subcommand)]
        cmd: CamouflageCmd,
    },
    /// Controllers: certificate requests and cluster membership
    Controller {
        #[command(subcommand)]
        cmd: ControllerCmd,
    },
    /// Submit a signed file (certificate, tombstone, account, state version).
    Submit { file: PathBuf },
    /// Inject offline-signed material into this node (spreads by gossip).
    Inject { file: PathBuf },
    /// The offline root and emergency revocation keys (§5): run these on
    /// the offline computer. They never talk to the network.
    Root {
        /// Directory holding the encrypted root and emergency keys.
        #[arg(long, global = true, default_value = webjet_tools::root::DEFAULT_DIR)]
        dir: PathBuf,
        #[command(subcommand)]
        cmd: webjet_tools::root::RootCmd,
    },
}

/// The agent's configuration for `init` and `enroll`.
fn agent_config(
    config: Option<&Path>,
    data_dir: Option<PathBuf>,
) -> Result<webjetd::config::Config> {
    let path = config
        .map(Path::to_path_buf)
        .unwrap_or_else(webjetd::config::default_config_path);
    if config.is_some() && !path.exists() {
        bail!("configuration file {} not found", path.display());
    }
    let mut cfg = webjetd::config::Config::load(Some(&path))?;
    if let Some(d) = data_dir {
        cfg.override_data_dir(d, path.exists());
    }
    Ok(cfg)
}

#[derive(Subcommand)]
enum AccountCmd {
    /// Create an account key on this machine.
    Keygen {
        #[arg(long)]
        name: String,
        #[arg(long)]
        pub_out: PathBuf,
    },
    /// Create a normal account signed by your admin account.
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        key: PathBuf,
    },
    /// Revoke an account and with it all its nodes.
    Revoke {
        name: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        revoke_issued: bool,
    },
    List,
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Create an enrollment and print the enrollment string.
    Enroll {
        #[arg(long)]
        owner: String,
        #[arg(long)]
        name: String,
        /// Overlay address(es); picked from the pool when omitted.
        #[arg(long)]
        ip: Vec<String>,
        #[arg(long, default_value = "data")]
        roles: String,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Subnet route grants: `192.168.1.0/24` or `192.168.1.0/24=10.2.2.0/24`.
        #[arg(long)]
        route: Vec<String>,
        /// Hours until the token expires.
        #[arg(long, default_value_t = 24)]
        expires_hours: u64,
        /// Controller enrollment endpoints (`transport:host:port`); defaults to known ones.
        #[arg(long)]
        controller: Vec<String>,
    },
    List,
    Show {
        name: String,
    },
    Update {
        name: String,
        #[arg(long)]
        roles: Option<String>,
        #[arg(long, value_delimiter = ',')]
        tags: Option<Vec<String>>,
        #[arg(long)]
        ip: Option<Vec<String>>,
        #[arg(long)]
        route: Option<Vec<String>>,
        #[arg(long)]
        no_routes: bool,
        #[arg(long)]
        owner: Option<String>,
    },
    Rename {
        name: String,
        new_name: String,
    },
    Revoke {
        name: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Issue a re-key token for a reinstalled node (runbook 8).
    Rekey {
        name: String,
        #[arg(long)]
        revoke_old_now: bool,
        #[arg(long, default_value_t = 24)]
        expires_hours: u64,
        #[arg(long)]
        controller: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ApplyCmd {
    /// Validate and submit a YAML file.
    Apply { file: PathBuf },
    /// Validate a YAML file without submitting (policies: run its tests).
    Check { file: Option<PathBuf> },
    /// Show the current configuration.
    Show,
}

#[derive(Subcommand)]
enum PskCmd {
    Rotate,
}

#[derive(Subcommand)]
enum CamouflageCmd {
    /// Store the certificate's private key and the website on the controllers.
    SetSecret {
        #[arg(long)]
        key: PathBuf,
        /// An HTML file, or a directory with index.html.
        #[arg(long)]
        site: PathBuf,
    },
    /// Generate a self-signed certificate and key (REFUSE mode, labs).
    Selfsign {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        cert_out: PathBuf,
        #[arg(long)]
        key_out: PathBuf,
    },
}

#[derive(Subcommand)]
enum ControllerCmd {
    /// Create a certificate request for this controller's signing key.
    CertRequest {
        #[arg(long)]
        out: PathBuf,
    },
    List,
    AddLearner {
        name: String,
    },
    Promote {
        name: String,
    },
    Demote {
        name: String,
    },
    Remove {
        name: String,
    },
}

// ---------------------------------------------------------------- account keys

fn key_dir(cli: &Cli) -> PathBuf {
    cli.keys.clone().unwrap_or_else(default_key_dir)
}

fn load_account(cli: &Cli) -> Result<Account> {
    let dir = key_dir(cli);
    let name = match &cli.account {
        Some(n) => n.clone(),
        None => {
            let mut names = account_names(&dir)?;
            match names.len() {
                1 => names.remove(0),
                0 => bail!("no account keys in {}", dir.display()),
                _ => bail!(
                    "several account keys; choose one with --account ({})",
                    names.join(", ")
                ),
            }
        }
    };
    let pass = passphrase(
        "WEBJET_ACCOUNT_PASSPHRASE",
        &format!("passphrase for account {name}"),
    )?;
    Account::unlock(&dir, &name, &pass)
}

// ---------------------------------------------------------------- talking to webjetd

async fn call(cli: &Cli, req: Value) -> Result<Value> {
    client::call(&cli.socket, req).await
}

async fn submit(cli: &Cli, signed: Vec<u8>) -> Result<Value> {
    call(cli, json!({"cmd": "submit_op", "signed": b64(&signed)})).await
}

async fn nodes(cli: &Cli) -> Result<Vec<Value>> {
    Ok(call(cli, json!({"cmd": "nodes"}))
        .await?
        .as_array()
        .cloned()
        .unwrap_or_default())
}

async fn node_id(cli: &Cli, name: &str) -> Result<Bytes32> {
    for n in nodes(cli).await? {
        if n["name"].as_str() == Some(name)
            || n["id"].as_str() == Some(name)
            || n["key"].as_str() == Some(name)
        {
            return crypto::parse_hex32(n["id"].as_str().unwrap_or(""))
                .ok_or_else(|| anyhow!("bad id"));
        }
    }
    bail!("no node named {name}")
}

async fn account_id(cli: &Cli, name: &str) -> Result<Bytes32> {
    let accts = call(cli, json!({"cmd": "accounts"})).await?;
    for a in accts.as_array().cloned().unwrap_or_default() {
        if a["name"].as_str() == Some(name) && a["valid"].as_bool() == Some(true) {
            return crypto::parse_hex32(a["id"].as_str().unwrap_or(""))
                .ok_or_else(|| anyhow!("bad id"));
        }
    }
    bail!("no valid account named {name}")
}

/// Pick a free address from the overlay pool.
fn pick_ip(info: &Value) -> Result<String> {
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

async fn ticket(cli: &Cli, token: &[u8], controllers: &[String]) -> Result<String> {
    let info = call(cli, json!({"cmd": "enroll_info"})).await?;
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

/// `<setting> show`: the setting in force as an apply file, defaults filled in.
async fn show_setting(cli: &Cli, what: &str) -> Result<()> {
    let t = call(cli, json!({"cmd": "tree"})).await?;
    let text = match what {
        "transport" => webjet_tools::show::transport(&t)?,
        "dns" => webjet_tools::show::dns(&t)?,
        "seeds" => webjet_tools::show::seeds(&t)?,
        "limits" => webjet_tools::show::limits(&t)?,
        "policy" => webjet_tools::show::policy(&t)?,
        other => bail!("nothing to show for {other}"),
    };
    if cli.json {
        print(cli, &webjet_tools::show::as_json(&text)?);
    } else {
        print!("{text}");
    }
    Ok(())
}

fn print(cli: &Cli, v: &Value) {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
        return;
    }
    match v {
        Value::Object(_) | Value::Array(_) => println!(
            "{}",
            serde_yaml::to_string(v).unwrap_or_default().trim_end()
        ),
        other => println!("{other}"),
    }
}

fn print_table(rows: &[Vec<String>]) {
    if rows.is_empty() {
        return;
    }
    let cols = rows[0].len();
    let w: Vec<usize> = (0..cols)
        .map(|c| {
            rows.iter()
                .map(|r| r.get(c).map(|s| s.len()).unwrap_or(0))
                .max()
                .unwrap_or(0)
        })
        .collect();
    for r in rows {
        let line: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(i, s)| format!("{:<w$}", s, w = w[i]))
            .collect();
        println!("{}", line.join("  ").trim_end());
    }
}

fn site_bundle(p: &Path) -> Result<Vec<u8>> {
    if p.is_dir() {
        read(&p.join("index.html"))
    } else {
        read(p)
    }
}

/// Read and validate a transport.yaml. Warns about fields refuse mode
/// ignores; their files aren't read.
fn transport_file(file: &Path) -> Result<wp::TransportConfig> {
    let f: TransportFile = serde_yaml::from_slice(&read(file)?)?;
    if let Some(c) = &f.camouflage {
        let ignored = c.ignored();
        if !ignored.is_empty() {
            eprintln!(
                "note: camouflage mode is refuse; ignoring {}",
                ignored.join(", ")
            );
        }
    }
    let base = file.parent().map(Path::to_path_buf).unwrap_or_default();
    f.to_wire(&base)
}

/// `transport apply`. In refuse mode the network keeps its camouflage
/// certificate; a network without one gets a self-signed certificate, whose
/// private key is stored with the controllers first so relays can serve it.
async fn transport_apply(cli: &Cli, file: &Path) -> Result<()> {
    let mut cfg = transport_file(file)?;
    let a = load_account(cli)?;
    if let Some(cam) = cfg.camouflage.as_mut()
        && cam.mode == wp::CamouflageMode::Refuse
    {
        let t = call(cli, json!({"cmd": "tree"})).await?;
        let current: Option<wp::TransportConfig> = match &t["transport"] {
            Value::Null => None,
            v => Some(serde_json::from_value(v.clone())?),
        };
        let cur_cam = current.as_ref().and_then(|c| c.camouflage.as_deref());
        match refuse_certificate(cam, cur_cam)? {
            RefuseCertificate::Kept => {
                println!("refuse mode: keeping the network's camouflage certificate");
            }
            RefuseCertificate::New { key_pem } => {
                let op = wp::SetCamouflageSecret {
                    private_key: Some(key_pem),
                    site: Some(Vec::new()),
                };
                let r = submit(cli, a.sign(AccountOp::SetCamouflageSecret(Box::new(op)))?).await?;
                println!(
                    "refuse mode: made a self-signed camouflage certificate for {} (key stored, entry {})",
                    cam.domain.as_deref().unwrap_or(""),
                    r["index"]
                );
            }
        }
    }
    let op = AccountOp::SetTransport(Box::new(wp::SetTransport {
        config: Some(Box::new(cfg)),
    }));
    let r = submit(cli, a.sign(op)?).await?;
    println!("transport applied (entry {})", r["index"]);
    Ok(())
}

// ---------------------------------------------------------------- main

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Init {
            genesis,
            config,
            data_dir,
        } => {
            let cfg = agent_config(config.as_deref(), data_dir.clone())?;
            webjetd::agent::init(&cfg, &read(genesis)?, true)?;
        }
        Cmd::Enroll {
            string,
            config,
            data_dir,
        } => {
            let cfg = agent_config(config.as_deref(), data_dir.clone())?;
            webjetd::agent::enroll(&cfg, string).await?;
        }
        Cmd::Root { dir, cmd } => {
            // Offline: no agent, no network. Blocking file and prompt work
            // runs off the async runtime's thread.
            let (dir, cmd) = (dir.clone(), cmd.clone());
            tokio::task::spawn_blocking(move || webjet_tools::root::run(&dir, cmd)).await??;
        }
        Cmd::Status => {
            let s = call(&cli, json!({"cmd": "status"})).await?;
            print(&cli, &s);
        }
        Cmd::Peers => {
            let v = call(&cli, json!({"cmd": "peers"})).await?;
            if cli.json {
                print(&cli, &v);
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
        Cmd::Sessions => print(&cli, &call(&cli, json!({"cmd": "sessions"})).await?),
        Cmd::Ping { target, count } => {
            let v = call(
                &cli,
                json!({"cmd": "ping", "target": target, "count": count}),
            )
            .await?;
            let mut ok = 0;
            for (i, r) in v["replies"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .enumerate()
            {
                match r.as_f64() {
                    Some(ms) => {
                        ok += 1;
                        println!(
                            "reply from {}: seq={i} time={ms:.2} ms",
                            v["target"].as_str().unwrap_or("")
                        );
                    }
                    None => println!("seq={i}: timeout"),
                }
            }
            if ok == 0 {
                bail!("no reply from {target}");
            }
        }
        Cmd::Metrics { all } => {
            let v = call(&cli, json!({"cmd": "metrics", "all": all})).await?;
            print!("{}", v["openmetrics"].as_str().unwrap_or(""));
        }
        Cmd::Account { cmd } => match cmd {
            AccountCmd::Keygen { name, pub_out } => {
                if !webjet_core::types::valid_name(name) {
                    bail!("account names are [a-z0-9-]{{1,32}}");
                }
                let dir = key_dir(&cli);
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
                println!(
                    "account key for {name} created in {}; public part in {}",
                    dir.display(),
                    pub_out.display()
                );
            }
            AccountCmd::Create { name, key } => {
                let a = load_account(&cli)?;
                let mut p = AccountPub::load(key)?;
                p.name = name.clone();
                let rec = account_record(&p, false, Some(a.id))?;
                let signed = a.kp.sign_obj(wp::msg_type::ACCOUNT_RECORD, &rec);
                let r = submit(
                    &cli,
                    a.sign(AccountOp::PutAccount(Box::new(wp::PutAccount {
                        record: Some(signed),
                    })))?,
                )
                .await?;
                println!("account {name} created (entry {})", r["index"]);
            }
            AccountCmd::Revoke {
                name,
                reason,
                revoke_issued,
            } => {
                let a = load_account(&cli)?;
                let id = account_id(&cli, name).await?;
                let t = wp::AccountTombstone {
                    account_id: Some(crypto::k32(&id)),
                    version: now_ms(),
                    revoke_issued: *revoke_issued,
                    reason: reason.clone(),
                };
                let signed = a.kp.sign_obj(wp::msg_type::ACCOUNT_TOMBSTONE, &t);
                let r = submit(
                    &cli,
                    a.sign(AccountOp::TombstoneAccount(Box::new(
                        wp::TombstoneAccount {
                            tombstone: Some(signed),
                        },
                    )))?,
                )
                .await?;
                println!("account {name} revoked (entry {})", r["index"]);
            }
            AccountCmd::List => {
                let v = call(&cli, json!({"cmd": "accounts"})).await?;
                if cli.json {
                    print(&cli, &v);
                } else {
                    let mut rows = vec![vec![
                        "NAME".into(),
                        "ADMIN".into(),
                        "VALID".into(),
                        "KEY".into(),
                    ]];
                    for a in v.as_array().cloned().unwrap_or_default() {
                        rows.push(vec![
                            a["name"].as_str().unwrap_or("").into(),
                            a["admin"].to_string(),
                            a["valid"].to_string(),
                            a["key"].as_str().unwrap_or("").into(),
                        ]);
                    }
                    print_table(&rows);
                }
            }
        },
        Cmd::Node { cmd } => match cmd {
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
                let a = load_account(&cli)?;
                let owner_id = account_id(&cli, owner).await?;
                let ips = if ip.is_empty() {
                    vec![pick_ip(&call(&cli, json!({"cmd": "enroll_info"})).await?)?]
                } else {
                    ip.clone()
                };
                let token = crypto::random32();
                let th = crypto::token_hash(&token);
                let op = wp::CreateEnrollment {
                    owner: Some(crypto::k32(&owner_id)),
                    name: Some(name.clone()),
                    overlay_ips: Some(overlay_ips(&ips)?),
                    roles: Some(parse_roles(roles)?),
                    tags: Some(tags(tg)?),
                    routes: Some(grants(route)?),
                    token_hash: Some(crypto::k32(&th)),
                    expires_at: now_ms() + expires_hours * 3_600_000,
                    identity_key: None,
                    node_id: None,
                };
                let r = submit(&cli, a.sign(AccountOp::CreateEnrollment(Box::new(op)))?).await?;
                eprintln!(
                    "enrollment for {name} ({}) created (entry {}); on the node run:",
                    ips.join(", "),
                    r["index"]
                );
                println!("{}", ticket(&cli, &token, controller).await?);
            }
            NodeCmd::List => {
                let v = nodes(&cli).await?;
                if cli.json {
                    print(&cli, &json!(v));
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
                let id = node_id(&cli, name).await?;
                let n = nodes(&cli)
                    .await?
                    .into_iter()
                    .find(|n| n["id"].as_str() == Some(&hex::encode(id)))
                    .unwrap_or_default();
                print(&cli, &n);
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
                let a = load_account(&cli)?;
                let id = node_id(&cli, name).await?;
                let owner = match owner {
                    Some(o) => Some(crypto::k32(&account_id(&cli, o).await?)),
                    None => None,
                };
                let op = wp::UpdateNode {
                    node_id: Some(crypto::k32(&id)),
                    owner,
                    set_overlay_ips: ip.is_some(),
                    overlay_ips: ip.as_ref().map(|v| overlay_ips(v)).transpose()?,
                    set_roles: roles.is_some(),
                    roles: roles.as_ref().map(|r| parse_roles(r)).transpose()?,
                    set_tags: tg.is_some(),
                    tags: tg.as_ref().map(|t| tags(t)).transpose()?,
                    set_routes: route.is_some() || *no_routes,
                    routes: if *no_routes {
                        Some(vec![])
                    } else {
                        route.as_ref().map(|r| grants(r)).transpose()?
                    },
                };
                let r = submit(&cli, a.sign(AccountOp::UpdateNode(Box::new(op)))?).await?;
                println!("{name} updated (entry {})", r["index"]);
            }
            NodeCmd::Rename { name, new_name } => {
                let a = load_account(&cli)?;
                let id = node_id(&cli, name).await?;
                let r = submit(
                    &cli,
                    a.sign(AccountOp::RenameNode(Box::new(wp::RenameNode {
                        node_id: Some(crypto::k32(&id)),
                        name: Some(new_name.clone()),
                    })))?,
                )
                .await?;
                println!("{name} is now {new_name} (entry {})", r["index"]);
            }
            NodeCmd::Revoke { name, reason } => {
                let a = load_account(&cli)?;
                let id = node_id(&cli, name).await?;
                let r = submit(
                    &cli,
                    a.sign(AccountOp::TombstoneNode(Box::new(wp::TombstoneNode {
                        node_id: Some(crypto::k32(&id)),
                        reason: reason.clone(),
                    })))?,
                )
                .await?;
                println!("{name} revoked (entry {})", r["index"]);
            }
            NodeCmd::Rekey {
                name,
                revoke_old_now,
                expires_hours,
                controller,
            } => {
                let a = load_account(&cli)?;
                let id = node_id(&cli, name).await?;
                let token = crypto::random32();
                let op = wp::RekeyNode {
                    node_id: Some(crypto::k32(&id)),
                    token_hash: Some(crypto::k32(&crypto::token_hash(&token))),
                    expires_at: now_ms() + expires_hours * 3_600_000,
                    revoke_old_now: *revoke_old_now,
                };
                let r = submit(&cli, a.sign(AccountOp::RekeyNode(Box::new(op)))?).await?;
                eprintln!(
                    "re-key for {name} issued (entry {}); on the node run `webjetup enroll` (or `webjetctl enroll`) with:",
                    r["index"]
                );
                println!("{}", ticket(&cli, &token, controller).await?);
            }
        },
        Cmd::Policy { cmd } => match cmd {
            ApplyCmd::Apply { file } | ApplyCmd::Check { file: Some(file) } => {
                let f: webjet_core::policy::PolicyFile = serde_yaml::from_slice(&read(file)?)?;
                let wire = f.to_wire()?;
                let pol = webjet_core::policy::Policy::from_wire(&wire)?;
                pol.run_tests(&|_| None)?;
                if matches!(cmd, ApplyCmd::Check { .. }) {
                    println!(
                        "policy version {} is valid; its {} tests pass",
                        wire.version,
                        f.tests.len()
                    );
                    return Ok(());
                }
                let a = load_account(&cli)?;
                let r = submit(
                    &cli,
                    a.sign(AccountOp::SetPolicy(Box::new(wp::SetPolicy {
                        policy: Some(Box::new(wire)),
                    })))?,
                )
                .await?;
                println!("policy applied (entry {})", r["index"]);
            }
            ApplyCmd::Check { file: None } => bail!("give a policy file to check"),
            ApplyCmd::Show => show_setting(&cli, "policy").await?,
        },
        Cmd::Dns { cmd } => {
            apply(
                &cli,
                cmd,
                |b| {
                    let f: DnsFile = serde_yaml::from_slice(b)?;
                    Ok(AccountOp::SetDns(Box::new(wp::SetDns {
                        config: Some(Box::new(f.to_wire()?)),
                    })))
                },
                "dns",
            )
            .await?
        }
        Cmd::Seeds { cmd } => {
            apply(
                &cli,
                cmd,
                |b| {
                    let f: SeedsFile = serde_yaml::from_slice(b)?;
                    Ok(AccountOp::SetSeeds(Box::new(wp::SetSeeds {
                        seeds: Some(Box::new(f.to_wire()?)),
                    })))
                },
                "seeds",
            )
            .await?
        }
        Cmd::Limits { cmd } => {
            apply(
                &cli,
                cmd,
                |b| {
                    let f: LimitsFile = serde_yaml::from_slice(b)?;
                    Ok(AccountOp::SetLimits(Box::new(wp::SetLimits {
                        limits: Some(Box::new(f.to_wire()?)),
                    })))
                },
                "limits",
            )
            .await?
        }
        Cmd::Transport { cmd } => match cmd {
            ApplyCmd::Apply { file } => transport_apply(&cli, file).await?,
            ApplyCmd::Check { file: Some(file) } => {
                let cfg = transport_file(file)?;
                let refuse = cfg
                    .camouflage
                    .as_ref()
                    .is_some_and(|c| c.mode == wp::CamouflageMode::Refuse);
                println!("{} is valid", file.display());
                if refuse {
                    println!(
                        "refuse mode: the network's current camouflage certificate is kept, \
                         or a self-signed one is made when applying"
                    );
                }
            }
            ApplyCmd::Check { file: None } => bail!("give a file to check"),
            ApplyCmd::Show => show_setting(&cli, "transport").await?,
        },
        Cmd::Psk {
            cmd: PskCmd::Rotate,
        } => {
            let a = load_account(&cli)?;
            let st = call(&cli, json!({"cmd": "status"})).await?;
            let cur = st["psk_epoch"].as_u64().unwrap_or(0) as u16;
            let r = submit(
                &cli,
                a.sign(AccountOp::RotatePsk(Box::new(wp::RotatePsk {
                    epoch_id: cur.wrapping_add(1),
                })))?,
            )
            .await?;
            println!(
                "PSK rotated to epoch {} (entry {})",
                cur.wrapping_add(1),
                r["index"]
            );
        }
        Cmd::Camouflage { cmd } => match cmd {
            CamouflageCmd::SetSecret { key, site } => {
                let a = load_account(&cli)?;
                let k = read(key)?;
                if !String::from_utf8_lossy(&k).contains("PRIVATE KEY") {
                    bail!("{} is not a PEM private key", key.display());
                }
                let op = wp::SetCamouflageSecret {
                    private_key: Some(k),
                    site: Some(site_bundle(site)?),
                };
                let r = submit(&cli, a.sign(AccountOp::SetCamouflageSecret(Box::new(op)))?).await?;
                println!("camouflage secret stored (entry {})", r["index"]);
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
                write_private(key_out, &key)?;
                println!(
                    "self-signed certificate for {domain}: {} / {}",
                    cert_out.display(),
                    key_out.display()
                );
            }
            #[cfg(not(feature = "anytls"))]
            CamouflageCmd::Selfsign { .. } => bail!("built without AnyTLS"),
        },
        Cmd::Controller { cmd } => match cmd {
            ControllerCmd::CertRequest { out } => {
                let r = call(&cli, json!({"cmd": "cert_request"})).await?;
                let raw = webjetd::state::unb64(r["request"].as_str().unwrap_or(""))?;
                write_public(out, &raw)?;
                println!(
                    "certificate request → {} (sign it offline: webjetctl root controller sign)",
                    out.display()
                );
            }
            ControllerCmd::List => print(&cli, &call(&cli, json!({"cmd": "controller"})).await?),
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
                let a = load_account(&cli)?;
                let id = node_id(&cli, name).await?;
                let r = submit(
                    &cli,
                    a.sign(AccountOp::ChangeMembership(Box::new(
                        wp::ChangeMembership {
                            change,
                            node_id: Some(crypto::k32(&id)),
                        },
                    )))?,
                )
                .await?;
                println!("{change:?} {name} (entry {})", r["index"]);
            }
        },
        Cmd::Submit { file } | Cmd::Inject { file } => {
            let raw = read(file)?;
            eprintln!("{}", describe(&raw));
            let r = call(&cli, json!({"cmd": "submit_signed", "signed": b64(&raw)})).await?;
            print(&cli, &r);
        }
    }
    Ok(())
}

async fn apply<F>(cli: &Cli, cmd: &ApplyCmd, build: F, what: &str) -> Result<()>
where
    F: Fn(&[u8]) -> Result<AccountOp>,
{
    match cmd {
        ApplyCmd::Apply { file } => {
            let op = build(&read(file)?)?;
            let a = load_account(cli)?;
            let r = submit(cli, a.sign(op)?).await?;
            println!("{what} applied (entry {})", r["index"]);
        }
        ApplyCmd::Check { file: Some(file) } => {
            build(&read(file)?)?;
            println!("{} is valid", file.display());
        }
        ApplyCmd::Check { file: None } => bail!("give a file to check"),
        ApplyCmd::Show => show_setting(cli, what).await?,
    }
    Ok(())
}
