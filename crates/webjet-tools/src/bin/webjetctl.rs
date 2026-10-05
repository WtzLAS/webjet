//! webjetctl: the Webjet command-line tool (§13). Three groups, by scope:
//!
//! - `network`: the whole network — its configuration, nodes, accounts,
//!   controllers, PSK and camouflage. Signs operations with an account key
//!   kept on this machine and submits them through the local webjetd.
//! - `local`: this machine and one node — setting it up (`init`, `enroll`),
//!   looking at it (`status`, `peers`, …) and the node's own configuration
//!   (`local config`, which overrides the network's for that node).
//! - `root`: the offline root and emergency revocation keys.

use anyhow::{Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use webjet_core::crypto::{self, Bytes32, KeyPair};
use webjet_core::types::{now_ms, parse_roles};
use webjet_proto::{self as wp, AccountOp};
use webjet_tools::config::{
    self, ConfigFile, effective_from_json, fill_refuse_certificate, network_from_tree,
    node_from_wire, render_effective, render_network, render_node,
};
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
        default_value_os_t = webjetd::ipc::default_control()
    )]
    socket: PathBuf,
    /// Directory with account keys.
    #[arg(long, global = true, env = "WEBJET_KEYS")]
    keys: Option<PathBuf>,
    /// The account to sign with. Defaults to the one chosen with
    /// `network account use`, else the only key in the key directory.
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
    /// The whole network: its configuration, nodes, accounts, controllers,
    /// PSK and camouflage (signed with your account key).
    Network {
        #[command(subcommand)]
        cmd: NetworkCmd,
    },
    /// This machine and its node: setup, state, and the node's own
    /// configuration (overrides of the network's).
    Local {
        #[command(subcommand)]
        cmd: LocalCmd,
    },
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

#[derive(Subcommand)]
enum NetworkCmd {
    /// The network configuration: policy, DNS, seeds, transport, limits
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
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
}

#[derive(Subcommand)]
enum LocalCmd {
    /// Make this machine the first controller of a new network (ops guide 2.1):
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
    /// `network node enroll` or `network node rekey`. Restart the agent afterwards (webjetup
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
    /// Tracked flows (connection tracking) and the circuit each one takes.
    Conntrack,
    /// Reverse proxy ports: this node's rules with their status and
    /// warnings, and its proxy flows as listener and as target (kept apart
    /// from `conntrack`).
    Proxy,
    /// The network graph as this node sees it: nodes, relay links,
    /// attachments and this node's hops.
    Topology,
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
    /// Inject offline-signed material into this node (spreads by gossip).
    Inject { file: PathBuf },
    /// This node's configuration (`--node` for another one you own):
    /// overrides of the network configuration for this node only
    Config {
        /// The node (name, id or key); default: this node.
        #[arg(long, global = true)]
        node: Option<String>,
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
}

/// The same verbs at both scopes.
#[derive(Subcommand)]
enum ConfigCmd {
    /// Print the configuration as a TOML file to edit and apply.
    Show {
        /// Local scope: what is in force for the node (network values with
        /// its overrides), not only what it sets.
        #[arg(long)]
        effective: bool,
    },
    /// Validate a file without submitting it (policy tests run).
    Check { file: PathBuf },
    /// Validate a file and submit it as the next version.
    Apply { file: PathBuf },
    /// Open the configuration in $EDITOR and apply the result.
    Edit,
    /// Print one value (dotted key: `transport.priority.kcp`, `seeds.0`).
    Get { key: String },
    /// Set one value and apply (TOML value: `0`, `true`, `["a", "b"]`).
    Set { key: String, value: String },
    /// Remove one value (back to the network's or built-in) and apply.
    Unset { key: String },
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
    /// Give a normal account a new key (lost or compromised key). The account
    /// keeps its name, devices and policy; only the old key stops working.
    /// Admin accounts get a new key from the root (`root admin sign --replaces`).
    Rekey {
        name: String,
        /// The new key's public file, from `network account keygen`.
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
    /// List the network's accounts; `*` marks the one this machine signs
    /// with by default, `key` the others with a key here.
    List,
    /// Sign with this account when --account isn't given (recorded in the
    /// key directory). Without a name, show the current choice.
    Use {
        /// An account with a key in the key directory.
        #[arg(conflicts_with = "clear")]
        name: Option<String>,
        /// Forget the default (back to: the only key, or --account).
        #[arg(long)]
        clear: bool,
    },
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
        /// Roles: any of `data`, `relay`, `control` (comma-separated).
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
        /// The full role set: any of `data`, `relay`, `control`.
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
    /// Issue a re-key token for a reinstalled node (ops guide 2.7).
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
    /// Certify a controller's signing key with an admin key and submit the
    /// certificate. The node needs the `control` role; its request is fetched
    /// from it over the overlay, or read from `--request`.
    Certify {
        name: String,
        #[arg(long)]
        request: Option<PathBuf>,
    },
    /// Write the certificate request for a controller's signing key (this
    /// node's, or `--node`'s), to sign offline with `webjetctl root controller sign`.
    CertRequest {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        node: Option<String>,
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

/// Unlock the account key to sign with. The account it signs for is the one
/// the network holds this key under: after `network account rekey` (or a
/// root-signed key change) the new key's `.pub` still carries the random
/// account ID `keygen` gave it, so the network's ID is used, and written
/// back to the `.pub` once.
async fn load_account(cli: &Cli) -> Result<Account> {
    let dir = key_dir(cli);
    let name = pick_account(&dir, cli.account.as_deref())?;
    let pass = passphrase(
        "WEBJET_ACCOUNT_PASSPHRASE",
        &format!("passphrase for account {name}"),
    )?;
    let mut a = Account::unlock(&dir, &name, &pass)?;
    // Without an agent the command fails at submit anyway, with its own error.
    let Ok(accts) = call(cli, json!({"cmd": "accounts"})).await else {
        return Ok(a);
    };
    let key = crypto::key_b64(&a.kp.public());
    let held = accts
        .as_array()
        .into_iter()
        .flatten()
        .find(|x| x["key"].as_str() == Some(key.as_str()));
    if let Some(x) = held
        && let Some(id) = x["id"].as_str().and_then(crypto::parse_hex32)
        && id != a.id
    {
        a.id = id;
        let path = dir.join(format!("{name}.pub"));
        let mut p = AccountPub::load(&path)?;
        p.account_id = hex::encode(id);
        if write_public(&path, &serde_json::to_vec_pretty(&p)?).is_ok() {
            eprintln!(
                "note: this key belongs to account {}; {} updated with its account ID",
                x["name"].as_str().unwrap_or("?"),
                path.display()
            );
        }
    }
    Ok(a)
}

// ---------------------------------------------------------------- talking to webjetd

/// A controller's certificate request, from the local agent (`None`: this
/// node's own) or fetched from another node over the overlay.
async fn cert_request(cli: &Cli, node: Option<Bytes32>) -> Result<Vec<u8>> {
    let mut req = json!({"cmd": "cert_request"});
    if let Some(id) = node {
        req["node"] = json!(hex::encode(id));
    }
    let r = call(cli, req).await?;
    webjetd::state::unb64(r["request"].as_str().unwrap_or(""))
}

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

// ---------------------------------------------------------------- configuration

async fn tree(cli: &Cli) -> Result<Value> {
    call(cli, json!({"cmd": "tree"})).await
}

/// A wire value from a control reply; `None` for null.
fn from_json<T: serde::de::DeserializeOwned>(v: &Value) -> Result<Option<T>> {
    match v {
        Value::Null => Ok(None),
        v => Ok(Some(serde_json::from_value(v.clone())?)),
    }
}

fn show_doc(cli: &Cli, text: &str, doc: &ConfigFile) -> Result<()> {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(doc)?);
    } else {
        print!("{text}");
    }
    Ok(())
}

fn print_value(cli: &Cli, v: &toml::Value) -> Result<()> {
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
fn base_dir(file: &Path) -> PathBuf {
    file.parent()
        .map(Path::to_path_buf)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Edit `text` in $VISUAL / $EDITOR. Returns the parsed result and the
/// file it is in (kept until the caller applied it), or `None` when nothing
/// changed.
fn edit_text(text: &str, name: &str) -> Result<Option<(ConfigFile, PathBuf)>> {
    let dir = std::env::temp_dir().join(format!("webjetctl-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
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
async fn apply_edited<F: std::future::Future<Output = Result<()>>>(
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

/// Validate a network configuration file the way `apply` will (policy tests
/// with names unresolved; the controllers run them against the nodes).
fn network_wire(f: &ConfigFile, version: u64, base: &Path) -> Result<wp::NetworkConfig> {
    let w = f.to_network(version, base)?;
    if let Some(p) = &w.policy {
        webjet_core::policy::Policy::from_wire(p)?.run_tests(&|_| None)?;
    }
    if let Some(c) = f.transport.as_ref().and_then(|t| t.camouflage.as_ref()) {
        let ignored = c.ignored();
        if !ignored.is_empty() {
            eprintln!(
                "note: camouflage mode is refuse; ignoring {}",
                ignored.join(", ")
            );
        }
    }
    Ok(w)
}

/// `network config apply`: the file's sections over the configuration in
/// force, as the next version. In refuse mode the network keeps its
/// camouflage certificate; a network without one gets a self-signed one,
/// whose key is stored with the controllers first so relays can serve it.
async fn apply_network(cli: &Cli, f: &ConfigFile, base: &Path, what: Option<&str>) -> Result<()> {
    let from = f.base_version()?;
    let sections = f.sections();
    if sections.is_empty() {
        bail!("the file sets nothing: no [policy], [dns], seeds, [transport] or [limits]");
    }
    let t = tree(cli).await?;
    let now = t["network_version"].as_u64().unwrap_or(0);
    if from != now {
        bail!(
            "the file was made from network configuration version {from}, but version {now} is in force: someone applied a change meanwhile. Start again from `webjetctl network config show` (or set `version = {now}` to overwrite their change)."
        );
    }
    let merged = f.over(&network_from_tree(&t, false)?);
    let mut w = network_wire(&merged, now + 1, base)?;
    let a = load_account(cli).await?;
    let current: Option<wp::TransportConfig> = from_json(&t["transport"])?;
    let current_cam = current.as_ref().and_then(|c| c.camouflage.as_deref());
    if let Some(key_pem) = fill_refuse_certificate(&mut w, current_cam)? {
        let op = wp::SetCamouflageSecret {
            private_key: Some(key_pem),
            site: Some(Vec::new()),
        };
        let r = submit(cli, a.sign(AccountOp::SetCamouflageSecret(Box::new(op)))?).await?;
        let domain = w
            .transport
            .as_ref()
            .and_then(|t| t.camouflage.as_ref())
            .and_then(|c| c.domain.clone())
            .unwrap_or_default();
        println!(
            "refuse mode: made a self-signed camouflage certificate for {domain} (key stored, entry {})",
            r["index"]
        );
    }
    let op = AccountOp::SetNetworkConfig(Box::new(wp::SetNetworkConfig {
        config: Some(Box::new(w)),
    }));
    let r = submit(cli, a.sign(op)?).await?;
    let what = what.map_or_else(|| sections.join(", "), String::from);
    println!(
        "network configuration version {} applied: {what} (entry {})",
        now + 1,
        r["index"]
    );
    Ok(())
}

async fn network_config(cli: &Cli, cmd: &ConfigCmd) -> Result<()> {
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
            network_wire(&f, from + 1, &base_dir(file))?;
            println!(
                "{} is valid: {} (sections left out stay as they are)",
                file.display(),
                f.sections().join(", ")
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
                println!("no changes");
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
            let f = config::edit_doc(&cur, |d| config::set(d, key, config::parse_value(value)))?;
            apply_network(cli, &f, Path::new("."), Some(&format!("{key} = {value}"))).await?;
        }
        ConfigCmd::Unset { key } => {
            let t = tree(cli).await?;
            let cur = network_from_tree(&t, false)?;
            let f = config::edit_doc(&cur, |d| config::unset(d, key))?;
            apply_network(cli, &f, Path::new("."), Some(&format!("{key} unset"))).await?;
        }
    }
    Ok(())
}

/// A node's configuration and what is in force for it.
struct NodeConf {
    id: Bytes32,
    name: String,
    current: Option<wp::NodeConfig>,
    effective: Value,
}

async fn node_conf(cli: &Cli, node: Option<&str>) -> Result<NodeConf> {
    let id = match node {
        Some(n) => node_id(cli, n).await?,
        None => {
            let st = call(cli, json!({"cmd": "status"})).await?;
            crypto::parse_hex32(st["node_id"].as_str().unwrap_or(""))
                .ok_or_else(|| anyhow!("the agent didn't report its node id"))?
        }
    };
    let r = call(cli, json!({"cmd": "node_config", "node": hex::encode(id)})).await?;
    Ok(NodeConf {
        id,
        name: r["name"].as_str().unwrap_or("").to_string(),
        current: from_json(&r["config"])?,
        effective: r["effective"].clone(),
    })
}

/// `local config apply`: the file is the node's whole configuration (an
/// empty one clears it), submitted as the next version.
async fn apply_node(cli: &Cli, n: &NodeConf, f: &ConfigFile) -> Result<()> {
    let from = f.base_version()?;
    let now = n.current.as_ref().map_or(0, |c| c.version);
    if from != now {
        bail!(
            "the file was made from version {from} of {}'s configuration, but version {now} is in force: someone changed it meanwhile. Start again from `webjetctl local config show`.",
            n.name
        );
    }
    let w = f.to_node(&n.id, now + 1)?;
    if f.is_empty() && n.current.is_none() {
        println!(
            "{} has no configuration of its own; nothing to apply",
            n.name
        );
        return Ok(());
    }
    let a = load_account(cli).await?;
    let op = AccountOp::SetNodeConfig(Box::new(wp::SetNodeConfig {
        config: Some(Box::new(w)),
    }));
    let r = submit(cli, a.sign(op)?).await?;
    if f.is_empty() {
        println!("configuration of {} cleared (entry {})", n.name, r["index"]);
    } else {
        println!(
            "configuration of {} version {} applied (entry {})",
            n.name,
            now + 1,
            r["index"]
        );
    }
    Ok(())
}

async fn local_config(cli: &Cli, node: Option<&str>, cmd: &ConfigCmd) -> Result<()> {
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
            println!(
                "{} is valid for a node's configuration (the controllers check the seeds and DNS names)",
                file.display()
            );
        }
        ConfigCmd::Apply { file } => apply_node(cli, &n, &ConfigFile::load(file)?).await?,
        ConfigCmd::Edit => {
            let text = render_node(&n.name, n.current.as_ref())?;
            let Some((f, path)) = edit_text(&text, &format!("{}.toml", n.name))? else {
                println!("no changes");
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

// ---------------------------------------------------------------- main

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Root { dir, cmd } => {
            // Offline: no agent, no network. Blocking file and prompt work
            // runs off the async runtime's thread.
            let (dir, cmd) = (dir.clone(), cmd.clone());
            tokio::task::spawn_blocking(move || webjet_tools::root::run(&dir, cmd)).await??;
        }
        Cmd::Network { cmd } => network(&cli, cmd).await?,
        Cmd::Local { cmd } => local(&cli, cmd).await?,
    }
    Ok(())
}

async fn local(cli: &Cli, cmd: &LocalCmd) -> Result<()> {
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
            let s = call(cli, json!({"cmd": "status"})).await?;
            print(cli, &s);
        }
        LocalCmd::Peers => {
            let v = call(cli, json!({"cmd": "peers"})).await?;
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
        LocalCmd::Sessions => print(cli, &call(cli, json!({"cmd": "sessions"})).await?),
        LocalCmd::Conntrack => print(cli, &call(cli, json!({"cmd": "conntrack"})).await?),
        LocalCmd::Proxy => print(cli, &call(cli, json!({"cmd": "proxy"})).await?),
        LocalCmd::Topology => print(cli, &call(cli, json!({"cmd": "topology"})).await?),
        LocalCmd::Ping { target, count } => {
            let v = call(
                cli,
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
        LocalCmd::Metrics { all } => {
            let v = call(cli, json!({"cmd": "metrics", "all": all})).await?;
            print!("{}", v["openmetrics"].as_str().unwrap_or(""));
        }
        LocalCmd::Inject { file } => {
            let raw = read(file)?;
            eprintln!("{}", describe(&raw));
            let r = call(cli, json!({"cmd": "submit_signed", "signed": b64(&raw)})).await?;
            print(cli, &r);
        }
        LocalCmd::Config { node, cmd } => local_config(cli, node.as_deref(), cmd).await?,
    }
    Ok(())
}

async fn network(cli: &Cli, cmd: &NetworkCmd) -> Result<()> {
    match cmd {
        NetworkCmd::Account { cmd } => match cmd {
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
                println!(
                    "account key for {name} created in {}; public part in {}",
                    dir.display(),
                    pub_out.display()
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
                println!("account {name} created (entry {})", r["index"]);
            }
            AccountCmd::Rekey { name, key } => {
                let a = load_account(cli).await?;
                let accts = call(cli, json!({"cmd": "accounts"})).await?;
                let cur = accts
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|x| {
                        x["name"].as_str() == Some(name) && x["valid"].as_bool() == Some(true)
                    })
                    .ok_or_else(|| anyhow!("no valid account named {name}"))?;
                if cur["admin"].as_bool() == Some(true) {
                    bail!(
                        "{name} is an admin: only the root gives it a new key (`webjetctl root admin sign --name {name} --key <new>.pub --replaces <old>.pub`)"
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
                p.name = name.clone();
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
                println!(
                    "account {name} has a new key (entry {}); the old key no longer signs. {} now carries the account's ID",
                    r["index"],
                    key.display()
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
                println!("account {name} revoked (entry {})", r["index"]);
            }
            AccountCmd::List => {
                let v = call(cli, json!({"cmd": "accounts"})).await?;
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
                    println!("no default account ({} removed)", file.display());
                } else if let Some(n) = name {
                    set_default_account(&dir, Some(n))?;
                    println!("default account: {n} ({})", file.display());
                } else {
                    if let Some(a) = &cli.account {
                        println!("--account / WEBJET_ACCOUNT overrides it here: {a}");
                    }
                    match default_account(&dir)? {
                        Some(n) => println!("default account: {n} ({})", file.display()),
                        None => match pick_account(&dir, None) {
                            Ok(n) => println!("no default set; using the only key: {n}"),
                            Err(e) => println!("no default account: {e}"),
                        },
                    }
                }
            }
        },
        NetworkCmd::Node { cmd } => match cmd {
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
                    vec![pick_ip(&call(cli, json!({"cmd": "enroll_info"})).await?)?]
                } else {
                    ip.clone()
                };
                let token = crypto::random32();
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
                    expires_at: now_ms() + expires_hours * 3_600_000,
                    identity_key: None,
                    node_id: None,
                };
                let r = submit(cli, a.sign(AccountOp::CreateEnrollment(Box::new(op)))?).await?;
                eprintln!(
                    "enrollment for {name} ({}) created (entry {}); on the node run:",
                    ips.join(", "),
                    r["index"]
                );
                println!("{}", ticket(cli, &token, controller).await?);
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
                println!("{name} updated (entry {})", r["index"]);
            }
            NodeCmd::Rename { name, new_name } => {
                let a = load_account(cli).await?;
                let id = node_id(cli, name).await?;
                let r = submit(
                    cli,
                    a.sign(AccountOp::RenameNode(Box::new(wp::RenameNode {
                        node_id: Some(crypto::k32(&id)),
                        name: Some(new_name.clone()),
                    })))?,
                )
                .await?;
                println!("{name} is now {new_name} (entry {})", r["index"]);
            }
            NodeCmd::Revoke { name, reason } => {
                let a = load_account(cli).await?;
                let id = node_id(cli, name).await?;
                let r = submit(
                    cli,
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
                let a = load_account(cli).await?;
                let id = node_id(cli, name).await?;
                let token = crypto::random32();
                let op = wp::RekeyNode {
                    node_id: Some(crypto::k32(&id)),
                    token_hash: Some(crypto::k32(&crypto::token_hash(&token))),
                    expires_at: now_ms() + expires_hours * 3_600_000,
                    revoke_old_now: *revoke_old_now,
                };
                let r = submit(cli, a.sign(AccountOp::RekeyNode(Box::new(op)))?).await?;
                eprintln!(
                    "re-key for {name} issued (entry {}); on the node run `webjetup enroll` (or `webjetctl enroll`) with:",
                    r["index"]
                );
                println!("{}", ticket(cli, &token, controller).await?);
            }
        },
        NetworkCmd::Psk {
            cmd: PskCmd::Rotate,
        } => {
            let a = load_account(cli).await?;
            let st = call(cli, json!({"cmd": "status"})).await?;
            let cur = st["psk_epoch"].as_u64().unwrap_or(0) as u16;
            let r = submit(
                cli,
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
        NetworkCmd::Camouflage { cmd } => match cmd {
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
        NetworkCmd::Controller { cmd } => match cmd {
            ControllerCmd::Certify { name, request } => {
                let id = node_id(cli, name).await?;
                let req = match request {
                    Some(p) => read(p)?,
                    None => cert_request(cli, Some(id)).await?,
                };
                let a = load_account(cli).await?;
                let accts = call(cli, json!({"cmd": "accounts"})).await?;
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
                let r = call(cli, json!({"cmd": "submit_signed", "signed": b64(&cert)})).await?;
                println!(
                    "certified {name}'s signing key {} (added: {})",
                    hex::encode(kid),
                    r["added"]
                );
            }
            ControllerCmd::CertRequest { out, node } => {
                let target = match node {
                    Some(nm) => Some(node_id(cli, nm).await?),
                    None => None,
                };
                let raw = cert_request(cli, target).await?;
                write_public(out, &raw)?;
                println!(
                    "certificate request → {} (sign it offline: webjetctl root controller sign)",
                    out.display()
                );
            }
            ControllerCmd::List => print(cli, &call(cli, json!({"cmd": "controller"})).await?),
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
                println!("{change:?} {name} (entry {})", r["index"]);
            }
        },
        NetworkCmd::Submit { file } => {
            let raw = read(file)?;
            eprintln!("{}", describe(&raw));
            let r = call(cli, json!({"cmd": "submit_signed", "signed": b64(&raw)})).await?;
            print(cli, &r);
        }
        NetworkCmd::Config { cmd } => network_config(cli, cmd).await?,
    }
    Ok(())
}
