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
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use webjet_core::crypto::{self, Bytes32, KeyPair};
use webjet_core::types::{now_ms, parse_roles};
use webjet_proto::{self as wp, AccountOp};
use webjet_tools::config::{
    self, ConfigFile, effective_from_json, network_from_tree, node_from_wire, render_effective,
    render_network, render_node,
};
use webjet_tools::*;
use webjetd::control::{Request, client};

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
    /// Ping a node (by name, node id, overlay address or magic DNS name) through the overlay.
    Ping {
        target: String,
        #[arg(short, long, default_value_t = 3)]
        count: u16,
        /// Payload bytes (filled with a pattern, as ping(8) does); at most 1232
        #[arg(short, long, default_value_t = 0)]
        size: u16,
    },
    /// Inject offline-signed material into this node (spreads by gossip).
    Inject { file: PathBuf },
    /// Restart the controller cluster with the agent stopped (ops guide 4.1).
    Controller {
        #[command(subcommand)]
        cmd: LocalControllerCmd,
    },
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
    let path = config.map_or_else(webjetd::config::default_config_path, Path::to_path_buf);
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
        /// The account: name, account id in hex (or a unique prefix of it) or key.
        name: String,
        /// The new key's public file, from `network account keygen`.
        #[arg(long)]
        key: PathBuf,
    },
    /// Revoke an account and with it all its nodes.
    Revoke {
        /// The account: name, account id in hex (or a unique prefix of it) or key.
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
        /// The node: name, node id in hex (or a unique prefix of it) or key.
        name: String,
    },
    Update {
        /// The node: name, node id in hex (or a unique prefix of it) or key.
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
        /// The node: name, node id in hex (or a unique prefix of it) or key.
        name: String,
        new_name: String,
    },
    Revoke {
        /// The node: name, node id in hex (or a unique prefix of it) or key.
        name: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Issue a re-key token for a reinstalled node (ops guide 2.7).
    Rekey {
        /// The node: name, node id in hex (or a unique prefix of it) or key.
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
        /// The node: name, node id in hex (or a unique prefix of it) or key.
        name: String,
        #[arg(long)]
        request: Option<PathBuf>,
    },
    /// Write the certificate request for a controller's signing key (this
    /// node's, or `--node`'s), to sign offline with `webjetctl root controller sign`.
    CertRequest {
        #[arg(long)]
        out: PathBuf,
        /// The node: name, node id in hex (or a unique prefix of it) or key.
        #[arg(long)]
        node: Option<String>,
    },
    /// The controllers' Raft state (`node_names` gives the names of the node ids in it).
    List,
    AddLearner {
        /// The node: name, node id in hex (or a unique prefix of it) or key.
        name: String,
    },
    Promote {
        /// The node: name, node id in hex (or a unique prefix of it) or key.
        name: String,
    },
    Demote {
        /// The node: name, node id in hex (or a unique prefix of it) or key.
        name: String,
    },
    Remove {
        /// The node: name, node id in hex (or a unique prefix of it) or key.
        name: String,
    },
    /// Export a controller's state (the network tree, pending enrollments,
    /// PSKs, the camouflage key) to an encrypted file (admins; ops guide
    /// 3.8). Restore it with `webjetctl local controller restore` when no
    /// controller survives (ops guide 4.1). The passphrase comes from
    /// WEBJET_BACKUP_PASSPHRASE or a prompt.
    Snapshot {
        #[arg(long)]
        out: PathBuf,
    },
}

/// Restarting the controller cluster while the agent is stopped (ops guide 4.1).
#[derive(Subcommand)]
enum LocalControllerCmd {
    /// A majority of voters is lost for good: make this stopped controller
    /// the only voter of a new cluster that continues from its log. Run it
    /// on the survivor with the highest `applied` index; the others stay as
    /// learners and are promoted again. Never start a lost voter again
    /// without wiping it.
    ForceNewCluster {
        /// Why (kept in the operation log).
        #[arg(long)]
        reason: String,
        /// Start the new cluster's tree versions above this one: the
        /// highest `tree_version` any node shows (`webjetctl local status`).
        /// This node's own is always included.
        #[arg(long)]
        min_version: Option<u64>,
        #[arg(short, long, env = "WEBJET_CONFIG")]
        config: Option<PathBuf>,
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// No controller survives: install a snapshot from `webjetctl network
    /// controller snapshot` on this stopped node (enrolled before the
    /// snapshot was taken, for example a relay) and make it the only voter.
    /// It gets the control role if it lacked it.
    Restore {
        /// The encrypted snapshot file.
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        reason: String,
        /// As for force-new-cluster; at least the snapshot's own index.
        #[arg(long)]
        min_version: Option<u64>,
        /// Set aside controller state this node already holds.
        #[arg(long)]
        replace: bool,
        #[arg(short, long, env = "WEBJET_CONFIG")]
        config: Option<PathBuf>,
        #[arg(long)]
        data_dir: Option<PathBuf>,
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
    let Ok(accts) = call(cli, Request::Accounts).await else {
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
    let r = call(cli, Request::CertRequest { node }).await?;
    webjetd::state::unb64(r["request"].as_str().unwrap_or(""))
}

async fn call(cli: &Cli, req: Request) -> Result<Value> {
    // Agents before 0.7 printed ids as `{"b0": …}` word structs.
    Ok(legacy_ids(client::call(&cli.socket, &req).await?))
}

async fn submit(cli: &Cli, signed: Vec<u8>) -> Result<Value> {
    call(cli, Request::SubmitOp { signed }).await
}

async fn nodes(cli: &Cli) -> Result<Vec<Value>> {
    Ok(call(cli, Request::Nodes)
        .await?
        .as_array()
        .cloned()
        .unwrap_or_default())
}

/// A node by name, `name.<suffix>`, hex id (or a unique prefix of it) or key.
async fn node_id(cli: &Cli, name: &str) -> Result<Bytes32> {
    let suffix = call(cli, Request::Status)
        .await
        .ok()
        .and_then(|s| s["dns_suffix"].as_str().map(String::from));
    webjet_tools::find_id(&nodes(cli).await?, name, suffix.as_deref(), "node", |_| {
        false
    })
}

/// Node names by hex id, to label ids in JSON answers.
async fn node_names(cli: &Cli) -> Result<HashMap<String, String>> {
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
async fn account_id(cli: &Cli, name: &str) -> Result<Bytes32> {
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

/// The result of a command: a sentence for people, an object with `--json`.
fn report(cli: &Cli, text: impl std::fmt::Display, v: Value) {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    } else {
        println!("{text}");
    }
}

/// The log entry index a submit reply names.
fn entry(r: &Value) -> Value {
    r["index"].clone()
}

fn print_table(rows: &[Vec<String>]) {
    if rows.is_empty() {
        return;
    }
    let cols = rows[0].len();
    let w: Vec<usize> = (0..cols)
        .map(|c| {
            rows.iter()
                .map(|r| r.get(c).map_or(0, |s| s.len()))
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
    call(cli, Request::Tree).await
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

/// `network config apply`: the file's sections over the configuration in
/// force, as the next version. In refuse mode the network keeps its
/// camouflage certificate; a network without one gets a self-signed one,
/// whose key is stored with the controllers first so relays can serve it.
async fn apply_network(cli: &Cli, f: &ConfigFile, base: &Path, what: Option<&str>) -> Result<()> {
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
            let f = config::edit_doc(&cur, |d| config::set(d, key, config::parse_value(value)))?;
            apply_network(cli, &f, Path::new("."), Some(&format!("{key} = {value}"))).await?;
        }
        ConfigCmd::Unset { key } => {
            let t = tree(cli).await?;
            let cur = network_from_tree(&t, false)?;
            let mut f = config::edit_doc(&cur, |d| config::unset(d, key))?;
            // A section left out stays as it is: unsetting the last key of
            // [controllers] (or all of it) means the built-in values.
            if f.controllers.is_none() && cur.controllers.is_some() {
                f.controllers = Some(Default::default());
            }
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
async fn apply_node(cli: &Cli, n: &NodeConf, f: &ConfigFile) -> Result<()> {
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
            let s = call(cli, Request::Status).await?;
            print(cli, &s);
        }
        LocalCmd::Peers => {
            let v = call(cli, Request::Peers).await?;
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
        LocalCmd::Sessions => print(cli, &call(cli, Request::Sessions).await?),
        LocalCmd::Conntrack => print(cli, &call(cli, Request::Conntrack).await?),
        LocalCmd::Proxy => print(cli, &call(cli, Request::Proxy).await?),
        LocalCmd::Topology => print(cli, &call(cli, Request::Topology).await?),
        LocalCmd::Ping {
            target,
            count,
            size,
        } => {
            // Names, ids and id prefixes are resolved here; addresses and
            // magic DNS names go to the agent as they are.
            let to = if target.parse::<std::net::IpAddr>().is_ok() {
                target.clone()
            } else {
                match node_id(cli, target).await {
                    // By address: every agent version takes that.
                    Ok(id) => nodes(cli)
                        .await?
                        .iter()
                        .find(|n| n["id"].as_str() == Some(&hex::encode(id)))
                        .and_then(|n| n["ips"][0].as_str())
                        .and_then(|ip| ip.split('/').next())
                        .map_or_else(|| target.clone(), String::from),
                    Err(_) => target.clone(),
                }
            };
            let v = call(
                cli,
                Request::Ping {
                    target: to,
                    count: Some(u64::from(*count)),
                    size: Some(u64::from(*size)),
                },
            )
            .await?;
            let replies = v["replies"].as_array().cloned().unwrap_or_default();
            let ok = replies.iter().filter(|r| r.is_number()).count();
            if cli.json {
                print(cli, &v);
            } else {
                for (i, r) in replies.iter().enumerate() {
                    match r.as_f64() {
                        Some(ms) => println!(
                            "reply from {}: seq={i} time={ms:.2} ms",
                            v["target"].as_str().unwrap_or("")
                        ),
                        None => println!("seq={i}: timeout"),
                    }
                }
            }
            if ok == 0 {
                bail!("no reply from {target}");
            }
        }
        LocalCmd::Metrics { all } => {
            let v = call(cli, Request::Metrics { all: *all }).await?;
            if cli.json {
                print(cli, &v);
            } else {
                print!("{}", v["openmetrics"].as_str().unwrap_or(""));
            }
        }
        LocalCmd::Inject { file } => {
            let raw = read(file)?;
            eprintln!("{}", describe(&raw));
            let r = call(cli, Request::SubmitSigned { signed: raw }).await?;
            print(cli, &r);
        }
        LocalCmd::Config { node, cmd } => local_config(cli, node.as_deref(), cmd).await?,
        LocalCmd::Controller { cmd } => local_controller(cli, cmd).await?,
    }
    Ok(())
}

async fn local_controller(cli: &Cli, cmd: &LocalControllerCmd) -> Result<()> {
    use webjetd::controller::recovery;
    let (r, what) = match cmd {
        LocalControllerCmd::ForceNewCluster {
            reason,
            min_version,
            config,
            data_dir,
        } => {
            let cfg = agent_config(config.as_deref(), data_dir.clone())?;
            recovery::ensure_stopped(&cfg).await?;
            (
                recovery::force_new_cluster(&cfg, *min_version, reason)?,
                "this controller is now the only voter of a new cluster",
            )
        }
        LocalControllerCmd::Restore {
            from,
            reason,
            min_version,
            replace,
            config,
            data_dir,
        } => {
            let cfg = agent_config(config.as_deref(), data_dir.clone())?;
            recovery::ensure_stopped(&cfg).await?;
            let pass = passphrase("WEBJET_BACKUP_PASSPHRASE", "snapshot passphrase")?;
            let snap = unseal(&pass, &read(from)?)?;
            (
                recovery::restore(&cfg, &snap, *min_version, *replace, reason)?,
                "restored the controller state; this node is the only voter of a new cluster",
            )
        }
    };
    report(
        cli,
        format!(
            "{what} (first entry {}, term {}{}{}).\nStart the agent, certify the controller's signing key if it has none (ops guide 2.4), and retire the lost controllers' keys (ops guide 2.9).",
            r.index,
            r.term,
            if r.jumped {
                ", above the versions nodes hold"
            } else {
                ""
            },
            if r.learners.is_empty() {
                String::new()
            } else {
                format!(", {} learners kept", r.learners.len())
            }
        ),
        serde_json::to_value(&r)?,
    );
    Ok(())
}

async fn network(cli: &Cli, cmd: &NetworkCmd) -> Result<()> {
    match cmd {
        NetworkCmd::Account { cmd } => network_account(cli, cmd).await?,
        NetworkCmd::Node { cmd } => network_node(cli, cmd).await?,
        NetworkCmd::Psk {
            cmd: PskCmd::Rotate,
        } => {
            let a = load_account(cli).await?;
            let st = call(cli, Request::Status).await?;
            let cur = st["psk_epoch"].as_u64().unwrap_or(0) as u16;
            let r = submit(
                cli,
                a.sign(AccountOp::RotatePsk(Box::new(wp::RotatePsk {
                    epoch_id: cur.wrapping_add(1),
                })))?,
            )
            .await?;
            report(
                cli,
                format!(
                    "PSK rotated to epoch {} (entry {})",
                    cur.wrapping_add(1),
                    r["index"]
                ),
                json!({"psk_epoch": cur.wrapping_add(1), "entry": entry(&r)}),
            );
        }
        NetworkCmd::Camouflage { cmd } => network_camouflage(cli, cmd).await?,
        NetworkCmd::Controller { cmd } => network_controller(cli, cmd).await?,
        NetworkCmd::Submit { file } => {
            let raw = read(file)?;
            eprintln!("{}", describe(&raw));
            let r = call(cli, Request::SubmitSigned { signed: raw }).await?;
            print(cli, &r);
        }
        NetworkCmd::Config { cmd } => network_config(cli, cmd).await?,
    }
    Ok(())
}

/// `webjetctl network account …`: account keys and records.
async fn network_account(cli: &Cli, cmd: &AccountCmd) -> Result<()> {
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
            report(
                cli,
                format!(
                    "account {name} has a new key (entry {}); the old key no longer signs. {} now carries the account's ID",
                    r["index"],
                    key.display()
                ),
                json!({"account": name, "account_id": hex::encode(id), "key": p.key, "rekeyed": true, "entry": entry(&r)}),
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

/// `webjetctl network node …`: enrollment and node records.
async fn network_node(cli: &Cli, cmd: &NodeCmd) -> Result<()> {
    match cmd {
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
            let t = ticket(cli, &token, controller).await?;
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
            let r = submit(
                cli,
                a.sign(AccountOp::RenameNode(Box::new(wp::RenameNode {
                    node_id: Some(crypto::k32(&id)),
                    name: Some(new_name.clone()),
                })))?,
            )
            .await?;
            report(
                cli,
                format!("{name} is now {new_name} (entry {})", r["index"]),
                json!({"node": new_name, "old_name": name, "node_id": hex::encode(id), "entry": entry(&r)}),
            );
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
            let op = wp::RekeyNode {
                node_id: Some(crypto::k32(&id)),
                token_hash: Some(crypto::k32(&crypto::token_hash(&token))),
                expires_at: now_ms() + expires_hours * 3_600_000,
                revoke_old_now: *revoke_old_now,
            };
            let r = submit(cli, a.sign(AccountOp::RekeyNode(Box::new(op)))?).await?;
            let t = ticket(cli, &token, controller).await?;
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

/// `webjetctl network camouflage …`: the AnyTLS camouflage secret and certificate.
async fn network_camouflage(cli: &Cli, cmd: &CamouflageCmd) -> Result<()> {
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
            write_private(key_out, &key)?;
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
async fn network_controller(cli: &Cli, cmd: &ControllerCmd) -> Result<()> {
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
            let req = a.kp.sign_obj(
                wp::msg_type::SNAPSHOT_REQUEST,
                &wp::SnapshotRequest {
                    account_id: Some(crypto::k32(&a.id)),
                    issued_at: now_ms(),
                },
            );
            let r = call(cli, Request::Snapshot { request: req }).await?;
            let snap = webjetd::state::unb64(r["snapshot"].as_str().unwrap_or(""))?;
            let pass = new_passphrase("WEBJET_BACKUP_PASSPHRASE", "passphrase for the snapshot")?;
            write_private(out, &seal(&pass, &snap)?)?;
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
