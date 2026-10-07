//! The command line: every command, subcommand and flag.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "webjetctl", version, about = "Webjet administration")]
pub(crate) struct Cli {
    /// webjetd's control socket.
    #[arg(
        long,
        global = true,
        env = "WEBJET_SOCKET",
        default_value_os_t = webjetd::ipc::default_control()
    )]
    pub(crate) socket: PathBuf,
    /// Directory with account keys.
    #[arg(long, global = true, env = "WEBJET_KEYS")]
    pub(crate) keys: Option<PathBuf>,
    /// The account to sign with. Defaults to the one chosen with
    /// `network account use`, else the only key in the key directory.
    #[arg(long, global = true, env = "WEBJET_ACCOUNT")]
    pub(crate) account: Option<String>,
    /// Print raw JSON.
    #[arg(long, global = true)]
    pub(crate) json: bool,
    #[command(subcommand)]
    pub(crate) cmd: Cmd,
}

#[derive(Subcommand)]
pub(crate) enum Cmd {
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
pub(crate) enum NetworkCmd {
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
pub(crate) enum LocalCmd {
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
pub(crate) enum ConfigCmd {
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

#[derive(Subcommand)]
pub(crate) enum AccountCmd {
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
pub(crate) enum NodeCmd {
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
    /// Upgrade nodes to a release remotely (ops guide 3.3, architecture
    /// §19.8). Pins the release's published checksums, signs a request for
    /// each node, and rolls out in order: controllers one at a time (the
    /// leader last), then relays, then the other nodes in batches, waiting
    /// for each to run the new version. Stops at the first failure. Nodes
    /// need the helper `webjetup` installs (on unless
    /// `--no-remote-upgrade`); a node whose new agent doesn't come up puts
    /// the previous version back by itself.
    Upgrade {
        /// The release tag, e.g. v0.9.0. Only upgrades: nodes refuse older
        /// or equal versions.
        version: String,
        /// The nodes: names, node ids in hex (or unique prefixes) or keys.
        nodes: Vec<String>,
        /// Also every node with one of these tags.
        #[arg(long, value_delimiter = ',')]
        tag: Vec<String>,
        /// Every node of the network.
        #[arg(long, conflicts_with_all = ["nodes", "tag"])]
        all: bool,
        /// Nodes upgraded at once after the controllers.
        #[arg(long, default_value_t = 5)]
        batch: usize,
        /// The repository the release's checksums come from (the nodes
        /// download from the one webjetup was installed with).
        #[arg(long, env = "WEBJETUP_REPO", default_value = webjet_release::http::DEFAULT_REPO)]
        repo: String,
        /// How long one stage may take before the rollout stops.
        #[arg(long, default_value_t = 15)]
        timeout_minutes: u64,
        /// Show the order and stop.
        #[arg(long)]
        dry_run: bool,
        /// Don't ask for confirmation.
        #[arg(short, long)]
        yes: bool,
    },
    /// Nodes' versions and remote upgrade state (default: this node).
    UpgradeStatus {
        /// The nodes: names, node ids in hex (or unique prefixes) or keys.
        nodes: Vec<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum PskCmd {
    Rotate,
}

#[derive(Subcommand)]
pub(crate) enum CamouflageCmd {
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
pub(crate) enum ControllerCmd {
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
pub(crate) enum LocalControllerCmd {
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
