//! What the app shows, decoded from the agent's control channel, and what
//! the signed-in account may do. No GUI code: everything here is tested
//! headless.

use serde::Deserialize;
use serde_json::Value;

/// A node as listed by the agent (`nodes` on the control channel).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub key: String,
    pub ips: Vec<String>,
    pub tags: Vec<String>,
    /// The owner account's name (or id when the account is unknown).
    pub owner: String,
    pub owner_id: String,
    pub relay: bool,
    pub data: bool,
    /// CONTROL in effect (role held and the signing key certified).
    pub control: bool,
    /// The `control` role is granted, certified or not.
    pub control_role: bool,
    pub routes: Vec<String>,
    pub valid: bool,
    pub version: u64,
}

impl Node {
    pub fn roles(&self) -> String {
        let mut r = Vec::new();
        if self.data {
            r.push("data");
        }
        if self.relay {
            r.push("relay");
        }
        if self.control {
            r.push("control");
        } else if self.control_role {
            r.push("control (key not certified)");
        }
        r.join(", ")
    }

    /// Case-insensitive match on name, address, tag, owner or role.
    pub fn matches(&self, filter: &str) -> bool {
        let f = filter.trim().to_ascii_lowercase();
        if f.is_empty() {
            return true;
        }
        self.name.to_ascii_lowercase().contains(&f)
            || self.owner.to_ascii_lowercase().contains(&f)
            || self.ips.iter().any(|i| i.contains(&f))
            || self
                .tags
                .iter()
                .any(|t| t.to_ascii_lowercase().contains(&f))
            || self.roles().contains(&f)
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Account {
    pub id: String,
    pub name: String,
    pub admin: bool,
    pub valid: bool,
    pub key: String,
    pub version: u64,
}

/// A hop session of the local agent (`peers`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Peer {
    pub peer: String,
    pub id: String,
    pub transport: String,
    pub remote: String,
    pub outbound: bool,
    pub rtt_ms: f64,
    pub min_rtt_ms: f64,
    pub jitter_ms: f64,
    pub loss: f64,
    pub cost: Option<f64>,
    pub age_s: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// An end-to-end session with another node (`sessions`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct E2eSession {
    pub peer: String,
    pub peer_id: String,
    pub established: bool,
    pub handshaking: bool,
    pub key_age_s: Option<u64>,
    pub queued: u64,
    /// The label of the circuit the session sends on.
    pub primary_circuit: Option<u32>,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub path_switches: u64,
}

/// A circuit ending at this node (§11.5).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Circuit {
    pub peer: String,
    pub peer_id: String,
    /// This node's label for frames arriving on the circuit.
    pub label: u32,
    /// The neighbor frames go to first.
    pub next: String,
    /// The relays in between (empty: direct).
    pub hops: Vec<String>,
    pub hop_ids: Vec<String>,
    pub direct: bool,
    /// This node opened it.
    pub source: bool,
    pub open: bool,
    /// The session with the peer currently sends on it.
    pub primary: bool,
    pub rtt_ms: f64,
    pub loss: f64,
    pub probes: u64,
    pub age_s: u64,
    pub route_id: String,
}

impl Circuit {
    /// "node-02 → relay-a → node-03" from this node's point of view.
    pub fn path_text(&self, me: &str) -> String {
        std::iter::once(me)
            .chain(self.hops.iter().map(String::as_str))
            .chain(std::iter::once(self.peer.as_str()))
            .collect::<Vec<_>>()
            .join(" → ")
    }

    /// Node ids along the circuit, starting at `me`.
    pub fn path_ids(&self, me: &str) -> Vec<String> {
        std::iter::once(me.to_string())
            .chain(self.hop_ids.iter().cloned())
            .chain(std::iter::once(self.peer_id.clone()))
            .collect()
    }
}

/// Traffic accounting of a route this node carries (§12.3).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Route {
    pub route_id: String,
    /// `source`, `destination` or `transit`.
    pub role: String,
    pub src: String,
    pub dst: String,
    pub path: Vec<String>,
    pub path_ids: Vec<String>,
    pub fwd_bytes: u64,
    pub fwd_frames: u64,
    pub rev_bytes: u64,
    pub rev_frames: u64,
    pub dropped_queue: u64,
    pub dropped_hop_limit: u64,
    pub ecn_marked: u64,
    pub setups: u64,
    pub circuits: u64,
    pub active_since: u64,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Circuits {
    pub local: Vec<Circuit>,
    pub routes: Vec<Route>,
    /// Circuits passing through this node as a relay.
    pub transit: u64,
    /// Refused circuit setups by reason.
    pub refused: std::collections::BTreeMap<String, u64>,
}

/// `sessions`: end-to-end sessions and circuits.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Sessions {
    pub sessions: Vec<E2eSession>,
    pub circuits: Circuits,
}

impl Sessions {
    pub fn route(&self, id: &str) -> Option<&Route> {
        self.circuits.routes.iter().find(|r| r.route_id == id)
    }
}

/// The circuit a tracked flow's traffic takes.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct FlowCircuit {
    pub label: u32,
    pub direct: bool,
    pub hops: Vec<String>,
    pub rtt_ms: f64,
}

impl FlowCircuit {
    pub fn text(&self) -> String {
        if self.direct {
            "direct".into()
        } else {
            format!("via {}", self.hops.join(" → "))
        }
    }
}

/// A tracked flow (`conntrack`, §14.4).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Flow {
    pub peer: String,
    pub peer_id: String,
    pub proto: String,
    pub src: String,
    pub sport: u16,
    pub dst: String,
    pub dport: u16,
    pub state: String,
    /// This node started it.
    pub outbound: bool,
    pub replied: bool,
    /// Through this node as a gateway to a LAN.
    pub gateway: bool,
    pub rule: Option<String>,
    pub idle_s: u64,
    pub expires_s: u64,
    pub circuit: Option<FlowCircuit>,
}

impl Flow {
    fn endpoint(addr: &str, port: u16, proto: &str) -> String {
        let a = if addr.contains(':') {
            format!("[{addr}]")
        } else {
            addr.to_string()
        };
        if proto.starts_with("icmp") {
            a
        } else {
            format!("{a}:{port}")
        }
    }

    pub fn from_text(&self) -> String {
        Self::endpoint(&self.src, self.sport, &self.proto)
    }

    pub fn to_text(&self) -> String {
        Self::endpoint(&self.dst, self.dport, &self.proto)
    }

    pub fn circuit_text(&self) -> String {
        self.circuit
            .as_ref()
            .map(FlowCircuit::text)
            .unwrap_or_else(|| "—".into())
    }

    /// Case-insensitive match on peer, addresses, ports, protocol, state,
    /// rule or circuit.
    pub fn matches(&self, filter: &str) -> bool {
        let f = filter.trim().to_ascii_lowercase();
        if f.is_empty() {
            return true;
        }
        [
            self.peer.clone(),
            self.from_text(),
            self.to_text(),
            self.proto.clone(),
            self.state.clone(),
            self.rule.clone().unwrap_or_default(),
            self.circuit_text(),
            if self.outbound { "out" } else { "in" }.to_string(),
        ]
        .iter()
        .any(|s| s.to_ascii_lowercase().contains(&f))
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct ConntrackLimits {
    pub per_peer: u64,
    pub new_per_sec: u64,
    pub global: u64,
    pub evictions: u64,
}

/// `conntrack`: the tracked flows.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Conntrack {
    /// The data plane runs (it may still be starting).
    pub running: bool,
    pub total: u64,
    pub live: u64,
    pub gateway: u64,
    /// More flows than the agent lists.
    pub truncated: bool,
    pub limits: ConntrackLimits,
    pub flows: Vec<Flow>,
}

/// A reverse proxy rule of this node with its status (`proxy`, §11.11).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct ProxyRule {
    pub name: String,
    pub protocol: String,
    pub listen_port: u16,
    pub target: Vec<String>,
    pub target_port: u16,
    pub real_ip: bool,
    pub status: String,
    pub warnings: Vec<String>,
}

impl ProxyRule {
    pub fn text(&self) -> String {
        format!(
            "{} :{} → {} :{}",
            self.protocol,
            self.listen_port,
            self.target.join(", "),
            self.target_port
        )
    }
}

/// A reverse proxy flow, on the listening node (`ingress`) or a target.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct ProxyFlow {
    pub side: String,
    pub rule: String,
    /// The node that listens (owns the rule).
    pub node: String,
    /// The other end: the target node (ingress) or the ingress (target).
    pub peer: String,
    pub peer_id: String,
    pub proto: String,
    /// The client's address and port.
    pub client: String,
    /// Ingress: the port the client connected to.
    pub listen_port: Option<u16>,
    /// Ingress: the translated source, when the client's address isn't kept.
    pub source: Option<String>,
    pub target: String,
    /// Target: to a LAN host behind this gateway.
    pub gateway: bool,
    pub state: String,
    pub replied: bool,
    pub idle_s: u64,
    pub expires_s: u64,
}

impl ProxyFlow {
    pub fn ingress(&self) -> bool {
        self.side == "ingress"
    }

    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.side, self.peer_id, self.proto, self.client, self.target
        )
    }

    pub fn matches(&self, filter: &str) -> bool {
        let f = filter.trim().to_ascii_lowercase();
        if f.is_empty() {
            return true;
        }
        [
            &self.side,
            &self.rule,
            &self.node,
            &self.peer,
            &self.proto,
            &self.client,
            &self.target,
            &self.state,
            self.source.as_deref().unwrap_or(""),
        ]
        .iter()
        .any(|s| s.to_ascii_lowercase().contains(&f))
    }
}

/// Traffic of one rule on one side.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct ProxyCounter {
    pub rule: String,
    pub side: String,
    pub node: String,
    pub flows: u64,
    pub active: u64,
    pub to_target_packets: u64,
    pub to_target_bytes: u64,
    pub to_client_packets: u64,
    pub to_client_bytes: u64,
    pub refused: u64,
}

/// `proxy`: reverse proxy rules, flows and counters, apart from `conntrack`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Proxy {
    pub running: bool,
    pub accept_real_ip: bool,
    pub real_ip_ready: bool,
    /// The proxy addresses the listen ports are captured to.
    pub addresses: Vec<String>,
    pub rules: Vec<ProxyRule>,
    pub total: u64,
    pub live: u64,
    pub truncated: bool,
    pub flows: Vec<ProxyFlow>,
    pub counters: Vec<ProxyCounter>,
}

/// A relay's load figures from its LinkStateAdvert (§11.8.1).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Load {
    pub util_pct: u8,
    pub cpu_pct: u8,
    pub circuits_pct: u8,
    pub queue_pct: u8,
    pub capacity_mbps: u32,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct TopoNode {
    pub id: String,
    pub name: String,
    pub ips: Vec<String>,
    pub relay: bool,
    pub data: bool,
    pub control: bool,
    pub me: bool,
    pub load: Option<Load>,
    /// How the node's NAT maps UDP, from its EndpointRecord (§11.7):
    /// `none`, `consistent`, `symmetric` or `unknown`; absent when this
    /// agent has no record of the node (older agents don't send it).
    pub nat: Option<String>,
    /// The addresses it advertises.
    pub endpoints: Vec<TopoAddr>,
    /// This agent's router port mapping (only on `me`).
    pub port_mapping: Option<PortMapping>,
}

/// An advertised address (§6.2).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct TopoAddr {
    pub addr: String,
    pub transport: String,
    pub kind: String,
}

/// A UDP port mapping the router gave (UPnP / NAT-PMP / PCP).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct PortMapping {
    pub external: String,
    pub protocol: String,
}

impl TopoNode {
    /// "symmetric NAT", "no NAT", …, for people.
    pub fn nat_text(&self) -> Option<String> {
        let t = self.nat.as_deref()?;
        Some(match t {
            "none" => "no NAT (public address)".into(),
            "consistent" => "consistent NAT (hole punching works)".into(),
            "symmetric" => "symmetric NAT (punching only toward non-symmetric peers)".into(),
            _ => "unknown (fewer than two relays measured it)".into(),
        })
    }

    /// Advertised addresses grouped by kind: "public 1.2.3.4:443 (kcp, tls) · …".
    pub fn endpoints_text(&self) -> String {
        let mut groups: Vec<(String, Vec<String>)> = Vec::new();
        for kind in ["public", "reflexive", "host"] {
            let mut addrs: Vec<(String, Vec<String>)> = Vec::new();
            for e in self.endpoints.iter().filter(|e| e.kind == kind) {
                match addrs.iter_mut().find(|(a, _)| *a == e.addr) {
                    Some((_, ts)) => ts.push(e.transport.clone()),
                    None => addrs.push((e.addr.clone(), vec![e.transport.clone()])),
                }
            }
            if !addrs.is_empty() {
                groups.push((
                    kind.to_string(),
                    addrs
                        .into_iter()
                        .map(|(a, ts)| format!("{a} ({})", ts.join(", ")))
                        .collect(),
                ));
            }
        }
        if groups.is_empty() {
            return "—".into();
        }
        groups
            .into_iter()
            .map(|(k, v)| format!("{k} {}", v.join(", ")))
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

/// A link between two nodes as reported by one of them (`topology`):
/// `relay` (a relay's LinkStateAdvert), `attachment` (an edge node to its
/// home relay) or `hop` (measured by this agent).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct TopoEdge {
    pub a: String,
    pub b: String,
    pub kind: String,
    pub transport: String,
    pub rtt_ms: f64,
    pub loss: f64,
    pub util_pct: Option<u8>,
    pub remote: Option<String>,
    pub outbound: Option<bool>,
    pub tx_bytes: Option<u64>,
    pub rx_bytes: Option<u64>,
    pub age_s: u64,
}

/// `topology`: the network graph as this agent knows it.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Topology {
    pub me: String,
    pub nodes: Vec<TopoNode>,
    pub edges: Vec<TopoEdge>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Alarm {
    pub name: String,
    pub severity: String,
    pub since: u64,
}

/// The local agent's status (`status`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Status {
    pub node_id: String,
    pub name: Option<String>,
    pub ips: Option<Vec<String>>,
    pub valid: bool,
    pub tree_version: Option<u64>,
    pub tree_root: Option<String>,
    pub head_expires: Option<u64>,
    pub valid_until: u64,
    pub nodes: u64,
    pub controllers: u64,
    pub psk_epoch: u64,
    pub peers: u64,
    pub sessions: u64,
    pub alarms: Vec<Alarm>,
    pub uptime_s: u64,
    pub version: String,
    /// This agent's controller status, when it runs the controller role.
    pub controller: Option<Value>,
    /// Compression in force and its counters (agents from 0.6.0 on).
    pub compression: Option<Compression>,
}

/// Compression on the local agent (§9.8), per plane.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Compression {
    pub control: CompressionPlane,
    pub data: CompressionPlane,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct CompressionPlane {
    /// `zstd`, `lz4` or `off`.
    pub algorithm: String,
    pub tx_raw_bytes: u64,
    pub tx_wire_bytes: u64,
    pub rx_raw_bytes: u64,
    pub rx_wire_bytes: u64,
}

impl CompressionPlane {
    /// The algorithm and, once something was compressed, the bytes saved.
    pub fn summary(&self) -> String {
        let raw = self.tx_raw_bytes + self.rx_raw_bytes;
        let wire = self.tx_wire_bytes + self.rx_wire_bytes;
        if raw == 0 || wire >= raw {
            return self.algorithm.clone();
        }
        format!(
            "{} · {:.0}% smaller ({} saved)",
            self.algorithm,
            (raw - wire) as f64 * 100.0 / raw as f64,
            bytes(raw - wire)
        )
    }
}

/// Network-wide settings (`tree`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Tree {
    /// The network configuration's version in force.
    pub network_version: u64,
    pub policy_version: u64,
    pub valid_until: u64,
    pub overlay_pool: Vec<String>,
    pub dns: Option<Value>,
    pub seeds: Option<Value>,
    pub limits: Option<Value>,
    pub transport: Option<Value>,
}

/// Everything one refresh fetches. The parts after `tree` come from
/// commands an older agent may not know; they are `Err` with the reason then.
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    pub status: Status,
    pub nodes: Vec<Node>,
    pub accounts: Vec<Account>,
    pub peers: Vec<Peer>,
    pub tree: Tree,
    pub sessions: Result<Sessions, String>,
    pub conntrack: Result<Conntrack, String>,
    /// Reverse proxy ports and flows (kept apart from `conntrack`).
    pub proxy: Result<Proxy, String>,
    pub topology: Result<Topology, String>,
    /// OpenMetrics text: this node's, or every node's on a controller when asked.
    pub metrics: Result<String, String>,
    /// `metrics` holds every node's latest report.
    pub metrics_all: bool,
    /// The state tree (`merkle`), fetched only while the Merkle tab is
    /// shown; `None` when not fetched this time.
    pub merkle: Option<Result<crate::merkle::MerkleWire, String>>,
}

impl Default for Snapshot {
    fn default() -> Self {
        fn none<T>() -> Result<T, String> {
            Err("not loaded".to_string())
        }
        Snapshot {
            status: Status::default(),
            nodes: Vec::new(),
            accounts: Vec::new(),
            peers: Vec::new(),
            tree: Tree::default(),
            sessions: none(),
            conntrack: none(),
            proxy: none(),
            topology: none(),
            metrics: none(),
            metrics_all: false,
            merkle: None,
        }
    }
}

impl Snapshot {
    pub fn account(&self, id: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.id == id)
    }

    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Valid nodes an account owns.
    pub fn owned_by(&self, account_id: &str) -> Vec<&Node> {
        self.nodes
            .iter()
            .filter(|n| n.owner_id == account_id && n.valid)
            .collect()
    }

    /// This agent runs the controller role.
    pub fn is_controller(&self) -> bool {
        self.status
            .controller
            .as_ref()
            .is_some_and(|c| !c.is_null())
    }

    pub fn me(&self) -> &str {
        &self.status.node_id
    }

    /// The headline numbers for the dashboard.
    pub fn summary(&self) -> Summary {
        let valid: Vec<&Node> = self.nodes.iter().filter(|n| n.valid).collect();
        let sessions = self.sessions.as_ref().ok();
        let ct = self.conntrack.as_ref().ok();
        Summary {
            nodes_active: valid.len(),
            nodes_total: self.nodes.len(),
            relays: valid.iter().filter(|n| n.relay).count(),
            controllers: valid.iter().filter(|n| n.control).count(),
            gateways: valid.iter().filter(|n| !n.routes.is_empty()).count(),
            accounts_active: self.accounts.iter().filter(|a| a.valid).count(),
            admins: self.accounts.iter().filter(|a| a.valid && a.admin).count(),
            hops: self.peers.len(),
            sessions_established: sessions
                .map(|s| s.sessions.iter().filter(|x| x.established).count())
                .unwrap_or(0),
            sessions_total: sessions.map(|s| s.sessions.len()).unwrap_or(0),
            circuits: sessions.map(|s| s.circuits.local.len()).unwrap_or(0),
            circuits_direct: sessions
                .map(|s| s.circuits.local.iter().filter(|c| c.direct).count())
                .unwrap_or(0),
            transit: sessions.map(|s| s.circuits.transit).unwrap_or(0),
            flows: ct.map(|c| c.live).unwrap_or(0),
            flows_gateway: ct.map(|c| c.gateway).unwrap_or(0),
            tx_bytes: self.peers.iter().map(|p| p.tx_bytes).sum(),
            rx_bytes: self.peers.iter().map(|p| p.rx_bytes).sum(),
            alarms: self.status.alarms.len(),
            critical_alarms: self
                .status
                .alarms
                .iter()
                .filter(|a| a.severity == "critical")
                .count(),
        }
    }
}

/// Headline numbers of a snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub nodes_active: usize,
    pub nodes_total: usize,
    pub relays: usize,
    pub controllers: usize,
    pub gateways: usize,
    pub accounts_active: usize,
    pub admins: usize,
    pub hops: usize,
    pub sessions_established: usize,
    pub sessions_total: usize,
    pub circuits: usize,
    pub circuits_direct: usize,
    pub transit: u64,
    pub flows: u64,
    pub flows_gateway: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub alarms: usize,
    pub critical_alarms: usize,
}

// ---------------------------------------------------------------- dashboard

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warn,
    Bad,
}

/// How the network looks from this agent, with the reasons.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    pub level: Level,
    pub reasons: Vec<String>,
}

impl Health {
    pub fn title(&self) -> &'static str {
        match self.level {
            Level::Ok => "Healthy",
            Level::Warn => "Needs attention",
            Level::Bad => "Problem",
        }
    }
}

const WEEK_MS: u64 = 7 * 86_400_000;

/// Judge a snapshot: the agent's own record, the tree head and validity
/// horizon, alarms and connectivity.
pub fn health(s: &Snapshot, now_ms: u64) -> Health {
    let mut r: Vec<(Level, String)> = Vec::new();
    let st = &s.status;
    if !st.valid {
        r.push((Level::Bad, "this agent's node record isn't valid".into()));
    }
    match (st.tree_version, st.head_expires) {
        (None, _) => r.push((Level::Warn, "no signed tree head yet".into())),
        (Some(_), Some(e)) if e < now_ms => r.push((
            Level::Bad,
            format!("the tree head expired {}", relative(e, now_ms)),
        )),
        _ => {}
    }
    let vu = s.tree.valid_until.max(st.valid_until);
    if vu > 0 && vu < now_ms {
        r.push((
            Level::Bad,
            "the network's validity horizon has passed".into(),
        ));
    } else if vu > 0 && vu < now_ms + WEEK_MS {
        r.push((
            Level::Warn,
            format!("the network's validity ends {}", relative(vu, now_ms)),
        ));
    }
    for a in &st.alarms {
        let l = if a.severity == "critical" {
            Level::Bad
        } else {
            Level::Warn
        };
        r.push((l, format!("alarm {} ({})", a.name, a.severity)));
    }
    if s.peers.is_empty() && s.nodes.iter().filter(|n| n.valid).count() > 1 {
        r.push((
            Level::Warn,
            "no hop sessions: not connected to any other node".into(),
        ));
    }
    let level = r.iter().map(|(l, _)| *l).max().unwrap_or(Level::Ok);
    r.sort_by_key(|x| std::cmp::Reverse(x.0));
    Health {
        level,
        reasons: r.into_iter().map(|(_, t)| t).collect(),
    }
}

/// Byte counters over time, for throughput on the dashboard.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Traffic {
    /// (Unix ms, bytes sent, bytes received) per refresh.
    samples: std::collections::VecDeque<(u64, u64, u64)>,
}

impl Traffic {
    /// Samples kept: five minutes at one refresh every 2 s.
    pub const KEEP: usize = 151;

    pub fn push(&mut self, ms: u64, tx: u64, rx: u64) {
        if self.samples.back().is_some_and(|(t, _, _)| *t >= ms) {
            return;
        }
        self.samples.push_back((ms, tx, rx));
        while self.samples.len() > Self::KEEP {
            self.samples.pop_front();
        }
    }

    /// Bytes per second (sent, received) for each interval. A counter that
    /// went down (a hop closed) counts as no traffic for that interval.
    pub fn rates(&self) -> Vec<(f64, f64)> {
        self.samples
            .iter()
            .zip(self.samples.iter().skip(1))
            .map(|(a, b)| {
                let dt = (b.0 - a.0) as f64 / 1000.0;
                (
                    b.1.saturating_sub(a.1) as f64 / dt,
                    b.2.saturating_sub(a.2) as f64 / dt,
                )
            })
            .collect()
    }

    pub fn last(&self) -> Option<(f64, f64)> {
        self.rates().last().copied()
    }
}

// ---------------------------------------------------------------- permissions

/// What the signed-in account may do, decided from its record in the
/// network (§13.2). The controllers enforce the same rules; the app only
/// avoids offering actions that would be refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Admin account: every operation.
    Admin,
    /// Normal account: read-only, plus rename and revoke of its own nodes.
    Member,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    RenameNode,
    RevokeNode,
    UpdateNode,
    EnrollNode,
    RotatePsk,
    RevokeAccount,
    /// Change the network's or a node's configuration (the Config tab;
    /// admins only in the app, though controllers also let owners change
    /// their nodes' own).
    EditConfig,
}

/// The signed-in account, as found in the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub name: String,
    pub id: String,
    pub role: Role,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignInError {
    #[error("account {0} isn't in this network (it may belong to another network)")]
    Unknown(String),
    #[error("account {0} has been revoked")]
    Revoked(String),
    #[error("the account key doesn't match account {0}'s record in the network")]
    KeyMismatch(String),
}

impl Session {
    /// Check an unlocked account against the network's records.
    pub fn new(
        snapshot: &Snapshot,
        name: &str,
        id: &str,
        key: &str,
    ) -> Result<Session, SignInError> {
        let a = snapshot
            .account(id)
            .ok_or_else(|| SignInError::Unknown(name.to_string()))?;
        if !a.valid {
            return Err(SignInError::Revoked(name.to_string()));
        }
        if a.key != key {
            return Err(SignInError::KeyMismatch(name.to_string()));
        }
        Ok(Session {
            name: a.name.clone(),
            id: a.id.clone(),
            role: if a.admin { Role::Admin } else { Role::Member },
        })
    }

    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }

    /// May this account do `action` on `node` (None for network-wide actions)?
    pub fn may(&self, action: &Action, node: Option<&Node>) -> bool {
        match self.role {
            Role::Admin => true,
            Role::Member => match action {
                Action::RenameNode | Action::RevokeNode => {
                    node.is_some_and(|n| n.owner_id == self.id && n.valid)
                }
                _ => false,
            },
        }
    }
}

// ---------------------------------------------------------------- formatting

/// "3 d 4 h", "5 min", "12 s".
pub fn duration(secs: u64) -> String {
    match secs {
        s if s >= 86_400 => format!("{} d {} h", s / 86_400, (s % 86_400) / 3600),
        s if s >= 3600 => format!("{} h {} min", s / 3600, (s % 3600) / 60),
        s if s >= 60 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}

/// Time from now until `ms` (Unix ms), or how long ago it was.
pub fn relative(ms: u64, now_ms: u64) -> String {
    if ms >= now_ms {
        format!("in {}", duration((ms - now_ms) / 1000))
    } else {
        format!("{} ago", duration((now_ms - ms) / 1000))
    }
}

/// "1.5 MiB", "300 B".
pub fn bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// The first 12 hex digits of an id.
pub fn short(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

/// A node name as the network accepts it: 1–32 of `a-z`, `0-9` and `-`.
pub fn valid_node_name(s: &str) -> bool {
    webjet_core::types::valid_name(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snap() -> Snapshot {
        Snapshot {
            accounts: serde_json::from_value(json!([
                {"id": "aa", "name": "alice", "admin": true, "valid": true, "key": "KA"},
                {"id": "bb", "name": "bob", "admin": false, "valid": true, "key": "KB"},
                {"id": "cc", "name": "carol", "admin": false, "valid": false, "key": "KC"},
            ]))
            .unwrap(),
            ..Default::default()
        }
    }

    fn node(owner_id: &str) -> Node {
        Node {
            name: "laptop".into(),
            owner_id: owner_id.into(),
            valid: true,
            ..Default::default()
        }
    }

    #[test]
    fn sign_in_checks_the_network_record() {
        let s = snap();
        assert_eq!(
            Session::new(&s, "alice", "aa", "KA").unwrap().role,
            Role::Admin
        );
        assert_eq!(
            Session::new(&s, "bob", "bb", "KB").unwrap().role,
            Role::Member
        );
        assert_eq!(
            Session::new(&s, "carol", "cc", "KC"),
            Err(SignInError::Revoked("carol".into()))
        );
        assert_eq!(
            Session::new(&s, "dave", "dd", "KD"),
            Err(SignInError::Unknown("dave".into()))
        );
        assert_eq!(
            Session::new(&s, "bob", "bb", "other"),
            Err(SignInError::KeyMismatch("bob".into()))
        );
    }

    #[test]
    fn admins_may_do_everything() {
        let a = Session::new(&snap(), "alice", "aa", "KA").unwrap();
        for act in [
            Action::RenameNode,
            Action::RevokeNode,
            Action::UpdateNode,
            Action::EnrollNode,
            Action::RotatePsk,
            Action::RevokeAccount,
            Action::EditConfig,
        ] {
            assert!(a.may(&act, Some(&node("bb"))), "{act:?}");
        }
    }

    #[test]
    fn members_only_manage_their_own_live_nodes() {
        let b = Session::new(&snap(), "bob", "bb", "KB").unwrap();
        assert!(b.may(&Action::RenameNode, Some(&node("bb"))));
        assert!(b.may(&Action::RevokeNode, Some(&node("bb"))));
        assert!(
            !b.may(&Action::RenameNode, Some(&node("aa"))),
            "someone else's node"
        );
        assert!(
            !b.may(&Action::UpdateNode, Some(&node("bb"))),
            "tags/roles/IPs are admin-only"
        );
        assert!(!b.may(&Action::EnrollNode, None));
        assert!(!b.may(&Action::RotatePsk, None));
        assert!(
            !b.may(&Action::EditConfig, Some(&node("bb"))),
            "configuration is for admins, even of their own nodes"
        );
        let mut revoked = node("bb");
        revoked.valid = false;
        assert!(!b.may(&Action::RenameNode, Some(&revoked)));
    }

    #[test]
    fn decodes_agent_json() {
        let n: Node = serde_json::from_value(json!({
            "id": "0123456789abcdef", "name": "relay-fra", "ips": ["10.7.0.2/32"], "tags": ["tag:infra"],
            "owner": "infra", "owner_id": "ff", "relay": true, "data": true, "valid": true, "version": 3,
            "unknown_field": 1
        }))
        .unwrap();
        assert_eq!(n.roles(), "data, relay");
        let c = Node {
            control_role: true,
            ..n.clone()
        };
        assert_eq!(c.roles(), "data, relay, control (key not certified)");
        assert!(
            n.matches("FRA") && n.matches("10.7.0.2") && n.matches("infra") && n.matches("relay")
        );
        assert!(!n.matches("laptop"));
        let st: Status = serde_json::from_value(json!({"node_id": "ab", "tree_version": 7, "alarms": [{"name": "soft_mode", "severity": "warning", "since": 1}]})).unwrap();
        assert_eq!(st.tree_version, Some(7));
        assert_eq!(st.alarms.len(), 1);
        assert!(st.compression.is_none(), "agents before 0.6.0");
        let st: Status = serde_json::from_value(json!({"compression": {
            "control": {"algorithm": "zstd", "tx_raw_bytes": 3000, "tx_wire_bytes": 1000, "rx_raw_bytes": 1000, "rx_wire_bytes": 1000, "rx_errors": 0},
            "data": {"algorithm": "off"}
        }}))
        .unwrap();
        let c = st.compression.unwrap();
        assert_eq!(
            c.control.summary(),
            format!("zstd · 50% smaller ({} saved)", bytes(2000))
        );
        assert_eq!(c.data.summary(), "off");
    }

    #[test]
    fn formatting() {
        assert_eq!(duration(5), "5 s");
        assert_eq!(duration(3 * 3600 + 120), "3 h 2 min");
        assert_eq!(duration(2 * 86_400 + 3600), "2 d 1 h");
        assert_eq!(relative(10_000, 4_000), "in 6 s");
        assert_eq!(relative(4_000, 10_000), "6 s ago");
        assert_eq!(short("0123456789abcdef"), "0123456789ab");
        assert_eq!(short("abc"), "abc");
        assert!(valid_node_name("laptop-2") && !valid_node_name("") && !valid_node_name("Laptop"));
        assert!(!valid_node_name(&"a".repeat(33)));
        assert_eq!(bytes(300), "300 B");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn decodes_sessions_flows_and_topology() {
        let s: Sessions = serde_json::from_value(json!({
            "sessions": [{"peer": "node-03", "peer_id": "cc", "established": true, "primary_circuit": 7, "tx_packets": 4}],
            "circuits": {"local": [{"peer": "node-03", "peer_id": "cc", "label": 7, "hops": ["ctl-01"], "hop_ids": ["aa"],
                                    "primary": true, "open": true, "rtt_ms": 1.5, "route_id": "0102"}],
                         "routes": [{"route_id": "0102", "role": "source", "path": ["node-02", "ctl-01", "node-03"], "fwd_bytes": 10}],
                         "transit": 2, "refused": {"load": 1}}
        }))
        .unwrap();
        let c = &s.circuits.local[0];
        assert_eq!(c.path_text("node-02"), "node-02 → ctl-01 → node-03");
        assert_eq!(c.path_ids("bb"), vec!["bb", "aa", "cc"]);
        assert_eq!(s.route("0102").map(|r| r.fwd_bytes), Some(10));
        let f: Flow = serde_json::from_value(json!({
            "peer": "node-03", "proto": "tcp", "src": "10.7.0.2", "sport": 5000, "dst": "fd00::3", "dport": 22,
            "state": "tcp established", "outbound": true, "rule": "ssh",
            "circuit": {"label": 7, "direct": false, "hops": ["ctl-01"], "rtt_ms": 1.5}
        }))
        .unwrap();
        assert_eq!(f.from_text(), "10.7.0.2:5000");
        assert_eq!(f.to_text(), "[fd00::3]:22");
        assert_eq!(f.circuit_text(), "via ctl-01");
        assert!(f.matches("SSH") && f.matches("ctl-01") && f.matches("out") && !f.matches("udp"));
        let ping = Flow {
            proto: "icmp".into(),
            src: "10.7.0.2".into(),
            ..Default::default()
        };
        assert_eq!(ping.from_text(), "10.7.0.2");
        assert_eq!(ping.circuit_text(), "—");
        let t: Topology = serde_json::from_value(json!({
            "me": "aa", "nodes": [{"id": "aa", "name": "ctl-01", "relay": true, "load": {"util_pct": 3}}],
            "edges": [{"a": "aa", "b": "bb", "kind": "hop", "rtt_ms": 0.4, "remote": "127.0.0.1:1"}]
        }))
        .unwrap();
        assert_eq!(t.nodes[0].load.as_ref().map(|l| l.util_pct), Some(3));
        assert_eq!(t.edges[0].remote.as_deref(), Some("127.0.0.1:1"));
    }

    #[test]
    fn topology_nat_and_endpoints() {
        let t: Topology = serde_json::from_value(json!({
            "me": "aa", "nodes": [{"id": "aa", "name": "mbp", "nat": "symmetric",
                "endpoints": [
                    {"addr": "1.2.3.4:443", "transport": "kcp", "kind": "public"},
                    {"addr": "1.2.3.4:443", "transport": "tls", "kind": "public"},
                    {"addr": "5.6.7.8:6000", "transport": "kcp", "kind": "reflexive"},
                    {"addr": "192.168.1.5:6000", "transport": "kcp", "kind": "host"}
                ],
                "port_mapping": {"external": "5.6.7.8:6000", "protocol": "upnp"}},
                {"id": "bb", "name": "old"}],
            "edges": []
        }))
        .unwrap();
        let n = &t.nodes[0];
        assert!(n.nat_text().unwrap().starts_with("symmetric NAT"));
        assert_eq!(
            n.endpoints_text(),
            "public 1.2.3.4:443 (kcp, tls) · reflexive 5.6.7.8:6000 (kcp) · host 192.168.1.5:6000 (kcp)"
        );
        assert_eq!(
            n.port_mapping.as_ref().map(|m| m.protocol.as_str()),
            Some("upnp")
        );
        assert_eq!(t.nodes[1].nat_text(), None);
        assert_eq!(t.nodes[1].endpoints_text(), "—");
    }

    #[test]
    fn health_levels() {
        let now = 1_000_000_000;
        let mut s = Snapshot::default();
        s.status.valid = true;
        s.status.tree_version = Some(3);
        s.status.head_expires = Some(now + 60_000);
        s.tree.valid_until = now + 30 * 86_400_000;
        let h = health(&s, now);
        assert_eq!((h.level, h.title()), (Level::Ok, "Healthy"));
        s.status.alarms = vec![Alarm {
            name: "soft_mode".into(),
            severity: "warning".into(),
            since: 0,
        }];
        assert_eq!(health(&s, now).level, Level::Warn);
        s.status.head_expires = Some(now - 1000);
        let h = health(&s, now);
        assert_eq!(h.level, Level::Bad);
        assert!(
            h.reasons[0].contains("expired"),
            "worst first: {:?}",
            h.reasons
        );
        s.status.head_expires = None;
        s.status.alarms.clear();
        s.tree.valid_until = now + 86_400_000;
        assert_eq!(health(&s, now).level, Level::Warn, "validity ends soon");
        s.status.valid = false;
        assert_eq!(health(&s, now).level, Level::Bad);
    }

    #[test]
    fn traffic_rates() {
        let mut t = Traffic::default();
        assert_eq!(t.last(), None);
        t.push(0, 0, 0);
        t.push(2000, 2000, 400);
        t.push(2000, 9, 9); // same time: ignored
        t.push(4000, 1000, 600); // counter went down
        assert_eq!(t.rates(), vec![(1000.0, 200.0), (0.0, 100.0)]);
        for i in 0..200 {
            t.push(10_000 + i, i, i);
        }
        assert_eq!(t.rates().len(), Traffic::KEEP - 1);
    }

    #[test]
    fn summary_counts() {
        let mut s = snap();
        s.nodes = vec![
            Node {
                valid: true,
                relay: true,
                control: true,
                ..Default::default()
            },
            Node {
                valid: true,
                data: true,
                routes: vec!["192.168.1.0/24".into()],
                ..Default::default()
            },
            Node {
                valid: false,
                relay: true,
                ..Default::default()
            },
        ];
        s.peers = vec![Peer {
            tx_bytes: 5,
            rx_bytes: 7,
            ..Default::default()
        }];
        s.status.alarms = vec![Alarm {
            severity: "critical".into(),
            ..Default::default()
        }];
        let m = s.summary();
        assert_eq!(
            (
                m.nodes_active,
                m.nodes_total,
                m.relays,
                m.controllers,
                m.gateways
            ),
            (2, 3, 1, 1, 1)
        );
        assert_eq!((m.accounts_active, m.admins), (2, 1));
        assert_eq!((m.tx_bytes, m.rx_bytes, m.critical_alarms), (5, 7, 1));
        assert_eq!(m.flows, 0, "no conntrack answer");
        assert!(!s.is_controller());
        s.status.controller = Some(json!({"leader": true}));
        assert!(s.is_controller());
    }
}
