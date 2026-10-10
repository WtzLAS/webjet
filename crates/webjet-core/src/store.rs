//! The node's trust store (§10): root and emergency keys, controller
//! certificates and their tombstones, the accepted tree head and the full
//! network tree, offline-signed tombstones, and the merge rules of §10.2.
//! Everything here is verified before it is stored; the derived [`View`] is
//! what the rest of the agent reads.

use crate::crypto::{self, Bytes32, open_envelope, open_expect};
use crate::leaf::{self, LeafValue};
use crate::merkle::{self, Tree, kind};
use crate::policy::{Policy, Subject};
use crate::types::{Grant, SKEW_HEAD, cidr_to_net, now_ms};
use anyhow::{Result, anyhow, bail};
use ipnet::IpNet;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use webjet_proto::{self as wp, Decodable, msg_type as mt};

#[derive(Clone, Debug)]
pub struct CertEntry {
    pub cert: wp::SigningKeyCert,
    pub raw: Vec<u8>,
    /// The admin who signed it; `None` for the root.
    pub issuer: Option<CertIssuer>,
}

/// The admin account that signed a SigningKeyCert, and the key it used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertIssuer {
    pub id: Bytes32,
    pub key: Bytes32,
}

#[derive(Clone, Debug)]
pub struct KeyTombEntry {
    pub tomb: wp::SigningKeyTombstone,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct HeadEntry {
    pub head: wp::SignedTreeHead,
    pub raw: Vec<u8>,
}

impl HeadEntry {
    pub fn root(&self) -> Bytes32 {
        crypto::opt_k32(&self.head.root)
    }
    pub fn key_id(&self) -> Bytes32 {
        crypto::opt_k32(&self.head.signing_key_id)
    }
}

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub id: Bytes32,
    pub rec: wp::NodeRecord,
    pub key: Bytes32,
    pub name: String,
    pub owner: Bytes32,
    pub ips: Vec<IpNet>,
    pub tags: Vec<String>,
    pub routes: Vec<Grant>,
    pub data: bool,
    pub relay: bool,
    /// CONTROL in effect: the role is held (or the record predates it as a
    /// role) and a valid SigningKeyCert names the node.
    pub control: bool,
    /// The record grants the `control` role (§4), certified or not.
    pub control_role: bool,
    /// Record present, no tombstone, owner valid.
    pub valid: bool,
}

#[derive(Clone, Debug)]
pub struct AccountInfo {
    pub id: Bytes32,
    pub rec: wp::AccountRecord,
    pub key: Bytes32,
    pub name: String,
    pub admin: bool,
    pub valid: bool,
}

#[derive(Clone, Debug, Default)]
pub struct View {
    pub nodes: HashMap<Bytes32, NodeInfo>,
    pub tombstoned_nodes: HashSet<Bytes32>,
    pub by_key: HashMap<Bytes32, Bytes32>,
    pub by_name: HashMap<String, Bytes32>,
    /// Overlay addresses of valid nodes: single addresses (/32, /128) by
    /// address, wider prefixes longest first (`node_by_ip`, per packet).
    pub host_routes: HashMap<IpAddr, Bytes32>,
    /// Some valid node is a relay (there is a core, §10.6).
    pub any_relay: bool,
    pub ip_routes: Vec<(IpNet, Bytes32)>,
    pub accounts: HashMap<Bytes32, AccountInfo>,
    pub tombstoned_accounts: HashSet<Bytes32>,
    pub policy: Policy,
    pub policy_version: u64,
    /// The policy as committed (for `network config show`).
    pub policy_wire: Option<wp::Policy>,
    pub dns: Option<wp::DnsConfig>,
    pub seeds: Option<wp::Seeds>,
    pub limits: Option<wp::Limits>,
    pub transport: Option<wp::TransportConfig>,
    /// `[controllers]` (§7.5); absent = the built-in values.
    pub controller_settings: Option<wp::ControllerSettings>,
    /// The network configuration's version (§6.18): the highest version of
    /// the Policy, DnsConfig, Seeds, Limits and TransportConfig leaves
    /// (0 = nothing applied yet).
    pub network_version: u64,
    /// Node-scope configurations by node id (§6.19).
    pub node_configs: HashMap<Bytes32, wp::NodeConfig>,
    pub valid_until: u64,
    /// Controllers: node_id → valid signing key ids, for nodes that hold the
    /// `control` role and are valid (§4).
    pub controllers: HashMap<Bytes32, Vec<Bytes32>>,
    /// Signing key ids whose certificate is valid: signed by the root, or by
    /// an admin that is neither revoked nor using a replaced key.
    pub valid_certs: HashSet<Bytes32>,
}

impl View {
    pub fn node(&self, id: &Bytes32) -> Option<&NodeInfo> {
        self.nodes.get(id)
    }

    /// The node owning an overlay address (longest prefix).
    pub fn node_by_ip(&self, ip: &IpAddr) -> Option<Bytes32> {
        if let Some(id) = self.host_routes.get(ip) {
            return Some(*id);
        }
        self.ip_routes
            .iter()
            .find(|(n, _)| n.contains(ip))
            .map(|(_, id)| *id)
    }

    pub fn subject(&self, n: &NodeInfo) -> Subject {
        let owner = self.accounts.get(&n.owner);
        Subject {
            node_id: n.id,
            enrolled: true,
            name: Some(n.name.clone()),
            key: Some(n.key),
            tags: n.tags.clone(),
            owner_name: owner.filter(|a| a.valid).map(|a| a.name.clone()),
            owner_key: owner.filter(|a| a.valid).map(|a| a.key),
            data: n.data,
            relay: n.relay,
            control: n.control,
        }
    }

    pub fn subjects(&self) -> Vec<Subject> {
        self.nodes
            .values()
            .filter(|n| n.valid)
            .map(|n| self.subject(n))
            .collect()
    }

    pub fn granted_prefixes(&self, id: &Bytes32) -> Vec<IpNet> {
        self.nodes
            .get(id)
            .map(|n| n.routes.iter().map(|g| g.published).collect())
            .unwrap_or_default()
    }

    pub fn is_controller(&self, id: &Bytes32) -> bool {
        self.controllers.get(id).is_some_and(|v| !v.is_empty())
    }

    /// The local resolver's addresses (§11.10.1): the DnsConfig's
    /// `resolver_ip`, or by default the highest address of each family's
    /// first overlay pool that no node holds.
    pub fn resolver_ips(&self, pool: &[IpNet]) -> Vec<IpAddr> {
        if let Some(d) = &self.dns {
            let set: Vec<IpAddr> = d
                .resolver_ip
                .clone()
                .unwrap_or_default()
                .iter()
                .filter_map(|i| i.to_ip())
                .collect();
            if !set.is_empty() {
                return set;
            }
        }
        default_resolver_ips(pool, |ip| self.node_by_ip(ip).is_some())
    }

    pub fn suffix(&self) -> String {
        self.dns
            .as_ref()
            .and_then(|d| d.suffix.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "internal".into())
    }

    /// The node-scope configuration of a node (§6.19), if it has one.
    pub fn node_config(&self, id: &Bytes32) -> Option<&wp::NodeConfig> {
        self.node_configs.get(id)
    }

    /// Whether a list of selectors picks a node (the network config's
    /// `select`, §6.18). Unparsable selectors match nothing.
    fn selected(&self, select: &Option<Vec<String>>, node: &Bytes32) -> bool {
        let Some(subj) = self.nodes.get(node).map(|n| self.subject(n)) else {
            return false;
        };
        let sels: Vec<crate::policy::Selector> = select
            .clone()
            .unwrap_or_default()
            .iter()
            .filter_map(|s| crate::policy::Selector::parse(s).ok())
            .collect();
        crate::policy::selects(&sels, &subj)
    }

    /// Effective value of a limit for a node (§16.4), first found: the
    /// node's own configuration, the highest value among the network's
    /// matching overrides, the network's value, the built-in default
    /// (`validate::LIMITS`). `None` for a limit that is unset by default and
    /// set nowhere.
    pub fn limit(&self, node: &Bytes32, name: &str) -> Option<u64> {
        let find = |v: &Option<Vec<wp::LimitValue>>| {
            v.clone()
                .unwrap_or_default()
                .into_iter()
                .filter(|x| x.name.as_deref() == Some(name))
                .map(|x| x.value)
                .next_back()
        };
        if let Some(v) = self.node_configs.get(node).and_then(|c| find(&c.limits)) {
            return Some(v);
        }
        let builtin = crate::validate::limit_default(name);
        let Some(l) = &self.limits else {
            return builtin;
        };
        let best = l
            .overrides
            .clone()
            .unwrap_or_default()
            .iter()
            .filter(|o| self.selected(&o.select, node))
            .filter_map(|o| find(&o.values))
            .max();
        best.or_else(|| find(&l.defaults)).or(builtin)
    }

    /// Effective priority of a transport for a node (§9.6), first found:
    /// the node's own configuration, the first of the network's matching
    /// overrides that names the transport, the network's value, built-in.
    pub fn priority(&self, node: &Bytes32, t: wp::Transport) -> u8 {
        let find = |v: &Option<Vec<wp::TransportPriority>>| {
            v.clone()
                .unwrap_or_default()
                .into_iter()
                .find(|p| p.transport == t)
                .map(|p| p.priority)
        };
        if let Some(p) = self
            .node_configs
            .get(node)
            .and_then(|c| find(&c.priorities))
        {
            return p;
        }
        if let Some(tc) = &self.transport {
            for o in tc.overrides.clone().unwrap_or_default() {
                if self.selected(&o.select, node)
                    && let Some(p) = find(&o.values)
                {
                    return p;
                }
            }
            if let Some(p) = find(&tc.defaults) {
                return p;
            }
        }
        builtin_priority(t)
    }

    /// Compression in force for a node (§9.8), per plane: the node's own
    /// configuration, the network's, built-in (control zstd, data off).
    pub fn compression(&self, node: &Bytes32) -> crate::compress::Settings {
        let pair = |c: &wp::CompressionConfig| (c.control, c.data);
        crate::compress::Settings::resolve(
            self.node_configs
                .get(node)
                .and_then(|c| c.compression.as_deref())
                .map(pair),
            self.transport
                .as_ref()
                .and_then(|t| t.compression.as_deref())
                .map(pair),
        )
    }

    /// Whether a node retransmits unreliable-class frames (§17.5) on the KCP
    /// hops it sends on, first found: the node's own configuration, the
    /// first of the network's matching overrides that sets it, the
    /// network's value, built-in off.
    pub fn retransmit(&self, node: &Bytes32) -> bool {
        if let Some(r) = self.node_configs.get(node).and_then(|c| c.retransmit) {
            return r;
        }
        let Some(tc) = &self.transport else {
            return false;
        };
        for o in tc.overrides.as_deref().unwrap_or_default() {
            if let Some(r) = o.retransmit
                && self.selected(&o.select, node)
            {
                return r;
            }
        }
        tc.retransmit.unwrap_or(false)
    }

    /// The UDP ports whose broadcasts and multicasts a node captures from
    /// its other interfaces (§9.5.2): the node's own `capture`, else the
    /// network's, else none.
    pub fn capture_ports(&self, node: &Bytes32) -> Vec<String> {
        let node_set = self
            .node_configs
            .get(node)
            .and_then(|c| c.multicast.as_deref())
            .and_then(|m| m.capture.clone());
        node_set
            .or_else(|| {
                self.transport
                    .as_ref()
                    .and_then(|t| t.multicast.as_deref())
                    .and_then(|m| m.capture.clone())
            })
            .unwrap_or_default()
    }

    /// The seed list a node uses (§10.7.1): its own seeds first, then the
    /// network's.
    pub fn seeds_for(&self, node: &Bytes32) -> Vec<wp::SeedEntry> {
        let mut out = self
            .node_configs
            .get(node)
            .and_then(|c| c.seeds.clone())
            .unwrap_or_default();
        if let Some(s) = &self.seeds {
            out.extend(s.entries.clone().unwrap_or_default());
        }
        out
    }

    /// The DNS records a node's resolver answers (§11.10): its own first,
    /// then the network's.
    pub fn dns_records_for(&self, node: &Bytes32) -> Vec<wp::DnsRecord> {
        let mut out = self
            .node_configs
            .get(node)
            .and_then(|c| c.dns_records.clone())
            .unwrap_or_default();
        if let Some(d) = &self.dns {
            out.extend(d.records.clone().unwrap_or_default());
        }
        out
    }

    /// The zones a node's resolver forwards (§11.10.6): its own first (they
    /// win for the same zone), then the network's.
    pub fn dns_forward_for(&self, node: &Bytes32) -> Vec<wp::ForwardZone> {
        let mut out = self
            .node_configs
            .get(node)
            .and_then(|c| c.dns_forward.clone())
            .unwrap_or_default();
        if let Some(d) = &self.dns {
            out.extend(d.forward.clone().unwrap_or_default());
        }
        out
    }
}

/// Built-in transport priorities (§9.6): UDP+KCP+FEC 30, TCP+AnyTLS 20,
/// TCP+TLS 10.
pub const BUILTIN_PRIORITIES: [(wp::Transport, u8); 3] = [
    (wp::Transport::KcpFecTls, 30),
    (wp::Transport::AnyTls, 20),
    (wp::Transport::TcpTls, 10),
];

pub fn builtin_priority(t: wp::Transport) -> u8 {
    BUILTIN_PRIORITIES
        .iter()
        .find(|(x, _)| *x == t)
        .map_or(0, |x| x.1)
}

/// What happened to an offered tree head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadOutcome {
    /// Same state, possibly re-signed with a later expiry.
    Refreshed,
    /// Already have it (or an equal-or-newer one).
    Known,
    /// Newer state: the caller must sync the tree diff and call `install`.
    NeedSync,
    /// Two valid heads with the same version and different roots (§21.3).
    Equivocation,
}

pub struct Store {
    pub genesis_raw: Vec<u8>,
    pub genesis: wp::Genesis,
    pub root: Bytes32,
    pub emergency: Option<Bytes32>,
    pub overlay_pool: Vec<IpNet>,
    /// By the hash of the cert's bytes.
    certs: BTreeMap<Bytes32, CertEntry>,
    key_tombs: BTreeMap<Bytes32, KeyTombEntry>,
    head: Option<HeadEntry>,
    tree: Tree,
    offline_node_tombs: BTreeMap<Bytes32, (wp::Tombstone, Vec<u8>)>,
    offline_acct_tombs: BTreeMap<Bytes32, (wp::AccountTombstone, Vec<u8>)>,
    pub high_water: u64,
    pub equivocation: Option<(Vec<u8>, Vec<u8>)>,
    pub trusted_floor: u64,
    view: View,
    /// Bumped whenever anything changes; consumers use it to recompute caches.
    pub generation: u64,
}

/// Verify a genesis file and return its decoded form and trust anchors.
pub fn open_genesis(raw: &[u8]) -> Result<(wp::Genesis, Bytes32, Option<Bytes32>)> {
    let g = wp::Genesis::decode_bytes(raw)?;
    let root = crypto::opt_k32(&g.root_key);
    let mut emergency = None;
    if let Some(ec) = &g.emergency_cert {
        let v = open_expect(ec, mt::EMERGENCY_KEY_CERT, &[root])?;
        let c: wp::EmergencyKeyCert = v.decode()?;
        emergency = Some(crypto::opt_k32(&c.key));
    }
    if let Some(a) = &g.first_admin {
        let v = open_expect(a, mt::ACCOUNT_RECORD, &[root])?;
        let r: wp::AccountRecord = v.decode()?;
        crate::validate::account_record(&r)?;
        if !r.admin {
            bail!("genesis first admin is not an admin");
        }
    }
    Ok((g, root, emergency))
}

impl Store {
    pub fn new(genesis_raw: Vec<u8>) -> Result<Store> {
        let (genesis, root, emergency) = open_genesis(&genesis_raw)?;
        let overlay_pool = genesis
            .overlay_pool
            .clone()
            .unwrap_or_default()
            .iter()
            .filter_map(cidr_to_net)
            .collect();
        let mut s = Store {
            genesis_raw,
            genesis,
            root,
            emergency,
            overlay_pool,
            certs: BTreeMap::new(),
            key_tombs: BTreeMap::new(),
            head: None,
            tree: Tree::new(),
            offline_node_tombs: BTreeMap::new(),
            offline_acct_tombs: BTreeMap::new(),
            high_water: 0,
            equivocation: None,
            trusted_floor: 0,
            view: View::default(),
            generation: 0,
        };
        s.rebuild();
        Ok(s)
    }

    pub fn view(&self) -> &View {
        &self.view
    }

    pub fn head(&self) -> Option<&HeadEntry> {
        self.head.as_ref()
    }

    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    pub fn offline_signers(&self) -> Vec<Bytes32> {
        let mut v = vec![self.root];
        v.extend(self.emergency);
        v
    }

    // ------------------------------------------------------------ certificates

    pub fn certs(&self) -> impl Iterator<Item = &CertEntry> {
        self.certs.values()
    }

    pub fn key_tombstones(&self) -> impl Iterator<Item = &KeyTombEntry> {
        self.key_tombs.values()
    }

    /// Accept a SigningKeyCert signed by the root, or by an admin whose
    /// root-signed AccountRecord the cert carries in `issuer` (§6.5, §10.2).
    /// Admins' certs for one key are all kept (one may be voided by its
    /// issuer's revocation while another stays good) until a root-signed one
    /// replaces them; which count is decided in the view (`View::valid_certs`).
    pub fn add_cert(&mut self, raw: &[u8]) -> Result<bool> {
        let v = open_envelope(raw)?;
        if v.ty != mt::SIGNING_KEY_CERT {
            bail!("expected a SigningKeyCert, got {}", mt::name(v.ty));
        }
        let c: wp::SigningKeyCert = v.decode()?;
        let issuer = self.cert_issuer(&v, &c)?;
        let key = crypto::opt_k32(&c.signing_key);
        let id = crypto::opt_k32(&c.signing_key_id);
        if crypto::signing_key_id(&key) != id {
            bail!("signing key id does not match the key");
        }
        if crypto::opt_k32(&c.controller) == [0; 32] {
            bail!("certificate names no controller");
        }
        if self.key_tombs.contains_key(&id) {
            return Ok(false);
        }
        let cid = crypto::hash(raw);
        if self.certs.contains_key(&cid) {
            return Ok(false);
        }
        let same_key = || {
            self.certs
                .values()
                .filter(move |o| crypto::opt_k32(&o.cert.signing_key_id) == id)
        };
        if same_key().any(|o| o.cert.controller != c.controller) {
            bail!("this signing key is already certified for another node");
        }
        // One root-signed cert per key is enough, and it replaces admins'
        // (in whatever order they arrive, so every node ends up with the
        // same set and anti-entropy settles). One per admin key, too.
        if same_key().any(|o| o.issuer.is_none() || o.issuer == issuer) {
            return Ok(false);
        }
        if issuer.is_none() {
            self.certs
                .retain(|_, o| crypto::opt_k32(&o.cert.signing_key_id) != id);
        }
        self.certs.insert(
            cid,
            CertEntry {
                cert: c,
                raw: raw.to_vec(),
                issuer,
            },
        );
        self.rebuild();
        Ok(true)
    }

    /// Who signed a certificate: `None` for the root, or the admin account.
    fn cert_issuer(
        &self,
        v: &crypto::Verified,
        c: &wp::SigningKeyCert,
    ) -> Result<Option<CertIssuer>> {
        let Some(rec_raw) = &c.issuer else {
            if v.signer != self.root {
                bail!("certificate signed by neither the root nor an admin");
            }
            return Ok(None);
        };
        if v.signer == self.root {
            bail!("a root-signed certificate carries no issuer");
        }
        let rv = open_expect(rec_raw, mt::ACCOUNT_RECORD, &[self.root])?;
        let r: wp::AccountRecord = rv.decode()?;
        if !r.admin || !r.issuer_root {
            bail!("certificate issuer is not an admin account");
        }
        let key = crypto::opt_k32(&r.account_key);
        if key != v.signer {
            bail!("certificate not signed by its issuer's key");
        }
        let id = crypto::opt_k32(&r.account_id);
        Ok(Some(CertIssuer { id, key }))
    }

    /// Accept a SigningKeyTombstone signed by the root or emergency key
    /// (§6.6, §22.1). Permanent.
    pub fn add_key_tombstone(&mut self, raw: &[u8]) -> Result<bool> {
        let v = open_expect(raw, mt::SIGNING_KEY_TOMBSTONE, &self.offline_signers())?;
        let t: wp::SigningKeyTombstone = v.decode()?;
        let id = crypto::opt_k32(&t.signing_key_id);
        if self.key_tombs.contains_key(&id) {
            return Ok(false);
        }
        let last_valid = t.last_valid_version;
        self.key_tombs.insert(
            id,
            KeyTombEntry {
                tomb: t,
                raw: raw.to_vec(),
            },
        );
        self.certs
            .retain(|_, c| crypto::opt_k32(&c.cert.signing_key_id) != id);
        // Discard state known only through heads above last_valid_version.
        if let Some(h) = &self.head
            && h.key_id() == id
            && h.head.version > last_valid
        {
            tracing::warn!(
                "current tree head came from a retired key above its last valid version; discarding it"
            );
            self.head = None;
            self.tree = Tree::new();
            self.high_water = self.high_water.min(last_valid);
        }
        self.rebuild();
        Ok(true)
    }

    fn key_for_head(&self, key_id: &Bytes32, version: u64) -> Option<Bytes32> {
        if let Some(t) = self.key_tombs.get(key_id)
            && version > t.tomb.last_valid_version
        {
            return None;
        }
        // A retired key's cert is removed, so only heads from still-certified
        // keys can be verified; retired keys' older heads are kept as stored.
        // A cert from a revoked admin no longer verifies anything.
        if !self.view.valid_certs.contains(key_id) {
            return None;
        }
        self.certs
            .values()
            .find(|c| crypto::opt_k32(&c.cert.signing_key_id) == *key_id)
            .map(|c| crypto::opt_k32(&c.cert.signing_key))
    }

    /// Verify a head's signature and certificate chain.
    pub fn verify_head(&self, raw: &[u8]) -> Result<wp::SignedTreeHead> {
        let v = open_envelope(raw)?;
        if v.ty != mt::SIGNED_TREE_HEAD {
            bail!("not a tree head");
        }
        let h: wp::SignedTreeHead = v.decode()?;
        let kid = crypto::opt_k32(&h.signing_key_id);
        let key = self
            .key_for_head(&kid, h.version)
            .ok_or_else(|| anyhow!("tree head from an unknown or retired key"))?;
        if key != v.signer {
            bail!("tree head signed by a key other than its signing_key_id");
        }
        if !wp::SUPPORTED_STATE_VERSIONS.contains(&h.state_version) {
            bail!(
                "tree head with unsupported state version {}",
                h.state_version
            );
        }
        if h.issued_at > now_ms().saturating_add(SKEW_HEAD) {
            bail!("tree head issued in the future");
        }
        Ok(h)
    }

    /// Offer a tree head (§10.2, §10.3).
    pub fn offer_head(&mut self, raw: &[u8]) -> Result<HeadOutcome> {
        let h = self.verify_head(raw)?;
        let now = now_ms();
        if h.expires_at.saturating_add(SKEW_HEAD) < now {
            bail!("tree head expired");
        }
        if h.version < self.high_water {
            return Ok(HeadOutcome::Known);
        }
        let root = crypto::opt_k32(&h.root);
        if let Some(cur) = &self.head {
            if h.version == cur.head.version {
                if root != cur.root() {
                    self.equivocation = Some((cur.raw.clone(), raw.to_vec()));
                    self.generation += 1;
                    return Ok(HeadOutcome::Equivocation);
                }
                if h.expires_at > cur.head.expires_at {
                    self.trusted_floor = self.trusted_floor.max(h.issued_at);
                    self.head = Some(HeadEntry {
                        head: h,
                        raw: raw.to_vec(),
                    });
                    self.generation += 1;
                    return Ok(HeadOutcome::Refreshed);
                }
                return Ok(HeadOutcome::Known);
            }
            if h.version < cur.head.version {
                return Ok(HeadOutcome::Known);
            }
        }
        if self.equivocation.is_some() {
            // Tree updates are frozen until an operator retires the bad key.
            bail!("tree updates frozen after equivocation");
        }
        if root == self.tree.compute_root() {
            // Same tree, newer version (e.g. a no-op entry): no sync needed.
            self.trusted_floor = self.trusted_floor.max(h.issued_at);
            self.high_water = h.version;
            self.head = Some(HeadEntry {
                head: h,
                raw: raw.to_vec(),
            });
            self.generation += 1;
            return Ok(HeadOutcome::Refreshed);
        }
        Ok(HeadOutcome::NeedSync)
    }

    /// Install a newer tree: `updates` are the leaves that changed relative
    /// to the current tree (`None` bytes = removed). The resulting root must
    /// equal the head's root, and no leaf may go back in version (§10.2,
    /// §21.1).
    pub fn install(
        &mut self,
        head_raw: &[u8],
        updates: Vec<(u8, Bytes32, Option<Vec<u8>>)>,
    ) -> Result<()> {
        let h = self.verify_head(head_raw)?;
        if h.version < self.high_water {
            bail!(
                "rollback: head version {} below {}",
                h.version,
                self.high_water
            );
        }
        // Every check is against the tree as it was before this sync, and a
        // leaf may appear only once: otherwise removing a leaf and adding it
        // back would get past both the tombstone and the version rules.
        let mut seen = HashSet::new();
        let mut t = self.tree.clone();
        for (k, key, bytes) in &updates {
            if !seen.insert(merkle::path_of(*k, key)) {
                bail!("leaf listed twice in one sync");
            }
            let old = self
                .tree
                .get(*k, key)
                .and_then(|old| Some((leaf::decode(*k, key, &old.bytes).ok()?, &old.bytes)));
            let tomb_old = old.as_ref().is_some_and(|(v, _)| {
                matches!(
                    v,
                    LeafValue::NodeTombstone(_) | LeafValue::AccountTombstone(..)
                )
            });
            match bytes {
                Some(b) => {
                    let new = leaf::decode(*k, key, b)?;
                    // Sending a leaf unchanged is harmless.
                    if let Some((oldv, old_bytes)) = &old
                        && *old_bytes != b
                    {
                        if tomb_old {
                            bail!("a tombstone can't be replaced");
                        }
                        if *k != kind::VALIDITY
                            && !matches!(new, LeafValue::Unknown)
                            && leaf::version(&new) <= leaf::version(oldv)
                        {
                            bail!("leaf version went backwards");
                        }
                    }
                    t.insert(*k, *key, b.clone());
                }
                None => {
                    if tomb_old {
                        bail!("a tombstone can't be removed");
                    }
                    t.remove(*k, key);
                }
            }
        }
        let root = t.root();
        if root != crypto::opt_k32(&h.root) {
            bail!("tree root mismatch after sync");
        }
        self.tree = t;
        self.high_water = h.version;
        self.trusted_floor = self.trusted_floor.max(h.issued_at);
        self.head = Some(HeadEntry {
            head: h,
            raw: head_raw.to_vec(),
        });
        self.rebuild();
        Ok(())
    }

    /// Restore persisted state without the "newer" checks; the persisted
    /// root must still match the persisted head.
    pub fn restore(
        &mut self,
        head_raw: Option<&[u8]>,
        leaves: Vec<(u8, Bytes32, Vec<u8>)>,
        high_water: u64,
        floor: u64,
    ) -> Result<()> {
        let mut t = Tree::new();
        for (k, key, b) in leaves {
            t.insert(k, key, b);
        }
        if let Some(raw) = head_raw {
            let v = open_envelope(raw)?;
            let h: wp::SignedTreeHead = v.decode()?;
            if crypto::opt_k32(&h.root) != t.root() {
                bail!("persisted tree does not match the persisted head");
            }
            self.head = Some(HeadEntry {
                head: h,
                raw: raw.to_vec(),
            });
        }
        self.tree = t;
        self.high_water = high_water;
        self.trusted_floor = floor;
        self.rebuild();
        Ok(())
    }

    // ------------------------------------------------------------ offline tombstones

    /// Accept a root- or emergency-signed node or account tombstone (§6.3, §6.11).
    pub fn add_offline_tombstone(&mut self, raw: &[u8]) -> Result<bool> {
        let v = open_envelope(raw)?;
        if !self.offline_signers().contains(&v.signer) {
            bail!("offline tombstone not signed by the root or emergency key");
        }
        match v.ty {
            mt::TOMBSTONE => {
                let t: wp::Tombstone = v.decode()?;
                let id = crypto::opt_k32(&t.node_id);
                if let Some((old, _)) = self.offline_node_tombs.get(&id)
                    && old.version >= t.version
                {
                    return Ok(false);
                }
                self.offline_node_tombs.insert(id, (t, raw.to_vec()));
            }
            mt::ACCOUNT_TOMBSTONE => {
                let t: wp::AccountTombstone = v.decode()?;
                let id = crypto::opt_k32(&t.account_id);
                if self.offline_acct_tombs.contains_key(&id) {
                    return Ok(false);
                }
                self.offline_acct_tombs.insert(id, (t, raw.to_vec()));
            }
            _ => bail!("not a tombstone"),
        }
        self.rebuild();
        Ok(true)
    }

    /// Generic entry point for any priority-gossiped offline item.
    pub fn add_offline_item(&mut self, raw: &[u8]) -> Result<bool> {
        let v = open_envelope(raw)?;
        match v.ty {
            mt::SIGNING_KEY_CERT => self.add_cert(raw),
            mt::SIGNING_KEY_TOMBSTONE => self.add_key_tombstone(raw),
            mt::TOMBSTONE | mt::ACCOUNT_TOMBSTONE => self.add_offline_tombstone(raw),
            _ => bail!("unexpected offline item {}", mt::name(v.ty)),
        }
    }

    pub fn offline_items(&self) -> Vec<Vec<u8>> {
        let mut v: Vec<Vec<u8>> = Vec::new();
        v.extend(self.certs.values().map(|c| c.raw.clone()));
        v.extend(self.key_tombs.values().map(|c| c.raw.clone()));
        v.extend(self.offline_node_tombs.values().map(|c| c.1.clone()));
        v.extend(self.offline_acct_tombs.values().map(|c| c.1.clone()));
        v
    }

    pub fn offline_hash(&self) -> Bytes32 {
        let mut ids: Vec<Bytes32> = Vec::new();
        // Root-signed certs by key id, as before admins could sign them, so
        // nodes of either kind agree while only the root signs certs.
        let mut root_kids: Vec<Bytes32> = Vec::new();
        for (cid, c) in &self.certs {
            match c.issuer {
                None => root_kids.push(crypto::opt_k32(&c.cert.signing_key_id)),
                Some(_) => ids.push(crypto::hash(&[b"C".as_slice(), cid].concat())),
            }
        }
        root_kids.sort();
        root_kids.dedup();
        ids.extend(
            root_kids
                .iter()
                .map(|k| crypto::hash(&[b"c".as_slice(), k].concat())),
        );
        ids.extend(
            self.key_tombs
                .keys()
                .map(|k| crypto::hash(&[b"k".as_slice(), k].concat())),
        );
        ids.extend(self.offline_node_tombs.iter().map(|(k, (t, _))| {
            crypto::hash(&[b"n".as_slice(), k, &t.version.to_be_bytes()].concat())
        }));
        ids.extend(
            self.offline_acct_tombs
                .keys()
                .map(|k| crypto::hash(&[b"a".as_slice(), k].concat())),
        );
        ids.sort();
        let mut h = blake3::Hasher::new();
        for i in ids {
            h.update(&i);
        }
        *h.finalize().as_bytes()
    }

    /// The gossip digest of §10.3.1.
    pub fn digest(&self) -> Bytes32 {
        let (ver, root) = match &self.head {
            Some(h) => (h.head.version, h.root()),
            None => (0, [0; 32]),
        };
        let mut m = Vec::with_capacity(72);
        m.extend_from_slice(&ver.to_be_bytes());
        m.extend_from_slice(&root);
        m.extend_from_slice(&self.offline_hash());
        crypto::derive(crypto::ctx::DIGEST, &m)
    }

    // ------------------------------------------------------------ status

    pub fn head_expired(&self, now: u64) -> bool {
        match &self.head {
            Some(h) => h.head.expires_at.saturating_add(SKEW_HEAD) < now,
            None => true,
        }
    }

    /// Records are trusted only until the validity horizon (§6.16).
    pub fn horizon_passed(&self, now: u64) -> bool {
        self.view.valid_until == 0 || self.view.valid_until.saturating_add(SKEW_HEAD) < now
    }

    /// The node is trusted right now: valid record, no tombstone, owner
    /// valid, validity horizon not passed (§9.2).
    pub fn node_trusted(&self, id: &Bytes32) -> bool {
        !self.horizon_passed(now_ms()) && self.view.nodes.get(id).is_some_and(|n| n.valid)
    }

    /// Resolve an identity key to a trusted node id.
    pub fn trusted_by_key(&self, key: &Bytes32) -> Option<Bytes32> {
        let id = *self.view.by_key.get(key)?;
        self.node_trusted(&id).then_some(id)
    }

    // ------------------------------------------------------------ derived view

    /// The view of another tree (a controller's state machine, which is
    /// ahead of signed heads) with this store's certificates and offline
    /// tombstones, so CONTROL shows as the network will see it.
    pub fn view_of(&self, tree: &Tree) -> View {
        build_view(
            tree,
            &self.root,
            &self.certs,
            &self.offline_node_tombs,
            &self.offline_acct_tombs,
        )
    }

    fn rebuild(&mut self) {
        self.view = build_view(
            &self.tree,
            &self.root,
            &self.certs,
            &self.offline_node_tombs,
            &self.offline_acct_tombs,
        );
        self.generation += 1;
    }

    // ------------------------------------------------------------ sync helpers

    /// Leaves of the given buckets, as `(path, hash)` pairs.
    pub fn bucket_index(&self, buckets: &[u8]) -> Vec<(Bytes32, Bytes32)> {
        let mut out = Vec::new();
        for b in buckets {
            out.extend(self.tree.bucket_entries(*b));
        }
        out
    }

    pub fn leaves_by_path(&self, paths: &[Bytes32]) -> Vec<(u8, Bytes32, Vec<u8>)> {
        paths
            .iter()
            .filter_map(|p| self.tree.get_by_path(p))
            .map(|e| (e.kind, e.key, e.bytes.clone()))
            .collect()
    }

    pub fn all_leaves(&self) -> Vec<(u8, Bytes32, Vec<u8>)> {
        self.tree
            .iter()
            .map(|(_, e)| (e.kind, e.key, e.bytes.clone()))
            .collect()
    }

    pub fn prove(&self, k: u8, key: &Bytes32) -> merkle::Proof {
        self.tree.prove(k, key)
    }
}

pub fn build_view(
    tree: &Tree,
    root: &Bytes32,
    certs: &BTreeMap<Bytes32, CertEntry>,
    offline_node_tombs: &BTreeMap<Bytes32, (wp::Tombstone, Vec<u8>)>,
    offline_acct_tombs: &BTreeMap<Bytes32, (wp::AccountTombstone, Vec<u8>)>,
) -> View {
    let mut v = View::default();
    // Every leaf decoded once for all the passes below.
    let leaves: Vec<LeafValue> = tree
        .iter()
        .filter_map(|(_, e)| match decode_leaf(e) {
            Ok(val) => Some(val),
            Err(_) => {
                tracing::warn!("undecodable leaf of kind {} in the tree", e.kind);
                None
            }
        })
        .collect();
    view_accounts(&mut v, &leaves, root, offline_acct_tombs);
    let ctrl = view_certs(&mut v, certs);
    // Nodes and singletons.
    for val in leaves {
        match val {
            LeafValue::Node(r) => {
                let (info, offline_tomb) = node_info(&v, r, offline_node_tombs);
                if offline_tomb {
                    v.tombstoned_nodes.insert(info.id);
                }
                v.nodes.insert(info.id, info);
            }
            LeafValue::NodeTombstone(t) => {
                v.tombstoned_nodes.insert(crypto::opt_k32(&t.node_id));
            }
            LeafValue::Policy(p) => match Policy::from_wire(&p) {
                Ok(pol) => {
                    v.network_version = v.network_version.max(p.version);
                    v.policy_version = p.version;
                    v.policy = pol;
                    v.policy_wire = Some(p);
                }
                Err(e) => tracing::error!("policy in the tree does not parse: {e}"),
            },
            LeafValue::Dns(d) => {
                v.network_version = v.network_version.max(d.version);
                v.dns = Some(d);
            }
            LeafValue::Seeds(s) => {
                v.network_version = v.network_version.max(s.version);
                v.seeds = Some(s);
            }
            LeafValue::Limits(l) => {
                v.network_version = v.network_version.max(l.version);
                v.limits = Some(l);
            }
            LeafValue::Transport(t) => {
                v.network_version = v.network_version.max(t.version);
                v.transport = Some(t);
            }
            LeafValue::Controllers(c) => {
                v.network_version = v.network_version.max(c.version);
                v.controller_settings = Some(c);
            }
            LeafValue::NodeConfig(c) => {
                v.node_configs.insert(crypto::opt_k32(&c.node_id), c);
            }
            LeafValue::Validity(val) => v.valid_until = val.valid_until,
            LeafValue::Account(..) | LeafValue::AccountTombstone(..) | LeafValue::Unknown => {}
        }
    }
    v.any_relay = v.nodes.values().any(|x| x.relay && x.valid);
    for n in v.nodes.values() {
        v.by_key.insert(n.key, n.id);
        v.by_name.insert(n.name.clone(), n.id);
        if n.valid {
            for ip in &n.ips {
                if ip.prefix_len() == ip.max_prefix_len() {
                    v.host_routes.insert(ip.addr(), n.id);
                } else {
                    v.ip_routes.push((*ip, n.id));
                }
            }
        }
    }
    // Longest prefix first, so the first match is the best.
    v.ip_routes
        .sort_by_key(|(net, id)| (std::cmp::Reverse(net.prefix_len()), *id));
    view_controllers(&mut v, ctrl);
    for n in v.nodes.values_mut() {
        n.control = v.controllers.contains_key(&n.id);
    }
    v
}

/// A tree leaf decoded. Account leaves are signed envelopes, and the view is
/// rebuilt from every leaf on each change, so their decoding (signature
/// check included) is kept by leaf hash, which covers kind, key and bytes.
fn decode_leaf(e: &merkle::LeafEntry) -> Result<LeafValue> {
    use parking_lot::Mutex;
    use std::sync::OnceLock;
    /// Enough for every account leaf of a large network, plus old versions.
    const CACHED: usize = 1 << 16;
    static CACHE: OnceLock<Mutex<HashMap<Bytes32, LeafValue>>> = OnceLock::new();
    if e.kind != kind::ACCOUNT {
        return leaf::decode(e.kind, &e.key, &e.bytes);
    }
    let cache = CACHE.get_or_init(Default::default);
    if let Some(v) = cache.lock().get(&e.hash) {
        return Ok(v.clone());
    }
    let v = leaf::decode(e.kind, &e.key, &e.bytes)?;
    let mut c = cache.lock();
    if c.len() >= CACHED {
        c.clear();
    }
    c.insert(e.hash, v.clone());
    Ok(v)
}

/// Accounts: signature and signer checks (§6.10, §10.2), into `v.accounts`
/// and `v.tombstoned_accounts`.
fn view_accounts(
    v: &mut View,
    leaves: &[LeafValue],
    root: &Bytes32,
    offline_acct_tombs: &BTreeMap<Bytes32, (wp::AccountTombstone, Vec<u8>)>,
) {
    // Accounts first: signature and signer checks (§6.10, §10.2).
    let mut raw_accounts: Vec<(&wp::AccountRecord, &crypto::Verified)> = Vec::new();
    let mut revoke_issuers: HashSet<Bytes32> = HashSet::new();
    for val in leaves {
        match val {
            LeafValue::Account(r, ver) => raw_accounts.push((r, ver)),
            LeafValue::AccountTombstone(t, _) => {
                let id = crypto::opt_k32(&t.account_id);
                v.tombstoned_accounts.insert(id);
                if t.revoke_issued {
                    revoke_issuers.insert(id);
                }
            }
            _ => {}
        }
    }
    // Offline account tombstones, with `revoke_issued` cascades.
    for (id, (t, _)) in offline_acct_tombs {
        v.tombstoned_accounts.insert(*id);
        if t.revoke_issued {
            revoke_issuers.insert(*id);
        }
    }
    // Admin accounts (root-signed) first, then normal accounts.
    for pass in 0..2 {
        for &(r, ver) in &raw_accounts {
            let admin_pass = r.issuer_root;
            if (pass == 0) != admin_pass {
                continue;
            }
            let id = crypto::opt_k32(&r.account_id);
            let mut valid = !v.tombstoned_accounts.contains(&id);
            if r.issuer_root {
                valid &= ver.signer == *root;
            } else {
                let issuer = crypto::opt_k32(&r.issuer);
                // A tombstone replaces the issuer's record leaf, so a revoked
                // admin is no longer among the accounts. Only admins issue
                // records, so a tombstoned issuer was one: its accounts stay
                // valid unless the tombstone said `revoke_issued` (§13.4).
                let issuer_ok = !revoke_issuers.contains(&issuer)
                    && match v.accounts.get(&issuer) {
                        Some(a) => a.admin,
                        None => v.tombstoned_accounts.contains(&issuer),
                    };
                valid &= issuer_ok && !r.admin;
            }
            v.accounts.insert(
                id,
                AccountInfo {
                    id,
                    key: crypto::opt_k32(&r.account_key),
                    name: r.name.clone().unwrap_or_default(),
                    admin: r.admin,
                    rec: r.clone(),
                    valid,
                },
            );
        }
    }
}

/// The valid controller signing-key certificates, into `v.valid_certs`;
/// returns node → (signing key id, signed by the root).
fn view_certs(
    v: &mut View,
    certs: &BTreeMap<Bytes32, CertEntry>,
) -> HashMap<Bytes32, Vec<(Bytes32, bool)>> {
    // Valid certs (§6.5): root-signed, or signed by an admin that isn't
    // revoked and still has the key it signed with. Certs aren't ordered by
    // the log, so a cert signed with a revoked or replaced admin key can't be
    // told apart from one signed in time: revoking or re-keying an admin
    // voids every cert it signed (the root or another admin re-signs them).
    // Head verification needs only this, never the tree's node records.
    // node → (signing key id, signed by the root)
    let mut ctrl: HashMap<Bytes32, Vec<(Bytes32, bool)>> = HashMap::new();
    for c in certs.values() {
        if let Some(i) = c.issuer {
            let revoked = v.tombstoned_accounts.contains(&i.id);
            let rekeyed = v.accounts.get(&i.id).is_some_and(|a| a.key != i.key);
            if revoked || rekeyed {
                continue;
            }
        }
        let kid = crypto::opt_k32(&c.cert.signing_key_id);
        v.valid_certs.insert(kid);
        let e = ctrl.entry(crypto::opt_k32(&c.cert.controller)).or_default();
        match e.iter_mut().find(|(k, _)| *k == kid) {
            Some(x) => x.1 |= c.issuer.is_none(),
            None => e.push((kid, c.issuer.is_none())),
        }
    }
    ctrl
}

/// A node record as the view shows it; `true` when an offline tombstone
/// newer than the record revokes it.
fn node_info(
    v: &View,
    r: wp::NodeRecord,
    offline_node_tombs: &BTreeMap<Bytes32, (wp::Tombstone, Vec<u8>)>,
) -> (NodeInfo, bool) {
    let id = crypto::opt_k32(&r.node_id);
    let roles = r.roles.clone().unwrap_or_default();
    let owner = crypto::opt_k32(&r.owner);
    let offline_tomb = offline_node_tombs
        .get(&id)
        .is_some_and(|(t, _)| t.version > r.version);
    let owner_ok = v.accounts.get(&owner).is_some_and(|a| a.valid);
    let key = crypto::opt_k32(&r.identity_key);
    let info = NodeInfo {
        id,
        key,
        name: r.name.clone().unwrap_or_default(),
        owner,
        ips: r
            .overlay_ips
            .clone()
            .unwrap_or_default()
            .iter()
            .filter_map(cidr_to_net)
            .collect(),
        tags: r.tags.clone().unwrap_or_default(),
        routes: r
            .routes
            .clone()
            .unwrap_or_default()
            .iter()
            .filter_map(|g| Grant::from_wire(g).ok())
            .collect(),
        data: roles.contains(&wp::Role::Data),
        relay: roles.contains(&wp::Role::Relay),
        control: false,
        control_role: r.control == Some(true),
        valid: !offline_tomb && owner_ok && key != [0u8; 32],
        rec: r,
    };
    (info, offline_tomb)
}

/// The controllers, into `v.controllers`.
fn view_controllers(v: &mut View, ctrl: HashMap<Bytes32, Vec<(Bytes32, bool)>>) {
    // CONTROL (§4): a valid node with a valid cert and the `control` role.
    // A record that doesn't mention the role (from before it was one) counts
    // with a root-signed cert, as it always did; an admin's cert needs the
    // role. A role removed by an admin (`false`) turns every cert off.
    for (id, keys) in ctrl {
        let Some(n) = v.nodes.get(&id).filter(|n| n.valid) else {
            continue;
        };
        let keys: Vec<Bytes32> = keys
            .into_iter()
            .filter(|(_, by_root)| match n.rec.control {
                Some(c) => c,
                None => *by_root,
            })
            .map(|(k, _)| k)
            .collect();
        if !keys.is_empty() {
            v.controllers.insert(id, keys);
        }
    }
}

/// The default resolver addresses: per address family, the highest host
/// address of the first overlay pool of that family that `taken` doesn't
/// claim (a node may hold the top address in older networks).
pub fn default_resolver_ips(pool: &[IpNet], taken: impl Fn(&IpAddr) -> bool) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for v6 in [false, true] {
        let Some(net) = pool.iter().find(|p| p.addr().is_ipv6() == v6) else {
            continue;
        };
        if let Some(ip) = net.hosts().rev().take(256).find(|ip| !taken(ip)) {
            out.push(ip);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Cluster;

    #[test]
    fn node_by_ip_takes_hosts_then_the_longest_prefix() {
        let mut c = Cluster::new();
        let (a, _) = c.data_node("a", "10.7.0.5", &[]);
        let st = c.store();
        let v = st.view();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(v.node_by_ip(&ip("10.7.0.5")), Some(a));
        assert_eq!(v.node_by_ip(&ip("10.7.0.6")), None);
        // Wider prefixes: the longest wins, whatever the order they came in.
        let mut v = v.clone();
        let (wide, narrow) = ([1u8; 32], [2u8; 32]);
        v.ip_routes = vec![
            ("10.9.0.0/16".parse().unwrap(), wide),
            ("10.9.1.0/24".parse().unwrap(), narrow),
        ];
        v.ip_routes
            .sort_by_key(|(net, id)| (std::cmp::Reverse(net.prefix_len()), *id));
        assert_eq!(v.node_by_ip(&ip("10.9.1.7")), Some(narrow));
        assert_eq!(v.node_by_ip(&ip("10.9.2.7")), Some(wide));
        assert_eq!(v.node_by_ip(&ip("10.7.0.5")), Some(a));
    }

    /// A head from the cluster's signing key over `tree`, newer than any
    /// the cluster has signed: what a compromised head signer could send.
    fn forged_head(c: &Cluster, tree: &mut Tree) -> Vec<u8> {
        let head = wp::SignedTreeHead {
            signing_key_id: Some(crypto::k32(&crypto::signing_key_id(&c.head_key.public()))),
            version: c.machine.last_index + 10,
            root: Some(crypto::k32(&tree.root())),
            state_version: 1,
            issued_at: now_ms(),
            expires_at: now_ms() + 3_600_000,
        };
        c.head_key.sign_obj(mt::SIGNED_TREE_HEAD, &head)
    }

    /// A node, its record leaf as first enrolled, and a store that has seen
    /// the node revoked.
    fn revoked_node() -> (Cluster, Bytes32, Vec<u8>, Store) {
        let mut c = Cluster::new();
        let (id, _) = c.data_node("a", "10.7.0.5", &[]);
        let record = c.machine.tree.get(kind::NODE, &id).unwrap().bytes.clone();
        c.admin_op(webjet_proto::AccountOp::TombstoneNode(Box::new(
            wp::TombstoneNode {
                node_id: Some(crypto::k32(&id)),
                reason: None,
            },
        )))
        .unwrap();
        let st = c.store();
        assert!(!st.view().nodes.get(&id).is_some_and(|n| n.valid));
        (c, id, record, st)
    }

    #[test]
    fn a_tombstone_cannot_be_removed() {
        let (c, id, _, mut st) = revoked_node();
        let mut t = st.tree().clone();
        t.remove(kind::NODE, &id);
        let head = forged_head(&c, &mut t);
        let e = st.install(&head, vec![(kind::NODE, id, None)]).unwrap_err();
        assert!(e.to_string().contains("can't be removed"), "{e}");
        assert!(st.tree().get(kind::NODE, &id).is_some());
    }

    #[test]
    fn a_tombstone_cannot_be_replaced_even_after_removing_it() {
        let (c, id, record, mut st) = revoked_node();
        let mut t = st.tree().clone();
        t.insert(kind::NODE, id, record.clone());
        let head = forged_head(&c, &mut t);
        // Directly...
        let e = st
            .install(&head, vec![(kind::NODE, id, Some(record.clone()))])
            .unwrap_err();
        assert!(e.to_string().contains("can't be replaced"), "{e}");
        // ...or removed first in the same sync.
        let e = st
            .install(
                &head,
                vec![(kind::NODE, id, None), (kind::NODE, id, Some(record))],
            )
            .unwrap_err();
        assert!(e.to_string().contains("can't be removed"), "{e}");
    }

    #[test]
    fn a_leaf_may_appear_once_per_sync() {
        let mut c = Cluster::new();
        let (id, _) = c.data_node("a", "10.7.0.5", &[]);
        let mut st = c.store();
        let record = st.tree().get(kind::NODE, &id).unwrap().bytes.clone();
        let mut t = st.tree().clone();
        let head = forged_head(&c, &mut t);
        let e = st
            .install(
                &head,
                vec![
                    (kind::NODE, id, Some(record.clone())),
                    (kind::NODE, id, Some(record)),
                ],
            )
            .unwrap_err();
        assert!(e.to_string().contains("listed twice"), "{e}");
    }

    #[test]
    fn ordinary_leaves_are_still_removed_and_resent_unchanged() {
        let mut c = Cluster::new();
        let (id, _) = c.data_node("a", "10.7.0.5", &[]);
        c.set_node_config(wp::NodeConfig {
            node_id: Some(crypto::k32(&id)),
            limits: Some(vec![wp::LimitValue {
                name: Some("circuits_global".into()),
                value: 7,
            }]),
            ..Default::default()
        })
        .unwrap();
        let mut st = c.store();
        assert!(st.tree().get(kind::NODE_CONFIG, &id).is_some());
        // Revoking the node removes its configuration leaf; the sync sends
        // every leaf, unchanged ones included.
        c.admin_op(webjet_proto::AccountOp::TombstoneNode(Box::new(
            wp::TombstoneNode {
                node_id: Some(crypto::k32(&id)),
                reason: None,
            },
        )))
        .unwrap();
        c.sync(&mut st);
        assert!(st.tree().get(kind::NODE_CONFIG, &id).is_none());
        // The same tree again is accepted.
        c.sync(&mut st);
    }
}
