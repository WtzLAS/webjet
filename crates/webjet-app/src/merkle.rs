//! The Merkle tab's data, GUI-free: the state tree rebuilt from the agent's
//! leaves (`merkle` on the control channel) and checked against the signed
//! tree head, each leaf decoded with who signed it, and the controllers'
//! operation log (`log`, admins only) with names for every key.

use crate::model::Snapshot;
use serde::Deserialize;
use std::collections::BTreeMap;
use webjet_core::crypto::{self, Bytes32};
use webjet_core::leaf::{self, LeafValue};
use webjet_core::merkle::{self, Proof, Tree, kind};
use webjet_proto as wp;

// ---------------------------------------------------------------- wire

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct HeadWire {
    pub version: u64,
    pub root: String,
    pub signing_key_id: String,
    /// The node id of the controller whose key signed the head.
    pub controller: Option<String>,
    pub state_version: u32,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct GenesisWire {
    pub root_key: String,
    pub emergency_key: Option<String>,
    pub created_at: u64,
    pub first_admin: Option<String>,
}

/// A controller's signing-key certificate.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct CertWire {
    pub signing_key_id: String,
    pub signing_key: String,
    pub controller: String,
    pub serial: u64,
    /// The admin account that signed it; `None`: the root key did.
    pub issuer: Option<String>,
    pub issuer_key: Option<String>,
    pub valid: bool,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct KeyTombWire {
    pub signing_key_id: String,
    pub last_valid_version: u64,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct LeafWire {
    pub kind: u8,
    pub key: String,
    /// Base64 leaf bytes.
    pub bytes: String,
}

/// The agent's answer to `merkle`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct MerkleWire {
    /// "head": the node's verified tree; "controller": a controller's own
    /// state, which may be ahead of the signed head.
    pub source: String,
    pub head: Option<HeadWire>,
    pub genesis: GenesisWire,
    pub certs: Vec<CertWire>,
    pub key_tombstones: Vec<KeyTombWire>,
    pub leaves: Vec<LeafWire>,
}

/// A tree leaf an operation wrote (`log`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct LogLeaf {
    pub kind: u8,
    pub key: Option<String>,
    pub hash: Option<String>,
    pub deleted: bool,
}

/// One committed log entry.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct LogRecord {
    pub index: u64,
    pub term: u64,
    /// When the leader proposed it (Unix ms).
    pub timestamp: u64,
    pub payload: Option<String>,
    pub op: Option<String>,
    /// Base64 key that signed the operation.
    pub signer_key: Option<String>,
    /// The account (hex id) of a SignedOp.
    pub account_id: Option<String>,
    pub op_seq: u64,
    /// When the signer issued it (Unix ms).
    pub issued_at: u64,
    pub description: Option<String>,
    pub leaves: Vec<LogLeaf>,
}

impl LogRecord {
    /// Case-insensitive match on the operation, its description, the
    /// signer's name or the index.
    pub fn matches(&self, filter: &str, names: &Names) -> bool {
        let f = filter.trim().to_ascii_lowercase();
        if f.is_empty() {
            return true;
        }
        let has = |s: &str| s.to_ascii_lowercase().contains(&f);
        self.index.to_string() == f
            || self.op.as_deref().is_some_and(has)
            || self.payload.as_deref().is_some_and(has)
            || self.description.as_deref().is_some_and(has)
            || has(&self.signer(names))
    }

    /// Who signed the entry, in words.
    pub fn signer(&self, names: &Names) -> String {
        match (&self.signer_key, &self.account_id) {
            (Some(k), _) => names.key(k),
            (None, Some(a)) => names.account(a),
            (None, None) => match self.payload.as_deref() {
                Some("NoopEntry")
                | Some("ExtendValidityEntry")
                | Some("ExpireEnrollmentsEntry") => "the controllers".into(),
                _ => "—".into(),
            },
        }
    }

    /// The operation's name: the signed operation, else the entry type.
    pub fn title(&self) -> String {
        match (&self.op, &self.payload) {
            (Some(o), _) => o.clone(),
            (None, Some(p)) => p.trim_end_matches("Entry").to_string(),
            (None, None) => "unknown".into(),
        }
    }
}

/// A page of the operation log (`log`), oldest first.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct LogPage {
    /// Oldest entry still in the log; older ones were compacted into a snapshot.
    pub first_index: u64,
    pub commit_index: u64,
    pub records: Vec<LogRecord>,
}

impl LogPage {
    /// Add an older page in front of this one.
    pub fn prepend(&mut self, older: LogPage) {
        let first = self.records.first().map_or(u64::MAX, |r| r.index);
        let mut v: Vec<LogRecord> = older
            .records
            .into_iter()
            .filter(|r| r.index < first)
            .collect();
        v.append(&mut self.records);
        self.records = v;
        self.first_index = older.first_index;
    }

    /// Merge a fresh page of the newest entries with what was shown: the
    /// old entries stay in front when they join up with the new ones,
    /// unless compaction removed them meanwhile.
    pub fn refreshed(mut newest: LogPage, shown: LogPage) -> LogPage {
        let joins = match (shown.records.last(), newest.records.first()) {
            (Some(o), Some(n)) => o.index + 1 >= n.index,
            _ => false,
        };
        if joins {
            let first = newest.first_index;
            newest.prepend(shown);
            newest.records.retain(|r| r.index >= first);
            newest.first_index = first;
        }
        newest
    }

    /// More entries exist before the oldest one shown.
    pub fn has_older(&self) -> bool {
        self.records
            .first()
            .is_some_and(|r| r.index > self.first_index)
    }
}

// ---------------------------------------------------------------- names

/// Names for keys and ids: accounts, nodes, the root and emergency keys,
/// controllers' signing keys.
#[derive(Clone, Debug, Default)]
pub struct Names {
    keys: BTreeMap<String, String>,
    accounts: BTreeMap<String, String>,
    nodes: BTreeMap<String, String>,
}

impl Names {
    pub fn new(s: &Snapshot, w: Option<&MerkleWire>) -> Names {
        let mut n = Names::default();
        for a in &s.accounts {
            let what = if a.admin { "admin" } else { "account" };
            n.keys.insert(a.key.clone(), format!("{what} {}", a.name));
            n.accounts.insert(a.id.clone(), a.name.clone());
        }
        for x in &s.nodes {
            n.keys.insert(x.key.clone(), format!("node {}", x.name));
            n.nodes.insert(x.id.clone(), x.name.clone());
        }
        if let Some(w) = w {
            n.keys
                .insert(w.genesis.root_key.clone(), "the root key".into());
            if let Some(e) = &w.genesis.emergency_key {
                n.keys.insert(e.clone(), "the emergency key".into());
            }
            for c in &w.certs {
                let who = n.node(&c.controller);
                n.keys
                    .insert(c.signing_key.clone(), format!("signing key of {who}"));
            }
        }
        n
    }

    /// A base64 key in words, or its first characters.
    pub fn key(&self, k: &str) -> String {
        self.keys
            .get(k)
            .cloned()
            .unwrap_or_else(|| format!("key {}…", k.get(..10).unwrap_or(k)))
    }

    pub fn key_bytes(&self, k: &Bytes32) -> String {
        self.key(&crypto::key_b64(k))
    }

    /// An account's name by hex id.
    pub fn account(&self, id: &str) -> String {
        self.accounts
            .get(id)
            .cloned()
            .unwrap_or_else(|| format!("account {}", crate::model::short(id)))
    }

    /// A node's name by hex id.
    pub fn node(&self, id: &str) -> String {
        self.nodes
            .get(id)
            .cloned()
            .unwrap_or_else(|| format!("node {}", crate::model::short(id)))
    }

    /// What a leaf key names, for a leaf of `kind`.
    pub fn leaf_key(&self, k: u8, key: &str) -> String {
        match k {
            kind::NODE | kind::NODE_CONFIG => self.node(key),
            kind::ACCOUNT => self.account(key),
            _ => kind_name(k).to_string(),
        }
    }
}

// ---------------------------------------------------------------- leaves

pub fn kind_name(k: u8) -> &'static str {
    match k {
        kind::NODE => "node",
        kind::ACCOUNT => "account",
        kind::POLICY => "policy",
        kind::DNS => "dns",
        kind::SEEDS => "seeds",
        kind::LIMITS => "limits",
        kind::VALIDITY => "validity",
        kind::TRANSPORT => "transport",
        kind::NODE_CONFIG => "node config",
        kind::CONTROLLERS => "controllers",
        _ => "unknown",
    }
}

/// Who vouches for a leaf.
#[derive(Clone, Debug, PartialEq)]
pub enum Signer {
    /// Built by the controllers; only the tree head's signature covers it.
    Controllers,
    /// Carries its own signature (account leaves).
    Key { key: String, who: String },
}

/// One decoded leaf.
#[derive(Clone, Debug, PartialEq)]
pub struct Leaf {
    pub path: Bytes32,
    pub kind: u8,
    pub key: Bytes32,
    pub hash: Bytes32,
    pub size: usize,
    /// The record type inside, e.g. "NodeRecord" or "AccountTombstone".
    pub record: String,
    pub version: u64,
    /// The leaf in a few words, e.g. the node's name.
    pub title: String,
    pub signer: Signer,
    pub fields: Vec<(String, String)>,
    /// The bytes didn't decode.
    pub error: Option<String>,
}

impl Leaf {
    pub fn bucket(&self) -> u8 {
        self.path[0]
    }

    pub fn matches(&self, filter: &str) -> bool {
        let f = filter.trim().to_ascii_lowercase();
        if f.is_empty() {
            return true;
        }
        let has = |s: &str| s.to_ascii_lowercase().contains(&f);
        has(&self.title)
            || has(&self.record)
            || has(kind_name(self.kind))
            || hex::encode(self.hash).starts_with(&f)
            || hex::encode(self.key).starts_with(&f)
            || match &self.signer {
                Signer::Key { who, .. } => has(who),
                Signer::Controllers => false,
            }
    }
}

fn opt_hex(k: &Option<wp::Key32>) -> String {
    k.map(|k| hex::encode(k.to_bytes())).unwrap_or_default()
}

fn opt_b64(k: &Option<wp::Key32>) -> String {
    k.map(|k| crypto::key_b64(&k.to_bytes()))
        .unwrap_or_default()
}

fn list(v: &[String]) -> String {
    if v.is_empty() {
        "—".into()
    } else {
        v.join(", ")
    }
}

fn decode_leaf(k: u8, key: Bytes32, bytes: &[u8], names: &Names) -> Leaf {
    let mut l = Leaf {
        path: merkle::path_of(k, &key),
        kind: k,
        key,
        hash: merkle::leaf_hash(k, &key, bytes),
        size: bytes.len(),
        record: String::new(),
        version: 0,
        title: names.leaf_key(k, &hex::encode(key)),
        signer: Signer::Controllers,
        fields: Vec::new(),
        error: None,
    };
    let v = match leaf::decode(k, &key, bytes) {
        Ok(v) => v,
        Err(e) => {
            l.record = "undecodable".into();
            l.error = Some(format!("{e:#}"));
            return l;
        }
    };
    l.version = leaf::version(&v);
    let mut f: Vec<(String, String)> = Vec::new();
    let mut put = |k: &str, v: String| f.push((k.to_string(), v));
    match &v {
        LeafValue::Node(r) => {
            l.record = "NodeRecord".into();
            if let Some(n) = &r.name {
                l.title = n.clone();
            }
            put("Identity key", opt_b64(&r.identity_key));
            put(
                "Addresses",
                list(
                    &r.overlay_ips
                        .iter()
                        .flatten()
                        .filter_map(|c| c.addr().map(|a| format!("{a}/{}", c.prefix)))
                        .collect::<Vec<_>>(),
                ),
            );
            let mut roles: Vec<String> = r
                .roles
                .iter()
                .flatten()
                .map(|r| format!("{r:?}").to_ascii_lowercase())
                .collect();
            if r.control == Some(true) {
                roles.push("control".into());
            }
            put("Roles", list(&roles));
            put("Owner", names.account(&opt_hex(&r.owner)));
            put("Tags", list(r.tags.as_deref().unwrap_or_default()));
            put(
                "Subnet routes",
                r.routes.as_ref().map_or(0, |v| v.len()).to_string(),
            );
        }
        LeafValue::NodeTombstone(t) => {
            l.record = "Tombstone".into();
            l.title = format!("{} (revoked)", l.title);
            put("Reason", t.reason.clone().unwrap_or_else(|| "—".into()));
        }
        LeafValue::Account(r, sig) => {
            l.record = "AccountRecord".into();
            if let Some(n) = &r.name {
                l.title = n.clone();
            }
            put("Account key", opt_b64(&r.account_key));
            put("Admin", if r.admin { "yes" } else { "no" }.into());
            put(
                "Issued by",
                if r.issuer_root {
                    "the root key".into()
                } else {
                    format!("admin {}", names.account(&opt_hex(&r.issuer)))
                },
            );
            l.signer = Signer::Key {
                key: crypto::key_b64(&sig.signer),
                who: names.key_bytes(&sig.signer),
            };
        }
        LeafValue::AccountTombstone(t, sig) => {
            l.record = "AccountTombstone".into();
            l.title = format!("{} (revoked)", l.title);
            put("Reason", t.reason.clone().unwrap_or_else(|| "—".into()));
            put(
                "Revokes what it issued",
                if t.revoke_issued { "yes" } else { "no" }.into(),
            );
            l.signer = Signer::Key {
                key: crypto::key_b64(&sig.signer),
                who: names.key_bytes(&sig.signer),
            };
        }
        LeafValue::Policy(p) => {
            l.record = "Policy".into();
            put("Default", format!("{:?}", p.default_action).to_lowercase());
            put("Rules", p.rules.as_ref().map_or(0, |v| v.len()).to_string());
            put("Tests", p.tests.as_ref().map_or(0, |v| v.len()).to_string());
        }
        LeafValue::Dns(d) => {
            l.record = "DnsConfig".into();
            put("Suffix", d.suffix.clone().unwrap_or_else(|| "—".into()));
            put(
                "Records",
                d.records.as_ref().map_or(0, |v| v.len()).to_string(),
            );
            put(
                "Forward zones",
                d.forward.as_ref().map_or(0, |v| v.len()).to_string(),
            );
        }
        LeafValue::Seeds(s) => {
            l.record = "Seeds".into();
            put(
                "Seeds",
                list(
                    &s.entries
                        .iter()
                        .flatten()
                        .filter_map(|e| e.node.clone())
                        .collect::<Vec<_>>(),
                ),
            );
        }
        LeafValue::Limits(x) => {
            l.record = "Limits".into();
            put(
                "Defaults",
                list(
                    &x.defaults
                        .iter()
                        .flatten()
                        .map(|v| format!("{}={}", v.name.as_deref().unwrap_or("?"), v.value))
                        .collect::<Vec<_>>(),
                ),
            );
            put(
                "Overrides",
                x.overrides.as_ref().map_or(0, |v| v.len()).to_string(),
            );
        }
        LeafValue::Validity(v) => {
            l.record = "Validity".into();
            put("Valid until", utc(v.valid_until));
        }
        LeafValue::Transport(t) => {
            l.record = "TransportConfig".into();
            put(
                "Camouflage",
                t.camouflage.as_ref().map_or_else(
                    || "—".into(),
                    |c| {
                        format!("{:?} {}", c.mode, c.domain.clone().unwrap_or_default())
                            .to_lowercase()
                    },
                ),
            );
        }
        LeafValue::NodeConfig(c) => {
            l.record = "NodeConfig".into();
            put(
                "Overrides",
                format!(
                    "{} priorities · {} limits · {} seeds · {} DNS records",
                    c.priorities.as_ref().map_or(0, |v| v.len()),
                    c.limits.as_ref().map_or(0, |v| v.len()),
                    c.seeds.as_ref().map_or(0, |v| v.len()),
                    c.dns_records.as_ref().map_or(0, |v| v.len()),
                ),
            );
        }
        LeafValue::Controllers(c) => {
            l.record = "ControllerSettings".into();
            let s = webjet_core::membership::Settings::of(Some(c));
            put("Automatic membership", s.auto_membership.to_string());
            put("Voters", s.voters.to_string());
            put(
                "Dead voter after",
                if s.dead_voter_after_s == 0 {
                    "never".into()
                } else {
                    format!("{} s", s.dead_voter_after_s)
                },
            );
        }
        LeafValue::Unknown => {
            l.record = format!("unknown kind {k}");
        }
    }
    l.fields = f;
    l
}

// ---------------------------------------------------------------- the tree

/// A subtree at depth 8 (`merkle::BUCKET_DEPTH`), as gossip compares them.
#[derive(Clone, Debug, PartialEq)]
pub struct Bucket {
    pub hash: Bytes32,
    pub leaves: usize,
}

/// One step of an inclusion proof, from the leaf up.
#[derive(Clone, Debug, PartialEq)]
pub struct ProofStep {
    /// Depth of the sibling (256 = next to the leaf, 1 = under the root).
    pub depth: usize,
    /// The path goes right at this level (the sibling is on the left).
    pub right: bool,
    pub sibling: Bytes32,
}

#[derive(Clone, Debug, Default)]
pub struct Merkle {
    pub wire: MerkleWire,
    pub tree: Tree,
    /// The root of the leaves as received.
    pub root: Bytes32,
    /// Sorted by path, as the tree orders them.
    pub leaves: Vec<Leaf>,
    pub buckets: Vec<Bucket>,
    /// Leaves whose key didn't parse (dropped).
    pub bad: usize,
}

impl Merkle {
    pub fn new(w: MerkleWire, names: &Names) -> Merkle {
        let mut tree = Tree::new();
        let mut leaves = Vec::with_capacity(w.leaves.len());
        let mut bad = 0;
        for lw in &w.leaves {
            let (Some(key), Ok(bytes)) = (
                crypto::parse_hex32(&lw.key),
                webjetd::state::unb64(&lw.bytes),
            ) else {
                bad += 1;
                continue;
            };
            leaves.push(decode_leaf(lw.kind, key, &bytes, names));
            tree.insert(lw.kind, key, bytes);
        }
        leaves.sort_by_key(|l| l.path);
        let root = tree.root();
        let hashes = tree.buckets();
        let mut counts = [0usize; 256];
        for l in &leaves {
            counts[usize::from(l.bucket())] += 1;
        }
        let buckets = hashes
            .into_iter()
            .zip(counts)
            .map(|(hash, leaves)| Bucket { hash, leaves })
            .collect();
        Merkle {
            wire: w,
            tree,
            root,
            leaves,
            buckets,
            bad,
        }
    }

    /// The root the signed tree head commits to, if there is a head.
    pub fn head_root(&self) -> Option<Bytes32> {
        self.wire
            .head
            .as_ref()
            .and_then(|h| crypto::parse_hex32(&h.root))
    }

    /// The leaves hash to the signed head's root.
    pub fn matches_head(&self) -> bool {
        self.head_root() == Some(self.root)
    }

    pub fn leaf(&self, path: &Bytes32) -> Option<&Leaf> {
        self.leaves
            .binary_search_by(|l| l.path.cmp(path))
            .ok()
            .map(|i| &self.leaves[i])
    }

    /// The leaf of `kind` under `key` (hex), if in the tree.
    pub fn find(&self, k: u8, key: &str) -> Option<&Leaf> {
        let key = crypto::parse_hex32(key)?;
        self.leaf(&merkle::path_of(k, &key))
    }

    /// The inclusion proof of a leaf, its non-empty steps from the leaf up,
    /// and whether it verifies against `root`.
    pub fn proof(&self, l: &Leaf) -> (Vec<ProofStep>, bool) {
        let p: Proof = self.tree.prove_path(&l.path);
        let ok = merkle::root_from_proof(&l.path, Some(l.hash), &p) == Some(self.root);
        let mut steps = Vec::new();
        let mut sib = p.siblings.iter();
        for i in 0..merkle::DEPTH {
            if (p.bitmap.get(i / 8).copied().unwrap_or(0) >> (i % 8)) & 1 == 1 {
                let depth = merkle::DEPTH - i;
                let bit = depth - 1;
                let right = (l.path[bit / 8] >> (7 - (bit % 8))) & 1 == 1;
                if let Some(s) = sib.next() {
                    steps.push(ProofStep {
                        depth,
                        right,
                        sibling: *s,
                    });
                }
            }
        }
        (steps, ok)
    }

    /// How many leaves of each kind.
    pub fn kinds(&self) -> Vec<(&'static str, usize)> {
        let mut m: BTreeMap<u8, usize> = BTreeMap::new();
        for l in &self.leaves {
            *m.entry(l.kind).or_default() += 1;
        }
        m.into_iter().map(|(k, n)| (kind_name(k), n)).collect()
    }
}

// ---------------------------------------------------------------- time

/// "2025-06-01 12:34:56 UTC" for Unix milliseconds.
pub fn utc(ms: u64) -> String {
    if ms == 0 {
        return "—".into();
    }
    let secs = ms / 1000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Account, Node};
    use webjet_core::crypto::KeyPair;
    use webjet_proto::Encodable;

    fn b64(b: &[u8]) -> String {
        webjetd::state::b64(b)
    }

    fn wire() -> (MerkleWire, KeyPair, KeyPair) {
        let root = KeyPair::generate();
        let admin = KeyPair::generate();
        let node = wp::NodeRecord {
            node_id: Some(crypto::k32(&[1; 32])),
            identity_key: Some(crypto::k32(&[5; 32])),
            name: Some("laptop".into()),
            owner: Some(crypto::k32(&[2; 32])),
            roles: Some(vec![wp::Role::Data]),
            version: 3,
            ..Default::default()
        };
        let acct = wp::AccountRecord {
            account_id: Some(crypto::k32(&[2; 32])),
            account_key: Some(crypto::k32(&admin.public())),
            name: Some("alice".into()),
            admin: true,
            issuer_root: true,
            version: 1,
            ..Default::default()
        };
        let acct_leaf = root.sign_obj(wp::msg_type::ACCOUNT_RECORD, &acct);
        let mut leaves = vec![
            LeafWire {
                kind: kind::NODE,
                key: hex::encode([1; 32]),
                bytes: b64(&leaf::encode_node(&node)),
            },
            LeafWire {
                kind: kind::ACCOUNT,
                key: hex::encode([2; 32]),
                bytes: b64(&acct_leaf),
            },
            LeafWire {
                kind: kind::VALIDITY,
                key: hex::encode(leaf::SINGLETON),
                bytes: b64(&leaf::encode_validity(&wp::Validity {
                    valid_until: 86_400_000,
                })),
            },
        ];
        // Not a leaf this kind accepts: shown as undecodable, still hashed.
        leaves.push(LeafWire {
            kind: kind::POLICY,
            key: hex::encode(leaf::SINGLETON),
            bytes: b64(&wp::Validity::default().encode_bytes()),
        });
        let mut t = Tree::new();
        for l in &leaves {
            t.insert(
                l.kind,
                crypto::parse_hex32(&l.key).unwrap(),
                webjetd::state::unb64(&l.bytes).unwrap(),
            );
        }
        let w = MerkleWire {
            source: "head".into(),
            head: Some(HeadWire {
                version: 9,
                root: hex::encode(t.root()),
                ..Default::default()
            }),
            genesis: GenesisWire {
                root_key: crypto::key_b64(&root.public()),
                ..Default::default()
            },
            leaves,
            ..Default::default()
        };
        (w, root, admin)
    }

    fn snapshot(admin: &KeyPair) -> Snapshot {
        Snapshot {
            accounts: vec![Account {
                id: hex::encode([2; 32]),
                name: "alice".into(),
                admin: true,
                valid: true,
                key: crypto::key_b64(&admin.public()),
                version: 1,
            }],
            nodes: vec![Node {
                id: hex::encode([1; 32]),
                name: "laptop".into(),
                key: crypto::key_b64(&[5; 32]),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn rebuilds_the_tree_and_names_the_signers() {
        let (w, _, admin) = wire();
        let names = Names::new(&snapshot(&admin), Some(&w));
        let m = Merkle::new(w.clone(), &names);
        assert_eq!(m.leaves.len(), 4);
        assert!(m.matches_head(), "the leaves hash to the head's root");
        assert_eq!(m.buckets.len(), 256);
        assert_eq!(m.buckets.iter().map(|b| b.leaves).sum::<usize>(), 4);
        assert!(m.leaves.windows(2).all(|p| p[0].path < p[1].path));

        let node = m.find(kind::NODE, &hex::encode([1; 32])).unwrap();
        assert_eq!((node.title.as_str(), node.version), ("laptop", 3));
        assert_eq!(node.signer, Signer::Controllers);
        assert!(node.fields.contains(&("Owner".into(), "alice".into())));
        assert!(node.fields.contains(&("Roles".into(), "data".into())));

        let acct = m.find(kind::ACCOUNT, &hex::encode([2; 32])).unwrap();
        assert_eq!(acct.record, "AccountRecord");
        match &acct.signer {
            Signer::Key { who, .. } => assert_eq!(who, "the root key"),
            s => panic!("{s:?}"),
        }
        assert!(acct.matches("root key"));
        assert!(!acct.matches("laptop"));

        let bad = m.find(kind::POLICY, &hex::encode(leaf::SINGLETON)).unwrap();
        assert!(bad.error.is_some());

        let v = m
            .find(kind::VALIDITY, &hex::encode(leaf::SINGLETON))
            .unwrap();
        assert_eq!(v.fields[0].1, "1970-01-02 00:00:00 UTC");

        // Every leaf's proof verifies against the root.
        for l in &m.leaves {
            let (steps, ok) = m.proof(l);
            assert!(ok, "{}", l.title);
            assert!(!steps.is_empty());
            assert!(steps.windows(2).all(|p| p[0].depth > p[1].depth), "leaf up");
        }
        assert_eq!(
            m.kinds(),
            vec![("node", 1), ("account", 1), ("policy", 1), ("validity", 1)]
        );

        // A changed leaf no longer matches the head.
        let mut w2 = w;
        w2.leaves.pop();
        let m2 = Merkle::new(w2, &names);
        assert!(!m2.matches_head());
        assert!(
            Merkle::new(MerkleWire::default(), &names)
                .head_root()
                .is_none()
        );
    }

    #[test]
    fn log_records_in_words() {
        let (w, root, admin) = wire();
        let names = Names::new(&snapshot(&admin), Some(&w));
        let r = LogRecord {
            index: 7,
            payload: Some("OpEntry".into()),
            op: Some("RenameNode".into()),
            signer_key: Some(crypto::key_b64(&admin.public())),
            account_id: Some(hex::encode([2; 32])),
            description: Some("rename node 0101 to laptop".into()),
            ..Default::default()
        };
        assert_eq!(r.signer(&names), "admin alice");
        assert_eq!(r.title(), "RenameNode");
        assert!(r.matches("alice", &names));
        assert!(r.matches("rename", &names));
        assert!(r.matches("7", &names));
        assert!(!r.matches("policy", &names));
        let g = LogRecord {
            payload: Some("RootAccountEntry".into()),
            op: Some("AccountRecord".into()),
            signer_key: Some(crypto::key_b64(&root.public())),
            ..Default::default()
        };
        assert_eq!(g.signer(&names), "the root key");
        let noop = LogRecord {
            payload: Some("NoopEntry".into()),
            ..Default::default()
        };
        assert_eq!(
            (noop.signer(&names), noop.title()),
            ("the controllers".into(), "Noop".into())
        );
        assert!(names.key("zzzzzzzzzzzzzz").starts_with("key zzzzzzzzzz"));
        assert_eq!(names.leaf_key(kind::DNS, "00"), "dns");

        // Paging: an older page goes in front, without duplicates.
        let rec = |i| LogRecord {
            index: i,
            ..Default::default()
        };
        let mut p = LogPage {
            first_index: 1,
            commit_index: 10,
            records: vec![rec(8), rec(9), rec(10)],
        };
        assert!(p.has_older());
        p.prepend(LogPage {
            first_index: 1,
            commit_index: 10,
            records: vec![rec(5), rec(6), rec(7), rec(8)],
        });
        let idx: Vec<u64> = p.records.iter().map(|r| r.index).collect();
        assert_eq!(idx, [5, 6, 7, 8, 9, 10]);
        p.prepend(LogPage {
            first_index: 1,
            records: (1..5).map(rec).collect(),
            ..Default::default()
        });
        assert!(!p.has_older());

        // A refresh keeps what joins up, drops what was compacted away,
        // and starts over after a gap.
        let page = |first, idx: std::ops::RangeInclusive<u64>| LogPage {
            first_index: first,
            commit_index: *idx.end(),
            records: idx.map(rec).collect(),
        };
        let r = LogPage::refreshed(page(4, 9..=12), page(1, 1..=10));
        let idx: Vec<u64> = r.records.iter().map(|r| r.index).collect();
        assert_eq!(idx, (4..=12).collect::<Vec<_>>());
        assert_eq!(r.first_index, 4);
        let r = LogPage::refreshed(page(1, 20..=25), page(1, 1..=10));
        assert_eq!(r.records.len(), 6, "gap: only the fresh page");
        assert!(r.has_older());
    }

    #[test]
    fn utc_dates() {
        assert_eq!(utc(0), "—");
        assert_eq!(utc(1_000), "1970-01-01 00:00:01 UTC");
        assert_eq!(utc(951_782_400_000), "2000-02-29 00:00:00 UTC");
        assert_eq!(utc(1_735_689_599_000), "2024-12-31 23:59:59 UTC");
    }
}
