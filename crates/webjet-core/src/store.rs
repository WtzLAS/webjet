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
    pub ip_routes: Vec<(IpNet, Bytes32)>,
    pub accounts: HashMap<Bytes32, AccountInfo>,
    pub tombstoned_accounts: HashSet<Bytes32>,
    pub policy: Policy,
    pub policy_version: u64,
    /// The policy as committed (for `policy show`).
    pub policy_wire: Option<wp::Policy>,
    pub dns: Option<wp::DnsConfig>,
    pub seeds: Option<wp::Seeds>,
    pub limits: Option<wp::Limits>,
    pub transport: Option<wp::TransportConfig>,
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
        self.ip_routes
            .iter()
            .filter(|(n, _)| n.contains(ip))
            .max_by_key(|(n, _)| n.prefix_len())
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
        self.controllers
            .get(id)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
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

    /// Effective value of a limit for a node (§16.4): built-in default
    /// (`validate::LIMITS`), then tree defaults, then the highest matching
    /// override. `None` for a limit that is unset by default and not set.
    pub fn limit(&self, me: Option<&Subject>, name: &str) -> Option<u64> {
        let builtin = crate::validate::limit_default(name);
        let Some(l) = &self.limits else {
            return builtin;
        };
        let mut v = builtin;
        for d in l.defaults.clone().unwrap_or_default() {
            if d.name.as_deref() == Some(name) {
                v = Some(d.value);
            }
        }
        if let Some(me) = me {
            let mut best: Option<u64> = None;
            for o in l.overrides.clone().unwrap_or_default() {
                let sels: Vec<_> = o
                    .select
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|s| crate::policy::Selector::parse(s).ok())
                    .collect();
                let pol = Policy {
                    version: 0,
                    default: crate::policy::Decision::Deny,
                    rules: vec![crate::policy::Rule {
                        id: "x".into(),
                        action: crate::policy::Decision::Allow,
                        src: sels,
                        dst: vec![crate::policy::Selector::Any],
                        ports: crate::policy::PortSet::all(),
                    }],
                    tests: vec![],
                };
                if pol
                    .evaluate(me, crate::policy::Dest::Node(me), 6, 1)
                    .decision
                    == crate::policy::Decision::Allow
                {
                    for x in o.values.clone().unwrap_or_default() {
                        if x.name.as_deref() == Some(name) {
                            best = Some(best.map_or(x.value, |b: u64| b.max(x.value)));
                        }
                    }
                }
            }
            if let Some(b) = best {
                v = Some(b);
            }
        }
        v
    }
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
        if h.issued_at > now_ms() + SKEW_HEAD {
            bail!("tree head issued in the future");
        }
        Ok(h)
    }

    /// Offer a tree head (§10.2, §10.3).
    pub fn offer_head(&mut self, raw: &[u8]) -> Result<HeadOutcome> {
        let h = self.verify_head(raw)?;
        let now = now_ms();
        if h.expires_at + SKEW_HEAD < now {
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
        let mut t = self.tree.clone();
        for (k, key, bytes) in &updates {
            match bytes {
                Some(b) => {
                    let new = leaf::decode(*k, key, b)?;
                    if let Some(old) = t.get(*k, key)
                        && let Ok(oldv) = leaf::decode(*k, key, &old.bytes)
                    {
                        let tomb_old = matches!(
                            oldv,
                            LeafValue::NodeTombstone(_) | LeafValue::AccountTombstone(..)
                        );
                        if tomb_old {
                            bail!("a tombstone can't be replaced");
                        }
                        if *k != kind::VALIDITY
                            && leaf::version(&new) <= leaf::version(&oldv)
                            && old.bytes != *b
                        {
                            bail!("leaf version went backwards");
                        }
                    }
                    t.insert(*k, *key, b.clone());
                }
                None => t.remove(*k, key),
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
            Some(h) => h.head.expires_at + SKEW_HEAD < now,
            None => true,
        }
    }

    /// Records are trusted only until the validity horizon (§6.16).
    pub fn horizon_passed(&self, now: u64) -> bool {
        self.view.valid_until == 0 || self.view.valid_until + SKEW_HEAD < now
    }

    /// The node is trusted right now: valid record, no tombstone, owner
    /// valid, validity horizon not passed (§9.2).
    pub fn node_trusted(&self, id: &Bytes32) -> bool {
        !self.horizon_passed(now_ms()) && self.view.nodes.get(id).map(|n| n.valid).unwrap_or(false)
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
    // Accounts first: signature and signer checks (§6.10, §10.2).
    let mut raw_accounts: Vec<(wp::AccountRecord, crypto::Verified)> = Vec::new();
    for (_, e) in tree.iter() {
        if e.kind == kind::ACCOUNT {
            match leaf::decode(e.kind, &e.key, &e.bytes) {
                Ok(LeafValue::Account(r, ver)) => raw_accounts.push((r, ver)),
                Ok(LeafValue::AccountTombstone(t, ver)) => {
                    let id = crypto::opt_k32(&t.account_id);
                    let _ = ver;
                    v.tombstoned_accounts.insert(id);
                }
                _ => {}
            }
        }
    }
    // Offline account tombstones, with `revoke_issued` cascades.
    let mut revoke_issuers: HashSet<Bytes32> = HashSet::new();
    for (id, (t, _)) in offline_acct_tombs {
        v.tombstoned_accounts.insert(*id);
        if t.revoke_issued {
            revoke_issuers.insert(*id);
        }
    }
    for (_, e) in tree.iter() {
        if e.kind == kind::ACCOUNT
            && let Ok(LeafValue::AccountTombstone(t, _)) = leaf::decode(e.kind, &e.key, &e.bytes)
            && t.revoke_issued
        {
            revoke_issuers.insert(crypto::opt_k32(&t.account_id));
        }
    }
    // Admin accounts (root-signed) first, then normal accounts.
    for pass in 0..2 {
        for (r, ver) in &raw_accounts {
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
                let iss = v.accounts.get(&issuer);
                let issuer_ok = iss
                    .map(|a| a.admin && (a.valid || !revoke_issuers.contains(&issuer)))
                    .unwrap_or(false)
                    && !revoke_issuers.contains(&issuer);
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
    // Nodes and singletons.
    for (_, e) in tree.iter() {
        let Ok(val) = leaf::decode(e.kind, &e.key, &e.bytes) else {
            tracing::warn!("undecodable leaf of kind {} in the tree", e.kind);
            continue;
        };
        match val {
            LeafValue::Node(r) => {
                let id = crypto::opt_k32(&r.node_id);
                let roles = r.roles.clone().unwrap_or_default();
                let owner = crypto::opt_k32(&r.owner);
                let offline_tomb = offline_node_tombs
                    .get(&id)
                    .map(|(t, _)| t.version > r.version)
                    .unwrap_or(false);
                let owner_ok = v.accounts.get(&owner).map(|a| a.valid).unwrap_or(false);
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
                if offline_tomb {
                    v.tombstoned_nodes.insert(id);
                }
                v.nodes.insert(id, info);
            }
            LeafValue::NodeTombstone(t) => {
                v.tombstoned_nodes.insert(crypto::opt_k32(&t.node_id));
            }
            LeafValue::Policy(p) => match Policy::from_wire(&p) {
                Ok(pol) => {
                    v.policy_version = p.version;
                    v.policy = pol;
                    v.policy_wire = Some(p);
                }
                Err(e) => tracing::error!("policy in the tree does not parse: {e}"),
            },
            LeafValue::Dns(d) => v.dns = Some(d),
            LeafValue::Seeds(s) => v.seeds = Some(s),
            LeafValue::Limits(l) => v.limits = Some(l),
            LeafValue::Transport(t) => v.transport = Some(t),
            LeafValue::Validity(val) => v.valid_until = val.valid_until,
            LeafValue::Account(..) | LeafValue::AccountTombstone(..) => {}
        }
    }
    for n in v.nodes.values() {
        v.by_key.insert(n.key, n.id);
        v.by_name.insert(n.name.clone(), n.id);
        if n.valid {
            for ip in &n.ips {
                v.ip_routes.push((*ip, n.id));
            }
        }
    }
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
    for n in v.nodes.values_mut() {
        n.control = v.controllers.contains_key(&n.id);
    }
    v
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
pub(crate) mod testutil {
    use super::*;
    use crate::crypto::KeyPair;
    use webjet_proto::Encodable;

    pub struct Net {
        pub root: KeyPair,
        pub emergency: KeyPair,
        pub admin: KeyPair,
        pub admin_id: Bytes32,
        pub genesis: Vec<u8>,
    }

    pub fn net() -> Net {
        let root = KeyPair::generate();
        let emergency = KeyPair::generate();
        let admin = KeyPair::generate();
        let admin_id = crypto::random32();
        let rec = wp::AccountRecord {
            account_id: Some(crypto::k32(&admin_id)),
            account_key: Some(crypto::k32(&admin.public())),
            name: Some("alice".into()),
            admin: true,
            issuer_root: true,
            issuer: None,
            version: 1,
        };
        let g = wp::Genesis {
            root_key: Some(crypto::k32(&root.public())),
            emergency_cert: Some(root.sign_obj(
                mt::EMERGENCY_KEY_CERT,
                &wp::EmergencyKeyCert {
                    key: Some(crypto::k32(&emergency.public())),
                },
            )),
            first_admin: Some(root.sign_obj(mt::ACCOUNT_RECORD, &rec)),
            overlay_pool: Some(vec![crate::types::net_to_cidr(
                &"10.7.0.0/16".parse().unwrap(),
            )]),
            created_at: now_ms(),
        };
        Net {
            root,
            emergency,
            admin,
            admin_id,
            genesis: g.encode_bytes(),
        }
    }
}
