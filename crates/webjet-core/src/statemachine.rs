//! The controller state machine (§7.2, §13.3, §15.5).
//!
//! Every controller applies the same committed log. The leader *prepares*
//! an entry: it stamps the timestamp, picks random values and serializes the
//! resulting leaves into the entry. Every replica (leader included) then
//! *applies* it: it recomputes the expected result from its own state and
//! checks that the leader's leaf bytes decode to exactly that result, then
//! stores the leader's bytes unchanged. A mismatch halts the replica.
//!
//! Rules (§15.5): no wall clock (only `entry.timestamp`), no randomness (only
//! `entry.random`), only ordered maps.

use crate::crypto::{self, open_envelope, open_expect, opt_k32, Bytes32};
use crate::leaf::{self, LeafValue, SINGLETON};
use crate::merkle::{kind, Tree};
use crate::policy::{Policy, Selector};
use crate::store::{build_view, View};
use crate::types::{
    self, canonical, cidr_to_net, overlaps, sort_dedup, valid_name, valid_tag, Grant, MINUTE,
    SKEW_SHORT_RECORD, VALIDITY_PERIOD,
};
use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;
use std::collections::{BTreeMap, BTreeSet};
use webjet_proto::{self as wp, msg_type as mt, AccountOp, Decodable, EntryPayload};

#[derive(Clone, Debug)]
pub struct Pending {
    pub token_hash: Bytes32,
    pub expires_at: u64,
    pub is_rekey: bool,
    pub node_id: Bytes32,
    pub create: Option<wp::CreateEnrollment>,
}

#[derive(Clone, Debug, Default)]
pub struct Membership {
    pub voters: BTreeSet<Bytes32>,
    pub learners: BTreeSet<Bytes32>,
}

impl Membership {
    pub fn contains(&self, id: &Bytes32) -> bool {
        self.voters.contains(id) || self.learners.contains(id)
    }
    pub fn all(&self) -> Vec<Bytes32> {
        self.voters
            .iter()
            .chain(self.learners.iter())
            .copied()
            .collect()
    }
}

/// What a committed entry did, for the audit trail and for callers.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub description: String,
    pub signer: Option<Bytes32>,
    pub node_id: Option<Bytes32>,
    pub membership_changed: bool,
    pub psk_rotated: bool,
}

#[derive(Clone)]
pub struct Machine {
    pub tree: Tree,
    pub genesis: Option<(Vec<u8>, wp::Genesis)>,
    pub root_key: Bytes32,
    pub emergency_key: Option<Bytes32>,
    pub pool: Vec<IpNet>,
    pub pending: BTreeMap<Bytes32, Pending>,
    pub op_seqs: BTreeMap<Bytes32, u64>,
    pub psk_epochs: BTreeMap<u16, Bytes32>,
    pub psk_current: u16,
    pub camouflage: Option<(Vec<u8>, Vec<u8>)>,
    pub members: Membership,
    pub used_keys: BTreeSet<Bytes32>,
    pub retired_names: BTreeSet<String>,
    pub state_version: Option<Vec<u8>>,
    pub last_index: u64,
    pub last_term: u64,
    view: View,
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The entry is invalid against the current state; the leader must not
    /// propose it.
    #[error("rejected: {0}")]
    Rejected(String),
    /// The leader's bytes differ from our own result (§15.5): stop applying.
    #[error("divergence: {0}")]
    Divergence(String),
    /// The entry needs a StateVersion this software doesn't support (§15.7).
    #[error("unsupported state version {0}")]
    Unsupported(u32),
}

fn rej<T>(e: impl std::fmt::Display) -> std::result::Result<T, ApplyError> {
    Err(ApplyError::Rejected(e.to_string()))
}

type LeafChange = (u8, Bytes32, Option<Vec<u8>>);

/// Side effects on controller-only state, computed together with the leaves.
#[derive(Default)]
struct Effects {
    leaves: Vec<LeafChange>,
    pending_put: Vec<Pending>,
    pending_del: Vec<Bytes32>,
    op_seq: Option<(Bytes32, u64)>,
    psk: Option<(u16, Bytes32)>,
    camouflage: Option<(Vec<u8>, Vec<u8>)>,
    members: Option<Membership>,
    used_keys: Vec<Bytes32>,
    retired_names: Vec<String>,
    state_version: Option<Vec<u8>>,
    genesis: Option<Vec<u8>>,
    outcome: Outcome,
}

impl Default for Machine {
    fn default() -> Self {
        Machine {
            tree: Tree::new(),
            genesis: None,
            root_key: [0; 32],
            emergency_key: None,
            pool: Vec::new(),
            pending: BTreeMap::new(),
            op_seqs: BTreeMap::new(),
            psk_epochs: BTreeMap::new(),
            psk_current: 0,
            camouflage: None,
            members: Membership::default(),
            used_keys: BTreeSet::new(),
            retired_names: BTreeSet::new(),
            state_version: None,
            last_index: 0,
            last_term: 0,
            view: View::default(),
        }
    }
}

impl Machine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn view(&self) -> &View {
        &self.view
    }

    pub fn root(&mut self) -> Bytes32 {
        self.tree.root()
    }

    fn refresh_view(&mut self) {
        self.view = build_view(
            &self.tree,
            &self.root_key,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
    }

    // ------------------------------------------------------------ preparing (leader)

    /// Build a complete log entry for `payload` at `timestamp`, choosing the
    /// random values and serializing the leaves (§15.5).
    pub fn prepare(
        &self,
        term: u64,
        index: u64,
        timestamp: u64,
        payload: EntryPayload,
    ) -> std::result::Result<wp::LogEntry, ApplyError> {
        let random = wp::EntryRandom {
            node_id: Some(crypto::k32(&crypto::random32())),
            psk: Some(crypto::k32(&crypto::random32())),
        };
        let mut entry = wp::LogEntry {
            term,
            index,
            timestamp,
            payload: Some(payload),
            random: Some(Box::new(random)),
            leaves: None,
        };
        let fx = self.execute(&entry)?;
        entry.leaves = Some(
            fx.leaves
                .iter()
                .map(|(k, key, b)| wp::LeafUpdate {
                    kind: *k,
                    key: Some(crypto::k32(key)),
                    bytes: Some(b.clone().unwrap_or_default()),
                })
                .collect(),
        );
        Ok(entry)
    }

    /// Check an operation without preparing an entry (for early errors).
    pub fn check(
        &self,
        timestamp: u64,
        payload: EntryPayload,
    ) -> std::result::Result<Outcome, ApplyError> {
        let entry = wp::LogEntry {
            term: 0,
            index: self.last_index + 1,
            timestamp,
            payload: Some(payload),
            random: Some(Box::new(wp::EntryRandom {
                node_id: Some(crypto::k32(&crypto::random32())),
                psk: Some(crypto::k32(&[0; 32])),
            })),
            leaves: None,
        };
        Ok(self.execute(&entry)?.outcome)
    }

    // ------------------------------------------------------------ applying (every replica)

    pub fn apply(&mut self, entry: &wp::LogEntry) -> std::result::Result<Outcome, ApplyError> {
        if entry.index != self.last_index + 1 && self.last_index != 0 {
            return Err(ApplyError::Divergence(format!(
                "entry {} applied after {}",
                entry.index, self.last_index
            )));
        }
        let fx = match self.execute(entry) {
            Ok(fx) => fx,
            Err(ApplyError::Rejected(e)) => {
                // A committed entry the replica considers invalid: the
                // leader must have validated it, so this is divergence.
                return Err(ApplyError::Divergence(format!(
                    "committed entry {} rejected locally: {e}",
                    entry.index
                )));
            }
            Err(e) => return Err(e),
        };
        // Compare our expected leaves with the leader's bytes.
        let theirs = entry.leaves.clone().unwrap_or_default();
        if theirs.len() != fx.leaves.len() {
            return Err(ApplyError::Divergence(format!(
                "entry {}: {} leaves expected, leader sent {}",
                entry.index,
                fx.leaves.len(),
                theirs.len()
            )));
        }
        let mut accepted: Vec<LeafChange> = Vec::new();
        for ((k, key, mine), t) in fx.leaves.iter().zip(theirs.iter()) {
            let tkey = opt_k32(&t.key);
            let tbytes = t.bytes.clone().unwrap_or_default();
            if *k != t.kind || *key != tkey {
                return Err(ApplyError::Divergence(format!(
                    "entry {}: leaf key mismatch",
                    entry.index
                )));
            }
            match mine {
                None => {
                    if !tbytes.is_empty() {
                        return Err(ApplyError::Divergence(format!(
                            "entry {}: leader kept a leaf we delete",
                            entry.index
                        )));
                    }
                    accepted.push((*k, *key, None));
                }
                Some(m) => {
                    if !leaf_equal(*k, key, m, &tbytes) {
                        return Err(ApplyError::Divergence(format!(
                            "entry {}: leaf bytes differ from local result",
                            entry.index
                        )));
                    }
                    accepted.push((*k, *key, Some(tbytes)));
                }
            }
        }
        // Commit.
        for (k, key, b) in accepted {
            match b {
                Some(b) => self.tree.insert(k, key, b),
                None => self.tree.remove(k, &key),
            }
        }
        for t in fx.pending_del {
            self.pending.remove(&t);
        }
        for p in fx.pending_put {
            self.pending.insert(p.token_hash, p);
        }
        if let Some((a, s)) = fx.op_seq {
            self.op_seqs.insert(a, s);
        }
        if let Some((e, k)) = fx.psk {
            self.psk_epochs.insert(e, k);
            self.psk_current = e;
        }
        if let Some(c) = fx.camouflage {
            self.camouflage = Some(c);
        }
        if let Some(m) = fx.members {
            self.members = m;
        }
        self.used_keys.extend(fx.used_keys);
        self.retired_names.extend(fx.retired_names);
        if let Some(sv) = fx.state_version {
            self.state_version = Some(sv);
        }
        if let Some(g) = fx.genesis {
            let (gen, root, em) = crate::store::open_genesis(&g)
                .map_err(|e| ApplyError::Divergence(e.to_string()))?;
            self.root_key = root;
            self.emergency_key = em;
            self.pool = gen
                .overlay_pool
                .clone()
                .unwrap_or_default()
                .iter()
                .filter_map(cidr_to_net)
                .collect();
            self.genesis = Some((g, gen));
        }
        self.last_index = entry.index;
        self.last_term = entry.term;
        self.refresh_view();
        Ok(fx.outcome)
    }

    // ------------------------------------------------------------ the apply function

    fn execute(&self, e: &wp::LogEntry) -> std::result::Result<Effects, ApplyError> {
        let ts = e.timestamp;
        let random = e.random.clone().map(|b| *b).unwrap_or(wp::EntryRandom {
            node_id: None,
            psk: None,
        });
        let payload = e
            .payload
            .as_ref()
            .ok_or_else(|| ApplyError::Rejected("entry without payload".into()))?;
        if self.genesis.is_none()
            && !matches!(
                payload,
                EntryPayload::GenesisEntry(_) | EntryPayload::NoopEntry(_)
            )
        {
            return rej("the first entry must be the genesis");
        }
        let mut fx = Effects::default();
        match payload {
            EntryPayload::GenesisEntry(g) => {
                if self.genesis.is_some() {
                    return rej("genesis already applied");
                }
                let raw = g.genesis.clone().unwrap_or_default();
                let (gen, root, _) = crate::store::open_genesis(&raw)
                    .map_err(|e| ApplyError::Rejected(e.to_string()))?;
                let admin = gen
                    .first_admin
                    .clone()
                    .ok_or_else(|| ApplyError::Rejected("genesis without admin".into()))?;
                let v = open_expect(&admin, mt::ACCOUNT_RECORD, &[root])
                    .map_err(|e| ApplyError::Rejected(e.to_string()))?;
                let r: wp::AccountRecord = v
                    .decode()
                    .map_err(|e| ApplyError::Rejected(e.to_string()))?;
                fx.leaves
                    .push((kind::ACCOUNT, opt_k32(&r.account_id), Some(admin)));
                fx.leaves.push((
                    kind::VALIDITY,
                    SINGLETON,
                    Some(leaf::encode_validity(&wp::Validity {
                        valid_until: ts + VALIDITY_PERIOD,
                    })),
                ));
                let me = opt_k32(&random.node_id);
                let mut m = Membership::default();
                m.voters.insert(me);
                fx.members = Some(m);
                fx.genesis = Some(raw);
                // The first PSK epoch exists from the start, so nodes enrolled
                // before any rotation can pass the gate (§7.6).
                fx.psk = Some((0, opt_k32(&random.psk)));
                fx.used_keys.push(opt_k32(&r.account_key));
                fx.outcome.description =
                    format!("genesis; first controller {}", crypto::short(&me));
            }
            EntryPayload::NoopEntry(_) => fx.outcome.description = "no-op".into(),
            EntryPayload::ExtendValidityEntry(v) => {
                if v.valid_until != ts + VALIDITY_PERIOD {
                    return rej("ExtendValidity must be exactly 30 days after the entry timestamp");
                }
                if v.valid_until <= self.view.valid_until {
                    return rej("ExtendValidity may only move forward");
                }
                fx.leaves.push((
                    kind::VALIDITY,
                    SINGLETON,
                    Some(leaf::encode_validity(&wp::Validity {
                        valid_until: v.valid_until,
                    })),
                ));
                fx.outcome.description = format!("validity extended to {}", v.valid_until);
            }
            EntryPayload::ExpireEnrollmentsEntry(x) => {
                if x.now != ts {
                    return rej("ExpireEnrollments must use the entry timestamp");
                }
                for (t, p) in &self.pending {
                    if p.expires_at < ts {
                        fx.pending_del.push(*t);
                    }
                }
                fx.outcome.description = format!("expired {} enrollments", fx.pending_del.len());
            }
            EntryPayload::RedeemEnrollmentEntry(r) => self.redeem(r, ts, &mut fx)?,
            EntryPayload::RotateNodeKeyEntry(r) => self.rotate_key(r, ts, &mut fx)?,
            EntryPayload::RootAccountEntry(r) => {
                let raw = r.record.clone().unwrap_or_default();
                let v = open_envelope(&raw).map_err(|e| ApplyError::Rejected(e.to_string()))?;
                match v.ty {
                    mt::ACCOUNT_RECORD if v.signer == self.root_key => {
                        self.put_account(&raw, None, &mut fx)?
                    }
                    mt::ACCOUNT_TOMBSTONE
                        if v.signer == self.root_key || Some(v.signer) == self.emergency_key =>
                    {
                        self.tombstone_account(&raw, None, &mut fx)?
                    }
                    _ => return rej("root account entry not signed by the root"),
                }
            }
            EntryPayload::SetStateVersionEntry(s) => {
                let raw = s.state_version.clone().unwrap_or_default();
                let v = open_expect(&raw, mt::STATE_VERSION, &[self.root_key])
                    .map_err(|e| ApplyError::Rejected(e.to_string()))?;
                let sv: wp::StateVersion = v
                    .decode()
                    .map_err(|e| ApplyError::Rejected(e.to_string()))?;
                if !wp::SUPPORTED_STATE_VERSIONS.contains(&sv.version) {
                    return Err(ApplyError::Unsupported(sv.version));
                }
                fx.state_version = Some(raw);
                fx.outcome.description = format!("state version {} activated", sv.version);
            }
            EntryPayload::OpEntry(o) => {
                let raw = o.signed_op.clone().unwrap_or_default();
                self.signed_op(&raw, ts, &random, &mut fx)?;
            }
            EntryPayload::MembershipEntry(_) => {
                return rej("raw membership entries are not accepted")
            }
        }
        Ok(fx)
    }

    fn signed_op(
        &self,
        raw: &[u8],
        ts: u64,
        random: &wp::EntryRandom,
        fx: &mut Effects,
    ) -> std::result::Result<(), ApplyError> {
        let v = open_envelope(raw).map_err(|e| ApplyError::Rejected(e.to_string()))?;
        if v.ty != mt::SIGNED_OP {
            return rej("not a SignedOp");
        }
        let op: wp::SignedOp = v
            .decode()
            .map_err(|e| ApplyError::Rejected(e.to_string()))?;
        let signer_id = opt_k32(&op.signer);
        let acct = self
            .view
            .accounts
            .get(&signer_id)
            .ok_or_else(|| ApplyError::Rejected("unknown signer account".into()))?;
        if !acct.valid {
            return rej("signer account is not valid");
        }
        if acct.key != v.signer {
            return rej("SignedOp not signed by the account's current key");
        }
        if op.op_seq <= self.op_seqs.get(&signer_id).copied().unwrap_or(0) {
            return rej("replayed or out-of-order op_seq");
        }
        if op.issued_at.abs_diff(ts) > SKEW_SHORT_RECORD {
            return rej("issued_at too far from the entry timestamp");
        }
        fx.op_seq = Some((signer_id, op.op_seq));
        fx.outcome.signer = Some(signer_id);
        let admin = acct.admin;
        let body = op
            .op
            .ok_or_else(|| ApplyError::Rejected("SignedOp without operation".into()))?;
        let need_admin = || -> std::result::Result<(), ApplyError> {
            if admin {
                Ok(())
            } else {
                rej("operation requires an admin account")
            }
        };
        let owner_or_admin = |node: &Bytes32| -> std::result::Result<(), ApplyError> {
            if admin {
                return Ok(());
            }
            match self.view.nodes.get(node) {
                Some(n) if n.owner == signer_id => Ok(()),
                _ => rej("only the node's owner or an admin may do this"),
            }
        };
        match body {
            AccountOp::CreateEnrollment(c) => {
                need_admin()?;
                self.create_enrollment(&c, ts, random, fx)?;
            }
            AccountOp::RenameNode(r) => {
                let id = opt_k32(&r.node_id);
                owner_or_admin(&id)?;
                let mut rec = self.live_node(&id)?;
                let name = r.name.clone().unwrap_or_default();
                if !valid_name(&name) {
                    return rej("invalid node name");
                }
                self.check_name_free(&name, Some(&id))?;
                rec.name = Some(name.clone());
                rec.version += 1;
                fx.leaves
                    .push((kind::NODE, id, Some(leaf::encode_node(&rec))));
                fx.outcome.description = format!("rename node {} to {name}", crypto::short(&id));
                fx.outcome.node_id = Some(id);
            }
            AccountOp::UpdateNode(u) => {
                need_admin()?;
                let id = opt_k32(&u.node_id);
                let mut rec = self.live_node(&id)?;
                if let Some(o) = u.owner {
                    if !o.is_zero() {
                        let oid = o.to_bytes();
                        if !self
                            .view
                            .accounts
                            .get(&oid)
                            .map(|a| a.valid)
                            .unwrap_or(false)
                        {
                            return rej("new owner is not a valid account");
                        }
                        rec.owner = Some(o);
                    }
                }
                if u.set_overlay_ips {
                    rec.overlay_ips = Some(
                        self.check_ips(&u.overlay_ips.clone().unwrap_or_default(), Some(&id))?,
                    );
                }
                if u.set_roles {
                    rec.roles = Some(sort_dedup(u.roles.clone().unwrap_or_default()));
                }
                if u.set_tags {
                    rec.tags = Some(check_tags(&u.tags.clone().unwrap_or_default())?);
                }
                if u.set_routes {
                    rec.routes =
                        Some(self.check_routes(&u.routes.clone().unwrap_or_default(), &id)?);
                }
                rec.version += 1;
                fx.leaves
                    .push((kind::NODE, id, Some(leaf::encode_node(&rec))));
                fx.outcome.description =
                    format!("update node {}", rec.name.clone().unwrap_or_default());
                fx.outcome.node_id = Some(id);
            }
            AccountOp::TombstoneNode(t) => {
                let id = opt_k32(&t.node_id);
                owner_or_admin(&id)?;
                let rec = self.live_node(&id)?;
                let tomb = wp::Tombstone {
                    node_id: Some(crypto::k32(&id)),
                    version: rec.version + 1,
                    reason: t.reason.clone(),
                };
                fx.leaves
                    .push((kind::NODE, id, Some(leaf::encode_tombstone(&tomb))));
                // Drop any pending re-key for it.
                for (th, p) in &self.pending {
                    if p.is_rekey && p.node_id == id {
                        fx.pending_del.push(*th);
                    }
                }
                fx.outcome.description = format!(
                    "tombstone node {} ({})",
                    rec.name.unwrap_or_default(),
                    t.reason.unwrap_or_default()
                );
                fx.outcome.node_id = Some(id);
            }
            AccountOp::RekeyNode(r) => {
                let id = opt_k32(&r.node_id);
                owner_or_admin(&id)?;
                let mut rec = self.live_node(&id)?;
                let th = opt_k32(&r.token_hash);
                if self.pending.contains_key(&th) {
                    return rej("token already pending");
                }
                if r.expires_at <= ts {
                    return rej("token already expired");
                }
                for (t, p) in &self.pending {
                    if p.is_rekey && p.node_id == id {
                        fx.pending_del.push(*t);
                    }
                }
                fx.pending_put.push(Pending {
                    token_hash: th,
                    expires_at: r.expires_at,
                    is_rekey: true,
                    node_id: id,
                    create: None,
                });
                if r.revoke_old_now {
                    rec.identity_key = Some(crypto::k32(&[0; 32]));
                    rec.version += 1;
                    fx.leaves
                        .push((kind::NODE, id, Some(leaf::encode_node(&rec))));
                }
                fx.outcome.description = format!(
                    "re-key node {} (revoke_old_now={})",
                    rec.name.unwrap_or_default(),
                    r.revoke_old_now
                );
                fx.outcome.node_id = Some(id);
            }
            AccountOp::PutAccount(p) => {
                need_admin()?;
                self.put_account(&p.record.unwrap_or_default(), Some(signer_id), fx)?;
            }
            AccountOp::TombstoneAccount(t) => {
                need_admin()?;
                self.tombstone_account(&t.tombstone.unwrap_or_default(), Some(signer_id), fx)?;
            }
            AccountOp::SetPolicy(p) => {
                need_admin()?;
                let pol = p
                    .policy
                    .ok_or_else(|| ApplyError::Rejected("missing policy".into()))?;
                if pol.version <= self.view.policy_version
                    && self.tree.get(kind::POLICY, &SINGLETON).is_some()
                {
                    return rej("policy version must increase");
                }
                let parsed =
                    Policy::from_wire(&pol).map_err(|e| ApplyError::Rejected(e.to_string()))?;
                let view = &self.view;
                parsed
                    .run_tests(&|s: &Selector| match s {
                        Selector::NodeName(n) => view
                            .by_name
                            .get(n)
                            .and_then(|id| view.nodes.get(id))
                            .map(|n| view.subject(n)),
                        Selector::NodeKey(k) => view
                            .by_key
                            .get(k)
                            .and_then(|id| view.nodes.get(id))
                            .map(|n| view.subject(n)),
                        _ => None,
                    })
                    .map_err(|e| ApplyError::Rejected(e.to_string()))?;
                fx.leaves
                    .push((kind::POLICY, SINGLETON, Some(leaf::encode_policy(&pol))));
                fx.outcome.description = format!("set policy version {}", pol.version);
            }
            AccountOp::SetDns(d) => {
                need_admin()?;
                let cfg = d
                    .config
                    .ok_or_else(|| ApplyError::Rejected("missing DNS config".into()))?;
                self.check_version(kind::DNS, cfg.version)?;
                self.validate_dns(&cfg)?;
                fx.leaves
                    .push((kind::DNS, SINGLETON, Some(leaf::encode_dns(&cfg))));
                fx.outcome.description = format!("set DNS config version {}", cfg.version);
            }
            AccountOp::SetSeeds(s) => {
                need_admin()?;
                let seeds = s
                    .seeds
                    .ok_or_else(|| ApplyError::Rejected("missing seeds".into()))?;
                self.check_version(kind::SEEDS, seeds.version)?;
                for e in seeds.entries.clone().unwrap_or_default() {
                    let n = e.node.clone().unwrap_or_default();
                    let id = self
                        .resolve_node_ref(&n)
                        .ok_or_else(|| ApplyError::Rejected(format!("seed {n} names no node")))?;
                    let info = &self.view.nodes[&id];
                    if !info.valid || !(info.relay || self.members.contains(&id)) {
                        return rej(format!("seed {n} is not a valid RELAY or CONTROL node"));
                    }
                    for a in e.addrs.clone().unwrap_or_default() {
                        let h = a.host.clone().unwrap_or_default();
                        if h.parse::<std::net::IpAddr>().is_err()
                            && !crate::validate::valid_dns_name(&h)
                        {
                            return rej(format!("seed address {h} doesn't parse"));
                        }
                        if a.port == 0 {
                            return rej("seed port 0");
                        }
                    }
                }
                fx.leaves
                    .push((kind::SEEDS, SINGLETON, Some(leaf::encode_seeds(&seeds))));
                fx.outcome.description = format!("set seeds version {}", seeds.version);
            }
            AccountOp::SetLimits(l) => {
                need_admin()?;
                let lim = l
                    .limits
                    .ok_or_else(|| ApplyError::Rejected("missing limits".into()))?;
                self.check_version(kind::LIMITS, lim.version)?;
                crate::validate::limits(&lim).map_err(|e| ApplyError::Rejected(e.to_string()))?;
                fx.leaves
                    .push((kind::LIMITS, SINGLETON, Some(leaf::encode_limits(&lim))));
                fx.outcome.description = format!("set limits version {}", lim.version);
            }
            AccountOp::SetTransport(t) => {
                need_admin()?;
                let cfg = t
                    .config
                    .ok_or_else(|| ApplyError::Rejected("missing transport config".into()))?;
                self.check_version(kind::TRANSPORT, cfg.version)?;
                crate::validate::transport(&cfg)
                    .map_err(|e| ApplyError::Rejected(e.to_string()))?;
                fx.leaves.push((
                    kind::TRANSPORT,
                    SINGLETON,
                    Some(leaf::encode_transport(&cfg)),
                ));
                fx.outcome.description = format!("set transport config version {}", cfg.version);
            }
            AccountOp::SetCamouflageSecret(c) => {
                need_admin()?;
                let k = c.private_key.unwrap_or_default();
                if k.is_empty() {
                    return rej("empty camouflage private key");
                }
                fx.camouflage = Some((k, c.site.unwrap_or_default()));
                fx.outcome.description = "set camouflage secret".into();
            }
            AccountOp::ChangeMembership(c) => {
                need_admin()?;
                let id = opt_k32(&c.node_id);
                let mut m = self.members.clone();
                match c.change {
                    wp::MembershipChange::AddLearner => {
                        if m.contains(&id) {
                            return rej("already a member");
                        }
                        if !self.view.nodes.get(&id).map(|n| n.valid).unwrap_or(false) {
                            return rej("learner must be a valid enrolled node");
                        }
                        m.learners.insert(id);
                    }
                    wp::MembershipChange::Promote => {
                        if !m.learners.remove(&id) {
                            return rej("not a learner");
                        }
                        if m.voters.len() >= 7 {
                            return rej("at most 7 voters");
                        }
                        m.voters.insert(id);
                    }
                    wp::MembershipChange::Demote => {
                        if !m.voters.remove(&id) {
                            return rej("not a voter");
                        }
                        if m.voters.is_empty() {
                            return rej("can't demote the last voter");
                        }
                        m.learners.insert(id);
                    }
                    wp::MembershipChange::Remove => {
                        let was_voter = m.voters.remove(&id);
                        if !was_voter && !m.learners.remove(&id) {
                            return rej("not a member");
                        }
                        if m.voters.is_empty() {
                            return rej("can't remove the last voter");
                        }
                    }
                }
                fx.members = Some(m);
                fx.outcome.membership_changed = true;
                fx.outcome.description =
                    format!("membership {:?} {}", c.change, crypto::short(&id));
            }
            AccountOp::RotatePsk(r) => {
                need_admin()?;
                if r.epoch_id != self.psk_current.wrapping_add(1) || r.epoch_id == 0 {
                    return rej(format!(
                        "next PSK epoch must be {}",
                        self.psk_current.wrapping_add(1)
                    ));
                }
                let psk = opt_k32(&random.psk);
                fx.psk = Some((r.epoch_id, psk));
                fx.outcome.psk_rotated = true;
                fx.outcome.description = format!("rotate PSK to epoch {}", r.epoch_id);
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ helpers

    fn check_version(&self, k: u8, v: u64) -> std::result::Result<(), ApplyError> {
        if let Some(e) = self.tree.get(k, &SINGLETON) {
            if let Ok(old) = leaf::decode(k, &SINGLETON, &e.bytes) {
                if v <= leaf::version(&old) {
                    return rej("version must increase");
                }
            }
        }
        Ok(())
    }

    fn live_node(&self, id: &Bytes32) -> std::result::Result<wp::NodeRecord, ApplyError> {
        let e = self
            .tree
            .get(kind::NODE, id)
            .ok_or_else(|| ApplyError::Rejected("no such node".into()))?;
        match leaf::decode(kind::NODE, id, &e.bytes) {
            Ok(LeafValue::Node(r)) => Ok(r),
            Ok(LeafValue::NodeTombstone(_)) => rej("node is tombstoned"),
            _ => rej("bad node leaf"),
        }
    }

    pub fn resolve_node_ref(&self, s: &str) -> Option<Bytes32> {
        let s = s.strip_prefix("node:").unwrap_or(s);
        if let Some(k) = crypto::parse_key_b64(s) {
            return self.view.by_key.get(&k).copied();
        }
        self.view.by_name.get(s).copied()
    }

    fn check_name_free(
        &self,
        name: &str,
        except: Option<&Bytes32>,
    ) -> std::result::Result<(), ApplyError> {
        if let Some(id) = self.view.by_name.get(name) {
            if Some(id) != except && !self.view.tombstoned_nodes.contains(id) {
                return rej(format!("node name {name} is taken"));
            }
        }
        for p in self.pending.values() {
            if let Some(c) = &p.create {
                if c.name.as_deref() == Some(name) {
                    return rej(format!(
                        "node name {name} is reserved by a pending enrollment"
                    ));
                }
            }
        }
        Ok(())
    }

    fn resolver_ips(&self) -> Vec<std::net::IpAddr> {
        self.view
            .dns
            .as_ref()
            .map(|d| {
                d.resolver_ip
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|i| i.to_ip())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn check_ips(
        &self,
        ips: &[wp::Cidr],
        except: Option<&Bytes32>,
    ) -> std::result::Result<Vec<wp::Cidr>, ApplyError> {
        let mut nets = Vec::new();
        for c in ips {
            let n = canonical(c).map_err(|e| ApplyError::Rejected(e.to_string()))?;
            if !self
                .pool
                .iter()
                .any(|p| p.contains(&n.network()) && p.prefix_len() <= n.prefix_len())
            {
                return rej(format!("{n} is outside the overlay pool"));
            }
            if self.resolver_ips().iter().any(|r| n.contains(r)) {
                return rej(format!("{n} contains the DNS resolver address"));
            }
            for other in self.view.nodes.values() {
                if Some(&other.id) == except || self.view.tombstoned_nodes.contains(&other.id) {
                    continue;
                }
                if other.ips.iter().any(|o| overlaps(o, &n)) {
                    return rej(format!("{n} overlaps node {}", other.name));
                }
            }
            for p in self.pending.values() {
                if let Some(cr) = &p.create {
                    if cr
                        .overlay_ips
                        .clone()
                        .unwrap_or_default()
                        .iter()
                        .filter_map(cidr_to_net)
                        .any(|o| overlaps(&o, &n))
                    {
                        return rej(format!("{n} is reserved by a pending enrollment"));
                    }
                }
            }
            for g in self.all_grants(except) {
                if overlaps(&g.published, &n) {
                    return rej(format!("{n} overlaps a published subnet route"));
                }
            }
            nets.push(*c);
        }
        let out = sort_dedup(nets);
        if out.is_empty() {
            return rej("a node needs at least one overlay IP");
        }
        Ok(out)
    }

    fn all_grants(&self, except: Option<&Bytes32>) -> Vec<Grant> {
        self.view
            .nodes
            .values()
            .filter(|n| Some(&n.id) != except && !self.view.tombstoned_nodes.contains(&n.id))
            .flat_map(|n| n.routes.clone())
            .collect()
    }

    fn check_routes(
        &self,
        routes: &[wp::RouteGrant],
        me: &Bytes32,
    ) -> std::result::Result<Vec<wp::RouteGrant>, ApplyError> {
        let mut out = Vec::new();
        for r in routes {
            let g = Grant::from_wire(r).map_err(|e| ApplyError::Rejected(e.to_string()))?;
            if self.pool.iter().any(|p| overlaps(p, &g.published)) {
                return rej(format!(
                    "published prefix {} overlaps the overlay pool",
                    g.published
                ));
            }
            for n in self.view.nodes.values() {
                if n.ips.iter().any(|i| overlaps(i, &g.published)) {
                    return rej(format!(
                        "published prefix {} overlaps node {}",
                        g.published, n.name
                    ));
                }
            }
            for other in self.all_grants(Some(me)) {
                if overlaps(&other.published, &g.published) && other != g {
                    return rej(format!(
                        "published prefix {} overlaps another grant",
                        g.published
                    ));
                }
            }
            for prev in &out {
                let pg = Grant::from_wire(prev).unwrap();
                if overlaps(&pg.published, &g.published) {
                    return rej("overlapping grants on one node");
                }
            }
            out.push(*r);
        }
        Ok(sort_dedup(out))
    }

    fn create_enrollment(
        &self,
        c: &wp::CreateEnrollment,
        ts: u64,
        random: &wp::EntryRandom,
        fx: &mut Effects,
    ) -> std::result::Result<(), ApplyError> {
        let owner = opt_k32(&c.owner);
        if !self
            .view
            .accounts
            .get(&owner)
            .map(|a| a.valid)
            .unwrap_or(false)
        {
            return rej("owner must be a valid account");
        }
        let name = c.name.clone().unwrap_or_default();
        if !valid_name(&name) {
            return rej("invalid node name");
        }
        self.check_name_free(&name, None)?;
        let mut c = c.clone();
        c.overlay_ips = Some(self.check_ips(&c.overlay_ips.clone().unwrap_or_default(), None)?);
        c.roles = Some(sort_dedup(c.roles.clone().unwrap_or_default()));
        c.tags = Some(check_tags(&c.tags.clone().unwrap_or_default())?);
        let fixed_id = c.node_id.map(|k| k.to_bytes()).filter(|k| *k != [0; 32]);
        if let Some(f) = fixed_id {
            // Only a controller that is a Raft member but has no record yet
            // (bootstrap, runbook 1) may be enrolled under a fixed id.
            if !self.members.contains(&f) {
                return rej("a fixed node_id is only allowed for a Raft member without a record");
            }
        }
        let node_id = fixed_id.unwrap_or_else(|| opt_k32(&random.node_id));
        if self.tree.get(kind::NODE, &node_id).is_some() {
            return rej("node id already enrolled");
        }
        c.routes = Some(self.check_routes(&c.routes.clone().unwrap_or_default(), &node_id)?);
        let key = c
            .identity_key
            .map(|k| k.to_bytes())
            .filter(|k| *k != [0; 32]);
        if let Some(key) = key {
            // Alternative flow: the key is known, create the record directly.
            if self.used_keys.contains(&key) {
                return rej("identity key already used");
            }
            let rec = record_from(&c, node_id, key);
            fx.leaves
                .push((kind::NODE, node_id, Some(leaf::encode_node(&rec))));
            fx.used_keys.push(key);
            fx.outcome.description = format!("enroll node {name} directly");
        } else {
            let th = opt_k32(&c.token_hash);
            if th == [0; 32] || self.pending.contains_key(&th) {
                return rej("missing or duplicate token");
            }
            if c.expires_at <= ts {
                return rej("token already expired");
            }
            fx.pending_put.push(Pending {
                token_hash: th,
                expires_at: c.expires_at,
                is_rekey: false,
                node_id,
                create: Some(c.clone()),
            });
            fx.outcome.description = format!("create enrollment for {name}");
        }
        fx.outcome.node_id = Some(node_id);
        Ok(())
    }

    fn redeem(
        &self,
        r: &wp::RedeemEnrollmentEntry,
        ts: u64,
        fx: &mut Effects,
    ) -> std::result::Result<(), ApplyError> {
        let th = opt_k32(&r.token_hash);
        let key = opt_k32(&r.identity_key);
        let p = self
            .pending
            .get(&th)
            .ok_or_else(|| ApplyError::Rejected("unknown enrollment token".into()))?;
        if p.expires_at < ts {
            return rej("enrollment token expired");
        }
        if key == [0; 32] || self.used_keys.contains(&key) {
            return rej("identity key already used");
        }
        // The node id is the pending one, except that a Raft member without a
        // record (a bootstrapping controller) keeps its own id (runbook 1).
        let node_id = opt_k32(&r.node_id);
        let member_bootstrap = !p.is_rekey
            && node_id != p.node_id
            && self.members.contains(&node_id)
            && self.tree.get(kind::NODE, &node_id).is_none();
        if p.node_id != node_id && !member_bootstrap {
            return rej("node id does not match the pending enrollment");
        }
        if p.is_rekey {
            let mut rec = self.live_node(&p.node_id)?;
            rec.identity_key = Some(crypto::k32(&key));
            rec.version += 1;
            fx.leaves
                .push((kind::NODE, p.node_id, Some(leaf::encode_node(&rec))));
            fx.outcome.description =
                format!("re-key redeemed for {}", rec.name.unwrap_or_default());
        } else {
            let c = p
                .create
                .clone()
                .ok_or_else(|| ApplyError::Rejected("pending enrollment without data".into()))?;
            // Re-check uniqueness against the current state (it may have changed).
            if !self
                .view
                .accounts
                .get(&opt_k32(&c.owner))
                .map(|a| a.valid)
                .unwrap_or(false)
            {
                return rej("owner account no longer valid");
            }
            let rec = record_from(&c, node_id, key);
            fx.leaves
                .push((kind::NODE, node_id, Some(leaf::encode_node(&rec))));
            fx.outcome.description =
                format!("enrollment redeemed for {}", rec.name.unwrap_or_default());
        }
        fx.pending_del.push(th);
        fx.used_keys.push(key);
        fx.outcome.node_id = Some(node_id);
        Ok(())
    }

    fn rotate_key(
        &self,
        r: &wp::RotateNodeKeyEntry,
        ts: u64,
        fx: &mut Effects,
    ) -> std::result::Result<(), ApplyError> {
        let raw = r.rotation.clone().unwrap_or_default();
        let outer = open_envelope(&raw).map_err(|e| ApplyError::Rejected(e.to_string()))?;
        if outer.ty != mt::ROTATE_NODE_KEY {
            return rej("not a RotateNodeKey");
        }
        let inner = open_envelope(&outer.body).map_err(|e| ApplyError::Rejected(e.to_string()))?;
        if inner.ty != mt::ROTATE_NODE_KEY_NEW {
            return rej("RotateNodeKey without the new key's signature");
        }
        let rot: wp::RotateNodeKey = inner
            .decode()
            .map_err(|e| ApplyError::Rejected(e.to_string()))?;
        let id = opt_k32(&rot.node_id);
        let new_key = opt_k32(&rot.new_key);
        if inner.signer != new_key {
            return rej("inner signature is not by the new key");
        }
        let mut rec = self.live_node(&id)?;
        if opt_k32(&rec.identity_key) != outer.signer {
            return rej("outer signature is not by the node's current key");
        }
        if rot.issued_at.abs_diff(ts) > SKEW_SHORT_RECORD {
            return rej("rotation issued_at too far from the entry timestamp");
        }
        if self.pending.values().any(|p| p.is_rekey && p.node_id == id) {
            return rej("node has a pending re-key");
        }
        if self.used_keys.contains(&new_key) {
            return rej("key already used");
        }
        rec.identity_key = Some(crypto::k32(&new_key));
        rec.version += 1;
        fx.leaves
            .push((kind::NODE, id, Some(leaf::encode_node(&rec))));
        fx.used_keys.push(new_key);
        fx.outcome.description = format!("node {} rotated its key", rec.name.unwrap_or_default());
        fx.outcome.node_id = Some(id);
        Ok(())
    }

    fn put_account(
        &self,
        raw: &[u8],
        submitter: Option<Bytes32>,
        fx: &mut Effects,
    ) -> std::result::Result<(), ApplyError> {
        let v = open_envelope(raw).map_err(|e| ApplyError::Rejected(e.to_string()))?;
        if v.ty != mt::ACCOUNT_RECORD {
            return rej("not an AccountRecord");
        }
        let r: wp::AccountRecord = v
            .decode()
            .map_err(|e| ApplyError::Rejected(e.to_string()))?;
        crate::validate::account_record(&r).map_err(|e| ApplyError::Rejected(e.to_string()))?;
        if r.issuer_root {
            if v.signer != self.root_key {
                return rej("record claims the root as issuer but isn't root-signed");
            }
        } else {
            let issuer = opt_k32(&r.issuer);
            let a = self
                .view
                .accounts
                .get(&issuer)
                .ok_or_else(|| ApplyError::Rejected("unknown issuer".into()))?;
            if !a.valid || !a.admin || a.key != v.signer {
                return rej("record must be signed by a valid admin");
            }
            if submitter.is_some() && submitter != Some(issuer) {
                return rej("an admin may only submit records it signed");
            }
            if r.admin {
                return rej("admins can't create admins");
            }
        }
        let id = opt_k32(&r.account_id);
        let name = r.name.clone().unwrap_or_default();
        if self.view.tombstoned_accounts.contains(&id) {
            return rej("account is tombstoned");
        }
        if let Some(old) = self.view.accounts.get(&id) {
            if r.version <= old.rec.version {
                return rej("account version must increase");
            }
            if old.admin && !r.issuer_root {
                return rej("only the root may change an admin account");
            }
        }
        if self.retired_names.contains(&name) {
            return rej("account name was used by a tombstoned account");
        }
        if self
            .view
            .accounts
            .values()
            .any(|a| a.id != id && a.name == name)
        {
            return rej(format!("account name {name} is taken"));
        }
        let key = opt_k32(&r.account_key);
        if self
            .view
            .accounts
            .values()
            .any(|a| a.id != id && a.key == key)
        {
            return rej("account key used by another account");
        }
        fx.leaves.push((kind::ACCOUNT, id, Some(raw.to_vec())));
        fx.outcome.description = format!("put account {name} (admin={})", r.admin);
        Ok(())
    }

    fn tombstone_account(
        &self,
        raw: &[u8],
        submitter: Option<Bytes32>,
        fx: &mut Effects,
    ) -> std::result::Result<(), ApplyError> {
        let v = open_envelope(raw).map_err(|e| ApplyError::Rejected(e.to_string()))?;
        if v.ty != mt::ACCOUNT_TOMBSTONE {
            return rej("not an AccountTombstone");
        }
        let t: wp::AccountTombstone = v
            .decode()
            .map_err(|e| ApplyError::Rejected(e.to_string()))?;
        let id = opt_k32(&t.account_id);
        let target = self
            .view
            .accounts
            .get(&id)
            .ok_or_else(|| ApplyError::Rejected("unknown account".into()))?;
        let offline = v.signer == self.root_key || Some(v.signer) == self.emergency_key;
        if !offline {
            let signer = self
                .view
                .accounts
                .values()
                .find(|a| a.key == v.signer && a.valid && a.admin)
                .ok_or_else(|| ApplyError::Rejected("tombstone not signed by an admin".into()))?;
            if target.admin {
                return rej("only the root or emergency key may revoke an admin");
            }
            if submitter.is_some() && submitter != Some(signer.id) {
                return rej("an admin may only submit tombstones it signed");
            }
        }
        if t.version <= target.rec.version {
            return rej("tombstone version must exceed the record's");
        }
        if self.view.tombstoned_accounts.contains(&id) {
            return rej("already tombstoned");
        }
        fx.leaves.push((kind::ACCOUNT, id, Some(raw.to_vec())));
        fx.retired_names.push(target.name.clone());
        fx.outcome.description = format!(
            "tombstone account {} (revoke_issued={})",
            target.name, t.revoke_issued
        );
        Ok(())
    }

    fn validate_dns(&self, d: &wp::DnsConfig) -> std::result::Result<(), ApplyError> {
        use crate::validate::valid_dns_name;
        let suffix = d
            .suffix
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "internal".into());
        if !valid_dns_name(&suffix) {
            return rej("invalid DNS suffix");
        }
        let in_zone = |name: &str, zone: &str| {
            let n = name.trim_end_matches('.').to_ascii_lowercase();
            let z = zone.trim_end_matches('.').to_ascii_lowercase();
            n == z || n.ends_with(&format!(".{z}"))
        };
        for ip in d.resolver_ip.clone().unwrap_or_default() {
            let ip = ip
                .to_ip()
                .ok_or_else(|| ApplyError::Rejected("bad resolver ip".into()))?;
            if !self.pool.iter().any(|p| p.contains(&ip)) {
                return rej("resolver_ip must be in the overlay pool");
            }
            if self.view.node_by_ip(&ip).is_some() {
                return rej("resolver_ip is assigned to a node");
            }
        }
        let zones: Vec<String> = d
            .forward
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|f| f.zone.clone().unwrap_or_default())
            .collect();
        let published: Vec<IpNet> = self.all_grants(None).iter().map(|g| g.published).collect();
        for r in d.records.clone().unwrap_or_default() {
            let name = r.name.clone().unwrap_or_default();
            if !valid_dns_name(&name) {
                return rej(format!("invalid record name {name}"));
            }
            if !in_zone(&name, &suffix) && !zones.iter().any(|z| in_zone(&name, z)) {
                return rej(format!(
                    "record {name} is outside the suffix and every listed zone"
                ));
            }
            let lname = name.trim_end_matches('.').to_ascii_lowercase();
            if self
                .view
                .nodes
                .values()
                .any(|n| lname == format!("{}.{}", n.name, suffix))
            {
                return rej(format!("record {name} shadows a magic DNS name"));
            }
            let value = r.value.clone().unwrap_or_default();
            match r.rtype {
                wp::DnsType::A | wp::DnsType::Aaaa => {
                    if value.starts_with("node:") {
                        continue;
                    }
                    let ip: std::net::IpAddr = value
                        .parse()
                        .map_err(|_| ApplyError::Rejected(format!("bad address {value}")))?;
                    if !self.pool.iter().any(|p| p.contains(&ip))
                        && !published.iter().any(|p| p.contains(&ip))
                    {
                        return rej(format!(
                            "{value} is neither an overlay address nor in a published prefix"
                        ));
                    }
                }
                _ => {}
            }
        }
        for f in d.forward.clone().unwrap_or_default() {
            let z = f.zone.clone().unwrap_or_default();
            if !valid_dns_name(&z) {
                return rej(format!("invalid forward zone {z}"));
            }
            if in_zone(&suffix, &z) || in_zone(&z, &suffix) {
                return rej("a forward zone may not cover the magic DNS suffix");
            }
            let grants = self.all_grants(None);
            for g in f.rewrite.clone().unwrap_or_default() {
                let g = Grant::from_wire(&g).map_err(|e| ApplyError::Rejected(e.to_string()))?;
                if !grants.contains(&g) {
                    return rej("rewrite grant doesn't match an existing route grant");
                }
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ snapshots (§7.1)

    pub fn snapshot(&self) -> wp::ControllerSnapshot {
        wp::ControllerSnapshot {
            last_index: self.last_index,
            last_term: self.last_term,
            leaves: Some(
                self.tree
                    .iter()
                    .map(|(_, e)| wp::LeafData {
                        kind: e.kind,
                        key: Some(crypto::k32(&e.key)),
                        bytes: Some(e.bytes.clone()),
                    })
                    .collect(),
            ),
            pending: Some(
                self.pending
                    .values()
                    .map(|p| wp::PendingEnrollment {
                        token_hash: Some(crypto::k32(&p.token_hash)),
                        expires_at: p.expires_at,
                        is_rekey: p.is_rekey,
                        node_id: Some(crypto::k32(&p.node_id)),
                        create: p.create.clone().map(Box::new),
                    })
                    .collect(),
            ),
            op_seqs: Some(
                self.op_seqs
                    .iter()
                    .map(|(a, s)| wp::OpSeq {
                        account_id: Some(crypto::k32(a)),
                        seq: *s,
                    })
                    .collect(),
            ),
            psk_epochs: Some(
                self.psk_epochs
                    .iter()
                    .map(|(e, k)| wp::PskEpoch {
                        epoch_id: *e,
                        psk: Some(crypto::k32(k)),
                    })
                    .collect(),
            ),
            psk_current: self.psk_current,
            camouflage: self.camouflage.clone().map(|(k, s)| {
                Box::new(wp::CamouflageSecret {
                    private_key: Some(k),
                    site: Some(s),
                })
            }),
            voters: Some(self.members.voters.iter().map(crypto::k32).collect()),
            learners: Some(self.members.learners.iter().map(crypto::k32).collect()),
            used_keys: Some(self.used_keys.iter().map(crypto::k32).collect()),
            state_version: self.state_version.clone(),
            retired_names: Some(self.retired_names.iter().cloned().collect()),
            genesis: self.genesis.as_ref().map(|g| g.0.clone()),
        }
    }

    pub fn restore(s: &wp::ControllerSnapshot) -> Result<Machine> {
        let mut m = Machine::new();
        for l in s.leaves.clone().unwrap_or_default() {
            m.tree
                .insert(l.kind, opt_k32(&l.key), l.bytes.unwrap_or_default());
        }
        for p in s.pending.clone().unwrap_or_default() {
            let th = opt_k32(&p.token_hash);
            m.pending.insert(
                th,
                Pending {
                    token_hash: th,
                    expires_at: p.expires_at,
                    is_rekey: p.is_rekey,
                    node_id: opt_k32(&p.node_id),
                    create: p.create.map(|b| *b),
                },
            );
        }
        for o in s.op_seqs.clone().unwrap_or_default() {
            m.op_seqs.insert(opt_k32(&o.account_id), o.seq);
        }
        for e in s.psk_epochs.clone().unwrap_or_default() {
            m.psk_epochs.insert(e.epoch_id, opt_k32(&e.psk));
        }
        m.psk_current = s.psk_current;
        m.camouflage = s.camouflage.clone().map(|c| {
            (
                c.private_key.unwrap_or_default(),
                c.site.unwrap_or_default(),
            )
        });
        m.members.voters = s
            .voters
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|k| k.to_bytes())
            .collect();
        m.members.learners = s
            .learners
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|k| k.to_bytes())
            .collect();
        m.used_keys = s
            .used_keys
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|k| k.to_bytes())
            .collect();
        m.state_version = s.state_version.clone();
        m.retired_names = s
            .retired_names
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();
        if let Some(g) = &s.genesis {
            let (gen, root, em) = crate::store::open_genesis(g).context("snapshot genesis")?;
            m.root_key = root;
            m.emergency_key = em;
            m.pool = gen
                .overlay_pool
                .clone()
                .unwrap_or_default()
                .iter()
                .filter_map(cidr_to_net)
                .collect();
            m.genesis = Some((g.clone(), gen));
        }
        m.last_index = s.last_index;
        m.last_term = s.last_term;
        m.refresh_view();
        Ok(m)
    }

    pub fn snapshot_bytes(&self) -> Vec<u8> {
        use webjet_proto::Encodable;
        self.snapshot().encode_bytes()
    }

    pub fn restore_bytes(b: &[u8]) -> Result<Machine> {
        let s = wp::ControllerSnapshot::decode_bytes(b).map_err(|e| anyhow!("{e}"))?;
        Machine::restore(&s)
    }

    pub fn pending_by_lookup(&self, lookup_id: &Bytes32) -> Option<&Pending> {
        self.pending
            .values()
            .find(|p| crypto::enroll_lookup_id(&p.token_hash) == *lookup_id)
    }

    pub fn psk(&self, epoch: u16) -> Option<Bytes32> {
        self.psk_epochs.get(&epoch).copied()
    }

    /// Does the daily validity extension need proposing? (once a day)
    pub fn validity_due(&self, now: u64) -> bool {
        self.view.valid_until < now + VALIDITY_PERIOD - 24 * 60 * MINUTE + MINUTE
    }

    pub fn expiry_due(&self, now: u64) -> bool {
        self.pending.values().any(|p| p.expires_at < now)
    }
}

fn record_from(c: &wp::CreateEnrollment, node_id: Bytes32, key: Bytes32) -> wp::NodeRecord {
    wp::NodeRecord {
        node_id: Some(crypto::k32(&node_id)),
        identity_key: Some(crypto::k32(&key)),
        overlay_ips: c.overlay_ips.clone(),
        roles: c.roles.clone(),
        name: c.name.clone(),
        owner: c.owner,
        tags: c.tags.clone(),
        routes: c.routes.clone(),
        version: 1,
    }
}

fn check_tags(tags: &[String]) -> std::result::Result<Vec<String>, ApplyError> {
    for t in tags {
        if !valid_tag(t) {
            return rej(format!("invalid tag {t}"));
        }
    }
    Ok(sort_dedup(tags.to_vec()))
}

/// Leader bytes and our bytes describe the same leaf (§15.5 step 3).
fn leaf_equal(k: u8, key: &Bytes32, mine: &[u8], theirs: &[u8]) -> bool {
    if mine == theirs {
        return true;
    }
    if k == kind::ACCOUNT {
        return false; // account leaves are copied signed bytes
    }
    let (Ok(a), Ok(b)) = (leaf::decode(k, key, mine), leaf::decode(k, key, theirs)) else {
        return false;
    };
    match (a, b) {
        (LeafValue::Node(a), LeafValue::Node(b)) => a == b,
        (LeafValue::NodeTombstone(a), LeafValue::NodeTombstone(b)) => a == b,
        (LeafValue::Policy(a), LeafValue::Policy(b)) => a == b,
        (LeafValue::Dns(a), LeafValue::Dns(b)) => a == b,
        (LeafValue::Seeds(a), LeafValue::Seeds(b)) => a == b,
        (LeafValue::Limits(a), LeafValue::Limits(b)) => a == b,
        (LeafValue::Validity(a), LeafValue::Validity(b)) => a == b,
        (LeafValue::Transport(a), LeafValue::Transport(b)) => a == b,
        _ => false,
    }
}

/// Helpers for building operations (admin tool, tests).
pub mod ops {
    use super::*;
    use crate::crypto::KeyPair;
    use webjet_proto::Encodable;

    pub fn sign_op(
        key: &KeyPair,
        account_id: &Bytes32,
        seq: u64,
        issued_at: u64,
        op: AccountOp,
    ) -> Vec<u8> {
        let so = wp::SignedOp {
            signer: Some(crypto::k32(account_id)),
            op_seq: seq,
            issued_at,
            op: Some(op),
        };
        key.sign_envelope(mt::SIGNED_OP, so.encode_bytes())
            .encode_bytes()
    }

    pub fn op_entry(signed: Vec<u8>) -> EntryPayload {
        EntryPayload::OpEntry(Box::new(wp::OpEntry {
            signed_op: Some(signed),
        }))
    }

    pub fn ip(s: &str) -> wp::Cidr {
        types::host_cidr(s.parse().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::ops::*;
    use super::*;
    use crate::crypto::KeyPair;
    use crate::store::{testutil, Store};
    use crate::types::now_ms;
    use webjet_proto::Encodable;

    struct H {
        m: Machine,
        idx: u64,
        net: testutil::Net,
        seq: u64,
    }

    impl H {
        fn new() -> H {
            let net = testutil::net();
            let mut h = H {
                m: Machine::new(),
                idx: 0,
                net,
                seq: 0,
            };
            let g = EntryPayload::GenesisEntry(Box::new(wp::GenesisEntry {
                genesis: Some(h.net.genesis.clone()),
            }));
            h.run(g).unwrap();
            h
        }
        fn run(&mut self, p: EntryPayload) -> std::result::Result<Outcome, ApplyError> {
            self.idx += 1;
            let e = self.m.prepare(1, self.idx, now_ms(), p).map_err(|e| {
                self.idx -= 1;
                e
            })?;
            // Replicate through bytes, like the log does.
            let bytes = e.encode_bytes();
            let e2 = wp::LogEntry::decode_bytes(&bytes).unwrap();
            self.m.apply(&e2)
        }
        fn admin_op(&mut self, op: AccountOp) -> std::result::Result<Outcome, ApplyError> {
            self.seq += 1;
            let s = sign_op(&self.net.admin, &self.net.admin_id, self.seq, now_ms(), op);
            self.run(op_entry(s))
        }
    }

    fn enroll(h: &mut H, name: &str, ip: &str, key: &KeyPair) -> Bytes32 {
        let o = h
            .admin_op(AccountOp::CreateEnrollment(Box::new(
                wp::CreateEnrollment {
                    owner: Some(crypto::k32(&h.net.admin_id)),
                    name: Some(name.into()),
                    overlay_ips: Some(vec![super::ops::ip(ip)]),
                    roles: Some(vec![wp::Role::Data]),
                    tags: Some(vec!["tag:x".into()]),
                    identity_key: Some(crypto::k32(&key.public())),
                    ..Default::default()
                },
            )))
            .unwrap();
        o.node_id.unwrap()
    }

    #[test]
    fn genesis_and_enrollment() {
        let mut h = H::new();
        let k = KeyPair::generate();
        let id = enroll(&mut h, "laptop", "10.7.0.10", &k);
        assert!(h.m.view().nodes[&id].valid);
        // Duplicate name and IP are rejected.
        let k2 = KeyPair::generate();
        let r = h.admin_op(AccountOp::CreateEnrollment(Box::new(
            wp::CreateEnrollment {
                owner: Some(crypto::k32(&h.net.admin_id)),
                name: Some("laptop".into()),
                overlay_ips: Some(vec![super::ops::ip("10.7.0.11")]),
                identity_key: Some(crypto::k32(&k2.public())),
                ..Default::default()
            },
        )));
        assert!(matches!(r, Err(ApplyError::Rejected(_))));
        let r = h.admin_op(AccountOp::CreateEnrollment(Box::new(
            wp::CreateEnrollment {
                owner: Some(crypto::k32(&h.net.admin_id)),
                name: Some("other".into()),
                overlay_ips: Some(vec![super::ops::ip("10.7.0.10")]),
                identity_key: Some(crypto::k32(&k2.public())),
                ..Default::default()
            },
        )));
        assert!(matches!(r, Err(ApplyError::Rejected(_))));
        // Outside the pool.
        let r = h.admin_op(AccountOp::CreateEnrollment(Box::new(
            wp::CreateEnrollment {
                owner: Some(crypto::k32(&h.net.admin_id)),
                name: Some("other".into()),
                overlay_ips: Some(vec![super::ops::ip("192.168.0.1")]),
                identity_key: Some(crypto::k32(&k2.public())),
                ..Default::default()
            },
        )));
        assert!(matches!(r, Err(ApplyError::Rejected(_))));
    }

    #[test]
    fn token_enrollment_and_rekey() {
        let mut h = H::new();
        let token = crypto::random32();
        let th = crypto::token_hash(&token);
        let o = h
            .admin_op(AccountOp::CreateEnrollment(Box::new(
                wp::CreateEnrollment {
                    owner: Some(crypto::k32(&h.net.admin_id)),
                    name: Some("srv".into()),
                    overlay_ips: Some(vec![super::ops::ip("10.7.0.20")]),
                    token_hash: Some(crypto::k32(&th)),
                    expires_at: now_ms() + 3600_000,
                    ..Default::default()
                },
            )))
            .unwrap();
        let nid = o.node_id.unwrap();
        assert!(h
            .m
            .pending_by_lookup(&crypto::enroll_lookup_id(&th))
            .is_some());
        let k = KeyPair::generate();
        h.run(EntryPayload::RedeemEnrollmentEntry(Box::new(
            wp::RedeemEnrollmentEntry {
                token_hash: Some(crypto::k32(&th)),
                identity_key: Some(crypto::k32(&k.public())),
                node_id: Some(crypto::k32(&nid)),
            },
        )))
        .unwrap();
        assert_eq!(h.m.view().nodes[&nid].key, k.public());
        // Token is consumed.
        assert!(h.m.pending.is_empty());
        // Re-key with revoke_old_now.
        let th2 = crypto::token_hash(b"second");
        h.admin_op(AccountOp::RekeyNode(Box::new(wp::RekeyNode {
            node_id: Some(crypto::k32(&nid)),
            token_hash: Some(crypto::k32(&th2)),
            expires_at: now_ms() + 3600_000,
            revoke_old_now: true,
        })))
        .unwrap();
        assert!(!h.m.view().nodes[&nid].valid);
        let k2 = KeyPair::generate();
        h.run(EntryPayload::RedeemEnrollmentEntry(Box::new(
            wp::RedeemEnrollmentEntry {
                token_hash: Some(crypto::k32(&th2)),
                identity_key: Some(crypto::k32(&k2.public())),
                node_id: Some(crypto::k32(&nid)),
            },
        )))
        .unwrap();
        let n = &h.m.view().nodes[&nid];
        assert!(n.valid);
        assert_eq!(n.key, k2.public());
        assert_eq!(n.name, "srv");
        // The old key can't come back.
        let r = h.run(EntryPayload::RotateNodeKeyEntry(Box::new(
            wp::RotateNodeKeyEntry {
                rotation: Some({
                    let rot = wp::RotateNodeKey {
                        node_id: Some(crypto::k32(&nid)),
                        new_key: Some(crypto::k32(&k.public())),
                        issued_at: now_ms(),
                    };
                    let inner = k
                        .sign_envelope(mt::ROTATE_NODE_KEY_NEW, rot.encode_bytes())
                        .encode_bytes();
                    k2.sign_envelope(mt::ROTATE_NODE_KEY, inner).encode_bytes()
                }),
            },
        )));
        assert!(r.is_err());
    }

    #[test]
    fn replay_and_permissions() {
        let mut h = H::new();
        let k = KeyPair::generate();
        let id = enroll(&mut h, "a", "10.7.0.5", &k);
        let s = sign_op(
            &h.net.admin,
            &h.net.admin_id,
            100,
            now_ms(),
            AccountOp::RenameNode(Box::new(wp::RenameNode {
                node_id: Some(crypto::k32(&id)),
                name: Some("b".into()),
            })),
        );
        h.run(op_entry(s.clone())).unwrap();
        // Replay is rejected.
        assert!(h.run(op_entry(s)).is_err());
        // A normal account created by the admin can't update nodes it doesn't own.
        let bob = KeyPair::generate();
        let bob_id = crypto::random32();
        let rec = wp::AccountRecord {
            account_id: Some(crypto::k32(&bob_id)),
            account_key: Some(crypto::k32(&bob.public())),
            name: Some("bob".into()),
            admin: false,
            issuer_root: false,
            issuer: Some(crypto::k32(&h.net.admin_id)),
            version: 1,
        };
        let signed = h.net.admin.sign_obj(mt::ACCOUNT_RECORD, &rec);
        h.seq = 100;
        h.admin_op(AccountOp::PutAccount(Box::new(wp::PutAccount {
            record: Some(signed),
        })))
        .unwrap();
        let s = sign_op(
            &bob,
            &bob_id,
            1,
            now_ms(),
            AccountOp::TombstoneNode(Box::new(wp::TombstoneNode {
                node_id: Some(crypto::k32(&id)),
                reason: None,
            })),
        );
        assert!(h.run(op_entry(s)).is_err());
        // An admin can't create an admin.
        let eve_id = crypto::random32();
        let rec = wp::AccountRecord {
            account_id: Some(crypto::k32(&eve_id)),
            account_key: Some(crypto::k32(&KeyPair::generate().public())),
            name: Some("eve".into()),
            admin: true,
            issuer_root: false,
            issuer: Some(crypto::k32(&h.net.admin_id)),
            version: 1,
        };
        let signed = h.net.admin.sign_obj(mt::ACCOUNT_RECORD, &rec);
        assert!(h
            .admin_op(AccountOp::PutAccount(Box::new(wp::PutAccount {
                record: Some(signed)
            })))
            .is_err());
    }

    #[test]
    fn follower_detects_divergence() {
        let mut h = H::new();
        let k = KeyPair::generate();
        enroll(&mut h, "a", "10.7.0.5", &k);
        h.seq += 1;
        let s = sign_op(
            &h.net.admin,
            &h.net.admin_id,
            h.seq,
            now_ms(),
            AccountOp::RenameNode(Box::new(wp::RenameNode {
                node_id: Some(crypto::k32(&h.m.view().by_name["a"])),
                name: Some("c".into()),
            })),
        );
        let mut e = h.m.prepare(1, h.idx + 1, now_ms(), op_entry(s)).unwrap();
        // Tamper with the leader's leaf bytes.
        let mut leaves = e.leaves.clone().unwrap();
        let mut rec = match leaf::decode(
            leaves[0].kind,
            &opt_k32(&leaves[0].key),
            leaves[0].bytes.as_ref().unwrap(),
        )
        .unwrap()
        {
            LeafValue::Node(r) => r,
            _ => panic!(),
        };
        rec.tags = Some(vec!["tag:admin".into()]);
        leaves[0].bytes = Some(leaf::encode_node(&rec));
        e.leaves = Some(leaves);
        let mut follower = h.m.clone();
        assert!(matches!(follower.apply(&e), Err(ApplyError::Divergence(_))));
    }

    #[test]
    fn replicas_agree_and_store_verifies() {
        let mut h = H::new();
        let mut replica = Machine::new();
        // Replay the same log on a fresh replica through a snapshot.
        let k = KeyPair::generate();
        enroll(&mut h, "n1", "10.7.0.7", &k);
        let snap = h.m.snapshot_bytes();
        replica = Machine::restore_bytes(&snap).unwrap_or(replica);
        assert_eq!(replica.root(), h.m.root());
        // A node's store accepts the controller's tree through a signed head.
        let ctl = KeyPair::generate();
        let cert = wp::SigningKeyCert {
            signing_key_id: Some(crypto::k32(&crypto::signing_key_id(&ctl.public()))),
            signing_key: Some(crypto::k32(&ctl.public())),
            controller: Some(crypto::k32(&[9; 32])),
            cert_serial: 1,
        };
        let cert_raw = h.net.root.sign_obj(mt::SIGNING_KEY_CERT, &cert);
        let mut st = Store::new(h.net.genesis.clone()).unwrap();
        st.add_cert(&cert_raw).unwrap();
        let head = wp::SignedTreeHead {
            signing_key_id: cert.signing_key_id,
            version: h.m.last_index,
            root: Some(crypto::k32(&h.m.root())),
            state_version: 1,
            issued_at: now_ms(),
            expires_at: now_ms() + 3600_000,
        };
        let head_raw = ctl.sign_obj(mt::SIGNED_TREE_HEAD, &head);
        assert_eq!(
            st.offer_head(&head_raw).unwrap(),
            crate::store::HeadOutcome::NeedSync
        );
        let leaves: Vec<_> =
            h.m.tree
                .iter()
                .map(|(_, e)| (e.kind, e.key, Some(e.bytes.clone())))
                .collect();
        st.install(&head_raw, leaves).unwrap();
        let id = st.view().by_name["n1"];
        assert!(st.node_trusted(&id));
        // Rollback is rejected.
        let old = wp::SignedTreeHead {
            version: 1,
            ..head.clone()
        };
        assert_eq!(
            st.offer_head(&ctl.sign_obj(mt::SIGNED_TREE_HEAD, &old))
                .unwrap(),
            crate::store::HeadOutcome::Known
        );
        // Equivocation is detected.
        let eq = wp::SignedTreeHead {
            root: Some(crypto::k32(&[1; 32])),
            ..head.clone()
        };
        assert_eq!(
            st.offer_head(&ctl.sign_obj(mt::SIGNED_TREE_HEAD, &eq))
                .unwrap(),
            crate::store::HeadOutcome::Equivocation
        );
        // An offline tombstone takes the node off the network.
        let tomb = wp::Tombstone {
            node_id: Some(crypto::k32(&id)),
            version: 99,
            reason: Some("lost".into()),
        };
        st.add_offline_tombstone(&h.net.emergency.sign_obj(mt::TOMBSTONE, &tomb))
            .unwrap();
        assert!(!st.node_trusted(&id));
        // A forged head (signed by an uncertified key) is rejected.
        let rogue = KeyPair::generate();
        assert!(st
            .offer_head(&rogue.sign_obj(mt::SIGNED_TREE_HEAD, &head))
            .is_err());
    }

    #[test]
    fn account_tombstone_revokes_nodes() {
        let mut h = H::new();
        let bob = KeyPair::generate();
        let bob_id = crypto::random32();
        let rec = wp::AccountRecord {
            account_id: Some(crypto::k32(&bob_id)),
            account_key: Some(crypto::k32(&bob.public())),
            name: Some("bob".into()),
            admin: false,
            issuer_root: false,
            issuer: Some(crypto::k32(&h.net.admin_id)),
            version: 1,
        };
        h.admin_op(AccountOp::PutAccount(Box::new(wp::PutAccount {
            record: Some(h.net.admin.sign_obj(mt::ACCOUNT_RECORD, &rec)),
        })))
        .unwrap();
        let k = KeyPair::generate();
        let o = h
            .admin_op(AccountOp::CreateEnrollment(Box::new(
                wp::CreateEnrollment {
                    owner: Some(crypto::k32(&bob_id)),
                    name: Some("bobs-laptop".into()),
                    overlay_ips: Some(vec![super::ops::ip("10.7.0.30")]),
                    identity_key: Some(crypto::k32(&k.public())),
                    ..Default::default()
                },
            )))
            .unwrap();
        let nid = o.node_id.unwrap();
        assert!(h.m.view().nodes[&nid].valid);
        // Bob can rename his own node.
        let s = sign_op(
            &bob,
            &bob_id,
            1,
            now_ms(),
            AccountOp::RenameNode(Box::new(wp::RenameNode {
                node_id: Some(crypto::k32(&nid)),
                name: Some("bob-mac".into()),
            })),
        );
        h.run(op_entry(s)).unwrap();
        let t = wp::AccountTombstone {
            account_id: Some(crypto::k32(&bob_id)),
            version: 2,
            revoke_issued: false,
            reason: Some("left".into()),
        };
        h.admin_op(AccountOp::TombstoneAccount(Box::new(
            wp::TombstoneAccount {
                tombstone: Some(h.net.admin.sign_obj(mt::ACCOUNT_TOMBSTONE, &t)),
            },
        )))
        .unwrap();
        assert!(!h.m.view().nodes[&nid].valid);
        // The name is retired.
        let rec2 = wp::AccountRecord {
            account_id: Some(crypto::k32(&crypto::random32())),
            name: Some("bob".into()),
            ..rec
        };
        assert!(h
            .admin_op(AccountOp::PutAccount(Box::new(wp::PutAccount {
                record: Some(h.net.admin.sign_obj(mt::ACCOUNT_RECORD, &rec2))
            })))
            .is_err());
    }

    #[test]
    fn validity_and_psk() {
        let mut h = H::new();
        let ts = now_ms() + 1000;
        h.idx += 1;
        let e =
            h.m.prepare(
                1,
                h.idx,
                ts,
                EntryPayload::ExtendValidityEntry(Box::new(wp::ExtendValidityEntry {
                    valid_until: ts + VALIDITY_PERIOD,
                })),
            )
            .unwrap();
        h.m.apply(&e).unwrap();
        assert_eq!(h.m.view().valid_until, ts + VALIDITY_PERIOD);
        // Wrong period rejected.
        assert!(h
            .m
            .prepare(
                1,
                h.idx + 1,
                ts + 5,
                EntryPayload::ExtendValidityEntry(Box::new(wp::ExtendValidityEntry {
                    valid_until: ts + 5 + VALIDITY_PERIOD + 1
                }))
            )
            .is_err());
        h.admin_op(AccountOp::RotatePsk(Box::new(wp::RotatePsk {
            epoch_id: 1,
        })))
        .unwrap();
        assert!(h.m.psk(1).is_some());
        assert!(h
            .admin_op(AccountOp::RotatePsk(Box::new(wp::RotatePsk {
                epoch_id: 1
            })))
            .is_err());
    }
}
