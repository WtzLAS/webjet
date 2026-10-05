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

use crate::crypto::{self, Bytes32, open_envelope, open_expect, opt_k32};
use crate::leaf::{self, LeafValue, SINGLETON};
use crate::merkle::{Tree, kind};
use crate::policy::{Policy, Selector};
use crate::store::{View, build_view};
use crate::types::{
    self, Grant, MINUTE, SKEW_SHORT_RECORD, VALIDITY_PERIOD, canonical, cidr_to_net, overlaps,
    sort_dedup, valid_name, valid_tag,
};
use anyhow::{Context, Result, anyhow};
use ipnet::IpNet;
use std::collections::{BTreeMap, BTreeSet};
use webjet_proto::{self as wp, AccountOp, Decodable, EntryPayload, msg_type as mt};

#[derive(Clone, Debug)]
pub struct Pending {
    pub token_hash: Bytes32,
    pub expires_at: u64,
    pub is_rekey: bool,
    pub node_id: Bytes32,
    pub create: Option<wp::CreateEnrollment>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
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

/// New entries may not use the per-setting operations that 0.4.0 replaced
/// with SetNetworkConfig (§6.18). Only the leader's `prepare` checks this:
/// entries already in the log still apply as before.
fn refuse_retired(payload: &EntryPayload) -> std::result::Result<(), ApplyError> {
    let EntryPayload::OpEntry(o) = payload else {
        return Ok(());
    };
    let Some(op) = o
        .signed_op
        .as_deref()
        .and_then(|raw| open_envelope(raw).ok())
        .and_then(|v| v.decode::<wp::SignedOp>().ok())
        .and_then(|op| op.op)
    else {
        return Ok(());
    };
    let name = match op {
        AccountOp::SetPolicy(_) => "SetPolicy",
        AccountOp::SetDns(_) => "SetDns",
        AccountOp::SetSeeds(_) => "SetSeeds",
        AccountOp::SetLimits(_) => "SetLimits",
        AccountOp::SetTransport(_) => "SetTransport",
        _ => return Ok(()),
    };
    rej(format!(
        "{name} is retired: the network configuration is one document now; use `webjetctl network config` (0.4.0 or later)"
    ))
}

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
        refuse_retired(&payload)?;
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
            let (genesis_rec, root, em) = crate::store::open_genesis(&g)
                .map_err(|e| ApplyError::Divergence(e.to_string()))?;
            self.root_key = root;
            self.emergency_key = em;
            self.pool = genesis_rec
                .overlay_pool
                .clone()
                .unwrap_or_default()
                .iter()
                .filter_map(cidr_to_net)
                .collect();
            self.genesis = Some((g, genesis_rec));
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
                let (genesis_rec, root, _) = crate::store::open_genesis(&raw)
                    .map_err(|e| ApplyError::Rejected(e.to_string()))?;
                let admin = genesis_rec
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
                return rej("raw membership entries are not accepted");
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
                if let Some(o) = u.owner
                    && !o.is_zero()
                {
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
                if u.set_overlay_ips {
                    rec.overlay_ips = Some(
                        self.check_ips(&u.overlay_ips.clone().unwrap_or_default(), Some(&id))?,
                    );
                }
                if u.set_roles {
                    rec.roles = Some(sort_dedup(u.roles.clone().unwrap_or_default()));
                }
                if let Some(ctl) = u.control {
                    if !ctl && self.members.contains(&id) {
                        return rej(
                            "the node is a controller cluster member; remove it from the cluster first",
                        );
                    }
                    rec.control = Some(ctl);
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
                if self.tree.get(kind::NODE_CONFIG, &id).is_some() {
                    fx.leaves.push((kind::NODE_CONFIG, id, None));
                }
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
            // SetPolicy … SetTransport come from webjetctl before 0.4.0. They
            // stay valid so logs written then replay the same (§15.5).
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
                self.check_policy(&pol)?;
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
                self.check_seeds(&seeds.entries.clone().unwrap_or_default())?;
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
            AccountOp::SetNetworkConfig(c) => {
                need_admin()?;
                let cfg = c
                    .config
                    .ok_or_else(|| ApplyError::Rejected("missing network config".into()))?;
                self.set_network_config(*cfg, fx)?;
            }
            AccountOp::SetNodeConfig(c) => {
                let cfg = c
                    .config
                    .ok_or_else(|| ApplyError::Rejected("missing node config".into()))?;
                let id = opt_k32(&cfg.node_id);
                owner_or_admin(&id)?;
                self.set_node_config(*cfg, fx)?;
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
                        let Some(node) = self.view.nodes.get(&id).filter(|n| n.valid) else {
                            return rej("learner must be a valid enrolled node");
                        };
                        if node.rec.control != Some(true) {
                            return rej(
                                "learner must hold the control role (webjetctl network node update --roles)",
                            );
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
        if let Some(e) = self.tree.get(k, &SINGLETON)
            && let Ok(old) = leaf::decode(k, &SINGLETON, &e.bytes)
            && v <= leaf::version(&old)
        {
            return rej("version must increase");
        }
        Ok(())
    }

    /// Policy tests run against the current nodes (§6.7).
    fn check_policy(&self, pol: &wp::Policy) -> std::result::Result<(), ApplyError> {
        let parsed = Policy::from_wire(pol).map_err(|e| ApplyError::Rejected(e.to_string()))?;
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
            .map_err(|e| ApplyError::Rejected(e.to_string()))
    }

    /// Seeds must name valid relays or controllers and parse (§6.8).
    fn check_seeds(&self, entries: &[wp::SeedEntry]) -> std::result::Result<(), ApplyError> {
        for e in entries {
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
                if h.parse::<std::net::IpAddr>().is_err() && !crate::validate::valid_dns_name(&h) {
                    return rej(format!("seed address {h} doesn't parse"));
                }
                if a.port == 0 {
                    return rej("seed port 0");
                }
            }
        }
        Ok(())
    }

    /// The network configuration (§6.18): one document, one version, written
    /// as the five network leaves in one entry. A section left out is
    /// written empty, which means its built-in defaults.
    fn set_network_config(
        &self,
        cfg: wp::NetworkConfig,
        fx: &mut Effects,
    ) -> std::result::Result<(), ApplyError> {
        let version = cfg.version;
        if version <= self.view.network_version {
            return rej(format!(
                "network config version must be above {} (someone applied a newer one; start again from `webjetctl network config show`)",
                self.view.network_version
            ));
        }
        let mut pol = cfg.policy.map(|b| *b).unwrap_or_default();
        pol.version = version;
        self.check_policy(&pol)?;
        let mut dns = cfg.dns.map(|b| *b).unwrap_or_default();
        dns.version = version;
        self.validate_dns(&dns)?;
        let mut seeds = cfg.seeds.map(|b| *b).unwrap_or_default();
        seeds.version = version;
        self.check_seeds(&seeds.entries.clone().unwrap_or_default())?;
        let mut lim = cfg.limits.map(|b| *b).unwrap_or_default();
        lim.version = version;
        crate::validate::limits(&lim).map_err(|e| ApplyError::Rejected(e.to_string()))?;
        let mut tr = cfg.transport.map(|b| *b).unwrap_or_default();
        tr.version = version;
        crate::validate::transport(&tr).map_err(|e| ApplyError::Rejected(e.to_string()))?;
        fx.leaves.extend([
            (kind::POLICY, SINGLETON, Some(leaf::encode_policy(&pol))),
            (kind::DNS, SINGLETON, Some(leaf::encode_dns(&dns))),
            (kind::SEEDS, SINGLETON, Some(leaf::encode_seeds(&seeds))),
            (kind::LIMITS, SINGLETON, Some(leaf::encode_limits(&lim))),
            (
                kind::TRANSPORT,
                SINGLETON,
                Some(leaf::encode_transport(&tr)),
            ),
        ]);
        fx.outcome.description = format!("set network config version {version}");
        Ok(())
    }

    /// One node's configuration (§6.19). An empty one removes the leaf.
    fn set_node_config(
        &self,
        cfg: wp::NodeConfig,
        fx: &mut Effects,
    ) -> std::result::Result<(), ApplyError> {
        let id = opt_k32(&cfg.node_id);
        let rec = self.live_node(&id)?;
        let current = self.view.node_configs.get(&id).map_or(0, |c| c.version);
        if cfg.version <= current {
            return rej(format!(
                "node config version must be above {current} (someone changed it; start again from `webjetctl local config show`)"
            ));
        }
        crate::validate::limits(&wp::Limits {
            version: 0,
            defaults: cfg.limits.clone(),
            overrides: None,
        })
        .map_err(|e| ApplyError::Rejected(e.to_string()))?;
        self.check_seeds(&cfg.seeds.clone().unwrap_or_default())?;
        // Node records and zones are checked like the network's, against
        // the network's suffix and with the network's zones also allowed.
        let net = self.view.dns.clone().unwrap_or_default();
        let mut forward = cfg.dns_forward.clone().unwrap_or_default();
        forward.extend(net.forward.clone().unwrap_or_default());
        self.validate_dns(&wp::DnsConfig {
            version: 0,
            suffix: net.suffix.clone(),
            resolver_ip: None,
            records: cfg.dns_records.clone(),
            forward: Some(forward),
        })?;
        let proxy = cfg.proxy.clone().unwrap_or_default();
        crate::proxy::rules(&proxy).map_err(|e| ApplyError::Rejected(e.to_string()))?;
        if !proxy.is_empty()
            && !rec
                .roles
                .clone()
                .unwrap_or_default()
                .contains(&wp::Role::Data)
        {
            return rej("proxy rules need the data role on the node");
        }
        let name = rec.name.unwrap_or_default();
        let empty = [
            cfg.proxy.as_ref().map(Vec::len),
            cfg.priorities.as_ref().map(Vec::len),
            cfg.limits.as_ref().map(Vec::len),
            cfg.seeds.as_ref().map(Vec::len),
            cfg.dns_records.as_ref().map(Vec::len),
            cfg.dns_forward.as_ref().map(Vec::len),
        ]
        .iter()
        .all(|n| n.unwrap_or(0) == 0);
        if empty {
            if current == 0 {
                return rej("the node has no configuration to clear");
            }
            fx.leaves.push((kind::NODE_CONFIG, id, None));
            fx.outcome.description = format!("clear node config of {name}");
        } else {
            fx.leaves
                .push((kind::NODE_CONFIG, id, Some(leaf::encode_node_config(&cfg))));
            fx.outcome.description = format!("set node config of {name} version {}", cfg.version);
        }
        fx.outcome.node_id = Some(id);
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
        if let Some(id) = self.view.by_name.get(name)
            && Some(id) != except
            && !self.view.tombstoned_nodes.contains(id)
        {
            return rej(format!("node name {name} is taken"));
        }
        for p in self.pending.values() {
            if let Some(c) = &p.create
                && c.name.as_deref() == Some(name)
            {
                return rej(format!(
                    "node name {name} is reserved by a pending enrollment"
                ));
            }
        }
        Ok(())
    }

    /// The resolver addresses, which no node may hold: the DnsConfig's, or
    /// the default from the overlay pool (§11.10.1).
    fn resolver_ips(&self) -> Vec<std::net::IpAddr> {
        self.view.resolver_ips(&self.pool)
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
                if let Some(cr) = &p.create
                    && cr
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
        let mut accepted: Vec<Grant> = Vec::new();
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
            if accepted
                .iter()
                .any(|pg| overlaps(&pg.published, &g.published))
            {
                return rej("overlapping grants on one node");
            }
            accepted.push(g);
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
            // (bootstrap, ops guide 2.1) may be enrolled under a fixed id.
            if !self.members.contains(&f) {
                return rej("a fixed node_id is only allowed for a Raft member without a record");
            }
            if !c.control {
                return rej("a controller cluster member's record needs the control role");
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
        // record (a bootstrapping controller) keeps its own id (ops guide 2.1).
        let node_id = opt_k32(&r.node_id);
        let member_bootstrap = !p.is_rekey
            && node_id != p.node_id
            && self.members.contains(&node_id)
            && self.tree.get(kind::NODE, &node_id).is_none();
        if p.node_id != node_id && !member_bootstrap {
            return rej("node id does not match the pending enrollment");
        }
        if member_bootstrap && !p.create.as_ref().is_some_and(|c| c.control) {
            return rej(
                "a controller cluster member's record needs the control role (webjetctl network node enroll --roles ...,control)",
            );
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
            let (genesis_rec, root, em) =
                crate::store::open_genesis(g).context("snapshot genesis")?;
            m.root_key = root;
            m.emergency_key = em;
            m.pool = genesis_rec
                .overlay_pool
                .clone()
                .unwrap_or_default()
                .iter()
                .filter_map(cidr_to_net)
                .collect();
            m.genesis = Some((g.clone(), genesis_rec));
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
        // Left out unless granted, so records stay as older software wrote them.
        control: c.control.then_some(true),
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

    /// A host address as a CIDR (`10.7.0.12` → `10.7.0.12/32`).
    pub fn ip(s: &str) -> Option<wp::Cidr> {
        s.parse().ok().map(types::host_cidr)
    }
}

#[cfg(test)]
mod tests {
    use super::ops::*;
    use super::*;
    use crate::crypto::KeyPair;
    use crate::store::{Store, testutil};
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
            let e = self.m.prepare(1, self.idx, now_ms(), p).inspect_err(|_| {
                self.idx -= 1;
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
                    overlay_ips: Some(vec![super::ops::ip(ip).unwrap()]),
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
    fn default_resolver_is_reserved() {
        let mut h = H::new();
        // The pool is 10.7.0.0/16: the default resolver is its top host.
        assert_eq!(
            h.m.view().resolver_ips(&h.m.pool),
            vec!["10.7.255.254".parse::<std::net::IpAddr>().unwrap()]
        );
        let k = KeyPair::generate();
        let r = h.admin_op(AccountOp::CreateEnrollment(Box::new(
            wp::CreateEnrollment {
                owner: Some(crypto::k32(&h.net.admin_id)),
                name: Some("dns-thief".into()),
                overlay_ips: Some(vec![super::ops::ip("10.7.255.254").unwrap()]),
                identity_key: Some(crypto::k32(&k.public())),
                ..Default::default()
            },
        )));
        assert!(matches!(r, Err(ApplyError::Rejected(_))), "{r:?}");
        enroll(&mut h, "fine", "10.7.255.253", &k);
    }

    #[test]
    fn default_resolver_skips_taken_addresses() {
        let pool: Vec<ipnet::IpNet> =
            vec!["10.7.0.0/16".parse().unwrap(), "fd7a::/64".parse().unwrap()];
        let top: std::net::IpAddr = "10.7.255.254".parse().unwrap();
        let ips = crate::store::default_resolver_ips(&pool, |ip| *ip == top);
        assert_eq!(ips[0], "10.7.255.253".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(
            ips[1],
            "fd7a::ffff:ffff:ffff:ffff"
                .parse::<std::net::IpAddr>()
                .unwrap()
        );
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
                overlay_ips: Some(vec![super::ops::ip("10.7.0.11").unwrap()]),
                identity_key: Some(crypto::k32(&k2.public())),
                ..Default::default()
            },
        )));
        assert!(matches!(r, Err(ApplyError::Rejected(_))));
        let r = h.admin_op(AccountOp::CreateEnrollment(Box::new(
            wp::CreateEnrollment {
                owner: Some(crypto::k32(&h.net.admin_id)),
                name: Some("other".into()),
                overlay_ips: Some(vec![super::ops::ip("10.7.0.10").unwrap()]),
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
                overlay_ips: Some(vec![super::ops::ip("192.168.0.1").unwrap()]),
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
                    overlay_ips: Some(vec![super::ops::ip("10.7.0.20").unwrap()]),
                    token_hash: Some(crypto::k32(&th)),
                    expires_at: now_ms() + 3_600_000,
                    ..Default::default()
                },
            )))
            .unwrap();
        let nid = o.node_id.unwrap();
        assert!(
            h.m.pending_by_lookup(&crypto::enroll_lookup_id(&th))
                .is_some()
        );
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
            expires_at: now_ms() + 3_600_000,
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
        assert!(
            h.admin_op(AccountOp::PutAccount(Box::new(wp::PutAccount {
                record: Some(signed)
            })))
            .is_err()
        );
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
            issuer: None,
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
            expires_at: now_ms() + 3_600_000,
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
        assert!(
            st.offer_head(&rogue.sign_obj(mt::SIGNED_TREE_HEAD, &head))
                .is_err()
        );
    }

    fn enroll_roles(h: &mut H, name: &str, ip: &str, key: &KeyPair, control: bool) -> Bytes32 {
        let o = h
            .admin_op(AccountOp::CreateEnrollment(Box::new(
                wp::CreateEnrollment {
                    owner: Some(crypto::k32(&h.net.admin_id)),
                    name: Some(name.into()),
                    overlay_ips: Some(vec![super::ops::ip(ip).unwrap()]),
                    roles: Some(vec![wp::Role::Data, wp::Role::Relay]),
                    identity_key: Some(crypto::k32(&key.public())),
                    control,
                    ..Default::default()
                },
            )))
            .unwrap();
        o.node_id.unwrap()
    }

    fn cert_for(node: &Bytes32, key: &KeyPair, issuer: Option<Vec<u8>>) -> wp::SigningKeyCert {
        wp::SigningKeyCert {
            signing_key_id: Some(crypto::k32(&crypto::signing_key_id(&key.public()))),
            signing_key: Some(crypto::k32(&key.public())),
            controller: Some(crypto::k32(node)),
            cert_serial: 1,
            issuer,
        }
    }

    fn head_for(h: &mut H, key: &KeyPair) -> Vec<u8> {
        let head = wp::SignedTreeHead {
            signing_key_id: Some(crypto::k32(&crypto::signing_key_id(&key.public()))),
            version: h.m.last_index,
            root: Some(crypto::k32(&h.m.root())),
            state_version: 1,
            issued_at: now_ms(),
            expires_at: now_ms() + 3_600_000,
        };
        key.sign_obj(mt::SIGNED_TREE_HEAD, &head)
    }

    fn install_tree(h: &mut H, st: &mut Store, head: &[u8]) {
        let leaves: Vec<_> =
            h.m.tree
                .iter()
                .map(|(_, e)| (e.kind, e.key, Some(e.bytes.clone())))
                .collect();
        st.install(head, leaves).unwrap();
    }

    #[test]
    fn control_role_and_admin_certificates() {
        let mut h = H::new();
        let admin_rec = wp::Genesis::decode_bytes(&h.net.genesis)
            .unwrap()
            .first_admin
            .unwrap();
        let (ka, kb, kc) = (
            KeyPair::generate(),
            KeyPair::generate(),
            KeyPair::generate(),
        );
        let ctl = enroll_roles(&mut h, "ctl", "10.7.0.10", &ka, true);
        let plain = enroll_roles(&mut h, "plain", "10.7.0.11", &kb, false);
        let legacy = enroll_roles(&mut h, "legacy", "10.7.0.12", &kc, false);
        // The record carries the role only when granted.
        assert_eq!(h.m.view().nodes[&ctl].rec.control, Some(true));
        assert_eq!(h.m.view().nodes[&plain].rec.control, None);
        assert!(h.m.view().nodes[&ctl].control_role);
        let (sa, sb, sc) = (
            KeyPair::generate(),
            KeyPair::generate(),
            KeyPair::generate(),
        );
        let admin = h.net.admin.clone();
        let admin_cert = |node, key| {
            admin.sign_obj(
                mt::SIGNING_KEY_CERT,
                &cert_for(node, key, Some(admin_rec.clone())),
            )
        };
        let (cert_a, cert_b) = (admin_cert(&ctl, &sa), admin_cert(&plain, &sb));
        let mut st = Store::new(h.net.genesis.clone()).unwrap();
        // An admin may certify a controller's key; heads from it verify.
        assert!(st.add_cert(&cert_a).unwrap());
        assert!(!st.add_cert(&cert_a).unwrap(), "duplicate");
        let again = h.net.admin.sign_obj(
            mt::SIGNING_KEY_CERT,
            &wp::SigningKeyCert {
                cert_serial: 2,
                ..cert_for(&ctl, &sa, Some(admin_rec.clone()))
            },
        );
        assert!(!st.add_cert(&again).unwrap(), "one cert per admin and key");
        let head = head_for(&mut h, &sa);
        install_tree(&mut h, &mut st, &head);
        assert!(st.view().is_controller(&ctl));
        assert!(st.view().nodes[&ctl].control);
        // An admin's cert for a node without the control role doesn't make
        // it a controller.
        st.add_cert(&cert_b).unwrap();
        assert!(!st.view().is_controller(&plain));
        // A root-signed cert still works for a record from before the role
        // existed (field absent), as before.
        st.add_cert(
            &h.net
                .root
                .sign_obj(mt::SIGNING_KEY_CERT, &cert_for(&legacy, &sc, None)),
        )
        .unwrap();
        assert!(st.view().is_controller(&legacy));
        // Malformed issuers are refused.
        let no_issuer = h.net.admin.sign_obj(
            mt::SIGNING_KEY_CERT,
            &cert_for(&ctl, &KeyPair::generate(), None),
        );
        assert!(st.add_cert(&no_issuer).is_err());
        let wrong_key = KeyPair::generate().sign_obj(
            mt::SIGNING_KEY_CERT,
            &cert_for(&ctl, &KeyPair::generate(), Some(admin_rec.clone())),
        );
        assert!(st.add_cert(&wrong_key).is_err());
        let root_with_issuer = h.net.root.sign_obj(
            mt::SIGNING_KEY_CERT,
            &cert_for(&ctl, &KeyPair::generate(), Some(admin_rec.clone())),
        );
        assert!(st.add_cert(&root_with_issuer).is_err());
        // A key certified for one node can't be certified for another.
        assert!(st.add_cert(&admin_cert(&plain, &sa)).is_err());
        // Taking the role away ends CONTROL, cert or not.
        h.admin_op(AccountOp::UpdateNode(Box::new(wp::UpdateNode {
            node_id: Some(crypto::k32(&legacy)),
            control: Some(false),
            ..Default::default()
        })))
        .unwrap();
        let head = head_for(&mut h, &sa);
        install_tree(&mut h, &mut st, &head);
        assert!(!st.view().is_controller(&legacy));
        assert!(st.view().is_controller(&ctl));
        // Revoking the admin voids the certs it signed: their heads no
        // longer verify.
        let tomb = wp::AccountTombstone {
            account_id: Some(crypto::k32(&h.net.admin_id)),
            version: 99,
            revoke_issued: false,
            reason: None,
        };
        st.add_offline_tombstone(&h.net.root.sign_obj(mt::ACCOUNT_TOMBSTONE, &tomb))
            .unwrap();
        assert!(!st.view().is_controller(&ctl));
        assert!(st.verify_head(&head_for(&mut h, &sa)).is_err());
        // The root re-signs it; the root's cert replaces the admin's.
        st.add_cert(
            &h.net
                .root
                .sign_obj(mt::SIGNING_KEY_CERT, &cert_for(&ctl, &sa, None)),
        )
        .unwrap();
        assert!(st.verify_head(&head_for(&mut h, &sa)).is_ok());
        assert_eq!(
            st.certs()
                .filter(|c| opt_k32(&c.cert.controller) == ctl)
                .count(),
            1
        );
        // Arrival order doesn't matter: a store that sees the root's cert
        // first ends up with the same set.
        let mut st2 = Store::new(h.net.genesis.clone()).unwrap();
        st2.add_cert(
            &h.net
                .root
                .sign_obj(mt::SIGNING_KEY_CERT, &cert_for(&ctl, &sa, None)),
        )
        .unwrap();
        assert!(!st2.add_cert(&cert_a).unwrap());
    }

    #[test]
    fn cluster_members_need_the_control_role() {
        let mut h = H::new();
        let (ka, kb) = (KeyPair::generate(), KeyPair::generate());
        let ctl = enroll_roles(&mut h, "ctl", "10.7.0.10", &ka, true);
        let plain = enroll_roles(&mut h, "plain", "10.7.0.11", &kb, false);
        let change = |h: &mut H, change, id: &Bytes32| {
            h.admin_op(AccountOp::ChangeMembership(Box::new(
                wp::ChangeMembership {
                    change,
                    node_id: Some(crypto::k32(id)),
                },
            )))
        };
        assert!(change(&mut h, wp::MembershipChange::AddLearner, &plain).is_err());
        change(&mut h, wp::MembershipChange::AddLearner, &ctl).unwrap();
        // A member keeps its role until it leaves the cluster.
        let drop_role = |h: &mut H| {
            h.admin_op(AccountOp::UpdateNode(Box::new(wp::UpdateNode {
                node_id: Some(crypto::k32(&ctl)),
                control: Some(false),
                ..Default::default()
            })))
        };
        assert!(drop_role(&mut h).is_err());
        change(&mut h, wp::MembershipChange::Remove, &ctl).unwrap();
        drop_role(&mut h).unwrap();
        assert!(!h.m.view().nodes[&ctl].control_role);
        // Granting it again through the role set.
        h.admin_op(AccountOp::UpdateNode(Box::new(wp::UpdateNode {
            node_id: Some(crypto::k32(&plain)),
            set_roles: true,
            roles: Some(vec![wp::Role::Data]),
            control: Some(true),
            ..Default::default()
        })))
        .unwrap();
        let n = &h.m.view().nodes[&plain];
        assert!(n.control_role && n.data && !n.relay);
    }

    /// §13.4: revoking an admin without `revoke_issued` keeps the normal
    /// accounts it created; with it, they go too. A normal account given a
    /// new key by an admin stays valid and only the new key signs.
    #[test]
    fn admin_revocation_and_account_rekey() {
        for revoke_issued in [false, true] {
            let mut h = H::new();
            // carol: a second admin (root-signed); dave: created by carol.
            let carol = KeyPair::generate();
            let carol_id = crypto::random32();
            let crec = wp::AccountRecord {
                account_id: Some(crypto::k32(&carol_id)),
                account_key: Some(crypto::k32(&carol.public())),
                name: Some("carol".into()),
                admin: true,
                issuer_root: true,
                issuer: None,
                version: 1,
            };
            h.run(EntryPayload::RootAccountEntry(Box::new(
                wp::RootAccountEntry {
                    record: Some(h.net.root.sign_obj(mt::ACCOUNT_RECORD, &crec)),
                },
            )))
            .unwrap();
            let dave = KeyPair::generate();
            let dave_id = crypto::random32();
            let drec = wp::AccountRecord {
                account_id: Some(crypto::k32(&dave_id)),
                account_key: Some(crypto::k32(&dave.public())),
                name: Some("dave".into()),
                admin: false,
                issuer_root: false,
                issuer: Some(crypto::k32(&carol_id)),
                version: 1,
            };
            let s = sign_op(
                &carol,
                &carol_id,
                1,
                now_ms(),
                AccountOp::PutAccount(Box::new(wp::PutAccount {
                    record: Some(carol.sign_obj(mt::ACCOUNT_RECORD, &drec)),
                })),
            );
            h.run(op_entry(s)).unwrap();
            assert!(h.m.view().accounts[&dave_id].valid);
            // alice gives dave a new key.
            let dave2 = KeyPair::generate();
            let drec2 = wp::AccountRecord {
                account_key: Some(crypto::k32(&dave2.public())),
                issuer: Some(crypto::k32(&h.net.admin_id)),
                version: 2,
                ..drec
            };
            h.admin_op(AccountOp::PutAccount(Box::new(wp::PutAccount {
                record: Some(h.net.admin.sign_obj(mt::ACCOUNT_RECORD, &drec2)),
            })))
            .unwrap();
            assert!(h.m.view().accounts[&dave_id].valid);
            let rename = |k: &KeyPair, seq| {
                op_entry(sign_op(
                    k,
                    &dave_id,
                    seq,
                    now_ms(),
                    AccountOp::RenameNode(Box::new(wp::RenameNode {
                        node_id: Some(crypto::k32(&crypto::random32())),
                        name: Some("x".into()),
                    })),
                ))
            };
            let e = h.run(rename(&dave, 1)).unwrap_err();
            assert!(e.to_string().contains("current key"), "{e}");
            let e = h.run(rename(&dave2, 1)).unwrap_err();
            assert!(!e.to_string().contains("current key"), "{e}");
            // The root revokes carol. dave was re-issued by alice, so only
            // a fresh account of carol's shows the cascade: eve.
            let eve_id = crypto::random32();
            let erec = wp::AccountRecord {
                account_id: Some(crypto::k32(&eve_id)),
                account_key: Some(crypto::k32(&KeyPair::generate().public())),
                name: Some("eve".into()),
                admin: false,
                issuer_root: false,
                issuer: Some(crypto::k32(&carol_id)),
                version: 1,
            };
            let s = sign_op(
                &carol,
                &carol_id,
                2,
                now_ms(),
                AccountOp::PutAccount(Box::new(wp::PutAccount {
                    record: Some(carol.sign_obj(mt::ACCOUNT_RECORD, &erec)),
                })),
            );
            h.run(op_entry(s)).unwrap();
            let t = wp::AccountTombstone {
                account_id: Some(crypto::k32(&carol_id)),
                version: 2,
                revoke_issued,
                reason: None,
            };
            h.run(EntryPayload::RootAccountEntry(Box::new(
                wp::RootAccountEntry {
                    record: Some(h.net.root.sign_obj(mt::ACCOUNT_TOMBSTONE, &t)),
                },
            )))
            .unwrap();
            let v = h.m.view();
            assert!(!v.accounts.get(&carol_id).is_some_and(|a| a.valid));
            assert_eq!(
                v.accounts.get(&eve_id).is_some_and(|a| a.valid),
                !revoke_issued,
                "revoke_issued={revoke_issued}"
            );
            assert!(v.accounts[&dave_id].valid);
        }
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
                    overlay_ips: Some(vec![super::ops::ip("10.7.0.30").unwrap()]),
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
        assert!(
            h.admin_op(AccountOp::PutAccount(Box::new(wp::PutAccount {
                record: Some(h.net.admin.sign_obj(mt::ACCOUNT_RECORD, &rec2))
            })))
            .is_err()
        );
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
        assert!(
            h.m.prepare(
                1,
                h.idx + 1,
                ts + 5,
                EntryPayload::ExtendValidityEntry(Box::new(wp::ExtendValidityEntry {
                    valid_until: ts + 5 + VALIDITY_PERIOD + 1
                }))
            )
            .is_err()
        );
        h.admin_op(AccountOp::RotatePsk(Box::new(wp::RotatePsk {
            epoch_id: 1,
        })))
        .unwrap();
        assert!(h.m.psk(1).is_some());
        assert!(
            h.admin_op(AccountOp::RotatePsk(Box::new(wp::RotatePsk {
                epoch_id: 1
            })))
            .is_err()
        );
    }

    fn net_config(version: u64) -> wp::NetworkConfig {
        wp::NetworkConfig {
            version,
            policy: Some(Box::new(wp::Policy {
                version,
                default_action: wp::Action::Deny,
                rules: Some(vec![wp::Rule {
                    id: Some("all".into()),
                    action: wp::Action::Allow,
                    src: Some(vec!["*".into()]),
                    dst: Some(vec!["*".into()]),
                    ports: Some(vec!["*".into()]),
                }]),
                tests: None,
            })),
            dns: None,
            seeds: None,
            limits: Some(Box::new(wp::Limits {
                version,
                defaults: Some(vec![wp::LimitValue {
                    name: Some("circuits_global".into()),
                    value: 100,
                }]),
                overrides: Some(vec![wp::LimitOverride {
                    select: Some(vec!["tag:x".into()]),
                    values: Some(vec![wp::LimitValue {
                        name: Some("circuits_global".into()),
                        value: 200,
                    }]),
                }]),
            })),
            transport: Some(Box::new(wp::TransportConfig {
                version,
                defaults: Some(vec![wp::TransportPriority {
                    transport: wp::Transport::KcpFecTls,
                    priority: 5,
                }]),
                overrides: Some(vec![wp::PriorityOverride {
                    select: Some(vec!["tag:x".into()]),
                    values: Some(vec![wp::TransportPriority {
                        transport: wp::Transport::TcpTls,
                        priority: 50,
                    }]),
                }]),
                camouflage: None,
                padding: None,
            })),
        }
    }

    fn set_network(h: &mut H, c: wp::NetworkConfig) -> std::result::Result<Outcome, ApplyError> {
        h.admin_op(AccountOp::SetNetworkConfig(Box::new(
            wp::SetNetworkConfig {
                config: Some(Box::new(c)),
            },
        )))
    }

    #[test]
    fn network_config_is_one_versioned_document() {
        let mut h = H::new();
        assert_eq!(h.m.view().network_version, 0);
        set_network(&mut h, net_config(1)).unwrap();
        let v = h.m.view();
        assert_eq!(v.network_version, 1);
        // Every network leaf carries the document's version, also the
        // sections the document left out (written empty = built-in).
        for k in [
            kind::POLICY,
            kind::DNS,
            kind::SEEDS,
            kind::LIMITS,
            kind::TRANSPORT,
        ] {
            let e = h.m.tree.get(k, &SINGLETON).unwrap();
            assert_eq!(
                leaf::version(&leaf::decode(k, &SINGLETON, &e.bytes).unwrap()),
                1
            );
        }
        assert_eq!(v.policy.rules.len(), 1);
        assert_eq!(v.suffix(), "internal");
        // A document made from an older version is refused.
        let e = set_network(&mut h, net_config(1)).unwrap_err().to_string();
        assert!(e.contains("must be above 1"), "{e}");
        set_network(&mut h, net_config(2)).unwrap();
        // Bad content anywhere refuses the whole document.
        let mut bad = net_config(3);
        bad.limits.as_mut().unwrap().defaults = Some(vec![wp::LimitValue {
            name: Some("no_such_limit".into()),
            value: 1,
        }]);
        assert!(set_network(&mut h, bad).is_err());
        assert_eq!(h.m.view().network_version, 2);
    }

    #[test]
    fn retired_setting_ops_are_refused_for_new_entries() {
        let mut h = H::new();
        let e = h
            .admin_op(AccountOp::SetPolicy(Box::new(wp::SetPolicy {
                policy: Some(Box::new(wp::Policy {
                    version: 1,
                    default_action: wp::Action::Deny,
                    rules: None,
                    tests: None,
                })),
            })))
            .unwrap_err()
            .to_string();
        assert!(e.contains("retired") && e.contains("network config"), "{e}");
    }

    fn node_config(id: &Bytes32, version: u64) -> wp::NodeConfig {
        wp::NodeConfig {
            node_id: Some(crypto::k32(id)),
            version,
            priorities: Some(vec![wp::TransportPriority {
                transport: wp::Transport::KcpFecTls,
                priority: 0,
            }]),
            limits: Some(vec![wp::LimitValue {
                name: Some("circuits_global".into()),
                value: 7,
            }]),
            seeds: None,
            dns_records: None,
            dns_forward: None,
            proxy: None,
        }
    }

    #[test]
    fn node_config_proxy_rules_are_checked() {
        let mut h = H::new();
        let a = enroll(&mut h, "a", "10.7.0.5", &KeyPair::generate());
        let set = |h: &mut H, c: wp::NodeConfig| {
            h.admin_op(AccountOp::SetNodeConfig(Box::new(wp::SetNodeConfig {
                config: Some(Box::new(c)),
            })))
        };
        let rule = |name: &str, port: u16| wp::ProxyRule {
            name: Some(name.into()),
            protocol: crate::policy::PROTO_TCP,
            listen_port: port,
            target: Some(vec!["tag:web".into()]),
            target_port: 80,
            real_ip: true,
        };
        let mut c = wp::NodeConfig {
            node_id: Some(crypto::k32(&a)),
            version: 1,
            proxy: Some(vec![rule("web", 8080), rule("web2", 8080)]),
            ..Default::default()
        };
        let e = set(&mut h, c.clone()).unwrap_err().to_string();
        assert!(e.contains("both listen"), "{e}");
        c.proxy = Some(vec![rule("web", 8080)]);
        set(&mut h, c.clone()).unwrap();
        assert_eq!(
            h.m.view().node_config(&a).and_then(|c| c.proxy.clone()),
            Some(vec![rule("web", 8080)])
        );
        // Only data nodes listen.
        h.admin_op(AccountOp::UpdateNode(Box::new(wp::UpdateNode {
            node_id: Some(crypto::k32(&a)),
            set_roles: true,
            roles: Some(vec![wp::Role::Relay]),
            ..Default::default()
        })))
        .unwrap();
        c.version = 2;
        let e = set(&mut h, c).unwrap_err().to_string();
        assert!(e.contains("data role"), "{e}");
    }

    #[test]
    fn node_config_overrides_the_network_for_one_node() {
        let mut h = H::new();
        let a = enroll(&mut h, "a", "10.7.0.5", &KeyPair::generate());
        let b = enroll(&mut h, "b", "10.7.0.6", &KeyPair::generate());
        set_network(&mut h, net_config(1)).unwrap();
        let tls = wp::Transport::TcpTls;
        let kcp = wp::Transport::KcpFecTls;
        let any = wp::Transport::AnyTls;
        {
            let v = h.m.view();
            // Both carry tag:x: the override, then the network's value,
            // then the built-in.
            assert_eq!(
                (
                    v.priority(&a, tls),
                    v.priority(&a, kcp),
                    v.priority(&a, any)
                ),
                (50, 5, 20)
            );
            assert_eq!(v.limit(&a, "circuits_global"), Some(200));
            assert_eq!(v.limit(&a, "circuits_per_source"), Some(64));
            assert_eq!(v.limit(&a, "rate_ceiling_mbps"), None);
        }
        h.admin_op(AccountOp::SetNodeConfig(Box::new(wp::SetNodeConfig {
            config: Some(Box::new(node_config(&a, 1))),
        })))
        .unwrap();
        {
            let v = h.m.view();
            assert_eq!(v.priority(&a, kcp), 0);
            assert_eq!(v.priority(&a, tls), 50);
            assert_eq!(v.limit(&a, "circuits_global"), Some(7));
            // Node b is untouched.
            assert_eq!(v.priority(&b, kcp), 5);
            assert_eq!(v.limit(&b, "circuits_global"), Some(200));
        }
        // Stale version refused; an empty configuration removes the leaf.
        assert!(
            h.admin_op(AccountOp::SetNodeConfig(Box::new(wp::SetNodeConfig {
                config: Some(Box::new(node_config(&a, 1))),
            })))
            .is_err()
        );
        let empty = wp::NodeConfig {
            node_id: Some(crypto::k32(&a)),
            version: 2,
            ..Default::default()
        };
        h.admin_op(AccountOp::SetNodeConfig(Box::new(wp::SetNodeConfig {
            config: Some(Box::new(empty.clone())),
        })))
        .unwrap();
        assert!(h.m.tree.get(kind::NODE_CONFIG, &a).is_none());
        assert_eq!(h.m.view().priority(&a, kcp), 5);
        assert!(
            h.admin_op(AccountOp::SetNodeConfig(Box::new(wp::SetNodeConfig {
                config: Some(Box::new(wp::NodeConfig {
                    version: 3,
                    ..empty
                })),
            })))
            .is_err(),
            "nothing to clear"
        );
        // Tombstoning the node removes its configuration.
        h.admin_op(AccountOp::SetNodeConfig(Box::new(wp::SetNodeConfig {
            config: Some(Box::new(node_config(&b, 1))),
        })))
        .unwrap();
        assert!(h.m.tree.get(kind::NODE_CONFIG, &b).is_some());
        h.admin_op(AccountOp::TombstoneNode(Box::new(wp::TombstoneNode {
            node_id: Some(crypto::k32(&b)),
            reason: None,
        })))
        .unwrap();
        assert!(h.m.tree.get(kind::NODE_CONFIG, &b).is_none());
    }

    #[test]
    fn node_config_seeds_and_dns_are_checked_and_added() {
        let mut h = H::new();
        let a = enroll(&mut h, "a", "10.7.0.5", &KeyPair::generate());
        let r = enroll(&mut h, "relay-1", "10.7.0.9", &KeyPair::generate());
        let set = |h: &mut H, c: wp::NodeConfig| {
            h.admin_op(AccountOp::SetNodeConfig(Box::new(wp::SetNodeConfig {
                config: Some(Box::new(c)),
            })))
        };
        let seed = |node: &str| wp::SeedEntry {
            node: Some(node.into()),
            addrs: Some(vec![wp::SeedAddr {
                host: Some("198.51.100.7".into()),
                port: 443,
                transport: wp::Transport::TcpTls,
            }]),
        };
        // relay-1 is a data node: not a valid seed.
        let mut c = node_config(&a, 1);
        c.seeds = Some(vec![seed("relay-1")]);
        assert!(set(&mut h, c.clone()).is_err());
        h.admin_op(AccountOp::UpdateNode(Box::new(wp::UpdateNode {
            node_id: Some(crypto::k32(&r)),
            set_roles: true,
            roles: Some(vec![wp::Role::Relay]),
            ..Default::default()
        })))
        .unwrap();
        // A record shadowing a magic DNS name is refused like the network's.
        c.dns_records = Some(vec![wp::DnsRecord {
            name: Some("relay-1.internal".into()),
            rtype: wp::DnsType::A,
            value: Some("10.7.0.5".into()),
            ttl: 0,
        }]);
        assert!(set(&mut h, c.clone()).is_err());
        c.dns_records = Some(vec![wp::DnsRecord {
            name: Some("db.internal".into()),
            rtype: wp::DnsType::A,
            value: Some("10.7.0.5".into()),
            ttl: 0,
        }]);
        set(&mut h, c).unwrap();
        let v = h.m.view();
        assert_eq!(v.seeds_for(&a)[0].node.as_deref(), Some("relay-1"));
        assert!(v.seeds_for(&r).is_empty());
        assert_eq!(v.dns_records_for(&a).len(), 1);
        assert!(v.dns_records_for(&r).is_empty());
    }

    #[test]
    fn node_owner_may_set_its_node_config_others_may_not() {
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
        let signed = h.net.admin.sign_obj(mt::ACCOUNT_RECORD, &rec);
        h.admin_op(AccountOp::PutAccount(Box::new(wp::PutAccount {
            record: Some(signed),
        })))
        .unwrap();
        let mine = h
            .admin_op(AccountOp::CreateEnrollment(Box::new(
                wp::CreateEnrollment {
                    owner: Some(crypto::k32(&bob_id)),
                    name: Some("bobs-laptop".into()),
                    overlay_ips: Some(vec![super::ops::ip("10.7.0.20").unwrap()]),
                    roles: Some(vec![wp::Role::Data]),
                    identity_key: Some(crypto::k32(&KeyPair::generate().public())),
                    ..Default::default()
                },
            )))
            .unwrap()
            .node_id
            .unwrap();
        let other = enroll(&mut h, "server", "10.7.0.21", &KeyPair::generate());
        let as_bob = |h: &mut H, seq: u64, c: wp::NodeConfig| {
            let s = sign_op(
                &bob,
                &bob_id,
                seq,
                now_ms(),
                AccountOp::SetNodeConfig(Box::new(wp::SetNodeConfig {
                    config: Some(Box::new(c)),
                })),
            );
            h.run(op_entry(s))
        };
        as_bob(&mut h, 1, node_config(&mine, 1)).unwrap();
        let e = as_bob(&mut h, 2, node_config(&other, 1))
            .unwrap_err()
            .to_string();
        assert!(e.contains("owner or an admin"), "{e}");
        // But not the network's configuration.
        let s = sign_op(
            &bob,
            &bob_id,
            3,
            now_ms(),
            AccountOp::SetNetworkConfig(Box::new(wp::SetNetworkConfig {
                config: Some(Box::new(net_config(1))),
            })),
        );
        assert!(h.run(op_entry(s)).is_err());
    }
}
