//! The controller role (§7): Raft over end-to-end sessions, proposing and
//! applying operations, signing tree heads, serving enrollment, PSK and
//! camouflage material, and collecting metric reports.

pub mod audit;
pub mod raft;
pub mod recovery;
pub mod signer;

use crate::node::Node;
use crate::rpc;
use anyhow::{Result, anyhow, bail};
use parking_lot::Mutex;
use raft::{Raft, Role};
use signer::Signer;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use webjet_core::crypto::{self, Bytes32, opt_k32};
use webjet_core::membership;
use webjet_core::statemachine::{ApplyError, Machine, Membership, Outcome};
use webjet_core::store::HeadOutcome;
use webjet_core::types::{HOUR, VALIDITY_PERIOD, now_ms};
use webjet_net::hop::{self, BoxIo, rec};
use webjet_proto::{
    self as wp, Decodable, Encodable, EntryPayload, RaftBody, RpcBody, msg_type as mt,
};

const PROPOSE_TIMEOUT: Duration = Duration::from_secs(15);

/// The latest verified metric report of a node.
pub struct StoredReport {
    pub received: u64,
    pub report: wp::MetricReport,
}

/// The membership change carried by a log entry (genesis, or a signed
/// ChangeMembership operation). Raft uses it to track the configuration
/// straight from the log (§7.1); the state machine applies the same change.
pub fn classify_entry(bytes: &[u8]) -> Option<raft::ConfChange> {
    use raft::ConfChange;
    let e = wp::LogEntry::decode_bytes(bytes).ok()?;
    match e.payload? {
        EntryPayload::GenesisEntry(_) => {
            let first = opt_k32(&e.random?.node_id);
            Some(ConfChange::Set(Membership {
                voters: BTreeSet::from([first]),
                learners: BTreeSet::new(),
            }))
        }
        EntryPayload::OpEntry(o) => {
            let v = crypto::open_envelope(&o.signed_op?).ok()?;
            let op: wp::SignedOp = v.decode().ok()?;
            match op.op? {
                wp::AccountOp::ChangeMembership(c) => {
                    let id = opt_k32(&c.node_id);
                    Some(match c.change {
                        wp::MembershipChange::AddLearner => ConfChange::AddLearner(id),
                        wp::MembershipChange::Promote => ConfChange::Promote(id),
                        wp::MembershipChange::Demote => ConfChange::Demote(id),
                        wp::MembershipChange::Remove => ConfChange::Remove(id),
                    })
                }
                _ => None,
            }
        }
        EntryPayload::ForceNewClusterEntry(f) => {
            let voter = opt_k32(&f.voter);
            Some(ConfChange::Set(Membership {
                voters: BTreeSet::from([voter]),
                learners: f
                    .learners
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .map(|k| k.to_bytes())
                    .filter(|k| *k != voter)
                    .collect(),
            }))
        }
        EntryPayload::AutoMembershipEntry(a) => {
            let id = opt_k32(&a.node_id);
            Some(match a.change {
                wp::MembershipChange::AddLearner => ConfChange::AddLearner(id),
                wp::MembershipChange::Promote => ConfChange::Promote(id),
                wp::MembershipChange::Demote => ConfChange::Demote(id),
                wp::MembershipChange::Remove => ConfChange::Remove(id),
            })
        }
        _ => None,
    }
}
const HEAD_RESIGN: u64 = HOUR;

struct Waiter {
    hash: Bytes32,
    tx: oneshot::Sender<std::result::Result<Outcome, String>>,
}

/// Lock order, where more than one is held: `apply_lock`, then `raft`, then
/// `machine`, then the node's store. Never take `raft` while holding
/// `machine`: `propose` and snapshot installs hold both, raft first.
pub struct Controller {
    node: Weak<Node>,
    pub machine: Mutex<Machine>,
    pub raft: Mutex<Raft>,
    signer: Box<dyn Signer>,
    pub signing_key_id: Bytes32,
    applied: AtomicU64,
    /// Serializes applying committed entries (several tasks trigger it).
    apply_lock: Mutex<()>,
    waiters: Mutex<HashMap<u64, Waiter>>,
    propose_lock: tokio::sync::Mutex<()>,
    /// An automatic membership change is being proposed (leader duties run
    /// every second and may overlap).
    membership_busy: std::sync::atomic::AtomicBool,
    last_signed: Mutex<(u64, u64)>,
    pub halted: Mutex<Option<String>>,
    pub reports: Mutex<HashMap<Bytes32, StoredReport>>,
    /// What each entry still in the log did when applied, by index (the
    /// audit trail, `audit::summarize`). Entries since the snapshot are
    /// re-applied at start, so this covers the whole log.
    descriptions: Mutex<BTreeMap<u64, String>>,
    bootstrap: bool,
}

fn entry_hash(bytes: &[u8]) -> Bytes32 {
    crypto::hash(bytes)
}

impl Controller {
    fn node(&self) -> Option<Arc<Node>> {
        self.node.upgrade()
    }

    pub fn pending_token_hashes(&self) -> Vec<Bytes32> {
        let now = now_ms();
        self.machine
            .lock()
            .pending
            .values()
            .filter(|p| p.expires_at > now)
            .map(|p| p.token_hash)
            .collect()
    }

    pub fn is_leader(&self) -> bool {
        self.raft.lock().role == Role::Leader
    }

    pub fn leader(&self) -> Option<Bytes32> {
        self.raft.lock().leader
    }

    // ------------------------------------------------------------ startup

    pub fn start(n: &Arc<Node>, bootstrap: bool) -> Result<Arc<Controller>> {
        let dir = n.paths.raft();
        let storage = raft::Storage::disk(dir.clone())?;
        let machine = match storage.load_snapshot() {
            Some(b) => Machine::restore_bytes(&b)?,
            None => Machine::new(),
        };
        // The configuration at the snapshot; later changes come from the log.
        let base = if machine.genesis.is_some() {
            machine.members.clone()
        } else if bootstrap {
            Membership {
                voters: BTreeSet::from([n.me]),
                learners: BTreeSet::new(),
            }
        } else {
            Membership::default()
        };
        let r = Raft::open(
            n.me,
            dir,
            machine.last_index,
            machine.last_term,
            base,
            Box::new(classify_entry),
        )?;
        let signer: Box<dyn Signer> = match &n.cfg.controller.signer_socket {
            Some(p) => Box::new(signer::SocketSigner::new(p.clone())),
            None => Box::new(signer::FileSigner::open(&n.paths.dir.join("signing.key"))?),
        };
        let pk = signer.public()?;
        let c = Arc::new(Controller {
            node: Arc::downgrade(n),
            applied: AtomicU64::new(machine.last_index),
            apply_lock: Mutex::new(()),
            machine: Mutex::new(machine),
            raft: Mutex::new(r),
            signing_key_id: crypto::signing_key_id(&pk),
            signer,
            waiters: Mutex::new(HashMap::new()),
            propose_lock: tokio::sync::Mutex::new(()),
            membership_busy: std::sync::atomic::AtomicBool::new(false),
            last_signed: Mutex::new((0, 0)),
            halted: Mutex::new(None),
            reports: Mutex::new(HashMap::new()),
            descriptions: Mutex::new(BTreeMap::new()),
            bootstrap,
        });
        // Controllers accept every PSK epoch (§10.7.3).
        n.epochs.write().accept_all = true;
        c.sync_psk(n);
        tracing::info!(signing_key_id = %crypto::short(&c.signing_key_id), "controller role started");
        Ok(c)
    }

    pub async fn run(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        let mut i: u64 = 0;
        loop {
            tick.tick().await;
            i += 1;
            let Some(n) = self.node() else { break };
            if self.is_halted() {
                continue;
            }
            let out = self.raft.lock().tick(Instant::now());
            self.send_raft(&n, out);
            self.apply_committed(&n);
            self.send_snapshots(&n);
            if i.is_multiple_of(10) {
                self.maybe_sign_head(&n);
                if self.is_leader() {
                    let me = self.clone();
                    tokio::spawn(async move { me.leader_duties().await });
                }
            }
        }
    }

    fn send_raft(&self, n: &Arc<Node>, out: raft::Out) {
        for (to, body) in out {
            let msg = raft::wrap(&n.me, &to, body);
            rpc::send_oneway(
                n,
                &to,
                RpcBody::RaftRpc(Box::new(wp::RaftRpc { message: Some(msg) })),
            );
        }
    }

    fn send_snapshots(&self, n: &Arc<Node>) {
        let peers = self.raft.lock().needs_snapshot();
        if peers.is_empty() {
            return;
        }
        let Some(data) = self.raft.lock().storage().load_snapshot() else {
            return;
        };
        for p in peers {
            let body = {
                let mut r = self.raft.lock();
                r.mark_snapshot_sent(&p);
                r.snapshot_msg(data.clone())
            };
            tracing::info!(peer = %n.name_of(&p), "sending Raft snapshot");
            self.send_raft(n, vec![(p, body)]);
        }
    }

    // ------------------------------------------------------------ applying

    fn apply_committed(&self, n: &Arc<Node>) {
        let _g = self.apply_lock.lock();
        loop {
            // A halted controller applies nothing more: whatever stopped it
            // (divergence, membership mismatch, unsupported version) would
            // only repeat, or apply later entries on a wrong state.
            if self.is_halted() {
                return;
            }
            let next = self.applied.load(Ordering::SeqCst) + 1;
            let bytes = {
                let r = self.raft.lock();
                if next > r.commit {
                    return;
                }
                match r.entry(next) {
                    Some(e) => e.bytes.clone(),
                    None => return,
                }
            };
            let entry = match wp::LogEntry::decode_bytes(&bytes) {
                Ok(e) => e,
                Err(e) => {
                    self.halt(n, format!("undecodable committed entry {next}: {e}"));
                    return;
                }
            };
            let res = self.machine.lock().apply(&entry);
            match res {
                Ok(outcome) => {
                    if outcome.membership_changed
                        || matches!(entry.payload, Some(EntryPayload::GenesisEntry(_)))
                    {
                        // Raft tracked the change from the log already; the
                        // state machine must agree with it.
                        let sm = self.machine.lock().members.clone();
                        let rf = self.raft.lock().config_at(next);
                        if rf.as_ref() != Some(&sm) {
                            self.halt(n, format!("membership mismatch at {next}: Raft {rf:?}, state machine {sm:?}"));
                            return;
                        }
                    }
                    self.applied.store(next, Ordering::SeqCst);
                    self.descriptions
                        .lock()
                        .insert(next, outcome.description.clone());
                    if !outcome.description.is_empty() && outcome.description != "no-op" {
                        tracing::info!(index = next, signer = ?outcome.signer.map(|s| crypto::short(&s)), "applied: {}", outcome.description);
                    }
                    if outcome.psk_rotated
                        || matches!(entry.payload, Some(EntryPayload::GenesisEntry(_)))
                    {
                        self.sync_psk(n);
                    }
                    if let Some(w) = self.waiters.lock().remove(&next) {
                        let _ = w.tx.send(if w.hash == entry_hash(&bytes) {
                            Ok(outcome)
                        } else {
                            Err("entry was superseded by a new leader".into())
                        });
                    }
                    if next.is_multiple_of(raft::COMPACT_EVERY) {
                        self.compact();
                    }
                }
                Err(ApplyError::Unsupported(v)) => {
                    self.halt(
                        n,
                        format!(
                            "state version {v} is not supported by this software; upgrade (§15.7)"
                        ),
                    );
                    return;
                }
                Err(e) => {
                    self.halt(n, format!("{e}"));
                    return;
                }
            }
        }
    }

    pub fn is_halted(&self) -> bool {
        self.halted.lock().is_some()
    }

    fn halt(&self, n: &Arc<Node>, why: String) {
        tracing::error!("controller halted: {why}");
        n.alarm("controller_halted", "critical", why.clone());
        *self.halted.lock() = Some(why);
    }

    fn compact(&self) {
        let (bytes, idx) = {
            let m = self.machine.lock();
            (m.snapshot_bytes(), m.last_index)
        };
        let first = {
            let mut r = self.raft.lock();
            if r.storage().save_snapshot(&bytes).is_ok() {
                r.compact(idx);
            }
            r.snap_index + 1
        };
        self.descriptions.lock().retain(|i, _| *i >= first);
    }

    /// The audit trail for an admin's signed `LogRequest`.
    pub fn log(&self, raw: &[u8]) -> wp::LogReply {
        let checked = {
            let m = self.machine.lock();
            audit::check_request(m.view(), raw, now_ms())
        };
        let req = match checked {
            Ok(r) => r,
            Err(e) => {
                return wp::LogReply {
                    error: Some(format!("{e:#}")),
                    ..Default::default()
                };
            }
        };
        let (first, commit, entries) = {
            let r = self.raft.lock();
            let first = r.snap_index + 1;
            let entries: Vec<(u64, Vec<u8>)> = audit::window(&req, first, r.commit)
                .filter_map(|i| r.entry(i).map(|e| (i, e.bytes.clone())))
                .collect();
            (first, r.commit, entries)
        };
        let records = {
            let d = self.descriptions.lock();
            entries
                .iter()
                .filter_map(|(i, b)| audit::summarize(b, d.get(i).cloned()))
                .collect()
        };
        wp::LogReply {
            error: None,
            first_index: first,
            commit_index: commit,
            records: Some(records),
        }
    }

    /// This controller's applied state for an admin's signed
    /// `SnapshotRequest` (ops guide 3.8): what `webjetctl local controller
    /// restore` installs when no controller survives.
    pub fn export_snapshot(&self, raw: &[u8]) -> wp::SnapshotReply {
        let m = self.machine.lock();
        match audit::check_snapshot_request(m.view(), raw, now_ms()) {
            Ok(()) if m.genesis.is_some() => wp::SnapshotReply {
                error: None,
                snapshot: Some(m.snapshot_bytes()),
            },
            Ok(()) => wp::SnapshotReply {
                error: Some("this controller holds no network yet".into()),
                snapshot: None,
            },
            Err(e) => wp::SnapshotReply {
                error: Some(format!("{e:#}")),
                snapshot: None,
            },
        }
    }

    fn sync_psk(&self, n: &Arc<Node>) {
        let (cur, epochs) = {
            let m = self.machine.lock();
            (
                m.psk_current,
                m.psk_epochs
                    .iter()
                    .map(|(k, v)| (*k, *v))
                    .collect::<Vec<_>>(),
            )
        };
        if epochs.is_empty() {
            return;
        }
        n.set_psk(cur, epochs);
    }

    // ------------------------------------------------------------ tree heads (§7.3)

    fn maybe_sign_head(&self, n: &Arc<Node>) {
        // A halted controller's state can't be trusted; it signs nothing.
        if self.is_halted() {
            return;
        }
        let (version, root, genesis) = {
            let mut m = self.machine.lock();
            (m.last_index, m.root(), m.genesis.is_some())
        };
        if !genesis || version == 0 {
            return;
        }
        let now = now_ms();
        {
            let ls = self.last_signed.lock();
            if ls.0 == version && now < ls.1 + HEAD_RESIGN {
                return;
            }
        }
        // Only sign with a validly certified key (§6.5).
        let certified = n
            .store
            .read()
            .view()
            .valid_certs
            .contains(&self.signing_key_id);
        if !certified {
            n.alarm(
                "no_signing_cert",
                "warning",
                "this controller's signing key has no valid SigningKeyCert yet (`webjetctl network controller certify`, ops guide 2.4)".into(),
            );
            return;
        }
        n.clear_alarm("no_signing_cert");
        let head = wp::SignedTreeHead {
            signing_key_id: Some(crypto::k32(&self.signing_key_id)),
            version,
            root: Some(crypto::k32(&root)),
            state_version: 1,
            issued_at: now,
            expires_at: now + n.cfg.controller.head_lifetime_hours.max(1) * HOUR,
        };
        let raw = match self.signer.sign(mt::SIGNED_TREE_HEAD, head.encode_bytes()) {
            Ok(r) => r,
            Err(e) => {
                n.alarm(
                    "signer_unavailable",
                    "critical",
                    format!("signing the tree head failed: {e}"),
                );
                return;
            }
        };
        n.clear_alarm("signer_unavailable");
        *self.last_signed.lock() = (version, now);
        self.install_into_store(n, &raw);
    }

    /// Put our machine's tree into the node's own trust store under `head`.
    fn install_into_store(&self, n: &Arc<Node>, head_raw: &[u8]) {
        let outcome = n.store.write().offer_head(head_raw);
        match outcome {
            Ok(HeadOutcome::NeedSync) => {
                let updates = {
                    let m = self.machine.lock();
                    let s = n.store.read();
                    let mut u: Vec<(u8, Bytes32, Option<Vec<u8>>)> = Vec::new();
                    for (p, e) in m.tree.iter() {
                        if s.tree().get_by_path(p).is_none_or(|x| x.hash != e.hash) {
                            u.push((e.kind, e.key, Some(e.bytes.clone())));
                        }
                    }
                    for (p, e) in s.tree().iter() {
                        if m.tree.get_by_path(p).is_none() {
                            u.push((e.kind, e.key, None));
                        }
                    }
                    u
                };
                if let Err(e) = n.store.write().install(head_raw, updates) {
                    tracing::error!("installing our own tree head failed: {e}");
                    return;
                }
                n.persist_store();
                n.emit(crate::node::Event::HeadChanged);
                crate::gossip::push_head(n);
            }
            Ok(HeadOutcome::Refreshed) => {
                n.persist_store();
                n.emit(crate::node::Event::HeadChanged);
                crate::gossip::push_head(n);
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("own tree head rejected: {e}"),
        }
    }

    // ------------------------------------------------------------ proposing

    async fn leader_duties(self: Arc<Self>) {
        let Ok(_g) = self.propose_lock.try_lock() else {
            return;
        };
        let (genesis_needed, due_validity, due_expiry) = {
            let m = self.machine.lock();
            let now = now_ms();
            (
                m.genesis.is_none(),
                m.genesis.is_some() && m.validity_due(now),
                m.expiry_due(now),
            )
        };
        drop(_g);
        if genesis_needed {
            if !self.bootstrap {
                return;
            }
            let Some(n) = self.node() else { return };
            let g = n.store.read().genesis_raw.clone();
            match self
                .propose(EntryPayload::GenesisEntry(Box::new(wp::GenesisEntry {
                    genesis: Some(g),
                })))
                .await
            {
                Ok(_) => tracing::info!("network genesis committed"),
                Err(e) => tracing::warn!("genesis: {e}"),
            }
            return;
        }
        if due_validity {
            let now = now_ms();
            if let Err(e) = self
                .propose(EntryPayload::ExtendValidityEntry(Box::new(
                    wp::ExtendValidityEntry {
                        valid_until: now + VALIDITY_PERIOD,
                    },
                )))
                .await
            {
                tracing::debug!("validity extension: {e}");
            }
        }
        if due_expiry {
            let _ = self
                .propose(EntryPayload::ExpireEnrollmentsEntry(Box::new(
                    wp::ExpireEnrollmentsEntry { now: now_ms() },
                )))
                .await;
        }
        self.auto_membership().await;
    }

    /// Automatic membership (§7.5): propose the next change, if any. One at a
    /// time; the next round (a second later) proposes the following one.
    async fn auto_membership(&self) {
        if self.membership_busy.swap(true, Ordering::SeqCst) {
            return;
        }
        self.auto_membership_once().await;
        self.membership_busy.store(false, Ordering::SeqCst);
    }

    async fn auto_membership_once(&self) {
        let Some(n) = self.node() else { return };
        let Some((change, id)) = self.membership_plan(&n) else {
            return;
        };
        let name = n
            .store
            .read()
            .view()
            .node(&id)
            .map_or_else(|| crypto::short(&id), |x| x.name.clone());
        match self
            .propose(EntryPayload::AutoMembershipEntry(Box::new(
                wp::AutoMembershipEntry {
                    change,
                    node_id: Some(crypto::k32(&id)),
                },
            )))
            .await
        {
            Ok(_) => tracing::info!("automatic membership: {change:?} {name}"),
            Err(e) => tracing::warn!("automatic membership {change:?} {name}: {e}"),
        }
    }

    /// The next automatic membership change, when this controller is the
    /// leader, no change is pending and every controller involved runs
    /// software that applies it.
    fn membership_plan(&self, n: &Node) -> Option<membership::Change> {
        use webjet_core::membership::{self as mb, Input, Peer};
        let (members, member_since, settings, eligible, joinable) = {
            let m = self.machine.lock();
            let v = m.view();
            let settings = mb::Settings::of(v.controller_settings.as_ref());
            if !settings.auto_membership || m.genesis.is_none() {
                return None;
            }
            let valid = || v.nodes.values().filter(|x| x.valid);
            let eligible: BTreeSet<Bytes32> = valid()
                .filter(|x| x.rec.control != Some(false))
                .map(|x| x.id)
                .collect();
            let joinable: BTreeSet<Bytes32> = valid()
                .filter(|x| x.rec.control == Some(true) && !m.removed_by_admin.contains(&x.id))
                .map(|x| x.id)
                .collect();
            (
                m.members.clone(),
                m.member_since.clone(),
                settings,
                eligible,
                joinable,
            )
        };
        // Certificates aren't replicated state: the leader's own view
        // decides who is a valid controller.
        let controllers: BTreeSet<Bytes32> =
            n.store.read().view().controllers.keys().copied().collect();
        let peers: BTreeMap<Bytes32, Peer> = {
            let r = self.raft.lock();
            if r.role != Role::Leader || r.conf_change_pending() {
                return None;
            }
            // The log's configuration is the applied one (nothing pending).
            if r.config() != &members {
                return None;
            }
            // Give a new leader time to hear from everyone first.
            if r.leader_for()? < mb::HEALTHY_WITHIN {
                return None;
            }
            let last = r.last_index();
            members
                .all()
                .into_iter()
                // A peer that never answered this leader has been silent
                // for as long as it has been leader.
                .filter_map(|p| {
                    Some((
                        p,
                        Peer {
                            silent: r.silent_for(&p)?,
                            lag: last.saturating_sub(r.match_of(&p)),
                        },
                    ))
                })
                .collect()
        };
        let plan = mb::plan(&Input {
            settings,
            leader: n.me,
            members: &members,
            controllers: &controllers,
            eligible: &eligible,
            joinable: &joinable,
            member_since: &member_since,
            peers: &peers,
        })?;
        // Rolling upgrades: controllers from before 0.7.0 can't apply the
        // entry and would halt. Every reachable member and the node joining
        // must advertise support; unreachable members are being replaced
        // or removed, and an old one coming back is upgraded by the admin.
        let recs = n.records.lock();
        let supports = |id: &Bytes32| {
            *id == n.me
                || recs.endpoints.get(id).is_some_and(|(r, _)| {
                    r.features
                        .as_ref()
                        .is_some_and(|f| f.iter().any(|x| x == mb::FEATURE))
                })
        };
        let reachable = |id: &Bytes32| peers.get(id).is_some_and(|p| p.silent < mb::HEALTHY_WITHIN);
        let joining = plan.0 == wp::MembershipChange::AddLearner;
        let ok = members
            .all()
            .iter()
            .filter(|id| reachable(id))
            .all(supports)
            && (!joining || supports(&plan.1));
        if !ok {
            tracing::debug!(
                "automatic membership: waiting for every controller to run 0.7.0 or later"
            );
            return None;
        }
        Some(plan)
    }

    /// Propose an entry as the leader and wait for it to be applied here.
    /// Proposals are serialized so each is validated against the state it
    /// will be applied to.
    pub async fn propose(&self, payload: EntryPayload) -> Result<(u64, Outcome)> {
        let _g = tokio::time::timeout(PROPOSE_TIMEOUT, self.propose_lock.lock())
            .await
            .map_err(|_| anyhow!("controller busy"))?;
        let Some(n) = self.node() else {
            bail!("shutting down")
        };
        let start = Instant::now();
        // Wait until everything in the log is applied.
        loop {
            if self.is_halted() {
                bail!("controller halted");
            }
            let (leader, last) = {
                let r = self.raft.lock();
                (r.role == Role::Leader, r.last_index())
            };
            if !leader {
                bail!("not the leader");
            }
            if self.applied.load(Ordering::SeqCst) >= last {
                break;
            }
            if start.elapsed() > PROPOSE_TIMEOUT {
                bail!("log not caught up");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (rx, idx) = {
            let mut r = self.raft.lock();
            let m = self.machine.lock();
            let idx = r.last_index() + 1;
            let mut entry = m
                .prepare(r.term, idx, now_ms(), payload)
                .map_err(|e| anyhow!("{e}"))?;
            if matches!(entry.payload, Some(EntryPayload::GenesisEntry(_))) {
                // The first voter is this controller.
                if let Some(rnd) = entry.random.as_mut() {
                    rnd.node_id = Some(crypto::k32(&n.me));
                }
            }
            drop(m);
            let bytes = entry.encode_bytes();
            let (i, out) = r
                .propose(Instant::now(), &entry)
                .map_err(|e| anyhow!("{e}"))?;
            debug_assert_eq!(i, idx);
            let (tx, rx) = oneshot::channel();
            self.waiters.lock().insert(
                i,
                Waiter {
                    hash: entry_hash(&bytes),
                    tx,
                },
            );
            drop(r);
            self.send_raft(&n, out);
            (rx, i)
        };
        // Single-voter clusters commit immediately; apply right away.
        self.apply_committed(&n);
        let outcome = tokio::time::timeout(PROPOSE_TIMEOUT, rx)
            .await
            .map_err(|_| anyhow!("entry {idx} not committed in time"))?
            .map_err(|_| anyhow!("waiter dropped"))?
            .map_err(|e| anyhow!(e))?;
        drop(_g);
        self.maybe_sign_head(&n);
        Ok((idx, outcome))
    }

    /// Submit an operation: propose here if leader, else forward to the leader.
    pub async fn submit(
        self: &Arc<Self>,
        payload: EntryPayload,
        raw_for_forward: Option<RpcBody>,
    ) -> Result<(u64, Outcome)> {
        if self.is_leader() {
            return self.propose(payload).await;
        }
        let Some(n) = self.node() else {
            bail!("shutting down")
        };
        let leader = self
            .leader()
            .ok_or_else(|| anyhow!("no Raft leader (is a majority of voters up?)"))?;
        let body = raw_for_forward.ok_or_else(|| anyhow!("can't forward this operation"))?;
        match rpc::call(&n, &leader, body, PROPOSE_TIMEOUT).await? {
            RpcBody::SubmitResult(r) if r.ok => {
                // Wait for the entry to reach us, so callers see it locally.
                let start = Instant::now();
                while self.applied.load(Ordering::SeqCst) < r.index
                    && start.elapsed() < PROPOSE_TIMEOUT
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Ok((
                    r.index,
                    Outcome {
                        description: "forwarded".into(),
                        ..Default::default()
                    },
                ))
            }
            RpcBody::SubmitResult(r) => bail!(r.error.unwrap_or_default()),
            _ => bail!("unexpected reply from the leader"),
        }
    }

    // ------------------------------------------------------------ RPC

    pub async fn handle_rpc(self: Arc<Self>, from: Bytes32, body: RpcBody) -> Option<RpcBody> {
        let n = self.node()?;
        let ack = |ok: bool, e: Option<String>| {
            Some(RpcBody::RpcAck(Box::new(wp::RpcAck { ok, error: e })))
        };
        let member = {
            let r = self.raft.lock();
            r.voters().contains(&from) || r.learners().contains(&from)
        };
        let trusted = member || n.store.read().node_trusted(&from);
        if !trusted {
            return ack(false, Some("untrusted caller".into()));
        }
        match body {
            RpcBody::RaftRpc(r) => {
                let (src, to, rb) = raft::unwrap(&r.message.unwrap_or_default())?;
                if src != from || to != n.me {
                    return None;
                }
                let is_ctl = member || n.store.read().view().is_controller(&from);
                if !is_ctl {
                    return None;
                }
                self.on_raft(&n, from, rb);
                None
            }
            RpcBody::GetCertRequest(_) => Some(RpcBody::CertRequestReply(Box::new(
                match self.cert_request() {
                    Ok(r) => wp::CertRequestReply {
                        request: Some(r),
                        error: None,
                    },
                    Err(e) => wp::CertRequestReply {
                        request: None,
                        error: Some(e.to_string()),
                    },
                },
            ))),
            RpcBody::SubmitOp(s) => {
                let raw = s.signed.clone().unwrap_or_default();
                let payload = webjet_core::statemachine::ops::op_entry(raw.clone());
                let res = self.submit(payload, Some(RpcBody::SubmitOp(s))).await;
                Some(submit_result(res))
            }
            RpcBody::RedeemRequest(r) => {
                let req =
                    wp::EnrollRequest::decode_bytes(&r.request.clone().unwrap_or_default()).ok()?;
                let res = self
                    .redeem(&req, Some(RpcBody::RedeemRequest(r)))
                    .await
                    .map(|(i, o, _)| (i, o));
                Some(submit_result(res))
            }
            RpcBody::GetPsk(g) => {
                let m = self.machine.lock();
                let cur = m.psk_current;
                let all = g.all
                    && n.store
                        .read()
                        .view()
                        .nodes
                        .get(&from)
                        .is_some_and(|x| x.relay || x.control);
                let epochs = m
                    .psk_epochs
                    .iter()
                    .filter(|(k, _)| all || **k == cur || **k == cur.wrapping_sub(1))
                    .map(|(k, v)| wp::PskEpoch {
                        epoch_id: *k,
                        psk: Some(crypto::k32(v)),
                    })
                    .collect();
                Some(RpcBody::PskInfo(Box::new(wp::PskInfo {
                    current: cur,
                    epochs: Some(epochs),
                })))
            }
            RpcBody::GetCamouflage(_) => {
                let allowed = n
                    .store
                    .read()
                    .view()
                    .nodes
                    .get(&from)
                    .is_some_and(|x| x.relay || x.control);
                if !allowed {
                    return ack(
                        false,
                        Some("only relays and controllers get the camouflage key".into()),
                    );
                }
                let c = self.machine.lock().camouflage.clone();
                match c {
                    Some((k, site)) => {
                        Some(RpcBody::CamouflageSecret(Box::new(wp::CamouflageSecret {
                            private_key: Some(k),
                            site: Some(site),
                        })))
                    }
                    None => ack(false, Some("no camouflage secret set".into())),
                }
            }
            RpcBody::MetricUpload(m) => {
                self.ingest_metrics(from, &m.report.unwrap_or_default());
                ack(true, None)
            }
            RpcBody::OfflineSubmit(o) => {
                let mut errs = Vec::new();
                for b in o.items.unwrap_or_default() {
                    if let Err(e) = n
                        .store
                        .write()
                        .add_offline_item(&b.data.unwrap_or_default())
                    {
                        errs.push(e.to_string());
                    }
                }
                n.persist_store();
                crate::gossip::push_head(&n);
                ack(errs.is_empty(), (!errs.is_empty()).then(|| errs.join("; ")))
            }
            RpcBody::SubmitRoot(r) => {
                let raw = r.signed.clone().unwrap_or_default();
                let res = match root_payload(&raw) {
                    Ok(p) => self.submit(p, Some(RpcBody::SubmitRoot(r))).await,
                    Err(e) => Err(e),
                };
                Some(submit_result(res))
            }
            RpcBody::GetControllerStatus(_) => {
                Some(RpcBody::ControllerStatus(Box::new(self.status_wire(&n))))
            }
            RpcBody::GetLog(g) => Some(RpcBody::LogReply(Box::new(
                self.log(&g.request.unwrap_or_default()),
            ))),
            RpcBody::GetSnapshot(g) => Some(RpcBody::SnapshotReply(Box::new(
                self.export_snapshot(&g.request.unwrap_or_default()),
            ))),
            _ => None,
        }
    }

    fn on_raft(&self, n: &Arc<Node>, from: Bytes32, rb: RaftBody) {
        match rb {
            RaftBody::RaftSnapshot(s) => {
                let _g = self.apply_lock.lock();
                let offer =
                    self.raft
                        .lock()
                        .offer_snapshot(Instant::now(), from, s.term, s.last_index);
                let out = match offer {
                    raft::SnapshotOffer::Reply(out) => out,
                    raft::SnapshotOffer::Install => {
                        let data = s.data.clone().unwrap_or_default();
                        match Machine::restore_bytes(&data) {
                            Ok(m) if m.last_index == s.last_index && m.last_term == s.last_term => {
                                let members = m.members.clone();
                                let mut r = self.raft.lock();
                                if let Err(e) = r.storage().save_snapshot(&data) {
                                    tracing::error!("saving Raft snapshot: {e}");
                                    return;
                                }
                                *self.machine.lock() = m;
                                self.applied.store(s.last_index, Ordering::SeqCst);
                                let out = r.install_snapshot(s.last_index, s.last_term, members);
                                drop(r);
                                tracing::info!(index = s.last_index, "installed Raft snapshot");
                                self.sync_psk(n);
                                out
                            }
                            _ => {
                                tracing::warn!("bad Raft snapshot from {}", n.name_of(&from));
                                Vec::new()
                            }
                        }
                    }
                };
                drop(_g);
                self.send_raft(n, out);
                self.apply_committed(n);
                self.maybe_sign_head(n);
            }
            other => {
                let out = self.raft.lock().handle(Instant::now(), from, other);
                self.send_raft(n, out);
                self.apply_committed(n);
            }
        }
    }

    // ------------------------------------------------------------ enrollment (§8)

    /// Redeem an enrollment request. Returns the log index, outcome and node id.
    pub async fn redeem(
        self: &Arc<Self>,
        req: &wp::EnrollRequest,
        fwd: Option<RpcBody>,
    ) -> Result<(u64, Outcome, Bytes32)> {
        let lookup = opt_k32(&req.lookup_id);
        let key = opt_k32(&req.identity_key);
        let nonce = opt_k32(&req.nonce);
        let (th, node_id) = {
            let m = self.machine.lock();
            let p = m
                .pending_by_lookup(&lookup)
                .ok_or_else(|| anyhow!("unknown or expired enrollment"))?;
            (p.token_hash, p.node_id)
        };
        if !crypto::ct_eq(
            &crypto::enroll_proof(&th, &key, &nonce),
            &opt_k32(&req.proof),
        ) {
            bail!("bad enrollment proof");
        }
        let payload = EntryPayload::RedeemEnrollmentEntry(Box::new(wp::RedeemEnrollmentEntry {
            token_hash: Some(crypto::k32(&th)),
            identity_key: Some(crypto::k32(&key)),
            node_id: Some(crypto::k32(&node_id)),
        }));
        let fwd = fwd.or_else(|| {
            Some(RpcBody::RedeemRequest(Box::new(wp::RedeemRequest {
                request: Some(req.encode_bytes()),
            })))
        });
        let (i, o) = self.submit(payload, fwd).await?;
        Ok((i, o, node_id))
    }

    /// Redeem for this controller itself (bootstrap, ops guide 2.1 step 5).
    pub async fn redeem_self(self: &Arc<Self>, token: &[u8]) -> Result<Bytes32> {
        let n = self.node().ok_or_else(|| anyhow!("shutting down"))?;
        let th = crypto::token_hash(token);
        let key = n.kp.public();
        let payload = EntryPayload::RedeemEnrollmentEntry(Box::new(wp::RedeemEnrollmentEntry {
            token_hash: Some(crypto::k32(&th)),
            identity_key: Some(crypto::k32(&key)),
            node_id: Some(crypto::k32(&n.me)),
        }));
        self.submit(payload, None).await?;
        Ok(n.me)
    }

    /// Serve one enrollment connection (§8 steps 3–5).
    pub async fn serve_enrollment(self: Arc<Self>, mut io: BoxIo, remote: SocketAddr) {
        let r = async {
            let (ty, body) =
                tokio::time::timeout(Duration::from_secs(10), hop::read_record(&mut io)).await??;
            if ty != rec::CONTROL {
                bail!("unexpected record");
            }
            let req = wp::EnrollRequest::decode_bytes(&body)?;
            let resp = match self.redeem(&req, None).await {
                Ok((idx, _, node_id)) => self.enroll_response(idx, node_id).await,
                Err(e) => wp::EnrollResponse {
                    ok: false,
                    error: Some(e.to_string()),
                    ..Default::default()
                },
            };
            hop::write_record(&mut io, rec::CONTROL, &resp.encode_bytes()).await?;
            use tokio::io::AsyncWriteExt;
            io.flush().await?;
            let _ = io.shutdown().await;
            Ok::<_, anyhow::Error>(resp.ok)
        }
        .await;
        match r {
            Ok(true) => tracing::info!(%remote, "node enrolled"),
            Ok(false) => tracing::info!(%remote, "enrollment refused"),
            Err(e) => tracing::debug!(%remote, "enrollment connection: {e}"),
        }
    }

    async fn enroll_response(&self, idx: u64, node_id: Bytes32) -> wp::EnrollResponse {
        let Some(n) = self.node() else {
            return wp::EnrollResponse::default();
        };
        // Wait until our signed head covers the new record.
        let start = Instant::now();
        loop {
            self.maybe_sign_head(&n);
            let v = n.store.read().head().map_or(0, |h| h.head.version);
            if v >= idx || start.elapsed() > PROPOSE_TIMEOUT {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let s = n.store.read();
        let Some(head) = s.head() else {
            return wp::EnrollResponse {
                ok: false,
                error: Some("controller has no signed tree head yet".into()),
                ..Default::default()
            };
        };
        let leaf = s
            .tree()
            .get(webjet_core::merkle::kind::NODE, &node_id)
            .map(|e| e.bytes.clone())
            .unwrap_or_default();
        let m = self.machine.lock();
        let cur = m.psk_current;
        wp::EnrollResponse {
            ok: true,
            error: None,
            node_id: Some(crypto::k32(&node_id)),
            record: Some(leaf),
            proof: Some(Box::new(
                s.prove(webjet_core::merkle::kind::NODE, &node_id).to_wire(),
            )),
            genesis: Some(s.genesis_raw.clone()),
            certs: Some(
                s.certs()
                    .map(|c| wp::Blob {
                        data: Some(c.raw.clone()),
                    })
                    .collect(),
            ),
            key_tombstones: Some(
                s.key_tombstones()
                    .map(|c| wp::Blob {
                        data: Some(c.raw.clone()),
                    })
                    .collect(),
            ),
            head: Some(head.raw.clone()),
            leaves: Some(
                s.all_leaves()
                    .into_iter()
                    .map(|(k, key, b)| wp::LeafData {
                        kind: k,
                        key: Some(crypto::k32(&key)),
                        bytes: Some(b),
                    })
                    .collect(),
            ),
            offline: Some(
                s.offline_items()
                    .into_iter()
                    .map(|b| wp::Blob { data: Some(b) })
                    .collect(),
            ),
            psk_current: cur,
            psk_epochs: Some(
                m.psk_epochs
                    .iter()
                    .filter(|(k, _)| **k == cur || **k == cur.wrapping_sub(1))
                    .map(|(k, v)| wp::PskEpoch {
                        epoch_id: *k,
                        psk: Some(crypto::k32(v)),
                    })
                    .collect(),
            ),
        }
    }

    // ------------------------------------------------------------ certificates

    /// A certificate request for this controller's signing key (ops guide 2.1
    /// step 6): a SigningKeyCert body signed by the signing key itself.
    pub fn cert_request(&self) -> Result<Vec<u8>> {
        let n = self.node().ok_or_else(|| anyhow!("shutting down"))?;
        let pk = self.signer.public()?;
        let body = wp::SigningKeyCert {
            signing_key_id: Some(crypto::k32(&self.signing_key_id)),
            signing_key: Some(crypto::k32(&pk)),
            controller: Some(crypto::k32(&n.me)),
            cert_serial: now_ms(),
            issuer: None,
        };
        self.signer.sign(mt::CERT_REQUEST, body.encode_bytes())
    }

    // ------------------------------------------------------------ metrics (§12.5)

    /// Verify and keep a node's metric report (§12.5). Reports that come
    /// straight from their node are passed on to the other controllers, so
    /// every controller can serve the whole network to Prometheus.
    pub fn ingest_metrics(&self, from: Bytes32, raw: &[u8]) {
        let Some(n) = self.node() else { return };
        let Ok(v) = crypto::open_envelope(raw) else {
            return;
        };
        if v.ty != mt::METRIC_REPORT {
            return;
        }
        let Ok(rep) = v.decode::<wp::MetricReport>() else {
            return;
        };
        let origin = opt_k32(&rep.node_id);
        if n.store.read().view().nodes.get(&origin).map(|x| x.key) != Some(v.signer) {
            return;
        }
        let from_controller = from != origin;
        if from_controller
            && !self.raft.lock().voters().contains(&from)
            && !self.raft.lock().learners().contains(&from)
        {
            return;
        }
        {
            let mut r = self.reports.lock();
            if let Some(old) = r.get(&origin) {
                // Keep the newest; a restarted node's seq starts over, so compare time first.
                if (old.report.taken_at, old.report.report_seq) >= (rep.taken_at, rep.report_seq) {
                    return;
                }
            }
            r.insert(
                origin,
                StoredReport {
                    received: now_ms(),
                    report: rep,
                },
            );
        }
        if !from_controller {
            let peers: Vec<Bytes32> = {
                let r = self.raft.lock();
                r.voters()
                    .iter()
                    .chain(r.learners().iter())
                    .copied()
                    .filter(|p| *p != n.me)
                    .collect()
            };
            for p in peers {
                rpc::send_oneway(
                    &n,
                    &p,
                    RpcBody::MetricUpload(Box::new(wp::MetricUpload {
                        report: Some(raw.to_vec()),
                    })),
                );
            }
        }
    }

    /// Every node's latest report as OpenMetrics text (the scrape target).
    /// Reports older than 15 minutes are left out (§12.5: one per minute).
    pub fn openmetrics(&self) -> String {
        let Some(n) = self.node() else {
            return "# EOF\n".into();
        };
        let now = now_ms();
        // Copy the recent reports out first so the reports lock isn't nested
        // inside the store lock.
        let recent: Vec<_> = {
            let r = self.reports.lock();
            let mut v: Vec<_> = r
                .iter()
                .filter(|(_, sr)| now.saturating_sub(sr.received) < 15 * 60_000)
                .map(|(id, sr)| (*id, sr.report.clone()))
                .collect();
            v.sort_by_key(|a| a.0);
            v
        };
        let s = n.store.read();
        let names = crate::exposition::ViewNames(s.view());
        let mut e = crate::exposition::Exposition::default();
        for (_, report) in &recent {
            e.report(report, &names, true);
        }
        e.render()
    }

    fn status_wire(&self, n: &Node) -> wp::ControllerStatus {
        let r = self.raft.lock();
        let s = n.store.read();
        wp::ControllerStatus {
            node_id: Some(crypto::k32(&n.me)),
            is_leader: r.role == Role::Leader,
            leader: r.leader.map(|l| crypto::k32(&l)),
            term: r.term,
            commit_index: r.commit,
            applied_index: self.applied.load(Ordering::SeqCst),
            voters: Some(r.voters().iter().map(crypto::k32).collect()),
            learners: Some(r.learners().iter().map(crypto::k32).collect()),
            signed_version: s.head().map_or(0, |h| h.head.version),
        }
    }

    pub fn status(&self) -> serde_json::Value {
        // Raft before the machine (see the lock order on `Controller`).
        let raft = self.raft.lock().status();
        let halted = self.halted.lock().clone();
        let m = self.machine.lock();
        serde_json::json!({
            "raft": raft,
            "applied": self.applied.load(Ordering::SeqCst),
            "signing_key_id": hex::encode(self.signing_key_id),
            "halted": halted,
            "pending_enrollments": m.pending.len(),
            "psk_epoch": m.psk_current,
            "valid_until": m.view().valid_until,
            "camouflage_secret": m.camouflage.is_some(),
            "membership": {
                "settings": membership_settings_json(
                    &membership::Settings::of(m.view().controller_settings.as_ref()),
                ),
                "joined_at": m.member_since.iter().map(|(k, v)| (hex::encode(k), *v)).collect::<BTreeMap<_, _>>(),
            },
        })
    }
}

fn membership_settings_json(s: &membership::Settings) -> serde_json::Value {
    serde_json::json!({
        "auto_membership": s.auto_membership,
        "voters": s.voters,
        "dead_voter_after_s": s.dead_voter_after_s,
    })
}

/// A controller's status as another node received it (`GetControllerStatus`),
/// with hex node ids like the local status.
pub fn remote_status_json(s: &wp::ControllerStatus) -> serde_json::Value {
    let id = |k: &Option<wp::Key32>| k.as_ref().map(|k| hex::encode(k.to_bytes()));
    let ids = |v: &Option<Vec<wp::Key32>>| {
        v.iter()
            .flatten()
            .map(|k| hex::encode(k.to_bytes()))
            .collect::<Vec<_>>()
    };
    serde_json::json!({
        "answered_by": id(&s.node_id),
        "raft": {
            "role": if s.is_leader { "Leader" } else if ids(&s.voters).contains(&id(&s.node_id).unwrap_or_default()) { "Follower" } else { "Learner" },
            "term": s.term,
            "leader": id(&s.leader),
            "commit": s.commit_index,
            "voters": ids(&s.voters),
            "learners": ids(&s.learners),
        },
        "applied": s.applied_index,
        "signed_version": s.signed_version,
    })
}

/// The log payload for a root-signed item submitted by an admin.
pub fn root_payload(raw: &[u8]) -> Result<EntryPayload> {
    let v = crypto::open_envelope(raw)?;
    Ok(match v.ty {
        mt::ACCOUNT_RECORD | mt::ACCOUNT_TOMBSTONE => {
            EntryPayload::RootAccountEntry(Box::new(wp::RootAccountEntry {
                record: Some(raw.to_vec()),
            }))
        }
        mt::STATE_VERSION => {
            EntryPayload::SetStateVersionEntry(Box::new(wp::SetStateVersionEntry {
                state_version: Some(raw.to_vec()),
            }))
        }
        t => bail!("{} is not submitted through the log", mt::name(t)),
    })
}

fn submit_result(res: Result<(u64, Outcome)>) -> RpcBody {
    match res {
        Ok((i, _)) => RpcBody::SubmitResult(Box::new(wp::SubmitResult {
            ok: true,
            index: i,
            error: None,
        })),
        Err(e) => RpcBody::SubmitResult(Box::new(wp::SubmitResult {
            ok: false,
            index: 0,
            error: Some(e.to_string()),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testnode;
    use webjet_core::crypto::KeyPair;
    use webjet_core::statemachine::ops;
    use webjet_core::store::Store;
    use webjet_core::testutil::{Net, net};

    fn op_entry(net: &Net, seq: u64, op: wp::AccountOp) -> EntryPayload {
        ops::op_entry(ops::sign_op(&net.admin, &net.admin_id, seq, now_ms(), op))
    }

    fn change(c: wp::MembershipChange, id: Bytes32) -> wp::AccountOp {
        wp::AccountOp::ChangeMembership(Box::new(wp::ChangeMembership {
            change: c,
            node_id: Some(crypto::k32(&id)),
        }))
    }

    fn entry(payload: EntryPayload, random_node: Option<Bytes32>) -> Vec<u8> {
        wp::LogEntry {
            index: 1,
            term: 1,
            payload: Some(payload),
            random: random_node.map(|id| {
                Box::new(wp::EntryRandom {
                    node_id: Some(crypto::k32(&id)),
                    ..Default::default()
                })
            }),
            ..Default::default()
        }
        .encode_bytes()
    }

    #[test]
    fn classify_entries() {
        use raft::ConfChange;
        let net = net();
        let me = [7; 32];
        let g = EntryPayload::GenesisEntry(Box::new(wp::GenesisEntry {
            genesis: Some(net.genesis.clone()),
        }));
        assert!(matches!(
            classify_entry(&entry(g, Some(me))),
            Some(ConfChange::Set(m)) if m.voters == BTreeSet::from([me]) && m.learners.is_empty()
        ));
        let id = [8; 32];
        use wp::MembershipChange as M;
        for (c, want) in [
            (M::AddLearner, ConfChange::AddLearner(id)),
            (M::Promote, ConfChange::Promote(id)),
            (M::Demote, ConfChange::Demote(id)),
            (M::Remove, ConfChange::Remove(id)),
        ] {
            let signed = entry(op_entry(&net, 1, change(c, id)), None);
            assert_eq!(classify_entry(&signed), Some(want.clone()), "{c:?}");
            let auto = entry(
                EntryPayload::AutoMembershipEntry(Box::new(wp::AutoMembershipEntry {
                    change: c,
                    node_id: Some(crypto::k32(&id)),
                })),
                None,
            );
            assert_eq!(classify_entry(&auto), Some(want), "auto {c:?}");
        }
        // Other operations, other entries, garbage: no change.
        let rename = op_entry(&net, 1, wp::AccountOp::RenameNode(Box::default()));
        assert_eq!(classify_entry(&entry(rename, None)), None);
        let noop = EntryPayload::NoopEntry(Box::default());
        assert_eq!(classify_entry(&entry(noop, None)), None);
        assert_eq!(classify_entry(b"junk"), None);
        // A membership change with a broken signature is no change.
        let EntryPayload::OpEntry(mut o) = op_entry(&net, 1, change(M::Promote, id)) else {
            unreachable!()
        };
        let s = o.signed_op.as_mut().unwrap();
        let last = s.len() - 1;
        s[last] ^= 1;
        assert_eq!(classify_entry(&entry(EntryPayload::OpEntry(o), None)), None);
    }

    #[test]
    fn root_payloads() {
        let net = net();
        let rec = wp::AccountRecord {
            account_id: Some(crypto::k32(&[1; 32])),
            ..Default::default()
        };
        let raw = net.root.sign_obj(mt::ACCOUNT_RECORD, &rec);
        assert!(matches!(
            root_payload(&raw),
            Ok(EntryPayload::RootAccountEntry(_))
        ));
        let raw = net
            .root
            .sign_obj(mt::STATE_VERSION, &wp::StateVersion::default());
        assert!(matches!(
            root_payload(&raw),
            Ok(EntryPayload::SetStateVersionEntry(_))
        ));
        let raw = net.root.sign_obj(mt::TOMBSTONE, &wp::Tombstone::default());
        let e = root_payload(&raw).map(|_| ()).unwrap_err().to_string();
        assert!(e.contains("not submitted through the log"), "{e}");
        assert!(root_payload(b"junk").is_err());
    }

    #[test]
    fn submit_results() {
        let ok = submit_result(Ok((5, Outcome::default())));
        assert!(
            matches!(ok, RpcBody::SubmitResult(r) if r.ok && r.index == 5 && r.error.is_none())
        );
        let err = submit_result(Err(anyhow!("nope")));
        assert!(
            matches!(err, RpcBody::SubmitResult(r) if !r.ok && r.error.as_deref() == Some("nope"))
        );
    }

    #[test]
    fn remote_status() {
        let (a, b, c) = ([1; 32], [2; 32], [3; 32]);
        let s = |me: Bytes32, leader: bool| wp::ControllerStatus {
            node_id: Some(crypto::k32(&me)),
            is_leader: leader,
            leader: Some(crypto::k32(&a)),
            term: 4,
            commit_index: 10,
            applied_index: 9,
            voters: Some(vec![crypto::k32(&a), crypto::k32(&b)]),
            learners: Some(vec![crypto::k32(&c)]),
            signed_version: 8,
        };
        let j = remote_status_json(&s(a, true));
        assert_eq!(j["raft"]["role"], "Leader");
        assert_eq!(j["answered_by"], hex::encode(a));
        assert_eq!(j["raft"]["voters"][1], hex::encode(b));
        assert_eq!(
            (j["applied"].as_u64(), j["signed_version"].as_u64()),
            (Some(9), Some(8))
        );
        assert_eq!(remote_status_json(&s(b, false))["raft"]["role"], "Follower");
        assert_eq!(remote_status_json(&s(c, false))["raft"]["role"], "Learner");
    }

    /// The first controller of a new network, made leader.
    fn first_controller() -> (Net, Arc<Node>, Arc<Controller>, tempfile::TempDir) {
        let net = net();
        let me = crypto::random32();
        let kp = KeyPair::generate();
        let store = Store::new(net.genesis.clone()).unwrap();
        let (n, dir) = testnode::with_store(store, me, kp);
        let c = Controller::start(&n, true).unwrap();
        let _ = n.controller.set(c.clone());
        assert!(n.epochs.read().accept_all, "controllers accept every epoch");
        // A single voter elects itself once its election timeout passes.
        let later = Instant::now() + Duration::from_secs(10);
        let _ = c.raft.lock().tick(later);
        assert!(c.is_leader());
        // The new leader's first entry commits at once; apply it, as the
        // run loop would.
        let _ = c.raft.lock().tick(later);
        c.apply_committed(&n);
        assert_eq!(c.applied.load(Ordering::SeqCst), c.raft.lock().last_index());
        assert_eq!(c.leader(), Some(me));
        (net, n, c, dir)
    }

    #[tokio::test]
    async fn a_new_network_commits_genesis_and_operations() {
        let (net, n, c, _d) = first_controller();
        // Nothing is proposed before genesis.
        let early = c.propose(op_entry(
            &net,
            1,
            change(wp::MembershipChange::Promote, n.me),
        ));
        assert!(early.await.is_err());

        c.clone().leader_duties().await;
        assert!(c.machine.lock().genesis.is_some());
        assert_eq!(c.raft.lock().voters(), &BTreeSet::from([n.me]));
        assert!(
            n.epochs.read().current_key().is_some(),
            "PSK epoch 0 synced"
        );

        let key = KeyPair::generate();
        let (idx, out) = c
            .propose(op_entry(
                &net,
                1,
                wp::AccountOp::CreateEnrollment(Box::new(wp::CreateEnrollment {
                    owner: Some(crypto::k32(&net.admin_id)),
                    name: Some("web".into()),
                    overlay_ips: Some(vec![ops::ip("10.7.0.9").unwrap()]),
                    roles: Some(vec![wp::Role::Data]),
                    identity_key: Some(crypto::k32(&key.public())),
                    ..Default::default()
                })),
            ))
            .await
            .unwrap();
        assert!(idx >= 2);
        let web = out.node_id.unwrap();
        assert_eq!(c.applied.load(Ordering::SeqCst), idx);
        assert!(c.machine.lock().view().nodes.contains_key(&web));
        // A replayed operation (same sequence number) is refused.
        let replay = c
            .propose(op_entry(&net, 1, wp::AccountOp::RenameNode(Box::default())))
            .await;
        assert!(replay.is_err());
        assert!(c.halted.lock().is_none(), "refused at prepare, not halted");
        // `submit` on the leader proposes.
        let (i2, _) = c
            .submit(
                op_entry(
                    &net,
                    2,
                    wp::AccountOp::RenameNode(Box::new(wp::RenameNode {
                        node_id: Some(crypto::k32(&web)),
                        name: Some("www".into()),
                    })),
                ),
                None,
            )
            .await
            .unwrap();
        assert_eq!(i2, idx + 1);
        assert_eq!(c.machine.lock().view().by_name.get("www"), Some(&web));

        let st = c.status();
        assert_eq!(st["applied"], i2);
        assert_eq!(st["halted"], serde_json::Value::Null);
        assert_eq!(st["raft"]["role"], "Leader");
        assert_eq!(
            st["membership"]["settings"]["voters"],
            membership::Settings::of(None).voters
        );
        assert_eq!(st["psk_epoch"], 0);
    }

    #[tokio::test]
    async fn heads_are_signed_only_with_a_certified_key() {
        let (net, n, c, _d) = first_controller();
        c.clone().leader_duties().await;
        let key = KeyPair::generate();
        let (_, out) = c
            .propose(op_entry(
                &net,
                1,
                wp::AccountOp::CreateEnrollment(Box::new(wp::CreateEnrollment {
                    owner: Some(crypto::k32(&net.admin_id)),
                    name: Some("web".into()),
                    overlay_ips: Some(vec![ops::ip("10.7.0.9").unwrap()]),
                    roles: Some(vec![wp::Role::Data]),
                    identity_key: Some(crypto::k32(&key.public())),
                    ..Default::default()
                })),
            ))
            .await
            .unwrap();
        let web = out.node_id.unwrap();
        // No certificate: no head, an alarm.
        c.maybe_sign_head(&n);
        assert!(n.store.read().head().is_none());
        assert!(n.alarms.lock().contains_key("no_signing_cert"));

        // The certificate request is signed by the signing key itself.
        let req = crypto::open_envelope(&c.cert_request().unwrap()).unwrap();
        assert_eq!(req.ty, mt::CERT_REQUEST);
        assert_eq!(crypto::signing_key_id(&req.signer), c.signing_key_id);
        let body: wp::SigningKeyCert = req.decode().unwrap();
        assert_eq!(crypto::opt_k32(&body.controller), n.me);

        // The root certifies it: the next head goes into the node's store.
        let cert = net
            .root
            .sign_envelope(mt::SIGNING_KEY_CERT, req.body)
            .encode_bytes();
        n.store.write().add_cert(&cert).unwrap();
        c.maybe_sign_head(&n);
        assert!(!n.alarms.lock().contains_key("no_signing_cert"));
        let s = n.store.read();
        assert_eq!(
            s.head().unwrap().head.version,
            c.applied.load(Ordering::SeqCst)
        );
        assert!(s.node_trusted(&web));
        drop(s);
        assert!(n.paths.store().exists(), "persisted");
    }

    #[tokio::test]
    async fn a_halted_controller_applies_and_signs_nothing() {
        let (net, n, c, _d) = first_controller();
        c.clone().leader_duties().await;
        let req = crypto::open_envelope(&c.cert_request().unwrap()).unwrap();
        let cert = net
            .root
            .sign_envelope(mt::SIGNING_KEY_CERT, req.body)
            .encode_bytes();
        n.store.write().add_cert(&cert).unwrap();
        c.halt(&n, "test".into());
        // An entry that commits after the halt isn't applied...
        let applied = c.applied.load(Ordering::SeqCst);
        {
            let mut r = c.raft.lock();
            let entry = wp::LogEntry {
                term: r.term,
                index: r.last_index() + 1,
                timestamp: now_ms(),
                payload: Some(EntryPayload::NoopEntry(Box::new(wp::NoopEntry {
                    term: r.term,
                }))),
                random: None,
                leaves: Some(Vec::new()),
            };
            r.propose(Instant::now(), &entry).unwrap();
            assert!(r.commit > applied);
        }
        c.apply_committed(&n);
        assert_eq!(c.applied.load(Ordering::SeqCst), applied);
        // ...no head is signed, and nothing more is proposed.
        c.maybe_sign_head(&n);
        assert!(n.store.read().head().is_none());
        let e = c
            .propose(op_entry(&net, 2, wp::AccountOp::RenameNode(Box::default())))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("halted"), "{e}");
        // Status still answers (and doesn't deadlock against a proposal).
        assert_eq!(c.status()["halted"], "test");
    }

    #[tokio::test]
    async fn the_operation_log_is_for_admins() {
        let (net, n, c, _d) = first_controller();
        c.clone().leader_duties().await;
        let req = |key: &KeyPair, account: Bytes32, issued_at| {
            key.sign_obj(
                mt::LOG_REQUEST,
                &wp::LogRequest {
                    account_id: Some(crypto::k32(&account)),
                    issued_at,
                    before: 0,
                    limit: 10,
                },
            )
        };
        let r = c.log(&req(&net.admin, net.admin_id, now_ms()));
        assert_eq!(r.error, None);
        // The new leader's no-op, then genesis.
        assert_eq!(r.commit_index, 2);
        let recs = r.records.unwrap();
        assert_eq!(recs.iter().map(|r| r.index).collect::<Vec<_>>(), vec![1, 2]);
        // Another key for the admin's account, an unknown account, a stale request.
        let other = KeyPair::generate();
        assert!(c.log(&req(&other, net.admin_id, now_ms())).error.is_some());
        assert!(c.log(&req(&other, [9; 32], now_ms())).error.is_some());
        let stale = c.log(&req(&net.admin, net.admin_id, now_ms() - 3_600_000));
        assert!(stale.error.unwrap().contains("clock"));
        drop(n);
    }

    #[tokio::test]
    async fn snapshots_are_for_admins() {
        let (net, n, c, _d) = first_controller();
        let req = |key: &KeyPair, account: Bytes32, issued_at| {
            key.sign_obj(
                mt::SNAPSHOT_REQUEST,
                &wp::SnapshotRequest {
                    account_id: Some(crypto::k32(&account)),
                    issued_at,
                },
            )
        };
        // Before genesis there's nothing to export (and no admin to check).
        assert!(
            c.export_snapshot(&req(&net.admin, net.admin_id, now_ms()))
                .error
                .is_some()
        );
        c.clone().leader_duties().await;
        let r = c.export_snapshot(&req(&net.admin, net.admin_id, now_ms()));
        assert_eq!(r.error, None);
        let m = Machine::restore_bytes(&r.snapshot.unwrap()).unwrap();
        assert_eq!(m.last_index, c.machine.lock().last_index);
        assert_eq!(m.members.voters, BTreeSet::from([n.me]));
        assert!(m.psk(0).is_some(), "the PSKs are in it");
        let other = KeyPair::generate();
        assert!(
            c.export_snapshot(&req(&other, net.admin_id, now_ms()))
                .snapshot
                .is_none()
        );
        let stale = c.export_snapshot(&req(&net.admin, net.admin_id, now_ms() - 3_600_000));
        assert!(stale.error.unwrap().contains("clock"));
        // A log request is no snapshot request.
        let log = net.admin.sign_obj(
            mt::LOG_REQUEST,
            &wp::LogRequest {
                account_id: Some(crypto::k32(&net.admin_id)),
                issued_at: now_ms(),
                ..Default::default()
            },
        );
        assert!(c.export_snapshot(&log).error.is_some());
    }

    #[tokio::test]
    async fn metric_reports_from_their_nodes() {
        let (net, n, c, _d) = first_controller();
        c.clone().leader_duties().await;
        let key = KeyPair::generate();
        let (_, out) = c
            .propose(op_entry(
                &net,
                1,
                wp::AccountOp::CreateEnrollment(Box::new(wp::CreateEnrollment {
                    owner: Some(crypto::k32(&net.admin_id)),
                    name: Some("web".into()),
                    overlay_ips: Some(vec![ops::ip("10.7.0.9").unwrap()]),
                    roles: Some(vec![wp::Role::Data]),
                    identity_key: Some(crypto::k32(&key.public())),
                    ..Default::default()
                })),
            ))
            .await
            .unwrap();
        let web = out.node_id.unwrap();
        // The node's store needs the tree for the signer check.
        let req = crypto::open_envelope(&c.cert_request().unwrap()).unwrap();
        let cert = net
            .root
            .sign_envelope(mt::SIGNING_KEY_CERT, req.body)
            .encode_bytes();
        n.store.write().add_cert(&cert).unwrap();
        c.maybe_sign_head(&n);

        let report = |seq: u64, taken_at: u64| wp::MetricReport {
            node_id: Some(crypto::k32(&web)),
            report_seq: seq,
            taken_at,
            policy_version: 42,
            ..Default::default()
        };
        let t = now_ms();
        c.ingest_metrics(web, &key.sign_obj(mt::METRIC_REPORT, &report(1, t)));
        assert_eq!(c.reports.lock()[&web].report.report_seq, 1);
        // Older reports don't replace newer ones.
        c.ingest_metrics(web, &key.sign_obj(mt::METRIC_REPORT, &report(9, t - 1000)));
        assert_eq!(c.reports.lock()[&web].report.report_seq, 1);
        // Signed by another key, or relayed by a node that isn't a controller.
        let rogue = KeyPair::generate();
        c.ingest_metrics(web, &rogue.sign_obj(mt::METRIC_REPORT, &report(2, t + 1)));
        c.ingest_metrics([5; 32], &key.sign_obj(mt::METRIC_REPORT, &report(3, t + 2)));
        // Not a report at all.
        c.ingest_metrics(
            web,
            &key.sign_obj(mt::LOG_REQUEST, &wp::LogRequest::default()),
        );
        assert_eq!(c.reports.lock()[&web].report.report_seq, 1);
        c.ingest_metrics(web, &key.sign_obj(mt::METRIC_REPORT, &report(2, t + 1)));
        assert_eq!(c.reports.lock()[&web].report.report_seq, 2);

        let text = c.openmetrics();
        assert!(text.contains("webjet_policy_version"), "{text}");
        assert!(text.contains("node=\"web\""), "{text}");
        assert!(text.ends_with("# EOF\n"));
    }
}
