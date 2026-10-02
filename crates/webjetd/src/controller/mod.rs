//! The controller role (§7): Raft over end-to-end sessions, proposing and
//! applying operations, signing tree heads, serving enrollment, PSK and
//! camouflage material, and collecting metric reports.

pub mod raft;
pub mod signer;

use crate::node::Node;
use crate::rpc;
use anyhow::{anyhow, bail, Result};
use parking_lot::Mutex;
use raft::{Raft, Role};
use signer::Signer;
use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use webjet_core::crypto::{self, opt_k32, Bytes32};
use webjet_core::statemachine::{ApplyError, Machine, Outcome};
use webjet_core::store::HeadOutcome;
use webjet_core::types::{now_ms, HOUR, VALIDITY_PERIOD};
use webjet_net::hop::{self, rec, BoxIo};
use webjet_proto::{self as wp, msg_type as mt, Decodable, Encodable, EntryPayload, RaftBody, RpcBody};

const PROPOSE_TIMEOUT: Duration = Duration::from_secs(15);
const HEAD_RESIGN: u64 = HOUR;

struct Waiter {
    hash: Bytes32,
    tx: oneshot::Sender<std::result::Result<Outcome, String>>,
}

pub struct Controller {
    node: Weak<Node>,
    pub machine: Mutex<Machine>,
    pub raft: Mutex<Raft>,
    signer: Box<dyn Signer>,
    pub signing_key_id: Bytes32,
    applied: AtomicU64,
    waiters: Mutex<HashMap<u64, Waiter>>,
    propose_lock: tokio::sync::Mutex<()>,
    last_signed: Mutex<(u64, u64)>,
    pub halted: Mutex<Option<String>>,
    pub reports: Mutex<HashMap<Bytes32, (u64, serde_json::Value)>>,
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
        self.machine.lock().pending.values().filter(|p| p.expires_at > now).map(|p| p.token_hash).collect()
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
        let storage = raft::Storage::new(dir.clone())?;
        let machine = match storage.load_snapshot() {
            Some(b) => Machine::restore_bytes(&b)?,
            None => Machine::new(),
        };
        let mut r = Raft::open(n.me, dir, machine.last_index, machine.last_term)?;
        if machine.genesis.is_some() {
            r.set_members(machine.members.voters.clone(), machine.members.learners.clone());
        } else if bootstrap {
            r.set_members(BTreeSet::from([n.me]), BTreeSet::new());
        }
        let signer: Box<dyn Signer> = match &n.cfg.controller.signer_socket {
            Some(p) => Box::new(signer::SocketSigner::new(p.clone())),
            None => Box::new(signer::FileSigner::open(&n.paths.dir.join("signing.key"))?),
        };
        let pk = signer.public()?;
        let c = Arc::new(Controller {
            node: Arc::downgrade(n),
            applied: AtomicU64::new(machine.last_index),
            machine: Mutex::new(machine),
            raft: Mutex::new(r),
            signing_key_id: crypto::signing_key_id(&pk),
            signer,
            waiters: Mutex::new(HashMap::new()),
            propose_lock: tokio::sync::Mutex::new(()),
            last_signed: Mutex::new((0, 0)),
            halted: Mutex::new(None),
            reports: Mutex::new(HashMap::new()),
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
            if self.halted.lock().is_some() {
                continue;
            }
            let out = self.raft.lock().tick();
            self.send_raft(&n, out);
            self.apply_committed(&n);
            self.send_snapshots(&n);
            if i % 10 == 0 {
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
            rpc::send_oneway(n, &to, RpcBody::RaftRpc(Box::new(wp::RaftRpc { message: Some(msg) })));
        }
    }

    fn send_snapshots(&self, n: &Arc<Node>) {
        let peers = self.raft.lock().needs_snapshot();
        if peers.is_empty() {
            return;
        }
        let Some(data) = self.raft.lock().storage().load_snapshot() else { return };
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
        loop {
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
                    self.applied.store(next, Ordering::SeqCst);
                    if !outcome.description.is_empty() && outcome.description != "no-op" {
                        tracing::info!(index = next, signer = ?outcome.signer.map(|s| crypto::short(&s)), "applied: {}", outcome.description);
                    }
                    if outcome.membership_changed || matches!(entry.payload, Some(EntryPayload::GenesisEntry(_))) {
                        let (v, l) = {
                            let m = self.machine.lock();
                            (m.members.voters.clone(), m.members.learners.clone())
                        };
                        self.raft.lock().set_members(v, l);
                    }
                    if outcome.psk_rotated || matches!(entry.payload, Some(EntryPayload::GenesisEntry(_))) {
                        self.sync_psk(n);
                    }
                    if let Some(w) = self.waiters.lock().remove(&next) {
                        let _ = w.tx.send(if w.hash == entry_hash(&bytes) { Ok(outcome) } else { Err("entry was superseded by a new leader".into()) });
                    }
                    if next % raft::COMPACT_EVERY == 0 {
                        self.compact();
                    }
                }
                Err(ApplyError::Unsupported(v)) => {
                    self.halt(n, format!("state version {v} is not supported by this software; upgrade (§15.7)"));
                    return;
                }
                Err(e) => {
                    self.halt(n, format!("{e}"));
                    return;
                }
            }
        }
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
        let mut r = self.raft.lock();
        if r.storage().save_snapshot(&bytes).is_ok() {
            r.compact(idx);
        }
    }

    fn sync_psk(&self, n: &Arc<Node>) {
        let (cur, epochs) = {
            let m = self.machine.lock();
            (m.psk_current, m.psk_epochs.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>())
        };
        if epochs.is_empty() {
            return;
        }
        n.set_psk(cur, epochs);
    }

    // ------------------------------------------------------------ tree heads (§7.3)

    fn maybe_sign_head(&self, n: &Arc<Node>) {
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
        // Only sign with a certified key (§6.5).
        let certified = n.store.read().certs().any(|c| opt_k32(&c.cert.signing_key_id) == self.signing_key_id);
        if !certified {
            n.alarm("no_signing_cert", "warning", "this controller's signing key has no SigningKeyCert yet (runbook 1 step 6)".into());
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
                n.alarm("signer_unavailable", "critical", format!("signing the tree head failed: {e}"));
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
                        if s.tree().get_by_path(p).map(|x| x.hash != e.hash).unwrap_or(true) {
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
        let Ok(_g) = self.propose_lock.try_lock() else { return };
        let (genesis_needed, due_validity, due_expiry) = {
            let m = self.machine.lock();
            let now = now_ms();
            (m.genesis.is_none(), m.genesis.is_some() && m.validity_due(now), m.expiry_due(now))
        };
        drop(_g);
        if genesis_needed {
            if !self.bootstrap {
                return;
            }
            let Some(n) = self.node() else { return };
            let g = n.store.read().genesis_raw.clone();
            match self.propose(EntryPayload::GenesisEntry(Box::new(wp::GenesisEntry { genesis: Some(g) }))).await {
                Ok(_) => tracing::info!("network genesis committed"),
                Err(e) => tracing::warn!("genesis: {e}"),
            }
            return;
        }
        if due_validity {
            let now = now_ms();
            if let Err(e) = self.propose(EntryPayload::ExtendValidityEntry(Box::new(wp::ExtendValidityEntry { valid_until: now + VALIDITY_PERIOD }))).await {
                tracing::debug!("validity extension: {e}");
            }
        }
        if due_expiry {
            let _ = self.propose(EntryPayload::ExpireEnrollmentsEntry(Box::new(wp::ExpireEnrollmentsEntry { now: now_ms() }))).await;
        }
    }

    /// Propose an entry as the leader and wait for it to be applied here.
    /// Proposals are serialized so each is validated against the state it
    /// will be applied to.
    pub async fn propose(&self, payload: EntryPayload) -> Result<(u64, Outcome)> {
        let _g = tokio::time::timeout(PROPOSE_TIMEOUT, self.propose_lock.lock()).await.map_err(|_| anyhow!("controller busy"))?;
        let Some(n) = self.node() else { bail!("shutting down") };
        let start = Instant::now();
        // Wait until everything in the log is applied.
        loop {
            if self.halted.lock().is_some() {
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
            let mut entry = m.prepare(r.term, idx, now_ms(), payload).map_err(|e| anyhow!("{e}"))?;
            if matches!(entry.payload, Some(EntryPayload::GenesisEntry(_))) {
                // The first voter is this controller.
                if let Some(rnd) = entry.random.as_mut() {
                    rnd.node_id = Some(crypto::k32(&n.me));
                }
            }
            drop(m);
            let bytes = entry.encode_bytes();
            let Some((i, out)) = r.propose(&entry) else { bail!("not the leader") };
            debug_assert_eq!(i, idx);
            let (tx, rx) = oneshot::channel();
            self.waiters.lock().insert(i, Waiter { hash: entry_hash(&bytes), tx });
            drop(r);
            self.send_raft(&n, out);
            (rx, i)
        };
        // Single-voter clusters commit immediately; apply right away.
        self.apply_committed(&n);
        let outcome = tokio::time::timeout(PROPOSE_TIMEOUT, rx).await.map_err(|_| anyhow!("entry {idx} not committed in time"))?.map_err(|_| anyhow!("waiter dropped"))?.map_err(|e| anyhow!(e))?;
        drop(_g);
        self.maybe_sign_head(&n);
        Ok((idx, outcome))
    }

    /// Submit an operation: propose here if leader, else forward to the leader.
    pub async fn submit(self: &Arc<Self>, payload: EntryPayload, raw_for_forward: Option<RpcBody>) -> Result<(u64, Outcome)> {
        if self.is_leader() {
            return self.propose(payload).await;
        }
        let Some(n) = self.node() else { bail!("shutting down") };
        let leader = self.leader().ok_or_else(|| anyhow!("no Raft leader (is a majority of voters up?)"))?;
        let body = raw_for_forward.ok_or_else(|| anyhow!("can't forward this operation"))?;
        match rpc::call(&n, &leader, body, PROPOSE_TIMEOUT).await? {
            RpcBody::SubmitResult(r) if r.ok => {
                // Wait for the entry to reach us, so callers see it locally.
                let start = Instant::now();
                while self.applied.load(Ordering::SeqCst) < r.index && start.elapsed() < PROPOSE_TIMEOUT {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Ok((r.index, Outcome { description: "forwarded".into(), ..Default::default() }))
            }
            RpcBody::SubmitResult(r) => bail!(r.error.unwrap_or_default()),
            _ => bail!("unexpected reply from the leader"),
        }
    }

    // ------------------------------------------------------------ RPC

    pub async fn handle_rpc(self: Arc<Self>, from: Bytes32, body: RpcBody) -> Option<RpcBody> {
        let n = self.node()?;
        let ack = |ok: bool, e: Option<String>| Some(RpcBody::RpcAck(Box::new(wp::RpcAck { ok, error: e })));
        let trusted = n.store.read().node_trusted(&from) || self.raft.lock().voters.contains(&from) || self.raft.lock().learners.contains(&from);
        if !trusted {
            return ack(false, Some("untrusted caller".into()));
        }
        match body {
            RpcBody::RaftRpc(r) => {
                let (src, to, rb) = raft::unwrap(&r.message.unwrap_or_default())?;
                if src != from || to != n.me {
                    return None;
                }
                let is_ctl = n.store.read().view().is_controller(&from) || self.raft.lock().voters.contains(&from) || self.raft.lock().learners.contains(&from);
                if !is_ctl {
                    return None;
                }
                self.on_raft(&n, from, rb);
                None
            }
            RpcBody::SubmitOp(s) => {
                let raw = s.signed.clone().unwrap_or_default();
                let payload = webjet_core::statemachine::ops::op_entry(raw.clone());
                let res = self.submit(payload, Some(RpcBody::SubmitOp(s))).await;
                Some(submit_result(res))
            }
            RpcBody::RedeemRequest(r) => {
                let req = wp::EnrollRequest::decode_bytes(&r.request.clone().unwrap_or_default()).ok()?;
                let res = self.redeem(&req, Some(RpcBody::RedeemRequest(r))).await.map(|(i, o, _)| (i, o));
                Some(submit_result(res))
            }
            RpcBody::GetPsk(g) => {
                let m = self.machine.lock();
                let cur = m.psk_current;
                let all = g.all && n.store.read().view().nodes.get(&from).map(|x| x.relay || x.control).unwrap_or(false);
                let epochs = m
                    .psk_epochs
                    .iter()
                    .filter(|(k, _)| all || **k == cur || **k == cur.wrapping_sub(1))
                    .map(|(k, v)| wp::PskEpoch { epoch_id: *k, psk: Some(crypto::k32(v)) })
                    .collect();
                Some(RpcBody::PskInfo(Box::new(wp::PskInfo { current: cur, epochs: Some(epochs) })))
            }
            RpcBody::GetCamouflage(_) => {
                let allowed = n.store.read().view().nodes.get(&from).map(|x| x.relay || x.control).unwrap_or(false);
                if !allowed {
                    return ack(false, Some("only relays and controllers get the camouflage key".into()));
                }
                let c = self.machine.lock().camouflage.clone();
                match c {
                    Some((k, site)) => Some(RpcBody::CamouflageSecret(Box::new(wp::CamouflageSecret { private_key: Some(k), site: Some(site) }))),
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
                    if let Err(e) = n.store.write().add_offline_item(&b.data.unwrap_or_default()) {
                        errs.push(e.to_string());
                    }
                }
                n.persist_store();
                crate::gossip::push_head(&n);
                ack(errs.is_empty(), (!errs.is_empty()).then(|| errs.join("; ")))
            }
            RpcBody::GetControllerStatus(_) => Some(RpcBody::ControllerStatus(Box::new(self.status_wire(&n)))),
            _ => None,
        }
    }

    fn on_raft(&self, n: &Arc<Node>, from: Bytes32, rb: RaftBody) {
        match rb {
            RaftBody::RaftSnapshot(s) => {
                let data = s.data.clone().unwrap_or_default();
                let res = Machine::restore_bytes(&data);
                let mut r = self.raft.lock();
                if s.term < r.term {
                    return;
                }
                match res {
                    Ok(m) if m.last_index == s.last_index => {
                        let (v, l) = (m.members.voters.clone(), m.members.learners.clone());
                        let _ = r.storage().save_snapshot(&data);
                        r.install_snapshot(s.last_index, s.last_term);
                        r.set_members(v, l);
                        r.leader = Some(from);
                        r.last_leader_contact = Instant::now();
                        *self.machine.lock() = m;
                        self.applied.store(s.last_index, Ordering::SeqCst);
                        let term = r.term;
                        drop(r);
                        tracing::info!(index = s.last_index, "installed Raft snapshot");
                        self.sync_psk(n);
                        self.send_raft(n, vec![(from, RaftBody::RaftSnapshotResponse(Box::new(wp::RaftSnapshotResponse { term, last_index: s.last_index })))]);
                        self.maybe_sign_head(n);
                    }
                    Ok(_) | Err(_) => tracing::warn!("bad Raft snapshot from {}", n.name_of(&from)),
                }
            }
            other => {
                let out = self.raft.lock().handle(from, other);
                self.send_raft(n, out);
                self.apply_committed(n);
            }
        }
    }

    // ------------------------------------------------------------ enrollment (§8)

    /// Redeem an enrollment request. Returns the log index, outcome and node id.
    pub async fn redeem(self: &Arc<Self>, req: &wp::EnrollRequest, fwd: Option<RpcBody>) -> Result<(u64, Outcome, Bytes32)> {
        let lookup = opt_k32(&req.lookup_id);
        let key = opt_k32(&req.identity_key);
        let nonce = opt_k32(&req.nonce);
        let (th, node_id) = {
            let m = self.machine.lock();
            let p = m.pending_by_lookup(&lookup).ok_or_else(|| anyhow!("unknown or expired enrollment"))?;
            (p.token_hash, p.node_id)
        };
        if !crypto::ct_eq(&crypto::enroll_proof(&th, &key, &nonce), &opt_k32(&req.proof)) {
            bail!("bad enrollment proof");
        }
        let payload = EntryPayload::RedeemEnrollmentEntry(Box::new(wp::RedeemEnrollmentEntry {
            token_hash: Some(crypto::k32(&th)),
            identity_key: Some(crypto::k32(&key)),
            node_id: Some(crypto::k32(&node_id)),
        }));
        let fwd = fwd.or_else(|| Some(RpcBody::RedeemRequest(Box::new(wp::RedeemRequest { request: Some(req.encode_bytes()) }))));
        let (i, o) = self.submit(payload, fwd).await?;
        Ok((i, o, node_id))
    }

    /// Redeem for this controller itself (bootstrap, runbook 1 step 5).
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
            let (ty, body) = tokio::time::timeout(Duration::from_secs(10), hop::read_record(&mut io)).await??;
            if ty != rec::CONTROL {
                bail!("unexpected record");
            }
            let req = wp::EnrollRequest::decode_bytes(&body)?;
            let resp = match self.redeem(&req, None).await {
                Ok((idx, _, node_id)) => self.enroll_response(idx, node_id).await,
                Err(e) => wp::EnrollResponse { ok: false, error: Some(e.to_string()), ..Default::default() },
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
        let Some(n) = self.node() else { return wp::EnrollResponse::default() };
        // Wait until our signed head covers the new record.
        let start = Instant::now();
        loop {
            self.maybe_sign_head(&n);
            let v = n.store.read().head().map(|h| h.head.version).unwrap_or(0);
            if v >= idx || start.elapsed() > PROPOSE_TIMEOUT {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let s = n.store.read();
        let Some(head) = s.head() else {
            return wp::EnrollResponse { ok: false, error: Some("controller has no signed tree head yet".into()), ..Default::default() };
        };
        let leaf = s.tree().get(webjet_core::merkle::kind::NODE, &node_id).map(|e| e.bytes.clone()).unwrap_or_default();
        let m = self.machine.lock();
        let cur = m.psk_current;
        wp::EnrollResponse {
            ok: true,
            error: None,
            node_id: Some(crypto::k32(&node_id)),
            record: Some(leaf),
            proof: Some(Box::new(s.prove(webjet_core::merkle::kind::NODE, &node_id).to_wire())),
            genesis: Some(s.genesis_raw.clone()),
            certs: Some(s.certs().map(|c| wp::Blob { data: Some(c.raw.clone()) }).collect()),
            key_tombstones: Some(s.key_tombstones().map(|c| wp::Blob { data: Some(c.raw.clone()) }).collect()),
            head: Some(head.raw.clone()),
            leaves: Some(s.all_leaves().into_iter().map(|(k, key, b)| wp::LeafData { kind: k, key: Some(crypto::k32(&key)), bytes: Some(b) }).collect()),
            offline: Some(s.offline_items().into_iter().map(|b| wp::Blob { data: Some(b) }).collect()),
            psk_current: cur,
            psk_epochs: Some(m.psk_epochs.iter().filter(|(k, _)| **k == cur || **k == cur.wrapping_sub(1)).map(|(k, v)| wp::PskEpoch { epoch_id: *k, psk: Some(crypto::k32(v)) }).collect()),
        }
    }

    // ------------------------------------------------------------ certificates

    /// A certificate request for this controller's signing key (runbook 1
    /// step 6): a SigningKeyCert body signed by the signing key itself.
    pub fn cert_request(&self) -> Result<Vec<u8>> {
        let n = self.node().ok_or_else(|| anyhow!("shutting down"))?;
        let pk = self.signer.public()?;
        let body = wp::SigningKeyCert { signing_key_id: Some(crypto::k32(&self.signing_key_id)), signing_key: Some(crypto::k32(&pk)), controller: Some(crypto::k32(&n.me)), cert_serial: now_ms() };
        self.signer.sign(mt::CERT_REQUEST, body.encode_bytes())
    }

    // ------------------------------------------------------------ metrics (§12.5)

    pub fn ingest_metrics(&self, from: Bytes32, raw: &[u8]) {
        let Some(n) = self.node() else { return };
        let Ok(v) = crypto::open_envelope(raw) else { return };
        if v.ty != mt::METRIC_REPORT || n.store.read().view().nodes.get(&from).map(|x| x.key) != Some(v.signer) {
            return;
        }
        let Ok(rep) = v.decode::<wp::MetricReport>() else { return };
        let name = n.name_of(&from);
        if let Some(dir) = &n.cfg.controller.metrics_dir {
            let _ = std::fs::create_dir_all(dir);
            let _ = std::fs::write(dir.join(format!("{name}.prom")), crate::metrics::openmetrics(&name, &rep));
        }
        if let Some(url) = n.cfg.controller.metrics_push.clone() {
            let body = crate::metrics::openmetrics(&name, &rep);
            tokio::spawn(async move {
                if let Err(e) = push_http(&url, &body).await {
                    tracing::debug!("metrics push: {e}");
                }
            });
        }
        let json = serde_json::to_value(&rep).unwrap_or_default();
        self.reports.lock().insert(from, (now_ms(), json));
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
            voters: Some(r.voters.iter().map(crypto::k32).collect()),
            learners: Some(r.learners.iter().map(crypto::k32).collect()),
            signed_version: s.head().map(|h| h.head.version).unwrap_or(0),
        }
    }

    pub fn status(&self) -> serde_json::Value {
        let m = self.machine.lock();
        serde_json::json!({
            "raft": self.raft.lock().status(),
            "applied": self.applied.load(Ordering::SeqCst),
            "signing_key_id": hex::encode(self.signing_key_id),
            "halted": self.halted.lock().clone(),
            "pending_enrollments": m.pending.len(),
            "psk_epoch": m.psk_current,
            "valid_until": m.view().valid_until,
            "camouflage_secret": m.camouflage.is_some(),
        })
    }
}

fn submit_result(res: Result<(u64, Outcome)>) -> RpcBody {
    match res {
        Ok((i, _)) => RpcBody::SubmitResult(Box::new(wp::SubmitResult { ok: true, index: i, error: None })),
        Err(e) => RpcBody::SubmitResult(Box::new(wp::SubmitResult { ok: false, index: 0, error: Some(e.to_string()) })),
    }
}

/// POST OpenMetrics text to an http:// URL (a local collector or agent).
async fn push_http(url: &str, body: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rest = url.strip_prefix("http://").ok_or_else(|| anyhow!("only http:// push URLs are supported"))?;
    let (hostport, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let mut s = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(hostport)).await??;
    let req = format!("POST {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/openmetrics-text; version=1.0.0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    s.write_all(req.as_bytes()).await?;
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await?;
    let line = String::from_utf8_lossy(&buf[..n]);
    if !line.contains(" 2") {
        bail!("push rejected: {}", line.lines().next().unwrap_or(""));
    }
    Ok(())
}
