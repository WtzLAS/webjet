//! Circuits (§11.5, §11.6): label-switched paths through relays.
//!
//! Every node keeps a table keyed by `(neighbor, label)`, where `label` is
//! the circuit ID this node allocated for frames arriving from that neighbor.
//! `CircuitOpen.label` is the opener's label for frames coming back to it;
//! `CircuitAccept.peer_label` is the acceptor's label for frames toward it.

use crate::node::{Hop, Node};
use anyhow::{Result, anyhow, bail};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use webjet_core::crypto::{self, Bytes32, opt_k32};
use webjet_core::frames::{self, DEFAULT_HOP_LIMIT};
use webjet_core::routing::LinkStats;
use webjet_core::types::{SKEW_SHORT_RECORD, now_ms};
use webjet_proto::{self as wp, HopMsg, msg_type as mt};

const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const TRANSIT_IDLE: Duration = Duration::from_secs(300);
const PENDING_TIMEOUT: Duration = Duration::from_secs(30);

/// A circuit ending at this node (as source or destination).
pub struct LocalCircuit {
    /// The end-to-end peer.
    pub peer: Bytes32,
    /// My label for frames arriving from `next`.
    pub label: u32,
    /// The neighbor frames go to (first relay, or the peer when direct).
    pub next: Bytes32,
    pub out_label: Mutex<Option<u32>>,
    pub hops: Vec<Bytes32>,
    pub route_id: Bytes32,
    pub is_source: bool,
    pub created: Instant,
    pub probes: Mutex<LinkStats>,
    pub e2e_rtt_ms: Mutex<Option<f64>>,
    pub last_rx: Mutex<Instant>,
}

impl LocalCircuit {
    pub fn direct(&self) -> bool {
        self.hops.is_empty()
    }

    /// Measured end-to-end cost; infinite until probes have answered.
    pub fn cost(&self) -> f64 {
        let p = self.probes.lock();
        if p.samples == 0 {
            f64::INFINITY
        } else {
            p.cost()
        }
    }

    fn flow(&self) -> u64 {
        webjet_core::bytes::prefix_u64(&self.route_id)
    }

    /// Send an end-to-end frame on this circuit.
    pub fn send(&self, n: &Node, frame: &[u8], ecn: u8) -> bool {
        let Some(out) = *self.out_label.lock() else {
            return false;
        };
        let Some(hop) = n.best_hop(&self.next) else {
            return false;
        };
        let mut f = Vec::with_capacity(frames::RELAY_HEADER + frame.len());
        f.extend_from_slice(&frames::relay_header(out, DEFAULT_HOP_LIMIT, ecn));
        f.extend_from_slice(frame);
        if let Some(r) = n.circuits.lock().routes.get(&self.route_id) {
            r.fwd.add(frame.len());
        }
        hop.send_relay(self.flow(), f)
    }
}

pub struct Transit {
    pub out_neighbor: Bytes32,
    pub out_label: Option<u32>,
    pub route_id: Bytes32,
    pub src: Bytes32,
    /// Forward (src → dst) or reverse direction.
    pub forward: bool,
    /// The reverse direction's key in the table.
    pub pair: (Bytes32, u32),
    pub last: Instant,
}

pub enum Kind {
    Local(Arc<LocalCircuit>),
    Transit(Transit),
}

pub struct Entry {
    pub kind: Kind,
    pub created: Instant,
}

#[derive(Default)]
pub struct Dir {
    pub frames: AtomicU64,
    pub bytes: AtomicU64,
}

impl Dir {
    pub fn add(&self, len: usize) {
        self.frames.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(len as u64, Ordering::Relaxed);
    }
}

/// Per-route accounting (§12.3), shared by every circuit with the same route.
#[derive(Default)]
pub struct RouteAcct {
    pub src: Bytes32,
    pub dst: Bytes32,
    pub hops: Vec<Bytes32>,
    pub fwd: Dir,
    pub rev: Dir,
    pub dropped_queue: AtomicU64,
    pub dropped_hop_limit: AtomicU64,
    pub ecn_marked: AtomicU64,
    pub setups: AtomicU64,
    pub active_since: AtomicU64,
    pub circuits: AtomicU64,
}

/// A setup waiting for the next hop's answer (relays and sources).
struct PendingOpen {
    /// Where the answer goes: the previous neighbor and its label, or the
    /// local opener.
    prev: Option<(Bytes32, u32, u32)>,
    waiter: Option<oneshot::Sender<Result<u32, String>>>,
    at: Instant,
}

#[derive(Default)]
pub struct Table {
    pub entries: HashMap<(Bytes32, u32), Entry>,
    pub routes: HashMap<Bytes32, Arc<RouteAcct>>,
    pub refused: BTreeMap<String, u64>,
    /// Keyed by (next neighbor, the label we sent in CircuitOpen).
    pending: HashMap<(Bytes32, u32), PendingOpen>,
    nonces: HashMap<[u8; 16], Instant>,
    setup_rate: (Option<Instant>, u32),
}

impl Table {
    fn alloc(&self, neighbor: &Bytes32) -> u32 {
        loop {
            let l = rand::random::<u32>() | 1;
            if !self.entries.contains_key(&(*neighbor, l))
                && !self.pending.contains_key(&(*neighbor, l))
            {
                return l;
            }
        }
    }

    pub fn local_circuits(&self, peer: &Bytes32) -> Vec<Arc<LocalCircuit>> {
        self.entries
            .values()
            .filter_map(|e| match &e.kind {
                Kind::Local(c) if c.peer == *peer && c.out_label.lock().is_some() => {
                    Some(c.clone())
                }
                _ => None,
            })
            .collect()
    }

    pub fn transit_count(&self) -> usize {
        self.entries
            .values()
            .filter(|e| matches!(&e.kind, Kind::Transit(t) if t.forward))
            .count()
    }

    fn route(
        &mut self,
        rid: &Bytes32,
        src: &Bytes32,
        dst: &Bytes32,
        hops: &[Bytes32],
    ) -> Arc<RouteAcct> {
        let r = self.routes.entry(*rid).or_insert_with(|| {
            Arc::new(RouteAcct {
                src: *src,
                dst: *dst,
                hops: hops.to_vec(),
                active_since: AtomicU64::new(now_ms()),
                ..Default::default()
            })
        });
        r.setups.fetch_add(1, Ordering::Relaxed);
        r.circuits.fetch_add(1, Ordering::Relaxed);
        r.clone()
    }

    fn refuse(&mut self, why: &str) {
        *self.refused.entry(why.to_string()).or_insert(0) += 1;
    }

    fn remove_entry(&mut self, key: &(Bytes32, u32)) -> Option<Entry> {
        let e = self.entries.remove(key)?;
        let rid = match &e.kind {
            Kind::Local(c) => Some(c.route_id),
            Kind::Transit(t) if t.forward => Some(t.route_id),
            _ => None,
        };
        if let Some(rid) = rid
            && let Some(r) = self.routes.get(&rid)
            && r.circuits.fetch_sub(1, Ordering::Relaxed) <= 1
        {
            // Keep the counters around for the next report; dropped in sweep.
            r.active_since.store(0, Ordering::Relaxed);
        }
        Some(e)
    }
}

/// Pair reachability with the infrastructure exception (§14.4).
pub fn may_talk(n: &Node, a: &Bytes32, b: &Bytes32) -> bool {
    let s = n.store.read();
    let v = s.view();
    if v.is_controller(a) || v.is_controller(b) {
        return true;
    }
    let (Some(na), Some(nb)) = (v.nodes.get(a), v.nodes.get(b)) else {
        return false;
    };
    webjet_core::policy::pair_may_talk(
        &v.policy,
        &v.subject(na),
        &v.subject(nb),
        &v.granted_prefixes(a),
        &v.granted_prefixes(b),
    )
}

fn limit(n: &Node, name: &str, builtin: u64) -> u64 {
    crate::metrics::limit(n, name, builtin)
}

// ---------------------------------------------------------------- opening (source)

/// Open a circuit to `peer` through `hops` (empty = direct).
pub async fn open(n: &Arc<Node>, peer: Bytes32, hops: Vec<Bytes32>) -> Result<Arc<LocalCircuit>> {
    let next = hops.first().copied().unwrap_or(peer);
    // Make sure we have a hop session to the first neighbor.
    if n.best_hop(&next).is_none() {
        n.dial_node(next).await?;
    }
    let route_id = crypto::route_id(&n.me, &peer, &hops);
    let setup = wp::CircuitSetup {
        route_id: Some(crypto::k32(&route_id)),
        src: Some(crypto::k32(&n.me)),
        dst: Some(crypto::k32(&peer)),
        hops: Some(hops.iter().map(crypto::k32).collect()),
        nonce: Some(wp::Id16::from_bytes(&crypto::random16())),
        issued_at: now_ms(),
    };
    let raw = n.kp.sign_obj(mt::CIRCUIT_SETUP, &setup);
    let (tx, rx) = oneshot::channel();
    let c = {
        let mut t = n.circuits.lock();
        let label = t.alloc(&next);
        let c = Arc::new(LocalCircuit {
            peer,
            label,
            next,
            out_label: Mutex::new(None),
            hops: hops.clone(),
            route_id,
            is_source: true,
            created: Instant::now(),
            probes: Mutex::new(LinkStats::default()),
            e2e_rtt_ms: Mutex::new(None),
            last_rx: Mutex::new(Instant::now()),
        });
        t.route(&route_id, &n.me, &peer, &hops);
        t.entries.insert(
            (next, label),
            Entry {
                kind: Kind::Local(c.clone()),
                created: Instant::now(),
            },
        );
        t.pending.insert(
            (next, label),
            PendingOpen {
                prev: None,
                waiter: Some(tx),
                at: Instant::now(),
            },
        );
        c
    };
    let hop = n
        .best_hop(&next)
        .ok_or_else(|| anyhow!("hop to the first neighbor went away"))?;
    hop.send_control(HopMsg::CircuitOpen(Box::new(wp::CircuitOpen {
        setup: Some(raw),
        label: c.label,
    })));
    let res = tokio::time::timeout(OPEN_TIMEOUT, rx).await;
    let out = match res {
        Ok(Ok(Ok(out))) => out,
        Ok(Ok(Err(reason))) => {
            n.circuits.lock().remove_entry(&(next, c.label));
            bail!("circuit refused: {reason}");
        }
        _ => {
            let mut t = n.circuits.lock();
            t.pending.remove(&(next, c.label));
            t.remove_entry(&(next, c.label));
            bail!("circuit setup timed out");
        }
    };
    *c.out_label.lock() = Some(out);
    tracing::debug!(peer = %n.name_of(&peer), hops = hops.len(), "circuit open");
    Ok(c)
}

// ---------------------------------------------------------------- control messages

pub async fn on_open(n: &Arc<Node>, hop: &Arc<Hop>, o: wp::CircuitOpen) -> Result<()> {
    let from = hop.peer;
    let refuse = |why: &str| {
        hop.send_control(HopMsg::CircuitRefuse(Box::new(wp::CircuitRefuse {
            label: o.label,
            reason: Some(why.to_string()),
        })));
    };
    let raw = o.setup.clone().unwrap_or_default();
    let v = match crypto::open_envelope(&raw) {
        Ok(v) if v.ty == mt::CIRCUIT_SETUP => v,
        _ => {
            refuse("bad setup");
            bail!("bad circuit setup");
        }
    };
    let s: wp::CircuitSetup = v.decode()?;
    let src = opt_k32(&s.src);
    let dst = opt_k32(&s.dst);
    let hops: Vec<Bytes32> = s
        .hops
        .clone()
        .unwrap_or_default()
        .iter()
        .map(|k| k.to_bytes())
        .collect();
    let nonce = s.nonce.map(|x| x.to_bytes()).unwrap_or_default();
    // Signature by the source's current key; source and destination trusted.
    let check = || -> std::result::Result<(), &'static str> {
        let st = n.store.read();
        let vw = st.view();
        if !st.node_trusted(&src) || vw.nodes.get(&src).map(|x| x.key) != Some(v.signer) {
            return Err("source");
        }
        if !st.node_trusted(&dst) {
            return Err("destination");
        }
        if crypto::route_id(&src, &dst, &hops) != opt_k32(&s.route_id) {
            return Err("route_id");
        }
        if s.issued_at.abs_diff(now_ms()) > SKEW_SHORT_RECORD {
            return Err("stale");
        }
        if hops.len() > DEFAULT_HOP_LIMIT as usize {
            return Err("too_long");
        }
        Ok(())
    };
    if let Err(why) = check() {
        n.circuits.lock().refuse(why);
        refuse(why);
        bail!("circuit refused: {why}");
    }
    {
        let mut t = n.circuits.lock();
        let now = Instant::now();
        t.nonces
            .retain(|_, at| now.duration_since(*at) < Duration::from_secs(300));
        if t.nonces.insert(nonce, now).is_some() {
            t.refuse("replay");
            drop(t);
            refuse("replay");
            bail!("replayed circuit setup");
        }
    }
    if dst == n.me {
        return accept_as_destination(n, hop, &o, src, hops, opt_k32(&s.route_id));
    }
    // Relay checks (§11.5).
    let Some(pos) = hops.iter().position(|h| *h == n.me) else {
        n.circuits.lock().refuse("not_on_path");
        refuse("not on path");
        bail!("circuit setup doesn't list us");
    };
    let prev = if pos == 0 { src } else { hops[pos - 1] };
    let next = hops.get(pos + 1).copied().unwrap_or(dst);
    let fail = |why: &str| -> Result<()> {
        n.circuits.lock().refuse(why);
        refuse(why);
        bail!("circuit refused: {why}")
    };
    if prev != from {
        return fail("wrong_neighbor");
    }
    if !n.is_relay() {
        return fail("not_relay");
    }
    {
        let st = n.store.read();
        let vw = st.view();
        let next_ok = if next == dst {
            st.node_trusted(&next)
        } else {
            vw.nodes
                .get(&next)
                .map(|x| x.valid && x.relay)
                .unwrap_or(false)
        };
        if !next_ok {
            drop(st);
            return fail("next_hop");
        }
    }
    {
        let per_src = limit(n, "circuits_per_source", 256) as usize;
        let global = limit(n, "circuits_global", 50_000) as usize;
        let rate = limit(n, "circuit_setups_per_sec", 200) as u32;
        let mut t = n.circuits.lock();
        let now = Instant::now();
        if t.setup_rate
            .0
            .map(|x| now.duration_since(x) >= Duration::from_secs(1))
            .unwrap_or(true)
        {
            t.setup_rate = (Some(now), 0);
        }
        t.setup_rate.1 += 1;
        let count_src = t
            .entries
            .values()
            .filter(|e| matches!(&e.kind, Kind::Transit(x) if x.forward && x.src == src))
            .count();
        let why = if t.setup_rate.1 > rate {
            Some("rate")
        } else if count_src >= per_src {
            Some("per_source")
        } else if t.transit_count() >= global {
            Some("global")
        } else {
            None
        };
        if let Some(w) = why {
            drop(t);
            return fail(w);
        }
    }
    if !may_talk(n, &src, &dst) {
        return fail("policy");
    }
    // Reach the next hop.
    if n.best_hop(&next).is_none()
        && let Err(e) = n.dial_node(next).await
    {
        tracing::debug!("circuit next hop {}: {e}", n.name_of(&next));
        return fail("next_unreachable");
    }
    let Some(next_hop) = n.best_hop(&next) else {
        return fail("next_unreachable");
    };
    let rid = opt_k32(&s.route_id);
    let out_back = {
        let mut t = n.circuits.lock();
        let in_label = t.alloc(&from);
        let back_label = t.alloc(&next);
        t.route(&rid, &src, &dst, &hops);
        let now = Instant::now();
        // Forward: frames from `from` with in_label go to next (label unknown yet).
        t.entries.insert(
            (from, in_label),
            Entry {
                kind: Kind::Transit(Transit {
                    out_neighbor: next,
                    out_label: None,
                    route_id: rid,
                    src,
                    forward: true,
                    pair: (next, back_label),
                    last: now,
                }),
                created: now,
            },
        );
        // Reverse: frames from next with back_label go to `from` with the opener's label.
        t.entries.insert(
            (next, back_label),
            Entry {
                kind: Kind::Transit(Transit {
                    out_neighbor: from,
                    out_label: Some(o.label),
                    route_id: rid,
                    src,
                    forward: false,
                    pair: (from, in_label),
                    last: now,
                }),
                created: now,
            },
        );
        t.pending.insert(
            (next, back_label),
            PendingOpen {
                prev: Some((from, o.label, in_label)),
                waiter: None,
                at: now,
            },
        );
        back_label
    };
    next_hop.send_control(HopMsg::CircuitOpen(Box::new(wp::CircuitOpen {
        setup: Some(raw),
        label: out_back,
    })));
    Ok(())
}

fn accept_as_destination(
    n: &Arc<Node>,
    hop: &Arc<Hop>,
    o: &wp::CircuitOpen,
    src: Bytes32,
    hops: Vec<Bytes32>,
    rid: Bytes32,
) -> Result<()> {
    let from = hop.peer;
    let expected_prev = hops.last().copied().unwrap_or(src);
    if expected_prev != from {
        hop.send_control(HopMsg::CircuitRefuse(Box::new(wp::CircuitRefuse {
            label: o.label,
            reason: Some("wrong neighbor".into()),
        })));
        bail!("circuit setup from an unexpected neighbor");
    }
    if !may_talk(n, &n.me, &src) {
        n.circuits.lock().refuse("policy");
        hop.send_control(HopMsg::CircuitRefuse(Box::new(wp::CircuitRefuse {
            label: o.label,
            reason: Some("policy".into()),
        })));
        bail!("policy allows nothing with the circuit's source");
    }
    let label = {
        let mut t = n.circuits.lock();
        let label = t.alloc(&from);
        let c = Arc::new(LocalCircuit {
            peer: src,
            label,
            next: from,
            out_label: Mutex::new(Some(o.label)),
            hops,
            route_id: rid,
            is_source: false,
            created: Instant::now(),
            probes: Mutex::new(LinkStats::default()),
            e2e_rtt_ms: Mutex::new(None),
            last_rx: Mutex::new(Instant::now()),
        });
        t.route(&rid, &src, &n.me, &c.hops);
        t.entries.insert(
            (from, label),
            Entry {
                kind: Kind::Local(c),
                created: Instant::now(),
            },
        );
        label
    };
    hop.send_control(HopMsg::CircuitAccept(Box::new(wp::CircuitAccept {
        label: o.label,
        peer_label: label,
    })));
    Ok(())
}

pub fn on_accept(n: &Arc<Node>, hop: &Arc<Hop>, a: wp::CircuitAccept) {
    let from = hop.peer;
    let mut t = n.circuits.lock();
    let Some(p) = t.pending.remove(&(from, a.label)) else {
        return;
    };
    match p.prev {
        None => {
            if let Some(w) = p.waiter {
                let _ = w.send(Ok(a.peer_label));
            }
        }
        Some((prev, prev_label, in_label)) => {
            if let Some(Entry {
                kind: Kind::Transit(tr),
                ..
            }) = t.entries.get_mut(&(prev, in_label))
            {
                tr.out_label = Some(a.peer_label);
            } else {
                return;
            }
            drop(t);
            if let Some(h) = n.best_hop(&prev) {
                h.send_control(HopMsg::CircuitAccept(Box::new(wp::CircuitAccept {
                    label: prev_label,
                    peer_label: in_label,
                })));
            }
        }
    }
}

pub fn on_refuse(n: &Arc<Node>, hop: &Arc<Hop>, r: wp::CircuitRefuse) {
    let from = hop.peer;
    let mut t = n.circuits.lock();
    let Some(p) = t.pending.remove(&(from, r.label)) else {
        return;
    };
    let reason = r.reason.clone().unwrap_or_default();
    match p.prev {
        None => {
            if let Some(w) = p.waiter {
                let _ = w.send(Err(reason));
            }
        }
        Some((prev, prev_label, in_label)) => {
            t.remove_entry(&(prev, in_label));
            t.remove_entry(&(from, r.label));
            drop(t);
            if let Some(h) = n.best_hop(&prev) {
                h.send_control(HopMsg::CircuitRefuse(Box::new(wp::CircuitRefuse {
                    label: prev_label,
                    reason: Some(reason),
                })));
            }
        }
    }
}

/// The neighbor closed the circuit whose label (allocated by us) is `label`.
pub fn on_close(n: &Arc<Node>, hop: &Arc<Hop>, label: u32) {
    close_key(n, (hop.peer, label), true);
}

/// Remove an entry and its pair, telling the neighbor on the other side.
fn close_key(n: &Arc<Node>, key: (Bytes32, u32), propagate: bool) {
    let mut t = n.circuits.lock();
    let Some(e) = t.remove_entry(&key) else {
        return;
    };
    match e.kind {
        Kind::Local(c) => {
            drop(t);
            n.e2e.on_circuit_closed(&c);
        }
        Kind::Transit(tr) => {
            t.remove_entry(&tr.pair);
            t.pending.remove(&tr.pair);
            drop(t);
            if propagate {
                // Tell the neighbor on the other side, using its label.
                if let (Some(out), Some(h)) = (tr.out_label, n.best_hop(&tr.out_neighbor)) {
                    h.send_control(HopMsg::CircuitClose(Box::new(wp::CircuitClose {
                        label: out,
                    })));
                }
            }
        }
    }
}

/// Close one of our circuits.
pub fn close_local(n: &Arc<Node>, c: &Arc<LocalCircuit>) {
    let out = *c.out_label.lock();
    n.circuits.lock().remove_entry(&(c.next, c.label));
    n.e2e.on_circuit_closed(c);
    if let (Some(out), Some(h)) = (out, n.best_hop(&c.next)) {
        h.send_control(HopMsg::CircuitClose(Box::new(wp::CircuitClose {
            label: out,
        })));
    }
}

pub fn on_hop_down(n: &Arc<Node>, hop: &Hop) {
    if n.hops_to(&hop.peer).iter().any(|h| h.id != hop.id) {
        return; // another session to the same neighbor carries the circuits
    }
    let keys: Vec<(Bytes32, u32)> = n
        .circuits
        .lock()
        .entries
        .keys()
        .filter(|k| k.0 == hop.peer)
        .copied()
        .collect();
    for k in keys {
        close_key(n, k, true);
    }
    let mut t = n.circuits.lock();
    let dead: Vec<(Bytes32, u32)> = t
        .pending
        .keys()
        .filter(|k| k.0 == hop.peer)
        .copied()
        .collect();
    for k in dead {
        if let Some(p) = t.pending.remove(&k)
            && let Some(w) = p.waiter
        {
            let _ = w.send(Err("hop down".into()));
        }
    }
}

// ---------------------------------------------------------------- frames

pub fn on_relay_frame(n: &Arc<Node>, hop: &Arc<Hop>, payload: Vec<u8>) {
    let Some((label, hop_limit, ecn, body)) = frames::parse_relay(&payload) else {
        return;
    };
    let key = (hop.peer, label);
    let action = {
        let mut t = n.circuits.lock();
        let found = match t.entries.get_mut(&key) {
            None => return,
            Some(Entry {
                kind: Kind::Local(c),
                ..
            }) => Ok(c.clone()),
            Some(Entry {
                kind: Kind::Transit(tr),
                ..
            }) => {
                tr.last = Instant::now();
                Err((tr.out_neighbor, tr.out_label, tr.forward, tr.route_id))
            }
        };
        match found {
            Ok(c) => Ok(c),
            Err((on, ol, fw, rid)) => Err((on, ol, fw, t.routes.get(&rid).cloned())),
        }
    };
    match action {
        Ok(c) => {
            *c.last_rx.lock() = Instant::now();
            if let Some(r) = n.circuits.lock().routes.get(&c.route_id) {
                r.rev.add(body.len());
            }
            if ecn == frames::ecn::CE
                && let Some(r) = n.circuits.lock().routes.get(&c.route_id)
            {
                r.ecn_marked.fetch_add(1, Ordering::Relaxed);
            }
            crate::e2e::on_frame(n, &c, body, ecn);
        }
        Err((out_n, out_l, forward, route)) => {
            let Some(out_l) = out_l else { return };
            if hop_limit == 0 {
                if let Some(r) = &route {
                    r.dropped_hop_limit.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
            if let Some(r) = &route {
                if forward {
                    r.fwd.add(body.len());
                } else {
                    r.rev.add(body.len());
                }
            }
            let Some(h) = n.best_hop(&out_n) else {
                if let Some(r) = &route {
                    r.dropped_queue.fetch_add(1, Ordering::Relaxed);
                }
                return;
            };
            let mut f = Vec::with_capacity(payload.len());
            f.extend_from_slice(&frames::relay_header(out_l, hop_limit - 1, ecn));
            f.extend_from_slice(body);
            let flow = route
                .as_ref()
                .map(|r| webjet_core::bytes::prefix_u64(&r.src))
                .unwrap_or(label as u64);
            if !h.send_relay(flow, f)
                && let Some(r) = &route
            {
                r.dropped_queue.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ---------------------------------------------------------------- housekeeping

/// Drop stale pending setups, idle transit entries and idle destination-side
/// circuits; re-check admission after tree changes.
pub fn sweep(n: &Arc<Node>) {
    let now = Instant::now();
    let mut stale: Vec<(Bytes32, u32)> = Vec::new();
    {
        let mut t = n.circuits.lock();
        let dead: Vec<(Bytes32, u32)> = t
            .pending
            .iter()
            .filter(|(_, p)| now.duration_since(p.at) > PENDING_TIMEOUT)
            .map(|(k, _)| *k)
            .collect();
        for k in dead {
            t.pending.remove(&k);
        }
        for (k, e) in &t.entries {
            match &e.kind {
                Kind::Transit(tr) if tr.forward && now.duration_since(tr.last) > TRANSIT_IDLE => {
                    stale.push(*k)
                }
                Kind::Transit(tr)
                    if tr.forward
                        && tr.out_label.is_none()
                        && now.duration_since(e.created) > PENDING_TIMEOUT =>
                {
                    stale.push(*k)
                }
                Kind::Local(c)
                    if !c.is_source && now.duration_since(*c.last_rx.lock()) > TRANSIT_IDLE =>
                {
                    stale.push(*k)
                }
                _ => {}
            }
        }
        t.routes.retain(|_, r| {
            r.circuits.load(Ordering::Relaxed) > 0 || r.active_since.load(Ordering::Relaxed) != 0
        });
    }
    // Revoked sources or destinations lose their circuits (§10.5).
    let untrusted: HashSet<Bytes32> = {
        let st = n.store.read();
        let t = n.circuits.lock();
        t.routes
            .values()
            .flat_map(|r| [r.src, r.dst])
            .filter(|x| *x != n.me && !st.node_trusted(x))
            .collect()
    };
    if !untrusted.is_empty() {
        let t = n.circuits.lock();
        for (k, e) in &t.entries {
            let hit = match &e.kind {
                Kind::Transit(tr) => {
                    tr.forward
                        && t.routes
                            .get(&tr.route_id)
                            .map(|r| untrusted.contains(&r.src) || untrusted.contains(&r.dst))
                            .unwrap_or(false)
                }
                Kind::Local(c) => untrusted.contains(&c.peer),
            };
            if hit {
                stale.push(*k);
            }
        }
    }
    stale.sort();
    stale.dedup();
    for k in stale {
        close_key(n, k, true);
    }
}

pub fn summary(n: &Node) -> serde_json::Value {
    let t = n.circuits.lock();
    let locals: Vec<serde_json::Value> = t
        .entries
        .values()
        .filter_map(|e| match &e.kind {
            Kind::Local(c) => Some(serde_json::json!({
                "peer": n.name_of(&c.peer),
                "hops": c.hops.iter().map(|h| n.name_of(h)).collect::<Vec<_>>(),
                "source": c.is_source,
                "open": c.out_label.lock().is_some(),
                "rtt_ms": c.probes.lock().srtt_ms,
                "loss": c.probes.lock().loss,
                "age_s": c.created.elapsed().as_secs(),
            })),
            _ => None,
        })
        .collect();
    serde_json::json!({ "local": locals, "transit": t.transit_count(), "refused": t.refused })
}
