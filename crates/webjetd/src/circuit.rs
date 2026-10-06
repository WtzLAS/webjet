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
    /// The route's counters (the table's entry for `route_id`), held here so
    /// sending and receiving needn't take the circuit lock per frame.
    pub acct: Arc<RouteAcct>,
    pub is_source: bool,
    pub created: Instant,
    /// End-to-end probes (§11.4): sent only while the circuit carries
    /// little traffic, so they measure the path and not the backlog in
    /// front of it. They show the circuit is alive, and give the cost
    /// until the path's links are known.
    pub probes: Mutex<LinkStats>,
    pub e2e_rtt_ms: Mutex<Option<f64>>,
    pub last_rx: Mutex<Instant>,
    pub live: Live,
}

/// A circuit's traffic and its path cost from link measurements.
#[derive(Default)]
pub struct Live {
    /// Session frames sent and received (not probes).
    pub tx: AtomicU64,
    pub rx: AtomicU64,
    /// The counts at the last [`LocalCircuit::busy`].
    seen: Mutex<(u64, u64)>,
    /// The path's cost composed from its links (§11.4); `None` while a link
    /// isn't known. Refreshed every second by the path loop.
    pub path_cost: Mutex<Option<f64>>,
    /// The first probe sent since the last frame received.
    pub(crate) probe_pending: Mutex<Option<Instant>>,
}

/// Frames each way per probe interval that make a circuit busy enough to
/// skip its probe: the traffic itself shows it works.
pub const BUSY_FRAMES: u64 = 3;
/// A probe unanswered this long, with nothing else received meanwhile,
/// makes a circuit unusable until it answers again.
const UNANSWERED: Duration = Duration::from_secs(3);

impl LocalCircuit {
    pub fn direct(&self) -> bool {
        self.hops.is_empty()
    }

    /// The circuit's cost (§11.4): the sum of its links' measured costs
    /// (the first hop live, the rest as advertised), which a busy circuit's
    /// own traffic can't distort. Until those are known, the probes' cost;
    /// infinite while the circuit doesn't answer.
    pub fn cost(&self) -> f64 {
        if self.unanswered() {
            return f64::INFINITY;
        }
        if let Some(c) = *self.live.path_cost.lock() {
            return c;
        }
        let p = self.probes.lock();
        if p.samples == 0 {
            f64::INFINITY
        } else {
            p.cost()
        }
    }

    /// A probe has waited [`UNANSWERED`] and nothing came back since.
    fn unanswered(&self) -> bool {
        self.live
            .probe_pending
            .lock()
            .is_some_and(|at| at.elapsed() >= UNANSWERED)
    }

    /// A probe went out.
    pub fn on_probe_sent(&self) {
        self.live
            .probe_pending
            .lock()
            .get_or_insert_with(Instant::now);
    }

    /// A frame came in on this circuit.
    pub fn on_received(&self) {
        let now = Instant::now();
        *self.last_rx.lock() = now;
        *self.live.probe_pending.lock() = None;
    }

    /// Whether the circuit carried at least [`BUSY_FRAMES`] session frames
    /// each way since the last call (made once per probe interval).
    pub fn busy(&self) -> bool {
        let (tx, rx) = (
            self.live.tx.load(Ordering::Relaxed),
            self.live.rx.load(Ordering::Relaxed),
        );
        let mut seen = self.live.seen.lock();
        let busy =
            tx.saturating_sub(seen.0) >= BUSY_FRAMES && rx.saturating_sub(seen.1) >= BUSY_FRAMES;
        *seen = (tx, rx);
        busy
    }

    /// Whether the cost reflects measurements (to compare and drop circuits).
    pub fn measured(&self, min_probes: u64) -> bool {
        self.probes.lock().samples >= min_probes
            || (self.live.path_cost.lock().is_some()
                && self.created.elapsed() >= Duration::from_secs(5)
                && self.last_rx.lock().elapsed() < UNANSWERED)
    }

    /// The relays from this end to the other, in order.
    pub fn relays_from_me(&self) -> Vec<Bytes32> {
        let mut h = self.hops.clone();
        if !self.is_source {
            h.reverse();
        }
        h
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
        self.acct.fwd.add(frame.len());
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
    /// Circuit setups per source node in the current second.
    setup_rate: HashMap<Bytes32, (Instant, u32)>,
    /// Circuits ending here, by end-to-end peer (an index into `entries`).
    by_peer: HashMap<Bytes32, Vec<Arc<LocalCircuit>>>,
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

    /// Open circuits to `peer` (per packet: an index lookup, not a scan).
    pub fn local_circuits(&self, peer: &Bytes32) -> Vec<Arc<LocalCircuit>> {
        self.by_peer
            .get(peer)
            .into_iter()
            .flatten()
            .filter(|c| c.out_label.lock().is_some())
            .cloned()
            .collect()
    }

    /// Add a circuit ending here under `(c.next, c.label)`.
    fn insert_local(&mut self, c: Arc<LocalCircuit>) {
        self.by_peer.entry(c.peer).or_default().push(c.clone());
        self.entries.insert(
            (c.next, c.label),
            Entry {
                kind: Kind::Local(c),
                created: Instant::now(),
            },
        );
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
        if let Kind::Local(c) = &e.kind
            && let Some(v) = self.by_peer.get_mut(&c.peer)
        {
            v.retain(|x| !Arc::ptr_eq(x, c));
            if v.is_empty() {
                self.by_peer.remove(&c.peer);
            }
        }
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

fn limit(n: &Node, name: &str) -> u64 {
    crate::metrics::limit(n, name)
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
        let acct = t.route(&route_id, &n.me, &peer, &hops);
        let c = Arc::new(LocalCircuit {
            peer,
            label,
            next,
            out_label: Mutex::new(None),
            hops: hops.clone(),
            route_id,
            acct,
            is_source: true,
            created: Instant::now(),
            probes: Mutex::new(LinkStats::default()),
            e2e_rtt_ms: Mutex::new(None),
            last_rx: Mutex::new(Instant::now()),
            live: Default::default(),
        });
        t.insert_local(c.clone());
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

/// Count a circuit setup from `src` and check it against the limits
/// (§16.2): setups per second and circuits per source node, plus, for
/// transit circuits, the global count. Circuits that end here count too, or
/// any trusted peer could open them without bound.
fn admit(n: &Arc<Node>, src: &Bytes32, to_me: bool) -> Option<&'static str> {
    let per_src = limit(n, "circuits_per_source") as usize;
    let global = limit(n, "circuits_global") as usize;
    let rate = limit(n, "circuit_setups_per_sec") as u32;
    let mut t = n.circuits.lock();
    let now = Instant::now();
    t.setup_rate
        .retain(|_, (at, _)| now.duration_since(*at) < Duration::from_secs(1));
    let r = t.setup_rate.entry(*src).or_insert((now, 0));
    r.1 += 1;
    if r.1 > rate {
        return Some("rate");
    }
    let count_src = t
        .entries
        .values()
        .filter(|e| match &e.kind {
            Kind::Transit(x) => !to_me && x.forward && x.src == *src,
            Kind::Local(c) => to_me && !c.is_source && c.peer == *src,
        })
        .count();
    if count_src >= per_src {
        Some("per_source")
    } else if !to_me && t.transit_count() >= global {
        Some("global")
    } else {
        None
    }
}

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
            vw.nodes.get(&next).is_some_and(|x| x.valid && x.relay)
        };
        if !next_ok {
            drop(st);
            return fail("next_hop");
        }
    }
    if let Some(w) = admit(n, &src, false) {
        return fail(w);
    }
    if !may_talk(n, &src, &dst) {
        return fail("policy");
    }
    let ext = Extend {
        from,
        next,
        src,
        dst,
        hops,
        rid: opt_k32(&s.route_id),
        label: o.label,
        raw,
    };
    // Dialing the next hop takes up to HANDSHAKE_TIMEOUT per address and
    // transport. This runs inside the previous hop's reader loop, so dial in
    // a task of its own: waiting here would stall every other circuit on that
    // link, and its keepalives, meanwhile.
    if n.best_hop(&next).is_some() {
        return extend(n, hop, ext).await;
    }
    let (n, hop) = (n.clone(), hop.clone());
    tokio::spawn(async move {
        if let Err(e) = extend(&n, &hop, ext).await {
            tracing::debug!(peer = %n.name_of(&hop.peer), "circuit open: {e}");
        }
    });
    Ok(())
}

/// An admitted transit circuit, waiting for its next hop.
struct Extend {
    from: Bytes32,
    next: Bytes32,
    src: Bytes32,
    dst: Bytes32,
    hops: Vec<Bytes32>,
    rid: Bytes32,
    /// The previous hop's label for the circuit.
    label: u32,
    raw: Vec<u8>,
}

/// Reach the next hop (dialing it if needed), install the transit entries
/// and pass the setup on.
async fn extend(n: &Arc<Node>, hop: &Arc<Hop>, x: Extend) -> Result<()> {
    let Extend {
        from,
        next,
        src,
        dst,
        hops,
        rid,
        label,
        raw,
    } = x;
    let fail = |why: &str| -> Result<()> {
        n.circuits.lock().refuse(why);
        hop.send_control(HopMsg::CircuitRefuse(Box::new(wp::CircuitRefuse {
            label,
            reason: Some(why.to_string()),
        })));
        bail!("circuit refused: {why}")
    };
    if n.best_hop(&next).is_none()
        && let Err(e) = n.dial_node(next).await
    {
        tracing::debug!("circuit next hop {}: {e}", n.name_of(&next));
        return fail("next_unreachable");
    }
    let Some(next_hop) = n.best_hop(&next) else {
        return fail("next_unreachable");
    };
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
                    out_label: Some(label),
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
                prev: Some((from, label, in_label)),
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
    if let Some(why) = admit(n, &src, true) {
        n.circuits.lock().refuse(why);
        hop.send_control(HopMsg::CircuitRefuse(Box::new(wp::CircuitRefuse {
            label: o.label,
            reason: Some(why.into()),
        })));
        bail!("circuit refused: {why}");
    }
    let label = {
        let mut t = n.circuits.lock();
        let label = t.alloc(&from);
        let acct = t.route(&rid, &src, &n.me, &hops);
        t.insert_local(Arc::new(LocalCircuit {
            peer: src,
            label,
            next: from,
            out_label: Mutex::new(Some(o.label)),
            hops,
            route_id: rid,
            acct,
            is_source: false,
            created: Instant::now(),
            probes: Mutex::new(LinkStats::default()),
            e2e_rtt_ms: Mutex::new(None),
            last_rx: Mutex::new(Instant::now()),
            live: Default::default(),
        }));
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
            c.on_received();
            c.acct.rev.add(body.len());
            if ecn == frames::ecn::CE {
                c.acct.ecn_marked.fetch_add(1, Ordering::Relaxed);
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
            // Same size header: rewrite it in place and pass the frame on.
            let mut f = payload;
            f[..frames::RELAY_HEADER].copy_from_slice(&frames::relay_header(
                out_l,
                hop_limit - 1,
                ecn,
            ));
            let flow = route
                .as_ref()
                .map_or(label as u64, |r| webjet_core::bytes::prefix_u64(&r.src));
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
                        && t.routes.get(&tr.route_id).is_some_and(|r| {
                            untrusted.contains(&r.src) || untrusted.contains(&r.dst)
                        })
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

/// One circuit ending here, copied out of the table so names can be looked
/// up without holding the circuit lock.
struct LocalSummary {
    peer: Bytes32,
    label: u32,
    next: Bytes32,
    hops: Vec<Bytes32>,
    source: bool,
    open: bool,
    rtt_ms: f64,
    loss: f64,
    samples: u64,
    /// What path selection compares (§11.4); `None` when infinite.
    cost: Option<f64>,
    age_s: u64,
    route_id: Bytes32,
}

/// Circuits ending at this node and routes this node carries, for the
/// control channel (`sessions`, `webjetctl local sessions`, the app).
pub fn summary(n: &Node) -> serde_json::Value {
    let (locals, routes, transit, refused) = {
        let t = n.circuits.lock();
        let locals: Vec<LocalSummary> = t
            .entries
            .values()
            .filter_map(|e| match &e.kind {
                Kind::Local(c) => {
                    let cost = Some(c.cost()).filter(|x| x.is_finite());
                    let p = c.probes.lock();
                    Some(LocalSummary {
                        peer: c.peer,
                        label: c.label,
                        next: c.next,
                        hops: c.hops.clone(),
                        source: c.is_source,
                        open: c.out_label.lock().is_some(),
                        rtt_ms: p.srtt_ms,
                        loss: p.loss,
                        samples: p.samples,
                        cost,
                        age_s: c.created.elapsed().as_secs(),
                        route_id: c.route_id,
                    })
                }
                Kind::Transit(_) => None,
            })
            .collect();
        let routes: Vec<(Bytes32, Arc<RouteAcct>)> =
            t.routes.iter().map(|(k, r)| (*k, r.clone())).collect();
        (locals, routes, t.transit_count(), t.refused.clone())
    };
    // Which circuit each end-to-end session sends on.
    let primary: HashMap<Bytes32, u32> = n
        .e2e
        .all()
        .iter()
        .filter_map(|s| s.primary().map(|l| (s.peer, l)))
        .collect();
    let locals: Vec<serde_json::Value> = locals
        .iter()
        .map(|c| {
            serde_json::json!({
                "peer": n.name_of(&c.peer),
                "peer_id": hex::encode(c.peer),
                "label": c.label,
                "next": n.name_of(&c.next),
                "hops": c.hops.iter().map(|h| n.name_of(h)).collect::<Vec<_>>(),
                "hop_ids": c.hops.iter().map(hex::encode).collect::<Vec<_>>(),
                "direct": c.hops.is_empty(),
                "source": c.source,
                "open": c.open,
                "primary": primary.get(&c.peer) == Some(&c.label),
                "rtt_ms": c.rtt_ms,
                "loss": c.loss,
                "probes": c.samples,
                "cost": c.cost,
                "age_s": c.age_s,
                "route_id": hex::encode(&c.route_id[..8]),
            })
        })
        .collect();
    let routes: Vec<serde_json::Value> = routes
        .iter()
        .map(|(id, r)| {
            let role = if r.src == n.me {
                "source"
            } else if r.dst == n.me {
                "destination"
            } else {
                "transit"
            };
            let ld = |a: &AtomicU64| a.load(Ordering::Relaxed);
            serde_json::json!({
                "route_id": hex::encode(&id[..8]),
                "role": role,
                "src": n.name_of(&r.src),
                "dst": n.name_of(&r.dst),
                "path": std::iter::once(&r.src).chain(r.hops.iter()).chain(std::iter::once(&r.dst)).map(|h| n.name_of(h)).collect::<Vec<_>>(),
                "path_ids": std::iter::once(&r.src).chain(r.hops.iter()).chain(std::iter::once(&r.dst)).map(hex::encode).collect::<Vec<_>>(),
                "fwd_bytes": ld(&r.fwd.bytes), "fwd_frames": ld(&r.fwd.frames),
                "rev_bytes": ld(&r.rev.bytes), "rev_frames": ld(&r.rev.frames),
                "dropped_queue": ld(&r.dropped_queue), "dropped_hop_limit": ld(&r.dropped_hop_limit),
                "ecn_marked": ld(&r.ecn_marked), "setups": ld(&r.setups),
                "circuits": ld(&r.circuits), "active_since": ld(&r.active_since),
            })
        })
        .collect();
    serde_json::json!({ "local": locals, "routes": routes, "transit": transit, "refused": refused })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::TestHopRx;
    use crate::testnode::{self, Cluster};
    use webjet_core::crypto::KeyPair;
    use webjet_core::testutil::NodeSpec;
    use webjet_proto::Transport;

    struct Net {
        c: Cluster,
        s: (Bytes32, KeyPair),
        r: (Bytes32, KeyPair),
        d: (Bytes32, KeyPair),
    }

    fn allow_all() -> wp::Policy {
        wp::Policy {
            default_action: wp::Action::Deny,
            rules: Some(vec![wp::Rule {
                id: Some("all".into()),
                action: wp::Action::Allow,
                src: Some(vec!["*".into()]),
                dst: Some(vec!["*".into()]),
                ports: Some(vec!["*".into()]),
            }]),
            ..Default::default()
        }
    }

    /// Source `s`, relay `r`, destination `d`; everything allowed.
    fn net() -> Net {
        let mut c = Cluster::new();
        let s = c.data_node("src", "10.7.0.2", &[]);
        let r = c.enroll(NodeSpec {
            name: "relay",
            ip: "10.7.0.3",
            roles: &[wp::Role::Data, wp::Role::Relay],
            ..Default::default()
        });
        let d = c.data_node("dst", "10.7.0.4", &[]);
        c.set_policy(allow_all()).unwrap();
        Net { c, s, r, d }
    }

    fn setup(src: &(Bytes32, KeyPair), dst: &Bytes32, hops: &[Bytes32]) -> wp::CircuitSetup {
        wp::CircuitSetup {
            route_id: Some(crypto::k32(&crypto::route_id(&src.0, dst, hops))),
            src: Some(crypto::k32(&src.0)),
            dst: Some(crypto::k32(dst)),
            hops: Some(hops.iter().map(crypto::k32).collect()),
            nonce: Some(wp::Id16::from_bytes(&crypto::random16())),
            issued_at: now_ms(),
        }
    }

    fn open_msg(signer: &KeyPair, s: &wp::CircuitSetup, label: u32) -> wp::CircuitOpen {
        wp::CircuitOpen {
            setup: Some(signer.sign_obj(mt::CIRCUIT_SETUP, s)),
            label,
        }
    }

    fn only(mut v: Vec<HopMsg>) -> HopMsg {
        assert_eq!(v.len(), 1, "expected one control message");
        v.remove(0)
    }

    fn refused(rx: &mut TestHopRx) -> String {
        match only(rx.control()) {
            HopMsg::CircuitRefuse(r) => r.reason.unwrap_or_default(),
            _ => panic!("expected CircuitRefuse"),
        }
    }

    #[tokio::test]
    async fn relay_sets_up_forwards_and_closes() {
        let mut t = net();
        let (rn, _dir) = testnode::node(&mut t.c, t.r.0, t.r.1.clone());
        let (hs, mut rs) = rn.test_hop(t.s.0, Transport::TcpTls);
        let (hd, mut rd) = rn.test_hop(t.d.0, Transport::TcpTls);

        // The source opens with its label 11.
        let s = setup(&t.s, &t.d.0, &[t.r.0]);
        on_open(&rn, &hs, open_msg(&t.s.1, &s, 11)).await.unwrap();
        let HopMsg::CircuitOpen(fwd) = only(rd.control()) else {
            panic!("expected CircuitOpen to the destination");
        };
        let back = fwd.label;
        assert_eq!(
            fwd.setup,
            open_msg(&t.s.1, &s, 0).setup,
            "setup forwarded as signed"
        );
        assert!(rs.control().is_empty());
        assert_eq!(rn.circuits.lock().transit_count(), 1);

        // The destination accepts with its label 22.
        on_accept(
            &rn,
            &hd,
            wp::CircuitAccept {
                label: back,
                peer_label: 22,
            },
        );
        let HopMsg::CircuitAccept(acc) = only(rs.control()) else {
            panic!("expected CircuitAccept to the source");
        };
        assert_eq!(acc.label, 11);
        let in_label = acc.peer_label;

        // Forward: source → destination, label swapped, hop limit decremented.
        let frame = [
            frames::relay_header(in_label, 5, frames::ecn::ECT0).as_slice(),
            b"hi",
        ]
        .concat();
        on_relay_frame(&rn, &hs, frame);
        let out = rd.relay();
        assert_eq!(out.len(), 1);
        let (label, limit, ecn, body) = frames::parse_relay(&out[0]).unwrap();
        assert_eq!(
            (label, limit, ecn, body),
            (22, 4, frames::ecn::ECT0, &b"hi"[..])
        );

        // Reverse: destination → source with the source's label.
        let frame = [frames::relay_header(back, 5, 0).as_slice(), b"yo"].concat();
        on_relay_frame(&rn, &hd, frame);
        let out = rs.relay();
        assert_eq!(frames::parse_relay(&out[0]).unwrap().0, 11);

        // Hop limit 0 is dropped and counted.
        on_relay_frame(&rn, &hs, frames::relay_header(in_label, 0, 0).to_vec());
        assert!(rd.relay().is_empty());
        // Unknown labels are ignored.
        on_relay_frame(&rn, &hs, frames::relay_header(999, 5, 0).to_vec());
        assert!(rd.relay().is_empty());
        {
            let tb = rn.circuits.lock();
            let r = &tb.routes[&crypto::route_id(&t.s.0, &t.d.0, &[t.r.0])];
            assert_eq!(r.fwd.frames.load(Ordering::Relaxed), 1);
            assert_eq!(r.rev.frames.load(Ordering::Relaxed), 1);
            assert_eq!(r.dropped_hop_limit.load(Ordering::Relaxed), 1);
        }
        let sum = summary(&rn);
        assert_eq!(sum["transit"], 1);
        assert_eq!(sum["routes"][0]["role"], "transit");
        assert_eq!(sum["routes"][0]["src"], "src");

        // The source closes: the destination is told with its label; both
        // directions are gone.
        on_close(&rn, &hs, in_label);
        let HopMsg::CircuitClose(cl) = only(rd.control()) else {
            panic!("expected CircuitClose");
        };
        assert_eq!(cl.label, 22);
        assert!(rn.circuits.lock().entries.is_empty());
    }

    #[tokio::test]
    async fn relay_passes_a_refusal_back() {
        let mut t = net();
        let (rn, _dir) = testnode::node(&mut t.c, t.r.0, t.r.1.clone());
        let (hs, mut rs) = rn.test_hop(t.s.0, Transport::TcpTls);
        let (hd, mut rd) = rn.test_hop(t.d.0, Transport::TcpTls);
        let s = setup(&t.s, &t.d.0, &[t.r.0]);
        on_open(&rn, &hs, open_msg(&t.s.1, &s, 11)).await.unwrap();
        let HopMsg::CircuitOpen(fwd) = only(rd.control()) else {
            panic!()
        };
        on_refuse(
            &rn,
            &hd,
            wp::CircuitRefuse {
                label: fwd.label,
                reason: Some("policy".into()),
            },
        );
        let HopMsg::CircuitRefuse(r) = only(rs.control()) else {
            panic!()
        };
        assert_eq!((r.label, r.reason.as_deref()), (11, Some("policy")));
        assert!(rn.circuits.lock().entries.is_empty());
    }

    #[tokio::test]
    async fn hop_down_closes_the_other_side() {
        let mut t = net();
        let (rn, _dir) = testnode::node(&mut t.c, t.r.0, t.r.1.clone());
        let (hs, _rs) = rn.test_hop(t.s.0, Transport::TcpTls);
        let (hd, mut rd) = rn.test_hop(t.d.0, Transport::TcpTls);
        let s = setup(&t.s, &t.d.0, &[t.r.0]);
        on_open(&rn, &hs, open_msg(&t.s.1, &s, 11)).await.unwrap();
        let HopMsg::CircuitOpen(fwd) = only(rd.control()) else {
            panic!()
        };
        on_accept(
            &rn,
            &hd,
            wp::CircuitAccept {
                label: fwd.label,
                peer_label: 22,
            },
        );
        rn.hop_down(&hs);
        let HopMsg::CircuitClose(cl) = only(rd.control()) else {
            panic!("expected CircuitClose")
        };
        assert_eq!(cl.label, 22);
        assert!(rn.circuits.lock().entries.is_empty());
    }

    #[tokio::test]
    async fn relay_refusals() {
        let mut t = net();
        let other = t.c.data_node("other", "10.7.0.5", &[]);
        let (rn, _dir) = testnode::node(&mut t.c, t.r.0, t.r.1.clone());
        let (hs, mut rs) = rn.test_hop(t.s.0, Transport::TcpTls);
        let (ho, mut ro) = rn.test_hop(other.0, Transport::TcpTls);
        let (_hd, _rd) = rn.test_hop(t.d.0, Transport::TcpTls);
        let path = [t.r.0];

        // Signed by a key that isn't the source's.
        let s = setup(&t.s, &t.d.0, &path);
        assert!(on_open(&rn, &hs, open_msg(&other.1, &s, 1)).await.is_err());
        assert_eq!(refused(&mut rs), "source");
        // Not a CircuitSetup at all.
        let bogus = wp::CircuitOpen {
            setup: Some(b"junk".to_vec()),
            label: 1,
        };
        assert!(on_open(&rn, &hs, bogus).await.is_err());
        assert_eq!(refused(&mut rs), "bad setup");
        // Route id that doesn't match the path.
        let s = wp::CircuitSetup {
            route_id: Some(crypto::k32(&[1; 32])),
            ..setup(&t.s, &t.d.0, &path)
        };
        assert!(on_open(&rn, &hs, open_msg(&t.s.1, &s, 1)).await.is_err());
        assert_eq!(refused(&mut rs), "route_id");
        // Too old.
        let s = wp::CircuitSetup {
            issued_at: now_ms() - SKEW_SHORT_RECORD - 1000,
            ..setup(&t.s, &t.d.0, &path)
        };
        assert!(on_open(&rn, &hs, open_msg(&t.s.1, &s, 1)).await.is_err());
        assert_eq!(refused(&mut rs), "stale");
        // Unknown destination.
        let s = setup(&t.s, &[9; 32], &path);
        assert!(on_open(&rn, &hs, open_msg(&t.s.1, &s, 1)).await.is_err());
        assert_eq!(refused(&mut rs), "destination");
        // We're not on the path.
        let s = setup(&t.s, &t.d.0, &[other.0]);
        assert!(on_open(&rn, &hs, open_msg(&t.s.1, &s, 1)).await.is_err());
        assert_eq!(refused(&mut rs), "not on path");
        // Arrives from a neighbor that isn't before us on the path.
        let s = setup(&t.s, &t.d.0, &path);
        assert!(on_open(&rn, &ho, open_msg(&t.s.1, &s, 1)).await.is_err());
        assert_eq!(refused(&mut ro), "wrong_neighbor");
        // The next hop on the path must be a relay.
        let s = setup(&t.s, &t.d.0, &[t.r.0, other.0]);
        assert!(on_open(&rn, &hs, open_msg(&t.s.1, &s, 1)).await.is_err());
        assert_eq!(refused(&mut rs), "next_hop");
        // A replayed setup.
        let s = setup(&t.s, &t.d.0, &path);
        on_open(&rn, &hs, open_msg(&t.s.1, &s, 1)).await.unwrap();
        assert!(on_open(&rn, &hs, open_msg(&t.s.1, &s, 2)).await.is_err());
        assert_eq!(refused(&mut rs), "replay");

        let refused_counts = rn.circuits.lock().refused.clone();
        for why in [
            "source",
            "route_id",
            "stale",
            "destination",
            "not_on_path",
            "wrong_neighbor",
            "next_hop",
            "replay",
        ] {
            assert_eq!(
                refused_counts.get(why),
                Some(&1),
                "{why}: {refused_counts:?}"
            );
        }
    }

    #[tokio::test]
    async fn only_relays_relay() {
        let mut t = net();
        // The destination is asked to relay for a path that lists it.
        let (dn, _dir) = testnode::node(&mut t.c, t.d.0, t.d.1.clone());
        let (hs, mut rs) = dn.test_hop(t.s.0, Transport::TcpTls);
        let s = setup(&t.s, &t.r.0, &[t.d.0]);
        assert!(on_open(&dn, &hs, open_msg(&t.s.1, &s, 1)).await.is_err());
        assert_eq!(refused(&mut rs), "not_relay");
    }

    #[tokio::test]
    async fn relay_follows_the_policy() {
        let mut t = net();
        t.c.set_policy(wp::Policy {
            default_action: wp::Action::Deny,
            ..Default::default()
        })
        .unwrap();
        let (rn, _dir) = testnode::node(&mut t.c, t.r.0, t.r.1.clone());
        let (hs, mut rs) = rn.test_hop(t.s.0, Transport::TcpTls);
        let (_hd, _rd) = rn.test_hop(t.d.0, Transport::TcpTls);
        let s = setup(&t.s, &t.d.0, &[t.r.0]);
        assert!(on_open(&rn, &hs, open_msg(&t.s.1, &s, 1)).await.is_err());
        assert_eq!(refused(&mut rs), "policy");
    }

    #[tokio::test]
    async fn destination_accepts() {
        let mut t = net();
        let (dn, _dir) = testnode::node(&mut t.c, t.d.0, t.d.1.clone());
        let (hr, mut rr) = dn.test_hop(t.r.0, Transport::TcpTls);
        let s = setup(&t.s, &t.d.0, &[t.r.0]);
        on_open(&dn, &hr, open_msg(&t.s.1, &s, 33)).await.unwrap();
        let HopMsg::CircuitAccept(a) = only(rr.control()) else {
            panic!("expected CircuitAccept")
        };
        assert_eq!(a.label, 33);
        {
            let tb = dn.circuits.lock();
            let Some(Entry {
                kind: Kind::Local(c),
                ..
            }) = tb.entries.get(&(t.r.0, a.peer_label))
            else {
                panic!("no local circuit")
            };
            assert_eq!((c.peer, c.next, c.is_source), (t.s.0, t.r.0, false));
            assert_eq!(*c.out_label.lock(), Some(33));
            assert_eq!(tb.local_circuits(&t.s.0).len(), 1);
        }
        let sum = summary(&dn);
        assert_eq!(sum["local"][0]["peer"], "src");
        assert_eq!(sum["local"][0]["source"], false);
        assert_eq!(sum["routes"][0]["role"], "destination");

        // The same setup from a neighbor that isn't the last relay.
        let (hs, mut rs) = dn.test_hop(t.s.0, Transport::TcpTls);
        let s = setup(&t.s, &t.d.0, &[t.r.0]);
        assert!(on_open(&dn, &hs, open_msg(&t.s.1, &s, 34)).await.is_err());
        assert_eq!(refused(&mut rs), "wrong neighbor");
    }

    #[tokio::test]
    async fn destination_follows_the_policy() {
        let mut t = net();
        t.c.set_policy(wp::Policy {
            default_action: wp::Action::Deny,
            ..Default::default()
        })
        .unwrap();
        let (dn, _dir) = testnode::node(&mut t.c, t.d.0, t.d.1.clone());
        let (hs, mut rs) = dn.test_hop(t.s.0, Transport::TcpTls);
        let s = setup(&t.s, &t.d.0, &[]);
        assert!(on_open(&dn, &hs, open_msg(&t.s.1, &s, 1)).await.is_err());
        assert_eq!(refused(&mut rs), "policy");
        assert!(dn.circuits.lock().entries.is_empty());
    }

    #[tokio::test]
    async fn source_opens_through_a_relay() {
        let mut t = net();
        let (sn, _dir) = testnode::node(&mut t.c, t.s.0, t.s.1.clone());
        let (hr, mut rr) = sn.test_hop(t.r.0, Transport::TcpTls);
        let n2 = sn.clone();
        let (peer, relay) = (t.d.0, t.r.0);
        let opening = tokio::spawn(async move { open(&n2, peer, vec![relay]).await });
        // Wait for the CircuitOpen to the relay and answer it.
        let o = loop {
            if let Some(HopMsg::CircuitOpen(o)) = rr.control().pop() {
                break o;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        let v = crypto::open_envelope(o.setup.as_deref().unwrap()).unwrap();
        assert_eq!(v.signer, t.s.1.public());
        on_accept(
            &sn,
            &hr,
            wp::CircuitAccept {
                label: o.label,
                peer_label: 44,
            },
        );
        let c = opening.await.unwrap().unwrap();
        assert_eq!(*c.out_label.lock(), Some(44));
        assert!(c.is_source && !c.direct());
        assert_eq!(c.cost(), f64::INFINITY, "no probes yet");

        // Frames go out with the relay's label.
        assert!(c.send(&sn, b"data", 0));
        let out = rr.relay();
        let (label, limit, _, body) = frames::parse_relay(&out[0]).unwrap();
        assert_eq!((label, limit, body), (44, DEFAULT_HOP_LIMIT, &b"data"[..]));

        close_local(&sn, &c);
        let HopMsg::CircuitClose(cl) = only(rr.control()) else {
            panic!()
        };
        assert_eq!(cl.label, 44);
        assert!(sn.circuits.lock().entries.is_empty());
    }

    #[tokio::test]
    async fn source_open_refused() {
        let mut t = net();
        let (sn, _dir) = testnode::node(&mut t.c, t.s.0, t.s.1.clone());
        let (hr, mut rr) = sn.test_hop(t.r.0, Transport::TcpTls);
        let n2 = sn.clone();
        let (peer, relay) = (t.d.0, t.r.0);
        let opening = tokio::spawn(async move { open(&n2, peer, vec![relay]).await });
        let o = loop {
            if let Some(HopMsg::CircuitOpen(o)) = rr.control().pop() {
                break o;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        on_refuse(
            &sn,
            &hr,
            wp::CircuitRefuse {
                label: o.label,
                reason: Some("rate".into()),
            },
        );
        let Err(e) = opening.await.unwrap() else {
            panic!("refused circuit opened")
        };
        let e = e.to_string();
        assert!(e.contains("rate"), "{e}");
        assert!(sn.circuits.lock().entries.is_empty());
    }

    #[test]
    fn may_talk_follows_the_policy_with_the_controller_exception() {
        let mut t = net();
        let ctl = t.c.enroll(NodeSpec {
            name: "ctl",
            ip: "10.7.0.9",
            control: true,
            ..Default::default()
        });
        t.c.set_policy(wp::Policy {
            default_action: wp::Action::Deny,
            ..Default::default()
        })
        .unwrap();
        let (n, _dir) = testnode::node(&mut t.c, t.s.0, t.s.1.clone());
        assert!(!may_talk(&n, &t.s.0, &t.d.0));
        assert!(!may_talk(&n, &t.s.0, &[9; 32]), "unknown node");
        // Controllers are reachable whatever the policy says, once certified.
        let certified = n.store.read().view().is_controller(&ctl.0);
        assert_eq!(may_talk(&n, &t.s.0, &ctl.0), certified);
        t.c.set_policy(allow_all()).unwrap();
        testnode::sync(&mut t.c, &n);
        assert!(may_talk(&n, &t.s.0, &t.d.0));
    }
}
