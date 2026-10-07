//! End-to-end sessions (§9.4): one per peer, independent of circuits. The
//! handshake is TLS 1.3 run on in-memory buffers and carried in HANDSHAKE
//! frames; afterwards packets use the AEAD frames of §6.9 with keys exported
//! from the TLS session.

use crate::circuit::LocalCircuit;
use crate::node::Node;
use anyhow::{Result, anyhow, bail};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use webjet_core::crypto::{self, Bytes32};
use webjet_core::frames::{self, ReplayWindow, SessionKey, ftype};
use webjet_net::tls;

pub const REKEY_AFTER: Duration = Duration::from_secs(120);
pub const REJECT_AFTER: Duration = Duration::from_secs(180);
pub const OLD_KEY_GRACE: Duration = Duration::from_secs(10);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const HS_GIVE_UP: Duration = Duration::from_secs(30);
/// Largest probe echoed back (§11.4); an encoded `Probe` is 66 bytes.
const PROBE_ECHO_MAX: usize = 128;

struct SendKey {
    /// Shared so frames are sealed outside the session lock.
    key: Arc<SessionKey>,
    peer_kid: u32,
    counter: u64,
    created: Instant,
}

struct RecvKey {
    /// Shared so frames are opened outside the session lock.
    key: Arc<SessionKey>,
    window: ReplayWindow,
    created: Instant,
    retire_at: Option<Instant>,
}

struct Handshake {
    nonce: [u8; 16],
    initiator: bool,
    conn: rustls::Connection,
    my_kid: u32,
    my_flight: u16,
    peer_flight: u16,
    last_sent: Vec<u8>,
    sent_at: Instant,
    rto: Duration,
    started: Instant,
    /// The circuit the handshake runs on.
    circuit: u32,
    done: bool,
}

#[derive(Default)]
struct Inner {
    hs: Option<Handshake>,
    send: Option<SendKey>,
    recv: HashMap<u32, RecvKey>,
    queue: VecDeque<(u8, Vec<u8>)>,
    established_at: Option<Instant>,
    primary: Option<u32>,
    /// The primary circuit as last chosen, reused for PICK_TTL so a packet
    /// needn't take the circuit table's lock; cleared when it closes.
    picked: Option<(Arc<LocalCircuit>, Instant)>,
    hyst: webjet_core::routing::Hysteresis,
    hs_times: VecDeque<Instant>,
    last_unknown_hs: Option<Instant>,
}

pub struct Session {
    pub peer: Bytes32,
    pub peer_key: Bytes32,
    inner: Mutex<Inner>,
    pub created: Instant,
    pub last_used: Mutex<Instant>,
    pub connecting: AtomicBool,
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
    pub path_switches: AtomicU64,
    /// Whether the peer takes LZ4 data frames, and when that was looked up
    /// (its EndpointRecord, re-read every few seconds, not per packet).
    lz4_peer: Mutex<Option<(Instant, bool)>>,
    /// Flows whose packets don't compress (§9.8). Its own lock, so packets
    /// are compressed outside the session's.
    lz4_backoff: Mutex<webjet_core::compress::Backoff>,
}

impl Session {
    pub fn established(&self) -> bool {
        let i = self.inner.lock();
        i.send
            .as_ref()
            .is_some_and(|s| s.created.elapsed() < REJECT_AFTER)
    }

    pub fn handshaking(&self) -> bool {
        self.inner.lock().hs.is_some()
    }

    pub fn primary(&self) -> Option<u32> {
        self.inner.lock().primary
    }
}

#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<Bytes32, Arc<Session>>>,
}

impl Sessions {
    pub fn get(&self, peer: &Bytes32) -> Option<Arc<Session>> {
        self.map.lock().get(peer).cloned()
    }

    pub fn all(&self) -> Vec<Arc<Session>> {
        self.map.lock().values().cloned().collect()
    }

    pub fn remove(&self, peer: &Bytes32) {
        self.map.lock().remove(peer);
    }

    fn get_or_create(&self, n: &Node, peer: &Bytes32) -> Option<Arc<Session>> {
        let key = {
            let s = n.store.read();
            if !s.node_trusted(peer) {
                return None;
            }
            s.view().nodes.get(peer)?.key
        };
        let mut m = self.map.lock();
        if let Some(s) = m.get(peer)
            && s.peer_key == key
        {
            return Some(s.clone());
        }
        let s = Arc::new(Session {
            peer: *peer,
            peer_key: key,
            inner: Mutex::new(Inner::default()),
            created: Instant::now(),
            last_used: Mutex::new(Instant::now()),
            connecting: AtomicBool::new(false),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            path_switches: AtomicU64::new(0),
            lz4_peer: Mutex::new(None),
            lz4_backoff: Mutex::new(Default::default()),
        });
        m.insert(*peer, s.clone());
        Some(s)
    }

    pub fn on_circuit_closed(&self, c: &LocalCircuit) {
        if let Some(s) = self.get(&c.peer) {
            let mut i = s.inner.lock();
            if i.primary == Some(c.label) {
                i.primary = None;
            }
            if i.picked.as_ref().is_some_and(|(p, _)| p.label == c.label) {
                i.picked = None;
            }
        }
    }

    fn in_progress(&self) -> usize {
        let all: Vec<Arc<Session>> = self.map.lock().values().cloned().collect();
        all.iter()
            .filter(|s| s.inner.try_lock().is_none_or(|i| i.hs.is_some()))
            .count()
    }
}

#[derive(Debug)]
struct E2eTrust(std::sync::Weak<Node>);

impl tls::PeerTrust for E2eTrust {
    fn trusted(&self, key: &Bytes32) -> bool {
        self.0
            .upgrade()
            .is_some_and(|n| n.store.read().trusted_by_key(key).is_some())
    }
}

fn trust(n: &Node) -> Arc<dyn tls::PeerTrust> {
    Arc::new(E2eTrust(n.me_weak.get().cloned().unwrap_or_default()))
}

// ---------------------------------------------------------------- sending

#[derive(Debug, PartialEq, Eq)]
pub enum SendResult {
    Sent,
    Queued,
    Dropped,
    NoRoute,
}

/// Send one payload of type `ty` to `peer`, setting up the session and a
/// circuit on demand (§9.4.1).
pub fn send(n: &Arc<Node>, peer: &Bytes32, ty: u8, payload: &[u8], ecn: u8) -> SendResult {
    let Some(s) = n.e2e.get_or_create(n, peer) else {
        return SendResult::NoRoute;
    };
    *s.last_used.lock() = Instant::now();
    let lz4 = (ty == ftype::DATA || ty == ftype::PROXY) && lz4_to(n, &s);
    // Under the session lock only the bookkeeping: pick the circuit and
    // reserve a counter. Compressing and sealing happen after it's released,
    // so a peer's sending and receiving don't wait on each other's crypto.
    let reserved = {
        let mut i = s.inner.lock();
        let usable = i.send.as_ref().is_some_and(|k| {
            k.created.elapsed() < REJECT_AFTER && k.counter < frames::REKEY_PACKETS
        });
        let circ = if usable {
            pick_circuit(n, &s, &mut i)
        } else {
            None
        };
        match (circ, i.send.as_mut()) {
            (Some(c), Some(k)) => {
                let ctr = k.counter;
                k.counter += 1;
                Some((
                    c,
                    k.key.clone(),
                    k.peer_kid,
                    ctr,
                    k.created.elapsed() > REKEY_AFTER,
                ))
            }
            _ => None,
        }
    };
    let Some((c, key, peer_kid, ctr, needs_rekey)) = reserved else {
        // No keys or circuit yet: queue for after the handshake. The limit
        // is read without the session lock (it reads the tree).
        let max = crate::metrics::limit(n, "handshake_queue") as usize;
        let mut i = s.inner.lock();
        if i.queue.len() >= max {
            return SendResult::Dropped;
        }
        i.queue.push_back((ty, payload.to_vec()));
        drop(i);
        ensure(n, &s);
        return SendResult::Queued;
    };
    let packed = if lz4 {
        compress_packet(n, &mut s.lz4_backoff.lock(), payload)
    } else {
        None
    };
    let (ty, payload) = match &packed {
        Some(z) if ty == ftype::DATA => (ftype::DATA_LZ4, &z[..]),
        Some(z) => (ftype::PROXY_LZ4, &z[..]),
        None => (ty, payload),
    };
    let Some(f) = key.seal(ty, peer_kid, ctr, payload) else {
        return SendResult::Dropped;
    };
    if needs_rekey {
        maybe_rekey(n, &s);
    }
    s.tx_packets.fetch_add(1, Ordering::Relaxed);
    if c.send(n, &f, ecn) {
        c.live.tx.fetch_add(1, Ordering::Relaxed);
        SendResult::Sent
    } else {
        SendResult::Dropped
    }
}

/// Whether DATA/PROXY to this session's peer may be LZ4-compressed (§9.8):
/// this node has it on and the peer advertises it. The peer's side is
/// cached for a few seconds.
fn lz4_to(n: &Node, s: &Session) -> bool {
    if !crate::compression::mine(n).data_on() {
        return false;
    }
    if let Some((at, yes)) = *s.lz4_peer.lock()
        && at.elapsed() < Duration::from_secs(5)
    {
        return yes;
    }
    let yes = crate::compression::data_to(n, &s.peer);
    *s.lz4_peer.lock() = Some((Instant::now(), yes));
    yes
}

/// One inner packet LZ4-compressed, or `None` to send it as it is: known
/// encrypted traffic, a flow that has stopped compressing, or no gain.
fn compress_packet(
    n: &Node,
    backoff: &mut webjet_core::compress::Backoff,
    p: &[u8],
) -> Option<Vec<u8>> {
    use webjet_core::compress;
    let stats = &n.metrics.compression.data;
    if p.len() < compress::MIN_DATA || compress::incompressible(p) {
        stats.skipped();
        return None;
    }
    let flow = compress::flow_key(p);
    if !backoff.should_try(flow) {
        stats.skipped();
        return None;
    }
    let z = compress::lz4_compress(p);
    backoff.record(flow, z.is_some());
    match &z {
        Some(z) => stats.sent(p.len(), z.len()),
        None => stats.skipped(),
    }
    z
}

/// How long `pick_circuit`'s choice is reused. Switching waits 3 s of
/// hysteresis anyway, and a closed circuit is dropped at once.
const PICK_TTL: Duration = Duration::from_millis(250);

fn pick_circuit(n: &Node, s: &Session, i: &mut Inner) -> Option<Arc<LocalCircuit>> {
    if let Some((c, at)) = &i.picked
        && at.elapsed() < PICK_TTL
        && !c.live.removed.load(Ordering::Relaxed)
        && c.out_label.lock().is_some()
    {
        return Some(c.clone());
    }
    let chosen = choose_circuit(n, s, i);
    i.picked = chosen.clone().map(|c| (c, Instant::now()));
    chosen
}

fn choose_circuit(n: &Node, s: &Session, i: &mut Inner) -> Option<Arc<LocalCircuit>> {
    let circuits = n.circuits.lock().local_circuits(&s.peer);
    if circuits.is_empty() {
        i.primary = None;
        return None;
    }
    let cur = i
        .primary
        .and_then(|l| circuits.iter().find(|c| c.label == l).cloned());
    let best = circuits.iter().min_by(|a, b| {
        let (ca, cb) = (a.cost(), b.cost());
        let ca = if ca.is_finite() {
            ca
        } else {
            1e9 + a.hops.len() as f64
        };
        let cb = if cb.is_finite() {
            cb
        } else {
            1e9 + b.hops.len() as f64
        };
        ca.partial_cmp(&cb).unwrap_or(std::cmp::Ordering::Equal)
    })?;
    let chosen = match cur {
        Some(c) if c.label != best.label => {
            let now = webjet_core::types::now_ms();
            if i.hyst
                .should_switch(c.cost(), best.label as u64, best.cost(), now, 3000)
            {
                s.path_switches.fetch_add(1, Ordering::Relaxed);
                best.clone()
            } else {
                c
            }
        }
        Some(c) => c,
        None => best.clone(),
    };
    i.primary = Some(chosen.label);
    Some(chosen)
}

/// Make sure a circuit exists and a handshake is under way (async).
fn ensure(n: &Arc<Node>, s: &Arc<Session>) {
    if s.connecting.swap(true, Ordering::SeqCst) {
        return;
    }
    let n = n.clone();
    let s = s.clone();
    tokio::spawn(async move {
        let r = async {
            let existing = n.circuits.lock().local_circuits(&s.peer).into_iter().next();
            let circ = match existing {
                Some(c) => c,
                None => crate::paths::open_best(&n, s.peer).await?,
            };
            if s.established() {
                // Keys are still valid: the circuit came back (§9.4.6).
                flush_queue(&n, &s);
            } else if !s.handshaking() {
                start_handshake(&n, &s, &circ)?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        s.connecting.store(false, Ordering::SeqCst);
        if let Err(e) = r {
            tracing::debug!(peer = %n.name_of(&s.peer), "session setup: {e}");
            let dropped: Vec<(u8, Vec<u8>)> = s.inner.lock().queue.drain(..).collect();
            if let Some(dp) = n.dataplane.get() {
                for (ty, p) in dropped {
                    if ty == ftype::DATA {
                        dp.unreachable(&p);
                    }
                }
            }
        }
    });
}

fn maybe_rekey(n: &Arc<Node>, s: &Arc<Session>) {
    // The lower node id rekeys at 120 s; the other side only as a fallback.
    let age = s
        .inner
        .lock()
        .send
        .as_ref()
        .map(|k| k.created.elapsed())
        .unwrap_or_default();
    let mine = n.me < s.peer || age > REKEY_AFTER + Duration::from_secs(20);
    if !mine || s.handshaking() {
        return;
    }
    // Take the circuit out first: sending on it locks the circuit table.
    let circ = n.circuits.lock().local_circuits(&s.peer).into_iter().next();
    if let Some(c) = circ
        && let Err(e) = start_handshake(n, s, &c)
    {
        tracing::debug!("rekey: {e}");
    }
}

fn flush_queue(n: &Arc<Node>, s: &Arc<Session>) {
    let q: Vec<(u8, Vec<u8>)> = s.inner.lock().queue.drain(..).collect();
    for (ty, p) in q {
        let ecn = if ty == ftype::DATA || ty == ftype::PROXY {
            inner_ecn(&p)
        } else {
            0
        };
        send(n, &s.peer, ty, &p, ecn);
    }
}

/// The relay-header ECN for an inner packet: ECT(0) if the packet is ECN-capable.
pub fn inner_ecn(p: &[u8]) -> u8 {
    match webjet_core::packet::ecn_of(p) {
        0 => 0,
        _ => frames::ecn::ECT0,
    }
}

// ---------------------------------------------------------------- the handshake

fn start_handshake(n: &Arc<Node>, s: &Arc<Session>, c: &Arc<LocalCircuit>) -> Result<()> {
    if n.e2e.in_progress() >= crate::metrics::limit(n, "e2e_handshakes_global") as usize {
        bail!("too many handshakes in progress");
    }
    if !crate::circuit::may_talk(n, &n.me, &s.peer) {
        bail!("policy allows no traffic with this peer");
    }
    let cfg = tls::client_config(&n.kp, vec![s.peer_key], trust(n), tls::ALPN_E2E)?;
    let conn = rustls::ClientConnection::new(cfg, tls::server_name())?;
    let mut hs = Handshake {
        nonce: crypto::random16(),
        initiator: true,
        conn: rustls::Connection::Client(conn),
        my_kid: rand::random::<u32>() | 1,
        my_flight: 0,
        peer_flight: 0,
        last_sent: Vec::new(),
        sent_at: Instant::now(),
        rto: Duration::from_secs(1),
        started: Instant::now(),
        circuit: c.label,
        done: false,
    };
    let out = drain_tls(&mut hs.conn)?;
    hs.my_flight = 1;
    let f = frames::handshake_frame(true, &hs.nonce, hs.my_flight, &out)
        .ok_or_else(|| anyhow!("TLS flight too large"))?;
    hs.last_sent = f.clone();
    s.inner.lock().hs = Some(hs);
    c.send(n, &f, 0);
    Ok(())
}

fn drain_tls(conn: &mut rustls::Connection) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out)?;
    }
    Ok(out)
}

fn feed_tls(conn: &mut rustls::Connection, data: &[u8]) -> Result<()> {
    let mut rd = data;
    while !rd.is_empty() {
        conn.read_tls(&mut rd)?;
        conn.process_new_packets()?;
    }
    Ok(())
}

fn read_app(conn: &mut rustls::Connection) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = conn.reader().read_to_end(&mut buf);
    buf
}

fn derive(conn: &rustls::Connection, init_kid: u32, resp_kid: u32) -> Result<(Bytes32, Bytes32)> {
    let mut km = [0u8; 64];
    let ctx = frames::exporter_context(init_kid, resp_kid);
    match conn {
        rustls::Connection::Client(c) => {
            c.export_keying_material(&mut km, frames::E2E_EXPORTER_LABEL, Some(&ctx))?
        }
        rustls::Connection::Server(c) => {
            c.export_keying_material(&mut km, frames::E2E_EXPORTER_LABEL, Some(&ctx))?
        }
    };
    Ok(frames::split_keys(&km))
}

fn install(i: &mut Inner, send_key: Bytes32, recv_key: Bytes32, my_kid: u32, peer_kid: u32) {
    let now = Instant::now();
    // Keep decrypting with the previous key for a grace period (§9.4.5).
    for k in i.recv.values_mut() {
        if k.retire_at.is_none() {
            k.retire_at = Some(now + OLD_KEY_GRACE);
        }
    }
    i.recv.insert(
        my_kid,
        RecvKey {
            key: Arc::new(SessionKey::new(recv_key)),
            window: ReplayWindow::default(),
            created: now,
            retire_at: None,
        },
    );
    i.send = Some(SendKey {
        key: Arc::new(SessionKey::new(send_key)),
        peer_kid,
        counter: 0,
        created: now,
    });
    i.established_at = Some(now);
}

fn on_handshake(n: &Arc<Node>, c: &Arc<LocalCircuit>, frame: &[u8]) -> Result<()> {
    let h = frames::parse_handshake(frame).ok_or_else(|| anyhow!("bad handshake frame"))?;
    let s = n
        .e2e
        .get_or_create(n, &c.peer)
        .ok_or_else(|| anyhow!("handshake from an untrusted peer"))?;
    *s.last_used.lock() = Instant::now();
    // Count before taking our own lock: in_progress() locks every session.
    let busy = n.e2e.in_progress() >= crate::metrics::limit(n, "e2e_handshakes_global") as usize;
    let per_sec = crate::metrics::limit(n, "e2e_handshakes_per_sec") as usize;
    let mut i = s.inner.lock();
    // A frame for the handshake in progress?
    if let Some(hs) = i.hs.as_mut() {
        if hs.nonce == h.nonce {
            if h.flight <= hs.peer_flight {
                // A retransmission: the peer lost our reply.
                if !hs.last_sent.is_empty() {
                    let f = hs.last_sent.clone();
                    drop(i);
                    c.send(n, &f, 0);
                }
                return Ok(());
            }
            return continue_handshake(n, &s, c, i, h.flight, h.tls);
        }
        // A different handshake from the peer while ours is in progress.
        if h.initiator && hs.initiator && h.flight == 1 {
            if n.me < s.peer {
                return Ok(()); // we stay client; the peer abandons theirs
            }
            i.hs = None; // abandon ours, answer theirs
        } else if !h.initiator {
            return Ok(()); // stale response to an old attempt
        }
    }
    if !h.initiator || h.flight != 1 {
        return Ok(());
    }
    // A new handshake: we are the responder.
    {
        let now = Instant::now();
        i.hs_times
            .retain(|t| now.duration_since(*t) < Duration::from_secs(1));
        if i.hs_times.len() >= per_sec {
            bail!("handshake rate limit");
        }
        i.hs_times.push_back(now);
    }
    if busy {
        bail!("too many handshakes in progress");
    }
    if !crate::circuit::may_talk(n, &n.me, &s.peer) {
        bail!("policy allows no traffic with this peer");
    }
    // Binding to the circuit (§9.4.2 step 4): the TLS identity must be the
    // circuit's signed source.
    let cfg = tls::server_config(&n.kp, trust(n), Some(s.peer_key), &[tls::ALPN_E2E], false)?;
    let conn = rustls::ServerConnection::new(cfg)?;
    i.hs = Some(Handshake {
        nonce: h.nonce,
        initiator: false,
        conn: rustls::Connection::Server(conn),
        my_kid: rand::random::<u32>() | 1,
        my_flight: 0,
        peer_flight: 0,
        last_sent: Vec::new(),
        sent_at: Instant::now(),
        rto: Duration::from_secs(1),
        started: Instant::now(),
        circuit: c.label,
        done: false,
    });
    continue_handshake(n, &s, c, i, h.flight, h.tls)
}

fn continue_handshake(
    n: &Arc<Node>,
    s: &Arc<Session>,
    c: &Arc<LocalCircuit>,
    mut i: parking_lot::MutexGuard<'_, Inner>,
    flight: u16,
    data: &[u8],
) -> Result<()> {
    let Some(hs) = i.hs.as_mut() else {
        bail!("no handshake in progress");
    };
    hs.peer_flight = flight;
    hs.circuit = c.label;
    // Any failure ends the handshake: stale state would keep the session
    // "handshaking" (no re-key, packets queued) until HS_GIVE_UP.
    let (keys, to_send) = match advance(hs, s, data) {
        Ok(x) => x,
        Err(e) => {
            i.hs = None;
            bail!("e2e handshake with {}: {e}", crypto::short(&s.peer));
        }
    };
    let established = keys.is_some();
    let Some(hs) = i.hs.as_ref() else {
        bail!("no handshake in progress");
    };
    if let Some((send_k, recv_k, my_kid, peer_kid)) = keys {
        let initiator = hs.initiator;
        install(&mut i, send_k, recv_k, my_kid, peer_kid);
        // The responder keeps its state briefly to answer a retransmitted flight 3.
        if initiator {
            i.hs = None;
        } else if let Some(h) = i.hs.as_mut() {
            h.done = true;
        }
        tracing::debug!(peer = %n.name_of(&s.peer), initiator, "e2e session established");
    }
    drop(i);
    if let Some(f) = to_send {
        c.send(n, &f, 0);
    }
    if established {
        flush_queue(n, s);
        crate::paths::on_established(n, &s.peer);
    }
    Ok(())
}

/// Keys found by a handshake step: send key, receive key, our key id and the
/// peer's.
type NewKeys = (Bytes32, Bytes32, u32, u32);

/// Feed the peer's flight to TLS; returns the keys once both key ids are
/// known, and our next flight (if any) to send.
fn advance(
    hs: &mut Handshake,
    s: &Session,
    data: &[u8],
) -> Result<(Option<NewKeys>, Option<Vec<u8>>)> {
    feed_tls(&mut hs.conn, data)?;
    let mut keys: Option<NewKeys> = None;
    if !hs.conn.is_handshaking() {
        // Bind the identity: exactly the expected key (the verifier already
        // checked; re-check for defence in depth) and the PQ group.
        if tls::peer_key(&hs.conn) != Some(s.peer_key) {
            bail!("peer identity mismatch");
        }
        tls::check_pq(&hs.conn)?;
        let app = read_app(&mut hs.conn);
        if hs.initiator {
            if !hs.done {
                // Flight 3: send our key_id with our Finished.
                hs.conn.writer().write_all(&hs.my_kid.to_be_bytes())?;
                hs.done = true;
            }
            if let Some(resp_kid) = webjet_core::bytes::be_u32(&app, 0) {
                // Flight 4: the responder's key_id.
                let (i2r, r2i) = derive(&hs.conn, hs.my_kid, resp_kid)?;
                keys = Some((i2r, r2i, hs.my_kid, resp_kid));
            }
        } else if let Some(init_kid) = webjet_core::bytes::be_u32(&app, 0) {
            hs.conn.writer().write_all(&hs.my_kid.to_be_bytes())?;
            let (i2r, r2i) = derive(&hs.conn, init_kid, hs.my_kid)?;
            keys = Some((r2i, i2r, hs.my_kid, init_kid));
        }
    }
    let out = drain_tls(&mut hs.conn)?;
    let mut to_send = None;
    if !out.is_empty() {
        hs.my_flight = hs.peer_flight + 1;
        let f = frames::handshake_frame(hs.initiator, &hs.nonce, hs.my_flight, &out)
            .ok_or_else(|| anyhow!("TLS flight too large"))?;
        hs.last_sent = f.clone();
        hs.sent_at = Instant::now();
        to_send = Some(f);
    }
    Ok((keys, to_send))
}

// ---------------------------------------------------------------- receiving

/// An end-to-end frame at `buf[at..]` (after the relay header) arrived on
/// circuit `c`. Taking the buffer lets it be decrypted in place.
pub fn on_frame(n: &Arc<Node>, c: &Arc<LocalCircuit>, buf: Vec<u8>, at: usize, ecn: u8) {
    let Some(body) = buf.get(at..) else { return };
    let Some(h) = frames::parse_header(body) else {
        return;
    };
    if h.ty == ftype::HANDSHAKE {
        if let Err(e) = on_handshake(n, c, body) {
            tracing::debug!("{e}");
        }
        return;
    }
    let Some(s) = n
        .e2e
        .get(&c.peer)
        .or_else(|| n.e2e.get_or_create(n, &c.peer))
    else {
        return;
    };
    // Decrypt outside the session lock: check the replay window first (cheap
    // drop of replays), open, then re-check and mark under the lock, so two
    // copies of a frame racing each other still get in only once.
    let key = {
        let mut i = s.inner.lock();
        let Some(k) = i.recv.get(&h.key_id) else {
            // A frame under a key we don't have: we restarted, or the peer
            // holds stale keys. Start a fresh handshake so it re-keys (rate
            // limited; the peer answers as responder).
            let due = i
                .last_unknown_hs
                .is_none_or(|t| t.elapsed() > Duration::from_secs(5));
            if due && i.hs.is_none() {
                i.last_unknown_hs = Some(Instant::now());
                drop(i);
                if let Err(e) = start_handshake(n, &s, c) {
                    tracing::debug!("re-key on unknown key id: {e}");
                }
            }
            return;
        };
        if k.created.elapsed() > REJECT_AFTER
            || k.retire_at.is_some_and(|t| Instant::now() > t)
            || !k.window.check(h.counter)
        {
            return;
        }
        k.key.clone()
    };
    let Some(plain) = key.open_owned(buf, at) else {
        return;
    };
    {
        let mut i = s.inner.lock();
        let Some(k) = i.recv.get_mut(&h.key_id) else {
            return;
        };
        if !k.window.check(h.counter) {
            return;
        }
        k.window.mark(h.counter);
        // The responder's handshake state can go once traffic flows.
        if i.hs.as_ref().is_some_and(|x| x.done && !x.initiator) {
            i.hs = None;
        }
    }
    *s.last_used.lock() = Instant::now();
    s.rx_packets.fetch_add(1, Ordering::Relaxed);
    if h.ty != ftype::PROBE && h.ty != ftype::PROBE_ACK {
        c.live.rx.fetch_add(1, Ordering::Relaxed);
    }
    // Compressed payloads (§9.8) are accepted whatever this node's settings.
    let (ty, plain) = match h.ty {
        ftype::DATA_LZ4 | ftype::PROXY_LZ4 => {
            let stats = &n.metrics.compression.data;
            let Some(p) = webjet_core::compress::lz4_decompress(&plain, usize::from(u16::MAX))
            else {
                stats.error();
                return;
            };
            stats.received(p.len(), plain.len());
            let ty = if h.ty == ftype::DATA_LZ4 {
                ftype::DATA
            } else {
                ftype::PROXY
            };
            (ty, p)
        }
        ftype::RPC_ZSTD => {
            let stats = &n.metrics.compression.control;
            let Some(p) =
                webjet_core::compress::zstd_decompress(&plain, webjet_net::hop::MAX_RECORD)
            else {
                stats.error();
                return;
            };
            stats.received(p.len(), plain.len());
            (ftype::RPC, p)
        }
        t => (t, plain),
    };
    match ty {
        ftype::DATA => {
            if let Some(dp) = n.dataplane.get() {
                let mut p = plain;
                if ecn == frames::ecn::CE && webjet_core::packet::ecn_of(&p) != 0 {
                    webjet_core::packet::set_ecn(&mut p, frames::ecn::CE);
                }
                dp.inbound(&c.peer, p);
            }
        }
        ftype::PROXY => {
            if let Some(dp) = n.dataplane.get() {
                let mut p = plain;
                if ecn == frames::ecn::CE && webjet_core::packet::ecn_of(&p) != 0 {
                    webjet_core::packet::set_ecn(&mut p, frames::ecn::CE);
                }
                dp.proxy.from_peer(n, dp, &c.peer, p);
            }
        }
        ftype::PROBE => {
            // Echo the probe, bounded so a reply is never large. A probe
            // encodes to 66 bytes; the old bound of 64 cut every probe, so
            // no circuit was ever measured (rtt 0, loss → 1, circuits closed
            // as dead, path choice blind).
            let mut reply = plain;
            reply.truncate(PROBE_ECHO_MAX);
            send_on(n, &s, c, ftype::PROBE_ACK, &reply);
        }
        ftype::PROBE_ACK => crate::paths::on_probe_ack(n, c, &plain),
        ftype::PUNCH_OFFER | ftype::PUNCH_GO => crate::punch::on_message(n, &c.peer, ty, &plain),
        ftype::RPC => crate::rpc::on_frame(n, &c.peer, &plain),
        ftype::CLOSE => {
            tracing::debug!(peer = %n.name_of(&c.peer), "session closed by peer");
            n.e2e.remove(&c.peer);
        }
        _ => {}
    }
}

/// Send on a specific circuit (probes go on the circuit they measure).
pub fn send_on(n: &Arc<Node>, s: &Session, c: &LocalCircuit, ty: u8, payload: &[u8]) -> bool {
    let (key, peer_kid, ctr) = {
        let mut i = s.inner.lock();
        let Some(k) = i.send.as_mut() else {
            return false;
        };
        if k.created.elapsed() > REJECT_AFTER {
            return false;
        }
        let ctr = k.counter;
        k.counter += 1;
        (k.key.clone(), k.peer_kid, ctr)
    };
    let f = key.seal(ty, peer_kid, ctr, payload);
    f.is_some_and(|f| c.send(n, &f, 0))
}

// ---------------------------------------------------------------- timers

pub async fn run(n: Arc<Node>) {
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tick.tick().await;
        let now = Instant::now();
        for s in n.e2e.all() {
            // Lifecycle: the peer's key changed or it was tombstoned (§9.4.6).
            let cur_key = n.store.read().view().nodes.get(&s.peer).map(|x| x.key);
            let trusted = n.store.read().node_trusted(&s.peer);
            if cur_key != Some(s.peer_key) || !trusted {
                n.e2e.remove(&s.peer);
                continue;
            }
            if s.last_used.lock().elapsed() > IDLE_TIMEOUT {
                n.e2e.remove(&s.peer);
                continue;
            }
            let mut resend: Option<(u32, Vec<u8>)> = None;
            let mut failed = false;
            {
                let mut i = s.inner.lock();
                i.recv.retain(|_, k| {
                    k.created.elapsed() < REJECT_AFTER && k.retire_at.is_none_or(|t| now < t)
                });
                if let Some(hs) = i.hs.as_mut() {
                    // The initiator keeps retransmitting flight 3 until the
                    // responder's key_id arrives; a finished responder only
                    // answers retransmissions.
                    let finished_responder = hs.done && !hs.initiator;
                    if hs.started.elapsed() > HS_GIVE_UP {
                        failed = !finished_responder;
                        i.hs = None;
                    } else if !finished_responder
                        && now.duration_since(hs.sent_at) > hs.rto
                        && !hs.last_sent.is_empty()
                    {
                        hs.rto = (hs.rto * 2).min(Duration::from_secs(8));
                        hs.sent_at = now;
                        resend = Some((hs.circuit, hs.last_sent.clone()));
                    }
                }
            }
            if failed {
                tracing::debug!(peer = %n.name_of(&s.peer), "e2e handshake gave up");
                let dropped: Vec<(u8, Vec<u8>)> = s.inner.lock().queue.drain(..).collect();
                if let Some(dp) = n.dataplane.get() {
                    for (ty, p) in dropped {
                        if ty == ftype::DATA {
                            dp.unreachable(&p);
                        }
                    }
                }
            }
            if let Some((label, f)) = resend {
                let all = n.circuits.lock().local_circuits(&s.peer);
                let c = all
                    .iter()
                    .find(|c| c.label == label)
                    .or_else(|| all.first())
                    .cloned();
                if let Some(c) = c {
                    c.send(&n, &f, 0);
                }
            }
            if s.established() {
                let age = s
                    .inner
                    .lock()
                    .send
                    .as_ref()
                    .map(|k| k.created.elapsed())
                    .unwrap_or_default();
                if age > REKEY_AFTER && s.last_used.lock().elapsed() < Duration::from_secs(60) {
                    maybe_rekey(&n, &s);
                }
            }
        }
    }
}

/// Tear down a session explicitly, telling the peer.
pub fn close(n: &Arc<Node>, peer: &Bytes32) {
    if let Some(s) = n.e2e.get(peer) {
        let circ = n.circuits.lock().local_circuits(peer).into_iter().next();
        if let Some(c) = circ {
            send_on(n, &s, &c, ftype::CLOSE, &[]);
        }
        n.e2e.remove(peer);
    }
}

pub fn summary(s: &Session) -> serde_json::Value {
    let i = s.inner.lock();
    serde_json::json!({
        "established": i.send.as_ref().is_some_and(|k| k.created.elapsed() < REJECT_AFTER),
        "key_age_s": i.send.as_ref().map(|k| k.created.elapsed().as_secs()),
        "handshaking": i.hs.is_some(),
        "queued": i.queue.len(),
        "primary_circuit": i.primary,
        "tx_packets": s.tx_packets.load(Ordering::Relaxed),
        "rx_packets": s.rx_packets.load(Ordering::Relaxed),
        "path_switches": s.path_switches.load(Ordering::Relaxed),
    })
}

#[cfg(test)]
impl Sessions {
    /// What waits in `peer`'s session for its handshake: (frame type,
    /// payload).
    pub(crate) fn queued_for_test(&self, peer: &Bytes32) -> Vec<(u8, Vec<u8>)> {
        self.get(peer)
            .map(|s| s.inner.lock().queue.iter().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webjet_proto::{self as wp, Decodable, Encodable};

    /// A probe must survive the echo bound, or no circuit is ever measured.
    #[test]
    fn probe_survives_echo() {
        let p = wp::Probe {
            route_id: Some(crypto::k32(&[0xff; 32])),
            probe_seq: u64::MAX,
            sent_at_us: u64::MAX,
        };
        let mut echo = p.encode_bytes();
        echo.truncate(PROBE_ECHO_MAX);
        let back = wp::Probe::decode_bytes(&echo).unwrap();
        assert_eq!(back.probe_seq, u64::MAX);
        assert_eq!(back.route_id, p.route_id);
    }

    /// Per-packet cost of the data path through an established session on
    /// a relayed circuit: `send` (seal, pick circuit and hop, relay header,
    /// hop record) and `on_frame` (open, replay check, data plane). Not a
    /// regression test; run in release when touching the hot path:
    ///
    ///   cargo test --release -p webjetd --lib e2e::tests::data_path_cost -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "benchmark"]
    async fn data_path_cost() {
        use crate::testnode::{self, Cluster};
        use webjet_core::testutil::{NodeSpec, packets};
        let mut c = Cluster::new();
        let s = c.data_node("src", "10.7.0.2", &[]);
        let r = c.enroll(NodeSpec {
            name: "relay",
            ip: "10.7.0.3",
            roles: &[wp::Role::Data, wp::Role::Relay],
            ..Default::default()
        });
        let d = c.data_node("dst", "10.7.0.4", &[]);
        // Some unrelated relays and circuits, as on a busy node.
        let others: Vec<Bytes32> = (0..20)
            .map(|i| {
                c.data_node(&format!("o{i}"), &format!("10.7.1.{}", i + 1), &[])
                    .0
            })
            .collect();
        c.set_policy(wp::Policy {
            default_action: wp::Action::Allow,
            ..Default::default()
        })
        .expect("policy");
        let (n, _dir) = testnode::node(&mut c, s.0, s.1.clone());
        let (dp, mut tun) = crate::dataplane::Dataplane::for_test(&n);
        let (hop, mut rx) = n.test_hop(r.0, wp::Transport::TcpTls);
        let mut keep = Vec::new();
        for o in &others {
            keep.push(n.test_hop(*o, wp::Transport::TcpTls));
        }
        // Circuits: one to `dst` through the relay, others to other peers.
        let mut circuits = Vec::new();
        for (i, peer) in std::iter::once(d.0)
            .chain(others.iter().copied())
            .enumerate()
        {
            let n2 = n.clone();
            let relay = r.0;
            let opening =
                tokio::spawn(async move { crate::circuit::open(&n2, peer, vec![relay]).await });
            let o = loop {
                if let Some(webjet_proto::HopMsg::CircuitOpen(o)) = rx.control().pop() {
                    break o;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            };
            crate::circuit::on_accept(
                &n,
                &hop,
                wp::CircuitAccept {
                    label: o.label,
                    peer_label: 100 + i as u32,
                },
            );
            circuits.push(opening.await.expect("task").expect("circuit"));
        }
        let circ = circuits[0].clone();
        let sess = n.e2e.get_or_create(&n, &d.0).expect("session");
        install(&mut sess.inner.lock(), [1; 32], [2; 32], 7, 9);
        let peer_key = SessionKey::new([2; 32]);

        let payload = packets::udp4([10, 7, 0, 2], [10, 7, 0, 4], 4000, 5000, &[0x5a; 1172]);
        let reply = packets::udp4([10, 7, 0, 4], [10, 7, 0, 2], 5000, 4000, &[0x5a; 1172]);
        let rounds: u64 = std::env::var("WEBJET_BENCH_ROUNDS")
            .ok()
            .and_then(|r| r.parse().ok())
            .unwrap_or(200_000);

        let t = Instant::now();
        for i in 0..rounds {
            assert!(matches!(
                send(&n, &d.0, ftype::DATA, &payload, 0),
                SendResult::Sent
            ));
            if i % 512 == 511 {
                let _ = rx.relay();
            }
        }
        let out_ns = t.elapsed().as_nanos() as f64 / rounds as f64;
        let _ = rx.relay();

        // Prime conntrack with the outbound flow, then time replies.
        dp.outbound(payload);
        let _ = rx.relay();
        let frames: Vec<Vec<u8>> = (0..rounds)
            .map(|i| peer_key.seal(ftype::DATA, 7, i, &reply).expect("seal"))
            .collect();
        let t = Instant::now();
        for (i, f) in frames.into_iter().enumerate() {
            on_frame(&n, &circ, f, 0, 0);
            if i % 512 == 511 {
                while tun.try_recv().is_ok() {}
            }
        }
        let in_ns = t.elapsed().as_nanos() as f64 / rounds as f64;
        let delivered = sess.rx_packets.load(Ordering::Relaxed);
        assert_eq!(delivered, rounds);
        println!(
            "data path, 1200-byte packets: send {out_ns:.0} ns, receive {in_ns:.0} ns per packet"
        );
        drop((keep, circuits));
    }
}
