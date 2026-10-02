//! End-to-end sessions (§9.4): one per peer, independent of circuits. The
//! handshake is TLS 1.3 run on in-memory buffers and carried in HANDSHAKE
//! frames; afterwards packets use the AEAD frames of §6.9 with keys exported
//! from the TLS session.

use crate::circuit::LocalCircuit;
use crate::node::Node;
use anyhow::{anyhow, bail, Result};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use webjet_core::crypto::{self, Bytes32};
use webjet_core::frames::{self, ftype, ReplayWindow, SessionKey};
use webjet_net::tls;

pub const REKEY_AFTER: Duration = Duration::from_secs(120);
pub const REJECT_AFTER: Duration = Duration::from_secs(180);
pub const OLD_KEY_GRACE: Duration = Duration::from_secs(10);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(180);
pub const MAX_QUEUED: usize = 64;
const HS_GIVE_UP: Duration = Duration::from_secs(30);
const MAX_HS_IN_PROGRESS: usize = 1000;

struct SendKey {
    key: SessionKey,
    peer_kid: u32,
    counter: u64,
    created: Instant,
}

struct RecvKey {
    key: SessionKey,
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
}

impl Session {
    pub fn established(&self) -> bool {
        let i = self.inner.lock();
        i.send.as_ref().map(|s| s.created.elapsed() < REJECT_AFTER).unwrap_or(false)
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
        if let Some(s) = m.get(peer) {
            if s.peer_key == key {
                return Some(s.clone());
            }
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
        }
    }

    fn in_progress(&self) -> usize {
        let all: Vec<Arc<Session>> = self.map.lock().values().cloned().collect();
        all.iter().filter(|s| s.inner.try_lock().map(|i| i.hs.is_some()).unwrap_or(true)).count()
    }
}

#[derive(Debug)]
struct E2eTrust(std::sync::Weak<Node>);

impl tls::PeerTrust for E2eTrust {
    fn trusted(&self, key: &Bytes32) -> bool {
        self.0.upgrade().map(|n| n.store.read().trusted_by_key(key).is_some()).unwrap_or(false)
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
    let Some(s) = n.e2e.get_or_create(n, peer) else { return SendResult::NoRoute };
    *s.last_used.lock() = Instant::now();
    let mut i = s.inner.lock();
    let usable = i.send.as_ref().map(|k| k.created.elapsed() < REJECT_AFTER && k.counter < frames::REKEY_PACKETS).unwrap_or(false);
    if usable {
        let circ = pick_circuit(n, &s, &mut i);
        if let Some(c) = circ {
            let k = i.send.as_mut().unwrap();
            let ctr = k.counter;
            k.counter += 1;
            let f = k.key.seal(ty, k.peer_kid, ctr, payload);
            let needs_rekey = k.created.elapsed() > REKEY_AFTER;
            drop(i);
            if needs_rekey {
                maybe_rekey(n, &s);
            }
            s.tx_packets.fetch_add(1, Ordering::Relaxed);
            return if c.send(n, &f, ecn) { SendResult::Sent } else { SendResult::Dropped };
        }
    }
    if i.queue.len() >= MAX_QUEUED {
        return SendResult::Dropped;
    }
    i.queue.push_back((ty, payload.to_vec()));
    drop(i);
    ensure(n, &s);
    SendResult::Queued
}

fn pick_circuit(n: &Node, s: &Session, i: &mut Inner) -> Option<Arc<LocalCircuit>> {
    let circuits = n.circuits.lock().local_circuits(&s.peer);
    if circuits.is_empty() {
        i.primary = None;
        return None;
    }
    let cur = i.primary.and_then(|l| circuits.iter().find(|c| c.label == l).cloned());
    let best = circuits.iter().min_by(|a, b| {
        let (ca, cb) = (a.cost(), b.cost());
        let ca = if ca.is_finite() { ca } else { 1e9 + a.hops.len() as f64 };
        let cb = if cb.is_finite() { cb } else { 1e9 + b.hops.len() as f64 };
        ca.partial_cmp(&cb).unwrap_or(std::cmp::Ordering::Equal)
    })?;
    let chosen = match cur {
        Some(c) if c.label != best.label => {
            let now = webjet_core::types::now_ms();
            if i.hyst.should_switch(c.cost(), best.label as u64, best.cost(), now, 3000) {
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
    let age = s.inner.lock().send.as_ref().map(|k| k.created.elapsed()).unwrap_or_default();
    let mine = n.me < s.peer || age > REKEY_AFTER + Duration::from_secs(20);
    if mine && !s.handshaking() {
        if let Some(c) = n.circuits.lock().local_circuits(&s.peer).into_iter().next() {
            if let Err(e) = start_handshake(n, s, &c) {
                tracing::debug!("rekey: {e}");
            }
        }
    }
}

fn flush_queue(n: &Arc<Node>, s: &Arc<Session>) {
    let q: Vec<(u8, Vec<u8>)> = s.inner.lock().queue.drain(..).collect();
    for (ty, p) in q {
        let ecn = if ty == ftype::DATA { inner_ecn(&p) } else { 0 };
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
    if n.e2e.in_progress() >= MAX_HS_IN_PROGRESS {
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
    let f = frames::handshake_frame(true, &hs.nonce, hs.my_flight, &out);
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
        rustls::Connection::Client(c) => c.export_keying_material(&mut km, frames::E2E_EXPORTER_LABEL, Some(&ctx))?,
        rustls::Connection::Server(c) => c.export_keying_material(&mut km, frames::E2E_EXPORTER_LABEL, Some(&ctx))?,
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
    i.recv.insert(my_kid, RecvKey { key: SessionKey::new(recv_key), window: ReplayWindow::default(), created: now, retire_at: None });
    i.send = Some(SendKey { key: SessionKey::new(send_key), peer_kid, counter: 0, created: now });
    i.established_at = Some(now);
}

fn on_handshake(n: &Arc<Node>, c: &Arc<LocalCircuit>, frame: &[u8]) -> Result<()> {
    let h = frames::parse_handshake(frame).ok_or_else(|| anyhow!("bad handshake frame"))?;
    let s = n.e2e.get_or_create(n, &c.peer).ok_or_else(|| anyhow!("handshake from an untrusted peer"))?;
    *s.last_used.lock() = Instant::now();
    // Count before taking our own lock: in_progress() locks every session.
    let busy = n.e2e.in_progress() >= MAX_HS_IN_PROGRESS;
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
        i.hs_times.retain(|t| now.duration_since(*t) < Duration::from_secs(1));
        if i.hs_times.len() >= 10 {
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

fn continue_handshake(n: &Arc<Node>, s: &Arc<Session>, c: &Arc<LocalCircuit>, mut i: parking_lot::MutexGuard<'_, Inner>, flight: u16, data: &[u8]) -> Result<()> {
    let hs = i.hs.as_mut().unwrap();
    hs.peer_flight = flight;
    hs.circuit = c.label;
    if let Err(e) = feed_tls(&mut hs.conn, data) {
        i.hs = None;
        bail!("e2e handshake with {}: {e}", crypto::short(&s.peer));
    }
    let mut keys: Option<(Bytes32, Bytes32, u32, u32)> = None;
    if !hs.conn.is_handshaking() {
        // Bind the identity: exactly the expected key (the verifier already
        // checked; re-check for defence in depth) and the PQ group.
        let peer = tls::peer_key(&hs.conn);
        if peer != Some(s.peer_key) {
            i.hs = None;
            bail!("e2e peer identity mismatch");
        }
        tls::check_pq(&hs.conn)?;
        let app = read_app(&mut hs.conn);
        if hs.initiator {
            if !hs.done {
                // Flight 3: send our key_id with our Finished.
                hs.conn.writer().write_all(&hs.my_kid.to_be_bytes())?;
                hs.done = true;
            }
            if app.len() >= 4 {
                // Flight 4: the responder's key_id.
                let resp_kid = u32::from_be_bytes(app[..4].try_into().unwrap());
                let (i2r, r2i) = derive(&hs.conn, hs.my_kid, resp_kid)?;
                keys = Some((i2r, r2i, hs.my_kid, resp_kid));
            }
        } else if app.len() >= 4 {
            let init_kid = u32::from_be_bytes(app[..4].try_into().unwrap());
            hs.conn.writer().write_all(&hs.my_kid.to_be_bytes())?;
            let (i2r, r2i) = derive(&hs.conn, init_kid, hs.my_kid)?;
            keys = Some((r2i, i2r, hs.my_kid, init_kid));
        }
    }
    let out = drain_tls(&mut hs.conn)?;
    let mut to_send = None;
    if !out.is_empty() {
        hs.my_flight = hs.peer_flight + 1;
        let f = frames::handshake_frame(hs.initiator, &hs.nonce, hs.my_flight, &out);
        hs.last_sent = f.clone();
        hs.sent_at = Instant::now();
        to_send = Some(f);
    }
    let established = keys.is_some();
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

// ---------------------------------------------------------------- receiving

pub fn on_frame(n: &Arc<Node>, c: &Arc<LocalCircuit>, body: &[u8], ecn: u8) {
    let Some(h) = frames::parse_header(body) else { return };
    if h.ty == ftype::HANDSHAKE {
        if let Err(e) = on_handshake(n, c, body) {
            tracing::debug!("{e}");
        }
        return;
    }
    let Some(s) = n.e2e.get(&c.peer).or_else(|| n.e2e.get_or_create(n, &c.peer)) else { return };
    let plain = {
        let mut i = s.inner.lock();
        let Some(k) = i.recv.get_mut(&h.key_id) else {
            // A frame under a key we don't have: we restarted, or the peer
            // holds stale keys. Start a fresh handshake so it re-keys (rate
            // limited; the peer answers as responder).
            let due = i.last_unknown_hs.map(|t| t.elapsed() > Duration::from_secs(5)).unwrap_or(true);
            if due && i.hs.is_none() {
                i.last_unknown_hs = Some(Instant::now());
                drop(i);
                if let Err(e) = start_handshake(n, &s, c) {
                    tracing::debug!("re-key on unknown key id: {e}");
                }
            }
            return;
        };
        if k.created.elapsed() > REJECT_AFTER || k.retire_at.map(|t| Instant::now() > t).unwrap_or(false) {
            return;
        }
        if !k.window.check(h.counter) {
            return;
        }
        let Some(p) = k.key.open(body) else { return };
        k.window.mark(h.counter);
        // The responder's handshake state can go once traffic flows.
        if i.hs.as_ref().map(|x| x.done && !x.initiator).unwrap_or(false) {
            i.hs = None;
        }
        p
    };
    *s.last_used.lock() = Instant::now();
    s.rx_packets.fetch_add(1, Ordering::Relaxed);
    match h.ty {
        ftype::DATA => {
            if let Some(dp) = n.dataplane.get() {
                let mut p = plain;
                if ecn == frames::ecn::CE && webjet_core::packet::ecn_of(&p) != 0 {
                    webjet_core::packet::set_ecn(&mut p, frames::ecn::CE);
                }
                dp.inbound(&c.peer, p);
            }
        }
        ftype::PROBE => {
            let mut reply = plain;
            reply.truncate(64);
            send_on(n, &s, c, ftype::PROBE_ACK, &reply);
        }
        ftype::PROBE_ACK => crate::paths::on_probe_ack(n, c, &plain),
        ftype::PUNCH_OFFER | ftype::PUNCH_GO => crate::punch::on_message(n, &c.peer, h.ty, &plain),
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
    let f = {
        let mut i = s.inner.lock();
        let Some(k) = i.send.as_mut() else { return false };
        if k.created.elapsed() > REJECT_AFTER {
            return false;
        }
        let ctr = k.counter;
        k.counter += 1;
        k.key.seal(ty, k.peer_kid, ctr, payload)
    };
    c.send(n, &f, 0)
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
                i.recv.retain(|_, k| k.created.elapsed() < REJECT_AFTER && k.retire_at.map(|t| now < t).unwrap_or(true));
                if let Some(hs) = i.hs.as_mut() {
                    // The initiator keeps retransmitting flight 3 until the
                    // responder's key_id arrives; a finished responder only
                    // answers retransmissions.
                    let finished_responder = hs.done && !hs.initiator;
                    if hs.started.elapsed() > HS_GIVE_UP {
                        failed = !finished_responder;
                        i.hs = None;
                    } else if !finished_responder && now.duration_since(hs.sent_at) > hs.rto && !hs.last_sent.is_empty() {
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
                let c = all.iter().find(|c| c.label == label).or_else(|| all.first()).cloned();
                if let Some(c) = c {
                    c.send(&n, &f, 0);
                }
            }
            if s.established() {
                let age = s.inner.lock().send.as_ref().map(|k| k.created.elapsed()).unwrap_or_default();
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
        if let Some(c) = n.circuits.lock().local_circuits(peer).into_iter().next() {
            send_on(n, &s, &c, ftype::CLOSE, &[]);
        }
        n.e2e.remove(peer);
    }
}

pub fn summary(s: &Session) -> serde_json::Value {
    let i = s.inner.lock();
    serde_json::json!({
        "established": i.send.as_ref().map(|k| k.created.elapsed() < REJECT_AFTER).unwrap_or(false),
        "key_age_s": i.send.as_ref().map(|k| k.created.elapsed().as_secs()),
        "handshaking": i.hs.is_some(),
        "queued": i.queue.len(),
        "primary_circuit": i.primary,
        "tx_packets": s.tx_packets.load(Ordering::Relaxed),
        "rx_packets": s.rx_packets.load(Ordering::Relaxed),
        "path_switches": s.path_switches.load(Ordering::Relaxed),
    })
}
