//! UDP + KCP + FEC transport (§9.1, §9.7.3, §17.5, §17.6).
//!
//! One [`UdpEndpoint`] per UDP socket both listens and dials, so the
//! reflexive address a relay observes is the one peers can punch to (§11.7).
//! Every datagram is obfuscated whole by [`UdpObfs`]. Inner datagrams:
//!
//! ```text
//! inner = kind[1] || conv[4] || body
//! kind  = 1 SHARD (FEC shard of KCP packets)
//!       | 2 OPEN  (ts[8] || nonce[16] || shard)  — first packets of a dial
//!       | 3 PUNCH (type[1] || token[16])         — connectivity checks (§11.7):
//!                                                  type 1 PING is answered with
//!                                                  type 2 PONG to its source
//!       | 4 STATS (received[4] || expected[4] [|| flags[1]])
//!                                                — loss feedback for FEC;
//!                                                  flag 1: takes RAW_ACK
//!       | 5 RAW_ACK (held_us[4] || KCP ACKs)    — acknowledgements outside
//!                                                  FEC and the pacer, sent
//!                                                  only to peers that set
//!                                                  the STATS flag; held_us:
//!                                                  how long the sender held
//!                                                  the acknowledged data
//! ```
//!
//! Acknowledgements skip the pacer so the time from a segment leaving the
//! socket to its acknowledgement is the path's round trip, whatever the
//! peer is sending (§11.2). That RTT and the FEC line loss of both
//! directions are the hop's measurements ([`KcpStats::take_sample`]).
//!
//! A session is created on the listening side only for a valid OPEN
//! (timestamp within ±60 s, fresh nonce); unknown sessions are dropped
//! silently (§9.1). KCP runs with its congestion window off and is paced by
//! a BBR-style controller.

mod proto;

use crate::fec;
use crate::gate::{GateResult, ReplayCache, SharedEpochs, UdpObfs, small_packet_padding};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use webjet_core::types::{SKEW_PSK_GATE, now_ms};

const K_SHARD: u8 = 1;
const K_OPEN: u8 = 2;
const K_PUNCH: u8 = 3;
const K_STATS: u8 = 4;
const K_RAW_ACK: u8 = 5;
/// STATS flag: this end takes RAW_ACK datagrams.
const STATS_RAW_ACK: u8 = 1;
const PUNCH_PING: u8 = 1;
const PUNCH_PONG: u8 = 2;
/// PONGs sent per second at most (a captured PING replayed with a forged
/// source must not turn this socket into a reflector).
const PONGS_PER_S: u32 = 2000;

/// A connectivity check that arrived (§11.7): `from` is the address the
/// datagram came from (peer-reflexive when it's not a known candidate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PunchEvent {
    pub from: SocketAddr,
    pub token: [u8; 16],
    /// A PONG: our PING to `from` got through and back.
    pub pong: bool,
}

/// KCP MTU: leaves room for FEC (9), the inner header (5+24 on OPEN) and
/// obfuscation (42+2) inside a 1400-byte datagram.
pub const KCP_MTU: usize = 1300;
const _: () = assert!(KCP_MTU + 2 <= crate::fec::MAX_SHARD);
/// The byte pipe between the hop writer and the session. Small: the
/// session's KCP queue already holds about a round trip of data, and
/// anything more should wait in the hop queue, where fair queueing and
/// CoDel manage it (§17.2), not in a buffer in front of KCP.
const DUPLEX: usize = 16 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Per-session counters for metrics (§12.3).
#[derive(Debug, Default)]
pub struct KcpStats {
    pub wire_tx: AtomicU64,
    pub wire_rx: AtomicU64,
    pub fec_parity_tx: AtomicU64,
    pub fec_recovered: AtomicU64,
    pub retrans: AtomicU64,
    pub fec_ratio_pct: AtomicU64,
    pub bw_estimate_kbps: AtomicU64,
    /// How long the oldest unsent byte has waited in KCP, µs (§17.7).
    pub backlog_us: AtomicU64,
    /// Raw RTT samples and loss counts since the last [`Self::take_sample`].
    meas: Mutex<Measured>,
}

#[derive(Debug, Default)]
struct Measured {
    rtt: crate::meter::RttAgg,
    /// What the peer received of ours (its STATS), and we of its.
    tx: crate::meter::Counts,
    rx: crate::meter::Counts,
}

impl KcpStats {
    /// The path's RTT and round-trip datagram loss (before FEC recovery)
    /// since the last call (§11.2).
    pub fn take_sample(&self) -> crate::meter::Sample {
        let mut m = self.meas.lock();
        let s = crate::meter::Sample {
            rtt_ms: m.rtt.take(),
            loss: crate::meter::round_trip_loss(m.tx.loss(), m.rx.loss()),
            packets: m.tx.expected.saturating_add(m.rx.expected),
        };
        m.tx = Default::default();
        m.rx = Default::default();
        s
    }
}

pub struct KcpConn {
    pub stream: DuplexStream,
    pub peer: SocketAddr,
    pub gate: GateResult,
    pub stats: Arc<KcpStats>,
    /// An accepted session counts against [`MAX_HANDSHAKING`] until this
    /// is dropped: hold it until the TLS handshake is done.
    pub handshake: Option<HandshakeSlot>,
}

/// One of the endpoint's [`MAX_HANDSHAKING`] slots for accepted sessions
/// whose TLS handshake hasn't finished.
pub struct HandshakeSlot(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for HandshakeSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Accepted sessions still in their TLS handshake, across all sources.
/// The per-IP limit alone doesn't hold: source addresses can be spoofed
/// by anyone with the network PSK.
pub const MAX_HANDSHAKING: usize = 256;
/// Sessions an endpoint keeps at once (dialed and accepted).
pub const MAX_SESSIONS: usize = 8192;
/// The largest datagram a peer sends: a sealed OPEN (kind, conv, ts,
/// nonce) carrying the largest FEC shard, plus the most padding. Anything
/// larger is dropped before it is decrypted or copied.
pub const MAX_DATAGRAM: usize =
    crate::gate::UDP_OVERHEAD + 2 + (1 + 4 + 8 + 16) + fec::HDR + fec::MAX_SHARD + 96;

/// A datagram for a session (`kind || body`) and when the socket gave it to us.
type Arrived = (Instant, Vec<u8>);

struct SessionHandle {
    tx: mpsc::Sender<Arrived>,
    /// Tells this session from a later one under the same (peer, conv).
    id: u64,
}

pub struct UdpEndpoint {
    sock: Arc<UdpSocket>,
    obfs: Arc<UdpObfs>,
    epochs: SharedEpochs,
    replay: ReplayCache,
    sessions: Mutex<HashMap<(SocketAddr, u32), SessionHandle>>,
    accept_tx: mpsc::Sender<KcpConn>,
    pub accept_rx: tokio::sync::Mutex<mpsc::Receiver<KcpConn>>,
    /// Pending OPENs per source IP (§16.2: hop handshakes per source IP).
    per_ip: Mutex<HashMap<std::net::IpAddr, (Instant, u32)>>,
    pub listening: bool,
    pub rate_ceiling_bps: AtomicU64,
    /// Handshakes per source IP per 10 s (`hop_handshakes_per_ip`).
    pub per_ip_limit: std::sync::atomic::AtomicU32,
    /// Where arriving connectivity checks are reported (the punch module).
    pub punch_events: Mutex<Option<mpsc::Sender<PunchEvent>>>,
    pongs: Mutex<(Instant, u32)>,
    /// Accepted sessions whose TLS handshake is still running.
    handshaking: Arc<std::sync::atomic::AtomicUsize>,
}

impl UdpEndpoint {
    pub async fn bind(
        addr: SocketAddr,
        root_key: &[u8; 32],
        epochs: SharedEpochs,
        listening: bool,
    ) -> anyhow::Result<Arc<UdpEndpoint>> {
        let sock = Arc::new(UdpSocket::bind(addr).await?);
        let obfs = Arc::new(UdpObfs::new(root_key));
        obfs.set_epochs(&epochs.read());
        let (accept_tx, accept_rx) = mpsc::channel(64);
        let ep = Arc::new(UdpEndpoint {
            sock,
            obfs,
            epochs,
            replay: ReplayCache::new(100_000),
            sessions: Mutex::new(HashMap::new()),
            accept_tx,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            per_ip: Mutex::new(HashMap::new()),
            listening,
            rate_ceiling_bps: AtomicU64::new(0),
            per_ip_limit: std::sync::atomic::AtomicU32::new(5),
            punch_events: Mutex::new(None),
            pongs: Mutex::new((Instant::now(), 0)),
            handshaking: Arc::default(),
        });
        // Several receivers on the one socket, so the gate's decryption
        // isn't bounded by one core. KCP and FEC take reordering anyway.
        for _ in 0..recv_tasks() {
            let e2 = ep.clone();
            tokio::spawn(async move { e2.recv_loop().await });
        }
        Ok(ep)
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    /// Re-key the obfuscation layer after a PSK change.
    pub fn refresh_epochs(&self) {
        self.obfs.set_epochs(&self.epochs.read());
    }

    fn seal(&self, inner: &[u8]) -> Option<Vec<u8>> {
        let (epoch, _) = self.epochs.read().current_key()?;
        self.obfs
            .seal(epoch, inner, small_packet_padding(inner.len()))
    }

    fn punch_datagram(&self, kind: u8, token: &[u8; 16]) -> Option<Vec<u8>> {
        let mut inner = vec![K_PUNCH, 0, 0, 0, 0, kind];
        inner.extend_from_slice(token);
        self.seal(&inner)
    }

    /// Send a connectivity check (PING) to `to` (§11.7). It opens this
    /// side's NAT mapping toward `to`; a PONG comes back when it got
    /// through. `token` ties the answer to one punching attempt.
    pub async fn punch(&self, to: SocketAddr, token: &[u8; 16]) {
        if let Some(d) = self.punch_datagram(PUNCH_PING, token) {
            let _ = self.sock.send_to(&d, to).await;
        }
    }

    fn on_punch(&self, from: SocketAddr, body: &[u8]) {
        let (Some(&kind), Some(token)) = (body.first(), webjet_core::bytes::array::<16>(body, 1))
        else {
            return; // 0.6 and earlier: padding only
        };
        if kind == PUNCH_PING {
            let allowed = {
                let mut p = self.pongs.lock();
                if p.0.elapsed() >= Duration::from_secs(1) {
                    *p = (Instant::now(), 0);
                }
                p.1 += 1;
                p.1 <= PONGS_PER_S
            };
            if allowed && let Some(d) = self.punch_datagram(PUNCH_PONG, &token) {
                let _ = self.sock.try_send_to(&d, from);
            }
        } else if kind != PUNCH_PONG {
            return;
        }
        if let Some(tx) = self.punch_events.lock().as_ref() {
            let _ = tx.try_send(PunchEvent {
                from,
                token,
                pong: kind == PUNCH_PONG,
            });
        }
    }

    async fn recv_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, from) = match self.sock.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    tracing::debug!("udp recv: {e}");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            // Larger than anything a peer sends: not worth a decryption,
            // and it must not reach a session's buffers.
            if n > MAX_DATAGRAM {
                continue;
            }
            let at = Instant::now();
            let Some((gate, inner)) = self.obfs.open(&buf[..n], &self.epochs.read()) else {
                continue;
            };
            let (Some(&kind), Some(conv)) = (inner.first(), webjet_core::bytes::be_u32(&inner, 1))
            else {
                continue;
            };
            let mut inner = inner;
            let body = &inner[5..];
            if kind == K_PUNCH {
                self.on_punch(from, body);
                continue;
            }
            let key = (from, conv);
            let existing = self.sessions.lock().get(&key).map(|h| h.tx.clone());
            if let Some(tx) = existing {
                // `kind || body` in the gate's buffer, without another one.
                inner[4] = kind;
                inner.drain(..4);
                let _ = tx.try_send((at, inner));
                continue;
            }
            if kind != K_OPEN || !self.listening {
                continue;
            }
            let (Some(ts), Some(nonce)) = (
                webjet_core::bytes::be_u64(body, 0),
                webjet_core::bytes::array::<16>(body, 8),
            ) else {
                continue;
            };
            if ts.abs_diff(now_ms()) > SKEW_PSK_GATE {
                continue;
            }
            // Room for one more session, counted across all sources.
            let Some(slot) = self.handshake_slot() else {
                continue;
            };
            if !self.replay.check_and_insert(nonce, now_ms()) {
                continue;
            }
            if !self.admit_ip(from.ip()) {
                continue;
            }
            // Another receive task may have opened it meanwhile (OPENs are
            // resent): then this OPEN goes to that session.
            let Some((stream, tx, stats, id)) = self.clone().spawn_session(from, conv) else {
                let tx = self.sessions.lock().get(&key).map(|h| h.tx.clone());
                if let Some(tx) = tx {
                    let mut d = vec![K_OPEN];
                    d.extend_from_slice(body);
                    let _ = tx.try_send((at, d));
                }
                continue;
            };
            let mut d = vec![K_OPEN];
            d.extend_from_slice(body);
            let _ = tx.try_send((at, d));
            if self
                .accept_tx
                .try_send(KcpConn {
                    stream,
                    peer: from,
                    gate,
                    stats,
                    handshake: Some(slot),
                })
                .is_err()
            {
                self.forget_session(key, id);
            }
        }
    }

    /// A handshake slot for one more accepted session, unless the endpoint
    /// has [`MAX_HANDSHAKING`] handshakes running or [`MAX_SESSIONS`]
    /// sessions.
    fn handshake_slot(&self) -> Option<HandshakeSlot> {
        if self.sessions.lock().len() >= MAX_SESSIONS {
            return None;
        }
        let prev = self.handshaking.fetch_add(1, Ordering::Relaxed);
        let slot = HandshakeSlot(self.handshaking.clone());
        (prev < MAX_HANDSHAKING).then_some(slot)
    }

    /// Remove a session's entry, if it is still that session's: the same
    /// (peer, conv) may already belong to a newer one.
    fn forget_session(&self, key: (SocketAddr, u32), id: u64) {
        let mut s = self.sessions.lock();
        if s.get(&key).is_some_and(|h| h.id == id) {
            s.remove(&key);
        }
    }

    fn admit_ip(&self, ip: std::net::IpAddr) -> bool {
        let mut m = self.per_ip.lock();
        let now = Instant::now();
        m.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(10));
        let e = m.entry(ip).or_insert((now, 0));
        if e.1 >= self.per_ip_limit.load(Ordering::Relaxed) {
            return false;
        }
        e.1 += 1;
        true
    }

    /// Dial a peer: returns a byte stream over KCP.
    pub fn dial(self: &Arc<Self>, to: SocketAddr) -> KcpConn {
        let conv = rand::random::<u32>() | 1;
        let (stream, _tx, stats, _) = self.clone().start_session(to, conv, true);
        let gate = GateResult::Normal(self.epochs.read().current);
        KcpConn {
            stream,
            peer: to,
            gate,
            stats,
            handshake: None,
        }
    }

    /// An accepted session, unless (peer, conv) has one already.
    fn spawn_session(
        self: Arc<Self>,
        peer: SocketAddr,
        conv: u32,
    ) -> Option<(DuplexStream, mpsc::Sender<Arrived>, Arc<KcpStats>, u64)> {
        let mut sessions = self.sessions.lock();
        if sessions.contains_key(&(peer, conv)) {
            return None;
        }
        Some(
            self.clone()
                .start_session_locked(&mut sessions, peer, conv, false),
        )
    }

    /// A new session for (peer, conv), replacing any (a dial's conv is random).
    fn start_session(
        self: Arc<Self>,
        peer: SocketAddr,
        conv: u32,
        dialer: bool,
    ) -> (DuplexStream, mpsc::Sender<Arrived>, Arc<KcpStats>, u64) {
        let mut sessions = self.sessions.lock();
        self.clone()
            .start_session_locked(&mut sessions, peer, conv, dialer)
    }

    /// Register and start a session; checking and inserting under one
    /// guard, so concurrent receive tasks can't both open (peer, conv).
    fn start_session_locked(
        self: Arc<Self>,
        sessions: &mut HashMap<(SocketAddr, u32), SessionHandle>,
        peer: SocketAddr,
        conv: u32,
        dialer: bool,
    ) -> (DuplexStream, mpsc::Sender<Arrived>, Arc<KcpStats>, u64) {
        static SESSION_IDS: AtomicU64 = AtomicU64::new(1);
        let id = SESSION_IDS.fetch_add(1, Ordering::Relaxed);
        let (user, inner) = tokio::io::duplex(DUPLEX);
        let (tx, rx) = mpsc::channel(4096);
        sessions.insert((peer, conv), SessionHandle { tx: tx.clone(), id });
        let stats = Arc::new(KcpStats::default());
        let st = stats.clone();
        tokio::spawn(async move {
            let ep = self.clone();
            run_session(ep, peer, conv, dialer, inner, rx, st).await;
            self.forget_session((peer, conv), id);
        });
        (user, tx, stats, id)
    }
}

// ---------------------------------------------------------------- BBR-style pacing (§17.5)

struct Bbr {
    btl_bw: f64, // bytes/s
    bw_samples: VecDeque<(Instant, f64)>,
    min_rtt: Duration,
    min_rtt_at: Instant,
    full_bw: f64,
    full_bw_count: u32,
    startup: bool,
    cycle: usize,
    cycle_start: Instant,
    ceiling: f64,
}

const GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

impl Bbr {
    fn new() -> Self {
        Bbr {
            btl_bw: 1_000_000.0,
            bw_samples: VecDeque::new(),
            min_rtt: Duration::from_millis(100),
            min_rtt_at: Instant::now(),
            full_bw: 0.0,
            full_bw_count: 0,
            startup: true,
            cycle: 0,
            cycle_start: Instant::now(),
            ceiling: 0.0,
        }
    }

    /// A delivery-rate sample. `app_limited`: the sender had less to send
    /// than the window allowed, so the sample shows the application's rate,
    /// not the path's. Such a sample may raise the estimate but never lowers
    /// it, and the old samples are kept meanwhile (as in BBR); otherwise an
    /// idle second followed by one small packet collapsed the estimate to the
    /// floor and throttled the next burst.
    fn on_delivery(&mut self, bytes: usize, interval: Duration, now: Instant, app_limited: bool) {
        if bytes == 0 || interval.is_zero() {
            return;
        }
        let rate = bytes as f64 / interval.as_secs_f64();
        if app_limited && rate <= self.btl_bw {
            return;
        }
        self.bw_samples.push_back((now, rate));
        let window = (self.min_rtt * 10).max(Duration::from_secs(1));
        while let Some((t, _)) = self.bw_samples.front() {
            if now.duration_since(*t) > window {
                self.bw_samples.pop_front();
            } else {
                break;
            }
        }
        self.btl_bw = self.bw_samples.iter().map(|s| s.1).fold(50_000.0, f64::max);
        if self.startup {
            if self.btl_bw > self.full_bw * 1.25 {
                self.full_bw = self.btl_bw;
                self.full_bw_count = 0;
            } else {
                self.full_bw_count += 1;
                if self.full_bw_count >= 3 {
                    self.startup = false;
                }
            }
        }
    }

    fn on_rtt(&mut self, rtt: Duration, now: Instant) {
        if rtt < self.min_rtt || now.duration_since(self.min_rtt_at) > Duration::from_secs(10) {
            self.min_rtt = rtt.max(Duration::from_millis(1));
            self.min_rtt_at = now;
        }
    }

    fn pacing_rate(&mut self, now: Instant) -> f64 {
        let gain = if self.startup {
            2.89
        } else {
            if now.duration_since(self.cycle_start) > self.min_rtt {
                self.cycle = (self.cycle + 1) % GAINS.len();
                self.cycle_start = now;
            }
            GAINS[self.cycle]
        };
        let r = (self.btl_bw * gain).max(64_000.0);
        if self.ceiling > 0.0 {
            r.min(self.ceiling)
        } else {
            r
        }
    }

    /// In-flight cap ≈ 2 × BDP, in KCP segments.
    fn window(&self) -> u16 {
        let bdp = self.btl_bw * self.min_rtt.as_secs_f64();
        ((2.0 * bdp / KCP_MTU as f64).ceil() as u32).clamp(32, 4096) as u16
    }
}

/// Shortest time a delivery-rate sample covers. Acknowledgements arrive in
/// bursts (several in one datagram, or queued behind a busy task), so a rate
/// taken between two ticks a millisecond apart was many times the path's:
/// a 20 Mbit/s path read as 500 Mbit/s, and a 200 Mbit/s relay advertised
/// gigabits of capacity (§11.8.1).
const MIN_SAMPLE_INTERVAL: Duration = Duration::from_millis(25);

/// One delivery-rate sample for [`Bbr::on_delivery`].
#[derive(Debug, PartialEq)]
struct DeliverySample {
    bytes: usize,
    interval: Duration,
    app_limited: bool,
}

/// Turns the bytes KCP reports acknowledged into delivery-rate samples
/// (§17.5), each covering at least an RTT (and [`MIN_SAMPLE_INTERVAL`]).
#[derive(Debug)]
struct Delivery {
    epoch_start: Instant,
    epoch_bytes: usize,
    epoch_app_limited: bool,
}

impl Delivery {
    fn new(now: Instant) -> Self {
        Delivery {
            epoch_start: now,
            epoch_bytes: 0,
            epoch_app_limited: false,
        }
    }

    /// Called every loop turn with the bytes acknowledged since the last
    /// call. `idle`: nothing queued or in flight. `app_limited`: nothing was
    /// waiting to be sent. Returns a sample when enough time has passed, or
    /// when the sender went idle (then application-limited).
    fn on_tick(
        &mut self,
        delivered: usize,
        idle: bool,
        now: Instant,
        min_interval: Duration,
        app_limited: bool,
    ) -> Option<DeliverySample> {
        self.epoch_bytes += delivered;
        self.epoch_app_limited |= app_limited;
        let elapsed = now.duration_since(self.epoch_start);
        let sample = if self.epoch_bytes > 0 && elapsed >= min_interval {
            Some(DeliverySample {
                bytes: self.epoch_bytes,
                interval: elapsed,
                app_limited: self.epoch_app_limited,
            })
        } else if idle {
            // A short burst before going idle says little about the path.
            // With nothing delivered, the next sample starts now rather than
            // spanning the idle time.
            (self.epoch_bytes > 0).then(|| DeliverySample {
                bytes: self.epoch_bytes,
                interval: elapsed.max(min_interval),
                app_limited: true,
            })
        } else {
            return None;
        };
        self.epoch_start = now;
        self.epoch_bytes = 0;
        self.epoch_app_limited = false;
        sample
    }
}

/// How much unsent data KCP may hold: about 5 ms at the pacing rate (at
/// least a few segments). More waits in the hop queue, where fair queueing
/// and CoDel manage it (§17.2).
fn queue_limit(rate_bytes_per_s: f64) -> usize {
    ((rate_bytes_per_s * 0.005) as usize).max(4 * KCP_MTU)
}

/// What one datagram (`kind || body`, as `recv_loop` hands it to a session)
/// carries for the session.
#[derive(Debug, PartialEq)]
enum Inbound<'a> {
    /// An FEC shard (from a SHARD, or an OPEN after its timestamp and nonce).
    Shard(&'a [u8]),
    /// The peer's loss feedback: of the datagrams we sent, how many it
    /// received before FEC recovery, and whether it takes RAW_ACK.
    Loss {
        received: u64,
        expected: u64,
        raw_ack: bool,
    },
    /// KCP acknowledgements sent outside FEC, and how long the peer held
    /// them after the acknowledged data reached its socket.
    RawAck {
        held: Duration,
        acks: &'a [u8],
    },
    Ignore,
}

impl Inbound<'_> {
    /// The loss fraction a `Loss` reports.
    fn loss(received: u64, expected: u64) -> f64 {
        if expected == 0 {
            return 0.0;
        }
        (expected.saturating_sub(received) as f64 / expected as f64).clamp(0.0, 1.0)
    }
}

fn inbound(d: &[u8]) -> Inbound<'_> {
    let (Some(&kind), Some(body)) = (d.first(), d.get(1..)) else {
        return Inbound::Ignore;
    };
    match kind {
        K_SHARD => Inbound::Shard(body),
        K_OPEN if body.len() >= 24 => Inbound::Shard(&body[24..]),
        K_STATS if body.len() >= 8 => {
            let recv = u64::from(webjet_core::bytes::be_u32(body, 0).unwrap_or(0));
            let exp = u64::from(webjet_core::bytes::be_u32(body, 4).unwrap_or(0));
            if exp > 0 {
                Inbound::Loss {
                    received: recv.min(exp),
                    expected: exp,
                    // 0.6 and earlier send no flags.
                    raw_ack: body.get(8).is_some_and(|f| f & STATS_RAW_ACK != 0),
                }
            } else {
                Inbound::Ignore
            }
        }
        K_RAW_ACK if body.len() >= 4 => Inbound::RawAck {
            held: Duration::from_micros(u64::from(
                webjet_core::bytes::be_u32(body, 0).unwrap_or(0),
            )),
            acks: &body[4..],
        },
        _ => Inbound::Ignore,
    }
}

/// A STATS datagram (before sealing): what we received of what the peer's
/// shard groups said it sent (§17.6).
fn stats_frame(conv: u32, received: u64, expected: u64) -> Vec<u8> {
    let mut inner = Vec::with_capacity(14);
    inner.push(K_STATS);
    inner.extend_from_slice(&conv.to_be_bytes());
    inner.extend_from_slice(&(received.min(u64::from(u32::MAX)) as u32).to_be_bytes());
    inner.extend_from_slice(&(expected.min(u64::from(u32::MAX)) as u32).to_be_bytes());
    inner.push(STATS_RAW_ACK);
    inner
}

/// A RAW_ACK datagram (before sealing).
fn raw_ack_frame(conv: u32, held: Duration, acks: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(9 + acks.len());
    inner.push(K_RAW_ACK);
    inner.extend_from_slice(&conv.to_be_bytes());
    let us = u32::try_from(held.as_micros()).unwrap_or(u32::MAX);
    inner.extend_from_slice(&us.to_be_bytes());
    inner.extend_from_slice(acks);
    inner
}

/// A shard as a datagram (before sealing): SHARD once the peer answered,
/// else OPEN with a fresh timestamp and nonce for the listener's gate.
fn shard_frame(opened: bool, conv: u32, shard: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(shard.len() + 30);
    if opened {
        inner.push(K_SHARD);
        inner.extend_from_slice(&conv.to_be_bytes());
    } else {
        inner.push(K_OPEN);
        inner.extend_from_slice(&conv.to_be_bytes());
        inner.extend_from_slice(&now_ms().to_be_bytes());
        inner.extend_from_slice(&rand::random::<[u8; 16]>());
    }
    inner.extend_from_slice(shard);
    inner
}

/// Token bucket for the paced send rate: refills at the pacing rate, holds
/// at most 10 ms of it plus a 16 kB burst. Sending may overdraw it by a
/// packet or an FEC group; the debt is paid back before more data goes.
struct Pacer {
    tokens: f64,
    last: Instant,
}

impl Pacer {
    const BURST: f64 = 16_000.0;

    fn new(now: Instant) -> Pacer {
        Pacer {
            tokens: Self::BURST,
            last: now,
        }
    }

    /// Refill for the time since the last call, at `rate` bytes/s.
    fn refill(&mut self, now: Instant, rate: f64) {
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * rate)
            .min(rate * 0.01 + Self::BURST);
        self.last = now;
    }

    /// Bytes that may go now.
    fn budget(&self) -> usize {
        self.tokens.max(0.0) as usize
    }

    fn spend(&mut self, len: usize) {
        self.tokens -= len as f64;
    }
}

async fn run_session(
    ep: Arc<UdpEndpoint>,
    peer: SocketAddr,
    conv: u32,
    dialer: bool,
    user: DuplexStream,
    mut rx: mpsc::Receiver<Arrived>,
    stats: Arc<KcpStats>,
) {
    let mut kcp = proto::Kcp::new(conv, KCP_MTU);
    kcp.set_wndsize(256, 1024);
    let start = Instant::now();
    let us = |t: Instant| t.duration_since(start).as_micros() as u64;
    let mut enc = fec::Encoder::new();
    let mut dec = fec::Decoder::new();
    let mut bbr = Bbr::new();
    let mut rate = bbr.pacing_rate(start);
    let mut opened = !dialer; // the dialer sends OPENs until it hears back
    let mut last_rx = Instant::now();
    let mut pacer = Pacer::new(Instant::now());
    let mut fec_flush_at: Option<Instant> = None;
    let mut delivery = Delivery::new(Instant::now());
    let mut stats_sent_at = Instant::now();
    let mut out = proto::Output::default();
    let mut rtts: Vec<Duration> = Vec::new();
    // The peer takes acknowledgements outside FEC and the pacer (it said so
    // in its STATS).
    let mut peer_raw_ack = false;
    // When the newest datagram whose segments this flush acknowledges
    // reached the socket: the peer subtracts how long we held them.
    let mut acked_arrival: Option<Instant> = None;
    let mut user_buf = vec![0u8; 16 * 1024];
    let mut user_open = true;
    // Received bytes on their way to the user. While a slow reader hasn't
    // taken them, KCP keeps the rest in its receive queue, so the window it
    // advertises shrinks and the peer slows down; ticks and acknowledgements
    // go on meanwhile.
    let (mut rd, mut wr) = tokio::io::split(user);
    let mut pending: Vec<u8> = Vec::new();
    let mut pend_off = 0usize;
    let mut user_gone = false;
    // The next wake-up without traffic: every BUSY_TICK while anything is
    // queued, in flight or due, otherwise IDLE_TICK (a host may hold
    // thousands of idle hops; their keepalives wake them anyway).
    let mut wake = Instant::now() + BUSY_TICK;

    let seal_and_send = |inner: Vec<u8>| {
        let ep = ep.clone();
        let st = stats.clone();
        async move {
            if let Some(d) = ep.seal(&inner) {
                st.wire_tx.fetch_add(d.len() as u64, Ordering::Relaxed);
                let _ = ep.sock.send_to(&d, peer).await;
            }
        }
    };

    loop {
        // Take more user data only while KCP holds a few milliseconds of it
        // (§17.2): the rest waits in the hop queue, where CoDel sees it.
        let can_take = user_open && kcp.queued_bytes() < queue_limit(rate);
        tokio::select! {
            r = rd.read(&mut user_buf), if can_take => {
                match r {
                    Ok(0) | Err(_) => { user_open = false; }
                    Ok(n) => kcp.send(&user_buf[..n], us(Instant::now())),
                }
            }
            d = rx.recv() => {
                let Some(d) = d else { break };
                last_rx = Instant::now();
                opened = true;
                // Take what else has arrived, so one flush answers it all.
                let mut batch = vec![d];
                while batch.len() < 64 {
                    match rx.try_recv() {
                        Ok(d) => batch.push(d),
                        Err(_) => break,
                    }
                }
                for (at, d) in batch {
                    stats.wire_rx.fetch_add(d.len() as u64, Ordering::Relaxed);
                    match inbound(&d) {
                        Inbound::Shard(shard) => {
                            for pkt in dec.push(shard) {
                                let _ = kcp.input(&pkt, us(at), Duration::ZERO);
                                acked_arrival = Some(acked_arrival.map_or(at, |t| t.max(at)));
                            }
                        }
                        Inbound::RawAck { held, acks } => {
                            let _ = kcp.input_control(acks, us(at), held);
                        }
                        Inbound::Loss { received, expected, raw_ack } => {
                            peer_raw_ack = raw_ack;
                            stats.meas.lock().tx.add(received, expected);
                            enc.adapt(Inbound::loss(received, expected));
                            stats.fec_ratio_pct.store((enc.ratio * 100.0) as u64, Ordering::Relaxed);
                        }
                        Inbound::Ignore => {}
                    }
                }
                stats.fec_recovered.store(dec.recovered, Ordering::Relaxed);
            }
            r = wr.write(&pending[pend_off..]), if pend_off < pending.len() => {
                match r {
                    Ok(0) | Err(_) => {
                        // The user is gone: drop what it would have read.
                        user_open = false;
                        user_gone = true;
                        pending.clear();
                        pend_off = 0;
                    }
                    Ok(n) => {
                        pend_off += n;
                        if pend_off == pending.len() {
                            pending.clear();
                            pend_off = 0;
                        }
                    }
                }
            }
            _ = tokio::time::sleep_until(wake.into()) => {}
        }
        // Hand received bytes to the user, a bounded amount at a time.
        if pending.is_empty() {
            while pending.len() < PENDING_MAX
                && let Some(b) = kcp.recv()
            {
                if !user_gone {
                    pending.extend_from_slice(&b);
                }
            }
        }
        let now = Instant::now();
        // What KCP measured: raw round trips (§11.2), retransmissions and
        // delivered bytes for the rate controller (§17.5).
        kcp.take_rtt_samples(&mut rtts);
        if !rtts.is_empty() {
            let mut m = stats.meas.lock();
            for r in rtts.drain(..) {
                m.rtt.add(r.as_secs_f64() * 1000.0);
                bbr.on_rtt(r, now);
            }
        }
        let re = kcp.take_retransmits();
        if re > 0 {
            stats.retrans.fetch_add(re, Ordering::Relaxed);
        }
        let min_interval = bbr.min_rtt.max(MIN_SAMPLE_INTERVAL);
        let idle = kcp.wait_snd() == 0;
        // Nothing waited for the pacer or the window: the sender had no
        // more to send, so the sample is application-limited.
        let app_limited = kcp.queued_bytes() == 0;
        if let Some(s) =
            delivery.on_tick(kcp.take_delivered(), idle, now, min_interval, app_limited)
        {
            bbr.on_delivery(s.bytes, s.interval, now, s.app_limited);
        }
        bbr.ceiling = ep.rate_ceiling_bps.load(Ordering::Relaxed) as f64 / 8.0;
        kcp.set_wndsize(bbr.window(), 1024);
        stats
            .bw_estimate_kbps
            .store((bbr.btl_bw * 8.0 / 1000.0) as u64, Ordering::Relaxed);
        // Acknowledgements, retransmissions and new data, paced: data goes
        // only while the pacer has tokens, and FEC parity counts too.
        rate = bbr.pacing_rate(now);
        pacer.refill(now, rate);
        out.clear();
        kcp.flush(us(now), pacer.budget(), &mut out);
        let held = acked_arrival
            .take()
            .map_or(Duration::ZERO, |t| now.duration_since(t));
        for p in out.control.drain(..) {
            if peer_raw_ack && opened {
                // At once and on their own, so the peer's RTT never
                // includes our send backlog (§11.2).
                seal_and_send(raw_ack_frame(conv, held, &p)).await;
                continue;
            }
            for s in enc.push(&p) {
                pacer.spend(s.len());
                seal_and_send(shard_frame(opened, conv, &s)).await;
            }
            fec_flush_at.get_or_insert(now + Duration::from_millis(15));
        }
        for p in out.data.drain(..) {
            for s in enc.push(&p) {
                pacer.spend(s.len());
                seal_and_send(shard_frame(opened, conv, &s)).await;
            }
            fec_flush_at.get_or_insert(now + Duration::from_millis(15));
        }
        if fec_flush_at.is_some_and(|t| now >= t) {
            for s in enc.flush() {
                pacer.spend(s.len());
                seal_and_send(shard_frame(opened, conv, &s)).await;
            }
            fec_flush_at = None;
        }
        stats
            .fec_parity_tx
            .store(enc.parity_bytes, Ordering::Relaxed);
        // How long data has waited in KCP: the hop queue's CoDel adds it to
        // each frame's own wait (§17.2, §17.7).
        stats.backlog_us.store(
            kcp.backlog_age(us(now)).as_micros() as u64,
            Ordering::Relaxed,
        );
        // Loss feedback for the peer's FEC (§17.6).
        if now.duration_since(stats_sent_at) > Duration::from_secs(1) {
            // Line loss before FEC recovery, counted from shard group gaps.
            let (received, expected) = dec.take_loss();
            stats.meas.lock().rx.add(received, expected);
            if expected > 0 {
                seal_and_send(stats_frame(conv, received, expected)).await;
            }
            stats_sent_at = now;
        }
        if now.duration_since(last_rx) > IDLE_TIMEOUT || kcp.is_dead() {
            break;
        }
        if !user_open && kcp.wait_snd() == 0 && pending.is_empty() {
            break;
        }
        let busy = kcp.wait_snd() > 0 || fec_flush_at.is_some() || !pending.is_empty();
        let now = Instant::now();
        wake = now + if busy { BUSY_TICK } else { IDLE_TICK };
    }
}

/// Receive tasks per UDP endpoint: one per core, up to 4.
fn recv_tasks() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().min(4))
}

/// `run_session`'s tick with data queued or in flight: KCP's flush interval.
const BUSY_TICK: Duration = Duration::from_millis(5);
/// Its tick when idle; under the 1 s loss report and far under IDLE_TIMEOUT.
const IDLE_TICK: Duration = Duration::from_millis(100);

/// Received bytes taken out of KCP at once for a slow user; the rest waits
/// in KCP's receive queue, where it shrinks the advertised window.
const PENDING_MAX: usize = 256 * 1024;

/// Entry points for the fuzz targets (`fuzz/fuzz_targets/kcp_session.rs`):
/// what a KCP session does with datagrams that passed the UDP gate, without
/// sockets or timers.
#[doc(hidden)]
pub mod fuzzing {
    use super::*;

    /// Feed `datagrams` (each `kind || body`, as `recv_loop` hands them to a
    /// session) through the FEC decoder into KCP, read what KCP delivers and
    /// flush its answers through the FEC encoder, like `run_session`.
    /// Returns the bytes delivered to the user.
    pub fn session_input(conv: u32, datagrams: &[&[u8]]) -> Vec<u8> {
        let mut kcp = proto::Kcp::new(conv, KCP_MTU);
        let mut dec = fec::Decoder::new();
        let mut enc = fec::Encoder::new();
        let mut out = proto::Output::default();
        let mut delivered = Vec::new();
        for (i, d) in datagrams.iter().enumerate() {
            let t = 10_000 * i as u64;
            match inbound(d) {
                Inbound::Shard(shard) => {
                    for pkt in dec.push(shard) {
                        let _ = kcp.input(&pkt, t, Duration::ZERO);
                    }
                }
                Inbound::Loss {
                    received, expected, ..
                } => enc.adapt(Inbound::loss(received, expected)),
                Inbound::RawAck { held, acks } => {
                    let _ = kcp.input_control(acks, t, held);
                }
                Inbound::Ignore => continue,
            }
            while let Some(b) = kcp.recv() {
                delivered.extend_from_slice(&b);
            }
            out.clear();
            kcp.flush(t, usize::MAX, &mut out);
            kcp.take_rtt_samples(&mut Vec::new());
            let _ = (
                kcp.take_delivered(),
                kcp.take_retransmits(),
                dec.take_loss(),
            );
            for pkt in out.control.iter().chain(&out.data) {
                let _ = enc.push(pkt);
            }
        }
        let _ = enc.flush();
        delivered
    }

    /// One packet straight into a KCP conversation, and its answer.
    pub fn proto_input(pkt: &[u8]) {
        let conv = webjet_core::bytes::array::<4>(pkt, 0).map_or(0, u32::from_le_bytes);
        let mut kcp = proto::Kcp::new(conv, KCP_MTU);
        kcp.send(b"data", 0);
        let _ = kcp.input(pkt, 1000, Duration::from_micros(10));
        let mut out = proto::Output::default();
        kcp.flush(2000, usize::MAX, &mut out);
        while kcp.recv().is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::Epochs;

    fn epochs() -> SharedEpochs {
        let mut e = Epochs::default();
        e.keys.insert(1, [5; 32]);
        e.current = 1;
        Arc::new(parking_lot::RwLock::new(e))
    }

    #[test]
    fn inbound_datagrams_are_classified() {
        let mut open = vec![K_OPEN];
        open.extend_from_slice(&[0; 24]);
        open.extend_from_slice(b"shard");
        assert_eq!(inbound(&open), Inbound::Shard(b"shard"));
        assert_eq!(inbound(&[K_SHARD, 1, 2]), Inbound::Shard(&[1, 2]));
        // An OPEN too short for its timestamp and nonce carries nothing.
        assert_eq!(inbound(&[K_OPEN, 1, 2, 3]), Inbound::Ignore);
        let frame = stats_frame(7, 90, 100);
        assert_eq!(frame.len(), 14);
        // `recv_loop` strips kind and conv, then hands `kind || body` on.
        let mut d = vec![K_STATS];
        d.extend_from_slice(&frame[5..]);
        assert_eq!(
            inbound(&d),
            Inbound::Loss {
                received: 90,
                expected: 100,
                raw_ack: true
            }
        );
        assert!((Inbound::loss(90, 100) - 0.1).abs() < 1e-9);
        // An older peer's STATS has no flags.
        assert_eq!(
            inbound(&d[..9]),
            Inbound::Loss {
                received: 90,
                expected: 100,
                raw_ack: false
            }
        );
        // More received than expected is no loss, nothing expected no report.
        d[1..5].copy_from_slice(&200u32.to_be_bytes());
        assert_eq!(
            inbound(&d),
            Inbound::Loss {
                received: 100,
                expected: 100,
                raw_ack: true
            }
        );
        assert_eq!(Inbound::loss(100, 100), 0.0);
        let empty = stats_frame(7, 0, 0);
        assert_eq!(
            inbound(&[&[K_STATS][..], &empty[5..]].concat()),
            Inbound::Ignore
        );
        let ack = raw_ack_frame(7, Duration::from_micros(1234), b"acks");
        assert_eq!(
            inbound(&[&[K_RAW_ACK][..], &ack[5..]].concat()),
            Inbound::RawAck {
                held: Duration::from_micros(1234),
                acks: b"acks"
            }
        );
        assert_eq!(inbound(&[K_RAW_ACK, 0, 0]), Inbound::Ignore);
        assert_eq!(inbound(&[]), Inbound::Ignore);
        assert_eq!(inbound(&[99, 1]), Inbound::Ignore);
    }

    #[test]
    fn shard_frames_open_until_the_peer_answers() {
        let f = shard_frame(false, 9, b"x");
        assert_eq!(f[0], K_OPEN);
        assert_eq!(&f[1..5], &9u32.to_be_bytes());
        assert_eq!(f.len(), 5 + 24 + 1);
        assert_eq!(
            inbound(&[&[K_OPEN][..], &f[5..]].concat()),
            Inbound::Shard(b"x")
        );
        assert_eq!(
            shard_frame(true, 9, b"x"),
            [&[K_SHARD][..], &9u32.to_be_bytes(), b"x"].concat()
        );
    }

    #[test]
    fn the_pacer_refills_at_the_rate_up_to_its_burst() {
        let t0 = Instant::now();
        let mut p = Pacer::new(t0);
        assert_eq!(p.budget(), 16_000);
        p.spend(17_000);
        assert_eq!(p.budget(), 0, "overdrawn by 1 kB");
        // 1 MB/s for 5 ms: 5 kB, less the debt.
        p.refill(t0 + Duration::from_millis(5), 1e6);
        assert_eq!(p.budget(), 4_000);
        // A long idle period fills only up to 10 ms of rate plus the burst.
        p.refill(t0 + Duration::from_secs(10), 1e6);
        assert_eq!(p.budget(), 26_000);
    }

    #[tokio::test]
    async fn kcp_roundtrip() {
        let ep_a = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), false)
            .await
            .unwrap();
        let ep_b = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), true)
            .await
            .unwrap();
        let mut c = ep_a.dial(ep_b.local_addr().unwrap());
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let d2 = data.clone();
        let w = tokio::spawn(async move {
            c.stream.write_all(&d2).await.unwrap();
            let mut back = vec![0u8; 5];
            c.stream.read_exact(&mut back).await.unwrap();
            back
        });
        let mut s = tokio::time::timeout(Duration::from_secs(5), async {
            ep_b.accept_rx.lock().await.recv().await.unwrap()
        })
        .await
        .unwrap();
        let mut got = vec![0u8; data.len()];
        tokio::time::timeout(Duration::from_secs(20), s.stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, data);
        s.stream.write_all(b"thanks").await.unwrap();
        let back = tokio::time::timeout(Duration::from_secs(5), w)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&back, b"thank");
    }

    /// A small message and its reply cross KCP without waiting for KCP's
    /// 10 ms flush interval on either side.
    #[tokio::test]
    async fn small_messages_are_not_delayed() {
        let ep_a = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), false)
            .await
            .unwrap();
        let ep_b = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), true)
            .await
            .unwrap();
        let mut c = ep_a.dial(ep_b.local_addr().unwrap());
        c.stream.write_all(b"x").await.unwrap();
        let mut s = tokio::time::timeout(Duration::from_secs(5), async {
            ep_b.accept_rx.lock().await.recv().await.unwrap()
        })
        .await
        .unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 1];
            while s.stream.read_exact(&mut b).await.is_ok() {
                if s.stream.write_all(&b).await.is_err() {
                    break;
                }
            }
        });
        let mut b = [0u8; 1];
        c.stream.read_exact(&mut b).await.unwrap();
        let mut rtts = Vec::new();
        for _ in 0..30 {
            let t = Instant::now();
            c.stream.write_all(b"y").await.unwrap();
            c.stream.read_exact(&mut b).await.unwrap();
            rtts.push(t.elapsed());
            tokio::time::sleep(Duration::from_millis(7)).await;
        }
        rtts.sort();
        let median = rtts[rtts.len() / 2];
        assert!(median < Duration::from_millis(4), "median RTT {median:?}");
    }

    /// Over a lossy path, the sender's FEC ratio rises and the counters move.
    #[tokio::test]
    async fn lossy_link_turns_on_fec() {
        let ep_a = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), false)
            .await
            .unwrap();
        let ep_b = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), true)
            .await
            .unwrap();
        // A proxy dropping every 10th datagram in each direction.
        let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (b_addr, p) = (ep_b.local_addr().unwrap(), proxy.clone());
        tokio::spawn(async move {
            let (mut buf, mut a_addr, mut n) = (vec![0u8; 65536], None, 0u64);
            while let Ok((len, from)) = p.recv_from(&mut buf).await {
                n += 1;
                let to = if from == b_addr {
                    a_addr
                } else {
                    a_addr = Some(from);
                    Some(b_addr)
                };
                if n % 10 != 0
                    && let Some(to) = to
                {
                    let _ = p.send_to(&buf[..len], to).await;
                }
            }
        });
        let mut c = ep_a.dial(proxy.local_addr().unwrap());
        let stats = c.stats.clone();
        let w = tokio::spawn(async move {
            for _ in 0..40 {
                c.stream.write_all(&[7u8; 50_000]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            c
        });
        let mut s = tokio::time::timeout(Duration::from_secs(5), async {
            ep_b.accept_rx.lock().await.recv().await.unwrap()
        })
        .await
        .unwrap();
        let mut got = vec![0u8; 40 * 50_000];
        tokio::time::timeout(Duration::from_secs(30), s.stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        let _c = w.await.unwrap();
        let ratio = stats.fec_ratio_pct.load(Ordering::Relaxed);
        assert!(ratio > 0, "FEC ratio rose");
        assert!(
            stats.fec_parity_tx.load(Ordering::Relaxed) > 0,
            "parity sent"
        );
        assert!(
            stats.retrans.load(Ordering::Relaxed) > 0,
            "retransmits counted"
        );
        assert!(
            s.stats.fec_recovered.load(Ordering::Relaxed) > 0,
            "receiver recovered"
        );
    }

    /// Over a 20 Mbit/s path, the bandwidth estimate never goes far above
    /// 20 Mbit/s during a bulk transfer (it read 500 Mbit/s before): delivery samples cover enough time that a
    /// burst of acknowledgements in one tick is not taken for a fast path.
    #[tokio::test]
    async fn bandwidth_estimate_follows_the_path_rate() {
        const RATE_BPS: f64 = 20e6;
        let ep_a = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), false)
            .await
            .unwrap();
        let ep_b = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), true)
            .await
            .unwrap();
        // A proxy serializing a→b datagrams at RATE_BPS with a 50 ms queue.
        let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (b_addr, p) = (ep_b.local_addr().unwrap(), proxy.clone());
        tokio::spawn(async move {
            let (mut buf, mut a_addr) = (vec![0u8; 65536], None);
            let mut free_at = tokio::time::Instant::now();
            while let Ok((len, from)) = p.recv_from(&mut buf).await {
                if from == b_addr {
                    if let Some(a) = a_addr {
                        let _ = p.send_to(&buf[..len], a).await;
                    }
                    continue;
                }
                a_addr = Some(from);
                let now = tokio::time::Instant::now();
                let done =
                    free_at.max(now) + Duration::from_secs_f64((len + 28) as f64 * 8.0 / RATE_BPS);
                if done - now > Duration::from_millis(50) {
                    continue; // queue full: tail drop
                }
                free_at = done;
                let (p, d) = (p.clone(), buf[..len].to_vec());
                tokio::spawn(async move {
                    tokio::time::sleep_until(done).await;
                    let _ = p.send_to(&d, b_addr).await;
                });
            }
        });
        let mut c = ep_a.dial(proxy.local_addr().unwrap());
        let stats = c.stats.clone();
        let total = 4_000_000usize;
        let w = tokio::spawn(async move {
            c.stream.write_all(&vec![3u8; total]).await.unwrap();
            c
        });
        let mut s = tokio::time::timeout(Duration::from_secs(5), async {
            ep_b.accept_rx.lock().await.recv().await.unwrap()
        })
        .await
        .unwrap();
        let st = stats.clone();
        let peak = tokio::spawn(async move {
            let mut peak = 0u64;
            for _ in 0..1000 {
                peak = peak.max(st.bw_estimate_kbps.load(Ordering::Relaxed));
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            peak
        });
        let mut got = vec![0u8; total];
        tokio::time::timeout(Duration::from_secs(30), s.stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        let _c = w.await.unwrap();
        let peak = peak.await.unwrap();
        let limit_kbps = (RATE_BPS / 1000.0) as u64;
        assert!(
            peak > limit_kbps / 4 && peak < limit_kbps * 2,
            "peak estimate {peak} kbit/s on a {limit_kbps} kbit/s path"
        );
    }

    /// A burst of acknowledgements in one millisecond is not a sample of its
    /// own; it is averaged over the minimum interval.
    #[test]
    fn delivery_samples_span_the_minimum_interval() {
        let t0 = Instant::now();
        let ms = |n: u64| t0 + Duration::from_millis(n);
        let min = Duration::from_millis(25);
        let mut d = Delivery::new(t0);
        assert_eq!(d.on_tick(0, false, ms(0), min, false), None);
        // 60 kB acknowledged at once after 1 ms: too soon.
        assert_eq!(d.on_tick(60_000, false, ms(1), min, false), None);
        // 30 kB more at 30 ms: one sample over all 30 ms.
        let s = d.on_tick(30_000, false, ms(30), min, false).unwrap();
        assert_eq!(s.bytes, 90_000);
        assert_eq!(s.interval, Duration::from_millis(30));
        assert!(!s.app_limited);
        // The rest arrives 2 ms later and the sender goes idle: an
        // application-limited sample over the minimum interval.
        let s = d.on_tick(2_500, true, ms(32), min, false).unwrap();
        assert_eq!(s.bytes, 2_500);
        assert_eq!(s.interval, min);
        assert!(s.app_limited);
        // Idle with nothing delivered: no sample.
        assert_eq!(d.on_tick(0, true, ms(500), min, true), None);
    }

    /// While both ends push bulk data through a 20 Mbit/s, 20 ms path, the
    /// raw RTT stays near the path's (its delay plus the path's own queue),
    /// although each end has a large backlog of its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn raw_rtt_ignores_the_send_backlog() {
        const RATE_BPS: f64 = 20e6;
        let ep_a = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), false)
            .await
            .unwrap();
        let ep_b = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), true)
            .await
            .unwrap();
        // 10 ms each way, each direction serialized at RATE_BPS, 50 ms queue.
        let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (b_addr, p) = (ep_b.local_addr().unwrap(), proxy.clone());
        tokio::spawn(async move {
            let (mut buf, mut a_addr) = (vec![0u8; 65536], None);
            let mut free_at = [tokio::time::Instant::now(); 2];
            while let Ok((len, from)) = p.recv_from(&mut buf).await {
                let (dir, to) = if from == b_addr {
                    (1, a_addr)
                } else {
                    a_addr = Some(from);
                    (0, Some(b_addr))
                };
                let Some(to) = to else { continue };
                let now = tokio::time::Instant::now();
                let done = free_at[dir].max(now)
                    + Duration::from_secs_f64((len + 28) as f64 * 8.0 / RATE_BPS);
                if done - now > Duration::from_millis(50) {
                    continue;
                }
                free_at[dir] = done;
                let (p, d) = (p.clone(), buf[..len].to_vec());
                tokio::spawn(async move {
                    tokio::time::sleep_until(done + Duration::from_millis(10)).await;
                    let _ = p.send_to(&d, to).await;
                });
            }
        });
        let total = 6_000_000usize;
        let mut c = ep_a.dial(proxy.local_addr().unwrap());
        let stats = c.stats.clone();
        c.stream.write_all(&[0u8; 1]).await.unwrap();
        let mut s = tokio::time::timeout(Duration::from_secs(5), async {
            ep_b.accept_rx.lock().await.recv().await.unwrap()
        })
        .await
        .unwrap();
        let mut one = [0u8; 1];
        s.stream.read_exact(&mut one).await.unwrap();
        let _ = stats.take_sample();
        let (mut ca, mut cb) = tokio::io::split(c.stream);
        let (mut sa, mut sb) = tokio::io::split(s.stream);
        let push_a = tokio::spawn(async move { cb.write_all(&vec![1u8; total]).await });
        let push_b = tokio::spawn(async move { sb.write_all(&vec![2u8; total]).await });
        let pull_a = tokio::spawn(async move {
            let mut got = vec![0u8; total];
            ca.read_exact(&mut got).await.map(|_| ())
        });
        let pull_b = tokio::spawn(async move {
            let mut got = vec![0u8; total];
            sa.read_exact(&mut got).await.map(|_| ())
        });
        let mut worst: f64 = 0.0;
        let mut seen = 0;
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Some((mean, min)) = stats.take_sample().rtt_ms {
                seen += 1;
                worst = worst.max(mean);
                assert!(min >= 19.0, "min {min} ms below the path delay");
            }
        }
        assert!(seen >= 6, "raw RTT samples while loaded: {seen}");
        // 20 ms of delay plus at most 50 ms of queue each way.
        assert!(worst < 150.0, "raw RTT {worst} ms under load");
        for t in [push_a, push_b] {
            t.abort();
        }
        for t in [pull_a, pull_b] {
            t.abort();
        }
    }

    #[tokio::test]
    async fn accepted_sessions_are_bounded_across_sources() {
        let ep = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), true)
            .await
            .unwrap();
        let slots: Vec<_> = (0..MAX_HANDSHAKING)
            .map(|_| ep.handshake_slot().expect("a free slot"))
            .collect();
        assert!(ep.handshake_slot().is_none(), "all slots taken");
        assert_eq!(ep.handshaking.load(Ordering::Relaxed), MAX_HANDSHAKING);
        drop(slots);
        assert_eq!(ep.handshaking.load(Ordering::Relaxed), 0);
        assert!(ep.handshake_slot().is_some());
    }

    #[tokio::test]
    async fn an_old_session_leaves_its_successor_alone() {
        let ep = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), true)
            .await
            .unwrap();
        let key: (SocketAddr, u32) = ("127.0.0.1:9".parse().unwrap(), 7);
        let (tx, _rx) = mpsc::channel(1);
        ep.sessions.lock().insert(key, SessionHandle { tx, id: 2 });
        ep.forget_session(key, 1);
        assert!(
            ep.sessions.lock().contains_key(&key),
            "a newer session's entry"
        );
        ep.forget_session(key, 2);
        assert!(!ep.sessions.lock().contains_key(&key));
    }

    #[test]
    fn the_largest_datagram_a_peer_sends_fits_the_cap() {
        // An OPEN with a full FEC shard and the most padding.
        let shard = vec![0u8; fec::MAX_SHARD + fec::HDR];
        let inner = shard_frame(false, 1, &shard);
        let o = UdpObfs::new(&[1; 32]);
        o.set_epochs(&epochs().read());
        let d = o.seal(1, &inner, 95).unwrap();
        assert!(d.len() <= MAX_DATAGRAM, "{} > {MAX_DATAGRAM}", d.len());
    }

    #[tokio::test]
    async fn wrong_network_is_silent() {
        let ep_a = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), false)
            .await
            .unwrap();
        let ep_b = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[2; 32], epochs(), true)
            .await
            .unwrap();
        let mut c = ep_a.dial(ep_b.local_addr().unwrap());
        c.stream.write_all(b"hello").await.unwrap();
        let r = tokio::time::timeout(Duration::from_millis(500), async {
            ep_b.accept_rx.lock().await.recv().await
        })
        .await;
        assert!(r.is_err(), "no session must be created");
    }

    #[tokio::test]
    async fn punch_ping_is_answered_with_a_pong() {
        let ep_a = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), true)
            .await
            .unwrap();
        let ep_b = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), true)
            .await
            .unwrap();
        let (ta, mut ra) = mpsc::channel(8);
        let (tb, mut rb) = mpsc::channel(8);
        *ep_a.punch_events.lock() = Some(ta);
        *ep_b.punch_events.lock() = Some(tb);
        let token = [7u8; 16];
        ep_a.punch(ep_b.local_addr().unwrap(), &token).await;
        let at_b = tokio::time::timeout(Duration::from_secs(2), rb.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(at_b.from, ep_a.local_addr().unwrap());
        assert!(!at_b.pong);
        assert_eq!(at_b.token, token);
        let at_a = tokio::time::timeout(Duration::from_secs(2), ra.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(at_a.from, ep_b.local_addr().unwrap());
        assert!(at_a.pong);
        assert_eq!(at_a.token, token);
        // Another network's checks are dropped silently.
        let ep_c = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[2; 32], epochs(), true)
            .await
            .unwrap();
        ep_c.punch(ep_b.local_addr().unwrap(), &token).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(300), rb.recv())
                .await
                .is_err()
        );
    }
}
