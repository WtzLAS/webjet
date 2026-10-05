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
//!       | 3 PUNCH (padding only)                 — opens NAT mappings
//!       | 4 STATS (received[4] || expected[4])   — loss feedback for FEC
//! ```
//!
//! A session is created on the listening side only for a valid OPEN
//! (timestamp within ±60 s, fresh nonce); unknown sessions are dropped
//! silently (§9.1). KCP runs with its congestion window off and is paced by
//! a BBR-style controller.

use crate::fec;
use crate::gate::{GateResult, ReplayCache, SharedEpochs, UdpObfs, small_packet_padding};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::io::Write;
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

/// KCP MTU: leaves room for FEC (9), the inner header (5+24 on OPEN) and
/// obfuscation (42+2) inside a 1400-byte datagram.
pub const KCP_MTU: usize = 1300;
const DUPLEX: usize = 512 * 1024;
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
}

pub struct KcpConn {
    pub stream: DuplexStream,
    pub peer: SocketAddr,
    pub gate: GateResult,
    pub stats: Arc<KcpStats>,
}

struct SessionHandle {
    tx: mpsc::Sender<Vec<u8>>,
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
        });
        let e2 = ep.clone();
        tokio::spawn(async move { e2.recv_loop().await });
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

    /// Send PUNCH datagrams to open a NAT mapping toward `to` (§11.7).
    pub async fn punch(&self, to: SocketAddr) {
        let mut inner = vec![K_PUNCH, 0, 0, 0, 0];
        inner.extend_from_slice(&rand::random::<[u8; 8]>());
        if let Some(d) = self.seal(&inner) {
            let _ = self.sock.send_to(&d, to).await;
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
            let Some((gate, inner)) = self.obfs.open(&buf[..n], &self.epochs.read()) else {
                continue;
            };
            let (Some(&kind), Some(conv)) = (inner.first(), webjet_core::bytes::be_u32(&inner, 1))
            else {
                continue;
            };
            let body = &inner[5..];
            if kind == K_PUNCH {
                continue;
            }
            let key = (from, conv);
            let existing = self.sessions.lock().get(&key).map(|h| h.tx.clone());
            if let Some(tx) = existing {
                let mut d = Vec::with_capacity(1 + body.len());
                d.push(kind);
                d.extend_from_slice(body);
                let _ = tx.try_send(d);
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
            if !self.replay.check_and_insert(nonce, now_ms()) {
                continue;
            }
            if !self.admit_ip(from.ip()) {
                continue;
            }
            let (stream, tx, stats) = self.clone().spawn_session(from, conv);
            let mut d = vec![K_OPEN];
            d.extend_from_slice(body);
            let _ = tx.try_send(d);
            if self
                .accept_tx
                .try_send(KcpConn {
                    stream,
                    peer: from,
                    gate,
                    stats,
                })
                .is_err()
            {
                self.sessions.lock().remove(&key);
            }
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
        let (stream, _tx, stats) = self.clone().spawn_session_inner(to, conv, true);
        let gate = GateResult::Normal(self.epochs.read().current);
        KcpConn {
            stream,
            peer: to,
            gate,
            stats,
        }
    }

    fn spawn_session(
        self: Arc<Self>,
        peer: SocketAddr,
        conv: u32,
    ) -> (DuplexStream, mpsc::Sender<Vec<u8>>, Arc<KcpStats>) {
        self.spawn_session_inner(peer, conv, false)
    }

    fn spawn_session_inner(
        self: Arc<Self>,
        peer: SocketAddr,
        conv: u32,
        dialer: bool,
    ) -> (DuplexStream, mpsc::Sender<Vec<u8>>, Arc<KcpStats>) {
        let (user, inner) = tokio::io::duplex(DUPLEX);
        let (tx, rx) = mpsc::channel(4096);
        self.sessions
            .lock()
            .insert((peer, conv), SessionHandle { tx: tx.clone() });
        let stats = Arc::new(KcpStats::default());
        let st = stats.clone();
        tokio::spawn(async move {
            let ep = self.clone();
            run_session(ep, peer, conv, dialer, inner, rx, st).await;
            self.sessions.lock().remove(&(peer, conv));
        });
        (user, tx, stats)
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

/// KCP output sink: collects packets for the session task to FEC-wrap and pace.
#[derive(Clone, Default)]
struct OutQueue(Arc<Mutex<VecDeque<Vec<u8>>>>);

impl Write for OutQueue {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().push_back(buf.to_vec());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn run_session(
    ep: Arc<UdpEndpoint>,
    peer: SocketAddr,
    conv: u32,
    dialer: bool,
    mut user: DuplexStream,
    mut rx: mpsc::Receiver<Vec<u8>>,
    stats: Arc<KcpStats>,
) {
    let out = OutQueue::default();
    let mut kcp = kcp::Kcp::new_stream(conv, out.clone());
    let _ = kcp.set_mtu(KCP_MTU);
    kcp.set_nodelay(true, 10, 2, true); // no-delay, 10 ms, fast resend after 2 dup acks, no cwnd
    kcp.set_wndsize(256, 1024);
    let start = Instant::now();
    let ms = |t: Instant| t.duration_since(start).as_millis() as u32;
    let mut enc = fec::Encoder::new();
    let mut dec = fec::Decoder::new();
    let mut bbr = Bbr::new();
    let mut opened = !dialer; // the dialer sends OPENs until it hears back
    let mut last_rx = Instant::now();
    let mut paced: VecDeque<Vec<u8>> = VecDeque::new();
    let mut tokens: f64 = 16_000.0;
    let mut last_tick = Instant::now();
    let mut fec_flush_at: Option<Instant> = None;
    let mut last_wait_snd = 0usize;
    let mut last_delivery = Instant::now();
    let mut stats_sent_at = Instant::now();
    let mut next_new_sn: Option<u32> = None;
    let mut user_buf = vec![0u8; 16 * 1024];
    let mut user_open = true;
    let mut tick = tokio::time::interval(Duration::from_millis(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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
        // Pull more user data only while KCP's send queue is short (§17.2).
        let can_take = user_open && kcp.wait_snd() < bbr.window() as usize * 2;
        // New data or acknowledgements to send: flush KCP now instead of at
        // its next 10 ms interval, which added up to 10 ms per direction and
        // per hop (and delayed acknowledgements inflated KCP's RTT).
        let mut flush_now = false;
        tokio::select! {
            r = user.read(&mut user_buf), if can_take => {
                match r {
                    Ok(0) | Err(_) => { user_open = false; }
                    Ok(n) => {
                        let _ = kcp.send(&user_buf[..n]);
                        flush_now = true;
                    }
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
                for d in batch {
                    stats.wire_rx.fetch_add(d.len() as u64, Ordering::Relaxed);
                    let (kind, body) = (d[0], &d[1..]);
                    let shard = match kind {
                        K_SHARD => body,
                        K_OPEN if body.len() >= 24 => &body[24..],
                        K_STATS if body.len() >= 8 => {
                            let recv = webjet_core::bytes::be_u32(body, 0).unwrap_or(0) as f64;
                            let exp = webjet_core::bytes::be_u32(body, 4).unwrap_or(0) as f64;
                            if exp > 0.0 {
                                enc.adapt(((exp - recv) / exp).clamp(0.0, 1.0));
                                stats.fec_ratio_pct.store((enc.ratio * 100.0) as u64, Ordering::Relaxed);
                            }
                            continue;
                        }
                        _ => continue,
                    };
                    for pkt in dec.push(shard) {
                        let _ = kcp.input(&pkt);
                        flush_now = true;
                    }
                }
                stats.fec_recovered.store(dec.recovered, Ordering::Relaxed);
                // Deliver received bytes to the user.
                while let Ok(n) = kcp.peeksize() {
                    let mut b = vec![0u8; n];
                    if kcp.recv(&mut b).is_err() { break; }
                    if user.write_all(&b).await.is_err() { user_open = false; break; }
                }
            }
            _ = tick.tick() => {}
        }
        let now = Instant::now();
        if let Err(e) = kcp.update(ms(now)) {
            tracing::debug!("kcp update: {e}");
        }
        if flush_now && let Err(e) = kcp.flush() {
            tracing::debug!("kcp flush: {e}");
        }
        // Delivery-rate sample from bytes leaving KCP's send buffer.
        let ws = kcp.wait_snd();
        if ws < last_wait_snd {
            let delivered = (last_wait_snd - ws) * KCP_MTU;
            // Neither the window nor the pacer held data back: the sender
            // had no more to send, so the sample is application-limited.
            let app_limited = paced.is_empty() && last_wait_snd < bbr.window() as usize;
            bbr.on_delivery(
                delivered,
                now.duration_since(last_delivery),
                now,
                app_limited,
            );
            last_delivery = now;
        } else if ws == 0 {
            last_delivery = now;
        }
        last_wait_snd = ws;
        bbr.ceiling = ep.rate_ceiling_bps.load(Ordering::Relaxed) as f64 / 8.0;
        let wnd = bbr.window();
        kcp.set_wndsize(wnd, 1024);
        stats
            .bw_estimate_kbps
            .store((bbr.btl_bw * 8.0 / 1000.0) as u64, Ordering::Relaxed);
        // FEC-wrap new KCP packets; parity counts toward the paced rate.
        let pkts: Vec<Vec<u8>> = out.0.lock().drain(..).collect();
        for p in pkts {
            let re = count_retransmits(&p, &mut next_new_sn);
            if re > 0 {
                stats.retrans.fetch_add(re, Ordering::Relaxed);
            }
            for s in enc.push(&p) {
                paced.push_back(s);
            }
            if fec_flush_at.is_none() {
                fec_flush_at = Some(now + Duration::from_millis(15));
            }
        }
        if fec_flush_at.map(|t| now >= t).unwrap_or(false) {
            for s in enc.flush() {
                paced.push_back(s);
            }
            fec_flush_at = None;
        }
        stats
            .fec_parity_tx
            .store(enc.parity_bytes, Ordering::Relaxed);
        // Loss feedback for the peer's FEC (§17.6).
        if now.duration_since(stats_sent_at) > Duration::from_secs(1) {
            // Line loss before FEC recovery, counted from shard group gaps.
            let (received, expected) = dec.take_loss();
            if expected > 0 {
                let mut inner = vec![K_STATS];
                inner.extend_from_slice(&conv.to_be_bytes());
                inner.extend_from_slice(&(received.min(u64::from(u32::MAX)) as u32).to_be_bytes());
                inner.extend_from_slice(&(expected.min(u64::from(u32::MAX)) as u32).to_be_bytes());
                seal_and_send(inner).await;
            }
            stats_sent_at = now;
            if let Some(rtt) = kcp_rtt(&kcp) {
                bbr.on_rtt(rtt, now);
            }
        }
        // Pace.
        let rate = bbr.pacing_rate(now);
        tokens = (tokens + now.duration_since(last_tick).as_secs_f64() * rate)
            .min(rate * 0.01 + 16_000.0);
        last_tick = now;
        while paced.front().is_some_and(|s| tokens >= s.len() as f64) {
            let Some(s) = paced.pop_front() else { break };
            tokens -= s.len() as f64;
            let mut inner = Vec::with_capacity(s.len() + 30);
            if opened {
                inner.push(K_SHARD);
                inner.extend_from_slice(&conv.to_be_bytes());
            } else {
                inner.push(K_OPEN);
                inner.extend_from_slice(&conv.to_be_bytes());
                inner.extend_from_slice(&now_ms().to_be_bytes());
                inner.extend_from_slice(&rand::random::<[u8; 16]>());
            }
            inner.extend_from_slice(&s);
            seal_and_send(inner).await;
        }
        if paced.len() > 8192 {
            paced.drain(..paced.len() - 8192);
        }
        if now.duration_since(last_rx) > IDLE_TIMEOUT || kcp.is_dead_link() {
            break;
        }
        if !user_open && kcp.wait_snd() == 0 && paced.is_empty() {
            break;
        }
    }
}

/// KCP segment header: conv[4] cmd[1] frg[1] wnd[2] ts[4] sn[4] una[4] len[4],
/// little-endian.
const KCP_SEG_HDR: usize = 24;
const KCP_CMD_PUSH: u8 = 81;

/// Count the data segments in one KCP output packet that were sent before:
/// KCP sends new segments in sequence order, so a PUSH whose number is below
/// the next new one is a retransmission (timeout or fast resend; §12.3
/// `kcp_retrans`). The `kcp` crate counts only timeouts, and privately.
fn count_retransmits(pkt: &[u8], next_new_sn: &mut Option<u32>) -> u64 {
    let le = |at: usize| webjet_core::bytes::array::<4>(pkt, at).map(u32::from_le_bytes);
    let mut n = 0;
    let mut at = 0;
    while let (Some(&cmd), Some(sn), Some(len)) = (pkt.get(at + 4), le(at + 12), le(at + 20)) {
        if cmd == KCP_CMD_PUSH {
            match *next_new_sn {
                Some(next) if sn.wrapping_sub(next) >= u32::MAX / 2 => n += 1,
                _ => *next_new_sn = Some(sn.wrapping_add(1)),
            }
        }
        at += KCP_SEG_HDR + len as usize;
    }
    n
}

fn kcp_rtt<O>(k: &kcp::Kcp<O>) -> Option<Duration> {
    // The kcp crate doesn't expose srtt; use its debug output as a source of truth.
    let s = format!("{k:?}");
    let i = s.find("rx_srtt: ")?;
    let rest = &s[i + 9..];
    let end = rest.find(|c: char| !c.is_ascii_digit())?;
    rest[..end]
        .parse::<u64>()
        .ok()
        .filter(|v| *v > 0)
        .map(Duration::from_millis)
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

    #[test]
    fn counts_kcp_retransmits() {
        let (a_out, b_out) = (OutQueue::default(), OutQueue::default());
        let mut a = kcp::Kcp::new_stream(7, a_out.clone());
        let mut b = kcp::Kcp::new_stream(7, b_out.clone());
        for k in [&mut a, &mut b] {
            k.set_mtu(KCP_MTU).unwrap();
            k.set_nodelay(true, 10, 2, true);
        }
        a.send(&vec![9u8; 20 * 1200]).unwrap();
        let (mut next, mut re, mut dropped) = (None, 0, false);
        for t in (0..3000).step_by(10) {
            a.update(t).unwrap();
            for p in a_out.0.lock().drain(..).collect::<Vec<_>>() {
                re += count_retransmits(&p, &mut next);
                if !dropped && get_sn(&p) == 3 {
                    dropped = true; // lose one data packet once
                    continue;
                }
                b.input(&p).unwrap();
            }
            b.update(t).unwrap();
            for p in b_out.0.lock().drain(..).collect::<Vec<_>>() {
                a.input(&p).unwrap();
            }
            while b.recv(&mut [0u8; 65536]).is_ok() {}
        }
        assert_eq!(a.wait_snd(), 0, "all delivered");
        assert_eq!(re, 1, "the one lost segment was resent once");
    }

    fn get_sn(p: &[u8]) -> u32 {
        u32::from_le_bytes([p[12], p[13], p[14], p[15]])
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
}
