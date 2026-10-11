//! Hole punching (§11.7), ICE-style.
//!
//! 1. **Gathering.** Each side lists its candidates: a router port mapping
//!    (UPnP / NAT-PMP / PCP), public and reflexive addresses, then local
//!    interface addresses (public first). Tunnel interfaces (other VPNs)
//!    are left out (`nat`).
//! 2. **Exchange** inside the end-to-end session: `PUNCH_OFFER` both ways
//!    with one nonce, then `PUNCH_GO`. The responder starts on GO, the
//!    initiator half a round trip after sending it.
//! 3. **Connectivity checks.** Both sides send PINGs (tagged with the
//!    nonce) to every candidate of the other for several seconds; a PING
//!    that arrives is answered with a PONG to its source. A PING from an
//!    address the peer never offered is a peer-reflexive candidate (its
//!    NAT picked a new port): it is checked too. Toward a peer behind a
//!    symmetric NAT we also probe the ports next to its reflexive ports
//!    (port prediction). NAT types never stop an attempt: two nodes behind
//!    one NAT look symmetric to relays but reach each other on the LAN.
//! 4. **Nomination.** The first address that answers a PONG is reachable
//!    both ways. The lower node id dials it at once (the higher one a
//!    second later if no hop came up); the KCP OPEN uses the mappings the
//!    checks opened. If that dial fails (another node at the same private
//!    address answered), the address is dropped and checks go on until the
//!    window ends. Without any answer (a peer from before checks were
//!    answered) the lower id dials every candidate at once at the end.
//! 5. **Retry** while the session is in use: 15 s, doubling to 5 min, and
//!    at once when either side's endpoint record changes or the direct hop
//!    goes down.

use crate::node::Node;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use webjet_core::crypto::{self, Bytes32};
use webjet_core::frames::ftype;
use webjet_net::kcp::PunchEvent;
use webjet_proto::{self as wp, Decodable, Encodable, Transport};

/// Candidates sent / accepted per side.
const MAX_CANDIDATES: usize = 12;
/// Peer-reflexive candidates learned per attempt.
const MAX_PRFLX: usize = 8;
/// How long checks run.
const WINDOW: Duration = Duration::from_secs(6);
/// Check rounds: fast at first, then slower.
const FAST_GAP: Duration = Duration::from_millis(50);
const FAST_FOR: Duration = Duration::from_secs(1);
const SLOW_GAP: Duration = Duration::from_millis(200);
/// Port prediction: ports after (and a few before) a reflexive port.
const PREDICT_AFTER: u16 = 96;
const PREDICT_BEFORE: u16 = 8;
const PREDICT_FOR: Duration = Duration::from_secs(3);
const PREDICT_GAP: Duration = Duration::from_millis(500);
/// Retry backoff.
const FIRST_RETRY: Duration = Duration::from_secs(15);
const MAX_RETRY: Duration = Duration::from_secs(300);
/// The higher id's first attempt waits this long (the lower id goes first).
const HIGHER_ID_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct Attempt {
    nonce: [u8; 16],
    /// We sent the first offer.
    initiator: bool,
    /// The peer's offered candidates, then peer-reflexive ones.
    theirs: Vec<SocketAddr>,
    prflx: usize,
    /// The address being dialed: the first one that answered a check.
    validated: Option<SocketAddr>,
    /// Addresses that answered a check but whose dial failed: another
    /// node of the network at the same private address on our LAN (two
    /// LANs often share a subnet), or ourselves. Checks go on without them.
    rejected: Vec<SocketAddr>,
    started: Instant,
    probing: bool,
    dialing: bool,
    predict: bool,
}

#[derive(Debug, Default)]
struct PeerState {
    attempt: Option<Attempt>,
    next_try: Option<Instant>,
    backoff: Duration,
    /// For `local sessions`: how the last attempt ended.
    last: Option<(Instant, String)>,
}

/// Each peer's punching state; one per node (`Node::punch`).
#[derive(Default)]
pub struct Table(Mutex<HashMap<Bytes32, PeerState>>);

fn table(n: &Node) -> &Mutex<HashMap<Bytes32, PeerState>> {
    &n.punch.0
}

fn has_direct_udp(n: &Node, peer: &Bytes32) -> bool {
    n.hops_to(peer)
        .iter()
        .any(|h| h.transport == Transport::KcpFecTls)
}

/// Our candidates, best first (§11.7 rules, plus the router's mapping).
fn my_candidates(n: &Node) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    if let Some(m) = *n.port_mapping.lock() {
        out.push(m.external);
    }
    let mut addrs = crate::transport::my_addrs(n);
    addrs.retain(|a| a.transport == Transport::KcpFecTls);
    addrs.sort_by_key(|a| match a.kind {
        wp::AddrKind::Public => 0,
        wp::AddrKind::Reflexive => 1,
        wp::AddrKind::Host => 2,
    });
    for a in addrs.iter().filter_map(|a| a.addr.as_ref()?.to_sock()) {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out.truncate(MAX_CANDIDATES);
    out
}

fn nat_of(n: &Node, peer: &Bytes32) -> wp::NatType {
    n.records
        .lock()
        .endpoints
        .get(peer)
        .map_or(wp::NatType::Unknown, |(r, _)| r.nat)
}

/// Punch unless a direct UDP hop exists or either side turned UDP off. The
/// NAT types don't matter: two nodes behind one NAT (on one LAN) look
/// symmetric to relays yet reach each other's HOST candidates, and port
/// prediction may still meet across two symmetric NATs.
fn should_try(n: &Node, peer: &Bytes32) -> bool {
    !has_direct_udp(n, peer)
        && crate::transport::priority(n, &n.me, Transport::KcpFecTls) != 0
        && crate::transport::priority(n, peer, Transport::KcpFecTls) != 0
}

/// Port prediction applies when the peer's NAT is symmetric (whatever ours
/// is: two symmetric NATs that hand out ports in sequence can still meet).
fn should_predict(n: &Node, peer: &Bytes32) -> bool {
    matches!(nat_of(n, peer), wp::NatType::Symmetric)
}

/// Start punching toward `peer` once a session exists, unless we already
/// hold a direct UDP hop or an attempt is running. The lower node id goes
/// first; the higher one tries too (later), so either side can start.
pub fn maybe_start(n: &Arc<Node>, peer: &Bytes32) {
    if !should_try(n, peer) {
        return;
    }
    let now = Instant::now();
    let mut t = table(n).lock();
    let st = t.entry(*peer).or_default();
    if st
        .attempt
        .as_ref()
        .is_some_and(|a| now.duration_since(a.started) < WINDOW * 3)
    {
        return;
    }
    match st.next_try {
        None if n.me > *peer => {
            st.next_try = Some(now + HIGHER_ID_DELAY);
            return;
        }
        Some(at) if now < at => return,
        _ => {}
    }
    st.backoff = if st.backoff.is_zero() {
        FIRST_RETRY
    } else {
        (st.backoff * 2).min(MAX_RETRY)
    };
    st.next_try = Some(now + st.backoff);
    let nonce = crypto::random16();
    st.attempt = Some(Attempt {
        nonce,
        initiator: true,
        theirs: Vec::new(),
        prflx: 0,
        validated: None,
        rejected: Vec::new(),
        started: now,
        probing: false,
        dialing: false,
        predict: false,
    });
    drop(t);
    send_offer(n, peer, nonce);
}

fn send_offer(n: &Arc<Node>, peer: &Bytes32, nonce: [u8; 16]) {
    let offer = wp::PunchOffer {
        candidates: Some(
            my_candidates(n)
                .into_iter()
                .map(wp::SockAddr::from_sock)
                .collect(),
        ),
        nonce: Some(wp::Id16::from_bytes(&nonce)),
    };
    crate::e2e::send(n, peer, ftype::PUNCH_OFFER, &offer.encode_bytes(), 0);
}

/// Half the measured end-to-end round trip (§11.7: the initiator starts
/// that long after sending GO).
fn half_rtt(n: &Node, peer: &Bytes32) -> Duration {
    let rtt = n
        .circuits
        .lock()
        .local_circuits(peer)
        .iter()
        .filter_map(|c| *c.e2e_rtt_ms.lock())
        .fold(f64::INFINITY, f64::min);
    if rtt.is_finite() {
        Duration::from_micros((rtt * 500.0) as u64)
    } else {
        Duration::from_millis(50)
    }
}

pub fn on_message(n: &Arc<Node>, peer: &Bytes32, ty: u8, payload: &[u8]) {
    match ty {
        ftype::PUNCH_OFFER => {
            let Ok(o) = wp::PunchOffer::decode_bytes(payload) else {
                return;
            };
            let nonce = o.nonce.map(|x| x.to_bytes()).unwrap_or_default();
            // Our own addresses: a peer on another LAN with the same subnet
            // may offer an address that is ours here.
            let mine = my_candidates(n);
            let cands: Vec<SocketAddr> = o
                .candidates
                .unwrap_or_default()
                .iter()
                .filter_map(|c| c.to_sock())
                .filter(|a| crate::nat::dialable(n, a) && !mine.contains(a))
                .take(MAX_CANDIDATES)
                .collect();
            let predict = should_predict(n, peer);
            let try_ok = should_try(n, peer);
            let mut t = table(n).lock();
            let st = t.entry(*peer).or_default();
            let ours = st.attempt.as_ref().map(|a| (a.nonce, a.initiator));
            match ours {
                // The answer to our offer: GO, and start half an RTT later.
                Some((mine, true)) if mine == nonce => {
                    let Some(a) = st.attempt.as_mut() else { return };
                    if a.probing {
                        return;
                    }
                    a.theirs = cands;
                    a.predict = predict;
                    a.probing = true;
                    drop(t);
                    let go = wp::PunchGo {
                        nonce: Some(wp::Id16::from_bytes(&nonce)),
                    };
                    crate::e2e::send(n, peer, ftype::PUNCH_GO, &go.encode_bytes(), 0);
                    spawn_probes(n, *peer, half_rtt(n, peer));
                }
                // A repeated offer of the attempt we answer: nothing new.
                Some((theirs, false)) if theirs == nonce => {}
                // Both started at once: the lower id's attempt goes on.
                Some((_, true)) if n.me < *peer => {}
                _ => {
                    if !try_ok {
                        return;
                    }
                    st.attempt = Some(Attempt {
                        nonce,
                        initiator: false,
                        theirs: cands,
                        prflx: 0,
                        validated: None,
                        rejected: Vec::new(),
                        started: Instant::now(),
                        probing: false,
                        dialing: false,
                        predict,
                    });
                    drop(t);
                    send_offer(n, peer, nonce);
                }
            }
        }
        ftype::PUNCH_GO => {
            let Ok(g) = wp::PunchGo::decode_bytes(payload) else {
                return;
            };
            let go = g.nonce.map(|x| x.to_bytes());
            let start = {
                let mut t = table(n).lock();
                match t.get_mut(peer).and_then(|s| s.attempt.as_mut()) {
                    Some(a) if Some(a.nonce) == go && !a.initiator && !a.probing => {
                        a.probing = true;
                        a.started = Instant::now();
                        true
                    }
                    _ => false,
                }
            };
            if start {
                spawn_probes(n, *peer, Duration::ZERO);
            }
        }
        _ => {}
    }
}

/// Ports near the peer's first two outside addresses (peer-reflexive ones
/// come first, then its offer order: mapping, public, reflexive), for a
/// symmetric NAT that hands out ports in sequence. Its LAN addresses are
/// left out when it offered an outside one.
fn predicted(theirs: &[SocketAddr]) -> Vec<SocketAddr> {
    let outside: Vec<&SocketAddr> = theirs
        .iter()
        .filter(|a| crate::nat::is_global(&a.ip()))
        .collect();
    let pick: Vec<&SocketAddr> = if outside.is_empty() {
        theirs.iter().filter(|a| !a.ip().is_loopback()).collect()
    } else {
        outside
    };
    let mut v = Vec::new();
    for a in pick.into_iter().take(2) {
        let base = a.port();
        let lo = base.saturating_sub(PREDICT_BEFORE).max(1024);
        let hi = base.saturating_add(PREDICT_AFTER);
        v.extend(
            (lo..=hi)
                .filter(|p| *p != base)
                .map(|p| SocketAddr::new(a.ip(), p)),
        );
    }
    v
}

fn spawn_probes(n: &Arc<Node>, peer: Bytes32, wait: Duration) {
    let n = n.clone();
    tokio::spawn(async move {
        tokio::time::sleep(wait).await;
        let Some(ep) = n.udp.get().cloned() else {
            return;
        };
        let t0 = Instant::now();
        let mut last_predict: Option<Instant> = None;
        while t0.elapsed() < WINDOW {
            let snapshot = table(&n)
                .lock()
                .get(&peer)
                .and_then(|s| s.attempt.as_ref())
                .map(|a| (a.nonce, a.theirs.clone(), a.predict, a.validated));
            let Some((nonce, theirs, predict, validated)) = snapshot else {
                return;
            };
            if has_direct_udp(&n, &peer) {
                finish(&n, &peer, None);
                return;
            }
            if validated.is_none() {
                for c in &theirs {
                    ep.punch(*c, &nonce).await;
                }
                if predict
                    && t0.elapsed() < PREDICT_FOR
                    && last_predict.is_none_or(|t| t.elapsed() >= PREDICT_GAP)
                {
                    last_predict = Some(Instant::now());
                    for (i, c) in predicted(&theirs).into_iter().enumerate() {
                        ep.punch(c, &nonce).await;
                        if i % 32 == 31 {
                            tokio::task::yield_now().await;
                        }
                    }
                }
            } else {
                // Keep the mapping warm while the dial runs.
                if let Some(v) = validated {
                    ep.punch(v, &nonce).await;
                }
            }
            let gap = if t0.elapsed() < FAST_FOR {
                FAST_GAP
            } else {
                SLOW_GAP
            };
            tokio::time::sleep(gap).await;
        }
        // No answer to any check: a peer from before checks were answered,
        // or answers were lost. The lower id dials everything at once.
        let state = table(&n)
            .lock()
            .get(&peer)
            .and_then(|s| s.attempt.as_ref())
            .map(|a| (a.validated.is_some() || a.dialing, a.theirs.clone()));
        match state {
            Some((false, theirs)) if n.me < peer && !has_direct_udp(&n, &peer) => {
                mark_dialing(&n, &peer);
                let tries = theirs
                    .into_iter()
                    .map(|c| dial(n.clone(), peer, c, "blind"));
                let ok = futures::future::join_all(tries)
                    .await
                    .into_iter()
                    .any(|x| x);
                if !ok {
                    finish(&n, &peer, Some("no candidate answered".into()));
                }
            }
            Some((false, _)) => {
                tokio::time::sleep(Duration::from_secs(12)).await;
                if !has_direct_udp(&n, &peer) {
                    finish(&n, &peer, Some("no candidate answered".into()));
                }
            }
            _ => {}
        }
    });
}

fn mark_dialing(n: &Node, peer: &Bytes32) -> bool {
    let mut t = table(n).lock();
    match t.get_mut(peer).and_then(|s| s.attempt.as_mut()) {
        Some(a) if !a.dialing => {
            a.dialing = true;
            true
        }
        _ => false,
    }
}

/// End the attempt; `None` = success (backoff reset).
fn finish(n: &Node, peer: &Bytes32, failure: Option<String>) {
    let mut t = table(n).lock();
    let Some(st) = t.get_mut(peer) else { return };
    if st.attempt.take().is_none() {
        return;
    }
    match failure {
        None => {
            st.backoff = Duration::ZERO;
            st.last = Some((Instant::now(), "direct".into()));
        }
        Some(why) => {
            tracing::debug!(peer = %n.name_of(peer), "hole punching failed: {why}");
            st.last = Some((Instant::now(), why));
        }
    }
}

/// The dial to a validated address failed: the PONG came from someone else
/// (another node at the same private address on our LAN, or ourselves).
/// Drop the address and let the checks go on while the window lasts, so
/// the next address that answers is nominated; afterwards the attempt
/// fails.
fn reject(n: &Node, peer: &Bytes32, addr: SocketAddr) {
    {
        let mut t = table(n).lock();
        let Some(a) = t.get_mut(peer).and_then(|s| s.attempt.as_mut()) else {
            return;
        };
        // A dial from an attempt that is gone (a new one took its place).
        if a.validated != Some(addr) {
            return;
        }
        if !a.rejected.contains(&addr) {
            a.rejected.push(addr);
        }
        a.theirs.retain(|c| *c != addr);
        // `started` is at or before the probe loop's start, so the loop
        // still runs and will judge the outcome at the end of its window.
        if a.started.elapsed() < WINDOW {
            tracing::debug!(peer = %n.name_of(peer), %addr, "punch: dial failed, checks go on");
            a.validated = None;
            a.dialing = false;
            return;
        }
    }
    finish(n, peer, Some(format!("dial to {addr} failed")));
}

/// Dial `addr` over the opened mappings; returns whether a hop came up.
async fn dial(n: Arc<Node>, peer: Bytes32, addr: SocketAddr, how: &'static str) -> bool {
    let key = n.store.read().view().nodes.get(&peer).map(|x| x.key);
    let Some(key) = key else { return false };
    match n.dial(addr, Transport::KcpFecTls, vec![key]).await {
        Ok(_) => {
            tracing::info!(peer = %n.name_of(&peer), %addr, how, "hole punching succeeded");
            finish(&n, &peer, None);
            // A direct circuit becomes a path candidate (§11.7 step 3).
            let _ = crate::circuit::open(&n, peer, Vec::new()).await;
            true
        }
        Err(e) => {
            // The other side may have dialed first (its hop counts).
            if has_direct_udp(&n, &peer) {
                finish(&n, &peer, None);
                return true;
            }
            tracing::debug!(peer = %n.name_of(&peer), %addr, "punch dial: {e}");
            false
        }
    }
}

/// A check arrived on the UDP socket.
fn on_check(n: &Arc<Node>, ev: PunchEvent) {
    if !crate::nat::dialable(n, &ev.from) {
        return;
    }
    let mut t = table(n).lock();
    let Some((peer, a)) = t.iter_mut().find_map(|(p, s)| {
        s.attempt
            .as_mut()
            .filter(|a| a.nonce == ev.token)
            .map(|a| (*p, a))
    }) else {
        return;
    };
    if !ev.pong {
        // A PING from an address the peer didn't offer: its NAT mapped a
        // new port for us. Check it too (it gets our PONG already).
        if !a.theirs.contains(&ev.from) && !a.rejected.contains(&ev.from) && a.prflx < MAX_PRFLX {
            a.prflx += 1;
            a.theirs.insert(0, ev.from);
        }
        return;
    }
    if a.validated.is_some() || a.rejected.contains(&ev.from) {
        return;
    }
    a.validated = Some(ev.from);
    let how = if a.theirs.first() == Some(&ev.from) && a.prflx > 0 {
        "peer-reflexive"
    } else if a.theirs.contains(&ev.from) {
        "candidate"
    } else {
        "predicted port"
    };
    drop(t);
    let n = n.clone();
    tokio::spawn(async move {
        if n.me > peer {
            // The lower id dials; step in only if nothing came up.
            tokio::time::sleep(Duration::from_millis(1500)).await;
            if has_direct_udp(&n, &peer) {
                finish(&n, &peer, None);
                return;
            }
        }
        if mark_dialing(&n, &peer) && !dial(n.clone(), peer, ev.from, how).await {
            reject(&n, &peer, ev.from);
        }
    });
}

/// Punch state per peer, for `local sessions`.
pub fn status(n: &Node) -> serde_json::Value {
    let t = table(n).lock();
    let mut out = serde_json::Map::new();
    for (peer, s) in t.iter() {
        out.insert(
            n.name_of(peer),
            serde_json::json!({
                "peer_id": hex::encode(peer),
                "running": s.attempt.as_ref().map(|a| serde_json::json!({
                    "initiator": a.initiator,
                    "age_ms": a.started.elapsed().as_millis() as u64,
                    "candidates": a.theirs.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                    "validated": a.validated.map(|v| v.to_string()),
                    "rejected": a.rejected.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                    "port_prediction": a.predict,
                })),
                "last": s.last.as_ref().map(|(at, why)| serde_json::json!({"result": why, "age_s": at.elapsed().as_secs()})),
                "next_try_s": s.next_try.map(|at| at.saturating_duration_since(Instant::now()).as_secs()),
            }),
        );
    }
    serde_json::json!({"mine": my_candidates(n).iter().map(|c| c.to_string()).collect::<Vec<_>>(), "nat": format!("{:?}", crate::transport::nat_type(n)), "peers": out})
}

/// Retry punching for active sessions on the backoff schedule, and
/// immediately when a peer's EndpointRecord changes or its direct hop
/// goes down. Also receives the connectivity checks.
pub async fn run(n: Arc<Node>) {
    let (tx, mut checks) = tokio::sync::mpsc::channel::<PunchEvent>(1024);
    // The UDP endpoint starts with the listeners; wait for it.
    loop {
        if let Some(ep) = n.udp.get() {
            *ep.punch_events.lock() = Some(tx);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let mut ev = n.events.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    let active = |n: &Node, id: &Bytes32| {
        n.e2e.get(id).is_some_and(|s| {
            s.established() && s.last_used.lock().elapsed() < Duration::from_secs(60)
        })
    };
    loop {
        tokio::select! {
            Some(c) = checks.recv() => on_check(&n, c),
            e = ev.recv() => {
                let id = match e {
                    Ok(crate::node::Event::RecordsChanged(id)) if id != n.me => id,
                    Ok(crate::node::Event::HopDown(id)) => id,
                    _ => continue,
                };
                if active(&n, &id) {
                    if let Some(st) = table(&n).lock().get_mut(&id) {
                        st.next_try = Some(Instant::now());
                    }
                    maybe_start(&n, &id);
                }
            }
            _ = tick.tick() => {
                for s in n.e2e.all() {
                    if active(&n, &s.peer) {
                        maybe_start(&n, &s.peer);
                    }
                }
                // Forget peers without sessions.
                table(&n).lock().retain(|p, s| s.attempt.is_some() || n.e2e.get(p).is_some());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testnode::{self, Cluster};

    /// Two nodes that may talk, as (lower id, higher id).
    fn pair() -> (Arc<Node>, Arc<Node>, Vec<tempfile::TempDir>) {
        let mut c = Cluster::new();
        let a = c.data_node("a", "10.7.0.2", &[]);
        let b = c.data_node("b", "10.7.0.3", &[]);
        c.set_policy(wp::Policy {
            default_action: wp::Action::Allow,
            ..Default::default()
        })
        .expect("policy");
        let (an, d1) = testnode::node(&mut c, a.0, a.1);
        let (bn, d2) = testnode::node(&mut c, b.0, b.1);
        let (lo, hi) = if an.me < bn.me { (an, bn) } else { (bn, an) };
        (lo, hi, vec![d1, d2])
    }

    fn offer(nonce: [u8; 16], cands: &[&str]) -> Vec<u8> {
        wp::PunchOffer {
            candidates: Some(
                cands
                    .iter()
                    .map(|c| wp::SockAddr::from_sock(c.parse().expect("address")))
                    .collect(),
            ),
            nonce: Some(wp::Id16::from_bytes(&nonce)),
        }
        .encode_bytes()
    }

    fn go(nonce: [u8; 16]) -> Vec<u8> {
        wp::PunchGo {
            nonce: Some(wp::Id16::from_bytes(&nonce)),
        }
        .encode_bytes()
    }

    /// (nonce, initiator, probing, candidates) of the attempt with `peer`.
    fn attempt(n: &Node, peer: &Bytes32) -> Option<([u8; 16], bool, bool, Vec<SocketAddr>)> {
        table(n)
            .lock()
            .get(peer)
            .and_then(|s| s.attempt.as_ref())
            .map(|a| (a.nonce, a.initiator, a.probing, a.theirs.clone()))
    }

    #[tokio::test]
    async fn an_offer_is_answered_and_go_starts_the_responder() {
        let (lo, hi, _d) = pair();
        let nonce = [5; 16];
        on_message(
            &lo,
            &hi.me,
            ftype::PUNCH_OFFER,
            &offer(nonce, &["198.51.100.7:4000"]),
        );
        let (n1, initiator, probing, theirs) = attempt(&lo, &hi.me).expect("an attempt");
        assert_eq!((n1, initiator, probing), (nonce, false, false));
        assert_eq!(theirs, ["198.51.100.7:4000".parse::<SocketAddr>().unwrap()]);
        // The same offer again changes nothing.
        on_message(
            &lo,
            &hi.me,
            ftype::PUNCH_OFFER,
            &offer(nonce, &["198.51.100.8:1"]),
        );
        assert_eq!(attempt(&lo, &hi.me).expect("kept").3, theirs);
        // GO for another nonce is ignored; for ours it starts the checks.
        on_message(&lo, &hi.me, ftype::PUNCH_GO, &go([6; 16]));
        assert!(!attempt(&lo, &hi.me).expect("kept").2);
        on_message(&lo, &hi.me, ftype::PUNCH_GO, &go(nonce));
        assert!(attempt(&lo, &hi.me).expect("kept").2, "probing");
        let name = lo.name_of(&hi.me);
        assert_eq!(status(&lo)["peers"][name]["running"]["initiator"], false);
    }

    /// Both sides offered at once: the lower id's attempt goes on, the
    /// higher id answers it.
    #[tokio::test]
    async fn simultaneous_offers_settle_on_the_lower_ids_attempt() {
        let (lo, hi, _d) = pair();
        let start = |n: &Node, peer: Bytes32, nonce: [u8; 16]| {
            table(n).lock().entry(peer).or_default().attempt = Some(Attempt {
                nonce,
                initiator: true,
                theirs: Vec::new(),
                prflx: 0,
                validated: None,
                rejected: Vec::new(),
                started: Instant::now(),
                probing: false,
                dialing: false,
                predict: false,
            });
        };
        let (mine_lo, mine_hi) = ([1; 16], [2; 16]);
        start(&lo, hi.me, mine_lo);
        start(&hi, lo.me, mine_hi);
        on_message(
            &lo,
            &hi.me,
            ftype::PUNCH_OFFER,
            &offer(mine_hi, &["198.51.100.7:4000"]),
        );
        on_message(
            &hi,
            &lo.me,
            ftype::PUNCH_OFFER,
            &offer(mine_lo, &["198.51.100.9:4000"]),
        );
        let (n_lo, init_lo, ..) = attempt(&lo, &hi.me).expect("lower");
        let (n_hi, init_hi, ..) = attempt(&hi, &lo.me).expect("higher");
        assert_eq!((n_lo, init_lo), (mine_lo, true));
        assert_eq!((n_hi, init_hi), (mine_lo, false));
    }

    /// Checks: a PING from an address the peer didn't offer adds it (up to
    /// MAX_PRFLX), first; a PONG validates the address it came from.
    #[tokio::test]
    async fn checks_add_peer_reflexive_candidates_and_validate() {
        let (lo, hi, _d) = pair();
        let nonce = [5; 16];
        on_message(
            &lo,
            &hi.me,
            ftype::PUNCH_OFFER,
            &offer(nonce, &["198.51.100.7:4000"]),
        );
        for port in 0..MAX_PRFLX as u16 + 2 {
            on_check(
                &lo,
                PunchEvent {
                    from: SocketAddr::new([203, 0, 113, 1].into(), 5000 + port),
                    token: nonce,
                    pong: false,
                },
            );
        }
        let theirs = attempt(&lo, &hi.me).expect("attempt").3;
        assert_eq!(theirs.len(), 1 + MAX_PRFLX);
        assert_eq!(theirs.last(), Some(&"198.51.100.7:4000".parse().unwrap()));
        // A check for another attempt is ignored.
        on_check(
            &lo,
            PunchEvent {
                from: "203.0.113.9:1".parse().unwrap(),
                token: [9; 16],
                pong: true,
            },
        );
        assert!(
            table(&lo).lock()[&hi.me]
                .attempt
                .as_ref()
                .unwrap()
                .validated
                .is_none()
        );
        on_check(
            &lo,
            PunchEvent {
                from: "198.51.100.7:4000".parse().unwrap(),
                token: nonce,
                pong: true,
            },
        );
        let validated = table(&lo).lock()[&hi.me]
            .attempt
            .as_ref()
            .and_then(|a| a.validated);
        assert_eq!(validated, Some("198.51.100.7:4000".parse().unwrap()));
    }

    /// Each node keeps its own attempts (two nodes in one process).
    #[tokio::test]
    async fn attempts_are_per_node() {
        let (lo, hi, _d) = pair();
        on_message(
            &lo,
            &hi.me,
            ftype::PUNCH_OFFER,
            &offer([5; 16], &["198.51.100.7:4000"]),
        );
        assert!(attempt(&lo, &hi.me).is_some());
        assert!(table(&hi).lock().is_empty());
    }

    /// A symmetric NAT on the peer's side (and possibly ours) doesn't stop
    /// punching: two nodes behind one NAT reach each other's LAN addresses.
    /// Port prediction runs toward a symmetric peer.
    #[tokio::test]
    async fn symmetric_peers_are_punched_with_port_prediction() {
        let (lo, hi, _d) = pair();
        assert!(!should_predict(&lo, &hi.me));
        let rec = wp::EndpointRecord {
            node_id: Some(webjet_core::crypto::k32(&hi.me)),
            nat: wp::NatType::Symmetric,
            ..Default::default()
        };
        lo.records.lock().endpoints.insert(hi.me, (rec, Vec::new()));
        assert!(should_try(&lo, &hi.me));
        assert!(should_predict(&lo, &hi.me));
        on_message(
            &lo,
            &hi.me,
            ftype::PUNCH_OFFER,
            &offer([5; 16], &["203.0.113.20:4000"]),
        );
        let t = table(&lo).lock();
        assert!(t[&hi.me].attempt.as_ref().is_some_and(|a| a.predict));
    }

    /// A validated address whose dial failed (someone else answered) is
    /// dropped and the checks go on; the next answer is nominated. After
    /// the window a failed dial ends the attempt.
    #[tokio::test]
    async fn a_failed_dial_rejects_the_address_and_checks_go_on() {
        let (lo, hi, _d) = pair();
        let nonce = [5; 16];
        let (a, b): (SocketAddr, SocketAddr) = (
            "203.0.113.20:4000".parse().unwrap(),
            "198.51.100.7:4000".parse().unwrap(),
        );
        on_message(
            &hi,
            &lo.me,
            ftype::PUNCH_OFFER,
            &offer(nonce, &["203.0.113.20:4000", "198.51.100.7:4000"]),
        );
        let pong = |from| PunchEvent {
            from,
            token: nonce,
            pong: true,
        };
        let validated = |n: &Node, peer: &Bytes32| {
            table(n).lock()[peer]
                .attempt
                .as_ref()
                .and_then(|x| x.validated)
        };
        on_check(&hi, pong(a));
        assert_eq!(validated(&hi, &lo.me), Some(a));
        mark_dialing(&hi, &lo.me);
        // A failure for another address (an older dial) changes nothing.
        reject(&hi, &lo.me, b);
        assert_eq!(validated(&hi, &lo.me), Some(a));
        reject(&hi, &lo.me, a);
        {
            let t = table(&hi).lock();
            let at = t[&lo.me].attempt.as_ref().expect("still running");
            assert_eq!((at.validated, at.dialing), (None, false));
            assert_eq!(at.rejected, [a]);
            assert_eq!(at.theirs, [b]);
        }
        // The rejected address answering again (or pinging) is ignored.
        on_check(&hi, pong(a));
        on_check(
            &hi,
            PunchEvent {
                from: a,
                token: nonce,
                pong: false,
            },
        );
        assert_eq!(validated(&hi, &lo.me), None);
        assert_eq!(
            table(&hi).lock()[&lo.me].attempt.as_ref().unwrap().theirs,
            [b]
        );
        on_check(&hi, pong(b));
        assert_eq!(validated(&hi, &lo.me), Some(b));
        // Past the window: the attempt ends.
        table(&hi)
            .lock()
            .get_mut(&lo.me)
            .and_then(|s| s.attempt.as_mut())
            .unwrap()
            .started -= WINDOW;
        reject(&hi, &lo.me, b);
        let t = table(&hi).lock();
        assert!(t[&lo.me].attempt.is_none());
        assert!(t[&lo.me].last.as_ref().unwrap().1.starts_with("dial to"));
    }

    #[test]
    fn prediction_covers_ports_near_public_candidates_only() {
        let theirs: Vec<SocketAddr> = vec![
            "192.168.1.5:40000".parse().unwrap(),
            "47.107.180.197:50000".parse().unwrap(),
        ];
        let p = predicted(&theirs);
        assert_eq!(p.len(), usize::from(PREDICT_AFTER + PREDICT_BEFORE));
        assert!(p.iter().all(|a| a.ip().to_string() == "47.107.180.197"));
        assert!(p.contains(&"47.107.180.197:50001".parse().unwrap()));
        assert!(p.contains(&"47.107.180.197:49992".parse().unwrap()));
        assert!(!p.contains(&"47.107.180.197:50000".parse().unwrap()));
        // Without outside addresses (a test network), the first ones.
        let lan = predicted(&["172.31.0.22:40000".parse().unwrap()]);
        assert!(lan.contains(&"172.31.0.22:40001".parse().unwrap()));
        // Never below 1024 nor past 65535.
        let low = predicted(&["1.2.3.4:1025".parse().unwrap()]);
        assert!(low.iter().all(|a| a.port() >= 1024));
        let high = predicted(&["1.2.3.4:65530".parse().unwrap()]);
        assert!(high.iter().all(|a| a.port() >= 65522));
    }
}
