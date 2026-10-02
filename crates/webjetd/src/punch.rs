//! Hole punching (§11.7): exchange candidates over the end-to-end session,
//! then both sides send KCP OPEN probes to each other's candidates at the
//! same moment. The first side whose probe lands gets a KCP session and
//! runs the normal hop handshake on it.

use crate::node::Node;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use webjet_core::crypto::{self, Bytes32};
use webjet_core::frames::ftype;
use webjet_proto::{self as wp, Decodable, Encodable, Transport};

const PROBES: u32 = 10;
const PROBE_GAP: Duration = Duration::from_millis(50);

#[derive(Default)]
struct PeerState {
    nonce: Option<[u8; 16]>,
    their_candidates: Vec<SocketAddr>,
    offered: bool,
    next_try: Option<Instant>,
    backoff: Duration,
    last_offer: Option<Instant>,
}

fn table() -> &'static Mutex<HashMap<Bytes32, PeerState>> {
    static T: OnceLock<Mutex<HashMap<Bytes32, PeerState>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Our candidates, HOST first, then REFLEXIVE (§11.7 rules).
fn my_candidates(n: &Node) -> Vec<SocketAddr> {
    let mut addrs = crate::transport::my_addrs(n);
    addrs.retain(|a| a.transport == Transport::KcpFecTls);
    addrs.sort_by_key(|a| match a.kind {
        wp::AddrKind::Host => 0,
        wp::AddrKind::Reflexive => 1,
        wp::AddrKind::Public => 2,
    });
    addrs
        .iter()
        .filter_map(|a| a.addr.as_ref()?.to_sock())
        .take(8)
        .collect()
}

fn should_try(n: &Node, peer: &Bytes32) -> bool {
    if n.hops_to(peer)
        .iter()
        .any(|h| h.transport == Transport::KcpFecTls)
    {
        return false;
    }
    if n.store
        .read()
        .view()
        .nodes
        .get(&n.me)
        .map(|x| x.relay)
        .unwrap_or(false)
    {
        return false;
    }
    if crate::transport::priority(n, &n.me, Transport::KcpFecTls) == 0
        || crate::transport::priority(n, peer, Transport::KcpFecTls) == 0
    {
        return false;
    }
    // If the peer is directly reachable at a public address, a plain dial is enough.
    let peer_nat = n.records.lock().endpoints.get(peer).map(|(r, _)| r.nat);
    !(matches!(peer_nat, Some(wp::NatType::Symmetric))
        && matches!(crate::transport::nat_type(n), wp::NatType::Symmetric))
}

/// Start punching toward `peer` once a session exists, unless we already
/// hold a direct UDP hop. The lower node id initiates.
pub fn maybe_start(n: &Arc<Node>, peer: &Bytes32) {
    if n.me > *peer || !should_try(n, peer) {
        return;
    }
    let mut t = table().lock();
    let st = t.entry(*peer).or_default();
    if let Some(at) = st.next_try {
        if Instant::now() < at {
            return;
        }
    }
    st.backoff = if st.backoff.is_zero() {
        Duration::from_secs(60)
    } else {
        (st.backoff * 2).min(Duration::from_secs(1800))
    };
    st.next_try = Some(Instant::now() + st.backoff);
    let nonce = crypto::random16();
    st.nonce = Some(nonce);
    st.offered = true;
    st.last_offer = Some(Instant::now());
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

pub fn on_message(n: &Arc<Node>, peer: &Bytes32, ty: u8, payload: &[u8]) {
    match ty {
        ftype::PUNCH_OFFER => {
            let Ok(o) = wp::PunchOffer::decode_bytes(payload) else {
                return;
            };
            let nonce = o.nonce.map(|x| x.to_bytes()).unwrap_or_default();
            let cands: Vec<SocketAddr> = o
                .candidates
                .unwrap_or_default()
                .iter()
                .filter_map(|c| c.to_sock())
                .take(8)
                .collect();
            let initiator = n.me < *peer;
            let mut t = table().lock();
            let st = t.entry(*peer).or_default();
            st.their_candidates = cands;
            if initiator {
                // The responder's offer: send GO and start half an RTT later.
                if st.nonce != Some(nonce) {
                    return;
                }
                drop(t);
                let go = wp::PunchGo {
                    nonce: Some(wp::Id16::from_bytes(&nonce)),
                };
                crate::e2e::send(n, peer, ftype::PUNCH_GO, &go.encode_bytes(), 0);
                let half = n
                    .circuits
                    .lock()
                    .local_circuits(peer)
                    .iter()
                    .filter_map(|c| *c.e2e_rtt_ms.lock())
                    .fold(f64::INFINITY, f64::min);
                let wait = if half.is_finite() {
                    Duration::from_micros((half * 500.0) as u64)
                } else {
                    Duration::from_millis(50)
                };
                spawn_probes(n, *peer, wait);
            } else {
                st.nonce = Some(nonce);
                drop(t);
                if should_try(n, peer) {
                    send_offer(n, peer, nonce);
                }
            }
        }
        ftype::PUNCH_GO => {
            let Ok(g) = wp::PunchGo::decode_bytes(payload) else {
                return;
            };
            let ok = table()
                .lock()
                .get(peer)
                .map(|s| s.nonce == g.nonce.map(|x| x.to_bytes()))
                .unwrap_or(false);
            if ok {
                spawn_probes(n, *peer, Duration::ZERO);
            }
        }
        _ => {}
    }
}

fn spawn_probes(n: &Arc<Node>, peer: Bytes32, wait: Duration) {
    let n = n.clone();
    tokio::spawn(async move {
        tokio::time::sleep(wait).await;
        let cands = table()
            .lock()
            .get(&peer)
            .map(|s| s.their_candidates.clone())
            .unwrap_or_default();
        let Some(ep) = n.udp.get().cloned() else {
            return;
        };
        // Open the mappings on both NATs.
        for _ in 0..PROBES {
            for c in &cands {
                ep.punch(*c).await;
            }
            tokio::time::sleep(PROBE_GAP).await;
            if n.hops_to(&peer)
                .iter()
                .any(|h| h.transport == Transport::KcpFecTls)
            {
                return;
            }
        }
        // The lower id dials over the opened mappings; the other side accepts.
        if n.me < peer {
            let key = n.store.read().view().nodes.get(&peer).map(|x| x.key);
            let Some(key) = key else { return };
            for c in cands {
                match n.dial(c, Transport::KcpFecTls, vec![key]).await {
                    Ok(_) => {
                        tracing::info!(peer = %n.name_of(&peer), addr = %c, "hole punching succeeded");
                        if let Some(st) = table().lock().get_mut(&peer) {
                            st.backoff = Duration::ZERO;
                        }
                        // A direct circuit becomes a path candidate (§11.7 step 3).
                        let n2 = n.clone();
                        tokio::spawn(async move {
                            let _ = crate::circuit::open(&n2, peer, Vec::new()).await;
                        });
                        return;
                    }
                    Err(e) => tracing::debug!("punch dial {c}: {e}"),
                }
            }
        }
    });
}

/// Retry punching for active sessions on the backoff schedule, and
/// immediately when a peer's EndpointRecord changes.
pub async fn run(n: Arc<Node>) {
    let mut ev = n.events.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            e = ev.recv() => {
                if let Ok(crate::node::Event::RecordsChanged(id)) = e {
                    if n.e2e.get(&id).map(|s| s.established()).unwrap_or(false) {
                        if let Some(st) = table().lock().get_mut(&id) { st.next_try = None; }
                        maybe_start(&n, &id);
                    }
                }
            }
            _ = tick.tick() => {
                for s in n.e2e.all() {
                    if s.established() && s.last_used.lock().elapsed() < Duration::from_secs(60) {
                        maybe_start(&n, &s.peer);
                    }
                }
            }
        }
    }
}
