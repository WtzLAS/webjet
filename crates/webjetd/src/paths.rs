//! Path selection (§11.4): candidates from the relay graph plus the direct
//! route, opened as circuits. A circuit's cost is the sum of its links' raw
//! measurements (§11.2): this node's first hop live, the rest as their ends
//! advertise them. End-to-end probes go only over circuits without enough
//! traffic of their own, so they never queue behind it: they show the
//! circuit is alive and give its cost until the links are known. The
//! session sends on the circuit with the best cost.

use crate::circuit::{self, LocalCircuit};
use crate::node::Node;
use anyhow::{Result, anyhow, bail};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use webjet_core::crypto::{self, Bytes32, opt_k32};
use webjet_core::frames::ftype;
use webjet_core::routing::{Path, spread_pick};
use webjet_proto::{self as wp, Decodable, Encodable};

const K_PATHS: usize = 4;
const PROBE_INTERVAL: Duration = Duration::from_secs(1);
const MAX_CIRCUITS: usize = 2;
/// How often an active session opens a trial circuit on the best path it
/// hasn't tried lately, and how long a tried path stays "tried".
const TRIAL_EVERY: Duration = Duration::from_secs(30);
const TRIAL_FORGET: Duration = Duration::from_secs(300);
/// Probe answers a circuit needs before it can be compared (and dropped).
const MEASURED_PROBES: u64 = 3;

/// Can we (or could we) reach `peer` without relays?
fn direct_possible(n: &Node, peer: &Bytes32) -> bool {
    if n.best_hop(peer).is_some() {
        return true;
    }
    let recs = n.records.lock();
    recs.endpoints.get(peer).is_some_and(|(r, _)| {
        r.addrs
            .clone()
            .unwrap_or_default()
            .iter()
            .any(|a| a.kind == wp::AddrKind::Public && a.priority > 0)
    })
}

/// Candidate paths to `peer`, best first.
pub fn candidates(n: &Arc<Node>, peer: &Bytes32) -> Vec<Path> {
    let g = crate::gossip::graph(n);
    let mut v = g.k_paths(&n.me, peer, K_PATHS);
    // Only relays we can actually reach (or dial) as the first hop.
    v.retain(|p| {
        p.hops
            .first()
            .is_none_or(|h| n.best_hop(h).is_some() || !n.endpoint_addrs(h).is_empty())
    });
    if direct_possible(n, peer) && !v.iter().any(|p| p.hops.is_empty()) {
        let cost = n
            .best_hop(peer)
            .map(|h| h.cost())
            .filter(|c| c.is_finite())
            .unwrap_or(f64::INFINITY);
        v.insert(
            0,
            Path {
                hops: Vec::new(),
                cost,
                spare: 100,
            },
        );
    }
    v.sort_by(|a, b| {
        a.cost
            .partial_cmp(&b.cost)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    v
}

/// Open the best available circuit to `peer` (§11.4 step 6: spreading).
pub async fn open_best(n: &Arc<Node>, peer: Bytes32) -> Result<Arc<LocalCircuit>> {
    crate::gossip::lookup(n, &peer);
    let mut cands = candidates(n, &peer);
    if cands.is_empty() {
        // Edge nodes may not have the peer's records yet: wait briefly for the lookup.
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cands = candidates(n, &peer);
            if !cands.is_empty() {
                break;
            }
        }
    }
    if cands.is_empty() {
        bail!("no route to {}", n.name_of(&peer));
    }
    // Prefer an existing direct hop; otherwise spread among near-best relay paths.
    let first = if n.best_hop(&peer).is_some() {
        cands.iter().position(|p| p.hops.is_empty()).unwrap_or(0)
    } else {
        let relayed: Vec<Path> = cands
            .iter()
            .filter(|p| !p.hops.is_empty())
            .cloned()
            .collect();
        match spread_pick(&relayed) {
            Some(p) => cands.iter().position(|c| c == p).unwrap_or(0),
            None => 0,
        }
    };
    let mut order: Vec<Path> = vec![cands[first].clone()];
    order.extend(
        cands
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != first)
            .map(|(_, p)| p.clone()),
    );
    let mut last = anyhow!("no route");
    for p in order {
        match circuit::open(n, peer, p.hops.clone()).await {
            Ok(c) => return Ok(c),
            Err(e) => {
                tracing::debug!(peer = %n.name_of(&peer), hops = p.hops.len(), "circuit attempt failed: {e}");
                last = e;
            }
        }
    }
    Err(last)
}

pub fn on_established(n: &Arc<Node>, peer: &Bytes32) {
    crate::punch::maybe_start(n, peer);
}

pub fn on_probe_ack(n: &Arc<Node>, c: &Arc<LocalCircuit>, payload: &[u8]) {
    let Ok(p) = wp::Probe::decode_bytes(payload) else {
        return;
    };
    if opt_k32(&p.route_id) != c.route_id {
        return;
    }
    let now_us = n.started.elapsed().as_micros() as u64;
    let rtt = c.probes.lock().on_ack(p.probe_seq, now_us);
    if let Some(rtt) = rtt {
        *c.e2e_rtt_ms.lock() = Some(rtt);
    }
}

fn send_probe(n: &Arc<Node>, c: &Arc<LocalCircuit>, seq: u64) {
    let Some(s) = n.e2e.get(&c.peer) else { return };
    if !s.established() {
        return;
    }
    let us = n.started.elapsed().as_micros() as u64;
    c.probes.lock().on_sent(seq, us);
    c.on_probe_sent();
    let p = wp::Probe {
        route_id: Some(crypto::k32(&c.route_id)),
        probe_seq: seq,
        sent_at_us: us,
    };
    crate::e2e::send_on(n, &s, c, ftype::PROBE, &p.encode_bytes());
}

/// The cost of the path `me → relays → peer` from its links' measurements
/// (§11.2, §11.4): the first hop live, the others as advertised (relay
/// links and the far end's attachment). No load penalty: an established
/// circuit doesn't move because a relay got busier, only when one is full
/// (§11.8.3). `None` while a link isn't known.
pub fn path_cost(
    n: &Node,
    g: &webjet_core::routing::Graph,
    peer: &Bytes32,
    relays: &[Bytes32],
) -> Option<f64> {
    let first = relays.first().unwrap_or(peer);
    let mut cost = n
        .best_hop(first)
        .map(|h| h.cost())
        .filter(|c| c.is_finite())?;
    let mut prev = *first;
    for next in relays.iter().skip(1).chain(std::iter::once(peer)) {
        if prev == *peer {
            break;
        }
        cost += g.link(&prev, next)?;
        prev = *next;
    }
    let full = relays.iter().any(|r| {
        g.relays
            .get(r)
            .is_some_and(|i| webjet_core::routing::load_penalty(i.load).is_none())
    });
    Some(if full { cost * FULL_RELAY_FACTOR } else { cost })
}

/// A circuit through a full relay costs this much more, so traffic leaves
/// it (§11.8.3) unless every other path is far worse.
const FULL_RELAY_FACTOR: f64 = 4.0;

/// The path maintenance loop: probe idle circuits, keep a backup open while
/// a session is active, and close circuits nobody uses.
pub async fn run(n: Arc<Node>) {
    let mut tick = tokio::time::interval(PROBE_INTERVAL);
    let mut seq: u64 = 0;
    let mut backup_tried: HashMap<Bytes32, Instant> = HashMap::new();
    // Paths opened lately, per peer.
    let mut tried: HashMap<(Bytes32, Vec<Bytes32>), Instant> = HashMap::new();
    loop {
        tick.tick().await;
        seq += 1;
        let sessions = n.e2e.all();
        // Built once per round, when an active session needs it.
        let mut graph: Option<webjet_core::routing::Graph> = None;
        let mut active: HashMap<Bytes32, bool> = HashMap::new();
        for s in &sessions {
            let recent = s.last_used.lock().elapsed() < Duration::from_secs(60);
            active.insert(s.peer, recent);
            if !recent {
                continue;
            }
            let circs = n.circuits.lock().local_circuits(&s.peer);
            let g = graph.get_or_insert_with(|| crate::gossip::graph(&n));
            for c in &circs {
                *c.live.path_cost.lock() = path_cost(&n, g, &s.peer, &c.relays_from_me());
                // A circuit carrying traffic both ways needs no probe: the
                // traffic shows it works, and a probe would only measure the
                // queue in front of it.
                if !c.busy() {
                    send_probe(&n, c, seq);
                }
            }
            // Keep a backup (§11.4 step 4), and every TRIAL_EVERY try the best
            // path not tried lately; the measurements decide which two stay
            // (below). Only the source side builds them.
            let mine: Vec<&Arc<LocalCircuit>> = circs.iter().filter(|c| c.is_source).collect();
            let trial = s.established() && !circs.is_empty();
            let have_direct = circs.iter().any(|c| c.direct());
            let direct_now = n.best_hop(&s.peer).is_some() && !have_direct;
            let due = backup_tried
                .get(&s.peer)
                .is_none_or(|t| t.elapsed() > TRIAL_EVERY);
            if direct_now || (trial && due) {
                backup_tried.insert(s.peer, Instant::now());
                let existing: Vec<Vec<Bytes32>> = circs.iter().map(|c| c.hops.clone()).collect();
                let pick = candidates(&n, &s.peer).into_iter().find(|p| {
                    !existing.contains(&p.hops)
                        && (p.hops.is_empty() && direct_now
                            || tried
                                .get(&(s.peer, p.hops.clone()))
                                .is_none_or(|t| t.elapsed() > TRIAL_FORGET))
                });
                if let Some(p) = pick {
                    tried.insert((s.peer, p.hops.clone()), Instant::now());
                    let n2 = n.clone();
                    let peer = s.peer;
                    tokio::spawn(async move {
                        if let Err(e) = circuit::open(&n2, peer, p.hops).await {
                            tracing::trace!("backup circuit: {e}");
                        }
                    });
                }
            }
            // More than two of our circuits: drop the worst measured one
            // (a trial circuit gets its probes first).
            if mine.len() > MAX_CIRCUITS {
                let primary = s.primary();
                if let Some(worst) = mine
                    .iter()
                    .filter(|c| Some(c.label) != primary)
                    .filter(|c| c.measured(MEASURED_PROBES))
                    .max_by(|a, b| {
                        a.cost()
                            .partial_cmp(&b.cost())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                {
                    circuit::close_local(&n, worst);
                }
            }
            // A circuit whose probes all fail for a while is dead.
            for c in &circs {
                let loss = c.probes.lock().loss;
                if c.created.elapsed() > Duration::from_secs(15) && loss > 0.95 && circs.len() > 1 {
                    circuit::close_local(&n, c);
                }
            }
        }
        // Close source circuits of sessions that are gone or idle for long.
        let locals: Vec<Arc<LocalCircuit>> = {
            let t = n.circuits.lock();
            t.entries
                .values()
                .filter_map(|e| match &e.kind {
                    circuit::Kind::Local(c) => Some(c.clone()),
                    _ => None,
                })
                .collect()
        };
        for c in locals {
            let keep =
                active.contains_key(&c.peer) || c.created.elapsed() < Duration::from_secs(30);
            if !keep && c.is_source {
                circuit::close_local(&n, &c);
            }
        }
        backup_tried.retain(|_, t| t.elapsed() < Duration::from_secs(600));
        tried.retain(|_, t| t.elapsed() < TRIAL_FORGET);
        if seq.is_multiple_of(10) {
            circuit::sweep(&n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testnode::{self, Cluster};
    use webjet_core::testutil::NodeSpec;
    use webjet_core::types::now_ms;
    use webjet_proto::Transport;

    struct Net {
        c: Cluster,
        me: (Bytes32, webjet_core::crypto::KeyPair),
        peer: Bytes32,
        r1: Bytes32,
        r2: Bytes32,
    }

    fn relay(c: &mut Cluster, name: &str, ip: &str) -> Bytes32 {
        c.enroll(NodeSpec {
            name,
            ip,
            roles: &[wp::Role::Data, wp::Role::Relay],
            ..Default::default()
        })
        .0
    }

    fn net() -> Net {
        let mut c = Cluster::new();
        let me = c.data_node("me", "10.7.0.2", &[]);
        let peer = c.data_node("peer", "10.7.0.3", &[]).0;
        let r1 = relay(&mut c, "r1", "10.7.0.10");
        let r2 = relay(&mut c, "r2", "10.7.0.11");
        Net {
            c,
            me,
            peer,
            r1,
            r2,
        }
    }

    fn lsa(n: &Node, origin: Bytes32, links: &[(Bytes32, u16)]) {
        let l = wp::LinkStateAdvert {
            origin: Some(crypto::k32(&origin)),
            seq: 1,
            links: Some(
                links
                    .iter()
                    .map(|(p, rtt)| wp::LinkEntry {
                        peer: Some(crypto::k32(p)),
                        transport: Transport::TcpTls,
                        rtt_ms: *rtt,
                        ..Default::default()
                    })
                    .collect(),
            ),
            expires_at: now_ms() + 60_000,
            ..Default::default()
        };
        n.records.lock().lsas.insert(origin, (l, Vec::new()));
    }

    fn attach(n: &Node, node: Bytes32, relays: &[(Bytes32, u16)]) {
        let a = wp::AttachmentRecord {
            node_id: Some(crypto::k32(&node)),
            seq: 1,
            relays: Some(
                relays
                    .iter()
                    .map(|(r, rtt)| wp::AttachmentEntry {
                        relay: Some(crypto::k32(r)),
                        transport: Transport::TcpTls,
                        rtt_ms: *rtt,
                        loss_pct: 0,
                    })
                    .collect(),
            ),
            expires_at: now_ms() + 60_000,
            ..Default::default()
        };
        n.records.lock().attachments.insert(node, (a, Vec::new()));
    }

    fn endpoint(n: &Node, node: Bytes32, kind: wp::AddrKind, priority: u8) {
        let r = wp::EndpointRecord {
            node_id: Some(crypto::k32(&node)),
            addrs: Some(vec![wp::EndpointAddr {
                addr: Some(wp::SockAddr::from_sock("198.51.100.7:443".parse().unwrap())),
                transport: Transport::TcpTls,
                kind,
                priority,
            }]),
            expires_at: now_ms() + 60_000,
            ..Default::default()
        };
        n.records.lock().endpoints.insert(node, (r, Vec::new()));
    }

    #[test]
    fn no_records_no_candidates() {
        let mut t = net();
        let (n, _d) = testnode::node(&mut t.c, t.me.0, t.me.1.clone());
        assert!(candidates(&n, &t.peer).is_empty());
        assert!(!direct_possible(&n, &t.peer));
    }

    #[test]
    fn direct_when_a_hop_or_a_public_address_exists() {
        let mut t = net();
        let (n, _d) = testnode::node(&mut t.c, t.me.0, t.me.1.clone());
        // A host address, or a public one with priority 0, isn't enough.
        endpoint(&n, t.peer, wp::AddrKind::Host, 10);
        assert!(!direct_possible(&n, &t.peer));
        endpoint(&n, t.peer, wp::AddrKind::Public, 0);
        assert!(!direct_possible(&n, &t.peer));
        endpoint(&n, t.peer, wp::AddrKind::Public, 10);
        assert!(direct_possible(&n, &t.peer));
        let c = candidates(&n, &t.peer);
        assert_eq!(c.len(), 1);
        assert!(c[0].hops.is_empty());
        assert_eq!(c[0].cost, f64::INFINITY, "not measured yet");

        // An open hop makes it possible whatever the records say.
        n.records.lock().endpoints.clear();
        let (_h, _rx) = n.test_hop(t.peer, Transport::TcpTls);
        assert!(direct_possible(&n, &t.peer));
    }

    #[test]
    fn relay_paths_best_first_and_reachable_only() {
        let mut t = net();
        let (n, _d) = testnode::node(&mut t.c, t.me.0, t.me.1.clone());
        // Both relays know each other; the peer hangs off both; we have a
        // hop to r1 only (and no addresses for r2).
        lsa(&n, t.r1, &[(t.r2, 5)]);
        lsa(&n, t.r2, &[(t.r1, 5)]);
        attach(&n, t.peer, &[(t.r1, 30), (t.r2, 10)]);
        attach(&n, t.me.0, &[(t.r1, 10), (t.r2, 10)]);
        let (_h, _rx) = n.test_hop(t.r1, Transport::TcpTls);
        let c = candidates(&n, &t.peer);
        assert!(!c.is_empty());
        assert!(c.iter().all(|p| p.hops.first() == Some(&t.r1)), "{c:?}");
        assert!(c.windows(2).all(|w| w[0].cost <= w[1].cost));

        // Once r2 has an address we could dial, its paths count too.
        endpoint(&n, t.r2, wp::AddrKind::Public, 10);
        let c = candidates(&n, &t.peer);
        assert!(c.iter().any(|p| p.hops == vec![t.r2]), "{c:?}");
    }

    #[test]
    fn expired_or_revoked_relays_are_left_out() {
        let mut t = net();
        let (n, _d) = testnode::node(&mut t.c, t.me.0, t.me.1.clone());
        lsa(&n, t.r1, &[]);
        attach(&n, t.peer, &[(t.r1, 10)]);
        attach(&n, t.me.0, &[(t.r1, 10)]);
        let (_h, _rx) = n.test_hop(t.r1, Transport::TcpTls);
        assert_eq!(candidates(&n, &t.peer).len(), 1);
        n.records.lock().lsas.get_mut(&t.r1).unwrap().0.expires_at = 1;
        assert!(candidates(&n, &t.peer).is_empty(), "expired advert");

        // A fresh advert again, but the relay is revoked.
        lsa(&n, t.r1, &[]);
        assert_eq!(candidates(&n, &t.peer).len(), 1);
        t.c.admin_op(webjet_proto::AccountOp::TombstoneNode(Box::new(
            wp::TombstoneNode {
                node_id: Some(crypto::k32(&t.r1)),
                ..Default::default()
            },
        )))
        .unwrap();
        testnode::sync(&mut t.c, &n);
        assert!(candidates(&n, &t.peer).is_empty(), "revoked relay");
    }

    #[test]
    fn probe_acks_measure_the_circuit() {
        let mut t = net();
        let (n, _d) = testnode::node(&mut t.c, t.me.0, t.me.1.clone());
        let rid = crypto::route_id(&t.me.0, &t.peer, &[]);
        let c = Arc::new(LocalCircuit {
            peer: t.peer,
            label: 1,
            next: t.peer,
            out_label: parking_lot::Mutex::new(Some(2)),
            hops: vec![],
            route_id: rid,
            acct: Default::default(),
            is_source: true,
            created: Instant::now(),
            probes: parking_lot::Mutex::new(Default::default()),
            e2e_rtt_ms: parking_lot::Mutex::new(None),
            last_rx: parking_lot::Mutex::new(Instant::now()),
            live: Default::default(),
        });
        c.probes.lock().on_sent(7, 0);
        let probe = |route: Bytes32, seq| {
            wp::Probe {
                route_id: Some(crypto::k32(&route)),
                probe_seq: seq,
                sent_at_us: 0,
            }
            .encode_bytes()
        };
        // Another route's probe, an unknown sequence number, garbage: ignored.
        on_probe_ack(&n, &c, &probe([1; 32], 7));
        on_probe_ack(&n, &c, &probe(rid, 8));
        on_probe_ack(&n, &c, b"junk");
        assert!(c.e2e_rtt_ms.lock().is_none());
        on_probe_ack(&n, &c, &probe(rid, 7));
        assert!(c.e2e_rtt_ms.lock().is_some());
        assert_eq!(c.probes.lock().samples, 1);
        assert!(c.cost().is_finite());
    }

    fn circuit(peer: Bytes32, hops: Vec<Bytes32>, source: bool) -> Arc<LocalCircuit> {
        Arc::new(LocalCircuit {
            peer,
            label: 1,
            next: if source {
                hops.first().copied().unwrap_or(peer)
            } else {
                hops.last().copied().unwrap_or(peer)
            },
            out_label: parking_lot::Mutex::new(Some(2)),
            hops,
            route_id: [9; 32],
            acct: Default::default(),
            is_source: source,
            created: Instant::now(),
            probes: parking_lot::Mutex::new(Default::default()),
            e2e_rtt_ms: parking_lot::Mutex::new(None),
            last_rx: parking_lot::Mutex::new(Instant::now()),
            live: Default::default(),
        })
    }

    /// A circuit is busy only with traffic both ways in one interval.
    #[test]
    fn busy_needs_traffic_both_ways() {
        use std::sync::atomic::Ordering;
        let c = circuit([3; 32], vec![], true);
        assert!(!c.busy());
        c.live.tx.fetch_add(10, Ordering::Relaxed);
        assert!(!c.busy(), "sending only: the probe checks the way back");
        c.live.tx.fetch_add(10, Ordering::Relaxed);
        c.live.rx.fetch_add(circuit::BUSY_FRAMES, Ordering::Relaxed);
        assert!(c.busy());
        assert!(!c.busy(), "counted per interval");
    }

    /// The path cost: the live first hop plus the advertised links, the far
    /// end's attachment last; unknown while a link is missing.
    #[test]
    fn path_cost_from_links() {
        let mut t = net();
        let (n, _d) = testnode::node(&mut t.c, t.me.0, t.me.1.clone());
        lsa(&n, t.r1, &[(t.r2, 5)]);
        lsa(&n, t.r2, &[(t.r1, 7)]);
        attach(&n, t.peer, &[(t.r2, 10)]);
        let g = || crate::gossip::graph(&n);
        assert_eq!(
            path_cost(&n, &g(), &t.peer, &[t.r1, t.r2]),
            None,
            "no hop to r1"
        );
        let (h, _rx) = n.test_hop(t.r1, Transport::TcpTls);
        h.stats
            .lock()
            .on_raw(Some((20.0, 20.0)), Some(0.0), 100, 0, now_ms());
        let first = h.cost();
        assert!(first.is_finite());
        let c = path_cost(&n, &g(), &t.peer, &[t.r1, t.r2]).unwrap();
        // r1–r2 at the higher of both ends' figures (7), then r2–peer (10).
        assert!((c - (first + 7.0 + 10.0)).abs() < 1e-9, "{c} vs {first}");
        assert_eq!(
            path_cost(&n, &g(), &t.peer, &[t.r1]),
            None,
            "peer not on r1"
        );
        // A full relay on the path makes it much dearer.
        n.records.lock().lsas.get_mut(&t.r2).unwrap().0.load = Some(Box::new(wp::RelayLoad {
            util_pct: 95,
            ..Default::default()
        }));
        let full = path_cost(&n, &g(), &t.peer, &[t.r1, t.r2]).unwrap();
        assert!((full - c * FULL_RELAY_FACTOR).abs() < 1e-9);
        // The destination end of the same circuit sees it reversed.
        let d = circuit(t.me.0, vec![t.r1, t.r2], false);
        assert_eq!(d.relays_from_me(), vec![t.r2, t.r1]);
    }

    /// The circuit's cost follows its links, ignoring what its probes say,
    /// and turns infinite when a probe goes unanswered with nothing else
    /// received.
    #[test]
    fn circuit_cost_prefers_links_and_notices_silence() {
        let c = circuit([3; 32], vec![], true);
        assert_eq!(c.cost(), f64::INFINITY, "nothing known");
        c.probes.lock().on_sent_at(1, 0, now_ms());
        c.probes.lock().on_ack_at(1, 300_000, now_ms());
        assert_eq!(c.cost(), 375.0, "probe only (300 ms + half its jitter)");
        *c.live.path_cost.lock() = Some(25.0);
        assert_eq!(c.cost(), 25.0, "links win over a probe stuck behind data");
        c.on_probe_sent();
        assert_eq!(c.cost(), 25.0, "just sent");
        *c.live.probe_pending.lock() = Some(Instant::now() - Duration::from_secs(4));
        assert_eq!(c.cost(), f64::INFINITY, "unanswered");
        c.on_received();
        assert_eq!(c.cost(), 25.0, "answered");
    }

    #[tokio::test]
    async fn open_best_without_a_route() {
        let mut t = net();
        let (n, _d) = testnode::node(&mut t.c, t.me.0, t.me.1.clone());
        let e = open_best(&n, t.peer).await.map(|_| ()).unwrap_err();
        assert!(e.to_string().contains("no route to peer"), "{e}");
    }
}
