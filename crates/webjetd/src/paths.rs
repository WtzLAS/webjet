//! Path selection (§11.4): candidates from the relay graph plus the direct
//! route, opened as circuits and measured end to end with encrypted probes.
//! The session sends on the circuit with the best measured cost.

use crate::circuit::{self, LocalCircuit};
use crate::node::Node;
use anyhow::{anyhow, bail, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use webjet_core::crypto::{self, opt_k32, Bytes32};
use webjet_core::frames::ftype;
use webjet_core::routing::{spread_pick, Path};
use webjet_proto::{self as wp, Decodable, Encodable};

const K_PATHS: usize = 4;
const PROBE_INTERVAL: Duration = Duration::from_secs(1);
const MAX_CIRCUITS: usize = 2;

/// Can we (or could we) reach `peer` without relays?
fn direct_possible(n: &Node, peer: &Bytes32) -> bool {
    if n.best_hop(peer).is_some() {
        return true;
    }
    let recs = n.records.lock();
    recs.endpoints
        .get(peer)
        .map(|(r, _)| r.addrs.clone().unwrap_or_default().iter().any(|a| a.kind == wp::AddrKind::Public && a.priority > 0))
        .unwrap_or(false)
}

/// Candidate paths to `peer`, best first.
pub fn candidates(n: &Arc<Node>, peer: &Bytes32) -> Vec<Path> {
    let g = crate::gossip::graph(n);
    let mut v = g.k_paths(&n.me, peer, K_PATHS);
    // Only relays we can actually reach (or dial) as the first hop.
    v.retain(|p| p.hops.first().map(|h| n.best_hop(h).is_some() || !n.endpoint_addrs(h).is_empty()).unwrap_or(true));
    if direct_possible(n, peer) && !v.iter().any(|p| p.hops.is_empty()) {
        let cost = n.best_hop(peer).map(|h| h.cost()).filter(|c| c.is_finite()).unwrap_or(f64::INFINITY);
        v.insert(0, Path { hops: Vec::new(), cost, spare: 100 });
    }
    v.sort_by(|a, b| a.cost.partial_cmp(&b.cost).unwrap_or(std::cmp::Ordering::Equal));
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
        let relayed: Vec<Path> = cands.iter().filter(|p| !p.hops.is_empty()).cloned().collect();
        match spread_pick(&relayed) {
            Some(p) => cands.iter().position(|c| c == p).unwrap_or(0),
            None => 0,
        }
    };
    let mut order: Vec<Path> = vec![cands[first].clone()];
    order.extend(cands.iter().enumerate().filter(|(i, _)| *i != first).map(|(_, p)| p.clone()));
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
    let Ok(p) = wp::Probe::decode_bytes(payload) else { return };
    if opt_k32(&p.route_id) != c.route_id {
        return;
    }
    let now_us = n.started.elapsed().as_micros() as u64;
    if let Some(rtt) = c.probes.lock().on_ack(p.probe_seq, now_us) {
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
    let p = wp::Probe { route_id: Some(crypto::k32(&c.route_id)), probe_seq: seq, sent_at_us: us };
    crate::e2e::send_on(n, &s, c, ftype::PROBE, &p.encode_bytes());
}

/// The path maintenance loop: probe every circuit, keep a backup open while
/// a session is active, and close circuits nobody uses.
pub async fn run(n: Arc<Node>) {
    let mut tick = tokio::time::interval(PROBE_INTERVAL);
    let mut seq: u64 = 0;
    let mut backup_tried: HashMap<Bytes32, Instant> = HashMap::new();
    loop {
        tick.tick().await;
        seq += 1;
        let sessions = n.e2e.all();
        let mut active: HashMap<Bytes32, bool> = HashMap::new();
        for s in &sessions {
            let recent = s.last_used.lock().elapsed() < Duration::from_secs(60);
            active.insert(s.peer, recent);
            if !recent {
                continue;
            }
            let circs = n.circuits.lock().local_circuits(&s.peer);
            for c in &circs {
                send_probe(&n, c, seq);
            }
            // Keep one or two backups (§11.4 step 4); only the source side builds them.
            let mine: Vec<&Arc<LocalCircuit>> = circs.iter().filter(|c| c.is_source).collect();
            let want_more = s.established() && mine.len() < MAX_CIRCUITS && !circs.is_empty();
            let have_direct = circs.iter().any(|c| c.direct());
            let direct_now = n.best_hop(&s.peer).is_some() && !have_direct;
            let due = backup_tried.get(&s.peer).map(|t| t.elapsed() > Duration::from_secs(30)).unwrap_or(true);
            if (want_more || direct_now) && (due || direct_now) {
                backup_tried.insert(s.peer, Instant::now());
                let existing: Vec<Vec<Bytes32>> = circs.iter().map(|c| c.hops.clone()).collect();
                let pick = candidates(&n, &s.peer).into_iter().find(|p| !existing.contains(&p.hops));
                if let Some(p) = pick {
                    let n2 = n.clone();
                    let peer = s.peer;
                    tokio::spawn(async move {
                        if let Err(e) = circuit::open(&n2, peer, p.hops).await {
                            tracing::trace!("backup circuit: {e}");
                        }
                    });
                }
            }
            // More than two of our circuits: drop the worst.
            if mine.len() > MAX_CIRCUITS {
                let primary = s.primary();
                if let Some(worst) = mine.iter().filter(|c| Some(c.label) != primary).max_by(|a, b| a.cost().partial_cmp(&b.cost()).unwrap_or(std::cmp::Ordering::Equal)) {
                    circuit::close_local(&n, worst);
                }
            }
            // A circuit whose probes all fail for a while is dead.
            for c in &circs {
                let st = c.probes.lock();
                if c.created.elapsed() > Duration::from_secs(15) && st.loss > 0.95 && circs.len() > 1 {
                    drop(st);
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
            let keep = active.contains_key(&c.peer) || c.created.elapsed() < Duration::from_secs(30);
            if !keep && c.is_source {
                circuit::close_local(&n, &c);
            }
        }
        backup_tried.retain(|_, t| t.elapsed() < Duration::from_secs(600));
        if seq.is_multiple_of(10) {
            circuit::sweep(&n);
        }
    }
}
