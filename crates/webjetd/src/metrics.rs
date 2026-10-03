//! Counters, relay load (§11.8.1) and metric reports (§12.3-§12.5).

use crate::node::Node;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use webjet_core::crypto;
use webjet_core::types::now_ms;
use webjet_proto::{self as wp, RpcBody, msg_type as mt};

#[derive(Default, Debug)]
pub struct Counters {
    pub ecn_marked: AtomicU64,
    pub aqm_dropped: AtomicU64,
    pub acl_denied: AtomicU64,
    pub no_route: AtomicU64,
    pub cryptokey_dropped: AtomicU64,
    pub conntrack_limit: AtomicU64,
    pub snat_exhausted: AtomicU64,
    pub tun_rx: AtomicU64,
    pub tun_tx: AtomicU64,
    pub report_seq: AtomicU64,
    /// Bytes sent on hops that have since closed (keeps totals monotonic).
    pub retired_tx: AtomicU64,
    pub rule_hits: parking_lot::Mutex<BTreeMap<(String, bool), u64>>,
    pub last_report: parking_lot::Mutex<Option<serde_json::Value>>,
    /// For relay utilization: transit bytes at the last sample.
    pub load: parking_lot::Mutex<crate::load::LoadSampler>,
}

impl Counters {
    pub fn rule_hit(&self, rule: &str, allow: bool) {
        *self
            .rule_hits
            .lock()
            .entry((rule.to_string(), allow))
            .or_insert(0) += 1;
    }
}

/// Relay capacity (§11.8.1): local config or the Limits leaf when set,
/// otherwise auto-estimated from the highest sustained throughput and the
/// KCP bandwidth estimates, never below 100 Mbit/s.
fn capacity_mbps(n: &Node) -> u32 {
    let configured = n
        .cfg
        .limits
        .relay_capacity_mbps
        .map(|v| v as u64)
        .or_else(|| {
            let s = n.store.read();
            let v = s.view();
            let has_override = v.limits.as_ref().map(|l| {
                l.defaults
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .any(|x| x.name.as_deref() == Some("relay_capacity_mbps"))
                    || l.overrides.clone().unwrap_or_default().iter().any(|o| {
                        o.values
                            .clone()
                            .unwrap_or_default()
                            .iter()
                            .any(|x| x.name.as_deref() == Some("relay_capacity_mbps"))
                    })
            });
            if has_override == Some(true) {
                Some(limit(n, "relay_capacity_mbps", 1000))
            } else {
                None
            }
        });
    if let Some(c) = configured {
        return c.max(1) as u32;
    }
    let peak = n.metrics.load.lock().peak_mbps;
    let kcp_bw: f64 = n
        .hops
        .lock()
        .values()
        .filter_map(|h| h.kcp_stats.as_ref())
        .map(|k| k.bw_estimate_kbps.load(Ordering::Relaxed) as f64 / 1000.0)
        .fold(0.0, f64::max);
    peak.max(kcp_bw).max(100.0) as u32
}

/// Take one load sample (every 2 s from the gossip loop).
pub fn sample_load(n: &Node) {
    let cpu = crate::load::process_cpu_time().unwrap_or_default();
    let (bytes, queue_us) = {
        let hops = n.hops.lock();
        (
            hops.values()
                .map(|h| h.tx_bytes.load(Ordering::Relaxed))
                .sum::<u64>()
                + n.metrics.retired_tx.load(Ordering::Relaxed),
            hops.values()
                .map(|h| h.queue_delay_us.load(Ordering::Relaxed))
                .max()
                .unwrap_or(0),
        )
    };
    n.metrics.load.lock().record(
        std::time::Instant::now(),
        cpu,
        bytes,
        queue_us as f64 / 1000.0,
    );
}

/// Self-reported relay load (§11.8.1), each part a 30-second average:
/// forwarding utilization against capacity, the agent's CPU, circuits
/// against the cap, and hop queue delay against its budget.
pub fn relay_load(n: &Node) -> wp::RelayLoad {
    let cap = capacity_mbps(n).max(1);
    let avg = n.metrics.load.lock().averages().unwrap_or_default();
    let util = ((avg.tx_bps * 8.0 / 1e6) / cap as f64 * 100.0).clamp(0.0, 100.0) as u8;
    let circuits_cap = limit(n, "circuits_global", 50_000).max(1);
    let transit = n.circuits.lock().transit_count() as u64;
    let queue = webjet_core::routing::queue_load_pct(
        avg.queue_ms,
        webjet_core::queue::TARGET.as_secs_f64() * 1000.0,
        100.0,
    );
    wp::RelayLoad {
        util_pct: util,
        cpu_pct: avg.cpu_pct.round() as u8,
        circuits_pct: ((transit * 100 / circuits_cap).min(100)) as u8,
        capacity_mbps: cap,
        queue_pct: queue,
    }
}

fn counter(name: &str, v: u64) -> wp::Counter {
    wp::Counter {
        name: Some(name.into()),
        value: v,
    }
}

/// Build this node's signed metric report (§12.5).
pub fn build_report(n: &Arc<Node>) -> Vec<u8> {
    let now = now_ms();
    let routes: Vec<wp::RouteMetrics> = {
        let t = n.circuits.lock();
        t.routes
            .iter()
            .map(|(rid, r)| {
                let role = if r.src == n.me {
                    wp::RouteRole::Source
                } else if r.dst == n.me {
                    wp::RouteRole::Dest
                } else {
                    wp::RouteRole::Relay
                };
                wp::RouteMetrics {
                    route_id: Some(crypto::k32(rid)),
                    src: Some(crypto::k32(&r.src)),
                    dst: Some(crypto::k32(&r.dst)),
                    hops: Some(r.hops.iter().map(crypto::k32).collect()),
                    role,
                    fwd: Some(Box::new(wp::RouteDir {
                        frames: r.fwd.frames.load(Ordering::Relaxed),
                        bytes: r.fwd.bytes.load(Ordering::Relaxed),
                    })),
                    rev: Some(Box::new(wp::RouteDir {
                        frames: r.rev.frames.load(Ordering::Relaxed),
                        bytes: r.rev.bytes.load(Ordering::Relaxed),
                    })),
                    dropped: Some(vec![
                        counter("queue", r.dropped_queue.load(Ordering::Relaxed)),
                        counter("hop_limit", r.dropped_hop_limit.load(Ordering::Relaxed)),
                    ]),
                    ecn_marked: r.ecn_marked.load(Ordering::Relaxed),
                    circuit_setups: r.setups.load(Ordering::Relaxed),
                    active_since: r.active_since.load(Ordering::Relaxed),
                    e2e: None,
                }
            })
            .collect()
    };
    let links: Vec<wp::LinkMetrics> = n
        .hops
        .lock()
        .values()
        .map(|h| {
            let st = h.stats.lock();
            let k = h.kcp_stats.as_ref();
            wp::LinkMetrics {
                peer: Some(crypto::k32(&h.peer)),
                transport: h.transport,
                wire_tx: k
                    .map(|k| k.wire_tx.load(Ordering::Relaxed))
                    .unwrap_or(h.tx_bytes.load(Ordering::Relaxed)),
                wire_rx: k
                    .map(|k| k.wire_rx.load(Ordering::Relaxed))
                    .unwrap_or(h.rx_bytes.load(Ordering::Relaxed)),
                payload_tx: h.tx_bytes.load(Ordering::Relaxed),
                payload_rx: h.rx_bytes.load(Ordering::Relaxed),
                fec_parity_tx: k.map(|k| k.fec_parity_tx.load(Ordering::Relaxed)),
                kcp_retrans: k.map(|k| k.retrans.load(Ordering::Relaxed)),
                fec_recovered: k.map(|k| k.fec_recovered.load(Ordering::Relaxed)),
                fec_ratio_pct: k.map(|k| k.fec_ratio_pct.load(Ordering::Relaxed) as u8),
                bw_estimate_mbps: k
                    .map(|k| (k.bw_estimate_kbps.load(Ordering::Relaxed) / 1000) as u32),
                queue_delay_ms: (h.queue_delay_us.load(Ordering::Relaxed) / 1000) as u32,
                rtt_ms: st.effective().map(|e| e.0.ceil() as u32).unwrap_or(0),
                loss_pct: st
                    .effective()
                    .map(|e| (e.1 * 100.0).round() as u8)
                    .unwrap_or(0),
            }
        })
        .collect();
    let m = &n.metrics;
    let rule_hits = m
        .rule_hits
        .lock()
        .iter()
        .map(|((r, a), v)| wp::RuleHit {
            rule_id: Some(r.clone()),
            decision: if *a {
                wp::Action::Allow
            } else {
                wp::Action::Deny
            },
            flows: *v,
        })
        .collect();
    let refused = n
        .circuits
        .lock()
        .refused
        .iter()
        .map(|(k, v)| counter(k, *v))
        .collect();
    let alarms = n
        .alarms
        .lock()
        .iter()
        .map(|(k, (sev, since))| wp::Alarm {
            name: Some(k.clone()),
            severity: Some(sev.clone()),
            since: *since,
        })
        .collect();
    let rep = wp::MetricReport {
        node_id: Some(crypto::k32(&n.me)),
        boot_id: Some(wp::Id16::from_bytes(&n.boot_id)),
        software: Some(format!("webjetd/{}", env!("CARGO_PKG_VERSION"))),
        report_seq: m.report_seq.fetch_add(1, Ordering::Relaxed) + 1,
        taken_at: now,
        routes: Some(routes),
        links: Some(links),
        policy_version: n.store.read().view().policy_version,
        rule_hits: Some(rule_hits),
        circuits_refused: Some(refused),
        limit_hits: Some(vec![
            counter("acl_denied", m.acl_denied.load(Ordering::Relaxed)),
            counter("conntrack_limit", m.conntrack_limit.load(Ordering::Relaxed)),
            counter("snat_exhausted", m.snat_exhausted.load(Ordering::Relaxed)),
            counter("no_route", m.no_route.load(Ordering::Relaxed)),
            counter(
                "cryptokey_dropped",
                m.cryptokey_dropped.load(Ordering::Relaxed),
            ),
            counter("aqm_dropped", m.aqm_dropped.load(Ordering::Relaxed)),
            counter("ecn_marked", m.ecn_marked.load(Ordering::Relaxed)),
        ]),
        alarms: Some(alarms),
        load: Some(Box::new(relay_load(n))),
    };
    n.kp.sign_obj(mt::METRIC_REPORT, &rep)
}

/// Upload reports every 30 s to a controller; unsent ones go to a small
/// on-disk ring and are retried (§12.5).
pub async fn run(n: Arc<Node>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.tick().await;
    loop {
        tick.tick().await;
        let rep = build_report(&n);
        let mut ring: Vec<Vec<u8>> =
            crate::state::load_json::<Vec<String>>(&n.paths.metrics_ring())
                .ok()
                .flatten()
                .unwrap_or_default()
                .iter()
                .filter_map(|s| crate::state::unb64(s).ok())
                .collect();
        ring.push(rep);
        if ring.len() > 120 {
            let drop = ring.len() - 120;
            ring.drain(..drop);
        }
        if n.is_controller() {
            if let Some(c) = n.controller.get() {
                for r in ring.drain(..) {
                    c.ingest_metrics(n.me, &r);
                }
            }
        } else {
            while let Some(r) = ring.first().cloned() {
                let body = RpcBody::MetricUpload(Box::new(wp::MetricUpload { report: Some(r) }));
                match crate::rpc::call_any(&n, body, Duration::from_secs(10)).await {
                    Ok((_, RpcBody::RpcAck(a))) if a.ok => {
                        ring.remove(0);
                    }
                    _ => break,
                }
            }
        }
        let enc: Vec<String> = ring.iter().map(|r| crate::state::b64(r)).collect();
        let _ = crate::state::save_json(&n.paths.metrics_ring(), &enc);
    }
}

/// This node's own metrics as OpenMetrics text (local endpoint, `webjetctl
/// metrics`). Relays leave out per-route series locally (§12.5).
pub fn local_openmetrics(n: &Arc<Node>) -> String {
    let raw = build_report(n);
    let Ok(v) = webjet_core::crypto::open_envelope(&raw) else {
        return "# EOF\n".into();
    };
    let Ok(rep) = v.decode::<wp::MetricReport>() else {
        return "# EOF\n".into();
    };
    let s = n.store.read();
    let mut e = crate::exposition::Exposition::default();
    e.report(&rep, &crate::exposition::ViewNames(s.view()), !n.is_relay());
    e.render()
}

/// The effective value of a limit for this node (§16.4): local config,
/// then the tree's defaults and overrides, then the built-in.
pub fn limit(n: &Node, name: &str, builtin: u64) -> u64 {
    if let Some(v) = n.cfg.limits.get(name) {
        return v;
    }
    let s = n.store.read();
    let v = s.view();
    let me = v.nodes.get(&n.me).map(|x| v.subject(x));
    v.limit(me.as_ref(), name, builtin)
}
