//! Counters, relay load (§11.8.1) and metric reports (§12.3-§12.5).

use crate::node::Node;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use webjet_core::crypto::{self, Bytes32};
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
    /// Broadcast and multicast (§9.5.1): copies sent, datagrams delivered
    /// to the tun interface, copies or datagrams over a budget, and echoes
    /// of delivered datagrams the host sent back.
    pub multicast_tx: AtomicU64,
    pub multicast_rx: AtomicU64,
    pub multicast_limited: AtomicU64,
    pub multicast_echo: AtomicU64,
    /// Capture (§9.5.2): datagrams the host sent out another interface,
    /// taken into the overlay; and datagrams sent both ways, sent once.
    pub multicast_captured: AtomicU64,
    pub multicast_duplicate: AtomicU64,
    /// Overlay packets and bytes read from the tun interface (rx) and
    /// written to it (tx); reverse proxy traffic is counted apart.
    pub tun_rx: AtomicU64,
    pub tun_tx: AtomicU64,
    pub tun_rx_bytes: AtomicU64,
    pub tun_tx_bytes: AtomicU64,
    pub report_seq: AtomicU64,
    /// Bytes sent on hops that have since closed (keeps totals monotonic).
    pub retired_tx: AtomicU64,
    pub rule_hits: parking_lot::Mutex<BTreeMap<(String, bool), u64>>,
    pub last_report: parking_lot::Mutex<Option<serde_json::Value>>,
    /// For relay utilization: transit bytes at the last sample.
    pub load: parking_lot::Mutex<crate::load::LoadSampler>,
    /// Compression counters and the settings in force (§9.8).
    pub compression: crate::compression::Counters,
}

impl Counters {
    /// A packet read from the tun interface into the overlay.
    pub fn tun_in(&self, len: usize) {
        self.tun_rx.fetch_add(1, Ordering::Relaxed);
        self.tun_rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
    }

    /// A packet the overlay delivered to the tun interface.
    pub fn tun_out(&self, len: usize) {
        self.tun_tx.fetch_add(1, Ordering::Relaxed);
        self.tun_tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
    }

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
    if let Some(c) = limit_opt(n, "relay_capacity_mbps") {
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
    let circuits_cap = limit(n, "circuits_global");
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

/// End-to-end figures of the routes this node is an end of (§12.3), from the
/// probes of their local circuits: RTT and loss, whether the session sends on
/// it, and the session's path switches.
fn route_e2e(
    t: &crate::circuit::Table,
    sessions: &HashMap<Bytes32, (Option<u32>, u64)>,
) -> HashMap<Bytes32, wp::RouteE2e> {
    let mut out: HashMap<Bytes32, (u64, wp::RouteE2e)> = HashMap::new();
    for e in t.entries.values() {
        let crate::circuit::Kind::Local(c) = &e.kind else {
            continue;
        };
        if !c.is_source {
            continue; // source only (§12.3)
        }
        let p = c.probes.lock();
        if p.samples == 0 {
            continue;
        }
        let (primary, switches) = sessions.get(&c.peer).copied().unwrap_or((None, 0));
        let selected = match primary {
            Some(l) if l == c.label => 1,
            Some(_) => 2,
            None => 0,
        };
        let fig = wp::RouteE2e {
            rtt_ms: p.srtt_ms.ceil() as u32,
            loss_pct: (p.loss.max(p.window_loss()) * 100.0).round() as u8,
            selected,
            switches,
        };
        // Several circuits on one route (a rebuild): the best measured.
        let keep = out
            .get(&c.route_id)
            .is_none_or(|(s, f)| selected == 1 && f.selected != 1 || p.samples > *s);
        if keep {
            out.insert(c.route_id, (p.samples, fig));
        }
    }
    out.into_iter().map(|(k, (_, f))| (k, f)).collect()
}

/// Build this node's signed metric report (§12.5).
pub fn build_report(n: &Arc<Node>) -> Vec<u8> {
    let m = &n.metrics;
    let refused = n
        .circuits
        .lock()
        .refused
        .iter()
        .map(|(k, v)| counter(k, *v))
        .collect();
    let rep = wp::MetricReport {
        node_id: Some(crypto::k32(&n.me)),
        boot_id: Some(wp::Id16::from_bytes(&n.boot_id)),
        software: Some(format!("webjetd/{}", env!("CARGO_PKG_VERSION"))),
        report_seq: m.report_seq.fetch_add(1, Ordering::Relaxed) + 1,
        taken_at: now_ms(),
        routes: Some(route_metrics(n)),
        links: Some(link_metrics(n)),
        policy_version: n.store.snapshot().view().policy_version,
        rule_hits: Some(rule_hits(m)),
        circuits_refused: Some(refused),
        limit_hits: Some(limit_hits(m)),
        alarms: Some(alarms(n)),
        load: Some(Box::new(relay_load(n))),
        proxy: Some(
            n.dataplane
                .get()
                .map(|d| d.proxy.metrics())
                .unwrap_or_default(),
        ),
        compression: Some(m.compression.report()),
        tun: Some(Box::new(tun_metrics(m))),
    };
    n.kp.sign_obj(mt::METRIC_REPORT, &rep)
}

/// Every circuit through this node, with the end-to-end view of those it
/// starts or ends.
fn route_metrics(n: &Node) -> Vec<wp::RouteMetrics> {
    // Which circuit each session sends on, and its path switches; taken
    // before the circuit table (a session's lock is never taken inside it).
    let sessions: HashMap<Bytes32, (Option<u32>, u64)> = n
        .e2e
        .all()
        .iter()
        .map(|s| {
            (
                s.peer,
                (s.primary(), s.path_switches.load(Ordering::Relaxed)),
            )
        })
        .collect();
    let t = n.circuits.lock();
    let e2e = route_e2e(&t, &sessions);
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
                e2e: e2e.get(rid).cloned().map(Box::new),
            }
        })
        .collect()
}

/// Every hop of this node: wire and payload bytes, KCP/FEC counters, the
/// measured round trip and loss.
fn link_metrics(n: &Node) -> Vec<wp::LinkMetrics> {
    n.hops
        .lock()
        .values()
        .map(|h| {
            let st = h.stats.lock();
            let k = h.kcp_stats.as_ref();
            wp::LinkMetrics {
                peer: Some(crypto::k32(&h.peer)),
                transport: h.transport,
                wire_tx: k.map_or(h.tx_bytes.load(Ordering::Relaxed), |k| {
                    k.wire_tx.load(Ordering::Relaxed)
                }),
                wire_rx: k.map_or(h.rx_bytes.load(Ordering::Relaxed), |k| {
                    k.wire_rx.load(Ordering::Relaxed)
                }),
                payload_tx: h.tx_bytes.load(Ordering::Relaxed),
                payload_rx: h.rx_bytes.load(Ordering::Relaxed),
                fec_parity_tx: k.map(|k| k.fec_parity_tx.load(Ordering::Relaxed)),
                kcp_retrans: k.map(|k| k.retrans.load(Ordering::Relaxed)),
                fec_recovered: k.map(|k| k.fec_recovered.load(Ordering::Relaxed)),
                fec_ratio_pct: k.map(|k| k.fec_ratio_pct.load(Ordering::Relaxed) as u8),
                bw_estimate_mbps: k
                    .map(|k| (k.bw_estimate_kbps.load(Ordering::Relaxed) / 1000) as u32),
                queue_delay_ms: (h.queue_delay_us.load(Ordering::Relaxed) / 1000) as u32,
                rtt_ms: st.effective().map_or(0, |e| e.0.ceil() as u32),
                loss_pct: st.effective().map_or(0, |e| (e.1 * 100.0).round() as u8),
                lane_tx: k
                    .filter(|_| h.lane)
                    .map(|k| k.lane_tx.load(Ordering::Relaxed)),
                lane_rx: k
                    .filter(|_| h.lane)
                    .map(|k| k.lane_rx.load(Ordering::Relaxed)),
                lane_incomplete: k
                    .filter(|_| h.lane)
                    .map(|k| k.lane_incomplete.load(Ordering::Relaxed)),
            }
        })
        .collect()
}

/// Flows each policy rule allowed or denied.
fn rule_hits(m: &Counters) -> Vec<wp::RuleHit> {
    m.rule_hits
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
        .collect()
}

/// Packets dropped or marked by a limit, by reason.
fn limit_hits(m: &Counters) -> Vec<wp::Counter> {
    vec![
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
        counter(
            "multicast_limited",
            m.multicast_limited.load(Ordering::Relaxed),
        ),
        counter("multicast_echo", m.multicast_echo.load(Ordering::Relaxed)),
        counter(
            "multicast_duplicate",
            m.multicast_duplicate.load(Ordering::Relaxed),
        ),
    ]
}

fn alarms(n: &Node) -> Vec<wp::Alarm> {
    n.alarms
        .lock()
        .iter()
        .map(|(k, (sev, since))| wp::Alarm {
            name: Some(k.clone()),
            severity: Some(sev.clone()),
            since: *since,
        })
        .collect()
}

fn tun_metrics(m: &Counters) -> wp::TunMetrics {
    wp::TunMetrics {
        rx_packets: m.tun_rx.load(Ordering::Relaxed),
        rx_bytes: m.tun_rx_bytes.load(Ordering::Relaxed),
        tx_packets: m.tun_tx.load(Ordering::Relaxed),
        tx_bytes: m.tun_tx_bytes.load(Ordering::Relaxed),
        multicast_tx_packets: m.multicast_tx.load(Ordering::Relaxed),
        multicast_rx_packets: m.multicast_rx.load(Ordering::Relaxed),
        multicast_captured_packets: m.multicast_captured.load(Ordering::Relaxed),
    }
}

/// Reports kept for a later upload: 120 × 30 s = one hour.
const RING_MAX: usize = 120;

/// Upload reports every 30 s to a controller; unsent ones go to a small
/// on-disk ring and are retried (§12.5). The ring lives in memory and is
/// read from disk once, at start; it is written back only when it changed,
/// so a node whose uploads succeed doesn't rewrite the file every 30 s.
pub async fn run(n: Arc<Node>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.tick().await;
    let mut ring: VecDeque<Vec<u8>> =
        crate::state::load_json::<Vec<String>>(&n.paths.metrics_ring())
            .ok()
            .flatten()
            .unwrap_or_default()
            .iter()
            .filter_map(|s| crate::state::unb64(s).ok())
            .collect();
    // What the file holds now: an unchanged ring isn't written again.
    let mut saved: Option<Vec<u8>> = std::fs::read(n.paths.metrics_ring()).ok();
    loop {
        tick.tick().await;
        ring.push_back(build_report(&n));
        while ring.len() > RING_MAX {
            ring.pop_front();
        }
        if n.is_controller() {
            if let Some(c) = n.controller.get() {
                for r in ring.drain(..) {
                    c.ingest_metrics(n.me, &r);
                }
            }
        } else {
            while let Some(r) = ring.pop_front() {
                let body = RpcBody::MetricUpload(Box::new(wp::MetricUpload {
                    report: Some(r.clone()),
                }));
                match crate::rpc::call_any(&n, body, Duration::from_secs(10)).await {
                    Ok((_, RpcBody::RpcAck(a))) if a.ok => {}
                    _ => {
                        ring.push_front(r);
                        break;
                    }
                }
            }
        }
        save_ring(&n, &ring, &mut saved);
    }
}

/// Write the ring when it differs from what was last written.
fn save_ring(n: &Node, ring: &VecDeque<Vec<u8>>, saved: &mut Option<Vec<u8>>) {
    let enc: Vec<String> = ring.iter().map(|r| crate::state::b64(r)).collect();
    let Ok(bytes) = serde_json::to_vec_pretty(&enc) else {
        return;
    };
    if saved.as_ref() == Some(&bytes) {
        return;
    }
    let path = n.paths.metrics_ring();
    match crate::tasks::blocking(|| crate::state::write_private(&path, &bytes)) {
        Ok(()) => *saved = Some(bytes),
        Err(e) => tracing::debug!("saving unsent metrics: {e}"),
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
    let s = n.store.snapshot();
    let mut e = crate::exposition::Exposition::default();
    e.report(&rep, &crate::exposition::ViewNames(s.view()), !n.is_relay());
    e.render()
}

/// The effective value of a limit for this node (§16.4, `View::limit`):
/// node scope, network overrides, network value, built-in default. `None`
/// for a limit that is unset by default (relay capacity, rate ceiling) and
/// set nowhere.
pub fn limit_opt(n: &Node, name: &str) -> Option<u64> {
    n.store.snapshot().view().limit(&n.me, name)
}

/// A limit with a built-in default; never below 1.
pub fn limit(n: &Node, name: &str) -> u64 {
    limit_opt(n, name).unwrap_or(1).max(1)
}

/// [`limit`] as a count. Limits are u64 in the tree with no upper bound;
/// one beyond the type saturates (no limit) instead of wrapping to a small
/// number, or to 0 that would refuse everything.
pub fn limit_usize(n: &Node, name: &str) -> usize {
    usize::try_from(limit(n, name)).unwrap_or(usize::MAX)
}

/// [`limit`] as a per-second rate, saturating like [`limit_usize`].
pub fn limit_u32(n: &Node, name: &str) -> u32 {
    u32::try_from(limit(n, name)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testnode::{self, Cluster};
    use webjet_core::testutil::NodeSpec;
    use webjet_proto::Transport;

    fn lv(name: &str, value: u64) -> wp::LimitValue {
        wp::LimitValue {
            name: Some(name.into()),
            value,
        }
    }

    #[test]
    fn limits_resolve_node_override_network_default() {
        let mut c = Cluster::new();
        let (me, kp) = c.data_node("me", "10.7.0.2", &["tag:big"]);
        let (n, _d) = testnode::node(&mut c, me, kp);
        // Built-in defaults; unset ones are None, or 1 through `limit`.
        assert_eq!(limit(&n, "circuits_global"), 50_000);
        assert_eq!(limit_opt(&n, "relay_capacity_mbps"), None);
        assert_eq!(limit(&n, "relay_capacity_mbps"), 1);

        c.set_network(wp::NetworkConfig {
            limits: Some(Box::new(wp::Limits {
                defaults: Some(vec![lv("circuits_global", 100), lv("lookups_per_sec", 7)]),
                overrides: Some(vec![wp::LimitOverride {
                    select: Some(vec!["tag:big".into()]),
                    values: Some(vec![lv("circuits_global", 200)]),
                }]),
                ..Default::default()
            })),
            ..Default::default()
        })
        .unwrap();
        testnode::sync(&mut c, &n);
        assert_eq!(limit(&n, "circuits_global"), 200, "override for the tag");
        assert_eq!(limit(&n, "lookups_per_sec"), 7, "network value");

        c.set_node_config(wp::NodeConfig {
            node_id: Some(crypto::k32(&me)),
            limits: Some(vec![lv("circuits_global", 300)]),
            ..Default::default()
        })
        .unwrap();
        testnode::sync(&mut c, &n);
        assert_eq!(limit(&n, "circuits_global"), 300, "node scope wins");
    }

    #[test]
    fn huge_limits_saturate_instead_of_wrapping() {
        let mut c = Cluster::new();
        let (me, kp) = c.data_node("me", "10.7.0.2", &[]);
        let (n, _d) = testnode::node(&mut c, me, kp);
        // 2^32 as `as u32` is 0: every new flow would be refused.
        let big = 1u64 << 32;
        c.set_node_config(wp::NodeConfig {
            node_id: Some(crypto::k32(&me)),
            limits: Some(vec![
                lv("conntrack_new_per_sec", big),
                lv("conntrack_global", u64::MAX),
            ]),
            ..Default::default()
        })
        .unwrap();
        testnode::sync(&mut c, &n);
        assert_eq!(limit_u32(&n, "conntrack_new_per_sec"), u32::MAX);
        assert_eq!(
            limit_usize(&n, "conntrack_global"),
            usize::try_from(u64::MAX).unwrap_or(usize::MAX)
        );
        assert_eq!(
            limit_u32(&n, "lookups_per_sec"),
            limit(&n, "lookups_per_sec") as u32
        );
    }

    #[test]
    fn relay_load_and_capacity() {
        let mut c = Cluster::new();
        let (me, kp) = c.enroll(NodeSpec {
            name: "relay",
            ip: "10.7.0.3",
            roles: &[wp::Role::Data, wp::Role::Relay],
            ..Default::default()
        });
        let (n, _d) = testnode::node(&mut c, me, kp);
        // Estimated, never below 100 Mbit/s.
        assert_eq!(relay_load(&n).capacity_mbps, 100);
        c.set_node_config(wp::NodeConfig {
            node_id: Some(crypto::k32(&me)),
            limits: Some(vec![
                lv("relay_capacity_mbps", 40),
                lv("circuits_global", 10),
            ]),
            ..Default::default()
        })
        .unwrap();
        testnode::sync(&mut c, &n);
        let l = relay_load(&n);
        assert_eq!((l.capacity_mbps, l.util_pct, l.circuits_pct), (40, 0, 0));
        sample_load(&n);
    }

    #[test]
    fn counters() {
        let m = Counters::default();
        m.tun_in(100);
        m.tun_in(50);
        m.tun_out(10);
        m.rule_hit("web", true);
        m.rule_hit("web", true);
        m.rule_hit("web", false);
        assert_eq!(m.tun_rx.load(Ordering::Relaxed), 2);
        assert_eq!(m.tun_rx_bytes.load(Ordering::Relaxed), 150);
        assert_eq!(m.tun_tx_bytes.load(Ordering::Relaxed), 10);
        let hits = m.rule_hits.lock();
        assert_eq!(hits[&("web".to_string(), true)], 2);
        assert_eq!(hits[&("web".to_string(), false)], 1);
    }

    #[tokio::test]
    async fn report_is_signed_and_complete() {
        let mut c = Cluster::new();
        let (me, kp) = c.data_node("me", "10.7.0.2", &[]);
        let (peer, _) = c.data_node("peer", "10.7.0.3", &[]);
        let (n, _d) = testnode::node(&mut c, me, kp.clone());
        n.metrics.rule_hit("web", true);
        n.metrics.acl_denied.fetch_add(3, Ordering::Relaxed);
        n.metrics.tun_in(1500);
        n.alarm("clock", "warning", "test".into());
        let (hop, _rx) = n.test_hop(peer, Transport::TcpTls);
        hop.tx_bytes.store(1000, Ordering::Relaxed);

        let raw = build_report(&n);
        let v = crypto::open_envelope(&raw).unwrap();
        assert_eq!((v.ty, v.signer), (mt::METRIC_REPORT, kp.public()));
        let r: wp::MetricReport = v.decode().unwrap();
        assert_eq!(crypto::opt_k32(&r.node_id), me);
        assert_eq!(r.report_seq, 1);
        let links = r.links.unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(crypto::opt_k32(&links[0].peer), peer);
        assert_eq!((links[0].payload_tx, links[0].wire_tx), (1000, 1000));
        let hits = r.rule_hits.unwrap();
        assert_eq!(hits[0].rule_id.as_deref(), Some("web"));
        assert_eq!(hits[0].flows, 1);
        let lim = r.limit_hits.unwrap();
        assert!(
            lim.iter()
                .any(|c| c.name.as_deref() == Some("acl_denied") && c.value == 3)
        );
        assert_eq!(r.tun.unwrap().rx_bytes, 1500);
        assert_eq!(r.alarms.unwrap()[0].name.as_deref(), Some("clock"));
        assert_eq!(r.compression.unwrap().len(), 2);
        // The sequence number goes up per report.
        let raw = build_report(&n);
        let r: wp::MetricReport = crypto::open_envelope(&raw).unwrap().decode().unwrap();
        assert_eq!(r.report_seq, 2);

        let text = local_openmetrics(&n);
        assert!(text.ends_with("# EOF\n"), "{text}");
        for series in [
            "webjet_rule_flows",
            "webjet_limit_hits",
            "webjet_tun_bytes",
            "webjet_alarm",
        ] {
            assert!(text.contains(series), "{series} missing:\n{text}");
        }
    }

    #[tokio::test]
    async fn route_figures_come_from_source_circuits() {
        use crate::circuit::{Entry, Kind, LocalCircuit};
        let mut c = Cluster::new();
        let (me, kp) = c.data_node("me", "10.7.0.2", &[]);
        let (peer, _) = c.data_node("peer", "10.7.0.3", &[]);
        let (n, _d) = testnode::node(&mut c, me, kp);
        let rid = crypto::route_id(&me, &peer, &[]);
        let circuit = |label: u32, source: bool, rtt: Option<f64>| {
            let mut probes = webjet_core::routing::LinkStats::default();
            if let Some(ms) = rtt {
                probes.on_sent_at(1, 0, now_ms());
                probes.on_ack_at(1, (ms * 1000.0) as u64, now_ms());
            }
            Arc::new(LocalCircuit {
                peer,
                label,
                next: peer,
                out_label: parking_lot::Mutex::new(Some(label)),
                hops: vec![],
                route_id: rid,
                acct: Default::default(),
                is_source: source,
                created: std::time::Instant::now(),
                probes: parking_lot::Mutex::new(probes),
                e2e_rtt_ms: parking_lot::Mutex::new(None),
                last_rx: parking_lot::Mutex::new(std::time::Instant::now()),
                live: Default::default(),
            })
        };
        let mut t = crate::circuit::Table::default();
        for (label, src, rtt) in [
            (1, true, Some(20.0)),
            (2, true, None),
            (3, false, Some(5.0)),
        ] {
            t.entries.insert(
                (peer, label),
                Entry {
                    kind: Kind::Local(circuit(label, src, rtt)),
                    created: std::time::Instant::now(),
                },
            );
        }
        // The session sends on circuit 1, with 4 switches so far.
        let sessions = HashMap::from([(peer, (Some(1), 4))]);
        let e = route_e2e(&t, &sessions);
        assert_eq!(e.len(), 1);
        let f = &e[&rid];
        assert_eq!((f.rtt_ms, f.selected, f.switches), (20, 1, 4));
        // A session on another circuit: this one is "not selected" (2);
        // no session at all: 0.
        assert_eq!(
            route_e2e(&t, &HashMap::from([(peer, (Some(9), 0))]))[&rid].selected,
            2
        );
        assert_eq!(route_e2e(&t, &HashMap::new())[&rid].selected, 0);
        drop(n);
    }

    #[test]
    fn the_ring_is_written_only_when_it_changes() {
        let mut c = Cluster::new();
        let (me, kp) = c.data_node("a", "10.7.0.5", &[]);
        let (n, _d) = testnode::node(&mut c, me, kp);
        let path = n.paths.metrics_ring();
        let mut ring: VecDeque<Vec<u8>> = VecDeque::from([vec![1, 2, 3]]);
        let mut saved = None;
        save_ring(&n, &ring, &mut saved);
        let first = std::fs::read(&path).unwrap();
        assert_eq!(saved.as_deref(), Some(&first[..]));
        // Unchanged: not written (a removed file stays removed).
        std::fs::remove_file(&path).unwrap();
        save_ring(&n, &ring, &mut saved);
        assert!(!path.exists());
        // Changed: written, and it reads back as the ring.
        ring.clear();
        save_ring(&n, &ring, &mut saved);
        let back: Vec<String> = crate::state::load_json(&path).unwrap().unwrap();
        assert!(back.is_empty());
    }
}
