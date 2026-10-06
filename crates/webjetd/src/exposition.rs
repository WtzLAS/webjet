//! OpenMetrics exposition (§12.5): metric reports rendered as OpenMetrics
//! text for a Prometheus scrape.
//!
//! * Controllers keep the latest verified report of every node (reports
//!   are forwarded between controllers, so each one holds the full set) and
//!   serve them all; Prometheus scrapes any or all controllers. Samples
//!   carry the report's `taken_at` timestamp, so samples from different
//!   controllers coincide.
//! * Any node can serve its own report on localhost for debugging. Locally
//!   a relay omits per-route series (§12.5: no `route_id` labels on relays).
//!
//! Mapping (§12.5.1): monotonic counters are OpenMetrics counters (`_total`),
//! gauges are gauges. `boot_id` is not a label.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use webjet_core::crypto::{Bytes32, opt_k32};
use webjet_proto as wp;

/// Names for node ids and the owner (account name) of each node.
pub trait Names {
    fn node(&self, id: &Bytes32) -> String;
    fn owner(&self, id: &Bytes32) -> String;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Counter,
    Gauge,
}

struct Family {
    kind: Kind,
    help: &'static str,
    samples: Vec<String>,
}

/// The node a report is about, as labels.
struct Subject {
    node: String,
    owner: String,
    /// The report's `taken_at`, ms.
    ts: u64,
}

/// Collects samples by family so each family is written once with its
/// metadata, as OpenMetrics requires.
#[derive(Default)]
pub struct Exposition {
    families: BTreeMap<&'static str, Family>,
}

pub fn escape(v: &str) -> String {
    let mut o = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            c => o.push(c),
        }
    }
    o
}

fn labels(l: &[(&str, &str)]) -> String {
    if l.is_empty() {
        return String::new();
    }
    let inner: Vec<String> = l
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
        .collect();
    format!("{{{}}}", inner.join(","))
}

fn fmt_value(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

impl Exposition {
    fn add(
        &mut self,
        name: &'static str,
        kind: Kind,
        help: &'static str,
        l: &[(&str, &str)],
        v: f64,
        ts_ms: u64,
    ) {
        let f = self.families.entry(name).or_insert_with(|| Family {
            kind,
            help,
            samples: Vec::new(),
        });
        debug_assert!(f.kind == kind, "metric {name} registered with two types");
        let suffix = if kind == Kind::Counter { "_total" } else { "" };
        let ts = format!("{}.{:03}", ts_ms / 1000, ts_ms % 1000);
        f.samples
            .push(format!("{name}{suffix}{} {} {ts}", labels(l), fmt_value(v)));
    }

    pub fn counter(
        &mut self,
        name: &'static str,
        help: &'static str,
        l: &[(&str, &str)],
        v: u64,
        ts_ms: u64,
    ) {
        self.add(name, Kind::Counter, help, l, v as f64, ts_ms);
    }

    pub fn gauge(
        &mut self,
        name: &'static str,
        help: &'static str,
        l: &[(&str, &str)],
        v: f64,
        ts_ms: u64,
    ) {
        self.add(name, Kind::Gauge, help, l, v, ts_ms);
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for (name, f) in &self.families {
            let _ = writeln!(
                out,
                "# TYPE {name} {}",
                if f.kind == Kind::Counter {
                    "counter"
                } else {
                    "gauge"
                }
            );
            let _ = writeln!(out, "# HELP {name} {}", f.help);
            for s in &f.samples {
                out.push_str(s);
                out.push('\n');
            }
        }
        out.push_str("# EOF\n");
        out
    }

    /// Add one node's report. `with_routes = false` omits per-route series.
    pub fn report(&mut self, rep: &wp::MetricReport, names: &dyn Names, with_routes: bool) {
        let id = opt_k32(&rep.node_id);
        let node = names.node(&id);
        let owner = names.owner(&id);
        let ts = rep.taken_at;
        let base = [("node", node.as_str()), ("owner", owner.as_str())];
        let s = Subject {
            node: node.clone(),
            owner: owner.clone(),
            ts,
        };
        self.gauge(
            "webjet_node_info",
            "Software and identity of a reporting node.",
            &[
                ("node", &node),
                ("owner", &owner),
                ("node_id", &hex::encode(&id[..8])),
                ("software", rep.software.as_deref().unwrap_or("")),
            ],
            1.0,
            ts,
        );
        self.gauge(
            "webjet_policy_version",
            "Policy version the node enforces.",
            &base,
            rep.policy_version as f64,
            ts,
        );
        self.gauge(
            "webjet_report_seq",
            "Sequence number of the node's latest metric report.",
            &base,
            rep.report_seq as f64,
            ts,
        );
        self.load(rep, &s);
        if with_routes {
            self.routes(rep, names, &s);
        }
        self.links(rep, names, &s);
        self.refusals(rep, &s);
        self.compression(rep, &s);
        self.tun(rep, &s);
        self.proxy(rep, names, &s);
        self.alarms(rep, &s);
    }

    /// Load and queue gauges.
    fn load(&mut self, rep: &wp::MetricReport, s: &Subject) {
        let (node, owner, ts) = (s.node.clone(), s.owner.clone(), s.ts);
        let base = [("node", node.as_str()), ("owner", owner.as_str())];
        if let Some(l) = &rep.load {
            self.gauge(
                "webjet_load_cpu_ratio",
                "Agent CPU use as a share of all cores, 30 s average.",
                &base,
                l.cpu_pct as f64 / 100.0,
                ts,
            );
            self.gauge(
                "webjet_load_util_ratio",
                "Forwarding utilization against relay capacity, 30 s average.",
                &base,
                l.util_pct as f64 / 100.0,
                ts,
            );
            self.gauge(
                "webjet_load_circuits_ratio",
                "Transit circuits against the circuit cap.",
                &base,
                l.circuits_pct as f64 / 100.0,
                ts,
            );
            self.gauge(
                "webjet_load_queue_ratio",
                "Hop queue delay against its budget, 30 s average.",
                &base,
                l.queue_pct as f64 / 100.0,
                ts,
            );
            self.gauge(
                "webjet_relay_capacity_mbps",
                "Configured or estimated relay capacity.",
                &base,
                l.capacity_mbps as f64,
                ts,
            );
            let lv = webjet_core::routing::relay_load(
                l.util_pct,
                l.cpu_pct,
                l.circuits_pct,
                l.queue_pct,
            );
            self.gauge(
                "webjet_load_ratio",
                "Advertised relay load: the highest of the load figures, in 10% steps.",
                &base,
                lv as f64 / 100.0,
                ts,
            );
        }
    }

    /// Per-route series (sources, relays, destinations).
    fn routes(&mut self, rep: &wp::MetricReport, names: &dyn Names, s: &Subject) {
        let (node, owner, ts) = (s.node.clone(), s.owner.clone(), s.ts);
        for r in rep.routes.clone().unwrap_or_default() {
            let rid = hex::encode(&opt_k32(&r.route_id)[..8]);
            let role = match r.role {
                wp::RouteRole::Source => "source",
                wp::RouteRole::Relay => "relay",
                wp::RouteRole::Dest => "dest",
            };
            let src = names.node(&opt_k32(&r.src));
            let dst = names.node(&opt_k32(&r.dst));
            let rl = |dir: &'static str| -> Vec<(&'static str, String)> {
                vec![
                    ("node", node.clone()),
                    ("owner", owner.clone()),
                    ("role", role.into()),
                    ("route_id", rid.clone()),
                    ("src", src.clone()),
                    ("dst", dst.clone()),
                    ("direction", dir.into()),
                ]
            };
            for (dir, d) in [("fwd", &r.fwd), ("rev", &r.rev)] {
                if let Some(d) = d {
                    let l = rl(dir);
                    let lr: Vec<(&str, &str)> = l.iter().map(|(k, v)| (*k, v.as_str())).collect();
                    self.counter(
                        "webjet_route_bytes",
                        "Bytes carried on a route, by direction.",
                        &lr,
                        d.bytes,
                        ts,
                    );
                    self.counter(
                        "webjet_route_frames",
                        "Frames carried on a route, by direction.",
                        &lr,
                        d.frames,
                        ts,
                    );
                }
            }
            let l = rl("fwd");
            let lr: Vec<(&str, &str)> = l
                .iter()
                .filter(|(k, _)| *k != "direction")
                .map(|(k, v)| (*k, v.as_str()))
                .collect();
            for c in r.dropped.clone().unwrap_or_default() {
                let reason = c.name.clone().unwrap_or_default();
                let mut ld = lr.clone();
                ld.push(("reason", &reason));
                self.counter(
                    "webjet_route_dropped",
                    "Frames dropped on a route, by reason.",
                    &ld,
                    c.value,
                    ts,
                );
            }
            self.counter(
                "webjet_route_ecn_marked",
                "Frames marked Congestion Experienced on a route.",
                &lr,
                r.ecn_marked,
                ts,
            );
            self.counter(
                "webjet_route_circuit_setups",
                "Circuit (re)builds for a route; shows flapping.",
                &lr,
                r.circuit_setups,
                ts,
            );
            if let Some(e) = &r.e2e {
                self.gauge(
                    "webjet_route_e2e_rtt_ms",
                    "End-to-end probe RTT (EWMA) of a route.",
                    &lr,
                    e.rtt_ms as f64,
                    ts,
                );
                self.gauge(
                    "webjet_route_e2e_loss_ratio",
                    "End-to-end probe loss (EWMA) of a route.",
                    &lr,
                    e.loss_pct as f64 / 100.0,
                    ts,
                );
                self.gauge(
                    "webjet_route_selected",
                    "Whether the session sends on this route: 0 idle, 1 primary, 2 backup.",
                    &lr,
                    e.selected as f64,
                    ts,
                );
                self.counter(
                    "webjet_route_path_switches",
                    "Times the session to this route's destination moved its traffic to another circuit.",
                    &lr,
                    e.switches,
                    ts,
                );
            }
        }
    }

    /// Per-link quality series.
    fn links(&mut self, rep: &wp::MetricReport, names: &dyn Names, s: &Subject) {
        let (node, owner, ts) = (s.node.clone(), s.owner.clone(), s.ts);
        for l in rep.links.clone().unwrap_or_default() {
            let peer = names.node(&opt_k32(&l.peer));
            let t = l.transport.name();
            let ll = [
                ("node", node.as_str()),
                ("owner", owner.as_str()),
                ("peer", peer.as_str()),
                ("transport", t),
            ];
            for (dir, w, p) in [
                ("tx", l.wire_tx, l.payload_tx),
                ("rx", l.wire_rx, l.payload_rx),
            ] {
                let mut ld = ll.to_vec();
                ld.push(("direction", dir));
                self.counter(
                    "webjet_link_wire_bytes",
                    "Bytes on the wire of a hop, including transport overhead.",
                    &ld,
                    w,
                    ts,
                );
                self.counter(
                    "webjet_link_payload_bytes",
                    "Hop record bytes carried on a hop.",
                    &ld,
                    p,
                    ts,
                );
            }
            if let Some(v) = l.fec_parity_tx {
                self.counter(
                    "webjet_link_fec_parity_bytes",
                    "FEC parity bytes sent on a KCP hop.",
                    &ll,
                    v,
                    ts,
                );
            }
            if let Some(v) = l.kcp_retrans {
                self.counter(
                    "webjet_link_kcp_retransmits",
                    "KCP retransmissions on a hop.",
                    &ll,
                    v,
                    ts,
                );
            }
            if let Some(v) = l.fec_recovered {
                self.counter(
                    "webjet_link_fec_recovered",
                    "Packets recovered by FEC on a hop.",
                    &ll,
                    v,
                    ts,
                );
            }
            if let Some(v) = l.fec_ratio_pct {
                self.gauge(
                    "webjet_link_fec_ratio",
                    "Current FEC parity ratio of a hop.",
                    &ll,
                    v as f64 / 100.0,
                    ts,
                );
            }
            if let Some(v) = l.bw_estimate_mbps {
                self.gauge(
                    "webjet_link_bw_estimate_mbps",
                    "Bandwidth estimate of a KCP hop.",
                    &ll,
                    v as f64,
                    ts,
                );
            }
            self.gauge(
                "webjet_link_queue_delay_ms",
                "Hop queue delay.",
                &ll,
                l.queue_delay_ms as f64,
                ts,
            );
            self.gauge(
                "webjet_link_rtt_ms",
                "Hop RTT (effective, including long-term history).",
                &ll,
                l.rtt_ms as f64,
                ts,
            );
            self.gauge(
                "webjet_link_loss_ratio",
                "Hop loss (effective, including long-term history).",
                &ll,
                l.loss_pct as f64 / 100.0,
                ts,
            );
        }
    }

    /// Policy rule hits, refused circuits and limit hits.
    fn refusals(&mut self, rep: &wp::MetricReport, s: &Subject) {
        let (node, owner, ts) = (s.node.clone(), s.owner.clone(), s.ts);
        for h in rep.rule_hits.clone().unwrap_or_default() {
            let rule = h.rule_id.clone().unwrap_or_default();
            let dec = if h.decision == wp::Action::Allow {
                "allow"
            } else {
                "deny"
            };
            self.counter(
                "webjet_rule_flows",
                "New flows decided by a policy rule.",
                &[
                    ("node", &node),
                    ("owner", &owner),
                    ("rule_id", &rule),
                    ("decision", dec),
                ],
                h.flows,
                ts,
            );
        }
        for c in rep.circuits_refused.clone().unwrap_or_default() {
            let reason = c.name.clone().unwrap_or_default();
            self.counter(
                "webjet_circuits_refused",
                "Circuit setups this node refused, by reason.",
                &[("node", &node), ("owner", &owner), ("reason", &reason)],
                c.value,
                ts,
            );
        }
        for c in rep.limit_hits.clone().unwrap_or_default() {
            let what = c.name.clone().unwrap_or_default();
            self.counter(
                "webjet_limit_hits",
                "Packets or flows refused by a limit or check, by kind.",
                &[("node", &node), ("owner", &owner), ("limit", &what)],
                c.value,
                ts,
            );
        }
    }

    /// Compression (§9.8), per plane.
    fn compression(&mut self, rep: &wp::MetricReport, s: &Subject) {
        let (node, owner, ts) = (s.node.clone(), s.owner.clone(), s.ts);
        for c in rep.compression.clone().unwrap_or_default() {
            let plane = c.plane.clone().unwrap_or_default();
            let l = [
                ("node", node.as_str()),
                ("owner", owner.as_str()),
                ("plane", plane.as_str()),
            ];
            for (dir, msgs, raw, wire) in [
                ("tx", c.tx_messages, c.tx_raw_bytes, c.tx_wire_bytes),
                ("rx", c.rx_messages, c.rx_raw_bytes, c.rx_wire_bytes),
            ] {
                let mut ld = l.to_vec();
                ld.push(("direction", dir));
                self.counter(
                    "webjet_compression_messages",
                    "Compressed messages sent or received, by plane (control: zstd, data: lz4).",
                    &ld,
                    msgs,
                    ts,
                );
                self.counter(
                    "webjet_compression_raw_bytes",
                    "Bytes of compressed messages before compression or after decompression.",
                    &ld,
                    raw,
                    ts,
                );
                self.counter(
                    "webjet_compression_wire_bytes",
                    "Bytes of compressed messages as sent or received.",
                    &ld,
                    wire,
                    ts,
                );
            }
            self.counter(
                "webjet_compression_skipped",
                "Messages sent uncompressed although compression was on: no gain, known encrypted traffic or a backed-off flow.",
                &l,
                c.tx_skipped,
                ts,
            );
            self.counter(
                "webjet_compression_errors",
                "Received compressed messages that failed to decompress.",
                &l,
                c.rx_errors,
                ts,
            );
        }
    }

    /// Overlay traffic through the tun interface, by direction.
    fn tun(&mut self, rep: &wp::MetricReport, s: &Subject) {
        let (node, owner, ts) = (s.node.clone(), s.owner.clone(), s.ts);
        if let Some(t) = &rep.tun {
            for (dir, packets, bytes) in [
                ("rx", t.rx_packets, t.rx_bytes),
                ("tx", t.tx_packets, t.tx_bytes),
            ] {
                let l = [
                    ("node", node.as_str()),
                    ("owner", owner.as_str()),
                    ("direction", dir),
                ];
                self.counter(
                    "webjet_tun_packets",
                    "Overlay packets read from the tun interface (rx) or written to it (tx); reverse proxy traffic excluded.",
                    &l,
                    packets,
                    ts,
                );
                self.counter(
                    "webjet_tun_bytes",
                    "Bytes of overlay packets read from the tun interface (rx) or written to it (tx).",
                    &l,
                    bytes,
                    ts,
                );
            }
        }
    }

    /// Reverse proxy traffic (§11.11), apart from the overlay's series.
    fn proxy(&mut self, rep: &wp::MetricReport, names: &dyn Names, s: &Subject) {
        let (node, owner, ts) = (s.node.clone(), s.owner.clone(), s.ts);
        for m in rep.proxy.clone().unwrap_or_default() {
            let rule = m.rule.clone().unwrap_or_default();
            let side = if m.ingress { "ingress" } else { "target" };
            let ingress = names.node(&opt_k32(&m.node));
            let l = [
                ("node", node.as_str()),
                ("owner", owner.as_str()),
                ("rule", rule.as_str()),
                ("side", side),
                ("ingress", ingress.as_str()),
            ];
            self.counter(
                "webjet_proxy_flows",
                "Reverse proxy flows started, by rule and side (ingress or target).",
                &l,
                m.flows,
                ts,
            );
            self.gauge(
                "webjet_proxy_active_flows",
                "Reverse proxy flows tracked now.",
                &l,
                m.active as f64,
                ts,
            );
            self.counter(
                "webjet_proxy_refused",
                "New reverse proxy flows refused (policy, limits, no usable target, real address not accepted).",
                &l,
                m.refused,
                ts,
            );
            for (dir, packets, bytes) in [
                ("to_target", m.to_target_packets, m.to_target_bytes),
                ("to_client", m.to_client_packets, m.to_client_bytes),
            ] {
                let mut ld = l.to_vec();
                ld.push(("direction", dir));
                self.counter(
                    "webjet_proxy_packets",
                    "Reverse proxy packets (inner IP packets), by direction.",
                    &ld,
                    packets,
                    ts,
                );
                self.counter(
                    "webjet_proxy_bytes",
                    "Reverse proxy bytes (inner IP packets), by direction.",
                    &ld,
                    bytes,
                    ts,
                );
            }
        }
    }

    /// Active alarms.
    fn alarms(&mut self, rep: &wp::MetricReport, s: &Subject) {
        let (node, ts) = (s.node.clone(), s.ts);
        for a in rep.alarms.clone().unwrap_or_default() {
            let name = a.name.clone().unwrap_or_default();
            let sev = a.severity.clone().unwrap_or_default();
            self.gauge(
                "webjet_alarm",
                "Active alarms (§19.7); 1 while active.",
                &[("node", &node), ("alarm", &name), ("severity", &sev)],
                1.0,
                ts,
            );
        }
    }
}

/// Names from a node's view of the network.
pub struct ViewNames<'a>(pub &'a webjet_core::store::View);

impl Names for ViewNames<'_> {
    fn node(&self, id: &Bytes32) -> String {
        self.0
            .nodes
            .get(id)
            .map_or_else(|| hex::encode(&id[..6]), |n| n.name.clone())
    }
    fn owner(&self, id: &Bytes32) -> String {
        self.0
            .nodes
            .get(id)
            .and_then(|n| self.0.accounts.get(&n.owner))
            .map(|a| a.name.clone())
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------- HTTP endpoint

pub const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Serve `GET /metrics` on `addr`. `body` renders the exposition per scrape.
pub async fn serve(
    addr: std::net::SocketAddr,
    body: Arc<dyn Fn() -> String + Send + Sync>,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("OpenMetrics endpoint at http://{addr}/metrics");
    loop {
        let (mut s, _) = l.accept().await?;
        let body = body.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut n = 0;
            // Read the request head.
            loop {
                let Ok(Ok(k)) =
                    tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf[n..]))
                        .await
                else {
                    return;
                };
                if k == 0 {
                    return;
                }
                n += k;
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") || n == buf.len() {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buf[..n]);
            let line = head.lines().next().unwrap_or("");
            let mut parts = line.split_whitespace();
            let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            let path = path.split('?').next().unwrap_or("");
            let resp = if method != "GET" && method != "HEAD" {
                "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
            } else if path == "/metrics" {
                let b = body();
                let mut r = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {CONTENT_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    b.len()
                );
                if method == "GET" {
                    r.push_str(&b);
                }
                r
            } else {
                let b = "see /metrics\n";
                format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                    b.len()
                )
            };
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webjet_core::crypto;

    struct N;
    impl Names for N {
        fn node(&self, id: &Bytes32) -> String {
            format!("n{}", id[0])
        }
        fn owner(&self, _: &Bytes32) -> String {
            "alice".into()
        }
    }

    fn report() -> wp::MetricReport {
        wp::MetricReport {
            node_id: Some(crypto::k32(&[1; 32])),
            software: Some("webjetd/0.1.0".into()),
            report_seq: 5,
            taken_at: 1_700_000_000_123,
            routes: Some(vec![wp::RouteMetrics {
                route_id: Some(crypto::k32(&[9; 32])),
                src: Some(crypto::k32(&[1; 32])),
                dst: Some(crypto::k32(&[2; 32])),
                role: wp::RouteRole::Source,
                fwd: Some(Box::new(wp::RouteDir {
                    frames: 10,
                    bytes: 1000,
                })),
                rev: Some(Box::new(wp::RouteDir {
                    frames: 4,
                    bytes: 400,
                })),
                dropped: Some(vec![wp::Counter {
                    name: Some("queue".into()),
                    value: 2,
                }]),
                e2e: Some(Box::new(wp::RouteE2e {
                    rtt_ms: 31,
                    loss_pct: 2,
                    selected: 1,
                    switches: 4,
                })),
                ..Default::default()
            }]),
            links: Some(vec![wp::LinkMetrics {
                peer: Some(crypto::k32(&[3; 32])),
                transport: wp::Transport::KcpFecTls,
                wire_tx: 7,
                rtt_ms: 12,
                loss_pct: 5,
                fec_ratio_pct: Some(10),
                ..Default::default()
            }]),
            rule_hits: Some(vec![wp::RuleHit {
                rule_id: Some("web \"tier\"".into()),
                decision: wp::Action::Deny,
                flows: 3,
            }]),
            alarms: Some(vec![wp::Alarm {
                name: Some("clock_skew".into()),
                severity: Some("warning".into()),
                since: 1,
            }]),
            load: Some(Box::new(wp::RelayLoad {
                util_pct: 12,
                cpu_pct: 34,
                circuits_pct: 5,
                capacity_mbps: 1000,
                queue_pct: 0,
            })),
            proxy: Some(vec![wp::ProxyMetrics {
                rule: Some("web".into()),
                ingress: true,
                node: Some(crypto::k32(&[1; 32])),
                flows: 4,
                active: 2,
                to_target_packets: 40,
                to_target_bytes: 4000,
                to_client_packets: 30,
                to_client_bytes: 9000,
                refused: 1,
            }]),
            tun: Some(Box::new(wp::TunMetrics {
                rx_packets: 11,
                rx_bytes: 1100,
                tx_packets: 7,
                tx_bytes: 700,
            })),
            compression: Some(vec![wp::CompressionMetrics {
                plane: Some("control".into()),
                tx_messages: 10,
                tx_raw_bytes: 50000,
                tx_wire_bytes: 12000,
                tx_skipped: 3,
                ..Default::default()
            }]),
            ..Default::default()
        }
    }

    #[test]
    fn renders_valid_openmetrics() {
        let mut e = Exposition::default();
        e.report(&report(), &N, true);
        let t = e.render();
        assert!(t.ends_with("# EOF\n"));
        assert!(t.contains("# TYPE webjet_route_bytes counter\n"));
        assert!(t.contains("webjet_route_bytes_total{node=\"n1\",owner=\"alice\",role=\"source\",route_id=\"0909090909090909\",src=\"n1\",dst=\"n2\",direction=\"fwd\"} 1000 1700000000.123\n"), "{t}");
        assert!(t.contains("webjet_link_loss_ratio{node=\"n1\",owner=\"alice\",peer=\"n3\",transport=\"kcp\"} 0.05 1700000000.123"));
        assert!(
            t.contains("rule_id=\"web \\\"tier\\\"\""),
            "label values are escaped"
        );
        assert!(t.contains("webjet_load_cpu_ratio{node=\"n1\",owner=\"alice\"} 0.34 "));
        assert!(t.contains("webjet_load_ratio{node=\"n1\",owner=\"alice\"} 0.3 "));
        let rl = "node=\"n1\",owner=\"alice\",role=\"source\",route_id=\"0909090909090909\",src=\"n1\",dst=\"n2\"";
        assert!(
            t.contains(&format!("webjet_route_e2e_rtt_ms{{{rl}}} 31 ")),
            "{t}"
        );
        assert!(t.contains(&format!("webjet_route_e2e_loss_ratio{{{rl}}} 0.02 ")));
        assert!(t.contains(&format!("webjet_route_selected{{{rl}}} 1 ")));
        assert!(t.contains(&format!("webjet_route_path_switches_total{{{rl}}} 4 ")));
        assert!(t.contains(
            "webjet_tun_packets_total{node=\"n1\",owner=\"alice\",direction=\"rx\"} 11 "
        ));
        assert!(
            t.contains("webjet_tun_bytes_total{node=\"n1\",owner=\"alice\",direction=\"tx\"} 700 ")
        );
        // Proxy traffic has its own families.
        assert!(t.contains("webjet_proxy_bytes_total{node=\"n1\",owner=\"alice\",rule=\"web\",side=\"ingress\",ingress=\"n1\",direction=\"to_client\"} 9000 "), "{t}");
        assert!(t.contains("webjet_proxy_active_flows{node=\"n1\",owner=\"alice\",rule=\"web\",side=\"ingress\",ingress=\"n1\"} 2 "));
        assert!(t.contains("webjet_compression_raw_bytes_total{node=\"n1\",owner=\"alice\",plane=\"control\",direction=\"tx\"} 50000 "), "{t}");
        assert!(t.contains(
            "webjet_compression_skipped_total{node=\"n1\",owner=\"alice\",plane=\"control\"} 3 "
        ));
        // Each family's metadata appears exactly once, before its samples.
        for line in t.lines().filter(|l| l.starts_with("# TYPE ")) {
            let name = line.split_whitespace().nth(2).unwrap();
            assert_eq!(t.matches(&format!("# TYPE {name} ")).count(), 1);
        }
        // Counters carry _total, gauges don't.
        for line in t.lines().filter(|l| !l.starts_with('#')) {
            let name = line.split(['{', ' ']).next().unwrap();
            let fam = name.strip_suffix("_total").unwrap_or(name);
            let ty = t
                .lines()
                .find(|l| l.starts_with(&format!("# TYPE {fam} ")))
                .unwrap();
            assert_eq!(ty.ends_with("counter"), name.ends_with("_total"), "{line}");
        }
    }

    #[test]
    fn relay_local_view_has_no_route_ids() {
        let mut e = Exposition::default();
        e.report(&report(), &N, false);
        assert!(!e.render().contains("route_id"));
    }

    #[tokio::test]
    async fn http_endpoint() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        tokio::spawn(serve(addr, Arc::new(|| "x 1\n# EOF\n".to_string())));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(
            b"GET /metrics HTTP/1.1\r\nHost: x\r\nAccept: application/openmetrics-text\r\n\r\n",
        )
        .await
        .unwrap();
        let mut r = String::new();
        s.read_to_string(&mut r).await.unwrap();
        assert!(r.starts_with("HTTP/1.1 200"));
        assert!(r.contains("application/openmetrics-text"));
        assert!(r.ends_with("x 1\n# EOF\n"));
    }
}
