//! Broadcast and multicast over the overlay (§9.5.1): fan-out of what the
//! host sends, delivery of what peers send, and the host's group
//! memberships. The decisions without I/O are in `webjet_core::multicast`.
//!
//! Storm-proofing, all of it local to the sending and the receiving node:
//! - the sender makes every copy, nobody forwards: a copy is written to the
//!   receiver's tun interface and nowhere else, gateways included;
//! - only UDP the host sent from its own overlay address is carried, and a
//!   datagram the host sends back within a second of receiving it (an echo)
//!   is not;
//! - every copy counts against the sender's budget
//!   (`multicast_packets_per_sec`, `multicast_bytes_per_sec`); receivers
//!   take no more than that budget from each sender;
//! - multicast goes only to peers whose host joined the group; policy is
//!   checked per recipient on both ends.

use crate::dataplane::Dataplane;
use crate::node::Node;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use webjet_core::conntrack::Verdict as Ct;
use webjet_core::crypto::Bytes32;
use webjet_core::frames::ftype;
use webjet_core::multicast::{self as mc, Kind, Origin, State};
use webjet_core::packet::{self, Parsed};
use webjet_core::policy::{Decision, Dest, PROTO_UDP};
use webjet_core::types::now_ms;

pub use mc::FEATURE;

const PPS: &str = "multicast_packets_per_sec";
const BPS: &str = "multicast_bytes_per_sec";
/// How long the `multicast_limit` alarm stays after the budget last
/// refused a copy.
const ALARM_FOR: Duration = Duration::from_secs(60);
/// How often the host's memberships are read (sooner when it sends an
/// IGMP or MLD report).
const MEMBERSHIP_EVERY: Duration = Duration::from_secs(5);

fn limits(n: &Node) -> (u64, u64) {
    let pps = crate::metrics::limit_opt(n, PPS).unwrap_or(0);
    let bps = crate::metrics::limit(n, BPS);
    (pps, bps)
}

pub(crate) fn new_state(n: &Node) -> State {
    let (pps, bps) = limits(n);
    State::new(pps, bps, Instant::now())
}

/// Does this node carry broadcast and multicast? Not with
/// `multicast_packets_per_sec = 0`, nor without a tun interface.
pub fn on(n: &Node, dp: &Dataplane) -> bool {
    limits(n).0 > 0 && (dp.has_tun() || dp.sink.lock().is_some())
}

fn peer_takes(n: &Node, peer: &Bytes32) -> Option<bool> {
    let recs = n.records.lock();
    let (r, _) = recs.endpoints.get(peer)?;
    Some(
        r.expires_at > now_ms()
            && r.features
                .as_ref()
                .is_some_and(|f| f.iter().any(|x| x == FEATURE)),
    )
}

// ---------------------------------------------------------------- sending

/// A broadcast or multicast datagram the host sent into the tun interface.
pub(crate) fn outbound(dp: &Dataplane, n: &Arc<Node>, mut p: Vec<u8>, parsed: &Parsed) {
    // IGMP / MLD: the host joined or left a group.
    if is_membership_report(&p, parsed) {
        dp.mcast_wake.notify_one();
        return;
    }
    if parsed.flow.proto != PROTO_UDP || !on(n, dp) {
        return;
    }
    let pools = n.store.snapshot().overlay_pool.clone();
    let Some(kind) = mc::kind(&parsed.flow.dst, &pools) else {
        return;
    };
    // Only what this host sends from its own overlay address; IPv6
    // link-local sources (mDNS, LLMNR) are given the overlay address.
    let mut parsed = parsed.clone();
    let src = parsed.flow.src;
    if !dp.is_mine(&src) {
        let IpAddr::V6(s6) = src else { return };
        let Some(mine) = dp.my_ip(true) else { return };
        if !s6.is_unicast_link_local() || !packet::map_addrs(&mut p, true, |_| Some(mine)) {
            return;
        }
        parsed.flow.src = mine;
    }
    fan_out(dp, n, p, &parsed, kind, Origin::Tun);
}

/// A datagram the host sent out another interface, taken by capture
/// (§9.5.2) and already given this node's overlay address as its source.
pub(crate) fn captured(dp: &Dataplane, n: &Arc<Node>, p: Vec<u8>, parsed: &Parsed) {
    if parsed.flow.proto != PROTO_UDP || !on(n, dp) || !dp.is_mine(&parsed.flow.src) {
        return;
    }
    let pools = n.store.snapshot().overlay_pool.clone();
    let Some(kind) = mc::kind(&parsed.flow.dst, &pools) else {
        return;
    };
    n.metrics.multicast_captured.fetch_add(1, Ordering::Relaxed);
    fan_out(dp, n, p, parsed, kind, Origin::Captured);
}

/// One copy of a datagram from this host to each peer that takes it,
/// within the budget.
fn fan_out(dp: &Dataplane, n: &Arc<Node>, p: Vec<u8>, parsed: &Parsed, kind: Kind, origin: Origin) {
    let m = &n.metrics;
    let now = Instant::now();
    let payload = p.get(parsed.l4_offset + 8..).unwrap_or_default();
    let digest = mc::digest(kind, payload);
    let candidates = {
        let mut st = dp.mcast.lock();
        if st.is_echo(digest, now) {
            m.multicast_echo.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // An app that sends on every interface: once, by the first path.
        if st.duplicate(digest, origin, now) {
            m.multicast_duplicate.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !st.budget_left(now) {
            st.limited_at = Some(now);
            m.multicast_limited.fetch_add(1, Ordering::Relaxed);
            let first = !std::mem::replace(&mut st.alarmed, true);
            drop(st);
            if first {
                alarm(n);
            }
            return;
        }
        drop(st);
        recipients(dp, n, parsed, kind, now)
    };
    if candidates.is_empty() {
        return;
    }
    // Spend the budget copy by copy, starting where the last fan-out
    // stopped, so a budget smaller than the network still reaches every
    // peer in turn.
    let chosen: Vec<(Bytes32, IpAddr, Option<String>)> = {
        let mut st = dp.mcast.lock();
        let start = st.rotate % candidates.len();
        let mut out = Vec::new();
        for i in 0..candidates.len() {
            let c = &candidates[(start + i) % candidates.len()];
            if !st.spend(p.len(), now) {
                st.rotate = start + i;
                m.multicast_limited
                    .fetch_add((candidates.len() - i) as u64, Ordering::Relaxed);
                break;
            }
            out.push(c.clone());
        }
        if out.len() == candidates.len() {
            st.rotate = start + 1;
        }
        let first = out.len() < candidates.len() && !std::mem::replace(&mut st.alarmed, true);
        drop(st);
        if first {
            alarm(n);
        }
        out
    };
    let ecn = crate::e2e::inner_ecn(&p);
    for (peer, addr, rule) in chosen {
        // Track the flow as if it went to the peer's address, so its
        // unicast reply (a pong, an mDNS answer) is let back in.
        track(dp, n, &peer, parsed, addr, true, rule, now);
        if crate::e2e::send(n, &peer, ftype::MCAST, &p, ecn) != crate::e2e::SendResult::NoRoute {
            m.multicast_tx.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Track a broadcast or multicast datagram as the unicast flow it stands
/// for (`dst` = the peer's address when sending, ours when receiving), so
/// the unicast replies it asks for pass as replies. A new flow counts as a
/// hit of the allowing rule.
#[allow(clippy::too_many_arguments)]
fn track(
    dp: &Dataplane,
    n: &Node,
    peer: &Bytes32,
    parsed: &Parsed,
    dst: IpAddr,
    outbound: bool,
    rule: Option<String>,
    now: Instant,
) {
    let mut as_unicast = parsed.clone();
    as_unicast.flow.dst = dst;
    let mut ct = dp.conntrack.lock();
    if ct.classify(peer, &as_unicast, outbound, now) == Ct::New {
        n.metrics
            .rule_hit(rule.as_deref().unwrap_or("(default)"), true);
        let _ = ct.insert(peer, &as_unicast, outbound, rule, false, now);
    }
}

/// The peers a datagram goes to: data nodes with an address of its family
/// that take broadcast and multicast, want this kind, and that policy lets
/// this node reach on the datagram's port. With the address the reply
/// will come from and the allowing rule.
fn recipients(
    dp: &Dataplane,
    n: &Arc<Node>,
    parsed: &Parsed,
    kind: Kind,
    now: Instant,
) -> Vec<(Bytes32, IpAddr, Option<String>)> {
    let v6 = parsed.flow.dst.is_ipv6();
    let mut out = Vec::new();
    let mut unknown = Vec::new();
    {
        let s = n.store.snapshot();
        let vw = s.view();
        let Some(me) = vw.nodes.get(&n.me).map(|x| vw.subject(x)) else {
            return out;
        };
        let st = dp.mcast.lock();
        let mut ids: Vec<&Bytes32> = vw.nodes.keys().collect();
        ids.sort();
        for id in ids {
            let info = &vw.nodes[id];
            if *id == n.me || !info.valid || !info.data {
                continue;
            }
            let Some(addr) = info
                .ips
                .iter()
                .map(|i| i.addr())
                .find(|a| a.is_ipv6() == v6)
            else {
                continue;
            };
            if !st.wants(id, kind, now) {
                continue;
            }
            let verdict = vw.policy.evaluate(
                &me,
                Dest::Node(&vw.subject(info)),
                parsed.flow.proto,
                parsed.flow.dport,
            );
            if verdict.decision != Decision::Allow {
                continue;
            }
            match peer_takes(n, id) {
                None => unknown.push(*id),
                Some(false) => {}
                Some(true) => out.push((*id, addr, verdict.rule)),
            }
        }
    }
    // Edge nodes learn other nodes' records by lookup: these are reached
    // from the next datagram on (discovery repeats).
    crate::gossip::lookup_many(n, &unknown);
    out
}

fn is_membership_report(p: &[u8], parsed: &Parsed) -> bool {
    const PROTO_IGMP: u8 = 2;
    parsed.flow.proto == PROTO_IGMP
        // MLDv1 report (131) and done (132), MLDv2 report (143).
        || (parsed.flow.proto == webjet_core::policy::PROTO_ICMPV6
            && matches!(p.get(parsed.l4_offset), Some(131 | 132 | 143)))
}

// ---------------------------------------------------------------- receiving

/// An MCAST frame from `peer`: deliver it to the host, or drop it.
pub(crate) fn inbound(n: &Arc<Node>, peer: &Bytes32, mut p: Vec<u8>) {
    let Some(dp) = n.dataplane.get() else { return };
    let m = &n.metrics;
    let now = Instant::now();
    let enabled = on(n, dp);
    let delivered = enabled && deliver(dp, n, peer, &mut p, now);
    // Tell the sender what we take: on first contact, now and then, and
    // when it sent something we don't take (so it stops).
    let report = {
        let mut st = dp.mcast.lock();
        st.report_due(peer, now).then(|| st.report(!enabled))
    };
    if let Some(r) = report {
        crate::e2e::send(n, peer, ftype::GROUPS, &mc::encode_report(&r), 0);
    }
    if delivered {
        m.multicast_rx.fetch_add(1, Ordering::Relaxed);
        dp.write_tun(p);
    }
}

fn deliver(dp: &Dataplane, n: &Arc<Node>, peer: &Bytes32, p: &mut [u8], now: Instant) -> bool {
    let m = &n.metrics;
    let Some(parsed) = packet::parse(p) else {
        return false;
    };
    if parsed.flow.proto != PROTO_UDP || parsed.fragment == packet::Fragment::Later {
        return false;
    }
    let (pools, verdict, my_addr) = {
        let s = n.store.snapshot();
        let vw = s.view();
        let (Some(pi), Some(me)) = (vw.nodes.get(peer), vw.nodes.get(&n.me)) else {
            return false;
        };
        // Cryptokey routing (§9.5): only from the sender's own address.
        if !pi.ips.iter().any(|i| i.contains(&parsed.flow.src)) {
            m.cryptokey_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let verdict = vw.policy.evaluate(
            &vw.subject(pi),
            Dest::Node(&vw.subject(me)),
            parsed.flow.proto,
            parsed.flow.dport,
        );
        let v6 = parsed.flow.src.is_ipv6();
        let my_addr = me.ips.iter().map(|i| i.addr()).find(|a| a.is_ipv6() == v6);
        (s.overlay_pool.clone(), verdict, my_addr)
    };
    let Some(kind) = mc::kind(&parsed.flow.dst, &pools) else {
        return false;
    };
    {
        let mut st = dp.mcast.lock();
        if !st.member(kind) {
            return false;
        }
        if !st.accept(peer, p.len(), now) {
            m.multicast_limited.fetch_add(1, Ordering::Relaxed);
            return false;
        }
    }
    if verdict.decision == Decision::Deny {
        m.rule_hit(verdict.rule_id(), false);
        m.acl_denied.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    // Track it as a flow to this node's address, so the host's unicast
    // reply goes out as a reply.
    if let Some(a) = my_addr {
        track(dp, n, peer, &parsed, a, false, verdict.rule, now);
    }
    // The pool's directed broadcast arrives as the limited broadcast:
    // point-to-point interfaces (macOS utun) have no broadcast address.
    if mc::is_pool_broadcast(&parsed.flow.dst, &pools)
        && !packet::map_addrs(p, false, |_| Some(IpAddr::from([255, 255, 255, 255])))
    {
        return false;
    }
    let payload = p.get(parsed.l4_offset + 8..).unwrap_or_default();
    let digest = mc::digest(kind, payload);
    dp.mcast.lock().delivered(digest, now);
    true
}

/// A GROUPS frame from `peer`: which broadcasts and groups it takes.
pub(crate) fn on_report(n: &Arc<Node>, peer: &Bytes32, b: &[u8]) {
    let (Some(dp), Some(r)) = (n.dataplane.get(), mc::decode_report(b)) else {
        return;
    };
    dp.mcast.lock().on_report(peer, r, Instant::now());
}

// ---------------------------------------------------------------- upkeep

/// After a tree change: the budget follows the limits at once (not at the
/// next upkeep, up to 10 s later). Has this node started or stopped taking
/// broadcast and multicast since its EndpointRecord was published? Then
/// the record must be published again (returns true), and the senders
/// holding our report get a new one at once.
pub(crate) fn refresh(n: &Arc<Node>) -> bool {
    let Some(dp) = n.dataplane.get() else {
        return false;
    };
    let (pps, bps) = limits(n);
    let now_on = on(n, dp);
    let (report, peers) = {
        let mut st = dp.mcast.lock();
        st.set_limits(pps, bps);
        let changed = st.advertised.is_some_and(|a| a != now_on);
        st.advertised = Some(now_on);
        if !changed {
            return false;
        }
        st.report_changed();
        (st.report(!now_on), st.stale_reports(Instant::now()))
    };
    let b = mc::encode_report(&report);
    for p in peers {
        crate::e2e::send(n, &p, ftype::GROUPS, &b, 0);
    }
    true
}

/// The budget refused a copy: raise the `multicast_limit` alarm (at once,
/// on the first refusal; `upkeep` clears it a minute after the last).
fn alarm(n: &Node) {
    let (pps, bps) = limits(n);
    n.alarm(
        "multicast_limit",
        "warning",
        format!(
            "broadcast/multicast over budget ({pps} copies/s, {bps} bytes/s, every copy counts): \
             a chatty or looping application; raise {PPS}/{BPS} or narrow the policy"
        ),
    );
}

/// Every 10 s: expire state, follow limit changes, clear the alarm a
/// minute after the budget last refused a copy.
pub(crate) fn upkeep(dp: &Dataplane) {
    let Some(n) = dp.node() else { return };
    let (pps, bps) = limits(&n);
    let now = Instant::now();
    let clear = {
        let mut st = dp.mcast.lock();
        st.set_limits(pps, bps);
        st.expire(now);
        let limited = st
            .limited_at
            .is_some_and(|t| now.saturating_duration_since(t) < ALARM_FOR);
        let clear = st.alarmed && !limited;
        if clear {
            st.alarmed = false;
        }
        clear
    };
    if clear {
        n.clear_alarm("multicast_limit");
    }
}

/// The host's memberships changed: senders holding an older report of
/// ours get the new one.
fn membership_changed(n: &Arc<Node>, dp: &Dataplane, groups: Option<HashSet<IpAddr>>) {
    let enabled = on(n, dp);
    let (report, peers) = {
        let mut st = dp.mcast.lock();
        if !st.set_local(groups) {
            return;
        }
        (st.report(!enabled), st.stale_reports(Instant::now()))
    };
    let b = mc::encode_report(&report);
    for p in peers {
        crate::e2e::send(n, &p, ftype::GROUPS, &b, 0);
    }
}

/// Follow the groups the host joins on the tun interface `dev`.
pub(crate) fn watch_memberships(n: &Arc<Node>, dp: Arc<Dataplane>) {
    let dev = dp.dev_name.clone();
    let weak = Arc::downgrade(n);
    n.tasks.service("multicast-groups", async move {
        loop {
            let Some(n) = weak.upgrade() else { return };
            let d = dev.clone();
            let groups = tokio::task::spawn_blocking(move || crate::platform::multicast_groups(&d))
                .await
                .ok()
                .flatten();
            membership_changed(&n, &dp, groups);
            drop(n);
            // An IGMP/MLD report wakes us at once; then a short pause, as
            // the OS updates its table right after sending.
            if tokio::time::timeout(MEMBERSHIP_EVERY, dp.mcast_wake.notified())
                .await
                .is_ok()
            {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testnode;
    use webjet_core::multicast::Report;
    use webjet_core::testutil::{Cluster, packets::udp4};
    use webjet_proto as wp;

    fn rule(id: &str, src: &str, dst: &str, ports: &str) -> wp::Rule {
        wp::Rule {
            id: Some(id.into()),
            action: wp::Action::Allow,
            src: Some(vec![src.into()]),
            dst: Some(vec![dst.into()]),
            ports: Some(vec![ports.into()]),
        }
    }

    struct T {
        _c: Cluster,
        n: Arc<Node>,
        dp: Arc<Dataplane>,
        tun: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        a: Bytes32,
        b: Bytes32,
        c: Bytes32,
        _dir: tempfile::TempDir,
    }

    const ME: [u8; 4] = [10, 7, 0, 2];
    const A: [u8; 4] = [10, 7, 0, 3];

    /// Me and three peers: `a` and `b` games players, `c` not; all
    /// advertise multicast except `b`'s record, which is left out where
    /// a test says so.
    fn setup(limits: &[(&str, u64)]) -> T {
        let mut c = Cluster::new();
        let me = c.data_node("me", "10.7.0.2", &["tag:game"]);
        let a = c.data_node("a", "10.7.0.3", &["tag:game"]).0;
        let b = c.data_node("b", "10.7.0.4", &["tag:game"]).0;
        let cc = c.data_node("c", "10.7.0.5", &["tag:office"]).0;
        c.set_network(wp::NetworkConfig {
            policy: Some(Box::new(wp::Policy {
                default_action: wp::Action::Deny,
                rules: Some(vec![
                    rule("lan-games", "tag:game", "tag:game", "udp:19132"),
                    rule("mdns", "*", "*", "udp:5353"),
                ]),
                ..Default::default()
            })),
            limits: (!limits.is_empty()).then(|| {
                Box::new(wp::Limits {
                    defaults: Some(
                        limits
                            .iter()
                            .map(|(k, v)| wp::LimitValue {
                                name: Some(k.to_string()),
                                value: *v,
                            })
                            .collect(),
                    ),
                    ..Default::default()
                })
            }),
            ..Default::default()
        })
        .unwrap();
        let (n, dir) = testnode::node(&mut c, me.0, me.1);
        let (dp, tun) = Dataplane::for_test(&n);
        for id in [a, b, cc] {
            advertise(&n, id, true);
        }
        T {
            _c: c,
            n,
            dp,
            tun,
            a,
            b,
            c: cc,
            _dir: dir,
        }
    }

    fn advertise(n: &Node, id: Bytes32, multicast: bool) {
        let mut f = vec!["kcp".to_string()];
        if multicast {
            f.push(FEATURE.into());
        }
        let rec = wp::EndpointRecord {
            node_id: Some(webjet_core::crypto::k32(&id)),
            features: Some(f),
            expires_at: now_ms() + 60_000,
            ..Default::default()
        };
        n.records.lock().endpoints.insert(id, (rec, Vec::new()));
    }

    fn sent(t: &T, peer: &Bytes32) -> Vec<(u8, Vec<u8>)> {
        t.n.e2e.queued_for_test(peer)
    }

    fn mcast_to(t: &T, peer: &Bytes32) -> usize {
        sent(t, peer)
            .iter()
            .filter(|(ty, _)| *ty == ftype::MCAST)
            .count()
    }

    fn tun_packets(t: &mut T) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        while let Ok(p) = t.tun.try_recv() {
            v.push(p);
        }
        v
    }

    #[tokio::test]
    async fn a_broadcast_goes_once_to_each_allowed_peer() {
        let t = setup(&[]);
        let ping = udp4(ME, [255, 255, 255, 255], 50000, 19132, b"unconnected ping");
        t.dp.outbound(ping);
        assert_eq!(mcast_to(&t, &t.a), 1);
        assert_eq!(mcast_to(&t, &t.b), 1);
        assert_eq!(mcast_to(&t, &t.c), 0, "policy: not a game node");
        assert_eq!(t.n.metrics.multicast_tx.load(Ordering::Relaxed), 2);
        assert_eq!(t.n.metrics.no_route.load(Ordering::Relaxed), 0);
        // The pong comes back from a's address as a tracked reply.
        let pong = udp4(A, ME, 19132, 50000, b"unconnected pong");
        let parsed = packet::parse(&pong).unwrap();
        assert_eq!(
            t.dp.conntrack
                .lock()
                .classify(&t.a, &parsed, false, Instant::now()),
            webjet_core::conntrack::Verdict::Tracked
        );
    }

    #[tokio::test]
    async fn only_udp_from_this_host_and_no_echoes() {
        let mut t = setup(&[]);
        // Someone else's address (a gateway's LAN, a spoofing app).
        t.dp.outbound(udp4([10, 7, 0, 9], [255, 255, 255, 255], 1, 19132, b"x"));
        t.dp.outbound(udp4([192, 168, 1, 5], [255, 255, 255, 255], 1, 19132, b"x"));
        assert_eq!(mcast_to(&t, &t.a), 0);
        // A broadcast delivered to the host and sent straight back.
        let from_a = udp4(A, [255, 255, 255, 255], 50000, 19132, b"ping from a");
        inbound(&t.n, &t.a, from_a);
        assert_eq!(tun_packets(&mut t).len(), 1);
        t.dp.outbound(udp4(ME, [255, 255, 255, 255], 50001, 19132, b"ping from a"));
        assert_eq!(mcast_to(&t, &t.b), 0, "echo");
        assert_eq!(t.n.metrics.multicast_echo.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn the_budget_counts_every_copy_and_rotates() {
        // Two copies a second: one broadcast to two peers uses it up.
        let t = setup(&[(PPS, 2)]);
        for i in 0..5u8 {
            t.dp.outbound(udp4(ME, [255, 255, 255, 255], 50000, 19132, &[i]));
        }
        let (a, b) = (mcast_to(&t, &t.a), mcast_to(&t, &t.b));
        assert_eq!(a + b, 2, "two copies, whatever the number of datagrams");
        assert!(t.n.metrics.multicast_limited.load(Ordering::Relaxed) >= 3);
        assert!(
            t.n.alarms.lock().contains_key("multicast_limit"),
            "raised at once"
        );
        upkeep(&t.dp);
        assert!(
            t.n.alarms.lock().contains_key("multicast_limit"),
            "kept for a minute"
        );
    }

    #[tokio::test]
    async fn rotation_reaches_every_peer_on_a_small_budget() {
        let t = setup(&[(PPS, 1)]);
        t.dp.outbound(udp4(ME, [255, 255, 255, 255], 50000, 19132, b"1"));
        // A second later the budget has one copy again: the other peer.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        t.dp.outbound(udp4(ME, [255, 255, 255, 255], 50000, 19132, b"2"));
        assert_eq!((mcast_to(&t, &t.a), mcast_to(&t, &t.b)), (1, 1));
    }

    #[tokio::test]
    async fn multicast_follows_reports_and_records() {
        let t = setup(&[]);
        advertise(&t.n, t.b, false);
        // a reports it only joined mDNS.
        let r = Report::Groups(vec!["224.0.0.251".parse().unwrap()]);
        on_report(&t.n, &t.a, &mc::encode_report(&r));
        t.dp.outbound(udp4(ME, [239, 255, 255, 250], 50000, 5353, b"ssdp-ish"));
        t.dp.outbound(udp4(ME, [224, 0, 0, 251], 5353, 5353, b"mdns"));
        assert_eq!(mcast_to(&t, &t.a), 1, "mDNS only");
        assert_eq!(mcast_to(&t, &t.b), 0, "no multicast feature");
        // c: no game rule, but mDNS is open to everyone.
        assert_eq!(mcast_to(&t, &t.c), 2);
    }

    #[tokio::test]
    async fn off_means_nothing_sent_and_nothing_taken() {
        let mut t = setup(&[(PPS, 0)]);
        assert!(!on(&t.n, &t.dp));
        t.dp.outbound(udp4(ME, [255, 255, 255, 255], 50000, 19132, b"x"));
        assert_eq!(mcast_to(&t, &t.a), 0);
        inbound(
            &t.n,
            &t.a,
            udp4(A, [255, 255, 255, 255], 50000, 19132, b"x"),
        );
        assert!(tun_packets(&mut t).is_empty());
        // The sender is told to stop.
        let groups: Vec<_> = sent(&t, &t.a)
            .into_iter()
            .filter(|(ty, _)| *ty == ftype::GROUPS)
            .collect();
        assert_eq!(groups.len(), 1);
        assert_eq!(mc::decode_report(&groups[0].1), Some(Report::Nothing));
    }

    #[tokio::test]
    async fn receiving_checks_source_policy_and_rate() {
        let mut t = setup(&[(PPS, 3)]);
        // Not from the sender's own address.
        inbound(
            &t.n,
            &t.a,
            udp4([10, 7, 0, 4], [255, 255, 255, 255], 1, 19132, b"x"),
        );
        // Policy: c may not reach game ports.
        inbound(
            &t.n,
            &t.c,
            udp4([10, 7, 0, 5], [255, 255, 255, 255], 1, 19132, b"x"),
        );
        assert!(tun_packets(&mut t).is_empty());
        assert_eq!(t.n.metrics.cryptokey_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(t.n.metrics.acl_denied.load(Ordering::Relaxed), 1);
        // The pool broadcast arrives as the limited broadcast; at most
        // the budget per sender.
        for i in 0..5u8 {
            inbound(&t.n, &t.a, udp4(A, [10, 7, 255, 255], 50000, 19132, &[i]));
        }
        let got = tun_packets(&mut t);
        assert_eq!(got.len(), 3);
        let p = packet::parse(&got[0]).unwrap();
        assert_eq!(p.flow.dst, IpAddr::from([255, 255, 255, 255]));
        let mut fixed = got[0].clone();
        packet::fix_checksums(&mut fixed);
        assert_eq!(fixed, got[0], "checksums still valid");
        // Our reply to a's ping goes out as a reply.
        let reply = packet::parse(&udp4(ME, A, 19132, 50000, b"pong")).unwrap();
        assert_eq!(
            t.dp.conntrack
                .lock()
                .classify(&t.a, &reply, true, Instant::now()),
            webjet_core::conntrack::Verdict::Tracked
        );
        // The first frame from a sender gets our report.
        assert!(sent(&t, &t.a).iter().any(|(ty, _)| *ty == ftype::GROUPS));
    }

    #[tokio::test]
    async fn turning_off_tells_senders_at_once() {
        let mut t = setup(&[]);
        inbound(
            &t.n,
            &t.a,
            udp4(A, [255, 255, 255, 255], 50000, 19132, b"x"),
        );
        assert_eq!(tun_packets(&mut t).len(), 1);
        crate::gossip::publish_endpoint(&t.n, true);
        assert!(!refresh(&t.n), "nothing changed");
        t._c.set_network(wp::NetworkConfig {
            limits: Some(Box::new(wp::Limits {
                defaults: Some(vec![wp::LimitValue {
                    name: Some(PPS.into()),
                    value: 0,
                }]),
                ..Default::default()
            })),
            ..Default::default()
        })
        .unwrap();
        testnode::sync(&mut t._c, &t.n);
        assert!(refresh(&t.n), "the record must be republished");
        let reports: Vec<_> = sent(&t, &t.a)
            .into_iter()
            .filter(|(ty, _)| *ty == ftype::GROUPS)
            .map(|(_, b)| mc::decode_report(&b).unwrap())
            .collect();
        assert_eq!(reports.last(), Some(&Report::Nothing), "{reports:?}");
    }

    #[tokio::test]
    async fn captured_datagrams_fan_out_once() {
        let t = setup(&[]);
        let ping = udp4(ME, [255, 255, 255, 255], 50000, 19132, b"captured ping");
        let parsed = packet::parse(&ping).unwrap();
        captured(&t.dp, &t.n, ping.clone(), &parsed);
        assert_eq!((mcast_to(&t, &t.a), mcast_to(&t, &t.b)), (1, 1));
        assert_eq!(mcast_to(&t, &t.c), 0, "policy");
        let m = &t.n.metrics;
        assert_eq!(m.multicast_captured.load(Ordering::Relaxed), 1);
        // The app also sent it into the tun interface: once is enough.
        t.dp.outbound(ping);
        assert_eq!(mcast_to(&t, &t.a), 1);
        assert_eq!(m.multicast_duplicate.load(Ordering::Relaxed), 1);
        // Capture hands over only datagrams from this node's overlay address.
        let other = udp4([10, 7, 0, 9], [255, 255, 255, 255], 1, 19132, b"other");
        captured(&t.dp, &t.n, other.clone(), &packet::parse(&other).unwrap());
        assert_eq!(mcast_to(&t, &t.a), 1);
        // The pong to a captured ping comes back as a tracked reply.
        let pong = packet::parse(&udp4(A, ME, 19132, 50000, b"pong")).unwrap();
        assert_eq!(
            t.dp.conntrack
                .lock()
                .classify(&t.a, &pong, false, Instant::now()),
            webjet_core::conntrack::Verdict::Tracked
        );
    }

    #[tokio::test]
    async fn membership_reports_are_not_carried() {
        let t = setup(&[]);
        // IGMPv3 report to 224.0.0.22.
        let mut igmp = udp4(ME, [224, 0, 0, 22], 0, 0, b"");
        igmp[9] = 2;
        t.dp.outbound(igmp);
        assert_eq!(mcast_to(&t, &t.a), 0);
    }
}
