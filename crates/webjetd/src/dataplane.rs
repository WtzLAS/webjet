//! The data plane (§9.5, §11.9, §14.4): the tun interface, cryptokey
//! routing, policy enforcement with connection tracking, the gateway path
//! and ICMP replies for denied or unroutable packets.

use crate::node::Node;
use ipnet::IpNet;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;
use tokio::sync::mpsc;
use webjet_core::conntrack::{Conntrack, InsertError as CtError, Verdict as Ct};
use webjet_core::crypto::Bytes32;
use webjet_core::frames::ftype;
use webjet_core::packet::{self, Bucket, Parsed, Unreach};
use webjet_core::policy::{Decision, Dest};
use webjet_core::types::{Grant, map_prefix};

pub struct Dataplane {
    node: Weak<Node>,
    pub dev_name: String,
    tun_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Packets that would go to the tun interface when none exists (tests).
    pub sink: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    pub conntrack: Mutex<Conntrack>,
    icmp_bucket: Mutex<Bucket>,
    my_ips: RwLock<Vec<IpNet>>,
    /// Grants this node serves as a gateway, with the LAN interface.
    serving: RwLock<Vec<(Grant, String)>>,
    routes: Mutex<Vec<IpNet>>,
    applied_gen: AtomicU64,
    pub resolver: RwLock<Vec<IpAddr>>,
    /// Sticky gateway choice per published prefix (§11.9.3).
    gw_choice: Mutex<HashMap<IpNet, Bytes32>>,
    nat_done: Mutex<Vec<String>>,
    pings: Mutex<HashMap<u16, mpsc::UnboundedSender<u16>>>,
    /// Reverse proxy ports and flows (§11.11), apart from the overlay's.
    pub proxy: crate::proxy::Proxy,
}

impl Dataplane {
    pub fn serving_prefixes(&self) -> Vec<IpNet> {
        let mut v: Vec<IpNet> = self
            .serving
            .read()
            .iter()
            .map(|(g, _)| g.published)
            .collect();
        v.sort();
        v.dedup();
        v
    }

    fn node(&self) -> Option<Arc<Node>> {
        self.node.upgrade()
    }

    pub(crate) fn has_tun(&self) -> bool {
        self.tun_tx.is_some()
    }

    /// The grant this node serves as a gateway that covers `ip`.
    pub(crate) fn serving_grant(&self, ip: &IpAddr) -> Option<Grant> {
        self.serving
            .read()
            .iter()
            .map(|(g, _)| *g)
            .find(|g| g.published.contains(ip))
    }

    /// This node's overlay address of a family.
    pub(crate) fn my_ip(&self, v6: bool) -> Option<IpAddr> {
        self.my_ips
            .read()
            .iter()
            .map(|n| n.addr())
            .find(|a| a.is_ipv6() == v6)
    }

    pub(crate) fn write_tun(&self, p: Vec<u8>) {
        if self.own_ping_reply(&p) {
            return;
        }
        if let Some(n) = self.node() {
            n.metrics.tun_out(p.len());
        }
        self.write_tun_raw(p);
    }

    /// Replies to our own pings (control channel `ping`) stop here.
    fn own_ping_reply(&self, p: &[u8]) -> bool {
        if let Some(pp) = packet::parse(p)
            && pp.icmp == Some(packet::IcmpKind::Echo { request: false })
            && p.len() >= pp.l4_offset + 8
        {
            let id = u16::from_be_bytes([p[pp.l4_offset + 4], p[pp.l4_offset + 5]]);
            let seq = u16::from_be_bytes([p[pp.l4_offset + 6], p[pp.l4_offset + 7]]);
            if let Some(tx) = self.pings.lock().get(&id) {
                let _ = tx.send(seq);
                return true;
            }
        }
        false
    }

    /// A packet the host sent to one of this node's own overlay addresses:
    /// hand it straight back, so the host's own stack answers it. Linux and
    /// Windows keep such packets on their loopback, but macOS routes them
    /// into the utun interface. Not overlay traffic: no counters, no policy.
    /// The agent's own pings (control channel `ping` to itself) are answered
    /// here, since the kernel's reply may never come back through the tun.
    fn loopback(&self, p: Vec<u8>) {
        if self.own_ping_reply(&p) {
            return;
        }
        if let Some(reply) = packet::echo_reply(&p)
            && self.own_ping_reply(&reply)
        {
            return;
        }
        self.write_tun_raw(p);
    }

    /// Write to the tun interface without counting it as overlay traffic
    /// (reverse proxy packets have their own counters).
    pub(crate) fn write_tun_raw(&self, p: Vec<u8>) {
        match &self.tun_tx {
            Some(tx) => {
                let _ = tx.try_send(p);
            }
            None => {
                // No tun interface: answer pings ourselves, like a host stack
                // would, so connectivity can be checked without root.
                if let Some(reply) = packet::echo_reply(&p)
                    && let Some(n) = self.node()
                {
                    let n2 = n.clone();
                    tokio::spawn(async move {
                        if let Some(dp) = n2.dataplane.get() {
                            dp.outbound(reply);
                        }
                    });
                }
                if let Some(s) = self.sink.lock().as_ref() {
                    let _ = s.send(p);
                }
            }
        }
    }

    pub(crate) fn icmp(&self, orig: &[u8], why: Unreach) {
        if !self.icmp_bucket.lock().take() {
            return;
        }
        if let Some(r) = packet::icmp_unreachable(orig, why) {
            self.write_tun(r);
        }
    }

    /// Send `count` pings to `dst` through the overlay and wait for replies
    /// (control channel `ping`; works with or without a tun interface).
    /// Ping `dst` `count` times with `size` payload bytes (at least the
    /// 11 of "webjet ping"; more are filled with an incrementing byte
    /// pattern, as ping(8) does).
    pub async fn ping(
        &self,
        dst: IpAddr,
        count: u16,
        size: usize,
    ) -> Vec<Option<std::time::Duration>> {
        let Some(n) = self.node() else {
            return Vec::new();
        };
        let src = match self
            .my_ips
            .read()
            .iter()
            .find(|i| i.addr().is_ipv4() == dst.is_ipv4())
        {
            Some(i) => i.addr(),
            None => return Vec::new(),
        };
        let id: u16 = rand::random();
        let mut payload = b"webjet ping".to_vec();
        payload.extend((payload.len()..size).map(|i| i as u8));
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.pings.lock().insert(id, tx);
        let mut out = Vec::new();
        for seq in 0..count {
            let t0 = Instant::now();
            self.outbound(packet::icmp_echo(src, dst, true, id, seq, &payload));
            let got = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                while let Some(s) = rx.recv().await {
                    if s == seq {
                        return true;
                    }
                }
                false
            })
            .await
            .unwrap_or(false);
            out.push(got.then(|| t0.elapsed()));
            let _ = &n;
        }
        self.pings.lock().remove(&id);
        out
    }

    /// No route to the destination (§9.5): host unreachable.
    pub fn unreachable(&self, orig: &[u8]) {
        if let Some(n) = self.node() {
            n.metrics.no_route.fetch_add(1, Ordering::Relaxed);
        }
        self.icmp(orig, Unreach::Host);
    }

    pub(crate) fn is_mine(&self, ip: &IpAddr) -> bool {
        self.my_ips.read().iter().any(|n| n.contains(ip))
    }

    // ------------------------------------------------------------ from the tun interface

    /// A packet the local host sent into the overlay.
    pub fn outbound(&self, mut p: Vec<u8>) {
        let Some(n) = self.node() else { return };
        let Some(parsed) = packet::parse(&p) else {
            n.metrics.tun_in(p.len());
            return;
        };
        let (src, dst) = (parsed.flow.src, parsed.flow.dst);
        // Reverse proxy traffic (§11.11) is kept out of the overlay's
        // counters and connection tracking: a client's packet the kernel
        // captured, or a reply to a proxy flow to this node.
        if self.proxy.is_capture(self, &parsed) {
            self.proxy.from_client(&n, self, p, parsed);
            return;
        }
        if self.is_mine(&src) && self.proxy.from_local(&n, &p, &parsed) {
            return;
        }
        // The local resolver (§11.10.1).
        if self.resolver.read().contains(&dst) {
            n.metrics.tun_in(p.len());
            let n2 = n.clone();
            tokio::spawn(async move {
                if let Some(reply) = crate::dns::handle(&n2, &p).await
                    && let Some(dp) = n2.dataplane.get()
                {
                    dp.write_tun(reply);
                }
            });
            return;
        }
        if self.is_mine(&dst) {
            self.loopback(p);
            return;
        }
        // Gateway return traffic: LAN → overlay (§11.9.4).
        if !self.is_mine(&src) {
            let grant = self
                .serving
                .read()
                .iter()
                .map(|(g, _)| *g)
                .find(|g| g.lan.contains(&src));
            let Some(g) = grant else { return };
            let Some(peer) = n.store.read().view().node_by_ip(&dst) else {
                return;
            };
            if g.mapped() {
                let Some(ps) = map_prefix(src, &g.lan, &g.published) else {
                    return;
                };
                packet::rewrite(&mut p, Some((ps, parsed.flow.sport)), None);
            }
            let Some(after) = packet::parse(&p) else {
                return;
            };
            if self.proxy.from_local(&n, &p, &after) {
                return;
            }
            n.metrics.tun_in(p.len());
            let v = self
                .conntrack
                .lock()
                .classify(&peer, &after, true, Instant::now());
            if !matches!(v, Ct::Tracked | Ct::RelatedError) {
                return; // replies only; LAN hosts can't start flows (§11.9.4)
            }
            crate::e2e::send(&n, &peer, ftype::DATA, &p, crate::e2e::inner_ecn(&p));
            return;
        }
        n.metrics.tun_in(p.len());
        // Where does it go? A node, or a gateway serving a published prefix (§9.5, §11.9.3).
        let (peer, dest_is_node) = match self.route(&n, &dst) {
            Some(x) => x,
            None => {
                self.unreachable(&p);
                return;
            }
        };
        if peer == n.me {
            return;
        }
        let now = Instant::now();
        let v = self.conntrack.lock().classify(&peer, &parsed, true, now);
        match v {
            Ct::Tracked | Ct::RelatedError => {}
            Ct::New | Ct::Invalid => {
                let verdict = {
                    let s = n.store.read();
                    let vw = s.view();
                    let Some(me) = vw.nodes.get(&n.me).map(|x| vw.subject(x)) else {
                        return;
                    };
                    match (dest_is_node, vw.nodes.get(&peer)) {
                        (true, Some(pn)) => {
                            let ps = vw.subject(pn);
                            vw.policy.evaluate(
                                &me,
                                Dest::Node(&ps),
                                parsed.flow.proto,
                                parsed.flow.dport,
                            )
                        }
                        _ => vw.policy.evaluate(
                            &me,
                            Dest::Addr(dst),
                            parsed.flow.proto,
                            parsed.flow.dport,
                        ),
                    }
                };
                n.metrics
                    .rule_hit(verdict.rule_id(), verdict.decision == Decision::Allow);
                if verdict.decision == Decision::Deny {
                    n.metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
                    self.icmp(&p, Unreach::Prohibited);
                    return;
                }
                if v == Ct::New
                    && self
                        .conntrack
                        .lock()
                        .insert(&peer, &parsed, true, verdict.rule.clone(), false, now)
                        .is_err()
                {
                    n.metrics.conntrack_limit.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
        if crate::e2e::send(&n, &peer, ftype::DATA, &p, crate::e2e::inner_ecn(&p))
            == crate::e2e::SendResult::NoRoute
        {
            self.unreachable(&p)
        }
    }

    /// The node or serving gateway for a destination address.
    pub(crate) fn route(&self, n: &Arc<Node>, dst: &IpAddr) -> Option<(Bytes32, bool)> {
        let view_node = n.store.read().view().node_by_ip(dst);
        if let Some(id) = view_node {
            return Some((id, true));
        }
        // Published prefixes: gateways that hold the grant and serve it.
        let mut best: Option<(u8, IpNet, Vec<Bytes32>)> = None;
        let mut unknown: Vec<Bytes32> = Vec::new();
        {
            let s = n.store.read();
            let v = s.view();
            let recs = n.records.lock();
            for (id, info) in &v.nodes {
                if !info.valid || *id == n.me {
                    continue;
                }
                // No record yet (edge nodes learn other nodes' records by
                // lookup): treat a grant holder as serving until we know.
                let known = recs.endpoints.contains_key(id);
                if !known && info.routes.iter().any(|g| g.published.contains(dst)) {
                    unknown.push(*id);
                }
                let serving: Vec<IpNet> = recs
                    .endpoints
                    .get(id)
                    .map(|(r, _)| {
                        r.serving
                            .clone()
                            .unwrap_or_default()
                            .iter()
                            .filter_map(webjet_core::types::cidr_to_net)
                            .collect()
                    })
                    .unwrap_or_default();
                for g in &info.routes {
                    if g.published.contains(dst) && (serving.contains(&g.published) || !known) {
                        let pl = g.published.prefix_len();
                        match &mut best {
                            Some((bp, _, ids)) if *bp == pl => ids.push(*id),
                            Some((bp, _, _)) if *bp > pl => {}
                            _ => best = Some((pl, g.published, vec![*id])),
                        }
                    }
                }
            }
        }
        for id in &unknown {
            crate::gossip::lookup(n, id);
        }
        let (_, prefix, gws) = best?;
        // A published prefix that clashes with a directly connected LAN is
        // skipped (§11.9.3).
        if crate::platform::local_networks()
            .iter()
            .any(|l| webjet_core::types::overlaps(l, &prefix))
        {
            n.alarm(
                "route_clash",
                "warning",
                format!("published prefix {prefix} overlaps a local network; not routed"),
            );
            return None;
        }
        let mut choice = self.gw_choice.lock();
        if let Some(c) = choice.get(&prefix)
            && gws.contains(c)
        {
            return Some((*c, false));
        }
        let pick = gws
            .iter()
            .find(|g| n.e2e.get(g).map(|s| s.established()).unwrap_or(false))
            .copied()
            .unwrap_or_else(|| gws[rand::random_range(0..gws.len())]);
        choice.insert(prefix, pick);
        Some((pick, false))
    }

    // ------------------------------------------------------------ from the overlay

    /// A decrypted packet from `peer` (§9.4.4 step 5, §14.4).
    pub fn inbound(&self, peer: &Bytes32, mut p: Vec<u8>) {
        let Some(n) = self.node() else { return };
        let Some(parsed) = packet::parse(&p) else {
            return;
        };
        let (src, dst) = (parsed.flow.src, parsed.flow.dst);
        // Never answer queries to our resolver from the network (§11.10.1).
        if self.resolver.read().contains(&dst) {
            return;
        }
        // Cryptokey routing (§9.5).
        let (src_ok, peer_subject) = {
            let s = n.store.read();
            let v = s.view();
            match v.nodes.get(peer) {
                Some(info) => (
                    info.ips.iter().any(|i| i.contains(&src)),
                    Some(v.subject(info)),
                ),
                None => (false, None),
            }
        };
        let Some(peer_subject) = peer_subject else {
            return;
        };
        let now = Instant::now();
        if !src_ok {
            // Gateway replies: only on a flow this node started (§9.5 exception).
            let served = n
                .records
                .lock()
                .endpoints
                .get(peer)
                .map(|(r, _)| {
                    r.serving
                        .clone()
                        .unwrap_or_default()
                        .iter()
                        .filter_map(webjet_core::types::cidr_to_net)
                        .any(|x| x.contains(&src))
                })
                .unwrap_or(false);
            let tracked = served
                && matches!(
                    self.conntrack.lock().classify(peer, &parsed, false, now),
                    Ct::Tracked | Ct::RelatedError
                );
            if !tracked || !self.is_mine(&dst) {
                n.metrics.cryptokey_dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            self.write_tun(p);
            return;
        }
        // To me, or to a LAN I serve?
        let gw = if self.is_mine(&dst) {
            None
        } else {
            match self
                .serving
                .read()
                .iter()
                .find(|(g, _)| g.published.contains(&dst))
            {
                Some((g, _)) => Some(*g),
                None => {
                    n.metrics.cryptokey_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        };
        let v = self.conntrack.lock().classify(peer, &parsed, false, now);
        match v {
            Ct::Tracked | Ct::RelatedError => {}
            Ct::Invalid => return,
            Ct::New => {
                let verdict = {
                    let s = n.store.read();
                    let vw = s.view();
                    match gw {
                        None => {
                            let Some(me) = vw.nodes.get(&n.me).map(|x| vw.subject(x)) else {
                                return;
                            };
                            vw.policy.evaluate(
                                &peer_subject,
                                Dest::Node(&me),
                                parsed.flow.proto,
                                parsed.flow.dport,
                            )
                        }
                        Some(_) => vw.policy.evaluate(
                            &peer_subject,
                            Dest::Addr(dst),
                            parsed.flow.proto,
                            parsed.flow.dport,
                        ),
                    }
                };
                n.metrics
                    .rule_hit(verdict.rule_id(), verdict.decision == Decision::Allow);
                if verdict.decision == Decision::Deny {
                    n.metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                if let Err(e) = self.conntrack.lock().insert(
                    peer,
                    &parsed,
                    false,
                    verdict.rule.clone(),
                    gw.is_some(),
                    now,
                ) {
                    tracing::trace!("conntrack: {e:?}");
                    let counter = match e {
                        CtError::SnatPeerQuota | CtError::SnatGlobal => &n.metrics.snat_exhausted,
                        _ => &n.metrics.conntrack_limit,
                    };
                    counter.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
        if let Some(g) = gw {
            // Destination translation for mapped routes; the kernel does SNAT.
            if g.mapped() {
                let Some(ld) = map_prefix(dst, &g.published, &g.lan) else {
                    return;
                };
                packet::rewrite(&mut p, None, Some((ld, parsed.flow.dport)));
            }
        }
        self.write_tun(p);
    }

    // ------------------------------------------------------------ state changes

    /// Undo system changes (routes, split DNS) at shutdown (§20.8). The tun
    /// interface itself disappears with the process.
    pub fn shutdown(&self) {
        if self.tun_tx.is_none() {
            return;
        }
        self.proxy.shutdown(self);
        for r in self.routes.lock().drain(..) {
            crate::platform::del_route(&r, &self.dev_name);
        }
        crate::platform::cleanup(&self.dev_name);
    }

    /// Re-apply routes, gateway serving and policy after the tree changed.
    pub fn refresh(&self) {
        let Some(n) = self.node() else { return };
        let generation = n.store.read().generation;
        if self.applied_gen.swap(generation, Ordering::SeqCst) == generation {
            return;
        }
        // Limits may have changed with the tree.
        apply_limits(&n, &mut self.conntrack.lock());
        let (my_ips, grants, pool, resolver, suffix, zones) = {
            let s = n.store.read();
            let v = s.view();
            let me = v.nodes.get(&n.me);
            let resolver: Vec<IpAddr> = v.resolver_ips(&s.overlay_pool);
            // The zones this node's resolver answers: forwarded zones and the
            // parents of admin records, the network's and its own (§6.19).
            let mut zones: Vec<String> = v
                .dns_forward_for(&n.me)
                .iter()
                .filter_map(|f| f.zone.clone())
                .collect();
            zones.extend(
                v.dns_records_for(&n.me)
                    .iter()
                    .filter_map(|r| r.name.clone())
                    .filter_map(|nm| nm.split_once('.').map(|x| x.1.to_string())),
            );
            zones.sort();
            zones.dedup();
            (
                me.map(|m| m.ips.clone()).unwrap_or_default(),
                me.map(|m| m.routes.clone()).unwrap_or_default(),
                s.overlay_pool.clone(),
                resolver,
                v.suffix(),
                zones,
            )
        };
        *self.my_ips.write() = my_ips;
        *self.resolver.write() = resolver.clone();
        // Gateway serving (§11.9.2): local config ∩ grants, LAN interface up.
        let mut serving = Vec::new();
        for r in &n.cfg.gateway.route {
            let Ok(pubnet) = webjet_core::types::parse_net(&r.published) else {
                continue;
            };
            if let Some(g) = grants.iter().find(|g| g.published == pubnet)
                && crate::platform::iface_up(&r.interface)
            {
                serving.push((*g, r.interface.clone()));
                let mut done = self.nat_done.lock();
                if !done.contains(&r.interface)
                    && crate::platform::setup_gateway_nat(&pool, &self.dev_name, &r.interface)
                {
                    done.push(r.interface.clone());
                }
            }
        }
        let changed = *self.serving.read().iter().map(|x| x.0).collect::<Vec<_>>()
            != serving.iter().map(|x| x.0).collect::<Vec<_>>();
        *self.serving.write() = serving;
        if changed {
            crate::gossip::publish_endpoint(&n, true);
        }
        // Routes: the overlay pool and every published prefix.
        if self.tun_tx.is_some() {
            let mut want: Vec<IpNet> = pool.clone();
            let s = n.store.read();
            for info in s.view().nodes.values() {
                if info.id != n.me && info.valid {
                    want.extend(info.routes.iter().map(|g| g.published));
                }
            }
            drop(s);
            want.sort();
            want.dedup();
            let mut cur = self.routes.lock();
            for r in cur.iter() {
                if !want.contains(r) {
                    crate::platform::del_route(r, &self.dev_name);
                }
            }
            for r in &want {
                if !cur.contains(r) {
                    crate::platform::add_route(r, &self.dev_name);
                }
            }
            *cur = want;
            if n.cfg.dns.configure_system {
                let mut domains = vec![suffix];
                domains.extend(zones);
                domains.sort();
                domains.dedup();
                crate::platform::configure_dns(&self.dev_name, &resolver, &domains);
            }
        }
        // Re-evaluate tracked flows under the new policy (§14.4).
        let dropped = {
            let s = n.store.read();
            let vw = s.view();
            let me = vw.nodes.get(&n.me).map(|x| vw.subject(x));
            let mut ct = self.conntrack.lock();
            ct.reevaluate(|k, e| {
                let Some(me) = me.as_ref() else { return false };
                let Some(pn) = vw.nodes.get(&k.peer).filter(|x| x.valid) else {
                    return false;
                };
                let ps = vw.subject(pn);
                let to_node = vw.node_by_ip(&k.flow.dst).is_some();
                let d = if e.outbound {
                    if to_node {
                        vw.policy
                            .evaluate(me, Dest::Node(&ps), k.flow.proto, k.flow.dport)
                    } else {
                        vw.policy
                            .evaluate(me, Dest::Addr(k.flow.dst), k.flow.proto, k.flow.dport)
                    }
                } else if to_node {
                    vw.policy
                        .evaluate(&ps, Dest::Node(me), k.flow.proto, k.flow.dport)
                } else {
                    vw.policy
                        .evaluate(&ps, Dest::Addr(k.flow.dst), k.flow.proto, k.flow.dport)
                };
                d.decision == Decision::Allow
            })
        };
        if dropped > 0 {
            tracing::info!("policy change closed {dropped} tracked flows");
        }
        self.proxy.refresh(&n, self);
    }
}

/// Create the data plane: the tun device (if enabled) and its tasks.
/// Connection tracking limits from the effective Limits (§16.2, §16.4).
fn apply_limits(n: &Node, ct: &mut Conntrack) {
    use crate::metrics::limit;
    ct.per_peer_quota = limit(n, "conntrack_per_peer") as usize;
    ct.new_per_sec = limit(n, "conntrack_new_per_sec") as u32;
    ct.global_cap = limit(n, "conntrack_global") as usize;
    ct.gateway_per_peer_quota = limit(n, "snat_ports_per_source") as usize;
    ct.gateway_cap = limit(n, "snat_global") as usize;
}

pub async fn start(n: &Arc<Node>) -> anyhow::Result<Arc<Dataplane>> {
    let (my_ips, pool) = {
        let s = n.store.read();
        (
            s.view()
                .nodes
                .get(&n.me)
                .map(|m| m.ips.clone())
                .unwrap_or_default(),
            s.overlay_pool.clone(),
        )
    };
    let mut ct = Conntrack::new(0, 0, 0);
    apply_limits(n, &mut ct);
    let mut dev_name = n.cfg.tun.name.clone().unwrap_or_else(|| {
        if cfg!(target_os = "macos") {
            "utun".into()
        } else {
            "webjet0".into()
        }
    });
    let mut tun_tx = None;
    let mut dev_handle = None;
    if n.cfg.tun.enabled {
        let mut b = tun_rs::DeviceBuilder::new().mtu(n.cfg.tun.mtu);
        #[cfg(windows)]
        {
            // wintun.dll ships next to webjetd.exe (§19.1).
            let dll = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("wintun.dll")));
            if let Some(d) = dll.filter(|d| d.exists()) {
                b = b.wintun_file(d.to_string_lossy().into_owned());
            }
            b = b.description("Webjet");
        }
        if !cfg!(target_os = "macos") || dev_name.starts_with("utun") && dev_name.len() > 4 {
            b = b.name(dev_name.clone());
        }
        for ip in &my_ips {
            let plen = pool
                .iter()
                .find(|p| p.contains(&ip.addr()))
                .map(|p| p.prefix_len())
                .unwrap_or(ip.prefix_len());
            match ip.addr() {
                IpAddr::V4(a) => b = b.ipv4(a, plen, None),
                IpAddr::V6(a) => b = b.ipv6(a, plen),
            }
        }
        let dev = Arc::new(b.build_async().map_err(|e| {
            anyhow::anyhow!("creating the tun interface: {e} (root/CAP_NET_ADMIN needed)")
        })?);
        if let Ok(name) = dev.name() {
            dev_name = name;
        }
        tracing::info!("tun interface {dev_name} up, mtu {}", n.cfg.tun.mtu);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4096);
        let d2 = dev.clone();
        tokio::spawn(async move {
            while let Some(p) = rx.recv().await {
                if let Err(e) = d2.send(&p).await {
                    tracing::debug!("tun write: {e}");
                }
            }
        });
        tun_tx = Some(tx);
        dev_handle = Some(dev);
    } else {
        tracing::info!("tun interface disabled by configuration");
    }
    let dp = Arc::new(Dataplane {
        node: Arc::downgrade(n),
        dev_name,
        tun_tx,
        sink: Mutex::new(None),
        conntrack: Mutex::new(ct),
        icmp_bucket: Mutex::new(Bucket::new(10.0, 20.0)),
        my_ips: RwLock::new(my_ips),
        serving: RwLock::new(Vec::new()),
        routes: Mutex::new(Vec::new()),
        applied_gen: AtomicU64::new(u64::MAX),
        resolver: RwLock::new(Vec::new()),
        gw_choice: Mutex::new(HashMap::new()),
        nat_done: Mutex::new(Vec::new()),
        pings: Mutex::new(HashMap::new()),
        proxy: crate::proxy::Proxy::new(),
    });
    if let Some(dev) = dev_handle {
        let dp2 = dp.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match dev.recv(&mut buf).await {
                    Ok(len) => dp2.outbound(buf[..len].to_vec()),
                    Err(e) => {
                        tracing::warn!("tun read: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }
    let dp2 = dp.clone();
    let mut ev = n.events.subscribe();
    tokio::spawn(async move {
        dp2.refresh();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            tokio::select! {
                e = ev.recv() => {
                    if matches!(e, Err(tokio::sync::broadcast::error::RecvError::Closed)) { break }
                }
                _ = tick.tick() => {
                    dp2.conntrack.lock().expire(Instant::now());
                    dp2.proxy.table.lock().expire(Instant::now());
                    // Re-check LAN interfaces for serving changes.
                    dp2.applied_gen.store(u64::MAX, Ordering::SeqCst);
                }
            }
            dp2.refresh();
        }
    });
    Ok(dp)
}

#[allow(dead_code)]
fn _parsed(_: &Parsed) {}

/// At most this many flows go into one `conntrack` answer.
const FLOWS_SHOWN: usize = 2000;

fn proto_name(p: u8) -> String {
    use webjet_core::policy::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
    match p {
        PROTO_TCP => "tcp".into(),
        PROTO_UDP => "udp".into(),
        PROTO_ICMP => "icmp".into(),
        PROTO_ICMPV6 => "icmpv6".into(),
        p => p.to_string(),
    }
}

/// A conntrack state for people.
pub fn state_name(s: webjet_core::conntrack::State) -> &'static str {
    use webjet_core::conntrack::State;
    match s {
        State::TcpOpening => "tcp opening",
        State::TcpEstablished => "tcp established",
        State::TcpClosing => "tcp closing",
        State::UdpOneWay => "udp one-way",
        State::UdpBoth => "udp",
        State::IcmpEcho => "icmp echo",
        State::Other => "other",
    }
}

/// The tracked flows (§14.4) with the circuit each peer's traffic currently
/// takes, for the control channel (`conntrack`). Most recently active first.
pub fn flows(n: &Node) -> serde_json::Value {
    use serde_json::json;

    let Some(dp) = n.dataplane.get() else {
        return json!({"running": false, "total": 0, "flows": [], "limits": {}});
    };
    let now = Instant::now();
    let (mut rows, total, gateway, limits) = {
        let ct = dp.conntrack.lock();
        let rows: Vec<_> = ct
            .entries()
            .filter(|(_, e)| now.duration_since(e.last) < e.state.timeout())
            .map(|(k, e)| (*k, e.clone()))
            .collect();
        (
            rows,
            ct.len(),
            ct.gateway_len(),
            json!({
                "per_peer": ct.per_peer_quota,
                "new_per_sec": ct.new_per_sec,
                "global": ct.global_cap,
                "evictions": ct.evictions,
            }),
        )
    };
    rows.sort_by_key(|(_, e)| std::cmp::Reverse(e.last));
    let shown = rows.len().min(FLOWS_SHOWN);
    // The circuit each peer's session sends on: its hops, or direct.
    let mut circuit_of: HashMap<Bytes32, Option<serde_json::Value>> = HashMap::new();
    let mut out = Vec::with_capacity(shown);
    for (k, e) in rows.iter().take(FLOWS_SHOWN) {
        let circuit = circuit_of
            .entry(k.peer)
            .or_insert_with(|| {
                let label = n.e2e.get(&k.peer)?.primary()?;
                let c = n
                    .circuits
                    .lock()
                    .local_circuits(&k.peer)
                    .into_iter()
                    .find(|c| c.label == label)?;
                let rtt_ms = c.probes.lock().srtt_ms;
                Some(json!({
                    "label": label,
                    "direct": c.direct(),
                    "hops": c.hops.iter().map(|h| n.name_of(h)).collect::<Vec<_>>(),
                    "rtt_ms": rtt_ms,
                }))
            })
            .clone();
        let state = state_name(e.state);
        let idle = now.duration_since(e.last);
        out.push(json!({
            "peer": n.name_of(&k.peer),
            "peer_id": hex::encode(k.peer),
            "proto": proto_name(k.flow.proto),
            "src": k.flow.src.to_string(),
            "sport": k.flow.sport,
            "dst": k.flow.dst.to_string(),
            "dport": k.flow.dport,
            "state": state,
            "outbound": e.outbound,
            "replied": e.saw_reply,
            "gateway": e.gateway,
            "rule": e.rule,
            "idle_s": idle.as_secs(),
            "expires_s": e.state.timeout().saturating_sub(idle).as_secs(),
            "circuit": circuit,
        }));
    }
    json!({
        "running": true,
        "total": total,
        "live": rows.len(),
        "gateway": gateway,
        "truncated": rows.len() > shown,
        "limits": limits,
        "flows": out,
    })
}
