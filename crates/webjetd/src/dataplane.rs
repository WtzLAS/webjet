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
use webjet_core::packet::{self, Bucket, Unreach};
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
    /// The tree generation tracked flows were last re-checked against.
    policy_gen: AtomicU64,
    pub resolver: RwLock<Vec<IpAddr>>,
    /// Sticky gateway choice per published prefix (§11.9.3).
    gw_choice: Mutex<HashMap<IpNet, Bytes32>>,
    /// `gateways_for` answers by destination, briefly.
    gw_cache: Mutex<HashMap<IpAddr, GwCached>>,
    local_nets: Mutex<Option<(Instant, Vec<IpNet>)>>,
    nat_done: Mutex<Vec<String>>,
    /// System DNS as last configured.
    dns_applied: Mutex<Option<DnsApplied>>,
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
                    tokio::spawn(async move {
                        if let Some(dp) = n.dataplane.get() {
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
            tokio::spawn(async move {
                if let Some(reply) = crate::dns::handle(&n, &p).await
                    && let Some(dp) = n.dataplane.get()
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
                // Addresses only; for ICMP errors the quoted destination too.
                if !packet::map_addrs(&mut p, true, |a| map_prefix(a, &g.lan, &g.published)) {
                    return;
                }
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
                        .insert(&peer, &parsed, true, verdict.rule, false, now)
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
        let (prefix, gws) = self.gateways_for(n, dst)?;
        // Keep the sticky choice while it serves the prefix and its session
        // is up (or no gateway has one). Session lookups happen without the
        // choice lock held (lock-ordering rule: never nest helper locks).
        let established = |g: &Bytes32| n.e2e.get(g).is_some_and(|s| s.established());
        let current = self.gw_choice.lock().get(&prefix).copied();
        if let Some(c) = current
            && gws.contains(&c)
            && (established(&c) || !gws.iter().any(established))
        {
            return Some((c, false));
        }
        let pick = gws
            .iter()
            .copied()
            .find(|g| established(g))
            .unwrap_or_else(|| gws[rand::random_range(0..gws.len())]);
        self.gw_choice.lock().insert(prefix, pick);
        Some((pick, false))
    }

    /// The most specific published prefix containing `dst` and the gateways
    /// serving it, or None (none, or it clashes with a local network). Every
    /// packet to a gateway route asks, so answers are cached briefly instead
    /// of scanning every node's grants and record per packet.
    fn gateways_for(&self, n: &Arc<Node>, dst: &IpAddr) -> Option<(IpNet, Vec<Bytes32>)> {
        let now = Instant::now();
        if let Some((at, v)) = self.gw_cache.lock().get(dst)
            && now.duration_since(*at) < GW_CACHE_TTL
        {
            return v.clone();
        }
        let v = self.scan_gateways(n, dst);
        let mut c = self.gw_cache.lock();
        if c.len() >= GW_CACHE_MAX {
            c.retain(|_, (at, _)| now.duration_since(*at) < GW_CACHE_TTL);
            if c.len() >= GW_CACHE_MAX {
                c.clear();
            }
        }
        c.insert(*dst, (now, v.clone()));
        v
    }

    fn scan_gateways(&self, n: &Arc<Node>, dst: &IpAddr) -> Option<(IpNet, Vec<Bytes32>)> {
        // Published prefixes: gateways that hold the grant and serve it.
        let mut best: Option<(u8, IpNet, Vec<Bytes32>)> = None;
        let mut unknown: Vec<Bytes32> = Vec::new();
        {
            let s = n.store.read();
            let v = s.view();
            let recs = n.records.lock();
            for (id, info) in &v.nodes {
                if !info.valid
                    || *id == n.me
                    || !info.routes.iter().any(|g| g.published.contains(dst))
                {
                    continue;
                }
                // No record yet (edge nodes learn other nodes' records by
                // lookup): treat a grant holder as serving until we know.
                let rec = recs.endpoints.get(id);
                if rec.is_none() {
                    unknown.push(*id);
                }
                let serving: Vec<IpNet> = rec
                    .and_then(|(r, _)| r.serving.as_ref())
                    .map(|s| {
                        s.iter()
                            .filter_map(webjet_core::types::cidr_to_net)
                            .collect()
                    })
                    .unwrap_or_default();
                for g in &info.routes {
                    if g.published.contains(dst)
                        && (rec.is_none() || serving.contains(&g.published))
                    {
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
        if self
            .local_nets(Instant::now())
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
        Some((prefix, gws))
    }

    /// This host's directly connected networks, re-read every few seconds
    /// (each read lists every interface).
    fn local_nets(&self, now: Instant) -> Vec<IpNet> {
        let mut c = self.local_nets.lock();
        if let Some((at, v)) = &*c
            && now.duration_since(*at) < LOCAL_NETS_TTL
        {
            return v.clone();
        }
        let v = crate::platform::local_networks();
        *c = Some((now, v.clone()));
        v
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
                .and_then(|(r, _)| r.serving.as_ref())
                .is_some_and(|s| {
                    s.iter()
                        .filter_map(webjet_core::types::cidr_to_net)
                        .any(|x| x.contains(&src))
                });
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
                    verdict.rule,
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
        // Destination translation for mapped routes; the kernel does SNAT.
        if let Some(g) = gw
            && g.mapped()
            && !packet::map_addrs(&mut p, false, |a| map_prefix(a, &g.published, &g.lan))
        {
            return;
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
            let mut want: Vec<IpNet> = pool;
            let s = n.store.read();
            for info in s.view().nodes.values() {
                if info.id != n.me && info.valid {
                    want.extend(info.routes.iter().map(|g| g.published));
                }
            }
            drop(s);
            want.sort();
            want.dedup();
            // Run the OS commands without holding the routes lock.
            let (gone, new): (Vec<IpNet>, Vec<IpNet>) = {
                let mut cur = self.routes.lock();
                let gone = cur.iter().filter(|r| !want.contains(r)).copied().collect();
                let new = want.iter().filter(|r| !cur.contains(r)).copied().collect();
                *cur = want;
                (gone, new)
            };
            for r in &gone {
                crate::platform::del_route(r, &self.dev_name);
            }
            for r in &new {
                crate::platform::add_route(r, &self.dev_name);
            }
            if n.cfg.dns.configure_system {
                let mut domains = vec![suffix];
                domains.extend(zones);
                domains.sort();
                domains.dedup();
                // Only when it changed (the 10 s tick also lands here), but
                // now and then anyway, in case something else reset it.
                let mut last = self.dns_applied.lock();
                let stale = last.as_ref().is_none_or(|(r, d, at)| {
                    *r != resolver || *d != domains || at.elapsed() >= DNS_REAPPLY
                });
                if stale {
                    crate::platform::configure_dns(&self.dev_name, &resolver, &domains);
                    *last = Some((resolver, domains, Instant::now()));
                }
            }
        }
        // Re-evaluate tracked flows under the new policy (§14.4). Only when
        // the tree changed, not on the periodic re-check: it walks every
        // tracked flow while holding the conntrack lock packets need.
        if self.policy_gen.swap(generation, Ordering::SeqCst) == generation {
            self.proxy.refresh(&n, self);
            return;
        }
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

#[cfg(test)]
impl Dataplane {
    /// Drop cached gateway lookups (records changed under the test).
    pub fn forget_gateways(&self) {
        self.gw_cache.lock().clear();
    }

    /// A data plane without a tun interface or tasks, installed in `n`;
    /// what would go to the tun interface arrives on the receiver.
    pub(crate) fn for_test(n: &Arc<Node>) -> (Arc<Dataplane>, mpsc::UnboundedReceiver<Vec<u8>>) {
        let mut ct = Conntrack::new(0, 0, 0);
        apply_limits(n, &mut ct);
        let (tx, rx) = mpsc::unbounded_channel();
        let dp = Arc::new(Dataplane {
            node: Arc::downgrade(n),
            dev_name: "test0".into(),
            tun_tx: None,
            sink: Mutex::new(Some(tx)),
            conntrack: Mutex::new(ct),
            icmp_bucket: Mutex::new(Bucket::new(1000.0, 1000.0)),
            my_ips: RwLock::new(Vec::new()),
            serving: RwLock::new(Vec::new()),
            routes: Mutex::new(Vec::new()),
            applied_gen: AtomicU64::new(u64::MAX),
            policy_gen: AtomicU64::new(u64::MAX),
            resolver: RwLock::new(Vec::new()),
            gw_choice: Mutex::new(HashMap::new()),
            gw_cache: Mutex::new(HashMap::new()),
            local_nets: Mutex::new(None),
            nat_done: Mutex::new(Vec::new()),
            dns_applied: Mutex::new(None),
            pings: Mutex::new(HashMap::new()),
            proxy: crate::proxy::Proxy::new(),
        });
        let _ = n.dataplane.set(dp.clone());
        dp.refresh();
        (dp, rx)
    }

    /// Serve a grant as a gateway (tests skip the interface check).
    pub(crate) fn serve_for_test(&self, g: Grant) {
        self.serving.write().push((g, "lan0".into()));
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
                .map_or(ip.prefix_len(), |p| p.prefix_len());
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
        n.tasks.service("tun-writer", async move {
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
        policy_gen: AtomicU64::new(u64::MAX),
        resolver: RwLock::new(Vec::new()),
        gw_choice: Mutex::new(HashMap::new()),
        gw_cache: Mutex::new(HashMap::new()),
        local_nets: Mutex::new(None),
        nat_done: Mutex::new(Vec::new()),
        dns_applied: Mutex::new(None),
        pings: Mutex::new(HashMap::new()),
        proxy: crate::proxy::Proxy::new(),
    });
    if let Some(dev) = dev_handle {
        let dp2 = dp.clone();
        n.tasks.service("tun-reader", async move {
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
    n.tasks.service("dataplane-refresh", async move {
        // Refreshing runs OS commands (routes, DNS, NAT) that block: keep
        // them off the async workers. One at a time, as this loop awaits each.
        let refresh = |dp: Arc<Dataplane>| async move {
            let _ = tokio::task::spawn_blocking(move || dp.refresh()).await;
        };
        refresh(dp2.clone()).await;
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
            refresh(dp2.clone()).await;
        }
    });
    Ok(dp)
}

/// At most this many flows go into one `conntrack` answer.
const FLOWS_SHOWN: usize = 2000;

/// Unchanged system DNS settings are re-applied this often (another program
/// or a network change may have reset them); changes apply at once.
const DNS_REAPPLY: std::time::Duration = std::time::Duration::from_secs(300);

/// Resolvers, domains, and when they were configured.
type DnsApplied = (Vec<IpAddr>, Vec<String>, Instant);

/// A gateway lookup: when, and the prefix with its gateways.
type GwCached = (Instant, Option<(IpNet, Vec<Bytes32>)>);

/// Gateway lookups are reused this long: a new or withdrawn gateway record
/// takes effect within it.
const GW_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(1);
/// Destinations cached at most (scans of many addresses can't grow it).
const GW_CACHE_MAX: usize = 4096;
const LOCAL_NETS_TTL: std::time::Duration = std::time::Duration::from_secs(5);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testnode::{self, Cluster};
    use webjet_core::crypto::KeyPair;
    use webjet_core::packet::tcpf;
    use webjet_core::testutil::{
        NodeSpec,
        packets::{tcp4, udp4},
    };
    use webjet_proto as wp;

    const ME: [u8; 4] = [10, 7, 0, 2];
    const CLIENT: [u8; 4] = [10, 7, 0, 3];
    const OTHER: [u8; 4] = [10, 7, 0, 4];

    fn rule(id: &str, src: &str, dst: &str, ports: &str) -> wp::Rule {
        wp::Rule {
            id: Some(id.into()),
            action: wp::Action::Allow,
            src: Some(vec![src.into()]),
            dst: Some(vec![dst.into()]),
            ports: Some(vec![ports.into()]),
        }
    }

    /// Clients may reach servers on tcp:80 and ICMP; nothing else.
    fn policy() -> wp::Policy {
        wp::Policy {
            default_action: wp::Action::Deny,
            rules: Some(vec![
                rule("web", "tag:client", "tag:server", "tcp:80"),
                rule("ping", "*", "*", "icmp"),
            ]),
            ..Default::default()
        }
    }

    struct T {
        c: Cluster,
        n: Arc<Node>,
        dp: Arc<Dataplane>,
        tun: mpsc::UnboundedReceiver<Vec<u8>>,
        client: Bytes32,
        other: Bytes32,
        gw: (Bytes32, KeyPair),
        _dir: tempfile::TempDir,
    }

    fn setup() -> T {
        let mut c = Cluster::new();
        let me = c.data_node("me", "10.7.0.2", &["tag:server"]);
        let client = c.data_node("client", "10.7.0.3", &["tag:client"]).0;
        let other = c.data_node("other", "10.7.0.4", &[]).0;
        let gw = c.enroll(NodeSpec {
            name: "gw",
            ip: "10.7.0.5",
            tags: &["tag:server"],
            routes: &["172.31.99.0/24"],
            ..Default::default()
        });
        c.set_policy(policy()).unwrap();
        let (n, dir) = testnode::node(&mut c, me.0, me.1);
        let (dp, tun) = Dataplane::for_test(&n);
        T {
            c,
            n,
            dp,
            tun,
            client,
            other,
            gw,
            _dir: dir,
        }
    }

    fn tun_packets(t: &mut T) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        while let Ok(p) = t.tun.try_recv() {
            v.push(p);
        }
        v
    }

    fn counter(a: &AtomicU64) -> u64 {
        a.load(Ordering::Relaxed)
    }

    #[tokio::test]
    async fn inbound_allowed_by_policy() {
        let mut t = setup();
        let syn = tcp4(CLIENT, ME, 40000, 80, tcpf::SYN);
        t.dp.inbound(&t.client, syn.clone());
        assert_eq!(tun_packets(&mut t), vec![syn]);
        assert_eq!(t.dp.conntrack.lock().len(), 1);
        assert_eq!(t.n.metrics.rule_hits.lock()[&("web".into(), true)], 1);
        let f = flows(&t.n);
        assert_eq!(f["total"], 1);
        assert_eq!(f["flows"][0]["peer"], "client");
        assert_eq!(f["flows"][0]["rule"], "web");
        assert_eq!(f["flows"][0]["proto"], "tcp");
        assert_eq!(f["flows"][0]["outbound"], false);
    }

    #[tokio::test]
    async fn later_fragments_follow_an_allowed_first_fragment() {
        let mut t = setup();
        // A datagram to an allowed port, split in two: the later fragment
        // has no ports (it used to be refused as port 0 / an invalid flow).
        let mut first = tcp4(CLIENT, ME, 40000, 80, tcpf::SYN);
        first[4..6].copy_from_slice(&[0x12, 0x34]);
        first[6] = 0x20;
        let mut later = tcp4(CLIENT, ME, 1, 2, 0);
        later[4..6].copy_from_slice(&[0x12, 0x34]);
        later[7] = 5;
        t.dp.inbound(&t.client, first.clone());
        t.dp.inbound(&t.client, later.clone());
        assert_eq!(tun_packets(&mut t), vec![first, later.clone()]);
        assert_eq!(t.dp.conntrack.lock().len(), 1);
        // A later fragment of a datagram that wasn't admitted stays out.
        later[4..6].copy_from_slice(&[0x56, 0x78]);
        t.dp.inbound(&t.client, later);
        assert!(tun_packets(&mut t).is_empty());
    }

    #[tokio::test]
    async fn inbound_denied_by_policy() {
        let mut t = setup();
        t.dp.inbound(&t.client, tcp4(CLIENT, ME, 40000, 22, tcpf::SYN));
        // Not tagged as a client.
        t.dp.inbound(&t.other, tcp4(OTHER, ME, 40000, 80, tcpf::SYN));
        assert!(tun_packets(&mut t).is_empty());
        assert_eq!(counter(&t.n.metrics.acl_denied), 2);
        assert_eq!(t.dp.conntrack.lock().len(), 0);
    }

    #[tokio::test]
    async fn cryptokey_routing_drops_spoofed_and_misdirected_packets() {
        let mut t = setup();
        // The client sends with the other node's address.
        t.dp.inbound(&t.client, tcp4(OTHER, ME, 40000, 80, tcpf::SYN));
        // To an address that is neither ours nor a LAN we serve.
        t.dp.inbound(&t.client, tcp4(CLIENT, OTHER, 40000, 80, tcpf::SYN));
        // From a node that doesn't exist.
        t.dp.inbound(&[9; 32], tcp4(CLIENT, ME, 40000, 80, tcpf::SYN));
        // Not an IP packet.
        t.dp.inbound(&t.client, b"junk".to_vec());
        assert!(tun_packets(&mut t).is_empty());
        assert_eq!(counter(&t.n.metrics.cryptokey_dropped), 2);
    }

    #[tokio::test]
    async fn the_resolver_is_not_reachable_from_the_network() {
        let mut t = setup();
        let resolver = t.dp.resolver.read()[0];
        let IpAddr::V4(r) = resolver else {
            panic!("IPv4 pool, IPv4 resolver")
        };
        t.dp.inbound(&t.client, udp4(CLIENT, r.octets(), 5353, 53, b"query"));
        assert!(tun_packets(&mut t).is_empty());
    }

    #[tokio::test]
    async fn outbound_without_a_route_is_host_unreachable() {
        let mut t = setup();
        let p = tcp4(ME, [10, 7, 9, 9], 40000, 80, tcpf::SYN);
        t.dp.outbound(p);
        let out = tun_packets(&mut t);
        assert_eq!(out.len(), 1, "an ICMP error back to the host");
        let icmp = packet::parse(&out[0]).unwrap();
        assert_eq!(icmp.icmp, Some(packet::IcmpKind::Error));
        assert_eq!(icmp.flow.dst, IpAddr::from(ME));
        assert_eq!(counter(&t.n.metrics.no_route), 1);
        assert_eq!(counter(&t.n.metrics.tun_rx), 1);
    }

    #[tokio::test]
    async fn outbound_denied_is_prohibited() {
        let mut t = setup();
        // A server may not open connections to the client.
        t.dp.outbound(tcp4(ME, CLIENT, 40000, 80, tcpf::SYN));
        let out = tun_packets(&mut t);
        assert_eq!(out.len(), 1);
        assert_eq!(
            packet::parse(&out[0]).unwrap().icmp,
            Some(packet::IcmpKind::Error)
        );
        assert_eq!(counter(&t.n.metrics.acl_denied), 1);
        assert_eq!(t.dp.conntrack.lock().len(), 0);
    }

    #[tokio::test]
    async fn outbound_allowed_is_tracked_and_replies_come_back() {
        let mut t = setup();
        t.c.set_policy(wp::Policy {
            rules: Some(vec![rule("out", "tag:server", "tag:client", "tcp:443")]),
            ..policy()
        })
        .unwrap();
        testnode::sync(&mut t.c, &t.n);
        t.dp.refresh();
        t.dp.outbound(tcp4(ME, CLIENT, 40000, 443, tcpf::SYN));
        assert!(tun_packets(&mut t).is_empty(), "sent to the overlay");
        assert_eq!(t.dp.conntrack.lock().len(), 1);
        // Queued in the new end-to-end session until its handshake.
        assert!(t.n.e2e.get(&t.client).is_some());
        // The reply is let in although the policy has nothing for that
        // direction: it belongs to a tracked flow.
        let reply = tcp4(CLIENT, ME, 443, 40000, tcpf::SYN | tcpf::ACK);
        t.dp.inbound(&t.client, reply.clone());
        assert_eq!(tun_packets(&mut t), vec![reply]);
        assert_eq!(flows(&t.n)["flows"][0]["state"], "tcp established");
    }

    #[tokio::test]
    async fn a_policy_change_closes_flows_it_no_longer_allows() {
        let mut t = setup();
        t.dp.inbound(&t.client, tcp4(CLIENT, ME, 40000, 80, tcpf::SYN));
        assert_eq!(t.dp.conntrack.lock().len(), 1);
        t.c.set_policy(wp::Policy {
            rules: Some(vec![rule("ping", "*", "*", "icmp")]),
            ..policy()
        })
        .unwrap();
        // Unchanged tree: nothing re-evaluated.
        t.dp.refresh();
        assert_eq!(t.dp.conntrack.lock().len(), 1);
        testnode::sync(&mut t.c, &t.n);
        t.dp.refresh();
        assert_eq!(t.dp.conntrack.lock().len(), 0);
        // Now the next packet of the flow is new again, and denied.
        t.dp.inbound(&t.client, tcp4(CLIENT, ME, 40000, 80, tcpf::ACK));
        let _ = tun_packets(&mut t);
        assert_eq!(t.dp.conntrack.lock().len(), 0);
    }

    #[tokio::test]
    async fn own_addresses_loop_back() {
        let mut t = setup();
        let p = udp4(ME, ME, 1000, 2000, b"hello");
        t.dp.outbound(p.clone());
        assert_eq!(tun_packets(&mut t), vec![p]);
        assert_eq!(counter(&t.n.metrics.tun_rx), 0, "not overlay traffic");
        assert!(t.dp.is_mine(&IpAddr::from(ME)));
        assert_eq!(t.dp.my_ip(false), Some(IpAddr::from(ME)));
        assert_eq!(t.dp.my_ip(true), None);
    }

    #[tokio::test]
    async fn ping_myself_without_a_tun_interface() {
        let t = setup();
        let r = t.dp.ping(IpAddr::from(ME), 2, 32).await;
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|x| x.is_some()), "{r:?}");
        // No address of that family: nothing to ping from.
        assert!(
            t.dp.ping("fd00::1".parse().unwrap(), 1, 32)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn published_prefixes_route_to_a_serving_gateway() {
        let t = setup();
        let lan: IpAddr = "172.31.99.7".parse().unwrap();
        // Nodes by overlay address.
        assert_eq!(
            t.dp.route(&t.n, &IpAddr::from(CLIENT)),
            Some((t.client, true))
        );
        // No record of the gateway yet: assumed to serve its grant.
        assert_eq!(t.dp.route(&t.n, &lan), Some((t.gw.0, false)));
        // Its record says it serves nothing: no route.
        let rec = |serving: Vec<wp::Cidr>| wp::EndpointRecord {
            node_id: Some(webjet_core::crypto::k32(&t.gw.0)),
            serving: Some(serving),
            ..Default::default()
        };
        t.n.records
            .lock()
            .endpoints
            .insert(t.gw.0, (rec(vec![]), Vec::new()));
        // Gateway lookups are cached for GW_CACHE_TTL; tests don't wait.
        t.dp.forget_gateways();
        assert_eq!(t.dp.route(&t.n, &lan), None);
        let published = webjet_core::types::net_to_cidr(&"172.31.99.0/24".parse().unwrap());
        t.n.records
            .lock()
            .endpoints
            .insert(t.gw.0, (rec(vec![published]), Vec::new()));
        t.dp.forget_gateways();
        assert_eq!(t.dp.route(&t.n, &lan), Some((t.gw.0, false)));
        assert_eq!(t.dp.route(&t.n, &"172.31.98.1".parse().unwrap()), None);
    }

    #[tokio::test]
    async fn serving_a_mapped_grant_translates_destinations() {
        let mut t = setup();
        let g = Grant::parse("192.168.50.0/24=172.31.99.0/24").unwrap();
        t.dp.serve_for_test(g);
        assert_eq!(t.dp.serving_prefixes(), vec![g.published]);
        assert_eq!(t.dp.serving_grant(&"172.31.99.9".parse().unwrap()), Some(g));
        // Clients may reach the published prefix on tcp:80.
        t.c.set_policy(wp::Policy {
            rules: Some(vec![rule(
                "lan",
                "tag:client",
                "cidr:172.31.99.0/24",
                "tcp:80",
            )]),
            ..policy()
        })
        .unwrap();
        testnode::sync(&mut t.c, &t.n);
        t.dp.refresh();
        t.dp.serve_for_test(g);
        t.dp.inbound(
            &t.client,
            tcp4(CLIENT, [172, 31, 99, 9], 40000, 80, tcpf::SYN),
        );
        let out = tun_packets(&mut t);
        assert_eq!(out.len(), 1);
        let p = packet::parse(&out[0]).unwrap();
        assert_eq!(p.flow.dst, "192.168.50.9".parse::<IpAddr>().unwrap());
        assert_eq!(p.flow.dport, 80);
        let f = flows(&t.n);
        assert_eq!(f["gateway"], 1);
        // LAN hosts may answer the tracked flow but not start one.
        t.dp.outbound(tcp4([192, 168, 50, 10], CLIENT, 80, 40000, tcpf::SYN));
        assert_eq!(t.dp.conntrack.lock().len(), 1, "no new flow");
    }

    #[test]
    fn names() {
        use webjet_core::conntrack::State;
        assert_eq!(state_name(State::UdpBoth), "udp");
        assert_eq!(state_name(State::TcpOpening), "tcp opening");
        assert_eq!(proto_name(6), "tcp");
        assert_eq!(proto_name(58), "icmpv6");
        assert_eq!(proto_name(47), "47");
    }

    #[tokio::test]
    async fn limits_follow_the_tree() {
        let mut t = setup();
        assert_eq!(t.dp.conntrack.lock().per_peer_quota, 4096);
        t.c.set_network(wp::NetworkConfig {
            policy: Some(Box::new(policy())),
            limits: Some(Box::new(wp::Limits {
                defaults: Some(vec![wp::LimitValue {
                    name: Some("conntrack_per_peer".into()),
                    value: 3,
                }]),
                ..Default::default()
            })),
            ..Default::default()
        })
        .unwrap();
        testnode::sync(&mut t.c, &t.n);
        t.dp.refresh();
        assert_eq!(t.dp.conntrack.lock().per_peer_quota, 3);
        assert_eq!(flows(&t.n)["limits"]["per_peer"], 3);
        // The fourth flow from one peer is refused and counted.
        for port in 0..4 {
            t.dp.inbound(&t.client, tcp4(CLIENT, ME, 40000 + port, 80, tcpf::SYN));
        }
        assert_eq!(t.dp.conntrack.lock().len(), 3);
        assert_eq!(counter(&t.n.metrics.conntrack_limit), 1);
    }
}
