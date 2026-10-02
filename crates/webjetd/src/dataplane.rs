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
use webjet_core::conntrack::{Conntrack, Verdict as Ct};
use webjet_core::crypto::Bytes32;
use webjet_core::frames::ftype;
use webjet_core::packet::{self, Bucket, Parsed, Unreach};
use webjet_core::policy::{Decision, Dest};
use webjet_core::types::{map_prefix, Grant};

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
}

impl Dataplane {
    pub fn serving_prefixes(&self) -> Vec<IpNet> {
        let mut v: Vec<IpNet> = self.serving.read().iter().map(|(g, _)| g.published).collect();
        v.sort();
        v.dedup();
        v
    }

    fn node(&self) -> Option<Arc<Node>> {
        self.node.upgrade()
    }

    fn write_tun(&self, p: Vec<u8>) {
        if let Some(n) = self.node() {
            n.metrics.tun_tx.fetch_add(1, Ordering::Relaxed);
        }
        match &self.tun_tx {
            Some(tx) => {
                let _ = tx.try_send(p);
            }
            None => {
                if let Some(s) = self.sink.lock().as_ref() {
                    let _ = s.send(p);
                }
            }
        }
    }

    fn icmp(&self, orig: &[u8], why: Unreach) {
        if !self.icmp_bucket.lock().take() {
            return;
        }
        if let Some(r) = packet::icmp_unreachable(orig, why) {
            self.write_tun(r);
        }
    }

    /// No route to the destination (§9.5): host unreachable.
    pub fn unreachable(&self, orig: &[u8]) {
        if let Some(n) = self.node() {
            n.metrics.no_route.fetch_add(1, Ordering::Relaxed);
        }
        self.icmp(orig, Unreach::Host);
    }

    fn is_mine(&self, ip: &IpAddr) -> bool {
        self.my_ips.read().iter().any(|n| n.contains(ip))
    }

    // ------------------------------------------------------------ from the tun interface

    /// A packet the local host sent into the overlay.
    pub fn outbound(&self, mut p: Vec<u8>) {
        let Some(n) = self.node() else { return };
        n.metrics.tun_rx.fetch_add(1, Ordering::Relaxed);
        let Some(parsed) = packet::parse(&p) else { return };
        let (src, dst) = (parsed.flow.src, parsed.flow.dst);
        // The local resolver (§11.10.1).
        if self.resolver.read().contains(&dst) {
            let n2 = n.clone();
            tokio::spawn(async move {
                if let Some(reply) = crate::dns::handle(&n2, &p).await {
                    if let Some(dp) = n2.dataplane.get() {
                        dp.write_tun(reply);
                    }
                }
            });
            return;
        }
        // Gateway return traffic: LAN → overlay (§11.9.4).
        if !self.is_mine(&src) {
            let grant = self.serving.read().iter().map(|(g, _)| *g).find(|g| g.lan.contains(&src));
            let Some(g) = grant else { return };
            let Some(peer) = n.store.read().view().node_by_ip(&dst) else { return };
            if g.mapped() {
                let Some(ps) = map_prefix(src, &g.lan, &g.published) else { return };
                packet::rewrite(&mut p, Some((ps, parsed.flow.sport)), None);
            }
            let Some(after) = packet::parse(&p) else { return };
            let v = self.conntrack.lock().classify(&peer, &after, true, Instant::now());
            if !matches!(v, Ct::Tracked | Ct::RelatedError) {
                return; // replies only; LAN hosts can't start flows (§11.9.4)
            }
            crate::e2e::send(&n, &peer, ftype::DATA, &p, crate::e2e::inner_ecn(&p));
            return;
        }
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
                    let Some(me) = vw.nodes.get(&n.me).map(|x| vw.subject(x)) else { return };
                    match (dest_is_node, vw.nodes.get(&peer)) {
                        (true, Some(pn)) => {
                            let ps = vw.subject(pn);
                            vw.policy.evaluate(&me, Dest::Node(&ps), parsed.flow.proto, parsed.flow.dport)
                        }
                        _ => vw.policy.evaluate(&me, Dest::Addr(dst), parsed.flow.proto, parsed.flow.dport),
                    }
                };
                n.metrics.rule_hit(verdict.rule_id(), verdict.decision == Decision::Allow);
                if verdict.decision == Decision::Deny {
                    n.metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
                    self.icmp(&p, Unreach::Prohibited);
                    return;
                }
                if v == Ct::New {
                    if self.conntrack.lock().insert(&peer, &parsed, true, verdict.rule.clone(), now).is_err() {
                        n.metrics.conntrack_limit.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }
        match crate::e2e::send(&n, &peer, ftype::DATA, &p, crate::e2e::inner_ecn(&p)) {
            crate::e2e::SendResult::NoRoute => self.unreachable(&p),
            _ => {}
        }
    }

    /// The node or serving gateway for a destination address.
    fn route(&self, n: &Arc<Node>, dst: &IpAddr) -> Option<(Bytes32, bool)> {
        let view_node = n.store.read().view().node_by_ip(dst);
        if let Some(id) = view_node {
            return Some((id, true));
        }
        // Published prefixes: gateways that hold the grant and serve it.
        let mut best: Option<(u8, IpNet, Vec<Bytes32>)> = None;
        {
            let s = n.store.read();
            let v = s.view();
            let recs = n.records.lock();
            for (id, info) in &v.nodes {
                if !info.valid || *id == n.me {
                    continue;
                }
                let serving: Vec<IpNet> = recs
                    .endpoints
                    .get(id)
                    .map(|(r, _)| r.serving.clone().unwrap_or_default().iter().filter_map(webjet_core::types::cidr_to_net).collect())
                    .unwrap_or_default();
                for g in &info.routes {
                    if g.published.contains(dst) && serving.contains(&g.published) {
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
        let (_, prefix, gws) = best?;
        // A published prefix that clashes with a directly connected LAN is
        // skipped (§11.9.3).
        if crate::platform::local_networks().iter().any(|l| webjet_core::types::overlaps(l, &prefix)) {
            n.alarm("route_clash", "warning", format!("published prefix {prefix} overlaps a local network; not routed"));
            return None;
        }
        let mut choice = self.gw_choice.lock();
        if let Some(c) = choice.get(&prefix) {
            if gws.contains(c) {
                return Some((*c, false));
            }
        }
        let pick = gws.iter().find(|g| n.e2e.get(g).map(|s| s.established()).unwrap_or(false)).copied().unwrap_or_else(|| gws[rand::random::<usize>() % gws.len()]);
        choice.insert(prefix, pick);
        Some((pick, false))
    }

    // ------------------------------------------------------------ from the overlay

    /// A decrypted packet from `peer` (§9.4.4 step 5, §14.4).
    pub fn inbound(&self, peer: &Bytes32, mut p: Vec<u8>) {
        let Some(n) = self.node() else { return };
        let Some(parsed) = packet::parse(&p) else { return };
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
                Some(info) => (info.ips.iter().any(|i| i.contains(&src)), Some(v.subject(info))),
                None => (false, None),
            }
        };
        let Some(peer_subject) = peer_subject else { return };
        let now = Instant::now();
        if !src_ok {
            // Gateway replies: only on a flow this node started (§9.5 exception).
            let served = n.records.lock().endpoints.get(peer).map(|(r, _)| r.serving.clone().unwrap_or_default().iter().filter_map(webjet_core::types::cidr_to_net).any(|x| x.contains(&src))).unwrap_or(false);
            let tracked = served && matches!(self.conntrack.lock().classify(peer, &parsed, false, now), Ct::Tracked | Ct::RelatedError);
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
            match self.serving.read().iter().find(|(g, _)| g.published.contains(&dst)) {
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
                            let Some(me) = vw.nodes.get(&n.me).map(|x| vw.subject(x)) else { return };
                            vw.policy.evaluate(&peer_subject, Dest::Node(&me), parsed.flow.proto, parsed.flow.dport)
                        }
                        Some(_) => vw.policy.evaluate(&peer_subject, Dest::Addr(dst), parsed.flow.proto, parsed.flow.dport),
                    }
                };
                n.metrics.rule_hit(verdict.rule_id(), verdict.decision == Decision::Allow);
                if verdict.decision == Decision::Deny {
                    n.metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                if let Err(e) = self.conntrack.lock().insert(peer, &parsed, false, verdict.rule.clone(), now) {
                    tracing::trace!("conntrack: {e:?}");
                    n.metrics.conntrack_limit.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
        if let Some(g) = gw {
            // Destination translation for mapped routes; the kernel does SNAT.
            if g.mapped() {
                let Some(ld) = map_prefix(dst, &g.published, &g.lan) else { return };
                packet::rewrite(&mut p, None, Some((ld, parsed.flow.dport)));
            }
        }
        self.write_tun(p);
    }

    // ------------------------------------------------------------ state changes

    /// Re-apply routes, gateway serving and policy after the tree changed.
    pub fn refresh(&self) {
        let Some(n) = self.node() else { return };
        let gen = n.store.read().generation;
        if self.applied_gen.swap(gen, Ordering::SeqCst) == gen {
            return;
        }
        let (my_ips, grants, pool, resolver, suffix, zones) = {
            let s = n.store.read();
            let v = s.view();
            let me = v.nodes.get(&n.me);
            let resolver: Vec<IpAddr> = v.dns.as_ref().map(|d| d.resolver_ip.clone().unwrap_or_default().iter().filter_map(|i| i.to_ip()).collect()).unwrap_or_default();
            let zones: Vec<String> = v
                .dns
                .as_ref()
                .map(|d| {
                    let mut z: Vec<String> = d.forward.clone().unwrap_or_default().iter().filter_map(|f| f.zone.clone()).collect();
                    z.extend(d.records.clone().unwrap_or_default().iter().filter_map(|r| r.name.clone()).filter_map(|nm| nm.split_once('.').map(|x| x.1.to_string())));
                    z
                })
                .unwrap_or_default();
            (me.map(|m| m.ips.clone()).unwrap_or_default(), me.map(|m| m.routes.clone()).unwrap_or_default(), s.overlay_pool.clone(), resolver, v.suffix(), zones)
        };
        *self.my_ips.write() = my_ips;
        *self.resolver.write() = resolver.clone();
        // Gateway serving (§11.9.2): local config ∩ grants, LAN interface up.
        let mut serving = Vec::new();
        for r in &n.cfg.gateway.route {
            let Ok(pubnet) = webjet_core::types::parse_net(&r.published) else { continue };
            if let Some(g) = grants.iter().find(|g| g.published == pubnet) {
                if crate::platform::iface_up(&r.interface) {
                    serving.push((*g, r.interface.clone()));
                    let mut done = self.nat_done.lock();
                    if !done.contains(&r.interface) && crate::platform::setup_gateway_nat(&pool, &self.dev_name, &r.interface) {
                        done.push(r.interface.clone());
                    }
                }
            }
        }
        let changed = *self.serving.read().iter().map(|x| x.0).collect::<Vec<_>>() != serving.iter().map(|x| x.0).collect::<Vec<_>>();
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
                let Some(pn) = vw.nodes.get(&k.peer).filter(|x| x.valid) else { return false };
                let ps = vw.subject(pn);
                let to_node = vw.node_by_ip(&k.flow.dst).is_some();
                let d = if e.outbound {
                    if to_node {
                        vw.policy.evaluate(me, Dest::Node(&ps), k.flow.proto, k.flow.dport)
                    } else {
                        vw.policy.evaluate(me, Dest::Addr(k.flow.dst), k.flow.proto, k.flow.dport)
                    }
                } else if to_node {
                    vw.policy.evaluate(&ps, Dest::Node(me), k.flow.proto, k.flow.dport)
                } else {
                    vw.policy.evaluate(&ps, Dest::Addr(k.flow.dst), k.flow.proto, k.flow.dport)
                };
                d.decision == Decision::Allow
            })
        };
        if dropped > 0 {
            tracing::info!("policy change closed {dropped} tracked flows");
        }
    }
}

/// Create the data plane: the tun device (if enabled) and its tasks.
pub async fn start(n: &Arc<Node>) -> anyhow::Result<Arc<Dataplane>> {
    let (my_ips, pool) = {
        let s = n.store.read();
        (s.view().nodes.get(&n.me).map(|m| m.ips.clone()).unwrap_or_default(), s.overlay_pool.clone())
    };
    let ct = Conntrack::new(
        crate::metrics::limit(n, "conntrack_per_peer", 4096) as usize,
        crate::metrics::limit(n, "conntrack_new_per_sec", 500) as u32,
        crate::metrics::limit(n, "conntrack_global", 262_144) as usize,
    );
    let mut dev_name = n.cfg.tun.name.clone().unwrap_or_else(|| if cfg!(target_os = "macos") { "utun".into() } else { "webjet0".into() });
    let mut tun_tx = None;
    let mut dev_handle = None;
    if n.cfg.tun.enabled {
        let mut b = tun_rs::DeviceBuilder::new().mtu(n.cfg.tun.mtu);
        if !cfg!(target_os = "macos") || dev_name.starts_with("utun") && dev_name.len() > 4 {
            b = b.name(dev_name.clone());
        }
        for ip in &my_ips {
            let plen = pool.iter().find(|p| p.contains(&ip.addr())).map(|p| p.prefix_len()).unwrap_or(ip.prefix_len());
            match ip.addr() {
                IpAddr::V4(a) => b = b.ipv4(a, plen, None),
                IpAddr::V6(a) => b = b.ipv6(a, plen),
            }
        }
        let dev = Arc::new(b.build_async().map_err(|e| anyhow::anyhow!("creating the tun interface: {e} (root/CAP_NET_ADMIN needed)"))?);
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
