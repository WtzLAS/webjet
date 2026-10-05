//! Reverse proxy ports in the agent (§11.11).
//!
//! The ingress (a Linux data node with rules in its node configuration)
//! has the kernel DNAT each listen port to the proxy address (the overlay
//! resolver address: routed into the tun interface, held by no node) and
//! forward it into the tun interface; the packet keeps the client's address
//! as its source. [`Proxy::from_client`] picks a target, translates the
//! destination (and the source unless the client's address is kept) and
//! sends it in a PROXY frame. The target checks the ingress's rule and the
//! policy ([`Proxy::from_peer`]) and writes it to its tun interface; its
//! replies are found by flow ([`Proxy::from_local`]) and go back in PROXY
//! frames, and the ingress turns them back into replies from the proxy
//! address, which the kernel un-DNATs.
//!
//! Proxy flows live in their own table (separate connection tracking,
//! counters, `proxy` control call), never in the overlay's.

use crate::dataplane::Dataplane;
use crate::node::Node;
use parking_lot::{Mutex, RwLock};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use webjet_core::conntrack::{Key, Verdict as Ct};
use webjet_core::crypto::{self, Bytes32};
use webjet_core::frames::ftype;
use webjet_core::packet::{self, Flow, IcmpKind, Parsed, Unreach, tcpf};
use webjet_core::policy::{self, Decision, Dest, PROTO_TCP};
use webjet_core::proxy::{self as px, FlowInfo, Role, Rule, Table, Target};
use webjet_core::store::View;
use webjet_proto as wp;

/// EndpointRecord features: the node takes PROXY frames as a target, and
/// accepts real client addresses (`[proxy] accept_real_ip`, set up).
pub const FEATURE: &str = "proxy";
pub const FEATURE_REAL_IP: &str = "proxy-real-ip";

#[derive(Clone, Debug, Default)]
pub struct Counters {
    pub flows: u64,
    pub to_target_packets: u64,
    pub to_target_bytes: u64,
    pub to_client_packets: u64,
    pub to_client_bytes: u64,
    pub refused: u64,
}

#[derive(Clone, Debug)]
struct RuleState {
    rule: Rule,
    status: String,
    warnings: Vec<String>,
}

/// Where a new flow goes.
struct Choice {
    peer: Bytes32,
    addr: IpAddr,
    /// A node's address (not one behind a gateway).
    is_node: bool,
    real_ip: bool,
}

/// Listen ports (protocol, port) and proxy addresses in the chains.
type Applied = (Vec<(u8, u16)>, Vec<IpAddr>);

pub struct Proxy {
    pub table: Mutex<Table>,
    rules: RwLock<Vec<RuleState>>,
    /// The proxy address of each family (the resolver addresses).
    addrs: RwLock<Vec<IpAddr>>,
    /// What the iptables chains hold: listen ports and proxy addresses.
    applied: Mutex<Option<Applied>>,
    pub real_ip_ready: AtomicBool,
    /// Leftovers of an earlier run were removed.
    cleaned: AtomicBool,
    counters: Mutex<BTreeMap<(Role, String, Bytes32), Counters>>,
}

impl Default for Proxy {
    fn default() -> Self {
        Proxy::new()
    }
}

fn send(n: &Arc<Node>, peer: &Bytes32, p: &[u8]) {
    crate::e2e::send(n, peer, ftype::PROXY, p, crate::e2e::inner_ecn(p));
}

fn features(n: &Node, id: &Bytes32) -> Option<Vec<String>> {
    n.records
        .lock()
        .endpoints
        .get(id)
        .map(|(r, _)| r.features.clone().unwrap_or_default())
}

/// The overlay pool and every published prefix: addresses a client can't
/// have.
fn overlay_nets(v: &View, pool: &[ipnet::IpNet]) -> Vec<ipnet::IpNet> {
    let mut out = pool.to_vec();
    for info in v.nodes.values().filter(|x| x.valid) {
        out.extend(info.routes.iter().map(|g| g.published));
    }
    out
}

/// Data nodes (other than this one) the selectors pick that have an
/// address of the family.
fn candidates(n: &Node, v: &View, sels: &[policy::Selector], v6: bool) -> Vec<Bytes32> {
    v.nodes
        .values()
        .filter(|x| x.valid && x.data && x.id != n.me)
        .filter(|x| x.ips.iter().any(|i| i.addr().is_ipv6() == v6))
        .filter(|x| policy::selects(sels, &v.subject(x)))
        .map(|x| x.id)
        .collect()
}

fn node_ip(v: &View, id: &Bytes32, v6: bool) -> Option<IpAddr> {
    v.nodes
        .get(id)?
        .ips
        .iter()
        .map(|i| i.addr())
        .find(|a| a.is_ipv6() == v6)
}

fn endpoint(a: &IpAddr, port: u16) -> String {
    match a {
        IpAddr::V6(_) => format!("[{a}]:{port}"),
        IpAddr::V4(_) => format!("{a}:{port}"),
    }
}

impl Proxy {
    pub fn new() -> Self {
        Proxy {
            table: Mutex::new(Table::new()),
            rules: RwLock::new(Vec::new()),
            addrs: RwLock::new(Vec::new()),
            applied: Mutex::new(None),
            real_ip_ready: AtomicBool::new(false),
            cleaned: AtomicBool::new(false),
            counters: Mutex::new(BTreeMap::new()),
        }
    }

    fn count(&self, role: Role, rule: &str, owner: Bytes32, f: impl FnOnce(&mut Counters)) {
        f(self
            .counters
            .lock()
            .entry((role, rule.to_string(), owner))
            .or_default());
    }

    /// A packet from the tun interface to the proxy address with a foreign
    /// source on a listen port (or an ICMP error about a proxied flow): a
    /// client's packet the kernel captured (ingress).
    pub fn is_capture(&self, dp: &Dataplane, p: &Parsed) -> bool {
        let f = &p.flow;
        if !self.addrs.read().contains(&f.dst) || dp.is_mine(&f.src) {
            return false;
        }
        p.icmp == Some(IcmpKind::Error)
            || self
                .rules
                .read()
                .iter()
                .any(|r| r.rule.proto == f.proto && r.rule.listen_port == f.dport)
    }

    // ------------------------------------------------------------ the ingress

    /// A client's packet (ingress): an existing flow's or a new one.
    pub fn from_client(&self, n: &Arc<Node>, dp: &Dataplane, p: Vec<u8>, parsed: Parsed) {
        let now = Instant::now();
        let error = parsed.icmp == Some(IcmpKind::Error);
        // An ICMP error from the client quotes a reply we sent it.
        let client = if error {
            match parsed.inner {
                Some(f) => f.reverse(),
                None => return,
            }
        } else {
            parsed.flow
        };
        let known = {
            let t = self.table.lock();
            t.ingress_key(&client, now)
                .and_then(|k| t.info(&k).map(|i| (k, i.rule.clone())))
        };
        if let Some((k, rule)) = known {
            let mut q = p;
            packet::rewrite(
                &mut q,
                Some((k.flow.src, k.flow.sport)),
                Some((k.flow.dst, k.flow.dport)),
            );
            if !error && let Some(pp) = packet::parse(&q) {
                self.table.lock().ct.classify(&k.peer, &pp, true, now);
            }
            self.count(Role::Ingress, &rule, n.me, |c| {
                c.to_target_packets += 1;
                c.to_target_bytes += q.len() as u64;
            });
            send(n, &k.peer, &q);
            return;
        }
        if error {
            return;
        }
        let rule = self
            .rules
            .read()
            .iter()
            .map(|r| r.rule.clone())
            .find(|r| r.proto == client.proto && r.listen_port == client.dport);
        let Some(rule) = rule else { return };
        // Only flow starts open a flow (TCP: a SYN).
        if client.proto == PROTO_TCP && parsed.tcp_flags & (tcpf::SYN | tcpf::ACK) != tcpf::SYN {
            return;
        }
        let refuse = |why: &str| {
            self.count(Role::Ingress, &rule.name, n.me, |c| c.refused += 1);
            tracing::debug!(rule = %rule.name, "reverse proxy: refused {}: {why}", client.src);
        };
        let plausible = {
            let s = n.store.read();
            px::plausible_client(&client.src, &overlay_nets(s.view(), &s.overlay_pool))
        };
        if !plausible {
            return refuse("not a client address");
        }
        let choice = match self.choose(n, dp, &rule, &client.src) {
            Ok(c) => c,
            Err(e) => return refuse(&e),
        };
        let src = if choice.real_ip {
            (client.src, client.sport)
        } else {
            let Some(me) = dp.my_ip(client.src.is_ipv6()) else {
                return refuse("this node has no overlay address of the client's family");
            };
            let Some(port) =
                self.table
                    .lock()
                    .snat_port(client.proto, me, choice.addr, rule.target_port)
            else {
                return refuse("no free source port");
            };
            (me, port)
        };
        let mut q = p.clone();
        packet::rewrite(&mut q, Some(src), Some((choice.addr, rule.target_port)));
        let Some(tp) = packet::parse(&q) else { return };
        let allowed = {
            let s = n.store.read();
            let v = s.view();
            let Some(me) = v.nodes.get(&n.me).map(|x| v.subject(x)) else {
                return;
            };
            let target = v.nodes.get(&choice.peer).map(|x| v.subject(x));
            let dest = match (&target, choice.is_node) {
                (Some(t), true) => Dest::Node(t),
                _ => Dest::Addr(choice.addr),
            };
            v.policy
                .evaluate(&me, dest, client.proto, rule.target_port)
                .decision
                == Decision::Allow
        };
        if !allowed {
            refuse("the policy denies this node the target");
            dp.icmp(&p, Unreach::Prohibited);
            return;
        }
        {
            let mut t = self.table.lock();
            let key = Key {
                peer: choice.peer,
                flow: tp.flow,
            };
            if t.info(&key).is_some() {
                drop(t);
                return refuse("the same flow is already proxied");
            }
            if let Err(e) = t.ct.insert(
                &choice.peer,
                &tp,
                true,
                Some(rule.name.clone()),
                !choice.real_ip,
                now,
            ) {
                drop(t);
                return refuse(&format!("{e:?}"));
            }
            t.add(
                &choice.peer,
                &tp,
                FlowInfo {
                    role: Role::Ingress,
                    rule: rule.name.clone(),
                    owner: n.me,
                    client: Some(client),
                },
            );
        }
        self.count(Role::Ingress, &rule.name, n.me, |c| {
            c.flows += 1;
            c.to_target_packets += 1;
            c.to_target_bytes += q.len() as u64;
        });
        send(n, &choice.peer, &q);
    }

    fn choose(
        &self,
        n: &Arc<Node>,
        dp: &Dataplane,
        rule: &Rule,
        client: &IpAddr,
    ) -> Result<Choice, String> {
        let v6 = client.is_ipv6();
        match &rule.target {
            Target::Addr(a) => {
                if a.is_ipv6() != v6 {
                    return Err("the target's address family isn't the client's".into());
                }
                let (peer, is_node) = dp.route(n, a).ok_or("no route to the target")?;
                if peer == n.me {
                    return Err("the target is this node".into());
                }
                let Some(f) = features(n, &peer) else {
                    crate::gossip::lookup(n, &peer);
                    return Err("the target's endpoint record isn't known yet".into());
                };
                if !f.iter().any(|x| x == FEATURE) {
                    return Err("the target's webjetd has no reverse proxy support".into());
                }
                Ok(Choice {
                    peer,
                    addr: *a,
                    is_node,
                    real_ip: rule.real_ip && is_node && f.iter().any(|x| x == FEATURE_REAL_IP),
                })
            }
            Target::Nodes(sels) => {
                let (ranked, addrs) = {
                    let s = n.store.read();
                    let v = s.view();
                    let c = candidates(n, v, sels, v6);
                    let ranked = px::rank(&c, client);
                    let addrs: Vec<Option<IpAddr>> =
                        ranked.iter().map(|id| node_ip(v, id, v6)).collect();
                    (ranked, addrs)
                };
                for (id, addr) in ranked.iter().zip(addrs) {
                    let Some(addr) = addr else { continue };
                    match features(n, id) {
                        None => crate::gossip::lookup(n, id),
                        Some(f) if f.iter().any(|x| x == FEATURE) => {
                            return Ok(Choice {
                                peer: *id,
                                addr,
                                is_node: true,
                                real_ip: rule.real_ip && f.iter().any(|x| x == FEATURE_REAL_IP),
                            });
                        }
                        Some(_) => {}
                    }
                }
                Err("no target node can take the flow".into())
            }
        }
    }

    // ------------------------------------------------------------ PROXY frames

    /// A PROXY frame from `peer`: a target's reply to one of our ingress
    /// flows, or a flow to this node as a target.
    pub fn from_peer(&self, n: &Arc<Node>, dp: &Dataplane, peer: &Bytes32, p: Vec<u8>) {
        let Some(parsed) = packet::parse(&p) else {
            return;
        };
        let now = Instant::now();
        let error = parsed.icmp == Some(IcmpKind::Error);
        // A reply's flow reversed, or the flow an ICMP error quotes, is the
        // flow as the ingress sent it.
        let started = if error {
            parsed.inner
        } else {
            Some(parsed.flow.reverse())
        };
        if let Some(started) = started {
            let hit = {
                let t = self.table.lock();
                t.ingress_reply(peer, &started)
                    .map(|(_, i)| (i.rule.clone(), i.client))
            };
            if let Some((rule, Some(client))) = hit {
                if !error {
                    self.table.lock().ct.classify(peer, &parsed, false, now);
                }
                let mut q = p;
                packet::rewrite(
                    &mut q,
                    Some((client.dst, client.dport)),
                    Some((client.src, client.sport)),
                );
                self.count(Role::Ingress, &rule, n.me, |c| {
                    c.to_client_packets += 1;
                    c.to_client_bytes += q.len() as u64;
                });
                dp.write_tun_raw(q);
                return;
            }
        }
        self.to_target(n, dp, peer, p, parsed, now);
    }

    fn to_target(
        &self,
        n: &Arc<Node>,
        dp: &Dataplane,
        peer: &Bytes32,
        mut p: Vec<u8>,
        parsed: Parsed,
        now: Instant,
    ) {
        let flow = parsed.flow;
        let mine = dp.is_mine(&flow.dst);
        let gw = if mine {
            None
        } else {
            match dp.serving_grant(&flow.dst) {
                Some(g) => Some(g),
                None => return,
            }
        };
        let v = self.table.lock().ct.classify(peer, &parsed, false, now);
        let rule = match v {
            Ct::Invalid => return,
            Ct::Tracked | Ct::RelatedError => {
                let started = match (v, parsed.inner) {
                    (Ct::RelatedError, Some(i)) => i.reverse(),
                    _ => flow,
                };
                let t = self.table.lock();
                t.info(&Key {
                    peer: *peer,
                    flow: started,
                })
                .map(|i| i.rule.clone())
                .unwrap_or_default()
            }
            Ct::New => match self.admit(n, dp, peer, &flow, mine, gw.is_some()) {
                Ok(rule) => {
                    let mut t = self.table.lock();
                    if let Err(e) =
                        t.ct.insert(peer, &parsed, false, Some(rule.clone()), gw.is_some(), now)
                    {
                        drop(t);
                        self.count(Role::Target, &rule, *peer, |c| c.refused += 1);
                        tracing::debug!(
                            "reverse proxy: refused a flow from {}: {e:?}",
                            n.name_of(peer)
                        );
                        return;
                    }
                    t.add(
                        peer,
                        &parsed,
                        FlowInfo {
                            role: Role::Target,
                            rule: rule.clone(),
                            owner: *peer,
                            client: None,
                        },
                    );
                    drop(t);
                    self.count(Role::Target, &rule, *peer, |c| c.flows += 1);
                    rule
                }
                Err((rule, why)) => {
                    self.count(Role::Target, &rule, *peer, |c| c.refused += 1);
                    tracing::debug!(
                        "reverse proxy: refused {} from {}: {why}",
                        endpoint(&flow.dst, flow.dport),
                        n.name_of(peer)
                    );
                    return;
                }
            },
        };
        if let Some(g) = gw
            && g.mapped()
        {
            let Some(ld) = webjet_core::types::map_prefix(flow.dst, &g.published, &g.lan) else {
                return;
            };
            packet::rewrite(&mut p, None, Some((ld, flow.dport)));
        }
        self.count(Role::Target, &rule, *peer, |c| {
            c.to_target_packets += 1;
            c.to_target_bytes += p.len() as u64;
        });
        dp.write_tun_raw(p);
    }

    /// May the ingress `peer` start this flow here? Its rule's name, or the
    /// reason it may not (with the rule's name when one was found).
    fn admit(
        &self,
        n: &Arc<Node>,
        _dp: &Dataplane,
        peer: &Bytes32,
        flow: &Flow,
        mine: bool,
        gateway: bool,
    ) -> Result<String, (String, String)> {
        let s = n.store.read();
        let v = s.view();
        let Some(info) = v.nodes.get(peer).filter(|x| x.valid) else {
            return Err((String::new(), "unknown ingress".into()));
        };
        let Some(me) = v.nodes.get(&n.me).map(|x| v.subject(x)) else {
            return Err((String::new(), "this node isn't in the tree".into()));
        };
        let rules = px::rules(
            &v.node_config(peer)
                .and_then(|c| c.proxy.clone())
                .unwrap_or_default(),
        )
        .unwrap_or_default();
        let rule = rules.iter().find(|r| {
            r.proto == flow.proto
                && r.target_port == flow.dport
                && match &r.target {
                    Target::Addr(a) => *a == flow.dst,
                    Target::Nodes(sels) => mine && policy::selects(sels, &me),
                }
        });
        let Some(rule) = rule else {
            return Err((String::new(), "no rule of the ingress points here".into()));
        };
        let name = rule.name.clone();
        let from_ingress = info.ips.iter().any(|i| i.contains(&flow.src));
        if !from_ingress {
            if !rule.real_ip {
                return Err((name, "the rule doesn't keep client addresses".into()));
            }
            if gateway {
                return Err((
                    name,
                    "a real client address to a LAN behind this gateway".into(),
                ));
            }
            if !n.cfg.proxy.accept_real_ip || !self.real_ip_ready.load(Ordering::Relaxed) {
                return Err((
                    name,
                    "real client addresses aren't accepted ([proxy] accept_real_ip)".into(),
                ));
            }
            if !px::plausible_client(&flow.src, &overlay_nets(v, &s.overlay_pool)) {
                return Err((name, format!("{} isn't a client address", flow.src)));
            }
        }
        let dest = if mine {
            Dest::Node(&me)
        } else {
            Dest::Addr(flow.dst)
        };
        let verdict = v
            .policy
            .evaluate(&v.subject(info), dest, flow.proto, flow.dport);
        if verdict.decision == Decision::Deny {
            return Err((name, "the policy denies the ingress".into()));
        }
        Ok(name)
    }

    // ------------------------------------------------------------ the target's replies

    /// A packet from the tun interface (or a LAN host, after the gateway's
    /// mapping) that answers a proxy flow to this node: send it back to the
    /// ingress. False when it isn't one.
    pub fn from_local(&self, n: &Arc<Node>, p: &[u8], parsed: &Parsed) -> bool {
        let error = parsed.icmp == Some(IcmpKind::Error);
        let started = if error {
            match parsed.inner {
                Some(i) => i,
                None => return false,
            }
        } else {
            parsed.flow.reverse()
        };
        let (peer, rule) = {
            let mut t = self.table.lock();
            if t.is_empty() {
                return false;
            }
            let Some(peer) = t.target_peer(&started) else {
                return false;
            };
            if !error {
                t.ct.classify(&peer, parsed, true, Instant::now());
            }
            let rule = t
                .info(&Key {
                    peer,
                    flow: started,
                })
                .map(|i| i.rule.clone())
                .unwrap_or_default();
            (peer, rule)
        };
        self.count(Role::Target, &rule, peer, |c| {
            c.to_client_packets += 1;
            c.to_client_bytes += p.len() as u64;
        });
        send(n, &peer, p);
        true
    }

    // ------------------------------------------------------------ state

    /// Rules, iptables, real-IP routing and flows after the tree or the
    /// interfaces changed (from `Dataplane::refresh`).
    pub fn refresh(&self, n: &Arc<Node>, dp: &Dataplane) {
        {
            use crate::metrics::limit;
            let mut t = self.table.lock();
            let global = limit(n, "conntrack_global") as usize;
            t.ct.global_cap = global;
            t.ct.per_peer_quota = global;
            t.ct.new_per_sec = limit(n, "conntrack_new_per_sec") as u32;
            t.ct.gateway_per_peer_quota = limit(n, "snat_ports_per_source") as usize;
            t.ct.gateway_cap = limit(n, "snat_global") as usize;
        }
        let addrs = dp.resolver.read().clone();
        *self.addrs.write() = addrs.clone();
        let wire = n
            .store
            .read()
            .view()
            .node_config(&n.me)
            .and_then(|c| c.proxy.clone())
            .unwrap_or_default();
        let mut rules = match px::rules(&wire) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("reverse proxy rules: {e}");
                Vec::new()
            }
        };
        let data = n
            .store
            .read()
            .view()
            .nodes
            .get(&n.me)
            .is_some_and(|x| x.data);
        if !data && !rules.is_empty() {
            tracing::warn!("reverse proxy rules need the data role; not listening");
            rules.clear();
        }
        let linux = cfg!(target_os = "linux");
        let supported = linux && dp.has_tun();
        // Chains and routing an earlier run left behind (a crash) go first.
        if supported && !self.cleaned.swap(true, Ordering::SeqCst) {
            crate::platform::proxy_clear(&dp.dev_name);
        }
        let states: Vec<RuleState> = rules
            .iter()
            .map(|r| self.check_rule(n, dp, r, supported, &addrs))
            .collect();
        if !rules.is_empty() && !supported {
            n.alarm(
                "proxy_unsupported",
                "warning",
                "reverse proxy rules need Linux with the tun interface; not listening".into(),
            );
        } else {
            n.clear_alarm("proxy_unsupported");
        }
        match states.iter().find(|s| !s.warnings.is_empty()) {
            Some(s) => n.alarm(
                "proxy_rule",
                "warning",
                format!("reverse proxy rule {}: {}", s.rule.name, s.warnings[0]),
            ),
            None => n.clear_alarm("proxy_rule"),
        }
        *self.rules.write() = states;
        if supported {
            let listens: Vec<(u8, u16)> = rules.iter().map(|r| (r.proto, r.listen_port)).collect();
            let want = (listens, addrs);
            let mut applied = self.applied.lock();
            if applied.as_ref() != Some(&want) {
                let l: Vec<(&str, u16)> = want
                    .0
                    .iter()
                    .map(|(p, port)| (px::proto_name(*p), *port))
                    .collect();
                if crate::platform::proxy_ingress(&dp.dev_name, &want.1, &l) {
                    if !l.is_empty() {
                        tracing::info!("reverse proxy listening on {} port(s)", l.len());
                    }
                    *applied = Some(want);
                }
            }
        }
        if n.cfg.proxy.accept_real_ip {
            if !supported {
                n.alarm(
                    "proxy_real_ip",
                    "warning",
                    "[proxy] accept_real_ip needs Linux with the tun interface".into(),
                );
            } else if !self.real_ip_ready.load(Ordering::Relaxed) {
                let pool = n.store.read().overlay_pool.clone();
                if crate::platform::proxy_real_ip(&dp.dev_name, &pool) {
                    self.real_ip_ready.store(true, Ordering::Relaxed);
                    n.clear_alarm("proxy_real_ip");
                    crate::gossip::publish_endpoint(n, true);
                } else {
                    n.alarm(
                        "proxy_real_ip",
                        "warning",
                        "could not set up routing for real client addresses".into(),
                    );
                }
            }
        }
        self.reevaluate(n);
    }

    fn check_rule(
        &self,
        n: &Arc<Node>,
        dp: &Dataplane,
        r: &Rule,
        supported: bool,
        addrs: &[IpAddr],
    ) -> RuleState {
        let mut warnings = Vec::new();
        let mut families: Vec<bool> = Vec::new();
        {
            let s = n.store.read();
            let v = s.view();
            let real_ip_of = |id: &Bytes32| -> Option<bool> {
                features(n, id).map(|f| f.iter().any(|x| x == FEATURE_REAL_IP))
            };
            match &r.target {
                Target::Addr(a) => {
                    families.push(a.is_ipv6());
                    match v.node_by_ip(a) {
                        Some(id) if id == n.me => {
                            warnings.push("the target is this node; give another node".into())
                        }
                        Some(id) => {
                            let name = n.name_of(&id);
                            match features(n, &id) {
                                // Not known yet: ask; the next refresh checks.
                                None => crate::gossip::lookup(n, &id),
                                Some(f) if !f.iter().any(|x| x == FEATURE) => warnings.push(
                                    format!("{name} runs a webjetd without reverse proxy support"),
                                ),
                                Some(_) if r.real_ip && real_ip_of(&id) == Some(false) => {
                                    warnings.push(format!(
                                        "{name} doesn't accept real client addresses ([proxy] accept_real_ip = true in its webjetd.toml); it sees this node's address"
                                    ))
                                }
                                Some(_) => {}
                            }
                        }
                        None => {
                            let behind_gateway = v.nodes.values().any(|x| {
                                x.valid && x.routes.iter().any(|g| g.published.contains(a))
                            });
                            if !behind_gateway {
                                warnings.push(format!("no node or gateway has {a}"));
                            } else if r.real_ip {
                                warnings.push(format!(
                                    "real_ip can't work for {a}: it is behind a gateway, so its replies would bypass the overlay. The gateway translates the source and the host sees the gateway's address; set real_ip = false"
                                ));
                            }
                        }
                    }
                }
                Target::Nodes(sels) => {
                    let mut any = false;
                    for v6 in [false, true] {
                        let c = candidates(n, v, sels, v6);
                        if !c.is_empty() {
                            any = true;
                            families.push(v6);
                        }
                    }
                    let all: Vec<Bytes32> = {
                        let mut a = candidates(n, v, sels, false);
                        a.extend(candidates(n, v, sels, true));
                        a.sort();
                        a.dedup();
                        a
                    };
                    if !any {
                        warnings.push("the target selectors pick no other data node".into());
                    }
                    for id in all.iter().filter(|id| features(n, id).is_none()) {
                        crate::gossip::lookup(n, id);
                    }
                    if r.real_ip {
                        let without: Vec<String> = all
                            .iter()
                            .filter(|id| real_ip_of(id) == Some(false))
                            .map(|id| n.name_of(id))
                            .collect();
                        if !without.is_empty() {
                            warnings.push(format!(
                                "not accepting real client addresses (they see this node's address): {}",
                                without.join(", ")
                            ));
                        }
                    }
                }
            }
        }
        families.sort();
        families.dedup();
        let served: Vec<&str> = families
            .iter()
            .filter(|v6| addrs.iter().any(|a| a.is_ipv6() == **v6))
            .map(|v6| if *v6 { "IPv6" } else { "IPv4" })
            .collect();
        if families
            .iter()
            .any(|v6| !addrs.iter().any(|a| a.is_ipv6() == *v6))
        {
            warnings.push(
                "the overlay pool has no range of the target's address family; those clients aren't proxied".into(),
            );
        }
        let status = if !supported {
            "not listening: needs Linux with the tun interface".to_string()
        } else if served.is_empty() {
            "listening, but no target is usable".to_string()
        } else {
            format!(
                "listening on {} port {} ({} clients)",
                px::proto_name(r.proto),
                r.listen_port,
                served.join(" and ")
            )
        };
        let _ = dp;
        RuleState {
            rule: r.clone(),
            status,
            warnings,
        }
    }

    /// Close flows whose rule is gone or whose policy no longer allows them.
    fn reevaluate(&self, n: &Arc<Node>) {
        let mine: Vec<Rule> = self.rules.read().iter().map(|r| r.rule.clone()).collect();
        let s = n.store.read();
        let v = s.view();
        let Some(me) = v.nodes.get(&n.me).map(|x| v.subject(x)) else {
            return;
        };
        let closed = self.table.lock().reevaluate(|k, info| {
            let f = &k.flow;
            match info.role {
                Role::Ingress => {
                    let Some(r) = mine.iter().find(|r| r.name == info.rule) else {
                        return false;
                    };
                    if r.proto != f.proto || r.target_port != f.dport {
                        return false;
                    }
                    let target = v.node_by_ip(&f.dst).and_then(|id| v.nodes.get(&id));
                    let still = match &r.target {
                        Target::Addr(a) => *a == f.dst,
                        Target::Nodes(sels) => {
                            target.is_some_and(|t| t.valid && policy::selects(sels, &v.subject(t)))
                        }
                    };
                    let dest_subject = target.filter(|t| t.id == k.peer).map(|t| v.subject(t));
                    let dest = match &dest_subject {
                        Some(t) => Dest::Node(t),
                        None => Dest::Addr(f.dst),
                    };
                    still
                        && v.policy.evaluate(&me, dest, f.proto, f.dport).decision
                            == Decision::Allow
                }
                Role::Target => {
                    let Some(ing) = v.nodes.get(&k.peer).filter(|x| x.valid) else {
                        return false;
                    };
                    let rules = px::rules(
                        &v.node_config(&k.peer)
                            .and_then(|c| c.proxy.clone())
                            .unwrap_or_default(),
                    )
                    .unwrap_or_default();
                    let ok = rules.iter().any(|r| {
                        r.name == info.rule && r.proto == f.proto && r.target_port == f.dport
                    });
                    let dest = if v.node_by_ip(&f.dst) == Some(n.me) {
                        Dest::Node(&me)
                    } else {
                        Dest::Addr(f.dst)
                    };
                    ok && v
                        .policy
                        .evaluate(&v.subject(ing), dest, f.proto, f.dport)
                        .decision
                        == Decision::Allow
                }
            }
        });
        if closed > 0 {
            tracing::info!("reverse proxy: closed {closed} flows after a rule or policy change");
        }
    }

    /// Remove the iptables chains and routing rule (shutdown).
    pub fn shutdown(&self, dp: &Dataplane) {
        if cfg!(target_os = "linux")
            && dp.has_tun()
            && (self.applied.lock().is_some() || self.real_ip_ready.load(Ordering::Relaxed))
        {
            crate::platform::proxy_clear(&dp.dev_name);
        }
    }

    /// This node's proxy traffic for its metric report (§12.5).
    pub fn metrics(&self) -> Vec<wp::ProxyMetrics> {
        let mut active: BTreeMap<(Role, String, Bytes32), u64> = BTreeMap::new();
        {
            let t = self.table.lock();
            let now = Instant::now();
            for (_, e, i) in t.flows() {
                if now.duration_since(e.last) < e.state.timeout() {
                    *active.entry((i.role, i.rule.clone(), i.owner)).or_default() += 1;
                }
            }
        }
        self.counters
            .lock()
            .iter()
            .map(|((role, rule, owner), c)| wp::ProxyMetrics {
                rule: Some(rule.clone()),
                ingress: *role == Role::Ingress,
                node: Some(crypto::k32(owner)),
                flows: c.flows,
                active: active
                    .get(&(*role, rule.clone(), *owner))
                    .copied()
                    .unwrap_or(0),
                to_target_packets: c.to_target_packets,
                to_target_bytes: c.to_target_bytes,
                to_client_packets: c.to_client_packets,
                to_client_bytes: c.to_client_bytes,
                refused: c.refused,
            })
            .collect()
    }
}

/// At most this many flows go into one `proxy` answer.
const FLOWS_SHOWN: usize = 2000;

/// The control channel's `proxy`: this node's rules with their status and
/// warnings, its proxy flows (as ingress and as target) and counters.
pub fn status(n: &Node) -> Value {
    let Some(dp) = n.dataplane.get() else {
        return json!({"running": false, "rules": [], "flows": [], "counters": []});
    };
    let pr = &dp.proxy;
    let rules: Vec<Value> = pr
        .rules
        .read()
        .iter()
        .map(|s| {
            let target: Vec<String> = match &s.rule.target {
                Target::Addr(a) => vec![a.to_string()],
                Target::Nodes(_) => n
                    .store
                    .read()
                    .view()
                    .node_config(&n.me)
                    .and_then(|c| c.proxy.clone())
                    .unwrap_or_default()
                    .iter()
                    .find(|w| w.name.as_deref() == Some(s.rule.name.as_str()))
                    .and_then(|w| w.target.clone())
                    .unwrap_or_default(),
            };
            json!({
                "name": s.rule.name,
                "protocol": px::proto_name(s.rule.proto),
                "listen_port": s.rule.listen_port,
                "target": target,
                "target_port": s.rule.target_port,
                "real_ip": s.rule.real_ip,
                "status": s.status,
                "warnings": s.warnings,
            })
        })
        .collect();
    let now = Instant::now();
    let (mut rows, total) = {
        let t = pr.table.lock();
        let rows: Vec<_> = t
            .flows()
            .filter(|(_, e, _)| now.duration_since(e.last) < e.state.timeout())
            .map(|(k, e, i)| (*k, e.clone(), i.clone()))
            .collect();
        (rows, t.ct.len())
    };
    rows.sort_by_key(|(_, e, _)| std::cmp::Reverse(e.last));
    let live = rows.len();
    let flows: Vec<Value> = rows
        .iter()
        .take(FLOWS_SHOWN)
        .map(|(k, e, i)| {
            let f = &k.flow;
            let (client, via) = match (i.role, i.client) {
                (Role::Ingress, Some(c)) => (
                    endpoint(&c.src, c.sport),
                    (f.src != c.src).then(|| endpoint(&f.src, f.sport)),
                ),
                _ => (endpoint(&f.src, f.sport), None),
            };
            let idle = now.duration_since(e.last);
            json!({
                "side": if i.role == Role::Ingress { "ingress" } else { "target" },
                "rule": i.rule,
                "node": n.name_of(&i.owner),
                "peer": n.name_of(&k.peer),
                "peer_id": hex::encode(k.peer),
                "proto": px::proto_name(f.proto),
                "client": client,
                "listen_port": i.client.map(|c| c.dport),
                "source": via,
                "target": endpoint(&f.dst, f.dport),
                "gateway": i.role == Role::Target && e.gateway,
                "state": crate::dataplane::state_name(e.state),
                "replied": e.saw_reply,
                "idle_s": idle.as_secs(),
                "expires_s": e.state.timeout().saturating_sub(idle).as_secs(),
            })
        })
        .collect();
    let counters: Vec<Value> = pr
        .metrics()
        .iter()
        .map(|m| {
            json!({
                "rule": m.rule,
                "side": if m.ingress { "ingress" } else { "target" },
                "node": n.name_of(&crypto::opt_k32(&m.node)),
                "flows": m.flows,
                "active": m.active,
                "to_target_packets": m.to_target_packets,
                "to_target_bytes": m.to_target_bytes,
                "to_client_packets": m.to_client_packets,
                "to_client_bytes": m.to_client_bytes,
                "refused": m.refused,
            })
        })
        .collect();
    json!({
        "running": true,
        "accept_real_ip": n.cfg.proxy.accept_real_ip,
        "real_ip_ready": pr.real_ip_ready.load(Ordering::Relaxed),
        "addresses": pr.addrs.read().iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        "rules": rules,
        "total": total,
        "live": live,
        "truncated": live > FLOWS_SHOWN,
        "flows": flows,
        "counters": counters,
    })
}
