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
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use webjet_core::conntrack::{Key, Verdict as Ct};
use webjet_core::crypto::{self, Bytes32};
use webjet_core::frames::ftype;
use webjet_core::packet::{self, Flow, Fragment, IcmpKind, Parsed, Unreach, tcpf};
use webjet_core::policy::{self, Decision, Dest, PROTO_TCP, PROTO_UDP};
use webjet_core::proxy::{self as px, FlowInfo, FragRoute, Role, Rule, Table, Target};
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

/// At most this many real-IP UDP flows get a reply route (each is an
/// `ip rule`, and the kernel walks the rules in order).
const REPLY_ROUTE_CAP: usize = 1024;

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
    /// Real-IP UDP flows (as received) whose replies have a route into the
    /// tun interface (`platform::proxy_reply_route`).
    reply_routes: Mutex<HashSet<Flow>>,
    /// Adding such a route failed once (warned).
    reply_route_failed: AtomicBool,
    /// TCP resets for segments of flows no table knows (either end
    /// restarted, or a flow was closed): rate limit.
    reset_bucket: Mutex<packet::Bucket>,
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
/// Whether the policy lets this node reach the chosen target (None: this
/// node isn't in the tree).
fn policy_allows(n: &Node, choice: &Choice, proto: u8, port: u16) -> Option<bool> {
    let s = n.store.snapshot();
    let v = s.view();
    let me = v.nodes.get(&n.me).map(|x| v.subject(x))?;
    let target = v.nodes.get(&choice.peer).map(|x| v.subject(x));
    let dest = match (&target, choice.is_node) {
        (Some(t), true) => Dest::Node(t),
        _ => Dest::Addr(choice.addr),
    };
    Some(v.policy.evaluate(&me, dest, proto, port).decision == Decision::Allow)
}

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
            reply_routes: Mutex::new(HashSet::new()),
            reply_route_failed: AtomicBool::new(false),
            reset_bucket: Mutex::new(packet::Bucket::new(100.0, 200.0)),
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

    /// A TCP reset for `p`, a segment of a flow no table here knows
    /// (`None`: not one to answer — not TCP, a reset itself, a SYN that may
    /// open a flow, over the rate limit). Either end of a proxy flow may
    /// have restarted or closed the flow (its rule, the policy or the
    /// target's real-address support changed); the reset makes both ends
    /// drop their connection, and the client opens a new one.
    fn reset_for(&self, p: &[u8], parsed: &Parsed, reply: bool) -> Option<Vec<u8>> {
        if parsed.flow.proto != PROTO_TCP
            || parsed.icmp.is_some()
            || parsed.tcp_flags & tcpf::RST != 0
            || parsed.tcp_flags & (tcpf::SYN | tcpf::ACK) == tcpf::SYN
        {
            return None;
        }
        if !self.reset_bucket.lock().take() {
            return None;
        }
        packet::tcp_reset(p, reply)
    }

    /// A packet from the tun interface to the proxy address with a foreign
    /// source on a listen port (or an ICMP error about a proxied flow): a
    /// client's packet the kernel captured (ingress).
    pub fn is_capture(&self, dp: &Dataplane, p: &Parsed) -> bool {
        let f = &p.flow;
        if !self.addrs.read().contains(&f.dst) || dp.is_mine(&f.src) {
            return false;
        }
        // A later fragment has no ports; it follows its first fragment.
        p.icmp == Some(IcmpKind::Error)
            || p.fragment == Fragment::Later
            || self
                .rules
                .read()
                .iter()
                .any(|r| r.rule.proto == f.proto && r.rule.listen_port == f.dport)
    }

    /// A later fragment from a client or a peer: where its first fragment
    /// went, or held until that first fragment comes (the path reordered
    /// them, §11.11).
    fn later_or_hold(&self, n: &Arc<Node>, from: Option<&Bytes32>, p: &[u8], parsed: &Parsed) {
        if !self.later_fragment(n, from, p, parsed) {
            self.table
                .lock()
                .hold_early(from, parsed, p, Instant::now());
        }
    }

    /// Send on the later fragments that waited for a first fragment that
    /// has now opened their route.
    fn release_early(&self, n: &Arc<Node>) {
        let ready = self.table.lock().take_ready();
        for (from, q) in ready {
            if let Some(parsed) = packet::parse(&q) {
                self.later_fragment(n, from.as_ref(), &q, &parsed);
            }
        }
    }

    /// A later fragment of a datagram (it has no ports, so no flow finds
    /// it) goes where its first fragment went, with the same addresses.
    /// `from`: the peer it came from, `None` for the tun interface. False
    /// when no first fragment went this way.
    fn later_fragment(
        &self,
        n: &Arc<Node>,
        from: Option<&Bytes32>,
        p: &[u8],
        parsed: &Parsed,
    ) -> bool {
        if parsed.fragment != Fragment::Later {
            return false;
        }
        let Some(r) = self.table.lock().frag_route(from, parsed, Instant::now()) else {
            return false;
        };
        let mut q = p.to_vec();
        if r.src.is_some() || r.dst.is_some() {
            // Addresses only: a later fragment carries no ports.
            packet::rewrite(&mut q, r.src.map(|a| (a, 0)), r.dst.map(|a| (a, 0)));
        }
        // The ingress sends to the target in frames; the target writes to
        // its tun interface what goes to the target.
        let to_target = (r.role == Role::Ingress) == r.peer.is_some();
        let bytes = q.len() as u64;
        self.count(r.role, &r.rule, r.owner, |c| {
            if to_target {
                c.to_target_packets += 1;
                c.to_target_bytes += bytes;
            } else {
                c.to_client_packets += 1;
                c.to_client_bytes += bytes;
            }
        });
        match r.peer {
            Some(peer) => send(n, &peer, &q),
            None => {
                if let Some(dp) = n.dataplane.get() {
                    dp.write_tun_raw(q);
                }
            }
        }
        true
    }

    // ------------------------------------------------------------ the ingress

    /// A client's packet (ingress): an existing flow's or a new one.
    pub fn from_client(&self, n: &Arc<Node>, dp: &Dataplane, p: Vec<u8>, parsed: Parsed) {
        if parsed.fragment == Fragment::Later {
            self.later_or_hold(n, None, &p, &parsed);
            return;
        }
        self.client_packet(n, dp, p, parsed);
        self.release_early(n);
    }

    fn client_packet(&self, n: &Arc<Node>, dp: &Dataplane, p: Vec<u8>, parsed: Parsed) {
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
            self.known_flow(n, p, &parsed, error, k, &rule, now);
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
        // Only flow starts open a flow (TCP: a SYN). Any other segment
        // belongs to a connection this node no longer tracks (it restarted,
        // or closed the flow): reset it, so the client opens a new one.
        if client.proto == PROTO_TCP && parsed.tcp_flags & (tcpf::SYN | tcpf::ACK) != tcpf::SYN {
            if let Some(r) = self.reset_for(&p, &parsed, true) {
                tracing::debug!(rule = %rule.name, "reverse proxy: reset {}: no such flow", client.src);
                dp.write_tun_raw(r);
            }
            return;
        }
        if let Err(why) = self.open_flow(n, dp, p, &parsed, client, &rule, now) {
            self.count(Role::Ingress, &rule.name, n.me, |c| c.refused += 1);
            tracing::debug!(rule = %rule.name, "reverse proxy: refused {}: {why}", client.src);
        }
    }

    /// A client's packet on a flow this ingress already proxies: rewritten
    /// to the flow's target addresses and sent on.
    #[allow(clippy::too_many_arguments)]
    fn known_flow(
        &self,
        n: &Arc<Node>,
        mut q: Vec<u8>,
        parsed: &Parsed,
        error: bool,
        k: Key,
        rule: &str,
        now: Instant,
    ) {
        packet::rewrite(
            &mut q,
            Some((k.flow.src, k.flow.sport)),
            Some((k.flow.dst, k.flow.dport)),
        );
        if !error {
            if let Some(pp) = packet::parse(&q) {
                self.table.lock().ct.classify(&k.peer, &pp, true, now);
            }
            self.table.lock().add_frag(
                None,
                parsed,
                FragRoute {
                    peer: Some(k.peer),
                    src: Some(k.flow.src),
                    dst: Some(k.flow.dst),
                    role: Role::Ingress,
                    rule: rule.to_string(),
                    owner: n.me,
                },
                now,
            );
        }
        self.count(Role::Ingress, rule, n.me, |c| {
            c.to_target_packets += 1;
            c.to_target_bytes += q.len() as u64;
        });
        send(n, &k.peer, &q);
    }

    /// A client's first packet for `rule`: pick a target, rewrite, check the
    /// policy, track the flow and send it. The error says why it was refused.
    #[allow(clippy::too_many_arguments)]
    fn open_flow(
        &self,
        n: &Arc<Node>,
        dp: &Dataplane,
        p: Vec<u8>,
        parsed: &Parsed,
        client: Flow,
        rule: &Rule,
        now: Instant,
    ) -> Result<(), String> {
        let plausible = {
            let s = n.store.snapshot();
            px::plausible_client(&client.src, &overlay_nets(s.view(), &s.overlay_pool))
        };
        if !plausible {
            return Err("not a client address".into());
        }
        let choice = Self::choose(n, dp, rule, &client.src)?;
        let src = if choice.real_ip {
            (client.src, client.sport)
        } else {
            let me = dp
                .my_ip(client.src.is_ipv6())
                .ok_or("this node has no overlay address of the client's family")?;
            let port = self
                .table
                .lock()
                .snat_port(client.proto, me, choice.addr, rule.target_port)
                .ok_or("no free source port")?;
            (me, port)
        };
        let mut q = p.clone();
        packet::rewrite(&mut q, Some(src), Some((choice.addr, rule.target_port)));
        let Some(tp) = packet::parse(&q) else {
            return Ok(());
        };
        match policy_allows(n, &choice, client.proto, rule.target_port) {
            None => return Ok(()),
            Some(false) => {
                dp.icmp(&p, Unreach::Prohibited);
                return Err("the policy denies this node the target".into());
            }
            Some(true) => {}
        }
        {
            let mut t = self.table.lock();
            let key = Key {
                peer: choice.peer,
                flow: tp.flow,
            };
            if t.info(&key).is_some() {
                return Err("the same flow is already proxied".into());
            }
            t.ct.insert(
                &choice.peer,
                &tp,
                true,
                Some(rule.name.clone()),
                !choice.real_ip,
                now,
            )
            .map_err(|e| format!("{e:?}"))?;
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
            t.add_frag(
                None,
                parsed,
                FragRoute {
                    peer: Some(choice.peer),
                    src: Some(src.0),
                    dst: Some(choice.addr),
                    role: Role::Ingress,
                    rule: rule.name.clone(),
                    owner: n.me,
                },
                now,
            );
        }
        self.count(Role::Ingress, &rule.name, n.me, |c| {
            c.flows += 1;
            c.to_target_packets += 1;
            c.to_target_bytes += q.len() as u64;
        });
        send(n, &choice.peer, &q);
        Ok(())
    }

    fn choose(
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
                    let s = n.store.snapshot();
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
        if parsed.fragment == Fragment::Later {
            self.later_or_hold(n, Some(peer), &p, &parsed);
            return;
        }
        self.peer_packet(n, dp, peer, p, parsed);
        self.release_early(n);
    }

    fn peer_packet(
        &self,
        n: &Arc<Node>,
        dp: &Dataplane,
        peer: &Bytes32,
        p: Vec<u8>,
        parsed: Parsed,
    ) {
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
                if !error {
                    self.table.lock().add_frag(
                        Some(peer),
                        &parsed,
                        FragRoute {
                            peer: None,
                            src: Some(client.dst),
                            dst: Some(client.src),
                            role: Role::Ingress,
                            rule: rule.clone(),
                            owner: n.me,
                        },
                        now,
                    );
                }
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
        let v = self.table.lock().ct.classify(peer, &parsed, false, now);
        if v == Ct::Invalid {
            // A TCP segment of a connection we don't track: this node
            // restarted or closed the flow, or the peer did (a reply to an
            // ingress that forgot it). Reset it at the peer's end.
            if let Some(r) = self.reset_for(&p, &parsed, true) {
                tracing::debug!(
                    "reverse proxy: reset {} from {}: no such flow",
                    endpoint(&flow.dst, flow.dport),
                    n.name_of(peer)
                );
                send(n, peer, &r);
            }
            return;
        }
        let mine = dp.is_mine(&flow.dst);
        let gw = if mine {
            None
        } else {
            match dp.serving_grant(&flow.dst) {
                Some(g) => Some(g),
                None => return,
            }
        };
        let mut reply_route = false;
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
                Ok((rule, real)) => {
                    reply_route = real && mine && flow.proto == PROTO_UDP;
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
        let mut mapped = None;
        if let Some(g) = gw
            && g.mapped()
        {
            let Some(ld) = webjet_core::types::map_prefix(flow.dst, &g.published, &g.lan) else {
                return;
            };
            packet::rewrite(&mut p, None, Some((ld, flow.dport)));
            mapped = Some(ld);
        }
        if v != Ct::RelatedError {
            self.table.lock().add_frag(
                Some(peer),
                &parsed,
                FragRoute {
                    peer: None,
                    src: None,
                    dst: mapped,
                    role: Role::Target,
                    rule: rule.clone(),
                    owner: *peer,
                },
                now,
            );
        }
        self.count(Role::Target, &rule, *peer, |c| {
            c.to_target_packets += 1;
            c.to_target_bytes += p.len() as u64;
        });
        if reply_route && self.claim_reply_route(&flow) {
            // The server's first reply must find the route: write the
            // packet once it is in (the `ip` command blocks).
            let n = n.clone();
            let job = move || {
                if let Some(dp) = n.dataplane.get() {
                    dp.proxy.add_reply_route(&flow);
                    dp.write_tun_raw(p);
                }
            };
            match tokio::runtime::Handle::try_current() {
                Ok(h) => drop(h.spawn_blocking(job)),
                Err(_) => job(),
            }
            return;
        }
        dp.write_tun_raw(p);
    }

    /// Take a reply route slot for a new real-IP UDP flow; false when it
    /// has one already or too many flows do.
    fn claim_reply_route(&self, f: &Flow) -> bool {
        let mut r = self.reply_routes.lock();
        if r.len() >= REPLY_ROUTE_CAP {
            tracing::debug!(
                "reverse proxy: no reply route for {}: too many flows",
                f.src
            );
            return false;
        }
        r.insert(*f)
    }

    /// Add the reply route of a claimed flow (blocking).
    fn add_reply_route(&self, f: &Flow) {
        if crate::platform::proxy_reply_route(f, true) {
            return;
        }
        self.reply_routes.lock().remove(f);
        if !self.reply_route_failed.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "reverse proxy: could not route UDP replies to {} into the tun interface \
                 (ip rule with ports needs Linux 4.17); a server on a wildcard address \
                 will answer it from another address",
                f.src
            );
        }
    }

    /// Remove the reply routes of flows that are gone (blocking).
    fn sweep_reply_routes(&self) {
        let live: HashSet<Flow> = self
            .table
            .lock()
            .flows()
            .filter(|(_, _, i)| i.role == Role::Target)
            .map(|(k, _, _)| k.flow)
            .collect();
        let gone: Vec<Flow> = {
            let mut r = self.reply_routes.lock();
            let gone = r.iter().filter(|f| !live.contains(f)).copied().collect();
            r.retain(|f| live.contains(f));
            gone
        };
        for f in gone {
            crate::platform::proxy_reply_route(&f, false);
        }
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
    ) -> Result<(String, bool), (String, String)> {
        let s = n.store.snapshot();
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
        Ok((name, !from_ingress))
    }

    // ------------------------------------------------------------ the target's replies

    /// A packet from the tun interface (or a LAN host, after the gateway's
    /// mapping) that answers a proxy flow to this node: send it back to the
    /// ingress. False when it isn't one.
    pub fn from_local(&self, n: &Arc<Node>, p: &[u8], parsed: &Parsed) -> bool {
        if parsed.fragment == Fragment::Later {
            return self.later_fragment(n, None, p, parsed);
        }
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
            let now = Instant::now();
            if !error {
                t.ct.classify(&peer, parsed, true, now);
            }
            let rule = t
                .info(&Key {
                    peer,
                    flow: started,
                })
                .map(|i| i.rule.clone())
                .unwrap_or_default();
            if !error {
                t.add_frag(
                    None,
                    parsed,
                    FragRoute {
                        peer: Some(peer),
                        src: None,
                        dst: None,
                        role: Role::Target,
                        rule: rule.clone(),
                        owner: peer,
                    },
                    now,
                );
            }
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
            use crate::metrics::{limit_u32, limit_usize};
            // Read before locking the table: limits take the store lock.
            let global = limit_usize(n, "conntrack_global");
            let new_per_sec = limit_u32(n, "conntrack_new_per_sec");
            let gw_per_source = limit_usize(n, "snat_ports_per_source");
            let gw_cap = limit_usize(n, "snat_global");
            let mut t = self.table.lock();
            t.ct.global_cap = global;
            t.ct.per_peer_quota = global;
            t.ct.new_per_sec = new_per_sec;
            t.ct.gateway_per_peer_quota = gw_per_source;
            t.ct.gateway_cap = gw_cap;
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
            .map(|r| Self::check_rule(n, dp, r, supported, &addrs))
            .collect();
        if !rules.is_empty() && !supported {
            n.alarm(
                "proxy_unsupported",
                "warning",
                "reverse proxy rules need Linux with the tun interface; not listening",
            );
        } else {
            n.clear_alarm("proxy_unsupported");
        }
        match states.iter().find(|s| !s.warnings.is_empty()) {
            Some(s) => n.alarm(
                "proxy_rule",
                "warning",
                &format!("reverse proxy rule {}: {}", s.rule.name, s.warnings[0]),
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
                    "[proxy] accept_real_ip needs Linux with the tun interface",
                );
            } else if !self.real_ip_ready.load(Ordering::Relaxed) {
                let pool = n.store.snapshot().overlay_pool.clone();
                if crate::platform::proxy_real_ip(&dp.dev_name, &pool) {
                    self.real_ip_ready.store(true, Ordering::Relaxed);
                    n.clear_alarm("proxy_real_ip");
                    crate::gossip::publish_endpoint(n, true);
                } else {
                    n.alarm(
                        "proxy_real_ip",
                        "warning",
                        "could not set up routing for real client addresses",
                    );
                }
            }
        }
        self.reevaluate(n);
        self.sweep_reply_routes();
    }

    fn check_rule(
        n: &Arc<Node>,
        dp: &Dataplane,
        r: &Rule,
        supported: bool,
        addrs: &[IpAddr],
    ) -> RuleState {
        let mut warnings = Vec::new();
        let mut families: Vec<bool> = Vec::new();
        {
            let s = n.store.snapshot();
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

    /// Close flows whose rule is gone, whose policy no longer allows them,
    /// or whose source no longer matches what their target accepts: a
    /// target that turned `accept_real_ip` on (or off, or restarted
    /// without it) gets new flows with the source it takes now. The
    /// client's next datagram opens a new flow; its next TCP segment gets
    /// a reset ([`Proxy::reset_for`]), and it reconnects.
    fn reevaluate(&self, n: &Arc<Node>) {
        let mine: Vec<Rule> = self.rules.read().iter().map(|r| r.rule.clone()).collect();
        // Per target node: does it take real client addresses (`None`: its
        // record isn't known, keep its flows as they are).
        let takes_real: BTreeMap<Bytes32, bool> = n
            .records
            .lock()
            .endpoints
            .iter()
            .map(|(id, (r, _))| {
                let real = r
                    .features
                    .as_ref()
                    .is_some_and(|f| f.iter().any(|x| x == FEATURE_REAL_IP));
                (*id, real)
            })
            .collect();
        let s = n.store.snapshot();
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
                    // The source the flow has (client's, or translated)
                    // and the one a new flow would get (as `choose`).
                    let real = info.client.is_some_and(|c| c.src == f.src);
                    let is_node = target.is_some_and(|t| t.id == k.peer);
                    let source_ok = match takes_real.get(&k.peer) {
                        Some(takes) => real == (r.real_ip && is_node && *takes),
                        None => true,
                    };
                    still
                        && source_ok
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
            tracing::info!(
                "reverse proxy: closed {closed} flows after a rule, policy or target change"
            );
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
        self.reply_routes.lock().clear();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testnode::{self, Cluster};
    use tokio::sync::mpsc;
    use webjet_core::crypto::KeyPair;
    use webjet_core::testutil::packets::tcp4;

    const CLIENT: [u8; 4] = [203, 0, 113, 5];
    const ING: [u8; 4] = [10, 7, 0, 2];
    const WEB: [u8; 4] = [10, 7, 0, 3];

    fn allow(id: &str, src: &str, dst: &str, ports: &str) -> wp::Rule {
        wp::Rule {
            id: Some(id.into()),
            action: wp::Action::Allow,
            src: Some(vec![src.into()]),
            dst: Some(vec![dst.into()]),
            ports: Some(vec![ports.into()]),
        }
    }

    fn policy(rules: Vec<wp::Rule>) -> wp::Policy {
        wp::Policy {
            default_action: wp::Action::Deny,
            rules: Some(rules),
            ..Default::default()
        }
    }

    /// tcp 8080 on the ingress → port 80 on nodes tagged `tag:web`.
    fn web_rule() -> wp::ProxyRule {
        wp::ProxyRule {
            name: Some("web".into()),
            protocol: PROTO_TCP,
            listen_port: 8080,
            target: Some(vec!["tag:web".into()]),
            target_port: 80,
            real_ip: false,
        }
    }

    struct T {
        c: Cluster,
        ing: (Bytes32, KeyPair),
        web: (Bytes32, KeyPair),
    }

    fn net() -> T {
        let mut c = Cluster::new();
        let ing = c.data_node("ing", "10.7.0.2", &["tag:ingress"]);
        let web = c.data_node("web", "10.7.0.3", &["tag:web"]);
        c.set_policy(policy(vec![allow(
            "in",
            "tag:ingress",
            "tag:web",
            "tcp:80",
        )]))
        .unwrap();
        c.set_node_config(wp::NodeConfig {
            node_id: Some(crypto::k32(&ing.0)),
            proxy: Some(vec![web_rule()]),
            ..Default::default()
        })
        .unwrap();
        T { c, ing, web }
    }

    /// `node`'s agent, with `other`'s EndpointRecord features known.
    fn agent(
        t: &mut T,
        me: &(Bytes32, KeyPair),
        other: Bytes32,
        features: &[&str],
    ) -> (
        Arc<Node>,
        Arc<Dataplane>,
        mpsc::UnboundedReceiver<Vec<u8>>,
        tempfile::TempDir,
    ) {
        let (n, dir) = testnode::node(&mut t.c, me.0, me.1.clone());
        let r = wp::EndpointRecord {
            node_id: Some(crypto::k32(&other)),
            features: Some(features.iter().map(|f| f.to_string()).collect()),
            ..Default::default()
        };
        n.records.lock().endpoints.insert(other, (r, Vec::new()));
        let (dp, rx) = Dataplane::for_test(&n);
        (n, dp, rx, dir)
    }

    fn proxy_addr(dp: &Dataplane) -> [u8; 4] {
        match dp.proxy.addrs.read().first() {
            Some(IpAddr::V4(a)) => a.octets(),
            _ => panic!("no IPv4 proxy address"),
        }
    }

    fn drain(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        while let Ok(p) = rx.try_recv() {
            v.push(p);
        }
        v
    }

    fn counters(p: &Proxy) -> Counters {
        p.counters
            .lock()
            .values()
            .next()
            .cloned()
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn ingress_proxies_a_client_flow_and_its_replies() {
        let mut t = net();
        let web = t.web.0;
        let ing = t.ing.clone();
        let (n, dp, mut tun, _d) = agent(&mut t, &ing, web, &[FEATURE]);
        let pa = proxy_addr(&dp);
        // A client's SYN the kernel captured.
        let syn = tcp4(CLIENT, pa, 5555, 8080, tcpf::SYN);
        assert!(dp.proxy.is_capture(&dp, &packet::parse(&syn).unwrap()));
        dp.outbound(syn);
        assert_eq!(
            n.metrics.tun_rx.load(Ordering::Relaxed),
            0,
            "kept out of overlay counters"
        );
        let q = n.e2e.queued_for_test(&web);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, ftype::PROXY);
        let sent = packet::parse(&q[0].1).unwrap();
        // Translated: from this node (a source port of its own) to web:80.
        assert_eq!(sent.flow.src, IpAddr::from(ING));
        assert_eq!(sent.flow.dst, IpAddr::from(WEB));
        assert_eq!(sent.flow.dport, 80);
        let sport = sent.flow.sport;

        // The target's reply goes back to the client from the proxy address.
        let reply = tcp4(WEB, ING, 80, sport, tcpf::SYN | tcpf::ACK);
        dp.proxy.from_peer(&n, &dp, &web, reply);
        let out = drain(&mut tun);
        assert_eq!(out.len(), 1);
        let back = packet::parse(&out[0]).unwrap();
        assert_eq!((back.flow.src, back.flow.sport), (IpAddr::from(pa), 8080));
        assert_eq!(
            (back.flow.dst, back.flow.dport),
            (IpAddr::from(CLIENT), 5555)
        );

        // The client's next packet follows the flow.
        dp.outbound(tcp4(CLIENT, pa, 5555, 8080, tcpf::ACK));
        assert_eq!(n.e2e.queued_for_test(&web).len(), 2);

        let c = counters(&dp.proxy);
        assert_eq!(
            (c.flows, c.to_target_packets, c.to_client_packets, c.refused),
            (1, 2, 1, 0)
        );
        let m = dp.proxy.metrics();
        assert_eq!(m.len(), 1);
        assert!(m[0].ingress);
        assert_eq!(m[0].active, 1);

        let s = status(&n);
        assert_eq!(s["rules"][0]["name"], "web");
        assert_eq!(s["rules"][0]["target"][0], "tag:web");
        assert!(
            s["rules"][0]["status"]
                .as_str()
                .unwrap()
                .starts_with("not listening")
        );
        assert_eq!(s["flows"][0]["side"], "ingress");
        assert_eq!(s["flows"][0]["client"], "203.0.113.5:5555");
        assert_eq!(s["flows"][0]["target"], "10.7.0.3:80");
        assert_eq!(s["counters"][0]["flows"], 1);
        assert!(n.alarms.lock().contains_key("proxy_unsupported"));
    }

    #[tokio::test]
    async fn ingress_refusals() {
        let mut t = net();
        let web = t.web.0;
        let ing = t.ing.clone();
        // The target runs a webjetd without proxy support.
        let (n, dp, mut tun, _d) = agent(&mut t, &ing, web, &[]);
        let pa = proxy_addr(&dp);
        dp.outbound(tcp4(CLIENT, pa, 5555, 8080, tcpf::SYN));
        assert!(n.e2e.queued_for_test(&web).is_empty());
        assert_eq!(counters(&dp.proxy).refused, 1);
        // Only a SYN starts a flow; another segment gets a reset.
        dp.outbound(tcp4(CLIENT, pa, 5556, 8080, tcpf::ACK));
        assert_eq!(counters(&dp.proxy).refused, 1);
        let rst: Vec<_> = drain(&mut tun)
            .iter()
            .map(|p| packet::parse(p).unwrap())
            .filter(|p| p.icmp.is_none())
            .collect();
        assert_eq!(rst.len(), 1);
        assert_eq!(rst[0].tcp_flags, tcpf::RST);
        assert_eq!(
            (rst[0].flow.dst, rst[0].flow.dport),
            (IpAddr::from(CLIENT), 5556)
        );
        // A source address that only an overlay node could have.
        let spoofed = tcp4([10, 7, 0, 9], pa, 5557, 8080, tcpf::SYN);
        assert!(dp.proxy.is_capture(&dp, &packet::parse(&spoofed).unwrap()));
        dp.outbound(spoofed);
        assert_eq!(counters(&dp.proxy).refused, 2);
        // Not a listen port: not a capture at all.
        let other = tcp4(CLIENT, pa, 5558, 9090, tcpf::SYN);
        assert!(!dp.proxy.is_capture(&dp, &packet::parse(&other).unwrap()));
        assert!(
            drain(&mut tun)
                .iter()
                .all(|p| packet::parse(p).unwrap().icmp.is_some())
        );
    }

    #[tokio::test]
    async fn ingress_policy_denies_the_target() {
        let mut t = net();
        t.c.set_policy(policy(vec![])).unwrap();
        let web = t.web.0;
        let ing = t.ing.clone();
        let (n, dp, mut tun, _d) = agent(&mut t, &ing, web, &[FEATURE]);
        let pa = proxy_addr(&dp);
        dp.outbound(tcp4(CLIENT, pa, 5555, 8080, tcpf::SYN));
        assert!(n.e2e.queued_for_test(&web).is_empty());
        let out = drain(&mut tun);
        assert_eq!(out.len(), 1);
        assert_eq!(packet::parse(&out[0]).unwrap().icmp, Some(IcmpKind::Error));
        assert_eq!(counters(&dp.proxy).refused, 1);
    }

    #[tokio::test]
    async fn target_admits_the_ingress_rule_and_answers() {
        let mut t = net();
        let ing = t.ing.0;
        let web = t.web.clone();
        let (n, dp, mut tun, _d) = agent(&mut t, &web, ing, &[FEATURE]);
        let syn = tcp4(ING, WEB, 40000, 80, tcpf::SYN);
        dp.proxy.from_peer(&n, &dp, &ing, syn.clone());
        assert_eq!(drain(&mut tun), vec![syn], "written to the tun interface");
        // The local reply goes back to the ingress in a PROXY frame.
        let reply = tcp4(WEB, ING, 80, 40000, tcpf::SYN | tcpf::ACK);
        let parsed = packet::parse(&reply).unwrap();
        assert!(dp.proxy.from_local(&n, &reply, &parsed));
        let q = n.e2e.queued_for_test(&ing);
        assert_eq!(q, vec![(ftype::PROXY, reply)]);
        // Unrelated local traffic isn't proxy traffic.
        let other = tcp4(WEB, ING, 22, 40000, tcpf::SYN | tcpf::ACK);
        assert!(
            !dp.proxy
                .from_local(&n, &other, &packet::parse(&other).unwrap())
        );
        let c = counters(&dp.proxy);
        assert_eq!(
            (c.flows, c.to_target_packets, c.to_client_packets),
            (1, 1, 1)
        );
        assert_eq!(status(&n)["flows"][0]["side"], "target");

        // A policy change that drops the ingress closes the flow.
        t.c.set_policy(policy(vec![])).unwrap();
        testnode::sync(&mut t.c, &n);
        dp.refresh();
        assert_eq!(dp.proxy.table.lock().ct.len(), 0);
    }

    #[tokio::test]
    async fn target_refusals() {
        let mut t = net();
        let ing = t.ing.0;
        let web = t.web.clone();
        let (n, dp, mut tun, _d) = agent(&mut t, &web, ing, &[FEATURE]);
        // No rule of the ingress has target port 22.
        dp.proxy
            .from_peer(&n, &dp, &ing, tcp4(ING, WEB, 40000, 22, tcpf::SYN));
        // A client's own address, but the rule doesn't keep them.
        dp.proxy
            .from_peer(&n, &dp, &ing, tcp4(CLIENT, WEB, 40001, 80, tcpf::SYN));
        // Not addressed to this node or a LAN it serves.
        dp.proxy.from_peer(
            &n,
            &dp,
            &ing,
            tcp4(ING, [10, 7, 0, 99], 40002, 80, tcpf::SYN),
        );
        // From a node that isn't in the tree.
        dp.proxy
            .from_peer(&n, &dp, &[9; 32], tcp4(ING, WEB, 40003, 80, tcpf::SYN));
        assert!(drain(&mut tun).is_empty());
        let refused: u64 = dp.proxy.counters.lock().values().map(|c| c.refused).sum();
        assert_eq!(refused, 3);
        assert_eq!(dp.proxy.table.lock().ct.len(), 0);
    }

    #[tokio::test]
    async fn rule_warnings() {
        let mut t = net();
        // The selector picks no node.
        t.c.set_node_config(wp::NodeConfig {
            node_id: Some(crypto::k32(&t.ing.0)),
            proxy: Some(vec![wp::ProxyRule {
                target: Some(vec!["tag:nobody".into()]),
                ..web_rule()
            }]),
            ..Default::default()
        })
        .unwrap();
        let web = t.web.0;
        let ing = t.ing.clone();
        let (n, _dp, _tun, _d) = agent(&mut t, &ing, web, &[FEATURE]);
        let s = status(&n);
        let w = s["rules"][0]["warnings"][0].as_str().unwrap();
        assert!(w.contains("pick no other data node"), "{w}");
        assert!(n.alarms.lock().contains_key("proxy_rule"));

        // A target address behind no node or gateway.
        t.c.set_node_config(wp::NodeConfig {
            node_id: Some(crypto::k32(&t.ing.0)),
            proxy: Some(vec![wp::ProxyRule {
                target: Some(vec!["192.0.2.80".into()]),
                ..web_rule()
            }]),
            ..Default::default()
        })
        .unwrap();
        testnode::sync(&mut t.c, &n);
        n.dataplane.get().unwrap().refresh();
        let s = status(&n);
        let w = s["rules"][0]["warnings"][0].as_str().unwrap();
        assert!(w.contains("no node or gateway has 192.0.2.80"), "{w}");
    }

    fn set_features(n: &Node, id: Bytes32, features: &[&str]) {
        let r = wp::EndpointRecord {
            node_id: Some(crypto::k32(&id)),
            features: Some(features.iter().map(|f| f.to_string()).collect()),
            ..Default::default()
        };
        n.records.lock().endpoints.insert(id, (r, Vec::new()));
    }

    /// The last frame queued for `peer`, parsed.
    fn last_sent(n: &Node, peer: &Bytes32) -> Parsed {
        let q = n.e2e.queued_for_test(peer);
        packet::parse(&q.last().expect("a frame").1).unwrap()
    }

    /// A target that turns `accept_real_ip` on (restarting its agent) gets
    /// the clients' addresses on flows that were already running: the
    /// ingress closes their translated flows, the client's next datagram
    /// opens a new flow, its next TCP segment gets a reset. Turned off
    /// again, the flows go back to translated sources.
    #[tokio::test]
    async fn ingress_closes_flows_when_the_target_changes_real_ip() {
        use webjet_core::testutil::packets::udp4;
        let mut t = net();
        t.c.set_policy(policy(vec![
            allow("web", "tag:ingress", "tag:web", "tcp:80"),
            allow("game", "tag:ingress", "tag:web", "udp:27015"),
        ]))
        .unwrap();
        t.c.set_node_config(wp::NodeConfig {
            node_id: Some(crypto::k32(&t.ing.0)),
            proxy: Some(vec![
                wp::ProxyRule {
                    real_ip: true,
                    ..web_rule()
                },
                wp::ProxyRule {
                    name: Some("game".into()),
                    protocol: PROTO_UDP,
                    listen_port: 27015,
                    target_port: 27015,
                    real_ip: true,
                    ..web_rule()
                },
            ]),
            ..Default::default()
        })
        .unwrap();
        let web = t.web.0;
        let ing = t.ing.clone();
        let (n, dp, mut tun, _d) = agent(&mut t, &ing, web, &[FEATURE]);
        let pa = proxy_addr(&dp);
        let datagram = |b: &[u8]| udp4(CLIENT, pa, 5555, 27015, b);

        // The target doesn't take real addresses: both flows translated.
        dp.outbound(datagram(b"1"));
        assert_eq!(last_sent(&n, &web).flow.src, IpAddr::from(ING));
        dp.outbound(tcp4(CLIENT, pa, 6666, 8080, tcpf::SYN));
        assert_eq!(last_sent(&n, &web).flow.src, IpAddr::from(ING));
        dp.proxy.refresh(&n, &dp);
        assert_eq!(dp.proxy.table.lock().ct.len(), 2, "nothing changed");

        // It restarts with accept_real_ip: its record says so.
        set_features(&n, web, &[FEATURE, FEATURE_REAL_IP]);
        dp.proxy.refresh(&n, &dp);
        assert_eq!(dp.proxy.table.lock().ct.len(), 0, "both flows closed");
        dp.outbound(datagram(b"2"));
        let f = last_sent(&n, &web).flow;
        assert_eq!((f.src, f.sport), (IpAddr::from(CLIENT), 5555));
        // The TCP connection is gone: the client gets a reset from the
        // proxy address (the kernel un-DNATs it), the target nothing.
        let sent = n.e2e.queued_for_test(&web).len();
        dp.outbound(tcp4(CLIENT, pa, 6666, 8080, tcpf::ACK));
        assert_eq!(n.e2e.queued_for_test(&web).len(), sent);
        let out = drain(&mut tun);
        assert_eq!(out.len(), 1);
        let rst = packet::parse(&out[0]).unwrap();
        assert_eq!(rst.tcp_flags & tcpf::RST, tcpf::RST);
        assert_eq!((rst.flow.src, rst.flow.sport), (IpAddr::from(pa), 8080));
        assert_eq!((rst.flow.dst, rst.flow.dport), (IpAddr::from(CLIENT), 6666));
        // It reconnects with the real address.
        dp.outbound(tcp4(CLIENT, pa, 6667, 8080, tcpf::SYN));
        assert_eq!(last_sent(&n, &web).flow.src, IpAddr::from(CLIENT));
        dp.proxy.refresh(&n, &dp);
        assert_eq!(dp.proxy.table.lock().ct.len(), 2, "the new flows stay");

        // Turned off again: back to translated sources.
        set_features(&n, web, &[FEATURE]);
        dp.proxy.refresh(&n, &dp);
        assert_eq!(dp.proxy.table.lock().ct.len(), 0);
        dp.outbound(datagram(b"3"));
        assert_eq!(last_sent(&n, &web).flow.src, IpAddr::from(ING));

        // A target whose record isn't known keeps its flows.
        n.records.lock().endpoints.remove(&web);
        dp.proxy.refresh(&n, &dp);
        assert_eq!(dp.proxy.table.lock().ct.len(), 1);
    }

    /// A TCP segment of a flow the target doesn't track (it restarted, or
    /// the ingress kept a flow it closed) gets a reset back to the ingress,
    /// which passes it to the client.
    #[tokio::test]
    async fn target_resets_segments_of_unknown_flows() {
        let mut t = net();
        let ing = t.ing.0;
        let web = t.web.clone();
        let (n, dp, mut tun, _d) = agent(&mut t, &web, ing, &[FEATURE]);
        dp.proxy
            .from_peer(&n, &dp, &ing, tcp4(ING, WEB, 40000, 80, tcpf::ACK));
        assert!(drain(&mut tun).is_empty(), "not written to the tun");
        let rst = last_sent(&n, &ing);
        assert_eq!(rst.tcp_flags, tcpf::RST);
        assert_eq!((rst.flow.src, rst.flow.sport), (IpAddr::from(WEB), 80));
        assert_eq!((rst.flow.dst, rst.flow.dport), (IpAddr::from(ING), 40000));
        // Resets aren't answered.
        dp.proxy
            .from_peer(&n, &dp, &ing, tcp4(ING, WEB, 40000, 80, tcpf::RST));
        assert_eq!(n.e2e.queued_for_test(&ing).len(), 1);
        assert_eq!(dp.proxy.table.lock().ct.len(), 0);
    }

    #[test]
    fn helpers() {
        assert_eq!(endpoint(&"10.0.0.1".parse().unwrap(), 80), "10.0.0.1:80");
        assert_eq!(endpoint(&"fd00::1".parse().unwrap(), 80), "[fd00::1]:80");
    }

    /// Split an IPv4 packet into two fragments, the first carrying `at`
    /// bytes (a multiple of 8) of the L4 header and data.
    fn frag4(p: &[u8], id: u16, at: usize) -> (Vec<u8>, Vec<u8>) {
        let ihl = usize::from(p[0] & 0x0f) * 4;
        let mut a = p[..ihl + at].to_vec();
        let mut b = p[..ihl].to_vec();
        b.extend_from_slice(&p[ihl + at..]);
        for (f, flags) in [(&mut a, 0x2000u16), (&mut b, (at / 8) as u16)] {
            let len = f.len() as u16;
            f[2..4].copy_from_slice(&len.to_be_bytes());
            f[4..6].copy_from_slice(&id.to_be_bytes());
            f[6..8].copy_from_slice(&flags.to_be_bytes());
            packet::fix_checksums(f);
        }
        (a, b)
    }

    /// Put two IPv4 fragments back together; the UDP checksum must hold.
    fn reassemble(a: &[u8], b: &[u8]) -> Vec<u8> {
        let ihl = usize::from(a[0] & 0x0f) * 4;
        assert_eq!(
            &a[12..20],
            &b[12..20],
            "both fragments have the same addresses"
        );
        let mut p = a.to_vec();
        p.extend_from_slice(&b[ihl..]);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p[6] = 0;
        p[7] = 0;
        let mut fixed = p.clone();
        packet::fix_checksums(&mut fixed);
        assert_eq!(p[ihl + 6..ihl + 8], fixed[ihl + 6..ihl + 8], "UDP checksum");
        p
    }

    /// udp 27015 on the ingress → udp 27015 on web (a game server).
    fn game_net() -> T {
        let mut t = net();
        t.c.set_policy(policy(vec![allow(
            "in",
            "tag:ingress",
            "tag:web",
            "udp:27015",
        )]))
        .unwrap();
        t.c.set_node_config(wp::NodeConfig {
            node_id: Some(crypto::k32(&t.ing.0)),
            proxy: Some(vec![wp::ProxyRule {
                name: Some("game".into()),
                protocol: webjet_core::policy::PROTO_UDP,
                listen_port: 27015,
                target_port: 27015,
                ..web_rule()
            }]),
            ..Default::default()
        })
        .unwrap();
        t
    }

    #[tokio::test]
    async fn ingress_sends_fragments_after_their_first() {
        use webjet_core::testutil::packets::udp4;
        let mut t = game_net();
        let web = t.web.0;
        let ing = t.ing.clone();
        let (n, dp, mut tun, _d) = agent(&mut t, &ing, web, &[FEATURE]);
        let pa = proxy_addr(&dp);
        // A client's datagram bigger than the tun MTU arrives in two pieces.
        let big = udp4(CLIENT, pa, 5555, 27015, &[7u8; 1400]);
        let (a, b) = frag4(&big, 0x1234, 1200);
        assert!(dp.proxy.is_capture(&dp, &packet::parse(&b).unwrap()));
        dp.outbound(a);
        dp.outbound(b);
        let q = n.e2e.queued_for_test(&web);
        assert_eq!(q.len(), 2, "both fragments go to the target");
        let whole = reassemble(&q[0].1, &q[1].1);
        let f = packet::parse(&whole).unwrap().flow;
        assert_eq!(
            (f.src, f.dst, f.dport),
            (IpAddr::from(ING), IpAddr::from(WEB), 27015)
        );
        assert_eq!(&whole[28..], &[7u8; 1400][..]);

        // The target's big reply comes back in pieces too.
        let reply = udp4(WEB, ING, 27015, f.sport, &[9u8; 1400]);
        let (a, b) = frag4(&reply, 0x4321, 1200);
        dp.proxy.from_peer(&n, &dp, &web, a);
        dp.proxy.from_peer(&n, &dp, &web, b);
        let out = drain(&mut tun);
        assert_eq!(out.len(), 2, "both fragments go to the client");
        let back = reassemble(&out[0], &out[1]);
        let f = packet::parse(&back).unwrap().flow;
        assert_eq!(
            (f.src, f.sport, f.dst, f.dport),
            (IpAddr::from(pa), 27015, IpAddr::from(CLIENT), 5555)
        );
        let c = counters(&dp.proxy);
        assert_eq!((c.to_target_packets, c.to_client_packets), (2, 2));

        // A later fragment of a datagram whose first one never came is dropped.
        let (_, stray) = frag4(&udp4(CLIENT, pa, 5555, 27015, &[1u8; 1400]), 0x9999, 1200);
        dp.outbound(stray);
        assert_eq!(n.e2e.queued_for_test(&web).len(), 2);
    }

    #[tokio::test]
    async fn target_takes_fragments_and_answers_in_fragments() {
        use webjet_core::testutil::packets::udp4;
        let mut t = game_net();
        let ing = t.ing.0;
        let web = t.web.clone();
        let (n, dp, mut tun, _d) = agent(&mut t, &web, ing, &[FEATURE]);
        let req = udp4(ING, WEB, 61000, 27015, &[3u8; 1400]);
        let (a, b) = frag4(&req, 0x0101, 1200);
        dp.proxy.from_peer(&n, &dp, &ing, a.clone());
        dp.proxy.from_peer(&n, &dp, &ing, b.clone());
        assert_eq!(drain(&mut tun), vec![a, b], "written to the tun interface");
        // The server's reply, fragmented by the local stack.
        let reply = udp4(WEB, ING, 27015, 61000, &[4u8; 1400]);
        let (a, b) = frag4(&reply, 0x0202, 1200);
        for f in [&a, &b] {
            assert!(dp.proxy.from_local(&n, f, &packet::parse(f).unwrap()));
        }
        assert_eq!(
            n.e2e.queued_for_test(&ing),
            vec![(ftype::PROXY, a), (ftype::PROXY, b)]
        );
        // Another datagram's later fragment isn't proxy traffic.
        let (_, other) = frag4(&udp4(WEB, ING, 53, 61000, &[5u8; 1400]), 0x0303, 1200);
        assert!(
            !dp.proxy
                .from_local(&n, &other, &packet::parse(&other).unwrap())
        );

        // A KCP hop that doesn't retransmit (§17.5.1), like the internet,
        // may deliver a later fragment first: it waits for its first.
        let req = udp4(ING, WEB, 61000, 27015, &[6u8; 1400]);
        let (a, b) = frag4(&req, 0x0404, 1200);
        dp.proxy.from_peer(&n, &dp, &ing, b.clone());
        assert!(drain(&mut tun).is_empty(), "held for its first fragment");
        dp.proxy.from_peer(&n, &dp, &ing, a.clone());
        assert_eq!(drain(&mut tun), vec![a, b], "both go once the first came");
    }
}
