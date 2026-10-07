//! Reverse proxy ports (§11.11): rules from a node's configuration, target
//! selection, and the proxy flow table. The table reuses connection
//! tracking ([`Conntrack`]) but is a separate instance from the overlay
//! traffic's, so proxy flows have their own limits, listings and metrics.
//!
//! A rule makes a Linux data node (the ingress) take TCP or UDP traffic for
//! `listen_port` from outside the overlay and send each new flow to
//! `target_port` of one target:
//!
//! * an address: a node's overlay address, or an address behind a gateway;
//! * selectors (`tag`, `node:…`, `role:…`, …): the data nodes they pick, one
//!   per client address (rendezvous hashing, so a client sticks to a node).
//!
//! With `real_ip` the packet keeps the client's address as its source; the
//! target has to accept that (`[proxy] accept_real_ip` in its webjetd.toml)
//! and route the replies back into the overlay. Otherwise, and always for
//! targets behind a gateway, the ingress translates the source to its own
//! overlay address and a port from [`SNAT_PORTS`].

use crate::conntrack::{Conntrack, Key};
use crate::crypto::Bytes32;
use crate::packet::{Flow, Fragment, Parsed};
use crate::policy::{PROTO_TCP, PROTO_UDP, Selector};
use crate::types::valid_name;
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};
use webjet_proto as wp;

/// Source ports the ingress uses when it translates the source: above
/// Linux's default ephemeral range (32768–60999), so they don't collide
/// with the ingress's own connections to the same target.
pub const SNAT_PORTS: RangeInclusive<u16> = 61000..=65535;

/// At most this many rules per node.
pub const MAX_RULES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Addr(IpAddr),
    Nodes(Vec<Selector>),
}

impl Target {
    pub fn parse(t: &[String]) -> Result<Target> {
        if let [one] = t
            && let Ok(a) = one.trim().parse::<IpAddr>()
        {
            return Ok(Target::Addr(a));
        }
        match t {
            [] => bail!("target is empty"),
            many => {
                let mut sels = Vec::new();
                for s in many {
                    if s.trim().parse::<IpAddr>().is_ok() {
                        bail!("target {s:?}: an address must be the only target");
                    }
                    let sel = Selector::parse(s)?;
                    if matches!(sel, Selector::Cidr(_)) {
                        bail!("target {s:?}: cidr selectors pick no nodes; give one address");
                    }
                    sels.push(sel);
                }
                Ok(Target::Nodes(sels))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub proto: u8,
    pub listen_port: u16,
    pub target: Target,
    pub target_port: u16,
    pub real_ip: bool,
}

pub fn proto_name(p: u8) -> &'static str {
    match p {
        PROTO_TCP => "tcp",
        PROTO_UDP => "udp",
        _ => "?",
    }
}

pub fn parse_proto(s: &str) -> Result<u8> {
    Ok(match s {
        "tcp" => PROTO_TCP,
        "udp" => PROTO_UDP,
        _ => bail!("protocol {s:?}: tcp or udp"),
    })
}

impl Rule {
    pub fn from_wire(r: &wp::ProxyRule) -> Result<Rule> {
        let name = r.name.clone().unwrap_or_default();
        if !valid_name(&name) {
            bail!("proxy rule name {name:?} is not a valid name");
        }
        if r.protocol != PROTO_TCP && r.protocol != PROTO_UDP {
            bail!("proxy rule {name}: protocol must be tcp or udp");
        }
        if r.listen_port == 0 || r.target_port == 0 {
            bail!("proxy rule {name}: ports must not be 0");
        }
        let target = Target::parse(&r.target.clone().unwrap_or_default())
            .map_err(|e| anyhow::anyhow!("proxy rule {name}: {e}"))?;
        if let Target::Addr(a) = target
            && (a.is_unspecified() || a.is_loopback() || a.is_multicast())
        {
            bail!("proxy rule {name}: target {a} is not a unicast address");
        }
        Ok(Rule {
            name,
            proto: r.protocol,
            listen_port: r.listen_port,
            target,
            target_port: r.target_port,
            real_ip: r.real_ip,
        })
    }
}

/// Parse a node's rules: valid, unique names, one rule per protocol and
/// listen port.
pub fn rules(v: &[wp::ProxyRule]) -> Result<Vec<Rule>> {
    if v.len() > MAX_RULES {
        bail!("at most {MAX_RULES} proxy rules per node");
    }
    let mut out: Vec<Rule> = Vec::new();
    for r in v {
        let r = Rule::from_wire(r)?;
        if out.iter().any(|o| o.name == r.name) {
            bail!("two proxy rules are named {}", r.name);
        }
        if let Some(o) = out
            .iter()
            .find(|o| o.proto == r.proto && o.listen_port == r.listen_port)
        {
            bail!(
                "proxy rules {} and {} both listen on {} port {}",
                o.name,
                r.name,
                proto_name(r.proto),
                r.listen_port
            );
        }
        out.push(r);
    }
    Ok(out)
}

/// Rendezvous hashing: the candidate a client address goes to. The same
/// client keeps its node while that node stays a candidate; when one leaves
/// only its clients move.
pub fn rank(candidates: &[Bytes32], client: &IpAddr) -> Vec<Bytes32> {
    let c = match client {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    let mut v: Vec<(Bytes32, Bytes32)> = candidates
        .iter()
        .map(|id| {
            let mut m = Vec::with_capacity(32 + c.len());
            m.extend_from_slice(id);
            m.extend_from_slice(&c);
            (crate::crypto::hash(&m), *id)
        })
        .collect();
    v.sort();
    v.reverse();
    v.into_iter().map(|(_, id)| id).collect()
}

/// An address a client may have: not an overlay or published address (that
/// would let an ingress speak for other nodes), not loopback, multicast or
/// unspecified.
pub fn plausible_client(a: &IpAddr, overlay: &[ipnet::IpNet]) -> bool {
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || overlay.iter().any(|n| n.contains(a)))
}

/// Which side of a proxy flow this node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    Ingress,
    Target,
}

/// What the table knows about one flow.
#[derive(Clone, Debug)]
pub struct FlowInfo {
    pub role: Role,
    pub rule: String,
    /// The node that owns the rule (the ingress).
    pub owner: Bytes32,
    /// Ingress: the flow as captured (client → proxy address:listen port).
    pub client: Option<Flow>,
}

/// How long a datagram's later fragments may follow its first one.
pub const FRAG_TIMEOUT: Duration = Duration::from_secs(30);
/// At most this many datagrams' fragment routes at once.
pub const FRAG_CAP: usize = 8192;

/// One fragmented datagram as it arrives at one point of the proxy: from
/// the tun interface (`from: None`) or in a PROXY frame from a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FragKey {
    pub from: Option<Bytes32>,
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub id: u32,
}

impl FragKey {
    pub fn of(from: Option<&Bytes32>, p: &Parsed) -> Self {
        FragKey {
            from: from.copied(),
            proto: p.flow.proto,
            src: p.flow.src,
            dst: p.flow.dst,
            id: p.frag_id,
        }
    }
}

/// Where the later fragments of a datagram go: the way its first fragment
/// went. Later fragments carry no ports, so no flow lookup finds them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FragRoute {
    /// To this peer in a PROXY frame; `None`: into the tun interface.
    pub peer: Option<Bytes32>,
    /// The addresses the first fragment was given (`None`: kept).
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    /// For the counters: the flow's side, rule and rule owner.
    pub role: Role,
    pub rule: String,
    pub owner: Bytes32,
}

/// Proxy flows: their own connection tracking plus the address mappings.
///
/// * Ingress flows: conntrack key = (target node, translated flow), entry
///   outbound; `by_client` maps the captured flow to that key.
/// * Target flows: conntrack key = (ingress, flow as received), entry
///   inbound; `by_flow` finds the ingress for replies from the tun.
/// * Fragmented datagrams: `frags` sends later fragments after their first.
pub struct Table {
    pub ct: Conntrack,
    info: HashMap<Key, FlowInfo>,
    by_client: HashMap<Flow, Key>,
    by_flow: HashMap<Flow, Bytes32>,
    /// Translated sources in use: (protocol, source, port, target, port).
    snat_used: HashSet<(u8, IpAddr, u16, IpAddr, u16)>,
    frags: HashMap<FragKey, (FragRoute, Instant)>,
}

impl Default for Table {
    fn default() -> Self {
        Table::new()
    }
}

impl Table {
    pub fn new() -> Self {
        Table {
            ct: Conntrack::new(0, 0, 0),
            info: HashMap::new(),
            by_client: HashMap::new(),
            by_flow: HashMap::new(),
            snat_used: HashSet::new(),
            frags: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.info.is_empty()
    }

    fn live(&self, k: &Key, now: Instant) -> bool {
        self.ct
            .get(k)
            .is_some_and(|e| now.duration_since(e.last) < e.state.timeout())
    }

    /// Ingress: the tracked flow for a captured packet.
    pub fn ingress_key(&self, client: &Flow, now: Instant) -> Option<Key> {
        self.by_client
            .get(client)
            .copied()
            .filter(|k| self.live(k, now))
    }

    /// The flow a packet from `peer` belongs to, as the reply to one of
    /// our ingress flows (`inner` is the packet's flow, or the quoted flow
    /// of an ICMP error, reversed to the direction the flow started).
    pub fn ingress_reply(&self, peer: &Bytes32, started: &Flow) -> Option<(Key, &FlowInfo)> {
        let k = Key {
            peer: *peer,
            flow: *started,
        };
        let i = self.info.get(&k)?;
        (i.role == Role::Ingress).then_some((k, i))
    }

    /// Target: the ingress a flow (in the direction it started) came from.
    pub fn target_peer(&self, started: &Flow) -> Option<Bytes32> {
        self.by_flow.get(started).copied()
    }

    pub fn info(&self, k: &Key) -> Option<&FlowInfo> {
        self.info.get(k)
    }

    /// A free translated source port from `src` towards `dst:dport`, or
    /// `None` when the range is used up for that target.
    pub fn snat_port(&self, proto: u8, src: IpAddr, dst: IpAddr, dport: u16) -> Option<u16> {
        let span = (*SNAT_PORTS.end() - *SNAT_PORTS.start()) as u32 + 1;
        let start = rand::random::<u32>() % span;
        (0..span)
            .map(|i| *SNAT_PORTS.start() + ((start + i) % span) as u16)
            .find(|p| !self.snat_used.contains(&(proto, src, *p, dst, dport)))
    }

    /// Record a flow conntrack accepted (`ct.insert` succeeded). `p` is
    /// the packet as conntrack saw it.
    pub fn add(&mut self, peer: &Bytes32, p: &Parsed, info: FlowInfo) {
        let k = Key {
            peer: *peer,
            flow: p.flow,
        };
        if let Some(c) = info.client {
            self.by_client.insert(c, k);
            if info.role == Role::Ingress {
                let f = p.flow;
                self.snat_used
                    .insert((f.proto, f.src, f.sport, f.dst, f.dport));
            }
        }
        if info.role == Role::Target {
            self.by_flow.insert(p.flow, *peer);
        }
        self.info.insert(k, info);
    }

    fn forget(&mut self, k: &Key) {
        if let Some(i) = self.info.remove(k) {
            if let Some(c) = i.client {
                // The captured flow may have been re-tracked under a new key
                // since (its old entry timed out before the sweep): that
                // mapping belongs to the new flow.
                if self.by_client.get(&c) == Some(k) {
                    self.by_client.remove(&c);
                }
                let f = k.flow;
                self.snat_used
                    .remove(&(f.proto, f.src, f.sport, f.dst, f.dport));
            }
            if i.role == Role::Target && self.by_flow.get(&k.flow) == Some(&k.peer) {
                self.by_flow.remove(&k.flow);
            }
        }
    }

    /// Drop expired flows (conntrack's and the mappings with them).
    pub fn expire(&mut self, now: Instant) {
        self.ct.expire(now);
        let dead: Vec<Key> = self
            .info
            .keys()
            .filter(|k| self.ct.get(k).is_none())
            .copied()
            .collect();
        for k in dead {
            self.forget(&k);
        }
        self.frags
            .retain(|_, (_, t)| now.duration_since(*t) < FRAG_TIMEOUT);
    }

    /// Remember where a first fragment went (`p`: the fragment as it
    /// arrived), so its datagram's later fragments follow it.
    pub fn add_frag(&mut self, from: Option<&Bytes32>, p: &Parsed, route: FragRoute, now: Instant) {
        if p.fragment != Fragment::First {
            return;
        }
        if self.frags.len() >= FRAG_CAP {
            self.frags
                .retain(|_, (_, t)| now.duration_since(*t) < FRAG_TIMEOUT);
            if self.frags.len() >= FRAG_CAP {
                return;
            }
        }
        self.frags.insert(FragKey::of(from, p), (route, now));
    }

    /// Where a later fragment goes, if its first fragment came this way.
    pub fn frag_route(
        &mut self,
        from: Option<&Bytes32>,
        p: &Parsed,
        now: Instant,
    ) -> Option<FragRoute> {
        let (r, t) = self.frags.get_mut(&FragKey::of(from, p))?;
        if now.duration_since(*t) >= FRAG_TIMEOUT {
            return None;
        }
        *t = now;
        Some(r.clone())
    }

    /// Re-check every flow (rules or policy changed); `keep` says whether
    /// a flow is still allowed. Returns how many were closed.
    pub fn reevaluate(&mut self, mut keep: impl FnMut(&Key, &FlowInfo) -> bool) -> usize {
        let info = &self.info;
        let n = self
            .ct
            .reevaluate(|k, _| info.get(k).is_some_and(|i| keep(k, i)));
        let dead: Vec<Key> = self
            .info
            .keys()
            .filter(|k| self.ct.get(k).is_none())
            .copied()
            .collect();
        for k in dead {
            self.forget(&k);
        }
        if n > 0 {
            // Datagrams in flight may belong to a flow just closed.
            self.frags.clear();
        }
        n
    }

    /// Flows with their conntrack entries.
    pub fn flows(&self) -> impl Iterator<Item = (&Key, &crate::conntrack::Entry, &FlowInfo)> {
        self.ct
            .entries()
            .filter_map(|(k, e)| self.info.get(k).map(|i| (k, e, i)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{parse, tcpf, tests::tcp4, tests::udp4};

    fn wire(name: &str, proto: u8, listen: u16, target: &[&str]) -> wp::ProxyRule {
        wp::ProxyRule {
            name: Some(name.into()),
            protocol: proto,
            listen_port: listen,
            target: Some(target.iter().map(|s| s.to_string()).collect()),
            target_port: 80,
            real_ip: true,
        }
    }

    #[test]
    fn rules_are_checked() {
        let ok = rules(&[
            wire("web", PROTO_TCP, 8080, &["10.7.0.2"]),
            wire("dns", PROTO_UDP, 8080, &["tag:web", "role:data"]),
        ])
        .unwrap();
        assert_eq!(ok[0].target, Target::Addr("10.7.0.2".parse().unwrap()));
        assert!(matches!(ok[1].target, Target::Nodes(ref s) if s.len() == 2));
        for (bad, why) in [
            (
                vec![
                    wire("a", PROTO_TCP, 1, &["tag:x"]),
                    wire("a", PROTO_UDP, 2, &["tag:x"]),
                ],
                "named",
            ),
            (
                vec![
                    wire("a", PROTO_TCP, 1, &["tag:x"]),
                    wire("b", PROTO_TCP, 1, &["tag:y"]),
                ],
                "both listen",
            ),
            (vec![wire("a", 1, 1, &["x"])], "protocol"),
            (vec![wire("a", PROTO_TCP, 0, &["x"])], "ports"),
            (vec![wire("a", PROTO_TCP, 1, &[])], "empty"),
            (
                vec![wire("a", PROTO_TCP, 1, &["10.0.0.1", "tag:x"])],
                "only target",
            ),
            (vec![wire("a", PROTO_TCP, 1, &["cidr:10.0.0.0/8"])], "cidr"),
            (vec![wire("a", PROTO_TCP, 1, &["127.0.0.1"])], "unicast"),
            (vec![wire("Bad Name", PROTO_TCP, 1, &["x"])], "valid name"),
        ] {
            let e = rules(&bad).unwrap_err().to_string();
            assert!(e.contains(why), "{e} should mention {why}");
        }
    }

    #[test]
    fn rendezvous_is_sticky() {
        let nodes: Vec<Bytes32> = (1..=5u8).map(|i| [i; 32]).collect();
        let c: IpAddr = "203.0.113.7".parse().unwrap();
        let first = rank(&nodes, &c)[0];
        assert_eq!(rank(&nodes, &c)[0], first);
        // Removing another node doesn't move the client.
        let other: Vec<Bytes32> = nodes.iter().copied().filter(|n| *n != first).collect();
        let fewer: Vec<Bytes32> = nodes.iter().copied().filter(|n| *n != other[0]).collect();
        assert_eq!(rank(&fewer, &c)[0], first);
        // Clients spread out.
        let picks: HashSet<Bytes32> = (0..64u8)
            .map(|i| rank(&nodes, &IpAddr::from([198, 51, 100, i]))[0])
            .collect();
        assert!(picks.len() >= 3);
    }

    #[test]
    fn table_maps_and_expires() {
        let mut t = Table::new();
        t.ct = Conntrack::new(10, 100, 100);
        let peer = [9; 32];
        let now = Instant::now();
        let client = parse(&tcp4(
            [203, 0, 113, 7],
            [10, 7, 255, 254],
            4000,
            8080,
            tcpf::SYN,
        ))
        .unwrap()
        .flow;
        let me: IpAddr = "10.7.0.1".parse().unwrap();
        let target: IpAddr = "10.7.0.2".parse().unwrap();
        let port = t.snat_port(PROTO_TCP, me, target, 80).unwrap();
        assert!(SNAT_PORTS.contains(&port));
        let inner = parse(&tcp4([10, 7, 0, 1], [10, 7, 0, 2], port, 80, tcpf::SYN)).unwrap();
        t.ct.insert(&peer, &inner, true, Some("web".into()), false, now)
            .unwrap();
        t.add(
            &peer,
            &inner,
            FlowInfo {
                role: Role::Ingress,
                rule: "web".into(),
                owner: [1; 32],
                client: Some(client),
            },
        );
        let k = t.ingress_key(&client, now).unwrap();
        assert_eq!(k.flow, inner.flow);
        assert!(t.ingress_reply(&peer, &inner.flow).is_some());
        assert!(t.snat_used.contains(&(PROTO_TCP, me, port, target, 80)));
        // Opening TCP times out after 30 s; the mapping goes with it.
        t.expire(now + std::time::Duration::from_secs(31));
        assert!(t.is_empty());
        assert!(t.by_client.is_empty() && t.snat_used.is_empty());
    }

    #[test]
    fn target_flows_find_their_ingress() {
        let mut t = Table::new();
        t.ct = Conntrack::new(10, 100, 100);
        let ingress = [3; 32];
        let now = Instant::now();
        let p = parse(&tcp4([203, 0, 113, 7], [10, 7, 0, 2], 4000, 80, tcpf::SYN)).unwrap();
        t.ct.insert(&ingress, &p, false, Some("web".into()), false, now)
            .unwrap();
        t.add(
            &ingress,
            &p,
            FlowInfo {
                role: Role::Target,
                rule: "web".into(),
                owner: ingress,
                client: None,
            },
        );
        assert_eq!(t.target_peer(&p.flow), Some(ingress));
        assert_eq!(t.reevaluate(|_, _| false), 1);
        assert_eq!(t.target_peer(&p.flow), None);
    }

    #[test]
    fn a_flow_tracked_again_keeps_its_new_mapping_when_the_old_one_is_swept() {
        let mut t = Table::new();
        t.ct = Conntrack::new(10, 100, 100);
        let (peer, ingress2) = ([9; 32], [8; 32]);
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(31);
        let client = parse(&udp4([203, 0, 113, 7], [10, 7, 255, 254], 4000, 53, b"q"))
            .unwrap()
            .flow;
        let ingress = |t: &mut Table, port: u16, at: Instant| {
            let p = parse(&udp4([10, 7, 0, 1], [10, 7, 0, 2], port, 53, b"q")).unwrap();
            t.ct.insert(&peer, &p, true, Some("dns".into()), false, at)
                .unwrap();
            t.add(
                &peer,
                &p,
                FlowInfo {
                    role: Role::Ingress,
                    rule: "dns".into(),
                    owner: [1; 32],
                    client: Some(client),
                },
            );
            p.flow
        };
        ingress(&mut t, 40000, now);
        // The one-way UDP flow times out (30 s) before the sweep; the
        // client's next packet is tracked again with a new source port.
        assert!(t.ingress_key(&client, later).is_none());
        let second = ingress(&mut t, 40001, later);
        // Sweeping the old flow leaves the new mapping alone: the client
        // isn't moved to yet another port by its next packet.
        t.expire(later);
        assert_eq!(t.ingress_key(&client, later).map(|k| k.flow), Some(second));
        assert_eq!(t.snat_used.len(), 1);
        // Target side: the same flow, now from another ingress.
        let p = parse(&udp4([203, 0, 113, 7], [10, 7, 0, 2], 4000, 53, b"q")).unwrap();
        for (from, at) in [(peer, now), (ingress2, later)] {
            t.ct.insert(&from, &p, false, Some("dns".into()), false, at)
                .unwrap();
            t.add(
                &from,
                &p,
                FlowInfo {
                    role: Role::Target,
                    rule: "dns".into(),
                    owner: from,
                    client: None,
                },
            );
        }
        t.expire(later);
        assert_eq!(t.target_peer(&p.flow), Some(ingress2));
    }

    #[test]
    fn later_fragments_follow_their_first_until_it_expires() {
        let mut t = Table::new();
        let now = Instant::now();
        let mut p = udp4([203, 0, 113, 7], [10, 7, 255, 53], 4000, 27015, &[0; 64]);
        p[4..6].copy_from_slice(&7u16.to_be_bytes());
        p[6] = 0x20;
        let first = parse(&p).unwrap();
        p[6] = 0;
        p[7] = 4;
        let later = parse(&p).unwrap();
        let route = FragRoute {
            peer: Some([9; 32]),
            src: None,
            dst: Some("10.7.0.2".parse().unwrap()),
            role: Role::Ingress,
            rule: "game".into(),
            owner: [1; 32],
        };
        // Only a first fragment opens a route; it is per arrival point.
        t.add_frag(None, &later, route.clone(), now);
        assert_eq!(t.frag_route(None, &later, now), None);
        t.add_frag(None, &first, route.clone(), now);
        assert_eq!(t.frag_route(None, &later, now), Some(route));
        assert_eq!(t.frag_route(Some(&[9; 32]), &later, now), None);
        t.expire(now + FRAG_TIMEOUT);
        assert_eq!(t.frag_route(None, &later, now + FRAG_TIMEOUT), None);
    }
}
