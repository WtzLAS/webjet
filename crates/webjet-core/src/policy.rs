//! Tag-based access control (§14): selectors, port specs, deny-overrides
//! evaluation, per-node compiled tables and pair reachability.

use crate::crypto::{Bytes32, parse_key_b64};
use crate::types::{parse_net, valid_name, valid_tag};
use anyhow::{Result, anyhow, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use webjet_proto as wp;

// ---------------------------------------------------------------- protocols and ports

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

/// A set of (protocol, port) combinations: TCP and UDP port ranges, ICMP,
/// and "any other IP protocol".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortSet {
    pub tcp: Vec<(u16, u16)>,
    pub udp: Vec<(u16, u16)>,
    pub icmp: bool,
    pub other: bool,
}

fn norm(mut v: Vec<(u16, u16)>) -> Vec<(u16, u16)> {
    v.sort();
    let mut out: Vec<(u16, u16)> = Vec::new();
    for (lo, hi) in v {
        if let Some(last) = out.last_mut()
            && lo as u32 <= last.1 as u32 + 1
        {
            last.1 = last.1.max(hi);
            continue;
        }
        out.push((lo, hi));
    }
    out
}

fn sub(a: &[(u16, u16)], b: &[(u16, u16)]) -> Vec<(u16, u16)> {
    let mut out = Vec::new();
    for &(lo, hi) in a {
        let mut pieces = vec![(lo as u32, hi as u32)];
        for &(blo, bhi) in b {
            let (blo, bhi) = (blo as u32, bhi as u32);
            let mut next = Vec::new();
            for (plo, phi) in pieces {
                if bhi < plo || blo > phi {
                    next.push((plo, phi));
                    continue;
                }
                if blo > plo {
                    next.push((plo, blo - 1));
                }
                if bhi < phi {
                    next.push((bhi + 1, phi));
                }
            }
            pieces = next;
        }
        out.extend(pieces.into_iter().map(|(l, h)| (l as u16, h as u16)));
    }
    norm(out)
}

fn has(v: &[(u16, u16)], p: u16) -> bool {
    v.iter().any(|&(lo, hi)| lo <= p && p <= hi)
}

impl PortSet {
    pub fn all() -> Self {
        PortSet {
            tcp: vec![(0, 65535)],
            udp: vec![(0, 65535)],
            icmp: true,
            other: true,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.udp.is_empty() && !self.icmp && !self.other
    }
    pub fn union(&mut self, o: &PortSet) {
        self.tcp = norm(self.tcp.iter().chain(o.tcp.iter()).copied().collect());
        self.udp = norm(self.udp.iter().chain(o.udp.iter()).copied().collect());
        self.icmp |= o.icmp;
        self.other |= o.other;
    }
    pub fn subtract(&mut self, o: &PortSet) {
        self.tcp = sub(&self.tcp, &o.tcp);
        self.udp = sub(&self.udp, &o.udp);
        self.icmp &= !o.icmp;
        self.other &= !o.other;
    }
    pub fn intersects(&self, o: &PortSet) -> bool {
        let mut a = self.clone();
        a.subtract(o);
        a != *self
    }
    pub fn contains(&self, proto: u8, port: u16) -> bool {
        match proto {
            PROTO_TCP => has(&self.tcp, port),
            PROTO_UDP => has(&self.udp, port),
            PROTO_ICMP | PROTO_ICMPV6 => self.icmp,
            _ => self.other,
        }
    }

    /// Parse one port spec: `tcp:22`, `tcp:8000-8100`, `udp:53`, `tcp`,
    /// `tcp:*`, `icmp`, `*`.
    pub fn parse_spec(s: &str) -> Result<PortSet> {
        let s = s.trim();
        if s == "*" {
            return Ok(PortSet::all());
        }
        if s == "icmp" {
            return Ok(PortSet {
                icmp: true,
                ..Default::default()
            });
        }
        let (proto, ports) = match s.split_once(':') {
            Some((p, r)) => (p, r),
            None => (s, "*"),
        };
        let range = if ports == "*" {
            (0u16, 65535u16)
        } else if let Some((a, b)) = ports.split_once('-') {
            let (a, b): (u16, u16) = (a.parse()?, b.parse()?);
            if a > b {
                bail!("bad port range {s}");
            }
            (a, b)
        } else {
            let p: u16 = ports.parse()?;
            (p, p)
        };
        match proto {
            "tcp" => Ok(PortSet {
                tcp: vec![range],
                ..Default::default()
            }),
            "udp" => Ok(PortSet {
                udp: vec![range],
                ..Default::default()
            }),
            _ => bail!("unknown protocol in port spec {s:?}"),
        }
    }

    pub fn parse_list(v: &[String]) -> Result<PortSet> {
        let mut out = PortSet::default();
        for s in v {
            out.union(&PortSet::parse_spec(s)?);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------- selectors

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    Any,
    Tag(String),
    Role(RoleSel),
    NodeName(String),
    NodeKey(Bytes32),
    OwnerName(String),
    OwnerKey(Bytes32),
    Cidr(IpNet),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleSel {
    Relay,
    Data,
    Control,
}

impl Selector {
    pub fn parse(s: &str) -> Result<Selector> {
        let s = s.trim();
        if s == "*" {
            return Ok(Selector::Any);
        }
        if valid_tag(s) {
            return Ok(Selector::Tag(s.to_string()));
        }
        let (k, v) = s
            .split_once(':')
            .ok_or_else(|| anyhow!("bad selector {s:?}"))?;
        Ok(match k {
            "role" => Selector::Role(match v {
                "relay" => RoleSel::Relay,
                "data" => RoleSel::Data,
                "control" => RoleSel::Control,
                _ => bail!("unknown role selector {s:?}"),
            }),
            "node" | "owner" => {
                let key = parse_key_b64(v);
                match (k, key) {
                    ("node", Some(key)) => Selector::NodeKey(key),
                    ("owner", Some(key)) => Selector::OwnerKey(key),
                    ("node", None) if valid_name(v) => Selector::NodeName(v.to_string()),
                    ("owner", None) if valid_name(v) => Selector::OwnerName(v.to_string()),
                    _ => bail!("bad selector {s:?}"),
                }
            }
            "cidr" => Selector::Cidr(parse_net(v)?),
            _ => bail!("unknown selector {s:?}"),
        })
    }

    fn matches_node(&self, n: &Subject) -> bool {
        match self {
            Selector::Any => n.enrolled,
            Selector::Tag(t) => n.tags.iter().any(|x| x == t),
            Selector::Role(RoleSel::Relay) => n.relay,
            Selector::Role(RoleSel::Data) => n.data,
            Selector::Role(RoleSel::Control) => n.control,
            Selector::NodeName(name) => n.name.as_deref() == Some(name.as_str()),
            Selector::NodeKey(k) => n.key.as_ref() == Some(k),
            Selector::OwnerName(o) => n.owner_name.as_deref() == Some(o.as_str()),
            Selector::OwnerKey(k) => n.owner_key.as_ref() == Some(k),
            Selector::Cidr(_) => false,
        }
    }
}

/// What the policy needs to know about a node.
#[derive(Clone, Debug, Default)]
pub struct Subject {
    pub node_id: Bytes32,
    pub enrolled: bool,
    pub name: Option<String>,
    pub key: Option<Bytes32>,
    pub tags: Vec<String>,
    pub owner_name: Option<String>,
    pub owner_key: Option<Bytes32>,
    pub data: bool,
    pub relay: bool,
    pub control: bool,
}

/// The destination of a flow: a node, or an address inside a published
/// subnet prefix (served by a gateway).
#[derive(Clone, Copy, Debug)]
pub enum Dest<'a> {
    Node(&'a Subject),
    Addr(IpAddr),
}

// ---------------------------------------------------------------- rules

#[derive(Clone, Debug, PartialEq, Eq, Copy, Hash)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub action: Decision,
    pub src: Vec<Selector>,
    pub dst: Vec<Selector>,
    pub ports: PortSet,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub version: u64,
    pub default: Decision,
    pub rules: Vec<Rule>,
    pub tests: Vec<wp::PolicyTest>,
}

/// Who decided a flow: a rule id, or the default.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Verdict {
    pub decision: Decision,
    pub rule: Option<String>,
}

impl Verdict {
    pub fn rule_id(&self) -> &str {
        self.rule.as_deref().unwrap_or("(default)")
    }
}

impl Default for Policy {
    fn default() -> Self {
        // With no policy in the tree, nothing is allowed (default deny, §6.12).
        Policy {
            version: 0,
            default: Decision::Deny,
            rules: Vec::new(),
            tests: Vec::new(),
        }
    }
}

fn action(a: wp::Action) -> Decision {
    match a {
        wp::Action::Allow => Decision::Allow,
        wp::Action::Deny => Decision::Deny,
    }
}

impl Policy {
    pub fn from_wire(p: &wp::Policy) -> Result<Policy> {
        let mut rules = Vec::new();
        let mut ids = std::collections::HashSet::new();
        for r in p.rules.clone().unwrap_or_default() {
            let id = r.id.clone().unwrap_or_default();
            if id.is_empty() || !ids.insert(id.clone()) {
                bail!("rule ids must be present and unique ({id:?})");
            }
            let src = r
                .src
                .clone()
                .unwrap_or_default()
                .iter()
                .map(|s| Selector::parse(s))
                .collect::<Result<Vec<_>>>()?;
            let dst = r
                .dst
                .clone()
                .unwrap_or_default()
                .iter()
                .map(|s| Selector::parse(s))
                .collect::<Result<Vec<_>>>()?;
            if src.iter().any(|s| matches!(s, Selector::Cidr(_))) {
                bail!("rule {id}: cidr: selectors are allowed only in dst (§14.2)");
            }
            if src.is_empty() || dst.is_empty() {
                bail!("rule {id}: src and dst must not be empty");
            }
            let ports = PortSet::parse_list(&r.ports.clone().unwrap_or_default())?;
            rules.push(Rule {
                id,
                action: action(r.action),
                src,
                dst,
                ports,
            });
        }
        Ok(Policy {
            version: p.version,
            default: action(p.default_action),
            rules,
            tests: p.tests.clone().unwrap_or_default(),
        })
    }

    fn dst_matches(sel: &[Selector], d: Dest) -> bool {
        sel.iter().any(|s| match (s, d) {
            (Selector::Cidr(n), Dest::Addr(a)) => n.contains(&a),
            (_, Dest::Node(n)) => s.matches_node(n),
            _ => false,
        })
    }

    /// Evaluate a new flow (§14.3): any matching deny wins, then any allow,
    /// then the default.
    pub fn evaluate(&self, src: &Subject, dst: Dest, proto: u8, port: u16) -> Verdict {
        let mut allow: Option<&Rule> = None;
        for r in &self.rules {
            if !r.ports.contains(proto, port)
                || !r.src.iter().any(|s| s.matches_node(src))
                || !Self::dst_matches(&r.dst, dst)
            {
                continue;
            }
            match r.action {
                Decision::Deny => {
                    return Verdict {
                        decision: Decision::Deny,
                        rule: Some(r.id.clone()),
                    };
                }
                Decision::Allow => {
                    if allow.is_none() {
                        allow = Some(r);
                    }
                }
            }
        }
        match allow {
            Some(r) => Verdict {
                decision: Decision::Allow,
                rule: Some(r.id.clone()),
            },
            None => Verdict {
                decision: self.default,
                rule: None,
            },
        }
    }

    /// The set of (proto, port) a flow from `src` to `dst` may use, after
    /// deny rules.
    pub fn allowed(&self, src: &Subject, dst: Dest) -> PortSet {
        let mut allow = if self.default == Decision::Allow {
            PortSet::all()
        } else {
            PortSet::default()
        };
        let mut deny = PortSet::default();
        for r in &self.rules {
            if !r.src.iter().any(|s| s.matches_node(src)) || !Self::dst_matches(&r.dst, dst) {
                continue;
            }
            match r.action {
                Decision::Allow => allow.union(&r.ports),
                Decision::Deny => deny.union(&r.ports),
            }
        }
        allow.subtract(&deny);
        allow
    }

    /// Allowed set from `src` to anything inside `prefix` (for gateways):
    /// rules whose cidr: selectors overlap the prefix. Conservative: the
    /// union over addresses, minus denies covering the whole prefix.
    pub fn allowed_prefix(&self, src: &Subject, prefix: &IpNet) -> PortSet {
        let mut allow = if self.default == Decision::Allow {
            PortSet::all()
        } else {
            PortSet::default()
        };
        let mut deny = PortSet::default();
        for r in &self.rules {
            if !r.src.iter().any(|s| s.matches_node(src)) {
                continue;
            }
            let touches = r
                .dst
                .iter()
                .any(|s| matches!(s, Selector::Cidr(n) if crate::types::overlaps(n, prefix)));
            let covers = r.dst.iter().any(|s| matches!(s, Selector::Cidr(n) if n.contains(&prefix.network()) && n.prefix_len() <= prefix.prefix_len()));
            match r.action {
                Decision::Allow if touches => allow.union(&r.ports),
                Decision::Deny if covers => deny.union(&r.ports),
                _ => {}
            }
        }
        allow.subtract(&deny);
        allow
    }

    /// Run the policy's own tests (§14.5) with synthetic subjects.
    pub fn run_tests(&self, lookup: &dyn Fn(&Selector) -> Option<Subject>) -> Result<()> {
        for (i, t) in self.tests.iter().enumerate() {
            let src_s = Selector::parse(t.src.as_deref().unwrap_or(""))?;
            let dst_txt = t.dst.as_deref().unwrap_or("");
            let port_txt = t.port.as_deref().unwrap_or("");
            let (proto, port) = parse_test_port(port_txt)?;
            let src = synth(&src_s, lookup);
            let dst_s = Selector::parse(dst_txt)?;
            let got = match &dst_s {
                Selector::Cidr(n) => self.evaluate(&src, Dest::Addr(n.network()), proto, port),
                other => {
                    let d = synth(other, lookup);
                    self.evaluate(&src, Dest::Node(&d), proto, port)
                }
            };
            let want = action(t.expect);
            if got.decision != want {
                bail!(
                    "policy test #{i} ({} -> {} {}) expected {:?}, got {:?} by {}",
                    t.src.as_deref().unwrap_or(""),
                    dst_txt,
                    port_txt,
                    want,
                    got.decision,
                    got.rule_id()
                );
            }
        }
        Ok(())
    }

    /// Warnings shown to the admin (§14.5): selectors matching no node, and
    /// deny rules that override every allow they overlap.
    pub fn warnings(&self, subjects: &[Subject]) -> Vec<String> {
        let mut w = Vec::new();
        for r in &self.rules {
            for s in r.src.iter().chain(r.dst.iter()) {
                if matches!(s, Selector::Any | Selector::Cidr(_)) {
                    continue;
                }
                if !subjects.iter().any(|n| s.matches_node(n)) {
                    w.push(format!("rule {}: selector {:?} matches no node", r.id, s));
                }
            }
        }
        for d in self.rules.iter().filter(|r| r.action == Decision::Deny) {
            for a in self.rules.iter().filter(|r| r.action == Decision::Allow) {
                let mut rest = a.ports.clone();
                rest.subtract(&d.ports);
                let overlap_sel = subjects.iter().any(|s| {
                    d.src.iter().any(|x| x.matches_node(s))
                        && a.src.iter().any(|x| x.matches_node(s))
                });
                if rest.is_empty() && overlap_sel && d.dst == a.dst {
                    w.push(format!(
                        "deny rule {} overrides all of allow rule {}",
                        d.id, a.id
                    ));
                }
            }
        }
        w
    }
}

fn synth(s: &Selector, lookup: &dyn Fn(&Selector) -> Option<Subject>) -> Subject {
    if let Some(n) = lookup(s) {
        return n;
    }
    let mut n = Subject {
        enrolled: true,
        ..Default::default()
    };
    match s {
        Selector::Tag(t) => n.tags.push(t.clone()),
        Selector::Role(RoleSel::Relay) => n.relay = true,
        Selector::Role(RoleSel::Data) => n.data = true,
        Selector::Role(RoleSel::Control) => n.control = true,
        Selector::NodeName(x) => n.name = Some(x.clone()),
        Selector::NodeKey(k) => n.key = Some(*k),
        Selector::OwnerName(x) => n.owner_name = Some(x.clone()),
        Selector::OwnerKey(k) => n.owner_key = Some(*k),
        Selector::Any | Selector::Cidr(_) => {}
    }
    n
}

fn parse_test_port(s: &str) -> Result<(u8, u16)> {
    if s == "icmp" {
        return Ok((PROTO_ICMP, 0));
    }
    let (p, port) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("bad test port {s:?}"))?;
    let proto = match p {
        "tcp" => PROTO_TCP,
        "udp" => PROTO_UDP,
        _ => bail!("bad test port {s:?}"),
    };
    Ok((proto, port.parse()?))
}

// ---------------------------------------------------------------- compiled per-node tables (§14.4)

#[derive(Clone, Debug, Default)]
pub struct Compiled {
    pub version: u64,
    /// Flows others may start to me, by source node.
    pub inbound: HashMap<Bytes32, PortSet>,
    /// Flows I may start, by destination node.
    pub outbound: HashMap<Bytes32, PortSet>,
    /// For gateways: per source node, per published prefix I serve.
    pub subnet_in: HashMap<Bytes32, Vec<(IpNet, PortSet)>>,
}

impl Compiled {
    pub fn build(
        policy: &Policy,
        me: &Subject,
        others: &[Subject],
        my_prefixes: &[IpNet],
    ) -> Compiled {
        let mut c = Compiled {
            version: policy.version,
            ..Default::default()
        };
        for o in others {
            if o.node_id == me.node_id {
                continue;
            }
            let i = policy.allowed(o, Dest::Node(me));
            if !i.is_empty() {
                c.inbound.insert(o.node_id, i);
            }
            let out = policy.allowed(me, Dest::Node(o));
            if !out.is_empty() {
                c.outbound.insert(o.node_id, out);
            }
            if !my_prefixes.is_empty() {
                let v: Vec<(IpNet, PortSet)> = my_prefixes
                    .iter()
                    .map(|p| (*p, policy.allowed_prefix(o, p)))
                    .filter(|(_, s)| !s.is_empty())
                    .collect();
                if !v.is_empty() {
                    c.subnet_in.insert(o.node_id, v);
                }
            }
        }
        c
    }

    /// Pair reachability (§14.4): some flow allowed in either direction, or
    /// the peer may reach one of my prefixes.
    pub fn may_talk(&self, peer: &Bytes32) -> bool {
        self.inbound.contains_key(peer)
            || self.outbound.contains_key(peer)
            || self.subnet_in.contains_key(peer)
    }
}

/// Pair reachability evaluated directly (relays, §11.5): `a` and `b` may
/// talk if any flow is allowed in either direction, or either may reach a
/// prefix the other is granted.
pub fn pair_may_talk(
    policy: &Policy,
    a: &Subject,
    b: &Subject,
    a_prefixes: &[IpNet],
    b_prefixes: &[IpNet],
) -> bool {
    !policy.allowed(a, Dest::Node(b)).is_empty()
        || !policy.allowed(b, Dest::Node(a)).is_empty()
        || b_prefixes
            .iter()
            .any(|p| !policy.allowed_prefix(a, p).is_empty())
        || a_prefixes
            .iter()
            .any(|p| !policy.allowed_prefix(b, p).is_empty())
}

// ---------------------------------------------------------------- YAML form (admin tool)

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyFile {
    pub version: u64,
    #[serde(default = "default_deny")]
    pub default: String,
    #[serde(default)]
    pub rules: Vec<RuleFile>,
    #[serde(default)]
    pub tests: Vec<TestFile>,
}

fn default_deny() -> String {
    "deny".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleFile {
    pub id: String,
    pub action: String,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestFile {
    pub src: String,
    pub dst: String,
    pub port: String,
    pub expect: String,
}

fn parse_action(s: &str) -> Result<wp::Action> {
    match s {
        "allow" => Ok(wp::Action::Allow),
        "deny" => Ok(wp::Action::Deny),
        _ => bail!("action must be allow or deny, got {s:?}"),
    }
}

impl PolicyFile {
    pub fn to_wire(&self) -> Result<wp::Policy> {
        let p = wp::Policy {
            version: self.version,
            default_action: parse_action(&self.default)?,
            rules: Some(
                self.rules
                    .iter()
                    .map(|r| {
                        Ok(wp::Rule {
                            id: Some(r.id.clone()),
                            action: parse_action(&r.action)?,
                            src: Some(r.src.clone()),
                            dst: Some(r.dst.clone()),
                            ports: Some(r.ports.clone()),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
            tests: Some(
                self.tests
                    .iter()
                    .map(|t| {
                        Ok(wp::PolicyTest {
                            src: Some(t.src.clone()),
                            dst: Some(t.dst.clone()),
                            port: Some(t.port.clone()),
                            expect: parse_action(&t.expect)?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
        };
        Policy::from_wire(&p)?;
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
version: 7
default: deny
rules:
  - id: admins-everywhere
    action: allow
    src: [tag:admin]
    dst: ["*"]
    ports: ["*"]
  - id: own-devices
    action: allow
    src: [owner:alice]
    dst: [owner:alice]
    ports: ["*"]
  - id: web-tier
    action: allow
    src: [tag:laptop]
    dst: [tag:web]
    ports: [tcp:80, tcp:443]
  - id: app-to-db
    action: allow
    src: [tag:web]
    dst: [tag:db]
    ports: [tcp:5432]
  - id: no-ssh-to-prod-db
    action: deny
    src: ["*"]
    dst: [tag:db, tag:prod]
    ports: [tcp:22]
tests:
  - { src: tag:laptop, dst: tag:db,  port: tcp:5432, expect: deny  }
  - { src: tag:web,    dst: tag:db,  port: tcp:5432, expect: allow }
  - { src: tag:admin,  dst: tag:db,  port: tcp:22,   expect: deny  }
"#;

    fn subj(id: u8, tags: &[&str]) -> Subject {
        Subject {
            node_id: [id; 32],
            enrolled: true,
            tags: tags.iter().map(|s| s.to_string()).collect(),
            data: true,
            ..Default::default()
        }
    }

    fn policy() -> Policy {
        let f: PolicyFile = serde_yaml::from_str(EXAMPLE).unwrap();
        Policy::from_wire(&f.to_wire().unwrap()).unwrap()
    }

    #[test]
    fn example_tests_pass() {
        policy().run_tests(&|_| None).unwrap();
    }

    #[test]
    fn deny_wins_and_order_independent() {
        let p = policy();
        let admin = subj(1, &["tag:admin"]);
        let db = subj(2, &["tag:db"]);
        assert_eq!(
            p.evaluate(&admin, Dest::Node(&db), PROTO_TCP, 22).decision,
            Decision::Deny
        );
        assert_eq!(
            p.evaluate(&admin, Dest::Node(&db), PROTO_TCP, 5432)
                .decision,
            Decision::Allow
        );
        let mut rev = p.clone();
        rev.rules.reverse();
        for port in [22u16, 80, 443, 5432, 9999] {
            assert_eq!(
                p.evaluate(&admin, Dest::Node(&db), PROTO_TCP, port)
                    .decision,
                rev.evaluate(&admin, Dest::Node(&db), PROTO_TCP, port)
                    .decision
            );
        }
    }

    #[test]
    fn compiled_agrees_with_direct() {
        let p = policy();
        let nodes = vec![
            subj(1, &["tag:admin"]),
            subj(2, &["tag:db", "tag:prod"]),
            subj(3, &["tag:web"]),
            subj(4, &["tag:laptop"]),
        ];
        for me in &nodes {
            let c = Compiled::build(&p, me, &nodes, &[]);
            for o in &nodes {
                if o.node_id == me.node_id {
                    continue;
                }
                for (proto, port) in [
                    (PROTO_TCP, 22u16),
                    (PROTO_TCP, 80),
                    (PROTO_TCP, 5432),
                    (PROTO_UDP, 53),
                    (PROTO_ICMP, 0),
                ] {
                    let direct =
                        p.evaluate(o, Dest::Node(me), proto, port).decision == Decision::Allow;
                    let comp = c
                        .inbound
                        .get(&o.node_id)
                        .map(|s| s.contains(proto, port))
                        .unwrap_or(false);
                    assert_eq!(direct, comp, "{:?} -> {:?} {proto}/{port}", o.tags, me.tags);
                }
            }
        }
    }

    #[test]
    fn cidr_only_in_dst() {
        assert!(
            Policy::from_wire(&wp::Policy {
                version: 1,
                default_action: wp::Action::Deny,
                rules: Some(vec![wp::Rule {
                    id: Some("x".into()),
                    action: wp::Action::Allow,
                    src: Some(vec!["cidr:10.0.0.0/8".into()]),
                    dst: Some(vec!["*".into()]),
                    ports: Some(vec!["*".into()])
                }]),
                tests: None,
            })
            .is_err()
        );
    }

    #[test]
    fn names_and_keys_never_collide() {
        let k = crate::crypto::key_b64(&[7u8; 32]);
        assert!(matches!(
            Selector::parse(&format!("node:{k}")).unwrap(),
            Selector::NodeKey(_)
        ));
        assert!(matches!(
            Selector::parse("node:build-01").unwrap(),
            Selector::NodeName(_)
        ));
    }

    #[test]
    fn portset_algebra() {
        let mut a = PortSet::parse_spec("tcp:1-100").unwrap();
        a.subtract(&PortSet::parse_spec("tcp:50").unwrap());
        assert!(a.contains(PROTO_TCP, 49));
        assert!(!a.contains(PROTO_TCP, 50));
        assert!(a.contains(PROTO_TCP, 51));
        let mut all = PortSet::all();
        all.subtract(&PortSet::all());
        assert!(all.is_empty());
    }
}
