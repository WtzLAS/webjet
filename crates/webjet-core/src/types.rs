//! Common value types: CIDRs, names, tags, roles, time.

use anyhow::{Result, bail};
use ipnet::IpNet;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use webjet_proto as wp;

/// Wall-clock milliseconds since the Unix epoch, UTC (§18.4).
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

pub const SECOND: u64 = 1000;
pub const MINUTE: u64 = 60 * SECOND;
pub const HOUR: u64 = 60 * MINUTE;
pub const DAY: u64 = 24 * HOUR;

/// Tolerances of §18.5.
pub const SKEW_PSK_GATE: u64 = 60 * SECOND;
pub const SKEW_SHORT_RECORD: u64 = 2 * MINUTE;
pub const SKEW_HEAD: u64 = 5 * MINUTE;

pub const VALIDITY_PERIOD: u64 = 30 * DAY;

/// `[a-z0-9-]{1,32}` (§11.10.2, §6.10).
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `tag:` followed by `[a-z0-9-]{1,32}` (§14.1).
pub fn valid_tag(s: &str) -> bool {
    s.strip_prefix("tag:").is_some_and(valid_name)
}

pub fn cidr_to_net(c: &wp::Cidr) -> Option<IpNet> {
    let ip = c.addr()?;
    let net = IpNet::new(ip, c.prefix).ok()?;
    Some(net)
}

pub fn net_to_cidr(n: &IpNet) -> wp::Cidr {
    wp::Cidr::new(n.network(), n.prefix_len())
}

/// Canonical: host bits zero and address family consistent (§15.2).
pub fn canonical(c: &wp::Cidr) -> Result<IpNet> {
    let Some(n) = cidr_to_net(c) else {
        bail!("malformed CIDR")
    };
    if n.network() != n.addr() {
        bail!("CIDR {n} has host bits set");
    }
    if net_to_cidr(&n) != *c {
        bail!("CIDR {n} not canonical");
    }
    Ok(n)
}

pub fn parse_net(s: &str) -> Result<IpNet> {
    let n: IpNet = if s.contains('/') {
        s.parse()?
    } else {
        let ip: IpAddr = s.parse()?;
        IpNet::from(ip)
    };
    if n.network() != n.addr() {
        bail!("{s}: host bits set");
    }
    Ok(n)
}

pub fn overlaps(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// Map an address between a grant's `lan` and `published` prefixes, keeping
/// host bits (§11.9.1).
pub fn map_prefix(addr: IpAddr, from: &IpNet, to: &IpNet) -> Option<IpAddr> {
    if !from.contains(&addr) || from.prefix_len() != to.prefix_len() {
        return None;
    }
    match (addr, from.netmask(), to.network()) {
        (IpAddr::V4(a), IpAddr::V4(m), IpAddr::V4(t)) => {
            let host = u32::from(a) & !u32::from(m);
            Some(IpAddr::V4((u32::from(t) | host).into()))
        }
        (IpAddr::V6(a), IpAddr::V6(m), IpAddr::V6(t)) => {
            let host = u128::from(a) & !u128::from(m);
            Some(IpAddr::V6((u128::from(t) | host).into()))
        }
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub lan: IpNet,
    pub published: IpNet,
}

impl Grant {
    pub fn from_wire(g: &wp::RouteGrant) -> Result<Self> {
        let lan = canonical(&g.lan)?;
        let published = canonical(&g.published)?;
        if lan.prefix_len() == 0 || published.prefix_len() == 0 {
            bail!("/0 route grants are not allowed");
        }
        if lan.prefix_len() != published.prefix_len()
            || lan.addr().is_ipv4() != published.addr().is_ipv4()
        {
            bail!("mapped route must keep family and prefix length");
        }
        Ok(Grant { lan, published })
    }
    pub fn to_wire(&self) -> wp::RouteGrant {
        wp::RouteGrant {
            lan: net_to_cidr(&self.lan),
            published: net_to_cidr(&self.published),
        }
    }
    pub fn mapped(&self) -> bool {
        self.lan != self.published
    }
    pub fn parse(s: &str) -> Result<Self> {
        // "192.168.1.0/24" or "192.168.1.0/24=10.2.2.0/24" (lan=published)
        let (lan, published) = match s.split_once('=') {
            Some((l, p)) => (parse_net(l)?, parse_net(p)?),
            None => {
                let n = parse_net(s)?;
                (n, n)
            }
        };
        Grant::from_wire(&wp::RouteGrant {
            lan: net_to_cidr(&lan),
            published: net_to_cidr(&published),
        })
    }
}

/// Sets are sorted and without duplicates (§15.2).
pub fn sorted_unique<T: Ord + Clone>(v: &[T]) -> bool {
    v.windows(2).all(|w| w[0] < w[1])
}

pub fn sort_dedup<T: Ord>(mut v: Vec<T>) -> Vec<T> {
    v.sort();
    v.dedup();
    v
}

/// A node's roles (§4) as admins assign them: `data` and `relay` travel in
/// the NodeRecord's `roles` vector, `control` in its own field (older
/// software reads the vector and ignores the field).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Roles {
    pub data: bool,
    pub relay: bool,
    pub control: bool,
}

impl Roles {
    /// The `roles` vector of the wire format (sorted, without duplicates).
    pub fn wire(&self) -> Vec<wp::Role> {
        let mut v = Vec::new();
        if self.data {
            v.push(wp::Role::Data);
        }
        if self.relay {
            v.push(wp::Role::Relay);
        }
        v
    }

    pub fn names(&self) -> Vec<&'static str> {
        [
            (self.data, "data"),
            (self.relay, "relay"),
            (self.control, "control"),
        ]
        .into_iter()
        .filter_map(|(on, n)| on.then_some(n))
        .collect()
    }
}

/// Parses `data,relay,control` (any subset, any order).
pub fn parse_roles(s: &str) -> Result<Roles> {
    let mut r = Roles::default();
    for p in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match p {
            "data" => r.data = true,
            "relay" => r.relay = true,
            "control" => r.control = true,
            other => bail!("unknown role {other} (roles are data, relay and control)"),
        }
    }
    Ok(r)
}

/// Builds a canonical CIDR for an overlay host address.
pub fn host_cidr(ip: IpAddr) -> wp::Cidr {
    net_to_cidr(&IpNet::from(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_tags() {
        assert!(valid_name("build-01"));
        assert!(!valid_name("Build"));
        assert!(!valid_name(""));
        assert!(!valid_name(&"a".repeat(33)));
        assert!(valid_tag("tag:prod"));
        assert!(!valid_tag("prod"));
    }

    #[test]
    fn mapping_roundtrip() {
        let lan: IpNet = "192.168.1.0/24".parse().unwrap();
        let publ: IpNet = "10.2.2.0/24".parse().unwrap();
        let a: IpAddr = "192.168.1.17".parse().unwrap();
        let m = map_prefix(a, &lan, &publ).unwrap();
        assert_eq!(m, "10.2.2.17".parse::<IpAddr>().unwrap());
        assert_eq!(map_prefix(m, &publ, &lan).unwrap(), a);
    }

    #[test]
    fn canonical_cidr() {
        let c = net_to_cidr(&"10.7.0.12/32".parse().unwrap());
        assert!(canonical(&c).is_ok());
        let bad = wp::Cidr::new("10.7.0.12".parse().unwrap(), 24);
        assert!(canonical(&bad).is_err());
    }

    #[test]
    fn roles_parse() {
        let r = parse_roles("control, data").unwrap();
        assert_eq!(
            r,
            Roles {
                data: true,
                relay: false,
                control: true
            }
        );
        assert_eq!(r.wire(), vec![wp::Role::Data]);
        assert_eq!(r.names(), vec!["data", "control"]);
        assert_eq!(parse_roles("").unwrap(), Roles::default());
        assert!(parse_roles("data,admin").is_err());
    }
}
