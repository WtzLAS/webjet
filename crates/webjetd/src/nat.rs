//! Direct paths (§11.7): which local addresses are offered as candidates,
//! which peer addresses may be dialed, and port mappings asked of the
//! router (UPnP IGD, NAT-PMP, PCP).
//!
//! Another VPN is not a direct path. Addresses of tunnel interfaces
//! (point-to-point ones, and well-known VPN interface names) are not
//! offered, and a peer address the system would reach through a tunnel
//! interface is not dialed, unless the default route uses that interface
//! too (a full-tunnel VPN: then every path goes through it anyway).

use crate::config::NatCfg;
use crate::node::Node;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Interface name prefixes of VPN software and tunnels.
const TUNNEL_PREFIXES: &[&str] = &[
    "wg",
    "wireguard",
    "tun",
    "utun",
    "tap",
    "tailscale",
    "zt",
    "zerotier",
    "ppp",
    "ipsec",
    "gif",
    "stf",
    "nordlynx",
    "proton",
    "mullvad",
    "openvpn",
    "cscotun",
    "gpd",
    "pangp",
    "ham",
    "wintun",
];

/// Webjet's own interface: never a candidate, whatever the configuration.
pub fn is_overlay_if(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("webjet") || n == "wintun"
}

/// `*` matches any run of characters; case-insensitive.
pub fn glob(pattern: &str, name: &str) -> bool {
    fn rec(p: &[u8], n: &[u8]) -> bool {
        match p.split_first() {
            None => n.is_empty(),
            Some((b'*', rest)) => (0..=n.len()).any(|i| rec(rest, &n[i..])),
            Some((c, rest)) => n
                .split_first()
                .is_some_and(|(d, nr)| c.eq_ignore_ascii_case(d) && rec(rest, nr)),
        }
    }
    rec(pattern.as_bytes(), name.as_bytes())
}

/// Is this interface a tunnel that direct paths must not use?
pub fn is_tunnel(cfg: &NatCfg, name: &str, p2p: bool) -> bool {
    if is_overlay_if(name) {
        return true;
    }
    if cfg.allow_interfaces.iter().any(|p| glob(p, name)) {
        return false;
    }
    if cfg.exclude_interfaces.iter().any(|p| glob(p, name)) {
        return true;
    }
    if !cfg.skip_tunnels {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    p2p || TUNNEL_PREFIXES.iter().any(|t| lower.starts_with(t))
}

/// A publicly routable address (not private, shared, link-local,
/// documentation, loopback or multicast).
pub fn is_global(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_documentation()
                || a.is_multicast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || o[0] == 0
                || o[0] >= 240)
        }
        IpAddr::V6(a) => (a.segments()[0] & 0xe000) == 0x2000,
    }
}

fn link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => (a.segments()[0] & 0xffc0) == 0xfe80,
    }
}

pub fn excluded(cfg: &NatCfg, ip: &IpAddr) -> bool {
    cfg.exclude_cidrs.iter().any(|n| n.contains(ip))
}

#[derive(Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub ip: IpAddr,
    pub p2p: bool,
    pub loopback: bool,
}

pub fn interfaces() -> Vec<Iface> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .map(|i| Iface {
            ip: i.ip(),
            p2p: i.is_p2p(),
            loopback: i.is_loopback(),
            name: i.name,
        })
        .collect()
}

/// Local addresses to offer as HOST candidates: public ones first, then
/// LAN ones; no loopback, link-local, tunnel or excluded addresses.
pub fn candidate_ips(cfg: &NatCfg) -> Vec<IpAddr> {
    candidates_from(cfg, &interfaces())
}

fn candidates_from(cfg: &NatCfg, ifs: &[Iface]) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = ifs
        .iter()
        .filter(|i| !i.loopback && !is_tunnel(cfg, &i.name, i.p2p))
        .map(|i| i.ip)
        .filter(|a| !a.is_unspecified() && !link_local(a) && !excluded(cfg, a))
        .collect();
    v.sort_by_key(|a| (!is_global(a), a.is_ipv6(), *a));
    v.dedup();
    v.truncate(8);
    v
}

/// Addresses of local tunnel interfaces (an address a relay saw us at
/// through a VPN is no reflexive candidate either).
pub fn tunnel_ips(cfg: &NatCfg) -> Vec<IpAddr> {
    interfaces()
        .into_iter()
        .filter(|i| !i.loopback && is_tunnel(cfg, &i.name, i.p2p))
        .map(|i| i.ip)
        .collect()
}

/// The interface the system would send to `dst` from: the source address
/// a connected UDP socket gets (no packet is sent), and its interface.
fn egress(dst: IpAddr, ifs: &[Iface]) -> Option<Iface> {
    let bind: SocketAddr = match dst {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let s = std::net::UdpSocket::bind(bind).ok()?;
    s.connect(SocketAddr::new(dst, 9)).ok()?;
    let src = s.local_addr().ok()?.ip();
    ifs.iter().find(|i| i.ip == src).cloned()
}

fn via_tunnel_uncached(cfg: &NatCfg, dst: IpAddr) -> bool {
    let ifs = interfaces();
    let Some(e) = egress(dst, &ifs) else {
        return false;
    };
    if e.loopback || !is_tunnel(cfg, &e.name, e.p2p) {
        return false;
    }
    if is_overlay_if(&e.name) {
        return true;
    }
    // A full-tunnel VPN carries the default route as well.
    let probe = match dst {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    };
    egress(probe, &ifs).map(|d| d.name) != Some(e.name)
}

/// Would the system send to `dst` through a tunnel interface (and not
/// because all traffic goes through it)? Cached for 30 s.
pub fn via_tunnel(cfg: &NatCfg, dst: IpAddr) -> bool {
    static CACHE: OnceLock<Mutex<HashMap<IpAddr, (Instant, bool)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let now = Instant::now();
    if let Some((at, v)) = cache.lock().get(&dst)
        && now.duration_since(*at) < Duration::from_secs(30)
    {
        return *v;
    }
    let v = via_tunnel_uncached(cfg, dst);
    let mut c = cache.lock();
    if c.len() > 4096 {
        c.retain(|_, (at, _)| now.duration_since(*at) < Duration::from_secs(30));
    }
    c.insert(dst, (now, v));
    v
}

/// May a direct path use this peer address (HOST / REFLEXIVE candidates)?
pub fn dialable(n: &Node, addr: &SocketAddr) -> bool {
    let ip = addr.ip();
    if ip.is_unspecified() || ip.is_multicast() || addr.port() == 0 {
        return false;
    }
    let cfg = &n.cfg.nat;
    if excluded(cfg, &ip) {
        return false;
    }
    // Never into the overlay itself.
    if n.store.read().overlay_pool.iter().any(|p| p.contains(&ip)) {
        return false;
    }
    !via_tunnel(cfg, ip)
}

// ---------------------------------------------------------------- port mapping

/// A port mapping on the router: the public address peers can reach this
/// node's UDP socket at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapped {
    pub external: SocketAddr,
    pub protocol: &'static str,
}

const LEASE_S: u32 = 7200;

enum Lease {
    Pcp(crab_nat::PortMapping),
    Upnp {
        gw: igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>,
        port: u16,
    },
}

/// The default gateway and the local address toward it.
fn gateway() -> Option<(Ipv4Addr, Ipv4Addr)> {
    let gw = netdev::get_default_gateway().ok()?;
    let g = *gw.ipv4.first()?;
    let ifs = interfaces();
    let local = match egress(IpAddr::V4(g), &ifs)?.ip {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => return None,
    };
    Some((g, local))
}

async fn map_pcp(gw: Ipv4Addr, local: Ipv4Addr, port: u16) -> Option<(Lease, Mapped)> {
    let internal = std::num::NonZeroU16::new(port)?;
    let opts = crab_nat::PortMappingOptions {
        external_port: Some(internal),
        lifetime_seconds: Some(LEASE_S),
        timeout_config: Some(crab_nat::TimeoutConfig {
            initial_timeout: Duration::from_millis(250),
            max_retries: 2,
            max_retry_timeout: Some(Duration::from_secs(1)),
        }),
    };
    let m = crab_nat::PortMapping::new(
        crab_nat::GatewayAddress::IpV4(gw),
        IpAddr::V4(local),
        crab_nat::InternetProtocol::Udp,
        internal,
        opts,
    )
    .await
    .ok()?;
    let (ip, protocol) = match m.mapping_type() {
        crab_nat::PortMappingType::Pcp { external_ip, .. } => (external_ip, "pcp"),
        crab_nat::PortMappingType::NatPmp => (
            IpAddr::V4(
                crab_nat::natpmp::external_address(m.gateway(), m.timeout_config.into())
                    .await
                    .ok()?,
            ),
            "nat-pmp",
        ),
    };
    let external = SocketAddr::new(ip, m.external_port().get());
    Some((Lease::Pcp(m), Mapped { external, protocol }))
}

async fn map_upnp(local: Ipv4Addr, port: u16) -> Option<(Lease, Mapped)> {
    let mut opts = igd_next::SearchOptions::default();
    opts.timeout = Some(Duration::from_secs(2));
    let gw = igd_next::aio::tokio::search_gateway(opts).await.ok()?;
    let ip = gw.get_external_ip().await.ok()?;
    let local_addr = SocketAddr::new(IpAddr::V4(local), port);
    let ext = match gw
        .add_port(
            igd_next::PortMappingProtocol::UDP,
            port,
            local_addr,
            LEASE_S,
            "webjet",
        )
        .await
    {
        Ok(()) => port,
        Err(_) => gw
            .add_any_port(
                igd_next::PortMappingProtocol::UDP,
                local_addr,
                LEASE_S,
                "webjet",
            )
            .await
            .ok()?,
    };
    Some((
        Lease::Upnp { gw, port: ext },
        Mapped {
            external: SocketAddr::new(ip, ext),
            protocol: "upnp",
        },
    ))
}

async fn renew(lease: &mut Lease, local: Ipv4Addr, port: u16) -> bool {
    match lease {
        Lease::Pcp(m) => m.renew().await.is_ok(),
        Lease::Upnp { gw, port: ext } => gw
            .add_port(
                igd_next::PortMappingProtocol::UDP,
                *ext,
                SocketAddr::new(IpAddr::V4(local), port),
                LEASE_S,
                "webjet",
            )
            .await
            .is_ok(),
    }
}

async fn release(lease: Lease) {
    match lease {
        Lease::Pcp(m) => {
            let _ = m.try_drop().await;
        }
        Lease::Upnp { gw, port } => {
            let _ = gw
                .remove_port(igd_next::PortMappingProtocol::UDP, port)
                .await;
        }
    }
}

/// The mapping held now, released at shutdown ([`release_mapping`]).
fn lease_slot() -> &'static tokio::sync::Mutex<Option<Lease>> {
    static L: OnceLock<tokio::sync::Mutex<Option<Lease>>> = OnceLock::new();
    L.get_or_init(|| tokio::sync::Mutex::new(None))
}

/// Keep a port mapping for the UDP socket while the agent runs (when the
/// router offers one and gives a public address): PCP / NAT-PMP first,
/// then UPnP. Retried every 10 minutes when none is available; the
/// mapping is published as a PUBLIC address (`transport::my_addrs`; the
/// endpoint record is republished within seconds when addresses change).
pub async fn run_port_mapping(n: Arc<Node>) {
    if !n.cfg.nat.port_mapping {
        return;
    }
    let Some(port) = n
        .udp
        .get()
        .and_then(|u| u.local_addr().ok())
        .map(|a| a.port())
    else {
        return;
    };
    loop {
        let found = match gateway() {
            Some((gw, local)) => match map_pcp(gw, local, port).await {
                Some(x) => Some((x, local)),
                None => map_upnp(local, port).await.map(|x| (x, local)),
            },
            None => None,
        };
        let Some(((lease, m), local)) = found else {
            tokio::time::sleep(Duration::from_secs(600)).await;
            continue;
        };
        if !is_global(&m.external.ip()) {
            // Double NAT (or carrier-grade NAT): the mapping doesn't make
            // this node reachable from the internet.
            tracing::debug!(external = %m.external, "port mapping has no public address; not used");
            release(lease).await;
            tokio::time::sleep(Duration::from_secs(1800)).await;
            continue;
        }
        tracing::info!(external = %m.external, protocol = m.protocol, "router port mapping");
        *lease_slot().lock().await = Some(lease);
        *n.port_mapping.lock() = Some(m);
        loop {
            tokio::time::sleep(Duration::from_secs(u64::from(LEASE_S) / 2)).await;
            let mut slot = lease_slot().lock().await;
            let ok = match slot.as_mut() {
                Some(l) => renew(l, local, port).await,
                None => false,
            };
            if !ok {
                tracing::info!(external = %m.external, "router port mapping lost");
                *slot = None;
                break;
            }
        }
        *n.port_mapping.lock() = None;
    }
}

/// Give the router's port mapping back (at shutdown), within 2 s.
pub async fn release_mapping() {
    let lease = lease_slot().lock().await.take();
    if let Some(l) = lease {
        let _ = tokio::time::timeout(Duration::from_secs(2), release(l)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: &str, p2p: bool) -> Iface {
        Iface {
            name: name.into(),
            ip: ip.parse().unwrap(),
            p2p,
            loopback: name == "lo",
        }
    }

    #[test]
    fn globs() {
        assert!(glob("wg*", "wg0"));
        assert!(glob("WG*", "wg0"));
        assert!(glob("*vpn*", "my-vpn-1"));
        assert!(glob("eth0", "eth0"));
        assert!(!glob("eth0", "eth01"));
        assert!(!glob("wg*", "eth0"));
    }

    #[test]
    fn tunnels_are_recognised() {
        let c = NatCfg::default();
        assert!(is_tunnel(&c, "wg0", false));
        assert!(is_tunnel(&c, "utun6", false));
        assert!(is_tunnel(&c, "tailscale0", false));
        assert!(is_tunnel(&c, "myvpn", true));
        assert!(is_tunnel(&c, "webjet0", false));
        assert!(!is_tunnel(&c, "eth0", false));
        assert!(!is_tunnel(&c, "en0", false));
        let c = NatCfg {
            allow_interfaces: vec!["wg-lan".into()],
            exclude_interfaces: vec!["eth9".into()],
            ..NatCfg::default()
        };
        assert!(!is_tunnel(&c, "wg-lan", false));
        assert!(is_tunnel(&c, "eth9", false));
        let off = NatCfg {
            skip_tunnels: false,
            ..NatCfg::default()
        };
        assert!(!is_tunnel(&off, "wg0", true));
        assert!(
            is_tunnel(&off, "webjet0", false),
            "the overlay is never a candidate"
        );
    }

    #[test]
    fn candidates_put_public_first_and_skip_tunnels() {
        let ifs = vec![
            iface("lo", "127.0.0.1", false),
            iface("docker0", "172.17.0.1", false),
            iface("eth0", "10.0.0.5", false),
            iface("eth1", "47.107.180.197", false),
            iface("wg0", "10.1.1.22", false),
            iface("utun6", "10.1.1.11", true),
            iface("eth0", "fe80::1", false),
            iface("eth0", "2001:db8:1::5", false),
            iface("eth2", "192.168.1.9", false),
        ];
        let c = NatCfg {
            exclude_cidrs: vec!["192.168.1.0/24".parse().unwrap()],
            ..NatCfg::default()
        };
        let v = candidates_from(&c, &ifs);
        let s: Vec<String> = v.iter().map(|a| a.to_string()).collect();
        assert_eq!(
            s,
            ["47.107.180.197", "2001:db8:1::5", "10.0.0.5", "172.17.0.1"]
        );
    }

    #[test]
    fn global_addresses() {
        for a in ["47.107.180.197", "2606:4700::1111", "1.1.1.1"] {
            assert!(is_global(&a.parse().unwrap()), "{a}");
        }
        for a in [
            "10.1.1.1",
            "172.16.0.1",
            "192.168.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
            "::1",
            "192.0.2.1",
        ] {
            assert!(!is_global(&a.parse().unwrap()), "{a}");
        }
    }

    #[test]
    fn loopback_destination_is_not_a_tunnel() {
        assert!(!via_tunnel_uncached(
            &NatCfg::default(),
            "127.0.0.1".parse().unwrap()
        ));
    }
}
