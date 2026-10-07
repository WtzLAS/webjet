//! Transport priorities, camouflage material and the listeners (§9.1, §9.6, §9.7).

use crate::node::Node;
#[cfg(feature = "anytls")]
use crate::state;
use anyhow::Result;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use webjet_core::crypto::Bytes32;
use webjet_net::hop::{self, Accepted, EnrollGate};
use webjet_net::kcp::UdpEndpoint;
use webjet_proto::{self as wp, Transport};

/// A node's priority for a transport (§9.6). For this node: its node-scope
/// configuration, the network's first matching override, the network's
/// value, built-in (`View::priority`). For a peer, what it published in its
/// EndpointRecord comes first: that is what the peer itself uses, also when
/// this node's copy of the tree is older.
pub fn priority(n: &Node, node: &Bytes32, t: Transport) -> u8 {
    if *node != n.me {
        // Read the published priority and release the records lock before
        // taking the store lock below.
        let published = n.records.lock().endpoints.get(node).and_then(|(r, _)| {
            r.priorities
                .as_ref()
                .and_then(|ps| ps.iter().find(|p| p.transport == t).map(|p| p.priority))
        });
        if let Some(p) = published {
            return p;
        }
    }
    n.store.read().view().priority(node, t)
}

/// This node's priorities for its EndpointRecord.
pub fn my_priorities(n: &Node) -> Vec<wp::TransportPriority> {
    Transport::ALL
        .iter()
        .map(|t| wp::TransportPriority {
            transport: *t,
            priority: priority(n, &n.me, *t),
        })
        .collect()
}

/// The camouflage settings from the tree, or from the enrollment ticket.
#[cfg(feature = "anytls")]
pub fn camouflage(n: &Node) -> Option<webjet_net::anytls::Camouflage> {
    // Clone out of the store so its lock isn't held while taking node_file's.
    let tree_cfg = n
        .store
        .read()
        .view()
        .transport
        .as_ref()
        .and_then(|t| t.camouflage.clone());
    if let Some(c) = tree_cfg {
        let chain: Vec<Vec<u8>> = c
            .certificate
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|b| b.data)
            .collect();
        if let Some(leaf) = chain.first() {
            let mut pins = vec![webjet_net::anytls::spki_pin(leaf).ok()?];
            if let Some(next) = c.next_spki {
                pins.push(next.to_bytes());
            }
            return Some(webjet_net::anytls::Camouflage {
                domain: c.domain.clone().unwrap_or_default(),
                chain,
                pins,
                website: c.mode == wp::CamouflageMode::Website,
            });
        }
    }
    let (domain, pin) = {
        let nf = n.node_file.lock();
        (nf.camouflage_domain.clone(), nf.camouflage_pin.clone())
    };
    let domain = domain?;
    let pin = pin.as_deref().and_then(webjet_core::crypto::parse_hex32)?;
    Some(webjet_net::anytls::Camouflage {
        domain,
        chain: vec![],
        pins: vec![pin],
        website: false,
    })
}

#[cfg(not(feature = "anytls"))]
pub fn camouflage(_: &Node) -> Option<()> {
    None
}

/// When the network's camouflage certificate (the leaf in the tree) expires,
/// in Unix milliseconds; `None` without one or without AnyTLS support.
pub fn camouflage_not_after(n: &Node) -> Option<u64> {
    #[cfg(feature = "anytls")]
    {
        let cam = camouflage(n)?;
        webjet_net::anytls::not_after_ms(cam.chain.first()?).ok()
    }
    #[cfg(not(feature = "anytls"))]
    {
        let _ = n;
        None
    }
}

/// The enrollment credentials a controller accepts at its gate.
pub struct ControllerEnrollGate(pub Arc<Node>);

impl EnrollGate for ControllerEnrollGate {
    fn enroll_keys(&self) -> Vec<Bytes32> {
        match self.0.controller.get() {
            Some(c) => c.pending_token_hashes(),
            None => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------- listeners

/// Hop TLS handshakes in progress per source IP (§16.2), for the TCP
/// listeners; KCP counts its own.
#[derive(Default)]
pub struct HandshakeGate(Mutex<HashMap<std::net::IpAddr, u32>>);

/// One admitted handshake; frees its slot when dropped.
pub struct HandshakeSlot<'a>(&'a HandshakeGate, std::net::IpAddr);

impl HandshakeGate {
    pub fn admit(&self, ip: std::net::IpAddr, limit: u64) -> Option<HandshakeSlot<'_>> {
        let mut m = self.0.lock();
        let c = m.entry(ip).or_insert(0);
        if u64::from(*c) >= limit {
            return None;
        }
        *c += 1;
        Some(HandshakeSlot(self, ip))
    }
}

impl Drop for HandshakeSlot<'_> {
    fn drop(&mut self) {
        let mut m = self.0.0.lock();
        if let Some(c) = m.get_mut(&self.1) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                m.remove(&self.1);
            }
        }
    }
}

/// Re-read the limits that live in the transport layer (after a tree change).
pub fn apply_limits(n: &Node) {
    if let Some(ep) = n.udp.get() {
        let ceiling = crate::metrics::limit_opt(n, "rate_ceiling_mbps").unwrap_or(0);
        ep.rate_ceiling_bps.store(
            ceiling.saturating_mul(1_000_000),
            std::sync::atomic::Ordering::Relaxed,
        );
        let per_ip = crate::metrics::limit(n, "hop_handshakes_per_ip");
        ep.per_ip_limit.store(
            u32::try_from(per_ip).unwrap_or(u32::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

pub async fn start_listeners(n: &Arc<Node>) -> Result<()> {
    if let Some(addr) = n.cfg.listen.tls {
        let l = hop::TlsListener::bind(addr).await?;
        tracing::info!("TCP+TLS listening on {addr}");
        let n2 = n.clone();
        n.tasks.service("tls-listener", async move {
            let l = Arc::new(l);
            loop {
                let Ok((s, remote)) = l.listener.accept().await else {
                    // Out of file descriptors, most likely: don't spin.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                };
                let n3 = n2.clone();
                let l2 = l.clone();
                tokio::spawn(async move {
                    let limit = crate::metrics::limit(&n3, "hop_handshakes_per_ip");
                    let Some(_slot) = n3.hop_handshakes.admit(remote.ip(), limit) else {
                        return; // silently drop (§16.2)
                    };
                    let gate = ControllerEnrollGate(n3.clone());
                    let eg: Option<&dyn EnrollGate> = if n3.is_controller() {
                        Some(&gate)
                    } else {
                        None
                    };
                    match hop::accept_tls(s, remote, &n3.kp, n3.trust(), &n3.epochs, &l2.replay, eg)
                        .await
                    {
                        Ok(Accepted::Hop(est)) => {
                            if let Err(e) = n3.register_hop(est, false) {
                                tracing::debug!("inbound hop from {remote}: {e}");
                            }
                        }
                        Ok(Accepted::Enroll(io, remote)) => {
                            if let Some(c) = n3.controller.get() {
                                c.clone().serve_enrollment(io, remote).await;
                            }
                        }
                        Err(e) => tracing::trace!("inbound TLS from {remote}: {e}"),
                    }
                });
            }
        });
    }
    // One UDP socket both listens and dials (§11.7).
    let udp_addr = n
        .cfg
        .listen
        .kcp
        .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
    let root = n.store.read().root;
    // Always accept: hole-punched hops arrive on the same socket (§11.7).
    let ep = UdpEndpoint::bind(udp_addr, &root, n.epochs.clone(), true).await?;
    let _ = n.udp.set(ep.clone());
    apply_limits(n);
    if n.cfg.listen.kcp.is_some() {
        tracing::info!("UDP+KCP listening on {}", ep.local_addr()?);
    }
    let n2 = n.clone();
    n.tasks.service("kcp-accept", async move {
        loop {
            let c = {
                let mut rx = ep.accept_rx.lock().await;
                match rx.recv().await {
                    Some(c) => c,
                    None => break,
                }
            };
            let n3 = n2.clone();
            tokio::spawn(async move {
                let remote = c.peer;
                match hop::accept_kcp(c, &n3.kp, n3.trust()).await {
                    Ok(est) => {
                        if let Err(e) = n3.register_hop(est, false) {
                            tracing::debug!("inbound KCP hop from {remote}: {e}");
                        }
                    }
                    Err(e) => tracing::trace!("inbound KCP from {remote}: {e}"),
                }
            });
        }
    });
    #[cfg(feature = "anytls")]
    if let Some(addr) = n.cfg.listen.anytls {
        start_anytls(n, addr).await?;
    }
    Ok(())
}

#[cfg(feature = "anytls")]
async fn start_anytls(n: &Arc<Node>, addr: std::net::SocketAddr) -> Result<()> {
    let l = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("TCP+AnyTLS listening on {addr}");
    let n2 = n.clone();
    n.tasks.service("anytls-listener", async move {
        const RETRY: std::time::Duration = std::time::Duration::from_secs(1);
        let mut last_try: Option<std::time::Instant> = None;
        loop {
            let Ok((s, remote)) = l.accept().await else {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            };
            // The acceptor is refreshed when the tree or the camouflage
            // secret changes (agent `secrets`), not per connection: that
            // reads a file. Until there is one, retry at most once a second.
            let mut acceptor = n2.anytls_acceptor.lock().clone();
            if acceptor.is_none() && last_try.is_none_or(|t| t.elapsed() >= RETRY) {
                last_try = Some(std::time::Instant::now());
                refresh_anytls(&n2);
                acceptor = n2.anytls_acceptor.lock().clone();
            }
            let Some((acc, secret, website)) = acceptor else {
                drop(s);
                continue;
            };
            let n3 = n2.clone();
            tokio::spawn(async move {
                let limit = crate::metrics::limit(&n3, "hop_handshakes_per_ip");
                let Some(_slot) = n3.hop_handshakes.admit(remote.ip(), limit) else {
                    return;
                };
                let enroll: Vec<Bytes32> = n3
                    .controller
                    .get()
                    .map(|c| c.pending_token_hashes())
                    .unwrap_or_default();
                let ctx = webjet_net::anytls::AcceptCtx {
                    acceptor: &acc,
                    secret: &secret,
                    website,
                    kp: &n3.kp,
                    trust: n3.trust(),
                    epochs: &n3.epochs,
                    enroll_keys: &enroll,
                };
                match webjet_net::anytls::accept(s, remote, &ctx).await {
                    Ok(webjet_net::anytls::AnyAccepted::Hop(est)) => {
                        if let Err(e) = n3.register_hop(est, false) {
                            tracing::debug!("inbound AnyTLS hop from {remote}: {e}");
                        }
                    }
                    Ok(webjet_net::anytls::AnyAccepted::Enroll(io, remote)) => {
                        if let Some(c) = n3.controller.get() {
                            c.clone().serve_enrollment(io, remote).await;
                        }
                    }
                    Ok(webjet_net::anytls::AnyAccepted::Camouflaged) => {}
                    Err(e) => tracing::trace!("inbound AnyTLS from {remote}: {e}"),
                }
            });
        }
    });
    Ok(())
}

/// (Re)build the AnyTLS acceptor from the tree's certificate and the
/// camouflage secret fetched from a controller (§9.7.2).
#[cfg(feature = "anytls")]
pub fn refresh_anytls(n: &Arc<Node>) {
    let Some(cam) = camouflage(n) else { return };
    if cam.chain.is_empty() {
        return;
    }
    let secret = match state::load_json::<state::CamouflageFile>(&n.paths.camouflage()) {
        Ok(Some(f)) => webjet_net::anytls::CamouflageSecret {
            key_pem: f.key_pem,
            site: f.site,
        },
        _ => return,
    };
    let mut cur = n.anytls_acceptor.lock();
    if let Some((_, s, w)) = cur.as_ref()
        && s.key_pem == secret.key_pem
        && s.site == secret.site
        && *w == cam.website
    {
        return;
    }
    match webjet_net::anytls::acceptor(&cam, &secret) {
        Ok(a) => *cur = Some((Arc::new(a), secret, cam.website)),
        Err(e) => tracing::warn!("AnyTLS certificate/key mismatch: {e}"),
    }
}

#[cfg(not(feature = "anytls"))]
pub fn refresh_anytls(_: &Arc<Node>) {}

/// Advertised addresses (§6.2): configured public addresses, listening
/// sockets bound to specific IPs, and reflexive addresses seen by relays.
pub fn my_addrs(n: &Node) -> Vec<wp::EndpointAddr> {
    let mut v: Vec<wp::EndpointAddr> = Vec::new();
    let mut push = |a: std::net::SocketAddr, t: Transport, kind: wp::AddrKind| {
        if a.ip().is_unspecified() || a.port() == 0 {
            return;
        }
        let e = wp::EndpointAddr {
            addr: Some(wp::SockAddr::from_sock(a)),
            transport: t,
            kind,
            priority: priority(n, &n.me, t),
        };
        if !v
            .iter()
            .any(|x| x.addr == e.addr && x.transport == e.transport)
        {
            v.push(e);
        }
    };
    let resolved = n.public_resolved.lock().clone();
    for p in &n.cfg.public {
        let Some(t) = Transport::parse(&p.transport) else {
            continue;
        };
        match p.addr.ip() {
            Some(a) => push(a, t, wp::AddrKind::Public),
            None => {
                for ip in resolved.get(&p.addr.host).into_iter().flatten() {
                    push(
                        std::net::SocketAddr::new(*ip, p.addr.port),
                        t,
                        wp::AddrKind::Public,
                    );
                }
            }
        }
    }
    if let Some(a) = n.cfg.listen.tls {
        push(a, Transport::TcpTls, wp::AddrKind::Public);
    }
    if let Some(a) = n.cfg.listen.anytls {
        push(a, Transport::AnyTls, wp::AddrKind::Public);
    }
    if let Some(a) = n.cfg.listen.kcp {
        push(a, Transport::KcpFecTls, wp::AddrKind::Public);
    }
    // The router's port mapping, reachable from anywhere (§11.7).
    if let Some(m) = *n.port_mapping.lock() {
        push(m.external, Transport::KcpFecTls, wp::AddrKind::Public);
    }
    // Reflexive UDP addresses from relays' observations (§11.7), then the
    // interface addresses; never those of tunnels (another VPN is no
    // direct path) or excluded ones.
    if let Some(port) = n
        .udp
        .get()
        .and_then(|u| u.local_addr().ok())
        .map(|a| a.port())
    {
        for o in observed(n) {
            push(o, Transport::KcpFecTls, wp::AddrKind::Reflexive);
        }
        for ip in crate::nat::candidate_ips(&n.cfg.nat) {
            push(
                std::net::SocketAddr::new(ip, port),
                Transport::KcpFecTls,
                wp::AddrKind::Host,
            );
        }
    }
    v.retain(|a| a.priority > 0);
    v
}

/// Keep the addresses of the DNS names in webjetd.toml `[[public]]` (a
/// dynamic-DNS name for a home connection, say) current: resolved at start
/// and every 5 minutes; the endpoint record is republished when they
/// change. A failed lookup keeps the last addresses.
pub async fn resolve_public(n: Arc<Node>) {
    let mut names: Vec<(String, u16)> = n
        .cfg
        .public
        .iter()
        .filter_map(|p| p.addr.name().map(|h| (h.to_string(), p.addr.port)))
        .collect();
    names.sort();
    names.dedup_by(|a, b| a.0 == b.0);
    if names.is_empty() {
        return;
    }
    let mut first = true;
    loop {
        let mut changed = false;
        for (host, port) in &names {
            let ips = match tokio::net::lookup_host((host.as_str(), *port)).await {
                Ok(it) => {
                    let mut v: Vec<std::net::IpAddr> = it.map(|a| a.ip()).collect();
                    v.sort();
                    v.dedup();
                    v
                }
                Err(e) => {
                    if first {
                        tracing::warn!(host = %host, "[[public]] address doesn't resolve: {e}");
                    }
                    continue;
                }
            };
            if ips.is_empty() {
                continue;
            }
            let mut r = n.public_resolved.lock();
            if r.get(host) != Some(&ips) {
                tracing::info!(host = %host, addrs = ?ips, "[[public]] address resolved");
                r.insert(host.clone(), ips);
                changed = true;
            }
        }
        if changed {
            crate::gossip::publish_endpoint(&n, true);
        }
        first = false;
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;
    }
}

/// Our UDP address as relays saw it, over hops not carried by a tunnel
/// interface (a relay reached through another VPN sees its address).
fn observed(n: &Node) -> Vec<std::net::SocketAddr> {
    let hops: Vec<(std::net::SocketAddr, Option<std::net::SocketAddr>)> = n
        .hops
        .lock()
        .values()
        .filter(|h| h.transport == Transport::KcpFecTls)
        .map(|h| (h.remote, *h.observed.lock()))
        .collect();
    let tunnels = crate::nat::tunnel_ips(&n.cfg.nat);
    let mut v: Vec<std::net::SocketAddr> = hops
        .into_iter()
        .filter(|(remote, _)| !crate::nat::via_tunnel(&n.cfg.nat, remote.ip()))
        .filter_map(|(_, o)| o)
        .filter(|o| {
            o.port() != 0
                && !tunnels.contains(&o.ip())
                && !crate::nat::excluded(&n.cfg.nat, &o.ip())
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// The NAT type as the CLI and webjet-app show it.
pub fn nat_name(t: wp::NatType) -> &'static str {
    match t {
        wp::NatType::NoNat => "none",
        wp::NatType::Consistent => "consistent",
        wp::NatType::Symmetric => "symmetric",
        _ => "unknown",
    }
}

/// Advertised addresses for JSON: `{addr, transport, kind}`.
pub fn addrs_json(addrs: &[wp::EndpointAddr]) -> Vec<serde_json::Value> {
    addrs
        .iter()
        .filter_map(|a| {
            Some(serde_json::json!({
                "addr": a.addr.as_ref()?.to_sock()?.to_string(),
                "transport": a.transport.name(),
                "kind": match a.kind {
                    wp::AddrKind::Public => "public",
                    wp::AddrKind::Host => "host",
                    wp::AddrKind::Reflexive => "reflexive",
                },
            }))
        })
        .collect()
}

/// How this node's NAT maps UDP (§11.7), from what relays observe: the
/// same address and port everywhere is consistent (or no NAT at all when
/// it is our own address and port), different ports are symmetric.
/// Only relays count (§11.7): a data node's observation can come from a
/// hole-punched flow whose mapping a NAT had to change.
pub fn nat_type(n: &Node) -> wp::NatType {
    // Clone the hops first: the store lock is taken below (lock order).
    let hops: Vec<(Bytes32, std::net::SocketAddr, Option<std::net::SocketAddr>)> = n
        .hops
        .lock()
        .values()
        .filter(|h| h.transport == Transport::KcpFecTls)
        .map(|h| (h.peer, h.remote, *h.observed.lock()))
        .collect();
    let relays: Vec<Bytes32> = {
        let s = n.store.read();
        let v = s.view();
        hops.iter()
            .filter(|(p, _, _)| v.nodes.get(p).is_some_and(|x| x.relay))
            .map(|(p, _, _)| *p)
            .collect()
    };
    let obs: Vec<std::net::SocketAddr> = hops
        .into_iter()
        .filter(|(p, remote, _)| {
            relays.contains(p) && !crate::nat::via_tunnel(&n.cfg.nat, remote.ip())
        })
        .filter_map(|(_, _, o)| o)
        .collect();
    let local = n.udp.get().and_then(|u| u.local_addr().ok());
    classify_nat(
        &obs,
        local.map(|l| l.port()),
        &crate::nat::candidate_ips(&n.cfg.nat),
    )
}

fn classify_nat(
    obs: &[std::net::SocketAddr],
    local_port: Option<u16>,
    local_ips: &[std::net::IpAddr],
) -> wp::NatType {
    let Some(first) = obs.first() else {
        return wp::NatType::Unknown;
    };
    if obs.iter().any(|o| o != first) {
        return wp::NatType::Symmetric;
    }
    if local_port == Some(first.port()) && local_ips.contains(&first.ip()) {
        return wp::NatType::NoNat;
    }
    if obs.len() < 2 {
        return wp::NatType::Unknown;
    }
    wp::NatType::Consistent
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_classification() {
        let a: std::net::SocketAddr = "47.1.2.3:6969".parse().unwrap();
        let b: std::net::SocketAddr = "47.1.2.3:7000".parse().unwrap();
        let ip = a.ip();
        assert_eq!(classify_nat(&[], Some(6969), &[ip]), wp::NatType::Unknown);
        // One relay seeing our own address and port: no NAT.
        assert_eq!(classify_nat(&[a], Some(6969), &[ip]), wp::NatType::NoNat);
        assert_eq!(classify_nat(&[a], Some(5000), &[]), wp::NatType::Unknown);
        assert_eq!(
            classify_nat(&[a, a], Some(5000), &[]),
            wp::NatType::Consistent
        );
        assert_eq!(
            classify_nat(&[a, b], Some(6969), &[ip]),
            wp::NatType::Symmetric
        );
    }
}
