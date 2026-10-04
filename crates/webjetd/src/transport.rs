//! Transport priorities, camouflage material and the listeners (§9.1, §9.6, §9.7).

use crate::node::Node;
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
    let s = n.store.read();
    if let Some(c) = s
        .view()
        .transport
        .as_ref()
        .and_then(|t| t.camouflage.clone())
    {
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
    let nf = n.node_file.lock();
    let domain = nf.camouflage_domain.clone()?;
    let pin = nf
        .camouflage_pin
        .as_deref()
        .and_then(webjet_core::crypto::parse_hex32)?;
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
        tokio::spawn(async move {
            let l = Arc::new(l);
            loop {
                let Ok((s, remote)) = l.listener.accept().await else {
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
    tokio::spawn(async move {
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
    tokio::spawn(async move {
        loop {
            let Ok((s, remote)) = l.accept().await else {
                continue;
            };
            refresh_anytls(&n2);
            let Some((acc, secret, website)) = n2.anytls_acceptor.lock().clone() else {
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
    for p in &n.cfg.public {
        if let Some(t) = Transport::parse(&p.transport) {
            push(p.addr, t, wp::AddrKind::Public);
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
    // Reflexive UDP addresses from relays' observations (§11.7).
    if let Some(port) = n
        .udp
        .get()
        .and_then(|u| u.local_addr().ok())
        .map(|a| a.port())
    {
        for h in n.hops.lock().values() {
            if h.transport == Transport::KcpFecTls
                && let Some(o) = *h.observed.lock()
                && o.port() != 0
            {
                push(o, Transport::KcpFecTls, wp::AddrKind::Reflexive);
            }
        }
        for ip in crate::platform::local_ips() {
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

pub fn nat_type(n: &Node) -> wp::NatType {
    let obs: Vec<std::net::SocketAddr> = n
        .hops
        .lock()
        .values()
        .filter(|h| h.transport == Transport::KcpFecTls)
        .filter_map(|h| *h.observed.lock())
        .collect();
    if obs.len() < 2 {
        return wp::NatType::Unknown;
    }
    if obs.windows(2).all(|w| w[0] == w[1]) {
        let local = n.udp.get().and_then(|u| u.local_addr().ok());
        if local
            .map(|l| {
                l.port() == obs[0].port() && crate::platform::local_ips().contains(&obs[0].ip())
            })
            .unwrap_or(false)
        {
            wp::NatType::NoNat
        } else {
            wp::NatType::Consistent
        }
    } else {
        wp::NatType::Symmetric
    }
}

#[allow(unused)]
fn _assert_state(_: &state::NodeFile) {}
