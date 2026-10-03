//! Transport priorities, camouflage material and the listeners (§9.1, §9.6, §9.7).

use crate::node::Node;
use crate::state;
use anyhow::Result;
use std::sync::Arc;
use webjet_core::crypto::Bytes32;
use webjet_core::policy::{Dest, Selector};
use webjet_net::hop::{self, Accepted, EnrollGate};
use webjet_net::kcp::UdpEndpoint;
use webjet_proto::{self as wp, Transport};

const BUILTIN: [(Transport, u8); 3] = [
    (Transport::KcpFecTls, 30),
    (Transport::AnyTls, 20),
    (Transport::TcpTls, 10),
];

fn builtin(t: Transport) -> u8 {
    BUILTIN
        .iter()
        .find(|(x, _)| *x == t)
        .map(|x| x.1)
        .unwrap_or(0)
}

/// A node's priority for a transport (§9.6): local config (for this node),
/// the peer's published priorities (for others), the tree's first matching
/// override, the tree defaults, then built-ins.
pub fn priority(n: &Node, node: &Bytes32, t: Transport) -> u8 {
    if *node == n.me {
        if let Some(p) = n.cfg.local_priority(t) {
            return p;
        }
    } else if let Some((r, _)) = n.records.lock().endpoints.get(node) {
        if let Some(p) = r
            .priorities
            .as_ref()
            .and_then(|ps| ps.iter().find(|p| p.transport == t))
        {
            return p.priority;
        }
    }
    let s = n.store.read();
    let v = s.view();
    if let Some(tc) = &v.transport {
        if let Some(info) = v.nodes.get(node) {
            let subj = v.subject(info);
            for o in tc.overrides.clone().unwrap_or_default() {
                let sels: Vec<Selector> = o
                    .select
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|s| Selector::parse(s).ok())
                    .collect();
                if selects(&sels, &subj) {
                    if let Some(p) = o
                        .values
                        .clone()
                        .unwrap_or_default()
                        .iter()
                        .find(|p| p.transport == t)
                    {
                        return p.priority;
                    }
                }
            }
        }
        if let Some(p) = tc
            .defaults
            .clone()
            .unwrap_or_default()
            .iter()
            .find(|p| p.transport == t)
        {
            return p.priority;
        }
    }
    builtin(t)
}

pub fn selects(sels: &[Selector], s: &webjet_core::policy::Subject) -> bool {
    let pol = webjet_core::policy::Policy {
        version: 0,
        default: webjet_core::policy::Decision::Deny,
        rules: vec![webjet_core::policy::Rule {
            id: "s".into(),
            action: webjet_core::policy::Decision::Allow,
            src: sels.to_vec(),
            dst: vec![Selector::Any],
            ports: webjet_core::policy::PortSet::all(),
        }],
        tests: vec![],
    };
    pol.evaluate(s, Dest::Node(s), 6, 1).decision == webjet_core::policy::Decision::Allow
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
    if let Some(c) = n.cfg.limits.rate_ceiling_mbps {
        ep.rate_ceiling_bps
            .store(c as u64 * 1_000_000, std::sync::atomic::Ordering::Relaxed);
    }
    if n.cfg.listen.kcp.is_some() {
        tracing::info!("UDP+KCP listening on {}", ep.local_addr()?);
    }
    let _ = n.udp.set(ep.clone());
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
    if let Some((_, s, w)) = cur.as_ref() {
        if s.key_pem == secret.key_pem && s.site == secret.site && *w == cam.website {
            return;
        }
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
            if h.transport == Transport::KcpFecTls {
                if let Some(o) = *h.observed.lock() {
                    if o.port() != 0 {
                        push(o, Transport::KcpFecTls, wp::AddrKind::Reflexive);
                    }
                }
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
