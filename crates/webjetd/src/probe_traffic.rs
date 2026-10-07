//! Probe traffic: what a node sends and receives only to measure its links
//! and circuits, and what that costs on the wire.
//!
//! - **Hop keepalives** (§11.2): on every hop, each end sends a `Keepalive`
//!   every [`node::KEEPALIVE`] and answers the other's with a
//!   `KeepaliveAck`.
//! - **End-to-end probes** (§11.4): on every circuit of a recently used
//!   session that isn't busy, each end sends a `PROBE` every
//!   [`crate::paths`] probe interval (1 s) and answers the other's with a
//!   `PROBE_ACK`; every relay on the circuit forwards both.
//!
//! `keepalives_per_hop` runs the agent's own keepalive task and control
//! handler on a pair of test hops and checks the cadence and record sizes.
//! `wire_cost` carries exactly those records, at that cadence, over real
//! hop transports on loopback (UDP+KCP+FEC+TLS, TCP+TLS) and reports the
//! bytes on the wire. It takes real time, so it is ignored by default:
//!
//!   cargo test -p webjetd --lib probe_traffic -- --ignored --nocapture
//!
//! (`WEBJET_PROBE_SECS` sets the measured window, default 30.) The
//! end-to-end probe cadence on a real circuit is measured in
//! `e2e::handshake_tests::probe_traffic_on_an_idle_circuit`.

use crate::node;
use crate::testnode::{self, Cluster};
use std::sync::Arc;
use std::time::Duration;
use webjet_core::crypto::{self, Bytes32};
use webjet_core::frames::{self, SessionKey, ftype};
use webjet_core::testutil::NodeSpec;
use webjet_net::hop::{self, rec};
use webjet_proto::{self as wp, Decodable, Encodable, HopMsg, Transport};

/// The records probe traffic consists of, as the agent encodes them
/// (hop record header included).
struct Records {
    /// A `Keepalive` from an edge node: it carries the store digest.
    ka_edge: Vec<u8>,
    /// A `Keepalive` from a relay or controller: no digest.
    ka_core: Vec<u8>,
    ka_ack: Vec<u8>,
    /// A `PROBE` relay frame as a hop record (`PROBE_ACK` echoes the probe
    /// payload, so it is the same size).
    probe: Vec<u8>,
    probe_ack: Vec<u8>,
}

fn records() -> Records {
    let ka = |digest: Option<Bytes32>| {
        node::ctl(HopMsg::Keepalive(Box::new(wp::Keepalive {
            seq: 123_456,
            echo_us: 3_600_000_000,
            wall_ms: 1_800_000_000_000,
            digest: digest.map(|d| crypto::k32(&d)),
            flags: node::KA_ONE_SIDED,
            observed_addr: None,
        })))
        .expect("record")
    };
    let ka_ack = node::ctl(HopMsg::KeepaliveAck(Box::new(wp::KeepaliveAck {
        seq: 123_456,
        echo_us: 3_600_000_000,
        wall_ms: 1_800_000_000_000,
        observed_addr: Some(wp::SockAddr::from_sock(
            "[2001:db8::1]:40000".parse().expect("address"),
        )),
        digest: None,
    })))
    .expect("record");
    let key = SessionKey::new([9; 32]);
    let relay = |ty: u8| {
        // A probe from a circuit's source (echoing the last answer), and
        // the answer to one.
        let p = if ty == ftype::PROBE {
            wp::Probe {
                route_tag: 0xabab_abab_abab_abab,
                sent_at_us: 3_600_000_000,
                echo_us: 3_599_000_000,
                held_us: 4_000_000,
                ..Default::default()
            }
        } else {
            wp::Probe {
                route_tag: 0xabab_abab_abab_abab,
                sent_at_us: 3_600_000_000,
                reply_at_us: 3_600_050_000,
                ..Default::default()
            }
        };
        let f = key
            .seal(ty, 0x0102_0304, 1 << 20, &p.encode_bytes())
            .expect("seal");
        let frame = [&frames::relay_header(77, 16, 0)[..], &f].concat();
        hop::encode_record(rec::RELAY, &frame).expect("record")
    };
    Records {
        ka_edge: ka(Some([7; 32])),
        ka_core: ka(None),
        ka_ack,
        probe: relay(ftype::PROBE),
        probe_ack: relay(ftype::PROBE_ACK),
    }
}

fn control_msgs(record: &[u8]) -> Vec<HopMsg> {
    assert_eq!(record.first(), Some(&rec::CONTROL), "uncompressed control");
    wp::HopControl::decode_bytes(&record[4..])
        .expect("control record")
        .msg
        .into_iter()
        .collect()
}

#[derive(Default, Debug, Clone, Copy, PartialEq)]
struct Tally {
    msgs: u64,
    bytes: u64,
}

impl Tally {
    fn add(&mut self, bytes: usize) {
        self.msgs += 1;
        self.bytes += bytes as u64;
    }
}

/// Keepalives and acks one end of a hop sent.
#[derive(Default, Debug, Clone, Copy)]
struct HopSent {
    ka: Tally,
    ack: Tally,
    other: Tally,
}

/// The agent's keepalive task and control handler on an edge↔relay hop
/// (§11.2): only the dialer (the edge) sends keepalives, every 2 s for the
/// hop's first 30 s and every 5 s once it is stable; the relay answers
/// each and sends none of its own.
#[tokio::test(start_paused = true)]
async fn keepalives_per_hop() {
    let mut c = Cluster::new();
    let e = c.data_node("edge", "10.7.0.2", &[]);
    let r = c.enroll(NodeSpec {
        name: "relay",
        ip: "10.7.0.3",
        roles: &[wp::Role::Data, wp::Role::Relay],
        ..Default::default()
    });
    let (en, _d1) = testnode::node(&mut c, e.0, e.1.clone());
    let (rn, _d2) = testnode::node(&mut c, r.0, r.1.clone());
    let (he, mut xe) = en.test_hop_dir(r.0, Transport::KcpFecTls, true);
    let (hr, mut xr) = rn.test_hop_dir(e.0, Transport::KcpFecTls, false);
    tokio::spawn(node::keepalive(en.clone(), he.clone()));
    tokio::spawn(node::keepalive(rn.clone(), hr.clone()));

    let mut sent = [HopSent::default(), HopSent::default()];
    let mut phase = Vec::new();
    let t0 = tokio::time::Instant::now();
    for until in [Duration::from_secs(30), Duration::from_secs(90)] {
        while t0.elapsed() < until {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let [se, sr] = &mut sent;
            for (rx, sent, to_node, to_hop) in [(&mut xe, se, &rn, &hr), (&mut xr, sr, &en, &he)] {
                while let Ok(record) = rx.ctl.try_recv() {
                    for m in control_msgs(&record) {
                        match &m {
                            HopMsg::Keepalive(_) => sent.ka.add(record.len()),
                            HopMsg::KeepaliveAck(_) => sent.ack.add(record.len()),
                            _ => sent.other.add(record.len()),
                        }
                        node::handle_control(to_node, to_hop, m)
                            .await
                            .expect("handled");
                    }
                    *to_hop.last_rx.lock() = std::time::Instant::now();
                }
            }
        }
        phase.push(std::mem::take(&mut sent));
    }
    let rs = records();
    for (what, p) in ["first 30 s", "next 60 s (stable)"].iter().zip(&phase) {
        println!("keepalive records, {what} (one hop, edge ↔ relay):");
        println!("  edge  → relay: {:?}", p[0]);
        println!("  relay → edge : {:?}", p[1]);
    }
    let (fast, slow) = (&phase[0], &phase[1]);
    // The edge keeps the hop alive for both; the relay only answers.
    assert!(fast[0].ka.msgs.abs_diff(30 / 2) <= 1, "{:?}", fast[0]);
    assert!(slow[0].ka.msgs.abs_diff(60 / 5) <= 1, "{:?}", slow[0]);
    for p in &phase {
        assert_eq!(p[1].ka.msgs, 0, "the relay sends no keepalives");
        assert_eq!(p[1].ack.msgs, p[0].ka.msgs, "each answered");
        assert_eq!(p[0].ack.msgs, 0);
        assert_eq!(p[0].other.msgs + p[1].other.msgs, 0);
    }
    // Sizes: an edge keepalive carries the digest (now and then the
    // relay's address too); a relay's ack carries no digest.
    assert!(slow[0].ka.bytes >= slow[0].ka.msgs * rs.ka_edge.len() as u64);
    assert_eq!(slow[1].ack.bytes, slow[1].ack.msgs * rs.ka_ack.len() as u64);
    // The relay learned the edge's clock and keeps quiet.
    assert!(hr.peer_keeps.lock().is_some());
}

/// What each probe record is made of, for the report.
#[test]
fn probe_record_sizes() {
    let r = records();
    println!(
        "hop records: keepalive edge {} B, keepalive relay/controller {} B, keepalive ack {} B",
        r.ka_edge.len(),
        r.ka_core.len(),
        r.ka_ack.len()
    );
    println!(
        "e2e probe {} B, answer {} B (hop records: e2e frame {} B + relay header {} B + record header 4 B + payload)",
        r.probe.len(),
        r.probe_ack.len(),
        frames::OVERHEAD,
        frames::RELAY_HEADER,
    );
    // Control records this small are never compressed (§9.8).
    assert!(r.ka_edge.len() < 4 + webjet_core::compress::MIN_CONTROL);
    // Compact probes: under the 104 bytes of a probe with a route id.
    assert!(
        r.probe.len() < 104 && r.probe_ack.len() < 104,
        "compact probes"
    );
}

// ---------------------------------------------------------------- on the wire

mod wire {
    //! The agent's own hop tasks (writer, reader, keepalive), path loop and
    //! session timers on two nodes joined by a real hop on loopback, through
    //! a proxy that counts what crosses it.

    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use webjet_core::crypto::KeyPair;
    use webjet_net::gate::{Epochs, SharedEpochs};
    use webjet_net::hop::{Accepted, Established, TlsListener};
    use webjet_net::kcp::UdpEndpoint;
    use webjet_net::tls::TrustAll;

    /// Bytes and packets (datagrams, or TCP reads) one way through a proxy.
    #[derive(Default)]
    struct Dir {
        packets: AtomicU64,
        bytes: AtomicU64,
    }

    impl Dir {
        fn add(&self, len: usize) {
            self.packets.fetch_add(1, Ordering::Relaxed);
            self.bytes.fetch_add(len as u64, Ordering::Relaxed);
        }
        fn take(&self) -> (u64, u64) {
            (
                self.packets.swap(0, Ordering::Relaxed),
                self.bytes.swap(0, Ordering::Relaxed),
            )
        }
    }

    /// The traffic between the dialer (a) and the listener (b).
    #[derive(Default)]
    struct Meter {
        a_to_b: Dir,
        b_to_a: Dir,
    }

    fn epochs() -> SharedEpochs {
        let mut e = Epochs::default();
        e.keys.insert(4, [4; 32]);
        e.current = 4;
        Arc::new(parking_lot::RwLock::new(e))
    }

    /// A UDP relay between `a` (whoever sends to it first) and `b`.
    async fn udp_proxy(b: SocketAddr, m: Arc<Meter>) -> SocketAddr {
        let p = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let addr = p.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut buf, mut a) = (vec![0u8; 65536], None);
            while let Ok((len, from)) = p.recv_from(&mut buf).await {
                if from == b {
                    m.b_to_a.add(len);
                    if let Some(a) = a {
                        let _ = p.send_to(&buf[..len], a).await;
                    }
                } else {
                    a = Some(from);
                    m.a_to_b.add(len);
                    let _ = p.send_to(&buf[..len], b).await;
                }
            }
        });
        addr
    }

    /// A TCP relay to `b` for one connection.
    async fn tcp_proxy(b: SocketAddr, m: Arc<Meter>) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = l.local_addr().expect("addr");
        tokio::spawn(async move {
            let Ok((a, _)) = l.accept().await else { return };
            let Ok(bs) = TcpStream::connect(b).await else {
                return;
            };
            let _ = a.set_nodelay(true);
            let _ = bs.set_nodelay(true);
            let (mut ar, mut aw) = a.into_split();
            let (mut br, mut bw) = bs.into_split();
            let m2 = m.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                while let Ok(n) = ar.read(&mut buf).await {
                    if n == 0 || bw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    m2.a_to_b.add(n);
                }
            });
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = br.read(&mut buf).await {
                if n == 0 || aw.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                m.b_to_a.add(n);
            }
        });
        addr
    }

    /// A UDP+KCP+FEC+TLS hop from `a` to `b` through a counting proxy.
    async fn kcp_pair(a: KeyPair, b: KeyPair) -> (Established, Established, Arc<Meter>) {
        let bp = b.public();
        let ea = UdpEndpoint::bind("127.0.0.1:0".parse().expect("a"), &[1; 32], epochs(), false)
            .await
            .expect("bind");
        let eb = UdpEndpoint::bind("127.0.0.1:0".parse().expect("a"), &[1; 32], epochs(), true)
            .await
            .expect("bind");
        let m = Arc::new(Meter::default());
        let via = udp_proxy(eb.local_addr().expect("addr"), m.clone()).await;
        let srv = tokio::spawn(async move {
            let c = eb.accept_rx.lock().await.recv().await.expect("session");
            let h = hop::accept_kcp(c, &b, Arc::new(TrustAll))
                .await
                .expect("accept");
            (h, eb)
        });
        let ha = hop::dial_kcp(&ea, via, &a, vec![bp], Arc::new(TrustAll))
            .await
            .expect("dial");
        let (hb, eb) = srv.await.expect("task");
        // The endpoints must outlive the hops.
        std::mem::forget((ea, eb));
        (ha, hb, m)
    }

    /// A TCP+TLS hop from `a` to `b` through a counting proxy.
    async fn tls_pair(a: KeyPair, b: KeyPair) -> (Established, Established, Arc<Meter>) {
        let bp = b.public();
        let l = TlsListener::bind("127.0.0.1:0".parse().expect("a"))
            .await
            .expect("bind");
        let m = Arc::new(Meter::default());
        let via = tcp_proxy(l.listener.local_addr().expect("addr"), m.clone()).await;
        let ep = epochs();
        let srv = tokio::spawn(async move {
            let (s, r) = l.listener.accept().await.expect("accept");
            match hop::accept_tls(s, r, &b, Arc::new(TrustAll), &ep, &l.replay, None)
                .await
                .expect("accept")
            {
                Accepted::Hop(h) => h,
                Accepted::Enroll(..) => panic!("not an enrollment"),
            }
        });
        let ha = hop::dial_tls(via, &a, vec![bp], Arc::new(TrustAll), 4, &[4; 32])
            .await
            .expect("dial");
        (ha, srv.await.expect("task"), m)
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Kind {
        Kcp,
        Tls,
    }

    struct Scenario {
        name: &'static str,
        kind: Kind,
        /// A session between the two, used once at the start, then idle.
        session: bool,
    }

    struct Outcome {
        name: &'static str,
        kind: Kind,
        secs: f64,
        /// (packets, bytes) edge → relay and back.
        a_to_b: (u64, u64),
        b_to_a: (u64, u64),
    }

    /// An edge node dials a relay; both run the agent's hop, path and
    /// session tasks.
    async fn run(s: Scenario, warm: Duration, window: Duration) -> Outcome {
        let mut c = Cluster::new();
        let e = c.data_node("edge", "10.7.0.2", &[]);
        let r = c.enroll(NodeSpec {
            name: "relay",
            ip: "10.7.0.3",
            roles: &[wp::Role::Data, wp::Role::Relay],
            ..Default::default()
        });
        c.set_policy(wp::Policy {
            default_action: wp::Action::Allow,
            ..Default::default()
        })
        .expect("policy");
        let (en, _d1) = testnode::node(&mut c, e.0, e.1.clone());
        let (rn, _d2) = testnode::node(&mut c, r.0, r.1.clone());
        let (ha, hb, m) = match s.kind {
            Kind::Kcp => kcp_pair(e.1.clone(), r.1.clone()).await,
            Kind::Tls => tls_pair(e.1.clone(), r.1.clone()).await,
        };
        en.register_hop(ha, true).expect("edge hop");
        rn.register_hop(hb, false).expect("relay hop");
        let mut tasks = Vec::new();
        for n in [&en, &rn] {
            tasks.push(tokio::spawn(crate::paths::run(n.clone())));
            tasks.push(tokio::spawn(crate::e2e::run(n.clone())));
        }
        let (_dpe, _tune) = crate::dataplane::Dataplane::for_test(&en);
        let (_dpr, mut tunr) = crate::dataplane::Dataplane::for_test(&rn);
        if s.session {
            let p = webjet_core::testutil::packets::udp4(
                [10, 7, 0, 2],
                [10, 7, 0, 3],
                4000,
                5000,
                b"hello",
            );
            crate::e2e::send(&en, &r.0, ftype::DATA, &p, 0);
            let got = tokio::time::timeout(Duration::from_secs(5), tunr.recv()).await;
            assert_eq!(got.ok().flatten(), Some(p), "the session works");
        }
        tokio::time::sleep(warm).await;
        m.a_to_b.take();
        m.b_to_a.take();
        let t = std::time::Instant::now();
        tokio::time::sleep(window).await;
        let o = Outcome {
            name: s.name,
            kind: s.kind,
            secs: t.elapsed().as_secs_f64(),
            a_to_b: m.a_to_b.take(),
            b_to_a: m.b_to_a.take(),
        };
        for t in tasks {
            t.abort();
        }
        for n in [&en, &rn] {
            for h in n.hops.lock().values() {
                h.retire();
            }
        }
        drop((en, rn));
        o
    }

    /// Probe traffic on the wire between an edge node and its relay, as
    /// the agent produces it: hop keepalives, end-to-end probes on an idle
    /// session's circuit, and the transports' own packets (KCP
    /// acknowledgements, FEC loss feedback, padding, TLS records). IP/UDP
    /// (28 B per datagram) and IP/TCP (52 B per read; TCP's pure ACKs are
    /// not seen) headers are added in the `+hdr` columns.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "takes real time; prints a report"]
    async fn wire_cost() {
        let secs: u64 = std::env::var("WEBJET_PROBE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        let window = Duration::from_secs(secs);
        let warm = Duration::from_secs(5);
        let mut runs = Vec::new();
        for kind in [Kind::Kcp, Kind::Tls] {
            for (name, session) in [("hop only", false), ("hop + idle session", true)] {
                runs.push(tokio::spawn(run(
                    Scenario {
                        name,
                        kind,
                        session,
                    },
                    warm,
                    window,
                )));
            }
        }
        println!("\nprobe traffic, edge (a) ↔ relay (b), {secs} s each\n");
        println!(
            "{:<9} {:<20} {:>8} {:>9} {:>9} {:>8} {:>9} {:>9}",
            "transport",
            "scenario",
            "a→b pk/s",
            "a→b B/s",
            "+hdr B/s",
            "b→a pk/s",
            "b→a B/s",
            "+hdr B/s",
        );
        for r in runs {
            let r = r.await.expect("scenario");
            let (label, hdr) = match r.kind {
                Kind::Kcp => ("UDP+KCP", 28.0),
                Kind::Tls => ("TCP+TLS", 52.0),
            };
            let rate = |(p, b): (u64, u64)| {
                (
                    p as f64 / r.secs,
                    b as f64 / r.secs,
                    (b as f64 + p as f64 * hdr) / r.secs,
                )
            };
            let (ap, ab, ah) = rate(r.a_to_b);
            let (bp, bb, bh) = rate(r.b_to_a);
            println!(
                "{label:<9} {:<20} {ap:>8.2} {ab:>9.1} {ah:>9.1} {bp:>8.2} {bb:>9.1} {bh:>9.1}",
                r.name,
            );
            assert!(r.a_to_b.0 > 0 && r.b_to_a.0 > 0, "the hop stayed up");
        }
    }
}
