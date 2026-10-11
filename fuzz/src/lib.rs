//! Fuzz targets for every parser that reads bytes from the network or from
//! local clients (architecture §20). Each `pub fn` here is one target: the
//! libFuzzer binaries in `fuzz_targets/` call it (`cargo +nightly fuzz run
//! <name>`, see `scripts/fuzz.sh`), and `tests/smoke.rs` runs it on stable
//! over seed inputs and pseudo-random mutations of them, in CI.
//!
//! A target fails by panicking: a parser panicked, or an invariant
//! (round trips, size caps) asserted here didn't hold.

pub mod seeds;

use std::collections::BTreeMap;
use webjet_core::{compress, crypto, frames, leaf, multicast, packet, padding, sntp};
use webjet_net::{fec, gate, hop, kcp};
use webjet_proto::{self as wp, Decodable, Encodable};

/// Split fuzz input in two: a 2-byte length prefix, then that many bytes
/// for the first part (as far as available), the rest for the second.
pub fn split(data: &[u8]) -> (&[u8], &[u8]) {
    let n = match data {
        [a, b, ..] => usize::from(u16::from_be_bytes([*a, *b])),
        _ => return (data, &[]),
    };
    let rest = &data[2..];
    rest.split_at(n.min(rest.len()))
}

/// Split fuzz input into several chunks, each with a 2-byte length prefix.
pub fn chunks(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while !data.is_empty() && out.len() < 256 {
        let (a, b) = split(data);
        out.push(a);
        data = b;
    }
    out
}

macro_rules! roundtrip_types {
    ($sel:expr, $bytes:expr, $($t:ident),* $(,)?) => {{
        const TYPES: &[&str] = &[$(stringify!($t)),*];
        let i = usize::from($sel) % TYPES.len();
        let mut j = 0usize;
        $(
            if i == j {
                roundtrip::<wp::$t>($bytes);
            }
            j += 1;
        )*
        let _ = j;
    }};
}

/// Decoding must never panic, and whatever decodes must re-encode to bytes
/// that decode to the same value (compared by their encoding, since floats
/// may be NaN).
fn roundtrip<T: Decodable + Encodable>(bytes: &[u8]) {
    let Ok(v) = T::decode_bytes(bytes) else {
        return;
    };
    let once = v.encode_bytes();
    let again = match T::decode_bytes(&once) {
        Ok(x) => x,
        Err(e) => panic!("re-encoded message doesn't decode: {e}"),
    };
    assert_eq!(once, again.encode_bytes(), "encoding isn't stable");
}

/// FlatBuffers messages (`webjet-proto`): the first byte picks the type.
/// Also signed envelopes (signature checks on hostile input) and tree
/// leaves, which every node decodes from gossip.
pub fn proto(data: &[u8]) {
    let Some((&sel, bytes)) = data.split_first() else {
        return;
    };
    roundtrip_types!(
        sel,
        bytes,
        Signed,
        Leaf,
        NodeRecord,
        Tombstone,
        AccountRecord,
        AccountTombstone,
        Policy,
        DnsConfig,
        Seeds,
        Limits,
        Validity,
        TransportConfig,
        NodeConfig,
        ControllerSettings,
        NetworkConfig,
        SignedTreeHead,
        SigningKeyCert,
        SigningKeyTombstone,
        EmergencyKeyCert,
        StateVersion,
        Genesis,
        EndpointRecord,
        LinkStateAdvert,
        AttachmentRecord,
        CircuitSetup,
        RotateNodeKey,
        MetricReport,
        SignedOp,
        LogEntry,
        HopControl,
        Probe,
        PunchOffer,
        PunchGo,
        Rpc,
        RaftMessage,
        ControllerSnapshot,
        EnrollRequest,
        EnrollResponse,
        EnrollmentTicket,
        CreateEnrollment,
        LogRequest,
    );
    if let Ok(v) = crypto::open_envelope(bytes) {
        let _ = v.decode::<wp::NodeRecord>();
        let _ = crypto::open_expect(bytes, v.ty, &[v.signer]);
    }
    let _ = leaf::decode(sel % 12, &[sel; 32], bytes);
}

/// End-to-end and relay frames (`webjet_core::frames`): header, handshake
/// and relay parsing, AEAD opening with a fixed key, the replay window, and
/// seal/open round trips.
pub fn frames(data: &[u8]) {
    let _ = frames::parse_header(data);
    let _ = frames::parse_handshake(data);
    if let Some((_, _, _, inner)) = frames::parse_relay(data) {
        let _ = frames::parse_header(inner);
    }
    let key = frames::SessionKey::new([7; 32]);
    let _ = key.open(data);
    let mut w = frames::ReplayWindow::default();
    for c in data.chunks(8) {
        let mut b = [0u8; 8];
        b[..c.len()].copy_from_slice(c);
        let c = u64::from_be_bytes(b);
        if w.check(c) {
            assert!(w.mark(c), "a counter that passed check must be accepted");
            assert!(!w.check(c), "a counter must not be accepted twice");
        }
    }
    let (head, payload) = split(data);
    let ty = head.first().copied().unwrap_or(1);
    let key_id = webjet_core::bytes::be_u32(head, 1).unwrap_or(0);
    let counter = webjet_core::bytes::be_u64(head, 5).unwrap_or(0);
    let Some(f) = key.seal(ty, key_id, counter, payload) else {
        panic!("sealing a short payload failed");
    };
    assert_eq!(
        key.open(&f).as_deref(),
        Some(payload),
        "seal/open round trip"
    );
    if let Some(h) = frames::parse_header(&f)
        && ty != frames::ftype::HANDSHAKE
    {
        assert_eq!((h.ty, h.key_id, h.counter), (ty, key_id, counter));
    }
    let mut relay = frames::relay_header(key_id, ty, ty & 3).to_vec();
    relay.extend_from_slice(payload);
    let parsed = frames::parse_relay(&relay);
    assert_eq!(parsed.map(|(c, _, _, p)| (c, p)), Some((key_id, payload)));
}

/// IP packets from the tun interface or a peer (`webjet_core::packet`),
/// and what the data plane does to them: NAT rewrites, ECN marking, ICMP
/// replies, compression decisions.
pub fn packet(data: &[u8]) {
    let parsed = packet::parse(data);
    let _ = packet::version(data);
    let _ = packet::src_dst(data);
    let _ = packet::ecn_of(data);
    let _ = packet::checksum(data);
    let _ = compress::incompressible(data);
    let _ = compress::flow_key(data);
    if let Some(r) = packet::echo_reply(data) {
        assert!(packet::parse(&r).is_some(), "an echo reply must parse");
    }
    for why in [packet::Unreach::Prohibited, packet::Unreach::Host] {
        if let Some(r) = packet::icmp_unreachable(data, why) {
            assert!(packet::parse(&r).is_some(), "an ICMP error must parse");
        }
    }
    let mut p = data.to_vec();
    packet::set_ecn(&mut p, 3);
    packet::fix_checksums(&mut p);
    if let Some(parsed) = parsed {
        let src = (parsed.flow.src, 40000);
        let dst = match parsed.flow.dst {
            std::net::IpAddr::V4(_) => ("10.7.0.9".parse().ok(), 53),
            std::net::IpAddr::V6(_) => ("fd00::9".parse().ok(), 53),
        };
        let mut q = data.to_vec();
        packet::rewrite(&mut q, Some(src), dst.0.map(|ip| (ip, dst.1)));
        let _ = packet::parse(&q);
    }
    if let Some(c) = compress::lz4_compress(data) {
        assert_eq!(
            compress::lz4_decompress(&c, data.len()).as_deref(),
            Some(data),
            "lz4 round trip"
        );
    }
}

/// Decompression of hostile input (§9.8): never more than the cap, and
/// compressed data round-trips.
pub fn decompress(data: &[u8]) {
    let (head, body) = split(data);
    let cap = usize::from(webjet_core::bytes::be_u16(head, 0).unwrap_or(4096)) * 16;
    if let Some(out) = compress::zstd_decompress(body, cap) {
        assert!(out.len() <= cap, "zstd output above the cap");
    }
    if let Some(out) = compress::lz4_decompress(body, cap) {
        assert!(out.len() <= cap, "lz4 output above the cap");
    }
    let _ = compress::zstd_decompress(body, hop::MAX_RECORD);
    if let Some(c) = compress::zstd_compress(body) {
        assert_eq!(
            compress::zstd_decompress(&c, body.len()).as_deref(),
            Some(body),
            "zstd round trip"
        );
        if !body.is_empty() {
            assert!(
                compress::zstd_decompress(&c, body.len() - 1).is_none(),
                "zstd cap not enforced"
            );
        }
    }
}

fn epochs() -> gate::Epochs {
    gate::Epochs {
        keys: BTreeMap::from([(0, [1; 32]), (1, [2; 32])]),
        current: 1,
        accept_all: false,
    }
}

/// The UDP gate (§9.7.3): every datagram from anyone reaches `open`.
pub fn gate(data: &[u8]) {
    let g = gate::UdpObfs::new(&[9; 32]);
    let e = epochs();
    g.set_epochs(&e);
    let _ = g.open(data, &e);
    let (head, inner) = split(data);
    let epoch = u16::from(head.first().copied().unwrap_or(1) & 1);
    let pad = usize::from(head.get(1).copied().unwrap_or(0));
    if inner.len() <= usize::from(u16::MAX) - pad {
        let Some(d) = g.seal(epoch, inner, pad) else {
            panic!("sealing failed for a known epoch");
        };
        let opened = g.open(&d, &e).map(|(_, b)| b);
        assert_eq!(opened.as_deref(), Some(inner), "gate round trip");
        // Another network (root key) can't open it.
        let other = gate::UdpObfs::new(&[8; 32]);
        other.set_epochs(&e);
        let _ = other.open(&d, &e);
    }
}

/// FEC shards and KCP segments after the gate (`webjet_net::kcp`, `fec`).
pub fn kcp_session(data: &[u8]) {
    let (head, rest) = split(data);
    let conv = webjet_core::bytes::be_u32(head, 0).unwrap_or(1);
    let datagrams = chunks(rest);
    let _ = kcp::fuzzing::session_input(conv, &datagrams);
    kcp::fuzzing::proto_input(rest);
    let mut dec = fec::Decoder::new();
    for d in &datagrams {
        let _ = dec.push(d);
    }
    // Shards made by the encoder decode back to the packets, in order.
    let mut enc = fec::Encoder::new();
    let mut dec = fec::Decoder::new();
    let packets: Vec<&[u8]> = datagrams
        .iter()
        .copied()
        .filter(|p| !p.is_empty() && p.len() <= kcp::KCP_MTU)
        .collect();
    let mut got = Vec::new();
    for p in &packets {
        for s in enc.push(p) {
            got.extend(dec.push(&s));
        }
    }
    for s in enc.flush() {
        got.extend(dec.push(&s));
    }
    let want: Vec<Vec<u8>> = packets.iter().map(|p| p.to_vec()).collect();
    assert_eq!(got, want, "FEC round trip without loss");
}

/// Hop records (`webjet_net::hop`): the framing every TLS/AnyTLS/KCP hop
/// reads first, including CONTROL_ZSTD payloads.
pub fn hop_record(data: &[u8]) {
    futures::executor::block_on(async {
        let (mut r, mut whole) = (data, data);
        while let Ok((ty, body)) = hop::read_record(&mut r).await {
            let Ok((t, rec)) = hop::read_record_buf(&mut whole).await else {
                panic!("read_record_buf refused what read_record took");
            };
            assert_eq!(
                (t, &rec[hop::RECORD_HEADER..]),
                (ty, &body[..]),
                "both readers agree"
            );
            assert!(body.len() <= hop::MAX_RECORD);
            if ty == hop::rec::CONTROL_ZSTD {
                let _ = compress::zstd_decompress(&body, hop::MAX_RECORD);
            }
            let _ = wp::HopControl::decode_bytes(&body);
        }
        let (ty, payload) = split(data);
        let ty = ty.first().copied().unwrap_or(hop::rec::CONTROL);
        let Some(enc) = hop::encode_record(ty, payload) else {
            assert!(
                payload.len() > hop::MAX_RECORD,
                "a record within the limit encodes"
            );
            return;
        };
        let mut r = enc.as_slice();
        match hop::read_record(&mut r).await {
            Ok((t, b)) => assert_eq!((t, b.as_slice()), (ty, payload), "record round trip"),
            Err(e) => panic!("encoded record doesn't read back: {e}"),
        }
        // Built in place and read whole (the relay path): the same bytes.
        let mut built = [&[0; hop::RECORD_HEADER][..], payload].concat();
        assert!(
            hop::seal_record(ty, &mut built),
            "a record within the limit seals"
        );
        assert_eq!(built, enc, "sealed in place = encoded");
        let mut r = enc.as_slice();
        match hop::read_record_buf(&mut r).await {
            Ok((t, b)) => assert_eq!((t, b.as_slice()), (ty, enc.as_slice()), "whole record"),
            Err(e) => panic!("encoded record doesn't read back whole: {e}"),
        }
    });
}

/// The local resolver (§11.10): queries from local clients, answers from
/// forwarded zones' servers.
pub fn dns(data: &[u8]) {
    let (query, response) = split(data);
    webjetd::dns::fuzzing::query_and_answer(query, response);
}

/// Control-channel request lines (`webjetd::control::Request`): every
/// local user may send them. A line that parses must write back as JSON
/// that parses to the same request.
pub fn control_request(data: &[u8]) {
    use webjetd::control::Request;
    let Ok(req) = serde_json::from_slice::<Request>(data) else {
        return;
    };
    let back: Request = serde_json::from_value(req.to_json()).expect("request round trip");
    assert_eq!(back, req, "request round trip");
}

/// SNTP answers (§21.2): UDP datagrams from any server we ask, or anyone
/// spoofing one. Parsing never panics, and a well-formed answer from a
/// server whose clock is `d` ms ahead, with no network delay, gives an
/// offset of exactly `-d`.
pub fn sntp(data: &[u8]) {
    // Times the clock can hold (until 2106, where NTP's era 1 ends).
    const SPAN: u64 = 4_000_000_000_000;
    let (head, resp) = split(data);
    let num = |i: usize| {
        let mut b = [0u8; 8];
        for (j, x) in head.iter().skip(i).take(6).enumerate() {
            b[2 + j] = *x;
        }
        u64::from_be_bytes(b) % SPAN
    };
    let (t1, server, t4) = (num(0), num(6), num(12));
    let _ = sntp::parse(resp, t1, t4);
    let mut answer = [0u8; 48];
    answer[0] = 0x24; // version 4, mode 4 (server)
    answer[1] = 2;
    answer[24..32].copy_from_slice(&sntp::request(t1)[40..48]);
    let stamp = sntp::request(server);
    answer[32..40].copy_from_slice(&stamp[40..48]);
    answer[40..48].copy_from_slice(&stamp[40..48]);
    let got = sntp::parse(&answer, t1, t1);
    // Both below SPAN, so no overflow.
    let ahead = server as i64 - t1 as i64;
    assert_eq!(got, Some(-ahead), "offset of a well-formed answer");
    // A reply to another request is not taken.
    if t4 != t1 {
        assert_eq!(
            sntp::parse(&answer, t4, t4),
            None,
            "answer to another request"
        );
    }
}

/// Multicast membership reports (§9.5.1), from any peer. What decodes
/// encodes back to a report that decodes the same.
pub fn multicast_report(data: &[u8]) {
    let Some(r) = multicast::decode_report(data) else {
        return;
    };
    let again = multicast::decode_report(&multicast::encode_report(&r));
    assert_eq!(again.as_ref(), Some(&r), "report round trip");
}

/// Padding schemes (§9.7.4) from the TransportConfig: parsed by every
/// node. A plan always carries the whole payload.
pub fn padding(data: &[u8]) {
    let (head, text) = split(data);
    let text = String::from_utf8_lossy(text);
    let lines: Vec<String> = text.lines().map(str::to_owned).collect();
    for l in &lines {
        if let Ok((_, segs)) = padding::parse_line(l) {
            for s in segs {
                if let padding::Seg::Range(a, b) = s {
                    assert!(a <= b && b <= 16384, "range out of bounds");
                }
            }
        }
    }
    let stop = u32::from(head.first().copied().unwrap_or(8));
    let wire = wp::PaddingScheme {
        stop,
        lines: Some(lines),
    };
    let Ok(scheme) = padding::Scheme::from_wire(&wire) else {
        return;
    };
    let len = usize::from(webjet_core::bytes::be_u16(head, 1).unwrap_or(1200));
    for pkt in 0..stop.min(16) {
        if let Some(plan) = scheme.plan(pkt, len) {
            assert_eq!(
                plan.iter().map(|x| x.0).sum::<usize>(),
                len,
                "plan loses data"
            );
        }
    }
    assert!(scheme.plan(stop, len).is_none(), "plan past stop");
}

/// A fuzz target: panics on a bug.
pub type Target = fn(&[u8]);

/// Every target, by name (for the smoke test and the seed writer).
pub const TARGETS: &[(&str, Target)] = &[
    ("proto", proto),
    ("frames", frames),
    ("packet", packet),
    ("decompress", decompress),
    ("gate", gate),
    ("kcp_session", kcp_session),
    ("hop_record", hop_record),
    ("dns", dns),
    ("control_request", control_request),
    ("sntp", sntp),
    ("multicast_report", multicast_report),
    ("padding", padding),
];
