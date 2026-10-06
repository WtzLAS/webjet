//! Seed inputs for every target: valid messages of each kind, so the fuzzer
//! (and the stable smoke test) start from inputs that get past the first
//! length and type checks. `cargo run --manifest-path fuzz/Cargo.toml
//! --no-default-features --example seeds` writes them to `fuzz/corpus/<target>/`.

use crate::TARGETS;
use std::net::IpAddr;
use webjet_core::{compress, crypto, frames, packet};
use webjet_net::{fec, gate, hop};
use webjet_proto::{self as wp, Encodable};

/// Length-prefix `a` for [`crate::split`], then append `b`.
pub fn pair(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(a.len())
        .unwrap_or(u16::MAX)
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

/// Length-prefix every chunk for [`crate::chunks`].
pub fn chain(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend(pair(p, &[]));
    }
    out
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap_or(IpAddr::from([127, 0, 0, 1]))
}

fn udp(src: &str, dst: &str, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    webjetd::dns::udp_packet(ip(src), sport, ip(dst), dport, payload)
}

/// A DNS query for `name` (A) on the wire.
fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&0x0100u16.to_be_bytes());
    m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for l in name.split('.').filter(|l| !l.is_empty()) {
        m.push(u8::try_from(l.len()).unwrap_or(63));
        m.extend_from_slice(l.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m
}

/// An answer to [`dns_query`] with A records (name as a pointer).
fn dns_answer(id: u16, name: &str, addrs: &[[u8; 4]]) -> Vec<u8> {
    let mut m = dns_query(id, name, 1);
    m[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    m[6..8].copy_from_slice(&u16::try_from(addrs.len()).unwrap_or(0).to_be_bytes());
    for a in addrs {
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        m.extend_from_slice(a);
    }
    m
}

fn signed(ty: u16, body: Vec<u8>) -> Vec<u8> {
    crypto::KeyPair::from_seed(&[3; 32])
        .sign_envelope(ty, body)
        .encode_bytes()
}

/// Seeds for one target.
pub fn for_target(name: &str) -> Vec<Vec<u8>> {
    match name {
        "proto" => {
            let rec = wp::NodeRecord {
                name: Some("node-01".into()),
                version: 3,
                ..Default::default()
            };
            let ep = wp::EndpointRecord {
                software: Some("webjetd 0.7.1".into()),
                seq: 9,
                ..Default::default()
            };
            // The selector byte picks the type in `proto` (index in its list).
            let with = |sel: u8, b: Vec<u8>| [vec![sel], b].concat();
            vec![
                with(0, signed(wp::msg_type::NODE_RECORD, rec.encode_bytes())),
                with(2, rec.encode_bytes()),
                with(21, ep.encode_bytes()),
                with(29, wp::HopControl::default().encode_bytes()),
                with(33, wp::Rpc::default().encode_bytes()),
                with(34, wp::RaftMessage::default().encode_bytes()),
                with(12, wp::NodeConfig::default().encode_bytes()),
            ]
        }
        "frames" => {
            let key = frames::SessionKey::new([7; 32]);
            let data = key
                .seal(frames::ftype::DATA, 5, 1, b"hello")
                .unwrap_or_default();
            let hs = frames::handshake_frame(true, &[1; 16], 0, b"client hello");
            let mut relay = frames::relay_header(77, 8, 2).to_vec();
            relay.extend_from_slice(&data);
            vec![
                data,
                hs,
                relay,
                pair(&[1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 2], b"payload"),
            ]
        }
        "packet" => vec![
            udp("10.7.0.1", "10.7.0.2", 4000, 53, b"query"),
            udp("fd00::1", "fd00::2", 4000, 443, b"tls"),
            packet::icmp_echo(ip("10.7.0.1"), ip("10.7.0.2"), true, 1, 1, b"ping"),
            packet::icmp_echo(ip("fd00::1"), ip("fd00::2"), true, 1, 1, b"ping6"),
            {
                // TCP SYN, IPv4.
                let mut p = vec![
                    0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 7, 0, 1, 10, 7, 0, 2,
                ];
                p.extend_from_slice(&[0x9c, 0x40, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 2]);
                p.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
                packet::fix_checksums(&mut p);
                p
            },
        ],
        "decompress" => {
            let text = b"webjet control traffic ".repeat(40);
            let z = compress::zstd_compress(&text).unwrap_or_default();
            let pkt = udp("10.7.0.1", "10.7.0.2", 4000, 5000, &[b'a'; 600]);
            let l = compress::lz4_compress(&pkt).unwrap_or_default();
            vec![
                pair(&[0, 128], &z),
                pair(&[0, 128], &l),
                pair(&[0, 1], &text),
            ]
        }
        "gate" => {
            let g = gate::UdpObfs::new(&[9; 32]);
            let e = gate::Epochs {
                keys: std::collections::BTreeMap::from([(0, [1; 32]), (1, [2; 32])]),
                current: 1,
                accept_all: false,
            };
            g.set_epochs(&e);
            let d = g.seal(1, b"\x02\0\0\0\x01inner", 16).unwrap_or_default();
            vec![d, pair(&[1, 8], b"inner datagram")]
        }
        "kcp_session" => {
            // FEC shards of KCP segments from a real encoder.
            let mut seg = vec![1, 0, 0, 0, 81, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
            seg.extend_from_slice(&[0, 0, 0, 0, 5, 0, 0, 0]);
            seg.extend_from_slice(b"hello");
            let mut enc = fec::Encoder::new();
            let mut shards = enc.push(&seg);
            shards.extend(enc.flush());
            let datagrams: Vec<Vec<u8>> = shards
                .iter()
                .map(|s| [&[1u8][..], s].concat())
                .chain(std::iter::once(vec![4, 0, 0, 0, 9, 0, 0, 0, 10]))
                .collect();
            vec![pair(&1u32.to_be_bytes(), &chain(&datagrams))]
        }
        "hop_record" => {
            let ctl =
                hop::encode_record(hop::rec::CONTROL, &wp::HopControl::default().encode_bytes());
            let big = wp::HopControl::default().encode_bytes().repeat(50);
            let z = compress::zstd_compress(&big).unwrap_or_default();
            let zr = hop::encode_record(hop::rec::CONTROL_ZSTD, &z);
            vec![
                [ctl.clone(), zr].concat(),
                pair(&[hop::rec::RELAY], b"relay"),
            ]
        }
        "dns" => {
            let q = udp(
                "10.7.0.1",
                "10.7.255.53",
                5353,
                53,
                &dns_query(7, "nas.lan.internal", 1),
            );
            let a = dns_answer(7, "nas.lan.internal", &[[192, 168, 1, 10]]);
            let ptr = dns_query(8, "10.1.99.10.in-addr.arpa", 12);
            vec![pair(&q, &a), pair(&ptr, &dns_answer(8, "x", &[]))]
        }
        "control_request" => [
            r#"{"cmd":"status"}"#,
            r#"{"cmd":"node_config","node":"0707070707070707070707070707070707070707070707070707070707070707"}"#,
            r#"{"cmd":"submit_op","signed":"c2lnbmVk"}"#,
            r#"{"cmd":"submit_offline","items":["YQ==","Yg=="]}"#,
            r#"{"cmd":"ping","target":"nas","count":3,"size":56}"#,
            r#"{"cmd":"metrics","all":true}"#,
            r#"{"cmd":"cert_request","node":null}"#,
        ]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect(),
        _ => Vec::new(),
    }
}

/// Every target's seeds.
pub fn all() -> Vec<(&'static str, Vec<Vec<u8>>)> {
    TARGETS
        .iter()
        .map(|(name, _)| (*name, for_target(name)))
        .collect()
}
