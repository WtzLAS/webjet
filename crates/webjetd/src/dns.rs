//! The local resolver (§11.10): magic DNS from the tree, admin records,
//! forwarded zones with answer rewriting for mapped subnet routes.

use crate::node::Node;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, PTR, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use webjet_core::packet;
use webjet_core::policy::PROTO_UDP;
use webjet_core::types::{Grant, map_prefix};
use webjet_proto as wp;

const TTL: u32 = 60;

fn lower(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}

fn in_zone(name: &str, zone: &str) -> bool {
    let (n, z) = (lower(name), lower(zone));
    n == z || n.ends_with(&format!(".{z}"))
}

/// Answer a DNS query packet (IP/UDP to the resolver address); returns the
/// IP/UDP reply to write into the tun interface.
pub async fn handle(n: &Arc<Node>, p: &[u8]) -> Option<Vec<u8>> {
    let parsed = packet::parse(p)?;
    if parsed.flow.proto != PROTO_UDP || parsed.flow.dport != 53 {
        return None;
    }
    let payload = p.get(parsed.l4_offset + 8..)?;
    let q = Message::from_vec(payload).ok()?;
    let reply = answer(n, &q).await;
    let bytes = reply.to_vec().ok()?;
    Some(udp_packet(
        parsed.flow.dst,
        53,
        parsed.flow.src,
        parsed.flow.sport,
        &bytes,
    ))
}

/// An empty response to `q`: same id, op code and questions, recursion
/// desired copied, recursion available.
fn response_to(q: &Message) -> Message {
    let mut r = Message::response(q.metadata.id, q.metadata.op_code);
    r.metadata.recursion_desired = q.metadata.recursion_desired;
    r.metadata.recursion_available = true;
    r.queries = q.queries.clone();
    r
}

pub async fn answer(n: &Arc<Node>, q: &Message) -> Message {
    let mut r = response_to(q);
    let Some(query) = q.queries.first() else {
        r.metadata.response_code = ResponseCode::FormErr;
        return r;
    };
    let name = query.name().to_ascii();
    let qtype = query.query_type();
    // This node's own records and zones come first, then the network's
    // (§6.19).
    let (suffix, records, forwards) = {
        let s = n.store.snapshot();
        let v = s.view();
        (
            v.suffix(),
            v.dns_records_for(&n.me),
            v.dns_forward_for(&n.me),
        )
    };
    // Forwarded zones first: they never cover the suffix (§11.10.6).
    for f in &forwards {
        let zone = f.zone.as_deref().unwrap_or_default();
        if in_zone(&name, zone) || (qtype == RecordType::PTR && reverse_in_rewrite(&name, f)) {
            return forward(n, q, f).await.unwrap_or_else(|| {
                let mut e = r.clone();
                e.metadata.response_code = ResponseCode::ServFail;
                e
            });
        }
    }
    let mut answered = false;
    if qtype == RecordType::PTR
        && let Some(ip) = ptr_to_ip(&name)
    {
        let s = n.store.snapshot();
        if let Some(id) = s.view().node_by_ip(&ip)
            && let Some(info) = s.view().nodes.get(&id)
            && let Ok(target) = Name::from_ascii(format!("{}.{suffix}.", info.name))
        {
            r.add_answer(Record::from_rdata(
                query.name().clone(),
                TTL,
                RData::PTR(PTR(target)),
            ));
            answered = true;
        }
    }
    if !answered {
        answered = resolve(n, &name, qtype, &suffix, &records, &mut r, 0);
    }
    let known_zone = in_zone(&name, &suffix)
        || records.iter().any(|x| {
            x.name
                .as_deref()
                .is_some_and(|z| in_zone(&name, z.split_once('.').map_or(z, |y| y.1)))
        });
    if !answered && known_zone && !name_exists(n, &name, &suffix, &records) {
        r.metadata.response_code = ResponseCode::NXDomain;
    } else if !answered && !known_zone && qtype != RecordType::PTR {
        r.metadata.response_code = ResponseCode::Refused;
    }
    r
}

fn name_exists(n: &Node, name: &str, suffix: &str, records: &[wp::DnsRecord]) -> bool {
    if records
        .iter()
        .any(|x| x.name.as_deref().is_some_and(|y| lower(y) == lower(name)))
    {
        return true;
    }
    node_by_magic(n, name, suffix).is_some()
}

fn node_by_magic(n: &Node, name: &str, suffix: &str) -> Option<Vec<IpAddr>> {
    let lname = lower(name);
    let host = lname.strip_suffix(&format!(".{}", lower(suffix)))?;
    let s = n.store.snapshot();
    let id = s.view().by_name.get(host)?;
    let info = s.view().nodes.get(id)?;
    if !info.valid {
        return None;
    }
    Some(info.ips.iter().map(|i| i.addr()).collect())
}

fn node_ref_ips(n: &Node, value: &str) -> Option<(String, Vec<IpAddr>)> {
    let r = value.strip_prefix("node:")?;
    let s = n.store.snapshot();
    let v = s.view();
    let id = match webjet_core::crypto::parse_key_b64(r) {
        Some(k) => *v.by_key.get(&k)?,
        None => *v.by_name.get(r)?,
    };
    let info = v.nodes.get(&id)?;
    if !info.valid {
        return None;
    }
    Some((
        info.name.clone(),
        info.ips.iter().map(|i| i.addr()).collect(),
    ))
}

fn push_addrs(r: &mut Message, owner: &Name, ips: &[IpAddr], qtype: RecordType) -> bool {
    let mut any = false;
    for ip in ips {
        match (ip, qtype) {
            (IpAddr::V4(a), RecordType::A | RecordType::ANY) => {
                r.add_answer(Record::from_rdata(owner.clone(), TTL, RData::A(A(*a))));
                any = true;
            }
            (IpAddr::V6(a), RecordType::AAAA | RecordType::ANY) => {
                r.add_answer(Record::from_rdata(
                    owner.clone(),
                    TTL,
                    RData::AAAA(AAAA(*a)),
                ));
                any = true;
            }
            _ => {}
        }
    }
    any || !ips.is_empty()
}

fn resolve(
    n: &Node,
    name: &str,
    qtype: RecordType,
    suffix: &str,
    records: &[wp::DnsRecord],
    r: &mut Message,
    depth: u8,
) -> bool {
    if depth > 4 {
        return false;
    }
    let Ok(owner) = Name::from_ascii(format!("{}.", lower(name))) else {
        return false;
    };
    if let Some(ips) = node_by_magic(n, name, suffix) {
        return push_addrs(r, &owner, &ips, qtype);
    }
    let mut answered = false;
    for rec in records
        .iter()
        .filter(|x| x.name.as_deref().is_some_and(|y| lower(y) == lower(name)))
    {
        let value = rec.value.clone().unwrap_or_default();
        let ttl = if rec.ttl > 0 { rec.ttl } else { TTL };
        match rec.rtype {
            wp::DnsType::A | wp::DnsType::Aaaa => {
                if let Some((_, ips)) = node_ref_ips(n, &value) {
                    answered |= push_addrs(r, &owner, &ips, qtype);
                } else if let Ok(ip) = value.parse::<IpAddr>() {
                    answered |= push_addrs(r, &owner, &[ip], qtype);
                }
            }
            wp::DnsType::Cname => {
                let target = match node_ref_ips(n, &value) {
                    Some((nm, _)) => format!("{nm}.{suffix}"),
                    None => value.clone(),
                };
                if let Ok(t) = Name::from_ascii(format!("{}.", lower(&target))) {
                    r.add_answer(Record::from_rdata(
                        owner.clone(),
                        ttl,
                        RData::CNAME(CNAME(t)),
                    ));
                    answered = true;
                    if qtype != RecordType::CNAME {
                        resolve(n, &target, qtype, suffix, records, r, depth + 1);
                    }
                }
            }
            wp::DnsType::Txt if matches!(qtype, RecordType::TXT | RecordType::ANY) => {
                r.add_answer(Record::from_rdata(
                    owner.clone(),
                    ttl,
                    RData::TXT(TXT::new(vec![value.clone()])),
                ));
                answered = true;
            }
            wp::DnsType::Srv if matches!(qtype, RecordType::SRV | RecordType::ANY) => {
                let f: Vec<&str> = value.split_whitespace().collect();
                if f.len() == 4
                    && let (Ok(pr), Ok(w), Ok(port), Ok(t)) = (
                        f[0].parse(),
                        f[1].parse(),
                        f[2].parse(),
                        Name::from_ascii(format!("{}.", lower(f[3]))),
                    )
                {
                    r.add_answer(Record::from_rdata(
                        owner.clone(),
                        ttl,
                        RData::SRV(SRV::new(pr, w, port, t)),
                    ));
                    answered = true;
                }
            }
            _ => answered = true,
        }
    }
    answered
}

fn ptr_to_ip(name: &str) -> Option<IpAddr> {
    let l = lower(name);
    if let Some(v4) = l.strip_suffix(".in-addr.arpa") {
        let mut parts: Vec<&str> = v4.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        parts.reverse();
        return parts.join(".").parse().ok();
    }
    if let Some(v6) = l.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = v6.split('.').collect();
        if nibbles.len() != 32 {
            return None;
        }
        let hex: String = nibbles.iter().rev().copied().collect();
        let b = hex::decode(hex).ok()?;
        let arr: [u8; 16] = b.try_into().ok()?;
        return Some(IpAddr::from(arr));
    }
    None
}

fn ip_to_ptr(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let h = hex::encode(a.octets());
            let mut s: Vec<String> = h.chars().rev().map(|c| c.to_string()).collect();
            s.push("ip6.arpa".into());
            s.join(".")
        }
    }
}

fn grants(f: &wp::ForwardZone) -> Vec<Grant> {
    f.rewrite
        .clone()
        .unwrap_or_default()
        .iter()
        .filter_map(|g| Grant::from_wire(g).ok())
        .collect()
}

fn reverse_in_rewrite(name: &str, f: &wp::ForwardZone) -> bool {
    ptr_to_ip(name).is_some_and(|ip| grants(f).iter().any(|g| g.published.contains(&ip)))
}

/// DNS queries from the tun interface answered at once.
pub const MAX_INFLIGHT: usize = 512;

/// Forward a query to the zone's servers over the overlay (§11.10.4) and
/// rewrite LAN addresses to published ones (§11.10.5).
async fn forward(n: &Arc<Node>, q: &Message, f: &wp::ForwardZone) -> Option<Message> {
    let gs = grants(f);
    let mut out = q.clone();
    // Reverse lookups for a published address go out as the LAN address.
    let mut ptr_orig: Option<Name> = None;
    if let Some(query) = q.queries.first()
        && query.query_type() == RecordType::PTR
        && let Some(ip) = ptr_to_ip(&query.name().to_ascii())
        && let Some(g) = gs.iter().find(|g| g.published.contains(&ip))
    {
        let lan = map_prefix(ip, &g.published, &g.lan)?;
        let mut nq = query.clone();
        nq.set_name(Name::from_ascii(format!("{}.", ip_to_ptr(lan))).ok()?);
        ptr_orig = Some(query.name().clone());
        out = q.clone();
        out.queries = vec![nq];
    }
    let bytes = out.to_vec().ok()?;
    let servers: Vec<IpAddr> = f
        .servers
        .clone()
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.to_ip())
        .collect();
    let _ = n;
    for srv in servers {
        let bind = SocketAddr::new(
            if srv.is_ipv4() {
                std::net::Ipv4Addr::UNSPECIFIED.into()
            } else {
                std::net::Ipv6Addr::UNSPECIFIED.into()
            },
            0,
        );
        let Ok(sock) = tokio::net::UdpSocket::bind(bind).await else {
            continue;
        };
        if sock
            .send_to(&bytes, SocketAddr::new(srv, 53))
            .await
            .is_err()
        {
            continue;
        }
        // Only the server's answer to this query counts: anything else
        // arriving on the socket (another source, another id) is skipped
        // until the deadline.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut buf = vec![0u8; 4096];
        let resp = loop {
            let Ok(Ok((len, from))) =
                tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await
            else {
                break None;
            };
            if from != SocketAddr::new(srv, 53) {
                continue;
            }
            match Message::from_vec(&buf[..len]) {
                Ok(r) if r.metadata.id == out.metadata.id => break Some(r),
                _ => continue,
            }
        };
        let Some(resp) = resp else { continue };
        return Some(fix_forwarded(resp, q, &gs, ptr_orig.as_ref()));
    }
    None
}

/// A forwarded zone's answer to `q`, as the client gets it: LAN addresses
/// rewritten to published ones (§11.10.5), a reverse lookup sent as the LAN
/// address answered under the published name the client asked for, and the
/// client's query id.
fn fix_forwarded(mut resp: Message, q: &Message, gs: &[Grant], ptr_orig: Option<&Name>) -> Message {
    if gs.iter().any(|g| g.mapped()) {
        resp.answers = std::mem::take(&mut resp.answers)
            .into_iter()
            .map(|rec| rewrite_record(rec, gs))
            .collect();
        resp.additionals = std::mem::take(&mut resp.additionals)
            .into_iter()
            .map(|rec| rewrite_record(rec, gs))
            .collect();
        resp.metadata.authentic_data = false;
    }
    if let Some(orig) = ptr_orig {
        resp.queries = q.queries.clone();
        for rec in &mut resp.answers {
            rec.name = orig.clone();
        }
    }
    resp.metadata.id = q.metadata.id;
    resp
}

fn rewrite_record(mut rec: Record, gs: &[Grant]) -> Record {
    let new = match &rec.data {
        RData::A(a) => {
            let ip = IpAddr::V4(a.0);
            gs.iter()
                .find(|g| g.lan.contains(&ip))
                .and_then(|g| map_prefix(ip, &g.lan, &g.published))
                .and_then(|x| match x {
                    IpAddr::V4(v) => Some(RData::A(A(v))),
                    IpAddr::V6(_) => None,
                })
        }
        RData::AAAA(a) => {
            let ip = IpAddr::V6(a.0);
            gs.iter()
                .find(|g| g.lan.contains(&ip))
                .and_then(|g| map_prefix(ip, &g.lan, &g.published))
                .and_then(|x| match x {
                    IpAddr::V6(v) => Some(RData::AAAA(AAAA(v))),
                    IpAddr::V4(_) => None,
                })
        }
        _ => None,
    };
    if let Some(d) = new {
        rec.data = d;
    }
    rec
}

/// Build an IPv4/IPv6 UDP packet.
pub fn udp_packet(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, payload: &[u8]) -> Vec<u8> {
    let ulen = 8 + payload.len();
    // Larger than an IP packet can be (IPv4 total length includes 20 more).
    let Some(len16) = u16::try_from(ulen).ok().filter(|l| *l <= u16::MAX - 20) else {
        return Vec::new();
    };
    let mut p = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut h = vec![0u8; 20];
            h[0] = 0x45;
            h[2..4].copy_from_slice(&(20 + len16).to_be_bytes());
            h[8] = 64;
            h[9] = PROTO_UDP;
            h[12..16].copy_from_slice(&s.octets());
            h[16..20].copy_from_slice(&d.octets());
            h
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut h = vec![0u8; 40];
            h[0] = 0x60;
            h[4..6].copy_from_slice(&len16.to_be_bytes());
            h[6] = PROTO_UDP;
            h[7] = 64;
            h[8..24].copy_from_slice(&s.octets());
            h[24..40].copy_from_slice(&d.octets());
            h
        }
        _ => return Vec::new(),
    };
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&len16.to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    packet::fix_checksums(&mut p);
    p
}

/// Entry points for the fuzz targets (`fuzz/fuzz_targets/dns.rs`): the
/// parsing and rewriting the resolver does on bytes from local clients and
/// from upstream servers, without a running node.
#[doc(hidden)]
pub mod fuzzing {
    use super::*;

    /// A client's query packet (IP/UDP from the tun interface) and an
    /// upstream server's answer to it, through every step that doesn't need
    /// the tree: parsing, the empty response, reverse-name parsing, the
    /// reverse-lookup rewrite and answer rewriting for a mapped route.
    pub fn query_and_answer(packet: &[u8], response: &[u8]) {
        let q = match packet::parse(packet) {
            Some(parsed) if parsed.flow.proto == PROTO_UDP => packet
                .get(parsed.l4_offset + 8..)
                .and_then(|b| Message::from_vec(b).ok()),
            // Not an IP/UDP packet: treat the bytes as the DNS payload.
            _ => Message::from_vec(packet).ok(),
        };
        let Some(q) = q else { return };
        let r = response_to(&q);
        let _ = r.to_vec();
        let mut ptr_orig = None;
        if let Some(query) = q.queries.first() {
            let name = query.name().to_ascii();
            let _ = in_zone(&name, "internal");
            if let Some(ip) = ptr_to_ip(&name) {
                // What `forward` does for a reverse lookup of a published
                // address: the LAN name must parse back.
                let lan = Name::from_ascii(format!("{}.", ip_to_ptr(ip)));
                assert!(lan.is_ok(), "{ip}: {lan:?}");
                ptr_orig = Some(query.name().clone());
            }
        }
        let Ok(resp) = Message::from_vec(response) else {
            return;
        };
        let gs = [
            grant("192.168.1.0/24", "10.99.1.0/24"),
            grant("fd00:1::/64", "fd99:1::/64"),
        ];
        let out = fix_forwarded(resp, &q, &gs, ptr_orig.as_ref());
        assert_eq!(out.metadata.id, q.metadata.id);
        let _ = out.to_vec();
    }

    fn grant(lan: &str, published: &str) -> Grant {
        let parse = |s: &str| {
            s.parse()
                .unwrap_or_else(|_| unreachable!("constant prefix {s}"))
        };
        Grant {
            lan: parse(lan),
            published: parse(published),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ptr_roundtrip() {
        for ip in ["10.7.0.12", "2001:db8::1"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(ptr_to_ip(&ip_to_ptr(ip)), Some(ip));
        }
    }
    #[test]
    fn udp_builds() {
        let p = udp_packet(
            "10.7.255.53".parse().unwrap(),
            53,
            "10.7.0.1".parse().unwrap(),
            5353,
            b"hello",
        );
        let parsed = packet::parse(&p).unwrap();
        assert_eq!(parsed.flow.sport, 53);
        assert_eq!(parsed.flow.dport, 5353);
    }

    /// A DNS message on the wire: header, one question, and A answers for it
    /// (name compressed as a pointer to the question).
    fn wire(id: u16, flags: u16, name: &str, qtype: u16, answers: &[[u8; 4]]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        for label in name.trim_end_matches('.').split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        for a in answers {
            m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            m.extend_from_slice(a);
        }
        m
    }

    #[test]
    fn response_keeps_query_header() {
        // RD set, standard query.
        let q = Message::from_vec(&wire(0xbeef, 0x0100, "web.internal", 1, &[])).unwrap();
        let mut r = response_to(&q);
        r.metadata.response_code = ResponseCode::NXDomain;
        let b = r.to_vec().unwrap();
        assert_eq!(&b[0..2], &[0xbe, 0xef]);
        // QR, RD, RA; rcode 3.
        assert_eq!(u16::from_be_bytes([b[2], b[3]]), 0x8183);
        let back = Message::from_vec(&b).unwrap();
        assert_eq!(back.queries.len(), 1);
        assert_eq!(back.queries[0].name().to_ascii(), "web.internal.");
        assert_eq!(back.queries[0].query_type(), RecordType::A);
    }

    #[test]
    fn forwarded_answers_are_rewritten() {
        let gs = [Grant::parse("192.168.1.0/24=10.2.2.0/24").unwrap()];
        let q = Message::from_vec(&wire(7, 0x0100, "nas.lan", 1, &[])).unwrap();
        // The server answers with its own id and the LAN address.
        let resp =
            Message::from_vec(&wire(99, 0x8180, "nas.lan", 1, &[[192, 168, 1, 20]])).unwrap();
        let out = fix_forwarded(resp, &q, &gs, None);
        assert_eq!(out.metadata.id, 7);
        assert!(!out.metadata.authentic_data);
        let ips: Vec<IpAddr> = out
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                _ => None,
            })
            .collect();
        assert_eq!(ips, vec!["10.2.2.20".parse::<IpAddr>().unwrap()]);
        // A reverse lookup answered under the name the client asked for.
        let orig = Name::from_ascii("20.2.2.10.in-addr.arpa.").unwrap();
        let q = Message::from_vec(&wire(8, 0x0100, "20.2.2.10.in-addr.arpa", 12, &[])).unwrap();
        let resp = Message::from_vec(&wire(
            8,
            0x8180,
            "20.1.168.192.in-addr.arpa",
            1,
            &[[1, 2, 3, 4]],
        ))
        .unwrap();
        let out = fix_forwarded(resp, &q, &gs, Some(&orig));
        assert_eq!(out.queries[0].name(), &orig);
        assert!(out.answers.iter().all(|r| r.name == orig));
        assert!(out.to_vec().is_ok());
    }
}
