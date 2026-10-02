//! The local resolver (§11.10): magic DNS from the tree, admin records,
//! forwarded zones with answer rewriting for mapped subnet routes.

use crate::node::Node;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, PTR, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use webjet_core::packet;
use webjet_core::policy::PROTO_UDP;
use webjet_core::types::{map_prefix, Grant};
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
    Some(udp_packet(parsed.flow.dst, 53, parsed.flow.src, parsed.flow.sport, &bytes))
}

pub async fn answer(n: &Arc<Node>, q: &Message) -> Message {
    let mut r = Message::new();
    r.set_id(q.id());
    r.set_message_type(MessageType::Response);
    r.set_op_code(q.op_code());
    r.set_recursion_desired(q.recursion_desired());
    r.set_recursion_available(true);
    for query in q.queries() {
        r.add_query(query.clone());
    }
    let Some(query) = q.queries().first() else {
        r.set_response_code(ResponseCode::FormErr);
        return r;
    };
    let name = query.name().to_ascii();
    let qtype = query.query_type();
    let (suffix, cfg) = {
        let s = n.store.read();
        (s.view().suffix(), s.view().dns.clone())
    };
    // Forwarded zones first: they never cover the suffix (§11.10.6).
    if let Some(cfg) = &cfg {
        for f in cfg.forward.clone().unwrap_or_default() {
            let zone = f.zone.clone().unwrap_or_default();
            if in_zone(&name, &zone) || (qtype == RecordType::PTR && reverse_in_rewrite(&name, &f)) {
                return forward(n, q, &f).await.unwrap_or_else(|| {
                    let mut e = r.clone();
                    e.set_response_code(ResponseCode::ServFail);
                    e
                });
            }
        }
    }
    let mut answered = false;
    if qtype == RecordType::PTR {
        if let Some(ip) = ptr_to_ip(&name) {
            let s = n.store.read();
            if let Some(id) = s.view().node_by_ip(&ip) {
                if let Some(info) = s.view().nodes.get(&id) {
                    if let Ok(target) = Name::from_ascii(format!("{}.{suffix}.", info.name)) {
                        r.add_answer(Record::from_rdata(query.name().clone(), TTL, RData::PTR(PTR(target))));
                        answered = true;
                    }
                }
            }
        }
    }
    let records = cfg.as_ref().map(|c| c.records.clone().unwrap_or_default()).unwrap_or_default();
    if !answered {
        answered = resolve(n, &name, qtype, &suffix, &records, &mut r, 0);
    }
    let known_zone = in_zone(&name, &suffix) || records.iter().any(|x| x.name.as_deref().map(|z| in_zone(&name, z.split_once('.').map(|y| y.1).unwrap_or(z))).unwrap_or(false));
    if !answered && known_zone && !name_exists(n, &name, &suffix, &records) {
        r.set_response_code(ResponseCode::NXDomain);
    } else if !answered && !known_zone && qtype != RecordType::PTR {
        r.set_response_code(ResponseCode::Refused);
    }
    r
}

fn name_exists(n: &Node, name: &str, suffix: &str, records: &[wp::DnsRecord]) -> bool {
    if records.iter().any(|x| x.name.as_deref().map(|y| lower(y) == lower(name)).unwrap_or(false)) {
        return true;
    }
    node_by_magic(n, name, suffix).is_some()
}

fn node_by_magic(n: &Node, name: &str, suffix: &str) -> Option<Vec<IpAddr>> {
    let lname = lower(name);
    let host = lname.strip_suffix(&format!(".{}", lower(suffix)))?;
    let s = n.store.read();
    let id = s.view().by_name.get(host)?;
    let info = s.view().nodes.get(id)?;
    if !info.valid {
        return None;
    }
    Some(info.ips.iter().map(|i| i.addr()).collect())
}

fn node_ref_ips(n: &Node, value: &str) -> Option<(String, Vec<IpAddr>)> {
    let r = value.strip_prefix("node:")?;
    let s = n.store.read();
    let v = s.view();
    let id = match webjet_core::crypto::parse_key_b64(r) {
        Some(k) => *v.by_key.get(&k)?,
        None => *v.by_name.get(r)?,
    };
    let info = v.nodes.get(&id)?;
    if !info.valid {
        return None;
    }
    Some((info.name.clone(), info.ips.iter().map(|i| i.addr()).collect()))
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
                r.add_answer(Record::from_rdata(owner.clone(), TTL, RData::AAAA(AAAA(*a))));
                any = true;
            }
            _ => {}
        }
    }
    any || !ips.is_empty()
}

fn resolve(n: &Node, name: &str, qtype: RecordType, suffix: &str, records: &[wp::DnsRecord], r: &mut Message, depth: u8) -> bool {
    if depth > 4 {
        return false;
    }
    let Ok(owner) = Name::from_ascii(format!("{}.", lower(name))) else { return false };
    if let Some(ips) = node_by_magic(n, name, suffix) {
        return push_addrs(r, &owner, &ips, qtype);
    }
    let mut answered = false;
    for rec in records.iter().filter(|x| x.name.as_deref().map(|y| lower(y) == lower(name)).unwrap_or(false)) {
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
                    r.add_answer(Record::from_rdata(owner.clone(), ttl, RData::CNAME(CNAME(t))));
                    answered = true;
                    if qtype != RecordType::CNAME {
                        resolve(n, &target, qtype, suffix, records, r, depth + 1);
                    }
                }
            }
            wp::DnsType::Txt if matches!(qtype, RecordType::TXT | RecordType::ANY) => {
                r.add_answer(Record::from_rdata(owner.clone(), ttl, RData::TXT(TXT::new(vec![value.clone()]))));
                answered = true;
            }
            wp::DnsType::Srv if matches!(qtype, RecordType::SRV | RecordType::ANY) => {
                let f: Vec<&str> = value.split_whitespace().collect();
                if f.len() == 4 {
                    if let (Ok(pr), Ok(w), Ok(port), Ok(t)) = (f[0].parse(), f[1].parse(), f[2].parse(), Name::from_ascii(format!("{}.", lower(f[3])))) {
                        r.add_answer(Record::from_rdata(owner.clone(), ttl, RData::SRV(SRV::new(pr, w, port, t))));
                        answered = true;
                    }
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
    f.rewrite.clone().unwrap_or_default().iter().filter_map(|g| Grant::from_wire(g).ok()).collect()
}

fn reverse_in_rewrite(name: &str, f: &wp::ForwardZone) -> bool {
    ptr_to_ip(name).map(|ip| grants(f).iter().any(|g| g.published.contains(&ip))).unwrap_or(false)
}

/// Forward a query to the zone's servers over the overlay (§11.10.4) and
/// rewrite LAN addresses to published ones (§11.10.5).
async fn forward(n: &Arc<Node>, q: &Message, f: &wp::ForwardZone) -> Option<Message> {
    let gs = grants(f);
    let mut out = q.clone();
    // Reverse lookups for a published address go out as the LAN address.
    let mut ptr_orig: Option<Name> = None;
    if let Some(query) = q.queries().first() {
        if query.query_type() == RecordType::PTR {
            if let Some(ip) = ptr_to_ip(&query.name().to_ascii()) {
                if let Some(g) = gs.iter().find(|g| g.published.contains(&ip)) {
                    let lan = map_prefix(ip, &g.published, &g.lan)?;
                    let mut nq = query.clone();
                    nq.set_name(Name::from_ascii(format!("{}.", ip_to_ptr(lan))).ok()?);
                    ptr_orig = Some(query.name().clone());
                    out = q.clone();
                    out.take_queries();
                    out.add_query(nq);
                }
            }
        }
    }
    let bytes = out.to_vec().ok()?;
    let servers: Vec<IpAddr> = f.servers.clone().unwrap_or_default().iter().filter_map(|s| s.to_ip()).collect();
    let _ = n;
    for srv in servers {
        let bind: SocketAddr = if srv.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
        let Ok(sock) = tokio::net::UdpSocket::bind(bind).await else { continue };
        if sock.send_to(&bytes, SocketAddr::new(srv, 53)).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; 4096];
        let Ok(Ok((len, _))) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await else { continue };
        let Ok(mut resp) = Message::from_vec(&buf[..len]) else { continue };
        if gs.iter().any(|g| g.mapped()) {
            let answers: Vec<Record> = resp.take_answers().into_iter().map(|rec| rewrite_record(rec, &gs)).collect();
            resp.add_answers(answers);
            let adds: Vec<Record> = resp.take_additionals().into_iter().map(|rec| rewrite_record(rec, &gs)).collect();
            resp.add_additionals(adds);
            resp.set_authentic_data(false);
        }
        if let Some(orig) = &ptr_orig {
            resp.take_queries();
            for qq in q.queries() {
                resp.add_query(qq.clone());
            }
            let answers: Vec<Record> = resp
                .take_answers()
                .into_iter()
                .map(|mut rec| {
                    rec.set_name(orig.clone());
                    rec
                })
                .collect();
            resp.add_answers(answers);
        }
        resp.set_id(q.id());
        return Some(resp);
    }
    None
}

fn rewrite_record(mut rec: Record, gs: &[Grant]) -> Record {
    let new = match rec.data() {
        Some(RData::A(a)) => {
            let ip = IpAddr::V4(a.0);
            gs.iter().find(|g| g.lan.contains(&ip)).and_then(|g| map_prefix(ip, &g.lan, &g.published)).and_then(|x| match x {
                IpAddr::V4(v) => Some(RData::A(A(v))),
                _ => None,
            })
        }
        Some(RData::AAAA(a)) => {
            let ip = IpAddr::V6(a.0);
            gs.iter().find(|g| g.lan.contains(&ip)).and_then(|g| map_prefix(ip, &g.lan, &g.published)).and_then(|x| match x {
                IpAddr::V6(v) => Some(RData::AAAA(AAAA(v))),
                _ => None,
            })
        }
        _ => None,
    };
    if let Some(d) = new {
        rec.set_data(Some(d));
    }
    rec
}

/// Build an IPv4/IPv6 UDP packet.
pub fn udp_packet(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, payload: &[u8]) -> Vec<u8> {
    let ulen = 8 + payload.len();
    let mut p = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut h = vec![0u8; 20];
            h[0] = 0x45;
            h[2..4].copy_from_slice(&((20 + ulen) as u16).to_be_bytes());
            h[8] = 64;
            h[9] = PROTO_UDP;
            h[12..16].copy_from_slice(&s.octets());
            h[16..20].copy_from_slice(&d.octets());
            h
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut h = vec![0u8; 40];
            h[0] = 0x60;
            h[4..6].copy_from_slice(&(ulen as u16).to_be_bytes());
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
    p.extend_from_slice(&(ulen as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    packet::fix_checksums(&mut p);
    p
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
        let p = udp_packet("10.7.255.53".parse().unwrap(), 53, "10.7.0.1".parse().unwrap(), 5353, b"hello");
        let parsed = packet::parse(&p).unwrap();
        assert_eq!(parsed.flow.sport, 53);
        assert_eq!(parsed.flow.dport, 5353);
    }
}
