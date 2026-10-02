//! Inner IP packet handling: parsing flows, ICMP error generation (§9.5),
//! checksum-correct address/port rewriting for gateways (§11.9.4) and ECN.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::policy::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Flow {
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
}

impl Flow {
    pub fn reverse(&self) -> Flow {
        Flow { proto: self.proto, src: self.dst, dst: self.src, sport: self.dport, dport: self.sport }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpKind {
    /// Echo request/reply: `sport` holds the identifier.
    Echo { request: bool },
    /// An error message that quotes another packet's header.
    Error,
    Other,
}

#[derive(Clone, Debug)]
pub struct Parsed {
    pub flow: Flow,
    pub l4_offset: usize,
    pub tcp_flags: u8,
    pub icmp: Option<IcmpKind>,
    pub ecn: u8,
    /// For ICMP errors: the quoted flow (as sent by the original sender).
    pub inner: Option<Flow>,
}

pub mod tcpf {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const ACK: u8 = 0x10;
}

pub fn version(p: &[u8]) -> Option<u8> {
    p.first().map(|b| b >> 4)
}

pub fn src_dst(p: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match version(p)? {
        4 if p.len() >= 20 => Some((IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15])), IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19])))),
        6 if p.len() >= 40 => {
            let s: [u8; 16] = p[8..24].try_into().ok()?;
            let d: [u8; 16] = p[24..40].try_into().ok()?;
            Some((IpAddr::V6(Ipv6Addr::from(s)), IpAddr::V6(Ipv6Addr::from(d))))
        }
        _ => None,
    }
}

/// Parse an IPv4 or IPv6 packet into its flow. For IPv6, extension headers
/// are skipped (hop-by-hop, routing, destination options); fragments other
/// than the first carry no ports.
pub fn parse(p: &[u8]) -> Option<Parsed> {
    let (src, dst) = src_dst(p)?;
    let (proto, off, ecn) = match version(p)? {
        4 => {
            let ihl = ((p[0] & 0x0f) as usize) * 4;
            if ihl < 20 || p.len() < ihl {
                return None;
            }
            let total = u16::from_be_bytes([p[2], p[3]]) as usize;
            if total > p.len() || total < ihl {
                return None;
            }
            let frag_off = u16::from_be_bytes([p[6], p[7]]) & 0x1fff;
            if frag_off != 0 {
                return Some(Parsed { flow: Flow { proto: p[9], src, dst, sport: 0, dport: 0 }, l4_offset: ihl, tcp_flags: 0, icmp: None, ecn: p[1] & 3, inner: None });
            }
            (p[9], ihl, p[1] & 3)
        }
        6 => {
            let mut nh = p[6];
            let mut off = 40;
            let ecn = ((u16::from_be_bytes([p[0], p[1]]) >> 4) & 3) as u8;
            loop {
                match nh {
                    0 | 43 | 60 => {
                        if p.len() < off + 8 {
                            return None;
                        }
                        nh = p[off];
                        off += (p[off + 1] as usize + 1) * 8;
                    }
                    44 => {
                        if p.len() < off + 8 {
                            return None;
                        }
                        let frag = u16::from_be_bytes([p[off + 2], p[off + 3]]) >> 3;
                        nh = p[off];
                        off += 8;
                        if frag != 0 {
                            return Some(Parsed { flow: Flow { proto: nh, src, dst, sport: 0, dport: 0 }, l4_offset: off, tcp_flags: 0, icmp: None, ecn, inner: None });
                        }
                    }
                    _ => break,
                }
            }
            (nh, off, ecn)
        }
        _ => return None,
    };
    let l4 = p.get(off..)?;
    let mut parsed = Parsed { flow: Flow { proto, src, dst, sport: 0, dport: 0 }, l4_offset: off, tcp_flags: 0, icmp: None, ecn, inner: None };
    match proto {
        PROTO_TCP if l4.len() >= 20 => {
            parsed.flow.sport = u16::from_be_bytes([l4[0], l4[1]]);
            parsed.flow.dport = u16::from_be_bytes([l4[2], l4[3]]);
            parsed.tcp_flags = l4[13];
        }
        PROTO_UDP if l4.len() >= 8 => {
            parsed.flow.sport = u16::from_be_bytes([l4[0], l4[1]]);
            parsed.flow.dport = u16::from_be_bytes([l4[2], l4[3]]);
        }
        PROTO_ICMP | PROTO_ICMPV6 if l4.len() >= 8 => {
            let ty = l4[0];
            let (echo_req, echo_rep, is_err) = if proto == PROTO_ICMP { (ty == 8, ty == 0, matches!(ty, 3 | 4 | 5 | 11 | 12)) } else { (ty == 128, ty == 129, ty < 128) };
            if echo_req || echo_rep {
                let id = u16::from_be_bytes([l4[4], l4[5]]);
                parsed.flow.sport = id;
                parsed.flow.dport = id;
                parsed.icmp = Some(IcmpKind::Echo { request: echo_req });
            } else if is_err {
                parsed.icmp = Some(IcmpKind::Error);
                parsed.inner = parse_quoted(&l4[8..]);
            } else {
                parsed.icmp = Some(IcmpKind::Other);
            }
        }
        PROTO_TCP | PROTO_UDP | PROTO_ICMP | PROTO_ICMPV6 => return None,
        _ => {}
    }
    Some(parsed)
}

/// Parse the (possibly truncated) packet quoted in an ICMP error.
fn parse_quoted(q: &[u8]) -> Option<Flow> {
    let (src, dst) = src_dst(q)?;
    let (proto, off) = match version(q)? {
        4 => (q[9], ((q[0] & 0x0f) as usize) * 4),
        6 => (q[6], 40),
        _ => return None,
    };
    let l4 = q.get(off..off + 4)?;
    let (sport, dport) = match proto {
        PROTO_TCP | PROTO_UDP => (u16::from_be_bytes([l4[0], l4[1]]), u16::from_be_bytes([l4[2], l4[3]])),
        PROTO_ICMP | PROTO_ICMPV6 => {
            let id = q.get(off + 4..off + 6).map(|b| u16::from_be_bytes([b[0], b[1]]))?;
            (id, id)
        }
        _ => (0, 0),
    };
    Some(Flow { proto, src, dst, sport, dport })
}

// ---------------------------------------------------------------- checksums

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        acc += (*b as u32) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

pub fn checksum(data: &[u8]) -> u16 {
    fold(sum16(data, 0))
}

fn pseudo(src: &IpAddr, dst: &IpAddr, proto: u8, len: usize) -> u32 {
    let mut acc = 0;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            acc = sum16(&s.octets(), acc);
            acc = sum16(&d.octets(), acc);
            acc += proto as u32 + len as u32;
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            acc = sum16(&s.octets(), acc);
            acc = sum16(&d.octets(), acc);
            acc += (len as u32 >> 16) + (len as u32 & 0xffff) + proto as u32;
        }
        _ => {}
    }
    acc
}

/// Recompute every checksum of a packet (IPv4 header, TCP/UDP/ICMP).
/// Used after rewriting addresses or ports. Fragments other than the first
/// keep their L4 bytes untouched.
pub fn fix_checksums(p: &mut [u8]) {
    let Some(parsed) = parse(p) else { return };
    let (src, dst) = (parsed.flow.src, parsed.flow.dst);
    let off = parsed.l4_offset;
    if version(p) == Some(4) {
        let ihl = ((p[0] & 0x0f) as usize) * 4;
        p[10] = 0;
        p[11] = 0;
        let c = checksum(&p[..ihl]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        let frag_off = u16::from_be_bytes([p[6], p[7]]) & 0x1fff;
        let mf = p[6] & 0x20 != 0;
        if frag_off != 0 || mf {
            // L4 checksum covers the whole datagram; can't recompute on a fragment.
            return;
        }
    }
    let total = if version(p) == Some(4) { u16::from_be_bytes([p[2], p[3]]) as usize } else { 40 + u16::from_be_bytes([p[4], p[5]]) as usize };
    let end = total.min(p.len());
    if end <= off {
        return;
    }
    let len = end - off;
    match parsed.flow.proto {
        PROTO_TCP if len >= 20 => {
            p[off + 16] = 0;
            p[off + 17] = 0;
            let c = fold(sum16(&p[off..end], pseudo(&src, &dst, PROTO_TCP, len)));
            p[off + 16..off + 18].copy_from_slice(&c.to_be_bytes());
        }
        PROTO_UDP if len >= 8 => {
            p[off + 6] = 0;
            p[off + 7] = 0;
            let mut c = fold(sum16(&p[off..end], pseudo(&src, &dst, PROTO_UDP, len)));
            if c == 0 {
                c = 0xffff;
            }
            p[off + 6..off + 8].copy_from_slice(&c.to_be_bytes());
        }
        PROTO_ICMP if len >= 4 => {
            p[off + 2] = 0;
            p[off + 3] = 0;
            let c = checksum(&p[off..end]);
            p[off + 2..off + 4].copy_from_slice(&c.to_be_bytes());
        }
        PROTO_ICMPV6 if len >= 4 => {
            p[off + 2] = 0;
            p[off + 3] = 0;
            let c = fold(sum16(&p[off..end], pseudo(&src, &dst, PROTO_ICMPV6, len)));
            p[off + 2..off + 4].copy_from_slice(&c.to_be_bytes());
        }
        _ => {}
    }
}

fn set_addr(p: &mut [u8], src: bool, a: IpAddr) {
    match (version(p), a) {
        (Some(4), IpAddr::V4(v)) => {
            let o = if src { 12 } else { 16 };
            p[o..o + 4].copy_from_slice(&v.octets());
        }
        (Some(6), IpAddr::V6(v)) => {
            let o = if src { 8 } else { 24 };
            p[o..o + 16].copy_from_slice(&v.octets());
        }
        _ => {}
    }
}

fn set_port(p: &mut [u8], off: usize, proto: u8, src: bool, port: u16) {
    match proto {
        PROTO_TCP | PROTO_UDP => {
            let o = off + if src { 0 } else { 2 };
            if p.len() >= o + 2 {
                p[o..o + 2].copy_from_slice(&port.to_be_bytes());
            }
        }
        PROTO_ICMP | PROTO_ICMPV6
            if p.len() >= off + 6 => {
                p[off + 4..off + 6].copy_from_slice(&port.to_be_bytes());
            }
        _ => {}
    }
}

/// Rewrite a packet's source and/or destination address and port, and its
/// checksums. For ICMP errors, the quoted header is rewritten with the
/// inverse mapping (its source is our destination), so PMTUD and port
/// unreachables survive NAT (§11.9.4).
pub fn rewrite(p: &mut [u8], new_src: Option<(IpAddr, u16)>, new_dst: Option<(IpAddr, u16)>) {
    let Some(parsed) = parse(p) else { return };
    let off = parsed.l4_offset;
    let proto = parsed.flow.proto;
    let is_echo = matches!(parsed.icmp, Some(IcmpKind::Echo { .. }));
    if let Some((a, port)) = new_src {
        set_addr(p, true, a);
        if proto == PROTO_TCP || proto == PROTO_UDP || is_echo {
            set_port(p, off, proto, true, port);
        }
    }
    if let Some((a, port)) = new_dst {
        set_addr(p, false, a);
        if proto == PROTO_TCP || proto == PROTO_UDP {
            set_port(p, off, proto, false, port);
        }
    }
    if parsed.icmp == Some(IcmpKind::Error) && p.len() > off + 8 {
        // The quoted packet went from (our new dst) to (our new src).
        let q = off + 8;
        if let Some(inner) = parse_quoted(&p[q..]) {
            let qoff = match version(&p[q..]) {
                Some(4) => ((p[q] & 0x0f) as usize) * 4,
                _ => 40,
            };
            if let Some((a, port)) = new_dst {
                set_addr(&mut p[q..], true, a);
                set_port(&mut p[q..], qoff, inner.proto, true, port);
            }
            if let Some((a, port)) = new_src {
                set_addr(&mut p[q..], false, a);
                if inner.proto == PROTO_TCP || inner.proto == PROTO_UDP {
                    set_port(&mut p[q..], qoff, inner.proto, false, port);
                }
            }
            if version(&p[q..]) == Some(4) && p.len() >= q + 20 {
                let ihl = qoff.min(p.len() - q);
                p[q + 10] = 0;
                p[q + 11] = 0;
                let c = checksum(&p[q..q + ihl]);
                p[q + 10..q + 12].copy_from_slice(&c.to_be_bytes());
            }
        }
    }
    fix_checksums(p);
}

/// Set the IP header's ECN field (§17.7).
pub fn set_ecn(p: &mut [u8], ecn: u8) {
    match version(p) {
        Some(4) if p.len() >= 20 => {
            p[1] = (p[1] & !3) | (ecn & 3);
            let ihl = ((p[0] & 0x0f) as usize) * 4;
            p[10] = 0;
            p[11] = 0;
            let c = checksum(&p[..ihl.min(p.len())]);
            p[10..12].copy_from_slice(&c.to_be_bytes());
        }
        Some(6) if p.len() >= 40 => {
            let v = u16::from_be_bytes([p[0], p[1]]);
            let v = (v & !0x0030) | (((ecn & 3) as u16) << 4);
            p[0..2].copy_from_slice(&v.to_be_bytes());
        }
        _ => {}
    }
}

pub fn ecn_of(p: &[u8]) -> u8 {
    match version(p) {
        Some(4) if p.len() >= 2 => p[1] & 3,
        Some(6) if p.len() >= 2 => ((u16::from_be_bytes([p[0], p[1]]) >> 4) & 3) as u8,
        _ => 0,
    }
}

// ---------------------------------------------------------------- ICMP generation (§9.5)

#[derive(Clone, Copy, Debug)]
pub enum Unreach {
    /// "Administratively prohibited" (policy denied).
    Prohibited,
    /// "Host unreachable" (no route).
    Host,
}

/// Build an ICMP/ICMPv6 destination-unreachable reply to `orig`, sourced
/// from `orig`'s destination, to be written back into the tun interface.
pub fn icmp_unreachable(orig: &[u8], why: Unreach) -> Option<Vec<u8>> {
    let parsed = parse(orig)?;
    if parsed.icmp == Some(IcmpKind::Error) {
        return None; // never answer an error with an error
    }
    let (src, dst) = (parsed.flow.dst, parsed.flow.src);
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let quote = &orig[..orig.len().min(((orig[0] & 0x0f) as usize) * 4 + 8)];
            let code = match why {
                Unreach::Prohibited => 13,
                Unreach::Host => 1,
            };
            let mut icmp = vec![3, code, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(quote);
            let c = checksum(&icmp);
            icmp[2..4].copy_from_slice(&c.to_be_bytes());
            let total = 20 + icmp.len();
            let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, PROTO_ICMP, 0, 0];
            p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            let c = checksum(&p);
            p[10..12].copy_from_slice(&c.to_be_bytes());
            p.extend_from_slice(&icmp);
            Some(p)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let quote = &orig[..orig.len().min(1280 - 48)];
            let code = match why {
                Unreach::Prohibited => 1,
                Unreach::Host => 3,
            };
            let mut icmp = vec![1, code, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(quote);
            let mut p = vec![0x60, 0, 0, 0];
            p.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
            p.push(PROTO_ICMPV6);
            p.push(64);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(&icmp);
            fix_checksums(&mut p);
            Some(p)
        }
        _ => None,
    }
}

/// Simple token bucket for rate-limiting ICMP replies and logs.
#[derive(Clone, Debug)]
pub struct Bucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: std::time::Instant,
}

impl Bucket {
    pub fn new(rate: f64, burst: f64) -> Self {
        Bucket { tokens: burst, rate, burst, last: std::time::Instant::now() }
    }
    pub fn take(&mut self) -> bool {
        let now = std::time::Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(self.burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn udp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = 28 + payload.len();
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0];
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        fix_checksums(&mut p);
        p
    }

    pub fn tcp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        fix_checksums(&mut p);
        p
    }

    fn verify_udp(p: &[u8]) -> bool {
        let parsed = parse(p).unwrap();
        let off = parsed.l4_offset;
        fold(sum16(&p[off..], pseudo(&parsed.flow.src, &parsed.flow.dst, 17, p.len() - off))) == 0 && checksum(&p[..20]) == 0
    }

    #[test]
    fn parse_and_rewrite_udp() {
        let mut p = udp4([10, 7, 0, 1], [10, 2, 2, 17], 5000, 53, b"hello");
        assert!(verify_udp(&p));
        let f = parse(&p).unwrap().flow;
        assert_eq!((f.sport, f.dport, f.proto), (5000, 53, 17));
        rewrite(&mut p, Some(("192.168.1.1".parse().unwrap(), 40000)), Some(("192.168.1.17".parse().unwrap(), 53)));
        assert!(verify_udp(&p));
        let f = parse(&p).unwrap().flow;
        assert_eq!(f.src, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(f.sport, 40000);
    }

    #[test]
    fn icmp_reply_and_quoted_rewrite() {
        let p = tcp4([10, 7, 0, 1], [10, 7, 0, 2], 1234, 22, tcpf::SYN);
        let r = icmp_unreachable(&p, Unreach::Prohibited).unwrap();
        let parsed = parse(&r).unwrap();
        assert_eq!(parsed.icmp, Some(IcmpKind::Error));
        let inner = parsed.inner.unwrap();
        assert_eq!(inner.dport, 22);
        assert_eq!(checksum(&r[20..]), 0);
        assert!(icmp_unreachable(&r, Unreach::Host).is_none());
        // Translate the error as a gateway would.
        let mut r2 = r.clone();
        rewrite(&mut r2, Some(("10.2.2.17".parse().unwrap(), 0)), Some(("10.7.0.9".parse().unwrap(), 4321)));
        let pr = parse(&r2).unwrap();
        assert_eq!(pr.inner.unwrap().src, "10.7.0.9".parse::<IpAddr>().unwrap());
        assert_eq!(pr.inner.unwrap().sport, 4321);
        assert_eq!(checksum(&r2[20..]), 0);
    }

    #[test]
    fn ecn_bits() {
        let mut p = udp4([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, b"");
        set_ecn(&mut p, 3);
        assert_eq!(ecn_of(&p), 3);
        assert_eq!(checksum(&p[..20]), 0);
    }

    #[test]
    fn garbage_never_panics() {
        for n in 0..200usize {
            let v: Vec<u8> = (0..n).map(|i| (i * 131 + n) as u8).collect();
            let _ = parse(&v);
            let mut w = v.clone();
            if !w.is_empty() {
                w[0] = 0x45;
            }
            let _ = parse(&w);
            rewrite(&mut w, Some(("1.2.3.4".parse().unwrap(), 1)), None);
            let _ = icmp_unreachable(&w, Unreach::Host);
        }
    }
}
