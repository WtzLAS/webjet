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
        Flow {
            proto: self.proto,
            src: self.dst,
            dst: self.src,
            sport: self.dport,
            dport: self.sport,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpKind {
    /// Echo request/reply: `sport` holds the identifier.
    Echo {
        request: bool,
    },
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
    pub fragment: Fragment,
    /// The datagram's fragment id (IPv4 Identification, IPv6 fragment
    /// header Identification); 0 when the packet is whole. With source,
    /// destination and protocol it ties later fragments to the first one.
    pub frag_id: u32,
}

/// Where a packet stands in IP fragmentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fragment {
    /// Not fragmented.
    Whole,
    /// The first fragment: has the L4 header, but not the whole datagram
    /// its checksum covers.
    First,
    /// A later fragment: no L4 header; `l4_offset` points at payload and
    /// the ports are 0.
    Later,
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
        4 if p.len() >= 20 => Some((
            IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15])),
            IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19])),
        )),
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
    let later = |proto: u8, l4_offset: usize, ecn: u8, frag_id: u32| Parsed {
        flow: Flow {
            proto,
            src,
            dst,
            sport: 0,
            dport: 0,
        },
        l4_offset,
        tcp_flags: 0,
        icmp: None,
        ecn,
        inner: None,
        fragment: Fragment::Later,
        frag_id,
    };
    let (proto, off, ecn, fragment, frag_id) = match version(p)? {
        4 => {
            let ihl = ((p[0] & 0x0f) as usize) * 4;
            if ihl < 20 || p.len() < ihl {
                return None;
            }
            let total = u16::from_be_bytes([p[2], p[3]]) as usize;
            if total > p.len() || total < ihl {
                return None;
            }
            let id = u32::from(u16::from_be_bytes([p[4], p[5]]));
            let frag_off = u16::from_be_bytes([p[6], p[7]]) & 0x1fff;
            if frag_off != 0 {
                return Some(later(p[9], ihl, p[1] & 3, id));
            }
            let (fragment, id) = if p[6] & 0x20 != 0 {
                (Fragment::First, id)
            } else {
                (Fragment::Whole, 0)
            };
            (p[9], ihl, p[1] & 3, fragment, id)
        }
        6 => {
            let mut nh = p[6];
            let mut off = 40;
            let ecn = ((u16::from_be_bytes([p[0], p[1]]) >> 4) & 3) as u8;
            let mut fragment = Fragment::Whole;
            let mut frag_id = 0;
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
                        let more = p[off + 3] & 1 != 0;
                        let id = crate::bytes::be_u32(p, off + 4)?;
                        nh = p[off];
                        off += 8;
                        if frag != 0 {
                            return Some(later(nh, off, ecn, id));
                        }
                        if more {
                            fragment = Fragment::First;
                            frag_id = id;
                        }
                    }
                    _ => break,
                }
            }
            (nh, off, ecn, fragment, frag_id)
        }
        _ => return None,
    };
    let l4 = p.get(off..)?;
    let mut parsed = Parsed {
        flow: Flow {
            proto,
            src,
            dst,
            sport: 0,
            dport: 0,
        },
        l4_offset: off,
        tcp_flags: 0,
        icmp: None,
        ecn,
        inner: None,
        fragment,
        frag_id,
    };
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
            let (echo_req, echo_rep, is_err) = if proto == PROTO_ICMP {
                (ty == 8, ty == 0, matches!(ty, 3 | 4 | 5 | 11 | 12))
            } else {
                (ty == 128, ty == 129, ty < 128)
            };
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
        PROTO_TCP | PROTO_UDP => (
            u16::from_be_bytes([l4[0], l4[1]]),
            u16::from_be_bytes([l4[2], l4[3]]),
        ),
        PROTO_ICMP | PROTO_ICMPV6 => {
            let id = q
                .get(off + 4..off + 6)
                .map(|b| u16::from_be_bytes([b[0], b[1]]))?;
            (id, id)
        }
        _ => (0, 0),
    };
    Some(Flow {
        proto,
        src,
        dst,
        sport,
        dport,
    })
}

// ---------------------------------------------------------------- checksums

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let (pairs, rest) = data.as_chunks::<2>();
    for c in pairs {
        acc += u16::from_be_bytes(*c) as u32;
    }
    if let [b] = rest {
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
    }
    if parsed.fragment != Fragment::Whole {
        // The L4 checksum covers the whole datagram; a fragment can't
        // recompute it (see `map_addrs` for an incremental update).
        return;
    }
    let total = if version(p) == Some(4) {
        u16::from_be_bytes([p[2], p[3]]) as usize
    } else {
        40 + u16::from_be_bytes([p[4], p[5]]) as usize
    };
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
        PROTO_ICMP | PROTO_ICMPV6 if p.len() >= off + 6 => {
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
    // A later fragment has no ports: its L4 bytes are payload.
    let ports = parsed.fragment != Fragment::Later;
    // A first fragment's L4 checksum covers the whole datagram, which
    // `fix_checksums` can't see: update it for what changes here instead.
    let before = (parsed.fragment == Fragment::First).then(|| l4_sum_fields(p, &parsed));
    if let Some((a, port)) = new_src {
        set_addr(p, true, a);
        if ports && (proto == PROTO_TCP || proto == PROTO_UDP || is_echo) {
            set_port(p, off, proto, true, port);
        }
    }
    if let Some((a, port)) = new_dst {
        set_addr(p, false, a);
        if ports && (proto == PROTO_TCP || proto == PROTO_UDP) {
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
            fix_quoted_ip_checksum(p, q);
        }
    }
    if let Some(old) = before {
        adjust_l4_checksum(p, &parsed, &old);
    }
    fix_checksums(p);
}

/// The bytes of a packet's L4 checksum that `rewrite` may change: the
/// pseudo header's addresses (TCP, UDP, ICMPv6) and the ports or echo id.
fn l4_sum_fields(p: &[u8], parsed: &Parsed) -> Vec<u8> {
    let off = parsed.l4_offset;
    let mut v = Vec::with_capacity(36);
    if parsed.flow.proto != PROTO_ICMP
        && let Some((s, d)) = src_dst(p)
    {
        v.extend_from_slice(&octets(s));
        v.extend_from_slice(&octets(d));
    }
    let span = match parsed.flow.proto {
        PROTO_TCP | PROTO_UDP => off..off + 4,
        PROTO_ICMP | PROTO_ICMPV6 => off + 4..off + 6,
        _ => off..off,
    };
    v.extend_from_slice(p.get(span).unwrap_or_default());
    v
}

/// Update the L4 checksum of a first fragment for the fields `rewrite`
/// changed (`old`: `l4_sum_fields` before the change; RFC 1624).
fn adjust_l4_checksum(p: &mut [u8], parsed: &Parsed, old: &[u8]) {
    let off = parsed.l4_offset;
    let at = match parsed.flow.proto {
        PROTO_TCP => off + 16,
        PROTO_UDP => off + 6,
        PROTO_ICMP | PROTO_ICMPV6 if matches!(parsed.icmp, Some(IcmpKind::Echo { .. })) => off + 2,
        _ => return,
    };
    let new = l4_sum_fields(p, parsed);
    if p.len() < at + 2 || new.len() != old.len() {
        return;
    }
    let c = u16::from_be_bytes([p[at], p[at + 1]]);
    if parsed.flow.proto == PROTO_UDP && c == 0 && version(p) == Some(4) {
        return; // IPv4 UDP without a checksum
    }
    let mut c = adjust_checksum(c, old, &new);
    if parsed.flow.proto == PROTO_UDP && c == 0 {
        c = 0xffff;
    }
    p[at..at + 2].copy_from_slice(&c.to_be_bytes());
}

/// Recompute the IPv4 header checksum of the packet an ICMP error quotes
/// (at `q`); the quote may be cut short.
fn fix_quoted_ip_checksum(p: &mut [u8], q: usize) {
    if version(p.get(q..).unwrap_or_default()) == Some(4) && p.len() >= q + 20 {
        let ihl = (((p[q] & 0x0f) as usize) * 4).min(p.len() - q);
        p[q + 10] = 0;
        p[q + 11] = 0;
        let c = checksum(&p[q..q + ihl]);
        p[q + 10..q + 12].copy_from_slice(&c.to_be_bytes());
    }
}

/// An address's bytes on the stack (`map_addrs` runs per packet).
struct Octets([u8; 16], usize);

impl std::ops::Deref for Octets {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0[..self.1]
    }
}

fn octets(a: IpAddr) -> Octets {
    let mut b = [0u8; 16];
    match a {
        IpAddr::V4(v) => {
            b[..4].copy_from_slice(&v.octets());
            Octets(b, 4)
        }
        IpAddr::V6(v) => Octets(v.octets(), 16),
    }
}

/// Update a checksum for `old` bytes replaced by `new` (RFC 1624:
/// HC' = ~(~HC + ~m + m')). Both are whole 16-bit words.
fn adjust_checksum(c: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut acc = u32::from(!c);
    for w in old.as_chunks::<2>().0 {
        acc += u32::from(!u16::from_be_bytes(*w));
    }
    fold(sum16(new, acc))
}

/// Translate one address by a 1:1 prefix mapping (§11.9.2), leaving ports
/// alone: the outer source (`src`) or destination goes through `f`; for an
/// ICMP error, the quoted packet's opposite address too (it travelled the
/// other way), so PMTUD and unreachables survive the mapping. The L4
/// checksum is updated incrementally, which also works on a first fragment
/// (whose checksum covers bytes it doesn't carry). Returns false, leaving
/// the packet as it was, when `f` doesn't map the outer address.
pub fn map_addrs(p: &mut [u8], src: bool, f: impl Fn(IpAddr) -> Option<IpAddr>) -> bool {
    let Some(parsed) = parse(p) else { return false };
    let old = if src {
        parsed.flow.src
    } else {
        parsed.flow.dst
    };
    let Some(new) = f(old).filter(|a| a.is_ipv4() == old.is_ipv4()) else {
        return false;
    };
    set_addr(p, src, new);
    let off = parsed.l4_offset;
    if parsed.icmp == Some(IcmpKind::Error) {
        let q = off + 8;
        if let Some(inner) = p.get(q..).and_then(parse_quoted) {
            let qa = if src { inner.dst } else { inner.src };
            if let Some(nq) = f(qa).filter(|a| a.is_ipv4() == qa.is_ipv4()) {
                set_addr(&mut p[q..], !src, nq);
                fix_quoted_ip_checksum(p, q);
            }
        }
        // An ICMP error is never fragmented by us; recompute it all.
        fix_checksums(p);
        return true;
    }
    if version(p) == Some(4) {
        let ihl = ((p[0] & 0x0f) as usize) * 4;
        p[10] = 0;
        p[11] = 0;
        let c = checksum(&p[..ihl]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
    }
    if parsed.fragment == Fragment::Later {
        return true;
    }
    // Checksums with a pseudo header (ICMPv4 has none).
    let at = match parsed.flow.proto {
        PROTO_TCP => off + 16,
        PROTO_UDP => off + 6,
        PROTO_ICMPV6 => off + 2,
        _ => return true,
    };
    if p.len() < at + 2 {
        return true;
    }
    let c = u16::from_be_bytes([p[at], p[at + 1]]);
    if parsed.flow.proto == PROTO_UDP && c == 0 && old.is_ipv4() {
        return true; // IPv4 UDP without a checksum
    }
    let mut c = adjust_checksum(c, &octets(old), &octets(new));
    if parsed.flow.proto == PROTO_UDP && c == 0 {
        c = 0xffff;
    }
    p[at..at + 2].copy_from_slice(&c.to_be_bytes());
    true
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
    if parsed.fragment == Fragment::Later {
        return None; // only the first fragment (RFC 1122 3.2.2)
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
            p[2..4].copy_from_slice(&u16::try_from(total).ok()?.to_be_bytes());
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
            p.extend_from_slice(&u16::try_from(icmp.len()).ok()?.to_be_bytes());
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
        Bucket {
            tokens: burst,
            rate,
            burst,
            last: std::time::Instant::now(),
        }
    }
    pub fn take(&mut self) -> bool {
        let now = std::time::Instant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(self.burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Build an ICMP(v6) echo request or reply.
pub fn icmp_echo(
    src: IpAddr,
    dst: IpAddr,
    request: bool,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let l4len = 8 + payload.len();
    // Larger than an IP packet can be (IPv4 total length includes 20 more).
    let Some(len16) = u16::try_from(l4len).ok().filter(|l| *l <= u16::MAX - 20) else {
        return Vec::new();
    };
    let mut p = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut h = vec![0u8; 20];
            h[0] = 0x45;
            h[2..4].copy_from_slice(&(20 + len16).to_be_bytes());
            h[8] = 64;
            h[9] = PROTO_ICMP;
            h[12..16].copy_from_slice(&s.octets());
            h[16..20].copy_from_slice(&d.octets());
            h.push(if request { 8 } else { 0 });
            h
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut h = vec![0u8; 40];
            h[0] = 0x60;
            h[4..6].copy_from_slice(&len16.to_be_bytes());
            h[6] = PROTO_ICMPV6;
            h[7] = 64;
            h[8..24].copy_from_slice(&s.octets());
            h[24..40].copy_from_slice(&d.octets());
            h.push(if request { 128 } else { 129 });
            h
        }
        _ => return Vec::new(),
    };
    p.push(0);
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(payload);
    fix_checksums(&mut p);
    p
}

/// Turn an echo request into its reply (for a userspace host stack).
pub fn echo_reply(req: &[u8]) -> Option<Vec<u8>> {
    let p = parse(req)?;
    if p.icmp != Some(IcmpKind::Echo { request: true }) {
        return None;
    }
    let off = p.l4_offset;
    let id = u16::from_be_bytes([*req.get(off + 4)?, *req.get(off + 5)?]);
    let seq = u16::from_be_bytes([*req.get(off + 6)?, *req.get(off + 7)?]);
    Some(icmp_echo(
        p.flow.dst,
        p.flow.src,
        false,
        id,
        seq,
        req.get(off + 8..)?,
    ))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn oversized_echo_is_not_built() {
        let (a, b) = (IpAddr::from([10, 0, 0, 1]), IpAddr::from([10, 0, 0, 2]));
        assert!(icmp_echo(a, b, true, 1, 1, &vec![0; 70_000]).is_empty());
        assert!(!icmp_echo(a, b, true, 1, 1, &[0; 64]).is_empty());
    }

    #[test]
    fn fragments_carry_their_datagram_id() {
        // IPv4: the 16-bit Identification, only for fragments.
        let mut p = udp4([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, &[0; 16]);
        p[4..6].copy_from_slice(&0xbeefu16.to_be_bytes());
        assert_eq!(parse(&p).unwrap().frag_id, 0);
        p[6] = 0x20;
        let first = parse(&p).unwrap();
        assert_eq!((first.fragment, first.frag_id), (Fragment::First, 0xbeef));
        p[6] = 0;
        p[7] = 3;
        let later = parse(&p).unwrap();
        assert_eq!((later.fragment, later.frag_id), (Fragment::Later, 0xbeef));
        // IPv6: the fragment header's 32-bit Identification.
        let mut v6 = vec![0x60, 0, 0, 0, 0, 24, 44, 64];
        v6.extend_from_slice(&[0xfd; 16]);
        v6.extend_from_slice(&[0xfe; 16]);
        v6.extend_from_slice(&[PROTO_UDP, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef]);
        v6.extend_from_slice(&[0, 9, 0, 53, 0, 16, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
        let first = parse(&v6).unwrap();
        assert_eq!(
            (first.fragment, first.frag_id, first.flow.dport),
            (Fragment::First, 0xdead_beef, 53)
        );
        v6[42..44].copy_from_slice(&[0, 0x10]); // offset 2 × 8 bytes, last
        let later = parse(&v6).unwrap();
        assert_eq!(
            (later.fragment, later.frag_id, later.flow.dport),
            (Fragment::Later, 0xdead_beef, 0)
        );
    }

    pub use crate::testutil::packets::{tcp4, udp4};

    fn verify_udp(p: &[u8]) -> bool {
        let parsed = parse(p).unwrap();
        let off = parsed.l4_offset;
        fold(sum16(
            &p[off..],
            pseudo(&parsed.flow.src, &parsed.flow.dst, 17, p.len() - off),
        )) == 0
            && checksum(&p[..20]) == 0
    }

    #[test]
    fn rewriting_a_first_fragment_keeps_the_datagram_checksum() {
        // The UDP checksum of a first fragment covers bytes in later
        // fragments: rewriting must adjust it, not recompute it.
        for (src, dst) in [
            ([10, 0, 0, 1], [10, 0, 0, 2]),
            ([203, 0, 113, 5], [10, 7, 255, 53]),
        ] {
            let whole = udp4(src, dst, 5555, 27015, &[7u8; 64]);
            let mut first = whole[..20 + 32].to_vec();
            first[2..4].copy_from_slice(&52u16.to_be_bytes());
            first[6] = 0x20;
            fix_checksums(&mut first);
            let to = (IpAddr::from([10, 7, 0, 3]), 27016);
            let from = (IpAddr::from([10, 7, 0, 2]), 61000);
            rewrite(&mut first, Some(from), Some(to));
            let mut expect = whole.clone();
            rewrite(&mut expect, Some(from), Some(to));
            assert_eq!(first[20..28], expect[20..28], "ports and checksum");
            assert_eq!(checksum(&first[..20]), 0);
        }
    }

    #[test]
    fn parse_and_rewrite_udp() {
        let mut p = udp4([10, 7, 0, 1], [10, 2, 2, 17], 5000, 53, b"hello");
        assert!(verify_udp(&p));
        let f = parse(&p).unwrap().flow;
        assert_eq!((f.sport, f.dport, f.proto), (5000, 53, 17));
        rewrite(
            &mut p,
            Some(("192.168.1.1".parse().unwrap(), 40000)),
            Some(("192.168.1.17".parse().unwrap(), 53)),
        );
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
        let mut r2 = r;
        rewrite(
            &mut r2,
            Some(("10.2.2.17".parse().unwrap(), 0)),
            Some(("10.7.0.9".parse().unwrap(), 4321)),
        );
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

#[cfg(test)]
mod prop {
    use super::*;
    use crate::testutil::packets::{tcp4, udp4};
    use proptest::prelude::*;

    /// Every checksum of a TCP/UDP/ICMP IPv4 packet verifies.
    fn checksums_ok(p: &[u8]) -> bool {
        let Some(pp) = parse(p) else { return false };
        let ihl = ((p[0] & 0x0f) as usize) * 4;
        if checksum(&p[..ihl]) != 0 {
            return false;
        }
        let off = pp.l4_offset;
        match pp.flow.proto {
            PROTO_TCP | PROTO_UDP => {
                fold(sum16(
                    &p[off..],
                    pseudo(&pp.flow.src, &pp.flow.dst, pp.flow.proto, p.len() - off),
                )) == 0
            }
            PROTO_ICMP => checksum(&p[off..]) == 0,
            _ => true,
        }
    }

    fn v4() -> impl Strategy<Value = [u8; 4]> {
        any::<[u8; 4]>()
    }

    proptest! {
        #[test]
        fn parse_reads_what_was_built(
            src in v4(), dst in v4(), sport in any::<u16>(), dport in any::<u16>(),
            payload in proptest::collection::vec(any::<u8>(), 0..200),
            flags in any::<u8>(),
        ) {
            let u = udp4(src, dst, sport, dport, &payload);
            let p = parse(&u).unwrap();
            prop_assert_eq!(p.flow, Flow {
                proto: PROTO_UDP,
                src: IpAddr::from(src),
                dst: IpAddr::from(dst),
                sport,
                dport,
            });
            prop_assert!(checksums_ok(&u));
            let t = tcp4(src, dst, sport, dport, flags);
            let p = parse(&t).unwrap();
            prop_assert_eq!((p.flow.proto, p.tcp_flags), (PROTO_TCP, flags));
            prop_assert_eq!(src_dst(&t), Some((IpAddr::from(src), IpAddr::from(dst))));
        }

        /// Rewriting keeps the packet valid, changes exactly what was asked,
        /// and rewriting back restores the original bytes.
        #[test]
        fn rewrite_roundtrip(
            src in v4(), dst in v4(), sport in any::<u16>(), dport in any::<u16>(),
            nsrc in v4(), nsport in any::<u16>(), ndst in v4(), ndport in any::<u16>(),
            tcp in any::<bool>(),
            payload in proptest::collection::vec(any::<u8>(), 0..100),
            which in 0u8..3,
        ) {
            let orig = if tcp {
                tcp4(src, dst, sport, dport, tcpf::SYN)
            } else {
                udp4(src, dst, sport, dport, &payload)
            };
            let s = (which != 1).then_some((IpAddr::from(nsrc), nsport));
            let d = (which != 0).then_some((IpAddr::from(ndst), ndport));
            let mut p = orig.clone();
            rewrite(&mut p, s, d);
            prop_assert!(checksums_ok(&p));
            let f = parse(&p).unwrap().flow;
            let want_src = s.unwrap_or((IpAddr::from(src), sport));
            let want_dst = d.unwrap_or((IpAddr::from(dst), dport));
            prop_assert_eq!((f.src, f.sport), want_src);
            prop_assert_eq!((f.dst, f.dport), want_dst);
            rewrite(
                &mut p,
                s.map(|_| (IpAddr::from(src), sport)),
                d.map(|_| (IpAddr::from(dst), dport)),
            );
            prop_assert_eq!(p, orig);
        }

        /// An ICMP error about a packet quotes it; rewriting the error with
        /// the inverse mapping rewrites the quote too.
        #[test]
        fn icmp_errors_quote_and_follow_nat(
            src in v4(), dst in v4(), sport in any::<u16>(), dport in any::<u16>(),
            nsrc in v4(), nsport in any::<u16>(),
            prohibited in any::<bool>(),
        ) {
            let orig = udp4(src, dst, sport, dport, b"payload");
            let why = if prohibited { Unreach::Prohibited } else { Unreach::Host };
            let Some(err) = icmp_unreachable(&orig, why) else {
                // Never answered: errors about ICMP errors, non-unicast sources.
                return Ok(());
            };
            let e = parse(&err).unwrap();
            prop_assert_eq!(e.icmp, Some(IcmpKind::Error));
            prop_assert_eq!(e.flow.dst, IpAddr::from(src), "sent back to the source");
            prop_assert_eq!(e.inner, Some(parse(&orig).unwrap().flow));
            prop_assert!(checksums_ok(&err));
            // The error travels back through a gateway that had translated
            // the source: its destination becomes the original source.
            let mut back = err;
            rewrite(&mut back, None, Some((IpAddr::from(nsrc), nsport)));
            let b = parse(&back).unwrap();
            prop_assert_eq!(b.flow.dst, IpAddr::from(nsrc));
            let inner = b.inner.unwrap();
            prop_assert_eq!((inner.src, inner.sport), (IpAddr::from(nsrc), nsport));
            prop_assert!(checksums_ok(&back));
        }

        /// A mapped gateway translates addresses only: ports stay, the
        /// incrementally updated checksums verify, and the mapping undoes.
        #[test]
        fn map_addrs_keeps_ports_and_checksums(
            src in v4(), dst in v4(), sport in any::<u16>(), dport in any::<u16>(),
            to in v4(), tcp in any::<bool>(), on_src in any::<bool>(),
            payload in proptest::collection::vec(any::<u8>(), 0..100),
        ) {
            let orig = if tcp {
                tcp4(src, dst, sport, dport, tcpf::SYN)
            } else {
                udp4(src, dst, sport, dport, &payload)
            };
            let old = IpAddr::from(if on_src { src } else { dst });
            let mut p = orig.clone();
            prop_assert!(map_addrs(&mut p, on_src, |a| (a == old).then_some(IpAddr::from(to))));
            prop_assert!(checksums_ok(&p));
            let f = parse(&p).unwrap().flow;
            prop_assert_eq!((f.sport, f.dport), (sport, dport));
            prop_assert_eq!(if on_src { f.src } else { f.dst }, IpAddr::from(to));
            prop_assert!(map_addrs(&mut p, on_src, |a| (a == IpAddr::from(to)).then_some(old)));
            prop_assert_eq!(p, orig);
        }

        /// An ICMP error coming back through a mapped gateway: the quoted
        /// packet's addresses follow the mapping and its ports stay.
        #[test]
        fn map_addrs_follows_icmp_quotes(
            client in v4(), lan in v4(), router in v4(), sport in any::<u16>(), dport in any::<u16>(),
            published in v4(),
        ) {
            // Inside the LAN the packet went client → lan host; a router on
            // the way answers it.
            let quoted = udp4(client, lan, sport, dport, b"payload");
            let Some(mut err) = icmp_unreachable(&quoted, Unreach::Host) else {
                return Ok(());
            };
            set_addr(&mut err, true, IpAddr::from(router));
            fix_checksums(&mut err);
            let map = |a: IpAddr| (a == IpAddr::from(lan)).then_some(IpAddr::from(published));
            let router_mapped = |a: IpAddr| {
                if a == IpAddr::from(router) { Some(IpAddr::from(published)) } else { map(a) }
            };
            prop_assert!(map_addrs(&mut err, true, router_mapped));
            let e = parse(&err).unwrap();
            prop_assert!(checksums_ok(&err));
            let inner = e.inner.unwrap();
            prop_assert_eq!((inner.src, inner.sport), (IpAddr::from(client), sport));
            prop_assert_eq!(inner.dport, dport);
        }

        /// A later fragment carries payload where ports would be: address
        /// rewrites leave it alone, and it gets no ICMP error of its own.
        #[test]
        fn later_fragments_keep_their_payload(
            src in v4(), dst in v4(), to in v4(), payload in proptest::collection::vec(any::<u8>(), 8..100),
        ) {
            let mut frag = udp4(src, dst, 1, 2, &payload);
            frag[6] = 0x00;
            frag[7] = 0x10; // offset 16 × 8 bytes
            fix_checksums(&mut frag);
            let body = frag[20..].to_vec();
            prop_assert_eq!(parse(&frag).unwrap().fragment, Fragment::Later);
            prop_assert!(icmp_unreachable(&frag, Unreach::Host).is_none());
            let mut a = frag.clone();
            rewrite(&mut a, Some((IpAddr::from(to), 9)), Some((IpAddr::from(to), 9)));
            prop_assert_eq!(&a[20..], &body[..]);
            prop_assert!(map_addrs(&mut frag, false, |_| Some(IpAddr::from(to))));
            prop_assert_eq!(&frag[20..], &body[..]);
            prop_assert_eq!(checksum(&frag[..20]), 0);
        }
        #[test]
        fn echo_reply_swaps_and_keeps_id_and_seq(
            src in v4(), dst in v4(), id in any::<u16>(), seq in any::<u16>(),
            payload in proptest::collection::vec(any::<u8>(), 0..100),
        ) {
            let req = icmp_echo(IpAddr::from(src), IpAddr::from(dst), true, id, seq, &payload);
            prop_assert!(checksums_ok(&req));
            let p = parse(&req).unwrap();
            prop_assert_eq!(p.icmp, Some(IcmpKind::Echo { request: true }));
            let rep = echo_reply(&req).unwrap();
            prop_assert_eq!(rep, icmp_echo(IpAddr::from(dst), IpAddr::from(src), false, id, seq, &payload));
            // A reply has no reply.
            prop_assert!(echo_reply(&echo_reply(&req).unwrap()).is_none());
        }

        #[test]
        fn ecn_set_and_read(src in v4(), dst in v4(), ecn in 0u8..4) {
            let mut p = udp4(src, dst, 1, 2, b"x");
            set_ecn(&mut p, ecn);
            prop_assert_eq!(ecn_of(&p), ecn);
            prop_assert_eq!(parse(&p).unwrap().ecn, ecn);
            prop_assert!(checksums_ok(&p));
        }

        /// Arbitrary bytes never panic any packet function.
        #[test]
        fn any_bytes(mut b in proptest::collection::vec(any::<u8>(), 0..120)) {
            let _ = parse(&b);
            let _ = src_dst(&b);
            let _ = echo_reply(&b);
            let _ = icmp_unreachable(&b, Unreach::Host);
            let _ = ecn_of(&b);
            fix_checksums(&mut b);
            set_ecn(&mut b, 3);
            rewrite(&mut b, Some(("10.0.0.1".parse().unwrap(), 1)), Some(("fd00::1".parse().unwrap(), 2)));
        }
    }
}
