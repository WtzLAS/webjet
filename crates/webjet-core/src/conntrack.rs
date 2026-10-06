//! Connection tracking (§14.4, §16.3): per-flow entries keyed by the
//! 5-tuple and the peer node, timeouts by state, per-peer quotas and a
//! global cap with the eviction order half-open TCP → one-way UDP → longest
//! idle.

use crate::crypto::Bytes32;
use crate::packet::{Flow, Fragment, IcmpKind, Parsed, tcpf};
use crate::policy::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// How long a fragmented datagram's later fragments follow its first one
/// (Linux's reassembly timeout).
const FRAG_TIMEOUT: Duration = Duration::from_secs(30);
/// Fragmented datagrams remembered at once.
const FRAG_CAP: usize = 16_384;

/// One fragmented datagram: the fragment id with the addresses, protocol and
/// peer it travels with (RFC 791, RFC 8200 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FragKey {
    peer: Bytes32,
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    id: u32,
}

impl FragKey {
    fn of(peer: &Bytes32, p: &Parsed) -> Self {
        FragKey {
            peer: *peer,
            proto: p.flow.proto,
            src: p.flow.src,
            dst: p.flow.dst,
            id: p.frag_id,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    TcpOpening,
    TcpEstablished,
    TcpClosing,
    UdpOneWay,
    UdpBoth,
    IcmpEcho,
    Other,
}

impl State {
    pub fn timeout(&self) -> Duration {
        match self {
            State::TcpOpening => Duration::from_secs(30),
            State::TcpEstablished => Duration::from_secs(3600),
            State::TcpClosing => Duration::from_secs(60),
            State::UdpOneWay => Duration::from_secs(30),
            State::UdpBoth => Duration::from_secs(120),
            State::IcmpEcho => Duration::from_secs(10),
            State::Other => Duration::from_secs(60),
        }
    }
    fn evict_rank(&self) -> u8 {
        match self {
            State::TcpOpening => 0,
            State::UdpOneWay => 1,
            _ => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    pub peer: Bytes32,
    /// The flow as seen in the direction it was started (initiator → responder).
    pub flow: Flow,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub state: State,
    pub last: Instant,
    /// We started it (outbound) or the peer did (inbound).
    pub outbound: bool,
    pub saw_reply: bool,
    /// The rule that admitted it, for re-evaluation on policy change.
    pub rule: Option<String>,
    /// A flow through this node as a gateway, counted against the SNAT
    /// limits (§11.9.4, §16.2).
    pub gateway: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Belongs to a tracked flow.
    Tracked,
    /// A new flow: needs a policy check, then `insert`.
    New,
    /// An ICMP error relating to a tracked flow.
    RelatedError,
    /// Not a valid flow start (e.g. a reply with no state, a non-SYN TCP).
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertError {
    PeerQuota,
    RateLimited,
    /// The source's gateway (SNAT) quota is used up.
    SnatPeerQuota,
    /// The gateway's SNAT table is full.
    SnatGlobal,
}

pub struct Conntrack {
    entries: HashMap<Key, Entry>,
    per_peer: HashMap<Bytes32, usize>,
    gateway_per_peer: HashMap<Bytes32, usize>,
    gateway_total: usize,
    new_rate: HashMap<Bytes32, (Instant, u32)>,
    /// Datagrams whose first fragment belongs to a tracked or admitted
    /// flow: their later fragments carry no ports, and follow it.
    frags: HashMap<FragKey, Instant>,
    pub per_peer_quota: usize,
    pub new_per_sec: u32,
    pub global_cap: usize,
    /// Gateway flows per source node (`snat_ports_per_source`).
    pub gateway_per_peer_quota: usize,
    /// Gateway flows in total (`snat_global`).
    pub gateway_cap: usize,
    pub evictions: u64,
}

impl Conntrack {
    pub fn new(per_peer_quota: usize, new_per_sec: u32, global_cap: usize) -> Self {
        Conntrack {
            entries: HashMap::new(),
            per_peer: HashMap::new(),
            gateway_per_peer: HashMap::new(),
            gateway_total: 0,
            new_rate: HashMap::new(),
            frags: HashMap::new(),
            per_peer_quota,
            new_per_sec,
            global_cap,
            gateway_per_peer_quota: usize::MAX,
            gateway_cap: usize::MAX,
            evictions: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn initial_state(p: &Parsed) -> Option<State> {
        if p.fragment == Fragment::Later {
            // No ports: it can't start (or name) a flow of its own.
            return None;
        }
        Some(match p.flow.proto {
            PROTO_TCP => {
                if p.tcp_flags & tcpf::SYN != 0 && p.tcp_flags & tcpf::ACK == 0 {
                    State::TcpOpening
                } else {
                    return None;
                }
            }
            PROTO_UDP => State::UdpOneWay,
            PROTO_ICMP | PROTO_ICMPV6 => match p.icmp {
                Some(IcmpKind::Echo { request: true }) => State::IcmpEcho,
                _ => return None,
            },
            _ => State::Other,
        })
    }

    /// Classify a packet travelling `outbound` (we send it) or inbound
    /// (from `peer`), updating state for tracked flows.
    pub fn classify(
        &mut self,
        peer: &Bytes32,
        p: &Parsed,
        outbound: bool,
        now: Instant,
    ) -> Verdict {
        if p.icmp == Some(IcmpKind::Error) {
            if let Some(inner) = p.inner {
                // The quoted packet travelled the opposite way.
                for f in [inner, inner.reverse()] {
                    if let Some(e) = self.entries.get(&Key {
                        peer: *peer,
                        flow: f,
                    }) && now.duration_since(e.last) < e.state.timeout()
                    {
                        return Verdict::RelatedError;
                    }
                }
            }
            return Verdict::Invalid;
        }
        if p.fragment == Fragment::Later {
            return self.classify_later(peer, p, now);
        }
        let fwd = Key {
            peer: *peer,
            flow: p.flow,
        };
        let rev = Key {
            peer: *peer,
            flow: p.flow.reverse(),
        };
        for (k, is_reply) in [(fwd, false), (rev, true)] {
            let Some(e) = self.entries.get_mut(&k) else {
                continue;
            };
            if now.duration_since(e.last) >= e.state.timeout() {
                continue;
            }
            // Same direction as the initiator, or the opposite one for replies.
            if (e.outbound == outbound) == is_reply {
                continue;
            }
            e.last = now;
            if is_reply {
                e.saw_reply = true;
            }
            e.state = match (e.state, p.flow.proto) {
                (_, PROTO_TCP) if p.tcp_flags & (tcpf::FIN | tcpf::RST) != 0 => State::TcpClosing,
                (State::TcpOpening, PROTO_TCP) if is_reply && p.tcp_flags & tcpf::ACK != 0 => {
                    State::TcpEstablished
                }
                (State::UdpOneWay, _) if is_reply => State::UdpBoth,
                (s, _) => s,
            };
            if p.fragment == Fragment::First {
                self.remember_fragments(peer, p, now);
            }
            return Verdict::Tracked;
        }
        match Self::initial_state(p) {
            Some(_) => Verdict::New,
            None => Verdict::Invalid,
        }
    }

    /// A later fragment follows its datagram's first fragment. Without one
    /// on record (it was refused, or the fragments arrived out of order) it
    /// is classified as before: a UDP or other fragment as new (the policy
    /// sees port 0), a TCP or ICMP one as invalid.
    fn classify_later(&mut self, peer: &Bytes32, p: &Parsed, now: Instant) -> Verdict {
        let k = FragKey::of(peer, p);
        if let Some(seen) = self.frags.get_mut(&k)
            && now.duration_since(*seen) < FRAG_TIMEOUT
        {
            *seen = now;
            return Verdict::Tracked;
        }
        match p.flow.proto {
            PROTO_TCP | PROTO_ICMP | PROTO_ICMPV6 => Verdict::Invalid,
            _ => Verdict::New,
        }
    }

    fn remember_fragments(&mut self, peer: &Bytes32, p: &Parsed, now: Instant) {
        if self.frags.len() >= FRAG_CAP {
            self.frags
                .retain(|_, t| now.duration_since(*t) < FRAG_TIMEOUT);
            if self.frags.len() >= FRAG_CAP {
                // Full of live datagrams: later fragments of this one get
                // the policy check instead.
                return;
            }
        }
        self.frags.insert(FragKey::of(peer, p), now);
    }

    /// Gateway flows being tracked.
    pub fn gateway_len(&self) -> usize {
        self.gateway_total
    }

    /// Track a new flow after the policy allowed it. `gateway`: the flow
    /// goes through this node to a LAN it serves (counts against SNAT limits).
    pub fn insert(
        &mut self,
        peer: &Bytes32,
        p: &Parsed,
        outbound: bool,
        rule: Option<String>,
        gateway: bool,
        now: Instant,
    ) -> Result<(), InsertError> {
        let Some(state) = Self::initial_state(p) else {
            return Ok(());
        };
        // New-flow rate per peer. Attempts count, refused ones too: each
        // refusal over the quota scans the table, so it must be bounded.
        let r = self.new_rate.entry(*peer).or_insert((now, 0));
        if now.duration_since(r.0) >= Duration::from_secs(1) {
            *r = (now, 0);
        }
        if r.1 >= self.new_per_sec {
            return Err(InsertError::RateLimited);
        }
        r.1 += 1;
        let cnt = self.per_peer.get(peer).copied().unwrap_or(0);
        if cnt >= self.per_peer_quota {
            self.expire_peer(peer, now);
            if self.per_peer.get(peer).copied().unwrap_or(0) >= self.per_peer_quota {
                return Err(InsertError::PeerQuota);
            }
        }
        if gateway {
            if self.gateway_per_peer.get(peer).copied().unwrap_or(0) >= self.gateway_per_peer_quota
            {
                self.expire_peer(peer, now);
                if self.gateway_per_peer.get(peer).copied().unwrap_or(0)
                    >= self.gateway_per_peer_quota
                {
                    return Err(InsertError::SnatPeerQuota);
                }
            }
            if self.gateway_total >= self.gateway_cap {
                self.expire(now);
                if self.gateway_total >= self.gateway_cap {
                    return Err(InsertError::SnatGlobal);
                }
            }
        }
        if self.entries.len() >= self.global_cap {
            self.expire(now);
            if self.entries.len() >= self.global_cap {
                self.evict_one(now);
            }
        }
        let k = Key {
            peer: *peer,
            flow: p.flow,
        };
        // A flow already tracked under this key (seen as new from the other
        // side, or expired but not yet swept) is replaced: take it out with
        // its counters first, or a replaced gateway flow would keep its
        // SNAT count forever.
        self.remove(&k);
        self.entries.insert(
            k,
            Entry {
                state,
                last: now,
                outbound,
                saw_reply: false,
                rule,
                gateway,
            },
        );
        *self.per_peer.entry(*peer).or_insert(0) += 1;
        if gateway {
            *self.gateway_per_peer.entry(*peer).or_insert(0) += 1;
            self.gateway_total += 1;
        }
        if p.fragment == Fragment::First {
            self.remember_fragments(peer, p, now);
        }
        Ok(())
    }

    fn remove(&mut self, k: &Key) {
        let Some(e) = self.entries.remove(k) else {
            return;
        };
        if let Some(c) = self.per_peer.get_mut(&k.peer) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.per_peer.remove(&k.peer);
            }
        }
        if e.gateway {
            self.gateway_total = self.gateway_total.saturating_sub(1);
            if let Some(c) = self.gateway_per_peer.get_mut(&k.peer) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    self.gateway_per_peer.remove(&k.peer);
                }
            }
        }
    }

    fn evict_one(&mut self, now: Instant) {
        let victim = self
            .entries
            .iter()
            .min_by_key(|(_, e)| {
                (
                    e.state.evict_rank(),
                    std::cmp::Reverse(now.duration_since(e.last)),
                )
            })
            .map(|(k, _)| *k);
        if let Some(k) = victim {
            self.remove(&k);
            self.evictions += 1;
        }
    }

    fn expire_peer(&mut self, peer: &Bytes32, now: Instant) {
        let dead: Vec<Key> = self
            .entries
            .iter()
            .filter(|(k, e)| k.peer == *peer && now.duration_since(e.last) >= e.state.timeout())
            .map(|(k, _)| *k)
            .collect();
        for k in dead {
            self.remove(&k);
        }
    }

    /// Drop expired entries.
    pub fn expire(&mut self, now: Instant) {
        let dead: Vec<Key> = self
            .entries
            .iter()
            .filter(|(_, e)| now.duration_since(e.last) >= e.state.timeout())
            .map(|(k, _)| *k)
            .collect();
        for k in dead {
            self.remove(&k);
        }
        self.new_rate
            .retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(2));
        self.frags
            .retain(|_, t| now.duration_since(*t) < FRAG_TIMEOUT);
    }

    /// Re-evaluate every tracked flow after a policy change (§14.4); `keep`
    /// returns whether the flow is still allowed.
    pub fn reevaluate(&mut self, mut keep: impl FnMut(&Key, &Entry) -> bool) -> usize {
        let dead: Vec<Key> = self
            .entries
            .iter()
            .filter(|(k, e)| !keep(k, e))
            .map(|(k, _)| *k)
            .collect();
        let n = dead.len();
        for k in dead {
            self.remove(&k);
        }
        if n > 0 {
            // Datagrams in flight may belong to a flow just refused.
            self.frags.clear();
        }
        n
    }

    /// Drop every flow with a peer (session destroyed).
    pub fn drop_peer(&mut self, peer: &Bytes32) {
        let dead: Vec<Key> = self
            .entries
            .keys()
            .filter(|k| k.peer == *peer)
            .copied()
            .collect();
        for k in dead {
            self.remove(&k);
        }
        self.frags.retain(|k, _| k.peer != *peer);
    }

    pub fn get(&self, k: &Key) -> Option<&Entry> {
        self.entries.get(k)
    }

    pub fn entries(&self) -> impl Iterator<Item = (&Key, &Entry)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{parse, tests::tcp4, tests::udp4};

    #[test]
    fn tcp_lifecycle() {
        let mut ct = Conntrack::new(10, 100, 100);
        let peer = [1; 32];
        let now = Instant::now();
        let syn = parse(&tcp4([10, 7, 0, 1], [10, 7, 0, 2], 1000, 22, tcpf::SYN)).unwrap();
        assert_eq!(ct.classify(&peer, &syn, false, now), Verdict::New);
        ct.insert(&peer, &syn, false, None, false, now).unwrap();
        let synack = parse(&tcp4(
            [10, 7, 0, 2],
            [10, 7, 0, 1],
            22,
            1000,
            tcpf::SYN | tcpf::ACK,
        ))
        .unwrap();
        assert_eq!(ct.classify(&peer, &synack, true, now), Verdict::Tracked);
        // A bare ACK that starts nothing is invalid.
        let ack = parse(&tcp4([10, 7, 0, 3], [10, 7, 0, 2], 5, 22, tcpf::ACK)).unwrap();
        assert_eq!(ct.classify(&peer, &ack, false, now), Verdict::Invalid);
        // Expiry.
        assert_eq!(
            ct.classify(&peer, &synack, true, now + Duration::from_secs(4000)),
            Verdict::Invalid
        );
    }

    /// IPv4 fragments of one UDP datagram: the first (with ports) and a
    /// later one (offset 8 × 8 bytes), both with IP id `id`.
    fn fragments(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, id: u16) -> (Parsed, Parsed) {
        let mut first = udp4(src, dst, sport, dport, &[7; 56]);
        first[4..6].copy_from_slice(&id.to_be_bytes());
        first[6] = 0x20; // more fragments, offset 0
        let mut later = udp4(src, dst, 1, 2, &[7; 56]);
        later[4..6].copy_from_slice(&id.to_be_bytes());
        later[6] = 0;
        later[7] = 8;
        let (f, l) = (parse(&first).unwrap(), parse(&later).unwrap());
        assert_eq!((f.fragment, l.fragment), (Fragment::First, Fragment::Later));
        assert_eq!((l.flow.sport, l.flow.dport), (0, 0));
        (f, l)
    }

    #[test]
    fn later_fragments_follow_their_first_fragment() {
        let mut ct = Conntrack::new(10, 100, 100);
        let (a, b) = ([1; 32], [2; 32]);
        let now = Instant::now();
        // A new flow whose first datagram is fragmented (EDNS, say): the
        // first fragment is admitted on its ports, the rest follow it
        // without a policy check on "port 0" or an entry of their own.
        let (first, later) = fragments([10, 7, 0, 1], [10, 7, 0, 2], 5353, 53, 77);
        assert_eq!(ct.classify(&a, &first, true, now), Verdict::New);
        ct.insert(&a, &first, true, None, false, now).unwrap();
        assert_eq!(ct.classify(&a, &later, true, now), Verdict::Tracked);
        assert_eq!(ct.len(), 1);
        // The reply, also fragmented, on the tracked flow.
        let (rfirst, rlater) = fragments([10, 7, 0, 2], [10, 7, 0, 1], 53, 5353, 9);
        assert_eq!(ct.classify(&a, &rfirst, false, now), Verdict::Tracked);
        assert_eq!(ct.classify(&a, &rlater, false, now), Verdict::Tracked);
        // Another datagram id, another peer, or too late: no match. A UDP
        // fragment then gets the policy check as before; TCP stays invalid.
        let (_, other) = fragments([10, 7, 0, 1], [10, 7, 0, 2], 5353, 53, 78);
        assert_eq!(ct.classify(&a, &other, true, now), Verdict::New);
        assert_eq!(ct.classify(&b, &later, true, now), Verdict::New);
        let late = now + FRAG_TIMEOUT + Duration::from_secs(1);
        assert_eq!(ct.classify(&a, &later, true, late), Verdict::New);
        let mut tcp_later = tcp4([10, 7, 0, 1], [10, 7, 0, 2], 1, 2, tcpf::ACK);
        tcp_later[7] = 8;
        let tcp_later = parse(&tcp_later).unwrap();
        assert_eq!(ct.classify(&a, &tcp_later, true, now), Verdict::Invalid);
        // A later fragment never becomes a flow of its own.
        ct.insert(&a, &other, true, None, false, now).unwrap();
        assert_eq!(ct.len(), 1);
        // Gone with the peer, and with flows a policy change refused.
        ct.drop_peer(&a);
        assert_eq!(ct.classify(&a, &rlater, false, now), Verdict::New);
        ct.insert(&b, &first, true, None, false, now).unwrap();
        assert_eq!(ct.classify(&b, &later, true, now), Verdict::Tracked);
        assert_eq!(ct.reevaluate(|_, _| false), 1);
        assert_eq!(ct.classify(&b, &later, true, now), Verdict::New);
        ct.insert(&b, &first, true, None, false, now).unwrap();
        ct.expire(late);
        assert!(ct.frags.is_empty());
    }

    #[test]
    fn quotas_and_eviction_order() {
        let mut ct = Conntrack::new(3, 100, 4);
        let now = Instant::now();
        let a = [1; 32];
        for p in 0..3u16 {
            let u = parse(&udp4([10, 7, 0, 1], [10, 7, 0, 2], 1000 + p, 53, b"")).unwrap();
            ct.insert(&a, &u, false, None, false, now).unwrap();
        }
        let u = parse(&udp4([10, 7, 0, 1], [10, 7, 0, 2], 2000, 53, b"")).unwrap();
        assert_eq!(
            ct.insert(&a, &u, false, None, false, now),
            Err(InsertError::PeerQuota)
        );
        // Another peer: an established UDP flow plus the global cap.
        let b = [2; 32];
        let u2 = parse(&udp4([10, 7, 0, 1], [10, 7, 0, 3], 3000, 53, b"")).unwrap();
        ct.insert(&b, &u2, false, None, false, now).unwrap();
        let rep = parse(&udp4([10, 7, 0, 3], [10, 7, 0, 1], 53, 3000, b"")).unwrap();
        assert_eq!(ct.classify(&b, &rep, true, now), Verdict::Tracked);
        let u3 = parse(&udp4([10, 7, 0, 1], [10, 7, 0, 3], 3001, 53, b"")).unwrap();
        ct.insert(&b, &u3, false, None, false, now).unwrap();
        // The established two-way flow survived; a one-way one was evicted.
        assert_eq!(ct.classify(&b, &rep, true, now), Verdict::Tracked);
        assert_eq!(ct.len(), 4);
        assert_eq!(ct.evictions, 1);
    }

    #[test]
    fn gateway_flows_have_their_own_quotas() {
        let mut ct = Conntrack::new(100, 100, 100);
        ct.gateway_per_peer_quota = 2;
        ct.gateway_cap = 3;
        let now = Instant::now();
        let (a, b) = ([1; 32], [2; 32]);
        let flow =
            |sport: u16| parse(&udp4([10, 7, 0, 1], [192, 168, 1, 5], sport, 53, b"")).unwrap();
        ct.insert(&a, &flow(1), false, None, true, now).unwrap();
        ct.insert(&a, &flow(2), false, None, true, now).unwrap();
        assert_eq!(
            ct.insert(&a, &flow(3), false, None, true, now),
            Err(InsertError::SnatPeerQuota)
        );
        // Flows to the node itself don't count against the gateway quota.
        ct.insert(&a, &flow(4), false, None, false, now).unwrap();
        ct.insert(&b, &flow(5), false, None, true, now).unwrap();
        assert_eq!(
            ct.insert(&b, &flow(6), false, None, true, now),
            Err(InsertError::SnatGlobal)
        );
        assert_eq!(ct.gateway_len(), 3);
        // Dropping a peer frees its gateway flows.
        ct.drop_peer(&a);
        assert_eq!(ct.gateway_len(), 1);
        ct.insert(&b, &flow(7), false, None, true, now).unwrap();
    }
}

#[cfg(test)]
mod regressions {
    use super::*;
    use crate::packet::parse;
    use crate::testutil::packets::udp4;

    /// Found by `prop::counters_and_limits_hold`: a gateway flow replaced by
    /// the same 5-tuple from the other direction kept its SNAT count, so the
    /// gateway's quota leaked one slot each time.
    #[test]
    fn replacing_a_flow_keeps_the_counters_right() {
        let mut ct = Conntrack::new(10, 100, 100);
        let peer = [2; 32];
        let now = Instant::now();
        let p = parse(&udp4([10, 7, 0, 1], [10, 7, 0, 2], 1004, 80, b"x")).unwrap();
        ct.insert(&peer, &p, true, None, true, now).unwrap();
        assert_eq!((ct.len(), ct.gateway_len()), (1, 1));
        // The same tuple, inbound and not through the gateway.
        assert_eq!(ct.classify(&peer, &p, false, now), Verdict::New);
        ct.insert(&peer, &p, false, None, false, now).unwrap();
        assert_eq!((ct.len(), ct.gateway_len()), (1, 0));
        assert_eq!(ct.per_peer.get(&peer), Some(&1));
        assert!(ct.gateway_per_peer.is_empty());
        ct.drop_peer(&peer);
        assert!(ct.is_empty() && ct.per_peer.is_empty());
    }
}

#[cfg(test)]
mod prop {
    use super::*;
    use crate::packet::parse;
    use crate::testutil::packets::{tcp4, udp4};
    use proptest::prelude::*;

    #[derive(Clone, Debug)]
    enum Op {
        /// A new flow from peer `p` (TCP SYN or UDP), port `port`.
        Insert {
            p: u8,
            port: u16,
            tcp: bool,
            outbound: bool,
            gateway: bool,
        },
        /// The reply to that flow.
        Reply {
            p: u8,
            port: u16,
            tcp: bool,
        },
        /// Time passes, in seconds.
        Wait(u64),
        Expire,
        DropPeer(u8),
        /// Drop flows on odd ports.
        Reevaluate,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            6 => (0u8..3, 0u16..8, any::<bool>(), any::<bool>(), any::<bool>()).prop_map(
                |(p, port, tcp, outbound, gateway)| Op::Insert { p, port, tcp, outbound, gateway }
            ),
            3 => (0u8..3, 0u16..8, any::<bool>()).prop_map(|(p, port, tcp)| Op::Reply { p, port, tcp }),
            2 => prop_oneof![Just(1u64), Just(20), Just(45), Just(200)].prop_map(Op::Wait),
            1 => Just(Op::Expire),
            1 => (0u8..3).prop_map(Op::DropPeer),
            1 => Just(Op::Reevaluate),
        ]
    }

    fn packet(port: u16, tcp: bool, reply: bool) -> Vec<u8> {
        let (a, b) = ([10, 7, 0, 1], [10, 7, 0, 2]);
        let (src, dst, sp, dp) = if reply {
            (b, a, 80, 1000 + port)
        } else {
            (a, b, 1000 + port, 80)
        };
        if tcp {
            tcp4(
                src,
                dst,
                sp,
                dp,
                if reply {
                    tcpf::SYN | tcpf::ACK
                } else {
                    tcpf::SYN
                },
            )
        } else {
            udp4(src, dst, sp, dp, b"x")
        }
    }

    /// The bookkeeping matches the entries, and no limit is exceeded.
    fn check(ct: &Conntrack) -> Result<(), TestCaseError> {
        let mut per: HashMap<Bytes32, usize> = HashMap::new();
        let mut gw_per: HashMap<Bytes32, usize> = HashMap::new();
        for (k, e) in &ct.entries {
            *per.entry(k.peer).or_default() += 1;
            if e.gateway {
                *gw_per.entry(k.peer).or_default() += 1;
            }
        }
        prop_assert_eq!(&ct.per_peer, &per);
        prop_assert_eq!(&ct.gateway_per_peer, &gw_per);
        prop_assert_eq!(ct.gateway_total, gw_per.values().sum::<usize>());
        prop_assert!(ct.entries.len() <= ct.global_cap);
        prop_assert!(per.values().all(|c| *c <= ct.per_peer_quota));
        prop_assert!(gw_per.values().all(|c| *c <= ct.gateway_per_peer_quota));
        prop_assert!(ct.gateway_total <= ct.gateway_cap);
        Ok(())
    }

    proptest! {
        #[test]
        fn counters_and_limits_hold(ops in proptest::collection::vec(op(), 1..120)) {
            let mut ct = Conntrack::new(5, 1000, 8);
            ct.gateway_per_peer_quota = 2;
            ct.gateway_cap = 4;
            let start = Instant::now();
            let mut now = start;
            for o in ops {
                match o {
                    Op::Insert { p, port, tcp, outbound, gateway } => {
                        let pkt = packet(port, tcp, false);
                        let parsed = parse(&pkt).unwrap();
                        let peer = [p; 32];
                        let v = ct.classify(&peer, &parsed, outbound, now);
                        if v == Verdict::New {
                            let key = Key { peer, flow: parsed.flow };
                            let before = ct.get(&key).is_some();
                            let r = ct.insert(&peer, &parsed, outbound, None, gateway, now);
                            if r.is_ok() {
                                // Once inserted, the next packet of the flow is tracked.
                                let after = ct.get(&key).is_some();
                                prop_assert!(before || after);
                                prop_assert_eq!(ct.classify(&peer, &parsed, outbound, now), Verdict::Tracked);
                            }
                        }
                    }
                    Op::Reply { p, port, tcp } => {
                        let pkt = packet(port, tcp, true);
                        let parsed = parse(&pkt).unwrap();
                        let peer = [p; 32];
                        let started = parse(&packet(port, tcp, false)).unwrap().flow;
                        let live = ct
                            .get(&Key { peer, flow: started })
                            .map(|e| (e.outbound, now.duration_since(e.last) < e.state.timeout()));
                        // A reply comes the other way: inbound for our flows.
                        for outbound in [false, true] {
                            let v = ct.classify(&peer, &parsed, outbound, now);
                            if live == Some((!outbound, true)) {
                                prop_assert_eq!(v, Verdict::Tracked);
                                let e = ct.get(&Key { peer, flow: started }).unwrap();
                                prop_assert!(e.saw_reply);
                                if tcp {
                                    prop_assert_eq!(e.state, State::TcpEstablished);
                                } else {
                                    prop_assert_eq!(e.state, State::UdpBoth);
                                }
                                break;
                            }
                        }
                    }
                    Op::Wait(s) => now += Duration::from_secs(s),
                    Op::Expire => {
                        ct.expire(now);
                        prop_assert!(ct.entries.values().all(|e| now.duration_since(e.last) < e.state.timeout()));
                    }
                    Op::DropPeer(p) => {
                        ct.drop_peer(&[p; 32]);
                        prop_assert!(ct.entries.keys().all(|k| k.peer != [p; 32]));
                    }
                    Op::Reevaluate => {
                        let odd = ct.entries.keys().filter(|k| k.flow.sport % 2 == 1).count();
                        prop_assert_eq!(ct.reevaluate(|k, _| k.flow.sport % 2 == 0), odd);
                    }
                }
                check(&ct)?;
            }
        }

        /// The cap evicts half-open TCP first, then one-way UDP, then the
        /// longest idle.
        #[test]
        fn eviction_order(states in proptest::collection::vec(0u8..3, 4..12)) {
            let cap = states.len();
            let mut ct = Conntrack::new(usize::MAX, u32::MAX, cap);
            let mut now = Instant::now();
            let peer = [1; 32];
            for (i, s) in states.iter().enumerate() {
                let port = i as u16;
                let tcp = *s != 1;
                let pkt = packet(port, tcp, false);
                ct.insert(&peer, &parse(&pkt).unwrap(), true, None, false, now).unwrap();
                if *s == 2 {
                    // Answered: established TCP.
                    let r = packet(port, true, true);
                    prop_assert_eq!(ct.classify(&peer, &parse(&r).unwrap(), false, now), Verdict::Tracked);
                }
                now += Duration::from_millis(10);
            }
            let rank = |e: &Entry| e.state.evict_rank();
            let victim_rank = ct.entries.values().map(rank).min().unwrap();
            let oldest = ct
                .entries
                .iter()
                .filter(|(_, e)| rank(e) == victim_rank)
                .min_by_key(|(_, e)| e.last)
                .map(|(k, _)| *k)
                .unwrap();
            let extra = packet(999, false, false);
            ct.insert(&[2; 32], &parse(&extra).unwrap(), true, None, false, now).unwrap();
            prop_assert_eq!(ct.len(), cap);
            prop_assert!(ct.get(&oldest).is_none(), "evicted the wrong flow");
            prop_assert_eq!(ct.evictions, 1);
        }
    }
}
