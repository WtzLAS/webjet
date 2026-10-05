//! Connection tracking (§14.4, §16.3): per-flow entries keyed by the
//! 5-tuple and the peer node, timeouts by state, per-peer quotas and a
//! global cap with the eviction order half-open TCP → one-way UDP → longest
//! idle.

use crate::crypto::Bytes32;
use crate::packet::{Flow, IcmpKind, Parsed, tcpf};
use crate::policy::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use std::collections::HashMap;
use std::time::{Duration, Instant};

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
            return Verdict::Tracked;
        }
        match Self::initial_state(p) {
            Some(_) => Verdict::New,
            None => Verdict::Invalid,
        }
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
        // New-flow rate per peer.
        let r = self.new_rate.entry(*peer).or_insert((now, 0));
        if now.duration_since(r.0) >= Duration::from_secs(1) {
            *r = (now, 0);
        }
        if r.1 >= self.new_per_sec {
            return Err(InsertError::RateLimited);
        }
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
        if let Some(r) = self.new_rate.get_mut(peer) {
            r.1 += 1;
        }
        let k = Key {
            peer: *peer,
            flow: p.flow,
        };
        if self
            .entries
            .insert(
                k,
                Entry {
                    state,
                    last: now,
                    outbound,
                    saw_reply: false,
                    rule,
                    gateway,
                },
            )
            .is_none()
        {
            *self.per_peer.entry(*peer).or_insert(0) += 1;
            if gateway {
                *self.gateway_per_peer.entry(*peer).or_insert(0) += 1;
                self.gateway_total += 1;
            }
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
