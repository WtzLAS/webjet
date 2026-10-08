//! Broadcast and multicast over the overlay (§9.5.1), the parts without I/O.
//!
//! The overlay is one link. A UDP datagram the host sends to a broadcast or
//! multicast address is fanned out by the sending node, once, as unicast
//! copies inside the end-to-end sessions of the peers that may receive it;
//! a received copy is only written to the local tun interface and never
//! sent on. Nothing is re-forwarded, so there is no loop to amplify.
//!
//! Multicast goes only where it is wanted: each receiver reports the groups
//! its host has joined on the tun interface (read from the OS, the way an
//! IGMP/MLD snooping switch learns them) to the senders it hears from, and
//! senders skip peers whose report leaves a group out. Broadcasts go to
//! every peer. A per-node budget, counting every copy, caps what one node
//! can send; receivers cap what they take from each sender.

use crate::crypto::Bytes32;
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// EndpointRecord feature: the node takes MCAST and GROUPS frames.
pub const FEATURE: &str = "multicast";
/// How long a sender trusts a receiver's report; past it, it sends again
/// and the receiver reports anew.
pub const REPORT_TTL: Duration = Duration::from_secs(180);
/// A receiver reports again to a sender it keeps hearing from this often,
/// so the sender's copy never lapses while traffic flows.
pub const REPORT_EVERY: Duration = Duration::from_secs(60);
/// A datagram the host sends within this time of one just delivered to
/// it, with the same destination and payload, is an echo and not sent.
pub const ECHO_WINDOW: Duration = Duration::from_secs(1);
/// Most groups a report carries; a host with more is reported as "any".
pub const MAX_GROUPS: usize = 256;
/// A datagram the host sends both into the tun interface and out another
/// interface within this time goes out once (§9.5.2).
pub const DUPLICATE_WINDOW: Duration = Duration::from_millis(500);
const ECHO_CAP: usize = 4096;
const SENDER_CAP: usize = 4096;

/// What a datagram to some address is on the overlay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// For every host: the limited broadcast, the overlay pool's broadcast
    /// address, all-hosts 224.0.0.1 and ff02::1.
    Broadcast,
    /// For the hosts that joined this group.
    Group(IpAddr),
}

/// `dst` as broadcast or multicast, or `None` when the overlay doesn't
/// carry it that way: unicast, unspecified, and IPv6 interface-local or
/// reserved scopes (which never leave a host).
pub fn kind(dst: &IpAddr, pools: &[IpNet]) -> Option<Kind> {
    match dst {
        IpAddr::V4(a) => {
            if a.is_broadcast()
                || *a == Ipv4Addr::new(224, 0, 0, 1)
                || is_pool_broadcast(dst, pools)
            {
                Some(Kind::Broadcast)
            } else if a.is_multicast() {
                Some(Kind::Group(*dst))
            } else {
                None
            }
        }
        IpAddr::V6(a) => {
            if !a.is_multicast() {
                return None;
            }
            match a.octets()[1] & 0x0f {
                0 | 1 => None,
                _ if a.segments() == [0xff02, 0, 0, 0, 0, 0, 0, 1] => Some(Kind::Broadcast),
                _ => Some(Kind::Group(*dst)),
            }
        }
    }
}

/// The directed broadcast address of an IPv4 overlay pool (the tun
/// interface's subnet), e.g. 10.7.255.255 for 10.7.0.0/16. Receivers
/// deliver it as the limited broadcast, which every OS accepts.
pub fn is_pool_broadcast(dst: &IpAddr, pools: &[IpNet]) -> bool {
    pools.iter().any(|p| match p {
        IpNet::V4(n) => n.prefix_len() <= 30 && IpAddr::V4(n.broadcast()) == *dst,
        IpNet::V6(_) => false,
    })
}

/// A fingerprint of a datagram for echo detection: its kind and UDP
/// payload (the addresses differ between the copy delivered and its echo).
pub fn digest(kind: Kind, payload: &[u8]) -> u64 {
    let mut h = std::hash::DefaultHasher::new();
    kind.hash(&mut h);
    payload.hash(&mut h);
    h.finish()
}

// ---------------------------------------------------------------- capture

/// UDP ports capture never takes, whatever the configuration says: their
/// answers carry LAN addresses peers can't reach (mDNS, LLMNR, SSDP,
/// NetBIOS, WS-Discovery) or configure the LAN itself (DHCP).
pub const NEVER_CAPTURED: [u16; 8] = [67, 68, 137, 138, 1900, 3702, 5353, 5355];

/// The UDP ports to capture (§9.5.2), from `[multicast] capture` specs:
/// `udp:19132`, `udp:4000-4010`, `udp` (every port but [`NEVER_CAPTURED`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapturePorts(Vec<(u16, u16)>);

impl CapturePorts {
    pub fn parse(specs: &[String]) -> anyhow::Result<CapturePorts> {
        let mut set = crate::policy::PortSet::default();
        for s in specs {
            let p = crate::policy::PortSet::parse_spec(s)
                .map_err(|e| anyhow::anyhow!("multicast.capture {s:?}: {e}"))?;
            if !p.tcp.is_empty() || p.icmp || p.other || p.udp.is_empty() {
                anyhow::bail!("multicast.capture {s:?}: only UDP ports (udp:19132, udp:4000-4010)");
            }
            if let [(lo, hi)] = p.udp[..]
                && lo == hi
                && NEVER_CAPTURED.contains(&lo)
            {
                anyhow::bail!(
                    "multicast.capture {s:?}: port {lo} is never captured (its answers carry LAN addresses)"
                );
            }
            set.union(&p);
        }
        Ok(CapturePorts(set.udp))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The port ranges, merged and sorted.
    pub fn ranges(&self) -> &[(u16, u16)] {
        &self.0
    }

    pub fn contains(&self, port: u16) -> bool {
        !NEVER_CAPTURED.contains(&port) && self.0.iter().any(|&(lo, hi)| lo <= port && port <= hi)
    }
}

/// A datagram the host sent out another interface, as the overlay carries
/// it: `None` unless it is UDP to a captured port, unfragmented, sent from
/// one of `lan_addrs` (this host's own addresses on other interfaces, never
/// the overlay's), to the limited broadcast, a LAN's directed broadcast
/// (`lan_nets`) or an IPv4 multicast group. The source becomes `overlay`,
/// so replies come back through the tun interface, and a directed LAN
/// broadcast becomes the limited broadcast, which receivers deliver.
pub fn captured(
    p: &[u8],
    ports: &CapturePorts,
    lan_addrs: &[IpAddr],
    lan_nets: &[IpNet],
    overlay: IpAddr,
) -> Option<Vec<u8>> {
    let parsed = crate::packet::parse(p)?;
    let f = &parsed.flow;
    if f.proto != crate::policy::PROTO_UDP
        || parsed.fragment != crate::packet::Fragment::Whole
        || !overlay.is_ipv4()
        || !lan_addrs.contains(&f.src)
        || !ports.contains(f.dport)
        || NEVER_CAPTURED.contains(&f.sport)
    {
        return None;
    }
    let IpAddr::V4(dst) = f.dst else { return None };
    let directed = !dst.is_broadcast()
        && lan_nets.iter().any(|n| match n {
            IpNet::V4(n) => {
                n.prefix_len() <= 30 && n.broadcast() == dst && IpNet::V4(*n).contains(&f.src)
            }
            IpNet::V6(_) => false,
        });
    if !(dst.is_broadcast() || dst.is_multicast() || directed) {
        return None;
    }
    let mut out = p.to_vec();
    let bcast = IpAddr::V4(Ipv4Addr::BROADCAST);
    crate::packet::rewrite(
        &mut out,
        Some((overlay, f.sport)),
        directed.then_some((bcast, f.dport)),
    );
    Some(out)
}

// ---------------------------------------------------------------- reports

/// What a receiver takes, as it tells its senders (frame GROUPS).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Report {
    /// Membership unknown (no tun, or the OS can't tell): send everything.
    Any,
    /// Nothing: multicast is off on this node.
    Nothing,
    /// Broadcasts, and multicast to these groups.
    Groups(Vec<IpAddr>),
}

const R_ANY: u8 = 1;
const R_NOTHING: u8 = 2;

/// `version(1)=1 || flags(1) || count(2) || count × (family(1)=4|6 || addr)`.
pub fn encode_report(r: &Report) -> Vec<u8> {
    let (flags, groups): (u8, &[IpAddr]) = match r {
        Report::Any => (R_ANY, &[]),
        Report::Nothing => (R_NOTHING, &[]),
        Report::Groups(g) => (0, &g[..g.len().min(MAX_GROUPS)]),
    };
    let mut out = vec![1, flags];
    out.extend_from_slice(&(groups.len() as u16).to_be_bytes());
    for g in groups {
        match g {
            IpAddr::V4(a) => {
                out.push(4);
                out.extend_from_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                out.push(6);
                out.extend_from_slice(&a.octets());
            }
        }
    }
    out
}

pub fn decode_report(b: &[u8]) -> Option<Report> {
    let (&[1, flags, c0, c1], mut rest) = b.split_first_chunk::<4>()? else {
        return None;
    };
    let count = usize::from(u16::from_be_bytes([c0, c1]));
    if count > MAX_GROUPS {
        return None;
    }
    let mut groups = Vec::with_capacity(count);
    for _ in 0..count {
        let (&fam, r) = rest.split_first()?;
        let a = match fam {
            4 => {
                let (a, r) = r.split_first_chunk::<4>()?;
                rest = r;
                IpAddr::from(*a)
            }
            6 => {
                let (a, r) = r.split_first_chunk::<16>()?;
                rest = r;
                IpAddr::from(*a)
            }
            _ => return None,
        };
        if !a.is_multicast() {
            return None;
        }
        groups.push(a);
    }
    if !rest.is_empty() {
        return None;
    }
    Some(match flags {
        R_ANY => Report::Any,
        R_NOTHING => Report::Nothing,
        0 => Report::Groups(groups),
        _ => return None,
    })
}

// ---------------------------------------------------------------- budget

/// A token bucket over packets and bytes at once, holding one second's
/// worth. Time is passed in, for tests.
#[derive(Clone, Debug)]
pub struct Budget {
    packets: f64,
    bytes: f64,
    pps: f64,
    bps: f64,
    last: Instant,
}

impl Budget {
    pub fn new(pps: u64, bps: u64, now: Instant) -> Budget {
        Budget {
            packets: pps as f64,
            bytes: bps as f64,
            pps: pps as f64,
            bps: bps as f64,
            last: now,
        }
    }

    /// Follow changed limits, keeping what is left (capped to the new size).
    pub fn set(&mut self, pps: u64, bps: u64) {
        self.pps = pps as f64;
        self.bps = bps as f64;
        self.packets = self.packets.min(self.pps);
        self.bytes = self.bytes.min(self.bps);
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = self.last.max(now);
        self.packets = (self.packets + dt * self.pps).min(self.pps);
        self.bytes = (self.bytes + dt * self.bps).min(self.bps);
    }

    /// Is there room for one more packet at all?
    pub fn any_left(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.packets >= 1.0
    }

    /// Spend one packet of `len` bytes, if both are there.
    pub fn take(&mut self, len: usize, now: Instant) -> bool {
        self.refill(now);
        if self.packets >= 1.0 && self.bytes >= len as f64 {
            self.packets -= 1.0;
            self.bytes -= len as f64;
            true
        } else {
            false
        }
    }

    fn full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.packets >= self.pps && self.bytes >= self.bps
    }
}

// ---------------------------------------------------------------- state

#[derive(Clone, Debug)]
struct PeerReport {
    report: Report,
    until: Instant,
}

/// One node's broadcast and multicast state, both directions.
#[derive(Debug)]
pub struct State {
    // Sending.
    /// What each receiver said it takes, until it lapses.
    reports: HashMap<Bytes32, PeerReport>,
    budget: Budget,
    /// Where the next fan-out starts, so a budget too small for all peers
    /// still reaches each of them in turn.
    pub rotate: usize,
    /// When the budget last refused a copy (for the alarm).
    pub limited_at: Option<Instant>,
    /// Whether the over-budget alarm is raised.
    pub alarmed: bool,
    /// Whether the EndpointRecord last published said `multicast`.
    pub advertised: Option<bool>,
    // Receiving.
    /// The groups the host joined on the tun interface; `None` = unknown.
    local: Option<HashSet<IpAddr>>,
    local_gen: u64,
    /// Senders we reported to: when, and the membership generation sent.
    reported: HashMap<Bytes32, (Instant, u64)>,
    per_sender: HashMap<Bytes32, Budget>,
    /// Recently delivered datagrams (`digest`), for echo detection.
    delivered: HashMap<u64, Instant>,
    /// Recently sent datagrams (`digest`) and the path they took, so one
    /// the host sends both into the tun interface and out a LAN interface
    /// (apps that send on every interface) goes out once.
    sent: HashMap<u64, (Instant, Origin)>,
}

/// Where a datagram the overlay carries came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The host sent it into the tun interface.
    Tun,
    /// The host sent it out another interface; capture took it (§9.5.2).
    Captured,
}

impl State {
    pub fn new(pps: u64, bps: u64, now: Instant) -> State {
        State {
            reports: HashMap::new(),
            budget: Budget::new(pps, bps, now),
            rotate: 0,
            limited_at: None,
            alarmed: false,
            advertised: None,
            local: None,
            local_gen: 0,
            reported: HashMap::new(),
            per_sender: HashMap::new(),
            delivered: HashMap::new(),
            sent: HashMap::new(),
        }
    }

    pub fn set_limits(&mut self, pps: u64, bps: u64) {
        self.budget.set(pps, bps);
        for b in self.per_sender.values_mut() {
            b.set(pps, bps);
        }
    }

    // ------------------------------------------------------------ sending

    /// Does `peer` take a datagram of this kind, as far as we know? Peers
    /// without a current report get it (and answer with one).
    pub fn wants(&self, peer: &Bytes32, kind: Kind, now: Instant) -> bool {
        match self.reports.get(peer) {
            Some(r) if r.until > now => match (&r.report, kind) {
                (Report::Nothing, _) => false,
                (Report::Any, _) | (_, Kind::Broadcast) => true,
                (Report::Groups(g), Kind::Group(a)) => g.contains(&a),
            },
            _ => true,
        }
    }

    pub fn on_report(&mut self, peer: &Bytes32, report: Report, now: Instant) {
        self.reports.insert(
            *peer,
            PeerReport {
                report,
                until: now + REPORT_TTL,
            },
        );
    }

    pub fn budget_left(&mut self, now: Instant) -> bool {
        self.budget.any_left(now)
    }

    /// Spend the budget on one copy of `len` bytes.
    pub fn spend(&mut self, len: usize, now: Instant) -> bool {
        let ok = self.budget.take(len, now);
        if !ok {
            self.limited_at = Some(now);
        }
        ok
    }

    /// Was this datagram just delivered to the host? Then the host is
    /// sending it back (a reflector, a relaying app): not again.
    pub fn is_echo(&self, digest: u64, now: Instant) -> bool {
        self.delivered
            .get(&digest)
            .is_some_and(|t| now.saturating_duration_since(*t) < ECHO_WINDOW)
    }

    // ------------------------------------------------------------ receiving

    /// The host's memberships changed (or became known/unknown). Returns
    /// whether they differ from before.
    pub fn set_local(&mut self, groups: Option<HashSet<IpAddr>>) -> bool {
        if self.local == groups {
            return false;
        }
        self.local = groups;
        self.local_gen += 1;
        true
    }

    /// What we take changed for another reason (turned on or off): every
    /// sender holding our report gets a new one (`stale_reports`).
    pub fn report_changed(&mut self) {
        self.local_gen += 1;
    }

    /// Does the host take a datagram of this kind?
    pub fn member(&self, kind: Kind) -> bool {
        match (kind, &self.local) {
            (Kind::Broadcast, _) | (_, None) => true,
            (Kind::Group(a), Some(g)) => g.contains(&a),
        }
    }

    /// Our report, as of now. `off`: multicast is off on this node.
    pub fn report(&self, off: bool) -> Report {
        match &self.local {
            _ if off => Report::Nothing,
            None => Report::Any,
            Some(g) if g.len() > MAX_GROUPS => Report::Any,
            Some(g) => {
                let mut v: Vec<IpAddr> = g.iter().copied().collect();
                v.sort();
                Report::Groups(v)
            }
        }
    }

    /// We heard from `peer`: should it get our report now? It should when
    /// it never had one, its copy is about to lapse, or ours changed.
    pub fn report_due(&mut self, peer: &Bytes32, now: Instant) -> bool {
        let due = self.reported.get(peer).is_none_or(|(at, g)| {
            *g != self.local_gen || now.saturating_duration_since(*at) >= REPORT_EVERY
        });
        if due {
            self.reported.insert(*peer, (now, self.local_gen));
        }
        due
    }

    /// After a membership change: the senders that still hold an older
    /// report of ours, which now get the new one.
    pub fn stale_reports(&mut self, now: Instant) -> Vec<Bytes32> {
        let g = self.local_gen;
        let mut out = Vec::new();
        for (peer, (at, sent)) in self.reported.iter_mut() {
            if *sent != g && now.saturating_duration_since(*at) < REPORT_TTL {
                *at = now;
                *sent = g;
                out.push(*peer);
            }
        }
        out
    }

    /// Take one datagram of `len` bytes from `peer`, within what one
    /// sender may send (our own budget: a sender never exceeds it towards
    /// one receiver unless it is broken or hostile).
    pub fn accept(&mut self, peer: &Bytes32, len: usize, now: Instant) -> bool {
        if !self.per_sender.contains_key(peer) && self.per_sender.len() >= SENDER_CAP {
            self.per_sender.retain(|_, b| !b.full(now));
            if self.per_sender.len() >= SENDER_CAP {
                return false;
            }
        }
        let (pps, bps) = (self.budget.pps as u64, self.budget.bps as u64);
        self.per_sender
            .entry(*peer)
            .or_insert_with(|| Budget::new(pps, bps, now))
            .take(len, now)
    }

    /// A datagram went to the host.
    pub fn delivered(&mut self, digest: u64, now: Instant) {
        if self.delivered.len() >= ECHO_CAP {
            self.delivered
                .retain(|_, t| now.saturating_duration_since(*t) < ECHO_WINDOW);
            if self.delivered.len() >= ECHO_CAP {
                self.delivered.clear();
            }
        }
        self.delivered.insert(digest, now);
    }

    /// A datagram is about to go out by way of `origin`: is it the same one
    /// the host just sent by the other path? Then it's a duplicate. Only
    /// across paths: an app repeating a datagram on one path keeps doing so.
    pub fn duplicate(&mut self, digest: u64, origin: Origin, now: Instant) -> bool {
        if let Some((t, o)) = self.sent.get(&digest)
            && *o != origin
            && now.saturating_duration_since(*t) < DUPLICATE_WINDOW
        {
            return true;
        }
        if self.sent.len() >= ECHO_CAP {
            self.sent
                .retain(|_, (t, _)| now.saturating_duration_since(*t) < DUPLICATE_WINDOW);
            if self.sent.len() >= ECHO_CAP {
                self.sent.clear();
            }
        }
        self.sent.insert(digest, (now, origin));
        false
    }

    // ------------------------------------------------------------ upkeep

    pub fn forget(&mut self, peer: &Bytes32) {
        self.reports.remove(peer);
        self.reported.remove(peer);
        self.per_sender.remove(peer);
    }

    pub fn expire(&mut self, now: Instant) {
        self.reports.retain(|_, r| r.until > now);
        self.reported
            .retain(|_, (at, _)| now.saturating_duration_since(*at) < REPORT_TTL);
        self.per_sender.retain(|_, b| !b.full(now));
        self.delivered
            .retain(|_, t| now.saturating_duration_since(*t) < ECHO_WINDOW);
        self.sent
            .retain(|_, (t, _)| now.saturating_duration_since(*t) < DUPLICATE_WINDOW);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn pools() -> Vec<IpNet> {
        vec![
            "10.7.0.0/16".parse().unwrap(),
            "fd00:7::/48".parse().unwrap(),
        ]
    }

    #[test]
    fn kinds() {
        let p = pools();
        let k = |s: &str| kind(&ip(s), &p);
        assert_eq!(k("255.255.255.255"), Some(Kind::Broadcast));
        assert_eq!(k("10.7.255.255"), Some(Kind::Broadcast));
        assert_eq!(k("224.0.0.1"), Some(Kind::Broadcast));
        assert_eq!(k("ff02::1"), Some(Kind::Broadcast));
        assert_eq!(k("224.0.0.251"), Some(Kind::Group(ip("224.0.0.251"))));
        assert_eq!(
            k("239.255.255.250"),
            Some(Kind::Group(ip("239.255.255.250")))
        );
        assert_eq!(k("ff02::fb"), Some(Kind::Group(ip("ff02::fb"))));
        assert_eq!(k("ff05::1:3"), Some(Kind::Group(ip("ff05::1:3"))));
        // Unicast, another subnet's broadcast, interface-local scope.
        for s in [
            "10.7.0.2",
            "10.8.255.255",
            "0.0.0.0",
            "ff01::1",
            "ff00::1",
            "fd00:7::1",
        ] {
            assert_eq!(k(s), None, "{s}");
        }
        // Pools too small to have a broadcast address.
        let tiny = vec!["10.9.0.0/31".parse().unwrap()];
        assert_eq!(kind(&ip("10.9.0.1"), &tiny), None);
    }

    #[test]
    fn reports_round_trip() {
        for r in [
            Report::Any,
            Report::Nothing,
            Report::Groups(vec![]),
            Report::Groups(vec![ip("224.0.0.251"), ip("ff02::fb")]),
        ] {
            assert_eq!(decode_report(&encode_report(&r)), Some(r));
        }
        // Unicast groups, trailing bytes, unknown versions and flags.
        let mut bad = encode_report(&Report::Groups(vec![ip("224.0.0.251")]));
        bad[4 + 1] = 10;
        assert_eq!(decode_report(&bad), None);
        let mut long = encode_report(&Report::Any);
        long.push(0);
        assert_eq!(decode_report(&long), None);
        assert_eq!(decode_report(&[2, 0, 0, 0]), None);
        assert_eq!(decode_report(&[1, 9, 0, 0]), None);
        assert_eq!(decode_report(&[1, 0, 0, 1, 4, 224]), None);
    }

    proptest! {
        #[test]
        fn decoding_never_panics(b in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = decode_report(&b);
        }
    }

    #[test]
    fn the_budget_counts_packets_and_bytes() {
        let t = Instant::now();
        let mut b = Budget::new(3, 1000, t);
        assert!(b.take(400, t) && b.take(400, t));
        assert!(!b.take(400, t), "bytes run out first");
        assert!(b.take(100, t));
        assert!(!b.take(1, t), "then packets");
        assert!(!b.any_left(t));
        // A third of a second later: one packet, 100 + 333 bytes.
        let later = t + Duration::from_millis(334);
        assert!(b.any_left(later));
        assert!(!b.take(500, later));
        assert!(b.take(400, later));
    }

    #[test]
    fn senders_skip_peers_that_did_not_join() {
        let t = Instant::now();
        let mut s = State::new(50, 65536, t);
        let (a, b, c) = ([1; 32], [2; 32], [3; 32]);
        let mdns = Kind::Group(ip("224.0.0.251"));
        let ssdp = Kind::Group(ip("239.255.255.250"));
        // Nothing known yet: everyone gets everything.
        assert!(s.wants(&a, mdns, t));
        s.on_report(&a, Report::Groups(vec![ip("224.0.0.251")]), t);
        s.on_report(&b, Report::Nothing, t);
        s.on_report(&c, Report::Any, t);
        assert!(s.wants(&a, mdns, t) && !s.wants(&a, ssdp, t));
        assert!(s.wants(&a, Kind::Broadcast, t));
        assert!(!s.wants(&b, Kind::Broadcast, t) && !s.wants(&b, mdns, t));
        assert!(s.wants(&c, ssdp, t));
        // Reports lapse: then the peer gets it again, and reports anew.
        let late = t + REPORT_TTL;
        assert!(s.wants(&a, ssdp, late) && s.wants(&b, mdns, late));
        s.expire(late);
        assert!(s.reports.is_empty());
    }

    #[test]
    fn receivers_report_when_due_and_after_changes() {
        let t = Instant::now();
        let mut s = State::new(50, 65536, t);
        let (a, b) = ([1; 32], [2; 32]);
        assert_eq!(s.report(false), Report::Any);
        assert_eq!(s.report(true), Report::Nothing);
        assert!(s.member(Kind::Group(ip("239.1.2.3"))));
        assert!(s.report_due(&a, t));
        assert!(!s.report_due(&a, t + Duration::from_secs(1)));
        assert!(s.report_due(&a, t + REPORT_EVERY));
        // Joining a group: senders holding an old report get the new one.
        let t2 = t + REPORT_EVERY;
        let groups: HashSet<IpAddr> = [ip("224.0.0.251")].into();
        assert!(s.set_local(Some(groups.clone())));
        assert!(!s.set_local(Some(groups)));
        assert_eq!(s.report(false), Report::Groups(vec![ip("224.0.0.251")]));
        assert!(s.member(Kind::Group(ip("224.0.0.251"))));
        assert!(!s.member(Kind::Group(ip("239.1.2.3"))));
        assert!(s.member(Kind::Broadcast));
        assert_eq!(s.stale_reports(t2), vec![a]);
        assert!(s.stale_reports(t2).is_empty());
        assert!(!s.report_due(&a, t2));
        assert!(s.report_due(&b, t2));
        // A sender we reported to long ago has dropped our report anyway.
        s.set_local(None);
        assert!(s.stale_reports(t2 + REPORT_TTL).is_empty());
    }

    #[test]
    fn receivers_cap_each_sender() {
        let t = Instant::now();
        let mut s = State::new(2, 65536, t);
        let (a, b) = ([1; 32], [2; 32]);
        assert!(s.accept(&a, 100, t) && s.accept(&a, 100, t));
        assert!(!s.accept(&a, 100, t));
        assert!(s.accept(&b, 100, t), "per sender");
        // Idle senders are forgotten once their bucket is full again.
        s.expire(t + Duration::from_secs(1));
        assert!(s.per_sender.is_empty());
    }

    #[test]
    fn echoes_are_recognised_briefly() {
        let t = Instant::now();
        let mut s = State::new(50, 65536, t);
        let d = digest(Kind::Broadcast, b"ping");
        assert_ne!(d, digest(Kind::Group(ip("224.0.0.251")), b"ping"));
        assert!(!s.is_echo(d, t));
        s.delivered(d, t);
        assert!(s.is_echo(d, t + Duration::from_millis(500)));
        assert!(!s.is_echo(d, t + ECHO_WINDOW));
    }

    #[test]
    fn capture_ports() {
        let p =
            |v: &[&str]| CapturePorts::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let c = p(&["udp:19132", "udp:4000-4010"]).unwrap();
        assert!(c.contains(19132) && c.contains(4005) && !c.contains(19133));
        let all = p(&["udp"]).unwrap();
        assert!(all.contains(19132) && !all.contains(5353) && !all.contains(67));
        assert!(p(&[]).unwrap().is_empty());
        for bad in [
            "tcp:80", "icmp", "*", "udp:5353", "udp:67", "udp:x", "udp:9-1",
        ] {
            assert!(p(&[bad]).is_err(), "{bad}");
        }
    }

    #[test]
    fn captured_datagrams() {
        use crate::testutil::packets::udp4;
        let ports = CapturePorts::parse(&["udp:19132".to_string()]).unwrap();
        let lan = [ip("192.168.1.5")];
        let nets: Vec<IpNet> = vec!["192.168.1.0/24".parse().unwrap()];
        let me = ip("10.7.0.11");
        let cap = |p: &[u8]| captured(p, &ports, &lan, &nets, me);
        // A Bedrock ping to the limited broadcast: the source becomes ours.
        let ping = udp4(
            [192, 168, 1, 5],
            [255, 255, 255, 255],
            50000,
            19132,
            b"ping",
        );
        let out = cap(&ping).unwrap();
        let f = crate::packet::parse(&out).unwrap().flow;
        assert_eq!(
            (f.src, f.sport, f.dst, f.dport),
            (me, 50000, ip("255.255.255.255"), 19132)
        );
        let mut fixed = out.clone();
        crate::packet::fix_checksums(&mut fixed);
        assert_eq!(fixed, out, "checksums valid");
        // The LAN's directed broadcast arrives as the limited broadcast.
        let out = cap(&udp4(
            [192, 168, 1, 5],
            [192, 168, 1, 255],
            50000,
            19132,
            b"x",
        ))
        .unwrap();
        assert_eq!(
            crate::packet::parse(&out).unwrap().flow.dst,
            ip("255.255.255.255")
        );
        // Multicast, kept as it is.
        let out = cap(&udp4([192, 168, 1, 5], [239, 1, 2, 3], 50000, 19132, b"x")).unwrap();
        assert_eq!(
            crate::packet::parse(&out).unwrap().flow.dst,
            ip("239.1.2.3")
        );
        // Not ours, not a captured port, DHCP, unicast, another subnet's broadcast.
        for (src, dst, sport, dport) in [
            ([192, 168, 1, 9], [255, 255, 255, 255], 50000, 19132),
            ([192, 168, 1, 5], [255, 255, 255, 255], 50000, 19133),
            ([192, 168, 1, 5], [255, 255, 255, 255], 68, 19132),
            ([192, 168, 1, 5], [192, 168, 1, 7], 50000, 19132),
            ([192, 168, 1, 5], [192, 168, 2, 255], 50000, 19132),
        ] {
            assert!(
                cap(&udp4(src, dst, sport, dport, b"x")).is_none(),
                "{src:?} -> {dst:?}"
            );
        }
        // TCP, and an IPv6 overlay address.
        let mut tcp = ping.clone();
        tcp[9] = 6;
        assert!(cap(&tcp).is_none());
        assert!(captured(&ping, &ports, &lan, &nets, ip("fd00::1")).is_none());
    }

    #[test]
    fn duplicates_across_paths_only() {
        let t = Instant::now();
        let mut s = State::new(50, 65536, t);
        let d = digest(Kind::Broadcast, b"ping");
        assert!(!s.duplicate(d, Origin::Tun, t));
        assert!(s.duplicate(d, Origin::Captured, t + Duration::from_millis(10)));
        // The same path again: an app repeating itself.
        assert!(!s.duplicate(d, Origin::Tun, t + Duration::from_millis(20)));
        let later = t + Duration::from_millis(20) + DUPLICATE_WINDOW;
        assert!(!s.duplicate(d, Origin::Captured, later));
    }

    #[test]
    fn spending_past_the_budget_is_remembered() {
        let t = Instant::now();
        let mut s = State::new(1, 65536, t);
        assert!(s.budget_left(t) && s.spend(10, t));
        assert!(s.limited_at.is_none());
        assert!(!s.budget_left(t) && !s.spend(10, t));
        assert_eq!(s.limited_at, Some(t));
    }
}
