//! Adaptive Reed–Solomon FEC below KCP (§17.6).
//!
//! Data shards (KCP packets) are sent immediately; after `k` data shards or
//! a short flush timeout, `m` parity shards follow. Shard wire format:
//! `group[4] || index[1] || k[1] || m[1] || len[2] || payload` where parity
//! payloads cover the data shards each prefixed with its 2-byte length and
//! zero-padded to the longest.

use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::{BTreeMap, HashMap};

pub const HDR: usize = 9;
pub const GROUP_DATA: usize = 8;
/// Largest shard payload the decoder accepts: a KCP packet (`KCP_MTU`,
/// 1300 bytes) plus the 2-byte length inside parity, with room to spare.
pub const MAX_SHARD: usize = 2048;
pub const MAX_PARITY_RATIO: f64 = 0.30;

pub struct Encoder {
    group: u32,
    /// Data packets in the current group.
    count: usize,
    /// Their copies, kept only when parity is on.
    pending: Vec<Vec<u8>>,
    pub ratio: f64,
    pub parity_bytes: u64,
    codecs: HashMap<(usize, usize), ReedSolomon>,
}

/// A cached Reed–Solomon codec; `None` for parameters it can't handle
/// (zero shards, or more than 256 in total).
fn codec(
    cache: &mut HashMap<(usize, usize), ReedSolomon>,
    k: usize,
    m: usize,
) -> Option<&ReedSolomon> {
    use std::collections::hash_map::Entry;
    match cache.entry((k, m)) {
        Entry::Occupied(e) => Some(e.into_mut()),
        Entry::Vacant(e) => Some(e.insert(ReedSolomon::new(k, m).ok()?)),
    }
}

fn header(group: u32, idx: u8, k: u8, m: u8, len: u16) -> [u8; HDR] {
    let mut h = [0u8; HDR];
    h[..4].copy_from_slice(&group.to_be_bytes());
    h[4] = idx;
    h[5] = k;
    h[6] = m;
    h[7..9].copy_from_slice(&len.to_be_bytes());
    h
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    pub fn new() -> Self {
        Encoder {
            group: 0,
            count: 0,
            pending: Vec::new(),
            ratio: 0.0,
            parity_bytes: 0,
            codecs: HashMap::new(),
        }
    }

    fn parity_count(&self, k: usize) -> usize {
        if self.ratio <= 0.001 {
            return 0;
        }
        ((k as f64) * self.ratio)
            .ceil()
            .clamp(1.0, (k as f64 * MAX_PARITY_RATIO).ceil().max(1.0)) as usize
    }

    /// Wrap one data packet; returns the shards to send now (the data shard
    /// and, when the group is complete, its parity).
    pub fn push(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        // `count < GROUP_DATA` (8) always fits; a packet longer than the
        // 16-bit length field can't be framed, and the decoder would drop it
        // anyway (> MAX_SHARD), so it is not sent rather than mislabelled.
        let (Ok(idx), Ok(len)) = (u8::try_from(self.count), u16::try_from(data.len())) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(2);
        let mut s = Vec::with_capacity(HDR + data.len());
        s.extend_from_slice(&header(self.group, idx, 0, 0, len));
        s.extend_from_slice(data);
        out.push(s);
        // Keep a copy for parity only while there will be parity: on a clean
        // link (ratio 0) the copies would just be thrown away.
        if self.parity_count(GROUP_DATA) > 0 {
            self.pending.push(data.to_vec());
        }
        self.count += 1;
        if self.count >= GROUP_DATA {
            out.extend(self.flush());
        }
        out
    }

    /// Close the current group (on a flush timer), emitting its parity.
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.count == 0 {
            return Vec::new();
        }
        let k = self.count;
        let m = self.parity_count(k);
        let group = self.group;
        self.group = self.group.wrapping_add(1);
        self.count = 0;
        let pending = std::mem::take(&mut self.pending);
        // No parity, or it was switched on mid-group and copies are missing.
        // The header fields are 8/16 bits: k ≤ GROUP_DATA, m ≤ 30 % of it and
        // width ≤ a KCP packet + 2, so this only rejects impossible groups.
        let width = pending.iter().map(|p| p.len() + 2).max().unwrap_or(2);
        let (Ok(k8), Ok(m8), Ok(width16)) =
            (u8::try_from(k), u8::try_from(m), u16::try_from(width))
        else {
            return Vec::new();
        };
        if m == 0 || pending.len() != k || usize::from(k8) + usize::from(m8) > 256 {
            return Vec::new();
        }
        let mut shards: Vec<Vec<u8>> = pending
            .iter()
            .map(|p| {
                let mut v = Vec::with_capacity(width);
                // p.len() + 2 ≤ width ≤ u16::MAX, checked above.
                v.extend_from_slice(&u16::try_from(p.len()).unwrap_or(0).to_be_bytes());
                v.extend_from_slice(p);
                v.resize(width, 0);
                v
            })
            .collect();
        shards.extend((0..m).map(|_| vec![0u8; width]));
        if !codec(&mut self.codecs, k, m).is_some_and(|c| c.encode(&mut shards).is_ok()) {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(m);
        for (j, p) in shards.into_iter().skip(k).enumerate() {
            // k + j < k + m ≤ 256, checked above.
            let Ok(idx) = u8::try_from(k + j) else { break };
            let mut s = Vec::with_capacity(HDR + p.len());
            s.extend_from_slice(&header(group, idx, k8, m8, width16));
            s.extend_from_slice(&p);
            self.parity_bytes += s.len() as u64;
            out.push(s);
        }
        out
    }

    pub fn has_pending(&self) -> bool {
        self.count > 0
    }

    /// Adapt the ratio to the measured loss, aiming at <0.1% residual loss
    /// (§17.6). Moves gradually.
    pub fn adapt(&mut self, loss: f64) {
        let target = if loss < 0.002 {
            0.0
        } else {
            (loss * 3.0 + 0.05).min(MAX_PARITY_RATIO)
        };
        self.ratio = self.ratio * 0.8 + target * 0.2;
        if self.ratio < 0.005 {
            self.ratio = 0.0;
        }
    }
}

struct Group {
    data: BTreeMap<u8, Vec<u8>>,
    parity: BTreeMap<u8, Vec<u8>>,
    k: u8,
    m: u8,
    done: bool,
}

/// Groups behind the newest one before a group's loss is counted, so
/// reordered shards still arrive in time.
const SETTLE_LAG: u32 = 4;
/// A larger jump in group numbers is an outage, not line loss; it is skipped
/// rather than counted group by group.
const MAX_SETTLE_GAP: u32 = 256;
/// Groups kept for recovery, counted back from the newest.
const WINDOW: u32 = 64;

pub struct Decoder {
    groups: BTreeMap<u32, Group>,
    newest: u32,
    pub recovered: u64,
    pub received: u64,
    codecs: HashMap<(usize, usize), ReedSolomon>,
    /// Next group whose loss is to be counted.
    next_settle: Option<u32>,
    /// Data shards sent and received in counted groups, since the last
    /// [`Decoder::take_loss`].
    loss_expected: u64,
    loss_received: u64,
    /// Average data shards per group, for groups lost entirely (0 = none seen).
    avg_k: f64,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Decoder {
            groups: BTreeMap::new(),
            newest: 0,
            recovered: 0,
            received: 0,
            codecs: HashMap::new(),
            next_settle: None,
            loss_expected: 0,
            loss_received: 0,
            avg_k: 0.0,
        }
    }

    /// Line loss of data shards since the last call, as `(received,
    /// expected)`, measured before recovery: the loss FEC has to cover (§17.6).
    /// A group's size is known from its parity header; a group without parity
    /// counts up to its highest data shard seen, so trailing losses go unseen
    /// until parity flows.
    pub fn take_loss(&mut self) -> (u64, u64) {
        let r = (self.loss_received, self.loss_expected);
        self.loss_received = 0;
        self.loss_expected = 0;
        r
    }

    /// Count the loss of every group at least [`SETTLE_LAG`] behind the newest.
    fn settle(&mut self) {
        let Some(mut next) = self.next_settle else {
            return;
        };
        let behind = self.newest.wrapping_sub(next);
        if behind >= u32::MAX / 2 {
            return;
        }
        if behind > MAX_SETTLE_GAP + SETTLE_LAG {
            next = self.newest;
        }
        while self.newest.wrapping_sub(next) >= SETTLE_LAG
            && self.newest.wrapping_sub(next) < u32::MAX / 2
        {
            let (expected, got) = match self.groups.get(&next) {
                Some(g) => {
                    let seen = g.data.keys().next_back().map_or(0, |i| u64::from(*i) + 1);
                    let expected = if g.k > 0 { u64::from(g.k) } else { seen };
                    self.avg_k = if self.avg_k == 0.0 {
                        expected as f64
                    } else {
                        self.avg_k * 0.9 + expected as f64 * 0.1
                    };
                    (expected, (g.data.len() as u64).min(expected))
                }
                None => ((self.avg_k.round() as u64).max(1), 0),
            };
            self.loss_expected += expected;
            self.loss_received += got;
            next = next.wrapping_add(1);
        }
        self.next_settle = Some(next);
    }

    /// Process one shard; returns the data packets to hand to KCP.
    pub fn push(&mut self, shard: &[u8]) -> Vec<Vec<u8>> {
        if shard.len() < HDR {
            return Vec::new();
        }
        let Some(group) = webjet_core::bytes::be_u32(shard, 0) else {
            return Vec::new();
        };
        let idx = shard[4];
        let (k, m) = (shard[5], shard[6]);
        let len = u16::from_be_bytes([shard[7], shard[8]]) as usize;
        let Some(payload) = shard.get(HDR..HDR + len) else {
            return Vec::new();
        };
        // Our encoder sends at most GROUP_DATA data shards per group, each a
        // KCP packet (≤ KCP_MTU), and parity a little wider. Anything else
        // is malformed; storing it would let a peer pin megabytes per group.
        if len > MAX_SHARD || (k == 0 && usize::from(idx) >= GROUP_DATA) {
            return Vec::new();
        }
        self.received += 1;
        // Keep a bounded window of groups.
        if group.wrapping_sub(self.newest) < u32::MAX / 2 {
            self.newest = group;
        }
        if self.next_settle.is_none() {
            self.next_settle = Some(group);
        }
        self.settle();
        // Group numbers wrap: the groups kept are the WINDOW newest by
        // distance from `newest`, not the numerically largest (after the
        // wrap, 0, 1, … are the newest and u32::MAX the stalest).
        if self.groups.len() > WINDOW as usize {
            let newest = self.newest;
            self.groups.retain(|g, _| newest.wrapping_sub(*g) < WINDOW);
        }
        let g = self.groups.entry(group).or_insert(Group {
            data: BTreeMap::new(),
            parity: BTreeMap::new(),
            k: 0,
            m: 0,
            done: false,
        });
        let mut out = Vec::new();
        if k == 0 {
            // A data shard: deliver immediately.
            if let std::collections::btree_map::Entry::Vacant(e) = g.data.entry(idx) {
                e.insert(payload.to_vec());
                out.push(payload.to_vec());
            }
        } else {
            // A parity shard. Our encoder never uses more than GROUP_DATA
            // data shards (and fewer parity shards); anything else is
            // malformed. Bounding k and m also bounds the codec cache.
            let (ku, mu) = (usize::from(k), usize::from(m));
            if ku > GROUP_DATA || mu == 0 || mu > GROUP_DATA {
                return out;
            }
            if usize::from(idx) < ku || usize::from(idx) >= ku + mu {
                return out;
            }
            if g.k != 0 && (g.k, g.m) != (k, m) {
                // Parity shards of one group disagree about its shape.
                g.done = true;
                return out;
            }
            g.k = k;
            g.m = m;
            g.parity.insert(idx, payload.to_vec());
        }
        if g.done || g.k == 0 {
            return out;
        }
        let (kk, mm) = (usize::from(g.k), usize::from(g.m));
        if g.data.len() >= kk {
            g.done = true;
            return out;
        }
        if g.data.len() + g.parity.len() < kk {
            return out;
        }
        let width = g.parity.values().next().map_or(0, |p| p.len());
        // Every data shard is encoded as `len[2] || data`, padded to the
        // width: a width below 2, or a data shard that doesn't fit, means the
        // shards don't belong together.
        if width < 2 || g.data.values().any(|d| d.len() + 2 > width) {
            g.done = true;
            return out;
        }
        // k, m ≤ GROUP_DATA (checked on arrival), so k + m fits in a u8, and
        // stored data shards are ≤ MAX_SHARD bytes, so their length fits a u16.
        let mut slots: Vec<Option<Vec<u8>>> = (0..g.k + g.m)
            .map(|i| {
                if i < g.k {
                    g.data.get(&i).map(|d| {
                        let mut v = Vec::with_capacity(width);
                        v.extend_from_slice(&u16::try_from(d.len()).unwrap_or(0).to_be_bytes());
                        v.extend_from_slice(d);
                        v.resize(width, 0);
                        v
                    })
                } else {
                    g.parity.get(&i).cloned()
                }
            })
            .collect();
        if slots.iter().flatten().any(|s| s.len() != width) {
            g.done = true;
            return out;
        }
        let missing: Vec<usize> = (0..kk).filter(|i| slots[*i].is_none()).collect();
        let ok =
            codec(&mut self.codecs, kk, mm).is_some_and(|c| c.reconstruct_data(&mut slots).is_ok());
        if let Some(g) = self.groups.get_mut(&group) {
            g.done = true;
        }
        if ok {
            for i in missing {
                if let Some(s) = &slots[i]
                    && let Some(l) = webjet_core::bytes::be_u16(s, 0)
                    && let Some(d) = s.get(2..2 + usize::from(l))
                {
                    out.push(d.to_vec());
                    self.recovered += 1;
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_lost_data() {
        let mut e = Encoder::new();
        e.ratio = 0.25;
        let mut d = Decoder::new();
        let pkts: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 50 + i as usize * 7]).collect();
        let mut shards = Vec::new();
        for p in &pkts {
            shards.extend(e.push(p));
        }
        assert_eq!(shards.len(), 8 + 2);
        let mut got = Vec::new();
        for (i, s) in shards.iter().enumerate() {
            if i == 2 || i == 5 {
                continue; // lose two data shards
            }
            got.extend(d.push(s));
        }
        got.sort();
        let mut want = pkts.clone();
        want.sort();
        assert_eq!(got, want);
        assert_eq!(d.recovered, 2);
    }

    #[test]
    fn no_parity_when_clean() {
        let mut e = Encoder::new();
        for _ in 0..50 {
            e.adapt(0.0);
        }
        let mut n = 0;
        for i in 0..16u8 {
            n += e.push(&[i; 10]).len();
        }
        assert_eq!(n, 16);
        e.adapt(0.05);
        e.adapt(0.05);
        assert!(e.ratio > 0.0 && e.ratio <= MAX_PARITY_RATIO);
    }

    /// Shards of `groups` groups of 8 packets, with `ratio` parity.
    fn stream(ratio: f64, groups: usize) -> Vec<Vec<u8>> {
        let mut e = Encoder::new();
        e.ratio = ratio;
        let mut shards = Vec::new();
        for i in 0..groups * GROUP_DATA {
            shards.extend(e.push(&[i as u8; 40]));
        }
        shards
    }

    fn is_data(s: &[u8]) -> bool {
        s[5] == 0
    }

    #[test]
    fn measures_loss_without_parity() {
        // No parity yet (a clean link's start): loss must still be seen, or
        // the sender's ratio never leaves 0.
        let mut d = Decoder::new();
        for (i, s) in stream(0.0, 20).iter().enumerate() {
            if i % 10 != 3 {
                d.push(s);
            }
        }
        let (got, expected) = d.take_loss();
        assert!(expected >= 120, "expected {expected}");
        let loss = 1.0 - got as f64 / expected as f64;
        assert!((0.07..0.13).contains(&loss), "loss {loss}");
        assert_eq!(d.take_loss(), (0, 0), "counted once");
    }

    #[test]
    fn measures_loss_before_recovery_and_whole_lost_groups() {
        let mut d = Decoder::new();
        let shards = stream(0.25, 20);
        let mut data_seen = 0;
        for s in &shards {
            let group = u32::from_be_bytes([s[0], s[1], s[2], s[3]]);
            if group == 5 {
                continue; // a whole group lost
            }
            if is_data(s) {
                data_seen += 1;
                if data_seen % 8 == 1 {
                    continue; // one data shard per group lost, recovered by parity
                }
            }
            d.push(s);
        }
        assert!(d.recovered > 0);
        let (got, expected) = d.take_loss();
        // 16 settled groups × 8 data shards; group 5 lost, one shard lost in
        // every other group, whether or not parity rebuilt it.
        assert_eq!(expected, 16 * 8);
        assert_eq!(got, 15 * 7);
    }

    #[test]
    fn outage_is_not_counted_as_loss() {
        let mut d = Decoder::new();
        let shards = stream(0.0, 2000);
        for s in shards.iter().take(80).chain(shards.iter().skip(15_000)) {
            d.push(s);
        }
        let (got, expected) = d.take_loss();
        assert!(expected > 0);
        assert_eq!(got, expected);
    }

    /// A shard: `group || idx || k || m || len || payload`.
    fn shard(group: u32, idx: u8, k: u8, m: u8, payload: &[u8]) -> Vec<u8> {
        let mut s = header(group, idx, k, m, payload.len() as u16).to_vec();
        s.extend_from_slice(payload);
        s
    }

    #[test]
    fn oversized_or_out_of_range_data_shards_are_dropped() {
        let mut d = Decoder::new();
        assert_eq!(d.push(&shard(0, 7, 0, 0, &[1; 1300])).len(), 1);
        assert!(d.push(&shard(0, 8, 0, 0, &[1; 10])).is_empty());
        assert!(d.push(&shard(0, 255, 0, 0, &[1; 10])).is_empty());
        assert!(d.push(&shard(1, 0, 0, 0, &[1; MAX_SHARD + 1])).is_empty());
        assert!(d.push(&shard(1, 9, 8, 1, &[1; MAX_SHARD + 1])).is_empty());
        assert_eq!(d.received, 1);
    }

    #[test]
    fn malformed_parity_is_dropped_without_panicking() {
        // Found by fuzzing: a 1-byte parity shard made the recovered slot
        // too short for its length prefix.
        let mut d = Decoder::new();
        assert!(d.push(&shard(0, 1, 1, 1, &[0x7a])).is_empty());
        // Data shard too big for the parity width, and the other order.
        let mut d = Decoder::new();
        d.push(&shard(1, 0, 0, 0, &[1; 10]));
        assert!(d.push(&shard(1, 2, 2, 1, &[0; 4])).is_empty());
        // k or m beyond what an encoder sends, a parity index among the
        // data indexes, and groups whose parity shards disagree.
        let mut d = Decoder::new();
        assert!(d.push(&shard(2, 200, 200, 1, &[0; 8])).is_empty());
        assert!(d.push(&shard(3, 9, 1, 250, &[0; 8])).is_empty());
        assert!(d.push(&shard(4, 0, 2, 1, &[0; 8])).is_empty());
        assert!(d.push(&shard(5, 2, 2, 1, &[0; 8])).is_empty());
        assert!(d.push(&shard(5, 3, 2, 2, &[0; 8])).is_empty());
        assert!(d.codecs.len() <= 1);
    }

    #[test]
    fn real_groups_still_recover_after_the_checks() {
        let mut e = Encoder::new();
        e.ratio = 0.3;
        let pkts: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 1 + i as usize * 30]).collect();
        let mut shards = Vec::new();
        for p in &pkts {
            shards.extend(e.push(p));
        }
        shards.extend(e.flush());
        // Lose the two longest data shards.
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for s in &shards {
            if s[5] == 0 && (s[4] == 6 || s[4] == 7) {
                continue;
            }
            got.extend(d.push(s));
        }
        got.sort();
        let mut want = pkts.clone();
        want.sort();
        assert_eq!(got, want);
        assert_eq!(d.recovered, 2);
    }

    #[test]
    fn recovery_keeps_working_across_the_group_number_wrap() {
        // A long-lived hop's group counter wraps: groups 0, 1, … are then
        // the newest, and evicting by number would drop each group as it
        // fills, ending recovery for the rest of the session.
        let mut e = Encoder::new();
        e.ratio = 0.25;
        e.group = u32::MAX - 100;
        let mut d = Decoder::new();
        let (mut sent, mut got) = (0usize, 0usize);
        for i in 0..300 * GROUP_DATA {
            let pkt = [i as u8; 40];
            sent += 1;
            for s in e.push(&pkt) {
                // One data shard lost in every group.
                if is_data(&s) && s[4] == 3 {
                    continue;
                }
                got += d.push(&s).len();
            }
        }
        assert!(e.group < 300, "the counter wrapped");
        assert_eq!(got, sent, "every lost shard rebuilt");
        assert_eq!(d.recovered, 300);
        assert!(d.groups.len() <= WINDOW as usize + 1);
        assert!(d.groups.keys().all(|g| d.newest.wrapping_sub(*g) <= WINDOW));
    }
}
