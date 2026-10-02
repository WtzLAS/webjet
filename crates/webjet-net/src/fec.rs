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
pub const MAX_PARITY_RATIO: f64 = 0.30;

pub struct Encoder {
    group: u32,
    pending: Vec<Vec<u8>>,
    pub ratio: f64,
    pub parity_bytes: u64,
    codecs: HashMap<(usize, usize), ReedSolomon>,
}

fn codec(cache: &mut HashMap<(usize, usize), ReedSolomon>, k: usize, m: usize) -> &ReedSolomon {
    cache.entry((k, m)).or_insert_with(|| ReedSolomon::new(k, m).expect("rs params"))
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
        Encoder { group: 0, pending: Vec::new(), ratio: 0.0, parity_bytes: 0, codecs: HashMap::new() }
    }

    fn parity_count(&self, k: usize) -> usize {
        if self.ratio <= 0.001 {
            return 0;
        }
        ((k as f64) * self.ratio).ceil().clamp(1.0, (k as f64 * MAX_PARITY_RATIO).ceil().max(1.0)) as usize
    }

    /// Wrap one data packet; returns the shards to send now (the data shard
    /// and, when the group is complete, its parity).
    pub fn push(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let idx = self.pending.len() as u8;
        let mut out = Vec::with_capacity(2);
        let mut s = header(self.group, idx, 0, 0, data.len() as u16).to_vec();
        s.extend_from_slice(data);
        out.push(s);
        self.pending.push(data.to_vec());
        if self.pending.len() >= GROUP_DATA {
            out.extend(self.flush());
        }
        out
    }

    /// Close the current group (on a flush timer), emitting its parity.
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let k = self.pending.len();
        let m = self.parity_count(k);
        let group = self.group;
        self.group = self.group.wrapping_add(1);
        let pending = std::mem::take(&mut self.pending);
        if m == 0 {
            return Vec::new();
        }
        let width = pending.iter().map(|p| p.len() + 2).max().unwrap_or(2);
        let mut shards: Vec<Vec<u8>> = pending
            .iter()
            .map(|p| {
                let mut v = Vec::with_capacity(width);
                v.extend_from_slice(&(p.len() as u16).to_be_bytes());
                v.extend_from_slice(p);
                v.resize(width, 0);
                v
            })
            .collect();
        shards.extend((0..m).map(|_| vec![0u8; width]));
        if codec(&mut self.codecs, k, m).encode(&mut shards).is_err() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(m);
        for (j, p) in shards.into_iter().skip(k).enumerate() {
            let mut s = header(group, (k + j) as u8, k as u8, m as u8, width as u16).to_vec();
            s.extend_from_slice(&p);
            self.parity_bytes += s.len() as u64;
            out.push(s);
        }
        out
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Adapt the ratio to the measured loss, aiming at <0.1% residual loss
    /// (§17.6). Moves gradually.
    pub fn adapt(&mut self, loss: f64) {
        let target = if loss < 0.002 { 0.0 } else { (loss * 3.0 + 0.05).min(MAX_PARITY_RATIO) };
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

pub struct Decoder {
    groups: BTreeMap<u32, Group>,
    newest: u32,
    pub recovered: u64,
    pub received: u64,
    codecs: HashMap<(usize, usize), ReedSolomon>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Decoder { groups: BTreeMap::new(), newest: 0, recovered: 0, received: 0, codecs: HashMap::new() }
    }

    /// Process one shard; returns the data packets to hand to KCP.
    pub fn push(&mut self, shard: &[u8]) -> Vec<Vec<u8>> {
        if shard.len() < HDR {
            return Vec::new();
        }
        let group = u32::from_be_bytes(shard[..4].try_into().unwrap());
        let idx = shard[4];
        let (k, m) = (shard[5], shard[6]);
        let len = u16::from_be_bytes([shard[7], shard[8]]) as usize;
        let Some(payload) = shard.get(HDR..HDR + len) else { return Vec::new() };
        self.received += 1;
        // Keep a bounded window of groups.
        if group.wrapping_sub(self.newest) < u32::MAX / 2 {
            self.newest = group;
        }
        while self.groups.len() > 64 {
            let first = *self.groups.keys().next().unwrap();
            self.groups.remove(&first);
        }
        let g = self.groups.entry(group).or_insert(Group { data: BTreeMap::new(), parity: BTreeMap::new(), k: 0, m: 0, done: false });
        let mut out = Vec::new();
        if k == 0 {
            // A data shard: deliver immediately.
            if let std::collections::btree_map::Entry::Vacant(e) = g.data.entry(idx) {
                e.insert(payload.to_vec());
                out.push(payload.to_vec());
            }
        } else {
            g.k = k;
            g.m = m;
            g.parity.insert(idx, payload.to_vec());
        }
        if g.done || g.k == 0 {
            return out;
        }
        let (kk, mm) = (g.k as usize, g.m as usize);
        if g.data.len() >= kk {
            g.done = true;
            return out;
        }
        if g.data.len() + g.parity.len() < kk {
            return out;
        }
        let width = g.parity.values().next().map(|p| p.len()).unwrap_or(0);
        let mut slots: Vec<Option<Vec<u8>>> = (0..kk + mm)
            .map(|i| {
                if i < kk {
                    g.data.get(&(i as u8)).map(|d| {
                        let mut v = Vec::with_capacity(width);
                        v.extend_from_slice(&(d.len() as u16).to_be_bytes());
                        v.extend_from_slice(d);
                        v.resize(width, 0);
                        v
                    })
                } else {
                    g.parity.get(&(i as u8)).cloned()
                }
            })
            .collect();
        if slots.iter().flatten().any(|s| s.len() != width) {
            g.done = true;
            return out;
        }
        let missing: Vec<usize> = (0..kk).filter(|i| slots[*i].is_none()).collect();
        let ok = codec(&mut self.codecs, kk, mm).reconstruct_data(&mut slots).is_ok();
        let g = self.groups.get_mut(&group).unwrap();
        g.done = true;
        if ok {
            for i in missing {
                if let Some(s) = &slots[i] {
                    let l = u16::from_be_bytes([s[0], s[1]]) as usize;
                    if let Some(d) = s.get(2..2 + l) {
                        out.push(d.to_vec());
                        self.recovered += 1;
                    }
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
}
