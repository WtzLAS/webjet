//! Routing (§11): link costs, load penalty, the relay graph built from
//! LinkStateAdverts and AttachmentRecords, k-best loop-free paths (Yen) with
//! at most 3 relays, hysteresis and randomized spreading, and transport
//! choice per neighbor (§9.6).

use crate::crypto::Bytes32;
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap};
use webjet_proto::Transport;

/// k in `cost = rtt × (1 + k × loss)` (§11.2).
pub const LOSS_K: f64 = 10.0;
pub const MAX_RELAYS: usize = 3;
/// Switch only if better by this fraction (§11.4).
pub const HYSTERESIS: f64 = 0.18;
/// Candidates within this fraction of the best are spread randomly (§11.4).
pub const SPREAD: f64 = 0.10;
pub const FULL_LOAD: u8 = 90;

pub fn link_cost(rtt_ms: f64, loss: f64) -> f64 {
    rtt_ms.max(0.1) * (1.0 + LOSS_K * loss.clamp(0.0, 1.0))
}

/// The convex load penalty of §11.8.2. `None` means "full": excluded.
pub fn load_penalty(load_pct: u8) -> Option<f64> {
    if load_pct >= FULL_LOAD {
        return None;
    }
    if load_pct < 50 {
        return Some(1.0);
    }
    let x = (load_pct as f64 - 50.0) / 50.0;
    Some(1.0 + 3.0 * x * x)
}

/// Relay load L = the highest of utilization, CPU, circuits and queue delay
/// (whichever runs out first matters), quantized to 10% steps (§11.8.1).
pub fn relay_load(util: u8, cpu: u8, circuits: u8, queue: u8) -> u8 {
    let l = util.max(cpu).max(circuits).max(queue).min(100);
    (l / 10) * 10
}

/// Queue delay as a load percentage: 0 at or below the CoDel target, 100
/// at `budget_ms` (where the hop queue starts dropping).
pub fn queue_load_pct(delay_ms: f64, target_ms: f64, budget_ms: f64) -> u8 {
    if delay_ms <= target_ms {
        return 0;
    }
    (((delay_ms - target_ms) / (budget_ms - target_ms)) * 100.0).clamp(0.0, 100.0) as u8
}

#[derive(Clone, Debug, Default)]
pub struct RelayInfo {
    /// Advertised neighbors: peer → cost.
    pub links: HashMap<Bytes32, f64>,
    pub load: u8,
    pub capacity_mbps: u32,
}

/// The graph a source computes paths over.
#[derive(Clone, Debug, Default)]
pub struct Graph {
    pub relays: HashMap<Bytes32, RelayInfo>,
    /// DATA node → (relay → cost), from AttachmentRecords.
    pub attachments: HashMap<Bytes32, HashMap<Bytes32, f64>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Path {
    /// Relays in order (empty = direct).
    pub hops: Vec<Bytes32>,
    pub cost: f64,
    /// Spare capacity weight (100 − max load on the path).
    pub spare: u8,
}

impl Graph {
    /// Cost of the relay-relay link, used only if both ends advertise it, at
    /// the higher of the two costs (§11.2).
    pub fn relay_link(&self, a: &Bytes32, b: &Bytes32) -> Option<f64> {
        let ca = self.relays.get(a)?.links.get(b)?;
        let cb = self.relays.get(b)?.links.get(a)?;
        Some(ca.max(*cb))
    }

    /// Edges out of `n`, for path search from `src` to `dst`.
    fn edges(&self, n: &Bytes32, src: &Bytes32, dst: &Bytes32) -> Vec<(Bytes32, f64)> {
        let mut out = Vec::new();
        if n == src && !self.relays.contains_key(src) {
            // A DATA source enters through its attachments.
            if let Some(att) = self.attachments.get(src) {
                for (r, c) in att {
                    if self.relays.contains_key(r) {
                        out.push((*r, *c));
                    }
                }
            }
            return out;
        }
        if let Some(info) = self.relays.get(n) {
            for p in info.links.keys() {
                if let Some(c) = self.relay_link(n, p) {
                    out.push((*p, c));
                }
            }
            // Last hop to a DATA destination attached to this relay.
            if !self.relays.contains_key(dst) {
                if let Some(c) = self.attachments.get(dst).and_then(|a| a.get(n)) {
                    out.push((*dst, *c));
                }
            }
        }
        out
    }

    fn relays_of(&self, nodes: &[Bytes32], src: &Bytes32, dst: &Bytes32) -> Vec<Bytes32> {
        nodes
            .iter()
            .filter(|n| *n != src && *n != dst)
            .copied()
            .collect()
    }

    fn path_cost(&self, nodes: &[Bytes32], src: &Bytes32, dst: &Bytes32) -> Option<(f64, u8)> {
        let mut c = 0.0;
        for w in nodes.windows(2) {
            let e = self.edges(&w[0], src, dst);
            c += e.iter().find(|(n, _)| *n == w[1])?.1;
        }
        let relays = self.relays_of(nodes, src, dst);
        let mut pen: f64 = 1.0;
        let mut max_load = 0u8;
        for r in &relays {
            let l = self.relays.get(r)?.load;
            pen = pen.max(load_penalty(l)?);
            max_load = max_load.max(l);
        }
        Some((c * pen, 100 - max_load.min(100)))
    }

    /// Dijkstra avoiding `banned_nodes` and `banned_edges`, with a relay-count cap.
    fn shortest(
        &self,
        src: &Bytes32,
        dst: &Bytes32,
        banned_nodes: &BTreeSet<Bytes32>,
        banned_edges: &BTreeSet<(Bytes32, Bytes32)>,
    ) -> Option<Vec<Bytes32>> {
        #[derive(PartialEq)]
        struct St(f64, Vec<Bytes32>);
        impl Eq for St {}
        impl PartialOrd for St {
            fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(o))
            }
        }
        impl Ord for St {
            fn cmp(&self, o: &Self) -> std::cmp::Ordering {
                o.0.partial_cmp(&self.0)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }
        }
        let mut best: HashMap<(Bytes32, usize), f64> = HashMap::new();
        let mut heap = BinaryHeap::new();
        heap.push(St(0.0, vec![*src]));
        while let Some(St(c, path)) = heap.pop() {
            let n = *path.last().unwrap();
            if n == *dst {
                return Some(path);
            }
            let relays_used = path.len() - 1;
            for (m, ec) in self.edges(&n, src, dst) {
                if banned_nodes.contains(&m) || banned_edges.contains(&(n, m)) || path.contains(&m)
                {
                    continue;
                }
                let is_relay = m != *dst;
                if is_relay {
                    if relays_used + 1 > MAX_RELAYS {
                        continue;
                    }
                    match self.relays.get(&m).map(|r| r.load) {
                        Some(l) if load_penalty(l).is_none() => continue,
                        None => continue,
                        _ => {}
                    }
                }
                let nc = c + ec;
                let key = (m, path.len());
                if best.get(&key).map(|b| *b <= nc).unwrap_or(false) {
                    continue;
                }
                best.insert(key, nc);
                let mut p = path.clone();
                p.push(m);
                heap.push(St(nc, p));
            }
        }
        None
    }

    /// Yen's k shortest loop-free paths from `src` to `dst` (§11.4). If the
    /// source or destination is itself a relay it is its own first or last
    /// relay and is not listed in `hops` (§4.1).
    pub fn k_paths(&self, src: &Bytes32, dst: &Bytes32, k: usize) -> Vec<Path> {
        let mut a: Vec<Vec<Bytes32>> = Vec::new();
        let mut b: Vec<(f64, Vec<Bytes32>)> = Vec::new();
        let Some(first) = self.shortest(src, dst, &BTreeSet::new(), &BTreeSet::new()) else {
            return Vec::new();
        };
        a.push(first);
        while a.len() < k {
            let last = a.last().unwrap().clone();
            for i in 0..last.len() - 1 {
                let spur = last[i];
                let root = &last[..=i];
                let mut banned_edges = BTreeSet::new();
                for p in &a {
                    if p.len() > i && &p[..=i] == root {
                        banned_edges.insert((p[i], p[i + 1]));
                    }
                }
                let banned_nodes: BTreeSet<Bytes32> = root[..i].iter().copied().collect();
                if let Some(spur_path) =
                    self.shortest_from(src, &spur, dst, &banned_nodes, &banned_edges, i)
                {
                    let mut total = root[..i].to_vec();
                    total.extend(spur_path);
                    if total.len() - 2 > MAX_RELAYS {
                        continue;
                    }
                    if !a.contains(&total) && !b.iter().any(|(_, p)| *p == total) {
                        if let Some((c, _)) = self.path_cost(&total, src, dst) {
                            b.push((c, total));
                        }
                    }
                }
            }
            if b.is_empty() {
                break;
            }
            b.sort_by(|x, y| x.0.partial_cmp(&y.0).unwrap());
            a.push(b.remove(0).1);
        }
        let mut out: Vec<Path> = a
            .into_iter()
            .filter_map(|p| {
                let (cost, spare) = self.path_cost(&p, src, dst)?;
                Some(Path {
                    hops: self.relays_of(&p, src, dst),
                    cost,
                    spare,
                })
            })
            .collect();
        out.sort_by(|x, y| x.cost.partial_cmp(&y.cost).unwrap());
        out
    }

    fn shortest_from(
        &self,
        src: &Bytes32,
        from: &Bytes32,
        dst: &Bytes32,
        banned_nodes: &BTreeSet<Bytes32>,
        banned_edges: &BTreeSet<(Bytes32, Bytes32)>,
        prefix_relays: usize,
    ) -> Option<Vec<Bytes32>> {
        if from == src {
            return self.shortest(src, dst, banned_nodes, banned_edges);
        }
        // Treat `from` as the start but keep edge semantics of the full search.
        let mut best: HashMap<Bytes32, f64> = HashMap::new();
        let mut frontier: Vec<(f64, Vec<Bytes32>)> = vec![(0.0, vec![*from])];
        let mut found: Option<(f64, Vec<Bytes32>)> = None;
        while let Some(idx) = frontier
            .iter()
            .enumerate()
            .min_by(|a, b| a.1 .0.partial_cmp(&b.1 .0).unwrap())
            .map(|(i, _)| i)
        {
            let (c, path) = frontier.swap_remove(idx);
            let n = *path.last().unwrap();
            if n == *dst {
                found = Some((c, path));
                break;
            }
            for (m, ec) in self.edges(&n, src, dst) {
                if banned_nodes.contains(&m)
                    || banned_edges.contains(&(n, m))
                    || path.contains(&m)
                    || m == *src
                {
                    continue;
                }
                let relays = prefix_relays + path.len();
                if m != *dst
                    && (relays > MAX_RELAYS
                        || self
                            .relays
                            .get(&m)
                            .and_then(|r| load_penalty(r.load))
                            .is_none())
                {
                    continue;
                }
                let nc = c + ec;
                if best.get(&m).map(|b| *b <= nc).unwrap_or(false) {
                    continue;
                }
                best.insert(m, nc);
                let mut p = path.clone();
                p.push(m);
                frontier.push((nc, p));
            }
        }
        found.map(|f| f.1)
    }
}

/// Pick among candidates within `SPREAD` of the best, weighted by spare
/// capacity (§11.8.3).
pub fn spread_pick(cands: &[Path]) -> Option<&Path> {
    let best = cands.first()?.cost;
    let near: Vec<&Path> = cands
        .iter()
        .filter(|p| p.cost <= best * (1.0 + SPREAD))
        .collect();
    let total: u32 = near.iter().map(|p| p.spare.max(1) as u32).sum();
    let mut x = rand::thread_rng().gen_range(0..total.max(1));
    for p in &near {
        let w = p.spare.max(1) as u32;
        if x < w {
            return Some(p);
        }
        x -= w;
    }
    near.first().copied()
}

/// Hysteresis for path or transport switching (§11.4, §9.6): switch only
/// when the challenger has been better by `HYSTERESIS` for `hold_ms`.
#[derive(Clone, Debug, Default)]
pub struct Hysteresis {
    challenger: Option<(u64, u64)>, // (candidate id, since_ms)
}

impl Hysteresis {
    pub fn should_switch(
        &mut self,
        current_cost: f64,
        cand_id: u64,
        cand_cost: f64,
        now_ms: u64,
        hold_ms: u64,
    ) -> bool {
        if !current_cost.is_finite() {
            self.challenger = None;
            return cand_cost.is_finite();
        }
        if cand_cost < current_cost * (1.0 - HYSTERESIS) {
            match self.challenger {
                Some((id, since)) if id == cand_id => {
                    if now_ms.saturating_sub(since) >= hold_ms {
                        self.challenger = None;
                        return true;
                    }
                }
                _ => self.challenger = Some((cand_id, now_ms)),
            }
        } else if self.challenger.map(|c| c.0) == Some(cand_id) {
            self.challenger = None;
        }
        false
    }
}

// ---------------------------------------------------------------- transport choice (§9.6)

pub const DEFAULT_PRIORITIES: [(Transport, u8); 3] = [
    (Transport::KcpFecTls, 30),
    (Transport::AnyTls, 20),
    (Transport::TcpTls, 10),
];

#[derive(Clone, Copy, Debug)]
pub struct TransportCand {
    pub transport: Transport,
    pub cost: f64, // infinite when down
    pub prio_sum: u16,
}

/// Choose the transport to send on: lowest cost; near-ties (within 10%) go
/// to the highest priority sum, then the fixed tie order.
pub fn choose_transport(cands: &[TransportCand]) -> Option<Transport> {
    let best = cands
        .iter()
        .filter(|c| c.cost.is_finite())
        .map(|c| c.cost)
        .fold(f64::INFINITY, f64::min);
    if !best.is_finite() {
        return None;
    }
    let mut near: Vec<&TransportCand> = cands
        .iter()
        .filter(|c| c.cost.is_finite() && c.cost <= best * 1.10)
        .collect();
    near.sort_by(|a, b| {
        b.prio_sum
            .cmp(&a.prio_sum)
            .then(a.transport.tie_rank().cmp(&b.transport.tie_rank()))
    });
    near.first().map(|c| c.transport)
}

/// Long-term memory of a link (one per neighbor and transport), kept across
/// hop reconnects and agent restarts. It makes a link that keeps failing,
/// or that is lossy now and then, cost more than its last few probes
/// suggest, and lets a link earn trust back gradually (§11.2, §11.8.3).
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LinkHistory {
    /// Slow EWMAs (time constant [`LONG_TAU_MS`]).
    pub rtt_ms: f64,
    pub loss: f64,
    pub jitter_ms: f64,
    /// Decaying count of session failures (half-life [`FLAP_HALF_LIFE_MS`]).
    pub flaps: f64,
    pub samples: u64,
    /// Wall clock of the last update, ms.
    pub updated_ms: u64,
}

pub const LONG_TAU_MS: f64 = 15.0 * 60_000.0;
pub const FLAP_HALF_LIFE_MS: f64 = 60.0 * 60_000.0;
/// Each recent failure adds this much to the cost, up to `MAX_FLAP_FACTOR`.
const FLAP_WEIGHT: f64 = 0.15;
const MAX_FLAP_FACTOR: f64 = 2.0;
/// Jitter counts at half weight: it hurts tunnelled TCP less than delay.
const JITTER_WEIGHT: f64 = 0.5;
/// Probe outcomes kept for the exact recent loss rate.
const LOSS_WINDOW: usize = 64;

impl LinkHistory {
    fn decay(&mut self, now_ms: u64) -> f64 {
        let dt = now_ms.saturating_sub(self.updated_ms) as f64;
        if self.updated_ms != 0 {
            self.flaps *= 0.5f64.powf(dt / FLAP_HALF_LIFE_MS);
        }
        self.updated_ms = now_ms;
        if self.samples == 0 {
            1.0
        } else {
            1.0 - (-dt.max(1.0) / LONG_TAU_MS).exp()
        }
    }

    /// One probe answered after `rtt_ms`.
    pub fn observe(&mut self, rtt_ms: f64, jitter_ms: f64, now_ms: u64) {
        let a = self.decay(now_ms);
        self.rtt_ms += a * (rtt_ms - self.rtt_ms);
        self.jitter_ms += a * (jitter_ms - self.jitter_ms);
        self.loss += a * (0.0 - self.loss);
        self.samples += 1;
    }

    /// One probe lost.
    pub fn observe_loss(&mut self, now_ms: u64) {
        let a = self.decay(now_ms);
        if self.samples > 0 {
            self.loss += a * (1.0 - self.loss);
        }
    }

    /// The hop session died (timeout or error, not an orderly close).
    pub fn flap(&mut self, now_ms: u64) {
        self.decay(now_ms);
        self.flaps += 1.0;
    }

    /// Cost multiplier for instability.
    pub fn stability_factor(&self) -> f64 {
        (1.0 + FLAP_WEIGHT * self.flaps).min(MAX_FLAP_FACTOR)
    }

    pub fn cost(&self) -> f64 {
        if self.samples == 0 {
            return f64::INFINITY;
        }
        link_cost(self.rtt_ms + JITTER_WEIGHT * self.jitter_ms, self.loss) * self.stability_factor()
    }

    /// Bring the history forward to `now_ms` (flaps decay while idle).
    pub fn age(&mut self, now_ms: u64) {
        if self.updated_ms != 0 && now_ms > self.updated_ms {
            let dt = (now_ms - self.updated_ms) as f64;
            self.flaps *= 0.5f64.powf(dt / FLAP_HALF_LIFE_MS);
            self.updated_ms = now_ms;
        }
    }
}

/// RTT/loss estimate for one link (§11.2): RFC 6298-style smoothed RTT and
/// variance, a windowed minimum RTT, a short EWMA and an exact windowed loss
/// rate, combined with the link's long-term [`LinkHistory`].
#[derive(Clone, Debug)]
pub struct LinkStats {
    pub srtt_ms: f64,
    pub rttvar_ms: f64,
    /// Lowest RTT over the last ten minutes (the path's base delay).
    pub min_rtt_ms: f64,
    /// Short-term loss EWMA (~10 probes).
    pub loss: f64,
    pub samples: u64,
    pub history: LinkHistory,
    sent: BTreeMap<u64, u64>,
    outcomes: std::collections::VecDeque<bool>,
    min_buckets: std::collections::VecDeque<(u64, f64)>,
}

impl Default for LinkStats {
    fn default() -> Self {
        LinkStats::with_history(LinkHistory::default())
    }
}

const MIN_BUCKET_US: u64 = 60_000_000;
const MIN_BUCKETS: usize = 10;
/// Probes before the session's own measurements fully replace history.
const WARMUP: u64 = 8;

impl LinkStats {
    pub fn with_history(history: LinkHistory) -> Self {
        LinkStats {
            srtt_ms: 0.0,
            rttvar_ms: 0.0,
            min_rtt_ms: f64::INFINITY,
            loss: 0.0,
            samples: 0,
            history,
            sent: BTreeMap::new(),
            outcomes: std::collections::VecDeque::new(),
            min_buckets: std::collections::VecDeque::new(),
        }
    }

    fn record(&mut self, ok: bool) {
        self.outcomes.push_back(ok);
        while self.outcomes.len() > LOSS_WINDOW {
            self.outcomes.pop_front();
        }
    }

    fn lost_one(&mut self, now_ms: u64) {
        self.loss = self.loss * 0.9 + 0.1;
        self.record(false);
        self.history.observe_loss(now_ms);
    }

    pub fn on_sent(&mut self, seq: u64, at_us: u64) {
        self.on_sent_at(seq, at_us, crate::types::now_ms());
    }

    pub fn on_sent_at(&mut self, seq: u64, at_us: u64, now_ms: u64) {
        self.sent.insert(seq, at_us);
        // Anything older than 16 outstanding probes counts as lost.
        while self.sent.len() > 16 {
            let (&k, _) = self.sent.iter().next().unwrap();
            self.sent.remove(&k);
            self.lost_one(now_ms);
        }
    }

    pub fn on_ack(&mut self, seq: u64, now_us: u64) -> Option<f64> {
        self.on_ack_at(seq, now_us, crate::types::now_ms())
    }

    pub fn on_ack_at(&mut self, seq: u64, now_us: u64, now_ms: u64) -> Option<f64> {
        let at = self.sent.remove(&seq)?;
        // Earlier unacked probes are lost.
        let lost: Vec<u64> = self.sent.range(..seq).map(|(k, _)| *k).collect();
        for k in lost {
            self.sent.remove(&k);
            self.lost_one(now_ms);
        }
        let rtt = (now_us.saturating_sub(at)) as f64 / 1000.0;
        if self.samples == 0 {
            self.srtt_ms = rtt;
            self.rttvar_ms = rtt / 2.0;
        } else {
            self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * (self.srtt_ms - rtt).abs();
            self.srtt_ms = 0.875 * self.srtt_ms + 0.125 * rtt;
        }
        // Windowed minimum in one-minute buckets.
        let bucket = now_us / MIN_BUCKET_US;
        match self.min_buckets.back_mut() {
            Some((b, m)) if *b == bucket => *m = m.min(rtt),
            _ => self.min_buckets.push_back((bucket, rtt)),
        }
        while self
            .min_buckets
            .front()
            .map(|(b, _)| bucket.saturating_sub(*b) >= MIN_BUCKETS as u64)
            .unwrap_or(false)
        {
            self.min_buckets.pop_front();
        }
        self.min_rtt_ms = self
            .min_buckets
            .iter()
            .map(|x| x.1)
            .fold(f64::INFINITY, f64::min);
        self.loss *= 0.9;
        self.record(true);
        self.samples += 1;
        self.history.observe(rtt, self.rttvar_ms, now_ms);
        Some(rtt)
    }

    /// Exact loss over the recent probe window.
    pub fn window_loss(&self) -> f64 {
        if self.outcomes.is_empty() {
            return 0.0;
        }
        self.outcomes.iter().filter(|o| !**o).count() as f64 / self.outcomes.len() as f64
    }

    /// Effective RTT and loss: what the cost is computed from, and what is
    /// advertised (§11.2). Short-term measurements dominate, but a link that
    /// has been lossy keeps part of that loss, recent session failures raise
    /// the cost, and a new session starts from the link's history.
    pub fn effective(&self) -> Option<(f64, f64)> {
        let h = &self.history;
        if self.samples == 0 && h.samples == 0 {
            return None;
        }
        let short_rtt = self.srtt_ms + JITTER_WEIGHT * self.rttvar_ms;
        let short_loss = self.loss.max(self.window_loss());
        let (rtt, loss) = if self.samples == 0 {
            (h.rtt_ms + JITTER_WEIGHT * h.jitter_ms, h.loss)
        } else if self.samples < WARMUP && h.samples > 0 {
            // Blend from history toward the fresh session.
            let w = self.samples as f64 / WARMUP as f64;
            let hr = h.rtt_ms + JITTER_WEIGHT * h.jitter_ms;
            (
                w * short_rtt + (1.0 - w) * hr,
                (w * short_loss + (1.0 - w) * h.loss).max(short_loss),
            )
        } else {
            (short_rtt, short_loss.max(0.5 * h.loss))
        };
        // Instability shows up as extra delay, so remote cost computations agree.
        Some((rtt * h.stability_factor(), loss.clamp(0.0, 1.0)))
    }

    pub fn cost(&self) -> f64 {
        match self.effective() {
            Some((rtt, loss)) if self.samples > 0 || self.history.samples > 0 => {
                link_cost(rtt, loss)
            }
            _ => f64::INFINITY,
        }
    }

    /// Quantized values for adverts (so small changes don't trigger updates).
    pub fn quantized(&self) -> (u16, u8) {
        let (rtt, loss) = self.effective().unwrap_or((0.0, 0.0));
        let rtt = if rtt < 10.0 {
            rtt.ceil()
        } else {
            (rtt / 5.0).round() * 5.0
        };
        (
            rtt.min(65535.0) as u16,
            (loss * 100.0).round().min(100.0) as u8,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(i: u8) -> Bytes32 {
        [i; 32]
    }

    fn mesh() -> Graph {
        let mut g = Graph::default();
        // relays 1..=4 in a ring with a diagonal 1-3
        let links = [
            (1, 2, 10.0),
            (2, 3, 10.0),
            (3, 4, 15.0),
            (4, 1, 15.0),
            (1, 3, 25.0),
        ];
        for (a, b, c) in links {
            g.relays.entry(id(a)).or_default().links.insert(id(b), c);
            g.relays.entry(id(b)).or_default().links.insert(id(a), c);
        }
        g.attachments
            .insert(id(100), [(id(1), 5.0)].into_iter().collect());
        g.attachments
            .insert(id(200), [(id(3), 5.0)].into_iter().collect());
        g
    }

    #[test]
    fn k_paths_basic() {
        let g = mesh();
        let p = g.k_paths(&id(100), &id(200), 4);
        assert!(!p.is_empty());
        assert_eq!(p[0].hops, vec![id(1), id(2), id(3)]);
        assert!(p.windows(2).all(|w| w[0].cost <= w[1].cost));
        for x in &p {
            assert!(x.hops.len() <= MAX_RELAYS);
        }
        assert!(p.iter().any(|x| x.hops == vec![id(1), id(3)]));
    }

    #[test]
    fn one_sided_links_ignored_and_full_relay_excluded() {
        let mut g = mesh();
        g.relays.get_mut(&id(2)).unwrap().links.remove(&id(3));
        let p = g.k_paths(&id(100), &id(200), 3);
        assert!(p.iter().all(|x| x.hops != vec![id(1), id(2), id(3)]));
        let mut g = mesh();
        g.relays.get_mut(&id(2)).unwrap().load = 95;
        let p = g.k_paths(&id(100), &id(200), 5);
        assert!(p.iter().all(|x| !x.hops.contains(&id(2))));
    }

    #[test]
    fn relay_endpoints_are_not_hops() {
        let g = mesh();
        let p = g.k_paths(&id(1), &id(3), 3);
        assert_eq!(p[0].hops, vec![id(2)]);
        let p = g.k_paths(&id(100), &id(1), 2);
        assert_eq!(p[0].hops, Vec::<Bytes32>::new());
    }

    #[test]
    fn penalty_monotonic() {
        let mut last = 0.0;
        for l in 0..90u8 {
            let p = load_penalty(l).unwrap();
            assert!(p >= last);
            last = p;
        }
        assert!(load_penalty(90).is_none());
    }

    #[test]
    fn transport_choice() {
        let c = |t, cost, p| TransportCand {
            transport: t,
            cost,
            prio_sum: p,
        };
        assert_eq!(
            choose_transport(&[
                c(Transport::KcpFecTls, 50.0, 60),
                c(Transport::AnyTls, 53.0, 40)
            ]),
            Some(Transport::KcpFecTls)
        );
        assert_eq!(
            choose_transport(&[
                c(Transport::KcpFecTls, 100.0, 60),
                c(Transport::TcpTls, 50.0, 20)
            ]),
            Some(Transport::TcpTls)
        );
        assert_eq!(
            choose_transport(&[
                c(Transport::KcpFecTls, 50.0, 60),
                c(Transport::TcpTls, 51.0, 200)
            ]),
            Some(Transport::TcpTls)
        );
        assert_eq!(
            choose_transport(&[c(Transport::KcpFecTls, f64::INFINITY, 60)]),
            None
        );
    }

    #[test]
    fn hysteresis_holds() {
        let mut h = Hysteresis::default();
        assert!(!h.should_switch(100.0, 1, 50.0, 0, 3000));
        assert!(!h.should_switch(100.0, 1, 50.0, 2000, 3000));
        assert!(h.should_switch(100.0, 1, 50.0, 3000, 3000));
        assert!(!h.should_switch(100.0, 2, 95.0, 4000, 0));
    }

    fn probe(st: &mut LinkStats, seq: u64, rtt_ms: u64, t_ms: u64, lost: bool) {
        st.on_sent_at(seq, t_ms * 1000, t_ms);
        if !lost {
            st.on_ack_at(seq, (t_ms + rtt_ms) * 1000, t_ms + rtt_ms);
        }
    }

    #[test]
    fn rtt_variance_and_min() {
        let mut st = LinkStats::default();
        for i in 0..50 {
            probe(
                &mut st,
                i,
                if i % 2 == 0 { 20 } else { 40 },
                i * 2000,
                false,
            );
        }
        assert!(st.srtt_ms > 25.0 && st.srtt_ms < 35.0);
        assert!(st.rttvar_ms > 5.0, "jitter is tracked");
        assert_eq!(st.min_rtt_ms, 20.0);
        let steady = {
            let mut s2 = LinkStats::default();
            for i in 0..50 {
                probe(&mut s2, i, 30, i * 2000, false);
            }
            s2.cost()
        };
        assert!(
            st.cost() > steady,
            "a jittery link costs more than a steady one with the same mean"
        );
    }

    #[test]
    fn window_loss_is_exact() {
        let mut st = LinkStats::default();
        for i in 0..64 {
            probe(&mut st, i, 10, i * 2000, i % 4 == 0);
        }
        // Make the last loss resolve.
        probe(&mut st, 64, 10, 64 * 2000, false);
        assert!(
            (st.window_loss() - 16.0 / 64.0).abs() < 0.03,
            "{}",
            st.window_loss()
        );
    }

    #[test]
    fn history_survives_reconnect_and_remembers_loss() {
        let mut st = LinkStats::default();
        // A long lossy period.
        for i in 0..900 {
            probe(&mut st, i, 30, i * 2000, i % 5 == 0);
        }
        let mut h = st.history.clone();
        assert!(h.loss > 0.1, "long-term loss {}", h.loss);
        h.flap(900 * 2000);
        // A new session on the same link starts from history, not from zero.
        let fresh = LinkStats::with_history(h.clone());
        assert!(fresh.cost().is_finite());
        assert!(fresh.cost() > link_cost(30.0, 0.0) * 1.5);
        // Clean probes bring the cost down, but some long-term loss remains.
        let mut st2 = LinkStats::with_history(h);
        for i in 0..30 {
            probe(&mut st2, 1000 + i, 30, 2_000_000 + i * 2000, false);
        }
        let clean = {
            let mut c = LinkStats::default();
            for i in 0..30 {
                probe(&mut c, i, 30, i * 2000, false);
            }
            c.cost()
        };
        assert!(
            st2.cost() > clean,
            "a historically lossy link stays more expensive for a while"
        );
        assert!(st2.cost() < fresh.cost());
    }

    #[test]
    fn flaps_raise_cost_and_decay() {
        let mut h = LinkHistory::default();
        h.observe(20.0, 1.0, 1_000);
        let base = h.cost();
        for k in 0..5 {
            h.flap(2_000 + k);
        }
        assert!(h.cost() > base * 1.5);
        assert!(h.cost() <= base * MAX_FLAP_FACTOR + 1e-9);
        h.age(2_000 + 6 * 3_600_000);
        assert!(
            h.cost() < base * 1.1,
            "flaps are forgotten after a few hours"
        );
    }

    #[test]
    fn quantized_matches_cost() {
        let mut st = LinkStats::default();
        for i in 0..20 {
            probe(&mut st, i, 47, i * 2000, i == 7);
        }
        let (r, l) = st.quantized();
        let c = link_cost(r as f64, l as f64 / 100.0);
        assert!(
            (c - st.cost()).abs() / st.cost() < 0.15,
            "adverts let others compute about the same cost"
        );
    }
}
