//! Hop queues (§17.2, §17.3): a priority lane for control traffic and a
//! fair-queued CoDel lane for data, marking ECN-capable frames instead of
//! dropping them (§17.7).

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub const TARGET: Duration = Duration::from_millis(5);
pub const INTERVAL: Duration = Duration::from_millis(100);
const QUANTUM: usize = 1514;

#[derive(Debug)]
pub struct Item {
    pub flow: u64,
    pub data: Vec<u8>,
    pub at: Instant,
    /// Offset of the relay header's hop/ecn byte, when the frame can be marked.
    pub ecn_offset: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    QueueFull,
    Aqm,
}

#[derive(Default, Debug)]
struct Codel {
    first_above: Option<Instant>,
    dropping: bool,
    drop_next: Option<Instant>,
    count: u32,
}

impl Codel {
    /// Returns true if the item dequeued at `now` with sojourn `s` must be
    /// dropped/marked.
    fn should_drop(
        &mut self,
        s: Duration,
        now: Instant,
        interval: Duration,
        queue_empty_after: bool,
    ) -> bool {
        let ok_to_drop = if s < TARGET || queue_empty_after {
            self.first_above = None;
            false
        } else {
            match self.first_above {
                None => {
                    self.first_above = Some(now + interval);
                    false
                }
                Some(t) => now >= t,
            }
        };
        if self.dropping {
            if !ok_to_drop {
                self.dropping = false;
                return false;
            }
            if let Some(dn) = self.drop_next {
                if now >= dn {
                    self.count += 1;
                    self.drop_next = Some(dn + interval.div_f64((self.count as f64).sqrt()));
                    return true;
                }
            }
            false
        } else if ok_to_drop {
            self.dropping = true;
            self.count = if self.count > 2 { self.count - 2 } else { 1 };
            self.drop_next = Some(now + interval.div_f64((self.count as f64).sqrt()));
            true
        } else {
            false
        }
    }
}

#[derive(Default, Debug)]
struct FlowQ {
    items: VecDeque<Item>,
    deficit: isize,
    codel: Codel,
    bytes: usize,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub dropped_full: u64,
    pub dropped_aqm: u64,
    pub marked: u64,
    pub last_sojourn: Duration,
}

pub struct HopQueue {
    control: VecDeque<Vec<u8>>,
    flows: HashMap<u64, FlowQ>,
    active: VecDeque<u64>,
    pub bytes: usize,
    pub max_bytes: usize,
    pub interval: Duration,
    pub stats: Stats,
    control_budget: usize,
}

impl Default for HopQueue {
    fn default() -> Self {
        Self::new(1 << 20)
    }
}

impl HopQueue {
    pub fn new(max_bytes: usize) -> Self {
        HopQueue {
            control: VecDeque::new(),
            flows: HashMap::new(),
            active: VecDeque::new(),
            bytes: 0,
            max_bytes,
            interval: INTERVAL,
            stats: Stats::default(),
            control_budget: 0,
        }
    }

    /// Adapt CoDel's interval to the hop RTT (§17.2) and the hard cap to
    /// ~100 ms at the current rate.
    pub fn tune(&mut self, rtt: Duration, rate_bytes_per_sec: f64) {
        self.interval = if rtt > Duration::from_millis(50) {
            rtt * 2
        } else {
            INTERVAL
        };
        self.max_bytes = ((rate_bytes_per_sec * 0.1) as usize).clamp(64 * 1024, 16 << 20);
    }

    pub fn push_control(&mut self, data: Vec<u8>) {
        self.control.push_back(data);
    }

    pub fn push(&mut self, item: Item) -> Result<(), Dropped> {
        if self.bytes + item.data.len() > self.max_bytes {
            self.stats.dropped_full += 1;
            return Err(Dropped::QueueFull);
        }
        self.bytes += item.data.len();
        let f = self.flows.entry(item.flow).or_default();
        if f.items.is_empty() {
            f.deficit = QUANTUM as isize;
            self.active.push_back(item.flow);
        }
        f.bytes += item.data.len();
        f.items.push_back(item);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.control.is_empty() && self.active.is_empty()
    }

    /// Dequeue the next frame to send. Control goes first but is limited to
    /// roughly a quarter of the bytes while data is waiting (§17.3).
    pub fn pop(&mut self, now: Instant) -> Option<Vec<u8>> {
        if !self.control.is_empty() && (self.active.is_empty() || self.control_budget < 3 * QUANTUM)
        {
            let c = self.control.pop_front().unwrap();
            self.control_budget += c.len();
            return Some(c);
        }
        self.control_budget = 0;
        loop {
            let flow = *self.active.front()?;
            let f = self.flows.get_mut(&flow).unwrap();
            if f.deficit <= 0 {
                f.deficit += QUANTUM as isize;
                self.active.rotate_left(1);
                continue;
            }
            let Some(mut it) = f.items.pop_front() else {
                self.active.pop_front();
                self.flows.remove(&flow);
                continue;
            };
            f.bytes -= it.data.len();
            self.bytes -= it.data.len();
            let sojourn = now.duration_since(it.at);
            self.stats.last_sojourn = sojourn;
            let empty_after = f.items.is_empty();
            let drop = f
                .codel
                .should_drop(sojourn, now, self.interval, empty_after);
            if empty_after {
                self.active.pop_front();
                self.flows.remove(&flow);
            } else {
                f.deficit -= it.data.len() as isize;
            }
            if drop {
                // Mark ECN-capable frames, drop the rest (§17.7).
                if let Some(off) = it.ecn_offset {
                    if let Some(b) = it.data.get_mut(off) {
                        if *b & 3 != crate::frames::ecn::NOT_ECT {
                            *b |= crate::frames::ecn::CE;
                            self.stats.marked += 1;
                            return Some(it.data);
                        }
                    }
                }
                self.stats.dropped_aqm += 1;
                continue;
            }
            return Some(it.data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_first_and_fairness() {
        let mut q = HopQueue::new(1 << 20);
        let t = Instant::now();
        for i in 0..10 {
            q.push(Item {
                flow: 1,
                data: vec![1; 1000],
                at: t,
                ecn_offset: None,
            })
            .unwrap();
            if i < 2 {
                q.push(Item {
                    flow: 2,
                    data: vec![2; 1000],
                    at: t,
                    ecn_offset: None,
                })
                .unwrap();
            }
        }
        q.push_control(vec![9; 10]);
        assert_eq!(q.pop(t).unwrap(), vec![9; 10]);
        // Flow 2 gets served early despite flow 1's backlog.
        let order: Vec<u8> = (0..4).map(|_| q.pop(t).unwrap()[0]).collect();
        assert!(order.contains(&2));
    }

    #[test]
    fn codel_marks_ecn_and_drops_others() {
        let mut q = HopQueue::new(1 << 20);
        let t0 = Instant::now();
        for i in 0..200u32 {
            let ecn = if i % 2 == 0 {
                crate::frames::ecn::ECT0
            } else {
                0
            };
            let mut d = vec![0u8; 100];
            d[4] = ecn;
            q.push(Item {
                flow: (i % 2) as u64,
                data: d,
                at: t0,
                ecn_offset: Some(4),
            })
            .unwrap();
        }
        let mut now = t0 + Duration::from_millis(50);
        let mut out = 0;
        while let Some(_) = q.pop(now) {
            out += 1;
            now += Duration::from_millis(10);
        }
        assert!(q.stats.marked > 0);
        assert!(q.stats.dropped_aqm > 0);
        assert_eq!(out as u64 + q.stats.dropped_aqm, 200);
    }

    #[test]
    fn hard_cap() {
        let mut q = HopQueue::new(1000);
        let t = Instant::now();
        assert!(q
            .push(Item {
                flow: 1,
                data: vec![0; 900],
                at: t,
                ecn_offset: None
            })
            .is_ok());
        assert_eq!(
            q.push(Item {
                flow: 1,
                data: vec![0; 200],
                at: t,
                ecn_offset: None
            }),
            Err(Dropped::QueueFull)
        );
    }
}
