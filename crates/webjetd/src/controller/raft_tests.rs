//! Raft tests: targeted scenarios plus a deterministic simulator that runs
//! clusters through crashes, restarts, partitions, message loss,
//! duplication, reordering, snapshots and membership changes, checking the
//! Raft safety properties after every step:
//!
//! * **Election safety:** at most one leader per term.
//! * **Log matching:** if two logs hold an entry with the same index and
//!   term, they are identical up to that index.
//! * **Leader completeness:** a new leader holds every committed entry.
//! * **State machine safety:** no two servers apply different entries at the
//!   same index (also across restarts and snapshot installs).
//! * **Configuration tracking:** the configuration Raft derives from the log
//!   equals the one the state machine computes by applying it.
//!
//! and, once faults stop, **liveness**: a leader emerges and new entries
//! commit everywhere. Extra seeds: `WEBJET_RAFT_SEEDS=200 cargo test raft`.

use super::*;
use rand::rngs::StdRng;
use rand::{Rng, RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use webjet_proto::EntryPayload;

const T: Timing = Timing {
    heartbeat: Duration::from_millis(50),
    election_min: Duration::from_millis(300),
    election_max: Duration::from_millis(600),
};

fn nid(i: u8) -> Bytes32 {
    [i; 32]
}

fn members(voters: &[u8], learners: &[u8]) -> Membership {
    Membership {
        voters: voters.iter().map(|i| nid(*i)).collect(),
        learners: learners.iter().map(|i| nid(*i)).collect(),
    }
}

fn classify(b: &[u8]) -> Option<ConfChange> {
    let e = wp::LogEntry::decode_bytes(b).ok()?;
    match e.payload? {
        EntryPayload::MembershipEntry(m) => Some(ConfChange::Set(Membership {
            voters: m
                .voters
                .unwrap_or_default()
                .iter()
                .map(|k| k.to_bytes())
                .collect(),
            learners: m
                .learners
                .unwrap_or_default()
                .iter()
                .map(|k| k.to_bytes())
                .collect(),
        })),
        _ => None,
    }
}

fn value_entry(term: u64, index: u64, value: u64) -> wp::LogEntry {
    wp::LogEntry {
        term,
        index,
        timestamp: 0,
        payload: Some(EntryPayload::ExpireEnrollmentsEntry(Box::new(
            wp::ExpireEnrollmentsEntry { now: value },
        ))),
        random: None,
        leaves: None,
    }
}

fn conf_entry(term: u64, index: u64, m: &Membership) -> wp::LogEntry {
    wp::LogEntry {
        term,
        index,
        timestamp: 0,
        payload: Some(EntryPayload::MembershipEntry(Box::new(
            wp::MembershipEntry {
                voters: Some(m.voters.iter().map(crypto::k32).collect()),
                learners: Some(m.learners.iter().map(crypto::k32).collect()),
            },
        ))),
        random: None,
        leaves: None,
    }
}

fn hash(b: &[u8]) -> u64 {
    u64::from_be_bytes(blake3::hash(b).as_bytes()[..8].try_into().unwrap())
}

fn value_of(b: &[u8]) -> Option<u64> {
    match wp::LogEntry::decode_bytes(b).ok()?.payload? {
        EntryPayload::ExpireEnrollmentsEntry(e) => Some(e.now),
        _ => None,
    }
}

/// The test state machine: the hash of every applied entry, the client
/// values, and the membership (applied exactly like the controller does).
#[derive(Clone, Default, Serialize, Deserialize, Debug)]
struct Sm {
    applied: u64,
    last_term: u64,
    hashes: Vec<u64>,
    values: Vec<u64>,
    voters: Vec<Bytes32>,
    learners: Vec<Bytes32>,
}

impl Sm {
    fn membership(&self) -> Membership {
        Membership {
            voters: self.voters.iter().copied().collect(),
            learners: self.learners.iter().copied().collect(),
        }
    }
    fn set_membership(&mut self, m: &Membership) {
        self.voters = m.voters.iter().copied().collect();
        self.learners = m.learners.iter().copied().collect();
    }
}

struct SimNode {
    id: Bytes32,
    store: Arc<Mutex<MemStore>>,
    raft: Option<Raft>,
    sm: Sm,
    initial: Membership,
}

#[derive(Default, Debug)]
struct Stats {
    elections: u64,
    crashes: u64,
    partitions: u64,
    snapshots_installed: u64,
    conf_changes: u64,
    delivered: u64,
    proposed: u64,
}

struct Sim {
    rng: StdRng,
    base: Instant,
    t: u64,
    nodes: Vec<SimNode>,
    net: Vec<(u64, Bytes32, Bytes32, RaftBody)>,
    group: Option<Vec<u8>>,
    drop_p: f64,
    dup_p: f64,
    max_delay: u64,
    committed: BTreeMap<u64, u64>,
    leaders: HashMap<u64, Bytes32>,
    completeness_checked: HashSet<(u64, Bytes32)>,
    next_value: u64,
    compact_every: u64,
    stats: Stats,
}

impl Sim {
    /// `n` nodes `1..=n`; those in `initial` start with it as their
    /// configuration (like the genesis), the others with an empty one.
    fn new(seed: u64, n: u8, initial: Membership) -> Sim {
        let mut s = Sim {
            rng: StdRng::seed_from_u64(seed),
            base: Instant::now(),
            t: 0,
            nodes: Vec::new(),
            net: Vec::new(),
            group: None,
            drop_p: 0.0,
            dup_p: 0.0,
            max_delay: 10,
            committed: BTreeMap::new(),
            leaders: HashMap::new(),
            completeness_checked: HashSet::new(),
            next_value: 1,
            compact_every: 50,
            stats: Stats::default(),
        };
        for i in 1..=n {
            let id = nid(i);
            let member = initial.voters.contains(&id) || initial.learners.contains(&id);
            let init = if member {
                initial.clone()
            } else {
                Membership::default()
            };
            let (_, store) = Storage::mem();
            s.nodes.push(SimNode {
                id,
                store,
                raft: None,
                sm: Sm::default(),
                initial: init,
            });
            s.start(i as usize - 1);
        }
        s
    }

    fn now(&self) -> Instant {
        self.base + Duration::from_millis(self.t)
    }

    fn ix(&self, id: &Bytes32) -> usize {
        self.nodes.iter().position(|n| n.id == *id).unwrap()
    }

    fn start(&mut self, i: usize) {
        let now = self.now();
        let seed: u64 = self.rng.next_u64();
        let node = &mut self.nodes[i];
        let snap = node.store.lock().snapshot.clone();
        node.sm = match snap {
            Some(b) => serde_json::from_slice(&b).unwrap(),
            None => {
                let mut sm = Sm::default();
                sm.set_membership(&node.initial);
                sm
            }
        };
        let r = Raft::new(
            node.id,
            Storage::Mem(node.store.clone()),
            node.sm.applied,
            node.sm.last_term,
            node.sm.membership(),
            Box::new(classify),
            T,
            now,
            Some(seed),
        )
        .unwrap();
        node.raft = Some(r);
    }

    fn crash(&mut self, i: usize) {
        self.nodes[i].raft = None;
        self.nodes[i].sm = Sm::default();
        self.stats.crashes += 1;
    }

    fn connected(&self, a: &Bytes32, b: &Bytes32) -> bool {
        match &self.group {
            None => true,
            Some(g) => g[self.ix(a)] == g[self.ix(b)],
        }
    }

    fn send(&mut self, from: Bytes32, out: Out) {
        for (to, body) in out {
            if self.rng.random_bool(self.drop_p) {
                continue;
            }
            let copies = if self.rng.random_bool(self.dup_p) {
                2
            } else {
                1
            };
            for _ in 0..copies {
                let d = self.rng.random_range(1..=self.max_delay);
                self.net.push((self.t + d, from, to, body.clone()));
            }
        }
    }

    fn deliver(&mut self) {
        let t = self.t;
        let mut due: Vec<(u64, Bytes32, Bytes32, RaftBody)> = Vec::new();
        let mut keep = Vec::new();
        for m in self.net.drain(..) {
            if m.0 <= t {
                due.push(m);
            } else {
                keep.push(m);
            }
        }
        self.net = keep;
        // Random order among messages due at the same time: more reordering.
        for k in (1..due.len()).rev() {
            let j = self.rng.random_range(0..=k);
            due.swap(k, j);
        }
        for (_, from, to, body) in due {
            if !self.connected(&from, &to) {
                continue;
            }
            let i = self.ix(&to);
            if self.nodes[i].raft.is_none() {
                continue;
            }
            self.stats.delivered += 1;
            let out = self.handle(i, from, body);
            self.send(to, out);
            self.after(i);
        }
    }

    fn handle(&mut self, i: usize, from: Bytes32, body: RaftBody) -> Out {
        let now = self.now();
        if let RaftBody::RaftSnapshot(s) = body {
            let offer = self.nodes[i].raft.as_mut().unwrap().offer_snapshot(
                now,
                from,
                s.term,
                s.last_index,
            );
            return match offer {
                SnapshotOffer::Reply(out) => out,
                SnapshotOffer::Install => {
                    let data = s.data.clone().unwrap();
                    let sm: Sm = serde_json::from_slice(&data).unwrap();
                    assert_eq!(sm.applied, s.last_index, "snapshot index mismatch");
                    assert!(
                        sm.applied >= self.nodes[i].sm.applied,
                        "installing a snapshot that rolls the state machine back"
                    );
                    for (k, h) in sm.hashes.iter().enumerate() {
                        self.check_committed(k as u64 + 1, *h, "snapshot");
                    }
                    self.nodes[i].store.lock().snapshot = Some(data);
                    let m = sm.membership();
                    self.nodes[i].sm = sm;
                    self.stats.snapshots_installed += 1;
                    self.nodes[i].raft.as_mut().unwrap().install_snapshot(
                        s.last_index,
                        s.last_term,
                        m,
                    )
                }
            };
        }
        self.nodes[i].raft.as_mut().unwrap().handle(now, from, body)
    }

    fn check_committed(&mut self, idx: u64, h: u64, what: &str) {
        match self.committed.get(&idx) {
            Some(c) => assert_eq!(
                *c, h,
                "state machine safety violated at index {idx} ({what})"
            ),
            None => {
                self.committed.insert(idx, h);
            }
        }
    }

    /// Apply committed entries, compact, send snapshots, check invariants.
    fn after(&mut self, i: usize) {
        loop {
            let (idx, bytes, term) = {
                let n = &self.nodes[i];
                let r = n.raft.as_ref().unwrap();
                if n.sm.applied >= r.commit {
                    break;
                }
                let idx = n.sm.applied + 1;
                let e = r.entry(idx).unwrap_or_else(|| {
                    panic!("committed entry {idx} missing (snap {})", r.snap_index)
                });
                (idx, e.bytes.clone(), e.term)
            };
            let h = hash(&bytes);
            self.check_committed(idx, h, "apply");
            let n = &mut self.nodes[i];
            if let Some(c) = classify(&bytes) {
                let m = apply_change(&n.sm.membership(), &c);
                n.sm.set_membership(&m);
            }
            if let Some(v) = value_of(&bytes) {
                n.sm.values.push(v);
            }
            n.sm.applied = idx;
            n.sm.last_term = term;
            n.sm.hashes.push(h);
            let r = n.raft.as_ref().unwrap();
            assert_eq!(
                r.config_at(idx),
                Some(n.sm.membership()),
                "Raft's configuration differs from the state machine's at {idx}"
            );
        }
        // Compaction.
        let n = &mut self.nodes[i];
        let r = n.raft.as_mut().unwrap();
        if n.sm.applied >= r.snap_index + self.compact_every {
            n.store.lock().snapshot = Some(serde_json::to_vec(&n.sm).unwrap());
            r.compact(n.sm.applied);
            assert_eq!(r.snap_index, n.sm.applied);
        }
        // Snapshots for lagging followers.
        let mut out = Vec::new();
        let peers = r.needs_snapshot();
        if !peers.is_empty() {
            let data = n.store.lock().snapshot.clone();
            if let Some(d) = data {
                for p in peers {
                    r.mark_snapshot_sent(&p);
                    out.push((p, r.snapshot_msg(d.clone())));
                }
            }
        }
        let id = n.id;
        self.send(id, out);
        self.check_leader(i);
    }

    fn check_leader(&mut self, i: usize) {
        let (id, term, is_leader) = {
            let r = self.nodes[i].raft.as_ref().unwrap();
            (r.id, r.term, r.role == Role::Leader)
        };
        if !is_leader {
            return;
        }
        match self.leaders.get(&term) {
            Some(l) => assert_eq!(
                *l, id,
                "election safety violated: two leaders in term {term}"
            ),
            None => {
                self.leaders.insert(term, id);
                self.stats.elections += 1;
            }
        }
        if self.completeness_checked.insert((term, id)) {
            let r = self.nodes[i].raft.as_ref().unwrap();
            for (idx, h) in self.committed.range(r.snap_index + 1..) {
                let e = r.entry(*idx).unwrap_or_else(|| {
                    panic!(
                        "leader completeness: new leader of term {term} lacks committed entry {idx}"
                    )
                });
                assert_eq!(
                    hash(&e.bytes),
                    *h,
                    "leader completeness: wrong entry {idx} in leader of term {term}"
                );
            }
        }
    }

    fn check_log_matching(&self) {
        let live: Vec<&Raft> = self.nodes.iter().filter_map(|n| n.raft.as_ref()).collect();
        for a in 0..live.len() {
            for b in a + 1..live.len() {
                let (x, y) = (live[a], live[b]);
                let lo = x.snap_index.max(y.snap_index) + 1;
                let hi = x.last_index().min(y.last_index());
                let mut top = None;
                for idx in (lo..=hi).rev() {
                    if x.term_at(idx) == y.term_at(idx) {
                        top = Some(idx);
                        break;
                    }
                }
                if let Some(top) = top {
                    for idx in lo..=top {
                        assert_eq!(
                            x.entry(idx).map(|e| hash(&e.bytes)),
                            y.entry(idx).map(|e| hash(&e.bytes)),
                            "log matching violated at {idx} (match up to {top})"
                        );
                    }
                }
            }
        }
    }

    fn tick(&mut self) {
        let now = self.now();
        for i in 0..self.nodes.len() {
            let Some(r) = self.nodes[i].raft.as_mut() else {
                continue;
            };
            let id = r.id;
            let out = r.tick(now);
            self.send(id, out);
            self.after(i);
        }
    }

    fn leader(&self) -> Option<usize> {
        // The live leader with the highest term.
        self.nodes
            .iter()
            .enumerate()
            .filter_map(|(i, n)| {
                n.raft
                    .as_ref()
                    .filter(|r| r.role == Role::Leader)
                    .map(|r| (r.term, i))
            })
            .max()
            .map(|x| x.1)
    }

    fn propose_value(&mut self) -> Option<(u64, u64)> {
        let i = self.leader()?;
        let v = self.next_value;
        self.next_value += 1;
        let now = self.now();
        let r = self.nodes[i].raft.as_mut().unwrap();
        let e = value_entry(r.term, r.last_index() + 1, v);
        let (idx, out) = r.propose(now, &e).ok()?;
        let id = r.id;
        self.stats.proposed += 1;
        self.send(id, out);
        self.after(i);
        Some((v, idx))
    }

    /// A single-server membership change, like the admin operations.
    fn propose_conf(&mut self, max_voters: usize) {
        let Some(i) = self.leader() else { return };
        let all: Vec<Bytes32> = self.nodes.iter().map(|n| n.id).collect();
        let cur = self.nodes[i].raft.as_ref().unwrap().config().clone();
        let mut options: Vec<Membership> = Vec::new();
        for id in &all {
            let mut m = cur.clone();
            if cur.voters.contains(id) {
                if cur.voters.len() > 1 {
                    m.voters.remove(id);
                    m.learners.insert(*id);
                    options.push(m);
                }
            } else if cur.learners.contains(id) {
                let mut rm = cur.clone();
                rm.learners.remove(id);
                options.push(rm);
                if cur.voters.len() < max_voters {
                    m.learners.remove(id);
                    m.voters.insert(*id);
                    options.push(m);
                }
            } else {
                m.learners.insert(*id);
                options.push(m);
            }
        }
        if options.is_empty() {
            return;
        }
        let m = options[self.rng.random_range(0..options.len())].clone();
        let now = self.now();
        let r = self.nodes[i].raft.as_mut().unwrap();
        let e = conf_entry(r.term, r.last_index() + 1, &m);
        if let Ok((_, out)) = r.propose(now, &e) {
            let id = r.id;
            self.stats.conf_changes += 1;
            self.send(id, out);
            self.after(i);
        }
    }

    /// Advance virtual time by `ms`, one millisecond at a time.
    fn run(&mut self, ms: u64, faults: Option<&Faults>, propose_every: u64) {
        let end = self.t + ms;
        while self.t < end {
            self.t += 1;
            self.deliver();
            if self.t.is_multiple_of(10) {
                self.tick();
            }
            if propose_every > 0 && self.t.is_multiple_of(propose_every) {
                self.propose_value();
            }
            if let Some(f) = faults {
                self.faults(f);
            }
            if self.t.is_multiple_of(100) {
                self.check_log_matching();
            }
        }
    }

    fn faults(&mut self, f: &Faults) {
        let n = self.nodes.len();
        if self.rng.random_bool(f.crash) {
            let i = self.rng.random_range(0..n);
            if self.nodes[i].raft.is_some() {
                self.crash(i);
            }
        }
        if self.rng.random_bool(f.restart) {
            let down: Vec<usize> = (0..n).filter(|i| self.nodes[*i].raft.is_none()).collect();
            if !down.is_empty() {
                let i = down[self.rng.random_range(0..down.len())];
                self.start(i);
            }
        }
        if self.rng.random_bool(f.partition) {
            if self.group.is_some() {
                self.group = None;
            } else {
                self.group = Some((0..n).map(|_| self.rng.random_range(0..2u8)).collect());
                self.stats.partitions += 1;
            }
        }
        if f.conf > 0.0 && self.rng.random_bool(f.conf) {
            self.propose_conf(f.max_voters);
        }
    }

    /// Stop faults, heal, restart everything, and require progress: a
    /// leader, and new entries applied by every member of the configuration.
    fn settle_and_check_liveness(&mut self) {
        self.group = None;
        self.drop_p = 0.0;
        self.dup_p = 0.0;
        for i in 0..self.nodes.len() {
            if self.nodes[i].raft.is_none() {
                self.start(i);
            }
        }
        let mut waited = 0;
        while self.leader().is_none() {
            self.run(100, None, 0);
            waited += 100;
            assert!(
                waited < 30_000,
                "no leader 30 s after healing: {:?}",
                self.roles()
            );
        }
        let mut last = None;
        let mut tries = 0;
        while last.is_none() {
            last = self.propose_value();
            self.run(50, None, 0);
            tries += 1;
            assert!(tries < 400, "could not propose after healing");
        }
        let (mut v, _) = last.unwrap();
        let mut waited = 0;
        let mut since_propose = 0;
        loop {
            self.run(100, None, 0);
            waited += 100;
            since_propose += 100;
            let Some(li) = self.leader() else { continue };
            let cfg = self.nodes[li].raft.as_ref().unwrap().config().clone();
            let done = self
                .nodes
                .iter()
                .filter(|n| cfg.voters.contains(&n.id) || cfg.learners.contains(&n.id))
                .all(|n| n.sm.values.contains(&v));
            if done {
                break;
            }
            assert!(
                waited < 120_000,
                "entries don't commit after healing: {:?}",
                self.roles()
            );
            // A value proposed to a leader that was then deposed is lost
            // (legitimately); propose a fresh one and wait for that instead.
            if since_propose >= 5_000
                && let Some((nv, _)) = self.propose_value()
            {
                v = nv;
                since_propose = 0;
            }
        }
        self.check_log_matching();
        // Every member applied the same sequence.
        let li = self.leader().unwrap();
        let cfg = self.nodes[li].raft.as_ref().unwrap().config().clone();
        for n in self.nodes.iter().filter(|n| cfg.voters.contains(&n.id)) {
            for (k, h) in n.sm.hashes.iter().enumerate() {
                assert_eq!(self.committed.get(&(k as u64 + 1)), Some(h));
            }
        }
    }

    fn roles(&self) -> Vec<String> {
        self.nodes
            .iter()
            .map(|n| match &n.raft {
                None => format!("{}:down", n.id[0]),
                Some(r) => format!(
                    "{}:{:?}/t{}/c{}/l{}/v{}",
                    n.id[0],
                    r.role,
                    r.term,
                    r.commit,
                    r.last_index(),
                    r.voters().len()
                ),
            })
            .collect()
    }
}

struct Faults {
    crash: f64,
    restart: f64,
    partition: f64,
    conf: f64,
    max_voters: usize,
}

fn seeds(default: u64) -> u64 {
    std::env::var("WEBJET_RAFT_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------- scenarios

#[test]
fn single_node_elects_itself_and_commits() {
    let mut s = Sim::new(1, 1, members(&[1], &[]));
    s.run(1000, None, 0);
    assert!(s.leader().is_some());
    for _ in 0..10 {
        s.propose_value().unwrap();
    }
    s.run(10, None, 0);
    assert_eq!(s.nodes[0].sm.values, (1..=10).collect::<Vec<_>>());
}

#[test]
fn three_nodes_replicate() {
    let mut s = Sim::new(2, 3, members(&[1, 2, 3], &[]));
    s.run(2000, None, 0);
    let l = s.leader().expect("leader");
    for _ in 0..100 {
        s.propose_value();
    }
    s.run(1000, None, 0);
    for n in &s.nodes {
        assert_eq!(
            n.sm.values.len(),
            100,
            "node {} applied {}",
            n.id[0],
            n.sm.values.len()
        );
    }
    // Stable leadership without faults.
    assert_eq!(s.leader(), Some(l));
    assert_eq!(s.stats.elections, 1);
}

#[test]
fn commit_never_regresses_on_stale_append() {
    let (st, _) = Storage::mem();
    let now = Instant::now();
    let mut r = Raft::new(
        nid(2),
        st,
        0,
        0,
        members(&[1, 2, 3], &[]),
        Box::new(classify),
        T,
        now,
        Some(1),
    )
    .unwrap();
    let entries: Vec<wp::Blob> = (1..=10)
        .map(|i| wp::Blob {
            data: Some(value_entry(1, i, i).encode_bytes()),
        })
        .collect();
    let a = wp::RaftAppend {
        term: 1,
        prev_log_index: 0,
        prev_log_term: 0,
        entries: Some(entries),
        leader_commit: 10,
    };
    r.handle(now, nid(1), RaftBody::RaftAppend(Box::new(a)));
    assert_eq!(r.commit, 10);
    // A delayed heartbeat that only proves the log up to 5.
    let hb = wp::RaftAppend {
        term: 1,
        prev_log_index: 5,
        prev_log_term: 1,
        entries: Some(vec![]),
        leader_commit: 12,
    };
    r.handle(now, nid(1), RaftBody::RaftAppend(Box::new(hb)));
    assert_eq!(r.commit, 10, "commit index went backwards");
}

#[test]
fn heartbeat_does_not_commit_unproven_suffix() {
    // The follower holds entries 1..=6 from an old term; the leader's heartbeat
    // proves only up to 3, so entries 4..=6 must not be committed.
    let (st, _) = Storage::mem();
    let now = Instant::now();
    let mut r = Raft::new(
        nid(2),
        st,
        0,
        0,
        members(&[1, 2, 3], &[]),
        Box::new(classify),
        T,
        now,
        Some(1),
    )
    .unwrap();
    let entries: Vec<wp::Blob> = (1..=6)
        .map(|i| wp::Blob {
            data: Some(value_entry(1, i, i).encode_bytes()),
        })
        .collect();
    r.handle(
        now,
        nid(3),
        RaftBody::RaftAppend(Box::new(wp::RaftAppend {
            term: 1,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: Some(entries),
            leader_commit: 0,
        })),
    );
    r.handle(
        now,
        nid(1),
        RaftBody::RaftAppend(Box::new(wp::RaftAppend {
            term: 2,
            prev_log_index: 3,
            prev_log_term: 1,
            entries: Some(vec![]),
            leader_commit: 9,
        })),
    );
    assert_eq!(r.commit, 3);
}

#[test]
fn conflicting_suffix_is_replaced_and_config_reverted() {
    let (st, mem) = Storage::mem();
    let now = Instant::now();
    let mut r = Raft::new(
        nid(2),
        st,
        0,
        0,
        members(&[1, 2, 3], &[]),
        Box::new(classify),
        T,
        now,
        Some(1),
    )
    .unwrap();
    // Old leader (term 1) appended a value and an uncommitted config change.
    let old = vec![
        wp::Blob {
            data: Some(value_entry(1, 1, 1).encode_bytes()),
        },
        wp::Blob {
            data: Some(conf_entry(1, 2, &members(&[1, 2, 3], &[4])).encode_bytes()),
        },
    ];
    r.handle(
        now,
        nid(1),
        RaftBody::RaftAppend(Box::new(wp::RaftAppend {
            term: 1,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: Some(old),
            leader_commit: 1,
        })),
    );
    assert!(
        r.learners().contains(&nid(4)),
        "configuration takes effect on append"
    );
    // New leader (term 2) overwrites index 2.
    let new = vec![wp::Blob {
        data: Some(value_entry(2, 2, 99).encode_bytes()),
    }];
    let out = r.handle(
        now,
        nid(3),
        RaftBody::RaftAppend(Box::new(wp::RaftAppend {
            term: 2,
            prev_log_index: 1,
            prev_log_term: 1,
            entries: Some(new),
            leader_commit: 2,
        })),
    );
    assert!(
        matches!(&out[0].1, RaftBody::RaftAppendResponse(a) if a.success && a.match_index == 2)
    );
    assert!(
        r.learners().is_empty(),
        "configuration reverted with the truncated entry"
    );
    assert_eq!(value_of(&r.entry(2).unwrap().bytes), Some(99));
    // The rewrite is durable.
    assert_eq!(mem.lock().log.len(), 2);
}

#[test]
fn committed_entries_are_never_overwritten() {
    let (st, _) = Storage::mem();
    let now = Instant::now();
    let mut r = Raft::new(
        nid(2),
        st,
        0,
        0,
        members(&[1, 2, 3], &[]),
        Box::new(classify),
        T,
        now,
        Some(1),
    )
    .unwrap();
    let e = vec![wp::Blob {
        data: Some(value_entry(1, 1, 1).encode_bytes()),
    }];
    r.handle(
        now,
        nid(1),
        RaftBody::RaftAppend(Box::new(wp::RaftAppend {
            term: 1,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: Some(e),
            leader_commit: 1,
        })),
    );
    let bad = vec![wp::Blob {
        data: Some(value_entry(2, 1, 7).encode_bytes()),
    }];
    let out = r.handle(
        now,
        nid(3),
        RaftBody::RaftAppend(Box::new(wp::RaftAppend {
            term: 2,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: Some(bad),
            leader_commit: 1,
        })),
    );
    assert!(matches!(&out[0].1, RaftBody::RaftAppendResponse(a) if !a.success));
    assert_eq!(value_of(&r.entry(1).unwrap().bytes), Some(1));
}

#[test]
fn stale_snapshot_is_not_installed() {
    let (st, _) = Storage::mem();
    let now = Instant::now();
    let mut r = Raft::new(
        nid(2),
        st,
        0,
        0,
        members(&[1, 2, 3], &[]),
        Box::new(classify),
        T,
        now,
        Some(1),
    )
    .unwrap();
    let entries: Vec<wp::Blob> = (1..=20)
        .map(|i| wp::Blob {
            data: Some(value_entry(1, i, i).encode_bytes()),
        })
        .collect();
    r.handle(
        now,
        nid(1),
        RaftBody::RaftAppend(Box::new(wp::RaftAppend {
            term: 1,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: Some(entries),
            leader_commit: 20,
        })),
    );
    match r.offer_snapshot(now, nid(1), 1, 10) {
        SnapshotOffer::Reply(out) => {
            assert!(matches!(&out[0].1, RaftBody::RaftSnapshotResponse(s) if s.last_index == 20))
        }
        SnapshotOffer::Install => {
            panic!("a snapshot behind the commit index must not be installed")
        }
    }
}

#[test]
fn snapshot_keeps_matching_suffix() {
    let (st, _) = Storage::mem();
    let now = Instant::now();
    let mut r = Raft::new(
        nid(2),
        st,
        0,
        0,
        members(&[1, 2, 3], &[]),
        Box::new(classify),
        T,
        now,
        Some(1),
    )
    .unwrap();
    let entries: Vec<wp::Blob> = (1..=20)
        .map(|i| wp::Blob {
            data: Some(value_entry(1, i, i).encode_bytes()),
        })
        .collect();
    r.handle(
        now,
        nid(1),
        RaftBody::RaftAppend(Box::new(wp::RaftAppend {
            term: 1,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: Some(entries),
            leader_commit: 5,
        })),
    );
    assert!(matches!(
        r.offer_snapshot(now, nid(1), 1, 15),
        SnapshotOffer::Install
    ));
    r.install_snapshot(15, 1, members(&[1, 2, 3], &[]));
    assert_eq!(r.snap_index, 15);
    assert_eq!(
        r.last_index(),
        20,
        "entries after a matching snapshot point are kept"
    );
    // A snapshot whose term at that index differs discards the log.
    let (st, _) = Storage::mem();
    let mut r = Raft::new(
        nid(2),
        st,
        0,
        0,
        members(&[1, 2, 3], &[]),
        Box::new(classify),
        T,
        now,
        Some(1),
    )
    .unwrap();
    let entries: Vec<wp::Blob> = (1..=20)
        .map(|i| wp::Blob {
            data: Some(value_entry(1, i, i).encode_bytes()),
        })
        .collect();
    r.handle(
        now,
        nid(1),
        RaftBody::RaftAppend(Box::new(wp::RaftAppend {
            term: 1,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: Some(entries),
            leader_commit: 5,
        })),
    );
    r.install_snapshot(15, 3, members(&[1, 2, 3], &[]));
    assert_eq!(r.last_index(), 15);
}

#[test]
fn restart_recovers_term_vote_log_and_config_from_storage() {
    let (st, mem) = Storage::mem();
    let now = Instant::now();
    let mut r = Raft::new(
        nid(2),
        st.clone(),
        0,
        0,
        members(&[1, 2, 3], &[]),
        Box::new(classify),
        T,
        now,
        Some(1),
    )
    .unwrap();
    // Vote in term 4.
    let out = r.handle(
        now,
        nid(3),
        RaftBody::RaftVote(Box::new(wp::RaftVote {
            term: 4,
            last_log_index: 0,
            last_log_term: 0,
            pre_vote: false,
        })),
    );
    assert!(matches!(&out[0].1, RaftBody::RaftVoteResponse(v) if v.granted));
    let e = vec![
        wp::Blob {
            data: Some(value_entry(4, 1, 1).encode_bytes()),
        },
        wp::Blob {
            data: Some(conf_entry(4, 2, &members(&[1, 2, 3, 4], &[])).encode_bytes()),
        },
    ];
    r.handle(
        now,
        nid(3),
        RaftBody::RaftAppend(Box::new(wp::RaftAppend {
            term: 4,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: Some(e),
            leader_commit: 0,
        })),
    );
    drop(r);
    let r2 = Raft::new(
        nid(2),
        Storage::Mem(mem.clone()),
        0,
        0,
        members(&[1, 2, 3], &[]),
        Box::new(classify),
        T,
        now,
        Some(2),
    )
    .unwrap();
    assert_eq!(r2.term, 4);
    assert_eq!(r2.voted_for, Some(nid(3)));
    assert_eq!(r2.last_index(), 2);
    assert_eq!(
        r2.voters().len(),
        4,
        "uncommitted configuration in the log is in force after a restart"
    );
    assert_eq!(r2.commit, 0);
    // It won't vote for someone else in term 4.
    let mut r2 = r2;
    let out = r2.handle(
        now,
        nid(1),
        RaftBody::RaftVote(Box::new(wp::RaftVote {
            term: 4,
            last_log_index: 9,
            last_log_term: 4,
            pre_vote: false,
        })),
    );
    assert!(matches!(&out[0].1, RaftBody::RaftVoteResponse(v) if !v.granted));
}

#[test]
fn disk_storage_roundtrip() {
    let dir = std::env::temp_dir().join(format!("webjet-raft-{}", rand::random::<u64>()));
    let st = Storage::disk(dir.clone()).unwrap();
    st.save_meta(7, Some(nid(3)));
    let e: Vec<Entry> = (1..=5)
        .map(|i| Entry {
            term: 7,
            index: i,
            bytes: value_entry(7, i, i).encode_bytes(),
        })
        .collect();
    st.append(&e[..3]);
    st.append(&e[3..]);
    assert_eq!(st.load_log().len(), 5);
    st.rewrite(&e[..2]);
    let r = Raft::new(
        nid(1),
        Storage::disk(dir.clone()).unwrap(),
        0,
        0,
        members(&[1], &[]),
        Box::new(classify),
        T,
        Instant::now(),
        Some(1),
    )
    .unwrap();
    assert_eq!((r.term, r.voted_for, r.last_index()), (7, Some(nid(3)), 2));
    // A torn final record (crash mid-append) is ignored.
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(dir.join("log.bin"))
        .unwrap()
        .write_all(&[0, 0, 1, 0, 1, 2])
        .unwrap();
    assert_eq!(st.load_log().len(), 2);
    // Entries appended after a restart over the torn tail survive the next
    // restart: opening the log drops the torn bytes before appending.
    let r = Raft::new(
        nid(1),
        Storage::disk(dir.clone()).unwrap(),
        0,
        0,
        members(&[1], &[]),
        Box::new(classify),
        T,
        Instant::now(),
        Some(1),
    )
    .unwrap();
    r.storage.append(&e[2..]);
    assert_eq!(st.load_log().len(), 5);
    st.save_snapshot(b"snap").unwrap();
    assert_eq!(st.load_snapshot().as_deref(), Some(&b"snap"[..]));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn prevote_keeps_a_partitioned_follower_from_disrupting() {
    let mut s = Sim::new(3, 3, members(&[1, 2, 3], &[]));
    s.run(2000, None, 0);
    let l = s.leader().unwrap();
    let term = s.nodes[l].raft.as_ref().unwrap().term;
    let victim = (l + 1) % 3;
    let mut g = vec![0u8; 3];
    g[victim] = 1;
    s.group = Some(g);
    s.run(10_000, None, 20);
    let vt = s.nodes[victim].raft.as_ref().unwrap();
    assert_eq!(
        vt.term, term,
        "an isolated follower must not raise its term (pre-vote)"
    );
    s.group = None;
    s.run(3000, None, 20);
    assert_eq!(s.leader(), Some(l), "rejoining must not depose the leader");
    assert_eq!(s.nodes[l].raft.as_ref().unwrap().term, term);
    // Proposals stopped: the newest commit index reaches the follower with
    // the next heartbeat, so let it settle before comparing.
    s.run(1000, None, 0);
    assert_eq!(s.leader(), Some(l));
    assert_eq!(s.nodes[victim].sm.values.len(), s.nodes[l].sm.values.len());
}

#[test]
fn isolated_leader_steps_down_and_majority_elects() {
    let mut s = Sim::new(4, 5, members(&[1, 2, 3, 4, 5], &[]));
    s.run(2000, None, 0);
    let l = s.leader().unwrap();
    let mut g = vec![0u8; 5];
    g[l] = 1;
    s.group = Some(g);
    s.run(T.election_max.as_millis() as u64 * 3, None, 0);
    assert_ne!(
        s.nodes[l].raft.as_ref().unwrap().role,
        Role::Leader,
        "check-quorum must depose an isolated leader"
    );
    let nl = s.leader().unwrap();
    assert_ne!(nl, l);
    // Writes on the majority side commit.
    for _ in 0..5 {
        s.propose_value();
    }
    s.run(1000, None, 0);
    assert_eq!(s.nodes[nl].sm.values.len(), 5);
    // The old leader catches up after healing.
    s.group = None;
    s.run(3000, None, 0);
    assert_eq!(s.nodes[l].sm.values.len(), 5);
}

#[test]
fn proposals_to_minority_leader_never_commit() {
    let mut s = Sim::new(5, 3, members(&[1, 2, 3], &[]));
    s.run(2000, None, 0);
    let l = s.leader().unwrap();
    let mut g = vec![0u8; 3];
    g[l] = 1;
    s.group = Some(g);
    // Proposals on the cut-off leader before it notices.
    let before = s.nodes[l].raft.as_ref().unwrap().commit;
    for _ in 0..5 {
        s.propose_value();
    }
    s.run(100, None, 0);
    assert_eq!(s.nodes[l].raft.as_ref().unwrap().commit, before);
    s.run(5000, None, 0);
    s.group = None;
    s.settle_and_check_liveness();
}

#[test]
fn lagging_follower_catches_up_by_snapshot() {
    let mut s = Sim::new(6, 3, members(&[1, 2, 3], &[]));
    s.compact_every = 20;
    s.run(2000, None, 0);
    let l = s.leader().unwrap();
    let lag = (l + 1) % 3;
    s.crash(lag);
    for _ in 0..200 {
        s.propose_value();
        s.run(5, None, 0);
    }
    s.run(500, None, 0);
    assert!(s.nodes[l].raft.as_ref().unwrap().snap_index > 100);
    s.start(lag);
    s.run(3000, None, 0);
    assert!(
        s.stats.snapshots_installed >= 1,
        "the lagging follower should have received a snapshot"
    );
    assert_eq!(s.nodes[lag].sm.values.len(), 200);
}

#[test]
fn conf_change_waits_for_previous_and_for_own_term_commit() {
    let mut s = Sim::new(7, 4, members(&[1, 2, 3], &[]));
    s.run(2000, None, 0);
    let l = s.leader().unwrap();
    let now = s.now();
    let r = s.nodes[l].raft.as_mut().unwrap();
    let e1 = conf_entry(r.term, r.last_index() + 1, &members(&[1, 2, 3], &[4]));
    r.propose(now, &e1).unwrap();
    let e2 = conf_entry(r.term, r.last_index() + 1, &members(&[1, 2, 3, 4], &[]));
    assert_eq!(
        r.propose(now, &e2).err(),
        Some(ProposeError::ConfChangePending)
    );
    s.run(500, None, 0);
    let now = s.now();
    let r = s.nodes[l].raft.as_mut().unwrap();
    let e2 = conf_entry(r.term, r.last_index() + 1, &members(&[1, 2, 3, 4], &[]));
    r.propose(now, &e2).unwrap();
    s.run(1000, None, 0);
    assert_eq!(
        s.nodes[3].raft.as_ref().unwrap().role,
        Role::Follower,
        "the promoted learner is a voter now"
    );
    assert_eq!(s.nodes[l].raft.as_ref().unwrap().voters().len(), 4);
}

#[test]
fn learner_joins_votes_only_after_promotion() {
    let mut s = Sim::new(8, 4, members(&[1, 2, 3], &[]));
    s.run(2000, None, 0);
    for _ in 0..30 {
        s.propose_value();
    }
    s.run(500, None, 0);
    assert_eq!(s.nodes[3].sm.values.len(), 0, "a non-member gets nothing");
    let l = s.leader().unwrap();
    let now = s.now();
    let r = s.nodes[l].raft.as_mut().unwrap();
    let e = conf_entry(r.term, r.last_index() + 1, &members(&[1, 2, 3], &[4]));
    let (_, out) = r.propose(now, &e).unwrap();
    s.send(nid(l as u8 + 1), out);
    s.run(1500, None, 0);
    assert_eq!(s.nodes[3].raft.as_ref().unwrap().role, Role::Learner);
    assert_eq!(
        s.nodes[3].sm.values.len(),
        30,
        "the learner replicates the log"
    );
    // With two voters down, the learner can't help elect anyone.
    let others: Vec<usize> = (0..3).filter(|i| *i != l).collect();
    s.crash(others[0]);
    s.crash(l);
    s.run(5000, None, 0);
    assert!(s.leader().is_none());
    assert_eq!(
        s.nodes[3].raft.as_ref().unwrap().term,
        s.nodes[others[1]]
            .raft
            .as_ref()
            .unwrap()
            .term
            .min(s.nodes[3].raft.as_ref().unwrap().term)
    );
}

#[test]
fn leader_removing_itself_hands_over() {
    let mut s = Sim::new(9, 3, members(&[1, 2, 3], &[]));
    s.run(2000, None, 0);
    let l = s.leader().unwrap();
    let lid = nid(l as u8 + 1);
    let mut m = members(&[1, 2, 3], &[]);
    m.voters.remove(&lid);
    m.learners.insert(lid);
    let now = s.now();
    let r = s.nodes[l].raft.as_mut().unwrap();
    let e = conf_entry(r.term, r.last_index() + 1, &m);
    let (_, out) = r.propose(now, &e).unwrap();
    s.send(lid, out);
    s.run(3000, None, 0);
    assert_eq!(s.nodes[l].raft.as_ref().unwrap().role, Role::Learner);
    let nl = s.leader().expect("a new leader among the remaining voters");
    assert_ne!(nl, l);
    for _ in 0..10 {
        s.propose_value();
    }
    s.run(1000, None, 0);
    assert_eq!(
        s.nodes[l].sm.values.len(),
        10,
        "the demoted node still replicates as a learner"
    );
}

#[test]
fn removed_voter_does_not_disrupt() {
    // Node 3 is removed while partitioned, so it never learns about it.
    let mut s = Sim::new(10, 3, members(&[1, 2, 3], &[]));
    s.run(2000, None, 0);
    let l = s.leader().unwrap();
    if l == 2 {
        return; // this seed picked node 3 as leader; covered by other seeds
    }
    s.group = Some(vec![0, 0, 1]);
    let now = s.now();
    let r = s.nodes[l].raft.as_mut().unwrap();
    let e = conf_entry(r.term, r.last_index() + 1, &members(&[1, 2], &[]));
    let (_, out) = r.propose(now, &e).unwrap();
    s.send(nid(l as u8 + 1), out);
    s.run(2000, None, 0);
    let term = s.nodes[l].raft.as_ref().unwrap().term;
    s.group = None;
    s.run(10_000, None, 50);
    assert_eq!(
        s.leader(),
        Some(l),
        "a removed server must not depose the leader"
    );
    assert_eq!(s.nodes[l].raft.as_ref().unwrap().term, term);
}

// ---------------------------------------------------------------- randomized

fn randomized(seed: u64, n: u8, faults: Faults, ms: u64, lossy: bool) {
    if std::env::var("WEBJET_RAFT_TRACE").is_ok() {
        eprintln!("== seed {seed}");
    }
    let initial: Vec<u8> = (1..=n.min(3)).collect();
    let mut s = Sim::new(seed, n, members(&initial, &[]));
    if lossy {
        s.drop_p = 0.05;
        s.dup_p = 0.05;
        s.max_delay = 40;
    }
    s.compact_every = 30;
    s.run(ms, Some(&faults), 15);
    s.settle_and_check_liveness();
    assert!(s.stats.elections >= 1);
    if std::env::var("WEBJET_RAFT_STATS").is_ok() {
        eprintln!("seed {seed}: {:?} committed={}", s.stats, s.committed.len());
    }
}

#[test]
fn randomized_crashes_and_partitions() {
    for seed in 0..seeds(12) {
        randomized(
            1000 + seed,
            5,
            Faults {
                crash: 0.0005,
                restart: 0.002,
                partition: 0.0005,
                conf: 0.0,
                max_voters: 5,
            },
            20_000,
            false,
        );
    }
}

#[test]
fn randomized_lossy_network() {
    for seed in 0..seeds(12) {
        randomized(
            2000 + seed,
            5,
            Faults {
                crash: 0.0003,
                restart: 0.002,
                partition: 0.0003,
                conf: 0.0,
                max_voters: 5,
            },
            20_000,
            true,
        );
    }
}

#[test]
fn randomized_membership_changes() {
    for seed in 0..seeds(12) {
        randomized(
            3000 + seed,
            6,
            Faults {
                crash: 0.0003,
                restart: 0.002,
                partition: 0.0003,
                conf: 0.002,
                max_voters: 5,
            },
            25_000,
            true,
        );
    }
}

#[test]
fn randomized_heavy_churn() {
    for seed in 0..seeds(6) {
        randomized(
            4000 + seed,
            7,
            Faults {
                crash: 0.002,
                restart: 0.004,
                partition: 0.001,
                conf: 0.003,
                max_voters: 7,
            },
            25_000,
            true,
        );
    }
}

#[test]
fn deposed_leader_with_uncommitted_self_demotion_can_finish_it() {
    // Two voters. The leader appends its own demotion, is cut off before the
    // other voter sees it, and steps down. Its log is now the longest, and in
    // its latest configuration it is no longer a voter. The other voter can't
    // win without its vote, so the deposed leader must be able to campaign
    // (it is still a voter of the committed configuration).
    let mut s = Sim::new(11, 2, members(&[1, 2], &[]));
    s.run(2000, None, 0);
    let l = s.leader().unwrap();
    let other = 1 - l;
    for _ in 0..5 {
        s.propose_value();
    }
    s.run(500, None, 0);
    let mut g = vec![0u8; 2];
    g[l] = 1;
    s.group = Some(g);
    let lid = nid(l as u8 + 1);
    let mut m = members(&[1, 2], &[]);
    m.voters.remove(&lid);
    m.learners.insert(lid);
    let now = s.now();
    let r = s.nodes[l].raft.as_mut().unwrap();
    let e = conf_entry(r.term, r.last_index() + 1, &m);
    r.propose(now, &e).unwrap();
    for _ in 0..3 {
        s.propose_value();
    }
    s.run(T.election_max.as_millis() as u64 * 3, None, 0);
    assert_ne!(
        s.nodes[l].raft.as_ref().unwrap().role,
        Role::Leader,
        "check-quorum deposes the cut-off leader"
    );
    s.group = None;
    s.settle_and_check_liveness();
    // The demotion finished: only the other node is a voter now.
    let nl = s.leader().unwrap();
    assert_eq!(nl, other);
    assert_eq!(
        s.nodes[nl].raft.as_ref().unwrap().voters(),
        &BTreeSet::from([nid(other as u8 + 1)])
    );
}

/// A node whose storage already holds `log` (term, value) entries and `term`.
fn preloaded(id: u8, term: u64, log: &[(u64, u64)], voters: &[u8]) -> Raft {
    let (st, mem) = Storage::mem();
    {
        let mut m = mem.lock();
        m.term = term;
        m.log = log
            .iter()
            .enumerate()
            .map(|(i, (t, v))| value_entry(*t, i as u64 + 1, *v).encode_bytes())
            .collect();
    }
    Raft::new(
        nid(id),
        st,
        0,
        0,
        members(voters, &[]),
        Box::new(classify),
        T,
        Instant::now(),
        Some(id as u64),
    )
    .unwrap()
}

/// Drive `r` (a voter of 1..=5) to leadership with votes from `from`.
fn elect(r: &mut Raft, from: &[u8]) -> Instant {
    let mut now = Instant::now() + T.election_max * 2;
    r.tick(now);
    assert_eq!(r.role, Role::PreCandidate);
    let pre_term = r.term + 1;
    for f in from {
        r.handle(
            now,
            nid(*f),
            RaftBody::RaftVoteResponse(Box::new(wp::RaftVoteResponse {
                term: pre_term,
                granted: true,
                pre_vote: true,
            })),
        );
    }
    assert_eq!(r.role, Role::Candidate);
    for f in from {
        r.handle(
            now,
            nid(*f),
            RaftBody::RaftVoteResponse(Box::new(wp::RaftVoteResponse {
                term: r.term,
                granted: true,
                pre_vote: false,
            })),
        );
    }
    assert_eq!(r.role, Role::Leader);
    now += Duration::from_millis(1);
    now
}

#[test]
fn figure8_old_term_entry_is_not_committed_by_counting() {
    // Raft paper, Figure 8 (c): S1 leads again in term 4 with an entry from
    // term 2 at index 2 that is now on a majority. It must not be committed
    // by counting replicas, since S5 (term 3 entry at index 2) could still
    // win an election and overwrite it. Only an entry of the leader's own
    // term commits, and with it everything before.
    let mut s1 = preloaded(1, 3, &[(1, 1), (2, 2)], &[1, 2, 3, 4, 5]);
    let now = elect(&mut s1, &[2, 3]);
    assert_eq!(s1.term, 4);
    assert_eq!(s1.last_index(), 3, "the new leader appended its no-op");
    let before = s1.commit;
    for f in [2, 3] {
        s1.handle(
            now,
            nid(f),
            RaftBody::RaftAppendResponse(Box::new(wp::RaftAppendResponse {
                term: 4,
                success: true,
                match_index: 2,
                hint_index: 0,
            })),
        );
    }
    assert_eq!(
        s1.commit, before,
        "an old-term entry was committed by counting replicas"
    );
    // The term-4 no-op on a majority commits it, and index 2 with it.
    for f in [2, 3] {
        s1.handle(
            now,
            nid(f),
            RaftBody::RaftAppendResponse(Box::new(wp::RaftAppendResponse {
                term: 4,
                success: true,
                match_index: 3,
                hint_index: 0,
            })),
        );
    }
    assert_eq!(s1.commit, 3);
}

#[test]
fn votes_require_an_up_to_date_log() {
    let mut f = preloaded(2, 1, &[(1, 1), (1, 2), (1, 3)], &[1, 2, 3]);
    let now = Instant::now();
    // Shorter log, same last term: refused.
    let out = f.handle(
        now,
        nid(3),
        RaftBody::RaftVote(Box::new(wp::RaftVote {
            term: 2,
            last_log_index: 2,
            last_log_term: 1,
            pre_vote: false,
        })),
    );
    assert!(
        matches!(&out[0].1, RaftBody::RaftVoteResponse(v) if !v.granted),
        "voted for a candidate with a shorter log"
    );
    // Longer log but an older last term: refused.
    let out = f.handle(
        now,
        nid(3),
        RaftBody::RaftVote(Box::new(wp::RaftVote {
            term: 3,
            last_log_index: 9,
            last_log_term: 0,
            pre_vote: false,
        })),
    );
    assert!(
        matches!(&out[0].1, RaftBody::RaftVoteResponse(v) if !v.granted),
        "voted for a candidate with an older last term"
    );
    // The same rules apply to pre-votes.
    let out = f.handle(
        now,
        nid(3),
        RaftBody::RaftVote(Box::new(wp::RaftVote {
            term: 4,
            last_log_index: 2,
            last_log_term: 1,
            pre_vote: true,
        })),
    );
    assert!(matches!(&out[0].1, RaftBody::RaftVoteResponse(v) if !v.granted));
    // An up-to-date candidate gets the vote.
    let out = f.handle(
        now,
        nid(1),
        RaftBody::RaftVote(Box::new(wp::RaftVote {
            term: 4,
            last_log_index: 3,
            last_log_term: 1,
            pre_vote: false,
        })),
    );
    assert!(matches!(&out[0].1, RaftBody::RaftVoteResponse(v) if v.granted));
}
