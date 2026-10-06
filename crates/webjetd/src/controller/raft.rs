//! A compact Raft (§7.1): voters and learners, pre-vote, check-quorum and
//! leader leases, randomized election timeouts, log replication with fast
//! backtracking, snapshots for lagging members and log compaction.
//!
//! Membership follows the Raft dissertation: a server uses the **latest
//! configuration in its log**, committed or not, and only one change may be
//! uncommitted at a time (single-server changes). Configurations come from
//! the entries themselves through a classifier, so a restarted server knows
//! its configuration before anything is re-applied.
//!
//! The core is deterministic: time is passed in (`now`), randomness comes
//! from a seedable RNG, and storage can live in memory. `raft_tests.rs`
//! drives it through a simulated network with crashes, partitions, loss,
//! duplication and reordering.
//!
//! The log holds encoded `LogEntry` FlatBuffers; their `term` and `index`
//! fields are authoritative.

use anyhow::{Context, Result};
use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use webjet_core::crypto::{self, Bytes32, opt_k32};
use webjet_core::statemachine::Membership;
use webjet_proto::{self as wp, Decodable, Encodable, RaftBody};

pub const COMPACT_EVERY: u64 = 2000;
const MAX_BATCH: usize = 64;

#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub heartbeat: Duration,
    pub election_min: Duration,
    pub election_max: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            heartbeat: Duration::from_millis(500),
            election_min: Duration::from_millis(3000),
            election_max: Duration::from_millis(6000),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Role {
    Follower,
    PreCandidate,
    Candidate,
    Leader,
    Learner,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub term: u64,
    pub index: u64,
    pub bytes: Vec<u8>,
}

/// A membership change carried by a log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfChange {
    Set(Membership),
    AddLearner(Bytes32),
    Promote(Bytes32),
    Demote(Bytes32),
    Remove(Bytes32),
}

/// Apply a change exactly like the state machine does.
pub fn apply_change(m: &Membership, c: &ConfChange) -> Membership {
    let mut m = m.clone();
    match c {
        ConfChange::Set(x) => return x.clone(),
        ConfChange::AddLearner(id) => {
            m.learners.insert(*id);
        }
        ConfChange::Promote(id) => {
            m.learners.remove(id);
            m.voters.insert(*id);
        }
        ConfChange::Demote(id) => {
            m.voters.remove(id);
            m.learners.insert(*id);
        }
        ConfChange::Remove(id) => {
            m.voters.remove(id);
            m.learners.remove(id);
        }
    }
    m
}

/// Finds the membership change in an encoded entry, if any.
pub type Classifier = Box<dyn Fn(&[u8]) -> Option<ConfChange> + Send>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposeError {
    NotLeader,
    /// The entry's term/index don't continue this leader's log.
    Stale,
    /// A membership change while another is uncommitted, or before the
    /// leader has committed an entry of its own term.
    ConfChangePending,
    /// Writing to durable storage failed; this node has stopped.
    Storage,
}

impl std::fmt::Display for ProposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ProposeError::NotLeader => "not the leader",
            ProposeError::Stale => "entry does not continue the log",
            ProposeError::ConfChangePending => "another membership change is still in progress",
            ProposeError::Storage => "Raft storage failed; this controller has stopped",
        })
    }
}

impl std::error::Error for ProposeError {}

// ---------------------------------------------------------------- storage

#[derive(Default, Serialize, Deserialize)]
struct Meta {
    term: u64,
    voted_for: Option<String>,
}

/// In-memory storage, shared across "restarts" in tests.
#[derive(Default, Debug)]
pub struct MemStore {
    pub term: u64,
    pub vote: Option<Bytes32>,
    pub log: Vec<Vec<u8>>,
    pub snapshot: Option<Vec<u8>>,
    /// Tests: every write fails (a full or broken disk).
    pub fail_writes: bool,
}

impl MemStore {
    fn check(&self) -> Result<()> {
        if self.fail_writes {
            anyhow::bail!("simulated disk failure");
        }
        Ok(())
    }
}

/// Durable Raft state: term and vote, the log, and the snapshot. On disk:
/// meta.json, an append-only log.bin and snapshot.wj, all fsynced.
#[derive(Clone)]
pub enum Storage {
    Disk(PathBuf),
    Mem(Arc<Mutex<MemStore>>),
}

fn encode_entries(entries: &[Entry]) -> Vec<u8> {
    let mut buf = Vec::new();
    for e in entries {
        buf.extend_from_slice(&(e.bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&e.bytes);
    }
    buf
}

fn decode_entry(bytes: Vec<u8>) -> Option<Entry> {
    let e = wp::LogEntry::decode_bytes(&bytes).ok()?;
    Some(Entry {
        term: e.term,
        index: e.index,
        bytes,
    })
}

impl Storage {
    pub fn disk(dir: PathBuf) -> Result<Storage> {
        std::fs::create_dir_all(&dir)?;
        Ok(Storage::Disk(dir))
    }

    pub fn mem() -> (Storage, Arc<Mutex<MemStore>>) {
        let m = Arc::new(Mutex::new(MemStore::default()));
        (Storage::Mem(m.clone()), m)
    }

    fn save_meta(&self, term: u64, vote: Option<Bytes32>) -> Result<()> {
        match self {
            Storage::Disk(d) => {
                let m = Meta {
                    term,
                    voted_for: vote.map(hex::encode),
                };
                crate::state::save_json(&d.join("meta.json"), &m).context("saving Raft term/vote")
            }
            Storage::Mem(m) => {
                let mut m = m.lock();
                m.check()?;
                m.term = term;
                m.vote = vote;
                Ok(())
            }
        }
    }

    /// Term and vote. Only a missing file means a fresh start; a damaged
    /// one is an error, since guessing could vote twice in one term.
    fn load_meta(&self) -> Result<(u64, Option<Bytes32>)> {
        match self {
            Storage::Disk(d) => {
                let path = d.join("meta.json");
                let Some(m) = crate::state::load_json::<Meta>(&path)? else {
                    return Ok((0, None));
                };
                let vote = match m.voted_for {
                    None => None,
                    Some(s) => Some(
                        crypto::parse_hex32(&s)
                            .ok_or_else(|| anyhow::anyhow!("{}: bad voted_for", path.display()))?,
                    ),
                };
                Ok((m.term, vote))
            }
            Storage::Mem(m) => {
                let m = m.lock();
                Ok((m.term, m.vote))
            }
        }
    }

    fn append(&self, entries: &[Entry]) -> Result<()> {
        match self {
            Storage::Disk(d) => {
                let buf = encode_entries(entries);
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(d.join("log.bin"))
                    .and_then(|mut f| {
                        f.write_all(&buf)?;
                        f.sync_data()
                    })
                    .context("appending to the Raft log")
            }
            Storage::Mem(m) => {
                let mut m = m.lock();
                m.check()?;
                m.log.extend(entries.iter().map(|e| e.bytes.clone()));
                Ok(())
            }
        }
    }

    fn rewrite(&self, entries: &[Entry]) -> Result<()> {
        match self {
            Storage::Disk(d) => {
                crate::state::write_private(&d.join("log.bin"), &encode_entries(entries))
                    .context("rewriting the Raft log")
            }
            Storage::Mem(m) => {
                let mut m = m.lock();
                m.check()?;
                m.log = entries.iter().map(|e| e.bytes.clone()).collect();
                Ok(())
            }
        }
    }

    /// Read the log. A torn tail (a crash mid-append: a short record, or
    /// records that don't decode with nothing valid after them) is cut off
    /// the file, so entries appended after the restart don't land behind
    /// it, where the next load would never reach them. A bad record with
    /// valid ones after it is damage, not a torn append: an error.
    fn load_log(&self) -> Result<Vec<Entry>> {
        match self {
            Storage::Disk(d) => {
                let path = d.join("log.bin");
                let b = match std::fs::read(&path) {
                    Ok(b) => b,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                    Err(e) => return Err(e).context("reading the Raft log"),
                };
                let mut out = Vec::new();
                let mut i = 0;
                // Where the first undecodable record starts.
                let mut bad: Option<usize> = None;
                while let Some(len) = webjet_core::bytes::be_u32(&b, i) {
                    let Some(end) = (i + 4).checked_add(len as usize).filter(|&e| e <= b.len())
                    else {
                        break;
                    };
                    match decode_entry(b[i + 4..end].to_vec()) {
                        Some(e) => {
                            if let Some(at) = bad {
                                anyhow::bail!(
                                    "{}: damaged record at byte {at} before valid ones",
                                    path.display()
                                );
                            }
                            out.push(e);
                        }
                        None => {
                            bad.get_or_insert(i);
                        }
                    }
                    i = end;
                }
                let keep = bad.unwrap_or(i);
                if keep < b.len() {
                    tracing::warn!("raft log: torn tail of {} bytes dropped", b.len() - keep);
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .and_then(|f| {
                            f.set_len(keep as u64)?;
                            f.sync_data()
                        })
                        .context("truncating the Raft log")?;
                }
                Ok(out)
            }
            Storage::Mem(m) => Ok(m
                .lock()
                .log
                .iter()
                .filter_map(|b| decode_entry(b.clone()))
                .collect()),
        }
    }

    pub fn save_snapshot(&self, data: &[u8]) -> Result<()> {
        match self {
            Storage::Disk(d) => crate::state::write_private(&d.join("snapshot.wj"), data),
            Storage::Mem(m) => {
                let mut m = m.lock();
                m.check()?;
                m.snapshot = Some(data.to_vec());
                Ok(())
            }
        }
    }

    /// Drop the whole log (a new snapshot replaces it, offline recovery).
    pub fn clear_log(&self) -> Result<()> {
        match self {
            Storage::Disk(d) => crate::state::write_private(&d.join("log.bin"), &[]),
            Storage::Mem(m) => {
                let mut m = m.lock();
                m.check()?;
                m.log.clear();
                Ok(())
            }
        }
    }

    pub fn load_snapshot(&self) -> Option<Vec<u8>> {
        match self {
            Storage::Disk(d) => std::fs::read(d.join("snapshot.wj")).ok(),
            Storage::Mem(m) => m.lock().snapshot.clone(),
        }
    }
}

/// The run of entries that continues the snapshot. A later append after a
/// rewrite can only extend; an index going back means the tail was replaced.
/// An index jumping forward means entries are missing: the log is damaged.
fn contiguous(log: Vec<Entry>, snap_index: u64) -> Result<Vec<Entry>> {
    let mut expect = snap_index + 1;
    let mut out: Vec<Entry> = Vec::new();
    for e in log {
        if e.index <= snap_index {
            continue;
        }
        if e.index == expect {
            expect += 1;
            out.push(e);
        } else if e.index < expect {
            out.truncate((e.index - snap_index - 1) as usize);
            expect = e.index + 1;
            out.push(e);
        } else {
            anyhow::bail!(
                "Raft log has a gap: entry {} follows {}",
                e.index,
                expect - 1
            );
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- the node

pub struct Raft {
    pub id: Bytes32,
    pub term: u64,
    pub voted_for: Option<Bytes32>,
    pub role: Role,
    pub leader: Option<Bytes32>,
    /// Entries after the snapshot.
    log: Vec<Entry>,
    pub snap_index: u64,
    pub snap_term: u64,
    pub commit: u64,
    /// Configurations by the index of the entry that introduced them; the
    /// first one is the configuration at `snap_index`.
    configs: Vec<(u64, Membership)>,
    next_index: HashMap<Bytes32, u64>,
    match_index: HashMap<Bytes32, u64>,
    last_sent: HashMap<Bytes32, Instant>,
    last_ack: HashMap<Bytes32, Instant>,
    votes: HashSet<Bytes32>,
    election_deadline: Instant,
    last_leader_contact: Option<Instant>,
    leader_since: Instant,
    now: Instant,
    timing: Timing,
    rng: StdRng,
    storage: Storage,
    classify: Classifier,
    /// Set when a write to durable storage failed. From then on this node
    /// sends nothing and accepts nothing (fail-stop): a vote, an append
    /// acknowledgement or a commit counted on our own entry could all be
    /// forgotten by a restart, which breaks Raft's safety.
    failed: Option<String>,
}

pub type Out = Vec<(Bytes32, RaftBody)>;

pub enum SnapshotOffer {
    /// Restore the state machine from the snapshot, then call `install_snapshot`.
    Install,
    /// Nothing to install; send this reply.
    Reply(Out),
}

impl Raft {
    /// Open a node. `base` is the membership at `snap_index` (from the
    /// snapshot, or the initial configuration).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Bytes32,
        storage: Storage,
        snap_index: u64,
        snap_term: u64,
        base: Membership,
        classify: Classifier,
        timing: Timing,
        now: Instant,
        seed: Option<u64>,
    ) -> Result<Raft> {
        let (term, voted_for) = storage.load_meta()?;
        let log = contiguous(storage.load_log()?, snap_index)?;
        let rng = match seed {
            Some(s) => StdRng::seed_from_u64(s),
            None => rand::make_rng(),
        };
        let mut r = Raft {
            id,
            term,
            voted_for,
            role: Role::Follower,
            leader: None,
            log: Vec::new(),
            snap_index,
            snap_term,
            commit: snap_index,
            configs: vec![(snap_index, base)],
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            last_sent: HashMap::new(),
            last_ack: HashMap::new(),
            votes: HashSet::new(),
            election_deadline: now,
            last_leader_contact: None,
            leader_since: now,
            now,
            timing,
            rng,
            storage,
            classify,
            failed: None,
        };
        for e in log {
            r.push_entry(e);
        }
        r.update_role();
        r.reset_deadline();
        Ok(r)
    }

    /// Open with on-disk storage in `dir`, production timing.
    pub fn open(
        id: Bytes32,
        dir: PathBuf,
        snap_index: u64,
        snap_term: u64,
        base: Membership,
        classify: Classifier,
    ) -> Result<Raft> {
        let storage = Storage::disk(dir).context("raft storage")?;
        Raft::new(
            id,
            storage,
            snap_index,
            snap_term,
            base,
            classify,
            Timing::default(),
            Instant::now(),
            None,
        )
    }

    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    /// Why this node stopped, if a write to its storage failed.
    pub fn failed(&self) -> Option<&str> {
        self.failed.as_deref()
    }

    /// Record the result of a storage write: false, and this node stops for
    /// good (fail-stop), when it failed.
    fn persisted(&mut self, r: Result<()>) -> bool {
        match r {
            Ok(()) => self.failed.is_none(),
            Err(e) => {
                tracing::error!("Raft storage failed, this controller stops: {e:#}");
                self.failed.get_or_insert_with(|| format!("{e:#}"));
                false
            }
        }
    }

    // ------------------------------------------------------------ log access

    pub fn last_index(&self) -> u64 {
        self.log.last().map_or(self.snap_index, |e| e.index)
    }

    pub fn last_term(&self) -> u64 {
        self.log.last().map_or(self.snap_term, |e| e.term)
    }

    pub fn term_at(&self, idx: u64) -> Option<u64> {
        if idx == self.snap_index {
            return Some(self.snap_term);
        }
        if idx < self.snap_index {
            return None;
        }
        self.log
            .get((idx - self.snap_index - 1) as usize)
            .map(|e| e.term)
    }

    pub fn entry(&self, idx: u64) -> Option<&Entry> {
        if idx <= self.snap_index {
            return None;
        }
        self.log.get((idx - self.snap_index - 1) as usize)
    }

    /// Append an entry while the controller is stopped (`webjetctl local
    /// controller force-new-cluster` / `restore`, ops guide 4.1). It starts
    /// a new term, `term`, in which this server votes for itself, so no
    /// earlier leader's entries at that index can win against it.
    pub fn append_offline(&mut self, term: u64, bytes: Vec<u8>) -> Result<u64> {
        let e = decode_entry(bytes).context("undecodable entry")?;
        if e.index != self.last_index() + 1 {
            anyhow::bail!(
                "entry {} does not continue the log at {}",
                e.index,
                self.last_index()
            );
        }
        if e.term != term || term <= self.term.max(self.last_term()) {
            anyhow::bail!("an offline entry needs a new term");
        }
        self.storage.save_meta(term, Some(self.id))?;
        self.storage.append(std::slice::from_ref(&e))?;
        self.term = term;
        self.voted_for = Some(self.id);
        let idx = e.index;
        self.push_entry(e);
        self.update_role();
        Ok(idx)
    }

    fn push_entry(&mut self, e: Entry) {
        if let Some(c) = (self.classify)(&e.bytes) {
            let next = apply_change(self.config(), &c);
            self.configs.push((e.index, next));
        }
        self.log.push(e);
    }

    /// Drop entries from `idx` on (conflict resolution).
    fn truncate_from(&mut self, idx: u64) {
        self.log.truncate((idx - self.snap_index - 1) as usize);
        self.configs.retain(|(i, _)| *i < idx);
    }

    // ------------------------------------------------------------ membership

    /// The configuration in force: the latest one in the log.
    pub fn config(&self) -> &Membership {
        static NONE: Membership = Membership {
            voters: BTreeSet::new(),
            learners: BTreeSet::new(),
        };
        // There is always at least the base configuration.
        self.configs.last().map_or(&NONE, |c| &c.1)
    }

    pub fn voters(&self) -> &BTreeSet<Bytes32> {
        &self.config().voters
    }

    pub fn learners(&self) -> &BTreeSet<Bytes32> {
        &self.config().learners
    }

    /// The configuration in force after entry `idx`.
    pub fn config_at(&self, idx: u64) -> Option<Membership> {
        if idx < self.configs[0].0 {
            return None;
        }
        self.configs
            .iter()
            .rev()
            .find(|(i, _)| *i <= idx)
            .map(|(_, m)| m.clone())
    }

    /// Index of the entry that introduced the current configuration.
    pub fn config_index(&self) -> u64 {
        self.configs.last().map_or(0, |c| c.0)
    }

    /// A membership change is in the log but not yet committed in this
    /// leader's term, so another one would be refused (`propose`).
    pub fn conf_change_pending(&self) -> bool {
        self.config_index() > self.commit || self.term_at(self.commit) != Some(self.term)
    }

    /// Leader: how long `peer` has been silent — since its last answer, or
    /// since this node became leader when it hasn't answered yet. `None`
    /// when this node isn't the leader.
    pub fn silent_for(&self, peer: &Bytes32) -> Option<Duration> {
        if self.role != Role::Leader {
            return None;
        }
        if *peer == self.id {
            return Some(Duration::ZERO);
        }
        let since = self
            .last_ack
            .get(peer)
            .copied()
            .unwrap_or(self.leader_since)
            .max(self.leader_since);
        Some(self.now.saturating_duration_since(since))
    }

    /// Leader: how long this node has been leader.
    pub fn leader_for(&self) -> Option<Duration> {
        (self.role == Role::Leader).then(|| self.now.saturating_duration_since(self.leader_since))
    }

    /// Leader: the highest log index known to be replicated on `peer`.
    pub fn match_of(&self, peer: &Bytes32) -> u64 {
        if *peer == self.id {
            return self.last_index();
        }
        self.match_index.get(peer).copied().unwrap_or(0)
    }

    pub fn is_voter(&self) -> bool {
        self.voters().contains(&self.id)
    }

    /// May this server start an election? A voter of its latest
    /// configuration, or of the last committed one: a leader that appended
    /// its own demotion and then lost leadership may hold the only complete
    /// log, and must be able to finish the change (votes are still counted
    /// against the latest configuration).
    pub fn can_campaign(&self) -> bool {
        self.is_voter()
            || self
                .config_at(self.commit)
                .is_some_and(|c| c.voters.contains(&self.id))
    }

    /// Votes received that count in the latest configuration.
    fn counted_votes(&self) -> usize {
        self.votes
            .iter()
            .filter(|v| self.voters().contains(*v))
            .count()
    }

    fn quorum(&self) -> usize {
        self.voters().len() / 2 + 1
    }

    fn peers(&self) -> Vec<Bytes32> {
        let c = self.config();
        c.voters
            .iter()
            .chain(c.learners.iter())
            .filter(|p| **p != self.id)
            .copied()
            .collect()
    }

    fn update_role(&mut self) {
        match self.role {
            Role::Leader => {} // handled after the change commits
            Role::Learner if self.is_voter() => {
                self.role = Role::Follower;
                self.reset_deadline();
            }
            Role::Follower if !self.is_voter() => {
                self.role = Role::Learner;
            }
            Role::PreCandidate | Role::Candidate if !self.can_campaign() => {
                self.role = Role::Learner;
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------ role changes

    fn reset_deadline(&mut self) {
        let lo = self.timing.election_min.as_millis() as u64;
        let hi = self.timing.election_max.as_millis() as u64;
        self.election_deadline = self.now + Duration::from_millis(self.rng.random_range(lo..=hi));
    }

    fn in_lease(&self) -> bool {
        self.role == Role::Leader
            || (self.leader.is_some()
                && self
                    .last_leader_contact
                    .is_some_and(|t| self.now.duration_since(t) < self.timing.election_min))
    }

    fn become_follower(&mut self, term: u64, leader: Option<Bytes32>) {
        if term > self.term {
            self.term = term;
            self.voted_for = None;
            let r = self.storage.save_meta(self.term, self.voted_for);
            self.persisted(r);
            self.leader = None;
            self.last_leader_contact = None;
        }
        self.role = if self.is_voter() {
            Role::Follower
        } else {
            Role::Learner
        };
        if let Some(l) = leader {
            self.leader = Some(l);
            self.last_leader_contact = Some(self.now);
        }
        self.votes.clear();
        self.reset_deadline();
    }

    fn step_down(&mut self) {
        self.role = if self.is_voter() {
            Role::Follower
        } else {
            Role::Learner
        };
        self.leader = None;
        self.last_leader_contact = None;
        self.reset_deadline();
    }

    fn become_leader(&mut self) -> Out {
        self.role = Role::Leader;
        self.leader = Some(self.id);
        self.leader_since = self.now;
        self.last_ack.clear();
        self.last_sent.clear();
        let next = self.last_index() + 1;
        self.next_index = self.peers().into_iter().map(|p| (p, next)).collect();
        self.match_index = self.peers().into_iter().map(|p| (p, 0)).collect();
        tracing::info!(term = self.term, "became Raft leader");
        // A no-op in the new term lets earlier entries commit (Raft §5.4.2).
        let noop = wp::LogEntry {
            term: self.term,
            index: next,
            timestamp: webjet_core::types::now_ms(),
            payload: Some(wp::EntryPayload::NoopEntry(Box::new(wp::NoopEntry {
                term: self.term,
            }))),
            random: None,
            leaves: Some(Vec::new()),
        };
        if !self.append_local(noop.encode_bytes(), self.term, next) {
            return Vec::new();
        }
        self.broadcast(true)
    }

    fn start_prevote(&mut self) -> Out {
        if !self.can_campaign() {
            self.reset_deadline();
            return Vec::new();
        }
        self.role = Role::PreCandidate;
        self.leader = None;
        self.last_leader_contact = None;
        self.votes = HashSet::from([self.id]);
        self.reset_deadline();
        if self.counted_votes() >= self.quorum() {
            return self.start_election();
        }
        let msg = RaftBody::RaftVote(Box::new(wp::RaftVote {
            term: self.term + 1,
            last_log_index: self.last_index(),
            last_log_term: self.last_term(),
            pre_vote: true,
        }));
        self.voters()
            .iter()
            .filter(|v| **v != self.id)
            .map(|v| (*v, msg.clone()))
            .collect()
    }

    fn start_election(&mut self) -> Out {
        self.term += 1;
        self.role = Role::Candidate;
        self.voted_for = Some(self.id);
        let r = self.storage.save_meta(self.term, self.voted_for);
        if !self.persisted(r) {
            return Vec::new();
        }
        self.votes = HashSet::from([self.id]);
        self.leader = None;
        self.reset_deadline();
        if self.counted_votes() >= self.quorum() {
            return self.become_leader();
        }
        let msg = RaftBody::RaftVote(Box::new(wp::RaftVote {
            term: self.term,
            last_log_index: self.last_index(),
            last_log_term: self.last_term(),
            pre_vote: false,
        }));
        self.voters()
            .iter()
            .filter(|v| **v != self.id)
            .map(|v| (*v, msg.clone()))
            .collect()
    }

    // ------------------------------------------------------------ leader side

    /// Append our own entry; false (and nothing appended) when it couldn't
    /// be made durable, since it would then count towards a commit.
    fn append_local(&mut self, bytes: Vec<u8>, term: u64, index: u64) -> bool {
        let e = Entry { term, index, bytes };
        let r = self.storage.append(std::slice::from_ref(&e));
        if !self.persisted(r) {
            return false;
        }
        self.push_entry(e);
        self.advance_commit();
        true
    }

    /// Leader: append a fully prepared entry (its term and index must
    /// continue this leader's log). Returns the index and messages to send.
    pub fn propose(
        &mut self,
        now: Instant,
        entry: &wp::LogEntry,
    ) -> std::result::Result<(u64, Out), ProposeError> {
        self.now = now;
        if self.failed.is_some() {
            return Err(ProposeError::Storage);
        }
        if self.role != Role::Leader {
            return Err(ProposeError::NotLeader);
        }
        if entry.term != self.term || entry.index != self.last_index() + 1 {
            return Err(ProposeError::Stale);
        }
        let bytes = entry.encode_bytes();
        if (self.classify)(&bytes).is_some()
            && (self.config_index() > self.commit || self.term_at(self.commit) != Some(self.term))
        {
            return Err(ProposeError::ConfChangePending);
        }
        let idx = entry.index;
        if !self.append_local(bytes, self.term, idx) {
            return Err(ProposeError::Storage);
        }
        Ok((idx, self.broadcast(true)))
    }

    fn append_msg(&self, peer: &Bytes32) -> Option<RaftBody> {
        let next = *self.next_index.get(peer)?;
        if next <= self.snap_index {
            return None; // needs a snapshot
        }
        let prev = next - 1;
        let prev_term = self.term_at(prev)?;
        let entries: Vec<wp::Blob> = (next..=self.last_index())
            .take(MAX_BATCH)
            .filter_map(|i| self.entry(i))
            .map(|e| wp::Blob {
                data: Some(e.bytes.clone()),
            })
            .collect();
        Some(RaftBody::RaftAppend(Box::new(wp::RaftAppend {
            term: self.term,
            prev_log_index: prev,
            prev_log_term: prev_term,
            entries: Some(entries),
            leader_commit: self.commit,
        })))
    }

    /// Peers that need a snapshot (the caller builds and sends it).
    pub fn needs_snapshot(&self) -> Vec<Bytes32> {
        if self.role != Role::Leader {
            return Vec::new();
        }
        self.next_index
            .iter()
            .filter(|(_, n)| **n <= self.snap_index)
            .map(|(p, _)| *p)
            .collect()
    }

    fn broadcast(&mut self, force: bool) -> Out {
        let mut out = Vec::new();
        let now = self.now;
        for p in self.peers() {
            let due = force
                || self
                    .last_sent
                    .get(&p)
                    .is_none_or(|t| now.duration_since(*t) >= self.timing.heartbeat);
            if !due {
                continue;
            }
            if let Some(m) = self.append_msg(&p) {
                out.push((p, m));
                self.last_sent.insert(p, now);
            }
        }
        out
    }

    fn advance_commit(&mut self) {
        if self.role != Role::Leader {
            return;
        }
        let mut idx = self.last_index();
        while idx > self.commit {
            if self.term_at(idx) != Some(self.term) {
                break; // only entries of the current term commit by counting
            }
            let count = self
                .voters()
                .iter()
                .filter(|v| **v == self.id || self.match_index.get(*v).copied().unwrap_or(0) >= idx)
                .count();
            if count >= self.quorum() {
                self.commit = idx;
                break;
            }
            idx -= 1;
        }
        // A leader that is no longer a voter hands over once that change commits.
        if !self.is_voter() && self.commit >= self.config_index() {
            tracing::info!("stepping down: this controller is no longer a voter");
            self.step_down();
        }
    }

    pub fn tick(&mut self, now: Instant) -> Out {
        self.now = now;
        if self.failed.is_some() {
            return Vec::new();
        }
        let out = self.tick_inner(now);
        if self.failed.is_some() {
            return Vec::new();
        }
        out
    }

    fn tick_inner(&mut self, now: Instant) -> Out {
        match self.role {
            Role::Leader => {
                let next = self.last_index() + 1;
                let peers = self.peers();
                for p in &peers {
                    self.next_index.entry(*p).or_insert(next);
                    self.match_index.entry(*p).or_insert(0);
                }
                self.next_index.retain(|p, _| peers.contains(p));
                self.match_index.retain(|p, _| peers.contains(p));
                // Check quorum: a leader cut off from a majority steps down.
                if now.duration_since(self.leader_since) >= self.timing.election_max {
                    let live = self
                        .voters()
                        .iter()
                        .filter(|v| {
                            **v == self.id
                                || self.last_ack.get(*v).is_some_and(|t| {
                                    now.duration_since(*t) < self.timing.election_max
                                })
                        })
                        .count();
                    if live < self.quorum() {
                        tracing::warn!(
                            term = self.term,
                            "Raft leader lost contact with a majority; stepping down"
                        );
                        self.step_down();
                        return Vec::new();
                    }
                }
                self.advance_commit();
                if self.role != Role::Leader {
                    return Vec::new();
                }
                self.broadcast(false)
            }
            Role::Learner if !self.can_campaign() => Vec::new(),
            _ => {
                if now >= self.election_deadline {
                    self.start_prevote()
                } else {
                    Vec::new()
                }
            }
        }
    }

    // ------------------------------------------------------------ messages

    /// Handle a Raft message (snapshots go through `offer_snapshot`).
    /// After a storage failure nothing is answered: a reply could promise
    /// a vote or entries this node can't keep.
    pub fn handle(&mut self, now: Instant, from: Bytes32, body: RaftBody) -> Out {
        self.now = now;
        if self.failed.is_some() {
            return Vec::new();
        }
        let out = self.handle_inner(now, from, body);
        if self.failed.is_some() {
            return Vec::new();
        }
        out
    }

    fn handle_inner(&mut self, now: Instant, from: Bytes32, body: RaftBody) -> Out {
        let mut out = Vec::new();
        match body {
            RaftBody::RaftVote(v) => {
                let up_to_date =
                    (v.last_log_term, v.last_log_index) >= (self.last_term(), self.last_index());
                if v.pre_vote {
                    // Pre-vote (dissertation §9.6): no state changes here.
                    let grant = v.term > self.term && up_to_date && !self.in_lease();
                    let term = if grant { v.term } else { self.term };
                    out.push((
                        from,
                        RaftBody::RaftVoteResponse(Box::new(wp::RaftVoteResponse {
                            term,
                            granted: grant,
                            pre_vote: true,
                        })),
                    ));
                    return out;
                }
                if v.term > self.term {
                    if self.in_lease() {
                        // A live leader exists: ignore disruptive candidates (§4.2.3).
                        out.push((
                            from,
                            RaftBody::RaftVoteResponse(Box::new(wp::RaftVoteResponse {
                                term: self.term,
                                granted: false,
                                pre_vote: false,
                            })),
                        ));
                        return out;
                    }
                    self.become_follower(v.term, None);
                }
                let grant = v.term == self.term
                    && up_to_date
                    && (self.voted_for.is_none() || self.voted_for == Some(from))
                    && self.role != Role::Leader;
                if grant {
                    self.voted_for = Some(from);
                    let r = self.storage.save_meta(self.term, self.voted_for);
                    if !self.persisted(r) {
                        return out;
                    }
                    self.reset_deadline();
                }
                out.push((
                    from,
                    RaftBody::RaftVoteResponse(Box::new(wp::RaftVoteResponse {
                        term: self.term,
                        granted: grant,
                        pre_vote: false,
                    })),
                ));
            }
            RaftBody::RaftVoteResponse(r) => {
                if r.pre_vote {
                    if self.role != Role::PreCandidate {
                        return out;
                    }
                    if r.granted && r.term == self.term + 1 {
                        self.votes.insert(from);
                        let n = self.counted_votes();
                        if n >= self.quorum() {
                            out.extend(self.start_election());
                        }
                    } else if !r.granted && r.term > self.term {
                        self.become_follower(r.term, None);
                    }
                    return out;
                }
                if r.term > self.term {
                    self.become_follower(r.term, None);
                } else if self.role == Role::Candidate && r.term == self.term && r.granted {
                    self.votes.insert(from);
                    let n = self.counted_votes();
                    if n >= self.quorum() {
                        out.extend(self.become_leader());
                    }
                }
            }
            RaftBody::RaftAppend(a) => {
                if a.term < self.term {
                    out.push((
                        from,
                        RaftBody::RaftAppendResponse(Box::new(wp::RaftAppendResponse {
                            term: self.term,
                            success: false,
                            match_index: 0,
                            hint_index: self.last_index() + 1,
                        })),
                    ));
                    return out;
                }
                self.become_follower(a.term, Some(from));
                let resp = self.accept_append(&a);
                out.push((from, RaftBody::RaftAppendResponse(Box::new(resp))));
            }
            RaftBody::RaftAppendResponse(r) => {
                if r.term > self.term {
                    self.become_follower(r.term, None);
                    return out;
                }
                if self.role != Role::Leader || r.term != self.term {
                    return out;
                }
                self.last_ack.insert(from, now);
                let matched = self.match_index.get(&from).copied().unwrap_or(0);
                if r.success {
                    let m = matched.max(r.match_index).min(self.last_index());
                    self.match_index.insert(from, m);
                    self.next_index.insert(from, m + 1);
                    self.advance_commit();
                    if self.role == Role::Leader
                        && m < self.last_index()
                        && let Some(msg) = self.append_msg(&from)
                    {
                        self.last_sent.insert(from, now);
                        out.push((from, msg));
                    }
                } else {
                    let next = r.hint_index.max(matched + 1).min(self.last_index() + 1);
                    self.next_index.insert(from, next);
                    if let Some(msg) = self.append_msg(&from) {
                        self.last_sent.insert(from, now);
                        out.push((from, msg));
                    }
                }
            }
            RaftBody::RaftSnapshotResponse(r) => {
                if r.term > self.term {
                    self.become_follower(r.term, None);
                } else if self.role == Role::Leader && r.term == self.term {
                    self.last_ack.insert(from, now);
                    let m = self
                        .match_index
                        .get(&from)
                        .copied()
                        .unwrap_or(0)
                        .max(r.last_index)
                        .min(self.last_index());
                    self.match_index.insert(from, m);
                    self.next_index.insert(from, m + 1);
                    self.advance_commit();
                }
            }
            RaftBody::RaftTimeoutNow(t)
                if t.term == self.term && self.can_campaign() && self.role != Role::Leader =>
            {
                out.extend(self.start_election());
            }
            _ => {}
        }
        out
    }

    fn accept_append(&mut self, a: &wp::RaftAppend) -> wp::RaftAppendResponse {
        let term = self.term;
        let fail = |hint: u64| wp::RaftAppendResponse {
            term,
            success: false,
            match_index: 0,
            hint_index: hint,
        };
        if a.prev_log_index > self.last_index() {
            return fail(self.last_index() + 1);
        }
        if a.prev_log_index >= self.snap_index {
            match self.term_at(a.prev_log_index) {
                Some(t) if t == a.prev_log_term => {}
                Some(t) => {
                    // Skip back over the whole conflicting term.
                    let mut i = a.prev_log_index;
                    while i > self.snap_index + 1 && self.term_at(i - 1) == Some(t) {
                        i -= 1;
                    }
                    return fail(i.max(self.commit + 1));
                }
                None => return fail(self.snap_index + 1),
            }
        }
        let mut idx = a.prev_log_index;
        let mut appended = Vec::new();
        let mut truncated = false;
        for b in a.entries.clone().unwrap_or_default() {
            let bytes = b.data.unwrap_or_default();
            let Some(e) = decode_entry(bytes) else {
                return fail(idx + 1);
            };
            idx += 1;
            if e.index != idx {
                return fail(idx);
            }
            if idx <= self.snap_index {
                continue; // covered by our snapshot
            }
            match self.term_at(idx) {
                Some(t) if t == e.term => continue,
                Some(_) => {
                    if idx <= self.commit {
                        tracing::error!("leader tried to overwrite committed entry {idx}");
                        return fail(self.commit + 1);
                    }
                    self.truncate_from(idx);
                    truncated = true;
                }
                None => {}
            }
            appended.push(e.clone());
            self.push_entry(e);
        }
        let r = if truncated {
            self.storage.rewrite(&self.log)
        } else if !appended.is_empty() {
            self.storage.append(&appended)
        } else {
            Ok(())
        };
        if !self.persisted(r) {
            // Not durable: acknowledge nothing (the caller sends nothing).
            return fail(self.last_index() + 1);
        }
        // Commit never goes backwards, and only up to what this append proved.
        if a.leader_commit > self.commit {
            self.commit = self.commit.max(a.leader_commit.min(idx));
        }
        self.update_role();
        wp::RaftAppendResponse {
            term: self.term,
            success: true,
            match_index: idx,
            hint_index: 0,
        }
    }

    // ------------------------------------------------------------ snapshots

    /// A snapshot arrived from `from`. Decides whether to install it.
    pub fn offer_snapshot(
        &mut self,
        now: Instant,
        from: Bytes32,
        term: u64,
        last_index: u64,
    ) -> SnapshotOffer {
        self.now = now;
        if self.failed.is_some() {
            return SnapshotOffer::Reply(Vec::new());
        }
        if term < self.term {
            return SnapshotOffer::Reply(vec![(
                from,
                RaftBody::RaftSnapshotResponse(Box::new(wp::RaftSnapshotResponse {
                    term: self.term,
                    last_index: 0,
                })),
            )]);
        }
        self.become_follower(term, Some(from));
        if last_index <= self.commit {
            // Already have everything it contains: never roll back.
            return SnapshotOffer::Reply(vec![(
                from,
                RaftBody::RaftSnapshotResponse(Box::new(wp::RaftSnapshotResponse {
                    term: self.term,
                    last_index: self.commit,
                })),
            )]);
        }
        SnapshotOffer::Install
    }

    /// The caller restored its state machine from the snapshot.
    pub fn install_snapshot(
        &mut self,
        last_index: u64,
        last_term: u64,
        members: Membership,
    ) -> Out {
        let keep = self.term_at(last_index) == Some(last_term);
        if keep {
            self.log.retain(|e| e.index > last_index);
            self.configs.retain(|(i, _)| *i > last_index);
        } else {
            self.log.clear();
            self.configs.clear();
        }
        self.configs.insert(0, (last_index, members));
        self.snap_index = last_index;
        self.snap_term = last_term;
        self.commit = self.commit.max(last_index);
        let r = self.storage.rewrite(&self.log);
        if !self.persisted(r) {
            return Vec::new();
        }
        self.update_role();
        match self.leader {
            Some(l) => vec![(
                l,
                RaftBody::RaftSnapshotResponse(Box::new(wp::RaftSnapshotResponse {
                    term: self.term,
                    last_index,
                })),
            )],
            None => Vec::new(),
        }
    }

    /// Drop entries up to `index` (the caller saved a snapshot of it).
    pub fn compact(&mut self, index: u64) {
        if index <= self.snap_index || index > self.commit {
            return;
        }
        let Some(term) = self.term_at(index) else {
            return;
        };
        let Some(base) = self.config_at(index) else {
            return;
        };
        self.log.retain(|e| e.index > index);
        self.configs.retain(|(i, _)| *i > index);
        self.configs.insert(0, (index, base));
        self.snap_index = index;
        self.snap_term = term;
        let r = self.storage.rewrite(&self.log);
        self.persisted(r);
    }

    pub fn snapshot_msg(&self, data: Vec<u8>) -> RaftBody {
        RaftBody::RaftSnapshot(Box::new(wp::RaftSnapshot {
            term: self.term,
            last_index: self.snap_index,
            last_term: self.snap_term,
            data: Some(data),
        }))
    }

    pub fn mark_snapshot_sent(&mut self, peer: &Bytes32) {
        // Optimistic, so it isn't resent every tick; a rejection corrects it.
        self.next_index.insert(*peer, self.snap_index + 1);
        self.last_sent.insert(*peer, self.now);
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "role": self.role,
            "term": self.term,
            "leader": self.leader.map(hex::encode),
            "commit": self.commit,
            "last_index": self.last_index(),
            "snapshot_index": self.snap_index,
            "voters": self.voters().iter().map(hex::encode).collect::<Vec<_>>(),
            "learners": self.learners().iter().map(hex::encode).collect::<Vec<_>>(),
            "match": self.match_index.iter().map(|(k, v)| (hex::encode(k), *v)).collect::<HashMap<_, _>>(),
        })
    }
}

/// Encode a Raft message for the RPC layer.
pub fn wrap(from: &Bytes32, to: &Bytes32, body: RaftBody) -> Vec<u8> {
    wp::RaftMessage {
        from: Some(crypto::k32(from)),
        to: Some(crypto::k32(to)),
        body: Some(body),
    }
    .encode_bytes()
}

pub fn unwrap(bytes: &[u8]) -> Option<(Bytes32, Bytes32, RaftBody)> {
    let m = wp::RaftMessage::decode_bytes(bytes).ok()?;
    Some((opt_k32(&m.from), opt_k32(&m.to), m.body?))
}

#[cfg(test)]
#[path = "raft_tests.rs"]
mod tests;
