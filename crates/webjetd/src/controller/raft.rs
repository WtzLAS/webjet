//! A compact Raft (§7.1): voters and learners, randomized election timeouts
//! of a few seconds, log replication with fast backtracking, snapshots for
//! lagging members and log compaction. Messages travel over end-to-end
//! sessions between controllers (see `controller.rs`).
//!
//! The log holds encoded `LogEntry` FlatBuffers; their `term` and `index`
//! fields are authoritative.

use anyhow::{Context, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use webjet_core::crypto::{self, opt_k32, Bytes32};
use webjet_proto::{self as wp, Decodable, Encodable, RaftBody};

pub const HEARTBEAT: Duration = Duration::from_millis(500);
pub const ELECTION_MIN: Duration = Duration::from_millis(3000);
pub const ELECTION_MAX: Duration = Duration::from_millis(6000);
const MAX_BATCH: usize = 64;
pub const COMPACT_EVERY: u64 = 2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Role {
    Follower,
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

#[derive(Default, Serialize, Deserialize)]
struct Meta {
    term: u64,
    voted_for: Option<String>,
}

/// On-disk state: meta.json, snapshot.wj and an append-only log file.
pub struct Storage {
    dir: PathBuf,
}

impl Storage {
    pub fn new(dir: PathBuf) -> Result<Storage> {
        std::fs::create_dir_all(&dir)?;
        Ok(Storage { dir })
    }

    fn meta_path(&self) -> PathBuf {
        self.dir.join("meta.json")
    }
    fn log_path(&self) -> PathBuf {
        self.dir.join("log.bin")
    }
    fn snap_path(&self) -> PathBuf {
        self.dir.join("snapshot.wj")
    }

    fn save_meta(&self, term: u64, vote: Option<Bytes32>) {
        let m = Meta { term, voted_for: vote.map(hex::encode) };
        if let Err(e) = crate::state::save_json(&self.meta_path(), &m) {
            tracing::error!("raft meta: {e}");
        }
    }

    fn load_meta(&self) -> (u64, Option<Bytes32>) {
        match crate::state::load_json::<Meta>(&self.meta_path()) {
            Ok(Some(m)) => (m.term, m.voted_for.and_then(|s| crypto::parse_hex32(&s))),
            _ => (0, None),
        }
    }

    fn append(&self, entries: &[Entry]) {
        let mut buf = Vec::new();
        for e in entries {
            buf.extend_from_slice(&(e.bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(&e.bytes);
        }
        let r = std::fs::OpenOptions::new().create(true).append(true).open(self.log_path()).and_then(|mut f| {
            f.write_all(&buf)?;
            f.sync_data()
        });
        if let Err(e) = r {
            tracing::error!("raft log append: {e}");
        }
    }

    fn rewrite(&self, entries: &[Entry]) {
        let mut buf = Vec::new();
        for e in entries {
            buf.extend_from_slice(&(e.bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(&e.bytes);
        }
        if let Err(e) = crate::state::write_private(&self.log_path(), &buf) {
            tracing::error!("raft log rewrite: {e}");
        }
    }

    fn load_log(&self) -> Vec<Entry> {
        let Ok(b) = std::fs::read(self.log_path()) else { return Vec::new() };
        let mut out = Vec::new();
        let mut i = 0;
        while i + 4 <= b.len() {
            let len = u32::from_be_bytes(b[i..i + 4].try_into().unwrap()) as usize;
            if i + 4 + len > b.len() {
                tracing::warn!("raft log: truncated tail ignored");
                break;
            }
            let bytes = b[i + 4..i + 4 + len].to_vec();
            if let Ok(e) = wp::LogEntry::decode_bytes(&bytes) {
                out.push(Entry { term: e.term, index: e.index, bytes });
            }
            i += 4 + len;
        }
        out
    }

    pub fn save_snapshot(&self, data: &[u8]) -> Result<()> {
        crate::state::write_private(&self.snap_path(), data)
    }

    pub fn load_snapshot(&self) -> Option<Vec<u8>> {
        std::fs::read(self.snap_path()).ok()
    }
}

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
    pub voters: BTreeSet<Bytes32>,
    pub learners: BTreeSet<Bytes32>,
    next_index: HashMap<Bytes32, u64>,
    match_index: HashMap<Bytes32, u64>,
    last_sent: HashMap<Bytes32, Instant>,
    votes: HashSet<Bytes32>,
    election_deadline: Instant,
    pub last_leader_contact: Instant,
    storage: Storage,
}

pub type Out = Vec<(Bytes32, RaftBody)>;

fn deadline() -> Instant {
    let ms = rand::thread_rng().gen_range(ELECTION_MIN.as_millis()..=ELECTION_MAX.as_millis()) as u64;
    Instant::now() + Duration::from_millis(ms)
}

impl Raft {
    pub fn open(id: Bytes32, dir: PathBuf, snap_index: u64, snap_term: u64) -> Result<Raft> {
        let storage = Storage::new(dir).context("raft storage")?;
        let (term, voted_for) = storage.load_meta();
        let mut log = storage.load_log();
        log.retain(|e| e.index > snap_index);
        // Keep only a contiguous run after the snapshot.
        let mut expect = snap_index + 1;
        let mut contiguous = Vec::new();
        for e in log {
            if e.index == expect {
                expect += 1;
                contiguous.push(e);
            } else if e.index < expect {
                // A later rewrite superseded an earlier append.
                contiguous.truncate((e.index - snap_index - 1) as usize);
                expect = e.index + 1;
                contiguous.push(e);
            }
        }
        Ok(Raft {
            id,
            term,
            voted_for,
            role: Role::Follower,
            leader: None,
            log: contiguous,
            snap_index,
            snap_term,
            commit: snap_index,
            voters: BTreeSet::new(),
            learners: BTreeSet::new(),
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            last_sent: HashMap::new(),
            votes: HashSet::new(),
            election_deadline: deadline(),
            last_leader_contact: Instant::now(),
            storage,
        })
    }

    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    pub fn last_index(&self) -> u64 {
        self.log.last().map(|e| e.index).unwrap_or(self.snap_index)
    }

    pub fn last_term(&self) -> u64 {
        self.log.last().map(|e| e.term).unwrap_or(self.snap_term)
    }

    pub fn term_at(&self, idx: u64) -> Option<u64> {
        if idx == self.snap_index {
            return Some(self.snap_term);
        }
        if idx < self.snap_index {
            return None;
        }
        self.log.get((idx - self.snap_index - 1) as usize).map(|e| e.term)
    }

    pub fn entry(&self, idx: u64) -> Option<&Entry> {
        if idx <= self.snap_index {
            return None;
        }
        self.log.get((idx - self.snap_index - 1) as usize)
    }

    pub fn is_voter(&self) -> bool {
        self.voters.contains(&self.id)
    }

    /// Apply a membership from the state machine.
    pub fn set_members(&mut self, voters: BTreeSet<Bytes32>, learners: BTreeSet<Bytes32>) {
        self.voters = voters;
        self.learners = learners;
        if !self.is_voter() && self.role != Role::Leader {
            self.role = Role::Learner;
        } else if self.role == Role::Learner && self.is_voter() {
            self.role = Role::Follower;
            self.election_deadline = deadline();
        }
        if self.role == Role::Leader && !self.is_voter() {
            // Demoted or removed: step down.
            self.role = Role::Learner;
            self.leader = None;
        }
    }

    fn quorum(&self) -> usize {
        self.voters.len() / 2 + 1
    }

    fn peers(&self) -> Vec<Bytes32> {
        self.voters.iter().chain(self.learners.iter()).filter(|p| **p != self.id).copied().collect()
    }

    fn become_follower(&mut self, term: u64, leader: Option<Bytes32>) {
        if term > self.term {
            self.term = term;
            self.voted_for = None;
            self.storage.save_meta(self.term, self.voted_for);
        }
        self.role = if self.is_voter() { Role::Follower } else { Role::Learner };
        self.leader = leader;
        self.election_deadline = deadline();
    }

    fn become_leader(&mut self) -> Out {
        self.role = Role::Leader;
        self.leader = Some(self.id);
        let next = self.last_index() + 1;
        self.next_index = self.peers().into_iter().map(|p| (p, next)).collect();
        self.match_index = self.peers().into_iter().map(|p| (p, 0)).collect();
        self.last_sent.clear();
        tracing::info!(term = self.term, "became Raft leader");
        // A no-op in the new term lets earlier entries commit (§5.4.2 of Raft).
        let noop = wp::LogEntry {
            term: self.term,
            index: next,
            timestamp: webjet_core::types::now_ms(),
            payload: Some(wp::EntryPayload::NoopEntry(Box::new(wp::NoopEntry { term: self.term }))),
            random: None,
            leaves: Some(Vec::new()),
        };
        self.append_local(noop.encode_bytes());
        self.broadcast(true)
    }

    fn append_local(&mut self, bytes: Vec<u8>) -> u64 {
        let index = self.last_index() + 1;
        let e = Entry { term: self.term, index, bytes };
        self.storage.append(std::slice::from_ref(&e));
        self.log.push(e);
        self.advance_commit();
        index
    }

    /// Leader: append a fully prepared entry. Returns its index.
    pub fn propose(&mut self, entry: &wp::LogEntry) -> Option<(u64, Out)> {
        if self.role != Role::Leader {
            return None;
        }
        let idx = self.append_local(entry.encode_bytes());
        Some((idx, self.broadcast(true)))
    }

    fn start_election(&mut self) -> Out {
        if !self.is_voter() {
            self.election_deadline = deadline();
            return Vec::new();
        }
        self.term += 1;
        self.role = Role::Candidate;
        self.voted_for = Some(self.id);
        self.storage.save_meta(self.term, self.voted_for);
        self.votes = HashSet::from([self.id]);
        self.leader = None;
        self.election_deadline = deadline();
        if self.votes.len() >= self.quorum() {
            return self.become_leader();
        }
        let msg = RaftBody::RaftVote(Box::new(wp::RaftVote { term: self.term, last_log_index: self.last_index(), last_log_term: self.last_term(), pre_vote: false }));
        self.voters.iter().filter(|v| **v != self.id).map(|v| (*v, msg.clone())).collect()
    }

    fn append_msg(&self, peer: &Bytes32) -> Option<RaftBody> {
        let next = *self.next_index.get(peer)?;
        if next <= self.snap_index {
            return None; // needs a snapshot
        }
        let prev = next - 1;
        let prev_term = self.term_at(prev)?;
        let entries: Vec<wp::Blob> = (next..=self.last_index()).take(MAX_BATCH).filter_map(|i| self.entry(i)).map(|e| wp::Blob { data: Some(e.bytes.clone()) }).collect();
        Some(RaftBody::RaftAppend(Box::new(wp::RaftAppend { term: self.term, prev_log_index: prev, prev_log_term: prev_term, entries: Some(entries), leader_commit: self.commit })))
    }

    /// Peers that need a snapshot (the caller builds and sends it).
    pub fn needs_snapshot(&self) -> Vec<Bytes32> {
        if self.role != Role::Leader {
            return Vec::new();
        }
        self.next_index.iter().filter(|(_, n)| **n <= self.snap_index).map(|(p, _)| *p).collect()
    }

    fn broadcast(&mut self, force: bool) -> Out {
        let mut out = Vec::new();
        let now = Instant::now();
        for p in self.peers() {
            let due = force || self.last_sent.get(&p).map(|t| now.duration_since(*t) >= HEARTBEAT).unwrap_or(true);
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
            let count = self.voters.iter().filter(|v| **v == self.id || self.match_index.get(*v).copied().unwrap_or(0) >= idx).count();
            if count >= self.quorum() && self.term_at(idx) == Some(self.term) {
                self.commit = idx;
                break;
            }
            idx -= 1;
        }
    }

    pub fn tick(&mut self) -> Out {
        let now = Instant::now();
        match self.role {
            Role::Leader => {
                // Keep the peer set in sync with membership.
                let next = self.last_index() + 1;
                for p in self.peers() {
                    self.next_index.entry(p).or_insert(next);
                    self.match_index.entry(p).or_insert(0);
                }
                let peers = self.peers();
                self.next_index.retain(|p, _| peers.contains(p));
                self.match_index.retain(|p, _| peers.contains(p));
                self.advance_commit();
                self.broadcast(false)
            }
            Role::Learner => Vec::new(),
            _ => {
                if now >= self.election_deadline {
                    self.start_election()
                } else {
                    Vec::new()
                }
            }
        }
    }

    /// Handle a Raft message. Returns replies and whether entries were
    /// appended or committed (the caller applies committed entries).
    pub fn handle(&mut self, from: Bytes32, body: RaftBody) -> Out {
        let mut out = Vec::new();
        match body {
            RaftBody::RaftVote(v) => {
                if v.term > self.term {
                    self.become_follower(v.term, None);
                }
                let up_to_date = (v.last_log_term, v.last_log_index) >= (self.last_term(), self.last_index());
                // Ignore votes while a leader is known to be alive (disruptive servers).
                let leader_alive = self.leader.is_some() && self.last_leader_contact.elapsed() < ELECTION_MIN;
                let grant = v.term == self.term && up_to_date && (self.voted_for.is_none() || self.voted_for == Some(from)) && self.voters.contains(&from) && !leader_alive;
                if grant {
                    self.voted_for = Some(from);
                    self.storage.save_meta(self.term, self.voted_for);
                    self.election_deadline = deadline();
                }
                out.push((from, RaftBody::RaftVoteResponse(Box::new(wp::RaftVoteResponse { term: self.term, granted: grant, pre_vote: false }))));
            }
            RaftBody::RaftVoteResponse(r) => {
                if r.term > self.term {
                    self.become_follower(r.term, None);
                } else if self.role == Role::Candidate && r.term == self.term && r.granted {
                    self.votes.insert(from);
                    if self.votes.iter().filter(|v| self.voters.contains(*v)).count() >= self.quorum() {
                        out.extend(self.become_leader());
                    }
                }
            }
            RaftBody::RaftAppend(a) => {
                if a.term < self.term {
                    out.push((from, RaftBody::RaftAppendResponse(Box::new(wp::RaftAppendResponse { term: self.term, success: false, match_index: 0, hint_index: self.last_index() + 1 }))));
                    return out;
                }
                self.become_follower(a.term, Some(from));
                self.last_leader_contact = Instant::now();
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
                if r.success {
                    let m = self.match_index.entry(from).or_insert(0);
                    *m = (*m).max(r.match_index);
                    self.next_index.insert(from, r.match_index + 1);
                    self.advance_commit();
                    if r.match_index < self.last_index() {
                        if let Some(m) = self.append_msg(&from) {
                            out.push((from, m));
                        }
                    }
                } else {
                    let next = r.hint_index.max(1).min(self.last_index() + 1);
                    self.next_index.insert(from, next);
                    if let Some(m) = self.append_msg(&from) {
                        out.push((from, m));
                    }
                }
            }
            RaftBody::RaftSnapshotResponse(r) => {
                if r.term > self.term {
                    self.become_follower(r.term, None);
                } else if self.role == Role::Leader {
                    self.match_index.insert(from, r.last_index);
                    self.next_index.insert(from, r.last_index + 1);
                    self.advance_commit();
                }
            }
            RaftBody::RaftTimeoutNow(t) => {
                if t.term == self.term && self.is_voter() {
                    out.extend(self.start_election());
                }
            }
            _ => {}
        }
        out
    }

    fn accept_append(&mut self, a: &wp::RaftAppend) -> wp::RaftAppendResponse {
        let fail = |hint: u64, term| wp::RaftAppendResponse { term, success: false, match_index: 0, hint_index: hint };
        if a.prev_log_index > self.last_index() {
            return fail(self.last_index() + 1, self.term);
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
                    return fail(i, self.term);
                }
                None => return fail(self.snap_index + 1, self.term),
            }
        }
        let mut idx = a.prev_log_index;
        let mut appended = Vec::new();
        let mut truncated = false;
        for b in a.entries.clone().unwrap_or_default() {
            let bytes = b.data.unwrap_or_default();
            let Ok(e) = wp::LogEntry::decode_bytes(&bytes) else { return fail(idx + 1, self.term) };
            idx += 1;
            if e.index != idx {
                return fail(idx, self.term);
            }
            if idx <= self.snap_index {
                continue;
            }
            match self.term_at(idx) {
                Some(t) if t == e.term => continue,
                Some(_) => {
                    if idx <= self.commit {
                        tracing::error!("leader tried to overwrite a committed entry");
                        return fail(self.commit + 1, self.term);
                    }
                    self.log.truncate((idx - self.snap_index - 1) as usize);
                    truncated = true;
                }
                None => {}
            }
            let ent = Entry { term: e.term, index: idx, bytes };
            appended.push(ent.clone());
            self.log.push(ent);
        }
        if truncated {
            self.storage.rewrite(&self.log);
        } else if !appended.is_empty() {
            self.storage.append(&appended);
        }
        if a.leader_commit > self.commit {
            self.commit = a.leader_commit.min(idx.max(a.prev_log_index));
        }
        wp::RaftAppendResponse { term: self.term, success: true, match_index: idx, hint_index: 0 }
    }

    /// Install a snapshot received from the leader.
    pub fn install_snapshot(&mut self, last_index: u64, last_term: u64) {
        self.log.retain(|e| e.index > last_index);
        if self.log.first().map(|e| e.index != last_index + 1).unwrap_or(false) {
            self.log.clear();
        }
        self.snap_index = last_index;
        self.snap_term = last_term;
        self.commit = self.commit.max(last_index);
        self.storage.rewrite(&self.log);
    }

    /// Drop entries up to `index` (already in a saved snapshot).
    pub fn compact(&mut self, index: u64) {
        if index <= self.snap_index {
            return;
        }
        let Some(term) = self.term_at(index) else { return };
        self.log.retain(|e| e.index > index);
        self.snap_index = index;
        self.snap_term = term;
        self.storage.rewrite(&self.log);
    }

    pub fn snapshot_msg(&self, data: Vec<u8>) -> RaftBody {
        RaftBody::RaftSnapshot(Box::new(wp::RaftSnapshot { term: self.term, last_index: self.snap_index, last_term: self.snap_term, data: Some(data) }))
    }

    pub fn mark_snapshot_sent(&mut self, peer: &Bytes32) {
        // Optimistic: avoid resending every tick; the response corrects it.
        self.next_index.insert(*peer, self.snap_index + 1);
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "role": self.role,
            "term": self.term,
            "leader": self.leader.map(|l| hex::encode(l)),
            "commit": self.commit,
            "last_index": self.last_index(),
            "snapshot_index": self.snap_index,
            "voters": self.voters.iter().map(hex::encode).collect::<Vec<_>>(),
            "learners": self.learners.iter().map(hex::encode).collect::<Vec<_>>(),
            "match": self.match_index.iter().map(|(k, v)| (hex::encode(k), *v)).collect::<HashMap<_, _>>(),
        })
    }
}

/// Encode a Raft message for the RPC layer.
pub fn wrap(from: &Bytes32, to: &Bytes32, body: RaftBody) -> Vec<u8> {
    wp::RaftMessage { from: Some(crypto::k32(from)), to: Some(crypto::k32(to)), body: Some(body) }.encode_bytes()
}

pub fn unwrap(bytes: &[u8]) -> Option<(Bytes32, Bytes32, RaftBody)> {
    let m = wp::RaftMessage::decode_bytes(bytes).ok()?;
    Some((opt_k32(&m.from), opt_k32(&m.to), m.body?))
}
