//! Restarting the controller cluster offline (ops guide 4.1), while the
//! agent is stopped:
//!
//! * [`force_new_cluster`]: a majority of voters is lost for good, but this
//!   controller survives. Its whole log is taken as it is, and a
//!   `ForceNewClusterEntry` makes it the only voter; the other members stay
//!   as learners, so survivors catch up and automatic membership promotes
//!   them (§7.5).
//! * [`restore`]: no controller survives. A snapshot exported with
//!   `webjetctl network controller snapshot` is installed on a node in it,
//!   which becomes the only voter, and is granted the control role if it
//!   lacked it.
//!
//! Both start a new Raft term in which this server voted for itself, so no
//! earlier leader can overwrite the entry, and both put the new cluster's
//! first entry above every tree version nodes may hold (`min_version`):
//! heads at versions the old controllers signed would otherwise conflict
//! with theirs (equivocation, §21.3). When the log has to jump, it is
//! replaced by a snapshot at that version.

use super::raft::{Raft, Storage};
use super::{classify_entry, raft};
use crate::config::Config;
use crate::state::{self, NodeFile, Paths};
use anyhow::{Context, Result, anyhow, bail};
use webjet_core::crypto::{self, Bytes32};
use webjet_core::statemachine::Machine;
use webjet_core::types::now_ms;
use webjet_proto::{self as wp, Decodable, Encodable, EntryPayload};

/// What was done, for the operator.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Report {
    pub node_id: String,
    /// Index of the new cluster's first entry (the next tree versions).
    pub index: u64,
    pub term: u64,
    /// The log was replaced by a snapshot to move above `min_version`.
    pub jumped: bool,
    /// Members of the old cluster kept as learners.
    pub learners: Vec<String>,
    /// Entries the old log held after its snapshot, now taken as committed.
    pub replayed: u64,
}

/// Highest tree version this node has seen (the store's high-water mark).
pub fn local_tree_version(paths: &Paths) -> u64 {
    state::load_json::<state::StoreFile>(&paths.store())
        .ok()
        .flatten()
        .map(|f| f.high_water)
        .unwrap_or(0)
}

fn node_file(paths: &Paths) -> Result<(NodeFile, Bytes32)> {
    let nf: NodeFile = state::load_json(&paths.node())?.ok_or_else(|| {
        anyhow!(
            "{} has no node.json: not an enrolled node",
            paths.dir.display()
        )
    })?;
    let me = crypto::parse_hex32(&nf.node_id).ok_or_else(|| anyhow!("bad node id in node.json"))?;
    Ok((nf, me))
}

/// The machine at the end of this controller's log: the snapshot plus every
/// entry after it, committed or not.
fn replay(storage: &Storage) -> Result<(Machine, Raft, u64)> {
    let mut m = match storage.load_snapshot() {
        Some(b) => Machine::restore_bytes(&b).context("the Raft snapshot")?,
        None => Machine::new(),
    };
    let r = open(storage, &m, crypto::random32())?;
    let mut replayed = 0;
    for i in m.last_index + 1..=r.last_index() {
        let e = r
            .entry(i)
            .ok_or_else(|| anyhow!("entry {i} missing from the log"))?;
        let entry = wp::LogEntry::decode_bytes(&e.bytes).with_context(|| format!("entry {i}"))?;
        m.apply(&entry)
            .map_err(|e| anyhow!("entry {i} doesn't apply ({e}); nothing was changed"))?;
        replayed += 1;
    }
    Ok((m, r, replayed))
}

fn open(storage: &Storage, m: &Machine, me: Bytes32) -> Result<Raft> {
    Raft::new(
        me,
        storage.clone(),
        m.last_index,
        m.last_term,
        m.members.clone(),
        Box::new(classify_entry),
        raft::Timing::default(),
        std::time::Instant::now(),
        None,
    )
}

/// Write the new cluster's first entry. When the log doesn't reach above
/// `min_version`, it becomes a snapshot of `m` at `min_version` first.
fn start_cluster(
    storage: &Storage,
    me: Bytes32,
    mut m: Machine,
    old: Option<Raft>,
    min_version: u64,
    payload: EntryPayload,
) -> Result<(u64, u64, bool)> {
    let prev_term = match &old {
        Some(r) => r.term.max(r.last_term()),
        None => m.last_term,
    };
    let jumped = m.last_index < min_version;
    let mut r = match old {
        Some(mut r) if !jumped => {
            r.id = me;
            r
        }
        _ => {
            // The snapshot stands in for the entries up to `min_version`.
            m.last_index = m.last_index.max(min_version);
            storage.save_snapshot(&m.snapshot_bytes())?;
            storage.clear_log()?;
            open(storage, &m, me)?
        }
    };
    let term = prev_term.max(r.term) + 1;
    let idx = r.last_index() + 1;
    let entry = m
        .prepare_offline(term, idx, now_ms(), payload)
        .map_err(|e| anyhow!("{e}"))?;
    r.append_offline(term, entry.encode_bytes())?;
    Ok((idx, term, jumped))
}

/// Files written here belong to whoever runs `webjetctl`; give them to the
/// owner of the data directory (the agent's user, `webjet` on Linux).
fn match_owner(paths: &Paths) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(&paths.dir)?;
        let (uid, gid) = (m.uid(), m.gid());
        let mut todo = vec![paths.raft(), paths.node()];
        while let Some(p) = todo.pop() {
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.uid() != uid || meta.gid() != gid {
                std::os::unix::fs::chown(&p, Some(uid), Some(gid))
                    .with_context(|| format!("chown {}", p.display()))?;
            }
            if meta.is_dir() {
                for e in std::fs::read_dir(&p)? {
                    todo.push(e?.path());
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = paths;
    Ok(())
}

/// Refuse while the agent runs: it holds the log in memory and would
/// overwrite what is written here.
pub async fn ensure_stopped(cfg: &Config) -> Result<()> {
    if crate::ipc::connect(&cfg.control_socket).await.is_ok() {
        bail!(
            "webjetd is running (its control socket {} answers); stop the agent first",
            cfg.control_socket.display()
        );
    }
    Ok(())
}

/// `webjetctl local controller force-new-cluster` (ops guide 4.1 step 3).
pub fn force_new_cluster(cfg: &Config, min_version: Option<u64>, reason: &str) -> Result<Report> {
    let paths = Paths::new(&cfg.data_dir);
    let (_, me) = node_file(&paths)?;
    let dir = paths.raft();
    if !dir.join("log.bin").exists() && !dir.join("snapshot.wj").exists() {
        bail!(
            "{} holds no controller state: this node isn't a controller",
            dir.display()
        );
    }
    let storage = Storage::disk(dir)?;
    let (m, r, replayed) = replay(&storage)?;
    if m.genesis.is_none() {
        bail!("this controller's log doesn't reach the genesis yet");
    }
    if !m.members.contains(&me) {
        bail!("this node is not a member of the controller cluster in its own log");
    }
    let learners: Vec<Bytes32> = m.members.all().into_iter().filter(|x| *x != me).collect();
    let min_version = min_version.unwrap_or(0).max(local_tree_version(&paths));
    let payload = EntryPayload::ForceNewClusterEntry(Box::new(wp::ForceNewClusterEntry {
        voter: Some(crypto::k32(&me)),
        learners: Some(learners.iter().map(crypto::k32).collect()),
        grant_control: false,
        reason: Some(reason.to_string()),
    }));
    let (index, term, jumped) = start_cluster(&storage, me, m, Some(r), min_version, payload)?;
    match_owner(&paths)?;
    Ok(Report {
        node_id: hex::encode(me),
        index,
        term,
        jumped,
        learners: learners.iter().map(hex::encode).collect(),
        replayed,
    })
}

/// `webjetctl local controller restore` (ops guide 4.1 step 4): install a
/// `ControllerSnapshot` on this node and make it the only voter. An old
/// Raft directory is kept beside the new one (`raft.replaced-<ms>`) when
/// `replace` allows it.
pub fn restore(
    cfg: &Config,
    snapshot: &[u8],
    min_version: Option<u64>,
    replace: bool,
    reason: &str,
) -> Result<Report> {
    let paths = Paths::new(&cfg.data_dir);
    let (mut nf, me) = node_file(&paths)?;
    let m = Machine::restore_bytes(snapshot).context("not a controller snapshot")?;
    let Some((g, _)) = &m.genesis else {
        bail!("the snapshot holds no network");
    };
    let mine = std::fs::read(paths.genesis()).context("this node's genesis")?;
    if *g != mine {
        bail!("the snapshot is of another network");
    }
    match m.view().nodes.get(&me) {
        Some(n) if n.valid => {}
        _ => bail!(
            "this node ({}) isn't a valid node in the snapshot; restore onto a node enrolled before it was taken",
            crypto::short(&me)
        ),
    }
    let dir = paths.raft();
    if dir.exists() && std::fs::read_dir(&dir)?.next().is_some() {
        if !replace {
            bail!(
                "{} already holds controller state; pass --replace to set it aside",
                dir.display()
            );
        }
        let aside = dir.with_file_name(format!("raft.replaced-{}", now_ms()));
        std::fs::rename(&dir, &aside).with_context(|| format!("move {} aside", dir.display()))?;
    }
    let storage = Storage::disk(dir)?;
    let min_version = min_version
        .unwrap_or(0)
        .max(local_tree_version(&paths))
        .max(m.last_index);
    let payload = EntryPayload::ForceNewClusterEntry(Box::new(wp::ForceNewClusterEntry {
        voter: Some(crypto::k32(&me)),
        learners: Some(Vec::new()),
        grant_control: true,
        reason: Some(reason.to_string()),
    }));
    let (index, term, jumped) = start_cluster(&storage, me, m, None, min_version, payload)?;
    // The node's own tree doesn't show the control role yet: only the new
    // controller grants it.
    nf.restored_controller = true;
    state::save_json(&paths.node(), &nf)?;
    match_owner(&paths)?;
    Ok(Report {
        node_id: hex::encode(me),
        index,
        term,
        jumped,
        learners: Vec::new(),
        replayed: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::{Controller, Role};
    use crate::testnode;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    use webjet_core::crypto::KeyPair;
    use webjet_core::statemachine::Membership;
    use webjet_core::store::Store;
    use webjet_core::testutil::{Cluster, NodeSpec};
    use webjet_proto::AccountOp;

    /// A controller log on disk: genesis (a voter that is gone), the node
    /// `ctl-02` with the control role, added as a learner. Term 1.
    struct OldCluster {
        cluster: Cluster,
        entries: Vec<Vec<u8>>,
        lost_voter: Bytes32,
        survivor: Bytes32,
    }

    fn old_cluster() -> OldCluster {
        let mut cluster = Cluster::new();
        let lost_voter = cluster
            .machine
            .members
            .voters
            .iter()
            .next()
            .copied()
            .unwrap();
        let (survivor, _) = cluster.enroll(NodeSpec {
            name: "ctl-02",
            ip: "10.7.0.2",
            roles: &[wp::Role::Data, wp::Role::Relay],
            control: true,
            ..Default::default()
        });
        cluster
            .admin_op(AccountOp::ChangeMembership(Box::new(
                wp::ChangeMembership {
                    change: wp::MembershipChange::AddLearner,
                    node_id: Some(crypto::k32(&survivor)),
                },
            )))
            .unwrap();
        let entries = cluster.log().to_vec();
        OldCluster {
            cluster,
            entries,
            lost_voter,
            survivor,
        }
    }

    fn write_log(dir: &std::path::Path, entries: &[Vec<u8>]) {
        let mut buf = Vec::new();
        for e in entries {
            buf.extend_from_slice(&(e.len() as u32).to_be_bytes());
            buf.extend_from_slice(e);
        }
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("log.bin"), buf).unwrap();
    }

    /// A stopped node `me` of the network, with `entries` as its Raft log.
    fn stopped_node(
        old: &OldCluster,
        me: Bytes32,
        entries: &[Vec<u8>],
    ) -> (std::sync::Arc<crate::node::Node>, tempfile::TempDir) {
        let store = Store::new(old.cluster.net.genesis.clone()).unwrap();
        let (n, dir) = testnode::with_store(store, me, KeyPair::generate());
        std::fs::write(n.paths.genesis(), &old.cluster.net.genesis).unwrap();
        state::save_json(
            &n.paths.node(),
            &NodeFile {
                node_id: hex::encode(me),
                ..Default::default()
            },
        )
        .unwrap();
        if !entries.is_empty() {
            write_log(&n.paths.raft(), entries);
        }
        (n, dir)
    }

    /// Start the controller role on `n` and let it elect itself and apply
    /// everything; it must not halt.
    fn run_controller(n: &std::sync::Arc<crate::node::Node>) -> std::sync::Arc<Controller> {
        let c = Controller::start(n, false).unwrap();
        let _ = n.controller.set(c.clone());
        let later = Instant::now() + Duration::from_secs(10);
        let _ = c.raft.lock().tick(later);
        assert_eq!(
            c.raft.lock().role,
            Role::Leader,
            "the only voter elects itself"
        );
        let _ = c.raft.lock().tick(later);
        c.apply_committed(n);
        assert_eq!(*c.halted.lock(), None);
        assert_eq!(c.applied.load(Ordering::SeqCst), c.raft.lock().last_index());
        c
    }

    #[test]
    fn only_offline_entries_start_a_new_cluster() {
        let old = old_cluster();
        let p = || {
            EntryPayload::ForceNewClusterEntry(Box::new(wp::ForceNewClusterEntry {
                voter: Some(crypto::k32(&old.survivor)),
                ..Default::default()
            }))
        };
        let m = &old.cluster.machine;
        assert!(m.prepare(1, m.last_index + 1, now_ms(), p()).is_err());
        assert!(
            m.prepare_offline(1, m.last_index + 1, now_ms(), p())
                .is_ok()
        );
    }

    #[test]
    fn the_new_voter_must_be_a_controller() {
        let mut old = old_cluster();
        let (data, _) = old.cluster.data_node("laptop", "10.7.0.9", &[]);
        let m = &old.cluster.machine;
        let entry = |voter: Bytes32, grant: bool, learners: Vec<Bytes32>| {
            EntryPayload::ForceNewClusterEntry(Box::new(wp::ForceNewClusterEntry {
                voter: Some(crypto::k32(&voter)),
                learners: Some(learners.iter().map(crypto::k32).collect()),
                grant_control: grant,
                reason: None,
            }))
        };
        let at = m.last_index + 1;
        assert!(
            m.prepare_offline(1, at, now_ms(), entry(data, false, vec![]))
                .is_err()
        );
        assert!(
            m.prepare_offline(1, at, now_ms(), entry(data, true, vec![]))
                .is_ok()
        );
        assert!(
            m.prepare_offline(1, at, now_ms(), entry(old.survivor, false, vec![data]))
                .is_err(),
            "learners come from the old membership"
        );
        assert!(
            m.prepare_offline(1, at, now_ms(), entry(crypto::random32(), true, vec![]))
                .is_err(),
            "unknown node"
        );
    }

    #[tokio::test]
    async fn a_surviving_learner_becomes_the_only_voter() {
        let old = old_cluster();
        let (n, d) = stopped_node(&old, old.survivor, &old.entries);
        let mut cfg = n.cfg.clone();
        cfg.control_socket = d.path().join("none.sock");
        ensure_stopped(&cfg).await.unwrap();
        let r = force_new_cluster(&cfg, None, "voters lost").unwrap();
        let last = old.entries.len() as u64;
        assert_eq!((r.index, r.term, r.jumped), (last + 1, 2, false));
        assert_eq!(r.replayed, last);
        assert_eq!(r.learners, vec![hex::encode(old.lost_voter)]);

        let c = run_controller(&n);
        let m = c.machine.lock().members.clone();
        assert_eq!(
            m,
            Membership {
                voters: [old.survivor].into(),
                learners: [old.lost_voter].into(),
            }
        );
        assert_eq!(c.raft.lock().config(), &m);
        // It goes on committing on its own: the new term's no-op, and what
        // it proposes.
        assert!(
            c.raft.lock().commit > last + 1,
            "the new term's entries commit"
        );
        let (idx, _) = c
            .propose(EntryPayload::NoopEntry(Box::default()))
            .await
            .unwrap();
        assert_eq!(c.raft.lock().commit, idx);
        // The audit trail names it.
        let e = c.raft.lock().entry(last + 1).unwrap().bytes.clone();
        let e = wp::LogEntry::decode_bytes(&e).unwrap();
        assert!(matches!(
            e.payload,
            Some(EntryPayload::ForceNewClusterEntry(_))
        ));
    }

    #[tokio::test]
    async fn the_new_cluster_starts_above_the_versions_nodes_hold() {
        let old = old_cluster();
        let (n, _d) = stopped_node(&old, old.survivor, &old.entries);
        let r = force_new_cluster(&n.cfg, Some(100), "voters lost").unwrap();
        assert_eq!((r.index, r.jumped), (101, true));
        let c = run_controller(&n);
        assert_eq!(c.raft.lock().snap_index, 100);
        assert!(c.machine.lock().last_index >= 101);
        assert!(c.machine.lock().view().nodes.contains_key(&old.survivor));
    }

    #[tokio::test]
    async fn force_new_cluster_refuses_what_it_cannot_do() {
        let old = old_cluster();
        // Not a member: the voter that is gone was the only one, and this
        // node never joined.
        let mut c2 = old_cluster();
        let (other, _) = c2.cluster.data_node("laptop", "10.7.0.9", &[]);
        let (n, _d) = stopped_node(&c2, other, &c2.entries);
        assert!(
            force_new_cluster(&n.cfg, None, "x")
                .unwrap_err()
                .to_string()
                .contains("not a member")
        );
        // No controller state at all.
        let (n, _d) = stopped_node(&old, old.survivor, &[]);
        assert!(
            force_new_cluster(&n.cfg, None, "x")
                .unwrap_err()
                .to_string()
                .contains("no controller state")
        );
        // A running agent.
        let (n, d) = stopped_node(&old, old.survivor, &old.entries);
        let mut cfg = n.cfg.clone();
        cfg.control_socket = d.path().join("c.sock");
        let _l =
            crate::ipc::Listener::bind(&cfg.control_socket, crate::ipc::Access::Private).unwrap();
        assert!(ensure_stopped(&cfg).await.is_err());
    }

    #[tokio::test]
    async fn a_snapshot_is_restored_onto_a_relay() {
        let mut old = old_cluster();
        let (relay, _) = old.cluster.enroll(NodeSpec {
            name: "relay-01",
            ip: "10.7.0.3",
            roles: &[wp::Role::Relay],
            ..Default::default()
        });
        let snap = old.cluster.machine.snapshot_bytes();
        let (n, _d) = stopped_node(&old, relay, &[]);
        let r = restore(&n.cfg, &snap, Some(50), false, "all controllers lost").unwrap();
        assert_eq!(r.index, 51);
        let nf: NodeFile = state::load_json(&n.paths.node()).unwrap().unwrap();
        assert!(nf.restored_controller);
        let c = run_controller(&n);
        let m = c.machine.lock();
        assert_eq!(m.members.voters, [relay].into());
        assert!(m.members.learners.is_empty());
        assert_eq!(
            m.view().nodes[&relay].rec.control,
            Some(true),
            "control granted"
        );
        drop(m);
        // A second restore needs --replace and keeps the old state aside.
        drop(c);
        assert!(
            restore(&n.cfg, &snap, None, false, "again")
                .unwrap_err()
                .to_string()
                .contains("--replace")
        );
        restore(&n.cfg, &snap, None, true, "again").unwrap();
        let aside = std::fs::read_dir(&n.paths.dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("raft.replaced-")
            })
            .count();
        assert_eq!(aside, 1);
    }

    #[test]
    fn a_snapshot_is_checked_before_anything_changes() {
        let old = old_cluster();
        let snap = old.cluster.machine.snapshot_bytes();
        // A node the snapshot doesn't know.
        let (n, _d) = stopped_node(&old, crypto::random32(), &[]);
        assert!(
            restore(&n.cfg, &snap, None, false, "x")
                .unwrap_err()
                .to_string()
                .contains("isn't a valid node")
        );
        assert!(!n.paths.raft().join("snapshot.wj").exists());
        // Another network.
        let other = Cluster::new();
        let (n, _d) = stopped_node(&old, old.survivor, &[]);
        let e = restore(&n.cfg, &other.machine.snapshot_bytes(), None, false, "x").unwrap_err();
        assert!(e.to_string().contains("another network"), "{e}");
        assert!(restore(&n.cfg, b"junk", None, false, "x").is_err());
    }
}
