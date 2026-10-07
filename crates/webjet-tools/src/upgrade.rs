//! Remote upgrades from the admin's side (architecture §19.8, ops guide
//! 3.3): pinning a release's checksums, signing one `UpgradeRequest` per
//! node, and the order of a rollout. `webjetctl network node upgrade` drives
//! it through the local agent.

use anyhow::{Result, anyhow, bail};
use std::collections::BTreeMap;
use webjet_core::crypto::{self, Bytes32, KeyPair};
use webjet_proto as wp;
use webjet_release::{self as rel, http};

/// How long each request may be used (the node checks at most an hour).
pub const REQUEST_LIFETIME_MS: u64 = 30 * 60 * 1000;

/// The release's files and their published SHA-256s, for every target that
/// has them. Targets without files (published later, like the macOS ones)
/// are left out and named in the second value.
pub fn pin_release(repo: &str, tag: &str) -> Result<(Vec<wp::UpgradeFile>, Vec<&'static str>)> {
    let tag = rel::normalize_version(tag);
    if !rel::valid_tag(&tag) {
        bail!("{tag:?} is not a release tag like v0.9.0");
    }
    let repo = http::Repo::parse(repo)?;
    let c = http::Client::new();
    c.check_release(&repo, &tag)?;
    let mut files = Vec::new();
    let mut missing = Vec::new();
    for t in rel::TARGETS {
        let names = [rel::archive_name(&tag, t), rel::webjetup_name(&tag, t)];
        let sums: Result<Vec<String>> = names
            .iter()
            .map(|n| c.published_sha256(&repo, &tag, n))
            .collect();
        match sums {
            Ok(sums) => {
                for (name, sum) in names.into_iter().zip(sums) {
                    let b = hex::decode(&sum)?;
                    let b: Bytes32 = b
                        .try_into()
                        .map_err(|_| anyhow!("bad SHA-256 for {name}"))?;
                    files.push(wp::UpgradeFile {
                        name: Some(name),
                        sha256: Some(crypto::k32(&b)),
                    });
                }
            }
            Err(e) if http::is_not_found(&e) => missing.push(t),
            Err(e) => return Err(e),
        }
    }
    if files.is_empty() {
        bail!("release {tag} has no files for any platform");
    }
    Ok((files, missing))
}

/// One node's signed `UpgradeRequest`.
pub fn sign_request(
    kp: &KeyPair,
    account: &Bytes32,
    node: &Bytes32,
    tag: &str,
    files: &[wp::UpgradeFile],
    now: u64,
) -> Vec<u8> {
    kp.sign_obj(
        wp::msg_type::UPGRADE_REQUEST,
        &wp::UpgradeRequest {
            account_id: Some(crypto::k32(account)),
            node_id: Some(crypto::k32(node)),
            nonce: Some(wp::Id16::from_bytes(&crypto::random16())),
            issued_at: now,
            expires_at: now + REQUEST_LIFETIME_MS,
            version: Some(rel::normalize_version(tag)),
            files: Some(files.to_vec()),
        },
    )
}

/// What the rollout needs to know about a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub id: Bytes32,
    pub name: String,
    pub relay: bool,
    /// Raft membership: `Some(true)` voter, `Some(false)` learner.
    pub voter: Option<bool>,
    pub leader: bool,
    /// The node the admin's agent runs on.
    pub me: bool,
}

/// The rollout's stages, in order (§19.8, ops guide 3.3): controllers one
/// at a time (learners, then voters, the leader last), then relays, then
/// the other nodes, `batch` at a time. The admin's own node goes last in
/// its group, so the local agent stays up for as long as possible.
pub fn stages(targets: &[Target], batch: usize) -> Vec<Vec<Target>> {
    let batch = batch.max(1);
    let key = |t: &Target| (t.me, t.name.clone());
    let mut ctl: Vec<&Target> = targets.iter().filter(|t| t.voter.is_some()).collect();
    ctl.sort_by_key(|t| (t.leader, t.voter == Some(true), key(t)));
    let mut relays: Vec<&Target> = targets
        .iter()
        .filter(|t| t.voter.is_none() && t.relay)
        .collect();
    relays.sort_by_key(|t| key(t));
    let mut rest: Vec<&Target> = targets
        .iter()
        .filter(|t| t.voter.is_none() && !t.relay)
        .collect();
    rest.sort_by_key(|t| key(t));
    let mut out: Vec<Vec<Target>> = ctl.into_iter().map(|t| vec![t.clone()]).collect();
    for group in [relays, rest] {
        for chunk in group.chunks(batch) {
            out.push(chunk.iter().map(|t| (*t).clone()).collect());
        }
    }
    out
}

/// Raft roles from `webjetctl network controller list` (the `controller`
/// control command): id → voter?, and the leader.
pub fn raft_roles(status: &serde_json::Value) -> (BTreeMap<Bytes32, bool>, Option<Bytes32>) {
    let raft = &status["raft"];
    let ids = |k: &str| -> Vec<Bytes32> {
        raft[k]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().and_then(crypto::parse_hex32))
            .collect()
    };
    let mut roles = BTreeMap::new();
    for id in ids("learners") {
        roles.insert(id, false);
    }
    for id in ids("voters") {
        roles.insert(id, true);
    }
    let leader = raft["leader"].as_str().and_then(crypto::parse_hex32);
    (roles, leader)
}

/// Where one node stands, from its `upgrade_status` answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress {
    /// Runs `want` (or newer) and the helper has finished.
    Done,
    /// Not yet.
    Waiting(String),
    /// The helper gave up: refused, failed, rolled back.
    Failed(String),
}

/// Judge an `upgrade_status` answer for request `id` to version `want`.
pub fn progress(v: &serde_json::Value, want: &str, id: &str) -> Progress {
    let have = v["version"].as_str().unwrap_or("");
    let st = &v["status"];
    let ours = st["id"].as_str() == Some(id);
    let state = st["state"].as_str().unwrap_or("");
    let err = st["error"].as_str().unwrap_or("").to_string();
    if ours
        && matches!(
            state,
            "refused" | "failed" | "rolled_back" | "rollback_failed"
        )
    {
        return Progress::Failed(format!("{state}: {err}"));
    }
    let at_least = rel::is_upgrade(have, want) == Some(false);
    if at_least && (!ours || state == "done") {
        return Progress::Done;
    }
    if ours {
        Progress::Waiting(format!("{state} (running {have})"))
    } else {
        Progress::Waiting(format!("queued (running {have})"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn t(n: u8, name: &str, relay: bool, voter: Option<bool>, leader: bool, me: bool) -> Target {
        Target {
            id: [n; 32],
            name: name.into(),
            relay,
            voter,
            leader,
            me,
        }
    }

    #[test]
    fn controllers_go_first_one_at_a_time_leader_last() {
        let all = vec![
            t(1, "data-b", false, None, false, false),
            t(2, "ctl-leader", true, Some(true), true, false),
            t(3, "ctl-voter", true, Some(true), false, false),
            t(4, "ctl-learner", false, Some(false), false, false),
            t(5, "relay-a", true, None, false, false),
            t(6, "data-a", false, None, false, true),
            t(7, "data-c", false, None, false, false),
            t(8, "relay-b", true, None, false, false),
        ];
        let names: Vec<Vec<String>> = stages(&all, 2)
            .iter()
            .map(|s| s.iter().map(|t| t.name.clone()).collect())
            .collect();
        assert_eq!(
            names,
            vec![
                vec!["ctl-learner"],
                vec!["ctl-voter"],
                vec!["ctl-leader"],
                vec!["relay-a", "relay-b"],
                // The admin's own node (data-a) last.
                vec!["data-b", "data-c"],
                vec!["data-a"],
            ]
        );
        assert_eq!(stages(&all, 0).len(), stages(&all, 1).len());
        assert!(stages(&[], 5).is_empty());
    }

    #[test]
    fn raft_roles_from_controller_status() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let s = json!({"raft": {"voters": [a], "learners": [b], "leader": a}});
        let (roles, leader) = raft_roles(&s);
        assert_eq!(roles.get(&[0xaa; 32]), Some(&true));
        assert_eq!(roles.get(&[0xbb; 32]), Some(&false));
        assert_eq!(leader, Some([0xaa; 32]));
        assert_eq!(raft_roles(&json!({})).0.len(), 0);
    }

    #[test]
    fn progress_of_a_node() {
        let id = "07".repeat(16);
        let st = |version: &str, sid: &str, state: &str| json!({"version": version, "status": {"id": sid, "state": state, "error": "boom"}});
        assert_eq!(
            progress(&st("0.9.0", &id, "done"), "v0.9.0", &id),
            Progress::Done
        );
        assert!(matches!(
            progress(&st("0.8.0", &id, "running"), "v0.9.0", &id),
            Progress::Waiting(_)
        ));
        // Restarted on the new version, helper still checking its health.
        assert!(matches!(
            progress(&st("0.9.0", &id, "running"), "v0.9.0", &id),
            Progress::Waiting(_)
        ));
        assert_eq!(
            progress(&st("0.8.0", &id, "rolled_back"), "v0.9.0", &id),
            Progress::Failed("rolled_back: boom".into())
        );
        assert!(matches!(
            progress(&st("0.8.0", &id, "refused"), "v0.9.0", &id),
            Progress::Failed(_)
        ));
        // Someone else's (older) status doesn't count against this request.
        assert!(matches!(
            progress(&st("0.8.0", "other", "failed"), "v0.9.0", &id),
            Progress::Waiting(_)
        ));
        // Already there (upgraded some other way).
        assert_eq!(
            progress(&json!({"version": "0.9.1"}), "v0.9.0", &id),
            Progress::Done
        );
    }

    #[test]
    fn signed_requests_name_one_node() {
        let kp = KeyPair::generate();
        let files = vec![wp::UpgradeFile {
            name: Some("x".into()),
            sha256: Some(crypto::k32(&[1; 32])),
        }];
        let a = sign_request(&kp, &[1; 32], &[2; 32], "0.9.0", &files, 1_000);
        let b = sign_request(&kp, &[1; 32], &[2; 32], "0.9.0", &files, 1_000);
        let v = crypto::open_expect(&a, wp::msg_type::UPGRADE_REQUEST, &[kp.public()]).unwrap();
        let r: wp::UpgradeRequest = v.decode().unwrap();
        assert_eq!(crypto::opt_k32(&r.node_id), [2; 32]);
        assert_eq!(r.version.as_deref(), Some("v0.9.0"));
        assert_eq!(r.expires_at - r.issued_at, REQUEST_LIFETIME_MS);
        assert_ne!(a, b, "each request has its own nonce");
    }
}
