//! Remote upgrades (architecture §19.8): an admin's signed `UpgradeRequest`
//! for this node, checked against this node's own tree and handed to the
//! root helper webjetup installed (`webjetup apply-upgrade`), which installs
//! exactly the release files the admin pinned and rolls back when the new
//! agent doesn't come up healthy.
//!
//! The request travels admin's agent → a controller → the node, because the
//! policy may not let the admin's machine reach the node directly, while
//! controllers reach every node (§14.4); an admin on a controller sends it
//! straight. The controller checks the signature too, so it relays only
//! admins' requests, and relays one hop only; the node trusts only its own
//! checks. Nothing enters the log.
//!
//! The node accepts a request only when `[upgrade] remote` is on (the
//! default), the helper is installed (its queue directory exists), the
//! version is newer than the running one, and the request names this node,
//! is recent and hasn't been seen before.

use crate::node::Node;
use anyhow::{Result, anyhow, bail};
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use webjet_core::crypto::{self, Bytes32};
use webjet_core::store::View;
use webjet_core::types::now_ms;
use webjet_proto::{self as wp, RpcBody, msg_type as mt};
use webjet_release as rel;

/// The running agent's version.
pub const RUNNING: &str = env!("CARGO_PKG_VERSION");

/// How long a node waits for the target of a forwarded request.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(30);

/// The checks everyone holding the request makes (the forwarding controller
/// and the node): a valid admin signed it with its current key, recently,
/// for a short time, for a well-formed version and one node.
pub fn check_signed(view: &View, raw: &[u8], now: u64) -> Result<wp::UpgradeRequest> {
    let req: wp::UpgradeRequest = crate::admin::signed_request(
        view,
        raw,
        mt::UPGRADE_REQUEST,
        "upgrade nodes",
        |r: &wp::UpgradeRequest| crypto::opt_k32(&r.account_id),
    )?;
    if req.node_id.is_none() || req.nonce.is_none() {
        bail!("the request names no node");
    }
    if now >= req.expires_at {
        bail!("the request expired");
    }
    if req.issued_at.abs_diff(now) > rel::REQUEST_SKEW_MS {
        bail!("the request's time is too far from this node's clock; check the clocks");
    }
    if req.expires_at.saturating_sub(req.issued_at) > rel::MAX_REQUEST_LIFETIME_MS {
        bail!("the request is valid for too long (at most an hour)");
    }
    if !rel::valid_tag(req.version.as_deref().unwrap_or("")) {
        bail!("bad version {:?}", req.version.as_deref().unwrap_or(""));
    }
    Ok(req)
}

/// The admin's AccountRecord as the tree has it (root-signed), for the
/// helper to check the request against.
fn account_record(n: &Node, id: &Bytes32) -> Option<Vec<u8>> {
    n.store
        .read()
        .tree()
        .get(webjet_core::merkle::kind::ACCOUNT, id)
        .map(|e| e.bytes.clone())
}

/// Request ids seen, with their expiry, so a request is taken once.
fn seen() -> &'static Mutex<HashMap<String, u64>> {
    static S: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Put a checked request (`plan` of `q`) in the helper's queue under `spool`.
pub fn queue(
    spool: &Path,
    remote: bool,
    plan: &rel::Plan,
    q: &rel::QueuedRequest,
    now: u64,
) -> Result<()> {
    if !remote {
        bail!("remote upgrades are turned off on this node ([upgrade] remote = false)");
    }
    let dir = rel::queue_dir(spool);
    if !dir.is_dir() {
        bail!(
            "this node has no upgrade helper (webjetup installs it; Docker containers are upgraded by replacing the image)"
        );
    }
    // The same request again (an RPC retransmitted after a lost answer):
    // taken already, nothing more to do. The helper keeps its own list too.
    if seen().lock().contains_key(&plan.id) {
        return Ok(());
    }
    if rel::request_path(spool).exists() {
        bail!("an upgrade is already waiting for the helper");
    }
    if let Ok(Some(st)) = rel::read_status(spool)
        && !st.state.finished()
        && now.saturating_sub(st.at) < rel::MAX_REQUEST_LIFETIME_MS
    {
        bail!("an upgrade to {} is running", st.version);
    }
    {
        let mut s = seen().lock();
        s.retain(|_, exp| *exp > now);
        s.insert(plan.id.clone(), plan.expires_at);
    }
    let bytes = serde_json::to_vec_pretty(q)?;
    rel::write_atomic(&dir, rel::REQUEST_FILE, &bytes, 0o600)
}

/// Check a request for this node, as the agent (against its tree, which
/// knows about revoked admins) and as the helper will, and queue it.
fn take(n: &Node, raw: &[u8]) -> Result<rel::Plan> {
    let now = now_ms();
    let (req, root) = {
        let s = n.store.read();
        (check_signed(s.view(), raw, now)?, s.root)
    };
    let account_id = crypto::opt_k32(&req.account_id);
    let account = account_record(n, &account_id)
        .ok_or_else(|| anyhow!("the admin's account record isn't in this node's tree"))?;
    let target = rel::target().ok_or_else(|| anyhow!("no Webjet release for this platform"))?;
    let plan = rel::plan(raw, &account, &root, &n.me, target, Some(RUNNING), now)?;
    let q = rel::QueuedRequest::new(raw, &account);
    queue(
        &n.cfg.upgrade.spool_dir(),
        n.cfg.upgrade.remote,
        &plan,
        &q,
        now,
    )?;
    tracing::warn!(
        version = %plan.version,
        account = %plan.account_name,
        "remote upgrade queued for the helper"
    );
    Ok(plan)
}

/// This node's upgrade state: running version, whether it takes remote
/// upgrades, and the helper's last status.
pub fn status(n: &Node) -> Value {
    let spool = n.cfg.upgrade.spool_dir();
    let helper = match rel::read_status(&spool) {
        Ok(s) => json!(s),
        Err(e) => json!({"error": format!("{e:#}")}),
    };
    json!({
        "node_id": hex::encode(n.me),
        "version": RUNNING,
        "remote": n.cfg.upgrade.remote,
        "helper": rel::queue_dir(&spool).is_dir(),
        "queued": rel::request_path(&spool).exists(),
        "status": helper,
    })
}

fn reply(r: Result<Value>) -> RpcBody {
    RpcBody::UpgradeReply(Box::new(match r {
        Ok(v) => wp::UpgradeReply {
            ok: true,
            error: None,
            version: Some(RUNNING.into()),
            status: Some(v.to_string()),
        },
        Err(e) => wp::UpgradeReply {
            ok: false,
            error: Some(format!("{e:#}")),
            version: Some(RUNNING.into()),
            status: None,
        },
    }))
}

fn queued_json(n: &Node, h: &rel::Plan) -> Value {
    json!({"node_id": hex::encode(n.me), "id": h.id, "version": h.version, "from": RUNNING, "queued": true})
}

/// An upgrade RPC. The node it names answers it, if a controller sent it;
/// a controller passes it on to that node.
pub async fn on_rpc(n: &Arc<Node>, from: Bytes32, body: RpcBody) -> Option<RpcBody> {
    let (target, raw) = match &body {
        RpcBody::UpgradeNode(u) => {
            let raw = u.request.as_deref().unwrap_or_default();
            let checked = {
                let s = n.store.read();
                check_signed(s.view(), raw, now_ms())
            };
            match checked {
                Ok(r) => (crypto::opt_k32(&r.node_id), Some(raw)),
                Err(e) => return Some(reply(Err(e))),
            }
        }
        RpcBody::GetUpgradeStatus(g) => (crypto::opt_k32(&g.node_id), None),
        _ => return None,
    };
    // Only nodes of the network ask (the request's signature is what
    // authorizes it; this keeps strangers from probing).
    let trusted = {
        let s = n.store.read();
        s.node_trusted(&from) || s.view().is_controller(&from)
    };
    if !trusted {
        return Some(reply(Err(anyhow!("untrusted caller"))));
    }
    if target == n.me {
        return Some(reply(match raw {
            Some(raw) => take(n, raw).map(|h| queued_json(n, &h)),
            None => Ok(status(n)),
        }));
    }
    // Only controllers pass requests on, and only from the node that asked
    // to the one named: never further.
    if !n.is_controller() || n.store.read().view().is_controller(&from) {
        return Some(reply(Err(anyhow!(
            "{} is not the node this is for",
            n.name_of(&n.me)
        ))));
    }
    Some(
        match crate::rpc::call(n, &target, body, FORWARD_TIMEOUT).await {
            Ok(r @ RpcBody::UpgradeReply(_)) => r,
            // Agents before 0.9.0 answer RPCs only as controllers.
            Ok(RpcBody::RpcAck(a)) => reply(Err(anyhow!(
                "{} doesn't take remote upgrades (older than 0.9.0?): {}",
                n.name_of(&target),
                a.error.unwrap_or_default()
            ))),
            Ok(_) => reply(Err(anyhow!("unexpected reply from {}", n.name_of(&target)))),
            Err(e) => reply(Err(e)),
        },
    )
}

/// The answer of an upgrade RPC as the control channel shows it.
fn from_reply(r: RpcBody) -> Result<Value> {
    match r {
        RpcBody::UpgradeReply(u) if u.ok => Ok(u
            .status
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_else(|| json!({"version": u.version}))),
        RpcBody::UpgradeReply(u) => bail!(u.error.unwrap_or_default()),
        RpcBody::RpcAck(a) => bail!(a.error.unwrap_or_default()),
        _ => bail!("unexpected reply"),
    }
}

/// Send `body` towards `target`: answered here when it is this node,
/// straight to it from a controller, else through a controller.
async fn route(n: &Arc<Node>, target: Bytes32, body: RpcBody) -> Result<Value> {
    let r = if n.is_controller() {
        crate::rpc::call(n, &target, body, FORWARD_TIMEOUT).await?
    } else {
        crate::rpc::call_any(n, body, FORWARD_TIMEOUT + Duration::from_secs(10))
            .await?
            .1
    };
    from_reply(r)
}

/// The control command `upgrade`: an admin's signed request for any node.
pub async fn request(n: &Arc<Node>, raw: Vec<u8>) -> Result<Value> {
    let req = {
        let s = n.store.read();
        check_signed(s.view(), &raw, now_ms())?
    };
    let target = crypto::opt_k32(&req.node_id);
    if target == n.me {
        let h = take(n, &raw)?;
        return Ok(queued_json(n, &h));
    }
    let body = RpcBody::UpgradeNode(Box::new(wp::UpgradeNode { request: Some(raw) }));
    route(n, target, body).await
}

/// The control command `upgrade_status` for `node` (this node by default).
pub async fn remote_status(n: &Arc<Node>, node: Option<Bytes32>) -> Result<Value> {
    let target = node.unwrap_or(n.me);
    if target == n.me {
        return Ok(status(n));
    }
    let body = RpcBody::GetUpgradeStatus(Box::new(wp::GetUpgradeStatus {
        node_id: Some(crypto::k32(&target)),
    }));
    route(n, target, body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use webjet_core::crypto::KeyPair;
    use webjet_core::testutil::Cluster;

    const T: &str = "x86_64-unknown-linux-gnu";

    fn files(version: &str) -> Vec<wp::UpgradeFile> {
        rel::TARGETS
            .iter()
            .flat_map(|t| {
                [
                    rel::archive_name(version, t),
                    rel::webjetup_name(version, t),
                ]
            })
            .map(|name| wp::UpgradeFile {
                name: Some(name),
                sha256: Some(crypto::k32(&[0xab; 32])),
            })
            .collect()
    }

    fn signed(kp: &KeyPair, account: Bytes32, node: Bytes32, version: &str, now: u64) -> Vec<u8> {
        kp.sign_obj(
            mt::UPGRADE_REQUEST,
            &wp::UpgradeRequest {
                account_id: Some(crypto::k32(&account)),
                node_id: Some(crypto::k32(&node)),
                nonce: Some(wp::Id16::from_bytes(&crypto::random16())),
                issued_at: now,
                expires_at: now + 30 * 60 * 1000,
                version: Some(version.into()),
                files: Some(files(version)),
            },
        )
    }

    #[test]
    fn only_a_valid_admin_signs_an_upgrade() {
        let mut c = Cluster::new();
        let (node, _) = c.data_node("a", "10.7.0.2", &[]);
        let store = c.store();
        let v = store.view();
        let now = now_ms();
        let (admin, admin_id) = (c.net.admin.clone(), c.net.admin_id);
        let ok = signed(&admin, admin_id, node, "v9.0.0", now);
        let r = check_signed(v, &ok, now).unwrap();
        assert_eq!(crypto::opt_k32(&r.node_id), node);
        let err = |raw: &[u8], at: u64| format!("{:#}", check_signed(v, raw, at).unwrap_err());
        // Someone else's key under the admin's id.
        let other = KeyPair::generate();
        assert!(
            err(&signed(&other, admin_id, node, "v9.0.0", now), now).contains("unexpected key")
        );
        // An unknown account.
        assert!(
            err(&signed(&other, [9; 32], node, "v9.0.0", now), now).contains("unknown account")
        );
        // Expired, from the future.
        assert!(err(&ok, now + 31 * 60 * 1000).contains("expired"));
        assert!(err(&ok, now + 10 * 60 * 1000).contains("too far"));
        assert!(
            err(
                &signed(&admin, admin_id, node, "v9.0.0", now + 600_000),
                now
            )
            .contains("too far")
        );
        // A version that isn't a release tag.
        assert!(
            err(&signed(&admin, admin_id, node, "v9.0.0/../x", now), now).contains("bad version")
        );
        // Not an upgrade request at all.
        let other_type = admin.sign_obj(
            mt::SNAPSHOT_REQUEST,
            &wp::SnapshotRequest {
                account_id: Some(crypto::k32(&admin_id)),
                issued_at: now,
            },
        );
        assert!(err(&other_type, now).contains("expected a signed UpgradeRequest"));
    }

    #[test]
    fn the_tree_holds_what_the_helper_checks() {
        // The agent hands the helper the admin's record from its tree; the
        // helper's own check (against the root key) accepts it.
        let mut c = Cluster::new();
        let (node, kp) = c.data_node("a", "10.7.0.2", &[]);
        let (n, _dir) = crate::testnode::node(&mut c, node, kp);
        let now = now_ms();
        let raw = signed(&c.net.admin, c.net.admin_id, node, "v99.0.0", now);
        let account = account_record(&n, &c.net.admin_id).expect("admin record in the tree");
        let root = n.store.read().root;
        let p = rel::plan(&raw, &account, &root, &node, T, Some(RUNNING), now).unwrap();
        assert_eq!(p.version, "v99.0.0");
        assert_eq!(p.archive.sha256, "ab".repeat(32));
        assert_eq!(p.account_id, hex::encode(c.net.admin_id));
        let old = signed(&c.net.admin, c.net.admin_id, node, "v0.0.1", now);
        let e = rel::plan(&old, &account, &root, &node, T, Some(RUNNING), now).unwrap_err();
        assert!(format!("{e:#}").contains("never downgrade"));
    }

    fn plan(id: u8, now: u64) -> rel::Plan {
        rel::Plan {
            id: hex::encode([id; 16]),
            account_id: "aa".into(),
            account_name: "alice".into(),
            version: "v0.9.0".into(),
            expires_at: now + 60_000,
            archive: rel::PinnedFile {
                name: rel::archive_name("v0.9.0", T),
                sha256: "a".repeat(64),
            },
            webjetup: rel::PinnedFile {
                name: rel::webjetup_name("v0.9.0", T),
                sha256: "b".repeat(64),
            },
        }
    }

    #[test]
    fn queueing_needs_consent_a_helper_and_a_fresh_request() {
        let d = tempfile::tempdir().unwrap();
        let spool = d.path();
        let now = now_ms();
        let q = rel::QueuedRequest::new(b"req", b"acct");
        let e = |r: Result<()>| format!("{:#}", r.unwrap_err());
        assert!(e(queue(spool, false, &plan(1, now), &q, now)).contains("turned off"));
        assert!(e(queue(spool, true, &plan(1, now), &q, now)).contains("no upgrade helper"));
        std::fs::create_dir_all(rel::queue_dir(spool)).unwrap();
        queue(spool, true, &plan(1, now), &q, now).unwrap();
        let got: rel::QueuedRequest =
            serde_json::from_slice(&std::fs::read(rel::request_path(spool)).unwrap()).unwrap();
        assert_eq!(got, q);
        assert!(e(queue(spool, true, &plan(2, now), &q, now)).contains("already waiting"));
        // The helper took it and is working on it.
        std::fs::remove_file(rel::request_path(spool)).unwrap();
        let running = rel::HelperStatus {
            id: plan(1, now).id,
            version: "v0.9.0".into(),
            from: None,
            state: rel::UpgradeState::Running,
            error: None,
            at: now,
        };
        rel::write_atomic(
            spool,
            rel::STATUS_FILE,
            &serde_json::to_vec(&running).unwrap(),
            0o644,
        )
        .unwrap();
        assert!(e(queue(spool, true, &plan(2, now), &q, now)).contains("is running"));
        let done = rel::HelperStatus {
            state: rel::UpgradeState::RolledBack,
            ..running
        };
        rel::write_atomic(
            spool,
            rel::STATUS_FILE,
            &serde_json::to_vec(&done).unwrap(),
            0o644,
        )
        .unwrap();
        // The same request again is taken already: nothing is queued.
        queue(spool, true, &plan(1, now), &q, now).unwrap();
        assert!(!rel::request_path(spool).exists());
        // A new one is queued.
        queue(spool, true, &plan(3, now), &q, now).unwrap();
        assert!(rel::request_path(spool).exists());
    }
}
