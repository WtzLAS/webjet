//! Signed requests and operations that both webjetctl and webjet-app build,
//! so the two sign exactly the same thing.

use crate::Account;
use anyhow::{Result, anyhow, bail};
use webjet_core::crypto::{self, Bytes32};
use webjet_core::types::now_ms;
use webjet_proto::{self as wp, AccountOp};

/// Give node `node` a new name.
pub fn rename_node(a: &Account, node: &Bytes32, name: &str) -> Result<Vec<u8>> {
    if !webjet_core::types::valid_name(name) {
        bail!("node names are 1–32 characters of a-z, 0-9 and -");
    }
    a.sign(AccountOp::RenameNode(Box::new(wp::RenameNode {
        node_id: Some(crypto::k32(node)),
        name: Some(name.to_string()),
    })))
}

/// Revoke node `node`; a blank reason is left out.
pub fn revoke_node(a: &Account, node: &Bytes32, reason: Option<&str>) -> Result<Vec<u8>> {
    let reason = reason
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(String::from);
    a.sign(AccountOp::TombstoneNode(Box::new(wp::TombstoneNode {
        node_id: Some(crypto::k32(node)),
        reason,
    })))
}

/// Replace node `node`'s tags (admin).
pub fn set_tags(a: &Account, node: &Bytes32, tags: &[String]) -> Result<Vec<u8>> {
    let tags = crate::tags(tags)?;
    a.sign(AccountOp::UpdateNode(Box::new(wp::UpdateNode {
        node_id: Some(crypto::k32(node)),
        set_tags: true,
        tags: Some(tags),
        ..Default::default()
    })))
}

/// The PSK epoch an agent's `status` reports.
pub fn psk_epoch(status: &serde_json::Value) -> Result<u64> {
    status["psk_epoch"]
        .as_u64()
        .ok_or_else(|| anyhow!("the agent's status has no PSK epoch"))
}

/// Advance the PSK from epoch `current` to the next (admin, §7.6). Returns
/// the new epoch and the signed operation.
pub fn rotate_psk(a: &Account, current: u64) -> Result<(u16, Vec<u8>)> {
    // The state machine takes exactly current + 1, and never 0.
    let next = u16::try_from(current)
        .ok()
        .and_then(|c| c.checked_add(1))
        .ok_or_else(|| anyhow!("PSK epoch {current} is the last one"))?;
    let op = a.sign(AccountOp::RotatePsk(Box::new(wp::RotatePsk {
        epoch_id: next,
    })))?;
    Ok((next, op))
}

/// A request to read the operation log (admins): up to `limit` entries
/// before index `before` (0 = the newest). Read-only, so it uses no
/// operation sequence number.
pub fn log_request(a: &Account, before: u64, limit: u32) -> Vec<u8> {
    a.kp.sign_obj(
        wp::msg_type::LOG_REQUEST,
        &wp::LogRequest {
            account_id: Some(crypto::k32(&a.id)),
            issued_at: now_ms(),
            before,
            limit,
        },
    )
}

/// A request to export the controller state (admins).
pub fn snapshot_request(a: &Account) -> Vec<u8> {
    a.kp.sign_obj(
        wp::msg_type::SNAPSHOT_REQUEST,
        &wp::SnapshotRequest {
            account_id: Some(crypto::k32(&a.id)),
            issued_at: now_ms(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use webjet_core::crypto::KeyPair;

    fn account(dir: &std::path::Path) -> Account {
        Account {
            name: "bob".into(),
            id: [7; 32],
            kp: KeyPair::generate(),
            dir: dir.to_path_buf(),
        }
    }

    fn op(raw: &[u8]) -> AccountOp {
        let v = crypto::open_envelope(raw).unwrap();
        let o: wp::SignedOp = v.decode().unwrap();
        o.op.unwrap()
    }

    #[test]
    fn operations() {
        let d = tempfile::tempdir().unwrap();
        let a = account(d.path());
        let node = [3; 32];
        assert!(rename_node(&a, &node, "Bad Name").is_err());
        match op(&rename_node(&a, &node, "web-1").unwrap()) {
            AccountOp::RenameNode(r) => assert_eq!(r.name.as_deref(), Some("web-1")),
            o => panic!("{o:?}"),
        }
        match op(&revoke_node(&a, &node, Some("  ")).unwrap()) {
            AccountOp::TombstoneNode(t) => assert_eq!(t.reason, None),
            o => panic!("{o:?}"),
        }
        assert!(set_tags(&a, &node, &["notatag".into()]).is_err());
        match op(&set_tags(&a, &node, &["tag:a".into()]).unwrap()) {
            AccountOp::UpdateNode(u) => assert!(u.set_tags && u.tags == Some(vec!["tag:a".into()])),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn psk_rotation_names_the_next_epoch_or_fails() {
        let d = tempfile::tempdir().unwrap();
        let a = account(d.path());
        let (next, raw) = rotate_psk(&a, 4).unwrap();
        assert_eq!(next, 5);
        match op(&raw) {
            AccountOp::RotatePsk(r) => assert_eq!(r.epoch_id, 5),
            o => panic!("{o:?}"),
        }
        assert!(rotate_psk(&a, u64::from(u16::MAX)).is_err());
        assert!(rotate_psk(&a, 1 << 20).is_err());
        assert!(psk_epoch(&serde_json::json!({})).is_err());
        assert_eq!(psk_epoch(&serde_json::json!({"psk_epoch": 3})).unwrap(), 3);
    }

    #[test]
    fn requests_name_the_account() {
        let d = tempfile::tempdir().unwrap();
        let a = account(d.path());
        let v = crypto::open_expect(
            &log_request(&a, 0, 10),
            wp::msg_type::LOG_REQUEST,
            &[a.kp.public()],
        )
        .unwrap();
        let r: wp::LogRequest = v.decode().unwrap();
        assert_eq!(crypto::opt_k32(&r.account_id), a.id);
        let v = crypto::open_expect(
            &snapshot_request(&a),
            wp::msg_type::SNAPSHOT_REQUEST,
            &[a.kp.public()],
        )
        .unwrap();
        let r: wp::SnapshotRequest = v.decode().unwrap();
        assert_eq!(crypto::opt_k32(&r.account_id), a.id);
    }
}
