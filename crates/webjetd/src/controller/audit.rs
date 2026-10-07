//! The audit trail an admin reads from the replicated log: one summary per
//! committed entry still in the log (webjet-app's Merkle tab). Reading it
//! takes a `LogRequest` signed by a valid admin account; secrets carried in
//! entries (the leader's random PSK, the camouflage private key) are never
//! part of a summary.

use anyhow::{Result, bail};
use webjet_core::crypto::{self, Bytes32};
use webjet_core::merkle::leaf_hash;
use webjet_core::store::View;
use webjet_core::types::MINUTE;
use webjet_proto::{self as wp, AccountOp, Decodable, EntryPayload, msg_type as mt};

/// How far a request's `issued_at` may be from the controller's clock.
pub const REQUEST_SKEW: u64 = 5 * MINUTE;
/// Most entries in one reply.
pub const MAX_RECORDS: u32 = 200;

/// Check a signed `LogRequest`: a valid admin account signed it with its
/// current key, recently. Returns the request.
pub fn check_request(view: &View, raw: &[u8], now: u64) -> Result<wp::LogRequest> {
    let req: wp::LogRequest = crate::admin::signed_request(
        view,
        raw,
        mt::LOG_REQUEST,
        "read the operation log",
        |r: &wp::LogRequest| crypto::opt_k32(&r.account_id),
    )?;
    recent(req.issued_at, now)?;
    Ok(req)
}

/// Check a signed `SnapshotRequest` the same way: a valid admin, its current
/// key, recently. The reply holds every secret the controllers keep (PSKs,
/// the camouflage key), so only admins get it.
pub fn check_snapshot_request(view: &View, raw: &[u8], now: u64) -> Result<()> {
    let req: wp::SnapshotRequest = crate::admin::signed_request(
        view,
        raw,
        mt::SNAPSHOT_REQUEST,
        "export the controller state",
        |r: &wp::SnapshotRequest| crypto::opt_k32(&r.account_id),
    )?;
    recent(req.issued_at, now)
}

fn recent(issued_at: u64, now: u64) -> Result<()> {
    if issued_at.abs_diff(now) > REQUEST_SKEW {
        bail!("the request's time is too far from the controller's clock; check the clocks");
    }
    Ok(())
}

/// The indices a request asks for, oldest first: up to `limit` entries
/// before `before` (0 = after the newest), within `first..=commit`.
pub fn window(req: &wp::LogRequest, first: u64, commit: u64) -> std::ops::RangeInclusive<u64> {
    let last = match req.before {
        0 => commit,
        b => b.saturating_sub(1).min(commit),
    };
    let limit = u64::from(req.limit.clamp(1, MAX_RECORDS));
    let from = last.saturating_sub(limit - 1).max(first);
    from..=last
}

pub fn op_name(op: &AccountOp) -> &'static str {
    match op {
        AccountOp::CreateEnrollment(_) => "CreateEnrollment",
        AccountOp::RenameNode(_) => "RenameNode",
        AccountOp::UpdateNode(_) => "UpdateNode",
        AccountOp::TombstoneNode(_) => "TombstoneNode",
        AccountOp::RekeyNode(_) => "RekeyNode",
        AccountOp::PutAccount(_) => "PutAccount",
        AccountOp::TombstoneAccount(_) => "TombstoneAccount",
        AccountOp::SetPolicy(_) => "SetPolicy",
        AccountOp::SetDns(_) => "SetDns",
        AccountOp::SetSeeds(_) => "SetSeeds",
        AccountOp::SetLimits(_) => "SetLimits",
        AccountOp::SetTransport(_) => "SetTransport",
        AccountOp::SetCamouflageSecret(_) => "SetCamouflageSecret",
        AccountOp::ChangeMembership(_) => "ChangeMembership",
        AccountOp::RotatePsk(_) => "RotatePsk",
        AccountOp::SetNetworkConfig(_) => "SetNetworkConfig",
        AccountOp::SetNodeConfig(_) => "SetNodeConfig",
    }
}

fn payload_name(p: &EntryPayload) -> &'static str {
    match p {
        EntryPayload::OpEntry(_) => "OpEntry",
        EntryPayload::RootAccountEntry(_) => "RootAccountEntry",
        EntryPayload::SetStateVersionEntry(_) => "SetStateVersionEntry",
        EntryPayload::RedeemEnrollmentEntry(_) => "RedeemEnrollmentEntry",
        EntryPayload::RotateNodeKeyEntry(_) => "RotateNodeKeyEntry",
        EntryPayload::ExtendValidityEntry(_) => "ExtendValidityEntry",
        EntryPayload::ExpireEnrollmentsEntry(_) => "ExpireEnrollmentsEntry",
        EntryPayload::NoopEntry(_) => "NoopEntry",
        EntryPayload::GenesisEntry(_) => "GenesisEntry",
        EntryPayload::MembershipEntry(_) => "MembershipEntry",
        EntryPayload::AutoMembershipEntry(_) => "AutoMembershipEntry",
        EntryPayload::ForceNewClusterEntry(_) => "ForceNewClusterEntry",
    }
}

/// The signer and type of a signed envelope, without trusting it further
/// (the entry was checked when it was applied).
fn envelope(raw: &[u8]) -> Option<(Bytes32, u16)> {
    crypto::open_envelope(raw).ok().map(|v| (v.signer, v.ty))
}

/// Summarize one committed log entry.
pub fn summarize(bytes: &[u8], description: Option<String>) -> Option<wp::LogRecord> {
    let e = wp::LogEntry::decode_bytes(bytes).ok()?;
    let mut r = wp::LogRecord {
        index: e.index,
        term: e.term,
        timestamp: e.timestamp,
        description,
        ..Default::default()
    };
    let key = |k: Bytes32| Some(crypto::k32(&k));
    if let Some(p) = &e.payload {
        r.payload = Some(payload_name(p).into());
        match p {
            EntryPayload::OpEntry(o) => {
                if let Some(v) = o
                    .signed_op
                    .as_deref()
                    .and_then(|b| crypto::open_envelope(b).ok())
                {
                    r.signer_key = key(v.signer);
                    if let Ok(so) = v.decode::<wp::SignedOp>() {
                        r.account_id = so.signer;
                        r.op_seq = so.op_seq;
                        r.issued_at = so.issued_at;
                        r.op = so.op.as_ref().map(|o| op_name(o).into());
                    }
                }
            }
            EntryPayload::RootAccountEntry(a) => {
                if let Some((s, ty)) = a.record.as_deref().and_then(envelope) {
                    r.signer_key = key(s);
                    r.op = Some(mt::name(ty).into());
                }
            }
            EntryPayload::SetStateVersionEntry(s) => {
                if let Some((k, ty)) = s.state_version.as_deref().and_then(envelope) {
                    r.signer_key = key(k);
                    r.op = Some(mt::name(ty).into());
                }
            }
            EntryPayload::RotateNodeKeyEntry(k) => {
                if let Some((s, ty)) = k.rotation.as_deref().and_then(envelope) {
                    r.signer_key = key(s);
                    r.op = Some(mt::name(ty).into());
                }
            }
            EntryPayload::GenesisEntry(g) => {
                if let Some(g) = g
                    .genesis
                    .as_deref()
                    .and_then(|b| wp::Genesis::decode_bytes(b).ok())
                {
                    r.signer_key = g.root_key;
                }
                r.op = Some("Genesis".into());
            }
            EntryPayload::RedeemEnrollmentEntry(x) => {
                // The node redeemed its token with its identity key.
                r.signer_key = x.identity_key;
                r.op = Some("RedeemEnrollment".into());
            }
            _ => {}
        }
    }
    r.leaves = Some(
        e.leaves
            .unwrap_or_default()
            .into_iter()
            .map(|l| {
                let k = crypto::opt_k32(&l.key);
                let bytes = l.bytes.unwrap_or_default();
                wp::LogLeaf {
                    kind: l.kind,
                    key: l.key,
                    hash: (!bytes.is_empty()).then(|| crypto::k32(&leaf_hash(l.kind, &k, &bytes))),
                    deleted: bytes.is_empty(),
                }
            })
            .collect(),
    );
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use webjet_core::crypto::KeyPair;
    use webjet_core::store::AccountInfo;
    use webjet_proto::Encodable;

    fn view_with(id: Bytes32, key: Bytes32, admin: bool, valid: bool) -> View {
        let mut v = View::default();
        v.accounts.insert(
            id,
            AccountInfo {
                id,
                rec: wp::AccountRecord::default(),
                key,
                name: "alice".into(),
                admin,
                valid,
            },
        );
        v
    }

    fn request(kp: &KeyPair, id: Bytes32, at: u64) -> Vec<u8> {
        kp.sign_obj(
            mt::LOG_REQUEST,
            &wp::LogRequest {
                account_id: Some(crypto::k32(&id)),
                issued_at: at,
                before: 0,
                limit: 10,
            },
        )
    }

    #[test]
    fn only_a_current_admin_may_read() {
        let kp = KeyPair::generate();
        let id = [3u8; 32];
        let now = 1_000_000_000;
        let raw = request(&kp, id, now);
        assert!(check_request(&view_with(id, kp.public(), true, true), &raw, now).is_ok());
        for (v, why) in [
            (view_with(id, kp.public(), false, true), "admins"),
            (view_with(id, kp.public(), true, false), "admins"),
            (view_with([4; 32], kp.public(), true, true), "unknown"),
            (view_with(id, KeyPair::generate().public(), true, true), ""),
        ] {
            let e = check_request(&v, &raw, now).unwrap_err().to_string();
            assert!(e.contains(why), "{e}");
        }
        let v = view_with(id, kp.public(), true, true);
        let old = request(&kp, id, now - REQUEST_SKEW - 1);
        assert!(check_request(&v, &old, now).is_err(), "stale request");
        // Another signed type is refused.
        let other = kp.sign_obj(mt::SIGNED_OP, &wp::SignedOp::default());
        assert!(check_request(&v, &other, now).is_err());
    }

    #[test]
    fn window_is_clamped() {
        let req = |before, limit| wp::LogRequest {
            before,
            limit,
            ..Default::default()
        };
        assert_eq!(window(&req(0, 10), 1, 100), 91..=100);
        assert_eq!(window(&req(50, 10), 1, 100), 40..=49);
        assert_eq!(window(&req(5, 10), 3, 100), 3..=4);
        assert_eq!(window(&req(0, 0), 1, 100), 100..=100, "at least one");
        assert_eq!(
            window(&req(0, 10_000), 1, 1000).count(),
            MAX_RECORDS as usize
        );
        assert!(window(&req(3, 10), 3, 100).is_empty(), "nothing older");
    }

    #[test]
    fn summary_names_the_signer_and_leaves() {
        let kp = KeyPair::generate();
        let id = [9u8; 32];
        let op = webjet_core::statemachine::ops::sign_op(
            &kp,
            &id,
            7,
            1234,
            AccountOp::RotatePsk(Box::new(wp::RotatePsk { epoch_id: 2 })),
        );
        let entry = wp::LogEntry {
            term: 2,
            index: 42,
            timestamp: 99,
            payload: Some(webjet_core::statemachine::ops::op_entry(op)),
            random: Some(Box::new(wp::EntryRandom {
                node_id: None,
                psk: Some(crypto::k32(&[0xAA; 32])),
            })),
            leaves: Some(vec![
                wp::LeafUpdate {
                    kind: 1,
                    key: Some(crypto::k32(&[1; 32])),
                    bytes: Some(vec![1, 2, 3]),
                },
                wp::LeafUpdate {
                    kind: 2,
                    key: Some(crypto::k32(&[2; 32])),
                    bytes: None,
                },
            ]),
        };
        let r = summarize(&entry.encode_bytes(), Some("rotate PSK".into())).unwrap();
        assert_eq!((r.index, r.term, r.timestamp), (42, 2, 99));
        assert_eq!(r.payload.as_deref(), Some("OpEntry"));
        assert_eq!(r.op.as_deref(), Some("RotatePsk"));
        assert_eq!(r.signer_key.map(|k| k.to_bytes()), Some(kp.public()));
        assert_eq!(r.account_id.map(|k| k.to_bytes()), Some(id));
        assert_eq!((r.op_seq, r.issued_at), (7, 1234));
        let leaves = r.leaves.unwrap();
        assert_eq!(
            leaves[0].hash.map(|h| h.to_bytes()),
            Some(leaf_hash(1, &[1; 32], &[1, 2, 3]))
        );
        assert!(leaves[1].deleted && leaves[1].hash.is_none());
        // The PSK the leader chose is not in the summary.
        let reply = wp::LogReply {
            records: Some(vec![summarize(&entry.encode_bytes(), None).unwrap()]),
            ..Default::default()
        };
        let enc = webjet_proto::encode::<wp::LogReply, _>(&reply);
        assert!(!enc.windows(32).any(|w| w == [0xAA; 32]));
        assert!(summarize(b"junk", None).is_none());
    }
}
