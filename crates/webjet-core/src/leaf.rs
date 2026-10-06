//! Tree leaf encodings (§6.4, §15.3).
//!
//! Controller-built leaves (NodeRecord, committed Tombstone, Policy, DnsConfig,
//! Seeds, Limits, Validity, TransportConfig, NodeConfig, ControllerSettings)
//! are unsigned `Leaf`
//! wrappers.
//! Account leaves keep their own signature: their bytes are the `Signed`
//! envelope of the AccountRecord or AccountTombstone (§6.10).

use crate::crypto::{Bytes32, Verified, open_envelope};
use crate::merkle::kind;
use anyhow::{Result, anyhow, bail};
use webjet_proto::{self as wp, Decodable, Encodable, msg_type as mt};

pub const SINGLETON: Bytes32 = [0u8; 32];

pub fn wrap(ty: u16, body: Vec<u8>) -> Vec<u8> {
    wp::Leaf {
        type_: ty,
        schema: wp::SCHEMA_V1,
        body: Some(body),
    }
    .encode_bytes()
}

#[derive(Clone, Debug)]
pub enum LeafValue {
    Node(wp::NodeRecord),
    NodeTombstone(wp::Tombstone),
    Account(wp::AccountRecord, Verified),
    AccountTombstone(wp::AccountTombstone, Verified),
    Policy(wp::Policy),
    Dns(wp::DnsConfig),
    Seeds(wp::Seeds),
    Limits(wp::Limits),
    Validity(wp::Validity),
    Transport(wp::TransportConfig),
    NodeConfig(wp::NodeConfig),
    Controllers(wp::ControllerSettings),
    /// A leaf kind this software doesn't know (added by a later release):
    /// kept and hashed, otherwise ignored, so the tree still syncs (§15.7).
    Unknown,
}

fn unwrap_leaf(bytes: &[u8]) -> Result<(u16, Vec<u8>)> {
    let l = wp::Leaf::decode_bytes(bytes)?;
    if l.schema != wp::SCHEMA_V1 {
        bail!("unsupported leaf schema {}", l.schema);
    }
    Ok((l.type_, l.body.ok_or_else(|| anyhow!("leaf without body"))?))
}

/// Decode and semantically check a leaf found at `(k, key)`.
pub fn decode(k: u8, key: &Bytes32, bytes: &[u8]) -> Result<LeafValue> {
    let v = match k {
        kind::NODE => {
            let (ty, body) = unwrap_leaf(bytes)?;
            match ty {
                mt::NODE_RECORD => {
                    let r = wp::NodeRecord::decode_bytes(&body)?;
                    crate::validate::node_record(&r)?;
                    if r.node_id.map(|k| k.to_bytes()) != Some(*key) {
                        bail!("node leaf under the wrong key");
                    }
                    LeafValue::Node(r)
                }
                mt::TOMBSTONE => {
                    let t = wp::Tombstone::decode_bytes(&body)?;
                    if t.node_id.map(|k| k.to_bytes()) != Some(*key) {
                        bail!("tombstone leaf under the wrong key");
                    }
                    LeafValue::NodeTombstone(t)
                }
                _ => bail!("unexpected leaf type {} for a node", mt::name(ty)),
            }
        }
        kind::ACCOUNT => {
            let v = open_envelope(bytes)?;
            match v.ty {
                mt::ACCOUNT_RECORD => {
                    let r: wp::AccountRecord = v.decode()?;
                    crate::validate::account_record(&r)?;
                    if r.account_id.map(|k| k.to_bytes()) != Some(*key) {
                        bail!("account leaf under the wrong key");
                    }
                    LeafValue::Account(r, v)
                }
                mt::ACCOUNT_TOMBSTONE => {
                    let t: wp::AccountTombstone = v.decode()?;
                    if t.account_id.map(|k| k.to_bytes()) != Some(*key) {
                        bail!("account tombstone under the wrong key");
                    }
                    LeafValue::AccountTombstone(t, v)
                }
                _ => bail!("unexpected leaf type {} for an account", mt::name(v.ty)),
            }
        }
        kind::NODE_CONFIG => {
            let (ty, body) = unwrap_leaf(bytes)?;
            if ty != mt::NODE_CONFIG {
                bail!("unexpected leaf type {} for a node config", mt::name(ty));
            }
            let c = wp::NodeConfig::decode_bytes(&body)?;
            if c.node_id.map(|k| k.to_bytes()) != Some(*key) {
                bail!("node config leaf under the wrong key");
            }
            LeafValue::NodeConfig(c)
        }
        kind::POLICY
        | kind::DNS
        | kind::SEEDS
        | kind::LIMITS
        | kind::VALIDITY
        | kind::TRANSPORT
        | kind::CONTROLLERS => {
            if *key != SINGLETON {
                bail!("singleton leaf with a non-zero key");
            }
            let (ty, body) = unwrap_leaf(bytes)?;
            match (k, ty) {
                (kind::POLICY, mt::POLICY) => LeafValue::Policy(wp::Policy::decode_bytes(&body)?),
                (kind::DNS, mt::DNS_CONFIG) => LeafValue::Dns(wp::DnsConfig::decode_bytes(&body)?),
                (kind::SEEDS, mt::SEEDS) => LeafValue::Seeds(wp::Seeds::decode_bytes(&body)?),
                (kind::LIMITS, mt::LIMITS) => LeafValue::Limits(wp::Limits::decode_bytes(&body)?),
                (kind::VALIDITY, mt::VALIDITY) => {
                    LeafValue::Validity(wp::Validity::decode_bytes(&body)?)
                }
                (kind::TRANSPORT, mt::TRANSPORT_CONFIG) => {
                    LeafValue::Transport(wp::TransportConfig::decode_bytes(&body)?)
                }
                (kind::CONTROLLERS, mt::CONTROLLER_SETTINGS) => {
                    LeafValue::Controllers(wp::ControllerSettings::decode_bytes(&body)?)
                }
                _ => bail!("leaf kind {k} with type {}", mt::name(ty)),
            }
        }
        _ => LeafValue::Unknown,
    };
    Ok(v)
}

/// Version of a leaf, for the "only newer versions" merge rules (§10.2).
pub fn version(v: &LeafValue) -> u64 {
    match v {
        LeafValue::Node(r) => r.version,
        LeafValue::NodeTombstone(t) => t.version,
        LeafValue::Account(r, _) => r.version,
        LeafValue::AccountTombstone(t, _) => t.version,
        LeafValue::Policy(p) => p.version,
        LeafValue::Dns(d) => d.version,
        LeafValue::Seeds(s) => s.version,
        LeafValue::Limits(l) => l.version,
        LeafValue::Validity(v) => v.valid_until,
        LeafValue::Transport(t) => t.version,
        LeafValue::NodeConfig(c) => c.version,
        LeafValue::Controllers(c) => c.version,
        LeafValue::Unknown => 0,
    }
}

pub fn encode_node(r: &wp::NodeRecord) -> Vec<u8> {
    wrap(mt::NODE_RECORD, r.encode_bytes())
}
pub fn encode_tombstone(t: &wp::Tombstone) -> Vec<u8> {
    wrap(mt::TOMBSTONE, t.encode_bytes())
}
pub fn encode_policy(p: &wp::Policy) -> Vec<u8> {
    wrap(mt::POLICY, p.encode_bytes())
}
pub fn encode_dns(d: &wp::DnsConfig) -> Vec<u8> {
    wrap(mt::DNS_CONFIG, d.encode_bytes())
}
pub fn encode_seeds(s: &wp::Seeds) -> Vec<u8> {
    wrap(mt::SEEDS, s.encode_bytes())
}
pub fn encode_limits(l: &wp::Limits) -> Vec<u8> {
    wrap(mt::LIMITS, l.encode_bytes())
}
pub fn encode_validity(v: &wp::Validity) -> Vec<u8> {
    wrap(mt::VALIDITY, v.encode_bytes())
}
pub fn encode_transport(t: &wp::TransportConfig) -> Vec<u8> {
    wrap(mt::TRANSPORT_CONFIG, t.encode_bytes())
}
pub fn encode_node_config(c: &wp::NodeConfig) -> Vec<u8> {
    wrap(mt::NODE_CONFIG, c.encode_bytes())
}
pub fn encode_controllers(c: &wp::ControllerSettings) -> Vec<u8> {
    wrap(mt::CONTROLLER_SETTINGS, c.encode_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, k32};

    fn record(id: Bytes32) -> wp::NodeRecord {
        wp::NodeRecord {
            node_id: Some(k32(&id)),
            identity_key: Some(k32(&[2; 32])),
            owner: Some(k32(&[3; 32])),
            name: Some("web-01".into()),
            version: 7,
            ..Default::default()
        }
    }

    #[test]
    fn node_leaves_roundtrip() {
        let id = [1; 32];
        let v = decode(kind::NODE, &id, &encode_node(&record(id))).unwrap();
        assert!(matches!(&v, LeafValue::Node(r) if r.name.as_deref() == Some("web-01")));
        assert_eq!(version(&v), 7);

        let t = wp::Tombstone {
            node_id: Some(k32(&id)),
            version: 9,
            reason: None,
        };
        let v = decode(kind::NODE, &id, &encode_tombstone(&t)).unwrap();
        assert!(matches!(v, LeafValue::NodeTombstone(_)));
        assert_eq!(version(&v), 9);
    }

    #[test]
    fn node_leaves_rejected() {
        let id = [1; 32];
        // Stored under another node's key.
        assert!(decode(kind::NODE, &[9; 32], &encode_node(&record(id))).is_err());
        let t = wp::Tombstone {
            node_id: Some(k32(&id)),
            ..Default::default()
        };
        assert!(decode(kind::NODE, &[9; 32], &encode_tombstone(&t)).is_err());
        // Semantically invalid record.
        let bad = wp::NodeRecord {
            name: Some("NO".into()),
            ..record(id)
        };
        assert!(decode(kind::NODE, &id, &encode_node(&bad)).is_err());
        // A policy leaf in the node kind.
        assert!(decode(kind::NODE, &id, &encode_policy(&wp::Policy::default())).is_err());
        // Garbage, unknown schema, missing body.
        assert!(decode(kind::NODE, &id, b"garbage").is_err());
        let future = wp::Leaf {
            type_: mt::NODE_RECORD,
            schema: wp::SCHEMA_V1 + 1,
            body: Some(record(id).encode_bytes()),
        };
        assert!(decode(kind::NODE, &id, &future.encode_bytes()).is_err());
        let empty = wp::Leaf {
            type_: mt::NODE_RECORD,
            schema: wp::SCHEMA_V1,
            body: None,
        };
        assert!(decode(kind::NODE, &id, &empty.encode_bytes()).is_err());
    }

    #[test]
    fn account_leaves_are_signed_envelopes() {
        let kp = KeyPair::generate();
        let id = [4; 32];
        let r = wp::AccountRecord {
            account_id: Some(k32(&id)),
            account_key: Some(k32(&kp.public())),
            name: Some("alice".into()),
            issuer_root: true,
            version: 3,
            ..Default::default()
        };
        let raw = kp.sign_obj(mt::ACCOUNT_RECORD, &r);
        let v = decode(kind::ACCOUNT, &id, &raw).unwrap();
        assert!(matches!(&v, LeafValue::Account(_, ver) if ver.signer == kp.public()));
        assert_eq!(version(&v), 3);
        assert!(decode(kind::ACCOUNT, &[5; 32], &raw).is_err());

        // A flipped bit breaks the signature.
        let mut tampered = raw;
        let n = tampered.len();
        tampered[n - 1] ^= 1;
        assert!(decode(kind::ACCOUNT, &id, &tampered).is_err());
        // An unsigned leaf is not an account.
        assert!(
            decode(
                kind::ACCOUNT,
                &id,
                &wrap(mt::ACCOUNT_RECORD, r.encode_bytes())
            )
            .is_err()
        );

        let t = wp::AccountTombstone {
            account_id: Some(k32(&id)),
            version: 4,
            ..Default::default()
        };
        let raw = kp.sign_obj(mt::ACCOUNT_TOMBSTONE, &t);
        let v = decode(kind::ACCOUNT, &id, &raw).unwrap();
        assert!(matches!(v, LeafValue::AccountTombstone(..)));
        assert_eq!(version(&v), 4);
        assert!(decode(kind::ACCOUNT, &[5; 32], &raw).is_err());
        // A signed node record is not an account leaf.
        let raw = kp.sign_obj(mt::NODE_RECORD, &record(id));
        assert!(decode(kind::ACCOUNT, &id, &raw).is_err());
    }

    #[test]
    fn node_config_leaf() {
        let id = [6; 32];
        let c = wp::NodeConfig {
            node_id: Some(k32(&id)),
            version: 2,
            ..Default::default()
        };
        let v = decode(kind::NODE_CONFIG, &id, &encode_node_config(&c)).unwrap();
        assert_eq!(version(&v), 2);
        assert!(decode(kind::NODE_CONFIG, &[7; 32], &encode_node_config(&c)).is_err());
        assert!(decode(kind::NODE_CONFIG, &id, &encode_node(&record(id))).is_err());
    }

    #[test]
    fn singleton_leaves() {
        let cases: Vec<(u8, Vec<u8>, u64)> = vec![
            (
                kind::POLICY,
                encode_policy(&wp::Policy {
                    version: 11,
                    ..Default::default()
                }),
                11,
            ),
            (
                kind::DNS,
                encode_dns(&wp::DnsConfig {
                    version: 12,
                    ..Default::default()
                }),
                12,
            ),
            (
                kind::SEEDS,
                encode_seeds(&wp::Seeds {
                    version: 13,
                    ..Default::default()
                }),
                13,
            ),
            (
                kind::LIMITS,
                encode_limits(&wp::Limits {
                    version: 14,
                    ..Default::default()
                }),
                14,
            ),
            (
                kind::VALIDITY,
                encode_validity(&wp::Validity { valid_until: 15 }),
                15,
            ),
            (
                kind::TRANSPORT,
                encode_transport(&wp::TransportConfig {
                    version: 16,
                    ..Default::default()
                }),
                16,
            ),
            (
                kind::CONTROLLERS,
                encode_controllers(&wp::ControllerSettings {
                    version: 17,
                    ..Default::default()
                }),
                17,
            ),
        ];
        for (i, (k, bytes, ver)) in cases.iter().enumerate() {
            let v = decode(*k, &SINGLETON, bytes).unwrap();
            assert_eq!(version(&v), *ver, "kind {k}");
            // Never under a non-zero key.
            assert!(decode(*k, &[1; 32], bytes).is_err(), "kind {k}");
            // Never in another singleton kind.
            let (other, other_bytes, _) = &cases[(i + 1) % cases.len()];
            assert!(
                decode(*k, &SINGLETON, other_bytes).is_err(),
                "{other} in {k}"
            );
        }
    }

    #[test]
    fn unknown_kinds_are_kept() {
        // A later release's leaf kind: any bytes, version 0.
        let v = decode(200, &[1; 32], b"whatever").unwrap();
        assert!(matches!(v, LeafValue::Unknown));
        assert_eq!(version(&v), 0);
    }
}
