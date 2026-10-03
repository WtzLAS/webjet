//! Tree leaf encodings (§6.4, §15.3).
//!
//! Controller-built leaves (NodeRecord, committed Tombstone, Policy, DnsConfig,
//! Seeds, Limits, Validity, TransportConfig) are unsigned `Leaf` wrappers.
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
        _ => {
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
                _ => bail!("leaf kind {k} with type {}", mt::name(ty)),
            }
        }
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
