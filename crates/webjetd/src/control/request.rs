//! Control-channel requests as one typed enum, shared by webjetd (which
//! parses them), webjetctl and webjet-app (which send them).
//!
//! The wire form is unchanged from the hand-built JSON it replaces: one
//! object per line with the command name in `cmd` and its arguments beside
//! it (`{"cmd": "submit_op", "signed": "<base64>"}`). Binary arguments are
//! base64 strings, node ids hex. Agents and clients of other versions
//! therefore still understand each other; an argument added later must be
//! optional (`Option` or `#[serde(default)]`) so old clients keep working.

use serde::{Deserialize, Serialize};
use webjet_core::crypto::Bytes32;

/// One control command and its arguments. Every variant must also be listed
/// in [`super::COMMANDS`] with its access class (a unit test checks).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    Peers,
    Sessions,
    Conntrack,
    Proxy,
    Topology,
    Nodes,
    Accounts,
    Tree,
    /// A node's configuration and what is in force for it; `None`: this node.
    NodeConfig {
        #[serde(default, with = "hex_id", skip_serializing_if = "Option::is_none")]
        node: Option<Bytes32>,
    },
    /// A SignedOp.
    SubmitOp {
        #[serde(with = "base64")]
        signed: Vec<u8>,
    },
    /// Offline-signed items (certificates, tombstones).
    SubmitOffline {
        #[serde(with = "base64_list")]
        items: Vec<Vec<u8>>,
    },
    /// Any signed envelope an admin or the root produced.
    SubmitSigned {
        #[serde(with = "base64")]
        signed: Vec<u8>,
    },
    EnrollInfo,
    /// Ping an overlay address, node name or node id.
    Ping {
        target: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        count: Option<u64>,
        /// Payload bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size: Option<u64>,
    },
    /// A controller's signing-key certificate request; `None`: this node's.
    CertRequest {
        #[serde(default, with = "hex_id", skip_serializing_if = "Option::is_none")]
        node: Option<Bytes32>,
    },
    Controller,
    /// A bootstrapping controller redeems its own enrollment token.
    RedeemSelf {
        #[serde(with = "base64")]
        token: Vec<u8>,
    },
    /// OpenMetrics text; `all`: every node's report (controllers only).
    Metrics {
        #[serde(default)]
        all: bool,
    },
    Reports,
    Head,
    Merkle,
    /// A page of the operation log, for an admin-signed LogRequest.
    Log {
        #[serde(with = "base64")]
        request: Vec<u8>,
    },
    /// The controller's snapshot, for an admin-signed SnapshotRequest.
    Snapshot {
        #[serde(with = "base64")]
        request: Vec<u8>,
    },
}

impl Request {
    /// The request as its JSON line (without the newline).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// The command name (`cmd`), for messages.
    pub fn name(&self) -> String {
        self.to_json()["cmd"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }
}

mod base64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::state::b64(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        crate::state::unb64(&s).map_err(|e| D::Error::custom(format!("{e:#}")))
    }
}

mod base64_list {
    use serde::{Deserialize, Deserializer, Serializer, de::Error, ser::SerializeSeq};

    pub fn serialize<S: Serializer>(items: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(items.len()))?;
        for b in items {
            seq.serialize_element(&crate::state::b64(b))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| crate::state::unb64(s).map_err(|e| D::Error::custom(format!("{e:#}"))))
            .collect()
    }
}

mod hex_id {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use webjet_core::crypto::{self, Bytes32};

    pub fn serialize<S: Serializer>(id: &Option<Bytes32>, s: S) -> Result<S::Ok, S::Error> {
        match id {
            Some(id) => s.serialize_str(&hex::encode(id)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Bytes32>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|h| crypto::parse_hex32(&h).ok_or_else(|| D::Error::custom("bad node id")))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(v: serde_json::Value) -> Request {
        serde_json::from_value(v).expect("request")
    }

    #[test]
    fn the_wire_form_is_the_old_hand_built_json() {
        // What webjetctl and webjet-app sent before the enum existed; agents
        // of every version must keep reading it, and must read what the enum
        // writes the same way.
        let id = [7u8; 32];
        let cases = [
            (Request::Status, json!({"cmd": "status"})),
            (Request::EnrollInfo, json!({"cmd": "enroll_info"})),
            (
                Request::SubmitOp {
                    signed: b"op".to_vec(),
                },
                json!({"cmd": "submit_op", "signed": crate::state::b64(b"op")}),
            ),
            (
                Request::SubmitOffline {
                    items: vec![b"a".to_vec(), b"b".to_vec()],
                },
                json!({"cmd": "submit_offline", "items": [crate::state::b64(b"a"), crate::state::b64(b"b")]}),
            ),
            (
                Request::NodeConfig { node: Some(id) },
                json!({"cmd": "node_config", "node": hex::encode(id)}),
            ),
            (
                Request::NodeConfig { node: None },
                json!({"cmd": "node_config"}),
            ),
            (
                Request::CertRequest { node: None },
                json!({"cmd": "cert_request"}),
            ),
            (
                Request::Ping {
                    target: "a".into(),
                    count: Some(3),
                    size: Some(0),
                },
                json!({"cmd": "ping", "target": "a", "count": 3, "size": 0}),
            ),
            (
                Request::Metrics { all: true },
                json!({"cmd": "metrics", "all": true}),
            ),
            (
                Request::RedeemSelf {
                    token: b"t".to_vec(),
                },
                json!({"cmd": "redeem_self", "token": crate::state::b64(b"t")}),
            ),
            (
                Request::Log {
                    request: b"r".to_vec(),
                },
                json!({"cmd": "log", "request": crate::state::b64(b"r")}),
            ),
        ];
        for (req, wire) in cases {
            assert_eq!(req.to_json(), wire, "{req:?}");
            assert_eq!(parse(wire), req);
        }
    }

    #[test]
    fn optional_arguments_may_be_missing_or_null() {
        assert_eq!(
            parse(json!({"cmd": "metrics"})),
            Request::Metrics { all: false }
        );
        assert_eq!(
            parse(json!({"cmd": "node_config", "node": null})),
            Request::NodeConfig { node: None }
        );
        assert_eq!(
            parse(json!({"cmd": "ping", "target": "x"})),
            Request::Ping {
                target: "x".into(),
                count: None,
                size: None
            }
        );
        // Unknown arguments are ignored, as before.
        assert_eq!(
            parse(json!({"cmd": "status", "verbose": true})),
            Request::Status
        );
    }

    #[test]
    fn bad_arguments_are_refused() {
        for bad in [
            json!({"cmd": "submit_op"}),
            json!({"cmd": "submit_op", "signed": "not base64!"}),
            json!({"cmd": "submit_offline", "items": ["@@"]}),
            json!({"cmd": "node_config", "node": "abc"}),
            json!({"cmd": "ping"}),
            json!({"cmd": "nonsense"}),
        ] {
            assert!(
                serde_json::from_value::<Request>(bad.clone()).is_err(),
                "{bad}"
            );
        }
    }
}
