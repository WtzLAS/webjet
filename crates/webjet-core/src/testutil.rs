//! Test helpers: a network's keys and genesis, and a controller state
//! machine to build trees with, so tests here and in other crates can make
//! a real, verifying [`Store`] without a running controller.
//!
//! Built for this crate's tests and, with the `testutil` feature, for other
//! crates' tests (`webjet-core = { features = ["testutil"] }` in their
//! dev-dependencies). Never used by the programs themselves.

// Test support: a broken fixture should fail the test right there.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::crypto::{self, Bytes32, KeyPair};
use crate::statemachine::{ApplyError, Machine, Outcome, ops};
use crate::store::Store;
use crate::types::now_ms;
use webjet_proto::{self as wp, AccountOp, Decodable, Encodable, EntryPayload, msg_type as mt};

/// A network's offline keys, its first admin and its genesis.
pub struct Net {
    pub root: KeyPair,
    pub emergency: KeyPair,
    pub admin: KeyPair,
    pub admin_id: Bytes32,
    pub genesis: Vec<u8>,
}

/// A new network with overlay pool 10.7.0.0/16 and admin `alice`.
pub fn net() -> Net {
    let root = KeyPair::generate();
    let emergency = KeyPair::generate();
    let admin = KeyPair::generate();
    let admin_id = crypto::random32();
    let rec = wp::AccountRecord {
        account_id: Some(crypto::k32(&admin_id)),
        account_key: Some(crypto::k32(&admin.public())),
        name: Some("alice".into()),
        admin: true,
        issuer_root: true,
        issuer: None,
        version: 1,
    };
    let g = wp::Genesis {
        root_key: Some(crypto::k32(&root.public())),
        emergency_cert: Some(root.sign_obj(
            mt::EMERGENCY_KEY_CERT,
            &wp::EmergencyKeyCert {
                key: Some(crypto::k32(&emergency.public())),
            },
        )),
        first_admin: Some(root.sign_obj(mt::ACCOUNT_RECORD, &rec)),
        overlay_pool: Some(vec![crate::types::net_to_cidr(
            &"10.7.0.0/16".parse().unwrap(),
        )]),
        created_at: now_ms(),
    };
    Net {
        root,
        emergency,
        admin,
        admin_id,
        genesis: g.encode_bytes(),
    }
}

/// A network with a controller state machine: apply admin operations, then
/// hand out stores that trust the resulting tree.
pub struct Cluster {
    pub net: Net,
    pub machine: Machine,
    /// The controller's tree-head signing key, root-certified.
    pub head_key: KeyPair,
    idx: u64,
    seq: u64,
}

/// What [`Cluster::enroll`] creates.
#[derive(Clone, Debug, Default)]
pub struct NodeSpec<'a> {
    pub name: &'a str,
    pub ip: &'a str,
    pub roles: &'a [wp::Role],
    pub tags: &'a [&'a str],
    pub control: bool,
    /// Route grants, `lan` or `lan=published`.
    pub routes: &'a [&'a str],
}

impl Default for Cluster {
    fn default() -> Self {
        Self::new()
    }
}

impl Cluster {
    pub fn new() -> Cluster {
        let net = net();
        let mut c = Cluster {
            net,
            machine: Machine::new(),
            head_key: KeyPair::generate(),
            idx: 0,
            seq: 0,
        };
        let g = EntryPayload::GenesisEntry(Box::new(wp::GenesisEntry {
            genesis: Some(c.net.genesis.clone()),
        }));
        c.run(g).expect("genesis");
        c
    }

    /// Prepare and apply one entry, replicated through its bytes.
    pub fn run(&mut self, p: EntryPayload) -> Result<Outcome, ApplyError> {
        self.idx += 1;
        let e = self
            .machine
            .prepare(1, self.idx, now_ms(), p)
            .inspect_err(|_| self.idx -= 1)?;
        let e = wp::LogEntry::decode_bytes(&e.encode_bytes()).expect("log entry");
        self.machine.apply(&e)
    }

    /// Apply an operation signed by the first admin.
    pub fn admin_op(&mut self, op: AccountOp) -> Result<Outcome, ApplyError> {
        self.seq += 1;
        let s = ops::sign_op(&self.net.admin, &self.net.admin_id, self.seq, now_ms(), op);
        self.run(ops::op_entry(s))
    }

    /// Enroll a node with a fresh key; returns its id and key.
    pub fn enroll(&mut self, spec: NodeSpec<'_>) -> (Bytes32, KeyPair) {
        let key = KeyPair::generate();
        let roles = if spec.roles.is_empty() {
            vec![wp::Role::Data]
        } else {
            spec.roles.to_vec()
        };
        let routes = spec
            .routes
            .iter()
            .map(|r| crate::types::Grant::parse(r).expect("route").to_wire())
            .collect::<Vec<_>>();
        let o = self
            .admin_op(AccountOp::CreateEnrollment(Box::new(
                wp::CreateEnrollment {
                    owner: Some(crypto::k32(&self.net.admin_id)),
                    name: Some(spec.name.into()),
                    overlay_ips: Some(vec![ops::ip(spec.ip).expect("ip")]),
                    roles: Some(roles),
                    tags: Some(spec.tags.iter().map(|t| t.to_string()).collect()),
                    routes: (!routes.is_empty()).then_some(routes),
                    identity_key: Some(crypto::k32(&key.public())),
                    control: spec.control,
                    ..Default::default()
                },
            )))
            .expect("enrollment");
        (o.node_id.expect("node id"), key)
    }

    /// Enroll a data node `name` at `ip` with the given tags.
    pub fn data_node(&mut self, name: &str, ip: &str, tags: &[&str]) -> (Bytes32, KeyPair) {
        self.enroll(NodeSpec {
            name,
            ip,
            tags,
            ..Default::default()
        })
    }

    /// Apply a network configuration with the next version (§6.18); the
    /// version of every part present is set to match.
    pub fn set_network(&mut self, mut c: wp::NetworkConfig) -> Result<Outcome, ApplyError> {
        let version = self.machine.view().network_version + 1;
        c.version = version;
        if let Some(p) = &mut c.policy {
            p.version = version;
        }
        if let Some(d) = &mut c.dns {
            d.version = version;
        }
        if let Some(s) = &mut c.seeds {
            s.version = version;
        }
        if let Some(l) = &mut c.limits {
            l.version = version;
        }
        if let Some(t) = &mut c.transport {
            t.version = version;
        }
        if let Some(k) = &mut c.controllers {
            k.version = version;
        }
        self.admin_op(AccountOp::SetNetworkConfig(Box::new(
            wp::SetNetworkConfig {
                config: Some(Box::new(c)),
            },
        )))
    }

    /// Apply a network configuration that has only this policy.
    pub fn set_policy(&mut self, p: wp::Policy) -> Result<Outcome, ApplyError> {
        self.set_network(wp::NetworkConfig {
            policy: Some(Box::new(p)),
            ..Default::default()
        })
    }

    /// Apply a node's own configuration with the next version (§6.19).
    pub fn set_node_config(&mut self, mut c: wp::NodeConfig) -> Result<Outcome, ApplyError> {
        let id = crypto::opt_k32(&c.node_id);
        c.version = self
            .machine
            .view()
            .node_configs
            .get(&id)
            .map_or(1, |old| old.version + 1);
        self.admin_op(AccountOp::SetNodeConfig(Box::new(wp::SetNodeConfig {
            config: Some(Box::new(c)),
        })))
    }

    /// A signed tree head for the current state.
    pub fn head(&mut self) -> Vec<u8> {
        let head = wp::SignedTreeHead {
            signing_key_id: Some(crypto::k32(&crypto::signing_key_id(
                &self.head_key.public(),
            ))),
            version: self.machine.last_index,
            root: Some(crypto::k32(&self.machine.root())),
            state_version: 1,
            issued_at: now_ms(),
            expires_at: now_ms() + 3_600_000,
        };
        self.head_key.sign_obj(mt::SIGNED_TREE_HEAD, &head)
    }

    /// A node's store with the controller's current tree installed.
    pub fn store(&mut self) -> Store {
        let mut st = Store::new(self.net.genesis.clone()).expect("store");
        let cert = wp::SigningKeyCert {
            signing_key_id: Some(crypto::k32(&crypto::signing_key_id(
                &self.head_key.public(),
            ))),
            signing_key: Some(crypto::k32(&self.head_key.public())),
            controller: Some(crypto::k32(&[0xc0; 32])),
            cert_serial: 1,
            issuer: None,
        };
        st.add_cert(&self.net.root.sign_obj(mt::SIGNING_KEY_CERT, &cert))
            .expect("certificate");
        self.sync(&mut st);
        st
    }

    /// Bring `st` up to the controller's current tree.
    pub fn sync(&mut self, st: &mut Store) {
        let head = self.head();
        let mut leaves: Vec<_> = self
            .machine
            .tree
            .iter()
            .map(|(_, e)| (e.kind, e.key, Some(e.bytes.clone())))
            .collect();
        // Leaves the store has that the controller no longer has.
        for (_, e) in st.tree().iter() {
            if self.machine.tree.get(e.kind, &e.key).is_none() {
                leaves.push((e.kind, e.key, None));
            }
        }
        st.install(&head, leaves).expect("install");
    }
}

/// IPv4 test packets with correct checksums.
pub mod packets {
    pub fn udp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = 28 + payload.len();
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0];
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        crate::packet::fix_checksums(&mut p);
        p
    }

    pub fn tcp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        crate::packet::fix_checksums(&mut p);
        p
    }
}
