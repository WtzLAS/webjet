//! Talking to the local webjetd: reading the network over its control
//! channel, and signing operations with the user's account key (the same
//! path `webjetctl` uses, §13.1). The agent forwards operations to a
//! controller, which checks the signature and the account's rights.

use crate::merkle::LogPage;
use crate::model::{Account, Node, Peer, Session, Sessions, Snapshot, Status, Tree};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use std::path::{Path, PathBuf};
use webjet_core::crypto;
use webjetd::control::Request;

/// Where the agent's control channel is (same defaults as `webjetctl`).
pub fn default_socket() -> PathBuf {
    std::env::var_os("WEBJET_SOCKET").map_or_else(webjetd::ipc::default_control, PathBuf::from)
}

/// Where account keys are (same defaults as `webjetctl`).
pub fn default_keys() -> PathBuf {
    std::env::var_os("WEBJET_KEYS").map_or_else(webjet_tools::default_key_dir, PathBuf::from)
}

/// The account the sign-in screen starts with, among the keys in `names`
/// (from `dir`): `given` (`WEBJET_ACCOUNT`), else the default set with
/// `webjetctl network account use`, else the only key — the account
/// `webjetctl` would sign with. None when that account has no key here.
pub fn preselected_account(dir: &Path, names: &[String], given: Option<&str>) -> Option<String> {
    webjet_tools::pick_account(dir, given)
        .ok()
        .filter(|n| names.contains(n))
}

#[derive(Clone, Debug)]
pub struct Client {
    pub socket: PathBuf,
}

impl Client {
    pub fn new(socket: impl Into<PathBuf>) -> Client {
        Client {
            socket: socket.into(),
        }
    }

    async fn call(&self, req: Request) -> Result<Value> {
        webjetd::control::client::call(&self.socket, &req).await
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, req: Request) -> Result<T> {
        let cmd = req.name();
        let v = self.call(req).await?;
        serde_json::from_value(v).with_context(|| format!("unexpected answer to {cmd}"))
    }

    /// Everything the views need, in one go. `metrics_all`: on a
    /// controller, fetch every node's latest metric report instead of this
    /// node's own. `merkle`: also fetch the whole state tree.
    pub async fn snapshot(&self, metrics_all: bool, merkle: bool) -> Result<Snapshot> {
        let status: Status = self.get(Request::Status).await?;
        let mut nodes: Vec<Node> = self.get(Request::Nodes).await?;
        nodes.sort_by(|a, b| a.name.cmp(&b.name));
        let mut accounts: Vec<Account> = self.get(Request::Accounts).await?;
        accounts.sort_by(|a, b| a.name.cmp(&b.name));
        let mut peers: Vec<Peer> = self.get(Request::Peers).await?;
        peers.sort_by(|a, b| a.peer.cmp(&b.peer).then(a.transport.cmp(&b.transport)));
        let tree: Tree = self.get(Request::Tree).await?;
        // Newer commands: an older agent answers "unknown command".
        fn opt<T>(r: Result<T>) -> Result<T, String> {
            r.map_err(|e| format!("{e:#}"))
        }
        let mut sessions: Result<Sessions, String> = opt(self.get(Request::Sessions).await);
        if let Ok(s) = &mut sessions {
            s.sessions.sort_by(|a, b| a.peer.cmp(&b.peer));
            s.circuits.local.sort_by(|a, b| {
                (&a.peer, !a.primary, a.label).cmp(&(&b.peer, !b.primary, b.label))
            });
            s.circuits
                .routes
                .sort_by(|a, b| (&a.src, &a.dst).cmp(&(&b.src, &b.dst)));
        }
        let conntrack = opt(self.get(Request::Conntrack).await);
        let proxy = opt(self.get(Request::Proxy).await);
        let topology = opt(self.get(Request::Topology).await);
        let all = metrics_all && status.controller.as_ref().is_some_and(|c| !c.is_null());
        let metrics = opt(self.call(Request::Metrics { all }).await.and_then(|v| {
            v.get("openmetrics")
                .and_then(|t| t.as_str())
                .map(String::from)
                .ok_or_else(|| anyhow!("no metrics in the answer"))
        }));
        let merkle = if merkle {
            Some(opt(self.get(Request::Merkle).await))
        } else {
            None
        };
        Ok(Snapshot {
            status,
            nodes,
            accounts,
            peers,
            tree,
            sessions,
            conntrack,
            proxy,
            topology,
            metrics,
            metrics_all: all,
            merkle,
        })
    }

    /// Submit a signed operation; returns the log index it was committed at.
    pub async fn submit(&self, signed: Vec<u8>) -> Result<u64> {
        let r = self.call(Request::SubmitOp { signed }).await?;
        r.get("index")
            .and_then(|i| i.as_u64())
            .ok_or_else(|| anyhow!("no log index in the answer"))
    }

    /// A page of the controllers' operation log, for an admin's signed
    /// request (`ops::log_request`).
    pub async fn log(&self, signed: Vec<u8>) -> Result<LogPage> {
        let v = self.call(Request::Log { request: signed }).await?;
        serde_json::from_value(v).context("unexpected answer to log")
    }

    /// Data for building enrollment strings.
    pub async fn enroll_info(&self) -> Result<Value> {
        self.call(Request::EnrollInfo).await
    }

    /// The network configuration in force, ready to edit.
    pub async fn network_config(&self) -> Result<crate::netconfig::Doc> {
        crate::netconfig::Doc::network(self.call(Request::Tree).await?)
    }

    /// A node's own configuration (by id, hex) and what is in force for it,
    /// ready to edit. The agent answers for any node in the tree, so this
    /// works for remote nodes too.
    pub async fn node_config(&self, node: &str) -> Result<crate::netconfig::Doc> {
        let r = self
            .call(Request::NodeConfig {
                node: Some(crypto::parse_hex32(node).ok_or_else(|| anyhow!("bad node id {node}"))?),
            })
            .await?;
        crate::netconfig::Doc::node(&r)
    }

    /// Submit signed operations in order; returns the last log index.
    pub async fn submit_all(&self, signed: Vec<Vec<u8>>) -> Result<u64> {
        let mut last = 0;
        for s in signed {
            last = self.submit(s).await?;
        }
        Ok(last)
    }
}

/// An unlocked account and its place in the network.
pub struct SignedIn {
    pub account: webjet_tools::Account,
    pub session: Session,
}

/// Unlock `<keys>/<name>.key` and check it against the network.
pub fn sign_in(keys: &Path, name: &str, passphrase: &str, snapshot: &Snapshot) -> Result<SignedIn> {
    if name.is_empty() {
        bail!("choose an account");
    }
    let mut account = webjet_tools::Account::unlock(keys, name, passphrase).map_err(|e| {
        // The most common failure, worded for people.
        if e.to_string().contains("wrong passphrase") {
            anyhow!("wrong passphrase for {name}")
        } else {
            e
        }
    })?;
    // A replaced key's `.pub` names the ID `keygen` made up: the network's
    // ID for this key counts (as in webjetctl).
    let held: Vec<Value> = snapshot
        .accounts
        .iter()
        .map(|a| serde_json::json!({"id": a.id, "key": a.key, "name": a.name}))
        .collect();
    account.adopt_network_id(&Value::Array(held));
    let session = Session::new(
        snapshot,
        name,
        &hex::encode(account.id),
        &crypto::key_b64(&account.kp.public()),
    )?;
    Ok(SignedIn { account, session })
}

fn node_id(n: &Node) -> Result<webjet_core::crypto::Bytes32> {
    crypto::parse_hex32(&n.id).ok_or_else(|| anyhow!("bad node id {}", n.id))
}

/// The operations the app offers: the ones `webjetctl` signs
/// (`webjet_tools::ops`), from the app's node records and text fields.
pub mod ops {
    use super::*;
    use webjet_tools::ops;

    pub fn rename(a: &webjet_tools::Account, n: &Node, new_name: &str) -> Result<Vec<u8>> {
        ops::rename_node(a, &node_id(n)?, new_name)
    }

    pub fn revoke(a: &webjet_tools::Account, n: &Node, reason: &str) -> Result<Vec<u8>> {
        ops::revoke_node(a, &node_id(n)?, Some(reason))
    }

    /// Replace a node's tags (admin): a comma- or space-separated list.
    pub fn set_tags(a: &webjet_tools::Account, n: &Node, tags: &str) -> Result<Vec<u8>> {
        let list: Vec<String> = tags
            .split([',', ' '])
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect();
        ops::set_tags(a, &node_id(n)?, &list)
    }

    pub use ops::log_request;

    /// Advance the PSK epoch (admin, §7.6).
    pub fn rotate_psk(a: &webjet_tools::Account, current_epoch: u64) -> Result<Vec<u8>> {
        Ok(ops::rotate_psk(a, current_epoch)?.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webjet_core::crypto::KeyPair;
    use webjet_proto as wp;

    fn account(dir: &Path) -> webjet_tools::Account {
        let kp = KeyPair::generate();
        let id = crypto::random32();
        let p = webjet_tools::AccountPub {
            name: "bob".into(),
            account_id: hex::encode(id),
            key: crypto::key_b64(&kp.public()),
        };
        std::fs::write(dir.join("bob.pub"), serde_json::to_vec(&p).unwrap()).unwrap();
        std::fs::write(
            dir.join("bob.key"),
            webjet_tools::seal("pw", &kp.seed()[..]).unwrap(),
        )
        .unwrap();
        webjet_tools::Account::unlock(dir, "bob", "pw").unwrap()
    }

    #[test]
    fn sign_in_starts_with_the_default_account() {
        let d = tmp();
        for n in ["alice", "bob"] {
            std::fs::write(d.join(format!("{n}.key")), b"x").unwrap();
        }
        let names = webjet_tools::account_names(&d).unwrap();
        assert_eq!(
            preselected_account(&d, &names, None),
            None,
            "two keys, no default"
        );
        webjet_tools::set_default_account(&d, Some("bob")).unwrap();
        assert_eq!(
            preselected_account(&d, &names, None).as_deref(),
            Some("bob")
        );
        assert_eq!(
            preselected_account(&d, &names, Some("alice")).as_deref(),
            Some("alice"),
            "WEBJET_ACCOUNT wins"
        );
        assert_eq!(
            preselected_account(&d, &names, Some("carol")),
            None,
            "an account without a key here isn't offered"
        );
        std::fs::remove_file(d.join("bob.key")).unwrap();
        let names = webjet_tools::account_names(&d).unwrap();
        assert_eq!(
            preselected_account(&d, &names, None),
            None,
            "a stale default selects nothing"
        );
        webjet_tools::set_default_account(&d, None).unwrap();
        assert_eq!(
            preselected_account(&d, &names, None).as_deref(),
            Some("alice"),
            "the only key"
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("wj-app-{}", hex::encode(crypto::random16())));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn sign_in_checks_passphrase_and_network() {
        let d = tmp();
        let a = account(&d);
        let snap = Snapshot {
            accounts: vec![Account {
                id: hex::encode(a.id),
                name: "bob".into(),
                admin: false,
                valid: true,
                key: crypto::key_b64(&a.kp.public()),
                version: 1,
            }],
            ..Default::default()
        };
        let s = sign_in(&d, "bob", "pw", &snap).unwrap();
        assert!(!s.session.is_admin());
        let e = sign_in(&d, "bob", "nope", &snap).err().unwrap().to_string();
        assert!(e.contains("wrong passphrase"), "{e}");
        let e = sign_in(&d, "bob", "pw", &Snapshot::default())
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("isn't in this network"), "{e}");
        let _ = std::fs::remove_dir_all(d);
    }

    /// After `network account rekey` the new key's `.pub` carries a random
    /// ID: signing in finds the account by its key and fixes the `.pub`.
    #[test]
    fn sign_in_after_a_rekey_uses_the_network_id() {
        let d = tmp();
        let a = account(&d);
        let network_id = [9u8; 32];
        let snap = Snapshot {
            accounts: vec![Account {
                id: hex::encode(network_id),
                name: "bob".into(),
                admin: true,
                valid: true,
                key: crypto::key_b64(&a.kp.public()),
                version: 2,
            }],
            ..Default::default()
        };
        let s = sign_in(&d, "bob", "pw", &snap).unwrap();
        assert_eq!(s.account.id, network_id);
        assert!(s.session.is_admin());
        let p = webjet_tools::AccountPub::load(&d.join("bob.pub")).unwrap();
        assert_eq!(p.id().unwrap(), network_id);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn operations_are_signed_ops_by_the_account() {
        let d = tmp();
        let a = account(&d);
        let n = Node {
            id: hex::encode([7u8; 32]),
            name: "laptop".into(),
            ..Default::default()
        };
        let seq0 = a.next_seq().unwrap();
        for raw in [
            ops::rename(&a, &n, "laptop-2").unwrap(),
            ops::revoke(&a, &n, "lost").unwrap(),
            ops::set_tags(&a, &n, "tag:a, tag:b").unwrap(),
            ops::rotate_psk(&a, 3).unwrap(),
        ] {
            let v = crypto::open_envelope(&raw).unwrap();
            assert_eq!(v.ty, wp::msg_type::SIGNED_OP);
            assert_eq!(v.signer, a.kp.public());
            let so: wp::SignedOp = v.decode().unwrap();
            assert_eq!(so.signer.map(|k| k.to_bytes()), Some(a.id));
            assert!(so.op_seq > seq0, "op_seq increases");
        }
        let v = crypto::open_envelope(&ops::log_request(&a, 9, 50)).unwrap();
        assert_eq!(v.ty, wp::msg_type::LOG_REQUEST);
        let r: wp::LogRequest = v.decode().unwrap();
        assert_eq!((r.before, r.limit), (9, 50));
        assert_eq!(r.account_id.map(|k| k.to_bytes()), Some(a.id));
        assert!(ops::rename(&a, &n, "Bad Name").is_err());
        assert!(ops::set_tags(&a, &n, "notatag").is_err());
        let _ = std::fs::remove_dir_all(d);
    }
}
