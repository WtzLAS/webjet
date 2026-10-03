//! Talking to the local webjetd: reading the network over its control
//! channel, and signing operations with the user's account key (the same
//! path `webjetctl` uses, §13.1). The agent forwards operations to a
//! controller, which checks the signature and the account's rights.

use crate::model::{Account, Node, Peer, Session, Snapshot, Status, Tree};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use webjet_core::crypto;
use webjet_proto::{self as wp, AccountOp};

/// Where the agent's control channel is (same defaults as `webjetctl`).
pub fn default_socket() -> PathBuf {
    std::env::var_os("WEBJET_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(webjetd::ipc::default_control)
}

/// Where account keys are (same defaults as `webjetctl`).
pub fn default_keys() -> PathBuf {
    std::env::var_os("WEBJET_KEYS")
        .map(PathBuf::from)
        .unwrap_or_else(webjet_tools::default_key_dir)
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

    async fn call(&self, req: Value) -> Result<Value> {
        webjetd::control::client::call(&self.socket, req).await
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, cmd: &str) -> Result<T> {
        let v = self.call(json!({"cmd": cmd})).await?;
        serde_json::from_value(v).with_context(|| format!("unexpected answer to {cmd}"))
    }

    /// Everything the views need, in one go.
    pub async fn snapshot(&self) -> Result<Snapshot> {
        let status: Status = self.get("status").await?;
        let mut nodes: Vec<Node> = self.get("nodes").await?;
        nodes.sort_by(|a, b| a.name.cmp(&b.name));
        let mut accounts: Vec<Account> = self.get("accounts").await?;
        accounts.sort_by(|a, b| a.name.cmp(&b.name));
        let peers: Vec<Peer> = self.get("peers").await?;
        let tree: Tree = self.get("tree").await?;
        Ok(Snapshot {
            status,
            nodes,
            accounts,
            peers,
            tree,
        })
    }

    /// Submit a signed operation; returns the log index it was committed at.
    pub async fn submit(&self, signed: Vec<u8>) -> Result<u64> {
        let r = self
            .call(json!({"cmd": "submit_op", "signed": webjet_tools::b64(&signed)}))
            .await?;
        r.get("index")
            .and_then(|i| i.as_u64())
            .ok_or_else(|| anyhow!("no log index in the answer"))
    }

    /// Data for building enrollment strings.
    pub async fn enroll_info(&self) -> Result<Value> {
        self.call(json!({"cmd": "enroll_info"})).await
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
    let account = webjet_tools::Account::unlock(keys, name, passphrase).map_err(|e| {
        // The most common failure, worded for people.
        if e.to_string().contains("wrong passphrase") {
            anyhow!("wrong passphrase for {name}")
        } else {
            e
        }
    })?;
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

/// The operations the app offers, built and signed the way `webjetctl` does.
pub mod ops {
    use super::*;

    pub fn rename(a: &webjet_tools::Account, n: &Node, new_name: &str) -> Result<Vec<u8>> {
        if !crate::model::valid_node_name(new_name) {
            bail!("node names are 1–32 characters of a-z, 0-9 and -");
        }
        a.sign(AccountOp::RenameNode(Box::new(wp::RenameNode {
            node_id: Some(crypto::k32(&node_id(n)?)),
            name: Some(new_name.to_string()),
        })))
    }

    pub fn revoke(a: &webjet_tools::Account, n: &Node, reason: &str) -> Result<Vec<u8>> {
        let reason = (!reason.trim().is_empty()).then(|| reason.trim().to_string());
        a.sign(AccountOp::TombstoneNode(Box::new(wp::TombstoneNode {
            node_id: Some(crypto::k32(&node_id(n)?)),
            reason,
        })))
    }

    /// Replace a node's tags (admin).
    pub fn set_tags(a: &webjet_tools::Account, n: &Node, tags: &str) -> Result<Vec<u8>> {
        let list: Vec<String> = tags
            .split([',', ' '])
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect();
        let tags = webjet_tools::tags(&list)?;
        a.sign(AccountOp::UpdateNode(Box::new(wp::UpdateNode {
            node_id: Some(crypto::k32(&node_id(n)?)),
            set_tags: true,
            tags: Some(tags),
            ..Default::default()
        })))
    }

    /// Advance the PSK epoch (admin, §7.6).
    pub fn rotate_psk(a: &webjet_tools::Account, current_epoch: u64) -> Result<Vec<u8>> {
        let next = u16::try_from(current_epoch)
            .unwrap_or(u16::MAX)
            .wrapping_add(1);
        a.sign(AccountOp::RotatePsk(Box::new(wp::RotatePsk {
            epoch_id: next,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webjet_core::crypto::KeyPair;

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
        assert!(ops::rename(&a, &n, "Bad Name").is_err());
        assert!(ops::set_tags(&a, &n, "notatag").is_err());
        let _ = std::fs::remove_dir_all(d);
    }
}
