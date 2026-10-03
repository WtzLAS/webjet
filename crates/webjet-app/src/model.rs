//! What the app shows, decoded from the agent's control channel, and what
//! the signed-in account may do. No GUI code: everything here is tested
//! headless.

use serde::Deserialize;
use serde_json::Value;

/// A node as listed by the agent (`nodes` on the control channel).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub key: String,
    pub ips: Vec<String>,
    pub tags: Vec<String>,
    /// The owner account's name (or id when the account is unknown).
    pub owner: String,
    pub owner_id: String,
    pub relay: bool,
    pub data: bool,
    pub control: bool,
    pub routes: Vec<String>,
    pub valid: bool,
    pub version: u64,
}

impl Node {
    pub fn roles(&self) -> String {
        let mut r = Vec::new();
        if self.data {
            r.push("data");
        }
        if self.relay {
            r.push("relay");
        }
        if self.control {
            r.push("control");
        }
        r.join(", ")
    }

    /// Case-insensitive match on name, address, tag, owner or role.
    pub fn matches(&self, filter: &str) -> bool {
        let f = filter.trim().to_ascii_lowercase();
        if f.is_empty() {
            return true;
        }
        self.name.to_ascii_lowercase().contains(&f)
            || self.owner.to_ascii_lowercase().contains(&f)
            || self.ips.iter().any(|i| i.contains(&f))
            || self
                .tags
                .iter()
                .any(|t| t.to_ascii_lowercase().contains(&f))
            || self.roles().contains(&f)
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Account {
    pub id: String,
    pub name: String,
    pub admin: bool,
    pub valid: bool,
    pub key: String,
    pub version: u64,
}

/// A hop session of the local agent (`peers`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Peer {
    pub peer: String,
    pub id: String,
    pub transport: String,
    pub remote: String,
    pub rtt_ms: f64,
    pub loss: f64,
    pub age_s: u64,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Alarm {
    pub name: String,
    pub severity: String,
    pub since: u64,
}

/// The local agent's status (`status`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Status {
    pub node_id: String,
    pub name: Option<String>,
    pub ips: Option<Vec<String>>,
    pub valid: bool,
    pub tree_version: Option<u64>,
    pub tree_root: Option<String>,
    pub head_expires: Option<u64>,
    pub valid_until: u64,
    pub nodes: u64,
    pub controllers: u64,
    pub psk_epoch: u64,
    pub peers: u64,
    pub sessions: u64,
    pub alarms: Vec<Alarm>,
    pub uptime_s: u64,
    pub version: String,
}

/// Network-wide settings (`tree`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Tree {
    pub policy_version: u64,
    pub valid_until: u64,
    pub overlay_pool: Vec<String>,
    pub dns: Option<Value>,
    pub seeds: Option<Value>,
    pub limits: Option<Value>,
    pub transport: Option<Value>,
}

/// Everything one refresh fetches.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub status: Status,
    pub nodes: Vec<Node>,
    pub accounts: Vec<Account>,
    pub peers: Vec<Peer>,
    pub tree: Tree,
}

impl Snapshot {
    pub fn account(&self, id: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.id == id)
    }
}

// ---------------------------------------------------------------- permissions

/// What the signed-in account may do, decided from its record in the
/// network (§13.2). The controllers enforce the same rules; the app only
/// avoids offering actions that would be refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Admin account: every operation.
    Admin,
    /// Normal account: read-only, plus rename and revoke of its own nodes.
    Member,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    RenameNode,
    RevokeNode,
    UpdateNode,
    EnrollNode,
    RotatePsk,
    RevokeAccount,
}

/// The signed-in account, as found in the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub name: String,
    pub id: String,
    pub role: Role,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignInError {
    #[error("account {0} isn't in this network (it may belong to another network)")]
    Unknown(String),
    #[error("account {0} has been revoked")]
    Revoked(String),
    #[error("the account key doesn't match account {0}'s record in the network")]
    KeyMismatch(String),
}

impl Session {
    /// Check an unlocked account against the network's records.
    pub fn new(
        snapshot: &Snapshot,
        name: &str,
        id: &str,
        key: &str,
    ) -> Result<Session, SignInError> {
        let a = snapshot
            .account(id)
            .ok_or_else(|| SignInError::Unknown(name.to_string()))?;
        if !a.valid {
            return Err(SignInError::Revoked(name.to_string()));
        }
        if a.key != key {
            return Err(SignInError::KeyMismatch(name.to_string()));
        }
        Ok(Session {
            name: a.name.clone(),
            id: a.id.clone(),
            role: if a.admin { Role::Admin } else { Role::Member },
        })
    }

    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }

    /// May this account do `action` on `node` (None for network-wide actions)?
    pub fn may(&self, action: &Action, node: Option<&Node>) -> bool {
        match self.role {
            Role::Admin => true,
            Role::Member => match action {
                Action::RenameNode | Action::RevokeNode => {
                    node.is_some_and(|n| n.owner_id == self.id && n.valid)
                }
                _ => false,
            },
        }
    }
}

// ---------------------------------------------------------------- formatting

/// "3 d 4 h", "5 min", "12 s".
pub fn duration(secs: u64) -> String {
    match secs {
        s if s >= 86_400 => format!("{} d {} h", s / 86_400, (s % 86_400) / 3600),
        s if s >= 3600 => format!("{} h {} min", s / 3600, (s % 3600) / 60),
        s if s >= 60 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}

/// Time from now until `ms` (Unix ms), or how long ago it was.
pub fn relative(ms: u64, now_ms: u64) -> String {
    if ms >= now_ms {
        format!("in {}", duration((ms - now_ms) / 1000))
    } else {
        format!("{} ago", duration((now_ms - ms) / 1000))
    }
}

/// The first 12 hex digits of an id.
pub fn short(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

/// A node name as the network accepts it: 1–32 of `a-z`, `0-9` and `-`.
pub fn valid_node_name(s: &str) -> bool {
    webjet_core::types::valid_name(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snap() -> Snapshot {
        Snapshot {
            accounts: serde_json::from_value(json!([
                {"id": "aa", "name": "alice", "admin": true, "valid": true, "key": "KA"},
                {"id": "bb", "name": "bob", "admin": false, "valid": true, "key": "KB"},
                {"id": "cc", "name": "carol", "admin": false, "valid": false, "key": "KC"},
            ]))
            .unwrap(),
            ..Default::default()
        }
    }

    fn node(owner_id: &str) -> Node {
        Node {
            name: "laptop".into(),
            owner_id: owner_id.into(),
            valid: true,
            ..Default::default()
        }
    }

    #[test]
    fn sign_in_checks_the_network_record() {
        let s = snap();
        assert_eq!(
            Session::new(&s, "alice", "aa", "KA").unwrap().role,
            Role::Admin
        );
        assert_eq!(
            Session::new(&s, "bob", "bb", "KB").unwrap().role,
            Role::Member
        );
        assert_eq!(
            Session::new(&s, "carol", "cc", "KC"),
            Err(SignInError::Revoked("carol".into()))
        );
        assert_eq!(
            Session::new(&s, "dave", "dd", "KD"),
            Err(SignInError::Unknown("dave".into()))
        );
        assert_eq!(
            Session::new(&s, "bob", "bb", "other"),
            Err(SignInError::KeyMismatch("bob".into()))
        );
    }

    #[test]
    fn admins_may_do_everything() {
        let a = Session::new(&snap(), "alice", "aa", "KA").unwrap();
        for act in [
            Action::RenameNode,
            Action::RevokeNode,
            Action::UpdateNode,
            Action::EnrollNode,
            Action::RotatePsk,
            Action::RevokeAccount,
        ] {
            assert!(a.may(&act, Some(&node("bb"))), "{act:?}");
        }
    }

    #[test]
    fn members_only_manage_their_own_live_nodes() {
        let b = Session::new(&snap(), "bob", "bb", "KB").unwrap();
        assert!(b.may(&Action::RenameNode, Some(&node("bb"))));
        assert!(b.may(&Action::RevokeNode, Some(&node("bb"))));
        assert!(
            !b.may(&Action::RenameNode, Some(&node("aa"))),
            "someone else's node"
        );
        assert!(
            !b.may(&Action::UpdateNode, Some(&node("bb"))),
            "tags/roles/IPs are admin-only"
        );
        assert!(!b.may(&Action::EnrollNode, None));
        assert!(!b.may(&Action::RotatePsk, None));
        let mut revoked = node("bb");
        revoked.valid = false;
        assert!(!b.may(&Action::RenameNode, Some(&revoked)));
    }

    #[test]
    fn decodes_agent_json() {
        let n: Node = serde_json::from_value(json!({
            "id": "0123456789abcdef", "name": "relay-fra", "ips": ["10.7.0.2/32"], "tags": ["tag:infra"],
            "owner": "infra", "owner_id": "ff", "relay": true, "data": true, "valid": true, "version": 3,
            "unknown_field": 1
        }))
        .unwrap();
        assert_eq!(n.roles(), "data, relay");
        assert!(
            n.matches("FRA") && n.matches("10.7.0.2") && n.matches("infra") && n.matches("relay")
        );
        assert!(!n.matches("laptop"));
        let st: Status = serde_json::from_value(json!({"node_id": "ab", "tree_version": 7, "alarms": [{"name": "soft_mode", "severity": "warning", "since": 1}]})).unwrap();
        assert_eq!(st.tree_version, Some(7));
        assert_eq!(st.alarms.len(), 1);
    }

    #[test]
    fn formatting() {
        assert_eq!(duration(5), "5 s");
        assert_eq!(duration(3 * 3600 + 120), "3 h 2 min");
        assert_eq!(duration(2 * 86_400 + 3600), "2 d 1 h");
        assert_eq!(relative(10_000, 4_000), "in 6 s");
        assert_eq!(relative(4_000, 10_000), "6 s ago");
        assert_eq!(short("0123456789abcdef"), "0123456789ab");
        assert_eq!(short("abc"), "abc");
        assert!(valid_node_name("laptop-2") && !valid_node_name("") && !valid_node_name("Laptop"));
        assert!(!valid_node_name(&"a".repeat(33)));
    }
}
