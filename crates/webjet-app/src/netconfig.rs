//! Editing configuration from the app (admins): the network's (§6.18) and
//! any node's own (§6.19), this one's or a remote one's. The same TOML
//! files, checks and operations as `webjetctl network config` and
//! `webjetctl local config --node`, through `webjet_tools::config`.

use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use std::fmt::Write as _;
use std::path::Path;
use webjet_core::crypto::{self, Bytes32};
use webjet_proto::{self as wp, AccountOp};
use webjet_tools::config::{self, ConfigFile, NetworkApply};

/// Which configuration is edited.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    Network,
    /// A node, by id (hex).
    Node(String),
}

/// A configuration as loaded from the agent.
#[derive(Clone, Debug)]
pub struct Doc {
    pub scope: Scope,
    /// "network" or the node's name.
    pub title: String,
    /// The version in force (0: nothing applied yet).
    pub version: u64,
    /// The file to edit, as `show` prints it.
    pub text: String,
    /// Nodes: what is in force for it (network values with its own), as
    /// `show --effective` prints it.
    pub effective: Option<String>,
    source: Source,
}

#[derive(Clone, Debug)]
enum Source {
    /// The `tree` control call's answer.
    Network(Value),
    Node {
        id: Bytes32,
        current: Option<wp::NodeConfig>,
    },
}

/// What applying the edited file does.
pub enum Plan {
    Network(NetworkApply),
    Node {
        name: String,
        config: wp::NodeConfig,
        /// The file was empty: the node's own configuration is removed.
        clears: bool,
    },
}

impl Plan {
    /// The operations to sign and submit, in order.
    pub fn ops(self) -> Vec<AccountOp> {
        match self {
            Plan::Network(n) => n.ops(),
            Plan::Node { config, .. } => {
                vec![AccountOp::SetNodeConfig(Box::new(wp::SetNodeConfig {
                    config: Some(Box::new(config)),
                }))]
            }
        }
    }

    /// For the notice once it went through.
    pub fn describe(&self) -> String {
        match self {
            Plan::Network(n) => {
                let mut s = format!(
                    "network configuration version {} ({})",
                    n.version,
                    n.sections.join(", ")
                );
                if let Some(d) = n.new_certificate_domain() {
                    let _ = write!(s, "; made a self-signed camouflage certificate for {d}");
                }
                s
            }
            Plan::Node {
                name, clears: true, ..
            } => format!("configuration of {name} cleared"),
            Plan::Node { name, config, .. } => {
                format!("configuration of {name} version {}", config.version)
            }
        }
    }

    pub fn note(&self) -> Option<&str> {
        match self {
            Plan::Network(n) => n.note.as_deref(),
            Plan::Node { .. } => None,
        }
    }
}

/// Relative certificate paths in a file are relative to this (the app has
/// no file of its own; `show` prints certificates inline).
fn base() -> &'static Path {
    Path::new(".")
}

impl Doc {
    /// The network configuration from the `tree` control call.
    pub fn network(tree: Value) -> Result<Doc> {
        let text = config::render_network(&tree)?;
        Ok(Doc {
            scope: Scope::Network,
            title: "network".into(),
            version: tree["network_version"].as_u64().unwrap_or(0),
            text,
            effective: None,
            source: Source::Network(tree),
        })
    }

    /// A node's configuration from the `node_config` control call.
    pub fn node(reply: &Value) -> Result<Doc> {
        let hex_id = reply["node_id"]
            .as_str()
            .ok_or_else(|| anyhow!("no node id in the answer"))?;
        let id = crypto::parse_hex32(hex_id).ok_or_else(|| anyhow!("bad node id {hex_id}"))?;
        let name = reply["name"].as_str().unwrap_or(hex_id).to_string();
        let current: Option<wp::NodeConfig> = match &reply["config"] {
            Value::Null => None,
            v => Some(serde_json::from_value(v.clone()).context("the node's configuration")?),
        };
        Ok(Doc {
            scope: Scope::Node(hex_id.to_string()),
            title: name.clone(),
            version: current.as_ref().map_or(0, |c| c.version),
            text: config::render_node(&name, current.as_ref())?,
            effective: Some(config::render_effective(&name, &reply["effective"])?),
            source: Source::Node { id, current },
        })
    }

    /// Check an edited file without submitting it: it parses, fits the
    /// scope and validates (policy tests run). Returns what it would do.
    pub fn check(&self, text: &str) -> Result<String> {
        let f = ConfigFile::parse(text)?;
        let from = f.base_version()?;
        let mut out = match &self.source {
            Source::Network(_) => {
                config::network_wire(&f, from + 1, base())?;
                let sections = f.sections();
                if sections.is_empty() {
                    "valid, but it sets nothing".to_string()
                } else {
                    format!(
                        "valid: {} (sections left out stay as they are)",
                        sections.join(", ")
                    )
                }
            }
            Source::Node { id, .. } => {
                f.to_node(id, from + 1)?;
                if f.is_empty() {
                    "valid: empty, applying it removes the node's own configuration".into()
                } else {
                    "valid for a node's configuration (the controllers check the seeds and DNS names)"
                        .into()
                }
            }
        };
        if let Source::Network(_) = self.source
            && let Some(n) = config::camouflage_note(&f)
        {
            let _ = write!(out, "; note: {n}");
        }
        if from != self.version {
            let _ = write!(
                out,
                "; made from version {from}, but version {} is in force: applying will refuse it",
                self.version
            );
        }
        Ok(out)
    }

    /// Prepare applying an edited file, against this document (load it
    /// fresh just before, so the version check is against what is in force).
    /// `None` when there is nothing to apply.
    pub fn plan(&self, text: &str) -> Result<Option<Plan>> {
        let f = ConfigFile::parse(text)?;
        match &self.source {
            Source::Network(tree) => Ok(Some(Plan::Network(config::network_apply(
                &f,
                tree,
                base(),
            )?))),
            Source::Node { id, current } => {
                Ok(
                    config::node_apply(&f, id, &self.title, current.as_ref())?.map(|config| {
                        Plan::Node {
                            name: self.title.clone(),
                            clears: f.is_empty(),
                            config,
                        }
                    }),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tree(version: u64) -> Value {
        json!({
            "network_version": version,
            "transport": null, "dns": null, "seeds": null, "limits": null, "policy": null,
            "resolver": ["10.7.255.254"], "suffix": "internal",
        })
    }

    fn node_reply(config: Value) -> Value {
        json!({
            "node_id": hex::encode([7u8; 32]),
            "name": "relay-07",
            "config": config,
            "effective": {
                "priorities": {"kcp": 1, "anytls": 2, "tls": 3},
                "limits": {},
                "seeds": [], "dns_records": [], "dns_forward": [],
                "suffix": "internal", "resolver": ["10.7.255.254"],
            },
        })
    }

    #[test]
    fn network_check_and_plan() {
        let doc = Doc::network(tree(0)).unwrap();
        assert_eq!(doc.version, 0);
        assert!(doc.text.contains("Nothing applied yet"), "{}", doc.text);
        // The shown defaults are a valid file.
        let c = doc.check(&doc.text).unwrap();
        assert!(c.starts_with("valid"), "{c}");

        let edited = format!(
            "{}\n",
            doc.text
                .replace("default = \"deny\"", "default = \"allow\"")
        );
        assert_ne!(
            edited.trim_end(),
            doc.text.trim_end(),
            "the policy default is in the file"
        );
        let plan = doc.plan(&edited).unwrap().unwrap();
        assert!(plan.describe().contains("version 1"), "{}", plan.describe());
        let ops = plan.ops();
        assert_eq!(ops.len(), 1);
        let AccountOp::SetNetworkConfig(op) = &ops[0] else {
            panic!("a network config op")
        };
        let cfg = op.config.as_ref().unwrap();
        assert_eq!(cfg.version, 1);
        assert_eq!(
            cfg.policy.as_ref().unwrap().default_action,
            wp::Action::Allow
        );

        // Broken files are refused with the reason.
        let e = doc
            .check("version = 0\n[policy]\ndefault = \"maybe\"\n")
            .unwrap_err();
        assert!(!format!("{e:#}").is_empty());
        assert!(doc.check("[[[").is_err());
        let e = doc.plan("version = 0\n").err().unwrap().to_string();
        assert!(e.contains("sets nothing"), "{e}");
        // A file from an older version: check warns, apply refuses.
        let doc2 = Doc::network(tree(3)).unwrap();
        let c = doc2.check(&doc.text).unwrap();
        assert!(c.contains("version 3 is in force"), "{c}");
        let e = doc2.plan(&edited).err().unwrap().to_string();
        assert!(e.contains("someone applied a change"), "{e}");
    }

    #[test]
    fn node_check_and_plan() {
        let doc = Doc::node(&node_reply(Value::Null)).unwrap();
        assert_eq!(doc.title, "relay-07");
        assert_eq!(doc.scope, Scope::Node(hex::encode([7u8; 32])));
        assert!(doc.effective.as_deref().unwrap().contains("In force"));
        assert!(doc.plan(&doc.text).unwrap().is_none(), "nothing to apply");
        let text = format!("{}\n[transport.priority]\nkcp = 9\n", doc.text);
        assert!(doc.check(&text).unwrap().starts_with("valid"));
        let plan = doc.plan(&text).unwrap().unwrap();
        assert_eq!(plan.describe(), "configuration of relay-07 version 1");
        let Plan::Node { config, clears, .. } = &plan else {
            panic!("a node plan")
        };
        assert!(!clears);
        assert_eq!(config.node_id.map(|k| k.to_bytes()), Some([7u8; 32]));
        // Network-only settings don't belong in a node's file.
        assert!(doc.check("[policy]\ndefault = \"allow\"\n").is_err());

        // The node now has version 1 of its own: an empty file clears it.
        let current = serde_json::to_value(config).unwrap();
        let doc = Doc::node(&node_reply(current)).unwrap();
        assert_eq!(doc.version, 1);
        assert!(doc.text.contains("kcp = 9"), "{}", doc.text);
        let plan = doc.plan("version = 1\n").unwrap().unwrap();
        assert_eq!(plan.describe(), "configuration of relay-07 cleared");
        let e = doc.plan("version = 0\n").err().unwrap().to_string();
        assert!(e.contains("someone changed it"), "{e}");
    }
}
