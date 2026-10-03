//! `webjetctl <setting> show`: the setting in force, as the YAML file that
//! `apply` reads, with built-in defaults where nothing was applied.
//!
//! The output can be saved, edited (raise `version`) and applied again. The
//! one exception is the camouflage certificate, which `show` prints as PEM
//! in a comment: `apply` reads it from a file.

use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use webjet_core::types::Grant;
use webjet_proto::{self as wp, Transport};

/// Built-in transport priorities (§9.6), the same as webjetd's.
pub const DEFAULT_PRIORITIES: [(Transport, u8); 3] = [
    (Transport::KcpFecTls, 30),
    (Transport::AnyTls, 20),
    (Transport::TcpTls, 10),
];

/// A config leaf from the `tree` control call; `None` when nothing was applied.
fn leaf<T: serde::de::DeserializeOwned>(tree: &Value, key: &str) -> Result<Option<T>> {
    match &tree[key] {
        Value::Null => Ok(None),
        v => Ok(Some(serde_json::from_value(v.clone())?)),
    }
}

fn header(applied: bool, what: &str) -> String {
    if applied {
        String::new()
    } else {
        format!("# No {what} applied yet: these are the built-in defaults.\n")
    }
}

fn yaml<T: serde::Serialize>(v: &T) -> Result<String> {
    Ok(serde_yaml::to_string(v)?)
}

fn ip_str(ip: &wp::IpAddress) -> String {
    ip.to_ip().map(|i| i.to_string()).unwrap_or_default()
}

fn grant_str(g: &wp::RouteGrant) -> String {
    match Grant::from_wire(g) {
        Ok(g) if g.mapped() => format!("{}={}", g.lan, g.published),
        Ok(g) => g.lan.to_string(),
        Err(_) => String::new(),
    }
}

// ---------------------------------------------------------------- transport

#[derive(serde::Serialize)]
struct TransportOut {
    version: u64,
    defaults: BTreeMap<&'static str, u8>,
    overrides: Vec<PriorityOverrideOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    camouflage: Option<CamouflageOut>,
    padding: PaddingOut,
}

#[derive(serde::Serialize)]
struct PriorityOverrideOut {
    select: Vec<String>,
    values: BTreeMap<&'static str, u8>,
}

#[derive(serde::Serialize)]
struct CamouflageOut {
    mode: &'static str,
    domain: String,
}

#[derive(serde::Serialize)]
struct PaddingOut {
    stop: u32,
    lines: Vec<String>,
}

fn priorities(v: &[wp::TransportPriority]) -> BTreeMap<&'static str, u8> {
    v.iter().map(|p| (p.transport.name(), p.priority)).collect()
}

fn pem(der: &[u8]) -> String {
    let b = crate::b64(der);
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b.as_bytes().chunks(64) {
        s.push_str(&String::from_utf8_lossy(chunk));
        s.push('\n');
    }
    s.push_str("-----END CERTIFICATE-----\n");
    s
}

pub fn transport(tree: &Value) -> Result<String> {
    let cur: Option<wp::TransportConfig> = leaf(tree, "transport")?;
    let applied = cur.is_some();
    let t = cur.unwrap_or(wp::TransportConfig {
        version: 0,
        defaults: None,
        overrides: None,
        camouflage: None,
        padding: None,
    });
    // Built-ins first; the tree's defaults replace them per transport.
    let mut defaults: BTreeMap<&'static str, u8> = DEFAULT_PRIORITIES
        .iter()
        .map(|(t, p)| (t.name(), *p))
        .collect();
    defaults.extend(priorities(&t.defaults.clone().unwrap_or_default()));
    let padding = match &t.padding {
        Some(p) => PaddingOut {
            stop: p.stop,
            lines: p.lines.clone().unwrap_or_default(),
        },
        None => PaddingOut {
            stop: webjet_core::padding::DEFAULT_STOP,
            lines: webjet_core::padding::DEFAULT_LINES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        },
    };
    let cam = t.camouflage.as_deref();
    let out = TransportOut {
        version: t.version,
        defaults,
        overrides: t
            .overrides
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|o| PriorityOverrideOut {
                select: o.select.clone().unwrap_or_default(),
                values: priorities(&o.values.clone().unwrap_or_default()),
            })
            .collect(),
        camouflage: cam.map(|c| CamouflageOut {
            mode: match c.mode {
                wp::CamouflageMode::Refuse => "refuse",
                _ => "website",
            },
            domain: c.domain.clone().unwrap_or_default(),
        }),
        padding,
    };
    let mut s = header(applied, "transport settings");
    s.push_str(&yaml(&out)?);
    match cam {
        None => s.push_str("# camouflage: not set (relays don't offer AnyTLS)\n"),
        Some(c) => {
            let chain: Vec<Vec<u8>> = c
                .certificate
                .clone()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|b| b.data)
                .collect();
            if c.mode == wp::CamouflageMode::Website {
                s.push_str("# Website mode: add `certificate: <file>` above (the chain below) to apply this file again.\n");
            }
            let _ = writeln!(s, "# Certificate chain ({} certificate(s)):", chain.len());
            for der in &chain {
                for line in pem(der).lines() {
                    let _ = writeln!(s, "#   {line}");
                }
            }
            if c.next_spki.is_some() {
                s.push_str("# A next certificate key is announced (next_certificate was set).\n");
            }
        }
    }
    Ok(s)
}

// ---------------------------------------------------------------- dns

#[derive(serde::Serialize)]
struct DnsOut {
    version: u64,
    suffix: String,
    resolver_ip: Vec<String>,
    records: Vec<DnsRecordOut>,
    forward: Vec<ForwardOut>,
}

#[derive(serde::Serialize)]
struct DnsRecordOut {
    name: String,
    #[serde(rename = "type")]
    rtype: &'static str,
    value: String,
    ttl: u32,
}

#[derive(serde::Serialize)]
struct ForwardOut {
    zone: String,
    servers: Vec<String>,
    rewrite: Vec<String>,
}

pub fn dns(tree: &Value) -> Result<String> {
    let cur: Option<wp::DnsConfig> = leaf(tree, "dns")?;
    let applied = cur.is_some();
    let d = cur.unwrap_or(wp::DnsConfig {
        version: 0,
        suffix: None,
        resolver_ip: None,
        records: None,
        forward: None,
    });
    let set_resolver: Vec<String> = d
        .resolver_ip
        .clone()
        .unwrap_or_default()
        .iter()
        .map(ip_str)
        .collect();
    // The resolver in force: the configured one, or the default from the pool.
    let resolver: Vec<String> = if set_resolver.is_empty() {
        tree["resolver"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect()
    } else {
        set_resolver.clone()
    };
    let out = DnsOut {
        version: d.version,
        suffix: d
            .suffix
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| tree["suffix"].as_str().unwrap_or("internal").to_string()),
        resolver_ip: resolver,
        records: d
            .records
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|r| DnsRecordOut {
                name: r.name.clone().unwrap_or_default(),
                rtype: match r.rtype {
                    wp::DnsType::A => "A",
                    wp::DnsType::Aaaa => "AAAA",
                    wp::DnsType::Cname => "CNAME",
                    wp::DnsType::Txt => "TXT",
                    wp::DnsType::Srv => "SRV",
                },
                value: r.value.clone().unwrap_or_default(),
                ttl: r.ttl,
            })
            .collect(),
        forward: d
            .forward
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|f| ForwardOut {
                zone: f.zone.clone().unwrap_or_default(),
                servers: f
                    .servers
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .map(ip_str)
                    .collect(),
                rewrite: f
                    .rewrite
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .map(grant_str)
                    .collect(),
            })
            .collect(),
    };
    let mut s = header(applied, "DNS settings");
    if set_resolver.is_empty() {
        s.push_str("# resolver_ip: the default, the top address of the overlay pool.\n");
    }
    s.push_str(&yaml(&out)?);
    Ok(s)
}

// ---------------------------------------------------------------- seeds

#[derive(serde::Serialize)]
struct SeedsOut {
    version: u64,
    seeds: Vec<SeedOut>,
}

#[derive(serde::Serialize)]
struct SeedOut {
    node: String,
    addrs: Vec<String>,
}

fn seed_addr(a: &wp::SeedAddr) -> String {
    let host = a.host.clone().unwrap_or_default();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    format!("{}:{host}:{}", a.transport.name(), a.port)
}

pub fn seeds(tree: &Value) -> Result<String> {
    let cur: Option<wp::Seeds> = leaf(tree, "seeds")?;
    let applied = cur.is_some();
    let out = SeedsOut {
        version: cur.as_ref().map(|c| c.version).unwrap_or(0),
        seeds: cur
            .and_then(|c| c.entries)
            .unwrap_or_default()
            .iter()
            .map(|e| SeedOut {
                node: e.node.clone().unwrap_or_default(),
                addrs: e
                    .addrs
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .map(seed_addr)
                    .collect(),
            })
            .collect(),
    };
    let mut s = header(applied, "seed list");
    if !applied {
        s.push_str("# Without seeds, nodes reach the network through the controllers in their enrollment.\n");
    }
    s.push_str(&yaml(&out)?);
    Ok(s)
}

// ---------------------------------------------------------------- limits

#[derive(serde::Serialize)]
struct LimitsOut {
    version: u64,
    defaults: BTreeMap<String, u64>,
    overrides: Vec<LimitOverrideOut>,
}

#[derive(serde::Serialize)]
struct LimitOverrideOut {
    select: Vec<String>,
    values: BTreeMap<String, u64>,
}

fn limit_values(v: &[wp::LimitValue]) -> BTreeMap<String, u64> {
    v.iter()
        .map(|x| (x.name.clone().unwrap_or_default(), x.value))
        .collect()
}

pub fn limits(tree: &Value) -> Result<String> {
    let cur: Option<wp::Limits> = leaf(tree, "limits")?;
    let applied = cur.is_some();
    let set = limit_values(
        &cur.as_ref()
            .and_then(|c| c.defaults.clone())
            .unwrap_or_default(),
    );
    let mut defaults = BTreeMap::new();
    let mut unset = Vec::new();
    for l in webjet_core::validate::LIMITS {
        match set.get(l.name).copied().or(l.default) {
            Some(v) => {
                defaults.insert(l.name.to_string(), v);
            }
            None => unset.push(l),
        }
    }
    let out = LimitsOut {
        version: cur.as_ref().map(|c| c.version).unwrap_or(0),
        defaults,
        overrides: cur
            .and_then(|c| c.overrides)
            .unwrap_or_default()
            .iter()
            .map(|o| LimitOverrideOut {
                select: o.select.clone().unwrap_or_default(),
                values: limit_values(&o.values.clone().unwrap_or_default()),
            })
            .collect(),
    };
    let mut s = header(applied, "limits");
    s.push_str(&yaml(&out)?);
    for l in unset {
        let _ = writeln!(s, "# {}: not set ({})", l.name, l.about);
    }
    s.push_str("# A node's own [limits] in webjetd.toml take precedence.\n");
    Ok(s)
}

// ---------------------------------------------------------------- policy

#[derive(serde::Serialize)]
struct PolicyOut {
    version: u64,
    default: &'static str,
    rules: Vec<RuleOut>,
    tests: Vec<TestOut>,
}

#[derive(serde::Serialize)]
struct RuleOut {
    id: String,
    action: &'static str,
    src: Vec<String>,
    dst: Vec<String>,
    ports: Vec<String>,
}

#[derive(serde::Serialize)]
struct TestOut {
    src: String,
    dst: String,
    port: String,
    expect: &'static str,
}

fn action(a: wp::Action) -> &'static str {
    match a {
        wp::Action::Allow => "allow",
        _ => "deny",
    }
}

pub fn policy(tree: &Value) -> Result<String> {
    let cur: Option<wp::Policy> = leaf(tree, "policy")?;
    let applied = cur.is_some();
    let p = cur.unwrap_or(wp::Policy {
        version: 0,
        default_action: wp::Action::Deny,
        rules: None,
        tests: None,
    });
    let out = PolicyOut {
        version: p.version,
        default: action(p.default_action),
        rules: p
            .rules
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|r| RuleOut {
                id: r.id.clone().unwrap_or_default(),
                action: action(r.action),
                src: r.src.clone().unwrap_or_default(),
                dst: r.dst.clone().unwrap_or_default(),
                ports: r.ports.clone().unwrap_or_default(),
            })
            .collect(),
        tests: p
            .tests
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|t| TestOut {
                src: t.src.clone().unwrap_or_default(),
                dst: t.dst.clone().unwrap_or_default(),
                port: t.port.clone().unwrap_or_default(),
                expect: action(t.expect),
            })
            .collect(),
    };
    let mut s = header(applied, "policy");
    if !applied {
        s.push_str("# Default deny: nodes can't reach each other until a policy allows it.\n");
    }
    s.push_str(&yaml(&out)?);
    Ok(s)
}

/// JSON form of the same (for `--json`): the YAML document as JSON.
pub fn as_json(yaml_text: &str) -> Result<Value> {
    Ok(serde_yaml::from_str(yaml_text)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn empty_tree() -> Value {
        json!({
            "transport": null, "dns": null, "seeds": null, "limits": null, "policy": null,
            "resolver": ["10.7.255.254"], "suffix": "internal",
        })
    }

    #[test]
    fn defaults_apply_cleanly() {
        let t = empty_tree();
        let dir = std::env::temp_dir();
        // Every default prints as a file `apply` accepts.
        let tr: crate::TransportFile = serde_yaml::from_str(&transport(&t).unwrap()).unwrap();
        let w = tr.to_wire(&dir).unwrap();
        assert_eq!(w.version, 0);
        assert_eq!(
            w.padding.as_ref().unwrap().stop,
            webjet_core::padding::DEFAULT_STOP
        );
        let d: crate::DnsFile = serde_yaml::from_str(&dns(&t).unwrap()).unwrap();
        assert_eq!(d.suffix.as_deref(), Some("internal"));
        assert_eq!(d.resolver_ip, ["10.7.255.254"]);
        d.to_wire().unwrap();
        let s: crate::SeedsFile = serde_yaml::from_str(&seeds(&t).unwrap()).unwrap();
        assert!(s.seeds.is_empty());
        let l: crate::LimitsFile = serde_yaml::from_str(&limits(&t).unwrap()).unwrap();
        let lw = l.to_wire().unwrap();
        assert_eq!(l.defaults["circuits_per_source"], 64);
        assert!(!l.defaults.contains_key("relay_capacity_mbps"));
        assert_eq!(
            lw.defaults.unwrap().len(),
            webjet_core::validate::LIMITS.len() - 2
        );
        let p: webjet_core::policy::PolicyFile =
            serde_yaml::from_str(&policy(&t).unwrap()).unwrap();
        assert_eq!(p.default, "deny");
        p.to_wire().unwrap();
        assert!(
            transport(&t)
                .unwrap()
                .starts_with("# No transport settings applied yet")
        );
    }

    #[test]
    fn applied_settings_round_trip() {
        let pol = webjet_core::policy::PolicyFile {
            version: 3,
            default: "deny".into(),
            rules: vec![webjet_core::policy::RuleFile {
                id: "web".into(),
                action: "allow".into(),
                src: vec!["tag:laptop".into()],
                dst: vec!["tag:web".into()],
                ports: vec!["tcp:443".into()],
            }],
            tests: vec![],
        };
        let dns_file: crate::DnsFile = serde_yaml::from_str(
            "version: 4\nsuffix: corp\nresolver_ip: [10.7.255.53]\nrecords:\n  - {name: git.corp, type: A, value: 10.7.0.9}\n",
        )
        .unwrap();
        let tf: crate::TransportFile = serde_yaml::from_str(
            "version: 2\ndefaults: {kcp: 0}\noverrides:\n  - select: [tag:relay]\n    values: {tls: 40}\n",
        )
        .unwrap();
        let tree = json!({
            "policy": pol.to_wire().unwrap(),
            "dns": dns_file.to_wire().unwrap(),
            "transport": tf.to_wire(&std::env::temp_dir()).unwrap(),
            "seeds": null, "limits": null, "resolver": ["10.7.255.53"], "suffix": "corp",
        });
        let p: webjet_core::policy::PolicyFile =
            serde_yaml::from_str(&policy(&tree).unwrap()).unwrap();
        assert_eq!(
            (p.version, p.rules[0].ports.clone()),
            (3, vec!["tcp:443".to_string()])
        );
        let d: crate::DnsFile = serde_yaml::from_str(&dns(&tree).unwrap()).unwrap();
        assert_eq!((d.version, d.records[0].rtype.as_str()), (4, "A"));
        let shown = transport(&tree).unwrap();
        let t: crate::TransportFile = serde_yaml::from_str(&shown).unwrap();
        // kcp set to 0, the others keep their built-ins.
        assert_eq!(t.defaults["kcp"], 0);
        assert_eq!(t.defaults["anytls"], 20);
        assert_eq!(t.overrides[0].values["tls"], 40);
        assert!(shown.contains("camouflage: not set"));
    }
}
