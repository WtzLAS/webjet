//! Semantic validation of decoded objects (§15.2 step 2).

use crate::types::{Grant, canonical, sorted_unique, valid_name, valid_tag};
use anyhow::{Result, bail};
use webjet_proto as wp;

pub fn node_record(r: &wp::NodeRecord) -> Result<()> {
    if r.node_id.is_none() || r.identity_key.is_none() || r.owner.is_none() {
        bail!("node record missing id, key or owner");
    }
    let name = r.name.as_deref().unwrap_or("");
    if !valid_name(name) {
        bail!("invalid node name {name:?}");
    }
    let ips = r.overlay_ips.as_deref().unwrap_or_default();
    for c in ips {
        canonical(c)?;
    }
    if !sorted_unique(ips) {
        bail!("overlay_ips not sorted/unique");
    }
    let roles = r.roles.as_deref().unwrap_or_default();
    if !sorted_unique(roles) {
        bail!("roles not sorted/unique");
    }
    let tags = r.tags.as_deref().unwrap_or_default();
    if !tags.iter().all(|t| valid_tag(t)) || !sorted_unique(tags) {
        bail!("tags invalid or not sorted/unique");
    }
    let routes = r.routes.as_deref().unwrap_or_default();
    for g in routes {
        Grant::from_wire(g)?;
    }
    if !sorted_unique(routes) {
        bail!("routes not sorted/unique");
    }
    Ok(())
}

pub fn account_record(r: &wp::AccountRecord) -> Result<()> {
    if r.account_id.is_none() || r.account_key.is_none() {
        bail!("account record missing id or key");
    }
    let name = r.name.as_deref().unwrap_or("");
    if !valid_name(name) {
        bail!("invalid account name {name:?}");
    }
    if !r.issuer_root && r.issuer.is_none() {
        bail!("account record without issuer");
    }
    if r.admin && !r.issuer_root {
        bail!("admin accounts must be signed by the root");
    }
    Ok(())
}

pub fn valid_dns_name(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// A resource limit (§16.2) and its built-in default. `None` means the
/// default is "not set": relay capacity is estimated, the send rate has no
/// ceiling.
pub struct LimitSpec {
    pub name: &'static str,
    pub default: Option<u64>,
    pub about: &'static str,
}

const fn lim(name: &'static str, default: u64, about: &'static str) -> LimitSpec {
    LimitSpec {
        name,
        default: Some(default),
        about,
    }
}

/// Every limit the Limits leaf may set, with the built-in defaults (§16.2).
pub const LIMITS: &[LimitSpec] = &[
    lim("conntrack_per_peer", 4096, "tracked flows per peer"),
    lim(
        "conntrack_new_per_sec",
        500,
        "new flows per second per peer",
    ),
    lim(
        "conntrack_global",
        262_144,
        "tracked flows in total (clamped to memory)",
    ),
    lim(
        "snat_ports_per_source",
        2048,
        "gateway: translated flows per source node",
    ),
    lim("snat_global", 65_536, "gateway: translated flows in total"),
    lim("circuits_per_source", 64, "relay: circuits per source node"),
    lim(
        "circuit_setups_per_sec",
        10,
        "relay: circuit setups per second per source node",
    ),
    lim("circuits_global", 50_000, "relay: circuits in total"),
    LimitSpec {
        name: "relay_capacity_mbps",
        default: None,
        about: "relay: capacity for the load figure; estimated when unset",
    },
    LimitSpec {
        name: "rate_ceiling_mbps",
        default: None,
        about: "highest send rate; no ceiling when unset",
    },
    lim(
        "e2e_handshakes_per_sec",
        10,
        "end-to-end handshakes per second per peer",
    ),
    lim(
        "e2e_handshakes_in_progress",
        4,
        "end-to-end handshakes in progress per peer (one session runs at most one)",
    ),
    lim(
        "e2e_handshakes_global",
        1000,
        "end-to-end handshakes in progress in total",
    ),
    lim(
        "handshake_queue",
        64,
        "packets queued per session before its handshake",
    ),
    lim(
        "hop_handshakes_per_ip",
        5,
        "hop TLS handshakes in progress per source IP",
    ),
    lim("lookups_per_sec", 20, "relay: lookups per second per peer"),
    lim(
        "subscriptions_per_peer",
        256,
        "relay: nodes a peer may subscribe to",
    ),
    lim(
        "multicast_packets_per_sec",
        50,
        "broadcast and multicast copies sent per second, and taken per sender; 0 turns them off",
    ),
    lim(
        "multicast_bytes_per_sec",
        65_536,
        "broadcast and multicast bytes sent per second (every copy counts), and taken per sender",
    ),
];

/// Limits that may be 0, which turns their feature off.
pub const ZERO_TURNS_OFF: &[&str] = &["multicast_packets_per_sec"];

/// The built-in default of a limit (`None`: not set by default, or unknown).
pub fn limit_default(name: &str) -> Option<u64> {
    LIMITS
        .iter()
        .find(|l| l.name == name)
        .and_then(|l| l.default)
}

pub fn known_limit(name: &str) -> bool {
    LIMITS.iter().any(|l| l.name == name)
}

pub fn limits(l: &wp::Limits) -> Result<()> {
    let check = |v: &[wp::LimitValue]| -> Result<()> {
        for x in v {
            let n = x.name.as_deref().unwrap_or("");
            if !known_limit(n) {
                bail!("unknown limit {n:?}");
            }
            if x.value == 0 && !ZERO_TURNS_OFF.contains(&n) {
                bail!("limit {n} must be positive");
            }
        }
        Ok(())
    };
    check(l.defaults.as_deref().unwrap_or_default())?;
    for o in l.overrides.iter().flatten() {
        for s in o.select.iter().flatten() {
            crate::policy::Selector::parse(s)?;
        }
        check(o.values.as_deref().unwrap_or_default())?;
    }
    Ok(())
}

pub fn transport(t: &wp::TransportConfig) -> Result<()> {
    for o in t.overrides.iter().flatten() {
        for s in o.select.iter().flatten() {
            crate::policy::Selector::parse(s)?;
        }
    }
    if let Some(c) = &t.camouflage
        && let Some(d) = &c.domain
        && !d.is_empty()
        && !valid_dns_name(d)
    {
        bail!("invalid camouflage domain {d:?}");
    }
    if let Some(p) = &t.padding {
        for l in p.lines.iter().flatten() {
            crate::padding::parse_line(l)?;
        }
    }
    if let Some(c) = &t.compression {
        compression(c)?;
    }
    if let Some(m) = &t.multicast {
        multicast(m)?;
    }
    let overrides = t.nat_overrides.as_deref().unwrap_or_default();
    if overrides.len() > 64 {
        bail!("nat: at most 64 overrides");
    }
    for o in overrides {
        for s in o.select.iter().flatten() {
            crate::policy::Selector::parse(s)?;
        }
    }
    Ok(())
}

/// A `[nat]` table that sets nothing (a node configuration with only that
/// is empty).
pub fn nat_unset(s: &wp::NatSettings) -> bool {
    s.punch.is_none()
        && s.predict.is_none()
        && s.port_mapping.is_none()
        && s.host_candidates.is_none()
}

/// `[controllers]` (§7.5): an odd voter target of at most 7, and a dead
/// voter delay of 0 (never) or at least a minute.
pub fn controller_settings(c: &wp::ControllerSettings) -> Result<()> {
    if let Some(v) = c.voters
        && !matches!(v, 1 | 3 | 5 | 7)
    {
        bail!("controllers.voters must be 1, 3, 5 or 7 (an odd number, at most 7), not {v}");
    }
    if let Some(d) = c.dead_voter_after_s
        && d != 0
        && d < crate::membership::MIN_DEAD_AFTER_S
    {
        bail!(
            "controllers.dead_voter_after_s must be 0 (never) or at least {} seconds, not {d}",
            crate::membership::MIN_DEAD_AFTER_S
        );
    }
    Ok(())
}

/// Compression settings (§9.8): control off or zstd, data off or lz4.
pub fn compression(c: &wp::CompressionConfig) -> Result<()> {
    crate::compress::check(c.control, c.data)
}

/// `[multicast]` (§9.5.2): capture takes UDP port specs only.
pub fn multicast(m: &wp::MulticastConfig) -> Result<()> {
    let capture = m.capture.as_deref().unwrap_or_default();
    if capture.len() > 64 {
        bail!("multicast.capture: at most 64 port specs");
    }
    crate::multicast::CapturePorts::parse(capture)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::k32;

    fn cidr(s: &str) -> wp::Cidr {
        crate::types::net_to_cidr(&s.parse().unwrap())
    }

    fn node() -> wp::NodeRecord {
        wp::NodeRecord {
            node_id: Some(k32(&[1; 32])),
            identity_key: Some(k32(&[2; 32])),
            owner: Some(k32(&[3; 32])),
            name: Some("web-01".into()),
            overlay_ips: Some(vec![cidr("10.7.0.2/32"), cidr("fd00::2/128")]),
            roles: Some(vec![wp::Role::Data, wp::Role::Relay]),
            tags: Some(vec!["tag:a".into(), "tag:b".into()]),
            routes: Some(vec![wp::RouteGrant {
                lan: cidr("192.168.1.0/24"),
                published: cidr("10.2.2.0/24"),
            }]),
            version: 1,
            control: None,
        }
    }

    #[test]
    fn node_record_accepts_a_good_record() {
        node_record(&node()).unwrap();
        // Every list may be missing.
        node_record(&wp::NodeRecord {
            overlay_ips: None,
            roles: None,
            tags: None,
            routes: None,
            ..node()
        })
        .unwrap();
    }

    #[test]
    fn node_record_rejects() {
        let bad: Vec<(&str, wp::NodeRecord)> = vec![
            (
                "no id",
                wp::NodeRecord {
                    node_id: None,
                    ..node()
                },
            ),
            (
                "no key",
                wp::NodeRecord {
                    identity_key: None,
                    ..node()
                },
            ),
            (
                "no owner",
                wp::NodeRecord {
                    owner: None,
                    ..node()
                },
            ),
            (
                "no name",
                wp::NodeRecord {
                    name: None,
                    ..node()
                },
            ),
            (
                "bad name",
                wp::NodeRecord {
                    name: Some("Web_01".into()),
                    ..node()
                },
            ),
            (
                "host bits",
                wp::NodeRecord {
                    overlay_ips: Some(vec![wp::Cidr::new("10.7.0.2".parse().unwrap(), 24)]),
                    ..node()
                },
            ),
            (
                "unsorted ips",
                wp::NodeRecord {
                    overlay_ips: Some(vec![cidr("10.7.0.3/32"), cidr("10.7.0.2/32")]),
                    ..node()
                },
            ),
            (
                "duplicate ips",
                wp::NodeRecord {
                    overlay_ips: Some(vec![cidr("10.7.0.2/32"), cidr("10.7.0.2/32")]),
                    ..node()
                },
            ),
            (
                "unsorted roles",
                wp::NodeRecord {
                    roles: Some(vec![wp::Role::Relay, wp::Role::Data]),
                    ..node()
                },
            ),
            (
                "bad tag",
                wp::NodeRecord {
                    tags: Some(vec!["a".into()]),
                    ..node()
                },
            ),
            (
                "unsorted tags",
                wp::NodeRecord {
                    tags: Some(vec!["tag:b".into(), "tag:a".into()]),
                    ..node()
                },
            ),
            (
                "/0 route",
                wp::NodeRecord {
                    routes: Some(vec![wp::RouteGrant {
                        lan: cidr("0.0.0.0/0"),
                        published: cidr("0.0.0.0/0"),
                    }]),
                    ..node()
                },
            ),
            (
                "route changes prefix length",
                wp::NodeRecord {
                    routes: Some(vec![wp::RouteGrant {
                        lan: cidr("192.168.1.0/24"),
                        published: cidr("10.2.0.0/16"),
                    }]),
                    ..node()
                },
            ),
            (
                "duplicate routes",
                wp::NodeRecord {
                    routes: Some(vec![
                        wp::RouteGrant {
                            lan: cidr("192.168.1.0/24"),
                            published: cidr("192.168.1.0/24"),
                        },
                        wp::RouteGrant {
                            lan: cidr("192.168.1.0/24"),
                            published: cidr("192.168.1.0/24"),
                        },
                    ]),
                    ..node()
                },
            ),
        ];
        for (what, r) in bad {
            assert!(node_record(&r).is_err(), "{what} accepted");
        }
    }

    fn account() -> wp::AccountRecord {
        wp::AccountRecord {
            account_id: Some(k32(&[1; 32])),
            account_key: Some(k32(&[2; 32])),
            name: Some("alice".into()),
            admin: false,
            issuer_root: false,
            issuer: Some(k32(&[3; 32])),
            version: 1,
        }
    }

    #[test]
    fn account_records() {
        account_record(&account()).unwrap();
        // Root-signed accounts and admins need no issuer.
        account_record(&wp::AccountRecord {
            issuer_root: true,
            issuer: None,
            ..account()
        })
        .unwrap();
        account_record(&wp::AccountRecord {
            admin: true,
            issuer_root: true,
            issuer: None,
            ..account()
        })
        .unwrap();

        assert!(
            account_record(&wp::AccountRecord {
                account_id: None,
                ..account()
            })
            .is_err()
        );
        assert!(
            account_record(&wp::AccountRecord {
                account_key: None,
                ..account()
            })
            .is_err()
        );
        assert!(
            account_record(&wp::AccountRecord {
                name: Some("".into()),
                ..account()
            })
            .is_err()
        );
        assert!(
            account_record(&wp::AccountRecord {
                issuer: None,
                ..account()
            })
            .is_err()
        );
        // An admin signed by another admin.
        assert!(
            account_record(&wp::AccountRecord {
                admin: true,
                ..account()
            })
            .is_err()
        );
    }

    #[test]
    fn dns_names() {
        for ok in [
            "example.com",
            "example.com.",
            "a",
            "_dmarc.x-y.example",
            &"a".repeat(63),
        ] {
            assert!(valid_dns_name(ok), "{ok:?}");
        }
        let long = vec!["a".repeat(63); 4].join("."); // 255 characters
        for bad in [
            "",
            ".",
            "a..b",
            "-a.com",
            "a-.com",
            "a b.com",
            "é.com",
            &"a".repeat(64),
            &long,
        ] {
            assert!(!valid_dns_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn limit_table() {
        assert_eq!(limit_default("conntrack_per_peer"), Some(4096));
        assert_eq!(limit_default("relay_capacity_mbps"), None);
        assert_eq!(limit_default("nope"), None);
        assert!(known_limit("relay_capacity_mbps"));
        assert!(!known_limit("nope"));
        let mut names: Vec<_> = LIMITS.iter().map(|l| l.name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), LIMITS.len(), "duplicate limit names");
        assert!(LIMITS.iter().all(|l| l.default != Some(0)));
    }

    fn lv(name: &str, value: u64) -> wp::LimitValue {
        wp::LimitValue {
            name: Some(name.into()),
            value,
        }
    }

    #[test]
    fn limits_leaf() {
        let good = wp::Limits {
            version: 1,
            defaults: Some(vec![lv("conntrack_per_peer", 100)]),
            overrides: Some(vec![wp::LimitOverride {
                select: Some(vec!["tag:big".into()]),
                values: Some(vec![lv("rate_ceiling_mbps", 50)]),
            }]),
        };
        limits(&good).unwrap();
        limits(&wp::Limits::default()).unwrap();

        let unknown = wp::Limits {
            defaults: Some(vec![lv("nope", 1)]),
            ..good.clone()
        };
        assert!(limits(&unknown).is_err());
        let zero = wp::Limits {
            defaults: Some(vec![lv("conntrack_per_peer", 0)]),
            ..good.clone()
        };
        assert!(limits(&zero).is_err());
        let bad_override = wp::Limits {
            overrides: Some(vec![wp::LimitOverride {
                select: Some(vec!["tag:big".into()]),
                values: Some(vec![lv("circuits_global", 0)]),
            }]),
            ..good.clone()
        };
        assert!(limits(&bad_override).is_err());
        let bad_selector = wp::Limits {
            overrides: Some(vec![wp::LimitOverride {
                select: Some(vec!["bogus:x".into()]),
                values: None,
            }]),
            ..good
        };
        assert!(limits(&bad_selector).is_err());
    }

    #[test]
    fn transport_leaf() {
        let camo = |d: &str| wp::TransportConfig {
            camouflage: Some(Box::new(wp::Camouflage {
                domain: Some(d.into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        transport(&wp::TransportConfig::default()).unwrap();
        transport(&camo("www.example.com")).unwrap();
        transport(&camo("")).unwrap(); // empty: no domain
        assert!(transport(&camo("bad domain")).is_err());

        let pad = |l: &str| wp::TransportConfig {
            padding: Some(Box::new(wp::PaddingScheme {
                stop: 2,
                lines: Some(vec![l.into()]),
            })),
            ..Default::default()
        };
        transport(&pad("0=30-30,c,100-200")).unwrap();
        assert!(transport(&pad("0=30")).is_err());
        assert!(transport(&pad("0=200-100")).is_err());

        let comp = |control, data| wp::TransportConfig {
            compression: Some(Box::new(wp::CompressionConfig { control, data })),
            ..Default::default()
        };
        use crate::compress::algo;
        transport(&comp(algo::ZSTD, algo::LZ4)).unwrap();
        transport(&comp(algo::UNSET, algo::OFF)).unwrap();
        assert!(transport(&comp(algo::LZ4, algo::UNSET)).is_err());
        assert!(transport(&comp(algo::UNSET, algo::ZSTD)).is_err());
        assert!(transport(&comp(99, algo::UNSET)).is_err());
    }

    #[test]
    fn controllers_leaf() {
        let c = |voters, dead| wp::ControllerSettings {
            voters,
            dead_voter_after_s: dead,
            ..Default::default()
        };
        for v in [1, 3, 5, 7] {
            controller_settings(&c(Some(v), None)).unwrap();
        }
        for v in [0, 2, 4, 9] {
            assert!(
                controller_settings(&c(Some(v), None)).is_err(),
                "{v} voters"
            );
        }
        controller_settings(&c(None, None)).unwrap();
        controller_settings(&c(None, Some(0))).unwrap();
        controller_settings(&c(None, Some(crate::membership::MIN_DEAD_AFTER_S))).unwrap();
        assert!(
            controller_settings(&c(None, Some(crate::membership::MIN_DEAD_AFTER_S - 1))).is_err()
        );
    }
}
