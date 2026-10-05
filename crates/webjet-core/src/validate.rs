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
    let ips = r.overlay_ips.clone().unwrap_or_default();
    for c in &ips {
        canonical(c)?;
    }
    if !sorted_unique(&ips) {
        bail!("overlay_ips not sorted/unique");
    }
    let roles = r.roles.clone().unwrap_or_default();
    if !sorted_unique(&roles) {
        bail!("roles not sorted/unique");
    }
    let tags = r.tags.clone().unwrap_or_default();
    if !tags.iter().all(|t| valid_tag(t)) || !sorted_unique(&tags) {
        bail!("tags invalid or not sorted/unique");
    }
    let routes = r.routes.clone().unwrap_or_default();
    for g in &routes {
        Grant::from_wire(g)?;
    }
    if !sorted_unique(&routes) {
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
];

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
            if x.value == 0 {
                bail!("limit {n} must be positive");
            }
        }
        Ok(())
    };
    check(&l.defaults.clone().unwrap_or_default())?;
    for o in l.overrides.clone().unwrap_or_default() {
        for s in o.select.clone().unwrap_or_default() {
            crate::policy::Selector::parse(&s)?;
        }
        check(&o.values.clone().unwrap_or_default())?;
    }
    Ok(())
}

pub fn transport(t: &wp::TransportConfig) -> Result<()> {
    for o in t.overrides.clone().unwrap_or_default() {
        for s in o.select.clone().unwrap_or_default() {
            crate::policy::Selector::parse(&s)?;
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
        for l in p.lines.clone().unwrap_or_default() {
            crate::padding::parse_line(&l)?;
        }
    }
    if let Some(c) = &t.compression {
        compression(c)?;
    }
    Ok(())
}

/// Compression settings (§9.8): control off or zstd, data off or lz4.
pub fn compression(c: &wp::CompressionConfig) -> Result<()> {
    crate::compress::check(c.control, c.data)
}
