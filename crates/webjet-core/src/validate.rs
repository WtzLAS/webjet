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

pub const LIMIT_NAMES: &[&str] = &[
    "conntrack_per_peer",
    "conntrack_new_per_sec",
    "conntrack_global",
    "snat_ports_per_source",
    "snat_global",
    "circuits_per_source",
    "circuit_setups_per_sec",
    "circuits_global",
    "relay_capacity_mbps",
    "rate_ceiling_mbps",
    "e2e_handshakes_per_sec",
    "e2e_handshakes_in_progress",
    "e2e_handshakes_global",
    "handshake_queue",
    "hop_handshakes_per_ip",
    "lookups_per_sec",
    "subscriptions_per_peer",
];

pub fn limits(l: &wp::Limits) -> Result<()> {
    let check = |v: &[wp::LimitValue]| -> Result<()> {
        for x in v {
            let n = x.name.as_deref().unwrap_or("");
            if !LIMIT_NAMES.contains(&n) {
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
    Ok(())
}
