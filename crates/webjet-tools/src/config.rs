//! The configuration document (TOML) behind `webjetctl network config` and
//! `webjetctl local config` (§6.18, §6.19).
//!
//! One schema, two scopes:
//! - **network scope** (`network.toml`, admins): `[policy]`, `[dns]`,
//!   `[[seeds]]`, `[transport]`, `[limits]`, `[controllers]` — the same on
//!   every node.
//! - **node scope** (one node, its owner or an admin): a subset that
//!   overrides or extends the network's for that node only:
//!   `[transport.priority]`, `[limits.value]`, `[[seeds]]` (tried first),
//!   `[[dns.record]]` and `[[dns.forward]]` (answered by that node only).
//!
//! `version` is the version the file was made from (`show` prints it).
//! `apply` refuses a file whose version is no longer the one in force, so a
//! change made meanwhile by someone else isn't overwritten, and submits the
//! next version itself.
//!
//! A top-level section the file leaves out (`[policy]`, `[dns]`, `seeds`,
//! `[transport]`, `[limits]`, `[controllers]`) stays as it is; a section that is present
//! replaces the current one completely, so an empty `[limits]` goes back to
//! the built-in limits and `seeds = []` removes the seeds.

use crate::{RefuseCertificate, parse_seed_addr, pem_certs, refuse_certificate};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use webjet_core::crypto;
use webjet_core::policy::{PolicyFile, RuleFile, TestFile};
use webjet_core::types::Grant;
use webjet_proto::{self as wp, Transport};

/// Where a configuration applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The whole network (`webjetctl network config`).
    Network,
    /// One node (`webjetctl local config`).
    Node,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    /// The version this file was made from (0 = nothing applied yet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seeds: Option<Vec<SeedSection>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<LimitsSection>,
    /// Reverse proxy ports (node scope only, §11.11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Vec<ProxyFile>>,
    /// The controller cluster's membership (network scope only, §7.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controllers: Option<ControllersSection>,
}

/// `[controllers]` (§7.5): how the Raft leader manages membership. A key
/// left out takes the built-in value.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllersSection {
    /// The leader adds controllers as learners, promotes the earliest-joined
    /// ones to voters (an odd number, at most `voters`), removes revoked
    /// ones and replaces dead voters. Built-in true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_membership: Option<bool>,
    /// Target number of voters: 1, 3, 5 or 7. Built-in 5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voters: Option<u8>,
    /// Seconds a voter may be unreachable before a healthy learner takes
    /// its place; 0 = never. Built-in 3600.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead_voter_after_s: Option<u32>,
}

impl ControllersSection {
    fn to_wire(&self, version: u64) -> Result<wp::ControllerSettings> {
        let c = wp::ControllerSettings {
            version,
            auto_membership: self.auto_membership,
            voters: self.voters,
            dead_voter_after_s: self.dead_voter_after_s,
        };
        webjet_core::validate::controller_settings(&c)?;
        Ok(c)
    }

    fn from_wire(c: &wp::ControllerSettings) -> ControllersSection {
        ControllersSection {
            auto_membership: c.auto_membership,
            voters: c.voters,
            dead_voter_after_s: c.dead_voter_after_s,
        }
    }
}

/// `[[proxy]]`: listen on a TCP or UDP port of this node and forward each
/// flow to a port of another node, of the data nodes some selectors pick,
/// or of an address behind a gateway.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyFile {
    pub name: String,
    /// `tcp` or `udp`.
    pub protocol: String,
    pub listen_port: u16,
    /// One address, or selectors (`tag:web`, `node:web-01`, `role:data`).
    pub target: Vec<String>,
    pub target_port: u16,
    /// Keep the client's address as the source (default true).
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub real_ip: bool,
}

fn yes() -> bool {
    true
}

fn is_true(v: &bool) -> bool {
    *v
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suffix: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolver_ip: Vec<String>,
    #[serde(default, rename = "record", skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<DnsRecordFile>,
    #[serde(default, rename = "forward", skip_serializing_if = "Vec::is_empty")]
    pub forward: Vec<ForwardFile>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRecordFile {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub ttl: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardFile {
    pub zone: String,
    pub servers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rewrite: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedSection {
    pub node: String,
    pub addrs: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportSection {
    /// Priority per transport (`kcp`, `anytls`, `tls`), 0–255; 0 = never.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub priority: BTreeMap<String, u8>,
    #[serde(default, rename = "override", skip_serializing_if = "Vec::is_empty")]
    pub overrides: Vec<PriorityOverrideFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camouflage: Option<CamouflageFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding: Option<PaddingFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression: Option<CompressionFile>,
}

/// `[transport.compression]` (§9.8): `control` = `zstd` | `off` (built-in
/// zstd), `data` = `lz4` | `off` (built-in off). A key left out takes the
/// next level's value (node → network → built-in).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

impl CompressionFile {
    fn to_wire(&self) -> Result<wp::CompressionConfig> {
        use webjet_core::compress::algo;
        let val = |v: &Option<String>, key: &str| -> Result<u8> {
            match v.as_deref() {
                None => Ok(algo::UNSET),
                Some(s) => algo::parse(s)
                    .ok_or_else(|| anyhow!("transport.compression.{key}: unknown value {s:?}")),
            }
        };
        let c = wp::CompressionConfig {
            control: val(&self.control, "control")?,
            data: val(&self.data, "data")?,
        };
        webjet_core::validate::compression(&c)?;
        Ok(c)
    }

    /// From the wire; `None` when nothing is set.
    fn from_wire(c: Option<&wp::CompressionConfig>) -> Option<CompressionFile> {
        use webjet_core::compress::algo;
        let c = c?;
        let name = |v: u8| (v != algo::UNSET).then(|| algo::name(v).to_string());
        let f = CompressionFile {
            control: name(c.control),
            data: name(c.data),
        };
        (f != CompressionFile::default()).then_some(f)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorityOverrideFile {
    pub select: Vec<String>,
    pub priority: BTreeMap<String, u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CamouflageFile {
    /// `website` or `refuse`.
    pub mode: String,
    /// SNI and certificate name. Website mode only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The certificate chain, leaf first: PEM text, or the name of a PEM
    /// file (relative to this file). Website mode only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// The next key's certificate (PEM text or file), announced for a key
    /// change (ops guide 3.2). Website mode only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_certificate: Option<String>,
    /// The announced next key as a hex SPKI pin, as `show` prints it;
    /// `next_certificate` takes precedence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_spki: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaddingFile {
    pub stop: u32,
    pub lines: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    /// Limit values by name (`webjet_core::validate::LIMITS`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub value: BTreeMap<String, u64>,
    #[serde(default, rename = "override", skip_serializing_if = "Vec::is_empty")]
    pub overrides: Vec<LimitOverrideFile>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitOverrideFile {
    pub select: Vec<String>,
    pub value: BTreeMap<String, u64>,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

// ---------------------------------------------------------------- parsing

impl ConfigFile {
    pub fn parse(text: &str) -> Result<ConfigFile> {
        Ok(toml::from_str(text)?)
    }

    pub fn load(path: &Path) -> Result<ConfigFile> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        ConfigFile::parse(&text).with_context(|| format!("parse {}", path.display()))
    }

    pub fn to_toml(&self) -> Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }

    /// The version the file was made from; apply needs it.
    pub fn base_version(&self) -> Result<u64> {
        self.version.ok_or_else(|| {
            anyhow!(
                "the file has no `version`: start from `show`, which prints the version in force"
            )
        })
    }

    /// Settings that the scope doesn't allow. Node scope may only override
    /// priorities and limits and add seeds and DNS records/zones.
    pub fn check_scope(&self, scope: Scope) -> Result<()> {
        if scope == Scope::Network {
            if self.proxy.is_some() {
                bail!(
                    "[[proxy]] rules belong to a node (`webjetctl local config [--node NAME]`), not the network"
                );
            }
            return Ok(());
        }
        let mut bad = Vec::new();
        if self.policy.is_some() {
            bad.push("policy");
        }
        if self.controllers.is_some() {
            bad.push("controllers");
        }
        if let Some(d) = &self.dns {
            if d.suffix.is_some() {
                bad.push("dns.suffix");
            }
            if !d.resolver_ip.is_empty() {
                bad.push("dns.resolver_ip");
            }
        }
        if let Some(t) = &self.transport {
            if !t.overrides.is_empty() {
                bad.push("transport.override");
            }
            if t.camouflage.is_some() {
                bad.push("transport.camouflage");
            }
            if t.padding.is_some() {
                bad.push("transport.padding");
            }
        }
        if let Some(l) = &self.limits
            && !l.overrides.is_empty()
        {
            bad.push("limits.override");
        }
        if bad.is_empty() {
            return Ok(());
        }
        bail!(
            "{} can only be set for the whole network (`webjetctl network config`); a node's configuration holds transport.priority, transport.compression, limits.value, seeds, dns.record, dns.forward and proxy",
            bad.join(", ")
        )
    }

    /// The network configuration on the wire, at `version`. `base` is the
    /// directory certificate files are relative to. Refuse mode's
    /// certificate is filled in by [`fill_refuse_certificate`].
    pub fn to_network(&self, version: u64, base: &Path) -> Result<wp::NetworkConfig> {
        self.check_scope(Scope::Network)?;
        let policy = self.policy.clone().unwrap_or_default().to_wire(version)?;
        let dns = self.dns.clone().unwrap_or_default();
        let t = self.transport.clone().unwrap_or_default();
        let l = self.limits.clone().unwrap_or_default();
        let transport = wp::TransportConfig {
            version,
            defaults: Some(priorities(&t.priority)?),
            overrides: Some(
                t.overrides
                    .iter()
                    .map(|o| {
                        Ok(wp::PriorityOverride {
                            select: Some(o.select.clone()),
                            values: Some(priorities(&o.priority)?),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
            camouflage: t
                .camouflage
                .as_ref()
                .map(|c| c.to_wire(base).map(Box::new))
                .transpose()?,
            padding: t.padding.as_ref().map(|p| {
                Box::new(wp::PaddingScheme {
                    stop: p.stop,
                    lines: Some(p.lines.clone()),
                })
            }),
            compression: t
                .compression
                .as_ref()
                .map(|c| c.to_wire().map(Box::new))
                .transpose()?,
        };
        webjet_core::validate::transport(&transport)?;
        let limits = wp::Limits {
            version,
            defaults: Some(limit_values(&l.value)),
            overrides: Some(
                l.overrides
                    .iter()
                    .map(|o| wp::LimitOverride {
                        select: Some(o.select.clone()),
                        values: Some(limit_values(&o.value)),
                    })
                    .collect(),
            ),
        };
        webjet_core::validate::limits(&limits)?;
        Ok(wp::NetworkConfig {
            version,
            policy: Some(Box::new(policy)),
            dns: Some(Box::new(wp::DnsConfig {
                version,
                suffix: dns.suffix.clone(),
                resolver_ip: Some(
                    dns.resolver_ip
                        .iter()
                        .map(|s| {
                            Ok(wp::IpAddress::from_ip(s.parse().with_context(|| {
                                format!("dns.resolver_ip: {s:?} is not an address")
                            })?))
                        })
                        .collect::<Result<Vec<_>>>()?,
                ),
                records: Some(records(&dns.records)?),
                forward: Some(forwards(&dns.forward)?),
            })),
            seeds: Some(Box::new(wp::Seeds {
                version,
                entries: Some(seeds(&self.seeds.clone().unwrap_or_default())?),
            })),
            limits: Some(Box::new(limits)),
            transport: Some(Box::new(transport)),
            controllers: self
                .controllers
                .as_ref()
                .map(|c| c.to_wire(version).map(Box::new))
                .transpose()?,
        })
    }

    /// One node's configuration on the wire, at `version`.
    pub fn to_node(&self, node_id: &crypto::Bytes32, version: u64) -> Result<wp::NodeConfig> {
        self.check_scope(Scope::Node)?;
        let dns = self.dns.clone().unwrap_or_default();
        let limits = limit_values(
            &self
                .limits
                .as_ref()
                .map(|l| l.value.clone())
                .unwrap_or_default(),
        );
        webjet_core::validate::limits(&wp::Limits {
            version: 0,
            defaults: Some(limits.clone()),
            overrides: None,
        })?;
        Ok(wp::NodeConfig {
            node_id: Some(crypto::k32(node_id)),
            version,
            priorities: Some(priorities(
                &self
                    .transport
                    .as_ref()
                    .map(|t| t.priority.clone())
                    .unwrap_or_default(),
            )?),
            limits: Some(limits),
            seeds: Some(seeds(&self.seeds.clone().unwrap_or_default())?),
            dns_records: Some(records(&dns.records)?),
            dns_forward: Some(forwards(&dns.forward)?),
            proxy: Some(proxy_rules(&self.proxy.clone().unwrap_or_default())?),
            compression: self
                .transport
                .as_ref()
                .and_then(|t| t.compression.as_ref())
                .map(|c| c.to_wire().map(Box::new))
                .transpose()?,
        })
    }

    /// This file over `current`: each section the file has replaces the
    /// current one; the others stay. The version is the file's.
    pub fn over(&self, current: &ConfigFile) -> ConfigFile {
        ConfigFile {
            version: self.version,
            policy: self.policy.clone().or_else(|| current.policy.clone()),
            dns: self.dns.clone().or_else(|| current.dns.clone()),
            seeds: self.seeds.clone().or_else(|| current.seeds.clone()),
            transport: self.transport.clone().or_else(|| current.transport.clone()),
            limits: self.limits.clone().or_else(|| current.limits.clone()),
            proxy: self.proxy.clone().or_else(|| current.proxy.clone()),
            controllers: self
                .controllers
                .clone()
                .or_else(|| current.controllers.clone()),
        }
    }

    /// The top-level sections the file has.
    pub fn sections(&self) -> Vec<&'static str> {
        [
            ("policy", self.policy.is_some()),
            ("dns", self.dns.is_some()),
            ("seeds", self.seeds.is_some()),
            ("transport", self.transport.is_some()),
            ("limits", self.limits.is_some()),
            ("proxy", self.proxy.is_some()),
            ("controllers", self.controllers.is_some()),
        ]
        .into_iter()
        .filter_map(|(k, set)| set.then_some(k))
        .collect()
    }

    /// Whether the file sets nothing (applying it clears a node's
    /// configuration).
    pub fn is_empty(&self) -> bool {
        ConfigFile {
            version: None,
            ..self.clone()
        } == ConfigFile::default()
    }
}

impl CamouflageFile {
    pub fn refuse(&self) -> bool {
        self.mode == "refuse"
    }

    /// Fields set in the file that refuse mode doesn't read.
    pub fn ignored(&self) -> Vec<&'static str> {
        if !self.refuse() {
            return Vec::new();
        }
        [
            ("domain", self.domain.is_some()),
            ("certificate", self.certificate.is_some()),
            ("next_certificate", self.next_certificate.is_some()),
            ("next_spki", self.next_spki.is_some()),
        ]
        .into_iter()
        .filter_map(|(k, set)| set.then_some(k))
        .collect()
    }

    fn to_wire(&self, base: &Path) -> Result<wp::Camouflage> {
        let mode = match self.mode.as_str() {
            "website" => wp::CamouflageMode::Website,
            "refuse" => wp::CamouflageMode::Refuse,
            m => bail!("transport.camouflage.mode must be website or refuse, got {m:?}"),
        };
        if self.refuse() {
            // Domain and certificate are filled in when applying
            // (fill_refuse_certificate), from the network or generated.
            return Ok(wp::Camouflage {
                mode,
                domain: None,
                certificate: None,
                next_spki: None,
            });
        }
        let domain = self
            .domain
            .clone()
            .ok_or_else(|| anyhow!("transport.camouflage.domain is required in website mode"))?;
        let cert = self.certificate.as_ref().ok_or_else(|| {
            anyhow!("transport.camouflage.certificate is required in website mode")
        })?;
        let chain = certificates(base, cert, "transport.camouflage.certificate")?;
        let next_spki = match (&self.next_certificate, &self.next_spki) {
            (Some(p), _) => {
                let next = certificates(base, p, "transport.camouflage.next_certificate")?;
                Some(crypto::k32(&spki_pin(&next[0])?))
            }
            (None, Some(h)) => Some(crypto::k32(&crypto::parse_hex32(h).ok_or_else(|| {
                anyhow!("transport.camouflage.next_spki must be 64 hex digits")
            })?)),
            (None, None) => None,
        };
        Ok(wp::Camouflage {
            mode,
            domain: Some(domain),
            certificate: Some(
                chain
                    .into_iter()
                    .map(|d| wp::Blob { data: Some(d) })
                    .collect(),
            ),
            next_spki,
        })
    }
}

#[cfg(feature = "anytls")]
fn spki_pin(der: &[u8]) -> Result<crypto::Bytes32> {
    webjet_net::anytls::spki_pin(der)
}

#[cfg(not(feature = "anytls"))]
fn spki_pin(_der: &[u8]) -> Result<crypto::Bytes32> {
    bail!("built without AnyTLS: can't read the next certificate")
}

/// PEM text, or a PEM file relative to `base`.
fn certificates(base: &Path, value: &str, field: &str) -> Result<Vec<Vec<u8>>> {
    if value.contains("-----BEGIN") {
        return pem_certs(value).with_context(|| field.to_string());
    }
    let path = base.join(value);
    let pem = std::fs::read_to_string(&path)
        .with_context(|| format!("{field}: read {}", path.display()))?;
    pem_certs(&pem).with_context(|| format!("{field}: {}", path.display()))
}

/// Refuse mode needs no public certificate, but AnyTLS clients still pin
/// one: keep the network's, or make one (its key must be submitted first).
/// Returns the new private key, if one was made.
pub fn fill_refuse_certificate(
    cfg: &mut wp::NetworkConfig,
    current: Option<&wp::Camouflage>,
) -> Result<Option<Vec<u8>>> {
    let Some(cam) = cfg
        .transport
        .as_mut()
        .and_then(|t| t.camouflage.as_mut())
        .filter(|c| c.mode == wp::CamouflageMode::Refuse)
    else {
        return Ok(None);
    };
    Ok(match refuse_certificate(cam, current)? {
        RefuseCertificate::Kept => None,
        RefuseCertificate::New { key_pem } => Some(key_pem),
    })
}

fn priorities(m: &BTreeMap<String, u8>) -> Result<Vec<wp::TransportPriority>> {
    m.iter()
        .map(|(k, v)| {
            Ok(wp::TransportPriority {
                transport: Transport::parse(k)
                    .ok_or_else(|| anyhow!("unknown transport {k:?} (use kcp, anytls or tls)"))?,
                priority: *v,
            })
        })
        .collect()
}

fn limit_values(m: &BTreeMap<String, u64>) -> Vec<wp::LimitValue> {
    m.iter()
        .map(|(k, v)| wp::LimitValue {
            name: Some(k.clone()),
            value: *v,
        })
        .collect()
}

fn records(v: &[DnsRecordFile]) -> Result<Vec<wp::DnsRecord>> {
    v.iter()
        .map(|r| {
            let rtype = match r.rtype.to_ascii_uppercase().as_str() {
                "A" => wp::DnsType::A,
                "AAAA" => wp::DnsType::Aaaa,
                "CNAME" => wp::DnsType::Cname,
                "TXT" => wp::DnsType::Txt,
                "SRV" => wp::DnsType::Srv,
                t => bail!("dns.record {}: unsupported type {t}", r.name),
            };
            Ok(wp::DnsRecord {
                name: Some(r.name.clone()),
                rtype,
                value: Some(r.value.clone()),
                ttl: r.ttl,
            })
        })
        .collect()
}

fn forwards(v: &[ForwardFile]) -> Result<Vec<wp::ForwardZone>> {
    v.iter()
        .map(|f| {
            Ok(wp::ForwardZone {
                zone: Some(f.zone.clone()),
                servers: Some(
                    f.servers
                        .iter()
                        .map(|s| {
                            Ok(wp::IpAddress::from_ip(s.parse().with_context(|| {
                                format!("dns.forward {}: server {s:?}", f.zone)
                            })?))
                        })
                        .collect::<Result<Vec<_>>>()?,
                ),
                rewrite: Some(
                    f.rewrite
                        .iter()
                        .map(|g| Ok(Grant::parse(g)?.to_wire()))
                        .collect::<Result<Vec<_>>>()?,
                ),
            })
        })
        .collect()
}

fn seeds(v: &[SeedSection]) -> Result<Vec<wp::SeedEntry>> {
    v.iter()
        .map(|e| {
            Ok(wp::SeedEntry {
                node: Some(e.node.clone()),
                addrs: Some(
                    e.addrs
                        .iter()
                        .map(|a| parse_seed_addr(a).with_context(|| format!("seed {}", e.node)))
                        .collect::<Result<Vec<_>>>()?,
                ),
            })
        })
        .collect()
}

// ---------------------------------------------------------------- show

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

fn prio_map(v: &[wp::TransportPriority]) -> BTreeMap<String, u8> {
    v.iter()
        .map(|p| (p.transport.name().to_string(), p.priority))
        .collect()
}

fn limit_map(v: &[wp::LimitValue]) -> BTreeMap<String, u64> {
    v.iter()
        .map(|x| (x.name.clone().unwrap_or_default(), x.value))
        .collect()
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

fn records_out(v: &[wp::DnsRecord]) -> Vec<DnsRecordFile> {
    v.iter()
        .map(|r| DnsRecordFile {
            name: r.name.clone().unwrap_or_default(),
            rtype: match r.rtype {
                wp::DnsType::A => "A",
                wp::DnsType::Aaaa => "AAAA",
                wp::DnsType::Cname => "CNAME",
                wp::DnsType::Txt => "TXT",
                wp::DnsType::Srv => "SRV",
            }
            .into(),
            value: r.value.clone().unwrap_or_default(),
            ttl: r.ttl,
        })
        .collect()
}

fn forwards_out(v: &[wp::ForwardZone]) -> Vec<ForwardFile> {
    v.iter()
        .map(|f| ForwardFile {
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
        .collect()
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

fn seeds_out(v: &[wp::SeedEntry]) -> Vec<SeedSection> {
    v.iter()
        .map(|e| SeedSection {
            node: e.node.clone().unwrap_or_default(),
            addrs: e
                .addrs
                .clone()
                .unwrap_or_default()
                .iter()
                .map(seed_addr)
                .collect(),
        })
        .collect()
}

/// A config leaf from the `tree` control call; `None` when nothing was applied.
fn leaf<T: serde::de::DeserializeOwned>(tree: &Value, key: &str) -> Result<Option<T>> {
    match &tree[key] {
        Value::Null => Ok(None),
        v => Ok(Some(serde_json::from_value(v.clone())?)),
    }
}

fn action(a: wp::Action) -> &'static str {
    match a {
        wp::Action::Allow => "allow",
        _ => "deny",
    }
}

/// The network configuration in force, from the `tree` control call, as a
/// document `apply` accepts. With `fill`, built-in defaults are spelled out
/// where nothing is set (for people); without, only what was applied is
/// (the base `apply` merges a partial file into).
pub fn network_from_tree(tree: &Value, fill: bool) -> Result<ConfigFile> {
    let version = tree["network_version"].as_u64().unwrap_or(0);
    let pol: Option<wp::Policy> = leaf(tree, "policy")?;
    let dns: Option<wp::DnsConfig> = leaf(tree, "dns")?;
    let sd: Option<wp::Seeds> = leaf(tree, "seeds")?;
    let lim: Option<wp::Limits> = leaf(tree, "limits")?;
    let tr: Option<wp::TransportConfig> = leaf(tree, "transport")?;
    let ctl: Option<wp::ControllerSettings> = leaf(tree, "controllers")?;
    let policy = pol
        .map(|p| PolicyFile {
            default: action(p.default_action).into(),
            rules: p
                .rules
                .unwrap_or_default()
                .into_iter()
                .map(|r| RuleFile {
                    id: r.id.unwrap_or_default(),
                    action: action(r.action).into(),
                    src: r.src.unwrap_or_default(),
                    dst: r.dst.unwrap_or_default(),
                    ports: r.ports.unwrap_or_default(),
                })
                .collect(),
            tests: p
                .tests
                .unwrap_or_default()
                .into_iter()
                .map(|t| TestFile {
                    src: t.src.unwrap_or_default(),
                    dst: t.dst.unwrap_or_default(),
                    port: t.port.unwrap_or_default(),
                    expect: action(t.expect).into(),
                })
                .collect(),
        })
        .unwrap_or_default();
    let dns = dns.unwrap_or_default();
    let set_resolver: Vec<String> = dns
        .resolver_ip
        .clone()
        .unwrap_or_default()
        .iter()
        .map(ip_str)
        .collect();
    let suffix = dns.suffix.clone().filter(|s| !s.is_empty());
    let dns = DnsSection {
        suffix: if fill {
            Some(suffix.unwrap_or_else(|| tree["suffix"].as_str().unwrap_or("internal").into()))
        } else {
            suffix
        },
        resolver_ip: set_resolver,
        records: records_out(&dns.records.clone().unwrap_or_default()),
        forward: forwards_out(&dns.forward.unwrap_or_default()),
    };
    let tr = tr.unwrap_or_default();
    let mut priority: BTreeMap<String, u8> = if fill {
        webjet_core::store::BUILTIN_PRIORITIES
            .iter()
            .map(|(t, p)| (t.name().to_string(), *p))
            .collect()
    } else {
        BTreeMap::new()
    };
    priority.extend(prio_map(&tr.defaults.clone().unwrap_or_default()));
    let camouflage = tr.camouflage.as_deref().map(|c| {
        let website = c.mode == wp::CamouflageMode::Website;
        let chain: String = c
            .certificate
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|b| b.data)
            .map(|d| pem(&d))
            .collect();
        CamouflageFile {
            mode: if website { "website" } else { "refuse" }.into(),
            domain: website.then(|| c.domain.clone().unwrap_or_default()),
            certificate: (website && !chain.is_empty()).then_some(chain),
            next_certificate: None,
            next_spki: c
                .next_spki
                .filter(|_| website)
                .map(|k| hex::encode(k.to_bytes())),
        }
    });
    let padding = match &tr.padding {
        Some(p) => Some(PaddingFile {
            stop: p.stop,
            lines: p.lines.clone().unwrap_or_default(),
        }),
        None if fill => Some(PaddingFile {
            stop: webjet_core::padding::DEFAULT_STOP,
            lines: webjet_core::padding::DEFAULT_LINES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }),
        None => None,
    };
    let compression = match CompressionFile::from_wire(tr.compression.as_deref()) {
        Some(c) if fill => {
            // Spell out the built-in value of a plane left unset.
            let d = webjet_core::compress::Settings::default();
            let name = |v: u8| webjet_core::compress::algo::name(v).to_string();
            Some(CompressionFile {
                control: c.control.or_else(|| Some(name(d.control))),
                data: c.data.or_else(|| Some(name(d.data))),
            })
        }
        None if fill => {
            let d = webjet_core::compress::Settings::default();
            let name = |v: u8| webjet_core::compress::algo::name(v).to_string();
            Some(CompressionFile {
                control: Some(name(d.control)),
                data: Some(name(d.data)),
            })
        }
        c => c,
    };
    let transport = TransportSection {
        priority,
        compression,
        overrides: tr
            .overrides
            .unwrap_or_default()
            .iter()
            .map(|o| PriorityOverrideFile {
                select: o.select.clone().unwrap_or_default(),
                priority: prio_map(&o.values.clone().unwrap_or_default()),
            })
            .collect(),
        camouflage,
        padding,
    };
    let lim = lim.unwrap_or_default();
    let set = limit_map(&lim.defaults.clone().unwrap_or_default());
    let mut value = BTreeMap::new();
    for l in webjet_core::validate::LIMITS {
        let builtin = if fill { l.default } else { None };
        if let Some(v) = set.get(l.name).copied().or(builtin) {
            value.insert(l.name.to_string(), v);
        }
    }
    let limits = LimitsSection {
        value,
        overrides: lim
            .overrides
            .unwrap_or_default()
            .iter()
            .map(|o| LimitOverrideFile {
                select: o.select.clone().unwrap_or_default(),
                value: limit_map(&o.values.clone().unwrap_or_default()),
            })
            .collect(),
    };
    Ok(ConfigFile {
        version: Some(version),
        policy: Some(policy),
        dns: Some(dns),
        seeds: Some(seeds_out(&sd.and_then(|s| s.entries).unwrap_or_default())),
        transport: Some(transport),
        limits: Some(limits),
        proxy: None,
        // Not spelled out with `fill` (render_network explains the built-in
        // values in a comment): a file with `[controllers]` writes a leaf
        // controllers before 0.7.0 don't know.
        controllers: ctl.as_ref().map(ControllersSection::from_wire),
    })
}

/// `[[proxy]]` entries on the wire, checked like the controllers check them.
pub fn proxy_rules(v: &[ProxyFile]) -> Result<Vec<wp::ProxyRule>> {
    let out = v
        .iter()
        .map(|p| {
            Ok(wp::ProxyRule {
                name: Some(p.name.clone()),
                protocol: webjet_core::proxy::parse_proto(&p.protocol)
                    .with_context(|| format!("proxy {}", p.name))?,
                listen_port: p.listen_port,
                target: Some(p.target.clone()),
                target_port: p.target_port,
                real_ip: p.real_ip,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    webjet_core::proxy::rules(&out)?;
    Ok(out)
}

fn proxy_out(v: &[wp::ProxyRule]) -> Vec<ProxyFile> {
    v.iter()
        .map(|p| ProxyFile {
            name: p.name.clone().unwrap_or_default(),
            protocol: webjet_core::proxy::proto_name(p.protocol).into(),
            listen_port: p.listen_port,
            target: p.target.clone().unwrap_or_default(),
            target_port: p.target_port,
            real_ip: p.real_ip,
        })
        .collect()
}

/// A node's own configuration (only what it sets).
pub fn node_from_wire(c: Option<&wp::NodeConfig>) -> ConfigFile {
    let Some(c) = c else {
        return ConfigFile {
            version: Some(0),
            ..Default::default()
        };
    };
    let priority = prio_map(&c.priorities.clone().unwrap_or_default());
    let value = limit_map(&c.limits.clone().unwrap_or_default());
    let records = records_out(&c.dns_records.clone().unwrap_or_default());
    let forward = forwards_out(&c.dns_forward.clone().unwrap_or_default());
    let proxy = proxy_out(&c.proxy.clone().unwrap_or_default());
    let compression = CompressionFile::from_wire(c.compression.as_deref());
    ConfigFile {
        proxy: (!proxy.is_empty()).then_some(proxy),
        version: Some(c.version),
        policy: None,
        dns: (!records.is_empty() || !forward.is_empty()).then(|| DnsSection {
            records,
            forward,
            ..Default::default()
        }),
        seeds: Some(seeds_out(&c.seeds.clone().unwrap_or_default())).filter(|v| !v.is_empty()),
        transport: (!priority.is_empty() || compression.is_some()).then(|| TransportSection {
            priority,
            compression,
            ..Default::default()
        }),
        limits: (!value.is_empty()).then(|| LimitsSection {
            value,
            ..Default::default()
        }),
        controllers: None,
    }
}

/// `network config show`: the document plus comments that explain what
/// isn't spelled out.
pub fn render_network(tree: &Value) -> Result<String> {
    let f = network_from_tree(tree, true)?;
    let mut s = String::new();
    s.push_str("# Webjet network configuration (webjetctl network config).\n");
    s.push_str("# Edit and apply with `webjetctl network config apply <file>`; keep `version`:\n");
    s.push_str("# apply refuses the file if someone applied a newer one meanwhile. Sections\n");
    s.push_str("# left out of a file stay as they are.\n");
    if f.version == Some(0) {
        s.push_str("# Nothing applied yet: these are the built-in defaults. Without a policy\n");
        s.push_str("# rule nothing may talk (default deny).\n");
    }
    let resolver_set = f.dns.as_ref().is_some_and(|d| !d.resolver_ip.is_empty());
    if !resolver_set {
        let r: Vec<&str> = tree["resolver"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let _ = writeln!(
            s,
            "# dns.resolver_ip not set: the resolver is {} (top of the overlay pool).",
            r.join(", ")
        );
    }
    if f.seeds.as_ref().is_none_or(|v| v.is_empty()) {
        s.push_str(
            "# No [[seeds]]: nodes find the network through the controllers in their enrollment.\n",
        );
    }
    match f.transport.as_ref().and_then(|t| t.camouflage.as_ref()) {
        None => s.push_str("# No [transport.camouflage]: relays don't offer AnyTLS.\n"),
        Some(c) if c.refuse() => {
            let tr: Option<wp::TransportConfig> = leaf(tree, "transport")?;
            if let Some(d) = tr
                .and_then(|t| t.camouflage)
                .and_then(|c| c.domain)
                .filter(|d| !d.is_empty())
            {
                let _ = writeln!(
                    s,
                    "# Camouflage refuse mode; the pinned certificate is for {d}."
                );
            }
        }
        Some(_) => {}
    }
    let unset: Vec<&str> = webjet_core::validate::LIMITS
        .iter()
        .filter(|l| {
            !f.limits
                .as_ref()
                .is_some_and(|x| x.value.contains_key(l.name))
        })
        .map(|l| l.name)
        .collect();
    if !unset.is_empty() {
        let _ = writeln!(
            s,
            "# Limits not set (no limit by default): {}.",
            unset.join(", ")
        );
    }
    let d = webjet_core::membership::Settings::of(None);
    let c = f.controllers.clone().unwrap_or_default();
    let mut builtin = Vec::new();
    if c.auto_membership.is_none() {
        builtin.push(format!("auto_membership = {}", d.auto_membership));
    }
    if c.voters.is_none() {
        builtin.push(format!("voters = {}", d.voters));
    }
    if c.dead_voter_after_s.is_none() {
        builtin.push(format!("dead_voter_after_s = {}", d.dead_voter_after_s));
    }
    if !builtin.is_empty() {
        let _ = writeln!(
            s,
            "# [controllers] built-in values in force: {} (the leader manages\n# the Raft membership; set auto_membership = false to do it by hand).",
            builtin.join(", ")
        );
    }
    s.push('\n');
    s.push_str(&f.to_toml()?);
    Ok(s)
}

/// `local config show`: the node's own settings.
pub fn render_node(name: &str, c: Option<&wp::NodeConfig>) -> Result<String> {
    let f = node_from_wire(c);
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# Configuration of node {name} (webjetctl local config)."
    );
    s.push_str("# Overrides the network configuration for this node: transport.priority,\n");
    s.push_str("# transport.compression, limits.value; adds seeds (tried first),\n");
    s.push_str("# dns.record and dns.forward;\n");
    s.push_str("# [[proxy]] makes the node a reverse proxy (Linux data nodes; see\n");
    s.push_str("# `webjetctl local proxy` for the rules' status).\n");
    s.push_str("# `webjetctl local config show --effective` shows what is in force.\n");
    if c.is_none() {
        s.push_str("# Nothing set: the node uses the network configuration.\n");
    }
    s.push('\n');
    s.push_str(&f.to_toml()?);
    Ok(s)
}

/// What is in force for a node (the `node_config` control call's
/// `effective`): network values with the node's overrides. Not a file to
/// apply.
pub fn effective_from_json(e: &Value) -> Result<ConfigFile> {
    let priority: BTreeMap<String, u8> = e["priorities"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.clone(), u8::try_from(v.as_u64()?).ok()?)))
                .collect()
        })
        .unwrap_or_default();
    let value: BTreeMap<String, u64> = e["limits"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_u64()?)))
                .collect()
        })
        .unwrap_or_default();
    let seeds: Vec<wp::SeedEntry> = serde_json::from_value(e["seeds"].clone())?;
    let recs: Vec<wp::DnsRecord> = serde_json::from_value(e["dns_records"].clone())?;
    let fwd: Vec<wp::ForwardZone> = serde_json::from_value(e["dns_forward"].clone())?;
    let resolver_ip: Vec<String> = e["resolver"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok(ConfigFile {
        version: None,
        policy: None,
        dns: Some(DnsSection {
            suffix: e["suffix"].as_str().map(String::from),
            resolver_ip,
            records: records_out(&recs),
            forward: forwards_out(&fwd),
        }),
        seeds: Some(seeds_out(&seeds)),
        transport: Some(TransportSection {
            priority,
            compression: serde_json::from_value(e["compression"].clone()).ok(),
            ..Default::default()
        }),
        limits: Some(LimitsSection {
            value,
            ..Default::default()
        }),
        controllers: None,
        proxy: None,
    })
}

/// `local config show --effective`.
pub fn render_effective(name: &str, e: &Value) -> Result<String> {
    let f = effective_from_json(e)?;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# In force for node {name}: the network configuration with the node's own"
    );
    s.push_str(
        "# overrides and additions (its seeds, records and zones come first). For
",
    );
    s.push_str(
        "# reading only; `webjetctl local config show` prints what the node sets.

",
    );
    s.push_str(&f.to_toml()?);
    Ok(s)
}

// ---------------------------------------------------------------- get / set / unset

fn segments(path: &str) -> Result<Vec<&str>> {
    let segs: Vec<&str> = path.split('.').collect();
    if segs.iter().any(|s| s.is_empty()) {
        bail!("bad key {path:?}: use dotted names like transport.priority.kcp");
    }
    Ok(segs)
}

/// The value at a dotted path (`transport.priority.kcp`, `seeds.0.node`).
pub fn get<'a>(doc: &'a toml::Value, path: &str) -> Result<&'a toml::Value> {
    let mut cur = doc;
    for seg in segments(path)? {
        cur = match cur {
            toml::Value::Table(t) => t.get(seg),
            toml::Value::Array(a) => seg.parse::<usize>().ok().and_then(|i| a.get(i)),
            _ => None,
        }
        .ok_or_else(|| anyhow!("{path} is not set"))?;
    }
    Ok(cur)
}

/// A value from the command line: TOML (`0`, `true`, `["a", "b"]`,
/// `"text"`), else the text itself as a string.
pub fn parse_value(text: &str) -> toml::Value {
    toml::from_str::<toml::Table>(&format!("v = {text}"))
        .ok()
        .and_then(|mut t| t.remove("v"))
        .unwrap_or_else(|| toml::Value::String(text.to_string()))
}

/// Set a dotted path, creating tables on the way.
pub fn set(doc: &mut toml::Value, path: &str, value: toml::Value) -> Result<()> {
    let segs = segments(path)?;
    let (last, parents) = segs.split_last().ok_or_else(|| anyhow!("empty key"))?;
    let mut cur = doc;
    for seg in parents {
        cur = match cur {
            toml::Value::Table(t) => t
                .entry(seg.to_string())
                .or_insert_with(|| toml::Value::Table(toml::Table::new())),
            toml::Value::Array(a) => {
                let i: usize = seg.parse().map_err(|_| anyhow!("{seg} is not an index"))?;
                a.get_mut(i)
                    .ok_or_else(|| anyhow!("{path}: no entry {i}"))?
            }
            _ => bail!("{path}: {seg} is inside a value, not a table"),
        };
    }
    match cur {
        toml::Value::Table(t) => {
            t.insert(last.to_string(), value);
        }
        toml::Value::Array(a) => {
            let i: usize = last
                .parse()
                .map_err(|_| anyhow!("{last} is not an index"))?;
            match i.cmp(&a.len()) {
                std::cmp::Ordering::Less => a[i] = value,
                std::cmp::Ordering::Equal => a.push(value),
                std::cmp::Ordering::Greater => bail!("{path}: no entry {i}"),
            }
        }
        _ => bail!("{path}: not inside a table"),
    }
    Ok(())
}

/// Remove a dotted path; empty tables left behind are removed too.
pub fn unset(doc: &mut toml::Value, path: &str) -> Result<()> {
    fn go(cur: &mut toml::Value, segs: &[&str], path: &str) -> Result<()> {
        let (seg, rest) = segs.split_first().ok_or_else(|| anyhow!("empty key"))?;
        match cur {
            toml::Value::Table(t) => {
                if rest.is_empty() {
                    t.remove(*seg).ok_or_else(|| anyhow!("{path} is not set"))?;
                } else {
                    let child = t
                        .get_mut(*seg)
                        .ok_or_else(|| anyhow!("{path} is not set"))?;
                    go(child, rest, path)?;
                    if child.as_table().is_some_and(|c| c.is_empty())
                        || child.as_array().is_some_and(|c| c.is_empty())
                    {
                        t.remove(*seg);
                    }
                }
            }
            toml::Value::Array(a) => {
                let i: usize = seg.parse().map_err(|_| anyhow!("{seg} is not an index"))?;
                if i >= a.len() {
                    bail!("{path} is not set");
                }
                if rest.is_empty() {
                    a.remove(i);
                } else {
                    go(&mut a[i], rest, path)?;
                }
            }
            _ => bail!("{path} is not set"),
        }
        Ok(())
    }
    go(doc, &segments(path)?, path)
}

/// Apply `f` to the document as a TOML value and parse the result back.
pub fn edit_doc(
    f: &ConfigFile,
    change: impl FnOnce(&mut toml::Value) -> Result<()>,
) -> Result<ConfigFile> {
    let mut v = toml::Value::try_from(f)?;
    change(&mut v)?;
    let text = toml::to_string(&v)?;
    ConfigFile::parse(&text).context("the result isn't a valid configuration")
}

// ---------------------------------------------------------------- applying

/// Check a network configuration file the way applying it does: the wire
/// form validates and the policy tests pass (with node names unresolved;
/// the controllers run them against the nodes).
pub fn network_wire(f: &ConfigFile, version: u64, base: &Path) -> Result<wp::NetworkConfig> {
    let w = f.to_network(version, base)?;
    if let Some(p) = &w.policy {
        webjet_core::policy::Policy::from_wire(p)?.run_tests(&|_| None)?;
    }
    Ok(w)
}

/// A note about settings the file sets but refuse mode ignores.
pub fn camouflage_note(f: &ConfigFile) -> Option<String> {
    let c = f.transport.as_ref()?.camouflage.as_ref()?;
    let ignored = c.ignored();
    (!ignored.is_empty())
        .then(|| format!("camouflage mode is refuse; ignoring {}", ignored.join(", ")))
}

/// What applying a network configuration file submits.
#[derive(Debug)]
pub struct NetworkApply {
    /// The version the file becomes.
    pub version: u64,
    /// The sections the file sets (the others stay as they are).
    pub sections: Vec<&'static str>,
    pub config: wp::NetworkConfig,
    /// Refuse mode without a camouflage certificate yet: the key of the
    /// self-signed one made for it, stored with the controllers first.
    pub camouflage_key: Option<Vec<u8>>,
    /// Something to tell the user ([`camouflage_note`]).
    pub note: Option<String>,
}

impl NetworkApply {
    /// The operations to sign and submit, in this order.
    pub fn ops(self) -> Vec<wp::AccountOp> {
        let mut ops = Vec::new();
        if let Some(key) = self.camouflage_key {
            ops.push(wp::AccountOp::SetCamouflageSecret(Box::new(
                wp::SetCamouflageSecret {
                    private_key: Some(key),
                    site: Some(Vec::new()),
                },
            )));
        }
        ops.push(wp::AccountOp::SetNetworkConfig(Box::new(
            wp::SetNetworkConfig {
                config: Some(Box::new(self.config)),
            },
        )));
        ops
    }

    /// The camouflage domain, when a certificate was made for it.
    pub fn new_certificate_domain(&self) -> Option<String> {
        self.camouflage_key.as_ref()?;
        self.config
            .transport
            .as_ref()
            .and_then(|t| t.camouflage.as_ref())
            .and_then(|c| c.domain.clone())
    }
}

/// Prepare applying a network configuration file over the configuration in
/// `tree` (the `tree` control call): the file must be made from the version
/// in force; its sections go over the current ones as the next version.
pub fn network_apply(f: &ConfigFile, tree: &Value, base: &Path) -> Result<NetworkApply> {
    let from = f.base_version()?;
    let sections = f.sections();
    if sections.is_empty() {
        bail!(
            "the file sets nothing: no [policy], [dns], seeds, [transport], [limits] or [controllers]"
        );
    }
    let now = tree["network_version"].as_u64().unwrap_or(0);
    if from != now {
        bail!(
            "the file was made from network configuration version {from}, but version {now} is in force: someone applied a change meanwhile. Start again from the configuration in force (or set `version = {now}` to overwrite their change)."
        );
    }
    let merged = f.over(&network_from_tree(tree, false)?);
    let mut config = network_wire(&merged, now + 1, base)?;
    let current: Option<wp::TransportConfig> = leaf(tree, "transport")?;
    let current_cam = current.as_ref().and_then(|c| c.camouflage.as_deref());
    let camouflage_key = fill_refuse_certificate(&mut config, current_cam)?;
    Ok(NetworkApply {
        version: now + 1,
        sections,
        config,
        camouflage_key,
        note: camouflage_note(&merged),
    })
}

/// Prepare applying a node configuration file: it is the node's whole
/// configuration (an empty one clears it), the next version after
/// `current`. `None` when there is nothing to apply (empty, and the node
/// has no configuration of its own).
pub fn node_apply(
    f: &ConfigFile,
    node_id: &crypto::Bytes32,
    name: &str,
    current: Option<&wp::NodeConfig>,
) -> Result<Option<wp::NodeConfig>> {
    let from = f.base_version()?;
    let now = current.map_or(0, |c| c.version);
    if from != now {
        bail!(
            "the file was made from version {from} of {name}'s configuration, but version {now} is in force: someone changed it meanwhile. Start again from the configuration in force."
        );
    }
    let w = f.to_node(node_id, now + 1)?;
    if f.is_empty() && current.is_none() {
        return Ok(None);
    }
    Ok(Some(w))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn empty_tree() -> Value {
        json!({
            "network_version": 0,
            "transport": null, "dns": null, "seeds": null, "limits": null, "policy": null,
            "resolver": ["10.7.255.254"], "suffix": "internal",
        })
    }

    #[test]
    fn defaults_show_and_apply_cleanly() {
        let text = render_network(&empty_tree()).unwrap();
        assert!(text.contains("Nothing applied yet"), "{text}");
        let f = ConfigFile::parse(&text).unwrap();
        assert_eq!(f.base_version().unwrap(), 0);
        let w = f.to_network(1, Path::new("/nonexistent")).unwrap();
        assert_eq!(w.version, 1);
        let t = w.transport.unwrap();
        assert_eq!(t.version, 1);
        assert_eq!(t.padding.unwrap().stop, webjet_core::padding::DEFAULT_STOP);
        assert_eq!(w.dns.unwrap().suffix.as_deref(), Some("internal"));
        assert_eq!(w.policy.unwrap().default_action, wp::Action::Deny);
        assert_eq!(
            w.limits.unwrap().defaults.unwrap().len(),
            webjet_core::validate::LIMITS.len() - 2
        );
        assert!(w.seeds.unwrap().entries.unwrap().is_empty());
    }

    const NETWORK: &str = r#"
version = 3

[policy]
default = "deny"

[[policy.rule]]
id = "web"
action = "allow"
src = ["tag:laptop"]
dst = ["tag:web"]
ports = ["tcp:443"]

[dns]
suffix = "corp"
resolver_ip = ["10.7.255.53"]

[[dns.record]]
name = "git.corp"
type = "A"
value = "10.7.0.9"

[[seeds]]
node = "ctl-01"
addrs = ["tls:203.0.113.10:443", "kcp:203.0.113.10:443"]

[transport.priority]
kcp = 0

[[transport.override]]
select = ["tag:relay"]
priority = { tls = 40 }

[transport.camouflage]
mode = "refuse"

[limits.value]
circuits_global = 1000

[[limits.override]]
select = ["tag:big"]
value = { circuits_global = 9000 }
"#;

    #[test]
    fn applied_configuration_round_trips() {
        let f = ConfigFile::parse(NETWORK).unwrap();
        let w = f.to_network(4, Path::new("/nonexistent")).unwrap();
        let tree = json!({
            "network_version": 4,
            "policy": w.policy, "dns": w.dns, "seeds": w.seeds,
            "limits": w.limits, "transport": w.transport,
            "resolver": ["10.7.255.53"], "suffix": "corp",
        });
        let text = render_network(&tree).unwrap();
        let back = ConfigFile::parse(&text).unwrap();
        assert_eq!(back.version, Some(4));
        assert_eq!(back.policy, f.policy);
        assert_eq!(back.seeds, f.seeds);
        let t = back.transport.clone().unwrap();
        // kcp set to 0, the others keep their built-ins.
        assert_eq!(t.priority["kcp"], 0);
        assert_eq!(t.priority["anytls"], 20);
        assert_eq!(t.overrides[0].priority["tls"], 40);
        let l = back.limits.clone().unwrap();
        assert_eq!(l.value["circuits_global"], 1000);
        assert_eq!(l.overrides[0].value["circuits_global"], 9000);
        assert_eq!(back.dns.as_ref().unwrap().records[0].rtype, "A");
        // And the shown document applies to the same wire form.
        let again = back.to_network(4, Path::new("/nonexistent")).unwrap();
        assert_eq!(again.policy, w.policy);
        assert_eq!(again.seeds, w.seeds);
    }

    #[test]
    fn node_scope_is_a_subset() {
        let node = ConfigFile::parse(
            "version = 0\n[transport.priority]\nkcp = 0\n[limits.value]\nrelay_capacity_mbps = 900\n[[seeds]]\nnode = \"relay-1\"\naddrs = [\"tls:198.51.100.7:443\"]\n[[dns.record]]\nname = \"db.internal\"\ntype = \"A\"\nvalue = \"10.7.0.5\"\n",
        )
        .unwrap();
        let c = node.to_node(&[7; 32], 1).unwrap();
        assert_eq!(c.priorities.as_ref().unwrap()[0].priority, 0);
        assert_eq!(c.limits.as_ref().unwrap()[0].value, 900);
        assert_eq!(c.seeds.as_ref().unwrap().len(), 1);
        let back = node_from_wire(Some(&c));
        assert_eq!(back.transport, node.transport);
        assert_eq!(back.limits, node.limits);
        assert_eq!(back.seeds, node.seeds);
        assert_eq!(back.dns, node.dns);
        let full = ConfigFile::parse(NETWORK).unwrap();
        let e = full.to_node(&[7; 32], 1).unwrap_err().to_string();
        for k in [
            "policy",
            "dns.suffix",
            "dns.resolver_ip",
            "transport.override",
            "transport.camouflage",
            "limits.override",
        ] {
            assert!(e.contains(k), "{k}: {e}");
        }
        assert!(node_from_wire(None).is_empty());
    }

    #[test]
    fn controller_settings() {
        // Not spelled out (an older controller would diverge on the leaf),
        // but `show` names the built-in values.
        let text = render_network(&empty_tree()).unwrap();
        assert!(
            text.contains("auto_membership = true, voters = 5, dead_voter_after_s = 3600"),
            "{text}"
        );
        let f = ConfigFile::parse(&text).unwrap();
        assert!(f.controllers.is_none());
        assert!(
            f.to_network(1, Path::new("/x"))
                .unwrap()
                .controllers
                .is_none()
        );
        // Set: written with the document's version, and read back.
        let f = ConfigFile::parse("version = 0\n[controllers]\nvoters = 3\n").unwrap();
        let w = f.to_network(4, Path::new("/x")).unwrap();
        let c = w.controllers.clone().unwrap();
        assert_eq!((c.version, c.voters, c.auto_membership), (4, Some(3), None));
        let mut t = empty_tree();
        t["controllers"] = serde_json::to_value(&*c).unwrap();
        let back = network_from_tree(&t, false).unwrap();
        assert_eq!(back.controllers, f.controllers);
        assert!(
            render_network(&t)
                .unwrap()
                .contains("[controllers]\nvoters = 3")
        );
        // A file without the section keeps it.
        let other = ConfigFile::parse("version = 0\n[limits]\n").unwrap();
        assert_eq!(other.over(&back).controllers, f.controllers);
        // Bad values; node scope doesn't take it.
        for bad in [
            "voters = 4",
            "voters = 9",
            "voters = 0",
            "dead_voter_after_s = 10",
        ] {
            let f = ConfigFile::parse(&format!("version = 0\n[controllers]\n{bad}\n")).unwrap();
            assert!(f.to_network(1, Path::new("/x")).is_err(), "{bad}");
        }
        let f = ConfigFile::parse("version = 0\n[controllers]\nauto_membership = false\n").unwrap();
        assert!(f.check_scope(Scope::Node).is_err());
        assert!(ConfigFile::parse("[controllers]\nmax = 3\n").is_err());
    }

    #[test]
    fn compression_settings() {
        use webjet_core::compress::algo;
        // Built-in values are spelled out by show and apply as set.
        let f = ConfigFile::parse(&render_network(&empty_tree()).unwrap()).unwrap();
        let c = f.transport.as_ref().unwrap().compression.clone().unwrap();
        assert_eq!(
            (c.control.as_deref(), c.data.as_deref()),
            (Some("zstd"), Some("off"))
        );
        let w = f.to_network(1, Path::new("/nonexistent")).unwrap();
        let wc = w.transport.unwrap().compression.unwrap();
        assert_eq!((wc.control, wc.data), (algo::ZSTD, algo::OFF));
        // Network: data on.
        let f =
            ConfigFile::parse("version = 0\n[transport.compression]\ndata = \"lz4\"\n").unwrap();
        let w = f.to_network(1, Path::new("/nonexistent")).unwrap();
        let wc = w.transport.unwrap().compression.unwrap();
        assert_eq!((wc.control, wc.data), (algo::UNSET, algo::LZ4));
        // Wrong algorithm for a plane, unknown values and keys.
        for bad in [
            "[transport.compression]\ncontrol = \"lz4\"\n",
            "[transport.compression]\ndata = \"zstd\"\n",
            "[transport.compression]\ndata = \"gzip\"\n",
        ] {
            let f = ConfigFile::parse(&format!("version = 0\n{bad}")).unwrap();
            assert!(f.to_network(1, Path::new("/x")).is_err(), "{bad}");
            assert!(f.to_node(&[7; 32], 1).is_err(), "{bad}");
        }
        assert!(ConfigFile::parse("[transport.compression]\nlevel = 3\n").is_err());
        // Node scope: an override that round-trips; a node config with only
        // compression is not empty.
        let node =
            ConfigFile::parse("version = 0\n[transport.compression]\ncontrol = \"off\"\n").unwrap();
        let c = node.to_node(&[7; 32], 1).unwrap();
        let cc = c.compression.as_deref().unwrap();
        assert_eq!((cc.control, cc.data), (algo::OFF, algo::UNSET));
        assert_eq!(node_from_wire(Some(&c)).transport, node.transport);
        assert!(!node_from_wire(Some(&c)).is_empty());
    }

    #[test]
    fn left_out_sections_stay() {
        let current = ConfigFile::parse(NETWORK).unwrap();
        let file = ConfigFile::parse("version = 3\n[limits]\n").unwrap();
        assert_eq!(file.sections(), ["limits"]);
        let merged = file.over(&current);
        assert_eq!(merged.policy, current.policy);
        assert_eq!(merged.seeds, current.seeds);
        assert_eq!(merged.limits, Some(LimitsSection::default()));
        let none = ConfigFile::parse("version = 3\nseeds = []\n").unwrap();
        assert_eq!(none.over(&current).seeds, Some(vec![]));
        // Without defaults filled in, an empty network is an empty document.
        let bare = network_from_tree(&empty_tree(), false).unwrap();
        assert!(bare.transport.as_ref().unwrap().priority.is_empty());
        assert!(bare.limits.as_ref().unwrap().value.is_empty());
        assert!(bare.dns.as_ref().unwrap().suffix.is_none());
    }

    #[test]
    fn effective_view_parses() {
        let e = json!({
            "priorities": {"kcp": 0, "anytls": 20, "tls": 10},
            "limits": {"circuits_global": 50000, "rate_ceiling_mbps": null},
            "seeds": [{"node": "relay-1", "addrs": [{"host": "198.51.100.7", "port": 443, "transport": "TcpTls"}]}],
            "dns_records": [], "dns_forward": [],
            "suffix": "internal", "resolver": ["10.7.255.254"],
        });
        let f = effective_from_json(&e).unwrap();
        assert_eq!(f.transport.as_ref().unwrap().priority["kcp"], 0);
        assert_eq!(f.limits.as_ref().unwrap().value.len(), 1);
        assert_eq!(f.seeds.as_ref().unwrap()[0].addrs, ["tls:198.51.100.7:443"]);
        assert!(
            render_effective("n", &e)
                .unwrap()
                .contains("[transport.priority]")
        );
    }

    #[test]
    fn unknown_keys_are_errors() {
        assert!(ConfigFile::parse("version = 1\n[transport]\nkcp = 0\n").is_err());
        assert!(ConfigFile::parse("version = 1\n[policy]\nrules = []\n").is_err());
        let e = ConfigFile::parse("version = 1\n[transport.priority]\nquic = 1\n")
            .unwrap()
            .to_network(2, Path::new("/"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("unknown transport"), "{e}");
    }

    #[test]
    fn get_set_unset() {
        let f = ConfigFile::parse("version = 2\n").unwrap();
        let f = edit_doc(&f, |d| set(d, "transport.priority.kcp", parse_value("0"))).unwrap();
        assert_eq!(f.transport.as_ref().unwrap().priority["kcp"], 0);
        let f = edit_doc(&f, |d| {
            set(
                d,
                "seeds",
                parse_value(r#"[{node = "r1", addrs = ["tls:198.51.100.7:443"]}]"#),
            )
        })
        .unwrap();
        assert_eq!(f.seeds.as_ref().unwrap()[0].node, "r1");
        let f = edit_doc(&f, |d| set(d, "seeds.0.node", parse_value("r2"))).unwrap();
        assert_eq!(f.seeds.as_ref().unwrap()[0].node, "r2");
        let v = toml::Value::try_from(&f).unwrap();
        assert_eq!(get(&v, "seeds.0.node").unwrap().as_str(), Some("r2"));
        assert!(get(&v, "limits.value.x").is_err());
        let f = edit_doc(&f, |d| unset(d, "transport.priority.kcp")).unwrap();
        assert!(f.transport.is_none(), "empty tables are dropped");
        let f = edit_doc(&f, |d| unset(d, "seeds.0")).unwrap();
        assert!(f.is_empty(), "{f:?}");
        assert!(edit_doc(&f, |d| set(d, "transport.kcp", parse_value("1"))).is_err());
        assert_eq!(parse_value("hello world").as_str(), Some("hello world"));
    }

    #[test]
    fn website_mode_reads_the_certificate_and_names_it_in_errors() {
        let dir = std::env::temp_dir().join(format!("webjet-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cam = |extra: &str| {
            ConfigFile::parse(&format!(
                "version = 1\n[transport.camouflage]\nmode = \"website\"\n{extra}"
            ))
            .unwrap()
        };
        let e = format!(
            "{:#}",
            cam("domain = \"cdn.example.com\"\ncertificate = \"missing.crt\"\n")
                .to_network(2, &dir)
                .unwrap_err()
        );
        assert!(
            e.contains("camouflage.certificate") && e.contains("missing.crt"),
            "{e}"
        );
        std::fs::write(dir.join("junk.crt"), "not a certificate").unwrap();
        let e = format!(
            "{:#}",
            cam("domain = \"cdn.example.com\"\ncertificate = \"junk.crt\"\n")
                .to_network(2, &dir)
                .unwrap_err()
        );
        assert!(
            e.contains("junk.crt") && e.contains("no certificate"),
            "{e}"
        );
        let e = format!(
            "{:#}",
            cam("certificate = \"junk.crt\"\n")
                .to_network(2, &dir)
                .unwrap_err()
        );
        assert!(e.contains("camouflage.domain is required"), "{e}");
        let e = format!(
            "{:#}",
            cam("domain = \"cdn.example.com\"\n")
                .to_network(2, &dir)
                .unwrap_err()
        );
        assert!(e.contains("camouflage.certificate is required"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuse_mode_ignores_domain_and_certificate() {
        let f = ConfigFile::parse(
            "version = 1\n[transport.camouflage]\nmode = \"refuse\"\ndomain = \"cdn.example.com\"\ncertificate = \"missing.crt\"\nnext_certificate = \"gone.crt\"\n",
        )
        .unwrap();
        let cam = f.transport.as_ref().unwrap().camouflage.as_ref().unwrap();
        assert_eq!(cam.ignored(), ["domain", "certificate", "next_certificate"]);
        let w = f.to_network(2, Path::new("/nonexistent")).unwrap();
        let cam = w.transport.unwrap().camouflage.unwrap();
        assert_eq!(cam.mode, wp::CamouflageMode::Refuse);
        assert!(cam.domain.is_none() && cam.certificate.is_none() && cam.next_spki.is_none());
    }

    #[cfg(feature = "anytls")]
    #[test]
    fn website_certificate_shows_inline_and_applies_again() {
        let (der, _key) = webjet_net::anytls::self_signed("cdn.example.com").unwrap();
        let tr = wp::TransportConfig {
            version: 5,
            defaults: None,
            overrides: None,
            camouflage: Some(Box::new(wp::Camouflage {
                mode: wp::CamouflageMode::Website,
                domain: Some("cdn.example.com".into()),
                certificate: Some(vec![wp::Blob {
                    data: Some(der.clone()),
                }]),
                next_spki: Some(crypto::k32(&[9; 32])),
            })),
            padding: None,
            compression: None,
        };
        let mut tree = empty_tree();
        tree["network_version"] = json!(5);
        tree["transport"] = serde_json::to_value(&tr).unwrap();
        let f = ConfigFile::parse(&render_network(&tree).unwrap()).unwrap();
        let w = f.to_network(6, Path::new("/nonexistent")).unwrap();
        let cam = w.transport.unwrap().camouflage.unwrap();
        assert_eq!(cam.certificate.unwrap()[0].data.as_ref(), Some(&der));
        assert_eq!(cam.next_spki, Some(crypto::k32(&[9; 32])));
    }
}
