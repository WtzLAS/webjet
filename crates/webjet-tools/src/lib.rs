//! Shared code for the command-line tools: key files, signed files, and the
//! YAML forms of the network settings (operations guide).

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use webjet_core::crypto::{self, Bytes32, KeyPair};
use webjet_core::types::{Grant, net_to_cidr, now_ms, parse_net};
use webjet_proto::{self as wp, Transport};
use zeroize::Zeroizing;

pub mod prompt;
pub mod root;
pub mod show;

pub use prompt::{new_passphrase, passphrase};
pub use webjetd::state::write_private;

pub fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

pub fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("read {}", path.display()))
}

pub fn write_public(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(d) = path.parent()
        && !d.as_os_str().is_empty()
    {
        std::fs::create_dir_all(d).with_context(|| format!("create {}", d.display()))?;
    }
    std::fs::write(path, data).with_context(|| format!("write {}", path.display()))
}

// ---------------------------------------------------------------- passphrase-encrypted key files

const MAGIC: &[u8; 4] = b"WJE1";

/// Encrypt secret bytes with a passphrase (Argon2id + ChaCha20-Poly1305).
pub fn seal(pass: &str, plain: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    let salt: [u8; 16] = rand::random();
    let nonce: [u8; 12] = rand::random();
    let mut key = Zeroizing::new([0u8; 32]);
    argon2::Argon2::default()
        .hash_password_into(pass.as_bytes(), &salt, &mut key[..])
        .map_err(|e| anyhow!("argon2: {e}"))?;
    let c = chacha20poly1305::ChaCha20Poly1305::new((&*key).into());
    let ct = c
        .encrypt((&nonce).into(), plain)
        .map_err(|_| anyhow!("encrypt"))?;
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn unseal(pass: &str, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    if data.len() < 32 + 16 || &data[..4] != MAGIC {
        bail!("not an encrypted webjet key file");
    }
    let (salt, nonce, ct) = (&data[4..20], &data[20..32], &data[32..]);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2::Argon2::default()
        .hash_password_into(pass.as_bytes(), salt, &mut key[..])
        .map_err(|e| anyhow!("argon2: {e}"))?;
    let c = chacha20poly1305::ChaCha20Poly1305::new((&*key).into());
    let pt = c
        .decrypt(nonce.into(), ct)
        .map_err(|_| anyhow!("wrong passphrase or damaged file"))?;
    Ok(Zeroizing::new(pt))
}

pub fn keypair_from(bytes: &[u8]) -> Result<KeyPair> {
    let seed: Bytes32 = bytes.try_into().map_err(|_| anyhow!("bad key length"))?;
    Ok(KeyPair::from_seed(&seed))
}

// ---------------------------------------------------------------- account keys

/// The default directory for account keys (`~/.config/webjet/accounts` and
/// the platform equivalents).
pub fn default_key_dir() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("webjet")
        .join("accounts")
}

/// Account names with a key in `dir` (from `<name>.key` files), sorted.
pub fn account_names(dir: &Path) -> Result<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .with_context(|| {
            format!(
                "no account keys in {} (webjetctl account keygen)",
                dir.display()
            )
        })?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|s| s.strip_suffix(".key"))
                .map(String::from)
        })
        .collect();
    names.sort();
    Ok(names)
}

/// An unlocked account key, ready to sign operations.
pub struct Account {
    pub name: String,
    pub id: Bytes32,
    pub kp: KeyPair,
    pub dir: std::path::PathBuf,
}

impl Account {
    /// Unlock `<dir>/<name>.key` with `pass` and check it against `<name>.pub`.
    pub fn unlock(dir: &Path, name: &str, pass: &str) -> Result<Account> {
        let p = AccountPub::load(&dir.join(format!("{name}.pub")))?;
        let kp = keypair_from(&unseal(pass, &read(&dir.join(format!("{name}.key")))?)?)?;
        if crypto::key_b64(&kp.public()) != p.key {
            bail!("account key file doesn't match {name}.pub");
        }
        Ok(Account {
            name: name.to_string(),
            id: p.id()?,
            kp,
            dir: dir.to_path_buf(),
        })
    }

    /// Monotonic op_seq (§13.3): milliseconds, never repeating, persisted
    /// next to the key so restarts and other tools don't reuse a value.
    pub fn next_seq(&self) -> Result<u64> {
        let path = self.dir.join(format!("{}.seq", self.name));
        let last: u64 = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let seq = now_ms().max(last + 1);
        std::fs::write(&path, seq.to_string())
            .with_context(|| format!("write {}", path.display()))?;
        Ok(seq)
    }

    /// Sign an operation as this account.
    pub fn sign(&self, op: wp::AccountOp) -> Result<Vec<u8>> {
        Ok(webjet_core::statemachine::ops::sign_op(
            &self.kp,
            &self.id,
            self.next_seq()?,
            now_ms(),
            op,
        ))
    }
}

// ---------------------------------------------------------------- account public files

/// `alice.pub`: what an admin hands to the root key holder or another admin.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountPub {
    pub name: String,
    pub account_id: String,
    pub key: String,
}

impl AccountPub {
    pub fn load(path: &Path) -> Result<AccountPub> {
        serde_json::from_slice(&read(path)?).with_context(|| format!("parse {}", path.display()))
    }
    pub fn id(&self) -> Result<Bytes32> {
        crypto::parse_hex32(&self.account_id).ok_or_else(|| anyhow!("bad account id"))
    }
    pub fn key(&self) -> Result<Bytes32> {
        crypto::parse_key_b64(&self.key).ok_or_else(|| anyhow!("bad account key"))
    }
}

pub fn account_record(
    p: &AccountPub,
    admin: bool,
    issuer: Option<Bytes32>,
) -> Result<wp::AccountRecord> {
    if !webjet_core::types::valid_name(&p.name) {
        bail!("invalid account name {:?}", p.name);
    }
    Ok(wp::AccountRecord {
        account_id: Some(crypto::k32(&p.id()?)),
        account_key: Some(crypto::k32(&p.key()?)),
        name: Some(p.name.clone()),
        admin,
        issuer_root: issuer.is_none(),
        issuer: issuer.map(|i| crypto::k32(&i)),
        // Versions are timestamps so offline and online signers never collide.
        version: now_ms(),
    })
}

/// Describe a signed file for the user.
/// Turn a controller's certificate request into a SigningKeyCert signed by
/// `signer` (§6.5): the root key (`issuer: None`), or an admin key with its
/// root-signed AccountRecord. Checks that the request is signed by the key it
/// certifies and, when `expect` is given, names that node. Returns the signed
/// cert and the signing key id.
pub fn certify(
    request: &[u8],
    expect: Option<Bytes32>,
    signer: &KeyPair,
    issuer: Option<Vec<u8>>,
) -> Result<(Vec<u8>, Bytes32)> {
    use webjet_proto::msg_type as mt;
    let v = crypto::open_envelope(request)?;
    if v.ty != mt::CERT_REQUEST {
        bail!("not a certificate request");
    }
    let mut c: wp::SigningKeyCert = v.decode()?;
    let key = crypto::opt_k32(&c.signing_key);
    let kid = crypto::opt_k32(&c.signing_key_id);
    if key != v.signer || crypto::signing_key_id(&key) != kid {
        bail!("the request isn't signed by the key it certifies");
    }
    if let Some(id) = expect
        && crypto::opt_k32(&c.controller) != id
    {
        bail!("the request names a different node");
    }
    c.issuer = issuer;
    Ok((signer.sign_obj(mt::SIGNING_KEY_CERT, &c), kid))
}

pub fn describe(raw: &[u8]) -> String {
    match crypto::open_envelope(raw) {
        Ok(v) => format!(
            "{} signed by {}",
            wp::msg_type::name(v.ty),
            crypto::key_b64(&v.signer)
        ),
        Err(e) => format!("invalid: {e}"),
    }
}

// ---------------------------------------------------------------- YAML forms

#[derive(Deserialize, Serialize, Debug)]
pub struct DnsFile {
    pub version: u64,
    #[serde(default)]
    pub suffix: Option<String>,
    #[serde(default)]
    pub resolver_ip: Vec<String>,
    #[serde(default)]
    pub records: Vec<DnsRecordFile>,
    #[serde(default)]
    pub forward: Vec<ForwardFile>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct DnsRecordFile {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub value: String,
    #[serde(default)]
    pub ttl: u32,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ForwardFile {
    pub zone: String,
    pub servers: Vec<String>,
    #[serde(default)]
    pub rewrite: Vec<String>,
}

impl DnsFile {
    pub fn to_wire(&self) -> Result<wp::DnsConfig> {
        Ok(wp::DnsConfig {
            version: self.version,
            suffix: self.suffix.clone(),
            resolver_ip: Some(
                self.resolver_ip
                    .iter()
                    .map(|s| Ok(wp::IpAddress::from_ip(s.parse()?)))
                    .collect::<Result<Vec<_>>>()?,
            ),
            records: Some(
                self.records
                    .iter()
                    .map(|r| {
                        let rtype = match r.rtype.to_ascii_uppercase().as_str() {
                            "A" => wp::DnsType::A,
                            "AAAA" => wp::DnsType::Aaaa,
                            "CNAME" => wp::DnsType::Cname,
                            "TXT" => wp::DnsType::Txt,
                            "SRV" => wp::DnsType::Srv,
                            t => bail!("unsupported record type {t}"),
                        };
                        Ok(wp::DnsRecord {
                            name: Some(r.name.clone()),
                            rtype,
                            value: Some(r.value.clone()),
                            ttl: r.ttl,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
            forward: Some(
                self.forward
                    .iter()
                    .map(|f| {
                        Ok(wp::ForwardZone {
                            zone: Some(f.zone.clone()),
                            servers: Some(
                                f.servers
                                    .iter()
                                    .map(|s| Ok(wp::IpAddress::from_ip(s.parse()?)))
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
                    .collect::<Result<Vec<_>>>()?,
            ),
        })
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SeedsFile {
    pub version: u64,
    pub seeds: Vec<SeedFile>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SeedFile {
    pub node: String,
    pub addrs: Vec<String>,
}

/// `transport:host:port`, for example `tls:203.0.113.5:443`.
pub fn parse_seed_addr(s: &str) -> Result<wp::SeedAddr> {
    let (t, rest) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("seed address {s:?} must be transport:host:port"))?;
    let transport = Transport::parse(t).ok_or_else(|| anyhow!("unknown transport {t}"))?;
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("seed address {s:?} without port"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Ok(wp::SeedAddr {
        host: Some(host.to_string()),
        port: port.parse()?,
        transport,
    })
}

impl SeedsFile {
    pub fn to_wire(&self) -> Result<wp::Seeds> {
        Ok(wp::Seeds {
            version: self.version,
            entries: Some(
                self.seeds
                    .iter()
                    .map(|e| {
                        Ok(wp::SeedEntry {
                            node: Some(e.node.clone()),
                            addrs: Some(
                                e.addrs
                                    .iter()
                                    .map(|a| parse_seed_addr(a))
                                    .collect::<Result<Vec<_>>>()?,
                            ),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
        })
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct LimitsFile {
    pub version: u64,
    #[serde(default)]
    pub defaults: BTreeMap<String, u64>,
    #[serde(default)]
    pub overrides: Vec<LimitOverrideFile>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct LimitOverrideFile {
    pub select: Vec<String>,
    pub values: BTreeMap<String, u64>,
}

fn limit_values(m: &BTreeMap<String, u64>) -> Vec<wp::LimitValue> {
    m.iter()
        .map(|(k, v)| wp::LimitValue {
            name: Some(k.clone()),
            value: *v,
        })
        .collect()
}

impl LimitsFile {
    pub fn to_wire(&self) -> Result<wp::Limits> {
        let l = wp::Limits {
            version: self.version,
            defaults: Some(limit_values(&self.defaults)),
            overrides: Some(
                self.overrides
                    .iter()
                    .map(|o| wp::LimitOverride {
                        select: Some(o.select.clone()),
                        values: Some(limit_values(&o.values)),
                    })
                    .collect(),
            ),
        };
        webjet_core::validate::limits(&l)?;
        Ok(l)
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct TransportFile {
    pub version: u64,
    #[serde(default)]
    pub defaults: BTreeMap<String, u8>,
    #[serde(default)]
    pub overrides: Vec<PriorityOverrideFile>,
    #[serde(default)]
    pub camouflage: Option<CamouflageFile>,
    #[serde(default)]
    pub padding: Option<PaddingFile>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PriorityOverrideFile {
    pub select: Vec<String>,
    pub values: BTreeMap<String, u8>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct CamouflageFile {
    /// `website` or `refuse`.
    pub mode: String,
    /// SNI and certificate name. Website mode only.
    #[serde(default)]
    pub domain: Option<String>,
    /// PEM certificate chain file, leaf first. Website mode only.
    #[serde(default)]
    pub certificate: Option<String>,
    /// Optional PEM certificate of the next key, for a key change (runbook 7).
    /// Website mode only.
    #[serde(default)]
    pub next_certificate: Option<String>,
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
        ]
        .into_iter()
        .filter_map(|(k, set)| set.then_some(k))
        .collect()
    }
}

/// What [`refuse_certificate`] did.
pub enum RefuseCertificate {
    /// The network's current certificate (and domain) were kept.
    Kept,
    /// A new self-signed certificate was made; its private key must be
    /// submitted with `SetCamouflageSecret` before the transport config.
    New { key_pem: Vec<u8> },
}

/// Fill in a refuse-mode camouflage's domain and certificate. Refuse mode
/// needs no public certificate, but AnyTLS clients still pin one so nobody
/// can intercept the PSK-derived password (§9.7.2), so the network's current
/// one is kept or, without one, a self-signed one is made for a random name.
pub fn refuse_certificate(
    cam: &mut wp::Camouflage,
    current: Option<&wp::Camouflage>,
) -> Result<RefuseCertificate> {
    if let Some(cur) = current
        && cur.certificate.as_ref().is_some_and(|c| !c.is_empty())
    {
        cam.domain = cur.domain.clone();
        cam.certificate = cur.certificate.clone();
        cam.next_spki = cur.next_spki;
        return Ok(RefuseCertificate::Kept);
    }
    #[cfg(feature = "anytls")]
    {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let label: String = (0..10)
            .map(|_| rng.gen_range(b'a'..=b'z') as char)
            .collect();
        let domain = format!("www.{label}.com");
        let (cert, key_pem) = webjet_net::anytls::self_signed(&domain)?;
        cam.domain = Some(domain);
        cam.certificate = Some(vec![wp::Blob { data: Some(cert) }]);
        cam.next_spki = None;
        Ok(RefuseCertificate::New { key_pem })
    }
    #[cfg(not(feature = "anytls"))]
    bail!("built without AnyTLS: can't make a camouflage certificate")
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PaddingFile {
    pub stop: u32,
    pub lines: Vec<String>,
}

fn priorities(m: &BTreeMap<String, u8>) -> Result<Vec<wp::TransportPriority>> {
    m.iter()
        .map(|(k, v)| {
            Ok(wp::TransportPriority {
                transport: Transport::parse(k).ok_or_else(|| anyhow!("unknown transport {k}"))?,
                priority: *v,
            })
        })
        .collect()
}

/// DER certificates from a PEM file.
pub fn pem_certs(pem: &str) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for line in pem.lines() {
        let l = line.trim();
        if l == "-----BEGIN CERTIFICATE-----" {
            cur = Some(String::new());
        } else if l == "-----END CERTIFICATE-----" {
            let b = cur.take().ok_or_else(|| anyhow!("unbalanced PEM"))?;
            out.push(base64::engine::general_purpose::STANDARD.decode(b)?);
        } else if let Some(c) = cur.as_mut() {
            c.push_str(l);
        }
    }
    if out.is_empty() {
        bail!("no certificate in PEM file");
    }
    Ok(out)
}

/// The certificates in a PEM file named by `field` of a settings file;
/// relative paths are relative to that file.
fn cert_file(path: &Path, field: &str) -> Result<Vec<Vec<u8>>> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("{field}: read {}", path.display()))?;
    pem_certs(&pem).with_context(|| format!("{field}: {}", path.display()))
}

impl TransportFile {
    pub fn to_wire(&self, base: &Path) -> Result<wp::TransportConfig> {
        let camouflage = match &self.camouflage {
            None => None,
            Some(c) => {
                let mode = match c.mode.as_str() {
                    "website" => wp::CamouflageMode::Website,
                    "refuse" => wp::CamouflageMode::Refuse,
                    m => bail!("camouflage mode must be website or refuse, got {m}"),
                };
                if c.refuse() {
                    // Domain and certificate are filled in when applying
                    // (refuse_certificate), from the network or generated.
                    Some(Box::new(wp::Camouflage {
                        mode,
                        domain: None,
                        certificate: None,
                        next_spki: None,
                    }))
                } else {
                    let domain = c
                        .domain
                        .clone()
                        .ok_or_else(|| anyhow!("camouflage.domain is required in website mode"))?;
                    let cert = c.certificate.as_ref().ok_or_else(|| {
                        anyhow!("camouflage.certificate is required in website mode")
                    })?;
                    let chain = cert_file(&base.join(cert), "camouflage.certificate")?;
                    let next_spki = match &c.next_certificate {
                        #[cfg(feature = "anytls")]
                        Some(p) => {
                            let next = cert_file(&base.join(p), "camouflage.next_certificate")?;
                            Some(crypto::k32(&webjet_net::anytls::spki_pin(&next[0])?))
                        }
                        #[cfg(not(feature = "anytls"))]
                        Some(_) => bail!("built without AnyTLS"),
                        None => None,
                    };
                    Some(Box::new(wp::Camouflage {
                        mode,
                        domain: Some(domain),
                        certificate: Some(
                            chain
                                .into_iter()
                                .map(|d| wp::Blob { data: Some(d) })
                                .collect(),
                        ),
                        next_spki,
                    }))
                }
            }
        };
        let t = wp::TransportConfig {
            version: self.version,
            defaults: Some(priorities(&self.defaults)?),
            overrides: Some(
                self.overrides
                    .iter()
                    .map(|o| {
                        Ok(wp::PriorityOverride {
                            select: Some(o.select.clone()),
                            values: Some(priorities(&o.values)?),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
            camouflage,
            padding: self.padding.as_ref().map(|p| {
                Box::new(wp::PaddingScheme {
                    stop: p.stop,
                    lines: Some(p.lines.clone()),
                })
            }),
        };
        webjet_core::validate::transport(&t)?;
        Ok(t)
    }
}

/// Parse a list of overlay addresses (`10.7.0.12` or `10.7.0.12/32`).
pub fn overlay_ips(v: &[String]) -> Result<Vec<wp::Cidr>> {
    let mut out = Vec::new();
    for s in v {
        out.push(net_to_cidr(&parse_net(s)?));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

pub fn grants(v: &[String]) -> Result<Vec<wp::RouteGrant>> {
    let mut out: Vec<wp::RouteGrant> = v
        .iter()
        .map(|s| Ok(Grant::parse(s)?.to_wire()))
        .collect::<Result<_>>()?;
    out.sort();
    out.dedup();
    Ok(out)
}

pub fn tags(v: &[String]) -> Result<Vec<String>> {
    for t in v {
        if !webjet_core::types::valid_tag(t) {
            bail!("invalid tag {t:?} (tags look like tag:name)");
        }
    }
    Ok(webjet_core::types::sort_dedup(v.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seal_roundtrip() {
        let s = seal("pw", b"secret").unwrap();
        assert_eq!(&unseal("pw", &s).unwrap()[..], b"secret");
        assert!(unseal("other", &s).is_err());
    }
    #[test]
    fn seed_addr() {
        let a = parse_seed_addr("tls:203.0.113.5:443").unwrap();
        assert_eq!(a.port, 443);
        assert_eq!(a.transport, Transport::TcpTls);
        let a = parse_seed_addr("kcp:[2001:db8::1]:443").unwrap();
        assert_eq!(a.host.as_deref(), Some("2001:db8::1"));
    }

    fn transport_yaml(camouflage: &str) -> TransportFile {
        serde_yaml::from_str(&format!("version: 1\ncamouflage:\n{camouflage}")).unwrap()
    }

    #[test]
    fn website_mode_reads_the_certificate_and_names_it_in_errors() {
        let dir = std::env::temp_dir().join(format!("webjet-tools-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = transport_yaml(
            "  mode: website\n  domain: cdn.example.com\n  certificate: missing.crt\n",
        );
        let e = format!("{:#}", f.to_wire(&dir).unwrap_err());
        assert!(
            e.contains("camouflage.certificate") && e.contains("missing.crt"),
            "{e}"
        );
        std::fs::write(dir.join("junk.crt"), "not a certificate").unwrap();
        let f =
            transport_yaml("  mode: website\n  domain: cdn.example.com\n  certificate: junk.crt\n");
        let e = format!("{:#}", f.to_wire(&dir).unwrap_err());
        assert!(
            e.contains("junk.crt") && e.contains("no certificate"),
            "{e}"
        );
        let f = transport_yaml("  mode: website\n  certificate: junk.crt\n");
        let e = format!("{:#}", f.to_wire(&dir).unwrap_err());
        assert!(e.contains("camouflage.domain is required"), "{e}");
        let f = transport_yaml("  mode: website\n  domain: cdn.example.com\n");
        let e = format!("{:#}", f.to_wire(&dir).unwrap_err());
        assert!(e.contains("camouflage.certificate is required"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuse_mode_ignores_domain_and_certificate() {
        // Files that don't exist are never read in refuse mode.
        let f = transport_yaml(
            "  mode: refuse\n  domain: cdn.example.com\n  certificate: missing.crt\n  next_certificate: gone.crt\n",
        );
        assert_eq!(
            f.camouflage.as_ref().unwrap().ignored(),
            ["domain", "certificate", "next_certificate"]
        );
        let cfg = f.to_wire(Path::new("/nonexistent")).unwrap();
        let cam = cfg.camouflage.unwrap();
        assert_eq!(cam.mode, wp::CamouflageMode::Refuse);
        assert!(cam.domain.is_none() && cam.certificate.is_none() && cam.next_spki.is_none());
        let bare = transport_yaml("  mode: refuse\n");
        assert!(bare.camouflage.as_ref().unwrap().ignored().is_empty());
        assert!(bare.to_wire(Path::new("/nonexistent")).is_ok());
    }

    #[test]
    fn refuse_mode_keeps_the_networks_certificate() {
        let current = wp::Camouflage {
            mode: wp::CamouflageMode::Website,
            domain: Some("cdn.example.com".into()),
            certificate: Some(vec![wp::Blob {
                data: Some(vec![1, 2, 3]),
            }]),
            next_spki: None,
        };
        let mut cam = wp::Camouflage {
            mode: wp::CamouflageMode::Refuse,
            domain: None,
            certificate: None,
            next_spki: None,
        };
        assert!(matches!(
            refuse_certificate(&mut cam, Some(&current)).unwrap(),
            RefuseCertificate::Kept
        ));
        assert_eq!(cam.domain.as_deref(), Some("cdn.example.com"));
        assert_eq!(cam.certificate, current.certificate);
        assert_eq!(cam.mode, wp::CamouflageMode::Refuse);
    }

    #[cfg(feature = "anytls")]
    #[test]
    fn refuse_mode_without_a_certificate_makes_one() {
        let mut cam = wp::Camouflage {
            mode: wp::CamouflageMode::Refuse,
            domain: None,
            certificate: None,
            next_spki: None,
        };
        let RefuseCertificate::New { key_pem } = refuse_certificate(&mut cam, None).unwrap() else {
            panic!("expected a new certificate");
        };
        assert!(String::from_utf8_lossy(&key_pem).contains("PRIVATE KEY"));
        let domain = cam.domain.clone().unwrap();
        assert!(webjet_core::validate::valid_dns_name(&domain), "{domain}");
        let leaf = cam.certificate.as_ref().unwrap()[0].data.clone().unwrap();
        assert!(webjet_net::anytls::spki_pin(&leaf).is_ok());
        // The result passes the controllers' validation.
        let t = wp::TransportConfig {
            version: 1,
            defaults: Some(vec![]),
            overrides: Some(vec![]),
            camouflage: Some(Box::new(cam)),
            padding: None,
        };
        webjet_core::validate::transport(&t).unwrap();
    }
}
