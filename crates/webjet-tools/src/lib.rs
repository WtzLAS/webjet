//! Shared code for the command-line tools: key files, signed files, and the
//! configuration documents (`config`).

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::Path;
use webjet_core::crypto::{self, Bytes32, KeyPair};
use webjet_core::types::{Grant, net_to_cidr, now_ms, parse_net};
use webjet_proto::{self as wp, Transport};
use zeroize::Zeroizing;

pub mod config;
pub mod prompt;
pub mod root;

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
                "no account keys in {} (webjetctl network account keygen)",
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

/// The file in a key directory naming the account to sign with when none is
/// given (`webjetctl network account use`).
pub const DEFAULT_ACCOUNT_FILE: &str = "default";

/// The default account recorded in `dir`, if any.
pub fn default_account(dir: &Path) -> Result<Option<String>> {
    let path = dir.join(DEFAULT_ACCOUNT_FILE);
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let name = s.trim();
            Ok((!name.is_empty()).then(|| name.to_string()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Record `name` as the default account in `dir` (`None` clears it). The
/// account's key must be in `dir`.
pub fn set_default_account(dir: &Path, name: Option<&str>) -> Result<()> {
    let path = dir.join(DEFAULT_ACCOUNT_FILE);
    match name {
        Some(n) => {
            if !account_names(dir)?.iter().any(|a| a == n) {
                bail!("no key for account {n} in {}", dir.display());
            }
            write_public(&path, format!("{n}\n").as_bytes())
        }
        None => match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(e).with_context(|| format!("remove {}", path.display()))
            }
            _ => Ok(()),
        },
    }
}

/// The account to sign with: `given` (`--account` / `WEBJET_ACCOUNT`), else
/// the default recorded in `dir`, else the only key in `dir`.
pub fn pick_account(dir: &Path, given: Option<&str>) -> Result<String> {
    if let Some(n) = given {
        return Ok(n.to_string());
    }
    let names = account_names(dir)?;
    if let Some(n) = default_account(dir)? {
        if !names.contains(&n) {
            bail!(
                "the default account {n} ({}) has no key in {}; choose another with \
                 `webjetctl network account use <name>`",
                dir.join(DEFAULT_ACCOUNT_FILE).display(),
                dir.display()
            );
        }
        return Ok(n);
    }
    match names.as_slice() {
        [one] => Ok(one.clone()),
        [] => bail!(
            "no account keys in {} (webjetctl network account keygen)",
            dir.display()
        ),
        _ => bail!(
            "several account keys ({}); choose one with --account, or set a default with \
             `webjetctl network account use <name>`",
            names.join(", ")
        ),
    }
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

// ---------------------------------------------------------------- shared parsing

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
    fn account_selection() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path();
        let key = |n: &str| std::fs::write(dir.join(format!("{n}.key")), b"x").unwrap();
        assert!(pick_account(dir, None).is_err(), "no keys");
        key("alice");
        assert_eq!(pick_account(dir, None).unwrap(), "alice", "the only key");
        key("infra");
        let e = pick_account(dir, None).unwrap_err().to_string();
        assert!(
            e.contains("alice, infra") && e.contains("account use"),
            "{e}"
        );
        assert!(
            set_default_account(dir, Some("bob")).is_err(),
            "no such key"
        );
        set_default_account(dir, Some("infra")).unwrap();
        assert_eq!(default_account(dir).unwrap().as_deref(), Some("infra"));
        assert_eq!(pick_account(dir, None).unwrap(), "infra");
        assert_eq!(
            pick_account(dir, Some("alice")).unwrap(),
            "alice",
            "--account wins"
        );
        std::fs::remove_file(dir.join("infra.key")).unwrap();
        let e = pick_account(dir, None).unwrap_err().to_string();
        assert!(e.contains("default account infra"), "{e}");
        set_default_account(dir, None).unwrap();
        set_default_account(dir, None).unwrap();
        assert_eq!(default_account(dir).unwrap(), None);
        assert_eq!(pick_account(dir, None).unwrap(), "alice");
    }
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
