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
        .decrypt(
            nonce.try_into().map_err(|_| anyhow!("bad nonce length"))?,
            ct,
        )
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

/// `transport:host:port`, for example `tls:203.0.113.5:443`,
/// `kcp:[2001:db8::1]:443` or `kcp:relay.example.com:443`. A DNS name is
/// resolved by each node when it dials the seed.
pub fn parse_seed_addr(s: &str) -> Result<wp::SeedAddr> {
    let (t, rest) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("seed address {s:?} must be transport:host:port"))?;
    let transport = Transport::parse(t).ok_or_else(|| anyhow!("unknown transport {t}"))?;
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("seed address {s:?} without port"))?;
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| anyhow!("seed address {s:?}: port {port:?} isn't 1–65535"))?;
    let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => {
            v6.parse::<std::net::Ipv6Addr>()
                .map_err(|_| anyhow!("seed address {s:?}: {v6:?} isn't an IPv6 address"))?;
            v6.to_string()
        }
        None if host.parse::<std::net::IpAddr>().is_ok() => host.to_string(),
        None => {
            let name = host.strip_suffix('.').unwrap_or(host);
            if name.contains(':') || !webjet_core::validate::valid_dns_name(name) {
                bail!(
                    "seed address {s:?}: the host must be an IP address (IPv6 in brackets) or a DNS name"
                );
            }
            name.to_ascii_lowercase()
        }
    };
    Ok(wp::SeedAddr {
        host: Some(host),
        port,
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
        use rand::RngExt;
        let mut rng = rand::rng();
        let label: String = (0..10)
            .map(|_| rng.random_range(b'a'..=b'z') as char)
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

/// Find a node or account in a control-channel list (`nodes`, `accounts`)
/// by what a person typed: its name, its id in hex (all 64 digits, or a
/// prefix of at least 4 that only one entry has, like the 12 digits the
/// logs print), or its key in base64. With `suffix` (the magic DNS suffix),
/// `name.suffix` works too. `skip` leaves entries out (revoked accounts).
pub fn find_id(
    items: &[serde_json::Value],
    query: &str,
    suffix: Option<&str>,
    what: &str,
    skip: impl Fn(&serde_json::Value) -> bool,
) -> Result<Bytes32> {
    let q = query.trim();
    let name = suffix
        .and_then(|s| q.strip_suffix(&format!(".{s}")))
        .unwrap_or(q);
    let id_of = |v: &serde_json::Value| -> Result<Bytes32> {
        crypto::parse_hex32(v["id"].as_str().unwrap_or(""))
            .ok_or_else(|| anyhow!("the agent sent a bad {what} id"))
    };
    let live: Vec<&serde_json::Value> = items.iter().filter(|v| !skip(v)).collect();
    if let Some(v) = live.iter().find(|v| {
        v["name"].as_str() == Some(name)
            || v["id"].as_str().is_some_and(|i| i.eq_ignore_ascii_case(q))
            || v["key"].as_str() == Some(q)
    }) {
        return id_of(v);
    }
    let lower = q.to_ascii_lowercase();
    if lower.len() >= 4 && lower.len() < 64 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
        let hits: Vec<&&serde_json::Value> = live
            .iter()
            .filter(|v| v["id"].as_str().is_some_and(|i| i.starts_with(&lower)))
            .collect();
        match hits.as_slice() {
            [one] => return id_of(one),
            [] => {}
            many => bail!(
                "{q} matches {} {what}s ({}); give more digits",
                many.len(),
                many.iter()
                    .filter_map(|v| v["name"].as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
    bail!("no {what} named {q} (give its name or its id in hex)")
}

/// Turn `{"b0": …, "b1": …, "b2": …, "b3": …}` (a 32-byte id as agents
/// before 0.7 printed it) into its hex string, anywhere in a document.
pub fn legacy_ids(v: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(o) => {
            if o.len() == 4
                && let Ok(k) =
                    serde_json::from_value::<webjet_proto::Key32>(Value::Object(o.clone()))
            {
                return Value::String(hex::encode(k.to_bytes()));
            }
            Value::Object(o.into_iter().map(|(k, x)| (k, legacy_ids(x))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(legacy_ids).collect()),
        other => other,
    }
}

/// Add `"node_names": {id: name}` to a JSON object for every node id (hex)
/// that appears in it as a value, so people see names while scripts keep
/// the ids where they were.
pub fn with_node_names(
    v: serde_json::Value,
    names: &std::collections::HashMap<String, String>,
) -> serde_json::Value {
    fn walk(
        v: &serde_json::Value,
        names: &std::collections::HashMap<String, String>,
        out: &mut std::collections::BTreeMap<String, String>,
    ) {
        match v {
            serde_json::Value::String(s) => {
                if let Some(n) = names.get(s) {
                    out.insert(s.clone(), n.clone());
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, names, out)),
            serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, names, out)),
            _ => {}
        }
    }
    let mut found = std::collections::BTreeMap::new();
    walk(&v, names, &mut found);
    match v {
        serde_json::Value::Object(mut o) if !found.is_empty() => {
            o.insert("node_names".into(), serde_json::json!(found));
            serde_json::Value::Object(o)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_id_by_name_hex_prefix_and_suffix() {
        let a = "af26bc854c76b23e4d039cb77aedc9ed867878e13115ce3892b19b4d53e20a9f";
        let b = "af27000000000000000000000000000000000000000000000000000000000000";
        let items = vec![
            serde_json::json!({"name": "mbp", "id": a, "key": "K1"}),
            serde_json::json!({"name": "pc", "id": b, "key": "K2", "gone": true}),
        ];
        let keep = |_: &serde_json::Value| false;
        let ida = crypto::parse_hex32(a).unwrap();
        assert_eq!(find_id(&items, "mbp", None, "node", keep).unwrap(), ida);
        assert_eq!(find_id(&items, a, None, "node", keep).unwrap(), ida);
        assert_eq!(
            find_id(&items, &a.to_uppercase(), None, "node", keep).unwrap(),
            ida
        );
        assert_eq!(
            find_id(&items, "af26bc854c76", None, "node", keep).unwrap(),
            ida
        );
        assert_eq!(find_id(&items, "K1", None, "node", keep).unwrap(), ida);
        assert_eq!(
            find_id(&items, "mbp.wj", Some("wj"), "node", keep).unwrap(),
            ida
        );
        // Too short for a prefix, and a prefix nobody has.
        let e = find_id(&items, "af2", None, "node", keep)
            .unwrap_err()
            .to_string();
        assert!(e.contains("no node named af2"), "{e}");
        assert!(find_id(&items, "af2a", None, "node", keep).is_err());
        // "af2" + 6 is only a's.
        assert_eq!(find_id(&items, "af26", None, "node", keep).unwrap(), ida);
        // Skipped entries don't match.
        let skip = |v: &serde_json::Value| v["gone"].as_bool() == Some(true);
        assert!(find_id(&items, "pc", None, "node", skip).is_err());
        assert!(find_id(&items, "pc", None, "node", keep).is_ok());
    }

    #[test]
    fn find_id_ambiguous_prefix_names_the_candidates() {
        let items = vec![
            serde_json::json!({"name": "x", "id": format!("abcd{}", "0".repeat(60))}),
            serde_json::json!({"name": "y", "id": format!("abce{}", "0".repeat(60))}),
        ];
        let e = find_id(&items, "abc0", None, "node", |_| false);
        assert!(e.is_err());
        let items2 = vec![
            serde_json::json!({"name": "x", "id": format!("abcd1{}", "0".repeat(59))}),
            serde_json::json!({"name": "y", "id": format!("abcd2{}", "0".repeat(59))}),
        ];
        let e = find_id(&items2, "abcd", None, "node", |_| false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("matches 2 nodes") && e.contains("x, y"), "{e}");
    }

    #[test]
    fn legacy_id_structs_become_hex() {
        let k = webjet_proto::Key32::from_bytes(&[0xab; 32]);
        let v = serde_json::json!({"leader": {"b0": k.b0, "b1": k.b1, "b2": k.b2, "b3": k.b3},
            "voters": [{"b0": k.b0, "b1": k.b1, "b2": k.b2, "b3": k.b3}], "term": 1,
            "other": {"a": 1, "b": 2, "c": 3, "d": 4}});
        let out = legacy_ids(v);
        assert_eq!(out["leader"], serde_json::json!("ab".repeat(32)));
        assert_eq!(out["voters"][0], serde_json::json!("ab".repeat(32)));
        assert_eq!(out["other"]["a"], serde_json::json!(1));
    }

    #[test]
    fn node_names_are_added_for_ids_in_values() {
        let a = "a".repeat(64);
        let mut names = std::collections::HashMap::new();
        names.insert(a.clone(), "ctl-01".to_string());
        let v = serde_json::json!({"raft": {"leader": a, "voters": [a, "other"]}, "term": 3});
        let out = with_node_names(v.clone(), &names);
        assert_eq!(out["raft"], v["raft"]);
        assert_eq!(out["node_names"], serde_json::json!({a.as_str(): "ctl-01"}));
        let none = with_node_names(serde_json::json!({"x": "y"}), &names);
        assert!(none.get("node_names").is_none());
    }

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
        let a = parse_seed_addr("kcp:SV.wolf109909.top:4883").unwrap();
        assert_eq!(
            (a.host.as_deref(), a.port, a.transport),
            (Some("sv.wolf109909.top"), 4883, Transport::KcpFecTls)
        );
        assert_eq!(
            parse_seed_addr("tls:relay.example.com.:443")
                .unwrap()
                .host
                .as_deref(),
            Some("relay.example.com")
        );
        for bad in [
            "kcp:sv.wolf109909.top",
            "kcp:sv.wolf109909.top:0",
            "kcp:sv.wolf109909.top:70000",
            "kcp:bad host:443",
            "kcp:-bad.example:443",
            "kcp:[nope]:443",
            "quic:sv.wolf109909.top:443",
        ] {
            assert!(parse_seed_addr(bad).is_err(), "{bad}");
        }
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
            compression: None,
        };
        webjet_core::validate::transport(&t).unwrap();
    }
}
