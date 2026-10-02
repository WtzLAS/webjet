//! Local state on disk (§10.4, §19.4): identity key, genesis, the verified
//! network state (head, leaves, certificates, tombstones), PSK epochs,
//! cached relay endpoints and unsent metric reports. Every write is atomic
//! (temp file + rename) and readable only by the agent's user.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use webjet_core::crypto::{Bytes32, KeyPair};
use zeroize::Zeroizing;

pub fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

pub fn unb64(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

mod b64v {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::b64(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        super::unb64(&s).map_err(serde::de::Error::custom)
    }
}

mod b64vv {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        v.iter()
            .map(|x| super::b64(x))
            .collect::<Vec<_>>()
            .serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let v = Vec::<String>::deserialize(d)?;
        v.iter()
            .map(|s| super::unb64(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub struct Paths {
    pub dir: PathBuf,
}

impl Paths {
    pub fn new(dir: &Path) -> Paths {
        Paths {
            dir: dir.to_path_buf(),
        }
    }
    pub fn identity(&self) -> PathBuf {
        self.dir.join("identity.key")
    }
    pub fn node(&self) -> PathBuf {
        self.dir.join("node.json")
    }
    pub fn genesis(&self) -> PathBuf {
        self.dir.join("genesis.wj")
    }
    pub fn store(&self) -> PathBuf {
        self.dir.join("store.json")
    }
    pub fn psk(&self) -> PathBuf {
        self.dir.join("psk.json")
    }
    pub fn relays(&self) -> PathBuf {
        self.dir.join("relays.json")
    }
    pub fn camouflage(&self) -> PathBuf {
        self.dir.join("camouflage.json")
    }
    pub fn metrics_ring(&self) -> PathBuf {
        self.dir.join("metrics-ring")
    }
    pub fn raft(&self) -> PathBuf {
        self.dir.join("raft")
    }
}

// ---------------------------------------------------------------- identity key (§8.3)

/// Load the node identity key, decrypting it with the platform key when one
/// is configured. On Linux servers the file is readable only by the agent's
/// user; device-bound sealing (TPM, Keychain, DPAPI) wraps the same 32 bytes.
pub fn load_identity(p: &Paths) -> Result<Option<KeyPair>> {
    let path = p.identity();
    if !path.exists() {
        return Ok(None);
    }
    let raw = Zeroizing::new(std::fs::read(&path)?);
    let seed = platform_unseal(&raw)?;
    Ok(Some(KeyPair::from_seed(&seed)))
}

pub fn save_identity(p: &Paths, kp: &KeyPair) -> Result<()> {
    let sealed = platform_seal(&kp.seed())?;
    write_private(&p.identity(), &sealed)
}

/// Device-bound wrapping hook. The default is the plain 32-byte seed in a
/// 0600 file; `WEBJET_KEY_WRAP=machine-id` binds it to the machine id on
/// Linux so a copied file is useless elsewhere.
fn platform_seal(seed: &Bytes32) -> Result<Vec<u8>> {
    match machine_wrap_key() {
        Some(k) => {
            let mut out = b"WJK1".to_vec();
            let pad = webjet_core::crypto::derive("webjet key wrap v1", &k);
            out.extend(seed.iter().zip(pad.iter()).map(|(a, b)| a ^ b));
            out.extend_from_slice(&webjet_core::crypto::keyed(&pad, seed)[..16]);
            Ok(out)
        }
        None => Ok(seed.to_vec()),
    }
}

fn platform_unseal(raw: &[u8]) -> Result<Zeroizing<Bytes32>> {
    if raw.len() == 32 {
        let mut s = Zeroizing::new([0u8; 32]);
        s.copy_from_slice(raw);
        return Ok(s);
    }
    if raw.len() == 52 && &raw[..4] == b"WJK1" {
        let k = machine_wrap_key().ok_or_else(|| {
            anyhow!("identity key is device-bound but the device key is unavailable")
        })?;
        let pad = webjet_core::crypto::derive("webjet key wrap v1", &k);
        let mut s = Zeroizing::new([0u8; 32]);
        for i in 0..32 {
            s[i] = raw[4 + i] ^ pad[i];
        }
        if webjet_core::crypto::keyed(&pad, &s[..])[..16] != raw[36..52] {
            anyhow::bail!("identity key is bound to another machine; re-key this node (§8.1)");
        }
        return Ok(s);
    }
    anyhow::bail!("unrecognized identity key file")
}

fn machine_wrap_key() -> Option<Vec<u8>> {
    if std::env::var("WEBJET_KEY_WRAP").ok().as_deref() != Some("machine-id") {
        return None;
    }
    std::fs::read("/etc/machine-id").ok()
}

// ---------------------------------------------------------------- node info

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NodeFile {
    pub node_id: String,
    /// Controller enrollment endpoints from the ticket (§10.7.1, last resort).
    #[serde(default)]
    pub enroll_controllers: Vec<SeedHint>,
    /// Seeds from enrollment (§10.7.1 step 3).
    #[serde(default)]
    pub enroll_seeds: Vec<SeedHint>,
    #[serde(default)]
    pub camouflage_domain: Option<String>,
    #[serde(default)]
    pub camouflage_pin: Option<String>,
    /// The first controller of a new network (runbook 1): it proposes the
    /// genesis entry and enrolls itself through the control channel.
    #[serde(default)]
    pub bootstrap: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedHint {
    pub node: Option<String>,
    pub host: String,
    pub port: u16,
    pub transport: String,
}

pub fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    let s = std::fs::read(path)?;
    Ok(Some(
        serde_json::from_slice(&s).with_context(|| format!("parse {}", path.display()))?,
    ))
}

pub fn save_json<T: Serialize>(path: &Path, v: &T) -> Result<()> {
    write_private(path, &serde_json::to_vec_pretty(v)?)
}

// ---------------------------------------------------------------- verified state (§10.4)

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LeafFile {
    pub kind: u8,
    pub key: String,
    #[serde(with = "b64v")]
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StoreFile {
    #[serde(default, with = "b64v")]
    pub head: Vec<u8>,
    pub high_water: u64,
    pub trusted_floor: u64,
    pub leaves: Vec<LeafFile>,
    /// Certificates, key tombstones, offline-signed tombstones.
    #[serde(with = "b64vv")]
    pub offline: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PskFile {
    pub current: u16,
    pub epochs: BTreeMap<u16, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RelayCache {
    /// Last known EndpointRecords of relays (§10.7.1 step 1), raw envelopes.
    #[serde(with = "b64vv")]
    pub endpoints: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CamouflageFile {
    #[serde(with = "b64v")]
    pub key_pem: Vec<u8>,
    #[serde(with = "b64v")]
    pub site: Vec<u8>,
}

pub fn save_store(p: &Paths, s: &webjet_core::store::Store) -> Result<()> {
    let f = StoreFile {
        head: s.head().map(|h| h.raw.clone()).unwrap_or_default(),
        high_water: s.high_water,
        trusted_floor: s.trusted_floor,
        leaves: s
            .all_leaves()
            .into_iter()
            .map(|(k, key, b)| LeafFile {
                kind: k,
                key: hex::encode(key),
                bytes: b,
            })
            .collect(),
        offline: s.offline_items(),
    };
    save_json(&p.store(), &f)
}

pub fn load_store(p: &Paths, genesis: Vec<u8>) -> Result<webjet_core::store::Store> {
    let mut s = webjet_core::store::Store::new(genesis)?;
    if let Some(f) = load_json::<StoreFile>(&p.store())? {
        for o in &f.offline {
            if let Err(e) = s.add_offline_item(o) {
                tracing::warn!("persisted offline item rejected: {e}");
            }
        }
        let leaves = f
            .leaves
            .iter()
            .filter_map(|l| {
                Some((
                    l.kind,
                    webjet_core::crypto::parse_hex32(&l.key)?,
                    l.bytes.clone(),
                ))
            })
            .collect();
        let head = if f.head.is_empty() {
            None
        } else {
            Some(&f.head[..])
        };
        if let Err(e) = s.restore(head, leaves, f.high_water, f.trusted_floor) {
            tracing::error!("persisted tree state rejected ({e}); resyncing from peers");
            s.high_water = f.high_water;
            s.trusted_floor = f.trusted_floor;
        }
    }
    Ok(s)
}

pub fn save_psk(p: &Paths, e: &webjet_net::gate::Epochs) -> Result<()> {
    let f = PskFile {
        current: e.current,
        epochs: e.keys.iter().map(|(k, v)| (*k, hex::encode(v))).collect(),
    };
    save_json(&p.psk(), &f)
}

pub fn load_psk(p: &Paths) -> Result<webjet_net::gate::Epochs> {
    let mut e = webjet_net::gate::Epochs::default();
    if let Some(f) = load_json::<PskFile>(&p.psk())? {
        e.current = f.current;
        for (k, v) in f.epochs {
            if let Some(b) = webjet_core::crypto::parse_hex32(&v) {
                e.keys.insert(k, b);
            }
        }
    }
    Ok(e)
}
