//! Local state on disk (§10.4, §19.4): identity key, genesis, the verified
//! network state (head, leaves, certificates, tombstones), PSK epochs,
//! cached relay endpoints and unsent metric reports. Every write is atomic
//! (temp file + rename) and readable only by the agent's user.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use webjet_core::crypto::{Bytes32, KeyPair};

pub use webjet_core::crypto::{b64, unb64};

mod b64v {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
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

/// Make a directory private to the agent: 0700 on Unix; on Windows an
/// ACL for SYSTEM and Administrators only, which files inside inherit.
pub fn restrict_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(windows)]
    {
        if let Err(e) = crate::winsec::restrict(dir) {
            tracing::debug!("restricting {}: {e}", dir.display());
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = dir;
}

/// Replace `path` atomically with `data`, readable only by the agent's
/// user. Each write goes through its own temp file, so concurrent writers
/// of one file never mix their contents (the last rename wins), and on Unix
/// the directory is synced so the rename survives a power cut.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        restrict_dir(dir);
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{:016x}.tmp", rand::random::<u64>()));
    let written = (|| -> Result<()> {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
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
        drop(f);
        std::fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
        Ok(())
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written?;
    sync_dir(path.parent());
    Ok(())
}

/// Make a rename in `dir` durable (Unix; Windows has no directory handles
/// for this, and NTFS journals the rename itself).
fn sync_dir(dir: Option<&Path>) {
    #[cfg(unix)]
    if let Some(dir) = dir {
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        if let Err(e) = std::fs::File::open(dir).and_then(|d| d.sync_all()) {
            tracing::debug!("syncing {}: {e}", dir.display());
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
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
    pub fn links(&self) -> PathBuf {
        self.dir.join("links.json")
    }
    pub fn metrics_ring(&self) -> PathBuf {
        self.dir.join("metrics-ring")
    }
    pub fn raft(&self) -> PathBuf {
        self.dir.join("raft")
    }
}

// ---------------------------------------------------------------- identity key (§8.3)

/// Load the node identity key from its platform store (§8.3).
pub fn load_identity(p: &Paths, cfg: &crate::keystore::KeyCfg) -> Result<Option<KeyPair>> {
    Ok(crate::keystore::load(&p.identity(), cfg)?.map(|(k, b)| {
        tracing::info!("identity key loaded from {} storage", b.name());
        k
    }))
}

/// Store the identity key; returns the backend used.
pub fn save_identity(
    p: &Paths,
    cfg: &crate::keystore::KeyCfg,
    kp: &KeyPair,
) -> Result<crate::keystore::Backend> {
    crate::keystore::save(
        &p.identity(),
        cfg,
        &crate::keystore::account_for(&p.dir),
        &kp.seed(),
    )
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
    /// The first controller of a new network (ops guide 2.1): it proposes the
    /// genesis entry and enrolls itself through the control channel.
    #[serde(default)]
    pub bootstrap: bool,
    /// A controller restored from a snapshot onto this node (ops guide 4.1):
    /// the controller role starts before the node's own tree shows the
    /// control role, which only the restored controller can grant. Cleared
    /// once the tree grants it.
    #[serde(default)]
    pub restored_controller: bool,
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
    save_store_file(p, &store_file(s))
}

/// A copy of what [`save_store`] writes: taken under the store lock, so the
/// slow part (encoding, the disk write) can run after the lock is released.
pub fn store_file(s: &webjet_core::store::Store) -> StoreFile {
    StoreFile {
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
    }
}

/// Write `store.json`. Compact JSON: it is rewritten after every tree
/// change and only ever read back by the agent.
pub fn save_store_file(p: &Paths, f: &StoreFile) -> Result<()> {
    write_private(&p.store(), &serde_json::to_vec(f)?)
}

pub fn load_store(p: &Paths, genesis: Vec<u8>) -> Result<webjet_core::store::Store> {
    let mut s = webjet_core::store::Store::new(genesis)?;
    if let Some(f) = load_json::<StoreFile>(&p.store())? {
        for r in s.add_offline_items(&f.offline) {
            if let Err(e) = r {
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

#[derive(Serialize, Deserialize)]
struct LinkEntry {
    peer: String,
    transport: String,
    #[serde(flatten)]
    history: webjet_core::routing::LinkHistory,
}

pub fn load_links(
    p: &Paths,
) -> std::collections::HashMap<(Bytes32, webjet_proto::Transport), webjet_core::routing::LinkHistory>
{
    let v: Vec<LinkEntry> = load_json(&p.links()).ok().flatten().unwrap_or_default();
    v.into_iter()
        .filter_map(|e| {
            Some((
                (
                    webjet_core::crypto::parse_hex32(&e.peer)?,
                    webjet_proto::Transport::parse(&e.transport)?,
                ),
                e.history,
            ))
        })
        .collect()
}

pub fn save_links(
    p: &Paths,
    m: &std::collections::HashMap<
        (Bytes32, webjet_proto::Transport),
        webjet_core::routing::LinkHistory,
    >,
) -> Result<()> {
    let mut v: Vec<LinkEntry> = m
        .iter()
        .map(|((peer, t), h)| LinkEntry {
            peer: hex::encode(peer),
            transport: t.name().into(),
            history: h.clone(),
        })
        .collect();
    v.sort_by(|a, b| (&a.peer, &a.transport).cmp(&(&b.peer, &b.transport)));
    save_json(&p.links(), &v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use webjet_core::crypto::k32;
    use webjet_core::testutil::Cluster;
    use webjet_proto::{self as wp, Transport, msg_type as mt};

    #[test]
    fn base64_fields_roundtrip() {
        let f = StoreFile {
            head: vec![1, 2, 3],
            offline: vec![vec![], vec![0xff; 40]],
            ..Default::default()
        };
        let j = serde_json::to_string(&f).unwrap();
        assert!(j.contains("\"AQID\""), "{j}");
        let back: StoreFile = serde_json::from_str(&j).unwrap();
        assert_eq!((back.head, back.offline), (f.head, f.offline));
        // A store file without a head (never synced) still loads.
        let old = r#"{"high_water":0,"trusted_floor":0,"leaves":[],"offline":[]}"#;
        assert!(
            serde_json::from_str::<StoreFile>(old)
                .unwrap()
                .head
                .is_empty()
        );
        assert!(
            serde_json::from_str::<StoreFile>(
                r#"{"head":"%%","high_water":0,"trusted_floor":0,"leaves":[],"offline":[]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn json_files() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/x.json");
        assert!(load_json::<NodeFile>(&p).unwrap().is_none());
        let nf = NodeFile {
            node_id: "ab".into(),
            bootstrap: true,
            ..Default::default()
        };
        save_json(&p, &nf).unwrap();
        let back: NodeFile = load_json(&p).unwrap().unwrap();
        assert_eq!((back.node_id.as_str(), back.bootstrap), ("ab", true));
        let files = || {
            let mut v: Vec<_> = std::fs::read_dir(p.parent().unwrap())
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            v.sort();
            v
        };
        assert_eq!(files(), ["x.json"], "temp file left behind");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&p), 0o600);
            assert_eq!(mode(p.parent().unwrap()), 0o700);
        }
        // Older node files lack the later fields.
        std::fs::write(&p, r#"{"node_id":"cd"}"#).unwrap();
        let old: NodeFile = load_json(&p).unwrap().unwrap();
        assert!(!old.bootstrap && old.enroll_seeds.is_empty());
        std::fs::write(&p, "not json").unwrap();
        let e = load_json::<NodeFile>(&p).unwrap_err().to_string();
        assert!(e.contains("x.json"), "{e}");
    }

    #[test]
    fn concurrent_writes_of_one_file_never_mix() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("store.json");
        let blobs: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 256 * 1024]).collect();
        std::thread::scope(|s| {
            for b in &blobs {
                let p = &p;
                s.spawn(move || {
                    for _ in 0..5 {
                        write_private(p, b).unwrap();
                    }
                });
            }
        });
        let got = std::fs::read(&p).unwrap();
        assert!(
            blobs.contains(&got),
            "the file is one writer's whole content"
        );
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[test]
    fn store_survives_a_restart() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::new(d.path());
        let mut c = Cluster::new();
        let (id, _) = c.data_node("web", "10.7.0.2", &[]);
        let (gone, _) = c.data_node("gone", "10.7.0.3", &[]);
        let mut st = c.store();
        // An offline tombstone too.
        let tomb = wp::Tombstone {
            node_id: Some(k32(&gone)),
            version: 99,
            reason: None,
        };
        st.add_offline_tombstone(&c.net.emergency.sign_obj(mt::TOMBSTONE, &tomb))
            .unwrap();
        save_store(&p, &st).unwrap();

        let back = load_store(&p, c.net.genesis.clone()).unwrap();
        assert_eq!(back.high_water, st.high_water);
        assert_eq!(back.view().by_name.get("web"), Some(&id));
        assert!(back.node_trusted(&id));
        assert!(!back.node_trusted(&gone));
        assert_eq!(back.all_leaves(), st.all_leaves());
    }

    #[test]
    fn a_damaged_store_file_falls_back_to_resync() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::new(d.path());
        let mut c = Cluster::new();
        c.data_node("web", "10.7.0.2", &[]);
        let st = c.store();
        save_store(&p, &st).unwrap();
        let mut f: StoreFile = load_json(&p.store()).unwrap().unwrap();
        // A leaf that doesn't match the signed head.
        f.leaves[0].bytes[10] ^= 1;
        save_json(&p.store(), &f).unwrap();
        let back = load_store(&p, c.net.genesis.clone()).unwrap();
        assert!(back.head().is_none(), "tree not restored");
        assert!(!back.view().by_name.contains_key("web"));
        // The rollback floor is kept.
        assert_eq!(back.high_water, st.high_water);
        // No store file at all: an empty store.
        std::fs::remove_file(p.store()).unwrap();
        assert!(
            load_store(&p, c.net.genesis.clone())
                .unwrap()
                .head()
                .is_none()
        );
    }

    #[test]
    fn psk_epochs() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::new(d.path());
        assert!(load_psk(&p).unwrap().keys.is_empty());
        let mut e = webjet_net::gate::Epochs::default();
        e.keys.insert(3, [3; 32]);
        e.keys.insert(4, [4; 32]);
        e.current = 4;
        save_psk(&p, &e).unwrap();
        let back = load_psk(&p).unwrap();
        assert_eq!((back.current, back.keys), (4, e.keys.clone()));
        // A damaged key is dropped, the rest kept.
        let mut f: PskFile = load_json(&p.psk()).unwrap().unwrap();
        f.epochs.insert(5, "zz".into());
        save_json(&p.psk(), &f).unwrap();
        assert_eq!(load_psk(&p).unwrap().keys, e.keys);
    }

    #[test]
    fn link_history() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::new(d.path());
        assert!(load_links(&p).is_empty());
        let h = webjet_core::routing::LinkHistory {
            rtt_ms: 12.5,
            samples: 9,
            ..Default::default()
        };
        let m = std::collections::HashMap::from([
            (([1; 32], Transport::TcpTls), h.clone()),
            (([2; 32], Transport::KcpFecTls), h),
        ]);
        save_links(&p, &m).unwrap();
        let back = load_links(&p);
        assert_eq!(back.len(), 2);
        assert_eq!(back[&([1; 32], Transport::TcpTls)].rtt_ms, 12.5);
        // Garbage in the file: nothing, not an error.
        std::fs::write(p.links(), "[{]").unwrap();
        assert!(load_links(&p).is_empty());
        // Entries with an unknown transport are skipped, the rest kept.
        let entry = |t: &str| {
            format!(
                r#"{{"peer":"{}","transport":"{t}","rtt_ms":1,"loss":0,"jitter_ms":0,"flaps":0,"samples":1,"updated_ms":0}}"#,
                hex::encode([1u8; 32])
            )
        };
        let file = format!(
            "[{},{}]",
            entry("carrier-pigeon"),
            entry(Transport::TcpTls.name())
        );
        std::fs::write(p.links(), file).unwrap();
        let back = load_links(&p);
        assert_eq!(back.len(), 1);
        assert!(back.contains_key(&([1; 32], Transport::TcpTls)));
    }

    #[test]
    fn paths() {
        let p = Paths::new(Path::new("/x"));
        let names = [
            p.identity(),
            p.node(),
            p.genesis(),
            p.store(),
            p.psk(),
            p.relays(),
            p.camouflage(),
            p.links(),
            p.metrics_ring(),
            p.raft(),
        ];
        let mut uniq = names.to_vec();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), names.len());
        assert!(names.iter().all(|n| n.parent() == Some(Path::new("/x"))));
    }
}
