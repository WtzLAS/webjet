//! What webjetup, webjetd and webjetctl must agree on about releases and
//! remote upgrades (architecture §19.8, ops guide 3.3):
//!
//! * release targets and file names, and version ordering;
//! * the upgrade spool ([`default_spool_dir`]): webjetd checks an admin's
//!   signed `UpgradeRequest` and puts it, with the admin's AccountRecord, in
//!   `<spool>/queue/` ([`QueuedRequest`]); the root helper (`webjetup
//!   apply-upgrade`, started by the service manager when a request appears)
//!   takes it, checks it itself against the root key and node id webjetup
//!   pinned ([`Trust`], [`plan`]), installs exactly the pinned files and
//!   leaves a [`HelperStatus`] in `<spool>/status.json`.
//!
//! `queue/` belongs to the agent's user, so the helper treats what is in it
//! as untrusted: [`read_untrusted`] refuses links, files with other names
//! and oversized files, and [`write_atomic`] never writes through a link.
//!
//! `http` (feature): the release server client.

#[cfg(feature = "http")]
pub mod http;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use webjet_core::crypto::{self, Bytes32};
use webjet_proto::{self as wp, msg_type as mt};

// ---------------------------------------------------------------- targets and names

/// Every platform a release is built for.
pub const TARGETS: [&str; 5] = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
];

/// The release target of this build, which is also the machine's.
pub fn target() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("x86_64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("aarch64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("x86_64-apple-darwin")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("aarch64-apple-darwin")
    } else if cfg!(all(windows, target_arch = "x86_64")) {
        Some("x86_64-pc-windows-msvc")
    } else {
        None
    }
}

/// The release archive for `target`: a zip on Windows, else a gzipped tar.
pub fn archive_name(tag: &str, target: &str) -> String {
    if target.contains("windows") {
        format!("webjet-{tag}-{target}.zip")
    } else {
        format!("webjet-{tag}-{target}.tar.gz")
    }
}

/// webjetup for `target`, published as a plain executable.
pub fn webjetup_name(tag: &str, target: &str) -> String {
    if target.contains("windows") {
        format!("webjetup-{tag}-{target}.exe")
    } else {
        format!("webjetup-{tag}-{target}")
    }
}

// ---------------------------------------------------------------- versions

/// A release version: `0.9.0`, `v0.9.0`, `0.9.0-rc.1`. Versions order by
/// SemVer precedence: a pre-release sorts before its release, and pre-release
/// labels compare identifier by identifier, numeric ones as numbers
/// (`rc.2` < `rc.10`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Option<String>,
}

impl Version {
    pub fn parse(s: &str) -> Option<Version> {
        let s = s.trim();
        let s = s.strip_prefix('v').unwrap_or(s);
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (s, None),
        };
        let mut parts = core.split('.');
        let mut num = || -> Option<u64> {
            let p = parts.next()?;
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse().ok()
        };
        let (major, minor, patch) = (num()?, num()?, num()?);
        if parts.next().is_some() {
            return None;
        }
        if let Some(p) = pre
            && (p.len() > 32
                || p.split('.')
                    .any(|id| id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric())))
        {
            return None;
        }
        Some(Version {
            major,
            minor,
            patch,
            pre: pre.map(str::to_string),
        })
    }
}

impl Ord for Version {
    fn cmp(&self, o: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(o.major, o.minor, o.patch))
            .then_with(|| match (&self.pre, &o.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => pre_cmp(a, b),
            })
    }
}

/// SemVer §11 precedence of two pre-release labels: identifier by identifier;
/// numeric identifiers compare as numbers and sort before alphanumeric ones;
/// a label that is a prefix of the other sorts first. Labels SemVer would call
/// equal (`rc.01`, `rc.1`) fall back to text so the order agrees with `Eq`.
fn pre_cmp(a: &str, b: &str) -> Ordering {
    fn num(id: &str) -> Option<&str> {
        id.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| id.trim_start_matches('0'))
    }
    let mut ia = a.split('.');
    let mut ib = b.split('.');
    loop {
        let o = match (ia.next(), ib.next()) {
            (None, None) => return a.cmp(b),
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => match (num(x), num(y)) {
                // Digits without leading zeros: the longer one is larger.
                (Some(m), Some(n)) => m.len().cmp(&n.len()).then_with(|| m.cmp(n)),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => x.cmp(y),
            },
        };
        if o != Ordering::Equal {
            return o;
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(p) = &self.pre {
            write!(f, "-{p}")?;
        }
        Ok(())
    }
}

/// `0.2.0` → `v0.2.0`; `latest` stays as it is.
pub fn normalize_version(v: &str) -> String {
    let v = v.trim();
    if v == "latest" || v.starts_with('v') {
        v.to_string()
    } else {
        format!("v{v}")
    }
}

/// A release tag safe to put in file names and URLs: `v` and a [`Version`].
pub fn valid_tag(tag: &str) -> bool {
    tag.starts_with('v') && Version::parse(tag).is_some()
}

/// Whether `to` is a strictly newer version than `from`.
pub fn is_upgrade(from: &str, to: &str) -> Option<bool> {
    Some(Version::parse(to)? > Version::parse(from)?)
}

// ---------------------------------------------------------------- the upgrade spool

/// How long an admin's upgrade request may live (issued_at to expires_at).
pub const MAX_REQUEST_LIFETIME_MS: u64 = 60 * 60 * 1000;
/// How far a request's issued_at may be from the node's clock.
pub const REQUEST_SKEW_MS: u64 = 5 * 60 * 1000;
/// Largest spool file read.
pub const MAX_SPOOL_FILE: u64 = 64 * 1024;

/// The spool directory webjetup creates when it installs the helper; that
/// `queue/` exists in it tells the agent the helper is there.
///
/// The spool itself is root's (the helper's status and backups live in it);
/// only `queue/` belongs to the agent's user. On Linux the agent runs as
/// `webjet` and so must not own anything the helper writes to or reads
/// through: it could swap a directory for a link. That is why the spool is
/// not in the agent's state directory there.
pub fn default_spool_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/Webjet/upgrade")
    } else if cfg!(windows) {
        std::env::var_os("ProgramData")
            .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
            .join("Webjet")
            .join("upgrade")
    } else {
        PathBuf::from("/var/lib/webjet-upgrade")
    }
}

/// Where the agent puts requests; the service manager starts the helper
/// when a request appears here (on Windows a task looks every minute).
pub fn queue_dir(spool: &Path) -> PathBuf {
    spool.join("queue")
}

pub const REQUEST_FILE: &str = "request.json";
pub const STATUS_FILE: &str = "status.json";

pub fn request_path(spool: &Path) -> PathBuf {
    queue_dir(spool).join(REQUEST_FILE)
}

pub fn status_path(spool: &Path) -> PathBuf {
    spool.join(STATUS_FILE)
}

/// What webjetup pins when it installs the helper (as root, from the node's
/// state at that moment) in `<spool>/trust.json`: the network's root key
/// and this node's id. The helper verifies every request against these
/// itself, so an agent whose user was taken over can't make root install
/// anything an admin didn't sign for this node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trust {
    /// Hex.
    pub root_key: String,
    /// Hex.
    pub node_id: String,
    /// The repository the helper downloads from (webjetup's `--repo`).
    pub repo: String,
}

pub const TRUST_FILE: &str = "trust.json";

pub fn trust_path(spool: &Path) -> PathBuf {
    spool.join(TRUST_FILE)
}

impl Trust {
    /// From the node's state as root reads it while installing: `node.json`
    /// (its `node_id`) and the network's genesis file.
    pub fn from_state(node_json: &[u8], genesis: &[u8], repo: &str) -> Result<Trust> {
        let v: serde_json::Value = serde_json::from_slice(node_json).context("node.json")?;
        let id = v
            .get("node_id")
            .and_then(|x| x.as_str())
            .and_then(crypto::parse_hex32)
            .ok_or_else(|| anyhow!("node.json has no node id"))?;
        let (_, root, _) = webjet_core::store::open_genesis(genesis).context("the genesis file")?;
        Ok(Trust {
            root_key: hex::encode(root),
            node_id: hex::encode(id),
            repo: repo.to_string(),
        })
    }

    pub fn root(&self) -> Result<Bytes32> {
        crypto::parse_hex32(&self.root_key).ok_or_else(|| anyhow!("bad root key in trust.json"))
    }
    pub fn node(&self) -> Result<Bytes32> {
        crypto::parse_hex32(&self.node_id).ok_or_else(|| anyhow!("bad node id in trust.json"))
    }
}

/// What the agent puts in the queue: the admin's signed request and that
/// admin's root-signed AccountRecord (from the agent's tree), both as they
/// were signed (base64). The helper checks both itself ([`plan`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedRequest {
    pub request: String,
    pub account: String,
}

impl QueuedRequest {
    pub fn new(request: &[u8], account: &[u8]) -> QueuedRequest {
        QueuedRequest {
            request: b64(request),
            account: b64(account),
        }
    }
    pub fn decode(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        Ok((unb64(&self.request)?, unb64(&self.account)?))
    }
}

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

/// One release file and the SHA-256 the admin pinned for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedFile {
    pub name: String,
    /// Lowercase hex.
    pub sha256: String,
}

/// A checked request: what to install on this machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// The request's nonce (hex): one request is used once.
    pub id: String,
    /// The admin account that signed it (hex) and its name.
    pub account_id: String,
    pub account_name: String,
    /// Release tag, e.g. `v0.9.0`.
    pub version: String,
    /// Milliseconds since the Unix epoch.
    pub expires_at: u64,
    pub archive: PinnedFile,
    pub webjetup: PinnedFile,
}

/// Check a signed `UpgradeRequest` and the signer's `AccountRecord` against
/// the network's `root` key, for node `me` on `target` running `installed`,
/// at `now` (ms): the record is a root-signed admin's, the request is signed
/// with that admin's key, names `me`, is recent and short-lived, and asks
/// for a newer release whose files for `target` it pins.
///
/// This doesn't know whether the admin was revoked since (the agent checks
/// that against its tree as well); a revoked admin's key would also need
/// files with the pinned checksums on the release server to do anything.
pub fn plan(
    request: &[u8],
    account: &[u8],
    root: &Bytes32,
    me: &Bytes32,
    target: &str,
    installed: Option<&str>,
    now: u64,
) -> Result<Plan> {
    let rec: wp::AccountRecord = crypto::open_expect(account, mt::ACCOUNT_RECORD, &[*root])
        .context("the admin's account record")?
        .decode()?;
    if !rec.admin || !rec.issuer_root {
        bail!("the request's signer is not an admin");
    }
    let key = crypto::opt_k32(&rec.account_key);
    let req: wp::UpgradeRequest = crypto::open_expect(request, mt::UPGRADE_REQUEST, &[key])
        .context("the upgrade request")?
        .decode()?;
    if req.account_id != rec.account_id {
        bail!("the request names another account");
    }
    if req.node_id.is_none() || crypto::opt_k32(&req.node_id) != *me {
        bail!("the request is for another node");
    }
    let Some(nonce) = &req.nonce else {
        bail!("the request has no nonce");
    };
    if now >= req.expires_at {
        bail!("the request expired");
    }
    if req.issued_at.abs_diff(now) > REQUEST_SKEW_MS {
        bail!("the request's time is too far from this machine's clock; check the clocks");
    }
    if req.expires_at.saturating_sub(req.issued_at) > MAX_REQUEST_LIFETIME_MS {
        bail!("the request is valid for too long (at most an hour)");
    }
    let version = req.version.clone().unwrap_or_default();
    if !valid_tag(&version) {
        bail!("bad version {version:?}");
    }
    let installed = installed.ok_or_else(|| anyhow!("can't tell the installed version"))?;
    match is_upgrade(installed, &version) {
        Some(true) => {}
        Some(false) => bail!(
            "{version} is not newer than the installed {installed}; remote upgrades never downgrade"
        ),
        None => bail!("can't compare the installed {installed} with {version}"),
    }
    let pinned = |name: String| -> Result<PinnedFile> {
        let sum = req
            .files
            .iter()
            .flatten()
            .find(|f| f.name.as_deref() == Some(name.as_str()))
            .and_then(|f| f.sha256)
            .ok_or_else(|| anyhow!("the request pins no {name} (this machine is {target})"))?;
        Ok(PinnedFile {
            name,
            sha256: hex::encode(crypto::opt_k32(&Some(sum))),
        })
    };
    Ok(Plan {
        id: hex::encode(nonce.to_bytes()),
        account_id: hex::encode(crypto::opt_k32(&rec.account_id)),
        account_name: rec.name.clone().unwrap_or_default(),
        archive: pinned(archive_name(&version, target))?,
        webjetup: pinned(webjetup_name(&version, target))?,
        version,
        expires_at: req.expires_at,
    })
}

/// Where an upgrade stands, as the helper last wrote it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeState {
    /// Taken; downloading or installing.
    Running,
    /// The new version runs and is healthy.
    Done,
    /// The request was not acceptable; nothing changed.
    Refused,
    /// Failed before anything was replaced (download, checksum).
    Failed,
    /// The new version didn't come up healthy; the previous one was put back.
    RolledBack,
    /// Putting the previous version back failed too: the node needs a person.
    RollbackFailed,
}

impl UpgradeState {
    /// Whether the helper is finished with the request.
    pub fn finished(self) -> bool {
        self != UpgradeState::Running
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperStatus {
    /// The request's id ([`Plan::id`]); empty when it couldn't be read.
    pub id: String,
    pub version: String,
    /// The version installed before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    pub state: UpgradeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Milliseconds since the Unix epoch.
    pub at: u64,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Read a spool file someone else controls: no symbolic links, a regular
/// file with one name, at most [`MAX_SPOOL_FILE`] bytes. `None` if absent.
pub fn read_untrusted(path: &Path) -> Result<Option<Vec<u8>>> {
    use std::io::Read;
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
        Ok(m) if !m.file_type().is_file() => bail!("{} is not a plain file", path.display()),
        Ok(_) => {}
    }
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let f = o
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let m = f.metadata()?;
    if !m.is_file() {
        bail!("{} is not a plain file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.nlink() != 1 {
            bail!("{} has more than one name", path.display());
        }
    }
    if m.len() > MAX_SPOOL_FILE {
        bail!("{} is too large", path.display());
    }
    let mut buf = Vec::new();
    f.take(MAX_SPOOL_FILE + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_SPOOL_FILE {
        bail!("{} is too large", path.display());
    }
    Ok(Some(buf))
}

/// Replace `dir/name` with `bytes` in one step: write a new file (never an
/// existing one, so never through a planted link), then rename it over.
pub fn write_atomic(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = dir.join(format!(
        ".{name}.{}.{}.{}.tmp",
        std::process::id(),
        now_ms(),
        SEQ.fetch_add(1, Relaxed)
    ));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let res = (|| -> Result<()> {
        let mut f = o
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, dir.join(name))
            .with_context(|| format!("replace {}", dir.join(name).display()))
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Read and parse the helper's status.
pub fn read_status(spool: &Path) -> Result<Option<HelperStatus>> {
    match read_untrusted(&status_path(spool))? {
        None => Ok(None),
        Some(b) => Ok(Some(
            serde_json::from_slice(&b).context("the upgrade status")?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webjet_core::crypto::KeyPair;

    #[test]
    fn versions_order() {
        let v = |s| Version::parse(s).unwrap();
        assert!(v("0.9.0") > v("0.8.9"));
        assert!(v("v1.0.0") > v("0.99.99"));
        assert!(v("0.9.0") > v("0.9.0-rc.1"));
        assert!(v("0.9.0-rc.2") > v("0.9.0-rc.1"));
        // SemVer §11: numeric identifiers compare as numbers.
        assert!(v("0.9.0-rc.10") > v("0.9.0-rc.2"));
        assert!(v("0.9.0-rc.100000000000000000000") > v("0.9.0-rc.99"));
        assert!(v("0.9.0-alpha") < v("0.9.0-alpha.1"));
        assert!(v("0.9.0-alpha.1") < v("0.9.0-alpha.beta"));
        assert!(v("0.9.0-alpha.beta") < v("0.9.0-beta"));
        assert!(v("0.9.0-beta.11") < v("0.9.0-rc.1"));
        assert!(v("0.9.0-1") < v("0.9.0-a"));
        assert_eq!(is_upgrade("0.9.0-rc.10", "v0.9.0-rc.2"), Some(false));
        // Order agrees with Eq.
        assert!(v("0.9.0-rc.01") != v("0.9.0-rc.1"));
        assert_ne!(v("0.9.0-rc.01").cmp(&v("0.9.0-rc.1")), Ordering::Equal);
        assert_eq!(v("v0.9.0"), v("0.9.0"));
        assert_eq!(v("0.10.0").to_string(), "0.10.0");
        assert_eq!(v("0.9.0-rc.1").to_string(), "0.9.0-rc.1");
        for bad in [
            "",
            "v",
            "0.9",
            "0.9.0.1",
            "a.b.c",
            "0.9.0-",
            "0.9.0-x/y",
            "0.9.0-rc..1",
            "0.9.0-.rc",
            "0.9.0-rc.",
            "0.9.-1",
            "v0.9.0 x",
        ] {
            assert!(Version::parse(bad).is_none(), "{bad:?}");
        }
        assert!(valid_tag("v0.9.0") && valid_tag("v0.9.0-rc.1"));
        assert!(!valid_tag("0.9.0") && !valid_tag("v0.9.0/../x") && !valid_tag("latest"));
        assert_eq!(is_upgrade("0.8.0", "v0.9.0"), Some(true));
        assert_eq!(is_upgrade("0.9.0", "v0.9.0"), Some(false));
        assert_eq!(is_upgrade("0.9.1", "v0.9.0"), Some(false));
        assert_eq!(is_upgrade("dev", "v0.9.0"), None);
    }

    #[test]
    fn names() {
        assert_eq!(
            archive_name("v0.2.0", "aarch64-apple-darwin"),
            "webjet-v0.2.0-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(
            archive_name("v0.2.0", "x86_64-pc-windows-msvc"),
            "webjet-v0.2.0-x86_64-pc-windows-msvc.zip"
        );
        assert_eq!(
            webjetup_name("v0.9.0", "x86_64-unknown-linux-gnu"),
            "webjetup-v0.9.0-x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            webjetup_name("v0.9.0", "x86_64-pc-windows-msvc"),
            "webjetup-v0.9.0-x86_64-pc-windows-msvc.exe"
        );
        let t = target().expect("release targets cover the test platforms");
        assert!(TARGETS.contains(&t));
    }

    const T: &str = "x86_64-unknown-linux-gnu";
    const NOW: u64 = 1_800_000_000_000;

    struct Net {
        root: KeyPair,
        admin: KeyPair,
        admin_id: Bytes32,
        node: Bytes32,
    }

    fn net() -> Net {
        Net {
            root: KeyPair::generate(),
            admin: KeyPair::generate(),
            admin_id: [3; 32],
            node: [5; 32],
        }
    }

    fn account(net: &Net, signer: &KeyPair, admin: bool) -> Vec<u8> {
        signer.sign_obj(
            mt::ACCOUNT_RECORD,
            &wp::AccountRecord {
                account_id: Some(crypto::k32(&net.admin_id)),
                account_key: Some(crypto::k32(&net.admin.public())),
                name: Some("alice".into()),
                admin,
                issuer_root: true,
                issuer: None,
                version: 1,
            },
        )
    }

    fn files(version: &str) -> Vec<wp::UpgradeFile> {
        TARGETS
            .iter()
            .flat_map(|t| [archive_name(version, t), webjetup_name(version, t)])
            .enumerate()
            .map(|(i, name)| wp::UpgradeFile {
                name: Some(name),
                sha256: Some(crypto::k32(&[i as u8; 32])),
            })
            .collect()
    }

    fn request_with(signer: &KeyPair, f: impl FnOnce(&mut wp::UpgradeRequest)) -> Vec<u8> {
        let mut r = wp::UpgradeRequest {
            account_id: Some(crypto::k32(&[3; 32])),
            node_id: Some(crypto::k32(&[5; 32])),
            nonce: Some(wp::Id16::from_bytes(&[7; 16])),
            issued_at: NOW,
            expires_at: NOW + 30 * 60 * 1000,
            version: Some("v0.9.0".into()),
            files: Some(files("v0.9.0")),
        };
        f(&mut r);
        signer.sign_obj(mt::UPGRADE_REQUEST, &r)
    }

    #[test]
    fn the_helper_checks_requests_itself() {
        let n = net();
        let acct = account(&n, &n.root, true);
        let ok = request_with(&n.admin, |_| {});
        let p = plan(&ok, &acct, &n.root.public(), &n.node, T, Some("0.8.0"), NOW).unwrap();
        assert_eq!(p.id, "07".repeat(16));
        assert_eq!(p.account_id, "03".repeat(32));
        assert_eq!(p.account_name, "alice");
        assert_eq!(p.version, "v0.9.0");
        assert_eq!(p.archive.name, archive_name("v0.9.0", T));
        assert_eq!(p.webjetup.name, webjetup_name("v0.9.0", T));
        // Each target gets its own pinned files.
        let mac = plan(
            &ok,
            &acct,
            &n.root.public(),
            &n.node,
            "aarch64-apple-darwin",
            Some("0.8.0"),
            NOW,
        )
        .unwrap();
        assert_ne!(mac.archive.sha256, p.archive.sha256);

        let err = |req: &[u8], acct: &[u8], me: &Bytes32, installed: Option<&str>, now: u64| {
            format!(
                "{:#}",
                plan(req, acct, &n.root.public(), me, T, installed, now).unwrap_err()
            )
        };
        let me = n.node;
        // The account record must be the root's, and an admin's.
        let other = KeyPair::generate();
        assert!(
            err(&ok, &account(&n, &other, true), &me, Some("0.8.0"), NOW)
                .contains("account record")
        );
        assert!(
            err(&ok, &account(&n, &n.root, false), &me, Some("0.8.0"), NOW)
                .contains("not an admin")
        );
        // The request must be signed with that admin's key, for its account.
        assert!(
            err(
                &request_with(&other, |_| {}),
                &acct,
                &me,
                Some("0.8.0"),
                NOW
            )
            .contains("upgrade request")
        );
        let r = request_with(&n.admin, |r| r.account_id = Some(crypto::k32(&[4; 32])));
        assert!(err(&r, &acct, &me, Some("0.8.0"), NOW).contains("another account"));
        // For this node.
        assert!(err(&ok, &acct, &[6; 32], Some("0.8.0"), NOW).contains("another node"));
        // In time, briefly.
        assert!(err(&ok, &acct, &me, Some("0.8.0"), NOW + 30 * 60 * 1000).contains("expired"));
        assert!(err(&ok, &acct, &me, Some("0.8.0"), NOW - 10 * 60 * 1000).contains("too far"));
        let r = request_with(&n.admin, |r| r.expires_at = NOW + 2 * 60 * 60 * 1000);
        assert!(err(&r, &acct, &me, Some("0.8.0"), NOW).contains("too long"));
        // Newer releases only.
        assert!(err(&ok, &acct, &me, Some("0.9.0"), NOW).contains("never downgrade"));
        assert!(err(&ok, &acct, &me, Some("1.0.0"), NOW).contains("never downgrade"));
        assert!(err(&ok, &acct, &me, None, NOW).contains("installed version"));
        // A version that isn't a release tag (it ends up in paths and URLs).
        let r = request_with(&n.admin, |r| r.version = Some("v0.9.0/../../x".into()));
        assert!(err(&r, &acct, &me, Some("0.8.0"), NOW).contains("bad version"));
        // Nothing pinned for this platform.
        let r = request_with(&n.admin, |r| r.files = Some(vec![]));
        assert!(err(&r, &acct, &me, Some("0.8.0"), NOW).contains("pins no"));
        let r = request_with(&n.admin, |r| r.nonce = None);
        assert!(err(&r, &acct, &me, Some("0.8.0"), NOW).contains("nonce"));
        // Envelopes of other types.
        assert!(err(&acct, &acct, &me, Some("0.8.0"), NOW).contains("upgrade request"));
        assert!(err(&ok, &ok, &me, Some("0.8.0"), NOW).contains("account record"));
    }

    #[test]
    fn queued_requests_round_trip() {
        let q = QueuedRequest::new(b"req", b"acct");
        let j = serde_json::to_string(&q).unwrap();
        let back: QueuedRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(back.decode().unwrap(), (b"req".to_vec(), b"acct".to_vec()));
        let t = Trust {
            root_key: "ab".repeat(32),
            node_id: "zz".into(),
            repo: String::new(),
        };
        assert_eq!(t.root().unwrap(), [0xab; 32]);
        assert!(t.node().is_err());
    }

    #[test]
    fn trust_comes_from_the_node_state() {
        let net = webjet_core::testutil::net();
        let node =
            br#"{"node_id": "0505050505050505050505050505050505050505050505050505050505050505"}"#;
        let t = Trust::from_state(node, &net.genesis, "https://r/o/w").unwrap();
        assert_eq!(t.root().unwrap(), net.root.public());
        assert_eq!(t.node().unwrap(), [5; 32]);
        assert_eq!(t.repo, "https://r/o/w");
        assert!(Trust::from_state(b"{}", &net.genesis, "").is_err());
        assert!(Trust::from_state(node, b"junk", "").is_err());
    }

    #[test]
    fn spool_files_are_read_carefully() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f.json");
        assert!(read_untrusted(&p).unwrap().is_none());
        write_atomic(d.path(), "f.json", b"{}", 0o600).unwrap();
        assert_eq!(read_untrusted(&p).unwrap().unwrap(), b"{}");
        write_atomic(d.path(), "f.json", b"[1]", 0o600).unwrap();
        assert_eq!(read_untrusted(&p).unwrap().unwrap(), b"[1]");
        // No temporary files are left.
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
        std::fs::write(&p, vec![b' '; MAX_SPOOL_FILE as usize + 1]).unwrap();
        assert!(read_untrusted(&p).is_err());
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        assert!(read_untrusted(&p).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn links_are_never_followed() {
        let d = tempfile::tempdir().unwrap();
        let secret = d.path().join("secret");
        std::fs::write(&secret, b"s").unwrap();
        let link = d.path().join("status.json");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert!(read_untrusted(&link).is_err(), "symbolic link read");
        // Writing replaces the link itself, not what it points at.
        write_atomic(d.path(), "status.json", b"new", 0o644).unwrap();
        assert_eq!(std::fs::read(&secret).unwrap(), b"s");
        assert!(
            !std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let hard = d.path().join("hard");
        std::fs::hard_link(&secret, &hard).unwrap();
        assert!(read_untrusted(&hard).is_err(), "a file with two names");
    }

    #[test]
    fn status_round_trip() {
        let s = HelperStatus {
            id: "x".into(),
            version: "v0.9.0".into(),
            from: Some("0.8.0".into()),
            state: UpgradeState::RolledBack,
            error: Some("unhealthy".into()),
            at: 5,
        };
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("\"rolled_back\""), "{j}");
        assert_eq!(serde_json::from_str::<HelperStatus>(&j).unwrap(), s);
        assert!(UpgradeState::Done.finished() && !UpgradeState::Running.finished());
    }
}
