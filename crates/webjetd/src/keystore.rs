//! Identity key storage at rest (§8.3).
//!
//! The identity key is Ed25519, which TPMs, the Secure Enclave and
//! TPM-backed Windows keys can't sign with. So the 32-byte seed is
//! protected at rest by a platform mechanism and decrypted into the agent's
//! memory at start-up:
//!
//! | backend    | where                         | protection                                  |
//! |------------|-------------------------------|---------------------------------------------|
//! | `tpm`      | Linux with a TPM 2.0          | sealed to the TPM's storage hierarchy       |
//! | `keychain` | macOS                         | System keychain item (device's SystemKey)   |
//! | `dpapi`    | Windows                       | DPAPI, machine scope, plus a private ACL    |
//! | `file`     | anywhere                      | file readable only by the agent's user      |
//!
//! `auto` picks TPM where one is usable on Linux, the Keychain on macOS and
//! DPAPI on Windows, else `file`. Sealed keys are device-bound: copying
//! `identity.key` to another machine (or restoring a backup there) fails,
//! and that machine is re-keyed instead (§8.1).
//!
//! `identity.key` format: `WJK2 || backend || payload`. A bare 32-byte file
//! is a plain key from an older version (still read).
//!
//! In memory the key lives in a locked (non-swappable) page and is zeroed
//! on drop; the process also opts out of core dumps.

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use webjet_core::crypto::{Bytes32, KeyPair};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"WJK2";
const TAG_FILE: u8 = 1;
const TAG_TPM: u8 = 2;
const TAG_KEYCHAIN: u8 = 3;
const TAG_DPAPI: u8 = 4;
/// Binds sealed blobs to their purpose.
#[cfg_attr(not(windows), allow(dead_code))]
const CONTEXT: &[u8] = b"webjet identity key v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    #[default]
    Auto,
    File,
    Tpm,
    Keychain,
    Dpapi,
}

/// `[key]` in webjetd.toml.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyCfg {
    #[serde(default)]
    pub storage: Backend,
    /// macOS: keychain file to use (default: the System keychain).
    pub keychain: Option<PathBuf>,
}

impl Backend {
    pub fn name(&self) -> &'static str {
        match self {
            Backend::Auto => "auto",
            Backend::File => "file",
            Backend::Tpm => "tpm",
            Backend::Keychain => "keychain",
            Backend::Dpapi => "dpapi",
        }
    }

    /// Resolve `auto` for this machine.
    pub fn resolve(self) -> Backend {
        match self {
            Backend::Auto => {
                if cfg!(target_os = "macos") {
                    Backend::Keychain
                } else if cfg!(windows) {
                    Backend::Dpapi
                } else if cfg!(target_os = "linux") && tpm::available() {
                    Backend::Tpm
                } else {
                    Backend::File
                }
            }
            b => b,
        }
    }
}

/// What `webjetd key show` reports.
#[derive(Debug, Clone)]
pub struct Info {
    pub backend: Backend,
    pub public: Bytes32,
}

/// Seal `seed` with the configured backend and write `path`. With `auto`,
/// a platform store that can't be used (no TPM access, no root for the
/// System keychain) falls back to `file` with a warning; an explicitly
/// configured backend must work.
pub fn save(path: &Path, cfg: &KeyCfg, account: &str, seed: &Bytes32) -> Result<Backend> {
    match save_with(path, cfg, cfg.storage.resolve(), account, seed) {
        Err(e) if cfg.storage == Backend::Auto && cfg.storage.resolve() != Backend::File => {
            tracing::warn!("{e:#}; storing the identity key in a private file instead");
            eprintln!("warning: {e:#}; storing the identity key in a private file instead");
            save_with(path, cfg, Backend::File, account, seed)
        }
        r => r,
    }
}

/// The Keychain item name for a data directory (one per agent instance).
pub fn account_for(data_dir: &Path) -> String {
    let h = webjet_core::crypto::hash(data_dir.to_string_lossy().as_bytes());
    format!("identity-{}", hex::encode(&h[..8]))
}

fn save_with(
    path: &Path,
    cfg: &KeyCfg,
    backend: Backend,
    account: &str,
    seed: &Bytes32,
) -> Result<Backend> {
    // A previous key held in the keychain is removed when replaced.
    discard(path, cfg);
    let payload: Vec<u8> = match backend {
        Backend::File => seed.to_vec(),
        Backend::Tpm => tpm::seal(seed)?,
        Backend::Keychain => keychain::store(cfg.keychain.as_deref(), account, seed)?,
        Backend::Dpapi => dpapi::protect(seed)?,
        Backend::Auto => unreachable!(),
    };
    let tag = match backend {
        Backend::File => TAG_FILE,
        Backend::Tpm => TAG_TPM,
        Backend::Keychain => TAG_KEYCHAIN,
        Backend::Dpapi => TAG_DPAPI,
        Backend::Auto => unreachable!(),
    };
    let mut out = MAGIC.to_vec();
    out.push(tag);
    out.extend_from_slice(&payload);
    crate::state::write_private(path, &out)?;
    Ok(backend)
}

/// Read and unseal the key at `path`.
pub fn load(path: &Path, cfg: &KeyCfg) -> Result<Option<(KeyPair, Backend)>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        Zeroizing::new(std::fs::read(path).with_context(|| format!("read {}", path.display()))?);
    let (seed, backend) = unseal(&raw, cfg).map_err(|e| anyhow!("{e:#}\nThe identity key can't be used on this machine. If it was copied or restored from another machine, re-key this node (§8.1): ask an admin for `webjetctl node rekey` and run `webjetd enroll` with the new string."))?;
    Ok(Some((KeyPair::from_seed(&seed), backend)))
}

fn unseal(raw: &[u8], cfg: &KeyCfg) -> Result<(Zeroizing<Bytes32>, Backend)> {
    if raw.len() == 32 {
        let mut s = Zeroizing::new([0u8; 32]);
        s.copy_from_slice(raw);
        return Ok((s, Backend::File));
    }
    if raw.len() < 5 || &raw[..4] != MAGIC {
        bail!("unrecognized identity key file");
    }
    let payload = &raw[5..];
    let (seed, b) = match raw[4] {
        TAG_FILE => (Zeroizing::new(payload.to_vec()), Backend::File),
        TAG_TPM => (tpm::unseal(payload)?, Backend::Tpm),
        TAG_KEYCHAIN => (
            keychain::load(cfg.keychain.as_deref(), payload)?,
            Backend::Keychain,
        ),
        TAG_DPAPI => (dpapi::unprotect(payload)?, Backend::Dpapi),
        t => bail!("unknown key storage {t}"),
    };
    if seed.len() != 32 {
        bail!("sealed identity key has the wrong length");
    }
    let mut s = Zeroizing::new([0u8; 32]);
    s.copy_from_slice(&seed);
    Ok((s, b))
}

/// Remove external material (Keychain items) for a key file being replaced.
pub fn discard(path: &Path, cfg: &KeyCfg) {
    if let Ok(raw) = std::fs::read(path)
        && raw.len() > 5
        && &raw[..4] == MAGIC
        && raw[4] == TAG_KEYCHAIN
    {
        keychain::delete(cfg.keychain.as_deref(), &raw[5..]);
    }
}

// ---------------------------------------------------------------- process hardening

/// Keep secrets out of core dumps and swap (§8.3).
pub fn harden_process() {
    #[cfg(unix)]
    unsafe {
        let r = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &r);
    }
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// Lock the key's memory so it is never swapped out. The key must not
/// move afterwards (it lives inside the agent's `Arc<Node>`).
pub fn lock_in_place(kp: &KeyPair) {
    lock_memory(
        kp as *const KeyPair as *const u8,
        std::mem::size_of::<KeyPair>(),
    );
}

fn lock_memory(p: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        if libc::mlock(p as *const libc::c_void, len) != 0 {
            tracing::debug!("mlock failed; the identity key may be swapped");
        }
    }
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Memory::VirtualLock(p as *const core::ffi::c_void, len);
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (p, len);
}

#[allow(dead_code)]
fn unlock_memory(p: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        libc::munlock(p as *const libc::c_void, len);
    }
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Memory::VirtualUnlock(p as *const core::ffi::c_void, len);
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (p, len);
}

// ---------------------------------------------------------------- TPM 2.0 (Linux)

/// Sealing through the TPM's storage hierarchy with tpm2-tools: the seed
/// becomes a sealed data object under a primary key derived from the TPM's
/// owner seed, so only this TPM can load it. `TPM2TOOLS_TCTI` selects the
/// device (default: the kernel resource manager).
pub mod tpm {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    pub fn available() -> bool {
        let dev = std::path::Path::new("/dev/tpmrm0").exists()
            || std::env::var_os("TPM2TOOLS_TCTI").is_some();
        dev && Command::new("tpm2_getcap")
            .arg("properties-fixed")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Unload transient objects. The kernel resource manager (/dev/tpmrm0)
    /// does this when a client closes, but a TPM reached directly (or a
    /// software TPM) keeps them until flushed and runs out of slots.
    fn flush_transient() {
        let _ = Command::new("tpm2_flushcontext")
            .arg("-t")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    /// Flushes transient objects when an operation ends, even on error.
    struct Session;
    impl Session {
        fn begin() -> Session {
            flush_transient();
            Session
        }
    }
    impl Drop for Session {
        fn drop(&mut self) {
            flush_transient();
        }
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Result<TempDir> {
            let d = std::env::temp_dir().join(format!(
                "webjet-tpm-{}",
                hex::encode(webjet_core::crypto::random16())
            ));
            std::fs::create_dir(&d)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
            }
            Ok(TempDir(d))
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn run(args: &[&str], dir: &Path, input: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut c = Command::new(args[0]);
        c.args(&args[1..])
            .current_dir(dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if input.is_some() {
            c.stdin(Stdio::piped());
        }
        let mut child = c
            .spawn()
            .with_context(|| format!("{} (install tpm2-tools)", args[0]))?;
        if let Some(i) = input
            && let Some(mut stdin) = child.stdin.take()
        {
            stdin.write_all(i)?;
        }
        let o = child.wait_with_output()?;
        if !o.status.success() {
            bail!(
                "{} failed: {}",
                args[0],
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        Ok(o.stdout)
    }

    fn primary(dir: &Path) -> Result<()> {
        // Same template every time: the TPM re-derives the same primary key.
        run(
            &[
                "tpm2_createprimary",
                "-Q",
                "-C",
                "o",
                "-g",
                "sha256",
                "-G",
                "ecc256:aes128cfb",
                "-c",
                "primary.ctx",
            ],
            dir,
            None,
        )?;
        // Each tool saves its objects as context files; without a resource
        // manager they also stay loaded, and the TPM has only a few slots.
        flush_transient();
        Ok(())
    }

    pub fn seal(seed: &Bytes32) -> Result<Vec<u8>> {
        let _s = Session::begin();
        let t = TempDir::new()?;
        primary(&t.0)?;
        run(
            &[
                "tpm2_create",
                "-Q",
                "-C",
                "primary.ctx",
                "-g",
                "sha256",
                "-a",
                "fixedtpm|fixedparent|userwithauth|noda",
                "-i",
                "-",
                "-u",
                "seal.pub",
                "-r",
                "seal.priv",
            ],
            &t.0,
            Some(&seed[..]),
        )?;
        let pubb = std::fs::read(t.0.join("seal.pub"))?;
        let privb = std::fs::read(t.0.join("seal.priv"))?;
        let mut out = Vec::new();
        out.extend_from_slice(&(pubb.len() as u16).to_be_bytes());
        out.extend_from_slice(&pubb);
        out.extend_from_slice(&privb);
        Ok(out)
    }

    pub fn unseal(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if blob.len() < 2 {
            bail!("bad TPM blob");
        }
        let n = u16::from_be_bytes([blob[0], blob[1]]) as usize;
        let pubb = blob.get(2..2 + n).ok_or_else(|| anyhow!("bad TPM blob"))?;
        let privb = &blob[2 + n..];
        let _s = Session::begin();
        let t = TempDir::new()?;
        std::fs::write(t.0.join("seal.pub"), pubb)?;
        std::fs::write(t.0.join("seal.priv"), privb)?;
        primary(&t.0)?;
        run(
            &[
                "tpm2_load",
                "-Q",
                "-C",
                "primary.ctx",
                "-u",
                "seal.pub",
                "-r",
                "seal.priv",
                "-c",
                "seal.ctx",
            ],
            &t.0,
            None,
        )
        .context("this key was sealed by a different TPM")?;
        flush_transient();
        let out = Zeroizing::new(run(&["tpm2_unseal", "-c", "seal.ctx"], &t.0, None)?);
        Ok(out)
    }
}

// ---------------------------------------------------------------- macOS Keychain

pub mod keychain {
    use super::*;

    pub const SERVICE: &str = "net.webjet.identity";
    pub const SYSTEM: &str = "/Library/Keychains/System.keychain";

    #[cfg(target_os = "macos")]
    fn open(path: Option<&Path>) -> Result<security_framework::os::macos::keychain::SecKeychain> {
        let p = path
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(SYSTEM));
        security_framework::os::macos::keychain::SecKeychain::open(&p)
            .map_err(|e| anyhow!("open keychain {}: {e}", p.display()))
    }

    /// Store the seed as a generic password; the payload is the account name.
    #[cfg(target_os = "macos")]
    pub fn store(path: Option<&Path>, account: &str, seed: &Bytes32) -> Result<Vec<u8>> {
        let kc = open(path)?;
        if let Ok((_, item)) = kc.find_generic_password(SERVICE, account) {
            item.delete();
        }
        kc.set_generic_password(SERVICE, account, &seed[..])
            .map_err(|e| anyhow!("store identity key in the keychain: {e}"))?;
        Ok(account.as_bytes().to_vec())
    }

    #[cfg(target_os = "macos")]
    pub fn load(path: Option<&Path>, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let account = std::str::from_utf8(payload)?;
        let kc = open(path)?;
        let (pw, _) = kc
            .find_generic_password(SERVICE, account)
            .map_err(|e| anyhow!("identity key not in this machine's keychain: {e}"))?;
        Ok(Zeroizing::new(pw.as_ref().to_vec()))
    }

    #[cfg(target_os = "macos")]
    pub fn delete(path: Option<&Path>, payload: &[u8]) {
        if let (Ok(account), Ok(kc)) = (std::str::from_utf8(payload), open(path))
            && let Ok((_, item)) = kc.find_generic_password(SERVICE, account)
        {
            item.delete();
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn store(_: Option<&Path>, _: &str, _: &Bytes32) -> Result<Vec<u8>> {
        bail!("the keychain backend exists only on macOS")
    }
    #[cfg(not(target_os = "macos"))]
    pub fn load(_: Option<&Path>, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        bail!("this identity key is stored in a macOS keychain")
    }
    #[cfg(not(target_os = "macos"))]
    pub fn delete(_: Option<&Path>, _: &[u8]) {}
}

// ---------------------------------------------------------------- Windows DPAPI

pub mod dpapi {
    use super::*;

    #[cfg(windows)]
    mod imp {
        use super::*;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
            CryptProtectData, CryptUnprotectData,
        };

        fn blob(b: &[u8]) -> CRYPT_INTEGER_BLOB {
            CRYPT_INTEGER_BLOB {
                cbData: b.len() as u32,
                pbData: b.as_ptr() as *mut u8,
            }
        }

        fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
            let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
            unsafe { LocalFree(out.pbData as _) };
            v
        }

        pub fn protect(data: &[u8], machine: bool) -> Result<Vec<u8>> {
            let input = blob(data);
            let entropy = blob(CONTEXT);
            let mut out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            let flags = CRYPTPROTECT_UI_FORBIDDEN
                | if machine {
                    CRYPTPROTECT_LOCAL_MACHINE
                } else {
                    0
                };
            let ok = unsafe {
                CryptProtectData(
                    &input,
                    std::ptr::null(),
                    &entropy,
                    std::ptr::null(),
                    std::ptr::null(),
                    flags,
                    &mut out,
                )
            };
            if ok == 0 {
                bail!(
                    "CryptProtectData failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            Ok(take(out))
        }

        pub fn unprotect(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            let input = blob(data);
            let entropy = blob(CONTEXT);
            let mut out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            let ok = unsafe {
                CryptUnprotectData(
                    &input,
                    std::ptr::null_mut(),
                    &entropy,
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            };
            if ok == 0 {
                bail!(
                    "CryptUnprotectData failed (sealed on another machine?): {}",
                    std::io::Error::last_os_error()
                );
            }
            let v = take(out);
            Ok(Zeroizing::new(v))
        }
    }

    /// Machine-scope DPAPI (the agent is a LocalSystem service, §19.1).
    #[cfg(windows)]
    pub fn protect(seed: &Bytes32) -> Result<Vec<u8>> {
        imp::protect(&seed[..], true)
    }
    #[cfg(windows)]
    pub fn unprotect(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        imp::unprotect(blob)
    }

    #[cfg(not(windows))]
    pub fn protect(_: &Bytes32) -> Result<Vec<u8>> {
        bail!("DPAPI exists only on Windows")
    }
    #[cfg(not(windows))]
    pub fn unprotect(_: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        bail!("this identity key is protected with Windows DPAPI")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!(
            "webjet-ks-{}",
            hex::encode(webjet_core::crypto::random16())
        ))
    }

    #[test]
    fn file_backend_roundtrip_and_legacy() {
        let d = tmp();
        let p = d.join("identity.key");
        let kp = KeyPair::generate();
        let cfg = KeyCfg {
            storage: Backend::File,
            keychain: None,
        };
        assert_eq!(save(&p, &cfg, "n", &kp.seed()).unwrap(), Backend::File);
        let (k2, b) = load(&p, &cfg).unwrap().unwrap();
        assert_eq!((k2.public(), b), (kp.public(), Backend::File));
        // A bare 32-byte key from an older version still loads.
        std::fs::write(&p, &kp.seed()[..]).unwrap();
        assert_eq!(load(&p, &cfg).unwrap().unwrap().0.public(), kp.public());
        // Garbage is refused with a re-key hint.
        std::fs::write(&p, b"WJK2\x09xx").unwrap();
        let e = load(&p, &cfg).err().unwrap().to_string();
        assert!(e.contains("re-key"), "{e}");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn wrong_platform_backend_is_refused() {
        let d = tmp();
        let p = d.join("identity.key");
        std::fs::create_dir_all(&d).unwrap();
        let mut f = MAGIC.to_vec();
        #[cfg(windows)]
        f.push(TAG_KEYCHAIN);
        #[cfg(not(windows))]
        f.push(TAG_DPAPI);
        f.extend_from_slice(b"blob");
        std::fs::write(&p, f).unwrap();
        assert!(load(&p, &KeyCfg::default()).is_err());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn locked_key_works() {
        harden_process();
        let kp = Box::new(KeyPair::generate());
        let pk = kp.public();
        lock_in_place(&kp);
        assert_eq!(kp.public(), pk);
    }

    /// Runs against a temporary keychain (no root needed).
    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_roundtrip() {
        use security_framework::os::macos::keychain::CreateOptions;
        let d = tmp();
        std::fs::create_dir_all(&d).unwrap();
        let kcp = d.join("test.keychain");
        let mut kc = CreateOptions::new().password("pw").create(&kcp).unwrap();
        kc.unlock(Some("pw")).unwrap();
        let cfg = KeyCfg {
            storage: Backend::Keychain,
            keychain: Some(kcp.clone()),
        };
        let p = d.join("identity.key");
        let kp = KeyPair::generate();
        save(&p, &cfg, "node-under-test", &kp.seed()).unwrap();
        // The file holds no key material, only the item's name.
        let raw = std::fs::read(&p).unwrap();
        assert!(!raw.windows(32).any(|w| w == &kp.seed()[..]));
        let (k2, b) = load(&p, &cfg).unwrap().unwrap();
        assert_eq!((k2.public(), b), (kp.public(), Backend::Keychain));
        // Re-saving replaces the item.
        let kp2 = KeyPair::generate();
        save(&p, &cfg, "node-under-test", &kp2.seed()).unwrap();
        assert_eq!(load(&p, &cfg).unwrap().unwrap().0.public(), kp2.public());
        discard(&p, &cfg);
        assert!(load(&p, &cfg).is_err(), "deleted from the keychain");
        drop(kc);
        let _ = std::fs::remove_dir_all(d);
    }

    /// `WEBJET_TEST_TPM=1` with a (software) TPM: see docker/tpm-test.sh.
    #[test]
    fn tpm_roundtrip() {
        if std::env::var("WEBJET_TEST_TPM").is_err() {
            return;
        }
        assert!(tpm::available(), "TPM not available");
        let d = tmp();
        let p = d.join("identity.key");
        let kp = KeyPair::generate();
        let cfg = KeyCfg {
            storage: Backend::Auto,
            keychain: None,
        };
        assert_eq!(save(&p, &cfg, "n", &kp.seed()).unwrap(), Backend::Tpm);
        let raw = std::fs::read(&p).unwrap();
        assert!(
            !raw.windows(32).any(|w| w == &kp.seed()[..]),
            "seed must not appear in the file"
        );
        let (k2, b) = load(&p, &cfg).unwrap().unwrap();
        assert_eq!((k2.public(), b), (kp.public(), Backend::Tpm));
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip() {
        let d = tmp();
        let p = d.join("identity.key");
        let kp = KeyPair::generate();
        let cfg = KeyCfg {
            storage: Backend::Dpapi,
            keychain: None,
        };
        save(&p, &cfg, "n", &kp.seed()).unwrap();
        let raw = std::fs::read(&p).unwrap();
        assert!(!raw.windows(32).any(|w| w == &kp.seed()[..]));
        assert_eq!(load(&p, &cfg).unwrap().unwrap().0.public(), kp.public());
        // Tampering is detected.
        let mut bad = raw.clone();
        let n = bad.len();
        bad[n - 5] ^= 1;
        std::fs::write(&p, bad).unwrap();
        assert!(load(&p, &cfg).is_err());
        let _ = std::fs::remove_dir_all(d);
    }
}
