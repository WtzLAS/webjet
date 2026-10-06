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
    let (seed, backend) = unseal(&raw, cfg).map_err(|e| anyhow!("{e:#}\nThe identity key can't be used on this machine. If it was copied or restored from another machine, re-key this node (§8.1): ask an admin for `webjetctl network node rekey` and run `webjetup enroll` (or `webjetctl local enroll`) with the new string."))?;
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
            .is_ok_and(|s| s.success())
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

    /// The seed is a generic password item (service [`SERVICE`], account =
    /// the payload in `identity.key`) whose access list lets any program
    /// read it, like `security add-generic-password -A`. The default access
    /// list trusts only the program that created the item (and, for an
    /// ad-hoc signed binary, only that exact build): an item written by
    /// `webjetctl local enroll` was then unreadable for the webjetd daemon
    /// ("User interaction is not allowed"), and every upgrade would have
    /// locked the agent out of its own key. What protects the item is the
    /// keychain: the System keychain opens only for root, the same bar as a
    /// root-owned `file` key, but the seed isn't stored in plain on disk.
    #[cfg(target_os = "macos")]
    mod imp {
        use super::*;
        use core_foundation::array::{CFArray, CFArrayRef};
        use core_foundation::base::{CFType, CFTypeRef, TCFType};
        use core_foundation::string::{CFString, CFStringRef};
        use security_framework::base::Error as SecError;
        use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference};
        use security_framework::os::macos::access::SecAccess;
        use security_framework::os::macos::keychain::SecKeychain;
        use security_framework_sys::base::{
            SecAccessRef, SecKeychainAttribute, SecKeychainAttributeList, SecKeychainItemRef,
            SecKeychainRef, errSecAuthFailed, errSecItemNotFound,
        };
        use std::os::raw::c_void;

        type OsStatus = i32;
        type SecAclRef = *const c_void;
        /// `errSecInteractionNotAllowed`: the item's access list would need
        /// the user's consent, which a daemon (or a disabled UI) can't give.
        const ERR_INTERACTION_NOT_ALLOWED: OsStatus = -25308;
        /// `errSecNoAccessForItem`.
        const ERR_NO_ACCESS_FOR_ITEM: OsStatus = -25243;

        // Legacy (file-based keychain) access control API. Deprecated, but
        // it is the only one for the System keychain and still supported.
        #[link(name = "Security", kind = "framework")]
        unsafe extern "C" {
            static kSecACLAuthorizationDecrypt: CFStringRef;
            fn SecAccessCreate(
                descriptor: CFStringRef,
                trusted_list: CFArrayRef,
                access: *mut SecAccessRef,
            ) -> OsStatus;
            fn SecAccessCopyMatchingACLList(access: SecAccessRef, tag: CFTypeRef) -> CFArrayRef;
            fn SecACLCopyContents(
                acl: SecAclRef,
                application_list: *mut CFArrayRef,
                description: *mut CFStringRef,
                prompt_selector: *mut u16,
            ) -> OsStatus;
            fn SecACLSetContents(
                acl: SecAclRef,
                application_list: CFArrayRef,
                description: CFStringRef,
                prompt_selector: u16,
            ) -> OsStatus;
            fn SecKeychainItemCreateFromContent(
                item_class: u32,
                attr_list: *const SecKeychainAttributeList,
                length: u32,
                data: *const c_void,
                keychain: SecKeychainRef,
                initial_access: SecAccessRef,
                item: *mut SecKeychainItemRef,
            ) -> OsStatus;
            fn SecKeychainItemDelete(item: SecKeychainItemRef) -> OsStatus;
        }

        fn fourcc(s: &[u8; 4]) -> u32 {
            u32::from_be_bytes(*s)
        }

        fn check(status: OsStatus) -> std::result::Result<(), SecError> {
            if status == 0 {
                Ok(())
            } else {
                Err(SecError::from_code(status))
            }
        }

        pub fn open(path: Option<&Path>) -> Result<SecKeychain> {
            let p = path.map_or_else(|| PathBuf::from(SYSTEM), Path::to_path_buf);
            SecKeychain::open(&p).map_err(|e| anyhow!("open keychain {}: {e}", p.display()))
        }

        /// An access object whose decrypt entries trust every application.
        fn open_access() -> std::result::Result<SecAccess, SecError> {
            let desc = CFString::new(SERVICE);
            let none: CFArray<CFType> = CFArray::from_CFTypes(&[]);
            let mut raw: SecAccessRef = std::ptr::null_mut();
            // SAFETY: valid CF objects in, `raw` is an out pointer; on success
            // we own the returned reference (create rule).
            check(unsafe {
                SecAccessCreate(
                    desc.as_concrete_TypeRef(),
                    none.as_concrete_TypeRef(),
                    &mut raw,
                )
            })?;
            if raw.is_null() {
                return Err(SecError::from_code(errSecAuthFailed));
            }
            // SAFETY: `raw` is a +1 SecAccessRef from SecAccessCreate.
            let access = unsafe { SecAccess::wrap_under_create_rule(raw) };
            // SAFETY: the access object is valid; the tag is a constant
            // CFString from the framework. The result is +1 (or null).
            let list = unsafe {
                SecAccessCopyMatchingACLList(
                    access.as_concrete_TypeRef(),
                    kSecACLAuthorizationDecrypt as CFTypeRef,
                )
            };
            if list.is_null() {
                return Err(SecError::from_code(errSecAuthFailed));
            }
            // SAFETY: +1 CFArray of SecACLRef.
            let acls: CFArray<CFType> = unsafe { CFArray::wrap_under_create_rule(list) };
            for acl in acls.iter() {
                let acl = acl.as_CFTypeRef();
                let mut apps: CFArrayRef = std::ptr::null();
                let mut desc: CFStringRef = std::ptr::null();
                let mut prompt = 0u16;
                // SAFETY: `acl` stays alive in `acls`; out pointers are valid.
                check(unsafe { SecACLCopyContents(acl, &mut apps, &mut desc, &mut prompt) })?;
                // SAFETY: both outputs are +1 references (or null); wrapping
                // them releases them at the end of this iteration.
                let _apps = (!apps.is_null())
                    .then(|| unsafe { CFArray::<CFType>::wrap_under_create_rule(apps) });
                let desc =
                    (!desc.is_null()).then(|| unsafe { CFString::wrap_under_create_rule(desc) });
                let desc_ref = desc
                    .as_ref()
                    .map_or(std::ptr::null(), |d| d.as_concrete_TypeRef());
                // SAFETY: a null application list means "any application".
                check(unsafe { SecACLSetContents(acl, std::ptr::null(), desc_ref, prompt) })?;
            }
            Ok(access)
        }

        /// Delete the items for `account` (all of webjet's when `None`)
        /// without reading them, so it works whatever their access list
        /// says. Returns how many were deleted.
        pub fn remove(kc: &SecKeychain, account: Option<&str>) -> Result<usize> {
            let mut q = ItemSearchOptions::new();
            q.class(ItemClass::generic_password())
                .keychains(std::slice::from_ref(kc))
                .service(SERVICE)
                .load_refs(true)
                .limit(Limit::All);
            if let Some(a) = account {
                q.account(a);
            }
            let found = match q.search() {
                Ok(v) => v,
                Err(e) if e.code() == errSecItemNotFound => return Ok(0),
                Err(e) => bail!("search the keychain: {e}"),
            };
            let mut n = 0;
            for r in found {
                if let security_framework::item::SearchResult::Ref(Reference::KeychainItem(item)) =
                    r
                {
                    // SAFETY: `item` is a live keychain item reference.
                    check(unsafe { SecKeychainItemDelete(item.as_concrete_TypeRef()) })
                        .map_err(|e| anyhow!("delete a keychain item: {e}"))?;
                    n += 1;
                }
            }
            Ok(n)
        }

        pub fn store(path: Option<&Path>, account: &str, seed: &Bytes32) -> Result<Vec<u8>> {
            // Never block on a consent dialog (an agent has no one to ask).
            let _ui = SecKeychain::disable_user_interaction();
            let kc = open(path)?;
            remove(&kc, Some(account))?;
            let access =
                open_access().map_err(|e| anyhow!("set up the keychain item's access: {e}"))?;
            let len = |s: &str| u32::try_from(s.len()).unwrap_or(u32::MAX);
            let mut attrs = [
                SecKeychainAttribute {
                    tag: fourcc(b"svce"),
                    length: len(SERVICE),
                    data: SERVICE.as_ptr() as *mut c_void,
                },
                SecKeychainAttribute {
                    tag: fourcc(b"acct"),
                    length: len(account),
                    data: account.as_ptr() as *mut c_void,
                },
                SecKeychainAttribute {
                    tag: fourcc(b"labl"),
                    length: len(SERVICE),
                    data: SERVICE.as_ptr() as *mut c_void,
                },
            ];
            let list = SecKeychainAttributeList {
                count: attrs.len() as u32,
                attr: attrs.as_mut_ptr(),
            };
            let mut item: SecKeychainItemRef = std::ptr::null_mut();
            // SAFETY: the attribute data outlive the call (SERVICE is static,
            // `account` is borrowed); the item reference is +1 and released.
            let status = unsafe {
                SecKeychainItemCreateFromContent(
                    fourcc(b"genp"),
                    &list,
                    seed.len() as u32,
                    seed.as_ptr().cast(),
                    kc.as_concrete_TypeRef(),
                    access.as_concrete_TypeRef(),
                    &mut item,
                )
            };
            if !item.is_null() {
                // SAFETY: +1 reference from the create call.
                drop(unsafe { CFType::wrap_under_create_rule(item as CFTypeRef) });
            }
            check(status).map_err(|e| anyhow!("store identity key in the keychain: {e}"))?;
            Ok(account.as_bytes().to_vec())
        }

        pub fn load(path: Option<&Path>, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            let account = std::str::from_utf8(payload)?;
            let _ui = SecKeychain::disable_user_interaction();
            let kc = open(path)?;
            match kc.find_generic_password(SERVICE, account) {
                Ok((pw, _)) => Ok(Zeroizing::new(pw.as_ref().to_vec())),
                Err(e)
                    if [
                        ERR_INTERACTION_NOT_ALLOWED,
                        errSecAuthFailed,
                        ERR_NO_ACCESS_FOR_ITEM,
                    ]
                    .contains(&e.code()) =>
                {
                    bail!(
                        "the identity key's keychain item doesn't let webjetd read it ({e}); \
                         webjet 0.4.0 created it readable only by the program that wrote it \
                         (webjetctl), so it can't be recovered"
                    )
                }
                Err(e) => bail!("identity key not in this machine's keychain: {e}"),
            }
        }
    }

    #[cfg(target_os = "macos")]
    pub use imp::{load, store};

    #[cfg(target_os = "macos")]
    pub fn delete(path: Option<&Path>, payload: &[u8]) {
        let _ui = security_framework::os::macos::keychain::SecKeychain::disable_user_interaction();
        if let (Ok(account), Ok(kc)) = (std::str::from_utf8(payload), imp::open(path))
            && let Err(e) = imp::remove(&kc, Some(account))
        {
            tracing::warn!("{e:#}");
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
        // Any program may read the item (the agent reads what webjetctl
        // wrote, and an upgraded agent what the old one wrote).
        let security = |args: &[&str]| {
            std::process::Command::new("security")
                .args(args)
                .arg(&kcp)
                .output()
                .unwrap()
        };
        let out = security(&["find-generic-password", "-s", keychain::SERVICE, "-w"]);
        assert!(out.status.success(), "another program reads the item");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            hex::encode(kp.seed())
        );
        // Re-saving replaces the item.
        let kp2 = KeyPair::generate();
        save(&p, &cfg, "node-under-test", &kp2.seed()).unwrap();
        assert_eq!(load(&p, &cfg).unwrap().unwrap().0.public(), kp2.public());
        discard(&p, &cfg);
        assert!(load(&p, &cfg).is_err(), "deleted from the keychain");
        // An item another program created with the default access list (as
        // 0.4.0's webjetctl did) can't be read, with a clear error, and
        // enrolling again (saving) replaces it.
        let added = security(&[
            "add-generic-password",
            "-s",
            keychain::SERVICE,
            "-a",
            "node-under-test",
            "-w",
            "not-a-key",
        ]);
        assert!(added.status.success());
        let e = load(&p, &cfg).unwrap_err();
        assert!(
            format!("{e:#}").contains("doesn't let webjetd read it"),
            "{e:#}"
        );
        save(&p, &cfg, "node-under-test", &kp.seed()).unwrap();
        assert_eq!(load(&p, &cfg).unwrap().unwrap().0.public(), kp.public());
        discard(&p, &cfg);
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
