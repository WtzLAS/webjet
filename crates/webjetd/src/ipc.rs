//! Local IPC for the control channel and the signer (§13.1, §19.2): a Unix
//! socket on Unix, a named pipe on Windows.
//!
//! The control channel is open to every local user ([`Access::Everyone`]):
//! it shows the network and accepts operations, and every operation is
//! checked against its account, root or emergency signature, so the socket
//! itself grants no rights. The signer holds a key and stays private
//! ([`Access::Private`]: the agent's user only; SYSTEM and Administrators
//! on Windows).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncWrite};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Default path of the control channel, shared by webjetd, `webjetctl` and
/// webjet-app. Unix uses `/var/run`: macOS has no `/run` (its root volume is
/// sealed read-only), and on Linux `/var/run` is a symlink to `/run`.
pub fn default_control() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"\\.\pipe\webjet")
    } else {
        PathBuf::from("/var/run/webjet/control.sock")
    }
}

/// Who may connect to a listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// The agent's own user (Unix mode 0600); SYSTEM and Administrators on
    /// Windows.
    Private,
    /// Every local user (Unix mode 0666); everyone on Windows, without the
    /// right to create pipe instances.
    Everyone,
    /// The owner and the process's group (Unix mode 0660), for a signer that
    /// runs as its own user in the agent's group (`webjetd signer
    /// --group-access`); like `Private` on Windows.
    Group,
}

/// Default path of the signer's socket (`webjetd signer --socket`).
pub fn default_signer() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"\\.\pipe\webjet-signer")
    } else {
        PathBuf::from("/var/run/webjet/signer.sock")
    }
}

#[cfg(unix)]
pub struct Listener {
    inner: tokio::net::UnixListener,
}

#[cfg(unix)]
impl Listener {
    pub fn bind(path: &Path, access: Access) -> Result<Listener> {
        use std::os::unix::fs::PermissionsExt;
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
            if access == Access::Everyone && Some(d) == default_control().parent() {
                open_dir(d)?;
            }
        }
        let _ = std::fs::remove_file(path);
        let inner = tokio::net::UnixListener::bind(path)
            .with_context(|| format!("bind {}", path.display()))?;
        let mode = match access {
            Access::Private => 0o600,
            Access::Group => 0o660,
            Access::Everyone => 0o666,
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        Ok(Listener { inner })
    }

    pub async fn accept(&mut self) -> Result<Box<dyn Stream>> {
        let (s, _) = self.inner.accept().await?;
        Ok(Box::new(s))
    }
}

/// Let every user through directory `d` to the socket in it (search
/// permission only: they can't list it). Used for the default socket
/// directory: older webjetup-written systemd units create `/run/webjet` with
/// mode 0750, owned by the agent, so the agent fixes it at every start.
/// Other directories (`control_socket` set in webjetd.toml) are left as they
/// are: the data directory, for one, must stay private.
#[cfg(unix)]
fn open_dir(d: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = std::fs::metadata(d)?;
    let mode = m.permissions().mode() & 0o7777;
    // SAFETY: geteuid has no preconditions.
    if m.uid() == unsafe { libc::geteuid() } && mode & 0o011 != 0o011 {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(mode | 0o011))
            .with_context(|| format!("let every user into {}", d.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
pub async fn connect(path: &Path) -> std::io::Result<Box<dyn Stream>> {
    Ok(Box::new(tokio::net::UnixStream::connect(path).await?))
}

#[cfg(windows)]
pub use win::{Listener, connect};

#[cfg(windows)]
mod win {
    use super::*;
    use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};

    /// SYSTEM and the Administrators group get full access; nobody else.
    pub const PRIVATE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

    /// Also everyone, to read and write (0x12008B = FILE_GENERIC_READ |
    /// FILE_WRITE_DATA). Not FILE_APPEND_DATA, which on a pipe is
    /// FILE_CREATE_PIPE_INSTANCE: another user must not be able to serve
    /// instances of the agent's pipe. So clients open the pipe with exactly
    /// those rights ([`connect`]), not GENERIC_WRITE.
    pub const EVERYONE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;WD)";

    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_WRITE_DATA: u32 = 0x0002;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    /// SECURITY_IDENTIFICATION: the server may identify the client but not
    /// act as it (what tokio's own client asks for).
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

    pub struct Listener {
        path: PathBuf,
        access: Access,
        next: NamedPipeServer,
    }

    fn create(path: &Path, access: Access, first: bool) -> Result<NamedPipeServer> {
        let sddl = match access {
            Access::Private | Access::Group => PRIVATE_SDDL,
            Access::Everyone => EVERYONE_SDDL,
        };
        let mut sa = crate::winsec::SecurityAttributes::from_sddl(sddl)?;
        let mut o = ServerOptions::new();
        o.first_pipe_instance(first).reject_remote_clients(true);
        let s = unsafe { o.create_with_security_attributes_raw(path, sa.as_mut_ptr()) }
            .with_context(|| format!("create pipe {}", path.display()))?;
        Ok(s)
    }

    impl Listener {
        pub fn bind(path: &Path, access: Access) -> Result<Listener> {
            Ok(Listener {
                path: path.to_path_buf(),
                access,
                next: create(path, access, true)?,
            })
        }

        pub async fn accept(&mut self) -> Result<Box<dyn Stream>> {
            self.next.connect().await?;
            let fresh = create(&self.path, self.access, false)?;
            let connected = std::mem::replace(&mut self.next, fresh);
            Ok(Box::new(connected))
        }
    }

    pub async fn connect(path: &Path) -> std::io::Result<Box<dyn Stream>> {
        const ERROR_PIPE_BUSY: i32 = 231;
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::IntoRawHandle;
        for _ in 0..50 {
            let opened = std::fs::OpenOptions::new()
                .access_mode(GENERIC_READ | FILE_WRITE_DATA)
                .custom_flags(FILE_FLAG_OVERLAPPED)
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(path);
            match opened {
                // SAFETY: the handle was just opened for overlapped I/O and
                // is owned by nothing else.
                Ok(f) => {
                    let c = unsafe { NamedPipeClient::from_raw_handle(f.into_raw_handle())? };
                    return Ok(Box::new(c));
                }
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await
                }
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "pipe busy",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(unix)]
    #[test]
    fn default_sockets_avoid_run() {
        // macOS has no /run (sealed read-only root volume).
        for p in [default_control(), default_signer()] {
            assert!(p.starts_with("/var/run/webjet"), "{}", p.display());
        }
    }

    #[tokio::test]
    async fn roundtrip() {
        for access in [Access::Private, Access::Group, Access::Everyone] {
            roundtrip_with(access).await;
        }
    }

    async fn roundtrip_with(access: Access) {
        let path = if cfg!(windows) {
            PathBuf::from(format!(
                r"\\.\pipe\webjet-test-{}",
                hex::encode(webjet_core::crypto::random16())
            ))
        } else {
            std::env::temp_dir().join(format!(
                "wj-ipc-{}.sock",
                hex::encode(&webjet_core::crypto::random16()[..6])
            ))
        };
        let mut l = Listener::bind(&path, access).unwrap();
        let srv = tokio::spawn(async move {
            for _ in 0..2 {
                let mut s = l.accept().await.unwrap();
                let mut b = [0u8; 4];
                s.read_exact(&mut b).await.unwrap();
                s.write_all(&b).await.unwrap();
            }
        });
        for _ in 0..2 {
            let mut c = connect(&path).await.unwrap();
            c.write_all(b"ping").await.unwrap();
            let mut b = [0u8; 4];
            c.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, b"ping");
        }
        srv.await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let want = match access {
                Access::Private => 0o600,
                Access::Group => 0o660,
                Access::Everyone => 0o666,
            };
            let m = std::fs::metadata(&path).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, want);
            let _ = std::fs::remove_file(&path);
        }
    }

    /// The control socket: every user may connect; the directory it's in
    /// becomes passable, not listable.
    #[cfg(unix)]
    #[tokio::test]
    async fn control_socket_is_open_to_everyone() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let d = std::env::temp_dir().join(format!(
            "wj-ipc-{}",
            hex::encode(&webjet_core::crypto::random16()[..6])
        ));
        std::fs::create_dir(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o750)).unwrap();
        let sock = d.join("control.sock");
        let _l = Listener::bind(&sock, Access::Everyone).unwrap();
        assert_eq!(mode(&sock), 0o666);
        assert_eq!(mode(&d), 0o750, "only the default directory is opened");
        open_dir(&d).unwrap();
        assert_eq!(mode(&d), 0o751);
        connect(&sock).await.unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }
}
