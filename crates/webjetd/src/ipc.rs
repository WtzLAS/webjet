//! Local IPC for the control channel and the signer (§13.1, §19.2): a Unix
//! socket (mode 0600) on Unix, a named pipe (SYSTEM and Administrators
//! only) on Windows.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncWrite};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Default path of the control channel.
pub fn default_control() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"\\.\pipe\webjet")
    } else {
        PathBuf::from("/run/webjet/control.sock")
    }
}

pub fn default_signer() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"\\.\pipe\webjet-signer")
    } else {
        PathBuf::from("/run/webjet/signer.sock")
    }
}

#[cfg(unix)]
pub struct Listener {
    inner: tokio::net::UnixListener,
}

#[cfg(unix)]
impl Listener {
    pub fn bind(path: &Path) -> Result<Listener> {
        use std::os::unix::fs::PermissionsExt;
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let _ = std::fs::remove_file(path);
        let inner = tokio::net::UnixListener::bind(path)
            .with_context(|| format!("bind {}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Listener { inner })
    }

    pub async fn accept(&mut self) -> Result<Box<dyn Stream>> {
        let (s, _) = self.inner.accept().await?;
        Ok(Box::new(s))
    }
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
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

    /// SYSTEM and the Administrators group get full access; nobody else.
    pub const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

    pub struct Listener {
        path: PathBuf,
        next: NamedPipeServer,
    }

    fn create(path: &Path, first: bool) -> Result<NamedPipeServer> {
        let mut sa = crate::winsec::SecurityAttributes::from_sddl(SDDL)?;
        let mut o = ServerOptions::new();
        o.first_pipe_instance(first).reject_remote_clients(true);
        let s = unsafe { o.create_with_security_attributes_raw(path, sa.as_mut_ptr()) }
            .with_context(|| format!("create pipe {}", path.display()))?;
        Ok(s)
    }

    impl Listener {
        pub fn bind(path: &Path) -> Result<Listener> {
            Ok(Listener {
                path: path.to_path_buf(),
                next: create(path, true)?,
            })
        }

        pub async fn accept(&mut self) -> Result<Box<dyn Stream>> {
            self.next.connect().await?;
            let fresh = create(&self.path, false)?;
            let connected = std::mem::replace(&mut self.next, fresh);
            Ok(Box::new(connected))
        }
    }

    pub async fn connect(path: &Path) -> std::io::Result<Box<dyn Stream>> {
        const ERROR_PIPE_BUSY: i32 = 231;
        for _ in 0..50 {
            match ClientOptions::new().open(path) {
                Ok(c) => return Ok(Box::new(c)),
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

    #[tokio::test]
    async fn roundtrip() {
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
        let mut l = Listener::bind(&path).unwrap();
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
            let _ =
                std::fs::metadata(&path).map(|m| assert_eq!(m.permissions().mode() & 0o777, 0o600));
            let _ = std::fs::remove_file(&path);
        }
    }
}
