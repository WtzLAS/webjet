//! Signing keys for controllers (§19.2): either `webjetd signer` over a Unix
//! socket (production), or an in-process key file (tests, small setups).
//!
//! The socket protocol is one JSON request per connection:
//! `{"op":"pubkey"}` → `{"pubkey": hex}`;
//! `{"op":"sign","type":u16,"body":b64}` → `{"envelope": b64}`.
//! The signer only signs SignedTreeHeads and its own certificate requests.

use anyhow::{Context, Result, anyhow, bail};
use std::path::PathBuf;
use webjet_core::crypto::{Bytes32, KeyPair};
use webjet_proto::{Encodable, msg_type as mt};

pub trait Signer: Send + Sync {
    fn public(&self) -> Result<Bytes32>;
    fn sign(&self, ty: u16, body: Vec<u8>) -> Result<Vec<u8>>;
}

pub struct FileSigner {
    kp: KeyPair,
}

/// The signing key in `path`, generated (and written there) when missing.
pub fn load_or_create_key(path: &std::path::Path) -> Result<KeyPair> {
    if !path.exists() {
        let kp = KeyPair::generate();
        crate::state::write_private(path, &kp.seed()[..])?;
        tracing::info!("generated a new signing key at {}", path.display());
    }
    let b = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let seed: Bytes32 = b
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("bad signing key file {}", path.display()))?;
    Ok(KeyPair::from_seed(&seed))
}

impl FileSigner {
    pub fn open(path: &std::path::Path) -> Result<FileSigner> {
        if !path.exists() {
            tracing::warn!(
                "using an in-process signing key at {} (run `webjetd signer` to keep it in a separate process)",
                path.display()
            );
        }
        Ok(FileSigner {
            kp: load_or_create_key(path)?,
        })
    }
}

pub fn allowed(ty: u16) -> bool {
    ty == mt::SIGNED_TREE_HEAD || ty == mt::CERT_REQUEST
}

impl Signer for FileSigner {
    fn public(&self) -> Result<Bytes32> {
        Ok(self.kp.public())
    }
    fn sign(&self, ty: u16, body: Vec<u8>) -> Result<Vec<u8>> {
        if !allowed(ty) {
            bail!("signer refuses type {ty}");
        }
        Ok(self.kp.sign_envelope(ty, body).encode_bytes())
    }
}

pub struct SocketSigner {
    path: PathBuf,
}

impl SocketSigner {
    pub fn new(path: PathBuf) -> SocketSigner {
        SocketSigner { path }
    }

    fn call(&self, req: serde_json::Value) -> Result<serde_json::Value> {
        // Called from synchronous code (head signing); run the exchange on a
        // small dedicated runtime so it works inside and outside tokio.
        let path = self.path.clone();
        let line = {
            let mut l = serde_json::to_vec(&req)?;
            l.push(b'\n');
            l
        };
        let resp = std::thread::spawn(move || -> Result<String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                let s = crate::ipc::connect(&path)
                    .await
                    .with_context(|| format!("webjetd signer at {}", path.display()))?;
                let (r, mut w) = tokio::io::split(s);
                w.write_all(&line).await?;
                let mut resp = String::new();
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    BufReader::new(r).read_line(&mut resp),
                )
                .await
                .map_err(|_| anyhow!("webjetd signer timed out"))??;
                Ok(resp)
            })
        })
        .join()
        .map_err(|_| anyhow!("signer thread panicked"))??;
        let v: serde_json::Value = serde_json::from_str(&resp)?;
        if let Some(e) = v.get("error").and_then(|e| e.as_str()) {
            bail!("webjetd signer: {e}");
        }
        Ok(v)
    }
}

impl Signer for SocketSigner {
    fn public(&self) -> Result<Bytes32> {
        let v = self.call(serde_json::json!({"op": "pubkey"}))?;
        v.get("pubkey")
            .and_then(|p| p.as_str())
            .and_then(webjet_core::crypto::parse_hex32)
            .ok_or_else(|| anyhow!("bad pubkey reply"))
    }
    fn sign(&self, ty: u16, body: Vec<u8>) -> Result<Vec<u8>> {
        let v = self.call(
            serde_json::json!({"op": "sign", "type": ty, "body": crate::state::b64(&body)}),
        )?;
        let e = v
            .get("envelope")
            .and_then(|p| p.as_str())
            .ok_or_else(|| anyhow!("bad sign reply"))?;
        crate::state::unb64(e)
    }
}

/// Serve the signer protocol for `kp` (`webjetd signer`).
pub async fn serve(path: &std::path::Path, kp: KeyPair) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut l = crate::ipc::Listener::bind(path)?;
    tracing::info!("signer listening on {}", path.display());
    let kp = std::sync::Arc::new(kp);
    loop {
        let s = l.accept().await?;
        let kp = kp.clone();
        tokio::spawn(async move {
            let (r, mut w) = tokio::io::split(s);
            let mut line = String::new();
            if BufReader::new(r).read_line(&mut line).await.is_err() {
                return;
            }
            let reply = handle_request(&kp, &line)
                .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}));
            let mut out = serde_json::to_vec(&reply).unwrap_or_default();
            out.push(b'\n');
            let _ = w.write_all(&out).await;
        });
    }
}

fn handle_request(kp: &KeyPair, line: &str) -> Result<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(line)?;
    match v.get("op").and_then(|o| o.as_str()) {
        Some("pubkey") => Ok(serde_json::json!({"pubkey": hex::encode(kp.public())})),
        Some("sign") => {
            let ty = v
                .get("type")
                .and_then(|t| t.as_u64())
                .ok_or_else(|| anyhow!("missing type"))? as u16;
            let body = crate::state::unb64(v.get("body").and_then(|b| b.as_str()).unwrap_or(""))?;
            if !allowed(ty) {
                bail!("refusing to sign message type {}", mt::name(ty));
            }
            // Only well-formed objects of the allowed types.
            match ty {
                mt::SIGNED_TREE_HEAD => {
                    <webjet_proto::SignedTreeHead as webjet_proto::Decodable>::decode_bytes(&body)?;
                }
                _ => {
                    <webjet_proto::SigningKeyCert as webjet_proto::Decodable>::decode_bytes(&body)?;
                }
            }
            Ok(
                serde_json::json!({"envelope": crate::state::b64(&kp.sign_envelope(ty, body).encode_bytes())}),
            )
        }
        _ => bail!("unknown op"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn signer_over_ipc() {
        let path = if cfg!(windows) {
            PathBuf::from(format!(
                r"\\.\pipe\webjet-signer-test-{}",
                std::process::id()
            ))
        } else {
            std::env::temp_dir().join(format!("wj-signer-{}.sock", std::process::id()))
        };
        let kp = KeyPair::generate();
        let pk = kp.public();
        let p2 = path.clone();
        tokio::spawn(async move { serve(&p2, kp).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let s = SocketSigner::new(path);
        let (pubkey, refused) = tokio::task::spawn_blocking(move || {
            (
                s.public().unwrap(),
                s.sign(mt::SIGNED_OP, vec![1, 2]).is_err(),
            )
        })
        .await
        .unwrap();
        assert_eq!(pubkey, pk);
        assert!(refused, "the signer refuses other message types");
    }
}
