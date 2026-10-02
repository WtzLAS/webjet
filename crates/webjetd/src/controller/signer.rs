//! Signing keys for controllers (§19.2): either `webjet-signer` over a Unix
//! socket (production), or an in-process key file (tests, small setups).
//!
//! The socket protocol is one JSON request per connection:
//! `{"op":"pubkey"}` → `{"pubkey": hex}`;
//! `{"op":"sign","type":u16,"body":b64}` → `{"envelope": b64}`.
//! The signer only signs SignedTreeHeads and its own certificate requests.

use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use webjet_core::crypto::{Bytes32, KeyPair};
use webjet_proto::{msg_type as mt, Encodable};

pub trait Signer: Send + Sync {
    fn public(&self) -> Result<Bytes32>;
    fn sign(&self, ty: u16, body: Vec<u8>) -> Result<Vec<u8>>;
}

pub struct FileSigner {
    kp: KeyPair,
}

impl FileSigner {
    pub fn open(path: &std::path::Path) -> Result<FileSigner> {
        if !path.exists() {
            let kp = KeyPair::generate();
            crate::state::write_private(path, &kp.seed()[..])?;
            tracing::warn!(
                "generated an in-process signing key at {} (use webjet-signer in production)",
                path.display()
            );
        }
        let b = std::fs::read(path)?;
        let seed: Bytes32 = b
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("bad signing key file"))?;
        Ok(FileSigner {
            kp: KeyPair::from_seed(&seed),
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

    #[cfg(unix)]
    fn call(&self, req: serde_json::Value) -> Result<serde_json::Value> {
        use std::io::{BufRead, BufReader, Write};
        let mut s = std::os::unix::net::UnixStream::connect(&self.path)
            .with_context(|| format!("webjet-signer at {}", self.path.display()))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut line = serde_json::to_vec(&req)?;
        line.push(b'\n');
        s.write_all(&line)?;
        let mut r = BufReader::new(s);
        let mut resp = String::new();
        r.read_line(&mut resp)?;
        let v: serde_json::Value = serde_json::from_str(&resp)?;
        if let Some(e) = v.get("error").and_then(|e| e.as_str()) {
            bail!("webjet-signer: {e}");
        }
        Ok(v)
    }

    #[cfg(not(unix))]
    fn call(&self, _: serde_json::Value) -> Result<serde_json::Value> {
        bail!("webjet-signer sockets need Unix")
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

/// Serve the signer protocol for `kp` (used by the `webjet-signer` binary).
#[cfg(unix)]
pub fn serve(path: &std::path::Path, kp: KeyPair) -> Result<()> {
    use std::io::{BufRead, BufReader, Write};
    let _ = std::fs::remove_file(path);
    let l = std::os::unix::net::UnixListener::bind(path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::info!("webjet-signer listening on {}", path.display());
    for conn in l.incoming() {
        let Ok(mut s) = conn else { continue };
        let mut line = String::new();
        if BufReader::new(&s).read_line(&mut line).is_err() {
            continue;
        }
        let reply = (|| -> Result<serde_json::Value> {
            let v: serde_json::Value = serde_json::from_str(&line)?;
            match v.get("op").and_then(|o| o.as_str()) {
                Some("pubkey") => Ok(serde_json::json!({"pubkey": hex::encode(kp.public())})),
                Some("sign") => {
                    let ty = v.get("type").and_then(|t| t.as_u64()).ok_or_else(|| anyhow!("missing type"))? as u16;
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
                    Ok(serde_json::json!({"envelope": crate::state::b64(&kp.sign_envelope(ty, body).encode_bytes())}))
                }
                _ => bail!("unknown op"),
            }
        })()
        .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}));
        let mut out = serde_json::to_vec(&reply).unwrap_or_default();
        out.push(b'\n');
        let _ = s.write_all(&out);
    }
    Ok(())
}
