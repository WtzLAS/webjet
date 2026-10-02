//! Keys, signatures, the signed envelope (§15.3) and BLAKE3 derivations (§15.4).

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use webjet_proto::{msg_type, Decodable, Encodable, Key32, Sig64, Signed};
use zeroize::Zeroizing;

pub type Bytes32 = [u8; 32];

/// The `webjetsig/v1` domain-separation prefix.
const SIG_DOMAIN: &[u8] = b"webjetsig/v1";

pub mod ctx {
    pub const SIGNING_KEY_ID: &str = "webjet signing-key-id v1";
    pub const ROUTE_ID: &str = "webjet route-id v1";
    pub const ENROLL_TOKEN: &str = "webjet enroll-token v1";
    pub const ENROLL_ID: &str = "webjet enroll-id v1";
    pub const ENROLL_PROOF: &str = "webjet enroll-proof v1";
    pub const ENROLL_ANYTLS: &str = "webjet enroll anytls v1";
    pub const TREE_PATH: &str = "webjet tree-path v1";
    pub const ANYTLS_PASSWORD: &str = "webjet anytls password v1";
    pub const UDP_OBFS: &str = "webjet udp obfs v1";
    pub const UDP_PACKET: &str = "webjet udp packet v1";
    pub const TCP_GATE: &str = "webjet tcp gate v1";
    pub const DIGEST: &str = "webjet digest v1";
    pub const ANYTLS_BIND: &str = "webjet anytls binding v1";
    pub const STATE_KEY: &str = "webjet state-at-rest v1";
}

/// An Ed25519 key pair. The secret is zeroized on drop.
pub struct KeyPair {
    sk: SigningKey,
}

impl Clone for KeyPair {
    fn clone(&self) -> Self {
        KeyPair {
            sk: SigningKey::from_bytes(&self.sk.to_bytes()),
        }
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyPair({})", key_b64(&self.public()))
    }
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut seed[..]);
        KeyPair {
            sk: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_seed(seed: &Bytes32) -> Self {
        KeyPair {
            sk: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed(&self) -> Zeroizing<Bytes32> {
        Zeroizing::new(self.sk.to_bytes())
    }

    pub fn public(&self) -> Bytes32 {
        self.sk.verifying_key().to_bytes()
    }

    pub fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        self.sk.sign(msg).to_bytes()
    }

    /// PKCS#8 v1 DER for rustls (RFC 8410).
    pub fn pkcs8_der(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(hex::decode("302e020100300506032b657004220420").unwrap());
        v.extend_from_slice(&self.sk.to_bytes());
        v
    }

    /// Sign `body` as a message of the given type, producing the envelope.
    pub fn sign_envelope(&self, ty: u16, body: Vec<u8>) -> Signed {
        let sig = self.sign_raw(&sig_input(ty, webjet_proto::SCHEMA_V1, &body));
        Signed {
            type_: ty,
            schema: webjet_proto::SCHEMA_V1,
            body: Some(body),
            signer: Some(Key32::from_bytes(&self.public())),
            alg: 1,
            sig: Some(Sig64::from_bytes(&sig)),
        }
    }

    /// Sign and encode an object.
    pub fn sign_obj<T: Encodable>(&self, ty: u16, obj: &T) -> Vec<u8> {
        self.sign_envelope(ty, obj.encode_bytes()).encode_bytes()
    }
}

/// Ed25519 SubjectPublicKeyInfo DER (RFC 8410), as used for TLS raw public keys.
pub fn spki_der(pk: &Bytes32) -> Vec<u8> {
    let mut v = hex::decode("302a300506032b6570032100").unwrap();
    v.extend_from_slice(pk);
    v
}

/// Extract the raw Ed25519 key from an SPKI DER; rejects anything else.
pub fn spki_to_key(der: &[u8]) -> Option<Bytes32> {
    let prefix = hex::decode("302a300506032b6570032100").unwrap();
    if der.len() != 44 || der[..12] != prefix[..] {
        return None;
    }
    der[12..].try_into().ok()
}

fn sig_input(ty: u16, schema: u16, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_DOMAIN.len() + 5 + body.len());
    m.extend_from_slice(SIG_DOMAIN);
    m.push(0);
    m.extend_from_slice(&ty.to_be_bytes());
    m.extend_from_slice(&schema.to_be_bytes());
    m.extend_from_slice(body);
    m
}

pub fn verify_raw(pk: &Bytes32, msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pk) else {
        return false;
    };
    vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig))
        .is_ok()
}

/// A decoded and signature-checked envelope. `body` is the exact received
/// bytes (§15.1).
#[derive(Clone, Debug)]
pub struct Verified {
    pub ty: u16,
    pub schema: u16,
    pub body: Vec<u8>,
    pub signer: Bytes32,
    /// The original envelope bytes, kept for forwarding and storage.
    pub raw: Vec<u8>,
}

impl Verified {
    pub fn decode<T: Decodable>(&self) -> Result<T> {
        T::decode_bytes(&self.body).map_err(|e| anyhow!("{}: {e}", msg_type::name(self.ty)))
    }
}

/// Decode an envelope and verify its signature against its own `signer`
/// field. The caller must still check that the signer is allowed to sign
/// this message type.
pub fn open_envelope(raw: &[u8]) -> Result<Verified> {
    let env = Signed::decode_bytes(raw)?;
    if env.alg != 1 {
        bail!("unsupported signature algorithm {}", env.alg);
    }
    if env.schema != webjet_proto::SCHEMA_V1 {
        bail!(
            "unsupported schema version {} for {}",
            env.schema,
            msg_type::name(env.type_)
        );
    }
    let body = env.body.ok_or_else(|| anyhow!("envelope without body"))?;
    let signer = env
        .signer
        .ok_or_else(|| anyhow!("envelope without signer"))?
        .to_bytes();
    let sig = env
        .sig
        .ok_or_else(|| anyhow!("envelope without signature"))?
        .to_bytes();
    if !verify_raw(&signer, &sig_input(env.type_, env.schema, &body), &sig) {
        bail!("bad signature on {}", msg_type::name(env.type_));
    }
    Ok(Verified {
        ty: env.type_,
        schema: env.schema,
        body,
        signer,
        raw: raw.to_vec(),
    })
}

/// Open an envelope that must be of type `ty` and signed by one of `allowed`.
pub fn open_expect(raw: &[u8], ty: u16, allowed: &[Bytes32]) -> Result<Verified> {
    let v = open_envelope(raw)?;
    if v.ty != ty {
        bail!(
            "expected {}, got {}",
            msg_type::name(ty),
            msg_type::name(v.ty)
        );
    }
    if !allowed.contains(&v.signer) {
        bail!("{} signed by an unexpected key", msg_type::name(ty));
    }
    Ok(v)
}

// ---------------------------------------------------------------- BLAKE3

pub fn derive(context: &str, material: &[u8]) -> Bytes32 {
    blake3::derive_key(context, material)
}

pub fn hash(data: &[u8]) -> Bytes32 {
    *blake3::hash(data).as_bytes()
}

pub fn keyed(key: &Bytes32, data: &[u8]) -> Bytes32 {
    *blake3::keyed_hash(key, data).as_bytes()
}

pub fn signing_key_id(signing_key: &Bytes32) -> Bytes32 {
    derive(ctx::SIGNING_KEY_ID, signing_key)
}

pub fn route_id(src: &Bytes32, dst: &Bytes32, hops: &[Bytes32]) -> Bytes32 {
    let mut m = Vec::with_capacity(64 + hops.len() * 32);
    m.extend_from_slice(src);
    m.extend_from_slice(dst);
    for h in hops {
        m.extend_from_slice(h);
    }
    derive(ctx::ROUTE_ID, &m)
}

pub fn token_hash(token: &[u8]) -> Bytes32 {
    derive(ctx::ENROLL_TOKEN, token)
}

/// Public lookup handle for a pending enrollment; reveals nothing about the token.
pub fn enroll_lookup_id(token_hash: &Bytes32) -> Bytes32 {
    derive(ctx::ENROLL_ID, token_hash)
}

/// `BLAKE3-keyed(token, pubkey || nonce)` (§8 step 3), keyed with a key derived from the token.
pub fn enroll_proof(token_hash: &Bytes32, pubkey: &Bytes32, nonce: &Bytes32) -> Bytes32 {
    let k = derive(ctx::ENROLL_PROOF, token_hash);
    let mut m = [0u8; 64];
    m[..32].copy_from_slice(pubkey);
    m[32..].copy_from_slice(nonce);
    keyed(&k, &m)
}

pub fn random32() -> Bytes32 {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

pub fn random16() -> [u8; 16] {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

// ---------------------------------------------------------------- text forms

/// Standard base64 with padding: 44 characters ending in `=` (§14.2).
pub fn key_b64(k: &Bytes32) -> String {
    base64::engine::general_purpose::STANDARD.encode(k)
}

pub fn parse_key_b64(s: &str) -> Option<Bytes32> {
    if s.len() != 44 || !s.ends_with('=') {
        return None;
    }
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .ok()?
        .try_into()
        .ok()
}

pub fn short(id: &Bytes32) -> String {
    hex::encode(&id[..6])
}

pub fn parse_hex32(s: &str) -> Option<Bytes32> {
    hex::decode(s).ok()?.try_into().ok()
}

pub fn k32(b: &Bytes32) -> Key32 {
    Key32::from_bytes(b)
}

pub fn opt_k32(k: &Option<Key32>) -> Bytes32 {
    k.map(|k| k.to_bytes()).unwrap_or([0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_sign_verify() {
        let kp = KeyPair::generate();
        let raw = kp
            .sign_envelope(msg_type::POLICY, b"hello".to_vec())
            .encode_bytes();
        let v = open_envelope(&raw).unwrap();
        assert_eq!(v.body, b"hello");
        assert_eq!(v.signer, kp.public());
        // A signature for one type can't be used for another.
        let mut env = Signed::decode_bytes(&raw).unwrap();
        env.type_ = msg_type::DNS_CONFIG;
        assert!(open_envelope(&env.encode_bytes()).is_err());
        assert!(open_expect(&raw, msg_type::POLICY, &[[0u8; 32]]).is_err());
    }

    #[test]
    fn spki_roundtrip() {
        let kp = KeyPair::generate();
        assert_eq!(spki_to_key(&spki_der(&kp.public())), Some(kp.public()));
    }

    #[test]
    fn b64_form() {
        let k = KeyPair::generate().public();
        let s = key_b64(&k);
        assert_eq!(s.len(), 44);
        assert!(s.ends_with('='));
        assert_eq!(parse_key_b64(&s), Some(k));
    }
}
