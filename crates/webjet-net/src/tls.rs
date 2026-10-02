//! rustls configurations for hop sessions and end-to-end sessions (§9.2-§9.4):
//! mutual TLS 1.3 with raw Ed25519 public keys (RFC 7250), no X.509, no
//! hostname checks, and `X25519MLKEM768` as the only key exchange group.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{aws_lc_rs, verify_tls13_signature_with_raw_key, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use std::sync::Arc;
use webjet_core::crypto::{spki_der, spki_to_key, Bytes32, KeyPair};

/// ALPN for hop sessions (§15.8).
pub const ALPN_HOP: &[u8] = b"webjet/1";
/// ALPN for end-to-end sessions (§15.8).
pub const ALPN_E2E: &[u8] = b"webjet-e2e/1";
/// ALPN for the enrollment endpoint (unauthenticated client).
pub const ALPN_ENROLL: &[u8] = b"webjet-enroll/1";

/// The SNI used for hop TLS; meaningless (no hostname checks) but required.
pub const SERVER_NAME: &str = "webjet.invalid";

/// Decides whether a raw public key belongs to a trusted node (§9.2).
pub trait PeerTrust: Send + Sync + std::fmt::Debug {
    /// Return true if `key` is the identity key of a currently trusted node.
    fn trusted(&self, key: &Bytes32) -> bool;
}

#[derive(Debug)]
pub struct TrustAll;
impl PeerTrust for TrustAll {
    fn trusted(&self, _: &Bytes32) -> bool {
        true
    }
}

/// The crypto provider: AWS-LC with only the hybrid PQ group (§9.3).
pub fn provider() -> Arc<CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    p.cipher_suites.retain(|s| s.version() == &rustls::version::TLS13);
    Arc::new(p)
}

fn algs() -> WebPkiSupportedAlgorithms {
    aws_lc_rs::default_provider().signature_verification_algorithms
}

pub fn certified_key(kp: &KeyPair) -> anyhow::Result<Arc<CertifiedKey>> {
    let der = kp.pkcs8_der();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec()));
    let signer = aws_lc_rs::sign::any_eddsa_type(match &key {
        PrivateKeyDer::Pkcs8(k) => k,
        _ => unreachable!(),
    })?;
    let spki = CertificateDer::from(spki_der(&kp.public()));
    Ok(Arc::new(CertifiedKey::new(vec![spki], signer)))
}

fn key_of(cert: &CertificateDer<'_>) -> Result<Bytes32, Error> {
    spki_to_key(cert.as_ref()).ok_or(Error::General("peer did not present an Ed25519 raw public key".into()))
}

fn verify_sig(message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
    verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(cert.as_ref()), dss, &algs())
}

/// Server verifier for the dialer: accepts exactly the expected key, and
/// only while it is trusted (§9.2: "the dialer ... rejects any other key").
#[derive(Debug)]
pub struct ExpectKey {
    /// Acceptable keys; the peer must present one of them.
    pub expected: Vec<Bytes32>,
    pub trust: Arc<dyn PeerTrust>,
}

impl ServerCertVerifier for ExpectKey {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(Error::General("unexpected certificate chain".into()));
        }
        let k = key_of(end_entity)?;
        if !self.expected.contains(&k) {
            return Err(Error::General("peer presented an unexpected key".into()));
        }
        if !self.trust.trusted(&k) {
            return Err(Error::General("peer key is not trusted".into()));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 not supported".into()))
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        verify_sig(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Client verifier for the listener: accepts any trusted node, or, when
/// `expected` is set (end-to-end responder), exactly that node.
#[derive(Debug)]
pub struct TrustedClient {
    pub trust: Arc<dyn PeerTrust>,
    pub expected: Option<Bytes32>,
}

impl ClientCertVerifier for TrustedClient {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], _: UnixTime) -> Result<ClientCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(Error::General("unexpected certificate chain".into()));
        }
        let k = key_of(end_entity)?;
        if let Some(e) = self.expected {
            if e != k {
                return Err(Error::General("peer presented an unexpected key".into()));
            }
        }
        if !self.trust.trusted(&k) {
            return Err(Error::General("peer key is not trusted".into()));
        }
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 not supported".into()))
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        verify_sig(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Client verifier that accepts no client certificate (enrollment endpoint).
pub fn no_client_auth() -> Arc<dyn ClientCertVerifier> {
    Arc::new(rustls::server::NoClientAuth)
}

pub fn client_config(kp: &KeyPair, expected: Vec<Bytes32>, trust: Arc<dyn PeerTrust>, alpn: &[u8]) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let mut c = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ExpectKey { expected, trust }))
        .with_client_cert_resolver(Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(certified_key(kp)?)));
    c.alpn_protocols = vec![alpn.to_vec()];
    c.enable_sni = false;
    c.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(c))
}

/// Client config for enrollment: verifies the controller's key, presents no
/// client identity (the node isn't enrolled yet).
pub fn enroll_client_config(expected: Option<Bytes32>) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    #[derive(Debug)]
    struct AnyTrusted;
    impl PeerTrust for AnyTrusted {
        fn trusted(&self, _: &Bytes32) -> bool {
            true
        }
    }
    #[derive(Debug)]
    struct AnyKey;
    impl ServerCertVerifier for AnyKey {
        fn verify_server_cert(&self, e: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, Error> {
            key_of(e)?;
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
            Err(Error::General("TLS 1.2 not supported".into()))
        }
        fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
            verify_sig(m, c, d)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }
    let verifier: Arc<dyn ServerCertVerifier> = match expected {
        Some(k) => Arc::new(ExpectKey { expected: vec![k], trust: Arc::new(AnyTrusted) }),
        None => Arc::new(AnyKey),
    };
    let mut c = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    c.alpn_protocols = vec![ALPN_ENROLL.to_vec()];
    c.enable_sni = false;
    Ok(Arc::new(c))
}

pub fn server_config(kp: &KeyPair, trust: Arc<dyn PeerTrust>, expected: Option<Bytes32>, alpn: &[&[u8]], allow_enroll: bool) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let verifier: Arc<dyn ClientCertVerifier> = Arc::new(OptionalClient { inner: TrustedClient { trust, expected }, optional: allow_enroll });
    let mut c = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(rustls::server::AlwaysResolvesServerRawPublicKeys::new(certified_key(kp)?)));
    c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    c.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    c.send_tls13_tickets = 0;
    Ok(Arc::new(c))
}

/// Wraps [`TrustedClient`], optionally allowing clients without a
/// certificate (only for the enrollment ALPN; the caller enforces that).
#[derive(Debug)]
struct OptionalClient {
    inner: TrustedClient,
    optional: bool,
}

impl ClientCertVerifier for OptionalClient {
    fn client_auth_mandatory(&self) -> bool {
        !self.optional
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(&self, e: &CertificateDer<'_>, i: &[CertificateDer<'_>], now: UnixTime) -> Result<ClientCertVerified, Error> {
        self.inner.verify_client_cert(e, i, now)
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Server side of the enrollment endpoint: no client certificate (§8).
pub fn enroll_server_config(kp: &KeyPair) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let mut c = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(no_client_auth())
        .with_cert_resolver(Arc::new(rustls::server::AlwaysResolvesServerRawPublicKeys::new(certified_key(kp)?)));
    c.alpn_protocols = vec![ALPN_ENROLL.to_vec()];
    c.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    c.send_tls13_tickets = 0;
    Ok(Arc::new(c))
}

pub fn server_name() -> ServerName<'static> {
    ServerName::try_from(SERVER_NAME).unwrap()
}

/// The peer's raw public key after a completed handshake.
pub fn peer_key(conn: &rustls::CommonState) -> Option<Bytes32> {
    let certs = conn.peer_certificates()?;
    spki_to_key(certs.first()?.as_ref())
}

/// Check that the hybrid PQ group was negotiated (§9.3).
pub fn check_pq(conn: &rustls::CommonState) -> anyhow::Result<()> {
    match conn.negotiated_key_exchange_group() {
        Some(g) if g.name() == rustls::NamedGroup::X25519MLKEM768 => Ok(()),
        other => anyhow::bail!("handshake did not use X25519MLKEM768 ({:?})", other.map(|g| g.name())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_handshake() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let cc = client_config(&a, vec![b.public()], Arc::new(TrustAll), ALPN_E2E).unwrap();
        let sc = server_config(&b, Arc::new(TrustAll), Some(a.public()), &[ALPN_E2E], false).unwrap();
        let mut c = rustls::ClientConnection::new(cc, server_name()).unwrap();
        let mut s = rustls::ServerConnection::new(sc).unwrap();
        for _ in 0..10 {
            let mut buf = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut buf).unwrap();
            }
            let mut rd = &buf[..];
            while !rd.is_empty() {
                s.read_tls(&mut rd).unwrap();
            }
            s.process_new_packets().unwrap();
            let mut buf = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut buf).unwrap();
            }
            let mut rd = &buf[..];
            while !rd.is_empty() {
                c.read_tls(&mut rd).unwrap();
            }
            c.process_new_packets().unwrap();
            if !c.is_handshaking() && !s.is_handshaking() {
                break;
            }
        }
        assert!(!c.is_handshaking() && !s.is_handshaking());
        assert_eq!(peer_key(&c), Some(b.public()));
        assert_eq!(peer_key(&s), Some(a.public()));
        check_pq(&c).unwrap();
        let mut k1 = [0u8; 64];
        let mut k2 = [0u8; 64];
        c.export_keying_material(&mut k1, b"webjet-e2e-v1", Some(b"ctx")).unwrap();
        s.export_keying_material(&mut k2, b"webjet-e2e-v1", Some(b"ctx")).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn wrong_key_rejected() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let other = KeyPair::generate();
        let cc = client_config(&a, vec![other.public()], Arc::new(TrustAll), ALPN_HOP).unwrap();
        let sc = server_config(&b, Arc::new(TrustAll), None, &[ALPN_HOP], false).unwrap();
        let mut c = rustls::ClientConnection::new(cc, server_name()).unwrap();
        let mut s = rustls::ServerConnection::new(sc).unwrap();
        let mut failed = false;
        for _ in 0..5 {
            let mut buf = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut buf).unwrap();
            }
            let mut rd = &buf[..];
            while !rd.is_empty() {
                s.read_tls(&mut rd).unwrap();
            }
            if s.process_new_packets().is_err() {
                failed = true;
                break;
            }
            let mut buf = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut buf).unwrap();
            }
            let mut rd = &buf[..];
            while !rd.is_empty() {
                c.read_tls(&mut rd).unwrap();
            }
            if c.process_new_packets().is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);
    }
}
