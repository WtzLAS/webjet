//! TCP + AnyTLS (§9.7.2): an outer TLS session that looks like a browser
//! visiting a website, carrying a PSK-derived password, then the identity
//! exchange of §9.2 bound to the outer session's exporter.
//!
//! * Client: BoringSSL with a Chrome-like ClientHello (GREASE, extension
//!   permutation, the browser's groups and ALPN); it pins the network's
//!   camouflage certificate key and closes unless `X25519MLKEM768` was
//!   negotiated (§9.3).
//! * Server: presents the network's certificate, prefers `X25519MLKEM768`,
//!   reads the 32-byte password and, when it is wrong, either serves the
//!   camouflage website from the bytes already read (`WEBSITE`) or closes
//!   (`REFUSE`).

use crate::gate::{anytls_enroll_password, anytls_password, Epochs, GateResult, SharedEpochs};
use crate::hop::{exchange_identity, BoxIo, Established};
use crate::tls::PeerTrust;
use anyhow::{anyhow, bail, Result};
use boring::ssl::{
    SslAcceptor, SslConnector, SslMethod, SslVerifyError, SslVerifyMode, SslVersion,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use webjet_core::crypto::{ct_eq, Bytes32, KeyPair};
use webjet_proto::Transport;

const EXPORTER_LABEL: &str = "EXPORTER-webjet-anytls-binding";
/// Version hello after authentication (§15.8): "WJ" || u16 version.
const VERSION_HELLO: [u8; 4] = [b'W', b'J', 0, 1];

/// Camouflage material from the TransportConfig and controller state.
#[derive(Clone, Debug)]
pub struct Camouflage {
    pub domain: String,
    /// DER chain, leaf first.
    pub chain: Vec<Vec<u8>>,
    /// Pins: BLAKE3 of the leaf's SubjectPublicKeyInfo (current and next).
    pub pins: Vec<Bytes32>,
    pub website: bool,
}

/// Server-side secret: the certificate's private key (PKCS#8 PEM) and the site.
#[derive(Clone)]
pub struct CamouflageSecret {
    pub key_pem: Vec<u8>,
    pub site: Vec<u8>,
}

/// BLAKE3 of a certificate's SubjectPublicKeyInfo DER.
pub fn spki_pin(cert_der: &[u8]) -> Result<Bytes32> {
    let c = boring::x509::X509::from_der(cert_der)?;
    let spki = c.public_key()?.public_key_to_der()?;
    Ok(webjet_core::crypto::hash(&spki))
}

/// Generate a self-signed P-256 certificate for `domain` (REFUSE mode, tests).
pub fn self_signed(domain: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    use boring::asn1::Asn1Time;
    use boring::bn::BigNum;
    use boring::ec::{EcGroup, EcKey};
    use boring::hash::MessageDigest;
    use boring::nid::Nid;
    use boring::pkey::PKey;
    use boring::x509::extension::SubjectAlternativeName;
    use boring::x509::{X509Builder, X509NameBuilder};
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, domain)?;
    let name = name.build();
    let mut b = X509Builder::new()?;
    b.set_version(2)?;
    let serial = BigNum::from_u32(rand::random::<u32>() >> 1)?.to_asn1_integer()?;
    b.set_serial_number(&serial)?;
    b.set_subject_name(&name)?;
    b.set_issuer_name(&name)?;
    b.set_pubkey(&key)?;
    let nb = Asn1Time::days_from_now(0)?;
    let na = Asn1Time::days_from_now(825)?;
    b.set_not_before(&nb)?;
    b.set_not_after(&na)?;
    let san = SubjectAlternativeName::new()
        .dns(domain)
        .build(&b.x509v3_context(None, None))?;
    b.append_extension(&san)?;
    b.sign(&key, MessageDigest::sha256())?;
    let cert = b.build();
    Ok((cert.to_der()?, key.private_key_to_pem_pkcs8()?))
}

fn chrome_connector(cam: &Camouflage) -> Result<SslConnector> {
    let mut b = SslConnector::builder(SslMethod::tls())?;
    b.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    b.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    b.set_grease_enabled(true);
    b.set_permute_extensions(true);
    b.enable_ocsp_stapling();
    b.enable_signed_cert_timestamps();
    b.set_curves_list("X25519MLKEM768:X25519:P-256:P-384")?;
    b.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA")?;
    b.set_sigalgs_list("ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512")?;
    b.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    let pins = cam.pins.clone();
    b.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        let Some(cert) = ssl.peer_certificate() else {
            return Err(SslVerifyError::Invalid(
                boring::ssl::SslAlert::CERTIFICATE_UNKNOWN,
            ));
        };
        let ok = cert
            .public_key()
            .and_then(|k| k.public_key_to_der())
            .map(|d| pins.contains(&webjet_core::crypto::hash(&d)))
            .unwrap_or(false);
        if ok {
            Ok(())
        } else {
            Err(SslVerifyError::Invalid(
                boring::ssl::SslAlert::BAD_CERTIFICATE,
            ))
        }
    });
    Ok(b.build())
}

async fn client_outer(
    addr: SocketAddr,
    cam: &Camouflage,
) -> Result<tokio_boring::SslStream<TcpStream>> {
    let s = TcpStream::connect(addr).await?;
    let _ = s.set_nodelay(true);
    let conn = chrome_connector(cam)?;
    let cfg = conn.configure()?.verify_hostname(false);
    let tls = tokio_boring::connect(cfg, &cam.domain, s)
        .await
        .map_err(|e| anyhow!("AnyTLS handshake: {e}"))?;
    if tls.ssl().curve_name() != Some("X25519MLKEM768") {
        bail!("AnyTLS server did not select X25519MLKEM768");
    }
    Ok(tls)
}

fn exporter(ssl: &boring::ssl::SslRef) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    ssl.export_keying_material(&mut out, EXPORTER_LABEL, None)?;
    Ok(out)
}

async fn send_password<S: AsyncWrite + Unpin>(s: &mut S, pw: &Bytes32) -> Result<()> {
    let pad = 30 + (rand::random::<u8>() % 200) as usize;
    let mut m = Vec::with_capacity(34 + pad);
    m.extend_from_slice(pw);
    m.extend_from_slice(&(pad as u16).to_be_bytes());
    m.extend(std::iter::repeat_with(rand::random::<u8>).take(pad));
    m.extend_from_slice(&VERSION_HELLO);
    s.write_all(&m).await?;
    Ok(())
}

pub async fn dial(
    addr: SocketAddr,
    cam: &Camouflage,
    kp: &KeyPair,
    expected: Vec<Bytes32>,
    trust: Arc<dyn PeerTrust>,
    psk: &Bytes32,
) -> Result<Established> {
    let fut = async {
        let mut tls = client_outer(addr, cam).await?;
        send_password(&mut tls, &anytls_password(psk)).await?;
        let mut vh = [0u8; 4];
        tls.read_exact(&mut vh).await?;
        if vh[..2] != VERSION_HELLO[..2] {
            bail!("bad AnyTLS version hello");
        }
        let ex = exporter(tls.ssl())?;
        let peer =
            exchange_identity(&mut tls, &ex, kp, true, Some(&expected), trust.as_ref()).await?;
        Ok(Established {
            io: Box::new(tls) as BoxIo,
            peer_key: peer,
            transport: Transport::AnyTls,
            remote: addr,
            bootstrap: false,
            kcp_stats: None,
        })
    };
    tokio::time::timeout(Duration::from_secs(15), fut)
        .await
        .map_err(|_| anyhow!("AnyTLS to {addr} timed out"))?
}

/// Enrollment over AnyTLS: the password is derived from the token (§9.7.2).
pub async fn dial_enroll(
    addr: SocketAddr,
    cam: &Camouflage,
    token_hash: &Bytes32,
) -> Result<BoxIo> {
    let mut tls = client_outer(addr, cam).await?;
    send_password(&mut tls, &anytls_enroll_password(token_hash)).await?;
    let mut vh = [0u8; 4];
    tls.read_exact(&mut vh).await?;
    Ok(Box::new(tls))
}

pub fn acceptor(cam: &Camouflage, secret: &CamouflageSecret) -> Result<SslAcceptor> {
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    let leaf = boring::x509::X509::from_der(
        cam.chain
            .first()
            .ok_or_else(|| anyhow!("empty camouflage chain"))?,
    )?;
    b.set_certificate(&leaf)?;
    for c in cam.chain.iter().skip(1) {
        b.add_extra_chain_cert(boring::x509::X509::from_der(c)?)?;
    }
    let key = boring::pkey::PKey::private_key_from_pem(&secret.key_pem)?;
    b.set_private_key(&key)?;
    b.check_private_key()?;
    // BoringSSL servers choose groups by their own preference.
    b.set_curves_list("X25519MLKEM768:X25519:P-256:P-384")?;
    b.set_alpn_select_callback(|_, client| {
        boring::ssl::select_next_proto(b"\x08http/1.1", client).ok_or(boring::ssl::AlpnError::NOACK)
    });
    Ok(b.build())
}

pub enum AnyAccepted {
    Hop(Established),
    Enroll(BoxIo, SocketAddr),
    /// Authentication failed and the website was served (or the connection closed).
    Camouflaged,
}

/// Accept an AnyTLS connection (§9.7.2).
pub async fn accept(
    s: TcpStream,
    remote: SocketAddr,
    acc: &SslAcceptor,
    secret: &CamouflageSecret,
    website: bool,
    kp: &KeyPair,
    trust: Arc<dyn PeerTrust>,
    epochs: &SharedEpochs,
    enroll_keys: &[Bytes32],
) -> Result<AnyAccepted> {
    let _ = s.set_nodelay(true);
    let mut tls = tokio::time::timeout(Duration::from_secs(10), tokio_boring::accept(acc, s))
        .await
        .map_err(|_| anyhow!("AnyTLS accept timeout"))?
        .map_err(|e| anyhow!("AnyTLS accept: {e}"))?;
    let pq = tls.ssl().curve_name() == Some("X25519MLKEM768");
    // Read the first 32 bytes, with a timeout like an HTTP server's.
    let mut first = [0u8; 32];
    let mut got = 0;
    let read = tokio::time::timeout(Duration::from_secs(10), async {
        while got < 32 {
            match tls.read(&mut first[got..]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
    })
    .await;
    let e = epochs.read().clone();
    let res = if got == 32 && read.is_ok() && pq {
        check_password(&first, &e, enroll_keys)
    } else {
        None
    };
    match res {
        Some(PwResult::Psk(gr)) => {
            let mut lenb = [0u8; 2];
            tls.read_exact(&mut lenb).await?;
            let pad = u16::from_be_bytes(lenb) as usize;
            let mut skip = vec![0u8; pad + 4];
            tls.read_exact(&mut skip).await?;
            tls.write_all(&VERSION_HELLO).await?;
            let ex = exporter(tls.ssl())?;
            let peer = exchange_identity(&mut tls, &ex, kp, false, None, trust.as_ref()).await?;
            Ok(AnyAccepted::Hop(Established {
                io: Box::new(tls),
                peer_key: peer,
                transport: Transport::AnyTls,
                remote,
                bootstrap: gr.bootstrap(),
                kcp_stats: None,
            }))
        }
        Some(PwResult::Enroll) => {
            let mut lenb = [0u8; 2];
            tls.read_exact(&mut lenb).await?;
            let pad = u16::from_be_bytes(lenb) as usize;
            let mut skip = vec![0u8; pad + 4];
            tls.read_exact(&mut skip).await?;
            tls.write_all(&VERSION_HELLO).await?;
            Ok(AnyAccepted::Enroll(Box::new(tls), remote))
        }
        None => {
            if website {
                serve_website(&mut tls, &first[..got], &secret.site).await;
            }
            let _ = tls.shutdown().await;
            Ok(AnyAccepted::Camouflaged)
        }
    }
}

enum PwResult {
    Psk(GateResult),
    Enroll,
}

fn check_password(first: &[u8; 32], e: &Epochs, enroll_keys: &[Bytes32]) -> Option<PwResult> {
    let mut found = None;
    // Compare against every accepted value in constant time per value.
    for (epoch, psk) in &e.keys {
        if ct_eq(first, &anytls_password(psk)) {
            found = e.classify(*epoch).map(PwResult::Psk);
        }
    }
    for k in enroll_keys {
        if ct_eq(first, &anytls_enroll_password(k)) {
            found = Some(PwResult::Enroll);
        }
    }
    found
}

/// A minimal static web server for the camouflage site: answers GET/HEAD
/// with the site bundle (a single HTML document) and 404 otherwise.
async fn serve_website<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, already: &[u8], site: &[u8]) {
    let mut req = already.to_vec();
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        let mut buf = [0u8; 2048];
        loop {
            if req.windows(4).any(|w| w == b"\r\n\r\n") || req.len() > 16384 {
                let line = req.split(|b| *b == b'\n').next().unwrap_or(&[]).to_vec();
                let ok = line.starts_with(b"GET / ") || line.starts_with(b"GET /index.html ") || line.starts_with(b"HEAD / ");
                let head = line.starts_with(b"HEAD ");
                let body: &[u8] = if ok { site } else { b"<html><body><h1>404 Not Found</h1></body></html>" };
                let status = if ok { "200 OK" } else { "404 Not Found" };
                let resp = format!("HTTP/1.1 {status}\r\nServer: nginx\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n", body.len());
                if s.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }
                if !head && s.write_all(body).await.is_err() {
                    return;
                }
                let end = req.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(req.len());
                req.drain(..end);
                continue;
            }
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => req.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::TrustAll;

    fn setup() -> (Camouflage, CamouflageSecret, SharedEpochs) {
        let (cert, key) = self_signed("cdn.example.com").unwrap();
        let pin = spki_pin(&cert).unwrap();
        let cam = Camouflage {
            domain: "cdn.example.com".into(),
            chain: vec![cert],
            pins: vec![pin],
            website: true,
        };
        let sec = CamouflageSecret {
            key_pem: key,
            site: b"<html>hello</html>".to_vec(),
        };
        let mut e = Epochs::default();
        e.keys.insert(7, [7; 32]);
        e.current = 7;
        (cam, sec, Arc::new(parking_lot::RwLock::new(e)))
    }

    #[tokio::test]
    async fn anytls_hop_and_website() {
        let (cam, sec, ep) = setup();
        let acc = Arc::new(acceptor(&cam, &sec).unwrap());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let server_kp = KeyPair::generate();
        let skp = server_kp.clone();
        let (sec2, ep2, acc2) = (sec.clone(), ep.clone(), acc.clone());
        tokio::spawn(async move {
            loop {
                let (s, r) = l.accept().await.unwrap();
                let (sec3, ep3, acc3, skp3) =
                    (sec2.clone(), ep2.clone(), acc2.clone(), skp.clone());
                tokio::spawn(async move {
                    match accept(
                        s,
                        r,
                        &acc3,
                        &sec3,
                        true,
                        &skp3,
                        Arc::new(TrustAll),
                        &ep3,
                        &[],
                    )
                    .await
                    {
                        Ok(AnyAccepted::Hop(mut h)) => {
                            let (t, p) = crate::hop::read_record(&mut h.io).await.unwrap();
                            crate::hop::write_record(&mut h.io, t, &p).await.unwrap();
                        }
                        _ => {}
                    }
                });
            }
        });
        let ckp = KeyPair::generate();
        let mut h = dial(
            addr,
            &cam,
            &ckp,
            vec![server_kp.public()],
            Arc::new(TrustAll),
            &[7; 32],
        )
        .await
        .unwrap();
        crate::hop::write_record(&mut h.io, 1, b"over anytls")
            .await
            .unwrap();
        let (_, p) = crate::hop::read_record(&mut h.io).await.unwrap();
        assert_eq!(p, b"over anytls");
        // Wrong password: the website answers.
        let mut tls = client_outer(addr, &cam).await.unwrap();
        tls.write_all(b"GET / HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n")
            .await
            .unwrap();
        let mut resp = vec![0u8; 512];
        let n = tls.read(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp[..n]).to_string();
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        // Wrong pin: the client refuses.
        let mut bad = cam.clone();
        bad.pins = vec![[0; 32]];
        assert!(client_outer(addr, &bad).await.is_err());
    }
}
