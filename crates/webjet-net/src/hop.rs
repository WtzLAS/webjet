//! Hop sessions (§9.1-§9.2): establishing an authenticated, framed stream to
//! a neighbor over TCP+TLS, UDP+KCP+FEC+TLS or TCP+AnyTLS.
//!
//! Hop record framing: `type[1] || len[3] || payload`.

use crate::gate::{
    self, GateResult, ReplayCache, SharedEpochs, TCP_PREAMBLE, check_tcp_preamble, tcp_preamble,
};
use crate::kcp::{KcpStats, LaneIo, UdpEndpoint};
use crate::meter::{Meter, MeteredTcp};
use crate::tls::{self, PeerTrust};
use anyhow::{Context, Result, anyhow, bail};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use webjet_core::crypto::{Bytes32, KeyPair, keyed};
use webjet_proto::Transport;

pub const MAX_RECORD: usize = 1 << 20;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub mod rec {
    /// A `HopControl` FlatBuffer.
    pub const CONTROL: u8 = 1;
    /// A relay frame (§11.5).
    pub const RELAY: u8 = 2;
    /// Padding, ignored (§9.7.4).
    pub const PAD: u8 = 3;
    /// A zstd-compressed `HopControl` FlatBuffer (§9.8); sent only to peers
    /// that advertise the `zstd` feature.
    pub const CONTROL_ZSTD: u8 = 4;
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Io for T {}
pub type BoxIo = Box<dyn Io>;

/// An authenticated hop stream.
pub struct Established {
    pub io: BoxIo,
    pub peer_key: Bytes32,
    pub transport: Transport,
    pub remote: SocketAddr,
    pub bootstrap: bool,
    pub kcp_stats: Option<Arc<KcpStats>>,
    /// The transport's own RTT and loss (§11.2), where it can be read.
    pub meter: Option<Meter>,
    /// A KCP hop's unreliable lane (§17.5), when both ends run it: started,
    /// for whole records sent once and received in any order.
    pub lane: Option<LaneIo>,
}

/// Start a KCP session's lane if the handshake chose [`tls::ALPN_HOP_LANE`]:
/// keys exported from the hop's TLS session, the first half for what the
/// client sends.
fn start_lane(
    mut lane: LaneIo,
    conn: &rustls::CommonState,
    exporter: impl FnOnce(&mut [u8; 64]) -> bool,
    client: bool,
) -> Option<LaneIo> {
    if conn.alpn_protocol() != Some(tls::ALPN_HOP_LANE) {
        return None;
    }
    let mut m = [0u8; 64];
    if !exporter(&mut m) {
        return None;
    }
    let (mut c2s, mut s2c) = ([0u8; 32], [0u8; 32]);
    c2s.copy_from_slice(&m[..32]);
    s2c.copy_from_slice(&m[32..]);
    let started = if client {
        lane.start(c2s, s2c)
    } else {
        lane.start(s2c, c2s)
    };
    zeroize::Zeroize::zeroize(&mut m);
    zeroize::Zeroize::zeroize(&mut c2s);
    zeroize::Zeroize::zeroize(&mut s2c);
    started.then_some(lane)
}

/// Bytes of the record header: `type[1] || len[3]`.
pub const RECORD_HEADER: usize = 4;

pub async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let mut h = [0u8; RECORD_HEADER];
    r.read_exact(&mut h).await?;
    let len = record_len(&h)?;
    let mut b = vec![0u8; len];
    r.read_exact(&mut b).await?;
    Ok((h[0], b))
}

/// [`read_record`], but the buffer holds the whole record, header included:
/// the payload is `buf[RECORD_HEADER..]`. A relay frame read this way can
/// be passed on with its header rewritten in place ([`seal_record`]),
/// without copying it into a new buffer.
pub async fn read_record_buf<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let mut h = [0u8; RECORD_HEADER];
    r.read_exact(&mut h).await?;
    let len = record_len(&h)?;
    let mut b = vec![0u8; RECORD_HEADER + len];
    b[..RECORD_HEADER].copy_from_slice(&h);
    r.read_exact(&mut b[RECORD_HEADER..]).await?;
    Ok((h[0], b))
}

fn record_len(h: &[u8; RECORD_HEADER]) -> std::io::Result<usize> {
    let len = u32::from_be_bytes([0, h[1], h[2], h[3]]) as usize;
    if len > MAX_RECORD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "record too large",
        ));
    }
    Ok(len)
}

/// A record as it goes on the wire: `type[1] || len[3] || payload`.
/// `None` when the payload is over [`MAX_RECORD`]: the peer would refuse
/// it and drop the hop (past 16 MiB the length wouldn't even fit).
pub fn encode_record(ty: u8, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > MAX_RECORD {
        return None;
    }
    let mut v = Vec::with_capacity(RECORD_HEADER + payload.len());
    v.extend_from_slice(&[0; RECORD_HEADER]);
    v.extend_from_slice(payload);
    seal_record(ty, &mut v).then_some(v)
}

/// Write the record header into the first [`RECORD_HEADER`] bytes of `buf`,
/// for the payload after them: a record built in place, without a copy.
/// False (`buf` untouched) when `buf` is shorter than the header or the
/// payload is over [`MAX_RECORD`].
pub fn seal_record(ty: u8, buf: &mut [u8]) -> bool {
    let Some(len) = buf.len().checked_sub(RECORD_HEADER) else {
        return false;
    };
    if len > MAX_RECORD {
        return false;
    }
    buf[0] = ty;
    buf[1..RECORD_HEADER].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
    true
}

pub async fn write_record<W: AsyncWrite + Unpin>(
    w: &mut W,
    ty: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let rec = encode_record(ty, payload)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "record too large"))?;
    w.write_all(&rec).await
}

/// Socket options for every TCP hop (§17.4): no Nagle delay, BBR where
/// the kernel offers it, and a small unsent backlog in the kernel
/// (`TCP_NOTSENT_LOWAT`), so data waits in the hop queue, where fair
/// queueing and CoDel manage it, rather than in the socket buffer.
pub(crate) fn tune_tcp(s: &TcpStream) {
    let _ = s.set_nodelay(true);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::fd::AsRawFd;
        let fd = s.as_raw_fd();
        let set = |name: libc::c_int, val: &[u8]| {
            // SAFETY: `fd` is the live socket `s` borrows; `val` is a valid
            // buffer of the given length. Failures are ignored on purpose.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    name,
                    val.as_ptr().cast(),
                    val.len() as libc::socklen_t,
                );
            }
        };
        #[cfg(target_os = "linux")]
        set(libc::TCP_CONGESTION, b"bbr");
        #[cfg(target_os = "linux")]
        const NOTSENT_LOWAT: libc::c_int = libc::TCP_NOTSENT_LOWAT;
        // <netinet/tcp.h>; the libc crate doesn't have it for Apple.
        #[cfg(target_os = "macos")]
        const NOTSENT_LOWAT: libc::c_int = 0x201;
        set(NOTSENT_LOWAT, &16384i32.to_ne_bytes());
    }
}

// ---------------------------------------------------------------- TCP + TLS

/// The enrollment credential for the TCP preamble: epoch 0xFFFF, MAC keyed
/// by a key derived from the token (§9.7.2).
pub const ENROLL_EPOCH: u16 = 0xffff;

pub fn enroll_preamble(token_hash: &Bytes32) -> [u8; TCP_PREAMBLE] {
    tcp_preamble(ENROLL_EPOCH, &gate::anytls_enroll_password(token_hash))
}

pub async fn dial_tls(
    addr: SocketAddr,
    kp: &KeyPair,
    expected: Vec<Bytes32>,
    trust: Arc<dyn PeerTrust>,
    epoch: u16,
    psk: &Bytes32,
) -> Result<Established> {
    let fut = async {
        let s = TcpStream::connect(addr).await?;
        tune_tcp(&s);
        let (mut s, meter) = MeteredTcp::new(s);
        s.write_all(&tcp_preamble(epoch, psk)).await?;
        let cfg = tls::client_config(kp, expected, trust, tls::ALPN_HOP)?;
        let tls = tokio_rustls::TlsConnector::from(cfg)
            .connect(tls::server_name(), s)
            .await?;
        tls::check_pq(tls.get_ref().1)?;
        let peer = tls::peer_key(tls.get_ref().1).ok_or_else(|| anyhow!("no peer key"))?;
        Ok::<_, anyhow::Error>(Established {
            io: Box::new(tls),
            peer_key: peer,
            transport: Transport::TcpTls,
            remote: addr,
            bootstrap: false,
            kcp_stats: None,
            meter: Some(Meter::Tcp(meter)),
            lane: None,
        })
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| anyhow!("TLS hop to {addr} timed out"))?
}

/// Dial a controller's enrollment endpoint (no client identity).
pub async fn dial_enroll(
    addr: SocketAddr,
    token_hash: &Bytes32,
    expected: Option<Bytes32>,
) -> Result<BoxIo> {
    let fut = async {
        let mut s = TcpStream::connect(addr).await?;
        tune_tcp(&s);
        s.write_all(&enroll_preamble(token_hash)).await?;
        let cfg = tls::enroll_client_config(expected)?;
        let tls = tokio_rustls::TlsConnector::from(cfg)
            .connect(tls::server_name(), s)
            .await?;
        tls::check_pq(tls.get_ref().1)?;
        Ok::<BoxIo, anyhow::Error>(Box::new(tls))
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| anyhow!("enrollment connection to {addr} timed out"))?
}

/// What an accepted connection turned out to be.
pub enum Accepted {
    Hop(Established),
    /// An enrollment connection: a TLS stream with no client identity.
    Enroll(BoxIo, SocketAddr),
}

/// Pending enrollment credentials a controller accepts at its gate: the
/// token hashes of pending enrollments.
pub trait EnrollGate: Send + Sync {
    fn enroll_keys(&self) -> Vec<Bytes32>;
}

pub struct TlsListener {
    pub listener: TcpListener,
    pub replay: Arc<ReplayCache>,
}

impl TlsListener {
    pub async fn bind(addr: SocketAddr) -> Result<TlsListener> {
        Ok(TlsListener {
            listener: TcpListener::bind(addr)
                .await
                .with_context(|| format!("bind {addr}"))?,
            replay: Arc::new(ReplayCache::new(100_000)),
        })
    }
}

/// Handle one accepted TCP connection: PSK gate, then TLS. Failures close
/// the connection without a reply (§9.1).
pub async fn accept_tls(
    s: TcpStream,
    remote: SocketAddr,
    kp: &KeyPair,
    trust: Arc<dyn PeerTrust>,
    epochs: &SharedEpochs,
    replay: &ReplayCache,
    enroll: Option<&dyn EnrollGate>,
) -> Result<Accepted> {
    tune_tcp(&s);
    let (mut s, meter) = MeteredTcp::new(s);
    let mut pre = [0u8; TCP_PREAMBLE];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut pre))
        .await
        .map_err(|_| anyhow!("preamble timeout"))??;
    let epoch = u16::from_be_bytes([pre[0], pre[1]]);
    let mut is_enroll = false;
    let gate_res = if epoch == ENROLL_EPOCH {
        let Some(eg) = enroll else {
            bail!("enrollment not offered here")
        };
        let mut ok = false;
        for k in eg.enroll_keys() {
            let mut e = gate::Epochs::default();
            e.keys
                .insert(ENROLL_EPOCH, gate::anytls_enroll_password(&k));
            e.current = ENROLL_EPOCH;
            if check_tcp_preamble(&pre, &e, replay).is_some() {
                ok = true;
                break;
            }
        }
        if !ok {
            bail!("bad enrollment preamble");
        }
        is_enroll = true;
        GateResult::Bootstrap(ENROLL_EPOCH)
    } else {
        let e = epochs.read().clone();
        check_tcp_preamble(&pre, &e, replay).ok_or_else(|| anyhow!("PSK gate rejected {remote}"))?
    };
    // The enrollment credential gets a config without client certificates;
    // everything else must present a raw public key.
    let cfg = if is_enroll {
        tls::enroll_server_config(kp)?
    } else {
        tls::server_config(kp, trust, None, &[tls::ALPN_HOP])?
    };
    let tls = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        tokio_rustls::TlsAcceptor::from(cfg).accept(s),
    )
    .await
    .map_err(|_| anyhow!("TLS accept timeout"))??;
    let conn = tls.get_ref().1;
    tls::check_pq(conn)?;
    let alpn = conn.alpn_protocol().map(|a| a.to_vec());
    if is_enroll {
        if alpn.as_deref() != Some(tls::ALPN_ENROLL) {
            bail!("enrollment credential with a non-enrollment ALPN");
        }
        return Ok(Accepted::Enroll(Box::new(tls), remote));
    }
    if alpn.as_deref() != Some(tls::ALPN_HOP) {
        bail!("unexpected ALPN");
    }
    let peer = tls::peer_key(conn).ok_or_else(|| anyhow!("hop client without identity"))?;
    Ok(Accepted::Hop(Established {
        io: Box::new(tls),
        peer_key: peer,
        transport: Transport::TcpTls,
        remote,
        bootstrap: gate_res.bootstrap(),
        kcp_stats: None,
        meter: Some(Meter::Tcp(meter)),
        lane: None,
    }))
}

// ---------------------------------------------------------------- UDP + KCP + FEC + TLS

pub async fn dial_kcp(
    ep: &Arc<UdpEndpoint>,
    addr: SocketAddr,
    kp: &KeyPair,
    expected: Vec<Bytes32>,
    trust: Arc<dyn PeerTrust>,
) -> Result<Established> {
    let fut = async {
        let c = ep.dial(addr);
        let mut cfg = (*tls::client_config(kp, expected, trust, tls::ALPN_HOP)?).clone();
        cfg.alpn_protocols = vec![tls::ALPN_HOP_LANE.to_vec(), tls::ALPN_HOP.to_vec()];
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(tls::server_name(), c.stream)
            .await?;
        let conn = tls.get_ref().1;
        tls::check_pq(conn)?;
        let peer = tls::peer_key(conn).ok_or_else(|| anyhow!("no peer key"))?;
        let lane = start_lane(
            c.lane,
            conn,
            |m| {
                conn.export_keying_material(m, tls::LANE_EXPORTER, None)
                    .is_ok()
            },
            true,
        );
        Ok::<_, anyhow::Error>(Established {
            io: Box::new(tls),
            peer_key: peer,
            transport: Transport::KcpFecTls,
            remote: addr,
            bootstrap: false,
            meter: Some(Meter::Kcp(c.stats.clone())),
            kcp_stats: Some(c.stats),
            lane,
        })
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| anyhow!("KCP hop to {addr} timed out"))?
}

pub async fn accept_kcp(
    c: crate::kcp::KcpConn,
    kp: &KeyPair,
    trust: Arc<dyn PeerTrust>,
) -> Result<Established> {
    // The endpoint's handshake slot is held until the handshake ends.
    let _slot = c.handshake;
    let cfg = tls::server_config(kp, trust, None, &[tls::ALPN_HOP_LANE, tls::ALPN_HOP])?;
    let tls = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        tokio_rustls::TlsAcceptor::from(cfg).accept(c.stream),
    )
    .await
    .map_err(|_| anyhow!("KCP TLS accept timeout"))??;
    let conn = tls.get_ref().1;
    tls::check_pq(conn)?;
    let peer = tls::peer_key(conn).ok_or_else(|| anyhow!("no peer key"))?;
    let lane = start_lane(
        c.lane,
        conn,
        |m| {
            conn.export_keying_material(m, tls::LANE_EXPORTER, None)
                .is_ok()
        },
        false,
    );
    Ok(Established {
        io: Box::new(tls),
        peer_key: peer,
        transport: Transport::KcpFecTls,
        remote: c.peer,
        bootstrap: c.gate.bootstrap(),
        meter: Some(Meter::Kcp(c.stats.clone())),
        kcp_stats: Some(c.stats),
        lane,
    })
}

// ---------------------------------------------------------------- inner identity for AnyTLS (§9.2)

/// Prove identity over an already-encrypted outer channel: each side signs
/// `label || exporter || role` with its identity key and checks the other's
/// signature (§9.2, AnyTLS).
pub async fn exchange_identity<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    exporter: &[u8; 32],
    kp: &KeyPair,
    initiator: bool,
    expected: Option<&[Bytes32]>,
    trust: &dyn PeerTrust,
) -> Result<Bytes32> {
    let my_role = if initiator { b'i' } else { b'r' };
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(webjet_core::crypto::ctx::ANYTLS_BIND.as_bytes());
    msg.extend_from_slice(exporter);
    msg.push(my_role);
    let sig = kp.sign_raw(&msg);
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&kp.public());
    out.extend_from_slice(&sig);
    io.write_all(&out).await?;
    io.flush().await?;
    let mut inb = [0u8; 96];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, io.read_exact(&mut inb))
        .await
        .map_err(|_| anyhow!("identity exchange timeout"))??;
    let (pk, psig) = inb.split_at(32);
    let (Ok(pk), Ok(psig)) = (<Bytes32>::try_from(pk), <[u8; 64]>::try_from(psig)) else {
        bail!("short identity message");
    };
    if let Some(last) = msg.last_mut() {
        *last = if initiator { b'r' } else { b'i' };
    }
    if !webjet_core::crypto::verify_raw(&pk, &msg, &psig) {
        bail!("bad identity signature");
    }
    if let Some(e) = expected
        && !e.contains(&pk)
    {
        bail!("peer presented an unexpected key");
    }
    if !trust.trusted(&pk) {
        bail!("peer key is not trusted");
    }
    Ok(pk)
}

/// Derive a 32-byte value from an exporter secret (for testability).
pub fn bind_value(exporter: &[u8]) -> [u8; 32] {
    keyed(&[0x42; 32], exporter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::Epochs;
    use crate::tls::TrustAll;

    fn epochs() -> SharedEpochs {
        let mut e = Epochs::default();
        e.keys.insert(4, [4; 32]);
        e.current = 4;
        Arc::new(parking_lot::RwLock::new(e))
    }

    #[test]
    fn records_over_the_limit_are_not_encoded() {
        let r = encode_record(rec::CONTROL, &[1; MAX_RECORD]).unwrap();
        assert_eq!(r.len(), 4 + MAX_RECORD);
        assert!(encode_record(rec::CONTROL, &vec![1; MAX_RECORD + 1]).is_none());
        // Past 16 MiB the length wouldn't fit: never mis-framed.
        assert!(encode_record(rec::RELAY, &vec![0; 1 << 24]).is_none());
    }

    #[test]
    fn records_built_in_place_match_encoded_ones() {
        let mut buf = vec![0, 0, 0, 0, 9, 8, 7];
        assert!(seal_record(rec::RELAY, &mut buf));
        assert_eq!(buf, encode_record(rec::RELAY, &[9, 8, 7]).unwrap());
        // An empty payload, too short a buffer, too long a payload.
        let mut empty = vec![0; RECORD_HEADER];
        assert!(seal_record(rec::PAD, &mut empty));
        assert_eq!(empty, [rec::PAD, 0, 0, 0]);
        let mut short = vec![1, 2, 3];
        assert!(!seal_record(rec::RELAY, &mut short));
        assert_eq!(short, [1, 2, 3]);
        let mut big = vec![0; RECORD_HEADER + MAX_RECORD + 1];
        assert!(!seal_record(rec::RELAY, &mut big));
        assert_eq!(big[0], 0);
    }

    #[tokio::test]
    async fn a_record_read_whole_keeps_its_header() {
        let mut wire = encode_record(rec::RELAY, b"frame").unwrap();
        wire.extend(encode_record(rec::CONTROL, b"").unwrap());
        let mut r = &wire[..];
        let (ty, rec1) = read_record_buf(&mut r).await.unwrap();
        assert_eq!(
            (ty, &rec1[..]),
            (
                rec::RELAY,
                &encode_record(rec::RELAY, b"frame").unwrap()[..]
            )
        );
        let (ty, rec2) = read_record_buf(&mut r).await.unwrap();
        assert_eq!((ty, rec2.len()), (rec::CONTROL, RECORD_HEADER));
        let mut over = vec![rec::RELAY, 0x10, 0, 1];
        over.extend([0; 8]);
        assert!(read_record_buf(&mut &over[..]).await.is_err());
    }

    #[tokio::test]
    async fn tls_hop() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let l = TlsListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = l.listener.local_addr().unwrap();
        let bk = b.clone();
        let ep = epochs();
        let srv = tokio::spawn(async move {
            let (s, r) = l.listener.accept().await.unwrap();
            match accept_tls(s, r, &bk, Arc::new(TrustAll), &ep, &l.replay, None)
                .await
                .unwrap()
            {
                Accepted::Hop(mut h) => {
                    let (t, p) = read_record(&mut h.io).await.unwrap();
                    write_record(&mut h.io, t, &p).await.unwrap();
                    h.peer_key
                }
                _ => panic!(),
            }
        });
        let mut h = dial_tls(addr, &a, vec![b.public()], Arc::new(TrustAll), 4, &[4; 32])
            .await
            .unwrap();
        write_record(&mut h.io, rec::CONTROL, b"ping")
            .await
            .unwrap();
        let (t, p) = read_record(&mut h.io).await.unwrap();
        assert_eq!((t, &p[..]), (rec::CONTROL, &b"ping"[..]));
        assert_eq!(srv.await.unwrap(), a.public());
    }

    #[tokio::test]
    async fn tls_gate_rejects_wrong_psk() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let l = TlsListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = l.listener.local_addr().unwrap();
        let ep = epochs();
        let bk = b.clone();
        tokio::spawn(async move {
            let (s, r) = l.listener.accept().await.unwrap();
            assert!(
                accept_tls(s, r, &bk, Arc::new(TrustAll), &ep, &l.replay, None)
                    .await
                    .is_err()
            );
        });
        assert!(
            dial_tls(addr, &a, vec![b.public()], Arc::new(TrustAll), 4, &[5; 32])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn kcp_hop() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let ea = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), false)
            .await
            .unwrap();
        let eb = UdpEndpoint::bind("127.0.0.1:0".parse().unwrap(), &[1; 32], epochs(), true)
            .await
            .unwrap();
        let addr = eb.local_addr().unwrap();
        let bk = b.clone();
        let srv = tokio::spawn(async move {
            let c = eb.accept_rx.lock().await.recv().await.unwrap();
            let mut h = accept_kcp(c, &bk, Arc::new(TrustAll)).await.unwrap();
            let (t, p) = read_record(&mut h.io).await.unwrap();
            write_record(&mut h.io, t, &p).await.unwrap();
            h.io.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let mut h = dial_kcp(&ea, addr, &a, vec![b.public()], Arc::new(TrustAll))
            .await
            .unwrap();
        write_record(&mut h.io, rec::RELAY, &[7; 3000])
            .await
            .unwrap();
        h.io.flush().await.unwrap();
        let (t, p) = read_record(&mut h.io).await.unwrap();
        assert_eq!(t, rec::RELAY);
        assert_eq!(p, vec![7; 3000]);
        srv.await.unwrap();
    }
}
