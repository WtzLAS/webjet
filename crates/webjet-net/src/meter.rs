//! Raw link measurement (§11.2): RTT and loss taken from the transport
//! underneath a hop's byte stream, not from messages sent through it.
//!
//! A message written into the hop stream waits behind everything written
//! before it (the hop queue, the KCP send buffer and pacer, or the TCP send
//! buffer), so under load its round trip shows this node's own backlog, not
//! the path. These measurements come from the traffic the link carries
//! anyway, so no probe packets are needed:
//!
//! - UDP+KCP+FEC: the time from a data segment leaving the socket to its
//!   acknowledgement (which the peer sends ahead of its own paced data), and
//!   the datagram loss both ends count from FEC shard groups (§17.6).
//! - TCP+TLS and TCP+AnyTLS: the kernel's smoothed RTT and its retransmitted
//!   share of what it sent ([`TcpMeter`]).
//!
//! When the link is idle, the keepalives (§11.2) are the traffic.

use parking_lot::Mutex;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// What a link measured since the last [`Meter::take`].
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Sample {
    /// Mean and lowest RTT of the samples, in ms; `None` without samples.
    pub rtt_ms: Option<(f64, f64)>,
    /// Round-trip loss fraction, `None` when nothing was counted.
    pub loss: Option<f64>,
    /// Packets the loss figure covers.
    pub packets: u64,
}

impl Sample {
    pub fn is_empty(&self) -> bool {
        self.rtt_ms.is_none() && self.loss.is_none()
    }
}

/// RTT samples gathered between two reads.
#[derive(Debug, Default)]
pub struct RttAgg {
    count: u32,
    sum_ms: f64,
    min_ms: f64,
}

impl RttAgg {
    pub fn add(&mut self, ms: f64) {
        if !ms.is_finite() || ms < 0.0 {
            return;
        }
        if self.count == 0 || ms < self.min_ms {
            self.min_ms = ms;
        }
        self.count = self.count.saturating_add(1);
        self.sum_ms += ms;
    }

    /// Mean and minimum since the last call.
    pub fn take(&mut self) -> Option<(f64, f64)> {
        let r = (self.count > 0).then(|| (self.sum_ms / self.count as f64, self.min_ms));
        *self = RttAgg::default();
        r
    }
}

/// Delivered/expected counts of one direction, gathered between two reads.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Counts {
    pub received: u64,
    pub expected: u64,
}

impl Counts {
    pub fn add(&mut self, received: u64, expected: u64) {
        self.received = self.received.saturating_add(received.min(expected));
        self.expected = self.expected.saturating_add(expected);
    }

    pub fn loss(&self) -> Option<f64> {
        (self.expected > 0).then(|| {
            (self.expected - self.received.min(self.expected)) as f64 / self.expected as f64
        })
    }
}

/// Loss over a round trip: a packet and its answer must both get through.
pub fn round_trip_loss(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (None, None) => None,
        (a, b) => {
            let ok =
                (1.0 - a.unwrap_or(0.0).clamp(0.0, 1.0)) * (1.0 - b.unwrap_or(0.0).clamp(0.0, 1.0));
            Some(1.0 - ok)
        }
    }
}

/// A hop's raw measurement source.
#[derive(Clone)]
pub enum Meter {
    Kcp(Arc<crate::kcp::KcpStats>),
    Tcp(Arc<TcpMeter>),
}

impl Meter {
    /// What the transport measured since the last call.
    pub fn take(&self) -> Sample {
        match self {
            Meter::Kcp(s) => s.take_sample(),
            Meter::Tcp(t) => t.take_sample(),
        }
    }
}

// ---------------------------------------------------------------- TCP

/// The kernel's view of a TCP connection: the socket is read with
/// `TCP_INFO` (Linux), `TCP_CONNECTION_INFO` (macOS) or `SIO_TCP_INFO`
/// (Windows). Shared with the [`MeteredTcp`] stream that owns the socket;
/// once the stream is dropped, the meter reads nothing (the descriptor
/// number may already belong to another socket).
#[derive(Debug, Default)]
pub struct TcpMeter {
    sock: Mutex<Option<RawSock>>,
    /// Sent and retransmitted totals at the last read.
    last: Mutex<Option<(u64, u64)>>,
}

#[cfg(unix)]
type RawSock = std::os::fd::RawFd;
#[cfg(windows)]
type RawSock = std::os::windows::io::RawSocket;

/// The kernel's figures for one connection.
#[derive(Clone, Copy, Debug, PartialEq)]
struct TcpInfo {
    srtt_us: u64,
    /// Sent and retransmitted, in segments or bytes (both in one unit).
    sent: u64,
    retrans: u64,
    /// Units of `sent` per packet (1, or a typical segment size for bytes).
    per_packet: u64,
}

impl TcpMeter {
    pub fn take_sample(&self) -> Sample {
        let info = {
            let g = self.sock.lock();
            match *g {
                Some(s) => tcp_info(s),
                None => None,
            }
        };
        let Some(info) = info else {
            return Sample::default();
        };
        let mut last = self.last.lock();
        let (loss, sent) = match *last {
            Some((s0, r0)) if info.sent > s0 => {
                let sent = info.sent - s0;
                let re = info.retrans.saturating_sub(r0).min(sent);
                (Some(re as f64 / sent as f64), sent / info.per_packet)
            }
            _ => (None, 0),
        };
        *last = Some((info.sent, info.retrans));
        let rtt = (info.srtt_us > 0).then(|| {
            let ms = info.srtt_us as f64 / 1000.0;
            (ms, ms)
        });
        Sample {
            rtt_ms: rtt,
            loss,
            packets: sent,
        }
    }
}

/// A TCP stream whose kernel statistics a [`TcpMeter`] can read.
pub struct MeteredTcp {
    s: TcpStream,
    meter: Arc<TcpMeter>,
}

impl MeteredTcp {
    pub fn new(s: TcpStream) -> (MeteredTcp, Arc<TcpMeter>) {
        #[cfg(unix)]
        let raw = {
            use std::os::fd::AsRawFd;
            s.as_raw_fd()
        };
        #[cfg(windows)]
        let raw = {
            use std::os::windows::io::AsRawSocket;
            s.as_raw_socket()
        };
        let meter = Arc::new(TcpMeter {
            sock: Mutex::new(Some(raw)),
            last: Mutex::new(None),
        });
        (
            MeteredTcp {
                s,
                meter: meter.clone(),
            },
            meter,
        )
    }

    pub fn get_ref(&self) -> &TcpStream {
        &self.s
    }

    pub fn meter(&self) -> Meter {
        Meter::Tcp(self.meter.clone())
    }
}

impl Drop for MeteredTcp {
    fn drop(&mut self) {
        // Before the socket closes: a read in progress holds the lock.
        *self.meter.sock.lock() = None;
    }
}

impl AsyncRead for MeteredTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_read(cx, buf)
    }
}

impl AsyncWrite for MeteredTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.s).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.s).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.s).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.s.is_write_vectored()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn tcp_info(fd: RawSock) -> Option<TcpInfo> {
    // SAFETY: `fd` is a live socket (the caller holds the meter's lock,
    // which the owning stream clears before closing it), and `info` is a
    // properly sized, writable `tcp_info`.
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&mut info as *mut libc::tcp_info).cast(),
            &mut len,
        )
    };
    if r != 0 {
        return None;
    }
    Some(TcpInfo {
        srtt_us: u64::from(info.tcpi_rtt),
        sent: u64::from(info.tcpi_segs_out),
        retrans: u64::from(info.tcpi_total_retrans),
        per_packet: 1,
    })
}

/// `struct tcp_connection_info` from <netinet/tcp.h>. The libc crate's
/// copy declares the TFO bitfield as fifteen separate words, which puts
/// every counter after it at the wrong offset.
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Default)]
struct TcpConnectionInfo {
    state: u8,
    snd_wscale: u8,
    rcv_wscale: u8,
    pad1: u8,
    options: u32,
    flags: u32,
    rto: u32,
    maxseg: u32,
    snd_ssthresh: u32,
    snd_cwnd: u32,
    snd_wnd: u32,
    snd_sbbytes: u32,
    rcv_wnd: u32,
    rttcur: u32,
    /// Smoothed RTT, ms.
    srtt: u32,
    rttvar: u32,
    tfo_bits: u32,
    txpackets: u64,
    txbytes: u64,
    txretransmitbytes: u64,
    rxpackets: u64,
    rxbytes: u64,
    rxoutoforderbytes: u64,
    txretransmitpackets: u64,
}

#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::size_of::<TcpConnectionInfo>() == 112);

#[cfg(target_os = "macos")]
fn tcp_info(fd: RawSock) -> Option<TcpInfo> {
    let mut info = TcpConnectionInfo::default();
    let mut len = std::mem::size_of::<TcpConnectionInfo>() as libc::socklen_t;
    // SAFETY: as on Linux; `info` has the layout TCP_CONNECTION_INFO fills.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONNECTION_INFO,
            (&mut info as *mut TcpConnectionInfo).cast(),
            &mut len,
        )
    };
    if r != 0 || (len as usize) < std::mem::size_of::<TcpConnectionInfo>() {
        return None;
    }
    Some(TcpInfo {
        srtt_us: u64::from(info.srtt) * 1000,
        sent: info.txpackets,
        retrans: info.txretransmitpackets,
        per_packet: 1,
    })
}

#[cfg(windows)]
fn tcp_info(sock: RawSock) -> Option<TcpInfo> {
    use windows_sys::Win32::Networking::WinSock::{SIO_TCP_INFO, TCP_INFO_v0, WSAIoctl};
    let version: u32 = 0;
    // SAFETY: `sock` is a live socket (see the Linux version); the buffers
    // are properly sized, and no overlapped I/O is requested.
    let mut info: TCP_INFO_v0 = unsafe { std::mem::zeroed() };
    let mut got: u32 = 0;
    let r = unsafe {
        WSAIoctl(
            sock as usize,
            SIO_TCP_INFO,
            (&version as *const u32).cast(),
            std::mem::size_of::<u32>() as u32,
            (&mut info as *mut TCP_INFO_v0).cast(),
            std::mem::size_of::<TCP_INFO_v0>() as u32,
            &mut got,
            std::ptr::null_mut(),
            None,
        )
    };
    if r != 0 {
        return None;
    }
    Some(TcpInfo {
        srtt_us: u64::from(info.RttUs),
        sent: info.BytesOut,
        retrans: u64::from(info.BytesRetrans),
        per_packet: u64::from(info.Mss.max(536)),
    })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
)))]
fn tcp_info(_: RawSock) -> Option<TcpInfo> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn rtt_aggregate() {
        let mut a = RttAgg::default();
        assert_eq!(a.take(), None);
        for ms in [10.0, 30.0, 20.0, f64::NAN, -1.0] {
            a.add(ms);
        }
        assert_eq!(a.take(), Some((20.0, 10.0)));
        assert_eq!(a.take(), None, "taken");
    }

    #[test]
    fn loss_counts_and_round_trip() {
        let mut c = Counts::default();
        assert_eq!(c.loss(), None);
        c.add(90, 100);
        c.add(10, 0); // nothing expected: no more received either
        assert_eq!(c.loss(), Some(0.1));
        assert_eq!(round_trip_loss(None, None), None);
        assert_eq!(round_trip_loss(Some(0.1), None), Some(0.09999999999999998));
        let rt = round_trip_loss(Some(0.1), Some(0.5)).unwrap();
        assert!((rt - 0.55).abs() < 1e-9, "{rt}");
    }

    #[tokio::test]
    async fn tcp_meter_reads_the_kernel() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 1024];
            loop {
                match s.read(&mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => s.write_all(&b[..n]).await.unwrap(),
                }
            }
        });
        let (mut s, meter) = MeteredTcp::new(TcpStream::connect(addr).await.unwrap());
        let mut b = [0u8; 100];
        for _ in 0..20 {
            s.write_all(&[1; 100]).await.unwrap();
            s.read_exact(&mut b).await.unwrap();
        }
        let first = meter.take_sample();
        if cfg!(any(target_os = "linux", target_os = "macos", windows)) {
            let (rtt, _) = first.rtt_ms.expect("kernel RTT");
            assert!(rtt < 50.0, "loopback RTT {rtt} ms");
        }
        for _ in 0..5 {
            s.write_all(&[1; 100]).await.unwrap();
            s.read_exact(&mut b).await.unwrap();
        }
        if cfg!(any(target_os = "linux", target_os = "macos", windows)) {
            assert_eq!(
                meter.take_sample().loss,
                Some(0.0),
                "loopback loses nothing"
            );
        }
        drop(s);
        assert_eq!(meter.take_sample(), Sample::default(), "closed");
        echo.await.unwrap();
    }
}
