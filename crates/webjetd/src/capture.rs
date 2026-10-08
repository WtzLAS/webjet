//! Capture (§9.5.2): broadcasts and multicasts the host sends out its other
//! interfaces, copied into the overlay.
//!
//! A game that sends its LAN discovery to 255.255.255.255 without choosing
//! an interface has it sent out one interface only: the default route's on
//! Linux and macOS, the lowest-metric broadcast route's on Windows, which
//! is the LAN, not the overlay. Capture sees those datagrams leave, without
//! taking them from the LAN (local players still see the game), and hands
//! them to the overlay's fan-out with this node's overlay address as the
//! source, so the peers' unicast replies come back through the overlay.
//!
//! Only UDP to the ports in `[multicast] capture` (none by default), only
//! from this host's own addresses, never mDNS, SSDP, LLMNR, NetBIOS or
//! DHCP. Everything after that is the overlay's (policy, budget, echoes),
//! plus one check: a datagram the app also sent into the tun interface goes
//! out once.
//!
//! - Linux: a packet socket on every interface, with a kernel filter for
//!   outgoing UDP to the captured ports (CAP_NET_RAW).
//! - macOS: a BPF device per Ethernet/Wi-Fi interface, with a kernel filter
//!   for UDP to the captured ports.
//! - Windows: a raw socket bound to 127.0.0.1, which sees the limited
//!   broadcasts the host sends (the WinIPBroadcast technique); no driver.

use crate::dataplane::Dataplane;
use crate::node::Node;
use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use webjet_core::multicast::{self as mc, CapturePorts};

/// How often the configuration and the interfaces are looked at.
const CHECK_EVERY: Duration = Duration::from_secs(5);
/// How long a failed start (no permission, no BPF device) waits before the
/// next try with the same settings.
const RETRY_AFTER: Duration = Duration::from_secs(60);
/// The capture threads' read timeout: how soon they notice they're stopped.
const READ_TIMEOUT: Duration = Duration::from_millis(500);
/// Captured datagrams waiting for the overlay; more are dropped.
const QUEUE: usize = 1024;

/// What capture runs with; a change restarts it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Want {
    ports: CapturePorts,
    /// The interfaces to open (macOS; empty elsewhere).
    ifaces: Vec<String>,
}

/// Running capture threads; dropping it stops them.
struct Running {
    want: Want,
    stop: Arc<AtomicBool>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// This host's IPv4 addresses and networks on interfaces other than the
/// overlay's and loopback.
fn lan(dev: &str) -> (Vec<IpAddr>, Vec<IpNet>) {
    let mut addrs = Vec::new();
    let mut nets = Vec::new();
    for i in if_addrs::get_if_addrs().unwrap_or_default() {
        if i.is_loopback() || i.name == dev || crate::nat::is_overlay_if(&i.name) {
            continue;
        }
        if let if_addrs::IfAddr::V4(a) = i.addr {
            addrs.push(IpAddr::V4(a.ip));
            if let Ok(n) = IpNet::new(IpAddr::V4(a.ip), a.prefixlen) {
                nets.push(n.trunc());
            }
        }
    }
    (addrs, nets)
}

/// The settings capture should run with now, or `None` for off.
fn wanted(n: &Node, dp: &Dataplane) -> Option<Want> {
    if !crate::multicast::on(n, dp) || dp.my_ip(false).is_none() {
        return None;
    }
    let specs = n.store.read().view().capture_ports(&n.me);
    let ports = CapturePorts::parse(&specs).ok()?;
    if ports.is_empty() {
        return None;
    }
    Some(Want {
        ports,
        ifaces: os::interfaces(&dp.dev_name),
    })
}

/// Run capture while the configuration asks for it (§9.5.2).
pub(crate) fn start(n: &Arc<Node>, dp: Arc<Dataplane>) {
    let weak = Arc::downgrade(n);
    n.tasks.service("multicast-capture", async move {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(QUEUE);
        let mut running: Option<Running> = None;
        let mut failed: Option<(Want, Instant)> = None;
        let mut lan_now = lan(&dp.dev_name);
        let mut tick = tokio::time::interval(CHECK_EVERY);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let Some(n) = weak.upgrade() else { return };
                    lan_now = lan(&dp.dev_name);
                    let want = wanted(&n, &dp);
                    if running.as_ref().map(|r| &r.want) == want.as_ref() {
                        continue;
                    }
                    running = None;
                    let Some(want) = want else {
                        n.clear_alarm("multicast_capture");
                        continue;
                    };
                    if failed.as_ref().is_some_and(|(w, at)| *w == want && at.elapsed() < RETRY_AFTER) {
                        continue;
                    }
                    let w = want.clone();
                    let tx2 = tx.clone();
                    let started = tokio::task::spawn_blocking(move || spawn(&w, tx2)).await;
                    match started {
                        Ok(Ok(stop)) => {
                            tracing::info!(ports = ?want.ports, "capturing broadcasts sent out other interfaces");
                            n.clear_alarm("multicast_capture");
                            failed = None;
                            running = Some(Running { want, stop });
                        }
                        Ok(Err(e)) => {
                            n.alarm(
                                "multicast_capture",
                                "warning",
                                format!("multicast.capture is set but capture could not start: {e}"),
                            );
                            failed = Some((want, Instant::now()));
                        }
                        Err(_) => {}
                    }
                }
                p = rx.recv() => {
                    let Some(p) = p else { return };
                    let Some(n) = weak.upgrade() else { return };
                    let Some(r) = &running else { continue };
                    let Some(me) = dp.my_ip(false) else { continue };
                    let Some(out) = mc::captured(&p, &r.want.ports, &lan_now.0, &lan_now.1, me) else {
                        continue;
                    };
                    let Some(parsed) = webjet_core::packet::parse(&out) else { continue };
                    crate::multicast::captured(&dp, &n, out, &parsed);
                }
            }
        }
    });
}

/// Open the OS capture and start its reader threads.
fn spawn(want: &Want, tx: mpsc::Sender<Vec<u8>>) -> anyhow::Result<Arc<AtomicBool>> {
    let sources = os::open(want)?;
    let stop = Arc::new(AtomicBool::new(false));
    for mut src in sources {
        let stop = stop.clone();
        let tx = tx.clone();
        std::thread::Builder::new()
            .name("webjet-capture".into())
            .spawn(move || {
                let mut out = Vec::new();
                while !stop.load(Ordering::SeqCst) && !tx.is_closed() {
                    if let Err(e) = src.read(&mut out) {
                        tracing::warn!("capture stopped: {e}");
                        return;
                    }
                    for p in out.drain(..) {
                        // Full: the overlay is behind (or a flood); drop.
                        let _ = tx.try_send(p);
                    }
                }
            })?;
    }
    Ok(stop)
}

/// One OS capture handle; `read` waits at most [`READ_TIMEOUT`] and appends
/// IPv4 packets (from the IP header on).
trait Source: Send {
    fn read(&mut self, out: &mut Vec<Vec<u8>>) -> std::io::Result<()>;
}

// ---------------------------------------------------------------- kernel filter

/// A classic BPF instruction: (code, jt, jf, k).
type Insn = (u16, u8, u8, u32);

const LD_W_ABS: u16 = 0x20;
const LD_H_ABS: u16 = 0x28;
const LD_B_ABS: u16 = 0x30;
const LD_H_IND: u16 = 0x48;
const LDX_B_MSH: u16 = 0xb1;
const JEQ_K: u16 = 0x15;
const JGT_K: u16 = 0x25;
const JGE_K: u16 = 0x35;
const JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;
/// Linux: the packet's direction (`SKF_AD_OFF + SKF_AD_PKTTYPE`).
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
const SKF_PKTTYPE: u32 = 0xffff_f004;
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
const PACKET_OUTGOING: u32 = 4;
/// Linux: the packet's protocol (`SKF_AD_OFF + SKF_AD_PROTOCOL`).
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
const SKF_PROTOCOL: u32 = 0xffff_f000;

/// Accept unfragmented IPv4 UDP datagrams to one of `ranges`. `eth`: the
/// packet starts with an Ethernet header (macOS BPF), else with the IP
/// header (Linux packet socket, which also checks the direction).
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", test)),
    allow(dead_code)
)]
fn filter(eth: bool, outgoing: bool, ranges: &[(u16, u16)]) -> Vec<Insn> {
    let ip = if eth { 14 } else { 0 };
    // The checks before the port ranges; each jumps to "drop" on failure.
    let mut pre: Vec<(u16, u32, u32, bool)> = Vec::new(); // (load, at, value, jset)
    if outgoing {
        // A socket for every protocol (only those see outgoing packets).
        pre.push((LD_W_ABS, SKF_PKTTYPE, PACKET_OUTGOING, false));
        pre.push((LD_W_ABS, SKF_PROTOCOL, 0x0800, false));
    }
    if eth {
        pre.push((LD_H_ABS, 12, 0x0800, false));
    }
    pre.push((LD_B_ABS, ip + 9, 17, false));
    // Not a fragment: no "more fragments" flag, offset 0.
    pre.push((LD_H_ABS, ip + 6, 0x3fff, true));
    let ranges = &ranges[..ranges.len().min(100)];
    // Layout: pre (2 each), ldxb, ldh dport, ranges (2 each), drop, accept.
    let total = pre.len() * 2 + 2 + ranges.len() * 2 + 2;
    let drop_at = total - 2;
    let accept_at = total - 1;
    let mut v: Vec<Insn> = Vec::with_capacity(total);
    for (load, at, value, jset) in pre {
        v.push((load, 0, 0, at));
        let here = v.len();
        let to_drop = (drop_at - here - 1) as u8;
        if jset {
            v.push((JSET_K, to_drop, 0, value));
        } else {
            v.push((JEQ_K, 0, to_drop, value));
        }
    }
    v.push((LDX_B_MSH, 0, 0, ip));
    v.push((LD_H_IND, 0, 0, ip + 2));
    for &(lo, hi) in ranges {
        // port >= lo ? (port > hi ? next : accept) : next
        let here = v.len();
        v.push((JGE_K, 0, 1, u32::from(lo)));
        let next = v.len();
        v.push((JGT_K, 0, (accept_at - next - 1) as u8, u32::from(hi)));
        debug_assert_eq!(v.len(), here + 2);
    }
    v.push((RET_K, 0, 0, 0));
    v.push((RET_K, 0, 0, 65535));
    v
}

// ---------------------------------------------------------------- Linux

#[cfg(target_os = "linux")]
mod os {
    use super::*;
    use socket2::{Domain, Protocol, SockFilter, Socket, Type};
    use std::io::Read;

    pub(super) fn interfaces(_dev: &str) -> Vec<String> {
        Vec::new()
    }

    struct Packet(Socket);

    impl Source for Packet {
        fn read(&mut self, out: &mut Vec<Vec<u8>>) -> std::io::Result<()> {
            let mut buf = vec![0u8; 65536];
            match (&self.0).read(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    out.push(buf);
                    Ok(())
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    }

    pub(super) fn open(want: &Want) -> anyhow::Result<Vec<Box<dyn Source>>> {
        // ETH_P_ALL: the kernel shows outgoing packets only to sockets for
        // every protocol; the filter keeps IPv4.
        let proto = i32::from((libc::ETH_P_ALL as u16).to_be());
        let s = Socket::new(Domain::PACKET, Type::DGRAM, Some(Protocol::from(proto)))
            .map_err(|e| anyhow::anyhow!("packet socket: {e} (needs CAP_NET_RAW)"))?;
        let prog: Vec<SockFilter> = filter(false, true, want.ports.ranges())
            .into_iter()
            .map(|(c, t, f, k)| SockFilter::new(c, t, f, k))
            .collect();
        s.attach_filter(&prog)?;
        s.set_read_timeout(Some(READ_TIMEOUT))?;
        // Datagrams queued before the filter was attached: drop them.
        s.set_nonblocking(true)?;
        let mut junk = [0u8; 2048];
        while (&s).read(&mut junk).is_ok() {}
        s.set_nonblocking(false)?;
        Ok(vec![Box::new(Packet(s))])
    }
}

// ---------------------------------------------------------------- macOS

#[cfg(target_os = "macos")]
mod os {
    use super::*;

    const BIOCSBLEN: libc::c_ulong = 0xc004_4266;
    const BIOCSETIF: libc::c_ulong = 0x8020_426c;
    const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270;
    const BIOCGDLT: libc::c_ulong = 0x4004_426a;
    const BIOCSETF: libc::c_ulong = 0x8010_4267;
    const BIOCSRTIMEOUT: libc::c_ulong = 0x8010_426d;
    const DLT_EN10MB: u32 = 1;
    const BUF: usize = 1 << 16;

    #[repr(C)]
    struct BpfInsn {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct BpfProgram {
        len: libc::c_uint,
        insns: *const BpfInsn,
    }

    /// Ethernet and Wi-Fi interfaces with an IPv4 address (not the
    /// overlay's, not other tunnels).
    pub(super) fn interfaces(dev: &str) -> Vec<String> {
        let mut v: Vec<String> = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .filter(|i| {
                !i.is_loopback()
                    && i.name != dev
                    && !crate::nat::is_overlay_if(&i.name)
                    && !["utun", "ipsec", "ppp", "gif", "stf", "awdl", "llw"]
                        .iter()
                        .any(|p| i.name.starts_with(p))
                    && matches!(i.addr, if_addrs::IfAddr::V4(_))
            })
            .map(|i| i.name)
            .collect();
        v.sort();
        v.dedup();
        v
    }

    struct Bpf {
        fd: libc::c_int,
        buf: Vec<u8>,
    }

    impl Drop for Bpf {
        fn drop(&mut self) {
            // SAFETY: fd is ours and open.
            unsafe { libc::close(self.fd) };
        }
    }

    fn ioctl<T>(fd: libc::c_int, req: libc::c_ulong, arg: *mut T) -> std::io::Result<()> {
        // SAFETY: each request is given the argument type it is defined for.
        if unsafe { libc::ioctl(fd, req, arg) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn open_dev() -> std::io::Result<libc::c_int> {
        let mut last = std::io::Error::from(std::io::ErrorKind::NotFound);
        for i in 0..256 {
            let path = std::ffi::CString::new(format!("/dev/bpf{i}")).unwrap_or_default();
            // SAFETY: a valid C string.
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
            if fd >= 0 {
                return Ok(fd);
            }
            last = std::io::Error::last_os_error();
            if last.raw_os_error() != Some(libc::EBUSY) {
                break;
            }
        }
        Err(last)
    }

    fn open_if(name: &str, prog: &[BpfInsn]) -> std::io::Result<Option<Bpf>> {
        let fd = open_dev()?;
        let b = Bpf {
            fd,
            buf: vec![0; BUF],
        };
        let mut blen: libc::c_uint = BUF as libc::c_uint;
        ioctl(fd, BIOCSBLEN, &mut blen)?;
        let mut ifr = [0u8; 32];
        let n = name.as_bytes();
        if n.len() >= 16 {
            return Ok(None);
        }
        ifr[..n.len()].copy_from_slice(n);
        ioctl(fd, BIOCSETIF, ifr.as_mut_ptr())?;
        let mut dlt: libc::c_uint = 0;
        ioctl(fd, BIOCGDLT, &mut dlt)?;
        if dlt != DLT_EN10MB {
            return Ok(None);
        }
        let mut one: libc::c_uint = 1;
        ioctl(fd, BIOCIMMEDIATE, &mut one)?;
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: READ_TIMEOUT.as_micros() as libc::suseconds_t,
        };
        ioctl(fd, BIOCSRTIMEOUT, &mut tv)?;
        let mut p = BpfProgram {
            len: prog.len() as libc::c_uint,
            insns: prog.as_ptr(),
        };
        ioctl(fd, BIOCSETF, &mut p)?;
        Ok(Some(b))
    }

    impl Source for Bpf {
        fn read(&mut self, out: &mut Vec<Vec<u8>>) -> std::io::Result<()> {
            // SAFETY: buf is BUF bytes long, the length BIOCSBLEN set.
            let n = unsafe { libc::read(self.fd, self.buf.as_mut_ptr().cast(), self.buf.len()) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                return match e.kind() {
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock => Ok(()),
                    _ => Err(e),
                };
            }
            out.extend(super::bpf_records(&self.buf[..n as usize]));
            Ok(())
        }
    }

    pub(super) fn open(want: &Want) -> anyhow::Result<Vec<Box<dyn Source>>> {
        let prog: Vec<BpfInsn> = filter(true, false, want.ports.ranges())
            .into_iter()
            .map(|(code, jt, jf, k)| BpfInsn { code, jt, jf, k })
            .collect();
        let mut v: Vec<Box<dyn Source>> = Vec::new();
        for name in &want.ifaces {
            match open_if(name, &prog) {
                Ok(Some(b)) => v.push(Box::new(b)),
                Ok(None) => {}
                Err(e) => anyhow::bail!("BPF on {name}: {e}"),
            }
        }
        if v.is_empty() {
            anyhow::bail!("no Ethernet or Wi-Fi interface to capture on");
        }
        Ok(v)
    }
}

/// The IPv4 packets in a macOS BPF read buffer: `bpf_hdr` records (caplen
/// at 8, hdrlen at 16), each padded to 4 bytes, holding Ethernet frames.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn bpf_records(buf: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 18 <= buf.len() {
        let u32_at = |i: usize| u32::from_ne_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        let caplen = u32_at(off + 8) as usize;
        let hdrlen = usize::from(u16::from_ne_bytes([buf[off + 16], buf[off + 17]]));
        let start = off + hdrlen;
        let Some(frame) = buf.get(start..start + caplen) else {
            break;
        };
        if frame.len() > 14 && frame[12..14] == [0x08, 0x00] {
            out.push(frame[14..].to_vec());
        }
        let next = (hdrlen + caplen + 3) & !3;
        if next == 0 {
            break;
        }
        off += next;
    }
    out
}

// ---------------------------------------------------------------- Windows

#[cfg(windows)]
mod os {
    use super::*;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::io::Read;

    pub(super) fn interfaces(_dev: &str) -> Vec<String> {
        Vec::new()
    }

    /// A raw UDP socket on 127.0.0.1 sees the limited broadcasts this host
    /// sends, whichever interface Windows sends them out of.
    struct Loopback(Socket);

    impl Source for Loopback {
        fn read(&mut self, out: &mut Vec<Vec<u8>>) -> std::io::Result<()> {
            let mut buf = vec![0u8; 65536];
            match (&self.0).read(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    // Only broadcasts; TTL 1 marks WinIPBroadcast's relays.
                    if n >= 28 && buf[16..20] == [255; 4] && buf[8] > 1 {
                        out.push(buf);
                    }
                    Ok(())
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    }

    pub(super) fn open(_want: &Want) -> anyhow::Result<Vec<Box<dyn Source>>> {
        let s = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))
            .map_err(|e| anyhow::anyhow!("raw socket: {e} (needs administrator rights)"))?;
        let lo = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        s.bind(&lo.into())?;
        s.set_read_timeout(Some(READ_TIMEOUT))?;
        Ok(vec![Box::new(Loopback(s))])
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod os {
    use super::*;

    pub(super) fn interfaces(_dev: &str) -> Vec<String> {
        Vec::new()
    }

    pub(super) fn open(_want: &Want) -> anyhow::Result<Vec<Box<dyn Source>>> {
        anyhow::bail!("capture is not supported on this system")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webjet_core::testutil::packets::udp4;

    /// A classic BPF interpreter for the instructions `filter` uses.
    fn run(prog: &[Insn], p: &[u8], pkttype: u32) -> bool {
        run_proto(prog, p, pkttype, 0x0800)
    }

    fn run_proto(prog: &[Insn], p: &[u8], pkttype: u32, proto: u32) -> bool {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let byte = |i: usize| p.get(i).copied().map(u32::from);
        loop {
            let (code, jt, jf, k) = prog[pc];
            pc += 1;
            let k_us = k as usize;
            match code {
                LD_W_ABS if k == SKF_PKTTYPE => a = pkttype,
                LD_W_ABS if k == SKF_PROTOCOL => a = proto,
                LD_H_ABS => match (byte(k_us), byte(k_us + 1)) {
                    (Some(h), Some(l)) => a = h << 8 | l,
                    _ => return false,
                },
                LD_B_ABS => match byte(k_us) {
                    Some(b) => a = b,
                    None => return false,
                },
                LD_H_IND => match (byte(x as usize + k_us), byte(x as usize + k_us + 1)) {
                    (Some(h), Some(l)) => a = h << 8 | l,
                    _ => return false,
                },
                LDX_B_MSH => match byte(k_us) {
                    Some(b) => x = 4 * (b & 0xf),
                    None => return false,
                },
                JEQ_K | JGT_K | JGE_K | JSET_K => {
                    let taken = match code {
                        JEQ_K => a == k,
                        JGT_K => a > k,
                        JGE_K => a >= k,
                        _ => a & k != 0,
                    };
                    pc += usize::from(if taken { jt } else { jf });
                }
                RET_K => return k != 0,
                _ => panic!("unexpected instruction {code:#x}"),
            }
        }
    }

    #[test]
    fn the_kernel_filter() {
        let ranges = [(4000, 4010), (19132, 19132)];
        let ping = udp4(
            [192, 168, 1, 5],
            [255, 255, 255, 255],
            50000,
            19132,
            b"ping",
        );
        let lin = filter(false, true, &ranges);
        assert!(run(&lin, &ping, PACKET_OUTGOING));
        assert!(!run(&lin, &ping, 0), "incoming");
        assert!(!run_proto(&lin, &ping, PACKET_OUTGOING, 0x86dd), "not IPv4");
        for port in [3999, 4011, 19131, 19133, 53] {
            let p = udp4([192, 168, 1, 5], [255, 255, 255, 255], 50000, port, b"x");
            assert!(!run(&lin, &p, PACKET_OUTGOING), "{port}");
        }
        for port in [4000, 4005, 4010] {
            let p = udp4([192, 168, 1, 5], [255, 255, 255, 255], 50000, port, b"x");
            assert!(run(&lin, &p, PACKET_OUTGOING), "{port}");
        }
        let mut tcp = ping.clone();
        tcp[9] = 6;
        assert!(!run(&lin, &tcp, PACKET_OUTGOING));
        let mut frag = ping.clone();
        frag[6] = 0x20; // more fragments
        assert!(!run(&lin, &frag, PACKET_OUTGOING));
        // IP options move the UDP header: the port is still found.
        let mut opts = ping[..20].to_vec();
        opts[0] = 0x46;
        opts.extend_from_slice(&[1, 1, 1, 0]);
        opts.extend_from_slice(&ping[20..]);
        assert!(run(&lin, &opts, PACKET_OUTGOING));
        // macOS: an Ethernet frame, any direction.
        let mac = filter(true, false, &ranges);
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[2, 0, 0, 0, 0, 1, 0x08, 0x00]);
        frame.extend_from_slice(&ping);
        assert!(run(&mac, &frame, 0));
        frame[12] = 0x86; // IPv6
        frame[13] = 0xdd;
        assert!(!run(&mac, &frame, 0));
        // Many ranges still jump within reach.
        let many: Vec<(u16, u16)> = (0..100).map(|i| (1000 + i * 10, 1000 + i * 10)).collect();
        let big = filter(false, true, &many);
        let p = udp4([192, 168, 1, 5], [255, 255, 255, 255], 1, 1990, b"x");
        assert!(run(&big, &p, PACKET_OUTGOING));
    }

    #[test]
    fn bpf_buffers() {
        let ping = udp4(
            [192, 168, 1, 5],
            [255, 255, 255, 255],
            50000,
            19132,
            b"ping",
        );
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[2, 0, 0, 0, 0, 1, 0x08, 0x00]);
        frame.extend_from_slice(&ping);
        let mut buf = Vec::new();
        for _ in 0..2 {
            let mut h = vec![0u8; 18];
            h[8..12].copy_from_slice(&(frame.len() as u32).to_ne_bytes());
            h[12..16].copy_from_slice(&(frame.len() as u32).to_ne_bytes());
            h[16..18].copy_from_slice(&18u16.to_ne_bytes());
            buf.extend_from_slice(&h);
            buf.extend_from_slice(&frame);
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
        }
        let got = bpf_records(&buf);
        assert_eq!(got, vec![ping.clone(), ping]);
        assert!(bpf_records(&buf[..30]).is_empty());
    }
}
