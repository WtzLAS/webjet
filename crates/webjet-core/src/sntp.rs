//! A minimal SNTP client (RFC 4330), only to tell a user that the
//! computer's clock is wrong (§18.6). Webjet never sets the clock from it.
//!
//! A node more than a minute off is dropped without an answer at every
//! PSK gate, so it learns nothing about the time from the network itself.

use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Asked when nothing else is configured: anycast or large pools, with one
/// that answers well from mainland China.
pub const SERVERS: &[&str] = &[
    "time.cloudflare.com",
    "ntp.aliyun.com",
    "time.windows.com",
    "pool.ntp.org",
];

/// How long to wait for the servers' answers.
pub const TIMEOUT: Duration = Duration::from_secs(3);

/// Seconds from 1900 (NTP's epoch) to 1970.
const NTP_UNIX: u64 = 2_208_988_800;

/// What the servers said about this computer's clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offset {
    /// The first server that answered.
    pub server: String,
    /// How far this computer's clock is ahead of the servers' (negative:
    /// behind), the median over the servers that answered.
    pub ahead_ms: i64,
    /// How many servers answered.
    pub answers: usize,
}

impl Offset {
    /// "this computer's clock is 8 h 0 min ahead (time.cloudflare.com and 2 more)"
    pub fn describe(&self) -> String {
        let more = match self.answers {
            0 | 1 => String::new(),
            n => format!(" and {} more", n - 1),
        };
        let dir = if self.ahead_ms >= 0 {
            "ahead"
        } else {
            "behind"
        };
        format!(
            "this computer's clock is {} {dir} of the time servers ({}{more})",
            span(self.ahead_ms.unsigned_abs() / 1000),
            self.server
        )
    }
}

fn span(s: u64) -> String {
    match s {
        0..120 => format!("{s} s"),
        120..7200 => format!("{} min", s / 60),
        7200..172_800 => format!("{} h {} min", s / 3600, s / 60 % 60),
        _ => format!("{} days", s / 86_400),
    }
}

/// How to set the clock right on this platform.
pub fn fix_hint() -> &'static str {
    if cfg!(windows) {
        "turn on Settings > Time & language > Date & time > Set time automatically, \
         or run `w32tm /resync /force` as Administrator"
    } else if cfg!(target_os = "macos") {
        "turn on System Settings > General > Date & Time > Set time and date automatically, \
         or run `sudo sntp -sS time.apple.com`"
    } else if cfg!(target_os = "freebsd") {
        "run `ntpdate -b pool.ntp.org` as root and enable ntpd (`sysrc ntpd_enable=YES`)"
    } else {
        "run `sudo timedatectl set-ntp true` (or `chronyc makestep` with chrony)"
    }
}

use crate::types::now_ms;

fn to_ntp(ms: u64) -> [u8; 8] {
    let secs = ms / 1000 + NTP_UNIX;
    // Rounded up, so that `from_ntp` (rounding down) gives `ms` back.
    let frac = ((ms % 1000) << 32).div_ceil(1000);
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&(secs as u32).to_be_bytes());
    b[4..].copy_from_slice(&(frac as u32).to_be_bytes());
    b
}

fn from_ntp(b: &[u8]) -> Option<u64> {
    let secs = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as u64;
    let frac = u32::from_be_bytes(b.get(4..8)?.try_into().ok()?) as u64;
    // Era 0 ends in 2036: timestamps below 1970 belong to era 1.
    let secs = if secs < NTP_UNIX {
        secs + (1 << 32)
    } else {
        secs
    };
    Some((secs - NTP_UNIX) * 1000 + ((frac * 1000) >> 32))
}

/// A client request carrying `t1` as its transmit timestamp; the server
/// echoes it, which ties the answer to this request.
pub fn request(t1_ms: u64) -> [u8; 48] {
    let mut p = [0u8; 48];
    p[0] = 0x23; // LI 0, version 4, mode 3 (client)
    p[40..48].copy_from_slice(&to_ntp(t1_ms));
    p
}

/// How far the local clock is ahead of the server's, from an answer to
/// `request(t1_ms)` received at `t4_ms`.
pub fn parse(resp: &[u8], t1_ms: u64, t4_ms: u64) -> Option<i64> {
    if resp.len() < 48 {
        return None;
    }
    let mode = resp[0] & 7;
    let stratum = resp[1];
    // A server answer, synchronized, not a kiss-o'-death; the originate
    // timestamp must be the transmit timestamp we sent.
    if mode != 4 || stratum == 0 || stratum > 15 || resp[24..32] != to_ntp(t1_ms) {
        return None;
    }
    let t2 = from_ntp(&resp[32..40])? as i64;
    let t3 = from_ntp(&resp[40..48])? as i64;
    let (t1, t4) = (t1_ms as i64, t4_ms as i64);
    // RFC 4330: offset = ((t2 - t1) + (t3 - t4)) / 2 is the server's clock
    // minus ours.
    Some(-((t2 - t1) + (t3 - t4)) / 2)
}

/// Ask one server; `None` on any failure.
pub fn query(server: &str, timeout: Duration) -> Option<i64> {
    let deadline = Instant::now() + timeout;
    // `host`, `host:port`, an IP address or `[v6]:port`.
    let addr = server
        .to_socket_addrs()
        .or_else(|_| (server, 123).to_socket_addrs())
        .ok()?
        .next()?;
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).ok()?;
    sock.connect(addr).ok()?;
    let t1 = now_ms();
    sock.send(&request(t1)).ok()?;
    let mut buf = [0u8; 128];
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        sock.set_read_timeout(Some(left.max(Duration::from_millis(1))))
            .ok()?;
        let n = sock.recv(&mut buf).ok()?;
        if let Some(o) = parse(&buf[..n], t1, now_ms()) {
            return Some(o);
        }
    }
}

/// Ask all `servers` at once and wait at most `timeout`. `None` when none
/// answered (no network, UDP 123 blocked, or no servers).
pub fn offset(servers: &[String], timeout: Duration) -> Option<Offset> {
    let (tx, rx) = mpsc::channel();
    for s in servers {
        let (tx, s) = (tx.clone(), s.clone());
        std::thread::spawn(move || {
            let r = query(&s, timeout);
            let _ = tx.send((s, r));
        });
    }
    drop(tx);
    let deadline = Instant::now() + timeout + Duration::from_millis(200);
    let mut got: Vec<(String, i64)> = Vec::new();
    for _ in servers {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match rx.recv_timeout(left) {
            Ok((s, Some(o))) => got.push((s, o)),
            Ok((_, None)) => {}
            Err(_) => break,
        }
    }
    let server = got.first()?.0.clone();
    let mut v: Vec<i64> = got.iter().map(|g| g.1).collect();
    v.sort();
    Some(Offset {
        server,
        ahead_ms: v[v.len() / 2],
        answers: v.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_round_trip() {
        for ms in [0u64, 1_760_000_000_123, 2_085_978_496_000 + 5_000] {
            assert_eq!(from_ntp(&to_ntp(ms)), Some(ms), "{ms}");
        }
    }

    fn answer(t1: u64, server_now: u64) -> [u8; 48] {
        let mut r = [0u8; 48];
        r[0] = 0x24; // version 4, mode 4 (server)
        r[1] = 2;
        r[24..32].copy_from_slice(&to_ntp(t1));
        r[32..40].copy_from_slice(&to_ntp(server_now));
        r[40..48].copy_from_slice(&to_ntp(server_now + 1));
        r
    }

    #[test]
    fn a_clock_ahead_gives_a_positive_offset() {
        let t1 = 1_760_000_000_000;
        // Our clock is 8 h ahead; 20 ms each way.
        let server = t1 - 8 * 3_600_000 + 20;
        let o = parse(&answer(t1, server), t1, t1 + 41).unwrap();
        assert!((o - 8 * 3_600_000).abs() <= 1, "{o}");
        // Behind.
        let server = t1 + 90_000 + 20;
        let o = parse(&answer(t1, server), t1, t1 + 41).unwrap();
        assert!((o + 90_000).abs() <= 1, "{o}");
    }

    #[test]
    fn foreign_and_unsynchronized_answers_are_ignored() {
        let t1 = 1_760_000_000_000;
        let mut a = answer(t1, t1);
        assert!(
            parse(&a, t1 + 1, t1 + 2).is_none(),
            "another request's answer"
        );
        a[1] = 0; // kiss-o'-death
        assert!(parse(&a, t1, t1 + 2).is_none());
        let mut a = answer(t1, t1);
        a[0] = 0x23; // a client packet
        assert!(parse(&a, t1, t1 + 2).is_none());
        assert!(parse(&a[..40], t1, t1 + 2).is_none());
    }

    /// Needs the internet: `cargo test -p webjet-core sntp -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn the_real_servers_answer() {
        let servers: Vec<String> = SERVERS.iter().map(|s| s.to_string()).collect();
        let o = offset(&servers, TIMEOUT).expect("no time server answered");
        println!("{o:?}: {}", o.describe());
        assert!(o.ahead_ms.abs() < 60_000, "{}", o.describe());
    }

    #[test]
    fn offsets_read_well() {
        let o = |ms| Offset {
            server: "time.example".into(),
            ahead_ms: ms,
            answers: 3,
        };
        assert_eq!(
            o(8 * 3_600_000).describe(),
            "this computer's clock is 8 h 0 min ahead of the time servers (time.example and 2 more)"
        );
        assert!(o(-95_000).describe().contains("95 s behind"));
        assert!(o(-30 * 60_000).describe().contains("30 min behind"));
        assert!(o(400 * 86_400_000).describe().contains("400 days ahead"));
    }
}
