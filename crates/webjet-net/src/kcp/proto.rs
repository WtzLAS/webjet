//! The KCP protocol (ARQ), adapted from the `kcp` crate 0.6.0
//! (<https://github.com/Matrix-Zhang/kcp>, itself a port of
//! <https://github.com/skywind3000/kcp>) for Webjet's KCP hops (§17.5).
//!
//! ```text
//! MIT License
//!
//! Copyright (c) 2017 Zhang Cheng
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//! SOFTWARE.
//! ```
//!
//! The wire format is unchanged: 24-byte little-endian segment headers
//! (`conv cmd frg wnd ts sn una len`), commands PUSH, ACK, WASK and WINS,
//! so it talks to the crate it came from. What changed:
//!
//! - **Stream mode only**, with the settings every hop uses: no-delay,
//!   10 ms RTO interval term, fast resend after 2 duplicate ACKs (at most 5
//!   times per segment), no congestion window. Rate control is the
//!   session's BBR-style pacer (§17.5), not KCP.
//! - **Pacing inside the flush.** [`Kcp::flush`] takes a byte budget: due
//!   retransmissions go first, then new data while the budget and the
//!   window allow. Data that can't go stays in the send queue, which the
//!   session keeps short, so a backlog waits in the hop queue where fair
//!   queueing and CoDel see it (§17.2) rather than in a pacer queue.
//! - **The send queue knows its age** ([`Kcp::backlog_age`]): every queued
//!   byte keeps the time it arrived, and the hop queue's CoDel counts that
//!   wait too (§17.7).
//! - **Acknowledgements are output on their own** ([`Output::control`]),
//!   so the session can send them at once, past FEC and the pacer.
//! - **Measurements from the protocol itself:** the raw round trip of each
//!   new segment (socket to acknowledgement, less the time the peer held
//!   it; Karn's rule), bytes delivered, and retransmissions.
//! - No panics, unwraps or unsafe code; sequence numbers and timestamps
//!   wrap by design and use wrapping arithmetic.

use std::collections::VecDeque;
use std::time::Duration;

/// Segment header size.
pub const OVERHEAD: usize = 24;

const CMD_PUSH: u8 = 81;
const CMD_ACK: u8 = 82;
const CMD_WASK: u8 = 83;
const CMD_WINS: u8 = 84;

const ASK_SEND: u32 = 1;
const ASK_TELL: u32 = 2;

/// Minimum RTO in no-delay mode, and the RTO bounds, in ms.
const RTO_MIN: u32 = 30;
const RTO_DEF: u32 = 200;
const RTO_MAX: u32 = 60_000;
/// The update interval term of the RTO, ms.
const INTERVAL: u32 = 10;
/// Duplicate acknowledgements that trigger a fast resend, and how often a
/// segment may be fast-resent.
const FAST_RESEND: u32 = 2;
const FAST_LIMIT: u32 = 5;
/// Transmissions after which the link counts as dead.
const DEAD_LINK: u32 = 20;
/// Default windows, in segments.
const WND_SND: u16 = 32;
const WND_RCV: u16 = 128;
/// Window probing when the peer's window is zero, ms.
const PROBE_INIT: u32 = 7000;
const PROBE_LIMIT: u32 = 120_000;

/// `later - earlier` for wrapping counters.
#[inline]
fn diff(later: u32, earlier: u32) -> i32 {
    later.wrapping_sub(earlier) as i32
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Shorter than a segment header, or a segment longer than the packet.
    Truncated,
    /// Another conversation's segment.
    Conv(u32),
    /// An unknown command.
    Cmd(u8),
    /// A data segment longer than the MSS.
    Oversize(usize),
}

#[derive(Debug, Default)]
struct Segment {
    ts: u32,
    sn: u32,
    resendts: u32,
    rto: u32,
    fastack: u32,
    xmit: u32,
    data: Vec<u8>,
    /// When the first byte of it was queued (µs, session clock).
    queued_us: u64,
    /// When it last went out (µs).
    sent_us: u64,
}

/// What a flush produced: packets of at most one MTU each.
#[derive(Debug, Default)]
pub struct Output {
    /// Acknowledgements and window probes.
    pub control: Vec<Vec<u8>>,
    /// Data segments (new and retransmitted).
    pub data: Vec<Vec<u8>>,
}

impl Output {
    pub fn clear(&mut self) {
        self.control.clear();
        self.data.clear();
    }
}

/// One KCP conversation (stream mode).
#[derive(Debug)]
pub struct Kcp {
    conv: u32,
    mtu: usize,
    mss: usize,
    dead: bool,

    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,

    rx_rttval: u32,
    rx_srtt: u32,
    rx_rto: u32,

    snd_wnd: u16,
    rcv_wnd: u16,
    rmt_wnd: u16,
    probe: u32,
    ts_probe: u32,
    probe_wait: u32,

    /// The clock, ms (wrapping).
    current: u32,

    snd_queue: VecDeque<Segment>,
    queued_bytes: usize,
    snd_buf: VecDeque<Segment>,
    rcv_queue: VecDeque<Vec<u8>>,
    rcv_buf: VecDeque<Segment>,
    acklist: Vec<(u32, u32)>,

    rtt_samples: Vec<Duration>,
    delivered: usize,
    retransmits: u64,
}

impl Kcp {
    /// A conversation with packets of at most `mtu` bytes.
    pub fn new(conv: u32, mtu: usize) -> Kcp {
        let mtu = mtu.max(OVERHEAD + 1);
        Kcp {
            conv,
            mtu,
            mss: mtu - OVERHEAD,
            dead: false,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            rx_rttval: 0,
            rx_srtt: 0,
            rx_rto: RTO_DEF,
            snd_wnd: WND_SND,
            rcv_wnd: WND_RCV,
            rmt_wnd: WND_RCV,
            probe: 0,
            ts_probe: 0,
            probe_wait: 0,
            current: 0,
            snd_queue: VecDeque::new(),
            queued_bytes: 0,
            snd_buf: VecDeque::new(),
            rcv_queue: VecDeque::new(),
            rcv_buf: VecDeque::new(),
            acklist: Vec::new(),
            rtt_samples: Vec::new(),
            delivered: 0,
            retransmits: 0,
        }
    }

    #[cfg(test)]
    fn mss(&self) -> usize {
        self.mss
    }

    /// Set the send window (segments in flight) and the receive window.
    pub fn set_wndsize(&mut self, snd: u16, rcv: u16) {
        if snd > 0 {
            self.snd_wnd = snd;
        }
        if rcv > 0 {
            self.rcv_wnd = rcv.max(WND_RCV);
        }
    }

    fn set_clock(&mut self, now_us: u64) {
        self.current = (now_us / 1000) as u32;
    }

    // ------------------------------------------------------------ sending

    /// Queue bytes to send (stream mode: they extend the last queued
    /// segment first).
    pub fn send(&mut self, mut data: &[u8], now_us: u64) {
        self.queued_bytes += data.len();
        if let Some(last) = self.snd_queue.back_mut()
            && last.data.len() < self.mss
        {
            let n = (self.mss - last.data.len()).min(data.len());
            last.data.extend_from_slice(&data[..n]);
            data = &data[n..];
        }
        for chunk in data.chunks(self.mss) {
            self.snd_queue.push_back(Segment {
                data: chunk.to_vec(),
                queued_us: now_us,
                ..Default::default()
            });
        }
    }

    /// Bytes queued and not sent yet.
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// How long the oldest queued byte has waited (§17.7).
    pub fn backlog_age(&self, now_us: u64) -> Duration {
        self.snd_queue.front().map_or(Duration::ZERO, |s| {
            Duration::from_micros(now_us.saturating_sub(s.queued_us))
        })
    }

    /// Segments sent and not acknowledged.
    #[cfg(test)]
    fn in_flight(&self) -> usize {
        self.snd_buf.len()
    }

    /// Segments queued or in flight.
    pub fn wait_snd(&self) -> usize {
        self.snd_buf.len() + self.snd_queue.len()
    }

    /// Too many transmissions of one segment: the path is gone.
    pub fn is_dead(&self) -> bool {
        self.dead
    }

    fn wnd_unused(&self) -> u16 {
        (self.rcv_wnd as usize).saturating_sub(self.rcv_queue.len()) as u16
    }

    fn header(&self, buf: &mut Vec<u8>, cmd: u8, wnd: u16, ts: u32, sn: u32, len: usize) {
        buf.extend_from_slice(&self.conv.to_le_bytes());
        buf.push(cmd);
        buf.push(0); // frg: stream mode
        buf.extend_from_slice(&wnd.to_le_bytes());
        buf.extend_from_slice(&ts.to_le_bytes());
        buf.extend_from_slice(&sn.to_le_bytes());
        buf.extend_from_slice(&self.rcv_nxt.to_le_bytes());
        buf.extend_from_slice(&(len as u32).to_le_bytes());
    }

    /// Emit acknowledgements, window probes, due retransmissions and new
    /// data. Data goes out only while `budget` (bytes, the pacer's tokens)
    /// lasts and the windows allow; the rest stays queued.
    pub fn flush(&mut self, now_us: u64, budget: usize, out: &mut Output) {
        self.set_clock(now_us);
        let wnd = self.wnd_unused();
        let mtu = self.mtu;
        let push = |pkts: &mut Vec<Vec<u8>>, buf: &mut Vec<u8>, need: usize| {
            if !buf.is_empty() && buf.len() + need > mtu {
                pkts.push(std::mem::take(buf));
            }
        };

        // Acknowledgements and probes.
        let mut buf = Vec::with_capacity(mtu);
        for (sn, ts) in std::mem::take(&mut self.acklist) {
            push(&mut out.control, &mut buf, OVERHEAD);
            self.header(&mut buf, CMD_ACK, wnd, ts, sn, 0);
        }
        self.probe_wnd_size();
        for (flag, cmd) in [(ASK_SEND, CMD_WASK), (ASK_TELL, CMD_WINS)] {
            if self.probe & flag != 0 {
                push(&mut out.control, &mut buf, OVERHEAD);
                self.header(&mut buf, cmd, wnd, 0, 0, 0);
            }
        }
        self.probe = 0;
        if !buf.is_empty() {
            out.control.push(std::mem::take(&mut buf));
        }

        // Retransmissions first, then new data, within the budget.
        let mut spent = 0usize;
        let current = self.current;
        let rx_rto = self.rx_rto;
        let mut sends: Vec<usize> = Vec::new();
        for (i, seg) in self.snd_buf.iter_mut().enumerate() {
            if spent >= budget {
                break;
            }
            let timeout = diff(current, seg.resendts) >= 0;
            let fast = !timeout && seg.fastack >= FAST_RESEND && seg.xmit <= FAST_LIMIT;
            if !(timeout || fast) {
                continue;
            }
            seg.xmit += 1;
            if timeout {
                // Back off, but never past RTO_MAX: an unbounded backoff
                // would put the dead-link verdict minutes away.
                seg.rto = seg.rto.saturating_add(seg.rto / 2).min(RTO_MAX);
            } else {
                seg.fastack = 0;
            }
            seg.resendts = current.wrapping_add(seg.rto);
            seg.ts = current;
            seg.sent_us = now_us;
            spent += OVERHEAD + seg.data.len();
            sends.push(i);
            if seg.xmit >= DEAD_LINK {
                self.dead = true;
            }
        }
        self.retransmits += sends.len() as u64;
        let cwnd = self.snd_wnd.min(self.rmt_wnd) as u32;
        while spent < budget && self.snd_nxt.wrapping_sub(self.snd_una) < cwnd {
            let Some(mut seg) = self.snd_queue.pop_front() else {
                break;
            };
            self.queued_bytes = self.queued_bytes.saturating_sub(seg.data.len());
            seg.sn = self.snd_nxt;
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            seg.ts = current;
            seg.xmit = 1;
            seg.rto = rx_rto;
            seg.resendts = current.wrapping_add(rx_rto);
            seg.sent_us = now_us;
            spent += OVERHEAD + seg.data.len();
            self.snd_buf.push_back(seg);
            sends.push(self.snd_buf.len() - 1);
        }
        for i in sends {
            let Some(seg) = self.snd_buf.get(i) else {
                continue;
            };
            let (ts, sn, len) = (seg.ts, seg.sn, seg.data.len());
            push(&mut out.data, &mut buf, OVERHEAD + len);
            self.header(&mut buf, CMD_PUSH, wnd, ts, sn, len);
            if let Some(seg) = self.snd_buf.get(i) {
                buf.extend_from_slice(&seg.data);
            }
        }
        if !buf.is_empty() {
            out.data.push(buf);
        }
    }

    fn probe_wnd_size(&mut self) {
        if self.rmt_wnd != 0 {
            self.ts_probe = 0;
            self.probe_wait = 0;
            return;
        }
        if self.probe_wait == 0 {
            self.probe_wait = PROBE_INIT;
            self.ts_probe = self.current.wrapping_add(self.probe_wait);
        } else if diff(self.current, self.ts_probe) >= 0 {
            self.probe_wait = (self.probe_wait.max(PROBE_INIT) * 3 / 2).min(PROBE_LIMIT);
            self.ts_probe = self.current.wrapping_add(self.probe_wait);
            self.probe |= ASK_SEND;
        }
    }

    // ------------------------------------------------------------ receiving

    /// A packet from the peer that reached the socket at `arrived_us`.
    /// `held` is how long the peer kept the data it acknowledges here
    /// before answering (zero when unknown); it is not the path's.
    pub fn input(&mut self, pkt: &[u8], arrived_us: u64, held: Duration) -> Result<(), Error> {
        self.input_inner(pkt, arrived_us, held, true)
    }

    /// Like [`Kcp::input`], for a packet that may carry only
    /// acknowledgements and window probes (RAW_ACK, sent outside FEC):
    /// data in it is refused.
    pub fn input_control(
        &mut self,
        pkt: &[u8],
        arrived_us: u64,
        held: Duration,
    ) -> Result<(), Error> {
        self.input_inner(pkt, arrived_us, held, false)
    }

    fn input_inner(
        &mut self,
        pkt: &[u8],
        arrived_us: u64,
        held: Duration,
        data_allowed: bool,
    ) -> Result<(), Error> {
        if pkt.len() < OVERHEAD {
            return Err(Error::Truncated);
        }
        self.set_clock(arrived_us);
        let mut max_ack: Option<(u32, u32)> = None;
        let mut at = 0usize;
        while pkt.len().saturating_sub(at) >= OVERHEAD {
            let le32 = |o: usize| {
                webjet_core::bytes::array::<4>(pkt, at + o)
                    .map(u32::from_le_bytes)
                    .unwrap_or(0)
            };
            let conv = le32(0);
            let cmd = pkt[at + 4];
            let wnd = u16::from_le_bytes([pkt[at + 6], pkt[at + 7]]);
            let (ts, sn, una, len) = (le32(8), le32(12), le32(16), le32(20) as usize);
            let start = at + OVERHEAD;
            let Some(data) = start.checked_add(len).and_then(|end| pkt.get(start..end)) else {
                return Err(Error::Truncated);
            };
            at = start + len;
            if conv != self.conv {
                return Err(Error::Conv(conv));
            }
            if !matches!(cmd, CMD_PUSH | CMD_ACK | CMD_WASK | CMD_WINS)
                || (cmd == CMD_PUSH && !data_allowed)
            {
                return Err(Error::Cmd(cmd));
            }
            // A segment never carries more than one MSS: a larger one is
            // the peer padding our buffers, not data we sent for.
            if len > self.mss {
                return Err(Error::Oversize(len));
            }
            self.rmt_wnd = wnd;
            // An acknowledgement's own segment before its `una`, so the
            // segment it names still gives a round trip.
            if cmd == CMD_ACK {
                self.parse_ack(sn, arrived_us, held);
            }
            self.parse_una(una);
            match cmd {
                CMD_ACK => {
                    let rtt = diff(self.current, ts);
                    if rtt >= 0 {
                        self.update_ack(rtt as u32);
                    }
                    max_ack = match max_ack {
                        Some((m, mts)) if !(diff(sn, m) > 0 && diff(ts, mts) > 0) => Some((m, mts)),
                        _ => Some((sn, ts)),
                    };
                }
                CMD_PUSH => {
                    if diff(sn, self.rcv_nxt.wrapping_add(u32::from(self.rcv_wnd))) < 0 {
                        self.acklist.push((sn, ts));
                        if diff(sn, self.rcv_nxt) >= 0 {
                            self.parse_data(sn, data);
                        }
                    }
                }
                CMD_WASK => self.probe |= ASK_TELL,
                _ => {} // WINS: the window came with the header
            }
        }
        if let Some((sn, ts)) = max_ack {
            self.parse_fastack(sn, ts);
        }
        Ok(())
    }

    fn update_ack(&mut self, rtt: u32) {
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt.max(1);
            self.rx_rttval = rtt / 2;
        } else {
            let delta = rtt.abs_diff(self.rx_srtt);
            self.rx_rttval = (3 * self.rx_rttval + delta) / 4;
            self.rx_srtt = ((7 * u64::from(self.rx_srtt) + u64::from(rtt)) / 8).max(1) as u32;
        }
        let rto = self
            .rx_srtt
            .saturating_add(INTERVAL.max(self.rx_rttval.saturating_mul(4)));
        self.rx_rto = rto.clamp(RTO_MIN, RTO_MAX);
    }

    fn shrink_buf(&mut self) {
        self.snd_una = self.snd_buf.front().map_or(self.snd_nxt, |s| s.sn);
    }

    fn parse_una(&mut self, una: u32) {
        while let Some(seg) = self.snd_buf.front() {
            if diff(una, seg.sn) <= 0 {
                break;
            }
            self.delivered += seg.data.len();
            self.snd_buf.pop_front();
        }
        self.shrink_buf();
    }

    fn parse_ack(&mut self, sn: u32, arrived_us: u64, held: Duration) {
        if diff(sn, self.snd_una) < 0 || diff(sn, self.snd_nxt) >= 0 {
            return;
        }
        if let Some(i) = self.snd_buf.iter().position(|s| s.sn == sn)
            && let Some(seg) = self.snd_buf.remove(i)
        {
            self.delivered += seg.data.len();
            // Karn: a retransmitted segment's acknowledgement is ambiguous.
            if seg.xmit == 1
                && let Some(rtt) =
                    Duration::from_micros(arrived_us.saturating_sub(seg.sent_us)).checked_sub(held)
            {
                self.rtt_samples.push(rtt);
            }
        }
        self.shrink_buf();
    }

    fn parse_fastack(&mut self, sn: u32, ts: u32) {
        if diff(sn, self.snd_una) < 0 || diff(sn, self.snd_nxt) >= 0 {
            return;
        }
        for seg in &mut self.snd_buf {
            if diff(sn, seg.sn) < 0 {
                break;
            }
            if sn != seg.sn && diff(ts, seg.ts) >= 0 {
                seg.fastack += 1;
            }
        }
    }

    fn parse_data(&mut self, sn: u32, data: &[u8]) {
        let mut idx = self.rcv_buf.len();
        for seg in self.rcv_buf.iter().rev() {
            if seg.sn == sn {
                return; // a duplicate
            }
            if diff(sn, seg.sn) > 0 {
                break;
            }
            idx -= 1;
        }
        self.rcv_buf.insert(
            idx,
            Segment {
                sn,
                data: data.to_vec(),
                ..Default::default()
            },
        );
        self.move_buf();
    }

    /// Move in-order segments to the receive queue, within the window.
    fn move_buf(&mut self) {
        while self
            .rcv_buf
            .front()
            .is_some_and(|s| s.sn == self.rcv_nxt && self.rcv_queue.len() < self.rcv_wnd as usize)
        {
            if let Some(seg) = self.rcv_buf.pop_front() {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.rcv_queue.push_back(seg.data);
            }
        }
    }

    /// The next received bytes for the user, in order.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        let recover = self.rcv_queue.len() >= self.rcv_wnd as usize;
        let data = self.rcv_queue.pop_front()?;
        self.move_buf();
        if recover && self.rcv_queue.len() < self.rcv_wnd as usize {
            // Tell the peer our window opened again.
            self.probe |= ASK_TELL;
        }
        Some(data)
    }

    // ------------------------------------------------------------ measurements

    /// Raw round trips of acknowledged new segments since the last call.
    pub fn take_rtt_samples(&mut self, out: &mut Vec<Duration>) {
        out.append(&mut self.rtt_samples);
    }

    /// Payload bytes acknowledged since the last call.
    pub fn take_delivered(&mut self) -> usize {
        std::mem::take(&mut self.delivered)
    }

    /// Segments sent again since the last call (timeouts and fast resends).
    pub fn take_retransmits(&mut self) -> u64 {
        std::mem::take(&mut self.retransmits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MTU: usize = 1300;

    /// Packets one way, with a drop filter.
    fn deliver(pkts: &[Vec<u8>], to: &mut Kcp, at_us: u64, mut drop: impl FnMut(&[u8]) -> bool) {
        for p in pkts {
            if !drop(p) {
                to.input(p, at_us, Duration::ZERO).unwrap();
            }
        }
    }

    fn sn_of(p: &[u8]) -> u32 {
        u32::from_le_bytes([p[12], p[13], p[14], p[15]])
    }

    fn drain(k: &mut Kcp) -> Vec<u8> {
        let mut v = Vec::new();
        while let Some(b) = k.recv() {
            v.extend(b);
        }
        v
    }

    #[test]
    fn stream_round_trip_with_loss_and_reordering() {
        let (mut a, mut b) = (Kcp::new(7, MTU), Kcp::new(7, MTU));
        a.set_wndsize(64, 1024);
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        for c in data.chunks(7000) {
            a.send(c, 0);
        }
        let (mut got, mut out) = (Vec::new(), Output::default());
        let mut n = 0u64;
        for t in 0..2000u64 {
            let now = t * 10_000;
            a.flush(now, usize::MAX, &mut out);
            let mut pkts = std::mem::take(&mut out.data);
            pkts.reverse(); // reordered
            deliver(&pkts, &mut b, now, |_| {
                n += 1;
                n.is_multiple_of(7) // every 7th lost
            });
            out.clear();
            b.flush(now, usize::MAX, &mut out);
            deliver(&out.control, &mut a, now + 5_000, |_| false);
            out.clear();
            got.extend(drain(&mut b));
            if got.len() == data.len() && a.wait_snd() == 0 {
                break;
            }
        }
        assert_eq!(got, data);
        assert_eq!(a.wait_snd(), 0);
        assert!(a.take_retransmits() > 0);
        assert_eq!(a.take_delivered(), data.len());
        assert!(!a.is_dead());
    }

    /// New data leaves only within the budget and the window; the rest waits
    /// in the queue, whose age is reported.
    #[test]
    fn budget_and_window_hold_data_back() {
        let mut a = Kcp::new(1, MTU);
        a.set_wndsize(4, 1024);
        a.send(&vec![1u8; 10 * a.mss()], 1_000_000);
        let mut out = Output::default();
        a.flush(1_000_000, 2 * (a.mss() + OVERHEAD), &mut out);
        assert_eq!(out.data.len(), 2, "two segments' worth of budget");
        assert_eq!(a.in_flight(), 2);
        assert_eq!(a.queued_bytes(), 8 * a.mss());
        assert_eq!(a.backlog_age(1_030_000), Duration::from_millis(30));
        out.clear();
        a.flush(1_030_000, usize::MAX, &mut out);
        assert_eq!(a.in_flight(), 4, "window of four");
        assert!(out.control.is_empty());
        // Zero budget: nothing at all, not even a due retransmission.
        out.clear();
        a.flush(5_000_000, 0, &mut out);
        assert!(out.data.is_empty());
    }

    /// Acknowledgements come out on their own; a raw RTT is taken from a
    /// segment sent once, less the time the peer held it, never from a
    /// retransmitted one; a retransmission counts.
    #[test]
    fn acknowledgements_and_raw_round_trips() {
        let (mut a, mut b) = (Kcp::new(3, MTU), Kcp::new(3, MTU));
        a.send(&vec![9u8; 3 * a.mss()], 0);
        let mut out = Output::default();
        a.flush(0, usize::MAX, &mut out);
        let first = std::mem::take(&mut out.data);
        // Segment 1 is lost; 0 and 2 arrive.
        deliver(&first, &mut b, 10_000, |p| sn_of(p) == 1);
        b.send(b"reply", 10_000);
        let mut bo = Output::default();
        b.flush(10_000, usize::MAX, &mut bo);
        assert_eq!(bo.control.len(), 1);
        assert_eq!(bo.control[0].len(), 2 * OVERHEAD, "two ACKs, no data");
        assert_eq!(bo.data.len(), 1);
        for p in &bo.control {
            a.input(p, 40_000, Duration::from_millis(5)).unwrap();
        }
        let mut rtts = Vec::new();
        a.take_rtt_samples(&mut rtts);
        assert_eq!(rtts, vec![Duration::from_millis(35); 2]);
        // The lost one goes again after its RTO, and its ACK gives no sample.
        out.clear();
        a.flush(1_000_000, usize::MAX, &mut out);
        assert_eq!(out.data.len(), 1);
        assert_eq!(sn_of(&out.data[0]), 1);
        assert_eq!(a.take_retransmits(), 1);
        deliver(&out.data, &mut b, 1_010_000, |_| false);
        bo.clear();
        b.flush(1_010_000, usize::MAX, &mut bo);
        deliver(&bo.control, &mut a, 1_020_000, |_| false);
        a.take_rtt_samples(&mut rtts);
        assert_eq!(rtts.len(), 2);
        assert_eq!(a.wait_snd(), 0);
        assert_eq!(drain(&mut b).len(), 3 * a.mss());
    }

    #[test]
    fn malformed_input_is_refused_without_panicking() {
        let mut k = Kcp::new(5, MTU);
        assert_eq!(k.input(&[0; 10], 0, Duration::ZERO), Err(Error::Truncated));
        let mut seg = vec![0u8; OVERHEAD];
        seg[..4].copy_from_slice(&6u32.to_le_bytes());
        assert_eq!(k.input(&seg, 0, Duration::ZERO), Err(Error::Conv(6)));
        seg[..4].copy_from_slice(&5u32.to_le_bytes());
        seg[4] = 99;
        assert_eq!(k.input(&seg, 0, Duration::ZERO), Err(Error::Cmd(99)));
        seg[4] = CMD_PUSH;
        seg[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(k.input(&seg, 0, Duration::ZERO), Err(Error::Truncated));
    }

    #[test]
    fn oversized_segments_and_data_in_control_packets_are_refused() {
        let mut k = Kcp::new(5, MTU);
        let mss = k.mss();
        let push = |len: usize| {
            let mut seg = vec![0u8; OVERHEAD];
            seg[..4].copy_from_slice(&5u32.to_le_bytes());
            seg[4] = CMD_PUSH;
            seg[20..24].copy_from_slice(&(len as u32).to_le_bytes());
            seg.extend(std::iter::repeat_n(7u8, len));
            seg
        };
        assert_eq!(
            k.input(&push(mss + 1), 0, Duration::ZERO),
            Err(Error::Oversize(mss + 1))
        );
        assert!(k.rcv_buf.is_empty() && k.rcv_queue.is_empty());
        // RAW_ACK may carry acknowledgements, never data.
        assert_eq!(
            k.input_control(&push(10), 0, Duration::ZERO),
            Err(Error::Cmd(CMD_PUSH))
        );
        assert!(k.recv().is_none());
        k.input(&push(mss), 0, Duration::ZERO).unwrap();
        assert_eq!(drain(&mut k).len(), mss);
    }

    /// A segment's retransmission timeout backs off to RTO_MAX and no
    /// further, so a dead path is noticed in minutes, not hours.
    #[test]
    fn retransmission_backoff_is_capped() {
        let mut k = Kcp::new(5, MTU);
        k.send(b"lost", 0);
        let mut out = Output::default();
        let mut now_ms: u64 = 0;
        for _ in 0..DEAD_LINK {
            out.clear();
            k.flush(now_ms * 1000, usize::MAX, &mut out);
            let seg = &k.snd_buf[0];
            assert!(seg.rto <= RTO_MAX, "rto {}", seg.rto);
            now_ms += u64::from(seg.rto) + 1;
        }
        assert!(k.is_dead());
        // 20 transmissions, each wait at most a minute.
        assert!(now_ms <= u64::from(DEAD_LINK) * u64::from(RTO_MAX) + 1000);
    }

    /// Sequence numbers and clocks wrap (49-day ms clock, u32 sn).
    #[test]
    fn counters_wrap() {
        let (mut a, mut b) = (Kcp::new(1, MTU), Kcp::new(1, MTU));
        a.snd_una = u32::MAX - 1;
        a.snd_nxt = u32::MAX - 1;
        b.rcv_nxt = u32::MAX - 1;
        let base = u64::from(u32::MAX) * 1000 - 20_000;
        a.send(&vec![4u8; 5 * a.mss()], base);
        let mut out = Output::default();
        for t in 0..10u64 {
            let now = base + t * 10_000;
            out.clear();
            a.flush(now, usize::MAX, &mut out);
            deliver(&out.data, &mut b, now, |_| false);
            out.clear();
            b.flush(now, usize::MAX, &mut out);
            deliver(&out.control, &mut a, now + 1000, |_| false);
        }
        assert_eq!(a.wait_snd(), 0);
        assert_eq!(drain(&mut b).len(), 5 * a.mss());
    }

    /// The crate this came from (what older nodes run) and this
    /// implementation exchange a stream both ways over a lossy link.
    #[test]
    fn interoperates_with_the_kcp_crate() {
        use std::io::Write;
        #[derive(Clone, Default)]
        struct Sink(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);
        impl Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().push(b.to_vec());
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = Sink::default();
        let mut old = kcp::Kcp::new_stream(9, sink.clone());
        old.set_mtu(MTU).unwrap();
        old.set_nodelay(true, 10, 2, true);
        old.set_wndsize(256, 1024);
        let mut new = Kcp::new(9, MTU);
        new.set_wndsize(256, 1024);
        let up: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        let down: Vec<u8> = (0..200_000u32).map(|i| (i % 241) as u8).collect();
        new.send(&up, 0);
        // The crate refuses 128 segments or more at once; sessions gave it
        // 16 kB reads.
        for c in down.chunks(16 * 1024) {
            old.send(c).unwrap();
        }
        let (mut got_up, mut got_down) = (Vec::new(), Vec::new());
        let mut out = Output::default();
        let mut n = 0u64;
        for t in 1..3000u32 {
            let now = u64::from(t) * 10_000;
            out.clear();
            new.flush(now, usize::MAX, &mut out);
            for p in out.control.iter().chain(&out.data) {
                n += 1;
                if !n.is_multiple_of(11) {
                    let _ = old.input(p);
                }
            }
            old.update(t * 10).unwrap();
            let pkts: Vec<Vec<u8>> = sink.0.lock().unwrap().drain(..).collect();
            for p in pkts {
                n += 1;
                if !n.is_multiple_of(13) {
                    new.input(&p, now + 2_000, Duration::ZERO).unwrap();
                }
            }
            while let Ok(size) = old.peeksize() {
                let mut b = vec![0u8; size];
                old.recv(&mut b).unwrap();
                got_up.extend(b);
            }
            got_down.extend(drain(&mut new));
            if got_up.len() == up.len() && got_down.len() == down.len() {
                break;
            }
        }
        assert_eq!(got_up, up);
        assert_eq!(got_down, down);
    }

    /// A peer that keeps its window closed is probed, and a reader that
    /// catches up announces its window again.
    #[test]
    fn window_probes() {
        let (mut a, mut b) = (Kcp::new(2, MTU), Kcp::new(2, MTU));
        b.set_wndsize(32, 128);
        a.set_wndsize(1024, 1024);
        a.send(&vec![0u8; 200 * a.mss()], 0);
        let mut out = Output::default();
        let mut now = 0;
        for _ in 0..20 {
            now += 10_000;
            out.clear();
            a.flush(now, usize::MAX, &mut out);
            deliver(&out.data, &mut b, now, |_| false);
            out.clear();
            b.flush(now, usize::MAX, &mut out);
            deliver(&out.control, &mut a, now, |_| false);
        }
        assert_eq!(a.rmt_wnd, 0, "b's queue is full");
        let mut probes = 0;
        for t in [8_000_000, 16_000_000, 30_000_000] {
            out.clear();
            a.flush(now + t, 0, &mut out);
            probes += out.control.iter().filter(|p| p[4] == CMD_WASK).count();
        }
        assert_eq!(probes, 2, "probed after 7 s, then after 10.5 s");
        while b.recv().is_some() {}
        out.clear();
        b.flush(now, usize::MAX, &mut out);
        assert!(out.control.iter().any(|p| p[4] == CMD_WINS), "window told");
    }
}
