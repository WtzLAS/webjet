//! The unreliable lane of a KCP hop (§17.5).
//!
//! Beside the reliable stream that carries the hop's TLS session, a KCP
//! session can send hop records (relay frames) that it never retransmits:
//! each record goes in one or more pieces, each piece one KCP segment of its
//! own command (`UPUSH`) with the usual 24-byte header. The receiver
//! acknowledges every piece (`UACK`), so the lane gives raw round trips and
//! delivery rates like the stream, and delivers records as they arrive, in
//! any order. FEC below repairs what it can; the rest is lost.
//!
//! The stream's records are protected by its TLS session; the lane's by
//! ChaCha20-Poly1305 under keys exported from that session, one per
//! direction, with a 64-bit piece counter as the nonce (its low 32 bits are
//! the segment's `sn`) and the segment header as associated data. A replay
//! window drops duplicates, including those FEC recovers late.
//!
//! A record over one piece is split: `frg` holds how many pieces follow, and
//! its top bit marks the first piece. Losing any piece loses the record.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;
use webjet_core::frames::{ReplayWindow, SessionKey};

/// The AEAD tag after each piece.
pub const TAG: usize = 16;
/// The largest KCP packet a piece goes in: larger than the stream's
/// packets (`KCP_MTU`), so that a relay frame carrying an inner packet of
/// 1280 bytes (the default tun MTU, and the least IPv6 allows) is one piece:
/// 1280 + 29 (end-to-end) + 5 (relay header) + 16 (tag) + 24 (KCP header).
/// The datagram is then 1412 bytes (FEC 9, session 5, obfuscation 44), 1460
/// with UDP and IPv6 headers.
pub const MTU: usize = 1354;
/// The most record bytes one piece carries.
pub const PIECE: usize = MTU - super::proto::OVERHEAD - TAG;
/// Pieces per record at most; `frg` has 7 bits for them.
pub const MAX_PIECES: usize = 64;
/// The largest record the lane takes.
pub const MAX_RECORD: usize = PIECE * MAX_PIECES;
/// `frg` bit: the first piece of a record.
const FIRST: u8 = 0x80;
/// Pieces of incomplete records kept, and for how long.
const FRAGS_MAX: usize = 512;
const FRAG_TTL_US: u64 = 1_000_000;
/// Pieces sent and not acknowledged that are tracked for their round trip.
const SENT_MAX: usize = 8192;
const SENT_TTL_US: u64 = 2_000_000;
/// Received records waiting for the session to take them.
const RECEIVED_MAX: usize = 1024;

/// A piece waiting to be sent.
#[derive(Debug)]
pub(super) struct Piece {
    pub counter: u64,
    pub frg: u8,
    pub data: Vec<u8>,
    pub queued_us: u64,
}

pub(super) struct Lane {
    tx: SessionKey,
    rx: SessionKey,
    next: u64,
    pub queue: VecDeque<Piece>,
    pub queued_bytes: usize,
    /// (counter, sent at µs, record bytes) of pieces not acknowledged yet.
    sent: VecDeque<(u64, u64, usize)>,
    /// Acknowledgements to send: (sn, ts).
    pub acks: Vec<(u32, u32)>,
    top: Option<u64>,
    replay: ReplayWindow,
    /// Pieces of incomplete records by counter: (frg, data, arrived at µs).
    frags: BTreeMap<u64, (u8, Vec<u8>, u64)>,
    pub received: VecDeque<Vec<u8>>,
    pub stats: LaneStats,
}

impl std::fmt::Debug for Lane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lane")
            .field("next", &self.next)
            .field("queued", &self.queue.len())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

/// Counters since the session started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LaneStats {
    pub tx_records: u64,
    pub rx_records: u64,
    /// Pieces dropped before their record was complete (a piece was lost).
    pub incomplete: u64,
}

/// The full counter for a 32-bit `sn`: the one nearest `near`.
fn extend(sn: u32, near: u64) -> u64 {
    const SPAN: u64 = 1 << 32;
    let c = (near & !(SPAN - 1)) | u64::from(sn);
    if c > near && c - near > SPAN / 2 && c >= SPAN {
        c - SPAN
    } else if c < near && near - c > SPAN / 2 {
        c.saturating_add(SPAN)
    } else {
        c
    }
}

impl Lane {
    /// `tx` seals what we send, `rx` opens what the peer sends.
    pub fn new(tx: [u8; 32], rx: [u8; 32]) -> Lane {
        Lane {
            tx: SessionKey::new(tx),
            rx: SessionKey::new(rx),
            next: 0,
            queue: VecDeque::new(),
            queued_bytes: 0,
            sent: VecDeque::new(),
            acks: Vec::new(),
            top: None,
            replay: ReplayWindow::default(),
            frags: BTreeMap::new(),
            received: VecDeque::new(),
            stats: LaneStats::default(),
        }
    }

    /// Queue a record in pieces; false when it is empty or too large.
    pub fn queue_record(&mut self, rec: &[u8], now_us: u64) -> bool {
        if rec.is_empty() || rec.len() > MAX_RECORD {
            return false;
        }
        let n = rec.len().div_ceil(PIECE);
        for (i, chunk) in rec.chunks(PIECE).enumerate() {
            let rem = (n - 1 - i) as u8;
            self.queue.push_back(Piece {
                counter: self.next,
                frg: if i == 0 { FIRST | rem } else { rem },
                data: chunk.to_vec(),
                queued_us: now_us,
            });
            self.next = self.next.wrapping_add(1);
        }
        self.queued_bytes += rec.len();
        self.stats.tx_records += 1;
        true
    }

    /// Take the next piece to send.
    pub fn pop(&mut self) -> Option<Piece> {
        let p = self.queue.pop_front()?;
        self.queued_bytes = self.queued_bytes.saturating_sub(p.data.len());
        Some(p)
    }

    /// Seal a piece whose header and plaintext are `seg` (header first);
    /// the tag is appended. The header must already give the sealed length.
    pub fn seal(&self, counter: u64, seg: &mut Vec<u8>) -> Option<()> {
        let hdr: [u8; super::proto::OVERHEAD] =
            seg.get(..super::proto::OVERHEAD)?.try_into().ok()?;
        self.tx
            .seal_in_place(counter, &hdr, seg, super::proto::OVERHEAD)
    }

    /// Track a sent piece for its round trip.
    pub fn on_sent(&mut self, counter: u64, now_us: u64, len: usize) {
        self.sent.push_back((counter, now_us, len));
        while self.sent.len() > SENT_MAX
            || self
                .sent
                .front()
                .is_some_and(|s| now_us.saturating_sub(s.1) > SENT_TTL_US)
        {
            self.sent.pop_front();
        }
    }

    /// An acknowledgement of piece `sn`: its raw round trip (less the time
    /// the peer held it) and its bytes, if it was still tracked.
    pub fn on_ack(
        &mut self,
        sn: u32,
        arrived_us: u64,
        held: Duration,
    ) -> Option<(Option<Duration>, usize)> {
        let c = extend(sn, self.next);
        let i = self.sent.partition_point(|s| s.0 < c);
        if self.sent.get(i).is_none_or(|s| s.0 != c) {
            return None;
        }
        let (_, sent_us, len) = self.sent.remove(i)?;
        let rtt = Duration::from_micros(arrived_us.saturating_sub(sent_us)).checked_sub(held);
        Some((rtt, len))
    }

    /// A piece from the peer, as it came: the segment's header, then the
    /// sealed record bytes. Returns false (and nothing is acknowledged)
    /// unless it is authentic and new.
    pub fn on_piece(
        &mut self,
        hdr: &[u8],
        sn: u32,
        ts: u32,
        frg: u8,
        sealed: &[u8],
        now_us: u64,
    ) -> bool {
        let c = extend(sn, self.top.unwrap_or(0));
        if !self.replay.check(c) {
            return false;
        }
        let mut body = sealed.to_vec();
        let Some(n) = self.rx.open_in_place(c, hdr, &mut body) else {
            return false;
        };
        body.truncate(n);
        self.replay.mark(c);
        self.top = Some(self.top.map_or(c, |t| t.max(c)));
        self.acks.push((sn, ts));
        if frg == FIRST {
            self.deliver(body);
        } else {
            self.frags.insert(c, (frg, body, now_us));
            self.assemble(c);
        }
        self.prune(now_us);
        true
    }

    fn deliver(&mut self, rec: Vec<u8>) {
        if self.received.len() < RECEIVED_MAX {
            self.received.push_back(rec);
            self.stats.rx_records += 1;
        }
    }

    /// Deliver the record piece `c` belongs to, if all its pieces are here.
    fn assemble(&mut self, c: u64) {
        let rem = |f: u8| u64::from(f & !FIRST);
        let mut start = c;
        loop {
            let Some(&(f, ..)) = self.frags.get(&start) else {
                return;
            };
            if f & FIRST != 0 {
                break;
            }
            let Some(prev) = start.checked_sub(1) else {
                return;
            };
            match self.frags.get(&prev) {
                Some(&(pf, ..)) if rem(pf) == rem(f) + 1 => start = prev,
                _ => return,
            }
        }
        let Some(&(f, ..)) = self.frags.get(&start) else {
            return;
        };
        let n = rem(f) + 1;
        for i in 1..n {
            match self.frags.get(&(start + i)) {
                Some(&(pf, ..)) if pf & FIRST == 0 && rem(pf) == n - 1 - i => {}
                _ => return,
            }
        }
        let mut rec = Vec::new();
        for i in 0..n {
            if let Some((_, d, _)) = self.frags.remove(&(start + i)) {
                rec.extend_from_slice(&d);
            }
        }
        self.deliver(rec);
    }

    /// Drop pieces of records that won't complete.
    fn prune(&mut self, now_us: u64) {
        let before = self.frags.len();
        self.frags
            .retain(|_, (_, _, at)| now_us.saturating_sub(*at) <= FRAG_TTL_US);
        while self.frags.len() > FRAGS_MAX {
            self.frags.pop_first();
        }
        self.stats.incomplete += (before - self.frags.len()) as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_extend_around_the_nearest() {
        assert_eq!(extend(5, 0), 5);
        assert_eq!(extend(u32::MAX, 0), u64::from(u32::MAX));
        assert_eq!(extend(3, (1 << 32) - 2), (1 << 32) + 3);
        assert_eq!(extend(u32::MAX - 1, (1 << 32) + 3), (1 << 32) - 2);
        assert_eq!(extend(7, (5 << 32) + 9), (5 << 32) + 7);
    }

    /// Pieces as the peer's KCP would hand them over: (header, sn, frg, sealed).
    fn pieces(a: &mut Lane, rec: &[u8]) -> Vec<(Vec<u8>, u32, u8, Vec<u8>)> {
        assert!(a.queue_record(rec, 0));
        let mut v = Vec::new();
        while let Some(p) = a.pop() {
            let mut seg = vec![0u8; super::super::proto::OVERHEAD];
            seg[5] = p.frg;
            seg[12..16].copy_from_slice(&(p.counter as u32).to_le_bytes());
            seg.extend_from_slice(&p.data);
            a.seal(p.counter, &mut seg).unwrap();
            let body = seg.split_off(super::super::proto::OVERHEAD);
            v.push((seg, p.counter as u32, p.frg, body));
        }
        v
    }

    #[test]
    fn records_arrive_in_pieces_in_any_order() {
        let (mut a, mut b) = (Lane::new([1; 32], [2; 32]), Lane::new([2; 32], [1; 32]));
        let small = vec![7u8; 100];
        let big: Vec<u8> = (0..3 * PIECE + 10).map(|i| i as u8).collect();
        let mut ps = pieces(&mut a, &small);
        ps.extend(pieces(&mut a, &big));
        assert_eq!(ps.len(), 5);
        ps.reverse();
        for (h, sn, frg, s) in &ps {
            assert!(b.on_piece(h, *sn, 0, *frg, s, 0));
        }
        assert_eq!(b.received, [big.clone(), small.clone()]);
        assert_eq!(b.acks.len(), 5);
        // Replayed: refused, not acknowledged again.
        assert!(!b.on_piece(&ps[0].0, ps[0].1, 0, ps[0].2, &ps[0].3, 0));
        // Tampered header or body: refused.
        let mut h = ps[1].0.clone();
        h[8] ^= 1;
        let mut c = Lane::new([2; 32], [1; 32]);
        assert!(!c.on_piece(&h, ps[1].1, 0, ps[1].2, &ps[1].3, 0));
        let mut s = ps[1].3.clone();
        s[0] ^= 1;
        assert!(!c.on_piece(&ps[1].0, ps[1].1, 0, ps[1].2, &s, 0));
    }

    #[test]
    fn a_lost_piece_loses_its_record_only() {
        let (mut a, mut b) = (Lane::new([1; 32], [2; 32]), Lane::new([2; 32], [1; 32]));
        let one: Vec<u8> = vec![1; 2 * PIECE];
        let two: Vec<u8> = vec![2; 2 * PIECE];
        let mut ps = pieces(&mut a, &one);
        ps.extend(pieces(&mut a, &two));
        ps.remove(0); // `one`'s first piece
        for (h, sn, frg, s) in &ps {
            assert!(b.on_piece(h, *sn, 0, *frg, s, 0));
        }
        assert_eq!(b.received, [two]);
        // The orphan goes after its time is up.
        let (h, sn, frg, s) = pieces(&mut a, &[3; 10]).remove(0);
        assert!(b.on_piece(&h, sn, 0, frg, &s, 2 * FRAG_TTL_US));
        assert_eq!(b.stats.incomplete, 1);
        assert!(b.frags.is_empty());
        assert!(!a.queue_record(&vec![0; MAX_RECORD + 1], 0));
        assert!(!a.queue_record(&[], 0));
    }

    #[test]
    fn acknowledgements_give_round_trips() {
        let mut a = Lane::new([1; 32], [2; 32]);
        a.queue_record(&[1; 10], 0);
        let p = a.pop().unwrap();
        a.on_sent(p.counter, 1_000, 10);
        let (rtt, len) = a
            .on_ack(p.counter as u32, 31_000, Duration::from_millis(5))
            .unwrap();
        assert_eq!((rtt, len), (Some(Duration::from_millis(25)), 10));
        assert!(a.on_ack(p.counter as u32, 32_000, Duration::ZERO).is_none());
    }
}
