//! End-to-end frames (§6.9, §9.4.3-§9.4.4), the replay window (RFC 6479
//! style, 8192 packets) and the relay frame header (§11.5, §17.7).

use crate::crypto::Bytes32;
use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use zeroize::Zeroize;

pub mod ftype {
    pub const DATA: u8 = 1;
    pub const HANDSHAKE: u8 = 2;
    pub const PROBE: u8 = 3;
    pub const PROBE_ACK: u8 = 4;
    pub const PUNCH_OFFER: u8 = 5;
    pub const PUNCH_GO: u8 = 6;
    pub const CLOSE: u8 = 7;
    /// Application RPC to/from controllers (PSK fetch, ops, metrics, Raft),
    /// carried inside the session like any other payload (§7.1, §12.5).
    pub const RPC: u8 = 8;
    /// Reverse proxy traffic (§11.11): an inner IP packet, like DATA, kept
    /// apart so neither end mixes it with overlay traffic.
    pub const PROXY: u8 = 9;
    /// DATA / PROXY with the inner packet LZ4-compressed (§9.8):
    /// `len[2] || LZ4 block`. Sent only to peers advertising `lz4`.
    pub const DATA_LZ4: u8 = 10;
    pub const PROXY_LZ4: u8 = 11;
    /// RPC with `req_id || kind || Rpc` zstd-compressed (§9.8). Sent only
    /// to peers advertising `zstd`.
    pub const RPC_ZSTD: u8 = 12;
}

/// type(1) + key_id(4) + counter(8)
pub const HEADER: usize = 13;
pub const TAG: usize = 16;
pub const OVERHEAD: usize = HEADER + TAG;

/// Maximum counter before a key must not be used any more (2⁴⁰ packets, §9.4.5).
pub const REKEY_PACKETS: u64 = 1 << 40;

/// One direction's ChaCha20-Poly1305 key (RFC 8439). aws-lc's assembly
/// implementation: the data path seals and opens every packet with it.
pub struct SessionKey {
    cipher: LessSafeKey,
}

impl SessionKey {
    pub fn new(mut k: [u8; 32]) -> Self {
        // A 32-byte key is always valid for ChaCha20-Poly1305.
        #[allow(clippy::expect_used)]
        let key = UnboundKey::new(&CHACHA20_POLY1305, &k).expect("32-byte key");
        k.zeroize();
        SessionKey {
            cipher: LessSafeKey::new(key),
        }
    }

    fn nonce(counter: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&counter.to_be_bytes());
        Nonce::assume_unique_for_key(n)
    }

    /// Seal `payload` into a complete frame. `None` only if the payload is
    /// beyond what the AEAD can encrypt (~256 GiB).
    pub fn seal(&self, ty: u8, key_id: u32, counter: u64, payload: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(OVERHEAD + payload.len());
        out.push(ty);
        out.extend_from_slice(&key_id.to_be_bytes());
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(payload);
        let (hdr, body) = out.split_at_mut(HEADER);
        let tag = self
            .cipher
            .seal_in_place_separate_tag(Self::nonce(counter), Aad::from(&*hdr), body)
            .ok()?;
        out.extend_from_slice(tag.as_ref());
        Some(out)
    }

    /// Open a frame whose header was already parsed. Does not touch any
    /// replay state.
    pub fn open(&self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() < OVERHEAD {
            return None;
        }
        let (hdr, rest) = frame.split_at(HEADER);
        let counter = crate::bytes::be_u64(hdr, 5)?;
        let mut body = rest.to_vec();
        let n = self
            .cipher
            .open_in_place(Self::nonce(counter), Aad::from(hdr), &mut body)
            .ok()?
            .len();
        body.truncate(n);
        Some(body)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub ty: u8,
    pub key_id: u32,
    pub counter: u64,
}

pub fn parse_header(frame: &[u8]) -> Option<FrameHeader> {
    if frame.is_empty() {
        return None;
    }
    let ty = frame[0];
    if ty == ftype::HANDSHAKE {
        return Some(FrameHeader {
            ty,
            key_id: 0,
            counter: 0,
        });
    }
    if frame.len() < OVERHEAD {
        return None;
    }
    Some(FrameHeader {
        ty,
        key_id: crate::bytes::be_u32(frame, 1)?,
        counter: crate::bytes::be_u64(frame, 5)?,
    })
}

/// HANDSHAKE frames: `type || initiator flag || session nonce[16] || flight[2]
/// || tls_len[2] || TLS bytes || padding`. They are not AEAD-protected; TLS
/// protects them (§6.9). Frames are padded to size buckets (§9.7.4).
/// None when the TLS flight doesn't fit the 16-bit length field.
pub fn handshake_frame(
    initiator: bool,
    nonce: &[u8; 16],
    flight: u16,
    tls: &[u8],
) -> Option<Vec<u8>> {
    let tls_len = u16::try_from(tls.len()).ok()?;
    let mut f = Vec::with_capacity(32 + tls.len());
    f.push(ftype::HANDSHAKE);
    f.push(initiator as u8);
    f.extend_from_slice(nonce);
    f.extend_from_slice(&flight.to_be_bytes());
    f.extend_from_slice(&tls_len.to_be_bytes());
    f.extend_from_slice(tls);
    let bucket = [256usize, 512, 1024, 1500, 2048, 4096, 8192, 16384]
        .into_iter()
        .find(|b| *b >= f.len())
        .unwrap_or(f.len());
    f.resize(bucket, 0);
    Some(f)
}

pub struct Handshake<'a> {
    pub initiator: bool,
    pub nonce: [u8; 16],
    pub flight: u16,
    pub tls: &'a [u8],
}

pub fn parse_handshake(f: &[u8]) -> Option<Handshake<'_>> {
    if f.len() < 22 || f[0] != ftype::HANDSHAKE {
        return None;
    }
    let initiator = f[1] == 1;
    let nonce: [u8; 16] = f[2..18].try_into().ok()?;
    let flight = u16::from_be_bytes([f[18], f[19]]);
    let len = u16::from_be_bytes([f[20], f[21]]) as usize;
    let tls = f.get(22..22 + len)?;
    Some(Handshake {
        initiator,
        nonce,
        flight,
        tls,
    })
}

// ---------------------------------------------------------------- replay window

pub const WINDOW: u64 = 8192;
const WORDS: usize = (WINDOW / 64) as usize;

/// Sliding bitmap replay window (RFC 6479).
#[derive(Clone)]
pub struct ReplayWindow {
    top: u64,
    bits: [u64; WORDS],
    any: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        ReplayWindow {
            top: 0,
            bits: [0; WORDS],
            any: false,
        }
    }
}

impl ReplayWindow {
    /// Would `c` be accepted? (check before decrypting)
    pub fn check(&self, c: u64) -> bool {
        if !self.any || c > self.top {
            return true;
        }
        if self.top - c >= WINDOW {
            return false;
        }
        let idx = (c % WINDOW) as usize;
        self.bits[idx / 64] & (1 << (idx % 64)) == 0
    }

    /// Mark `c` as seen (after successful decryption).
    pub fn mark(&mut self, c: u64) -> bool {
        if !self.check(c) {
            return false;
        }
        if !self.any || c > self.top {
            let start = if self.any {
                self.top + 1
            } else {
                c.saturating_sub(WINDOW - 1)
            };
            if !self.any || c - self.top >= WINDOW {
                self.bits = [0; WORDS];
            } else {
                for x in start..=c {
                    let idx = (x % WINDOW) as usize;
                    self.bits[idx / 64] &= !(1 << (idx % 64));
                }
            }
            self.top = c;
            self.any = true;
        }
        let idx = (c % WINDOW) as usize;
        self.bits[idx / 64] |= 1 << (idx % 64);
        true
    }
}

// ---------------------------------------------------------------- relay frames (§11.5)

/// `circuit_id: u32 || hop_limit:6 ecn:2` — a 5-byte header.
pub const RELAY_HEADER: usize = 5;
pub const DEFAULT_HOP_LIMIT: u8 = 8;

pub fn relay_header(circuit: u32, hop_limit: u8, ecn: u8) -> [u8; RELAY_HEADER] {
    let mut h = [0u8; RELAY_HEADER];
    h[..4].copy_from_slice(&circuit.to_be_bytes());
    h[4] = (hop_limit.min(63) << 2) | (ecn & 3);
    h
}

pub fn parse_relay(f: &[u8]) -> Option<(u32, u8, u8, &[u8])> {
    if f.len() < RELAY_HEADER {
        return None;
    }
    let c = crate::bytes::be_u32(f, 0)?;
    Some((c, f[4] >> 2, f[4] & 3, &f[RELAY_HEADER..]))
}

/// ECN codepoints (RFC 3168).
pub mod ecn {
    pub const NOT_ECT: u8 = 0;
    pub const ECT1: u8 = 1;
    pub const ECT0: u8 = 2;
    pub const CE: u8 = 3;
}

/// Exporter context for e2e keys (§9.4.2 step 6).
pub fn exporter_context(initiator_key_id: u32, responder_key_id: u32) -> [u8; 8] {
    let mut c = [0u8; 8];
    c[..4].copy_from_slice(&initiator_key_id.to_be_bytes());
    c[4..].copy_from_slice(&responder_key_id.to_be_bytes());
    c
}

pub const E2E_EXPORTER_LABEL: &[u8] = b"webjet-e2e-v1";

pub fn split_keys(material: &[u8; 64]) -> (Bytes32, Bytes32) {
    let (a, b) = material.split_at(32);
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(a);
    y.copy_from_slice(b);
    (x, y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open() {
        let k = SessionKey::new([7; 32]);
        let f = k.seal(ftype::DATA, 42, 9, b"packet").unwrap();
        assert_eq!(f.len(), OVERHEAD + 6);
        let h = parse_header(&f).unwrap();
        assert_eq!((h.ty, h.key_id, h.counter), (ftype::DATA, 42, 9));
        assert_eq!(k.open(&f).unwrap(), b"packet");
        let mut bad = f;
        bad[0] = ftype::PROBE; // type is authenticated
        assert!(k.open(&bad).is_none());
    }

    /// Nodes before the switch to aws-lc sealed frames with RustCrypto's
    /// ChaCha20-Poly1305: both must produce the same bytes (RFC 8439), so
    /// old and new nodes still read each other's frames.
    #[test]
    fn frames_match_the_rustcrypto_implementation() {
        use chacha20poly1305::aead::{AeadInOut, KeyInit};
        let key = [0x42u8; 32];
        let old = chacha20poly1305::ChaCha20Poly1305::new(&key.into());
        let k = SessionKey::new(key);
        for len in [0usize, 1, 63, 64, 65, 1200, 1500] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ctr = 0x0102_0304_0506 + len as u64;
            let f = k.seal(ftype::DATA, 77, ctr, &payload).unwrap();
            let mut body = payload.clone();
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&ctr.to_be_bytes());
            let tag = old
                .encrypt_inout_detached(&nonce.into(), &f[..HEADER], body.as_mut_slice().into())
                .unwrap();
            assert_eq!(
                &f[HEADER..HEADER + len],
                &body[..],
                "ciphertext, {len} bytes"
            );
            assert_eq!(&f[HEADER + len..], &tag[..], "tag, {len} bytes");
            assert_eq!(k.open(&f).unwrap(), payload);
            // Any flipped bit is refused.
            for at in [0, HEADER, f.len() - 1] {
                let mut bad = f.clone();
                bad[at] ^= 1;
                assert!(k.open(&bad).is_none(), "flipped byte {at}");
            }
        }
        assert!(k.open(&[0u8; OVERHEAD - 1]).is_none());
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        assert!(w.mark(5));
        assert!(!w.mark(5));
        assert!(w.mark(3));
        assert!(w.mark(10_000));
        assert!(!w.mark(3)); // too old now
        assert!(w.mark(10_000 - 8000));
        assert!(!w.mark(10_000 - 8000));
        assert!(w.mark(10_001));
        assert!(w.mark(9_999));
        for c in 20_000..20_100u64 {
            assert!(w.mark(c));
        }
        for c in 20_000..20_100u64 {
            assert!(!w.check(c));
        }
    }

    #[test]
    fn relay_hdr() {
        let h = relay_header(0xdeadbeef, 8, ecn::CE);
        let mut f = h.to_vec();
        f.extend_from_slice(b"x");
        assert_eq!(parse_relay(&f), Some((0xdeadbeef, 8, 3, &b"x"[..])));
    }

    #[test]
    fn handshake_frame_refuses_flights_over_the_length_field() {
        assert!(handshake_frame(true, &[1; 16], 1, &vec![0; usize::from(u16::MAX) + 1]).is_none());
        assert!(handshake_frame(true, &[1; 16], 1, &vec![0; usize::from(u16::MAX)]).is_some());
    }

    #[test]
    fn handshake_padding() {
        let f = handshake_frame(true, &[1; 16], 3, &[9; 300]).unwrap();
        assert_eq!(f.len(), 512);
        let h = parse_handshake(&f).unwrap();
        assert!(h.initiator);
        assert_eq!(h.nonce, [1; 16]);
        assert_eq!(h.flight, 3);
        assert_eq!(h.tls.len(), 300);
    }
}

#[cfg(test)]
mod prop {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    proptest! {
        /// Sealed frames open to the same payload, carry their header in
        /// the clear, and any changed byte makes them fail to open.
        #[test]
        fn seal_open_and_tamper(
            key in any::<[u8; 32]>(),
            ty in any::<u8>().prop_filter("not a handshake", |t| *t != ftype::HANDSHAKE),
            key_id in any::<u32>(),
            counter in any::<u64>(),
            payload in proptest::collection::vec(any::<u8>(), 0..600),
            flip in any::<usize>(),
            bit in 0u8..8,
        ) {
            let k = SessionKey::new(key);
            let f = k.seal(ty, key_id, counter, &payload).unwrap();
            prop_assert_eq!(f.len(), OVERHEAD + payload.len());
            prop_assert_eq!(parse_header(&f), Some(FrameHeader { ty, key_id, counter }));
            prop_assert_eq!(k.open(&f).unwrap(), payload);
            let mut bad = f.clone();
            let i = flip % bad.len();
            bad[i] ^= 1 << bit;
            prop_assert!(k.open(&bad).is_none(), "byte {} changed", i);
            // Another key opens nothing.
            let mut other = key;
            other[0] ^= 1;
            prop_assert!(SessionKey::new(other).open(&f).is_none());
            // Truncated frames are rejected, never a panic.
            prop_assert!(k.open(&f[..f.len().min(OVERHEAD - 1)]).is_none());
        }

        #[test]
        fn relay_header_roundtrip(
            circuit in any::<u32>(),
            hop_limit in any::<u8>(),
            ecn in any::<u8>(),
            body in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let f = [relay_header(circuit, hop_limit, ecn).as_slice(), &body].concat();
            let (c, h, e, b) = parse_relay(&f).unwrap();
            prop_assert_eq!((c, h, e, b), (circuit, hop_limit.min(63), ecn & 3, &body[..]));
        }

        #[test]
        fn handshake_roundtrip(
            initiator in any::<bool>(),
            nonce in any::<[u8; 16]>(),
            flight in any::<u16>(),
            tls in proptest::collection::vec(any::<u8>(), 0..5000),
        ) {
            let f = handshake_frame(initiator, &nonce, flight, &tls).unwrap();
            // Padded to a size bucket.
            prop_assert!(f.len() >= 22 + tls.len());
            prop_assert!([256, 512, 1024, 1500, 2048, 4096, 8192, 16384].contains(&f.len()));
            let h = parse_handshake(&f).unwrap();
            prop_assert_eq!((h.initiator, h.nonce, h.flight, h.tls), (initiator, nonce, flight, &tls[..]));
            prop_assert_eq!(parse_header(&f).unwrap().ty, ftype::HANDSHAKE);
        }

        #[test]
        fn parsers_take_any_bytes(f in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = parse_header(&f);
            let _ = parse_handshake(&f);
            let _ = parse_relay(&f);
            let _ = SessionKey::new([1; 32]).open(&f);
        }

        /// The bitmap window accepts exactly what a set of seen counters
        /// and a sliding lower bound accept (RFC 6479).
        #[test]
        fn replay_window_matches_a_model(
            ops in proptest::collection::vec(
                prop_oneof![
                    // Mostly near the top, sometimes far ahead or far behind.
                    8 => (0u64..64).prop_map(|d| (true, d)),
                    2 => (0u64..3 * WINDOW).prop_map(|d| (true, d)),
                    3 => (0u64..64).prop_map(|d| (false, d)),
                    1 => (0u64..3 * WINDOW).prop_map(|d| (false, d)),
                ],
                1..400,
            ),
        ) {
            let mut w = ReplayWindow::default();
            let mut seen: BTreeSet<u64> = BTreeSet::new();
            let mut top: Option<u64> = None;
            let base = 10 * WINDOW;
            for (ahead, d) in ops {
                let t = top.unwrap_or(base);
                let c = if ahead { t + d } else { t.saturating_sub(d) };
                let expect = match top {
                    None => true,
                    Some(t) => !seen.contains(&c) && (c > t || t - c < WINDOW),
                };
                prop_assert_eq!(w.check(c), expect, "check {}", c);
                prop_assert_eq!(w.mark(c), expect, "mark {}", c);
                if expect {
                    seen.insert(c);
                    top = Some(top.map_or(c, |t| t.max(c)));
                }
                // Marking twice never succeeds.
                prop_assert!(!w.mark(c));
            }
        }
    }
}
