//! End-to-end frames (§6.9, §9.4.3-§9.4.4), the replay window (RFC 6479
//! style, 8192 packets) and the relay frame header (§11.5, §17.7).

use crate::crypto::Bytes32;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
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
}

/// type(1) + key_id(4) + counter(8)
pub const HEADER: usize = 13;
pub const TAG: usize = 16;
pub const OVERHEAD: usize = HEADER + TAG;

/// Maximum counter before a key must not be used any more (2⁴⁰ packets, §9.4.5).
pub const REKEY_PACKETS: u64 = 1 << 40;

pub struct SessionKey {
    cipher: ChaCha20Poly1305,
}

impl SessionKey {
    pub fn new(mut k: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
        k.zeroize();
        SessionKey { cipher }
    }

    fn nonce(counter: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&counter.to_be_bytes());
        *Nonce::from_slice(&n)
    }

    /// Seal `payload` into a complete frame. `None` only if the payload is
    /// beyond what the AEAD can encrypt (~256 GiB).
    pub fn seal(&self, ty: u8, key_id: u32, counter: u64, payload: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(OVERHEAD + payload.len());
        out.push(ty);
        out.extend_from_slice(&key_id.to_be_bytes());
        out.extend_from_slice(&counter.to_be_bytes());
        let mut body = payload.to_vec();
        let mut aad = [0u8; HEADER];
        aad.copy_from_slice(&out);
        let tag = self
            .cipher
            .encrypt_in_place_detached(&Self::nonce(counter), &aad, &mut body)
            .ok()?;
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
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
        let (ct, tag) = rest.split_at(rest.len() - TAG);
        let mut body = ct.to_vec();
        self.cipher
            .decrypt_in_place_detached(&Self::nonce(counter), hdr, &mut body, tag.into())
            .ok()?;
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
pub fn handshake_frame(initiator: bool, nonce: &[u8; 16], flight: u16, tls: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(32 + tls.len());
    f.push(ftype::HANDSHAKE);
    f.push(initiator as u8);
    f.extend_from_slice(nonce);
    f.extend_from_slice(&flight.to_be_bytes());
    f.extend_from_slice(&(tls.len() as u16).to_be_bytes());
    f.extend_from_slice(tls);
    let bucket = [256usize, 512, 1024, 1500, 2048, 4096, 8192, 16384]
        .into_iter()
        .find(|b| *b >= f.len())
        .unwrap_or(f.len());
    f.resize(bucket, 0);
    f
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
        let mut bad = f.clone();
        bad[0] = ftype::PROBE; // type is authenticated
        assert!(k.open(&bad).is_none());
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
    fn handshake_padding() {
        let f = handshake_frame(true, &[1; 16], 3, &[9; 300]);
        assert_eq!(f.len(), 512);
        let h = parse_handshake(&f).unwrap();
        assert!(h.initiator);
        assert_eq!(h.nonce, [1; 16]);
        assert_eq!(h.flight, 3);
        assert_eq!(h.tls.len(), 300);
    }
}
