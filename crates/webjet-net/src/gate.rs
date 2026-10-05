//! The pre-handshake PSK gate (§9.1) and UDP packet encryption (§9.7.3).
//!
//! * TCP+TLS: the client first sends
//!   `epoch_id[2] || timestamp[8] || nonce[16] || MAC[32]` where
//!   `MAC = BLAKE3-keyed(derive("webjet tcp gate v1", PSK_epoch), epoch||ts||nonce)`.
//! * UDP: every datagram is `nonce[24] || masked_epoch[2] || XChaCha20-Poly1305(k_epoch, nonce, inner || padding)`.
//!   The first packet of a KCP session carries a timestamp inside the ciphertext (§9.1).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use parking_lot::Mutex;
use rand::Rng;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use webjet_core::crypto::{Bytes32, ct_eq, ctx, derive, keyed};
use webjet_core::types::{SKEW_PSK_GATE, now_ms};

pub const TCP_PREAMBLE: usize = 2 + 8 + 16 + 32;
pub const UDP_OVERHEAD: usize = 24 + 2 + 16;

/// Which PSK epochs this node accepts (§7.6, §10.7.3).
#[derive(Clone, Debug, Default)]
pub struct Epochs {
    pub keys: BTreeMap<u16, Bytes32>,
    pub current: u16,
    /// Controllers and seed relays accept every past epoch, in bootstrap mode.
    pub accept_all: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateResult {
    /// Current or previous epoch.
    Normal(u16),
    /// An older epoch, accepted only by controllers and seed relays (§10.7.3).
    Bootstrap(u16),
}

impl GateResult {
    pub fn epoch(&self) -> u16 {
        match self {
            GateResult::Normal(e) | GateResult::Bootstrap(e) => *e,
        }
    }
    pub fn bootstrap(&self) -> bool {
        matches!(self, GateResult::Bootstrap(_))
    }
}

impl Epochs {
    pub fn current_key(&self) -> Option<(u16, Bytes32)> {
        self.keys.get(&self.current).map(|k| (self.current, *k))
    }

    pub fn classify(&self, epoch: u16) -> Option<GateResult> {
        let _ = self.keys.get(&epoch)?;
        if epoch == self.current || epoch == self.current.wrapping_sub(1) {
            Some(GateResult::Normal(epoch))
        } else if self.accept_all {
            Some(GateResult::Bootstrap(epoch))
        } else {
            None
        }
    }
}

/// A shared, updatable epoch set.
pub type SharedEpochs = Arc<parking_lot::RwLock<Epochs>>;

// ---------------------------------------------------------------- replay cache

type Nonce = [u8; 16];

/// Nonces with the time they were seen, by value and in arrival order.
#[derive(Default)]
struct Seen {
    map: HashMap<Nonce, u64>,
    order: VecDeque<(Nonce, u64)>,
}

/// Remembers nonces seen within the timestamp tolerance, bounded in size.
pub struct ReplayCache {
    seen: Mutex<Seen>,
    cap: usize,
}

impl ReplayCache {
    pub fn new(cap: usize) -> Self {
        ReplayCache {
            seen: Mutex::new(Seen::default()),
            cap,
        }
    }

    /// Returns false if the nonce was already seen.
    pub fn check_and_insert(&self, nonce: [u8; 16], now: u64) -> bool {
        let mut g = self.seen.lock();
        let Seen { map, order } = &mut *g;
        while let Some((n, t)) = order.front().copied() {
            if t + 2 * SKEW_PSK_GATE < now || order.len() > self.cap {
                order.pop_front();
                if map.get(&n) == Some(&t) {
                    map.remove(&n);
                }
            } else {
                break;
            }
        }
        if map.contains_key(&nonce) {
            return false;
        }
        map.insert(nonce, now);
        order.push_back((nonce, now));
        true
    }
}

// ---------------------------------------------------------------- TCP preamble

fn tcp_gate_key(psk: &Bytes32) -> Bytes32 {
    derive(ctx::TCP_GATE, psk)
}

pub fn tcp_preamble(epoch: u16, psk: &Bytes32) -> [u8; TCP_PREAMBLE] {
    let mut out = [0u8; TCP_PREAMBLE];
    out[..2].copy_from_slice(&epoch.to_be_bytes());
    out[2..10].copy_from_slice(&now_ms().to_be_bytes());
    UnwrapErr(SysRng).fill_bytes(&mut out[10..26]);
    let mac = keyed(&tcp_gate_key(psk), &out[..26]);
    out[26..].copy_from_slice(&mac);
    out
}

/// Check a TCP preamble. Returns `None` on any failure; the caller closes
/// the connection without a reply.
pub fn check_tcp_preamble(
    p: &[u8; TCP_PREAMBLE],
    epochs: &Epochs,
    replay: &ReplayCache,
) -> Option<GateResult> {
    let epoch = u16::from_be_bytes([p[0], p[1]]);
    let res = epochs.classify(epoch)?;
    let psk = epochs.keys.get(&epoch)?;
    let mac = keyed(&tcp_gate_key(psk), &p[..26]);
    if !ct_eq(&mac, &p[26..]) {
        return None;
    }
    let ts = webjet_core::bytes::be_u64(p, 2)?;
    let now = now_ms();
    if ts.abs_diff(now) > SKEW_PSK_GATE {
        return None;
    }
    if !replay.check_and_insert(webjet_core::bytes::array(p, 10)?, now) {
        return None;
    }
    Some(res)
}

// ---------------------------------------------------------------- AnyTLS password

/// `BLAKE3.derive_key("webjet anytls password v1", PSK_epoch)` (§9.7.2).
pub fn anytls_password(psk: &Bytes32) -> Bytes32 {
    derive(ctx::ANYTLS_PASSWORD, psk)
}

/// The credential of a not-yet-enrolled node, derived from its token (§9.7.2).
pub fn anytls_enroll_password(token_hash: &Bytes32) -> Bytes32 {
    derive(ctx::ENROLL_ANYTLS, token_hash)
}

// ---------------------------------------------------------------- UDP obfuscation

/// Per-network UDP obfuscator: `k_obfs` from the root key, `k_epoch` per PSK epoch.
pub struct UdpObfs {
    k_obfs: Bytes32,
    ciphers: parking_lot::RwLock<BTreeMap<u16, XChaCha20Poly1305>>,
}

impl UdpObfs {
    pub fn new(root_key: &Bytes32) -> Self {
        UdpObfs {
            k_obfs: derive(ctx::UDP_OBFS, root_key),
            ciphers: parking_lot::RwLock::new(BTreeMap::new()),
        }
    }

    pub fn set_epochs(&self, e: &Epochs) {
        let mut c = self.ciphers.write();
        c.clear();
        for (id, psk) in &e.keys {
            let k = derive(ctx::UDP_PACKET, psk);
            c.insert(*id, XChaCha20Poly1305::new((&k).into()));
        }
    }

    fn mask(&self, nonce: &[u8]) -> [u8; 2] {
        let h = keyed(&self.k_obfs, nonce);
        [h[0], h[1]]
    }

    /// Encrypt `inner` under `epoch`, adding `pad` bytes of random padding
    /// (inside the ciphertext, after a 2-byte length).
    pub fn seal(&self, epoch: u16, inner: &[u8], pad: usize) -> Option<Vec<u8>> {
        let ciphers = self.ciphers.read();
        let c = ciphers.get(&epoch)?;
        let mut nonce = [0u8; 24];
        UnwrapErr(SysRng).fill_bytes(&mut nonce);
        let mut pt = Vec::with_capacity(2 + inner.len() + pad);
        pt.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        pt.extend_from_slice(inner);
        let mut padding = vec![0u8; pad];
        UnwrapErr(SysRng).fill_bytes(&mut padding);
        pt.extend_from_slice(&padding);
        let m = self.mask(&nonce);
        let me = [epoch.to_be_bytes()[0] ^ m[0], epoch.to_be_bytes()[1] ^ m[1]];
        let ct = c
            .encrypt(&XNonce::from(nonce), Payload { msg: &pt, aad: &me })
            .ok()?;
        let mut out = Vec::with_capacity(26 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&me);
        out.extend_from_slice(&ct);
        Some(out)
    }

    /// Decrypt a datagram; `None` means drop silently.
    pub fn open(&self, d: &[u8], epochs: &Epochs) -> Option<(GateResult, Vec<u8>)> {
        if d.len() < UDP_OVERHEAD + 2 {
            return None;
        }
        let nonce = &d[..24];
        let m = self.mask(nonce);
        let epoch = u16::from_be_bytes([d[24] ^ m[0], d[25] ^ m[1]]);
        let res = epochs.classify(epoch)?;
        let ciphers = self.ciphers.read();
        let c = ciphers.get(&epoch)?;
        let pt = c
            .decrypt(
                &XNonce::try_from(nonce).ok()?,
                Payload {
                    msg: &d[26..],
                    aad: &d[24..26],
                },
            )
            .ok()?;
        let len = u16::from_be_bytes([pt[0], pt[1]]) as usize;
        let inner = pt.get(2..2 + len)?.to_vec();
        Some((res, inner))
    }
}

/// Random padding for small UDP packets (§9.7.4): acks and keepalives get
/// a random length so they don't share one size.
pub fn small_packet_padding(len: usize) -> usize {
    if len < 200 {
        (rand::random::<u8>() % 96) as usize
    } else {
        (rand::random::<u8>() % 16) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epochs() -> Epochs {
        let mut e = Epochs::default();
        e.keys.insert(1, [1; 32]);
        e.keys.insert(2, [2; 32]);
        e.keys.insert(3, [3; 32]);
        e.current = 3;
        e
    }

    #[test]
    fn tcp_gate() {
        let e = epochs();
        let rc = ReplayCache::new(1000);
        let p = tcp_preamble(3, &[3; 32]);
        assert_eq!(check_tcp_preamble(&p, &e, &rc), Some(GateResult::Normal(3)));
        assert_eq!(check_tcp_preamble(&p, &e, &rc), None, "replay");
        let p = tcp_preamble(1, &[1; 32]);
        assert_eq!(
            check_tcp_preamble(&p, &e, &rc),
            None,
            "too old for a normal node"
        );
        let mut seed = e.clone();
        seed.accept_all = true;
        assert_eq!(
            check_tcp_preamble(&p, &seed, &rc),
            Some(GateResult::Bootstrap(1))
        );
        let mut bad = tcp_preamble(3, &[3; 32]);
        bad[40] ^= 1;
        assert_eq!(check_tcp_preamble(&bad, &e, &rc), None);
    }

    #[test]
    fn udp_obfs() {
        let e = epochs();
        let o = UdpObfs::new(&[9; 32]);
        o.set_epochs(&e);
        let d = o.seal(3, b"kcp packet", 17).unwrap();
        assert_eq!(d.len(), UDP_OVERHEAD + 2 + 10 + 17);
        let (r, inner) = o.open(&d, &e).unwrap();
        assert_eq!(r, GateResult::Normal(3));
        assert_eq!(inner, b"kcp packet");
        let mut bad = d.clone();
        bad[30] ^= 1;
        assert!(o.open(&bad, &e).is_none());
        // No constant bytes at fixed positions across datagrams.
        let d2 = o.seal(3, b"kcp packet", 17).unwrap();
        assert_ne!(d[24..26], d2[24..26]);
        // Another network (different root) can't read it.
        let o2 = UdpObfs::new(&[8; 32]);
        o2.set_epochs(&e);
        assert!(o2.open(&d, &e).is_none());
    }
}
