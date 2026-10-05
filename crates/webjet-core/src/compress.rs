//! Compression (§9.8): zstd for control messages (hop control records and
//! RPCs), LZ4 for data packets (each packet on its own), the settings that
//! decide which is in force, and the per-flow backoff that stops the data
//! plane from compressing traffic that doesn't shrink.
//!
//! Everything here is pure. Decompression never produces more than the cap
//! the caller gives and returns `None` for anything malformed.

use std::cell::RefCell;

/// Wire values of `CompressionConfig.control` / `.data` (webjet.fbs).
pub mod algo {
    /// Not set here: the next level decides (node, network, built-in).
    pub const UNSET: u8 = 0;
    pub const OFF: u8 = 1;
    pub const ZSTD: u8 = 2;
    pub const LZ4: u8 = 3;

    pub fn name(v: u8) -> &'static str {
        match v {
            UNSET => "unset",
            OFF => "off",
            ZSTD => "zstd",
            LZ4 => "lz4",
            _ => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<u8> {
        match s {
            "off" => Some(OFF),
            "zstd" => Some(ZSTD),
            "lz4" => Some(LZ4),
            _ => None,
        }
    }
}

/// Built-in settings: zstd on the control plane, the data plane uncompressed.
pub const DEFAULT_CONTROL: u8 = algo::ZSTD;
pub const DEFAULT_DATA: u8 = algo::OFF;

/// The algorithms each plane may use.
pub const CONTROL_ALGOS: [u8; 2] = [algo::OFF, algo::ZSTD];
pub const DATA_ALGOS: [u8; 2] = [algo::OFF, algo::LZ4];

/// EndpointRecord features: the node has zstd control compression turned on
/// (and takes compressed control records and RPCs), resp. LZ4 data
/// compression. A sender compresses only when both ends have it on.
pub const FEATURE_ZSTD: &str = "zstd";
pub const FEATURE_LZ4: &str = "lz4";

/// zstd level for control messages.
pub const ZSTD_LEVEL: i32 = 3;
/// Control messages shorter than this are sent as they are.
pub const MIN_CONTROL: usize = 256;
/// Data packets shorter than this are sent as they are.
pub const MIN_DATA: usize = 128;
/// A compressed data packet must be at least this much smaller.
const MIN_DATA_GAIN: usize = 16;

/// The settings in force for one node (§6.17, §6.19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub control: u8,
    pub data: u8,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            control: DEFAULT_CONTROL,
            data: DEFAULT_DATA,
        }
    }
}

impl Settings {
    /// First set value per plane: the node's, the network's, built-in.
    /// Values a node doesn't know count as off.
    pub fn resolve(node: Option<(u8, u8)>, network: Option<(u8, u8)>) -> Settings {
        let pick = |n: Option<u8>, w: Option<u8>, builtin: u8, allowed: &[u8]| {
            let v = [n, w]
                .into_iter()
                .flatten()
                .find(|v| *v != algo::UNSET)
                .unwrap_or(builtin);
            if allowed.contains(&v) { v } else { algo::OFF }
        };
        Settings {
            control: pick(
                node.map(|x| x.0),
                network.map(|x| x.0),
                DEFAULT_CONTROL,
                &CONTROL_ALGOS,
            ),
            data: pick(
                node.map(|x| x.1),
                network.map(|x| x.1),
                DEFAULT_DATA,
                &DATA_ALGOS,
            ),
        }
    }

    pub fn control_on(&self) -> bool {
        self.control == algo::ZSTD
    }

    pub fn data_on(&self) -> bool {
        self.data == algo::LZ4
    }

    /// The EndpointRecord features these settings advertise.
    pub fn features(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.control_on() {
            v.push(FEATURE_ZSTD);
        }
        if self.data_on() {
            v.push(FEATURE_LZ4);
        }
        v
    }
}

/// Check a configured pair of values: `control` must be unset, off or
/// zstd; `data` unset, off or lz4.
pub fn check(control: u8, data: u8) -> anyhow::Result<()> {
    if control != algo::UNSET && !CONTROL_ALGOS.contains(&control) {
        anyhow::bail!(
            "compression.control must be \"zstd\" or \"off\", got {}",
            algo::name(control)
        );
    }
    if data != algo::UNSET && !DATA_ALGOS.contains(&data) {
        anyhow::bail!(
            "compression.data must be \"lz4\" or \"off\", got {}",
            algo::name(data)
        );
    }
    Ok(())
}

// ---------------------------------------------------------------- zstd (control plane)

thread_local! {
    static ZC: RefCell<Option<zstd::bulk::Compressor<'static>>> = const { RefCell::new(None) };
    static ZD: RefCell<Option<zstd::bulk::Decompressor<'static>>> = const { RefCell::new(None) };
}

/// zstd-compress a control message. `None` when it is too short or doesn't
/// get smaller (send it as it is).
pub fn zstd_compress(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < MIN_CONTROL {
        return None;
    }
    let out = ZC.with(|c| {
        let mut c = c.borrow_mut();
        if c.is_none() {
            *c = zstd::bulk::Compressor::new(ZSTD_LEVEL).ok();
        }
        c.as_mut()?.compress(data).ok()
    })?;
    (out.len() < data.len()).then_some(out)
}

/// Decompress a zstd frame of at most `cap` bytes. The frame must declare
/// its size (ours always do), so no more than that is ever allocated.
pub fn zstd_decompress(data: &[u8], cap: usize) -> Option<Vec<u8>> {
    let size = zstd::zstd_safe::get_frame_content_size(data).ok()??;
    let size = usize::try_from(size).ok().filter(|s| *s <= cap)?;
    let out = ZD.with(|d| {
        let mut d = d.borrow_mut();
        if d.is_none() {
            *d = zstd::bulk::Decompressor::new().ok();
        }
        let mut buf = Vec::with_capacity(size);
        d.as_mut()?.decompress_to_buffer(data, &mut buf).ok()?;
        Some(buf)
    })?;
    (out.len() == size).then_some(out)
}

// ---------------------------------------------------------------- LZ4 (data plane)

/// LZ4-compress one packet: `len[2] || block`. `None` when the packet is
/// too short, too long for the length field, or doesn't shrink enough.
pub fn lz4_compress(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < MIN_DATA {
        return None;
    }
    let len = u16::try_from(packet.len()).ok()?;
    let mut out = vec![0u8; 2 + lz4_flex::block::get_maximum_output_size(packet.len())];
    out[..2].copy_from_slice(&len.to_be_bytes());
    let n = lz4_flex::block::compress_into(packet, &mut out[2..]).ok()?;
    out.truncate(2 + n);
    (out.len() + MIN_DATA_GAIN <= packet.len()).then_some(out)
}

/// Decompress a packet made by [`lz4_compress`]. `None` if malformed or if
/// it would be longer than `cap`.
pub fn lz4_decompress(data: &[u8], cap: usize) -> Option<Vec<u8>> {
    let len = usize::from(crate::bytes::be_u16(data, 0)?);
    if len > cap || len == 0 {
        return None;
    }
    let mut out = vec![0u8; len];
    let n = lz4_flex::block::decompress_into(data.get(2..)?, &mut out).ok()?;
    (n == len).then_some(out)
}

// ---------------------------------------------------------------- per-flow backoff

/// Whether a packet is known not to compress: traffic that is encrypted
/// already (HTTPS and QUIC, DNS over TLS, SSH, ESP).
pub fn incompressible(packet: &[u8]) -> bool {
    const PORTS: [u16; 3] = [443, 853, 22];
    match flow_of(packet) {
        Some((proto, sport, dport)) => {
            proto == 50
                || ((proto == 6 || proto == 17)
                    && (PORTS.contains(&sport) || PORTS.contains(&dport)))
        }
        None => false,
    }
}

/// Protocol and ports (0 when the protocol has none) of an IP packet.
fn flow_of(p: &[u8]) -> Option<(u8, u16, u16)> {
    let (proto, l4) = match p.first()? >> 4 {
        4 => {
            let ihl = usize::from(p.first()? & 0x0f) * 4;
            let frag = crate::bytes::be_u16(p, 6)? & 0x1fff;
            if frag != 0 {
                return Some((*p.get(9)?, 0, 0));
            }
            (*p.get(9)?, ihl)
        }
        6 => (*p.get(6)?, 40),
        _ => return None,
    };
    if proto == 6 || proto == 17 {
        Some((
            proto,
            crate::bytes::be_u16(p, l4).unwrap_or(0),
            crate::bytes::be_u16(p, l4 + 2).unwrap_or(0),
        ))
    } else {
        Some((proto, 0, 0))
    }
}

/// A flow key for [`Backoff`]: a hash of addresses, protocol and ports.
pub fn flow_key(p: &[u8]) -> u32 {
    let (addrs, rest) = match p.first().map(|b| b >> 4) {
        Some(4) => (p.get(12..20), flow_of(p)),
        Some(6) => (p.get(8..40), flow_of(p)),
        _ => (None, None),
    };
    let mut h = blake3::Hasher::new();
    h.update(addrs.unwrap_or_default());
    if let Some((proto, s, d)) = rest {
        h.update(&[proto]);
        h.update(&s.to_be_bytes());
        h.update(&d.to_be_bytes());
    }
    let b = h.finalize();
    let b = b.as_bytes();
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

const SLOTS: usize = 64;
/// Misses in a row before a flow is skipped.
const MISSES: u8 = 3;
/// Packets skipped after the first run of misses; doubles per further miss.
const SKIP_FIRST: u16 = 32;
const SKIP_MAX: u16 = 1024;

#[derive(Clone, Copy, Default)]
struct Slot {
    key: u32,
    misses: u8,
    skip: u16,
}

/// Remembers, per flow (a small table indexed by the flow key; a flow that
/// lands in a taken slot evicts it), whether compression has been paying
/// off. After [`MISSES`] packets in a row that didn't shrink, the flow's
/// next packets are sent without trying, and each further miss doubles the
/// pause, so an encrypted stream costs almost nothing while a flow that
/// becomes compressible is noticed again.
pub struct Backoff {
    slots: [Slot; SLOTS],
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff {
            slots: [Slot::default(); SLOTS],
        }
    }
}

impl Backoff {
    fn slot(&mut self, key: u32) -> &mut Slot {
        let s = &mut self.slots[key as usize % SLOTS];
        if s.key != key {
            *s = Slot {
                key,
                misses: 0,
                skip: 0,
            };
        }
        s
    }

    /// Whether to try compressing this flow's next packet.
    pub fn should_try(&mut self, key: u32) -> bool {
        let s = self.slot(key);
        if s.skip > 0 {
            s.skip -= 1;
            return false;
        }
        true
    }

    /// The outcome of a try.
    pub fn record(&mut self, key: u32, shrank: bool) {
        let s = self.slot(key);
        if shrank {
            s.misses = 0;
            return;
        }
        s.misses = s.misses.saturating_add(1);
        if s.misses >= MISSES {
            let shift = u32::from(s.misses - MISSES).min(10);
            s.skip = SKIP_FIRST.saturating_mul(1 << shift).min(SKIP_MAX);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn text(n: usize) -> Vec<u8> {
        b"GET /index.html HTTP/1.1\r\nHost: example.internal\r\n"
            .iter()
            .cycle()
            .take(n)
            .copied()
            .collect()
    }

    fn random(n: usize) -> Vec<u8> {
        (0..n).map(|_| rand::random::<u8>()).collect()
    }

    #[test]
    fn zstd_round_trip_and_declared_size() {
        let d = text(4000);
        let c = zstd_compress(&d).unwrap();
        assert!(c.len() < d.len() / 4);
        assert_eq!(
            zstd::zstd_safe::get_frame_content_size(&c).unwrap(),
            Some(4000)
        );
        assert_eq!(zstd_decompress(&c, 1 << 20).unwrap(), d);
        // Above the cap: refused without allocating it.
        assert!(zstd_decompress(&c, 3999).is_none());
    }

    #[test]
    fn zstd_skips_short_and_incompressible() {
        assert!(zstd_compress(&text(MIN_CONTROL - 1)).is_none());
        assert!(zstd_compress(&random(2000)).is_none());
    }

    #[test]
    fn zstd_rejects_garbage() {
        assert!(zstd_decompress(&[], 100).is_none());
        assert!(zstd_decompress(&random(100), 1 << 20).is_none());
        let mut c = zstd_compress(&text(4000)).unwrap();
        let last = c.len() - 1;
        c[last] ^= 0xff;
        c.truncate(c.len() - 3);
        assert!(zstd_decompress(&c, 1 << 20).is_none());
    }

    #[test]
    fn lz4_round_trip() {
        let p = text(1280);
        let c = lz4_compress(&p).unwrap();
        assert!(c.len() < p.len() / 2);
        assert_eq!(lz4_decompress(&c, 1500).unwrap(), p);
        assert!(lz4_decompress(&c, 1279).is_none());
    }

    #[test]
    fn lz4_skips_short_and_incompressible() {
        assert!(lz4_compress(&text(MIN_DATA - 1)).is_none());
        assert!(lz4_compress(&random(1280)).is_none());
    }

    #[test]
    fn lz4_rejects_garbage() {
        assert!(lz4_decompress(&[], 1500).is_none());
        assert!(lz4_decompress(&[0, 0], 1500).is_none());
        assert!(lz4_decompress(&[0x05, 0x00, 0xff, 0xff], 1500).is_none());
        let mut c = lz4_compress(&text(1280)).unwrap();
        c.truncate(c.len() - 4);
        assert!(lz4_decompress(&c, 1500).is_none());
    }

    proptest! {
        #[test]
        fn zstd_any_input(d in proptest::collection::vec(any::<u8>(), 0..3000)) {
            if let Some(c) = zstd_compress(&d) {
                prop_assert_eq!(zstd_decompress(&c, d.len()).unwrap(), d.clone());
            }
            let _ = zstd_decompress(&d, 1 << 16);
        }

        #[test]
        fn lz4_any_input(d in proptest::collection::vec(0u8..4, 0..2000)) {
            if let Some(c) = lz4_compress(&d) {
                prop_assert_eq!(lz4_decompress(&c, d.len()).unwrap(), d.clone());
            }
            let _ = lz4_decompress(&d, 1 << 16);
        }
    }

    #[test]
    fn settings_precedence() {
        let s = Settings::resolve(None, None);
        assert_eq!(s, Settings::default());
        assert!(s.control_on() && !s.data_on());
        assert_eq!(s.features(), vec![FEATURE_ZSTD]);
        let s = Settings::resolve(None, Some((algo::OFF, algo::LZ4)));
        assert!(!s.control_on() && s.data_on());
        let s = Settings::resolve(Some((algo::UNSET, algo::OFF)), Some((algo::OFF, algo::LZ4)));
        assert!(!s.control_on() && !s.data_on());
        let s = Settings::resolve(
            Some((algo::ZSTD, algo::UNSET)),
            Some((algo::OFF, algo::LZ4)),
        );
        assert!(s.control_on() && s.data_on());
        // A value from a later version counts as off.
        let s = Settings::resolve(None, Some((9, 9)));
        assert!(!s.control_on() && !s.data_on());
    }

    #[test]
    fn check_values() {
        assert!(check(algo::UNSET, algo::UNSET).is_ok());
        assert!(check(algo::ZSTD, algo::LZ4).is_ok());
        assert!(check(algo::OFF, algo::OFF).is_ok());
        assert!(check(algo::LZ4, algo::OFF).is_err());
        assert!(check(algo::OFF, algo::ZSTD).is_err());
        assert!(check(7, algo::OFF).is_err());
    }

    #[test]
    fn known_encrypted_traffic() {
        let https = crate::packet::tests::tcp4([10, 7, 0, 1], [10, 7, 0, 2], 50000, 443, 0x18);
        assert!(incompressible(&https));
        let quic = crate::packet::tests::udp4([10, 7, 0, 1], [10, 7, 0, 2], 443, 50000, &[0; 64]);
        assert!(incompressible(&quic));
        let http = crate::packet::tests::tcp4([10, 7, 0, 1], [10, 7, 0, 2], 50000, 80, 0x18);
        assert!(!incompressible(&http));
        assert_ne!(flow_key(&https), flow_key(&http));
    }

    #[test]
    fn backoff_skips_and_recovers() {
        let mut b = Backoff::default();
        let k = 12345;
        for _ in 0..MISSES {
            assert!(b.should_try(k));
            b.record(k, false);
        }
        let skipped = (0..SKIP_FIRST).filter(|_| !b.should_try(k)).count();
        assert_eq!(skipped, usize::from(SKIP_FIRST));
        // The probe after the pause misses again: the pause doubles.
        assert!(b.should_try(k));
        b.record(k, false);
        let skipped = (0..SKIP_FIRST * 2).filter(|_| !b.should_try(k)).count();
        assert_eq!(skipped, usize::from(SKIP_FIRST * 2));
        // A hit resets the flow.
        assert!(b.should_try(k));
        b.record(k, true);
        b.record(k, false);
        assert!(b.should_try(k));
        // Another flow is independent.
        assert!(b.should_try(k + 1));
    }
}
