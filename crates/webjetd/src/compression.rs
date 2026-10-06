//! Compression on the wire (§9.8): which peers get compressed messages, the
//! hop-record and RPC helpers for the control plane (zstd), and the
//! counters. The data plane (LZ4 per packet) lives in `e2e::send`.
//!
//! A message is compressed only when this node has the plane turned on and
//! the peer advertises it in its EndpointRecord features (it has it turned
//! on too). Compressed messages are always accepted, whatever the settings,
//! because a peer's view of our features lags a change.

use crate::node::Node;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use webjet_core::compress::{self, FEATURE_LZ4, FEATURE_ZSTD, Settings};
use webjet_core::crypto::Bytes32;
use webjet_net::hop::{self, MAX_RECORD, rec};
use webjet_proto::{self as wp, RpcBody};

/// The settings in force for this node, as last read from the tree by
/// [`refresh`] (the data path doesn't take the store lock per packet).
pub fn mine(n: &Node) -> Settings {
    let c = &n.metrics.compression;
    Settings {
        control: c.control_algo.load(Ordering::Relaxed),
        data: c.data_algo.load(Ordering::Relaxed),
    }
}

/// Re-read the settings from the tree; true when they changed.
pub fn refresh(n: &Node) -> bool {
    let s = n.store.read().view().compression(&n.me);
    let c = &n.metrics.compression;
    let old_control = c.control_algo.swap(s.control, Ordering::Relaxed);
    let old_data = c.data_algo.swap(s.data, Ordering::Relaxed);
    old_control != s.control || old_data != s.data
}

/// Whether a peer advertises a feature in its EndpointRecord.
fn peer_has(n: &Node, peer: &Bytes32, feature: &str) -> bool {
    n.records.lock().endpoints.get(peer).is_some_and(|(r, _)| {
        r.features
            .as_ref()
            .is_some_and(|f| f.iter().any(|x| x == feature))
    })
}

/// Control messages to `peer` may be zstd-compressed.
pub fn control_to(n: &Node, peer: &Bytes32) -> bool {
    mine(n).control_on() && peer_has(n, peer, FEATURE_ZSTD)
}

/// Data packets to `peer` may be LZ4-compressed.
pub fn data_to(n: &Node, peer: &Bytes32) -> bool {
    mine(n).data_on() && peer_has(n, peer, FEATURE_LZ4)
}

// ---------------------------------------------------------------- counters

#[derive(Default, Debug)]
pub struct Plane {
    pub tx_messages: AtomicU64,
    pub tx_raw_bytes: AtomicU64,
    pub tx_wire_bytes: AtomicU64,
    pub tx_skipped: AtomicU64,
    pub rx_messages: AtomicU64,
    pub rx_raw_bytes: AtomicU64,
    pub rx_wire_bytes: AtomicU64,
    pub rx_errors: AtomicU64,
}

impl Plane {
    pub fn sent(&self, raw: usize, wire: usize) {
        self.tx_messages.fetch_add(1, Ordering::Relaxed);
        self.tx_raw_bytes.fetch_add(raw as u64, Ordering::Relaxed);
        self.tx_wire_bytes.fetch_add(wire as u64, Ordering::Relaxed);
    }

    pub fn skipped(&self) {
        self.tx_skipped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn received(&self, raw: usize, wire: usize) {
        self.rx_messages.fetch_add(1, Ordering::Relaxed);
        self.rx_raw_bytes.fetch_add(raw as u64, Ordering::Relaxed);
        self.rx_wire_bytes.fetch_add(wire as u64, Ordering::Relaxed);
    }

    pub fn error(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn report(&self, plane: &str) -> wp::CompressionMetrics {
        let ld = |a: &AtomicU64| a.load(Ordering::Relaxed);
        wp::CompressionMetrics {
            plane: Some(plane.into()),
            tx_messages: ld(&self.tx_messages),
            tx_raw_bytes: ld(&self.tx_raw_bytes),
            tx_wire_bytes: ld(&self.tx_wire_bytes),
            tx_skipped: ld(&self.tx_skipped),
            rx_messages: ld(&self.rx_messages),
            rx_raw_bytes: ld(&self.rx_raw_bytes),
            rx_wire_bytes: ld(&self.rx_wire_bytes),
            rx_errors: ld(&self.rx_errors),
        }
    }
}

#[derive(Debug)]
pub struct Counters {
    pub control: Plane,
    pub data: Plane,
    /// The settings in force (`compress::algo` values), see [`mine`].
    control_algo: AtomicU8,
    data_algo: AtomicU8,
}

impl Default for Counters {
    fn default() -> Self {
        let d = Settings::default();
        Counters {
            control: Plane::default(),
            data: Plane::default(),
            control_algo: AtomicU8::new(d.control),
            data_algo: AtomicU8::new(d.data),
        }
    }
}

impl Counters {
    /// Both planes for the metric report.
    pub fn report(&self) -> Vec<wp::CompressionMetrics> {
        vec![self.control.report("control"), self.data.report("data")]
    }
}

// ---------------------------------------------------------------- control plane

/// An encoded hop record, compressed when it is a control record worth
/// compressing (`CONTROL` → `CONTROL_ZSTD`); otherwise unchanged.
pub fn control_record(n: &Node, peer: &Bytes32, record: Vec<u8>) -> Vec<u8> {
    if record.first() != Some(&rec::CONTROL)
        || record.len() < 4 + compress::MIN_CONTROL
        || !control_to(n, peer)
    {
        return record;
    }
    let Some(payload) = record.get(4..) else {
        return record;
    };
    match compress::zstd_compress(payload) {
        Some(c) => {
            n.metrics.compression.control.sent(payload.len(), c.len());
            hop::encode_record(rec::CONTROL_ZSTD, &c)
        }
        None => {
            n.metrics.compression.control.skipped();
            record
        }
    }
}

/// Decompress a `CONTROL_ZSTD` record's payload.
pub fn control_payload(n: &Node, payload: &[u8]) -> Option<Vec<u8>> {
    let out = compress::zstd_decompress(payload, MAX_RECORD);
    match &out {
        Some(p) => n
            .metrics
            .compression
            .control
            .received(p.len(), payload.len()),
        None => n.metrics.compression.control.error(),
    }
    out
}

/// RPC bodies that are never compressed: they carry secrets (PSKs, the
/// camouflage key; Raft entries and snapshots hold both) next to data that
/// others can influence, which is what makes compression leak (§9.8).
pub fn secret_rpc(body: &RpcBody) -> bool {
    matches!(
        body,
        RpcBody::PskInfo(_)
            | RpcBody::CamouflageSecret(_)
            | RpcBody::RaftRpc(_)
            | RpcBody::SnapshotReply(_)
    )
}

/// An RPC frame to `peer`: `(RPC_ZSTD, compressed)` when allowed and
/// smaller, else `(RPC, msg)`.
/// `secret` is [`secret_rpc`] of the body.
pub fn rpc_frame(n: &Node, peer: &Bytes32, secret: bool, msg: Vec<u8>) -> (u8, Vec<u8>) {
    use webjet_core::frames::ftype;
    if msg.len() < compress::MIN_CONTROL || secret || !control_to(n, peer) {
        return (ftype::RPC, msg);
    }
    match compress::zstd_compress(&msg) {
        Some(c) => {
            n.metrics.compression.control.sent(msg.len(), c.len());
            (ftype::RPC_ZSTD, c)
        }
        None => {
            n.metrics.compression.control.skipped();
            (ftype::RPC, msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testnode::{self, Cluster};
    use webjet_core::compress::algo;
    use webjet_core::frames::ftype;

    const PEER: Bytes32 = [7; 32];

    fn setup() -> (Cluster, std::sync::Arc<Node>, tempfile::TempDir) {
        let mut c = Cluster::new();
        let (me, kp) = c.data_node("me", "10.7.0.2", &[]);
        let (n, dir) = testnode::node(&mut c, me, kp);
        (c, n, dir)
    }

    fn advertise(n: &Node, features: &[&str]) {
        let r = wp::EndpointRecord {
            node_id: Some(webjet_core::crypto::k32(&PEER)),
            features: Some(features.iter().map(|f| f.to_string()).collect()),
            ..Default::default()
        };
        n.records.lock().endpoints.insert(PEER, (r, Vec::new()));
    }

    /// Compressible control payload of `len` bytes.
    fn payload(len: usize) -> Vec<u8> {
        b"webjet control message "
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect()
    }

    #[test]
    fn settings_follow_the_tree() {
        let (mut c, n, _d) = setup();
        // Built-in: control zstd, data off.
        assert!(!refresh(&n));
        assert!(mine(&n).control_on() && !mine(&n).data_on());

        c.set_network(wp::NetworkConfig {
            transport: Some(Box::new(wp::TransportConfig {
                compression: Some(Box::new(wp::CompressionConfig {
                    control: algo::OFF,
                    data: algo::LZ4,
                })),
                ..Default::default()
            })),
            ..Default::default()
        })
        .unwrap();
        testnode::sync(&mut c, &n);
        assert!(refresh(&n));
        assert!(!refresh(&n), "unchanged the second time");
        assert!(!mine(&n).control_on() && mine(&n).data_on());
    }

    #[test]
    fn only_peers_that_advertise_get_compressed_messages() {
        let (_c, n, _d) = setup();
        assert!(!control_to(&n, &PEER), "unknown peer");
        advertise(&n, &[]);
        assert!(!control_to(&n, &PEER));
        assert!(!data_to(&n, &PEER));
        advertise(&n, &[FEATURE_ZSTD, FEATURE_LZ4]);
        assert!(control_to(&n, &PEER));
        // Data compression is off here, whatever the peer has.
        assert!(!data_to(&n, &PEER));
    }

    #[test]
    fn control_records_roundtrip() {
        let (_c, n, _d) = setup();
        advertise(&n, &[FEATURE_ZSTD]);
        let body = payload(4000);
        let record = hop::encode_record(rec::CONTROL, &body);
        let out = control_record(&n, &PEER, record.clone());
        assert_eq!(out[0], rec::CONTROL_ZSTD);
        assert!(out.len() < record.len() / 4);
        assert_eq!(control_payload(&n, &out[4..]).unwrap(), body);

        let ctl = &n.metrics.compression.control;
        assert_eq!(ctl.tx_messages.load(Ordering::Relaxed), 1);
        assert_eq!(ctl.tx_raw_bytes.load(Ordering::Relaxed), 4000);
        assert_eq!(ctl.rx_messages.load(Ordering::Relaxed), 1);
        assert_eq!(ctl.rx_raw_bytes.load(Ordering::Relaxed), 4000);

        // Garbage counts as an error.
        assert!(control_payload(&n, b"not zstd").is_none());
        assert_eq!(ctl.rx_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn control_records_left_alone() {
        let (_c, n, _d) = setup();
        let big = hop::encode_record(rec::CONTROL, &payload(4000));
        // The peer doesn't take zstd.
        assert_eq!(control_record(&n, &PEER, big.clone()), big);
        advertise(&n, &[FEATURE_ZSTD]);
        // Too short to be worth it.
        let small = hop::encode_record(rec::CONTROL, &payload(compress::MIN_CONTROL - 1));
        assert_eq!(control_record(&n, &PEER, small.clone()), small);
        // Not a control record.
        let relay = hop::encode_record(rec::RELAY, &payload(4000));
        assert_eq!(control_record(&n, &PEER, relay.clone()), relay);
        // Incompressible: sent as it is and counted as skipped.
        let noise: Vec<u8> = (0..4000).map(|_| rand::random()).collect();
        let rnd = hop::encode_record(rec::CONTROL, &noise);
        assert_eq!(control_record(&n, &PEER, rnd.clone()), rnd);
        let ctl = &n.metrics.compression.control;
        assert_eq!(ctl.tx_skipped.load(Ordering::Relaxed), 1);
        assert_eq!(ctl.tx_messages.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rpc_frames() {
        let (_c, n, _d) = setup();
        advertise(&n, &[FEATURE_ZSTD]);
        let msg = payload(4000);
        let (ty, c) = rpc_frame(&n, &PEER, false, msg.clone());
        assert_eq!(ty, ftype::RPC_ZSTD);
        assert_eq!(compress::zstd_decompress(&c, MAX_RECORD).unwrap(), msg);
        // Secrets are never compressed.
        assert_eq!(rpc_frame(&n, &PEER, true, msg.clone()), (ftype::RPC, msg));
        let short = payload(10);
        assert_eq!(
            rpc_frame(&n, &PEER, false, short.clone()),
            (ftype::RPC, short)
        );
    }

    #[test]
    fn secret_bodies() {
        assert!(secret_rpc(&RpcBody::PskInfo(Box::default())));
        assert!(secret_rpc(&RpcBody::CamouflageSecret(Box::default())));
        assert!(secret_rpc(&RpcBody::RaftRpc(Box::default())));
        assert!(secret_rpc(&RpcBody::SnapshotReply(Box::default())));
        assert!(!secret_rpc(&RpcBody::GetPsk(Box::default())));
        assert!(!secret_rpc(&RpcBody::SubmitOp(Box::default())));
    }

    #[test]
    fn report_has_both_planes() {
        let c = Counters::default();
        c.data.sent(1000, 400);
        let r = c.report();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].plane.as_deref(), Some("control"));
        assert_eq!(r[1].plane.as_deref(), Some("data"));
        assert_eq!((r[1].tx_raw_bytes, r[1].tx_wire_bytes), (1000, 400));
    }
}
