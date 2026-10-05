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
        RpcBody::PskInfo(_) | RpcBody::CamouflageSecret(_) | RpcBody::RaftRpc(_)
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
