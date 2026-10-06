#![allow(dead_code)] // helpers for the modules' tests, not all used everywhere

//! Unit-test support: an agent `Node` over a real, verifying store built by
//! `webjet_core::testutil::Cluster`, with no sockets, tasks or tun.

use crate::config::Config;
use crate::node::Node;
use std::sync::Arc;
use webjet_core::crypto::{Bytes32, KeyPair};
pub use webjet_core::testutil::Cluster;

/// A node of `cluster` as its agent sees the network. The data directory is
/// a temporary one, removed with the returned guard.
pub fn node(cluster: &mut Cluster, me: Bytes32, kp: KeyPair) -> (Arc<Node>, tempfile::TempDir) {
    let store = cluster.store();
    with_store(store, me, kp)
}

/// A node over `store` as it is (for example a bare genesis store, as on a
/// new network's first controller).
pub fn with_store(
    store: webjet_core::store::Store,
    me: Bytes32,
    kp: KeyPair,
) -> (Arc<Node>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = Config::default();
    cfg.data_dir = dir.path().to_path_buf();
    let epochs = Arc::new(parking_lot::RwLock::new(Default::default()));
    let nf = crate::state::NodeFile {
        node_id: hex::encode(me),
        ..Default::default()
    };
    (Node::new(cfg, kp, me, store, epochs, nf), dir)
}

/// Bring `n`'s store up to the controller's current tree.
pub fn sync(cluster: &mut Cluster, n: &Node) {
    cluster.sync(&mut n.store.write());
}
