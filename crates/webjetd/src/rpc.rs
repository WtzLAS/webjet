//! RPC over end-to-end sessions (§7.1, §7.6, §12.5): `req_id[8] || kind[1] || Rpc`.
//! Used for PSK fetch, operations, metric uploads, status and Raft.

use crate::node::Node;
use anyhow::{Result, anyhow};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::oneshot;
use webjet_core::crypto::Bytes32;
use webjet_proto::{self as wp, Decodable, Encodable, RpcBody};

const REQUEST: u8 = 0;
const RESPONSE: u8 = 1;
const ONEWAY: u8 = 2;

static NEXT: AtomicU64 = AtomicU64::new(1);

fn pending() -> &'static Mutex<HashMap<u64, oneshot::Sender<RpcBody>>> {
    static P: OnceLock<Mutex<HashMap<u64, oneshot::Sender<RpcBody>>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(HashMap::new()))
}

/// An RPC frame for `peer`: its type (RPC, or RPC_ZSTD when compressed,
/// §9.8) and payload.
fn encode(n: &Node, peer: &Bytes32, id: u64, kind: u8, body: RpcBody) -> (u8, Vec<u8>) {
    let secret = crate::compression::secret_rpc(&body);
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(&id.to_be_bytes());
    v.push(kind);
    v.extend_from_slice(&wp::Rpc { body: Some(body) }.encode_bytes());
    crate::compression::rpc_frame(n, peer, secret, v)
}

/// Call `peer` and wait for its answer.
pub async fn call(
    n: &Arc<Node>,
    peer: &Bytes32,
    body: RpcBody,
    timeout: Duration,
) -> Result<RpcBody> {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = oneshot::channel();
    pending().lock().insert(id, tx);
    let (ty, msg) = encode(n, peer, id, REQUEST, body);
    // Retransmit while the session/circuit comes up; responses are idempotent.
    let res = tokio::time::timeout(timeout, async {
        let mut rx = rx;
        loop {
            crate::e2e::send(n, peer, ty, &msg, 0);
            tokio::select! {
                r = &mut rx => return r.map_err(|_| anyhow!("rpc cancelled")),
                _ = tokio::time::sleep(Duration::from_secs(3)) => {}
            }
        }
    })
    .await;
    pending().lock().remove(&id);
    res.map_err(|_| anyhow!("rpc to {} timed out", n.name_of(peer)))?
}

/// Fire and forget (Raft messages, which carry their own retries).
pub fn send_oneway(n: &Arc<Node>, peer: &Bytes32, body: RpcBody) {
    let (ty, msg) = encode(n, peer, 0, ONEWAY, body);
    crate::e2e::send(n, peer, ty, &msg, 0);
}

pub fn on_frame(n: &Arc<Node>, from: &Bytes32, payload: &[u8]) {
    let (Some(id), Some(&kind)) = (webjet_core::bytes::be_u64(payload, 0), payload.get(8)) else {
        return;
    };
    let Ok(rpc) = wp::Rpc::decode_bytes(&payload[9..]) else {
        return;
    };
    let Some(body) = rpc.body else { return };
    match kind {
        RESPONSE => {
            if let Some(tx) = pending().lock().remove(&id) {
                let _ = tx.send(body);
            }
        }
        REQUEST | ONEWAY => {
            let n = n.clone();
            let from = *from;
            tokio::spawn(async move {
                let reply = match (body, n.controller.get()) {
                    // Remote upgrades (§19.8) reach every node, not only
                    // controllers.
                    (body @ (RpcBody::UpgradeNode(_) | RpcBody::GetUpgradeStatus(_)), _) => {
                        crate::upgrade::on_rpc(&n, from, body).await
                    }
                    (body, Some(c)) => c.clone().handle_rpc(from, body).await,
                    (_, None) => Some(RpcBody::RpcAck(Box::new(wp::RpcAck {
                        ok: false,
                        error: Some("not a controller".into()),
                    }))),
                };
                if kind == REQUEST
                    && let Some(r) = reply
                {
                    let (ty, msg) = encode(&n, &from, id, RESPONSE, r);
                    crate::e2e::send(&n, &from, ty, &msg, 0);
                }
            });
        }
        _ => {}
    }
}

/// Controllers this node knows of, nearest first (by hop availability).
pub fn controllers(n: &Node) -> Vec<Bytes32> {
    let s = n.store.read();
    let mut v: Vec<Bytes32> = s
        .view()
        .controllers
        .keys()
        .copied()
        .filter(|c| *c != n.me)
        .collect();
    drop(s);
    v.sort_by_key(|c| (n.best_hop(c).is_none(), *c));
    v
}

/// Call any controller, trying them in order.
pub async fn call_any(
    n: &Arc<Node>,
    body: RpcBody,
    timeout: Duration,
) -> Result<(Bytes32, RpcBody)> {
    let list = controllers(n);
    if list.is_empty() {
        return Err(anyhow!("no controller known"));
    }
    let mut last = anyhow!("no controller answered");
    for c in list {
        match call(n, &c, body.clone(), timeout).await {
            Ok(r) => return Ok((c, r)),
            Err(e) => last = e,
        }
    }
    Err(last)
}
