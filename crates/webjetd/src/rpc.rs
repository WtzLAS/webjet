//! RPC over end-to-end sessions (§7.1, §7.6, §12.5): `req_id[8] || kind[1] || Rpc`.
//! Used for PSK fetch, operations, metric uploads, status and Raft.

use crate::node::Node;
use anyhow::{Result, anyhow};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::oneshot;
use webjet_core::crypto::Bytes32;
use webjet_proto::{self as wp, Decodable, Encodable, RpcBody};

const REQUEST: u8 = 0;
const RESPONSE: u8 = 1;
const ONEWAY: u8 = 2;

/// A call waiting for its answer: who was called and where the answer goes.
/// Ids are random, so a node can't guess another call's id, and a response
/// counts only from the node that was called.
type Pending = HashMap<u64, (Bytes32, oneshot::Sender<RpcBody>)>;

fn pending() -> &'static Mutex<Pending> {
    static P: OnceLock<Mutex<Pending>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Removes a call from `pending` when it ends, also when the caller's
/// future is dropped mid-call.
struct PendingGuard(u64);

impl Drop for PendingGuard {
    fn drop(&mut self) {
        pending().lock().remove(&self.0);
    }
}

/// Register a call to `peer` under a fresh random id.
fn register(peer: &Bytes32) -> (PendingGuard, oneshot::Receiver<RpcBody>) {
    let (tx, rx) = oneshot::channel();
    let mut p = pending().lock();
    let mut id: u64 = rand::random();
    // 0 is what one-way messages carry.
    while id == 0 || p.contains_key(&id) {
        id = rand::random();
    }
    p.insert(id, (*peer, tx));
    (PendingGuard(id), rx)
}

/// Deliver a response from `from`; ignored unless `from` is the node the
/// call `id` went to.
fn deliver(from: &Bytes32, id: u64, body: RpcBody) {
    let mut p = pending().lock();
    if p.get(&id).is_some_and(|(peer, _)| peer == from)
        && let Some((_, tx)) = p.remove(&id)
    {
        let _ = tx.send(body);
    }
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
    let (guard, rx) = register(peer);
    let (ty, msg) = encode(n, peer, guard.0, REQUEST, body);
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
    drop(guard);
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
        RESPONSE => deliver(from, id, body),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(ok: bool) -> RpcBody {
        RpcBody::RpcAck(Box::new(wp::RpcAck { ok, error: None }))
    }

    #[test]
    fn only_the_called_node_can_answer() {
        let peer = [1u8; 32];
        let other = [2u8; 32];
        let (guard, mut rx) = register(&peer);
        let id = guard.0;
        assert_ne!(id, 0);
        // Another node answering the same id is ignored, and doesn't
        // consume the call.
        deliver(&other, id, ack(false));
        assert!(rx.try_recv().is_err());
        assert!(pending().lock().contains_key(&id));
        deliver(&peer, id, ack(true));
        assert!(matches!(rx.try_recv(), Ok(RpcBody::RpcAck(a)) if a.ok));
        assert!(!pending().lock().contains_key(&id));
    }

    #[test]
    fn a_dropped_call_leaves_nothing_behind() {
        let (guard, _rx) = register(&[3u8; 32]);
        let id = guard.0;
        assert!(pending().lock().contains_key(&id));
        drop(guard);
        assert!(!pending().lock().contains_key(&id));
    }
}
