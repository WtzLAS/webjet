//! What each control command does (see `super::handle` for the dispatch).

use super::request::Request;
use crate::node::Node;
use crate::state::b64;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;
use webjet_core::crypto::{self, Bytes32};
use webjet_net::kcp::KcpStats;
use webjet_proto::{self as wp, RpcBody};

/// Run one parsed request.
pub async fn run(n: &Arc<Node>, req: Request) -> Result<Value> {
    match req {
        Request::Status => Ok(status(n)),
        Request::Peers => Ok(peers(n)),
        Request::Sessions => Ok(sessions(n)),
        Request::Conntrack => Ok(crate::dataplane::flows(n)),
        Request::Proxy => Ok(crate::proxy::status(n)),
        Request::Topology => {
            crate::gossip::watch_all(n);
            Ok(crate::gossip::topology(n))
        }
        Request::Nodes => Ok(nodes(n)),
        Request::Accounts => Ok(accounts(n)),
        Request::Tree => Ok(tree(n)),
        Request::NodeConfig { node } => node_config(n, node.unwrap_or(n.me)),
        Request::SubmitOp { signed } => {
            let (i, desc) = super::submit_op(n, signed).await?;
            Ok(json!({"index": i, "applied": desc}))
        }
        Request::SubmitOffline { items } => submit_offline(n, items).await,
        Request::SubmitSigned { signed } => super::submit_signed(n, signed).await,
        Request::EnrollInfo => Ok(enroll_info(n)),
        Request::Ping {
            target,
            count,
            size,
        } => ping(n, &target, count, size).await,
        Request::CertRequest { node } => cert_request(n, node.unwrap_or(n.me)).await,
        Request::Controller => controller(n).await,
        Request::RedeemSelf { token } => {
            let c = n.controller.get().ok_or_else(|| {
                anyhow!(
                    "only a bootstrapping controller enrolls itself through the control channel"
                )
            })?;
            let id = c.redeem_self(&token).await?;
            Ok(json!({"node_id": hex::encode(id)}))
        }
        Request::Metrics { all } => metrics(n, all),
        Request::Reports => reports(n),
        Request::Head => {
            let s = n.store.read();
            Ok(json!({"head": s.head().map(|h| b64(&h.raw))}))
        }
        Request::Merkle => Ok(merkle(n)),
        Request::Log { request } => log(n, request).await,
        Request::Snapshot { request } => snapshot(n, request).await,
        Request::Upgrade { request } => crate::upgrade::request(n, request).await,
        Request::UpgradeStatus { node } => crate::upgrade::remote_status(n, node).await,
    }
}

/// The state admins see: a controller's own state machine (which is ahead
/// of signed heads, and the only state before the first certificate), or
/// the node's verified tree.
fn admin_view(n: &Node) -> std::sync::Arc<webjet_core::store::View> {
    if let Some(c) = n.controller.get() {
        let m = c.machine.lock();
        if m.genesis.is_some() {
            return std::sync::Arc::new(n.store.read().view_of(&m.tree));
        }
    }
    n.store.snapshot().view.clone()
}

/// An account's leaf: its signed AccountRecord.
fn account_leaf(n: &Node, id: &Bytes32) -> Option<Vec<u8>> {
    use webjet_core::merkle::kind;
    if let Some(c) = n.controller.get() {
        let m = c.machine.lock();
        if m.genesis.is_some() {
            return m.tree.get(kind::ACCOUNT, id).map(|e| e.bytes.clone());
        }
    }
    n.store
        .read()
        .tree()
        .get(kind::ACCOUNT, id)
        .map(|e| e.bytes.clone())
}

/// A JSON value, or `null` when it can't be serialized.
fn to_json<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or_default()
}

fn ips<T: ToString>(it: impl IntoIterator<Item = T>) -> Vec<String> {
    it.into_iter().map(|i| i.to_string()).collect()
}

pub fn status(n: &Arc<Node>) -> Value {
    let s = n.store.read();
    let v = s.view();
    let me = v.nodes.get(&n.me);
    json!({
        "node_id": hex::encode(n.me),
        "name": me.map(|m| m.name.clone()),
        "key": crypto::key_b64(&n.kp.public()),
        "ips": me.map(|m| ips(&m.ips)),
        "roles": {"relay": me.map(|m| m.relay), "data": me.map(|m| m.data), "control": me.map(|m| m.control), "control_role": me.map(|m| m.control_role)},
        "valid": me.is_some_and(|m| m.valid),
        "tree_version": s.head().map(|h| h.head.version),
        "tree_root": s.head().map(|h| hex::encode(h.root())),
        "head_expires": s.head().map(|h| h.head.expires_at),
        "valid_until": v.valid_until,
        "camouflage_expires": crate::transport::camouflage_not_after(n),
        "dns_suffix": v.suffix(),
        "nat": crate::transport::nat_name(crate::transport::nat_type(n)),
        "port_mapping": n.port_mapping.lock().map(|m| json!({"external": m.external.to_string(), "protocol": m.protocol})),
        "nodes": v.nodes.len(),
        "controllers": v.controllers.len(),
        "psk_epoch": n.epochs.read().current,
        "peers": n.peers().len(),
        "sessions": n.e2e.all().len(),
        "alarms": n.alarms.lock().iter().map(|(k, (sev, since))| json!({"name": k, "severity": sev, "since": since})).collect::<Vec<_>>(),
        "controller": n.controller.get().map(|c| c.status()),
        "compression": compression_status(n),
        "retransmit": n.retransmit.load(Relaxed),
        "fec_simd": webjet_net::fec::simd(),
        "uptime_s": n.started.elapsed().as_secs(),
        "version": env!("CARGO_PKG_VERSION"),
    })
}

/// Compression in force and its counters (§9.8).
fn compression_status(n: &Node) -> Value {
    let set = crate::compression::mine(n);
    let plane = |p: &crate::compression::Plane, algo: u8| {
        json!({
            "algorithm": webjet_core::compress::algo::name(algo),
            "tx_messages": p.tx_messages.load(Relaxed),
            "tx_raw_bytes": p.tx_raw_bytes.load(Relaxed),
            "tx_wire_bytes": p.tx_wire_bytes.load(Relaxed),
            "tx_skipped": p.tx_skipped.load(Relaxed),
            "rx_messages": p.rx_messages.load(Relaxed),
            "rx_raw_bytes": p.rx_raw_bytes.load(Relaxed),
            "rx_wire_bytes": p.rx_wire_bytes.load(Relaxed),
            "rx_errors": p.rx_errors.load(Relaxed),
        })
    };
    let c = &n.metrics.compression;
    json!({
        "control": plane(&c.control, set.control),
        "data": plane(&c.data, set.data),
    })
}

/// Direct hops to peers and their link statistics.
fn peers(n: &Node) -> Value {
    let hops: Vec<Value> = n
        .hops
        .lock()
        .values()
        .map(|h| {
            let st = h.stats.lock();
            let lane = |f: fn(&KcpStats) -> &std::sync::atomic::AtomicU64| {
                h.kcp_stats
                    .as_deref()
                    .filter(|_| h.lane)
                    .map_or(0, |k| f(k).load(Relaxed))
            };
            json!({
                "peer": n.name_of(&h.peer),
                "id": hex::encode(h.peer),
                "transport": h.transport.name(),
                "remote": h.remote.to_string(),
                "outbound": h.outbound,
                "rtt_ms": st.srtt_ms,
                "min_rtt_ms": if st.min_rtt_ms.is_finite() { st.min_rtt_ms } else { 0.0 },
                "jitter_ms": st.rttvar_ms,
                "long_term_loss": st.history.loss,
                "flaps": st.history.flaps,
                "loss": st.loss,
                "cost": st.cost(),
                "age_s": h.created.elapsed().as_secs(),
                "tx_bytes": h.tx_bytes.load(Relaxed),
                "rx_bytes": h.rx_bytes.load(Relaxed),
                "restricted": h.restricted,
                // Flat, like the rest of the entry: scripts pick a peer's
                // entry out with a `{[^{}]*}` match (docker/nat-test.sh).
                "lane": h.lane,
                "lane_tx_records": lane(|k| &k.lane_tx),
                "lane_rx_records": lane(|k| &k.lane_rx),
                "lane_incomplete": lane(|k| &k.lane_incomplete),
            })
        })
        .collect();
    json!(hops)
}

/// End-to-end sessions, circuits and hole punching.
fn sessions(n: &Arc<Node>) -> Value {
    let v: Vec<Value> = n
        .e2e
        .all()
        .iter()
        .map(|s| {
            let mut j = crate::e2e::summary(s);
            j["peer"] = json!(n.name_of(&s.peer));
            j["peer_id"] = json!(hex::encode(s.peer));
            j
        })
        .collect();
    json!({"sessions": v, "circuits": crate::circuit::summary(n), "punch": crate::punch::status(n)})
}

fn node_json(v: &webjet_core::store::View, id: &Bytes32) -> Value {
    let Some(info) = v.nodes.get(id) else {
        return json!({"id": hex::encode(id)});
    };
    json!({
        "id": hex::encode(id),
        "name": info.name,
        "key": crypto::key_b64(&info.key),
        "ips": ips(&info.ips),
        "tags": info.tags,
        "owner": v.accounts.get(&info.owner).map_or_else(|| hex::encode(info.owner), |a| a.name.clone()),
        "owner_id": hex::encode(info.owner),
        "relay": info.relay,
        "data": info.data,
        "control": info.control,
        "control_role": info.control_role,
        "routes": info.routes.iter().map(|g| if g.mapped() { format!("{}={}", g.lan, g.published) } else { g.published.to_string() }).collect::<Vec<_>>(),
        "valid": info.valid,
        "version": info.rec.version,
    })
}

/// Sorted by the `name` field.
fn by_name(mut v: Vec<Value>) -> Value {
    v.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    json!(v)
}

fn nodes(n: &Node) -> Value {
    let view = admin_view(n);
    by_name(view.nodes.keys().map(|id| node_json(&view, id)).collect())
}

fn accounts(n: &Node) -> Value {
    let view = admin_view(n);
    by_name(
        view.accounts
            .values()
            .map(|a| json!({"id": hex::encode(a.id), "name": a.name, "admin": a.admin, "valid": a.valid, "key": crypto::key_b64(&a.key), "version": a.rec.version, "record": account_leaf(n, &a.id).map(|r| b64(&r))}))
            .collect(),
    )
}

/// Current singleton configs, for `webjetctl network config show`.
fn tree(n: &Node) -> Value {
    let v = &admin_view(n);
    let s = n.store.snapshot();
    json!({
        "network_version": v.network_version,
        "policy_version": v.policy_version,
        "dns": v.dns.as_ref().map(to_json),
        "seeds": v.seeds.as_ref().map(to_json),
        "limits": v.limits.as_ref().map(to_json),
        "transport": v.transport.as_ref().map(to_json),
        "controllers": v.controller_settings.as_ref().map(to_json),
        "policy": v.policy_wire.as_ref().map(to_json),
        "resolver": ips(v.resolver_ips(&s.overlay_pool)),
        "suffix": v.suffix(),
        "valid_until": v.valid_until,
        "overlay_pool": ips(&s.overlay_pool),
    })
}

/// A node's configuration (§6.19) and what is in force for it, for
/// `webjetctl local config`.
fn node_config(n: &Node, id: Bytes32) -> Result<Value> {
    let view = admin_view(n);
    let info = view.nodes.get(&id).ok_or_else(|| anyhow!("unknown node"))?;
    let s = n.store.snapshot();
    let priorities: serde_json::Map<String, Value> = wp::Transport::ALL
        .iter()
        .map(|t| (t.name().to_string(), json!(view.priority(&id, *t))))
        .collect();
    let limits: serde_json::Map<String, Value> = webjet_core::validate::LIMITS
        .iter()
        .map(|l| (l.name.to_string(), json!(view.limit(&id, l.name))))
        .collect();
    let compression = view.compression(&id);
    Ok(json!({
        "node_id": hex::encode(id),
        "name": info.name,
        "config": view.node_config(&id).map(to_json),
        "effective": {
            "priorities": priorities,
            "limits": limits,
            "seeds": view.seeds_for(&id),
            "dns_records": view.dns_records_for(&id),
            "dns_forward": view.dns_forward_for(&id),
            "compression": {
                "control": webjet_core::compress::algo::name(compression.control),
                "data": webjet_core::compress::algo::name(compression.data),
            },
            "capture": view.capture_ports(&id),
            "retransmit": view.retransmit(&id),
            "suffix": view.suffix(),
            "resolver": ips(view.resolver_ips(&s.overlay_pool)),
        },
    }))
}

/// Install offline-signed items, gossip them and hand them to a controller.
async fn submit_offline(n: &Arc<Node>, items: Vec<Vec<u8>>) -> Result<Value> {
    // One write lock and one view rebuild for the whole batch.
    let results = n.store.write().add_offline_items(&items);
    let added = results.iter().filter(|r| matches!(r, Ok(true))).count();
    if added > 0 || results.iter().all(Result::is_ok) {
        n.persist_store();
        crate::gossip::push_head(n);
    }
    // The first refused item fails the call, as before; the ones that went
    // in are kept (and now saved).
    if let Some(e) = results.into_iter().find_map(Result::err) {
        return Err(e);
    }
    super::forward_offline(n, items).await;
    Ok(json!({"added": added}))
}

/// The overlay address a ping target names: an address, a node id or a
/// node name (with or without the DNS suffix).
fn ping_target(n: &Node, target: &str) -> Result<std::net::IpAddr> {
    if let Ok(ip) = target.parse() {
        return Ok(ip);
    }
    let v = admin_view(n);
    let by_id = crypto::parse_hex32(target).filter(|id| v.nodes.contains_key(id));
    let id = by_id
        .as_ref()
        .or_else(|| {
            v.by_name
                .get(target.trim_end_matches(&format!(".{}", v.suffix())))
        })
        .ok_or_else(|| anyhow!("unknown node {target}"))?;
    v.nodes
        .get(id)
        .and_then(|x| x.ips.first())
        .map(|i| i.addr())
        .ok_or_else(|| anyhow!("{target} has no address"))
}

async fn ping(n: &Node, target: &str, count: Option<u64>, size: Option<u64>) -> Result<Value> {
    let count = count.map_or(3, |c| u16::try_from(c).unwrap_or(u16::MAX));
    // Payload bytes, up to what fits a 1280-byte packet (§9.4.7).
    let size = size.unwrap_or(0).min(1280 - 48) as usize;
    let ip = ping_target(n, target)?;
    let dp = n
        .dataplane
        .get()
        .ok_or_else(|| anyhow!("the data plane isn't running yet"))?;
    let r = dp.ping(ip, count, size).await;
    Ok(json!({
        "target": ip.to_string(),
        "replies": r.iter().map(|d| d.map(|x| x.as_secs_f64() * 1000.0)).collect::<Vec<_>>(),
    }))
}

/// This node's own certificate request, or another controller's (by node
/// id), asked of that node over the overlay.
async fn cert_request(n: &Arc<Node>, target: Bytes32) -> Result<Value> {
    if target == n.me {
        let c = n.controller.get().ok_or_else(|| {
            anyhow!("this node doesn't run the controller role; it needs the control role first (`webjetctl network node update <name> --roles ...,control`)")
        })?;
        return Ok(json!({"request": b64(&c.cert_request()?)}));
    }
    let r = crate::rpc::call(
        n,
        &target,
        RpcBody::GetCertRequest(Box::new(wp::GetCertRequest {})),
        Duration::from_secs(15),
    )
    .await?;
    match r {
        RpcBody::CertRequestReply(c) => match (c.request, c.error) {
            (Some(req), _) => Ok(json!({"request": b64(&req)})),
            (None, e) => bail!("{}", e.unwrap_or_else(|| "no certificate request".into())),
        },
        RpcBody::RpcAck(a) => bail!(
            "{} doesn't run the controller role yet ({})",
            n.name_of(&target),
            a.error.unwrap_or_default()
        ),
        _ => bail!("unexpected reply"),
    }
}

/// This controller's status, or any controller's.
async fn controller(n: &Arc<Node>) -> Result<Value> {
    if let Some(c) = n.controller.get() {
        return Ok(c.status());
    }
    let (_, r) = crate::rpc::call_any(
        n,
        RpcBody::GetControllerStatus(Box::new(wp::GetControllerStatus {})),
        Duration::from_secs(10),
    )
    .await?;
    match r {
        RpcBody::ControllerStatus(s) => Ok(crate::controller::remote_status_json(&s)),
        _ => bail!("unexpected reply"),
    }
}

fn metrics(n: &Arc<Node>, all: bool) -> Result<Value> {
    let text = match (all, n.controller.get()) {
        (true, Some(c)) => c.openmetrics(),
        (true, None) => bail!("only controllers hold every node's report"),
        _ => crate::metrics::local_openmetrics(n),
    };
    Ok(json!({"openmetrics": text}))
}

/// Every node's latest metric report (controllers only).
fn reports(n: &Node) -> Result<Value> {
    let c = n
        .controller
        .get()
        .ok_or_else(|| anyhow!("not a controller"))?;
    let r = c.reports.lock();
    Ok(json!(
        r.iter()
            .map(|(k, sr)| (
                n.name_of(k),
                json!({"received": sr.received, "report": to_json(&sr.report)})
            ))
            .collect::<serde_json::Map<_, _>>()
    ))
}

/// Ask any controller over the overlay; its reply must be `pick`'s variant
/// (an RpcAck carries its error).
async fn ask_controller<T>(
    n: &Arc<Node>,
    body: RpcBody,
    timeout: Duration,
    pick: impl FnOnce(RpcBody) -> Option<T>,
) -> Result<T> {
    match crate::rpc::call_any(n, body, timeout).await?.1 {
        RpcBody::RpcAck(a) => bail!(a.error.unwrap_or_default()),
        r => pick(r).ok_or_else(|| anyhow!("unexpected reply")),
    }
}

/// A page of the operation log (the request is admin-signed).
async fn log(n: &Arc<Node>, raw: Vec<u8>) -> Result<Value> {
    let reply = match n.controller.get() {
        Some(c) => c.log(&raw),
        None => {
            let body = RpcBody::GetLog(Box::new(wp::GetLog { request: Some(raw) }));
            ask_controller(n, body, Duration::from_secs(15), |r| match r {
                RpcBody::LogReply(r) => Some(*r),
                _ => None,
            })
            .await?
        }
    };
    if let Some(e) = reply.error {
        bail!(e);
    }
    Ok(log_json(&reply))
}

/// The controller's snapshot (the request is admin-signed).
async fn snapshot(n: &Arc<Node>, raw: Vec<u8>) -> Result<Value> {
    let reply = match n.controller.get() {
        Some(c) => c.export_snapshot(&raw),
        None => {
            let body = RpcBody::GetSnapshot(Box::new(wp::GetSnapshot { request: Some(raw) }));
            ask_controller(n, body, Duration::from_secs(30), |r| match r {
                RpcBody::SnapshotReply(r) => Some(*r),
                _ => None,
            })
            .await?
        }
    };
    if let Some(e) = reply.error {
        bail!(e);
    }
    let snap = reply.snapshot.unwrap_or_default();
    let m = webjet_core::statemachine::Machine::restore_bytes(&snap)
        .context("the controller's snapshot")?;
    Ok(json!({
        "snapshot": b64(&snap),
        "last_index": m.last_index,
        "nodes": m.view().nodes.len(),
        "voters": m.members.voters.iter().map(hex::encode).collect::<Vec<_>>(),
    }))
}

/// The state tree for webjet-app's Merkle tab: every leaf's bytes (the app
/// decodes them and recomputes the root), the signed tree head, the genesis
/// keys and the controllers' signing-key certificates. A controller shows
/// its own state machine's tree, which may be ahead of the signed head.
fn merkle(n: &Arc<Node>) -> Value {
    fn leaves<'a>(it: impl Iterator<Item = &'a webjet_core::merkle::LeafEntry>) -> Vec<Value> {
        it.map(|e| json!({"kind": e.kind, "key": hex::encode(e.key), "bytes": b64(&e.bytes)}))
            .collect()
    }
    let controller_tree = n.controller.get().and_then(|c| {
        let m = c.machine.lock();
        m.genesis
            .is_some()
            .then(|| leaves(m.tree.iter().map(|(_, e)| e)))
    });
    let view = admin_view(n);
    let s = n.store.read();
    let (source, leaves) = match controller_tree {
        Some(l) => ("controller", l),
        None => ("head", leaves(s.tree().iter().map(|(_, e)| e))),
    };
    let head = s.head().map(|h| {
        let kid = h.key_id();
        let controller = s
            .certs()
            .find(|c| crypto::opt_k32(&c.cert.signing_key_id) == kid)
            .map(|c| hex::encode(crypto::opt_k32(&c.cert.controller)));
        json!({
            "version": h.head.version,
            "root": hex::encode(h.root()),
            "signing_key_id": hex::encode(kid),
            "controller": controller,
            "state_version": h.head.state_version,
            "issued_at": h.head.issued_at,
            "expires_at": h.head.expires_at,
        })
    });
    let certs: Vec<Value> = s
        .certs()
        .map(|c| {
            let kid = crypto::opt_k32(&c.cert.signing_key_id);
            json!({
                "signing_key_id": hex::encode(kid),
                "signing_key": crypto::key_b64(&crypto::opt_k32(&c.cert.signing_key)),
                "controller": hex::encode(crypto::opt_k32(&c.cert.controller)),
                "serial": c.cert.cert_serial,
                "issuer": c.issuer.map(|i| hex::encode(i.id)),
                "issuer_key": c.issuer.map(|i| crypto::key_b64(&i.key)),
                "valid": view.valid_certs.contains(&kid),
            })
        })
        .collect();
    let tombs: Vec<Value> = s
        .key_tombstones()
        .map(|t| {
            json!({
                "signing_key_id": hex::encode(crypto::opt_k32(&t.tomb.signing_key_id)),
                "last_valid_version": t.tomb.last_valid_version,
                "reason": t.tomb.reason,
            })
        })
        .collect();
    let first_admin = s
        .genesis
        .first_admin
        .as_deref()
        .and_then(|b| crypto::open_envelope(b).ok())
        .and_then(|v| v.decode::<wp::AccountRecord>().ok())
        .and_then(|r| r.name);
    json!({
        "source": source,
        "head": head,
        "genesis": {
            "root_key": crypto::key_b64(&s.root),
            "emergency_key": s.emergency.as_ref().map(crypto::key_b64),
            "created_at": s.genesis.created_at,
            "first_admin": first_admin,
        },
        "certs": certs,
        "key_tombstones": tombs,
        "leaves": leaves,
    })
}

/// A `LogReply` as JSON for webjet-app.
fn log_json(r: &wp::LogReply) -> Value {
    let k = |k: &Option<wp::Key32>| k.as_ref().map(|k| k.to_bytes());
    let records: Vec<Value> = r
        .records
        .iter()
        .flatten()
        .map(|e| {
            json!({
                "index": e.index,
                "term": e.term,
                "timestamp": e.timestamp,
                "payload": e.payload,
                "op": e.op,
                "signer_key": k(&e.signer_key).map(|x| crypto::key_b64(&x)),
                "account_id": k(&e.account_id).map(hex::encode),
                "op_seq": e.op_seq,
                "issued_at": e.issued_at,
                "description": e.description,
                "leaves": e.leaves.iter().flatten().map(|l| json!({
                    "kind": l.kind,
                    "key": k(&l.key).map(hex::encode),
                    "hash": k(&l.hash).map(hex::encode),
                    "deleted": l.deleted,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "first_index": r.first_index,
        "commit_index": r.commit_index,
        "records": records,
    })
}

/// A public, non-FEC address as an enrollment-string controller entry.
fn controller_addr(a: &wp::EndpointAddr) -> Option<Value> {
    if a.kind != wp::AddrKind::Public || a.transport == wp::Transport::KcpFecTls {
        return None;
    }
    let sa = a.addr.as_ref().and_then(|x| x.to_sock())?;
    Some(json!({"host": sa.ip().to_string(), "port": sa.port(), "transport": a.transport.name()}))
}

/// What `webjetctl network node enroll` needs for an enrollment string.
fn enroll_info(n: &Arc<Node>) -> Value {
    let s = n.store.read();
    let v = &admin_view(n);
    let mut controllers: Vec<Value> = Vec::new();
    {
        let recs = n.records.lock();
        for id in v.controllers.keys() {
            if let Some((r, _)) = recs.endpoints.get(id) {
                controllers.extend(r.addrs.iter().flatten().filter_map(controller_addr));
            }
        }
    }
    if n.is_controller() {
        for j in crate::transport::my_addrs(n)
            .iter()
            .filter_map(controller_addr)
        {
            if !controllers.contains(&j) {
                controllers.push(j);
            }
        }
    }
    let cam = v.transport.as_ref().and_then(|t| t.camouflage.clone());
    #[cfg(feature = "anytls")]
    let pin = cam
        .as_ref()
        .and_then(|c| c.certificate.clone())
        .and_then(|c| c.first().and_then(|b| b.data.clone()))
        .and_then(|d| webjet_net::anytls::spki_pin(&d).ok())
        .map(hex::encode);
    #[cfg(not(feature = "anytls"))]
    let pin: Option<String> = None;
    json!({
        "root_key": crypto::key_b64(&s.root),
        "controllers": controllers,
        "camouflage_domain": cam.as_ref().and_then(|c| c.domain.clone()),
        "camouflage_pin": pin,
        "overlay_pool": ips(&s.overlay_pool),
        "used_ips": v.nodes.values().filter(|x| !v.tombstoned_nodes.contains(&x.id)).flat_map(|x| x.ips.iter().map(|i| i.addr().to_string())).collect::<Vec<_>>(),
        "resolver": ips(v.resolver_ips(&s.overlay_pool)),
    })
}
