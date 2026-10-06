//! The local control channel (§13.1): newline-delimited JSON over a Unix
//! socket (named pipe on Windows) every local user may use; operations carry
//! their own signatures (see `ipc`). `webjetctl` uses it to
//! inspect the agent and to submit signed operations; the agent forwards
//! operations to a controller over the overlay (or applies them itself when
//! it is one).

use crate::node::Node;
use crate::state::{b64, unb64};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use webjet_core::crypto::{self, Bytes32};
use webjet_proto::{self as wp, RpcBody};

/// Longest request line accepted. Every local user may connect, so a line
/// without a newline must not grow without bound; the largest real request
/// (a signed network configuration) is far below this.
pub const MAX_REQUEST: usize = 4 << 20;
/// Connections served at once; more are answered with an error and closed.
pub const MAX_CONNECTIONS: usize = 64;

/// What a control command may do, given that every local user can send it
/// (see the module docs and `ipc::Access::Everyone`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Reads the agent's state; changes nothing (subscriptions and pings
    /// included: they only make the agent ask or send on the user's behalf).
    Read,
    /// Changes state only through material whose signature is checked
    /// (account, admin, root or emergency keys) before it has any effect.
    Signed,
    /// Needs a secret the caller must already hold (an enrollment token).
    Capability,
}

/// Every control command and its access class. `handle` refuses anything
/// that isn't listed; a test checks that this table and `handle` agree.
pub const COMMANDS: &[(&str, Access)] = &[
    ("status", Access::Read),
    ("peers", Access::Read),
    ("sessions", Access::Read),
    ("conntrack", Access::Read),
    ("proxy", Access::Read),
    ("topology", Access::Read),
    ("nodes", Access::Read),
    ("accounts", Access::Read),
    ("tree", Access::Read),
    ("node_config", Access::Read),
    ("submit_op", Access::Signed),
    ("submit_offline", Access::Signed),
    ("submit_signed", Access::Signed),
    ("enroll_info", Access::Read),
    ("ping", Access::Read),
    ("cert_request", Access::Read),
    ("controller", Access::Read),
    ("redeem_self", Access::Capability),
    ("metrics", Access::Read),
    ("reports", Access::Read),
    ("head", Access::Read),
    ("merkle", Access::Read),
    // The request itself is admin-signed (controller::audit::check_request).
    ("log", Access::Signed),
];

pub fn access(cmd: &str) -> Option<Access> {
    COMMANDS.iter().find(|(c, _)| *c == cmd).map(|(_, a)| *a)
}

pub async fn serve(n: Arc<Node>) -> Result<()> {
    let path = n.cfg.control_socket.clone();
    let mut l = crate::ipc::Listener::bind(&path, crate::ipc::Access::Everyone)?;
    tracing::info!("control channel at {}", path.display());
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let s = l.accept().await?;
        let n2 = n.clone();
        let slot = slots.clone().try_acquire_owned();
        tokio::spawn(async move {
            let (r, mut w) = tokio::io::split(s);
            let Ok(_slot) = slot else {
                let busy = json!({"ok": false, "error": "too many control connections"});
                let _ = w.write_all(format!("{busy}\n").as_bytes()).await;
                return;
            };
            let mut r = BufReader::new(r);
            loop {
                let reply = match read_request(&mut r).await {
                    Ok(Some(line)) => match serde_json::from_slice::<Value>(&line) {
                        Ok(req) => match handle(&n2, req).await {
                            Ok(v) => json!({"ok": true, "result": v}),
                            Err(e) => json!({"ok": false, "error": format!("{e:#}")}),
                        },
                        Err(e) => json!({"ok": false, "error": format!("bad request: {e}")}),
                    },
                    Ok(None) => break,
                    Err(e) => {
                        let reply = json!({"ok": false, "error": format!("bad request: {e}")});
                        let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                        break;
                    }
                };
                let mut out = serde_json::to_vec(&reply).unwrap_or_default();
                out.push(b'\n');
                if w.write_all(&out).await.is_err() {
                    break;
                }
            }
        });
    }
}

/// One request line (without its newline), at most [`MAX_REQUEST`] bytes.
/// `None` at the end of the stream.
async fn read_request<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let got = (&mut *r)
        .take(MAX_REQUEST as u64 + 1)
        .read_until(b'\n', &mut line)
        .await?;
    if got == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    } else if line.len() > MAX_REQUEST {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("request longer than {MAX_REQUEST} bytes"),
        ));
    }
    Ok(Some(line))
}

/// The state admins see: a controller's own state machine (which is ahead
/// of signed heads, and the only state before the first certificate), or
/// the node's verified tree.
fn admin_view(n: &Node) -> webjet_core::store::View {
    if let Some(c) = n.controller.get() {
        let m = c.machine.lock();
        if m.genesis.is_some() {
            return n.store.read().view_of(&m.tree);
        }
    }
    n.store.read().view().clone()
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

fn str_arg<'a>(req: &'a Value, k: &str) -> Result<&'a str> {
    req.get(k)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing {k}"))
}

fn node_json(v: &webjet_core::store::View, id: &Bytes32) -> Value {
    let Some(info) = v.nodes.get(id) else {
        return json!({"id": hex::encode(id)});
    };
    json!({
        "id": hex::encode(id),
        "name": info.name,
        "key": crypto::key_b64(&info.key),
        "ips": info.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
        "tags": info.tags,
        "owner": v.accounts.get(&info.owner).map(|a| a.name.clone()).unwrap_or_else(|| hex::encode(info.owner)),
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

pub async fn handle(n: &Arc<Node>, req: Value) -> Result<Value> {
    let cmd = str_arg(&req, "cmd")?;
    if access(cmd).is_none() {
        bail!("unknown command {cmd}");
    }
    match cmd {
        "status" => Ok(status(n)),
        "peers" => {
            let hops: Vec<Value> = n
                .hops
                .lock()
                .values()
                .map(|h| {
                    let st = h.stats.lock();
                    json!({
                        "peer": n.name_of(&h.peer),
                        "id": hex::encode(h.peer),
                        "transport": h.transport.name(),
                        "remote": h.remote.to_string(),
                        "outbound": h.outbound,
                        "rtt_ms": st.srtt_ms, "min_rtt_ms": if st.min_rtt_ms.is_finite() { st.min_rtt_ms } else { 0.0 }, "jitter_ms": st.rttvar_ms, "long_term_loss": st.history.loss, "flaps": st.history.flaps,
                        "loss": st.loss,
                        "cost": st.cost(),
                        "age_s": h.created.elapsed().as_secs(),
                        "tx_bytes": h.tx_bytes.load(std::sync::atomic::Ordering::Relaxed),
                        "rx_bytes": h.rx_bytes.load(std::sync::atomic::Ordering::Relaxed),
                        "restricted": h.restricted,
                    })
                })
                .collect();
            Ok(json!(hops))
        }
        "sessions" => {
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
            Ok(
                json!({"sessions": v, "circuits": crate::circuit::summary(n), "punch": crate::punch::status(n)}),
            )
        }
        "conntrack" => Ok(crate::dataplane::flows(n)),
        "proxy" => Ok(crate::proxy::status(n)),
        "topology" => {
            crate::gossip::watch_all(n);
            Ok(crate::gossip::topology(n))
        }
        "nodes" => {
            let view = admin_view(n);
            let mut v: Vec<Value> = view.nodes.keys().map(|id| node_json(&view, id)).collect();
            v.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            Ok(json!(v))
        }
        "accounts" => {
            let view = admin_view(n);
            let mut v: Vec<Value> = view
                .accounts
                .values()
                .map(|a| json!({"id": hex::encode(a.id), "name": a.name, "admin": a.admin, "valid": a.valid, "key": crypto::key_b64(&a.key), "version": a.rec.version, "record": account_leaf(n, &a.id).map(|r| b64(&r))}))
                .collect();
            v.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            Ok(json!(v))
        }
        "tree" => {
            // Current singleton configs, for `webjetctl * show`.
            let s = n.store.read();
            let v = &admin_view(n);
            Ok(json!({
                "network_version": v.network_version,
                "policy_version": v.policy_version,
                "dns": v.dns.as_ref().map(|d| serde_json::to_value(d).unwrap_or_default()),
                "seeds": v.seeds.as_ref().map(|d| serde_json::to_value(d).unwrap_or_default()),
                "limits": v.limits.as_ref().map(|d| serde_json::to_value(d).unwrap_or_default()),
                "transport": v.transport.as_ref().map(|d| serde_json::to_value(d).unwrap_or_default()),
                "controllers": v.controller_settings.as_ref().map(|d| serde_json::to_value(d).unwrap_or_default()),
                "policy": v.policy_wire.as_ref().map(|d| serde_json::to_value(d).unwrap_or_default()),
                "resolver": v.resolver_ips(&s.overlay_pool).iter().map(|i| i.to_string()).collect::<Vec<_>>(),
                "suffix": v.suffix(),
                "valid_until": v.valid_until,
                "overlay_pool": s.overlay_pool.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            }))
        }
        "node_config" => {
            // A node's configuration (§6.19) and what is in force for it,
            // for `webjetctl local config`. Default: this node.
            let view = admin_view(n);
            let id = match req.get("node").and_then(|v| v.as_str()) {
                Some(h) => crypto::parse_hex32(h).ok_or_else(|| anyhow!("bad node id"))?,
                None => n.me,
            };
            let info = view.nodes.get(&id).ok_or_else(|| anyhow!("unknown node"))?;
            let s = n.store.read();
            let priorities: serde_json::Map<String, Value> = wp::Transport::ALL
                .iter()
                .map(|t| (t.name().to_string(), json!(view.priority(&id, *t))))
                .collect();
            let limits: serde_json::Map<String, Value> = webjet_core::validate::LIMITS
                .iter()
                .map(|l| (l.name.to_string(), json!(view.limit(&id, l.name))))
                .collect();
            Ok(json!({
                "node_id": hex::encode(id),
                "name": info.name,
                "config": view.node_config(&id).map(|c| serde_json::to_value(c).unwrap_or_default()),
                "effective": {
                    "priorities": priorities,
                    "limits": limits,
                    "seeds": view.seeds_for(&id),
                    "dns_records": view.dns_records_for(&id),
                    "dns_forward": view.dns_forward_for(&id),
                    "compression": {
                        "control": webjet_core::compress::algo::name(view.compression(&id).control),
                        "data": webjet_core::compress::algo::name(view.compression(&id).data),
                    },
                    "suffix": view.suffix(),
                    "resolver": view.resolver_ips(&s.overlay_pool).iter().map(|i| i.to_string()).collect::<Vec<_>>(),
                },
            }))
        }
        "submit_op" => {
            let raw = unb64(str_arg(&req, "signed")?)?;
            let (i, desc) = submit_op(n, raw).await?;
            Ok(json!({"index": i, "applied": desc}))
        }
        "submit_offline" => {
            let items: Vec<Vec<u8>> = req
                .get("items")
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow!("missing items"))?
                .iter()
                .filter_map(|x| x.as_str())
                .map(unb64)
                .collect::<Result<_>>()?;
            let mut added = 0;
            for it in &items {
                if n.store.write().add_offline_item(it)? {
                    added += 1;
                }
            }
            n.persist_store();
            crate::gossip::push_head(n);
            // Make sure controllers have them too.
            if !n.is_controller() {
                let body = RpcBody::OfflineSubmit(Box::new(wp::OfflineSubmit {
                    items: Some(
                        items
                            .iter()
                            .map(|b| wp::Blob {
                                data: Some(b.clone()),
                            })
                            .collect(),
                    ),
                }));
                let _ = crate::rpc::call_any(n, body, Duration::from_secs(10)).await;
            }
            Ok(json!({"added": added}))
        }
        "submit_signed" => {
            let raw = unb64(str_arg(&req, "signed")?)?;
            submit_signed(n, raw).await
        }
        "enroll_info" => Ok(enroll_info(n)),
        "ping" => {
            let target = str_arg(&req, "target")?;
            let count = req
                .get("count")
                .and_then(|c| c.as_u64())
                .map(|c| u16::try_from(c).unwrap_or(u16::MAX))
                .unwrap_or(3);
            // Payload bytes, up to what fits a 1280-byte packet (§9.4.7).
            let size = req
                .get("size")
                .and_then(|c| c.as_u64())
                .unwrap_or(0)
                .min(1280 - 48) as usize;
            let ip: std::net::IpAddr = match target.parse() {
                Ok(ip) => ip,
                Err(_) => {
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
                        .ok_or_else(|| anyhow!("{target} has no address"))?
                }
            };
            let dp = n
                .dataplane
                .get()
                .ok_or_else(|| anyhow!("the data plane isn't running yet"))?;
            let r = dp.ping(ip, count, size).await;
            Ok(
                json!({"target": ip.to_string(), "replies": r.iter().map(|d| d.map(|x| x.as_secs_f64() * 1000.0)).collect::<Vec<_>>()}),
            )
        }
        "cert_request" => {
            // This node's own request, or another controller's (by node id),
            // asked of that node over the overlay.
            let target = match req.get("node").and_then(|v| v.as_str()) {
                Some(h) => crypto::parse_hex32(h).ok_or_else(|| anyhow!("bad node id"))?,
                None => n.me,
            };
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
        "controller" => match n.controller.get() {
            Some(c) => Ok(c.status()),
            None => {
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
        },
        "redeem_self" => {
            let c = n.controller.get().ok_or_else(|| {
                anyhow!(
                    "only a bootstrapping controller enrolls itself through the control channel"
                )
            })?;
            let token = unb64(str_arg(&req, "token")?)?;
            let id = c.redeem_self(&token).await?;
            Ok(json!({"node_id": hex::encode(id)}))
        }
        "metrics" => {
            let all = req.get("all").and_then(|a| a.as_bool()).unwrap_or(false);
            let text = match (all, n.controller.get()) {
                (true, Some(c)) => c.openmetrics(),
                (true, None) => bail!("only controllers hold every node's report"),
                _ => crate::metrics::local_openmetrics(n),
            };
            Ok(json!({"openmetrics": text}))
        }
        "reports" => {
            let c = n
                .controller
                .get()
                .ok_or_else(|| anyhow!("not a controller"))?;
            let r = c.reports.lock();
            Ok(json!(r
                .iter()
                .map(|(k, sr)| (n.name_of(k), json!({"received": sr.received, "report": serde_json::to_value(&sr.report).unwrap_or_default()})))
                .collect::<serde_json::Map<_, _>>()))
        }
        "head" => {
            let s = n.store.read();
            Ok(json!({"head": s.head().map(|h| b64(&h.raw))}))
        }
        "merkle" => Ok(merkle(n)),
        "log" => {
            let raw = unb64(str_arg(&req, "request")?)?;
            let reply = match n.controller.get() {
                Some(c) => c.log(&raw),
                None => {
                    let body = RpcBody::GetLog(Box::new(wp::GetLog { request: Some(raw) }));
                    match crate::rpc::call_any(n, body, Duration::from_secs(15))
                        .await?
                        .1
                    {
                        RpcBody::LogReply(r) => *r,
                        RpcBody::RpcAck(a) => bail!(a.error.unwrap_or_default()),
                        _ => bail!("unexpected reply"),
                    }
                }
            };
            if let Some(e) = reply.error {
                bail!(e);
            }
            Ok(log_json(&reply))
        }
        _ => bail!("unknown command {cmd}"),
    }
}

/// Submit a signed operation: locally if we're a controller, else to any controller.
pub async fn submit_op(n: &Arc<Node>, raw: Vec<u8>) -> Result<(u64, String)> {
    if let Some(c) = n.controller.get() {
        let payload = webjet_core::statemachine::ops::op_entry(raw.clone());
        let body = RpcBody::SubmitOp(Box::new(wp::SubmitOp { signed: Some(raw) }));
        let (i, o) = c.submit(payload, Some(body)).await?;
        return Ok((i, o.description));
    }
    let body = RpcBody::SubmitOp(Box::new(wp::SubmitOp { signed: Some(raw) }));
    let (_, r) = crate::rpc::call_any(n, body, Duration::from_secs(20)).await?;
    match r {
        RpcBody::SubmitResult(r) if r.ok => {
            // Wait for the change to reach us.
            let start = std::time::Instant::now();
            while n.store.read().head().map(|h| h.head.version).unwrap_or(0) < r.index
                && start.elapsed() < Duration::from_secs(15)
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok((r.index, String::new()))
        }
        RpcBody::SubmitResult(r) => bail!(r.error.unwrap_or_default()),
        RpcBody::RpcAck(a) => bail!(a.error.unwrap_or_default()),
        _ => bail!("unexpected reply"),
    }
}

/// Submit any signed file an admin produced: offline-signed material is
/// installed and gossiped; root-signed accounts and state versions go
/// through the log; SignedOps are submitted as operations.
pub async fn submit_signed(n: &Arc<Node>, raw: Vec<u8>) -> Result<Value> {
    use webjet_proto::msg_type as mt;
    let v = crypto::open_envelope(&raw)?;
    let mut out = serde_json::Map::new();
    out.insert("type".into(), json!(mt::name(v.ty)));
    match v.ty {
        mt::SIGNED_OP => {
            let (i, d) = submit_op(n, raw).await?;
            out.insert("index".into(), json!(i));
            out.insert("applied".into(), json!(d));
        }
        mt::SIGNING_KEY_CERT | mt::SIGNING_KEY_TOMBSTONE | mt::TOMBSTONE => {
            let added = n.store.write().add_offline_item(&raw)?;
            n.persist_store();
            crate::gossip::push_head(n);
            if !n.is_controller() {
                let body = RpcBody::OfflineSubmit(Box::new(wp::OfflineSubmit {
                    items: Some(vec![wp::Blob {
                        data: Some(raw.clone()),
                    }]),
                }));
                let _ = crate::rpc::call_any(n, body, Duration::from_secs(10)).await;
            }
            out.insert("added".into(), json!(added));
        }
        mt::ACCOUNT_RECORD | mt::ACCOUNT_TOMBSTONE | mt::STATE_VERSION => {
            if v.ty == mt::ACCOUNT_TOMBSTONE {
                // Root- or emergency-signed account tombstones also spread
                // standalone (§6.11), so they work without a controller majority.
                if n.store.write().add_offline_item(&raw).unwrap_or(false) {
                    n.persist_store();
                    crate::gossip::push_head(n);
                }
            }
            let idx = match n.controller.get() {
                Some(c) => {
                    let p = crate::controller::root_payload(&raw)?;
                    c.submit(
                        p,
                        Some(RpcBody::SubmitRoot(Box::new(wp::SubmitRoot {
                            signed: Some(raw.clone()),
                        }))),
                    )
                    .await?
                    .0
                }
                None => {
                    let body = RpcBody::SubmitRoot(Box::new(wp::SubmitRoot {
                        signed: Some(raw.clone()),
                    }));
                    match crate::rpc::call_any(n, body, Duration::from_secs(20))
                        .await?
                        .1
                    {
                        RpcBody::SubmitResult(r) if r.ok => r.index,
                        RpcBody::SubmitResult(r) => bail!(r.error.unwrap_or_default()),
                        _ => bail!("unexpected reply"),
                    }
                }
            };
            out.insert("index".into(), json!(idx));
        }
        t => bail!("don't know how to submit a {}", mt::name(t)),
    }
    Ok(Value::Object(out))
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

/// What `webjetctl network node enroll` needs for an enrollment string.
fn enroll_info(n: &Arc<Node>) -> Value {
    let s = n.store.read();
    let v = &admin_view(n);
    let mut controllers: Vec<Value> = Vec::new();
    let recs = n.records.lock();
    for id in v.controllers.keys() {
        if let Some((r, _)) = recs.endpoints.get(id) {
            for a in r.addrs.clone().unwrap_or_default() {
                if a.kind == wp::AddrKind::Public
                    && a.transport != wp::Transport::KcpFecTls
                    && let Some(sa) = a.addr.as_ref().and_then(|x| x.to_sock())
                {
                    controllers.push(json!({"host": sa.ip().to_string(), "port": sa.port(), "transport": a.transport.name()}));
                }
            }
        }
    }
    drop(recs);
    if n.is_controller() {
        for a in crate::transport::my_addrs(n) {
            if a.kind == wp::AddrKind::Public
                && a.transport != wp::Transport::KcpFecTls
                && let Some(sa) = a.addr.as_ref().and_then(|x| x.to_sock())
            {
                let j = json!({"host": sa.ip().to_string(), "port": sa.port(), "transport": a.transport.name()});
                if !controllers.contains(&j) {
                    controllers.push(j);
                }
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
        "overlay_pool": s.overlay_pool.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
        "used_ips": v.nodes.values().filter(|x| !v.tombstoned_nodes.contains(&x.id)).flat_map(|x| x.ips.iter().map(|i| i.addr().to_string())).collect::<Vec<_>>(),
        "resolver": v.resolver_ips(&s.overlay_pool).iter().map(|i| i.to_string()).collect::<Vec<_>>(),
    })
}

pub fn status(n: &Arc<Node>) -> Value {
    let s = n.store.read();
    let v = s.view();
    let me = v.nodes.get(&n.me);
    json!({
        "node_id": hex::encode(n.me),
        "name": me.map(|m| m.name.clone()),
        "key": crypto::key_b64(&n.kp.public()),
        "ips": me.map(|m| m.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>()),
        "roles": {"relay": me.map(|m| m.relay), "data": me.map(|m| m.data), "control": me.map(|m| m.control), "control_role": me.map(|m| m.control_role)},
        "valid": me.map(|m| m.valid).unwrap_or(false),
        "tree_version": s.head().map(|h| h.head.version),
        "tree_root": s.head().map(|h| hex::encode(h.root())),
        "head_expires": s.head().map(|h| h.head.expires_at),
        "valid_until": v.valid_until,
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
        "uptime_s": n.started.elapsed().as_secs(),
        "version": env!("CARGO_PKG_VERSION"),
    })
}

/// Compression in force and its counters (§9.8).
fn compression_status(n: &Node) -> Value {
    use std::sync::atomic::Ordering::Relaxed;
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

/// A client for `webjetctl`.
pub mod client {
    use super::*;

    pub async fn call(path: &std::path::Path, req: Value) -> Result<Value> {
        let s = crate::ipc::connect(path).await.map_err(|e| {
            let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                if cfg!(windows) {
                    "agents up to 0.5.0 let only administrators in"
                } else {
                    "agents up to 0.5.0 let only root in"
                }
            } else {
                "is webjetd running?"
            };
            anyhow!("connect to {}: {e} ({hint})", path.display())
        })?;
        let (r, mut w) = tokio::io::split(s);
        let mut line = serde_json::to_vec(&req)?;
        line.push(b'\n');
        w.write_all(&line).await?;
        let mut lines = BufReader::new(r).lines();
        let resp = tokio::time::timeout(Duration::from_secs(60), lines.next_line())
            .await
            .map_err(|_| anyhow!("timeout"))??
            .ok_or_else(|| anyhow!("no reply"))?;
        let v: Value = serde_json::from_str(&resp)?;
        if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
            Ok(v.get("result").cloned().unwrap_or(Value::Null))
        } else {
            bail!(
                "{}",
                v.get("error").and_then(|e| e.as_str()).unwrap_or("error")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command names `handle` matches on, read from this file's source.
    fn handled() -> Vec<String> {
        let src = include_str!("control.rs");
        let start = src.find("pub async fn handle(").expect("handle");
        let body = &src[start..];
        let end = body.find("\n}\n").expect("end of handle");
        let mut out: Vec<String> = body[..end]
            .lines()
            .filter_map(|l| {
                let l = l.trim_start();
                let rest = l.strip_prefix('"')?;
                let (name, tail) = rest.split_once('"')?;
                tail.trim_start()
                    .starts_with("=>")
                    .then(|| name.to_string())
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn every_command_has_an_access_class() {
        let mut table: Vec<String> = COMMANDS.iter().map(|(c, _)| c.to_string()).collect();
        table.sort();
        let mut dedup = table.clone();
        dedup.dedup();
        assert_eq!(table, dedup, "a command is listed twice");
        assert_eq!(
            handled(),
            table,
            "`handle` and COMMANDS must name the same commands"
        );
    }

    #[test]
    fn state_changing_commands_need_a_signature_or_a_token() {
        // The commands that change state; each must check a signature or a
        // secret. A new state-changing command must be added here
        // deliberately, with that check in place.
        let changing = [
            "submit_op",
            "submit_offline",
            "submit_signed",
            "redeem_self",
        ];
        for c in changing {
            assert_ne!(access(c), Some(Access::Read), "{c}");
        }
        let not_read: Vec<&str> = COMMANDS
            .iter()
            .filter(|(_, a)| *a != Access::Read)
            .map(|(c, _)| *c)
            .collect();
        assert_eq!(
            not_read,
            [
                "submit_op",
                "submit_offline",
                "submit_signed",
                "redeem_self",
                "log"
            ]
        );
        assert_eq!(access("shutdown"), None);
    }

    async fn read(input: &[u8]) -> Vec<std::io::Result<Option<Vec<u8>>>> {
        let mut r = BufReader::new(input);
        let mut out = Vec::new();
        loop {
            let x = read_request(&mut r).await;
            let stop = !matches!(x, Ok(Some(_)));
            out.push(x);
            if stop {
                return out;
            }
        }
    }

    #[tokio::test]
    async fn requests_are_split_into_lines() {
        let got = read(b"{\"cmd\":\"status\"}\n{}\r\nlast").await;
        let lines: Vec<Option<Vec<u8>>> = got.into_iter().map(|x| x.expect("ok")).collect();
        assert_eq!(
            lines,
            vec![
                Some(b"{\"cmd\":\"status\"}".to_vec()),
                Some(b"{}".to_vec()),
                Some(b"last".to_vec()),
                None
            ]
        );
    }

    #[tokio::test]
    async fn an_overlong_request_is_refused() {
        let mut big = vec![b'x'; MAX_REQUEST + 1];
        let got = read(&big).await;
        assert!(matches!(got.last(), Some(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData));
        // Exactly the limit, with its newline, is fine.
        big.truncate(MAX_REQUEST);
        big.push(b'\n');
        let got = read(&big).await;
        assert!(matches!(&got[0], Ok(Some(l)) if l.len() == MAX_REQUEST));
    }
}
