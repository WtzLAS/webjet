//! The local control channel (§13.1): newline-delimited JSON over a Unix
//! socket readable only by root/the agent's user. `webjetctl` uses it to
//! inspect the agent and to submit signed operations; the agent forwards
//! operations to a controller over the overlay (or applies them itself when
//! it is one).

use crate::node::Node;
use crate::state::{b64, unb64};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use webjet_core::crypto::{self, Bytes32};
use webjet_proto::{self as wp, RpcBody};

pub async fn serve(n: Arc<Node>) -> Result<()> {
    #[cfg(unix)]
    {
        let path = n.cfg.control_socket.clone();
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let _ = std::fs::remove_file(&path);
        let l = tokio::net::UnixListener::bind(&path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!("control socket at {}", path.display());
        loop {
            let (s, _) = l.accept().await?;
            let n2 = n.clone();
            tokio::spawn(async move {
                let (r, mut w) = s.into_split();
                let mut lines = BufReader::new(r).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let reply = match serde_json::from_str::<Value>(&line) {
                        Ok(req) => match handle(&n2, req).await {
                            Ok(v) => json!({"ok": true, "result": v}),
                            Err(e) => json!({"ok": false, "error": format!("{e:#}")}),
                        },
                        Err(e) => json!({"ok": false, "error": format!("bad request: {e}")}),
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
    #[cfg(not(unix))]
    {
        let _ = n;
        bail!("the control channel needs Unix sockets on this platform")
    }
}

fn str_arg<'a>(req: &'a Value, k: &str) -> Result<&'a str> {
    req.get(k).and_then(|v| v.as_str()).ok_or_else(|| anyhow!("missing {k}"))
}

fn node_json(n: &Node, id: &Bytes32) -> Value {
    let s = n.store.read();
    let v = s.view();
    let Some(info) = v.nodes.get(id) else { return json!({"id": hex::encode(id)}) };
    json!({
        "id": hex::encode(id),
        "name": info.name,
        "key": crypto::key_b64(&info.key),
        "ips": info.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
        "tags": info.tags,
        "owner": v.accounts.get(&info.owner).map(|a| a.name.clone()).unwrap_or_else(|| hex::encode(info.owner)),
        "relay": info.relay,
        "data": info.data,
        "control": info.control,
        "routes": info.routes.iter().map(|g| if g.mapped() { format!("{}={}", g.lan, g.published) } else { g.published.to_string() }).collect::<Vec<_>>(),
        "valid": info.valid,
        "version": info.rec.version,
    })
}

pub async fn handle(n: &Arc<Node>, req: Value) -> Result<Value> {
    let cmd = str_arg(&req, "cmd")?;
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
                        "rtt_ms": st.srtt_ms,
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
            let v: Vec<Value> = n.e2e.all().iter().map(|s| {
                let mut j = crate::e2e::summary(s);
                j["peer"] = json!(n.name_of(&s.peer));
                j
            }).collect();
            Ok(json!({"sessions": v, "circuits": crate::circuit::summary(n)}))
        }
        "nodes" => {
            let ids: Vec<Bytes32> = n.store.read().view().nodes.keys().copied().collect();
            let mut v: Vec<Value> = ids.iter().map(|id| node_json(n, id)).collect();
            v.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            Ok(json!(v))
        }
        "accounts" => {
            let s = n.store.read();
            let mut v: Vec<Value> = s
                .view()
                .accounts
                .values()
                .map(|a| json!({"id": hex::encode(a.id), "name": a.name, "admin": a.admin, "valid": a.valid, "key": crypto::key_b64(&a.key), "version": a.rec.version}))
                .collect();
            v.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            Ok(json!(v))
        }
        "tree" => {
            // Current singleton configs, for `webjetctl * show`.
            let s = n.store.read();
            let v = s.view();
            Ok(json!({
                "policy_version": v.policy_version,
                "dns": v.dns.as_ref().map(|d| serde_json::to_value(d).unwrap_or_default()),
                "seeds": v.seeds.as_ref().map(|d| serde_json::to_value(d).unwrap_or_default()),
                "limits": v.limits.as_ref().map(|d| serde_json::to_value(d).unwrap_or_default()),
                "transport": v.transport.as_ref().map(|d| serde_json::to_value(d).unwrap_or_default()),
                "valid_until": v.valid_until,
                "overlay_pool": s.overlay_pool.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            }))
        }
        "submit_op" => {
            let raw = unb64(str_arg(&req, "signed")?)?;
            let (i, desc) = submit_op(n, raw).await?;
            Ok(json!({"index": i, "applied": desc}))
        }
        "submit_offline" => {
            let items: Vec<Vec<u8>> = req.get("items").and_then(|v| v.as_array()).ok_or_else(|| anyhow!("missing items"))?.iter().filter_map(|x| x.as_str()).map(unb64).collect::<Result<_>>()?;
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
                let body = RpcBody::OfflineSubmit(Box::new(wp::OfflineSubmit { items: Some(items.iter().map(|b| wp::Blob { data: Some(b.clone()) }).collect()) }));
                let _ = crate::rpc::call_any(n, body, Duration::from_secs(10)).await;
            }
            Ok(json!({"added": added}))
        }
        "cert_request" => {
            let c = n.controller.get().ok_or_else(|| anyhow!("this node doesn't run the controller role"))?;
            Ok(json!({"request": b64(&c.cert_request()?)}))
        }
        "controller" => match n.controller.get() {
            Some(c) => Ok(c.status()),
            None => {
                let (_, r) = crate::rpc::call_any(n, RpcBody::GetControllerStatus(Box::new(wp::GetControllerStatus {})), Duration::from_secs(10)).await?;
                Ok(serde_json::to_value(match r {
                    RpcBody::ControllerStatus(s) => *s,
                    _ => bail!("unexpected reply"),
                })?)
            }
        },
        "redeem_self" => {
            let c = n.controller.get().ok_or_else(|| anyhow!("only a bootstrapping controller enrolls itself through the control channel"))?;
            let token = unb64(str_arg(&req, "token")?)?;
            let id = c.redeem_self(&token).await?;
            Ok(json!({"node_id": hex::encode(id)}))
        }
        "metrics" => {
            let raw = crate::metrics::build_report(n);
            let v = crypto::open_envelope(&raw)?;
            let rep: wp::MetricReport = v.decode()?;
            Ok(json!({"openmetrics": crate::metrics::openmetrics(&n.name_of(&n.me), &rep)}))
        }
        "reports" => {
            let c = n.controller.get().ok_or_else(|| anyhow!("not a controller"))?;
            let r = c.reports.lock();
            Ok(json!(r.iter().map(|(k, (t, v))| (n.name_of(k), json!({"received": t, "report": v}))).collect::<serde_json::Map<_, _>>()))
        }
        "head" => {
            let s = n.store.read();
            Ok(json!({"head": s.head().map(|h| b64(&h.raw))}))
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
            while n.store.read().head().map(|h| h.head.version).unwrap_or(0) < r.index && start.elapsed() < Duration::from_secs(15) {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok((r.index, String::new()))
        }
        RpcBody::SubmitResult(r) => bail!(r.error.unwrap_or_default()),
        RpcBody::RpcAck(a) => bail!(a.error.unwrap_or_default()),
        _ => bail!("unexpected reply"),
    }
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
        "roles": {"relay": me.map(|m| m.relay), "data": me.map(|m| m.data), "control": me.map(|m| m.control)},
        "valid": me.map(|m| m.valid).unwrap_or(false),
        "tree_version": s.head().map(|h| h.head.version),
        "tree_root": s.head().map(|h| hex::encode(h.root())),
        "head_expires": s.head().map(|h| h.head.expires_at),
        "valid_until": v.valid_until,
        "nodes": v.nodes.len(),
        "controllers": v.controllers.len(),
        "psk_epoch": n.epochs.read().current,
        "peers": n.peers().len(),
        "sessions": n.e2e.all().len(),
        "alarms": n.alarms.lock().iter().map(|(k, (sev, since))| json!({"name": k, "severity": sev, "since": since})).collect::<Vec<_>>(),
        "controller": n.controller.get().map(|c| c.status()),
        "uptime_s": n.started.elapsed().as_secs(),
        "version": env!("CARGO_PKG_VERSION"),
    })
}

/// A client for `webjetctl`.
pub mod client {
    use super::*;

    pub async fn call(path: &std::path::Path, req: Value) -> Result<Value> {
        #[cfg(unix)]
        {
            let s = tokio::net::UnixStream::connect(path).await.map_err(|e| anyhow!("connect to {}: {e} (is webjetd running? are you root?)", path.display()))?;
            let (r, mut w) = s.into_split();
            let mut line = serde_json::to_vec(&req)?;
            line.push(b'\n');
            w.write_all(&line).await?;
            let mut lines = BufReader::new(r).lines();
            let resp = tokio::time::timeout(Duration::from_secs(60), lines.next_line()).await.map_err(|_| anyhow!("timeout"))??.ok_or_else(|| anyhow!("no reply"))?;
            let v: Value = serde_json::from_str(&resp)?;
            if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
                Ok(v.get("result").cloned().unwrap_or(Value::Null))
            } else {
                bail!("{}", v.get("error").and_then(|e| e.as_str()).unwrap_or("error"))
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (path, req);
            bail!("unsupported platform")
        }
    }
}
