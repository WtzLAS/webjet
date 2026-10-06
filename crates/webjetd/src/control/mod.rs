//! The local control channel (§13.1): newline-delimited JSON over a Unix
//! socket (named pipe on Windows) every local user may use; operations carry
//! their own signatures (see `ipc`). `webjetctl` uses it to
//! inspect the agent and to submit signed operations; the agent forwards
//! operations to a controller over the overlay (or applies them itself when
//! it is one).

mod commands;
pub mod request;

pub use commands::status;
pub use request::Request;

use crate::node::Node;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use webjet_core::crypto;
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
    // Admin-signed too (controller::audit::check_snapshot_request).
    ("snapshot", Access::Signed),
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

fn str_arg<'a>(req: &'a Value, k: &str) -> Result<&'a str> {
    req.get(k)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing {k}"))
}

/// Answer one request line. Commands not in [`COMMANDS`] are refused as
/// "unknown command" (webjet-app looks for those words to tell an older
/// agent), then the arguments are parsed into a [`Request`] and run by
/// `commands::run`.
pub async fn handle(n: &Arc<Node>, req: Value) -> Result<Value> {
    let cmd = str_arg(&req, "cmd")?;
    if access(cmd).is_none() {
        bail!("unknown command {cmd}");
    }
    let cmd = cmd.to_string();
    let req: Request =
        serde_json::from_value(req).with_context(|| format!("bad arguments for {cmd}"))?;
    commands::run(n, req).await
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

/// Offline-signed items a non-controller installed: hand them to a
/// controller as well (best effort; gossip spreads them anyway).
async fn forward_offline(n: &Arc<Node>, items: Vec<Vec<u8>>) {
    if n.is_controller() {
        return;
    }
    let body = RpcBody::OfflineSubmit(Box::new(wp::OfflineSubmit {
        items: Some(
            items
                .into_iter()
                .map(|b| wp::Blob { data: Some(b) })
                .collect(),
        ),
    }));
    let _ = crate::rpc::call_any(n, body, Duration::from_secs(10)).await;
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
            forward_offline(n, vec![raw]).await;
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

/// A client for `webjetctl`.
pub mod client {
    use super::*;

    /// Send one request and wait for its answer (the `result`, or the
    /// agent's error).
    pub async fn call(path: &std::path::Path, req: &Request) -> Result<Value> {
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
        let mut line = serde_json::to_vec(req)?;
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

    /// The command names of [`Request`]'s variants (snake_case, as serde
    /// writes them), read from the enum's source.
    fn variants() -> Vec<String> {
        let src = include_str!("request.rs");
        let start = src.find("pub enum Request {").expect("enum");
        let body = &src[start..];
        let end = body.find("\n}\n").expect("end of enum");
        let mut out: Vec<String> = body[..end]
            .lines()
            .skip(1)
            .filter_map(|l| {
                let name = l.strip_prefix("    ")?;
                let name: String = name.chars().take_while(|c| c.is_alphanumeric()).collect();
                name.starts_with(|c: char| c.is_ascii_uppercase()).then(|| {
                    let mut s = String::new();
                    for (i, c) in name.chars().enumerate() {
                        if c.is_ascii_uppercase() {
                            if i > 0 {
                                s.push('_');
                            }
                            s.push(c.to_ascii_lowercase());
                        } else {
                            s.push(c);
                        }
                    }
                    s
                })
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
            variants(),
            table,
            "`Request` and COMMANDS must name the same commands"
        );
        // And serde agrees with the names read from the source: every
        // listed command parses as a command (it may lack arguments).
        for (c, _) in COMMANDS {
            let e = serde_json::from_value::<Request>(json!({"cmd": c}))
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert!(!e.contains("unknown variant"), "{c}: {e}");
        }
    }

    #[test]
    fn unlisted_commands_and_bad_arguments_are_refused_before_running() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let mut c = crate::testnode::Cluster::new();
        let (id, kp) = c.data_node("a", "10.7.0.2", &[]);
        let (n, _dir) = crate::testnode::node(&mut c, id, kp);
        for (req, want) in [
            (json!({"cmd": "shutdown"}), "unknown command shutdown"),
            (json!({}), "missing cmd"),
            (json!({"cmd": "submit_op"}), "bad arguments for submit_op"),
            (
                json!({"cmd": "node_config", "node": "zz"}),
                "bad arguments for node_config",
            ),
        ] {
            let e = rt.block_on(handle(&n, req.clone())).expect_err("refused");
            assert!(format!("{e:#}").contains(want), "{req}: {e:#}");
        }
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
                "log",
                "snapshot"
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
