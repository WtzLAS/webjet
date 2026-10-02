//! Health checks (§18.6 clocks, §6.16 validity horizon, §19.7 alarms).

use crate::node::Node;
use std::sync::Arc;
use std::time::Duration;
use webjet_core::types::{now_ms, SKEW_HEAD};

const WARN_MS: i64 = 30_000;
const FATAL_MS: i64 = 60_000;

/// Set when the agent must stop because its clock is wrong.
pub static CLOCK_FATAL: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Trusted floor (§18.6): the clock must not be more than 5 min behind the
/// newest controller-signed `issued_at` we've seen.
pub fn check_floor(n: &Node) -> Result<(), String> {
    check_floor_raw(n.store.read().trusted_floor)
}

pub fn check_floor_raw(floor: u64) -> Result<(), String> {
    let now = now_ms();
    if floor > now + SKEW_HEAD {
        return Err(format!("system clock is {} s behind the newest signed tree head; fix the clock (§18.6)", (floor - now) / 1000));
    }
    Ok(())
}

/// Offsets against relays and controllers (§18.6).
pub fn check_clock(n: &Arc<Node>) {
    let offsets: Vec<i64> = {
        let s = n.store.read();
        let v = s.view();
        n.hops
            .lock()
            .values()
            .filter(|h| v.nodes.get(&h.peer).map(|x| x.relay || x.control).unwrap_or(false))
            .filter_map(|h| *h.clock_offset.lock())
            .collect()
    };
    if offsets.is_empty() {
        return;
    }
    let mut sorted = offsets.clone();
    sorted.sort();
    let median = sorted[sorted.len() / 2];
    // Fatal: at least two peers agreeing (within 5 s) that we're > 60 s off.
    let mut fatal = false;
    for (i, a) in sorted.iter().enumerate() {
        for b in sorted.iter().skip(i + 1) {
            if a.abs() > FATAL_MS && b.abs() > FATAL_MS && (a - b).abs() <= 5_000 && a.signum() == b.signum() {
                fatal = true;
            }
        }
    }
    if fatal {
        let msg = format!("clock is off by about {} s according to several peers; fix the clock (§18.6)", median / 1000);
        if CLOCK_FATAL.set(msg.clone()).is_ok() {
            tracing::error!("{msg}");
        }
        return;
    }
    if offsets.iter().any(|o| o.abs() > WARN_MS) {
        n.alarm("clock_skew", "warning", format!("clock offset against peers up to {} ms", offsets.iter().map(|o| o.abs()).max().unwrap_or(0)));
    } else {
        n.clear_alarm("clock_skew");
    }
}

/// Periodic checks: head expiry (soft mode), validity horizon, own record.
pub async fn run(n: Arc<Node>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tick.tick().await;
        if let Err(e) = check_floor(&n) {
            let _ = CLOCK_FATAL.set(e);
        }
        let now = now_ms();
        let (expired, horizon, me_ok, tomb) = {
            let s = n.store.read();
            (s.head_expired(now), s.horizon_passed(now), s.view().nodes.get(&n.me).map(|x| x.valid).unwrap_or(false), s.view().tombstoned_nodes.contains(&n.me))
        };
        if expired {
            n.alarm("soft_mode", "warning", "no fresh tree head: running in soft mode (§21.2)".into());
        } else {
            n.clear_alarm("soft_mode");
        }
        if horizon {
            n.alarm("validity_horizon", "critical", "the network's validity horizon has passed; no peer is trusted until a newer tree arrives (§6.16)".into());
        } else {
            n.clear_alarm("validity_horizon");
        }
        if tomb {
            n.alarm("node_tombstoned", "critical", "this node has been revoked; re-enroll it (§10.5)".into());
        } else if !me_ok && n.store.read().head().is_some() {
            n.alarm("node_invalid", "critical", "this node's record is missing or its key was replaced".into());
        } else {
            n.clear_alarm("node_tombstoned");
            n.clear_alarm("node_invalid");
        }
    }
}
