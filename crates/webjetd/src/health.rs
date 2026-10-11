//! Health checks (§18.6 clocks, §6.16 validity horizon, §19.7 alarms).

use crate::node::Node;
use std::sync::Arc;
use std::time::Duration;
use webjet_core::types::{SKEW_HEAD, now_ms};

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
        return Err(format!(
            "system clock is {} s behind the newest signed tree head; fix the clock (§18.6)",
            (floor - now) / 1000
        ));
    }
    Ok(())
}

/// Offsets against relays and controllers (§18.6).
pub fn check_clock(n: &Arc<Node>) {
    let offsets: Vec<i64> = {
        let s = n.store.snapshot();
        let v = s.view();
        n.hops
            .lock()
            .values()
            .filter(|h| v.nodes.get(&h.peer).is_some_and(|x| x.relay || x.control))
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
            if a.abs() > FATAL_MS
                && b.abs() > FATAL_MS
                && (a - b).abs() <= 5_000
                && a.signum() == b.signum()
            {
                fatal = true;
            }
        }
    }
    if fatal {
        let msg = format!(
            "clock is off by about {} s according to several peers; fix the clock (§18.6)",
            median / 1000
        );
        if CLOCK_FATAL.set(msg.clone()).is_ok() {
            tracing::error!("{msg}");
        }
        return;
    }
    if offsets.iter().any(|o| o.abs() > WARN_MS) {
        n.alarm(
            "clock_skew",
            "warning",
            format!(
                "clock offset against peers up to {} ms",
                offsets.iter().map(|o| o.abs()).max().unwrap_or(0)
            ),
        );
    } else {
        n.clear_alarm("clock_skew");
    }
}

/// Periodic checks: head expiry (soft mode), validity horizon, own record.
pub async fn run(n: Arc<Node>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    let mut i: u64 = 0;
    let mut alone = Alone::new(std::time::Instant::now());
    loop {
        tick.tick().await;
        i += 1;
        if i.is_multiple_of(6) {
            n.persist_links();
        }
        // Clock offsets come with keepalive acks; looked at here, not per ack.
        check_clock(&n);
        if let Err(e) = check_floor(&n) {
            let _ = CLOCK_FATAL.set(e);
        }
        let now = now_ms();
        let (expired, horizon, me_ok, tomb) = {
            let s = n.store.read();
            (
                s.head_expired(now),
                s.horizon_passed(now),
                s.view().nodes.get(&n.me).is_some_and(|x| x.valid),
                s.view().tombstoned_nodes.contains(&n.me),
            )
        };
        if expired {
            n.alarm(
                "soft_mode",
                "warning",
                "no fresh tree head: running in soft mode (§21.2)".into(),
            );
        } else {
            n.clear_alarm("soft_mode");
        }
        if horizon {
            n.alarm("validity_horizon", "critical", "the network's validity horizon has passed; no peer is trusted until a newer tree arrives (§6.16)".into());
        } else {
            n.clear_alarm("validity_horizon");
        }
        if tomb {
            n.alarm(
                "node_tombstoned",
                "critical",
                "this node has been revoked; re-enroll it (§10.5)".into(),
            );
        } else if !me_ok && n.store.read().head().is_some() {
            n.alarm(
                "node_invalid",
                "critical",
                "this node's record is missing or its key was replaced".into(),
            );
        } else {
            n.clear_alarm("node_tombstoned");
            n.clear_alarm("node_invalid");
        }
        if i.is_multiple_of(6) || i == 1 {
            check_camouflage(&n, now);
        }
        check_listen(&n);
        check_alone(&n, &mut alone).await;
    }
}

/// How long without any hop before asking time servers (§18.6).
const ALONE_AFTER: Duration = Duration::from_secs(120);
/// How often to ask again while still without hops.
const ALONE_RECHECK: Duration = Duration::from_secs(600);

/// Bookkeeping for `check_alone`.
pub struct Alone {
    /// Since when the node has had no hop.
    since: std::time::Instant,
    /// When time servers were last asked during this stretch.
    asked: Option<std::time::Instant>,
}

impl Alone {
    pub fn new(now: std::time::Instant) -> Self {
        Alone {
            since: now,
            asked: None,
        }
    }

    /// Whether to ask time servers now. `connected`: any hop is up;
    /// `others`: the network has relays or controllers to connect to.
    pub fn due(&mut self, now: std::time::Instant, connected: bool, others: bool) -> bool {
        if connected || !others {
            *self = Alone::new(now);
            return false;
        }
        let due = now.duration_since(self.since) >= ALONE_AFTER
            && self
                .asked
                .is_none_or(|a| now.duration_since(a) >= ALONE_RECHECK);
        if due {
            self.asked = Some(now);
        }
        due
    }
}

/// A node more than a minute off is dropped silently at every PSK gate, so
/// keepalive offsets (`check_clock`) never come. After two minutes without
/// any hop, ask time servers; a clock off by more than the gate allows
/// raises `clock_skew` (critical), which `check_clock` clears once hops
/// come back with sane offsets.
async fn check_alone(n: &Arc<Node>, alone: &mut Alone) {
    let connected = !n.hops.lock().is_empty();
    let others = {
        let s = n.store.snapshot();
        s.view()
            .nodes
            .iter()
            .any(|(id, x)| *id != n.me && x.valid && (x.relay || x.control))
    };
    if !alone.due(std::time::Instant::now(), connected, others) {
        return;
    }
    let Some(o) = crate::agent::clock_offset(&n.cfg).await else {
        return;
    };
    match crate::agent::clock_message(&o) {
        Some(msg) => {
            tracing::error!("{msg}");
            n.alarm("clock_skew", "critical", msg);
        }
        None => n.clear_alarm("clock_skew"),
    }
}

/// A relay or controller nobody can dial (§10.6): without `[listen]` in
/// webjetd.toml (or a router port mapping) edge nodes reach it only by
/// hole punching, which fails from behind symmetric NATs, so they keep
/// fewer home relays than they should and nothing else says why.
pub fn check_listen(n: &Node) {
    let core = n.is_controller()
        || n.store
            .read()
            .view()
            .nodes
            .get(&n.me)
            .is_some_and(|x| x.relay || x.control);
    match listen_alarm(core, &n.cfg.listen, n.port_mapping.lock().is_some()) {
        Some(msg) => n.alarm("not_listening", "warning", msg),
        None => n.clear_alarm("not_listening"),
    }
}

pub fn listen_alarm(core: bool, listen: &crate::config::Listen, mapped: bool) -> Option<String> {
    let listening = listen.tls.is_some() || listen.kcp.is_some() || listen.anytls.is_some();
    (core && !listening && !mapped).then(|| {
        "this relay/controller accepts no connections: webjetd.toml has no [listen], \
         so other nodes reach it only by hole punching"
            .into()
    })
}

const DAY_MS: u64 = 86_400_000;

/// The camouflage certificate alarm (§9.7.2): raised where it matters, on
/// nodes that serve AnyTLS and on controllers (which hold the secret), from
/// 30 days before the certificate expires.
fn check_camouflage(n: &Node, now: u64) {
    if n.cfg.listen.anytls.is_none() && !n.is_controller() {
        return;
    }
    match crate::transport::camouflage_not_after(n).and_then(|t| camouflage_alarm(now, t)) {
        Some((severity, msg)) => {
            // Re-raise when the severity changes.
            if n.alarms
                .lock()
                .get("camouflage_certificate")
                .map(|a| a.0.as_str())
                != Some(severity)
            {
                n.clear_alarm("camouflage_certificate");
            }
            n.alarm("camouflage_certificate", severity, msg);
        }
        None => n.clear_alarm("camouflage_certificate"),
    }
}

/// Severity and message for a certificate expiring at `not_after`, or
/// `None` while more than 30 days remain.
pub fn camouflage_alarm(now: u64, not_after: u64) -> Option<(&'static str, String)> {
    if not_after <= now {
        return Some((
            "critical",
            "the camouflage certificate has expired; renew it (ops guide 3.2)".into(),
        ));
    }
    let days = (not_after - now) / DAY_MS;
    if days >= 30 {
        return None;
    }
    let severity = if days < 7 { "critical" } else { "warning" };
    Some((
        severity,
        format!("the camouflage certificate expires in {days} days; renew it (ops guide 3.2)"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_servers_are_asked_after_two_minutes_alone() {
        use std::time::Instant;
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut a = Alone::new(t0);
        assert!(!a.due(at(60), false, true));
        assert!(a.due(at(120), false, true));
        assert!(!a.due(at(130), false, true), "not again at once");
        assert!(a.due(at(720), false, true), "again after ten minutes");
        // A hop resets it; a network without relays never asks.
        assert!(!a.due(at(730), true, true));
        assert!(!a.due(at(800), false, true));
        assert!(a.due(at(850), false, true));
        let mut b = Alone::new(t0);
        assert!(!b.due(at(1000), false, false));
    }

    #[test]
    fn relays_and_controllers_must_listen() {
        let none = crate::config::Listen::default();
        let kcp = crate::config::Listen {
            kcp: Some("0.0.0.0:6969".parse().unwrap()),
            ..Default::default()
        };
        assert!(listen_alarm(true, &none, false).is_some());
        assert!(listen_alarm(true, &none, true).is_none());
        assert!(listen_alarm(true, &kcp, false).is_none());
        assert!(listen_alarm(false, &none, false).is_none());
    }

    #[test]
    fn camouflage_alarm_thresholds() {
        let now = 1_000 * DAY_MS;
        assert_eq!(camouflage_alarm(now, now + 31 * DAY_MS), None);
        assert_eq!(camouflage_alarm(now, now + 30 * DAY_MS), None);
        assert_eq!(
            camouflage_alarm(now, now + 29 * DAY_MS).unwrap().0,
            "warning"
        );
        assert!(
            camouflage_alarm(now, now + 29 * DAY_MS)
                .unwrap()
                .1
                .contains("29 days")
        );
        assert_eq!(
            camouflage_alarm(now, now + 7 * DAY_MS).unwrap().0,
            "warning"
        );
        assert_eq!(
            camouflage_alarm(now, now + 6 * DAY_MS).unwrap().0,
            "critical"
        );
        assert!(camouflage_alarm(now, now).unwrap().1.contains("expired"));
        assert!(
            camouflage_alarm(now, now - 1)
                .unwrap()
                .1
                .contains("expired")
        );
    }
}
