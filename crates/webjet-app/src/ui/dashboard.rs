//! Dashboard: how the network is doing, at a glance.

use super::split::{Axis, Split};
use super::*;
use crate::model::Action;
use gpui::{Bounds, PathBuilder, Pixels, canvas, point};

/// Throughput beside the hops.
const DASH_TRAFFIC: Split = Split {
    id: "dash-traffic",
    axis: Axis::Row,
    sized_first: false,
    default: 420.0,
    min: 280.0,
    rest_min: 300.0,
};

/// The network's facts beside relay load and alarms.
const DASH_NETWORK: Split = Split {
    id: "dash-network",
    axis: Axis::Row,
    sized_first: false,
    default: 420.0,
    min: 280.0,
    rest_min: 300.0,
};

/// A headline number with a caption.
fn stat(title: &str, value: String, sub: String, color: u32) -> gpui::Div {
    panel()
        .flex_1()
        .min_w(px(150.))
        .child(muted(title.to_string()).text_xs())
        .child(
            div()
                .text_2xl()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .text_color(rgb(color))
                .child(value),
        )
        .child(muted(sub).text_xs())
}

/// A horizontal bar for a percentage.
fn bar(pct: f32, color: u32) -> gpui::Div {
    div()
        .h(px(6.))
        .flex_1()
        .rounded_sm()
        .bg(rgb(theme::INPUT))
        .child(
            div()
                .h_full()
                .rounded_sm()
                .w(gpui::relative(pct.clamp(0.0, 100.0) / 100.0))
                .bg(rgb(color)),
        )
}

/// Two lines (sent, received) over the refresh history.
fn sparkline(rates: Vec<(f64, f64)>) -> impl IntoElement {
    canvas(
        move |_, _, _| rates,
        move |b: Bounds<Pixels>, rates, window, _| {
            let max = rates.iter().map(|r| r.0.max(r.1)).fold(1.0f64, f64::max);
            let n = rates.len().max(2) - 1;
            let at = |i: usize, v: f64| {
                point(
                    b.origin.x + b.size.width * (i as f32 / n as f32),
                    b.origin.y + b.size.height * (1.0 - (v / max) as f32 * 0.92),
                )
            };
            // Base line.
            let mut base = PathBuilder::stroke(px(1.));
            base.move_to(point(b.origin.x, b.origin.y + b.size.height));
            base.line_to(point(b.origin.x + b.size.width, b.origin.y + b.size.height));
            if let Ok(p) = base.build() {
                window.paint_path(p, rgb(theme::BORDER));
            }
            if rates.len() < 2 {
                return;
            }
            for (pick, color) in [(0usize, theme::TX), (1, theme::RX)] {
                let mut pb = PathBuilder::stroke(px(1.5));
                for (i, r) in rates.iter().enumerate() {
                    let v = if pick == 0 { r.0 } else { r.1 };
                    if i == 0 {
                        pb.move_to(at(i, v));
                    } else {
                        pb.line_to(at(i, v));
                    }
                }
                if let Ok(p) = pb.build() {
                    window.paint_path(p, rgb(color));
                }
            }
        },
    )
    .w_full()
    .h(px(90.))
}

impl WebjetApp {
    pub(super) fn render_dashboard(&self, s: &Snapshot, cx: &mut Context<Self>) -> AnyElement {
        let now = now_ms();
        let st = &s.status;
        let sum = s.summary();
        let health = model::health(s, now);

        // ---- health banner
        let mut banner = panel()
            .border_l_4()
            .border_color(rgb(theme::level(health.level)))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(dot(theme::level(health.level)))
                    .child(
                        div()
                            .text_lg()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(health.title()),
                    )
                    .child(muted(format!(
                        "as seen from {} · tree v{} · {}",
                        st.name.clone().unwrap_or_else(|| "this agent".into()),
                        st.tree_version.map(|v| v.to_string()).unwrap_or("—".into()),
                        if s.is_controller() {
                            "controller"
                        } else {
                            "agent"
                        }
                    ))),
            );
        if health.reasons.is_empty() {
            banner = banner.child(muted(
                "Signed tree current, node record valid, no alarms, connected.",
            ));
        }
        for r in health.reasons.iter().take(4) {
            banner = banner.child(div().child(format!("• {r}")));
        }

        // ---- headline numbers
        let stats = div()
            .flex()
            .gap_3()
            .child(stat(
                "Nodes",
                sum.nodes_active.to_string(),
                format!(
                    "{} relays · {} controllers · {} gateways",
                    sum.relays, sum.controllers, sum.gateways
                ),
                theme::TEXT,
            ))
            .child(stat(
                "Accounts",
                sum.accounts_active.to_string(),
                format!("{} admins", sum.admins),
                theme::TEXT,
            ))
            .child(stat(
                "Peers",
                format!("{}/{}", sum.sessions_established, sum.sessions_total),
                format!("{} hops · sessions established", sum.hops),
                if sum.sessions_established < sum.sessions_total {
                    theme::WARN
                } else {
                    theme::TEXT
                },
            ))
            .child(stat(
                "Circuits",
                sum.circuits.to_string(),
                format!(
                    "{} direct · {} relayed · {} transit",
                    sum.circuits_direct,
                    sum.circuits - sum.circuits_direct,
                    sum.transit
                ),
                theme::TEXT,
            ))
            .child(stat(
                "Flows",
                sum.flows.to_string(),
                match &s.conntrack {
                    Ok(c) if !c.running => "data plane not running".into(),
                    Ok(_) => format!("{} through this gateway", sum.flows_gateway),
                    Err(_) => "agent doesn't report flows".into(),
                },
                theme::TEXT,
            ));

        // ---- throughput
        let (tx, rx) = self.traffic.last().unwrap_or((0.0, 0.0));
        let traffic = panel()
            .flex_1()
            .child(
                div()
                    .flex()
                    .justify_between()
                    .child(heading("Throughput on this agent's hops"))
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(
                                div()
                                    .text_color(rgb(theme::TX))
                                    .child(format!("▲ {}", rate_text(tx))),
                            )
                            .child(
                                div()
                                    .text_color(rgb(theme::RX))
                                    .child(format!("▼ {}", rate_text(rx))),
                            ),
                    ),
            )
            .child(sparkline(self.traffic.rates()))
            .child(
                muted(format!(
                    "last 5 minutes · total {} sent, {} received",
                    model::bytes(sum.tx_bytes),
                    model::bytes(sum.rx_bytes)
                ))
                .text_xs(),
            );

        // ---- links: the agent's hops, worst first
        let mut peers = s.peers.clone();
        peers.sort_by(|a, b| {
            link_level(b.rtt_ms, b.loss)
                .cmp(&link_level(a.rtt_ms, a.loss))
                .then(b.rtt_ms.total_cmp(&a.rtt_ms))
        });
        let mut links = panel().flex_1().child(heading("Hops"));
        if peers.is_empty() {
            links = links.child(muted("No hop sessions."));
        }
        for p in peers.iter().take(6) {
            let lvl = link_level(p.rtt_ms, p.loss);
            let id = p.id.clone();
            links = links.child(
                div()
                    .id(SharedString::from(format!(
                        "dash-hop-{}-{}",
                        p.id, p.transport
                    )))
                    .flex()
                    .items_center()
                    .gap_2()
                    .cursor_pointer()
                    .hover(|s| s.bg(rgb(theme::RAISED)))
                    .rounded_sm()
                    .child(dot(theme::level(lvl)))
                    .child(cell(130., p.peer.clone()))
                    .child(cell(55., p.transport.clone()).text_color(rgb(theme::MUTED)))
                    .child(cell(70., rtt_text(p.rtt_ms)))
                    .child(cell(55., loss_text(p.loss)).text_color(rgb(theme::MUTED)))
                    .child(muted(model::duration(p.age_s)).text_xs())
                    .on_click(cx.listener(move |this, _, _, cx| this.show_node(id.clone(), cx))),
            );
        }

        // ---- network facts
        let mut net = panel()
            .flex_1()
            .child(heading("Network"))
            .child(label_value("Overlay pool", s.tree.overlay_pool.join(", ")))
            .child(label_value(
                "Tree",
                format!(
                    "version {} · root {}",
                    st.tree_version
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "none yet".into()),
                    st.tree_root.as_deref().map(model::short).unwrap_or("—")
                ),
            ))
            .child(label_value(
                "Head expires",
                st.head_expires
                    .map(|t| model::relative(t, now))
                    .unwrap_or_else(|| "—".into()),
            ))
            .child(label_value(
                "Valid until",
                if s.tree.valid_until > 0 {
                    model::relative(s.tree.valid_until, now)
                } else {
                    "—".into()
                },
            ))
            .child(label_value(
                "Policy version",
                s.tree.policy_version.to_string(),
            ))
            .child(label_value("PSK epoch", st.psk_epoch.to_string()))
            .child(label_value(
                "This agent",
                format!(
                    "{} · {} · up {}",
                    st.ips.clone().unwrap_or_default().join(", "),
                    st.version,
                    model::duration(st.uptime_s)
                ),
            ));
        if let Some(si) = &self.signed_in
            && si.session.may(&Action::RotatePsk, None)
        {
            let confirming = self.confirm == Some(Confirm::RotatePsk);
            let epoch = st.psk_epoch;
            net = net.child(
                div().pt_2().flex().gap_2().child(
                    button(
                        "rotate-psk",
                        if confirming {
                            "Click again to rotate the PSK"
                        } else {
                            "Rotate PSK"
                        },
                        !self.busy,
                        if confirming {
                            theme::BAD
                        } else {
                            theme::ACCENT
                        },
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if this.confirm == Some(Confirm::RotatePsk) {
                            this.run_op(
                                "Rotate PSK".into(),
                                |a| client::ops::rotate_psk(a, epoch),
                                cx,
                            );
                        } else {
                            this.confirm = Some(Confirm::RotatePsk);
                            cx.notify();
                        }
                    })),
                ),
            );
        }

        // ---- relay load (from LinkStateAdverts)
        let mut load = panel().child(heading("Relay load"));
        let relays: Vec<_> = self.graph.vertices.iter().filter(|v| v.relay).collect();
        if relays.is_empty() {
            load = load.child(muted("No relay has advertised its load."));
        }
        for v in relays.iter().take(6) {
            let (pct, cap) = v
                .load
                .as_ref()
                .map(|l| {
                    (
                        l.util_pct
                            .max(l.cpu_pct)
                            .max(l.circuits_pct)
                            .max(l.queue_pct) as f32,
                        l.capacity_mbps,
                    )
                })
                .unwrap_or((0.0, 0));
            let color = if pct >= 85.0 {
                theme::BAD
            } else if pct >= 60.0 {
                theme::WARN
            } else {
                theme::OK
            };
            load = load.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(cell(130., v.name.clone()))
                    .child(bar(pct, color))
                    .child(cell(40., format!("{pct:.0}%")))
                    .child(
                        cell(
                            80.,
                            if cap > 0 {
                                format!("{cap} Mbit/s")
                            } else {
                                "—".into()
                            },
                        )
                        .text_color(rgb(theme::MUTED)),
                    ),
            );
        }

        // ---- alarms
        let mut alarms = panel().child(heading("Alarms on this agent"));
        if st.alarms.is_empty() {
            alarms = alarms.child(div().text_color(rgb(theme::OK)).child("none"));
        }
        for a in &st.alarms {
            let color = if a.severity == "critical" {
                theme::BAD
            } else {
                theme::WARN
            };
            alarms = alarms.child(div().text_color(rgb(color)).child(format!(
                "{} ({}, since {})",
                a.name,
                a.severity,
                model::relative(a.since, now)
            )));
        }

        scroll("dashboard")
            .gap_3()
            .child(banner)
            .child(stats)
            .child(self.split(DASH_TRAFFIC, traffic, links, cx))
            .child(self.split(
                DASH_NETWORK,
                net,
                div().flex().flex_col().gap_3().child(load).child(alarms),
                cx,
            ))
            .into_any_element()
    }
}
