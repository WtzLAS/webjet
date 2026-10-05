//! Connections: the flows this agent tracks (§14.4) and the circuit each
//! one's traffic takes; and, apart from them, its reverse proxy ports and
//! flows (§11.11).

use super::split::{Axis, Split};
use super::*;
use crate::model::{Circuit, Proxy, ProxyFlow, Sessions};
use gpui::uniform_list;

/// The flow table beside the selected flow or the sessions.
const CONNECTIONS: Split = Split {
    id: "connections",
    axis: Axis::Row,
    sized_first: false,
    default: 340.0,
    min: 240.0,
    rest_min: 400.0,
};

const COLS: [(f32, &str); 9] = [
    (34., "dir"),
    (52., "proto"),
    (190., "from"),
    (190., "to"),
    (110., "peer"),
    (110., "state"),
    (170., "circuit"),
    (110., "rule"),
    (70., "idle"),
];

pub(super) fn flow_key(f: &Flow) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        f.peer_id, f.proto, f.src, f.sport, f.dst, f.dport
    )
}

fn state_color(f: &Flow) -> u32 {
    if f.state.contains("one-way") || f.state.contains("opening") {
        theme::WARN
    } else if f.state.contains("closing") {
        theme::MUTED
    } else {
        theme::OK
    }
}

impl WebjetApp {
    pub(super) fn render_connections(
        &mut self,
        s: &Snapshot,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let mut sw = div().flex().gap_1();
        let proxied = s.proxy.as_ref().map(|p| p.live).unwrap_or(0);
        let labels = [
            "overlay flows".to_string(),
            format!("reverse proxy ({proxied})"),
        ];
        let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
        for (i, seg) in segmented("conn-view", &labels, usize::from(self.show_proxy))
            .into_iter()
            .enumerate()
        {
            sw = sw.child(seg.on_click(cx.listener(move |this, _, _, cx| {
                this.show_proxy = i == 1;
                cx.notify();
            })));
        }
        let body = if self.show_proxy {
            self.render_proxy(s, cx)
        } else {
            self.render_flows(s, cx)
        };
        div()
            .flex()
            .flex_col()
            .gap_2()
            .size_full()
            .child(sw)
            .child(div().flex_1().min_h(px(0.)).child(body))
            .into_any_element()
    }

    fn render_flows(&mut self, s: &Snapshot, cx: &mut Context<Self>) -> AnyElement {
        let ct = match &s.conntrack {
            Ok(c) => c,
            Err(e) => {
                return panel()
                    .child(heading("Connections"))
                    .child(muted(format!(
                        "This agent doesn't list its tracked flows ({e}). It needs webjetd {} or later.",
                        env!("CARGO_PKG_VERSION")
                    )))
                    .into_any_element();
            }
        };
        let filter = self.flow_filter.read(cx).text().to_string();
        let shown: Vec<Flow> = ct
            .flows
            .iter()
            .filter(|f| f.matches(&filter))
            .cloned()
            .collect();
        self.flows_shown = Rc::new(shown);
        let count = self.flows_shown.len();

        // ---- top line: counts and limits
        let summary = div()
            .flex()
            .items_center()
            .gap_3()
            .child(self.flow_filter.clone())
            .child(muted(format!("{count} of {} flows", ct.live)))
            .child(
                muted(format!(
                    "{} via gateway · limits {} per peer, {} new/s, {} total · {} evicted",
                    ct.gateway,
                    ct.limits.per_peer,
                    ct.limits.new_per_sec,
                    ct.limits.global,
                    ct.limits.evictions
                ))
                .text_xs(),
            );
        let summary = if ct.truncated {
            summary.child(chip("list cut to the most recent flows", theme::WARN))
        } else {
            summary
        };

        // ---- the table (virtualized)
        let flows = self.flows_shown.clone();
        let selected = self.flow_selected.clone();
        let list = uniform_list(
            "flows",
            count,
            cx.processor(move |_this, range: std::ops::Range<usize>, _window, cx| {
                range
                    .filter_map(|i| flows.get(i).map(|f| (i, f)))
                    .map(|(i, f)| {
                        let key = flow_key(f);
                        let sel = selected.as_deref() == Some(key.as_str());
                        let circuit_color = match &f.circuit {
                            Some(c) if c.direct => theme::OK,
                            Some(_) => theme::RELAY,
                            None => theme::MUTED,
                        };
                        div()
                            .id(("flow", i))
                            .flex()
                            .gap_2()
                            .px_2()
                            .h(px(24.))
                            .items_center()
                            .rounded_sm()
                            .cursor_pointer()
                            .bg(rgb(if sel { theme::RAISED } else { theme::PANEL }))
                            .hover(|s| s.bg(rgb(theme::RAISED)))
                            .child(
                                cell(COLS[0].0, if f.outbound { "→" } else { "←" }).text_color(
                                    rgb(if f.outbound { theme::TX } else { theme::RX }),
                                ),
                            )
                            .child(cell(COLS[1].0, f.proto.clone()))
                            .child(cell(COLS[2].0, f.from_text()))
                            .child(cell(COLS[3].0, f.to_text()))
                            .child(cell(COLS[4].0, f.peer.clone()))
                            .child(cell(COLS[5].0, f.state.clone()).text_color(rgb(state_color(f))))
                            .child(cell(COLS[6].0, f.circuit_text()).text_color(rgb(circuit_color)))
                            .child(
                                cell(COLS[7].0, f.rule.clone().unwrap_or_else(|| "—".into()))
                                    .text_color(rgb(theme::MUTED)),
                            )
                            .child(
                                cell(COLS[8].0, model::duration(f.idle_s))
                                    .text_color(rgb(theme::MUTED)),
                            )
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.flow_selected = Some(key.clone());
                                cx.notify();
                            }))
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .flex_1()
        .min_h(px(0.));
        let mut table = panel().flex_1().min_h(px(0.)).child(header_row(&COLS));
        if count == 0 {
            table = table.child(muted(if !ct.running {
                "The data plane isn't running yet."
            } else if ct.live == 0 {
                "No flows are tracked right now. Traffic to or from other nodes shows up here."
            } else {
                "No flow matches the filter."
            }));
        }
        let table = table.child(list);

        // ---- side: the selected flow, else the sessions
        let sessions = s.sessions.as_ref().ok();
        let side = match self
            .flow_selected
            .as_ref()
            .and_then(|k| ct.flows.iter().find(|f| &flow_key(f) == k))
        {
            Some(f) => self.render_flow_detail(s, f, sessions, cx),
            None => self.render_sessions_side(s, sessions, cx),
        };

        div()
            .flex()
            .flex_col()
            .gap_2()
            .size_full()
            .child(summary)
            .child(
                self.split(CONNECTIONS, table, side, cx)
                    .flex_1()
                    .min_h(px(0.)),
            )
            .into_any_element()
    }

    fn render_flow_detail(
        &self,
        s: &Snapshot,
        f: &Flow,
        sessions: Option<&Sessions>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let me = s.status.name.clone().unwrap_or_else(|| "this node".into());
        let mut p = scroll("flow-detail")
            .gap_1()
            .p_3()
            .rounded_md()
            .bg(rgb(theme::PANEL))
            .child(div().flex().justify_between().child(heading("Flow")).child(
                button("flow-close", "×", true, theme::BORDER).on_click(cx.listener(
                    |this, _, _, cx| {
                        this.flow_selected = None;
                        cx.notify();
                    },
                )),
            ))
            .child(label_value("Protocol", f.proto.clone()))
            .child(label_value("From", f.from_text()))
            .child(label_value("To", f.to_text()))
            .child(label_value(
                "Direction",
                if f.outbound {
                    "outbound (this node started it)"
                } else {
                    "inbound (the peer started it)"
                },
            ))
            .child(label_value("Peer", f.peer.clone()))
            .child(label_value(
                "State",
                format!(
                    "{}{}",
                    f.state,
                    if f.replied {
                        ", answered"
                    } else {
                        ", no reply yet"
                    }
                ),
            ))
            .child(label_value(
                "Admitted by",
                f.rule.clone().unwrap_or_else(|| "—".into()),
            ))
            .child(label_value(
                "Gateway",
                if f.gateway {
                    "yes (to a LAN behind this node)"
                } else {
                    "no"
                },
            ))
            .child(label_value(
                "Idle",
                format!(
                    "{} · expires in {}",
                    model::duration(f.idle_s),
                    model::duration(f.expires_s)
                ),
            ));
        p = p.child(div().pt_2().child(heading("Circuit")));
        let circuit: Option<&Circuit> = f.circuit.as_ref().and_then(|fc| {
            sessions?
                .circuits
                .local
                .iter()
                .find(|c| c.label == fc.label && c.peer_id == f.peer_id)
        });
        match (&f.circuit, circuit) {
            (None, _) => {
                p = p.child(muted(
                    "No end-to-end session with this peer is sending right now.",
                ))
            }
            (Some(fc), c) => {
                p = p
                    .child(label_value(
                        "Path",
                        c.map(|c| c.path_text(&me)).unwrap_or_else(|| fc.text()),
                    ))
                    .child(label_value(
                        "Kind",
                        if fc.direct {
                            "direct".to_string()
                        } else {
                            format!("relayed, {} relay(s)", fc.hops.len())
                        },
                    ))
                    .child(label_value("Round trip", rtt_text(fc.rtt_ms)))
                    .child(label_value("Label", fc.label.to_string()));
                if let Some(c) = c {
                    p = p
                        .child(label_value("Loss", loss_text(c.loss)))
                        .child(label_value("Age", model::duration(c.age_s)));
                    if let Some(r) = sessions.and_then(|ss| ss.route(&c.route_id)) {
                        p = p.child(label_value(
                            "Route traffic",
                            format!(
                                "▲ {} · ▼ {}",
                                model::bytes(r.fwd_bytes),
                                model::bytes(r.rev_bytes)
                            ),
                        ));
                    }
                    let label = c.label;
                    p = p.child(
                        div().pt_2().child(
                            button(
                                "flow-graph",
                                "Show in the network graph",
                                true,
                                theme::ACCENT,
                            )
                            .on_click(cx.listener(
                                move |this, _, _, cx| {
                                    this.circuit = Some(label);
                                    this.tab = Tab::Nodes;
                                    cx.notify();
                                },
                            )),
                        ),
                    );
                }
            }
        }
        let id = f.peer_id.clone();
        p.child(
            div().pt_1().child(
                button("flow-peer", "Show the peer node", true, theme::BORDER)
                    .on_click(cx.listener(move |this, _, _, cx| this.show_node(id.clone(), cx))),
            ),
        )
        .into_any_element()
    }

    fn render_sessions_side(
        &self,
        s: &Snapshot,
        sessions: Option<&Sessions>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let me = s.status.name.clone().unwrap_or_else(|| "this node".into());
        let mut p = scroll("sessions-side")
            .gap_1()
            .p_3()
            .rounded_md()
            .bg(rgb(theme::PANEL))
            .child(heading("End-to-end sessions"))
            .child(muted("Select a flow to see its circuit.").text_xs());
        let Some(ss) = sessions else {
            return p
                .child(muted("This agent doesn't report sessions."))
                .into_any_element();
        };
        if ss.sessions.is_empty() {
            p = p.child(muted("No end-to-end sessions."));
        }
        for (i, e) in ss.sessions.iter().enumerate() {
            let c = ss
                .circuits
                .local
                .iter()
                .find(|c| Some(c.label) == e.primary_circuit && c.peer_id == e.peer_id);
            let status = if e.established {
                ("established", theme::OK)
            } else if e.handshaking {
                ("handshaking", theme::WARN)
            } else {
                ("idle", theme::MUTED)
            };
            let label = c.map(|c| c.label);
            p = p.child(
                div()
                    .id(("sess", i))
                    .flex()
                    .flex_col()
                    .p_2()
                    .rounded_sm()
                    .bg(rgb(theme::RAISED))
                    .cursor_pointer()
                    .hover(|s| s.opacity(0.9))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(dot(status.1))
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child(e.peer.clone()),
                            )
                            .child(muted(status.0).text_xs()),
                    )
                    .child(
                        muted(match c {
                            Some(c) => format!("{} · {}", c.path_text(&me), rtt_text(c.rtt_ms)),
                            None => "no circuit".into(),
                        })
                        .text_xs(),
                    )
                    .child(
                        muted(format!(
                            "{} sent · {} received · {} path switches",
                            e.tx_packets, e.rx_packets, e.path_switches
                        ))
                        .text_xs(),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.circuit = label;
                        this.tab = Tab::Nodes;
                        cx.notify();
                    })),
            );
        }
        p.into_any_element()
    }
}

const PROXY: Split = Split {
    id: "proxy",
    axis: Axis::Row,
    sized_first: false,
    default: 360.0,
    min: 260.0,
    rest_min: 400.0,
};

const PROXY_COLS: [(f32, &str); 8] = [
    (56., "side"),
    (90., "rule"),
    (44., "proto"),
    (190., "client"),
    (190., "target"),
    (110., "via"),
    (110., "state"),
    (70., "idle"),
];

impl WebjetApp {
    fn render_proxy(&mut self, s: &Snapshot, cx: &mut Context<Self>) -> AnyElement {
        let px_ = match &s.proxy {
            Ok(p) => p,
            Err(e) => {
                return panel()
                    .child(heading("Reverse proxy"))
                    .child(muted(format!(
                        "This agent doesn't report reverse proxy ports ({e}). It needs webjetd {} or later.",
                        env!("CARGO_PKG_VERSION")
                    )))
                    .into_any_element();
            }
        };
        let filter = self.proxy_filter.read(cx).text().to_string();
        self.proxy_shown = Rc::new(
            px_.flows
                .iter()
                .filter(|f| f.matches(&filter))
                .cloned()
                .collect(),
        );
        let count = self.proxy_shown.len();
        let ingress = px_.flows.iter().filter(|f| f.ingress()).count();
        let mut summary = div()
            .flex()
            .items_center()
            .gap_3()
            .child(self.proxy_filter.clone())
            .child(muted(format!("{count} of {} proxy flows", px_.live)))
            .child(
                muted(format!(
                    "{ingress} listening here · {} to this node as a target · kept apart from the overlay's flows and counters",
                    px_.flows.len() - ingress
                ))
                .text_xs(),
            );
        if px_.truncated {
            summary = summary.child(chip("list cut to the most recent flows", theme::WARN));
        }

        let flows = self.proxy_shown.clone();
        let selected = self.proxy_selected.clone();
        let list =
            uniform_list(
                "proxy-flows",
                count,
                cx.processor(move |_this, range: std::ops::Range<usize>, _window, cx| {
                    range
                        .filter_map(|i| flows.get(i).map(|f| (i, f)))
                        .map(|(i, f)| {
                            let key = f.key();
                            let sel = selected.as_deref() == Some(key.as_str());
                            let via = if f.ingress() {
                                f.peer.clone()
                            } else {
                                format!("from {}", f.peer)
                            };
                            div()
                                .id(("pflow", i))
                                .flex()
                                .gap_2()
                                .px_2()
                                .h(px(24.))
                                .items_center()
                                .rounded_sm()
                                .cursor_pointer()
                                .bg(rgb(if sel { theme::RAISED } else { theme::PANEL }))
                                .hover(|s| s.bg(rgb(theme::RAISED)))
                                .child(cell(PROXY_COLS[0].0, f.side.clone()).text_color(rgb(
                                    if f.ingress() { theme::TX } else { theme::RX },
                                )))
                                .child(cell(PROXY_COLS[1].0, f.rule.clone()))
                                .child(cell(PROXY_COLS[2].0, f.proto.clone()))
                                .child(cell(PROXY_COLS[3].0, f.client.clone()))
                                .child(cell(PROXY_COLS[4].0, f.target.clone()))
                                .child(cell(PROXY_COLS[5].0, via))
                                .child(cell(PROXY_COLS[6].0, f.state.clone()).text_color(rgb(
                                    if f.state.contains("one-way") || f.state.contains("opening") {
                                        theme::WARN
                                    } else {
                                        theme::OK
                                    },
                                )))
                                .child(
                                    cell(PROXY_COLS[7].0, model::duration(f.idle_s))
                                        .text_color(rgb(theme::MUTED)),
                                )
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.proxy_selected = Some(key.clone());
                                    cx.notify();
                                }))
                        })
                        .collect::<Vec<_>>()
                }),
            )
            .flex_1()
            .min_h(px(0.));
        let mut table = panel()
            .flex_1()
            .min_h(px(0.))
            .child(header_row(&PROXY_COLS));
        if count == 0 {
            table = table.child(muted(if !px_.running {
                "The data plane isn't running yet."
            } else if px_.live == 0 {
                "No proxy flows right now."
            } else {
                "No flow matches the filter."
            }));
        }
        let table = table.child(list);

        let side = match self
            .proxy_selected
            .as_ref()
            .and_then(|k| px_.flows.iter().find(|f| &f.key() == k))
        {
            Some(f) => self.render_proxy_flow(f, cx),
            None => self.render_proxy_rules(px_),
        };
        div()
            .flex()
            .flex_col()
            .gap_2()
            .size_full()
            .child(summary)
            .child(self.split(PROXY, table, side, cx).flex_1().min_h(px(0.)))
            .into_any_element()
    }

    /// This node's rules with their status and warnings, and the traffic
    /// counters per rule.
    fn render_proxy_rules(&self, p: &Proxy) -> AnyElement {
        let mut side = scroll("proxy-rules")
            .gap_1()
            .p_3()
            .rounded_md()
            .bg(rgb(theme::PANEL))
            .child(heading("Reverse proxy rules"))
            .child(muted("Select a flow to see its addresses.").text_xs());
        if p.rules.is_empty() {
            side = side.child(muted(
                "This node listens on no port. Rules are [[proxy]] entries of the node's configuration (`webjetctl local config`).",
            ));
        }
        for (i, r) in p.rules.iter().enumerate() {
            let color = if !r.warnings.is_empty() {
                theme::WARN
            } else if r.status.starts_with("listening on") {
                theme::OK
            } else {
                theme::BAD
            };
            let mut card = div()
                .id(("prule", i))
                .flex()
                .flex_col()
                .p_2()
                .rounded_sm()
                .bg(rgb(theme::RAISED))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(dot(color))
                        .child(
                            div()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(r.name.clone()),
                        )
                        .child(muted(r.text()).text_xs()),
                )
                .child(
                    muted(format!(
                        "{} · {}",
                        r.status,
                        if r.real_ip {
                            "keeps the client's address"
                        } else {
                            "targets see this node's address"
                        }
                    ))
                    .text_xs(),
                );
            for w in &r.warnings {
                card = card.child(
                    div()
                        .text_xs()
                        .text_color(rgb(theme::WARN))
                        .child(format!("⚠ {w}")),
                );
            }
            side = side.child(card);
        }
        side = side.child(div().pt_2().child(heading("As a target")));
        side = side.child(
            muted(if p.real_ip_ready {
                "Accepts real client addresses ([proxy] accept_real_ip); replies are routed back into the overlay."
            } else if p.accept_real_ip {
                "[proxy] accept_real_ip is set but its routing isn't in place (see the alarms)."
            } else {
                "Real client addresses aren't accepted; proxies reach this node from their own overlay address."
            })
            .text_xs(),
        );
        if !p.counters.is_empty() {
            side = side.child(div().pt_2().child(heading("Traffic")));
            for c in &p.counters {
                side = side.child(
                    div()
                        .flex()
                        .flex_col()
                        .child(label_value(
                            &format!("{} ({})", c.rule, c.side),
                            format!(
                                "{} flows, {} active, {} refused",
                                c.flows, c.active, c.refused
                            ),
                        ))
                        .child(
                            muted(format!(
                                "{}to target {} · to client {}",
                                if c.side == "target" {
                                    format!("from {} · ", c.node)
                                } else {
                                    String::new()
                                },
                                model::bytes(c.to_target_bytes),
                                model::bytes(c.to_client_bytes)
                            ))
                            .text_xs(),
                        ),
                );
            }
        }
        side.into_any_element()
    }

    fn render_proxy_flow(&self, f: &ProxyFlow, cx: &mut Context<Self>) -> AnyElement {
        let mut p =
            scroll("proxy-flow")
                .gap_1()
                .p_3()
                .rounded_md()
                .bg(rgb(theme::PANEL))
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .child(heading("Proxy flow"))
                        .child(button("pflow-close", "×", true, theme::BORDER).on_click(
                            cx.listener(|this, _, _, cx| {
                                this.proxy_selected = None;
                                cx.notify();
                            }),
                        )),
                )
                .child(label_value(
                    "Rule",
                    format!("{} (listens on {})", f.rule, f.node),
                ))
                .child(label_value(
                    "This node",
                    if f.ingress() {
                        "listens: the client connected here"
                    } else {
                        "target: the flow came through the overlay"
                    },
                ))
                .child(label_value("Protocol", f.proto.clone()))
                .child(label_value("Client", f.client.clone()));
        if let Some(port) = f.listen_port {
            p = p.child(label_value("Listen port", port.to_string()));
        }
        p = p
            .child(label_value(
                "Source at the target",
                match &f.source {
                    Some(s) => format!("{s} (this node's address; the client's isn't kept)"),
                    None => format!("{} (the client's own address)", f.client),
                },
            ))
            .child(label_value("Target", f.target.clone()))
            .child(label_value(
                if f.ingress() {
                    "Target node"
                } else {
                    "Ingress"
                },
                f.peer.clone(),
            ));
        if f.gateway {
            p = p.child(label_value("Gateway", "to a LAN host behind this node"));
        }
        p = p
            .child(label_value(
                "State",
                format!(
                    "{}{}",
                    f.state,
                    if f.replied {
                        ", answered"
                    } else {
                        ", no reply yet"
                    }
                ),
            ))
            .child(label_value(
                "Idle",
                format!(
                    "{} · expires in {}",
                    model::duration(f.idle_s),
                    model::duration(f.expires_s)
                ),
            ));
        let id = f.peer_id.clone();
        p.child(
            div().pt_1().child(
                button("pflow-peer", "Show the other node", true, theme::BORDER)
                    .on_click(cx.listener(move |this, _, _, cx| this.show_node(id.clone(), cx))),
            ),
        )
        .into_any_element()
    }
}
