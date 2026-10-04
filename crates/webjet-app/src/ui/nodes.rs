//! Nodes: the network graph (every node, an edge per pair of nodes with a
//! link), the circuits of this agent, and the selected node's details.

use super::*;
use crate::graph::Edge;
use crate::model::{Action, Circuit, Node, Sessions};
use gpui::{Bounds, PathBuilder, Pixels, canvas, point};

/// One edge as the canvas draws it.
struct Line {
    a: (f32, f32),
    b: (f32, f32),
    color: u32,
    width: f32,
    dashed: bool,
}

fn vertex_color(relay: bool, control: bool) -> u32 {
    if control {
        theme::CONTROL
    } else if relay {
        theme::RELAY
    } else {
        theme::ACCENT
    }
}

fn kind_text(kind: &str) -> &'static str {
    match kind {
        "hop" => "measured by this agent",
        "relay" => "relay link (LinkStateAdvert)",
        "attachment" => "attachment to a home relay",
        _ => "reported link",
    }
}

fn edges_canvas(lines: Vec<Line>) -> impl IntoElement {
    canvas(
        move |_, _, _| lines,
        move |b: Bounds<Pixels>, lines, window, _| {
            let at = |p: (f32, f32)| {
                point(
                    b.origin.x + b.size.width * p.0,
                    b.origin.y + b.size.height * p.1,
                )
            };
            for l in lines {
                let mut pb = PathBuilder::stroke(px(l.width));
                if l.dashed {
                    pb = pb.dash_array(&[px(4.), px(4.)]);
                }
                pb.move_to(at(l.a));
                pb.line_to(at(l.b));
                if let Ok(p) = pb.build() {
                    window.paint_path(p, rgb(l.color));
                }
            }
        },
    )
    .absolute()
    .top_0()
    .left_0()
    .size_full()
}

impl WebjetApp {
    pub(super) fn render_nodes(&mut self, s: &Snapshot, cx: &mut Context<Self>) -> AnyElement {
        let sessions = s.sessions.as_ref().ok();
        let left = div()
            .flex()
            .flex_col()
            .gap_3()
            .flex_1()
            .min_w(px(0.))
            .h_full()
            .child(self.render_graph(s, sessions, cx))
            .child(self.render_circuits(s, sessions, cx));
        div()
            .flex()
            .gap_3()
            .size_full()
            .child(left)
            .child(self.render_node_side(s, cx))
            .into_any_element()
    }

    /// Node ids along the highlighted circuit.
    fn circuit_path(&self, s: &Snapshot, sessions: Option<&Sessions>) -> Vec<String> {
        let Some(l) = self.circuit else {
            return Vec::new();
        };
        sessions
            .and_then(|ss| ss.circuits.local.iter().find(|c| c.label == l))
            .map(|c| c.path_ids(s.me()))
            .unwrap_or_default()
    }

    fn render_graph(
        &self,
        s: &Snapshot,
        sessions: Option<&Sessions>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let g = &self.graph;
        let path = self.circuit_path(s, sessions);
        let on_path = |a: &str, b: &str| {
            path.windows(2)
                .any(|w| (w[0] == a && w[1] == b) || (w[0] == b && w[1] == a))
        };
        let sel = self.selected.as_deref().and_then(|id| g.index(id));
        let mut lines = Vec::new();
        let mut labels = Vec::new();
        let show_labels = g.edges.len() <= 40;
        for e in &g.edges {
            let (va, vb) = (&g.vertices[e.a], &g.vertices[e.b]);
            let highlight = on_path(&va.id, &vb.id);
            let touches = sel.is_some_and(|v| e.a == v || e.b == v);
            let lvl = link_level(e.rtt_ms(), e.loss());
            let color = if highlight {
                theme::ACCENT
            } else if sel.is_some() && !touches {
                theme::BORDER
            } else {
                theme::level(lvl)
            };
            lines.push(Line {
                a: (va.x, va.y),
                b: (vb.x, vb.y),
                color,
                width: if highlight {
                    4.0
                } else if e.mine() {
                    2.0
                } else {
                    1.25
                },
                dashed: !e.mine() && e.reports.iter().all(|r| r.kind == "attachment"),
            });
            if show_labels || highlight || touches {
                labels.push((
                    (va.x + vb.x) / 2.0,
                    (va.y + vb.y) / 2.0,
                    rtt_text(e.rtt_ms()),
                ));
            }
        }
        let mut area = div()
            .relative()
            .flex_1()
            .min_h(px(260.))
            .rounded_md()
            .bg(rgb(theme::INPUT))
            .overflow_hidden()
            .child(edges_canvas(lines));
        for (i, (x, y, t)) in labels.into_iter().enumerate() {
            area = area.child(
                div()
                    .id(("edge-label", i))
                    .absolute()
                    .left(gpui::relative(x))
                    .top(gpui::relative(y))
                    .ml(px(-26.))
                    .mt(px(-8.))
                    .w(px(52.))
                    .flex()
                    .justify_center()
                    .child(
                        div()
                            .px_1()
                            .rounded_sm()
                            .bg(rgb(theme::INPUT))
                            .text_xs()
                            .text_color(rgb(theme::MUTED))
                            .child(t),
                    ),
            );
        }
        for (i, v) in g.vertices.iter().enumerate() {
            let size = if v.infra() { 26.0 } else { 20.0 };
            let selected = sel == Some(i);
            let in_path = path.iter().any(|p| p == &v.id);
            let id = v.id.clone();
            let ring = if selected {
                0xffffff
            } else if in_path {
                theme::ACCENT
            } else if v.me {
                theme::TEXT
            } else {
                theme::INPUT
            };
            area = area.child(
                div()
                    .id(("vertex", i))
                    .absolute()
                    .left(gpui::relative(v.x))
                    .top(gpui::relative(v.y))
                    .ml(px(-60.))
                    .mt(px(-size / 2.0))
                    .w(px(120.))
                    .flex()
                    .flex_col()
                    .items_center()
                    .cursor_pointer()
                    .child(
                        div()
                            .w(px(size))
                            .h(px(size))
                            .rounded_full()
                            .border_2()
                            .border_color(rgb(ring))
                            .bg(rgb(vertex_color(v.relay, v.control)))
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_xs()
                            .text_color(rgb(0xffffff))
                            .child(if v.control {
                                "C"
                            } else if v.relay {
                                "R"
                            } else {
                                ""
                            }),
                    )
                    .child(
                        div()
                            .px_1()
                            .rounded_sm()
                            .bg(rgb(theme::INPUT))
                            .text_xs()
                            .text_color(rgb(if selected || v.me {
                                theme::TEXT
                            } else {
                                theme::MUTED
                            }))
                            .child(if v.me {
                                format!("{} (this)", v.name)
                            } else {
                                v.name.clone()
                            }),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.selected = if this.selected.as_deref() == Some(id.as_str()) {
                            None
                        } else {
                            Some(id.clone())
                        };
                        this.confirm = None;
                        cx.notify();
                    })),
            );
        }
        if g.vertices.is_empty() {
            area = area.child(
                div()
                    .size_full()
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(muted("No nodes known yet.")),
            );
        }
        let legend_item = |color: u32, t: &str| {
            div()
                .flex()
                .items_center()
                .gap_1()
                .child(dot(color))
                .child(muted(t.to_string()).text_xs())
        };
        let legend = div()
            .flex()
            .gap_3()
            .items_center()
            .child(legend_item(theme::CONTROL, "controller"))
            .child(legend_item(theme::RELAY, "relay"))
            .child(legend_item(theme::ACCENT, "data node"))
            .child(muted("·").text_xs())
            .child(legend_item(theme::OK, "good link"))
            .child(legend_item(theme::WARN, "slow or lossy"))
            .child(legend_item(theme::BAD, "bad"))
            .child(muted("thick: this agent's hops · dashed: attachments").text_xs());
        let topo_note = match &s.topology {
            Ok(_) => format!("{} nodes · {} links", g.vertices.len(), g.edges.len()),
            Err(e) => format!("links unavailable: {e}"),
        };
        panel()
            .flex_1()
            .min_h(px(0.))
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(heading("Network"))
                    .child(muted(topo_note).text_xs()),
            )
            .child(area)
            .child(legend)
            .into_any_element()
    }

    fn render_circuits(
        &self,
        s: &Snapshot,
        sessions: Option<&Sessions>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let me = s.status.name.clone().unwrap_or_else(|| "this node".into());
        let mut p = panel().h(px(250.)).flex_shrink_0();
        let Some(ss) = sessions else {
            return p
                .child(heading("Circuits"))
                .child(muted("This agent doesn't report its circuits."))
                .into_any_element();
        };
        let refused: u64 = ss.circuits.refused.values().sum();
        p = p.child(
            div()
                .flex()
                .justify_between()
                .child(heading("Circuits of this agent"))
                .child(
                    muted(format!(
                        "{} ending here · {} through here as a relay · {} refused",
                        ss.circuits.local.len(),
                        ss.circuits.transit,
                        refused
                    ))
                    .text_xs(),
                ),
        );
        let mut list = scroll("circuit-list").gap_1().w(px(470.)).flex_shrink_0();
        if ss.circuits.local.is_empty() {
            list = list.child(muted(
                "No circuits. One opens when this node talks to another node.",
            ));
        }
        for (i, c) in ss.circuits.local.iter().enumerate() {
            let sel = self.circuit == Some(c.label);
            let label = c.label;
            let lvl = link_level(c.rtt_ms, c.loss);
            list = list.child(
                div()
                    .id(("circuit", i))
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_2()
                    .py(px(3.))
                    .rounded_sm()
                    .cursor_pointer()
                    .bg(rgb(if sel { theme::RAISED } else { theme::PANEL }))
                    .border_1()
                    .border_color(rgb(if sel { theme::ACCENT } else { theme::PANEL }))
                    .hover(|s| s.bg(rgb(theme::RAISED)))
                    .child(dot(if c.open {
                        theme::level(lvl)
                    } else {
                        theme::MUTED
                    }))
                    .child(cell(14., if c.primary { "★" } else { "" }).text_color(rgb(theme::WARN)))
                    .child(cell(90., c.peer.clone()))
                    .child(
                        cell(
                            190.,
                            if c.direct {
                                "direct".to_string()
                            } else {
                                format!("via {}", c.hops.join(" → "))
                            },
                        )
                        .text_color(rgb(if c.direct {
                            theme::OK
                        } else {
                            theme::RELAY
                        })),
                    )
                    .child(cell(64., rtt_text(c.rtt_ms)))
                    .child(cell(44., loss_text(c.loss)).text_color(rgb(theme::MUTED)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.circuit = if this.circuit == Some(label) {
                            None
                        } else {
                            Some(label)
                        };
                        cx.notify();
                    })),
            );
        }
        let chosen: Option<&Circuit> = self
            .circuit
            .and_then(|l| ss.circuits.local.iter().find(|c| c.label == l));
        let mut detail = div().flex().flex_col().gap_1().flex_1().min_w(px(0.));
        match chosen {
            None => {
                detail = detail.child(muted(
                    "Select a circuit to see it in the graph. ★ marks the circuit a session sends on.",
                ));
                let transit: Vec<_> = ss
                    .circuits
                    .routes
                    .iter()
                    .filter(|r| r.role == "transit")
                    .collect();
                if !transit.is_empty() {
                    detail = detail.child(div().pt_1().child(heading("Relayed through this node")));
                    for r in transit.iter().take(5) {
                        detail = detail.child(
                            div()
                                .flex()
                                .gap_2()
                                .child(cell(240., r.path.join(" → ")))
                                .child(muted(format!(
                                    "▲ {} · ▼ {}",
                                    model::bytes(r.fwd_bytes),
                                    model::bytes(r.rev_bytes)
                                ))),
                        );
                    }
                }
            }
            Some(c) => {
                detail = detail
                    .child(label_value("Path", c.path_text(&me)))
                    .child(label_value(
                        "Kind",
                        format!(
                            "{} · {} · {}",
                            if c.direct {
                                "direct".to_string()
                            } else {
                                format!("{} relay(s)", c.hops.len())
                            },
                            if c.source {
                                "opened here"
                            } else {
                                "opened by the peer"
                            },
                            if c.primary {
                                "in use"
                            } else if c.open {
                                "standby"
                            } else {
                                "opening"
                            }
                        ),
                    ))
                    .child(label_value(
                        "Round trip",
                        format!(
                            "{} · {} loss · {} probes",
                            rtt_text(c.rtt_ms),
                            loss_text(c.loss),
                            c.probes
                        ),
                    ))
                    .child(label_value(
                        "Label / route",
                        format!("{} · {}", c.label, c.route_id),
                    ))
                    .child(label_value("Age", model::duration(c.age_s)));
                if let Some(r) = ss.route(&c.route_id) {
                    detail = detail
                        .child(label_value(
                            "Traffic",
                            format!(
                                "▲ {} ({} frames) · ▼ {} ({} frames)",
                                model::bytes(r.fwd_bytes),
                                r.fwd_frames,
                                model::bytes(r.rev_bytes),
                                r.rev_frames
                            ),
                        ))
                        .child(label_value(
                            "Dropped / ECN",
                            format!(
                                "{} queue · {} hop limit · {} ECN marked · {} setups",
                                r.dropped_queue, r.dropped_hop_limit, r.ecn_marked, r.setups
                            ),
                        ));
                }
            }
        }
        p.child(
            div()
                .flex()
                .gap_3()
                .flex_1()
                .min_h(px(0.))
                .child(list)
                .child(detail),
        )
        .into_any_element()
    }

    /// The finder, then the selected node's details and links.
    fn render_node_side(&self, s: &Snapshot, cx: &mut Context<Self>) -> AnyElement {
        let filter = self.node_filter.read(cx).text().to_string();
        let shown: Vec<&Node> = s.nodes.iter().filter(|n| n.matches(&filter)).collect();
        let mut list = scroll("node-list").gap(px(1.)).max_h(px(200.));
        for n in &shown {
            let sel = self.selected.as_deref() == Some(n.id.as_str());
            let id = n.id.clone();
            list = list.child(
                div()
                    .id(SharedString::from(format!("node-{}", n.id)))
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_2()
                    .py(px(2.))
                    .rounded_sm()
                    .cursor_pointer()
                    .bg(rgb(if sel { theme::RAISED } else { theme::PANEL }))
                    .hover(|s| s.bg(rgb(theme::RAISED)))
                    .child(dot(if !n.valid {
                        theme::BAD
                    } else {
                        vertex_color(n.relay, n.control)
                    }))
                    .child(cell(120., n.name.clone()))
                    .child(cell(100., n.ips.join(", ")).text_color(rgb(theme::MUTED)))
                    .child(cell(90., n.roles()).text_color(rgb(theme::MUTED)).text_xs())
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.selected = Some(id.clone());
                        this.confirm = None;
                        cx.notify();
                    })),
            );
        }
        let finder = panel()
            .child(
                div()
                    .flex()
                    .justify_between()
                    .child(heading("Nodes"))
                    .child(muted(format!("{} of {}", shown.len(), s.nodes.len())).text_xs()),
            )
            .child(self.node_filter.clone())
            .child(list);
        let detail = match self.selected.as_deref().and_then(|id| s.node(id)) {
            Some(n) => self.render_node_detail(s, &n.clone(), cx),
            None => panel()
                .child(muted("Select a node in the graph or the list."))
                .into_any_element(),
        };
        scroll("node-side")
            .w(px(380.))
            .flex_shrink_0()
            .gap_3()
            .child(finder)
            .child(detail)
            .into_any_element()
    }

    fn render_node_detail(&self, s: &Snapshot, n: &Node, cx: &mut Context<Self>) -> AnyElement {
        let mut d = panel()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(heading(&n.name))
                    .child(if n.valid {
                        chip("active", theme::OK)
                    } else {
                        chip("revoked or replaced", theme::BAD)
                    })
                    .child(if n.id == s.me() {
                        chip("this agent", theme::TEXT)
                    } else {
                        div()
                    }),
            )
            .child(label_value("Node id", model::short(&n.id).to_string()))
            .child(label_value("Key", n.key.clone()))
            .child(label_value("Addresses", n.ips.join(", ")))
            .child(label_value("Roles", n.roles()))
            .child(label_value(
                "Tags",
                if n.tags.is_empty() {
                    "—".into()
                } else {
                    n.tags.join(", ")
                },
            ))
            .child(label_value(
                "Subnet routes",
                if n.routes.is_empty() {
                    "—".into()
                } else {
                    n.routes.join(", ")
                },
            ))
            .child(label_value("Owner", n.owner.clone()))
            .child(label_value("Record version", n.version.to_string()));
        if let Some(v) = self.graph.index(&n.id)
            && let Some(l) = &self.graph.vertices[v].load
        {
            d = d.child(label_value(
                "Relay load",
                format!(
                    "util {}% · cpu {}% · circuits {}% · queue {}% · {} Mbit/s",
                    l.util_pct, l.cpu_pct, l.circuits_pct, l.queue_pct, l.capacity_mbps
                ),
            ));
        }
        d = d.child(self.render_links(n));
        let Some(si) = &self.signed_in else {
            return d.into_any_element();
        };
        let may_rename = si.session.may(&Action::RenameNode, Some(n));
        let may_revoke = si.session.may(&Action::RevokeNode, Some(n));
        let may_update = si.session.may(&Action::UpdateNode, Some(n)) && n.valid;
        if !(may_rename || may_revoke || may_update) {
            d = d.child(div().pt_2().text_color(rgb(theme::MUTED)).child(
                if si.session.is_admin() {
                    "This node is revoked; nothing can be changed."
                } else {
                    "Read-only: you can change only nodes your account owns."
                },
            ));
            return d.into_any_element();
        }
        let mut actions = div()
            .pt_2()
            .flex()
            .flex_col()
            .gap_2()
            .child(heading("Change"));
        let busy = self.busy;
        if may_rename {
            let node = n.clone();
            actions =
                actions.child(
                    div()
                        .flex()
                        .gap_2()
                        .items_center()
                        .child(self.rename.clone())
                        .child(button("rename", "Rename", !busy, theme::ACCENT).on_click(
                            cx.listener(move |this, _, _, cx| {
                                let new = this.rename.read(cx).text().trim().to_string();
                                let node = node.clone();
                                this.run_op(
                                    format!("Rename {} to {new}", node.name),
                                    move |a| client::ops::rename(a, &node, &new),
                                    cx,
                                );
                                this.rename.update(cx, |f, cx| f.clear(cx));
                            }),
                        )),
                );
        }
        if may_update {
            let node = n.clone();
            actions =
                actions.child(
                    div()
                        .flex()
                        .gap_2()
                        .items_center()
                        .child(self.tags.clone())
                        .child(button("tags", "Set tags", !busy, theme::ACCENT).on_click(
                            cx.listener(move |this, _, _, cx| {
                                let tags = this.tags.read(cx).text().to_string();
                                let node = node.clone();
                                this.run_op(
                                    format!("Set tags on {}", node.name),
                                    move |a| client::ops::set_tags(a, &node, &tags),
                                    cx,
                                );
                            }),
                        )),
                );
        }
        if may_revoke {
            let node = n.clone();
            let confirming = self.confirm == Some(Confirm::Revoke(n.id.clone()));
            actions = actions.child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .child(self.reason.clone())
                    .child(
                        button(
                            "revoke",
                            if confirming {
                                "Click again to revoke"
                            } else {
                                "Revoke node"
                            },
                            !busy,
                            theme::BAD,
                        )
                        .on_click(cx.listener(move |this, _, _, cx| {
                            if this.confirm == Some(Confirm::Revoke(node.id.clone())) {
                                let reason = this.reason.read(cx).text().to_string();
                                let node = node.clone();
                                this.run_op(
                                    format!("Revoke {}", node.name),
                                    move |a| client::ops::revoke(a, &node, &reason),
                                    cx,
                                );
                                this.reason.update(cx, |f, cx| f.clear(cx));
                            } else {
                                this.confirm = Some(Confirm::Revoke(node.id.clone()));
                                cx.notify();
                            }
                        })),
                    ),
            );
        }
        d.child(actions).into_any_element()
    }

    /// The node's links (graph edges) with what each end reported.
    fn render_links(&self, n: &Node) -> gpui::Div {
        let mut p = div()
            .pt_2()
            .flex()
            .flex_col()
            .gap_1()
            .child(heading("Links"));
        let Some(v) = self.graph.index(&n.id) else {
            return p.child(muted("Not in the graph."));
        };
        let mut edges: Vec<&Edge> = self.graph.edges_of(v);
        edges.sort_by(|a, b| a.rtt_ms().total_cmp(&b.rtt_ms()));
        if edges.is_empty() {
            p = p.child(muted("No links known."));
        }
        for e in edges {
            let other = &self.graph.vertices[e.other(v)];
            let mut row = div()
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
                        .child(dot(theme::level(link_level(e.rtt_ms(), e.loss()))))
                        .child(
                            div()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(other.name.clone()),
                        )
                        .child(muted(format!(
                            "{} · {} loss",
                            rtt_text(e.rtt_ms()),
                            loss_text(e.loss())
                        ))),
                );
            for r in &e.reports {
                let from = if r.a == n.id { &n.name } else { &other.name };
                let mut t = format!(
                    "{} · {} · {} {} · {} loss",
                    from,
                    kind_text(&r.kind),
                    r.transport,
                    rtt_text(r.rtt_ms),
                    loss_text(r.loss)
                );
                if let Some(u) = r.util_pct {
                    t.push_str(&format!(" · {u}% used"));
                }
                if let Some(remote) = &r.remote {
                    t.push_str(&format!(" · {remote}"));
                }
                if let (Some(tx), Some(rx)) = (r.tx_bytes, r.rx_bytes) {
                    t.push_str(&format!(" · ▲ {} ▼ {}", model::bytes(tx), model::bytes(rx)));
                }
                row = row.child(muted(t).text_xs());
            }
            p = p.child(row);
        }
        p
    }
}
