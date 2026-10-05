//! Nodes: the network graph (every node, an edge per pair of nodes with a
//! link), the circuits of this agent, and the selected node's details.

use super::split::{Axis, Split};
use super::*;
use crate::graph::{Edge, Viewport};
use crate::model::{Action, Circuit, Node, Sessions};
use gpui::{
    Bounds, CursorStyle, DispatchPhase, MouseButton, MouseDownEvent, MouseMoveEvent, MouseUpEvent,
    PathBuilder, Pixels, Point, ScrollDelta, ScrollWheelEvent, canvas, point,
};

/// What a drag on the graph moves.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum DragKind {
    /// The whole picture.
    Pan,
    /// One node, by id.
    Node(String),
}

/// A drag on the graph in progress. Positions are fractions of the graph
/// area (see `Viewport`).
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Drag {
    pub kind: DragKind,
    start: (f32, f32),
    last: (f32, f32),
    /// From the pointer to the dragged node's center, in graph units.
    grab: (f32, f32),
    /// Moved beyond the click threshold: not a click any more.
    pub moved: bool,
}

/// Pixels a press may wander and still count as a click.
const CLICK_SLOP: f32 = 3.0;

/// The graph and its circuits beside the node details.
const NODES: Split = Split {
    id: "nodes",
    axis: Axis::Row,
    sized_first: false,
    default: 420.0,
    min: 280.0,
    rest_min: 420.0,
};

/// The graph above this agent's circuits.
const GRAPH_CIRCUITS: Split = Split {
    id: "graph-circuits",
    axis: Axis::Column,
    sized_first: false,
    default: 250.0,
    min: 120.0,
    rest_min: 240.0,
};

/// The circuit list beside the selected circuit.
const CIRCUITS: Split = Split {
    id: "circuits",
    axis: Axis::Row,
    sized_first: true,
    default: 440.0,
    min: 200.0,
    rest_min: 240.0,
};

/// One edge as the canvas draws it.
struct Line {
    a: (f32, f32),
    b: (f32, f32),
    color: u32,
    width: f32,
    /// 1.0 for links a session sends on (and the selected circuit), less
    /// for the rest, so the links in use stand out in a crowded graph.
    opacity: f32,
}

/// Opacity of links no active circuit uses.
const IDLE_LINK_OPACITY: f32 = 0.7;
/// Opacity of the label backgrounds (delays, node names), so links and
/// nodes behind them stay visible.
const LABEL_BG_OPACITY: f32 = 0.7;

fn label_bg() -> gpui::Hsla {
    gpui::Hsla::from(rgb(theme::INPUT)).opacity(LABEL_BG_OPACITY)
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

/// The edges, drawn through the viewport. The canvas also records the
/// area's bounds (to turn pointer positions into graph positions) and,
/// while a drag is on, follows the pointer anywhere in the window.
fn edges_canvas(
    lines: Vec<Line>,
    vp: Viewport,
    bounds: Rc<Cell<[f32; 4]>>,
    dragging: Option<Entity<WebjetApp>>,
) -> impl IntoElement {
    canvas(
        move |b: Bounds<Pixels>, _, _| {
            bounds.set([
                f32::from(b.origin.x),
                f32::from(b.origin.y),
                f32::from(b.size.width),
                f32::from(b.size.height),
            ]);
            lines
        },
        move |b: Bounds<Pixels>, lines, window, _| {
            let at = |p: (f32, f32)| {
                let v = vp.to_view(p);
                point(
                    b.origin.x + b.size.width * v.0,
                    b.origin.y + b.size.height * v.1,
                )
            };
            // Links in use last, on top of the rest.
            let mut lines = lines;
            lines.sort_by(|x, y| x.opacity.total_cmp(&y.opacity));
            for l in lines {
                let mut pb = PathBuilder::stroke(px(l.width));
                pb.move_to(at(l.a));
                pb.line_to(at(l.b));
                if let Ok(p) = pb.build() {
                    window.paint_path(p, gpui::Hsla::from(rgb(l.color)).opacity(l.opacity));
                }
            }
            if let Some(app) = dragging {
                let up = app.clone();
                window.on_mouse_event(move |e: &MouseMoveEvent, phase, _, cx| {
                    if phase == DispatchPhase::Bubble {
                        app.update(cx, |this, cx| {
                            if e.pressed_button == Some(MouseButton::Left) {
                                this.drag_to(e.position, cx);
                            } else {
                                // The button went up outside the window.
                                this.end_drag(cx);
                            }
                        });
                    }
                });
                window.on_mouse_event(move |e: &MouseUpEvent, phase, _, cx| {
                    if phase == DispatchPhase::Bubble && e.button == MouseButton::Left {
                        up.update(cx, |this, cx| this.end_drag(cx));
                    }
                });
            }
        },
    )
    .absolute()
    .top_0()
    .left_0()
    .size_full()
}

impl WebjetApp {
    /// A window position as a fraction of the graph area.
    fn graph_pos(&self, p: Point<Pixels>) -> (f32, f32) {
        let [x, y, w, h] = self.graph_bounds.get();
        (
            (f32::from(p.x) - x) / w.max(1.0),
            (f32::from(p.y) - y) / h.max(1.0),
        )
    }

    pub(super) fn start_drag(&mut self, kind: DragKind, at: Point<Pixels>) {
        let v = self.graph_pos(at);
        let grab = match &kind {
            DragKind::Node(id) => self
                .graph
                .index(id)
                .map(|i| {
                    let g = self.viewport.to_graph(v);
                    let n = &self.graph.vertices[i];
                    (n.x - g.0, n.y - g.1)
                })
                .unwrap_or((0.0, 0.0)),
            DragKind::Pan => (0.0, 0.0),
        };
        self.drag = Some(Drag {
            kind,
            start: v,
            last: v,
            grab,
            moved: false,
        });
    }

    pub(super) fn drag_to(&mut self, at: Point<Pixels>, cx: &mut Context<Self>) {
        let v = self.graph_pos(at);
        let [_, _, w, h] = self.graph_bounds.get();
        let Some(d) = &mut self.drag else { return };
        if !d.moved {
            let (dx, dy) = ((v.0 - d.start.0) * w, (v.1 - d.start.1) * h);
            if dx.hypot(dy) < CLICK_SLOP {
                return;
            }
            d.moved = true;
        }
        match &d.kind {
            DragKind::Pan => self.viewport.pan_by(v.0 - d.last.0, v.1 - d.last.1),
            DragKind::Node(id) => {
                let g = self.viewport.to_graph(v);
                let p = (g.0 + d.grab.0, g.1 + d.grab.1);
                self.pinned.insert(id.clone(), p);
                if let Some(i) = self.graph.index(id) {
                    self.graph.vertices[i].x = p.0;
                    self.graph.vertices[i].y = p.1;
                }
            }
        }
        d.last = v;
        cx.notify();
    }

    /// The button went up: a node pressed without moving was clicked.
    pub(super) fn end_drag(&mut self, cx: &mut Context<Self>) {
        let Some(d) = self.drag.take() else { return };
        if !d.moved
            && let DragKind::Node(id) = d.kind
        {
            self.selected = if self.selected.as_deref() == Some(id.as_str()) {
                None
            } else {
                Some(id)
            };
            self.confirm = None;
        }
        cx.notify();
    }

    /// Two-finger scrolling pans; a mouse wheel, or scrolling with ⌘ or
    /// Ctrl held, zooms around the pointer.
    pub(super) fn scroll_graph(&mut self, e: &ScrollWheelEvent, cx: &mut Context<Self>) {
        let at = self.graph_pos(e.position);
        let [_, _, w, h] = self.graph_bounds.get();
        let zoom = e.modifiers.platform || e.modifiers.control;
        match e.delta {
            ScrollDelta::Pixels(p) if !zoom => self
                .viewport
                .pan_by(f32::from(p.x) / w.max(1.0), f32::from(p.y) / h.max(1.0)),
            ScrollDelta::Pixels(p) => self.viewport.zoom_at((f32::from(p.y) * 0.01).exp(), at),
            ScrollDelta::Lines(l) => self.viewport.zoom_at((l.y * 0.15).exp(), at),
        }
        cx.notify();
    }

    /// Forget moved nodes and go back to the computed layout and view.
    pub(super) fn reset_layout(&mut self) {
        self.pinned.clear();
        self.viewport = Viewport::default();
        if let Some(s) = &self.snapshot {
            self.graph = crate::graph::Graph::from_snapshot(s);
        }
    }

    pub(super) fn render_nodes(&mut self, s: &Snapshot, cx: &mut Context<Self>) -> AnyElement {
        let sessions = s.sessions.as_ref().ok();
        let graph = self.render_graph(s, sessions, cx);
        let circuits = self.render_circuits(s, sessions, cx);
        let left = self
            .split(GRAPH_CIRCUITS, graph, circuits, cx)
            .debug_selector(|| "nodes-left".into())
            .flex_1()
            .min_h(px(0.));
        let side = self.render_node_side(s, cx);
        self.split(NODES, left, side, cx)
            .size_full()
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
        let on = |path: &[String], a: &str, b: &str| {
            path.windows(2)
                .any(|w| (w[0] == a && w[1] == b) || (w[0] == b && w[1] == a))
        };
        // The paths of the circuits sessions send on (★ in the list).
        let active: Vec<Vec<String>> = sessions
            .map(|ss| {
                ss.circuits
                    .local
                    .iter()
                    .filter(|c| c.primary)
                    .map(|c| c.path_ids(s.me()))
                    .collect()
            })
            .unwrap_or_default();
        let sel = self.selected.as_deref().and_then(|id| g.index(id));
        let mut lines = Vec::new();
        let mut labels = Vec::new();
        let show_labels = g.edges.len() <= 40;
        for e in &g.edges {
            let (va, vb) = (&g.vertices[e.a], &g.vertices[e.b]);
            let highlight = on(&path, &va.id, &vb.id);
            let in_use = active.iter().any(|p| on(p, &va.id, &vb.id));
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
                } else if in_use {
                    2.5
                } else {
                    1.25
                },
                opacity: if highlight || in_use {
                    1.0
                } else {
                    IDLE_LINK_OPACITY
                },
            });
            if show_labels || highlight || in_use || touches {
                let (x, y) = self
                    .viewport
                    .to_view(((va.x + vb.x) / 2.0, (va.y + vb.y) / 2.0));
                labels.push((x, y, rtt_text(e.rtt_ms())));
            }
        }
        let panning = self.drag.as_ref().is_some_and(|d| d.moved);
        let listen = self.drag.is_some().then(|| cx.entity());
        let mut area = div()
            .id("graph-area")
            .relative()
            .flex_1()
            .min_h(px(100.))
            .rounded_md()
            .bg(rgb(theme::INPUT))
            .overflow_hidden()
            .cursor(if panning {
                CursorStyle::ClosedHand
            } else {
                CursorStyle::OpenHand
            })
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, e: &MouseDownEvent, _, cx| {
                    this.start_drag(DragKind::Pan, e.position);
                    cx.notify();
                }),
            )
            // Also ends a drag released before the window redrew with its
            // window-wide listeners.
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _: &MouseUpEvent, _, cx| this.end_drag(cx)),
            )
            .on_scroll_wheel(cx.listener(|this, e: &ScrollWheelEvent, _, cx| {
                this.scroll_graph(e, cx);
            }))
            .child(edges_canvas(
                lines,
                self.viewport,
                self.graph_bounds.clone(),
                listen,
            ));
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
                            .bg(label_bg())
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
            let (vx, vy) = self.viewport.to_view((v.x, v.y));
            let dragged = self
                .drag
                .as_ref()
                .is_some_and(|d| d.moved && d.kind == DragKind::Node(v.id.clone()));
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
                    .left(gpui::relative(vx))
                    .top(gpui::relative(vy))
                    .ml(px(-60.))
                    .mt(px(-size / 2.0))
                    .w(px(120.))
                    .flex()
                    .flex_col()
                    .items_center()
                    .cursor(if dragged {
                        CursorStyle::ClosedHand
                    } else {
                        CursorStyle::PointingHand
                    })
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
                            .bg(label_bg())
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
                    // Press and release: select; press and move: place it.
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, e: &MouseDownEvent, _, cx| {
                            this.start_drag(DragKind::Node(id.clone()), e.position);
                            cx.stop_propagation();
                            cx.notify();
                        }),
                    ),
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
                .flex_none()
                .items_center()
                .gap_1()
                .child(dot(color))
                .child(muted(t.to_string()).text_xs().whitespace_nowrap())
        };
        let legend_note = |t: &str| {
            muted(t.to_string())
                .text_xs()
                .flex_none()
                .whitespace_nowrap()
        };
        // Wraps onto more lines when the graph panel is narrow.
        let legend = div()
            .debug_selector(|| "graph-legend".into())
            .flex()
            .flex_wrap()
            .gap_x_3()
            .gap_y_1()
            .items_center()
            .min_w(px(0.))
            .child(legend_item(theme::CONTROL, "controller"))
            .child(legend_item(theme::RELAY, "relay"))
            .child(legend_item(theme::ACCENT, "data node"))
            .child(legend_item(theme::OK, "good link"))
            .child(legend_item(theme::WARN, "slow or lossy"))
            .child(legend_item(theme::BAD, "bad"))
            .child(legend_note("bold: links of circuits in use (★)"))
            .child(legend_note("faded: other links").debug_selector(|| "legend-last".into()));
        let hint = muted(
            "Drag the background to move the picture, drag a node to place it · scroll to move, \
             mouse wheel or ⌘/Ctrl + scroll to zoom",
        )
        .text_xs();
        let moved = self.pinned.len();
        let tools = div()
            .flex()
            .gap_1()
            .items_center()
            .child(muted(format!("{:.0}%", self.viewport.zoom * 100.0)).text_xs())
            .child(
                button("zoom-out", "−", true, theme::RAISED).on_click(cx.listener(
                    |this, _, _, cx| {
                        this.viewport.zoom_at(1.0 / 1.25, (0.5, 0.5));
                        cx.notify();
                    },
                )),
            )
            .child(
                button("zoom-in", "+", true, theme::RAISED).on_click(cx.listener(
                    |this, _, _, cx| {
                        this.viewport.zoom_at(1.25, (0.5, 0.5));
                        cx.notify();
                    },
                )),
            )
            .child(
                button("fit", "Fit", true, theme::RAISED).on_click(cx.listener(
                    |this, _, _, cx| {
                        this.viewport = Viewport::default();
                        cx.notify();
                    },
                )),
            )
            .child(
                button(
                    "relayout",
                    &if moved > 0 {
                        format!("Re-layout ({moved} moved)")
                    } else {
                        "Re-layout".to_string()
                    },
                    moved > 0,
                    theme::RAISED,
                )
                .on_click(cx.listener(|this, _, _, cx| {
                    this.reset_layout();
                    cx.notify();
                })),
            );
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
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .items_center()
                            .child(heading("Network"))
                            .child(muted(topo_note).text_xs()),
                    )
                    .child(tools),
            )
            .child(area)
            .child(legend)
            .child(hint)
            .into_any_element()
    }

    fn render_circuits(
        &self,
        s: &Snapshot,
        sessions: Option<&Sessions>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let me = s.status.name.clone().unwrap_or_else(|| "this node".into());
        let mut p = panel().flex_1().min_h(px(0.));
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
        let mut list = scroll("circuit-list")
            .gap_1()
            .debug_selector(|| "circuit-list".into());
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
                    .child(cell(120., c.peer.clone()).flex_shrink().min_w(px(0.)))
                    .child(
                        cell(
                            120.,
                            if c.direct {
                                "direct".to_string()
                            } else {
                                format!("via {}", c.hops.join(" → "))
                            },
                        )
                        .flex_shrink()
                        .min_w(px(0.))
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
        let mut detail = scroll("circuit-detail")
            .gap_1()
            .debug_selector(|| "circuit-detail".into());
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
        let row = self
            .split(CIRCUITS, list, detail, cx)
            .flex_1()
            .min_h(px(0.));
        p.child(row).into_any_element()
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
            .debug_selector(|| "node-side".into())
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
