//! The network graph for the Nodes tab: one vertex per node, one edge per
//! pair of nodes that report a link (§11.4), laid out deterministically with
//! a force-directed layout. Positions are fractions of the drawing area.

mod layout;

use crate::model::{Load, Snapshot, TopoEdge};
pub use layout::{DEFAULT_AREA, vertex_box};
use layout::{Item, P, layout, place};
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq)]
pub struct Vertex {
    pub id: String,
    pub name: String,
    pub ips: Vec<String>,
    pub relay: bool,
    pub control: bool,
    pub me: bool,
    pub load: Option<Load>,
    /// The webjetd version it runs, when known (`0.7.1`).
    pub software: Option<String>,
    /// Ignored by this agent for its old gossip protocol (§10.6.5).
    pub outdated: bool,
    /// Position in 0..1 of the drawing area's width and height.
    pub x: f32,
    pub y: f32,
}

impl Vertex {
    /// Relays and controllers form the network's core.
    pub fn infra(&self) -> bool {
        self.relay || self.control
    }

    /// The text under the vertex: name, "(this)" for this agent, and the
    /// version it runs; outdated nodes say so.
    pub fn label(&self) -> String {
        let mut t = self.name.clone();
        if self.me {
            t.push_str(" (this)");
        }
        match (&self.software, self.outdated) {
            (Some(v), true) => {
                let _ = write!(t, " · {v} outdated");
            }
            (None, true) => t.push_str(" · outdated"),
            (Some(v), false) => {
                let _ = write!(t, " · {v}");
            }
            (None, false) => {}
        }
        t
    }
}

/// An undirected edge, with every report of the link (each end may report).
#[derive(Clone, Debug, PartialEq)]
pub struct Edge {
    pub a: usize,
    pub b: usize,
    pub reports: Vec<TopoEdge>,
}

impl Edge {
    /// The report shown first: this agent's own measurement, else the
    /// freshest one.
    pub fn best(&self) -> Option<&TopoEdge> {
        self.reports
            .iter()
            .min_by_key(|r| (r.kind != "hop", r.age_s))
    }

    /// This agent has a live hop on this link.
    pub fn mine(&self) -> bool {
        self.reports.iter().any(|r| r.kind == "hop")
    }

    pub fn rtt_ms(&self) -> f64 {
        self.best().map_or(0.0, |r| r.rtt_ms)
    }

    pub fn loss(&self) -> f64 {
        self.best().map_or(0.0, |r| r.loss)
    }

    pub fn other(&self, v: usize) -> usize {
        if self.a == v { self.b } else { self.a }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Graph {
    pub vertices: Vec<Vertex>,
    pub edges: Vec<Edge>,
    /// The drawing area (pixels) the layout was made for.
    pub area: (f32, f32),
}

impl Graph {
    /// Build the graph from a snapshot's topology, falling back to the node
    /// list (no edges) for an agent without the `topology` command.
    pub fn from_snapshot(s: &Snapshot) -> Graph {
        Graph::build(s, DEFAULT_AREA, None)
    }

    /// Build the graph for a drawing area of `area` pixels. With the graph
    /// shown before (`previous`), every node keeps its place and new ones
    /// are put next to their neighbors (`keep`); only a graph with nothing
    /// to continue from is laid out.
    pub fn build(s: &Snapshot, area: (f32, f32), previous: Option<&Graph>) -> Graph {
        let mut g = Graph::shape(s, area);
        if !g.keep(previous) {
            g.lay_out(previous);
        }
        g
    }

    /// The vertices and edges, not laid out yet (every vertex in the middle).
    pub fn shape(s: &Snapshot, area: (f32, f32)) -> Graph {
        let mut vertices: Vec<Vertex> = match &s.topology {
            Ok(t) => t
                .nodes
                .iter()
                .map(|n| Vertex {
                    id: n.id.clone(),
                    name: n.name.clone(),
                    ips: n.ips.clone(),
                    relay: n.relay,
                    control: n.control,
                    me: n.me || n.id == t.me,
                    load: n.load.clone(),
                    software: n.software.clone(),
                    outdated: n.outdated,
                    x: 0.5,
                    y: 0.5,
                })
                .collect(),
            Err(_) => s
                .nodes
                .iter()
                .filter(|n| n.valid)
                .map(|n| Vertex {
                    id: n.id.clone(),
                    name: n.name.clone(),
                    ips: n.ips.clone(),
                    relay: n.relay,
                    control: n.control,
                    me: n.id == s.status.node_id,
                    load: None,
                    software: None,
                    outdated: false,
                    x: 0.5,
                    y: 0.5,
                })
                .collect(),
        };
        // Stable order: the core first, then by name.
        vertices.sort_by(|a, b| (!a.infra(), &a.name).cmp(&(!b.infra(), &b.name)));
        let index: BTreeMap<&str, usize> = vertices
            .iter()
            .enumerate()
            .map(|(i, v)| (v.id.as_str(), i))
            .collect();
        let mut merged: BTreeMap<(usize, usize), Vec<TopoEdge>> = BTreeMap::new();
        if let Ok(t) = &s.topology {
            for e in &t.edges {
                let (Some(&a), Some(&b)) = (index.get(e.a.as_str()), index.get(e.b.as_str()))
                else {
                    continue;
                };
                if a == b {
                    continue;
                }
                merged
                    .entry((a.min(b), a.max(b)))
                    .or_default()
                    .push(e.clone());
            }
        }
        let edges: Vec<Edge> = merged
            .into_iter()
            .map(|((a, b), reports)| Edge { a, b, reports })
            .collect();
        Graph {
            vertices,
            edges,
            area,
        }
    }

    /// Without the layout: take the positions of the graph shown before, so
    /// a refresh never moves a node that is already on the screen, whatever
    /// changed (links coming and going, labels, the area's size: positions
    /// are fractions of the area, so the picture stretches with it). New
    /// vertices are put into free room next to their neighbors (`place`);
    /// vertices that went away leave a gap. Only "Re-layout" lays out the
    /// whole picture again.
    ///
    /// The graph keeps the area the picture was laid out for. False when
    /// there is no picture to continue (none before, or none of its nodes
    /// left): then the caller lays it out (`lay_out`), which can take a
    /// while for a large graph, so the app does it in the background.
    pub fn keep(&mut self, previous: Option<&Graph>) -> bool {
        let Some(p) = previous else {
            return false;
        };
        let (aw, ah) = (
            f64::from(self.area.0.max(100.0)),
            f64::from(self.area.1.max(100.0)),
        );
        let pix = p.index_map();
        let mut at: Vec<Option<P>> = self
            .vertices
            .iter()
            .map(|v| {
                pix.get(v.id.as_str()).map(|&i| {
                    let o = &p.vertices[i];
                    (f64::from(o.x) * aw, f64::from(o.y) * ah)
                })
            })
            .collect();
        if at.iter().all(Option::is_none) {
            return false;
        }
        let items: Vec<Item> = self
            .vertices
            .iter()
            .map(|v| {
                let (w, h, circle) = vertex_box(&v.label(), v.infra());
                Item {
                    w,
                    h,
                    circle,
                    start: None,
                }
            })
            .collect();
        let n = self.vertices.len();
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        for e in &self.edges {
            adj[e.a].push(e.b);
            adj[e.b].push(e.a);
        }
        // New vertices one by one: first the one with the most neighbors
        // already placed, so a new group grows from where it is attached.
        loop {
            let next = (0..n).filter(|&i| at[i].is_none()).max_by_key(|&i| {
                let placed = adj[i].iter().filter(|&&j| at[j].is_some()).count();
                (placed, std::cmp::Reverse(i))
            });
            let Some(i) = next else { break };
            at[i] = Some(place(i, &items, &at, &adj, (aw, ah)));
        }
        for (v, a) in self.vertices.iter_mut().zip(&at) {
            if let Some((x, y)) = a {
                v.x = (x / aw) as f32;
                v.y = (y / ah) as f32;
            }
        }
        self.area = p.area;
        true
    }

    /// Compute the layout for `self.area`, continuing from `previous`
    /// where it has the same vertices.
    pub fn lay_out(&mut self, previous: Option<&Graph>) {
        let pix = previous.map(Graph::index_map);
        let items: Vec<Item> = self
            .vertices
            .iter()
            .map(|v| {
                let (w, h, circle) = vertex_box(&v.label(), v.infra());
                Item {
                    w,
                    h,
                    circle,
                    start: previous
                        .zip(pix.as_ref())
                        .and_then(|(p, ix)| ix.get(v.id.as_str()).map(|&i| &p.vertices[i]))
                        .map(|o| (o.x, o.y)),
                }
            })
            .collect();
        let pairs: Vec<(usize, usize)> = self.edges.iter().map(|e| (e.a, e.b)).collect();
        for (v, (x, y)) in self
            .vertices
            .iter_mut()
            .zip(layout(&items, &pairs, self.area))
        {
            v.x = x;
            v.y = y;
        }
    }

    pub fn index(&self, id: &str) -> Option<usize> {
        self.vertices.iter().position(|v| v.id == id)
    }

    /// Vertex index by id, built once for many lookups (`index` is a scan).
    fn index_map(&self) -> std::collections::HashMap<&str, usize> {
        self.vertices
            .iter()
            .enumerate()
            .map(|(i, v)| (v.id.as_str(), i))
            .collect()
    }

    /// Edges at a vertex.
    pub fn edges_of(&self, v: usize) -> Vec<&Edge> {
        self.edges.iter().filter(|e| e.a == v || e.b == v).collect()
    }

    /// Put the vertices the user moved where they left them (positions by
    /// node id, in the same 0..1 units as the layout).
    pub fn pin(&mut self, pinned: &BTreeMap<String, (f32, f32)>) {
        for v in &mut self.vertices {
            if let Some(&(x, y)) = pinned.get(&v.id) {
                v.x = x;
                v.y = y;
            }
        }
    }

    /// What a selected vertex and a selected circuit (node ids along its
    /// path) bring into focus: per vertex and per edge. The selected vertex,
    /// its edges and their other ends; the circuit's edges and nodes.
    /// Nothing is in focus when nothing is selected.
    pub fn focus(&self, selected: Option<usize>, path: &[String]) -> (Vec<bool>, Vec<bool>) {
        let mut vs = vec![false; self.vertices.len()];
        let mut es = vec![false; self.edges.len()];
        if let Some(v) = selected.filter(|&v| v < vs.len()) {
            vs[v] = true;
        }
        for (k, e) in self.edges.iter().enumerate() {
            let (a, b) = (&self.vertices[e.a].id, &self.vertices[e.b].id);
            let on_path = path
                .windows(2)
                .any(|w| (&w[0] == a && &w[1] == b) || (&w[0] == b && &w[1] == a));
            if on_path || selected.is_some_and(|v| e.a == v || e.b == v) {
                es[k] = true;
                vs[e.a] = true;
                vs[e.b] = true;
            }
        }
        for (i, v) in self.vertices.iter().enumerate() {
            if path.contains(&v.id) {
                vs[i] = true;
            }
        }
        (vs, es)
    }

    /// The edge between two vertices, if any.
    pub fn edge(&self, a: usize, b: usize) -> Option<&Edge> {
        self.edges
            .iter()
            .find(|e| (e.a, e.b) == (a.min(b), a.max(b)))
    }
}

/// How the graph is shown in its drawing area: zoomed by `zoom` around the
/// area's center, then panned by `pan`. Everything is in fractions of the
/// area's width and height, so drawing doesn't depend on its pixel size;
/// graph positions are the layout's 0..1 coordinates.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Viewport {
    pub pan: (f32, f32),
    pub zoom: f32,
}

impl Default for Viewport {
    fn default() -> Self {
        Viewport {
            pan: (0.0, 0.0),
            zoom: 1.0,
        }
    }
}

impl Viewport {
    pub const MIN_ZOOM: f32 = 0.2;
    pub const MAX_ZOOM: f32 = 8.0;

    /// A graph position to a position in the area (0..1 is visible).
    pub fn to_view(&self, p: (f32, f32)) -> (f32, f32) {
        (
            0.5 + self.pan.0 + (p.0 - 0.5) * self.zoom,
            0.5 + self.pan.1 + (p.1 - 0.5) * self.zoom,
        )
    }

    /// A position in the area to a graph position.
    pub fn to_graph(&self, v: (f32, f32)) -> (f32, f32) {
        (
            0.5 + (v.0 - 0.5 - self.pan.0) / self.zoom,
            0.5 + (v.1 - 0.5 - self.pan.1) / self.zoom,
        )
    }

    pub fn pan_by(&mut self, dx: f32, dy: f32) {
        self.pan.0 += dx;
        self.pan.1 += dy;
    }

    /// Zoom by `factor`, keeping the graph point at `at` (a position in the
    /// area) where it is.
    pub fn zoom_at(&mut self, factor: f32, at: (f32, f32)) {
        if !factor.is_finite() || factor <= 0.0 {
            return;
        }
        let g = self.to_graph(at);
        self.zoom = (self.zoom * factor).clamp(Self::MIN_ZOOM, Self::MAX_ZOOM);
        let v = self.to_view(g);
        self.pan_by(at.0 - v.0, at.1 - v.1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{TopoNode, Topology};
    use layout::tests::items;

    fn snap() -> Snapshot {
        let node = |id: &str, name: &str, relay: bool| TopoNode {
            id: id.into(),
            name: name.into(),
            relay,
            data: true,
            ..Default::default()
        };
        let edge = |a: &str, b: &str, kind: &str, rtt: f64, age: u64| TopoEdge {
            a: a.into(),
            b: b.into(),
            kind: kind.into(),
            rtt_ms: rtt,
            age_s: age,
            ..Default::default()
        };
        Snapshot {
            topology: Ok(Topology {
                me: "b".into(),
                nodes: vec![
                    node("c", "node-03", false),
                    node("a", "ctl-01", true),
                    node("b", "node-02", false),
                    node("d", "node-04", false),
                ],
                edges: vec![
                    edge("a", "c", "attachment", 3.0, 9),
                    edge("c", "a", "attachment", 2.0, 1),
                    edge("b", "a", "hop", 1.0, 50),
                    edge("a", "b", "relay", 5.0, 0),
                    edge("b", "zz", "hop", 1.0, 0),
                    edge("d", "d", "hop", 1.0, 0),
                ],
            }),
            ..Default::default()
        }
    }

    #[test]
    fn labels_carry_the_version() {
        let mut v = Graph::from_snapshot(&snap()).vertices[0].clone();
        v.name = "relay-1".into();
        v.me = false;
        v.software = None;
        assert_eq!(v.label(), "relay-1");
        v.software = Some("0.7.1".into());
        v.me = true;
        assert_eq!(v.label(), "relay-1 (this) · 0.7.1");
        v.me = false;
        v.software = Some("0.6.1".into());
        v.outdated = true;
        assert_eq!(v.label(), "relay-1 · 0.6.1 outdated");
    }

    #[test]
    fn merges_reports_of_a_link() {
        let g = Graph::from_snapshot(&snap());
        let names: Vec<&str> = g.vertices.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(
            names,
            ["ctl-01", "node-02", "node-03", "node-04"],
            "core first"
        );
        assert!(g.vertices[1].me);
        assert_eq!(g.edges.len(), 2, "unknown nodes and self-loops are dropped");
        let ac = g.edge(2, 0).unwrap();
        assert_eq!(ac.reports.len(), 2);
        assert_eq!(ac.rtt_ms(), 2.0, "freshest report");
        assert!(!ac.mine());
        let ab = g.edge(0, 1).unwrap();
        assert!(ab.mine());
        assert_eq!(ab.rtt_ms(), 1.0, "own measurement wins");
        assert_eq!(ab.other(0), 1);
        assert_eq!(g.edges_of(0).len(), 2);
        assert!(g.edges_of(3).is_empty());
    }

    #[test]
    fn layout_is_deterministic_and_inside() {
        let a = Graph::from_snapshot(&snap());
        let b = Graph::from_snapshot(&snap());
        assert_eq!(a, b);
        for v in &a.vertices {
            assert!(
                (0.0..=1.0).contains(&v.x) && (0.0..=1.0).contains(&v.y),
                "{v:?}"
            );
        }
        // Nodes don't sit on top of each other.
        for (i, p) in a.vertices.iter().enumerate() {
            for q in &a.vertices[i + 1..] {
                let d = ((p.x - q.x).powi(2) + (p.y - q.y).powi(2)).sqrt();
                assert!(d > 0.05, "{} and {} overlap", p.name, q.name);
            }
        }
        assert_eq!(layout(&[], &[], (800.0, 420.0)), vec![]);
        let one = layout(&items(&[("x", true)]), &[], (800.0, 420.0));
        assert_eq!(one[0].0, 0.5, "a lone node in the middle");
        assert!((one[0].1 - 0.5).abs() < 0.05, "{one:?}");
    }

    #[test]
    fn a_refresh_never_moves_a_node() {
        let s = snap();
        let a = Graph::build(&s, (800.0, 420.0), None);
        let b = Graph::build(&s, (800.0, 420.0), Some(&a));
        assert_eq!(a, b, "same graph, same picture");
        let at = |g: &Graph, id: &str| {
            let v = &g.vertices[g.index(id).expect("vertex")];
            (v.x, v.y)
        };
        // A link comes, another goes, a label changes, the area is resized:
        // nobody moves.
        let mut s2 = s;
        if let Ok(t) = &mut s2.topology {
            t.edges.push(TopoEdge {
                a: "c".into(),
                b: "d".into(),
                kind: "attachment".into(),
                ..Default::default()
            });
            t.edges
                .retain(|e| (e.a.as_str(), e.b.as_str()) != ("b", "a"));
            t.edges
                .retain(|e| (e.a.as_str(), e.b.as_str()) != ("a", "b"));
            t.nodes[0].software = Some("0.9.0".into());
        }
        let c = Graph::build(&s2, (1200.0, 300.0), Some(&a));
        let ix = |id: &str| c.index(id).expect("vertex");
        assert!(c.edge(ix("c"), ix("d")).is_some() && c.edge(ix("a"), ix("b")).is_none());
        assert_eq!(c.area, a.area, "the area the picture was made for");
        for v in &a.vertices {
            assert_eq!(at(&c, &v.id), (v.x, v.y), "{} moved", v.name);
        }
        // A node going away leaves the others where they were.
        if let Ok(t) = &mut s2.topology {
            t.nodes.retain(|n| n.id != "d");
        }
        let d = Graph::build(&s2, (800.0, 420.0), Some(&c));
        assert_eq!(d.vertices.len(), a.vertices.len() - 1);
        for v in &d.vertices {
            assert_eq!((v.x, v.y), at(&a, &v.id), "{} moved", v.name);
        }
        // Nothing left of the old picture: laid out afresh.
        let other = Snapshot {
            topology: Ok(Topology {
                nodes: vec![TopoNode {
                    id: "x".into(),
                    name: "other".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut e = Graph::shape(&other, (800.0, 420.0));
        assert!(!e.keep(Some(&a)));
    }

    #[test]
    fn new_nodes_go_next_to_their_neighbors_into_free_room() {
        let area = (800.0, 420.0);
        let s = snap();
        let a = Graph::build(&s, area, None);
        let mut s2 = s;
        if let Ok(t) = &mut s2.topology {
            let link = |x: &str, y: &str| TopoEdge {
                a: x.into(),
                b: y.into(),
                kind: "attachment".into(),
                ..Default::default()
            };
            for (id, name) in [
                ("e", "node-05"),
                ("f", "node-06"),
                ("g", "node-07"),
                ("h", "node-08"),
                ("i", "node-09"),
            ] {
                t.nodes.push(TopoNode {
                    id: id.into(),
                    name: name.into(),
                    data: true,
                    software: Some("0.8.0".into()),
                    ..Default::default()
                });
            }
            // Three attached to the relay, one to two nodes (one of them
            // new), one alone.
            for x in ["e", "f", "g"] {
                t.edges.push(link(x, "a"));
            }
            t.edges.push(link("h", "c"));
            t.edges.push(link("h", "e"));
        }
        let g = Graph::build(&s2, area, Some(&a));
        assert_eq!(g.vertices.len(), a.vertices.len() + 5);
        for v in &a.vertices {
            let n = &g.vertices[g.index(&v.id).expect("kept")];
            assert_eq!((n.x, n.y), (v.x, v.y), "{} moved", v.name);
        }
        let px = |v: &Vertex| (f64::from(v.x * area.0), f64::from(v.y * area.1));
        let rect = |v: &Vertex| {
            let (w, h, circle) = vertex_box(&v.label(), v.infra());
            let it = Item {
                w,
                h,
                circle,
                start: None,
            };
            let (l, t, r, b) = it.extent();
            let p = px(v);
            (p.0 + l, p.1 + t, p.0 + r, p.1 + b)
        };
        let new = ["e", "f", "g", "h", "i"];
        for id in new {
            let v = &g.vertices[g.index(id).expect("placed")];
            let r = rect(v);
            assert!(
                r.0 >= 0.0 && r.1 >= 0.0 && r.2 <= f64::from(area.0) && r.3 <= f64::from(area.1),
                "{} inside the area: {r:?}",
                v.name
            );
            for o in g.vertices.iter().filter(|o| o.id != v.id) {
                let q = rect(o);
                let overlap = r.2.min(q.2) > r.0.max(q.0) && r.3.min(q.3) > r.1.max(q.1);
                assert!(!overlap, "{} overlaps {}", v.name, o.name);
            }
            for e in g.edges_of(g.index(id).expect("placed")) {
                let (p, q) = (px(&g.vertices[e.a]), px(&g.vertices[e.b]));
                let len = (p.0 - q.0).hypot(p.1 - q.1);
                assert!(len < 320.0, "{}: a link of {len} px", v.name);
            }
        }
        // The same input, the same picture.
        assert_eq!(g, Graph::build(&s2, area, Some(&a)));
    }

    #[test]
    fn viewport_maps_both_ways_and_zooms_around_the_cursor() {
        let close =
            |a: (f32, f32), b: (f32, f32)| (a.0 - b.0).abs() < 1e-5 && (a.1 - b.1).abs() < 1e-5;
        let mut v = Viewport::default();
        assert!(
            close(v.to_view((0.2, 0.7)), (0.2, 0.7)),
            "identity at first"
        );
        v.pan_by(0.1, -0.05);
        for p in [(0.1, 0.9), (0.5, 0.5), (1.3, -0.2)] {
            assert!(close(v.to_graph(v.to_view(p)), p));
        }
        // The point under the cursor stays put while zooming.
        let at = (0.75, 0.25);
        let g = v.to_graph(at);
        v.zoom_at(2.0, at);
        assert_eq!(v.zoom, 2.0);
        assert!(close(v.to_view(g), at));
        assert!(close(v.to_graph(v.to_view((0.2, 0.7))), (0.2, 0.7)));
        // Zoom is bounded; nonsense factors are ignored.
        v.zoom_at(1000.0, at);
        assert_eq!(v.zoom, Viewport::MAX_ZOOM);
        v.zoom_at(1e-6, at);
        assert_eq!(v.zoom, Viewport::MIN_ZOOM);
        let before = v;
        v.zoom_at(f32::NAN, at);
        v.zoom_at(-1.0, at);
        assert_eq!(v, before);
    }

    #[test]
    fn pinned_vertices_stay_where_they_were_put() {
        let mut g = Graph::from_snapshot(&snap());
        let free = (g.vertices[1].x, g.vertices[1].y);
        let pinned = BTreeMap::from([
            ("c".to_string(), (0.9, 0.1)),
            ("zz".to_string(), (0.0, 0.0)),
        ]);
        g.pin(&pinned);
        let c = g.index("c").unwrap();
        assert_eq!((g.vertices[c].x, g.vertices[c].y), (0.9, 0.1));
        assert_eq!(
            (g.vertices[1].x, g.vertices[1].y),
            free,
            "others keep the layout"
        );
    }

    #[test]
    fn selection_brings_nodes_and_links_into_focus() {
        let g = Graph::from_snapshot(&snap());
        // ctl-01 (0) – node-02 (1), ctl-01 – node-03 (2); node-04 (3) alone.
        let (vs, es) = g.focus(None, &[]);
        assert!(
            !vs.contains(&true) && !es.contains(&true),
            "nothing selected"
        );
        let (vs, es) = g.focus(Some(1), &[]);
        assert_eq!(vs, [true, true, false, false], "node-02 and its neighbor");
        assert_eq!(es.iter().filter(|e| **e).count(), 1);
        let path = ["b".to_string(), "a".to_string(), "c".to_string()];
        let (vs, es) = g.focus(None, &path);
        assert_eq!(vs, [true, true, true, false], "the circuit's nodes");
        assert!(es.iter().all(|e| *e), "and its links");
        // Both: the union.
        let (vs, _) = g.focus(Some(3), &path);
        assert_eq!(vs, [true, true, true, true]);
    }

    #[test]
    fn falls_back_to_the_node_list() {
        let s = Snapshot {
            nodes: vec![crate::model::Node {
                id: "a".into(),
                name: "x".into(),
                valid: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        let g = Graph::from_snapshot(&s);
        assert_eq!(g.vertices.len(), 1);
        assert!(g.edges.is_empty());
    }
}
