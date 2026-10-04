//! The network graph for the Nodes tab: one vertex per node, one edge per
//! pair of nodes that report a link (§11.4), laid out deterministically with
//! a force-directed layout. Positions are fractions of the drawing area.

use crate::model::{Load, Snapshot, TopoEdge};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub struct Vertex {
    pub id: String,
    pub name: String,
    pub ips: Vec<String>,
    pub relay: bool,
    pub control: bool,
    pub me: bool,
    pub load: Option<Load>,
    /// Position in 0..1 of the drawing area's width and height.
    pub x: f32,
    pub y: f32,
}

impl Vertex {
    /// Relays and controllers form the network's core.
    pub fn infra(&self) -> bool {
        self.relay || self.control
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
        self.best().map(|r| r.rtt_ms).unwrap_or(0.0)
    }

    pub fn loss(&self) -> f64 {
        self.best().map(|r| r.loss).unwrap_or(0.0)
    }

    pub fn other(&self, v: usize) -> usize {
        if self.a == v { self.b } else { self.a }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Graph {
    pub vertices: Vec<Vertex>,
    pub edges: Vec<Edge>,
}

impl Graph {
    /// Build the graph from a snapshot's topology, falling back to the node
    /// list (no edges) for an agent without the `topology` command.
    pub fn from_snapshot(s: &Snapshot) -> Graph {
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
        let pairs: Vec<(usize, usize)> = edges.iter().map(|e| (e.a, e.b)).collect();
        let infra: Vec<bool> = vertices.iter().map(Vertex::infra).collect();
        for (v, (x, y)) in vertices.iter_mut().zip(layout(&infra, &pairs)) {
            v.x = x;
            v.y = y;
        }
        Graph { vertices, edges }
    }

    pub fn index(&self, id: &str) -> Option<usize> {
        self.vertices.iter().position(|v| v.id == id)
    }

    /// Edges at a vertex.
    pub fn edges_of(&self, v: usize) -> Vec<&Edge> {
        self.edges.iter().filter(|e| e.a == v || e.b == v).collect()
    }

    /// The edge between two vertices, if any.
    pub fn edge(&self, a: usize, b: usize) -> Option<&Edge> {
        self.edges
            .iter()
            .find(|e| (e.a, e.b) == (a.min(b), a.max(b)))
    }
}

/// Force-directed layout (Fruchterman–Reingold) from a fixed start: the
/// core on an inner circle, other nodes on an outer one, so the same graph
/// always gets the same picture. Returns positions in 0.06..0.94.
pub fn layout(infra: &[bool], edges: &[(usize, usize)]) -> Vec<(f32, f32)> {
    let n = infra.len();
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![(0.5, 0.5)];
    }
    let cores = infra.iter().filter(|c| **c).count();
    let (mut ci, mut oi) = (0usize, 0usize);
    let mut pos: Vec<(f32, f32)> = infra
        .iter()
        .map(|&core| {
            let (i, count, r) = if core {
                ci += 1;
                (ci - 1, cores, if cores == n { 0.35 } else { 0.18 })
            } else {
                oi += 1;
                (oi - 1, n - cores, 0.4)
            };
            let a = std::f32::consts::TAU * i as f32 / count.max(1) as f32 + 0.3;
            (0.5 + r * a.cos(), 0.5 + r * a.sin())
        })
        .collect();
    let k = (1.0 / n as f32).sqrt() * 0.75;
    let mut temp = 0.1f32;
    for _ in 0..300 {
        let mut disp = vec![(0.0f32, 0.0f32); n];
        for i in 0..n {
            for j in (i + 1)..n {
                let (dx, dy) = (pos[i].0 - pos[j].0, pos[i].1 - pos[j].1);
                let d = (dx * dx + dy * dy).sqrt().max(0.01);
                let f = k * k / d;
                disp[i].0 += dx / d * f;
                disp[i].1 += dy / d * f;
                disp[j].0 -= dx / d * f;
                disp[j].1 -= dy / d * f;
            }
        }
        for &(a, b) in edges {
            if a >= n || b >= n {
                continue;
            }
            let (dx, dy) = (pos[a].0 - pos[b].0, pos[a].1 - pos[b].1);
            let d = (dx * dx + dy * dy).sqrt().max(0.01);
            let f = d * d / k;
            disp[a].0 -= dx / d * f;
            disp[a].1 -= dy / d * f;
            disp[b].0 += dx / d * f;
            disp[b].1 += dy / d * f;
        }
        for (p, d) in pos.iter_mut().zip(&disp) {
            // A little gravity keeps separate components on screen.
            let (gx, gy) = ((0.5 - p.0) * 0.05, (0.5 - p.1) * 0.05);
            let (dx, dy) = (d.0 + gx, d.1 + gy);
            let len = (dx * dx + dy * dy).sqrt();
            if len > 0.0 {
                p.0 += dx / len * len.min(temp);
                p.1 += dy / len * len.min(temp);
            }
        }
        temp *= 0.985;
    }
    // Fit into the drawing area, keeping the aspect ratio.
    let (mut x0, mut y0, mut x1, mut y1) = (f32::MAX, f32::MAX, f32::MIN, f32::MIN);
    for p in &pos {
        x0 = x0.min(p.0);
        y0 = y0.min(p.1);
        x1 = x1.max(p.0);
        y1 = y1.max(p.1);
    }
    let span = (x1 - x0).max(y1 - y0).max(1e-3);
    let (cx, cy) = ((x0 + x1) / 2.0, (y0 + y1) / 2.0);
    pos.iter()
        .map(|p| {
            (
                0.5 + (p.0 - cx) / span * 0.88,
                0.5 + (p.1 - cy) / span * 0.88,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{TopoNode, Topology};

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
        assert_eq!(layout(&[], &[]), vec![]);
        assert_eq!(layout(&[true], &[]), vec![(0.5, 0.5)]);
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
