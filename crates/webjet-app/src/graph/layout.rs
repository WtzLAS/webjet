//! Laying the graph out: stress majorization, a cost of crossings and
//! overlaps, annealing or local search, then packing the components (see
//! [`layout`]). Pure and deterministic; positions are fractions of the area.

use std::collections::BTreeMap;

/// The drawing area's size in pixels before the app has measured it.
pub const DEFAULT_AREA: (f32, f32) = (800.0, 420.0);

/// Width of a label character (`text_xs`) in pixels, a little more than the
/// average (measured: 7.3), so the layout never thinks a label narrower than it is.
const CHAR_W: f32 = 7.8;
/// Height of a vertex label line in pixels.
const LABEL_H: f32 = 16.0;

/// The circle-and-label box the Nodes tab draws for a vertex, in pixels:
/// (width, height, circle diameter). The circle is centered on the vertex's
/// position and the label hangs below it.
pub fn vertex_box(label: &str, infra: bool) -> (f32, f32, f32) {
    let circle = if infra { 26.0 } else { 20.0 };
    let w = (label.chars().count() as f32 * CHAR_W + 8.0).max(circle);
    (w, circle + LABEL_H, circle)
}

pub(super) type P = (f64, f64);

/// One vertex for `layout`: its box (see `vertex_box`) and, for a warm
/// start, where it was (0..1 fractions of the area).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Item {
    pub w: f32,
    pub h: f32,
    pub circle: f32,
    pub start: Option<(f32, f32)>,
}

impl Item {
    /// Box edges relative to the vertex position: (left, top, right, bottom).
    pub(super) fn extent(&self) -> (f64, f64, f64, f64) {
        let (w, h, c) = (f64::from(self.w), f64::from(self.h), f64::from(self.circle));
        (-w / 2.0, -c / 2.0, w / 2.0, h - c / 2.0)
    }
}

/// Lay the graph out for a drawing area of `area` pixels. Returns positions
/// in fractions of the area (inside 0..1).
///
/// 1. Each connected component is laid out on its own, so lone nodes don't
///    push the rest into a corner. Stress majorization (Gansner, Koren and
///    North) places nodes so that their distances follow the number of hops
///    between them, from several starts (rings around the best connected
///    nodes, scattered pictures), each turned so its long side lies along
///    the area's.
/// 2. The `Cost` of a picture counts edge crossings, edges through another
///    node's label, overlapping labels, edges leaving a node at nearly the
///    same angle, and stress. Small components are annealed from the three
///    cheapest starts, larger ones get a local search (`improve`); the
///    cheapest result wins.
/// 3. With `start` positions for most of a component it continues from
///    those instead (local search only), unless that ends up much worse
///    than starting over, so a changed link doesn't reshuffle the picture.
/// 4. Overlapping label boxes are pushed apart, components are packed in
///    rows, largest first, and the whole is scaled to fit the area. Labels
///    keep their size when the picture shrinks, so a picture that doesn't
///    fit is shrunk and searched again at that scale.
///
/// The same input always gives the same picture.
pub fn layout(items: &[Item], edges: &[(usize, usize)], area: (f32, f32)) -> Vec<(f32, f32)> {
    let n = items.len();
    if n == 0 {
        return Vec::new();
    }
    let (aw, ah) = (f64::from(area.0.max(100.0)), f64::from(area.1.max(100.0)));
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    for &(a, b) in edges {
        if a < n && b < n && a != b && !adj[a].contains(&b) {
            adj[a].push(b);
            adj[b].push(a);
        }
    }
    for l in &mut adj {
        l.sort_unstable();
    }
    // Ideal edge length: room for a typical label beside another.
    let mut widths: Vec<f64> = items.iter().map(|i| f64::from(i.w)).collect();
    widths.sort_by(f64::total_cmp);
    let ideal = (widths[widths.len() / 2] + 50.0).clamp(120.0, 260.0);
    let mut parts: Vec<Part> = components(&adj)
        .into_iter()
        .map(|c| Part::new(c, &adj, items, ideal, (aw, ah)))
        .collect();
    let all: Vec<usize> = (0..n).collect();
    let mut pos = vec![(0.0, 0.0); n];
    for round in 0..4 {
        let boxes: Vec<[f64; 4]> = parts.iter().map(|p| bbox(&p.vs, &p.pos, items)).collect();
        let offsets = pack(&boxes, aw / ah, 40.0);
        for (p, off) in parts.iter().zip(&offsets) {
            for (&v, q) in p.vs.iter().zip(&p.pos) {
                pos[v] = (q.0 + off.0, q.1 + off.1);
            }
        }
        let [x0, y0, x1, y1] = bbox(&all, &pos, items);
        let fit = ((aw - 24.0) / (x1 - x0).max(1.0)).min((ah - 24.0) / (y1 - y0).max(1.0));
        let (cx, cy) = (f64::midpoint(x0, x1), f64::midpoint(y0, y1));
        if fit >= 0.97 || round == 3 {
            // Spread a small picture out a little (labels keep their size,
            // so that only adds room); shrink one that still doesn't fit.
            let k = fit.min(1.25);
            return pos
                .iter()
                .map(|p| {
                    (
                        (0.5 + (p.0 - cx) * k / aw) as f32,
                        (0.5 + (p.1 - cy) * k / ah) as f32,
                    )
                })
                .collect();
        }
        // Too large: bring the vertices closer along the axis that is too
        // long (labels keep their size), and let the search and the
        // separation work at that scale.
        let kx = ((aw - 24.0) / (x1 - x0).max(1.0)).min(1.0);
        let ky = ((ah - 24.0) / (y1 - y0).max(1.0)).min(1.0);
        for p in &mut parts {
            p.shrink(kx, ky);
        }
    }
    // Not reached: the last round returns.
    vec![(0.5, 0.5); n]
}

/// A connected component being laid out, in local indices.
struct Part {
    /// Its vertices.
    vs: Vec<usize>,
    adj: Vec<Vec<usize>>,
    /// Wanted distances: hop counts times the edge length.
    d: Vec<Vec<f64>>,
    items: Vec<Item>,
    ideal: f64,
    /// Positions in pixels, around the component's own origin.
    pos: Vec<P>,
    /// The drawing area's width over its height.
    aspect: f64,
}

impl Part {
    /// Lay the component out, from scratch or from where it was.
    fn new(
        vs: Vec<usize>,
        adj: &[Vec<usize>],
        items: &[Item],
        ideal: f64,
        area: (f64, f64),
    ) -> Part {
        let local: BTreeMap<usize, usize> = vs.iter().enumerate().map(|(i, &v)| (v, i)).collect();
        let ladj: Vec<Vec<usize>> = vs
            .iter()
            .map(|&v| {
                adj[v]
                    .iter()
                    .filter_map(|u| local.get(u).copied())
                    .collect()
            })
            .collect();
        let d: Vec<Vec<f64>> = hops(&ladj)
            .into_iter()
            .map(|row| row.into_iter().map(|h| h * ideal).collect())
            .collect();
        let lit: Vec<Item> = vs.iter().map(|&v| items[v]).collect();
        let mut part = Part {
            pos: vec![(0.0, 0.0); vs.len()],
            vs,
            adj: ladj,
            d,
            items: lit,
            ideal,
            aspect: area.0 / area.1,
        };
        let m = part.vs.len();
        if m == 1 {
            return part;
        }
        let known = part.items.iter().filter(|i| i.start.is_some()).count();
        let fresh = part.fresh(area);
        part.pos = if known * 2 > m {
            // Continue from the old picture, unless that ends up much worse
            // than starting over (a change it can't absorb): a picture that
            // stays put matters more than a slightly better one.
            let warm = part.warm(area);
            let looks = |p: &Part, pos: &[P]| Cost::new(&p.adj, &p.d, &p.items).looks(pos);
            if looks(&part, &warm.pos) <= looks(&part, &fresh) * 1.5 + CROSSING_SMALL {
                part.d = warm.d;
                part.ideal = warm.ideal;
                warm.pos
            } else {
                fresh
            }
        } else {
            fresh
        };
        let all: Vec<usize> = (0..m).collect();
        separate(&all, &mut part.pos, &part.items, area.0 / area.1);
        part
    }

    /// The old picture (in pixels of the new area), its distances wanted
    /// at the scale it has, settled in with short moves.
    fn warm(&self, area: (f64, f64)) -> Part {
        let mut pos = warm_start(&self.items, &self.adj, area, self.ideal);
        // The old picture was scaled to fit its area and labels keep their
        // size, so keep its scale: the wanted distances follow it.
        let (mut sum, mut count) = (0.0, 0);
        for (a, l) in self.adj.iter().enumerate() {
            for &b in l {
                if a < b {
                    sum += (pos[a].0 - pos[b].0).hypot(pos[a].1 - pos[b].1);
                    count += 1;
                }
            }
        }
        let k = if count > 0 && sum > 1.0 {
            (sum / count as f64 / self.ideal).clamp(0.3, 3.0)
        } else {
            1.0
        };
        let d: Vec<Vec<f64>> = self
            .d
            .iter()
            .map(|r| r.iter().map(|x| x * k).collect())
            .collect();
        let ideal = self.ideal * k;
        let cost = Cost::new(&self.adj, &d, &self.items);
        // No stress majorization here: it ignores crossings and labels and
        // would undo what the old layout found. Only moves that make the
        // whole picture better.
        improve(&mut pos, &cost, ideal, SEARCH_BUDGET / 4);
        Part {
            vs: self.vs.clone(),
            adj: self.adj.clone(),
            d,
            items: self.items.clone(),
            ideal,
            pos,
            aspect: self.aspect,
        }
    }

    /// A layout from scratch: stress majorization from several starts, then
    /// annealing (small components) or the local search from the best.
    fn fresh(&self, area: (f64, f64)) -> Vec<P> {
        let ideal = self.ideal;
        let cost = &Cost::new(&self.adj, &self.d, &self.items);
        let mut cands: Vec<(f64, Vec<P>)> = starts(&self.adj, ideal)
            .into_iter()
            .map(|mut p| {
                stress_majorize(&mut p, &self.d, 300);
                turn_and_stretch(&mut p, area.0 / area.1);
                (cost.total(&p), p)
            })
            .collect();
        cands.sort_by(|a, b| a.0.total_cmp(&b.0));
        // The search finds a local minimum, which depends on the start: a
        // small graph is annealed from the three best starts, a medium one
        // searched from every start, a large one only from the best.
        let each = SEARCH_BUDGET / cands.len().max(1);
        if self.vs.len() <= ANNEAL_MAX {
            cands.truncate(3);
            for (i, c) in cands.iter_mut().enumerate() {
                anneal(&mut c.1, cost, ideal, ANNEAL_STEPS, i as u64 + 7, 20.0, 2.0);
                improve(&mut c.1, cost, ideal, SEARCH_BUDGET / 3);
                c.0 = cost.total(&c.1);
            }
            cands.sort_by(|a, b| a.0.total_cmp(&b.0));
        } else if cost.pass_work() * 3 <= each {
            for c in &mut cands {
                improve(&mut c.1, cost, ideal, each);
                c.0 = cost.total(&c.1);
            }
            cands.sort_by(|a, b| a.0.total_cmp(&b.0));
        } else if let Some(c) = cands.first_mut() {
            improve(&mut c.1, cost, ideal, SEARCH_BUDGET);
        }
        cands.into_iter().next().map(|c| c.1).unwrap_or_default()
    }

    fn refine(&mut self, budget: usize) {
        let cost = Cost::new(&self.adj, &self.d, &self.items);
        if self.vs.len() <= ANNEAL_MAX {
            // A cooler anneal with short jumps: settle in nearby, don't
            // start over (or spread out again).
            anneal(
                &mut self.pos,
                &cost,
                self.ideal,
                ANNEAL_STEPS / 2,
                3,
                3.0,
                0.3,
            );
        }
        improve(&mut self.pos, &cost, self.ideal, budget);
        let all: Vec<usize> = (0..self.vs.len()).collect();
        separate(&all, &mut self.pos, &self.items, self.aspect);
    }

    /// Scale the picture by `kx` and `ky` (≤ 1) and the distances wanted
    /// by their mean, then refine at that scale.
    fn shrink(&mut self, kx: f64, ky: f64) {
        if self.vs.len() < 2 {
            return;
        }
        for p in &mut self.pos {
            *p = (p.0 * kx, p.1 * ky);
        }
        let k = (kx * ky).sqrt();
        for row in &mut self.d {
            for x in row {
                *x *= k;
            }
        }
        self.ideal *= k;
        self.refine(SEARCH_BUDGET / 4);
    }
}

/// Connected components, each in increasing vertex order, ordered by their
/// first vertex.
fn components(adj: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let mut seen = vec![false; adj.len()];
    let mut out = Vec::new();
    for s in 0..adj.len() {
        if seen[s] {
            continue;
        }
        seen[s] = true;
        let mut c = vec![s];
        let mut k = 0;
        while k < c.len() {
            for &u in &adj[c[k]] {
                if !seen[u] {
                    seen[u] = true;
                    c.push(u);
                }
            }
            k += 1;
        }
        c.sort_unstable();
        out.push(c);
    }
    out
}

/// Hop counts between all vertices of a component (local indices).
fn hops(adj: &[Vec<usize>]) -> Vec<Vec<f64>> {
    let m = adj.len();
    (0..m)
        .map(|s| {
            let mut d = vec![f64::INFINITY; m];
            d[s] = 0.0;
            let mut q = std::collections::VecDeque::from([s]);
            while let Some(v) = q.pop_front() {
                for &u in &adj[v] {
                    if d[u].is_infinite() {
                        d[u] = d[v] + 1.0;
                        q.push_back(u);
                    }
                }
            }
            // Connected, but never leave an infinity in the sums.
            d.iter()
                .map(|x| if x.is_finite() { *x } else { m as f64 })
                .collect()
        })
        .collect()
}

/// Components up to this size are annealed.
const ANNEAL_MAX: usize = 16;
/// Annealing steps per start.
const ANNEAL_STEPS: usize = 15_000;

/// Edges at a vertex closer than this (radians, 20°) start to cost.
const MIN_ANGLE: f64 = 0.35;

/// Cost of an edge crossing in a small component (see `Cost::crossing`).
const CROSSING_SMALL: f64 = 40.0;

/// Work the local search may do per component (well under a second in a
/// release build).
const SEARCH_BUDGET: usize = 12_000_000;

/// Continue from where the vertices were; new ones go between their placed
/// neighbors, a little apart.
fn warm_start(items: &[Item], adj: &[Vec<usize>], area: (f64, f64), ideal: f64) -> Vec<P> {
    let mut pos: Vec<Option<P>> = items
        .iter()
        .map(|i| {
            i.start
                .map(|(x, y)| ((f64::from(x) - 0.5) * area.0, (f64::from(y) - 0.5) * area.1))
        })
        .collect();
    let known: Vec<P> = pos.iter().flatten().copied().collect();
    let center = known.iter().fold((0.0, 0.0), |a, p| (a.0 + p.0, a.1 + p.1));
    let center = (
        center.0 / known.len().max(1) as f64,
        center.1 / known.len().max(1) as f64,
    );
    for v in 0..items.len() {
        if pos[v].is_some() {
            continue;
        }
        let near: Vec<P> = adj[v].iter().filter_map(|&u| pos[u]).collect();
        let base = if near.is_empty() {
            center
        } else {
            let s = near.iter().fold((0.0, 0.0), |a, p| (a.0 + p.0, a.1 + p.1));
            (s.0 / near.len() as f64, s.1 / near.len() as f64)
        };
        let a = v as f64 * 2.399_963;
        pos[v] = Some((
            base.0 + ideal * 0.5 * a.cos(),
            base.1 + ideal * 0.5 * a.sin(),
        ));
    }
    pos.into_iter().map(|p| p.unwrap_or(center)).collect()
}

/// A fresh start: `root` in the middle, the others on
/// rings by their hop count from it, each ring ordered like the ring
/// inside it so that edges between rings start out uncrossed.
fn rings(adj: &[Vec<usize>], root: usize, ideal: f64) -> Vec<P> {
    let m = adj.len();
    let mut level = vec![usize::MAX; m];
    let mut angle = vec![0.0f64; m];
    level[root] = 0;
    let mut ring = vec![root];
    let mut pos = vec![(0.0, 0.0); m];
    let mut depth = 0;
    while !ring.is_empty() {
        depth += 1;
        // Next ring: unvisited neighbors, keyed by the angle of the parent.
        let mut next: Vec<(f64, usize)> = Vec::new();
        for &v in &ring {
            for &u in &adj[v] {
                if level[u] == usize::MAX {
                    level[u] = depth;
                    next.push((angle[v], u));
                }
            }
        }
        next.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        let k = next.len();
        for (i, &(_, u)) in next.iter().enumerate() {
            let a = std::f64::consts::TAU * i as f64 / k.max(1) as f64 + 0.3 * depth as f64;
            angle[u] = a;
            let r = ideal * depth as f64;
            pos[u] = (r * a.cos(), r * a.sin());
        }
        ring = next.into_iter().map(|(_, u)| u).collect();
    }
    pos
}

/// Stress majorization: move every vertex to where its distances to the
/// others best match `d` (weights 1/d², so near neighbors matter most).
fn stress_majorize(pos: &mut [P], d: &[Vec<f64>], iterations: usize) {
    let m = pos.len();
    for _ in 0..iterations {
        let mut next = pos.to_vec();
        let mut moved: f64 = 0.0;
        for i in 0..m {
            let (mut sx, mut sy, mut sw) = (0.0, 0.0, 0.0);
            for j in 0..m {
                if i == j {
                    continue;
                }
                let dij = d[i][j].max(1.0);
                let w = 1.0 / (dij * dij);
                let (mut dx, mut dy) = (pos[i].0 - pos[j].0, pos[i].1 - pos[j].1);
                let mut l = dx.hypot(dy);
                if l < 1e-6 {
                    // Two vertices on one spot: part them in a fixed direction.
                    let a = (i * 31 + j * 17) as f64;
                    (dx, dy, l) = (a.cos(), a.sin(), 1.0);
                }
                sx += w * (pos[j].0 + dij * dx / l);
                sy += w * (pos[j].1 + dij * dy / l);
                sw += w;
            }
            if sw > 0.0 {
                next[i] = (sx / sw, sy / sw);
                moved = moved.max((next[i].0 - pos[i].0).hypot(next[i].1 - pos[i].1));
            }
        }
        pos.copy_from_slice(&next);
        if moved < 0.05 {
            break;
        }
    }
}

/// Turn the layout so its long side is horizontal, and widen it toward the
/// area's aspect ratio. Both are linear maps, so they keep crossings as they
/// are; labels are wide, so the extra horizontal room helps them too.
fn turn_and_stretch(pos: &mut [P], aspect: f64) {
    let m = pos.len() as f64;
    let (mx, my) = pos
        .iter()
        .fold((0.0, 0.0), |a, p| (a.0 + p.0 / m, a.1 + p.1 / m));
    let (mut sxx, mut syy, mut sxy) = (0.0, 0.0, 0.0);
    for p in pos.iter() {
        let (x, y) = (p.0 - mx, p.1 - my);
        sxx += x * x;
        syy += y * y;
        sxy += x * y;
    }
    let t = -0.5 * (2.0 * sxy).atan2(sxx - syy);
    let (s, c) = t.sin_cos();
    for p in pos.iter_mut() {
        let (x, y) = (p.0 - mx, p.1 - my);
        *p = (x * c - y * s, x * s + y * c);
    }
    let (w, h) = pos.iter().fold((0.0f64, 0.0f64), |a, p| {
        (a.0.max(p.0.abs()), a.1.max(p.1.abs()))
    });
    if h > 1.0 && w / h < aspect {
        let k = (aspect / (w / h)).min(1.5);
        for p in pos.iter_mut() {
            p.0 *= k;
        }
    }
}

/// Segments ab and cd cross (properly, not just touch at an end).
fn crosses(a: P, b: P, c: P, d: P) -> bool {
    let o = |p: P, q: P, r: P| (q.0 - p.0) * (r.1 - p.1) - (q.1 - p.1) * (r.0 - p.0);
    let (d1, d2) = (o(c, d, a), o(c, d, b));
    let (d3, d4) = (o(a, b, c), o(a, b, d));
    d1 * d2 < 0.0 && d3 * d4 < 0.0
}

/// Segment ab passes through the rectangle (x0, y0, x1, y1).
fn hits_box(a: P, b: P, r: (f64, f64, f64, f64)) -> bool {
    // Liang–Barsky clipping.
    let (dx, dy) = (b.0 - a.0, b.1 - a.1);
    let (mut t0, mut t1) = (0.0f64, 1.0f64);
    for (p, q) in [
        (-dx, a.0 - r.0),
        (dx, r.2 - a.0),
        (-dy, a.1 - r.1),
        (dy, r.3 - a.1),
    ] {
        if p.abs() < 1e-12 {
            if q < 0.0 {
                return false;
            }
        } else {
            let t = q / p;
            if p < 0.0 {
                t0 = t0.max(t);
            } else {
                t1 = t1.min(t);
            }
            if t0 > t1 {
                return false;
            }
        }
    }
    true
}

/// Room left between a placed vertex's box and the others, in pixels.
const PLACE_GAP: f64 = 10.0;
/// What a crossing or a link through a label costs a placed vertex, in
/// pixels of link length.
const PLACE_CROSSING: f64 = 80.0;
/// Distance between the rings `place` tries, in pixels.
const PLACE_STEP: f64 = 20.0;

/// Where a new vertex `i` goes in a picture that stays as it is (pixel
/// positions `at`, None for the vertices not placed yet): on rings around
/// the middle of its placed neighbors (the area's middle for a vertex
/// without any), at the nearest distance where its box overlaps no placed
/// box. Among the spots on that ring the cheapest wins: short links, few
/// crossings and labels in the way, room around it. Spots inside the area
/// come first.
pub(super) fn place(i: usize, items: &[Item], at: &[Option<P>], adj: &[Vec<usize>], area: P) -> P {
    let placed: Vec<(usize, P)> = at
        .iter()
        .enumerate()
        .filter(|&(j, _)| j != i)
        .filter_map(|(j, p)| p.map(|p| (j, p)))
        .collect();
    let near: Vec<(usize, P)> = adj[i]
        .iter()
        .filter_map(|&j| at[j].map(|p| (j, p)))
        .collect();
    // Links between placed vertices, which the new ones should not cross.
    let links: Vec<(P, P)> = placed
        .iter()
        .flat_map(|&(a, pa)| {
            adj[a]
                .iter()
                .filter(move |&&b| b > a)
                .filter_map(move |&b| at[b].map(|pb| (pa, pb)))
        })
        .collect();
    let rect = |j: usize, p: P, gap: f64| {
        let (l, t, r, b) = items[j].extent();
        (p.0 + l - gap, p.1 + t - gap, p.0 + r + gap, p.1 + b + gap)
    };
    let overlap = |a: (f64, f64, f64, f64), b: (f64, f64, f64, f64)| {
        a.2.min(b.2) > a.0.max(b.0) && a.3.min(b.3) > a.1.max(b.1)
    };
    let free = |p: P| {
        let mine = rect(i, p, PLACE_GAP);
        placed.iter().all(|&(j, q)| !overlap(mine, rect(j, q, 0.0)))
    };
    let inside = |p: P| {
        let r = rect(i, p, 0.0);
        r.0 >= 0.0 && r.1 >= 0.0 && r.2 <= area.0 && r.3 <= area.1
    };
    // A typical link: room for a label beside another (as in `layout`).
    let mut widths: Vec<f64> = items.iter().map(|it| f64::from(it.w)).collect();
    widths.sort_by(f64::total_cmp);
    let ideal = (widths[widths.len() / 2] + 50.0).clamp(120.0, 260.0);
    let cost = |p: P| {
        let mine = rect(i, p, 0.0);
        let mut c = 0.0;
        let mut bad = links.iter().filter(|&&(a, b)| hits_box(a, b, mine)).count();
        for &(k, q) in &near {
            c += (p.0 - q.0).hypot(p.1 - q.1);
            bad += links.iter().filter(|&&(a, b)| crosses(p, q, a, b)).count();
            bad += placed
                .iter()
                .filter(|&&(j, pj)| j != k && hits_box(p, q, rect(j, pj, 0.0)))
                .count();
        }
        let room = placed
            .iter()
            .map(|&(_, q)| (p.0 - q.0).hypot(p.1 - q.1))
            .fold(f64::MAX, f64::min);
        c + PLACE_CROSSING * bad as f64 - room.min(ideal)
    };
    let anchor = if near.is_empty() {
        (area.0 / 2.0, area.1 / 2.0)
    } else {
        let k = near.len() as f64;
        (
            near.iter().map(|(_, q)| q.0).sum::<f64>() / k,
            near.iter().map(|(_, q)| q.1).sum::<f64>() / k,
        )
    };
    let far = 1.5 * area.0.max(area.1) + ideal;
    for strict in [true, false] {
        let mut r = if near.len() == 1 { 0.6 * ideal } else { 0.0 };
        while r <= far {
            let steps = ((std::f64::consts::TAU * r / PLACE_STEP).ceil() as usize).max(1);
            let best = (0..steps)
                .map(|s| {
                    let a = std::f64::consts::TAU * s as f64 / steps as f64;
                    (anchor.0 + r * a.cos(), anchor.1 + r * a.sin())
                })
                .filter(|&p| (!strict || inside(p)) && free(p))
                .map(|p| (cost(p), p))
                .min_by(|a, b| a.0.total_cmp(&b.0));
            if let Some((_, p)) = best {
                return p;
            }
            r += PLACE_STEP;
        }
    }
    anchor
}

/// What the layout minimizes. `of(pos, vs)` sums the parts that moving the
/// vertices `vs` can change (with every vertex, the whole cost): edge
/// crossings, edges through another vertex's box (they hide its label),
/// overlapping boxes, and stress, so the picture keeps distances that
/// follow the hop counts.
#[derive(Clone)]
struct Cost<'a> {
    edges: Vec<(usize, usize)>,
    /// Edge indices at each vertex.
    at: Vec<Vec<usize>>,
    d: &'a [Vec<f64>],
    items: &'a [Item],
    /// Cost of a crossing. Small graphs can afford to give up more of the
    /// even spacing for fewer crossings; in large ones that would only crowd
    /// nodes.
    crossing: f64,
    /// Weight of stress (distances off the wanted ones).
    stress: f64,
}

impl<'a> Cost<'a> {
    const HIT: f64 = 20.0;
    const OVERLAP: f64 = 10.0;
    const ANGLE: f64 = 30.0;

    fn new(adj: &[Vec<usize>], d: &'a [Vec<f64>], items: &'a [Item]) -> Self {
        let mut edges = Vec::new();
        let mut at = vec![Vec::new(); adj.len()];
        for (a, l) in adj.iter().enumerate() {
            for &b in l {
                if a < b {
                    at[a].push(edges.len());
                    at[b].push(edges.len());
                    edges.push((a, b));
                }
            }
        }
        let crossing = if adj.len() <= 16 { CROSSING_SMALL } else { 4.0 };
        Cost {
            edges,
            at,
            d,
            items,
            crossing,
            stress: 1.0,
        }
    }

    /// A vertex's box, a little smaller than drawn: grazing a corner is fine.
    fn rect(&self, pos: &[P], v: usize) -> (f64, f64, f64, f64) {
        let (l, t, r, b) = self.items[v].extent();
        (
            pos[v].0 + l + 3.0,
            pos[v].1 + t + 3.0,
            pos[v].0 + r - 3.0,
            pos[v].1 + b - 3.0,
        )
    }

    /// A vertex's box with the gap kept between boxes.
    fn padded(&self, pos: &[P], v: usize) -> (f64, f64, f64, f64) {
        let (l, t, r, b) = self.items[v].extent();
        (
            pos[v].0 + l - 7.0,
            pos[v].1 + t - 4.0,
            pos[v].0 + r + 7.0,
            pos[v].1 + b + 4.0,
        )
    }

    /// Work of one pass of `improve`, about.
    fn pass_work(&self) -> usize {
        let m = self.d.len();
        let moves = m + 18;
        let deg = 2 * self.edges.len() / m.max(1);
        m * moves * 2 * (2 * deg + 2) * (self.edges.len() + m)
    }

    /// Work `of` does for `vs`, for the budget.
    fn work(&self, vs: &[usize]) -> usize {
        let deg: usize = vs.iter().map(|&v| self.at[v].len()).sum();
        (deg + vs.len()) * (self.edges.len() + self.d.len())
    }

    fn of(&self, pos: &[P], vs: &[usize]) -> f64 {
        let n = pos.len();
        let mut mine: Vec<usize> = vs
            .iter()
            .flat_map(|&v| self.at[v].iter().copied())
            .collect();
        mine.sort_unstable();
        mine.dedup();
        let mut moving = vec![false; n];
        for &v in vs {
            moving[v] = true;
        }
        let mut cost = 0.0;
        for &e in &mine {
            let (a, b) = self.edges[e];
            for (f, &(c, d)) in self.edges.iter().enumerate() {
                // Pairs of own edges once.
                if f == e || (f < e && mine.binary_search(&f).is_ok()) {
                    continue;
                }
                if a == c || a == d || b == c || b == d {
                    continue;
                }
                if crosses(pos[a], pos[b], pos[c], pos[d]) {
                    cost += self.crossing;
                }
            }
            for v in 0..n {
                if v != a && v != b && hits_box(pos[a], pos[b], self.rect(pos, v)) {
                    cost += Self::HIT;
                }
            }
        }
        for &v in vs {
            let r = self.rect(pos, v);
            for (f, &(c, d)) in self.edges.iter().enumerate() {
                if c != v
                    && d != v
                    && mine.binary_search(&f).is_err()
                    && hits_box(pos[c], pos[d], r)
                {
                    cost += Self::HIT;
                }
            }
            let a = self.padded(pos, v);
            for u in 0..n {
                if u == v || (moving[u] && u < v) {
                    continue;
                }
                let b = self.padded(pos, u);
                if a.2.min(b.2) > a.0.max(b.0) && a.3.min(b.3) > a.1.max(b.1) {
                    cost += Self::OVERLAP;
                }
                let dij = self.d[v][u].max(1.0);
                let l = (pos[v].0 - pos[u].0).hypot(pos[v].1 - pos[u].1);
                cost += self.stress * ((l - dij) / dij).powi(2);
            }
        }
        // Edges leaving a vertex at nearly the same angle lie on top of each
        // other; moving v changes the angles at v and at its neighbors.
        let mut near: Vec<usize> = vs.to_vec();
        for &e in &mine {
            near.extend([self.edges[e].0, self.edges[e].1]);
        }
        near.sort_unstable();
        near.dedup();
        for w in near {
            cost += self.angles(pos, w);
        }
        cost
    }

    /// Penalty for edges at `w` closer than `MIN_ANGLE` to each other.
    fn angles(&self, pos: &[P], w: usize) -> f64 {
        let at = &self.at[w];
        if at.len() < 2 {
            return 0.0;
        }
        let dirs: Vec<f64> = at
            .iter()
            .map(|&e| {
                let (a, b) = self.edges[e];
                let u = if a == w { b } else { a };
                (pos[u].1 - pos[w].1).atan2(pos[u].0 - pos[w].0)
            })
            .collect();
        let mut cost = 0.0;
        for i in 0..dirs.len() {
            for j in (i + 1)..dirs.len() {
                let mut d = (dirs[i] - dirs[j]).abs();
                if d > std::f64::consts::PI {
                    d = std::f64::consts::TAU - d;
                }
                if d < MIN_ANGLE {
                    cost += Self::ANGLE * (1.0 - d / MIN_ANGLE).powi(2);
                }
            }
        }
        cost
    }

    /// The cost without stress: how the picture looks, whatever its scale.
    fn looks(&self, pos: &[P]) -> f64 {
        let free = Cost {
            stress: 0.0,
            ..self.clone()
        };
        free.total(pos)
    }

    fn total(&self, pos: &[P]) -> f64 {
        let all: Vec<usize> = (0..pos.len()).collect();
        self.of(pos, &all)
    }
}

/// xorshift64*: deterministic pseudo-random numbers, so the same graph
/// always gets the same picture.
struct Rng(u64);

impl Rng {
    /// In 0..1.
    fn unit(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11) as f64 / (1u64 << 53) as f64
    }

    /// In 0..n.
    fn below(&mut self, n: usize) -> usize {
        ((self.unit() * n as f64) as usize).min(n.saturating_sub(1))
    }
}

/// Simulated annealing for small graphs, where the greedy search stops in a
/// local minimum (a node stuck on the wrong side of a link): random moves
/// and swaps, a worse one accepted with a chance that shrinks as the
/// temperature falls. Returns the best layout seen.
fn anneal(pos: &mut Vec<P>, cost: &Cost, ideal: f64, steps: usize, seed: u64, t0: f64, jump: f64) {
    let m = pos.len();
    if m < 3 {
        return;
    }
    let mut rng = Rng(seed | 1);
    let mut cur = cost.total(pos);
    let mut best = (cur, pos.clone());
    let t1 = 0.05f64;
    let all: Vec<usize> = (0..m).collect();
    for k in 0..steps {
        let t = t0 * (t1 / t0).powf(k as f64 / steps as f64);
        let v = rng.below(m);
        let delta;
        if rng.unit() < 0.3 {
            let u = rng.below(m);
            if u == v {
                continue;
            }
            let before = cost.of(pos, &[v, u]);
            pos.swap(v, u);
            delta = cost.of(pos, &[v, u]) - before;
            if delta > 0.0 && rng.unit() >= (-delta / t).exp() {
                pos.swap(v, u);
                continue;
            }
        } else {
            // A jump that gets shorter as it cools.
            let r = ideal * jump * (0.1 + 0.9 * t / t0);
            let a = rng.unit() * std::f64::consts::TAU;
            let old = pos[v];
            let before = cost.of(pos, &[v]);
            pos[v] = (old.0 + r * a.cos(), old.1 + r * a.sin());
            delta = cost.of(pos, &[v]) - before;
            if delta > 0.0 && rng.unit() >= (-delta / t).exp() {
                pos[v] = old;
                continue;
            }
        }
        cur += delta;
        if cur < best.0 - 1e-6 {
            // `of` sums parts, so check the running total now and then.
            cur = cost.of(pos, &all);
            if cur < best.0 {
                best = (cur, pos.clone());
            }
        }
    }
    *pos = best.1;
}

/// Starting layouts for a fresh picture: rings around the three best
/// connected vertices, then scattered ones from a fixed seed.
fn starts(adj: &[Vec<usize>], ideal: f64) -> Vec<Vec<P>> {
    let m = adj.len();
    let mut roots: Vec<usize> = (0..m).collect();
    roots.sort_by_key(|&v| (std::cmp::Reverse(adj[v].len()), v));
    let mut out: Vec<Vec<P>> = roots
        .iter()
        .take(3)
        .map(|&r| rings(adj, r, ideal))
        .collect();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut next = || rng.unit();
    let side = ideal * (m as f64).sqrt();
    let scattered = if m <= 16 { 9 } else { 3 };
    for _ in 0..scattered {
        out.push(
            (0..m)
                .map(|_| ((next() - 0.5) * side, (next() - 0.5) * side))
                .collect(),
        );
    }
    out
}

/// Local search: move single vertices (to another vertex's place, swapping
/// with it, or near the middle of their neighbors) while the cost drops.
/// Bounded work, so large graphs stay quick.
fn improve(pos: &mut [P], cost: &Cost, ideal: f64, mut budget: usize) {
    let m = pos.len();
    for _ in 0..8 {
        let mut better = false;
        for v in 0..m {
            // Moves for v: swaps, then places near its neighbors' middle.
            let mut targets: Vec<P> = Vec::new();
            let nb = &cost.at[v];
            if !nb.is_empty() {
                let mut c = (0.0, 0.0);
                for &e in nb {
                    let (a, b) = cost.edges[e];
                    let u = if a == v { b } else { a };
                    c = (c.0 + pos[u].0, c.1 + pos[u].1);
                }
                let c = (c.0 / nb.len() as f64, c.1 / nb.len() as f64);
                targets.push(c);
                targets.push((2.0 * c.0 - pos[v].0, 2.0 * c.1 - pos[v].1));
                for k in 0..8 {
                    let a = std::f64::consts::TAU * k as f64 / 8.0;
                    for r in [0.5, 1.0] {
                        targets.push((c.0 + r * ideal * a.cos(), c.1 + r * ideal * a.sin()));
                    }
                }
            }
            for u in 0..m {
                if u == v {
                    continue;
                }
                let w = cost.work(&[v, u]) * 2;
                if w > budget {
                    return;
                }
                budget -= w;
                let before = cost.of(pos, &[v, u]);
                pos.swap(v, u);
                if cost.of(pos, &[v, u]) < before - 1e-3 {
                    better = true;
                } else {
                    pos.swap(v, u);
                }
            }
            for t in targets {
                let w = cost.work(&[v]) * 2;
                if w > budget {
                    return;
                }
                budget -= w;
                let old = pos[v];
                let before = cost.of(pos, &[v]);
                pos[v] = t;
                if cost.of(pos, &[v]) < before - 1e-3 {
                    better = true;
                } else {
                    pos[v] = old;
                }
            }
        }
        if !better {
            break;
        }
    }
}

/// Push overlapping boxes apart, along the axis where they overlap least.
/// `pos[i]` is the position of vertex `vs[i]`.
fn separate(vs: &[usize], pos: &mut [P], items: &[Item], aspect: f64) {
    let (gx, gy) = (14.0, 8.0);
    let rect = |pos: &[P], i: usize| {
        let (l, t, r, b) = items[vs[i]].extent();
        (pos[i].0 + l, pos[i].1 + t, pos[i].0 + r, pos[i].1 + b)
    };
    for _ in 0..200 {
        let mut moved = false;
        for i in 0..vs.len() {
            for j in (i + 1)..vs.len() {
                let (a, b) = (rect(pos, i), rect(pos, j));
                let ox = (a.2.min(b.2) - a.0.max(b.0)) + gx;
                let oy = (a.3.min(b.3) - a.1.max(b.1)) + gy;
                if ox <= 0.0 || oy <= 0.0 {
                    continue;
                }
                moved = true;
                // The shorter way apart, measured against the room the
                // area has that way (it is wider than high).
                if ox / aspect < oy {
                    let s = if pos[i].0 <= pos[j].0 { -0.5 } else { 0.5 };
                    pos[i].0 += s * ox;
                    pos[j].0 -= s * ox;
                } else {
                    let s = if pos[i].1 <= pos[j].1 { -0.5 } else { 0.5 };
                    pos[i].1 += s * oy;
                    pos[j].1 -= s * oy;
                }
            }
        }
        if !moved {
            break;
        }
    }
}

/// The bounding box of the boxes, [x0, y0, x1, y1]; `pos[i]` is the
/// position of vertex `vs[i]`.
fn bbox(vs: &[usize], pos: &[P], items: &[Item]) -> [f64; 4] {
    let mut r = [f64::MAX, f64::MAX, f64::MIN, f64::MIN];
    for (&v, p) in vs.iter().zip(pos) {
        let (l, t, rr, b) = items[v].extent();
        r[0] = r[0].min(p.0 + l);
        r[1] = r[1].min(p.1 + t);
        r[2] = r[2].max(p.0 + rr);
        r[3] = r[3].max(p.1 + b);
    }
    r
}

/// Shelf packing: components left to right in rows about as wide as the
/// area's aspect ratio suggests, largest first. Returns each component's
/// offset.
fn pack(boxes: &[[f64; 4]], aspect: f64, gap: f64) -> Vec<P> {
    let size = |b: &[f64; 4]| (b[2] - b[0], b[3] - b[1]);
    let mut order: Vec<usize> = (0..boxes.len()).collect();
    order.sort_by(|&a, &b| {
        let (sa, sb) = (size(&boxes[a]), size(&boxes[b]));
        (sb.0 * sb.1).total_cmp(&(sa.0 * sa.1)).then(a.cmp(&b))
    });
    let total: f64 = boxes
        .iter()
        .map(|b| {
            let s = size(b);
            (s.0 + gap) * (s.1 + gap)
        })
        .sum();
    let widest = boxes.iter().map(|b| size(b).0).fold(0.0, f64::max);
    let row_w = widest.max((total * aspect).sqrt());
    let mut out = vec![(0.0, 0.0); boxes.len()];
    let (mut x, mut y, mut row_h) = (0.0, 0.0, 0.0f64);
    let mut row: Vec<usize> = Vec::new();
    let mut rows: Vec<(Vec<usize>, f64)> = Vec::new();
    for &c in &order {
        let (w, h) = size(&boxes[c]);
        if x > 0.0 && x + w > row_w {
            rows.push((std::mem::take(&mut row), x - gap));
            y += row_h + gap;
            x = 0.0;
            row_h = 0.0;
        }
        out[c] = (x - boxes[c][0], y - boxes[c][1]);
        row.push(c);
        x += w + gap;
        row_h = row_h.max(h);
    }
    rows.push((row, x - gap));
    // Center each row under the widest.
    let full = rows.iter().map(|r| r.1).fold(0.0, f64::max);
    for (r, w) in rows {
        for c in r {
            out[c].0 += (full - w) / 2.0;
        }
    }
    out
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::fmt::Write as _;

    /// Layout quality in pixels: (overlapping label boxes, edge crossings,
    /// edges through another vertex's box, shortest gap between vertices).
    fn quality(
        items: &[Item],
        edges: &[(usize, usize)],
        pos: &[(f32, f32)],
        area: (f32, f32),
    ) -> (usize, usize, usize, f64) {
        let px: Vec<P> = pos
            .iter()
            .map(|p| (f64::from(p.0 * area.0), f64::from(p.1 * area.1)))
            .collect();
        let rect = |v: usize| {
            let (l, t, r, b) = items[v].extent();
            (px[v].0 + l, px[v].1 + t, px[v].0 + r, px[v].1 + b)
        };
        let n = items.len();
        let (mut overlaps, mut crossings, mut hits) = (0, 0, 0);
        let mut gap = f64::MAX;
        for i in 0..n {
            for j in (i + 1)..n {
                let (a, b) = (rect(i), rect(j));
                if a.2.min(b.2) > a.0.max(b.0) && a.3.min(b.3) > a.1.max(b.1) {
                    overlaps += 1;
                }
                gap = gap.min((px[i].0 - px[j].0).hypot(px[i].1 - px[j].1));
            }
        }
        for (e, &(a, b)) in edges.iter().enumerate() {
            for &(c, d) in &edges[e + 1..] {
                if ![c, d].contains(&a)
                    && ![c, d].contains(&b)
                    && crosses(px[a], px[b], px[c], px[d])
                {
                    crossings += 1;
                }
            }
            for v in 0..n {
                let r = rect(v);
                if v != a
                    && v != b
                    && hits_box(px[a], px[b], (r.0 + 3.0, r.1 + 3.0, r.2 - 3.0, r.3 - 3.0))
                {
                    hits += 1;
                }
            }
        }
        let mut narrow = 0;
        for v in 0..n {
            let dirs: Vec<f64> = edges
                .iter()
                .filter_map(|&(a, b)| {
                    let u = if a == v {
                        b
                    } else if b == v {
                        a
                    } else {
                        return None;
                    };
                    Some((px[u].1 - px[v].1).atan2(px[u].0 - px[v].0))
                })
                .collect();
            for i in 0..dirs.len() {
                for j in (i + 1)..dirs.len() {
                    let mut d = (dirs[i] - dirs[j]).abs();
                    if d > std::f64::consts::PI {
                        d = std::f64::consts::TAU - d;
                    }
                    if d < 0.175 {
                        narrow += 1;
                    }
                }
            }
        }
        eprintln!("  narrow angles (<10°): {narrow}");
        (overlaps, crossings, hits, gap)
    }

    pub(in crate::graph) fn items(labels: &[(&str, bool)]) -> Vec<Item> {
        labels
            .iter()
            .map(|&(l, infra)| {
                let (w, h, circle) = vertex_box(l, infra);
                Item {
                    w,
                    h,
                    circle,
                    start: None,
                }
            })
            .collect()
    }

    /// The network in the bug report: four controllers (all relays, fully
    /// meshed), four data nodes each attached to three of them, one more
    /// link, and a node with no links.
    const REPORTED: [&str; 9] = [
        "ctl-01 · 0.7.1",
        "ctl-02 · 0.7.1",
        "ctl-03 · 0.7.1",
        "ctl-04 · 0.7.1",
        "laserrks-mbp (this) · 0.7.1",
        "laserrks-pc · 0.7.0",
        "ston-pc",
        "stllok-pc · 0.7.0",
        "wolf109909-windowspc · 0.7.0",
    ];

    fn reported() -> (Vec<Item>, Vec<(usize, usize)>) {
        let l: Vec<(&str, bool)> = REPORTED
            .iter()
            .enumerate()
            .map(|(i, s)| (*s, i < 4))
            .collect();
        let it = items(&l);
        let mut e = vec![(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
        for (d, homes) in [
            (4, [0, 1, 3]),
            (5, [1, 2, 3]),
            (7, [0, 2, 3]),
            (8, [0, 1, 2]),
        ] {
            for h in homes {
                e.push((h, d));
            }
        }
        e.push((4, 5));
        (it, e)
    }

    /// With WEBJET_LAYOUT_SVG=dir, write the picture as an SVG (for looking
    /// at layout changes).
    fn svg(
        name: &str,
        labels: &[&str],
        items: &[Item],
        edges: &[(usize, usize)],
        pos: &[(f32, f32)],
        area: (f32, f32),
    ) {
        let Ok(dir) = std::env::var("WEBJET_LAYOUT_SVG") else {
            return;
        };
        let mut out = format!(
            "<svg xmlns='http://www.w3.org/2000/svg' width='{}' height='{}'><rect width='100%' height='100%' fill='#1e1f22'/>",
            area.0, area.1
        );
        let at = |i: usize| (pos[i].0 * area.0, pos[i].1 * area.1);
        for &(a, b) in edges {
            let (p, q) = (at(a), at(b));
            let _ = write!(
                out,
                "<line x1='{}' y1='{}' x2='{}' y2='{}' stroke='#4caf50' stroke-width='1.5'/>",
                p.0, p.1, q.0, q.1
            );
        }
        for (i, it) in items.iter().enumerate() {
            let (x, y) = at(i);
            let (l, t, r, b) = it.extent();
            let _ = write!(
                out,
                "<rect x='{}' y='{}' width='{}' height='{}' fill='none' stroke='#555'/>",
                x as f64 + l,
                y as f64 + t,
                r - l,
                b - t
            );
            let _ = write!(
                out,
                "<circle cx='{x}' cy='{y}' r='{}' fill='#3b82f6'/>",
                it.circle / 2.0
            );
            let _ = write!(
                out,
                "<text x='{x}' y='{}' fill='#ccc' font-size='11' text-anchor='middle'>{}</text>",
                y + it.circle / 2.0 + 12.0,
                labels[i]
            );
        }
        out += "</svg>";
        std::fs::write(format!("{dir}/{name}.svg"), out).unwrap();
    }

    #[test]
    fn layout_spreads_the_reported_network() {
        let (it, e) = reported();
        // (800, 325) is the graph area in the bug report's window.
        for area in [
            (800.0, 325.0),
            (800.0, 420.0),
            (1240.0, 480.0),
            (600.0, 500.0),
        ] {
            let pos = layout(&it, &e, area);
            svg(
                &format!("reported-{}x{}", area.0, area.1),
                &REPORTED,
                &it,
                &e,
                &pos,
                area,
            );
            let (overlaps, crossings, hits, gap) = quality(&it, &e, &pos, area);
            eprintln!(
                "{area:?}: overlaps {overlaps} crossings {crossings} hits {hits} gap {gap:.0}"
            );
            assert_eq!(overlaps, 0, "{area:?}: labels overlap");
            // Without the link laserrks-mbp – laserrks-pc the network is
            // planar (a triakis tetrahedron); that link needs a crossing.
            assert!(crossings <= 3, "{area:?}: {crossings} crossings");
            // Few edges through labels; a small area has less room to avoid
            // them (and a label in focus is drawn above them anyway).
            assert!(hits <= 8, "{area:?}: {hits} edges run through labels");
            assert!(gap > 40.0, "{area:?}: nodes {gap:.0} px apart");
            // The picture uses the area, not a corner of it.
            let xs = pos.iter().map(|p| p.0);
            let ys = pos.iter().map(|p| p.1);
            let span = |v: &mut dyn Iterator<Item = f32>| {
                let (lo, hi) = v.fold((f32::MAX, f32::MIN), |a, x| (a.0.min(x), a.1.max(x)));
                hi - lo
            };
            let (sx, sy) = (span(&mut xs.clone()), span(&mut ys.clone()));
            assert!(sx.max(sy) > 0.75 && sx.min(sy) > 0.35, "{pos:?}");
            for p in &pos {
                assert!(
                    (0.0..=1.0).contains(&p.0) && (0.0..=1.0).contains(&p.1),
                    "{p:?}"
                );
            }
        }
    }

    #[test]
    fn layout_of_a_large_network_has_no_overlaps_and_is_quick() {
        // 6 meshed relays, 30 nodes on three relays each, 4 lone nodes.
        let mut labels: Vec<(String, bool)> = (0..6)
            .map(|i| (format!("relay-{i:02} · 0.7.1"), true))
            .collect();
        labels.extend((0..34).map(|i| (format!("node-{i:02} · 0.7.1"), false)));
        let l: Vec<(&str, bool)> = labels.iter().map(|(s, b)| (s.as_str(), *b)).collect();
        let it = items(&l);
        let mut e = Vec::new();
        for a in 0..6 {
            for b in (a + 1)..6 {
                e.push((a, b));
            }
        }
        for d in 0..30 {
            for k in 0..3 {
                e.push(((d + k * 2) % 6, 6 + d));
            }
        }
        let t = std::time::Instant::now();
        let area = (1000.0, 600.0);
        let pos = layout(&it, &e, area);
        let took = t.elapsed();
        let names: Vec<&str> = l.iter().map(|x| x.0).collect();
        svg("large", &names, &it, &e, &pos, area);
        let (overlaps, crossings, hits, gap) = quality(&it, &e, &pos, area);
        eprintln!(
            "large: {took:?} overlaps {overlaps} crossings {crossings} hits {hits} gap {gap:.0}"
        );
        // Unoptimized test builds are about ten times slower.
        let limit = if cfg!(debug_assertions) { 5.0 } else { 0.5 };
        assert!(took.as_secs_f64() < limit, "{took:?}");
        assert!(overlaps <= 2, "{overlaps} overlapping labels");
    }

    #[test]
    fn a_relayout_continues_from_the_old_picture() {
        let (it, e) = reported();
        let first = layout(&it, &e, (800.0, 420.0));
        let warm: Vec<Item> = it
            .iter()
            .zip(&first)
            .map(|(i, p)| Item {
                start: Some(*p),
                ..*i
            })
            .collect();
        // A larger area: the same picture, a little more room.
        let area = (960.0, 500.0);
        let second = layout(&warm, &e, area);
        let moved = first
            .iter()
            .zip(&second)
            .map(|(p, q)| (p.0 - q.0).hypot(p.1 - q.1))
            .fold(0.0, f32::max);
        assert!(moved < 0.2, "nodes moved by {moved}");
        // A link it can't absorb (the lone node joins): still a good picture.
        let mut e2 = e;
        e2.push((6, 0));
        let third = layout(&warm, &e2, area);
        let (overlaps, crossings, _, _) = quality(&warm, &e2, &third, area);
        assert_eq!(overlaps, 0);
        assert!(crossings <= 3, "{crossings} crossings");
    }
}
