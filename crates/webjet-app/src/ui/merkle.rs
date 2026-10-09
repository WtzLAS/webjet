//! Merkle: the network's state tree as this agent holds it, checked against
//! the signed tree head; every leaf decoded with who vouches for it and its
//! inclusion proof; and the controllers' operation log — what was done,
//! who signed it, which leaves it wrote (admins only).

use super::split::{self, Axis, Split};
use super::*;
use crate::merkle::{Leaf, LogPage, LogRecord, Signer, kind_name, utc};
use gpui::uniform_list;
use webjet_core::crypto::Bytes32;
use webjet_core::merkle::kind;

/// Entries asked for per page of the log.
const LOG_PAGE: u32 = 100;

/// The leaves beside the selected leaf's or operation's details.
const MERKLE_DETAIL: Split = Split {
    id: "merkle-detail",
    axis: Axis::Row,
    sized_first: false,
    default: 380.0,
    min: 240.0,
    rest_min: 260.0,
};

/// The leaves and details beside the operation log.
const MERKLE_OPS: Split = Split {
    id: "merkle-ops",
    axis: Axis::Row,
    sized_first: false,
    default: 420.0,
    min: 280.0,
    rest_min: 260.0 + split::HANDLE + 240.0,
};

/// The tree summary (head, genesis, signing keys) above the leaves, the
/// details and the log.
const MERKLE_SUMMARY: Split = Split {
    id: "merkle-summary",
    axis: Axis::Column,
    sized_first: true,
    default: 240.0,
    min: 100.0,
    rest_min: 200.0,
};

/// The signing keys beside the head and the genesis.
const MERKLE_KEYS: Split = Split {
    id: "merkle-keys",
    axis: Axis::Row,
    sized_first: false,
    default: 380.0,
    min: 200.0,
    rest_min: 260.0 + split::HANDLE + 200.0,
};

/// The genesis beside the signed tree head.
const MERKLE_HEAD: Split = Split {
    id: "merkle-head",
    axis: Axis::Row,
    sized_first: false,
    default: 360.0,
    min: 200.0,
    rest_min: 260.0,
};

/// A panel of the tree summary: scrolls when its pane is too short.
fn summary_panel(id: &str) -> gpui::Stateful<gpui::Div> {
    scroll(id).p_3().rounded_md().bg(rgb(theme::PANEL)).gap_1()
}

fn short_hex(b: &Bytes32) -> String {
    hex::encode(&b[..8])
}

fn kind_color(k: u8) -> u32 {
    match k {
        kind::NODE => theme::ACCENT,
        kind::ACCOUNT => theme::WARN,
        kind::NODE_CONFIG => theme::RELAY,
        _ => theme::CONTROL,
    }
}

/// The color of a log entry by what it is.
fn op_color(r: &LogRecord) -> u32 {
    match r.payload.as_deref() {
        Some("OpEntry") => theme::ACCENT,
        Some("RootAccountEntry") | Some("SetStateVersionEntry") | Some("GenesisEntry") => {
            theme::WARN
        }
        Some("RedeemEnrollmentEntry") | Some("RotateNodeKeyEntry") => theme::RELAY,
        _ => theme::MUTED,
    }
}

fn when(ms: u64) -> String {
    if ms == 0 {
        "—".into()
    } else {
        format!("{} ({})", utc(ms), model::relative(ms, now_ms()))
    }
}

impl WebjetApp {
    /// Fetch a page of the operation log: the newest (`before` = 0, merged
    /// with what is shown) or the one before index `before`.
    pub(super) fn fetch_log(&mut self, before: u64, cx: &mut Context<Self>) {
        if self.log_busy {
            return;
        }
        let Some(si) = &self.signed_in else { return };
        if !si.session.is_admin() {
            self.log = Some(Err(
                "Only admins read the operation log: controllers answer only requests signed by an admin account.".into(),
            ));
            return;
        }
        let signed = client::ops::log_request(&si.account, before, LOG_PAGE);
        self.log_busy = true;
        let client = self.client.clone();
        let job = self.rt.spawn(async move { client.log(signed).await });
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let r = job.await.map_err(anyhow::Error::from).and_then(|r| r);
            let _ = this.update(cx, |app, cx| {
                app.log_busy = false;
                app.log = Some(match (r, app.log.take()) {
                    (Ok(page), Some(Ok(old))) => {
                        if before == 0 {
                            Ok(LogPage::refreshed(page, old))
                        } else {
                            let mut old = old;
                            old.prepend(page);
                            Ok(old)
                        }
                    }
                    (Ok(page), _) => Ok(page),
                    (Err(e), _) => {
                        let e = format!("{e:#}");
                        Err(if e.contains("unknown command") {
                            "This agent's webjetd is too old to read the operation log.".into()
                        } else {
                            e
                        })
                    }
                });
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn render_merkle(&mut self, _s: &Snapshot, cx: &mut Context<Self>) -> AnyElement {
        let m = match &self.merkle {
            Some(Ok(m)) => m.clone(),
            Some(Err(e)) => {
                let e = if e.contains("unknown command") {
                    "This agent's webjetd is too old to show the state tree.".to_string()
                } else {
                    format!("The state tree isn't available: {e}")
                };
                return panel()
                    .child(heading("Merkle tree"))
                    .child(muted(e))
                    .into_any_element();
            }
            None => {
                return panel()
                    .child(heading("Merkle tree"))
                    .child(muted("Loading the state tree…"))
                    .into_any_element();
            }
        };
        let summary = self.render_tree_summary(&m, cx);
        let leaves = self.render_leaves(&m, cx);
        let detail = self.render_merkle_detail(&m, cx);
        let ops = self.render_ops(cx);
        let below = self
            .split(
                MERKLE_OPS,
                self.split(MERKLE_DETAIL, leaves, detail, cx)
                    .flex_1()
                    .min_h(px(0.)),
                ops,
                cx,
            )
            .flex_1()
            .min_h(px(0.));
        self.split(MERKLE_SUMMARY, summary.flex_1().min_h(px(0.)), below, cx)
            .size_full()
            .into_any_element()
    }

    /// The signed head, genesis and signing keys side by side, each
    /// scrolling, with movable separators between them.
    fn render_tree_summary(&self, m: &Merkle, cx: &mut Context<Self>) -> gpui::Div {
        let w = &m.wire;
        let ahead = w.source == "controller";
        let mut head = summary_panel("merkle-head").child(
            div()
                .flex()
                .gap_2()
                .items_center()
                .child(heading("Signed tree head"))
                .child(match (m.head_root(), m.matches_head()) {
                    (None, _) => chip("no head yet", theme::WARN),
                    (Some(_), true) => chip("leaves match the signed root", theme::OK),
                    (Some(_), false) if ahead => {
                        chip("controller state ahead of the head", theme::WARN)
                    }
                    (Some(_), false) => chip("leaves don't match the root", theme::BAD),
                }),
        );
        match &w.head {
            Some(h) => {
                let by = h
                    .controller
                    .as_deref()
                    .map_or_else(|| "an unknown controller".into(), |c| self.names.node(c));
                head = head
                    .child(label_value(
                        "Version",
                        format!("{} · state version {}", h.version, h.state_version),
                    ))
                    .child(label_value("Signed root", h.root.clone()))
                    .child(label_value(
                        "Signed by",
                        format!("{by} · key {}", model::short(&h.signing_key_id)),
                    ))
                    .child(label_value("Issued", when(h.issued_at)))
                    .child(label_value("Expires", when(h.expires_at)));
            }
            None => head = head.child(muted("This agent has no signed tree head yet.")),
        }
        head = head.child(label_value(
            if ahead {
                "Controller root"
            } else {
                "Computed root"
            },
            hex::encode(m.root),
        ));
        let kinds = m
            .kinds()
            .iter()
            .map(|(k, n)| format!("{n} {k}"))
            .collect::<Vec<_>>()
            .join(" · ");
        head = head.child(label_value(
            "Leaves",
            format!("{} · {kinds}", m.leaves.len()),
        ));

        let g = &w.genesis;
        let genesis = summary_panel("merkle-genesis")
            .child(heading("Genesis"))
            .child(label_value("Root key", g.root_key.clone()))
            .child(label_value(
                "Emergency key",
                g.emergency_key.clone().unwrap_or_else(|| "—".into()),
            ))
            .child(label_value(
                "First admin",
                g.first_admin.clone().unwrap_or_else(|| "—".into()),
            ))
            .child(label_value("Created", utc(g.created_at)))
            .child(label_value(
                "Tree from",
                if ahead {
                    "this controller's state machine"
                } else {
                    "this agent's verified copy"
                },
            ));

        let mut certs = summary_panel("merkle-certs").child(heading("Controller signing keys"));
        if w.certs.is_empty() {
            certs = certs.child(muted("No certificates known."));
        }
        for c in w.certs.iter().take(6) {
            let issuer = match &c.issuer {
                None => "the root key".to_string(),
                Some(a) => format!("admin {}", self.names.account(a)),
            };
            certs = certs.child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .child(dot(if c.valid { theme::OK } else { theme::BAD }))
                    .child(cell(100., self.names.node(&c.controller)))
                    .child(cell(150., format!("signed by {issuer}")).text_color(rgb(theme::MUTED)))
                    .child(
                        muted(format!(
                            "#{} · {}",
                            c.serial,
                            model::short(&c.signing_key_id)
                        ))
                        .text_xs(),
                    ),
            );
        }
        if w.certs.len() > 6 {
            certs = certs.child(muted(format!("and {} more", w.certs.len() - 6)).text_xs());
        }
        if !w.key_tombstones.is_empty() {
            certs = certs.child(
                muted(format!("{} signing key(s) revoked", w.key_tombstones.len())).text_xs(),
            );
        }
        let left = self.split(MERKLE_HEAD, head, genesis, cx);
        self.split(MERKLE_KEYS, left.flex_1().min_h(px(0.)), certs, cx)
    }

    /// The bucket map (256 subtrees at depth 8) and the leaf list.
    fn render_leaves(&mut self, m: &Rc<Merkle>, cx: &mut Context<Self>) -> AnyElement {
        let filter = self.leaf_filter.read(cx).text().to_string();
        let bucket = self.bucket;
        let shown: Vec<usize> = m
            .leaves
            .iter()
            .enumerate()
            .filter(|(_, l)| bucket.is_none_or(|b| l.bucket() == b) && l.matches(&filter))
            .map(|(i, _)| i)
            .collect();
        self.leaves_shown = Rc::new(shown);
        let max = m.buckets.iter().map(|b| b.leaves).max().unwrap_or(1).max(1);
        let sel_bucket = self
            .leaf
            .as_ref()
            .and_then(|p| m.leaf(p))
            .map(|l| l.bucket());
        let mut grid = div().flex().flex_wrap().w(px(16. * 13.)).gap(px(1.));
        for (i, b) in m.buckets.iter().enumerate() {
            let i = i as u8;
            let chosen = bucket == Some(i);
            let color = if b.leaves == 0 {
                theme::RAISED
            } else {
                theme::ACCENT
            };
            let alpha = if b.leaves == 0 {
                1.0
            } else {
                0.35 + 0.65 * b.leaves as f32 / max as f32
            };
            grid = grid.child(
                div()
                    .id(("bucket", usize::from(i)))
                    .w(px(12.))
                    .h(px(12.))
                    .rounded_sm()
                    .bg(rgb(color))
                    .opacity(alpha)
                    .border_1()
                    .border_color(rgb(if chosen {
                        0xffffff
                    } else if sel_bucket == Some(i) {
                        theme::WARN
                    } else {
                        theme::PANEL
                    }))
                    .cursor_pointer()
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.bucket = if this.bucket == Some(i) {
                            None
                        } else {
                            Some(i)
                        };
                        cx.notify();
                    })),
            );
        }
        let bucket_note = match bucket.and_then(|b| m.buckets.get(usize::from(b)).map(|x| (b, x))) {
            Some((b, x)) => format!(
                "Bucket {b:02x}: {} leaves · subtree {}",
                x.leaves,
                short_hex(&x.hash)
            ),
            None => format!(
                "{} of 256 subtrees hold leaves. Gossip compares these hashes to find what differs. Click one to list its leaves.",
                m.buckets.iter().filter(|b| b.leaves > 0).count()
            ),
        };
        let leaves = m.clone();
        let rows = self.leaves_shown.clone();
        let selected = self.leaf;
        let count = rows.len();
        let list = uniform_list(
            "leaves",
            count,
            cx.processor(move |_this, range: std::ops::Range<usize>, _window, cx| {
                range
                    .filter_map(|i| rows.get(i).and_then(|&j| leaves.leaves.get(j)))
                    .enumerate()
                    .map(|(n, l)| {
                        let path = l.path;
                        let sel = selected == Some(path);
                        let signer = match &l.signer {
                            Signer::Controllers => "controllers".to_string(),
                            Signer::Key { who, .. } => who.clone(),
                        };
                        div()
                            .id(SharedString::from(format!(
                                "leaf-{}-{n}",
                                hex::encode(&path[..6])
                            )))
                            .flex()
                            .gap_2()
                            .px_2()
                            .h(px(22.))
                            .items_center()
                            .rounded_sm()
                            .cursor_pointer()
                            .bg(rgb(if sel { theme::RAISED } else { theme::PANEL }))
                            .hover(|s| s.bg(rgb(theme::RAISED)))
                            .child(dot(if l.error.is_some() {
                                theme::BAD
                            } else {
                                kind_color(l.kind)
                            }))
                            .child(cell(70., kind_name(l.kind)).text_color(rgb(theme::MUTED)))
                            .child(cell(130., l.title.clone()))
                            .child(cell(120., signer).text_color(rgb(theme::MUTED)))
                            .child(
                                cell(40., format!("v{}", l.version)).text_color(rgb(theme::MUTED)),
                            )
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.leaf = Some(path);
                                this.op = None;
                                cx.notify();
                            }))
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .flex_1()
        .min_h(px(0.));
        let mut p = panel()
            .flex_1()
            .min_h(px(0.))
            .child(
                div()
                    .flex()
                    .justify_between()
                    .child(heading("Leaves"))
                    .child(muted(format!("{count} of {}", m.leaves.len())).text_xs()),
            )
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(grid)
                    .child(muted(bucket_note).text_xs().flex_1().min_w(px(0.))),
            )
            .child(self.leaf_filter.clone())
            .child(header_row(&[
                (8., ""),
                (70., "kind"),
                (130., "name"),
                (120., "signed by"),
                (40., "ver"),
            ]));
        if count == 0 {
            p = p.child(muted("No leaf matches."));
        }
        p.child(list).into_any_element()
    }

    /// The selected leaf or log entry.
    fn render_merkle_detail(&self, m: &Merkle, cx: &mut Context<Self>) -> AnyElement {
        let body = if let Some(r) = self.op.and_then(|i| self.log_record(i)) {
            self.render_op_detail(m, r, cx)
        } else if let Some(l) = self.leaf.as_ref().and_then(|p| m.leaf(p)) {
            self.render_leaf_detail(m, l, cx)
        } else {
            panel()
                .child(heading("Details"))
                .child(muted(
                    "Select a leaf to see what it holds, who vouches for it and its inclusion proof, or an operation to see who signed it and what it changed.",
                ))
                .into_any_element()
        };
        scroll("merkle-detail").child(body).into_any_element()
    }

    fn log_record(&self, index: u64) -> Option<&LogRecord> {
        match &self.log {
            Some(Ok(p)) => p.records.iter().find(|r| r.index == index),
            _ => None,
        }
    }

    /// The newest log entry that wrote a leaf.
    fn last_change(&self, l: &Leaf) -> Option<&LogRecord> {
        let key = hex::encode(l.key);
        match &self.log {
            Some(Ok(p)) => p.records.iter().rev().find(|r| {
                r.leaves
                    .iter()
                    .any(|x| x.kind == l.kind && x.key.as_deref() == Some(key.as_str()))
            }),
            _ => None,
        }
    }

    fn render_leaf_detail(&self, m: &Merkle, l: &Leaf, cx: &mut Context<Self>) -> AnyElement {
        let mut p = panel()
            .child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .child(heading(&l.title))
                    .child(chip(kind_name(l.kind), kind_color(l.kind)))
                    .child(chip(&l.record, theme::MUTED)),
            )
            .child(label_value("Version", l.version.to_string()))
            .child(label_value("Key", hex::encode(l.key)))
            .child(label_value(
                "Signed by",
                match &l.signer {
                    Signer::Controllers => {
                        "built by the controllers; the signed tree head vouches for it".to_string()
                    }
                    Signer::Key { key, who } => format!("{who} ({key})"),
                },
            ));
        if let Some(e) = &l.error {
            p = p.child(
                div()
                    .text_color(rgb(theme::BAD))
                    .child(format!("Doesn't decode: {e}")),
            );
        }
        for (k, v) in &l.fields {
            p = p.child(label_value(k, v.clone()));
        }
        match self.last_change(l) {
            Some(r) => {
                let index = r.index;
                p = p.child(
                    div()
                        .id("leaf-last-op")
                        .cursor_pointer()
                        .child(label_value(
                            "Last written by",
                            format!(
                                "#{} {} · {} · {}",
                                r.index,
                                r.title(),
                                r.signer(&self.names),
                                model::relative(r.timestamp, now_ms())
                            ),
                        ))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.op = Some(index);
                            cx.notify();
                        })),
                );
            }
            None if matches!(self.log, Some(Ok(_))) => {
                p = p.child(label_value(
                    "Last written by",
                    "before the oldest entry still in the log",
                ));
            }
            None => {}
        }

        let (steps, ok) = m.proof(l);
        let mut proof = div()
            .pt_2()
            .flex()
            .flex_col()
            .gap_1()
            .child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .child(heading("Inclusion proof"))
                    .child(if ok {
                        chip("verifies against the root", theme::OK)
                    } else {
                        chip("doesn't verify", theme::BAD)
                    }),
            )
            .child(label_value("Path", hex::encode(l.path)))
            .child(label_value("Leaf hash", hex::encode(l.hash)))
            .child(label_value(
                "Bucket",
                format!("{:02x} (first byte of the path)", l.bucket()),
            ))
            .child(muted(format!(
                "{} of 256 siblings are non-empty; the others are empty subtrees and are left out. From the leaf up:",
                steps.len()
            )).text_xs());
        for st in &steps {
            proof = proof.child(
                div()
                    .flex()
                    .gap_2()
                    .text_xs()
                    .child(cell(70., format!("depth {}", st.depth)).text_color(rgb(theme::MUTED)))
                    .child(
                        cell(
                            80.,
                            if st.right {
                                "left of us"
                            } else {
                                "right of us"
                            },
                        )
                        .text_color(rgb(theme::MUTED)),
                    )
                    .child(cell(150., short_hex(&st.sibling))),
            );
        }
        proof = proof.child(
            div()
                .flex()
                .gap_2()
                .text_xs()
                .child(cell(70., "root").text_color(rgb(theme::MUTED)))
                .child(cell(230., short_hex(&m.root))),
        );
        p.child(proof).into_any_element()
    }

    fn render_op_detail(&self, m: &Merkle, r: &LogRecord, cx: &mut Context<Self>) -> AnyElement {
        let mut p = panel()
            .child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .child(heading(&r.title()))
                    .child(chip(&format!("#{}", r.index), op_color(r))),
            )
            .child(label_value(
                "What it did",
                r.description
                    .clone()
                    .filter(|d| !d.is_empty())
                    .unwrap_or_else(|| "—".into()),
            ))
            .child(label_value("Signed by", r.signer(&self.names)));
        if let Some(k) = &r.signer_key {
            p = p.child(label_value("Signing key", k.clone()));
        }
        if let Some(a) = &r.account_id {
            p = p.child(label_value(
                "Account",
                format!("{} ({})", self.names.account(a), model::short(a)),
            ));
            p = p.child(label_value(
                "Operation",
                format!("sequence {} · issued {}", r.op_seq, when(r.issued_at)),
            ));
        }
        p = p
            .child(label_value("Committed", when(r.timestamp)))
            .child(label_value(
                "Log entry",
                format!(
                    "index {} · term {} · {}",
                    r.index,
                    r.term,
                    r.payload.clone().unwrap_or_default()
                ),
            ));
        let mut leaves = div()
            .pt_2()
            .flex()
            .flex_col()
            .gap_1()
            .child(heading("Leaves written"));
        if r.leaves.is_empty() {
            leaves = leaves.child(muted("None: this entry changed no tree leaf."));
        }
        for (i, x) in r.leaves.iter().enumerate() {
            let key = x.key.clone().unwrap_or_default();
            let in_tree = m.find(x.kind, &key).map(|l| (l.path, l.hash));
            let current = match (&x.hash, in_tree) {
                (_, None) if x.deleted => "deleted",
                (Some(h), Some((_, now))) if *h == hex::encode(now) => "still current",
                (_, Some(_)) => "changed since",
                (_, None) => "no longer in the tree",
            };
            let mut row = div()
                .id(("op-leaf", i))
                .flex()
                .gap_2()
                .items_center()
                .px_1()
                .rounded_sm()
                .child(dot(kind_color(x.kind)))
                .child(cell(70., kind_name(x.kind)).text_color(rgb(theme::MUTED)))
                .child(cell(110., self.names.leaf_key(x.kind, &key)))
                .child(
                    cell(
                        120.,
                        if x.deleted {
                            "deleted".to_string()
                        } else {
                            x.hash
                                .as_deref()
                                .map(|h| h.get(..16).unwrap_or(h).to_string())
                                .unwrap_or_default()
                        },
                    )
                    .text_xs(),
                )
                .child(muted(current).text_xs());
            if let Some((path, _)) = in_tree {
                row = row
                    .cursor_pointer()
                    .hover(|s| s.bg(rgb(theme::RAISED)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.leaf = Some(path);
                        this.op = None;
                        cx.notify();
                    }));
            }
            leaves = leaves.child(row);
        }
        p.child(leaves).into_any_element()
    }

    /// The operation log, newest first.
    fn render_ops(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let mut p = panel().flex_1().min_h(px(0.));
        let page = match &self.log {
            Some(Ok(page)) => page.clone(),
            Some(Err(e)) => {
                return p
                    .child(heading("Operations"))
                    .child(muted(e.clone()))
                    .into_any_element();
            }
            None => {
                return p
                    .child(heading("Operations"))
                    .child(muted("Loading the operation log…"))
                    .into_any_element();
            }
        };
        let filter = self.op_filter.read(cx).text().to_string();
        let shown: Vec<LogRecord> = page
            .records
            .iter()
            .rev()
            .filter(|r| r.matches(&filter, &self.names))
            .cloned()
            .collect();
        self.ops_shown = Rc::new(shown);
        let rows = self.ops_shown.clone();
        let names = self.names.clone();
        let selected = self.op;
        let count = rows.len();
        let list = uniform_list(
            "ops",
            count,
            cx.processor(move |_this, range: std::ops::Range<usize>, _window, cx| {
                range
                    .filter_map(|i| rows.get(i))
                    .map(|r| {
                        let index = r.index;
                        let sel = selected == Some(index);
                        div()
                            .id(("op", index as usize))
                            .flex()
                            .gap_2()
                            .px_2()
                            .h(px(22.))
                            .items_center()
                            .rounded_sm()
                            .cursor_pointer()
                            .bg(rgb(if sel { theme::RAISED } else { theme::PANEL }))
                            .hover(|s| s.bg(rgb(theme::RAISED)))
                            .child(dot(op_color(r)))
                            .child(cell(44., format!("#{index}")).text_color(rgb(theme::MUTED)))
                            .child(cell(120., r.title()))
                            .child(cell(110., r.signer(&names)).text_color(rgb(theme::MUTED)))
                            .child(
                                cell(70., model::relative(r.timestamp, now_ms()))
                                    .text_color(rgb(theme::MUTED))
                                    .text_xs(),
                            )
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.op = Some(index);
                                cx.notify();
                            }))
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .flex_1()
        .min_h(px(0.));
        let older = page.has_older();
        let oldest = page.records.first().map_or(0, |r| r.index);
        let busy = self.log_busy;
        p = p
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(heading("Operations"))
                    .child(
                        muted(format!(
                            "{count} shown · log {}–{}",
                            page.first_index, page.commit_index
                        ))
                        .text_xs(),
                    ),
            )
            .child(self.op_filter.clone())
            .child(header_row(&[
                (8., ""),
                (44., "index"),
                (120., "operation"),
                (110., "signed by"),
                (70., "when"),
            ]));
        if count == 0 {
            p = p.child(muted("No operation matches."));
        }
        p = p.child(list);
        let foot = div()
            .flex()
            .gap_2()
            .items_center()
            .child(
                button("ops-newer", "Refresh", !busy, theme::RAISED).on_click(cx.listener(
                    |this, _, _, cx| {
                        this.fetch_log(0, cx);
                        cx.notify();
                    },
                )),
            )
            .child(if older {
                button("ops-older", "Load older", !busy, theme::RAISED)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.fetch_log(oldest, cx);
                        cx.notify();
                    }))
                    .into_any_element()
            } else {
                muted(if page.first_index > 1 {
                    "Older entries were compacted into a snapshot."
                } else {
                    "This is the whole log, since genesis."
                })
                .text_xs()
                .into_any_element()
            });
        p.child(foot).into_any_element()
    }
}

#[cfg(test)]
pub(super) fn sample_log() -> LogPage {
    LogPage {
        first_index: 1,
        commit_index: 3,
        records: vec![
            LogRecord {
                index: 1,
                payload: Some("GenesisEntry".into()),
                op: Some("Genesis".into()),
                ..Default::default()
            },
            LogRecord {
                index: 2,
                payload: Some("NoopEntry".into()),
                ..Default::default()
            },
            LogRecord {
                index: 3,
                payload: Some("OpEntry".into()),
                op: Some("RenameNode".into()),
                description: Some("rename".into()),
                leaves: vec![crate::merkle::LogLeaf {
                    kind: kind::NODE,
                    key: Some("00".into()),
                    hash: None,
                    deleted: true,
                }],
                ..Default::default()
            },
        ],
    }
}
