//! The GPUI front end: a sign-in screen, then the tabs — Dashboard,
//! Connections, Nodes, Merkle, Metrics, Accounts and, for admins, Config.
//! What the account may change comes from `model::Session::may`; everything
//! else is shown read-only.

mod accounts;
mod config;
mod connections;
mod dashboard;
mod editor;
mod field;
mod merkle;
mod metrics;
mod nodes;
mod split;

use crate::client::{self, Client, SignedIn};
use crate::graph::{Graph, Viewport};
use crate::merkle::{LogPage, Merkle, Names};
use crate::model::{self, Flow, Level, ProxyFlow, Snapshot, Traffic};
use crate::openmetrics::{self, Family};
use field::Field;
use gpui::{
    AnyElement, App, AsyncApp, Context, Entity, SharedString, WeakEntity, Window, div, prelude::*,
    px, rgb,
};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

pub mod theme {
    pub const BG: u32 = 0x1e1f22;
    pub const PANEL: u32 = 0x2b2d31;
    pub const RAISED: u32 = 0x35373c;
    pub const INPUT: u32 = 0x1a1b1e;
    pub const BORDER: u32 = 0x3f4147;
    pub const TEXT: u32 = 0xe6e6e6;
    pub const MUTED: u32 = 0x8c8f96;
    pub const ACCENT: u32 = 0x4c8dff;
    pub const OK: u32 = 0x3ba55d;
    pub const WARN: u32 = 0xe0a030;
    pub const BAD: u32 = 0xe5484d;
    pub const RELAY: u32 = 0x9b6cff;
    pub const CONTROL: u32 = 0xe07b39;
    pub const TX: u32 = 0x4c8dff;
    pub const RX: u32 = 0x3ba55d;

    pub fn level(l: crate::model::Level) -> u32 {
        match l {
            crate::model::Level::Ok => OK,
            crate::model::Level::Warn => WARN,
            crate::model::Level::Bad => BAD,
        }
    }
}

const REFRESH: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Dashboard,
    Connections,
    Nodes,
    Merkle,
    Metrics,
    Accounts,
    Config,
}

const TABS: [(Tab, &str); 7] = [
    (Tab::Dashboard, "Dashboard"),
    (Tab::Connections, "Connections"),
    (Tab::Nodes, "Nodes"),
    (Tab::Merkle, "Merkle"),
    (Tab::Metrics, "Metrics"),
    (Tab::Accounts, "Accounts"),
    (Tab::Config, "Config"),
];

impl Tab {
    /// Tabs only admins get.
    fn admin_only(self) -> bool {
        self == Tab::Config
    }
}

/// A confirmation waiting for a second click.
#[derive(Clone, PartialEq, Eq)]
enum Confirm {
    Revoke(String),
    RotatePsk,
    /// Apply the edited configuration.
    ApplyConfig,
    /// Leave a configuration with unapplied edits (for this one).
    Discard(crate::netconfig::Scope),
}

pub struct WebjetApp {
    rt: Arc<tokio::runtime::Runtime>,
    client: Client,
    keys: PathBuf,
    snapshot: Option<Snapshot>,
    load_error: Option<String>,
    /// A snapshot is being fetched: the periodic refresh waits for it.
    refreshing: bool,
    /// A changed graph to lay out (shown meanwhile at the old places) and
    /// the graph shown before it.
    layout_job: Option<(Graph, Graph)>,
    /// Counts layouts started, so only the latest is shown.
    layout_seq: u64,
    accounts_on_disk: Vec<String>,
    /// The default account in the key directory (`webjetctl network account use`).
    default_account: Option<String>,
    chosen: Option<String>,
    passphrase: Entity<Field>,
    signed_in: Option<SignedIn>,
    sign_in_error: Option<String>,
    tab: Tab,
    confirm: Option<Confirm>,
    busy: bool,
    notice: Option<(bool, String)>,
    /// Bytes on this agent's hops over time.
    traffic: Traffic,
    // Nodes tab
    graph: Graph,
    node_filter: Entity<Field>,
    selected: Option<String>,
    /// The circuit (by this node's label) highlighted in the graph.
    circuit: Option<u32>,
    rename: Entity<Field>,
    tags: Entity<Field>,
    reason: Entity<Field>,
    /// Pan and zoom of the graph.
    viewport: Viewport,
    /// Positions of the nodes the user dragged, by node id; they survive
    /// refreshes and layout changes.
    pinned: BTreeMap<String, (f32, f32)>,
    /// A drag on the graph in progress.
    drag: Option<nodes::Drag>,
    /// The graph area's bounds in the window (x, y, width, height), from
    /// the last frame.
    graph_bounds: Rc<Cell<[f32; 4]>>,
    // Merkle tab
    merkle: Option<Result<Rc<Merkle>, String>>,
    names: Names,
    leaf_filter: Entity<Field>,
    op_filter: Entity<Field>,
    /// The selected leaf, by its tree path.
    leaf: Option<webjet_core::crypto::Bytes32>,
    bucket: Option<u8>,
    /// The selected log entry, by index.
    op: Option<u64>,
    /// The operation log; newest first is how it's shown.
    log: Option<Result<LogPage, String>>,
    log_busy: bool,
    /// The log entries shown, after the filter (shared with the virtual list).
    ops_shown: Rc<Vec<crate::merkle::LogRecord>>,
    /// Leaf indices shown, after the filter and bucket.
    leaves_shown: Rc<Vec<usize>>,
    // Connections tab
    flow_filter: Entity<Field>,
    /// The flows shown, after the filter (shared with the virtual list).
    flows_shown: Rc<Vec<Flow>>,
    flow_selected: Option<String>,
    /// Reverse proxy flows instead of the overlay's.
    show_proxy: bool,
    proxy_filter: Entity<Field>,
    proxy_shown: Rc<Vec<ProxyFlow>>,
    proxy_selected: Option<String>,
    // Metrics tab
    families: Rc<Vec<Family>>,
    metric_filter: Entity<Field>,
    family: Option<String>,
    metrics_all: bool,
    // Accounts tab
    account: Option<String>,
    // Config tab
    config: config::ConfigTab,
    /// Sizes of the panes beside the movable separators.
    splits: split::Splits,
}

impl WebjetApp {
    pub fn new(
        rt: Arc<tokio::runtime::Runtime>,
        socket: PathBuf,
        keys: PathBuf,
        cx: &mut Context<Self>,
    ) -> Self {
        let accounts_on_disk = webjet_tools::account_names(&keys).unwrap_or_default();
        let given = std::env::var("WEBJET_ACCOUNT").ok();
        let default_account = webjet_tools::default_account(&keys).ok().flatten();
        let chosen = client::preselected_account(&keys, &accounts_on_disk, given.as_deref());
        let app = WebjetApp {
            rt,
            client: Client::new(socket),
            keys,
            snapshot: None,
            load_error: None,
            refreshing: false,
            layout_job: None,
            layout_seq: 0,
            accounts_on_disk,
            default_account,
            chosen,
            passphrase: cx.new(|cx| Field::new(cx, "passphrase", true)),
            signed_in: None,
            sign_in_error: None,
            tab: Tab::Dashboard,
            confirm: None,
            busy: false,
            notice: None,
            traffic: Traffic::default(),
            graph: Graph::default(),
            node_filter: cx
                .new(|cx| Field::new(cx, "find: name, address, tag, owner, role", false)),
            selected: None,
            circuit: None,
            rename: cx.new(|cx| Field::new(cx, "new name", false)),
            tags: cx.new(|cx| Field::new(cx, "tag:a, tag:b", false)),
            reason: cx.new(|cx| Field::new(cx, "reason (optional)", false)),
            viewport: Viewport::default(),
            pinned: BTreeMap::new(),
            drag: None,
            graph_bounds: Rc::new(Cell::new([
                0.0,
                0.0,
                crate::graph::DEFAULT_AREA.0,
                crate::graph::DEFAULT_AREA.1,
            ])),
            merkle: None,
            names: Names::default(),
            leaf_filter: cx.new(|cx| Field::new(cx, "find: name, kind, signer, hash", false)),
            op_filter: cx.new(|cx| Field::new(cx, "filter: operation, signer, index", false)),
            leaf: None,
            bucket: None,
            op: None,
            log: None,
            log_busy: false,
            ops_shown: Rc::new(Vec::new()),
            leaves_shown: Rc::new(Vec::new()),
            flow_filter: cx.new(|cx| {
                Field::new(
                    cx,
                    "filter: peer, address, port, proto, state, rule, relay",
                    false,
                )
            }),
            flows_shown: Rc::new(Vec::new()),
            flow_selected: None,
            show_proxy: false,
            proxy_filter: cx
                .new(|cx| Field::new(cx, "filter: rule, client, target, node, state", false)),
            proxy_shown: Rc::new(Vec::new()),
            proxy_selected: None,
            families: Rc::new(Vec::new()),
            metric_filter: cx.new(|cx| Field::new(cx, "filter: name, help, label value", false)),
            family: None,
            metrics_all: false,
            account: None,
            config: config::ConfigTab::new(cx),
            splits: split::Splits::default(),
        };
        // Refresh now and then periodically while the window exists.
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            loop {
                let r = this.update(cx, |app, cx| {
                    if !app.refreshing {
                        app.refresh(cx);
                    }
                });
                if r.is_err() {
                    break;
                }
                cx.background_executor().timer(REFRESH).await;
            }
        })
        .detach();
        app
    }

    /// Fetch a fresh snapshot from the agent.
    fn refresh(&mut self, cx: &mut Context<Self>) {
        let client = self.client.clone();
        let all = self.metrics_all;
        let merkle = self.tab == Tab::Merkle;
        if merkle && self.log.is_none() {
            self.fetch_log(0, cx);
        }
        self.refreshing = true;
        let job = self
            .rt
            .spawn(async move { client.snapshot(all, merkle).await });
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let r = job.await.map_err(anyhow::Error::from).and_then(|r| r);
            let _ = this.update(cx, |app, cx| {
                app.refreshing = false;
                match r {
                    Ok(s) => app.loaded(s),
                    Err(e) => app.load_error = Some(format!("{e:#}")),
                }
                app.start_layout(cx);
                cx.notify();
            });
        })
        .detach();
    }

    /// Lay out a changed graph in the background (a large one takes a
    /// moment) and show it when done, unless a newer one came meanwhile.
    pub(super) fn start_layout(&mut self, cx: &mut Context<Self>) {
        let Some((mut g, previous)) = self.layout_job.take() else {
            return;
        };
        self.layout_seq += 1;
        let seq = self.layout_seq;
        let job = cx.background_executor().spawn(async move {
            g.lay_out(Some(&previous));
            g
        });
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let g = job.await;
            let _ = this.update(cx, |app, cx| {
                if app.layout_seq == seq {
                    app.graph = g;
                    app.graph.pin(&app.pinned);
                    cx.notify();
                }
            });
        })
        .detach();
    }

    fn loaded(&mut self, mut s: Snapshot) {
        // An account revoked or demoted meanwhile loses its rights.
        if let Some(si) = &mut self.signed_in {
            let key = webjet_core::crypto::key_b64(&si.account.kp.public());
            match model::Session::new(&s, &si.session.name, &si.session.id, &key) {
                Ok(sess) => si.session = sess,
                Err(e) => {
                    self.signed_in = None;
                    self.sign_in_error = Some(format!("signed out: {e}"));
                }
            }
        }
        // Admin-only tabs close when the account is no longer an admin.
        if self.tab.admin_only() && !self.is_admin() {
            self.tab = Tab::Dashboard;
            self.confirm = None;
        }
        let sum = s.summary();
        self.traffic.push(now_ms(), sum.tx_bytes, sum.rx_bytes);
        let [_, _, w, h] = self.graph_bounds.get();
        let mut g = Graph::shape(&s, (w, h));
        if self.graph.vertices.is_empty() {
            // The first picture: lay it out right away.
            g.lay_out(None);
        } else if !g.keep(Some(&self.graph)) {
            // Shown at the old places until the layout is done.
            self.layout_job = Some((g.clone(), self.graph.clone()));
        }
        self.graph = g;
        self.graph.pin(&self.pinned);
        // The tree is large: it lives here, not in the snapshot cloned
        // for every frame.
        if let Some(m) = s.merkle.take() {
            self.merkle = Some(m.map(|w| {
                self.names = Names::new(&s, Some(&w));
                Rc::new(Merkle::new(w, &self.names))
            }));
        }
        self.families = Rc::new(match &s.metrics {
            Ok(t) => openmetrics::parse(t),
            Err(_) => Vec::new(),
        });
        // A selected circuit that closed is no longer highlighted.
        if let (Some(l), Ok(ss)) = (self.circuit, &s.sessions)
            && !ss.circuits.local.iter().any(|c| c.label == l)
        {
            self.circuit = None;
        }
        self.snapshot = Some(s);
        self.load_error = None;
    }

    fn sign_in(&mut self, cx: &mut Context<Self>) {
        let Some(name) = self.chosen.clone() else {
            self.sign_in_error = Some("choose an account".into());
            return;
        };
        let Some(snap) = &self.snapshot else {
            self.sign_in_error = Some("not connected to webjetd yet".into());
            return;
        };
        let pass = self.passphrase.read(cx).text().to_string();
        match client::sign_in(&self.keys, &name, &pass, snap) {
            Ok(s) => {
                self.signed_in = Some(s);
                self.sign_in_error = None;
                self.passphrase.update(cx, |f, cx| f.clear(cx));
            }
            Err(e) => self.sign_in_error = Some(format!("{e:#}")),
        }
        cx.notify();
    }

    fn sign_out(&mut self, cx: &mut Context<Self>) {
        self.signed_in = None;
        self.log = None;
        self.op = None;
        self.selected = None;
        self.account = None;
        self.confirm = None;
        self.tab = Tab::Dashboard;
        // The next account starts from what is in force, not these edits.
        self.config = config::ConfigTab::new(cx);
        cx.notify();
    }

    /// Sign and submit an operation, then refresh.
    fn run_op(
        &mut self,
        what: String,
        build: impl FnOnce(&webjet_tools::Account) -> anyhow::Result<Vec<u8>>,
        cx: &mut Context<Self>,
    ) {
        let Some(si) = &self.signed_in else { return };
        self.confirm = None;
        let signed = match build(&si.account) {
            Ok(s) => s,
            Err(e) => {
                self.notice = Some((false, format!("{e:#}")));
                cx.notify();
                return;
            }
        };
        self.busy = true;
        self.notice = Some((true, format!("{what}…")));
        cx.notify();
        let client = self.client.clone();
        let job = self.rt.spawn(async move { client.submit(signed).await });
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let r = job.await.map_err(anyhow::Error::from).and_then(|r| r);
            let _ = this.update(cx, |app, cx| {
                app.busy = false;
                app.notice = Some(match r {
                    Ok(i) => (true, format!("{what}: done (entry {i})")),
                    Err(e) => (false, format!("{what}: {e:#}")),
                });
                app.refresh(cx);
            });
        })
        .detach();
    }

    fn is_admin(&self) -> bool {
        self.signed_in
            .as_ref()
            .is_some_and(|s| s.session.is_admin())
    }

    /// Show a node in the Nodes tab.
    fn show_node(&mut self, id: String, cx: &mut Context<Self>) {
        self.tab = Tab::Nodes;
        self.selected = Some(id);
        self.confirm = None;
        cx.notify();
    }
}

// ---------------------------------------------------------------- pieces

fn button(
    id: impl Into<SharedString>,
    label: &str,
    enabled: bool,
    color: u32,
) -> gpui::Stateful<gpui::Div> {
    let d = div()
        .id(gpui::ElementId::Name(id.into()))
        .px_3()
        .py_1()
        .rounded_md()
        .child(label.to_string());
    if enabled {
        d.bg(rgb(color))
            .text_color(rgb(0xffffff))
            .cursor_pointer()
            .hover(|s| s.opacity(0.85))
    } else {
        d.bg(rgb(theme::BORDER)).text_color(rgb(theme::MUTED))
    }
}

/// A two-state switch drawn as a pair of segments.
fn segmented(id: &str, options: &[&str], chosen: usize) -> Vec<gpui::Stateful<gpui::Div>> {
    options
        .iter()
        .enumerate()
        .map(|(i, o)| {
            div()
                .id(SharedString::from(format!("{id}-{i}")))
                .px_2()
                .py(px(2.))
                .rounded_md()
                .cursor_pointer()
                .bg(rgb(if i == chosen {
                    theme::ACCENT
                } else {
                    theme::RAISED
                }))
                .text_color(rgb(if i == chosen { 0xffffff } else { theme::MUTED }))
                .child(o.to_string())
        })
        .collect()
}

fn label_value(label: &str, value: impl Into<SharedString>) -> gpui::Div {
    let name = format!("value-{label}");
    div()
        .flex()
        .gap_2()
        .child(
            div()
                .w(px(130.))
                .flex_shrink_0()
                .text_color(rgb(theme::MUTED))
                .child(label.to_string()),
        )
        .child(
            wrapped(&value.into())
                .debug_selector(move || name)
                .flex_1()
                .min_w(px(0.))
                .text_color(rgb(theme::TEXT)),
        )
}

/// Longest piece of a word shown unbroken by `wrapped`.
const PIECE: usize = 12;

/// A word cut where it may break: after `-`, `.`, `:`, `/` or `,`, and
/// pieces still longer than `PIECE` characters every `PIECE` characters.
fn cut_word(w: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    for ch in w.chars() {
        cur.push(ch);
        if matches!(ch, '-' | '.' | ':' | '/' | ',') {
            parts.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        parts.push(cur);
    }
    // Join short parts again, so "10.4.0.1/32" stays one piece.
    let mut joined: Vec<String> = Vec::new();
    for p in parts {
        match joined.last_mut() {
            Some(l) if l.chars().count() + p.chars().count() <= PIECE => l.push_str(&p),
            _ => joined.push(p),
        }
    }
    joined
        .into_iter()
        .flat_map(|p| {
            let chars: Vec<char> = p.chars().collect();
            chars
                .chunks(PIECE)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The pieces `wrapped` lays out, one list per line: each word with the
/// space after it, long words cut by `cut_word`.
fn pieces(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .map(|line| {
            let words: Vec<&str> = line.split(' ').filter(|w| !w.is_empty()).collect();
            let mut out = Vec::new();
            for (i, w) in words.iter().enumerate() {
                let mut cut = cut_word(w);
                if i + 1 < words.len()
                    && let Some(last) = cut.last_mut()
                {
                    last.push(' ');
                }
                out.extend(cut);
            }
            if out.is_empty() {
                // An empty line keeps its height.
                out.push(" ".to_string());
            }
            out
        })
        .collect()
}

/// Text that wraps between words, built from unbreakable pieces in a
/// wrapping flex row. GPUI's own text wrapping can paint a paragraph
/// wrapped at another width than the one its height was measured for
/// (taffy measures text more than once and caches), so lines ran into the
/// row below; pieces that never wrap have one size whatever the width.
fn wrapped(text: &str) -> gpui::Div {
    let mut col = div().flex().flex_col();
    for line in pieces(text) {
        let mut row = div().flex().flex_wrap();
        for p in line {
            row = row.child(div().flex_none().whitespace_nowrap().child(p));
        }
        col = col.child(row);
    }
    col
}

fn panel() -> gpui::Div {
    div()
        .p_3()
        .rounded_md()
        .bg(rgb(theme::PANEL))
        .flex()
        .flex_col()
        .gap_1()
}

fn heading(t: &str) -> gpui::Div {
    div()
        .text_base()
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .text_color(rgb(theme::TEXT))
        .mb_1()
        .child(t.to_string())
}

fn muted(t: impl Into<SharedString>) -> gpui::Div {
    div().text_color(rgb(theme::MUTED)).child(t.into())
}

/// A small colored label.
fn chip(t: &str, color: u32) -> gpui::Div {
    div()
        .px(px(6.))
        .rounded_sm()
        .text_xs()
        .border_1()
        .border_color(rgb(color))
        .text_color(rgb(color))
        .child(t.to_string())
}

fn dot(color: u32) -> gpui::Div {
    div()
        .w(px(8.))
        .h(px(8.))
        .flex_shrink_0()
        .rounded_full()
        .bg(rgb(color))
}

/// A table cell of fixed width that cuts long text.
fn cell(w: f32, t: impl Into<SharedString>) -> gpui::Div {
    div()
        .w(px(w))
        .flex_shrink_0()
        .overflow_hidden()
        .whitespace_nowrap()
        .text_ellipsis()
        .child(t.into())
}

/// A table header row.
fn header_row(cols: &[(f32, &str)]) -> gpui::Div {
    let mut r = div()
        .flex()
        .gap_2()
        .px_2()
        .pb_1()
        .border_b_1()
        .border_color(rgb(theme::BORDER))
        .text_xs()
        .text_color(rgb(theme::MUTED));
    for (w, t) in cols {
        r = r.child(cell(*w, t.to_string()));
    }
    r
}

/// A scrolling column that takes the remaining height.
fn scroll(id: &str) -> gpui::Stateful<gpui::Div> {
    div()
        .id(SharedString::from(id.to_string()))
        .flex()
        .flex_col()
        .flex_1()
        .min_h(px(0.))
        .overflow_y_scroll()
}

/// The color for a link's quality: round-trip time and loss.
fn link_level(rtt_ms: f64, loss: f64) -> Level {
    if loss >= 0.05 || rtt_ms >= 300.0 {
        Level::Bad
    } else if loss >= 0.01 || rtt_ms >= 120.0 {
        Level::Warn
    } else {
        Level::Ok
    }
}

fn rtt_text(ms: f64) -> String {
    if ms <= 0.0 {
        "—".into()
    } else if ms < 10.0 {
        format!("{ms:.2} ms")
    } else {
        format!("{ms:.0} ms")
    }
}

fn loss_text(l: f64) -> String {
    format!("{:.1}%", l * 100.0)
}

fn rate_text(bps: f64) -> String {
    format!("{}/s", model::bytes(bps.max(0.0) as u64))
}

fn now_ms() -> u64 {
    webjet_core::types::now_ms()
}

// ---------------------------------------------------------------- screens

impl WebjetApp {
    /// The Sign in button is enabled: connected, with an account chosen.
    fn may_sign_in(&self) -> bool {
        self.snapshot.is_some() && self.chosen.is_some()
    }

    fn render_sign_in(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let mut list = div().flex().flex_col().gap_1();
        if self.accounts_on_disk.is_empty() {
            list = list.child(
                div().text_color(rgb(theme::MUTED)).child(format!(
                    "No account keys in {}. Create one with `webjetctl network account keygen` and have an admin add it.",
                    self.keys.display()
                )),
            );
        }
        for (i, name) in self.accounts_on_disk.clone().into_iter().enumerate() {
            let chosen = self.chosen.as_deref() == Some(name.as_str());
            let is_default = self.default_account.as_deref() == Some(name.as_str());
            let n2 = name.clone();
            list = list.child(
                div()
                    .id(("account", i))
                    .px_3()
                    .py_1()
                    .rounded_md()
                    .cursor_pointer()
                    .border_1()
                    .border_color(rgb(if chosen { theme::ACCENT } else { theme::BORDER }))
                    .bg(rgb(if chosen { theme::INPUT } else { theme::PANEL }))
                    .flex()
                    .justify_between()
                    .child(name)
                    .when(is_default, |d| d.child(muted("default").text_xs()))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.chosen = Some(n2.clone());
                        this.passphrase.read(cx).focus(window);
                        cx.notify();
                    })),
            );
        }
        let connected = self.snapshot.is_some();
        let mut col = div()
            .flex()
            .flex_col()
            .gap_3()
            .w(px(460.))
            // Enter in the passphrase field (key events bubble up from it)
            // does what the Sign in button does.
            .on_key_down(cx.listener(|this, e: &gpui::KeyDownEvent, _, cx| {
                if e.keystroke.key == "enter" && this.may_sign_in() {
                    cx.stop_propagation();
                    this.sign_in(cx);
                }
            }))
            .child(div().text_2xl().child("Webjet"))
            .child(div().text_color(rgb(theme::MUTED)).child(format!(
                "Sign in with an account of this network. Agent: {}",
                self.client.socket.display()
            )))
            .child(panel().child(heading("Account")).child(list))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .child(self.passphrase.clone())
                    .child(
                        button("sign-in", "Sign in", self.may_sign_in(), theme::ACCENT)
                            .on_click(cx.listener(|this, _, _, cx| this.sign_in(cx))),
                    ),
            );
        if !connected {
            col = col.child(
                div()
                    .text_color(rgb(theme::WARN))
                    .child(match &self.load_error {
                        Some(e) => format!("Can't reach webjetd: {e}"),
                        None => "Connecting to webjetd…".into(),
                    }),
            );
        }
        if let Some(e) = &self.sign_in_error {
            col = col.child(div().text_color(rgb(theme::BAD)).child(e.clone()));
        }
        div()
            .size_full()
            .flex()
            .justify_center()
            .items_center()
            .child(col)
            .into_any_element()
    }

    fn render_header(&self, s: &Snapshot, cx: &mut Context<Self>) -> impl IntoElement {
        let (name, role) = match &self.signed_in {
            Some(s) => (
                s.session.name.clone(),
                if s.session.is_admin() {
                    "admin"
                } else {
                    "read-only"
                },
            ),
            None => (String::new(), ""),
        };
        let health = model::health(s, now_ms());
        let mut tabs = div().flex().gap_1().items_center();
        tabs = tabs.child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .pr_3()
                .child(dot(theme::level(health.level)))
                .child(
                    div()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child(s.status.name.clone().unwrap_or_else(|| "Webjet".into())),
                ),
        );
        let admin = self.is_admin();
        for (i, (t, label)) in TABS.into_iter().enumerate() {
            if t.admin_only() && !admin {
                continue;
            }
            let on = self.tab == t;
            tabs = tabs.child(
                div()
                    .id(("tab", i))
                    .px_3()
                    .py_1()
                    .rounded_md()
                    .cursor_pointer()
                    .bg(rgb(if on { theme::ACCENT } else { theme::PANEL }))
                    .text_color(rgb(if on { 0xffffff } else { theme::TEXT }))
                    .child(label)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let fetch = t == Tab::Merkle && this.tab != Tab::Merkle;
                        this.tab = t;
                        this.confirm = None;
                        if fetch {
                            // The tree and the log are fetched only for this tab.
                            this.log = None;
                            this.refresh(cx);
                        }
                        cx.notify();
                    })),
            );
        }
        div()
            .flex()
            .justify_between()
            .items_center()
            .p_2()
            .border_b_1()
            .border_color(rgb(theme::BORDER))
            .child(tabs)
            .child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .child(
                        div()
                            .child(format!("{name} · {role}"))
                            .text_color(rgb(theme::MUTED)),
                    )
                    .child(
                        button("sign-out", "Sign out", true, theme::BORDER)
                            .on_click(cx.listener(|this, _, _, cx| this.sign_out(cx))),
                    ),
            )
    }
}

impl Render for WebjetApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let root = div()
            .size_full()
            .bg(rgb(theme::BG))
            .text_color(rgb(theme::TEXT))
            .text_sm()
            .flex()
            .flex_col();
        if self.signed_in.is_none() {
            return root.child(self.render_sign_in(cx));
        }
        let Some(s) = self.snapshot.clone() else {
            return root.child(self.render_sign_in(cx));
        };
        let body = match self.tab {
            Tab::Dashboard => self.render_dashboard(&s, cx),
            Tab::Connections => self.render_connections(&s, cx),
            Tab::Nodes => self.render_nodes(&s, cx),
            Tab::Merkle => self.render_merkle(&s, cx),
            Tab::Metrics => self.render_metrics(&s, cx),
            Tab::Accounts => self.render_accounts(&s, cx),
            Tab::Config => self.render_config(&s, cx),
        };
        let mut footer = div()
            .px_3()
            .py_1()
            .border_t_1()
            .border_color(rgb(theme::BORDER))
            .flex()
            .justify_between()
            .text_color(rgb(theme::MUTED));
        footer = footer.child(match &self.notice {
            Some((true, m)) => div().text_color(rgb(theme::OK)).child(m.clone()),
            Some((false, m)) => div().text_color(rgb(theme::BAD)).child(m.clone()),
            None => div().child(""),
        });
        footer = footer.child(match &self.load_error {
            Some(e) => div()
                .text_color(rgb(theme::WARN))
                .child(format!("agent unreachable: {e}")),
            None => div().child(format!(
                "connected · {} · webjetd {}",
                self.client.socket.display(),
                s.status.version
            )),
        });
        root.child(self.render_header(&s, cx))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h(px(0.))
                    .p_3()
                    .overflow_hidden()
                    .child(body),
            )
            .child(footer)
    }
}

/// Open the main window. Used by `main.rs`.
pub fn open(
    cx: &mut App,
    rt: Arc<tokio::runtime::Runtime>,
    socket: PathBuf,
    keys: PathBuf,
) -> anyhow::Result<()> {
    let bounds = gpui::Bounds::centered(None, gpui::size(px(1280.), px(820.)), cx);
    cx.open_window(
        gpui::WindowOptions {
            window_bounds: Some(gpui::WindowBounds::Windowed(bounds)),
            titlebar: Some(gpui::TitlebarOptions {
                title: Some("Webjet".into()),
                ..Default::default()
            }),
            ..Default::default()
        },
        move |_, cx| cx.new(|cx| WebjetApp::new(rt, socket, keys, cx)),
    )
    .map_err(|e| anyhow::anyhow!("opening the window: {e}"))?;
    cx.activate(true);
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Every tab renders headless from a real agent's answers
    //! (`tests/fixtures/node-02.json`, taken from `scripts/local-net.sh 4`).

    use super::*;
    use crate::model::{Account, Conntrack, Session, Sessions, Status, Topology, Tree};
    use gpui::{Pixels, Point, TestAppContext, point, size};
    use serde_json::Value;
    use webjet_core::crypto::{self, KeyPair};

    fn fixture() -> Snapshot {
        let v: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/node-02.json")).unwrap();
        let get = |k: &str| v[k].clone();
        Snapshot {
            status: serde_json::from_value::<Status>(get("status")).unwrap(),
            nodes: serde_json::from_value(get("nodes")).unwrap(),
            accounts: serde_json::from_value(get("accounts")).unwrap(),
            peers: serde_json::from_value(get("peers")).unwrap(),
            tree: serde_json::from_value::<Tree>(get("tree")).unwrap(),
            sessions: Ok(serde_json::from_value::<Sessions>(get("sessions")).unwrap()),
            conntrack: Ok(serde_json::from_value::<Conntrack>(get("conntrack")).unwrap()),
            proxy: Ok(serde_json::from_value::<model::Proxy>(get("proxy")).unwrap()),
            topology: Ok(serde_json::from_value::<Topology>(get("topology")).unwrap()),
            metrics: Ok(v["metrics"].as_str().unwrap().to_string()),
            metrics_all: false,
            merkle: Some(Ok(serde_json::from_value(get("merkle")).unwrap())),
        }
    }

    /// Key files of an admin account "tester" (passphrase "pw") in a new
    /// directory, and the account added to the snapshot. Returns the
    /// directory and the account id.
    fn admin_keys(s: &mut Snapshot) -> (std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("wj-ui-{}", hex::encode(crypto::random16())));
        std::fs::create_dir_all(&dir).unwrap();
        let kp = KeyPair::generate();
        let id = hex::encode(crypto::random32());
        let key = crypto::key_b64(&kp.public());
        let p = webjet_tools::AccountPub {
            name: "tester".into(),
            account_id: id.clone(),
            key: key.clone(),
        };
        std::fs::write(dir.join("tester.pub"), serde_json::to_vec(&p).unwrap()).unwrap();
        std::fs::write(
            dir.join("tester.key"),
            webjet_tools::seal("pw", &kp.seed()[..]).unwrap(),
        )
        .unwrap();
        s.accounts.push(Account {
            id: id.clone(),
            name: "tester".into(),
            admin: true,
            valid: true,
            key,
            version: 1,
        });
        (dir, id)
    }

    /// An admin account to sign in with, added to the snapshot.
    fn admin(s: &mut Snapshot) -> client::SignedIn {
        let (dir, id) = admin_keys(s);
        let account = webjet_tools::Account::unlock(&dir, "tester", "pw").unwrap();
        let key = crypto::key_b64(&account.kp.public());
        let session = Session::new(s, "tester", &id, &key).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        client::SignedIn { account, session }
    }

    /// Enter in the passphrase field signs in, like the Sign in button.
    #[gpui::test]
    fn enter_signs_in(cx: &mut TestAppContext) {
        let mut snap = fixture();
        let (dir, _) = admin_keys(&mut snap);
        let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
        let keys = dir.clone();
        let (view, cx) = cx.add_window_view(|_, cx| {
            WebjetApp::new(rt, "/nonexistent/control.sock".into(), keys, cx)
        });
        cx.simulate_resize(size(px(1280.), px(820.)));
        view.update(cx, |app, _| app.loaded(snap.clone()));
        let frame = |cx: &mut gpui::VisualTestContext| {
            view.update(cx, |_, cx| cx.notify());
            cx.run_until_parked();
        };
        let type_pass = |cx: &mut gpui::VisualTestContext, pass: &str| {
            cx.update(|window, cx| {
                view.update(cx, |app, cx| {
                    app.chosen = Some("tester".into());
                    app.passphrase.update(cx, |f, cx| f.set_text(pass, cx));
                    app.passphrase.read(cx).focus(window);
                })
            });
            frame(cx);
        };
        frame(cx);
        // A wrong passphrase: refused, as with the button.
        type_pass(cx, "wrong");
        cx.simulate_keystrokes("enter");
        frame(cx);
        view.update(cx, |app, _| {
            assert!(app.signed_in.is_none());
            assert!(app.sign_in_error.is_some(), "the error is shown");
        });
        type_pass(cx, "pw");
        cx.simulate_keystrokes("enter");
        frame(cx);
        view.update(cx, |app, cx| {
            assert!(app.signed_in.is_some(), "{:?}", app.sign_in_error);
            assert_eq!(app.passphrase.read(cx).text(), "", "the field is cleared");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[gpui::test]
    fn every_tab_renders(cx: &mut TestAppContext) {
        let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
        let (view, cx) = cx.add_window_view(|_, cx| {
            WebjetApp::new(
                rt,
                "/nonexistent/control.sock".into(),
                "/nonexistent".into(),
                cx,
            )
        });
        // The window's own frame (which events hit) the size of the drawn one.
        cx.simulate_resize(size(px(1280.), px(820.)));
        let mut snap = fixture();
        let si = admin(&mut snap);
        let node = snap.nodes.iter().find(|n| n.relay).unwrap().id.clone();
        let account = snap.accounts[0].id.clone();
        let flow = snap.conntrack.as_ref().unwrap().flows[0].clone();
        let relayed = snap
            .sessions
            .as_ref()
            .unwrap()
            .circuits
            .local
            .iter()
            .find(|c| !c.direct)
            .map(|c| c.label);
        view.update(cx, |app, _| {
            app.loaded(snap.clone());
            app.signed_in = Some(si);
        });
        let draw = |cx: &mut gpui::VisualTestContext| {
            let v = view.clone();
            cx.draw(
                point(px(0.), px(0.)),
                size(px(1280.), px(820.)),
                move |_, _| v.into_any_element(),
            );
            cx.run_until_parked();
        };
        // Each tab bare, then with something selected.
        for (tab, _) in TABS {
            view.update(cx, |app, _| app.tab = tab);
            draw(cx);
        }
        view.update(cx, |app, _| {
            app.tab = Tab::Nodes;
            app.selected = Some(node.clone());
            app.circuit = relayed;
        });
        draw(cx);
        view.update(cx, |app, _| {
            app.tab = Tab::Connections;
            app.flow_selected = Some(connections::flow_key(&flow));
        });
        draw(cx);
        // The reverse proxy view, bare and with a flow selected.
        let pflow = snap.proxy.as_ref().unwrap().flows[0].clone();
        view.update(cx, |app, _| app.show_proxy = true);
        draw(cx);
        view.update(cx, |app, _| app.proxy_selected = Some(pflow.key()));
        draw(cx);
        view.update(cx, |app, _| {
            assert_eq!(app.proxy_shown.len(), 2, "the proxy flows are listed apart");
            app.show_proxy = false;
            app.tab = Tab::Metrics;
            app.family = app.families.first().map(|f| f.name.clone());
        });
        draw(cx);
        view.update(cx, |app, _| {
            app.tab = Tab::Accounts;
            app.account = Some(account.clone());
        });
        draw(cx);

        // The Merkle tab: the tree, a leaf with its proof, the log and an
        // entry of it.
        view.update(cx, |app, _| {
            app.tab = Tab::Merkle;
            app.log = Some(Ok(merkle::sample_log()));
        });
        draw(cx);
        let leaf = view.update(cx, |app, _| {
            let Some(Ok(m)) = &app.merkle else {
                panic!("the tree is loaded")
            };
            assert!(
                m.matches_head(),
                "the fixture's leaves hash to its signed root"
            );
            assert!(m.leaves.iter().all(|l| l.error.is_none()));
            m.leaves[0].path
        });
        view.update(cx, |app, _| {
            app.leaf = Some(leaf);
            app.bucket = Some(leaf[0]);
        });
        draw(cx);
        view.update(cx, |app, _| {
            assert_eq!(app.leaves_shown.len(), 1, "the bucket filters the list");
            assert_eq!(app.ops_shown.len(), 3);
            assert_eq!(app.ops_shown[0].index, 3, "newest first");
            app.op = Some(3);
        });
        draw(cx);
        // Members can't read the log; old agents can't show the tree.
        view.update(cx, |app, _| {
            app.log = Some(Err("Only admins read the operation log".into()));
            app.merkle = Some(Err("unknown command merkle".into()));
        });
        draw(cx);

        view.update(cx, |app, _| {
            assert!(app.graph.vertices.len() >= 5, "every node is a vertex");
            assert!(!app.graph.edges.is_empty());
            assert!(!app.families.is_empty(), "the metrics parse");
            assert_eq!(app.flows_shown.len(), 2, "the flows are listed");
            assert!(app.signed_in.is_some(), "still signed in");
        });

        // The graph: drag a node to place it, click it to select it, drag
        // the background to pan, scroll to zoom. Events hit the window's own
        // frame, so these steps let the window redraw instead of `draw`.
        let frame = |cx: &mut gpui::VisualTestContext| {
            view.update(cx, |_, cx| cx.notify());
            cx.run_until_parked();
        };
        view.update(cx, |app, _| {
            app.tab = Tab::Nodes;
            app.selected = None;
            app.circuit = None;
        });
        frame(cx);
        let (at, dx, dy) = view.update(cx, |app, _| {
            let [x, y, w, h] = app.graph_bounds.get();
            assert!(w > 100.0 && h > 100.0, "the graph area was laid out");
            let v = &app.graph.vertices[0];
            let p = app.viewport.to_view((v.x, v.y));
            // Toward the middle, so the node stays inside the area.
            let dx = if p.0 < 0.5 { 60.0 } else { -60.0 };
            let dy = if p.1 < 0.5 { 40.0 } else { -40.0 };
            // The vertex's circle sits just below its center line.
            (point(px(x + p.0 * w), px(y + p.1 * h + 6.0)), dx, dy)
        });
        let to = point(at.x + px(dx), at.y + px(dy));
        cx.simulate_mouse_down(at, gpui::MouseButton::Left, Default::default());
        // Labels may overlap: whichever node is on top was grabbed.
        let (id, start) = view.update(cx, |app, _| {
            let Some(nodes::Drag {
                kind: nodes::DragKind::Node(id),
                ..
            }) = &app.drag
            else {
                panic!("a node was grabbed: {:?}", app.drag)
            };
            let v = &app.graph.vertices[app.graph.index(id).unwrap()];
            (id.clone(), app.viewport.to_view((v.x, v.y)))
        });
        frame(cx);
        cx.simulate_mouse_move(to, gpui::MouseButton::Left, Default::default());
        cx.simulate_mouse_up(to, gpui::MouseButton::Left, Default::default());
        view.update(cx, |app, _| {
            assert!(app.drag.is_none());
            assert!(app.pinned.contains_key(&id), "the dragged node is pinned");
            assert_eq!(app.selected, None, "a drag isn't a click");
            let v = &app.graph.vertices[app.graph.index(&id).unwrap()];
            assert_eq!((v.x, v.y), app.pinned[&id]);
            // It moved with the pointer.
            let [_, _, w, h] = app.graph_bounds.get();
            let now = app.viewport.to_view((v.x, v.y));
            assert!(
                ((now.0 - start.0) * w - dx).abs() < 1.0,
                "{now:?} {start:?}"
            );
            assert!(((now.1 - start.1) * h - dy).abs() < 1.0);
        });
        // A refresh keeps the node where it was put.
        view.update(cx, |app, _| {
            let p = app.pinned[&id];
            app.loaded(snap.clone());
            assert!(app.signed_in.is_some());
            let v = &app.graph.vertices[app.graph.index(&id).unwrap()];
            assert_eq!((v.x, v.y), p);
        });
        frame(cx);
        cx.simulate_mouse_down(to, gpui::MouseButton::Left, Default::default());
        let clicked = view.update(cx, |app, _| match &app.drag {
            Some(nodes::Drag {
                kind: nodes::DragKind::Node(id),
                ..
            }) => id.clone(),
            d => panic!("a node was pressed: {d:?}"),
        });
        frame(cx);
        cx.simulate_mouse_up(to, gpui::MouseButton::Left, Default::default());
        view.update(cx, |app, _| {
            assert!(app.drag.is_none());
            assert_eq!(
                app.selected.as_deref(),
                Some(clicked.as_str()),
                "a click selects"
            );
            assert!(
                !app.pinned.contains_key(&clicked) || clicked == id,
                "a click doesn't move"
            );
        });
        frame(cx);
        // Pan from an empty corner of the area.
        let corner = view.update(cx, |app, _| {
            let [x, y, _, _] = app.graph_bounds.get();
            point(px(x + 4.0), px(y + 4.0))
        });
        cx.simulate_mouse_down(corner, gpui::MouseButton::Left, Default::default());
        frame(cx);
        cx.simulate_mouse_move(
            point(corner.x + px(100.), corner.y + px(50.)),
            gpui::MouseButton::Left,
            Default::default(),
        );
        cx.simulate_mouse_up(corner, gpui::MouseButton::Left, Default::default());
        view.update(cx, |app, _| {
            let [_, _, w, h] = app.graph_bounds.get();
            assert!(
                (app.viewport.pan.0 * w - 100.0).abs() < 1.0,
                "{:?}",
                app.viewport
            );
            assert!((app.viewport.pan.1 * h - 50.0).abs() < 1.0);
            assert_eq!(
                app.selected.as_deref(),
                Some(id.as_str()),
                "panning keeps the selection"
            );
        });
        frame(cx);
        cx.simulate_event(gpui::ScrollWheelEvent {
            position: point(corner.x + px(200.), corner.y + px(100.)),
            delta: gpui::ScrollDelta::Lines(point(0., 2.)),
            ..Default::default()
        });
        view.update(cx, |app, _| {
            assert!(
                app.viewport.zoom > 1.2,
                "the wheel zooms: {:?}",
                app.viewport
            );
            app.reset_layout();
            assert!(app.pinned.is_empty() && app.viewport == Viewport::default());
        });
        frame(cx);

        // An older agent without the new commands still renders.
        view.update(cx, |app, _| {
            let mut old = snap.clone();
            old.sessions = Err("unknown command".into());
            old.conntrack = Err("unknown command".into());
            old.topology = Err("unknown command".into());
            old.metrics = Err("unknown command".into());
            old.merkle = Some(Err("unknown command".into()));
            app.loaded(old);
        });
        for (tab, _) in TABS {
            view.update(cx, |app, _| app.tab = tab);
            draw(cx);
        }
    }

    /// The Nodes tab fits a laptop-sized window: the legend stays inside the
    /// graph panel and a circuit's details get room beside the list.
    #[gpui::test]
    fn nodes_tab_fits(cx: &mut TestAppContext) {
        let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
        let (view, cx) = cx.add_window_view(|_, cx| {
            WebjetApp::new(
                rt,
                "/nonexistent/control.sock".into(),
                "/nonexistent".into(),
                cx,
            )
        });
        let mut snap = fixture();
        let si = admin(&mut snap);
        let node = snap.nodes.iter().find(|n| n.control).unwrap().id.clone();
        let circuit = snap.sessions.as_ref().unwrap().circuits.local[0].label;
        view.update(cx, |app, _| {
            app.loaded(snap.clone());
            app.signed_in = Some(si);
            app.tab = Tab::Nodes;
            app.selected = Some(node);
            app.circuit = Some(circuit);
        });
        // The window in the bug report (2870×1704 pixels at 2×) and smaller.
        for (w, h) in [(1435., 852.), (1280., 820.), (1100., 760.)] {
            cx.simulate_resize(size(px(w), px(h)));
            view.update(cx, |_, cx| cx.notify());
            cx.run_until_parked();
            let b = |cx: &mut gpui::VisualTestContext, s: &'static str| {
                cx.debug_bounds(s).unwrap_or_else(|| panic!("{s} drawn"))
            };
            let left = b(cx, "nodes-left");
            let legend = b(cx, "legend-last");
            let list = b(cx, "circuit-list");
            let detail = b(cx, "circuit-detail");
            let side = b(cx, "node-side");
            assert!(
                legend.right() <= left.right(),
                "{w}: legend {legend:?} inside {left:?}"
            );
            assert!(
                left.right() <= side.left(),
                "{w}: graph column ends before the node details"
            );
            assert_eq!(
                side.size.width,
                px(420.),
                "{w}: node details keep their width"
            );
            if w >= 1280. {
                assert_eq!(list.size.width, px(440.), "{w}: circuit list at full width");
            }
            assert!(list.size.width >= px(300.), "{w}: circuit list {list:?}");
            assert!(
                detail.size.width >= px(240.),
                "{w}: circuit details {detail:?} get room"
            );
        }

        // Drag the separator beside the node details 100 px to the left: the
        // details get 100 px more, the graph column 100 px less.
        let b = |cx: &mut gpui::VisualTestContext, s: &'static str| {
            cx.debug_bounds(s).unwrap_or_else(|| panic!("{s} drawn"))
        };
        let frame = |cx: &mut gpui::VisualTestContext| {
            view.update(cx, |_, cx| cx.notify());
            cx.run_until_parked();
        };
        let drag = |cx: &mut gpui::VisualTestContext, handle: &'static str, by: Point<Pixels>| {
            let at = b(cx, handle).center();
            cx.simulate_mouse_down(at, gpui::MouseButton::Left, Default::default());
            // The first move starts GPUI's drag, the next ones move it.
            for i in 1..=4 {
                let p = at + point(by.x * (i as f32 / 4.), by.y * (i as f32 / 4.));
                cx.simulate_mouse_move(p, gpui::MouseButton::Left, Default::default());
            }
            cx.simulate_mouse_up(at + by, gpui::MouseButton::Left, Default::default());
            frame(cx);
        };
        cx.simulate_resize(size(px(1280.), px(820.)));
        frame(cx);
        let (side0, left0) = (b(cx, "node-side"), b(cx, "nodes-left"));
        drag(cx, "split-nodes", point(px(-100.), px(0.)));
        let (side1, left1) = (b(cx, "node-side"), b(cx, "nodes-left"));
        assert_eq!(side1.size.width, side0.size.width + px(100.), "{side1:?}");
        assert_eq!(left1.size.width, left0.size.width - px(100.));
        // The graph above the circuits: dragging up gives the circuits room.
        let circuits0 = b(cx, "circuit-list");
        drag(cx, "split-graph-circuits", point(px(0.), px(-80.)));
        let circuits1 = b(cx, "circuit-list");
        assert_eq!(circuits1.size.height, circuits0.size.height + px(80.));
        // The circuit list beside the circuit's details.
        let list0 = b(cx, "circuit-list");
        drag(cx, "split-circuits", point(px(-60.), px(0.)));
        assert_eq!(b(cx, "circuit-list").size.width, list0.size.width - px(60.));
        // Not past the graph column's minimum, however far it goes.
        drag(cx, "split-nodes", point(px(-2000.), px(0.)));
        assert_eq!(b(cx, "nodes-left").size.width, px(420.));
        // A double click puts a separator back.
        let at = b(cx, "split-nodes").center();
        for n in 1..=2 {
            cx.simulate_event(gpui::MouseDownEvent {
                button: gpui::MouseButton::Left,
                position: at,
                click_count: n,
                ..Default::default()
            });
            cx.simulate_event(gpui::MouseUpEvent {
                button: gpui::MouseButton::Left,
                position: at,
                click_count: n,
                ..Default::default()
            });
        }
        frame(cx);
        assert_eq!(b(cx, "node-side").size.width, px(420.));
    }

    /// The graph as drawn: no two node labels overlap, and every node is
    /// inside the drawing area. The layout's idea of a label's width
    /// (`graph::vertex_box`) must not be smaller than the drawn one.
    #[gpui::test]
    fn graph_labels_do_not_overlap(cx: &mut TestAppContext) {
        let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
        let (view, cx) = cx.add_window_view(|_, cx| {
            WebjetApp::new(
                rt,
                "/nonexistent/control.sock".into(),
                "/nonexistent".into(),
                cx,
            )
        });
        cx.simulate_resize(size(px(1280.), px(820.)));
        let mut snap = fixture();
        let si = admin(&mut snap);
        view.update(cx, |app, _| {
            app.signed_in = Some(si);
            app.tab = Tab::Nodes;
        });
        // Draw once so the graph area has its size, then lay out for it.
        view.update(cx, |app, cx| {
            app.loaded(snap.clone());
            cx.notify();
        });
        cx.run_until_parked();
        view.update(cx, |app, cx| {
            app.reset_layout();
            app.start_layout(cx);
        });
        cx.run_until_parked();
        view.update(cx, |_, cx| cx.notify());
        cx.run_until_parked();
        let (n, labels, widths) = view.update(cx, |app, _| {
            let g = &app.graph;
            let w: Vec<f32> = g
                .vertices
                .iter()
                .map(|v| crate::graph::vertex_box(&v.label(), v.infra()).0)
                .collect();
            (
                g.vertices.len(),
                g.vertices.iter().map(|v| v.label()).collect::<Vec<_>>(),
                w,
            )
        });
        assert!(n >= 5);
        let area = cx.debug_bounds("graph-area-box").expect("graph area drawn");
        let b: Vec<gpui::Bounds<Pixels>> = (0..n)
            .map(|i| {
                let name: &'static str = Box::leak(format!("vertex-label-{i}").into_boxed_str());
                cx.debug_bounds(name)
                    .unwrap_or_else(|| panic!("{name} drawn"))
            })
            .collect();
        for i in 0..n {
            assert!(
                f32::from(b[i].size.width) <= widths[i] + 0.5,
                "{}: drawn {:?} wider than the layout thinks ({})",
                labels[i],
                b[i].size.width,
                widths[i]
            );
            assert!(
                b[i].left() >= area.left()
                    && b[i].right() <= area.right()
                    && b[i].bottom() <= area.bottom(),
                "{} {:?} inside {area:?}",
                labels[i],
                b[i]
            );
            for j in (i + 1)..n {
                assert!(
                    !b[i].intersects(&b[j]),
                    "{} {:?} and {} {:?} overlap",
                    labels[i],
                    b[i],
                    labels[j],
                    b[j]
                );
            }
        }
    }

    #[test]
    fn values_wrap_between_words() {
        assert_eq!(pieces("a b"), [["a ", "b"]]);
        assert_eq!(
            pieces("  a   b "),
            [["a ", "b"]],
            "runs of spaces count once"
        );
        assert_eq!(pieces(""), Vec::<Vec<String>>::new());
        assert_eq!(pieces("x\n\ny"), [["x"], [" "], ["y"]]);
        assert_eq!(
            pieces("0123456789abcdef →"),
            [["0123456789ab", "cdef ", "→"]],
            "long words are cut"
        );
        assert_eq!(
            pieces("laserrks-mbp → wolf109909-windowspc 10.4.0.1/32"),
            [[
                "laserrks-mbp ",
                "→ ",
                "wolf109909-",
                "windowspc ",
                "10.4.0.1/32"
            ]],
            "long words break after a hyphen, short ones stay whole"
        );
    }

    /// The selected circuit's details with long node names in a narrow
    /// window: every value wraps inside its own row, nothing runs into the
    /// row below (the bug report's screenshot QQ20261006-064820).
    #[gpui::test]
    fn circuit_details_do_not_overlap(cx: &mut TestAppContext) {
        let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
        let (view, cx) = cx.add_window_view(|_, cx| {
            WebjetApp::new(
                rt,
                "/nonexistent/control.sock".into(),
                "/nonexistent".into(),
                cx,
            )
        });
        let mut snap = fixture();
        let si = admin(&mut snap);
        snap.status.name = Some("laserrks-mbp".into());
        let label = {
            let ss = snap.sessions.as_mut().unwrap();
            let c = ss.circuits.local.iter_mut().find(|c| !c.direct).unwrap();
            c.peer = "wolf109909-windowspc".into();
            c.label
        };
        view.update(cx, |app, _| {
            app.loaded(snap.clone());
            app.signed_in = Some(si);
            app.tab = Tab::Nodes;
            app.circuit = Some(label);
        });
        let rows = ["Path", "Kind", "Round trip", "Label / route", "Age"];
        for w in [1000., 1100., 1280., 1435.] {
            cx.simulate_resize(size(px(w), px(852.)));
            view.update(cx, |_, cx| cx.notify());
            cx.run_until_parked();
            let detail = cx.debug_bounds("circuit-detail").unwrap();
            let mut last: Option<gpui::Bounds<Pixels>> = None;
            for r in rows {
                let name: &'static str = Box::leak(format!("value-{r}").into_boxed_str());
                let v = cx
                    .debug_bounds(name)
                    .unwrap_or_else(|| panic!("{name} drawn"));
                assert!(
                    v.right() <= detail.right(),
                    "{w}: {r} {v:?} inside {detail:?}"
                );
                if let Some(l) = last {
                    assert!(l.bottom() <= v.top(), "{w}: {r} {v:?} below {l:?}");
                }
                last = Some(v);
            }
            let path = cx.debug_bounds("value-Path").unwrap();
            if detail.size.width < px(300.) {
                assert!(path.size.height > px(40.), "{w}: the long path wraps");
            }
        }
    }

    /// The Config tab: admins edit the network's and a remote node's
    /// configuration in the editor, checked as they type; members don't get
    /// the tab.
    #[gpui::test]
    fn config_tab_is_for_admins(cx: &mut TestAppContext) {
        use crate::netconfig::{Doc, Scope};
        let rt = Arc::new(tokio::runtime::Runtime::new().unwrap());
        let (view, cx) = cx.add_window_view(|_, cx| {
            WebjetApp::new(
                rt,
                "/nonexistent/control.sock".into(),
                "/nonexistent".into(),
                cx,
            )
        });
        cx.simulate_resize(size(px(1280.), px(820.)));
        let mut snap = fixture();
        let si = admin(&mut snap);
        let raw: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/node-02.json")).unwrap();
        let tree = raw["tree"].clone();
        let frame = |cx: &mut gpui::VisualTestContext| {
            view.update(cx, |_, cx| cx.notify());
            cx.run_until_parked();
        };
        // Show a configuration as if the agent had answered.
        let show = |cx: &mut gpui::VisualTestContext, doc: Doc| {
            view.update(cx, |app, cx| {
                app.config.target = doc.scope.clone();
                app.config.seq += 1;
                let seq = app.config.seq;
                app.config_show(seq, Ok(doc), cx);
            });
        };
        view.update(cx, |app, _| {
            app.loaded(snap.clone());
            app.signed_in = Some(si);
            app.tab = Tab::Config;
        });
        frame(cx);
        show(cx, Doc::network(tree.clone()).unwrap());
        frame(cx);
        assert!(
            cx.debug_bounds("config-editor").is_some(),
            "the editor is drawn"
        );
        let text = view.update(cx, |app, cx| {
            assert!(!app.config.dirty(cx));
            assert!(
                matches!(&app.config.check, Some(Ok(_))),
                "{:?}",
                app.config.check
            );
            app.config.editor.read(cx).text()
        });
        assert!(text.contains("version = 1"), "{text}");
        assert!(text.contains("[[policy.rule]]"), "{text}");

        // Click into the editor and type at the end: checked as typed.
        let at = cx.debug_bounds("config-editor").unwrap().center();
        cx.simulate_click(at, gpui::Modifiers::default());
        cx.simulate_keystrokes("cmd-down enter");
        for line in ["[[dns.record]]", "name = \"web\"", "type = \"A\""] {
            cx.simulate_input(line);
            cx.simulate_keystrokes("enter");
        }
        cx.simulate_input("value = \"10.7.0.9\"");
        frame(cx);
        view.update(cx, |app, cx| {
            let t = app.config.editor.read(cx).text();
            assert!(
                t.ends_with("\n[[dns.record]]\nname = \"web\"\ntype = \"A\"\nvalue = \"10.7.0.9\""),
                "{t}"
            );
            assert!(app.config.dirty(cx));
            let Some(Ok(m)) = &app.config.check else {
                panic!("valid: {:?}", app.config.check)
            };
            assert!(m.contains("dns"), "{m}");
            // What Apply would submit: version 2, with the limit.
            let doc = app.config.doc.clone().unwrap().unwrap();
            let plan = doc.plan(&t).unwrap().unwrap();
            assert!(plan.describe().contains("version 2"), "{}", plan.describe());
        });
        // A broken file says why, and can't be applied.
        cx.simulate_keystrokes("cmd-down");
        cx.simulate_input(" = =");
        frame(cx);
        view.update(cx, |app, _| {
            assert!(matches!(&app.config.check, Some(Err(_))));
        });
        // Undo takes the typing back.
        cx.simulate_keystrokes("cmd-z");
        frame(cx);
        view.update(cx, |app, cx| {
            assert!(matches!(&app.config.check, Some(Ok(_))));
            assert!(app.config.editor.read(cx).text().ends_with("\"10.7.0.9\""));
        });
        // Leaving with unapplied edits needs a second click.
        let remote = snap
            .nodes
            .iter()
            .find(|n| n.id != snap.status.node_id && n.valid)
            .unwrap()
            .clone();
        view.update(cx, |app, cx| {
            app.config_select(Scope::Node(remote.id.clone()), cx);
            assert_eq!(app.config.target, Scope::Network, "kept the edits");
            assert!(matches!(app.confirm, Some(Confirm::Discard(_))));
        });
        frame(cx);

        // A remote node's own configuration, and what is in force there.
        let reply = serde_json::json!({
            "node_id": remote.id,
            "name": remote.name,
            "config": null,
            "effective": {
                "priorities": {"kcp": 1, "anytls": 2, "tls": 3},
                "limits": {"lookups_per_sec": 50},
                "seeds": [], "dns_records": [], "dns_forward": [],
                "suffix": "internal", "resolver": ["10.7.255.53"],
            },
        });
        show(cx, Doc::node(&reply).unwrap());
        frame(cx);
        view.update(cx, |app, cx| {
            assert_eq!(app.config.target, Scope::Node(remote.id.clone()));
            assert!(!app.config.dirty(cx), "the edits were discarded");
            app.config.show_effective = true;
        });
        frame(cx);
        view.update(cx, |app, cx| {
            let eff = app.config.effective.read(cx).text();
            assert!(eff.contains("lookups_per_sec = 50"), "{eff}");
            app.config.show_effective = false;
        });
        frame(cx);

        // A member doesn't get the tab, and loses it when demoted.
        let mut demoted = snap.clone();
        if let Some(a) = demoted.accounts.iter_mut().find(|a| a.name == "tester") {
            a.admin = false;
        }
        view.update(cx, |app, _| {
            app.loaded(demoted);
            assert!(!app.is_admin());
            assert!(app.tab == Tab::Dashboard, "the Config tab closed");
        });
        frame(cx);
        view.update(cx, |app, _| app.tab = Tab::Config);
        frame(cx);
        // (Debug bounds outlive their frame in GPUI 0.2.2: look for the
        // refusal, not for a missing editor.)
        assert!(
            cx.debug_bounds("config-admins-only").is_some(),
            "members are told it's for admins"
        );
    }
}
