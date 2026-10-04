//! The GPUI front end: a sign-in screen, then tabs for the network, its
//! nodes, accounts and this agent's peers. What the account may change
//! comes from `model::Session::may`; everything else is shown read-only.

mod field;

use crate::client::{self, Client, SignedIn};
use crate::model::{self, Action, Node, Snapshot};
use field::Field;
use gpui::{
    AnyElement, App, AsyncApp, Context, Entity, SharedString, WeakEntity, Window, div, prelude::*,
    px, rgb,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub mod theme {
    pub const BG: u32 = 0x1e1f22;
    pub const PANEL: u32 = 0x2b2d31;
    pub const INPUT: u32 = 0x1a1b1e;
    pub const BORDER: u32 = 0x3f4147;
    pub const TEXT: u32 = 0xe6e6e6;
    pub const MUTED: u32 = 0x8c8f96;
    pub const ACCENT: u32 = 0x4c8dff;
    pub const OK: u32 = 0x3ba55d;
    pub const WARN: u32 = 0xe0a030;
    pub const BAD: u32 = 0xe5484d;
}

const REFRESH: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Nodes,
    Accounts,
    Peers,
}

/// A confirmation waiting for a second click.
#[derive(Clone, PartialEq, Eq)]
enum Confirm {
    Revoke(String),
    RotatePsk,
}

pub struct WebjetApp {
    rt: Arc<tokio::runtime::Runtime>,
    client: Client,
    keys: PathBuf,
    snapshot: Option<Snapshot>,
    load_error: Option<String>,
    accounts_on_disk: Vec<String>,
    chosen: Option<String>,
    passphrase: Entity<Field>,
    signed_in: Option<SignedIn>,
    sign_in_error: Option<String>,
    tab: Tab,
    filter: Entity<Field>,
    selected: Option<String>,
    rename: Entity<Field>,
    tags: Entity<Field>,
    reason: Entity<Field>,
    confirm: Option<Confirm>,
    busy: bool,
    notice: Option<(bool, String)>,
}

impl WebjetApp {
    pub fn new(
        rt: Arc<tokio::runtime::Runtime>,
        socket: PathBuf,
        keys: PathBuf,
        cx: &mut Context<Self>,
    ) -> Self {
        let accounts_on_disk = webjet_tools::account_names(&keys).unwrap_or_default();
        let chosen = match accounts_on_disk.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        };
        let app = WebjetApp {
            rt,
            client: Client::new(socket),
            keys,
            snapshot: None,
            load_error: None,
            accounts_on_disk,
            chosen,
            passphrase: cx.new(|cx| Field::new(cx, "passphrase", true)),
            signed_in: None,
            sign_in_error: None,
            tab: Tab::Overview,
            filter: cx.new(|cx| Field::new(cx, "filter: name, address, tag, owner, role", false)),
            selected: None,
            rename: cx.new(|cx| Field::new(cx, "new name", false)),
            tags: cx.new(|cx| Field::new(cx, "tag:a, tag:b", false)),
            reason: cx.new(|cx| Field::new(cx, "reason (optional)", false)),
            confirm: None,
            busy: false,
            notice: None,
        };
        // Refresh now and then periodically while the window exists.
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            loop {
                if this.update(cx, |app, cx| app.refresh(cx)).is_err() {
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
        let job = self.rt.spawn(async move { client.snapshot().await });
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let r = job.await.map_err(anyhow::Error::from).and_then(|r| r);
            let _ = this.update(cx, |app, cx| {
                match r {
                    Ok(s) => {
                        // An account revoked or demoted meanwhile loses its rights.
                        if let Some(si) = &mut app.signed_in {
                            let key = webjet_core::crypto::key_b64(&si.account.kp.public());
                            match model::Session::new(&s, &si.session.name, &si.session.id, &key) {
                                Ok(sess) => si.session = sess,
                                Err(e) => {
                                    app.signed_in = None;
                                    app.sign_in_error = Some(format!("signed out: {e}"));
                                }
                            }
                        }
                        app.snapshot = Some(s);
                        app.load_error = None;
                    }
                    Err(e) => app.load_error = Some(format!("{e:#}")),
                }
                cx.notify();
            });
        })
        .detach();
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
        self.selected = None;
        self.confirm = None;
        self.tab = Tab::Overview;
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

    fn selected_node(&self) -> Option<Node> {
        let id = self.selected.as_ref()?;
        self.snapshot
            .as_ref()?
            .nodes
            .iter()
            .find(|n| &n.id == id)
            .cloned()
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

fn label_value(label: &str, value: impl Into<SharedString>) -> impl IntoElement {
    div()
        .flex()
        .gap_2()
        .child(
            div()
                .w(px(150.))
                .text_color(rgb(theme::MUTED))
                .child(label.to_string()),
        )
        .child(div().text_color(rgb(theme::TEXT)).child(value.into()))
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

fn heading(t: &str) -> impl IntoElement {
    div()
        .text_lg()
        .text_color(rgb(theme::TEXT))
        .mb_1()
        .child(t.to_string())
}

fn now_ms() -> u64 {
    webjet_core::types::now_ms()
}

// ---------------------------------------------------------------- screens

impl WebjetApp {
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
                    .child(name)
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
                        button(
                            "sign-in",
                            "Sign in",
                            connected && self.chosen.is_some(),
                            theme::ACCENT,
                        )
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

    fn render_header(&self, cx: &mut Context<Self>) -> impl IntoElement {
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
        let mut tabs = div().flex().gap_1();
        let mut all = vec![(Tab::Overview, "Network"), (Tab::Nodes, "Nodes")];
        if self
            .signed_in
            .as_ref()
            .is_some_and(|s| s.session.is_admin())
        {
            all.push((Tab::Accounts, "Accounts"));
        }
        all.push((Tab::Peers, "This agent"));
        for (i, (t, label)) in all.into_iter().enumerate() {
            let on = self.tab == t;
            tabs = tabs.child(
                div()
                    .id(("tab", i))
                    .px_3()
                    .py_1()
                    .rounded_md()
                    .cursor_pointer()
                    .bg(rgb(if on { theme::ACCENT } else { theme::PANEL }))
                    .child(label)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.tab = t;
                        this.confirm = None;
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

    fn render_overview(&self, s: &Snapshot, cx: &mut Context<Self>) -> AnyElement {
        let st = &s.status;
        let now = now_ms();
        let valid_nodes = s.nodes.iter().filter(|n| n.valid).count();
        let relays = s.nodes.iter().filter(|n| n.valid && n.relay).count();
        let mut net = panel()
            .child(heading("Network"))
            .child(label_value("Overlay pool", s.tree.overlay_pool.join(", ")))
            .child(label_value(
                "Nodes",
                format!(
                    "{valid_nodes} active, {} total, {relays} relays",
                    s.nodes.len()
                ),
            ))
            .child(label_value("Controllers", st.controllers.to_string()))
            .child(label_value(
                "Tree version",
                st.tree_version
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none yet".into()),
            ))
            .child(label_value(
                "Tree root",
                st.tree_root
                    .as_deref()
                    .map(model::short)
                    .unwrap_or("—")
                    .to_string(),
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
            .child(label_value("PSK epoch", st.psk_epoch.to_string()));
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
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(net)
            .child(alarms)
            .into_any_element()
    }

    fn render_nodes(&self, s: &Snapshot, cx: &mut Context<Self>) -> AnyElement {
        let filter = self.filter.read(cx).text().to_string();
        let shown: Vec<&Node> = s.nodes.iter().filter(|n| n.matches(&filter)).collect();
        let mut list = div()
            .id("node-list")
            .flex()
            .flex_col()
            .gap_1()
            .overflow_y_scroll()
            .h_full();
        for n in &shown {
            let sel = self.selected.as_deref() == Some(n.id.as_str());
            let id = n.id.clone();
            let status_color = if n.valid { theme::OK } else { theme::BAD };
            list = list.child(
                div()
                    .id(SharedString::from(format!("node-{}", n.id)))
                    .flex()
                    .gap_2()
                    .px_2()
                    .py_1()
                    .rounded_md()
                    .cursor_pointer()
                    .bg(rgb(if sel { theme::INPUT } else { theme::PANEL }))
                    .border_1()
                    .border_color(rgb(if sel { theme::ACCENT } else { theme::PANEL }))
                    .child(
                        div()
                            .w(px(8.))
                            .h(px(8.))
                            .mt(px(6.))
                            .rounded_full()
                            .bg(rgb(status_color)),
                    )
                    .child(div().w(px(170.)).child(n.name.clone()))
                    .child(
                        div()
                            .w(px(150.))
                            .text_color(rgb(theme::MUTED))
                            .child(n.ips.join(", ")),
                    )
                    .child(div().text_color(rgb(theme::MUTED)).child(n.roles()))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.selected = Some(id.clone());
                        this.confirm = None;
                        cx.notify();
                    })),
            );
        }
        let left = div()
            .flex()
            .flex_col()
            .gap_2()
            .w(px(520.))
            .h_full()
            .child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .child(self.filter.clone())
                    .child(div().text_color(rgb(theme::MUTED)).child(format!(
                        "{} of {}",
                        shown.len(),
                        s.nodes.len()
                    ))),
            )
            .child(list);
        let right = match self.selected_node() {
            Some(n) => self.render_node_detail(&n, cx),
            None => div()
                .text_color(rgb(theme::MUTED))
                .child("Select a node to see its details.")
                .into_any_element(),
        };
        div()
            .flex()
            .gap_3()
            .h_full()
            .child(left)
            .child(div().flex_1().child(right))
            .into_any_element()
    }

    fn render_node_detail(&self, n: &Node, cx: &mut Context<Self>) -> AnyElement {
        let mut d = panel()
            .child(heading(&n.name))
            .child(label_value(
                "Status",
                if n.valid {
                    "active"
                } else {
                    "revoked or replaced"
                },
            ))
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

    fn render_accounts(&self, s: &Snapshot) -> AnyElement {
        let mut p = panel().child(heading("Accounts"));
        for a in &s.accounts {
            let owned = s
                .nodes
                .iter()
                .filter(|n| n.owner_id == a.id && n.valid)
                .count();
            p = p.child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        div()
                            .w(px(160.))
                            .text_color(rgb(if a.valid { theme::TEXT } else { theme::MUTED }))
                            .child(a.name.clone()),
                    )
                    .child(
                        div()
                            .w(px(90.))
                            .child(if a.admin { "admin" } else { "member" }),
                    )
                    .child(
                        div()
                            .w(px(90.))
                            .text_color(rgb(if a.valid { theme::OK } else { theme::BAD }))
                            .child(if a.valid { "active" } else { "revoked" }),
                    )
                    .child(
                        div()
                            .text_color(rgb(theme::MUTED))
                            .child(format!("{owned} nodes")),
                    ),
            );
        }
        p.into_any_element()
    }

    fn render_peers(&self, s: &Snapshot) -> AnyElement {
        let st = &s.status;
        let mut me = panel()
            .child(heading("This agent"))
            .child(label_value(
                "Name",
                st.name.clone().unwrap_or_else(|| "not enrolled".into()),
            ))
            .child(label_value(
                "Addresses",
                st.ips.clone().unwrap_or_default().join(", "),
            ))
            .child(label_value("Version", st.version.clone()))
            .child(label_value("Up for", model::duration(st.uptime_s)))
            .child(label_value("Sessions", st.sessions.to_string()));
        if !st.valid {
            me = me.child(
                div()
                    .text_color(rgb(theme::WARN))
                    .child("This agent's own node record isn't valid."),
            );
        }
        let mut peers = panel().child(heading("Hop sessions"));
        if s.peers.is_empty() {
            peers = peers.child(div().text_color(rgb(theme::MUTED)).child("none"));
        }
        for p in &s.peers {
            peers = peers.child(
                div()
                    .flex()
                    .gap_2()
                    .child(div().w(px(160.)).child(p.peer.clone()))
                    .child(
                        div()
                            .w(px(70.))
                            .text_color(rgb(theme::MUTED))
                            .child(p.transport.clone()),
                    )
                    .child(
                        div()
                            .w(px(180.))
                            .text_color(rgb(theme::MUTED))
                            .child(p.remote.clone()),
                    )
                    .child(div().w(px(90.)).child(format!("{:.1} ms", p.rtt_ms)))
                    .child(
                        div()
                            .w(px(80.))
                            .child(format!("{:.1}% loss", p.loss * 100.0)),
                    )
                    .child(
                        div()
                            .text_color(rgb(theme::MUTED))
                            .child(model::duration(p.age_s)),
                    ),
            );
        }
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(me)
            .child(peers)
            .into_any_element()
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
        if self.tab == Tab::Accounts
            && !self
                .signed_in
                .as_ref()
                .is_some_and(|s| s.session.is_admin())
        {
            self.tab = Tab::Overview;
        }
        let body = match self.tab {
            Tab::Overview => self.render_overview(&s, cx),
            Tab::Nodes => self.render_nodes(&s, cx),
            Tab::Accounts => self.render_accounts(&s),
            Tab::Peers => self.render_peers(&s),
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
            None => div().child(format!("connected · {}", self.client.socket.display())),
        });
        root.child(self.render_header(cx))
            .child(div().flex_1().p_3().overflow_hidden().child(body))
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
    let bounds = gpui::Bounds::centered(None, gpui::size(px(1100.), px(720.)), cx);
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
