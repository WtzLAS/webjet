//! Config: edit the network configuration and any node's own configuration
//! (this node's or a remote one's) as TOML, the files `webjetctl network
//! config show` and `webjetctl local config [--node n] show` print. Admins
//! only: the tab isn't offered to other accounts.
//!
//! The file is checked as it is typed (the same checks `webjetctl … check`
//! runs). Applying fetches what is in force first, so a file made from an
//! older version is refused like `apply` refuses it, then signs and submits
//! the operations and waits until the agent sees the new version.

use super::editor::Editor;
use super::split::{Axis, Split};
use super::*;
use crate::netconfig::{Doc, Plan, Scope};

/// The list of configurations beside the editor.
const CONFIG: Split = Split {
    id: "config",
    axis: Axis::Row,
    sized_first: true,
    default: 300.0,
    min: 220.0,
    rest_min: 420.0,
};

/// How long to wait for the agent to see an applied change.
const SETTLE: Duration = Duration::from_secs(15);

/// The Config tab's state.
pub(super) struct ConfigTab {
    /// Which configuration is shown.
    pub target: Scope,
    /// It as loaded, or why it couldn't be.
    pub doc: Option<Result<Doc, String>>,
    pub loading: bool,
    /// Counts loads, so an answer for an older one is dropped.
    pub seq: u64,
    /// Applying (fetching, signing, submitting, waiting).
    pub applying: bool,
    /// The file being edited.
    pub editor: Entity<Editor>,
    /// Nodes: what is in force for it (read-only).
    pub effective: Entity<Editor>,
    pub show_effective: bool,
    /// The live check of the edited file: valid (with what it does) or why not.
    pub check: Option<Result<String, String>>,
    pub filter: Entity<Field>,
}

impl ConfigTab {
    pub fn new(cx: &mut Context<WebjetApp>) -> ConfigTab {
        let editor = cx.new(|cx| Editor::new(cx, false));
        cx.subscribe(
            &editor,
            |this: &mut WebjetApp, _, _: &editor::Changed, cx| {
                this.config_check(cx);
                cx.notify();
            },
        )
        .detach();
        ConfigTab {
            target: Scope::Network,
            doc: None,
            loading: false,
            seq: 0,
            applying: false,
            editor,
            effective: cx.new(|cx| Editor::new(cx, true)),
            show_effective: false,
            check: None,
            filter: cx.new(|cx| Field::new(cx, "find: node name, tag, role", false)),
        }
    }

    fn loaded(&self) -> Option<&Doc> {
        self.doc.as_ref().and_then(|d| d.as_ref().ok())
    }

    /// Whether the editor holds changes not applied.
    pub fn dirty(&self, cx: &App) -> bool {
        self.loaded()
            .is_some_and(|d| d.text != self.editor.read(cx).text())
    }
}

impl WebjetApp {
    /// Re-check the edited file against the loaded configuration.
    fn config_check(&mut self, cx: &mut Context<Self>) {
        let c = &mut self.config;
        c.check = c.loaded().map(|d| {
            let text = c.editor.read(cx).text();
            d.check(&text).map_err(|e| format!("{e:#}"))
        });
    }

    /// Fetch `target` from the agent and show it, replacing the editor's text.
    pub(super) fn config_load(&mut self, target: Scope, cx: &mut Context<Self>) {
        let c = &mut self.config;
        c.target = target.clone();
        c.loading = true;
        c.seq += 1;
        let seq = c.seq;
        c.doc = None;
        c.check = None;
        c.show_effective = false;
        self.confirm = None;
        let client = self.client.clone();
        let job = self.rt.spawn(async move { fetch(&client, &target).await });
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let r = job.await.map_err(anyhow::Error::from).and_then(|r| r);
            let _ = this.update(cx, |app, cx| app.config_show(seq, r, cx));
        })
        .detach();
        cx.notify();
    }

    /// Show a loaded configuration, unless the user moved on meanwhile
    /// (`seq` isn't the latest load, or it's for another configuration).
    pub(super) fn config_show(&mut self, seq: u64, r: anyhow::Result<Doc>, cx: &mut Context<Self>) {
        if seq != self.config.seq || matches!(&r, Ok(d) if d.scope != self.config.target) {
            return;
        }
        let c = &mut self.config;
        c.loading = false;
        match r {
            Ok(d) => {
                let text = d.text.clone();
                let eff = d.effective.clone().unwrap_or_default();
                c.editor.update(cx, |e, cx| e.set_text(&text, cx));
                c.effective.update(cx, |e, cx| e.set_text(&eff, cx));
                c.doc = Some(Ok(d));
            }
            Err(e) => c.doc = Some(Err(format!("{e:#}"))),
        }
        self.config_check(cx);
        cx.notify();
    }

    /// Choose another configuration; unapplied edits need a second click.
    pub(super) fn config_select(&mut self, target: Scope, cx: &mut Context<Self>) {
        if target == self.config.target && self.config.doc.is_some() {
            return;
        }
        if self.config.dirty(cx) && self.confirm != Some(Confirm::Discard(target.clone())) {
            self.confirm = Some(Confirm::Discard(target));
            cx.notify();
            return;
        }
        self.config_load(target, cx);
    }

    /// Apply the edited file: fetch what is in force, plan against it, sign
    /// and submit, then wait for the agent to show the new version.
    fn config_apply(&mut self, cx: &mut Context<Self>) {
        if !self.is_admin() || self.config.applying {
            return;
        }
        self.confirm = None;
        let target = self.config.target.clone();
        let text = self.config.editor.read(cx).text();
        self.config.applying = true;
        self.notice = Some((
            true,
            format!("Applying the {} configuration…", self.config_title()),
        ));
        let client = self.client.clone();
        let job = self.rt.spawn({
            let target = target.clone();
            async move { fetch(&client, &target).await }
        });
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let fresh = job.await.map_err(anyhow::Error::from).and_then(|r| r);
            let _ = this.update(cx, |app, cx| app.config_submit(fresh, &text, cx));
        })
        .detach();
        cx.notify();
    }

    fn config_fail(&mut self, what: String, cx: &mut Context<Self>) {
        self.config.applying = false;
        self.notice = Some((false, what));
        cx.notify();
    }

    /// Second step of applying: plan against the fresh configuration, sign.
    fn config_submit(&mut self, fresh: anyhow::Result<Doc>, text: &str, cx: &mut Context<Self>) {
        let title = self.config_title();
        let fresh = match fresh {
            Ok(d) => d,
            Err(e) => return self.config_fail(format!("Not applied: {e:#}"), cx),
        };
        let plan = match fresh.plan(text) {
            Ok(Some(p)) => p,
            Ok(None) => {
                self.config.applying = false;
                self.notice = Some((
                    true,
                    format!("{title} has no configuration of its own; nothing to apply"),
                ));
                cx.notify();
                return;
            }
            Err(e) => return self.config_fail(format!("Not applied: {e:#}"), cx),
        };
        let Some(si) = &self.signed_in else {
            return self.config_fail("Not applied: signed out".into(), cx);
        };
        let what = plan.describe();
        let note = plan.note().map(String::from);
        let signed: anyhow::Result<Vec<Vec<u8>>> = Plan::ops(plan)
            .into_iter()
            .map(|op| si.account.sign(op))
            .collect();
        let signed = match signed {
            Ok(s) => s,
            Err(e) => return self.config_fail(format!("Not applied: {e:#}"), cx),
        };
        let client = self.client.clone();
        let target = fresh.scope.clone();
        let old = fresh.version;
        let job = self.rt.spawn(async move {
            let index = client.submit_all(signed).await?;
            // The agent sees the change once the new tree head reaches it.
            let start = std::time::Instant::now();
            loop {
                let d = fetch(&client, &target).await?;
                if d.version != old || start.elapsed() > SETTLE {
                    return anyhow::Ok((index, d));
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        });
        cx.spawn(async move |this: WeakEntity<Self>, cx: &mut AsyncApp| {
            let r = job.await.map_err(anyhow::Error::from).and_then(|r| r);
            let _ = this.update(cx, |app, cx| {
                app.config.applying = false;
                match r {
                    Ok((index, doc)) => {
                        let mut m = format!("Applied {what} (entry {index})");
                        if doc.version == old {
                            m.push_str("; this agent doesn't show it yet, reload in a moment");
                        }
                        if let Some(n) = note {
                            m.push_str(&format!("; note: {n}"));
                        }
                        app.notice = Some((true, m));
                        let seq = app.config.seq;
                        app.config_show(seq, Ok(doc), cx);
                    }
                    Err(e) => app.notice = Some((false, format!("Not applied: {e:#}"))),
                }
                app.refresh(cx);
                cx.notify();
            });
        })
        .detach();
    }

    fn config_title(&self) -> String {
        match &self.config.target {
            Scope::Network => "network".into(),
            Scope::Node(_) => self
                .config
                .loaded()
                .map_or_else(|| "node".into(), |d| d.title.clone()),
        }
    }

    pub(super) fn render_config(&mut self, s: &Snapshot, cx: &mut Context<Self>) -> AnyElement {
        if !self.is_admin() {
            return panel()
                .debug_selector(|| "config-admins-only".into())
                .child(heading("Configuration"))
                .child(muted("Only admin accounts can change the configuration."))
                .into_any_element();
        }
        if self.config.doc.is_none() && !self.config.loading {
            self.config_load(self.config.target.clone(), cx);
        }
        let left = self.render_config_list(s, cx);
        let right = self.render_config_editor(s, cx);
        div()
            .flex()
            .flex_col()
            .gap_2()
            .size_full()
            .child(self.split(CONFIG, left, right, cx).flex_1().min_h(px(0.)))
            .child(
                muted(
                    "Changes are signed with your account and submitted through this agent; a node's own settings override the network's for that node.",
                )
                .text_xs(),
            )
            .into_any_element()
    }

    fn render_config_list(&mut self, s: &Snapshot, cx: &mut Context<Self>) -> gpui::Div {
        let me = s.status.node_id.clone();
        let q = self.config.filter.read(cx).text().trim().to_lowercase();
        let mut nodes: Vec<&model::Node> = s
            .nodes
            .iter()
            .filter(|n| n.valid)
            .filter(|n| {
                q.is_empty()
                    || n.name.to_lowercase().contains(&q)
                    || n.roles().contains(&q)
                    || n.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect();
        // This node first, then by name.
        nodes.sort_by_key(|n| (n.id != me, n.name.clone()));
        let item = |id: SharedString, sel: bool| {
            div()
                .id(id)
                .flex()
                .items_center()
                .gap_2()
                .px_2()
                .py(px(3.))
                .rounded_sm()
                .cursor_pointer()
                .bg(rgb(if sel { theme::RAISED } else { theme::PANEL }))
                .hover(|s| s.bg(rgb(theme::RAISED)))
        };
        let target = self.config.target.clone();
        let pending = match &self.confirm {
            Some(Confirm::Discard(t)) => Some(t.clone()),
            _ => None,
        };
        let mut list = scroll("config-nodes").gap(px(1.));
        list = list.child(
            item("cfg-network".into(), target == Scope::Network)
                .child(dot(theme::ACCENT))
                .child(div().flex_1().child("Network"))
                .child(muted(format!("version {}", s.tree.network_version)).text_xs())
                .on_click(cx.listener(|this, _, _, cx| this.config_select(Scope::Network, cx))),
        );
        list = list.child(div().pt_2().pb_1().child(muted("Nodes").text_xs()));
        for n in nodes {
            let scope = Scope::Node(n.id.clone());
            let sel = target == scope;
            let local = n.id == me;
            list = list.child(
                item(format!("cfg-node-{}", n.id).into(), sel)
                    .child(dot(if n.control {
                        theme::CONTROL
                    } else if n.relay {
                        theme::RELAY
                    } else {
                        theme::OK
                    }))
                    .child(cell(130., n.name.clone()))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_xs()
                            .text_color(rgb(theme::MUTED))
                            .child(n.roles()),
                    )
                    .when(local, |d| d.child(chip("this node", theme::ACCENT)))
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.config_select(scope.clone(), cx)),
                    ),
            );
        }
        let mut p = panel()
            .flex_1()
            .min_h(px(0.))
            .child(heading("Configuration"))
            .child(self.config.filter.clone())
            .child(list);
        if pending.is_some() {
            p = p.child(
                div()
                    .text_xs()
                    .text_color(rgb(theme::WARN))
                    .child("You have unapplied changes: click again to discard them."),
            );
        }
        p
    }

    fn render_config_editor(&mut self, s: &Snapshot, cx: &mut Context<Self>) -> AnyElement {
        let c = &self.config;
        let doc = match &c.doc {
            None => {
                return panel()
                    .flex_1()
                    .child(muted("Loading the configuration…"))
                    .into_any_element();
            }
            Some(Err(e)) => {
                let target = c.target.clone();
                return panel()
                    .flex_1()
                    .gap_2()
                    .child(heading("Configuration"))
                    .child(
                        div()
                            .text_color(rgb(theme::BAD))
                            .child(format!("Can't load it: {e}")),
                    )
                    .child(div().child(
                        button("cfg-retry", "Try again", true, theme::ACCENT).on_click(
                            cx.listener(move |this, _, _, cx| this.config_load(target.clone(), cx)),
                        ),
                    ))
                    .into_any_element();
            }
            Some(Ok(d)) => d,
        };
        let dirty = c.dirty(cx);
        let busy = c.applying || self.busy;
        let is_node = matches!(doc.scope, Scope::Node(_));
        let local = doc.scope == Scope::Node(s.status.node_id.clone());
        let title = match &doc.scope {
            Scope::Network => "Network configuration".to_string(),
            Scope::Node(_) => format!("{} · own configuration", doc.title),
        };
        let version = if doc.version == 0 {
            if is_node {
                "nothing set: the network's values apply".to_string()
            } else {
                "nothing applied yet".to_string()
            }
        } else {
            format!("version {}", doc.version)
        };
        let valid = matches!(c.check, Some(Ok(_)));
        let confirming = self.confirm == Some(Confirm::ApplyConfig);
        let show_eff = c.show_effective;

        let mut head = div()
            .flex()
            .items_center()
            .gap_2()
            .child(heading(&title))
            .child(muted(version).text_xs());
        if local {
            head = head.child(chip("this node", theme::ACCENT));
        } else if is_node {
            head = head.child(chip("remote", theme::RELAY));
        }
        if dirty {
            head = head.child(chip("edited", theme::WARN));
        }
        // Someone applied a newer network configuration since it was loaded.
        let stale = doc.scope == Scope::Network && s.tree.network_version > doc.version;
        if stale {
            head = head.child(chip(
                &format!("version {} is in force: reload", s.tree.network_version),
                theme::BAD,
            ));
        }

        let mut tools = div().flex().items_center().gap_2();
        if is_node {
            tools = tools.children(
                segmented(
                    "cfg-view",
                    &["own settings", "in force"],
                    usize::from(show_eff),
                )
                .into_iter()
                .enumerate()
                .map(|(i, d)| {
                    d.on_click(cx.listener(move |this, _, _, cx| {
                        this.config.show_effective = i == 1;
                        cx.notify();
                    }))
                }),
            );
        }
        tools = tools
            .child(div().flex_1())
            .child(
                button("cfg-reload", "Reload", !busy, theme::BORDER).on_click(cx.listener(
                    |this, _, _, cx| {
                        if this.config.dirty(cx)
                            && this.confirm != Some(Confirm::Discard(this.config.target.clone()))
                        {
                            this.confirm = Some(Confirm::Discard(this.config.target.clone()));
                            this.notice = Some((
                                false,
                                "Unapplied changes: click Reload again to discard them.".into(),
                            ));
                            cx.notify();
                            return;
                        }
                        this.notice = None;
                        this.config_load(this.config.target.clone(), cx);
                    },
                )),
            )
            .child(
                button("cfg-revert", "Revert", dirty && !busy, theme::BORDER).on_click(
                    cx.listener(|this, _, _, cx| {
                        if let Some(text) = this.config.loaded().map(|d| d.text.clone()) {
                            this.config.editor.update(cx, |e, cx| e.set_text(&text, cx));
                        }
                        this.confirm = None;
                        cx.notify();
                    }),
                ),
            )
            .child(
                button(
                    "cfg-apply",
                    if c.applying {
                        "Applying…"
                    } else if confirming {
                        "Click again to apply"
                    } else {
                        "Apply"
                    },
                    dirty && valid && !busy && !show_eff,
                    if confirming {
                        theme::WARN
                    } else {
                        theme::ACCENT
                    },
                )
                .on_click(cx.listener(|this, _, _, cx| {
                    let ready = this.config.dirty(cx)
                        && matches!(this.config.check, Some(Ok(_)))
                        && !this.config.applying
                        && !this.busy;
                    if !ready {
                        return;
                    }
                    if this.confirm == Some(Confirm::ApplyConfig) {
                        this.config_apply(cx);
                    } else {
                        this.confirm = Some(Confirm::ApplyConfig);
                        cx.notify();
                    }
                })),
            );

        let check = match (&c.check, show_eff) {
            (_, true) => muted(
                "What is in force for this node: the network's values with its own overrides and additions (read-only).",
            ),
            (Some(Ok(m)), _) if dirty => div().text_color(rgb(theme::OK)).child(format!("✓ {m}")),
            (Some(Ok(_)), _) => muted("No changes. Edit the file, then Apply."),
            (Some(Err(e)), _) => div().text_color(rgb(theme::BAD)).child(format!("✗ {e}")),
            (None, _) => muted(""),
        };
        let editor = if show_eff {
            c.effective.clone()
        } else {
            c.editor.clone()
        };
        let hint = if is_node {
            "Node settings: transport.priority, limits.value, seeds, dns.record, dns.forward and [[proxy]]. An empty file removes them. ⌘Z undo · ⌘/ comment · Tab indent"
        } else {
            "Sections: [policy], [dns], [[seeds]], [transport], [limits]. Sections left out stay as they are. ⌘Z undo · ⌘/ comment · Tab indent"
        };
        panel()
            .flex_1()
            .min_w(px(0.))
            .min_h(px(0.))
            .gap_2()
            .child(head)
            .child(tools)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h(px(0.))
                    .debug_selector(|| "config-editor".into())
                    .child(editor),
            )
            .child(check.text_xs())
            .child(muted(hint).text_xs())
            .into_any_element()
    }
}

async fn fetch(client: &Client, target: &Scope) -> anyhow::Result<Doc> {
    match target {
        Scope::Network => client.network_config().await,
        Scope::Node(id) => client.node_config(id).await,
    }
}
