//! Accounts: every account of the network, and the selected one's record
//! and nodes.

use super::*;

impl WebjetApp {
    pub(super) fn render_accounts(&mut self, s: &Snapshot, cx: &mut Context<Self>) -> AnyElement {
        let me = self.signed_in.as_ref().map(|si| si.session.id.clone());
        // Admins see every account; a normal account only its own.
        let admin = self.is_admin();
        let accounts: Vec<&model::Account> = s
            .accounts
            .iter()
            .filter(|a| admin || me.as_deref() == Some(a.id.as_str()))
            .collect();
        if !admin && self.account.is_none() {
            self.account = me.clone();
        }
        let active = accounts.iter().filter(|a| a.valid).count();
        let admins = accounts.iter().filter(|a| a.valid && a.admin).count();
        let mut list = scroll("accounts").gap(px(1.));
        for (i, a) in accounts.iter().enumerate() {
            let sel = self.account.as_deref() == Some(a.id.as_str());
            let id = a.id.clone();
            let owned = s.owned_by(&a.id).len();
            list = list.child(
                div()
                    .id(("acct", i))
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_2()
                    .py(px(3.))
                    .rounded_sm()
                    .cursor_pointer()
                    .bg(rgb(if sel { theme::RAISED } else { theme::PANEL }))
                    .hover(|s| s.bg(rgb(theme::RAISED)))
                    .child(dot(if a.valid { theme::OK } else { theme::BAD }))
                    .child(
                        cell(
                            150.,
                            if me.as_deref() == Some(a.id.as_str()) {
                                format!("{} (you)", a.name)
                            } else {
                                a.name.clone()
                            },
                        )
                        .text_color(rgb(if a.valid {
                            theme::TEXT
                        } else {
                            theme::MUTED
                        })),
                    )
                    .child(
                        cell(70., if a.admin { "admin" } else { "member" }).text_color(rgb(
                            if a.admin {
                                theme::CONTROL
                            } else {
                                theme::MUTED
                            },
                        )),
                    )
                    .child(
                        cell(70., if a.valid { "active" } else { "revoked" })
                            .text_color(rgb(if a.valid { theme::OK } else { theme::BAD })),
                    )
                    .child(muted(format!("{owned} nodes")).text_xs())
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.account = Some(id.clone());
                        cx.notify();
                    })),
            );
        }
        if accounts.is_empty() {
            list = list.child(muted("No accounts known yet."));
        }
        let left = panel()
            .w(px(440.))
            .flex_shrink_0()
            .h_full()
            .child(
                div()
                    .flex()
                    .justify_between()
                    .child(heading("Accounts"))
                    .child(
                        muted(format!(
                            "{active} active · {admins} admins · {} revoked",
                            accounts.len() - active
                        ))
                        .text_xs(),
                    ),
            )
            .child(header_row(&[
                (8., ""),
                (150., "name"),
                (70., "role"),
                (70., "status"),
                (60., "nodes"),
            ]))
            .child(list);

        let right = match self
            .account
            .as_deref()
            .and_then(|id| accounts.iter().find(|a| a.id == id))
        {
            None => panel()
                .flex_1()
                .child(muted("Select an account to see its record and nodes."))
                .child(div().pt_2().child(muted(
                    "Accounts are added with `webjetctl network account create` (members) or a root-signed record (admins).",
                )))
                .into_any_element(),
            Some(a) => {
                let nodes: Vec<&model::Node> =
                    s.nodes.iter().filter(|n| n.owner_id == a.id).collect();
                let mut p = panel()
                    .flex_1()
                    .min_w(px(0.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(heading(&a.name))
                            .child(if a.admin {
                                chip("admin", theme::CONTROL)
                            } else {
                                chip("member", theme::MUTED)
                            })
                            .child(if a.valid {
                                chip("active", theme::OK)
                            } else {
                                chip("revoked", theme::BAD)
                            }),
                    )
                    .child(label_value("Account id", a.id.clone()))
                    .child(label_value("Key", a.key.clone()))
                    .child(label_value("Record version", a.version.to_string()))
                    .child(label_value(
                        "May",
                        if !a.valid {
                            "nothing: the account is revoked"
                        } else if a.admin {
                            "every operation (nodes, accounts, network configuration, PSK)"
                        } else {
                            "read; rename and revoke the nodes it owns"
                        },
                    ))
                    .child(label_value(
                        "Nodes",
                        format!(
                            "{} active, {} revoked or replaced",
                            nodes.iter().filter(|n| n.valid).count(),
                            nodes.iter().filter(|n| !n.valid).count()
                        ),
                    ))
                    .child(div().pt_2().child(heading("Nodes")));
                if nodes.is_empty() {
                    p = p.child(muted("This account owns no nodes."));
                }
                for (i, n) in nodes.iter().enumerate() {
                    let id = n.id.clone();
                    p = p.child(
                        div()
                            .id(("acct-node", i))
                            .flex()
                            .items_center()
                            .gap_2()
                            .px_2()
                            .py(px(2.))
                            .rounded_sm()
                            .cursor_pointer()
                            .hover(|s| s.bg(rgb(theme::RAISED)))
                            .child(dot(if n.valid { theme::OK } else { theme::BAD }))
                            .child(cell(150., n.name.clone()))
                            .child(cell(130., n.ips.join(", ")).text_color(rgb(theme::MUTED)))
                            .child(cell(140., n.roles()).text_color(rgb(theme::MUTED)))
                            .child(muted(n.tags.join(", ")).text_xs())
                            .on_click(cx.listener(move |this, _, _, cx| this.show_node(id.clone(), cx))),
                    );
                }
                p.into_any_element()
            }
        };
        let note = if admin {
            muted("Accounts are changed with webjetctl; the app shows them read-only.")
        } else {
            muted("Your account only: admins see every account of the network.")
        };
        div()
            .flex()
            .flex_col()
            .gap_2()
            .size_full()
            .child(
                div()
                    .flex()
                    .gap_3()
                    .flex_1()
                    .min_h(px(0.))
                    .child(left)
                    .child(right),
            )
            .child(note.text_xs())
            .into_any_element()
    }
}
