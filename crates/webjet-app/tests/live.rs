//! The app's client against a running network: what the GUI does on sign-in
//! and on each button, without the window.
//!
//! Needs the local test network (`scripts/local-net.sh 2`); skipped when it
//! isn't running. `WEBJET_LOCAL_NET` points at another work directory.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use webjet_app::client::{self, Client, ops};
use webjet_app::model::Action;

fn net() -> Option<(Client, PathBuf)> {
    let dir = PathBuf::from(
        std::env::var("WEBJET_LOCAL_NET").unwrap_or_else(|_| "/tmp/webjet-local".into()),
    );
    let socket = dir.join("node-02").join("control.sock");
    if !socket.exists() {
        eprintln!(
            "skipped: no local test network at {} (scripts/local-net.sh 2)",
            dir.display()
        );
        return None;
    }
    Some((Client::new(socket), dir.join("keys")))
}

const PASS: &str = "acct-pass";

#[tokio::test]
async fn admin_and_member_against_a_live_network() {
    let Some((c, keys)) = net() else { return };
    let snap = c.snapshot().await.expect("snapshot");
    assert!(
        snap.nodes.len() >= 3,
        "nodes: {:?}",
        snap.nodes.iter().map(|n| &n.name).collect::<Vec<_>>()
    );
    assert!(snap.status.tree_version.is_some());
    assert!(
        snap.nodes.iter().all(|n| !n.owner_id.is_empty()),
        "owner ids are reported"
    );

    // Wrong passphrase and unknown account are refused.
    assert!(client::sign_in(&keys, "alice", "wrong", &snap).is_err());
    assert!(client::sign_in(&keys, "nobody", PASS, &snap).is_err());

    // The admin account gets everything.
    let admin = client::sign_in(&keys, "alice", PASS, &snap).expect("admin sign-in");
    assert!(admin.session.is_admin());

    // infra is a normal account that owns the nodes.
    let member = client::sign_in(&keys, "infra", PASS, &snap).expect("member sign-in");
    assert!(!member.session.is_admin());
    let mine = snap
        .nodes
        .iter()
        .find(|n| n.name == "node-03")
        .expect("node-03")
        .clone();
    assert!(member.session.may(&Action::RenameNode, Some(&mine)));
    assert!(!member.session.may(&Action::UpdateNode, Some(&mine)));
    assert!(!member.session.may(&Action::RotatePsk, None));

    // A member renames its own node; the controller accepts it.
    let renamed = "node-03-app";
    c.submit(ops::rename(&member.account, &mine, renamed).unwrap())
        .await
        .expect("member rename of own node");
    let after = wait_for(&c, |s| s.nodes.iter().any(|n| n.name == renamed)).await;
    let mine = after
        .nodes
        .iter()
        .find(|n| n.name == renamed)
        .unwrap()
        .clone();

    // The controller refuses what the app hides from members: tags are admin-only.
    let e = c
        .submit(ops::set_tags(&member.account, &mine, "tag:x").unwrap())
        .await
        .expect_err("member tag change refused");
    assert!(format!("{e:#}").contains("admin"), "{e:#}");

    // The admin can set tags and rename back.
    c.submit(ops::set_tags(&admin.account, &mine, "tag:app-test").unwrap())
        .await
        .expect("admin set tags");
    c.submit(ops::rename(&admin.account, &mine, "node-03").unwrap())
        .await
        .expect("admin rename");
    let fin = wait_for(&c, |s| {
        s.nodes
            .iter()
            .any(|n| n.name == "node-03" && n.tags.contains(&"tag:app-test".to_string()))
    })
    .await;
    assert!(fin.nodes.iter().any(|n| n.name == "node-03"));
}

async fn wait_for(
    c: &Client,
    ok: impl Fn(&webjet_app::model::Snapshot) -> bool,
) -> webjet_app::model::Snapshot {
    for _ in 0..100 {
        let s = c.snapshot().await.expect("snapshot");
        if ok(&s) {
            return s;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the change didn't arrive at the agent");
}
