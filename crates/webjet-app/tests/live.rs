//! The app's client against a running network: what the GUI does on sign-in
//! and on each button, without the window.
//!
//! Needs the local test network (`scripts/local-net.sh 2`); skipped when it
//! isn't running. `WEBJET_LOCAL_NET` points at another work directory.

#![cfg(unix)] // the local test network uses Unix control sockets
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use webjet_app::client::{self, Client, ops};
use webjet_app::model::Action;

fn net() -> Option<(Client, PathBuf)> {
    let dir = PathBuf::from(
        std::env::var("WEBJET_LOCAL_NET").unwrap_or_else(|_| "/tmp/webjet-local".into()),
    );
    let socket = dir.join("node-02").join("control.sock");
    // A socket file left by a stopped network doesn't count: an agent must answer.
    let alive = std::os::unix::net::UnixStream::connect(&socket).is_ok();
    if !alive {
        eprintln!(
            "skipped: no local test network running at {} (scripts/local-net.sh 2)",
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
    // A network that was just started may not have every node's record at
    // this agent yet.
    let snap = wait_for(&c, |s| s.nodes.len() >= 3).await;
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

#[tokio::test]
async fn tabs_data_from_a_live_network() {
    let Some((c, _)) = net() else { return };
    // The agent's hop to its relay and a session over a circuit.
    let s = wait_for(&c, |s| {
        !s.peers.is_empty()
            && s.sessions
                .as_ref()
                .is_ok_and(|x| x.sessions.iter().any(|e| e.established))
    })
    .await;
    let ss = s.sessions.as_ref().unwrap();
    assert!(!ss.circuits.local.is_empty(), "circuits are listed");
    assert!(ss.circuits.local.iter().all(|c| !c.peer_id.is_empty()));

    // Every node is in the graph; this agent's hops are edges.
    let g = webjet_app::graph::Graph::from_snapshot(&s);
    assert_eq!(g.vertices.len(), s.nodes.iter().filter(|n| n.valid).count());
    assert!(g.vertices.iter().any(|v| v.me));
    assert!(g.edges.iter().any(|e| e.mine()), "hops are edges");

    // The data plane tracks flows.
    let ct = s.conntrack.as_ref().unwrap();
    assert!(ct.running);
    assert!(ct.limits.global > 0);

    // The agent's own metrics parse into families.
    let fams = webjet_app::openmetrics::parse(s.metrics.as_ref().unwrap());
    assert!(
        fams.iter().any(|f| f.name.starts_with("webjet_")),
        "{fams:?}"
    );
    assert!(!s.metrics_all, "node-02 isn't a controller");

    let sum = s.summary();
    assert!(sum.nodes_active >= 3 && sum.hops >= 1 && sum.sessions_established >= 1);
}

async fn wait_for(
    c: &Client,
    ok: impl Fn(&webjet_app::model::Snapshot) -> bool,
) -> webjet_app::model::Snapshot {
    for _ in 0..100 {
        let s = c.snapshot(false).await.expect("snapshot");
        if ok(&s) {
            return s;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the change didn't arrive at the agent");
}
