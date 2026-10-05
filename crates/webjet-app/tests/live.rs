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
use webjet_app::netconfig::Doc;

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

#[tokio::test]
async fn merkle_tree_and_operation_log_from_a_live_network() {
    use webjet_app::merkle::{Merkle, Names, Signer};
    let Some((c, keys)) = net() else { return };
    wait_for(&c, |s| s.nodes.len() >= 3).await;
    let s = c
        .snapshot(false, true)
        .await
        .expect("snapshot with the tree");
    let w = s.merkle.clone().expect("fetched").expect("merkle answered");
    assert_eq!(w.source, "head", "node-02 isn't a controller");
    assert_eq!(w.genesis.first_admin.as_deref(), Some("alice"));
    assert!(!w.certs.is_empty() && w.certs.iter().all(|c| c.valid));

    // The leaves rebuild the signed root (or the head moved meanwhile).
    let names = Names::new(&s, Some(&w));
    let m = Merkle::new(w, &names);
    assert!(
        m.matches_head()
            || m.wire
                .head
                .as_ref()
                .is_some_and(|h| h.version > s.status.tree_version.unwrap_or(0)),
        "leaves hash to the signed root"
    );
    assert_eq!(m.bad, 0);
    assert!(
        m.leaves.iter().all(|l| l.error.is_none()),
        "every leaf decodes"
    );
    for n in s.nodes.iter().filter(|n| n.valid) {
        let l = m
            .find(webjet_core::merkle::kind::NODE, &n.id)
            .expect("every node has a leaf");
        assert_eq!(l.title, n.name);
        let (_, ok) = m.proof(l);
        assert!(ok);
    }
    let alice = s.accounts.iter().find(|a| a.name == "alice").unwrap();
    let leaf = m
        .find(webjet_core::merkle::kind::ACCOUNT, &alice.id)
        .unwrap();
    assert_eq!(
        leaf.signer,
        Signer::Key {
            key: m.wire.genesis.root_key.clone(),
            who: "the root key".into()
        },
        "the first admin's record is root-signed"
    );

    // An admin reads the log through node-02 (forwarded to a controller).
    let admin = client::sign_in(&keys, "alice", PASS, &s).unwrap();
    let page = c
        .log(ops::log_request(&admin.account, 0, 50))
        .await
        .expect("admin reads the log");
    assert!(!page.records.is_empty() && page.records.len() <= 50);
    assert!(page.records.windows(2).all(|p| p[0].index < p[1].index));
    assert_eq!(page.records.last().unwrap().index, page.commit_index);
    let first = c
        .log(ops::log_request(&admin.account, 2, 50))
        .await
        .expect("older page");
    assert!(first.records.iter().all(|r| r.index < 2), "before = 2");
    // An uncompacted log starts with the leader's no-op, then genesis,
    // signed by the root key.
    if page.first_index == 1 {
        let g = c.log(ops::log_request(&admin.account, 3, 2)).await.unwrap();
        let t: Vec<(String, String)> = g
            .records
            .iter()
            .map(|r| (r.title(), r.signer(&names)))
            .collect();
        assert_eq!(
            t,
            [
                ("Noop".to_string(), "the controllers".to_string()),
                ("Genesis".to_string(), "the root key".to_string())
            ]
        );
    }
    // Some entry was signed by alice, and some wrote node leaves.
    let all = c
        .log(ops::log_request(&admin.account, 0, 200))
        .await
        .unwrap();
    assert!(
        all.records.iter().any(|r| r.signer(&names) == "admin alice"
            && r.account_id.as_deref() == Some(alice.id.as_str())),
        "{:?}",
        all.records
            .iter()
            .map(|r| (r.title(), r.signer(&names)))
            .collect::<Vec<_>>()
    );
    assert!(all.records.iter().any(|r| {
        r.leaves
            .iter()
            .any(|l| l.kind == webjet_core::merkle::kind::NODE)
    }));
    assert!(
        all.records
            .iter()
            .all(|r| r.description.is_some() || r.payload.is_none())
    );

    // A member's request is refused by the controller.
    let member = client::sign_in(&keys, "infra", PASS, &s).unwrap();
    let e = c
        .log(ops::log_request(&member.account, 0, 10))
        .await
        .expect_err("members don't read the log");
    assert!(format!("{e:#}").contains("only admins"), "{e:#}");
}

/// The Config tab's path: an admin edits the network configuration and a
/// remote node's own configuration through this agent, as the app does
/// (load, check, plan against what is in force, sign, submit).
#[tokio::test]
async fn admin_edits_network_and_remote_node_configuration() {
    let Some((c, keys)) = net() else { return };
    let snap = wait_for(&c, |s| s.nodes.iter().any(|n| n.name == "ctl-01")).await;
    let admin = client::sign_in(&keys, "alice", PASS, &snap).expect("admin sign-in");
    let sign = |plan: webjet_app::netconfig::Plan| -> Vec<Vec<u8>> {
        plan.ops()
            .into_iter()
            .map(|op| admin.account.sign(op).unwrap())
            .collect()
    };

    // The network: add a DNS record at the end of the file shown.
    let doc = c.network_config().await.expect("network config");
    let name = format!("app-{}.internal", std::process::id());
    let text = format!(
        "{}\n[[dns.record]]\nname = \"{name}\"\ntype = \"A\"\nvalue = \"10.7.9.9\"\n",
        doc.text.trim_end()
    );
    assert!(doc.check(&text).expect("valid").contains("dns"));
    let plan = doc.plan(&text).expect("plan").expect("something to apply");
    c.submit_all(sign(plan)).await.expect("applied");
    let after = wait_doc(|| c.network_config(), doc.version).await;
    assert!(after.text.contains(&name), "{}", after.text);
    // The same file again is now stale: refused before anything is signed.
    let e = after
        .plan(&text)
        .err()
        .expect("stale file refused")
        .to_string();
    assert!(e.contains("someone applied a change"), "{e}");

    // A remote node (ctl-01, seen from node-02's agent; the member test
    // renames node-03 meanwhile): its own transport
    // priority, then cleared again.
    let remote = snap.nodes.iter().find(|n| n.name == "ctl-01").unwrap();
    assert_ne!(remote.id, snap.status.node_id, "ctl-01 is remote here");
    let doc = c.node_config(&remote.id).await.expect("node config");
    assert_eq!(doc.title, "ctl-01");
    let text = format!("{}\n[transport.priority]\nkcp = 7\n", doc.text.trim_end());
    let text = if doc.version == 0 {
        text
    } else {
        // Left over from an earlier run: start from an empty file.
        format!("version = {}\n[transport.priority]\nkcp = 7\n", doc.version)
    };
    let plan = doc.plan(&text).expect("plan").expect("something to apply");
    c.submit_all(sign(plan)).await.expect("node config applied");
    let set = wait_doc(|| c.node_config(&remote.id), doc.version).await;
    assert!(set.text.contains("kcp = 7"), "{}", set.text);
    assert!(
        set.effective.as_deref().unwrap().contains("kcp = 7"),
        "in force for ctl-01"
    );
    let plan = set
        .plan(&format!("version = {}\n", set.version))
        .expect("plan")
        .expect("clears");
    assert_eq!(plan.describe(), "configuration of ctl-01 cleared");
    c.submit_all(sign(plan)).await.expect("cleared");
    let cleared = wait_doc(|| c.node_config(&remote.id), set.version).await;
    assert!(!cleared.text.contains("kcp = 7"), "{}", cleared.text);
}

/// Load a configuration until its version moves past `old`.
async fn wait_doc<F, Fut>(load: F, old: u64) -> Doc
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Doc>>,
{
    for _ in 0..100 {
        let d = load().await.expect("load");
        if d.version != old {
            return d;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the change didn't arrive at the agent");
}

async fn wait_for(
    c: &Client,
    ok: impl Fn(&webjet_app::model::Snapshot) -> bool,
) -> webjet_app::model::Snapshot {
    for _ in 0..100 {
        let s = c.snapshot(false, false).await.expect("snapshot");
        if ok(&s) {
            return s;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the change didn't arrive at the agent");
}
