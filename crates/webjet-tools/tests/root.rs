//! `webjetctl root`: every offline command against a key directory, and what
//! the files it writes contain. Runs the real binary; passphrases come from
//! the environment as in scripts.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};
use webjet_core::crypto::{self, KeyPair, open_envelope};
use webjet_proto::{self as wp, Decodable, msg_type as mt};

const ROOT_PASS: &str = "root-pass";
const BACKUP_PASS: &str = "backup-pass";

fn webjetctl(work: &Path, root_pass: &str, backup_pass: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_webjetctl"))
        .current_dir(work)
        .env("WEBJET_ROOT_PASSPHRASE", root_pass)
        .env("WEBJET_BACKUP_PASSPHRASE", backup_pass)
        .env("WEBJET_ACCOUNT_PASSPHRASE", "account-pass")
        .args(["--keys", "keys"])
        .args(args)
        .output()
        .unwrap()
}

fn ok(work: &Path, args: &[&str]) -> String {
    let o = webjetctl(work, ROOT_PASS, BACKUP_PASS, args);
    assert!(
        o.status.success(),
        "webjetctl {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap()
}

fn fails_with(work: &Path, root_pass: &str, backup_pass: &str, args: &[&str]) -> String {
    let o = webjetctl(work, root_pass, backup_pass, args);
    assert!(!o.status.success(), "webjetctl {args:?} succeeded");
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn fails(work: &Path, args: &[&str]) -> String {
    fails_with(work, ROOT_PASS, BACKUP_PASS, args)
}

/// `webjetctl root --dir <dir> <args>`.
fn root<'a>(dir: &'a str, args: &[&'a str]) -> Vec<&'a str> {
    let mut v = vec!["root", "--dir", dir];
    v.extend_from_slice(args);
    v
}

/// The root key's public half, from `root show`.
fn root_key(work: &Path, dir: &str) -> crypto::Bytes32 {
    let out = ok(work, &root(dir, &["show"]));
    let line = out.lines().find(|l| l.starts_with("root key:")).unwrap();
    crypto::parse_key_b64(line.split_whitespace().last().unwrap()).unwrap()
}

fn file(work: &Path, name: &str) -> Vec<u8> {
    std::fs::read(work.join(name)).unwrap()
}

#[test]
fn offline_root_workflow() {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    let r = "rk";
    ok(w, &root(r, &["init"]));
    let msg = fails(w, &root(r, &["init"]));
    assert!(msg.contains("already holds keys"), "{msg}");
    // The keys are encrypted at rest; the wrong passphrase opens nothing.
    for f in ["root.key.enc", "emergency.key.enc", "emergency.cert"] {
        assert!(w.join(r).join(f).exists(), "{f}");
    }
    fails_with(w, "wrong", BACKUP_PASS, &root(r, &["show"]));
    let rk = root_key(w, r);

    // The first admin: a key made on the admin's machine, signed by the root.
    ok(
        w,
        &[
            "network",
            "account",
            "keygen",
            "--name",
            "alice",
            "--pub-out",
            "alice.pub",
        ],
    );
    ok(
        w,
        &root(
            r,
            &[
                "admin",
                "sign",
                "--name",
                "alice",
                "--key",
                "alice.pub",
                "--out",
                "alice.admin",
            ],
        ),
    );
    let v = crypto::open_expect(&file(w, "alice.admin"), mt::ACCOUNT_RECORD, &[rk]).unwrap();
    let admin: wp::AccountRecord = v.decode().unwrap();
    assert!(admin.admin && admin.issuer_root);
    assert_eq!(admin.name.as_deref(), Some("alice"));

    // The genesis names the root, the emergency key and the admin.
    let msg = fails(
        w,
        &root(
            r,
            &["genesis", "--admin", "alice.admin", "--out", "genesis.wj"],
        ),
    );
    assert!(msg.contains("--overlay-pool"), "{msg}");
    ok(
        w,
        &root(
            r,
            &[
                "genesis",
                "--overlay-pool",
                "10.7.0.0/16",
                "--admin",
                "alice.admin",
                "--out",
                "genesis.wj",
            ],
        ),
    );
    let raw = file(w, "genesis.wj");
    let (g, groot, emergency) = webjet_core::store::open_genesis(&raw).unwrap();
    let emergency = emergency.expect("emergency key");
    assert_eq!(groot, rk);
    assert_ne!(emergency, rk);
    assert_eq!(g.overlay_pool.unwrap().len(), 1);
    webjet_core::store::Store::new(raw).unwrap();
    // A record that isn't root-signed can't found a network.
    let other = KeyPair::generate();
    std::fs::write(
        w.join("bob.rec"),
        other.sign_obj(mt::ACCOUNT_RECORD, &admin),
    )
    .unwrap();
    fails(
        w,
        &root(
            r,
            &[
                "genesis",
                "--overlay-pool",
                "10.7.0.0/16",
                "--admin",
                "bob.rec",
                "--out",
                "g2.wj",
            ],
        ),
    );
    assert!(!w.join("g2.wj").exists());

    // Emergency node tombstone (default key: emergency).
    let node = hex::encode([7u8; 32]);
    ok(
        w,
        &root(
            r,
            &[
                "node",
                "revoke",
                "--node",
                &node,
                "--reason",
                "lost",
                "--out",
                "node.tomb",
            ],
        ),
    );
    let v = open_envelope(&file(w, "node.tomb")).unwrap();
    assert_eq!((v.ty, v.signer), (mt::TOMBSTONE, emergency));
    let t: wp::Tombstone = v.decode().unwrap();
    assert_eq!(crypto::opt_k32(&t.node_id), [7; 32]);
    assert_eq!(t.reason.as_deref(), Some("lost"));
    let msg = fails(
        w,
        &root(r, &["node", "revoke", "--node", "abc", "--out", "x"]),
    );
    assert!(msg.contains("64 hex"), "{msg}");
    let msg = fails(
        w,
        &root(
            r,
            &[
                "node", "revoke", "--node", &node, "--with", "admin", "--out", "x",
            ],
        ),
    );
    assert!(msg.contains("root or emergency"), "{msg}");

    // Account tombstones by .pub file or by id (default key: root).
    ok(
        w,
        &root(
            r,
            &[
                "account",
                "revoke",
                "--key",
                "alice.pub",
                "--revoke-issued",
                "--out",
                "a.tomb",
            ],
        ),
    );
    let v = open_envelope(&file(w, "a.tomb")).unwrap();
    assert_eq!((v.ty, v.signer), (mt::ACCOUNT_TOMBSTONE, rk));
    let t: wp::AccountTombstone = v.decode().unwrap();
    assert!(t.revoke_issued);
    assert_eq!(t.account_id, admin.account_id);
    let id = hex::encode(crypto::opt_k32(&admin.account_id));
    ok(
        w,
        &root(
            r,
            &[
                "admin",
                "revoke",
                "--key",
                &id,
                "--with",
                "emergency",
                "--out",
                "b.tomb",
            ],
        ),
    );
    let v = open_envelope(&file(w, "b.tomb")).unwrap();
    assert_eq!(v.signer, emergency);

    // A controller's certificate request, certified by the root.
    let sk = KeyPair::generate();
    let body = wp::SigningKeyCert {
        signing_key_id: Some(crypto::k32(&crypto::signing_key_id(&sk.public()))),
        signing_key: Some(crypto::k32(&sk.public())),
        controller: Some(crypto::k32(&[9; 32])),
        cert_serial: 1,
        issuer: None,
    };
    std::fs::write(w.join("ctl.req"), sk.sign_obj(mt::CERT_REQUEST, &body)).unwrap();
    let out = ok(
        w,
        &root(r, &["controller", "sign", "ctl.req", "--out", "ctl.cert"]),
    );
    assert!(out.contains(&hex::encode([9u8; 32])), "{out}");
    let v = crypto::open_expect(&file(w, "ctl.cert"), mt::SIGNING_KEY_CERT, &[rk]).unwrap();
    let cert = wp::SigningKeyCert::decode_bytes(&v.body).unwrap();
    assert_eq!(cert.signing_key, body.signing_key);
    // A request signed by another key than the one it names is refused.
    std::fs::write(w.join("bad.req"), other.sign_obj(mt::CERT_REQUEST, &body)).unwrap();
    fails(
        w,
        &root(r, &["controller", "sign", "bad.req", "--out", "bad.cert"]),
    );
    assert!(!w.join("bad.cert").exists());

    // Retiring a signing key.
    let kid = hex::encode(crypto::signing_key_id(&sk.public()));
    ok(
        w,
        &root(
            r,
            &[
                "controller",
                "retire",
                "--key-id",
                &kid,
                "--last-valid-version",
                "12",
                "--out",
                "k.tomb",
            ],
        ),
    );
    let v = open_envelope(&file(w, "k.tomb")).unwrap();
    assert_eq!((v.ty, v.signer), (mt::SIGNING_KEY_TOMBSTONE, rk));
    let t: wp::SigningKeyTombstone = v.decode().unwrap();
    assert_eq!(t.last_valid_version, 12);

    // A StateVersion for a schema-change release.
    ok(
        w,
        &root(
            r,
            &["state-version", "sign", "--version", "2", "--out", "sv"],
        ),
    );
    let v = crypto::open_expect(&file(w, "sv"), mt::STATE_VERSION, &[rk]).unwrap();
    let sv: wp::StateVersion = v.decode().unwrap();
    assert_eq!(
        (sv.version, sv.state_machine, sv.min_wire_protocol),
        (2, 2, 1)
    );
}

#[test]
fn backup_and_restore() {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    ok(w, &root("a", &["init"]));
    let rk = root_key(w, "a");
    ok(w, &root("a", &["backup", "--out", "keys.bak"]));
    ok(w, &root("b", &["restore", "--from", "keys.bak"]));
    assert_eq!(root_key(w, "b"), rk);
    assert!(w.join("b/emergency.cert").exists());
    // The wrong backup passphrase restores nothing.
    fails_with(
        w,
        ROOT_PASS,
        "wrong",
        &root("c", &["restore", "--from", "keys.bak"]),
    );
    assert!(!w.join("c/root.key.enc").exists());
    // A damaged backup is refused.
    std::fs::write(
        w.join("short.bak"),
        webjet_tools::seal(BACKUP_PASS, &[1; 10]).unwrap(),
    )
    .unwrap();
    let msg = fails(w, &root("d", &["restore", "--from", "short.bak"]));
    assert!(msg.contains("damaged backup"), "{msg}");
}
