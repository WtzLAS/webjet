# Webjet

A Rust implementation of the Webjet overlay VPN described in
[`docs/webjet-architecture.md`](docs/webjet-architecture.md) and
[`docs/webjet-operations-guide.md`](docs/webjet-operations-guide.md).

## Layout

| Crate | What it holds |
|---|---|
| `crates/webjet-proto` | FlatBuffers schemas (`schema/*.fbs`) and generated types; message-type registry |
| `crates/webjet-core` | Pure logic: Ed25519 envelopes and BLAKE3 derivations, sparse Merkle tree, trust store and merge rules, deterministic controller state machine, policy engine, routing (k-shortest paths, load, hysteresis), e2e frames and replay window, packet parsing/NAT/ICMP, conntrack, FQ-CoDel hop queue with ECN |
| `crates/webjet-net` | Transports: PSK gate and UDP obfuscation, raw-public-key TLS 1.3 with X25519MLKEM768 only, KCP + adaptive Reed–Solomon FEC with BBR-style pacing, AnyTLS (BoringSSL, Chrome-like ClientHello, camouflage website) |
| `crates/webjetd` | The agent: hop sessions, gossip and Merkle anti-entropy, circuits (label switching), end-to-end sessions, path probing, hole punching, tun data plane, gateway, magic DNS, metrics, controller role (Raft, signing, enrollment), local control socket |
| `crates/webjet-tools` | `webjetctl` (admin/node CLI), `webjet-root` (offline root key), `webjet-signer` (controller signing-key service) |

## Build

```sh
cargo build --release --workspace          # needs cmake + Go for BoringSSL (AnyTLS)
cargo build --release -p webjetd --no-default-features   # without AnyTLS
cargo test --workspace
```

Linux binaries via Docker: `docker build -f docker/Dockerfile -t webjet:test .`

## Try it

No root needed. `scripts/local-net.sh 3` builds a whole network on 127.0.0.1
by following runbook 1: root key, admin account, genesis, a bootstrap
controller/relay and three data nodes. The tun interface is disabled, and the
data plane answers pings itself.

```sh
cargo build --workspace
scripts/local-net.sh 3
export WEBJET_KEYS=/tmp/webjet-local/keys WEBJET_ACCOUNT_PASSPHRASE=acct-pass
target/debug/webjetctl --socket /tmp/webjet-local/node-02/control.sock peers
target/debug/webjetctl --socket /tmp/webjet-local/node-02/control.sock ping node-03
scripts/local-net.sh stop
```

`scripts/cluster-test.sh` turns two nodes into controllers: it signs their
certificates, adds them as learners and promotes them to voters. It then
stops the leader and checks that writes still commit.

`docker/e2e.sh` runs Linux containers with real tun interfaces. It checks
kernel ping across the overlay, magic DNS (including a CNAME to `node:`), a
deny policy, and a subnet gateway reaching a LAN host.
`docker/e2e.sh clean` removes the containers.

## Deploying

The operations guide's runbooks map to these commands:

```sh
# Root key holder (offline machine)
webjet-root --dir ./root init
webjet-root --dir ./root admin sign --name alice --key alice.pub --out alice.account
webjet-root --dir ./root genesis --overlay-pool 10.7.0.0/16 --admin alice.account --out genesis.wj
webjet-root --dir ./root controller sign ctl.req --out ctl.cert

# First controller
webjetd init --genesis genesis.wj && webjetd run
webjetctl account keygen --name alice --pub-out alice.pub
webjetctl node enroll --owner infra --name ctl-01 --roles data,relay --controller tls:203.0.113.5:443
webjetd enroll 'wj1:…'
webjetctl controller cert-request --out ctl.req;  webjetctl submit ctl.cert

# Everyday administration
webjetctl policy apply policy.yaml      # dns / seeds / limits / transport likewise
webjetctl node enroll --owner bob --name laptop --tags tag:laptop
webjetctl node revoke laptop;  webjetctl node rekey server-1
webjetctl psk rotate;  webjetctl controller add-learner ctl-02 / promote / demote / remove
```

The agent's configuration lives in `/etc/webjet/webjetd.toml` (see
`crates/webjetd/src/config.rs`). It covers listen addresses, public
addresses, tun, gateway routes, local limits and the controller role.

## Platform notes

* Linux: full support (tun, routes, gateway via iptables MASQUERADE, split
  DNS via `resolvectl`).
* macOS: utun interface, routes and `/etc/resolver` split DNS. Gateways are
  Linux-only.
* Identity keys are 0600 files. `WEBJET_KEY_WRAP=machine-id` binds them to
  the machine on Linux. TPM, Keychain and DPAPI sealing are not implemented.
