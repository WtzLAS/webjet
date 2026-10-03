# Webjet

A Rust implementation of the Webjet overlay VPN described in
[`docs/webjet-architecture.md`](docs/webjet-architecture.md) and
[`docs/webjet-operations-guide.md`](docs/webjet-operations-guide.md).

| Document | For |
| --- | --- |
| [docs/webjet-operations-guide.md](docs/webjet-operations-guide.md) | Runbooks: bootstrap, add relays and controllers, revoke, re-key, upgrades |
| [docs/configuration.md](docs/configuration.md) | Every `webjetd.toml` setting |
| [docs/docker.md](docs/docker.md) | Running nodes and controllers in containers |
| [docs/app.md](docs/app.md) | The desktop app (`webjet-app`) |
| [docs/development.md](docs/development.md) | Building, testing, conventions and pitfalls for contributors |

## Layout

| Crate | What it holds |
| --- | --- |
| `crates/webjet-proto` | FlatBuffers schemas (`schema/*.fbs`) and generated types; message-type registry |
| `crates/webjet-core` | Pure logic: Ed25519 envelopes and BLAKE3 derivations, sparse Merkle tree, trust store and merge rules, deterministic controller state machine, policy engine, routing (k-shortest paths, load, hysteresis), e2e frames and replay window, packet parsing/NAT/ICMP, conntrack, FQ-CoDel hop queue with ECN |
| `crates/webjet-net` | Transports: PSK gate and UDP obfuscation, raw-public-key TLS 1.3 with X25519MLKEM768 only, KCP + adaptive Reed–Solomon FEC with BBR-style pacing, AnyTLS (BoringSSL, Chrome-like ClientHello, camouflage website) |
| `crates/webjetd` | The agent: hop sessions, gossip and Merkle anti-entropy, circuits (label switching), end-to-end sessions, path probing, hole punching, tun data plane, gateway, magic DNS, metrics, controller role (Raft, signing, enrollment), local control socket |
| `crates/webjet-tools` | `webjetctl` (admin/node CLI), `webjet-root` (offline root key), `webjet-signer` (controller signing-key service) |
| `crates/webjet-app` | `webjet-app`, a GPUI desktop app: network overview, nodes, accounts; admin or read-only by account |

## Build

```sh
cargo build --release --workspace          # needs cmake + Go for BoringSSL (AnyTLS)
cargo build --release -p webjetd --no-default-features   # without AnyTLS
cargo test --workspace
```

## Docker

```sh
docker build -t webjet .                       # deployment image
docker build --build-arg ANYTLS=0 -t webjet .  # without AnyTLS (faster build)
docker build --target test -t webjet:test .    # plus debugging tools and test scripts
```

A node in a container needs NET_ADMIN, the tun device and a volume for its
state, and enrolls itself on first start:

```sh
docker run -d --name webjet --restart unless-stopped \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v webjet-state:/var/lib/webjet \
  -e WEBJET_ENROLL="<enrollment string>" \
  webjet
docker exec webjet webjetctl status
```

[docs/docker.md](docs/docker.md) covers relays and published ports, the first
controller (`WEBJET_GENESIS`), the signer container, every `WEBJET_*`
setting, DNS and upgrades. `docker/compose.example.yaml` is a Compose
starting point.

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

`docker/e2e.sh` runs Linux containers with real tun interfaces (image
`webjet:test`, see above). It checks kernel ping across the overlay, magic DNS
(including a CNAME to `node:`), a deny policy, and a subnet gateway reaching
a LAN host. `docker/e2e.sh clean` removes the containers.

`docker/deploy-test.sh` checks the deployment image the way docs/docker.md
uses it: a first controller from `WEBJET_GENESIS`, a node enrolled with
`WEBJET_ENROLL`, health checks, a restart and a clean stop.

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

The agent's configuration lives in `/etc/webjet/webjetd.toml`; every setting
is described in [docs/configuration.md](docs/configuration.md).

## Installing a release

Releases are published at
<https://forgejo.wolf109909.top/webj8/webjet/releases> with binaries for
Linux (x86_64 and aarch64, glibc 2.31+: Debian 11+, Ubuntu 20.04+, RHEL 9+),
macOS (x86_64 and aarch64) and Windows (x86_64). Install or upgrade a Linux
or macOS host as root from a
checkout of the release tag:

```sh
git clone https://forgejo.wolf109909.top/webj8/webjet.git && cd webjet
git checkout v0.1.0
WEBJET_RELEASE_URL=https://forgejo.wolf109909.top/webj8/webjet/releases/download \
  ./scripts/upgrade.sh v0.1.0
```

`upgrade.sh` downloads `webjet-<tag>-<target>.tar.gz`, checks it against the
`.sha256` next to it, installs the four binaries into `/usr/local/bin` and
sets up the systemd unit (Linux) or launchd daemon (macOS).
`./scripts/upgrade.sh --uninstall` removes them again.

On Windows, in PowerShell as Administrator from the same checkout:

```powershell
$env:WEBJET_RELEASE_URL = "https://forgejo.wolf109909.top/webj8/webjet/releases/download"
.\scripts\upgrade.ps1 v0.1.0
```

It installs the programs and `wintun.dll` into `%ProgramFiles%\Webjet` and
registers the `webjetd` service. The zip includes Wintun from wintun.net
with its license (`wintun-LICENSE.txt`).

## Platform notes

| Platform | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Install / upgrade | `scripts/upgrade.sh` (systemd unit, `webjet` user, `CAP_NET_ADMIN`) | `scripts/upgrade.sh` (launchd daemon) | `scripts/upgrade.ps1` (LocalSystem service via `webjetd install`) |
| Interface | `/dev/net/tun` | `utun` | Wintun (`wintun.dll` next to `webjetd.exe`) |
| Split DNS | `resolvectl` | `/etc/resolver/<domain>` | NRPT rules tagged `webjet` |
| Control channel | Unix socket, 0600 | Unix socket, 0600 | named pipe `\\.\pipe\webjet`, SYSTEM + Administrators |
| Key storage (`[key] storage`) | `tpm` (tpm2-tools) when a TPM is usable, else `file` | `keychain` (System keychain) | `dpapi` (machine scope) |
| Roles | all | DATA | DATA |

Routes and split DNS are removed when the agent stops; `upgrade.sh
--uninstall` / `upgrade.ps1 -Uninstall` remove the service as well.

### Identity key storage (§8.3)

`webjetd.toml`:

```toml
[key]
storage = "auto"   # auto | tpm | keychain | dpapi | file
```

`auto` picks the platform store and falls back to a private file (with a
warning) when it can't be used, e.g. no TPM access. Sealed keys are
device-bound. A key copied or restored onto another machine is refused, with
a message to re-key the node. In memory the key is `mlock`ed / `VirtualLock`ed
and core dumps are disabled. `docker/tpm-test.sh` checks the TPM backend
against a software TPM, including refusal by a second TPM.

### Metrics (§12.5)

```toml
[metrics]
listen = "127.0.0.1:9469"
```

On a controller, `GET /metrics` returns the latest report of **every** node
in OpenMetrics text. Reports are shared between controllers, so any of them
is a complete scrape target. Elsewhere it returns the node's own metrics, and
a relay leaves out per-route series. Samples carry the report's timestamp.
`webjetctl metrics [--all]` prints the same text.

```yaml
scrape_configs:
  - job_name: webjet
    honor_timestamps: true
    static_configs: [{ targets: ["10.7.0.1:9469", "10.7.0.2:9469"] }]
```

### Raft

`crates/webjetd/src/controller/raft.rs` is a deterministic core: time is passed
in, randomness comes from a seeded RNG, and storage can be in memory. It
supports pre-vote, check-quorum, and membership tracked from the log. Its
tests (`raft_tests.rs`) include targeted scenarios plus a simulator that
injects crashes, restarts, partitions, loss, duplication, reordering,
snapshots and membership changes. After every step it checks election safety,
log matching, leader completeness, state-machine safety and configuration
agreement, and once faults stop it checks liveness.

```sh
cargo test -p webjetd --lib raft
WEBJET_RAFT_SEEDS=2000 cargo test --release -p webjetd --lib randomized   # soak
scripts/raft-mutations.py   # re-introduces 10 classic Raft bugs; each must be caught
```

### Windows builds and tests

```sh
cargo xwin build --release --target x86_64-pc-windows-msvc -p webjetd -p webjet-tools
docker/windows-test.sh     # unit tests (DPAPI, named pipes, ACLs, ...) under Wine
```
