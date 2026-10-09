# Webjet

A Rust implementation of the Webjet overlay VPN described in
[`docs/webjet-architecture.md`](docs/webjet-architecture.md) and
[`docs/webjet-operations-guide.md`](docs/webjet-operations-guide.md).

| Document | For |
| --- | --- |
| [docs/webjet-operations-guide.md](docs/webjet-operations-guide.md) | Operations guide: accounts, nodes (bootstrap, relays, controllers, gateways, revoke, re-key), maintenance, emergencies |
| [docs/configuration.md](docs/configuration.md) | Every `webjetd.toml` setting |
| [docs/docker.md](docs/docker.md) | Running nodes and controllers in containers |
| [docs/app.md](docs/app.md) | The desktop app (`webjet-app`) |
| [docs/development.md](docs/development.md) | Building, testing, conventions and pitfalls for contributors |

## Layout

| Crate | What it holds |
| --- | --- |
| `crates/webjet-proto` | FlatBuffers schemas (`schema/*.fbs`) and generated types; message-type registry |
| `crates/webjet-core` | Pure logic: Ed25519 envelopes and BLAKE3 derivations, sparse Merkle tree, trust store and merge rules, deterministic controller state machine, policy engine, routing (k-shortest paths, load, hysteresis), e2e frames and replay window, packet parsing/NAT/ICMP, conntrack, FQ-CoDel hop queue with ECN, compression (zstd control plane, per-packet LZ4 data plane) |
| `crates/webjet-net` | Transports: PSK gate and UDP obfuscation, raw-public-key TLS 1.3 with X25519MLKEM768 only, KCP + adaptive Reed–Solomon FEC with BBR-style pacing, AnyTLS (BoringSSL, Chrome-like ClientHello, camouflage website) |
| `crates/webjetd` | The agent: hop sessions, gossip and Merkle anti-entropy, circuits (label switching), end-to-end sessions, path probing, hole punching, tun data plane, gateway, magic DNS, metrics, controller role (Raft, signing, enrollment), local control socket |
| `crates/webjet-tools` | `webjetctl`: `network` (configuration and administration), `local` (this machine and node), `root` (offline keys); the TOML configuration documents |
| `crates/webjet-app` | `webjet-app`, a GPUI desktop app: dashboard, connections, network graph and circuits, Merkle tree and log, metrics, accounts, and for admins a configuration editor (network and any node); admin or read-only by account |

## Programs

| Program | Commands |
| --- | --- |
| `webjetup` | `install` / `upgrade`, `enroll`, `status`, `list`, `remove`, `nuke`: installs and removes Webjet, including the system service (systemd, launchd, Windows service) |
| `webjetd` | `run`: the agent. `signer`: holds a controller's signing key in a separate process (§19.2) |
| `webjetctl` | `network` — the whole network, signed with an account key: `config` (policy, DNS, seeds, transport, limits as one TOML document), `account`, `node`, `controller`, `psk`, `camouflage`, `submit`. `local` — this machine and its node: `init` (first controller), `enroll` (join or re-key), `status`, `peers`, `sessions`, `metrics`, `ping`, `inject`, and `config` (the node's own overrides of the network configuration). `root` — offline root and emergency keys: `init`, `backup`, `restore`, `show`, `genesis`, `admin`, `controller`, `account`, `node`, `state-version` |

In 0.4.0 `webjetctl` was regrouped into `network`, `local` and `root`, and the
five YAML settings files (`policy`, `dns`, `seeds`, `limits`, `transport`)
became one TOML network configuration; `[transport]` and `[limits]` moved out
of `webjetd.toml` into each node's configuration (`webjetctl local config`).
Before 0.3.0, `webjetctl root` was a separate `webjet-root`, `webjetd signer`
was `webjet-signer`, and `webjetctl init`/`enroll` were `webjetd init`/`enroll`;
`webjetup` removes the old programs when it upgrades.

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
docker exec webjet webjetctl local status
```

[docs/docker.md](docs/docker.md) covers relays and published ports, the first
controller (`WEBJET_GENESIS`), the signer container, every `WEBJET_*`
setting, DNS and upgrades. `docker/compose.example.yaml` is a Compose
starting point.

## Try it

No root needed. `scripts/local-net.sh 3` builds a whole network on 127.0.0.1
by following section 2.1 of the operations guide: root key, admin account, genesis, a bootstrap
controller/relay and three data nodes. The tun interface is disabled, and the
data plane answers pings itself.

```sh
cargo build --workspace
scripts/local-net.sh 3
export WEBJET_KEYS=/tmp/webjet-local/keys WEBJET_ACCOUNT_PASSPHRASE=acct-pass
target/debug/webjetctl --socket /tmp/webjet-local/node-02/control.sock local peers
target/debug/webjetctl --socket /tmp/webjet-local/node-02/control.sock local ping node-03
scripts/local-net.sh stop
```

`scripts/cluster-test.sh` turns two nodes into controllers: it signs their
certificates and waits for the leader to add them and make them voters by
itself (automatic membership). It then stops the leader and checks that
writes still commit.

`docker/e2e.sh` runs Linux containers with real tun interfaces (image
`webjet:test`, see above). It checks kernel ping across the overlay, magic DNS
(including a CNAME to `node:`), a deny policy, and a subnet gateway reaching
a LAN host. `docker/e2e.sh clean` removes the containers.

`docker/deploy-test.sh` checks the deployment image the way docs/docker.md
uses it: a first controller from `WEBJET_GENESIS`, a node enrolled with
`WEBJET_ENROLL`, health checks, a restart and a clean stop.

## Deploying

The operations guide maps to these commands:

```sh
# Root key holder (offline machine)
webjetctl root --dir ./root init
webjetctl root --dir ./root admin sign --name alice --key alice.pub --out alice.account
webjetctl root --dir ./root genesis --overlay-pool 10.7.0.0/16 --admin alice.account --out genesis.wj
webjetctl root --dir ./root controller sign ctl.req --out ctl.cert   # optional: admins can certify controllers

# First controller
webjetctl local init --genesis genesis.wj && webjetd run
webjetctl network account keygen --name alice --pub-out alice.pub
webjetctl network node enroll --owner infra --name ctl-01 --roles data,relay,control --controller tls:203.0.113.5:443
webjetctl local enroll 'wj1:…'
webjetctl network controller certify ctl-01     # admin-signed; or cert-request + root sign + submit

# Everyday administration
webjetctl network config edit           # policy, DNS, seeds, transport, limits: one TOML document
webjetctl local config --node relay-1 set limits.value.relay_capacity_mbps 900   # one node's override
webjetctl network node enroll --owner bob --name laptop --tags tag:laptop
webjetctl network node revoke laptop;  webjetctl network node rekey server-1
webjetctl network account rekey bob --key bob-new.pub   # a lost account key; admins: root admin sign --replaces
webjetctl network psk rotate;  webjetctl network controller add-learner ctl-02 / promote / demote / remove   # by hand; the leader does it by default ([controllers])
```

The agent's configuration lives in `/etc/webjet/webjetd.toml`; every setting
is described in [docs/configuration.md](docs/configuration.md).

## Installing a release

Releases are published at
<https://forgejo.wolf109909.top/webj8/webjet/releases> with binaries for
Linux (x86_64 and aarch64, glibc 2.31+: Debian 11+, Ubuntu 20.04+, RHEL 9+),
macOS (x86_64 and aarch64), Windows (x86_64) and, from 0.11.0, FreeBSD 14 /
OPNsense 24.7+ (x86_64). From 0.11.0 they also include the desktop app
(`webjet-app-<tag>-<target>`, [docs/app.md](docs/app.md)).

`webjetup` installs, upgrades and removes Webjet. On Linux, macOS and
FreeBSD, as root:

```sh
curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.11.4/install.sh | sudo sh
sudo webjetup enroll 'wj1:…'                 # the string from `webjetctl network node enroll`
```

Any release's `install.sh` works: it installs the latest release unless told
otherwise (Forgejo has no "latest" download link, so the URL names a tag).
It downloads `webjetup` for the machine, checks it against its `.sha256` and
runs `webjetup install`. Arguments go to `webjetup install`, so
`… | sudo sh -s -- --enroll 'wj1:…'` installs and enrolls in one step, and
`… | sudo sh -s -- v0.11.4` picks a version.

Behind a proxy, `webjetup` (and `webjetctl network node upgrade`) take it
from the first variable that is set among `https_proxy`, `all_proxy` and
`http_proxy` (either case), and skip the hosts in `no_proxy`. They accept
`http://`, `https://`, `socks4://` and `socks5://` proxies (also `socks4a://`,
`socks5h://` and `socks://`). A SOCKS proxy always gets the host name, so a
lookup on the machine itself can't send the download elsewhere. `sudo` drops
these variables, so pass them on: `curl … | sudo env all_proxy=$all_proxy sh`
or `sudo env https_proxy=$https_proxy webjetup upgrade`. `install.sh`
downloads with curl, which only gives the host name to a SOCKS5 proxy written
as `socks5h://`. If a download fails with "invalid peer certificate", the
machine reached something other than the release server: a proxy that isn't
used, a filter or a wrong DNS answer.

On Windows, download `webjetup-<tag>-x86_64-pc-windows-msvc.exe` from the
release page and, in an Administrator prompt:

```powershell
.\webjetup-v0.11.4-x86_64-pc-windows-msvc.exe install --enroll "wj1:…"
```

Then, on any platform:

| Command | What it does |
| --- | --- |
| `webjetup install [VERSION]` (alias `upgrade`) | Install or upgrade to VERSION (default: latest). Downloads `webjet-<tag>-<target>.tar.gz` (Windows: `.zip`), checks its SHA-256, checks that the new `webjetd` runs, then stops the agent, replaces the programs and starts it again. Sets up the systemd unit and `webjet` user (Linux), the launchd daemon (macOS), the service, PATH and folder ACLs (Windows) or the rc.d service (FreeBSD). `--enroll` enrolls in the same step, `--from` installs from a local archive or directory, `--force` reinstalls the same version. On a controller, `--signer` adds the signer service, which holds the signing key in its own process (`webjetd signer`), and points the agent at it; later upgrades keep it. From 0.9.0 it also sets up the remote upgrade helper, which lets admins upgrade the node with `webjetctl network node upgrade` (signed per node, pinned checksums, forward only, automatic rollback); `--no-remote-upgrade` turns that off and `--remote-upgrade` back on, and later upgrades keep the choice. |
| `webjetup enroll <STRING>` | Enroll this node (or re-key it, operations guide 2.7) and start the agent. |
| `webjetup status` | Installed version, service state, enrollment, remote upgrades and the last one, this node's name and addresses. |
| `webjetup list` | Published releases. |
| `webjetup remove` (alias `uninstall`) | Stop the agent and remove the programs and service. The node's identity and state stay, so `webjetup install` brings it back as the same node. |
| `webjetup nuke` | Also delete the identity key (including its Keychain items, also in a keychain set by `[key] keychain`), network state, configuration, logs, leftover DNS settings, the `webjet` user and webjetup itself. The node must be enrolled again; an admin should revoke its old record. Account keys in home directories are not touched. |

`--dry-run` shows what any command would change. `remove` and `nuke` ask for
confirmation; `--yes` skips it. `WEBJETUP_REPO` points webjetup at another
repository.

## Platform notes

| Platform | Linux | macOS | Windows | FreeBSD 14, OPNsense 24.7+ (x86_64; from 0.11.0) |
| --- | --- | --- | --- | --- |
| Install / upgrade | `webjetup` (systemd unit, `webjet` user, `CAP_NET_ADMIN`) | `webjetup` (launchd daemon) | `webjetup` (LocalSystem service, registered with `sc.exe`) | `webjetup` (rc.d script `/usr/local/etc/rc.d/webjetd` under `daemon(8)`, root, enabled in `/etc/rc.conf.d/webjetd`; logs to syslog) |
| Interface | `/dev/net/tun` | `utun` | Wintun (`wintun.dll` next to `webjetd.exe`) | `tun`, renamed to `webjet0` |
| Split DNS | `resolvectl` | `/etc/resolver/<domain>` | NRPT rules tagged `webjet` | not set (Unbound query forwarding by hand) |
| Control channel (open to every local user; changes need a signature) | Unix socket, 0666 | Unix socket, 0666 | named pipe `\\.\pipe\webjet`, everyone reads and writes | Unix socket, 0666 |
| Key storage (`[key] storage`) | `tpm` (tpm2-tools) when a TPM is usable, else `file` | `keychain` (System keychain) | `dpapi` (machine scope) | `file` |
| Roles | all | DATA | DATA | DATA |

Routes and split DNS are removed when the agent stops; `webjetup remove`
removes the service as well.

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
`webjetctl local metrics [--all]` prints the same text.

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
