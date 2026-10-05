# Configuration reference

Webjet has two kinds of configuration:

- **`webjetd.toml`**: how one machine runs its agent (listen addresses,
  interface, key storage, logging, metrics). It's a file on that machine,
  edited by hand. See [webjetd.toml](#webjetdtoml) below.
- **The network configuration**: how the network behaves (access policy,
  DNS, seeds, transport priorities and camouflage, resource limits). It's
  stored in the signed network tree and changed with `webjetctl`. It has two
  scopes:
  - **network scope**: the same on every node; admins change it with
    `webjetctl network config` ([network scope](#network-scope)).
  - **node scope**: one node's overrides and additions; the node's owner or
    an admin changes it with `webjetctl local config`
    ([node scope](#node-scope)).

Both are TOML, and unknown keys are always an error, so a typo is reported
instead of being ignored.

## The network configuration

### How it's changed

`show` prints the configuration in force as a file that `apply` accepts:

```sh
webjetctl network config show > network.toml     # edit it
webjetctl network config check network.toml      # validate, run the policy tests
webjetctl network config apply network.toml      # submit it as the next version
```

`edit` does the three steps in `$EDITOR`. For a single value, `get`, `set`
and `unset` take a dotted key:

```sh
webjetctl network config get transport.priority
webjetctl network config set transport.priority.kcp 0
webjetctl network config set seeds '[{node = "relay-1", addrs = ["tls:198.51.100.7:443"]}]'
webjetctl network config unset limits.value.circuits_global     # back to the built-in
```

Values are TOML (`0`, `true`, `"text"`, `["a", "b"]`); a bare word is taken
as a string. Array entries are numbered from 0 (`policy.rule.2.ports`).

**Version.** `version` at the top is the version the file was made from;
leave it as `show` printed it. `apply` submits the next version, and refuses
a file whose version is no longer the one in force: someone applied a change
in between, and applying would undo it. Start again from `show`.

**Sections.** A file may contain only some of the sections (`[policy]`,
`[dns]`, `seeds`, `[transport]`, `[limits]`). Sections left out stay as they
are; a section that is present replaces the current one completely. An empty
`[limits]` goes back to the built-in limits; `seeds = []` removes all seeds.

**Atomic.** One `apply` is one signed operation (`SetNetworkConfig`), checked
completely by the controllers and written in one log entry, so nodes never
see half of a change. Every section has a built-in default, so a new network
works without any configuration except a policy: without a policy rule,
nothing may talk (default deny).

### Network scope

```toml
version = 4

[policy]                        # access policy (§11.3)
default = "deny"                # what no rule matches

[[policy.rule]]
id = "laptops-to-web"           # unique; shows up in metrics
action = "allow"                # allow | deny (deny wins)
src = ["tag:laptop"]            # selectors, see below
dst = ["tag:web", "cidr:192.168.50.0/24"]
ports = ["tcp:80", "tcp:443", "icmp"]   # proto:port[-port], icmp, or "*"

[[policy.test]]                 # checked on check and apply (§6.7)
src = "tag:laptop"
dst = "tag:db"
port = "tcp:5432"
expect = "deny"

[dns]                           # magic DNS (§11.10)
suffix = "internal"             # names are <node>.<suffix>
resolver_ip = ["10.7.255.53"]   # default: the top address of the overlay pool

[[dns.record]]                  # A, AAAA, CNAME, TXT, SRV; ttl optional
name = "web.internal"
type = "CNAME"
value = "node:web-1"            # node:<name> follows the node's addresses

[[dns.forward]]                 # zones forwarded to a LAN's DNS servers
zone = "corp.example"
servers = ["192.168.50.53"]
rewrite = ["192.168.1.0/24=10.2.2.0/24"]   # mapped route grants (§11.9.3)

[[seeds]]                       # where nodes find the network (§10.7.1)
node = "ctl-01"                 # a relay or controller
addrs = ["tls:203.0.113.10:443", "kcp:203.0.113.10:443"]

[transport.priority]            # 0–255 per transport; 0 = never (§9.6)
kcp = 30                        # UDP + KCP + FEC
anytls = 20                     # TCP + AnyTLS
tls = 10                        # TCP + TLS

[[transport.override]]          # first matching override wins, per transport
select = ["tag:relay", "role:control"]
priority = { tls = 40 }

[transport.camouflage]          # what AnyTLS ports show to strangers (§9.7.2)
mode = "refuse"                 # or "website"

[transport.padding]             # AnyTLS padding scheme; show prints the built-in
stop = 8
lines = ["0=30-30", "1=100-400", "..."]

[limits.value]                  # resource limits (§16.2), see the table below
circuits_global = 50000

[[limits.override]]             # all matching overrides apply; the highest value wins
select = ["tag:big-relay"]
value = { circuits_global = 200000 }
```

Selectors (`src`, `dst`, `select`): `*`, `tag:<tag>`, `node:<name>`,
`node:<key>`, `owner:<account>`, `role:data|relay|control`, `cidr:<prefix>`
(policy destinations only).

**Camouflage.** `mode = "refuse"` closes connections that don't
authenticate; it needs nothing else (a certificate to pin is kept from the
network or made on the first apply). `mode = "website"` serves a website,
which holds up to active probing; it needs `domain` and `certificate` (a PEM
chain, leaf first, as a file name relative to the configuration file or as
PEM text). `show` prints the chain as PEM text, so the printed file applies
again unchanged. For a key change, `next_certificate` (file or PEM) or
`next_spki` (hex pin, as `show` prints it) announces the next key
(operations guide 3.2). The private key and the website are set separately with
`webjetctl network camouflage set-secret`.

### Node scope

A node's configuration changes the network's for that node only. It holds a
subset of the same keys:

| Key | Effect for this node |
| --- | --- |
| `transport.priority.<transport>` | Replaces the network's priority (and any override). Other nodes see it too: the node publishes its priorities, and peers use them when choosing a transport. |
| `limits.value.<name>` | Replaces the network's value and overrides. |
| `[[seeds]]` | Tried before the network's seeds. |
| `[[dns.record]]`, `[[dns.forward]]` | Answered or forwarded by this node's resolver only, before the network's. Checked like the network's (in the suffix or a forwarded zone, no shadowing of magic DNS names). |

Policy, the DNS suffix and resolver, transport overrides, camouflage and
padding are network-wide only; `apply` refuses them at node scope.

```sh
webjetctl local config show                    # what this node sets
webjetctl local config show --effective        # what is in force for it
webjetctl local config set transport.priority.kcp 0       # no UDP from here
webjetctl local config set limits.value.relay_capacity_mbps 900
webjetctl local config unset transport.priority.kcp       # back to the network's
webjetctl local config --node relay-fra edit   # another node
```

Without `--node` the commands apply to the node whose agent `webjetctl`
talks to. The node's owner may change its configuration, and so may any
admin; the change is signed with your account key (`SetNodeConfig`) and
stored in the tree, so it survives reinstalls and can be made remotely. The
version rules are the same as at network scope. Removing every value clears
the node's configuration; revoking the node removes it.

### Precedence

For each value, the first that is set wins:

1. the node's configuration (node scope)
2. a matching network override: for priorities the first override that
   names the transport; for limits the highest value of all matching
   overrides
3. the network's value
4. the built-in default

For seeds, DNS records and forwarded zones the node's entries come first and
the network's follow.

### Limits

| Key | Default | Meaning |
| --- | --- | --- |
| `conntrack_per_peer` | 4096 | Tracked flows per peer |
| `conntrack_new_per_sec` | 500 | New flows per second per peer |
| `conntrack_global` | 262144 | Tracked flows in total |
| `snat_ports_per_source` | 2048 | Gateway: flows to served LANs per source node |
| `snat_global` | 65536 | Gateway: flows to served LANs in total |
| `circuits_per_source` | 64 | Relay: circuits per source node |
| `circuit_setups_per_sec` | 10 | Relay: circuit setups per second per source node |
| `circuits_global` | 50000 | Relay: circuits in total |
| `e2e_handshakes_per_sec` | 10 | End-to-end handshakes accepted per second per peer |
| `e2e_handshakes_in_progress` | 4 | End-to-end handshakes in progress per peer (the agent runs at most one per peer, so any value is met) |
| `e2e_handshakes_global` | 1000 | End-to-end handshakes in progress in total |
| `handshake_queue` | 64 | Packets queued per session while its handshake runs |
| `hop_handshakes_per_ip` | 5 | Hop TLS handshakes in progress per source IP |
| `lookups_per_sec` | 20 | Relay: record lookups per second per peer |
| `subscriptions_per_peer` | 256 | Relay: nodes one peer may subscribe to |
| `relay_capacity_mbps` | estimated | The relay's forwarding capacity for its load figure (§11.8.1); without it the agent estimates capacity from observed throughput, never below 100 Mbit/s. Usually set per node. |
| `rate_ceiling_mbps` | none | Upper bound for the UDP transport's sending rate |

## webjetd.toml

`webjetd.toml` holds how this machine runs the agent. Unknown keys are an
error, so a typo stops the agent instead of being ignored. Before 0.4.0 it
also had `[transport]` and `[limits]`; the agent now refuses to start with
them and says which `webjetctl local config set` command replaces each.

### Where it is read from

| Platform | Default path |
| --- | --- |
| Linux | `/etc/webjet/webjetd.toml` |
| macOS | `/Library/Application Support/Webjet/webjetd.toml` |
| Windows | `%ProgramData%\Webjet\webjetd.toml` |

`webjetd --config <path>` or the `WEBJET_CONFIG` environment variable selects
another file; a path given this way must exist. Without any file the defaults
below apply. In containers the file is generated from `WEBJET_*` variables
(docs/docker.md).

### Top level

| Key | Default | Meaning |
| --- | --- | --- |
| `data_dir` | `/var/lib/webjet` (Linux), `/Library/Application Support/Webjet/state` (macOS), `%ProgramData%\Webjet\state` (Windows) | Identity key, network state, Raft log (controllers), link history. Losing it means re-enrolling the node. A backup restored on another machine doesn't work when the key is sealed (TPM, Keychain, DPAPI): re-key that machine instead. |
| `control_socket` | `/var/run/webjet/control.sock`, Windows `\\.\pipe\webjet` | The local control channel for `webjetctl` and `webjet-app` (§13.1), which use the same default (or `--socket` / `WEBJET_SOCKET`). `/var/run` rather than `/run` because macOS has no `/run`; on Linux `/var/run` is a symlink to `/run`. Every local user may connect (mode 0666; on Windows, everyone may read and write the pipe but not create instances of it): it shows the network, and every change through it needs an account, root or emergency signature. At start the agent also lets every user through the default directory `/var/run/webjet` (adds `o+x`, not listing); a socket elsewhere needs a directory other users can pass. Up to 0.5.0: mode 0600, SYSTEM and Administrators only. A relative path is taken relative to `data_dir`. |
| `log` | `info` | Log filter in `tracing` syntax, e.g. `info,webjetd::gossip=debug`. `RUST_LOG` overrides it. |
| `log_format` | text | `json` for one JSON object per line (§19.6). |

### `[listen]`

Addresses this node accepts hop sessions on. Omit a key to disable that
transport. Data nodes behind NAT usually listen on nothing and only dial.

| Key | Example | Transport |
| --- | --- | --- |
| `tls` | `"0.0.0.0:443"` | TCP + TLS 1.3 |
| `kcp` | `"0.0.0.0:443"` | UDP + KCP + FEC + TLS (can share the port number with `tls`) |
| `anytls` | `"0.0.0.0:8443"` | TCP + AnyTLS with the camouflage certificate (relays; needs a build with the `anytls` feature) |

Even without `kcp`, the agent keeps one UDP socket for dialing and hole
punching.

### `[[public]]`

Addresses to advertise when they differ from the listen addresses (port
forwarding, cloud 1:1 NAT). Repeat the table per address.

```toml
[[public]]
addr = "203.0.113.5:443"
transport = "tls"      # tls | kcp | anytls

[[public]]
addr = "203.0.113.5:443"
transport = "kcp"
```

### `[tun]`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Create the overlay interface. `false` runs the node without one (pure relay or controller); `webjetctl local ping` still works because the data plane answers echo requests itself. |
| `name` | `webjet0`; on macOS the next free `utunN` | Interface name. On macOS only `utunN` names can be chosen. On Windows the adapter is described as "Webjet". |
| `mtu` | `1280` | Inner MTU. 1280 fits every transport, including IPv6 underlay paths. |

### `[dns]`

| Key | Default | Meaning |
| --- | --- | --- |
| `configure_system` | `true` | Install split DNS for the network's suffix and forwarded zones (§11.10.7): `resolvectl` on Linux, `/etc/resolver/<domain>` on macOS, NRPT rules on Windows. Removed again when the agent stops. |

### `[[gateway.route]]`

Subnet routes this node serves as a gateway (§11.9.2). Each must be within a
route grant in the node's record; a configured route without a grant is
ignored. Gateways run on Linux and need IP forwarding.

```toml
[[gateway.route]]
published = "192.168.50.0/24"   # the prefix as the overlay sees it
interface = "eth1"              # the LAN interface behind it
```

For mapped grants (`192.168.1.0/24=10.2.2.0/24`), `published` is the mapped
prefix.

### `[key]`

Where the identity key is stored at rest (§8.3).

| Key | Default | Meaning |
| --- | --- | --- |
| `storage` | `auto` | `auto`, `tpm`, `keychain`, `dpapi` or `file`. `auto` uses the TPM on Linux when one is usable, the System keychain on macOS and DPAPI on Windows, and falls back to `file` with a warning. An explicitly chosen backend must work. |
| `keychain` | System keychain | macOS: a different keychain file. |

On macOS the key is a generic password item (service `net.webjet.identity`)
in the System keychain, which only root can open. Any program running as root
may read the item, so the agent can use a key written by `webjetctl` or by an
older agent. Keys written by 0.4.0 trusted only the program that wrote them, so
the agent can't read them ("doesn't let webjetd read it"). To fix this,
re-key the node: an admin runs `webjetctl network node rekey`, and you run
`webjetup enroll` with the new string. `webjetup nuke` deletes these items
too.

TPM, Keychain and DPAPI keys are bound to the machine: a copied or restored
`identity.key` is refused with a message to re-key the node (operations guide 2.7).
The backend is chosen when the key is written (`webjetctl local init`, enrollment or
re-key); changing `storage` later doesn't move an existing key.

### `[metrics]`

| Key | Default | Meaning |
| --- | --- | --- |
| `listen` | off | `host:port` for `GET /metrics` in OpenMetrics text (§12.5). On a controller it serves every node's latest report; elsewhere the node's own metrics. There is no authentication: bind it to `127.0.0.1` or the node's overlay address. |

### `[controller]`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | The controller role runs when the network gives this node the `control` role (`webjetctl network node update <name> --roles ...,control`, operations guide 2.4), and on the first controller of a new network. `false` keeps it from running here even then. Acting as a controller also needs a SigningKeyCert signed by an admin or the root, and Raft membership. |
| `signer_socket` | none | Socket (Windows: named pipe) of `webjetd signer`, which holds the signing key in a separate process (§19.2). Without it the key is a file in `data_dir`. |
| `head_lifetime_hours` | `48` | How long signed tree heads stay valid (§7.3; 24–72 h recommended). |

### Example: a relay

```toml
[listen]
tls = "0.0.0.0:443"
kcp = "0.0.0.0:443"
anytls = "0.0.0.0:8443"

[[public]]
addr = "203.0.113.5:443"
transport = "tls"
[[public]]
addr = "203.0.113.5:443"
transport = "kcp"
[[public]]
addr = "203.0.113.5:8443"
transport = "anytls"

[tun]
enabled = true

[metrics]
listen = "127.0.0.1:9469"
```

Its forwarding capacity is part of its node configuration:
`webjetctl local config set limits.value.relay_capacity_mbps 1000`.

### Example: a laptop

A data node only dials out, so it needs no file at all. The defaults create
the tun interface, configure split DNS and store the key in the platform's
key store.
