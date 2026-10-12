# Configuration reference

This page describes every setting Webjet has: where it lives, what it does,
its default, and how to change it. Section numbers (§11.11) refer to
[webjet-architecture.md](webjet-architecture.md); "operations guide N.M"
refers to [webjet-operations-guide.md](webjet-operations-guide.md), which has
the step-by-step procedures.

- [Overview](#overview): the three places a setting can live, and which
  one to use
- [webjetd.toml](#webjetdtoml): one machine's agent
- [The network configuration](#the-network-configuration): the whole
  network ([network scope](#network-scope)) and one node
  ([node scope](#node-scope))
- [Precedence](#precedence): which value wins
- [Recipes](#recipes): reverse proxy, gateway, blocked UDP, compression

## Overview

### Three places

| | `webjetd.toml` | Network configuration, network scope | Network configuration, node scope |
| --- | --- | --- | --- |
| **Holds** | How this machine runs its agent: listen and public addresses, interface, key storage, gateway routes, metrics, logging | How the whole network behaves: policy, DNS, seeds, transports, NAT traversal, limits, controller cluster | One node's departures from the network: transport priorities, compression, NAT traversal, limits, extra seeds and DNS entries, reverse proxy ports |
| **Stored** | A file on the machine | The signed network tree | The signed network tree |
| **Changed with** | An editor on the machine | `webjetctl network config` | `webjetctl local config [--node NAME]` |
| **Who** | Root (Administrator) on the machine | Admins | The node's owner, or an admin |
| **Takes effect** | When the agent restarts | On every node as the change spreads; no restart | On that node as the change spreads; no restart |

All three are TOML. Unknown keys are always an error, so a typo is reported
instead of silently ignored.

Admins can also edit the network configuration and any node's configuration
in the desktop app's Config tab ([app.md](app.md)).

### Where to put a setting

| You want to… | Put it in |
| --- | --- |
| Accept connections from other nodes (be a relay or controller) | `webjetd.toml` [`[listen]`](#listen) |
| Advertise an address other than the listen address (port forwarding, cloud NAT, dynamic DNS) | `webjetd.toml` [`[[public]]`](#public) |
| Change the interface name or MTU, or run without an interface | `webjetd.toml` [`[tun]`](#tun) |
| Make a LAN reachable from the overlay | A route grant on the node, plus `webjetd.toml` [`[[gateway.route]]`](#gatewayroute) ([recipe](#serve-a-lan-as-a-gateway)) |
| Publish a service to clients outside the overlay | Node scope [`[[proxy]]`](#proxy-reverse-proxy-ports) on the ingress, plus `webjetd.toml` [`[proxy]`](#proxy) on the targets ([recipe](#publish-a-service-with-a-reverse-proxy)) |
| Exclude addresses or interfaces from direct paths | `webjetd.toml` [`[nat]`](#nat) |
| Turn off hole punching, port prediction, router port mapping or LAN candidates for some nodes | [`[nat]`](#nat-traversal-nat) at network or node scope, or in a `[[nat.override]]` |
| Choose where the identity key is stored | `webjetd.toml` [`[key]`](#key) |
| Expose Prometheus metrics | `webjetd.toml` [`[metrics]`](#metrics) |
| Keep the signing key in a separate process, or stop a node acting as controller | `webjetd.toml` [`[controller]`](#controller) |
| Refuse remote upgrades | `webjetd.toml` [`[upgrade]`](#upgrade) |
| Decide who may talk to whom | Network scope [`[policy]`](#policy) |
| Change the DNS suffix, add DNS records, forward a LAN's zone | Network scope [`[dns]`](#magic-dns-dns) (records and zones can also go in node scope) |
| Tell nodes where to find the network | Network scope [`[[seeds]]`](#seeds) |
| Prefer or forbid a transport (UDP, TLS, AnyTLS) | [`[transport.priority]`](#transport-priorities) at network or node scope |
| Change what AnyTLS ports show to strangers | Network scope [`[transport.camouflage]`](#camouflage-transportcamouflage) |
| Compress traffic | [`[transport.compression]`](#compression-transportcompression) at network or node scope |
| Let KCP hops retransmit packets again | [`transport.retransmit`](#retransmission-transportretransmit) at network or node scope, or in a `[[transport.override]]` |
| Raise or lower a resource limit, or set a relay's capacity | [`[limits]`](#limits) at network or node scope |
| Change how the controller cluster manages its members | Network scope [`[controllers]`](#controllers) |

## webjetd.toml

`webjetd.toml` holds how one machine runs the agent. It is a plain file that
you edit by hand. Every key has a default, so an empty file, or no file at
all, is a valid configuration: a data node that only dials out needs
nothing. A file that exists but that the agent can't read (no permission on
it or its directory) stops the agent with an error instead.

### Location and applying changes

| Platform | Default path | Restart the agent |
| --- | --- | --- |
| Linux | `/etc/webjet/webjetd.toml` | `sudo systemctl restart webjetd` |
| macOS | `/Library/Application Support/Webjet/webjetd.toml` | `sudo launchctl kickstart -k system/net.webjet.webjetd` |
| Windows | `%ProgramData%\Webjet\webjetd.toml` | `Restart-Service webjetd` (as Administrator) |
| FreeBSD, OPNsense | `/usr/local/etc/webjet/webjetd.toml` | `service webjetd restart` (as root) |

The agent reads the file only when it starts, so restart it after every
change. `webjetd --config <path>` or the `WEBJET_CONFIG` environment
variable selects a different file; a path given this way must exist. In
containers the file is generated from `WEBJET_*` variables
([docker.md](docker.md)).

Before 0.4.0 the file also had `[transport]` and `[limits]` sections. These
settings are now part of the node scope of the network configuration. The
agent refuses to start while the file still has them, and its error message
gives the `webjetctl local config set` command that replaces each one.

### Top-level keys

| Key | Default | Meaning |
| --- | --- | --- |
| `data_dir` | Linux `/var/lib/webjet`, FreeBSD `/var/db/webjet`, macOS `/Library/Application Support/Webjet/state`, Windows `%ProgramData%\Webjet\state` | Identity key, network state, Raft log (controllers), link history. See the notes below. |
| `control_socket` | `/var/run/webjet/control.sock`; Windows `\\.\pipe\webjet` | The local control channel for `webjetctl` and the desktop app (§13.1). A relative path is relative to `data_dir`. See the notes below. |
| `log` | `info` | Log filter in `tracing` syntax, for example `info,webjetd::gossip=debug`. The `RUST_LOG` environment variable overrides it. |
| `log_format` | text | `json` writes one JSON object per line (§19.6). |

**`data_dir`.** If this directory is lost, the node has to be enrolled
again. A backup restored on another machine doesn't work when the key is
sealed to the old machine (TPM, Keychain, DPAPI; see [`[key]`](#key)).
Re-key the node instead (operations guide 2.7). On OPNsense, leave
"Use memory file systems for /var" (System › Settings › Miscellaneous) off,
or point `data_dir` at a directory outside `/var`: with it on, `/var` is
emptied at every boot and the node with it.

**`control_socket`.**
- `webjetctl` and the desktop app use the same default, or `--socket` /
  `WEBJET_SOCKET`.
- The default is under `/var/run` rather than `/run` because macOS has no
  `/run`. On Linux, `/var/run` is a symlink to `/run`.
- Every local user may connect (mode 0666). On Windows, everyone may read
  and write the pipe but not create instances of it. The socket shows the
  network, but every change through it needs an account, root or emergency
  signature (or, for a bootstrapping controller's own enrollment, the
  enrollment token). Up to 0.5.0 it was mode 0600, and on Windows limited to
  SYSTEM and Administrators.
- At start the agent lets every user pass through the default directory
  `/var/run/webjet` (it adds `o+x`, which allows no listing). A socket
  elsewhere needs a directory other users can pass through.
- Requests are lines of at most 4 MiB, and at most 64 connections are
  served at once.

### `[listen]`

Addresses this node accepts hop sessions on, as `ip:port`. A transport
whose key is left out isn't offered. A node listens only where this section
says, so a data node behind NAT usually has no `[listen]` at all and only
dials out. Relays and controllers need it: without it (and without a
router port mapping) they raise the `not_listening` alarm, since edge nodes
behind symmetric NATs can't reach them and keep fewer home relays.

| Key | Example | Transport |
| --- | --- | --- |
| `tls` | `"0.0.0.0:443"` | TCP + TLS 1.3 |
| `kcp` | `"0.0.0.0:443"` | UDP + KCP + FEC + TLS. It can use the same port number as `tls`. |
| `anytls` | `"0.0.0.0:8443"` | TCP + AnyTLS with the camouflage certificate. Needs a build with the `anytls` feature. Mainly for relays. |

Even without `kcp`, the agent keeps one UDP socket for dialing and hole
punching. Listening on a port below 1024 as the `webjet` user needs
`CAP_NET_BIND_SERVICE`, which the systemd unit installed by `webjetup`
grants (with `CAP_NET_ADMIN` for the tun interface and `CAP_NET_RAW` for
multicast capture).

### `[[public]]`

Addresses to advertise when they differ from the listen addresses: port
forwarding, cloud 1:1 NAT. Repeat the table once per address and transport.

| Key | Meaning |
| --- | --- |
| `addr` | `ip:port`, `[ipv6]:port` or `name:port`. A DNS name (dynamic DNS for a home connection, say) is resolved when the agent starts and every 5 minutes after that. Every address it resolves to is advertised, and the agent republishes its endpoint record when they change. |
| `transport` | `tls`, `kcp` or `anytls` |

```toml
[[public]]
addr = "203.0.113.5:443"
transport = "tls"

[[public]]
addr = "home.example.net:4883"
transport = "kcp"
```

### `[tun]`

The overlay network interface.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Create the overlay interface. `false` runs the node without one (a pure relay or controller). `webjetctl local ping` still works without it, because the data plane answers echo requests itself. |
| `name` | `webjet0`; macOS: the next free `utunN` | Interface name. On macOS only `utunN` names can be used. On FreeBSD the interface is created as `tunN` and renamed (a `tunN` name is used as is); a renamed one left behind by an agent that was killed is removed at start. On Windows the adapter is described as "Webjet". |
| `mtu` | `1280` | Inner MTU, at least 576. 1280 fits every transport, including IPv6 underlay paths, and is the largest packet that crosses a KCP hop without retransmission in one datagram ([retransmission](#retransmission-transportretransmit)). Above it, larger packets take two datagrams on such hops and are lost if either is; webjetd logs a warning. |

### `[dns]`

| Key | Default | Meaning |
| --- | --- | --- |
| `configure_system` | `true` | Install split DNS for the network's suffix and forwarded zones (§11.10.7): `resolvectl` on Linux, `/etc/resolver/<domain>` on macOS, NRPT rules on Windows. They are removed again when the agent stops. `false` leaves the system's DNS alone; magic DNS names then only resolve if you point the system at the resolver yourself. |

The DNS suffix, records and forwarded zones themselves are part of the
network configuration ([`[dns]`](#magic-dns-dns)).

### `[[gateway.route]]`

Subnet routes this node serves as a gateway into a LAN (§11.9.2). Gateways
run on Linux and need `iptables`; the agent turns on IP forwarding and sets
up the address translation itself.

| Key | Meaning |
| --- | --- |
| `published` | The prefix as the overlay sees it. For a mapped grant (`192.168.1.0/24=10.2.2.0/24`) this is the mapped prefix (`10.2.2.0/24`). |
| `interface` | The LAN interface behind it, for example `eth1`. |

Each route must be within a route grant in the node's record
(`webjetctl network node update <name> --route …`). A configured route
without a grant is ignored. See the [gateway recipe](#serve-a-lan-as-a-gateway).

```toml
[[gateway.route]]
published = "10.2.2.0/24"
interface = "eth1"
```

### `[proxy]`

This node as the **target** of reverse proxy rules on other nodes (§11.11).
The rules themselves belong to the ingress node's
[node configuration](#proxy-reverse-proxy-ports).

| Key | Default | Meaning |
| --- | --- | --- |
| `accept_real_ip` | `false` | Accept proxied flows that keep the client's real address as their source, and route their replies back into the overlay. Needs Linux with the tun interface. The agent marks these flows with connmark `0x574a0000/0xffff0000` and routes their replies through routing table 22346, also for a server in a container whose port is published with DNAT (`docker run -p`). For UDP flows it also adds an `ip rule` (priority 22345) per flow, so a server listening on `0.0.0.0` (a game server, say) answers from its overlay address; that needs Linux 4.17 or later. Without it, this node still receives proxied flows, but from the ingress's overlay address. |

```toml
[proxy]
accept_real_ip = true
```

### `[nat]`

Direct paths and hole punching (§11.7). The agent offers its interface
addresses, the addresses relays see it at, and a router port mapping as
candidates. It checks every candidate pair from both sides and dials the
first one that answers. `webjetctl local sessions` shows the candidates and
the result of each peer's last attempt under `punch`.

| Key | Default | Meaning |
| --- | --- | --- |
| `skip_tunnels` | `true` | Don't treat another VPN as a direct path. Addresses of tunnel interfaces aren't offered: point-to-point interfaces, and names starting with `wg`, `tun`, `utun`, `tap`, `tailscale`, `zt`, `ppp`, `ipsec`, `nordlynx` and similar. A peer address the system would reach through such an interface isn't dialed either. The exception is a full-tunnel VPN that carries the default route, because every path uses it anyway. |
| `exclude_interfaces` | `[]` | More interfaces to leave out. `*` matches any characters: `["eth9", "vpn*"]`. |
| `allow_interfaces` | `[]` | Interfaces to use even though they look like tunnels, for example a WireGuard link that is your real LAN. |
| `exclude_cidrs` | `[]` | Addresses never offered and never dialed for direct paths: `["10.1.1.0/24"]`. The overlay's own pool is always excluded. |
| `port_mapping` | `true` | Ask the router for a UDP port mapping (PCP / NAT-PMP, then UPnP IGD) and offer it as a public candidate. Only used when the router has a public address. The mapping is released when the agent stops. |

```toml
[nat]
exclude_cidrs = ["10.1.1.0/24"]
allow_interfaces = ["wg-office"]
```

To turn hole punching, port prediction, port mapping or LAN candidates off
for nodes from a central place, use the network configuration's
[`[nat]`](#nat-traversal-nat). `port_mapping = false` here turns mapping off
on this machine whatever the network configuration says.

### `[key]`

Where the identity key is stored at rest (§8.3).

| Key | Default | Meaning |
| --- | --- | --- |
| `storage` | `auto` | `auto`, `tpm`, `keychain`, `dpapi` or `file`. `auto` uses the TPM on Linux when one is usable, the System keychain on macOS and DPAPI on Windows. If none of these works it falls back to `file` with a warning. A backend you choose explicitly must work; there is no fallback, and writing the key fails instead. |
| `keychain` | the System keychain | macOS only: use a different keychain file. |

- **The backend is chosen when the key is written**: by `webjetctl local
  init`, by enrollment, or by a re-key. Changing `storage` later doesn't move
  an existing key.
- **TPM, Keychain and DPAPI keys are bound to the machine.** A copied or
  restored `identity.key` is refused, with a message telling you to re-key
  the node (operations guide 2.7).
- **On macOS** the key is a generic password item (service
  `net.webjet.identity`) in the System keychain, which only root can open.
  Any program running as root may read the item, so the agent can use a key
  written by `webjetctl` or by an older agent. `webjetup nuke` deletes these
  items too.
- **Keys written on macOS by 0.4.0** trusted only the program that wrote
  them, so the agent can't read them ("doesn't let webjetd read it"). To fix
  this, re-key the node: an admin runs `webjetctl network node rekey`, and
  you run `webjetup enroll` with the new string.

### `[metrics]`

| Key | Default | Meaning |
| --- | --- | --- |
| `listen` | off | `ip:port` to serve `GET /metrics` on, in OpenMetrics text (§12.5). On a controller it serves every node's latest report, so Prometheus can scrape the whole network from any one controller. On other nodes it serves only the node's own metrics. There is no authentication: bind it to `127.0.0.1` or to the node's overlay address, never to a public address. |

### `[controller]`

Only matters on nodes that have, or may be given, the `control` role.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Run the controller role when the network gives this node the `control` role (`webjetctl network node update <name> --roles …,control`, operations guide 2.4), and on the first controller of a new network. `false` keeps it from running here even then. Acting as a controller also needs a signing key certificate from an admin or the root, and Raft membership. |
| `signer_socket` | none | Socket (Windows: named pipe) of `webjetd signer`, which holds the controller's signing key in a separate process (§19.2). Without it the key is a file in `data_dir`. `webjetup install --signer` sets this to `/var/run/webjet-signer/signer.sock` (Windows: `\\.\pipe\webjet-signer`) and installs the signer's service. Set it before the node is given the `control` role. |
| `head_lifetime_hours` | `48` | How long signed tree heads stay valid (§7.3). 24 to 72 hours is recommended. |

### `[upgrade]`

Remote upgrades (§19.8, operations guide 3.3), available from 0.9.0.

| Key | Default | Meaning |
| --- | --- | --- |
| `remote` | `true` | Accept an admin's signed request to upgrade this node (`webjetctl network node upgrade`). |

A helper installed by `webjetup` carries out the request. It runs as root
and checks the request again itself. It installs only the release files
whose checksums the admin signed, never downgrades, and puts the previous
version back if the new agent doesn't come up.
`webjetup install --no-remote-upgrade` sets `remote = false` and removes the
helper; `--remote-upgrade` turns it back on. Docker containers have no
helper.

### `[clock]`

A node whose clock is more than a minute off is turned away without an
answer by every controller and relay (§18.6), so the network can't tell it
what is wrong. When `webjetctl local enroll` fails at every controller, or a
running agent has had no hop for two minutes, the node asks public time
servers (SNTP, UDP port 123) how far off its clock is. Over 60 s,
enrollment fails with the offset and how to fix the clock, and the agent
raises the `clock_skew` alarm (critical). Webjet never sets the clock
itself; `webjetup enroll` resynchronizes it on Windows.

| Key | Default | Meaning |
| --- | --- | --- |
| `servers` | `time.cloudflare.com`, `ntp.aliyun.com`, `time.windows.com`, `pool.ntp.org` | Servers to ask, `host` or `host:port`. `[]` turns the check off. |

### Examples

**A laptop or desktop.** A data node only dials out, so it needs no file.
The defaults create the tun interface, configure split DNS and store the
key in the platform's key store.

**A relay** with a public address on a cloud 1:1 NAT:

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

[metrics]
listen = "127.0.0.1:9469"
```

The relay's forwarding capacity is part of its node configuration, not of
this file: `webjetctl local config set limits.value.relay_capacity_mbps 1000`.

**A controller** that is also a relay, with its signing key in the signer
service and metrics on its overlay address:

```toml
[listen]
tls = "0.0.0.0:443"
kcp = "0.0.0.0:443"

[[public]]
addr = "203.0.113.10:443"
transport = "tls"
[[public]]
addr = "203.0.113.10:443"
transport = "kcp"

[controller]
signer_socket = "/var/run/webjet-signer/signer.sock"   # written by webjetup install --signer

[metrics]
listen = "10.7.0.1:9469"
```

**A gateway** into an office LAN that is also a reverse proxy target:

```toml
[[gateway.route]]
published = "10.2.2.0/24"
interface = "eth1"

[proxy]
accept_real_ip = true
```

## The network configuration

The network configuration is a TOML document stored in the signed network
tree. It has two scopes:

- **Network scope** applies to every node. Admins change it with
  `webjetctl network config`.
- **Node scope** is one node's own configuration. It overrides or adds to
  the network scope for that node only. The node's owner or an admin changes
  it with `webjetctl local config`.

Both scopes use the same keys (node scope allows only some of them) and the
same commands.

### Working with it

```sh
webjetctl network config show > network.toml     # the configuration in force, as a file
$EDITOR network.toml
webjetctl network config check network.toml      # validate it and run the policy tests
webjetctl network config apply network.toml      # submit it as the next version
```

`webjetctl network config edit` runs these steps in `$EDITOR`. To change a
single value, `get`, `set` and `unset` take a dotted key. `set` and `unset`
apply the change immediately:

```sh
webjetctl network config get transport.priority
webjetctl network config set transport.priority.kcp 0
webjetctl network config set seeds '[{node = "relay-1", addrs = ["tls:198.51.100.7:443"]}]'
webjetctl network config unset limits.value.circuits_global     # back to the built-in value
```

- **Values** are TOML: `0`, `true`, `"text"`, `["a", "b"]`. A bare word is
  taken as a string. Array entries are numbered from 0
  (`policy.rule.2.ports`). Setting one entry of an empty array fails; set
  the whole array instead.
- **`version`** at the top of the file is the version the file was made
  from; leave it as `show` printed it. `apply` submits the next version. It
  refuses the file if another version has been applied since (someone else
  changed the configuration in between, and applying would undo their
  change). Start again from `show`.
- **Sections.** At network scope a file may contain only some of the
  sections: `[policy]`, `[dns]`, `seeds`, `[transport]`, `[limits]`,
  `[controllers]`. Sections left out stay as they are. A section that is
  present replaces the current one completely: an empty `[limits]` goes back
  to the built-in limits, and `seeds = []` removes all seeds.
- **Atomic.** One `apply` is one signed operation (`SetNetworkConfig`). The
  controllers check all of it and write it in one log entry, so nodes never
  see half of a change. Nodes use the new values as the change reaches them;
  no restart is needed.
- **Defaults.** Every section has a built-in default, so a new network works
  without any configuration except a policy. With no policy rules nothing
  may talk (default deny). On a new network, `show` prints the built-in
  defaults with `version = 0`.

### Network scope

Everything the network scope can hold, with the built-in values where there
are any. The sections below explain each one.

```toml
version = 4                        # the version this file was made from

[policy]                           # who may talk to whom (§11.3)
default = "deny"

[[policy.rule]]
id = "laptops-to-web"
action = "allow"
src = ["tag:laptop"]
dst = ["tag:web", "cidr:192.168.50.0/24"]
ports = ["tcp:80", "tcp:443", "icmp"]

[[policy.test]]                    # checked by check and apply (§6.7)
src = "tag:laptop"
dst = "tag:db"
port = "tcp:5432"
expect = "deny"

[dns]                              # magic DNS (§11.10)
suffix = "internal"
resolver_ip = ["10.7.255.53"]

[[dns.record]]
name = "web.internal"
type = "CNAME"
value = "node:web-1"

[[dns.forward]]
zone = "corp.example"
servers = ["192.168.50.53"]
rewrite = ["192.168.1.0/24=10.2.2.0/24"]

[[seeds]]                          # where nodes find the network (§10.7.1)
node = "ctl-01"
addrs = ["tls:203.0.113.10:443", "kcp:203.0.113.10:443", "kcp:ctl.example.net:4883"]

[transport]
retransmit = false                 # §17.5.1; the built-in value

[transport.priority]               # §9.6; these are the built-in values
kcp = 30
anytls = 20
tls = 10

[[transport.override]]
select = ["tag:relay", "role:control"]
priority = { tls = 40 }

[[transport.override]]
select = ["tag:voip"]
retransmit = true

[transport.camouflage]             # §9.7.2
mode = "refuse"

[transport.padding]                # §9.7.4; show prints the built-in scheme
stop = 8
lines = ["0=30-30", "1=100-400", "..."]

[transport.compression]            # §9.8; these are the built-in values
control = "zstd"
data = "off"

[limits.value]                     # §16.2
circuits_global = 50000

[[limits.override]]
select = ["tag:big-relay"]
value = { circuits_global = 200000 }

[controllers]                      # §7.5; these are the built-in values
auto_membership = true
voters = 5
dead_voter_after_s = 3600
```

#### `[policy]`

The access policy (§11.3, §14.3). Without any rule nothing is allowed.

| Key | Default | Meaning |
| --- | --- | --- |
| `default` | `"deny"` | `deny` or `allow`: what happens to a flow no rule matches. |
| `[[policy.rule]]` | none | The rules, see below. |
| `[[policy.test]]` | none | Statements the policy must satisfy, see below. |

Each `[[policy.rule]]`:

| Key | Meaning |
| --- | --- |
| `id` | Unique name of the rule. Appears in metrics and in `webjetctl` output as the reason for a decision. |
| `action` | `allow` or `deny`. |
| `src` | [Selectors](#selectors) for the nodes that start the flow. |
| `dst` | Selectors for the destination; `cidr:` selectors are allowed here only. |
| `ports` | [Port specs](#port-specs). A rule without ports matches nothing; use `["*"]` for everything. |

**How a flow is decided.** If any matching rule denies it, it is denied.
Otherwise, if any matching rule allows it, it is allowed. Otherwise
`default` applies. The order of the rules doesn't matter. A rule matches
when one of its `src` selectors picks the source, one of its `dst` selectors
picks the destination, and one of its port specs covers the port.

**Tests.** Each `[[policy.test]]` has `src`, `dst` (one selector each), a
`port` (one port spec) and `expect` (`allow` or `deny`). `check` and `apply`
refuse a policy whose tests fail. Tests are how you make sure a change
doesn't cut anyone off: state what must stay allowed and what must stay
denied. A selector that matches no node is allowed, but you get a warning.

#### Selectors

Used in policy rules and tests, in `select` lists of overrides, and as
reverse proxy targets. A list of selectors picks a node when any one of them
picks it.

| Selector | Picks |
| --- | --- |
| `*` | every enrolled node |
| `tag:<tag>` | nodes with that tag (`[a-z0-9-]`, at most 32 characters) |
| `node:<name>` or `node:<key>` | one node, by name or by its public key |
| `owner:<account>` or `owner:<key>` | every node of one account |
| `role:data`, `role:relay`, `role:control` | nodes with that role |
| `cidr:<prefix>` | addresses in a prefix, for example a LAN published by a gateway. Policy `dst` only. |

#### Port specs

| Spec | Covers |
| --- | --- |
| `tcp:443`, `udp:53` | one port |
| `tcp:8000-8100` | a range of ports |
| `tcp`, `tcp:*`, `udp`, `udp:*` | every port of the protocol |
| `icmp` | ICMP and ICMPv6 |
| `*` | everything, including other protocols |

#### Magic DNS (`[dns]`)

Every node is reachable as `<node>.<suffix>`. The agent answers on the
resolver address and installs split DNS for the suffix and the forwarded
zones (unless `[dns] configure_system = false` in `webjetd.toml`).

| Key | Default | Meaning |
| --- | --- | --- |
| `suffix` | `"internal"` | The domain for node names: `web-1.internal`. |
| `resolver_ip` | the highest free address of each overlay pool (`10.7.255.254` for `10.7.0.0/16`) | Address(es) the resolver answers on. Must be in the overlay pool and not assigned to a node. |
| `[[dns.record]]` | none | Extra records, see below. Also allowed at node scope. |
| `[[dns.forward]]` | none | Zones to forward, see below. Also allowed at node scope. |

Each `[[dns.record]]`:

| Key | Meaning |
| --- | --- |
| `name` | Must be inside the suffix or inside a forwarded zone, and must not be a node's magic name. |
| `type` | `A`, `AAAA`, `CNAME`, `TXT` or `SRV`. |
| `value` | `A`/`AAAA`: an overlay address, an address in a published prefix, or `node:<name>`, which follows the node's addresses. `CNAME`: a name, or `node:<name>`. `TXT`: the text. `SRV`: `"<priority> <weight> <port> <target>"`. |
| `ttl` | Seconds; default 60. |

Each `[[dns.forward]]` sends queries for a zone to DNS servers on a LAN
behind a gateway:

| Key | Meaning |
| --- | --- |
| `zone` | The zone, for example `corp.example`. It may not contain the suffix or be contained in it. |
| `servers` | The servers' addresses. |
| `rewrite` | Mapped route grants (`192.168.1.0/24=10.2.2.0/24`, §11.9.3). Addresses in answers are rewritten to their published form. Each must match an existing route grant. |

#### `[[seeds]]`

Where nodes look for the network when they start or come back (§10.7.1).
Keep at least two, on relays or controllers with stable addresses. Without
seeds, nodes find the network through the controllers named in their
enrollment strings.

| Key | Meaning |
| --- | --- |
| `node` | A valid node with the relay role, or a controller. |
| `addrs` | `transport:host:port`, where transport is `tls`, `kcp` or `anytls` and host is an IPv4 address, `[IPv6]` or a DNS name. Use DNS names only once every node runs 0.9.0, because older nodes can't dial them. |

Seeds are also allowed at node scope; that node then tries its own seeds
first.

#### Transport priorities

`[transport.priority]` gives each transport a priority from 0 to 255. A
higher number is preferred, and 0 means never use it. `kcp` is UDP + KCP +
FEC, `anytls` is TCP + AnyTLS, `tls` is TCP + TLS. The built-in values are
`kcp = 30`, `anytls = 20` and `tls = 10`.

`[[transport.override]]` gives different priorities, or a different
[retransmission](#retransmission-transportretransmit) setting, to some nodes:

| Key | Meaning |
| --- | --- |
| `select` | [Selectors](#selectors) for the nodes it applies to (no `cidr:`). |
| `priority` | The transports it changes, for example `{ tls = 40 }`. |
| `retransmit` | `true` or `false`: whether the selected nodes' KCP hops retransmit packets. |

An override needs at least one of `priority` and `retransmit`. For each
transport, the first override that selects the node and names that
transport wins, and likewise the first that selects the node and sets
`retransmit`. Transports the override doesn't name keep their values.
Overrides are network scope only, but a node's own configuration can set
`transport.priority.<transport>`, which beats every override. Nodes publish
their priorities, and peers use them when choosing how to connect.

#### Camouflage (`[transport.camouflage]`)

What a relay's AnyTLS port shows to a connection that doesn't authenticate
(§9.7.2; renewing the certificate: operations guide 3.2). Network scope only.
Without this section, relays don't offer AnyTLS; the priorities still apply.

| Key | Meaning |
| --- | --- |
| `mode` | `refuse` or `website`. |
| `domain` | Website mode: the domain the certificate is for. Its public DNS should point at the relays. |
| `certificate` | Website mode: the certificate chain, leaf first, as the name of a PEM file (relative to the configuration file) or as PEM text. |
| `next_certificate` | Website mode, for a key change: the next key's certificate (file or PEM text), announced in advance. |
| `next_spki` | The same as a hex SPKI pin, as `show` prints it. `next_certificate` takes precedence. |

- **`refuse`** closes the connection. It needs nothing else, and `apply`
  ignores the other keys (it tells you so). AnyTLS clients still pin a
  certificate, so `apply` keeps the network's current one. On a network
  without one, it makes a self-signed certificate for a random domain and
  stores its key with the controllers first. Refuse mode is the simple
  start, but a probe can tell the port isn't an ordinary website.
- **`website`** serves a website, which holds up to active probing. It needs
  `domain` and `certificate`. Supply the certificate's private key and the
  site with `webjetctl network camouflage set-secret --key site.key --site ./site/`
  (an HTML file, or a directory with `index.html`). For lab tests,
  `webjetctl network camouflage selfsign --domain … --cert-out … --key-out …`
  makes a self-signed certificate.

`show` prints the certificate as PEM text, so a shown file applies again
unchanged.

#### Padding (`[transport.padding]`)

How the first packets of every hop session are padded and split, in the
manner of AnyTLS's padding scheme (§9.7.4). Network scope only; `show`
prints the built-in scheme. Because it is in the tree, the scheme can be
changed for the whole network without a software update.

| Key | Meaning |
| --- | --- |
| `stop` | Packets numbered `stop` and later aren't padded (built-in: 8). |
| `lines` | One line per packet number: `"<n>=<min>-<max>,…"`. Each range is the size of one segment, chosen at random, at most 16384. A `c` between ranges means "stop here if the payload is used up". Built-in: `"0=30-30"`, `"1=100-400"`, `"2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000"`, `"3=9-9,500-1000"`, and `"500-1000"` for packets 4 to 7. |

#### Compression (`[transport.compression]`)

Compression (§9.8), from 0.6.0. Upgrade every controller before the first
change to this section.

| Key | Default | Meaning |
| --- | --- | --- |
| `control` | `"zstd"` | `zstd` or `off`. Compresses control messages: gossip, Merkle sync, circuit setup, operations, metric uploads. It costs little. |
| `data` | `"off"` | `lz4` or `off`. Compresses the packets nodes send each other with LZ4, one packet at a time. |

**Data compression is off by default** because compressing before encrypting
leaks information through packet sizes: someone who can inject data into a
connection and watch the sizes can learn secrets carried in the same
connection. Turn it on only where bandwidth is expensive and the traffic
compresses well (plain HTTP, file shares, logs), preferably at node scope
for the few nodes behind such links ([recipe](#compress-packets-on-an-expensive-link)).
Traffic that is already encrypted (HTTPS, QUIC, SSH) is skipped
automatically.

A message is compressed only when both ends have the setting on, so mixed
versions and mixed settings keep working. Secrets (PSKs, the camouflage key,
Raft) are never compressed. `webjetctl local status` shows what is in force
and the bytes saved, and Prometheus gets `webjet_compression_*`.

At node scope, `transport.compression.control` or `.data` replaces the
network's value for that one setting; the other keeps the network's value.

#### Retransmission (`transport.retransmit`)

From 0.12.0, KCP hops send packets between nodes **once** (§17.5.1). Most
traffic is TCP or QUIC, which retransmit what is lost themselves; a hop that
retransmitted as well would send the same data twice for one loss and hold
up every flow behind it. FEC still repairs most loss on the hop, and the hop
still measures its round trip and loss. Control traffic (gossip, Raft,
end-to-end handshakes, operations) is always retransmitted, as are packets
on TCP and AnyTLS hops, where TCP does it.

| Key | Default | Meaning |
| --- | --- | --- |
| `retransmit` | `false` | `true`: the node's KCP hops retransmit lost packets too, in order, as before 0.12.0. |

Turn it on for nodes whose traffic doesn't recover from loss by itself and
whose links lose packets, for example nodes carrying UDP voice or video, or
a gateway in front of old devices. It applies to the packets a node sends:
the other end of a hop, and every relay on the path, follows its own
setting. Set it for some nodes with a `[[transport.override]]`
(`select` + `retransmit`), or at node scope as `transport.retransmit`, which
beats every override. Upgrade every controller before the first change to
it. `webjetctl local status` shows `retransmit` in force, and `webjetctl
local peers` shows for each KCP hop whether it runs without retransmission
(`lane`) and how many packets it sent, received and lost that way.

#### `[limits]`

Resource limits (§16.2). `[limits.value]` sets values for the whole network,
`[[limits.override]]` (`select` + `value`) sets them for the nodes it
selects. When several overrides match, the highest value wins. At node
scope only `limits.value` is allowed, and it beats the network's values and
overrides.

| Key | Default | Meaning |
| --- | --- | --- |
| `conntrack_per_peer` | 4096 | Tracked flows per peer |
| `conntrack_new_per_sec` | 500 | New flows per second per peer |
| `conntrack_global` | 262144 | Tracked flows in total (also limited by memory) |
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
| `multicast_packets_per_sec` | 50 | Broadcast and multicast copies this node sends per second, each recipient counted (architecture §9.5.1); also what it takes from each sender. `0` turns broadcast and multicast off for the node |
| `multicast_bytes_per_sec` | 65536 | Broadcast and multicast bytes sent per second, every copy counted; also taken per sender |
| `relay_capacity_mbps` | estimated | The relay's forwarding capacity, used for its load figure (§11.8.1). When unset, the agent estimates it from observed throughput, never below 100 Mbit/s. Usually set per node. |
| `rate_ceiling_mbps` | none | Upper bound for the UDP transport's sending rate |

#### `[multicast]`

Broadcast and multicast over the overlay are on by default (architecture
§9.5.1; the `multicast_*` limits above). `capture` also takes, for the UDP
ports listed, the broadcasts and IPv4 multicasts the host sends out its
*other* interfaces (LAN, Wi-Fi) — what most games do for LAN discovery,
since they broadcast to `255.255.255.255` without choosing an interface
(architecture §9.5.2).

```toml
[multicast]
capture = ["udp:19132", "udp:7551"]   # Minecraft Bedrock, a game lobby
```

| Key | Default | Meaning |
| --- | --- | --- |
| `capture` | `[]` | UDP port specs (`udp:19132`, `udp:4000-4010`, `udp` for every port). Ports 67, 68, 137, 138, 1900, 3702, 5353 and 5355 are never captured. |

Capture runs on Linux (`AF_PACKET`, needs `CAP_NET_RAW`, which the systemd
unit `webjetup` installs grants from 0.12.0; run `webjetup upgrade` on nodes
set up by an older one), macOS (BPF) and
Windows (a raw socket on the loopback address; limited broadcasts only).
The source of a captured datagram becomes the node's overlay address, so
replies come back through the overlay; LAN players keep seeing the game.
Older controllers don't know the setting: upgrade every controller before
the first change. `show` doesn't write the section out when it is unset.

#### NAT traversal (`[nat]`)

How nodes find direct UDP paths through NATs (architecture §11.7). Everything
is on by default. This is not the `[nat]` section of
[`webjetd.toml`](#nat), which picks the interfaces and addresses one
machine uses. This one is in the tree: it is set at network or node scope,
and `[[nat.override]]` sets it for the nodes some selectors pick.

| Key | Default | Meaning |
| --- | --- | --- |
| `punch` | `true` | Hole punching. `false`: the node doesn't start hole punching and doesn't answer it. A pair of nodes is punched only when both have it on. Direct hops to public and port-mapped addresses still come up. |
| `predict` | `true` | Port prediction toward a peer behind a symmetric NAT: bursts to about a hundred ports next to the peer's observed ones. Prediction runs between two nodes only when both have it on. Turn it off where those bursts trip an intrusion detection system or a rate limiter. |
| `port_mapping` | `true` | Ask the router for a UDP port mapping (PCP / NAT-PMP, then UPnP IGD). `false` gives a held mapping back at once. `port_mapping = false` in the machine's `webjetd.toml` also turns it off, whatever this says. |
| `host_candidates` | `true` | Publish the node's interface (LAN) addresses and offer them when punching. `false` keeps them private. Nodes on the same LAN then meet through their outside addresses, if the router allows that (hairpinning), or through relays. |

```toml
[nat]
predict = false                      # nowhere in the network

[[nat.override]]
select = ["tag:office"]              # behind a strict corporate firewall
punch = false
host_candidates = false

[[nat.override]]
select = ["node:nas"]
port_mapping = false
```

An override needs `select` ([selectors](#selectors), no `cidr:`) and at
least one key. For each key, the first override that selects the node and
sets that key wins; keys it leaves out keep the next level's value. At node
scope, `nat.<key>` beats every override (`webjetctl local config set
nat.punch false`). Overrides are network scope only.

Every node reads the setting for itself and for its peers, so turning
`punch` or `predict` off on one node is enough for every pair it is in.
Older nodes don't know the setting and keep punching, but a node that has
it turned off doesn't answer them. Older controllers don't know it either:
upgrade every controller before the first change. `show` doesn't write
the section out when it is unset; a comment names the built-in values. A
change takes effect without a restart. `webjetctl local status` shows
what is in force as `nat_policy`, and `webjetctl local sessions` shows it
under `punch.policy`.

#### `[controllers]`

How the Raft leader manages the controller cluster (§7.5; operations guide
2.4). Network scope only. From 0.7.0: upgrade every controller before the
first change. `show` doesn't write this section out; it names the built-in
values in a comment.

| Key | Default | Meaning |
| --- | --- | --- |
| `auto_membership` | `true` | The leader manages membership itself, as described below. |
| `voters` | `5` | 1, 3, 5 or 7: the number of voters the leader aims for. |
| `dead_voter_after_s` | `3600` | A voter unreachable this long gives its seat to a healthy learner. `0` means never; otherwise at least 60. |

With `auto_membership` on, an admin only makes nodes controllers (the
`control` role and a certificate), and the leader does the rest:

- It adds every valid controller as a learner.
- It makes the earliest-joined healthy ones voters. The number of voters is
  always odd and at most `voters`, so two controllers have one voter and
  four have three.
- It removes members that are revoked or have lost their role or
  certificate.
- It replaces a voter it hasn't heard from for `dead_voter_after_s` with a
  healthy learner.
- It changes one member at a time.

`webjetctl network controller add-learner|promote|demote|remove` still work.
With automatic membership on, the leader may undo a manual change that
breaks the rules above, but it doesn't add back a controller an admin
removed. To manage membership only by hand, turn it off:
`webjetctl network config set controllers.auto_membership false`.

### Node scope

A node's own configuration changes the network configuration for that node
only. It holds a subset of the keys:

| Key | Effect for this node |
| --- | --- |
| `transport.priority.<transport>` | Replaces the network's priority and any override. Other nodes see it too: the node publishes its priorities, and peers use them when choosing a transport. |
| `transport.compression.control`, `.data` | Replaces the network's value for that setting; the other keeps the network's value. |
| `transport.retransmit` | Replaces the network's value and any override. |
| `limits.value.<name>` | Replaces the network's value and overrides. |
| `[[seeds]]` | Tried before the network's seeds. |
| `[[dns.record]]`, `[[dns.forward]]` | Answered or forwarded by this node's resolver only, before the network's. Checked like the network's (inside the suffix or a forwarded zone, no shadowing of magic DNS names). |
| `multicast.capture` | Replaces the network's list; `[]` turns capture off for this node. |
| `nat.punch`, `.predict`, `.port_mapping`, `.host_candidates` | Replaces the network's value and any override, key by key. |
| `[[proxy]]` | [Reverse proxy ports](#proxy-reverse-proxy-ports) this node listens on. Node scope only. |

Policy, the DNS suffix and resolver, transport overrides, camouflage,
padding, limit overrides, NAT overrides and `[controllers]` are network scope only;
`apply` refuses them at node scope.

```sh
webjetctl local config show                               # what this node sets itself
webjetctl local config show --effective                   # everything in force for it
webjetctl local config set transport.priority.kcp 0       # never UDP from this node
webjetctl local config set limits.value.relay_capacity_mbps 900
webjetctl local config set transport.compression.data lz4 # compress packets to and from this node
webjetctl local config set transport.retransmit true      # KCP hops retransmit this node's packets
webjetctl local config set nat.punch false                # no hole punching to or from this node
webjetctl local config unset transport.priority.kcp       # back to the network's value
webjetctl local config --node relay-fra edit              # another node
```

- **Which node.** Without `--node`, the commands apply to the node whose
  agent `webjetctl` talks to. `--node` takes a name, a node id (hex, or a
  unique prefix) or a key.
- **Who.** The node's owner and any admin may change it. The change is
  signed with your account key (`SetNodeConfig`) and stored in the tree, so
  it survives reinstalls and can be made from any machine.
- **A file is the whole configuration.** Unlike the network scope,
  `apply` at node scope takes the file as the node's complete configuration:
  anything the file leaves out is removed. Start from
  `webjetctl local config show` (not `--effective`, which isn't a file to
  apply), or use `edit` or `set`. The same `version` rule as at network
  scope applies.
- **Clearing it.** Removing every value clears the node's configuration.
  Revoking the node removes it.

#### `[[proxy]]`: reverse proxy ports

A Linux data node (the **ingress**) can listen on a TCP or UDP port for
clients outside the overlay and forward each flow to a port of a
**target**: another node, one of the data nodes some selectors pick, or an
address behind a gateway (§11.11). Before the first rule, upgrade every
controller to 0.6.0 or later; older controllers drop the field. Older nodes
are never chosen as targets.

| Key | Default | Meaning |
| --- | --- | --- |
| `name` | required | Unique on the node; `[a-z0-9-]`, at most 32 characters. |
| `protocol` | required | `tcp` or `udp`. |
| `listen_port` | required | The port clients connect to on the ingress. One rule per protocol and port. |
| `target` | required | Either one address (a node's overlay address, or an address in a prefix a gateway publishes), or a list of [selectors](#selectors) (`tag:web`, `node:web-02`, `role:data`, …; no `cidr:`, and no addresses mixed in). |
| `target_port` | required | The port on the target. |
| `real_ip` | `true` | Keep the client's address as the source. See below. |

```toml
[[proxy]]
name = "web"
protocol = "tcp"
listen_port = 8080
target = ["10.7.0.11"]                 # one address
target_port = 80

[[proxy]]
name = "dns"
protocol = "udp"
listen_port = 53
target = ["tag:dns", "node:ns-02"]     # selectors: one node per client
target_port = 53
real_ip = false                        # targets see the ingress's overlay address
```

- **Requirements.** The ingress needs the `data` role, Linux, `iptables`
  and the tun interface. A node may have at most 64 rules. The policy must
  allow the ingress to reach the target on `target_port`, as for its own
  traffic. The ingress's firewall or cloud security group must let clients
  reach `listen_port`.
- **Choosing a target.** With selectors, each client address goes to one of
  the data nodes they pick and stays with it as long as that node is a
  candidate. When a node drops out, only its clients move to another one.
- **Source address.** With `real_ip = true`, the target sees the client's
  real address, but only if it accepts that with
  [`[proxy] accept_real_ip = true`](#proxy) in its `webjetd.toml`. Targets
  that don't, and addresses behind a gateway, see the ingress's overlay
  address instead, and the rule shows a warning. With `real_ip = false` all
  targets see the ingress's overlay address. The ingress then uses source
  ports 61000 to 65535.
- **Changing `accept_real_ip`.** After a target's agent restarts with
  `accept_real_ip` turned on or off, the ingress closes the flows whose
  source no longer fits, within about 10 seconds. A UDP client's next
  datagram starts a new flow with the right source; open TCP connections
  are reset, and clients reconnect.
- **Not from the ingress itself.** The ingress doesn't capture connections
  that its own host makes to `listen_port`; test from another machine.
- **Watching it.** `webjetctl local proxy` on the ingress shows each rule's
  status and warnings, and the proxy flows with their counters; the desktop
  app shows the same under Connections → reverse proxy. Proxy flows are
  kept apart from the overlay's flows and metrics; their metrics are
  `webjet_proxy_*`.

See the [reverse proxy recipe](#publish-a-service-with-a-reverse-proxy) for
the whole setup.

### Precedence

For each value, the first one that is set wins:

1. the node's own configuration (node scope)
2. a matching network override: for priorities, the first override that
   names the transport; for `retransmit` and each `[nat]` key, the first
   override that sets it;
   for limits, the highest value of all matching overrides
3. the network's value
4. the built-in default

For seeds, DNS records and forwarded zones, both lists are used: the node's
entries first, then the network's.

`webjetctl local config [--node NAME] show --effective` prints the result
for a node.

## Recipes

### Publish a service with a reverse proxy

Goal: clients on the internet reach a web server on node `web-01`
(overlay address `10.7.0.11`, port 80) through port 8080 of `edge-01`, a
Linux data node with a public address. `web-01` should see the clients'
real addresses.

1. **Policy** (network scope): let the ingress reach the target.
   ```toml
   [[policy.rule]]
   id = "edge-to-web"
   action = "allow"
   src = ["node:edge-01"]
   dst = ["node:web-01"]
   ports = ["tcp:80"]
   ```
   ```sh
   webjetctl network config edit
   ```
2. **Target** (`webjetd.toml` on `web-01`, Linux): accept real client
   addresses, then restart its agent.
   ```toml
   [proxy]
   accept_real_ip = true
   ```
   ```sh
   sudo systemctl restart webjetd
   ```
3. **Ingress** (node scope of `edge-01`): add the rule.
   ```sh
   webjetctl local config --node edge-01 edit
   ```
   ```toml
   [[proxy]]
   name = "web"
   protocol = "tcp"
   listen_port = 8080
   target = ["10.7.0.11"]
   target_port = 80
   ```
4. **Check:** open port 8080 in `edge-01`'s firewall or security group. On
   `edge-01`, `webjetctl local proxy` shows the rule without warnings. From
   a machine outside the overlay, `curl http://<edge-01's public address>:8080/`
   reaches the server, and its access log shows the client's address.

To spread the clients over several servers instead, give them a tag and use
`target = ["tag:web"]`, with `dst = ["tag:web"]` in the policy rule.

### Serve a LAN as a gateway

Full procedure: operations guide 2.5. In short:

1. Grant the route: `webjetctl network node update gw-office --route 192.168.1.0/24=10.2.2.0/24`.
2. On the gateway, add a `[[gateway.route]]` to `webjetd.toml` and restart
   its agent:
   ```toml
   [[gateway.route]]
   published = "10.2.2.0/24"
   interface = "eth1"
   ```
3. Allow the published prefix in the policy:
   `dst = ["cidr:10.2.2.0/24"]`.
4. Optionally, forward the LAN's DNS zone with the same mapping:
   ```toml
   [[dns.forward]]
   zone = "corp.example"
   servers = ["192.168.1.53"]
   rewrite = ["192.168.1.0/24=10.2.2.0/24"]
   ```

### A node behind a firewall that blocks UDP

```sh
webjetctl local config --node laptop-17 set transport.priority.kcp 0
```

The node stops trying UDP and connects over TLS or AnyTLS. To undo it,
`unset` the same key.

### Play LAN games across the overlay

Games find each other with UDP broadcasts. Let the game nodes reach each
other on the game's ports, and capture its discovery port so broadcasts the
game sends out the LAN interface reach the overlay too:

```sh
webjetctl network config edit
```

```toml
[[policy.rule]]
id = "games"
action = "allow"
src = ["tag:game"]
dst = ["tag:game"]
ports = ["udp:19132-19133"]           # Minecraft Bedrock

[multicast]
capture = ["udp:19132"]
```

Every game node then lists the others' worlds. `webjetctl local metrics |
grep multicast` shows copies sent and captured; if a node's `local status`
shows the `multicast_capture` alarm, capture couldn't start there (see the
message: usually missing rights).

### Compress packets on an expensive link

```sh
webjetctl local config --node branch-gw set transport.compression.data lz4
```

Packets are compressed only between nodes that both have `data` on. To
compress a session between `branch-gw` and a server, turn it on for the
server too. Read the warning under [Compression](#compression-transportcompression)
first.
