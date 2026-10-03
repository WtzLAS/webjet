# webjetd.toml reference

`webjetd.toml` holds the settings that are local to one node. Everything that
must be the same network-wide (policy, DNS, seeds, limits, transport
priorities, camouflage) lives in the signed network tree and is changed with
`webjetctl`.

Unknown keys are an error, so a typo stops the agent instead of being ignored.

## Where it is read from

| Platform | Default path |
| --- | --- |
| Linux | `/etc/webjet/webjetd.toml` |
| macOS | `/Library/Application Support/Webjet/webjetd.toml` |
| Windows | `%ProgramData%\Webjet\webjetd.toml` |

`webjetd --config <path>` or the `WEBJET_CONFIG` environment variable selects
another file; a path given this way must exist. Without any file the defaults
below apply. In containers the file is generated from `WEBJET_*` variables
(docs/docker.md).

## Top level

| Key | Default | Meaning |
| --- | --- | --- |
| `data_dir` | `/var/lib/webjet` (Linux), `/Library/Application Support/Webjet/state` (macOS), `%ProgramData%\Webjet\state` (Windows) | Identity key, network state, Raft log (controllers), link history. Losing it means re-enrolling the node. A backup restored on another machine doesn't work when the key is sealed (TPM, Keychain, DPAPI): re-key that machine instead. |
| `control_socket` | `/run/webjet/control.sock`, Windows `\\.\pipe\webjet` | The local control channel for `webjetctl` (§13.1). Mode 0600; on Windows SYSTEM and Administrators only. A relative path is taken relative to `data_dir`. |
| `log` | `info` | Log filter in `tracing` syntax, e.g. `info,webjetd::gossip=debug`. `RUST_LOG` overrides it. |
| `log_format` | text | `json` for one JSON object per line (§19.6). |

## `[listen]`

Addresses this node accepts hop sessions on. Omit a key to disable that
transport. Data nodes behind NAT usually listen on nothing and only dial.

| Key | Example | Transport |
| --- | --- | --- |
| `tls` | `"0.0.0.0:443"` | TCP + TLS 1.3 |
| `kcp` | `"0.0.0.0:443"` | UDP + KCP + FEC + TLS (can share the port number with `tls`) |
| `anytls` | `"0.0.0.0:8443"` | TCP + AnyTLS with the camouflage certificate (relays; needs a build with the `anytls` feature) |

Even without `kcp`, the agent keeps one UDP socket for dialing and hole
punching.

## `[[public]]`

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

## `[tun]`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Create the overlay interface. `false` runs the node without one (pure relay or controller); `webjetctl ping` still works because the data plane answers echo requests itself. |
| `name` | `webjet0`; on macOS the next free `utunN` | Interface name. On macOS only `utunN` names can be chosen. On Windows the adapter is described as "Webjet". |
| `mtu` | `1280` | Inner MTU. 1280 fits every transport, including IPv6 underlay paths. |

## `[dns]`

| Key | Default | Meaning |
| --- | --- | --- |
| `configure_system` | `true` | Install split DNS for the network's suffix and forwarded zones (§11.10.7): `resolvectl` on Linux, `/etc/resolver/<domain>` on macOS, NRPT rules on Windows. Removed again when the agent stops. |

## `[[gateway.route]]`

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

## `[limits]`

Local overrides of the network's limits (§16.4): a value here takes
precedence over the network's Limits configuration (`webjetctl limits apply`)
for this node. `webjetctl limits show` prints the values in force. Every
limit has a built-in default:

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
| `relay_capacity_mbps` | estimated | The relay's forwarding capacity for its load figure (§11.8.1); without it the agent estimates capacity from observed throughput, never below 100 Mbit/s |
| `rate_ceiling_mbps` | none | Upper bound for the UDP transport's sending rate |

## `[key]`

Where the identity key is stored at rest (§8.3).

| Key | Default | Meaning |
| --- | --- | --- |
| `storage` | `auto` | `auto`, `tpm`, `keychain`, `dpapi` or `file`. `auto` uses the TPM on Linux when one is usable, the System keychain on macOS and DPAPI on Windows, and falls back to `file` with a warning. An explicitly chosen backend must work. |
| `keychain` | System keychain | macOS: a different keychain file. |

TPM, Keychain and DPAPI keys are bound to the machine: a copied or restored
`identity.key` is refused with a message to re-key the node (runbook 8).
The backend is chosen when the key is written (`webjetctl init`, enrollment or
re-key); changing `storage` later doesn't move an existing key.

## `[metrics]`

| Key | Default | Meaning |
| --- | --- | --- |
| `listen` | off | `host:port` for `GET /metrics` in OpenMetrics text (§12.5). On a controller it serves every node's latest report; elsewhere the node's own metrics. There is no authentication: bind it to `127.0.0.1` or the node's overlay address. |

## `[transport]`

Local transport priorities (§9.6), overriding the network's for this node:

```toml
[transport]
kcp = 0       # never use UDP from this node (0 disables a transport)
anytls = 40
tls = 10
```

## `[controller]`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Run the controller role. The node needs a SigningKeyCert from the root key (runbook 3) and must be added as a Raft member. |
| `signer_socket` | none | Socket (Windows: named pipe) of `webjetd signer`, which holds the signing key in a separate process (§19.2). Without it the key is a file in `data_dir`. |
| `head_lifetime_hours` | `48` | How long signed tree heads stay valid (§7.3; 24–72 h recommended). |

## Example: a relay

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

[limits]
relay_capacity_mbps = 1000

[metrics]
listen = "127.0.0.1:9469"
```

## Example: a laptop

A data node only dials out, so it needs no file at all. The defaults create
the tun interface, configure split DNS and store the key in the platform's
key store.
