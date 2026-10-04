# Webjet desktop app

`webjet-app` shows a Webjet network: its state, its nodes and, for admins,
its accounts. It talks to the `webjetd` agent on the same machine, like
`webjetctl` does, and signs changes with your account key.

## Running it

```sh
cargo run --release -p webjet-app
webjet-app --socket /var/run/webjet/control.sock --keys ~/.config/webjet/accounts
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--socket` | `WEBJET_SOCKET`, else the agent's default control socket | The local agent to talk to. |
| `--keys` | `WEBJET_KEYS`, else `~/.config/webjet/accounts` | Where account keys are (`<name>.key` and `<name>.pub`). |

The control socket is readable only by the agent's user (root on a default
install), so either run the app as that user, or point `control_socket` in
`webjetd.toml` to a socket your user can open.

Building needs no extra tools on macOS: the app compiles GPUI's Metal shaders
at run time, so the Xcode Command Line Tools are enough. On Linux, GPUI needs
the usual X11/Wayland and Vulkan development packages.

## Signing in

The app lists the account keys in the key directory. Pick one and enter its
passphrase. The app then checks the account against the network:

- an account that isn't in this network, or has been revoked, can't sign in;
- a key that doesn't match the account's current record can't sign in;
- if the account is revoked or demoted while the app runs, you are signed out
  or lose admin rights at the next refresh (every 5 s).

Accounts are created as before: `webjetctl network account keygen`, then an admin
adds the account (`webjetctl network account create`).

## What each account sees

| | Admin account | Normal account |
| --- | --- | --- |
| Dashboard, Connections, Nodes, Metrics | yes | yes |
| Accounts tab | every account | its own account |
| Rename or revoke a node | any node | only nodes it owns |
| Set a node's tags | yes | no |
| Rotate the PSK | yes | no |

The app only offers what the account may do. The controllers check every
operation on their own, so a change the app wouldn't offer is refused
anyway.

Revoking a node and rotating the PSK need a second click.

## Tabs

Everything is seen from the local agent and refreshes every 5 s. The
Connections, Nodes and Metrics tabs need webjetd's `sessions`, `conntrack`,
`topology` and `metrics` control commands. With an older agent the app
says the data isn't available.

- **Dashboard**: overall health (current tree head, node record, validity
  horizon, alarms, connectivity) with the reasons, then the headline numbers:
  nodes by role, accounts, established end-to-end sessions, circuits (direct,
  relayed, transit) and tracked flows. Below that: throughput on the agent's
  hops over the last 5 minutes, the hops listed worst link first, network
  facts (overlay pool, tree version and root, head expiry, validity, policy
  version, PSK epoch, with *Rotate PSK* for admins), relay load from the
  relays' link-state adverts, and the agent's alarms.
- **Connections**: the flows the agent tracks (§14.4): direction, protocol,
  addresses and ports, peer, state, the circuit the peer's traffic takes
  (direct, or via which relays), the rule that admitted the flow, and idle
  time. You can filter on any column. The counts and the conntrack limits
  are shown above the table. Selecting a flow shows its circuit's path,
  round trip, loss and route traffic, with links to the graph and the peer
  node. With nothing selected, the side panel lists the end-to-end sessions
  and the circuit each one sends on.
- **Nodes**: a graph of the network. It has one vertex per node (controllers
  and relays marked) and one edge per pair of nodes that report a link: relay
  links from link-state adverts, edge nodes' attachments to their home relays
  (dashed), and this agent's own hops (thick). Edges are colored by round
  trip and loss and labeled with the round trip. Selecting a node highlights
  its edges and shows its record, relay load, and every report of each of
  its links (who reported it, transport, round trip, loss, use, address,
  bytes), along with the changes the account may make. The circuit area
  below lists this agent's circuits, with ★ on the one a session sends on.
  Selecting a circuit draws its path in the graph and shows its hops, state,
  round trip, probes, and its route's traffic and drops. With no circuit
  selected, the area lists the routes relayed through this node.
- **Metrics**: the OpenMetrics families the agent exports (§12.5), the same
  text Prometheus scrapes. You can filter on name, help or label value.
  Selecting a family shows its help text and its samples with their labels,
  values and timestamps. On a controller, a switch shows every node's latest
  report instead of only this node's.
- **Accounts**: each account (all of them for admins; your own for a normal
  account), with role, status and number of nodes. Selecting one shows its
  id, key, record version, what it may do, and its nodes, which link to the
  Nodes tab.

## Tests

```sh
cargo test -p webjet-app                 # permissions, decoding, signing, graph layout,
                                         # metrics parsing; every tab rendered headless
scripts/local-net.sh 2
cargo test -p webjet-app --test live     # against the local network
```

The live test signs in as the admin and as a normal account, checks what
each may do, renames the normal account's own node through the controller,
checks that the controller refuses a tag change by the normal account, and
undoes its changes as the admin. A second live test checks the data behind
the tabs: sessions and circuits, the graph with this agent's hops as edges,
the conntrack answer and the agent's metrics. Both are skipped when no local
network runs.

The headless render test draws every tab from `tests/fixtures/node-02.json`,
the agents' answers captured from `scripts/local-net.sh 4`. Capture it again
after changing what the agent reports.
