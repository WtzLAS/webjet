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

Since 0.5.1 every local user can open the agent's control socket, so the app
runs as your own user, without `sudo`. (Agents up to 0.5.0 let only root, or
administrators on Windows, in.) The socket shows the network and passes on
operations; every change still needs a signature from an account key, which
the app makes with your key.

Building needs no extra tools on macOS: the app compiles GPUI's Metal shaders
at run time, so the Xcode Command Line Tools are enough. On Linux, GPUI needs
the usual X11/Wayland and Vulkan development packages.

## Signing in

The app lists the account keys in the key directory. Pick one and enter its
passphrase. The account `webjetctl` would sign with is already selected:
`WEBJET_ACCOUNT` if set, else the default account
(`webjetctl network account use <name>`, marked "default" in the list), else
the only key. The app then checks the account against the network:

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
| Merkle tab: state tree, leaves, proofs | yes | yes |
| Merkle tab: operation log | yes | no |
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
Connections, Nodes, Merkle and Metrics tabs need webjetd's `sessions`,
`conntrack`, `topology`, `merkle`, `log` and `metrics` control commands
(`merkle` and `log` are new in 0.5.0). With an older agent the app says the data
isn't available.

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
  and the circuit each one sends on. The *reverse proxy* switch shows the
  agent's reverse proxy flows instead (§11.11), kept apart from the overlay's:
  the side (listening here, or this node as a target), rule, client, target,
  the node at the other end and state. With nothing selected, the side panel
  lists the node's proxy rules with their status and warnings, whether it
  accepts real client addresses, and each rule's traffic.
- **Nodes**: a graph of the network. It has one vertex per node (controllers
  and relays marked) and one edge per pair of nodes that report a link: relay
  links from link-state adverts, edge nodes' attachments to their home relays
  (dashed), and this agent's own hops (thick). Edges are colored by round
  trip and loss and labeled with the round trip. Selecting a node highlights
  its edges and shows its record, relay load, and every report of each of
  its links (who reported it, transport, round trip, loss, use, address,
  bytes), along with the changes the account may make.

  The graph moves: drag the background (or scroll with two fingers) to move
  the picture, and use the mouse wheel, ⌘/Ctrl + scroll or the − / + buttons
  to zoom around the pointer. *Fit* goes back to the whole picture. Drag a
  node to place it; a short press without moving selects it. Placed nodes
  stay where you put them across refreshes until *Re-layout*, which also
  resets the zoom. The circuit area
  below lists this agent's circuits, with ★ on the one a session sends on.
  Selecting a circuit draws its path in the graph and shows its hops, state,
  round trip, probes, and its route's traffic and drops. With no circuit
  selected, the area lists the routes relayed through this node.
- **Merkle**: the network's state tree (§6.4) as the agent holds it. The
  top row shows the signed tree head (version, root, the controller whose
  signing key signed it, issue and expiry times) next to the root the app
  recomputes from the leaves, with a chip saying whether they match. On a
  controller the tree is the controller's own state machine, which may be
  a little ahead of the last signed head. Beside it are the genesis keys
  (root, emergency, first admin) and the controllers' signing-key
  certificates, each with who signed it (the root key or an admin) and
  whether it counts. Below, a map of the 256 subtrees at depth 8 (the
  buckets gossip compares; click one to list only its leaves) and the leaf
  list, filterable by name, kind, signer or hash prefix. Selecting a leaf
  shows its decoded record, who vouches for it (account records carry their
  own signature, by the root key or an admin; every other leaf is built by
  the controllers and covered by the head's signature), the log entry that
  last wrote it, and its inclusion proof: path, leaf hash and every
  non-empty sibling from the leaf up to the root, checked by the app.

  For admins, the right column is the controllers' operation log, newest
  first: every committed entry still in the Raft log (older ones were
  compacted into a snapshot), with the operation, who signed it (account,
  root key, emergency key or node), when, and its index. *Load older* pages
  back. Selecting an entry shows what applying it did, the signing key, the
  account's operation sequence number and issue time, the log index and
  term, and the leaves it wrote, each marked still current, changed since
  or deleted, and linked to the leaf. The app reads the log with a request
  signed by the admin's account key; controllers refuse requests from other
  accounts, and requests more than 5 minutes off their clock. Secrets in
  log entries (the PSK the leader chose, the camouflage private key) are
  never sent.
- **Metrics**: the OpenMetrics families the agent exports (§12.5), the same
  text Prometheus scrapes. You can filter on name, help or label value.
  Selecting a family shows its help text and its samples with their labels,
  values and timestamps. On a controller, a switch shows every node's latest
  report instead of only this node's.
- **Accounts**: each account (all of them for admins; your own for a normal
  account), with role, status and number of nodes. Selecting one shows its
  id, key, record version, what it may do, and its nodes, which link to the
  Nodes tab.

The separators between the panes of a tab can be moved: drag one to give
either side more room, double-click it to put it back. On the Nodes tab
that is the line between the graph and the node details, the one between
the graph and the circuits, and the one between the circuit list and the
selected circuit; on the other tabs it is the line beside the details
column (on the Merkle tab also the one beside the operation log, on the
Dashboard the ones beside the hops and the relay load). A pane
keeps the size you gave it when the window is resized, giving way only
when the other side would get too small. Sizes last until the app quits.

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
the conntrack answer and the agent's metrics. A third rebuilds the state
tree from the agent's leaves and checks it against the signed root, every
node's leaf and proof, the root signature on the first admin's record, and
the operation log read through node-02 (genesis signed by the root key,
alice's operations, paging), and that a normal account's log request is
refused. They are skipped when no local network runs.

The headless render test draws every tab from `tests/fixtures/node-02.json`
and drives the graph with simulated mouse events (drag a node, click it, pan,
wheel zoom),
the agents' answers captured from `scripts/local-net.sh 4`. Capture it again
after changing what the agent reports. `nodes_tab_fits` checks the Nodes
tab's layout at several window sizes and drags its three separators.
