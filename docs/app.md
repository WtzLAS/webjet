# Webjet desktop app

`webjet-app` shows a Webjet network: its state, its nodes and, for admins,
its accounts and configuration. It talks to the `webjetd` agent on the same machine, like
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

Releases from 0.11.0 include the app for Linux (x86_64, arm64), FreeBSD
(x86_64), macOS (arm64, x86_64) and Windows (x86_64). From 0.12.0 it is in
the release archive `webjet-<tag>-<target>.tar.gz` (Windows: `.zip`) next to
`webjetd` and `webjetctl`, and `webjetup install` puts it with them
(`/usr/local/bin/webjet-app`; on Windows `C:\Program Files\Webjet\webjet-app.exe`
with a "Webjet" Start menu shortcut), so it is upgraded with the agent; it
can also be unpacked from the archive and run from anywhere. Releases
0.11.0 to 0.11.6 had it in a separate `webjet-app-<tag>-<target>` archive.
On Linux and FreeBSD it needs a
graphical session (X11 or Wayland) with Vulkan, plus libxkbcommon and libxcb
(Debian/Ubuntu: `libxkbcommon-x11-0` `libvulkan1`, and a Vulkan driver such
as `mesa-vulkan-drivers`; FreeBSD: `pkg install libxkbcommon vulkan-loader
mesa-libs`). On macOS (11 or later) it is a plain program, not an `.app`
bundle, and isn't notarized: a browser download is quarantined, so run
`xattr -d com.apple.quarantine webjet-app` once (downloads with `curl` aren't
quarantined). On Windows (10 or later) it runs as `webjet-app.exe`; it uses Direct3D 11 and compiles its shaders when
it starts, with the `d3dcompiler_47.dll` Windows ships. The Windows app is
cross-built and its unit tests pass under Wine, but it hasn't been started on
real Windows yet (Wine can't run it: its DirectWrite has no font sets).

Building needs no extra tools on macOS: the app compiles GPUI's Metal shaders
at run time, so the Xcode Command Line Tools are enough. On Linux, building
needs libxkbcommon, libxkbcommon-x11 and libxcb with their headers
(Debian/Ubuntu: `libxkbcommon-dev libxkbcommon-x11-dev libxcb1-dev`);
Wayland and Vulkan are loaded at run time.

## Signing in

The app lists the account keys in the key directory. Pick one and enter its
passphrase, then press Enter or *Sign in*. The account `webjetctl` would
sign with is already selected:
`WEBJET_ACCOUNT` if set, else the default account
(`webjetctl network account use <name>`, marked "default" in the list), else
the only key. The app then checks the account against the network:

- an account that isn't in this network, or has been revoked, can't sign in;
- a key that doesn't match the account's current record can't sign in;
- if the account is revoked or demoted while the app runs, you are signed out
  or lose admin rights at the next refresh (every 2 s).

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
| Config tab: edit the network's and any node's configuration | yes | no (the tab isn't shown) |

The app only offers what the account may do. The controllers check every
operation on their own, so a change the app wouldn't offer is refused
anyway.

Revoking a node, rotating the PSK and applying a configuration need a
second click.

## Tabs

Everything is seen from the local agent and refreshes every 2 s. The
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
  and the circuit each one sends on. The switch above the table, *overlay
  flows (N)* / *reverse proxy (N)*, shows how many flows each side tracks;
  *reverse proxy* shows the agent's reverse proxy flows instead (§11.11),
  kept apart from the overlay's:
  the side (listening here, or this node as a target), rule, client, target,
  the node at the other end and state. With nothing selected, the side panel
  lists the node's proxy rules with their status and warnings, whether it
  accepts real client addresses, and each rule's traffic.
- **Nodes**: a graph of the network. It has one vertex per node (controllers
  and relays marked) and one edge per pair of nodes that report a link: relay
  links from link-state adverts, edge nodes' attachments to their home relays,
  and this agent's own hops. Links that a session's circuit sends on (★ in
  the circuit list) are drawn bold and fully opaque; the others are thinner
  and faded to 70%, and the labels' backgrounds are 70% opaque so crowded
  links stay visible. Edges are colored by round trip and loss and labeled
  with the round trip. While the tab is open the agent also subscribes to
  every node's attachment records, so an edge node shows the links and delays
  of all nodes, not only of the peers it talks to. Each vertex is labeled with
  the webjetd version the node runs (from its endpoint record). A node whose
  software is below this agent's gossip protocol floor (architecture
  §10.6.5, for example 0.6.x) is drawn dimmed and marked `outdated`. The
  agent ignores its records, so it has no links in the graph. Selecting a
  node highlights its edges and shows its record, software version, relay
  load, its NAT type (none,
  consistent, symmetric or unknown, from its endpoint record; for this
  agent also the router port mapping) and advertised addresses (public,
  reflexive, host), and every report of each of
  its links (who reported it, transport, round trip, loss, use, address,
  bytes), along with the changes the account may make.

  A selected node (its links and the nodes at their other ends) and a
  selected circuit (its links and nodes), or both, are drawn above
  everything else, with solid label backgrounds; all other links, delays and
  nodes are dimmed, so a crowded graph stays readable.

  The layout (`crates/webjet-app/src/graph/layout.rs`) is made for the size of the
  drawing area and takes the labels' sizes into account. Each connected
  part of the network is laid out on its own: stress majorization places
  nodes so that their distances follow the number of hops between them,
  from several starting pictures. A cost counts edge crossings, edges
  running through another node's label, overlapping labels, edges leaving a
  node at nearly the same angle, and distances off the wanted ones.
  Simulated annealing (small parts) or a local search of moves and swaps
  (large ones) lowers it. Overlapping labels are then pushed apart, the
  parts are packed in rows, largest first, and the whole is scaled to fit.
  The whole picture is laid out only once: for the first snapshot (again
  when the drawing area is first measured, if no node was moved yet) and
  when you press *Re-layout*. After that, nodes never move by themselves:
  when links come or go, labels change or the window is resized, every node
  stays where it is (the picture stretches with the area). A new node is put
  next to its neighbors, at the nearest free spot, preferring short links
  without crossings and labels in the way; a node that goes away leaves a
  gap. Only when none of the shown nodes is left (another network) is the
  graph laid out afresh. A full layout runs in the background; until it is
  done the graph shows the nodes at their old places. The same network
  always gets the same picture.

  The graph moves: drag the background (or scroll with two fingers) to move
  the picture, and pinch the trackpad, use the mouse wheel, ⌘/Ctrl + scroll
  or the − / + buttons to zoom around the pointer. *Fit* goes back to the
  whole picture. Drag a node to place it; a short press without moving selects it. Placed nodes
  stay where you put them until *Re-layout*, which also resets the zoom and
  lays the graph out from scratch for the area's current size. The circuit area
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
- **Config** (admins only): edit the network configuration (§6.18) and the
  own configuration of any node (§6.19): this agent's node or a remote one,
  picked from the list on the left (filter by name, tag or role). The editor
  holds the same TOML file `webjetctl network config show` or `webjetctl
  local config --node <name> show` prints (see docs/configuration.md), with
  line numbers and highlighting. It is checked as you type, with the checks
  `webjetctl … config check` runs (the policy tests included); the line
  under the editor says what the file would change or why it is refused.
  For a node, *in force* shows what applies to it: the network's values with
  its own overrides and additions (read-only). *Apply* (a second click
  confirms) loads what is in force again, refuses the file if someone applied
  a newer version meanwhile, as `apply` does, then signs the operations with
  your account key, submits them through the agent and waits until the agent
  shows the new version. For a node, an empty file removes its own
  configuration. *Revert* drops your edits, *Reload* fetches the
  configuration again; leaving a configuration with unapplied edits needs a
  second click. A refuse-mode camouflage section without a certificate gets
  a self-signed one, as with `webjetctl`. Keys: arrows (with Shift to
  select, ⌥ by word, ⌘ to the line or file ends), ⌘A, ⌘C/⌘X/⌘V, ⌘Z / ⇧⌘Z
  undo and redo, Tab / ⇧Tab indent, ⌘/ comments lines out; double-click
  selects a word, triple-click a line (Ctrl instead of ⌘ on Linux and
  Windows).

The separators between the panes of a tab can be moved: drag one to give
either side more room, double-click it to put it back. On the Nodes tab
that is the line between the graph and the node details, the one between
the graph and the circuits, and the one between the circuit list and the
selected circuit; on the other tabs it is the line beside the details
column (on the Config tab, beside the list of configurations) (on the Merkle tab also the one beside the operation log, the one
below the tree summary and the two between the signed head, the genesis
and the signing keys, whose panels scroll when made short; on the
Dashboard the ones beside the hops and the relay load). A pane
keeps the size you gave it when the window is resized, giving way only
when the other side would get too small. Sizes last until the app quits.

## Tests

```sh
cargo test -p webjet-app                 # permissions, decoding, signing, graph layout,
                                         # metrics parsing, the config editor; every tab
                                         # rendered headless
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
refused. A fourth applies a network configuration change (a DNS record) and
a remote node's own configuration (ctl-01 seen from node-02), checks that
the stale file is then refused, and clears the node's configuration again.
They are skipped when no local network runs.

The headless render test draws every tab from `tests/fixtures/node-02.json`
and drives the graph with simulated mouse events (drag a node, click it, pan,
wheel and pinch zoom),
the agents' answers captured from `scripts/local-net.sh 4`. Capture it again
after changing what the agent reports. `nodes_tab_fits` checks the Nodes
tab's layout at several window sizes and drags its three separators.
`merkle_separators_move` drags every Merkle separator at several window
sizes, and `the_node_list_scrolls_alone` checks that the wheel over the
node finder's list doesn't also scroll the node details around it.
`circuit_details_do_not_overlap` checks that a selected circuit's details
(long node names, narrow pane) wrap inside their own rows, and
`graph_labels_do_not_overlap` that no two node labels in the drawn graph
overlap. The layout itself is tested in `graph::layout::tests` (the network from a
bug report at several area sizes: no overlapping labels, at most a few
crossings and edges through labels; a 40-node network; continuing from an
old picture; refreshes never moving a node and new nodes going into free
room next to their neighbors). `refreshes_do_not_move_the_nodes` checks the
same through the app's refresh path (`graph::tests`). `WEBJET_LAYOUT_SVG=<dir> cargo test -p webjet-app --lib
graph::layout::tests` writes the test pictures as SVG files to look at.
`config_tab_is_for_admins` types into the configuration editor (checked as
typed, undo), switches to a remote node's configuration with unapplied
edits, and checks that a demoted account loses the tab.
