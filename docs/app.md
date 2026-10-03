# Webjet desktop app

`webjet-app` shows a Webjet network: its state, its nodes and, for admins,
its accounts. It talks to the `webjetd` agent on the same machine, like
`webjetctl` does, and signs changes with your account key.

## Running it

```sh
cargo run --release -p webjet-app
webjet-app --socket /run/webjet/control.sock --keys ~/.config/webjet/accounts
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

Accounts are created as before: `webjetctl account keygen`, then an admin
adds the account (`webjetctl account create`).

## What each account sees

| | Admin account | Normal account |
| --- | --- | --- |
| Network overview (tree version, validity, controllers, PSK epoch, alarms) | yes | yes |
| Node list and details | yes | yes |
| Accounts tab | yes | no |
| Rename or revoke a node | any node | only nodes it owns |
| Set a node's tags | yes | no |
| Rotate the PSK | yes | no |

The app only offers what the account may do. The controllers check every
operation independently; a change the app wouldn't offer would be refused
anyway.

Revoking a node and rotating the PSK ask for a second click.

## Views

- **Network**: the overlay pool, how many nodes, relays and controllers there
  are, the signed tree's version and root, when the current tree head
  expires, the network's validity horizon, the policy version and PSK epoch,
  and the agent's alarms.
- **Nodes**: all nodes with a filter (name, address, tag, owner or role).
  Selecting one shows its id, key, addresses, roles, tags, subnet routes,
  owner and record version, and the changes the account may make.
- **Accounts** (admins): each account, whether it is an admin, active or
  revoked, and how many active nodes it owns.
- **This agent**: the local node, its version and uptime, and its hop
  sessions with transport, address, round-trip time and loss.

## Tests

```sh
cargo test -p webjet-app                 # permissions, decoding, signing (no window)
scripts/local-net.sh 2
cargo test -p webjet-app --test live     # against the local network
```

The live test signs in as the admin and as a normal account, checks what
each may do, renames the normal account's own node through the controller,
checks that the controller refuses a tag change by the normal account, and
undoes its changes as the admin. It is skipped when no local network runs.
