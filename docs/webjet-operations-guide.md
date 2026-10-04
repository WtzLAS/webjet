# Webjet Operations Guide

**Status:** Draft
**Companion to:** Webjet Architecture (`webjet-architecture.md`). Section numbers such as "§7.5" refer to that document. Settings in `webjetd.toml` are described in [configuration.md](configuration.md); containers in [docker.md](docker.md).

Each command is marked with where it runs:

| Mark | Where |
|---|---|
| `[offline]` | The offline computer that holds the root and emergency revocation keys (`webjetctl root`) |
| `[admin]` | An admin's own machine, which holds their account key (`webjetctl`) |
| `[node]` | The machine being set up or repaired (`webjetup`, `webjetd`, `webjetctl`) |
| `[controller]` | A controller, through its local control channel (`webjetctl`) |

Files move to and from the offline computer on removable media only.

---

## Before you start

### Installing the programs

| Program | What it is | Where it's needed |
|---|---|---|
| `webjetup` | Installs, upgrades and removes Webjet | Every node |
| `webjetd` | The agent, run as a system service (`webjetd run`); `webjetd signer` optionally holds a controller's signing key in a separate process (runbook 1, step 4) | Every node |
| `webjetctl` | Three groups: `webjetctl network` changes the network (its configuration, nodes, accounts, controllers), signed with an account key; `webjetctl local` is about this machine and its node (`init`, `enroll`, `status`, `ping`, the node's own configuration); `webjetctl root` holds the offline root keys | Every node, admins' machines, the offline computer |

On every Linux or macOS machine that joins the network, as root:

```
curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.4.3/install.sh | sudo sh
```

This installs `webjetd`, `webjetctl` and `webjetup` into `/usr/local/bin` and sets up the `webjetd` service (systemd on Linux, running as the `webjet` user; launchd on macOS). On Windows, download `webjetup-<version>-x86_64-pc-windows-msvc.exe` from the release page and run `webjetup install` in an Administrator prompt. `sudo webjetup status` shows what is installed and running. Upgrades are `sudo webjetup upgrade`, and `webjetup remove` or `webjetup nuke` take Webjet off a machine again.

The offline computer gets no network. Copy the release archive for its platform (`webjet-<version>-<target>.tar.gz`, or the `.zip` on Windows) and its `.sha256` file over on removable media, check the checksum, and take `webjetctl` out of the archive. Only its `root` commands are used there.

### Running `webjetctl`

`webjetctl` talks to the Webjet agent on the machine where it runs, through the agent's control socket (`/var/run/webjet/control.sock`; a named pipe on Windows). Only root (Administrator on Windows) can open it, so run `webjetctl` with `sudo`. Operations are signed on that machine with your account key and sent to the controllers by the agent. Use either your own enrolled machine, or a controller's agent reached over SSH (see runbook 1, step 5).

Account keys live in `~/.config/webjet/accounts` (macOS: `~/Library/Application Support/webjet/accounts`; Windows: `%APPDATA%\webjet\accounts`). Run `webjetctl network account keygen` as yourself, without `sudo`. `sudo` on Linux changes the home directory, so point `webjetctl` at your key directory when signing:

```
sudo webjetctl --keys ~/.config/webjet/accounts --account alice network node list
```

The examples below leave out `sudo` and `--keys`. They also leave out `--account`. With one key in the directory, that key is used. With several, pick the usual one once:

```
webjetctl network account use alice        # recorded as `default` in the key directory
webjetctl network account use              # show the current choice; --clear forgets it
```

`--account` (or `WEBJET_ACCOUNT`) still overrides the default for a single command. `webjetctl network account list` marks with `*` the account it signs as. `webjetctl` asks for the key's passphrase. Scripts can set `WEBJET_ACCOUNT_PASSPHRASE` instead, and `webjetctl root` reads `WEBJET_ROOT_PASSPHRASE` and `WEBJET_BACKUP_PASSPHRASE`.

### Configuration

There are two kinds, both TOML ([configuration.md](configuration.md)):

- `/etc/webjet/webjetd.toml` on each machine: how that machine runs the agent (listen and public addresses, interface, key storage, metrics). Edit it by hand and restart the agent.
- The **network configuration** in the signed tree: policy, DNS, seeds, transport priorities and camouflage, limits. It has two scopes. `webjetctl network config` changes it for the whole network (admins). `webjetctl local config` changes it for one node (the node's owner or an admin), which overrides the network's values for that node: transport priorities and limits, plus extra seeds and DNS entries. Both have the same verbs: `show`, `check <file>`, `apply <file>`, `edit`, and `get`/`set`/`unset <key>` for one value.

### Reading the output

Times in `webjetctl local status` and `webjetctl network controller list` (`valid_until`, `head_expires`, alarm `since`) are Unix times in milliseconds. `--json` prints any command's output as JSON.

---

## Contents

1. Bootstrap a new network
2. Add a device for a person (a data node), with a new account if needed
3. Add a relay
4. Add a controller and promote it to voter
5. Replace a lost voter
6. Rotate the PSK
7. Renew or replace the camouflage certificate
8. Revoke a lost device or an account
9. Re-key a reinstalled node
10. Retire a controller's signing key
11. Roll out a release with a schema change
12. A majority of voters is lost
13. Add an admin

---

## 1. Bootstrap a new network

**When:** once, to create the network. References: §13.5, §7.5, §5.

**You need:**
- the offline computer
- one Linux host for the first controller, ideally with a public IP so it can also be a relay
- the first admin's machine
- the overlay address range you will use, for example `10.7.0.0/16`

**Steps:**

1. Create the root and emergency revocation keys, and back them up encrypted on two separate media. Both commands ask for a new passphrase twice.
   ```
   [offline]  webjetctl root --dir ./webjet-root init
   [offline]  webjetctl root --dir ./webjet-root backup --out /media/usb1/root-backup.enc
   ```
   Every `webjetctl root` command takes the same `--dir`. It defaults to `./webjet-root`, which is what the examples below assume.
2. Create the first admin's account key. It never leaves the admin's machine; copy only `alice.pub` to the offline computer.
   ```
   [admin]    webjetctl network account keygen --name alice --pub-out alice.pub
   ```
3. Sign the admin account with the root key and build the genesis file. The genesis file holds the root public key, the emergency key's certificate, the first admin account and the overlay range.
   ```
   [offline]  webjetctl root admin sign --name alice --key alice.pub --out alice.account
   [offline]  webjetctl root genesis --overlay-pool 10.7.0.0/16 --admin alice.account --out genesis.wj
   ```
4. Start the first controller as a one-member cluster. Install Webjet without starting the agent, give the addresses others reach it on in `/etc/webjet/webjetd.toml`, initialize it with the genesis file, and start it. A node initialized with the genesis file runs the controller role from the start; every later controller gets it from the `control` role (runbook 4).
   ```
   [node]     curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.4.3/install.sh | sudo sh -s -- --no-start
   [node]     sudoedit /etc/webjet/webjetd.toml
   ```
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
   ```
   ```
   [node]     sudo webjetctl local init --genesis genesis.wj
   [node]     sudo systemctl start webjetd
   [node]     sudo webjetctl network controller list      # wait for a non-zero valid_until
   ```
   The controller's signing key is created on first start, as `signing.key` in `/var/lib/webjet`. To keep it out of the agent's process, run `webjetd signer --socket /var/run/webjet-signer/signer.sock --key /var/lib/webjet-signer/signing.key` as its own service before the first start, and set `signer_socket = "/var/run/webjet-signer/signer.sock"` in the `[controller]` section. The signer's socket is private to the user it runs as, so on Linux run the signer as the `webjet` user too. There is no ready-made service file for it.
5. Create an account to own infrastructure nodes, and enroll the controller's own node. The overlay doesn't exist yet, so the admin's operations go through the controller's agent. Either run them on the controller with the admin's key directory copied there for the bootstrap (remove it afterwards), or forward the controller's control socket to the admin's machine over SSH and point `webjetctl` at it:
   ```
   [admin]    ssh -N -L /tmp/ctl-01.sock:/var/run/webjet/control.sock root@ctl-01 &
   [admin]    export WEBJET_SOCKET=/tmp/ctl-01.sock
   ```
   Then:
   ```
   [admin]    webjetctl network account keygen --name infra --pub-out infra.pub
   [admin]    webjetctl network account create --name infra --key infra.pub
   [admin]    webjetctl network node enroll --owner infra --name ctl-01 --ip 10.7.0.1 \
                  --roles data,relay,control --tags tag:infra --controller tls:203.0.113.10:443
              → prints an enrollment string
   [node]     sudo webjetctl local enroll '<enrollment string>'
   ```
   The first controller enrolls its own node through its running agent, so leave the agent running here; `webjetctl local enroll` talks to it. Every other node is enrolled with `webjetup enroll` (runbooks 3 and 9), which stops the agent, enrolls and starts it again. The enrollment string is valid for 24 hours (`--expires-hours`).
6. Certify the controller's signing key with the admin key. `certify` fetches the node's certificate request, signs it and submits the certificate; it prints the key ID, note it for runbook 10.
   ```
   [admin]    webjetctl network controller certify ctl-01
   ```
   From now on, nodes accept this controller's tree heads. `webjetctl network node list` shows `control` among its roles (`control(uncertified)` before this step). The root can sign the certificate instead, offline, which keeps it valid even if the admin is later revoked (an admin's certificates become void when the admin is revoked or changes key):
   ```
   [controller]  webjetctl network controller cert-request --out ctl-01.req
   [offline]     webjetctl root controller sign ctl-01.req --out ctl-01.cert
   [admin]       webjetctl network submit ctl-01.cert
   ```
7. Apply the first network configuration. Policy, DNS, seeds, transport priorities, camouflage and limits are one TOML document, the network configuration ([configuration.md](configuration.md#the-network-configuration)). `show` prints the one in force as a file `apply` accepts; on a new network that's the built-in defaults with `version = 0`. Edit it and apply it: `apply` submits it as the next version and refuses a file made from an older version, so nobody overwrites someone else's change unseen. `check` validates (and runs the policy tests) without submitting.
   ```
   [admin]    webjetctl network psk rotate                     # creates the first PSK epoch
   [admin]    webjetctl network config show > network.toml     # the defaults, version = 0
   [admin]    $EDITOR network.toml                             # see below
   [admin]    webjetctl network config check network.toml
   [admin]    webjetctl network config apply network.toml      # applies version 1
   [admin]    webjetctl network camouflage set-secret --key site.key --site ./site/   # website mode only
   ```
   `webjetctl network config edit` does show, edit and apply in one step. Every setting has a built-in default, so you only need to change what you want different, and you can leave sections out: a file with only `[policy]` changes only the policy. Without a policy rule nothing is allowed (default deny), and without seeds nodes find the network through the controllers in their enrollment strings. DNS works without changes: the suffix is `internal` and the resolver is the top address of the overlay pool (10.7.255.254 for 10.7.0.0/16), which is never given to a node. A minimal start:
   ```toml
   version = 0                  # as show printed it

   [policy]
   default = "deny"

   [[policy.rule]]
   id = "everyone"
   action = "allow"
   src = ["*"]
   dst = ["*"]
   ports = ["*"]

   [dns]
   suffix = "internal"
   resolver_ip = ["10.7.255.53"]   # optional; leave out to keep the default

   [[seeds]]
   node = "ctl-01"
   addrs = ["tls:203.0.113.10:443", "kcp:203.0.113.10:443"]

   [transport.priority]         # 0–255 per transport; 0 = never use (§9.6)
   kcp = 30                     # UDP+KCP+FEC
   anytls = 20                  # TCP+AnyTLS
   tls = 10                     # TCP+TLS

   [[transport.override]]       # checked in order, per transport
   select = ["tag:relay", "role:control"]
   priority = { tls = 40 }      # datacenter hosts: plain TLS is fine there

   [transport.camouflage]
   mode = "refuse"              # or "website", see below
   ```
   The priorities above are the built-in ones. For each transport, a node takes its priority from its own node configuration (`webjetctl local config`, see [configuration.md](configuration.md#node-scope)), else from the first override that selects it and lists that transport, else from `[transport.priority]`. `select` takes the same selectors as policy rules (`tag:…`, `role:relay|data|control`, `node:<name>`, `owner:<account>`).

   The camouflage mode decides what a relay's AnyTLS port shows to a connection that doesn't authenticate (§9.7.2):
   - **`refuse`** closes the connection. It needs no domain, certificate or website, and `apply` ignores those fields in this mode. AnyTLS clients still pin a certificate, so `apply` keeps the network's current one, or on a network without one makes a self-signed certificate for a random domain and stores its key with the controllers first. Use refuse to start with; a probe can tell the port isn't an ordinary website.
   - **`website`** serves a website, which holds up to active probing. It needs a domain whose public DNS points at the relays and a CA certificate for it:
     ```toml
     [transport.camouflage]
     mode = "website"
     domain = "cdn.example.com"
     certificate = "site.crt"   # PEM chain, leaf first; relative to this file, or PEM text
     ```
     The certificate is read when you apply and sent with the configuration; `show` prints it back as PEM text, so a shown file applies again unchanged. `network camouflage set-secret` supplies the certificate's private key and the website relays serve. `webjetctl network camouflage selfsign --domain cdn.example.com --cert-out site.crt --key-out site.key` makes a self-signed certificate for testing website mode in a lab.

   Without `[transport.camouflage]` the priorities still apply, and relays don't offer AnyTLS.
8. Grow the cluster: add two more controllers and promote them, so there are three voters, then continue to five (runbook 4). Add relays (runbook 3), and update the seed list to at least two entries.
9. Set up monitoring. Set `[metrics] listen` on the controllers (for example their overlay address and port 9469). Each controller then serves every node's latest report as OpenMetrics text at `/metrics`, so Prometheus can scrape any one of them. There's no authentication on that endpoint, so don't expose it to the internet (§12.5).
10. Enroll the admin's own device with `webjetup` and an enrollment string, and add a policy rule that lets admin devices reach the controllers. From then on, run `webjetctl` there against the device's own agent; the SSH forward from step 5 is no longer needed.

**Check:**
- `webjetctl local status` on a second node shows the current tree version and no alarms.
- A test node can be enrolled and reaches another node by name (`webjetctl local ping <name>`).

**Notes:**
- Until step 6 is done, no node trusts the tree.
- Until there are three voters, losing the one controller stops all changes.
- Add more admins with runbook 13, so the network doesn't depend on one person's key.

---

## 2. Add a device for a person (a data node)

**When:** someone needs a laptop, desktop or server on the network, either a new person or someone who already has an account. References: §13.3, §8.

A data node is the default kind of node: it sends and receives its own traffic, and relays nothing for others. Every node is owned by an account. The owner can rename the device, revoke it (for example when it's lost) and re-key it after a reinstall (runbook 9) without an admin. Only an admin can enroll devices or change their tags, addresses, roles or owner, because those decide what the device may reach.

**You need:** an admin account, and the person's device with Linux, macOS or Windows.

**Steps:**

1. **New person only:** create their account. The person makes the key on their own machine, where it stays, and sends you only the public file. If they will never run `webjetctl` themselves, you can make the key for them and keep it.
   ```
   [person]   webjetctl network account keygen --name bob --pub-out bob.pub
   [admin]    webjetctl network account create --name bob --key bob.pub
   [admin]    webjetctl network account list                  # bob, VALID true, ADMIN false
   ```
   Account names are 1–32 lowercase letters, digits and `-`, unique in the network. The account can only manage its own devices; admin accounts are made offline with the root key (runbook 13).
2. Choose the tags the device gets. Tags are how the policy decides what it may reach (§14), and the device's owner can't change them. Check what the current rules allow those tags, and if needed add a rule and apply the policy again. For example, to let laptops reach the web servers on HTTPS:
   ```toml
   # network.toml (excerpt): the [policy] section of `network config show`
   [[policy.rule]]
   id = "laptops-to-web"
   action = "allow"
   src = ["tag:laptop"]
   dst = ["tag:web"]
   ports = ["tcp:443"]

   [[policy.test]]
   src = "tag:laptop"
   dst = "tag:web"
   port = "tcp:443"
   expect = "allow"

   [[policy.test]]
   src = "tag:laptop"
   dst = "tag:db"
   port = "tcp:5432"
   expect = "deny"
   ```
   ```
   [admin]    webjetctl network config show > network.toml     # start from what is in force
   [admin]    webjetctl network config check network.toml      # runs the tests, submits nothing
   [admin]    webjetctl network config apply network.toml
   ```
   `owner:bob` in a rule matches every device bob owns, if access should follow the person rather than the kind of device.
3. Create the enrollment. The overlay address is picked from the pool unless you give `--ip`; `--roles` defaults to `data`.
   ```
   [admin]    webjetctl network node enroll --owner bob --name bob-laptop --tags tag:laptop
              → prints an enrollment string
   ```
   The string is valid for 24 hours (`--expires-hours` changes that) and can be used once. Treat it like a password until then: whoever redeems it first gets the device's place in the network. Send it to the person over a channel you trust.
4. On the device, install Webjet and enroll it in one step. On Linux and macOS:
   ```
   [node]     curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.4.3/install.sh \
                  | sudo sh -s -- --enroll '<enrollment string>'
   ```
   On Windows, download `webjetup-v0.4.3-x86_64-pc-windows-msvc.exe` from the release page and run, in an Administrator prompt:
   ```
   [node]     webjetup-v0.4.3-x86_64-pc-windows-msvc.exe install --enroll "<enrollment string>"
   ```
   On a device that already has Webjet installed, `sudo webjetup enroll '<enrollment string>'` does the same. A device doesn't need a public address or open ports: it reaches the network through relays, and connects directly to other nodes where NAT allows (§10).
5. If the person will administer their own devices from it (rename, revoke, re-key), they run `webjetctl` there with their key; see "Running `webjetctl`" above.

**Check:**
- On the device, `sudo webjetctl local status` shows its name, its overlay address and no alarms.
- `sudo webjetctl local ping <name>` reaches a node the policy allows, and the device resolves names under the DNS suffix (`<name>.internal` by default).
- On any node, `webjetctl network node list` lists the device with its owner.

**Later:**
- The owner, or an admin, renames it with `webjetctl network node rename bob-laptop bob-mbp`.
- Only an admin changes its tags or owner: `webjetctl network node update bob-laptop --tags tag:laptop,tag:dev`, or `--owner carol` when the device changes hands.
- A lost device is revoked (runbook 8), a reinstalled one re-keyed (runbook 9). When the person leaves, `webjetctl network account revoke bob` removes the account and every device it owns.

---

## 3. Add a relay

**When:** to add capacity, cover a new region, or replace a relay. References: §4, §8, §11.8.

**You need:** a Linux host with a public IP address, synchronized time, and its transport ports open from the internet.

**Steps:**

1. Check that each port you plan to listen on is reachable from outside. The examples use 443 over TCP (TLS) and UDP (KCP). Without a `[listen]` section a node listens on nothing and only dials out.
2. Create an enrollment with the `RELAY` role.
   ```
   [admin]    webjetctl network node enroll --owner infra --name relay-07 --ip 10.7.0.27 \
                  --roles data,relay --tags tag:relay
   ```
3. On the host, install Webjet without starting it. In `/etc/webjet/webjetd.toml`, set the addresses others reach it on and the listen addresses. Then enroll.
   ```
   [node]     curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.4.3/install.sh | sudo sh -s -- --no-start
   [node]     sudoedit /etc/webjet/webjetd.toml       # [[public]], [listen]
   [node]     sudo webjetup enroll '<enrollment string>'
   ```
   For example:
   ```toml
   [listen]
   tls = "0.0.0.0:443"
   kcp = "0.0.0.0:443"

   [[public]]
   addr = "203.0.113.27:443"
   transport = "tls"
   [[public]]
   addr = "203.0.113.27:443"
   transport = "kcp"
   ```
   [configuration.md](configuration.md) has a fuller relay configuration. The `webjetd` service may bind ports below 1024 (`CAP_NET_BIND_SERVICE` in its unit). The relay fetches the camouflage certificate key and website from a controller by itself (§9.7.2). If you know the relay's forwarding capacity, set it in its node configuration once it is enrolled (otherwise the agent estimates it):
   ```
   [admin]    webjetctl local config --node relay-07 set limits.value.relay_capacity_mbps 1000
   ```
4. Add the relay's address to the camouflage domain's public DNS records.
5. If the relay's address is stable, add it to the seed list: add a `[[seeds]]` entry with `webjetctl network config edit`, or
   ```
   [admin]    webjetctl network config set seeds.2 '{node = "relay-07", addrs = ["tls:203.0.113.27:443", "kcp:203.0.113.27:443"]}'
   ```
   (`seeds.2` is the next free entry; `network config get seeds` lists them.) A node that should prefer a nearby relay can have it as its own first seed: `webjetctl local config --node <node> set seeds '[{node = "relay-07", addrs = [...]}]'`.

**Check:**
- `webjetctl local peers` on another relay lists the new one, with measured costs.
- The relay's `webjet_load_ratio` in the metrics stays low at first.
- An outside connection to its AnyTLS port, without credentials, gets the camouflage website (or is closed, in `REFUSE` mode).

**To take a relay out of service:** remove its role first, so new paths avoid it, then revoke or repurpose the node.
```
[admin]    webjetctl network node update relay-07 --roles data
```

---

## 4. Add a controller and promote it to voter

**When:** building the cluster up, or adding spare learners. References: §7.1, §7.5.

**You need:** a Linux node that is already enrolled (runbook 3 without the relay-specific steps; giving controllers `RELAY` as well is recommended). A new node can be enrolled with the `control` role right away (`--roles data,relay,control`); then skip step 1. In a network upgraded from 0.3.0 or earlier, every controller must run a release with the `control` role before you grant it (older controllers would diverge on the operation), and every node before you use `certify` (older nodes accept only root-signed certificates).

**Steps:**

1. Give the node the `control` role. `--roles` is the whole role set, so repeat the roles it keeps. The agent starts the controller role by itself within a minute, without a restart, and creates its signing key (or uses `webjetd signer`, see runbook 1, step 4; configure `signer_socket` before granting the role).
   ```
   [admin]    webjetctl network node update ctl-06 --roles data,relay,control
   ```
2. Certify its signing key. Note the key ID it prints.
   ```
   [admin]    webjetctl network controller certify ctl-06
   ```
   Or have the root sign it (see runbook 1, step 6):
   ```
   [node]     sudo webjetctl network controller cert-request --out ctl-06.req
   [offline]  webjetctl root controller sign ctl-06.req --out ctl-06.cert
   [admin]    webjetctl network submit ctl-06.cert
   ```
3. Add it to the cluster as a learner. It receives a snapshot, catches up and starts signing tree heads.
   ```
   [admin]    webjetctl network controller add-learner ctl-06
   ```
4. Wait until it has caught up.
   ```
   [node]     sudo webjetctl network controller list      # role: Learner; applied matches the leader's
   ```
5. To make it a voter, promote it. Keep the number of voters odd: promote two at a time when growing from three to five, or pair a promotion with a demotion (`webjetctl network controller demote`).
   ```
   [admin]    webjetctl network controller promote ctl-06
   ```

**Check:** `webjetctl network controller list` on a controller shows the intended voters and learners (by node ID) and a leader. `webjetctl local status` shows no alarms.

**If it goes wrong:** a learner that never catches up can be removed with `webjetctl network controller remove` without affecting writes.

---

## 5. Replace a lost voter

**When:** a voter is down and won't be back soon, or the "voters below a majority plus one" alarm fires. References: §7.4, §7.5.

**Steps:**

1. Find out whether the voter is dead or only unreachable. Check `webjetctl network controller list` on two other controllers. If it will be back within hours, do nothing: five voters tolerate two failures.
2. Promote a healthy, well-connected learner.
   ```
   [admin]    webjetctl network controller promote ctl-09
   ```
3. Remove the lost voter from the cluster.
   ```
   [admin]    webjetctl network controller remove ctl-03
   ```
4. If the machine is gone for good, or might have been compromised, retire its signing key (runbook 10). Never start it again without wiping it (`webjetup nuke`).
5. Add a new learner to restore the number of spares (runbook 4).

**Check:** five voters, one leader, no alarms.

---

## 6. Rotate the PSK

**When:** on a regular schedule, and after revoking a node that may have been compromised, since it knew the PSK. References: §7.6, §9.1, §10.7.3.

**Steps:**

1. Look for nodes that have been offline. They will catch up through a seed relay in bootstrap mode when they return, as long as at least two seeds are reachable. A node that hasn't reported for 15 minutes is missing from the controllers' metrics: compare `webjet_node_info` in Prometheus, or `webjetctl local metrics --all` on a controller, with `webjetctl network node list`.
2. Rotate.
   ```
   [admin]    webjetctl network psk rotate
   ```
3. Wait until online nodes show the new epoch before rotating again. Nodes accept only the current and previous epoch, so two quick rotations would push connected nodes into bootstrap mode.
   ```
   [node]     sudo webjetctl local status      # psk_epoch
   ```

**After a compromise:** rotate **twice**, waiting for step 3 in between. After one rotation, the epoch the revoked node knew is still accepted as "previous".

**Check:** nodes report the new epoch, and there is no sustained rise in connections dropped at the PSK gate.

---

## 7. Renew or replace the camouflage certificate

**When:** the "camouflage certificate expires in under 14 days" alarm, or a key change. References: §9.7.2, §6.17.

### Renew with the same key

Clients pin the certificate's public key, so they need no change.

1. Obtain the renewed certificate from the CA for the same key.
2. Publish it.
   ```
   [admin]    webjetctl network config edit     # new chain in transport.camouflage.certificate
   ```

### Replace the key

1. Generate the new key and obtain a certificate for it.
2. Announce the new key ahead of time, and wait at least as long as nodes are normally offline (for example 14 days).
   ```
   [admin]    webjetctl network config set transport.camouflage.next_certificate new-site.crt
   ```
3. Switch.
   ```
   [admin]    webjetctl network camouflage set-secret --key new-site.key --site ./site/
   [admin]    webjetctl network config edit     # certificate = "new-site.crt", next_spki removed
   ```

A node that was offline through the whole announcement period can't use AnyTLS until it has synced over another transport.

**If the key was compromised:** do steps 1 and 3 immediately, without the waiting period. AnyTLS is briefly unavailable to nodes that haven't synced yet.

**Check:** the alarm clears; an outside connection shows the new certificate; nodes still connect over AnyTLS.

---

## 8. Revoke a lost device or an account

**When:** a device is lost, stolen or decommissioned, or a person leaves. References: §22, §13.4, §8.1.

### A device

1. Revoke it. The owner can do this for their own device; an admin can do it for any.
   ```
   [admin]    webjetctl network node revoke laptop-17 --reason lost
   ```
   It takes effect on online nodes within about 10 seconds, and relays tear down its circuits.
2. If the device will be replaced and should keep its name, addresses and tags, re-key it instead of revoking it (runbook 9, with `--revoke-old-now`).

### An account

Revoking an account removes every node it owns from the network.

```
[admin]    webjetctl network account revoke bob --reason left
```

Add `--revoke-issued` to also revoke the accounts that one signed.

An **admin** account can only be revoked with the root or emergency key. It takes the admin's public file (the `.pub` from `webjetctl network account keygen`). Add `--revoke-issued` if the admin may have been compromised, which also revokes the accounts that admin signed.
```
[offline]  webjetctl root admin revoke --key carol.pub --reason compromised --revoke-issued --out carol.tomb
[admin]    webjetctl network submit carol.tomb
```

Revoking an admin, or replacing an admin's key, also voids the controller certificates that admin signed (`webjetctl network controller certify`): those controllers' tree heads stop being accepted. Before revoking, have another admin re-certify them (`webjetctl network controller certify <name>`), or right after; `webjetctl network node list` shows `control(uncertified)` for a controller without a valid certificate.

`webjetctl root account revoke --key <account>.pub` does the same for a normal account, for when no admin is available to do it.

### If no controller majority is available

Sign the tombstone with the emergency revocation key and inject it at any node. It spreads by gossip. `webjetctl root node revoke` needs the node's ID, which `webjetctl network node show` prints (`id:`).
```
[admin]    webjetctl network node show laptop-17
[offline]  webjetctl root node revoke --node <node id> --reason lost --out laptop-17.tomb
[node]     sudo webjetctl local inject laptop-17.tomb
```

**Afterwards, if the device or account may have been compromised:**
- rotate the PSK twice (runbook 6)
- check the audit trail for operations the account signed (§13.3)
- review policy rules that name the device or account by key

**Check:** `webjetctl network node list` on other nodes no longer lists the node (a revoked node leaves the tree), and it no longer appears in the metrics.

---

## 9. Re-key a reinstalled node

**When:** a machine was reinstalled, replaced, or restored from a backup, and no longer has its key. The node keeps its name, addresses, tags, routes and history. References: §8.1, §8.3.

**Steps:**

1. Issue a re-key token. The node's owner or an admin can do this.
   ```
   [admin]    webjetctl network node rekey build-01
   ```
   Add `--revoke-old-now` if the old machine was lost or stolen: the old key stops working at once, and the node is offline until step 2.
2. On the new installation, redeem it.
   ```
   [node]     curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.4.3/install.sh | sudo sh -s -- --enroll '<enrollment string>'
   ```
   On a machine that still has Webjet installed, `sudo webjetup enroll '<enrollment string>'` does the same.

**Check:**
- `webjetctl local status` on the node shows its old name and addresses.
- Policy rules that named the node by its old key no longer match it. Update them, then validate the file before applying it:
  ```
  [admin]    webjetctl network config show > network.toml   # fix the rules
  [admin]    webjetctl network config check network.toml
  [admin]    webjetctl network config apply network.toml
  ```

---

## 10. Retire a controller's signing key

**When:** a controller is decommissioned, is dead and won't return, or may have been compromised. The other controllers keep running throughout. References: §22.1, §6.6.

**Steps:**

1. Find the key ID and the highest tree-head version that key signed. The key ID was printed by `webjetctl network controller certify` (or `webjetctl root controller sign`) when the controller was set up. While the controller still runs, `webjetctl network controller list` on it shows the same value as `signing_key_id`. The current tree version is `tree_version` in `webjetctl local status`.
   For a suspected compromise, find the last version known to be legitimate by comparing with the other controllers' logs.
2. Sign the retirement with the root or emergency key (`--with emergency`), and submit it. If no controller majority is available, inject it at any node instead (`webjetctl local inject`).
   ```
   [offline]  webjetctl root controller retire --key-id <id> --last-valid-version <n> \
                  --reason decommissioned --out ctl-03.keytomb
   [admin]    webjetctl network submit ctl-03.keytomb
   ```
3. Remove the controller from the cluster, then take away its `control` role (refused while it is a member).
   ```
   [admin]    webjetctl network controller remove ctl-03
   [admin]    webjetctl network node update ctl-03 --roles data,relay
   ```
4. **For a compromise only:** revoke the node itself (runbook 8), rotate the PSK twice (runbook 6), and review the audit trail and the current tree for changes made after the last legitimate version.
5. Add a replacement controller if the cluster needs it (runbook 4).

**Check:** no equivocation alarm remains in `webjetctl local status` on several nodes, and the retired controller's tree heads are no longer accepted.

---

## 11. Roll out a release with a schema change

**When:** a release introduces new schema versions or state-machine rules, which take effect only when the root activates a new StateVersion. References: §15.6, §15.7, §19.8.

**Steps:**

1. Read the release notes: which StateVersion the release introduces, and which older versions it still reads.
2. Rehearse the whole rollout, including activation, in a test network.
3. Upgrade the controllers one at a time with `webjetup`: learners first, then voters, the leader last. After each, confirm it has rejoined and caught up.
   ```
   [node]     sudo webjetup upgrade v2.4.0         # Windows: webjetup upgrade v2.4.0 as Administrator
   ```
4. Upgrade relays, then other nodes, the same way, in stages by tag. Watch software versions (`webjet_node_info`) and alarms between stages.
5. Decide what to do about nodes that are offline. After activation, a node on the old release raises "upgrade required" and eventually drops off.
6. When every node that matters runs the new release, sign the StateVersion and submit it. Take the version number and the minimum node software version from the release notes.
   ```
   [offline]  webjetctl root state-version sign --version <n> --min-node-software 2.4.0 --out release-2.4.sv
   [admin]    webjetctl network submit release-2.4.sv
   ```
7. Watch for the "doesn't support the active StateVersion" alarm, and upgrade any node that raises it.

**Releases without a StateVersion step.** Some releases add operations or tree records without a new StateVersion; their release notes say which order they need instead. 0.4.0 (one network configuration, node configurations) is one: upgrade every controller before the first `webjetctl network config apply`, and every node before the first `webjetctl local config` change, because older software can't apply or sync them. Before upgrading a node, move any `[transport]` or `[limits]` section out of its `webjetd.toml` (0.4.0 refuses to start with them and names the replacement): for example `[transport] kcp = 0` becomes `webjetctl local config --node <name> set transport.priority.kcp 0`.

**Rollback:** binaries can be downgraded freely **until step 6** (`sudo webjetup install <older version> --force`). After activation there is no way back; fix forward.

**Check:** tree heads carry the new state version; no node reports an unsupported StateVersion.

---

## 12. A majority of voters is lost

**When:** the "no Raft leader" alarm fires and can't be cleared by waiting. References: §7.4, §6.16, §2.

### What still works, and for how long

| | Status |
|---|---|
| Traffic, routing, DNS, policy enforcement | Keep working |
| Enrollment, changes, revocation through controllers, the daily validity extension | Stopped |
| Revocation with the emergency key | Works (runbook 8) |

| Deadline | When | Effect |
|---|---|---|
| Tree heads expire | Never, while **any** controller is alive, because each re-signs hourly. If none is alive: 24–72 hours after the last signature (`head_lifetime_hours`) | Soft mode: the network keeps running on its last state |
| Validity horizon | **30 days** after the last daily extension | Nodes stop trusting the tree. The network stops |

The validity horizon is the hard deadline. Check how much time is left:
```
[node]     sudo webjetctl local status      # valid_until (Unix time in milliseconds)
```

### Steps

1. **Find out why.** If the voters are alive but unreachable, restore connectivity. Nothing else is needed.
2. **If lost voters can be brought back within days,** bring them back. Their Raft log is in their data directory, so a controller whose disk survived can be restarted, even on new hardware with the directory restored, as long as its identity key isn't sealed to the old machine (TPM, Keychain, DPAPI; see `[key] storage`).
3. **If voters are permanently lost but at least one controller (voter or learner) survives:** restarting a survivor as the only voter of a new cluster (`force-new-cluster`) is **not implemented yet**. Until it is, the remaining options are bringing voters back (step 2) or rebuilding (step 4). The intended procedure is:
   1. Stop Raft on every surviving controller.
   2. Find the survivor with the highest applied log index (`applied` in `webjetctl network controller list`).
   3. Restart it as the only voter of a new cluster that continues from its log.
   4. Re-add the other survivors as learners and promote until there are five voters (runbook 4).
   5. Retire the lost controllers' signing keys (runbook 10), so they can never return with a different history. Never start a lost voter again without wiping it.
4. **If no controller survives:** rebuild from the latest snapshot (§19.9). The architecture leaves this as a manual procedure (§2), and it loses everything committed after the snapshot. There is no snapshot export or restore tool yet. Keeping a copy of a controller's data directory (`/var/lib/webjet`, taken with the agent stopped) is the closest thing available.
   1. Restore the snapshot onto a new controller host.
   2. Create new signing keys and certify them (an admin or the root); retire all the old controller keys (runbook 10).
   3. Start the new cluster's log **above the highest tree version any node holds**, or nodes will reject its tree heads as a rollback. Read the version (`tree_version`) from `webjetctl local status` on several nodes.
   4. Redo the changes made after the snapshot. Nodes enrolled after it must be enrolled again or re-keyed.
   5. Rehearse this in a test network before you need it.

**Check:** a leader exists, tree heads are fresh, the validity horizon moves forward again, and nodes show no alarms.

---

## 13. Add an admin

**When:** another person needs to administer the network, or an existing account should become an admin. References: §13.5, §6.10.

Admins can't create admins, only the root key can, so the account record is signed on the offline computer. An admin can do everything a normal account can, and also enroll and change any node, create and revoke normal accounts, change the network configuration and camouflage secret, rotate the PSK, and certify and manage controllers.

**You need:** the offline computer, and the new admin's public key file.

**Steps:**

1. **New person only:** the person creates their account key on their own machine, where it stays, and sends you only the public file. To make an existing account an admin instead, use its existing `.pub`. Its record is replaced, and it keeps its devices.
   ```
   [person]   webjetctl network account keygen --name carol --pub-out carol.pub
   ```
2. Sign it as an admin account with the root key.
   ```
   [offline]  webjetctl root admin sign --name carol --key carol.pub --out carol.account
   ```
3. Submit it through any enrolled node. It is signed by the root, so no account key is needed to submit it.
   ```
   [admin]    webjetctl network submit carol.account
   ```

**Check:** `webjetctl network account list` shows `carol` with `ADMIN true` and `VALID true`. The new admin can then sign operations, for example `webjetctl network account create`, from their own machine (see "Running `webjetctl`"; with several keys there, `webjetctl network account use carol`).

**Notes:**
- The account ID comes from the `.pub` file, the name from `--name`. Signing an existing account's `.pub` under a new name renames that account. Signing an existing name with a different person's `.pub` is refused (`account name … is taken`). The name of a revoked account can't be used again.
- Submitting the same `.account` file twice is refused (`account version must increase`). Each `root admin sign` makes a new version.
- Only the root or emergency key can revoke an admin or replace its key (runbook 8). Revoking an admin also voids the controller certificates it signed.

---

## Testing this guide

`docker/runbook-test.sh` runs runbooks 1, 2, 3, 4, 6, 8, 9 and 13 with these commands on systemd machines (containers) installed with `webjetup`, from a local copy of the release files built from the checkout.
