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
| `webjetctl` | Sets up a node (`init`, `enroll`); talks to the local agent; signs operations with an account key; `webjetctl root` holds the offline root keys | Every node, admins' machines, the offline computer |

On every Linux or macOS machine that joins the network, as root:

```
curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.3.0/install.sh | sudo sh
```

This installs `webjetd`, `webjetctl` and `webjetup` into `/usr/local/bin` and sets up the `webjetd` service (systemd on Linux, running as the `webjet` user; launchd on macOS). On Windows, download `webjetup-<version>-x86_64-pc-windows-msvc.exe` from the release page and run `webjetup install` in an Administrator prompt. `sudo webjetup status` shows what is installed and running. Upgrades are `sudo webjetup upgrade`, and `webjetup remove` or `webjetup nuke` take Webjet off a machine again.

The offline computer gets no network. Copy the release archive for its platform (`webjet-<version>-<target>.tar.gz`, or the `.zip` on Windows) and its `.sha256` file over on removable media, check the checksum, and take `webjetctl` out of the archive. Only its `root` commands are used there.

### Running `webjetctl`

`webjetctl` talks to the Webjet agent on the machine where it runs, through the agent's control socket (`/run/webjet/control.sock`; a named pipe on Windows). Only root (Administrator on Windows) can open it, so run `webjetctl` with `sudo`. Operations are signed on that machine with your account key and sent to the controllers by the agent. Use either your own enrolled machine, or a controller's agent reached over SSH (see runbook 1, step 5).

Account keys live in `~/.config/webjet/accounts` (macOS: `~/Library/Application Support/webjet/accounts`; Windows: `%APPDATA%\webjet\accounts`). Run `webjetctl account keygen` as yourself, without `sudo`. `sudo` on Linux changes the home directory, so point `webjetctl` at your key directory when signing:

```
sudo webjetctl --keys ~/.config/webjet/accounts --account alice node list
```

The examples below leave out `sudo` and `--keys`. With a single key in the directory, `--account` can be left out as well. `webjetctl` asks for the key's passphrase. Scripts can set `WEBJET_ACCOUNT_PASSPHRASE` instead, and `webjetctl root` reads `WEBJET_ROOT_PASSPHRASE` and `WEBJET_BACKUP_PASSPHRASE`.

### Reading the output

Times in `webjetctl status` and `webjetctl controller list` (`valid_until`, `head_expires`, alarm `since`) are Unix times in milliseconds. `--json` prints any command's output as JSON.

---

## Contents

1. Bootstrap a new network
2. Add a relay
3. Add a controller and promote it to voter
4. Replace a lost voter
5. Rotate the PSK
6. Renew or replace the camouflage certificate
7. Revoke a lost device or an account
8. Re-key a reinstalled node
9. Retire a controller's signing key
10. Roll out a release with a schema change
11. A majority of voters is lost

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
   [admin]    webjetctl account keygen --name alice --pub-out alice.pub
   ```
3. Sign the admin account with the root key and build the genesis file. The genesis file holds the root public key, the emergency key's certificate, the first admin account and the overlay range.
   ```
   [offline]  webjetctl root admin sign --name alice --key alice.pub --out alice.account
   [offline]  webjetctl root genesis --overlay-pool 10.7.0.0/16 --admin alice.account --out genesis.wj
   ```
4. Start the first controller as a one-member cluster. Install Webjet without starting the agent, turn on the controller role and give the addresses others reach it on in `/etc/webjet/webjetd.toml`, initialize it with the genesis file, and start it.
   ```
   [node]     curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.3.0/install.sh | sudo sh -s -- --no-start
   [node]     sudoedit /etc/webjet/webjetd.toml
   ```
   ```toml
   [listen]
   tls = "0.0.0.0:443"
   kcp = "0.0.0.0:443"

   [controller]
   enabled = true

   [[public]]
   addr = "203.0.113.10:443"
   transport = "tls"
   [[public]]
   addr = "203.0.113.10:443"
   transport = "kcp"
   ```
   ```
   [node]     sudo webjetctl init --genesis genesis.wj
   [node]     sudo systemctl start webjetd
   [node]     sudo webjetctl controller list      # wait for a non-zero valid_until
   ```
   The controller's signing key is created on first start, as `signing.key` in `/var/lib/webjet`. To keep it out of the agent's process, run `webjetd signer --socket /run/webjet-signer/signer.sock --key /var/lib/webjet-signer/signing.key` as its own service before the first start, and set `signer_socket = "/run/webjet-signer/signer.sock"` in the `[controller]` section. The signer's socket is private to the user it runs as, so on Linux run the signer as the `webjet` user too. There is no ready-made service file for it.
5. Create an account to own infrastructure nodes, and enroll the controller's own node. The overlay doesn't exist yet, so the admin's operations go through the controller's agent. Either run them on the controller with the admin's key directory copied there for the bootstrap (remove it afterwards), or forward the controller's control socket to the admin's machine over SSH and point `webjetctl` at it:
   ```
   [admin]    ssh -N -L /tmp/ctl-01.sock:/run/webjet/control.sock root@ctl-01 &
   [admin]    export WEBJET_SOCKET=/tmp/ctl-01.sock
   ```
   Then:
   ```
   [admin]    webjetctl account keygen --name infra --pub-out infra.pub
   [admin]    webjetctl account create --name infra --key infra.pub
   [admin]    webjetctl node enroll --owner infra --name ctl-01 --ip 10.7.0.1 \
                  --roles data,relay --tags tag:infra --controller tls:203.0.113.10:443
              → prints an enrollment string
   [node]     sudo webjetctl enroll '<enrollment string>'
   ```
   The first controller enrolls its own node through its running agent, so leave the agent running here; `webjetctl enroll` talks to it. Every other node is enrolled with `webjetup enroll` (runbooks 2 and 8), which stops the agent, enrolls and starts it again. The enrollment string is valid for 24 hours (`--expires-hours`).
6. Make the node a controller: request a certificate for its signing key, sign it offline, and submit it. `webjetctl root controller sign` prints the key ID; note it for runbook 9.
   ```
   [controller]  webjetctl controller cert-request --out ctl-01.req
   [offline]     webjetctl root controller sign ctl-01.req --out ctl-01.cert
   [admin]       webjetctl submit ctl-01.cert
   ```
   From now on, nodes accept this controller's tree heads.
7. Apply the first network settings. Each `apply` validates the YAML file and submits it; `check` only validates. `show` prints the setting in force in the same YAML form, and on a new network the built-in defaults (with `version: 0`), so `webjetctl dns show > dns.yaml` is a good starting point: edit it, raise `version`, and apply.
   ```
   [admin]    webjetctl psk rotate                      # creates the first PSK epoch
   [admin]    webjetctl transport apply transport.yaml  # priorities and camouflage mode
   [admin]    webjetctl camouflage set-secret --key site.key --site ./site/   # website mode only
   [admin]    webjetctl dns apply dns.yaml              # suffix, resolver address, records
   [admin]    webjetctl seeds apply seeds.yaml          # ctl-01 for now
   [admin]    webjetctl policy apply policy.yaml        # default deny, plus the rules you need
   ```
   Every setting has a built-in default, so these are only needed to change something. Without a policy nothing is allowed (default deny), and without seeds nodes find the network through the controllers in their enrollment strings. DNS works without `dns.yaml`: the suffix is `internal` and the resolver is the top address of the overlay pool (10.7.255.254 for 10.7.0.0/16), which is never given to a node. A minimal start:
   ```yaml
   # dns.yaml
   version: 1
   suffix: internal
   resolver_ip: [10.7.255.53]   # optional; leave out to keep the default
   ```
   ```yaml
   # seeds.yaml
   version: 1
   seeds:
     - node: ctl-01
       addrs: [tls:203.0.113.10:443, kcp:203.0.113.10:443]
   ```
   ```yaml
   # policy.yaml
   version: 1
   default: deny
   rules:
     - id: everyone
       action: allow
       src: ["*"]
       dst: ["*"]
       ports: ["*"]
   ```
   ```yaml
   # transport.yaml
   version: 1             # raise it on every later apply
   defaults:              # priority 0–255 per transport; 0 = never use (§9.6)
     kcp: 30              # UDP+KCP+FEC
     anytls: 20           # TCP+AnyTLS
     tls: 10              # TCP+TLS
   overrides:             # checked in order, per transport
     - select: ["tag:relay", "role:control"]
       values:
         tls: 40          # datacenter hosts: plain TLS is fine there
   camouflage:
     mode: refuse         # or website, see below
   ```
   `defaults` and `overrides` are optional; without them every node uses the built-in priorities, which are the values in `defaults` above. For each transport, a node takes its priority from the first override that selects it and lists that transport, else from `defaults`; a `[transport]` section in the node's own `webjetd.toml` takes precedence over both. `select` takes the same selectors as policy rules (`tag:…`, `role:relay|data|control`, `node:<name>`, `owner:<account>`, `cidr:…`).

   The camouflage mode decides what a relay's AnyTLS port shows to a connection that doesn't authenticate (§9.7.2):
   - **`refuse`** closes the connection. It needs no domain, certificate or website, and `transport apply` ignores those fields in this mode. AnyTLS clients still pin a certificate, so `apply` keeps the network's current one, or on a network without one makes a self-signed certificate for a random domain and stores its key with the controllers first. Use refuse to start with; a probe can tell the port isn't an ordinary website.
   - **`website`** serves a website, which holds up to active probing. It needs a domain whose public DNS points at the relays and a CA certificate for it:
     ```yaml
     camouflage:
       mode: website
       domain: cdn.example.com
       certificate: site.crt   # PEM chain, leaf first; relative to this file
     ```
     The certificate file must exist when you apply: it is read from disk and sent with the setting. `camouflage set-secret` supplies the certificate's private key and the website relays serve. `webjetctl camouflage selfsign --domain cdn.example.com --cert-out site.crt --key-out site.key` makes a self-signed certificate for testing website mode in a lab.

   Without a `camouflage:` section the priorities still apply, and relays don't offer AnyTLS. `webjetctl transport check transport.yaml` validates the file without submitting it.
8. Grow the cluster: add two more controllers and promote them, so there are three voters, then continue to five (runbook 3). Add relays (runbook 2), and update the seed list to at least two entries.
9. Set up monitoring. Set `[metrics] listen` on the controllers (for example their overlay address and port 9469). Each controller then serves every node's latest report as OpenMetrics text at `/metrics`, so Prometheus can scrape any one of them. There's no authentication on that endpoint, so don't expose it to the internet (§12.5).
10. Enroll the admin's own device with `webjetup` and an enrollment string, and add a policy rule that lets admin devices reach the controllers. From then on, run `webjetctl` there against the device's own agent; the SSH forward from step 5 is no longer needed.

**Check:**
- `webjetctl status` on a second node shows the current tree version and no alarms.
- A test node can be enrolled and reaches another node by name (`webjetctl ping <name>`).

**Notes:**
- Until step 6 is done, no node trusts the tree.
- Until there are three voters, losing the one controller stops all changes.

---

## 2. Add a relay

**When:** to add capacity, cover a new region, or replace a relay. References: §4, §8, §11.8.

**You need:** a Linux host with a public IP address, synchronized time, and its transport ports open from the internet.

**Steps:**

1. Check that each port you plan to listen on is reachable from outside. The examples use 443 over TCP (TLS) and UDP (KCP). Without a `[listen]` section a node listens on nothing and only dials out.
2. Create an enrollment with the `RELAY` role.
   ```
   [admin]    webjetctl node enroll --owner infra --name relay-07 --ip 10.7.0.27 \
                  --roles data,relay --tags tag:relay
   ```
3. On the host, install Webjet without starting it. In `/etc/webjet/webjetd.toml`, set the addresses others reach it on, the listen addresses if they differ from the defaults, and the capacity if you know it. Then enroll.
   ```
   [node]     curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.3.0/install.sh | sudo sh -s -- --no-start
   [node]     sudoedit /etc/webjet/webjetd.toml       # [[public]], [listen], [limits] relay_capacity_mbps
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
   [configuration.md](configuration.md) has a fuller relay configuration. The `webjetd` service may bind ports below 1024 (`CAP_NET_BIND_SERVICE` in its unit). The relay fetches the camouflage certificate key and website from a controller by itself (§9.7.2).
4. Add the relay's address to the camouflage domain's public DNS records.
5. If the relay's address is stable, add it to the seed list.
   ```
   [admin]    webjetctl seeds apply seeds.yaml
   ```

**Check:**
- `webjetctl peers` on another relay lists the new one, with measured costs.
- The relay's `webjet_load_ratio` in the metrics stays low at first.
- An outside connection to its AnyTLS port, without credentials, gets the camouflage website (or is closed, in `REFUSE` mode).

**To take a relay out of service:** remove its role first, so new paths avoid it, then revoke or repurpose the node.
```
[admin]    webjetctl node update relay-07 --roles data
```

---

## 3. Add a controller and promote it to voter

**When:** building the cluster up, or adding spare learners. References: §7.1, §7.5.

**You need:** a Linux node that is already enrolled (runbook 2 without the relay-specific steps; giving controllers `RELAY` as well is recommended), and the offline computer.

**Steps:**

1. Turn on the controller role and restart the agent. This creates the controller's signing key (or uses `webjetd signer`, see runbook 1, step 4). Then create a certificate request.
   ```
   [node]     sudoedit /etc/webjet/webjetd.toml       # [controller] enabled = true
   [node]     sudo systemctl restart webjetd
   [node]     sudo webjetctl controller cert-request --out ctl-06.req
   ```
2. Sign the certificate with the root key and submit it. Note the key ID that `webjetctl root controller sign` prints.
   ```
   [offline]  webjetctl root controller sign ctl-06.req --out ctl-06.cert
   [admin]    webjetctl submit ctl-06.cert
   ```
3. Add it to the cluster as a learner. It receives a snapshot, catches up and starts signing tree heads.
   ```
   [admin]    webjetctl controller add-learner ctl-06
   ```
4. Wait until it has caught up.
   ```
   [node]     sudo webjetctl controller list      # role: Learner; applied matches the leader's
   ```
5. To make it a voter, promote it. Keep the number of voters odd: promote two at a time when growing from three to five, or pair a promotion with a demotion (`webjetctl controller demote`).
   ```
   [admin]    webjetctl controller promote ctl-06
   ```

**Check:** `webjetctl controller list` on a controller shows the intended voters and learners (by node ID) and a leader. `webjetctl status` shows no alarms.

**If it goes wrong:** a learner that never catches up can be removed with `webjetctl controller remove` without affecting writes.

---

## 4. Replace a lost voter

**When:** a voter is down and won't be back soon, or the "voters below a majority plus one" alarm fires. References: §7.4, §7.5.

**Steps:**

1. Find out whether the voter is dead or only unreachable. Check `webjetctl controller list` on two other controllers. If it will be back within hours, do nothing: five voters tolerate two failures.
2. Promote a healthy, well-connected learner.
   ```
   [admin]    webjetctl controller promote ctl-09
   ```
3. Remove the lost voter from the cluster.
   ```
   [admin]    webjetctl controller remove ctl-03
   ```
4. If the machine is gone for good, or might have been compromised, retire its signing key (runbook 9). Never start it again without wiping it (`webjetup nuke`).
5. Add a new learner to restore the number of spares (runbook 3).

**Check:** five voters, one leader, no alarms.

---

## 5. Rotate the PSK

**When:** on a regular schedule, and after revoking a node that may have been compromised, since it knew the PSK. References: §7.6, §9.1, §10.7.3.

**Steps:**

1. Look for nodes that have been offline. They will catch up through a seed relay in bootstrap mode when they return, as long as at least two seeds are reachable. A node that hasn't reported for 15 minutes is missing from the controllers' metrics: compare `webjet_node_info` in Prometheus, or `webjetctl metrics --all` on a controller, with `webjetctl node list`.
2. Rotate.
   ```
   [admin]    webjetctl psk rotate
   ```
3. Wait until online nodes show the new epoch before rotating again. Nodes accept only the current and previous epoch, so two quick rotations would push connected nodes into bootstrap mode.
   ```
   [node]     sudo webjetctl status      # psk_epoch
   ```

**After a compromise:** rotate **twice**, waiting for step 3 in between. After one rotation, the epoch the revoked node knew is still accepted as "previous".

**Check:** nodes report the new epoch, and there is no sustained rise in connections dropped at the PSK gate.

---

## 6. Renew or replace the camouflage certificate

**When:** the "camouflage certificate expires in under 14 days" alarm, or a key change. References: §9.7.2, §6.17.

### Renew with the same key

Clients pin the certificate's public key, so they need no change.

1. Obtain the renewed certificate from the CA for the same key.
2. Publish it.
   ```
   [admin]    webjetctl transport apply transport.yaml     # new chain in certificate:, version raised
   ```

### Replace the key

1. Generate the new key and obtain a certificate for it.
2. Announce the new key ahead of time, and wait at least as long as nodes are normally offline (for example 14 days).
   ```
   [admin]    webjetctl transport apply transport.yaml     # adds next_certificate: new-site.crt
   ```
3. Switch.
   ```
   [admin]    webjetctl camouflage set-secret --key new-site.key --site ./site/
   [admin]    webjetctl transport apply transport.yaml     # certificate: new-site.crt, next_certificate removed
   ```

A node that was offline through the whole announcement period can't use AnyTLS until it has synced over another transport.

**If the key was compromised:** do steps 1 and 3 immediately, without the waiting period. AnyTLS is briefly unavailable to nodes that haven't synced yet.

**Check:** the alarm clears; an outside connection shows the new certificate; nodes still connect over AnyTLS.

---

## 7. Revoke a lost device or an account

**When:** a device is lost, stolen or decommissioned, or a person leaves. References: §22, §13.4, §8.1.

### A device

1. Revoke it. The owner can do this for their own device; an admin can do it for any.
   ```
   [admin]    webjetctl node revoke laptop-17 --reason lost
   ```
   It takes effect on online nodes within about 10 seconds, and relays tear down its circuits.
2. If the device will be replaced and should keep its name, addresses and tags, re-key it instead of revoking it (runbook 8, with `--revoke-old-now`).

### An account

Revoking an account removes every node it owns from the network.

```
[admin]    webjetctl account revoke bob --reason left
```

Add `--revoke-issued` to also revoke the accounts that one signed.

An **admin** account can only be revoked with the root or emergency key. It takes the admin's public file (the `.pub` from `webjetctl account keygen`). Add `--revoke-issued` if the admin may have been compromised, which also revokes the accounts that admin signed.
```
[offline]  webjetctl root admin revoke --key carol.pub --reason compromised --revoke-issued --out carol.tomb
[admin]    webjetctl submit carol.tomb
```

`webjetctl root account revoke --key <account>.pub` does the same for a normal account, for when no admin is available to do it.

### If no controller majority is available

Sign the tombstone with the emergency revocation key and inject it at any node. It spreads by gossip. `webjetctl root node revoke` needs the node's ID, which `webjetctl node show` prints (`id:`).
```
[admin]    webjetctl node show laptop-17
[offline]  webjetctl root node revoke --node <node id> --reason lost --out laptop-17.tomb
[node]     sudo webjetctl inject laptop-17.tomb
```

**Afterwards, if the device or account may have been compromised:**
- rotate the PSK twice (runbook 5)
- check the audit trail for operations the account signed (§13.3)
- review policy rules that name the device or account by key

**Check:** `webjetctl node list` on other nodes no longer lists the node (a revoked node leaves the tree), and it no longer appears in the metrics.

---

## 8. Re-key a reinstalled node

**When:** a machine was reinstalled, replaced, or restored from a backup, and no longer has its key. The node keeps its name, addresses, tags, routes and history. References: §8.1, §8.3.

**Steps:**

1. Issue a re-key token. The node's owner or an admin can do this.
   ```
   [admin]    webjetctl node rekey build-01
   ```
   Add `--revoke-old-now` if the old machine was lost or stolen: the old key stops working at once, and the node is offline until step 2.
2. On the new installation, redeem it.
   ```
   [node]     curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.3.0/install.sh | sudo sh -s -- --enroll '<enrollment string>'
   ```
   On a machine that still has Webjet installed, `sudo webjetup enroll '<enrollment string>'` does the same.

**Check:**
- `webjetctl status` on the node shows its old name and addresses.
- Policy rules that named the node by its old key no longer match it. Update them, then validate the file before applying it:
  ```
  [admin]    webjetctl policy check policy.yaml
  [admin]    webjetctl policy apply policy.yaml
  ```

---

## 9. Retire a controller's signing key

**When:** a controller is decommissioned, is dead and won't return, or may have been compromised. The other controllers keep running throughout. References: §22.1, §6.6.

**Steps:**

1. Find the key ID and the highest tree-head version that key signed. The key ID was printed by `webjetctl root controller sign` when the controller was set up. While the controller still runs, `webjetctl controller list` on it shows the same value as `signing_key_id`. The current tree version is `tree_version` in `webjetctl status`.
   For a suspected compromise, find the last version known to be legitimate by comparing with the other controllers' logs.
2. Sign the retirement with the root or emergency key (`--with emergency`), and submit it. If no controller majority is available, inject it at any node instead (`webjetctl inject`).
   ```
   [offline]  webjetctl root controller retire --key-id <id> --last-valid-version <n> \
                  --reason decommissioned --out ctl-03.keytomb
   [admin]    webjetctl submit ctl-03.keytomb
   ```
3. Remove the controller from the cluster.
   ```
   [admin]    webjetctl controller remove ctl-03
   ```
4. **For a compromise only:** revoke the node itself (runbook 7), rotate the PSK twice (runbook 5), and review the audit trail and the current tree for changes made after the last legitimate version.
5. Add a replacement controller if the cluster needs it (runbook 3).

**Check:** no equivocation alarm remains in `webjetctl status` on several nodes, and the retired controller's tree heads are no longer accepted.

---

## 10. Roll out a release with a schema change

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
   [admin]    webjetctl submit release-2.4.sv
   ```
7. Watch for the "doesn't support the active StateVersion" alarm, and upgrade any node that raises it.

**Rollback:** binaries can be downgraded freely **until step 6** (`sudo webjetup install <older version> --force`). After activation there is no way back; fix forward.

**Check:** tree heads carry the new state version; no node reports an unsupported StateVersion.

---

## 11. A majority of voters is lost

**When:** the "no Raft leader" alarm fires and can't be cleared by waiting. References: §7.4, §6.16, §2.

### What still works, and for how long

| | Status |
|---|---|
| Traffic, routing, DNS, policy enforcement | Keep working |
| Enrollment, changes, revocation through controllers, the daily validity extension | Stopped |
| Revocation with the emergency key | Works (runbook 7) |

| Deadline | When | Effect |
|---|---|---|
| Tree heads expire | Never, while **any** controller is alive, because each re-signs hourly. If none is alive: 24–72 hours after the last signature (`head_lifetime_hours`) | Soft mode: the network keeps running on its last state |
| Validity horizon | **30 days** after the last daily extension | Nodes stop trusting the tree. The network stops |

The validity horizon is the hard deadline. Check how much time is left:
```
[node]     sudo webjetctl status      # valid_until (Unix time in milliseconds)
```

### Steps

1. **Find out why.** If the voters are alive but unreachable, restore connectivity. Nothing else is needed.
2. **If lost voters can be brought back within days,** bring them back. Their Raft log is in their data directory, so a controller whose disk survived can be restarted, even on new hardware with the directory restored, as long as its identity key isn't sealed to the old machine (TPM, Keychain, DPAPI; see `[key] storage`).
3. **If voters are permanently lost but at least one controller (voter or learner) survives:** restarting a survivor as the only voter of a new cluster (`force-new-cluster`) is **not implemented yet**. Until it is, the remaining options are bringing voters back (step 2) or rebuilding (step 4). The intended procedure is:
   1. Stop Raft on every surviving controller.
   2. Find the survivor with the highest applied log index (`applied` in `webjetctl controller list`).
   3. Restart it as the only voter of a new cluster that continues from its log.
   4. Re-add the other survivors as learners and promote until there are five voters (runbook 3).
   5. Retire the lost controllers' signing keys (runbook 9), so they can never return with a different history. Never start a lost voter again without wiping it.
4. **If no controller survives:** rebuild from the latest snapshot (§19.9). The architecture leaves this as a manual procedure (§2), and it loses everything committed after the snapshot. There is no snapshot export or restore tool yet. Keeping a copy of a controller's data directory (`/var/lib/webjet`, taken with the agent stopped) is the closest thing available.
   1. Restore the snapshot onto a new controller host.
   2. Create new signing keys and have the root certify them; retire all the old controller keys (runbook 9).
   3. Start the new cluster's log **above the highest tree version any node holds**, or nodes will reject its tree heads as a rollback. Read the version (`tree_version`) from `webjetctl status` on several nodes.
   4. Redo the changes made after the snapshot. Nodes enrolled after it must be enrolled again or re-keyed.
   5. Rehearse this in a test network before you need it.

**Check:** a leader exists, tree heads are fresh, the validity horizon moves forward again, and nodes show no alarms.

---

## Testing this guide

`docker/runbook-test.sh` runs runbooks 1, 2, 3, 5, 7 and 8 with these commands on systemd machines (containers) installed with `webjetup`, from a local copy of the release files built from the checkout.
