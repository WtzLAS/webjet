# Webjet Operations Guide

**Status:** Draft
**Companion to:** Webjet Architecture (`webjet-architecture.md`). Section numbers such as "§7.5" refer to that document.

**About the commands.** The command-line tools are not implemented yet. Command names and flags here are **proposed syntax** that shows what each step does; adjust them when the tools exist. Each command is marked with where it runs:

| Mark | Where |
|---|---|
| `[offline]` | The offline computer that holds the root and emergency revocation keys (`webjet-root`) |
| `[admin]` | An admin's own machine, which holds their account key (`webjetctl`) |
| `[node]` | The machine being set up or repaired (`webjetd`, `webjetctl`) |
| `[controller]` | A controller, through its local control channel |

Files move to and from the offline computer on removable media only.

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

1. Create the root and emergency revocation keys, and back them up encrypted on two separate media.
   ```
   [offline]  webjet-root init
   [offline]  webjet-root backup --out /media/usb1/root-backup.enc
   ```
2. Create the first admin's account key. It never leaves the admin's machine.
   ```
   [admin]    webjetctl account keygen --name alice --pub-out alice.pub
   ```
3. Sign the admin account with the root key and build the genesis file. The genesis file holds the root public key, the emergency key's certificate, the first admin account and the overlay range.
   ```
   [offline]  webjet-root admin sign --name alice --key alice.pub --out alice.account
   [offline]  webjet-root genesis --overlay-pool 10.7.0.0/16 --admin alice.account --out genesis.wj
   ```
4. Start the first controller as a one-member cluster.
   ```
   [node]     webjetd init --genesis genesis.wj
   [node]     systemctl enable --now webjetd webjet-signer
   ```
5. Create an account to own infrastructure nodes, and enroll the controller's own node. The overlay doesn't exist yet, so operations are signed on the admin's machine and submitted through the controller's local control channel (for example over SSH).
   ```
   [admin]    webjetctl account keygen --name infra --pub-out infra.pub
   [admin]    webjetctl account create --name infra --key infra.pub
   [admin]    webjetctl node enroll --owner infra --name ctl-01 --ip 10.7.0.1 \
                  --roles data,relay --tags tag:infra
              → prints an enrollment string
   [node]     webjetd enroll <enrollment string>
   ```
6. Make the node a controller: request a certificate for its signing key, sign it offline, and submit it.
   ```
   [controller]  webjetctl controller cert-request --out ctl-01.req
   [offline]     webjet-root controller sign ctl-01.req --out ctl-01.cert
   [admin]       webjetctl submit ctl-01.cert
   ```
   From now on, nodes accept this controller's tree heads.
7. Apply the first network settings.
   ```
   [admin]    webjetctl psk rotate                      # creates the first PSK epoch
   [admin]    webjetctl transport apply transport.yaml  # priorities, camouflage mode, domain, certificate
   [admin]    webjetctl camouflage set-secret --key site.key --site ./site/
   [admin]    webjetctl dns apply dns.yaml              # suffix, resolver address
   [admin]    webjetctl seeds apply seeds.yaml          # ctl-01 for now
   [admin]    webjetctl policy apply policy.yaml        # default deny, plus the rules you need
   ```
8. Grow the cluster: add two more controllers and promote them, so there are three voters, then continue to five (runbook 3). Add relays (runbook 2), and update the seed list to at least two entries.
9. Set up the metrics store on a controller that also has `DATA`, import the alert rules and dashboards, and schedule the daily snapshot (§12.5.1, §19.7, §19.9).
10. Enroll the admin's own device, and add a policy rule that lets admin devices reach the controllers' admin interface.

**Check:**
- `webjetctl status` on a second node shows the current tree version and no alarms.
- A test node can be enrolled and reaches another node by name.

**Notes:**
- Until step 6 is done, no node trusts the tree.
- Until there are three voters, losing the one controller stops all changes.

---

## 2. Add a relay

**When:** to add capacity, cover a new region, or replace a relay. References: §4, §8, §11.8.

**You need:** a Linux host with a public IP address, synchronized time, and its transport ports open from the internet.

**Steps:**

1. Check that each port you plan to listen on is reachable from outside.
2. Enroll the node with the `RELAY` role.
   ```
   [admin]    webjetctl node enroll --owner infra --name relay-07 --ip 10.7.0.27 \
                  --roles data,relay --tags tag:relay
   ```
3. On the host, set the listen addresses in `webjetd.toml` and, if you know it, the capacity. Then enroll.
   ```
   [node]     webjetd enroll <enrollment string>
   ```
   The relay fetches the camouflage certificate key and website from a controller by itself (§9.7.2).
4. Add the relay's address to the camouflage domain's public DNS records.
5. If the relay's address is stable, add it to the seed list.
   ```
   [admin]    webjetctl seeds apply seeds.yaml
   ```

**Check:**
- `webjetctl peers` on another relay lists the new one, with measured costs.
- The relay appears in the relay dashboard, and its load stays low at first.
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

1. Create the controller's signing key and a certificate request. The key is generated inside `webjet-signer` and never leaves it.
   ```
   [node]     webjetctl controller cert-request --out ctl-06.req
   ```
2. Sign the certificate with the root key and submit it.
   ```
   [offline]  webjet-root controller sign ctl-06.req --out ctl-06.cert
   [admin]    webjetctl submit ctl-06.cert
   ```
3. Add it to the cluster as a learner. It receives a snapshot, catches up and starts signing tree heads.
   ```
   [admin]    webjetctl controller add-learner ctl-06
   ```
4. Wait until it has caught up.
   ```
   [admin]    webjetctl controller list      # its applied index matches the leader's
   ```
5. To make it a voter, promote it. Keep the number of voters odd: promote two at a time when growing from three to five, or pair a promotion with a demotion.
   ```
   [admin]    webjetctl controller promote ctl-06
   ```

**Check:** `webjetctl controller list` shows the intended voters and learners, a leader, and no alarms.

**If it goes wrong:** a learner that never catches up can be removed with `webjetctl controller remove` without affecting writes.

---

## 4. Replace a lost voter

**When:** a voter is down and won't be back soon, or the "voters below a majority plus one" alarm fires. References: §7.4, §7.5.

**Steps:**

1. Find out whether the voter is dead or only unreachable. Check `webjetctl controller list` from two other controllers. If it will be back within hours, do nothing: five voters tolerate two failures.
2. Promote a healthy, well-connected learner.
   ```
   [admin]    webjetctl controller promote ctl-09
   ```
3. Remove the lost voter from the cluster.
   ```
   [admin]    webjetctl controller remove ctl-03
   ```
4. If the machine is gone for good, or might have been compromised, retire its signing key (runbook 9). Never start it again without wiping it.
5. Add a new learner to restore the number of spares (runbook 3).

**Check:** five voters, one leader, no alarms.

---

## 5. Rotate the PSK

**When:** on a regular schedule, and after revoking a node that may have been compromised, since it knew the PSK. References: §7.6, §9.1, §10.7.3.

**Steps:**

1. Look for nodes that have been offline. They will catch up through a seed relay in bootstrap mode when they return, as long as at least two seeds are reachable.
   ```
   [admin]    webjetctl node list --not-seen 7d
   ```
2. Rotate.
   ```
   [admin]    webjetctl psk rotate
   ```
3. Wait until online nodes show the new epoch before rotating again. Nodes accept only the current and previous epoch, so two quick rotations would push connected nodes into bootstrap mode.
   ```
   [node]     webjetctl status      # shows the PSK epoch in use
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
   [admin]    webjetctl transport apply transport.yaml     # with the new certificate chain
   ```

### Replace the key

1. Generate the new key and obtain a certificate for it.
2. Announce the new key ahead of time, and wait at least as long as nodes are normally offline (for example 14 days).
   ```
   [admin]    webjetctl transport apply transport.yaml     # sets next_spki
   ```
3. Switch.
   ```
   [admin]    webjetctl camouflage set-secret --key new-site.key --site ./site/
   [admin]    webjetctl transport apply transport.yaml     # new chain as current, next_spki cleared
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

An **admin** account can only be revoked with the root or emergency key. Add `--revoke-issued` if the admin may have been compromised, which also revokes the accounts that admin signed.
```
[offline]  webjet-root account revoke --name carol --revoke-issued --out carol.tomb
[admin]    webjetctl submit carol.tomb
```

### If no controller majority is available

Sign the tombstone with the emergency revocation key and inject it at any node. It spreads by gossip.
```
[offline]  webjet-root node revoke --node laptop-17 --with emergency --out laptop-17.tomb
[node]     webjetctl inject laptop-17.tomb
```

**Afterwards, if the device or account may have been compromised:**
- rotate the PSK twice (runbook 5)
- check the audit trail for operations the account signed (§13.3)
- review policy rules that name the device or account by key

**Check:** `webjetctl node list` shows the node as revoked, and it no longer appears in the metrics.

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
   [node]     webjetd enroll <enrollment string>
   ```

**Check:**
- `webjetctl status` on the node shows its old name and addresses.
- The policy validator lists any rules that named the node by its old key. Update them.
  ```
  [admin]    webjetctl policy check
  ```

---

## 9. Retire a controller's signing key

**When:** a controller is decommissioned, is dead and won't return, or may have been compromised. The other controllers keep running throughout. References: §22.1, §6.6.

**Steps:**

1. Find the key ID and the highest tree-head version that key signed.
   ```
   [admin]    webjetctl controller list --keys
   ```
   For a suspected compromise, find the last version known to be legitimate by comparing with the other controllers' logs.
2. Sign the retirement with the root or emergency key, and submit it. If no controller majority is available, inject it at any node instead.
   ```
   [offline]  webjet-root controller retire --key-id <id> --last-valid-version <n> \
                  --reason decommissioned --out ctl-03.keytomb
   [admin]    webjetctl submit ctl-03.keytomb
   ```
3. Remove the controller from the cluster.
   ```
   [admin]    webjetctl controller remove ctl-03
   ```
4. **For a compromise only:** revoke the node itself (runbook 7), rotate the PSK twice (runbook 5), and review the audit trail and the current tree for changes made after the last legitimate version.
5. Add a replacement controller if the cluster needs it (runbook 3).

**Check:** `webjetctl status` on several nodes shows the key as retired; no equivocation alarm remains.

---

## 10. Roll out a release with a schema change

**When:** a release introduces new schema versions or state-machine rules, which take effect only when the root activates a new StateVersion. References: §15.6, §15.7, §19.8.

**Steps:**

1. Read the release notes: which StateVersion the release introduces, and which older versions it still reads.
2. Rehearse the whole rollout, including activation, in a test network.
3. Upgrade the controllers one at a time with the repository's upgrade script, run from the release's tag: learners first, then voters, the leader last. After each, confirm it has rejoined and caught up.
   ```
   [node]     ./scripts/upgrade.sh v2.4.0          # upgrade.ps1 on Windows
   ```
4. Upgrade relays, then other nodes, the same way, in stages by tag. Watch software versions and alarms in Grafana between stages.
5. Decide what to do about nodes that are offline. After activation, a node on the old release raises "upgrade required" and eventually drops off.
6. When every node that matters runs the new release, sign the StateVersion and submit it.
   ```
   [offline]  webjet-root state-version sign release-2.4.sv --out release-2.4.sv.signed
   [admin]    webjetctl submit release-2.4.sv.signed
   ```
7. Watch for the "doesn't support the active StateVersion" alarm, and upgrade any node that raises it.

**Rollback:** binaries can be downgraded freely **until step 6**. After activation there is no way back; fix forward.

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
| Tree heads expire | Never, while **any** controller is alive, because each re-signs hourly. If none is alive: 24–72 hours after the last signature | Soft mode: the network keeps running on its last state |
| Validity horizon | **30 days** after the last daily extension | Nodes stop trusting the tree. The network stops |

The validity horizon is the hard deadline. Check how much time is left:
```
[node]     webjetctl status      # shows "valid until"
```

### Steps

1. **Find out why.** If the voters are alive but unreachable, restore connectivity. Nothing else is needed.
2. **If lost voters can be brought back within days,** bring them back.
3. **If voters are permanently lost but at least one controller (voter or learner) survives:**
   1. Stop Raft on every surviving controller.
   2. Find the survivor with the highest applied log index.
   3. Restart it as the only voter of a new cluster that continues from its log.
      ```
      [controller]  webjetd controller force-new-cluster
      ```
   4. Re-add the other survivors as learners and promote until there are five voters (runbook 3).
   5. Retire the lost controllers' signing keys (runbook 9), so they can never return with a different history. Never start a lost voter again without wiping it.
4. **If no controller survives:** rebuild from the latest snapshot (§19.9). The architecture leaves this as a manual procedure (§2), and it loses everything committed after the snapshot.
   1. Restore the snapshot onto a new controller host.
   2. Create new signing keys and have the root certify them; retire all the old controller keys (runbook 9).
   3. Start the new cluster's log **above the highest tree version any node holds**, or nodes will reject its tree heads as a rollback. Read the version from `webjetctl status` on several nodes.
   4. Redo the changes made after the snapshot. Nodes enrolled after it must be enrolled again or re-keyed.
   5. Rehearse this in a test network before you need it.

**Check:** a leader exists, tree heads are fresh, the validity horizon moves forward again, and nodes show no alarms.
