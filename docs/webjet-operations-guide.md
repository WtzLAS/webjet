# Webjet Operations Guide

**Status:** Draft
**Companion to:** Webjet Architecture (`webjet-architecture.md`). Section numbers such as "§7.5" refer to that document; numbers without `§`, such as "section 2.4", refer to this guide. Settings in `webjetd.toml` are described in [configuration.md](configuration.md); containers in [docker.md](docker.md).

The guide has four chapters: [Accounts](#chapter-1-accounts) (the people who use and administer the network), [Nodes](#chapter-2-nodes) (the machines in it, from the first controller on), [Maintenance](#chapter-3-maintenance) (routine changes to a running network) and [Emergency](#chapter-4-emergency) (when something important is lost or compromised). A new network starts with section 2.1.

Each command is marked with where it runs:

| Mark | Where |
|---|---|
| `[offline]` | The offline computer that holds the root and emergency revocation keys (`webjetctl root`) |
| `[admin]` | An admin's own machine, which holds their account key (`webjetctl`) |
| `[person]` | The machine of the person an account belongs to, which holds their account key |
| `[node]` | The machine being set up or repaired (`webjetup`, `webjetd`, `webjetctl`) |
| `[controller]` | A controller, through its local control channel (`webjetctl`) |

Files move to and from the offline computer on removable media only.

---

## Before you start

### Installing the programs

| Program | What it is | Where it's needed |
|---|---|---|
| `webjetup` | Installs, upgrades and removes Webjet | Every node |
| `webjetd` | The agent, run as a system service (`webjetd run`); `webjetd signer` optionally holds a controller's signing key in a separate process (section 2.1, step 4) | Every node |
| `webjetctl` | Three groups: `webjetctl network` changes the network (its configuration, nodes, accounts, controllers), signed with an account key; `webjetctl local` is about this machine and its node (`init`, `enroll`, `status`, `ping`, the node's own configuration); `webjetctl root` holds the offline root keys | Every node, admins' machines, the offline computer |

On every Linux or macOS machine that joins the network, as root:

```
curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.7.0/install.sh | sudo sh
```

This installs `webjetd`, `webjetctl` and `webjetup` into `/usr/local/bin` and sets up the `webjetd` service (systemd on Linux, running as the `webjet` user; launchd on macOS). On Windows, download `webjetup-<version>-x86_64-pc-windows-msvc.exe` from the release page and run `webjetup install` in an Administrator prompt. `sudo webjetup status` shows what is installed and running. Upgrades are described in section 3.3, and `webjetup remove` or `webjetup nuke` take Webjet off a machine again.

The offline computer gets no network. Copy the release archive for its platform (`webjet-<version>-<target>.tar.gz`, or the `.zip` on Windows) and its `.sha256` file over on removable media, check the checksum, and take `webjetctl` out of the archive. Only its `root` commands are used there.

### Running `webjetctl`

`webjetctl` talks to the Webjet agent on the machine where it runs, through the agent's control socket (`/var/run/webjet/control.sock`; a named pipe on Windows). Every local user can open it, so `webjetctl` runs as your own user; only `webjetctl local init` and `local enroll`, which write the agent's state directory, need `sudo`. Anyone on the machine can read the network through it, but every change needs a signature (your account key, or the root or emergency key). Agents up to 0.5.0 let only root (Administrator on Windows) in; with them, use `sudo`. Operations are signed on that machine with your account key and sent to the controllers by the agent. Use either your own enrolled machine, or a controller's agent reached over SSH (see section 2.1, step 5).

Account keys live in `~/.config/webjet/accounts` (macOS: `~/Library/Application Support/webjet/accounts`; Windows: `%APPDATA%\webjet\accounts`). Run `webjetctl` as yourself, so it finds them. When it does run under `sudo` (an older agent), `sudo` on Linux changes the home directory, so point `webjetctl` at your key directory when signing:

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

- `/etc/webjet/webjetd.toml` on each machine: how that machine runs the agent (listen and public addresses, interface, key storage, gateway routes, metrics). Edit it by hand and restart the agent.
- The **network configuration** in the signed tree: policy, DNS, seeds, transport priorities and camouflage, limits. It has two scopes. `webjetctl network config` changes it for the whole network (admins, section 3.5). `webjetctl local config` changes it for one node (the node's owner or an admin, section 3.6), which overrides the network's values for that node: transport priorities and limits, plus extra seeds and DNS entries. Both have the same verbs: `show`, `check <file>`, `apply <file>`, `edit`, and `get`/`set`/`unset <key>` for one value.

### Reading the output

Times in `webjetctl local status` and `webjetctl network controller list` (`valid_until`, `head_expires`, alarm `since`) are Unix times in milliseconds. `--json` prints any command's output as one JSON document, results of changes included (for example `{"node": "laptop", "node_id": "…", "entry": 41}`; enrollment strings under `enroll`). Node IDs, keys and hashes are hex strings, addresses `ip:port` or `ip/prefix`; `controller list` adds `node_names` to name the IDs in it.

Wherever a command takes a node (`network node show`, `update`, `revoke`, `rekey`, `network controller certify`/`promote`/`demote`/`remove`, `local ping`, `local config --node`), it accepts the node's name, its ID in hex (all 64 digits, or a prefix only that node has — like the 12 digits the logs print), or its key. Accounts likewise take a name, ID or key.

### Who may do what

| Who | Holds | May |
|---|---|---|
| Root key holder | The root and emergency revocation keys, offline | Create admins and give them new keys, revoke any account, certify and retire controller keys, revoke nodes, activate StateVersions |
| Admin | An admin account key | Everything a member may, plus: enroll and change any node, create, re-key and revoke member accounts, change the network configuration and camouflage secret, rotate the PSK, certify and manage controllers |
| Member | A normal account key | Rename, revoke and re-key the nodes it owns, and change their node configuration |

---

## Contents

**Chapter 1: Accounts**
- 1.1 Create a member account
- 1.2 Create an admin account
- 1.3 Revoke an account
- 1.4 Replace a lost or compromised account key

**Chapter 2: Nodes**
- 2.1 Bootstrap a new network
- 2.2 Add a data node (a device for a person)
- 2.3 Add a relay node
- 2.4 Add a control node
- 2.5 Add a gateway to a LAN
- 2.6 Revoke a lost or compromised node
- 2.7 Re-key or replace a node
- 2.8 Replace a lost voter
- 2.9 Retire a controller

**Chapter 3: Maintenance**
- 3.1 Rotate the PSK
- 3.2 Renew or replace the camouflage certificate
- 3.3 Upgrade to a new release
- 3.4 Roll out a release with a schema change
- 3.5 Change the network configuration
- 3.6 Change one node's configuration
- 3.7 Change a node's tags, roles, addresses or owner
- 3.8 Back up

**Chapter 4: Emergency**
- 4.1 A majority of voters is lost
- 4.2 Revoke without a controller majority
- 4.3 A controller is compromised
- 4.4 An admin account is compromised
- 4.5 The offline computer is lost, or its keys are exposed

---

# Chapter 1: Accounts

Every person who uses the network has an **account**: a name, an Ed25519 key that the person keeps on their own machine, and a flag saying whether the account is an admin (§13). Every node is owned by an account. A **member** (a normal account) manages the nodes it owns; an **admin** manages the whole network. Admin accounts are signed by the root key on the offline computer, member accounts by an admin.

Account names are 1–32 lowercase letters, digits and `-`, unique in the network. The name of a revoked account can't be used again. An account is identified inside the network by its **account ID**, which never changes: a new key (section 1.4) or a new name keeps it. `webjetctl --json network account list` shows each account's `id`.

A key file `<name>.key` (encrypted with a passphrase) and its public part `<name>.pub` are made together by `webjetctl network account keygen`. Only the `.pub` file is ever sent to anyone.

---

## 1.1 Create a member account

**When:** a new person needs a device on the network, or someone needs to own infrastructure nodes (such as the `infra` account of section 2.1). References: §13.1, §13.2.

**You need:** an admin account.

**Steps:**

1. The person makes the key on their own machine, where it stays, and sends you only the public file. If they will never run `webjetctl` themselves, you can make the key for them and keep it.
   ```
   [person]   webjetctl network account keygen --name bob --pub-out bob.pub
   ```
2. Create the account.
   ```
   [admin]    webjetctl network account create --name bob --key bob.pub
   ```
3. If the person will manage their own devices (rename, revoke, re-key), they run `webjetctl` on one of them with their key; see "Running `webjetctl`".

**Check:** `webjetctl network account list` shows `bob` with `ADMIN false` and `VALID true`.

**Next:** give the person a device (section 2.2). Policy rules can name all of a person's devices with `owner:bob`.

---

## 1.2 Create an admin account

**When:** another person needs to administer the network, or an existing member should become an admin. References: §13.5, §6.10.

Admins can't create admins, only the root key can, so the account record is signed on the offline computer. Have at least two admins, so the network doesn't depend on one person's key. The first admin is created while bootstrapping (section 2.1, steps 2–3).

**You need:** the offline computer, and the new admin's public key file.

**Steps:**

1. **New person only:** the person creates their account key on their own machine, where it stays, and sends you only the public file. To make an existing member an admin instead, use its existing `.pub`. Its record is replaced, and it keeps its devices.
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
- The account ID comes from the `.pub` file, the name from `--name`. Signing an existing account's `.pub` under a new name renames that account. Signing an existing name with a different person's `.pub` is refused (`account name … is taken`).
- Submitting the same `.account` file twice is refused (`account version must increase`). Each `root admin sign` makes a new version.
- Only the root or emergency key can revoke an admin (section 1.3), and only the root can give it a new key (section 1.4).

---

## 1.3 Revoke an account

**When:** a person leaves, or an account must stop working at once. If the person stays and only their key was lost or exposed, replace the key instead (section 1.4): revoking removes their devices too. References: §22, §13.4.

Revoking an account removes **every node it owns** from the network, and its name can't be used again. Move nodes that should stay to another owner first (section 3.7).

### A member account

```
[admin]    webjetctl network account revoke bob --reason left
```

Without an admin (for example, the only admin's key is lost), the root key revokes it from the account's public file or its account ID:

```
[offline]  webjetctl root account revoke --key bob.pub --reason left --out bob.tomb
[admin]    webjetctl network submit bob.tomb
```

### An admin account

Only the root or emergency key (`--with emergency`) revokes an admin. `--key` takes the admin's public file (the `.pub` from `webjetctl network account keygen`) or the account ID. Add `--revoke-issued` if the admin may have been compromised: it also revokes every member account that admin created. Leave it out when an admin simply leaves, so their colleagues' accounts keep working.

```
[offline]  webjetctl root admin revoke --key carol.pub --reason left --out carol.tomb
[admin]    webjetctl network submit carol.tomb
```

Revoking an admin also voids the controller certificates that admin signed (`webjetctl network controller certify`): those controllers' tree heads stop being accepted. Have another admin re-certify them before revoking, or right after:

```
[admin]    webjetctl network node list                         # control(uncertified) = needs a certificate
[admin]    webjetctl network controller certify ctl-01
```

**If no controller majority is available,** inject the tombstone at any node instead of submitting it (section 4.2).

**Check:** `webjetctl network account list` no longer lists the account, and `webjetctl network node list` shows its nodes with `VALID false`.

**Afterwards, if the account may have been compromised:** rotate the PSK twice (section 3.1), check the audit trail for operations the account signed (§13.3), and review policy rules that name it.

---

## 1.4 Replace a lost or compromised account key

**When:** a person lost their account key (a lost laptop, a forgotten passphrase), or it may have been copied. The account keeps its name, ID, devices and admin status; only the key changes. References: §13.6.

`webjetctl network account rekey` and `webjetctl root admin sign --replaces` are new in 0.4.4; the controllers need no upgrade for them.

From the moment the new key is committed, operations signed with the old key are refused (`SignedOp not signed by the account's current key`). Policy rules that name the account (`owner:bob`) keep matching; rules that name it by its old key (`owner:<base64 key>`) stop matching.

### A member account

1. The person makes a new key. If the old key files are still in their key directory, remove `bob.key` and `bob.pub` first (`keygen` doesn't overwrite them).
   ```
   [person]   webjetctl network account keygen --name bob --pub-out bob.pub
   ```
2. An admin gives the account the new key.
   ```
   [admin]    webjetctl network account rekey bob --key bob.pub
   ```
   `bob.pub` is rewritten with the account's ID, so the file can be used for the account later (for example in section 1.2). On the person's machine, `webjetctl` notices the new key on its first use, prints a note and updates the `.pub` in the key directory the same way.

### An admin account

The root signs a new record for the account, with the new key. `--replaces` names the account: its old `.pub` file, or its account ID.

1. The admin makes a new key, as in step 1 above, and sends `carol.pub` to the root key holder.
2. Sign and submit.
   ```
   [offline]  webjetctl root admin sign --name carol --key carol.pub --replaces carol-old.pub --out carol.account
   [admin]    webjetctl network submit carol.account
   ```
   `carol.pub` is rewritten with the account's ID. Anyone can submit the file; it is signed by the root.
3. The controller certificates the admin signed with the old key are void now. Re-certify them, with the new key or by another admin:
   ```
   [admin]    webjetctl network node list                      # control(uncertified) = needs a certificate
   [admin]    webjetctl network controller certify ctl-01
   ```
   Member accounts the admin created stay valid.

**Check:** `webjetctl network account list` shows the new key in `KEY`, and a signed command (for example `webjetctl network node rename` of one of the person's devices, back and forth) works with the new key.

**If the key may have been compromised:** whoever has it could act as the account until the new key was committed. Look through the audit trail (§13.3) for operations it signed, and check its nodes in `webjetctl network node list`: a node it re-keyed may now be someone else's machine; re-key that node again (section 2.7, with `--revoke-old-now`). For an admin, see section 4.4.

---

# Chapter 2: Nodes

A node is one machine in the network, owned by an account. Its **roles** decide what it does: `data` (it sends and receives its own traffic; the default), `relay` (it forwards circuits for other nodes and needs a public address) and `control` (it can run the controller). Its **tags** decide what the policy lets it reach. Only admins enroll nodes or change their roles, tags, addresses and owner; the owner can rename, revoke and re-key it.

---

## 2.1 Bootstrap a new network

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
4. Start the first controller as a one-member cluster. Install Webjet without starting the agent, give the addresses others reach it on in `/etc/webjet/webjetd.toml`, initialize it with the genesis file, and start it. A node initialized with the genesis file runs the controller role from the start; every later controller gets it from the `control` role (section 2.4).
   ```
   [node]     curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.7.0/install.sh | sudo sh -s -- --no-start
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
   [node]     webjetctl network controller list      # wait for a non-zero valid_until
   ```
   The controller's signing key is created on first start, as `signing.key` in `/var/lib/webjet`. To keep it out of the agent's process, run `webjetd signer --socket /var/run/webjet-signer/signer.sock --key /var/lib/webjet-signer/signing.key` as its own service before the first start, and set `signer_socket = "/var/run/webjet-signer/signer.sock"` in the `[controller]` section. The signer's socket is private to the user it runs as, so on Linux run the signer as the `webjet` user too. There is no ready-made service file for it.
5. Create an account to own infrastructure nodes (section 1.1), and enroll the controller's own node. The overlay doesn't exist yet, so the admin's operations go through the controller's agent. Either run them on the controller with the admin's key directory copied there for the bootstrap (remove it afterwards), or forward the controller's control socket to the admin's machine over SSH and point `webjetctl` at it:
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
   The first controller enrolls its own node through its running agent, so leave the agent running here; `webjetctl local enroll` talks to it. Every other node is enrolled with `webjetup enroll` (sections 2.3 and 2.7), which stops the agent, enrolls and starts it again. The enrollment string is valid for 24 hours (`--expires-hours`).
6. Certify the controller's signing key with the admin key. `certify` fetches the node's certificate request, signs it and submits the certificate; it prints the key ID, note it for section 2.9.
   ```
   [admin]    webjetctl network controller certify ctl-01
   ```
   From now on, nodes accept this controller's tree heads. `webjetctl network node list` shows `control` among its roles (`control(uncertified)` before this step). The root can sign the certificate instead, offline, which keeps it valid even if the admin is later revoked or gets a new key (an admin's certificates become void then, sections 1.3 and 1.4):
   ```
   [controller]  webjetctl network controller cert-request --out ctl-01.req
   [offline]     webjetctl root controller sign ctl-01.req --out ctl-01.cert
   [admin]       webjetctl network submit ctl-01.cert
   ```
7. Apply the first network configuration. Policy, DNS, seeds, transport priorities, camouflage and limits are one TOML document, the network configuration ([configuration.md](configuration.md#the-network-configuration), section 3.5). `show` prints the one in force as a file `apply` accepts; on a new network that's the built-in defaults with `version = 0`. Edit it and apply it: `apply` submits it as the next version and refuses a file made from an older version, so nobody overwrites someone else's change unseen. `check` validates (and runs the policy tests) without submitting.
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
   The priorities above are the built-in ones. For each transport, a node takes its priority from its own node configuration (`webjetctl local config`, section 3.6), else from the first override that selects it and lists that transport, else from `[transport.priority]`. `select` takes the same selectors as policy rules (`tag:…`, `role:relay|data|control`, `node:<name>`, `owner:<account>`).

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
8. Grow the cluster: give two more nodes the `control` role and certify them (section 2.4). The leader adds them and makes them voters by itself, so there are three voters; with five or more controllers it keeps five. Add relays (section 2.3), and update the seed list to at least two entries.
9. Set up monitoring. Set `[metrics] listen` on the controllers (for example their overlay address and port 9469). Each controller then serves every node's latest report as OpenMetrics text at `/metrics`, so Prometheus can scrape any one of them. There's no authentication on that endpoint, so don't expose it to the internet (§12.5).
10. Enroll the admin's own device with `webjetup` and an enrollment string (section 2.2), and add a policy rule that lets admin devices reach the controllers. From then on, run `webjetctl` there against the device's own agent; the SSH forward from step 5 is no longer needed.
11. Add a second admin (section 1.2), and make the backups of section 3.8.

**Check:**
- `webjetctl local status` on a second node shows the current tree version and no alarms.
- A test node can be enrolled and reaches another node by name (`webjetctl local ping <name>`).

**Notes:**
- Until step 6 is done, no node trusts the tree.
- Until there are three voters, losing the one controller stops all changes.

---

## 2.2 Add a data node (a device for a person)

**When:** someone needs a laptop, desktop or server on the network. References: §13.3, §8.

A data node is the default kind of node: it sends and receives its own traffic, and relays nothing for others. The owner can rename the device, revoke it (for example when it's lost) and re-key it after a reinstall (section 2.7) without an admin. Only an admin can enroll devices or change their tags, addresses, roles or owner, because those decide what the device may reach.

**You need:** an admin account, the person's account (create it first if they have none, section 1.1), and the person's device with Linux, macOS or Windows.

**Steps:**

1. Choose the tags the device gets. Tags are how the policy decides what it may reach (§14), and the device's owner can't change them. Check what the current rules allow those tags, and if needed add a rule and apply the policy again (section 3.5). For example, to let laptops reach the web servers on HTTPS:
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
2. Create the enrollment. The overlay address is picked from the pool unless you give `--ip`; `--roles` defaults to `data`.
   ```
   [admin]    webjetctl network node enroll --owner bob --name bob-laptop --tags tag:laptop
              → prints an enrollment string
   ```
   The string is valid for 24 hours (`--expires-hours` changes that) and can be used once. Treat it like a password until then: whoever redeems it first gets the device's place in the network. Send it to the person over a channel you trust.
3. On the device, install Webjet and enroll it in one step. On Linux and macOS:
   ```
   [node]     curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.7.0/install.sh \
                  | sudo sh -s -- --enroll '<enrollment string>'
   ```
   On Windows, download `webjetup-v0.7.0-x86_64-pc-windows-msvc.exe` from the release page and run, in an Administrator prompt:
   ```
   [node]     webjetup-v0.7.0-x86_64-pc-windows-msvc.exe install --enroll "<enrollment string>"
   ```
   On a device that already has Webjet installed, `sudo webjetup enroll '<enrollment string>'` does the same. A device doesn't need a public address or open ports: it reaches the network through relays, and connects directly to other nodes where NAT allows (§10).
4. If the person will administer their own devices from it (rename, revoke, re-key), they run `webjetctl` there with their key; see "Running `webjetctl`" above.

**Check:**
- On the device, `webjetctl local status` shows its name, its overlay address and no alarms.
- `webjetctl local ping <name>` reaches a node the policy allows, and the device resolves names under the DNS suffix (`<name>.internal` by default).
- On any node, `webjetctl network node list` lists the device with its owner.

**Later:** the owner, or an admin, renames it with `webjetctl network node rename bob-laptop bob-mbp`. Tags and owner change with section 3.7. A lost device is revoked (section 2.6), a reinstalled one re-keyed (section 2.7). When the person leaves, revoking their account removes every device they own (section 1.3).

---

## 2.3 Add a relay node

**When:** to add capacity, cover a new region, or replace a relay. References: §4, §8, §11.8.

**You need:** a Linux host with a public IP address, synchronized time, and its transport ports open from the internet.

**Steps:**

1. Check that each port you plan to listen on is reachable from outside. The examples use 443 over TCP (TLS) and UDP (KCP). Without a `[listen]` section a node listens on nothing and only dials out.
2. Create an enrollment with the `relay` role.
   ```
   [admin]    webjetctl network node enroll --owner infra --name relay-07 --ip 10.7.0.27 \
                  --roles data,relay --tags tag:relay
   ```
3. On the host, install Webjet without starting it. In `/etc/webjet/webjetd.toml`, set the addresses others reach it on and the listen addresses. Then enroll.
   ```
   [node]     curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.7.0/install.sh | sudo sh -s -- --no-start
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
4. In website camouflage mode, add the relay's address to the camouflage domain's public DNS records.
5. If the relay's address is stable, add it to the seed list: add a `[[seeds]]` entry with `webjetctl network config edit`, or
   ```
   [admin]    webjetctl network config set seeds.2 '{node = "relay-07", addrs = ["tls:203.0.113.27:443", "kcp:203.0.113.27:443"]}'
   ```
   (`seeds.2` is the next free entry; `network config get seeds` lists them.) A node that should prefer a nearby relay can have it as its own first seed: `webjetctl local config --node <node> set seeds '[{node = "relay-07", addrs = [...]}]'`.

**Check:**
- `webjetctl local peers` on another relay lists the new one, with measured costs.
- The relay's `webjet_load_ratio` in the metrics stays low at first.
- An outside connection to its AnyTLS port, without credentials, gets the camouflage website (or is closed, in `refuse` mode).

**To take a relay out of service:** remove its role first, so new paths avoid it, and its entry from the seed list; then revoke the node (section 2.6) or keep it as a data node.
```
[admin]    webjetctl network node update relay-07 --roles data
```

---

## 2.4 Add a control node

**When:** building the cluster up, or adding spare learners. References: §7.1, §7.5.

**Automatic membership** (on by default, `[controllers]` in section 3.5): once a node is a valid controller (steps 1 and 2), the leader adds it to the cluster as a learner within seconds. It makes the earliest-joined healthy controllers voters: always an odd number, at most `voters` (5 by default). With two controllers there is one voter, with three or four there are three, from five on there are five, and the rest are learners. It changes one member at a time, so growing from one voter to three takes a few seconds. Steps 3 to 5 are only needed with `auto_membership = false`.

**You need:** a Linux node that is already enrolled (section 2.3 without the relay-specific steps; giving controllers `relay` as well is recommended). A new node can be enrolled with the `control` role right away (`--roles data,relay,control`); then skip step 1. In a network upgraded from 0.3.0 or earlier, every controller must run a release with the `control` role before you grant it (older controllers would diverge on the operation), and every node before you use `certify` (older nodes accept only root-signed certificates).

**Steps:**

1. Give the node the `control` role. `--roles` is the whole role set, so repeat the roles it keeps. The agent starts the controller role by itself within a minute, without a restart, and creates its signing key (or uses `webjetd signer`, see section 2.1, step 4; configure `signer_socket` before granting the role).
   ```
   [admin]    webjetctl network node update ctl-06 --roles data,relay,control
   ```
2. Certify its signing key. Note the key ID it prints.
   ```
   [admin]    webjetctl network controller certify ctl-06
   ```
   Or have the root sign it (see section 2.1, step 6):
   ```
   [node]     webjetctl network controller cert-request --out ctl-06.req
   [offline]  webjetctl root controller sign ctl-06.req --out ctl-06.cert
   [admin]    webjetctl network submit ctl-06.cert
   ```
3. Add it to the cluster as a learner (automatic membership does this by itself). It receives a snapshot, catches up and starts signing tree heads.
   ```
   [admin]    webjetctl network controller add-learner ctl-06
   ```
4. Wait until it has caught up.
   ```
   [node]     webjetctl network controller list      # role: Learner; applied matches the leader's
   ```
5. To make it a voter, promote it (automatic membership does this by itself when a voter seat is free). Keep the number of voters odd: promote two at a time when growing from three to five, or pair a promotion with a demotion (`webjetctl network controller demote`). With automatic membership on, a manual promotion that makes the count even or exceeds `voters` is undone by the leader.
   ```
   [admin]    webjetctl network controller promote ctl-06
   ```

**Check:** `webjetctl network controller list` on a controller shows the intended voters and learners (by node ID) and a leader. `webjetctl local status` shows no alarms.

**If it goes wrong:** a learner that never catches up can be removed with `webjetctl network controller remove` without affecting writes. A controller an admin removed isn't added back automatically until `add-learner` is run for it again. If the leader doesn't add a certified controller, check the leader's log for "automatic membership": it waits until every reachable controller runs 0.7.0 or later.

---

## 2.5 Add a gateway to a LAN

**When:** machines on a LAN that can't run Webjet themselves (printers, NAS, a whole office network) should be reachable from the overlay. References: §11.9, §14.2.

A gateway is a node on that LAN that forwards overlay traffic into it. Connections are started from the overlay side only; the gateway translates their source address, so LAN hosts see the gateway as the sender. Several sites that all use the same LAN range can each be published under a different overlay-visible prefix (a **mapped** route): `192.168.1.0/24=10.2.2.0/24` publishes the LAN `192.168.1.0/24` as `10.2.2.0/24`, so `10.2.2.17` reaches `192.168.1.17`.

**You need:** a Linux machine on the LAN with `iptables` installed. It doesn't need a public address or the `relay` role.

**Steps:**

1. Grant the route. For a new node, at enrollment:
   ```
   [admin]    webjetctl network node enroll --owner infra --name gw-office --tags tag:gateway \
                  --route 192.168.1.0/24=10.2.2.0/24
   ```
   For an enrolled node, `webjetctl network node update gw-office --route 192.168.1.0/24=10.2.2.0/24` (this replaces its grants; `--no-routes` removes them all). A route without `=` is published as it is.
2. On the gateway, install and enroll it (section 2.2, step 3), then say which grant it serves and on which LAN interface, in `/etc/webjet/webjetd.toml`, and restart the agent:
   ```toml
   [[gateway.route]]
   published = "10.2.2.0/24"   # the prefix as the overlay sees it
   interface = "eth1"          # the LAN interface
   ```
   ```
   [node]     sudo systemctl restart webjetd
   ```
   The agent turns on IP forwarding and sets up the address translation itself.
3. Allow traffic to the published prefix in the policy (section 3.5). `cidr:` selectors are only allowed in `dst`:
   ```toml
   [[policy.rule]]
   id = "staff-to-office"
   action = "allow"
   src = ["tag:laptop"]
   dst = ["cidr:10.2.2.0/24"]
   ports = ["tcp:445", "icmp"]
   ```
4. For names on the LAN, forward its DNS zone to the LAN's DNS server, with the same mapping (`[[dns.forward]]` in [configuration.md](configuration.md#network-scope)).

**Check:** from an allowed device, a LAN host answers at its published address (`ping 10.2.2.17`).

**High availability:** give the identical grant to a second gateway on the same LAN. Clients pick one by cost and load and fail over when it stops serving; open connections break on failover.

---

## 2.6 Revoke a lost or compromised node

**When:** a device is lost, stolen, decommissioned or may be compromised. If it will be replaced and should keep its name, addresses and tags, re-key it instead (section 2.7, with `--revoke-old-now`). References: §22, §8.1.

**Steps:**

1. Revoke it. The owner can do this for their own device; an admin can do it for any.
   ```
   [admin]    webjetctl network node revoke laptop-17 --reason lost
   ```
   It takes effect on online nodes within about 10 seconds, and relays tear down its circuits. A revoked node is removed from the tree; its name can be enrolled again later.
2. **If no controller majority is available,** sign the revocation offline and inject it (section 4.2).
3. **If the node may have been compromised:** it knew the PSK, so rotate the PSK twice (section 3.1). If it was a relay, remove it from the seed list (section 3.5). If it was a controller, follow section 4.3 instead.

**Check:** `webjetctl network node list` on other nodes no longer lists the node, and it no longer appears in the metrics.

---

## 2.7 Re-key or replace a node

**When:** a machine was reinstalled, replaced by new hardware, or restored from a backup, and no longer has its key; or its key may have been stolen. The node keeps its name, addresses, tags, routes and history. References: §8.1, §8.3.

**Steps:**

1. Issue a re-key token. The node's owner or an admin can do this.
   ```
   [admin]    webjetctl network node rekey build-01
   ```
   Add `--revoke-old-now` if the old machine was lost or stolen, or its key may have been copied: the old key stops working at once, and the node is offline until step 2. Without it, the old key works until the token is redeemed.
2. On the new installation, redeem it.
   ```
   [node]     curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.7.0/install.sh | sudo sh -s -- --enroll '<enrollment string>'
   ```
   On a machine that still has Webjet installed, `sudo webjetup enroll '<enrollment string>'` does the same. A node in a container is re-keyed as described in [docker.md](docker.md).
3. **If the old key may have been stolen:** rotate the PSK twice (section 3.1).

**Check:**
- `webjetctl local status` on the node shows its old name and addresses.
- Policy rules that named the node by its old key no longer match it. Update them, then validate the file before applying it:
  ```
  [admin]    webjetctl network config show > network.toml   # fix the rules
  [admin]    webjetctl network config check network.toml
  [admin]    webjetctl network config apply network.toml
  ```

**A controller** is re-keyed the same way only if its signing key survived (it is a separate key, in `/var/lib/webjet` or the signer's directory). Otherwise treat it as a new controller: retire the old one (section 2.9) and add a new one (section 2.4).

---

## 2.8 Replace a lost voter

**When:** a voter is down and won't be back soon, or the "voters below a majority plus one" alarm fires. If most voters are lost, see section 4.1 instead. References: §7.4, §7.5.

With automatic membership (section 2.4), the leader does steps 2 and 3 by itself: a voter it hasn't heard from for `dead_voter_after_s` (an hour by default) is demoted, and the earliest-joined healthy learner is promoted in its place. That needs a learner that is up and caught up; with no spare learner the dead voter keeps its seat. When the voter comes back, it stays a learner. Then only steps 4 and 5 remain. Do the steps by hand to act sooner.

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
4. If the machine is gone for good, or might have been compromised, retire it (section 2.9; for a compromise, section 4.3). Never start it again without wiping it (`webjetup nuke`).
5. Add a new learner to restore the number of spares (section 2.4).

**Check:** five voters, one leader, no alarms.

---

## 2.9 Retire a controller

**When:** a controller is decommissioned, or is dead and won't return. Its signing key is retired so that it can never sign tree heads again. The other controllers keep running throughout. For a controller that may be compromised, follow section 4.3. References: §22.1, §6.6.

**Steps:**

1. Find the key ID and the highest tree-head version that key signed. The key ID was printed by `webjetctl network controller certify` (or `webjetctl root controller sign`) when the controller was set up. While the controller still runs, `webjetctl network controller list` on it shows the same value as `signing_key_id`. The current tree version is `tree_version` in `webjetctl local status`.
2. Sign the retirement with the root or emergency key (`--with emergency`), and submit it. If no controller majority is available, inject it at any node instead (`webjetctl local inject`).
   ```
   [offline]  webjetctl root controller retire --key-id <id> --last-valid-version <n> \
                  --reason decommissioned --out ctl-03.keytomb
   [admin]    webjetctl network submit ctl-03.keytomb
   ```
3. Remove the controller from the cluster, then take away its `control` role (refused while it is a member). With automatic membership the leader removes it by itself once its certificate is gone (step 2), and doesn't add a controller back that an admin removed.
   ```
   [admin]    webjetctl network controller remove ctl-03
   [admin]    webjetctl network node update ctl-03 --roles data,relay
   ```
4. If the machine is decommissioned, revoke the node too (section 2.6), and remove it from the seed list (section 3.5).
5. Add a replacement controller if the cluster needs it (section 2.4).

**Check:** no equivocation alarm remains in `webjetctl local status` on several nodes, and the retired controller's tree heads are no longer accepted.

---

# Chapter 3: Maintenance

---

## 3.1 Rotate the PSK

**When:** on a regular schedule (for example every few months), and after revoking a node or account that may have been compromised, since its nodes knew the PSK. References: §7.6, §9.1, §10.7.3.

**Steps:**

1. Look for nodes that have been offline. They will catch up through a seed relay in bootstrap mode when they return, as long as at least two seeds are reachable. A node that hasn't reported for 15 minutes is missing from the controllers' metrics: compare `webjet_node_info` in Prometheus, or `webjetctl local metrics --all` on a controller, with `webjetctl network node list`.
2. Rotate.
   ```
   [admin]    webjetctl network psk rotate
   ```
3. Wait until online nodes show the new epoch before rotating again. Nodes accept only the current and previous epoch, so two quick rotations would push connected nodes into bootstrap mode.
   ```
   [node]     webjetctl local status      # psk_epoch
   ```

**After a compromise:** rotate **twice**, waiting for step 3 in between. After one rotation, the epoch the revoked node knew is still accepted as "previous".

**Check:** nodes report the new epoch, and there is no sustained rise in connections dropped at the PSK gate.

---

## 3.2 Renew or replace the camouflage certificate

**When:** in website mode, before the certificate expires (`openssl x509 -noout -enddate -in site.crt`; Webjet raises no alarm for it yet), or for a key change. In `refuse` mode with the self-signed certificate `apply` made, nothing needs renewing for 825 days. References: §9.7.2, §6.17.

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

**Check:** an outside connection shows the new certificate (`openssl s_client -connect <relay>:443 -servername cdn.example.com`); nodes still connect over AnyTLS.

---

## 3.3 Upgrade to a new release

**When:** a new release is out. If its release notes say it introduces a new StateVersion or needs a particular order, follow section 3.4 instead. References: §19.8, §15.8.

Each release speaks the current and the previous wire protocol, so a network runs mixed versions while it is upgraded. Nothing in the network upgrades nodes; you run `webjetup` on each.

**Steps:**

1. Read the release notes. `webjetup` never updates itself: `webjetup upgrade` installs the new `webjetd` and `webjetctl` but keeps the installed `webjetup`. When the notes say the release fixes `webjetup` (for example its service files), upgrade with that release's `install.sh` instead, which installs the new `webjetup` and then upgrades the same way.
2. Upgrade the controllers one at a time: learners first, then voters, the leader last. After each, confirm it has rejoined and caught up (`webjetctl network controller list`).
   ```
   [node]     sudo webjetup upgrade v0.7.0        # Windows: webjetup upgrade v0.7.0 as Administrator
   ```
   or, to update `webjetup` too:
   ```
   [node]     curl -fsSL https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.7.0/install.sh | sudo sh
   ```
3. Upgrade relays, then the other nodes, in stages by tag. Watch software versions (`webjet_node_info`) and alarms between stages.
4. Upgrade `webjetctl` on admins' machines and on the offline computer (from the release archive, as in "Installing the programs").

**Check:** `sudo webjetup status` on each node shows the new version, and `webjetctl local status` shows no alarms.

**Rollback:** `sudo webjetup install <older version> --force` installs an older release again (not past an activated StateVersion, section 3.4).

---

## 3.4 Roll out a release with a schema change

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

**Releases without a StateVersion step.** Some releases add operations or tree records without a new StateVersion; their release notes say which order they need instead. 0.4.0 (one network configuration, node configurations) is one: upgrade every controller before the first `webjetctl network config apply`, and every node before the first `webjetctl local config` change, because older software can't apply or sync them. Compression (0.6.0) is another: upgrade every controller before the first change to `[transport.compression]`, network-wide or for a node, because controllers that don't know the setting compute different leaf bytes and halt on divergence. Nodes need no order: compressed messages go only to peers that advertise support, and control compression (on by default) needs no configuration change. Reverse proxy rules (0.6.0) are a third: upgrade every controller before the first `[[proxy]]` rule in a node's configuration, because older controllers drop the field when they re-encode it; older nodes are never chosen as proxy targets. Automatic controller membership (0.7.0) needs no order: the leader changes nothing until every reachable controller runs 0.7.0, but upgrade every controller before the first change to `[controllers]`, because older controllers can't apply that leaf. Before upgrading a node, move any `[transport]` or `[limits]` section out of its `webjetd.toml` (0.4.0 refuses to start with them and names the replacement): for example `[transport] kcp = 0` becomes `webjetctl local config --node <name> set transport.priority.kcp 0`.

**Rollback:** binaries can be downgraded freely **until step 6** (`sudo webjetup install <older version> --force`). After activation there is no way back; fix forward.

**Check:** tree heads carry the new state version; no node reports an unsupported StateVersion.

---

## 3.5 Change the network configuration

**When:** to change the policy, DNS, seeds, transport priorities, camouflage, padding, compression, limits or how the controller cluster is managed for the whole network. References: §6.7, §11.10, §9.6, §9.8, §16.2; all keys are in [configuration.md](configuration.md#network-scope).

**You need:** an admin account.

The network configuration is one TOML document with a version. Every change submits the next version as one signed operation, so nodes never see half of a change, and a change made from an older version is refused, so nobody overwrites someone else's change unseen.

**Steps:**

1. Take the configuration in force, change it, check it, apply it.
   ```
   [admin]    webjetctl network config show > network.toml
   [admin]    $EDITOR network.toml
   [admin]    webjetctl network config check network.toml      # validates, runs the policy tests
   [admin]    webjetctl network config apply network.toml
   ```
   `webjetctl network config edit` does the same in one step. A file may hold only some sections (`[policy]`, `[dns]`, `seeds`, `[transport]`, `[limits]`, `[controllers]`); a section that is present replaces the current one completely, and those left out stay as they are.
2. For a single value, `get`, `set` and `unset` take a dotted key (array entries are numbered from 0) and apply at once:
   ```
   [admin]    webjetctl network config get dns
   [admin]    webjetctl network config set transport.priority.kcp 0          # no UDP anywhere
   [admin]    webjetctl network config set dns.record '[{name = "web.internal", type = "CNAME", value = "node:web-1"}]'
   [admin]    webjetctl network config unset limits.value.circuits_global    # back to the built-in
   ```
3. If `apply` refuses the file because the version moved on, someone applied a change in between. Start again from `show`.

**Policy changes** are the ones that cut people off. Add `[[policy.test]]` entries that state what must stay allowed and what must stay denied (section 2.2, step 1); `check` and `apply` refuse a policy whose tests fail. A selector that matches nothing is allowed but warned about.

**Seeds:** keep at least two, on relays or controllers with stable addresses. Nodes returning after a PSK rotation find the network through them.

**Compression:** control messages are zstd-compressed by default. Packet compression (`set transport.compression.data lz4`) is off by default: it saves bandwidth only on compressible traffic (plain HTTP, file shares, logs) and lets an attacker who can both inject data into a connection and watch packet sizes learn secrets from that connection (architecture §9.8). Prefer turning it on for the few nodes behind expensive links (section 3.6); both ends of a session must have it on. `webjetctl local status --json` shows the bytes saved under `compression`.

**Controllers:** `[controllers]` sets how the Raft leader manages the cluster (section 2.4). `auto_membership` (default `true`) turns automatic membership on or off; `voters` (1, 3, 5 or 7; default 5) is the number of voters it aims for; `dead_voter_after_s` (default 3600; 0 = never) is how long a voter may be unreachable before a healthy learner takes its seat. `show` names the built-in values in a comment. Turn it off before managing membership by hand:
   ```
   [admin]    webjetctl network config set controllers.auto_membership false
   ```

**Check:** `webjetctl network config show` prints the new version; `webjetctl local status` on a node shows the new tree version and no alarms.

---

## 3.6 Change one node's configuration

**When:** one node should differ from the network: a relay's capacity, a transport it can't use (UDP blocked on its network), a nearby seed, or DNS entries only it answers. References: §6.19; the keys are in [configuration.md](configuration.md#node-scope).

**You need:** the node's owner account or an admin account. The change is signed and kept in the tree, so it survives reinstalls and can be made from any machine.

**Steps:**

```
[admin]    webjetctl local config --node relay-07 show --effective      # what is in force there
[admin]    webjetctl local config --node relay-07 set limits.value.relay_capacity_mbps 1000
[admin]    webjetctl local config --node laptop-17 set transport.priority.kcp 0   # never UDP from this node
[admin]    webjetctl local config --node laptop-17 unset transport.priority.kcp   # back to the network's
[admin]    webjetctl local config --node branch-gw set transport.compression.data lz4   # compress packets (section 3.5)
[admin]    webjetctl local config --node relay-07 edit                  # several values at once
```

Without `--node`, the commands apply to the node whose agent `webjetctl` talks to. Policy, the DNS suffix and resolver, transport overrides, camouflage and padding are network-wide only (section 3.5).

**Check:** `webjetctl local config --node <name> show --effective` shows the new values.

**Not here:** the node's listen and public addresses, interface, key storage, gateway routes and metrics endpoint are in its own `/etc/webjet/webjetd.toml` ([configuration.md](configuration.md#webjetdtoml)); edit that file on the machine and restart the agent (`sudo systemctl restart webjetd`).

---

## 3.7 Change a node's tags, roles, addresses or owner

**When:** a device's purpose changes (new tags), it changes hands (new owner), it should serve as a relay or controller (new roles), or it needs another overlay address or route grant. References: §13.3, §14.2.

**You need:** an admin account. Owners can't change these, because they decide what the node may reach.

**Steps:**

1. **Before changing tags,** check what the policy allows the new tags and what it allowed the old ones (section 3.5): a node loses access granted by a tag the moment the tag is removed, and gains what the new tags allow at once.
2. Make the change. Each option replaces the whole list, so repeat what the node keeps:
   ```
   [admin]    webjetctl network node update bob-laptop --tags tag:laptop,tag:dev
   [admin]    webjetctl network node update bob-laptop --owner carol
   [admin]    webjetctl network node update relay-07 --roles data            # stop relaying
   [admin]    webjetctl network node update build-01 --ip 10.7.0.40
   [admin]    webjetctl network node update gw-office --route 192.168.1.0/24=10.2.2.0/24   # or --no-routes
   ```
   Adding the `control` role is section 2.4; removing it from a controller is section 2.9 (refused while it is a cluster member). The owner, or an admin, renames a node with `webjetctl network node rename <old> <new>`; `node:<name>` rules follow the rename.

**Check:** `webjetctl network node list` shows the new roles, tags and owner, and `webjetctl network node show <name>` its addresses. Test the affected access with `webjetctl local ping` from a node the policy should (or shouldn't) allow.

---

## 3.8 Back up

**When:** after bootstrapping, and whenever what is listed here changes. References: §19.9, §5.

| What | How | Why |
|---|---|---|
| Root and emergency revocation keys | `[offline] webjetctl root backup --out /media/usb1/root-backup.enc`, on two media kept apart, with a passphrase of their own | Without them there are no new admins, no controller retirements, no StateVersions, and the network can't be repaired (section 4.5) |
| Controller state | Stop the agent on one controller, copy `/var/lib/webjet` (and the signer's directory, if any), start it again; keep the copy encrypted and away from the controllers | The closest thing to a snapshot for section 4.1, step 4 |
| Admins' account keys | Optional: the person's own encrypted copy of their key directory | A lost key can be replaced (section 1.4), but the person can't act until then |
| Node identity keys | Nothing | A reinstalled node is re-keyed (section 2.7) |

Check the backup of the root keys now and then on the offline computer: restore it into a scratch directory (`webjetctl root --dir ./restore-test restore --from /media/usb1/root-backup.enc`), compare `webjetctl root --dir ./restore-test show` with `webjetctl root show`, and delete the scratch directory.

---

# Chapter 4: Emergency

---

## 4.1 A majority of voters is lost

**When:** the "no Raft leader" alarm fires and can't be cleared by waiting. References: §7.4, §6.16, §2.

### What still works, and for how long

| | Status |
|---|---|
| Traffic, routing, DNS, policy enforcement | Keep working |
| Enrollment, changes, revocation through controllers, the daily validity extension | Stopped |
| Revocation with the emergency key | Works (section 4.2) |

| Deadline | When | Effect |
|---|---|---|
| Tree heads expire | Never, while **any** controller is alive, because each re-signs hourly. If none is alive: 24–72 hours after the last signature (`head_lifetime_hours`) | Soft mode: the network keeps running on its last state |
| Validity horizon | **30 days** after the last daily extension | Nodes stop trusting the tree. The network stops |

The validity horizon is the hard deadline. Check how much time is left:
```
[node]     webjetctl local status      # valid_until (Unix time in milliseconds)
```

### Steps

1. **Find out why.** If the voters are alive but unreachable, restore connectivity. Nothing else is needed.
2. **If lost voters can be brought back within days,** bring them back. Their Raft log is in their data directory, so a controller whose disk survived can be restarted, even on new hardware with the directory restored, as long as its identity key isn't sealed to the old machine (TPM, Keychain, DPAPI; see `[key] storage`).
3. **If voters are permanently lost but at least one controller (voter or learner) survives:** restarting a survivor as the only voter of a new cluster (`force-new-cluster`) is **not implemented yet**. Until it is, the remaining options are bringing voters back (step 2) or rebuilding (step 4). The intended procedure is:
   1. Stop Raft on every surviving controller.
   2. Find the survivor with the highest applied log index (`applied` in `webjetctl network controller list`).
   3. Restart it as the only voter of a new cluster that continues from its log.
   4. Re-add the other survivors as learners and promote until there are five voters (section 2.4; automatic membership does this by itself).
   5. Retire the lost controllers' signing keys (section 2.9), so they can never return with a different history. Never start a lost voter again without wiping it.
4. **If no controller survives:** rebuild from the latest snapshot (§19.9). The architecture leaves this as a manual procedure (§2), and it loses everything committed after the snapshot. There is no snapshot export or restore tool yet. Keeping a copy of a controller's data directory (section 3.8) is the closest thing available.
   1. Restore the snapshot onto a new controller host.
   2. Create new signing keys and certify them (an admin or the root); retire all the old controller keys (section 2.9).
   3. Start the new cluster's log **above the highest tree version any node holds**, or nodes will reject its tree heads as a rollback. Read the version (`tree_version`) from `webjetctl local status` on several nodes.
   4. Redo the changes made after the snapshot. Nodes enrolled after it must be enrolled again or re-keyed.
   5. Rehearse this in a test network before you need it.

**Check:** a leader exists, tree heads are fresh, the validity horizon moves forward again, and nodes show no alarms.

---

## 4.2 Revoke without a controller majority

**When:** a node or account must be cut off now, and the controllers can't commit (section 4.1), so `revoke` would not go through. References: §22, §6.6.

Tombstones signed by the emergency revocation key (or the root key) don't need the controllers: injected at any node, they spread by gossip and every node applies them.

**A node:** `webjetctl root node revoke` needs the node's ID, which `webjetctl network node show` prints (`id:`). The emergency key is the default (`--with root` for the root key).
```
[admin]    webjetctl network node show laptop-17
[offline]  webjetctl root node revoke --node <node id> --reason lost --out laptop-17.tomb
[node]     webjetctl local inject laptop-17.tomb
```

**An account** (member or admin), from its public file or account ID:
```
[offline]  webjetctl root account revoke --key bob.pub --with emergency --reason compromised --out bob.tomb
[node]     webjetctl local inject bob.tomb
```
For an admin, `webjetctl root admin revoke` takes the same options, plus `--revoke-issued`.

**A controller's signing key:** `webjetctl root controller retire`, injected the same way (section 4.3).

**Check:** `webjetctl network node list` on a few other nodes no longer lists the node (for an account: shows its nodes with `VALID false`).

**Afterwards,** once the controllers are back, submit the same files with `webjetctl network submit` if they aren't in the tree yet, and rotate the PSK twice (section 3.1) if anything revoked may have been compromised.

---

## 4.3 A controller is compromised

**When:** a controller's host or signing key may be in someone else's hands, or nodes raise an equivocation alarm (two tree heads with the same version and different contents). Controllers are trusted by design, so a compromised one can present nodes with a forged node list until its key is retired. References: §21.18, §22.1, §21.3.

**Steps:**

1. Find the controller's signing key ID (section 2.9, step 1) and the **last tree version known to be legitimate**, by comparing with the other controllers' logs. Everything above it signed by this key will be rejected.
2. Retire the key at once, with the root or emergency key. Submit it, or inject it at any node if the cluster can't commit:
   ```
   [offline]  webjetctl root controller retire --key-id <id> --last-valid-version <n> \
                  --reason compromised --with emergency --out ctl-03.keytomb
   [admin]    webjetctl network submit ctl-03.keytomb          # or: [node] webjetctl local inject ctl-03.keytomb
   ```
3. Remove it from the cluster and revoke the node.
   ```
   [admin]    webjetctl network controller remove ctl-03
   [admin]    webjetctl network node revoke ctl-03 --reason compromised
   ```
4. Rotate the PSK twice (section 3.1).
5. Review the audit trail and the current tree for changes committed after the last legitimate version: nodes enrolled, keys changed, roles and tags given, policy and configuration changes. Undo what you don't recognize (revoke nodes, re-key, apply a corrected configuration).
6. Wipe the machine (`webjetup nuke`, or reinstall) before it is used for anything again. Add a replacement controller (section 2.4).

**Check:** no equivocation alarm remains in `webjetctl local status` on several nodes; `webjetctl network controller list` shows the intended members and a leader.

---

## 4.4 An admin account is compromised

**When:** an admin's key, or the machine holding it with its passphrase, may be in someone else's hands. An admin can enroll nodes, change the policy, create accounts and certify controllers, so act quickly. References: §13.6, §6.5.

**Steps:**

1. **Stop the key.** Either give the account a new key (section 1.4, an admin account), if the person stays and you trust everything else on the account, or revoke it with `--revoke-issued` (section 1.3), which also revokes every member account it created; recreate the ones that are legitimate. Both void the controller certificates the account signed.
2. **Re-certify the controllers** it had certified, with another admin's key or the root (section 2.1, step 6). Until then `webjetctl network node list` shows them as `control(uncertified)` and nodes don't accept their tree heads.
3. **Review what the key did** since it may have leaked (§13.3): nodes enrolled or re-keyed, tags, roles and owners changed, accounts created, policy and configuration versions applied, camouflage secrets set. Revoke unknown nodes (section 2.6) and accounts (section 1.3), and apply a corrected configuration (section 3.5).
4. Rotate the PSK twice (section 3.1).
5. If a controller certificate was signed with the stolen key for a machine you don't control, that machine could act as a controller: retire its key and remove it (section 4.3).

**Check:** `webjetctl network account list` shows the account's new key, or no longer lists it; no node shows `control(uncertified)`; `webjetctl local status` shows no alarms.

---

## 4.5 The offline computer is lost, or its keys are exposed

**When:** the offline computer, or the medium holding a backup of the root keys, is lost, broken or stolen. References: §5.

**If the keys are only lost** (broken disk, lost computer whose passphrase is safe): restore them from the backup onto a new offline computer. `restore` asks for the backup's passphrase and a new passphrase for the restored keys.
```
[offline]  webjetctl root --dir ./webjet-root restore --from /media/usb1/root-backup.enc
[offline]  webjetctl root show                     # compare with the keys you know
```
If the lost computer could be unlocked by someone (its passphrase may be known), treat the keys as exposed.

**If the root or emergency key may be exposed:** whoever has the emergency key can revoke any node or account, and whoever has the root key can also create admins and certify controllers. Webjet has no way to replace either key: both are fixed in the genesis file. The network has to be rebuilt:

1. Bootstrap a new network with new root keys (section 2.1), in a different overlay range or after the old network is shut down.
2. Recreate the accounts (sections 1.1 and 1.2) and the network configuration (`webjetctl network config show` on the old network gives a file to start from; set `version = 0`).
3. Move every node: install it again and enroll it in the new network (sections 2.2 to 2.5), or `webjetup nuke` and reinstall.
4. Shut the old controllers down and wipe them.

Until the move is done, watch the old network for unexpected admins (`webjetctl network account list`), controllers and tombstones.

**If both the keys and every backup are lost:** the network keeps working, and admins can still create members, enroll nodes and certify controllers. What is gone is creating admins or giving them new keys, retiring controller keys, emergency revocations and StateVersions. Plan a rebuild as above before you need one of them.

---

## Testing this guide

`docker/runbook-test.sh` runs these commands on systemd machines (containers) installed with `webjetup`, from a local copy of the release files built from the checkout, or from a published release with `RELEASE=vX.Y.Z` (0.4.3 and earlier lack the commands of section 1.4). It covers sections 1.1–1.4, 2.1–2.4, 2.6, 2.7, 3.1, 3.5, 3.6 and 3.7. Not covered: gateways (2.5), replacing and retiring controllers (2.8, 2.9), the camouflage certificate (3.2), upgrades (3.3, 3.4), and chapter 4, apart from making an offline node tombstone (4.2).
