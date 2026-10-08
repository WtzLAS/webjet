# Webjet Architecture

**Status:** Draft

**Scope:** Testing, operations, congestion control, transport selection and obfuscation, scale targets and time requirements, load-aware routing, resource limits, gossip topology and peer discovery, encoding and versioning, subnet routes, overlay DNS, node roles, controller cluster (Raft), accounts and admin identity, tag-based access control, identity and keys, PSK usage, transport and end-to-end security, node-list distribution and offline operation, node liveness, revocation, multi-relay routing, NAT traversal, traffic accounting and metrics

---

## 1. Overview

### 1.1 Goals

- Nodes run a `tun-rs` virtual interface and exchange traffic over:
  - TCP + TLS
  - UDP + KCP + FEC + TLS
  - TCP + AnyTLS
- Admins enroll nodes manually through a **cluster of control servers** that replicate their state with Raft and fail over automatically. Each control server has its own permanent online signing key.
- After enrollment, nodes must keep working **without any control server**:
  - verify each other
  - probe, route and exchange traffic
  - sync the node list with each other
- Traffic may cross **multiple relays** to take the best available path.
- Nodes can act as **gateways** to LANs behind them (subnet routes), optionally publishing a LAN under a different prefix to avoid address clashes.
- Nodes are reachable **by name** (magic DNS), admins can define overlay DNS records and forward private zones, and all of it works with no controller reachable.
- Admins can see how much traffic each DATA node sends and how much each RELAY carries, **per route**.
- Every node belongs to a **person's account**. Admins are accounts too, and every admin action is signed by the admin who made it.
- Admins control **who may reach whom** with a tag-based policy of allow and deny rules, enforced by the nodes themselves even while no controller is reachable.
- A malicious or compromised peer must not be able to impersonate other nodes, spoof addresses, inject nodes, roll back state, hide revocations, read relayed traffic, or falsify traffic accounting unnoticed.

### 1.2 Layers

```
┌──────────────────────────────────────────────────────────────┐
│ tun-rs interface (overlay IP packets)                        │
├──────────────────────────────────────────────────────────────┤
│ End-to-end session (src ↔ dst, identity-authenticated)  §9.4 │
│   cryptokey routing check at the endpoint               §9.5 │
│   access-control check (policy, conntrack)               §14 │
├──────────────────────────────────────────────────────────────┤
│ Circuit layer (source-routed, label-switched relays)   §11.5 │
│   per-route accounting                                   §12 │
├──────────────────────────────────────────────────────────────┤
│ Hop session (mutual TLS, raw public keys, PQ hybrid)  §9.2-3 │
│ Pre-handshake PSK gate                                  §9.1 │
├──────────────────────────────────────────────────────────────┤
│ Transport: TCP+TLS │ UDP+KCP+FEC+TLS │ TCP+AnyTLS            │
└──────────────────────────────────────────────────────────────┘

Control plane:
  controller cluster (Raft between CONTROL nodes) §7
  signed node list + Merkle sync, gossiped between all nodes §10
  link-state adverts §11.3 · metric reports pushed to CONTROL §12.5
```

## 2. Non-Goals

- Protecting against a fully compromised **root key**.
- Containing a compromised **controller**. Controllers are **trusted by assumption**: admins and the root grant `CONTROL` only to trusted computers. Any single controller's signing key can sign network-wide state, so if a controller were compromised anyway, the network would be affected until its key is retired (§21.18, §22.1).
- Automated disaster recovery of the controller cluster. If every controller is lost, the cluster is rebuilt manually.
- iOS and Android clients. The first implementation targets Linux, macOS and Windows (§19.1); mobile is left for later. Notes about phones elsewhere in this document describe the intended behavior once they are added.
- Byzantine fault tolerance between controllers. Raft assumes controllers are honest; it tolerates crashes, not malice.
- Instant revocation while no controller is reachable (this is traded off explicitly; see §10 and §22).
- Detecting a compromised controller that rewrites history. Equivocation detection is considered sufficient, so no append-only transparency log is used (see §21.3).
- Hiding from relays **who** is talking to whom. Relays learn the source and destination of each route they carry, so they can account for it (§11.5). They never see content.

## 3. Design Principles

1. **Keys give identity; the PSK is only a gate.** A network-wide PSK is known by every node, so it must never authorize anything.
2. **Verify signatures, not sources.** State is trusted because of its signature chain, not because of where it came from (a controller, a peer, or disk cache).
3. **Private keys never leave the node that generated them.**
4. **Every trusted claim is bound and enforced.** Overlay IPs and capabilities are bound to keys by controller-signed state and checked on the data path.
5. **Each node speaks only for itself.** Endpoint addresses, link metrics, attachments and traffic reports are signed by the node they describe.
6. **Controllers agree; nodes don't depend on them.** Controllers use consensus to change state, but nodes never need a controller to send traffic.
7. **Relays forward; they never see content.** Traffic is encrypted end to end between source and destination.
8. **Every change is signed by the account that made it.** Controllers apply an operation only if it carries a valid signature from an account allowed to make it: an admin, or for a few operations on their own nodes, the node's owner. Every change is authenticated and attributable.
9. **Access is decided by the destination.** Policy is enforced where the traffic arrives, using the end-to-end authenticated source; every other check is an optimization.
10. **Liveness, routing and metrics are soft state.** They are short-lived, self-signed and kept out of the controller log and the Merkle-synced node list.

---

## 4. Node Roles & Capabilities

| Capability | Meaning | Granted by |
|---|---|---|
| `CONTROL` | Member of the controller cluster: replicates the log, signs tree heads, handles enrollment and admin operations, collects metric reports | An admin, through a signed operation (§13.3), in the NodeRecord's roles, **plus** a SigningKeyCert for the node's signing key, signed by an admin or the root key (§6.5) |
| `DATA` | Sends and receives overlay traffic through its tun interface | An admin, through a signed operation (§13.3), in the NodeRecord's roles |
| `RELAY` | Forwards traffic for other nodes and takes part in link-state routing. Requires a global public IP address | An admin, through a signed operation (§13.3), in the NodeRecord's roles |

All three are assigned the same way, as the node's role set (`webjetctl network node enroll|update --roles data,relay,control`). `CONTROL` needs one more thing, because a controller signs tree heads with its own online signing key, and nodes must be able to check that key without the tree: a **SigningKeyCert** (§6.5) binding the key to the node. A node has `CONTROL` if and only if its record holds the `control` role, it is valid (§6.1), and a valid, non-tombstoned SigningKeyCert names its `node_id` as `controller`. Records written before `control` was a role don't mention it; for them a root-signed cert alone decides, as it did then.

A node whose record holds the `control` role starts the controller role by itself, creating its signing key; it needs no local setting. Removing the role takes `CONTROL` away even while the cert stays valid, but a node can't lose the role while it is a Raft member (§7.5).

Enforcement, which works even while every controller is down:

- A node forwards traffic for others only if its own record has `RELAY`.
- A node uses a path through X only if X's record has `RELAY` and X has no tombstone.
- Nodes ignore LinkStateAdverts (§6.7) from nodes without `RELAY`.
- Metric reports are pushed only to nodes with `CONTROL`.

Admins verify a RELAY node's public reachability before granting the capability. At runtime, a relay that stops being reachable drops out of routing when its link-state adverts expire (§11.3).

### 4.1 Nodes with several capabilities

A node may hold any combination: `CONTROL+DATA`, `CONTROL+RELAY`, `DATA+RELAY`, or all three. Capabilities are independent checks, so no special trust rules are needed, but the design takes advantage of the combinations:

| Combination | How it is used |
|---|---|
| `DATA+RELAY` | The node is its own first and last relay. It publishes no AttachmentRecord, because its LinkStateAdvert already describes how to reach it, and its own traffic enters the relay mesh without an extra hop. |
| `CONTROL+RELAY` | The controller is directly part of the relay mesh, so every node reaches it in at most the usual number of hops, and Raft traffic between such controllers (§7.1) needs no extra relay. |
| `CONTROL+DATA` | The controller has an overlay IP. Its admin UI and metrics ingestion (§12.5) listen **only on the overlay IP**, so they are never exposed to the internet. The enrollment endpoint is the one exception (§8). |
| Any `RELAY` | Relays have public IPs, so they also act as **address reflectors and rendezvous points** for hole punching (§11.7). |

Rules for combined nodes:

- **Accounting:** each route is counted once per node, in the node's role **on that route** (`SOURCE`, `RELAY` or `DEST`, §12.5). A `DATA+RELAY` node's own traffic is counted as `SOURCE`/`DEST`, never also as `RELAY`.
- **Route identity:** when a `DATA+RELAY` node is the source or destination, it is not listed in `hops` (§11.5). It is `src` or `dst`.
- **Isolation:** on a node that has `CONTROL` together with `RELAY` or `DATA`, the online signing key is held by a separate process running as a separate OS user, never by the forwarding process. An internet-facing forwarding bug then can't read the key.
- **A controller's own NodeRecord** (its identity, overlay IP, `DATA`/`RELAY` roles) is created through the cluster like any other node's.

---

## 5. Key Hierarchy

```
Root Key (offline, Ed25519)
 ├── signs → SigningKeyCerts         (certify a controller's signing key; admins may too)
 ├── signs → SigningKeyTombstones    (retire a controller's signing key)
 ├── signs → Node Tombstones
 ├── signs → Admin AccountRecords    (create admins)
 ├── signs → Account Tombstones      (any account)
 ├── signs → StateVersions           (protocol and schema upgrades, §15.7)
 └── signs → Emergency Revocation Key cert

Admin Account Key (Ed25519, held by each admin person)
 ├── signs → SigningKeyCerts         (for nodes with the control role, §6.5)
 ├── signs → Normal AccountRecords   (never other admins)
 ├── signs → Account Tombstones      (normal accounts only)
 └── signs → admin operations        (enrollment, node changes, tags, policy, …)

Normal Account Key (Ed25519, held by each person)
 └── identifies the person who owns nodes (§13)

Online Signing Key — one per CONTROL node (permanent until tombstoned)
 └── signs → SignedTreeHeads over the cluster's committed state

Emergency Revocation Key (offline, same admin's computer)
 ├── signs → SigningKeyTombstones
 ├── signs → Node Tombstones
 └── signs → Account Tombstones

Node Identity Key (Ed25519, generated on each node)
 └── signs → EndpointRecords, LinkStateAdverts, AttachmentRecords,
             CircuitSetups, MetricReports, handshake channel bindings
```

| Key | Location | Purpose | Lifetime |
|---|---|---|---|
| Root | Offline, on one admin's computer | Admits and retires controllers | Permanent |
| Online signing (one per controller) | Its CONTROL node, in an isolated process (§4.1) | Signs tree heads over the committed network state | **Permanent**; ends only through a SigningKeyTombstone signed by the root or emergency revocation key |
| Emergency revocation | Offline, on the same admin's computer | Retires signing keys and revokes nodes | Permanent |
| Admin account | Each admin's own computer or hardware token | Signs admin operations and normal accounts | Until its account is tombstoned |
| Normal account | Each person's own computer or hardware token | Identifies the owner of nodes | Until its account is tombstoned |
| Node identity | Each node, encrypted at rest (§8.3) | Authenticates the node; signs its own self-describing records | Until rotated by the node or replaced by a re-key (§8.1, §8.2) |
| Network PSK | All nodes | Anti-probing / anti-DoS gate | Epoch-based (§7.6) |
| Enrollment token | Cluster → admin → one node | One-time bootstrap | Single use, short TTL |

Every node **pins the root public key**, and through it learns every valid controller.

**Custody note:** the root and emergency revocation keys are both held offline on a single admin's computer. That machine should not be used for day-to-day networking. Keep an encrypted offline backup of both keys, because losing them means you can never admit new controllers or retire compromised ones.

**Online signing key lifetime:** each controller's key has no expiry and is never rotated on a schedule. It stays valid until a SigningKeyTombstone (§6.6), signed by the root or emergency revocation key, retires it. The emergency revocation key can retire a signing key but cannot admit a new controller.

---

## 6. Data Structures

The structures below are written as pseudocode for readability. On the wire and on disk they are **FlatBuffers** messages inside a signed envelope, and every hash is **BLAKE3** (§15).

### 6.1 NodeRecord (a leaf of the network tree)

```
NodeRecord {
    node_id:      [u8; 32]      // random, fixed at enrollment; survives key changes (§8.1)
    identity_key: Ed25519 pubkey // the node's current key
    overlay_ips:  [CIDR]        // admin-assigned, e.g. 10.7.0.12/32
    roles:        {DATA, RELAY} // capability set (§4)
    control:      bool?         // the CONTROL role (§4); absent in records from before it was a role
    name:         String        // unique, admin-assigned, e.g. "build-01" (§14.2)
    owner:        account_id    // the account this node belongs to (§13)
    tags:         [String]      // admin-assigned, e.g. ["tag:server", "tag:prod"] (§14.1)
    routes:       [RouteGrant]  // admin-assigned subnet routes this node may serve (§11.9)
    version:      u64           // monotonic per node
}
```

- A NodeRecord **carries no signature of its own**. Every controller applies the same committed log, so the record must be byte-identical on every controller. A per-controller signature would make the trees differ.
- A record is authenticated by its **inclusion proof** against a valid SignedTreeHead (§6.4). Records are gossiped together with their proofs.
- `CONTROL` is a separate field rather than a member of `roles`, so software that reads only `roles` keeps working; tools show all three as one role set. Having the role isn't enough on its own: a SigningKeyCert is needed too (§4).
- These fields change only through committed operations (§7.2), signed by an admin or, for renaming and tombstoning, by the node's owner (§13.3).
- If the `owner` account is tombstoned, the node is treated as revoked (§13.4).
- A record has **no expiry of its own**. Every record in the tree is valid until the tree's validity horizon (§6.16), unless tombstoned.

### 6.2 EndpointRecord (signed by the node itself)

```
EndpointRecord {
    node_id:    [u8; 32]
    addrs: [{
        addr:      SocketAddr
        transport: TCP_TLS | KCP_FEC_TLS | ANYTLS
        kind:      PUBLIC | HOST | REFLEXIVE
        priority:  u8        // this node's priority for the transport; 0 = never use (§9.6)
    }]
    nat:        NONE | CONSISTENT | SYMMETRIC   // §11.7
    software:   String       // node software version
    features:   [String]     // optional protocol features it supports (§15.8)
    serving:    [Cidr]       // published prefixes it is serving right now; ⊆ its grants (§11.9)
    gateway_load: u8?        // gateways only: load in %, as for relays (§11.8.5)
    seq:        u64          // issued_at in milliseconds; monotonic across reboots
    issued_at:  Timestamp
    expires_at: Timestamp    // e.g. issued_at + 10 min; re-published before expiry
}
```

- `PUBLIC`: a directly reachable address (always the case for RELAY nodes).
- `HOST`: a local interface address, useful when two nodes share a LAN.
- `REFLEXIVE`: the node's address as seen from outside its NAT, learned from relays (§11.7).

Endpoints change often, so the node publishes them itself. Peers can then learn new addresses even while no controller is reachable. The expiry keeps stale addresses from circulating after a node goes offline (§10.5). Using the timestamp as `seq` keeps it increasing after a reboot, without persisting a counter.

### 6.3 Node Tombstone (node revocation)

```
Tombstone {
    node_id:    [u8; 32]
    version:    u64      // must be > last NodeRecord version
    reason:     String
}
```

- Created by a committed operation (§7.2), in which case it is an unsigned leaf of the network tree like a NodeRecord, **or** signed by the root or emergency revocation key, in which case it is a standalone record: gossiped with priority, exempt from rate limits, and persisted.
- A tombstone overrides **any** NodeRecord with a lower version for the same `node_id`.

### 6.4 SignedTreeHead

```
SignedTreeHead {
    signing_key_id: [u8; 32]     // the controller key that signed it
    version:        u64          // Raft log index of the last applied operation
    root:           [u8; 32]     // sparse Merkle tree root (BLAKE3, §15.4)
    state_version:  u32          // the StateVersion in effect at `version` (§15.7)
    issued_at:      Timestamp
    expires_at:     Timestamp    // hours to days
}
```

- The tree's key space holds several kinds of leaf, keyed by `(kind, id)`: nodes (`node_id` → NodeRecord or Tombstone), accounts (`account_id` → AccountRecord or AccountTombstone, §6.10–6.11), one policy leaf (§6.12), one DNS configuration leaf (§6.13), one seed-list leaf (§6.14), one limits leaf (§6.15), one validity leaf (§6.16), one transport configuration leaf (§6.17) and, per node that has one, a node configuration leaf (`node_id` → NodeConfig, §6.19). Empty keys prove absence.
- **Any** controller signs heads for the state it has applied (§7.3). Because the state is deterministic, heads from different honest controllers for the same `version` always have the same `root`.
- Two heads with the same `version` and the same `root` but different `expires_at` are **not** equivocation. They are re-signings of the same state.

### 6.5 SigningKeyCert (signed by the root key or an admin account key)

```
SigningKeyCert {
    signing_key_id: [u8; 32]      // BLAKE3-derived from signing_key (§15.4)
    signing_key:    Ed25519 pubkey
    controller:     node_id       // the CONTROL node that holds this key
    cert_serial:    u64           // from the request; informational
    issuer:         Signed(AccountRecord)?  // the signing admin's root-signed record; absent when the root signs
}
```

- No expiry field: the key is permanent until tombstoned.
- Nodes receive all certs during enrollment and through priority gossip.
- **Who signs:** the root, offline (`webjetctl root controller sign`), or any admin (`webjetctl network controller certify`). An admin's cert carries the admin's own root-signed AccountRecord, so a node verifies it with the root key alone, without the tree, which it needs before it can trust any tree head.
- **An admin's cert is valid while** the admin's account isn't tombstoned and its current key is the one that signed. Certs aren't ordered by the log, so a cert signed with a stolen key after a revocation or key change couldn't be told apart from one signed before: **revoking an admin, or replacing an admin's key, voids every cert it signed.** The root or another admin re-signs the controllers concerned.
- A root-signed cert replaces any admins' certs for the same key; one key is certified for one node only.
- **Upgrading:** software from before `control` was a role rejects admin-signed certs (and heads from keys certified only that way), and its state machine doesn't know the `control` field. Upgrade every controller before the first operation that sets `control`, and every node before the first admin-signed cert; until then keep using root-signed certs.
- A cert lets a node with the `control` role act as a controller (§4). Joining the Raft cluster itself is a separate membership change (§7.5).

### 6.6 SigningKeyTombstone (signed by root or emergency revocation key)

```
SigningKeyTombstone {
    signing_key_id:     [u8; 32]
    last_valid_version: u64      // highest tree-head version from this key still trusted
    reason:             String
}
```

- Once accepted, the signing key is permanently retired. The tombstone cannot be undone, and a retired key is never reinstated. The node named in its cert loses `CONTROL` unless it holds another valid cert.
- Heads signed by that key with `version <= last_valid_version` stay trusted. Anything it signed above that version is rejected. When the key is retired because of compromise, the admin sets `last_valid_version` to the last version known to be legitimate.
- The other controllers are unaffected and keep signing.
- SigningKeyTombstones are gossiped with priority and are exempt from the tree-head rate limit (§10.3.1), because they are rare and signed by offline keys.

### 6.7 LinkStateAdvert (signed by the originating RELAY)

```
LinkStateAdvert {
    origin:     node_id           // must have RELAY
    seq:        u64               // monotonic; newer replaces older
    links: [{
        peer:      node_id
        transport: TCP_TLS | KCP_FEC_TLS | ANYTLS   // currently selected toward this peer (§9.6)
        rtt_ms:    u16            // smoothed, quantized
        loss_pct:  u8
        util_pct:  u8             // link utilization vs. capacity (§11.8)
    }]
    load: {                       // §11.8.1
        util_pct:      u8         // max of uplink/downlink utilization vs. capacity
        cpu_pct:       u8         // forwarding CPU
        circuits_pct:  u8         // circuits in use vs. the circuit cap (§16.2)
        capacity_mbps: u32        // configured, or auto-estimated
    }
    expires_at: Timestamp         // 5 min; refreshed every minute (§11.3)
}
```

### 6.8 AttachmentRecord (signed by the DATA node)

```
AttachmentRecord {
    node_id:  node_id
    seq:      u64
    relays: [{
        relay:     node_id
        transport: TCP_TLS | KCP_FEC_TLS | ANYTLS   // currently selected toward this relay (§9.6)
        rtt_ms:    u16
        loss_pct:  u8
    }]
    expires_at: Timestamp
}
```

Tells the network which relays a DATA node can be reached through. These are also the node's **home relays** for gossip (§10.6): 2 by default, at most 3, chosen automatically as the lowest-cost links. Nodes that also hold `RELAY` don't publish one (§4.1).

### 6.9 E2EFrame (end-to-end session frame)

```
E2EFrame {
    type:     u8     // DATA | HANDSHAKE | PROBE | PROBE_ACK |
                     // PUNCH_OFFER | PUNCH_GO | CLOSE | RPC | PROXY |
                     // DATA_LZ4 | PROXY_LZ4 | RPC_ZSTD |
                     // MCAST | GROUPS
    key_id:   u32    // receiver's key id (absent in HANDSHAKE)
    counter:  u64    // per-key, strictly increasing, never reused
    body:     AEAD(key, nonce = 0u32 || counter,
                   aad = type || key_id || counter,
                   plaintext)
}
```

`HANDSHAKE` frames carry raw TLS handshake bytes and are not AEAD-protected (TLS protects them). All other types are encrypted. Overhead is 13 bytes of header plus a 16-byte tag. See §9.4 for how each type is used; the `_LZ4` and `_ZSTD` types carry their payload compressed (§9.8).

### 6.10 AccountRecord (signed by the root or an admin)

```
AccountRecord {
    account_id:  [u8; 32]       // random, fixed at creation; survives key rotation
    account_key: Ed25519 pubkey
    name:        String         // unique, [a-z0-9-]{1,32}, e.g. "alice"
    admin:       bool
    issuer:      ROOT | account_id   // who signed this record
    version:     u64            // monotonic per account
}
signed by: the root key (required if admin = true),
           or the account_key of a valid admin (only if admin = false)
```

- Stored as a leaf of the network tree through `PutAccount` (§7.2). Unlike NodeRecords, an AccountRecord **keeps its own signature**: the signature is part of the leaf bytes, which are identical on every controller. Nodes verify both the inclusion proof and the signature.
- An admin can sign **normal** accounts only. An admin account must be signed by the root, so no admin can create or promote another admin.
- Changing a record (renaming, a new key) means a new signed record with a higher `version`, from a signer allowed to sign it.

### 6.11 AccountTombstone

```
AccountTombstone {
    account_id:     [u8; 32]
    version:        u64        // must be > last AccountRecord version
    revoke_issued:  bool       // for an admin: also revoke the accounts it signed
    reason:         String
}
signed by: the root or emergency revocation key (any account),
           or a valid admin's account_key (normal accounts only)
```

- Committed into the tree through `TombstoneAccount` (§7.2). A tombstone signed by the root or emergency revocation key is also valid standalone, gossiped with priority like offline-signed node tombstones.
- Effects are in §13.4.

### 6.12 Policy (a single leaf of the network tree)

```
Policy {
    version:  u64
    default:  ALLOW | DENY           // DENY recommended
    rules:    [Rule]
    tests:    [PolicyTest]
}

Rule {
    id:       String
    action:   ALLOW | DENY
    src:      [Selector]
    dst:      [Selector]
    ports:    [PortSpec]            // "tcp:22", "tcp:8000-8100", "udp:53", "icmp", "*"
}
```

Part of the network configuration (§6.18), set by `SetNetworkConfig` (§7.2). Selectors and evaluation are in §14.

### 6.13 DnsConfig (a single leaf of the network tree)

```
DnsConfig {
    version:      u64
    suffix:       String            // magic DNS domain; default "internal"
    resolver_ip:  [IpAddr]          // reserved overlay address(es) of the local resolver
    records:      [DnsRecord]       // admin-defined overlay records
    forward:      [ForwardZone]     // split DNS for private zones
}

DnsRecord {
    name:   String                  // fully qualified, e.g. "db.prod.internal" (with the default suffix)
    type:   A | AAAA | CNAME | TXT | SRV
    value:  String | IpAddr | NodeRef   // NodeRef = a node, by name or key (§11.10.3)
    ttl:    u32
}

ForwardZone {
    zone:     String                // e.g. "corp.example.com", or a reverse zone
    servers:  [IpAddr]              // overlay or published subnet addresses
    rewrite:  [RouteGrant]?         // translate answers for mapped subnet routes (§11.10.5)
}
```

Part of the network configuration (§6.18). Behavior is in §11.10.

### 6.14 Seeds (a single leaf of the network tree)

```
Seeds {
    version: u64
    entries: [{
        node:  NodeRef                  // a RELAY or CONTROL node, by name or key (§14.2)
        addrs: [{
            host:      String           // public DNS hostname or IP literal
            port:      u16
            transport: TCP_TLS | KCP_FEC_TLS | ANYTLS
        }]
    }]
}
```

Stable entry points for nodes that have lost track of the network. Part of the network configuration (§6.18). Behavior is in §10.7.

### 6.15 Limits (a single leaf of the network tree)

```
Limits {
    version:    u64
    defaults:   { limit_name → value }        // override built-in defaults network-wide
    overrides:  [{
        select:  [Selector]                   // as in the policy (§14.2)
        values:  { limit_name → value }
    }]
}
```

Part of the network configuration (§6.18). The limits and their defaults are in §16.

### 6.16 Validity (a single leaf of the network tree)

```
Validity {
    valid_until: Timestamp      // every non-tombstoned record in the tree is valid until then
}
```

- Extended once a day by the system operation `ExtendValidity` (§7.2), to 30 days ahead.
- It replaces a per-record expiry. Refreshing every node's record each day would rewrite every leaf of the tree daily; this changes one leaf.
- After `valid_until` passes without a newer tree, nodes stop trusting the tree's records. That happens only if no controller has been able to commit for 30 days (§7.4).

### 6.17 TransportConfig (a single leaf of the network tree)

```
TransportConfig {
    version: u64
    priorities: {                              // §9.6
        defaults:   { transport → u8 }
        overrides:  [{ select: [Selector], values: { transport → u8 } }]
    }
    camouflage: {                              // §9.7.2
        mode:         WEBSITE | REFUSE
        domain:       String                   // the SNI every node uses for AnyTLS
        certificate:  [bytes]                  // the network's one certificate chain (public part)
        next_spki:    [u8; 32]?                // announced ahead of a key change
    }
    padding: PaddingScheme                     // §9.7.4
    compression: {                             // §9.8
        control:  UNSET | OFF | ZSTD           // built-in ZSTD
        data:     UNSET | OFF | LZ4            // built-in OFF
    }
}
```

Part of the network configuration (§6.18). The certificate's private key and the camouflage website are **not** in the tree; they are held in controller state and given only to nodes that accept AnyTLS connections (§9.7.2).

### 6.18 NetworkConfig (the network scope of the configuration)

```
NetworkConfig {
    version:   u64
    policy:    Policy            // §6.12
    dns:       DnsConfig         // §6.13
    seeds:     Seeds             // §6.14
    limits:    Limits            // §6.15
    transport: TransportConfig   // §6.17
    controllers: ControllerSettings?  // §7.5: { auto_membership, voters, dead_voter_after_s }
}
```

The network's settings are one document with one version. `SetNetworkConfig` (§7.2) checks every part as before and writes the five leaves in **one log entry**, each carrying the document's version, so a node never sees half of a change, and one signed operation records who changed what. A part left out of the operation is written empty, which means its built-in defaults; admin tools send the whole document (the parts a file leaves out are taken from the tree first). The configuration's version is the highest version of the five leaves. `controllers` (from 0.7.0) is different: it is written as a sixth leaf (kind CONTROLLERS) only when the operation has it, and an operation without it leaves that leaf as it is, so a document from an older tool, or one that leaves the section out, computes the same leaves on controllers from before 0.7.0.

- **Optimistic concurrency:** `version` must be above the one in force. `webjetctl network config apply` submits the file's version plus one and refuses a file made from an older version, so two admins can't overwrite each other's change unseen.
- Admins edit it as TOML (`network.toml`; schema in [configuration.md](configuration.md)). The wire form stays FlatBuffers; TOML exists only in the tools.
- The per-setting operations `SetPolicy`, `SetDns`, `SetSeeds`, `SetLimits` and `SetTransport` from before 0.4.0 are still applied when they are already in the log (so old logs replay identically), but a leader refuses to propose new ones.

### 6.19 NodeConfig (the node scope of the configuration)

```
NodeConfig {
    node_id:     NodeId
    version:     u64
    priorities:  { transport → u8 }   // replace the network's (§9.6)
    limits:      { limit_name → value }   // replace the network's (§16.4)
    seeds:       [SeedEntry]          // tried before the network's (§10.7)
    dns_records: [DnsRecord]          // answered by this node's resolver only
    dns_forward: [ForwardZone]        // forwarded by this node's resolver only
    proxy:       [ProxyRule]          // reverse proxy ports (§11.11)
    compression: { control, data }    // replace the network's, per plane (§9.8)
}
```

One node's overrides of, and additions to, the network configuration: a leaf of kind NODE_CONFIG keyed by `node_id`, absent when the node has none.

- **Who:** `SetNodeConfig` (§7.2) may be signed by the node's **owner** or by an admin (§13.3). Everything in it only affects how that node behaves or what it resolves for itself, which is why owners may set it; anything that decides access (policy, tags, routes, roles) stays admin-only.
- **Precedence:** a node's value, then the network's matching overrides (§9.6, §16.4), then the network's value, then the built-in default. Seeds, records and zones are added in front of the network's.
- **Validation** is the network's: limit names known and positive, seeds name valid RELAY or CONTROL nodes, records within the network's suffix or a forwarded zone and not shadowing magic DNS names.
- **Version** must increase, as for the network configuration. A NodeConfig with nothing in it removes the leaf; tombstoning the node removes it too.
- **Other nodes:** priorities matter to peers, and a node publishes its effective priorities in its EndpointRecord (§6.2), so peers use what the node uses even before their tree has its NodeConfig. Limits, seeds and DNS affect only the node itself.
- Before 0.4.0 these lived in each machine's `webjetd.toml` (`[transport]`, `[limits]`). Keeping them in the tree makes them signed, auditable, settable remotely, and lets them survive a reinstall.

**Upgrading to 0.4.0:** there is no StateVersion gate for the two new operations or the new leaf kind. Controllers from before 0.4.0 can't apply `SetNetworkConfig` or `SetNodeConfig`, so a leader that commits one makes old followers halt on divergence; upgrade every controller before the first apply. Nodes from before 0.4.0 can't decode a NODE_CONFIG leaf and so fail to sync any tree that has one; upgrade every node before the first node configuration is set. (0.4.0 nodes keep leaves of kinds they don't know without interpreting them, so later leaf kinds don't have this problem.)

---

## 7. Controller Cluster

### 7.1 Cluster and consensus

- The `CONTROL` nodes form one **Raft** cluster. The deployment has 8–16 controllers (§18.1), which is more than Raft should have as voting members, so controllers are either **voters** or **learners**:
  - **Voters: 5 by default** (always an odd number, at most 7). A write needs a majority of voters: 5 tolerate 2 failures, 7 tolerate 3. The leader picks them by itself (automatic membership, §7.5).
  - **Learners:** every other controller. A learner replicates the log, applies it, signs tree heads, accepts operations, enrollments and metric reports, and forwards writes to the leader. It doesn't vote, so it never slows down or blocks a commit.
  - More voters would not help: each write would need more acknowledgements across wide-area links, and an even number tolerates no more failures than the odd number below it.
- **Raft traffic runs over the overlay itself**, inside end-to-end sessions (§9.4) between controllers. It gets the same authentication and encryption as any traffic, and controllers don't need public IPs to reach each other, although `CONTROL+RELAY` makes it shorter (§4.1). This works because the overlay never depends on controllers.
- A controller accepts Raft messages only from peers that hold a valid SigningKeyCert and are current members.
- **Election timeouts are a few seconds**, because controllers may be far apart and ordinary wide-area latency spikes must not trigger elections.
- **Log compaction:** the state machine (the network tree plus pending enrollments, §7.2) is snapshotted periodically, and older log entries are discarded.
- Any controller accepts admin actions and enrollment requests, and forwards them to the current leader.

### 7.2 State machine and operations

Every controller applies committed operations to the same deterministic state machine: the **network tree** (nodes, accounts and the policy, §6.4), plus a table of pending enrollments.

**Account-initiated.** Every one of these is wrapped in a `SignedOp` (§13.3) and is applied only if its signer is allowed to make it. Admins may submit all of them; a normal account may submit only those marked ✓, and only for nodes it owns (§13.3):

| Operation | Effect | Owner |
|---|---|---|
| `CreateEnrollment { owner, name, overlay_ips, roles, control, tags, token_hash, expires_at }` | Adds a pending enrollment for a node owned by the account `owner`. The node's key isn't known yet | |
| `RenameNode { node_id, name }` | Changes a node's name and increments its `version` | ✓ |
| `UpdateNode { node_id, owner?, overlay_ips?, roles?, control?, tags?, routes? }` | Changes a NodeRecord's other fields and increments its `version`. Removing `control` is refused while the node is a Raft member | |
| `TombstoneNode { node_id, reason }` | Adds a Tombstone leaf | ✓ |
| `RekeyNode { node_id, token_hash, expires_at, revoke_old_now }` | Adds a pending re-key for an existing node (§8.1) | ✓ |
| `PutAccount { record }` | Stores a signed AccountRecord (§6.10) | |
| `TombstoneAccount { tombstone }` | Stores a signed AccountTombstone (§6.11) | |
| `SetNetworkConfig { config }` | Replaces the policy, DNS, seed-list, limits and transport leaves together, all at the document's version, and the controller settings when present (§6.18). Validated as in §14.5, §11.10.6, §10.7.2, §16.4, §7.5 | |
| `SetNodeConfig { config }` | Sets or removes one node's configuration leaf (§6.19) | ✓ |
| `SetCamouflageSecret { private_key, site }` | Stores the camouflage certificate's private key and the website. Kept in controller state, encrypted at rest; never in the tree (§9.7.2) | |
| `ChangeMembership { add learner / promote / demote / remove }` | Raft membership change (§7.5) | |
| `RotatePsk { epoch_id }` | Starts a new network PSK epoch (§7.6) | |

`PutAccount` and `TombstoneAccount` carry their own signatures from the root or an admin. Records signed by the root are accepted with or without a `SignedOp` wrapper, which is how the first admin is created (§13.5).

**Root-signed:**

| Operation | Effect |
|---|---|
| `SetStateVersion { state_version }` | Activates a new StateVersion (§15.7). Accepted only with the **root key's** signature; no admin or account can submit it on its own authority |

**Node-initiated:**

| Operation | Effect |
|---|---|
| `RedeemEnrollment { token_proof, identity_key }` | Validated by the controller that received it against the pending entry. For an enrollment, creates the NodeRecord; for a re-key, replaces the existing node's `identity_key` (§8.1). Removes the pending entry. Because pending entries are replicated, a node can redeem its token at **any** controller |
| `RotateNodeKey { node_id, new_key }` | Signed by both the node's current key and `new_key`; replaces `identity_key` (§8.2) |

**System-initiated** (proposed by the leader, no admin involved):

| Operation | Effect |
|---|---|
| `ExtendValidity { valid_until }` | Sets the validity leaf (§6.16) to 30 days ahead. Proposed daily. It covers **every** non-tombstoned node at once, **whether or not the node has been seen online** (§10.5) |
| `ExpireEnrollments` | Removes pending enrollments whose token has expired |
| `AutoMembership { add learner / promote / demote / remove }` | A membership change the leader decided by itself (§7.5). Applied with the same checks as `ChangeMembership`, and refused when automatic membership is off |

Every controller validates each entry's shape before applying it. For example, an `ExtendValidity` entry may only move `valid_until` forward, to exactly the standard period after the entry's timestamp. This catches bugs in the leader. It is not protection against a compromised leader (§21.18).

**Not operations:** re-signing tree heads (§7.3); self-signed records (endpoints, link-state adverts, attachments, circuit setups, metric reports); and root- or emergency-signed material (certs, key tombstones, offline node tombstones). Controllers may store copies of the offline-signed items, but they don't need consensus to be valid.

**Uniqueness checks** in the state machine: overlay IPs are never assigned to two non-tombstoned nodes, a `node_id` is enrolled at most once, no identity key is used by two nodes (or reused after being replaced), and node names and account names are each unique. `node_id`s are random, chosen by the leader when proposing `CreateEnrollment` (§15.5).

**Reference checks:** a node's `owner` must be a valid, non-tombstoned account; the policy in a `SetNetworkConfig` must parse and pass its own tests (§14.5).

**Subnet route checks:** see §11.9.2. Published prefixes never overlap the overlay pool, each other (except identical grants for high availability), or any node's overlay IPs.

### 7.3 Signing tree heads

- After applying an operation, **each controller**, voter or learner, signs a SignedTreeHead with its own key, with `version` = the Raft log index it has applied.
- Each controller also **re-signs** its latest head periodically (for example every hour) with a later `expires_at`. This needs no quorum, so heads stay fresh as long as **any** controller is alive, even when the cluster can't commit writes.
- A controller signs only state that is **committed** (known to the Raft commit index), never uncommitted entries.
- Nodes accept a head from any valid controller key (§10.2) and keep the highest `version`.

### 7.4 Failover

| Situation | Effect |
|---|---|
| Leader dies | Raft elects a new leader within seconds. Writes and the daily validity extension resume automatically. Nodes notice nothing |
| A minority of voters down | Nothing visible. Remaining controllers keep committing and signing. After `dead_voter_after_s` (an hour by default) the leader gives a dead voter's seat to a healthy learner (§7.5), or an admin does sooner |
| Any number of learners down | No effect on writes |
| A majority of voters down or partitioned away | No new writes (no enrollment, changes or validity extension). Surviving controllers keep re-signing the last committed state, so tree heads stay fresh. Traffic is unaffected |
| All controllers down | Heads expire after 24–72 h and the network enters **soft mode** (§21.2). Records remain valid until the validity horizon, up to 30 days ahead (§6.16, §22) |

A controller that has died but is not suspected of compromise can stay a Raft member until the admin removes it (§7.5). The cluster keeps working as long as a majority is alive.

### 7.5 Adding and removing controllers

**Adding:**
1. The admin enrolls the node with the `control` role, or gives an enrolled node the role with `UpdateNode` (§8). The node starts the controller role and creates its signing key.
2. An admin signs a **SigningKeyCert** for the node's signing key (§6.5), or the root does on the offline computer.
3. The cert spreads by gossip, and the admin submits `ChangeMembership { add learner }`, which is accepted only for a valid node with the `control` role. The new controller receives a snapshot, catches up, and starts signing heads.
4. To make it a voter, the admin submits `ChangeMembership { promote }`, usually together with demoting or removing another voter so the count stays odd.

**Automatic membership** (from 0.7.0, on by default) does steps 3 and 4, and the cleanup, without an admin. Once a second after each commit, the leader computes one change and proposes it as an `AutoMembership` entry; Raft applies membership changes one at a time, so the next follows once it has committed. In order:
1. **Remove** a member that is no longer a valid controller: its node is revoked or lost the `control` role, or its SigningKeyCert is gone (its key retired, or its certifying admin revoked) while the leader's own is valid. Learners go first; the leader and the last voter never go.
2. **Add as a learner** every valid controller (role and cert) that isn't a member, unless an admin removed it with `ChangeMembership { remove }` (a manual `add learner` clears that).
3. **Replace a dead voter:** a voter the leader hasn't heard from for `dead_voter_after_s` (default 3600 s; 0 = never) is demoted, but only while a healthy learner (heard from within 30 s, at most 64 entries behind) can take its place.
4. **Voter count:** the target is the largest odd number no larger than both `voters` (default 5) and the number of members. Above it, the latest-joined voter is demoted (an unreachable one first, never the leader). Below it, the earliest-joined healthy learner is promoted, and only when the count can end odd: from an odd count, two healthy learners are needed.

"Joined" is the log index at which a node became a member, kept in controller state and snapshots (members from before 0.7.0 count as the earliest). Health, silence and certificates are the leader's own view; replicas check an `AutoMembership` entry only against replicated state, like a manual change. A new leader waits 30 s, so it has heard from its peers, before changing anything. The settings are the network configuration's `[controllers]` section (§6.18); with `auto_membership = false`, only admins change membership, as before.

**Upgrading to 0.7.0:** a controller from before 0.7.0 can't apply an `AutoMembership` entry and would halt. Controllers from 0.7.0 advertise `auto-membership` in their EndpointRecord, and the leader proposes nothing until every reachable member, and a node it is about to add, advertises it. An old controller that is unreachable for good is removed or replaced without that check; one that comes back must be upgraded. Upgrade every controller before the first change to `[controllers]` (a new leaf kind older controllers can't write).

**Removing:**
1. The admin submits `ChangeMembership { remove }`, then removes the node's `control` role (refused while it is still a member). With automatic membership, revoking the node or retiring its signing key (step 2) is enough: the leader removes it.
2. If the controller is being decommissioned, or might be compromised, its key is **retired** with a SigningKeyTombstone (§22.1), so the key can't be used again even if its disk is later recovered.

### 7.6 Network PSK epochs

- `RotatePsk` commits a new epoch ID. The leader generates the new PSK, and it is replicated to all controllers as part of the committed operation. Controllers encrypt the log at rest.
- Nodes fetch the current PSK from any controller over their end-to-end session, and periodically check for a new epoch.
- Nodes accept the current and previous epoch at the PSK gate (§9.1).
- **Controllers and seed relays accept every past epoch** at their PSK gate. A node that was offline through several rotations can therefore still reach the network (identity is still checked by the hop handshake), fetch the current PSK, and rejoin. On a seed relay, a session that passed the gate with an old epoch is restricted to **bootstrap mode** (§10.7.3).

---

## 8. Enrollment

1. An **admin** submits a signed `CreateEnrollment` through any controller, naming the **owner account** and assigning a name, overlay IPs, roles and tags. Normal accounts cannot start enrollments. The cluster commits it and returns a one-time **enrollment token**. The admin copies it to the node, with the address of any controller's enrollment endpoint.
2. The node generates its identity keypair locally.
3. The node connects to a controller and authenticates with `BLAKE3-keyed(token, pubkey || nonce)` (§15.4).
4. The controller submits `RedeemEnrollment`. Once it is committed, it returns:
   - the NodeRecord and its inclusion proof
   - the root public key, all SigningKeyCerts, and all SigningKeyTombstones
   - the current SignedTreeHead and the node list
   - all standalone offline-signed node tombstones
   - the seed list (§6.14), so the node can find the network before its first sync
   - the current network PSK and its epoch
5. The token is consumed by the committed operation.

**Alternative flow:** the node prints its public key fingerprint and the admin pastes it into the admin tool, which submits a signed enrollment directly, still naming an owner account. No token is needed, but it involves more manual copying.

The enrollment endpoint must be reachable by not-yet-enrolled nodes, so it is the one controller service not restricted to the overlay IP (§4.1). It is protected by the one-time token.

It is reached through the controller's ordinary TCP transport listeners, not a separate port, so it can't be found or blocked on its own (§9.7.2). The admin gives the node an **enrollment string** that bundles the token, controller addresses and transports, and for AnyTLS the camouflage domain and certificate pin.

### 8.1 Re-keying a node

A node's identity is its `node_id`, which is **random and fixed for life**, not derived from its key. Its key can therefore be replaced without changing anything else: name, overlay IPs, tags, owner, routes, magic DNS name, `node:<name>` rules and metrics history all carry over.

**Re-key** is for a machine that **no longer has its key**: reinstalled, replaced, or restored from a backup that can't restore a device-bound key (§8.3).

1. An admin, **or the node's owner**, submits a signed `RekeyNode` (§7.2). The cluster returns a one-time token, exactly as for an enrollment.
2. The new installation generates a fresh key and redeems the token with the normal `RedeemEnrollment`. Instead of creating a node, this replaces the existing node's `identity_key` and increments its `version`.
3. From that commit on, only the new key is accepted. Sessions using the old key are destroyed (§9.4.6).

`revoke_old_now` chooses what happens to the old key in the meantime:
- **false** (planned reinstall or migration): the old key keeps working until the token is redeemed, so the machine stays online until the switch.
- **true** (lost, stolen or compromised machine): the old key is removed at once, and the node is offline until the new installation redeems the token. This is the alternative to tombstoning when the node's identity should be kept.

A re-key gives the new installation exactly the node's existing name, IPs, tags, roles and routes, nothing more, which is why owners may do it for their own nodes.

### 8.2 Node-initiated key rotation

A node that still has its key can rotate it without an admin, for routine hygiene or to move the key into hardware-protected storage:

```
RotateNodeKey {
    node_id:  node_id
    new_key:  Ed25519 pubkey
}
signed by: the node's current key AND new_key
```

- The current key proves the request comes from the node; the new key proves the node actually holds it.
- Rejected for tombstoned nodes, nodes with a pending `RekeyNode`, and keys that are already in use or were used before.
- The node submits it to any controller over its end-to-end session. From the commit on, only the new key is accepted.
- **Stolen-key risk:** someone who stole the current key could rotate to a key of their own and lock the real machine out. They already had full access with the stolen key, though; an admin or the owner overrides it with `RekeyNode` (`revoke_old_now = true`) or a tombstone, and every rotation is in the audit trail (§13.3).

### 8.3 Key storage at rest

The identity key is Ed25519, as the raw-public-key TLS setup requires (§9.2). Most platform security hardware can't sign with Ed25519 (TPMs, Apple's Secure Enclave and Windows' TPM-backed keys mainly support P-256 and RSA). So the key is **encrypted at rest by a hardware- or OS-protected key** and decrypted into the agent's memory at start-up:

| Platform | Storage |
|---|---|
| Linux server | Key file readable only by the agent's OS user; where a TPM exists, **sealed to the TPM** |
| macOS / iOS | Keychain item restricted to this device only, optionally encrypted with a Secure Enclave key |
| Windows | Encrypted with DPAPI in machine scope (the agent runs as a service), or sealed through the TPM |
| Android | Encrypted with an Android Keystore key, StrongBox-backed where available |

- **In memory:** the key lives only in the agent process, in non-swappable memory, and is zeroed on exit.
- **Device-bound:** a sealed or device-only key can't be restored onto another machine, even from a full backup. A stolen disk image is therefore useless, and a restored or migrated machine uses a **re-key** (§8.1) instead of copying its key.
- Account keys (§13.1) are held by people, not the agent, and are outside this section.

---

## 9. Peer Authentication & Transport Security

Every link between two adjacent nodes is a **hop session** (§9.1–9.3). Traffic between a source and its final destination additionally runs inside an **end-to-end session** (§9.4), whether the path is direct or crosses relays.

### 9.1 Pre-handshake PSK gate

This layer resists probing, scanning, and DoS. It does **not** establish identity. Every transport checks knowledge of the network PSK before any identity handshake and before allocating session state:

- **UDP + KCP + FEC:** every datagram is encrypted whole under a PSK-derived key (§9.7.3).
  - A datagram that fails to decrypt is dropped **silently**, with no reply and no session allocation.
  - The first packet of a session carries a timestamp inside the ciphertext (tolerance ±60 s), and a replay cache rejects repeated nonces.
  - This prevents amplification and session-exhaustion attacks through KCP/FEC.
- **TCP + AnyTLS:** the AnyTLS password, a value derived from the PSK epoch, is the first data inside the outer TLS session. A connection that fails gets the camouflage website, or is closed (§9.7.2).
- **TCP + TLS:** the client sends `epoch_id || timestamp || nonce || MAC(PSK_epoch, …)` as the first bytes of the connection, before the TLS ClientHello. If it is invalid, the server closes the connection without starting TLS. This transport makes no attempt to hide (§9.7.1).
- **Epochs:** nodes accept the current and previous epoch; controllers and seed relays accept every past epoch (§7.6, §10.7.3).

### 9.2 Hop identity handshake

This uses mutual TLS with **raw public keys (RFC 7250)** in rustls, with no X.509 certificates, no WebPKI and no hostname checks.

- Each node presents its Ed25519 identity key directly as a raw public key.
- The custom verifiers (`ServerCertVerifier` / `ClientCertVerifier`) accept a peer only if:
  - its SPKI matches the `identity_key` of a NodeRecord
  - that record is included in a valid tree head, the tree's validity horizon has not passed (§6.16), and the node has no tombstone
  - its `owner` account is valid and not tombstoned (§13.4)
- The dialer knows which `node_id` it intends to reach and rejects any other key, even another node's valid one.

**AnyTLS transport:** the outer TLS session (BoringSSL, with the network's camouflage certificate, §9.7.2) provides no identity. Inside it, each side signs a TLS exporter value of the outer session (RFC 5705 / RFC 9266) with its identity key, and the other side verifies it against the NodeRecord. The same verifier rules as above apply.

### 9.3 Post-quantum protection

- Hop and end-to-end TLS handshakes complete **only** with the hybrid key exchange `X25519MLKEM768`.
- The AnyTLS outer ClientHello also lists the other groups a browser offers, so that it looks ordinary. Relays still always select `X25519MLKEM768`, and the client closes the connection if anything else is chosen.
- External PSKs are not mixed into TLS. The network PSK is used only by the pre-handshake gate (§9.1).
- The end-to-end session (§9.4) uses the same hybrid key exchange.

### 9.4 End-to-end session

The end-to-end session is a WireGuard-style packet protocol whose handshake is ordinary TLS 1.3. It reuses the hop layer's rustls setup for authentication and post-quantum key exchange, then leaves the TLS record layer behind, because a stream protocol breaks on the frame loss that relays are allowed to cause and adds head-of-line blocking.

#### 9.4.1 Session model

- **One session per `(src, dst)` pair, independent of circuits.** Primary and backup circuits (§11.4) carry the same session. Switching paths, including between direct and relayed routes, needs no renegotiation.
- **Used on direct paths too.** One code path for the endpoint check (§9.5), and seamless switching when hole punching (§11.7) succeeds or fails.
- **Created on demand** when the first packet for a destination leaves the tun interface. Up to 64 packets are queued during the handshake; beyond that they are dropped.
- **Idle timeout:** keys are discarded after 180 s without traffic.

#### 9.4.2 Handshake

1. **Roles:** the initiator is the TLS client. If both sides start at once, the node with the lower `node_id` stays client and the other abandons its attempt.
2. **Transport:** rustls runs on in-memory buffers (`write_tls` / `read_tls`). Handshake bytes travel in `HANDSHAKE` frames through the circuit, and a flight is retransmitted on timeout (starting at 1 s, exponential backoff).
3. **Authentication:** the same verifier as the hop layer (§9.2): raw public keys, `X25519MLKEM768` only, and each side expects exactly the `node_id` it intends to reach.
4. **Binding to the circuit:** the destination checks that the TLS peer identity equals `src` in the signed CircuitSetup (§11.5) of the circuit the handshake arrived on. On a mismatch it drops the circuit.
5. **Reachability check:** each side refuses the session if the policy allows no traffic in either direction between the two nodes (§14.4). The peer then can't even confirm the node exists.
6. **Key derivation:** each side picks a random receive `key_id` (u32) and sends it in a TLS application-data message at the end of the handshake. Then:
   ```
   keys  = export_keying_material(label   = "webjet-e2e-v1",
                                  context = initiator_key_id || responder_key_id,
                                  len     = 64)
   k_i2r = keys[0..32]   // initiator → responder
   k_r2i = keys[32..64]  // responder → initiator
   ```
   The TLS connection object is then dropped; its record layer is never used for data.

#### 9.4.3 Frames

Frames use the format in §6.9.

- **AEAD:** ChaCha20-Poly1305 by default; AES-256-GCM where hardware AES is available.
- **`DATA`:** one inner IP packet, never fragmented. **`DATA_LZ4`** carries it LZ4-compressed (§9.8).
- **`PROBE` / `PROBE_ACK`:** `{ route_tag, sent_at, echo, held }` and `{ route_tag, sent_at, reply_at }`: the route tag is the route id's first 8 bytes, a probe echoes the last answer's `reply_at` and how long it was held, so both ends measure the round trip from one exchange (§11.4). Nodes before 0.10.2 send `{ route_id, probe_seq, sent_at }` and expect it echoed; newer nodes answer such probes that way. Encrypted end to end, so a relay can delay or drop probes but never forge an answer. They are sent only over circuits with little traffic of their own (§11.4): they show the circuit works, and give its cost until its links are known.
- **`PUNCH_OFFER` / `PUNCH_GO`:** hole-punching coordination (§11.7).
- **`MCAST`:** one inner broadcast or multicast packet, delivered to the tun interface only and never forwarded; **`GROUPS`:** which broadcasts and groups the sender takes (§9.5.1). Both are sent only to peers advertising `multicast`.
- **`CLOSE`:** the peer tears down the session.
- The whole E2EFrame is the **inner frame** counted by accounting (§12.1).

#### 9.4.4 Receiving

1. Look up `key_id`. If it is unknown, drop the frame silently.
2. Check `counter` against a sliding **replay window** (bitmap, as in RFC 6479) of 8,192 packets, large enough for reordering when switching between circuits.
3. Decrypt. If authentication fails, drop the frame without updating the window.
4. Mark the counter as seen.
5. For `DATA`, apply the cryptokey routing check (§9.5), then the access-control check (§14.4), then write the packet to the tun interface.

#### 9.4.5 Rekeying

| Parameter | Value |
|---|---|
| Rekey after | 120 s or 2⁴⁰ packets, whichever comes first |
| Reject keys after | 180 s |
| Old-key grace period | Keep decrypting with the previous key for 10 s after switching |

Each rekey is a full new handshake in the background over the current circuit, giving forward secrecy (including post-quantum forward secrecy). The sender switches keys only after the new handshake completes.

#### 9.4.6 Lifecycle events

| Event | Action |
|---|---|
| Peer tombstoned | Destroy the session and its keys immediately |
| Peer's NodeRecord changes identity key (re-key or rotation, §8.1–8.2) | Destroy the session; the next packet triggers a new handshake with the new key |
| Path switch or circuit rebuilt | Nothing; the session continues on the new circuit |
| All circuits to the peer down | Keep the keys until they expire; resume without a handshake if a circuit returns in time |
| Authenticated `CLOSE` received | Destroy the session |

#### 9.4.7 MTU

Per-packet overhead is 29 bytes (e2e) + 5 bytes (relay frame header) + the hop transport's own overhead. The e2e layer never fragments. Compression (§9.8) only ever makes a frame smaller, so it doesn't change the MTU. The tun MTU defaults to **1280 bytes**, the IPv6 minimum, which fits through every hop type; admins may raise it after measuring their paths.

### 9.5 Cryptokey routing (mandatory, at the endpoint)

With relays, the last hop's TLS peer is a relay, not the source. So the check uses the identity from the **end-to-end session**:

- Inbound: drop any inner packet whose source IP is not in the `overlay_ips` of the end-to-end authenticated source node. **Exception for gateways:** a packet from a gateway may also carry a source IP inside a published prefix that gateway is granted and serving, but only as a reply on a flow this node started (§11.9.4).
- Outbound: send packets for a destination IP only to the node whose record contains that IP, or, for a published subnet prefix, to a gateway serving it (§11.9.3). The state machine guarantees each overlay IP belongs to at most one node (§7.2).
- **Denied by policy:** if the outbound access-control check (§14.4) denies a packet, write an ICMP / ICMPv6 "administratively prohibited" back into the tun interface. Rate-limit these replies too.
- **Unreachable destination:** if path computation finds no route to the destination (for example because it is offline, §10.5), write an ICMP / ICMPv6 "host unreachable" back into the tun interface, so applications fail fast instead of waiting for a timeout. Rate-limit these replies.
- **Multicast and broadcast** go through §9.5.1 or are dropped silently: they never count as unroutable, and no ICMP error is sent about a packet to or from a multicast, broadcast or unspecified address (RFC 1122 3.2.2, RFC 4443 2.4). That rule applies to every ICMP error Webjet writes, and only a reply that is actually sent takes a rate-limit token.

#### 9.5.1 Broadcast and multicast

The overlay behaves as one link for UDP broadcast and multicast, so LAN discovery works across it (Minecraft Bedrock's RakNet pings to `255.255.255.255:19132`, mDNS, SSDP, game lobbies). It is on by default and needs no configuration beyond the policy.

**What is carried.** UDP that the host sends from its own overlay address to:

- a broadcast: the limited broadcast `255.255.255.255`, the IPv4 overlay pool's own broadcast address (`10.7.255.255` for `10.7.0.0/16`), all-hosts `224.0.0.1`, or `ff02::1`;
- a multicast group: any other IPv4 multicast address, or IPv6 multicast of link-local scope or wider (interface-local `ff01::/16` never leaves a host).

IPv6 link-local sources (mDNS and LLMNR use them) are rewritten to the node's overlay address. Other sources (a gateway's LAN, another program's spoofed address), other protocols and IGMP/MLD are not carried; a gateway never passes a LAN's broadcasts into the overlay, nor the overlay's onto a LAN.

**Fan-out, never forwarding.** The sending node makes one copy per recipient and sends it, frame type `MCAST`, in its end-to-end session with that peer (§9.4), through whatever circuit the session uses; relays see only ordinary encrypted frames. A receiving node writes the copy to its tun interface and nowhere else. No node forwards a broadcast it received, so a packet can't loop through the overlay or come back multiplied. Recipients are the valid DATA nodes that:

- have an overlay address of the packet's family;
- advertise the `multicast` feature in their EndpointRecord (an edge node that has no record for a peer yet looks it up, and reaches it from the next packet on; discovery repeats);
- the policy lets the sender reach on the packet's protocol and port (§14.4);
- want it: for a group, only peers whose host joined that group (below).

**Membership (IGMP/MLD snooping).** Each node reads the groups its host joined on the tun interface from the OS (Linux `/proc/net/igmp` and `/proc/net/igmp6`, macOS and FreeBSD `getifmaddrs`, Windows `GetMulticastIpAddressTable`) every 5 s, and at once when the host sends an IGMP or MLD report. When a node receives a copy from a sender, it answers with a `GROUPS` frame listing the groups it takes: on first contact, every 60 s while copies keep coming, and to every recent sender when its groups change. A sender keeps the list for 180 s; until it has one for a peer, it sends the peer everything. Broadcasts go to every recipient regardless. A node whose OS can't tell its groups reports "any". A receiving host's kernel still drops groups it hasn't joined, so a stale list costs only bandwidth.

**Replies.** Discovery is answered by unicast (a RakNet pong, an mDNS reply). Each copy is tracked in connection tracking as the unicast flow it stands for, on both ends: the sender records `(peer, its host's address and port → the peer's overlay address and the destination port)`, the receiver the same flow towards its own address. The reply then passes as a reply on both ends without a separate rule from the replier to the sender, exactly as for a unicast flow the sender started. A hit counts for the allowing rule.

**Storm limits.** On top of having no forwarding:

- **Budget per node:** `multicast_packets_per_sec` (default 50) and `multicast_bytes_per_sec` (default 64 KiB) cap what the node sends. *Every copy counts*: a broadcast to 20 peers takes 20 packets of the budget. Copies over the budget are dropped; the next datagram starts where the last fan-out stopped, so a budget smaller than the network still reaches each peer in turn. A node's broadcast traffic can't exceed the budget, whatever its applications do, and the `multicast_limit` alarm (warning) is raised at the first refused copy (it clears after a minute without).
- **Cap per sender:** a receiver takes at most the same budget from each sender and drops the rest, so a broken or hostile node can't flood others.
- **Echoes:** a datagram the host sends within a second of receiving one with the same destination kind and payload is not sent again. That stops reflectors (an mDNS repeater, an application that rebroadcasts what it hears) from bouncing packets between nodes.
- **Off:** `multicast_packets_per_sec = 0` turns it off for the nodes it applies to: they send nothing, drop what arrives, tell senders so (an empty `GROUPS` report), and stop advertising `multicast`.

For Minecraft Bedrock: a client on the server list pings about once a second, which is one copy per peer per second, under 2 KB/s with 30 peers; the defaults leave room for about 50 peers before the budget rotates.

**Counters.** `webjet_multicast_packets_total{direction}` counts copies sent (tx), datagrams delivered (rx) and datagrams taken by capture (captured, §9.5.2); `webjet_limit_hits_total{limit="multicast_limited"}` counts copies and datagrams over a budget, `{limit="multicast_echo"}` echoes not sent, `{limit="multicast_duplicate"}` datagrams sent both ways and carried once. Copies denied by policy on the receiving end count as `acl_denied`.

**Limits.** Without capture (§9.5.2), only what reaches the tun interface is carried. An application that broadcasts to `255.255.255.255` without choosing an interface has it sent out of one interface: on Linux, macOS and FreeBSD the one with the default route, on Windows the one whose `255.255.255.255/32` route has the lowest metric; normally the physical one, not the overlay's. Applications that broadcast to the overlay pool's address (`10.7.255.255`), bind to the overlay address, or send multicast on the overlay interface work everywhere; receivers deliver the pool broadcast as `255.255.255.255`, which every OS accepts. Fragmented datagrams are not carried whole: later fragments have no ports for the policy check and are dropped (discovery packets are small).

#### 9.5.2 Capture: broadcasts sent out other interfaces

Most games broadcast their LAN discovery to `255.255.255.255` from a socket bound to `0.0.0.0`, so the OS sends it out of the LAN interface (above). Capture copies those datagrams into the overlay without taking them from the LAN, so players on the LAN and on the overlay both see the game. It is off by default and turned on per UDP port: `[multicast] capture = ["udp:19132"]` in the network configuration (for every node) or a node's own configuration (replacing the network's; `capture = []` turns it off for that node).

**What is captured.** UDP datagrams that the host itself sends (their source is one of its addresses on another interface) to a captured port, unfragmented, to the limited broadcast, to the directed broadcast of the sending interface's subnet, or to an IPv4 multicast group. Never DHCP (67, 68), NetBIOS (137, 138), SSDP (1900), WS-Discovery (3702), mDNS (5353) or LLMNR (5355): their answers carry LAN addresses peers can't reach, and those protocols already run on every interface, the overlay's included. IPv6 has no broadcast; its multicast stacks send on every interface.

**Into the overlay.** The datagram's source becomes the node's IPv4 overlay address (the port stays), and a directed LAN broadcast becomes `255.255.255.255`. Then it takes the path of a datagram the host sent into the tun interface: policy per recipient, the budget, echo detection, fan-out (§9.5.1). The peers' unicast replies come back to the overlay address and port, where the application's `0.0.0.0` socket receives them, and are tracked as replies. One addition: an application that sends the same datagram both ways (to every interface) within 500 ms has it carried once, by whichever way came first.

**How, per OS.** Capture needs no driver and changes no route:

- **Linux:** one `AF_PACKET` socket with a classic BPF filter in the kernel: outgoing (`PACKET_OUTGOING`) IPv4 UDP to the captured ports, unfragmented. Only matching datagrams are copied to the agent. Needs `CAP_NET_RAW` (the agent runs as root or with the capability).
- **macOS:** a BPF device (`/dev/bpf*`) per Ethernet or Wi-Fi interface with an IPv4 address, with the same filter for Ethernet frames; the agent keeps only datagrams from the host's own addresses. Interfaces are re-checked every 5 s.
- **FreeBSD (OPNsense):** as macOS (one cloned `/dev/bpf` per Ethernet interface, including VLAN, bridge and lagg interfaces; tunnels such as `tun`, `ovpn`, `wg`, `enc` and `pflog`/`pfsync` are skipped), with the device set to see sent packets only (`BIOCSDIRECTION`), so a router's busy LANs cost nothing.
- **Windows:** a raw UDP socket bound to `127.0.0.1`, which receives the limited broadcasts this host sends whatever interface Windows chose (the technique of WinIPBroadcast). It sees no directed broadcasts or multicast, and, as WinIPBroadcast documents, no datagram whose source and destination ports are equal. Datagrams with TTL 1 (WinIPBroadcast's own relays) are ignored. Needs administrator rights, which the service has.

If capture can't start (no permission, no BPF device), the `multicast_capture` alarm (warning) says why and the agent retries every minute; everything else works as without capture.

**Applications bound to a LAN address** (`192.168.1.5:port` rather than `0.0.0.0`) don't receive the replies, which go to the overlay address. That is rare for discovery.

**Upgrading.** Nodes before 0.11.0 don't advertise `multicast`, so they are left out of fan-out and never receive `MCAST` or `GROUPS` frames; no order is needed. Older controllers refuse the new limit names in a network configuration (`unknown limit`); upgrade controllers before setting them.

### 9.6 Transport selection: priority and cost

Two nodes may be able to reach each other over several transports. **Priority** decides which transports are allowed and preferred; **measured cost** decides which one carries traffic.

**Priority.** Every node has a priority from 0 to 255 for each transport. **0 means "never use"**. A node's priorities come from, first match wins:
1. the node's own configuration (NodeConfig, §6.19)
2. the first matching override in the TransportConfig leaf (§6.17), by selector
3. the TransportConfig defaults
4. built-in defaults: UDP+KCP+FEC 30, TCP+AnyTLS 20, TCP+TLS 10

Each node publishes its priorities in its EndpointRecord (§6.2). For a peer, the published priorities come first: they are what the peer itself uses.

**Eligible transports.** A transport is eligible between two nodes if both give it a priority above 0 and the side being dialed publishes an address for it. Hole-punched direct hops are UDP only (§11.7). The side being dialed accepts any transport to which it gives a priority above 0.

**All eligible transports are kept connected and measured.** A pair holds one hop session per eligible transport, up to three, and measures RTT and loss on each through its keepalives (§11.2).

**One session per transport.** When both nodes dial each other at once, both keep the connection the lower node id dialed. Racing dials finish within about a round trip of each other, so any other incoming connection for a transport that already has a session means the peer lost that session: it restarted, or its side of the connection died. Over UDP nothing tells the other end. The new connection replaces the old one at once, and the circuits through the old one are closed (the peer lost them too), instead of being refused until the old session times out (15 s).

**Choosing by cost.** For each neighbor, a node sends on the eligible transport with the **lowest measured cost** (§11.2):
- If several transports are within 10% of the best cost, the one with the **highest sum of the two nodes' priorities** is used. Remaining ties go to UDP+KCP+FEC, then TCP+AnyTLS, then TCP+TLS.
- The usual hysteresis applies: a node switches only when another transport is better by 15–20% for several seconds (§11.4).
- A transport that can't connect, or whose session drops, has infinite cost until it reconnects. Reconnection is retried with backoff (1 min, doubling to 30 min).
- Each direction chooses independently, so the two nodes may send on different transports.

| Situation | Transport used |
|---|---|
| All three eligible, UDP clearly cheapest | UDP+KCP+FEC |
| UDP and AnyTLS within 10% of each other, default priorities | UDP+KCP+FEC (sum 60 against 40) |
| One node sets UDP and TLS to 0 (a restricted network) | TCP+AnyTLS, the only eligible one |
| UDP is blocked or throttled on the path | The cheaper of TCP+AnyTLS and TCP+TLS |
| Two datacenter relays give TLS priority 100, costs near-equal | TCP+TLS (sum 200) |

**Switching is invisible above the hop.** Circuits belong to the pair of neighbors, not to one transport session (§11.5), so moving to another transport rebuilds nothing. Path computation sees one link per neighbor pair: the selected transport and its cost, which is what link-state adverts and attachment records carry (§6.7, §6.8).

### 9.7 Obfuscation and probing resistance

#### 9.7.1 Threat and what each transport offers

The observer is an on-path middlebox that classifies traffic and then blocks or throttles it. It can inspect passively (handshake fingerprints, byte patterns, packet sizes and timing), probe actively (connect to a node's port, replay captured packets), and block addresses.

| Transport | To a passive observer | To an active probe |
|---|---|---|
| TCP+AnyTLS, `WEBSITE` mode | HTTPS from a browser to a website | A web server with a valid certificate and a real site |
| TCP+AnyTLS, `REFUSE` mode | HTTPS from a browser to a website | A TLS server that closes every connection: recognizably not an ordinary website |
| UDP+KCP+FEC | Random-looking UDP with no recognizable header | No reply at all |
| TCP+TLS | **Identifiable.** A TCP preamble followed by a TLS handshake with a custom ALPN and raw-public-key extensions | A port that closes without answering |

Nodes on inspected networks set the priorities of transports they must avoid to 0 (§9.6).

#### 9.7.2 AnyTLS (camouflage)

**Outer TLS: BoringSSL on both sides.**
- The client's ClientHello matches a current Chrome's: the same cipher suites, extensions and their ordering behavior, key-share groups and ALPN (`h2`, `http/1.1`). BoringSSL is the TLS library Chrome uses, which makes this achievable; rustls cannot produce it. The profile must be updated as browsers change.
- rustls remains the library for plain TCP+TLS hops, the TLS inside KCP, and end-to-end sessions.

**One domain, certificate and website for the whole network** (the `camouflage` part of the TransportConfig, §6.17):
- Every node uses `domain` as the SNI, whichever relay it connects to.
- Every node that accepts AnyTLS connections presents the same certificate. For `WEBSITE` mode to be convincing, the certificate must be issued by a public CA for that domain, and the domain's public DNS should resolve to relay addresses, since a name that doesn't match the address it's used with is itself detectable.
- **Clients pin the certificate's public key** (current, or `next_spki`). Nobody else can then terminate the connection and capture the credential. Renewing the certificate with the same key needs no client change; a key change is announced in `next_spki` beforehand. A node that was offline through the whole overlap uses another transport to catch up.
- **Private key and website:** set with `SetCamouflageSecret` (§7.2) and kept in controller state. Only nodes with `RELAY` or `CONTROL` accept AnyTLS connections; they fetch the key and site from a controller over their end-to-end session, as they fetch the PSK, and store them encrypted at rest (§8.3).
- **The website** is either a static bundle that relays serve themselves, or a reverse proxy to an origin URL.

**Authentication.** The first data inside the outer TLS session is the AnyTLS password, `BLAKE3.derive_key("webjet anytls password v1", PSK_epoch)`, followed by padding (§9.7.4). An observer can't see or replay it. The relay compares it in constant time against the epochs it accepts (§9.1). On success, the two sides continue with the version hello (§15.8) and the identity handshake (§9.2).

**When authentication fails**, according to `mode`:
- **`WEBSITE`:** the bytes already read are handed to the web server, which answers as the camouflage site. Serving the site is the default code path, so success and failure don't differ in timing before the first reply.
- **`REFUSE`:** the connection is closed. This needs no website and no public certificate, but a probe can tell the node isn't an ordinary web server (§9.7.1).

**Enrollment** uses the same listener on controllers. A node that isn't enrolled yet has no PSK, so its credential is derived from its enrollment token instead; the controller checks it against pending enrollments (§8).

**Connection lifetime.** Browsers don't keep one TLS connection open for days. An AnyTLS hop is replaced at a random interval of 30–90 minutes: the new connection is opened first, traffic moves over, and the old one closes.

#### 9.7.3 UDP packet encryption

Every UDP datagram, including KCP control packets and FEC parity, has this form:

```
datagram     = nonce[24] || masked_epoch[2] || XChaCha20-Poly1305(k_epoch, nonce, inner || padding)

k_obfs       = BLAKE3.derive_key("webjet udp obfs v1", root_public_key)      // static for the network
k_epoch      = BLAKE3.derive_key("webjet udp packet v1", PSK_epoch)
masked_epoch = epoch_id XOR first 2 bytes of BLAKE3-keyed(k_obfs, nonce)
```

- **Nothing is in cleartext:** no KCP header, no fixed field, and the nonce is random.
- **The masked epoch ID** tells the receiver which PSK epoch to decrypt with, in one attempt, without showing a constant value. `k_obfs` only hides structure; it is not a secret from former members and nothing relies on it for security.
- **A 24-byte random nonce** is safe for a key shared by the whole network at any packet rate.
- **Overhead:** 42 bytes per datagram, within the default tun MTU (§9.4.7).
- This layer is the PSK gate for UDP (§9.1). Identity still comes from the TLS handshake carried inside KCP (§9.2).

#### 9.7.4 Padding and timing

- **Padding scheme.** The first packets of every hop session are padded and split according to the `PaddingScheme` in the TransportConfig, in the manner of AnyTLS's padding scheme. Because it is in the tree, it can be changed for the whole network without a software update.
- **End-to-end handshakes** (§9.4.2) are a TLS handshake inside the hop session, a known way to recognize tunnels. `HANDSHAKE` frames are padded to size buckets, and because hop sessions are long-lived and shared by many circuits, these handshakes are spread through the session instead of sitting at its start.
- **Small UDP packets** (acknowledgements, keepalives) get 0–31 bytes of random padding, so they don't all have one size.
- **Timing.** Keepalives, the core's gossip tick (§10.3.1) and periodic refreshes are jittered by ±20%, and ride on data packets when there is traffic.

#### 9.7.5 What obfuscation doesn't cover

- **Address blocking.** Once a relay's address is identified, it can be blocked. The defense is several relays and seeds (§10.7).
- **One certificate links every relay.** Anyone can connect to a relay and see the camouflage certificate, then scan for other addresses presenting it. Identifying one relay can therefore reveal the others. This is the cost of one network-wide certificate instead of one per relay.
- **Random-looking UDP** is not recognizable as Webjet, but some networks throttle or block all unrecognized UDP. Its measured cost then rises and traffic moves to TCP+AnyTLS (§9.6). Imitating QUIC is not attempted; a careful observer can tell an imitation from the real protocol.
- **`REFUSE` mode and plain TCP+TLS** don't withstand active probing or fingerprinting, as §9.7.1 shows.
- **Traffic volume and long-term patterns** of a busy relay are not hidden.

### 9.8 Compression

Two planes, two algorithms, two defaults:

| Plane | What | Algorithm | Default |
|---|---|---|---|
| Control | Hop control records (gossip, Merkle sync, lookups, circuit setup) and RPCs over end-to-end sessions (operations, metric uploads, controller status, the audit log) | zstd, level 3, one message at a time | on |
| Data | Inner packets in `DATA` and `PROXY` frames | LZ4 block, one packet at a time | off |

- **One message at a time.** Neither plane keeps a dictionary or stream state between messages, so loss, reordering and switching circuits (§9.4.1) never break decompression, and a relay needs no state for it.
- **Only when it pays.** Control messages under 256 bytes and packets under 128 bytes are sent as they are, and so is anything that doesn't get smaller (a packet must save at least 16 bytes). The data plane also skips traffic that is encrypted already (TCP or UDP port 443, 853 or 22, and ESP) and backs off per flow: after three packets in a row that didn't shrink, a flow's next 32 packets are sent without trying, doubling with each further miss up to 1,024.
- **Where.** Data compression happens inside the end-to-end session, before encryption: relays see the same opaque frames as before, only shorter. The compressed payload of a `DATA_LZ4` / `PROXY_LZ4` frame is `len[2] || LZ4 block`, `len` being the inner packet's length. Control records are compressed per hop (hop records are `type[1] || len[3] || payload`; a compressed control record has its own type), RPCs per session (`RPC_ZSTD` frames); zstd frames declare their size.
- **Negotiation.** A node advertises the planes it has turned on as the EndpointRecord features `zstd` and `lz4` (§6.2, §15.8). A sender compresses only when it has the plane on and the receiver advertises it, so both ends must have it on, and nodes without compression support never receive compressed messages. A receiver accepts compressed messages whatever its own settings, because a peer's copy of its features lags a change.
- **Limits.** Decompression never produces more than the receiver's cap: a hop record's maximum (1 MiB) for control messages, 65,535 bytes for a packet. A zstd frame that doesn't declare its size, or declares more than the cap, is dropped before anything is allocated. A message that fails to decompress is dropped and counted.
- **Secrets are never compressed.** Compressing secrets together with data an attacker can influence leaks the secrets through message lengths (CRIME, BREACH). RPCs carrying PSKs or the camouflage key, and Raft traffic (log entries and snapshots hold both), are always sent uncompressed.
- **Why data compression is off by default.** Packet lengths are visible to everyone on the path. Compressing before encrypting makes those lengths depend on the content, so an attacker who can inject data into a flow next to a secret (a cookie in a web page, for example) can learn the secret byte by byte from the frame sizes (the VORACLE attack on OpenVPN). WireGuard has no compression for this reason. Most traffic today is encrypted already and doesn't shrink. Turn the data plane on for links where bandwidth is expensive, the traffic is compressible (plain HTTP, file shares, databases, logs) and this risk is acceptable, network-wide or only for some nodes.
- **Settings:** `[transport.compression]` in the network configuration (§6.17) with `control` (`zstd` or `off`) and `data` (`lz4` or `off`), and the same keys in a node's configuration (§6.19), which replace the network's per plane: node, then network, then built-in. A value a node doesn't know counts as off.
- **Upgrading.** Nodes may mix versions: compressed messages go only to peers that advertise support. The setting itself is new tree content, so every controller must run a version that knows it before the first change to `[transport.compression]`; an older controller recomputes different leaf bytes and halts on divergence (§15.5).
- **Accounting.** Route counters (§12.1) count frames as sent, so compressed frames count with their compressed size; link counters likewise. Each node also counts, per plane, the messages it compressed and decompressed, their bytes before and after, the messages it sent uncompressed although the plane was on, and decompression errors (`webjet_compression_*`, §12.5).

---

## 10. Node-List Distribution & Offline Operation

### 10.1 Sources

Nodes accept state from any controller **or** from any peer. The source doesn't matter, because every item is verified: tree heads by a controller signature, records by inclusion proofs, and everything else by its own signature.

### 10.2 Merge rules

**Controller certificates:**
- SigningKeyCert: accept only if signed by the root key, or by the key in its `issuer` AccountRecord, which must be a root-signed admin record (§6.5); and no SigningKeyTombstone exists for that `signing_key_id`. An admin's cert counts only while that admin isn't tombstoned and still has that key.
- SigningKeyTombstone: accept if signed by the root or emergency revocation key. It is permanent and takes effect immediately (§22.1).

**Tree state:**
- SignedTreeHead: accept only if its `signing_key_id` has a valid SigningKeyCert, `version` is at least the stored high-water mark, and, if the key is tombstoned, `version <= last_valid_version`. A head with the same version and root as the stored one but a later `expires_at` replaces it (a re-signing).
- NodeRecord and committed Tombstone: accept only with a valid inclusion proof against an accepted head, and only if `version` is greater than the stored version.
- Offline-signed Tombstone: accept if signed by the root or emergency revocation key and `version` is greater than the stored NodeRecord version. Tombstones are permanent.
- AccountRecord: accept only with a valid inclusion proof **and** a valid signature from an allowed signer (§6.10), and only if `version` is greater than the stored version.
- AccountTombstone: accept with an inclusion proof and a valid signature, or standalone if signed by the root or emergency revocation key. Permanent.
- Policy, DnsConfig, Seeds, Limits and TransportConfig: accept only with a valid inclusion proof and a `version` greater than the stored one.
- Validity: accept with a valid inclusion proof; the tree-head version orders it.

**Self-signed records:**
- EndpointRecord: accept only if the signature matches the node's identity key, `seq` is greater than the stored value, and it hasn't expired.

Routing records (LinkStateAdvert, AttachmentRecord) follow their own rules (§11.3).

### 10.3 Gossip sync (Merkle anti-entropy)

1. Peers exchange SignedTreeHeads.
2. If the roots differ and the versions are the same, that is **equivocation** (see §21.3).
3. If the roots differ and the versions differ, the node with the older version walks the sparse Merkle tree to find the differing subtrees and fetches only the changed leaves.
4. Every fetched leaf is checked with an inclusion proof against the signed root.

SigningKeyCerts, SigningKeyTombstones and offline-signed node and account tombstones are small, rare sets. They are gossiped with priority outside the tree.

#### 10.3.1 Sync interval and flood protection

This describes anti-entropy **within the core**. Edge nodes sync with their home relays instead (§10.6).

- **Sync tick: every 1 second.** On each tick, a core node sends one **digest** to each core peer it syncs with that tick (see fan-out below):
  `BLAKE3( version || root || BLAKE3(cert, key-tombstone and offline-tombstone sets) )`.
- **Identical parts are never transferred:**
  - If the digests match, nothing else is sent that tick.
  - If they differ, the peers exchange full SignedTreeHeads and, if needed, the small offline-signed sets.
  - The Merkle walk descends only into subtrees whose hashes differ, and only the changed leaves are fetched.
- A head re-signed with only a later `expires_at` changes nothing in the digest, so it spreads lazily: peers pick it up when they next exchange heads for another reason, or on a periodic full exchange (for example every 10 minutes).
- Nodes only relay SignedTreeHeads that are **already signed** by a valid controller key. They never create or re-sign heads. Heads that fail verification are dropped and not forwarded.
- **Rate limit:** at most one SignedTreeHead per peer per second in each direction. Extra heads within the same second are dropped.
- The two conflicting heads that prove equivocation (§21.3) are always forwarded, within the same rate limit, so the alarm spreads.

- **Fan-out:** with **64 relays or fewer**, each core node exchanges digests with every other core node each tick. Above 64, each core node picks **4 core peers at random** per tick; changes still reach every relay within a few seconds, because each round spreads them further. Either way, changes are also **pushed immediately** to all core peers, so the tick is only a safety net.

### 10.4 Persistence

The following are persisted to disk:
- the highest accepted `SignedTreeHead.version` and the head itself
- all records, their inclusion proofs, and all tombstones, including standalone offline-signed ones
- all SigningKeyCerts and SigningKeyTombstones

After a restart, a node must never accept state older than what it has persisted. The one exception is the reset when a controller key is retired for compromise (§22.1).

Routing and liveness state (§10.5, §11) are not persisted; they are rebuilt from fresh measurements after a restart. **Exception:** the last known EndpointRecords of relays are kept as reconnection hints (§10.7.1). Unsent metric reports are persisted (§12.5).

### 10.5 Node liveness (online and offline)

Nodes going online and offline is **not** an operation, and never touches the controller log (§7.2). Whether a node is *allowed* on the network (record, roles, tombstones) is decided by admins; whether it is *reachable* right now is soft state, observed by the nodes themselves.

**Signals:**

| Signal | Published by | How "offline" shows up |
|---|---|---|
| Hop keepalives | Each hop session | Adjacent peers notice within seconds |
| LinkStateAdvert | Relays | Neighbors drop a dead relay from their own adverts within seconds (§11.3); its own advert expires after 5 min |
| AttachmentRecord | DATA nodes | Expires; the node becomes unreachable in routing |
| EndpointRecord | Every node | Expires (§6.2); stale addresses stop circulating |
| Metric reports | Every node | Controllers see when a node last reported |

When a destination is offline, sources find no route and answer locally with host-unreachable (§9.5).

**Validity ignores liveness.** The daily `ExtendValidity` (§7.2) keeps every non-tombstoned node valid, whether or not it has been seen. A laptop that is off for two months comes back and works. Abandoned nodes are removed by an admin tombstone. The admin UI helps by listing nodes with no metric report for, say, 30 days (§12.6).

**When a node comes back online:**
1. It loads its persisted state, finds a relay through the discovery order (§10.7), and syncs tree heads, catching up through the Merkle diff (§10.3).
2. It checks its own record. If it was tombstoned, or the tree's validity horizon has passed and no newer tree is available, it stops and tells the operator.
3. If its PSK epoch is stale, it reaches a controller in bootstrap mode through a seed relay, or directly, and fetches the current PSK (§7.6, §10.7.3).
4. It publishes a new EndpointRecord, picks its home relays and publishes its AttachmentRecord (or LinkStateAdvert, if it is a relay).
5. Peers find routes to it again, and end-to-end sessions re-handshake on the first packet.

### 10.6 Gossip topology: core and edge

```
          ┌──────────── core: RELAY nodes (tens) ────────────┐
          │  R1 ◄──► R2 ◄──► R3 ◄──► R4   anti-entropy (§10.3)│
          └───▲───────▲───────────────▲─────────▲────────────┘
              │       │               │         │
            laptop   phone          server    gateway       edge: nodes without RELAY,
          (R1, R2)  (R2, R3)       (R3, R4)   (R1, R4)      syncing only with home relays
```

- **Core:** every `RELAY` node, including `DATA+RELAY` and `CONTROL+RELAY` nodes. Core nodes run the anti-entropy of §10.3 with each other.
- **Edge:** every node without `RELAY`. An edge node exchanges control-plane state **only with its home relays**, never with other edge nodes.
- **Home relays:** the relays in the node's AttachmentRecord (§6.8). **3**, chosen automatically as the relays with the **lowest measured link cost** (RTT and loss, §11.2), with hysteresis (a current home relay counts 10% cheaper) so the set doesn't flap. Every minute the node dials every relay it isn't connected to, measures the links for 15 s and keeps the best three, so a better relay (one just enrolled, say) becomes a home relay within about a minute. Hops to relays it drops are closed, except while a circuit of its own still goes through them. Between rounds, a lost home relay is replaced by the relay with the best long-term link record. The node already keeps hop sessions to them for traffic, so gossip needs no extra connections.
- **No relays at all** (a small deployment): every node is core.
- **Controllers** should hold `RELAY` too (§4.1). A controller without it is an edge node and pushes each new tree head to its home relays immediately.

#### 10.6.1 What flows where

| State | Within the core | Core → edge |
|---|---|---|
| Tree heads and Merkle diffs | Anti-entropy (§10.3.1) | **Pushed** when a new head arrives; the edge node pulls the diff |
| Certs and offline-signed tombstones | Priority flood | Priority push |
| LinkStateAdverts | Flooded (§11.3) | The full set, pushed. It is small and needed for path computation (§11.4) |
| Edge nodes' EndpointRecords and AttachmentRecords | Flooded, so every relay holds all of them | **On demand only**, through lookups and subscriptions (§10.6.2) |
| Metric reports | Not gossiped (§12.5) | Not gossiped |

Each edge node stores the full tree, the relay graph, and endpoint and attachment records **only for peers it talks to**. Address changes of unrelated nodes never reach it. The exception is a user looking at the whole network: the agent's `topology` control command (webjet-app's Nodes tab) makes it subscribe at its home relays to every node's records for two minutes, renewed each minute while requests keep coming, so the graph shows every node's links and delays.

#### 10.6.2 Lookups and subscriptions

```
Lookup    { node_ids: [node_id] }               → their EndpointRecords and AttachmentRecords
Subscribe { node_ids: [node_id], ttl: 300 s }   → the relay pushes changes until the ttl ends
```

- Before opening an end-to-end session to B, A looks B up through a home relay and subscribes. Path computation (§11.4) and hole punching (§11.7) use the result.
- A renews the subscription while the session is active and lets it lapse afterwards.
- Results are self-signed by the nodes they describe, so a relay can withhold them but not forge them.
- Relays rate-limit lookups and subscriptions per edge node. Lookups reveal nothing a relay doesn't already learn from circuit setups (§2).

#### 10.6.3 Sync rhythm at the edge

- **No 1-second polling.** Home relays **push** changes: new tree heads, offline-signed items, relay-graph changes, and subscribed records.
- The edge node piggybacks its digest on the **hop keepalive** it sends anyway every 2–5 s (§11.2), which also keeps NAT mappings open. A full digest exchange happens on reconnect and when a mobile app resumes.
- **Mobile background mode:** the keepalive interval stretches as far as the OS and NAT allow. Relays keep only the latest version of each pending item, so a phone that wakes up receives one batch of current state, not a backlog.

#### 10.6.4 Withholding by a home relay

A home relay can't forge state, but it could withhold updates (a freeze, §21.2):
- The edge node compares tree heads from **both** home relays. If one lags behind, it pulls from the other and flags the lagging relay.
- Tree-head expiry still applies (§21.2).
- If both home relays look stale, the node asks a third relay chosen at random.

#### 10.6.5 Gossip protocol floor

Every self-signed record (EndpointRecord, LinkStateAdvert, AttachmentRecord) carries `protocol`, the gossip protocol of the software that signed it (`webjet_core::protocol::GOSSIP_PROTOCOL`). Records from before the field have no `protocol` field (it reads as 0). For an EndpointRecord the protocol then comes from `software`: `webjetd/0.7.x` is protocol 1, anything older is 0. The protocol number goes up only when a release changes gossip or the records in a way older software can't handle. Patch releases normally keep it, so their rolling upgrades lose nothing.

A node ignores records from software below its floor (`MIN_GOSSIP_PROTOCOL`, currently 1, so 0.6.x and older are ignored):
- An EndpointRecord below the floor marks the node **outdated**. The node's endpoint, link-state and attachment records are removed, and later records without the field are refused as well. Outdated records aren't stored or forwarded, and aren't used for routing (§11.4), hole punching or display. The node keeps working as a tree-gossip peer, and its tree-head and Merkle traffic is unaffected. Only its soft state is ignored.
- An EndpointRecord at or above the floor with a higher `seq` clears the mark, for example after the node is upgraded.
- A LinkStateAdvert or AttachmentRecord without the field is used while its node's EndpointRecord is unknown or at or above the floor.

The `topology` control command reports each node's `software` version and whether it is `outdated`. webjet-app shows both in the Nodes tab.

### 10.7 Peer discovery and bootstrap

A node that has been offline for a long time may find that every address it remembers has changed. Identity is always checked by the hop handshake (§9.2), so every source below is only a **hint** for where to connect: a wrong hint can make a connection fail but can never make the node trust the wrong peer.

#### 10.7.1 Discovery order

1. **Cached relay endpoints.** Nodes persist the last known EndpointRecords of relays, even after they expire, as reconnection hints (§10.4).
2. **The seed list from the tree** (§6.14): admin-chosen stable relays or controllers, named by node name or key, with addresses given as public DNS hostnames or IPs. Hostnames let a seed change its IP without a tree update; a hijacked DNS answer only makes the connection fail, because the seed must still prove it is that node.
3. **The seed list from enrollment** (§8), for a node that has never synced.
4. **Controller enrollment endpoints,** as a last resort.

The node tries sources in order, several candidates in parallel, and stops at the first relay that completes a hop handshake. It then syncs, chooses its real home relays (§10.6), and continues normally.

#### 10.7.2 Managing seeds

- The seed list is part of the network configuration (`SetNetworkConfig`, admin-signed, §6.18); the committed list is a tree leaf (§6.14). A node's own configuration (§6.19) may add seeds it tries first, for example a nearby relay.
- **Validation:** every entry names an existing, non-tombstoned node with `RELAY` or `CONTROL`, and every address parses.
- **Warning:** fewer than 2 seeds, since one seed is a single point of failure for recovering nodes.

#### 10.7.3 Bootstrap mode for stale PSKs

If the PSK rotated while a node was offline, relays would drop it at the PSK gate (§9.1). To avoid that dead end:

- **Seed relays** (and controllers) accept every past PSK epoch at the gate.
- A hop session that passed the gate with an **old** epoch is in **bootstrap mode**. It may only:
  - sync tree state and offline-signed items
  - open a circuit to a controller, to fetch the current PSK (§7.6)
- It may not relay traffic, look up other nodes, or reach any other destination.
- Once the node has the current PSK, it reconnects normally.

An attacker who has an old PSK but no valid node key still can't get past the hop handshake, so the PSK keeps its anti-probing value.

---

## 11. Routing

### 11.1 Topology

```
DATA ─┬─ Relay A ── Relay B ── Relay C ─┬─ DATA
      └─ Relay D ───────────────────────┘
          (relay mesh: link-state)
```

- **RELAY nodes** form a mesh. They have public IPs, so they can all reach each other, and there are expected to be tens of them, so a full view of the mesh is cheap.
- **DATA nodes** don't route. Each one measures its links to a few relays and publishes an AttachmentRecord (§6.8).
- **A route** is: source → one of the source's relays → zero or more relays → one of the destination's relays → destination. A node that also holds `RELAY` is its own first or last relay (§4.1).
- **A direct route** between two nodes is another candidate with no relays. It exists when one side is publicly reachable, or when hole punching succeeds (§11.7).

### 11.2 Link measurement

- **Measure below the hop stream, from the traffic it carries.** A message written into a hop waits behind everything written before it (the hop queue, KCP's send buffer and pacer, or the TCP send buffer), so under load its round trip shows the sender's own backlog, not the path. Each transport is therefore measured underneath:
  - **UDP+KCP+FEC:** RTT from a new data segment leaving the socket to its acknowledgement arriving. Acknowledgements go outside FEC and the pacer, carrying how long the receiver held the acknowledged data; that time is subtracted. They go at once in their own datagrams (`RAW_ACK`), except that a lone small one waits up to 10 ms for a datagram that is going out anyway and rides in front of it (`SHARD_ACK`, to peers that say in their `STATS` they take it), so a keepalive's answer also acknowledges the keepalive. Retransmitted segments give no sample. Loss is the datagram loss of both directions before FEC recovery, which each end counts from shard-group gaps and reports to the other (§17.6).
  - **TCP+TLS and TCP+AnyTLS:** the kernel's smoothed RTT and its retransmitted share of what it sent (`TCP_INFO` on Linux, `TCP_CONNECTION_INFO` on macOS, `SIO_TCP_INFO` on Windows).
  - The figures are read every 2 s. On an idle link the keepalives are the traffic being measured, so no extra probe packets are needed either way.
- **Keepalives.** Only the end that dialed the hop sends them (flag `ONE_SIDED`): every 2 s for the hop's first 30 s, while it is lossy (over 1%) or after one went unanswered, otherwise every 5 s. The other end answers each and sends none of its own while they keep coming (it starts again if none came for 12 s, or none at all from a peer before 0.10.2). Both ends see the hop alive from the keepalive or its answer, and close it after 15 s of silence (`HOP_DEAD`). The answering end takes its clock offset (§18.6) from the keepalive's wall clock and the link's RTT, and its observed address (§11.7) from the keepalive (included every 12th); an edge node that answers sends its digest (§10.6) in the answer. Every keepalive carries a timestamp and sequence number; their round trips are the link's measurement only until the transport has given an RTT (a peer before 0.9, or a platform without TCP statistics); after that they only show the link is alive (§10.5).
- **Measure per transport.** KCP+FEC, AnyTLS and plain TLS between the same two nodes can behave very differently, especially under loss. Each eligible transport is measured separately, and each node sends on the cheapest one (§9.6). Adverts carry that selected transport and its cost.
- **Smooth and quantize.** Use an EWMA for RTT and loss, and round values before advertising them so small fluctuations never trigger an update.
- **Cost function:** `cost = rtt_ms × (1 + k × loss_fraction)`, with k ≈ 10 as a starting point. Loss hurts tunnelled TCP far more than latency does. Path cost additionally includes a load penalty for the relays on the path (§11.8.2).
- **Both directions must agree.** A relay-to-relay link is used only if both ends advertise it, and its cost is the higher of the two advertised costs.

### 11.3 Link-state distribution

- Each RELAY floods its LinkStateAdvert (§6.7); each DATA node publishes its AttachmentRecord (§6.8). Both are signed by the node they describe.
- **Periodic refresh:**
  - LinkStateAdverts: every **minute**, expiring after 5. They are pushed to every edge node (§10.6.1), so they are most of an idle node's control traffic (§18.3).
  - AttachmentRecords: every 10 s, expiring after 30 s. They stay within the core and are fetched on demand.
- **Triggered update:** when a link's RTT changes by more than about 10%, its loss by more than 2 points, or a link goes up or down; checked every 2 s.
- **Rate limit:** at most one advert per origin every ~2 s.
- **Deduplicate** by `(origin, seq)` and forward only newer sequence numbers.
- **Dead relays disappear in seconds, not at expiry.** A relay removes a peer from its `links` as soon as its hop sessions to that peer time out, and sends a triggered update. A link counts only if both ends advertise it (§11.2), so every link of a dead relay vanishes from the graph once its neighbors have noticed.
- **Expiry:** an advert that isn't refreshed expires, as a backstop.
- **Validation:** discard adverts from nodes without `RELAY` (for LinkStateAdverts), from tombstoned nodes, or with bad signatures.
- These records use the same gossip transport as the node list but a **separate channel**. They are not part of the tree and are not signed by any controller.

### 11.4 Path computation and selection (source routing)

1. The source builds a graph from all valid LinkStateAdverts and AttachmentRecords and computes the **k best paths** to the destination (Yen's algorithm), with at most **3 relays** per path.
2. It opens circuits on the top candidates.
3. It uses the circuit with the best **cost**: the sum of the measured costs of its links (§11.2), its own first hop live and the others as their ends advertise them (relay links, and the destination's attachment). The busier a circuit, the more its own traffic would distort anything measured through it; the link figures don't include that backlog, so a loaded circuit isn't mistaken for a bad one and abandoned for an idle one. No load penalty applies to an established circuit (§11.8.3), except that a full relay multiplies its cost by 4. Until all of a circuit's links are known, its end-to-end probes give its cost.
   - **End-to-end probes** (`PROBE`/`PROBE_ACK`, §9.4.3) go only over circuits of a session used in the last minute (probes themselves don't count as use) that haven't carried at least 3 session frames each way in the last second. On an idle circuit they show it is alive; on a busy one the traffic shows that, and a probe would only measure the queue in front of it.
   - **Who probes, how often.** The circuit's source probes for both ends: once a second until 3 probes have been answered, after a probe goes unanswered (retried every second), then every 5 s on the circuit the session uses and every 15 s on a backup. Each probe echoes the last answer it got (`echo_us` and how long it was held), so the destination measures the round trip too and sends no probes of its own; it starts probing again if it hears nothing on the circuit for 20 s, and probes in the old format while the source is a node before 0.10.2 (whose probes carry a `route_id`). A circuit whose probe goes unanswered for 3 s with nothing else received meanwhile is unusable (infinite cost) until something comes back, and one whose probes keep failing is closed. A hop that goes down closes its circuits at once (§11.6), so the probe rate bounds only how long a circuit that silently stops passing traffic is used.
4. It keeps **one or two backup paths** open with light probing, for fast failover. Every 30 s an active session also opens a **trial circuit** on the best candidate it hasn't tried in the last 5 minutes; once its probes have answered, the worst measured circuit beyond two (never the one in use) is closed. A new or improved relay therefore gets measured, and used when it is better, within a minute or so.
5. **Hysteresis:** switch paths only if the new one is better by more than 15–20% and stays better for several seconds. This prevents flapping between near-equal paths, which causes packet reordering for tunnelled TCP.
6. **Spreading:** among candidates within 10% of the best cost, the source picks at random, weighted by spare capacity, rather than always the single best (§11.8.3).

### 11.5 Circuits and forwarding

**Route identity:**

```
route_id = BLAKE3-derived(src_node_id || dst_node_id || [hop_1_relay, hop_2_relay, ...])   // §15.4
```

A direct route has an empty relay list. The same path always gives the same `route_id`, so accounting (§12) adds up across circuit rebuilds. The transport of each hop is not part of the ID.

**Circuit setup:**

```
CircuitSetup {
    route_id: [u8; 32]
    src:      node_id
    dst:      node_id
    hops:     [node_id]          // relays in order
    nonce:    [u8; 16]
    issued_at: Timestamp
}
signed by: src's identity key
```

- The setup travels hop by hop. Each relay checks that:
  - the source's signature is valid, and the source has no tombstone
  - it holds `RELAY` itself and appears in `hops`
  - the next hop is valid (a relay with `RELAY`, or the destination)
  - the source is within its per-source circuit limit
  - the policy allows some traffic between `src` and `dst`, in either direction (**circuit admission**, §14.4)
- Each relay allocates a short local **circuit ID** for its inbound hop, like an MPLS label, and records the `route_id`, `src` and `dst` for accounting.
- A circuit ID is scoped to the **neighbor node**, not to one transport session. Frames for a circuit are accepted on any hop session with that neighbor, so a hop can change transport (§9.6) without rebuilding the circuit.
- The destination completes the end-to-end handshake (§9.4) through the circuit.

**Data frames:**

```
RelayFrame {
    circuit_id: u32
    hop_limit:  u6          // defense against forwarding bugs
    ecn:        u2          // congestion marking; shares one byte with hop_limit (§17.7)
    payload:    opaque       // end-to-end ciphertext
}
```

Relays rewrite `circuit_id` for the next hop, decrement `hop_limit`, may set the congestion mark in `ecn` (§17.7), and never inspect `payload`. The header stays 5 bytes.

### 11.6 Relay protection

- Only authenticated, non-tombstoned nodes may set up circuits, and only between node pairs the policy lets talk at all (circuit admission, §14.4).
- Each relay rate-limits circuits and bandwidth **per source**, using the same per-route counters as accounting (§12.3), so enforcement and accounting never disagree. Limits and defaults are in §16.2.

### 11.7 NAT traversal (hole punching)

DATA nodes behind NAT try to establish direct routes to each other. Relays make this possible, because they have public IPs.

**1. Learning reflexive addresses.**
- Every hop keepalive from a relay to a node carries an `observed_addr` field: the source address and port the relay saw the node's packets come from. It travels inside the authenticated hop session, so it can't be spoofed off-path.
- A node compares the observed address across two or more relays:
  - the same address and port from different relays: the NAT maps consistently, so hole punching is likely to work
  - different ports from different relays: symmetric NAT; hole punching works only if the other side's NAT maps consistently
- The node publishes its `HOST` and `REFLEXIVE` addresses and its NAT type in its EndpointRecord (§6.2).

**Candidates.** In this order: a port mapping the node got from its router (PCP / NAT-PMP, then UPnP IGD; only when the mapping has a public address), `PUBLIC` addresses, `REFLEXIVE` addresses, then `HOST` addresses (public ones before LAN ones), at most 12. **Another VPN is not a direct path:** addresses of tunnel interfaces (point-to-point interfaces and well-known VPN interface names such as `wg*`, `utun*`, `tailscale*`) are not offered, a relay observation made through a tunnel doesn't count, and a peer candidate the system would reach through a tunnel interface is not dialed, unless the default route goes through that interface too (a full-tunnel VPN). Operators can add or allow interfaces and exclude prefixes (`[nat]` in webjetd.toml). The overlay's own pool is never a candidate.

**2. Coordination** through the already-established end-to-end session over the relayed route:
1. A sends `PUNCH_OFFER { candidates, nonce }` to B.
2. B replies with its own `PUNCH_OFFER` (same nonce).
3. The initiator sends `PUNCH_GO`. It carries no timestamp, because two nodes' clocks are rarely within the tens of milliseconds this needs.
4. The responder starts its connectivity checks as soon as `PUNCH_GO` arrives. The initiator starts **half a round trip after sending it**, using the end-to-end RTT it already measures (§9.4.3), so both sides start at about the same moment.

These messages are encrypted and authenticated end to end, so relays can't read or alter the candidates.

**3. Connectivity checks** (as in ICE). Each side sends a check (a PUNCH datagram with type PING and the nonce, under the PSK gate) to every candidate of the other, every 50 ms for the first second and every 200 ms up to 6 s. A PING that arrives is answered with a PONG to the address it came from (rate-limited, so a replayed PING can't make a node a reflector).
- A PING from an address the peer never offered is a **peer-reflexive** candidate: the peer's NAT gave this flow a new port. It is checked too.
- **Port prediction:** when the peer's NAT is symmetric and ours is not, we also check the ports just after (96) and before (8) the peer's public reflexive ports, for 3 s; many symmetric NATs hand out ports in sequence. Two symmetric NATs: no attempt; the pair stays relayed.
- **Nomination:** the first address that answers with a PONG is reachable both ways. The lower node ID dials it at once; the higher one 1.5 s later if no hop came up. When no check is ever answered (a peer from before checks were answered), the lower ID dials all candidates at once at the end of the window.

**4. Establishing the direct hop.**
- The dial is a normal **UDP + KCP + FEC + TLS** hop through the mappings the checks opened: its first packets carry the PSK-gate MAC (§9.1), and the normal hop handshake (§9.2) authenticates both sides.
- Once the hop is up, the source sends a CircuitSetup with an empty `hops` list over it, and the direct route becomes a candidate in path selection (§11.4). With hysteresis satisfied, the session moves over without renegotiating (§9.4.1).

**5. Keeping it alive.**
- Keepalives on the direct hop keep the NAT mapping open.
- If the direct hop fails, traffic falls back to the relayed route, which stays open as a backup, and punching starts again.

**Rules:**
- **UDP only.** TCP simultaneous open through NAT is unreliable, so TCP+TLS and AnyTLS are used only toward `PUBLIC` addresses.
- **Either side may start.** The lower node ID starts first; the higher one starts 5 s after it would have, so a pair still punches when only one side sees traffic. Simultaneous offers resolve to the lower ID's attempt.
- **Retry** while the session is in use: after 15 s, doubling to 5 min; immediately when either side's EndpointRecord changes or the direct hop goes down. Success resets the backoff.
- A direct route between two DATA nodes is not relaying, so it doesn't need `RELAY`. Its `route_id` has an empty relay list (§11.5), and accounting treats it like any other route.

### 11.8 Load-aware routing

Without a load signal, every source picks the same best relay until it saturates, its loss rises, and then everyone moves to the next relay together. Relays therefore advertise their load, path cost accounts for it, and several dampers keep traffic from swinging back and forth.

#### 11.8.1 Load advertisement

Each relay adds a `load` section to its LinkStateAdvert (§6.7), plus `util_pct` per link:

- **Relay load** `L` = the highest of `util_pct`, `cpu_pct` and `circuits_pct`; whichever resource runs out first is the one that matters.
- **Smoothed and quantized:** each value is a 30-second average, rounded to 10% steps. A load change triggers an advert only when it crosses a step, and at most every 10 s, so load doesn't flood the mesh.
- **Capacity:** **auto-estimated by default** from the highest throughput the relay has sustained and the bandwidth estimates of its KCP hops (§17.5). A value in the relay's node configuration (§6.19) takes precedence, and admins can also set it per tag through the Limits leaf (`relay_capacity_mbps`, §16.4).

#### 11.8.2 Cost with load

```
link_cost  = rtt_ms × (1 + k × loss)                     // §11.2
penalty(L) = 1                              if L < 50%
           = 1 + 3 × ((L − 50) / 50)²       if 50% ≤ L < 90%
path_cost  = Σ link_cost × max penalty(L) over the relays on the path
```

- Below 50% load nothing changes, so lightly used relays still compete on RTT and loss alone.
- The penalty rises steeply as a relay fills, the shape queueing delay has in practice.
- **At 90% load or above a relay is full:** it is excluded from new paths and refuses new circuits (§11.8.4).

#### 11.8.3 Preventing herding and oscillation

1. **Load affects only new choices.** An established circuit doesn't move because a relay got busier. It moves only if the relay becomes full, or its measured end-to-end quality degrades past the normal hysteresis (§11.4).
2. **Randomized choice among near-equal paths.** Candidates within 10% of the best cost are picked at random, weighted by spare capacity (`100 − L`), which spreads new circuits across relays without coordination.
3. **Jittered re-evaluation.** Each source re-checks its paths at randomized times, so sources don't all react in the same second.
4. **Measured performance still decides** (§11.4). Advertised load only ranks candidates; real congestion on a link shows up in its measured RTT and loss, which every end advertises.

#### 11.8.4 Admission control

- At **90% load or above**, a relay refuses new CircuitSetups with the reason `overloaded`. The source immediately tries its next candidate.
- Existing circuits continue, sharing bandwidth fairly per source (§16.2).
- Refusals are counted in `circuits_refused` by reason (§12.3), so admins can see when more relay capacity is needed.

#### 11.8.5 Gateways

Gateways serving the same published prefix (§11.9.3) report `gateway_load` in their serving status (§6.2), computed like relay load. Clients apply the same penalty, randomized choice and "existing connections stay put" rule when choosing among them.

#### 11.8.6 Trust

Load is self-reported:
- **Claiming high load** only sheds traffic, which harms nobody.
- **Claiming low load** attracts traffic. It gains the relay only metadata it would see anyway, and is limited by end-to-end measurement (overloaded paths measure badly) and by accounting, which compares advertised utilization with the bytes the relay reports relaying (§12.7).

### 11.9 Subnet routes (gateways)

A node can make a LAN behind it reachable from the overlay. That node is the LAN's **gateway**. Exit nodes (routing internet traffic) are not supported.

A gateway is different from a relay: a relay forwards opaque circuits and never sees content, while a gateway is the **endpoint** of the end-to-end session. It decrypts packets and forwards them as ordinary IP onto its LAN. A gateway needs neither `RELAY` nor a public IP.

#### 11.9.1 Route grants and prefix mapping

Admins grant routes in the NodeRecord (§6.1):

```
RouteGrant {
    lan:        Cidr    // the real LAN prefix behind the gateway, e.g. 192.168.1.0/24
    published:  Cidr    // the prefix overlay nodes use, e.g. 10.2.2.0/24
}
```

- **Unmapped route:** `published == lan`. Overlay nodes reach `192.168.1.x` directly.
- **Mapped route:** `published != lan`, with the **same address family and prefix length**. The gateway translates 1:1, keeping the host bits: `10.2.2.17` ↔ `192.168.1.17`. This lets many sites that all use `192.168.1.0/24` each be published under a unique prefix.

#### 11.9.2 Rules

**Granting** (admin only, through `UpdateNode`; owners can't grant routes to their own nodes):
- Prefixes are canonical (host bits zero), and `/0` is never allowed.
- `published` prefixes must not overlap the overlay IP pool or any node's `overlay_ips`.
- `published` prefixes of different grants must not overlap, **except** that the identical grant (same `lan` and `published`) may be given to several gateways for high availability.
- `lan` prefixes are only meaningful on their own gateway, so they may overlap freely across gateways; that is what mapping is for.

**Serving** (self-signed soft state, in the EndpointRecord's `serving`, §6.2):
- A gateway serves a grant only if its **local configuration** enables it and the grant exists. It lists the published prefixes it serves.
- It **withdraws** a prefix when its LAN interface goes down or the LAN is unreachable, and the record expires on its own if the gateway goes offline. Clients never send traffic into a gateway that isn't serving.
- `serving` must be a subset of the node's grants; peers ignore anything else.

#### 11.9.3 Client-side routing

Each node builds its routing table from the tree and the serving status:

| Destination | Goes to |
|---|---|
| A node's overlay IP | That node |
| An address in a published prefix | A gateway currently serving that prefix (longest-prefix match first) |
| Anything else | Not routed into the overlay |

- **Several gateways for one prefix:** pick by measured end-to-end cost and gateway load (§11.8.5), with the same hysteresis as path selection (§11.4). Fail over when the gateway stops serving or becomes unreachable. Failover breaks existing connections, because each gateway keeps its own SNAT state (§11.9.4).
- **Clash with the client's own LAN:** if a published prefix overlaps a network the client is directly connected to, the client's local network wins, the overlay route is skipped, and the client shows a warning. The admin fixes this by mapping the remote LAN to a different published prefix.

#### 11.9.4 Data path at the gateway

**Outbound (overlay → LAN):**
1. Decrypt the frame; the source node is authenticated by the end-to-end session.
2. Check that the destination is in a published prefix the gateway is serving.
3. Check the policy (§14.4). The gateway is the authoritative enforcement point for subnet traffic.
4. **Destination translation** (mapped routes only): rewrite the published address to the LAN address.
5. **SNAT, always:** rewrite the source to the gateway's own address on that LAN, allocating a port per flow.
6. Forward onto the LAN, and track the flow.

**Return (LAN → overlay):**
1. Match the reply against the flow table; anything that doesn't match a tracked flow is dropped.
2. Reverse the SNAT (destination becomes the original overlay node's IP), and for mapped routes rewrite the source from the LAN address to the published one.
3. Send it back to the originating node in its end-to-end session.

**Consequences of always-on SNAT:**
- LAN hosts need no configuration and no route back to the overlay.
- LAN hosts see every overlay user as the gateway's address; who actually connected is recorded on the gateway (§12.3).
- **Connections can only be started from the overlay side.** LAN hosts cannot start connections into the overlay.

**Translation details:**
- Checksums are updated incrementally for IPv4, TCP, UDP and ICMP.
- ICMP errors coming back from the LAN contain the original packet's header; the gateway translates that embedded header too, so path MTU discovery and "port unreachable" still work.
- **No application-level translation.** Protocols that carry IP addresses inside their payload (active FTP, SIP and similar) may not work through a mapped route.
- **DNS:** a LAN's own DNS server answers with LAN addresses (`192.168.1.x`), which are not reachable from the overlay when the route is mapped. Overlay DNS rewrites those answers to published addresses (§11.10.5).
- **Limits:** per-source caps on SNAT ports and tracked flows, so one overlay node can't exhaust the gateway's table (§16.2).

### 11.10 Overlay DNS and magic DNS

Every node runs its own **local resolver** inside the agent. It answers from the synced network tree, so names resolve even when no controller is reachable, and a rename takes effect as soon as the new tree head arrives.

#### 11.10.1 The local resolver

- **Address:** `resolver_ip` in the DnsConfig (§6.13) is a reserved address from the overlay pool (one IPv4 and optionally one IPv6). The state machine never assigns it to a node.
- **Local only:** packets from the local host to `resolver_ip` are captured by the agent and answered on the spot; they never leave the node. Packets addressed to `resolver_ip` that arrive from the network are dropped, so no node can query another node's resolver.
- **System integration (split DNS):** the agent sends only overlay names to its resolver, and leaves every other query with the system's existing DNS:
  - Linux: per-link DNS domains with systemd-resolved
  - macOS: per-domain resolver configuration
  - Windows: Name Resolution Policy Table (NRPT) rules
  - Where split DNS isn't available, the agent becomes the system resolver and forwards every other query to the original upstream servers unchanged.
- The magic DNS suffix, every `records` zone and every `forward` zone are routed to the local resolver.

#### 11.10.2 Magic DNS: automatic node names

| Query | Answer |
|---|---|
| `<node-name>.<suffix>` A / AAAA | The node's `overlay_ips` |
| PTR for an overlay IP | `<node-name>.<suffix>` |
| Any other name under `<suffix>` | Admin `records` (§11.10.3), otherwise NXDOMAIN |

- Built from the tree: only valid, non-tombstoned nodes with a valid owner (§13.4) appear, and node names are already valid DNS labels (`[a-z0-9-]{1,32}`).
- **TTL 60 s**, because owners can rename their nodes (§13.3).
- **Suffix:** configurable in the DnsConfig, **defaulting to `internal`**, a top-level domain reserved for private use, so it can never collide with a real public name. A domain the organization controls (for example `webjet.example.com`) also works. Never use a made-up public-looking TLD, which could collide with a real one later. Changing the suffix renames every node at once, so do it rarely.
- Answers are not filtered by policy. Every node already holds the whole tree, so hiding names would not hide anything; access is controlled by the policy (§14), not by name resolution.

#### 11.10.3 Overlay records

Admins add records in the DnsConfig:

```yaml
records:
  - { name: db.prod.internal,     type: CNAME, value: node:pg-01 }
  - { name: grafana.internal,     type: A,     value: 10.7.0.40 }
  - { name: nas.office.internal,  type: A,     value: 10.2.2.20 }   # a mapped subnet host
  - { name: _ldap._tcp.internal,  type: SRV,   value: "0 0 389 dc-01.internal" }
```

- `value: node:<name>` or `node:<base64 key>` points at a node and follows its current overlay IPs. The key form keeps pointing at the same machine even if it's renamed.
- Addresses must be overlay IPs or addresses inside **published** subnet prefixes.
- A record may not shadow a magic DNS node name; validation rejects that (§11.10.6).

#### 11.10.4 Forwarded zones (split DNS)

A forward zone sends queries for a private domain to DNS servers reachable through the overlay, typically a LAN's own DNS server behind a gateway:

```yaml
forward:
  - zone: corp.example.com
    servers: [10.2.2.53]                 # the office DNS server, at its published address
    rewrite:
      - { lan: 192.168.1.0/24, published: 10.2.2.0/24 }
```

- The local resolver sends the query over the overlay like any other traffic: through a gateway serving the server's prefix, or to a node.
- **Those queries are subject to the policy.** The querying node needs a rule allowing `udp:53` and `tcp:53` to the server. If the policy denies it, the zone simply doesn't resolve for that node.
- Servers are tried in order, with a short timeout. Answers are cached for their TTL.

#### 11.10.5 Rewriting answers for mapped subnet routes

A LAN's DNS server answers with LAN addresses (`192.168.1.20`), which aren't reachable when the route is mapped (§11.9.4). For a forward zone with `rewrite` grants, the local resolver translates answers before returning them:

- **A / AAAA records** inside a grant's `lan` prefix are rewritten to the `published` prefix, keeping host bits: `192.168.1.20` → `10.2.2.20`.
- Addresses outside every listed `lan` prefix pass through unchanged.
- **Reverse lookups:** PTR queries for the published prefix are translated to the LAN prefix, sent to the zone's servers, and the answer is returned for the original query.
- **DNSSEC:** rewritten answers can't validate. The local resolver doesn't validate DNSSEC for rewritten zones and clears the AD bit; it is trusted because it runs on the same host.
- Each `rewrite` grant must match a real RouteGrant that exists in the tree; validation checks this (§11.10.6).

#### 11.10.6 Configuration and validation

- The DnsConfig is part of the network configuration (`SetNetworkConfig`, admin-signed, §6.18), the tree's DNS leaf (§6.13), synced and authenticated like the policy. A node's own configuration (§6.19) may add records and forwarded zones that only its resolver answers; they are validated the same way, against the network's suffix and zones.
- **Validation before commit:**
  - `suffix` and every record name are valid DNS names; record names fall within `suffix` or an explicitly listed zone
  - `resolver_ip` is in the overlay pool and not assigned to any node
  - no record shadows a magic DNS node name
  - addresses are overlay IPs or inside published prefixes
  - `rewrite` grants match existing RouteGrants
  - no forward zone covers `suffix` or any name under it
- **Warnings:** `node:` references that match no node, and forward servers that no current policy rule lets anyone reach.
- **Soft mode:** with no controller reachable, nodes keep the last DnsConfig, and magic DNS still follows the tree.

### 11.11 Reverse proxy ports

A Linux data node can listen on TCP or UDP ports for clients outside the overlay and forward each flow to a port of another node, of a set of nodes, or of an address behind a gateway. That node is the rule's **ingress**. Rules are part of the ingress's node configuration (§6.19), `[[proxy]]` entries in `webjetctl local config`:

```toml
[[proxy]]
name = "web"              # unique on the node; labels flows and metrics
protocol = "tcp"          # tcp | udp
listen_port = 8080
target = ["tag:web"]      # one address, or selectors (policy syntax, no cidr:)
target_port = 80
real_ip = true            # keep the client's address (default)
```

The controllers check rules when the configuration is set: at most 64 rules, unique names, one rule per protocol and listen port, non-zero ports, a target that is either exactly one unicast address or selectors. Only nodes with the `data` role may have rules.

**Capture (ingress).** The agent adds iptables chains `WEBJET-PROXY` (nat PREROUTING: `DNAT` each listen port to the *proxy address*; filter FORWARD: accept to and from it; mangle FORWARD: clamp the TCP MSS to the overlay MTU). The proxy address is the overlay resolver address of each family (§11.10.1): routed into the tun interface and held by no node. The kernel forwards the client's packet into the tun interface with the client's own address as its source; the agent recognises it (destination = proxy address, foreign source, a listen port), picks a target and rewrites the destination to `target:target_port`. Replies come back the same way and the kernel's conntrack undoes the DNAT. Packets to the listen ports from the ingress host itself are not captured (only PREROUTING).

**Target choice.** An address target goes to the node holding it, or to the gateway serving it (§11.9.3). Selectors pick the valid data nodes (not the ingress) with an address of the client's family; rendezvous hashing over the client's address picks one, so a client stays with its node while that node stays a candidate. Only nodes whose EndpointRecord lists the feature `proxy` (webjetd with this support) are used.

**Client addresses.** With `real_ip` the packet keeps the client's address as its source, so the target's applications see it. The target must agree: `[proxy] accept_real_ip = true` in its webjetd.toml, which makes the agent mark connections that arrive on the tun interface from outside the overlay pool (mangle `WEBJET-REALIP`, connmark `0x574a0000/0xffff0000`), copy the mark to their reply packets (`WEBJET-REALIP-OUT` in OUTPUT and in PREROUTING of other interfaces, for containers), route marked packets through table 22346 (`default dev <tun>`) and loosen `rp_filter` on the tun interface. Once that works the node advertises the feature `proxy-real-ip`. For a target without it, and for any rule with `real_ip = false`, the ingress translates the source to its own overlay address and a port from 61000–65535 (above Linux's ephemeral range), and the target sees the ingress.

A UDP server on a wildcard address (`0.0.0.0`, as game servers usually are) doesn't answer from the address the datagram came to: the kernel picks each reply's source by its route to the client, through another interface, and the reply leaves from that interface's address in a kernel connection of its own that never got the mark. So for each new real-IP UDP flow to one of its own addresses, the target adds an `ip rule` (priority 22345: locally sent, UDP, from the flow's port to the client's address and port, lookup table 22346) before it writes the flow's first packet to the tun interface; the reply then routes into the tun and takes the overlay address. The rule goes when the flow does (swept every 10 s), at most 1024 flows have one, and all go with the other rules at shutdown. It needs Linux 4.17 (`ipproto`/`sport`/`dport` in `ip rule`); without it the agent warns once. TCP needs none of this: a TCP reply always leaves from the connection's own address.

An address behind a gateway never gets the client's address: the LAN host would send its replies to its own default router, not back through the gateway, and making that work needs routing changes on the LAN. The ingress translates the source for such targets, and the rule shows a warning (and the `proxy_rule` alarm) while `real_ip` is set. The gateway then masquerades as for any overlay flow (§11.9.4).

**Policy.** A proxied flow is a flow from the ingress: the ingress needs a policy rule allowing it the target and `target_port` (checked when the flow starts, as for its own traffic), and the target checks the same (§14.3), plus that a rule of the ingress points at it with this protocol and port. A target refuses real client addresses unless it accepts them, refuses addresses in the overlay pool or a published prefix as client addresses (no ingress can speak for other nodes), and refuses real client addresses towards a LAN it serves. Flows are re-checked when the tree changes, like other tracked flows.

**Traffic.** Proxied packets travel in end-to-end frames of type `PROXY` (9), not `DATA`, over the ingress's session with the target. Both ends keep proxy flows in their own connection tracking table (the same state machine and timeouts as §14.4; `conntrack_global`, `conntrack_new_per_sec`, `snat_*` limits apply to it separately), and count them apart from overlay traffic: they are not in `tun_rx`/`tun_tx`, `conntrack`, rule hits or the Connections tab's overlay flows. The control call `proxy` (`webjetctl local proxy`) lists the rules with their status and warnings, the flows on each side and the counters; metric reports carry them as `ProxyMetrics` (§12.5).

**Fragments.** Datagrams larger than the tun MTU (game servers' UDP, for one) reach the agent as IP fragments, and only the first fragment carries the ports a flow is found by. Wherever a first fragment of a proxy flow passes (client → ingress, ingress → target, target's reply, reply → client), the agent remembers the datagram (where it came from, protocol, addresses, fragment id) with where it sent it and the addresses it gave it; the later fragments of that datagram follow it with the same addresses, for up to 30 s, at most 8192 datagrams per node. The rewritten first fragment's UDP/TCP checksum is updated for the changed addresses and ports, since it covers the whole datagram. A later fragment whose first fragment didn't come this way is dropped.

**Limits.**
- Linux only, with the tun interface, on both the ingress and real-IP targets. Other platforms keep the rules but don't listen (alarm `proxy_unsupported`).
- An IPv4 client reaches IPv4 targets only, likewise IPv6; a rule whose target has no address of a family the overlay pool has doesn't serve those clients.
- The ingress's own host doesn't reach its listen ports (no OUTPUT capture); other overlay nodes don't either (their packets to the ingress's overlay address go through the overlay's policy as usual).
- Real client addresses go only to nodes. A target with real addresses routes every reply of a connection it marked back into the overlay, whatever its routing table says.
- Old nodes (without the `proxy` feature) aren't chosen as targets; old controllers drop the `proxy` field of a node configuration they re-encode, so upgrade the controllers first.

---

## 12. Traffic Accounting & Metrics

### 12.1 Counting unit

Every node on a route counts **inner frame bytes**: the end-to-end encrypted frame, which is the same size at every hop. Numbers along one path are then directly comparable.

Transport overhead (TLS records, KCP headers, FEC parity) differs per hop and is counted separately on **link counters**, keyed by `(peer, transport)` rather than by route.

```
 DATA A ──hop1──> Relay R1 ──hop2──> Relay R2 ──hop3──> DATA B
   │                 │                  │                  │
 route: sent      route: relayed     route: relayed     route: received
 link: wire tx    link: wire rx/tx   link: wire rx/tx   link: wire rx
```

### 12.2 Counter semantics

- All counters are **monotonic u64**, never per-interval deltas. A lost or late report loses nothing, because the next one has the full totals; rates are computed by the collector.
- Every report carries a `boot_id` (random per process start) so the collector can tell a counter reset from wraparound or bad data.
- Byte and frame counters are kept **per direction**: `fwd` (src→dst) and `rev` (dst→src).

### 12.3 What is counted

**Per route**, at every node on the route (source, each relay, destination):

| Counter | Type | Notes |
|---|---|---|
| `frames`, `bytes` | monotonic, per direction | inner frame bytes |
| `dropped_frames` | monotonic, by reason | `queue_full`, `aqm`, `rate_limited`, `no_circuit`, `hop_limit`, `acl_denied`, `conntrack_full` |
| `ecn_marked_frames` | monotonic | frames marked by the hop queue instead of dropped (§17.7) |
| `circuit_setups` | monotonic | rebuilds of the route; shows flapping |
| `active_since` | timestamp | when the current circuit came up |

**Per route, source only:**

| Metric | Type | Notes |
|---|---|---|
| `e2e_rtt_ms`, `e2e_loss_pct` | gauge (EWMA) | end-to-end probe results; probes go only while the circuit carries little traffic (§11.4) |
| `selected` | gauge | 0 idle, 1 primary, 2 backup |
| `switches` | monotonic | how often the session to the route's destination moved its traffic to another circuit |

**Per link**, keyed by `(peer, transport)`:

| Counter | Type | Notes |
|---|---|---|
| `wire_bytes_tx`, `wire_bytes_rx` | monotonic | actual bytes on the socket |
| `payload_bytes_tx`, `payload_bytes_rx` | monotonic | inner frame bytes carried |
| `fec_parity_bytes_tx` | monotonic | KCP links only |
| `kcp_retrans` | monotonic | KCP links only: data segments sent again (after a timeout or a fast resend) |
| `fec_recovered_packets` | monotonic | KCP links only: packets rebuilt from parity |
| `fec_ratio_pct`, `bw_estimate_mbps` | gauge | KCP links only: current parity ratio and bandwidth estimate (§17.5, §17.6) |
| `queue_delay_ms` | gauge | time frames spend in the hop queue (§17.2) |
| `rtt_ms`, `loss_pct` | gauge | the same values that feed link-state adverts |

Wire bytes divided by payload bytes gives each link's **overhead ratio**, showing the real cost of FEC and TLS.

**Per node**, the tun interface:

| Counter | Type | Notes |
|---|---|---|
| `tun_rx_packets`, `tun_rx_bytes` | monotonic | overlay packets read from the interface: what this host (or a gateway's LAN) sent into the overlay |
| `tun_tx_packets`, `tun_tx_bytes` | monotonic | overlay packets written to the interface: what the overlay delivered here; reverse proxy traffic is counted apart (§11.11) |

**Per policy rule**, at every node that enforces policy:

| Counter | Type | Notes |
|---|---|---|
| `rule_hits` | monotonic, by `rule_id` and decision | new flows allowed or denied by each rule (or the default) |
| `circuits_refused` | monotonic, by reason | relays only: circuit setups refused, by `policy` (circuit admission, §14.4), `overloaded` (§11.8.4) or `quota` (per-source limits, §16.2) |

**Per gateway** (§11.9), keyed by `(source node, published prefix)`:

| Counter | Type | Notes |
|---|---|---|
| `egress_bytes`, `egress_flows` | monotonic, per direction | traffic each overlay node sent into each served LAN |
| `snat_ports_in_use` | gauge | current SNAT port usage, to spot exhaustion |
| `snat_exhausted` | monotonic | flows refused because a per-source or global limit was hit |

### 12.4 On-node collection

- **Hot path:** each circuit holds per-thread counters updated with relaxed atomic increments. No locks and no map lookups per packet; the circuit struct points directly at its counters.
- **Aggregation tick (every 10 s):** a background task sums per-thread counters into a per-route snapshot.
- **On circuit close:** the final values are flushed immediately so short-lived flows aren't lost.
- **Cardinality cap on relays:** full detail for the top N routes by bytes (for example 1,000); the rest fold into one aggregate entry per `(src, dst)` pair.

### 12.5 Reporting

```
MetricReport {
    node_id:     [u8; 32]
    boot_id:     [u8; 16]
    software:    String         // node software version (for upgrade tracking, §15.7)
    report_seq:  u64            // monotonic per boot
    taken_at:    Timestamp
    routes: [{
        route_id, src, dst, hops: [node_id],
        role:     SOURCE | RELAY | DEST
        fwd: { frames, bytes }, rev: { frames, bytes },
        dropped:  { reason → frames },
        circuit_setups,
        e2e: { rtt_ms, loss_pct, selected, switches }?   // source only
    }]
    links: [{ peer, transport, wire_tx, wire_rx, payload_tx, payload_rx,
              fec_parity_tx?, kcp_retrans?, fec_recovered?, fec_ratio_pct?,
              bw_estimate_mbps?, queue_delay_ms, rtt_ms, loss_pct }]
    policy: { version, rule_hits: { (rule_id, decision) → flows },
              circuits_refused? }
    limit_hits: { (limit_name, peer) → count }      // §16.5
    alarms: [{ name, severity, since }]             // currently active alarms (§19.7)
    proxy: [{ rule, ingress: bool, node,            // reverse proxy traffic (§11.11),
              flows, active, refused,               // apart from routes/links/policy;
              to_target_{packets,bytes},            // exported as webjet_proxy_*
              to_client_{packets,bytes} }]
    compression: [{ plane: control | data,          // §9.8; webjet_compression_*
                    tx_{messages,raw_bytes,wire_bytes,skipped},
                    rx_{messages,raw_bytes,wire_bytes,errors} }]
    tun: { rx_packets, rx_bytes,                    // overlay packets through the tun
           tx_packets, tx_bytes }?                  // interface; webjet_tun_*
}
signed by: node identity key
```

- **Push every 60 s to the nearest controller** (lowest-cost route), over the normal routed data path to its overlay IP. If it is unreachable, try the next controller.
- Metric reports are **not** Raft operations. They never enter the controller log.
- Reports go only to controllers; they are never gossiped across the mesh.
- **Buffer while no controller is reachable:** a bounded on-disk ring (for example 24 h or about 50 MB), uploaded in `report_seq` order when a controller returns. If the ring overflows, time detail is lost but totals are not, because counters are cumulative.
- **Local endpoint:** each node may serve the same data as Prometheus/OpenMetrics on localhost for debugging. Relays must not use `route_id` as a label locally; per-route data is exported only through reports.

#### 12.5.1 Storage

Each controller verifies the signature of every report it receives and writes it into a **shared Prometheus-compatible time-series database** (Prometheus itself, or a compatible store such as VictoriaMetrics), using remote-write.

- **Where the store lives:** on one chosen `CONTROL` node (typically `CONTROL+DATA`), listening only on its overlay IP (§4.1). The other controllers remote-write to it. Remote-write queues on each controller absorb short outages of the store. The store is not part of the Raft state; losing it loses metrics history, never network state.
- **Duplicates:** a report that reaches two controllers (after a retry) produces identical samples with identical timestamps, which the store ignores.
- **Mapping:** monotonic counters become Prometheus counters, gauges become gauges. Labels:
  - per route: `node`, `role`, `route_id`, `src`, `dst`, `direction`, plus `reason` on drop counters
  - per link: `node`, `peer`, `transport`
  - per rule: `node`, `rule_id`, `decision`
  - `owner` (the node's account name) on per-node series, so usage can be summed per person
  - alarms: one gauge per active alarm, labelled `node`, `alarm` and `severity` (§19.7)
  - `boot_id` is **not** a label. Prometheus's `rate()` and `increase()` already handle counter resets, so a label would only multiply series.
- **Timestamps:** each sample uses the report's `taken_at`, not the arrival time, so buffered reports land at the right time.
- **Late data:** buffered reports can be up to 24 h old. Prometheus rejects old samples by default, so enable out-of-order ingestion with a window of at least the buffer length (`out_of_order_time_window: 24h`), or use a store that accepts backfill.
- **Cardinality** is bounded by the relays' top-N cap (§12.4) and the number of active routes. Watch the series count as the network grows.
- **Retention:**
  - raw per-route series: about 15 days
  - per-node and per-relay totals, precomputed with recording rules (for example bytes per node per direction): about 1 year
  - Prometheus applies one retention period per instance, so the long-lived totals go into a second instance (fed by remote-write or federation), or into a store that supports per-series retention.

### 12.6 Views

By joining reports on `route_id`, the metrics store provides:

- **Per DATA node:** bytes sent and received per destination and per route, the primary route, switch counts, and end-to-end quality over time. Summing all routes gives the node's total usage.
- **Per RELAY:** bytes relayed per route and per `(src, dst)` pair, top talkers, drops by reason, and wire vs. payload bytes per link.
- **Per route (path view):** one row per hop (sent → relayed → relayed → received) with the loss between each adjacent pair. This shows where a route loses traffic.
- **Per account:** all of the above summed over the nodes an account owns.
- **Per policy rule:** which rules are used and which never match, and the denials per rule.
- **Last seen:** the time of each node's latest report. Nodes not seen for a configurable period (for example 30 days) are listed as candidates for an admin tombstone (§10.5).

### 12.7 Cross-verification

- A relay's relayed bytes on a route must fall between the counts reported by the hops before and after it. Relays whose numbers fall outside that range by more than normal loss are flagged.
- Reports are signed, and each describes only what its node saw, so no node can inflate another node's usage.

---

## 13. Accounts & Identity

### 13.1 Accounts

Every person who uses the network has an **account** (§6.10): a name, an Ed25519 **account key** that the person holds on their own computer or a hardware token, and a flag saying whether the account is an **admin**.

- **Every node has an owner.** A NodeRecord's `owner` names one account. A person typically owns several nodes (a laptop, a phone, a server).
- **Account keys never leave their owner**, exactly like node identity keys. Controllers store only the public key.
- **`account_id` is random** and fixed when the account is created, so an account keeps its ID, its nodes and its place in the policy when its key is replaced (§13.6).

### 13.2 Who may sign what

| Signer | May sign |
|---|---|
| Root key | Admin AccountRecords; any AccountRecord; AccountTombstones for any account |
| Emergency revocation key | AccountTombstones for any account |
| Admin account key | **Normal** AccountRecords; AccountTombstones for **normal** accounts; SigningKeyCerts (§6.5); admin operations (§13.3) |
| Normal account key | `RenameNode`, `TombstoneNode` and `RekeyNode` for nodes it owns (§13.3). It also identifies the person in the policy (§14.2) |

Consequences:
- **An admin cannot create, promote, modify or revoke another admin.** Only the root can.
- **An admin can grant `CONTROL`:** the `control` role plus a SigningKeyCert signed with the admin's own key (§4, §6.5). Admins are therefore trusted as much as controllers are.
- **All admins have the same powers.** There are no scoped or partial admins.

### 13.3 Signed operations

Every account-initiated operation (§7.2) is wrapped and signed by the account that made it:

```
SignedOp {
    signer:    account_id     // a valid, non-tombstoned account
    op_seq:    u64            // per-account, strictly increasing
    issued_at: Timestamp
    op:        <operation>
}
signed by: that account's current account_key
```

**Controllers verify** the signature against the signer's current key, that `op_seq` is greater than the last one committed for that account (the state machine stores it, which stops replays), that `issued_at` is within ±2 minutes of the log entry's timestamp (§18.5), and that the signer is **allowed** to make the operation:

| Signer | Allowed operations |
|---|---|
| Admin account | Every operation in §7.2, on any node |
| Normal account | `RenameNode`, `TombstoneNode`, `RekeyNode` and `SetNodeConfig`, only for nodes whose `owner` is the signer |

**Self-service.** A person can rename their own devices, revoke one themselves (for example a lost phone), re-key one after a reinstall (§8.1), and tune its own configuration (§6.19: transport priorities, limits, extra seeds and DNS entries for that node), without waiting for an admin. They **cannot** enroll nodes, change tags, IPs, roles or owners, or touch anyone else's nodes, because those decide access. A node tombstoned by its owner is gone for good, like any tombstone; bringing the device back needs an admin to enroll it again.

**Signing:**
- **Admin tool (`webjetctl`, §19.2):** holds the account key, builds the operation, signs it and submits it to any controller.
- **Web UI:** an admin or normal account prepares changes in the browser. On **Submit**, the UI shows a summary of exactly what will be signed and **prompts for the account key** (pasted, or loaded from a key file, optionally protected by a passphrase). The browser signs the `SignedOp` locally with Ed25519 and sends only the signed operation. The private key is held in page memory just for that signature and then discarded; it is **never sent to the controller** or stored by the page. The prompt appears on every submission, so a left-open browser tab can't make changes on its own.
- The web UI is served by the controllers. A malicious controller could therefore serve a page that captures the key; this is acceptable only because controllers are trusted (§2). Admins who want to avoid that exposure use the admin tool.

**Audit trail:** each committed entry records which account signed what and when. The Raft log, and the snapshots that replace it, keep the signer of every change to the tree, so "who gave this node `RELAY`?" or "who revoked this laptop?" always has an answer. Controllers also export the audit trail to append-only storage, because log compaction discards old entries.

**Reading the audit trail:** an admin reads the log entries still in a controller's Raft log with a `LogRequest { account_id, issued_at, before, limit }` signed by their account key (message type 27), sent as a `GetLog` RPC (the agent forwards it from its `log` control command; webjet-app's Merkle tab uses it). It is read-only and never enters the log. A controller answers only when the signer is a valid admin whose current key signed it and `issued_at` is within 5 minutes of its clock, with at most 200 `LogRecord`s: index, term, timestamp, entry type, operation, signing key, account, `op_seq`, `issued_at`, what applying it did, and the hashes of the leaves it wrote. Secrets carried in entries (the leader's random PSK, the camouflage private key) are never included.

This closes the earlier gap where anyone on the overlay could reach the admin UI and act: reaching it is no longer enough, a signature from an allowed account is required.

### 13.4 Revoking accounts

| Tombstoned account | Effect |
|---|---|
| Normal account | Every node it owns is treated as **revoked**: hop and end-to-end sessions are destroyed, relays tear down their circuits, and the nodes drop off the network. `owner:` selectors for it match nothing |
| Admin account | It can no longer sign operations; operations it signed earlier stay in effect. Nodes it owns are revoked like a normal account's. Normal accounts it signed **stay valid**, unless the tombstone has `revoke_issued = true`, in which case they are revoked too. SigningKeyCerts it signed are **void** either way (§6.5) |

- `revoke_issued` lets the root choose: an admin who simply leaves keeps their colleagues' accounts working, while a compromised admin's accounts all go at once.
- Node verifiers (§9.2) check the owner on every handshake, so revoking one account takes all its nodes off the network without a tombstone per node.
- Tombstoned account names are not reused, so old audit records stay unambiguous.

### 13.5 Bootstrapping

1. On the offline computer, the root signs the first **admin AccountRecord**.
2. It is submitted, without a `SignedOp` wrapper, as the first `PutAccount` of a new cluster (or included in the cluster's initial state).
3. That admin creates the first controllers' NodeRecords with the `control` role (owned by an infrastructure account, for example `infra`) and signs their SigningKeyCerts, or has the root sign them (§7.5).
4. From then on, admins create normal accounts and enroll nodes; only new admins need the root.

### 13.6 Account key loss or rotation

- **Normal account:** an admin signs a new AccountRecord with the same `account_id` and a higher `version`, carrying the new key. Nodes, ownership and `owner:<name>` rules are unaffected. `owner:<base64 key>` rules naming the old key stop matching; the policy validator warns about this (§14.5).
- **Admin account:** the same, but signed by the root. SigningKeyCerts signed with the old key become void (§6.5); re-sign them with the new key.
- If a key may be stolen rather than lost, the old key is useless for control-plane actions as soon as the new record is committed, because only the current key is accepted.

---

## 14. Access Control

Access control decides which flows may start between nodes. It is a **tag-based policy** of allow and deny rules, set by admins, distributed in the network tree, and enforced by the nodes themselves.

### 14.1 Tags

- Tags are labels in a node's `tags` field (§6.1), for example `tag:server`, `tag:prod`, `tag:db`.
- **Only admins assign tags**, through signed `CreateEnrollment` or `UpdateNode` operations. A node or a normal account can never claim a tag, because tags grant access.
- Format: `tag:` followed by `[a-z0-9-]{1,32}`.
- Tags travel in the tree like every other field, so every node knows every node's tags even when no controller is reachable.

### 14.2 Selectors

Rules refer to nodes through selectors:

| Selector | Matches |
|---|---|
| `tag:<tag>` | Nodes with that tag |
| `role:relay`, `role:data`, `role:control` | Nodes with that capability |
| `node:<name>` | The node with that name |
| `node:<base64 node key>` | The node whose **current** identity key is this. Stops matching after a re-key or rotation (§8.1–8.2); the validator warns |
| `owner:<account name>` | Every node owned by that account |
| `owner:<base64 account key>` | Every node owned by the account whose current key is this |
| `cidr:<prefix>` | **Destination** addresses in that prefix, written in **published** (overlay-visible) form, e.g. `cidr:10.2.2.0/24` for a mapped LAN. Valid only in `dst` (§11.9) |
| `*` | Every enrolled node |

**Key form.** A key is written as standard base64 (RFC 4648, with padding) of the raw 32-byte Ed25519 public key, which is always 44 characters ending in `=`. Names are at most 32 characters of `[a-z0-9-]`, so a name and a key can never be confused.

- **Names** are readable and survive key rotation.
- **Keys** are unambiguous and survive renames, and they let a rule refer to a node or person by the identity that is cryptographically checked on the wire.

`tag:` and `role:` have no key form, because they don't name a single identity.

`cidr:` exists for subnet routes. Because gateways always SNAT, connections can't start from a LAN, so `cidr:` is not allowed in `src`. Rules always use published addresses, because those are what clients send to and what the gateway checks before translating.

**Resolution:** selectors are resolved against the current tree, so a rule takes effect for a node as soon as the node gets the tag, owner or name. A selector that currently matches nothing is allowed but produces a validation warning (§14.5).

### 14.3 Rules and evaluation

```yaml
version: 7
default: deny

rules:
  - id: admins-everywhere
    action: allow
    src: [tag:admin]
    dst: ["*"]
    ports: ["*"]

  - id: own-devices
    action: allow
    src: [owner:alice]
    dst: [owner:alice]
    ports: ["*"]

  - id: web-tier
    action: allow
    src: [tag:laptop]
    dst: [tag:web]
    ports: [tcp:80, tcp:443]

  - id: app-to-db
    action: allow
    src: [tag:web]
    dst: [tag:db]
    ports: [tcp:5432]

  - id: no-ssh-to-prod-db
    action: deny
    src: ["*"]
    dst: [tag:db, tag:prod]
    ports: [tcp:22]

  - id: quarantine
    action: deny
    src: [node:k3Jc0q2v1mJ8w2l3cY7p4XoTqk2Z1r6Hn0bQe5uA9sY=]
    dst: ["*"]
    ports: ["*"]

tests:
  - { src: tag:laptop, dst: tag:db,  port: tcp:5432, expect: deny  }
  - { src: tag:web,    dst: tag:db,  port: tcp:5432, expect: allow }
  - { src: tag:admin,  dst: tag:db,  port: tcp:22,   expect: deny  }
```

A list of selectors means "any of them" (`dst: [tag:db, tag:prod]` matches a node with either tag).

**Evaluating a new flow** `(src node, dst node, protocol, port)`:
1. If any matching rule is **deny**, the flow is denied.
2. Otherwise, if any matching rule is **allow**, the flow is allowed.
3. Otherwise, the `default` applies.

**Deny always wins, and order doesn't matter.** Rules can be added, removed or reordered without changing each other's meaning. In the example, `admins-everywhere` still can't SSH into production databases, because `no-ssh-to-prod-db` overrides it. To express "deny everything except X", use `default: deny` and allow X, rather than combining a broad deny with a narrower allow (which would not work, since deny wins).

**Rules are directional.** A rule allows *starting* a flow from `src` to `dst`. Replies on that flow are allowed by connection tracking (§14.4), so a rule never needs a mirror image.

### 14.4 Enforcement

Each node **compiles the policy into tables about itself**, recomputed whenever the policy or any node's name, tags, owner or roles change:

```
inbound:  src node_id → allowed (proto, port ranges)   // flows others may start to me
outbound: dst node_id → allowed (proto, port ranges)   // flows I may start
```

Deny rules are applied during compilation, so the tables contain only what is finally allowed, and the packet path is one lookup keyed by the authenticated peer.

**At the destination (authoritative):**
1. Decrypt the E2EFrame, which identifies the source `node_id` (§9.4.4).
2. Run the cryptokey routing check (§9.5).
3. If the packet belongs to a tracked flow, accept it.
4. Otherwise, if it starts a new flow, check `inbound[src]`. Accept it and create a tracking entry, or drop it and count `acl_denied`.

For **subnet traffic**, the destination is the gateway, and its table also includes, per source node, the published prefixes and ports that source may reach. The check uses the packet's destination address **before** translation.

**At the source (fail fast):**
- Before sending, check `outbound[dst]`. If denied, write ICMP "administratively prohibited" into the tun interface (§9.5); the packet never uses relay bandwidth.
- Allowed flows get a tracking entry too, so replies from the destination are accepted on the way back.

The destination check is the one that counts. A modified client can skip the source check, but its traffic still stops at the destination.

**Connection tracking:** per-flow entries keyed by the 5-tuple and the peer `node_id`, with the timeouts, quotas and eviction order in §16.3. ICMP errors are allowed when they relate to a tracked flow. **When the policy changes, every tracked flow is re-evaluated**, and flows the new policy denies are dropped, so a new deny rule cuts existing connections too.

**Pair reachability.** Two nodes *may talk* if, after deny rules, some protocol and port is allowed in at least one direction between them. A node may also talk to a gateway if some rule lets it reach any prefix that gateway is granted. This drives two earlier checks:
- **End-to-end handshake:** a node refuses a session with a peer it may not talk to (§9.4.2).
- **Circuit admission:** a relay refuses a CircuitSetup whose `src` and `dst` may not talk (§11.5) and counts it in `circuits_refused`. Relays compute pair reachability lazily, per circuit setup, and cache it until the policy or tree changes.

**Always allowed (infrastructure traffic):**
- hop sessions, gossip, link-state adverts, and hole-punching coordination
- relaying of circuits that pass admission
- every node → controllers for PSK fetch and metric reports; controllers ↔ controllers for Raft

Admin access to the controllers' admin endpoints is an ordinary rule (for example `tag:admin → role:control tcp:443`); the operations themselves still need an admin signature (§13.3).

### 14.5 Distribution and validation

- The policy is part of the network configuration (`SetNetworkConfig`, a signed admin operation, §6.18). The committed policy is the tree's policy leaf (§6.12), so nodes receive it through the normal Merkle sync and authenticate it with an inclusion proof.
- **Validation before commit** (controllers reject the operation if any fails):
  - the policy parses, and `version` is higher than the current one
  - every test in `tests` gives its expected result
- **Warnings** (shown to the admin, not blocking):
  - selectors that currently match no node, usually typos
  - `owner:<key>` or `node:<key>` selectors naming a key that is no longer current
  - deny rules that override every allow rule they overlap, which usually means a mistake
- **Dry run:** the admin tool shows which `(src, dst, port)` combinations the change allows or denies compared with the current policy, before signing.
- **Propagation:** nodes apply a new policy as soon as they receive the tree head that contains it, usually within seconds. To remove a node or person *immediately*, tombstone the node or account; that also tears down circuits.
- **Soft mode:** with no controller reachable, nodes keep enforcing the last policy they have.

### 14.6 Observability

- `acl_denied` drop reason in the per-route counters (§12.3).
- Per-rule hit counters and relays' refused circuits, in metric reports (§12.3, §12.5).
- **Denied-flow samples:** the destination logs the first denied flow per `(peer, protocol, port)` per minute, rate-limited, for answering "why can't I reach X?".

---

## 15. Encoding & Versioning

Every signature, hash and Merkle proof in this design depends on bytes. This section fixes what those bytes are and how their format changes over time.

### 15.1 Principle: sign and hash bytes, never re-encode

- Every signed or hashed object is **kept as the exact bytes it arrived as**. Signatures are verified over those bytes, Merkle leaves hash those bytes, and those bytes are what gets gossiped and stored.
- Nodes **never re-serialize** a received object, to check it or to forward it.
- Consequences:
  - The serialization format does **not** have to be canonical for verification to work.
  - The bytes an object was signed with can only be produced by its signer, so nobody else can create a second encoding of a signed object. Deduplication uses each record's own identity (`(origin, seq)`, `(node_id, version)`), never a hash of its bytes.
  - The one place where several parties must produce **identical** bytes is controller-built tree leaves. That is solved by copying the leader's bytes through the log (§15.5), not by canonical serialization.

### 15.2 FlatBuffers profile

All structures are defined as **FlatBuffers** schemas (`.fbs`), one root table per message type, compiled for Rust (and for TypeScript, for the web UI's signing, §13.3).

**Schema conventions:**

| Item | Representation |
|---|---|
| Keys, hashes, IDs | Fixed-size structs (`struct Key32 { b: [ubyte:32]; }`, `Sig64`), never variable-length vectors |
| Timestamps | `uint64`, milliseconds since the Unix epoch, UTC |
| CIDRs | `struct Cidr { family: ubyte; addr: [ubyte:16]; prefix: ubyte; }`, host bits zero, unused bytes zero |
| Sets (`roles`, `tags`, `overlay_ips`, `features`) | Vectors, **sorted and without duplicates** |
| Enums | Explicit values; never renumbered |
| Optional scalars | Declared `= null` (FlatBuffers optional scalars), so "absent" and "zero" are distinct |
| Identifiers | Each root type has a 4-byte `file_identifier`; a buffer with the wrong identifier is rejected |

**Builder discipline** (for reproducible output, though correctness never relies on it):
- one pinned FlatBuffers version across the project
- `force_defaults(true)`, so every scalar field is always written
- fields written in schema order
- golden test vectors check that builder output doesn't drift between releases

**Reading untrusted input** happens in two steps, before any field is used:
1. **Structural verification** with the FlatBuffers verifier, with explicit limits per message type: maximum buffer size, maximum depth, maximum number of tables, and maximum vector lengths. FlatBuffers reads fields in place, so skipping this step would let a malicious buffer cause out-of-bounds reads.
2. **Semantic validation:** sets sorted and unique, names and tags in the allowed format, CIDRs with zero host bits, lengths and ranges valid, and the schema version known (§15.6). Anything that fails is rejected.

### 15.3 Signed envelope

Every signed object travels in one envelope:

```
table Signed {
    type:    uint16;       // message-type registry: 1 NodeRecord, 2 EndpointRecord, 3 CircuitSetup, …
    schema:  uint16;       // schema version of `body` (§15.6)
    body:    [ubyte];      // the object's FlatBuffers bytes (a nested buffer)
    signer:  Key32;        // key id of the signer
    alg:     uint8;        // 1 = Ed25519
    sig:     Sig64;
}

sig = Ed25519(key, "webjetsig/v1" || 0x00 || u16be(type) || u16be(schema) || body)
```

- The signature covers `type`, `schema` and the body bytes, but not the envelope's own encoding, so the envelope can be rebuilt freely without breaking the signature.
- **Domain separation:** the `"webjetsig/v1"` prefix plus the type means a signature made for one message type can never be accepted as another. Every other signing and key-derivation context in the design uses its own distinct label too (the TLS exporter label, enrollment proofs, BLAKE3 contexts below).
- Tree leaves built by controllers (NodeRecords, committed tombstones) are not individually signed (§6.1); they use the same `type` and `schema` fields in an unsigned `Leaf` wrapper.

### 15.4 Hashing: BLAKE3

All hashes and derived identifiers use **BLAKE3** with 32-byte output. TLS and the end-to-end session keep their own TLS-internal hash functions; this section covers everything this design defines.

**Derived identifiers** use BLAKE3's key-derivation mode, with a distinct context string per kind:

| Identifier | Derivation |
|---|---|
| `signing_key_id` | `BLAKE3.derive_key("webjet signing-key-id v1", signing_key)` |
| `route_id` | `BLAKE3.derive_key("webjet route-id v1", src ‖ dst ‖ hops…)` |
| `token_hash` | `BLAKE3.derive_key("webjet enroll-token v1", token)` |

`node_id` and `account_id` are random (§8.1, §13.1), so they survive key changes. Enrollment proofs use BLAKE3's keyed mode, with a key derived from the token.

**Merkle tree**, with domain-separated leaves and internal nodes:

```
leaf     = BLAKE3(0x00 ‖ kind ‖ key ‖ leaf_bytes)
internal = BLAKE3(0x01 ‖ left ‖ right)
empty    = fixed constant per depth
```

The leaf and internal prefixes stop a leaf from ever being passed off as an internal node.

### 15.5 Identical bytes on every controller

Controllers build tree leaves themselves, and every controller's tree must hash to the same root. Instead of requiring byte-identical serializers on every controller:

1. The **leader** computes the operation's result and serializes the resulting leaves.
2. The **log entry carries those leaf bytes** along with the operation.
3. Each **follower** independently computes the expected result from its own state and the operation, decodes the leader's bytes, and checks that they decode to exactly that result and pass validation (§15.2). It then stores the leader's bytes unchanged.
4. On a mismatch, the follower **stops applying and raises an alarm**, rather than diverging. This catches both bugs and version skew.

**Rules for the apply function** (what every follower computes):
- no wall clock: timestamps come from the log entry, stamped by the leader when proposing
- no randomness: random values (a new `account_id`, a new PSK) are chosen before proposing and stored in the entry
- no iteration over unordered maps, no floats, no locale-dependent string handling

### 15.6 Schema versions

- **Every schema change bumps that type's schema version**, including additions that FlatBuffers itself would tolerate. There is no "unknown field" handling: a reader either knows a schema version exactly, or rejects the object.
- Field IDs and enum values are never reused or renumbered within a type, even across versions, so old and new schemas stay easy to read side by side.
- Software keeps reading the **previous** schema version of each type for as long as the current StateVersion allows it (§15.7).
- **Golden test vectors** for every type and schema version are checked into the repository. Every decoder is fuzzed: it must either reject an input or accept it and round-trip its values exactly.

### 15.7 StateVersion: coordinated, root-signed upgrades

Because every schema change is a new version, nobody may start **emitting** a new version until everyone can **read** it. A single root-signed record coordinates this:

```
StateVersion {
    version:            u32
    state_machine:      u32                  // apply rules the controllers use
    emit:               { type → schema }    // versions everyone writes
    accept:             { type → [schema] }  // versions everyone reads (emit + previous)
    min_wire_protocol:  u16                  // §15.8
    min_node_software:  String
}
signed by: the root key
```

- Activated by the **root-signed** `SetStateVersion` operation (§7.2) and committed into the log. It takes effect at that log index, and every tree head from then on carries its `state_version` (§6.4).
- **Root key only.** A bad upgrade can stall the controller cluster or cut off nodes that haven't upgraded, so it gets the same protection as admitting a controller.

**Rollout:**
1. Release software that can read the new schema versions (and apply the new rules), while still emitting the current ones.
2. Upgrade controllers, then nodes. Node software versions are visible in endpoint records and metric reports (§6.2, §12.5), so admins can see when coverage is complete.
3. On the offline computer, the root signs a StateVersion whose `emit` names the new schemas. It is submitted and committed.
4. Nodes switch to emitting the new versions once they see a tree head with the new `state_version`. The previous versions stay in `accept` until a later StateVersion drops them.

**Software that doesn't support the new StateVersion:**
- A **controller** stops applying at that log index and raises an alarm. It falls behind instead of diverging, and catches up once upgraded.
- A **node** keeps running on the last state it fully understands and raises "upgrade required". Peers keep talking to it as long as it meets `min_wire_protocol` and its records use accepted schemas.

### 15.8 Wire protocol versioning

- **Hop sessions** negotiate the protocol version with TLS ALPN (`webjet/1`, `webjet/2`, …).
- **AnyTLS** must present a browser's ALPN values (`h2`, `http/1.1`, §9.7.2), so it negotiates with a version hello as the first message after authentication instead.
- **End-to-end sessions** use ALPN on their internal TLS handshake (`webjet-e2e/1`, …).
- **Gossip records** carry their own protocol number. Records below a node's floor are ignored (§10.6.5).
- **Feature flags:** each node lists optional features in its EndpointRecord (§6.2), for example a new transport, so peers know what it supports before dialing. New record and frame types are sent only to peers that advertise them: `zstd` and `lz4` (compression, §9.8), `proxy`.
- Software supports the current and previous wire protocol versions. Peers refuse protocols below the StateVersion's `min_wire_protocol`.

---

## 16. Resource Limits

Every table a node keeps on behalf of peers is bounded, so an enrolled but misbehaving (or compromised) peer can't exhaust a node's memory or CPU.

### 16.1 Principles

1. **No state before authentication.** The PSK gate (§9.1) and the hop handshake (§9.2) decide statelessly whether to proceed. Anything an unauthenticated sender can trigger is either stateless or bounded by time (the replay window).
2. **Every table has a per-peer quota and a global cap.** One peer can use at most its quota; all peers together at most the cap.
3. **Hitting a limit refuses new state and never breaks existing state.** The one exception: when a global table is full, the oldest idle or half-open entries are evicted first (§16.3).
4. **Every limit hit is counted** and reported (§16.5), so reaching a limit is visible, not silent.

### 16.2 Limits and defaults

| Limit | Where | Per-peer quota (default) | Global cap (default) | When reached |
|---|---|---|---|---|
| Connection tracking | Every node (§14.4) | 4,096 flows; 500 new flows/s | Scaled to memory: ~256k on servers, ~16k on phones | Per peer: drop new flows from that peer. Global: evict (§16.3) |
| SNAT ports | Gateways (§11.9.4) | 2,048 ports per source node | 64k per LAN address; more LAN addresses raise it | Drop new flows; count `snat_exhausted` |
| Circuits | Relays (§11.6) | 64 circuits; 10 setups/s | e.g. 50k | Refuse the CircuitSetup |
| Relay capacity | Relays (§11.8.1) | — | Auto-estimated; local config or `relay_capacity_mbps` override | Used for load, not enforced |
| Relay bandwidth | Relays | Fair share per source, in the hop queue (§17.2) | Link capacity | The hop queue marks or drops (§17.2, §17.7) |
| Send rate ceiling | Every node | — | Unset by default; `rate_ceiling_mbps` in local config or as an override | Pacing never exceeds it (§17.5) |
| End-to-end handshakes | Every node (§9.4.2) | 10/s; 4 in progress | ~1,000 in progress | Ignore further handshake frames until older ones finish |
| Packets queued before a handshake | Every node (§9.4.1) | 64 per session | — | Drop |
| Hop TLS handshakes | Nodes with public addresses | 5 in progress per source IP | Configurable | Silently drop the connection |
| Lookups and subscriptions | Relays (§10.6.2) | 20 lookups/s; 256 subscribed nodes | Configurable | Reject the request |
| Pending pushes to edge nodes | Relays (§10.6.3) | Latest version of each item only | — | Older pending versions are replaced |

Per-peer quotas are keyed by the authenticated `node_id`, except hop TLS handshakes, which happen before identity is known and are keyed by source IP.

### 16.3 Connection tracking

**Timeouts:**

| Flow state | Timeout |
|---|---|
| TCP, handshake not complete | 30 s |
| TCP, established | 1 h idle |
| TCP, closing (FIN or RST seen) | 60 s |
| UDP, packets in one direction only | 30 s |
| UDP, packets in both directions | 2 min idle |
| ICMP echo | 10 s |

**Eviction when the global table is full**, in this order:
1. half-open TCP flows
2. one-direction UDP flows
3. other flows, longest idle first

A flood of new connection attempts therefore pushes out other half-open attempts, not established connections that people are using.

**Refusal is silent.** A destination that refuses a new flow because of a limit drops it without replying, so limits can't be used to make a node send traffic. A **source** whose own table is full writes ICMP "administratively prohibited" into its tun interface (§9.5), so local applications fail fast.

### 16.4 Configuring limits

The built-in defaults suit most nodes; busy gateways and relays need more than phones. Admins adjust them in the `[limits]` part of the network configuration (the Limits leaf, §6.15, §6.18):

```toml
[limits.value]
conntrack_per_peer = 4096

[[limits.override]]
select = ["tag:gateway"]
value = { conntrack_global = 1000000, snat_ports_per_source = 8192 }

[[limits.override]]
select = ["role:relay"]
value = { circuits_global = 200000 }
```

- Selectors are the same as in the policy (§14.2). Where several overrides match a node, the **highest value** wins for each limit.
- **Per node:** a node's own configuration (§6.19) sets a value for that node alone, ahead of every override; its owner may set it, for example `relay_capacity_mbps` for a relay they run.
- Memory-dependent global caps are **clamped by the node itself** to what it can actually hold, so an override can't make a small device run out of memory.
- **Validation:** limit names must be known and values positive; unknown names are rejected rather than ignored.
- **Soft mode:** with no controller reachable, nodes keep the last Limits they have.

### 16.5 Observability

- `limit_hits`, by limit name and peer, in metric reports (§12.5).
- The drop reason `conntrack_full` in per-route counters (§12.3), alongside `rate_limited` and `snat_exhausted`.
- The admin UI lists peers that repeatedly hit quotas. Persistent hits usually mean either a misbehaving node or a limit too low for a legitimate workload.

---

## 17. Congestion Control

### 17.1 Division of work

Every hop transport is a reliable stream, which hides packet loss from the traffic inside it. Three layers could react to congestion (the application's own TCP inside the tunnel, the end-to-end session, and each hop), and if they all did, they would work against each other. Each has one job:

- **Hops hide random loss.** KCP retransmission and FEC, or TCP on the TCP transports, turn line loss into a small delay.
- **Queues signal real congestion.** When a hop can't send as fast as traffic arrives, its queue marks or drops frames early instead of buffering them.
- **Inner flows do the congestion control.** The application's TCP (or QUIC) reacts to those marks and drops. The end-to-end session adds no congestion control of its own.

Without the second point, a reliable hop would turn congestion into seconds of queueing delay.

### 17.2 Hop queues

Every hop session has a small managed queue in front of it, on every node:

- **Fair queuing with CoDel** (RFC 8289): target delay 5 ms, interval 100 ms. On a hop whose RTT is above 50 ms, the interval is twice the hop's RTT.
- **Hard cap:** about 100 ms of data at the hop's current rate. Frames beyond it are dropped as `queue_full`.
- **What counts as a flow:**
  - on the **source node**, the inner packet's addresses and ports, so a bulk transfer can't starve an interactive session
  - on **relays**, where frames are opaque, the source node first and then the circuit. This is the per-source fair share of §16.2.
- **Short socket buffers.** TCP hops set `TCP_NOTSENT_LOWAT` (16 kB, Linux and macOS). A KCP hop takes more data from the hop, through a 16 kB pipe, only while KCP holds less than about 5 ms of unsent data at its pacing rate (§17.5). Waiting data thus sits in the managed queue and not in a kernel or KCP buffer, and the queue's CoDel interval follows the hop's raw RTT (§11.2), not one inflated by such a buffer.
- **CoDel sees the whole wait.** On a KCP hop, the time the oldest unsent byte has waited inside KCP is added to every frame's time in the managed queue. Frames waiting in KCP have already left the queue and been encrypted into the hop stream, so they can't be marked there. Instead, the frames behind them are marked as long as the total wait stays above the target.
- When CoDel decides a frame must go, it is **marked** if the frame is ECN-capable and **dropped** (`aqm`) otherwise (§17.7).

### 17.3 Control traffic

Keepalives, gossip, link-state and attachment records, end-to-end handshake frames and Raft traffic use a separate **priority queue** per hop, sent ahead of data and limited to a small share of the hop's rate. Congestion from user traffic then can't cause false failure detection, missed state updates or Raft leader elections.

### 17.4 TCP hops (plain TLS and AnyTLS)

The kernel's TCP does the congestion control. The agent requests **BBR** per socket where the kernel offers it, and otherwise uses the system default. `TCP_NODELAY` is set; the hop queue does the batching.

### 17.5 KCP hops: BBR-style rate control

KCP's own congestion window is turned off. It backs off on every loss, which collapses on lossy long-distance links, the links KCP is meant for. Sending with no control at all is unfair to other traffic, causes its own loss and invites throttling. Instead, each KCP hop session is **paced** by a BBR-style controller:

- **Estimates:** the bottleneck bandwidth (the highest delivery rate seen over recent round trips) and the minimum RTT (over about 10 s), both taken from KCP acknowledgements: the bytes each acknowledgement delivers, and the raw RTT of §11.2 (from the socket to the acknowledgement, never for a retransmitted segment).
- **Pacing:** packets leave at the estimated bandwidth, with BBR's phases: a fast start-up, a drain, steady probing for more bandwidth, and periodic probing for the minimum RTT.
- **In flight:** capped at about twice the bandwidth-delay product, which also sizes KCP's send window.
- **Loss is not a congestion signal.** Random line loss doesn't reduce the rate. Only loss that stays well above the link's usual level while probing for bandwidth lowers the estimate.
- **Everything is paced together:** data, retransmissions and FEC parity share the one rate. The pacer is a token bucket consulted inside KCP's flush: due retransmissions go first, then new data while tokens and the window last. Data that can't go yet stays in KCP's short send queue (above), not in a queue of finished packets in front of the socket.
- **KCP settings:** stream mode, no-delay, fast retransmit after 2 duplicate acknowledgements (at most 5 times per segment), an RTO of at least 30 ms. New data and received packets are flushed at once rather than at the next interval, so neither data nor acknowledgements wait up to 10 ms at each end of a hop. Acknowledgements are output separately from data, so they can go out at once (`RAW_ACK`, §11.2).
- **The KCP implementation** is adapted from the `kcp` crate 0.6.0 (MIT) and kept in `webjet-net/src/kcp/proto.rs`. The wire format is unchanged. The changes are the paced flush, the send queue's age, separate acknowledgements, measurements from the protocol itself (raw RTT per segment, delivered bytes, retransmissions), and wrapping arithmetic without panics.
- **Application-limited samples.** A delivery-rate sample taken while the sender had less to send than the window allowed may raise the bandwidth estimate but never lowers it, so a quiet period doesn't throttle the next burst.
- **Delivery samples span at least an RTT** (and 25 ms), and count each acknowledged segment at its real size. Acknowledgements arrive in bursts, so a rate taken between two loop turns a millisecond apart was many times the path's rate (a 20 Mbit/s path read as 500 Mbit/s, and relays advertised gigabits of capacity). A burst delivered just before the sender went idle counts as application-limited.

**Optional ceiling.** A node may have `rate_ceiling_mbps` set, in its node configuration (§6.19) or through a Limits override (§16.4), for example to match a purchased uplink. The pacing rate never exceeds it. Unset by default.

The bandwidth estimates also feed the relay capacity estimate used by load-aware routing (§11.8.1).

### 17.6 Adaptive FEC

- **Coding:** Reed–Solomon parity over groups of KCP packets, below KCP, so KCP sees fewer losses and retransmits less.
- **Adaptive ratio.** The share of parity follows the hop's measured loss, aiming for under **0.1% residual loss** after recovery. It ranges from **0 to 30%** and changes gradually. A clean link sends almost no parity. The loss is measured by the receiver before recovery, from the gaps in each parity group's data packets (a group whose parity hasn't flowed yet counts up to its highest packet seen), and reported to the sender (`STATS`) once a second while there is loss and for 10 s after the last, otherwise every 10 s.
- **Parity counts toward the paced rate** (§17.5), so FEC can never push a link past its capacity or make real congestion worse.
- Packets recovered by FEC don't count as loss for the rate controller.

### 17.7 Congestion marking through relays (ECN)

Relays can't see inner packets, so they can't set the IP header's ECN mark, and could otherwise only signal congestion by dropping. The relay frame header carries the mark instead, following the standard tunnel rules (RFC 6040):

| Step | Who | Action |
|---|---|---|
| Encapsulation | Source node | Copies the inner packet's ECN field into the frame's `ecn` bits (§11.5) |
| Congestion | Any relay's hop queue | For an ECN-capable frame, sets "congestion experienced" and forwards it; otherwise drops the frame |
| Decapsulation | Destination node | If the frame is marked and the inner packet is ECN-capable, marks the inner packet. A marked frame whose inner packet is not ECN-capable is dropped |

- Flows that support ECN slow down without losing packets.
- The source and destination nodes' own hop queues mark inner packets directly.
- Gateways preserve the ECN field when forwarding to and from a LAN (§11.9.4).
- **Trust.** The `ecn` bits are outside the end-to-end encryption, because relays must be able to change them. A relay that sets the mark falsely can slow a flow, which it could also do by dropping. A relay learns only whether a packet is ECN-capable.

### 17.8 Head-of-line blocking

All circuits between two nodes share one stream per transport. A lost packet on a TCP hop briefly stalls every circuit on that hop; on KCP, FEC and fast retransmit keep such stalls short. This is accepted. Opening parallel connections would add state and, on AnyTLS, look less like a browser.

### 17.9 Observability

Per link, in metric reports (§12.3): queue delay, frames dropped (`aqm`, `queue_full`) and marked, KCP retransmissions, packets recovered by FEC, the current parity ratio, and the bandwidth estimate.

---

## 18. Scale Targets & Time Requirements

Figures in this section are estimates to confirm by benchmark.

### 18.1 Scale targets

| Dimension | Design target | Should keep working up to |
|---|---|---|
| Nodes | ~100 | 1,000 |
| Relays | 8–16 | 64 |
| Controllers | 8–16 (5 voters, the rest learners, §7.1) | 32 |
| Accounts | ~100 | 1,000 |
| Policy rules / DNS records / subnet routes | 200 / 500 / 50 | 10× each |
| Active peers per edge node | 32 | 256 |
| Active peers per gateway | 100 | 1,000 |

Many nodes hold several capabilities at once (§4.1), so the relay and controller counts overlap with each other and with the node count.

### 18.2 Behavior targets

| Behavior | Target |
|---|---|
| Tombstone or policy change reaches online nodes | under 10 s |
| Reroute after a relay fails | under 5 s |
| Controller leader failover | under 10 s |
| Enrollment, from token to first traffic | under 10 s |
| Edge throughput (one laptop core) | 300 Mbit/s |
| Relay throughput (4 cores) | 1 Gbit/s |
| Idle edge node control traffic | under 10 MB/day |

### 18.3 Budgets at the design target

| Item | Size or rate |
|---|---|
| Network tree | ~350 bytes per node: about 35 KB in total |
| Daily tree change with nothing happening | One leaf (the validity leaf, §6.16) |
| Core gossip | 15 digests per second per relay (full exchange, §10.3.1); a few hundred bytes per second |
| LinkStateAdvert | ~1 KB each with 16 relays (one entry per peer: the selected transport and its cost, §9.6) |
| Relay graph pushed to each edge node | 16 adverts every minute: about 270 B/s, or 20–25 MB/day. This is most of an idle node's control traffic |
| AttachmentRecords through the core | ~5 per second |
| Metric reports | ~100 per minute; tens of thousands of time series. A single Prometheus instance is enough |
| Rekeying on a gateway with 100 peers | Under 1 handshake per second |
| Hop sessions | Up to three per neighbor pair, one per eligible transport, each with its own keepalives |

**Beyond the design target.** Three things would need rework well before the "should keep working" column is exceeded, and are deliberately left simple:
- **Relay graph to edge nodes:** grows with relays squared. Past about 64 relays, push it only to nodes with active sessions and shorten link entries.
- **AttachmentRecords:** flooded through the core every 10 s per edge node. Past a few thousand nodes, refresh them less often and have the last relay refuse circuits to nodes that aren't connected.
- **Per-route metrics:** series count grows with nodes times routes. Past a few thousand nodes, cap per-route detail on edge nodes and use a store built for high cardinality.

### 18.4 Clock rules

1. **Durations use the monotonic clock:** timeouts, rekey timers, connection tracking, rate limits and hysteresis. A wall-clock jump never affects them.
2. **The wall clock is used only to compare signed timestamps:** expiry of tree heads, the validity horizon and self-signed records; the PSK gate; `issued_at` on operations and circuit setups.
3. **All timestamps are UTC milliseconds** since the Unix epoch.
4. **Controllers never decide from their own clock while applying the log.** Every time-dependent check in the state machine uses the log entry's timestamp, stamped by the leader (§15.5), so all controllers reach the same result.
5. **Nothing that needs sub-second agreement uses the wall clock.** Hole punching is timed from message arrival and measured round-trip time (§11.7).
6. **The system clock is the only time source.** The agent never corrects its own timestamps from what peers report.

### 18.5 Required accuracy and tolerances

| Who | Requirement | Why |
|---|---|---|
| Nodes | Within ±30 s of true time (NTP or equivalent) | The PSK gate allows ±60 s between two nodes, so each may be off by half of that |
| Controllers | Within ±1 s of each other | The leader timestamps log entries, and all controllers sign tree heads |

| Check | Tolerance |
|---|---|
| PSK gate timestamp (§9.1) | ±60 s |
| Short-lived self-signed records (endpoint, link-state, attachment), CircuitSetup, SignedOp `issued_at` | ±2 min |
| Tree head `expires_at`, validity horizon | ±5 min |

### 18.6 Wrong clocks

A node whose clock is far off can't work correctly: its records look expired or not yet valid to everyone else, and it would misjudge other nodes' records. The agent **reports an error and exits** rather than run in that state. On a phone, "exit" means the tunnel stops and the error is shown.

**How the agent finds out:**

- **Trusted floor.** The newest `issued_at` among valid tree heads the node has seen is persisted. It is a controller-signed lower bound on the current time. If the system clock is more than 5 minutes **behind** it, at start-up or later, the agent exits.
- **Offset against peers.** Hop keepalives already carry the sender's timestamp, so a node measures its clock offset against each relay or controller it's connected to, corrected for round-trip time.
  - above **30 s**: a warning, also visible in metric reports
  - above **60 s**, confirmed by **at least two** peers whose own clocks agree with each other within 5 s: the agent exits, reporting the measured offset
  - reported by only **one** peer: a warning only, so a single relay with a bad clock can't shut down the nodes attached to it
- **Unable to connect.** A node more than 60 s off is dropped silently at the PSK gate and learns nothing from the network. After repeated failures to reach any seed, the agent's error names clock skew as a likely cause. If an NTP server is configured for this check, the agent queries it and exits if the offset is above the limit.

**Devices without a battery-backed clock** boot with a clock far in the past. The agent is ordered after time synchronization (for example systemd's `time-sync.target`); if it starts too early, the trusted-floor check makes it exit and the service manager restarts it later.

**Relays** apply the same rule against the median of the other relays they're connected to, and exit when more than 60 s off.

**Controllers:**
- A leader whose clock differs from the median of the other voters by more than **2 s** steps down, so a bad clock doesn't stamp log entries.
- Followers that notice a log entry's timestamp far from their own clock raise an alarm but still apply it, as rule 4 requires.

---

## 19. Operations

This section says where things live and how the system is run. Step-by-step procedures are in a separate **Operations Guide** (`webjet-operations-guide.md`); §19.10 lists them.

### 19.1 Platforms

| | Linux | macOS | Windows | FreeBSD (OPNsense) |
|---|---|---|---|---|
| Service | systemd unit | launchd daemon | Windows service | rc.d script under `daemon(8)`, enabled in `/etc/rc.conf.d/webjetd` |
| Virtual interface (`tun-rs`) | `/dev/net/tun` | `utun` | Wintun driver | `tun` driver, renamed |
| Runs as | Dedicated user with `CAP_NET_ADMIN` only, plus systemd sandboxing | Root daemon (creating `utun` requires it) | LocalSystem service | Root (tun, routes and BPF have no finer privilege) |
| Key storage (§8.3) | Key file, TPM-sealed where available | Keychain | DPAPI, or TPM | Key file |
| Split DNS (§11.10.1) | systemd-resolved | Per-domain resolver configuration | NRPT rules | — (Unbound query forwarding by hand) |
| Local control channel | Unix socket | Unix socket | Named pipe | Unix socket |
| Configuration | `/etc/webjet/` | `/Library/Application Support/Webjet/` | `%ProgramData%\Webjet\` | `/usr/local/etc/webjet/` |
| State | `/var/lib/webjet/` | `/Library/Application Support/Webjet/state/` | `%ProgramData%\Webjet\state\` | `/var/db/webjet/` |
| Logs | journald | Unified log | Event Log | syslog, tag `webjetd` |
| Start after time sync (§18.6) | `time-sync.target` | — | Windows Time service | — |
| Remote upgrade helper (§19.8) | systemd path unit | launchd queue directory | Scheduled task, every minute | cron job, every minute |

- **Controllers, relays and gateways run on Linux.** macOS and Windows are supported as DATA nodes. This keeps the server-side roles to one platform to build and test.
- **FreeBSD (OPNsense) is being prepared** as a DATA node platform. The agent's operating-system integration covers it: the tun interface (FreeBSD's `tun` driver makes `tunN` interfaces; any other configured name, `webjet0` by default, is given by renaming, and a renamed interface an earlier run left behind is destroyed at start, because FreeBSD keeps it after the process exits), routes (`route add`, falling back to `route change` for a route that already exists), multicast group membership (`getifmaddrs`) and capture (§9.5.2, BPF on sent packets only). Split DNS is not configured (on OPNsense, Unbound owns DNS: forward the overlay suffix to the overlay resolver by hand); gateway NAT and the reverse proxy are Linux only. `webjetup` installs the services: `webjetd` (and `webjet_signer` with `--signer`) as rc.d scripts run by `daemon(8)`, which restarts the program when it exits and sends its output to syslog; OPNsense starts every service enabled in `/etc/rc.conf.d/` at boot. Releases from 0.11.0 include `x86_64-unknown-freebsd` (cross-compiled in CI against a FreeBSD 14.4 sysroot; runs on FreeBSD 14.0 and later 14.x, OPNsense 24.7 and later).
- iOS and Android are not part of the first implementation (§2).

### 19.2 Programs

| Program | Runs on | Purpose |
|---|---|---|
| `webjetd` | Every node | The agent: data plane, gossip, local DNS resolver. On controllers it also runs Raft, the admin API and the web UI |
| `webjetd signer` | Controllers | Holds the controller's online signing key, as a separate OS user; signs tree heads for `webjetd` (§4.1) |
| `webjetctl` | Admins' machines and every node | Three groups by scope: `network` (the network configuration and administration, signed with an account key, §13.3), `local` (setting up this machine, status and diagnostics §19.5, and the node's own configuration §6.19), `root` (the offline root and emergency keys, §5; run on the offline computer, requests and signed results are carried on removable media) |

### 19.3 Where settings live

**Anything about the network, or about how a node behaves in it, is in the tree; only how one machine runs the agent is in its local file.**

- **In the tree**, set by signed operations:
  - the **network configuration** (§6.18): policy (§14), DNS (§11.10), seeds (§10.7), limits (§16.4), transport and camouflage settings (§9.6, §9.7); admins, `webjetctl network config`
  - each node's **node configuration** (§6.19): its own transport priorities and limits, extra seeds, DNS records and zones; the node's owner or an admin, `webjetctl local config`
  - each node's record (roles, tags, addresses, routes); admins
- **Local file** `webjetd.toml`:

```toml
data_dir  = "/var/lib/webjet"
log       = "info"

[listen]                      # addresses this node accepts connections on
kcp    = "0.0.0.0:4433"
anytls = "0.0.0.0:443"
tls    = "0.0.0.0:8443"

[[gateway.route]]             # which granted subnet routes to serve (§11.9.2)
published = "10.2.2.0/24"
interface = "eth1"

[time]
ntp_check = "pool.ntp.org"    # optional, for the clock check (§18.6)
```

- **Changes** to the local file take effect on a restart of the agent. Changes in the tree take effect as soon as the node has the new tree head.
- A local setting can only narrow what the tree grants: it can't give the node a route, role or tag the tree doesn't.

### 19.4 Local state

| Item | Back up? |
|---|---|
| Node identity key, encrypted at rest (§8.3) | No. A lost key is replaced by a re-key (§8.1) |
| Tree, certificates, PSK, camouflage material, cached relay endpoints | No. They re-sync |
| Unsent metric reports (§12.5) | No |
| Controller: Raft log and snapshots | **Yes** (§19.9) |
| Controller: online signing key | No. A lost key is retired and replaced (§22.1) |

The state directory is readable only by the agent's user, and `webjet-signer`'s key only by its own user.

### 19.5 Diagnostics

`webjetctl local` talks to the local agent over the control channel. Every local user may use it: it shows the network, and every change through it carries its own account, root or emergency signature, so the channel itself grants no rights. The signer's socket (§4.1) stays private to the agent's user.

| Command | Shows |
|---|---|
| `status` | The node's own record, home relays, tree version and age, clock offset, active alarms |
| `peers` | Neighbors, with the transport in use and each transport's measured cost (§9.6) |
| `route <node>` | The path in use and backups, with end-to-end cost (§11.4) |
| `sessions` | End-to-end sessions, the circuits ending here with their hops, round trip and the one in use, and the traffic of each route this node carries (§11.5, §12.3) |
| `conntrack` | Tracked flows (§14.4) with their state, the rule that admitted them and the circuit the peer's traffic takes |
| `topology` | The network graph as this node knows it: every node, and the links relays advertise, edge nodes' attachments and this node's own hops (§11.4) |
| `explain <src> <dst> <port>` | Which policy rule allows or denies the flow (§14.3) |
| `ping`, `trace <node>` | Reachability through the overlay, hop by hop |
| `dns <name>` | How the local resolver answers a name, and from which source (§11.10) |

### 19.6 Logging

- **Format:** structured JSON lines, to the platform's log service (§19.1).
- **Never logged:** identity keys, account keys, PSKs, enrollment tokens, the camouflage private key.
- **Rate-limited** per message type, so a flood of bad packets can't fill a disk.
- **Audit trail:** controllers export the record of signed operations (§13.3) separately, to append-only storage.
- Denied-flow samples (§14.6) and limit hits (§16.5) are logged at a low rate, for troubleshooting.

### 19.7 Alarms

Wherever this document says a node "raises an alarm", this is what happens:

1. The alarm is logged as an error.
2. It appears in `webjetctl local status`.
3. It is included in the node's metric reports while it stays active (§12.5), and reaches the metrics store as a gauge.
4. **Prometheus alert rules** fire on it, and Grafana shows and routes the alerts. Rule files and dashboards ship with the software. There is no other alert channel.

| Alarm | Severity |
|---|---|
| Equivocation detected (§21.3); a follower's result differs from the leader's (§15.5) | Critical |
| No Raft leader; voters below a majority plus one (§7.4) | Critical |
| Tree head expired, soft mode (§21.2); validity horizon less than 7 days away (§6.16) | High |
| Node software doesn't support the active StateVersion (§15.7) | High |
| Camouflage certificate expires in under 14 days (§9.7.2) | High |
| Clock offset above 30 s (§18.6) | Medium |
| Fewer than two seeds reachable (§10.7); relay overloaded for a long period (§11.8.4); repeated limit hits (§16.5) | Medium |

A node that can't reach any controller can't deliver its alarms. The metrics store therefore also alerts on **missing reports**: a node that should be online but hasn't reported (§12.6).

### 19.8 Upgrades

- **Order:** controllers, then relays, then other nodes.
- **Compatibility:** each release speaks the current and the previous wire protocol (§15.8) and reads the previous schema versions (§15.6), so a network can run mixed versions during a rollout.
- **Rollback:** binaries can be downgraded freely until the root activates a new StateVersion (§15.7). After activation, only forward.
- **Staged rollout:** by tag, watching software versions and alarms in the metrics store before continuing.
- **How new binaries reach nodes:** `webjetup` (§19.2), run on the node by an operator, or started remotely by an admin (below). It fetches the chosen release for the platform, checks it against the published SHA-256, replaces the installed programs and restarts the services. Nothing in the network tree controls software versions.
- Because every node runs what `webjetup` installs, **the release repository is the trust anchor for the software**. Installing a pinned tag, not "latest", keeps a rollout repeatable.

**Remote upgrades (from 0.9.0).** An admin can upgrade nodes without logging in to them: `webjetctl network node upgrade <version> <nodes | --tag | --all>`. This lets an admin key change the software on every node that allows it, which makes a stolen admin key (§21.13, ops guide 4.4) worth more. The design limits what such a key can do:

- **One signed request per node.** `UpgradeRequest { account_id, node_id, nonce, issued_at, expires_at, version, files }` is signed with the admin's account key (§13.2; normal accounts can't sign one). It names one node, lives at most an hour, and is accepted once. It is **not an operation**: it never enters the log and changes nothing in the tree. It goes from the admin's agent to a controller, which checks it and passes it to the node over the overlay (controllers reach every node, §14.4). Controllers pass it on one hop only, and nodes accept it only from a node of the network.
- **Pinned files.** `files` holds the SHA-256 of every platform's release archive and `webjetup`, which `webjetctl` reads from the release when it signs. The node installs only files with those exact checksums, so whoever controls the release server later can't change what gets installed. A compromise of the release server *before* signing still gets through, as it does for manual upgrades.
- **Forward only.** The version must be newer than the running one; a request can't downgrade a node to a release with known bugs.
- **Checked twice, by the agent and by a separate root helper.** The agent (unprivileged on Linux) checks the request against its tree, where a revoked admin is invalid, and drops it into a spool directory. The **helper** (`webjetup apply-upgrade`, started by systemd/launchd/a Windows scheduled task when a request appears) doesn't trust the agent: it checks the signature itself against the network's root key and the node id that `webjetup` pinned when it set the helper up (`trust.json`; the admin's root-signed AccountRecord travels with the request), checks the version, expiry and replay, and downloads only the pinned files from the repository `webjetup` was installed with. An agent taken over by an attacker therefore can't make root install anything. The helper doesn't know about revocations after the record it is given; the agent's check covers that.
- **Rollback.** The helper keeps the previous programs. If the new agent doesn't report the new version on its control socket within two minutes, it puts them back and restarts. A broken node can't take another remote request, so this matters more than for manual upgrades. The result (`done`, `refused`, `failed`, `rolled_back`, `rollback_failed`) is kept in the helper's `status.json`, readable over the overlay (`webjetctl network node upgrade-status`). A rollback puts back every file it can and always starts the agent again. The helper's downloads end within 20 minutes (systemd stops it after 30); a helper cut short while replacing the programs leaves a mark, and its next start (at the latest at boot) finishes the upgrade if the new agent is complete and healthy, or rolls back.
- **`webjetup` updates itself here.** A remote upgrade also replaces `webjetup` with the release's (pinned too); otherwise fixes to it would never reach remotely-upgraded nodes. Manual `webjetup upgrade` still keeps the running `webjetup` (`install.sh` replaces it).
- **On by default, opt-out per node.** `webjetup install --no-remote-upgrade` removes the helper and sets `[upgrade] remote = false` in `webjetd.toml`, so both the agent and the missing helper refuse. Docker containers have no helper. A remote admin can't turn this back on.
- **Order.** `webjetctl` rolls out as above: controllers one at a time (learners, voters, the leader last), then relays, then the other nodes in batches (`--batch`), and waits for each stage to report the new version before the next. It stops at the first refusal, failure or timeout.

### 19.9 Backups

- **Controllers:** a daily snapshot of the controller state (`webjetctl network controller snapshot`, admin-signed request), encrypted with a passphrase held by the admins and stored away from the controllers. Restoring it (`webjetctl local controller restore`) makes a node of the snapshot the only voter of a new cluster; an operator does it by hand (§2, ops guide 4.1).
- **Offline computer:** an encrypted backup of the root and emergency revocation keys (§5).
- **Metrics store:** optional. Losing it loses history, never network state.
- **Other nodes:** nothing to back up (§19.4).

### 19.10 Runbooks

The Operations Guide has a step-by-step procedure for each of these, grouped into accounts, nodes, maintenance and emergencies:

| Runbook | Main references |
|---|---|
| Create, revoke and re-key accounts (members and admins) | §13.1, §13.4, §13.5, §13.6 |
| Bootstrap a new network | §13.5, §7.5 |
| Add data, relay, control and gateway nodes | §8, §4, §7.5, §11.9 |
| Revoke or re-key a node | §22, §8.1 |
| Replace a lost voter | §7.4, §7.5 |
| Retire a controller's signing key | §22.1 |
| Rotate the PSK | §7.6 |
| Renew or replace the camouflage certificate | §9.7.2 |
| Upgrades, and a release with a schema change | §19.8, §15.7 |
| Change the network or a node's configuration, tags and roles | §6.7, §6.19, §14 |
| A majority of voters is lost: what to do, and by when | §7.4, §6.16 |
| Revoke without a controller majority | §22 |
| A compromised controller, admin account or root key | §21.18, §13.6, §5 |

---|---|
| Bootstrap a new network | §13.5, §7.5 |
| Add a relay | §8, §4 |
| Add a controller and promote it to voter | §7.5 |
| Replace a lost voter | §7.4, §7.5 |
| Rotate the PSK | §7.6 |
| Renew or replace the camouflage certificate | §9.7.2 |
| Revoke a lost device or an account | §22, §13.4 |
| Re-key a reinstalled node | §8.1 |
| Retire a controller's signing key | §22.1 |
| Roll out a release with a schema change | §15.7, §19.8 |
| A majority of voters is lost: what to do, and by when | §7.4, §6.16 |

---

## 20. Testing

### 20.1 Principles

1. **Every claim in Attack Mitigations (§21) has a test** that mounts the attack and checks the defense.
2. **Every parser of untrusted input is fuzzed.**
3. **Logic is tested deterministically** wherever possible, with simulated networks and clocks, so failures can be replayed.
4. **The targets and budgets of §18 are asserted,** not just measured.

### 20.2 Test levels

| Level | What it covers |
|---|---|
| Unit and property tests | Individual algorithms (§20.3) |
| Golden vectors | Byte-exact encodings and derivations (§15.6) |
| Fuzzing | Every decoder and packet path that handles untrusted bytes (§20.4) |
| Deterministic simulation | Controllers, gossip and routing under simulated networks, faults and clocks (§20.5) |
| Network emulation | Real binaries in Linux network namespaces with shaped links and NATs (§20.6) |
| Security tests | One per attack in §21, plus active probing and fingerprint checks (§20.7) |
| Platform tests | The agent on Linux, macOS and Windows (§20.8) |
| Upgrade tests | Mixed versions and StateVersion activation (§20.8) |
| Scale, soak and chaos | The design target and the "should keep working" size (§20.9) |
| Performance benchmarks | The behavior targets of §18.2, tracked per release |

### 20.3 Unit and property tests

| Area | Properties checked |
|---|---|
| Merkle tree (§15.4) | Inclusion and absence proofs verify; any changed bit breaks a proof; a leaf can't pass as an internal node |
| Policy (§14.3) | Deny always wins; rule order never changes a result; each node's compiled tables agree with direct evaluation of the rules |
| Selectors (§14.2) | Names and keys never collide; `cidr:` is rejected in `src` |
| State machine (§7.2, §15.5) | Replicas given the same log produce the same tree root; uniqueness and reference checks hold after any operation sequence |
| Transport choice (§9.6) | Priority 0 always excludes; lowest cost wins; near-ties go to the higher priority sum |
| Routing (§11.4, §11.8) | Cost and load penalty are monotonic; a full relay is never chosen for a new path |
| Replay window, connection tracking (§9.4.4, §16.3) | No frame accepted twice; eviction order is respected |
| Subnet mapping and DNS rewriting (§11.9, §11.10.5) | Host bits preserved; mapping then unmapping gives the original address |
| Queueing and FEC (§17) | Queue delay stays near the CoDel target; parity is counted inside the paced rate |

**Golden vectors** cover every message type and schema version, the signed envelope, each BLAKE3 derivation, the E2E frame, the relay frame and the obfuscated UDP datagram.

### 20.4 Fuzzing

Every target must either reject its input or accept it and round-trip its values exactly (§15.6), and must never crash, hang or exceed its limits (§16).

- FlatBuffers verification and semantic validation, for every message type (§15.2)
- The signed envelope, E2E frames and relay frames
- The UDP datagram path and the TCP PSK preamble (§9.1, §9.7.3)
- The first bytes of an AnyTLS connection, including the hand-off to the website (§9.7.2)
- Enrollment and re-key requests (§8)
- The local DNS resolver, including forwarded answers to rewrite (§11.10)
- Inner IP packets at the endpoint and gateway: cryptokey routing, NAT, and ICMP errors with embedded headers (§9.5, §11.9.4)
- The policy, DNS and limits configuration parsers

### 20.5 Deterministic simulation

The controller state machine, Raft, gossip and path selection run against a simulated network and clock, with a seed that reproduces any failure.

- **Controllers:** leader loss, voter loss, partitions, slow links, learners catching up, membership changes, a controller on an older StateVersion halting instead of diverging (§15.7), a follower detecting bytes that don't match its own result (§15.5).
- **Gossip:** convergence in the core and at the edge within the target of §18.2; a home relay that withholds updates (§10.6.4); two conflicting tree heads (§21.3); nodes returning after long absences (§10.5, §10.7).
- **Routing:** relay failure and reroute time; load spreading without oscillation (§11.8.3); transport switching when one transport degrades (§9.6).
- **Clocks:** skewed and jumping clocks on nodes and controllers; the trusted floor; the two-peer rule (§18.6).

### 20.6 Network emulation

Real binaries run in Linux network namespaces, with links shaped for delay, jitter, loss, reordering and rate.

- **Topologies:** direct, one relay, three relays, several gateways for one prefix.
- **Link profiles:** clean LAN, lossy long-distance (1–10% loss, 150–300 ms), throttled UDP, blocked UDP.
- **NAT types:** consistent, symmetric on one side, symmetric on both sides, and two nodes on one LAN (§11.7).
- **Congestion:** the KCP rate controller and adaptive FEC against each link profile; fairness with an ordinary TCP flow on the same bottleneck; queue delay under overload; an ECN mark carried from a relay to the inner packet (§17).
- **MTU:** the default tun MTU fits through every transport, including obfuscation overhead (§9.4.7, §9.7.3).

The rate controller and FEC are also tried on **real long-distance links** before each release that changes them, because emulation doesn't capture how real networks throttle.

### 20.7 Security, probing and fingerprint tests

- **One test per attack in §21.** Each mounts the attack with a modified node or relay and checks the stated defense. Examples: a rolled-back tree, a frozen head, forged or replayed operations, a DATA node advertising as a relay, a spoofed inner source address, a client that skips the policy check, a relay that reports false load, an old-PSK node trying to leave bootstrap mode.
- **Active-probe harness.** It connects to every listener with garbage, truncated handshakes and replayed captures, and checks the response:
  - UDP and plain TCP+TLS: nothing is sent back
  - AnyTLS in `WEBSITE` mode: indistinguishable from a reference web server serving the same site, including timing before the first reply
  - AnyTLS in `REFUSE` mode: the connection closes
- **Fingerprint checks**, run regularly so drift is noticed:
  - the AnyTLS ClientHello matches a capture from the current Chrome release
  - UDP datagrams have no constant bytes or fixed positions
  - packet sizes and timing at session start follow the padding scheme (§9.7.4)

### 20.8 Platform and upgrade tests

- **Platforms:** on Linux, macOS and Windows, a DATA node installs, enrolls, brings up its interface and routes, applies split DNS, stores its key, survives sleep, resume and a change of network, and removes everything on uninstall (§19.1).
- **Upgrades:**
  - a network running the current and previous releases together passes the emulation suite
  - a full StateVersion rollout: readers first, activation by the root, old versions dropped (§15.7)
  - a downgrade before activation works, and a node too old for the active StateVersion raises its alarm (§19.7)

### 20.9 Scale, soak and chaos

| Run | Size | Checks |
|---|---|---|
| Design target | ~100 nodes, 16 relays, 16 controllers (5 voters) | Every budget in §18.3 and every target in §18.2 |
| Upper bound | 1,000 nodes, 64 relays | The network converges and stays within resource limits (§16) |
| Soak | Design target, 7 days, with nodes joining, leaving, sleeping and re-keying | No growth in memory, table sizes or control traffic |
| Chaos | Design target | Killing the leader, killing voters down to a minority, partitions, clock jumps, relay loss, a full PSK rotation, a camouflage certificate change |

### 20.10 When tests run

| Stage | Tests |
|---|---|
| Every change | Unit, property, golden vectors, short fuzzing, deterministic simulation |
| Nightly | Long fuzzing, the emulation matrix, security tests, probe and fingerprint checks |
| Before a release | Platform matrix, upgrade tests, scale, soak and chaos, performance benchmarks, real-link trials where §17 changed |

A release is blocked by any failing security test, any golden-vector change without a schema version bump (§15.6), or a missed target in §18.2.

---

## 21. Attack Mitigations

### 21.1 Rollback (a peer serves an older state)

- **Defense:** persist the monotonic `SignedTreeHead.version` and reject any lower version.
- **Merkle role:** the version covers the whole node list atomically.

### 21.2 Freeze (a peer withholds updates)

- **Defense:** `expires_at` on the SignedTreeHead, plus fan-out: query several peers for their latest head.
- Because any surviving controller re-signs heads (§7.3), heads expire only when **no** controller is reachable, or when a peer is withholding them.
- **Policy when the head has expired: soft mode.**
  - Keep operating on the last known state.
  - Raise an alarm.
  - Don't accept new nodes or changed NodeRecords until a fresh head arrives. Offline-signed tombstones are still accepted, since they only reduce trust.
  - EndpointRecords, LinkStateAdverts and AttachmentRecords (self-signed by existing nodes) are still accepted, so addresses and routing keep up with changes.

### 21.3 Split view / equivocation (different states under the same version)

- **Defense:** gossip SignedTreeHeads. Honest controllers always sign the same root for the same version (§7.3). Two valid heads with the same version and different roots prove that at least one signing key is compromised, or that a controller has a serious bug.
- **Response:** alarm, reject both, and freeze tree updates. The conflicting heads name their signers. The admin compares them with the committed log on the other controllers to identify the misbehaving key, then retires it (§22.1).
- Equivocation detection is the chosen level of protection. An append-only log with consistency proofs is not used.

### 21.4 Hidden revocation

- **Defense:** sparse Merkle proofs. A peer can prove that a `node_id`'s leaf is a tombstone, or that the node is absent. Offline-signed tombstones are standalone and spread by priority gossip.

### 21.5 Address spoofing

- **Defense:** cryptokey routing at the endpoint, using the end-to-end authenticated source (§9.5), with IP uniqueness enforced by the state machine (§7.2).

### 21.6 Probing, traffic classification and DoS

- **Defense:**
  - The PSK gate on every transport (§9.1): silent drop on UDP, a closed connection on plain TCP+TLS, and on AnyTLS the camouflage website (or a closed connection in `REFUSE` mode).
  - AnyTLS presents a browser's ClientHello, and UDP datagrams have no cleartext structure (§9.7.2, §9.7.3).
  - Padding and jitter blur handshake sizes and periodic traffic (§9.7.4).
  - The limits are listed in §9.7.5.

### 21.7 Capability forgery (a DATA node poses as a relay or controller)

- **Defense:**
  - `RELAY` and `DATA` are in the NodeRecord, which is authenticated through a controller-signed tree head.
  - `CONTROL` needs the role in the record and a SigningKeyCert signed by an admin or the root.
  - Adverts and circuits involving nodes without `RELAY` are rejected.

### 21.8 Lying relay (false link metrics or traffic reports)

- **Defense:**
  - A link is used only if both ends advertise it, at the higher cost (§11.2).
  - Paths are chosen by measured end-to-end performance (§11.4).
  - Relayed-byte counts are cross-checked against neighboring hops (§12.7).
  - Advertised load is compared with reported relayed bytes, and only ranks candidates; measured end-to-end performance decides (§11.8.6).

### 21.9 Relay abuse (resource exhaustion)

- **Defense:** signed circuit setup from authenticated sources, and per-source circuit and bandwidth limits (§11.6).

### 21.10 Relays reading traffic

- **Defense:** end-to-end encryption between source and destination (§9.4). Relays see only `route_id`, `src`, `dst`, and ciphertext.

### 21.11 Misleading hole punching

- **Threat:** a malicious relay reports a wrong `observed_addr`, or an attacker tries to inject candidates.
- **Defense:**
  - Observed addresses arrive inside authenticated hop sessions, and a node compares them across several relays.
  - Candidates are exchanged only inside the end-to-end session (§11.7).
  - A direct hop still needs the PSK gate and the full hop handshake, so a wrong address can only make punching fail. Traffic then stays on the relayed route.

### 21.12 Forged or replayed operations

- **Threat:** someone on the overlay reaches a controller and submits operations, or replays an old one.
- **Defense:** controllers apply an operation only with a valid signature from an account allowed to make it, and per-account `op_seq` stops replays (§13.3). Reaching the admin endpoint is not enough.

### 21.13 Privilege escalation through accounts or tags

- **Threat:** a person tags their own node `tag:admin`, makes their account an admin, or an admin creates a second admin.
- **Defense:** tags, owners and roles change only through admin-signed operations (§14.1); normal accounts can only rename or tombstone nodes they own (§13.3); admin accounts can be created only by the root (§13.2).

### 21.13a Abuse of remote upgrades

- **Threat:** a stolen admin key, a compromised agent, or a compromised release server is used to run attacker-chosen software as root on nodes through remote upgrades (§19.8).
- **Defense:** a request is admin-signed, for one node, valid for at most an hour, used once, and only to a newer release. It pins the checksums of the release files when the admin signs it, so the release server can't swap files afterwards. The root helper checks it again on its own against the root key and node id it pinned at install, so taking over the agent's user isn't enough. A node can opt out (`webjetup install --no-remote-upgrade`), and a remote admin can't turn that back on.
- **Residual risk:** an attacker who holds an admin key **and** controls the release server can upgrade every node that allows it to their own build. Admins are as trusted as controllers (§13.2); the release repository is the software's trust anchor (§19.8). Nodes whose compromise would cost most can opt out.

### 21.14 Abuse of self-service

- **Threat:** a normal account renames a node to impersonate another node's name in rules, or tombstones someone else's node.
- **Defense:** controllers accept `RenameNode`, `TombstoneNode` and `RekeyNode` from a normal account only for nodes it owns, and names are unique, so a taken name can't be claimed. `node:<name>` rules follow renames; rules that must not move with a rename use `node:<base64 key>` (§14.2), which changes only with a re-key or rotation and is then flagged by the validator.
- **Re-key by an owner** gives the new installation only the node's existing name, IPs, tags, roles and routes, so it can't widen anyone's access (§8.1).

### 21.15 Withholding by home relays and bootstrap abuse

- **Threat:** a home relay hides updates from its edge nodes; or someone uses an old PSK to get past a seed relay's gate.
- **Defense:**
  - Edge nodes compare tree heads across their home relays and query a third relay when both look stale (§10.6.4). Relays can't forge anything they carry.
  - Bootstrap mode allows only state sync and reaching a controller, and only after the full hop handshake with a valid node key (§10.7.3).

### 21.16 Rogue subnet routes

- **Threat:** a node tries to attract traffic for a LAN it doesn't front, or to inject packets with LAN source addresses.
- **Defense:**
  - Only admins grant routes, and a node's `serving` list is honored only within its grants (§11.9.2).
  - Packets with a LAN source address are accepted from a gateway only as replies on a tracked flow the receiving node started (§9.5).
  - Gateways always SNAT and accept from the LAN only replies to tracked flows, so a LAN host can't reach into the overlay.

### 21.17 Bypassing the policy

- **Threat:** a node runs modified software that skips the source-side check.
- **Defense:** the destination enforces the policy using the end-to-end authenticated source identity (§14.4), and relays refuse circuits between nodes that may not talk. Skipping the source check gains nothing.

### 21.18 Compromised controller (outside the threat model)

Controllers are trusted: admins and the root key grant `CONTROL` only to trusted computers (§2), and the design does not try to contain a compromised controller. This section records what the impact would be, and the remedy, in case that assumption is ever broken.

- **Threat:** an attacker obtains one controller's signing key, or takes over a controller.
- **What it can do:** any valid controller key can sign a tree head over any root. The attacker can therefore present nodes with a forged node list: add rogue nodes, change IPs or roles, or leave out tombstones. As a Raft member (and especially as leader) it can also commit forged operations that honest controllers will apply.
- **What it cannot do:** certify other controllers' signing keys (that needs an admin or the root key), forge self-signed records of other nodes, forge account records (they carry their own root or admin signature, §6.10), or read end-to-end traffic.
- **Detection:** a forged head competes with honest controllers' heads for the same versions, so gossip exposes it as equivocation (§21.3) once both reach the same node.
- **Response:** retire the key with a SigningKeyTombstone (§22.1) and remove the controller from the cluster (§7.5).
- This is the accepted trade-off of this design: automatic failover with simple controllers, relying on controllers being trusted. Admitting only trusted computers, isolating the signing key (§4.1) and hardening controller hosts are what keep the assumption true.

---

## 22. Revocation Policy

| Parameter | Suggested value | Trade-off |
|---|---|---|
| `Validity.valid_until` | 30 days ahead, extended daily (§6.16) | Tolerance for a full controller outage vs. how long a stale tree stays trusted |
| `SignedTreeHead.expires_at` | 24–72 h, re-signed hourly by every controller | How soon a freeze is detected vs. outage tolerance |
| `EndpointRecord.expires_at` | About 10 min, re-published before expiry | How fast stale addresses disappear vs. gossip volume |
| Clock skew tolerance | ±60 s at the PSK gate, ±2 min for short-lived records and signed operations, ±5 min for tree heads and validity (§18.5) | Robustness vs. replay window |

- **Normal path:** an admin submits `TombstoneNode` through any controller; once committed, the tombstone spreads through gossip.
- **No controller majority available:** admins sign a Tombstone with the emergency revocation key (or root key) and inject it at any node.
- When a node is tombstoned, relays tear down all circuits where it is the source or destination, and its routing adverts are discarded.
- **Accounts:** tombstoning an account revokes every node it owns (§13.4). Admins can tombstone normal accounts; admin accounts need the root or emergency revocation key, which can also inject the tombstone standalone when no controller majority is available.

### 22.1 Retiring a controller's signing key

A controller's key is retired when the controller is decommissioned, has died and won't return, or is suspected of compromise. The other controllers keep running throughout.

1. On the offline computer, the admin signs a **SigningKeyTombstone** with the root or emergency revocation key.
   - For a decommissioned or dead controller: `last_valid_version` = the latest version it signed.
   - For a compromised one: `last_valid_version` = the last version known to be legitimate.
2. The admin injects the tombstone at any node or controller. It spreads by priority gossip.
3. Each node that accepts it:
   - rejects every head from that key with `version > last_valid_version`, and discards state known only through those heads
   - if the key was compromised and may have signed inflated versions, resets its high-water mark to the highest version signed by any **still-valid** controller key. This is the only permitted rollback.
   - removes `CONTROL` from the controller named in the retired cert, unless it holds another valid cert
   - (an admin's revocation or key change voids the certs it signed in the same way, §6.5; heads from those keys are no longer accepted)
4. The admin removes the controller from the Raft cluster (§7.5). If the cluster needs its full size back, a replacement controller is added the normal way.

No state has to be rebuilt: the remaining controllers already hold the full committed log, and every node already holds the full tree.

---

## 23. Rejected Alternatives

**Trust and keys**

- **Network PSK as identity:** a single compromised node leaks it for the whole network.
- **Per-pair PSKs:** the number of secrets grows quadratically, and they add nothing beyond what the keys already provide.
- **WebPKI / hostname verification:** unsuitable for overlay identities and camouflage modes.
- **Unsigned gossip of node lists:** would let any peer inject nodes.
- **Admin copying private keys to nodes:** breaks the rule that private keys never leave their node.
- **Self-signed X.509 certs:** unnecessary, because the target rustls version supports raw public keys.
- **Hard mode on tree-head expiry:** a full controller outage would take the whole network down.
- **Append-only transparency log:** more machinery than needed; equivocation detection is sufficient.
- **HSM or M-of-N custody for root keys:** rejected in favor of a single admin's offline computer, for simplicity.
- **External PSK mixed into TLS (`psk_dhe_ke`):** not needed; hybrid post-quantum key exchange covers the post-quantum concern.
- **Periodic rotation or expiry of controller signing keys:** rejected. Keys are permanent and end only through a SigningKeyTombstone, which avoids scheduled ceremonies with the offline root key.
- **Per-controller signatures on individual records:** would make the controllers' trees differ; records are authenticated by inclusion proofs instead.

**Controllers**

- **Independent controller domains** (each controller owning a set of nodes and IP ranges): contains a compromised controller to its domain, but a dead controller needs a manual succession step. Rejected in favor of automatic failover.
- **Unsigned admin operations (trusting whoever reaches the admin UI):** anyone on the overlay could act as an admin, and changes couldn't be attributed. Replaced by signed admin operations (§13.3), which give authentication and an audit trail. (They don't stop a compromised controller from signing forged heads, but controllers are trusted.)
- **Multisignature tree heads** (a majority of controllers must sign the same head): would contain a compromised controller, but heads would then need a majority alive to stay fresh. Not needed, because controllers are trusted (§2).
- **Threshold signing of tree heads (FROST):** would contain a compromised controller, at the cost of distributed key generation and signing rounds. Not needed, because controllers are trusted.
- **Byzantine fault-tolerant consensus:** much heavier than Raft, and not needed with trusted controllers.
- **Putting node liveness in the log:** nodes couldn't come online without a controller majority, and the log would be flooded with churn.
- **Refreshing only recently seen nodes:** "recently seen" differs between controllers unless it is itself committed, and honest nodes offline for a month would need re-enrollment.

**Encoding and versioning**

- **Deterministic CBOR:** canonical by construction, but FlatBuffers was preferred for zero-copy reads and its schema tooling. Canonical form is not needed, because bytes are never re-encoded (§15.1) and controllers copy the leader's bytes (§15.5).
- **Protobuf, bincode, Borsh, canonical JSON:** respectively not canonical with awkward unknown-field handling, unspecified and tied to Rust layout, unable to evolve, and slow with error-prone numbers.
- **Each controller serializing its own leaves:** would require byte-identical serializers across versions; copying the leader's bytes through the log removes that requirement.
- **Critical/non-critical field ranges (adding fields without a version bump):** every schema change bumps the version instead, so a reader never has to guess what an unknown field means.
- **State-version upgrades by an admin:** a bad upgrade can stall the cluster or strand nodes, so it needs the root key.
- **SHA-256:** BLAKE3 is faster and has built-in key-derivation and keyed modes, which give domain-separated IDs without extra constructions.

**Accounts and access control**

- **Admins able to create other admins:** a single compromised admin could create more admins and survive its own revocation. Only the root creates admins.
- **`account_id = hash(account_key)`:** replacing a lost key would change the account's ID and break ownership and policy references. IDs are random instead.
- **Allow-only policy:** simpler, but can't express exceptions such as "admins everywhere, except SSH to production databases".
- **Ordered, first-match rules (firewall style):** more expressive, but a rule's meaning depends on its position, which makes changes risky to review. Deny-overrides is order-independent.
- **Enforcing the policy only at the source:** a modified client could ignore it. The destination is authoritative.
- **Tags set by the node or its owner:** tags grant access, so only admins may set them.
- **`node_id = hash(identity_key)`:** a reinstall would change the node's identity and break its rules, records and history. `node_id` is random instead (§8.1).
- **Re-key only by admins:** a re-key restores exactly what the owner already has, so owners may do it too.
- **Every key change through an admin:** node-initiated rotation (signed by old and new keys) makes routine rotation and moving keys into hardware storage possible without admin work.
- **Non-exportable hardware Ed25519 keys:** most TPMs and secure enclaves can't sign with Ed25519; the key is encrypted at rest by a hardware- or OS-protected key instead.
- **Scoped admins** (for example managing only `tag:lab` nodes): all admins are equal, which keeps the permission model simple.
- **Self-service enrollment or re-tagging by normal accounts:** both decide access, so they stay with admins.
- **Web UI signing only through the admin tool:** less convenient; the UI prompts for the key and signs in the browser instead.

**Subnet routes**

- **Exit nodes (routing internet traffic):** not needed for this deployment, and they bring routing-loop, kill-switch and DNS-leak problems on every client.
- **Optional no-SNAT mode:** would let LAN hosts see overlay source IPs and connect back, but needs routes on every LAN and fails over badly with several gateways. Gateways always SNAT.
- **Application-level gateways for mapped routes** (FTP, SIP): complex and rarely needed.
- **Owner-granted routes:** a route attracts other people's traffic, so only admins grant routes.

**Testing**

- **Testing consensus and gossip only with real processes and real time:** failures can't be reproduced. A deterministic simulation with a seed can replay them.
- **Emulation alone for congestion control:** it doesn't capture how real networks throttle, so real long-distance links are tried as well.
- **Checking the AnyTLS fingerprint once:** browsers change; the check runs regularly against the current release.

**Operations**

- **A self-updater built into the agent,** with a root-certified release key and target versions set in the tree: more machinery than this deployment needs. Upgrades are started by an operator on the node or by an admin's signed per-node request (§19.8), carried out by `webjetup`, not by the agent.
- **Remote upgrades as a tree operation** (a version target in the tree that nodes follow): durable and audited, but every node would act on one admin signature at once. A per-node request with a short lifetime, rolled out in order by the admin's tool, limits a mistake or a stolen key to the nodes it is signed for, within the hour.
- **Runbooks inside this document:** they change with tooling more often than the architecture does. They live in a separate Operations Guide.
- **A direct alert channel from controllers (webhooks):** Prometheus alert rules with Grafana are enough, and add no new component.
- **Network-wide settings in local files:** every node would need editing by hand, and nodes could disagree. Shared settings are in the tree.
- **Controllers, relays and gateways on every platform:** triples what must be built and tested for roles that run on servers anyway.

**Congestion control**

- **Congestion control in the end-to-end session as well:** it would fight the inner flows' own control and the hops'. Inner flows control congestion; hop queues give them the signal.
- **Large buffers on reliable hops:** turn congestion into seconds of delay. Hop queues are short and managed.
- **KCP's built-in congestion window:** backs off on every loss, so it collapses on lossy links.
- **KCP with no congestion control (fixed windows):** unfair to other traffic, causes its own loss, and invites throttling.
- **A fixed FEC ratio:** wastes capacity on clean links and is too little on bad ones.
- **Signalling congestion only by dropping:** ECN-capable flows can slow down without loss if relays can mark frames.
- **Parallel connections per hop to avoid head-of-line blocking:** more state, and unlike a browser on AnyTLS.

**Transports and obfuscation**

- **rustls for the AnyTLS outer layer:** its ClientHello matches no browser, so it stands out among HTTPS traffic. BoringSSL can match Chrome's.
- **A domain, certificate and website per relay:** relays couldn't be linked to each other by certificate, but each would need its own domain and certificate to operate. One set for the whole network was chosen.
- **Accepting any outer certificate on the client:** an active attacker could terminate the connection and capture the credential. Clients pin the network certificate's key.
- **A cleartext PSK-gate header and cleartext KCP headers on UDP:** recognizable with one rule. Every datagram is encrypted whole.
- **Imitating QUIC on UDP:** a careful observer can tell an imitation from the real protocol.
- **Restricting plain TCP+TLS to trusted links by rule:** replaced by per-node priorities; a node that must avoid it sets its priority to 0.
- **Choosing the transport by priority sum alone:** ignores how each transport actually performs on a given path. Priority now excludes transports and breaks near-ties; measured cost decides.
- **Advertising all three transports' metrics in link-state adverts:** triples their size, and sources don't need it, because each hop picks its own transport. Per-transport metrics still go to controllers in metric reports (§12.3).

**Scale and time**

- **Per-record expiry (`not_after` on every NodeRecord):** the daily refresh rewrote every leaf of the tree. One validity leaf has the same meaning and changes one leaf.
- **All 8–16 controllers as Raft voters:** every write would need more acknowledgements over wide-area links, and even counts add no fault tolerance. Five voters plus learners gives the same availability for reads, signing and enrollment.
- **Refreshing link-state adverts every 15–30 s:** they are pushed to every edge node, so unchanged adverts dominated idle traffic. Neighbors detect a dead relay in seconds anyway.
- **Absolute start time for hole punching:** needs clocks agreeing to tens of milliseconds. Timing from message arrival and measured RTT needs no clock.
- **Correcting a node's timestamps from relay time:** would make time depend on peers. The system clock is the only source; a node that is far off exits.
- **Exiting on one peer's report of clock skew:** a single relay with a bad clock could shut down its edge nodes. Two agreeing peers are required.

**Load-aware routing**

- **Routing on RTT and loss only:** the best relay attracts every route until it saturates, then everyone moves at once.
- **Moving established circuits whenever load changes:** causes oscillation and reordering for tunnelled TCP. Load affects only new choices, unless a relay is full.
- **Always choosing the single best path:** concentrates new circuits on one relay. Near-equal candidates are chosen at random, weighted by spare capacity.
- **Monthly transfer-quota awareness:** not needed for this deployment.

**Resource limits**

- **Unbounded tables with only global caps:** one peer could fill a whole table. Every table has a per-peer quota too.
- **Evicting the oldest flows first, regardless of state:** a flood of new connection attempts would push out established connections. Half-open and one-way flows go first.
- **Replying to refused flows (TCP RST or ICMP from the destination):** would let limits be used to make nodes send traffic. Refusals at the destination are silent.
- **Only per-node local configuration of limits:** every busy gateway or relay would need manual tuning on the machine; tag-based overrides in the tree do it once.
- **Per-node overrides in each machine's `webjetd.toml`** (as before 0.4.0): unsigned and unaudited, invisible to admins and other nodes, lost on a reinstall, and only changeable on the machine itself. They are node configurations in the tree now (§6.19).
- **One operation and version per setting** (`SetPolicy`, `SetDns`, … before 0.4.0): a change touching two settings was two commits that nodes could see half of, and five versions had to be tracked and raised by hand. The network configuration is one document with one version (§6.18).

**Gossip and discovery**

- **Full-mesh gossip between all nodes:** costs every phone N−1 messages a second and every node every address change in the network. Edge nodes sync only with home relays.
- **Edge nodes gossiping with each other:** more paths for updates, but no node can then rely on a small, known set of sources; relays already have everything.
- **Pushing every edge node's endpoint records to every edge node:** most nodes never talk to most others; lookups and subscriptions fetch only what is needed.
- **Seeds only as IP literals:** relays could never change IP without a tree update; DNS hostnames are safe because identity is checked by the handshake.
- **Rejecting stale-PSK nodes outright:** a node offline through several rotations would need manual help to rejoin. Bootstrap mode limits what such a session can do instead.

**DNS**

- **A central DNS server on the controllers:** names would stop resolving when controllers are unreachable. Each node resolves locally from the tree instead.
- **Filtering magic DNS answers by policy:** every node already has the whole tree, so it hides nothing; the policy controls access.
- **Taking over all of the system's DNS:** used only as a fallback where the OS has no split DNS; otherwise only overlay zones go to the local resolver.
- **DNSSEC validation of rewritten answers:** impossible by design, since rewriting changes signed data.

**Routing**

- **Distance-vector routing (e.g. Babel):** each hop re-advertises derived numbers that others can't verify. With a small, trusted relay set, link-state is simpler and each node can only describe its own links.
- **Hop-by-hop forwarding:** allows transient loops while views converge and makes per-flow path choice hard. Source routing avoids both.
- **Routing metrics in the Merkle tree:** metrics change constantly and are short-lived; they don't belong in controller-signed, versioned state.
- **Relays able to read traffic:** rejected; traffic is encrypted end to end.
- **TLS or DTLS as the end-to-end data layer:** TLS breaks on frame loss and causes head-of-line blocking; rustls has no DTLS, so it would need a second TLS stack.
- **Noise for the end-to-end session:** hybrid post-quantum Noise isn't standardized, and it would need a second authentication path next to the rustls verifiers.
- **Hash-ratchet rekeying:** no forward secrecy against a later key compromise; a full handshake every 120 s is cheap enough.
- **Skipping the end-to-end session on direct paths:** saves one AEAD operation per packet, but needs a second endpoint-check code path and breaks seamless switching between direct and relayed routes.
- **TCP hole punching:** TCP simultaneous open through NAT is unreliable; hole punching uses UDP only.
- **Port prediction for symmetric NAT:** complex and unreliable; such pairs stay relayed.

**Accounting**

- **Per-interval delta counters:** a lost report would lose data. Monotonic counters don't.
- **Gossiping metric reports across the mesh:** costs bandwidth for no benefit; only controllers need them.
- **Counting only wire bytes:** overhead differs per hop, so route counts wouldn't be comparable along a path.
- **Metric reports as Raft operations:** high volume for no consistency benefit; the TSDB handles duplicates.

---

## 24. Resolved Decisions

| Question | Decision | Section |
|---|---|---|
| Behavior when the tree head expires | Soft mode | §21.2 |
| Transparency log vs. equivocation detection | Equivocation detection only | §21.3 |
| Raw public keys in rustls | Supported; used instead of certs | §9.2 |
| Gossip flooding | Relay only already-signed tree heads, rate-limited per peer | §10.3.1 |
| Root and emergency revocation key custody | Offline on one admin's computer | §5 |
| Post-quantum protection | Hybrid `X25519MLKEM768` only; no external PSK in TLS | §9.3 |
| Tree-head sync rate | Every 1 s within the core; one digest, then only differing heads and subtrees transferred | §10.3.1 |
| Multiple controllers | One Raft cluster of 8–16 controllers: 5 voters (odd, at most 7) and the rest learners, with automatic failover; each controller has its own permanent signing key and signs heads over the same committed state (Option A) | §7 |
| Controller signing key lifetime | Permanent; retired only by a SigningKeyTombstone signed by the root or emergency revocation key | §5, §6.6, §22.1 |
| What goes through the controller log | Enrollment, node and account changes, tombstones, policy and other tree settings, membership, PSK rotation, the daily validity extension | §7.2 |
| Node liveness | Soft state from expiring self-signed records; never in the controller log | §10.5 |
| Refreshing offline nodes | One validity leaf, extended daily, covers every non-tombstoned node regardless of liveness; records have no expiry of their own | §6.16, §7.2, §10.5 |
| Who may relay | Only nodes with the `RELAY` capability (public IP required) | §4 |
| Routing protocol | Link-state among relays; DATA nodes publish attachments | §11.1, §11.3 |
| Path selection | Source routing with circuits; chosen by measured end-to-end cost, with hysteresis | §11.4, §11.5 |
| Traffic accounting | Monotonic per-route counters of inner frame bytes at every hop | §12 |
| End-to-end session protocol | TLS 1.3 handshake (raw public keys, `X25519MLKEM768`) through the circuit, then exporter-derived keys for per-packet AEAD with counters and a replay window | §9.4 |
| NAT traversal | DATA nodes behind NAT try UDP hole punching, using relays as address reflectors and the e2e session for coordination | §11.7 |
| Metric reporting and storage | Push to the nearest controller; all controllers remote-write to one shared Prometheus-compatible store with out-of-order ingestion | §12.5 |
| Multi-capability nodes | Any combination allowed; roles are independent checks, with the specific uses and isolation rules in §4.1 | §4.1 |
| Compromised controllers | Outside the threat model: admins and the root grant `CONTROL` only to trusted computers. No multisignature or threshold signing | §2, §21.18 |
| Accounts | Every person has an account; every node has an owner account. Admin accounts are signed by the root only; admins sign normal accounts, never other admins | §13.1, §13.2 |
| Authentication and audit | Every operation is signed by the account that made it, with per-account sequence numbers; the log records who did what | §13.3 |
| Web admin UI | Prompts for the account key on every submit and signs in the browser; the key is never sent to the controller | §13.3 |
| Admin permission levels | None: all admins are equal | §13.2 |
| Self-service for normal accounts | May rename and tombstone nodes they own; may not enroll, re-tag or otherwise change nodes | §13.3 |
| Who may enroll nodes | Admins only; every enrollment names an owner account | §8, §13.3 |
| Account revocation | Revokes every node the account owns; for admins, optionally the accounts it signed (`revoke_issued`) | §13.4 |
| Access control model | Tag-based policy with allow and deny rules; deny overrides allow; order-independent; default deny | §14.3 |
| Selectors | `tag:`, `role:`, `node:` and `owner:` (names or base64 public keys), and `*` | §14.2 |
| Who may assign tags | Admins only | §14.1 |
| Enforcement points | Destination (authoritative), source (fail fast), e2e handshake and relay circuit admission | §14.4 |
| Serialization format | FlatBuffers, verified and semantically validated before use; signatures and hashes cover the exact received bytes, never re-encoded | §15.1, §15.2 |
| Identical controller output | The leader's serialized leaves travel in the log; followers check and copy them | §15.5 |
| Hash function | BLAKE3 for all hashes and derived IDs, with domain-separated contexts | §15.4 |
| Schema evolution | Every schema change bumps the version; no unknown-field handling | §15.6 |
| Upgrades | Root-signed StateVersion decides which schema versions are emitted and accepted and the minimum wire protocol | §15.7 |
| Subnet routes | Admin-granted, gateway-served; always SNAT; overlay-initiated connections only | §11.9 |
| Subnet mapping | 1:1 prefix mapping of a LAN to a different published prefix of the same length | §11.9.1 |
| Exit nodes | Not supported | §11.9 |
| Policy for subnets | `cidr:` selector on published addresses, destination only; gateway is the authoritative check | §14.2, §14.4 |
| Magic DNS | Every node resolves `<node-name>.<suffix>` locally from the tree; works offline | §11.10.2 |
| Overlay DNS | Admin-defined records and forwarded zones in a DnsConfig tree leaf; split DNS on the OS | §11.10.3, §11.10.4 |
| DNS for mapped subnets | The local resolver rewrites LAN addresses in forwarded answers to published addresses | §11.10.5 |
| Magic DNS suffix | Configurable; default `internal` | §11.10.2 |
| Gossip topology | Relays form the core and run anti-entropy; other nodes sync only with their home relays, by push plus keepalive-piggybacked digests | §10.6 |
| Core fan-out | Every core peer each second up to 64 relays; 4 random core peers per second above that; changes also pushed immediately | §10.3.1 |
| Home relays | 2 by default, at most 3; automatically the lowest-cost links | §6.8, §10.6 |
| Peer records at the edge | On demand through lookups and subscriptions | §10.6.2 |
| Peer discovery | Cached relay endpoints, then the tree's seed list (node name or key; hostnames or IPs), then enrollment seeds, then controllers | §10.7 |
| Stale PSK after long absence | Seed relays accept old epochs in bootstrap mode, limited to sync and reaching a controller | §10.7.3 |
| Node identity | Random `node_id` fixed for life; the identity key can change | §6.1, §8.1 |
| Re-keying | `RekeyNode` by an admin or the node's owner, redeemed like an enrollment; optional immediate revocation of the old key | §8.1 |
| Key rotation | Node-initiated `RotateNodeKey`, signed by old and new keys | §8.2 |
| Key storage at rest | Ed25519 key encrypted by a TPM, Keychain/Secure Enclave, DPAPI or Android Keystore key; device-bound | §8.3 |
| Disaster recovery of the controller cluster | Out of scope; rebuilt manually | §2 |
| Resource limits | Per-peer quota and global cap on every table; no state before authentication; limit hits counted | §16.1, §16.2 |
| Conntrack eviction | Half-open TCP, then one-way UDP, then longest idle | §16.3 |
| Configuring limits | Built-in defaults, overridden by a Limits tree leaf with tag-based overrides; highest matching value wins; clamped to the node's memory | §16.4 |
| Load-aware routing | Relays advertise smoothed, quantized load; convex penalty from 50%; full at 90% | §11.8.1, §11.8.2 |
| Relay capacity | Auto-estimated by default; local config or admin override takes precedence | §11.8.1 |
| Load damping | Load affects only new choices; randomized choice among near-equal paths; jittered re-evaluation | §11.8.3 |
| Overloaded relays | Refuse new circuits at 90%; existing circuits continue | §11.8.4 |
| Scale target | ~100 nodes, 8–16 relays, 8–16 controllers; should keep working to 1,000 nodes and 64 relays | §18.1 |
| Link-state refresh | Every 5 min, expiring after 15; changes sent immediately; dead relays removed by their neighbors within seconds | §11.3 |
| Hole-punch timing | No timestamps: responder starts on receipt, initiator half a round trip after sending | §11.7 |
| Clock requirements | Nodes within ±30 s of true time; controllers within ±1 s of each other; durations on the monotonic clock | §18.4, §18.5 |
| Wrong clocks | The system clock is the only time source; a node far off reports an error and exits. Needs two agreeing peers, or the trusted floor | §18.6 |
| Transport selection | All eligible transports are kept up and measured; each hop sends on the lowest-cost one. Priority 0 excludes a transport, and the priority sum breaks near-ties | §9.6 |
| Observer model | An actively probing, DPI-capable network is in scope | §9.7.1 |
| AnyTLS outer TLS | BoringSSL on both sides, with a Chrome-like ClientHello | §9.7.2 |
| Camouflage | One domain, certificate and website for the whole network, pinned by clients; optional: `REFUSE` mode closes failed connections instead | §9.7.2 |
| UDP obfuscation | Every datagram encrypted whole under a PSK-derived key, with a masked epoch ID; traffic moves to AnyTLS where UDP is blocked | §9.7.3, §9.6 |
| Plain TCP+TLS | Available everywhere, subject to priority; not hidden | §9.6, §9.7.1 |
| Who controls congestion | Inner flows; hops hide random loss; hop queues (fair queuing + CoDel) signal congestion | §17.1, §17.2 |
| KCP congestion control | BBR-style pacing, with an optional per-node rate ceiling | §17.5 |
| TCP hops | Kernel congestion control, BBR where available | §17.4 |
| FEC | Adaptive parity ratio, 0–30%, counted inside the paced rate | §17.6 |
| ECN through relays | Carried in two bits of the relay frame header; relays mark instead of dropping | §17.7 |
| Control traffic | Separate priority queue per hop | §17.3 |
| Platforms | Linux, macOS and Windows; controllers, relays and gateways on Linux; iOS and Android later | §19.1 |
| Programs | `webjetd` (agent; `signer`), `webjetctl` (`network`, `local`, `root`), `webjetup` | §19.2 |
| Configuration | TOML throughout. `webjetd.toml`: how one machine runs the agent. In the tree: the network configuration (one versioned document, admins) and each node's configuration (its owner or an admin) | §6.18, §6.19, §19.3 |
| Alarms | Logged, shown locally, carried in metric reports; alerting by Prometheus rules, viewed in Grafana | §19.7 |
| Runbooks | In a separate Operations Guide | §19.10 |
| Software updates | `webjetup` on the node, by an operator, or remotely by an admin's signed per-node request (pinned checksums, forward only, checked again by a root helper, automatic rollback, opt-out per node); no updater in the agent | §19.8 |
| Naming | The project and its programs are named Webjet; protocol labels use `webjet` | §15.3, §15.4, §15.8, §19.2 |
| Testing | Property tests, golden vectors, fuzzing of every parser, deterministic simulation, network emulation, one security test per attack, probe and fingerprint checks, scale and chaos runs | §20 |

## 25. Open Questions

None at this time.
