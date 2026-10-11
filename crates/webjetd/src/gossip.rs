//! Gossip (§10.3, §10.6, §11.3): tree-head exchange with Merkle anti-entropy,
//! priority flooding of offline-signed items, and the signed soft-state
//! records (EndpointRecords, LinkStateAdverts, AttachmentRecords).

use crate::node::{Event, Hop, Node};
use anyhow::{Result, bail};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use webjet_core::crypto::{self, Bytes32, opt_k32};
use webjet_core::protocol as proto;
use webjet_core::store::HeadOutcome;
use webjet_core::types::{MINUTE, SECOND, SKEW_SHORT_RECORD, now_ms};
use webjet_proto::{self as wp, HopMsg, Transport, msg_type as mt};

/// Unchanged LinkStateAdverts are refreshed every minute (§11.3), so the
/// graph and its delays stay current everywhere.
pub const LSA_REFRESH: u64 = MINUTE;
pub const LSA_LIFETIME: u64 = 5 * MINUTE;
pub const ENDPOINT_REFRESH: u64 = 5 * MINUTE;
pub const ENDPOINT_LIFETIME: u64 = 15 * MINUTE;
pub const ATTACH_REFRESH: u64 = 10 * SECOND;
pub const ATTACH_LIFETIME: u64 = 30 * SECOND;
/// How long a `topology` request keeps an edge node subscribed to every
/// node's AttachmentRecord, and how often the subscription is renewed.
const WATCH_FOR: Duration = Duration::from_secs(120);
const WATCH_RENEW: Duration = Duration::from_secs(60);
/// A link cost change of more than this share is advertised at once.
const LSA_CHANGE: f64 = 0.1;

/// One Merkle walk toward a newer head, run against one peer.
struct Walk {
    hop: u64,
    head_raw: Vec<u8>,
    root: Bytes32,
    /// The buckets that differ from ours, asked for with GetBucketIndex.
    buckets: Vec<u8>,
    removals: Vec<(u8, Bytes32)>,
    fetched: Vec<(u8, Bytes32, Vec<u8>)>,
    batches_left: usize,
    started: Instant,
}

/// A neighbor as advertised: (node, quantized RTT ms, loss %).
pub type LinkSummary = (Bytes32, u16, u8);

#[derive(Default)]
pub struct SyncState {
    walk: Mutex<Option<Walk>>,
    /// Per hop: when we last accepted a head from it (rate limit, §10.3.1).
    head_rx: Mutex<HashMap<u64, Instant>>,
    /// Relay side: edge peers' subscriptions: node → (subscriber hops, until).
    subs: Mutex<HashMap<Bytes32, Vec<(u64, Instant)>>>,
    lookup_rate: Mutex<HashMap<u64, (Instant, u32)>>,
    /// Per hop: sync requests (GetOffline, GetBuckets, GetBucketIndex,
    /// GetLeaves) answered in the current second.
    sync_rate: Mutex<HashMap<u64, (Instant, u32)>>,
    /// Last published own records, to republish on change.
    pub last_endpoint: Mutex<Option<(Vec<wp::EndpointAddr>, u64)>>,
    /// The links (neighbor, rtt, loss) last advertised, and when.
    pub last_lsa: Mutex<Option<(Vec<LinkSummary>, u64)>>,
    pub last_load_step: Mutex<u8>,
    pub last_attach: Mutex<Option<(Vec<Bytes32>, u64)>>,
    pub lookups_pending: Mutex<HashMap<Bytes32, Instant>>,
    /// Someone looks at the whole graph (`topology`) until then, and when
    /// the subscriptions to every node's records were last sent.
    watch_until: Mutex<Option<Instant>>,
    watch_sent: Mutex<Option<Instant>>,
}

fn head_msg(n: &Node) -> Option<HopMsg> {
    let s = n.store.read();
    let h = s.head()?;
    Some(HopMsg::HeadAnnounce(Box::new(wp::HeadAnnounce {
        head: Some(h.raw.clone()),
        offline_hash: Some(crypto::k32(&s.offline_hash())),
    })))
}

/// The core: relays and controllers, which keep full state and a mesh of
/// hops (§10.6). Without any relay every node is core.
pub fn is_core(n: &Node, id: &Bytes32) -> bool {
    let s = n.store.snapshot();
    let v = s.view();
    !v.any_relay
        || v.nodes.get(id).is_some_and(|x| x.relay || x.control)
        || (*id == n.me && n.is_controller())
}

/// Re-share infrastructure endpoint records with every neighbor, e.g. after
/// a node gained RELAY or CONTROL, so edges learn where to reach it.
pub fn share_infra(n: &Arc<Node>) {
    if !is_core(n, &n.me) {
        return;
    }
    let items: Vec<Vec<u8>> = {
        let s = n.store.snapshot();
        let v = s.view();
        let recs = n.records.lock();
        recs.endpoints
            .iter()
            .filter(|(id, _)| {
                v.nodes
                    .get(*id)
                    .is_some_and(|x| x.valid && (x.relay || x.control))
            })
            .map(|(_, (_, raw))| raw.clone())
            .collect()
    };
    if items.is_empty() {
        return;
    }
    let hops: Vec<Arc<Hop>> = n
        .hops
        .lock()
        .values()
        .filter(|h| h.alive() && !h.restricted)
        .cloned()
        .collect();
    for h in hops {
        send_records(&h, items.clone());
    }
}

pub fn on_hop_up(n: &Arc<Node>, hop: &Arc<Hop>) {
    if let Some(m) = head_msg(n) {
        hop.send_control(m);
    }
    // Our own records first, then what the peer should hold (§10.6.1).
    let mut items = own_records(n);
    let peer_core = is_core(n, &hop.peer);
    if !hop.restricted && (n.is_relay() || is_core(n, &n.me)) {
        let recs = n.records.lock();
        let s = n.store.snapshot();
        let v = s.view();
        for (id, (_, raw)) in &recs.lsas {
            if *id != n.me {
                items.push(raw.clone());
            }
        }
        for (id, (_, raw)) in &recs.endpoints {
            let infra = v.nodes.get(id).is_some_and(|x| x.relay || x.control);
            if *id != n.me && (peer_core || infra) {
                items.push(raw.clone());
            }
        }
        if peer_core {
            for (id, (_, raw)) in &recs.attachments {
                if *id != n.me {
                    items.push(raw.clone());
                }
            }
        }
    }
    send_records(hop, items);
}

fn own_records(n: &Node) -> Vec<Vec<u8>> {
    let recs = n.records.lock();
    let mut v = Vec::new();
    if let Some((_, raw)) = recs.endpoints.get(&n.me) {
        v.push(raw.clone());
    }
    if let Some((_, raw)) = recs.lsas.get(&n.me) {
        v.push(raw.clone());
    }
    if let Some((_, raw)) = recs.attachments.get(&n.me) {
        v.push(raw.clone());
    }
    v
}

fn send_records(hop: &Hop, items: Vec<Vec<u8>>) {
    for chunk in items.chunks(64) {
        hop.send_control(HopMsg::Records(Box::new(wp::Records {
            items: Some(
                chunk
                    .iter()
                    .map(|b| wp::Blob {
                        data: Some(b.clone()),
                    })
                    .collect(),
            ),
        })));
    }
}

pub fn on_digest(n: &Arc<Node>, hop: &Arc<Hop>, digest: Bytes32) {
    *hop.peer_digest.lock() = Some(digest);
    if digest != n.store.read().digest()
        && let Some(m) = head_msg(n)
    {
        hop.send_control(m);
    }
}

/// Push a new head (and offline items) to every peer immediately (§10.3.1).
pub fn push_head(n: &Arc<Node>) {
    if let Some(m) = head_msg(n) {
        n.broadcast_control(m, None);
    }
}

/// Sync requests a hop may make per second. A walk asks for 512 leaves
/// per GetLeaves, so this covers a tree of about half a million leaves in
/// one second; past it requests are dropped (the asker's walk times out
/// and starts over).
const SYNC_REQUESTS_PER_SEC: u32 = 1000;

/// Count a sync request from `hop`; false when it is over the rate.
fn sync_allowed(n: &Node, hop: &Hop) -> bool {
    let mut r = n.sync.sync_rate.lock();
    let e = r.entry(hop.id).or_insert_with(|| (Instant::now(), 0));
    if e.0.elapsed() > Duration::from_secs(1) {
        *e = (Instant::now(), 0);
    }
    e.1 += 1;
    e.1 <= SYNC_REQUESTS_PER_SEC
}

pub fn handle(n: &Arc<Node>, hop: &Arc<Hop>, m: HopMsg) -> Result<()> {
    if matches!(
        m,
        HopMsg::GetOffline(_)
            | HopMsg::GetBuckets(_)
            | HopMsg::GetBucketIndex(_)
            | HopMsg::GetLeaves(_)
    ) && !sync_allowed(n, hop)
    {
        bail!("sync request rate exceeded");
    }
    match m {
        HopMsg::HeadAnnounce(a) => on_head(n, hop, *a),
        HopMsg::GetOffline(_) => {
            let items = n.store.read().offline_items();
            hop.send_control(HopMsg::OfflineItems(Box::new(wp::OfflineItems {
                items: Some(
                    items
                        .into_iter()
                        .map(|b| wp::Blob { data: Some(b) })
                        .collect(),
                ),
            })));
            Ok(())
        }
        HopMsg::OfflineItems(o) => {
            let mut changed = false;
            for b in o.items.unwrap_or_default() {
                let raw = b.data.unwrap_or_default();
                match n.store.write().add_offline_item(&raw) {
                    Ok(true) => changed = true,
                    Ok(false) => {}
                    Err(e) => tracing::debug!("offline item rejected: {e}"),
                }
            }
            if changed {
                n.persist_store();
                n.emit(Event::HeadChanged);
                push_head(n);
            }
            Ok(())
        }
        HopMsg::GetBuckets(g) => {
            // Answer from the store, then send without holding its lock.
            let hashes = {
                let s = n.store.read();
                (opt_k32(&g.root) == s.tree().compute_root())
                    .then(|| s.tree().buckets().iter().map(crypto::k32).collect())
            };
            match hashes {
                None => hop.send_control(HopMsg::NotAvailable(Box::new(wp::NotAvailable {
                    root: g.root,
                }))),
                Some(h) => hop.send_control(HopMsg::Buckets(Box::new(wp::Buckets {
                    root: g.root,
                    hashes: Some(h),
                }))),
            }
            Ok(())
        }
        HopMsg::Buckets(b) => on_buckets(n, hop, *b),
        HopMsg::GetBucketIndex(g) => {
            let entries = {
                let s = n.store.read();
                (opt_k32(&g.root) == s.tree().compute_root())
                    .then(|| s.bucket_index(g.buckets.as_deref().unwrap_or_default()))
            };
            let Some(entries) = entries else {
                hop.send_control(HopMsg::NotAvailable(Box::new(wp::NotAvailable {
                    root: g.root,
                })));
                return Ok(());
            };
            hop.send_control(HopMsg::BucketIndex(Box::new(wp::BucketIndex {
                root: g.root,
                entries: Some(
                    entries
                        .into_iter()
                        .map(|(p, h)| wp::LeafIndex {
                            path: Some(crypto::k32(&p)),
                            hash: Some(crypto::k32(&h)),
                        })
                        .collect(),
                ),
            })));
            Ok(())
        }
        HopMsg::BucketIndex(b) => on_bucket_index(n, hop, *b),
        HopMsg::GetLeaves(g) => {
            let paths: Vec<Bytes32> = g
                .paths
                .unwrap_or_default()
                .iter()
                .map(|k| k.to_bytes())
                .collect();
            let leaves = {
                let s = n.store.read();
                (opt_k32(&g.root) == s.tree().compute_root()).then(|| s.leaves_by_path(&paths))
            };
            let Some(leaves) = leaves else {
                hop.send_control(HopMsg::NotAvailable(Box::new(wp::NotAvailable {
                    root: g.root,
                })));
                return Ok(());
            };
            hop.send_control(HopMsg::Leaves(Box::new(wp::Leaves {
                root: g.root,
                leaves: Some(
                    leaves
                        .into_iter()
                        .map(|(k, key, b)| wp::LeafData {
                            kind: k,
                            key: Some(crypto::k32(&key)),
                            bytes: Some(b),
                        })
                        .collect(),
                ),
            })));
            Ok(())
        }
        HopMsg::Leaves(l) => on_leaves(n, hop, *l),
        HopMsg::NotAvailable(_) => {
            let mut w = n.sync.walk.lock();
            if w.as_ref().is_some_and(|w| w.hop == hop.id) {
                *w = None;
            }
            Ok(())
        }
        HopMsg::Records(r) if !hop.restricted => {
            for b in r.items.unwrap_or_default() {
                if let Err(e) = accept_record(n, Some(hop), &b.data.unwrap_or_default()) {
                    tracing::trace!("record from {}: {e}", n.name_of(&hop.peer));
                }
            }
            Ok(())
        }
        HopMsg::Lookup(l) if !hop.restricted => on_lookup(n, hop, *l),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------- heads and the Merkle walk

fn on_head(n: &Arc<Node>, hop: &Arc<Hop>, a: wp::HeadAnnounce) -> Result<()> {
    {
        let mut rl = n.sync.head_rx.lock();
        if let Some(t) = rl.get(&hop.id)
            && t.elapsed() < Duration::from_millis(900)
        {
            return Ok(());
        }
        rl.insert(hop.id, Instant::now());
    }
    if let Some(oh) = a.offline_hash
        && oh.to_bytes() != n.store.read().offline_hash()
    {
        hop.send_control(HopMsg::GetOffline(Box::new(wp::GetOffline {
            have_hash: Some(crypto::k32(&n.store.read().offline_hash())),
        })));
    }
    let Some(raw) = a.head else { return Ok(()) };
    let outcome = n.store.write().offer_head(&raw);
    match outcome {
        Ok(HeadOutcome::Refreshed) => {
            n.persist_store();
            n.emit(Event::HeadChanged);
        }
        Ok(HeadOutcome::Known) => {
            // The peer is behind us: give it our head so it pulls from us.
            let ours = n.store.read().head().map_or(0, |h| h.head.version);
            let theirs = webjet_core::crypto::open_envelope(&raw)
                .ok()
                .and_then(|v| v.decode::<wp::SignedTreeHead>().ok())
                .map_or(0, |h| h.version);
            if theirs < ours
                && let Some(m) = head_msg(n)
            {
                hop.send_control(m);
            }
        }
        Ok(HeadOutcome::NeedSync) => start_walk(n, hop, raw)?,
        Ok(HeadOutcome::Equivocation) => {
            n.alarm("tree_head_equivocation", "critical", "two valid tree heads with the same version and different roots; tree updates frozen (§21.3)".into());
            let (a, b) = n.store.read().equivocation.clone().unwrap_or_default();
            for h in [a, b] {
                n.broadcast_control(
                    HopMsg::HeadAnnounce(Box::new(wp::HeadAnnounce {
                        head: Some(h),
                        offline_hash: None,
                    })),
                    Some(hop.id),
                );
            }
        }
        Err(e) => tracing::debug!("head from {} rejected: {e}", n.name_of(&hop.peer)),
    }
    Ok(())
}

fn start_walk(n: &Arc<Node>, hop: &Arc<Hop>, head_raw: Vec<u8>) -> Result<()> {
    let h = n.store.read().verify_head(&head_raw)?;
    let root = opt_k32(&h.root);
    let mut w = n.sync.walk.lock();
    if let Some(cur) = w.as_ref()
        && cur.started.elapsed() < Duration::from_secs(10)
    {
        // Prefer the newer target, but don't restart a walk to the same root.
        if cur.root == root {
            return Ok(());
        }
        let cur_v = n
            .store
            .read()
            .verify_head(&cur.head_raw)
            .map_or(0, |x| x.version);
        if cur_v >= h.version {
            return Ok(());
        }
    }
    *w = Some(Walk {
        hop: hop.id,
        head_raw,
        root,
        buckets: Vec::new(),
        removals: Vec::new(),
        fetched: Vec::new(),
        batches_left: 0,
        started: Instant::now(),
    });
    hop.send_control(HopMsg::GetBuckets(Box::new(wp::GetBuckets {
        root: Some(crypto::k32(&root)),
    })));
    Ok(())
}

fn walk_for<'a>(
    w: &'a mut Option<Walk>,
    hop: &Hop,
    root: &Option<wp::Key32>,
) -> Option<&'a mut Walk> {
    match w {
        Some(x) if x.hop == hop.id && Some(crypto::k32(&x.root)) == *root => Some(x),
        _ => None,
    }
}

fn on_buckets(n: &Arc<Node>, hop: &Arc<Hop>, b: wp::Buckets) -> Result<()> {
    let mut w = n.sync.walk.lock();
    let Some(walk) = walk_for(&mut w, hop, &b.root) else {
        return Ok(());
    };
    let theirs: Vec<Bytes32> = b
        .hashes
        .unwrap_or_default()
        .iter()
        .map(|k| k.to_bytes())
        .collect();
    if theirs.len() != 256 {
        *w = None;
        bail!("bad bucket list");
    }
    // Check the buckets recombine to the signed root before trusting them.
    let mut level = theirs.clone();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|c| webjet_core::merkle::internal_hash(&c[0], &c[1]))
            .collect();
    }
    if level[0] != walk.root {
        *w = None;
        bail!("buckets don't match the signed root");
    }
    let ours = n.store.read().tree().buckets();
    let diff: Vec<u8> = (0..256)
        .filter(|i| ours[*i] != theirs[*i])
        .map(|i| i as u8)
        .collect();
    if diff.is_empty() {
        let raw = walk.head_raw.clone();
        *w = None;
        drop(w);
        return finish(n, &raw, Vec::new());
    }
    walk.buckets = diff.clone();
    hop.send_control(HopMsg::GetBucketIndex(Box::new(wp::GetBucketIndex {
        root: b.root,
        buckets: Some(diff),
    })));
    Ok(())
}

fn on_bucket_index(n: &Arc<Node>, hop: &Arc<Hop>, b: wp::BucketIndex) -> Result<()> {
    let mut w = n.sync.walk.lock();
    let Some(walk) = walk_for(&mut w, hop, &b.root) else {
        return Ok(());
    };
    let theirs: HashMap<Bytes32, Bytes32> = b
        .entries
        .unwrap_or_default()
        .iter()
        .map(|e| (opt_k32(&e.path), opt_k32(&e.hash)))
        .collect();
    // The buckets we asked about, also those now empty on their side (a
    // leaf removed was the only one in its bucket): our leaves there that
    // they don't have are removed.
    let buckets: HashSet<u8> = walk.buckets.iter().copied().collect();
    let s = n.store.read();
    let mut want = Vec::new();
    for (p, h) in &theirs {
        match s.tree().get_by_path(p) {
            Some(e) if e.hash == *h => {}
            _ => want.push(*p),
        }
    }
    // Leaves we hold in the differing buckets that the target doesn't have.
    let mut removals = Vec::new();
    for (p, e) in s.tree().iter() {
        if !theirs.contains_key(p) && buckets.contains(&p[0]) {
            removals.push((e.kind, e.key));
        }
    }
    drop(s);
    walk.removals = removals;
    if want.is_empty() {
        let raw = walk.head_raw.clone();
        let rem = std::mem::take(&mut walk.removals);
        *w = None;
        drop(w);
        return finish(
            n,
            &raw,
            rem.into_iter().map(|(k, key)| (k, key, None)).collect(),
        );
    }
    walk.batches_left = want.len().div_ceil(512);
    for chunk in want.chunks(512) {
        hop.send_control(HopMsg::GetLeaves(Box::new(wp::GetLeaves {
            root: b.root,
            paths: Some(chunk.iter().map(crypto::k32).collect()),
        })));
    }
    Ok(())
}

fn on_leaves(n: &Arc<Node>, hop: &Arc<Hop>, l: wp::Leaves) -> Result<()> {
    let mut w = n.sync.walk.lock();
    let Some(walk) = walk_for(&mut w, hop, &l.root) else {
        return Ok(());
    };
    for x in l.leaves.unwrap_or_default() {
        walk.fetched
            .push((x.kind, opt_k32(&x.key), x.bytes.unwrap_or_default()));
    }
    walk.batches_left = walk.batches_left.saturating_sub(1);
    if walk.batches_left > 0 {
        return Ok(());
    }
    let raw = walk.head_raw.clone();
    let mut updates: Vec<(u8, Bytes32, Option<Vec<u8>>)> = walk
        .removals
        .iter()
        .map(|(k, key)| (*k, *key, None))
        .collect();
    updates.extend(walk.fetched.drain(..).map(|(k, key, b)| (k, key, Some(b))));
    *w = None;
    drop(w);
    // install() checks the resulting root against the signed head, so a
    // peer that sends wrong leaves only makes this walk fail.
    finish(n, &raw, updates)
}

fn finish(
    n: &Arc<Node>,
    head_raw: &[u8],
    updates: Vec<(u8, Bytes32, Option<Vec<u8>>)>,
) -> Result<()> {
    n.store.write().install(head_raw, updates)?;
    after_install(n);
    Ok(())
}

fn after_install(n: &Arc<Node>) {
    let (v, root) = {
        let s = n.store.read();
        (
            s.head().map_or(0, |h| h.head.version),
            s.head().map(|h| h.root()).unwrap_or_default(),
        )
    };
    tracing::info!(version = v, root = %crypto::short(&root), "network state updated");
    n.persist_store();
    n.emit(Event::HeadChanged);
    push_head(n);
}

// ---------------------------------------------------------------- self-signed records

/// Verify and merge an EndpointRecord, LinkStateAdvert or AttachmentRecord;
/// flood it onward if it is new.
pub fn accept_record(n: &Arc<Node>, from: Option<&Arc<Hop>>, raw: &[u8]) -> Result<bool> {
    let v = crypto::open_envelope(raw)?;
    let now = now_ms();
    // The gossip protocol the record states (§10.6.5); an EndpointRecord
    // from before the field also tells it through `software`.
    let mut software = None;
    let (origin, seq, expires, ty, protocol) = match v.ty {
        mt::ENDPOINT_RECORD => {
            let r: wp::EndpointRecord = v.decode()?;
            let p = proto::endpoint_protocol(r.protocol, r.software.as_deref());
            software = r.software;
            (opt_k32(&r.node_id), r.seq, r.expires_at, v.ty, p)
        }
        mt::LINK_STATE_ADVERT => {
            let r: wp::LinkStateAdvert = v.decode()?;
            (opt_k32(&r.origin), r.seq, r.expires_at, v.ty, r.protocol)
        }
        mt::ATTACHMENT_RECORD => {
            let r: wp::AttachmentRecord = v.decode()?;
            (opt_k32(&r.node_id), r.seq, r.expires_at, v.ty, r.protocol)
        }
        _ => bail!("not a record"),
    };
    if expires.saturating_add(SKEW_SHORT_RECORD) < now {
        bail!("expired record");
    }
    {
        let s = n.store.snapshot();
        let vw = s.view();
        let info = vw
            .nodes
            .get(&origin)
            .ok_or_else(|| anyhow::anyhow!("record from an unknown node"))?;
        if !info.valid || info.key != v.signer {
            bail!("record not signed by the node's current key");
        }
        if ty == mt::LINK_STATE_ADVERT && !info.relay {
            bail!("LinkStateAdvert from a node without RELAY");
        }
    }
    let new = {
        let mut recs = n.records.lock();
        if let Some(marked) = refuse_old_protocol(
            &mut recs,
            Incoming {
                origin,
                ty,
                seq,
                expires,
                protocol,
                software,
                raw,
            },
        ) {
            drop(recs);
            if marked {
                tracing::info!(
                    "{}: ignoring its records, gossip protocol {protocol} is below {} (§10.6.5)",
                    n.name_of(&origin),
                    proto::MIN_GOSSIP_PROTOCOL
                );
            }
            bail!("record from outdated software (gossip protocol {protocol})");
        }
        match ty {
            mt::ENDPOINT_RECORD => {
                if recs
                    .endpoints
                    .get(&origin)
                    .is_some_and(|(r, _)| r.seq >= seq)
                {
                    false
                } else {
                    recs.endpoints.insert(origin, (v.decode()?, raw.to_vec()));
                    true
                }
            }
            mt::LINK_STATE_ADVERT => {
                if recs.lsas.get(&origin).is_some_and(|(r, _)| r.seq >= seq) {
                    false
                } else {
                    recs.lsas.insert(origin, (v.decode()?, raw.to_vec()));
                    true
                }
            }
            _ => {
                if recs
                    .attachments
                    .get(&origin)
                    .is_some_and(|(r, _)| r.seq >= seq)
                {
                    false
                } else {
                    recs.attachments.insert(origin, (v.decode()?, raw.to_vec()));
                    true
                }
            }
        }
    };
    if !new {
        return Ok(false);
    }
    n.emit(Event::RecordsChanged(origin));
    flood(n, from.map(|h| h.id), origin, ty, raw);
    Ok(true)
}

/// The gossip protocol floor (§10.6.5): None when a record from `origin`
/// of this type and protocol may be used, else Some(whether the node was
/// newly marked outdated). An EndpointRecord below the floor
/// marks the node outdated and drops everything it published before; one at
/// or above it clears the mark. LinkStateAdverts and AttachmentRecords
/// without the field (protocol 0, before 0.7.1) take the protocol of the
/// node's EndpointRecord, and are used when there is none yet (an
/// EndpointRecord marking the node outdated removes them later).
/// What the floor check needs to know about an incoming record.
struct Incoming<'a> {
    origin: Bytes32,
    ty: u16,
    seq: u64,
    expires: u64,
    protocol: u16,
    software: Option<String>,
    raw: &'a [u8],
}

fn refuse_old_protocol(recs: &mut crate::node::Records, r: Incoming<'_>) -> Option<bool> {
    let Incoming {
        origin,
        ty,
        seq,
        expires,
        protocol,
        software,
        raw,
    } = r;
    if ty == mt::ENDPOINT_RECORD {
        if recs.outdated.get(&origin).is_some_and(|o| o.seq >= seq) {
            return Some(false);
        }
        if proto::accepted(protocol) {
            // Upgraded: the new EndpointRecord replaces the mark.
            recs.outdated.remove(&origin);
            return None;
        }
        if recs
            .endpoints
            .get(&origin)
            .is_some_and(|(r, _)| r.seq >= seq)
        {
            // Older than the record we have.
            return Some(false);
        }
        let marked = recs
            .outdated
            .insert(
                origin,
                crate::node::Outdated {
                    software: software.unwrap_or_default(),
                    protocol,
                    seq,
                    expires_at: expires,
                    raw: raw.to_vec(),
                },
            )
            .is_none();
        recs.endpoints.remove(&origin);
        recs.lsas.remove(&origin);
        recs.attachments.remove(&origin);
        return Some(marked);
    }
    let ok = if protocol > 0 {
        proto::accepted(protocol)
    } else {
        !recs.outdated.contains_key(&origin)
            && recs.endpoints.get(&origin).is_none_or(|(r, _)| {
                proto::accepted(proto::endpoint_protocol(r.protocol, r.software.as_deref()))
            })
    };
    (!ok).then_some(false)
}

/// Forward a new record (§10.6.1): within the core everything; to edge
/// peers LinkStateAdverts and infrastructure endpoints, plus subscribed
/// records. Edge nodes send only to their hops (home relays).
fn flood(n: &Arc<Node>, except: Option<u64>, origin: Bytes32, ty: u16, raw: &[u8]) {
    let i_am_core = is_core(n, &n.me);
    let infra = n
        .store
        .read()
        .view()
        .nodes
        .get(&origin)
        .is_some_and(|x| x.relay || x.control);
    let subs: HashSet<u64> = {
        let mut s = n.sync.subs.lock();
        let now = Instant::now();
        if let Some(v) = s.get_mut(&origin) {
            v.retain(|(_, until)| *until > now);
            v.iter().map(|(h, _)| *h).collect()
        } else {
            HashSet::new()
        }
    };
    let hops: Vec<Arc<Hop>> = n
        .hops
        .lock()
        .values()
        .filter(|h| h.alive() && !h.restricted && Some(h.id) != except)
        .cloned()
        .collect();
    // Encoded once for all the hops it goes to.
    let mut msg: Option<Option<Vec<u8>>> = None;
    for h in hops {
        let send = if !i_am_core {
            origin == n.me
        } else if is_core(n, &h.peer) {
            true
        } else {
            ty == mt::LINK_STATE_ADVERT
                || (ty == mt::ENDPOINT_RECORD && infra)
                || subs.contains(&h.id)
        };
        if send
            && let Some(bytes) = msg.get_or_insert_with(|| {
                crate::node::ctl(HopMsg::Records(Box::new(wp::Records {
                    items: Some(vec![wp::Blob {
                        data: Some(raw.to_vec()),
                    }]),
                })))
            })
        {
            h.send_raw_control(bytes.clone());
        }
    }
}

fn on_lookup(n: &Arc<Node>, hop: &Arc<Hop>, l: wp::Lookup) -> Result<()> {
    let per_sec = crate::metrics::limit(n, "lookups_per_sec");
    let max_subs = crate::metrics::limit_usize(n, "subscriptions_per_peer");
    {
        let mut r = n.sync.lookup_rate.lock();
        let e = r.entry(hop.id).or_insert_with(|| (Instant::now(), 0));
        if e.0.elapsed() > Duration::from_secs(1) {
            *e = (Instant::now(), 0);
        }
        e.1 += 1;
        if u64::from(e.1) > per_sec {
            bail!("lookup rate exceeded");
        }
    }
    let ids: Vec<Bytes32> = l
        .node_ids
        .unwrap_or_default()
        .iter()
        .take(64)
        .map(|k| k.to_bytes())
        .collect();
    let mut items = Vec::new();
    {
        let recs = n.records.lock();
        for id in &ids {
            if let Some((_, raw)) = recs.endpoints.get(id) {
                items.push(raw.clone());
            }
            if let Some((_, raw)) = recs.attachments.get(id) {
                items.push(raw.clone());
            }
            // Outdated software (§10.6.5): its EndpointRecord, so the edge
            // node can tell why it has nothing else.
            if let Some(o) = recs.outdated.get(id) {
                items.push(o.raw.clone());
            }
        }
    }
    if l.subscribe_ttl_s > 0 {
        let until = Instant::now() + Duration::from_secs(l.subscribe_ttl_s.min(600) as u64);
        let mut s = n.sync.subs.lock();
        let now = Instant::now();
        // Subscriptions this peer holds, renewals of which don't count again.
        let mut held = s
            .values()
            .filter(|v| v.iter().any(|(h, u)| *h == hop.id && *u > now))
            .count();
        for id in ids {
            let v = s.entry(id).or_default();
            let renewing = v.iter().any(|(h, u)| *h == hop.id && *u > now);
            if !renewing {
                if held >= max_subs {
                    continue; // over subscriptions_per_peer: answer, don't subscribe
                }
                held += 1;
            }
            // A shorter renewal (a graph watch) never cuts a longer one short.
            let keep = v
                .iter()
                .filter(|(h, _)| *h == hop.id)
                .map(|(_, u)| *u)
                .fold(until, Instant::max);
            v.retain(|(h, _)| *h != hop.id);
            v.push((hop.id, keep));
        }
    }
    send_records(hop, items);
    Ok(())
}

/// Ask home relays for a peer's records and subscribe (§10.6.2).
pub fn lookup(n: &Arc<Node>, peer: &Bytes32) {
    lookup_many(n, std::slice::from_ref(peer));
}

/// `lookup` for several peers at once, in as few Lookup messages as
/// possible (64 ids each; relays limit lookups per second).
pub fn lookup_many(n: &Arc<Node>, peers: &[Bytes32]) {
    if is_core(n, &n.me) {
        return;
    }
    let due: Vec<Bytes32> = {
        let mut p = n.sync.lookups_pending.lock();
        let now = Instant::now();
        peers
            .iter()
            .filter(|peer| {
                let fresh = p
                    .get(*peer)
                    .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(60));
                if !fresh {
                    p.insert(**peer, now);
                }
                !fresh
            })
            .copied()
            .collect()
    };
    for chunk in due.chunks(64) {
        let msg = HopMsg::Lookup(Box::new(wp::Lookup {
            node_ids: Some(chunk.iter().map(crypto::k32).collect()),
            subscribe_ttl_s: 300,
        }));
        n.broadcast_control(msg, None);
    }
}

/// Someone looks at the whole graph (the `topology` control command, e.g.
/// webjet-app's Nodes tab): an edge node, which holds attachment records only
/// for the peers it talks to (§10.6.1), subscribes at its home relays to
/// every node's records for a while, so it can show the links (and their
/// delays) of all nodes. Core nodes hold everything already.
pub fn watch_all(n: &Arc<Node>) {
    *n.sync.watch_until.lock() = Some(Instant::now() + WATCH_FOR);
    renew_watch(n);
}

fn renew_watch(n: &Arc<Node>) {
    let now = Instant::now();
    if n.sync.watch_until.lock().is_none_or(|t| now >= t) {
        return;
    }
    if n.sync
        .watch_sent
        .lock()
        .is_some_and(|t| now < t + WATCH_RENEW)
    {
        return;
    }
    if is_core(n, &n.me) {
        return;
    }
    let (ids, relays): (Vec<Bytes32>, Vec<Arc<Hop>>) = {
        let s = n.store.snapshot();
        let v = s.view();
        let ids = v
            .nodes
            .values()
            .filter(|x| x.valid && x.id != n.me && !x.relay)
            .map(|x| x.id)
            .collect();
        let relays = n
            .hops
            .lock()
            .values()
            .filter(|h| h.alive() && !h.restricted && is_core(n, &h.peer))
            .cloned()
            .collect();
        (ids, relays)
    };
    if relays.is_empty() {
        return;
    }
    *n.sync.watch_sent.lock() = Some(now);
    // Past WATCH_FOR without a new request the subscriptions lapse.
    let ttl = (WATCH_FOR + WATCH_RENEW).as_secs() as u32;
    for chunk in ids.chunks(64) {
        let Some(msg) = crate::node::ctl(HopMsg::Lookup(Box::new(wp::Lookup {
            node_ids: Some(chunk.iter().map(crypto::k32).collect()),
            subscribe_ttl_s: ttl,
        }))) else {
            continue;
        };
        for h in &relays {
            h.send_raw_control(msg.clone());
        }
    }
}

// ---------------------------------------------------------------- publishing our own records

/// What this node supports, for its EndpointRecord.
fn features(n: &Node) -> Vec<String> {
    let mut f = vec![
        "kcp".to_string(),
        "anytls".into(),
        crate::proxy::FEATURE.into(),
        // Applies automatic membership entries (§7.5).
        webjet_core::membership::FEATURE.into(),
    ];
    // Takes broadcast and multicast (§9.5.1), unless turned off.
    if let Some(d) = n.dataplane.get() {
        let on = crate::multicast::on(n, d);
        d.mcast.lock().advertised = Some(on);
        if on {
            f.push(webjet_core::multicast::FEATURE.into());
        }
    }
    if n.dataplane.get().is_some_and(|d| {
        d.proxy
            .real_ip_ready
            .load(std::sync::atomic::Ordering::Relaxed)
    }) {
        f.push(crate::proxy::FEATURE_REAL_IP.into());
    }
    // Compression this node has turned on (§9.8): peers compress towards
    // it only then.
    f.extend(
        crate::compression::mine(n)
            .features()
            .into_iter()
            .map(String::from),
    );
    f
}

pub fn publish_endpoint(n: &Arc<Node>, force: bool) {
    let addrs = crate::transport::my_addrs(n);
    let now = now_ms();
    {
        let last = n.sync.last_endpoint.lock();
        if !force
            && let Some((a, t)) = last.as_ref()
            && *a == addrs
            && now < t + ENDPOINT_REFRESH
        {
            return;
        }
    }
    let serving: Vec<wp::Cidr> = n
        .dataplane
        .get()
        .map(|d| d.serving_prefixes())
        .unwrap_or_default()
        .iter()
        .map(webjet_core::types::net_to_cidr)
        .collect();
    let rec = wp::EndpointRecord {
        node_id: Some(crypto::k32(&n.me)),
        addrs: Some(addrs.clone()),
        nat: crate::transport::nat_type(n),
        software: Some(format!("webjetd/{}", env!("CARGO_PKG_VERSION"))),
        features: Some(features(n)),
        serving: Some(serving),
        gateway_load: None,
        seq: n.next_seq(),
        issued_at: now,
        expires_at: now + ENDPOINT_LIFETIME,
        priorities: Some(crate::transport::my_priorities(n)),
        protocol: proto::GOSSIP_PROTOCOL,
    };
    let raw = n.kp.sign_obj(mt::ENDPOINT_RECORD, &rec);
    *n.sync.last_endpoint.lock() = Some((addrs, now));
    let _ = accept_record(n, None, &raw);
}

/// Our links for the LSA / attachment: per neighbor, the selected
/// transport's quantized cost (§11.2).
fn my_links(n: &Arc<Node>, relays_only: bool) -> Vec<(Bytes32, Transport, u16, u8)> {
    let peers = n.peers();
    let s = n.store.snapshot();
    let v = s.view();
    let mut out = Vec::new();
    for p in peers {
        let Some(info) = v.nodes.get(&p) else {
            continue;
        };
        if relays_only && !info.relay {
            continue;
        }
        if let Some(h) = n.best_hop(&p) {
            let st = h.stats.lock();
            if st.samples == 0 {
                continue;
            }
            let (rtt, loss) = st.quantized();
            out.push((p, h.transport, rtt.max(1), loss));
        }
    }
    out.sort_by_key(|a| a.0);
    out
}

pub fn publish_lsa(n: &Arc<Node>, force: bool) {
    if !n.is_relay() {
        return;
    }
    let links = my_links(n, true);
    let now = now_ms();
    let summary: Vec<LinkSummary> = links.iter().map(|l| (l.0, l.2, l.3)).collect();
    let load = crate::metrics::relay_load(n);
    let step = webjet_core::routing::relay_load(
        load.util_pct,
        load.cpu_pct,
        load.circuits_pct,
        load.queue_pct,
    );
    {
        let last = n.sync.last_lsa.lock();
        if let Some((prev, t)) = last.as_ref() {
            let since = now.saturating_sub(*t);
            if since < 2 * SECOND {
                return;
            }
            let changed = prev.len() != summary.len()
                || prev.iter().zip(summary.iter()).any(|(a, b)| {
                    a.0 != b.0
                        || (a.1 as f64 - b.1 as f64).abs() > a.1 as f64 * LSA_CHANGE + 1.0
                        || a.2.abs_diff(b.2) > 2
                });
            // A load step change is advertised at most every 10 s (§11.8.1).
            let load_changed = *n.sync.last_load_step.lock() != step && since >= 10 * SECOND;
            if !force && !changed && !load_changed && since < LSA_REFRESH {
                return;
            }
        }
    }
    *n.sync.last_load_step.lock() = step;
    let lsa = wp::LinkStateAdvert {
        origin: Some(crypto::k32(&n.me)),
        seq: n.next_seq(),
        links: Some(
            links
                .iter()
                .map(|(p, t, rtt, loss)| wp::LinkEntry {
                    peer: Some(crypto::k32(p)),
                    transport: *t,
                    rtt_ms: *rtt,
                    loss_pct: *loss,
                    util_pct: load.util_pct,
                })
                .collect(),
        ),
        load: Some(Box::new(load)),
        issued_at: now,
        expires_at: now + LSA_LIFETIME,
        protocol: proto::GOSSIP_PROTOCOL,
    };
    let raw = n.kp.sign_obj(mt::LINK_STATE_ADVERT, &lsa);
    *n.sync.last_lsa.lock() = Some((summary, now));
    let _ = accept_record(n, None, &raw);
}

/// Home relays (§10.6): the 2 (at most 3) lowest-cost relays we hold hops to.
pub fn home_relays(n: &Arc<Node>) -> Vec<(Bytes32, Transport, u16, u8)> {
    let mut links = my_links(n, true);
    links.sort_by_key(|l| webjet_core::routing::link_cost(l.2 as f64, l.3 as f64 / 100.0) as u64);
    links.truncate(3);
    links
}

pub fn publish_attachment(n: &Arc<Node>) {
    if n.is_relay() {
        return;
    }
    let relays = home_relays(n);
    let now = now_ms();
    let ids: Vec<Bytes32> = relays.iter().map(|r| r.0).collect();
    {
        let last = n.sync.last_attach.lock();
        if let Some((prev, t)) = last.as_ref()
            && *prev == ids
            && now < t + ATTACH_REFRESH
        {
            return;
        }
    }
    let rec = wp::AttachmentRecord {
        node_id: Some(crypto::k32(&n.me)),
        seq: n.next_seq(),
        relays: Some(
            relays
                .iter()
                .map(|(p, t, rtt, loss)| wp::AttachmentEntry {
                    relay: Some(crypto::k32(p)),
                    transport: *t,
                    rtt_ms: *rtt,
                    loss_pct: *loss,
                })
                .collect(),
        ),
        issued_at: now,
        expires_at: now + ATTACH_LIFETIME,
        protocol: proto::GOSSIP_PROTOCOL,
    };
    let raw = n.kp.sign_obj(mt::ATTACHMENT_RECORD, &rec);
    *n.sync.last_attach.lock() = Some((ids, now));
    let _ = accept_record(n, None, &raw);
}

/// Drop expired records and records of nodes that are no longer valid.
pub fn expire_records(n: &Arc<Node>) {
    let now = now_ms();
    let s = n.store.snapshot();
    let v = s.view();
    let ok = |id: &Bytes32, exp: u64| {
        exp.saturating_add(SKEW_SHORT_RECORD) >= now && v.nodes.get(id).is_some_and(|x| x.valid)
    };
    let mut recs = n.records.lock();
    // Relays' endpoint records are kept as reconnection hints even after expiry (§10.4).
    recs.endpoints.retain(|id, (r, _)| {
        ok(id, r.expires_at)
            || v.nodes
                .get(id)
                .is_some_and(|x| x.valid && (x.relay || x.control))
    });
    recs.lsas.retain(|id, (r, _)| ok(id, r.expires_at));
    recs.attachments.retain(|id, (r, _)| ok(id, r.expires_at));
    recs.outdated.retain(|id, o| ok(id, o.expires_at));
}

/// Build the routing graph from LSAs and attachments (§11.4).
pub fn graph(n: &Node) -> webjet_core::routing::Graph {
    use webjet_core::routing::{Graph, RelayInfo, link_cost};
    let now = now_ms();
    let recs = n.records.lock();
    let s = n.store.snapshot();
    let v = s.view();
    let mut g = Graph::default();
    for (id, (l, _)) in &recs.lsas {
        if l.expires_at.saturating_add(SKEW_SHORT_RECORD) < now
            || !v.nodes.get(id).is_some_and(|x| x.valid && x.relay)
        {
            continue;
        }
        let load = l.load.as_ref().map_or(0, |x| {
            webjet_core::routing::relay_load(x.util_pct, x.cpu_pct, x.circuits_pct, x.queue_pct)
        });
        let links = l
            .links
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|e| {
                (
                    opt_k32(&e.peer),
                    link_cost(e.rtt_ms as f64, e.loss_pct as f64 / 100.0),
                )
            })
            .collect();
        g.relays.insert(
            *id,
            RelayInfo {
                links,
                load,
                capacity_mbps: l.load.as_ref().map_or(0, |x| x.capacity_mbps),
            },
        );
    }
    for (id, (a, _)) in &recs.attachments {
        if a.expires_at.saturating_add(SKEW_SHORT_RECORD) < now
            || !v.nodes.get(id).is_some_and(|x| x.valid)
        {
            continue;
        }
        let m = a
            .relays
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|e| {
                (
                    opt_k32(&e.relay),
                    link_cost(e.rtt_ms as f64, e.loss_pct as f64 / 100.0),
                )
            })
            .collect();
        g.attachments.insert(*id, m);
    }
    // Our own live links are measured directly and always current.
    if !v.nodes.get(&n.me).is_some_and(|x| x.relay) {
        drop(recs);
        drop(s);
        let mut mine: HashMap<Bytes32, f64> = HashMap::new();
        for h in n.hops.lock().values() {
            if h.alive() && g.relays.contains_key(&h.peer) {
                let c = h.cost();
                if c.is_finite() {
                    let e = mine.entry(h.peer).or_insert(f64::INFINITY);
                    *e = e.min(c);
                }
            }
        }
        if !mine.is_empty() {
            g.attachments.insert(n.me, mine);
        }
    }
    g
}

/// The periodic gossip driver.
pub async fn run(n: Arc<Node>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut i: u64 = 0;
    let mut ev = n.events.subscribe();
    let mut last_infra: Vec<Bytes32> = Vec::new();
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            e = ev.recv() => {
                if let Ok(Event::HeadChanged) = e {
                    // Roles may have changed: republish and re-share.
                    let infra: Vec<Bytes32> = {
                        let s = n.store.snapshot();
                        let mut v: Vec<Bytes32> = s.view().nodes.values().filter(|x| x.valid && (x.relay || x.control)).map(|x| x.id).collect();
                        v.sort();
                        v
                    };
                    if infra != last_infra {
                        last_infra = infra;
                        publish_endpoint(&n, true);
                        share_infra(&n);
                    }
                }
                continue;
            }
        }
        i += 1;
        // Digest exchange within the core (§10.3.1).
        if is_core(&n, &n.me) {
            let d = crypto::k32(&n.store.read().digest());
            let hops: Vec<Arc<Hop>> = n
                .hops
                .lock()
                .values()
                .filter(|h| h.alive() && is_core(&n, &h.peer))
                .cloned()
                .collect();
            let fanout = if hops.len() > 64 { 4 } else { hops.len() };
            use rand::seq::IndexedRandom;
            for h in hops.sample(&mut rand::rng(), fanout) {
                h.send_control(HopMsg::Digest(Box::new(wp::Digest { digest: Some(d) })));
            }
        }
        if i.is_multiple_of(600) {
            push_head(&n);
        }
        // Stuck walk: give up after 30 s.
        {
            let mut w = n.sync.walk.lock();
            if w.as_ref()
                .is_some_and(|x| x.started.elapsed() > Duration::from_secs(30))
            {
                *w = None;
            }
        }
        if i.is_multiple_of(2) {
            crate::metrics::sample_load(&n);
        }
        if i % 5 == 1 {
            publish_endpoint(&n, false);
        }
        // Changed links are advertised within 2 s (§11.3).
        if i % 2 == 1 {
            publish_lsa(&n, false);
        } else {
            publish_attachment(&n);
        }
        renew_watch(&n);
        if i.is_multiple_of(30) {
            expire_records(&n);
            n.sync.subs.lock().retain(|_, v| {
                v.retain(|(_, u)| *u > Instant::now());
                !v.is_empty()
            });
            let live: HashSet<u64> = n.hops.lock().keys().copied().collect();
            n.sync.head_rx.lock().retain(|h, _| live.contains(h));
            n.sync.lookup_rate.lock().retain(|h, _| live.contains(h));
            n.sync.sync_rate.lock().retain(|h, _| live.contains(h));
        }
    }
}

/// The network graph as this node knows it (§11.4), for the control
/// channel (`topology`): every node, and an edge per relay link (from
/// LinkStateAdverts), per attachment of an edge node to a relay, and per
/// live hop of this agent. Edges are listed once per direction reported.
pub fn topology(n: &Node) -> serde_json::Value {
    use serde_json::json;
    let now = now_ms();
    let mut edges: Vec<serde_json::Value> = Vec::new();
    let (lsas, atts) = {
        let recs = n.records.lock();
        (
            recs.lsas
                .iter()
                .map(|(k, (l, _))| (*k, l.clone()))
                .collect::<Vec<_>>(),
            recs.attachments
                .iter()
                .map(|(k, (a, _))| (*k, a.clone()))
                .collect::<Vec<_>>(),
        )
    };
    let mut loads = serde_json::Map::new();
    for (id, l) in &lsas {
        if l.expires_at.saturating_add(SKEW_SHORT_RECORD) < now {
            continue;
        }
        if let Some(x) = &l.load {
            loads.insert(
                hex::encode(id),
                json!({"util_pct": x.util_pct, "cpu_pct": x.cpu_pct, "circuits_pct": x.circuits_pct, "queue_pct": x.queue_pct, "capacity_mbps": x.capacity_mbps}),
            );
        }
        for e in l.links.iter().flatten() {
            edges.push(json!({
                "a": hex::encode(id), "b": hex::encode(opt_k32(&e.peer)), "kind": "relay",
                "transport": e.transport.name(), "rtt_ms": e.rtt_ms, "loss": e.loss_pct as f64 / 100.0,
                "util_pct": e.util_pct, "age_s": now.saturating_sub(l.issued_at) / 1000,
            }));
        }
    }
    for (id, a) in &atts {
        if a.expires_at.saturating_add(SKEW_SHORT_RECORD) < now {
            continue;
        }
        for e in a.relays.iter().flatten() {
            edges.push(json!({
                "a": hex::encode(id), "b": hex::encode(opt_k32(&e.relay)), "kind": "attachment",
                "transport": e.transport.name(), "rtt_ms": e.rtt_ms, "loss": e.loss_pct as f64 / 100.0,
                "age_s": now.saturating_sub(a.issued_at) / 1000,
            }));
        }
    }
    let hops: Vec<Arc<Hop>> = n.hops.lock().values().cloned().collect();
    for h in hops.iter().filter(|h| h.alive()) {
        let st = h.stats.lock().clone();
        edges.push(json!({
            "a": hex::encode(n.me), "b": hex::encode(h.peer), "kind": "hop",
            "transport": h.transport.name(), "rtt_ms": st.srtt_ms, "loss": st.loss,
            "remote": h.remote.to_string(), "outbound": h.outbound,
            "tx_bytes": h.tx_bytes.load(std::sync::atomic::Ordering::Relaxed),
            "rx_bytes": h.rx_bytes.load(std::sync::atomic::Ordering::Relaxed),
            "age_s": h.created.elapsed().as_secs(),
        }));
    }
    // NAT type and addresses from each node's EndpointRecord (§6.2); this
    // node's own are current rather than as last published.
    // The software version too, and nodes whose records are ignored for
    // their old gossip protocol (§10.6.5).
    let (mut endpoints, outdated) = {
        let recs = n.records.lock();
        let endpoints: HashMap<Bytes32, (wp::NatType, Vec<wp::EndpointAddr>, Option<String>)> =
            recs.endpoints
                .iter()
                .map(|(id, (r, _))| {
                    let a = r.addrs.clone().unwrap_or_default();
                    (*id, (r.nat, a, r.software.clone()))
                })
                .collect();
        (endpoints, recs.outdated.clone())
    };
    endpoints.insert(
        n.me,
        (
            crate::transport::nat_type(n),
            crate::transport::my_addrs(n),
            Some(format!("webjetd/{}", env!("CARGO_PKG_VERSION"))),
        ),
    );
    let mapping = *n.port_mapping.lock();
    let s = n.store.snapshot();
    let v = s.view();
    let nodes: Vec<serde_json::Value> = v
        .nodes
        .values()
        .filter(|x| x.valid)
        .map(|x| {
            let ep = endpoints.get(&x.id);
            let old = outdated.get(&x.id);
            let software = ep
                .and_then(|(_, _, s)| s.as_deref())
                .or(old.map(|o| o.software.as_str()))
                .map(proto::version_text);
            json!({
                "id": hex::encode(x.id), "name": x.name,
                "ips": x.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
                "relay": x.relay, "data": x.data, "control": x.control,
                "me": x.id == n.me,
                "load": loads.get(&hex::encode(x.id)),
                "nat": ep.map(|(t, _, _)| crate::transport::nat_name(*t)),
                "endpoints": ep.map(|(_, a, _)| crate::transport::addrs_json(a)).unwrap_or_default(),
                "software": software,
                "outdated": old.is_some(),
                "port_mapping": (x.id == n.me).then_some(mapping).flatten().map(|m| json!({"external": m.external.to_string(), "protocol": m.protocol})),
            })
        })
        .collect();
    json!({"me": hex::encode(n.me), "nodes": nodes, "edges": edges})
}

#[cfg(test)]
mod walk_tests {
    use super::*;
    use crate::node::TestHopRx;
    use crate::testnode::{self, Cluster};
    use webjet_core::merkle::kind;
    use webjet_proto::AccountOp;

    /// Two nodes, `behind` holding an older tree than `ahead`, joined by a
    /// test hop each way.
    struct Pair {
        behind: Arc<Node>,
        ahead: Arc<Node>,
        to_ahead: (Arc<Hop>, TestHopRx),
        to_behind: (Arc<Hop>, TestHopRx),
        _dirs: (tempfile::TempDir, tempfile::TempDir),
    }

    /// The network changes between the two trees: nodes enrolled (new
    /// leaves in many buckets), one renamed (a changed leaf), one revoked
    /// (its node configuration leaf removed).
    fn pair() -> Pair {
        let mut c = Cluster::new();
        let (a, ka) = c.data_node("a", "10.7.0.2", &[]);
        let (b, kb) = c.data_node("b", "10.7.0.3", &[]);
        let gone = c.data_node("gone", "10.7.0.4", &[]).0;
        c.set_node_config(wp::NodeConfig {
            node_id: Some(crypto::k32(&gone)),
            limits: Some(vec![wp::LimitValue {
                name: Some("circuits_global".into()),
                value: 7,
            }]),
            ..Default::default()
        })
        .unwrap();
        let (behind, d1) = testnode::node(&mut c, a, ka);
        for i in 0..40 {
            c.data_node(&format!("n{i}"), &format!("10.7.1.{}", i + 1), &[]);
        }
        c.admin_op(AccountOp::RenameNode(Box::new(wp::RenameNode {
            node_id: Some(crypto::k32(&b)),
            name: Some("b2".into()),
        })))
        .unwrap();
        c.admin_op(AccountOp::TombstoneNode(Box::new(wp::TombstoneNode {
            node_id: Some(crypto::k32(&gone)),
            reason: None,
        })))
        .unwrap();
        let (ahead, d2) = testnode::node(&mut c, b, kb);
        let to_ahead = behind.test_hop(b, Transport::TcpTls);
        let to_behind = ahead.test_hop(a, Transport::TcpTls);
        Pair {
            behind,
            ahead,
            to_ahead,
            to_behind,
            _dirs: (d1, d2),
        }
    }

    /// Deliver control messages both ways until neither side sends more;
    /// `tamper` may change what `ahead` sends. Returns `behind`'s errors.
    async fn pump(p: &mut Pair, tamper: impl Fn(&mut HopMsg)) -> Vec<String> {
        let mut errors = Vec::new();
        loop {
            let up = p.to_ahead.1.control();
            let mut down = p.to_behind.1.control();
            if up.is_empty() && down.is_empty() {
                return errors;
            }
            for m in up {
                handle(&p.ahead, &p.to_behind.0, m).unwrap();
            }
            for mut m in down.drain(..) {
                tamper(&mut m);
                if let Err(e) = handle(&p.behind, &p.to_ahead.0, m) {
                    errors.push(e.to_string());
                }
            }
        }
    }

    fn announce(n: &Node) -> HopMsg {
        head_msg(n).expect("a head")
    }

    #[tokio::test]
    async fn a_walk_brings_a_node_up_to_the_newer_tree() {
        let mut p = pair();
        let (old, new) = (
            p.behind.store.read().tree().clone(),
            p.ahead.store.read().tree().clone(),
        );
        // The trees differ in every way a walk handles.
        assert!(
            old.iter()
                .any(|(path, e)| e.kind == kind::NODE_CONFIG && new.get_by_path(path).is_none()),
            "a leaf to remove"
        );
        assert!(old.len() + 30 < new.len(), "leaves to fetch");
        let m = announce(&p.ahead);
        handle(&p.behind, &p.to_ahead.0, m).unwrap();
        assert_eq!(pump(&mut p, |_| {}).await, Vec::<String>::new());
        let (b, a) = (p.behind.store.read(), p.ahead.store.read());
        assert_eq!(b.tree().clone().root(), a.tree().clone().root());
        assert_eq!(
            b.head().map(|h| h.head.version),
            a.head().map(|h| h.head.version)
        );
        assert!(p.behind.sync.walk.lock().is_none(), "the walk is over");
    }

    /// A peer that sends leaves other than the signed tree's only fails
    /// the walk: nothing is installed.
    #[tokio::test]
    async fn wrong_leaves_install_nothing() {
        let mut p = pair();
        let root = |n: &Node| n.store.read().tree().clone().root();
        let before = root(&p.behind);
        let m = announce(&p.ahead);
        handle(&p.behind, &p.to_ahead.0, m).unwrap();
        let errors = pump(&mut p, |m| {
            if let HopMsg::Leaves(l) = m
                && let Some(x) = l.leaves.as_mut().and_then(|v| v.first_mut())
                && let Some(b) = x.bytes.as_mut()
            {
                let mid = b.len() / 2;
                b[mid] ^= 1;
            }
        })
        .await;
        assert!(!errors.is_empty(), "the walk failed");
        assert_eq!(root(&p.behind), before);
        assert!(p.behind.sync.walk.lock().is_none());
    }

    /// Bucket hashes that don't add up to the signed root end the walk
    /// before anything else is asked for.
    #[tokio::test]
    async fn buckets_must_match_the_signed_root() {
        let mut p = pair();
        let m = announce(&p.ahead);
        handle(&p.behind, &p.to_ahead.0, m).unwrap();
        let errors = pump(&mut p, |m| {
            if let HopMsg::Buckets(b) = m
                && let Some(h) = b.hashes.as_mut().and_then(|v| v.first_mut())
            {
                *h = crypto::k32(&[0xee; 32]);
            }
        })
        .await;
        assert_eq!(errors, ["buckets don't match the signed root"]);
        assert!(p.to_ahead.1.control().is_empty(), "nothing more asked");
    }

    /// A peer behind us gets our head, so it walks toward us.
    #[tokio::test]
    async fn a_peer_behind_gets_our_head() {
        let mut p = pair();
        let m = announce(&p.behind);
        handle(&p.ahead, &p.to_behind.0, m).unwrap();
        let sent = p.to_behind.1.control();
        let ours = p.ahead.store.read().head().map(|h| h.raw.clone());
        assert!(
            matches!(&sent[..], [HopMsg::HeadAnnounce(a)] if a.head == ours),
            "{sent:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Records;

    const A: Bytes32 = [1; 32];

    fn endpoint(seq: u64, software: &str, protocol: u16) -> wp::EndpointRecord {
        wp::EndpointRecord {
            node_id: Some(crypto::k32(&A)),
            software: Some(software.into()),
            seq,
            expires_at: u64::MAX / 2,
            protocol,
            ..Default::default()
        }
    }

    /// Run the floor check like accept_record does, storing what passes.
    fn offer(recs: &mut Records, ty: u16, seq: u64, protocol: u16, sw: Option<&str>) -> bool {
        let p = if ty == mt::ENDPOINT_RECORD {
            proto::endpoint_protocol(protocol, sw)
        } else {
            protocol
        };
        let refused = refuse_old_protocol(
            recs,
            Incoming {
                origin: A,
                ty,
                seq,
                expires: u64::MAX / 2,
                protocol: p,
                software: sw.map(String::from),
                raw: &[],
            },
        )
        .is_some();
        if !refused {
            match ty {
                mt::ENDPOINT_RECORD => {
                    let r = endpoint(seq, sw.unwrap_or(""), protocol);
                    recs.endpoints.insert(A, (r, Vec::new()));
                }
                mt::LINK_STATE_ADVERT => {
                    let l = wp::LinkStateAdvert {
                        seq,
                        protocol,
                        ..Default::default()
                    };
                    recs.lsas.insert(A, (l, Vec::new()));
                }
                _ => {
                    let a = wp::AttachmentRecord {
                        seq,
                        protocol,
                        ..Default::default()
                    };
                    recs.attachments.insert(A, (a, Vec::new()));
                }
            }
        }
        !refused
    }

    #[test]
    fn old_software_is_ignored_and_comes_back_when_upgraded() {
        let mut recs = Records::default();
        // An LSA without the field arrives before any EndpointRecord: used.
        assert!(offer(&mut recs, mt::LINK_STATE_ADVERT, 1, 0, None));
        // Its 0.6.1 EndpointRecord marks it outdated and drops the LSA.
        assert!(!offer(
            &mut recs,
            mt::ENDPOINT_RECORD,
            2,
            0,
            Some("webjetd/0.6.1")
        ));
        assert!(recs.lsas.is_empty() && recs.endpoints.is_empty());
        assert_eq!(
            recs.outdated.get(&A).map(|o| o.software.as_str()),
            Some("webjetd/0.6.1")
        );
        // Further records without the field are ignored.
        assert!(!offer(&mut recs, mt::LINK_STATE_ADVERT, 3, 0, None));
        assert!(!offer(&mut recs, mt::ATTACHMENT_RECORD, 3, 0, None));
        // A replayed older record doesn't change anything.
        assert!(!offer(
            &mut recs,
            mt::ENDPOINT_RECORD,
            1,
            0,
            Some("webjetd/0.5.0")
        ));
        // Upgraded to the current software: accepted again.
        assert!(offer(
            &mut recs,
            mt::ENDPOINT_RECORD,
            4,
            proto::GOSSIP_PROTOCOL,
            Some("webjetd/9.9.9")
        ));
        assert!(recs.outdated.is_empty());
        assert!(offer(
            &mut recs,
            mt::LINK_STATE_ADVERT,
            5,
            proto::GOSSIP_PROTOCOL,
            None
        ));
    }

    #[test]
    fn compatible_older_software_is_kept() {
        let mut recs = Records::default();
        // 0.7.0 has no field but is at the floor.
        assert!(offer(
            &mut recs,
            mt::ENDPOINT_RECORD,
            1,
            0,
            Some("webjetd/0.7.0")
        ));
        assert!(offer(&mut recs, mt::LINK_STATE_ADVERT, 2, 0, None));
        assert!(offer(&mut recs, mt::ATTACHMENT_RECORD, 2, 0, None));
        assert!(recs.outdated.is_empty());
        // A stale downgrade below what we hold is ignored without marking.
        assert!(!offer(
            &mut recs,
            mt::ENDPOINT_RECORD,
            1,
            0,
            Some("webjetd/0.6.1")
        ));
        assert!(recs.outdated.is_empty() && recs.endpoints.contains_key(&A));
        // A real downgrade (newer seq) marks it outdated.
        assert!(!offer(
            &mut recs,
            mt::ENDPOINT_RECORD,
            3,
            0,
            Some("webjetd/0.6.1")
        ));
        assert!(recs.outdated.contains_key(&A) && recs.attachments.is_empty());
    }
}
