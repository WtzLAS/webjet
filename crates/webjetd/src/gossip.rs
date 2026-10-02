//! Gossip (§10.3, §10.6, §11.3): tree-head exchange with Merkle anti-entropy,
//! priority flooding of offline-signed items, and the signed soft-state
//! records (EndpointRecords, LinkStateAdverts, AttachmentRecords).

use crate::node::{Event, Hop, Node};
use anyhow::{bail, Result};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use webjet_core::crypto::{self, opt_k32, Bytes32};
use webjet_core::store::HeadOutcome;
use webjet_core::types::{now_ms, MINUTE, SECOND, SKEW_SHORT_RECORD};
use webjet_proto::{self as wp, msg_type as mt, HopMsg, Transport};

pub const LSA_REFRESH: u64 = 5 * MINUTE;
pub const LSA_LIFETIME: u64 = 15 * MINUTE;
pub const ENDPOINT_REFRESH: u64 = 5 * MINUTE;
pub const ENDPOINT_LIFETIME: u64 = 15 * MINUTE;
pub const ATTACH_REFRESH: u64 = 20 * SECOND;
pub const ATTACH_LIFETIME: u64 = 60 * SECOND;

/// One Merkle walk toward a newer head, run against one peer.
struct Walk {
    hop: u64,
    head_raw: Vec<u8>,
    root: Bytes32,
    removals: Vec<(u8, Bytes32)>,
    fetched: Vec<(u8, Bytes32, Vec<u8>)>,
    batches_left: usize,
    started: Instant,
}

#[derive(Default)]
pub struct SyncState {
    walk: Mutex<Option<Walk>>,
    /// Per hop: when we last accepted a head from it (rate limit, §10.3.1).
    head_rx: Mutex<HashMap<u64, Instant>>,
    /// Relay side: edge peers' subscriptions: node → (subscriber hops, until).
    subs: Mutex<HashMap<Bytes32, Vec<(u64, Instant)>>>,
    lookup_rate: Mutex<HashMap<u64, (Instant, u32)>>,
    /// Last published own records, to republish on change.
    pub last_endpoint: Mutex<Option<(Vec<wp::EndpointAddr>, u64)>>,
    pub last_lsa: Mutex<Option<(Vec<(Bytes32, u16, u8)>, u64)>>,
    pub last_attach: Mutex<Option<(Vec<Bytes32>, u64)>>,
    pub lookups_pending: Mutex<HashMap<Bytes32, Instant>>,
}

fn head_msg(n: &Node) -> Option<HopMsg> {
    let s = n.store.read();
    let h = s.head()?;
    Some(HopMsg::HeadAnnounce(Box::new(wp::HeadAnnounce { head: Some(h.raw.clone()), offline_hash: Some(crypto::k32(&s.offline_hash())) })))
}

fn is_core(n: &Node, id: &Bytes32) -> bool {
    let s = n.store.read();
    let v = s.view();
    let any_relay = v.nodes.values().any(|x| x.relay && x.valid);
    !any_relay || v.nodes.get(id).map(|x| x.relay).unwrap_or(false)
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
        let s = n.store.read();
        let v = s.view();
        for (id, (_, raw)) in &recs.lsas {
            if *id != n.me {
                items.push(raw.clone());
            }
        }
        for (id, (_, raw)) in &recs.endpoints {
            let infra = v.nodes.get(id).map(|x| x.relay || x.control).unwrap_or(false);
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
        hop.send_control(HopMsg::Records(Box::new(wp::Records { items: Some(chunk.iter().map(|b| wp::Blob { data: Some(b.clone()) }).collect()) })));
    }
}

pub fn on_digest(n: &Arc<Node>, hop: &Arc<Hop>, digest: Bytes32) {
    *hop.peer_digest.lock() = Some(digest);
    if digest != n.store.read().digest() {
        if let Some(m) = head_msg(n) {
            hop.send_control(m);
        }
    }
}

/// Push a new head (and offline items) to every peer immediately (§10.3.1).
pub fn push_head(n: &Arc<Node>) {
    if let Some(m) = head_msg(n) {
        n.broadcast_control(m, None);
    }
}

pub async fn handle(n: &Arc<Node>, hop: &Arc<Hop>, m: HopMsg) -> Result<()> {
    match m {
        HopMsg::HeadAnnounce(a) => on_head(n, hop, *a),
        HopMsg::GetOffline(_) => {
            let items = n.store.read().offline_items();
            hop.send_control(HopMsg::OfflineItems(Box::new(wp::OfflineItems { items: Some(items.into_iter().map(|b| wp::Blob { data: Some(b) }).collect()) })));
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
            let s = n.store.read();
            let root = s.tree().compute_root();
            if opt_k32(&g.root) != root {
                hop.send_control(HopMsg::NotAvailable(Box::new(wp::NotAvailable { root: g.root })));
            } else {
                hop.send_control(HopMsg::Buckets(Box::new(wp::Buckets { root: g.root, hashes: Some(s.tree().buckets().iter().map(crypto::k32).collect()) })));
            }
            Ok(())
        }
        HopMsg::Buckets(b) => on_buckets(n, hop, *b),
        HopMsg::GetBucketIndex(g) => {
            let s = n.store.read();
            if opt_k32(&g.root) != s.tree().compute_root() {
                hop.send_control(HopMsg::NotAvailable(Box::new(wp::NotAvailable { root: g.root })));
                return Ok(());
            }
            let entries = s.bucket_index(&g.buckets.unwrap_or_default());
            hop.send_control(HopMsg::BucketIndex(Box::new(wp::BucketIndex {
                root: g.root,
                entries: Some(entries.into_iter().map(|(p, h)| wp::LeafIndex { path: Some(crypto::k32(&p)), hash: Some(crypto::k32(&h)) }).collect()),
            })));
            Ok(())
        }
        HopMsg::BucketIndex(b) => on_bucket_index(n, hop, *b),
        HopMsg::GetLeaves(g) => {
            let s = n.store.read();
            if opt_k32(&g.root) != s.tree().compute_root() {
                hop.send_control(HopMsg::NotAvailable(Box::new(wp::NotAvailable { root: g.root })));
                return Ok(());
            }
            let paths: Vec<Bytes32> = g.paths.unwrap_or_default().iter().map(|k| k.to_bytes()).collect();
            let leaves = s.leaves_by_path(&paths);
            hop.send_control(HopMsg::Leaves(Box::new(wp::Leaves {
                root: g.root,
                leaves: Some(leaves.into_iter().map(|(k, key, b)| wp::LeafData { kind: k, key: Some(crypto::k32(&key)), bytes: Some(b) }).collect()),
            })));
            Ok(())
        }
        HopMsg::Leaves(l) => on_leaves(n, hop, *l),
        HopMsg::NotAvailable(_) => {
            let mut w = n.sync.walk.lock();
            if w.as_ref().map(|w| w.hop == hop.id).unwrap_or(false) {
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
        if let Some(t) = rl.get(&hop.id) {
            if t.elapsed() < Duration::from_millis(900) {
                return Ok(());
            }
        }
        rl.insert(hop.id, Instant::now());
    }
    if let Some(oh) = a.offline_hash {
        if oh.to_bytes() != n.store.read().offline_hash() {
            hop.send_control(HopMsg::GetOffline(Box::new(wp::GetOffline { have_hash: Some(crypto::k32(&n.store.read().offline_hash())) })));
        }
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
            let ours = n.store.read().head().map(|h| h.head.version).unwrap_or(0);
            let theirs = webjet_core::crypto::open_envelope(&raw).ok().and_then(|v| v.decode::<wp::SignedTreeHead>().ok()).map(|h| h.version).unwrap_or(0);
            if theirs < ours {
                if let Some(m) = head_msg(n) {
                    hop.send_control(m);
                }
            }
        }
        Ok(HeadOutcome::NeedSync) => start_walk(n, hop, raw)?,
        Ok(HeadOutcome::Equivocation) => {
            n.alarm("tree_head_equivocation", "critical", "two valid tree heads with the same version and different roots; tree updates frozen (§21.3)".into());
            let (a, b) = n.store.read().equivocation.clone().unwrap_or_default();
            for h in [a, b] {
                n.broadcast_control(HopMsg::HeadAnnounce(Box::new(wp::HeadAnnounce { head: Some(h), offline_hash: None })), Some(hop.id));
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
    if let Some(cur) = w.as_ref() {
        if cur.started.elapsed() < Duration::from_secs(10) {
            // Prefer the newer target, but don't restart a walk to the same root.
            if cur.root == root {
                return Ok(());
            }
            let cur_v = n.store.read().verify_head(&cur.head_raw).map(|x| x.version).unwrap_or(0);
            if cur_v >= h.version {
                return Ok(());
            }
        }
    }
    *w = Some(Walk { hop: hop.id, head_raw, root, removals: Vec::new(), fetched: Vec::new(), batches_left: 0, started: Instant::now() });
    hop.send_control(HopMsg::GetBuckets(Box::new(wp::GetBuckets { root: Some(crypto::k32(&root)) })));
    Ok(())
}

fn walk_for<'a>(w: &'a mut Option<Walk>, hop: &Hop, root: &Option<wp::Key32>) -> Option<&'a mut Walk> {
    match w {
        Some(x) if x.hop == hop.id && Some(crypto::k32(&x.root)) == *root => Some(x),
        _ => None,
    }
}

fn on_buckets(n: &Arc<Node>, hop: &Arc<Hop>, b: wp::Buckets) -> Result<()> {
    let mut w = n.sync.walk.lock();
    let Some(walk) = walk_for(&mut w, hop, &b.root) else { return Ok(()) };
    let theirs: Vec<Bytes32> = b.hashes.unwrap_or_default().iter().map(|k| k.to_bytes()).collect();
    if theirs.len() != 256 {
        *w = None;
        bail!("bad bucket list");
    }
    // Check the buckets recombine to the signed root before trusting them.
    let mut level = theirs.clone();
    while level.len() > 1 {
        level = level.chunks(2).map(|c| webjet_core::merkle::internal_hash(&c[0], &c[1])).collect();
    }
    if level[0] != walk.root {
        *w = None;
        bail!("buckets don't match the signed root");
    }
    let ours = n.store.read().tree().buckets();
    let diff: Vec<u8> = (0..256).filter(|i| ours[*i] != theirs[*i]).map(|i| i as u8).collect();
    if diff.is_empty() {
        let raw = walk.head_raw.clone();
        *w = None;
        drop(w);
        return finish(n, &raw, Vec::new());
    }
    hop.send_control(HopMsg::GetBucketIndex(Box::new(wp::GetBucketIndex { root: b.root, buckets: Some(diff) })));
    Ok(())
}

fn on_bucket_index(n: &Arc<Node>, hop: &Arc<Hop>, b: wp::BucketIndex) -> Result<()> {
    let mut w = n.sync.walk.lock();
    let Some(walk) = walk_for(&mut w, hop, &b.root) else { return Ok(()) };
    let theirs: HashMap<Bytes32, Bytes32> = b.entries.unwrap_or_default().iter().map(|e| (opt_k32(&e.path), opt_k32(&e.hash))).collect();
    let buckets: HashSet<u8> = theirs.keys().map(|p| p[0]).collect();
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
        if !theirs.contains_key(p) && (buckets.contains(&p[0]) || theirs.is_empty()) {
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
        return finish(n, &raw, rem.into_iter().map(|(k, key)| (k, key, None)).collect());
    }
    walk.batches_left = want.len().div_ceil(512);
    for chunk in want.chunks(512) {
        hop.send_control(HopMsg::GetLeaves(Box::new(wp::GetLeaves { root: b.root, paths: Some(chunk.iter().map(crypto::k32).collect()) })));
    }
    Ok(())
}

fn on_leaves(n: &Arc<Node>, hop: &Arc<Hop>, l: wp::Leaves) -> Result<()> {
    let mut w = n.sync.walk.lock();
    let Some(walk) = walk_for(&mut w, hop, &l.root) else { return Ok(()) };
    for x in l.leaves.unwrap_or_default() {
        walk.fetched.push((x.kind, opt_k32(&x.key), x.bytes.unwrap_or_default()));
    }
    walk.batches_left = walk.batches_left.saturating_sub(1);
    if walk.batches_left > 0 {
        return Ok(());
    }
    let raw = walk.head_raw.clone();
    let mut updates: Vec<(u8, Bytes32, Option<Vec<u8>>)> = walk.removals.iter().map(|(k, key)| (*k, *key, None)).collect();
    updates.extend(walk.fetched.drain(..).map(|(k, key, b)| (k, key, Some(b))));
    *w = None;
    drop(w);
    // install() checks the resulting root against the signed head, so a
    // peer that sends wrong leaves only makes this walk fail.
    finish(n, &raw, updates)
}

fn finish(n: &Arc<Node>, head_raw: &[u8], updates: Vec<(u8, Bytes32, Option<Vec<u8>>)>) -> Result<()> {
    n.store.write().install(head_raw, updates)?;
    after_install(n);
    Ok(())
}

fn after_install(n: &Arc<Node>) {
    let (v, root) = {
        let s = n.store.read();
        (s.head().map(|h| h.head.version).unwrap_or(0), s.head().map(|h| h.root()).unwrap_or_default())
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
    let (origin, seq, expires, ty) = match v.ty {
        mt::ENDPOINT_RECORD => {
            let r: wp::EndpointRecord = v.decode()?;
            (opt_k32(&r.node_id), r.seq, r.expires_at, v.ty)
        }
        mt::LINK_STATE_ADVERT => {
            let r: wp::LinkStateAdvert = v.decode()?;
            (opt_k32(&r.origin), r.seq, r.expires_at, v.ty)
        }
        mt::ATTACHMENT_RECORD => {
            let r: wp::AttachmentRecord = v.decode()?;
            (opt_k32(&r.node_id), r.seq, r.expires_at, v.ty)
        }
        _ => bail!("not a record"),
    };
    if expires + SKEW_SHORT_RECORD < now {
        bail!("expired record");
    }
    {
        let s = n.store.read();
        let vw = s.view();
        let info = vw.nodes.get(&origin).ok_or_else(|| anyhow::anyhow!("record from an unknown node"))?;
        if !info.valid || info.key != v.signer {
            bail!("record not signed by the node's current key");
        }
        if ty == mt::LINK_STATE_ADVERT && !info.relay {
            bail!("LinkStateAdvert from a node without RELAY");
        }
    }
    let new = {
        let mut recs = n.records.lock();
        match ty {
            mt::ENDPOINT_RECORD => {
                if recs.endpoints.get(&origin).map(|(r, _)| r.seq >= seq).unwrap_or(false) {
                    false
                } else {
                    recs.endpoints.insert(origin, (v.decode()?, raw.to_vec()));
                    true
                }
            }
            mt::LINK_STATE_ADVERT => {
                if recs.lsas.get(&origin).map(|(r, _)| r.seq >= seq).unwrap_or(false) {
                    false
                } else {
                    recs.lsas.insert(origin, (v.decode()?, raw.to_vec()));
                    true
                }
            }
            _ => {
                if recs.attachments.get(&origin).map(|(r, _)| r.seq >= seq).unwrap_or(false) {
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

/// Forward a new record (§10.6.1): within the core everything; to edge
/// peers LinkStateAdverts and infrastructure endpoints, plus subscribed
/// records. Edge nodes send only to their hops (home relays).
fn flood(n: &Arc<Node>, except: Option<u64>, origin: Bytes32, ty: u16, raw: &[u8]) {
    let i_am_core = is_core(n, &n.me);
    let infra = n.store.read().view().nodes.get(&origin).map(|x| x.relay || x.control).unwrap_or(false);
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
    let hops: Vec<Arc<Hop>> = n.hops.lock().values().filter(|h| h.alive() && !h.restricted && Some(h.id) != except).cloned().collect();
    for h in hops {
        let send = if !i_am_core {
            origin == n.me
        } else if is_core(n, &h.peer) {
            true
        } else {
            ty == mt::LINK_STATE_ADVERT || (ty == mt::ENDPOINT_RECORD && infra) || subs.contains(&h.id)
        };
        if send {
            send_records(&h, vec![raw.to_vec()]);
        }
    }
}

fn on_lookup(n: &Arc<Node>, hop: &Arc<Hop>, l: wp::Lookup) -> Result<()> {
    {
        let mut r = n.sync.lookup_rate.lock();
        let e = r.entry(hop.id).or_insert((Instant::now(), 0));
        if e.0.elapsed() > Duration::from_secs(1) {
            *e = (Instant::now(), 0);
        }
        e.1 += 1;
        if e.1 > 20 {
            bail!("lookup rate exceeded");
        }
    }
    let ids: Vec<Bytes32> = l.node_ids.unwrap_or_default().iter().take(64).map(|k| k.to_bytes()).collect();
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
        }
    }
    if l.subscribe_ttl_s > 0 {
        let until = Instant::now() + Duration::from_secs(l.subscribe_ttl_s.min(600) as u64);
        let mut s = n.sync.subs.lock();
        for id in ids {
            let v = s.entry(id).or_default();
            v.retain(|(h, _)| *h != hop.id);
            v.push((hop.id, until));
        }
    }
    send_records(hop, items);
    Ok(())
}

/// Ask home relays for a peer's records and subscribe (§10.6.2).
pub fn lookup(n: &Arc<Node>, peer: &Bytes32) {
    if is_core(n, &n.me) {
        return;
    }
    {
        let mut p = n.sync.lookups_pending.lock();
        if p.get(peer).map(|t| t.elapsed() < Duration::from_secs(60)).unwrap_or(false) {
            return;
        }
        p.insert(*peer, Instant::now());
    }
    let msg = HopMsg::Lookup(Box::new(wp::Lookup { node_ids: Some(vec![crypto::k32(peer)]), subscribe_ttl_s: 300 }));
    n.broadcast_control(msg, None);
}

// ---------------------------------------------------------------- publishing our own records

pub fn publish_endpoint(n: &Arc<Node>, force: bool) {
    let addrs = crate::transport::my_addrs(n);
    let now = now_ms();
    {
        let last = n.sync.last_endpoint.lock();
        if !force {
            if let Some((a, t)) = last.as_ref() {
                if *a == addrs && now < t + ENDPOINT_REFRESH {
                    return;
                }
            }
        }
    }
    let serving: Vec<wp::Cidr> = n.dataplane.get().map(|d| d.serving_prefixes()).unwrap_or_default().iter().map(webjet_core::types::net_to_cidr).collect();
    let rec = wp::EndpointRecord {
        node_id: Some(crypto::k32(&n.me)),
        addrs: Some(addrs.clone()),
        nat: crate::transport::nat_type(n),
        software: Some(format!("webjetd/{}", env!("CARGO_PKG_VERSION"))),
        features: Some(vec!["kcp".into(), "anytls".into()]),
        serving: Some(serving),
        gateway_load: None,
        seq: n.next_seq(),
        issued_at: now,
        expires_at: now + ENDPOINT_LIFETIME,
        priorities: Some(crate::transport::my_priorities(n)),
    };
    let raw = n.kp.sign_obj(mt::ENDPOINT_RECORD, &rec);
    *n.sync.last_endpoint.lock() = Some((addrs, now));
    let _ = accept_record(n, None, &raw);
}

/// Our links for the LSA / attachment: per neighbor, the selected
/// transport's quantized cost (§11.2).
fn my_links(n: &Arc<Node>, relays_only: bool) -> Vec<(Bytes32, Transport, u16, u8)> {
    let peers = n.peers();
    let s = n.store.read();
    let v = s.view();
    let mut out = Vec::new();
    for p in peers {
        let Some(info) = v.nodes.get(&p) else { continue };
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
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

pub fn publish_lsa(n: &Arc<Node>, force: bool) {
    if !n.is_relay() {
        return;
    }
    let links = my_links(n, true);
    let now = now_ms();
    let summary: Vec<(Bytes32, u16, u8)> = links.iter().map(|l| (l.0, l.2, l.3)).collect();
    {
        let last = n.sync.last_lsa.lock();
        if let Some((prev, t)) = last.as_ref() {
            let since = now.saturating_sub(*t);
            if since < 2 * SECOND {
                return;
            }
            let changed = prev.len() != summary.len()
                || prev.iter().zip(summary.iter()).any(|(a, b)| a.0 != b.0 || (a.1 as f64 - b.1 as f64).abs() > a.1 as f64 * 0.2 + 1.0 || a.2.abs_diff(b.2) > 2);
            if !force && !changed && since < LSA_REFRESH {
                return;
            }
        }
    }
    let load = crate::metrics::relay_load(n);
    let lsa = wp::LinkStateAdvert {
        origin: Some(crypto::k32(&n.me)),
        seq: n.next_seq(),
        links: Some(links.iter().map(|(p, t, rtt, loss)| wp::LinkEntry { peer: Some(crypto::k32(p)), transport: *t, rtt_ms: *rtt, loss_pct: *loss, util_pct: load.util_pct }).collect()),
        load: Some(Box::new(load)),
        issued_at: now,
        expires_at: now + LSA_LIFETIME,
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
        if let Some((prev, t)) = last.as_ref() {
            if *prev == ids && now < t + ATTACH_REFRESH {
                return;
            }
        }
    }
    let rec = wp::AttachmentRecord {
        node_id: Some(crypto::k32(&n.me)),
        seq: n.next_seq(),
        relays: Some(relays.iter().map(|(p, t, rtt, loss)| wp::AttachmentEntry { relay: Some(crypto::k32(p)), transport: *t, rtt_ms: *rtt, loss_pct: *loss }).collect()),
        issued_at: now,
        expires_at: now + ATTACH_LIFETIME,
    };
    let raw = n.kp.sign_obj(mt::ATTACHMENT_RECORD, &rec);
    *n.sync.last_attach.lock() = Some((ids, now));
    let _ = accept_record(n, None, &raw);
}

/// Drop expired records and records of nodes that are no longer valid.
pub fn expire_records(n: &Arc<Node>) {
    let now = now_ms();
    let s = n.store.read();
    let v = s.view();
    let ok = |id: &Bytes32, exp: u64| exp + SKEW_SHORT_RECORD >= now && v.nodes.get(id).map(|x| x.valid).unwrap_or(false);
    let mut recs = n.records.lock();
    // Relays' endpoint records are kept as reconnection hints even after expiry (§10.4).
    recs.endpoints.retain(|id, (r, _)| ok(id, r.expires_at) || v.nodes.get(id).map(|x| x.valid && (x.relay || x.control)).unwrap_or(false));
    recs.lsas.retain(|id, (r, _)| ok(id, r.expires_at));
    recs.attachments.retain(|id, (r, _)| ok(id, r.expires_at));
}

/// Build the routing graph from LSAs and attachments (§11.4).
pub fn graph(n: &Node) -> webjet_core::routing::Graph {
    use webjet_core::routing::{link_cost, Graph, RelayInfo};
    let now = now_ms();
    let recs = n.records.lock();
    let s = n.store.read();
    let v = s.view();
    let mut g = Graph::default();
    for (id, (l, _)) in &recs.lsas {
        if l.expires_at + SKEW_SHORT_RECORD < now || !v.nodes.get(id).map(|x| x.valid && x.relay).unwrap_or(false) {
            continue;
        }
        let load = l.load.as_ref().map(|x| webjet_core::routing::relay_load(x.util_pct, x.cpu_pct, x.circuits_pct)).unwrap_or(0);
        let links = l.links.clone().unwrap_or_default().iter().map(|e| (opt_k32(&e.peer), link_cost(e.rtt_ms as f64, e.loss_pct as f64 / 100.0))).collect();
        g.relays.insert(*id, RelayInfo { links, load, capacity_mbps: l.load.as_ref().map(|x| x.capacity_mbps).unwrap_or(0) });
    }
    for (id, (a, _)) in &recs.attachments {
        if a.expires_at + SKEW_SHORT_RECORD < now || !v.nodes.get(id).map(|x| x.valid).unwrap_or(false) {
            continue;
        }
        let m = a.relays.clone().unwrap_or_default().iter().map(|e| (opt_k32(&e.relay), link_cost(e.rtt_ms as f64, e.loss_pct as f64 / 100.0))).collect();
        g.attachments.insert(*id, m);
    }
    // Our own live links are measured directly and always current.
    if !v.nodes.get(&n.me).map(|x| x.relay).unwrap_or(false) {
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
    loop {
        tick.tick().await;
        i += 1;
        // Digest exchange within the core (§10.3.1).
        if is_core(&n, &n.me) {
            let d = crypto::k32(&n.store.read().digest());
            let hops: Vec<Arc<Hop>> = n.hops.lock().values().filter(|h| h.alive() && is_core(&n, &h.peer)).cloned().collect();
            let fanout = if hops.len() > 64 { 4 } else { hops.len() };
            use rand::seq::SliceRandom;
            for h in hops.choose_multiple(&mut rand::thread_rng(), fanout) {
                h.send_control(HopMsg::Digest(Box::new(wp::Digest { digest: Some(d) })));
            }
        }
        if i % 600 == 0 {
            push_head(&n);
        }
        // Stuck walk: give up after 30 s.
        {
            let mut w = n.sync.walk.lock();
            if w.as_ref().map(|x| x.started.elapsed() > Duration::from_secs(30)).unwrap_or(false) {
                *w = None;
            }
        }
        if i % 5 == 1 {
            publish_endpoint(&n, false);
            publish_lsa(&n, false);
        }
        if i % 5 == 3 {
            publish_attachment(&n);
        }
        if i % 30 == 0 {
            expire_records(&n);
            n.sync.subs.lock().retain(|_, v| {
                v.retain(|(_, u)| *u > Instant::now());
                !v.is_empty()
            });
            let live: HashSet<u64> = n.hops.lock().keys().copied().collect();
            n.sync.head_rx.lock().retain(|h, _| live.contains(h));
        }
    }
}
