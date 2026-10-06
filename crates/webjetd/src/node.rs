//! The agent's shared state and hop-session management (§9, §10.6, §11.2).

use crate::config::Config;
use crate::state::{self, Paths};
use anyhow::{Result, anyhow, bail};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use webjet_core::crypto::{self, Bytes32, KeyPair, opt_k32};
use webjet_core::queue::{HopQueue, Item};
use webjet_core::routing::LinkStats;
use webjet_core::store::Store;
use webjet_core::types::now_ms;
use webjet_net::gate::SharedEpochs;
use webjet_net::hop::{self, BoxIo, Established, rec};
use webjet_net::kcp::{KcpStats, UdpEndpoint};
use webjet_net::tls::PeerTrust;
use webjet_proto::{self as wp, Decodable, Encodable, HopMsg, Transport};

pub const KEEPALIVE: Duration = Duration::from_secs(2);
pub const HOP_DEAD: Duration = Duration::from_secs(15);

static HOP_IDS: AtomicU64 = AtomicU64::new(1);

/// An encoded hop record carrying a control message.
pub fn ctl(msg: HopMsg) -> Vec<u8> {
    hop::encode_record(
        rec::CONTROL,
        &wp::HopControl { msg: Some(msg) }.encode_bytes(),
    )
}

/// Offset of the relay header's hop-limit/ECN byte inside an encoded record.
const RELAY_ECN_OFFSET: usize = 4 + 4;

/// Data waiting in a hop's writer.
pub enum Out {
    Control(Vec<u8>),
    Relay { flow: u64, frame: Vec<u8> },
}

pub struct Hop {
    pub id: u64,
    pub peer: Bytes32,
    pub peer_key: Bytes32,
    pub transport: Transport,
    pub remote: SocketAddr,
    pub outbound: bool,
    /// Reached us with an old PSK epoch: only synchronization is allowed (§10.7.3).
    pub restricted: bool,
    pub created: Instant,
    tx: mpsc::Sender<Out>,
    ctl_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub closed: AtomicBool,
    pub intentional: AtomicBool,
    pub stats: Mutex<LinkStats>,
    pub last_rx: Mutex<Instant>,
    pub kcp_stats: Option<Arc<KcpStats>>,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub dropped: AtomicU64,
    /// The peer's wall clock minus ours, in ms (§18.6).
    pub clock_offset: Mutex<Option<i64>>,
    /// Our address as the peer saw it (§11.7).
    pub observed: Mutex<Option<SocketAddr>>,
    pub peer_digest: Mutex<Option<Bytes32>>,
    pub keepalive_seq: AtomicU64,
    pub queue_delay_us: AtomicU64,
}

impl Hop {
    pub fn send_control(&self, msg: HopMsg) {
        let _ = self.ctl_tx.send(ctl(msg));
    }

    pub fn send_raw_control(&self, bytes: Vec<u8>) {
        let _ = self.ctl_tx.send(bytes);
    }

    /// Queue a relay frame; returns false when the hop is congested/closed.
    pub fn send_relay(&self, flow: u64, frame: Vec<u8>) -> bool {
        let frame = hop::encode_record(rec::RELAY, &frame);
        match self.tx.try_send(Out::Relay { flow, frame }) {
            Ok(()) => true,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn alive(&self) -> bool {
        !self.closed.load(Ordering::Relaxed)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    /// Close on purpose (duplicate, revocation, shutdown): not a link failure.
    pub fn retire(&self) {
        self.intentional.store(true, Ordering::Relaxed);
        self.close();
    }

    pub fn cost(&self) -> f64 {
        self.stats.lock().cost()
    }
}

/// The trust store behind a lock whose read side is recursive: many helpers
/// read the store while a caller already holds a read guard, and a plain
/// fair RwLock would deadlock as soon as a writer queues between the two.
pub struct StoreLock(RwLock<Store>);

impl StoreLock {
    pub fn new(s: Store) -> Self {
        StoreLock(RwLock::new(s))
    }
    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, Store> {
        self.0.read_recursive()
    }
    pub fn write(&self) -> parking_lot::RwLockWriteGuard<'_, Store> {
        self.0.write()
    }
}

/// Signed soft state from nodes (§6.2, §6.7, §6.8).
#[derive(Default)]
pub struct Records {
    pub endpoints: HashMap<Bytes32, (wp::EndpointRecord, Vec<u8>)>,
    pub lsas: HashMap<Bytes32, (wp::LinkStateAdvert, Vec<u8>)>,
    pub attachments: HashMap<Bytes32, (wp::AttachmentRecord, Vec<u8>)>,
    /// Nodes whose latest EndpointRecord came from software below the
    /// gossip protocol floor (§10.6.5): their records are ignored, this is
    /// only kept to show which version they run.
    pub outdated: HashMap<Bytes32, Outdated>,
}

/// A node ignored for its old gossip protocol (§10.6.5).
#[derive(Clone, Debug)]
pub struct Outdated {
    pub software: String,
    pub protocol: u16,
    pub seq: u64,
    pub expires_at: u64,
    /// The EndpointRecord, signed: lookups answer with it so edge nodes
    /// learn the version too; it is never flooded.
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum Event {
    HeadChanged,
    HopUp(Bytes32),
    HopDown(Bytes32),
    RecordsChanged(Bytes32),
    PskChanged,
}

pub struct Node {
    pub cfg: Config,
    pub paths: Paths,
    pub kp: KeyPair,
    pub me: Bytes32,
    pub store: StoreLock,
    pub epochs: SharedEpochs,
    pub hops: Mutex<HashMap<u64, Arc<Hop>>>,
    pub records: Mutex<Records>,
    pub udp: OnceLock<Arc<UdpEndpoint>>,
    pub events: tokio::sync::broadcast::Sender<Event>,
    pub boot_id: [u8; 16],
    pub started: Instant,
    pub dialing: Mutex<HashSet<(Bytes32, Transport)>>,
    /// The router's port mapping for the UDP socket (§11.7), if any.
    pub port_mapping: Mutex<Option<crate::nat::Mapped>>,
    pub node_file: Mutex<state::NodeFile>,
    pub circuits: Mutex<crate::circuit::Table>,
    pub e2e: crate::e2e::Sessions,
    pub dataplane: OnceLock<Arc<crate::dataplane::Dataplane>>,
    pub controller: OnceLock<Arc<crate::controller::Controller>>,
    pub sync: crate::gossip::SyncState,
    pub alarms: Mutex<HashMap<String, (String, u64)>>,
    /// Long-term link memory per (neighbor, transport), persisted (§11.2).
    pub link_history: Mutex<HashMap<(Bytes32, Transport), webjet_core::routing::LinkHistory>>,
    pub metrics: crate::metrics::Counters,
    pub seq: AtomicU64,
    /// Hop handshakes in progress per source IP (§16.2).
    pub hop_handshakes: crate::transport::HandshakeGate,
    #[cfg(feature = "anytls")]
    pub anytls_acceptor: Mutex<
        Option<(
            Arc<boring::ssl::SslAcceptor>,
            webjet_net::anytls::CamouflageSecret,
            bool,
        )>,
    >,
    pub me_weak: OnceLock<Weak<Node>>,
    /// The agent's long-running tasks (`tasks`).
    pub tasks: crate::tasks::Supervisor,
}

/// Trust for hop TLS: a currently trusted node, or (for resync when the
/// validity horizon has passed) a controller or relay with a record.
#[derive(Debug)]
pub struct HopTrust(pub Weak<Node>);

impl PeerTrust for HopTrust {
    fn trusted(&self, key: &Bytes32) -> bool {
        let Some(n) = self.0.upgrade() else {
            return false;
        };
        let s = n.store.read();
        if s.trusted_by_key(key).is_some() {
            return true;
        }
        let v = s.view();
        v.by_key
            .get(key)
            .and_then(|id| v.nodes.get(id))
            .map(|ni| ni.valid && (ni.relay || ni.control))
            .unwrap_or(false)
    }
}

impl Node {
    pub fn new(
        cfg: Config,
        kp: KeyPair,
        me: Bytes32,
        store: Store,
        epochs: SharedEpochs,
        node_file: state::NodeFile,
    ) -> Arc<Node> {
        let (events, _) = tokio::sync::broadcast::channel(1024);
        let paths = Paths::new(&cfg.data_dir);
        let n = Arc::new(Node {
            paths,
            kp,
            me,
            store: StoreLock::new(store),
            epochs,
            hops: Mutex::new(HashMap::new()),
            records: Mutex::new(Records::default()),
            udp: OnceLock::new(),
            events,
            boot_id: crypto::random16(),
            started: Instant::now(),
            dialing: Mutex::new(HashSet::new()),
            port_mapping: Mutex::new(None),
            node_file: Mutex::new(node_file),
            circuits: Mutex::new(crate::circuit::Table::default()),
            e2e: crate::e2e::Sessions::default(),
            dataplane: OnceLock::new(),
            controller: OnceLock::new(),
            sync: crate::gossip::SyncState::default(),
            alarms: Mutex::new(HashMap::new()),
            link_history: Mutex::new(crate::state::load_links(&Paths::new(&cfg.data_dir))),
            metrics: crate::metrics::Counters::default(),
            seq: AtomicU64::new(now_ms()),
            hop_handshakes: crate::transport::HandshakeGate::default(),
            #[cfg(feature = "anytls")]
            anytls_acceptor: Mutex::new(None),
            me_weak: OnceLock::new(),
            tasks: crate::tasks::Supervisor::default(),
            cfg,
        });
        let _ = n.me_weak.set(Arc::downgrade(&n));
        n
    }

    pub fn trust(&self) -> Arc<dyn PeerTrust> {
        Arc::new(HopTrust(self.me_weak.get().cloned().unwrap_or_default()))
    }

    pub fn next_seq(&self) -> u64 {
        let now = now_ms();
        let prev = self.seq.fetch_max(now, Ordering::SeqCst);
        if prev >= now {
            self.seq.fetch_add(1, Ordering::SeqCst) + 1
        } else {
            now
        }
    }

    pub fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    pub fn alarm(&self, name: &str, severity: &str, msg: String) {
        let mut a = self.alarms.lock();
        if !a.contains_key(name) {
            tracing::warn!(alarm = name, "{msg}");
        }
        a.entry(name.to_string())
            .or_insert((severity.to_string(), now_ms()));
    }

    pub fn clear_alarm(&self, name: &str) {
        self.alarms.lock().remove(name);
    }

    pub fn is_relay(&self) -> bool {
        self.store
            .read()
            .view()
            .nodes
            .get(&self.me)
            .map(|n| n.relay)
            .unwrap_or(false)
    }

    pub fn is_controller(&self) -> bool {
        self.controller.get().is_some()
    }

    /// Live hops to a peer, best first.
    pub fn hops_to(&self, peer: &Bytes32) -> Vec<Arc<Hop>> {
        let mut v: Vec<Arc<Hop>> = self
            .hops
            .lock()
            .values()
            .filter(|h| h.peer == *peer && h.alive())
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            a.cost()
                .partial_cmp(&b.cost())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }

    pub fn best_hop(&self, peer: &Bytes32) -> Option<Arc<Hop>> {
        let hops = self.hops_to(peer);
        if hops.is_empty() {
            return None;
        }
        // Transport choice (§9.6): lowest cost; near ties by priority.
        let view_prio = |t: Transport| crate::transport::priority(self, &self.me, t);
        let cands: Vec<webjet_core::routing::TransportCand> = hops
            .iter()
            .map(|h| webjet_core::routing::TransportCand {
                transport: h.transport,
                cost: {
                    let c = h.cost();
                    if c.is_finite() { c } else { 1e6 }
                },
                prio_sum: view_prio(h.transport) as u16
                    + crate::transport::priority(self, &h.peer, h.transport) as u16,
            })
            .collect();
        let t = webjet_core::routing::choose_transport(&cands)?;
        hops.into_iter().find(|h| h.transport == t)
    }

    pub fn peers(&self) -> Vec<Bytes32> {
        let mut v: Vec<Bytes32> = self
            .hops
            .lock()
            .values()
            .filter(|h| h.alive())
            .map(|h| h.peer)
            .collect();
        v.sort();
        v.dedup();
        v
    }

    pub fn broadcast_control(&self, msg: HopMsg, except: Option<u64>) {
        let bytes = ctl(msg);
        for h in self.hops.lock().values() {
            if Some(h.id) != except && h.alive() && !h.restricted {
                h.send_raw_control(bytes.clone());
            }
        }
    }

    // ------------------------------------------------------------ registering hop sessions

    /// Take over an authenticated hop stream: identify the peer, register it
    /// and start its reader, writer and keepalive tasks.
    pub fn register_hop(self: &Arc<Self>, est: Established, outbound: bool) -> Result<Arc<Hop>> {
        let peer = {
            let s = self.store.read();
            let v = s.view();
            let id = *v
                .by_key
                .get(&est.peer_key)
                .ok_or_else(|| anyhow!("hop peer has no node record"))?;
            if !v
                .nodes
                .get(&id)
                .map(|n| n.valid && n.key == est.peer_key)
                .unwrap_or(false)
            {
                bail!("hop peer is not valid");
            }
            id
        };
        if peer == self.me {
            bail!("connected to myself");
        }
        // One hop per (peer, transport): the lower node id's outbound wins.
        {
            let hops = self.hops.lock();
            if let Some(dup) = hops
                .values()
                .find(|h| h.peer == peer && h.transport == est.transport && h.alive())
            {
                let keep_new = (self.me < peer) == outbound;
                if !keep_new {
                    bail!("duplicate hop to {}", crypto::short(&peer));
                }
                dup.retire();
            }
        }
        let (tx, rx) = mpsc::channel::<Out>(8192);
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let hop = Arc::new(Hop {
            id: HOP_IDS.fetch_add(1, Ordering::Relaxed),
            peer,
            peer_key: est.peer_key,
            transport: est.transport,
            remote: est.remote,
            outbound,
            restricted: est.bootstrap,
            created: Instant::now(),
            tx,
            ctl_tx,
            closed: AtomicBool::new(false),
            intentional: AtomicBool::new(false),
            stats: Mutex::new(LinkStats::with_history(
                self.link_history
                    .lock()
                    .get(&(peer, est.transport))
                    .cloned()
                    .map(|mut h| {
                        h.age(now_ms());
                        h
                    })
                    .unwrap_or_default(),
            )),
            last_rx: Mutex::new(Instant::now()),
            kcp_stats: est.kcp_stats.clone(),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            clock_offset: Mutex::new(None),
            observed: Mutex::new(None),
            peer_digest: Mutex::new(None),
            keepalive_seq: AtomicU64::new(0),
            queue_delay_us: AtomicU64::new(0),
        });
        self.hops.lock().insert(hop.id, hop.clone());
        tracing::info!(peer = %self.name_of(&peer), transport = est.transport.name(), remote = %est.remote, outbound, "hop up");
        let (r, w) = tokio::io::split(est.io);
        let n = self.clone();
        let h = hop.clone();
        tokio::spawn(async move { writer(n, h, w, rx, ctl_rx).await });
        let n = self.clone();
        let h = hop.clone();
        tokio::spawn(async move { reader(n, h, r).await });
        let n = self.clone();
        let h = hop.clone();
        tokio::spawn(async move { keepalive(n, h).await });
        crate::gossip::on_hop_up(self, &hop);
        self.emit(Event::HopUp(peer));
        Ok(hop)
    }

    pub fn hop_down(self: &Arc<Self>, hop: &Arc<Hop>) {
        let failed =
            !hop.intentional.load(Ordering::Relaxed) && !hop.closed.load(Ordering::Relaxed);
        hop.close();
        if self.hops.lock().remove(&hop.id).is_some() {
            // Fold this session into the link's long-term record.
            let mut h = hop.stats.lock().history.clone();
            if failed && h.samples > 0 {
                h.flap(now_ms());
            }
            self.link_history
                .lock()
                .insert((hop.peer, hop.transport), h);
            self.metrics
                .retired_tx
                .fetch_add(hop.tx_bytes.load(Ordering::Relaxed), Ordering::Relaxed);
            tracing::info!(peer = %self.name_of(&hop.peer), transport = hop.transport.name(), "hop down");
            crate::circuit::on_hop_down(self, hop);
            self.emit(Event::HopDown(hop.peer));
        }
    }

    /// Tear down everything with peers that are no longer trusted (§10.5):
    /// hop sessions, end-to-end sessions and circuits. Restricted (resync)
    /// hops to relays and controllers are kept.
    pub fn enforce_revocations(self: &Arc<Self>) {
        let dead: Vec<Arc<Hop>> = {
            let s = self.store.read();
            let v = s.view();
            self.hops
                .lock()
                .values()
                .filter(|h| {
                    let info = v.nodes.get(&h.peer);
                    let key_ok = info
                        .map(|x| x.key == h.peer_key && x.valid)
                        .unwrap_or(false);
                    !key_ok
                        || (!s.node_trusted(&h.peer)
                            && !info.map(|x| x.relay || x.control).unwrap_or(false))
                })
                .cloned()
                .collect()
        };
        for h in dead {
            tracing::info!(peer = %crypto::short(&h.peer), "closing hop to a revoked or re-keyed node");
            h.retire();
            self.hop_down(&h);
        }
        crate::circuit::sweep(self);
    }

    pub fn name_of(&self, id: &Bytes32) -> String {
        self.store
            .read()
            .view()
            .nodes
            .get(id)
            .map(|n| n.name.clone())
            .unwrap_or_else(|| crypto::short(id))
    }

    // ------------------------------------------------------------ dialing

    /// Dial a peer over one transport at `addr`, expecting one of `keys`.
    pub async fn dial(
        self: &Arc<Self>,
        addr: SocketAddr,
        t: Transport,
        keys: Vec<Bytes32>,
    ) -> Result<Arc<Hop>> {
        let trust = self.trust();
        let (epoch, psk) = self
            .epochs
            .read()
            .current_key()
            .ok_or_else(|| anyhow!("no PSK yet"))?;
        let est = match t {
            Transport::TcpTls => hop::dial_tls(addr, &self.kp, keys, trust, epoch, &psk).await?,
            Transport::KcpFecTls => {
                let ep = self
                    .udp
                    .get()
                    .ok_or_else(|| anyhow!("no UDP endpoint"))?
                    .clone();
                hop::dial_kcp(&ep, addr, &self.kp, keys, trust).await?
            }
            Transport::AnyTls => self.dial_anytls(addr, keys, trust, &psk).await?,
        };
        self.register_hop(est, true)
    }

    #[cfg(feature = "anytls")]
    async fn dial_anytls(
        &self,
        addr: SocketAddr,
        keys: Vec<Bytes32>,
        trust: Arc<dyn PeerTrust>,
        psk: &Bytes32,
    ) -> Result<Established> {
        let cam = crate::transport::camouflage(self)
            .ok_or_else(|| anyhow!("no camouflage configuration for AnyTLS"))?;
        webjet_net::anytls::dial(addr, &cam, &self.kp, keys, trust, psk).await
    }

    #[cfg(not(feature = "anytls"))]
    async fn dial_anytls(
        &self,
        _: SocketAddr,
        _: Vec<Bytes32>,
        _: Arc<dyn PeerTrust>,
        _: &Bytes32,
    ) -> Result<Established> {
        bail!("built without AnyTLS")
    }

    /// Dial a known node using its EndpointRecord (all transports, best first).
    pub async fn dial_node(self: &Arc<Self>, peer: Bytes32) -> Result<Arc<Hop>> {
        if let Some(h) = self.best_hop(&peer) {
            return Ok(h);
        }
        let key = self
            .store
            .read()
            .view()
            .nodes
            .get(&peer)
            .map(|n| n.key)
            .ok_or_else(|| anyhow!("unknown node"))?;
        let addrs = self.endpoint_addrs(&peer);
        if addrs.is_empty() {
            bail!("no known address for {}", self.name_of(&peer));
        }
        let mut last = anyhow!("no transport worked");
        for (addr, t) in addrs {
            if !self.dialing.lock().insert((peer, t)) {
                continue;
            }
            let r = self.dial(addr, t, vec![key]).await;
            self.dialing.lock().remove(&(peer, t));
            match r {
                Ok(h) => return Ok(h),
                Err(e) => {
                    tracing::debug!(
                        "dial {} via {} at {addr}: {e}",
                        self.name_of(&peer),
                        t.name()
                    );
                    last = e;
                }
            }
        }
        Err(last)
    }

    /// Candidate addresses of a node, best transport first.
    pub fn endpoint_addrs(&self, peer: &Bytes32) -> Vec<(SocketAddr, Transport)> {
        // Clone first: priority() takes the records lock itself.
        let Some(r) = self
            .records
            .lock()
            .endpoints
            .get(peer)
            .map(|(r, _)| r.clone())
        else {
            return Vec::new();
        };
        let mut v: Vec<(u8, SocketAddr, Transport)> = r
            .addrs
            .unwrap_or_default()
            .iter()
            .filter_map(|a| {
                let sa = a.addr.as_ref()?.to_sock()?;
                let p = crate::transport::priority(self, &self.me, a.transport) as u16
                    + crate::transport::priority(self, peer, a.transport) as u16;
                if crate::transport::priority(self, &self.me, a.transport) == 0 {
                    return None;
                }
                Some(((p / 2) as u8, sa, a.transport))
            })
            .collect();
        v.sort_by(|a, b| b.0.cmp(&a.0).then(a.2.tie_rank().cmp(&b.2.tie_rank())));
        v.into_iter().map(|(_, a, t)| (a, t)).collect()
    }

    // ------------------------------------------------------------ persistence

    pub fn persist_store(&self) {
        let s = self.store.read();
        if let Err(e) = state::save_store(&self.paths, &s) {
            tracing::error!("saving state: {e}");
        }
    }

    /// Save long-term link history (live hops included).
    pub fn persist_links(&self) {
        let mut book = self.link_history.lock().clone();
        for h in self.hops.lock().values() {
            book.insert((h.peer, h.transport), h.stats.lock().history.clone());
        }
        let now = now_ms();
        // Forget links not seen for 30 days.
        book.retain(|_, h| now.saturating_sub(h.updated_ms) < 30 * 24 * 3_600_000);
        *self.link_history.lock() = book.clone();
        if let Err(e) = crate::state::save_links(&self.paths, &book) {
            tracing::debug!("saving link history: {e}");
        }
    }

    pub fn persist_psk(&self) {
        let e = self.epochs.read().clone();
        if let Err(err) = state::save_psk(&self.paths, &e) {
            tracing::error!("saving PSK epochs: {err}");
        }
    }

    /// Install new PSK epochs (from a controller or enrollment).
    pub fn set_psk(&self, current: u16, epochs: Vec<(u16, Bytes32)>) {
        {
            let mut e = self.epochs.write();
            let changed =
                e.current != current || epochs.iter().any(|(k, v)| e.keys.get(k) != Some(v));
            if !changed {
                return;
            }
            for (k, v) in epochs {
                e.keys.insert(k, v);
            }
            e.current = current;
            // Keep the current and previous epoch, plus everything on seeds/controllers.
            if !e.accept_all {
                let keep = [current, current.wrapping_sub(1)];
                e.keys.retain(|k, _| keep.contains(k));
            }
        }
        if let Some(u) = self.udp.get() {
            u.refresh_epochs();
        }
        self.persist_psk();
        self.emit(Event::PskChanged);
    }
}

// ---------------------------------------------------------------- per-hop tasks

async fn writer(
    n: Arc<Node>,
    hop: Arc<Hop>,
    mut w: WriteHalf<BoxIo>,
    mut rx: mpsc::Receiver<Out>,
    mut ctl_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let mut q = HopQueue::new(4 << 20);
    // The TransportConfig's padding scheme, else the built-in one (§9.7.4).
    let mut pad_budget = n
        .store
        .read()
        .view()
        .transport
        .as_ref()
        .and_then(|t| t.padding.as_deref())
        .and_then(|p| webjet_core::padding::Scheme::from_wire(p).ok())
        .unwrap_or_else(webjet_core::padding::Scheme::default_scheme);
    let mut pkt_no: u32 = 0;
    let mut tune_at = Instant::now();
    loop {
        if !hop.alive() {
            break;
        }
        // Control records go out zstd-compressed where both ends have it
        // on (§9.8).
        let z = |c: Vec<u8>| crate::compression::control_record(&n, &hop.peer, c);
        // Gather what's ready.
        if q.is_empty() {
            tokio::select! {
                m = ctl_rx.recv() => match m { Some(c) => q.push_control(z(c)), None => break },
                m = rx.recv() => match m {
                    Some(Out::Control(c)) => q.push_control(z(c)),
                    Some(Out::Relay { flow, frame }) => { let _ = q.push(Item { flow, data: frame, at: Instant::now(), ecn_offset: Some(RELAY_ECN_OFFSET) }); }
                    None => break,
                },
                _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
            }
        }
        while let Ok(c) = ctl_rx.try_recv() {
            q.push_control(z(c));
        }
        while let Ok(m) = rx.try_recv() {
            match m {
                Out::Control(c) => q.push_control(z(c)),
                Out::Relay { flow, frame } => {
                    let _ = q.push(Item {
                        flow,
                        data: frame,
                        at: Instant::now(),
                        ecn_offset: Some(RELAY_ECN_OFFSET),
                    });
                }
            }
        }
        if tune_at.elapsed() > Duration::from_secs(1) {
            let rtt = Duration::from_micros((hop.stats.lock().srtt_ms * 1000.0) as u64);
            q.tune(rtt, 12_500_000.0);
            tune_at = Instant::now();
        }
        let mut batch = Vec::with_capacity(64 * 1024);
        let now = Instant::now();
        while batch.len() < 64 * 1024 {
            let Some(item) = q.pop(now) else { break };
            batch.extend_from_slice(&item);
            pkt_no += 1;
            // Padding for the first packets of the session (§9.7.4).
            if let Some(plan) = pad_budget.plan(pkt_no, item.len()) {
                let pad: usize = plan.iter().map(|x| x.1).sum();
                if pad > 0 {
                    batch.extend_from_slice(&hop::encode_record(
                        rec::PAD,
                        &vec![0u8; pad.min(4096)],
                    ));
                }
            } else if pkt_no > 64 {
                pad_budget.stop = 0;
            }
        }
        hop.queue_delay_us
            .store(q.stats.last_sojourn.as_micros() as u64, Ordering::Relaxed);
        n.metrics
            .ecn_marked
            .fetch_add(std::mem::take(&mut q.stats.marked), Ordering::Relaxed);
        n.metrics.aqm_dropped.fetch_add(
            std::mem::take(&mut q.stats.dropped_aqm) + std::mem::take(&mut q.stats.dropped_full),
            Ordering::Relaxed,
        );
        if batch.is_empty() {
            continue;
        }
        hop.tx_bytes
            .fetch_add(batch.len() as u64, Ordering::Relaxed);
        if w.write_all(&batch).await.is_err() || w.flush().await.is_err() {
            break;
        }
    }
    let _ = w.shutdown().await;
    n.hop_down(&hop);
}

async fn reader(n: Arc<Node>, hop: Arc<Hop>, mut r: ReadHalf<BoxIo>) {
    loop {
        let res = tokio::select! {
            r = hop::read_record(&mut r) => r,
            _ = tokio::time::sleep(HOP_DEAD) => {
                if hop.last_rx.lock().elapsed() > HOP_DEAD { break } else { continue }
            }
        };
        let (ty, payload) = match res {
            Ok(x) => x,
            Err(_) => break,
        };
        if !hop.alive() {
            break;
        }
        *hop.last_rx.lock() = Instant::now();
        hop.rx_bytes
            .fetch_add(payload.len() as u64 + 4, Ordering::Relaxed);
        let (ty, payload) = if ty == rec::CONTROL_ZSTD {
            match crate::compression::control_payload(&n, &payload) {
                Some(p) => (rec::CONTROL, p),
                None => {
                    tracing::debug!(peer = %n.name_of(&hop.peer), "bad compressed control record");
                    continue;
                }
            }
        } else {
            (ty, payload)
        };
        match ty {
            rec::CONTROL => match wp::HopControl::decode_bytes(&payload) {
                Ok(c) => {
                    if let Some(m) = c.msg
                        && let Err(e) = handle_control(&n, &hop, m).await
                    {
                        tracing::debug!(peer = %n.name_of(&hop.peer), "control message: {e}");
                    }
                }
                Err(e) => tracing::debug!("bad control message: {e}"),
            },
            rec::RELAY if !hop.restricted => {
                crate::circuit::on_relay_frame(&n, &hop, payload);
            }
            _ => {}
        }
    }
    n.hop_down(&hop);
}

async fn keepalive(n: Arc<Node>, hop: Arc<Hop>) {
    let mut t = tokio::time::interval(KEEPALIVE);
    loop {
        t.tick().await;
        if !hop.alive() {
            break;
        }
        if hop.last_rx.lock().elapsed() > HOP_DEAD {
            tracing::debug!(peer = %n.name_of(&hop.peer), "hop timed out");
            n.hop_down(&hop);
            break;
        }
        let seq = hop.keepalive_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let us = n.started.elapsed().as_micros() as u64;
        hop.stats.lock().on_sent(seq, us);
        let digest = if n.is_relay() || n.is_controller() {
            None
        } else {
            Some(crypto::k32(&n.store.read().digest()))
        };
        hop.send_control(HopMsg::Keepalive(Box::new(wp::Keepalive {
            seq,
            echo_us: us,
            wall_ms: now_ms(),
            digest,
        })));
    }
}

async fn handle_control(n: &Arc<Node>, hop: &Arc<Hop>, m: HopMsg) -> Result<()> {
    match m {
        HopMsg::Keepalive(k) => {
            hop.send_control(HopMsg::KeepaliveAck(Box::new(wp::KeepaliveAck {
                seq: k.seq,
                echo_us: k.echo_us,
                wall_ms: now_ms(),
                observed_addr: Some(wp::SockAddr::from_sock(hop.remote)),
            })));
            if let Some(d) = k.digest {
                crate::gossip::on_digest(n, hop, d.to_bytes());
            }
        }
        HopMsg::KeepaliveAck(a) => {
            let now_us = n.started.elapsed().as_micros() as u64;
            if let Some(rtt) = hop.stats.lock().on_ack(a.seq, now_us) {
                // Clock offset (§18.6): their wall clock vs ours at the midpoint.
                let mid = now_ms() as i64 - (rtt / 2.0) as i64;
                *hop.clock_offset.lock() = Some(a.wall_ms as i64 - mid);
            }
            if let Some(o) = a.observed_addr.and_then(|o| o.to_sock()) {
                *hop.observed.lock() = Some(o);
            }
            crate::health::check_clock(n);
        }
        HopMsg::Digest(d) => {
            if let Some(dg) = d.digest {
                crate::gossip::on_digest(n, hop, dg.to_bytes());
            }
        }
        HopMsg::CircuitOpen(o) if !hop.restricted => crate::circuit::on_open(n, hop, *o).await?,
        HopMsg::CircuitAccept(a) if !hop.restricted => crate::circuit::on_accept(n, hop, *a),
        HopMsg::CircuitRefuse(r) if !hop.restricted => crate::circuit::on_refuse(n, hop, *r),
        HopMsg::CircuitClose(c) if !hop.restricted => crate::circuit::on_close(n, hop, c.label),
        other => crate::gossip::handle(n, hop, other).await?,
    }
    Ok(())
}

pub fn opt_bytes(k: &Option<wp::Key32>) -> Bytes32 {
    opt_k32(k)
}

/// What a test hop's writer would have sent.
#[cfg(test)]
pub(crate) struct TestHopRx {
    pub data: mpsc::Receiver<Out>,
    pub ctl: mpsc::UnboundedReceiver<Vec<u8>>,
}

#[cfg(test)]
impl TestHopRx {
    /// Control messages queued so far, decoded.
    pub fn control(&mut self) -> Vec<HopMsg> {
        let mut out = Vec::new();
        while let Ok(rec) = self.ctl.try_recv() {
            let c = wp::HopControl::decode_bytes(&rec[4..]).expect("control record");
            out.extend(c.msg);
        }
        out
    }

    /// Relay frames (payloads of RELAY records) queued so far.
    pub fn relay(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Ok(o) = self.data.try_recv() {
            if let Out::Relay { frame, .. } = o {
                out.push(frame[4..].to_vec());
            }
        }
        out
    }
}

#[cfg(test)]
impl Node {
    /// Register a hop to `peer` without a connection: what it sends is read
    /// from the returned receivers.
    pub(crate) fn test_hop(&self, peer: Bytes32, transport: Transport) -> (Arc<Hop>, TestHopRx) {
        let (tx, data) = mpsc::channel::<Out>(1024);
        let (ctl_tx, ctl) = mpsc::unbounded_channel::<Vec<u8>>();
        let peer_key = self
            .store
            .read()
            .view()
            .nodes
            .get(&peer)
            .map(|x| x.key)
            .unwrap_or_default();
        let hop = Arc::new(Hop {
            id: HOP_IDS.fetch_add(1, Ordering::Relaxed),
            peer,
            peer_key,
            transport,
            remote: "192.0.2.1:443".parse().expect("address"),
            outbound: true,
            restricted: false,
            created: Instant::now(),
            tx,
            ctl_tx,
            closed: AtomicBool::new(false),
            intentional: AtomicBool::new(false),
            stats: Mutex::new(LinkStats::default()),
            last_rx: Mutex::new(Instant::now()),
            kcp_stats: None,
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            clock_offset: Mutex::new(None),
            observed: Mutex::new(None),
            peer_digest: Mutex::new(None),
            keepalive_seq: AtomicU64::new(0),
            queue_delay_us: AtomicU64::new(0),
        });
        self.hops.lock().insert(hop.id, hop.clone());
        (hop, TestHopRx { data, ctl })
    }
}
