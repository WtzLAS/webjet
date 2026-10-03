//! Agent lifecycle: enrollment (§8), startup, and keeping hop sessions to
//! relays, seeds and controllers (§10.6, §10.7).

use crate::config::Config;
use crate::node::{Event, Node};
use crate::state::{self, NodeFile, Paths, SeedHint};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use webjet_core::crypto::{self, opt_k32, Bytes32, KeyPair};
use webjet_core::store::{HeadOutcome, Store};
use webjet_net::hop::{self, rec};
use webjet_proto::{self as wp, Decodable, Encodable, RpcBody, Transport};

const TICKET_PREFIX: &str = "wj1:";

pub fn encode_ticket(t: &wp::EnrollmentTicket) -> String {
    format!(
        "{TICKET_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(t.encode_bytes())
    )
}

pub fn decode_ticket(s: &str) -> Result<wp::EnrollmentTicket> {
    let b = s
        .trim()
        .strip_prefix(TICKET_PREFIX)
        .ok_or_else(|| anyhow!("not a webjet enrollment string"))?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b)?;
    Ok(wp::EnrollmentTicket::decode_bytes(&raw)?)
}

fn seed_hint(a: &wp::SeedAddr, node: Option<String>) -> SeedHint {
    SeedHint {
        node,
        host: a.host.clone().unwrap_or_default(),
        port: a.port,
        transport: a.transport.name().into(),
    }
}

async fn resolve(host: &str, port: u16) -> Vec<SocketAddr> {
    match tokio::net::lookup_host((host, port)).await {
        Ok(it) => it.collect(),
        Err(_) => Vec::new(),
    }
}

// ---------------------------------------------------------------- init

/// `webjetd init --genesis`: create the data directory for a new node.
pub fn init(cfg: &Config, genesis: &[u8], bootstrap: bool) -> Result<()> {
    let paths = Paths::new(&cfg.data_dir);
    webjet_core::store::open_genesis(genesis).context("genesis file")?;
    if paths.genesis().exists() {
        bail!(
            "{} already holds a network; remove it to start over",
            cfg.data_dir.display()
        );
    }
    state::write_private(&paths.genesis(), genesis)?;
    let kp = KeyPair::generate();
    let backend = state::save_identity(&paths, &cfg.key, &kp)?;
    println!("identity key stored with {} storage", backend.name());
    let nf = NodeFile {
        node_id: hex::encode(crypto::random32()),
        bootstrap,
        ..Default::default()
    };
    state::save_json(&paths.node(), &nf)?;
    println!(
        "initialized {} (node id {}, key {})",
        cfg.data_dir.display(),
        nf.node_id,
        crypto::key_b64(&kp.public())
    );
    Ok(())
}

// ---------------------------------------------------------------- enrollment client

/// `webjetd enroll <ticket>`: generate a fresh identity key, redeem the
/// token at a controller, verify everything against the root key and store
/// the result. Also used for re-keying (§8.1).
pub async fn enroll(cfg: &Config, ticket_str: &str) -> Result<()> {
    let ticket = decode_ticket(ticket_str)?;
    let paths = Paths::new(&cfg.data_dir);
    // A bootstrapping controller enrolls itself through its running agent.
    if paths.node().exists() {
        let nf: Option<NodeFile> = state::load_json(&paths.node())?;
        if nf.map(|n| n.bootstrap).unwrap_or(false) && cfg.control_socket.exists() {
            let r = crate::control::client::call(&cfg.control_socket, serde_json::json!({"cmd": "redeem_self", "token": state::b64(&ticket.token.clone().unwrap_or_default())})).await?;
            println!("enrolled this controller: {r}");
            return Ok(());
        }
    }
    let token = ticket
        .token
        .clone()
        .ok_or_else(|| anyhow!("ticket without token"))?;
    let root_key = opt_k32(&ticket.root_key);
    let th = crypto::token_hash(&token);
    let kp = KeyPair::generate();
    let nonce = crypto::random32();
    let req = wp::EnrollRequest {
        lookup_id: Some(crypto::k32(&crypto::enroll_lookup_id(&th))),
        identity_key: Some(crypto::k32(&kp.public())),
        nonce: Some(crypto::k32(&nonce)),
        proof: Some(crypto::k32(&crypto::enroll_proof(
            &th,
            &kp.public(),
            &nonce,
        ))),
    };
    let mut last = anyhow!("no controller address in the ticket");
    for c in ticket.controllers.clone().unwrap_or_default() {
        let host = c.host.clone().unwrap_or_default();
        for addr in resolve(&host, c.port).await {
            match enroll_at(addr, c.transport, &ticket, &th, &req).await {
                Ok(resp) => return finish_enrollment(cfg, &paths, &kp, root_key, &ticket, resp),
                Err(e) => {
                    eprintln!("enrollment via {addr} ({}): {e:#}", c.transport.name());
                    last = e;
                }
            }
        }
    }
    Err(last)
}

async fn enroll_at(
    addr: SocketAddr,
    t: Transport,
    ticket: &wp::EnrollmentTicket,
    th: &Bytes32,
    req: &wp::EnrollRequest,
) -> Result<wp::EnrollResponse> {
    let mut io = match t {
        #[cfg(feature = "anytls")]
        Transport::AnyTls => {
            let domain = ticket.camouflage_domain.clone().unwrap_or_default();
            let pin = ticket
                .camouflage_pin
                .map(|p| p.to_bytes())
                .ok_or_else(|| anyhow!("ticket has no camouflage pin"))?;
            let cam = webjet_net::anytls::Camouflage {
                domain,
                chain: vec![],
                pins: vec![pin],
                website: false,
            };
            webjet_net::anytls::dial_enroll(addr, &cam, th).await?
        }
        _ => hop::dial_enroll(addr, th, None).await?,
    };
    hop::write_record(&mut io, rec::CONTROL, &req.encode_bytes()).await?;
    use tokio::io::AsyncWriteExt;
    io.flush().await?;
    let (_, body) = tokio::time::timeout(Duration::from_secs(30), hop::read_record(&mut io))
        .await
        .map_err(|_| anyhow!("no answer"))??;
    let resp = wp::EnrollResponse::decode_bytes(&body)?;
    if !resp.ok {
        bail!(
            "controller refused: {}",
            resp.error.clone().unwrap_or_default()
        );
    }
    let _ = ticket;
    Ok(resp)
}

fn finish_enrollment(
    cfg: &Config,
    paths: &Paths,
    kp: &KeyPair,
    root_key: Bytes32,
    ticket: &wp::EnrollmentTicket,
    resp: wp::EnrollResponse,
) -> Result<()> {
    let genesis = resp
        .genesis
        .clone()
        .ok_or_else(|| anyhow!("response without genesis"))?;
    let (_, groot, _) = webjet_core::store::open_genesis(&genesis)?;
    if groot != root_key {
        bail!("the controller's network has a different root key than the ticket");
    }
    let mut store = Store::new(genesis.clone())?;
    for c in resp
        .certs
        .clone()
        .unwrap_or_default()
        .into_iter()
        .chain(resp.key_tombstones.clone().unwrap_or_default())
        .chain(resp.offline.clone().unwrap_or_default())
    {
        let _ = store.add_offline_item(&c.data.unwrap_or_default());
    }
    let head = resp
        .head
        .clone()
        .ok_or_else(|| anyhow!("response without tree head"))?;
    match store.offer_head(&head)? {
        HeadOutcome::NeedSync | HeadOutcome::Refreshed => {}
        o => bail!("unexpected head outcome {o:?}"),
    }
    let leaves = resp
        .leaves
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|l| (l.kind, opt_k32(&l.key), Some(l.bytes.unwrap_or_default())))
        .collect();
    store
        .install(&head, leaves)
        .context("verifying the network state")?;
    let node_id = opt_k32(&resp.node_id);
    // The inclusion proof for our record (§8 step 5).
    let rec = resp.record.clone().unwrap_or_default();
    let proof =
        webjet_core::merkle::Proof::from_wire(&resp.proof.clone().map(|b| *b).unwrap_or_default());
    let root = store.head().map(|h| h.root()).unwrap_or_default();
    if !webjet_core::merkle::verify_inclusion(
        &root,
        webjet_core::merkle::kind::NODE,
        &node_id,
        &rec,
        &proof,
    ) {
        bail!("our node record is not proven by the signed tree head");
    }
    let info = store
        .view()
        .nodes
        .get(&node_id)
        .ok_or_else(|| anyhow!("no node record for us"))?;
    if info.key != kp.public() {
        bail!("the node record carries a different key");
    }
    let name = info.name.clone();
    let ips: Vec<String> = info.ips.iter().map(|i| i.to_string()).collect();
    std::fs::create_dir_all(&cfg.data_dir)?;
    state::write_private(&paths.genesis(), &genesis)?;
    let backend = state::save_identity(paths, &cfg.key, kp)?;
    println!("identity key stored with {} storage", backend.name());
    state::save_store(paths, &store)?;
    let mut e = webjet_net::gate::Epochs::default();
    for p in resp.psk_epochs.clone().unwrap_or_default() {
        e.keys.insert(p.epoch_id, opt_k32(&p.psk));
    }
    e.current = resp.psk_current;
    state::save_psk(paths, &e)?;
    let mut nf: NodeFile = state::load_json(&paths.node())?.unwrap_or_default();
    nf.node_id = hex::encode(node_id);
    nf.bootstrap = false;
    nf.enroll_controllers = ticket
        .controllers
        .clone()
        .unwrap_or_default()
        .iter()
        .map(|a| seed_hint(a, None))
        .collect();
    nf.camouflage_domain = ticket.camouflage_domain.clone();
    nf.camouflage_pin = ticket.camouflage_pin.map(|p| hex::encode(p.to_bytes()));
    state::save_json(&paths.node(), &nf)?;
    println!(
        "enrolled as {name} ({}) — start webjetd to join the network",
        ips.join(", ")
    );
    Ok(())
}

// ---------------------------------------------------------------- running

pub async fn run(cfg: Config) -> Result<()> {
    run_until(cfg, crate::service::signals()).await
}

/// Run until `shutdown` resolves (a signal, or the Windows service manager).
pub async fn run_until(cfg: Config, shutdown: crate::service::Shutdown) -> Result<()> {
    let paths = Paths::new(&cfg.data_dir);
    crate::keystore::harden_process();
    let kp = state::load_identity(&paths, &cfg.key)?.ok_or_else(|| {
        anyhow!(
            "no identity key in {}; run `webjetd init` or `webjetd enroll` first",
            cfg.data_dir.display()
        )
    })?;
    let genesis = std::fs::read(paths.genesis())
        .with_context(|| format!("no genesis in {}", cfg.data_dir.display()))?;
    let nf: NodeFile =
        state::load_json(&paths.node())?.ok_or_else(|| anyhow!("missing node.json"))?;
    let me = crypto::parse_hex32(&nf.node_id).ok_or_else(|| anyhow!("bad node id in node.json"))?;
    let store = state::load_store(&paths, genesis)?;
    let epochs = Arc::new(parking_lot::RwLock::new(state::load_psk(&paths)?));
    if let Err(e) = crate::health::check_floor_raw(store.trusted_floor) {
        bail!(e);
    }
    let bootstrap = nf.bootstrap;
    let n = Node::new(cfg, kp, me, store, epochs, nf);
    crate::keystore::lock_in_place(&n.kp);
    // Relays cached from the last run (§10.7.1 step 1).
    if let Ok(Some(rc)) = state::load_json::<state::RelayCache>(&n.paths.relays()) {
        for r in rc.endpoints {
            let _ = crate::gossip::accept_record(&n, None, &r);
        }
    }
    {
        let s = n.store.read();
        let enrolled = s.view().nodes.contains_key(&me);
        if !enrolled && !bootstrap && !n.cfg.controller.enabled {
            bail!("this node is not enrolled; run `webjetd enroll <enrollment string>`");
        }
    }
    if n.cfg.controller.enabled || bootstrap {
        let c = crate::controller::Controller::start(&n, bootstrap)?;
        let _ = n.controller.set(c.clone());
        tokio::spawn(c.run());
    }
    // Seed relays accept all epochs too (§10.7.3).
    if is_seed(&n) {
        n.epochs.write().accept_all = true;
    }
    crate::transport::start_listeners(&n).await?;
    {
        let n2 = n.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::control::serve(n2).await {
                tracing::error!("control socket: {e}");
            }
        });
    }
    tokio::spawn(crate::gossip::run(n.clone()));
    tokio::spawn(crate::e2e::run(n.clone()));
    tokio::spawn(crate::paths::run(n.clone()));
    tokio::spawn(crate::metrics::run(n.clone()));
    if let Some(addr) = n.cfg.metrics.listen {
        let n2 = n.clone();
        let body: Arc<dyn Fn() -> String + Send + Sync> =
            Arc::new(move || match n2.controller.get() {
                Some(c) => c.openmetrics(),
                None => crate::metrics::local_openmetrics(&n2),
            });
        tokio::spawn(async move {
            if let Err(e) = crate::exposition::serve(addr, body).await {
                tracing::error!("metrics endpoint on {addr}: {e}");
            }
        });
    }
    tokio::spawn(crate::health::run(n.clone()));
    tokio::spawn(crate::punch::run(n.clone()));
    tokio::spawn(connections(n.clone()));
    tokio::spawn(secrets(n.clone()));
    tokio::spawn(start_dataplane_when_ready(n.clone()));
    crate::transport::refresh_anytls(&n);
    tracing::info!(node = %crypto::short(&me), "webjetd running");
    // Exit on a fatal clock error (§18.6) or a stop request.
    let mut shutdown = shutdown;
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutting down");
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                if let Some(e) = crate::health::CLOCK_FATAL.get() {
                    n.persist_store();
                    bail!("{e}");
                }
            }
        }
    }
    n.persist_store();
    n.persist_links();
    if let Some(dp) = n.dataplane.get() {
        dp.shutdown();
    }
    Ok(())
}

async fn start_dataplane_when_ready(n: Arc<Node>) {
    loop {
        let ready = n
            .store
            .read()
            .view()
            .nodes
            .get(&n.me)
            .map(|x| x.valid)
            .unwrap_or(false);
        if ready {
            match crate::dataplane::start(&n).await {
                Ok(dp) => {
                    let _ = n.dataplane.set(dp);
                    crate::gossip::publish_endpoint(&n, true);
                }
                Err(e) => tracing::error!("data plane: {e:#}"),
            }
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn is_seed(n: &Node) -> bool {
    let s = n.store.read();
    let v = s.view();
    let Some(seeds) = &v.seeds else { return false };
    let my_name = v
        .nodes
        .get(&n.me)
        .map(|x| x.name.clone())
        .unwrap_or_default();
    let my_key = crypto::key_b64(&n.kp.public());
    seeds.entries.clone().unwrap_or_default().iter().any(|e| {
        let r = e.node.clone().unwrap_or_default();
        let r = r.strip_prefix("node:").unwrap_or(&r).to_string();
        r == my_name || r == my_key
    })
}

/// Keys of all valid relays and controllers: acceptable when dialing an
/// address whose owner isn't known in advance.
fn infra_keys(n: &Node) -> Vec<Bytes32> {
    let s = n.store.read();
    s.view()
        .nodes
        .values()
        .filter(|x| x.valid && (x.relay || x.control))
        .map(|x| x.key)
        .collect()
}

/// Bootstrap addresses (§10.7.1): seeds from the tree, then from
/// enrollment, then the ticket's controllers.
async fn seed_addrs(n: &Node) -> Vec<(SocketAddr, Transport, Vec<Bytes32>)> {
    let mut out = Vec::new();
    let mut hints: Vec<SeedHint> = Vec::new();
    {
        let s = n.store.read();
        if let Some(seeds) = &s.view().seeds {
            for e in seeds.entries.clone().unwrap_or_default() {
                for a in e.addrs.clone().unwrap_or_default() {
                    hints.push(seed_hint(&a, e.node.clone()));
                }
            }
        }
    }
    {
        let nf = n.node_file.lock();
        hints.extend(nf.enroll_seeds.iter().cloned());
        hints.extend(nf.enroll_controllers.iter().cloned());
    }
    let all: Vec<Bytes32> = infra_keys(n)
        .into_iter()
        .filter(|k| *k != n.kp.public())
        .collect();
    let mine: Vec<SocketAddr> = [n.cfg.listen.tls, n.cfg.listen.kcp, n.cfg.listen.anytls]
        .into_iter()
        .flatten()
        .collect();
    for h in hints {
        let Some(t) = Transport::parse(&h.transport) else {
            continue;
        };
        let keys = match &h.node {
            Some(r) => {
                let s = n.store.read();
                let v = s.view();
                let r = r.strip_prefix("node:").unwrap_or(r);
                let id = crypto::parse_key_b64(r)
                    .and_then(|k| v.by_key.get(&k).copied())
                    .or_else(|| v.by_name.get(r).copied());
                match id.and_then(|id| v.nodes.get(&id)) {
                    Some(x) if x.id == n.me => continue,
                    Some(x) => vec![x.key],
                    None => all.clone(),
                }
            }
            None => all.clone(),
        };
        for a in resolve(&h.host, h.port).await {
            if mine.contains(&a) {
                continue;
            }
            out.push((a, t, keys.clone()));
        }
    }
    out
}

/// Keep the hops this node needs (§10.6): edge nodes 2–3 home relays;
/// relays the other relays and controllers; controllers each other.
async fn connections(n: Arc<Node>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    let mut backoff: std::collections::HashMap<Bytes32, (Instant, Duration)> =
        std::collections::HashMap::new();
    let mut seed_backoff = Duration::from_secs(1);
    let mut next_seed = Instant::now();
    let mut ev = n.events.subscribe();
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            e = ev.recv() => {
                match e {
                    Ok(Event::HeadChanged) => n.enforce_revocations(),
                    Ok(Event::HopDown(_)) => {}
                    _ => continue,
                }
            }
        }
        let (me_relay, me_ctl, relays, controllers) = {
            let s = n.store.read();
            let v = s.view();
            let relays: Vec<Bytes32> = v
                .nodes
                .values()
                .filter(|x| x.valid && x.relay && x.id != n.me)
                .map(|x| x.id)
                .collect();
            let ctl: Vec<Bytes32> = v
                .controllers
                .keys()
                .copied()
                .filter(|c| *c != n.me)
                .collect();
            (
                v.nodes.get(&n.me).map(|x| x.relay).unwrap_or(false),
                n.is_controller(),
                relays,
                ctl,
            )
        };
        let mut want: Vec<Bytes32> = Vec::new();
        if me_relay || me_ctl {
            want.extend(relays.iter().copied());
            want.extend(controllers.iter().copied());
        } else {
            // Edge: the closest relays; fall back to controllers when there are none.
            let mut cands: Vec<Bytes32> = if relays.is_empty() {
                controllers.clone()
            } else {
                relays.clone()
            };
            let have: HashSet<Bytes32> = n.peers().into_iter().collect();
            cands.sort_by_key(|r| !have.contains(r));
            want.extend(cands.into_iter().take(3));
        }
        want.sort();
        want.dedup();
        let have: HashSet<Bytes32> = n.peers().into_iter().collect();
        let target = if me_relay || me_ctl {
            want.len()
        } else {
            2.min(want.len())
        };
        let connected = want.iter().filter(|w| have.contains(*w)).count();
        for peer in want.iter().filter(|w| !have.contains(*w)) {
            if !(me_relay || me_ctl) && connected >= target {
                break;
            }
            if n.endpoint_addrs(peer).is_empty() {
                continue;
            }
            if let Some((at, _)) = backoff.get(peer) {
                if Instant::now() < *at {
                    continue;
                }
            }
            let n2 = n.clone();
            let p = *peer;
            let r = tokio::time::timeout(Duration::from_secs(12), n2.dial_node(p)).await;
            match r {
                Ok(Ok(_)) => {
                    backoff.remove(peer);
                }
                _ => {
                    let e = backoff
                        .entry(*peer)
                        .or_insert((Instant::now(), Duration::from_secs(2)));
                    e.1 = (e.1 * 2).min(Duration::from_secs(300));
                    e.0 = Instant::now() + e.1;
                }
            }
        }
        // Not enough hops: use the seeds (§10.7.1).
        let connected = n.peers().iter().filter(|p| want.contains(p)).count();
        if (connected == 0 || n.peers().is_empty()) && Instant::now() >= next_seed {
            let mut ok = false;
            for (addr, t, keys) in seed_addrs(&n).await {
                if keys.is_empty() {
                    continue;
                }
                match tokio::time::timeout(Duration::from_secs(12), n.dial(addr, t, keys)).await {
                    Ok(Ok(h)) => {
                        tracing::info!(peer = %n.name_of(&h.peer), %addr, "connected to seed");
                        ok = true;
                        break;
                    }
                    Ok(Err(e)) => tracing::debug!("seed {addr} ({}): {e}", t.name()),
                    Err(_) => tracing::debug!("seed {addr}: timeout"),
                }
            }
            seed_backoff = if ok {
                Duration::from_secs(1)
            } else {
                (seed_backoff * 2).min(Duration::from_secs(120))
            };
            next_seed = Instant::now() + seed_backoff;
        }
        // Cache relay endpoints for the next start.
        let cache = {
            let s = n.store.read();
            let v = s.view();
            let recs = n.records.lock();
            state::RelayCache {
                endpoints: recs
                    .endpoints
                    .iter()
                    .filter(|(id, _)| {
                        v.nodes
                            .get(*id)
                            .map(|x| x.relay || x.control)
                            .unwrap_or(false)
                    })
                    .map(|(_, (_, raw))| raw.clone())
                    .collect(),
            }
        };
        let _ = state::save_json(&n.paths.relays(), &cache);
    }
}

/// Fetch PSK epochs (and, on relays, the camouflage secret) from a
/// controller (§7.6, §9.7.2).
async fn secrets(n: Arc<Node>) {
    let mut fails = 0u32;
    loop {
        let wait = if n.epochs.read().keys.is_empty() || fails > 0 {
            Duration::from_secs(5)
        } else {
            Duration::from_secs(600)
        };
        let mut ev = n.events.subscribe();
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            e = ev.recv() => { if !matches!(e, Ok(Event::HeadChanged)) { continue; } }
        }
        if n.is_controller() || n.peers().is_empty() {
            continue;
        }
        let relay = n.is_relay();
        match crate::rpc::call_any(
            &n,
            RpcBody::GetPsk(Box::new(wp::GetPsk { all: relay })),
            Duration::from_secs(15),
        )
        .await
        {
            Ok((_, RpcBody::PskInfo(p))) => {
                fails = 0;
                let epochs = p
                    .epochs
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .map(|e| (e.epoch_id, opt_k32(&e.psk)))
                    .collect();
                if is_seed(&n) || relay {
                    n.epochs.write().accept_all = is_seed(&n);
                }
                n.set_psk(p.current, epochs);
            }
            Ok(_) => fails += 1,
            Err(e) => {
                fails += 1;
                tracing::debug!("PSK fetch: {e}");
            }
        }
        if relay && n.cfg.listen.anytls.is_some() {
            if let Ok((_, RpcBody::CamouflageSecret(c))) = crate::rpc::call_any(
                &n,
                RpcBody::GetCamouflage(Box::new(wp::GetCamouflage {})),
                Duration::from_secs(15),
            )
            .await
            {
                let f = state::CamouflageFile {
                    key_pem: c.private_key.unwrap_or_default(),
                    site: c.site.unwrap_or_default(),
                };
                let _ = state::save_json(&n.paths.camouflage(), &f);
                crate::transport::refresh_anytls(&n);
            }
        }
    }
}
