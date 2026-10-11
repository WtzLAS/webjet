//! Requests other nodes send a controller over the overlay (`handle_rpc`),
//! Raft messages among controllers, and the admin-signed operation log and
//! state export.

use super::*;

impl Controller {
    /// The audit trail for an admin's signed `LogRequest`.
    pub fn log(&self, raw: &[u8]) -> wp::LogReply {
        let checked = {
            let m = self.machine.lock();
            audit::check_request(m.view(), raw, now_ms())
        };
        let req = match checked {
            Ok(r) => r,
            Err(e) => {
                return wp::LogReply {
                    error: Some(format!("{e:#}")),
                    ..Default::default()
                };
            }
        };
        let (first, commit, entries) = {
            let r = self.raft.lock();
            let first = r.snap_index + 1;
            let entries: Vec<(u64, Vec<u8>)> = audit::window(&req, first, r.commit)
                .filter_map(|i| r.entry(i).map(|e| (i, e.bytes.clone())))
                .collect();
            (first, r.commit, entries)
        };
        let records = {
            let d = self.descriptions.lock();
            entries
                .iter()
                .filter_map(|(i, b)| audit::summarize(b, d.get(i).cloned()))
                .collect()
        };
        wp::LogReply {
            error: None,
            first_index: first,
            commit_index: commit,
            records: Some(records),
        }
    }

    /// This controller's applied state for an admin's signed
    /// `SnapshotRequest` (ops guide 3.8): what `webjetctl local controller
    /// restore` installs when no controller survives.
    pub fn export_snapshot(&self, raw: &[u8]) -> wp::SnapshotReply {
        let m = self.machine.lock();
        match audit::check_snapshot_request(m.view(), raw, now_ms()) {
            Ok(()) if m.genesis.is_some() => wp::SnapshotReply {
                error: None,
                snapshot: Some(m.snapshot_bytes()),
            },
            Ok(()) => wp::SnapshotReply {
                error: Some("this controller holds no network yet".into()),
                snapshot: None,
            },
            Err(e) => wp::SnapshotReply {
                error: Some(format!("{e:#}")),
                snapshot: None,
            },
        }
    }

    pub async fn handle_rpc(self: Arc<Self>, from: Bytes32, body: RpcBody) -> Option<RpcBody> {
        let n = self.node()?;
        let ack = |ok: bool, e: Option<String>| {
            Some(RpcBody::RpcAck(Box::new(wp::RpcAck { ok, error: e })))
        };
        let member = {
            let r = self.raft.lock();
            r.voters().contains(&from) || r.learners().contains(&from)
        };
        let trusted = member || n.store.snapshot().node_trusted(&from);
        if !trusted {
            return ack(false, Some("untrusted caller".into()));
        }
        match body {
            RpcBody::RaftRpc(r) => {
                let (src, to, rb) = raft::unwrap(&r.message.unwrap_or_default())?;
                if src != from || to != n.me {
                    return None;
                }
                let is_ctl = member || n.store.snapshot().view().is_controller(&from);
                if !is_ctl {
                    return None;
                }
                blocking(|| self.on_raft(&n, from, rb));
                None
            }
            RpcBody::GetCertRequest(_) => Some(RpcBody::CertRequestReply(Box::new(
                match self.cert_request() {
                    Ok(r) => wp::CertRequestReply {
                        request: Some(r),
                        error: None,
                    },
                    Err(e) => wp::CertRequestReply {
                        request: None,
                        error: Some(e.to_string()),
                    },
                },
            ))),
            RpcBody::SubmitOp(s) => {
                let raw = s.signed.clone().unwrap_or_default();
                let payload = webjet_core::statemachine::ops::op_entry(raw.clone());
                let res = self.submit(payload, Some(RpcBody::SubmitOp(s))).await;
                Some(submit_result(res))
            }
            RpcBody::RedeemRequest(r) => {
                let req = wp::EnrollRequest::decode_bytes(r.request.as_deref().unwrap_or_default())
                    .ok()?;
                let res = self
                    .redeem(&req, Some(RpcBody::RedeemRequest(r)))
                    .await
                    .map(|(i, o, _)| (i, o));
                Some(submit_result(res))
            }
            RpcBody::GetPsk(g) => {
                let m = self.machine.lock();
                let cur = m.psk_current;
                let all = g.all
                    && n.store
                        .read()
                        .view()
                        .nodes
                        .get(&from)
                        .is_some_and(|x| x.relay || x.control);
                let epochs = m
                    .psk_epochs
                    .iter()
                    .filter(|(k, _)| all || **k == cur || **k == cur.wrapping_sub(1))
                    .map(|(k, v)| wp::PskEpoch {
                        epoch_id: *k,
                        psk: Some(crypto::k32(v)),
                    })
                    .collect();
                Some(RpcBody::PskInfo(Box::new(wp::PskInfo {
                    current: cur,
                    epochs: Some(epochs),
                })))
            }
            RpcBody::GetCamouflage(_) => {
                let allowed = n
                    .store
                    .read()
                    .view()
                    .nodes
                    .get(&from)
                    .is_some_and(|x| x.relay || x.control);
                if !allowed {
                    return ack(
                        false,
                        Some("only relays and controllers get the camouflage key".into()),
                    );
                }
                let c = self.machine.lock().camouflage.clone();
                match c {
                    Some((k, site)) => {
                        Some(RpcBody::CamouflageSecret(Box::new(wp::CamouflageSecret {
                            private_key: Some(k),
                            site: Some(site),
                        })))
                    }
                    None => ack(false, Some("no camouflage secret set".into())),
                }
            }
            RpcBody::MetricUpload(m) => {
                self.ingest_metrics(from, &m.report.unwrap_or_default());
                ack(true, None)
            }
            RpcBody::OfflineSubmit(o) => {
                let raws: Vec<Vec<u8>> = o
                    .items
                    .unwrap_or_default()
                    .into_iter()
                    .map(|b| b.data.unwrap_or_default())
                    .collect();
                // One write lock and one view rebuild for the whole batch.
                let results = n.store.write().add_offline_items(&raws);
                let errs: Vec<String> = results
                    .into_iter()
                    .filter_map(|r| r.err().map(|e| e.to_string()))
                    .collect();
                n.persist_store();
                crate::gossip::push_head(&n);
                ack(errs.is_empty(), (!errs.is_empty()).then(|| errs.join("; ")))
            }
            RpcBody::SubmitRoot(r) => {
                let raw = r.signed.as_deref().unwrap_or_default();
                let res = match root_payload(raw) {
                    Ok(p) => self.submit(p, Some(RpcBody::SubmitRoot(r))).await,
                    Err(e) => Err(e),
                };
                Some(submit_result(res))
            }
            RpcBody::GetControllerStatus(_) => {
                Some(RpcBody::ControllerStatus(Box::new(self.status_wire(&n))))
            }
            RpcBody::GetLog(g) => Some(RpcBody::LogReply(Box::new(
                self.log(&g.request.unwrap_or_default()),
            ))),
            RpcBody::GetSnapshot(g) => Some(RpcBody::SnapshotReply(Box::new(
                self.export_snapshot(&g.request.unwrap_or_default()),
            ))),
            _ => None,
        }
    }

    pub(super) fn on_raft(&self, n: &Arc<Node>, from: Bytes32, rb: RaftBody) {
        match rb {
            RaftBody::RaftSnapshot(s) => {
                let _g = self.apply_lock.lock();
                let offer =
                    self.raft
                        .lock()
                        .offer_snapshot(Instant::now(), from, s.term, s.last_index);
                let out = match offer {
                    raft::SnapshotOffer::Reply(out) => out,
                    raft::SnapshotOffer::Install => {
                        let data = s.data.as_deref().unwrap_or_default();
                        match Machine::restore_bytes(data) {
                            Ok(m) if m.last_index == s.last_index && m.last_term == s.last_term => {
                                let members = m.members.clone();
                                let mut r = self.raft.lock();
                                if let Err(e) = r.storage().save_snapshot(data) {
                                    tracing::error!("saving Raft snapshot: {e}");
                                    return;
                                }
                                *self.machine.lock() = m;
                                self.applied.store(s.last_index, Ordering::SeqCst);
                                let out = r.install_snapshot(s.last_index, s.last_term, members);
                                drop(r);
                                tracing::info!(index = s.last_index, "installed Raft snapshot");
                                self.sync_psk(n);
                                out
                            }
                            _ => {
                                tracing::warn!("bad Raft snapshot from {}", n.name_of(&from));
                                Vec::new()
                            }
                        }
                    }
                };
                drop(_g);
                Self::send_raft(n, out);
                self.apply_committed(n);
                self.maybe_sign_head(n);
            }
            other => {
                let out = self.raft.lock().handle(Instant::now(), from, other);
                Self::send_raft(n, out);
                self.apply_committed(n);
            }
        }
    }
}

pub(super) fn submit_result(res: Result<(u64, Outcome)>) -> RpcBody {
    match res {
        Ok((i, _)) => RpcBody::SubmitResult(Box::new(wp::SubmitResult {
            ok: true,
            index: i,
            error: None,
        })),
        Err(e) => RpcBody::SubmitResult(Box::new(wp::SubmitResult {
            ok: false,
            index: 0,
            error: Some(e.to_string()),
        })),
    }
}
