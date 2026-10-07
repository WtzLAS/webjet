//! Enrollment (§8): redeeming tokens over the overlay, from the local
//! agent and on the enrollment endpoint, and the controller's own
//! certificate request.

use super::*;

impl Controller {
    pub fn pending_token_hashes(&self) -> Vec<Bytes32> {
        let now = now_ms();
        self.machine
            .lock()
            .pending
            .values()
            .filter(|p| p.expires_at > now)
            .map(|p| p.token_hash)
            .collect()
    }

    /// Redeem an enrollment request. Returns the log index, outcome and node id.
    pub async fn redeem(
        self: &Arc<Self>,
        req: &wp::EnrollRequest,
        fwd: Option<RpcBody>,
    ) -> Result<(u64, Outcome, Bytes32)> {
        let lookup = opt_k32(&req.lookup_id);
        let key = opt_k32(&req.identity_key);
        let nonce = opt_k32(&req.nonce);
        let (th, node_id) = {
            let m = self.machine.lock();
            let p = m
                .pending_by_lookup(&lookup)
                .ok_or_else(|| anyhow!("unknown or expired enrollment"))?;
            (p.token_hash, p.node_id)
        };
        if !crypto::ct_eq(
            &crypto::enroll_proof(&th, &key, &nonce),
            &opt_k32(&req.proof),
        ) {
            bail!("bad enrollment proof");
        }
        let payload = EntryPayload::RedeemEnrollmentEntry(Box::new(wp::RedeemEnrollmentEntry {
            token_hash: Some(crypto::k32(&th)),
            identity_key: Some(crypto::k32(&key)),
            node_id: Some(crypto::k32(&node_id)),
        }));
        let fwd = fwd.or_else(|| {
            Some(RpcBody::RedeemRequest(Box::new(wp::RedeemRequest {
                request: Some(req.encode_bytes()),
            })))
        });
        let (i, o) = self.submit(payload, fwd).await?;
        Ok((i, o, node_id))
    }

    /// Redeem for this controller itself (bootstrap, ops guide 2.1 step 5).
    pub async fn redeem_self(self: &Arc<Self>, token: &[u8]) -> Result<Bytes32> {
        let n = self.node().ok_or_else(|| anyhow!("shutting down"))?;
        let th = crypto::token_hash(token);
        let key = n.kp.public();
        let payload = EntryPayload::RedeemEnrollmentEntry(Box::new(wp::RedeemEnrollmentEntry {
            token_hash: Some(crypto::k32(&th)),
            identity_key: Some(crypto::k32(&key)),
            node_id: Some(crypto::k32(&n.me)),
        }));
        self.submit(payload, None).await?;
        Ok(n.me)
    }

    /// Serve one enrollment connection (§8 steps 3–5).
    pub async fn serve_enrollment(self: Arc<Self>, mut io: BoxIo, remote: SocketAddr) {
        let r = async {
            let (ty, body) =
                tokio::time::timeout(Duration::from_secs(10), hop::read_record(&mut io)).await??;
            if ty != rec::CONTROL {
                bail!("unexpected record");
            }
            let req = wp::EnrollRequest::decode_bytes(&body)?;
            let resp = match self.redeem(&req, None).await {
                Ok((idx, _, node_id)) => self.enroll_response(idx, node_id).await,
                Err(e) => wp::EnrollResponse {
                    ok: false,
                    error: Some(e.to_string()),
                    ..Default::default()
                },
            };
            hop::write_record(&mut io, rec::CONTROL, &resp.encode_bytes()).await?;
            use tokio::io::AsyncWriteExt;
            io.flush().await?;
            let _ = io.shutdown().await;
            Ok::<_, anyhow::Error>(resp.ok)
        }
        .await;
        match r {
            Ok(true) => tracing::info!(%remote, "node enrolled"),
            Ok(false) => tracing::info!(%remote, "enrollment refused"),
            Err(e) => tracing::debug!(%remote, "enrollment connection: {e}"),
        }
    }

    pub(super) async fn enroll_response(&self, idx: u64, node_id: Bytes32) -> wp::EnrollResponse {
        let Some(n) = self.node() else {
            return wp::EnrollResponse::default();
        };
        // Wait until our signed head covers the new record.
        let start = Instant::now();
        loop {
            self.maybe_sign_head(&n);
            let v = n.store.read().head().map_or(0, |h| h.head.version);
            if v >= idx || start.elapsed() > PROPOSE_TIMEOUT {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let s = n.store.read();
        let Some(head) = s.head() else {
            return wp::EnrollResponse {
                ok: false,
                error: Some("controller has no signed tree head yet".into()),
                ..Default::default()
            };
        };
        let leaf = s
            .tree()
            .get(webjet_core::merkle::kind::NODE, &node_id)
            .map(|e| e.bytes.clone())
            .unwrap_or_default();
        let m = self.machine.lock();
        let cur = m.psk_current;
        wp::EnrollResponse {
            ok: true,
            error: None,
            node_id: Some(crypto::k32(&node_id)),
            record: Some(leaf),
            proof: Some(Box::new(
                s.prove(webjet_core::merkle::kind::NODE, &node_id).to_wire(),
            )),
            genesis: Some(s.genesis_raw.clone()),
            certs: Some(
                s.certs()
                    .map(|c| wp::Blob {
                        data: Some(c.raw.clone()),
                    })
                    .collect(),
            ),
            key_tombstones: Some(
                s.key_tombstones()
                    .map(|c| wp::Blob {
                        data: Some(c.raw.clone()),
                    })
                    .collect(),
            ),
            head: Some(head.raw.clone()),
            leaves: Some(
                s.all_leaves()
                    .into_iter()
                    .map(|(k, key, b)| wp::LeafData {
                        kind: k,
                        key: Some(crypto::k32(&key)),
                        bytes: Some(b),
                    })
                    .collect(),
            ),
            offline: Some(
                s.offline_items()
                    .into_iter()
                    .map(|b| wp::Blob { data: Some(b) })
                    .collect(),
            ),
            psk_current: cur,
            psk_epochs: Some(
                m.psk_epochs
                    .iter()
                    .filter(|(k, _)| **k == cur || **k == cur.wrapping_sub(1))
                    .map(|(k, v)| wp::PskEpoch {
                        epoch_id: *k,
                        psk: Some(crypto::k32(v)),
                    })
                    .collect(),
            ),
        }
    }

    /// A certificate request for this controller's signing key (ops guide 2.1
    /// step 6): a SigningKeyCert body signed by the signing key itself.
    pub fn cert_request(&self) -> Result<Vec<u8>> {
        let n = self.node().ok_or_else(|| anyhow!("shutting down"))?;
        let pk = self.signer.public()?;
        let body = wp::SigningKeyCert {
            signing_key_id: Some(crypto::k32(&self.signing_key_id)),
            signing_key: Some(crypto::k32(&pk)),
            controller: Some(crypto::k32(&n.me)),
            cert_serial: now_ms(),
            issuer: None,
        };
        self.signer.sign(mt::CERT_REQUEST, body.encode_bytes())
    }
}
