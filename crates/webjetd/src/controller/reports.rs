//! Nodes' metric reports (§18.6), kept by every controller, and the
//! OpenMetrics text built from them.

use super::*;

/// The latest verified metric report of a node.
pub struct StoredReport {
    pub received: u64,
    pub report: wp::MetricReport,
}

impl Controller {
    /// Verify and keep a node's metric report (§12.5). Reports that come
    /// straight from their node are passed on to the other controllers, so
    /// every controller can serve the whole network to Prometheus.
    pub fn ingest_metrics(&self, from: Bytes32, raw: &[u8]) {
        let Some(n) = self.node() else { return };
        let Ok(v) = crypto::open_envelope(raw) else {
            return;
        };
        if v.ty != mt::METRIC_REPORT {
            return;
        }
        let Ok(rep) = v.decode::<wp::MetricReport>() else {
            return;
        };
        let origin = opt_k32(&rep.node_id);
        if n.store.read().view().nodes.get(&origin).map(|x| x.key) != Some(v.signer) {
            return;
        }
        let from_controller = from != origin;
        if from_controller
            && !self.raft.lock().voters().contains(&from)
            && !self.raft.lock().learners().contains(&from)
        {
            return;
        }
        {
            let mut r = self.reports.lock();
            if let Some(old) = r.get(&origin) {
                // Keep the newest; a restarted node's seq starts over, so compare time first.
                if (old.report.taken_at, old.report.report_seq) >= (rep.taken_at, rep.report_seq) {
                    return;
                }
            }
            r.insert(
                origin,
                StoredReport {
                    received: now_ms(),
                    report: rep,
                },
            );
        }
        if !from_controller {
            let peers: Vec<Bytes32> = {
                let r = self.raft.lock();
                r.voters()
                    .iter()
                    .chain(r.learners().iter())
                    .copied()
                    .filter(|p| *p != n.me)
                    .collect()
            };
            for p in peers {
                rpc::send_oneway(
                    &n,
                    &p,
                    RpcBody::MetricUpload(Box::new(wp::MetricUpload {
                        report: Some(raw.to_vec()),
                    })),
                );
            }
        }
    }

    /// Every node's latest report as OpenMetrics text (the scrape target).
    /// Reports older than 15 minutes are left out (§12.5: one per minute).
    pub fn openmetrics(&self) -> String {
        let Some(n) = self.node() else {
            return "# EOF\n".into();
        };
        let now = now_ms();
        // Copy the recent reports out first so the reports lock isn't nested
        // inside the store lock.
        let recent: Vec<_> = {
            let r = self.reports.lock();
            let mut v: Vec<_> = r
                .iter()
                .filter(|(_, sr)| now.saturating_sub(sr.received) < 15 * 60_000)
                .map(|(id, sr)| (*id, sr.report.clone()))
                .collect();
            v.sort_by_key(|a| a.0);
            v
        };
        let s = n.store.read();
        let names = crate::exposition::ViewNames(s.view());
        let mut e = crate::exposition::Exposition::default();
        for (_, report) in &recent {
            e.report(report, &names, true);
        }
        e.render()
    }
}
