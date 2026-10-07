//! What the leader does besides Raft: renewing heads, and changing the
//! controller membership on its own (§7.5).

use super::*;

impl Controller {
    pub(super) async fn leader_duties(self: Arc<Self>) {
        let Ok(_g) = self.propose_lock.try_lock() else {
            return;
        };
        let (genesis_needed, due_validity, due_expiry) = {
            let m = self.machine.lock();
            let now = now_ms();
            (
                m.genesis.is_none(),
                m.genesis.is_some() && m.validity_due(now),
                m.expiry_due(now),
            )
        };
        drop(_g);
        if genesis_needed {
            if !self.bootstrap {
                return;
            }
            let Some(n) = self.node() else { return };
            let g = n.store.read().genesis_raw.clone();
            match self
                .propose(EntryPayload::GenesisEntry(Box::new(wp::GenesisEntry {
                    genesis: Some(g),
                })))
                .await
            {
                Ok(_) => tracing::info!("network genesis committed"),
                Err(e) => tracing::warn!("genesis: {e}"),
            }
            return;
        }
        if due_validity {
            let now = now_ms();
            if let Err(e) = self
                .propose(EntryPayload::ExtendValidityEntry(Box::new(
                    wp::ExtendValidityEntry {
                        valid_until: now + VALIDITY_PERIOD,
                    },
                )))
                .await
            {
                tracing::debug!("validity extension: {e}");
            }
        }
        if due_expiry {
            let _ = self
                .propose(EntryPayload::ExpireEnrollmentsEntry(Box::new(
                    wp::ExpireEnrollmentsEntry { now: now_ms() },
                )))
                .await;
        }
        self.auto_membership().await;
    }

    /// Automatic membership (§7.5): propose the next change, if any. One at a
    /// time; the next round (a second later) proposes the following one.
    pub(super) async fn auto_membership(&self) {
        if self.membership_busy.swap(true, Ordering::SeqCst) {
            return;
        }
        self.auto_membership_once().await;
        self.membership_busy.store(false, Ordering::SeqCst);
    }

    pub(super) async fn auto_membership_once(&self) {
        let Some(n) = self.node() else { return };
        let Some((change, id)) = self.membership_plan(&n) else {
            return;
        };
        let name = n
            .store
            .read()
            .view()
            .node(&id)
            .map_or_else(|| crypto::short(&id), |x| x.name.clone());
        match self
            .propose(EntryPayload::AutoMembershipEntry(Box::new(
                wp::AutoMembershipEntry {
                    change,
                    node_id: Some(crypto::k32(&id)),
                },
            )))
            .await
        {
            Ok(_) => tracing::info!("automatic membership: {change:?} {name}"),
            Err(e) => tracing::warn!("automatic membership {change:?} {name}: {e}"),
        }
    }

    /// The next automatic membership change, when this controller is the
    /// leader, no change is pending and every controller involved runs
    /// software that applies it.
    pub(super) fn membership_plan(&self, n: &Node) -> Option<membership::Change> {
        use webjet_core::membership::{self as mb, Input, Peer};
        let (members, member_since, settings, eligible, joinable) = {
            let m = self.machine.lock();
            let v = m.view();
            let settings = mb::Settings::of(v.controller_settings.as_ref());
            if !settings.auto_membership || m.genesis.is_none() {
                return None;
            }
            let valid = || v.nodes.values().filter(|x| x.valid);
            let eligible: BTreeSet<Bytes32> = valid()
                .filter(|x| x.rec.control != Some(false))
                .map(|x| x.id)
                .collect();
            let joinable: BTreeSet<Bytes32> = valid()
                .filter(|x| x.rec.control == Some(true) && !m.removed_by_admin.contains(&x.id))
                .map(|x| x.id)
                .collect();
            (
                m.members.clone(),
                m.member_since.clone(),
                settings,
                eligible,
                joinable,
            )
        };
        // Certificates aren't replicated state: the leader's own view
        // decides who is a valid controller.
        let controllers: BTreeSet<Bytes32> =
            n.store.read().view().controllers.keys().copied().collect();
        let peers: BTreeMap<Bytes32, Peer> = {
            let r = self.raft.lock();
            if r.role != Role::Leader || r.conf_change_pending() {
                return None;
            }
            // The log's configuration is the applied one (nothing pending).
            if r.config() != &members {
                return None;
            }
            // Give a new leader time to hear from everyone first.
            if r.leader_for()? < mb::HEALTHY_WITHIN {
                return None;
            }
            let last = r.last_index();
            members
                .all()
                .into_iter()
                // A peer that never answered this leader has been silent
                // for as long as it has been leader.
                .filter_map(|p| {
                    Some((
                        p,
                        Peer {
                            silent: r.silent_for(&p)?,
                            lag: last.saturating_sub(r.match_of(&p)),
                        },
                    ))
                })
                .collect()
        };
        let plan = mb::plan(&Input {
            settings,
            leader: n.me,
            members: &members,
            controllers: &controllers,
            eligible: &eligible,
            joinable: &joinable,
            member_since: &member_since,
            peers: &peers,
        })?;
        // Rolling upgrades: controllers from before 0.7.0 can't apply the
        // entry and would halt. Every reachable member and the node joining
        // must advertise support; unreachable members are being replaced
        // or removed, and an old one coming back is upgraded by the admin.
        let recs = n.records.lock();
        let supports = |id: &Bytes32| {
            *id == n.me
                || recs.endpoints.get(id).is_some_and(|(r, _)| {
                    r.features
                        .as_ref()
                        .is_some_and(|f| f.iter().any(|x| x == mb::FEATURE))
                })
        };
        let reachable = |id: &Bytes32| peers.get(id).is_some_and(|p| p.silent < mb::HEALTHY_WITHIN);
        let joining = plan.0 == wp::MembershipChange::AddLearner;
        let ok = members
            .all()
            .iter()
            .filter(|id| reachable(id))
            .all(supports)
            && (!joining || supports(&plan.1));
        if !ok {
            tracing::debug!(
                "automatic membership: waiting for every controller to run 0.7.0 or later"
            );
            return None;
        }
        Some(plan)
    }
}

pub(super) fn membership_settings_json(s: &membership::Settings) -> serde_json::Value {
    serde_json::json!({
        "auto_membership": s.auto_membership,
        "voters": s.voters,
        "dead_voter_after_s": s.dead_voter_after_s,
    })
}
