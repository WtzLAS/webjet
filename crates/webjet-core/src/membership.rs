//! Automatic controller membership (§7.5).
//!
//! The Raft leader keeps the cluster's membership in shape by itself:
//! - every valid controller (`control` role, valid SigningKeyCert) becomes a
//!   learner;
//! - a member that is no longer a valid controller is removed: its node was
//!   revoked or lost the `control` role, or its certificate is gone (its
//!   signing key was retired) while the leader's own is valid;
//! - the earliest-joined healthy controllers are voters, an odd number of
//!   them and at most the configured target (5 by default); the rest stay
//!   learners;
//! - a voter the leader hasn't heard from for `dead_voter_after_s` is demoted
//!   when a healthy learner can take its place.
//!
//! [`plan`] is a pure function of the state and the leader's view of its
//! peers. It returns at most one change, since Raft applies membership
//! changes one at a time; the leader calls it again once that change has
//! committed. Every replica applies the entry it proposes
//! (`AutoMembershipEntry`) with the same checks as a manual change, plus
//! [`check`]; the leader's reasons (who is healthy, whose certificate is
//! valid) aren't replicated and aren't rechecked.

use crate::crypto::Bytes32;
use crate::statemachine::Membership;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use webjet_proto as wp;

pub const DEFAULT_VOTERS: u8 = 5;
pub const MAX_VOTERS: usize = 7;
pub const DEFAULT_DEAD_AFTER_S: u32 = 3600;
/// The shortest `dead_voter_after_s` (other than 0 = never): far above any
/// election timeout, so a slow link or a restart never costs a voter seat.
pub const MIN_DEAD_AFTER_S: u32 = 60;
/// A learner heard from within this long is healthy enough to promote.
pub const HEALTHY_WITHIN: Duration = Duration::from_secs(30);
/// A learner at most this many entries behind the leader is caught up.
pub const CAUGHT_UP_LAG: u64 = 64;
/// Feature in the EndpointRecord of a controller that can apply
/// `AutoMembershipEntry` and the ControllerSettings leaf (0.7.0). The
/// leader changes nothing by itself until every member and candidate
/// advertises it, so older controllers in a rolling upgrade never see an
/// entry they can't apply.
pub const FEATURE: &str = "auto-membership";

/// `[controllers]` with the built-in values filled in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub auto_membership: bool,
    pub voters: u8,
    pub dead_voter_after_s: u32,
}

impl Settings {
    pub fn of(c: Option<&wp::ControllerSettings>) -> Settings {
        Settings {
            auto_membership: c.and_then(|c| c.auto_membership).unwrap_or(true),
            voters: c.and_then(|c| c.voters).unwrap_or(DEFAULT_VOTERS),
            dead_voter_after_s: c
                .and_then(|c| c.dead_voter_after_s)
                .unwrap_or(DEFAULT_DEAD_AFTER_S),
        }
    }

    fn dead_after(&self) -> Option<Duration> {
        (self.dead_voter_after_s != 0).then(|| Duration::from_secs(self.dead_voter_after_s as u64))
    }
}

/// What the leader knows about one member or candidate.
#[derive(Clone, Copy, Debug, Default)]
pub struct Peer {
    /// Time since the leader last heard from it (zero for the leader).
    pub silent: Duration,
    /// Entries it is behind the leader's log.
    pub lag: u64,
}

impl Peer {
    fn healthy(&self) -> bool {
        self.silent < HEALTHY_WITHIN && self.lag <= CAUGHT_UP_LAG
    }
}

/// Everything [`plan`] decides from.
pub struct Input<'a> {
    pub settings: Settings,
    pub leader: Bytes32,
    pub members: &'a Membership,
    /// Valid controllers in the leader's view: valid nodes with the
    /// `control` role and a valid SigningKeyCert (`View::is_controller`).
    pub controllers: &'a BTreeSet<Bytes32>,
    /// Nodes that may stay members by replicated state: valid, and the
    /// `control` role not taken away (a record from before the role counts).
    pub eligible: &'a BTreeSet<Bytes32>,
    /// Nodes that may join by replicated state: valid, with the `control`
    /// role (what `add learner` requires), and not removed by an admin.
    pub joinable: &'a BTreeSet<Bytes32>,
    /// The log index at which each member joined; members without one
    /// (joined before 0.7.0) count as the earliest, in node id order.
    pub member_since: &'a BTreeMap<Bytes32, u64>,
    /// The leader's view of each member (a member missing here counts as
    /// unhealthy and not dead).
    pub peers: &'a BTreeMap<Bytes32, Peer>,
}

pub type Change = (wp::MembershipChange, Bytes32);

/// The next membership change, if any.
pub fn plan(i: &Input) -> Option<Change> {
    use wp::MembershipChange as C;
    if !i.settings.auto_membership {
        return None;
    }
    let m = i.members;
    let joined = |id: &Bytes32| (i.member_since.get(id).copied().unwrap_or(0), *id);
    let peer = |id: &Bytes32| i.peers.get(id).copied();
    let healthy = |id: &Bytes32| *id == i.leader || peer(id).is_some_and(|p| p.healthy());
    let dead = |id: &Bytes32| {
        *id != i.leader
            && i.settings.dead_after().is_some_and(|d| match peer(id) {
                Some(p) => p.silent >= d,
                None => false,
            })
    };

    // 1. Members that are no longer valid controllers leave (never the
    //    leader itself, never the last voter). Learners first: removing
    //    them never touches the quorum. A missing certificate counts only
    //    while the leader's own is valid: when it isn't either, the leader's
    //    certificates are what's wrong (for example an admin who certified
    //    them all was revoked), and emptying the cluster wouldn't help.
    let certs_ok = i.controllers.contains(&i.leader);
    let stale = |id: &&Bytes32| {
        **id != i.leader
            && (!i.eligible.contains(*id) || (certs_ok && !i.controllers.contains(*id)))
    };
    if let Some(id) = m.learners.iter().find(stale) {
        return Some((C::Remove, *id));
    }
    if m.voters.len() > 1
        && let Some(id) = m.voters.iter().find(stale)
    {
        return Some((C::Remove, *id));
    }

    // 2. Valid controllers that aren't members join as learners.
    if let Some(id) = i
        .controllers
        .iter()
        .find(|id| !m.contains(id) && i.joinable.contains(*id))
    {
        return Some((C::AddLearner, *id));
    }

    // Learners that could become voters, earliest-joined first.
    let mut ready: Vec<Bytes32> = m.learners.iter().copied().filter(healthy).collect();
    ready.sort_by_key(joined);

    // 3. A dead voter gives its seat to a healthy learner: demote it now,
    //    step 4 promotes the learner next.
    if !ready.is_empty()
        && let Some(id) = m.voters.iter().copied().filter(dead).max_by_key(joined)
    {
        return Some((C::Demote, id));
    }

    // 4. The voter count: odd, at most the target, never more than the
    //    members can fill.
    let target = target(i.settings.voters, m.voters.len() + m.learners.len());
    let v = m.voters.len();
    if v > target {
        // Demote the latest-joined voter, a dead or unreachable one first;
        // never the leader.
        let pick = m
            .voters
            .iter()
            .copied()
            .filter(|id| *id != i.leader)
            .max_by_key(|id| (dead(id), !healthy(id), joined(id)))?;
        return Some((C::Demote, pick));
    }
    if v < target {
        // Promote only when the count can end odd: from an odd count two
        // healthy learners are needed (the second follows next round).
        let need = if v.is_multiple_of(2) { 1 } else { 2 };
        if ready.len() >= need {
            return Some((C::Promote, ready[0]));
        }
        return None;
    }
    // At the target: a dead voter with no learner to replace it stays (the
    // cluster still has its quorum).
    None
}

/// The odd voter count for `members` members with the configured target.
pub fn target(configured: u8, members: usize) -> usize {
    let cap = (configured as usize).clamp(1, MAX_VOTERS);
    let cap = if cap.is_multiple_of(2) { cap - 1 } else { cap };
    let n = members.max(1);
    let n = if n.is_multiple_of(2) { n - 1 } else { n };
    cap.min(n)
}

/// What every replica checks on an `AutoMembershipEntry` besides the
/// checks of a manual change: automatic membership must be on, so turning
/// it off stops a leader that hasn't noticed yet.
pub fn check(settings: Settings) -> Result<(), String> {
    if !settings.auto_membership {
        return Err("automatic membership is off ([controllers] auto_membership)".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wp::MembershipChange as C;

    fn id(n: u8) -> Bytes32 {
        [n; 32]
    }

    struct T {
        s: Settings,
        m: Membership,
        ctl: BTreeSet<Bytes32>,
        eligible: BTreeSet<Bytes32>,
        joinable: BTreeSet<Bytes32>,
        since: BTreeMap<Bytes32, u64>,
        peers: BTreeMap<Bytes32, Peer>,
    }

    impl T {
        /// Leader 1, voters and learners as given, all valid controllers
        /// and healthy, joined in id order.
        fn new(voters: &[u8], learners: &[u8]) -> T {
            let m = Membership {
                voters: voters.iter().map(|n| id(*n)).collect(),
                learners: learners.iter().map(|n| id(*n)).collect(),
            };
            let all: Vec<u8> = voters.iter().chain(learners).copied().collect();
            T {
                s: Settings::of(None),
                ctl: all.iter().map(|n| id(*n)).collect(),
                eligible: (1..=20).map(id).collect(),
                joinable: (1..=20).map(id).collect(),
                since: all.iter().map(|n| (id(*n), *n as u64)).collect(),
                peers: all.iter().map(|n| (id(*n), Peer::default())).collect(),
                m,
            }
        }
        fn plan(&self) -> Option<Change> {
            plan(&Input {
                settings: self.s,
                leader: id(1),
                members: &self.m,
                controllers: &self.ctl,
                eligible: &self.eligible,
                joinable: &self.joinable,
                member_since: &self.since,
                peers: &self.peers,
            })
        }
        /// Apply plans until none is left; returns the steps.
        fn settle(&mut self) -> Vec<Change> {
            let mut out = Vec::new();
            while let Some((c, x)) = self.plan() {
                out.push((c, x));
                match c {
                    C::AddLearner => {
                        self.m.learners.insert(x);
                        self.since.insert(x, 100 + out.len() as u64);
                        self.peers.insert(x, Peer::default());
                    }
                    C::Promote => {
                        self.m.learners.remove(&x);
                        self.m.voters.insert(x);
                    }
                    C::Demote => {
                        self.m.voters.remove(&x);
                        self.m.learners.insert(x);
                    }
                    C::Remove => {
                        self.m.voters.remove(&x);
                        self.m.learners.remove(&x);
                        self.since.remove(&x);
                    }
                }
                assert!(out.len() < 50, "no fixpoint: {out:?}");
            }
            out
        }
        fn voters(&self) -> Vec<u8> {
            self.m.voters.iter().map(|v| v[0]).collect()
        }
    }

    #[test]
    fn targets_are_odd() {
        assert_eq!(target(5, 1), 1);
        assert_eq!(target(5, 2), 1);
        assert_eq!(target(5, 3), 3);
        assert_eq!(target(5, 4), 3);
        assert_eq!(target(5, 5), 5);
        assert_eq!(target(5, 16), 5);
        assert_eq!(target(7, 16), 7);
        assert_eq!(target(3, 16), 3);
        assert_eq!(target(1, 16), 1);
        assert_eq!(target(9, 16), 7);
        assert_eq!(target(4, 16), 3);
    }

    #[test]
    fn new_controllers_join_and_the_earliest_become_voters() {
        // Genesis voter 1; controllers 2..=8 appear.
        let mut t = T::new(&[1], &[]);
        for n in 2..=8 {
            t.ctl.insert(id(n));
        }
        let steps = t.settle();
        assert_eq!(steps.iter().filter(|s| s.0 == C::AddLearner).count(), 7);
        assert_eq!(t.voters(), vec![1, 2, 3, 4, 5]);
        assert_eq!(t.m.learners.len(), 3);
    }

    #[test]
    fn three_controllers_make_three_voters() {
        let mut t = T::new(&[1], &[]);
        t.ctl.insert(id(2));
        t.ctl.insert(id(3));
        t.settle();
        assert_eq!(t.voters(), vec![1, 2, 3]);
    }

    #[test]
    fn a_single_learner_is_not_promoted_to_an_even_count() {
        let mut t = T::new(&[1], &[]);
        t.ctl.insert(id(2));
        t.settle();
        assert_eq!(t.voters(), vec![1]);
        assert_eq!(t.m.learners.len(), 1);
    }

    #[test]
    fn an_even_voter_count_is_made_odd() {
        let mut t = T::new(&[1, 2, 3, 4], &[]);
        assert_eq!(t.plan(), Some((C::Demote, id(4))));
        t.settle();
        assert_eq!(t.voters(), vec![1, 2, 3]);
    }

    #[test]
    fn a_ghost_voter_is_removed() {
        // The user's case: 4 voters, one of them no longer a controller.
        let mut t = T::new(&[1, 2, 3, 9], &[]);
        t.ctl.remove(&id(9));
        assert_eq!(t.plan(), Some((C::Remove, id(9))));
        t.settle();
        assert_eq!(t.voters(), vec![1, 2, 3]);
    }

    #[test]
    fn a_revoked_member_is_removed_even_with_the_leaders_cert_gone() {
        let mut t = T::new(&[1, 2, 3], &[4]);
        t.ctl.clear();
        // Every certificate is gone (the admin who signed them was
        // revoked): nobody is removed for that...
        assert_eq!(t.plan(), None);
        // ...but a revoked node still is.
        t.eligible.remove(&id(4));
        assert_eq!(t.plan(), Some((C::Remove, id(4))));
    }

    #[test]
    fn an_uncertified_controller_does_not_join() {
        let mut t = T::new(&[1], &[]);
        t.eligible.insert(id(2)); // role, no certificate yet
        assert_eq!(t.plan(), None);
        // A certificate without the replicated role isn't enough either.
        t.ctl.insert(id(30));
        assert_eq!(t.plan(), None);
        t.ctl.insert(id(3));
        t.joinable.remove(&id(3)); // a record from before the role
        assert_eq!(t.plan(), None);
    }

    #[test]
    fn the_leader_and_the_last_voter_stay() {
        let mut t = T::new(&[1], &[2]);
        t.ctl.retain(|x| *x == id(1));
        // Learner 2 goes; the leader (also the last voter) stays.
        assert_eq!(t.settle(), vec![(C::Remove, id(2))]);
        assert_eq!(t.voters(), vec![1]);
        // A larger cluster never demotes the leader to reach the target.
        let mut t = T::new(&[1, 2, 3], &[]);
        t.s.voters = 1;
        t.settle();
        assert_eq!(t.voters(), vec![1]);
    }

    #[test]
    fn a_dead_voter_is_replaced_by_a_healthy_learner() {
        let mut t = T::new(&[1, 2, 3], &[4]);
        t.peers.get_mut(&id(2)).unwrap().silent = Duration::from_secs(4000);
        assert_eq!(t.plan(), Some((C::Demote, id(2))));
        t.settle();
        assert_eq!(t.voters(), vec![1, 3, 4]);
        // Back again: it stays a learner, the count is at the target.
        t.peers.get_mut(&id(2)).unwrap().silent = Duration::ZERO;
        assert_eq!(t.plan(), None);
    }

    #[test]
    fn a_dead_voter_without_replacement_stays() {
        let mut t = T::new(&[1, 2, 3], &[]);
        t.peers.get_mut(&id(2)).unwrap().silent = Duration::from_secs(4000);
        assert_eq!(t.plan(), None);
        // Nor when the only learner is unhealthy or behind.
        let mut t = T::new(&[1, 2, 3], &[4]);
        t.peers.get_mut(&id(2)).unwrap().silent = Duration::from_secs(4000);
        t.peers.get_mut(&id(4)).unwrap().lag = 10_000;
        assert_eq!(t.plan(), None);
        // dead_voter_after_s = 0 never replaces.
        let mut t = T::new(&[1, 2, 3], &[4]);
        t.peers.get_mut(&id(2)).unwrap().silent = Duration::from_secs(400_000);
        t.s.dead_voter_after_s = 0;
        assert_eq!(t.plan(), None);
    }

    #[test]
    fn unhealthy_learners_are_not_promoted() {
        let mut t = T::new(&[1], &[2, 3]);
        t.peers.remove(&id(3)); // never answered
        assert_eq!(t.plan(), None);
        t.peers.insert(id(3), Peer::default());
        t.settle();
        assert_eq!(t.voters(), vec![1, 2, 3]);
    }

    #[test]
    fn off_changes_nothing() {
        let mut t = T::new(&[1, 2, 3, 4], &[]);
        t.ctl.insert(id(5));
        t.s.auto_membership = false;
        assert_eq!(t.plan(), None);
    }

    #[test]
    fn an_unreachable_voter_is_demoted_first() {
        let mut t = T::new(&[1, 2, 3, 4], &[]);
        t.peers.get_mut(&id(2)).unwrap().silent = Duration::from_secs(120);
        assert_eq!(t.plan(), Some((C::Demote, id(2))));
    }

    #[test]
    fn a_lower_target_demotes_the_latest_joined() {
        let mut t = T::new(&[1, 2, 3, 4, 5], &[]);
        t.s.voters = 3;
        t.settle();
        assert_eq!(t.voters(), vec![1, 2, 3]);
    }

    #[test]
    fn check_refuses_when_off() {
        let s = Settings::of(None);
        assert!(check(s).is_ok());
        let off = Settings {
            auto_membership: false,
            ..s
        };
        assert!(check(off).is_err());
    }
}
