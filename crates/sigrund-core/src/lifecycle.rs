//! Atomic public decisions are independent of irreversible operation ownership.
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Phase {
    Snapshotting = 1,
    Authorizing = 2,
    Committing = 3,
    Committed = 4,
    Spawning = 5,
    Running = 6,
    Cancelled = 7,
    Failed = 8,
    Releasing = 9,
    Hashing = 10,
    SilentTimeout = 11,
    ApprovalDelivery = 12,
    Approved = 13,
    Reviewing = 14,
    Finished = 15,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Decision {
    Undecided = 0,
    Approved = 1,
    Rejected = 2,
    Timeout = 3,
    NoReply = 4,
}
pub struct Lifecycle {
    word: AtomicU64,
    delivery: AtomicU8,
    pub cancelled: AtomicBool,
}
const PENDING: u64 = 1 << 16;
const READY: u64 = 1 << 17;
impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}
impl Lifecycle {
    pub fn new() -> Self {
        Self {
            word: AtomicU64::new(Self::pack(Phase::Snapshotting, Decision::Undecided)),
            delivery: AtomicU8::new(0),
            cancelled: AtomicBool::new(false),
        }
    }
    fn pack(p: Phase, d: Decision) -> u64 {
        p as u64 | ((d as u64) << 8)
    }
    fn unpack(w: u64) -> (Phase, Decision) {
        let p = match w & 255 {
            1 => Phase::Snapshotting,
            2 => Phase::Authorizing,
            3 => Phase::Committing,
            4 => Phase::Committed,
            5 => Phase::Spawning,
            6 => Phase::Running,
            7 => Phase::Cancelled,
            8 => Phase::Failed,
            9 => Phase::Releasing,
            10 => Phase::Hashing,
            11 => Phase::SilentTimeout,
            12 => Phase::ApprovalDelivery,
            13 => Phase::Approved,
            14 => Phase::Reviewing,
            _ => Phase::Finished,
        };
        let d = match (w >> 8) & 255 {
            1 => Decision::Approved,
            2 => Decision::Rejected,
            3 => Decision::Timeout,
            4 => Decision::NoReply,
            _ => Decision::Undecided,
        };
        (p, d)
    }
    pub fn state(&self) -> (Phase, Decision) {
        Self::unpack(self.word.load(Ordering::Acquire))
    }
    /// A completed socket write is not proof of receipt by the requester.
    pub fn mark_frame_written(&self) {
        let _ = self
            .delivery
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
    }
    pub fn mark_undelivered(&self) {
        let _ = self.delivery.compare_exchange(
            0,
            if self.state().1 == Decision::NoReply {
                3
            } else {
                2
            },
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    pub fn delivery_status(&self) -> &'static str {
        match self.delivery.load(Ordering::Acquire) {
            1 => "sent",
            2 => "failed",
            3 => "no_reply",
            _ => "not_started",
        }
    }
    pub fn public_outcome(&self) -> &'static str {
        match self.state().1 {
            Decision::Approved => "APPROVED",
            Decision::Rejected => "REJECTED",
            Decision::Timeout => "TIMEOUT",
            Decision::NoReply => "NO_REPLY",
            _ => "UNDECIDED",
        }
    }
    pub fn transition(&self, from: Phase, to: Phase) -> bool {
        let allowed = matches!(
            (from, to),
            (
                Phase::Snapshotting,
                Phase::Hashing | Phase::Reviewing | Phase::Authorizing
            ) | (Phase::Hashing, Phase::Reviewing | Phase::Authorizing)
                | (Phase::Reviewing, Phase::Authorizing)
                | (Phase::Authorizing, Phase::Committing)
                | (Phase::Committing, Phase::Committed)
                | (Phase::Committed, Phase::ApprovalDelivery)
                | (Phase::ApprovalDelivery, Phase::Approved)
                | (Phase::Approved, Phase::Spawning)
                | (Phase::Spawning, Phase::Running)
                | (Phase::Running, Phase::Releasing)
                | (Phase::Releasing, Phase::Running)
        );
        if !allowed {
            return false;
        }
        loop {
            let w = self.word.load(Ordering::Acquire);
            let (p, d) = Self::unpack(w);
            let reconcile = matches!(from, Phase::Committing | Phase::Spawning | Phase::Releasing);
            let post = matches!(
                from,
                Phase::ApprovalDelivery
                    | Phase::Approved
                    | Phase::Spawning
                    | Phase::Running
                    | Phase::Releasing
            );
            if p != from
                || (!reconcile && w & PENDING != 0)
                || (!reconcile
                    && d != if post {
                        Decision::Approved
                    } else {
                        Decision::Undecided
                    })
            {
                return false;
            }
            let next = (w & !255) | to as u64;
            if self
                .word
                .compare_exchange(w, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }
    pub fn rolled_back_commit(&self) -> bool {
        loop {
            let w = self.word.load(Ordering::Acquire);
            let (p, d) = Self::unpack(w);
            if p != Phase::Committing {
                return false;
            }
            let to = if d == Decision::Undecided && w & PENDING == 0 {
                Phase::Authorizing
            } else {
                Phase::SilentTimeout
            };
            if self
                .word
                .compare_exchange(
                    w,
                    (w & !255) | to as u64,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return true;
            }
        }
    }
    pub fn silence(&self) -> bool {
        loop {
            let w = self.word.load(Ordering::Acquire);
            let (p, d) = Self::unpack(w);
            if d != Decision::Undecided
                || matches!(p, Phase::SilentTimeout | Phase::Cancelled | Phase::Failed)
            {
                return false;
            }
            let next = if p == Phase::Committing {
                w | PENDING
            } else {
                (w & !255) | Phase::SilentTimeout as u64 | PENDING
            };
            if self
                .word
                .compare_exchange(w, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.cancelled.store(true, Ordering::Release);
                return true;
            }
        }
    }
    pub fn claim_terminal(&self, phase: Phase, decision: Decision) -> bool {
        if decision == Decision::Undecided {
            return false;
        }
        loop {
            let w = self.word.load(Ordering::Acquire);
            let (p, d) = Self::unpack(w);
            if p != phase || d != Decision::Undecided {
                return false;
            }
            if decision == Decision::Approved && (p != Phase::ApprovalDelivery || w & PENDING != 0)
            {
                return false;
            }
            if decision == Decision::Rejected && p != Phase::Reviewing {
                return false;
            }
            let next_phase = match decision {
                Decision::Approved => p,
                Decision::Rejected => Phase::Failed,
                _ if p == Phase::Committing => p,
                _ => Phase::Cancelled,
            };
            let next = Self::pack(next_phase, decision) | (w & (PENDING | READY));
            if self
                .word
                .compare_exchange(w, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                if decision != Decision::Approved {
                    self.cancelled.store(true, Ordering::Release);
                }
                return true;
            }
        }
    }
    pub fn publish_ready(&self) -> bool {
        loop {
            let w = self.word.load(Ordering::Acquire);
            if Self::unpack(w) != (Phase::Running, Decision::Approved) || w & (PENDING | READY) != 0
            {
                return false;
            }
            if self
                .word
                .compare_exchange(w, w | READY, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }
    pub fn finish_spawn(&self, _reason: Decision) -> bool {
        loop {
            let w = self.word.load(Ordering::Acquire);
            if Self::unpack(w).0 != Phase::Spawning {
                return false;
            }
            if self
                .word
                .compare_exchange(
                    w,
                    (w & !255) | Phase::Failed as u64,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return true;
            }
        }
    }
    pub fn cancel(&self) -> bool {
        loop {
            let w = self.word.load(Ordering::Acquire);
            let (p, d) = Self::unpack(w);
            if matches!(p, Phase::Cancelled | Phase::Failed | Phase::Finished) {
                return false;
            }
            let reserved = matches!(p, Phase::Committing | Phase::Spawning | Phase::Releasing);
            let d = if d == Decision::Undecided {
                Decision::NoReply
            } else {
                d
            };
            let next =
                Self::pack(if reserved { p } else { Phase::Cancelled }, d) | (w & READY) | PENDING;
            if self
                .word
                .compare_exchange(w, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.cancelled.store(true, Ordering::Release);
                return !reserved;
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn commit(l: &Lifecycle) {
        assert!(l.transition(Phase::Snapshotting, Phase::Authorizing));
        assert!(l.transition(Phase::Authorizing, Phase::Committing));
    }
    fn approved(l: &Lifecycle) {
        commit(l);
        assert!(l.transition(Phase::Committing, Phase::Committed));
        assert!(l.transition(Phase::Committed, Phase::ApprovalDelivery));
        assert!(l.claim_terminal(Phase::ApprovalDelivery, Decision::Approved));
        assert!(l.transition(Phase::ApprovalDelivery, Phase::Approved));
    }
    #[test]
    fn silent_failure_cannot_be_revived_by_late_approval() {
        let l = Lifecycle::new();
        assert!(l.transition(Phase::Snapshotting, Phase::Reviewing));
        assert!(l.silence());
        assert_eq!(l.state(), (Phase::SilentTimeout, Decision::Undecided));
        assert!(!l.transition(Phase::Reviewing, Phase::Authorizing));
        assert!(l.claim_terminal(Phase::SilentTimeout, Decision::Timeout));
        assert!(!l.claim_terminal(Phase::Cancelled, Decision::Approved));
    }
    #[test]
    fn timeout_wins_while_commit_ownership_reconciles() {
        let l = Lifecycle::new();
        commit(&l);
        assert!(l.silence());
        assert!(l.claim_terminal(Phase::Committing, Decision::Timeout));
        assert_eq!(l.state(), (Phase::Committing, Decision::Timeout));
        assert!(l.transition(Phase::Committing, Phase::Committed));
        assert!(!l.transition(Phase::Committed, Phase::ApprovalDelivery));
        assert!(!l.claim_terminal(Phase::Committed, Decision::Approved));
    }
    #[test]
    fn silence_before_commit_result_keeps_the_pending_public_timeout() {
        let l = Lifecycle::new();
        commit(&l);
        assert!(l.silence());
        assert!(l.transition(Phase::Committing, Phase::Committed));
        assert!(!l.transition(Phase::Committed, Phase::ApprovalDelivery));
        assert!(l.claim_terminal(Phase::Committed, Decision::Timeout));
    }
    #[test]
    fn approval_is_final_and_precedes_spawn_and_readiness() {
        let l = Lifecycle::new();
        assert!(!l.claim_terminal(Phase::Snapshotting, Decision::Approved));
        approved(&l);
        assert!(!l.claim_terminal(Phase::Approved, Decision::Timeout));
        assert!(l.transition(Phase::Approved, Phase::Spawning));
        assert!(l.transition(Phase::Spawning, Phase::Running));
        assert!(l.publish_ready());
        assert!(!l.publish_ready());
        assert!(l.cancel());
        assert_eq!(l.state(), (Phase::Cancelled, Decision::Approved));
    }
    #[test]
    fn disconnect_during_reserved_spawn_preserves_the_approval() {
        let l = Lifecycle::new();
        approved(&l);
        assert!(l.transition(Phase::Approved, Phase::Spawning));
        assert!(!l.cancel());
        assert_eq!(l.state(), (Phase::Spawning, Decision::Approved));
        assert!(l.transition(Phase::Spawning, Phase::Running));
        assert!(!l.publish_ready());
        assert!(l.cancel());
    }
    #[test]
    fn explicit_rejection_requires_review_and_is_final() {
        let l = Lifecycle::new();
        assert!(!l.claim_terminal(Phase::Snapshotting, Decision::Rejected));
        assert!(l.transition(Phase::Snapshotting, Phase::Reviewing));
        assert!(l.claim_terminal(Phase::Reviewing, Decision::Rejected));
        assert!(!l.transition(Phase::Reviewing, Phase::Authorizing));
        assert!(!l.claim_terminal(Phase::Failed, Decision::Timeout));
    }
}
