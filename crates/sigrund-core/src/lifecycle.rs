use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::{CoreError, Result};

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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Decision {
    Undecided = 0,
    Ready = 1,
    Rejected = 2,
    Timeout = 3,
    NoReply = 4,
}

pub struct Lifecycle {
    word: AtomicU64,
    pub cancelled: AtomicBool,
}

const CANCELLATION_PENDING: u64 = 1 << 16;

impl Lifecycle {
    pub fn new() -> Self {
        Self {
            word: AtomicU64::new(Self::pack(Phase::Snapshotting, Decision::Undecided)),
            cancelled: AtomicBool::new(false),
        }
    }
    fn pack(phase: Phase, decision: Decision) -> u64 {
        (phase as u64) | ((decision as u64) << 8)
    }
    fn unpack(word: u64) -> (Phase, Decision) {
        let phase = match (word & 0xff) as u8 {
            1 => Phase::Snapshotting,
            2 => Phase::Authorizing,
            3 => Phase::Committing,
            4 => Phase::Committed,
            5 => Phase::Spawning,
            6 => Phase::Running,
            7 => Phase::Cancelled,
            _ => Phase::Failed,
        };
        let decision = match ((word >> 8) & 0xff) as u8 {
            1 => Decision::Ready,
            2 => Decision::Rejected,
            3 => Decision::Timeout,
            4 => Decision::NoReply,
            _ => Decision::Undecided,
        };
        (phase, decision)
    }
    pub fn state(&self) -> (Phase, Decision) {
        Self::unpack(self.word.load(Ordering::Acquire))
    }
    /// Release a commit reservation only after a successful rollback has made
    /// its result known. Pending cancellation stays visible to the coordinator.
    pub fn rolled_back_commit(&self) -> bool {
        loop {
            let current = self.word.load(Ordering::Acquire);
            if Self::unpack(current) != (Phase::Committing, Decision::Undecided) {
                return false;
            }
            let next = Self::pack(Phase::Authorizing, Decision::Undecided)
                | (current & CANCELLATION_PENDING);
            if self
                .word
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }
    pub fn transition(&self, from: Phase, to: Phase) -> bool {
        if !matches!(
            (from, to),
            (Phase::Snapshotting, Phase::Authorizing)
                | (Phase::Authorizing, Phase::Committing)
                | (Phase::Committing, Phase::Committed)
                | (Phase::Committed, Phase::Spawning)
                | (Phase::Spawning, Phase::Running)
        ) {
            return false;
        }
        loop {
            let current = self.word.load(Ordering::Acquire);
            let (phase, decision) = Self::unpack(current);
            if phase != from || decision != Decision::Undecided {
                return false;
            }
            // The executor must finish recording the result of a reserved
            // operation even when cancellation became pending during it.
            if current & CANCELLATION_PENDING != 0
                && !matches!(from, Phase::Committing | Phase::Spawning)
            {
                return false;
            }
            let next = Self::pack(to, decision) | (current & CANCELLATION_PENDING);
            if self
                .word
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Atomically publishes readiness without ending the running lifecycle.
    pub fn publish_ready(&self) -> bool {
        self.word
            .compare_exchange(
                Self::pack(Phase::Running, Decision::Undecided),
                Self::pack(Phase::Running, Decision::Ready),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub fn claim_terminal(&self, phase: Phase, decision: Decision) -> bool {
        // Preserve the existing decision API while keeping readiness live.
        if decision == Decision::Ready {
            return phase == Phase::Running && self.publish_ready();
        }
        if decision == Decision::Undecided || matches!(phase, Phase::Cancelled | Phase::Failed) {
            return false;
        }
        if matches!(phase, Phase::Committing | Phase::Spawning) {
            if matches!(decision, Decision::Timeout | Decision::NoReply) {
                // A phase-specific timeout must not cancel a later phase if
                // completion wins while this callback is waiting to run.
                let current = self.word.load(Ordering::Acquire);
                if Self::unpack(current) == (phase, Decision::Undecided)
                    && self
                        .word
                        .compare_exchange(
                            current,
                            current | CANCELLATION_PENDING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                {
                    self.cancelled.store(true, Ordering::Release);
                }
            }
            return false;
        }
        let current = self.word.load(Ordering::Acquire);
        let (current_phase, current_decision) = Self::unpack(current);
        if current_phase != phase || current_decision != Decision::Undecided {
            return false;
        }
        let terminal = if decision == Decision::Rejected {
            Phase::Failed
        } else {
            Phase::Cancelled
        };
        let next = Self::pack(terminal, decision) | (current & CANCELLATION_PENDING);
        let won = self
            .word
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if won && terminal == Phase::Cancelled {
            self.cancelled.store(true, Ordering::Release);
        }
        won
    }

    /// Requests cancellation. Returns true only when a terminal phase was
    /// claimed. During reservations, the owner must reconcile the syscall's
    /// result before calling this again to finish cancellation.
    pub fn cancel(&self) -> bool {
        loop {
            let current = self.word.load(Ordering::Acquire);
            let (phase, decision) = Self::unpack(current);
            if matches!(phase, Phase::Cancelled | Phase::Failed) {
                return false;
            }
            let reserved = matches!(phase, Phase::Committing | Phase::Spawning);
            let next = if reserved {
                current | CANCELLATION_PENDING
            } else {
                let outcome = if decision == Decision::Undecided {
                    Decision::NoReply
                } else {
                    decision
                };
                Self::pack(Phase::Cancelled, outcome) | CANCELLATION_PENDING
            };
            if self
                .word
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.cancelled.store(true, Ordering::Release);
                return !reserved;
            }
        }
    }
    pub fn require(&self, expected: Phase) -> Result<()> {
        if self.state().0 == expected {
            Ok(())
        } else {
            Err(CoreError::Protocol(
                "invalid request lifecycle transition".into(),
            ))
        }
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_terminal_winner() {
        let lifecycle = Lifecycle::new();
        assert!(lifecycle.claim_terminal(Phase::Snapshotting, Decision::Timeout));
        assert!(!lifecycle.claim_terminal(Phase::Snapshotting, Decision::Rejected));
        assert_eq!(lifecycle.state(), (Phase::Cancelled, Decision::Timeout));
    }

    fn advance_to(lifecycle: &Lifecycle, target: Phase) {
        for (from, to) in [
            (Phase::Snapshotting, Phase::Authorizing),
            (Phase::Authorizing, Phase::Committing),
            (Phase::Committing, Phase::Committed),
            (Phase::Committed, Phase::Spawning),
            (Phase::Spawning, Phase::Running),
        ] {
            assert!(lifecycle.transition(from, to));
            if to == target {
                break;
            }
        }
    }

    #[test]
    fn cancellation_preserves_reservations_until_results_are_known() {
        for (reserved, completed) in [
            (Phase::Committing, Phase::Committed),
            (Phase::Spawning, Phase::Running),
        ] {
            let lifecycle = Lifecycle::new();
            advance_to(&lifecycle, reserved);
            assert!(!lifecycle.cancel());
            assert_eq!(lifecycle.state(), (reserved, Decision::Undecided));
            assert!(lifecycle.cancelled.load(Ordering::Acquire));
            assert!(!lifecycle.claim_terminal(reserved, Decision::Timeout));
            assert!(lifecycle.transition(reserved, completed));
            assert!(!lifecycle.publish_ready());
            assert!(!lifecycle.transition(completed, Phase::Spawning));
            assert!(lifecycle.cancel());
            assert_eq!(lifecycle.state(), (Phase::Cancelled, Decision::NoReply));
        }
    }

    #[test]
    fn reserved_executor_reconciles_cancellation_after_result_gate() {
        use std::sync::{Arc, mpsc};
        for (reserved, completed) in [
            (Phase::Committing, Phase::Committed),
            (Phase::Spawning, Phase::Running),
        ] {
            let lifecycle = Arc::new(Lifecycle::new());
            advance_to(&lifecycle, reserved);
            let (release, result_known) = mpsc::channel();
            let executor_context = lifecycle.clone();
            let executor = std::thread::spawn(move || {
                result_known.recv().unwrap();
                assert!(executor_context.transition(reserved, completed));
                assert!(!executor_context.publish_ready());
                assert!(executor_context.cancel());
            });
            assert!(!lifecycle.cancel());
            assert_eq!(lifecycle.state(), (reserved, Decision::Undecided));
            release.send(()).unwrap();
            executor.join().unwrap();
            assert_eq!(lifecycle.state(), (Phase::Cancelled, Decision::NoReply));
        }
    }

    #[test]
    fn stale_reservation_timeout_cannot_cancel_a_later_phase() {
        let lifecycle = Lifecycle::new();
        advance_to(&lifecycle, Phase::Running);
        assert!(!lifecycle.claim_terminal(Phase::Committing, Decision::Timeout));
        assert!(!lifecycle.claim_terminal(Phase::Spawning, Decision::Timeout));
        assert_eq!(lifecycle.state(), (Phase::Running, Decision::Undecided));
        assert!(!lifecycle.cancelled.load(Ordering::Acquire));
        assert!(lifecycle.publish_ready());
    }

    #[test]
    fn readiness_retains_running_and_teardown_retains_decision() {
        let lifecycle = Lifecycle::new();
        advance_to(&lifecycle, Phase::Running);
        assert!(lifecycle.claim_terminal(Phase::Running, Decision::Ready));
        assert_eq!(lifecycle.state(), (Phase::Running, Decision::Ready));
        assert!(!lifecycle.publish_ready());
        assert!(lifecycle.cancel());
        assert_eq!(lifecycle.state(), (Phase::Cancelled, Decision::Ready));
    }

    #[test]
    fn rejection_fails_and_terminal_states_cannot_be_revived() {
        let lifecycle = Lifecycle::new();
        assert!(lifecycle.claim_terminal(Phase::Snapshotting, Decision::Rejected));
        assert_eq!(lifecycle.state(), (Phase::Failed, Decision::Rejected));
        assert!(!lifecycle.transition(Phase::Failed, Phase::Authorizing));
        assert!(!lifecycle.claim_terminal(Phase::Failed, Decision::Ready));
    }
}
