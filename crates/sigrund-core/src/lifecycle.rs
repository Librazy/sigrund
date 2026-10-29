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
    pub fn transition(&self, from: Phase, to: Phase) -> bool {
        let current = self.word.load(Ordering::Acquire);
        let (_, decision) = Self::unpack(current);
        if Self::unpack(current).0 != from {
            return false;
        }
        self.word
            .compare_exchange(
                current,
                Self::pack(to, decision),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
    pub fn claim_terminal(&self, phase: Phase, decision: Decision) -> bool {
        let current = self.word.load(Ordering::Acquire);
        let (current_phase, current_decision) = Self::unpack(current);
        if current_phase != phase || current_decision != Decision::Undecided {
            return false;
        }
        self.cancelled.store(
            matches!(decision, Decision::Timeout | Decision::NoReply),
            Ordering::Release,
        );
        self.word
            .compare_exchange(
                current,
                Self::pack(Phase::Cancelled, decision),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
    pub fn cancel(&self) -> bool {
        self.cancelled.store(true, Ordering::Release);
        loop {
            let current = self.word.load(Ordering::Acquire);
            let (phase, decision) = Self::unpack(current);
            if matches!(phase, Phase::Cancelled | Phase::Failed) {
                return false;
            }
            if decision != Decision::Undecided && phase == Phase::Running {
                return false;
            }
            if self
                .word
                .compare_exchange(
                    current,
                    Self::pack(Phase::Cancelled, Decision::NoReply),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return true;
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
}
