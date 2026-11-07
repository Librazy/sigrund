//! Aggregate target ownership accounting. Transfer reservations with the owned
//! resources; cancellation is not a quota refund. Drop only after close/reap.
use crate::{CoreError, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Charge {
    pub targets: u32,
    pub target_fds: u32,
    pub helpers: u32,
    pub reviews: u32,
}
impl Charge {
    fn values(self) -> [u32; 4] {
        [self.targets, self.target_fds, self.helpers, self.reviews]
    }
    fn from(values: [u32; 4]) -> Self {
        Self {
            targets: values[0],
            target_fds: values[1],
            helpers: values[2],
            reviews: values[3],
        }
    }
    fn add(self, other: Self) -> Option<Self> {
        let mut values = self.values();
        for (value, extra) in values.iter_mut().zip(other.values()) {
            *value = value.checked_add(extra)?;
        }
        Some(Self::from(values))
    }
    fn within(self, ceiling: Self) -> bool {
        self.values()
            .into_iter()
            .zip(ceiling.values())
            .all(|(n, max)| n <= max)
    }
    fn subtract(&mut self, other: Self) {
        let mut values = self.values();
        for (value, extra) in values.iter_mut().zip(other.values()) {
            *value = value
                .checked_sub(extra)
                .expect("reservation accounting underflow");
        }
        *self = Self::from(values);
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub global: Charge,
    pub per_uid: Charge,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            global: Charge {
                targets: 64,
                target_fds: 2048,
                helpers: 16,
                reviews: 16,
            },
            per_uid: Charge {
                targets: 4,
                target_fds: 128,
                helpers: 2,
                reviews: 2,
            },
        }
    }
}
impl Limits {
    pub fn validate(self) -> Result<()> {
        let hard = Self::default();
        if !self.global.within(hard.global)
            || !self.per_uid.within(hard.per_uid)
            || !self.per_uid.within(self.global)
            || self.global.values().contains(&0)
            || self.per_uid.values().contains(&0)
        {
            return Err(CoreError::Config("invalid host resource limits".into()));
        }
        Ok(())
    }
}
#[derive(Default)]
struct Used {
    global: Charge,
    parent_target_fds: u32,
    per_uid: BTreeMap<u32, Charge>,
}
impl Used {
    fn reserve(&mut self, limits: Limits, uid: u32, charge: Charge) -> Option<()> {
        let global = self.global.add(charge)?;
        let per_uid = self
            .per_uid
            .get(&uid)
            .copied()
            .unwrap_or_default()
            .add(charge)?;
        if !global.within(limits.global) || !per_uid.within(limits.per_uid) {
            return None;
        }
        self.global = global;
        self.per_uid.insert(uid, per_uid);
        Some(())
    }
    fn release(&mut self, uid: u32, charge: Charge) {
        self.global.subtract(charge);
        let per_uid = self.per_uid.get_mut(&uid).expect("charged UID missing");
        per_uid.subtract(charge);
        if *per_uid == Charge::default() {
            self.per_uid.remove(&uid);
        }
    }
}
struct TransientCopies<'a> {
    used: &'a mut Used,
    uid: u32,
    charge: Charge,
}
impl Drop for TransientCopies<'_> {
    fn drop(&mut self) {
        self.used.release(self.uid, self.charge);
    }
}

#[derive(Clone)]
pub struct Budget {
    limits: Limits,
    used: Arc<Mutex<Used>>,
}
pub struct Reservation {
    budget: Budget,
    uid: u32,
    charge: Charge,
    inherited: bool,
}
impl Budget {
    pub fn new(limits: Limits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            used: Arc::new(Mutex::new(Used::default())),
        })
    }
    /// Reserve before acquiring resources, including transient FD duplicates.
    /// Failure leaves all counters unchanged and adds no UID table entry.
    pub fn reserve(&self, uid: u32, charge: Charge) -> Option<Reservation> {
        if uid == u32::MAX || charge == Charge::default() {
            return None;
        }
        let mut used = self.used.lock().expect("host budget poisoned");
        used.reserve(self.limits, uid, charge)?;
        used.parent_target_fds += charge.target_fds;
        Some(Reservation {
            budget: self.clone(),
            uid,
            charge,
            inherited: false,
        })
    }
    /// Transfer the inherited-copy reservation to a child owner. Callers keep
    /// it through actual close/reap, including an unpublished clone result.
    /// Only the fork/clone operation runs under the accounting lock. An unwind
    /// aborts: an unreported child must be reconciled by the process supervisor.
    pub fn with_retained_fd_copies<T>(
        &self,
        uid: u32,
        operation: impl FnOnce() -> T,
    ) -> Option<(T, Reservation)> {
        if uid == u32::MAX {
            return None;
        }
        let mut used = self.used.lock().expect("host budget poisoned");
        let charge = Charge {
            target_fds: used.parent_target_fds,
            ..Default::default()
        };
        if charge.target_fds == 0 {
            return None;
        }
        used.reserve(self.limits, uid, charge)?;
        let copies = TransientCopies {
            used: &mut used,
            uid,
            charge,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
            .unwrap_or_else(|_| std::process::abort());
        // The child owner takes over this already-accounted charge. On an
        // unexpected unwind child ownership is uncertain; abort under the
        // service supervisor instead of refunding an unknown live child.
        std::mem::forget(copies);
        drop(used);
        Some((
            result,
            Reservation {
                budget: self.clone(),
                uid,
                charge,
                inherited: true,
            },
        ))
    }
    /// A fresh-exec helper temporarily inherits the whole parent's descriptor
    /// table. Charge a conservative copy of every reserved parent target FD before
    /// fork, keeping the accounting lock through the exec handshake so another
    /// reservation cannot expand that table between counting and copying it.
    /// `operation` must return only after those inherited copies close/reap,
    /// and must not reserve/release this budget while the lock is held.
    pub fn with_transient_fd_copies<T>(
        &self,
        uid: u32,
        operation: impl FnOnce() -> T,
    ) -> Option<T> {
        if uid == u32::MAX {
            return None;
        }
        let mut used = self.used.lock().expect("host budget poisoned");
        let charge = Charge {
            target_fds: used.parent_target_fds,
            ..Default::default()
        };
        if charge.target_fds == 0 {
            return Some(operation());
        }
        used.reserve(self.limits, uid, charge)?;
        let _copies = TransientCopies {
            used: &mut used,
            uid,
            charge,
        };
        Some(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
                .unwrap_or_else(|_| std::process::abort()),
        )
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut used = self.budget.used.lock().expect("host budget poisoned");
        used.release(self.uid, self.charge);
        if !self.inherited {
            used.parent_target_fds -= self.charge.target_fds;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exhaustion_is_atomic_and_charges_survive_owner_transfer() {
        let budget = Budget::new(Limits::default()).unwrap();
        let charge = Charge {
            targets: 1,
            target_fds: 32,
            ..Charge::default()
        };
        let owners: Vec<_> = (0..4)
            .map(|_| budget.reserve(1000, charge).unwrap())
            .collect();
        assert!(budget.reserve(1000, charge).is_none());
        let owned = std::thread::spawn(move || owners).join().unwrap();
        assert!(budget.reserve(1000, charge).is_none());
        assert_eq!(budget.used.lock().unwrap().global.target_fds, 128);
        drop(owned);
        assert_eq!(budget.used.lock().unwrap().per_uid.len(), 0);
        assert!(budget.reserve(1000, charge).is_some());
    }
    #[test]
    fn global_exhaustion_does_not_grow_uid_table_or_refund_another_owner() {
        let budget = Budget::new(Limits::default()).unwrap();
        let charge = Charge {
            helpers: 2,
            ..Charge::default()
        };
        let owners: Vec<_> = (0..8)
            .map(|uid| budget.reserve(uid, charge).unwrap())
            .collect();
        for uid in 8..1000 {
            assert!(budget.reserve(uid, charge).is_none());
        }
        assert_eq!(budget.used.lock().unwrap().per_uid.len(), 8);
        drop(owners);
        assert!(budget.reserve(9, charge).is_some());
    }
    #[test]
    fn transient_inheritance_reserves_the_whole_table_before_the_operation() {
        let budget = Budget::new(Limits::default()).unwrap();
        let existing = budget
            .reserve(
                1,
                Charge {
                    target_fds: 65,
                    ..Default::default()
                },
            )
            .unwrap();
        let mut called = false;
        assert!(
            budget
                .with_transient_fd_copies(1, || {
                    called = true;
                })
                .is_none()
        );
        assert!(!called);
        assert_eq!(budget.used.lock().unwrap().global.target_fds, 65);
        let result = budget.with_transient_fd_copies(2, || {
            // New reservations cannot expand the parent's table until the
            // inherited copies have closed at the exec handshake.
            assert!(matches!(
                budget.used.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            42
        });
        assert_eq!(result, Some(42));
        let used = budget.used.lock().unwrap();
        assert_eq!(used.global.target_fds, 65);
        assert!(!used.per_uid.contains_key(&2));
        drop(used);
        drop(existing);
        assert_eq!(budget.used.lock().unwrap().global, Charge::default());
    }
    #[test]
    fn retained_inheritance_charge_moves_with_the_child_owner() {
        let budget = Budget::new(Limits::default()).unwrap();
        let existing = budget
            .reserve(
                1,
                Charge {
                    target_fds: 65,
                    ..Default::default()
                },
            )
            .unwrap();
        let (child, copies) = budget.with_retained_fd_copies(2, || "child").unwrap();
        assert_eq!(child, "child");
        assert_eq!(budget.used.lock().unwrap().global.target_fds, 130);
        assert!(
            budget
                .reserve(
                    2,
                    Charge {
                        target_fds: 64,
                        ..Default::default()
                    }
                )
                .is_none()
        );
        let copies = std::thread::spawn(move || copies).join().unwrap();
        assert_eq!(budget.used.lock().unwrap().per_uid[&2].target_fds, 65);
        drop(copies);
        assert_eq!(budget.used.lock().unwrap().global.target_fds, 65);
        assert!(!budget.used.lock().unwrap().per_uid.contains_key(&2));
        drop(existing);
    }
    #[test]
    fn invalid_or_overflowing_charges_and_limits_fail_closed() {
        let budget = Budget::new(Limits::default()).unwrap();
        assert!(
            budget
                .reserve(
                    1,
                    Charge {
                        target_fds: u32::MAX,
                        ..Charge::default()
                    }
                )
                .is_none()
        );
        assert!(
            budget
                .reserve(
                    u32::MAX,
                    Charge {
                        targets: 1,
                        ..Charge::default()
                    }
                )
                .is_none()
        );
        let mut limits = Limits::default();
        limits.per_uid.helpers = 3;
        assert!(Budget::new(limits).is_err());
    }
}

#[cfg(test)]
mod inheritance_regression {
    use super::*;
    #[test]
    fn sibling_copies_do_not_inflate_the_parent_table() {
        let budget = Budget::new(Default::default()).unwrap();
        let parent = budget
            .reserve(
                1,
                Charge {
                    target_fds: 16,
                    ..Default::default()
                },
            )
            .unwrap();
        let mut children = Vec::new();
        for uid in 2..10 {
            let (_, copies) = budget.with_retained_fd_copies(uid, || ()).unwrap();
            assert_eq!(copies.charge.target_fds, 16);
            children.push(copies);
        }
        budget.with_transient_fd_copies(10, || ()).unwrap();
        assert_eq!(budget.used.lock().unwrap().global.target_fds, 144);
        drop(children);
        drop(parent);
        assert_eq!(budget.used.lock().unwrap().parent_target_fds, 0);
    }
}
