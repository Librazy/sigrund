//! Process-wide admission windows and audit ownership, independent of sockets
//! and worker leases. Only the coordinator changes window counters.
use sigrund_core::config::DaemonConfig;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Instant,
};

struct Uid {
    admitted: u32,
    pending: Arc<AtomicU32>,
}
pub(crate) struct Admission {
    start: Instant,
    window_secs: u32,
    window: u64,
    admitted: u32,
    uids: HashMap<u32, Uid>,
    pending: Arc<AtomicU32>,
    diagnostic: Arc<AtomicBool>,
    refused: u64,
    diagnostic_emitted: bool,
}
/// One owned record buffer. Moving this value transfers its quota; completing
/// an append releases it even if the originating socket no longer exists.
pub(crate) struct AuditLease {
    global: Arc<AtomicU32>,
    uid: Option<Arc<AtomicU32>>,
    diagnostic: Option<Arc<AtomicBool>>,
}
impl Drop for AuditLease {
    fn drop(&mut self) {
        if let Some(uid) = &self.uid {
            assert!(uid.fetch_sub(1, Ordering::AcqRel) > 0);
        }
        assert!(self.global.fetch_sub(1, Ordering::AcqRel) > 0);
        if let Some(diagnostic) = &self.diagnostic {
            diagnostic.store(false, Ordering::Release);
        }
    }
}
impl Admission {
    pub fn new(config: &DaemonConfig, start: Instant) -> Self {
        Self {
            start,
            window_secs: config.admission_window_secs,
            window: 0,
            admitted: 0,
            uids: HashMap::new(),
            pending: Arc::new(AtomicU32::new(0)),
            diagnostic: Arc::new(AtomicBool::new(false)),
            refused: 0,
            diagnostic_emitted: false,
        }
    }
    fn refresh(&mut self, now: Instant) {
        let window =
            now.saturating_duration_since(self.start).as_secs() / u64::from(self.window_secs);
        if window > self.window {
            self.window = window;
            self.admitted = 0;
            self.uids.retain(|_, uid| {
                uid.admitted = 0;
                uid.pending.load(Ordering::Acquire) > 0
            });
            self.diagnostic_emitted = false;
            // Keep a fixed-size aggregate if a previous window could not log.
        }
    }
    pub fn is_idle(&self) -> bool {
        self.pending.load(Ordering::Acquire) == 0
    }
    pub fn refuse(&mut self) {
        self.refused = self.refused.saturating_add(1);
    }
    pub fn admit(&mut self, uid: u32, config: &DaemonConfig, now: Instant) -> Option<AuditLease> {
        self.refresh(now);
        let pending = self.pending.load(Ordering::Acquire);
        let diagnostic = u32::from(self.diagnostic.load(Ordering::Acquire));
        let entry = self.uids.get(&uid);
        if self.admitted >= config.request_admissions_global
            || entry.is_some_and(|e| {
                e.admitted >= config.request_admissions_per_uid
                    || e.pending.load(Ordering::Acquire) >= config.max_pending_audits_per_uid
            })
            || pending.saturating_sub(diagnostic) >= config.max_pending_audits_global - 1
            || (entry.is_none() && self.uids.len() >= 4096)
        {
            self.refuse();
            return None;
        }
        let entry = self.uids.entry(uid).or_insert_with(|| Uid {
            admitted: 0,
            pending: Arc::new(AtomicU32::new(0)),
        });
        // Validated immutable ceilings make all increments below bounded.
        self.admitted = self.admitted.checked_add(1)?;
        entry.admitted = entry.admitted.checked_add(1)?;
        entry.pending.fetch_add(1, Ordering::AcqRel);
        self.pending.fetch_add(1, Ordering::AcqRel);
        Some(AuditLease {
            global: self.pending.clone(),
            uid: Some(entry.pending.clone()),
            diagnostic: None,
        })
    }
    pub fn diagnostic(&mut self, now: Instant, requested: bool) -> Option<(AuditLease, u64)> {
        self.refresh(now);
        if (self.refused == 0 && !requested)
            || self.diagnostic_emitted
            || self.diagnostic.swap(true, Ordering::AcqRel)
        {
            return None;
        }
        self.pending.fetch_add(1, Ordering::AcqRel);
        self.diagnostic_emitted = true;
        let count = std::mem::take(&mut self.refused);
        Some((
            AuditLease {
                global: self.pending.clone(),
                uid: None,
                diagnostic: Some(self.diagnostic.clone()),
            },
            count,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> DaemonConfig {
        DaemonConfig::from_toml(
            include_str!("../../../config/sigrund.toml.example")
                .replace(
                    "<strict-padded-base64-32-byte-ed25519-key>",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                )
                .as_bytes(),
        )
        .unwrap()
    }
    #[test]
    fn rate_windows_do_not_refund_or_erase_audit_debt() {
        let mut c = config();
        c.request_admissions_per_uid = 2;
        c.request_admissions_global = 3;
        let now = Instant::now();
        let mut a = Admission::new(&c, now);
        let first = a.admit(1, &c, now).unwrap();
        drop(a.admit(1, &c, now).unwrap());
        assert!(a.admit(1, &c, now).is_none());
        drop(a.admit(2, &c, now).unwrap());
        assert!(a.admit(3, &c, now).is_none());
        let later = now + std::time::Duration::from_secs(60);
        c.max_pending_audits_per_uid = 1;
        assert!(a.admit(1, &c, later).is_none());
        drop(a.admit(2, &c, later).unwrap());
        drop(first);
        drop(a.admit(1, &c, later).unwrap());
        assert_eq!(a.pending.load(Ordering::Acquire), 0);
    }
    #[test]
    fn global_capacity_reserves_diagnostics_and_survives_reload_and_rollover() {
        let mut c = config();
        c.max_pending_audits_global = 3;
        c.max_pending_audits_per_uid = 2;
        let now = Instant::now();
        let mut a = Admission::new(&c, now);
        let first = a.admit(1, &c, now).unwrap();
        let second = a.admit(2, &c, now).unwrap();
        assert!(a.admit(3, &c, now).is_none());
        let (diagnostic, count) = a.diagnostic(now, false).unwrap();
        assert_eq!(count, 1);
        assert!(a.diagnostic(now, false).is_none());
        c.max_pending_audits_global = 2;
        c.max_pending_audits_per_uid = 1;
        let later = now + std::time::Duration::from_secs(60);
        assert!(a.admit(3, &c, later).is_none());
        drop(first);
        assert!(a.admit(3, &c, later).is_none());
        drop(second);
        drop(a.admit(3, &c, later).unwrap());
        drop(diagnostic);
        assert_eq!(a.pending.load(Ordering::Acquire), 0);
    }
    #[test]
    fn bounded_uid_table_and_global_window() {
        let mut c = config();
        c.request_admissions_global = 4096;
        let now = Instant::now();
        let mut a = Admission::new(&c, now);
        for uid in 0..4096 {
            drop(a.admit(uid, &c, now).unwrap());
        }
        assert_eq!(a.uids.len(), 4096);
        assert!(a.admit(4096, &c, now).is_none());
        let later = now + std::time::Duration::from_secs(60);
        drop(a.admit(4096, &c, later).unwrap());
        assert_eq!(a.uids.len(), 1);
        a.refused = u64::MAX;
        a.refuse();
        assert_eq!(a.refused, u64::MAX);
    }
}
