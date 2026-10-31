//! Pinned-descriptor capacity checks, used only before listening or by the
//! durable executor. A pressure closure is sticky until verified restart.
use sigrund_core::config::DaemonConfig;
use std::{
    fs::File,
    io,
    mem::MaybeUninit,
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub(crate) struct StoragePressure {
    log: File,
    filesystems: Vec<File>,
    pub closed: Arc<AtomicBool>,
}
impl StoragePressure {
    pub fn new(log: File, filesystems: Vec<File>) -> Self {
        Self {
            log,
            filesystems,
            closed: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn check(&self, config: &DaemonConfig) -> io::Result<bool> {
        let result = (|| {
            let mut healthy = self.log.metadata()?.len() < config.audit_log_high_water_bytes;
            for file in &self.filesystems {
                let mut stats = MaybeUninit::<libc::statvfs>::uninit();
                if unsafe { libc::fstatvfs(file.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                let stats = unsafe { stats.assume_init() };
                let available = available_bytes(stats.f_bavail, stats.f_frsize)?;
                healthy &= available >= config.audit_min_free_bytes;
            }
            Ok(healthy)
        })();
        if !matches!(result, Ok(true)) {
            self.closed.store(true, Ordering::Release);
        }
        result.map(|healthy| healthy && !self.closed.load(Ordering::Acquire))
    }

    /// Recheck after an append has completed.  The record that just crossed
    /// the threshold belongs to an existing owner and is allowed to persist;
    /// this call latches pressure so no new request can be admitted.
    pub fn latch_after_append(&self, config: &DaemonConfig) -> io::Result<()> {
        let _ = self.check(config)?;
        Ok(())
    }
}
fn available_bytes(blocks: u64, size: u64) -> io::Result<u64> {
    blocks
        .checked_mul(size)
        .ok_or_else(|| io::Error::other("filesystem capacity overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_arithmetic_is_checked() {
        assert_eq!(available_bytes(10, 4096).unwrap(), 40960);
        assert!(available_bytes(u64::MAX, 4096).is_err());
    }
    #[test]
    fn threshold_is_sticky_and_all_filesystems_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let log = File::create(&path).unwrap();
        let pressure = StoragePressure::new(
            log.try_clone().unwrap(),
            vec![File::open(dir.path()).unwrap()],
        );
        let mut config = DaemonConfig::from_toml(
            include_str!("../../../config/sigrund.toml.example")
                .replace(
                    "<strict-padded-base64-32-byte-ed25519-key>",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                )
                .as_bytes(),
        )
        .unwrap();
        assert!(pressure.check(&config).unwrap());
        config.audit_min_free_bytes = u64::MAX;
        assert!(!pressure.check(&config).unwrap());
        config.audit_min_free_bytes = 65536;
        assert!(!pressure.check(&config).unwrap());
        let pressure = StoragePressure::new(log.try_clone().unwrap(), vec![]);
        config.audit_log_high_water_bytes = 65536;
        log.set_len(65536).unwrap();
        assert!(!pressure.check(&config).unwrap());
        log.set_len(0).unwrap();
        assert!(!pressure.check(&config).unwrap());
    }

    #[test]
    fn append_crossing_high_water_latches_admission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut log = File::create(&path).unwrap();
        let pressure = StoragePressure::new(
            log.try_clone().unwrap(),
            vec![File::open(dir.path()).unwrap()],
        );
        let mut config = DaemonConfig::from_toml(
            include_str!("../../../config/sigrund.toml.example")
                .replace(
                    "<strict-padded-base64-32-byte-ed25519-key>",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                )
                .as_bytes(),
        )
        .unwrap();
        config.audit_log_high_water_bytes = 1;
        assert!(pressure.check(&config).unwrap());
        use std::io::Write;
        log.write_all(b"x").unwrap();
        log.sync_all().unwrap();
        pressure.latch_after_append(&config).unwrap();
        // The threshold check closes the admission flag even though the
        // owned append completed successfully.
        assert!(pressure.closed.load(Ordering::Acquire));
        assert!(!pressure.check(&config).unwrap());
    }
}
