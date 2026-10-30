//! Worker-only streaming snapshots and aggregate RAM ownership. Quotas remain
//! attached to the sealed bytes until their owning snapshot is destroyed.
use crate::{memfd, transport::invalid};
use sigrund_core::{
    config::DaemonConfig,
    snapshot::{SnapshotDigest, copy_stream},
};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Usage {
    global: u64,
    by_uid: HashMap<u32, u64>,
}
#[derive(Clone, Default)]
pub struct SnapshotBudget(Arc<Mutex<Usage>>);
impl SnapshotBudget {
    fn reserve(&self, uid: u32, bytes: u64, config: &DaemonConfig) -> io::Result<Reservation> {
        let mut usage = self
            .0
            .lock()
            .map_err(|_| invalid("snapshot budget poisoned"))?;
        let per_uid = usage.by_uid.get(&uid).copied().unwrap_or(0);
        let global = usage
            .global
            .checked_add(bytes)
            .filter(|total| *total <= config.snapshot_ram_global_bytes.min(536_870_912));
        let per_uid = per_uid
            .checked_add(bytes)
            .filter(|total| *total <= config.snapshot_ram_per_uid_bytes.min(134_217_728));
        let (Some(global), Some(per_uid)) = (global, per_uid) else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "snapshot RAM quota exhausted",
            ));
        };
        usage.global = global;
        usage.by_uid.insert(uid, per_uid);
        Ok(Reservation {
            budget: self.clone(),
            uid,
            bytes,
        })
    }
    pub fn usage(&self, uid: u32) -> (u64, u64) {
        let usage = self.0.lock().expect("snapshot budget poisoned");
        (usage.global, usage.by_uid.get(&uid).copied().unwrap_or(0))
    }
}
struct Reservation {
    budget: SnapshotBudget,
    uid: u32,
    bytes: u64,
}
impl Reservation {
    fn trim(&mut self, bytes: u64) {
        assert!(bytes <= self.bytes);
        if bytes == self.bytes {
            return;
        }
        let mut usage = self.budget.0.lock().expect("snapshot budget poisoned");
        let released = self.bytes - bytes;
        usage.global -= released;
        *usage.by_uid.get_mut(&self.uid).expect("live reservation") -= released;
        self.bytes = bytes;
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.trim(0);
        let mut usage = self.budget.0.lock().expect("snapshot budget poisoned");
        if usage.by_uid.get(&self.uid) == Some(&0) {
            usage.by_uid.remove(&self.uid);
        }
    }
}

pub struct SealedSnapshot {
    fd: OwnedFd,
    pub digest: SnapshotDigest,
    _reservation: Reservation,
}
impl AsFd for SealedSnapshot {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

// Destruction order is significant: potentially blocking source close, memfd
// close, then quota release. Construct this owner before creating the memfd.
struct SnapshotWork {
    source: Option<File>,
    destination: Option<File>,
    reservation: Option<Reservation>,
}

pub fn executable(
    source: File,
    budget: &SnapshotBudget,
    uid: u32,
    config: &DaemonConfig,
    check: impl Fn() -> io::Result<()>,
) -> io::Result<SealedSnapshot> {
    check()?;
    let metadata = source.metadata()?;
    check()?;
    let size = metadata.len();
    if !metadata.is_file() || size == 0 || size > config.max_executable_bytes.min(67_108_864) {
        return Err(invalid("invalid executable snapshot source size or type"));
    }
    snapshot(source, budget, uid, config, Some(size), check)
}

pub fn stdin(
    source: File,
    budget: &SnapshotBudget,
    uid: u32,
    config: &DaemonConfig,
    check: impl Fn() -> io::Result<()>,
) -> io::Result<SealedSnapshot> {
    snapshot(source, budget, uid, config, None, check)
}
fn snapshot(
    source: File,
    budget: &SnapshotBudget,
    uid: u32,
    config: &DaemonConfig,
    expected: Option<u64>,
    check: impl Fn() -> io::Result<()>,
) -> io::Result<SealedSnapshot> {
    check()?;
    let maximum = expected.unwrap_or(config.max_stdin_bytes.min(16_777_216));
    let reservation = budget.reserve(uid, maximum, config)?;
    let mut work = SnapshotWork {
        source: Some(source),
        destination: None,
        reservation: Some(reservation),
    };
    let executable = expected.is_some();
    work.destination = Some(memfd::create(
        if executable {
            "sigrun-executable"
        } else {
            "sigrun-stdin"
        },
        executable,
    )?);
    let digest = copy_stream(
        work.source.as_mut().expect("source"),
        work.destination.as_mut().expect("destination"),
        expected,
        maximum,
        &check,
    )?;
    check()?;
    if let Some(size) = expected {
        if work.source.as_ref().expect("source").metadata()?.len() != size {
            return Err(invalid("executable size changed during snapshot"));
        }
        check()?;
        let destination = work.destination.as_mut().expect("destination");
        destination.seek(SeekFrom::Start(0))?;
        let mut magic = [0; 4];
        destination.read_exact(&mut magic)?;
        if &magic != b"\x7fELF" {
            return Err(invalid("MVP executable is not ELF"));
        }
    }
    check()?;
    let fd = memfd::seal(
        work.destination.take().expect("destination"),
        if executable { 0o111 } else { 0o400 },
    )?;
    // Source close may block: keep the RAM and I/O reservations until it ends.
    drop(work.source.take());
    check()?;
    let mut reservation = work.reservation.take().expect("reservation");
    reservation.trim(digest.bytes);
    Ok(SealedSnapshot {
        fd,
        digest,
        _reservation: reservation,
    })
}
