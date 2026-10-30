//! Fixed, generation-scoped workers for potentially blocking FD metadata.
//! Reservations survive client teardown until the task has closed its FDs.
use std::{
    collections::HashMap,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    time::Instant,
};

use sigrund_core::{config::DaemonConfig, protocol::ClientHello};

use crate::transport::{invalid, validate_stdio_checked};

/// The connection owns cancellation, not the descriptors or reservation.
pub(crate) struct ValidationHandle(Arc<AtomicBool>);

impl Drop for ValidationHandle {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct Task {
    token: u64,
    hello: ClientHello,
    rights: Vec<OwnedFd>,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl Task {
    fn execute(self) -> Completion {
        let result = catch_unwind(AssertUnwindSafe(|| {
            validate_stdio_checked(&self.hello, &self.rights, || {
                if self.cancelled.load(Ordering::Acquire) {
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "validation cancelled",
                    ))
                } else if Instant::now() >= self.deadline {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "validation deadline expired",
                    ))
                } else {
                    Ok(())
                }
            })
        }))
        .unwrap_or_else(|_| Err(invalid("descriptor validation worker panicked")));
        let token = self.token;
        // close() can itself block. Cleanup precedes completion publication;
        // the event loop must not reclaim quotas while any task FD is held.
        drop(self);
        Completion { token, result }
    }
}

pub(crate) struct Completion {
    pub token: u64,
    pub result: io::Result<()>,
}

struct Reservation {
    uid: u32,
    slot: usize,
    cancelled: Arc<AtomicBool>,
}

pub(crate) struct MetadataWorkers {
    senders: Vec<SyncSender<Task>>,
    completions: Receiver<Completion>,
    reservations: HashMap<u64, Reservation>,
    wake: Arc<OwnedFd>,
    per_uid: usize,
}

impl MetadataWorkers {
    pub fn new(config: &DaemonConfig) -> io::Result<Self> {
        let count = config.max_io_workers_global as usize;
        let raw = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let wake = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
        let (completed, completions) = sync_channel(count);
        let mut senders = Vec::with_capacity(count);
        for slot in 0..count {
            let (sender, tasks) = sync_channel::<Task>(1);
            let completed = completed.clone();
            let wake = wake.clone();
            // Do not join blocked workers on shutdown or create replacements.
            // Dropping the sender stops each worker after its current task.
            std::thread::Builder::new()
                .name(format!("fd-metadata-{slot}"))
                .spawn(move || {
                    for task in tasks {
                        let result = task.execute();
                        if completed.send(result).is_err() {
                            break;
                        }
                        let one = 1u64;
                        loop {
                            let result = unsafe {
                                libc::write(wake.as_raw_fd(), (&one as *const u64).cast(), 8)
                            };
                            if result >= 0
                                || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                            {
                                break;
                            }
                        }
                    }
                })?;
            senders.push(sender);
        }
        Ok(Self {
            senders,
            completions,
            reservations: HashMap::new(),
            wake,
            per_uid: config.max_io_workers_per_uid as usize,
        })
    }

    pub fn fd(&self) -> i32 {
        self.wake.as_raw_fd()
    }

    pub fn submit(
        &mut self,
        token: u64,
        uid: u32,
        hello: ClientHello,
        rights: Vec<OwnedFd>,
        deadline: Instant,
    ) -> io::Result<ValidationHandle> {
        if self
            .reservations
            .values()
            .filter(|task| task.uid == uid)
            .count()
            >= self.per_uid
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "per-UID I/O worker quota exhausted",
            ));
        }
        let slot = (0..self.senders.len())
            .find(|slot| !self.reservations.values().any(|task| task.slot == *slot))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "global I/O worker quota exhausted",
                )
            })?;
        let cancelled = Arc::new(AtomicBool::new(false));
        self.senders[slot]
            .try_send(Task {
                token,
                hello,
                rights,
                deadline,
                cancelled: cancelled.clone(),
            })
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "I/O worker unavailable"))?;
        self.reservations.insert(
            token,
            Reservation {
                uid,
                slot,
                cancelled: cancelled.clone(),
            },
        );
        Ok(ValidationHandle(cancelled))
    }

    pub fn drain(&mut self) -> Vec<Completion> {
        let mut value = 0u64;
        loop {
            let result = unsafe { libc::read(self.fd(), (&mut value as *mut u64).cast(), 8) };
            if result >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
        let mut results = Vec::new();
        while let Ok(result) = self.completions.try_recv() {
            self.reservations.remove(&result.token);
            results.push(result);
        }
        results
    }
}

impl Drop for MetadataWorkers {
    fn drop(&mut self) {
        for reservation in self.reservations.values() {
            reservation.cancelled.store(true, Ordering::Release);
        }
    }
}
