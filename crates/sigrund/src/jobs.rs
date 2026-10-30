//! Bounded preparation and cleanup of committed jobs before clone admission.
use crate::{sequencer::CommittedJob, startup::CgroupLayout};
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

/// One bounded owner for cgroup operations. The coordinator never performs
/// cgroupfs I/O. Until Phase 5C installs its reaper and shutdown protocol this
/// stage prepares and disposes an empty cgroup, then explicitly aborts: it
/// cannot invoke the clone primitive or publish readiness.
pub(crate) struct JobSupervisor {
    sender: std::sync::mpsc::SyncSender<CommittedJob>,
    completed: std::sync::mpsc::Receiver<SpawnOutcome>,
    wake: std::sync::Arc<OwnedFd>,
}

pub(crate) enum SpawnOutcome {
    Failed {
        job: Box<CommittedJob>,
        message: String,
    },
    Fatal(String),
}

impl JobSupervisor {
    pub(crate) fn new(layout: Option<CgroupLayout>, capacity: usize) -> io::Result<Self> {
        Self::with_operation(layout, capacity, prepare_job)
    }
    pub(crate) fn with_operation(
        layout: Option<CgroupLayout>,
        capacity: usize,
        operation: impl Fn(
            Option<&CgroupLayout>,
            &CommittedJob,
        ) -> (Option<crate::startup::JobCgroup>, String)
        + Send
        + 'static,
    ) -> io::Result<Self> {
        use std::sync::{Arc, mpsc::sync_channel};
        if capacity == 0 || capacity > 16 {
            return Err(io::Error::other("invalid job preparation capacity"));
        }
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let wake = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
        let (sender, tasks) = sync_channel::<CommittedJob>(capacity);
        let (finished, completed) = sync_channel(capacity);
        if layout.is_none() {
            return Ok(Self {
                sender,
                completed,
                wake,
            });
        }
        let signal = wake.clone();
        std::thread::Builder::new()
            .name("job-cgroup-owner".into())
            .spawn(move || {
                for job in tasks {
                    let (cgroup, message) = operation(layout.as_ref(), &job);
                    if let Some(cgroup) = cgroup
                        && let Err((owner, error)) = cgroup.cleanup()
                    {
                        let _ = finished
                            .send(SpawnOutcome::Fatal(format!("job cleanup failed: {error}")));
                        wake_coordinator(signal.as_raw_fd());
                        // A failed cleanup keeps all original owners and quota.
                        // It never releases capacity to replacement work.
                        let _retained = (owner, job);
                        loop {
                            std::thread::park();
                        }
                    }
                    if finished
                        .send(SpawnOutcome::Failed {
                            job: Box::new(job),
                            message,
                        })
                        .is_err()
                    {
                        break;
                    }
                    wake_coordinator(signal.as_raw_fd());
                }
            })?;
        Ok(Self {
            sender,
            completed,
            wake,
        })
    }
    pub(crate) fn fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }
    pub(crate) fn submit(&self, job: CommittedJob) -> Result<(), Box<CommittedJob>> {
        self.sender.try_send(job).map_err(|error| {
            Box::new(match error {
                std::sync::mpsc::TrySendError::Full(job)
                | std::sync::mpsc::TrySendError::Disconnected(job) => job,
            })
        })
    }
    pub(crate) fn drain(&self) -> Vec<SpawnOutcome> {
        let mut count = 0u64;
        loop {
            if unsafe { libc::read(self.fd(), (&mut count as *mut u64).cast(), 8) } >= 0
                || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
            {
                break;
            }
        }
        self.completed.try_iter().collect()
    }
}
fn wake_coordinator(fd: RawFd) {
    let one = 1u64;
    loop {
        if unsafe { libc::write(fd, (&one as *const u64).cast(), 8) } >= 0
            || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            break;
        }
    }
}
pub(crate) fn prepare_job(
    layout: Option<&CgroupLayout>,
    job: &CommittedJob,
) -> (Option<crate::startup::JobCgroup>, String) {
    use std::sync::atomic::Ordering;
    let request = job.lease.request();
    let warrant = job.authorized.warrant.warrant();
    if job.lifecycle.cancelled.load(Ordering::Acquire)
        || !crate::sequencer::connection_live(job.control)
        || job.lifecycle.state().0 != sigrund_core::lifecycle::Phase::Committed
    {
        return (
            None,
            "committed job cancelled before cgroup preparation".into(),
        );
    }
    if job.gid != warrant.requester_gid || !job.authorized.signer_ids.contains(&job.signer_id) {
        return (None, "committed job identity mismatch".into());
    }
    let Some(layout) = layout else {
        return (None, "execution disabled".into());
    };
    match layout.create_job(
        &job.exec_id,
        request.policy.job_memory_max_bytes,
        request.policy.job_memory_swap_max_bytes,
        request.policy.job_pids_max,
    ) {
        Ok(cgroup) => (
            Some(cgroup),
            concat!(
                "child launch awaits Phase 5C reaper and shutdown integration; ",
                "one-time grant remains consumed"
            )
            .into(),
        ),
        Err(error) => (
            error.owner,
            format!("job cgroup setup failed: {}", error.error),
        ),
    }
}
