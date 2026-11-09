//! Bounded off-loop cgroup and clone operations. All completions return owners.
use crate::{
    execution::{ChildProcess, NamespaceLauncher, NamespaceTarget, PreparedChild, Spawned},
    sequencer::CommittedJob,
    startup::{CgroupLayout, JobCgroup},
};
use std::{
    io,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, SyncSender},
    },
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) struct PreparedJob {
    pub job: CommittedJob,
    pub cgroup: Option<JobCgroup>,
    pub(crate) inherited_target_fds: Option<sigrund_core::host_budget::Reservation>,
    pub(crate) namespace_resources: Option<(
        sigrund_core::host_budget::Reservation,
        sigrund_core::host_budget::Reservation,
    )>,
}
pub(crate) enum Task {
    Prepare(CommittedJob),
    Spawn(PreparedJob),
    Cleanup(PreparedJob),
    VerifyExec(PreparedJob, i32, std::time::Instant),
}
pub(crate) enum SpawnOutcome {
    Prepared {
        owner: Box<PreparedJob>,
        failure: Option<String>,
    },
    Launched {
        owner: Box<PreparedJob>,
        launcher: NamespaceLauncher,
    },
    Spawned {
        owner: Box<PreparedJob>,
        child: io::Result<ChildProcess>,
    },
    Cleaned(Box<CommittedJob>),
    ExecVerified {
        owner: Box<PreparedJob>,
        result: io::Result<serde_json::Value>,
    },
    Signal {
        token: u64,
        signal: i32,
    },
    ControlLost(u64),
    Fatal(String),
}
#[derive(Clone)]
pub(crate) struct Notifier {
    completed: SyncSender<SpawnOutcome>,
    wake: Arc<OwnedFd>,
}
impl Notifier {
    pub fn send(&self, outcome: SpawnOutcome) {
        // At most one outstanding task per admitted job; control traffic uses
        // try_send below. Losing an owned completion is an internal fatal error.
        if self.completed.send(outcome).is_err() {
            std::process::abort();
        }
        wake_coordinator(self.wake.as_raw_fd());
    }
    pub fn control(&self, outcome: SpawnOutcome) -> bool {
        if self.completed.try_send(outcome).is_err() {
            return false;
        }
        wake_coordinator(self.wake.as_raw_fd());
        true
    }
}
pub(crate) struct JobSupervisor {
    sender: SyncSender<Task>,
    completed: Receiver<SpawnOutcome>,
    notifier: Notifier,
}
impl JobSupervisor {
    pub fn new(layout: Option<CgroupLayout>, capacity: usize) -> io::Result<Self> {
        Self::with_operation(layout, capacity, prepare_job)
    }
    pub fn with_operation(
        layout: Option<CgroupLayout>,
        capacity: usize,
        operation: impl Fn(Option<&CgroupLayout>, &CommittedJob) -> (Option<JobCgroup>, String)
        + Send
        + Sync
        + 'static,
    ) -> io::Result<Self> {
        if capacity == 0 || capacity > 16 {
            return Err(io::Error::other("invalid job executor capacity"));
        }
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let wake = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
        let (sender, tasks) = mpsc::sync_channel::<Task>(capacity);
        let (completed, receiver) = mpsc::sync_channel(capacity * 8);
        let notifier = Notifier { completed, wake };
        {
            let tasks = Arc::new(Mutex::new(tasks));
            let operation = Arc::new(operation);
            for slot in 0..capacity {
                let tasks = tasks.clone();
                let notifier = notifier.clone();
                let layout = layout.clone();
                let operation = operation.clone();
                std::thread::Builder::new()
                    .name(format!("job-owner-{slot}"))
                    .spawn(move || {
                        loop {
                            let task = tasks.lock().expect("job receiver").recv();
                            let Ok(task) = task else { break };
                            match task {
                                Task::VerifyExec(owner, pid, deadline) => {
                                    let request = owner.job.lease.request();
                                    let check = || {
                                        request.check()?;
                                        if owner
                                            .job
                                            .lifecycle
                                            .cancelled
                                            .load(std::sync::atomic::Ordering::Acquire)
                                        {
                                            return Err(io::ErrorKind::Interrupted.into());
                                        }
                                        if std::time::Instant::now() >= deadline {
                                            return Err(io::ErrorKind::TimedOut.into());
                                        }
                                        Ok(())
                                    };
                                    let result = eligible(&owner.job).and_then(|()| {
                                        let mut credentials = owner
                                            .job
                                            .authorized
                                            .warrant
                                            .warrant()
                                            .execution_context
                                            .clone();
                                        if let Some(process) = &request.process {
                                            credentials.target_uid =
                                                process.evidence.credentials.host_uid;
                                            credentials.target_gid =
                                                process.evidence.credentials.host_gid;
                                            credentials.supplementary_gids =
                                                process.evidence.credentials.host_groups.clone();
                                        }
                                        request
                                            .snapshots
                                            .as_ref()
                                            .expect("executable owner")
                                            .executable
                                            .verify_exec_checked(pid, &credentials, check)?;
                                        if request.process.is_some() {
                                            crate::process_request::verify_execution(
                                                request,
                                                pid,
                                                owner.cgroup.as_ref().expect("job placement"),
                                                check,
                                            )
                                        } else {
                                            Ok(serde_json::Value::Null)
                                        }
                                    });
                                    notifier.send(SpawnOutcome::ExecVerified {
                                        owner: Box::new(owner),
                                        result,
                                    });
                                }
                                Task::Prepare(job) => {
                                    let (cgroup, message) = operation(layout.as_ref(), &job);
                                    let failure = (!message.is_empty()).then_some(message);
                                    notifier.send(SpawnOutcome::Prepared {
                                        owner: Box::new(PreparedJob {
                                            job,
                                            cgroup,
                                            inherited_target_fds: None,
                                            namespace_resources: None,
                                        }),
                                        failure,
                                    });
                                }
                                Task::Spawn(mut owner) => {
                                    let child = spawn(&mut owner);
                                    match child {
                                        Ok(Spawned::Launcher(launcher)) => {
                                            notifier.send(SpawnOutcome::Launched {
                                                owner: Box::new(owner),
                                                launcher,
                                            })
                                        }
                                        other => notifier.send(SpawnOutcome::Spawned {
                                            owner: Box::new(owner),
                                            child: other.map(|child| match child {
                                                Spawned::Child(child) => child,
                                                Spawned::Launcher(_) => unreachable!(),
                                            }),
                                        }),
                                    }
                                }
                                Task::Cleanup(mut owner) => {
                                    if let Some(cgroup) = owner.cgroup.take()
                                        && let Err((cgroup, error)) = cgroup.cleanup()
                                    {
                                        notifier.send(SpawnOutcome::Fatal(format!(
                                            "job cleanup failed: {error}"
                                        )));
                                        // Failed cleanup must retain every request/quota owner.
                                        let _retained = (cgroup, owner);
                                        loop {
                                            std::thread::park();
                                        }
                                    }
                                    notifier.send(SpawnOutcome::Cleaned(Box::new(owner.job)));
                                }
                            }
                        }
                    })?;
            }
        }
        Ok(Self {
            sender,
            completed: receiver,
            notifier,
        })
    }
    pub fn notifier(&self) -> Notifier {
        self.notifier.clone()
    }
    pub fn fd(&self) -> RawFd {
        self.notifier.wake.as_raw_fd()
    }
    pub fn submit(&self, job: CommittedJob) -> Result<(), Box<CommittedJob>> {
        self.send(Task::Prepare(job)).map_err(|task| {
            let Task::Prepare(job) = *task else {
                unreachable!()
            };
            Box::new(job)
        })
    }
    pub fn send(&self, task: Task) -> Result<(), Box<Task>> {
        self.sender.try_send(task).map_err(|e| {
            Box::new(match e {
                mpsc::TrySendError::Full(task) | mpsc::TrySendError::Disconnected(task) => task,
            })
        })
    }
    pub fn drain(&self) -> Vec<SpawnOutcome> {
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
pub(crate) fn eligible(job: &CommittedJob) -> io::Result<()> {
    eligible_for_release(job)?;
    let request = job.lease.request();
    if let Some(process) = &request.process {
        if !process
            .verified
            .as_ref()
            .is_some_and(|proof| proof.matches(request))
        {
            return Err(io::Error::other(
                "namespace execution plan differs from authorization",
            ));
        }
        return process.lease.revalidate();
    }
    let bundle = request
        .host_bundle
        .as_ref()
        .ok_or_else(|| io::Error::other("missing committed binding"))?;
    request
        .host_lease
        .as_ref()
        .ok_or_else(|| io::Error::other("missing committed target lease"))?
        .verify(bundle)?;
    job.authorized
        .warrant
        .warrant()
        .verify_bundle(bundle)
        .map_err(io::Error::other)
}

/// Coordinator checks must never acquire the target budget or inspect files.
pub(crate) fn eligible_for_release(job: &CommittedJob) -> io::Result<()> {
    use std::sync::atomic::Ordering;
    if job.lifecycle.cancelled.load(Ordering::Acquire)
        || !crate::sequencer::connection_live(job.control)
    {
        return Err(io::Error::other("committed job cancelled before spawn"));
    }
    job.lease.request().check()?;
    let w = job.authorized.warrant.warrant();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    if now < w.policy.not_before as u64 || w.policy.not_after.is_some_and(|end| now > end as u64) {
        return Err(io::Error::other("warrant expired before spawn"));
    }
    Ok(())
}
fn spawn(owner: &mut PreparedJob) -> io::Result<Spawned> {
    let request = owner.job.lease.request();
    if let Some(process) = &request.process {
        let parent = process
            .lease
            .reserve_resources(sigrund_core::host_budget::Charge {
                target_fds: 8,
                ..Default::default()
            })?;
        let child = process
            .lease
            .reserve_child_resources(sigrund_core::host_budget::Charge {
                target_fds: 18,
                ..Default::default()
            })?;
        owner.namespace_resources = Some((parent, child));
    }
    let mut command = PreparedChild::new(
        owner.job.authorized.warrant.warrant(),
        owner.job.authorized.envp.clone(),
    )?;
    let snapshot = request
        .snapshots
        .as_ref()
        .ok_or_else(|| io::Error::other("missing sealed snapshots"))?;
    let input = snapshot
        .stdin
        .as_ref()
        .map(|s| s.as_fd().as_raw_fd())
        .or_else(|| {
            request
                .prepared
                .as_ref()
                .and_then(|p| p.null_stdin.as_ref().map(AsRawFd::as_raw_fd))
        })
        .ok_or_else(|| io::Error::other("missing stdin"))?;
    let n = request.rights.len();
    if n < 2 {
        return Err(io::Error::other("missing output rights"));
    }
    eligible(&owner.job)?;
    let operation = || {
        if owner
            .job
            .lifecycle
            .cancelled
            .load(std::sync::atomic::Ordering::Acquire)
            || !crate::sequencer::connection_live(owner.job.control)
        {
            return Err(io::ErrorKind::Interrupted.into());
        }
        request.check()?;
        let fds = [
            input,
            request.rights[n - 2].as_raw_fd(),
            request.rights[n - 1].as_raw_fd(),
            snapshot.executable.as_fd().as_raw_fd(),
        ];
        if let Some(process) = &request.process {
            command
                .spawn_namespace(
                    owner.cgroup.as_ref().expect("prepared cgroup").fd(),
                    fds,
                    NamespaceTarget {
                        namespaces: process.lease.namespace_files()?,
                        root: process.lease.root().as_raw_fd(),
                        cwd: process.cwd.as_raw_fd(),
                    },
                )
                .map(Spawned::Launcher)
        } else {
            command
                .spawn_checkpoint(
                    owner.cgroup.as_ref().expect("prepared cgroup").fd(),
                    fds,
                    snapshot.executable.needs_checkpoint(),
                )
                .map(Spawned::Child)
        }
    };
    let (child, copies) = if let Some(process) = &request.process {
        let (result, copies) = process.lease.with_fd_copies(operation)?;
        (result?, copies)
    } else {
        request
            .host_lease
            .as_ref()
            .expect("validated host owner")
            .with_retained_fd_copies(operation)?
    };
    owner.inherited_target_fds = Some(copies);
    Ok(child)
}
pub(crate) fn prepare_job(
    layout: Option<&CgroupLayout>,
    job: &CommittedJob,
) -> (Option<JobCgroup>, String) {
    if let Err(error) = eligible(job) {
        return (None, error.to_string());
    }
    if job.lifecycle.state().0 != sigrund_core::lifecycle::Phase::Approved {
        return (None, "cancelled job preparation".into());
    }
    if job.gid != job.authorized.warrant.warrant().requester_gid
        || !job.authorized.signer_ids.contains(&job.signer_id)
    {
        return (None, "committed job identity mismatch".into());
    }
    let Some(layout) = layout else {
        return (None, "execution disabled".into());
    };
    let p = &job.lease.request().policy;
    let (memory, swap, pids) = if let Some(process) = &job.lease.request().process {
        let profile = process.lease.constraints();
        if profile.memory_max > p.job_memory_max_bytes
            || profile.memory_swap_max > p.job_memory_swap_max_bytes
            || u64::from(profile.pids_max) > p.job_pids_max
        {
            return (None, "namespace limits exceed daemon ceilings".into());
        }
        (
            profile.memory_max,
            profile.memory_swap_max,
            u64::from(profile.pids_max),
        )
    } else {
        (
            p.job_memory_max_bytes,
            p.job_memory_swap_max_bytes,
            p.job_pids_max,
        )
    };
    match layout.create_job(&job.exec_id, memory, swap, pids) {
        Ok(cgroup) => (Some(cgroup), String::new()),
        Err(error) => (
            error.owner,
            format!("job cgroup setup failed: {}", error.error),
        ),
    }
}
