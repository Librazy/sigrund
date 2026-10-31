//! Coordinator-owned execution lifecycle. No cgroup I/O or caller-FD disposal.
use crate::{
    execution::{Handshake, SyncOutcome},
    jobs::{JobSupervisor, PreparedJob, SpawnOutcome, Task},
    reaper::{ChildExit, Reaper},
    sequencer::{self, CommittedJob},
    transport::{ControlReader, invalid},
};
use sigrund_core::{
    lifecycle::{Decision, Phase},
    protocol,
};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    os::fd::{AsRawFd, OwnedFd, RawFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::SyncSender,
    },
    time::Instant,
};

pub(crate) const SYNC_TAG: u64 = 1 << 63;
pub(crate) const PID_TAG: u64 = 1 << 62;
pub(crate) enum Notice {
    Ready(u64),
    Failed(u64, String),
    Exit(u64, protocol::ChildExit),
}
struct Active {
    owner: Option<PreparedJob>,
    cleaned: Option<Box<CommittedJob>>,
    lifecycle: Arc<sigrund_core::lifecycle::Lifecycle>,
    fields: serde_json::Value,
    limit: usize,
    pid: Option<i32>,
    spawn_reserved: bool,
    sync: Option<OwnedFd>,
    deadline: Option<Instant>,
    handshake: Handshake,
    outcome: Option<SyncOutcome>,
    exit: Option<ChildExit>,
    failure: Option<String>,
    task: bool,
    cleanup: bool,
    ready_audited: bool,
    audit_pending: bool,
    final_pending: bool,
    stop_control: Arc<AtomicBool>,
    monitoring: bool,
    control_deadline: Arc<Mutex<Option<Instant>>>,
}
pub(crate) struct Execution {
    pub supervisor: JobSupervisor,
    reaper: Reaper,
    jobs: BTreeMap<u64, Active>,
    ready: VecDeque<u64>,
    durable: SyncSender<sequencer::Work>,
    stopping: bool,
    poisoned: bool,
}
impl Execution {
    pub fn new(supervisor: JobSupervisor, durable: SyncSender<sequencer::Work>) -> Self {
        Self {
            supervisor,
            reaper: Reaper::default(),
            jobs: BTreeMap::new(),
            ready: VecDeque::new(),
            durable,
            stopping: false,
            poisoned: false,
        }
    }
    pub fn is_idle(&self) -> bool {
        self.jobs.is_empty() && self.reaper.is_idle()
    }
    pub fn cancelled_connections(&self) -> Vec<u64> {
        self.jobs
            .iter()
            .filter_map(|(token, job)| {
                job.lifecycle
                    .cancelled
                    .load(Ordering::Acquire)
                    .then_some(*token)
            })
            .collect()
    }
    pub fn active(&self) -> bool {
        !self.jobs.is_empty()
    }
    pub fn shutdown(&mut self, poisoned: bool) {
        self.stopping = true;
        self.poisoned |= poisoned;
        for job in self.jobs.values() {
            job.lifecycle.cancel();
        }
    }
    pub fn submit(&mut self, job: CommittedJob) -> io::Result<()> {
        let token = job.token;
        let active = Active {
            lifecycle: job.lifecycle.clone(),
            fields: job.commit_fields.clone(),
            limit: job.lease.request().policy.audit_record_max_bytes as usize,
            owner: None,
            cleaned: None,
            pid: None,
            spawn_reserved: false,
            sync: None,
            deadline: None,
            handshake: Handshake::default(),
            outcome: None,
            exit: None,
            failure: None,
            task: true,
            cleanup: false,
            ready_audited: false,
            audit_pending: false,
            final_pending: false,
            stop_control: Arc::new(AtomicBool::new(false)),
            monitoring: false,
            control_deadline: Arc::new(Mutex::new(None)),
        };
        if self.stopping {
            job.lifecycle.cancel();
        }
        self.jobs.insert(token, active);
        if let Err(job) = self.supervisor.submit(job) {
            let active = self.jobs.get_mut(&token).unwrap();
            active.owner = Some(PreparedJob {
                job: *job,
                cgroup: None,
            });
            active.task = false;
            active.failure = Some("job executor unavailable after commit".into());
        }
        Ok(())
    }
    fn dispatch(&mut self, token: u64, task: Task) -> io::Result<()> {
        if let Err(task) = self.supervisor.send(task) {
            let owner = match *task {
                Task::Spawn(owner) | Task::Cleanup(owner) => owner,
                Task::Prepare(_) => unreachable!(),
            };
            self.jobs.get_mut(&token).unwrap().owner = Some(owner);
            return Err(invalid("reserved job executor capacity unavailable"));
        }
        self.jobs.get_mut(&token).unwrap().task = true;
        Ok(())
    }
    pub fn drain(&mut self, epoll: RawFd) -> io::Result<()> {
        let mut failure = None;
        for event in self.supervisor.drain() {
            let result = (|| -> io::Result<()> {
                match event {
                    SpawnOutcome::Prepared { owner, failure } => {
                        let token = owner.job.token;
                        let job = self.jobs.get_mut(&token).expect("prepared owner");
                        job.task = false;
                        job.owner = Some(*owner);
                        job.failure = failure;
                        self.ready.push_back(token);
                    }
                    SpawnOutcome::Spawned { owner, child } => {
                        let token = owner.job.token;
                        let job = self.jobs.get_mut(&token).expect("pending spawn");
                        job.task = false;
                        job.owner = Some(*owner);
                        match child {
                            Ok(child) => {
                                let pid = child.pid;
                                // Register before releasing the barrier, even during shutdown.
                                assert!(
                                    self.reaper
                                        .complete(token, Some((pid, child.pidfd)))
                                        .is_ok()
                                );
                                job.pid = Some(pid);
                                job.deadline = Some(child.deadline);
                                job.sync = Some(child.sync);
                                assert!(job.lifecycle.transition(Phase::Spawning, Phase::Running));
                                watch(
                                    epoll,
                                    job.sync.as_ref().unwrap().as_raw_fd(),
                                    token | SYNC_TAG,
                                )?;
                                watch(
                                    epoll,
                                    self.reaper.registered_fd(pid).unwrap(),
                                    token | PID_TAG,
                                )?;
                                if job.lifecycle.cancelled.load(Ordering::Acquire) {
                                    job.lifecycle.cancel();
                                }
                            }
                            Err(error) => {
                                assert!(self.reaper.complete(token, None).is_ok());
                                assert!(job.lifecycle.finish_spawn(
                                    if job.lifecycle.cancelled.load(Ordering::Acquire) {
                                        Decision::NoReply
                                    } else {
                                        Decision::Rejected
                                    }
                                ));
                                job.failure = Some(format!("child clone failed: {error}"));
                            }
                        }
                    }
                    SpawnOutcome::Cleaned(job) => {
                        let active = self.jobs.get_mut(&job.token).expect("cleanup owner");
                        active.task = false;
                        active.cleanup = true;
                        active.cleaned = Some(job);
                    }
                    SpawnOutcome::Signal { token, signal } => {
                        if let Some(job) = self.jobs.get(&token)
                            && let Some(pid) = job.pid
                            && self.reaper.registered_fd(pid).is_some()
                            && !job.lifecycle.cancelled.load(Ordering::Acquire)
                        {
                            unsafe {
                                libc::kill(-pid, signal);
                            }
                        }
                    }
                    SpawnOutcome::ControlLost(token) => {
                        if let Some(job) = self.jobs.get(&token) {
                            job.lifecycle.cancel();
                        }
                    }
                    SpawnOutcome::Fatal(message) => return Err(invalid(message)),
                }
                Ok(())
            })();
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
    pub fn recorded(&mut self, token: u64) -> Vec<Notice> {
        let Some(job) = self.jobs.get_mut(&token) else {
            return vec![];
        };
        job.audit_pending = false;
        if job.final_pending {
            let job = self.jobs.remove(&token).unwrap();
            if self.stopping || job.lifecycle.cancelled.load(Ordering::Acquire) {
                return vec![];
            }
            if job.outcome == Some(SyncOutcome::ReadyToExec) && job.ready_audited {
                vec![Notice::Exit(
                    token,
                    wire_exit(job.exit.expect("reaped primary")),
                )]
            } else {
                vec![Notice::Failed(
                    token,
                    format!(
                        "{}; authorization committed and one-time grant remains consumed",
                        job.failure.unwrap_or_else(|| "child setup failed".into())
                    ),
                )]
            }
        } else {
            job.ready_audited = true;
            if !self.stopping && job.lifecycle.publish_ready() {
                vec![Notice::Ready(token)]
            } else {
                vec![]
            }
        }
    }
    /// Called only once the complete readiness decision has reached the socket.
    pub fn monitor(&mut self, token: u64) -> io::Result<()> {
        let Some(job) = self.jobs.get_mut(&token) else {
            return Ok(());
        };
        if job.monitoring
            || job.cleanup
            || job.task
            || job.lifecycle.cancelled.load(Ordering::Acquire)
        {
            return Ok(());
        }
        let Some(owner) = job.owner.as_ref() else {
            return Ok(());
        };
        let socket = owner.job.lease.request().deferred_cleanup[0].try_clone()?;
        let stop = job.stop_control.clone();
        let lifecycle = job.lifecycle.clone();
        let notifier = self.supervisor.notifier();
        let deadline = job.control_deadline.clone();
        job.monitoring = true;
        owner.job.lease.monitor(move || {
            let mut reader = ControlReader::client_signal();
            while !stop.load(Ordering::Acquire) && !lifecycle.cancelled.load(Ordering::Acquire) {
                let result = (|| -> io::Result<()> {
                    let mut poll = libc::pollfd {
                        fd: socket.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ready = unsafe { libc::poll(&mut poll, 1, 20) };
                    if ready < 0 {
                        if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                            return Ok(());
                        }
                        return Err(io::Error::last_os_error());
                    }
                    if ready > 0 && reader.deadline().is_none() {
                        // Publish a timer before recvmsg can dispose of malformed
                        // ancillary rights and block in a filesystem's close.
                        deadline
                            .lock()
                            .expect("control timer")
                            .get_or_insert(Instant::now() + crate::transport::FRAME_TIMEOUT);
                    }
                    if let Some(frame) = reader.read(socket.as_raw_fd(), Instant::now())? {
                        let signal: protocol::ClientSignal = protocol::parse_strict(&frame.payload)
                            .map_err(|e| invalid(e.to_string()))?;
                        signal.validate().map_err(|e| invalid(e.to_string()))?;
                        if !notifier.control(SpawnOutcome::Signal {
                            token,
                            signal: signal.signal,
                        }) {
                            return Err(invalid("signal queue full"));
                        }
                        reader = ControlReader::client_signal();
                        *deadline.lock().expect("control timer") = None;
                    }
                    Ok(())
                })();
                if result.is_err() {
                    lifecycle.cancel();
                    let _ = notifier.control(SpawnOutcome::ControlLost(token));
                    break;
                }
            }
        });
        Ok(())
    }
    pub fn tick(&mut self, epoll: RawFd) -> io::Result<()> {
        let exits = self.reaper.poll().map_err(|error| {
            for exit in error.exits {
                if let Some(token) = exit.token
                    && let Some(job) = self.jobs.get_mut(&token)
                {
                    job.exit = Some(exit);
                }
            }
            error.error
        })?;
        for exit in exits {
            if let Some(token) = exit.token
                && let Some(job) = self.jobs.get_mut(&token)
            {
                job.exit = Some(exit);
            }
        }
        let tokens: Vec<_> = self.jobs.keys().copied().collect();
        for token in tokens {
            let job = self.jobs.get_mut(&token).unwrap();
            if job.outcome.is_none()
                && let Some(fd) = job.sync.as_ref()
                && let Some(outcome) =
                    job.handshake
                        .read(fd.as_raw_fd(), Instant::now(), job.deadline.unwrap())?
            {
                unwatch(epoll, fd.as_raw_fd())?;
                job.sync = None;
                if outcome != SyncOutcome::ReadyToExec {
                    job.failure = Some(format!("child setup failed: {outcome:?}"));
                }
                job.outcome = Some(outcome);
            }
            if job
                .control_deadline
                .lock()
                .expect("control timer")
                .is_some_and(|deadline| Instant::now() >= deadline)
            {
                job.lifecycle.cancel();
            }
            let cancelled = job.lifecycle.cancelled.load(Ordering::Acquire);
            let failed = job.failure.is_some()
                || job
                    .outcome
                    .as_ref()
                    .is_some_and(|o| *o != SyncOutcome::ReadyToExec);
            if !job.audit_pending
                && !job.ready_audited
                && !self.poisoned
                && job.outcome == Some(SyncOutcome::ReadyToExec)
            {
                let mut fields = job.fields.clone();
                fields["child_pid"] = job.pid.into();
                fields["exec_outcome"] = "unknown".into();
                self.durable
                    .try_send(sequencer::Work::Execution {
                        token,
                        records: vec![("EXEC_READY_TO_EXEC", fields)],
                        limit: job.limit,
                        owner: None,
                    })
                    .map_err(|_| invalid("ready audit capacity unavailable"))?;
                job.audit_pending = true;
            }
            if !job.task
                && !job.cleanup
                && (cancelled || failed || job.exit.is_some())
                && let Some(owner) = job.owner.take()
            {
                job.stop_control.store(true, Ordering::Release);
                self.dispatch(token, Task::Cleanup(owner))?;
            }
            let job = self.jobs.get_mut(&token).unwrap();
            if self.poisoned
                && job.cleanup
                && (job.pid.is_none() || job.exit.is_some())
                && job.sync.is_none()
                && !self.reaper.has_pending()
                && !self.reaper.sweep_required()
            {
                self.jobs.remove(&token);
                continue;
            }
            if job.cleanup
                && !job.audit_pending
                && !job.final_pending
                && (job.pid.is_none() || job.exit.is_some())
                && job.sync.is_none()
                && !self.reaper.has_pending()
                && !self.reaper.sweep_required()
            {
                job.stop_control.store(true, Ordering::Release);
                if self.poisoned {
                    self.jobs.remove(&token);
                    continue;
                }
                let mut records = Vec::new();
                let mut fields = job.fields.clone();
                fields["disconnected"] = cancelled.into();
                if let Some(exit) = job.exit {
                    let wire = wire_exit(exit);
                    fields["exit_code"] = serde_json::to_value(wire.exit_code)?;
                    fields["signal"] = serde_json::to_value(wire.signal)?;
                }
                if job.outcome != Some(SyncOutcome::ReadyToExec) {
                    fields["reason"] = job
                        .failure
                        .clone()
                        .unwrap_or_else(|| "cancelled before spawn".into())
                        .into();
                    fields["status"] = "SPAWN_FAILED".into();
                    records.push((
                        if job.spawn_reserved {
                            "EXEC_SPAWN_FAILED"
                        } else {
                            "AUTH_ABORTED_POST_COMMIT"
                        },
                        fields.clone(),
                    ));
                }
                if job.pid.is_some() && (job.outcome == Some(SyncOutcome::ReadyToExec) || cancelled)
                {
                    records.push(("EXEC_EXIT", fields));
                }
                let owner = job.cleaned.take().expect("cleaned job owner");
                if let Err(error) = self.durable.try_send(sequencer::Work::Execution {
                    token,
                    records,
                    limit: job.limit,
                    owner: Some(owner),
                }) {
                    let work = match error {
                        std::sync::mpsc::TrySendError::Full(work)
                        | std::sync::mpsc::TrySendError::Disconnected(work) => work,
                    };
                    if let sequencer::Work::Execution { owner, .. } = work {
                        job.cleaned = owner;
                    }
                    return Err(invalid("exit audit capacity unavailable"));
                }
                job.audit_pending = true;
                job.final_pending = true;
            }
        }
        // A complete deferred sweep precedes each next clone. FIFO prevents
        // fresh jobs from indefinitely overtaking an existing prepared job.
        while let Some(token) = self.ready.pop_front() {
            let Some(job) = self.jobs.get_mut(&token) else {
                continue;
            };
            if job.task
                || job.cleanup
                || job.failure.is_some()
                || job.lifecycle.cancelled.load(Ordering::Acquire)
            {
                continue;
            }
            if self.stopping {
                job.lifecycle.cancel();
                continue;
            }
            if !self.reaper.reserve(token) {
                self.ready.push_front(token);
                break;
            }
            if !job.lifecycle.transition(Phase::Committed, Phase::Spawning) {
                assert!(self.reaper.complete(token, None).is_ok());
                continue;
            }
            job.spawn_reserved = true;
            let owner = job.owner.take().expect("prepared owner");
            if let Err(error) = self.dispatch(token, Task::Spawn(owner)) {
                assert!(self.reaper.complete(token, None).is_ok());
                self.jobs
                    .get(&token)
                    .unwrap()
                    .lifecycle
                    .finish_spawn(Decision::Rejected);
                return Err(error);
            }
            break;
        }
        Ok(())
    }
}
fn wire_exit(exit: ChildExit) -> protocol::ChildExit {
    match exit.code {
        libc::CLD_EXITED => protocol::ChildExit {
            exit_code: Some(exit.status as u8),
            signal: None,
        },
        libc::CLD_KILLED | libc::CLD_DUMPED => protocol::ChildExit {
            exit_code: None,
            signal: Some(exit.status as u8),
        },
        _ => unreachable!("WEXITED returned nonterminal status"),
    }
}
fn watch(epoll: RawFd, fd: RawFd, token: u64) -> io::Result<()> {
    let mut event = libc::epoll_event {
        events: (libc::EPOLLIN | libc::EPOLLHUP | libc::EPOLLERR) as u32,
        u64: token,
    };
    if unsafe { libc::epoll_ctl(epoll, libc::EPOLL_CTL_ADD, fd, &mut event) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn unwatch(epoll: RawFd, fd: RawFd) -> io::Result<()> {
    if unsafe { libc::epoll_ctl(epoll, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
