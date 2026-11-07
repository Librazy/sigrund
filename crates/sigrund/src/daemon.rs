//! Foreground coordinator for snapshots, approval and durable authorization.
//! Runtime ownership outlives control connections through cleanup and auditing.
use crate::{
    admission::{Admission, AuditLease},
    jobs::JobSupervisor,
    linux::validate_absolute_path,
    preparation::{self, Context, Document, PinnedRoot},
    runtime::{Execution, Notice, PID_TAG, SYNC_TAG},
    sequencer::{self, Sequencer},
    snapshot::SnapshotBudget,
    socket_disposal::{Permit, Socket, SocketDisposal},
    startup::{StartupResources, check_root_metadata, open_pinned},
    transport::{
        FrameWriter, PeerCredentials, disable_ancillary_credentials, invalid, peer_credentials,
    },
    workers::{Completion, IoWorkers, RequestLease, ValidationHandle},
};
use sigrund_core::{
    approval::ApprovalRequest,
    config::{DaemonConfig, SignerPolicyFile},
    crypto::new_uuidv7,
    framing::FrameType,
    lifecycle::{Decision as LifecycleDecision, Lifecycle, Phase},
    protocol::Decision,
};
use std::{
    collections::HashMap,
    ffi::CString,
    fs::{self, File},
    io::{self, Write},
    mem::{size_of, zeroed},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        mpsc::{SyncSender, sync_channel},
    },
    time::{Duration, Instant},
};

const CLIENT_LISTENER: u64 = 1;
const APPROVAL_LISTENER: u64 = 2;
const SIGNALS: u64 = 3;
const IO_COMPLETE: u64 = 4;
const AUDIT_COMPLETE: u64 = 5;
const JOB_COMPLETE: u64 = 6;
const SOCKET_DISPOSAL: u64 = 7;
const CONTEXT_LISTENER: u64 = 8;
const CONTEXT_COMPLETE: u64 = 9;
const FIRST_CONNECTION: u64 = 10;

struct BoundSocket {
    fd: Option<OwnedFd>,
    disposal: Option<Permit>,
    parent: File,
    name: CString,
    inode: u64,
    device: u64,
}

impl BoundSocket {
    fn bind(path: &Path, mode: u32) -> io::Result<Self> {
        validate_absolute_path(path)?;
        if path.as_os_str().as_bytes().len() >= 108 {
            return Err(invalid("Unix socket path is too long"));
        }
        let name = path
            .file_name()
            .ok_or_else(|| invalid("socket path needs a filename"))?;
        let name = CString::new(name.as_bytes()).map_err(|_| invalid("NUL in socket name"))?;
        let parent = open_pinned(
            path.parent()
                .ok_or_else(|| invalid("socket path needs a parent"))?,
        )?;
        check_root_metadata(&parent, true, None)?;
        // Address the pinned directory instead of re-resolving its pathname.
        let pinned = PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            parent.as_raw_fd(),
            name.to_str()
                .map_err(|_| invalid("socket name must be UTF-8"))?
        ));
        if fs::symlink_metadata(&pinned).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "refusing to replace an existing socket path",
            ));
        }
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        disable_ancillary_credentials(fd.as_raw_fd())?;
        let mut address: libc::sockaddr_un = unsafe { zeroed() };
        address.sun_family = libc::AF_UNIX as _;
        let bytes = pinned.as_os_str().as_bytes();
        if bytes.len() >= address.sun_path.len() {
            return Err(invalid("pinned socket path is too long"));
        }
        for (target, source) in address.sun_path.iter_mut().zip(bytes) {
            *target = *source as _;
        }
        // Bind under a restrictive umask, then explicitly set the specified
        // mode. The process is single-threaded at listener creation.
        let old_mask = unsafe { libc::umask(0o177) };
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                (size_of::<libc::sa_family_t>() + bytes.len() + 1) as _,
            )
        };
        unsafe {
            libc::umask(old_mask);
        }
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let metadata = fs::symlink_metadata(&pinned)?;
        let bound = Self {
            fd: Some(fd),
            disposal: None,
            parent,
            name,
            inode: metadata.ino(),
            device: metadata.dev(),
        };
        if metadata.uid() != 0 || metadata.gid() != 0 {
            return Err(invalid("socket must be owned by root:root"));
        }
        fs::set_permissions(&pinned, fs::Permissions::from_mode(mode))?;
        Ok(bound)
    }

    fn listen(&self) -> io::Result<()> {
        if unsafe { libc::listen(self.fd(), 64) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn fd(&self) -> RawFd {
        self.fd.as_ref().expect("live listener").as_raw_fd()
    }

    fn close(&mut self) {
        if let Some(fd) = self.fd.take() {
            if let Some(permit) = self.disposal.take() {
                drop(permit.socket(fd));
            } else {
                drop(fd);
            }
        }
    }

    fn accept(&self, permit: Permit) -> io::Result<Option<Socket>> {
        let fd = unsafe {
            libc::accept4(
                self.fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = io::Error::last_os_error();
            return if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        Ok(Some(permit.socket(unsafe { OwnedFd::from_raw_fd(fd) })))
    }
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        self.close();
        let pinned = PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            self.parent.as_raw_fd(),
            self.name.to_string_lossy()
        ));
        if fs::symlink_metadata(&pinned)
            .is_ok_and(|m| m.ino() == self.inode && m.dev() == self.device)
        {
            unsafe {
                libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

struct SignalSource {
    fd: OwnedFd,
    previous: libc::sigset_t,
    previous_child: libc::sigaction,
}

impl SignalSource {
    fn new() -> io::Result<Self> {
        let mut mask = unsafe { zeroed() };
        let mut previous = unsafe { zeroed() };
        unsafe {
            libc::sigemptyset(&mut mask);
            for signal in [
                libc::SIGTERM,
                libc::SIGINT,
                libc::SIGHUP,
                libc::SIGCHLD,
                libc::SIGIO,
            ] {
                libc::sigaddset(&mut mask, signal);
            }
        }
        let mut action: libc::sigaction = unsafe { zeroed() };
        let mut previous_child = unsafe { zeroed() };
        action.sa_sigaction = libc::SIG_DFL;
        if unsafe { libc::sigaction(libc::SIGCHLD, &action, &mut previous_child) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous) };
        if result != 0 {
            unsafe {
                libc::sigaction(libc::SIGCHLD, &previous_child, std::ptr::null_mut());
            }
            return Err(io::Error::from_raw_os_error(result));
        }
        let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
                libc::sigaction(libc::SIGCHLD, &previous_child, std::ptr::null_mut());
            }
            return Err(error);
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            previous,
            previous_child,
        })
    }

    fn next(&self) -> io::Result<Option<u32>> {
        let mut info: libc::signalfd_siginfo = unsafe { zeroed() };
        let length = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                (&mut info as *mut libc::signalfd_siginfo).cast(),
                size_of::<libc::signalfd_siginfo>(),
            )
        };
        if length < 0 {
            let error = io::Error::last_os_error();
            return if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if length as usize != size_of::<libc::signalfd_siginfo>() {
            return Err(invalid("short signalfd read"));
        }
        Ok(Some(info.ssi_signo))
    }
}

impl Drop for SignalSource {
    fn drop(&mut self) {
        unsafe {
            // A break can race the shutdown signal. Once owners have cleaned
            // up, discard our pending wakeups before restoring a mask that
            // may otherwise deliver SIGIO with its terminating disposition.
            let mut mask = zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGIO);
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            while libc::sigtimedwait(&mask, std::ptr::null_mut(), &timeout) >= 0 {}
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
            libc::sigaction(libc::SIGCHLD, &self.previous_child, std::ptr::null_mut());
        }
    }
}

enum Input {
    Client,
    Approval,
    Serving {
        requester: u64,
    },
    Validating {
        _task: ValidationHandle,
    },
    Authorizing {
        _task: ValidationHandle,
    },
    Executing {
        _task: ValidationHandle,
        ready_sent: bool,
        finishing: bool,
        terminal: Option<FrameWriter>,
    },
}

struct Connection {
    token: u64,
    fd: Socket,
    peer: PeerCredentials,
    broker: bool,
    input: Input,
    output: Option<FrameWriter>,
    audit: Option<AuditLease>,
    request_deadline: Option<Instant>,
    exec_id: String,
    policy: Arc<DaemonConfig>,
    lifecycle: Arc<Lifecycle>,
    durable: SyncSender<sequencer::Work>,
    approval_reserved: bool,
    approval_broker: Option<u64>,
    approval_csr: Option<String>,
    approval_reusable: bool,
    auth_deadline: Instant,
    preparation_deadline: Instant,
    mode: String,
    full_validated: bool,
    private_failure: Option<serde_json::Value>,
    provenance: serde_json::Value,
    silent: bool,
    retained_lease: Option<RequestLease>,
    committed_job: Option<Box<sequencer::CommittedJob>>,
}

#[derive(Default)]
struct ApprovalAvailability {
    busy: bool,
    broker: Option<(u64, Socket)>,
}

impl Connection {
    fn deadline(&self) -> Option<Instant> {
        if let Some(output) = &self.output {
            return Some(output.deadline());
        }
        self.request_deadline
    }

    fn reject(&mut self, status: &str, message: &str, now: Instant) -> io::Result<()> {
        self.respond(status, message, None, now)
    }

    fn timeout_after_commit(&mut self, epoll: RawFd, now: Instant) -> io::Result<()> {
        self.reject("REQUEST_TIMEOUT", "authorization delivery expired", now)?;
        // A completion can beat the expiry sweep. Authorization had disabled
        // writes, so arm the queued decision before its send deadline takes over.
        register(
            epoll,
            libc::EPOLL_CTL_MOD,
            self.fd.as_raw_fd(),
            self.token,
            self.output.is_some(),
            false,
        )
    }

    fn respond(
        &mut self,
        status: &str,
        message: &str,
        csr_payload: Option<String>,
        now: Instant,
    ) -> io::Result<()> {
        self.respond_inner(status, message, csr_payload, now, false)
    }

    fn respond_inner(
        &mut self,
        status: &str,
        message: &str,
        _csr_payload: Option<String>,
        now: Instant,
        audited: bool,
    ) -> io::Result<()> {
        if self.lifecycle.state().1 != LifecycleDecision::Undecided {
            return Ok(());
        }
        let visible_rejection = status == "REJECTED"
            && self.mode == "full_csr"
            && self.full_validated
            && now < self.auth_deadline;
        let _ = audited;
        if self.private_failure.is_none() {
            self.private_failure = Some(serde_json::json!({"reason_code":status,"reason":message,
                "intended_public_outcome":if visible_rejection {"REJECTED"} else {"TIMEOUT"}}));
        }
        if !visible_rejection && now < self.auth_deadline {
            self.lifecycle.silence();
            self.silent = true;
            self.request_deadline = Some(self.auth_deadline);
            match &self.input {
                Input::Validating { _task } | Input::Authorizing { _task } => _task.cancel(),
                _ => (),
            }
            return Ok(());
        }
        let outcome = if visible_rejection {
            LifecycleDecision::Rejected
        } else {
            LifecycleDecision::Timeout
        };
        if !self
            .lifecycle
            .claim_terminal(self.lifecycle.state().0, outcome)
        {
            return Ok(());
        }
        self.silent = true;
        self.request_deadline = None;
        let decision = Decision {
            exec_id: self.exec_id.clone(),
            status: if visible_rejection {
                "REJECTED"
            } else {
                "TIMEOUT"
            }
            .into(),
        };
        self.output = Some(FrameWriter::control(
            FrameType::ServerAuthDecision,
            &serde_json::to_vec(&decision)?,
            now,
        )?);
        Ok(())
    }

    fn reading(&self) -> bool {
        !self.silent
            && self.output.is_none()
            && !matches!(
                self.input,
                Input::Validating { .. }
                    | Input::Authorizing { .. }
                    | Input::Serving { .. }
                    | Input::Executing { .. }
            )
    }

    fn queue_decision_audit(&mut self, decision: &Decision) -> io::Result<()> {
        let Some(audit) = self.audit.take() else {
            return Ok(());
        };
        let mut fields = self.provenance.clone();
        let object = fields.as_object_mut().expect("private provenance object");
        if let Some(failure) = &self.private_failure {
            object.extend(failure.as_object().expect("failure object").clone());
        }
        object.extend(serde_json::json!({"exec_id":self.exec_id,"requester_uid":self.peer.uid,"requester_gid":self.peer.gid,
            "submission_mode":self.mode,"public_outcome":decision.status,"delivery_status":self.lifecycle.delivery_status()}).as_object().unwrap().clone());
        self.durable
            .try_send(sequencer::Work::Event {
                token: self.token,
                event_type: "PRIVATE_OUTCOME",
                fields,
                limit: self.policy.audit_record_max_bytes as usize,
                _audit: audit,
            })
            .map_err(|_| invalid("reserved audit executor unavailable"))
    }

    fn finish_validation(
        &mut self,
        result: io::Result<RequestLease>,
        now: Instant,
        log: &SyncSender<String>,
        context: &Arc<Context>,
        budget: &SnapshotBudget,
        availability: ApprovalAvailability,
    ) -> io::Result<()> {
        if self.broker {
            return Err(invalid("unsolicited approval response"));
        }
        if self.silent || self.lifecycle.state().1 != LifecycleDecision::Undecided {
            if let Ok(lease) = result {
                self.retained_lease = Some(lease);
            }
            return Ok(());
        }
        if now >= self.auth_deadline {
            if let Ok(lease) = result {
                self.retained_lease = Some(lease);
            }
            return self.reject("REQUEST_TIMEOUT", "authorization deadline expired", now);
        }
        let mut lease = result?;
        if !lease.matches_admission(self.peer.uid, &self.policy) {
            return Err(invalid("request admission mismatch"));
        }
        self.mode = lease.hello().mode.clone();
        lease.set_identity(&self.exec_id);
        self.provenance = sequencer::request_provenance(lease.request());
        self.request_deadline = Some(self.auth_deadline);
        if self.mode != "signed" && !self.approval_reserved {
            if availability.busy {
                self.retained_lease = Some(lease);
                return self.reject("RESOURCE_EXHAUSTED", "approval slot unavailable", now);
            }
            self.approval_reserved = true;
        }
        if now >= self.auth_deadline {
            self.retained_lease = Some(lease);
            return self.reject("REQUEST_TIMEOUT", "authorization deadline expired", now);
        }
        if let Some(error) = &lease.request().failure {
            let status = error
                .get_ref()
                .and_then(|e| e.downcast_ref::<preparation::Failure>())
                .map_or("INVALID_REQUEST", |e| e.status);
            let message = error.to_string();
            self.approval_reusable = status == "REJECTED";
            self.retained_lease = Some(lease);
            return self.reject(status, &message, now);
        }
        if lease.request().pending_preparation.is_some() {
            if !self
                .lifecycle
                .transition(Phase::Snapshotting, Phase::Hashing)
            {
                return Err(invalid("stale hash handoff"));
            }
            let deadline = (now
                + Duration::from_millis(self.policy.direct_digest_timeout_ms.into()))
            .min(self.auth_deadline);
            lease.begin_hashing(deadline);
            let context = context.clone();
            let gid = self.peer.gid;
            lease.continue_on_worker(move |r| preparation::hash_and_finish(r, &context, gid));
            return Ok(());
        }
        if let Some(prepared) = lease.prepared() {
            let phase = self.lifecycle.state().0;
            match &prepared.document {
                Document::Unsigned(csr) => {
                    self.full_validated = self.mode == "full_csr";
                    if !self.lifecycle.transition(phase, Phase::Reviewing) {
                        return Err(invalid("stale review handoff"));
                    }
                    let signer_id = self
                        .policy
                        .mvp
                        .as_ref()
                        .expect("MVP")
                        .approval_signer_id
                        .clone();
                    let Some((broker_token, socket)) = availability.broker else {
                        self.retained_lease = Some(lease);
                        return self.reject("NO_APPROVER", "local approver unavailable", now);
                    };
                    let mut approval = ApprovalRequest::new(self.exec_id.clone(), signer_id, csr)
                        .map_err(|e| invalid(e.to_string()))?;
                    approval.remaining_ms = u32::try_from(
                        self.auth_deadline
                            .saturating_duration_since(now)
                            .as_millis(),
                    )
                    .unwrap_or(300_000)
                    .clamp(1, 300_000);
                    self.approval_csr =
                        Some(String::from_utf8(csr.as_bytes().to_vec()).expect("JCS"));
                    self.approval_broker = Some(broker_token);
                    lease.begin_approval(self.auth_deadline);
                    let context = context.clone();
                    let gid = self.peer.gid;
                    lease.continue_on_worker(move |r| {
                        preparation::approve(r, &context, gid, approval, socket)
                    });
                }
                Document::Signed { .. } => {
                    if !self.lifecycle.transition(phase, Phase::Authorizing) {
                        return Err(invalid("stale authorization handoff"));
                    }
                    self.approval_reusable = self.approval_csr.is_some();
                    lease.set_deadline(self.auth_deadline);
                    let Input::Validating { _task } =
                        std::mem::replace(&mut self.input, Input::Client)
                    else {
                        return Err(invalid("missing worker owner"));
                    };
                    self.input = Input::Authorizing { _task };
                    let work = sequencer::Work::Authorize(sequencer::AuthorizationTask {
                        token: self.token,
                        exec_id: self.exec_id.clone(),
                        gid: self.peer.gid,
                        lifecycle: self.lifecycle.clone(),
                        lease,
                        control: self.fd.clone(),
                        audit: self
                            .audit
                            .take()
                            .ok_or_else(|| invalid("missing audit reservation"))?,
                    });
                    if let Err(error) = self.durable.try_send(work) {
                        if let sequencer::Work::Authorize(task) = match error {
                            std::sync::mpsc::TrySendError::Full(w)
                            | std::sync::mpsc::TrySendError::Disconnected(w) => w,
                        } {
                            self.audit = Some(task.audit);
                            self.retained_lease = Some(task.lease);
                        }
                        return self.reject(
                            "RESOURCE_EXHAUSTED",
                            "authorization queue unavailable",
                            now,
                        );
                    }
                }
            }
        } else {
            lease.set_deadline(self.preparation_deadline.min(self.auth_deadline));
            let context = context.clone();
            let budget = budget.clone();
            let gid = self.peer.gid;
            let _=log.try_send(serde_json::json!({"event":"CLIENT_HELLO_VALIDATED","exec_id":self.exec_id,"request_mode":self.mode,"requester_uid":self.peer.uid,"requester_gid":self.peer.gid}).to_string());
            lease.continue_on_worker(move |r| preparation::prepare(r, &context, &budget, gid));
        }
        Ok(())
    }

    fn dispatch(
        &mut self,
        token: u64,
        now: Instant,
        workers: &mut IoWorkers,
        log: &SyncSender<String>,
    ) -> io::Result<bool> {
        if let Some(output) = &mut self.output {
            if !output.write(self.fd.as_raw_fd(), now)? {
                return Ok(true);
            }
            if !self.broker {
                self.lifecycle.mark_frame_written();
            }
            if let Some(job) = &mut self.committed_job {
                job.commit_fields["public_outcome"] = "APPROVED".into();
                job.commit_fields["delivery_status"] = self.lifecycle.delivery_status().into();
                self.output = None;
                if !self
                    .lifecycle
                    .transition(Phase::ApprovalDelivery, Phase::Approved)
                {
                    return Err(invalid("lost approval delivery"));
                }
                self.approval_reserved = false;
                return Ok(true);
            }
            if let Input::Executing {
                ready_sent,
                finishing,
                terminal,
                ..
            } = &mut self.input
            {
                if *finishing {
                    return Ok(false);
                }
                *ready_sent = true;
                self.output = terminal.take();
                *finishing = self.output.is_some();
                return Ok(true);
            }
            return Ok(false);
        }
        if self.deadline().is_some_and(|d| now >= d) {
            if self.broker {
                return Ok(false);
            }
            if self.lifecycle.state().1 == LifecycleDecision::Undecided {
                self.reject("REQUEST_TIMEOUT", "authorization deadline expired", now)?;
                return Ok(true);
            }
            return Ok(false);
        }
        match &mut self.input {
            Input::Client | Input::Approval => {
                if self.silent {
                    return Ok(true);
                }
                let deadline = self
                    .request_deadline
                    .unwrap_or(now + crate::transport::FRAME_TIMEOUT);
                match workers.submit(
                    token,
                    self.peer.uid,
                    &self.fd,
                    self.policy.clone(),
                    self.broker,
                    deadline,
                ) {
                    Ok(task) => {
                        self.input = Input::Validating { _task: task };
                        if !self.broker {
                            self.request_deadline = Some(self.auth_deadline);
                        }
                        let _ = log.try_send(
                            serde_json::json!({"event":"IO_WORKER_RESERVED","worker_task":token})
                                .to_string(),
                        );
                    }
                    Err(_) if self.broker => return Ok(false),
                    Err(_) => self.reject(
                        "RESOURCE_EXHAUSTED",
                        "request I/O worker quota exhausted",
                        now,
                    )?,
                }
            }
            // EPOLLIN is disabled while the worker receives/validates. The
            // remaining socket events are disconnect/error notifications.
            Input::Validating { .. }
            | Input::Serving { .. }
            | Input::Authorizing { .. }
            | Input::Executing { .. } => {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.lifecycle.cancel();
        self.lifecycle.mark_undelivered();
        // Durable tasks and I/O workers can retain shared socket ownership.
        // End peer communication now; final close and caller-FD cleanup stay
        // on their reserved workers even if audit persistence is stalled.
        unsafe {
            libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_RDWR);
        }
        if let Some(job) = self.committed_job.take() {
            abort_delivery(job, &self.durable);
        }
        if self.audit.is_some() {
            let decision = Decision {
                exec_id: self.exec_id.clone(),
                status: self.lifecycle.public_outcome().into(),
            };
            let _ = self.queue_decision_audit(&decision);
        }
    }
}

fn abort_delivery(job: Box<sequencer::CommittedJob>, durable: &SyncSender<sequencer::Work>) {
    let mut fields = job.commit_fields.clone();
    fields["reason"] = "authorization delivery expired or disconnected".into();
    fields["public_outcome"] = job.lifecycle.public_outcome().into();
    fields["delivery_status"] = job.lifecycle.delivery_status().into();
    // Retain the consumed grant, audit and request owners through reconciliation.
    let work = sequencer::Work::Execution {
        token: job.token,
        records: vec![("AUTH_ABORTED_POST_COMMIT", fields)],
        limit: job.lease.request().policy.audit_record_max_bytes as usize,
        owner: Some(job),
    };
    if durable.try_send(work).is_err() {
        // Reserved durable capacity must outlive every committed owner.
        std::process::abort();
    }
}

fn publish_notices(
    notices: Vec<Notice>,
    connections: &mut HashMap<u64, Connection>,
    epoll: RawFd,
) -> io::Result<()> {
    use sigrund_core::protocol::{ExecReady, ExecResult};
    for notice in notices {
        let token = match &notice {
            Notice::Ready(t, _) | Notice::Failed(t, _) | Notice::Exit(t, _) => *t,
        };
        let Some(c) = connections.get_mut(&token) else {
            continue;
        };
        match notice {
            Notice::Ready(_, outcome) => {
                if c.lifecycle.state().1 != LifecycleDecision::Approved {
                    return Err(invalid("readiness without approval"));
                }
                let Input::Authorizing { _task } = std::mem::replace(&mut c.input, Input::Client)
                else {
                    return Err(invalid("missing execution owner"));
                };
                c.input = Input::Executing {
                    _task,
                    ready_sent: false,
                    finishing: false,
                    terminal: None,
                };
                c.output = Some(FrameWriter::control(
                    FrameType::ServerExecReady,
                    &serde_json::to_vec(&ExecReady {
                        exec_id: c.exec_id.clone(),
                        exec_outcome: outcome.into(),
                    })?,
                    Instant::now(),
                )?);
            }
            other => {
                let result = match other {
                    Notice::Exit(_, exit) => ExecResult {
                        exec_id: c.exec_id.clone(),
                        status: "EXITED".into(),
                        exit_code: exit.exit_code,
                        signal: exit.signal,
                    },
                    Notice::Failed(_, status) => ExecResult {
                        exec_id: c.exec_id.clone(),
                        status: status.into(),
                        exit_code: None,
                        signal: None,
                    },
                    _ => unreachable!(),
                };
                result.validate().map_err(|e| invalid(e.to_string()))?;
                let writer = FrameWriter::control(
                    FrameType::ServerExecResult,
                    &serde_json::to_vec(&result)?,
                    Instant::now(),
                )?;
                if let Input::Executing {
                    ready_sent,
                    finishing,
                    terminal,
                    ..
                } = &mut c.input
                {
                    if *ready_sent {
                        c.output = Some(writer);
                        *finishing = true;
                    } else {
                        *terminal = Some(writer);
                    }
                } else {
                    let Input::Authorizing { _task } =
                        std::mem::replace(&mut c.input, Input::Client)
                    else {
                        return Err(invalid("missing result owner"));
                    };
                    c.input = Input::Executing {
                        _task,
                        ready_sent: true,
                        finishing: true,
                        terminal: None,
                    };
                    c.output = Some(writer);
                }
            }
        }
        register(
            epoll,
            libc::EPOLL_CTL_MOD,
            c.fd.as_raw_fd(),
            token,
            true,
            false,
        )?;
    }
    Ok(())
}

pub struct ForegroundDaemon {
    client: BoundSocket,
    approval: BoundSocket,
    context_listener: BoundSocket,
    _resources: StartupResources,
    host_target: Arc<crate::host_target::HostTarget>,
    _epoch_owner: Arc<crate::host_registry::EpochOwner>,
    config: Arc<DaemonConfig>,
    _signers: SignerPolicyFile,
    signals: SignalSource,
    disposal: SocketDisposal,
}

impl ForegroundDaemon {
    pub fn prepare(
        config: DaemonConfig,
        signers: SignerPolicyFile,
        state_dir: &Path,
        log_path: &Path,
        socket: &Path,
        approval_socket: &Path,
    ) -> io::Result<Self> {
        Self::prepare_with_mode(
            config,
            signers,
            state_dir,
            log_path,
            socket,
            approval_socket,
            false,
        )
    }

    pub fn prepare_with_mode(
        mut config: DaemonConfig,
        signers: SignerPolicyFile,
        state_dir: &Path,
        log_path: &Path,
        socket: &Path,
        approval_socket: &Path,
        authorization_only: bool,
    ) -> io::Result<Self> {
        config.validate().map_err(|e| invalid(e.to_string()))?;
        signers
            .validate_against(&config)
            .map_err(|e| invalid(e.to_string()))?;
        let signals = SignalSource::new()?;
        let target_budget =
            sigrund_core::host_budget::Budget::new(config.host_limits).map_err(io::Error::other)?;
        let mut resources = StartupResources::prepare_with_host_budget(
            &config,
            state_dir,
            log_path,
            &target_budget,
        )?;
        // Runtime enrollment is never trusted from callers/configuration.
        config.admin_trusted_composefs_mounts.clear();
        if config.digest_direct.allow_admin_trusted_composefs
            && config
                .executable_trust_models
                .contains(&sigrund_core::executable::TrustModel::DigestDirect)
        {
            match crate::composefs::discover() {
                Ok(Some(enrollment)) => {
                    config
                        .admin_trusted_composefs_mounts
                        .push(enrollment.mount_id);
                    resources.composefs = Some(enrollment);
                }
                Ok(None) => (),
                Err(error) => eprintln!(
                    "{}",
                    serde_json::json!({
                        "event":"COMPOSEFS_ENROLLMENT_UNAVAILABLE", "error":error.to_string()
                    })
                ),
            }
        }
        if !authorization_only {
            let layout = crate::startup::CgroupLayout::discover()?;
            layout.initialize()?;
            let removed = layout.cleanup_orphans()?;
            if removed > 0 {
                resources
                    .audit
                    .append_event(
                        "ORPHAN_CLEANUP",
                        serde_json::json!({"cgroups":removed}),
                        config.audit_record_max_bytes as usize,
                    )
                    .map_err(|e| invalid(e.to_string()))?;
            }
            let _probe = target_budget
                .reserve(
                    0,
                    sigrund_core::host_budget::Charge {
                        helpers: 1,
                        target_fds: 16,
                        ..Default::default()
                    },
                )
                .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
            target_budget
                .with_transient_fd_copies(0, || crate::execution::startup_probe(&layout))
                .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))??;
            resources.execution = Some(layout);
        }
        let last_cap: u32 = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
            .trim()
            .parse()
            .map_err(|_| invalid("invalid kernel capability bound"))?;
        crate::host_target::qualify_profiles(
            &config.host_profiles,
            crate::execution::trace_available(),
            last_cap,
        )?;
        // Startup recovery/orphan records may themselves cross high water.
        // Recheck before publishing either listener, retaining those records.
        if !resources.storage.check(&config)? {
            return Err(invalid(
                "audit storage pressure after execution startup; remediation and restart required",
            ));
        }
        if config
            .mvp
            .as_ref()
            .is_none_or(|p| p.approval_signer_id.is_empty())
        {
            return Err(invalid("local v3 profile requires an approval signer"));
        }
        let host_target = crate::host_target::HostTarget::acquire_pinned(
            &config.csr_allowed_executable_dirs,
            resources.roots.take().expect("startup pinned roots"),
            resources
                .composefs
                .as_ref()
                .map(|e| e.mount_id)
                .into_iter()
                .collect(),
            &target_budget,
        )?;
        let bundles = config
            .host_profiles
            .iter()
            .map(|profile| host_target.bundle(resources.host_id.clone(), profile.clone()))
            .collect::<io::Result<Vec<_>>>()?;
        let epoch_owner =
            crate::host_registry::EpochOwner::publish(&resources.state_directory, bundles)?;
        let context_path = crate::client::context_path(socket);
        if context_path == approval_socket {
            return Err(invalid("context and approval sockets must differ"));
        }
        let mut context_listener = BoundSocket::bind(&context_path, 0o666)?;
        let mut client = BoundSocket::bind(socket, 0o666)?;
        let mut approval = BoundSocket::bind(approval_socket, 0o600)?;
        let disposal = SocketDisposal::new()?;
        context_listener.disposal = Some(disposal.reserve().expect("new pool listener capacity"));
        client.disposal = Some(disposal.reserve().expect("new pool listener capacity"));
        approval.disposal = Some(disposal.reserve().expect("new pool listener capacity"));
        // Protect listener final closes before any peer can queue connections.
        context_listener.listen()?;
        client.listen()?;
        approval.listen()?;
        Ok(Self {
            context_listener,
            client,
            approval,
            _resources: resources,
            host_target,
            _epoch_owner: epoch_owner,
            config: Arc::new(config),
            _signers: signers,
            signals,
            disposal,
        })
    }

    pub fn run(mut self) -> io::Result<()> {
        let context = Arc::new(Context {
            epoch: Some(self._epoch_owner.clone()),
            host_target: Some(self.host_target.clone()),
            roots: self
                .host_target
                .pinned_roots()
                .into_iter()
                .map(|(path, directory)| PinnedRoot { path, directory })
                .collect(),
            host_id: self._resources.host_id.clone(),
            signers: self._signers.clone(),
        });
        use sigrund_core::protocol::{ContextFeatures, ContextLimits, PublicContext};
        let public_context = Arc::new(serde_json::to_vec(&PublicContext {
            version: "3.0".into(),
            host_id: context.host_id.clone(),
            policy_generation: 1,
            executable_trust_models: self.config.executable_trust_models.clone(),
            limits: ContextLimits {
                max_executable_bytes: self.config.max_executable_bytes,
                max_direct_digest_bytes: self.config.max_direct_digest_bytes,
                direct_digest_timeout_ms: self.config.direct_digest_timeout_ms,
                max_stdin_bytes: self.config.max_stdin_bytes,
                max_ttl_secs: self.config.max_ttl_secs,
                max_onetime_window_secs: self.config.max_onetime_window_secs,
                authorization_timeout_ms: self.config.authorization_timeout_ms,
            },
            features: ContextFeatures {
                admin_trusted_composefs_mounts: self.config.admin_trusted_composefs_mounts.clone(),
                direct_exec_checkpoint: crate::execution::trace_available(),
                host_file_capabilities: crate::execution::trace_available(),
                tty_modes: vec!["stdio".into()],
                stdin_policies: vec!["null".into(), "sha256".into()],
                grant_modes: vec!["one_time".into()],
            },
        })?);
        let mut context_workers = crate::context::ContextWorkers::new(public_context)?;
        let budget = SnapshotBudget::default();
        let signals = self.signals;
        crate::startup::CgroupLayout::register_subreaper()?;
        // Threads inherit the blocked signal mask, leaving shutdown handling
        // on signalfd even when a metadata syscall cannot be interrupted.
        let mut workers = IoWorkers::new(&self.config)?;
        let storage_closed = self._resources.storage.closed.clone();
        let admission_start = Instant::now();
        let mut admission = Admission::new(&self.config, admission_start);
        let mut context_window = 0u64;
        let mut context_rates: HashMap<u32, u32> = HashMap::new();
        let mut context_total = 0u32;
        let sequencer_capacity = (self.config.max_pending_audits_global as usize)
            .checked_mul(2)
            .ok_or_else(|| invalid("sequencer capacity overflow"))?;
        let execution_layout = self._resources.execution_layout().cloned();

        let sequencer = Sequencer::new(
            self._resources,
            context.clone(),
            self.config.clone(),
            sequencer_capacity,
        )?;
        let supervisor =
            JobSupervisor::new(execution_layout, self.config.max_io_workers_global as usize)?;
        let mut execution = Execution::new(supervisor, sequencer.sender());
        let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let epoll = unsafe { OwnedFd::from_raw_fd(raw) };
        for (fd, token) in [
            (self.context_listener.fd(), CONTEXT_LISTENER),
            (context_workers.fd(), CONTEXT_COMPLETE),
            (self.client.fd(), CLIENT_LISTENER),
            (self.approval.fd(), APPROVAL_LISTENER),
            (signals.fd.as_raw_fd(), SIGNALS),
            (workers.fd(), IO_COMPLETE),
            (self.disposal.fd(), SOCKET_DISPOSAL),
            (sequencer.fd(), AUDIT_COMPLETE),
            (execution.supervisor.fd(), JOB_COMPLETE),
        ] {
            register(
                epoll.as_raw_fd(),
                libc::EPOLL_CTL_ADD,
                fd,
                token,
                false,
                true,
            )?;
        }
        // Human-readable diagnostics remain separate from durable audit.
        let (log, receiver) = sync_channel::<String>(128);
        let logger = std::thread::Builder::new()
            .name("diagnostics".into())
            .spawn(move || {
                for message in receiver {
                    let _ = writeln!(io::stderr(), "{message}");
                }
            })?;
        drop(logger);
        let _ = log.try_send(
            serde_json::json!({"event":"DAEMON_READY", "host_id":context.host_id,
            "profile":"local-approval", "local_audit_forward_secure":false,
            "executable_trust_models":self.config.executable_trust_models,
            "admin_trusted_composefs_mounts":self.config.admin_trusted_composefs_mounts,
            "ctime_checkpoint_available":crate::execution::trace_available()})
            .to_string(),
        );
        let mut connections: HashMap<u64, Connection> = HashMap::new();
        let mut next_token = FIRST_CONNECTION;
        let mut reload_diagnostic_pending = false;
        let mut events: [libc::epoll_event; 64] = unsafe { zeroed() };
        let mut stopping: Option<Instant> = None;
        let mut fatal_error = None;
        let mut grace_reported = false;
        let mut service = crate::service::Service::new()?;
        let mut stop_notified = false;
        let mut listeners_registered = true;
        let mut storage_pressure_reported = false;
        service.ready();
        loop {
            let now = Instant::now();
            let timeout = connections
                .values()
                .filter_map(Connection::deadline)
                .map(|deadline| deadline.saturating_duration_since(now))
                .chain(service.watchdog_wait(now).filter(|_| stopping.is_none()))
                .min()
                .unwrap_or(Duration::from_secs(1));
            let milliseconds = timeout.as_millis().saturating_add(1).min(
                if execution.active() || stopping.is_some() {
                    20
                } else {
                    1000
                },
            ) as i32;
            let iteration = (|| -> io::Result<()> {
                let count = unsafe {
                    libc::epoll_wait(
                        epoll.as_raw_fd(),
                        events.as_mut_ptr(),
                        events.len() as _,
                        milliseconds,
                    )
                };
                if count < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        return Ok(());
                    }
                    return Err(error);
                }
                for event in &events[..count as usize] {
                    let token = event.u64;
                    if token == SIGNALS {
                        while let Some(signal) = signals.next()? {
                            if signal == libc::SIGINT as u32 || signal == libc::SIGTERM as u32 {
                                if stopping.is_none() {
                                    stopping = Some(Instant::now());
                                }
                                break;
                            }
                            if signal == libc::SIGCHLD as u32 || signal == libc::SIGIO as u32 {
                                continue;
                            }
                            let _ = log.try_send("{\"event\":\"RELOAD_UNAVAILABLE\",\"message\":\"reload is unavailable in the local-approval profile\"}".into());
                            reload_diagnostic_pending = true;
                        }
                    } else if stopping.is_some()
                        && (token == CLIENT_LISTENER
                            || token == APPROVAL_LISTENER
                            || token == CONTEXT_LISTENER)
                    {
                        continue;
                    } else if token == CONTEXT_COMPLETE {
                        context_workers.drain();
                    } else if token == SOCKET_DISPOSAL {
                        self.disposal.drain();
                    } else if token == AUDIT_COMPLETE {
                        for completion in sequencer.drain() {
                            match completion {
                                sequencer::Completion::Recorded { token } => {
                                    let notices = execution.recorded(token);
                                    if stopping.is_none() {
                                        publish_notices(
                                            notices,
                                            &mut connections,
                                            epoll.as_raw_fd(),
                                        )?;
                                    }
                                }
                                sequencer::Completion::Reserve { token, permit } => {
                                    let allowed = stopping.is_none()
                                        && connections.get(&token).is_some_and(|c| {
                                            matches!(c.input, Input::Authorizing { .. })
                                                && Instant::now() < c.auth_deadline
                                                && sequencer::connection_live(c.fd.as_raw_fd())
                                                && !c
                                                    .lifecycle
                                                    .cancelled
                                                    .load(std::sync::atomic::Ordering::Acquire)
                                                && c.lifecycle.transition(
                                                    Phase::Authorizing,
                                                    Phase::Committing,
                                                )
                                        });
                                    let _ = permit.send(allowed);
                                }
                                sequencer::Completion::Finished {
                                    token,
                                    lease,
                                    denial,
                                    audit,
                                    lifecycle,
                                    fields,
                                } => {
                                    if let Some(c) = connections.get_mut(&token) {
                                        c.audit = Some(audit);
                                    } else {
                                        let mut fields = fields;
                                        fields["public_outcome"] =
                                            lifecycle.public_outcome().into();
                                        fields["delivery_status"] =
                                            lifecycle.delivery_status().into();
                                        sequencer.sender().try_send(sequencer::Work::Event { token, event_type:"PRIVATE_OUTCOME", fields,
                                            limit:lease.request().policy.audit_record_max_bytes as usize, _audit:audit })
                                            .map_err(|_|invalid("reserved outcome reconciliation capacity unavailable"))?;
                                    }
                                    if let Some(c) = connections.get_mut(&token)
                                        && c.lifecycle.state().1 == LifecycleDecision::Undecided
                                    {
                                        c.respond_inner(
                                            denial.status,
                                            denial.message,
                                            None,
                                            Instant::now(),
                                            true,
                                        )?;
                                        register(
                                            epoll.as_raw_fd(),
                                            libc::EPOLL_CTL_MOD,
                                            c.fd.as_raw_fd(),
                                            token,
                                            c.output.is_some(),
                                            false,
                                        )?;
                                    }
                                    if let Some(c) = connections.get_mut(&token) {
                                        c.retained_lease = Some(lease);
                                    } else {
                                        drop(lease);
                                    }
                                }
                                sequencer::Completion::Committed(job) => {
                                    if let Some(c) = connections.get_mut(&job.token) {
                                        let now = Instant::now();
                                        let w = job.authorized.warrant.warrant();
                                        let valid_now = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .ok()
                                            .and_then(|d| i64::try_from(d.as_secs()).ok())
                                            .is_some_and(|t| {
                                                t >= w.policy.not_before
                                                    && w.policy
                                                        .not_after
                                                        .is_some_and(|end| t <= end)
                                            });
                                        if now < c.auth_deadline
                                            && valid_now
                                            && sequencer::connection_live(c.fd.as_raw_fd())
                                            && c.lifecycle.transition(
                                                Phase::Committed,
                                                Phase::ApprovalDelivery,
                                            )
                                            && c.lifecycle.claim_terminal(
                                                Phase::ApprovalDelivery,
                                                LifecycleDecision::Approved,
                                            )
                                        {
                                            c.request_deadline = None;
                                            c.output = Some(FrameWriter::control(
                                                FrameType::ServerAuthDecision,
                                                &serde_json::to_vec(&Decision {
                                                    exec_id: c.exec_id.clone(),
                                                    status: "APPROVED".into(),
                                                })?,
                                                now,
                                            )?);
                                            c.committed_job = Some(job);
                                            register(
                                                epoll.as_raw_fd(),
                                                libc::EPOLL_CTL_MOD,
                                                c.fd.as_raw_fd(),
                                                c.token,
                                                true,
                                                false,
                                            )?;
                                        } else {
                                            c.lifecycle.silence();
                                            let mut fields = job.commit_fields.clone();
                                            fields["reason"] =
                                                "authorization delivery expired or disconnected"
                                                    .into();
                                            c.retained_lease = Some(job.lease);
                                            c.audit = Some(job.audit);
                                            c.durable.try_send(sequencer::Work::Execution { token:0,
                                                records:vec![("AUTH_ABORTED_POST_COMMIT",fields)],
                                                limit:c.policy.audit_record_max_bytes as usize, owner:None})
                                                .map_err(|_|invalid("reserved reconciliation capacity unavailable"))?;
                                            c.timeout_after_commit(epoll.as_raw_fd(), now)?;
                                        }
                                    } else {
                                        abort_delivery(job, &sequencer.sender());
                                    }
                                }
                                sequencer::Completion::Denied { token, denial } => {
                                    if let Some(c) = connections.get_mut(&token)
                                        && c.lifecycle.state().1 == LifecycleDecision::Undecided
                                    {
                                        c.respond_inner(
                                            denial.status,
                                            denial.message,
                                            None,
                                            Instant::now(),
                                            true,
                                        )?;
                                        register(
                                            epoll.as_raw_fd(),
                                            libc::EPOLL_CTL_MOD,
                                            c.fd.as_raw_fd(),
                                            token,
                                            c.output.is_some(),
                                            false,
                                        )?;
                                    }
                                }
                                sequencer::Completion::Fatal(error) => {
                                    execution.shutdown(true);
                                    return Err(invalid(format!(
                                        "durable executor failed closed: {error}"
                                    )));
                                }
                            }
                        }
                    } else if token == JOB_COMPLETE {
                        execution.drain(epoll.as_raw_fd())?;
                    } else if token & (SYNC_TAG | PID_TAG) != 0 {
                        // Sync/pidfd readiness is serviced centrally below, after
                        // processing all returned spawn owners in this dispatch.
                    } else if token == IO_COMPLETE {
                        for completion in workers.drain() {
                            let (token, result) = match completion {
                                Completion::Released { token } => {
                                    let _ = log.try_send(serde_json::json!({"event":"FD_VALIDATION_COMPLETE", "worker_task":token}).to_string());
                                    continue;
                                }
                                Completion::Validated { token, result } => {
                                    if result.is_err() {
                                        let _ = log.try_send(serde_json::json!({"event":"FD_VALIDATION_COMPLETE", "worker_task":token}).to_string());
                                    }
                                    (token, result)
                                }
                            };
                            if let Some(mut connection) = connections.remove(&token) {
                                let approval_busy =
                                    connections.values().any(|c| c.approval_reserved);
                                let broker = if result.as_ref().is_ok_and(|lease| {
                                    lease.prepared().is_some_and(|p| {
                                        matches!(p.document, Document::Unsigned(_))
                                    })
                                }) {
                                    connections
                                        .iter()
                                        .find(|(_, c)| {
                                            c.broker && matches!(c.input, Input::Approval)
                                        })
                                        .map(|(id, c)| (*id, c.fd.clone()))
                                } else {
                                    None
                                };
                                if connection
                                    .finish_validation(
                                        result,
                                        Instant::now(),
                                        &log,
                                        &context,
                                        &budget,
                                        ApprovalAvailability {
                                            busy: approval_busy,
                                            broker,
                                        },
                                    )
                                    .is_ok()
                                {
                                    if connection.approval_reusable
                                        && let Some(id) = connection.approval_broker.take()
                                        && let Some(broker) = connections.get_mut(&id)
                                    {
                                        broker.input = Input::Approval;
                                        register(
                                            epoll.as_raw_fd(),
                                            libc::EPOLL_CTL_MOD,
                                            broker.fd.as_raw_fd(),
                                            id,
                                            false,
                                            true,
                                        )?;
                                    }
                                    if connection.output.is_none()
                                        && let Some(broker_token) = connection.approval_broker
                                        && let Some(broker) = connections.get_mut(&broker_token)
                                    {
                                        broker.input = Input::Serving { requester: token };
                                        register(
                                            epoll.as_raw_fd(),
                                            libc::EPOLL_CTL_MOD,
                                            broker.fd.as_raw_fd(),
                                            broker_token,
                                            false,
                                            false,
                                        )?;
                                    }
                                    register(
                                        epoll.as_raw_fd(),
                                        libc::EPOLL_CTL_MOD,
                                        connection.fd.as_raw_fd(),
                                        token,
                                        connection.output.is_some(),
                                        false,
                                    )?;
                                    connections.insert(token, connection);
                                } else {
                                    unregister(epoll.as_raw_fd(), connection.fd.as_raw_fd())?;
                                }
                            }
                        }
                    } else if token == CLIENT_LISTENER
                        || token == APPROVAL_LISTENER
                        || token == CONTEXT_LISTENER
                    {
                        let listener = if token == CONTEXT_LISTENER {
                            &self.context_listener
                        } else if token == CLIENT_LISTENER {
                            &self.client
                        } else {
                            &self.approval
                        };
                        // An accept flood cannot starve active frames or timers.
                        for _ in 0..64 {
                            let Some(permit) = self.disposal.reserve() else {
                                break;
                            };
                            let Some(fd) = listener.accept(permit)? else {
                                break;
                            };
                            let accepted = Instant::now();
                            let Ok(peer) = peer_credentials(fd.as_raw_fd()) else {
                                // SO_PEERCRED can contain pid=0 for an ancestor
                                // PID-namespace peer. Reject this connection only.
                                continue;
                            };
                            let broker = token == APPROVAL_LISTENER;
                            let context_query = token == CONTEXT_LISTENER;
                            if context_query {
                                let window = accepted
                                    .saturating_duration_since(admission_start)
                                    .as_secs()
                                    / u64::from(self.config.admission_window_secs);
                                if window != context_window {
                                    context_window = window;
                                    context_total = 0;
                                    context_rates.clear();
                                }
                                if context_total >= 64
                                    || context_rates.get(&peer.uid).copied().unwrap_or(0) >= 8
                                    || disable_ancillary_credentials(fd.as_raw_fd()).is_err()
                                {
                                    continue;
                                }
                                if context_workers.submit(fd, peer.uid, accepted) {
                                    context_total += 1;
                                    *context_rates.entry(peer.uid).or_default() += 1;
                                }
                                continue;
                            }
                            // Authenticate before constructing a broker parser or
                            // reading a single byte (including queued signatures).
                            if broker && peer.uid != 0 {
                                continue;
                            }
                            let clients = connections.values().filter(|c| !c.broker);
                            let client_count = clients.clone().count();
                            let uid_count = clients.filter(|c| c.peer.uid == peer.uid).count();
                            if !broker
                                && (client_count >= self.config.max_active_sockets_global as usize
                                    || uid_count >= self.config.max_active_sockets_per_uid as usize)
                            {
                                admission.refuse();
                                continue;
                            }
                            if broker && connections.values().any(|c| c.broker) {
                                continue;
                            }
                            if disable_ancillary_credentials(fd.as_raw_fd()).is_err() {
                                continue;
                            }
                            let audit = if broker {
                                None
                            } else {
                                if storage_closed.load(std::sync::atomic::Ordering::Acquire) {
                                    admission.refuse();
                                    continue;
                                }
                                let Some(lease) = admission.admit(peer.uid, &self.config, accepted)
                                else {
                                    continue;
                                };
                                Some(lease)
                            };
                            let connection = Connection {
                                token: next_token,
                                fd,
                                peer,
                                broker,
                                input: if broker {
                                    Input::Approval
                                } else {
                                    Input::Client
                                },
                                output: None,
                                audit,
                                request_deadline: (!broker).then_some(
                                    accepted
                                        + Duration::from_millis(
                                            self.config
                                                .request_deadline_ms
                                                .min(self.config.authorization_timeout_ms)
                                                .into(),
                                        ),
                                ),
                                exec_id: new_uuidv7().to_string(),
                                policy: self.config.clone(),
                                lifecycle: Arc::new(Lifecycle::new()),
                                durable: sequencer.sender(),
                                approval_reserved: false,
                                approval_broker: None,
                                approval_csr: None,
                                approval_reusable: false,
                                auth_deadline: accepted
                                    + Duration::from_millis(
                                        self.config.authorization_timeout_ms.into(),
                                    ),
                                preparation_deadline: accepted
                                    + Duration::from_millis(self.config.request_deadline_ms.into()),
                                mode: String::new(),
                                full_validated: false,
                                private_failure: None,
                                provenance: serde_json::json!({"request_origin":null,"intent_sha256":null,"approval_exec_id":null}),
                                silent: false,
                                retained_lease: None,
                                committed_job: None,
                            };
                            let id = next_token;
                            next_token = next_token
                                .checked_add(1)
                                .filter(|token| *token < PID_TAG)
                                .ok_or_else(|| invalid("connection token overflow"))?;
                            register(
                                epoll.as_raw_fd(),
                                libc::EPOLL_CTL_ADD,
                                connection.fd.as_raw_fd(),
                                id,
                                false,
                                true,
                            )?;
                            let _ = log.try_send(
                            serde_json::json!({"event":"SOCKET_ADMITTED", "worker_task":id, "broker":broker,"requester_pid":peer.pid,
                            "requester_uid":peer.uid,"requester_gid":peer.gid})
                            .to_string(),
                        );
                            connections.insert(id, connection);
                        }
                    } else if let Some(mut connection) = connections.remove(&token) {
                        if connection
                            .dispatch(token, Instant::now(), &mut workers, &log)
                            .unwrap_or(false)
                        {
                            register(
                                epoll.as_raw_fd(),
                                libc::EPOLL_CTL_MOD,
                                connection.fd.as_raw_fd(),
                                token,
                                connection.output.is_some(),
                                connection.reading(),
                            )?;
                            connections.insert(token, connection);
                        } else {
                            unregister(epoll.as_raw_fd(), connection.fd.as_raw_fd())?;
                        }
                    }
                }
                // One diagnostic slot is reserved separately from requester
                // ownership. Reconnect floods cannot allocate a durable side queue.
                if stopping.is_none()
                    && let Some((audit, refused)) =
                        admission.diagnostic(Instant::now(), reload_diagnostic_pending)
                {
                    let work = sequencer::Work::Event {
                        token: 0,
                        event_type: if reload_diagnostic_pending {
                            "RELOAD_UNAVAILABLE"
                        } else {
                            "ADMISSION_REFUSED"
                        },
                        fields: serde_json::json!({"refused":refused,"reload_supported":false}),
                        limit: self.config.audit_record_max_bytes as usize,
                        _audit: audit,
                    };
                    reload_diagnostic_pending = false;
                    sequencer
                        .sender()
                        .try_send(work)
                        .map_err(|_| invalid("reserved diagnostic capacity unavailable"))?;
                }
                for c in connections.values_mut() {
                    if c.lifecycle.state().0 == Phase::Approved
                        && let Some(mut job) = c.committed_job.take()
                    {
                        job.lease.disable_stage_deadline();
                        execution.submit(*job)?;
                    }
                }
                // Expiry is independent of socket readiness and read progress.
                let now = Instant::now();
                let expired: Vec<u64> = connections
                    .iter()
                    .filter_map(|(id, c)| {
                        c.deadline()
                            .filter(|deadline| now >= *deadline)
                            .map(|_| *id)
                    })
                    .collect();
                for id in expired {
                    if let Some(mut connection) = connections.remove(&id) {
                        if connection
                            .dispatch(id, now, &mut workers, &log)
                            .unwrap_or(false)
                        {
                            register(
                                epoll.as_raw_fd(),
                                libc::EPOLL_CTL_MOD,
                                connection.fd.as_raw_fd(),
                                id,
                                connection.output.is_some(),
                                connection.reading(),
                            )?;
                            connections.insert(id, connection);
                        } else {
                            unregister(epoll.as_raw_fd(), connection.fd.as_raw_fd())?;
                        }
                    }
                }
                // Retiring a requester invalidates its prompt. Only a completely
                // verified response (or explicit refusal) permits broker reuse.
                let finished: Vec<(u64, bool)> = connections
                    .iter()
                    .filter_map(|(id, c)| {
                        if let Input::Serving { requester } = c.input {
                            match connections.get(&requester) {
                                Some(request) if request.output.is_none() => None,
                                Some(request) => Some((*id, request.approval_reusable)),
                                None => Some((*id, false)),
                            }
                        } else {
                            None
                        }
                    })
                    .collect();
                for (id, reusable) in finished {
                    if reusable {
                        let broker = connections.get_mut(&id).expect("live broker");
                        broker.input = Input::Approval;
                        register(
                            epoll.as_raw_fd(),
                            libc::EPOLL_CTL_MOD,
                            broker.fd.as_raw_fd(),
                            id,
                            false,
                            true,
                        )?;
                    } else if let Some(broker) = connections.remove(&id) {
                        unregister(epoll.as_raw_fd(), broker.fd.as_raw_fd())?;
                        unsafe {
                            libc::shutdown(broker.fd.as_raw_fd(), libc::SHUT_RDWR);
                        }
                    }
                }
                Ok(())
            })();
            if let Err(error) = iteration {
                if fatal_error.is_none() {
                    fatal_error = Some(error);
                }
                if stopping.is_none() {
                    stopping = Some(Instant::now());
                }
            }
            if stopping.is_some() {
                if !stop_notified {
                    service.stopping();
                    stop_notified = true;
                }
                execution.shutdown(false);
                context_workers.shutdown();
                // Close both listening endpoints and all control connections
                // once. Worker-held shared sockets observe shutdown immediately.
                for listener in [
                    &mut self.client,
                    &mut self.approval,
                    &mut self.context_listener,
                ] {
                    if listener.fd.is_none() {
                        continue;
                    }
                    unsafe {
                        libc::epoll_ctl(
                            epoll.as_raw_fd(),
                            libc::EPOLL_CTL_DEL,
                            listener.fd(),
                            std::ptr::null_mut(),
                        );
                        libc::shutdown(listener.fd(), libc::SHUT_RDWR);
                    }
                    listener.close();
                }
                for (_, connection) in connections.drain() {
                    let _ = unregister(epoll.as_raw_fd(), connection.fd.as_raw_fd());
                    unsafe {
                        libc::shutdown(connection.fd.as_raw_fd(), libc::SHUT_RDWR);
                    }
                }
            }
            if let Err(error) = execution.tick(epoll.as_raw_fd()) {
                if fatal_error.is_none() {
                    fatal_error = Some(error);
                }
                if stopping.is_none() {
                    stopping = Some(Instant::now());
                }
                execution.shutdown(false);
            }
            for token in execution.cancelled_connections() {
                if let Some(connection) = connections.remove(&token) {
                    let _ = unregister(epoll.as_raw_fd(), connection.fd.as_raw_fd());
                    unsafe {
                        libc::shutdown(connection.fd.as_raw_fd(), libc::SHUT_RDWR);
                    }
                }
            }
            for (token, connection) in &connections {
                if matches!(
                    connection.input,
                    Input::Executing {
                        ready_sent: true,
                        ..
                    }
                ) && let Err(error) = execution.monitor(*token)
                {
                    fatal_error.get_or_insert(error);
                    stopping.get_or_insert(Instant::now());
                    execution.shutdown(false);
                }
            }
            if stopping.is_none() {
                // File growth precedes fsync and ratchet publication. Report
                // pressure only after the durable executor closes admission,
                // so observers can synchronize without submitting more work.
                if !storage_pressure_reported
                    && storage_closed.load(std::sync::atomic::Ordering::Acquire)
                {
                    storage_pressure_reported = log
                        .try_send("{\"event\":\"STORAGE_ADMISSION_CLOSED\"}".into())
                        .is_ok();
                }
                // Do not accept an FD without reserved final-close capacity.
                // Remove level-triggered listeners while full to avoid a spin;
                // disposal completion wakes epoll so admission can resume.
                let available = self.disposal.available();
                if available != listeners_registered {
                    for (listener, token) in [
                        (&self.context_listener, CONTEXT_LISTENER),
                        (&self.client, CLIENT_LISTENER),
                        (&self.approval, APPROVAL_LISTENER),
                    ] {
                        let result = if available {
                            register(
                                epoll.as_raw_fd(),
                                libc::EPOLL_CTL_ADD,
                                listener.fd(),
                                token,
                                false,
                                true,
                            )
                        } else {
                            unregister(epoll.as_raw_fd(), listener.fd())
                        };
                        if let Err(error) = result {
                            fatal_error.get_or_insert(error);
                            stopping.get_or_insert(Instant::now());
                        }
                    }
                    listeners_registered = available;
                }
                service.tick();
            }
            if let Some(start) = stopping {
                if execution.is_idle()
                    && context_workers.is_idle()
                    && workers.is_idle()
                    && admission.is_idle()
                    && self.disposal.used() == 0
                {
                    return fatal_error.map_or(Ok(()), Err);
                }
                if !grace_reported
                    && start.elapsed()
                        >= Duration::from_millis(self.config.shutdown_grace_ms.into())
                {
                    grace_reported = true;
                    let _=log.try_send("{\"event\":\"SHUTDOWN_CLEANUP_STALLED\",\"message\":\"ownership retained; supervisor escalation required\"}".into());
                }
            }
        }
    }
}

fn unregister(epoll: RawFd, fd: RawFd) -> io::Result<()> {
    // Workers and the disposal queue can retain the socket after retirement.
    // Explicitly stop HUP/error delivery before releasing coordinator ownership.
    if unsafe { libc::epoll_ctl(epoll, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn register(
    epoll: RawFd,
    operation: i32,
    fd: RawFd,
    token: u64,
    writing: bool,
    reading: bool,
) -> io::Result<()> {
    let mut event = libc::epoll_event {
        events: (if writing {
            libc::EPOLLOUT
        } else if reading {
            libc::EPOLLIN
        } else {
            0
        }) as u32
            | libc::EPOLLRDHUP as u32,
        u64: token,
    };
    if unsafe { libc::epoll_ctl(epoll, operation, fd, &mut event) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod approval_tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sigrund_core::{
        protocol::parse_strict,
        warrant::{Csr, CsrIdentity, SnapshotDigests},
    };
    use std::{io::Read, os::unix::net::UnixStream};

    #[test]
    fn approval_deadline_rejects_late_completion_even_before_timer_dispatch() {
        let config = Arc::new(
            DaemonConfig::from_toml(
                format!(
                    "{}\n[mvp]\n",
                    include_str!("../../../config/sigrund.toml.example").replace(
                        "<strict-padded-base64-32-byte-ed25519-key>",
                        &STANDARD.encode([1; 32])
                    )
                )
                .as_bytes(),
            )
            .unwrap(),
        );
        let hello = crate::cli::RequestOptions {
            target: Some("host".into()),
            security_profile: Some("host-baseline".into()),
            ..crate::cli::RequestOptions::default()
        }
        .hello(&["/usr/bin/id".into()], Path::new("/"))
        .unwrap();
        let csr = Csr::from_unsigned(
            &hello,
            CsrIdentity {
                binding: Some({
                    use sigrund_core::host::Record;
                    sigrund_core::host::BindingBundle::parse(include_bytes!(
                        "../../sigrund-core/tests/fixtures/v3-host/bundle.json"
                    ))
                    .unwrap()
                }),
                grant_id: new_uuidv7().to_string(),
                host_id: format!("sigrun-host:sha256:{}", "0".repeat(64)),
                requester_uid: 1001,
                requester_gid: 1001,
                now: 1000,
            },
            SnapshotDigests {
                post_exec_capabilities: None,
                executable_sha256: Some("0".repeat(64)),
                executable_trust: None,
                stdin_sha256: None,
            },
            3600,
        )
        .unwrap();
        let context = Arc::new(Context {
            epoch: None,
            host_target: None,
            roots: vec![],
            host_id: csr.warrant().host_id.clone(),
            signers: SignerPolicyFile::from_toml(include_bytes!(
                "../../../config/signers.toml.example"
            ))
            .unwrap(),
        });
        let (log, _logs) = sync_channel(16);
        let mut workers = IoWorkers::new(&config).unwrap();
        let disposal = SocketDisposal::new().unwrap();
        for case in ["validation", "timer", "commit"] {
            let (socket, mut peer) = UnixStream::pair().unwrap();
            socket.set_nonblocking(true).unwrap();
            let fd = disposal.reserve().unwrap().socket(socket.into());
            let deadline = Instant::now() + crate::approver::APPROVAL_TIMEOUT;
            assert_eq!(
                crate::approver::APPROVAL_TIMEOUT,
                Duration::from_millis(120_000)
            );
            let task = workers
                .submit(42, 1001, &fd, config.clone(), false, deadline)
                .unwrap();
            let lifecycle = Arc::new(Lifecycle::new());
            assert!(lifecycle.transition(Phase::Snapshotting, Phase::Authorizing));
            let payload = String::from_utf8(csr.as_bytes().to_vec()).unwrap();
            let (durable, _audit) = sync_channel(1);
            let mut connection = Connection {
                auth_deadline: deadline,
                preparation_deadline: deadline,
                mode: "thin_csr".into(),
                full_validated: false,
                silent: false,
                retained_lease: None,
                committed_job: None,
                token: 42,
                fd,
                peer: PeerCredentials {
                    pid: std::process::id() as i32,
                    uid: 1001,
                    gid: 1001,
                },
                broker: false,
                input: Input::Validating { _task: task },
                output: None,
                audit: Admission::new(&config, Instant::now()).admit(1001, &config, Instant::now()),
                request_deadline: Some(deadline),
                exec_id: new_uuidv7().to_string(),
                policy: config.clone(),
                lifecycle,
                durable,
                approval_reserved: true,
                approval_broker: None,
                approval_csr: Some(payload.clone()),
                private_failure: None,
                provenance: serde_json::json!({"request_origin":null,"intent_sha256":null,"approval_exec_id":null}),
                approval_reusable: false,
            };
            let now = deadline + Duration::from_millis(1);
            if case == "commit" {
                assert!(
                    connection
                        .lifecycle
                        .transition(Phase::Authorizing, Phase::Committing)
                );
                assert!(
                    connection
                        .lifecycle
                        .transition(Phase::Committing, Phase::Committed)
                );
                connection.lifecycle.silence();
                let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
                assert!(raw >= 0);
                let epoll = unsafe { OwnedFd::from_raw_fd(raw) };
                register(
                    epoll.as_raw_fd(),
                    libc::EPOLL_CTL_ADD,
                    connection.fd.as_raw_fd(),
                    42,
                    false,
                    false,
                )
                .unwrap();
                let mut event: libc::epoll_event = unsafe { zeroed() };
                assert_eq!(
                    unsafe { libc::epoll_wait(epoll.as_raw_fd(), &mut event, 1, 0) },
                    0
                );
                connection
                    .timeout_after_commit(epoll.as_raw_fd(), now)
                    .unwrap();
                assert_eq!(
                    unsafe { libc::epoll_wait(epoll.as_raw_fd(), &mut event, 1, 100) },
                    1
                );
                assert_ne!(event.events & libc::EPOLLOUT as u32, 0);
            } else if case == "validation" {
                connection
                    .finish_validation(
                        Err(invalid("late result")),
                        now,
                        &log,
                        &context,
                        &SnapshotBudget::default(),
                        ApprovalAvailability::default(),
                    )
                    .unwrap();
            } else {
                assert!(connection.dispatch(42, now, &mut workers, &log).unwrap());
            }
            assert!(!connection.dispatch(42, now, &mut workers, &log).unwrap());
            let mut header = [0; 5];
            peer.read_exact(&mut header).unwrap();
            let mut body = vec![0; u32::from_be_bytes(header[1..].try_into().unwrap()) as usize];
            peer.read_exact(&mut body).unwrap();
            let decision: Decision = parse_strict(&body).unwrap();
            assert_eq!(decision.status, "TIMEOUT");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .len(),
                2
            );
            // A timer/result arriving after that decision cannot publish again.
            connection
                .finish_validation(
                    Err(invalid("stale result")),
                    now,
                    &log,
                    &context,
                    &SnapshotBudget::default(),
                    ApprovalAvailability::default(),
                )
                .unwrap();
            // A queued authorization/audit task can retain the control socket
            // after terminal delivery. Peer EOF must not wait for its fsyncs.
            let retained_control = connection.fd.clone();
            drop(connection);
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
            drop(retained_control);
            drop(peer);
            let released = Instant::now() + Duration::from_secs(2);
            loop {
                if workers.drain().iter().any(|event| {
                    matches!(
                        event,
                        Completion::Validated { token: 42, .. }
                            | Completion::Released { token: 42 }
                    )
                }) {
                    break;
                }
                assert!(Instant::now() < released);
                std::thread::yield_now();
            }
        }
    }
}
