//! Foreground coordinator for snapshots, approval and durable authorization.
//! Child setup and readiness remain the Phase 5 execution boundary.
use crate::{
    admission::{Admission, AuditLease},
    linux::validate_absolute_path,
    preparation::{self, Context, Document, PinnedRoot},
    sequencer::{self, Sequencer},
    snapshot::SnapshotBudget,
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
const FIRST_CONNECTION: u64 = 6;

struct BoundSocket {
    fd: OwnedFd,
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
            fd,
            parent,
            name,
            inode: metadata.ino(),
            device: metadata.dev(),
        };
        if metadata.uid() != 0 || metadata.gid() != 0 {
            return Err(invalid("socket must be owned by root:root"));
        }
        fs::set_permissions(&pinned, fs::Permissions::from_mode(mode))?;
        if unsafe { libc::listen(bound.fd.as_raw_fd(), 64) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(bound)
    }

    fn accept(&self) -> io::Result<Option<OwnedFd>> {
        let fd = unsafe {
            libc::accept4(
                self.fd.as_raw_fd(),
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
        Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
    }
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
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
}

impl SignalSource {
    fn new() -> io::Result<Self> {
        let mut mask = unsafe { zeroed() };
        let mut previous = unsafe { zeroed() };
        unsafe {
            libc::sigemptyset(&mut mask);
            for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                libc::sigaddset(&mut mask, signal);
            }
        }
        let result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
        if fd < 0 {
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
            }
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            previous,
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
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
        }
    }
}

enum Input {
    Client,
    Approval,
    Serving { requester: u64 },
    Validating { _task: ValidationHandle },
    Authorizing { _task: ValidationHandle },
}

struct Connection {
    token: u64,
    fd: OwnedFd,
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
}

#[derive(Default)]
struct ApprovalAvailability {
    busy: bool,
    broker: Option<(u64, OwnedFd)>,
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
        csr_payload: Option<String>,
        now: Instant,
        audited: bool,
    ) -> io::Result<()> {
        let phase = self.lifecycle.state().0;
        let outcome = if status == "REQUEST_TIMEOUT" {
            LifecycleDecision::Timeout
        } else {
            LifecycleDecision::Rejected
        };
        if !self.lifecycle.claim_terminal(phase, outcome) {
            return Err(invalid("decision already claimed"));
        }
        // Cancelling a task never closes its caller rights on this thread.
        self.input = Input::Client;
        self.request_deadline = None;
        self.approval_reserved = false;
        let decision = Decision {
            csr_payload,
            exec_id: self.exec_id.clone(),
            status: status.into(),
            message: message.into(),
        };
        decision.validate().map_err(|e| invalid(e.to_string()))?;
        if !audited {
            self.queue_decision_audit(&decision)?;
        }
        self.output = Some(FrameWriter::control(
            FrameType::ServerAuthDecision,
            &serde_json::to_vec(&decision).map_err(|e| invalid(e.to_string()))?,
            now,
        )?);
        Ok(())
    }

    fn reading(&self) -> bool {
        self.output.is_none()
            && !matches!(
                self.input,
                Input::Validating { .. } | Input::Authorizing { .. } | Input::Serving { .. }
            )
    }

    fn queue_decision_audit(&mut self, decision: &Decision) -> io::Result<()> {
        let Some(audit) = self.audit.take() else {
            return Ok(());
        };
        let work = sequencer::Work::Event {
            token: self.token,
            event_type: "AUTH_REJECTED",
            fields: serde_json::json!({"exec_id":self.exec_id,"requester_uid":self.peer.uid,
                "requester_gid":self.peer.gid,"status":decision.status,"message":decision.message}),
            limit: self.policy.audit_record_max_bytes as usize,
            _audit: audit,
        };
        self.durable
            .try_send(work)
            .map_err(|_| invalid("reserved audit executor capacity unavailable"))
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
        // A timeout, disconnect, or protocol error may already have won. A
        // stale task can release resources but must not publish a decision.
        if !matches!(self.input, Input::Validating { .. }) {
            return Ok(());
        }
        if self.broker {
            let _ = log.try_send("{\"event\":\"UNSOLICITED_APPROVAL_REJECTED\"}".into());
            return Err(invalid("unsolicited approval response"));
        }
        if self.deadline().is_some_and(|deadline| now >= deadline)
            || result
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::TimedOut)
        {
            if let Some(csr) = self.approval_csr.clone() {
                self.respond(
                    "TIMEOUT_CSR",
                    "local approval deadline expired",
                    Some(csr),
                    now,
                )
            } else {
                self.reject("REQUEST_TIMEOUT", "hello validation deadline expired", now)
            }
        } else if let Ok(lease) = &result {
            if !lease.matches_admission(self.peer.uid, &self.policy) {
                return Err(invalid("request admission mismatch"));
            }
            if let Some(prepared) = lease.prepared() {
                if self.approval_csr.is_none()
                    && !self
                        .lifecycle
                        .transition(Phase::Snapshotting, Phase::Authorizing)
                {
                    return Err(invalid("stale snapshot handoff"));
                }
                self.request_deadline = None;
                let _ = log.try_send(serde_json::json!({"event":"SNAPSHOTS_PREPARED", "exec_id":self.exec_id,
                    "root_path":prepared.root_path,"root_device":prepared.root_identity.device,"root_inode":prepared.root_identity.inode,
                    "source_device":prepared.source_identity.device,"source_inode":prepared.source_identity.inode,
                    "null_stdin":prepared.null_stdin.is_some()}).to_string());
                match &prepared.document {
                    Document::Unsigned(csr) => {
                        let signer_id = self
                            .policy
                            .mvp
                            .as_ref()
                            .expect("MVP")
                            .approval_signer_id
                            .clone();
                        let csr_payload =
                            String::from_utf8(csr.as_bytes().to_vec()).expect("canonical UTF-8");
                        if signer_id.is_empty() || availability.broker.is_none() {
                            return self.respond(
                                "TIMEOUT_CSR",
                                "No local approver is available",
                                Some(csr_payload),
                                now,
                            );
                        }
                        let approval = ApprovalRequest::new(self.exec_id.clone(), signer_id, csr)
                            .map_err(|e| invalid(e.to_string()))?;
                        let (broker_token, socket) =
                            availability.broker.expect("authenticated broker");
                        let deadline = now + crate::approver::APPROVAL_TIMEOUT;
                        self.request_deadline = Some(deadline);
                        self.approval_csr = Some(csr_payload);
                        self.approval_broker = Some(broker_token);
                        let mut lease = result.expect("successful snapshots");
                        lease.begin_approval(deadline);
                        let context = context.clone();
                        let gid = self.peer.gid;
                        lease.continue_on_worker(move |request| {
                            preparation::approve(request, &context, gid, approval, socket)
                        });
                        Ok(())
                    }
                    Document::Signed {
                        warrant,
                        signer_ids,
                    } => {
                        self.approval_reusable = self.approval_csr.is_some();
                        let _ = log.try_send(serde_json::json!({"event":"SIGNED_SNAPSHOTS_BOUND", "exec_id":self.exec_id, "grant_id":warrant.warrant().grant_id,"candidate_signer_ids":signer_ids}).to_string());
                        let mut lease = result.expect("verified signed snapshots");
                        lease.begin_authorization();
                        let work = sequencer::Work::Authorize(sequencer::AuthorizationTask {
                            token: self.token,
                            exec_id: self.exec_id.clone(),
                            gid: self.peer.gid,
                            lifecycle: self.lifecycle.clone(),
                            lease,
                            control: self.fd.try_clone()?,
                            audit: self
                                .audit
                                .take()
                                .ok_or_else(|| invalid("missing audit reservation"))?,
                        });
                        if let Err(error) = self.durable.try_send(work) {
                            let work = match error {
                                std::sync::mpsc::TrySendError::Full(work) => work,
                                std::sync::mpsc::TrySendError::Disconnected(_) => {
                                    return Err(invalid("audit executor stopped"));
                                }
                            };
                            if let sequencer::Work::Authorize(task) = work {
                                self.audit = Some(task.audit);
                            }
                            return self.reject(
                                "RESOURCE_EXHAUSTED",
                                "authorization executor is full",
                                now,
                            );
                        }
                        let Input::Validating { _task } =
                            std::mem::replace(&mut self.input, Input::Client)
                        else {
                            unreachable!()
                        };
                        self.input = Input::Authorizing { _task };
                        self.approval_reserved = false;
                        Ok(())
                    }
                }
            } else {
                if lease.hello().mode == "unsigned_csr_request" {
                    if !lease.unsigned_policy_checked() {
                        let lease = result.expect("validated hello");
                        let context = context.clone();
                        let gid = self.peer.gid;
                        lease.continue_on_worker(move |request| {
                            preparation::check_unsigned_policy(request, &context, gid)
                        });
                        return Ok(());
                    }
                    if availability.busy {
                        return self.reject(
                            "RESOURCE_EXHAUSTED",
                            "local approval slot is busy",
                            now,
                        );
                    }
                    self.approval_reserved = true;
                }
                let _ = log.try_send(serde_json::json!({"event":"CLIENT_HELLO_VALIDATED", "exec_id":self.exec_id,
                "requester_pid":self.peer.pid,"requester_uid":self.peer.uid,"requester_gid":self.peer.gid,"request_mode":lease.hello().mode}).to_string());
                let lease = result.expect("successful lease");
                let context = context.clone();
                let budget = budget.clone();
                let gid = self.peer.gid;
                lease.continue_on_worker(move |request| {
                    preparation::prepare(request, &context, &budget, gid)
                });
                Ok(())
            }
        } else if let Some(failure) = result
            .as_ref()
            .err()
            .and_then(|error| error.get_ref())
            .and_then(|error| error.downcast_ref::<preparation::Failure>())
        {
            self.approval_reusable = failure.status == "REJECTED";
            if failure.status == "TIMEOUT_CSR" {
                self.respond(
                    "TIMEOUT_CSR",
                    &failure.to_string(),
                    self.approval_csr.clone(),
                    now,
                )
            } else {
                self.reject(failure.status, &failure.to_string(), now)
            }
        } else if result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
        {
            self.reject("POLICY_VIOLATION", "unsupported MVP request", now)
        } else {
            self.reject(
                "INVALID_REQUEST",
                "invalid request or stdio descriptors",
                now,
            )
        }
    }

    fn dispatch(
        &mut self,
        token: u64,
        now: Instant,
        workers: &mut IoWorkers,
        log: &SyncSender<String>,
    ) -> io::Result<bool> {
        if let Some(output) = &mut self.output {
            return output
                .write(self.fd.as_raw_fd(), now)
                .map(|complete| !complete);
        }
        if self.deadline().is_some_and(|deadline| now >= deadline) {
            return match self.input {
                Input::Client | Input::Validating { .. } => {
                    if let Some(csr) = self.approval_csr.clone() {
                        self.respond(
                            "TIMEOUT_CSR",
                            "local approval deadline expired",
                            Some(csr),
                            now,
                        )?;
                    } else {
                        self.reject("REQUEST_TIMEOUT", "hello assembly deadline expired", now)?;
                    }
                    Ok(true)
                }
                Input::Approval | Input::Serving { .. } | Input::Authorizing { .. } => Ok(false),
            };
        }
        match &self.input {
            Input::Client | Input::Approval => {
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
            Input::Validating { .. } | Input::Serving { .. } | Input::Authorizing { .. } => {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.lifecycle.cancel();
        if self.audit.is_some() {
            let decision = Decision {
                csr_payload: None,
                exec_id: self.exec_id.clone(),
                status: "REJECTED".into(),
                message: "request disconnected before authorization".into(),
            };
            let _ = self.queue_decision_audit(&decision);
        }
    }
}

pub struct ForegroundDaemon {
    client: BoundSocket,
    approval: BoundSocket,
    _resources: StartupResources,
    config: Arc<DaemonConfig>,
    _signers: SignerPolicyFile,
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
        config.validate().map_err(|e| invalid(e.to_string()))?;
        signers
            .validate_against(&config)
            .map_err(|e| invalid(e.to_string()))?;
        let resources = StartupResources::prepare(&config, state_dir, log_path)?;
        let client = BoundSocket::bind(socket, 0o666)?;
        let approval = BoundSocket::bind(approval_socket, 0o600)?;
        Ok(Self {
            client,
            approval,
            _resources: resources,
            config: Arc::new(config),
            _signers: signers,
        })
    }

    pub fn run(mut self) -> io::Result<()> {
        let context = Arc::new(Context {
            roots: self
                .config
                .csr_allowed_executable_dirs
                .iter()
                .cloned()
                .zip(std::mem::take(&mut self._resources.roots))
                .map(|(path, directory)| PinnedRoot { path, directory })
                .collect(),
            host_id: self._resources.host_id.clone(),
            signers: self._signers.clone(),
        });
        let budget = SnapshotBudget::default();
        let signals = SignalSource::new()?;
        // Threads inherit the blocked signal mask, leaving shutdown handling
        // on signalfd even when a metadata syscall cannot be interrupted.
        let mut workers = IoWorkers::new(&self.config)?;
        let storage_closed = self._resources.storage.closed.clone();
        let mut admission = Admission::new(&self.config, Instant::now());
        let sequencer_capacity = (self.config.max_pending_audits_global as usize)
            .checked_mul(2)
            .ok_or_else(|| invalid("sequencer capacity overflow"))?;
        let sequencer = Sequencer::new(
            self._resources,
            context.clone(),
            self.config.clone(),
            sequencer_capacity,
        )?;
        let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let epoll = unsafe { OwnedFd::from_raw_fd(raw) };
        for (fd, token) in [
            (self.client.fd.as_raw_fd(), CLIENT_LISTENER),
            (self.approval.fd.as_raw_fd(), APPROVAL_LISTENER),
            (signals.fd.as_raw_fd(), SIGNALS),
            (workers.fd(), IO_COMPLETE),
            (sequencer.fd(), AUDIT_COMPLETE),
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
            "phase":4, "local_audit_forward_secure":false})
            .to_string(),
        );
        let mut connections: HashMap<u64, Connection> = HashMap::new();
        let mut next_token = FIRST_CONNECTION;
        let mut reload_diagnostic_pending = false;
        let mut events: [libc::epoll_event; 64] = unsafe { zeroed() };
        loop {
            let now = Instant::now();
            let timeout = connections
                .values()
                .filter_map(Connection::deadline)
                .min()
                .map(|deadline| deadline.saturating_duration_since(now))
                .unwrap_or(Duration::from_secs(1));
            let milliseconds = timeout.as_millis().saturating_add(1).min(1000) as i32;
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
                    continue;
                }
                return Err(error);
            }
            for event in &events[..count as usize] {
                let token = event.u64;
                if token == SIGNALS {
                    while let Some(signal) = signals.next()? {
                        if signal == libc::SIGINT as u32 || signal == libc::SIGTERM as u32 {
                            return Ok(());
                        }
                        let _ = log.try_send("{\"event\":\"RELOAD_UNAVAILABLE\",\"message\":\"reload is outside the Phase 1 MVP\"}".into());
                        reload_diagnostic_pending = true;
                    }
                } else if token == AUDIT_COMPLETE {
                    for completion in sequencer.drain() {
                        match completion {
                            sequencer::Completion::Reserve { token, permit } => {
                                let allowed = connections.get(&token).is_some_and(|c| {
                                    matches!(c.input, Input::Authorizing { .. })
                                        && sequencer::connection_live(c.fd.as_raw_fd())
                                        && !c
                                            .lifecycle
                                            .cancelled
                                            .load(std::sync::atomic::Ordering::Acquire)
                                        && c.lifecycle
                                            .transition(Phase::Authorizing, Phase::Committing)
                                });
                                let _ = permit.send(allowed);
                            }
                            sequencer::Completion::Finished {
                                token,
                                lease,
                                denial,
                            } => {
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
                                        true,
                                        false,
                                    )?;
                                }
                                drop(lease);
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
                                        true,
                                        false,
                                    )?;
                                }
                            }
                            sequencer::Completion::Fatal(error) => {
                                return Err(invalid(format!(
                                    "durable executor failed closed: {error}"
                                )));
                            }
                        }
                    }
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
                            let approval_busy = connections
                                .values()
                                .any(|c| c.approval_reserved && c.output.is_none());
                            let broker = if result.as_ref().is_ok_and(|lease| {
                                lease
                                    .prepared()
                                    .is_some_and(|p| matches!(p.document, Document::Unsigned(_)))
                            }) {
                                connections
                                    .iter()
                                    .find(|(_, c)| c.broker && matches!(c.input, Input::Approval))
                                    .map(|(id, c)| c.fd.try_clone().map(|fd| (*id, fd)))
                                    .transpose()?
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
                } else if token == CLIENT_LISTENER || token == APPROVAL_LISTENER {
                    let listener = if token == CLIENT_LISTENER {
                        &self.client
                    } else {
                        &self.approval
                    };
                    // An accept flood cannot starve active frames or timers.
                    for _ in 0..64 {
                        let Some(fd) = listener.accept()? else {
                            break;
                        };
                        let accepted = Instant::now();
                        let Ok(peer) = peer_credentials(fd.as_raw_fd()) else {
                            // SO_PEERCRED can contain pid=0 for an ancestor
                            // PID-namespace peer. Reject this connection only.
                            continue;
                        };
                        let broker = token == APPROVAL_LISTENER;
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
                                    + Duration::from_millis(self.config.request_deadline_ms.into()),
                            ),
                            exec_id: new_uuidv7().to_string(),
                            policy: self.config.clone(),
                            lifecycle: Arc::new(Lifecycle::new()),
                            durable: sequencer.sender(),
                            approval_reserved: false,
                            approval_broker: None,
                            approval_csr: None,
                            approval_reusable: false,
                        };
                        let id = next_token;
                        next_token = next_token
                            .checked_add(1)
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
            if let Some((audit, refused)) =
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
        }
    }
}

fn unregister(epoll: RawFd, fd: RawFd) -> io::Result<()> {
    // A worker can retain a duplicate during blocked caller-FD disposal.
    // Closing only the coordinator's copy does not remove the registration
    // until every duplicate closes, so explicitly stop HUP/error delivery.
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
        let hello = crate::cli::RequestOptions::default()
            .hello(&["/usr/bin/id".into()], Path::new("/"))
            .unwrap();
        let csr = Csr::from_unsigned(
            &hello,
            CsrIdentity {
                grant_id: new_uuidv7().to_string(),
                host_id: format!("sigrun-host:sha256:{}", "0".repeat(64)),
                requester_uid: 1001,
                requester_gid: 1001,
                now: 1000,
            },
            SnapshotDigests {
                executable_sha256: "0".repeat(64),
                stdin_sha256: None,
            },
            3600,
        )
        .unwrap();
        let context = Arc::new(Context {
            roots: vec![],
            host_id: csr.warrant().host_id.clone(),
            signers: SignerPolicyFile::from_toml(include_bytes!(
                "../../../config/signers.toml.example"
            ))
            .unwrap(),
        });
        let (log, _logs) = sync_channel(16);
        let mut workers = IoWorkers::new(&config).unwrap();
        for completion_first in [true, false] {
            let (socket, mut peer) = UnixStream::pair().unwrap();
            socket.set_nonblocking(true).unwrap();
            let fd: OwnedFd = socket.into();
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
                approval_reusable: false,
            };
            let now = deadline + Duration::from_millis(1);
            if completion_first {
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
            assert_eq!(decision.status, "TIMEOUT_CSR");
            assert_eq!(decision.csr_payload.as_deref(), Some(payload.as_str()));
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
            drop(connection);
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
