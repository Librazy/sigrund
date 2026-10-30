//! Phase 1 foreground coordinator. It validates transport and admission only;
//! no request can be authorized or spawned before the later roadmap phases.
use crate::{
    linux::validate_absolute_path,
    startup::{StartupResources, check_root_metadata, open_pinned},
    transport::{
        ApprovalReader, ControlReader, FrameWriter, PeerCredentials, disable_ancillary_credentials,
        invalid, peer_credentials,
    },
    workers::{MetadataWorkers, ValidationHandle},
};
use sigrund_core::{
    approval::ApprovalResponse,
    config::{DaemonConfig, SignerPolicyFile},
    crypto::new_uuidv7,
    framing::FrameType,
    protocol::{ClientHello, Decision},
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
const METADATA_COMPLETE: u64 = 4;
const FIRST_CONNECTION: u64 = 5;

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
    Client(ControlReader),
    Approval(ApprovalReader),
    Validating {
        reader: ControlReader,
        _task: ValidationHandle,
    },
}

struct Connection {
    fd: OwnedFd,
    peer: PeerCredentials,
    input: Input,
    output: Option<FrameWriter>,
    request_deadline: Option<Instant>,
    exec_id: String,
    policy: Arc<DaemonConfig>,
}

impl Connection {
    fn deadline(&self) -> Option<Instant> {
        if let Some(output) = &self.output {
            return Some(output.deadline());
        }
        let frame = match &self.input {
            Input::Client(reader) => reader.deadline(),
            Input::Approval(reader) => reader.deadline(),
            Input::Validating { reader, .. } => reader.deadline(),
        };
        self.request_deadline.into_iter().chain(frame).min()
    }

    fn reject(&mut self, status: &str, message: &str, now: Instant) -> io::Result<()> {
        // Dropping the receiver closes all pending rights before sending.
        self.input = Input::Client(ControlReader::new(false));
        self.request_deadline = None;
        let decision = Decision {
            csr_payload: None,
            exec_id: self.exec_id.clone(),
            status: status.into(),
            message: message.into(),
        };
        decision.validate().map_err(|e| invalid(e.to_string()))?;
        self.output = Some(FrameWriter::control(
            FrameType::ServerAuthDecision,
            &serde_json::to_vec(&decision).map_err(|e| invalid(e.to_string()))?,
            now,
        )?);
        Ok(())
    }

    fn finish_validation(
        &mut self,
        result: io::Result<()>,
        now: Instant,
        log: &SyncSender<String>,
    ) -> io::Result<()> {
        // A timeout, disconnect, or protocol error may already have won. A
        // stale task can release resources but must not publish a decision.
        if !matches!(self.input, Input::Validating { .. }) {
            return Ok(());
        }
        if self.deadline().is_some_and(|deadline| now >= deadline)
            || result
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::TimedOut)
        {
            self.reject("REQUEST_TIMEOUT", "hello validation deadline expired", now)
        } else if result.is_ok() {
            let _ = log.try_send(serde_json::json!({"event":"CLIENT_HELLO_VALIDATED", "exec_id":self.exec_id,
                "requester_pid":self.peer.pid,"requester_uid":self.peer.uid,"requester_gid":self.peer.gid}).to_string());
            self.reject(
                "REJECTED",
                "Phase 1 transport validated; snapshotting and authorization are not implemented",
                now,
            )
        } else {
            self.reject("INVALID_REQUEST", "invalid stdio descriptors", now)
        }
    }

    fn dispatch(
        &mut self,
        token: u64,
        now: Instant,
        workers: &mut MetadataWorkers,
        log: &SyncSender<String>,
    ) -> io::Result<bool> {
        if let Some(output) = &mut self.output {
            return output
                .write(self.fd.as_raw_fd(), now)
                .map(|complete| !complete);
        }
        if self.deadline().is_some_and(|deadline| now >= deadline) {
            return match self.input {
                Input::Client(_) | Input::Validating { .. } => {
                    self.reject("REQUEST_TIMEOUT", "hello assembly deadline expired", now)?;
                    Ok(true)
                }
                Input::Approval(_) => Ok(false),
            };
        }
        match &mut self.input {
            Input::Client(reader) => {
                let result = reader.read(self.fd.as_raw_fd(), now);
                match result {
                    Ok(Some(frame)) => {
                        let hello = ClientHello::parse_request(&frame.payload)
                            .map_err(|e| invalid(e.to_string()))
                            .and_then(|hello| {
                                self.policy
                                    .mvp
                                    .as_ref()
                                    .expect("startup requires MVP")
                                    .validate_hello(&hello)
                                    .map_err(|e| invalid(e.to_string()))?;
                                Ok(hello)
                            });
                        // Parsing is part of the original cumulative deadline.
                        let after = Instant::now();
                        if self.deadline().is_some_and(|deadline| after >= deadline) {
                            self.reject(
                                "REQUEST_TIMEOUT",
                                "hello validation deadline expired",
                                after,
                            )?;
                        } else if let Ok(hello) = hello {
                            match workers.submit(
                                token,
                                self.peer.uid,
                                hello,
                                frame.rights,
                                self.deadline().expect("initial request has a deadline"),
                            ) {
                                Ok(task) => {
                                    self.input = Input::Validating {
                                        reader: ControlReader::new(false),
                                        _task: task,
                                    }
                                }
                                Err(_) => self.reject(
                                    "RESOURCE_EXHAUSTED",
                                    "descriptor validation worker quota exhausted",
                                    Instant::now(),
                                )?,
                            }
                        } else {
                            self.reject(
                                "INVALID_REQUEST",
                                "invalid hello or stdio descriptors",
                                after,
                            )?;
                        }
                    }
                    Ok(None) => {}
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
                    Err(_) => self.reject(
                        "INVALID_REQUEST",
                        "invalid framing or ancillary data",
                        Instant::now(),
                    )?,
                }
            }
            Input::Approval(reader) => {
                if let Some(payload) = reader.read(self.fd.as_raw_fd(), now)? {
                    // No Phase 1 request is awaiting a signature. Even a valid
                    // root response cannot authorize an unsolicited request.
                    let _ = ApprovalResponse::parse_jcs(&payload);
                    let _ = log.try_send("{\"event\":\"UNSOLICITED_APPROVAL_REJECTED\"}".into());
                    return Ok(false);
                }
            }
            Input::Validating { reader, .. } => {
                // Keep observing disconnects and ancillary protocol errors
                // while a worker owns the hello's descriptors.
                match reader.read(self.fd.as_raw_fd(), now) {
                    Ok(None) => {}
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
                    _ => self.reject(
                        "INVALID_REQUEST",
                        "unexpected frame during descriptor validation",
                        Instant::now(),
                    )?,
                }
            }
        }
        Ok(true)
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

    pub fn run(self) -> io::Result<()> {
        let signals = SignalSource::new()?;
        // Threads inherit the blocked signal mask, leaving shutdown handling
        // on signalfd even when a metadata syscall cannot be interrupted.
        let mut workers = MetadataWorkers::new(&self.config)?;
        let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let epoll = unsafe { OwnedFd::from_raw_fd(raw) };
        for (fd, token) in [
            (self.client.fd.as_raw_fd(), CLIENT_LISTENER),
            (self.approval.fd.as_raw_fd(), APPROVAL_LISTENER),
            (signals.fd.as_raw_fd(), SIGNALS),
            (workers.fd(), METADATA_COMPLETE),
        ] {
            register(epoll.as_raw_fd(), libc::EPOLL_CTL_ADD, fd, token, false)?;
        }
        // Diagnostic writes are off-loop and bounded. They are not audit
        // records; authorization/audit sequencing is introduced in Phase 4.
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
            serde_json::json!({"event":"DAEMON_READY", "host_id":self._resources.host_id,
            "phase":1})
            .to_string(),
        );
        let mut connections: HashMap<u64, Connection> = HashMap::new();
        let mut next_token = FIRST_CONNECTION;
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
                    }
                } else if token == METADATA_COMPLETE {
                    for completion in workers.drain() {
                        let _ = log.try_send(serde_json::json!({"event":"FD_VALIDATION_COMPLETE", "worker_task":completion.token}).to_string());
                        if let Some(mut connection) = connections.remove(&completion.token)
                            && connection
                                .finish_validation(completion.result, Instant::now(), &log)
                                .is_ok()
                        {
                            register(
                                epoll.as_raw_fd(),
                                libc::EPOLL_CTL_MOD,
                                connection.fd.as_raw_fd(),
                                completion.token,
                                connection.output.is_some(),
                            )?;
                            connections.insert(completion.token, connection);
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
                        let clients = connections
                            .values()
                            .filter(|c| !matches!(c.input, Input::Approval(_)));
                        let client_count = clients.clone().count();
                        let uid_count = clients.filter(|c| c.peer.uid == peer.uid).count();
                        if !broker
                            && (client_count >= self.config.max_active_sockets_global as usize
                                || uid_count >= self.config.max_active_sockets_per_uid as usize)
                        {
                            continue;
                        }
                        if broker
                            && connections
                                .values()
                                .any(|c| matches!(c.input, Input::Approval(_)))
                        {
                            continue;
                        }
                        if disable_ancillary_credentials(fd.as_raw_fd()).is_err() {
                            continue;
                        }
                        let connection = Connection {
                            fd,
                            peer,
                            input: if broker {
                                Input::Approval(ApprovalReader::default())
                            } else {
                                Input::Client(ControlReader::new(true))
                            },
                            output: None,
                            request_deadline: (!broker).then_some(
                                accepted
                                    + Duration::from_millis(self.config.request_deadline_ms.into()),
                            ),
                            exec_id: new_uuidv7().to_string(),
                            policy: self.config.clone(),
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
                        )?;
                        let _ = log.try_send(
                            serde_json::json!({"event":"SOCKET_ADMITTED", "broker":broker,"requester_pid":peer.pid,
                            "requester_uid":peer.uid,"requester_gid":peer.gid})
                            .to_string(),
                        );
                        connections.insert(id, connection);
                    }
                } else if let Some(mut connection) = connections.remove(&token)
                    && connection
                        .dispatch(token, Instant::now(), &mut workers, &log)
                        .unwrap_or(false)
                {
                    register(
                        epoll.as_raw_fd(),
                        libc::EPOLL_CTL_MOD,
                        connection.fd.as_raw_fd(),
                        token,
                        connection.output.is_some(),
                    )?;
                    connections.insert(token, connection);
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
                if let Some(mut connection) = connections.remove(&id)
                    && connection
                        .dispatch(id, now, &mut workers, &log)
                        .unwrap_or(false)
                {
                    register(
                        epoll.as_raw_fd(),
                        libc::EPOLL_CTL_MOD,
                        connection.fd.as_raw_fd(),
                        id,
                        connection.output.is_some(),
                    )?;
                    connections.insert(id, connection);
                }
            }
        }
    }
}

fn register(epoll: RawFd, operation: i32, fd: RawFd, token: u64, writing: bool) -> io::Result<()> {
    let mut event = libc::epoll_event {
        events: (if writing {
            libc::EPOLLOUT
        } else {
            libc::EPOLLIN
        }) as u32
            | libc::EPOLLRDHUP as u32,
        u64: token,
    };
    if unsafe { libc::epoll_ctl(epoll, operation, fd, &mut event) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
