//! Stdio requester. The control coordinator never writes a caller's output
//! sink: fixed relay/writer threads retain bounded buffers through backpressure.
use crate::{
    cli::RequestOptions,
    transport::{self, ControlReader, FRAME_TIMEOUT, FrameWriter},
};
use sigrund_core::{
    framing::FrameType,
    protocol::{ClientHello, Decision, DsseEnvelope, parse_strict},
    warrant::Csr,
};
use std::{
    collections::VecDeque,
    fs::File,
    io::{self, Read, Write},
    mem::{size_of, zeroed},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
    sync::{
        Arc,
        mpsc::{self, Receiver, SyncSender},
    },
    time::{Duration, Instant},
};

pub(crate) struct Signals {
    pub(crate) fd: OwnedFd,
    previous: libc::sigset_t,
}
impl Signals {
    pub(crate) fn new() -> io::Result<Self> {
        let mut mask = unsafe { zeroed() };
        let mut previous = unsafe { zeroed() };
        unsafe {
            libc::sigemptyset(&mut mask);
            for signal in [1, 2, 10, 12, 15] {
                libc::sigaddset(&mut mask, signal);
            }
        }
        let result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
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
    pub(crate) fn next(&self) -> io::Result<Option<u8>> {
        let mut info: libc::signalfd_siginfo = unsafe { zeroed() };
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                (&mut info as *mut libc::signalfd_siginfo).cast(),
                size_of::<libc::signalfd_siginfo>(),
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if matches!(
                e.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                Ok(None)
            } else {
                Err(e)
            };
        }
        if n as usize != size_of::<libc::signalfd_siginfo>() {
            return Err(io::Error::other("short signalfd read"));
        }
        Ok(Some(info.ssi_signo as u8))
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
        }
    }
}

fn duplicate(fd: RawFd) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}

/// `fstat()` identifies the same inode, but cannot distinguish two independent
/// opens from a shell alias such as `3>&1`. Linux `kcmp(KCMP_FILE)` compares
/// the underlying open file descriptions, which is the separation required for
/// the status stream. Fail closed if the kernel cannot perform that check.
fn same_open_file_description(left: RawFd, right: RawFd) -> io::Result<bool> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_kcmp,
            libc::getpid(),
            libc::getpid(),
            0usize, // KCMP_FILE
            left as usize,
            right as usize,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result == 0)
    }
}
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut pair = [-1; 2];
    if unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) })
}
fn poll(fds: &mut [libc::pollfd], deadline: Option<Instant>) -> io::Result<()> {
    let milliseconds = deadline
        .map(|d| {
            d.saturating_duration_since(Instant::now())
                .as_millis()
                .saturating_add(1)
                .min(1000) as i32
        })
        .unwrap_or(1000);
    if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, milliseconds) } < 0
        && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
#[derive(Clone, Copy)]
#[repr(u32)]
pub(crate) enum PeerRole {
    Execution = 0,
    Context = 1,
    Anchor = 2,
    // Approval and other administrative endpoints only admit initial-userns
    // host-root authentication. Never accept a public endpoint label for them.
    HostOnly = 3,
}
pub(crate) fn connect(path: &Path, signals: &Signals, role: PeerRole) -> io::Result<OwnedFd> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= 108 || bytes.contains(&0) {
        return Err(io::Error::other("invalid socket path"));
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
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as _;
    for (to, from) in address.sun_path.iter_mut().zip(bytes) {
        *to = *from as _;
    }
    let result = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            (size_of::<libc::sa_family_t>() + bytes.len() + 1) as _,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        // AF_UNIX EAGAIN means the listen backlog is full, not an in-progress
        // connect. Never send a request on that unconnected socket.
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        let deadline = Instant::now() + FRAME_TIMEOUT;
        loop {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let mut fds = [
                libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                },
                libc::pollfd {
                    fd: signals.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            poll(&mut fds, Some(deadline))?;
            if signals.next()?.is_some() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if fds[0].revents != 0 {
                break;
            }
        }
        let mut error = 0i32;
        let mut len = size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut error as *mut i32).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
    }
    verify_daemon_peer(&fd, role)?;
    Ok(fd)
}
fn verify_daemon_peer(fd: &OwnedFd, role: PeerRole) -> io::Result<()> {
    transport::disable_ancillary_credentials(fd.as_raw_fd())?;
    if unsafe { sigrun_authenticate_host_peer(fd.as_raw_fd(), role as u32) } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "cannot authenticate host daemon: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

unsafe extern "C" {
    fn sigrun_authenticate_host_peer(socket: i32, role: u32) -> i32;
    fn sigrun_spawn_self_connector(
        public: *const libc::sockaddr_un,
        anchor: *const libc::sockaddr_un,
        pidfd: *mut i32,
        control: *mut i32,
    ) -> i32;
}
struct SelfConnector {
    pidfd: OwnedFd,
}
impl Drop for SelfConnector {
    fn drop(&mut self) {
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                0,
                0,
            );
            let mut status = zeroed::<libc::siginfo_t>();
            // A capture tracer can still own the final wait. Never hold CLI
            // completion behind privileged target disposal or a stopped tracer.
            libc::waitid(
                libc::P_PIDFD,
                self.pidfd.as_raw_fd() as u32,
                &mut status,
                libc::WEXITED | libc::WNOHANG,
            );
        }
    }
}
fn connect_self(path: &Path, signals: &Signals) -> io::Result<(OwnedFd, SelfConnector)> {
    let address = |path: &Path| -> io::Result<libc::sockaddr_un> {
        let bytes = path.as_os_str().as_bytes();
        let mut address = unsafe { zeroed::<libc::sockaddr_un>() };
        if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
            return Err(transport::invalid("invalid self connector endpoint"));
        }
        address.sun_family = libc::AF_UNIX as _;
        for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as _;
        }
        Ok(address)
    };
    let public = address(path)?;
    let anchor = address(&crate::target_management::anchor_path(path))?;
    let mut pidfd = -1;
    let mut channel = -1;
    let pid = unsafe { sigrun_spawn_self_connector(&public, &anchor, &mut pidfd, &mut channel) };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    assert!(
        pid > 0 && pidfd >= 0 && channel >= 0,
        "self connector clone ABI"
    );
    let connector = SelfConnector {
        pidfd: unsafe { OwnedFd::from_raw_fd(pidfd) },
    };
    let channel = unsafe { OwnedFd::from_raw_fd(channel) };
    let deadline = Instant::now() + FRAME_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if signals.next()?.is_some() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let mut bytes = [0u8; 2];
        if let Some(mut received) = transport::receive(channel.as_raw_fd(), &mut bytes, true)? {
            if received.length != 1 || bytes[0] != b'S' || received.rights.len() != 1 {
                return Err(transport::invalid(
                    "self connector did not transfer its request socket",
                ));
            }
            let socket = received.rights.remove(0);
            verify_daemon_peer(&socket, PeerRole::Execution)?;
            return Ok((socket, connector));
        }
        let mut fds = [
            libc::pollfd {
                fd: channel.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: signals.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        poll(&mut fds, Some(deadline))?;
    }
}

fn check_input_signals(signals: &Signals, caught: &std::cell::Cell<Option<u8>>) -> io::Result<()> {
    if let Some(signal) = signals.next()? {
        caught.set(Some(signal));
    }
    if caught.get().is_some() {
        Err(io::ErrorKind::Interrupted.into())
    } else {
        Ok(())
    }
}
struct FiniteInput<'a> {
    source: File,
    signals: &'a Signals,
    caught: &'a std::cell::Cell<Option<u8>>,
}
impl Read for FiniteInput<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            check_input_signals(self.signals, self.caught)?;
            let mut fds = [
                libc::pollfd {
                    fd: self.source.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.signals.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            poll(&mut fds, None)?;
            check_input_signals(self.signals, self.caught)?;
            if fds[0].revents != 0 {
                return self.source.read(bytes);
            }
        }
    }
}

enum Notice {
    OutputDone(usize),
    Written(usize),
    Failed,
}
struct Notify {
    sender: SyncSender<Notice>,
    wake: OwnedFd,
}
impl Notify {
    fn send(&self, notice: Notice) {
        if self.sender.send(notice).is_ok() {
            let one = 1u64;
            loop {
                if unsafe { libc::write(self.wake.as_raw_fd(), (&one as *const u64).cast(), 8) }
                    >= 0
                    || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                {
                    break;
                }
            }
        }
    }
}
fn write_sink(fd: RawFd, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n > 0 {
            bytes = &bytes[n as usize..];
            continue;
        }
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if e.kind() == io::ErrorKind::WouldBlock {
            poll(
                &mut [libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                }],
                None,
            )?;
            continue;
        }
        return Err(e);
    }
    Ok(())
}
fn relay(id: usize, input: OwnedFd, sink: OwnedFd, notify: Arc<Notify>) -> io::Result<()> {
    std::thread::Builder::new()
        .name(format!("output-{id}"))
        .spawn(move || {
            let mut input = File::from(input);
            let mut chunk = [0u8; 65_536];
            loop {
                match input.read(&mut chunk) {
                    Ok(0) => {
                        notify.send(Notice::OutputDone(id));
                        break;
                    }
                    Ok(n) => {
                        if write_sink(sink.as_raw_fd(), &chunk[..n]).is_err() {
                            notify.send(Notice::Failed);
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        notify.send(Notice::Failed);
                        break;
                    }
                }
            }
        })?;
    Ok(())
}
struct Writer {
    sender: SyncSender<Vec<u8>>,
    pending: usize,
}
impl Writer {
    fn new(id: usize, sink: OwnedFd, notify: Arc<Notify>) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(4);
        std::thread::Builder::new()
            .name(format!("status-{id}"))
            .spawn(move || {
                for bytes in receiver {
                    if write_sink(sink.as_raw_fd(), &bytes).is_err() {
                        notify.send(Notice::Failed);
                        break;
                    }
                    notify.send(Notice::Written(id));
                }
            })?;
        Ok(Self { sender, pending: 0 })
    }
    fn queue(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        self.sender
            .try_send(bytes)
            .map_err(|_| io::Error::other("bounded output queue unavailable"))?;
        self.pending += 1;
        Ok(())
    }
}
pub(crate) fn escaped(message: &str) -> String {
    let mut out = String::new();
    for ch in message.chars() {
        if (' '..='~').contains(&ch) && ch != '\\' && ch != '"' {
            out.push(ch);
        } else if ch.is_ascii() {
            out.push_str(&format!("\\x{:02X}", ch as u32));
        } else {
            out.push_str(&format!("\\u{{{:04X}}}", ch as u32));
        }
    }
    out
}
fn status(writer: &mut Option<Writer>, payload: &[u8]) -> io::Result<()> {
    if let Some(writer) = writer {
        let mut line = payload.to_vec();
        line.push(b'\n');
        writer.queue(line)?;
    }
    Ok(())
}

/// Signed input supplies every command and execution field. Never reconstruct
/// or renew its canonical payload from CLI defaults or the client environment.
fn signed_hello(bytes: &[u8]) -> io::Result<ClientHello> {
    let invalid = |error: String| io::Error::new(io::ErrorKind::InvalidInput, error);
    if bytes.len() > sigrund_core::framing::max_payload(FrameType::ClientHello) {
        return Err(invalid("signed envelope exceeds wire bound".into()));
    }
    let envelope: DsseEnvelope = parse_strict(bytes).map_err(|e| invalid(e.to_string()))?;
    let warrant = envelope.warrant().map_err(|e| invalid(e.to_string()))?;
    let hello = ClientHello {
        original_intent: None,
        csr_payload: None,
        caller_env: warrant.warrant().caller_env.clone(),
        mode: "signed".into(),
        tty_mode: warrant.warrant().command.tty_mode.clone(),
        dsse_envelope: Some(envelope),
        requested_command: None,
        requested_execution_context: None,
        requested_policy: None,
    };
    sigrund_core::config::MvpProfile::default()
        .validate_hello(&hello)
        .map_err(|e| invalid(e.to_string()))?;
    ClientHello::parse_request(&serde_json::to_vec(&hello)?).map_err(|e| invalid(e.to_string()))
}

pub(crate) fn context_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".context");
    name.into()
}
fn public_context(
    path: &Path,
    signals: &Signals,
) -> io::Result<sigrund_core::protocol::PublicContext> {
    let socket = connect(&context_path(path), signals, PeerRole::Context)?;
    let deadline = Instant::now() + transport::FRAME_TIMEOUT;
    let mut writer = FrameWriter::control(
        FrameType::ClientContextQuery,
        br#"{"version":"3.0"}"#,
        Instant::now(),
    )?;
    while !writer.write(socket.as_raw_fd(), Instant::now())? {
        if signals.next()?.is_some() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        poll(
            &mut [libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            }],
            Some(deadline),
        )?;
    }
    let mut reader = ControlReader::server(FrameType::ServerContext);
    let result = loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if let Some(frame) = reader.read(socket.as_raw_fd(), Instant::now())? {
            break parse_strict::<sigrund_core::protocol::PublicContext>(&frame.payload)
                .map_err(|e| transport::invalid(e.to_string()))?;
        }
        if signals.next()?.is_some() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        poll(
            &mut [libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }],
            Some(deadline),
        )?;
    };
    sigrund_core::host::Record::validate(&result).map_err(io::Error::other)?;
    Ok(result)
}
fn full_csr(
    hello: &ClientHello,
    public: &sigrund_core::protocol::PublicContext,
    stdin_sha256: Option<String>,
    purpose: crate::executable::EvidencePurpose,
    binding_path: Option<&Path>,
) -> io::Result<Csr> {
    use sigrund_core::host::Record;
    let path =
        binding_path.ok_or_else(|| transport::invalid("trusted host binding bundle required"))?;
    let mut bytes = Vec::new();
    File::open(path)?.take(65_537).read_to_end(&mut bytes)?;
    let bundle = sigrund_core::host::BindingBundle::parse(&bytes).map_err(io::Error::other)?;
    let original = hello
        .original_intent
        .as_ref()
        .ok_or_else(|| transport::invalid("missing original intent"))?;
    if bundle.host_id != public.host_id
        || bundle.constraints.profile_id != original.security_profile
        || bundle.constraints.capabilities != original.execution_context.capabilities
    {
        return Err(transport::invalid(
            "host bundle authority or profile differs",
        ));
    }
    let (root, relative) = crate::host_target::preparation_root(
        &bundle,
        Path::new(&original.command.executable_path),
    )?;
    let mut hello = hello.clone();
    let (uid, gid, groups) = crate::accounts::resolve(&original.account)?;
    hello.requested_execution_context = Some(original.execution_context.resolve(uid, gid, groups));
    let mut public = public.clone();
    if !public
        .executable_trust_models
        .contains(&bundle.constraints.executable_model)
    {
        return Err(transport::invalid("bound executable model unavailable"));
    }
    public.executable_trust_models = vec![bundle.constraints.executable_model];
    let intent = hello
        .intent()
        .map_err(|e| transport::invalid(e.to_string()))?;
    let source: File = crate::linux::openat2_file(root.as_raw_fd(), &relative)?.into();
    let deadline =
        Instant::now() + Duration::from_millis(public.limits.direct_digest_timeout_ms.into());
    let (trust, profile) = crate::executable::client_evidence(
        &source,
        &intent.execution_context,
        &public,
        &bundle.admin_trusted_composefs_mounts,
        purpose,
        || {
            if Instant::now() >= deadline {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Ok(())
            }
        },
    )?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    Csr::from_unsigned(
        &hello,
        sigrund_core::warrant::CsrIdentity {
            binding: Some(bundle),
            grant_id: sigrund_core::crypto::new_uuidv7().to_string(),
            host_id: public.host_id.clone(),
            requester_uid: unsafe { libc::getuid() },
            requester_gid: unsafe { libc::getgid() },
            now: i64::try_from(now).map_err(io::Error::other)?,
        },
        sigrund_core::warrant::SnapshotDigests {
            executable_trust: Some(trust),
            post_exec_capabilities: Some(profile),
            executable_sha256: None,
            stdin_sha256,
        },
        public
            .limits
            .max_ttl_secs
            .min(public.limits.max_onetime_window_secs),
    )
    .map_err(|e| transport::invalid(e.to_string()))
}

pub fn run(path: &Path, command: &[String], options: &RequestOptions) -> io::Result<u8> {
    let mut hello = if let Some(path) = &options.warrant {
        let mut bytes = Vec::new();
        File::open(path)?
            .take(sigrund_core::framing::max_payload(FrameType::ClientHello) as u64 + 1)
            .read_to_end(&mut bytes)?;
        signed_hello(&bytes)?
    } else {
        let cwd = std::env::current_dir()?;
        options
            .hello(command, &cwd)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
    };
    let hash_stdin = if let Some(envelope) = &hello.dsse_envelope {
        envelope
            .warrant()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
            .warrant()
            .command
            .stdin_policy
            == "sha256"
    } else {
        hello
            .requested_command
            .as_ref()
            .expect("unsigned request")
            .stdin_policy
            == "sha256"
    };
    if hash_stdin && unsafe { libc::isatty(0) } == 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hashed stdin cannot be a TTY",
        ));
    }
    // Capture caller descriptors before allocating sockets/pipes/signalfds.
    // Otherwise an originally closed status/stdin FD could name one of ours.
    let report = options
        .status_fd
        .map(|fd| {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || flags & libc::O_PATH != 0 || flags & libc::O_ACCMODE == libc::O_RDONLY {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "status FD must be an open writable descriptor",
                ));
            }
            if same_open_file_description(fd, 1)? || same_open_file_description(fd, 2)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "status FD must not alias stdout or stderr",
                ));
            }
            duplicate(fd)
        })
        .transpose()?;
    let stdout = duplicate(1)?;
    let stderr = duplicate(2)?;
    let stdin = if hash_stdin {
        Some(duplicate(0)?)
    } else {
        None
    };
    let signals = Signals::new()?;
    let public = if options.warrant.is_none() {
        Some(public_context(path, &signals)?)
    } else {
        None
    };
    let spool = if let Some(source) = stdin {
        let maximum = public
            .as_ref()
            .map_or(16_777_216, |p| p.limits.max_stdin_bytes);
        let caught = std::cell::Cell::new(None);
        let mut input = FiniteInput {
            source: File::from(source),
            signals: &signals,
            caught: &caught,
        };
        let mut output = crate::memfd::create("sigrun-input-spool", false)?;
        let digest =
            sigrund_core::snapshot::copy_stream(&mut input, &mut output, None, maximum, || {
                check_input_signals(&signals, &caught)
            });
        if let Some(signal) = caught.get() {
            return Ok(128 + signal);
        }
        let digest = digest?;
        Some((crate::memfd::seal(output, 0o400)?, digest))
    } else {
        None
    };
    let cross_domain = !matches!(
        hello.original_intent().map_err(io::Error::other)?.target,
        sigrund_core::host::Selector::Host {}
    );
    if cross_domain
        && (options.full_only || options.export_csr.is_some() || options.binding_bundle.is_some())
    {
        return Err(transport::invalid(
            "cross-domain full preparation is unavailable",
        ));
    }
    if public.is_none() && options.full_only {
        return Err(transport::invalid(
            "public context required for full preparation",
        ));
    }
    let mut thin_fallback = false;
    if let Some(public) = public.as_ref().filter(|_| !cross_domain) {
        let purpose = if options.export_csr.is_some() {
            crate::executable::EvidencePurpose::OfflineExport
        } else {
            crate::executable::EvidencePurpose::Online
        };
        match full_csr(
            &hello,
            public,
            spool.as_ref().map(|s| s.1.sha256.clone()),
            purpose,
            options.binding_bundle.as_deref(),
        ) {
            Ok(csr) => {
                if let Some(export) = &options.export_csr {
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(export)?;
                    file.write_all(csr.as_bytes())?;
                    file.sync_all()?;
                    return Ok(0);
                }
                hello.mode = "full_csr".into();
                hello.csr_payload = Some(String::from_utf8(csr.as_bytes().to_vec()).expect("JCS"));
            }
            Err(error) if options.full_only || options.export_csr.is_some() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("cannot prepare full CSR: {error}"),
                ));
            }
            Err(_) => thin_fallback = true,
        }
    }
    let (socket, _self_connector) = if hello.mode == "thin_csr"
        && matches!(
            hello.original_intent().map_err(io::Error::other)?.target,
            sigrund_core::host::Selector::Self_ {}
        ) {
        let (socket, connector) = connect_self(path, &signals)?;
        (socket, Some(connector))
    } else {
        (connect(path, &signals, PeerRole::Execution)?, None)
    };
    let wake_raw = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if wake_raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let (sent, notices): (SyncSender<Notice>, Receiver<Notice>) = mpsc::sync_channel(32);
    let notify = Arc::new(Notify {
        sender: sent,
        wake: unsafe { OwnedFd::from_raw_fd(wake_raw) },
    });
    let (out_r, out_w) = pipe()?;
    let (err_r, err_w) = pipe()?;
    let mut rights = Vec::with_capacity(3);
    if let Some(spool) = &spool {
        use std::os::fd::AsFd;
        rights.push(spool.0.as_fd().try_clone_to_owned()?);
    }
    rights.extend([out_w, err_w]);
    let mut outgoing = Some(FrameWriter::hello(
        &serde_json::to_vec(&hello)?,
        rights,
        Instant::now(),
    )?);
    let mut queued = VecDeque::new();
    // No caller sink is accessed on the control thread once the request starts.
    relay(0, out_r, stdout, notify.clone())?;
    relay(1, err_r, stderr.try_clone()?, notify.clone())?;
    let mut diagnostics = Writer::new(2, stderr, notify.clone())?;
    let mut reporting = report
        .map(|fd| Writer::new(3, fd, notify.clone()))
        .transpose()?;
    if thin_fallback {
        diagnostics.queue(
            b"sigrun: local full preparation unavailable; submitting thin intent\n".to_vec(),
        )?;
    }
    diagnostics.queue(b"sigrun: waiting for authorization\n".to_vec())?;
    let mut reader = ControlReader::server(FrameType::ServerAuthDecision);
    let mut approved = false;
    let mut execution_id = None;
    let mut ready = false;
    let mut terminal = None;
    let mut drain = false;
    let mut active = true;
    let mut outputs = [false; 2];
    loop {
        let mut one = 0u64;
        unsafe {
            libc::read(notify.wake.as_raw_fd(), (&mut one as *mut u64).cast(), 8);
        }
        while let Ok(notice) = notices.try_recv() {
            match notice {
                Notice::OutputDone(id) => outputs[id] = true,
                Notice::Written(2) => diagnostics.pending -= 1,
                Notice::Written(3) => reporting.as_mut().expect("status writer").pending -= 1,
                Notice::Written(_) => unreachable!(),
                Notice::Failed => {
                    unsafe {
                        libc::shutdown(socket.as_raw_fd(), libc::SHUT_RDWR);
                    }
                    return Ok(254);
                }
            }
        }
        while let Some(signal) = signals.next()? {
            if !ready || terminal.is_some() {
                unsafe {
                    libc::shutdown(socket.as_raw_fd(), libc::SHUT_RDWR);
                }
                return Ok(128 + signal);
            }
            if queued.len() >= 16 {
                unsafe {
                    libc::shutdown(socket.as_raw_fd(), libc::SHUT_RDWR);
                }
                return Ok(254);
            }
            queued.push_back(FrameWriter::control(
                FrameType::ClientSignal,
                format!("{{\"signal\":{signal}}}").as_bytes(),
                Instant::now(),
            )?);
        }
        if let Some(code) = terminal
            && (!drain || outputs.iter().all(|done| *done))
            && diagnostics.pending == 0
            && reporting.as_ref().is_none_or(|w| w.pending == 0)
        {
            return Ok(code);
        }
        if outgoing.is_none() {
            outgoing = queued.pop_front();
        }
        if active {
            let progress = (|| -> io::Result<()> {
                if let Some(writer) = &mut outgoing
                    && writer.write(socket.as_raw_fd(), Instant::now())?
                {
                    outgoing = None;
                }
                if let Some(frame) = reader.read(socket.as_raw_fd(), Instant::now())? {
                    if !approved {
                        let decision: Decision = parse_strict(&frame.payload)
                            .map_err(|e| transport::invalid(e.to_string()))?;
                        decision
                            .validate()
                            .map_err(|e| transport::invalid(e.to_string()))?;
                        execution_id = Some(decision.exec_id.clone());
                        status(&mut reporting, &frame.payload)?;
                        if decision.status == "APPROVED" {
                            approved = true;
                            reader = ControlReader::server_execution();
                        } else {
                            diagnostics
                                .queue(format!("sigrun: {}\n", decision.status).into_bytes())?;
                            terminal = Some(options.auth_fail_exit_code);
                            active = false;
                            unsafe {
                                libc::shutdown(socket.as_raw_fd(), libc::SHUT_RDWR);
                            }
                        }
                    } else if frame.kind == FrameType::ServerExecReady {
                        if ready || terminal.is_some() {
                            return Err(transport::invalid("duplicate readiness"));
                        }
                        let notice: sigrund_core::protocol::ExecReady =
                            parse_strict(&frame.payload)
                                .map_err(|e| transport::invalid(e.to_string()))?;
                        notice
                            .validate()
                            .map_err(|e| transport::invalid(e.to_string()))?;
                        if execution_id.as_ref() != Some(&notice.exec_id) {
                            return Err(transport::invalid("execution ID mismatch"));
                        }
                        status(&mut reporting, &frame.payload)?;
                        ready = true;
                        reader = ControlReader::server(FrameType::ServerExecResult);
                    } else {
                        if terminal.is_some() {
                            return Err(transport::invalid("duplicate execution result"));
                        }
                        let result: sigrund_core::protocol::ExecResult =
                            parse_strict(&frame.payload)
                                .map_err(|e| transport::invalid(e.to_string()))?;
                        result
                            .validate()
                            .map_err(|e| transport::invalid(e.to_string()))?;
                        if execution_id.as_ref() != Some(&result.exec_id) {
                            return Err(transport::invalid("execution ID mismatch"));
                        }
                        status(&mut reporting, &frame.payload)?;
                        terminal = Some(if result.status == "EXITED" {
                            result
                                .exit_code
                                .unwrap_or_else(|| 128 + result.signal.expect("validated signal"))
                        } else {
                            254
                        });
                        drain = true;
                        reader = ControlReader::server_finished();
                    }
                }
                Ok(())
            })();
            if let Err(error) = progress {
                if error.kind() == io::ErrorKind::UnexpectedEof && terminal.is_some() && drain {
                    active = false;
                } else {
                    let code = if matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                    ) {
                        "DAEMON_DISCONNECTED"
                    } else {
                        "SERVER_PROTOCOL_ERROR"
                    };
                    status(
                        &mut reporting,
                        format!("{{\"error\":\"{code}\"}}").as_bytes(),
                    )?;
                    diagnostics.queue(format!("sigrun: {code}\n").into_bytes())?;
                    unsafe {
                        libc::shutdown(socket.as_raw_fd(), libc::SHUT_RDWR);
                    }
                    active = false;
                    terminal = Some(254);
                    drain = false;
                    outgoing = None;
                    queued.clear();
                }
            }
        }
        let deadline = if active {
            reader
                .deadline()
                .into_iter()
                .chain(outgoing.as_ref().map(FrameWriter::deadline))
                .min()
        } else {
            None
        };
        let mut fds = [
            libc::pollfd {
                fd: if active { socket.as_raw_fd() } else { -1 },
                events: libc::POLLIN | if outgoing.is_some() { libc::POLLOUT } else { 0 },
                revents: 0,
            },
            libc::pollfd {
                fd: signals.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: notify.wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        poll(&mut fds, deadline)?;
    }
}

/// Connect a disposable, single-threaded anchor to an authenticated host peer.
/// Successful capture holds this process until the daemon disposes the target.
pub fn run_dedicated_anchor(path: &Path) -> io::Result<()> {
    unsafe extern "C" {
        fn sigrun_run_dedicated_anchor(address: *const libc::sockaddr_un) -> i32;
    }
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::other("invalid rendezvous path"));
    }
    address.sun_family = libc::AF_UNIX as _;
    for (target, source) in address.sun_path.iter_mut().zip(bytes) {
        *target = *source as libc::c_char;
    }
    if unsafe { sigrun_run_dedicated_anchor(&address) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Err(io::Error::other("anchor unexpectedly returned"))
}

#[cfg(test)]
mod signed_input_tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sigrund_core::{
        crypto::WARRANT_PAYLOAD_TYPE,
        protocol::{DsseEnvelope, DsseSignature},
        warrant::{CanonicalWarrant, CsrIdentity, SnapshotDigests},
    };

    fn envelope(hashed_stdin: bool) -> DsseEnvelope {
        let options = RequestOptions {
            stdin_policy: if hashed_stdin { "sha256" } else { "null" }.into(),
            cwd: Some("/signed-directory".into()),
            target: Some("host".into()),
            security_profile: Some("host-baseline".into()),
            ..RequestOptions::default()
        };
        let hello = options
            .hello(
                &["/usr/bin/id".into(), "two words".into(), "".into()],
                Path::new("/"),
            )
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
                grant_id: "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f".into(),
                host_id: format!("sigrun-host:sha256:{}", "1".repeat(64)),
                requester_uid: 1001,
                requester_gid: 1001,
                now: 1000,
            },
            SnapshotDigests {
                post_exec_capabilities: None,
                executable_sha256: Some("2".repeat(64)),
                executable_trust: None,
                stdin_sha256: hashed_stdin.then(|| "3".repeat(64)),
            },
            3600,
        )
        .unwrap();
        DsseEnvelope::from_warrant(
            &CanonicalWarrant::parse(csr.as_bytes()).unwrap(),
            vec![DsseSignature {
                keyid: "fixture-signer".into(),
                sig: STANDARD.encode([0; 64]),
            }],
        )
        .unwrap()
    }

    #[test]
    fn signed_input_preserves_every_payload_byte_and_derives_stdin_from_the_warrant() {
        for hashed in [false, true] {
            let envelope = envelope(hashed);
            let hello = signed_hello(&serde_json::to_vec(&envelope).unwrap()).unwrap();
            assert_eq!(hello.mode, "signed");
            assert!(hello.requested_command.is_none());
            assert!(hello.requested_execution_context.is_none());
            assert!(hello.requested_policy.is_none());
            assert!(hello.caller_env.is_empty());
            assert_eq!(hello.dsse_envelope.as_ref(), Some(&envelope));
            let signed = hello.dsse_envelope.unwrap().warrant().unwrap();
            assert_eq!(signed.warrant().command.cwd, "/signed-directory");
            assert_eq!(
                signed.warrant().command.argv,
                ["/usr/bin/id", "two words", ""]
            );
            assert_eq!(
                signed.warrant().command.stdin_policy,
                if hashed { "sha256" } else { "null" }
            );
            assert_eq!(signed.warrant().policy.not_before, 1000);
            assert_eq!(signed.warrant().policy.not_after, Some(1900));
        }
    }

    #[test]
    fn signed_input_accepts_v2_envelopes_above_the_legacy_wire_limit() {
        let original = envelope(false);
        let mut warrant = original.warrant().unwrap().warrant().clone();
        warrant.command.argv.extend(vec!["a".repeat(4000); 6]);
        crate::synchronize_test_intent(&mut warrant);
        let envelope = DsseEnvelope::from_warrant(
            &CanonicalWarrant::new(warrant).unwrap(),
            (0..4)
                .map(|index| DsseSignature {
                    keyid: format!("signer-{index}"),
                    sig: STANDARD.encode(vec![0; 24_576]),
                })
                .collect(),
        )
        .unwrap();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        assert!(bytes.len() > 196_608);
        assert_eq!(signed_hello(&bytes).unwrap().dsse_envelope, Some(envelope));
    }

    #[test]
    fn malformed_and_unsupported_signed_input_fails_before_transport() {
        for bytes in [b"{}".to_vec(), b"not json".to_vec(), vec![b' '; 524_289]] {
            assert_eq!(
                signed_hello(&bytes).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let original = envelope(false);
        for mutation in ["mode", "script", "allowlist"] {
            let mut warrant = original.warrant().unwrap().warrant().clone();
            match mutation {
                "mode" => warrant.policy.mode = "time_range".into(),
                "script" => warrant.command.allow_interpreted_script = true,
                "allowlist" => warrant
                    .execution_context
                    .caller_env_allowlist
                    .push("USER".into()),
                _ => unreachable!(),
            }
            crate::synchronize_test_intent(&mut warrant);
            let envelope = DsseEnvelope::from_warrant(
                &CanonicalWarrant::new(warrant).unwrap(),
                original.signatures.clone(),
            )
            .unwrap();
            assert!(
                signed_hello(&serde_json::to_vec(&envelope).unwrap()).is_err(),
                "{mutation}"
            );
        }
        let mut wrong = original.clone();
        wrong.payload_type = "wrong".into();
        assert!(signed_hello(&serde_json::to_vec(&wrong).unwrap()).is_err());
        let mut wrong = original;
        wrong.payload = STANDARD.encode(b"{} ");
        assert!(signed_hello(&serde_json::to_vec(&wrong).unwrap()).is_err());
        assert_eq!(
            WARRANT_PAYLOAD_TYPE,
            "application/vnd.sigrun.warrant.v3+json"
        );
    }
}
