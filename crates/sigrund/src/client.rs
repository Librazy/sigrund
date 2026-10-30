//! Stdio requester. The control coordinator never writes a caller's output
//! sink: fixed relay/writer threads retain bounded buffers through backpressure.
use crate::{
    cli::RequestOptions,
    transport::{self, ControlReader, FRAME_TIMEOUT, FrameWriter},
};
use sigrund_core::{
    framing::FrameType,
    protocol::{ChildExit, Decision, parse_strict},
    warrant::Csr,
};
use std::{
    collections::VecDeque,
    fs::File,
    io::{self, Read},
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
    time::Instant,
};

struct Signals {
    fd: OwnedFd,
    previous: libc::sigset_t,
}
impl Signals {
    fn new() -> io::Result<Self> {
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
    fn next(&self) -> io::Result<Option<u8>> {
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
fn connect(path: &Path, signals: &Signals) -> io::Result<OwnedFd> {
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
    transport::disable_ancillary_credentials(fd.as_raw_fd())?;
    if transport::peer_credentials(fd.as_raw_fd())?.uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "daemon peer is not UID 0",
        ));
    }
    Ok(fd)
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
fn escaped(message: &str) -> String {
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

pub fn run(path: &Path, command: &[String], options: &RequestOptions) -> io::Result<u8> {
    let cwd = std::env::current_dir()?;
    let hello = options
        .hello(command, &cwd)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    if options.stdin_policy == "sha256" && unsafe { libc::isatty(0) } == 1 {
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
            duplicate(fd)
        })
        .transpose()?;
    let stdout = duplicate(1)?;
    let stderr = duplicate(2)?;
    let stdin = if options.stdin_policy == "sha256" {
        Some(duplicate(0)?)
    } else {
        None
    };
    let signals = Signals::new()?;
    let socket = connect(path, &signals)?;
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
    if let Some(stdin) = stdin {
        rights.push(stdin);
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
    diagnostics.queue(b"sigrun: waiting for authorization\n".to_vec())?;
    let mut reader = ControlReader::server(FrameType::ServerAuthDecision);
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
                    if !ready {
                        let decision: Decision = parse_strict(&frame.payload)
                            .map_err(|e| transport::invalid(e.to_string()))?;
                        decision
                            .validate()
                            .map_err(|e| transport::invalid(e.to_string()))?;
                        if decision.status == "TIMEOUT_CSR" {
                            Csr::parse(
                                decision
                                    .csr_payload
                                    .as_ref()
                                    .expect("validated CSR")
                                    .as_bytes(),
                            )
                            .map_err(|e| transport::invalid(e.to_string()))?;
                        }
                        if reader
                            .deadline()
                            .is_some_and(|deadline| Instant::now() >= deadline)
                        {
                            return Err(io::ErrorKind::TimedOut.into());
                        }
                        status(&mut reporting, &frame.payload)?;
                        if decision.status == "READY_TO_EXEC" {
                            ready = true;
                            reader = ControlReader::server(FrameType::ServerChildExit);
                        } else {
                            let mut message =
                                format!("sigrun: {}\n", escaped(&decision.message)).into_bytes();
                            if let Some(csr) = decision.csr_payload {
                                message.extend_from_slice(csr.as_bytes());
                                message.push(b'\n');
                            }
                            diagnostics.queue(message)?;
                            terminal = Some(options.auth_fail_exit_code);
                            active = false;
                            unsafe {
                                libc::shutdown(socket.as_raw_fd(), libc::SHUT_RDWR);
                            }
                        }
                    } else {
                        if terminal.is_some() {
                            return Err(transport::invalid("duplicate child exit"));
                        }
                        let child: ChildExit = parse_strict(&frame.payload)
                            .map_err(|e| transport::invalid(e.to_string()))?;
                        child
                            .validate()
                            .map_err(|e| transport::invalid(e.to_string()))?;
                        if reader
                            .deadline()
                            .is_some_and(|deadline| Instant::now() >= deadline)
                        {
                            return Err(io::ErrorKind::TimedOut.into());
                        }
                        status(&mut reporting, &frame.payload)?;
                        terminal = Some(child.exit_code.unwrap_or_else(|| {
                            128 + child.signal.expect("validated child signal")
                        }));
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
