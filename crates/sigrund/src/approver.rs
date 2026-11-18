//! Root TTY approval. Request bytes never supply paths or helper arguments.
use crate::{
    cli::ApprovalArgs,
    client::Signals,
    startup::{check_root_metadata, open_pinned, read_root_file},
    transport::{
        ApprovalReader, FrameWriter, disable_ancillary_credentials, invalid, peer_credentials,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sigrund_core::{
    approval::{ApprovalRequest, ApprovalResponse},
    config::{SignerConfig, SignerPolicyFile},
    crypto::{WARRANT_PAYLOAD_TYPE, pae, verify_ssh_signature},
    warrant::{CanonicalWarrant, Csr},
};
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, SshSig, encoding::Encode};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(test)]
pub(crate) const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_ARMOR: usize = 34_000;

fn nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub(crate) fn poll(descriptors: &mut [libc::pollfd], deadline: Option<Instant>) -> io::Result<()> {
    let timeout = deadline
        .map(|d| {
            d.saturating_duration_since(Instant::now())
                .as_millis()
                .saturating_add(1)
                .min(250) as i32
        })
        .unwrap_or(250);
    if unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, timeout) } < 0
        && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub(crate) fn event(fd: RawFd, events: i16) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

pub(crate) fn check_terminal_event(tty: libc::pollfd) -> io::Result<()> {
    if tty.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        Err(io::Error::other("operator terminal lost"))
    } else {
        Ok(())
    }
}

/// The socket must stay quiet while a request is displayed/signed. Peeking
/// creates no userspace rights; any unexpected input is a terminal fault.
fn check(socket: &UnixStream, signals: &Signals, deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    if signals.next()?.is_some() {
        return Err(io::ErrorKind::Interrupted.into());
    }
    let mut byte = 0u8;
    let result = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if result == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if result > 0 {
        return Err(invalid("unexpected broker input during approval"));
    }
    let error = io::Error::last_os_error();
    if !matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) {
        return Err(error);
    }
    Ok(())
}

pub fn run(args: &ApprovalArgs) -> io::Result<u8> {
    run_with(args, false)
}

pub fn run_tui(args: &ApprovalArgs) -> io::Result<u8> {
    run_with(args, true)
}

fn run_with(args: &ApprovalArgs, tui: bool) -> io::Result<u8> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approver requires UID 0",
        ));
    }
    let identity = args
        .identity
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--identity is required"))?;
    let tty = open_tty(&args.tty)?;
    let credentials = Credentials::load(&args.signers, identity)?;
    let signals = if tui {
        Signals::for_approval_tui()?
    } else {
        Signals::new()?
    };
    let mut socket = connect_broker(&args.socket, &signals)?;
    let mut screen;
    let frontend: &mut dyn Frontend = if tui {
        screen = crate::approval_tui::Screen::new(&tty);
        &mut screen
    } else {
        &mut Text
    };
    loop {
        let error = match watch_broker(
            &tty,
            &credentials,
            &socket,
            &signals,
            &args.epoch_file,
            frontend,
        ) {
            Ok(()) => return Ok(0),
            Err(error) if recoverable_connection_error(&error) => error,
            Err(error) => return Err(error),
        };
        // A timed-out or cancelled exchange is never reused. The daemon must
        // retire it before a fresh connection can receive another request.
        let _ = socket.shutdown(std::net::Shutdown::Both);
        drop(socket);
        frontend.reconnecting(&tty, &error)?;
        let Some(connected) = reconnect_broker(&args.socket, &signals, &tty, frontend)? else {
            return Ok(0);
        };
        socket = connected;
    }
}

struct Credentials {
    identity: File,
    signers: SignerPolicyFile,
    public: PublicKey,
}

impl Credentials {
    fn load(signers: &Path, identity: &Path) -> io::Result<Self> {
        let signers = load_signers(signers)?;
        let identity_file = open_pinned(identity)?;
        check_root_metadata(&identity_file, false, None)?;
        let mut bytes = Vec::new();
        (&identity_file).take(1_048_577).read_to_end(&mut bytes)?;
        if bytes.len() > 1_048_576 {
            return Err(invalid("SSH identity exceeds size bound"));
        }
        let public = match PublicKey::from_openssh(
            std::str::from_utf8(&bytes).map_err(|_| invalid("SSH identity is not UTF-8"))?,
        ) {
            Ok(public) => public,
            Err(_) => {
                if identity_file.metadata()?.mode() & 0o077 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "private SSH identity must be private to root",
                    ));
                }
                let private = PrivateKey::from_openssh(&bytes)
                    .map_err(|_| invalid("invalid SSH identity"))?;
                private.public_key().clone()
            }
        };
        bytes.fill(0);
        // This descriptor's open description is shared with the helper. Rewind it
        // before use and inherit only this deliberate identity handle.
        if unsafe { libc::lseek(identity_file.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            identity: identity_file,
            signers,
            public,
        })
    }
}

fn recoverable_connection_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

fn reconnect_broker(
    path: &Path,
    signals: &Signals,
    tty: &File,
    frontend: &mut dyn Frontend,
) -> io::Result<Option<UnixStream>> {
    loop {
        if signals.next()?.is_some() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        // Do not spin if the daemon has not yet retired the old connection or
        // is restarting. Polling also keeps local cancellation responsive.
        let mut events = [
            event(signals.fd.as_raw_fd(), libc::POLLIN),
            event(tty.as_raw_fd(), frontend.tty_events()),
        ];
        poll(&mut events, None)?;
        check_terminal_event(events[1])?;
        if signals.next()?.is_some() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if frontend.idle(false)? {
            return Ok(None);
        }
        match connect_broker(path, signals) {
            Ok(socket) => return Ok(Some(socket)),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) => {}
            Err(error) => return Err(error),
        }
    }
}

pub(crate) enum Decision {
    Approve,
    Reject,
    InvalidWarrant,
    TerminalEof,
    Quit,
}

pub(crate) struct Review {
    pub(crate) exec_id: String,
    pub(crate) signer_id: String,
    pub(crate) csr: Csr,
    pub(crate) details: String,
    pub(crate) target: &'static str,
    pub(crate) full_host_root: bool,
}

pub(crate) struct Exchange<'a> {
    socket: &'a UnixStream,
    signals: &'a Signals,
    pub(crate) deadline: Instant,
}

impl Exchange<'_> {
    pub(crate) fn check(&self) -> io::Result<()> {
        check(self.socket, self.signals, self.deadline)
    }

    pub(crate) fn wait_input(&self, tty: &File, refresh: Instant) -> io::Result<()> {
        poll(
            &mut [
                event(tty.as_raw_fd(), libc::POLLIN),
                event(self.socket.as_raw_fd(), libc::POLLIN),
                event(self.signals.fd.as_raw_fd(), libc::POLLIN),
            ],
            Some(self.deadline.min(refresh)),
        )
    }
}

pub(crate) trait Frontend {
    fn tty_events(&self) -> i16 {
        0
    }
    fn idle(&mut self, _connected: bool) -> io::Result<bool> {
        Ok(false)
    }
    fn review(
        &mut self,
        tty: &File,
        review: &Review,
        exchange: &Exchange<'_>,
    ) -> io::Result<Decision>;
    fn before_signing(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn decision_sent(&mut self) {}
    fn submission_interrupted(&mut self) {}
    fn reconnecting(&mut self, tty: &File, error: &io::Error) -> io::Result<()>;
}

struct Text;

impl Frontend for Text {
    fn review(
        &mut self,
        tty: &File,
        review: &Review,
        exchange: &Exchange<'_>,
    ) -> io::Result<Decision> {
        write_tty(
            tty,
            review.details.as_bytes(),
            exchange.socket,
            exchange.signals,
            exchange.deadline,
        )?;
        if !valid_now(&review.csr) {
            return Ok(Decision::InvalidWarrant);
        }
        Ok(
            match confirm(tty, exchange.socket, exchange.signals, exchange.deadline)? {
                Some(true) => Decision::Approve,
                Some(false) => Decision::Reject,
                None => Decision::TerminalEof,
            },
        )
    }

    fn reconnecting(&mut self, tty: &File, error: &io::Error) -> io::Result<()> {
        discard_confirmation_input(tty)?;
        eprintln!("\nsigrund-approve: approval connection ended ({error}); waiting to reconnect");
        Ok(())
    }
}

fn watch_broker(
    tty: &File,
    credentials: &Credentials,
    socket: &UnixStream,
    signals: &Signals,
    epoch_file: &Path,
    frontend: &mut dyn Frontend,
) -> io::Result<()> {
    loop {
        let mut reader = ApprovalReader::default();
        let request = loop {
            if signals.next()?.is_some() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if frontend.idle(true)? {
                return Ok(());
            }
            if let Some(bytes) = reader.read(socket.as_raw_fd(), Instant::now())? {
                break ApprovalRequest::parse_jcs(&bytes).map_err(|e| invalid(e.to_string()))?;
            }
            let mut events = [
                event(socket.as_raw_fd(), libc::POLLIN),
                event(signals.fd.as_raw_fd(), libc::POLLIN),
                event(tty.as_raw_fd(), frontend.tty_events()),
            ];
            poll(&mut events, reader.deadline())?;
            check_terminal_event(events[2])?;
        };
        let deadline = Instant::now() + Duration::from_millis(request.remaining_ms.into());
        let signer = credentials
            .signers
            .signers
            .iter()
            .find(|s| s.signer_id == request.signer_id)
            .ok_or_else(|| invalid("requested signer is not configured"))?;
        let configured = PublicKey::from_openssh(&signer.public_key)
            .map_err(|_| invalid("invalid configured SSH key"))?;
        if configured.key_data() != credentials.public.key_data() {
            return Err(invalid("explicit identity does not match requested signer"));
        }
        let csr = Csr::parse(request.csr_payload.as_bytes()).map_err(io::Error::other)?;
        let (details, target, full_host_root) = if matches!(
            csr.warrant().intent.target,
            sigrund_core::host::Selector::Host {}
        ) {
            let (bundle, composefs) =
                crate::host_registry::live_review(epoch_file, &request.exec_id, &csr)?;
            (
                render_request(&request, &csr, signer, &bundle, composefs)?,
                "Host",
                bundle.constraints.workload == Some(sigrund_core::workload::Workload::Root),
            )
        } else {
            let review =
                crate::host_registry::live_process_review(epoch_file, &request.exec_id, &csr)?;
            (
                render_process_request(&request, &csr, signer, &review)?,
                if review.constraints.executes() {
                    "Namespace execution"
                } else {
                    "Namespace review (execution disabled)"
                },
                review.constraints.workload() == Some(sigrund_core::workload::Workload::Root),
            )
        };
        let review = Review {
            exec_id: request.exec_id,
            signer_id: request.signer_id,
            csr,
            details,
            target,
            full_host_root,
        };
        let exchange = Exchange {
            socket,
            signals,
            deadline,
        };
        let decision = frontend.review(tty, &review, &exchange)?;
        let Some(response) = respond(
            tty,
            &credentials.identity,
            signer,
            &review,
            decision,
            &exchange,
            frontend,
        )?
        else {
            return Ok(());
        };
        if let Err(error) = submit(&exchange, &response) {
            frontend.submission_interrupted();
            return Err(error);
        }
        frontend.decision_sent();
    }
}

fn submit(exchange: &Exchange<'_>, response: &ApprovalResponse) -> io::Result<()> {
    let mut writer = FrameWriter::approval(
        &response.to_jcs().map_err(|e| invalid(e.to_string()))?,
        Instant::now(),
    )?;
    loop {
        exchange.check()?;
        if writer.write(exchange.socket.as_raw_fd(), Instant::now())? {
            return Ok(());
        }
        poll(
            &mut [
                event(exchange.socket.as_raw_fd(), libc::POLLOUT),
                event(exchange.signals.fd.as_raw_fd(), libc::POLLIN),
            ],
            Some(writer.deadline().min(exchange.deadline)),
        )?;
    }
}

fn open_tty(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let control = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/tty")?;
    let mut device = 0 as libc::dev_t;
    let mut selected_device = 0 as libc::dev_t;
    if unsafe { libc::ioctl(control.as_raw_fd(), libc::TIOCGDEV, &mut device) } < 0
        || unsafe { libc::ioctl(file.as_raw_fd(), libc::TIOCGDEV, &mut selected_device) } < 0
        || unsafe { libc::isatty(file.as_raw_fd()) } != 1
        || selected_device != device
        || unsafe { libc::tcgetpgrp(file.as_raw_fd()) } != unsafe { libc::getpgrp() }
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approval TTY must be the controlling foreground terminal",
        ));
    }
    Ok(file)
}

fn load_signers(path: &Path) -> io::Result<SignerPolicyFile> {
    let bytes = read_root_file(path, None, 1_048_576)?;
    let signers = SignerPolicyFile::from_toml(&bytes).map_err(|e| invalid(e.to_string()))?;
    let mut seen = BTreeSet::new();
    for signer in &signers.signers {
        if !seen.insert(&signer.signer_id)
            || signer.signer_id.is_empty()
            || signer.signer_id.len() > 128
            || !signer.signer_id.is_ascii()
            || signer.signer_id.bytes().any(|b| b.is_ascii_control())
        {
            return Err(invalid("invalid or duplicate signer identity"));
        }
        let key = PublicKey::from_openssh(&signer.public_key)
            .map_err(|_| invalid("invalid SSH signer public key"))?;
        if !matches!(
            (signer.signature_type.as_str(), key.algorithm()),
            ("ssh-ed25519", Algorithm::Ed25519) | ("sk-ssh-ed25519", Algorithm::SkEd25519)
        ) || (signer.signature_type == "ssh-ed25519"
            && (signer.require_user_presence || signer.require_user_verification))
        {
            return Err(invalid("unsupported SSH signer policy"));
        }
    }
    Ok(signers)
}

fn connect_broker(path: &Path, signals: &Signals) -> io::Result<UnixStream> {
    crate::linux::validate_absolute_path(path)?;
    let parent = open_pinned(
        path.parent()
            .ok_or_else(|| invalid("broker needs a parent"))?,
    )?;
    check_root_metadata(&parent, true, None)?;
    let pinned = std::path::PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(
        path.file_name()
            .ok_or_else(|| invalid("broker needs a filename"))?,
    );
    let metadata = fs::symlink_metadata(&pinned)?;
    if metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & libc::S_IFMT != libc::S_IFSOCK
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted broker socket",
        ));
    }
    let socket = UnixStream::from(crate::client::connect(
        &pinned,
        signals,
        crate::client::PeerRole::HostOnly,
    )?);
    socket.set_nonblocking(true)?;
    disable_ancillary_credentials(socket.as_raw_fd())?;
    if peer_credentials(socket.as_raw_fd())?.uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker peer is not UID 0",
        ));
    }
    Ok(socket)
}

fn write_tty(
    mut tty: &File,
    mut bytes: &[u8],
    socket: &UnixStream,
    signals: &Signals,
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        check(socket, signals, deadline)?;
        match tty.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                poll(
                    &mut [
                        event(tty.as_raw_fd(), libc::POLLOUT),
                        event(socket.as_raw_fd(), libc::POLLIN),
                        event(signals.fd.as_raw_fd(), libc::POLLIN),
                    ],
                    Some(deadline),
                )?
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn valid_now(csr: &Csr) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_secs()).ok());
    now.is_some_and(|now| {
        now >= csr.warrant().policy.not_before
            && csr.warrant().policy.not_after.is_some_and(|end| now <= end)
    })
}

pub(crate) fn discard_confirmation_input(tty: &File) -> io::Result<()> {
    // Drop complete lines and unfinished canonical input (for example a lone
    // 'y' left by a cancelled request). Pre-prompt input is not confirmation.
    if unsafe { libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn respond(
    tty: &File,
    identity: &File,
    signer: &SignerConfig,
    review: &Review,
    decision: Decision,
    exchange: &Exchange<'_>,
    frontend: &mut dyn Frontend,
) -> io::Result<Option<ApprovalResponse>> {
    let refused = |reason: &str| ApprovalResponse::Rejected {
        exec_id: review.exec_id.clone(),
        reason: reason.into(),
    };
    match decision {
        Decision::Quit => return Ok(None),
        Decision::Reject => return Ok(Some(refused("operator refused approval"))),
        Decision::InvalidWarrant => return Ok(Some(refused("warrant expired or not yet valid"))),
        Decision::TerminalEof => return Ok(Some(refused("operator terminal EOF"))),
        Decision::Approve => {}
    }
    if !valid_now(&review.csr) {
        return Ok(Some(refused("warrant expired while awaiting confirmation")));
    }
    frontend.before_signing()?;
    let signature = sign_payload(identity, tty, signer, review.csr.as_bytes(), || {
        exchange.check()
    })?;
    if !valid_now(&review.csr) {
        return Ok(Some(refused("warrant expired while signing")));
    }
    let warrant =
        CanonicalWarrant::parse(review.csr.as_bytes()).map_err(|e| invalid(e.to_string()))?;
    let envelope = sigrund_core::protocol::DsseEnvelope::from_warrant(
        &warrant,
        vec![sigrund_core::protocol::DsseSignature {
            keyid: signer.signer_id.clone(),
            sig: signature,
        }],
    )
    .map_err(|e| invalid(e.to_string()))?;
    Ok(Some(ApprovalResponse::Approved {
        exec_id: review.exec_id.clone(),
        dsse_envelope: envelope,
    }))
}

fn confirm(
    tty: &File,
    socket: &UnixStream,
    signals: &Signals,
    deadline: Instant,
) -> io::Result<Option<bool>> {
    let mut input = tty;
    let mut answer = Vec::with_capacity(16);
    let mut oversized = false;
    write_tty(
        tty,
        b"Approve and sign? [y/yes/n/no] ",
        socket,
        signals,
        deadline,
    )?;
    discard_confirmation_input(tty)?;
    loop {
        check(socket, signals, deadline)?;
        let mut byte = [0];
        match input.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) => {
                if byte[0] == b'\n' {
                    if !oversized {
                        match answer.as_slice() {
                            b"y" | b"yes" => return Ok(Some(true)),
                            b"n" | b"no" => return Ok(Some(false)),
                            _ => {}
                        }
                    }
                    write_tty(
                        tty,
                        b"Enter y or yes to approve, n or no to reject.\nApprove and sign? [y/yes/n/no] ",
                        socket,
                        signals,
                        deadline,
                    )?;
                    discard_confirmation_input(tty)?;
                    answer.clear();
                    oversized = false;
                } else if answer.len() < 16 {
                    answer.push(byte[0]);
                } else {
                    // Drain the rest of an overlong line with bounded memory;
                    // its prefix must never be treated as a valid answer.
                    oversized = true;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                poll(
                    &mut [
                        event(tty.as_raw_fd(), libc::POLLIN),
                        event(socket.as_raw_fd(), libc::POLLIN),
                        event(signals.fd.as_raw_fd(), libc::POLLIN),
                    ],
                    Some(deadline),
                )?
            }
            Err(error) => return Err(error),
        }
    }
}

/// Every leaf and empty container is rendered; indexed argv and escaped key
/// names make both argument and environment boundaries visible. Only ASCII
/// escapes are emitted for request data, including Unicode/BiDi and controls.
fn walk(path: String, value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Array(items) if !items.is_empty() => {
            for (i, v) in items.iter().enumerate() {
                walk(format!("{path}[{i}]"), v, out);
            }
        }
        serde_json::Value::Object(items) if !items.is_empty() => {
            for (k, v) in items {
                walk(format!("{path}[{}]", quote(k)), v, out);
            }
        }
        serde_json::Value::String(s) => out.push_str(&format!("{path} = {}\n", quote(s))),
        v => out.push_str(&format!("{path} = {v}\n")),
    }
}

fn render_request(
    request: &ApprovalRequest,
    csr: &Csr,
    signer: &SignerConfig,
    bundle: &sigrund_core::host::BindingBundle,
    admin_trusted_composefs: bool,
) -> io::Result<String> {
    let key = PublicKey::from_openssh(&signer.public_key)
        .map_err(|_| invalid("invalid configured SSH key"))?;
    let mut out = format!(
        "\nElevation request\nexec_id = {}\nsigner_id = {}\nkey_fingerprint = {}\nalgorithm = {}\nrequire_user_presence = {}\nrequire_user_verification = {}\n",
        quote(&request.exec_id),
        quote(&signer.signer_id),
        key.fingerprint(HashAlg::Sha256),
        quote(&signer.signature_type),
        signer.require_user_presence,
        signer.require_user_verification
    );
    walk(
        "csr".into(),
        &serde_json::from_slice::<serde_json::Value>(csr.as_bytes())
            .map_err(|e| invalid(e.to_string()))?,
        &mut out,
    );
    let evidence =
        sigrund_core::v3::approval_evidence(csr.warrant(), bundle).map_err(io::Error::other)?;
    walk(
        "verified_host".into(),
        &serde_json::from_str(&evidence).map_err(io::Error::other)?,
        &mut out,
    );
    if admin_trusted_composefs {
        out.push_str("executable_storage = administrator-maintained ComposeFS; backing objects must remain unchanged during execution\n");
    }
    if let Some(workload) = bundle.constraints.workload {
        out.push_str(&format!(
            "workload_authority = {}\nworkload_selinux_context = {}\n",
            quote(workload.authority()),
            quote(workload.context())
        ));
    }
    out.push_str(&format!(
        "umask_octal = {:03o}\n",
        csr.warrant().execution_context.umask
    ));
    Ok(out)
}
fn render_process_request(
    request: &ApprovalRequest,
    csr: &Csr,
    signer: &SignerConfig,
    review: &sigrund_core::namespace::ProcessReview,
) -> io::Result<String> {
    let evidence = review.render(csr).map_err(io::Error::other)?;
    let key = PublicKey::from_openssh(&signer.public_key)
        .map_err(|_| invalid("invalid configured SSH key"))?;
    let mut out = format!(
        "\n{}\nexec_id = {}\nsigner_id = {}\nkey_fingerprint = {}\n",
        if review.constraints.executes() {
            "Namespace execution request"
        } else {
            "Namespace private review (execution disabled)"
        },
        quote(&request.exec_id),
        quote(&signer.signer_id),
        key.fingerprint(HashAlg::Sha256)
    );
    walk(
        "csr".into(),
        &serde_json::from_slice(csr.as_bytes()).map_err(io::Error::other)?,
        &mut out,
    );
    walk(
        "verified_process".into(),
        &serde_json::from_str(&evidence).map_err(io::Error::other)?,
        &mut out,
    );
    Ok(out)
}

pub(crate) fn quote(value: &str) -> String {
    let mut result = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            ' '..='~' => result.push(c),
            _ => result.push_str(&format!("\\u{{{:04X}}}", c as u32)),
        }
    }
    result.push('"');
    result
}
struct Helper<'a> {
    process: Child,
    tty: &'a File,
    settings: Option<libc::termios>,
}
impl<'a> Helper<'a> {
    fn spawn(command: &mut Command, tty: &'a File) -> io::Result<Self> {
        let mut settings = unsafe { std::mem::zeroed() };
        loop {
            if unsafe { libc::tcgetattr(tty.as_raw_fd(), &mut settings) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Ok(Self {
            process: command.spawn()?,
            tty,
            settings: Some(settings),
        })
    }
    fn restore_terminal(&mut self) -> io::Result<()> {
        if let Some(settings) = &self.settings {
            loop {
                if unsafe { libc::tcsetattr(self.tty.as_raw_fd(), libc::TCSANOW, settings) } == 0 {
                    self.settings = None;
                    break;
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}
impl Drop for Helper<'_> {
    fn drop(&mut self) {
        // A killed OpenSSH passphrase reader cannot restore its own termios.
        // Reap first so it cannot change the terminal again after restoration.
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = self.restore_terminal();
    }
}
fn sign_payload(
    identity: &File,
    tty: &File,
    signer: &SignerConfig,
    payload: &[u8],
    check: impl Fn() -> io::Result<()>,
) -> io::Result<String> {
    sign_with_helper(
        Path::new("/usr/bin/ssh-keygen"),
        identity,
        tty,
        signer,
        payload,
        check,
    )
}
fn sign_with_helper(
    helper: &Path,
    identity: &File,
    tty: &File,
    signer: &SignerConfig,
    payload: &[u8],
    check: impl Fn() -> io::Result<()>,
) -> io::Result<String> {
    check()?;
    let fd = identity.as_raw_fd();
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut command = Command::new(helper);
    command
        .args([
            "-Y",
            "sign",
            "-n",
            "sigrun.warrant.v3",
            "-O",
            "hashalg=sha512",
            "-f",
        ])
        .arg(format!("/proc/self/fd/{fd}"))
        // Passphrases belong on the verified controlling terminal, even when
        // the operator's launch environment would force an askpass program.
        .env("SSH_ASKPASS_REQUIRE", "never")
        .env_remove("SSH_ASKPASS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(tty.try_clone()?));
    // Restore an ordinary mask in the exec'd helper. Only syscalls run in the
    // post-fork child; parent cancellation always kills/reaps this child.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut mask = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            let result = libc::pthread_sigmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut());
            if result != 0 {
                return Err(io::Error::from_raw_os_error(result));
            }
            Ok(())
        });
    }
    let mut child = Helper::spawn(&mut command, tty)?;
    let mut input = child.process.stdin.take();
    let mut output = child.process.stdout.take().expect("helper stdout");
    nonblocking(input.as_ref().unwrap().as_raw_fd())?;
    nonblocking(output.as_raw_fd())?;
    let message = pae(WARRANT_PAYLOAD_TYPE, payload);
    let mut sent = 0;
    let mut armor = Vec::new();
    let mut eof = false;
    let mut status = None;
    while !eof || status.is_none() {
        check()?;
        if let Some(stdin) = &mut input {
            match stdin.write(&message[sent..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => sent += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
            if sent == message.len() {
                input = None;
            }
        }
        let mut chunk = [0u8; 4096];
        match output.read(&mut chunk) {
            Ok(0) => eof = true,
            Ok(n) => {
                if armor.len() + n > MAX_ARMOR {
                    return Err(invalid("signing helper output exceeds limit"));
                }
                armor.extend_from_slice(&chunk[..n]);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
        if status.is_none() {
            status = child.process.try_wait()?;
        }
        if status.is_some_and(|s| !s.success()) {
            return Err(invalid("SSH signing helper failed"));
        }
        poll(
            &mut [
                event(if eof { -1 } else { output.as_raw_fd() }, libc::POLLIN),
                event(input.as_ref().map_or(-1, AsRawFd::as_raw_fd), libc::POLLOUT),
            ],
            Some(Instant::now() + Duration::from_millis(20)),
        )?;
    }
    child.restore_terminal()?;
    check()?;
    if sent != message.len() {
        return Err(invalid("incomplete SSH signing input"));
    }
    let signature =
        SshSig::from_pem(&armor).map_err(|_| invalid("invalid armored SSHSIG output"))?;
    let encoded = STANDARD.encode(
        signature
            .encode_vec()
            .map_err(|_| invalid("invalid SSHSIG output"))?,
    );
    verify_ssh_signature(
        &signer.signature_type,
        &signer.public_key,
        &encoded,
        WARRANT_PAYLOAD_TYPE,
        payload,
        signer.require_user_presence,
        signer.require_user_verification,
    )
    .map_err(|e| invalid(e.to_string()))?;
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::{fd::FromRawFd, unix::fs::PermissionsExt};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn terminal() -> (File, File) {
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let pair = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        for fd in [master, slave] {
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
        }
        pair
    }

    fn confirmation_terminal() -> (File, File) {
        let (master, tty) = terminal();
        // Packet mode reports the post-prompt TCIFLUSH, so the simulated
        // operator can wait until confirmation actually accepts input.
        let enabled: libc::c_int = 1;
        assert_eq!(
            unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCPKT, &enabled) },
            0
        );
        (master, tty)
    }

    #[test]
    fn text_approver_exits_when_idle_terminal_hangs_up() {
        let (master, tty) = terminal();
        let directory = tempfile::tempdir().unwrap();
        let (identity, signer) = identity(directory.path(), "operator");
        let public = PublicKey::from_openssh(&signer.public_key).unwrap();
        let credentials = Credentials {
            identity,
            public,
            signers: SignerPolicyFile {
                signers: vec![signer],
            },
        };
        let (socket, peer) = UnixStream::pair().unwrap();
        let signals = Signals::new().unwrap();
        drop(master);
        std::thread::scope(|scope| {
            let (done, finished) = std::sync::mpsc::channel();
            let watchdog = scope.spawn(move || {
                if finished.recv_timeout(Duration::from_secs(2)).is_err() {
                    peer.shutdown(std::net::Shutdown::Both).unwrap();
                }
            });
            let error = watch_broker(
                &tty,
                &credentials,
                &socket,
                &signals,
                directory.path(),
                &mut Text,
            )
            .unwrap_err();
            let _ = done.send(());
            watchdog.join().unwrap();
            assert_eq!(error.to_string(), "operator terminal lost");
        });
    }

    #[test]
    fn tui_pty_discards_queued_decisions_and_restores_terminal_after_disconnect() {
        fn await_text(master: &mut File, fragment: &[u8], deadline: Instant) {
            let mut output = Vec::new();
            while !output
                .windows(fragment.len())
                .any(|bytes| bytes == fragment)
            {
                assert!(
                    Instant::now() < deadline,
                    "missing terminal text: {}",
                    String::from_utf8_lossy(fragment)
                );
                let mut chunk = [0; 4096];
                match master.read(&mut chunk) {
                    Ok(count) => output.extend_from_slice(&chunk[..count]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        poll(
                            &mut [event(master.as_raw_fd(), libc::POLLIN)],
                            Some(deadline),
                        )
                        .unwrap();
                    }
                    Err(error) => panic!("{error}"),
                }
            }
        }
        let (mut master, tty) = terminal();
        nonblocking(tty.as_raw_fd()).unwrap();
        nonblocking(master.as_raw_fd()).unwrap();
        let size = libc::winsize {
            ws_row: 15,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_eq!(
            unsafe { libc::ioctl(tty.as_raw_fd(), libc::TIOCSWINSZ, &size) },
            0
        );
        let attributes = || {
            let mut state: libc::termios = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::tcgetattr(tty.as_raw_fd(), &mut state) }, 0);
            state
        };
        let original = attributes();
        let mut review = Review {
            exec_id: "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f".into(),
            signer_id: "operator".into(),
            csr: Csr::parse(include_bytes!(
                "../../sigrund-core/tests/fixtures/v3-host/warrant.json"
            ))
            .unwrap(),
            details: "Verified fixture".into(),
            target: "Host",
            full_host_root: false,
        };
        let signals = Signals::new().unwrap();
        let mut screen = crate::approval_tui::Screen::new(&tty);
        assert!(!screen.idle(true).unwrap());
        for disconnect in [true, false] {
            if !disconnect {
                review.exec_id = "0193d8f4-7c1b-7000-8a01-9f8b3c4d5e6f".into();
            }
            let (socket, peer) = UnixStream::pair().unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let exchange = Exchange {
                socket: &socket,
                signals: &signals,
                deadline,
            };
            let result = std::thread::scope(|scope| {
                let operator = scope.spawn(|| {
                    await_text(&mut master, b"a Approve", deadline);
                    // Read buffered input and a freshly displayed confirmation
                    // on distinct terminal boundaries.
                    master.write_all(b"ayes\r").unwrap();
                    await_text(&mut master, b"Type yes + Enter", deadline);
                    // The PTY reader can see output before the watcher
                    // completes its post-render input drain.
                    std::thread::sleep(Duration::from_millis(50));
                    if disconnect {
                        master.write_all(b"ye").unwrap();
                        peer.shutdown(std::net::Shutdown::Both).unwrap();
                    } else {
                        master.write_all(b"s\ryes\r").unwrap();
                    }
                });
                let result = screen.review(&tty, &review, &exchange);
                operator.join().unwrap();
                result
            });
            if disconnect {
                assert_eq!(result.err().unwrap().kind(), io::ErrorKind::UnexpectedEof);
                screen
                    .reconnecting(&tty, &io::ErrorKind::UnexpectedEof.into())
                    .unwrap();
                assert!(!screen.idle(false).unwrap());
            } else {
                assert!(matches!(result, Ok(Decision::Approve)));
                screen.before_signing().unwrap();
                assert_eq!(attributes().c_lflag, original.c_lflag);
            }
        }
        drop(screen);
        let restored = attributes();
        assert_eq!(restored.c_lflag, original.c_lflag);
        assert_eq!(restored.c_iflag, original.c_iflag);
        assert_eq!(restored.c_oflag, original.c_oflag);
        assert_eq!(restored.c_cc, original.c_cc);
    }

    fn identity(dir: &Path, name: &str) -> (File, SignerConfig) {
        let path = dir.join(name);
        assert!(
            Command::new("/usr/bin/ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let mut signer =
            SignerPolicyFile::from_toml(include_bytes!("../../../config/signers.toml.example"))
                .unwrap()
                .signers
                .remove(0);
        signer.signature_type = "ssh-ed25519".into();
        signer.public_key = fs::read_to_string(path.with_extension("pub")).unwrap();
        signer.require_user_presence = false;
        (File::open(path).unwrap(), signer)
    }

    fn read_prompt(terminal: &mut File) {
        read_flushed_terminal(terminal, b"Approve and sign? [y/yes/n/no] ");
    }

    fn read_flushed_terminal(terminal: &mut File, suffix: &[u8]) {
        // Linux PTY packet flags are not exposed by libc on all architectures.
        const TIOCPKT_DATA: u8 = 0;
        const TIOCPKT_FLUSHREAD: u8 = 1;
        nonblocking(terminal.as_raw_fd()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut text = Vec::new();
        let mut flushed = false;
        loop {
            assert!(
                Instant::now() < deadline,
                "confirmation terminal did not reach its post-flush state: flushed={flushed}, output={text:?}"
            );
            let mut bytes = [0; 4096];
            match terminal.read(&mut bytes) {
                Ok(0) => panic!("terminal closed before confirmation prompt"),
                Ok(n) => {
                    if bytes[0] == TIOCPKT_DATA {
                        text.extend_from_slice(&bytes[1..n]);
                    } else {
                        flushed |= bytes[0] & TIOCPKT_FLUSHREAD != 0;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    poll(
                        &mut [event(terminal.as_raw_fd(), libc::POLLIN)],
                        Some(deadline),
                    )
                    .unwrap();
                }
                Err(error) => panic!("confirmation terminal: {error}"),
            }
            // Control packets can precede earlier output, so require both
            // the complete prompt and its flush notification in either order.
            // Echo from discarded typeahead can arrive after the prompt text.
            let displayed =
                suffix.is_empty() || text.windows(suffix.len()).any(|bytes| bytes == suffix);
            if flushed && displayed {
                return;
            }
        }
    }

    #[test]
    fn confirmation_discards_typeahead_and_reprompts_until_an_explicit_answer() {
        let (mut master, tty) = confirmation_terminal();
        nonblocking(tty.as_raw_fd()).unwrap();
        let (socket, _peer) = UnixStream::pair().unwrap();
        let signals = Signals::new().unwrap();
        // A queued affirmative answer must not authorize the coming request.
        master.write_all(b"yes\n\n").unwrap();
        for (answer, expected) in [
            (b"y\n".as_slice(), true),
            (b"yes\n", true),
            (b"n\n", false),
            (b"no\n", false),
        ] {
            std::thread::scope(|scope| {
                let operator = scope.spawn(|| {
                    read_prompt(&mut master);
                    for invalid in [
                        b"\n".as_slice(),
                        b"wat\n",
                        b"y                 \n",
                        b"\nyes\n",
                    ] {
                        master.write_all(invalid).unwrap();
                        read_prompt(&mut master);
                    }
                    master.write_all(answer).unwrap();
                });
                assert_eq!(
                    confirm(
                        &tty,
                        &socket,
                        &signals,
                        Instant::now() + Duration::from_secs(5)
                    )
                    .unwrap(),
                    Some(expected)
                );
                operator.join().unwrap();
            });
        }
    }

    #[test]
    fn confirmation_without_enter_expires_and_partial_input_is_discarded() {
        let (mut master, tty) = confirmation_terminal();
        nonblocking(tty.as_raw_fd()).unwrap();
        let (socket, _peer) = UnixStream::pair().unwrap();
        let signals = Signals::new().unwrap();
        std::thread::scope(|scope| {
            let operator = scope.spawn(|| {
                read_prompt(&mut master);
                master.write_all(b"\n").unwrap();
                read_prompt(&mut master);
                master.write_all(b"y").unwrap();
            });
            let error = confirm(
                &tty,
                &socket,
                &signals,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(recoverable_connection_error(&error));
            operator.join().unwrap();
        });
        discard_confirmation_input(&tty).unwrap();
        // Consume this cancellation flush so it cannot acknowledge the next
        // prompt's flush before that prompt has actually finished discarding.
        read_flushed_terminal(&mut master, b"");
        let mut byte = [0];
        assert_eq!(
            tty.try_clone().unwrap().read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        // Enter on the next request must not complete the old partial 'y'.
        std::thread::scope(|scope| {
            let operator = scope.spawn(|| {
                read_prompt(&mut master);
                master.write_all(b"\n").unwrap();
                read_prompt(&mut master);
                master.write_all(b"no\n").unwrap();
            });
            assert_eq!(
                confirm(
                    &tty,
                    &socket,
                    &signals,
                    Instant::now() + Duration::from_secs(5)
                )
                .unwrap(),
                Some(false)
            );
            operator.join().unwrap();
        });
    }

    #[test]
    fn openssh_signs_exact_dsse_pae_and_rejects_other_keys_namespaces_and_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let (key, signer) = identity(dir.path(), "key");
        let (_master, tty) = terminal();
        let payload = b"exact canonical CSR bytes";
        let signature = sign_payload(&key, &tty, &signer, payload, || Ok(())).unwrap();
        let verify = |signature: &str, payload: &[u8], signer: &SignerConfig| {
            verify_ssh_signature(
                &signer.signature_type,
                &signer.public_key,
                signature,
                WARRANT_PAYLOAD_TYPE,
                payload,
                false,
                false,
            )
        };
        verify(&signature, payload, &signer).unwrap();
        assert!(verify(&signature, b"changed CSR", &signer).is_err());
        let (_, wrong_signer) = identity(dir.path(), "other");
        assert!(verify(&signature, payload, &wrong_signer).is_err());
        assert!(sign_payload(&key, &tty, &wrong_signer, payload, || Ok(())).is_err());
        // Independently invoke OpenSSH with the wrong domain or without PAE.
        for (namespace, input) in [
            ("wrong.namespace", pae(WARRANT_PAYLOAD_TYPE, payload)),
            ("sigrun.warrant.v3", payload.to_vec()),
        ] {
            let mut child = Command::new("/usr/bin/ssh-keygen")
                .args(["-Y", "sign", "-n", namespace, "-O", "hashalg=sha512", "-f"])
                .arg(dir.path().join("key"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(&input).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            let sig = STANDARD.encode(
                SshSig::from_pem(&output.stdout)
                    .unwrap()
                    .encode_vec()
                    .unwrap(),
            );
            assert!(verify(&sig, payload, &signer).is_err());
        }
    }

    #[test]
    fn helper_abort_kills_and_reaps_child_and_bounds_input_output() {
        let dir = tempfile::tempdir().unwrap();
        let (key, signer) = identity(dir.path(), "key");
        let (_master, tty) = terminal();
        let helper = dir.path().join("helper");
        for (attempt, kind) in [
            io::ErrorKind::Interrupted,
            io::ErrorKind::TimedOut,
            io::ErrorKind::UnexpectedEof,
        ]
        .into_iter()
        .enumerate()
        {
            // Each attempt publishes its own complete PID after disabling echo.
            // A delayed helper must not leave an empty or stale PID to inspect.
            let attempt_dir = dir.path().join(attempt.to_string());
            fs::create_dir(&attempt_dir).unwrap();
            let pending_pid = attempt_dir.join("pid");
            let ready_pid = attempt_dir.join("ready");
            fs::write(
                &helper,
                format!(
                    "#!/bin/sh\nset -e\n/usr/bin/stty -echo <&2\necho $$ > '{}'\n/usr/bin/mv '{}' '{}'\nexec /usr/bin/sleep 60\n",
                    pending_pid.display(),
                    pending_pid.display(),
                    ready_pid.display()
                ),
            )
            .unwrap();
            fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
            let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
            assert_eq!(
                unsafe { libc::tcgetattr(tty.as_raw_fd(), &mut original) },
                0
            );
            assert_ne!(original.c_lflag & libc::ECHO, 0);
            let start = Instant::now();
            let checks = AtomicUsize::new(0);
            let ready_at = Cell::new(None);
            let cancelled_at = Cell::new(None);
            let helper_pid = Cell::new(None);
            let result =
                sign_with_helper(&helper, &key, &tty, &signer, &vec![b'x'; 65_536], || {
                    checks.fetch_add(1, Ordering::Relaxed);
                    if ready_at.get().is_none() {
                        match fs::read_to_string(&ready_pid) {
                            Ok(pid) => {
                                helper_pid.set(Some(pid.trim().parse::<i32>().unwrap()));
                                let mut settings = unsafe { std::mem::zeroed::<libc::termios>() };
                                assert_eq!(
                                    unsafe { libc::tcgetattr(tty.as_raw_fd(), &mut settings) },
                                    0
                                );
                                assert_eq!(settings.c_lflag & libc::ECHO, 0);
                                ready_at.set(Some(Instant::now()));
                            }
                            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                                assert!(
                                    start.elapsed() < Duration::from_secs(5),
                                    "helper did not publish readiness"
                                );
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    if ready_at
                        .get()
                        .is_some_and(|ready| ready.elapsed() >= Duration::from_millis(100))
                    {
                        cancelled_at.set(Some(Instant::now()));
                        Err(kind.into())
                    } else {
                        Ok(())
                    }
                });
            assert_eq!(result.unwrap_err().kind(), kind);
            assert!(cancelled_at.get().unwrap().elapsed() < Duration::from_secs(2));
            assert!(checks.load(Ordering::Relaxed) > 2);
            let pid = helper_pid.get().unwrap();
            assert_eq!(
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
                -1
            );
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
            assert!(!Path::new(&format!("/proc/{pid}")).exists());
            let mut restored = unsafe { std::mem::zeroed::<libc::termios>() };
            assert_eq!(
                unsafe { libc::tcgetattr(tty.as_raw_fd(), &mut restored) },
                0
            );
            assert_eq!(restored.c_lflag, original.c_lflag);
        }
        fs::write(
            &helper,
            "#!/bin/sh\nexec /usr/bin/head -c 34001 /dev/zero\n",
        )
        .unwrap();
        let result = sign_with_helper(&helper, &key, &tty, &signer, b"csr", || Ok(()));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("output exceeds limit")
        );
    }

    #[test]
    fn display_escaping_preserves_boundaries_without_terminal_controls() {
        assert_eq!(quote("two words"), "\"two words\"");
        assert_eq!(quote(""), "\"\"");
        assert_eq!(
            quote("\"\\\n\x1b\u{202e}λ"),
            "\"\\\"\\\\\\u{000A}\\u{001B}\\u{202E}\\u{03BB}\""
        );
    }
}
