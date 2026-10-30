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

pub(crate) const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_ARMOR: usize = 34_000;

fn nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn poll(descriptors: &mut [libc::pollfd], deadline: Option<Instant>) -> io::Result<()> {
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
fn event(fd: RawFd, events: i16) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
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
    let signers = load_signers(&args.signers)?;
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
            let private =
                PrivateKey::from_openssh(&bytes).map_err(|_| invalid("invalid SSH identity"))?;
            private.public_key().clone()
        }
    };
    bytes.fill(0);
    // This descriptor's open description is shared with the helper. Rewind it
    // before use and inherit only this deliberate identity handle.
    if unsafe { libc::lseek(identity_file.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let signals = Signals::new()?;
    let socket = connect_broker(&args.socket, &signals)?;
    loop {
        let mut reader = ApprovalReader::default();
        let request = loop {
            if signals.next()?.is_some() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if let Some(bytes) = reader.read(socket.as_raw_fd(), Instant::now())? {
                break ApprovalRequest::parse_jcs(&bytes).map_err(|e| invalid(e.to_string()))?;
            }
            poll(
                &mut [
                    event(socket.as_raw_fd(), libc::POLLIN),
                    event(signals.fd.as_raw_fd(), libc::POLLIN),
                ],
                reader.deadline(),
            )?;
        };
        let deadline = Instant::now() + APPROVAL_TIMEOUT;
        let signer = signers
            .signers
            .iter()
            .find(|s| s.signer_id == request.signer_id)
            .ok_or_else(|| invalid("requested signer is not configured"))?;
        let configured = PublicKey::from_openssh(&signer.public_key)
            .map_err(|_| invalid("invalid configured SSH key"))?;
        if configured.key_data() != public.key_data() {
            return Err(invalid("explicit identity does not match requested signer"));
        }
        let response = approve(
            &tty,
            &identity_file,
            signer,
            &request,
            &socket,
            &signals,
            deadline,
        )?;
        let mut writer = FrameWriter::approval(
            &response.to_jcs().map_err(|e| invalid(e.to_string()))?,
            Instant::now(),
        )?;
        loop {
            check(&socket, &signals, deadline)?;
            if writer.write(socket.as_raw_fd(), Instant::now())? {
                break;
            }
            poll(
                &mut [
                    event(socket.as_raw_fd(), libc::POLLOUT),
                    event(signals.fd.as_raw_fd(), libc::POLLIN),
                ],
                Some(writer.deadline().min(deadline)),
            )?;
        }
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
    let socket = UnixStream::from(crate::client::connect(&pinned, signals)?);
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
fn approve(
    tty: &File,
    identity: &File,
    signer: &SignerConfig,
    request: &ApprovalRequest,
    socket: &UnixStream,
    signals: &Signals,
    deadline: Instant,
) -> io::Result<ApprovalResponse> {
    let csr = Csr::parse(request.csr_payload.as_bytes()).map_err(|e| invalid(e.to_string()))?;
    let refused = |reason: &str| ApprovalResponse::Rejected {
        exec_id: request.exec_id.clone(),
        reason: reason.into(),
    };
    write_tty(
        tty,
        render_request(request, &csr, signer)?.as_bytes(),
        socket,
        signals,
        deadline,
    )?;
    if !valid_now(&csr) {
        return Ok(refused("warrant expired or not yet valid"));
    }
    write_tty(tty, b"Approve and sign? [y/N] ", socket, signals, deadline)?;
    let mut input = tty;
    let mut answer = Vec::new();
    loop {
        check(socket, signals, deadline)?;
        let mut byte = [0];
        match input.read(&mut byte) {
            Ok(0) => return Ok(refused("operator terminal EOF")),
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                answer.push(byte[0]);
                if answer.len() > 16 {
                    return Err(invalid("confirmation exceeds length limit"));
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
            Err(_) => return Ok(refused("operator terminal lost")),
        }
    }
    if answer != b"y" && answer != b"yes" {
        return Ok(refused("operator refused approval"));
    }
    if !valid_now(&csr) {
        return Ok(refused("warrant expired while awaiting confirmation"));
    }
    let signature = sign_payload(
        identity,
        tty,
        signer,
        request.csr_payload.as_bytes(),
        || check(socket, signals, deadline),
    )?;
    if !valid_now(&csr) {
        return Ok(refused("warrant expired while signing"));
    }
    let warrant = CanonicalWarrant::parse(request.csr_payload.as_bytes())
        .map_err(|e| invalid(e.to_string()))?;
    let envelope = sigrund_core::protocol::DsseEnvelope::from_warrant(
        &warrant,
        vec![sigrund_core::protocol::DsseSignature {
            keyid: signer.signer_id.clone(),
            sig: signature,
        }],
    )
    .map_err(|e| invalid(e.to_string()))?;
    Ok(ApprovalResponse::Approved {
        exec_id: request.exec_id.clone(),
        dsse_envelope: envelope,
    })
}

/// Every leaf and empty container is rendered; indexed argv and escaped key
/// names make both argument and environment boundaries visible. Only ASCII
/// escapes are emitted for request data, including Unicode/BiDi and controls.
fn render_request(
    request: &ApprovalRequest,
    csr: &Csr,
    signer: &SignerConfig,
) -> io::Result<String> {
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
    out.push_str(&format!(
        "umask_octal = {:03o}\n",
        csr.warrant().execution_context.umask
    ));
    Ok(out)
}
fn quote(value: &str) -> String {
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
            "sigrun.warrant.v1",
            "-O",
            "hashalg=sha512",
            "-f",
        ])
        .arg(format!("/proc/self/fd/{fd}"))
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
            ("sigrun.warrant.v1", payload.to_vec()),
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
        let pid_path = dir.path().join("pid");
        let helper = dir.path().join("helper");
        fs::write(
            &helper,
            format!(
                "#!/bin/sh\n/usr/bin/stty -echo <&2\necho $$ > '{}'\nexec /usr/bin/sleep 60\n",
                pid_path.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        for kind in [
            io::ErrorKind::Interrupted,
            io::ErrorKind::TimedOut,
            io::ErrorKind::UnexpectedEof,
        ] {
            let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
            assert_eq!(
                unsafe { libc::tcgetattr(tty.as_raw_fd(), &mut original) },
                0
            );
            assert_ne!(original.c_lflag & libc::ECHO, 0);
            let start = Instant::now();
            let checks = AtomicUsize::new(0);
            let result =
                sign_with_helper(&helper, &key, &tty, &signer, &vec![b'x'; 65_536], || {
                    checks.fetch_add(1, Ordering::Relaxed);
                    if start.elapsed() >= Duration::from_millis(100) {
                        Err(kind.into())
                    } else {
                        Ok(())
                    }
                });
            assert_eq!(result.unwrap_err().kind(), kind);
            assert!(start.elapsed() < Duration::from_secs(2));
            assert!(checks.load(Ordering::Relaxed) > 2);
            let pid: i32 = fs::read_to_string(&pid_path)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
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
