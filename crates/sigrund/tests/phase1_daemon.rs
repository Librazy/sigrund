//! Real daemon exit gate, run as namespace root with a mapped non-root UID.
//! No host-root privilege, cgroup mutation, or production paths are required.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sigrund_core::{
    audit::entry_hmac,
    crypto::{new_uuidv7, sha256_hex},
    framing::{FrameType, encode_frame},
    protocol::{Decision, parse_strict},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    mem::zeroed,
    os::{
        fd::{AsRawFd, RawFd},
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn wait_for(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "fixture condition timed out");
        thread::sleep(Duration::from_millis(5));
    }
}

fn send_rights(socket: &UnixStream, bytes: &[u8], count: usize) {
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    send_fds(socket, bytes, &vec![null.as_raw_fd(); count]);
}

fn send_fds(socket: &UnixStream, bytes: &[u8], rights: &[RawFd]) {
    let count = rights.len();
    let mut control = [0usize; 16];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    if count > 0 {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE(std::mem::size_of_val(rights) as _) } as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(rights) as _) as _;
            for (index, fd) in rights.iter().enumerate() {
                std::ptr::write(libc::CMSG_DATA(header).cast::<i32>().add(index), *fd);
            }
        }
    }
    assert_eq!(
        unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) },
        bytes.len() as isize
    );
}

fn hello(executable: &Path) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "mode":"unsigned_csr_request", "tty_mode":"stdio", "caller_env":{},
        "requested_command":{"allow_interpreted_script":false,"argv":["id"],"cwd":"/",
            "executable_path":executable,"stdin_policy":"null","tty_mode":"stdio"},
        "requested_execution_context":{"capabilities":[],"env_exact":{},"caller_env_allowlist":[],
            "supplementary_gids":[],"target_gid":0,"target_uid":33,"umask":18},
        "requested_policy":{"mode":"one_time","ttl_secs":60}
    }))
    .unwrap()
}

fn connect(path: &Path) -> UnixStream {
    let socket = UnixStream::connect(path).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
}

fn decision(socket: &mut UnixStream) -> Decision {
    let mut header = [0u8; 5];
    socket.read_exact(&mut header).unwrap();
    assert_eq!(header[0], FrameType::ServerAuthDecision as u8);
    let length = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
    assert!(length <= 524_288);
    let mut payload = vec![0; length];
    socket.read_exact(&mut payload).unwrap();
    let decision: Decision = parse_strict(&payload).unwrap();
    decision.validate().unwrap();
    decision
}

fn expect_closed(socket: &mut UnixStream) {
    let mut byte = [0u8];
    match socket.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) => {}
        result => panic!("expected closed socket, got {result:?}"),
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    config: PathBuf,
    signers: PathBuf,
    state: PathBuf,
    log: PathBuf,
    executable: PathBuf,
    socket: PathBuf,
    broker: PathBuf,
    diagnostics: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let base = directory.path();
        let client_binary = base.join("sigrun");
        fs::copy(env!("CARGO_BIN_EXE_sigrun"), &client_binary).unwrap();
        fs::set_permissions(&client_binary, fs::Permissions::from_mode(0o755)).unwrap();
        let peer_binary = base.join("peer-probe");
        fs::copy(std::env::current_exe().unwrap(), &peer_binary).unwrap();
        fs::set_permissions(&peer_binary, fs::Permissions::from_mode(0o755)).unwrap();
        let config = base.join("config.toml");
        let signers = base.join("signers.toml");
        let state = base.join("state");
        let log_dir = base.join("log");
        let log = log_dir.join("audit.jsonl");
        let root = base.join("executables");
        for path in [&state, &log_dir, &root] {
            fs::create_dir(path).unwrap();
        }
        let executable = root.join("id");
        fs::write(&executable, b"\x7fELFphase2-fixture").unwrap();
        let mut configuration = include_str!("../../../config/sigrund.toml.example")
            .replace(
                "<strict-padded-base64-32-byte-ed25519-key>",
                &STANDARD.encode([1; 32]),
            )
            .replace(
                "[\"/usr/bin\", \"/usr/sbin\"]",
                &format!("[\"{}\"]", root.display()),
            )
            .replace(
                "max_active_sockets_global = 64",
                "max_active_sockets_global = 3",
            )
            .replace(
                "max_active_sockets_per_uid = 4",
                "max_active_sockets_per_uid = 2",
            )
            .replace("request_deadline_ms = 5000", "request_deadline_ms = 1500");
        for name in [
            "collector-ca.pem",
            "collector-client.crt",
            "collector-client.key",
        ] {
            let path = base.join(name);
            fs::write(&path, "fixture TLS file; no Phase 1 network use\n").unwrap();
            configuration =
                configuration.replace(&format!("/etc/sigrund/{name}"), path.to_str().unwrap());
        }
        configuration.push_str("\n[mvp]\n");
        fs::write(&config, configuration).unwrap();
        let public = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes();
        let mut key = Vec::new();
        key.extend_from_slice(&11u32.to_be_bytes());
        key.extend_from_slice(b"ssh-ed25519");
        key.extend_from_slice(&32u32.to_be_bytes());
        key.extend_from_slice(&public);
        let signer = include_str!("../../../config/signers.toml.example")
            .replace("type = \"sk-ssh-ed25519\"", "type = \"ssh-ed25519\"")
            .replace(
                "require_user_presence = true",
                "require_user_presence = false",
            )
            .replace(
                "sk-ssh-ed25519@openssh.com AAAA...",
                &format!("ssh-ed25519 {}", STANDARD.encode(key)),
            )
            .replace(
                "[\"/usr/bin\", \"/usr/sbin\"]",
                &format!("[\"{}\"]", root.display()),
            );
        fs::write(&signers, signer).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_sigrundctl"))
            .args(["init-host", "--state-dir"])
            .arg(&state)
            .arg("--log-path")
            .arg(&log)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            socket: base.join("client.sock"),
            broker: base.join("broker.sock"),
            diagnostics: base.join("diagnostics.jsonl"),
            config,
            signers,
            state,
            log,
            executable,
            directory,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sigrund"));
        command
            .arg("--foreground")
            .arg("--config")
            .arg(&self.config)
            .arg("--signers")
            .arg(&self.signers)
            .arg("--state-dir")
            .arg(&self.state)
            .arg("--log-path")
            .arg(&self.log)
            .arg("--socket")
            .arg(&self.socket)
            .arg("--approval-socket")
            .arg(&self.broker);
        command
    }

    fn launch(&self) -> DaemonChild {
        self.launch_command(self.command())
    }

    fn launch_command(&self, mut command: Command) -> DaemonChild {
        let child = command
            .stderr(File::create(&self.diagnostics).unwrap())
            .spawn()
            .unwrap();
        let mut daemon = DaemonChild(child);
        wait_for(|| {
            assert!(
                daemon.0.try_wait().unwrap().is_none(),
                "daemon exited: {}",
                fs::read_to_string(&self.diagnostics).unwrap()
            );
            fs::read_to_string(&self.diagnostics)
                .unwrap()
                .contains("DAEMON_READY")
        });
        daemon
    }

    fn must_fail(&self, message: &str) {
        let output = self.command().output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(78),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !self.socket.exists() && !self.broker.exists(),
            "startup failure published a socket"
        );
    }

    fn peer_command(&self, uid: u32, role: &str) -> Command {
        let mut command = Command::new(self.directory.path().join("peer-probe"));
        command
            .args([
                "--exact",
                "phase1_peer_probe",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("SIGRUND_PHASE1_ROLE", role)
            .env("SIGRUND_PHASE1_CLIENT", &self.socket)
            .env("SIGRUND_PHASE1_BROKER", &self.broker)
            .env("SIGRUND_PHASE1_EXECUTABLE", &self.executable);
        command.env("SIGRUND_PHASE1_DIAGNOSTICS", &self.diagnostics);
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(uid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
    }

    fn peer(&self, uid: u32, role: &str) {
        let output = self.peer_command(uid, role).output().unwrap();
        assert!(
            output.status.success(),
            "{role}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn diagnostic_count(&self) -> usize {
        fs::read_to_string(&self.diagnostics)
            .unwrap()
            .lines()
            .count()
    }

    fn wait_for_cleanup(&self, events_before: usize) {
        wait_for(|| {
            let events: Vec<serde_json::Value> = fs::read_to_string(&self.diagnostics)
                .unwrap()
                .lines()
                .skip(events_before)
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            let token = events
                .iter()
                .find(|event| event["event"] == "SOCKET_ADMITTED")
                .and_then(|event| event["worker_task"].as_u64());
            token.is_some()
                && events.iter().any(|event| {
                    event["event"] == "FD_VALIDATION_COMPLETE"
                        && event["worker_task"].as_u64() == token
                })
        });
    }
}

struct DaemonChild(Child);
impl DaemonChild {
    fn stop(mut self) {
        assert_eq!(unsafe { libc::kill(self.0.id() as _, libc::SIGTERM) }, 0);
        wait_for(|| self.0.try_wait().unwrap().is_some());
        assert!(self.0.wait().unwrap().success());
    }
}
impl Drop for DaemonChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn phase1_exit_gate_in_user_namespace() {
    let output = Command::new("unshare")
        .args(["--user", "--map-auto", "--map-root-user"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "phase1_namespace_fixture",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SIGRUND_PHASE1_NAMESPACE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "namespace exit gate failed (requires unshare, subordinate UID/GID ranges, and newuidmap/newgidmap):\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "invoked by the user-namespace exit gate"]
fn phase1_namespace_fixture() {
    assert_eq!(
        std::env::var("SIGRUND_PHASE1_NAMESPACE").as_deref(),
        Ok("1")
    );
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let fixture = Fixture::new();
    let daemon = fixture.launch();
    let fd_count = || {
        fs::read_dir(format!("/proc/{}/fd", daemon.0.id()))
            .unwrap()
            .count()
    };
    let baseline = fd_count();
    for (path, mode) in [(&fixture.socket, 0o666), (&fixture.broker, 0o600)] {
        let metadata = fs::metadata(path).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
            (0, 0, mode)
        );
    }
    fixture.peer(65534, "client");
    wait_for(|| {
        fs::read_to_string(&fixture.diagnostics)
            .unwrap()
            .contains("CLIENT_HELLO_VALIDATED")
    });
    let diagnostics = fs::read_to_string(&fixture.diagnostics).unwrap();
    let event: serde_json::Value = diagnostics
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|event| event["event"] == "CLIENT_HELLO_VALIDATED")
        .unwrap();
    assert_eq!(event["requester_uid"], 65534);
    assert_eq!(event["requester_gid"], 65534);
    fixture.peer(65534, "broker_permissions");
    // Deliberately loosen the filesystem permission to exercise SO_PEERCRED
    // independently. The daemon must reject before parsing a signed reply.
    fs::set_permissions(&fixture.broker, fs::Permissions::from_mode(0o666)).unwrap();
    fixture.peer(65534, "broker_credentials");
    fs::set_permissions(&fixture.broker, fs::Permissions::from_mode(0o600)).unwrap();
    let events_before = fixture.diagnostic_count();
    let mut broker = connect(&fixture.broker);
    // A root broker may wait idle without an assembly timeout; once it sends
    // a byte, the cumulative framing timer applies (unit-tested separately).
    let response = sigrund_core::approval::ApprovalResponse::Rejected {
        exec_id: new_uuidv7().to_string(),
        reason: "operator declined".into(),
    }
    .to_jcs()
    .unwrap();
    broker
        .write_all(&(response.len() as u32).to_be_bytes())
        .unwrap();
    broker.write_all(&response).unwrap();
    expect_closed(&mut broker);
    drop(broker);
    fixture.wait_for_cleanup(events_before);
    // Every rejection must release delivered FDs, including control padding,
    // truncated rights, invalid JSON, and rights attached to later bytes.
    for iteration in 0..40 {
        let events_before = fixture.diagnostic_count();
        let mut socket = connect(&fixture.socket);
        let body = if iteration % 2 == 0 {
            b"{}".to_vec()
        } else {
            hello(&fixture.executable)
        };
        let encoded = encode_frame(FrameType::ClientHello, &body).unwrap();
        send_rights(
            &socket,
            &encoded[..1],
            if iteration % 3 == 0 { 5 } else { 2 },
        );
        // A truncated ancillary set can be rejected on the first byte before
        // the remaining write. SIGPIPE is suppressed by Rust's socket writes.
        let _ = socket.write_all(&encoded[1..]);
        let status = decision(&mut socket).status;
        assert!(
            matches!(status.as_str(), "INVALID_REQUEST" | "TIMEOUT_CSR"),
            "iteration {iteration}: unexpected status {status}"
        );
        expect_closed(&mut socket);
        // A reply/EOF does not release a worker lease. Wait for this request's
        // actual cleanup so the next serial probe tests parsing, not quota
        // exhaustion caused by deliberately retained disposal reservations.
        fixture.wait_for_cleanup(events_before);
    }
    let events_before = fixture.diagnostic_count();
    let mut oversized = connect(&fixture.socket);
    oversized.write_all(&[1, 0, 3, 0, 1]).unwrap();
    assert_eq!(decision(&mut oversized).status, "INVALID_REQUEST");
    drop(oversized);
    fixture.wait_for_cleanup(events_before);
    let events_before = fixture.diagnostic_count();
    let mut misplaced = connect(&fixture.socket);
    misplaced.write_all(&[1]).unwrap();
    send_rights(&misplaced, &[0], 2);
    assert_eq!(decision(&mut misplaced).status, "INVALID_REQUEST");
    drop(misplaced);
    fixture.wait_for_cleanup(events_before);
    wait_for(|| fd_count() == baseline);
    // Capture both per-UID and global admission limits at accept4().
    let mut first = connect(&fixture.socket);
    let second = connect(&fixture.socket);
    let mut excess = connect(&fixture.socket);
    expect_closed(&mut excess);
    let mut holder = fixture
        .peer_command(65534, "hold")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(holder.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        assert_ne!(stdout.read_line(&mut line).unwrap(), 0);
        if line.contains("PEER_READY") {
            break;
        }
        line.clear();
    }
    fixture.peer(65533, "quota");
    // Removing any admitted socket releases capacity immediately.
    drop(second);
    wait_for(|| fd_count() == baseline + 2);
    let mut replacement = connect(&fixture.socket);
    send_rights(&replacement, &[1], 2);
    let encoded = encode_frame(FrameType::ClientHello, &hello(&fixture.executable)).unwrap();
    replacement.write_all(&encoded[1..]).unwrap();
    assert_eq!(decision(&mut replacement).status, "TIMEOUT_CSR");
    holder.stdin.take().unwrap().write_all(b"x").unwrap();
    assert!(holder.wait().unwrap().success());
    // The accept-based deadline also applies when no frame has started.
    assert_eq!(decision(&mut first).status, "REQUEST_TIMEOUT");
    expect_closed(&mut first);
    drop(first);
    wait_for(|| fd_count() == baseline);
    // Trickling header bytes does not replace the accept-time deadline with
    // a fresh deadline from the first byte or from the most recent progress.
    let accepted = Instant::now();
    let mut trickle = connect(&fixture.socket);
    thread::sleep(Duration::from_millis(750));
    send_rights(&trickle, &[1], 2);
    thread::sleep(Duration::from_millis(400));
    trickle.write_all(&[0]).unwrap();
    assert_eq!(decision(&mut trickle).status, "REQUEST_TIMEOUT");
    assert!(accepted.elapsed() < Duration::from_millis(2100));
    drop(trickle);
    wait_for(|| fd_count() == baseline);
    // A second daemon cannot reconcile or write the same audit state.
    let second = fixture.command().output().unwrap();
    assert_eq!(second.status.code(), Some(78));
    assert!(String::from_utf8_lossy(&second.stderr).contains("already in use"));
    daemon.stop();
    assert!(!fixture.socket.exists() && !fixture.broker.exists());
    // Startup failures and normal crash recovery are exercised through the
    // shipped daemon, rather than only through AuditLog helper tests.
    let original = fs::read(&fixture.log).unwrap();
    OpenOptions::new()
        .append(true)
        .open(&fixture.log)
        .unwrap()
        .write_all(b"partial")
        .unwrap();
    fs::write(fixture.state.join("audit_ratchet.state.tmp"), "stale").unwrap();
    fs::set_permissions(
        fixture.state.join("audit_ratchet.state.tmp"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fixture.launch().stop();
    assert!(!fixture.state.join("audit_ratchet.state.tmp").exists());
    assert!(
        fs::read_to_string(&fixture.log)
            .unwrap()
            .contains("RATCHET_PARTIAL_WRITE_TRUNCATED")
    );
    // A durable record without its successor state must forward recover.
    let state_path = fixture.state.join("audit_ratchet.state");
    let state: serde_json::Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    let mut key = [0u8; 32];
    let hex = state["key_hex"].as_str().unwrap();
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).unwrap();
    }
    let genesis: serde_json::Value =
        serde_json::from_slice(original.split(|byte| *byte == b'\n').next().unwrap()).unwrap();
    let mut record = serde_json::json!({"event_type":"TEST_CRASH_WINDOW","host_id":genesis["host_id"],
        "seq":state["seq"],"prev_record_sha256":state["last_record_sha256"]});
    let hmac = entry_hmac(&key, &serde_json::to_vec(&record).unwrap());
    record["entry_hmac"] = hmac.into();
    let bytes = serde_json::to_vec(&record).unwrap();
    let mut log = OpenOptions::new().append(true).open(&fixture.log).unwrap();
    log.write_all(&bytes).unwrap();
    log.write_all(b"\n").unwrap();
    log.sync_all().unwrap();
    drop(log);
    fixture.launch().stop();
    assert!(
        fs::read_to_string(&fixture.log)
            .unwrap()
            .contains("RATCHET_FORWARD_RECOVERY")
    );
    let synchronized_log = fs::read(&fixture.log).unwrap();
    fs::write(&fixture.log, b"corrupt\n").unwrap();
    fixture.must_fail("audit");
    fs::write(&fixture.log, &synchronized_log).unwrap();
    // Verify host binding before recovery can mutate either audit file.
    let identity = fixture.state.join("host_identity.key");
    let identity_bytes = fs::read(&identity).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let mut other_identity = vec![42; 32];
    other_identity.extend_from_slice(&key.verifying_key().to_bytes());
    fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&identity, other_identity).unwrap();
    fs::set_permissions(&identity, fs::Permissions::from_mode(0o400)).unwrap();
    let mut mismatched_log = synchronized_log.clone();
    mismatched_log.extend_from_slice(b"partial");
    fs::write(&fixture.log, &mismatched_log).unwrap();
    let state_before = fs::read(&state_path).unwrap();
    fixture.must_fail("host identity");
    assert_eq!(fs::read(&fixture.log).unwrap(), mismatched_log);
    assert_eq!(fs::read(&state_path).unwrap(), state_before);
    fs::write(&fixture.log, &synchronized_log).unwrap();
    fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&identity, identity_bytes).unwrap();
    fixture.must_fail("permissions");
    fs::set_permissions(&identity, fs::Permissions::from_mode(0o400)).unwrap();
    fs::rename(&fixture.log, fixture.log.with_extension("saved")).unwrap();
    fixture.must_fail("No such file");
    fs::rename(fixture.log.with_extension("saved"), &fixture.log).unwrap();
    let collector = fixture.directory.path().join("collector-ca.pem");
    fs::remove_file(&collector).unwrap();
    fixture.must_fail("No such file");
    fs::write(&collector, "fixture").unwrap();
    // Failed second bind removes only the first socket owned by this startup.
    fs::write(&fixture.broker, "operator-owned sentinel").unwrap();
    let output = fixture.command().output().unwrap();
    assert_eq!(output.status.code(), Some(78));
    assert!(!fixture.socket.exists());
    assert_eq!(
        fs::read_to_string(&fixture.broker).unwrap(),
        "operator-owned sentinel"
    );
    fs::remove_file(&fixture.broker).unwrap();
    // The recovered history remains authentic and can reopen repeatedly.
    fixture.launch().stop();
    let final_log = fs::read(&fixture.log).unwrap();
    assert_eq!(sha256_hex(&final_log), sha256_hex(&synchronized_log));
    verify_phase2_requests();
    verify_provisioning_permissions();
    verify_audit_directory_replacement();
    verify_blocked_metadata();
    verify_blocked_cleanup();
    verify_ancestor_pid_peer();
}

fn send_hello(socket: &mut UnixStream, executable: &Path) {
    let encoded = encode_frame(FrameType::ClientHello, &hello(executable)).unwrap();
    // Quota denial can close the socket immediately after the first byte.
    // Send ordinary probes in one call; fragmented-frame behavior has its own
    // tests that explicitly allow early rejection of the remaining writes.
    send_rights(socket, &encoded, 2);
}

fn verify_phase2_requests() {
    let fixture = Fixture::new();
    let daemon = fixture.launch();
    let baseline = fs::read_dir(format!("/proc/{}/fd", daemon.0.id()))
        .unwrap()
        .count();
    for input in [
        None,
        Some(b"".as_slice()),
        Some(b"finite input\0\xff".as_slice()),
    ] {
        let events_before = fixture.diagnostic_count();
        let mut command = Command::new(fixture.directory.path().join("sigrun"));
        command.arg("--socket").arg(&fixture.socket).args([
            "--target-uid",
            "33",
            "--target-gid",
            "0",
            "--cwd",
            "/",
            "--env",
            "LANG=en_US.UTF-8",
            "--env",
            "EMPTY=",
            "--ttl-secs",
            "60",
        ]);
        if let Some(input) = input {
            let path = fixture.directory.path().join("input");
            fs::write(&path, input).unwrap();
            command
                .args(["--stdin", "sha256"])
                .stdin(File::open(path).unwrap());
        } else {
            command.stdin(Stdio::null());
        }
        command
            .arg("--")
            .arg(&fixture.executable)
            .args(["two words", ""])
            .env("UNRELATED_CLIENT_SECRET", "must not be forwarded");
        unsafe {
            command.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(65534) != 0
                    || libc::setuid(65534) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(255),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        let text = String::from_utf8(output.stderr).unwrap();
        let csr =
            sigrund_core::warrant::Csr::parse(text.lines().last().unwrap().as_bytes()).unwrap();
        let w = csr.warrant();
        assert_eq!((w.requester_uid, w.requester_gid), (65534, 65534));
        assert_eq!(
            (
                w.execution_context.target_uid,
                w.execution_context.target_gid
            ),
            (33, 0)
        );
        assert_eq!(
            w.command.argv,
            [fixture.executable.to_str().unwrap(), "two words", ""]
        );
        assert_eq!(
            w.command.executable_sha256,
            sha256_hex(&fs::read(&fixture.executable).unwrap())
        );
        assert_eq!(w.command.stdin_sha256, input.map(sha256_hex));
        assert_eq!(w.policy.not_after.unwrap() - w.policy.not_before, 60);
        assert_eq!(w.execution_context.env_exact.len(), 3);
        assert_eq!(w.execution_context.env_exact["LANG"], "en_US.UTF-8");
        assert_eq!(w.execution_context.env_exact["EMPTY"], "");
        assert!(w.execution_context.caller_env_allowlist.is_empty());
        assert_eq!(w.execution_context.umask, 0o77);
        fixture.wait_for_cleanup(events_before);
        wait_for(|| {
            fs::read_dir(format!("/proc/{}/fd", daemon.0.id()))
                .unwrap()
                .count()
                == baseline
        });
    }
    for (name, kind) in [
        ("empty", "empty"),
        ("script", "script"),
        ("directory", "directory"),
        ("fifo", "fifo"),
        ("socket", "socket"),
        ("link", "link"),
    ] {
        let path = fixture.executable.parent().unwrap().join(name);
        let mut listener = None;
        match kind {
            "empty" => fs::write(&path, []).unwrap(),
            "script" => fs::write(&path, b"#!/bin/sh\n").unwrap(),
            "directory" => fs::create_dir(&path).unwrap(),
            "fifo" => {
                let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            "socket" => listener = Some(std::os::unix::net::UnixListener::bind(&path).unwrap()),
            "link" => std::os::unix::fs::symlink(&fixture.executable, &path).unwrap(),
            _ => unreachable!(),
        }
        let events_before = fixture.diagnostic_count();
        let mut body: serde_json::Value = serde_json::from_slice(&hello(&path)).unwrap();
        body["requested_command"]["executable_path"] = path.to_str().unwrap().into();
        let mut socket = connect(&fixture.socket);
        let encoded =
            encode_frame(FrameType::ClientHello, &serde_json::to_vec(&body).unwrap()).unwrap();
        send_rights(&socket, &encoded[..1], 2);
        socket.write_all(&encoded[1..]).unwrap();
        assert_eq!(
            decision(&mut socket).status,
            "EXECUTABLE_MUTATED_OR_TOO_LARGE",
            "{kind}"
        );
        drop(socket);
        drop(listener);
        fixture.wait_for_cleanup(events_before);
    }
    daemon.stop();
}

// Use child-only umasks so the parallel test harness is unaffected. Every
// successful provisioning must produce files/directories accepted by startup.
fn verify_provisioning_permissions() {
    let fixture = Fixture::new();
    let config =
        sigrund_core::config::DaemonConfig::from_toml(&fs::read(&fixture.config).unwrap()).unwrap();
    for mask in [0o000, 0o002] {
        let base = fixture.directory.path().join(format!("umask-{mask:o}"));
        let state = base.join("state/host");
        let log = base.join("log/host/audit.jsonl");
        let mut command = Command::new(env!("CARGO_BIN_EXE_sigrundctl"));
        command
            .arg("init-host")
            .arg("--state-dir")
            .arg(&state)
            .arg("--log-path")
            .arg(&log);
        unsafe {
            command.pre_exec(move || {
                libc::umask(mask);
                Ok(())
            });
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for path in [
            &state,
            state.parent().unwrap(),
            log.parent().unwrap(),
            log.parent().unwrap().parent().unwrap(),
            &base,
        ] {
            assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o700);
        }
        for (path, mode) in [
            (state.join("host_identity.key"), 0o400),
            (state.join("audit_ratchet.state"), 0o600),
            (log.clone(), 0o600),
        ] {
            let metadata = fs::metadata(path).unwrap();
            assert_eq!(
                (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
                (0, 0, mode)
            );
        }
        sigrund::startup::StartupResources::prepare(&config, &state, &log).unwrap();
    }
    // Trusted existing modes are preserved, rather than chmodded by init-host.
    let state = fixture.directory.path().join("trusted-state");
    let log_dir = fixture.directory.path().join("trusted-log");
    for directory in [&state, &log_dir] {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let log = log_dir.join("audit.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_sigrundctl"))
        .arg("init-host")
        .arg("--state-dir")
        .arg(&state)
        .arg("--log-path")
        .arg(&log)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for directory in [&state, &log_dir] {
        assert_eq!(fs::metadata(directory).unwrap().mode() & 0o777, 0o755);
    }
    sigrund::startup::StartupResources::prepare(&config, &state, &log).unwrap();
    for role in ["state", "log"] {
        for mode in [0o775, 0o777] {
            let base = fixture
                .directory
                .path()
                .join(format!("unsafe-{role}-{mode:o}"));
            let state = base.join("state");
            let log_dir = base.join("log");
            for directory in [&state, &log_dir] {
                fs::create_dir_all(directory).unwrap();
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let unsafe_dir = if role == "state" { &state } else { &log_dir };
            fs::set_permissions(unsafe_dir, fs::Permissions::from_mode(mode)).unwrap();
            let log = log_dir.join("audit.jsonl");
            let output = Command::new(env!("CARGO_BIN_EXE_sigrundctl"))
                .arg("init-host")
                .arg("--state-dir")
                .arg(&state)
                .arg("--log-path")
                .arg(&log)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(73));
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("untrusted provisioning directory")
            );
            assert!(!state.join("host_identity.key").exists());
            assert!(!state.join("audit_ratchet.state").exists());
            assert!(!state.join("audit_ratchet.state.tmp").exists());
            assert!(!log.exists());
            assert_eq!(fs::metadata(unsafe_dir).unwrap().mode() & 0o777, mode);
        }
    }
}

// Pause startup after audit-file verification, then replace both directory
// pathnames. Recovery must use the already checked descriptors, including
// publication of the advanced state and its authenticated recovery record.
fn verify_audit_directory_replacement() {
    for recovery in ["partial", "forward"] {
        let fixture = Fixture::new();
        let state_path = fixture.state.join("audit_ratchet.state");
        let state_bytes = fs::read(&state_path).unwrap();
        let state: serde_json::Value = serde_json::from_slice(&state_bytes).unwrap();
        let genesis: serde_json::Value = serde_json::from_str(
            fs::read_to_string(&fixture.log)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        let mut log = OpenOptions::new().append(true).open(&fixture.log).unwrap();
        if recovery == "partial" {
            log.write_all(b"partial").unwrap();
        } else {
            let mut key = [0; 32];
            let hex = state["key_hex"].as_str().unwrap();
            for (index, byte) in key.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
            }
            let mut record = serde_json::json!({"event_type":"TEST_CRASH_WINDOW",
                "host_id":genesis["host_id"],"seq":state["seq"],
                "prev_record_sha256":state["last_record_sha256"]});
            record["entry_hmac"] = entry_hmac(&key, &serde_json::to_vec(&record).unwrap()).into();
            log.write_all(&serde_json::to_vec(&record).unwrap())
                .unwrap();
            log.write_all(b"\n").unwrap();
        }
        log.sync_all().unwrap();
        drop(log);
        let interposer = fixture.directory.path().join("startup_gate.so");
        assert!(
            Command::new("cc")
                .args(["-shared", "-fPIC", "-Wall", "-Werror", "-o"])
                .arg(&interposer)
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/metadata_gate.c"
                ))
                .status()
                .unwrap()
                .success()
        );
        let metadata = fs::metadata(fixture.directory.path().join("collector-client.key")).unwrap();
        let (mut entered, worker_entered) = UnixStream::pair().unwrap();
        entered
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (mut release, worker_release) = UnixStream::pair().unwrap();
        let entered_fd = worker_entered.as_raw_fd();
        let release_fd = worker_release.as_raw_fd();
        let mut command = fixture.command();
        command
            .env("LD_PRELOAD", &interposer)
            .env("SIGRUND_GATE_INODE", metadata.ino().to_string())
            .env("SIGRUND_GATE_DEVICE", metadata.dev().to_string())
            .env("SIGRUND_GATE_ENTERED_FD", entered_fd.to_string())
            .env("SIGRUND_GATE_RELEASE_FD", release_fd.to_string())
            .stderr(File::create(&fixture.diagnostics).unwrap());
        unsafe {
            command.pre_exec(move || {
                for fd in [entered_fd, release_fd] {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut daemon = DaemonChild(command.spawn().unwrap());
        drop((worker_entered, worker_release));
        entered.read_exact(&mut [0; 8]).unwrap();
        let original_state = fixture.directory.path().join("verified-state");
        let original_log = fixture.directory.path().join("verified-log");
        fs::rename(&fixture.state, &original_state).unwrap();
        fs::rename(fixture.log.parent().unwrap(), &original_log).unwrap();
        for directory in [&fixture.state, fixture.log.parent().unwrap()] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o777)).unwrap();
        }
        for path in [&state_path, &fixture.log] {
            fs::write(path, b"untrusted replacement").unwrap();
        }
        release.write_all(b"x").unwrap();
        wait_for(|| {
            assert!(
                daemon.0.try_wait().unwrap().is_none(),
                "{}",
                fs::read_to_string(&fixture.diagnostics).unwrap()
            );
            fs::read_to_string(&fixture.diagnostics)
                .unwrap()
                .contains("DAEMON_READY")
        });
        fixture.peer(65534, "client");
        daemon.stop();
        for path in [&state_path, &fixture.log] {
            assert_eq!(fs::read(path).unwrap(), b"untrusted replacement");
        }
        assert!(!fixture.state.join("audit_ratchet.state.tmp").exists());
        let verified_log = original_log.join("audit.jsonl");
        assert!(
            fs::read_to_string(&verified_log)
                .unwrap()
                .contains(if recovery == "partial" {
                    "RATCHET_PARTIAL_WRITE_TRUNCATED"
                } else {
                    "RATCHET_FORWARD_RECOVERY"
                })
        );
        let audit = sigrund_core::audit::AuditLog::open_for_host(
            verified_log,
            original_state.join("audit_ratchet.state"),
            genesis["host_id"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(audit.state().seq, if recovery == "partial" { 3 } else { 4 });
    }
}

fn verify_blocked_metadata() {
    let fixture = Fixture::new();
    let config = fs::read_to_string(&fixture.config)
        .unwrap()
        .replace("max_io_workers_global = 16", "max_io_workers_global = 2")
        .replace("max_io_workers_per_uid = 2", "max_io_workers_per_uid = 1");
    fs::write(&fixture.config, config).unwrap();
    let interposer = fixture.directory.path().join("metadata_gate.so");
    let output = Command::new("cc")
        .args(["-shared", "-fPIC", "-Wall", "-Werror", "-o"])
        .arg(&interposer)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/metadata_gate.c"
        ))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let marker_path = fixture.directory.path().join("blocked-metadata");
    fs::write(&marker_path, "metadata gate fixture").unwrap();
    fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o666)).unwrap();
    let marker = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&marker_path)
        .unwrap();
    let metadata = marker.metadata().unwrap();
    let (mut entered, worker_entered) = UnixStream::pair().unwrap();
    entered
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (mut release, worker_release) = UnixStream::pair().unwrap();
    let entered_fd = worker_entered.as_raw_fd();
    let release_fd = worker_release.as_raw_fd();
    let mut command = fixture.command();
    command
        .env("LD_PRELOAD", &interposer)
        .env("SIGRUND_GATE_INODE", metadata.ino().to_string())
        .env("SIGRUND_GATE_DEVICE", metadata.dev().to_string())
        .env("SIGRUND_GATE_ENTERED_FD", entered_fd.to_string())
        .env("SIGRUND_GATE_RELEASE_FD", release_fd.to_string());
    unsafe {
        command.pre_exec(move || {
            for fd in [entered_fd, release_fd] {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut daemon = fixture.launch_command(command);
    drop((worker_entered, worker_release));
    let pid = daemon.0.id();
    let fd_count = || fs::read_dir(format!("/proc/{pid}/fd")).unwrap().count();
    let thread_count = || fs::read_dir(format!("/proc/{pid}/task")).unwrap().count();
    let completed_count = || {
        fs::read_to_string(&fixture.diagnostics)
            .unwrap()
            .lines()
            .filter(|line| line.contains("FD_VALIDATION_COMPLETE"))
            .count()
    };
    let baseline = fd_count();
    let baseline_threads = thread_count();
    assert_eq!(
        baseline_threads, 5,
        "expected coordinator, diagnostics, two fixed workers, and authorization executor"
    );
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    // Profile denials must happen before the interposed metadata syscall.
    for field in ["same_uid", "script", "stdin", "mode", "allowlist"] {
        let mut body: serde_json::Value =
            serde_json::from_slice(&hello(&fixture.executable)).unwrap();
        match field {
            "same_uid" => body["requested_execution_context"]["target_uid"] = serde_json::json!(0),
            "script" => {
                body["requested_command"]["allow_interpreted_script"] = serde_json::json!(true)
            }
            "stdin" => {
                body["requested_command"]["stdin_policy"] =
                    serde_json::json!("unrestricted_interactive")
            }
            "mode" => body["requested_policy"]["mode"] = serde_json::json!("time_range"),
            "allowlist" => {
                body["requested_execution_context"]["caller_env_allowlist"] =
                    serde_json::json!(["TERM"])
            }
            _ => unreachable!(),
        }
        let encoded =
            encode_frame(FrameType::ClientHello, &serde_json::to_vec(&body).unwrap()).unwrap();
        let mut socket = connect(&fixture.socket);
        send_fds(
            &socket,
            &encoded[..1],
            &[marker.as_raw_fd(), null.as_raw_fd()],
        );
        socket.write_all(&encoded[1..]).unwrap();
        assert_eq!(decision(&mut socket).status, "POLICY_VIOLATION", "{field}");
        drop(socket);
        wait_for(|| fd_count() == baseline);
        let mut gate = libc::pollfd {
            fd: entered.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut gate, 1, 0) },
            0,
            "{field}: metadata ran before profile denial"
        );
    }
    let mut stalled = connect(&fixture.socket);
    let encoded = encode_frame(FrameType::ClientHello, &hello(&fixture.executable)).unwrap();
    send_fds(
        &stalled,
        &encoded[..1],
        &[marker.as_raw_fd(), null.as_raw_fd()],
    );
    stalled.write_all(&encoded[1..]).unwrap();
    let mut tid = [0u8; 8];
    entered.read_exact(&mut tid).unwrap();
    assert_ne!(
        u64::from_ne_bytes(tid),
        pid as u64,
        "fstat blocked the coordinator thread"
    );
    // No second task from this UID may replace a blocked worker. Another UID
    // can still use the second worker and the event loop remains responsive.
    let mut same_uid = connect(&fixture.socket);
    send_hello(&mut same_uid, &fixture.executable);
    assert_eq!(decision(&mut same_uid).status, "RESOURCE_EXHAUSTED");
    drop(same_uid);
    fixture.peer(65534, "client");
    // Occupy the second worker using another UID, then probe the global cap
    // from a third UID, independently of per-UID and active-socket caps.
    let mut holder_command = fixture.peer_command(65534, "blocked_metadata");
    holder_command.env("SIGRUND_PHASE1_MARKER", &marker_path);
    let mut holder = holder_command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    entered.read_exact(&mut tid).unwrap();
    fixture.peer(65533, "worker_quota");
    assert_eq!(decision(&mut stalled).status, "REQUEST_TIMEOUT");
    expect_closed(&mut stalled);
    drop(stalled);
    // Both sockets expire while their tasks remain in the kernel syscall.
    // Worker FDs and quotas must stay pinned until actual cleanup.
    wait_for(|| fd_count() == baseline + 4);
    let mut timed_out_uid = connect(&fixture.socket);
    send_hello(&mut timed_out_uid, &fixture.executable);
    assert_eq!(decision(&mut timed_out_uid).status, "RESOURCE_EXHAUSTED");
    drop(timed_out_uid);
    holder.stdin.take().unwrap().write_all(b"x").unwrap();
    wait_for(|| holder.try_wait().unwrap().is_some());
    assert!(holder.wait().unwrap().success());
    let completed_before = completed_count();
    release.write_all(b"xx").unwrap();
    wait_for(|| completed_count() == completed_before + 2);
    wait_for(|| fd_count() == baseline);
    assert_eq!(
        thread_count(),
        baseline_threads,
        "blocked workers were replaced or leaked"
    );
    // Late success/error cannot resurrect either timed-out request.
    let events = fs::read_to_string(&fixture.diagnostics).unwrap();
    assert_eq!(
        events
            .lines()
            .filter(|line| line.contains("CLIENT_HELLO_VALIDATED"))
            .count(),
        1
    );
    let mut recovered = connect(&fixture.socket);
    send_hello(&mut recovered, &fixture.executable);
    assert_eq!(decision(&mut recovered).status, "TIMEOUT_CSR");
    drop(recovered);
    wait_for(|| fd_count() == baseline);
    // Disconnect also cancels without prematurely releasing the worker slot.
    let mut disconnected = connect(&fixture.socket);
    send_fds(
        &disconnected,
        &encoded[..1],
        &[marker.as_raw_fd(), null.as_raw_fd()],
    );
    disconnected.write_all(&encoded[1..]).unwrap();
    entered.read_exact(&mut tid).unwrap();
    drop(disconnected);
    wait_for(|| fd_count() == baseline + 2);
    let mut pinned_uid = connect(&fixture.socket);
    send_hello(&mut pinned_uid, &fixture.executable);
    assert_eq!(decision(&mut pinned_uid).status, "RESOURCE_EXHAUSTED");
    drop(pinned_uid);
    let completed_before = completed_count();
    release.write_all(b"x").unwrap();
    wait_for(|| completed_count() == completed_before + 1);
    wait_for(|| fd_count() == baseline);
    // Shutdown must not join or wait for a worker stuck in fstat().
    let mut stalled = connect(&fixture.socket);
    send_fds(
        &stalled,
        &encoded[..1],
        &[marker.as_raw_fd(), null.as_raw_fd()],
    );
    stalled.write_all(&encoded[1..]).unwrap();
    entered.read_exact(&mut tid).unwrap();
    assert!(daemon.0.try_wait().unwrap().is_none());
    daemon.stop();
    expect_closed(&mut stalled);
    assert!(!fixture.socket.exists() && !fixture.broker.exists());
}

fn verify_blocked_cleanup() {
    let fixture = Fixture::new();
    let config = fs::read_to_string(&fixture.config)
        .unwrap()
        .replace("max_io_workers_global = 16", "max_io_workers_global = 2")
        .replace("max_io_workers_per_uid = 2", "max_io_workers_per_uid = 1");
    fs::write(&fixture.config, config).unwrap();
    let interposer = fixture.directory.path().join("close_gate.so");
    let output = Command::new("cc")
        .args(["-shared", "-fPIC", "-Wall", "-Werror", "-o"])
        .arg(&interposer)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/metadata_gate.c"
        ))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let marker_path = fixture.directory.path().join("blocked-close");
    fs::write(&marker_path, "close gate fixture").unwrap();
    let marker = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&marker_path)
        .unwrap();
    let metadata = marker.metadata().unwrap();
    let (mut entered, worker_entered) = UnixStream::pair().unwrap();
    entered
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    let (mut release, worker_release) = UnixStream::pair().unwrap();
    let entered_fd = worker_entered.as_raw_fd();
    let release_fd = worker_release.as_raw_fd();
    let mut command = fixture.command();
    command
        .env("LD_PRELOAD", &interposer)
        .env("SIGRUND_GATE_CLOSE", "1")
        .env("SIGRUND_GATE_INODE", metadata.ino().to_string())
        .env("SIGRUND_GATE_DEVICE", metadata.dev().to_string())
        .env("SIGRUND_GATE_ENTERED_FD", entered_fd.to_string())
        .env("SIGRUND_GATE_RELEASE_FD", release_fd.to_string());
    unsafe {
        command.pre_exec(move || {
            for fd in [entered_fd, release_fd] {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let daemon = fixture.launch_command(command);
    drop((worker_entered, worker_release));
    let pid = daemon.0.id();
    let fd_count = || fs::read_dir(format!("/proc/{pid}/fd")).unwrap().count();
    let thread_count = || fs::read_dir(format!("/proc/{pid}/task")).unwrap().count();
    let baseline = fd_count();
    let threads = thread_count();
    let epoll_info = fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .flatten()
        .find(|entry| {
            fs::read_link(entry.path())
                .is_ok_and(|path| path == Path::new("anon_inode:[eventpoll]"))
        })
        .map(|entry| {
            PathBuf::from(format!(
                "/proc/{pid}/fdinfo/{}",
                entry.file_name().to_str().unwrap()
            ))
        })
        .expect("daemon epoll descriptor");
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    let encoded = encode_frame(FrameType::ClientHello, &hello(&fixture.executable)).unwrap();
    for case in [
        "valid",
        "json",
        "type",
        "rights",
        "late",
        "timeout",
        "disconnect",
        "profile",
        "broker",
    ] {
        let events_before = fs::read_to_string(&fixture.diagnostics)
            .unwrap()
            .lines()
            .count();
        let broker = case == "broker";
        let mut socket = connect(if broker {
            &fixture.broker
        } else {
            &fixture.socket
        });
        let rights = [marker.as_raw_fd(), null.as_raw_fd()];
        match case {
            "type" => send_fds(&socket, &[255], &rights),
            "rights" => send_fds(
                &socket,
                &encoded[..1],
                &[
                    marker.as_raw_fd(),
                    null.as_raw_fd(),
                    null.as_raw_fd(),
                    null.as_raw_fd(),
                    null.as_raw_fd(),
                ],
            ),
            "late" => {
                socket.write_all(&encoded[..1]).unwrap();
                send_fds(&socket, &encoded[1..2], &rights);
            }
            "broker" => send_fds(&socket, &[0], &rights),
            "json" => {
                let bad = encode_frame(FrameType::ClientHello, b"{").unwrap();
                send_fds(&socket, &bad[..1], &rights);
                socket.write_all(&bad[1..]).unwrap();
            }
            "profile" => {
                let mut body: serde_json::Value =
                    serde_json::from_slice(&hello(&fixture.executable)).unwrap();
                body["requested_execution_context"]["target_uid"] = serde_json::json!(0);
                let bad = encode_frame(FrameType::ClientHello, &serde_json::to_vec(&body).unwrap())
                    .unwrap();
                send_fds(&socket, &bad[..1], &rights);
                socket.write_all(&bad[1..]).unwrap();
            }
            _ => {
                send_fds(&socket, &encoded[..1], &rights);
                if !matches!(case, "timeout" | "disconnect") {
                    socket.write_all(&encoded[1..]).unwrap();
                }
            }
        }
        if case == "disconnect" {
            // Wait for actual userspace receipt, not just socket queuing.
            wait_for(|| {
                fs::read_dir(format!("/proc/{pid}/fd"))
                    .unwrap()
                    .flatten()
                    .any(|entry| fs::read_link(entry.path()).is_ok_and(|path| path == marker_path))
            });
            socket.shutdown(std::net::Shutdown::Both).unwrap();
        }
        let mut task = None;
        wait_for(|| {
            task = fs::read_to_string(&fixture.diagnostics)
                .unwrap()
                .lines()
                .skip(events_before)
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .find(|event| event["event"] == "SOCKET_ADMITTED")
                .and_then(|event| event["worker_task"].as_u64());
            task.is_some()
        });
        let task = task.unwrap();
        let mut tid = [0u8; 8];
        entered
            .read_exact(&mut tid)
            .unwrap_or_else(|error| panic!("{case}: close gate not reached: {error}"));
        assert_ne!(
            u64::from_ne_bytes(tid),
            pid as u64,
            "{case}: close ran on event loop"
        );
        assert_eq!(
            thread_count(),
            threads,
            "{case}: replacement cleanup worker"
        );
        // The cleanup reservation is still charged to UID 0. No additional
        // caller FDs may be received just to reject this quota-denied request.
        let mut same_uid = connect(&fixture.socket);
        send_hello(&mut same_uid, &fixture.executable);
        assert_eq!(
            decision(&mut same_uid).status,
            "RESOURCE_EXHAUSTED",
            "{case}"
        );
        drop(same_uid);
        fixture.peer(65534, "client");
        if !broker && case != "disconnect" {
            assert_eq!(
                decision(&mut socket).status,
                if case == "valid" {
                    "TIMEOUT_CSR"
                } else {
                    "REQUEST_TIMEOUT"
                },
                "{case}"
            );
        }
        drop(socket);
        // The worker may still own a duplicate control socket while closing
        // partial-frame rights. Removing the connection must remove its epoll
        // entry before that close finishes, or level-triggered HUP spins the
        // coordinator on a stale token. Inspect the registration directly so
        // this regression does not rely on timing-sensitive CPU measurements.
        wait_for(|| {
            !fs::read_to_string(&epoll_info)
                .unwrap()
                .lines()
                .filter(|line| line.starts_with("tfd:"))
                .any(|line| {
                    let mut fields = line.split_ascii_whitespace();
                    assert!(fields.any(|field| field == "data:"));
                    u64::from_str_radix(fields.next().expect("epoll token"), 16).unwrap() == task
                })
        });
        release.write_all(b"x").unwrap();
        wait_for(|| {
            fs::read_to_string(&fixture.diagnostics)
                .unwrap()
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|event| {
                    event["event"] == "FD_VALIDATION_COMPLETE"
                        && event["worker_task"].as_u64() == Some(task)
                })
        });
        wait_for(|| fd_count() == baseline);
        // Quota recovery, not merely an FD-count observation, is the gate.
        let events_before = fs::read_to_string(&fixture.diagnostics)
            .unwrap()
            .lines()
            .count();
        let mut recovered = connect(&fixture.socket);
        send_hello(&mut recovered, &fixture.executable);
        assert_eq!(decision(&mut recovered).status, "TIMEOUT_CSR", "{case}");
        drop(recovered);
        wait_for(|| {
            let events: Vec<serde_json::Value> = fs::read_to_string(&fixture.diagnostics)
                .unwrap()
                .lines()
                .skip(events_before)
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
            let task = events
                .iter()
                .find(|event| event["event"] == "SOCKET_ADMITTED")
                .and_then(|event| event["worker_task"].as_u64());
            task.is_some()
                && events.iter().any(|event| {
                    event["event"] == "FD_VALIDATION_COMPLETE"
                        && event["worker_task"].as_u64() == task
                })
        });
        wait_for(|| fd_count() == baseline);
    }
    // A worker still blocked in close must not make SIGTERM wait for cleanup.
    let mut stalled = connect(&fixture.socket);
    send_fds(
        &stalled,
        &encoded[..1],
        &[marker.as_raw_fd(), null.as_raw_fd()],
    );
    stalled.write_all(&encoded[1..]).unwrap();
    let mut tid = [0u8; 8];
    entered.read_exact(&mut tid).unwrap();
    assert_eq!(decision(&mut stalled).status, "TIMEOUT_CSR");
    daemon.stop();
    expect_closed(&mut stalled);
    assert!(!fixture.socket.exists() && !fixture.broker.exists());
}

fn verify_ancestor_pid_peer() {
    let directory = tempfile::tempdir().unwrap();
    let ready = directory.path().join("ready.json");
    let child = Command::new("unshare")
        .args(["--pid", "--fork", "--kill-child"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "phase1_pid_namespace_fixture",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SIGRUND_PHASE1_PID_READY", &ready)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut service = DaemonChild(child);
    wait_for(|| {
        assert!(
            service.0.try_wait().unwrap().is_none(),
            "PID namespace fixture exited early"
        );
        ready.exists()
    });
    let paths: Vec<PathBuf> = serde_json::from_slice(&fs::read(&ready).unwrap()).unwrap();
    // An ancestor PID-namespace peer has pid=0 as observed by the daemon.
    // Each connection must close while the daemon and both listeners survive.
    for path in paths.iter().cycle().take(6) {
        expect_closed(&mut connect(path));
    }
    service.0.stdin.take().unwrap().write_all(b"x").unwrap();
    wait_for(|| service.0.try_wait().unwrap().is_some());
    assert!(service.0.wait().unwrap().success());
}

#[test]
#[ignore = "PID namespace child of the namespace exit gate"]
fn phase1_pid_namespace_fixture() {
    let ready = PathBuf::from(std::env::var_os("SIGRUND_PHASE1_PID_READY").unwrap());
    let fixture = Fixture::new();
    let mut daemon = fixture.launch();
    let temporary = ready.with_extension("tmp");
    fs::write(
        &temporary,
        serde_json::to_vec(&[&fixture.socket, &fixture.broker]).unwrap(),
    )
    .unwrap();
    fs::rename(temporary, &ready).unwrap();
    io::stdin().read_exact(&mut [0u8]).unwrap();
    assert!(
        daemon.0.try_wait().unwrap().is_none(),
        "ancestor peer stopped the daemon"
    );
    // A mappable peer still works after both sockets rejected pid=0 peers.
    let mut socket = connect(&fixture.socket);
    send_hello(&mut socket, &fixture.executable);
    assert_eq!(decision(&mut socket).status, "TIMEOUT_CSR");
    drop(socket);
    let mut broker = connect(&fixture.broker);
    broker.write_all(&[0, 0, 0, 2, b'{', b'}']).unwrap();
    expect_closed(&mut broker);
    daemon.stop();
}

#[test]
#[ignore = "unprivileged child of the namespace fixture"]
fn phase1_peer_probe() {
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let client = PathBuf::from(std::env::var_os("SIGRUND_PHASE1_CLIENT").unwrap());
    let executable = PathBuf::from(std::env::var_os("SIGRUND_PHASE1_EXECUTABLE").unwrap());
    let broker = PathBuf::from(std::env::var_os("SIGRUND_PHASE1_BROKER").unwrap());
    match std::env::var("SIGRUND_PHASE1_ROLE").unwrap().as_str() {
        "client" => {
            let mut socket = connect(&client);
            let encoded = encode_frame(FrameType::ClientHello, &hello(&executable)).unwrap();
            send_rights(&socket, &encoded[..1], 2);
            socket.write_all(&encoded[1..]).unwrap();
            let decision = decision(&mut socket);
            assert_eq!(decision.status, "TIMEOUT_CSR");
            let csr = sigrund_core::warrant::Csr::parse(decision.csr_payload.unwrap().as_bytes())
                .unwrap();
            assert_eq!(csr.warrant().requester_uid, unsafe { libc::getuid() });
            assert_eq!(csr.warrant().requester_gid, unsafe { libc::getgid() });
            expect_closed(&mut socket);
        }
        "worker_quota" => {
            let mut socket = connect(&client);
            send_hello(&mut socket, &executable);
            assert_eq!(decision(&mut socket).status, "RESOURCE_EXHAUSTED");
            expect_closed(&mut socket);
        }
        "blocked_metadata" => {
            let marker = OpenOptions::new()
                .read(true)
                .write(true)
                .open(std::env::var_os("SIGRUND_PHASE1_MARKER").unwrap())
                .unwrap();
            let null = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")
                .unwrap();
            let mut socket = connect(&client);
            let encoded = encode_frame(FrameType::ClientHello, &hello(&executable)).unwrap();
            send_fds(
                &socket,
                &encoded[..1],
                &[marker.as_raw_fd(), null.as_raw_fd()],
            );
            socket.write_all(&encoded[1..]).unwrap();
            io::stdin().read_exact(&mut [0u8]).unwrap();
            assert_eq!(decision(&mut socket).status, "REQUEST_TIMEOUT");
            expect_closed(&mut socket);
        }
        "broker_permissions" => assert_eq!(
            UnixStream::connect(&broker).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        ),
        "broker_credentials" => {
            let mut socket = connect(&broker);
            // A syntactically signed response is never parsed for this UID.
            let response = serde_json::json!({"status":"approved", "exec_id":new_uuidv7().to_string(),
                "dsse_envelope":{"payloadType":"application/vnd.sigrun.warrant+json", "payload":STANDARD.encode(b"{}"),
                    "signatures":[{"keyid":"mandator-alice-yubikey", "sig":STANDARD.encode([1; 64])}]}}).to_string();
            let mut frame = (response.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(response.as_bytes());
            // Send only its valid bounded header: a parser that mistakenly
            // admits this UID would wait for the body instead of closing.
            let _ = socket.write_all(&frame[..4]);
            expect_closed(&mut socket);
        }
        "hold" => {
            let _socket = connect(&client);
            let diagnostics =
                PathBuf::from(std::env::var_os("SIGRUND_PHASE1_DIAGNOSTICS").unwrap());
            wait_for(|| {
                fs::read_to_string(&diagnostics)
                    .unwrap()
                    .lines()
                    .any(|line| {
                        serde_json::from_str::<serde_json::Value>(line).is_ok_and(|event| {
                            event["event"] == "SOCKET_ADMITTED"
                                && event["requester_pid"] == std::process::id()
                        })
                    })
            });
            println!("PEER_READY");
            io::stdout().flush().unwrap();
            io::stdin().read_exact(&mut [0u8]).unwrap();
        }
        "quota" => expect_closed(&mut connect(&client)),
        role => panic!("unexpected role {role}"),
    }
}

#[path = "fixtures/phase3.rs"]
mod phase3;
