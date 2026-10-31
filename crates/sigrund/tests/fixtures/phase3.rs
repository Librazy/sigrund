//! Phase 3 uses the production binaries inside the same disposable namespace
//! as the transport fixtures, with a real controlling pseudo-terminal.
use super::*;
use std::os::fd::FromRawFd;

#[test]
fn exit_gate() {
    let _gate = NAMESPACE_GATE.lock().unwrap();
    let output = Command::new("unshare")
        .args(["--user", "--map-auto", "--map-root-user"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "phase3::namespace_fixture",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SIGRUND_PHASE3_NAMESPACE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Phase 3 namespace gate:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
#[ignore = "invoked by the namespace exit gate"]
fn namespace_fixture() {
    assert_eq!(std::env::var("SIGRUND_PHASE3_NAMESPACE").unwrap(), "1");
    let fixture = Fixture::new();
    let identity = fixture.directory.path().join("identity");
    assert!(
        Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&identity)
            .status()
            .unwrap()
            .success()
    );
    let public = fs::read_to_string(identity.with_extension("pub")).unwrap();
    let signers =
        sigrund_core::config::SignerPolicyFile::from_toml(&fs::read(&fixture.signers).unwrap())
            .unwrap();
    let original = signers.signers[0].public_key.clone();
    fs::write(
        &fixture.signers,
        fs::read_to_string(&fixture.signers)
            .unwrap()
            .replace(&original, public.trim())
            .replace(
                "allowed_requester_uids = [1001]",
                "allowed_requester_uids = [0, 65534]",
            ),
    )
    .unwrap();
    fs::write(
        &fixture.config,
        format!(
            "{}\napproval_signer_id = \"mandator-alice-yubikey\"\n",
            fs::read_to_string(&fixture.config).unwrap()
        ),
    )
    .unwrap();
    let daemon = fixture.launch();
    let initial_log = fs::read(&fixture.log).unwrap();
    // No approver: completed canonical CSR is returned immediately.
    let before = fixture.diagnostic_count();
    let mut socket = connect(&fixture.socket);
    send_hello(&mut socket, &fixture.executable);
    assert_eq!(decision(&mut socket).status, "TIMEOUT_CSR");
    drop(socket);
    fixture.wait_for_cleanup(before);
    let (mut terminal, mut approver) = launch_approver(&fixture, &identity);
    wait_for(|| {
        fs::read_to_string(&fixture.diagnostics)
            .unwrap()
            .lines()
            .any(|line| line.contains("SOCKET_ADMITTED") && line.contains("\"broker\":true"))
    });
    // A non-root requester drives the real client/snapshot/TTY/signature path.
    let before = fixture.diagnostic_count();
    let mut command = Command::new(fixture.directory.path().join("sigrun"));
    command
        .arg("--socket")
        .arg(&fixture.socket)
        .args([
            "--target-uid",
            "33",
            "--target-gid",
            "33",
            "--supplementary-gid",
            "33",
            "--capability",
            "CAP_NET_BIND_SERVICE",
            "--stdin",
            "sha256",
            "--ttl-secs",
            "60",
            "--",
        ])
        .arg(&fixture.executable)
        .args(["two words", "", "quote\"\\λ"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
    let mut child = command.spawn().unwrap();
    let input = b"sealed stdin\0\xff";
    child.stdin.take().unwrap().write_all(input).unwrap();
    let display = prompt(&mut terminal);
    for field in [
        "exec_id",
        "signer_id",
        "key_fingerprint",
        "algorithm",
        "requester_uid",
        "requester_gid",
        "target_uid",
        "target_gid",
        "supplementary_gids",
        "capabilities",
        "umask",
        "allow_interpreted_script",
        "tty_mode",
        "stdin_policy",
        "stdin_sha256",
        "executable_path",
        "executable_sha256",
        "host_id",
        "grant_id",
        "not_before",
        "not_after",
        "mode",
        "version",
        "caller_env_allowlist",
        "env_exact",
        "cwd",
        "argv",
    ] {
        assert!(
            display.contains(field),
            "missing prompt field {field}: {display}"
        );
    }
    assert!(display.contains("65534"));
    assert!(display.contains("two words"));
    assert!(display.contains("[2] = \"\""));
    assert!(display.contains(r#"quote\"\\\u{03BB}"#));
    assert!(display.is_ascii());
    assert!(display.contains(&sha256_hex(input)));
    assert!(display.contains("CAP_NET_BIND_SERVICE"));
    assert!(display.contains(&sha256_hex(&fs::read(&fixture.executable).unwrap())));
    // Approval binds the retained executable snapshot even if the pathname
    // now contains different bytes; the daemon must not silently resnapshot.
    fs::write(&fixture.executable, b"\x7fELFreplacement-after-prompt").unwrap();
    // A busy request must be denied before another snapshot can start.
    let mut busy = connect(&fixture.socket);
    send_hello(
        &mut busy,
        &fixture
            .executable
            .with_file_name("missing-busy-snapshot-source"),
    );
    assert_eq!(decision(&mut busy).status, "RESOURCE_EXHAUSTED");
    drop(busy);
    let mut invalid_policy = connect(&fixture.socket);
    let mut invalid_hello: serde_json::Value =
        serde_json::from_slice(&hello(&fixture.executable)).unwrap();
    invalid_hello["requested_execution_context"]["target_uid"] = 77.into();
    send_rights(
        &invalid_policy,
        &encode_frame(
            FrameType::ClientHello,
            &serde_json::to_vec(&invalid_hello).unwrap(),
        )
        .unwrap(),
        2,
    );
    assert_eq!(decision(&mut invalid_policy).status, "POLICY_VIOLATION");
    drop(invalid_policy);
    terminal.write_all(b"yes\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(255),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("execution is disabled by --authorization-only"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.wait_for_cleanup(before);
    assert!(
        approver.0.try_wait().unwrap().is_none(),
        "approver should remain connected for subsequent requests"
    );
    // Blank and explicit no are default-deny and reuse the same idle broker.
    for answer in [b"\n".as_slice(), b"no\n", b"\x04"] {
        let before = fixture.diagnostic_count();
        let mut socket = connect(&fixture.socket);
        send_hello(&mut socket, &fixture.executable);
        prompt(&mut terminal);
        terminal.write_all(answer).unwrap();
        let response = decision(&mut socket);
        assert_eq!(response.status, "REJECTED");
        assert!(
            response
                .message
                .contains(if answer == b"\x04" { "EOF" } else { "refused" })
        );
        drop(socket);
        fixture.wait_for_cleanup(before);
    }
    // Requester cancellation invalidates the prompt and stops the watcher.
    let before = fixture.diagnostic_count();
    let mut socket = connect(&fixture.socket);
    send_hello(&mut socket, &fixture.executable);
    prompt(&mut terminal);
    drop(socket);
    wait_for(|| approver.0.try_wait().unwrap().is_some());
    fixture.wait_for_cleanup(before);
    broker_failures_and_reconnect(&fixture, &identity);
    operator_failures_and_expiry(&fixture, &identity);
    wrong_operator_identity(&fixture);
    revocation_after_approval_request(&fixture, &identity);
    slow_signing_cancellation(&fixture, &identity);
    successful_agent_and_encrypted_identity(&fixture, &identity);
    encrypted_signing_cancellation_restores_terminal(&fixture, &identity);
    // The preserved approval gate now reaches Phase 4's durable boundary.
    // Each successful approval consumes a fresh grant, records its abort, and
    // cannot claim child readiness in the authorization-only profile.
    let log = fs::read(&fixture.log).unwrap();
    assert!(log.starts_with(&initial_log));
    let events: Vec<serde_json::Value> = String::from_utf8(log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        events
            .iter()
            .filter(|r| r["event_type"] == "AUTH_COMMIT")
            .count(),
        4
    );
    assert_eq!(
        events
            .iter()
            .filter(|r| r["event_type"] == "AUTH_ABORTED_POST_COMMIT")
            .count(),
        4
    );
    assert!(
        events
            .iter()
            .all(|r| !r["event_type"].as_str().unwrap().starts_with("EXEC_"))
    );
    assert!(fixture.state.join("state.sqlite").exists());
    daemon.stop();
}

fn launch_approver(fixture: &Fixture, identity: &Path) -> (File, DaemonChild) {
    launch_approver_with(fixture, identity, |_| {})
}
fn launch_approver_with(
    fixture: &Fixture,
    identity: &Path,
    configure: impl FnOnce(&mut Command),
) -> (File, DaemonChild) {
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
    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
    }
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    let error = fixture.directory.path().join("approver.stderr");
    let mut command = Command::new(env!("CARGO_BIN_EXE_sigrund-approve"));
    command
        .arg("--socket")
        .arg(&fixture.broker)
        .arg("--signers")
        .arg(&fixture.signers)
        .arg("--identity")
        .arg(identity)
        .stdin(Stdio::from(slave))
        .stdout(Stdio::null())
        .stderr(File::create(error).unwrap());
    configure(&mut command);
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    (master, DaemonChild(command.spawn().unwrap()))
}
fn prompt(terminal: &mut File) -> String {
    let mut bytes = Vec::new();
    wait_for(|| {
        let mut chunk = [0; 4096];
        match terminal.read(&mut chunk) {
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            r => panic!("TTY read failed {r:?}: {}", String::from_utf8_lossy(&bytes)),
        }
        bytes
            .windows(b"Approve and sign? [y/N] ".len())
            .any(|w| w == b"Approve and sign? [y/N] ")
    });
    String::from_utf8(bytes).unwrap()
}

fn admitted_broker(fixture: &Fixture) -> UnixStream {
    let before = fixture.diagnostic_count();
    let socket = connect(&fixture.broker);
    wait_for(|| {
        fs::read_to_string(&fixture.diagnostics)
            .unwrap()
            .lines()
            .skip(before)
            .any(|line| line.contains("SOCKET_ADMITTED") && line.contains("\"broker\":true"))
    });
    socket
}
fn broker_request(socket: &mut UnixStream) -> sigrund_core::approval::ApprovalRequest {
    let mut length = [0u8; 4];
    socket.read_exact(&mut length).unwrap();
    let length = u32::from_be_bytes(length) as usize;
    assert!(length <= 524_288);
    let mut body = vec![0; length];
    socket.read_exact(&mut body).unwrap();
    sigrund_core::approval::ApprovalRequest::parse_jcs(&body).unwrap()
}
fn broker_send(socket: &mut UnixStream, value: &serde_json::Value) {
    let body = sigrund_core::json::canonical_bytes(value).unwrap();
    socket
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    socket.write_all(&body).unwrap();
}
fn revocation_after_approval_request(fixture: &Fixture, identity: &Path) {
    let mut broker = admitted_broker(fixture);
    let before = fixture.diagnostic_count();
    let mut client = connect(&fixture.socket);
    send_hello(&mut client, &fixture.executable);
    let approval = broker_request(&mut broker);
    let csr = sigrund_core::warrant::Csr::parse(approval.csr_payload.as_bytes()).unwrap();
    let store = sigrund_core::state::StateStore::open(fixture.state.join("state.sqlite")).unwrap();
    store
        .revoke(
            "grant_id",
            &csr.warrant().grant_id,
            csr.warrant().policy.not_before,
            "revoked while awaiting confirmation",
        )
        .unwrap();
    let response = signed_response(&approval, identity, |_| {});
    broker_send(&mut broker, &response);
    assert_eq!(decision(&mut client).status, "REVOKED");
    drop(client);
    fixture.wait_for_cleanup(before);
    drop(broker);
}
fn signed_response(
    request: &sigrund_core::approval::ApprovalRequest,
    identity: &Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> serde_json::Value {
    use ssh_key::encoding::Encode;
    let mut warrant: serde_json::Value = serde_json::from_str(&request.csr_payload).unwrap();
    mutate(&mut warrant);
    let payload = sigrund_core::json::canonical_bytes(&warrant).unwrap();
    let mut helper = Command::new("/usr/bin/ssh-keygen")
        .args([
            "-Y",
            "sign",
            "-n",
            "sigrun.warrant.v1",
            "-O",
            "hashalg=sha512",
            "-f",
        ])
        .arg(identity)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    helper
        .stdin
        .take()
        .unwrap()
        .write_all(&sigrund_core::crypto::pae(
            sigrund_core::crypto::WARRANT_PAYLOAD_TYPE,
            &payload,
        ))
        .unwrap();
    let result = helper.wait_with_output().unwrap();
    assert!(result.status.success());
    let raw = ssh_key::SshSig::from_pem(&result.stdout)
        .unwrap()
        .encode_vec()
        .unwrap();
    serde_json::json!({"status":"approved","exec_id":request.exec_id,
        "dsse_envelope":{"payloadType":sigrund_core::crypto::WARRANT_PAYLOAD_TYPE,
            "payload":STANDARD.encode(payload),"signatures":[{"keyid":request.signer_id,"sig":STANDARD.encode(raw)}]}})
}
fn broker_failures_and_reconnect(fixture: &Fixture, identity: &Path) {
    // Each response is signed with the real configured key, but changes one
    // retained CSR field. A valid signature cannot replace the original CSR.
    for field in [
        "argv",
        "executable_sha256",
        "target_uid",
        "grant_id",
        "exec_id",
        "signer_id",
        "signature",
        "malformed",
        "disconnect",
        "expired",
    ] {
        let mut broker = admitted_broker(fixture);
        let before = fixture.diagnostic_count();
        let mut client = connect(&fixture.socket);
        if field == "expired" {
            let mut hello: serde_json::Value =
                serde_json::from_slice(&hello(&fixture.executable)).unwrap();
            hello["requested_policy"]["ttl_secs"] = 1.into();
            send_rights(
                &client,
                &encode_frame(FrameType::ClientHello, &serde_json::to_vec(&hello).unwrap())
                    .unwrap(),
                2,
            );
        } else {
            send_hello(&mut client, &fixture.executable);
        }
        let request = broker_request(&mut broker);
        if field == "disconnect" {
            broker.shutdown(std::net::Shutdown::Both).unwrap();
        } else if field == "malformed" {
            broker.write_all(&2u32.to_be_bytes()).unwrap();
            broker.write_all(b"{}").unwrap();
        } else {
            if field == "expired" {
                thread::sleep(Duration::from_secs(2));
            }
            let mut response = signed_response(&request, identity, |w| match field {
                "argv" => w["command"]["argv"][0] = "changed".into(),
                "executable_sha256" => w["command"]["executable_sha256"] = "f".repeat(64).into(),
                "target_uid" => w["execution_context"]["target_uid"] = 0.into(),
                "grant_id" => w["grant_id"] = new_uuidv7().to_string().into(),
                _ => {}
            });
            match field {
                "exec_id" => response["exec_id"] = new_uuidv7().to_string().into(),
                "signer_id" => {
                    response["dsse_envelope"]["signatures"][0]["keyid"] = "wrong-signer".into()
                }
                "signature" => {
                    response["dsse_envelope"]["signatures"][0]["sig"] =
                        STANDARD.encode([0; 64]).into()
                }
                _ => {}
            }
            broker_send(&mut broker, &response);
        }
        let response = decision(&mut client);
        assert_eq!(
            response.status,
            match field {
                "malformed" | "disconnect" => "TIMEOUT_CSR",
                "expired" => "EXPIRED_OR_NOT_YET_VALID",
                _ => "POLICY_VIOLATION",
            },
            "{field}: {}",
            response.message
        );
        if response.status == "TIMEOUT_CSR" {
            assert_eq!(
                response.csr_payload.as_deref(),
                Some(request.csr_payload.as_str())
            );
        }
        expect_closed(&mut broker);
        drop(client);
        fixture.wait_for_cleanup(before);
    }
    // A complete valid response may reuse the idle broker, but a duplicate
    // response is unsolicited and must retire it rather than authorize again.
    let mut broker = admitted_broker(fixture);
    let before = fixture.diagnostic_count();
    let mut client = connect(&fixture.socket);
    send_hello(&mut client, &fixture.executable);
    let request = broker_request(&mut broker);
    let response = signed_response(&request, identity, |_| {});
    broker_send(&mut broker, &response);
    assert!(
        decision(&mut client)
            .message
            .contains("disabled by --authorization-only")
    );
    drop(client);
    fixture.wait_for_cleanup(before);
    broker_send(&mut broker, &response);
    expect_closed(&mut broker);
}

fn operator_failures_and_expiry(fixture: &Fixture, identity: &Path) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sigrund-approve"));
    command.arg("--identity").arg(identity).stdin(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let non_tty = command.output().unwrap();
    assert!(!non_tty.status.success());
    let (_terminal, mut bad_tty) = launch_approver_with(fixture, identity, |command| {
        command.args(["--tty", "/dev/null"]);
    });
    wait_for(|| bad_tty.0.try_wait().unwrap().is_some());
    assert!(
        fs::read_to_string(fixture.directory.path().join("approver.stderr"))
            .unwrap()
            .contains("controlling foreground terminal")
    );
    // Expiry while the real operator is looking at the prompt never refreshes
    // the signed time window. Refusal keeps this broker reusable.
    let admission = fixture.diagnostic_count();
    let (mut terminal, mut approver) = launch_approver(fixture, identity);
    wait_for(|| {
        fs::read_to_string(&fixture.diagnostics)
            .unwrap()
            .lines()
            .skip(admission)
            .any(|line| line.contains("SOCKET_ADMITTED") && line.contains("\"broker\":true"))
    });
    let before = fixture.diagnostic_count();
    let mut client = connect(&fixture.socket);
    let mut hello: serde_json::Value = serde_json::from_slice(&hello(&fixture.executable)).unwrap();
    hello["requested_policy"]["ttl_secs"] = 1.into();
    send_rights(
        &client,
        &encode_frame(FrameType::ClientHello, &serde_json::to_vec(&hello).unwrap()).unwrap(),
        2,
    );
    prompt(&mut terminal);
    thread::sleep(Duration::from_secs(2));
    terminal.write_all(b"yes\n").unwrap();
    let expired = decision(&mut client);
    assert_eq!(expired.status, "REJECTED");
    assert!(expired.message.contains("expired"));
    drop(client);
    fixture.wait_for_cleanup(before);
    // Losing the root's TTY invalidates an outstanding prompt.
    let before = fixture.diagnostic_count();
    let mut client = connect(&fixture.socket);
    send_hello(&mut client, &fixture.executable);
    prompt(&mut terminal);
    drop(terminal);
    assert_eq!(decision(&mut client).status, "TIMEOUT_CSR");
    drop(client);
    wait_for(|| approver.0.try_wait().unwrap().is_some());
    fixture.wait_for_cleanup(before);
}

fn slow_signing_cancellation(fixture: &Fixture, identity: &Path) {
    use std::os::unix::net::UnixListener;
    // A root-selected public key delegates signing to an agent. Holding an
    // agent query unanswered makes the real OpenSSH helper block predictably.
    let agent_path = fixture.directory.path().join("slow-agent.sock");
    let agent = UnixListener::bind(&agent_path).unwrap();
    agent.set_nonblocking(true).unwrap();
    let admission = fixture.diagnostic_count();
    let (mut terminal, mut approver) =
        launch_approver_with(fixture, &identity.with_extension("pub"), |command| {
            command.env("SSH_AUTH_SOCK", &agent_path);
        });
    wait_for(|| {
        fs::read_to_string(&fixture.diagnostics)
            .unwrap()
            .lines()
            .skip(admission)
            .any(|line| line.contains("SOCKET_ADMITTED") && line.contains("\"broker\":true"))
    });
    let before = fixture.diagnostic_count();
    let mut client = connect(&fixture.socket);
    send_hello(&mut client, &fixture.executable);
    prompt(&mut terminal);
    terminal.write_all(b"yes\n").unwrap();
    let mut accepted = None;
    wait_for(|| match agent.accept() {
        Ok((socket, _)) => {
            accepted = Some(socket);
            true
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
        error => panic!("slow agent accept: {error:?}"),
    });
    let children = format!(
        "/proc/{}/task/{}/children",
        approver.0.id(),
        approver.0.id()
    );
    let helper: u32 = fs::read_to_string(children)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(Path::new(&format!("/proc/{helper}")).exists());
    // This closes the daemon broker, which the approver must notice while its
    // child is blocked in agent I/O, then kill and reap before exiting itself.
    drop(client);
    wait_for(|| approver.0.try_wait().unwrap().is_some());
    assert!(
        !Path::new(&format!("/proc/{helper}")).exists(),
        "signing helper survived cancellation"
    );
    drop(accepted);
    fixture.wait_for_cleanup(before);
}

fn successful_agent_and_encrypted_identity(fixture: &Fixture, identity: &Path) {
    let askpass = fixture.directory.path().join("askpass");
    let askpass_marker = fixture.directory.path().join("askpass-invoked");
    fs::write(
        &askpass,
        format!(
            "#!/bin/sh\nprintf invoked > '{}'\nprintf 'phase3-test\\n'\n",
            askpass_marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&askpass, fs::Permissions::from_mode(0o700)).unwrap();
    let agent_path = fixture.directory.path().join("agent.sock");
    let mut command = Command::new("/usr/bin/ssh-agent");
    command
        .args(["-D", "-a"])
        .arg(&agent_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut agent = DaemonChild(command.spawn().unwrap());
    wait_for(|| agent_path.exists());
    let add = Command::new("/usr/bin/ssh-add")
        .arg(identity)
        .env("SSH_AUTH_SOCK", &agent_path)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );
    for encrypted in [false, true] {
        if encrypted {
            assert!(
                Command::new("/usr/bin/ssh-keygen")
                    .args(["-q", "-p", "-P", "", "-N", "phase3-test", "-f"])
                    .arg(identity)
                    .stdout(Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let admission = fixture.diagnostic_count();
        let selected = if encrypted {
            identity.to_owned()
        } else {
            identity.with_extension("pub")
        };
        let (mut terminal, mut approver) = launch_approver_with(fixture, &selected, |command| {
            if encrypted {
                command
                    .env_remove("SSH_AUTH_SOCK")
                    .env("SSH_ASKPASS", &askpass)
                    .env("SSH_ASKPASS_REQUIRE", "force")
                    .env("DISPLAY", ":phase3-fixture");
            } else {
                command.env("SSH_AUTH_SOCK", &agent_path);
            }
        });
        wait_for(|| {
            fs::read_to_string(&fixture.diagnostics)
                .unwrap()
                .lines()
                .skip(admission)
                .any(|line| line.contains("SOCKET_ADMITTED") && line.contains("\"broker\":true"))
        });
        let before = fixture.diagnostic_count();
        let mut client = connect(&fixture.socket);
        send_hello(&mut client, &fixture.executable);
        prompt(&mut terminal);
        terminal.write_all(b"yes\n").unwrap();
        if encrypted {
            let text = tty_until_checked(&mut terminal, b": ", || {
                assert!(
                    !askpass_marker.exists(),
                    "OpenSSH invoked inherited askpass instead of the verified TTY"
                );
            });
            assert!(text.contains("Enter passphrase"));
            terminal.write_all(b"phase3-test\n").unwrap();
        }
        assert!(
            decision(&mut client)
                .message
                .contains("disabled by --authorization-only")
        );
        assert!(
            !askpass_marker.exists(),
            "askpass must never receive a signing passphrase request"
        );
        drop(client);
        fixture.wait_for_cleanup(before);
        let before = fixture.diagnostic_count();
        let mut client = connect(&fixture.socket);
        send_hello(&mut client, &fixture.executable);
        prompt(&mut terminal);
        drop(client);
        wait_for(|| approver.0.try_wait().unwrap().is_some());
        fixture.wait_for_cleanup(before);
    }
    agent.0.kill().unwrap();
    agent.0.wait().unwrap();
}
fn tty_until(terminal: &mut File, target: &[u8]) -> String {
    tty_until_checked(terminal, target, || {})
}
fn tty_until_checked(terminal: &mut File, target: &[u8], check: impl Fn()) -> String {
    let mut bytes = Vec::new();
    wait_for(|| {
        check();
        let mut chunk = [0u8; 4096];
        match terminal.read(&mut chunk) {
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            error => panic!(
                "TTY read failed {error:?}: {}",
                String::from_utf8_lossy(&bytes)
            ),
        }
        bytes.windows(target.len()).any(|window| window == target)
    });
    String::from_utf8(bytes).unwrap()
}

fn wrong_operator_identity(fixture: &Fixture) {
    let wrong = fixture.directory.path().join("wrong-key");
    assert!(
        Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&wrong)
            .status()
            .unwrap()
            .success()
    );
    let admission = fixture.diagnostic_count();
    let (_terminal, mut approver) = launch_approver(fixture, &wrong);
    wait_for(|| {
        fs::read_to_string(&fixture.diagnostics)
            .unwrap()
            .lines()
            .skip(admission)
            .any(|line| line.contains("SOCKET_ADMITTED") && line.contains("\"broker\":true"))
    });
    let before = fixture.diagnostic_count();
    let mut client = connect(&fixture.socket);
    send_hello(&mut client, &fixture.executable);
    assert_eq!(decision(&mut client).status, "TIMEOUT_CSR");
    drop(client);
    wait_for(|| approver.0.try_wait().unwrap().is_some());
    assert!(
        fs::read_to_string(fixture.directory.path().join("approver.stderr"))
            .unwrap()
            .contains("identity does not match requested signer")
    );
    fixture.wait_for_cleanup(before);
}

fn tty_attributes(terminal: &File) -> libc::termios {
    let mut attributes = unsafe { zeroed() };
    assert_eq!(
        unsafe { libc::tcgetattr(terminal.as_raw_fd(), &mut attributes) },
        0
    );
    attributes
}
fn assert_tty_attributes_restored(terminal: &File, original: &libc::termios) {
    let restored = tty_attributes(terminal);
    assert_eq!(restored.c_iflag, original.c_iflag);
    assert_eq!(restored.c_oflag, original.c_oflag);
    assert_eq!(restored.c_cflag, original.c_cflag);
    assert_eq!(restored.c_lflag, original.c_lflag);
    assert_eq!(restored.c_cc, original.c_cc);
    assert_eq!(unsafe { libc::cfgetispeed(&restored) }, unsafe {
        libc::cfgetispeed(original)
    });
    assert_eq!(unsafe { libc::cfgetospeed(&restored) }, unsafe {
        libc::cfgetospeed(original)
    });
}
fn encrypted_signing_cancellation_restores_terminal(fixture: &Fixture, identity: &Path) {
    // The preceding encrypted-key test leaves this identity encrypted. Stop
    // OpenSSH while it has changed the real controlling terminal for a secret
    // read, then inspect the same PTY after the approver and helper are gone.
    for local_signal in [false, true] {
        let admission = fixture.diagnostic_count();
        let (mut terminal, mut approver) = launch_approver_with(fixture, identity, |command| {
            command
                .env_remove("SSH_AUTH_SOCK")
                .env("SSH_ASKPASS_REQUIRE", "never");
        });
        let original = tty_attributes(&terminal);
        assert_ne!(original.c_lflag & libc::ECHO, 0);
        wait_for(|| {
            fs::read_to_string(&fixture.diagnostics)
                .unwrap()
                .lines()
                .skip(admission)
                .any(|line| line.contains("SOCKET_ADMITTED") && line.contains("\"broker\":true"))
        });
        let before = fixture.diagnostic_count();
        let mut client = connect(&fixture.socket);
        send_hello(&mut client, &fixture.executable);
        prompt(&mut terminal);
        terminal.write_all(b"yes\n").unwrap();
        let text = tty_until(&mut terminal, b": ");
        assert!(text.contains("Enter passphrase"));
        wait_for(|| tty_attributes(&terminal).c_lflag & libc::ECHO == 0);
        let children = format!(
            "/proc/{}/task/{}/children",
            approver.0.id(),
            approver.0.id()
        );
        let helper: u32 = fs::read_to_string(children)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        if local_signal {
            assert_eq!(
                unsafe { libc::kill(approver.0.id() as _, libc::SIGTERM) },
                0
            );
            assert_eq!(decision(&mut client).status, "TIMEOUT_CSR");
        }
        drop(client);
        wait_for(|| approver.0.try_wait().unwrap().is_some());
        assert!(
            !Path::new(&format!("/proc/{helper}")).exists(),
            "signing helper survived"
        );
        assert_tty_attributes_restored(&terminal, &original);
        fixture.wait_for_cleanup(before);
    }
}
