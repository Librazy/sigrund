//! Real signed redemption and durable state through production binaries.
use super::*;
use ed25519_dalek::Signer;
use sha2::{Digest, Sha512};
use sigrund_core::{
    crypto::{WARRANT_PAYLOAD_TYPE, pae},
    protocol::{ClientHello, DsseEnvelope, DsseSignature},
    warrant::{CanonicalWarrant, Csr, CsrIdentity, SnapshotDigests, Warrant},
};

#[test]
fn exit_gate() {
    let _gate = NAMESPACE_GATE.lock().unwrap();
    let output = Command::new("unshare")
        .args(["--user", "--map-auto", "--map-root-user"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "phase4::namespace_fixture",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SIGRUND_PHASE4_NAMESPACE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Phase 4 namespace gate:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn fixture() -> Fixture {
    let fixture = Fixture::new();
    fs::write(
        &fixture.signers,
        fs::read_to_string(&fixture.signers).unwrap().replace(
            "allowed_requester_uids = [1001]",
            "allowed_requester_uids = [0, 65534]",
        ),
    )
    .unwrap();
    fixture
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn warrant(f: &Fixture, uid: u32) -> Warrant {
    let hello = ClientHello::parse_request(&hello(&f.executable)).unwrap();
    let genesis: serde_json::Value =
        serde_json::from_str(fs::read_to_string(&f.log).unwrap().lines().next().unwrap()).unwrap();
    Csr::from_unsigned(
        &hello,
        CsrIdentity {
            grant_id: new_uuidv7().to_string(),
            host_id: genesis["host_id"].as_str().unwrap().into(),
            requester_uid: uid,
            requester_gid: uid,
            now: now(),
        },
        SnapshotDigests {
            executable_sha256: sha256_hex(&fs::read(&f.executable).unwrap()),
            stdin_sha256: None,
        },
        3600,
    )
    .unwrap()
    .warrant()
    .clone()
}
fn ssh_string(input: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(&(input.len() as u32).to_be_bytes());
    output.extend_from_slice(input);
}
fn envelope(w: Warrant, key: u8) -> DsseEnvelope {
    envelope_for(w, key, "mandator-alice-yubikey")
}
fn envelope_for(w: Warrant, key: u8, signer_id: &str) -> DsseEnvelope {
    let w = CanonicalWarrant::new(w).unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(&[key; 32]);
    let mut public = Vec::new();
    ssh_string(b"ssh-ed25519", &mut public);
    ssh_string(&signing.verifying_key().to_bytes(), &mut public);
    let mut message = b"SSHSIG".to_vec();
    ssh_string(b"sigrun.warrant.v1", &mut message);
    ssh_string(b"", &mut message);
    ssh_string(b"sha512", &mut message);
    ssh_string(
        &Sha512::digest(pae(WARRANT_PAYLOAD_TYPE, w.as_bytes())),
        &mut message,
    );
    let mut signature = Vec::new();
    ssh_string(b"ssh-ed25519", &mut signature);
    ssh_string(&signing.sign(&message).to_bytes(), &mut signature);
    let mut packet = b"SSHSIG".to_vec();
    packet.extend_from_slice(&1u32.to_be_bytes());
    ssh_string(&public, &mut packet);
    ssh_string(b"sigrun.warrant.v1", &mut packet);
    ssh_string(b"", &mut packet);
    ssh_string(b"sha512", &mut packet);
    ssh_string(&signature, &mut packet);
    DsseEnvelope::from_warrant(
        &w,
        vec![DsseSignature {
            keyid: signer_id.into(),
            sig: STANDARD.encode(packet),
        }],
    )
    .unwrap()
}
fn send_signed(socket: &UnixStream, envelope: &DsseEnvelope) {
    let hello = serde_json::json!({"mode":"signed","tty_mode":"stdio","caller_env":{},"dsse_envelope":envelope});
    send_rights(
        socket,
        &encode_frame(FrameType::ClientHello, &serde_json::to_vec(&hello).unwrap()).unwrap(),
        2,
    );
}
fn redeem(f: &Fixture, envelope: &DsseEnvelope) -> Decision {
    let before = f.diagnostic_count();
    let mut client = connect(&f.socket);
    send_signed(&client, envelope);
    let result = decision(&mut client);
    assert_ne!(result.status, "READY_TO_EXEC");
    expect_closed(&mut client);
    drop(client);
    f.wait_for_cleanup(before);
    result
}
fn records(f: &Fixture) -> Vec<serde_json::Value> {
    fs::read_to_string(&f.log)
        .unwrap()
        .lines()
        .map(|r| serde_json::from_str(r).unwrap())
        .collect()
}
fn count(f: &Fixture) -> u64 {
    rusqlite::Connection::open(f.state.join("state.sqlite"))
        .unwrap()
        .query_row("SELECT count(*) FROM consumed_grants", [], |row| row.get(0))
        .unwrap()
}

#[test]
#[ignore = "invoked by the namespace exit gate"]
fn namespace_fixture() {
    assert_eq!(std::env::var("SIGRUND_PHASE4_NAMESPACE").unwrap(), "1");
    let f = fixture();
    let daemon = f.launch();
    assert_eq!(unsafe { libc::kill(daemon.0.id() as _, libc::SIGHUP) }, 0);
    wait_for(|| {
        records(&f)
            .iter()
            .any(|r| r["event_type"] == "RELOAD_UNAVAILABLE")
    });
    // Two connections present the same actual UID/GID and exact signed bytes.
    let valid = envelope(warrant(&f, 0), 7);
    let mut a = connect(&f.socket);
    let mut b = connect(&f.socket);
    send_signed(&a, &valid);
    send_signed(&b, &valid);
    let outcomes = [decision(&mut a), decision(&mut b)];
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| r.status == "SPAWN_FAILED")
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| r.status == "REPLAY_DETECTED")
            .count(),
        1
    );
    drop((a, b));
    assert_eq!(count(&f), 1);
    assert!(redeem(&f, &valid).message.contains("already been consumed"));
    for (case, status) in [
        ("host", "POLICY_VIOLATION"),
        ("peer", "POLICY_VIOLATION"),
        ("gid", "POLICY_VIOLATION"),
        ("signature", "POLICY_VIOLATION"),
        ("capability", "POLICY_VIOLATION"),
        ("groups", "POLICY_VIOLATION"),
        ("same_uid", "POLICY_VIOLATION"),
        ("digest", "EXECUTABLE_MUTATED_OR_TOO_LARGE"),
        ("expired", "EXPIRED_OR_NOT_YET_VALID"),
        ("future", "EXPIRED_OR_NOT_YET_VALID"),
    ] {
        let mut w = warrant(&f, 0);
        match case {
            "host" => w.host_id = format!("sigrun-host:sha256:{}", "0".repeat(64)),
            "peer" => w.requester_uid = 65534,
            "gid" => w.requester_gid = 65534,
            "signature" => (),
            "capability" => w.execution_context.capabilities = vec!["CAP_SYS_ADMIN".into()],
            "groups" => w.execution_context.supplementary_gids = vec![77],
            "same_uid" => w.execution_context.target_uid = 0,
            "digest" => w.command.executable_sha256 = "0".repeat(64),
            "expired" => {
                w.policy.not_before = now() - 100;
                w.policy.not_after = Some(now() - 1);
            }
            "future" => {
                w.policy.not_before = now() + 100;
                w.policy.not_after = Some(now() + 120);
            }
            _ => unreachable!(),
        }
        let envelope = envelope(w, if case == "signature" { 8 } else { 7 });
        assert_eq!(redeem(&f, &envelope).status, status, "{case}");
        assert_eq!(count(&f), 1, "{case} consumed a denied grant");
    }
    // Each supported revocation key is checked inside the serialized transaction.
    let store = sigrund_core::state::StateStore::open(f.state.join("state.sqlite")).unwrap();
    for kind in ["grant_id", "payload_sha256", "signer_id"] {
        let w = warrant(&f, 0);
        let target = match kind {
            "grant_id" => w.grant_id.clone(),
            "payload_sha256" => sha256_hex(CanonicalWarrant::new(w.clone()).unwrap().as_bytes()),
            _ => "mandator-alice-yubikey".into(),
        };
        store
            .revoke(kind, &target, now(), "namespace fixture")
            .unwrap();
        assert_eq!(redeem(&f, &envelope(w, 7)).status, "REVOKED", "{kind}");
        assert_eq!(count(&f), 1);
    }
    drop(store);
    daemon.stop();
    let data = records(&f);
    assert_eq!(
        data.iter()
            .filter(|r| r["event_type"] == "AUTH_COMMIT")
            .count(),
        1
    );
    let commits: Vec<_> = data
        .iter()
        .enumerate()
        .filter(|(_, r)| r["event_type"] == "AUTH_COMMIT")
        .collect();
    for (i, record) in commits {
        assert_eq!(data[i + 1]["event_type"], "AUTH_ABORTED_POST_COMMIT");
        assert_eq!(data[i + 1]["exec_id"], record["exec_id"]);
    }
    assert!(
        data.iter()
            .all(|r| !r["event_type"].as_str().unwrap().starts_with("EXEC_"))
    );
    let audit = sigrund_core::audit::AuditLog::open_for_host(
        &f.log,
        f.state.join("audit_ratchet.state"),
        data[0]["host_id"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(audit.state().seq as usize, data.len());
    drop(audit);
    OpenOptions::new()
        .append(true)
        .open(&f.log)
        .unwrap()
        .write_all(b"interrupted audit suffix")
        .unwrap();
    let daemon = f.launch();
    assert!(
        records(&f)
            .iter()
            .any(|r| r["event_type"] == "RATCHET_PARTIAL_WRITE_TRUNCATED")
    );
    assert_eq!(redeem(&f, &valid).status, "REVOKED");
    daemon.stop();
    signed_cli_and_restart();
    multisignature_revocation();
    cancellation_and_durable_failures();
    blocked_io_remains_bounded_and_responsive();
}

fn multisignature_revocation() {
    let f = fixture();
    let first_id = "mandator-alice-yubikey";
    let second_id = "mandator-bob";
    let first = fs::read_to_string(&f.signers).unwrap();
    let parsed = sigrund_core::config::SignerPolicyFile::from_toml(first.as_bytes()).unwrap();
    let mut public = Vec::new();
    ssh_string(b"ssh-ed25519", &mut public);
    ssh_string(
        &ed25519_dalek::SigningKey::from_bytes(&[8; 32])
            .verifying_key()
            .to_bytes(),
        &mut public,
    );
    let second = first.replace(first_id, second_id).replace(
        &parsed.signers[0].public_key,
        &format!("ssh-ed25519 {}", STANDARD.encode(public)),
    );
    fs::write(&f.signers, format!("{first}\n{second}")).unwrap();
    let both = |w: Warrant| {
        let mut signed = envelope(w.clone(), 7);
        signed
            .signatures
            .extend(envelope_for(w, 8, second_id).signatures);
        signed
    };
    let (mut gate, daemon) = Gate::launch(&f, "predicate-before");
    let store = sigrund_core::state::StateStore::open(f.state.join("state.sqlite")).unwrap();
    let signed = both(warrant(&f, 0));
    let before = f.diagnostic_count();
    gate.arm();
    let mut client = connect(&f.socket);
    send_signed(&client, &signed);
    gate.arrive(&daemon);
    // Revoke after preparation, while final authorization is rehashing the
    // retained snapshot. Selecting an unrevoked key before preparation is
    // insufficient: the serialized transaction must choose the winner.
    store
        .revoke("signer_id", first_id, now(), "first signer revoked")
        .unwrap();
    gate.release();
    assert_eq!(decision(&mut client).status, "SPAWN_FAILED");
    drop(client);
    f.wait_for_cleanup(before);
    assert_eq!(redeem(&f, &signed).status, "REPLAY_DETECTED");
    let mut signed = both(warrant(&f, 0));
    signed.signatures.reverse();
    assert_eq!(redeem(&f, &signed).status, "SPAWN_FAILED");
    assert_eq!(redeem(&f, &signed).status, "REPLAY_DETECTED");
    assert_eq!(count(&f), 2);
    let db = rusqlite::Connection::open(f.state.join("state.sqlite")).unwrap();
    let other_signers: u64 = db
        .query_row(
            "SELECT count(*) FROM consumed_grants WHERE signer_id != ?1",
            [second_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(other_signers, 0);
    let data = records(&f);
    let committed: Vec<_> = data
        .iter()
        .filter(|r| {
            r["event_type"] == "AUTH_COMMIT" || r["event_type"] == "AUTH_ABORTED_POST_COMMIT"
        })
        .collect();
    assert_eq!(committed.len(), 4);
    for record in committed {
        assert_eq!(record["signer_id"], second_id);
    }
    // An unrevoked key must still have a valid signature over this payload.
    let mut invalid = envelope(warrant(&f, 0), 7);
    invalid
        .signatures
        .extend(envelope_for(warrant(&f, 0), 8, second_id).signatures);
    assert_eq!(redeem(&f, &invalid).status, "REVOKED");
    assert_eq!(redeem(&f, &envelope(warrant(&f, 0), 7)).status, "REVOKED");
    // Payload/grant revocations deny the entire warrant, regardless of keys.
    for kind in ["grant_id", "payload_sha256"] {
        let w = warrant(&f, 0);
        let target = if kind == "grant_id" {
            w.grant_id.clone()
        } else {
            sha256_hex(CanonicalWarrant::new(w.clone()).unwrap().as_bytes())
        };
        store
            .revoke(kind, &target, now(), "entire warrant revoked")
            .unwrap();
        assert_eq!(redeem(&f, &both(w)).status, "REVOKED");
    }
    assert_eq!(count(&f), 2);
    daemon.stop();
    // The fallback signature cannot borrow the revoked key's UID ceiling.
    fs::write(
        &f.signers,
        format!(
            "{first}\n{}",
            second.replace("allowed_target_uids = [0, 33]", "allowed_target_uids = [0]")
        ),
    )
    .unwrap();
    let daemon = f.launch();
    assert_eq!(redeem(&f, &both(warrant(&f, 0))).status, "REVOKED");
    assert_eq!(count(&f), 2);
    daemon.stop();
    // Neither signer independently authorizes this UID/GID pair. Combining
    // one's UID ceiling with the other's GID ceiling must never authorize it.
    fs::write(
        &f.signers,
        format!(
            "{}\n{}",
            first.replace("allowed_target_uids = [0, 33]", "allowed_target_uids = [0]"),
            second.replace(
                "allowed_target_gids = [0, 33]",
                "allowed_target_gids = [33]"
            )
        ),
    )
    .unwrap();
    let daemon = f.launch();
    assert_eq!(redeem(&f, &both(warrant(&f, 0))).status, "POLICY_VIOLATION");
    assert_eq!(count(&f), 2);
    daemon.stop();
    fs::write(&f.signers, format!("{first}\n{second}")).unwrap();
    let daemon = f.launch();
    store
        .revoke("signer_id", second_id, now(), "all signers revoked")
        .unwrap();
    assert_eq!(redeem(&f, &both(warrant(&f, 0))).status, "REVOKED");
    assert_eq!(count(&f), 2);
    daemon.stop();
}

fn signed_cli_and_restart() {
    let f = fixture();
    let daemon = f.launch();
    let mut last_signed = None;
    for stdin in [None, Some(b"signed reviewed input\0\xff".as_slice())] {
        let mut w = warrant(&f, 65534);
        w.execution_context.target_uid = 0;
        if let Some(bytes) = stdin {
            w.command.stdin_policy = "sha256".into();
            w.command.stdin_sha256 = Some(sha256_hex(bytes));
        }
        let signed = envelope(w, 7);
        let input = f.directory.path().join("warrant.json");
        fs::write(&input, signed.to_jcs().unwrap()).unwrap();
        for expected in ["SPAWN_FAILED", "REPLAY_DETECTED"] {
            let status_path = f.directory.path().join(format!("{expected}.status"));
            let status = File::create(&status_path).unwrap();
            let fd = status.as_raw_fd();
            let mut command = Command::new(f.directory.path().join("sigrun"));
            command
                .arg("--socket")
                .arg(&f.socket)
                .arg("--warrant")
                .arg(&input)
                .args([
                    "--auth-fail-exit-code",
                    "42",
                    "--status-fd",
                    &fd.to_string(),
                ]);
            unsafe {
                command.pre_exec(move || {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0
                        || libc::setgroups(0, std::ptr::null()) < 0
                        || libc::setgid(65534) < 0
                        || libc::setuid(65534) < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().unwrap();
            if let Some(bytes) = stdin {
                child.stdin.take().unwrap().write_all(bytes).unwrap();
            }
            drop(child.stdin.take());
            let output = child.wait_with_output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(42),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stdout.is_empty());
            let report: serde_json::Value =
                serde_json::from_str(fs::read_to_string(status_path).unwrap().trim()).unwrap();
            assert_eq!(report["status"], expected);
        }
        last_signed = Some(signed);
    }
    assert_eq!(count(&f), 2);
    daemon.stop();
    let daemon = f.launch();
    // Wrong root peer is a policy denial, not a replay observation.
    assert_eq!(redeem(&f, &last_signed.unwrap()).status, "POLICY_VIOLATION");
    assert_eq!(count(&f), 2);
    daemon.stop();
}

struct Gate {
    entered: UnixStream,
    release: UnixStream,
    arm: PathBuf,
}
impl Gate {
    fn launch(f: &Fixture, point: &str) -> (Self, DaemonChild) {
        let library = f.directory.path().join("durable_gate.so");
        let output = Command::new("cc")
            .args(["-shared", "-fPIC", "-Wall", "-Werror", "-o"])
            .arg(&library)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/durable_gate.c"
            ))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let (entered, worker_entered) = UnixStream::pair().unwrap();
        entered
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let (release, worker_release) = UnixStream::pair().unwrap();
        let arm = f.directory.path().join("durable.armed");
        let entered_fd = worker_entered.as_raw_fd();
        let release_fd = worker_release.as_raw_fd();
        let mut command = f.command();
        command
            .env("LD_PRELOAD", &library)
            .env("SIGRUND_DURABLE_POINT", point)
            .env("SIGRUND_DURABLE_ARM", &arm)
            .env("SIGRUND_DURABLE_ENTERED", entered_fd.to_string())
            .env("SIGRUND_DURABLE_RELEASE", release_fd.to_string());
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
        let daemon = f.launch_command(command);
        drop((worker_entered, worker_release));
        (
            Self {
                entered,
                release,
                arm,
            },
            daemon,
        )
    }
    fn arm(&self) {
        fs::write(&self.arm, b"gate").unwrap();
    }
    fn arrive(&mut self, daemon: &DaemonChild) {
        let mut tid = [0; 8];
        self.entered.read_exact(&mut tid).unwrap();
        assert_ne!(
            u64::from_ne_bytes(tid),
            daemon.0.id() as u64,
            "durable I/O ran on the coordinator"
        );
    }
    fn release(&mut self) {
        self.release.write_all(b"x").unwrap();
    }
}

fn cancellation_and_durable_failures() {
    for point in [
        "predicate-before",
        "peek-before",
        "peek-after",
        "wal-before",
        "wal-after",
        "audit-before",
    ] {
        let f = fixture();
        let (mut gate, daemon) = Gate::launch(&f, point);
        let signed = envelope(warrant(&f, 0), 7);
        let before = f.diagnostic_count();
        gate.arm();
        let mut client = connect(&f.socket);
        send_signed(&client, &signed);
        gate.arrive(&daemon);
        // No terminal reply is permitted while the commit result is reserved
        // or the required audit reconciliation is still in flight.
        client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        assert!(
            matches!(client.read(&mut [0]),Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::TimedOut)),
            "{point}"
        );
        drop(client);
        gate.release();
        f.wait_for_cleanup(before);
        let expected = if matches!(point, "predicate-before" | "peek-before") {
            0
        } else {
            1
        };
        assert_eq!(count(&f), expected, "{point}");
        let data = records(&f);
        assert_eq!(
            data.iter()
                .filter(|r| r["event_type"] == "AUTH_COMMIT")
                .count(),
            expected as usize,
            "{point}"
        );
        assert_eq!(
            data.iter()
                .filter(|r| r["event_type"] == "AUTH_ABORTED_POST_COMMIT")
                .count(),
            expected as usize,
            "{point}"
        );
        let replay = redeem(&f, &signed);
        assert_eq!(
            replay.status,
            if expected == 0 {
                "SPAWN_FAILED"
            } else {
                "REPLAY_DETECTED"
            },
            "{point}"
        );
        daemon.stop();
    }
    // SQLite fsync errors are fatal durable-store uncertainty, never ordinary
    // authorization denials. Do not silently retry within this daemon run.
    let f = fixture();
    let (mut gate, mut daemon) = Gate::launch(&f, "wal-fail");
    let signed = envelope(warrant(&f, 0), 7);
    gate.arm();
    let mut client = connect(&f.socket);
    send_signed(&client, &signed);
    gate.arrive(&daemon);
    gate.release();
    wait_for(|| daemon.0.try_wait().unwrap().is_some());
    assert_eq!(daemon.0.wait().unwrap().code(), Some(78));
    expect_closed(&mut client);
    drop(client);
    assert!(!records(&f).iter().any(|r| r["event_type"] == "AUTH_COMMIT"));
    // An fsync error can leave uncertain consumption. Recovery determines
    // what survived; a later explicit redemption must agree with that state.
    let daemon = f.launch();
    let consumed = count(&f);
    assert!(consumed <= 1);
    assert_eq!(
        redeem(&f, &signed).status,
        if consumed == 1 {
            "REPLAY_DETECTED"
        } else {
            "SPAWN_FAILED"
        }
    );
    assert_eq!(count(&f), 1);
    daemon.stop();
    // A failure after the durable record write poisons the writer and closes
    // the daemon. Startup reconciles that exact one-record-forward state.
    let f = fixture();
    let (mut gate, mut daemon) = Gate::launch(&f, "state-fail");
    let signed = envelope(warrant(&f, 0), 7);
    gate.arm();
    let mut client = connect(&f.socket);
    send_signed(&client, &signed);
    gate.arrive(&daemon);
    gate.release();
    wait_for(|| daemon.0.try_wait().unwrap().is_some());
    assert_eq!(daemon.0.wait().unwrap().code(), Some(78));
    expect_closed(&mut client);
    drop(client);
    assert_eq!(count(&f), 1);
    assert_eq!(
        records(&f)
            .iter()
            .filter(|r| r["event_type"] == "AUTH_COMMIT")
            .count(),
        1
    );
    let daemon = f.launch();
    assert_eq!(redeem(&f, &signed).status, "REPLAY_DETECTED");
    assert!(
        records(&f)
            .iter()
            .any(|r| r["event_type"] == "RATCHET_FORWARD_RECOVERY")
    );
    daemon.stop();
}

fn blocked_io_remains_bounded_and_responsive() {
    for point in ["wal-after", "audit-before"] {
        let f = fixture();
        fs::write(
            &f.config,
            fs::read_to_string(&f.config)
                .unwrap()
                .replace("max_io_workers_global = 16", "max_io_workers_global = 2")
                .replace(
                    "max_active_sockets_per_uid = 2",
                    "max_active_sockets_per_uid = 3",
                ),
        )
        .unwrap();
        let (mut gate, mut daemon) = Gate::launch(&f, point);
        let pid = daemon.0.id();
        let threads = || fs::read_dir(format!("/proc/{pid}/task")).unwrap().count();
        assert_eq!(threads(), 5);
        let signed = envelope(warrant(&f, 0), 7);
        gate.arm();
        let client = connect(&f.socket);
        send_signed(&client, &signed);
        gate.arrive(&daemon);
        let before = f.diagnostic_count();
        let mut partial = connect(&f.socket);
        send_rights(&partial, &[FrameType::ClientHello as u8], 2);
        wait_for(|| {
            fs::read_to_string(&f.diagnostics)
                .unwrap()
                .lines()
                .skip(before)
                .any(|line| line.contains("IO_WORKER_RESERVED"))
        });
        // The blocked authorization owns one worker; partial reception owns
        // the other. A third request must not create a replacement worker.
        let mut excess = connect(&f.socket);
        send_hello(&mut excess, &f.executable);
        f.wait_for_cleanup(before); // partial-frame deadline runs while blocked
        assert_eq!(threads(), 5);
        drop(client);
        let retained = fs::read_dir(format!("/proc/{pid}/fd"))
            .unwrap()
            .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
            .filter(|path| path.to_string_lossy().contains("memfd:sigrun-executable"))
            .count();
        assert_eq!(
            retained, 1,
            "{point}: snapshots released before durable reconciliation"
        );
        // Both decisions must arrive while the durable operation is STILL
        // gated. This is the wire-level deadline proof missing from Phase 4.
        assert_eq!(decision(&mut partial).status, "REQUEST_TIMEOUT", "{point}");
        assert_eq!(
            decision(&mut excess).status,
            "RESOURCE_EXHAUSTED",
            "{point}"
        );
        expect_closed(&mut partial);
        expect_closed(&mut excess);
        gate.release();
        drop((partial, excess));
        assert_eq!(count(&f), 1);
        assert_eq!(redeem(&f, &signed).status, "REPLAY_DETECTED");
        // Shutdown must close controls without dropping durable ownership.
        let fresh = envelope(warrant(&f, 0), 7);
        gate.arm();
        let mut stalled = connect(&f.socket);
        send_signed(&stalled, &fresh);
        gate.arrive(&daemon);
        let start = Instant::now();
        daemon.begin_stop();
        expect_closed(&mut stalled);
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(daemon.0.try_wait().unwrap().is_none());
        let replacement = f.command().output().unwrap();
        assert!(String::from_utf8_lossy(&replacement.stderr).contains("already in use"));
        gate.release();
        daemon.finish_stop();
        drop(stalled);
        let daemon = f.launch();
        assert_eq!(redeem(&f, &fresh).status, "REPLAY_DETECTED");
        daemon.stop();
    }
}
