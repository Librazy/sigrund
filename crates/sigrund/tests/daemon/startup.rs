use super::*;

pub(super) fn verify_provisioning_permissions() {
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

fn append_recovery_tail(fixture: &Fixture, recovery: &str) -> serde_json::Value {
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
        let mut record = serde_json::json!({"schema_version":3,"event_type":"TEST_CRASH_WINDOW",
            "host_id":genesis["host_id"],"seq":state["seq"],
            "prev_record_sha256":state["last_record_sha256"]});
        record["entry_hmac"] = entry_hmac(&key, &serde_json::to_vec(&record).unwrap()).into();
        log.write_all(&serde_json::to_vec(&record).unwrap())
            .unwrap();
        log.write_all(b"\n").unwrap();
    }
    log.sync_all().unwrap();
    drop(log);
    genesis
}

// Pause startup after audit-file verification, then replace both directory
// pathnames. Recovery must use the already checked descriptors, including
// publication of the advanced state and its authenticated recovery record.
pub(super) fn verify_audit_directory_replacement() {
    for recovery in ["partial", "forward"] {
        let fixture = Fixture::new();
        let state_path = fixture.state.join("audit_ratchet.state");
        let genesis = append_recovery_tail(&fixture, recovery);
        let interposer = fixture.directory.path().join("startup_gate.so");
        assert!(
            Command::new("cc")
                .args(["-shared", "-fPIC", "-Wall", "-Werror", "-o"])
                .arg(&interposer)
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/transport/metadata.c"
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
                String::from_utf8_lossy(&fs::read(&fixture.diagnostics).unwrap())
            );
            daemon_ready(&fixture.diagnostics)
        });
        fixture.peer(65534, "client");
        daemon.stop();
        assert!(original_state.join("host-epoch.json").is_file());
        assert!(!fixture.state.join("host-epoch.json").exists());
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

#[test]
#[ignore = "requires initial-userns root; included in the privileged Phase 1 gate"]
fn stale_audit_temporary_gate() {
    let _gate = namespace_gate();
    let output = Command::new("unshare")
        .args(["--mount"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "startup::stale_audit_temporary_namespace_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("SIGRUND_STARTUP_NAMESPACE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "invoked by the startup namespace gate"]
fn stale_audit_temporary_namespace_fixture() {
    assert_eq!(std::env::var("SIGRUND_STARTUP_NAMESPACE").unwrap(), "1");
    for recovery in ["partial", "forward"] {
        for (uid, gid, mode) in [(65534, 0, 0o600), (0, 65534, 0o600), (0, 0, 0o644)] {
            let fixture = Fixture::new();
            append_recovery_tail(&fixture, recovery);
            let state_path = fixture.state.join("audit_ratchet.state");
            let temporary = fixture.state.join("audit_ratchet.state.tmp");
            fs::write(&temporary, b"untrusted stale temporary sentinel").unwrap();
            fs::set_permissions(&temporary, fs::Permissions::from_mode(mode)).unwrap();
            std::os::unix::fs::chown(&temporary, Some(uid), Some(gid)).unwrap();
            let retained = File::open(&temporary).unwrap();
            let metadata = retained.metadata().unwrap();
            let state_before = fs::read(&state_path).unwrap();
            let log_before = fs::read(&fixture.log).unwrap();
            let config =
                sigrund_core::config::DaemonConfig::from_toml(&fs::read(&fixture.config).unwrap())
                    .unwrap();
            let result =
                sigrund::startup::StartupResources::prepare(&config, &fixture.state, &fixture.log);
            let error = match result {
                Ok(_) => {
                    panic!("{recovery}: accepted stale audit temporary file {uid}:{gid} {mode:o}")
                }
                Err(error) => error,
            };
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(fs::read(&state_path).unwrap(), state_before);
            assert_eq!(fs::read(&fixture.log).unwrap(), log_before);
            assert_eq!(
                fs::read(&temporary).unwrap(),
                b"untrusted stale temporary sentinel"
            );
            let mut bytes = Vec::new();
            (&retained).read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"untrusted stale temporary sentinel");
            let after = fs::metadata(&temporary).unwrap();
            assert_eq!(
                (after.ino(), after.uid(), after.gid(), after.mode()),
                (
                    metadata.ino(),
                    metadata.uid(),
                    metadata.gid(),
                    metadata.mode()
                )
            );
        }
        // Even a trusted stale inode must be unlinked before recovery writes
        // secret state: an already open descriptor must retain only its sentinel.
        let fixture = Fixture::new();
        append_recovery_tail(&fixture, recovery);
        let temporary = fixture.state.join("audit_ratchet.state.tmp");
        fs::write(&temporary, b"trusted stale temporary sentinel").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        let mut retained = File::open(&temporary).unwrap();
        fixture.launch().stop();
        let mut bytes = Vec::new();
        retained.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"trusted stale temporary sentinel");
        assert!(!temporary.exists());
        let state = fs::metadata(fixture.state.join("audit_ratchet.state")).unwrap();
        assert_eq!(
            (state.uid(), state.gid(), state.mode() & 0o777),
            (0, 0, 0o600)
        );
        assert_ne!(state.ino(), retained.metadata().unwrap().ino());
    }
}

#[test]
#[ignore = "requires initial-userns root; included in the privileged Phase 1 gate"]
fn v3_provisioning_set_gate() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    for (role, sidecar) in [
        ("state", "state.sqlite-wal"),
        ("state", "state.sqlite-shm"),
        ("state", "audit_ratchet.state.tmp"),
        ("state", "host-epoch.json"),
        ("state", "unrecognized-prior-set"),
        ("log", "audit.jsonl.tmp"),
        ("log", "audit.jsonl.1"),
        ("log", "unrecognized-prior-log"),
    ] {
        let base = tempfile::tempdir().unwrap();
        let state = base.path().join("state");
        let log_dir = base.path().join("log");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&log_dir).unwrap();
        let sentinel = if role == "state" { &state } else { &log_dir }.join(sidecar);
        fs::write(&sentinel, b"prior provisioning sentinel").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_sigrundctl"))
            .arg("init-host")
            .arg("--state-dir")
            .arg(&state)
            .arg("--log-path")
            .arg(log_dir.join("audit.jsonl"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(73),
            "{role}/{sidecar}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"prior provisioning sentinel");
        assert!(!state.join("host_identity.key").exists());
        assert!(!state.join("state.sqlite").exists());
        assert!(!log_dir.join("audit.jsonl").exists());
    }
    // Every component is checked before the public, context or broker listener
    // is published. Failed checks preserve the exact supplied state/log bytes.
    for component in ["database", "ratchet", "audit", "configuration", "all"] {
        for version in [0, 2, 4] {
            let f = Fixture::new();
            if component == "database" || component == "all" {
                rusqlite::Connection::open(f.state.join("state.sqlite"))
                    .unwrap()
                    .execute_batch(&format!("PRAGMA user_version={version};"))
                    .unwrap();
            }
            for (role, path) in [
                ("ratchet", f.state.join("audit_ratchet.state")),
                ("audit", f.log.clone()),
            ] {
                if component == role || component == "all" {
                    let raw = fs::read(&path).unwrap();
                    let mut record: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                    if version == 0 {
                        record.as_object_mut().unwrap().remove("schema_version");
                    } else {
                        record["schema_version"] = version.into();
                    }
                    let mut bytes = serde_json::to_vec(&record).unwrap();
                    if role == "audit" {
                        bytes.push(b'\n');
                    }
                    fs::write(path, bytes).unwrap();
                }
            }
            if component == "configuration" || component == "all" {
                let config = fs::read_to_string(&f.config).unwrap();
                fs::write(
                    &f.config,
                    if version == 0 {
                        config.replace("version = \"3.0\"\n", "")
                    } else {
                        config.replace("version = \"3.0\"", &format!("version = \"{version}.0\""))
                    },
                )
                .unwrap();
            }
            let log_before = fs::read(&f.log).unwrap();
            let ratchet_before = fs::read(f.state.join("audit_ratchet.state")).unwrap();
            let db_before = fs::read(f.state.join("state.sqlite")).unwrap();
            let result = f.command().output().unwrap();
            assert!(
                !result.status.success(),
                "accepted {component} version {version}"
            );
            assert!(!f.socket.exists() && !f.broker.exists());
            assert!(!PathBuf::from(format!("{}.context", f.socket.display())).exists());
            assert!(!f.state.join("host-epoch.json").exists());
            assert_eq!(fs::read(&f.log).unwrap(), log_before);
            assert_eq!(
                fs::read(f.state.join("audit_ratchet.state")).unwrap(),
                ratchet_before
            );
            assert_eq!(fs::read(f.state.join("state.sqlite")).unwrap(), db_before);
        }
    }
    for component in [
        "host_identity.key",
        "audit_ratchet.state",
        "state.sqlite",
        "log",
    ] {
        let f = Fixture::new();
        let missing = if component == "log" {
            f.log.clone()
        } else {
            f.state.join(component)
        };
        fs::remove_file(&missing).unwrap();
        let result = f.command().output().unwrap();
        assert!(
            !result.status.success(),
            "reinitialized missing {component}"
        );
        assert!(!missing.exists());
        assert!(!f.socket.exists() && !f.broker.exists());
        assert!(!f.state.join("host-epoch.json").exists());
    }
}
