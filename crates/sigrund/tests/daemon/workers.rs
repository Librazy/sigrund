use super::*;

pub(super) fn verify_blocked_metadata() {
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
            "/tests/fixtures/transport/metadata.c"
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
        baseline_threads, 7,
        "expected coordinator, diagnostics, two I/O workers, two disposal workers, and authorization executor"
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
    holder_command.env("SIGRUND_DAEMON_MARKER", &marker_path);
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
    // Shutdown closes controls immediately but retains the instance and quota
    // until the off-loop fstat owner returns.
    let mut stalled = connect(&fixture.socket);
    send_fds(
        &stalled,
        &encoded[..1],
        &[marker.as_raw_fd(), null.as_raw_fd()],
    );
    stalled.write_all(&encoded[1..]).unwrap();
    entered.read_exact(&mut tid).unwrap();
    assert!(daemon.0.try_wait().unwrap().is_none());
    daemon.begin_stop();
    expect_closed(&mut stalled);
    assert!(daemon.0.try_wait().unwrap().is_none());
    let replacement = fixture.command().output().unwrap();
    assert!(String::from_utf8_lossy(&replacement.stderr).contains("already in use"));
    release.write_all(b"x").unwrap();
    daemon.finish_stop();
    assert!(!fixture.socket.exists() && !fixture.broker.exists());
}

pub(super) fn verify_blocked_cleanup() {
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
            "/tests/fixtures/transport/metadata.c"
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
    let mut daemon = fixture.launch_command(command);
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
    // A blocked close does not delay control shutdown or release the instance lock.
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
    daemon.begin_stop();
    expect_closed(&mut stalled);
    assert!(daemon.0.try_wait().unwrap().is_none());
    let replacement = fixture.command().output().unwrap();
    assert!(String::from_utf8_lossy(&replacement.stderr).contains("already in use"));
    release.write_all(b"x").unwrap();
    daemon.finish_stop();
    assert!(!fixture.socket.exists() && !fixture.broker.exists());
}

pub(super) fn verify_blocked_socket_disposal() {
    let fixture = Fixture::new();
    fs::write(
        &fixture.config,
        fs::read_to_string(&fixture.config)
            .unwrap()
            .replace(
                "max_active_sockets_per_uid = 2",
                "max_active_sockets_per_uid = 1",
            )
            .replace("request_deadline_ms = 1500", "request_deadline_ms = 5000"),
    )
    .unwrap();
    let interposer = fixture.directory.path().join("socket_close_gate.so");
    let output = Command::new("cc")
        .args(["-shared", "-fPIC", "-Wall", "-Werror", "-o"])
        .arg(&interposer)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/transport/socket_close.c"
        ))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (mut entered, worker_entered) = UnixStream::pair().unwrap();
    entered
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (mut release, worker_release) = UnixStream::pair().unwrap();
    let entered_fd = worker_entered.as_raw_fd();
    let release_fd = worker_release.as_raw_fd();
    let notify = UnixDatagram::bind(fixture.directory.path().join("notify.sock")).unwrap();
    notify
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut command = fixture.command();
    command
        .env("LD_PRELOAD", &interposer)
        .env(
            "SIGRUND_SOCKET_GATE_PEER_PID",
            std::process::id().to_string(),
        )
        .env("SIGRUND_GATE_ENTERED_FD", entered_fd.to_string())
        .env("SIGRUND_GATE_RELEASE_FD", release_fd.to_string())
        .env(
            "NOTIFY_SOCKET",
            fixture.directory.path().join("notify.sock"),
        )
        .env("WATCHDOG_USEC", "300000")
        .env_remove("WATCHDOG_PID");
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
    drop(worker_entered);
    let pid = daemon.0.id();
    let mut message = [0; 128];
    let count = notify.recv(&mut message).unwrap();
    assert!(message[..count].starts_with(b"READY=1\n"));
    let baseline_fds = fs::read_dir(format!("/proc/{pid}/fd")).unwrap().count();
    let threads = fs::read_dir(format!("/proc/{pid}/task")).unwrap().count();
    let mut held_client = connect(&fixture.socket);
    let mut held_broker = connect(&fixture.broker);
    wait_for(|| {
        fs::read_to_string(&fixture.diagnostics)
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["event"] == "SOCKET_ADMITTED")
            .count()
            == 2
    });
    let held_token = fs::read_to_string(&fixture.diagnostics)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|event| event["event"] == "SOCKET_ADMITTED" && event["broker"] == false)
        .and_then(|event| event["worker_task"].as_u64())
        .unwrap();
    let null = File::open("/dev/null").unwrap();
    let mut rejected = Vec::new();
    // Neither rejection may parse the queued rights. Both final closes stall
    // until released, representing arbitrary destructor work in queued rights.
    let pause = || {
        assert_eq!(unsafe { libc::kill(pid as _, libc::SIGSTOP) }, 0);
        wait_for(|| {
            fs::read_to_string(format!("/proc/{pid}/status"))
                .unwrap()
                .lines()
                .any(|line| line.starts_with("State:") && line.contains("T (stopped)"))
        });
    };
    let resume = || assert_eq!(unsafe { libc::kill(pid as _, libc::SIGCONT) }, 0);
    for path in [&fixture.socket, &fixture.broker] {
        // Queue rights before accept/rejection, as an attacker can do on a
        // busy daemon. This removes a sender-vs-shutdown race from the probe.
        pause();
        let socket = connect(path);
        send_fds(&socket, &[0xfe], &[null.as_raw_fd()]);
        rejected.push(socket);
        resume();
        let mut tid = [0; 8];
        entered
            .read_exact(&mut tid)
            .expect("rejected socket close not reached");
        assert_ne!(
            u64::from_ne_bytes(tid),
            pid as u64,
            "coordinator closed rejected socket"
        );
    }
    // An unrelated UID still receives a decision while both close workers are
    // stalled. Its final socket close must also retain bounded ownership.
    fixture.peer(65534, "client");
    let epoll_info = fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .flatten()
        .find(|entry| fs::read_link(entry.path()).unwrap() == Path::new("anon_inode:[eventpoll]"))
        .map(|entry| format!("/proc/{pid}/fdinfo/{}", entry.file_name().to_string_lossy()))
        .unwrap();
    let registered = |token: u64| {
        fs::read_to_string(&epoll_info)
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("tfd:"))
            .any(|line| {
                let mut fields = line.split_ascii_whitespace();
                assert!(fields.any(|field| field == "data:"));
                u64::from_str_radix(fields.next().unwrap(), 16).unwrap() == token
            })
    };
    // Fill disposal ownership, including a few sockets left in the kernel
    // backlog. A full queue must pause accept, not grow threads or spin epoll.
    for count in [32, 32, 32, 32, 2] {
        pause();
        for _ in 0..count {
            let socket = connect(&fixture.socket);
            send_fds(&socket, &[0xfe], &[null.as_raw_fd()]);
            rejected.push(socket);
        }
        resume();
        thread::sleep(Duration::from_millis(10));
    }
    wait_for(|| !registered(1) && !registered(2));
    assert_eq!(
        fs::read_dir(format!("/proc/{pid}/task")).unwrap().count(),
        threads
    );
    for _ in 0..3 {
        let count = notify
            .recv(&mut message)
            .expect("socket disposal delayed watchdog");
        assert_eq!(&message[..count], b"WATCHDOG=1");
    }
    // Retiring an admitted connection remains responsive with disposal full.
    held_client.shutdown(std::net::Shutdown::Both).unwrap();
    expect_closed(&mut held_client);
    wait_for(|| !registered(held_token));
    release.write_all(&[b'x'; 200]).unwrap();
    wait_for(|| registered(1) && registered(2));
    drop(rejected);
    drop(held_client);
    held_broker.shutdown(std::net::Shutdown::Both).unwrap();
    expect_closed(&mut held_broker);
    // All reserved capacity eventually returns; root can make a fresh request.
    let mut recovered = connect(&fixture.socket);
    send_hello(&mut recovered, &fixture.executable);
    assert_eq!(decision(&mut recovered).status, "TIMEOUT_CSR");
    drop(recovered);
    wait_for(|| fs::read_dir(format!("/proc/{pid}/fd")).unwrap().count() == baseline_fds);
    // Every queued close is done. Remove unused release bytes so a fresh close
    // can prove shutdown retains the instance lock through stalled disposal.
    let mut unused = [0u8; 200];
    let count = unsafe {
        libc::recv(
            worker_release.as_raw_fd(),
            unused.as_mut_ptr().cast(),
            unused.len(),
            libc::MSG_DONTWAIT,
        )
    };
    assert!(count > 0);
    let mut tid = [0u8; 8];
    let mut available = 0i32;
    assert_eq!(
        unsafe { libc::ioctl(entered.as_raw_fd(), libc::FIONREAD, &mut available) },
        0
    );
    for _ in 0..(available as usize / tid.len()) {
        entered.read_exact(&mut tid).unwrap();
    }
    let admitted_before = fixture.diagnostic_count();
    let mut blocker = connect(&fixture.broker);
    wait_for(|| {
        fs::read_to_string(&fixture.diagnostics)
            .unwrap()
            .lines()
            .skip(admitted_before)
            .any(|line| line.contains("SOCKET_ADMITTED"))
    });
    pause();
    let queued = connect(&fixture.broker);
    send_fds(&queued, &[0xfe], &[null.as_raw_fd()]);
    resume();
    entered
        .read_exact(&mut tid)
        .expect("shutdown close gate not reached");
    assert_ne!(u64::from_ne_bytes(tid), pid as u64);
    daemon.begin_stop();
    expect_closed(&mut blocker);
    assert!(daemon.0.try_wait().unwrap().is_none());
    let replacement = fixture.command().output().unwrap();
    assert!(String::from_utf8_lossy(&replacement.stderr).contains("already in use"));
    release.write_all(b"x").unwrap();
    drop((blocker, queued));
    daemon.finish_stop();
    assert!(!fixture.socket.exists() && !fixture.broker.exists());
}
