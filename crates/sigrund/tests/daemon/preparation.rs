use super::*;

pub(super) fn verify_preparation_requests() {
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
