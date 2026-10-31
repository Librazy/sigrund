//! Client runtime probes use a strict fake UID-0 peer in a disposable user
//! namespace. They exercise the real binary, without claiming daemon execution.
use sigrund::transport::{ControlFrame, ControlReader};
use sigrund_core::{
    crypto::new_uuidv7,
    framing::{FrameType, encode_frame},
    protocol::{ClientHello, Decision},
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn wait(mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(8);
    while !f() {
        assert!(Instant::now() < end, "client fixture deadline");
        thread::sleep(Duration::from_millis(5));
    }
}
fn hello(stream: &UnixStream) -> ControlFrame {
    let mut reader = ControlReader::new(true);
    let mut frame = None;
    wait(|| {
        frame = reader.read(stream.as_raw_fd(), Instant::now()).unwrap();
        frame.is_some()
    });
    frame.unwrap()
}
fn send(stream: &mut UnixStream, kind: FrameType, payload: &[u8]) {
    stream
        .write_all(&encode_frame(kind, payload).unwrap())
        .unwrap();
}
fn decide(stream: &mut UnixStream, status: &str) {
    send(
        stream,
        FrameType::ServerAuthDecision,
        &serde_json::to_vec(&Decision {
            csr_payload: None,
            exec_id: new_uuidv7().to_string(),
            message: "test decision".into(),
            status: status.into(),
        })
        .unwrap(),
    );
}
struct Fixture {
    _dir: tempfile::TempDir,
    listener: UnixListener,
    path: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let binary = dir.path().join("sigrun");
        fs::copy(env!("CARGO_BIN_EXE_sigrun"), &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.path().join("client.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        Self {
            _dir: dir,
            listener,
            path,
        }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(self._dir.path().join("sigrun"));
        command
            .arg("--socket")
            .arg(&self.path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(65534) != 0
                    || libc::setuid(65534) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
    }
}
fn case(
    driver: impl FnOnce(UnixStream, ControlFrame) + Send + 'static,
    options: &[&str],
) -> (std::process::Output, Vec<u8>) {
    let fixture = Fixture::new();
    let mut pair = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let report = unsafe { OwnedFd::from_raw_fd(pair[1]) };
    let reader = unsafe { File::from_raw_fd(pair[0]) };
    let reports = thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut reader = reader;
        reader.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let fd = report.as_raw_fd();
    let mut command = fixture.command();
    command
        .arg("--status-fd")
        .arg("99")
        .args(options)
        .args(["--", "/usr/bin/id", "two words", ""]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(fd, 99) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(report);
    let server = thread::spawn(move || {
        let (socket, _) = fixture.listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let frame = hello(&socket);
        driver(socket, frame);
    });
    let output = child.wait_with_output().unwrap();
    server.join().unwrap();
    (output, reports.join().unwrap())
}
fn values(bytes: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn client_gate_in_user_namespace() {
    let output = Command::new("unshare")
        .args(["--user", "--map-auto", "--map-root-user"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "client_namespace_fixture",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SIGRUND_CLIENT_NAMESPACE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "client namespace gate requires unshare/subuid/subgid mappings:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
#[ignore = "invoked by the namespace gate"]
fn client_namespace_fixture() {
    assert_eq!(std::env::var("SIGRUND_CLIENT_NAMESPACE").unwrap(), "1");
    let (output, reports) = case(
        |mut socket, frame| {
            let hello = ClientHello::parse_request(&frame.payload).unwrap();
            assert_eq!(
                hello.requested_command.as_ref().unwrap().argv,
                ["/usr/bin/id", "two words", ""]
            );
            assert_eq!(
                hello
                    .requested_execution_context
                    .as_ref()
                    .unwrap()
                    .env_exact
                    .len(),
                2
            );
            assert_eq!(frame.rights.len(), 2);
            let mut files = frame.rights.into_iter().map(File::from);
            let mut out = files.next().unwrap();
            let mut err = files.next().unwrap();
            decide(&mut socket, "READY_TO_EXEC");
            let writing = thread::spawn(move || {
                for _ in 0..100 {
                    out.write_all(&[b'x'; 16384]).unwrap();
                    err.write_all(&[b'y'; 8192]).unwrap();
                }
            });
            send(
                &mut socket,
                FrameType::ServerChildExit,
                br#"{"exit_code":37,"signal":null}"#,
            );
            writing.join().unwrap();
        },
        &[],
    );
    assert_eq!(output.status.code(), Some(37));
    assert_eq!(output.stdout, vec![b'x'; 100 * 16384]);
    let prefix = b"sigrun: waiting for authorization\n";
    assert_eq!(
        output.stderr.strip_prefix(prefix).unwrap(),
        vec![b'y'; 100 * 8192]
    );
    assert_eq!(values(&reports).len(), 2);
    let (output, reports) = case(
        |mut socket, _| decide(&mut socket, "REJECTED"),
        &["--auth-fail-exit-code", "42"],
    );
    assert_eq!(output.status.code(), Some(42));
    assert!(output.stdout.is_empty());
    assert_eq!(values(&reports)[0]["status"], "REJECTED");
    for bad in [
        vec![255],
        vec![1],
        vec![5],
        vec![2, 0, 8, 0, 1],
        encode_frame(
            FrameType::ServerAuthDecision,
            br#"{"status":"REJECTED","status":"REJECTED"}"#,
        )
        .unwrap(),
    ] {
        let (output, reports) = case(
            move |mut socket, _| {
                socket.write_all(&bad).unwrap();
                let mut byte = [0];
                let _ = socket.read(&mut byte);
            },
            &[],
        );
        assert_eq!(output.status.code(), Some(254));
        assert_eq!(
            values(&reports).last().unwrap()["error"],
            "SERVER_PROTOCOL_ERROR"
        );
    }
    let (output, reports) = case(
        |mut socket, frame| {
            decide(&mut socket, "READY_TO_EXEC");
            drop(frame);
        },
        &[],
    );
    assert_eq!(output.status.code(), Some(254));
    assert_eq!(
        values(&reports).last().unwrap()["error"],
        "DAEMON_DISCONNECTED"
    );
    let (output, reports) = case(
        |mut socket, frame| {
            decide(&mut socket, "READY_TO_EXEC");
            drop(frame);
            send(
                &mut socket,
                FrameType::ServerChildExit,
                br#"{"exit_code":null,"signal":15}"#,
            );
        },
        &[],
    );
    assert_eq!(output.status.code(), Some(143));
    assert_eq!(values(&reports)[1]["signal"], 15);
    verify_fragmentation_and_invalid_server_data();
    verify_slow_and_broken_output();
    verify_signals_and_blocked_sink(false);
    verify_signals_and_blocked_sink(true);
    verify_terminal();
}

fn verify_fragmentation_and_invalid_server_data() {
    let (output, reports) = case(
        |mut socket, frame| {
            let bytes = encode_frame(
                FrameType::ServerAuthDecision,
                &serde_json::to_vec(&Decision {
                    csr_payload: None,
                    exec_id: new_uuidv7().to_string(),
                    message: "fragmented".into(),
                    status: "READY_TO_EXEC".into(),
                })
                .unwrap(),
            )
            .unwrap();
            for byte in bytes {
                socket.write_all(&[byte]).unwrap();
            }
            let exit = encode_frame(
                FrameType::ServerChildExit,
                br#"{"exit_code":0,"signal":null}"#,
            )
            .unwrap();
            for byte in exit {
                socket.write_all(&[byte]).unwrap();
            }
            drop(frame);
        },
        &[],
    );
    assert!(output.status.success());
    assert_eq!(values(&reports).len(), 2);
    for payload in [
        br#"{"exit_code":0}"#.as_slice(),
        br#"{"exit_code":0,"signal":9}"#,
        br#"{"exit_code":0,"signal":null,"extra":1}"#,
    ] {
        let (output, reports) = case(
            move |mut socket, _| {
                decide(&mut socket, "READY_TO_EXEC");
                send(&mut socket, FrameType::ServerChildExit, payload);
                let _ = socket.read(&mut [0]);
            },
            &[],
        );
        assert_eq!(output.status.code(), Some(254));
        assert_eq!(
            values(&reports).last().unwrap()["error"],
            "SERVER_PROTOCOL_ERROR"
        );
    }
    for late in [false, true] {
        let (output, reports) = case(
            move |mut socket, _| {
                let bytes = encode_frame(
                    FrameType::ServerAuthDecision,
                    &serde_json::to_vec(&Decision {
                        csr_payload: None,
                        exec_id: new_uuidv7().to_string(),
                        message: "ancillary".into(),
                        status: "REJECTED".into(),
                    })
                    .unwrap(),
                )
                .unwrap();
                if late {
                    socket.write_all(&bytes[..1]).unwrap();
                }
                let null = File::open("/dev/null").unwrap();
                let mut control = [0usize; 8];
                let mut iov = libc::iovec {
                    iov_base: bytes[usize::from(late)..].as_ptr().cast_mut().cast(),
                    iov_len: 1,
                };
                let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = control.as_mut_ptr().cast();
                msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;
                unsafe {
                    let c = libc::CMSG_FIRSTHDR(&msg);
                    (*c).cmsg_level = libc::SOL_SOCKET;
                    (*c).cmsg_type = libc::SCM_RIGHTS;
                    (*c).cmsg_len = libc::CMSG_LEN(4) as _;
                    std::ptr::write(libc::CMSG_DATA(c).cast::<i32>(), null.as_raw_fd());
                    assert_eq!(
                        libc::sendmsg(socket.as_raw_fd(), &msg, libc::MSG_NOSIGNAL),
                        1
                    );
                }
                let _ = socket.read(&mut [0]);
            },
            &[],
        );
        assert_eq!(output.status.code(), Some(254));
        assert_eq!(
            values(&reports).last().unwrap()["error"],
            "SERVER_PROTOCOL_ERROR"
        );
    }
    // An incomplete frame has one cumulative deadline; receiving its type
    // cannot leave the requester waiting forever for the remaining header.
    let start = Instant::now();
    let (output, reports) = case(
        |mut socket, _| {
            socket
                .write_all(&[FrameType::ServerAuthDecision as u8])
                .unwrap();
            assert_eq!(socket.read(&mut [0]).unwrap(), 0);
        },
        &[],
    );
    assert_eq!(output.status.code(), Some(254));
    assert!(start.elapsed() < Duration::from_secs(8));
    assert_eq!(
        values(&reports).last().unwrap()["error"],
        "SERVER_PROTOCOL_ERROR"
    );
}

fn verify_slow_and_broken_output() {
    for broken in [false, true] {
        let fixture = Fixture::new();
        let mut pair = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        let sink = unsafe { File::from_raw_fd(pair[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(pair[1]) };
        let mut prefilled = 0;
        while unsafe { libc::write(writer.as_raw_fd(), [b'z'; 4096].as_ptr().cast(), 4096) } > 0 {
            prefilled += 4096;
        }
        let (mut report, report_writer) = UnixStream::pair().unwrap();
        report
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let report_fd = report_writer.as_raw_fd();
        let mut command = fixture.command();
        command
            .args(["--status-fd", "99", "--", "/usr/bin/id"])
            .stdout(Stdio::from(writer));
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(report_fd, 99) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop(command);
        drop(report_writer);
        let (mut socket, _) = fixture.listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let frame = hello(&socket);
        decide(&mut socket, "READY_TO_EXEC");
        let mut files = frame.rights.into_iter().map(File::from);
        let mut out = files.next().unwrap();
        drop(files);
        let producing = thread::spawn(move || {
            let result = out.write_all(&vec![b'x'; 262144]);
            if !broken {
                result.unwrap();
            }
        });
        if broken {
            drop(sink);
            assert_eq!(socket.read(&mut [0]).unwrap(), 0);
            wait(|| child.try_wait().unwrap().is_some());
            assert_eq!(child.wait().unwrap().code(), Some(254));
        } else {
            send(
                &mut socket,
                FrameType::ServerChildExit,
                br#"{"exit_code":19,"signal":null}"#,
            );
            let mut reports = std::io::BufReader::new(&mut report);
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reports, &mut line).unwrap();
            assert!(line.contains("READY_TO_EXEC"));
            line.clear();
            std::io::BufRead::read_line(&mut reports, &mut line).unwrap();
            assert!(
                line.contains("exit_code"),
                "control must progress while output blocks"
            );
            assert!(
                child.try_wait().unwrap().is_none(),
                "exit must await output EOF/drain"
            );
            let flags = unsafe { libc::fcntl(sink.as_raw_fd(), libc::F_GETFL) };
            assert_eq!(
                unsafe { libc::fcntl(sink.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) },
                0
            );
            let draining = thread::spawn(move || {
                let mut sink = sink;
                let mut bytes = Vec::new();
                sink.read_to_end(&mut bytes).unwrap();
                bytes
            });
            wait(|| child.try_wait().unwrap().is_some());
            assert_eq!(child.wait().unwrap().code(), Some(19));
            let bytes = draining.join().unwrap();
            assert_eq!(&bytes[..prefilled], vec![b'z'; prefilled]);
            assert_eq!(&bytes[prefilled..], vec![b'x'; 262144]);
        }
        producing.join().unwrap();
    }
}

fn verify_signals_and_blocked_sink(ready: bool) {
    let fixture = Fixture::new();
    let mut pair = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    let sink_read = unsafe { OwnedFd::from_raw_fd(pair[0]) };
    let sink_write = unsafe { OwnedFd::from_raw_fd(pair[1]) };
    while unsafe { libc::write(sink_write.as_raw_fd(), [b'z'; 4096].as_ptr().cast(), 4096) } > 0 {}
    let (report, report_writer) = UnixStream::pair().unwrap();
    report
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let report_fd = report_writer.as_raw_fd();
    let mut command = fixture.command();
    command
        .args(["--status-fd", "99", "--", "/usr/bin/id"])
        .stderr(Stdio::from(sink_write));
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(report_fd, 99) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    drop(report_writer);
    let mut reports = std::io::BufReader::new(report);
    let (mut socket, _) = fixture.listener.accept().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let frame = hello(&socket);
    if ready {
        decide(&mut socket, "READY_TO_EXEC");
        // Status delivery proves readiness was processed while the diagnostic
        // writer remains stalled; do not race a pre-readiness signal.
        let mut line = String::new();
        std::io::BufRead::read_line(&mut reports, &mut line).unwrap();
        assert!(line.contains("READY_TO_EXEC"));
        assert_eq!(unsafe { libc::kill(child.id() as _, libc::SIGUSR1) }, 0);
        let mut reader = ControlReader::new(false);
        let mut received = None;
        wait(|| {
            received = reader.read(socket.as_raw_fd(), Instant::now()).unwrap();
            received.is_some()
        });
        assert_eq!(received.unwrap().payload, br#"{"signal":10}"#);
        drop(frame);
        send(
            &mut socket,
            FrameType::ServerChildExit,
            br#"{"exit_code":0,"signal":null}"#,
        );
        line.clear();
        std::io::BufRead::read_line(&mut reports, &mut line).unwrap();
        assert!(line.contains("exit_code"));
    }
    assert_eq!(unsafe { libc::kill(child.id() as _, libc::SIGINT) }, 0);
    wait(|| child.try_wait().unwrap().is_some());
    assert_eq!(child.wait().unwrap().code(), Some(130));
    drop(sink_read);
}
fn verify_terminal() {
    let fixture = Fixture::new();
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
    let mut master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    let mut child = fixture
        .command()
        .args(["--", "/usr/bin/id"])
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave)
        .spawn()
        .unwrap();
    let (mut socket, _) = fixture.listener.accept().unwrap();
    let frame = hello(&socket);
    for fd in &frame.rights {
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) }, 0);
        assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFIFO);
    }
    decide(&mut socket, "READY_TO_EXEC");
    let mut files = frame.rights.into_iter().map(File::from);
    files
        .next()
        .unwrap()
        .write_all(b"terminal stdout\n")
        .unwrap();
    files
        .next()
        .unwrap()
        .write_all(b"terminal stderr\n")
        .unwrap();
    drop(files);
    send(
        &mut socket,
        FrameType::ServerChildExit,
        br#"{"exit_code":0,"signal":null}"#,
    );
    wait(|| child.try_wait().unwrap().is_some());
    assert!(child.wait().unwrap().success());
    let mut text = Vec::new();
    let _ = master.read_to_end(&mut text);
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("terminal stdout"));
    assert!(text.contains("terminal stderr"));
}
