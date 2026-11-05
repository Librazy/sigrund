//! Public observations are intentionally identical across private preparation failures.
use super::*;
use std::os::fd::{FromRawFd, OwnedFd};

#[test]
fn confidentiality_gate() {
    let _gate = namespace_gate();
    let output = Command::new("unshare")
        .args(["--user", "--map-auto", "--map-root-user"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "v2::namespace_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("SIGRUND_V2_NAMESPACE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn broker_request(socket: &mut UnixStream) -> sigrund_core::approval::ApprovalRequest {
    let mut header = [0; 4];
    socket.read_exact(&mut header).unwrap();
    let mut bytes = vec![0; u32::from_be_bytes(header) as usize];
    socket.read_exact(&mut bytes).unwrap();
    sigrund_core::approval::ApprovalRequest::parse_jcs(&bytes).unwrap()
}

#[test]
#[ignore = "invoked by the v2 namespace gate"]
fn namespace_fixture() {
    assert_eq!(std::env::var("SIGRUND_V2_NAMESPACE").unwrap(), "1");
    let f = Fixture::new();
    fs::write(
        &f.signers,
        fs::read_to_string(&f.signers).unwrap().replace(
            "allowed_requester_uids = [1001]",
            "allowed_requester_uids = [0, 65534]",
        ),
    )
    .unwrap();
    let daemon = f.launch();
    let context_path = PathBuf::from(format!("{}.context", f.socket.display()));
    let mut context = connect(&context_path);
    context
        .write_all(&encode_frame(FrameType::ClientContextQuery, br#"{"version":"2.0"}"#).unwrap())
        .unwrap();
    let mut header = [0; 5];
    context.read_exact(&mut header).unwrap();
    assert_eq!(header[0], FrameType::ServerContext as u8);
    let mut bytes = vec![0; u32::from_be_bytes(header[1..].try_into().unwrap()) as usize];
    context.read_exact(&mut bytes).unwrap();
    let public: sigrund_core::protocol::PublicContext = parse_strict(&bytes).unwrap();
    assert_eq!(public.version, "2.0");
    assert!(
        !String::from_utf8(bytes)
            .unwrap()
            .contains(f.executable.to_str().unwrap())
    );
    expect_closed(&mut context);
    for query in [
        br#"{"version":"2.0","path":"/root/private"}"#.as_slice(),
        br#"{"version":"2.0","version":"2.0"}"#,
    ] {
        let mut socket = connect(&context_path);
        socket
            .write_all(&encode_frame(FrameType::ClientContextQuery, query).unwrap())
            .unwrap();
        expect_closed(&mut socket);
    }
    let script = f.executable.with_file_name("script");
    fs::write(&script, b"#!/bin/sh\n").unwrap();
    for case in [
        "missing",
        "non_elf",
        "schema",
        "refused",
        "forged_full",
        "standalone_thin",
    ] {
        let before = f.diagnostic_count();
        let mut broker = connect(&f.broker);
        let mut socket = f.admitted_client();
        let start = Instant::now();
        let mut body: serde_json::Value = serde_json::from_slice(&hello(&f.executable)).unwrap();
        match case {
            "missing" => {
                body["intent"]["command"]["executable_path"] = f
                    .executable
                    .with_file_name("absent")
                    .to_str()
                    .unwrap()
                    .into()
            }
            "non_elf" => {
                body["intent"]["command"]["executable_path"] = script.to_str().unwrap().into()
            }
            "schema" => body["extra"] = true.into(),
            _ => (),
        }
        if matches!(case, "forged_full" | "standalone_thin") {
            let hello = sigrund_core::protocol::ClientHello::parse_request(
                &serde_json::to_vec(&body).unwrap(),
            )
            .unwrap();
            let csr = sigrund_core::warrant::Csr::from_unsigned(
                &hello,
                sigrund_core::warrant::CsrIdentity {
                    grant_id: new_uuidv7().to_string(),
                    host_id: public.host_id.clone(),
                    requester_uid: 0,
                    requester_gid: 0,
                    now: authorization::now(),
                },
                sigrund_core::warrant::SnapshotDigests {
                    executable_sha256: Some(sha256_hex(&fs::read(&f.executable).unwrap())),
                    executable_trust: None,
                    post_exec_capabilities: None,
                    stdin_sha256: None,
                },
                3600,
            )
            .unwrap();
            let mut w = csr.warrant().clone();
            // Exact evidence is insufficient without requester access proof. This
            // namespace is deliberately unsupported by the access helper.
            if case == "standalone_thin" {
                w.request_origin = "daemon_expanded_thin".into();
                w.approval_exec_id = Some(new_uuidv7().to_string());
                let envelope = authorization::envelope(w, 7);
                body = serde_json::json!({"version":"2.0","mode":"signed","tty_mode":"stdio","caller_env":{},"dsse_envelope":envelope});
            } else {
                body = serde_json::json!({"version":"2.0","mode":"full_csr","tty_mode":"stdio","caller_env":{},"csr_payload":String::from_utf8(csr.as_bytes().to_vec()).unwrap()});
            }
        }
        let mut pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        let read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        let regular = tempfile::tempfile().unwrap();
        send_fds(
            &socket,
            &encode_frame(FrameType::ClientHello, &serde_json::to_vec(&body).unwrap()).unwrap(),
            &[write.as_raw_fd(), regular.as_raw_fd()],
        );
        drop(write);
        if case == "refused" {
            let request = broker_request(&mut broker);
            let csr = sigrund_core::warrant::Csr::parse(request.csr_payload.as_bytes()).unwrap();
            assert_eq!(csr.warrant().request_origin, "daemon_expanded_thin");
            assert_eq!(
                csr.warrant().approval_exec_id.as_deref(),
                Some(request.exec_id.as_str())
            );
            let response = sigrund_core::approval::ApprovalResponse::Rejected {
                exec_id: request.exec_id,
                reason: "private refusal".into(),
            }
            .to_jcs()
            .unwrap();
            broker
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            broker.write_all(&response).unwrap();
        }
        thread::sleep(Duration::from_millis(80));
        assert_eq!(
            unsafe { libc::read(read.as_raw_fd(), [0u8; 1].as_mut_ptr().cast(), 1) },
            -1,
            "early output EOF: {case}"
        );
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(regular.metadata().unwrap().len(), 0);
        let mut peek = [0u8];
        assert_eq!(
            unsafe {
                libc::recv(
                    socket.as_raw_fd(),
                    peek.as_mut_ptr().cast(),
                    1,
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            },
            -1,
            "early outcome: {case}"
        );
        let result = decision(&mut socket);
        assert_eq!(result.status, "TIMEOUT", "{case}");
        assert!(
            start.elapsed() >= Duration::from_millis(2300),
            "early timeout: {case}"
        );
        assert_eq!(
            serde_json::to_value(&result)
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            2
        );
        expect_closed(&mut socket);
        if case != "refused" {
            assert_eq!(
                unsafe {
                    libc::recv(
                        broker.as_raw_fd(),
                        peek.as_mut_ptr().cast(),
                        1,
                        libc::MSG_PEEK | libc::MSG_DONTWAIT,
                    )
                },
                -1,
                "invalid request reached mandator: {case}"
            );
        }
        drop(broker);
        drop(socket);
        f.wait_for_cleanup(before);
    }
    daemon.stop();
}
