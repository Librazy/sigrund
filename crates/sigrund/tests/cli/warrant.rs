use sigrund::cli::{ClientArgs, RequestOptions};
use std::process::Command;
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn signed_warrant_input_is_mutually_exclusive_with_unsigned_construction() {
    let parsed = ClientArgs::parse(&args(&[
        "--warrant",
        "/tmp/envelope.json",
        "--status-fd",
        "9",
        "--auth-fail-exit-code",
        "42",
    ]))
    .unwrap();
    assert!(
        matches!(parsed, ClientArgs::Run {command,options:RequestOptions {warrant:Some(path),status_fd:Some(9),auth_fail_exit_code:42,..},..} if command.is_empty() && path.to_str()==Some("/tmp/envelope.json"))
    );
    for suffix in [
        vec!["--", "/usr/bin/id"],
        vec!["--target-uid", "0"],
        vec!["--target-gid", "0"],
        vec!["--cwd", "/"],
        vec!["--env", "LANG=C"],
        vec!["--supplementary-gid", "33"],
        vec!["--capability", "CAP_CHOWN"],
        vec!["--stdin", "null"],
        vec!["--ttl-secs", "900"],
        vec!["--umask", "077"],
    ] {
        let mut argv = args(&["--warrant", "/tmp/envelope.json"]);
        argv.extend(args(&suffix));
        assert!(ClientArgs::parse(&argv).is_err(), "{argv:?}");
    }
    for argv in [
        vec!["--warrant"],
        vec!["--warrant", "relative"],
        vec!["--warrant", "/a", "--warrant", "/b"],
    ] {
        assert!(ClientArgs::parse(&args(&argv)).is_err());
    }
}

#[test]
fn malformed_warrant_files_fail_before_connecting() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("daemon.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let file = directory.path().join("envelope.json");
    for bytes in [b"{}".to_vec(), b"[]".to_vec(), vec![b' '; 196_609]] {
        std::fs::write(&file, bytes).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_sigrun"))
            .arg("--socket")
            .arg(&socket)
            .arg("--warrant")
            .arg(&file)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(64),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            matches!(listener.accept(), Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
        );
    }
}
