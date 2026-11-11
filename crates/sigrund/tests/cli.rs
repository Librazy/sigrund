use base64::{Engine as _, engine::general_purpose::STANDARD};
use sigrund::cli::{ApprovalArgs, ClientArgs, DaemonArgs, DaemonMode, RequestOptions};
use std::process::Command;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).into()).collect()
}

#[test]
fn packaged_service_and_command_defaults_select_the_same_endpoints_and_state() {
    let service = include_str!("../../../packaging/sigrund.service");
    let command = service
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart="))
        .unwrap();
    let packaged = DaemonArgs::parse(
        &command
            .split_whitespace()
            .skip(1)
            .map(String::from)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let defaults = DaemonArgs::parse(&[]).unwrap();
    assert_eq!(packaged, defaults);
    assert_eq!(defaults.state_dir.to_str(), Some("/var/lib/sigrund"));
    assert_eq!(
        defaults.log_path.to_str(),
        Some("/var/log/sigrund/audit.jsonl")
    );
    assert_eq!(defaults.socket.to_str(), Some("/run/sigrund/client.sock"));
    assert_eq!(
        defaults.approval_socket.to_str(),
        Some("/run/sigrund/approve.sock")
    );
    for (setting, directory) in [
        ("StateDirectory=", defaults.state_dir.as_path()),
        ("LogsDirectory=", defaults.log_path.parent().unwrap()),
        ("RuntimeDirectory=", defaults.socket.parent().unwrap()),
    ] {
        let name = service
            .lines()
            .find_map(|line| line.strip_prefix(setting))
            .unwrap();
        assert_eq!(directory.file_name().unwrap(), name);
    }
    let approver = ApprovalArgs::parse(&args(&["--identity", "/root/.ssh/id_ed25519"])).unwrap();
    assert_eq!(approver.socket, defaults.approval_socket);
    assert_eq!(
        approver.epoch_file,
        defaults.state_dir.join("host-epoch.json")
    );
    let ClientArgs::Run { socket, .. } =
        ClientArgs::parse(&client_args(&["--", "/usr/bin/id"])).unwrap()
    else {
        panic!("expected a command request");
    };
    assert_eq!(socket, defaults.socket);
}

#[test]
fn mvp_command_forms_capture_socket_overrides_and_command_arguments() {
    let daemon = DaemonArgs::parse(&args(&[
        "--foreground",
        "--socket",
        "/tmp/client.sock",
        "--approval-socket",
        "/tmp/approve.sock",
        "--config",
        "/tmp/config.toml",
        "--signers",
        "/tmp/signers.toml",
        "--state-dir",
        "/tmp/state",
        "--log-path",
        "/tmp/log/audit.jsonl",
    ]))
    .unwrap();
    assert_eq!(daemon.mode, DaemonMode::Foreground);
    assert_eq!(daemon.socket.to_str(), Some("/tmp/client.sock"));
    assert_eq!(daemon.approval_socket.to_str(), Some("/tmp/approve.sock"));
    assert_eq!(daemon.config.unwrap().to_str(), Some("/tmp/config.toml"));
    assert_eq!(daemon.state_dir.to_str(), Some("/tmp/state"));
    assert_eq!(daemon.log_path.to_str(), Some("/tmp/log/audit.jsonl"));
    let approver = ApprovalArgs::parse(&args(&[
        "--socket",
        "/tmp/approve.sock",
        "--tty",
        "/dev/pts/1",
        "--identity",
        "/root/.ssh/id_ed25519",
        "--epoch-file",
        "/tmp/state/host-epoch.json",
    ]))
    .unwrap();
    assert_eq!(approver.socket.to_str(), Some("/tmp/approve.sock"));
    assert_eq!(approver.tty.to_str(), Some("/dev/pts/1"));
    assert_eq!(
        approver.epoch_file.to_str(),
        Some("/tmp/state/host-epoch.json")
    );
    let client = ClientArgs::parse(&client_args(&[
        "--socket",
        "/tmp/client.sock",
        "--",
        "/usr/bin/printf",
        "--socket",
        "two words",
        "",
    ]))
    .unwrap();
    assert_eq!(
        client,
        ClientArgs::Run {
            socket: "/tmp/client.sock".into(),
            command: args(&["/usr/bin/printf", "--socket", "two words", ""]),
            options: Box::new(RequestOptions {
                target: Some("host".into()),
                security_profile: Some("host-baseline".into()),
                ..RequestOptions::default()
            })
        }
    );
    assert!(matches!(
        ClientArgs::parse(&client_args(&["--", "/usr/bin/id"])).unwrap(),
        ClientArgs::Run { .. }
    ));
    assert_eq!(
        ApprovalArgs::parse(&args(&["--identity", "/root/.ssh/id_ed25519"]))
            .unwrap()
            .tty
            .to_str(),
        Some("/dev/tty")
    );
}

#[test]
fn invalid_or_ambiguous_cli_forms_are_rejected() {
    for arguments in [
        &["--socket"][..],
        &["--unknown"],
        &["--foreground", "--check-config"],
        &["--socket", "relative"],
        &["--socket", "/tmp/./client.sock"],
        &["--approval-socket", "/tmp/broker.sock/."],
        &["--state-dir", "/tmp/../state"],
        &["--log-path", "/tmp//audit.jsonl"],
        &["--socket", "/tmp/x", "--approval-socket", "/tmp/x"],
        &["--socket", "/tmp/a", "--socket", "/tmp/b"],
    ] {
        assert!(
            DaemonArgs::parse(&args(arguments)).is_err(),
            "{arguments:?}"
        );
    }
    for arguments in [
        &["--tty"][..],
        &["--tty", "relative"],
        &["--socket", "/a", "--socket", "/b"],
        &["--foreground"],
    ] {
        assert!(
            ApprovalArgs::parse(&args(arguments)).is_err(),
            "{arguments:?}"
        );
    }
    for arguments in [
        &[][..],
        &["--"],
        &["--", "id"],
        &["--socket", "/tmp/x", "/usr/bin/id"],
        &["--encode-signal", "9"],
    ] {
        assert!(
            ClientArgs::parse(&client_args(arguments)).is_err(),
            "{arguments:?}"
        );
    }
    for signal in [1, 2, 10, 12, 15] {
        assert_eq!(
            ClientArgs::parse(&client_args(&["--encode-signal", &signal.to_string()])).unwrap(),
            ClientArgs::EncodeSignal(signal)
        );
    }
}

#[test]
fn shipped_binaries_expose_help_and_reject_invalid_or_unavailable_invocations() {
    for binary in [
        env!("CARGO_BIN_EXE_sigrun"),
        env!("CARGO_BIN_EXE_sigrund"),
        env!("CARGO_BIN_EXE_sigrund-approve"),
    ] {
        let output = Command::new(binary).arg("--help").output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
        assert_eq!(
            Command::new(binary)
                .arg("--unknown")
                .output()
                .unwrap()
                .status
                .code(),
            Some(64)
        );
    }
    assert_eq!(
        Command::new(env!("CARGO_BIN_EXE_sigrun"))
            .args([
                "--target",
                "host",
                "--security-profile",
                "host-baseline",
                "--target-uid",
                "0",
                "--target-gid",
                "0",
                "--socket",
                "/tmp/cli-test.sock",
                "--",
                "/usr/bin/id"
            ])
            .output()
            .unwrap()
            .status
            .code(),
        Some(254)
    );
    assert_eq!(
        Command::new(env!("CARGO_BIN_EXE_sigrund-approve"))
            .args([
                "--socket",
                "/tmp/cli-test-approve.sock",
                "--tty",
                "/dev/tty"
            ])
            .output()
            .unwrap()
            .status
            .code(),
        Some(64)
    );
}

#[test]
fn check_config_reads_explicit_paths_and_rejects_invalid_mvp_profile() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.toml");
    let signers_path = temp.path().join("signers.toml");
    let mut config = include_str!("../../../config/sigrund.toml.example").replace(
        "<strict-padded-base64-32-byte-ed25519-key>",
        &STANDARD.encode([1; 32]),
    );
    config.push_str("\n[mvp]\n");
    // Valid OpenSSH wire key for the unprivileged configuration diagnostic.
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
        );
    std::fs::write(&config_path, &config).unwrap();
    std::fs::write(&signers_path, signer).unwrap();
    let check = || {
        Command::new(env!("CARGO_BIN_EXE_sigrund"))
            .arg("--check-config")
            .arg("--config")
            .arg(&config_path)
            .arg("--signers")
            .arg(&signers_path)
            .env("SIGRUND_CONFIG", "/nonexistent/overridden.toml")
            .output()
            .unwrap()
    };
    let output = check();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::write(&config_path, format!("{config}pty_enabled = true\n")).unwrap();
    let output = check();
    assert_eq!(output.status.code(), Some(78));
    assert!(String::from_utf8_lossy(&output.stderr).contains("MVP requires"));
}

#[test]
fn validate_hello_rejects_noncanonical_signed_warrant_through_cli() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("hello.json");
    let hello = serde_json::json!({"mode":"signed", "tty_mode":"stdio", "caller_env":{},
        "dsse_envelope":{"payloadType":sigrund_core::crypto::WARRANT_PAYLOAD_TYPE,
            "payload":STANDARD.encode(b"{}\n"), "signatures":[{"keyid":"root", "sig":STANDARD.encode([1;64])}]}});
    std::fs::write(&path, serde_json::to_vec(&hello).unwrap()).unwrap();
    assert_eq!(
        Command::new(env!("CARGO_BIN_EXE_sigrun"))
            .arg("--validate-hello")
            .arg(path)
            .output()
            .unwrap()
            .status
            .code(),
        Some(65)
    );
}

#[test]
fn approver_requires_operator_controlled_identity_and_policy_options() {
    let parsed = ApprovalArgs::parse(&args(&[
        "--signers",
        "/root/policy.toml",
        "--identity",
        "/root/.ssh/id_ed25519.pub",
    ]))
    .unwrap();
    assert_eq!(parsed.signers.to_str(), Some("/root/policy.toml"));
    assert_eq!(
        parsed.identity.unwrap().to_str(),
        Some("/root/.ssh/id_ed25519.pub")
    );
    for argv in [
        vec!["--identity"],
        vec!["--identity", "relative"],
        vec!["--signers", "/a", "--signers", "/b"],
        vec!["--identity", "/a", "--identity", "/b"],
    ] {
        assert!(ApprovalArgs::parse(&args(&argv)).is_err());
    }
}

#[path = "cli/request.rs"]
mod request;

#[path = "cli/warrant.rs"]
mod warrant;

fn client_args(values: &[&str]) -> Vec<String> {
    let mut result = Vec::new();
    let end = values
        .iter()
        .position(|v| *v == "--")
        .unwrap_or(values.len());
    let flags = &values[..end];
    if !flags.contains(&"--warrant")
        && !flags.contains(&"--encode-signal")
        && !flags.contains(&"--validate-hello")
    {
        for (flag, value) in [
            ("--target", "host"),
            ("--security-profile", "host-baseline"),
            ("--target-uid", "0"),
            ("--target-gid", "0"),
        ] {
            if !flags.contains(&flag) {
                result.extend([flag.to_owned(), value.to_owned()]);
            }
        }
    }
    result.extend(args(values));
    result
}

fn binaries() -> [&'static str; 6] {
    [
        env!("CARGO_BIN_EXE_sigrun"),
        env!("CARGO_BIN_EXE_sigrund"),
        env!("CARGO_BIN_EXE_sigrund-approve"),
        env!("CARGO_BIN_EXE_sigrundctl"),
        env!("CARGO_BIN_EXE_sigrund-collector"),
        env!("CARGO_BIN_EXE_sigrund-anchor"),
    ]
}

#[test]
fn all_binaries_offer_generated_help_version_and_usage_errors() {
    for binary in binaries() {
        for flag in ["-h", "--help", "-V", "--version"] {
            let output = Command::new(binary).arg(flag).output().unwrap();
            assert!(output.status.success(), "{binary} {flag}: {output:?}");
            assert!(output.stderr.is_empty(), "{binary} {flag}: {output:?}");
            let stdout = String::from_utf8(output.stdout).unwrap();
            if matches!(flag, "-h" | "--help") {
                assert!(stdout.contains("Usage:"), "{binary}: {stdout}");
                assert!(stdout.contains("--version"), "{binary}: {stdout}");
            } else {
                assert!(
                    stdout.contains(env!("CARGO_PKG_VERSION")),
                    "{binary}: {stdout}"
                );
            }
        }
        let output = Command::new(binary).arg("--unknown").output().unwrap();
        assert_eq!(output.status.code(), Some(64), "{binary}: {output:?}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("--unknown") && stderr.contains("--help"),
            "{binary}: {stderr}"
        );
    }
}

#[test]
fn administrative_commands_offer_help_at_every_level_without_effects() {
    let ctl = env!("CARGO_BIN_EXE_sigrundctl");
    for command in [
        vec!["init-host"],
        vec!["target"],
        vec!["target", "register"],
        vec!["target", "register-podman"],
        vec!["target", "revoke"],
        vec!["target", "export-binding"],
        vec!["target", "export-binding", "host"],
        vec!["csr-pae"],
        vec!["pack-warrant"],
        vec!["uuidv7"],
        vec!["validate-uuid"],
    ] {
        for arguments in [
            command
                .iter()
                .copied()
                .chain(["--help"])
                .collect::<Vec<_>>(),
            ["help"]
                .into_iter()
                .chain(command.iter().copied())
                .collect(),
        ] {
            let output = Command::new(ctl).args(&arguments).output().unwrap();
            assert!(output.status.success(), "{arguments:?}: {output:?}");
            assert!(output.stderr.is_empty(), "{arguments:?}: {output:?}");
            assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
        }
    }
}

#[test]
fn malformed_admin_commands_fail_before_creating_outputs() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    let log = directory.path().join("log/audit.jsonl");
    let ctl = env!("CARGO_BIN_EXE_sigrundctl");
    for arguments in [
        vec![
            "init-host",
            "--state-dir",
            state.to_str().unwrap(),
            "--log-path",
            log.to_str().unwrap(),
            "--unknown",
        ],
        vec!["init-host", "--state-dir", state.to_str().unwrap()],
        vec![
            "init-host",
            "--state-dir",
            "relative",
            "--log-path",
            log.to_str().unwrap(),
        ],
        vec![
            "init-host",
            "--state-dir",
            state.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--log-path",
            log.to_str().unwrap(),
        ],
        vec!["target", "register", "example", "--pid", "1"],
        vec![
            "target",
            "register",
            "example",
            "--pid",
            "0",
            "--owner-uid",
            "0",
            "--security-profile",
            "host-baseline",
        ],
        vec![
            "target",
            "register-podman",
            "example",
            "--pid",
            "1",
            "--owner-uid",
            "0",
            "--security-profile",
            "host-baseline",
        ],
        vec!["target", "revoke", "example", "--pid", "1"],
        vec![
            "target",
            "export-binding",
            "host",
            "--output",
            log.to_str().unwrap(),
        ],
        vec!["csr-pae", "--csr", "/nonexistent"],
        vec![
            "pack-warrant",
            "--csr",
            "/nonexistent",
            "--signature",
            "/nonexistent",
            "--output",
            log.to_str().unwrap(),
        ],
        vec!["uuidv7", "ignored"],
        vec!["--validate-uuid"],
        vec!["uuidv7", "--validate-uuid", "ignored"],
    ] {
        let output = Command::new(ctl).args(&arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(64), "{arguments:?}: {output:?}");
    }
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn uuid_generation_round_trips_through_subcommand_and_legacy_option() {
    let ctl = env!("CARGO_BIN_EXE_sigrundctl");
    let output = Command::new(ctl).arg("uuidv7").output().unwrap();
    assert!(output.status.success());
    let uuid = String::from_utf8(output.stdout).unwrap();
    for command in ["validate-uuid", "--validate-uuid"] {
        assert!(
            Command::new(ctl)
                .args([command, uuid.trim()])
                .output()
                .unwrap()
                .status
                .success()
        );
        assert_eq!(
            Command::new(ctl)
                .args([command, "invalid"])
                .output()
                .unwrap()
                .status
                .code(),
            Some(65)
        );
    }
}

#[test]
fn clap_equals_syntax_preserves_command_arguments_after_separator() {
    let command = [
        "/usr/bin/printf",
        "--help",
        "--version",
        "--target=other",
        "--",
        "",
        "two words",
        "-1",
    ];
    let input = [
        "--target=host",
        "--security-profile=host-baseline",
        "--target-uid=0",
        "--target-gid=0",
        "--env=LANG=C",
        "--",
    ]
    .into_iter()
    .chain(command)
    .map(String::from)
    .collect::<Vec<_>>();
    let ClientArgs::Run {
        command: actual,
        options,
        ..
    } = ClientArgs::parse(&input).unwrap()
    else {
        panic!("expected run")
    };
    assert_eq!(actual, command);
    assert_eq!(options.env_exact["LANG"], "C");
    let mut duplicate = input.clone();
    duplicate.insert(0, "--target=host".into());
    assert!(ClientArgs::parse(&duplicate).is_err());
    let mut missing_separator = input;
    missing_separator.remove(5);
    assert!(ClientArgs::parse(&missing_separator).is_err());
}

#[test]
fn protocol_and_privileged_paths_reject_non_utf8_without_panicking() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    for binary in [binaries()[0], binaries()[1], binaries()[2], binaries()[5]] {
        let output = Command::new(binary)
            .args([
                OsString::from("--socket"),
                OsString::from_vec(vec![b'/', 255]),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(64), "{binary}: {output:?}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    }
}
