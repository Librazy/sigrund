use sigrund::cli::{ClientArgs, RequestOptions};
use std::{os::unix::process::CommandExt, path::Path, process::Command};
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}
#[test]
fn defaults_overrides_and_canonical_collections_are_exact() {
    let options = RequestOptions::default();
    let hello = options
        .hello(
            &args(&["/usr/bin/printf", "two words", ""]),
            Path::new("/captured/cwd"),
        )
        .unwrap();
    assert!(hello.caller_env.is_empty());
    let cmd = hello.requested_command.unwrap();
    assert_eq!(cmd.cwd, "/captured/cwd");
    assert_eq!(cmd.argv, ["/usr/bin/printf", "two words", ""]);
    let c = hello.requested_execution_context.unwrap();
    assert_eq!((c.target_uid, c.target_gid, c.umask), (0, 0, 0o77));
    assert_eq!(
        c.env_exact,
        std::collections::BTreeMap::from([
            ("LANG".into(), "C.UTF-8".into()),
            ("PATH".into(), "/usr/sbin:/usr/bin".into())
        ])
    );
    let ClientArgs::Run { options, .. } = ClientArgs::parse(&args(&[
        "--target-uid",
        "33",
        "--target-gid",
        "44",
        "--supplementary-gid",
        "104",
        "--supplementary-gid",
        "33",
        "--capability",
        "CAP_SYS_ADMIN",
        "--capability",
        "CAP_NET_ADMIN",
        "--cwd",
        "/",
        "--env",
        "LANG=reviewed",
        "--env",
        "EMPTY=",
        "--umask",
        "027",
        "--stdin",
        "sha256",
        "--ttl-secs",
        "30",
        "--status-fd",
        "9",
        "--auth-fail-exit-code",
        "42",
        "--",
        "/usr/bin/id",
    ]))
    .unwrap() else {
        panic!()
    };
    assert_eq!(options.supplementary_gids, [33, 104]);
    assert_eq!(options.capabilities, ["CAP_NET_ADMIN", "CAP_SYS_ADMIN"]);
    assert_eq!(
        (options.target_uid, options.target_gid, options.umask),
        (33, 44, 0o27)
    );
    assert_eq!(options.env_exact["LANG"], "reviewed");
    assert_eq!(options.env_exact["EMPTY"], "");
    assert_eq!(options.status_fd, Some(9));
    assert_eq!(
        options
            .hello(&args(&["/usr/bin/id"]), Path::new("/ignored"))
            .unwrap()
            .requested_command
            .unwrap()
            .cwd,
        "/"
    );
}
#[test]
fn invalid_client_values_fail_before_connecting() {
    for flags in [
        args(&["--target-uid", "4294967295"]),
        args(&["--target-gid", "-1"]),
        args(&["--ttl-secs", "0"]),
        args(&["--ttl-secs", "18446744073709551616"]),
        args(&["--umask", "1000"]),
        args(&["--umask", "089"]),
        args(&["--stdin", "unrestricted_interactive"]),
        args(&["--env", "bad=x"]),
        args(&["--env", "LANG=x", "--env", "LANG=y"]),
        args(&["--env", "CONTROL=\n"]),
        args(&["--capability", "CAP_UNKNOWN"]),
        args(&[
            "--capability",
            "CAP_SYS_ADMIN",
            "--capability",
            "CAP_SYS_ADMIN",
        ]),
        args(&["--supplementary-gid", "33", "--supplementary-gid", "33"]),
        args(&["--status-fd", "1"]),
        args(&["--status-fd", "2"]),
        args(&["--status-fd", "-1"]),
        args(&["--auth-fail-exit-code", "256"]),
    ] {
        let mut input = args(&["--socket", "/nonexistent/socket"]);
        input.extend(flags);
        input.extend(args(&["--", "/usr/bin/id"]));
        assert!(ClientArgs::parse(&input).is_err(), "{input:?}");
        assert_eq!(
            Command::new(env!("CARGO_BIN_EXE_sigrun"))
                .args(&input)
                .output()
                .unwrap()
                .status
                .code(),
            Some(64),
            "{input:?}"
        );
    }
    use std::os::unix::ffi::OsStringExt;
    assert_eq!(
        Command::new(env!("CARGO_BIN_EXE_sigrun"))
            .args([
                std::ffi::OsString::from("--"),
                std::ffi::OsString::from("/usr/bin/id"),
                std::ffi::OsString::from_vec(vec![255])
            ])
            .output()
            .unwrap()
            .status
            .code(),
        Some(64)
    );
    // A closed status FD cannot accidentally become an internal event/socket FD.
    assert_eq!(
        Command::new(env!("CARGO_BIN_EXE_sigrun"))
            .args([
                "--socket",
                "/nonexistent/socket",
                "--status-fd",
                "99",
                "--",
                "/usr/bin/id"
            ])
            .output()
            .unwrap()
            .status
            .code(),
        Some(64)
    );

    // A distinct descriptor number may still be a shell alias (`3>&1`).
    // The client must reject it before opening the daemon connection.
    let alias_socket = tempfile::tempdir().unwrap().path().join("never.sock");
    let mut alias = Command::new(env!("CARGO_BIN_EXE_sigrun"));
    alias.args([
        "--socket",
        alias_socket.to_str().unwrap(),
        "--status-fd",
        "99",
        "--",
        "/usr/bin/id",
    ]);
    unsafe {
        alias.pre_exec(|| {
            if libc::dup2(1, 99) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    assert_eq!(alias.output().unwrap().status.code(), Some(64));
}
