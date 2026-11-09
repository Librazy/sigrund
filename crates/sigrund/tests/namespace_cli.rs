use sigrund::cli::ClientArgs;
use sigrund_core::host::Selector;
use std::path::Path;
fn args(target: &str, extra: &[&str]) -> Vec<String> {
    [
        "--target",
        target,
        "--security-profile",
        "selinux-minimal",
        "--account",
        "service",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .chain(["--", "/usr/bin/tool"])
    .map(str::to_owned)
    .collect()
}
#[test]
fn namespace_selection_preserves_explicit_intent_and_process_pid_scope() {
    for (target, expected) in [
        ("self", Selector::Self_ {}),
        (
            "registered:container-b",
            Selector::Registered {
                id: "container-b".into(),
            },
        ),
        (
            "process:1234",
            Selector::Process {
                pid: 1234,
                pid_scope: "daemon".into(),
            },
        ),
    ] {
        let ClientArgs::Run {
            options, command, ..
        } = ClientArgs::parse(&args(target, &[])).unwrap()
        else {
            panic!("expected run mode")
        };
        let hello = options.hello(&command, Path::new("/")).unwrap();
        let original = hello.original_intent().unwrap();
        assert_eq!(original.target, expected);
        assert_eq!(
            original.account,
            sigrund_core::host::Account::Name {
                name: "service".into()
            }
        );
        assert_eq!(hello.mode, "thin_csr");
    }
}
#[test]
fn unsupported_cross_domain_models_and_selectors_fail_locally() {
    for extra in [
        vec!["--full-only"],
        vec!["--export-csr", "/tmp/namespace.csr"],
        vec!["--binding-bundle", "/tmp/bundle.json"],
    ] {
        assert!(ClientArgs::parse(&args("registered:container-b", &extra)).is_err());
    }
    for target in [
        "self:1234",
        "process:0",
        "process:2147483648",
        "registered:",
        "registered:bad/id",
    ] {
        assert!(ClientArgs::parse(&args(target, &[])).is_err());
    }
}
