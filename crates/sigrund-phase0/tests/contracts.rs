use serde_json::{Value, json};
use sigrund_phase0::{contracts::*, selection};

const ACQUISITION: &[u8] = include_bytes!("fixtures/acquisition.json");
const CONSTRAINTS: &[u8] = include_bytes!("fixtures/constraints.json");
const INTENT: &[u8] = include_bytes!("fixtures/intent.json");
const BUNDLE: &[u8] = include_bytes!("fixtures/bundle.json");
fn hashes() -> Value {
    serde_json::from_slice(include_bytes!("fixtures/sha256.json")).unwrap()
}
fn args(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn independent_ascii_jcs_vectors_preserve_large_kernel_ids_and_bindings() {
    let acquisition = Acquisition::parse(ACQUISITION).unwrap();
    let constraints = Constraints::parse(CONSTRAINTS).unwrap();
    let intent = Intent::parse(INTENT).unwrap();
    let bundle = BindingBundle::parse(BUNDLE).unwrap();
    assert_eq!(acquisition.canonical().unwrap(), ACQUISITION);
    assert_eq!(constraints.canonical().unwrap(), CONSTRAINTS);
    assert_eq!(intent.canonical().unwrap(), INTENT);
    assert_eq!(bundle.canonical().unwrap(), BUNDLE);
    let expected = hashes();
    for (key, digest) in [
        ("acquisition", acquisition.sha256().unwrap()),
        ("constraints", constraints.sha256().unwrap()),
        ("intent", intent.sha256().unwrap()),
        ("bundle", bundle.sha256().unwrap()),
    ] {
        assert_eq!(digest, expected[key]);
    }
    assert_eq!(
        bundle.target_binding.context_sha256,
        acquisition.sha256().unwrap()
    );
    assert_eq!(acquisition.root.mount_id, "9007199254740993");
    assert_eq!(acquisition.root.inode, u64::MAX.to_string());
    let description =
        approval_description(&bundle, &intent, &intent.account, &acquisition).unwrap();
    let display: Value = serde_json::from_str(&description).unwrap();
    assert_eq!(
        display["security_constraints"],
        serde_json::to_value(&constraints).unwrap()
    );
    assert_eq!(
        display["target_binding"],
        serde_json::to_value(&bundle.target_binding).unwrap()
    );
    assert_eq!(
        display["resolved_numeric_account"],
        serde_json::to_value(&intent.account).unwrap()
    );
    assert_eq!(
        display["verified_acquisition"]["mappings"],
        serde_json::to_value(&acquisition.mappings).unwrap()
    );
    let mut stale = acquisition.clone();
    stale.instance_id = "0192d8f4-0000-7000-8000-000000000003".into();
    assert!(approval_description(&bundle, &intent, &intent.account, &stale).is_err());
}

#[test]
fn strict_records_reject_ambiguous_unbounded_and_unsupported_contracts() {
    let mut value: Value = serde_json::from_slice(ACQUISITION).unwrap();
    let original = value.clone();
    for (pointer, replacement) in [
        ("/pid", json!(0)),
        ("/start_ticks", json!("01")),
        ("/root/inode", json!(18446744073709551615u64)),
        ("/root/mount_id", json!("18446744073709551616")),
        (
            "/daemon_epoch",
            json!("12c29c35-9163-4184-bb1d-41b907132c48"),
        ),
        ("/lifecycle/anchor_required", json!(false)),
        ("/lifecycle/resolver", json!("docker")),
        ("/mappings/0/userns_inode", json!("123")),
        ("/mappings/0/uid/1/outside", json!(1000)),
    ] {
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            Acquisition::parse(&serde_json::to_vec(&value).unwrap()).is_err(),
            "accepted {pointer}"
        );
        value = original.clone();
    }
    value["surprise"] = json!(true);
    assert!(Acquisition::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(Acquisition::parse(&vec![b' '; MAX_RECORD_BYTES + 1]).is_err());
    let duplicate =
        String::from_utf8(INTENT.to_vec())
            .unwrap()
            .replacen("{", "{\"account\":{},", 1);
    assert!(Intent::parse(duplicate.as_bytes()).is_err());
    for object in [
        json!({"kind":"process","pid":42,"pid_scope":"caller"}),
        json!({"kind":"self","pid":42}),
        json!({"kind":"registered","id":"../B"}),
        json!({"kind":"manager","name":"B"}),
    ] {
        let mut intent: Value = serde_json::from_slice(INTENT).unwrap();
        intent["target"] = object;
        assert!(Intent::parse(&serde_json::to_vec(&intent).unwrap()).is_err());
    }
    let mut constraints: Value = serde_json::from_slice(CONSTRAINTS).unwrap();
    let original = constraints.clone();
    for (pointer, replacement) in [
        ("/no_new_privs", json!(false)),
        ("/verify_exec_stop", json!(false)),
        ("/selinux/enforcing", json!(false)),
        ("/apparmor", json!("complain")),
        ("/seccomp/audit_arch", json!(0x40000003u32)),
        ("/capabilities", json!(["CAP_SYS_ADMIN"])),
        ("/seccomp/syscalls", json!([110, 110])),
    ] {
        *constraints.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            Constraints::parse(&serde_json::to_vec(&constraints).unwrap()).is_err(),
            "accepted {pointer}"
        );
        constraints = original.clone();
    }
}

#[test]
fn context_profile_epoch_and_instance_substitution_change_bound_bytes() {
    let acquisition = Acquisition::parse(ACQUISITION).unwrap();
    let digest = acquisition.sha256().unwrap();
    for mut changed in [
        acquisition.clone(),
        acquisition.clone(),
        acquisition.clone(),
        acquisition.clone(),
    ]
    .into_iter()
    .enumerate()
    {
        match changed.0 {
            0 => changed.1.instance_id = "0192d8f4-0000-7000-8000-000000000003".into(),
            1 => changed.1.daemon_epoch = "0192d8f4-0000-7000-8000-000000000004".into(),
            2 => changed.1.root.inode = "42".into(),
            _ => changed.1.lifecycle.registration_revision = Some("cd".repeat(32)),
        }
        assert_ne!(changed.1.sha256().unwrap(), digest);
    }
    let mut bundle: Value = serde_json::from_slice(BUNDLE).unwrap();
    bundle["constraints"]["selinux"]["context"] =
        json!("unconfined_u:unconfined_r:sigrund_phase0_t:s0:c3");
    assert!(BindingBundle::parse(&serde_json::to_vec(&bundle).unwrap()).is_err());
}

#[test]
fn composed_mappings_distinguish_numeric_ids_and_reject_holes() {
    let acquisition = Acquisition::parse(ACQUISITION).unwrap();
    let outer = acquisition.mappings[0].uid.clone();
    assert_eq!(compose(0, std::slice::from_ref(&outer)).unwrap(), 1000);
    assert_eq!(compose(1001, std::slice::from_ref(&outer)).unwrap(), 101000);
    let inner = vec![Extent {
        inside: 0,
        outside: 1001,
        count: 1,
    }];
    assert_eq!(compose(0, &[inner.clone(), outer.clone()]).unwrap(), 101000);
    assert!(compose(1, &[inner, outer.clone()]).is_err());
    assert!(compose(65536, &[outer]).is_err());
    assert!(
        compose(
            u32::MAX,
            &[vec![Extent {
                inside: 0,
                outside: 0,
                count: u32::MAX
            }]]
        )
        .is_err()
    );
    assert!(
        compose(
            0,
            &[vec![Extent {
                inside: 0,
                outside: u32::MAX,
                count: 2
            }]]
        )
        .is_err()
    );
}

#[test]
fn requester_and_signer_ceilings_are_scoped_and_cross_owner_is_explicit() {
    let profile = Constraints::parse(CONSTRAINTS).unwrap().sha256().unwrap();
    let mut daemon = ScopedRule {
        requester_uids: vec![1000],
        target_scope: "registered:B".into(),
        target_uids: vec![0, 1001],
        target_gids: vec![1001],
        supplementary_gids: vec![104],
        profile_sha256: profile.clone(),
        cross_owner: false,
    };
    assert!(!daemon.permits(1000, "registered:B", 0, 1001, &[], &profile, 2000));
    daemon.cross_owner = true;
    let signer = ScopedRule {
        cross_owner: false,
        ..daemon.clone()
    };
    assert!(daemon.permits(1000, "registered:B", 0, 1001, &[], &profile, 2000));
    assert!(!signer.permits(1000, "registered:B", 0, 1001, &[], &profile, 2000));
    assert!(!daemon.permits(1000, "host", 0, 1001, &[], &profile, 1000));
    assert!(!daemon.permits(1000, "registered:C", 0, 1001, &[], &profile, 1000));
    assert!(!daemon.permits(1000, "registered:B", 0, 1001, &[0], &profile, 1000));
    assert!(!daemon.permits(1000, "registered:B", 0, 1001, &[], &"ab".repeat(32), 1000));
    Limits::default().validate().unwrap();
    let limits = Limits {
        helpers_global: 17,
        ..Limits::default()
    };
    assert!(limits.validate().is_err());
}

#[test]
fn selection_and_management_grammar_require_explicit_scopes_accounts_and_profiles() {
    let selected = selection::parse(&args(
        "--target self --target-uid 0 --target-gid 0 --security-profile minimal",
    ))
    .unwrap();
    assert!(matches!(selected.target, Selector::Self_ {}));
    selection::parse(&args(
        "--target process:42 --account root --security-profile minimal",
    ))
    .unwrap();
    selection::parse(&args("--target registered:B --target-uid 1001 --target-gid 1001 --supplementary-gids 104,33 --security-profile minimal")).unwrap();
    for text in [
        "--target self --account root",
        "--target B --account root --security-profile minimal",
        "--target host --account root --target-uid 0 --security-profile minimal",
        "--target process:0 --account root --security-profile minimal",
        "--target host --target host --account root --security-profile minimal",
        "--target host --target-uid 0 --target-gid 0 --supplementary-gids 33,33 --security-profile minimal",
    ] {
        assert!(selection::parse(&args(text)).is_err(), "accepted {text}");
    }
    assert!(
        selection::management(&args(
            "target register B --pid 42 --owner-uid 1000 --security-profile minimal"
        ))
        .is_ok()
    );
    assert!(selection::management(&args("target revoke B")).is_ok());
    assert!(selection::management(&args("target export-binding B --output /tmp/B.json")).is_ok());
    assert!(
        selection::management(&args("target export-binding B --output /tmp/../B.json")).is_err()
    );
    assert!(
        selection::management(&args(
            "target register B --pid 0 --owner-uid 1000 --security-profile minimal"
        ))
        .is_err()
    );
}
