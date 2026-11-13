#[path = "namespace/signing.rs"]
mod signing;

use sigrund_core::namespace::{Acquisition, Constraints, Contract, Registration};

#[test]
fn production_records_match_independent_frozen_vectors() {
    let acquisition = include_bytes!("fixtures/namespace/acquisition.json");
    let constraints = include_bytes!("fixtures/namespace/constraints.json");
    let hashes: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/namespace/sha256.json")).unwrap();
    let a = Acquisition::parse(acquisition).unwrap();
    let c = Constraints::parse(constraints).unwrap();
    assert_eq!(a.canonical().unwrap(), acquisition);
    assert_eq!(c.canonical().unwrap(), constraints);
    assert_eq!(a.sha256().unwrap(), hashes["acquisition"]);
    assert_eq!(c.sha256().unwrap(), hashes["constraints"]);
}

#[test]
fn registration_and_acquisition_reject_ambiguous_records() {
    let raw = include_bytes!("fixtures/namespace/acquisition.json");
    let mut value: serde_json::Value = serde_json::from_slice(raw).unwrap();
    value["pid"] = 0.into();
    assert!(Acquisition::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    value = serde_json::from_slice(raw).unwrap();
    value["lifecycle"]["registration_revision"] = serde_json::Value::Null;
    assert!(Acquisition::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(
        Registration::parse(br#"{"schema":"sigrund.registration.phase0.v1","id":"B","id":"C"}"#)
            .is_err()
    );
    assert!(Registration::parse(br#"{"schema":"sigrund.registration.phase0.v1","id":"B","revision":"00","daemon_pid":1,"owner_uid":1000,"profile_sha256":"00","extra":true}"#).is_err());
}

#[test]
fn process_review_binds_selector_generation_profile_and_exact_csr() {
    use sigrund_core::{
        crypto::sha256_hex,
        host::{Record, Selector},
        namespace::ProcessReview,
        warrant::{Csr, Warrant},
    };
    let acquisition =
        Acquisition::parse(include_bytes!("fixtures/namespace/acquisition.json")).unwrap();
    let constraints =
        Constraints::parse(include_bytes!("fixtures/namespace/constraints.json")).unwrap();
    let registration = Registration {
        schema: "sigrund.registration.phase0.v1".into(),
        id: acquisition.lifecycle.registration_id.clone().unwrap(),
        revision: acquisition.lifecycle.registration_revision.clone().unwrap(),
        daemon_pid: acquisition.pid,
        owner_uid: 1000,
        profile_sha256: constraints.sha256().unwrap(),
    };
    let mut review = ProcessReview {
        manager: None,
        schema: "sigrund.process-review.v1".into(),
        exec_id: "0192d8f4-0000-7000-8000-000000000004".into(),
        csr_sha256: "00".repeat(32),
        executable_roots: std::collections::BTreeMap::from([(
            "/usr/bin".into(),
            acquisition.root.clone(),
        )]),
        prepared_cwd: acquisition.cwd.clone(),
        prepared_executable: acquisition.root.clone(),
        acquisition,
        authenticated_source: None,
        registration: Some(registration),
        constraints,
    };
    let binding = review.binding().unwrap();
    let mut w = Warrant::parse_canonical(include_bytes!("fixtures/v3-host/warrant.json")).unwrap();
    w.intent.target = Selector::Registered {
        id: review.registration.as_ref().unwrap().id.clone(),
    };
    w.intent.security_profile = review.constraints.profile_id.clone();
    w.intent.execution_context.capabilities = review.constraints.capabilities.clone();
    w.intent_sha256 = w.intent.sha256().unwrap();
    w.execution_context.capabilities = review.constraints.capabilities.clone();
    w.execution_context.post_exec_capabilities = Some(
        sigrund_core::executable::CapabilitySets::ordinary(&w.execution_context.capabilities),
    );
    w.target_binding = binding.target_binding;
    w.security_constraints = binding.security_constraints;
    w.command.executable_trust = Some(sigrund_core::executable::ExecutableTrust::DigestMemfd {
        sha256: "11".repeat(32),
    });
    w.request_origin = "daemon_expanded_thin".into();
    w.approval_exec_id = Some(review.exec_id.clone());
    let csr = Csr::new(w.clone()).unwrap();
    review.csr_sha256 = sha256_hex(csr.as_bytes());
    review.verify_csr(&csr).unwrap();
    let display = review.render(&csr).unwrap();
    assert!(display.contains("verified_acquisition"));
    assert!(display.contains("Private namespace review"));
    {
        let mut managed = review.clone();
        managed.schema = "sigrund.podman-review.v1".into();
        managed.manager = Some(
            sigrund_core::manager::PodmanEvidence::parse(include_bytes!(
                "fixtures/manager/podman-evidence.json"
            ))
            .unwrap(),
        );
        let binding = managed.binding().unwrap();
        let mut payload = w.clone();
        payload.target_binding = binding.target_binding;
        payload.security_constraints = binding.security_constraints;
        let managed_csr = Csr::new(payload).unwrap();
        managed.csr_sha256 = sha256_hex(managed_csr.as_bytes());
        let display: serde_json::Value =
            serde_json::from_str(&managed.render(&managed_csr).unwrap()).unwrap();
        assert_eq!(
            display["manager"]["evidence"],
            serde_json::to_value(managed.manager.as_ref().unwrap()).unwrap()
        );
        assert!(
            display["manager"]["loss_contract"]
                .as_str()
                .unwrap()
                .contains("fresh acquisition")
        );
        managed.manager.as_mut().unwrap().container_id = "ff".repeat(32);
        assert!(managed.render(&managed_csr).is_err());
    }
    {
        let mut own = review.clone();
        own.schema = "sigrund.self-review.v1".into();
        own.registration = None;
        own.authenticated_source = Some(sigrund_core::namespace::ConnectorObservation {
            pid: own.acquisition.pid,
            uid: own.acquisition.anchor.host_uid,
            gid: own.acquisition.anchor.host_gid,
            supplementary_gids: own.acquisition.anchor.host_groups.clone(),
            security_label: None,
        });
        own.acquisition.lifecycle.registration_id = None;
        own.acquisition.lifecycle.registration_revision = None;
        own.constraints = Constraints::parse(include_bytes!(
            "fixtures/namespace/experimental-constraints.json"
        ))
        .unwrap();
        let binding = own.binding().unwrap();
        let mut payload = w.clone();
        payload.intent.target = Selector::Self_ {};
        payload.intent.security_profile = own.constraints.profile_id.clone();
        payload.intent_sha256 = payload.intent.sha256().unwrap();
        payload.target_binding = binding.target_binding;
        payload.security_constraints = binding.security_constraints;
        let own_csr = Csr::new(payload.clone()).unwrap();
        own.csr_sha256 = sha256_hex(own_csr.as_bytes());
        own.verify_csr(&own_csr).unwrap();
        assert!(
            own.render(&own_csr)
                .unwrap()
                .contains("Authenticated connector")
        );
        {
            let mut admin = own.clone();
            admin.constraints.schema = "sigrund.constraints.namespace-admin.v1".into();
            admin.constraints.profile_id = "namespace-admin-v1".into();
            admin.constraints.securebits = 0x2f;
            let binding = admin.binding().unwrap();
            let mut root = payload.clone();
            root.intent.security_profile = admin.constraints.profile_id.clone();
            root.intent.account = sigrund_core::host::Account::Numeric {
                uid: 0,
                gid: 0,
                supplementary_gids: vec![104],
            };
            root.execution_context.target_uid = 0;
            root.execution_context.target_gid = 0;
            root.execution_context.supplementary_gids = vec![104];
            root.intent_sha256 = root.intent.sha256().unwrap();
            root.target_binding = binding.target_binding;
            root.security_constraints = binding.security_constraints;
            let root_csr = Csr::new(root).unwrap();
            admin.csr_sha256 = sha256_hex(root_csr.as_bytes());
            admin.verify_csr(&root_csr).unwrap();
            assert!(
                admin
                    .render(&root_csr)
                    .unwrap()
                    .contains("container containment is best effort")
            );
            admin.constraints = own.constraints.clone();
            assert!(admin.verify_csr(&root_csr).is_err());
        }
        let verified = own.clone();
        for mutation in 0..7 {
            let mut substituted = verified.clone();
            let source = substituted.authenticated_source.as_mut().unwrap();
            match mutation {
                0 => source.pid += 1,
                1 => source.uid += 1,
                2 => source.gid += 1,
                3 => source.supplementary_gids = vec![104],
                4 => source.security_label = Some("substituted-label".into()),
                5 => substituted.schema = "sigrund.process-review.v1".into(),
                6 => {
                    substituted.acquisition.daemon_epoch =
                        "0192d8f4-0000-7000-8000-000000000009".into()
                }
                _ => unreachable!(),
            }
            assert!(
                substituted.verify_csr(&own_csr).is_err(),
                "source mutation {mutation}"
            );
        }
        let mut missing_label = serde_json::to_value(&own).unwrap();
        missing_label["authenticated_source"]
            .as_object_mut()
            .unwrap()
            .remove("security_label");
        assert!(ProcessReview::parse(&serde_json::to_vec(&missing_label).unwrap()).is_err());
        let mut encoded = serde_json::to_value(&own).unwrap();
        encoded.as_object_mut().unwrap().remove("registration");
        assert!(ProcessReview::parse(&serde_json::to_vec(&encoded).unwrap()).is_err());
        payload.requester_uid += 2;
        let forged = Csr::new(payload).unwrap();
        own.csr_sha256 = sha256_hex(forged.as_bytes());
        assert!(own.verify_csr(&forged).is_err());
        own.registration = review.registration.clone();
        assert!(own.validate().is_err());
    }
    let original = review.clone();
    review.registration.as_mut().unwrap().revision = "ff".repeat(32);
    assert!(review.render(&csr).is_err());
    review = original.clone();
    review.acquisition.instance_id = "0192d8f4-0000-7000-8000-000000000005".into();
    assert!(review.render(&csr).is_err());
    review = original.clone();
    review.executable_roots.get_mut("/usr/bin").unwrap().inode = "9999".into();
    assert!(review.render(&csr).is_err());
    review = original;
    w.intent.target = Selector::Host {};
    w.intent_sha256 = w.intent.sha256().unwrap();
    assert!(Csr::new(w).is_err());
    review.csr_sha256 = "00".repeat(32);
    assert!(review.render(&csr).is_err());
}

#[test]
fn experimental_profile_requires_a_distinct_exact_contract() {
    use sigrund_core::{executable::TrustModel, namespace::Seccomp};
    let historical =
        Constraints::parse(include_bytes!("fixtures/namespace/constraints.json")).unwrap();
    let mut profile = historical.clone();
    profile.schema = "sigrund.constraints.namespace-experimental.v1".into();
    profile.profile_id = "namespace-experimental-v1".into();
    profile.selinux.context.clear();
    profile.selinux.enforcing = false;
    profile.selinux.policy_change = "unmanaged".into();
    profile.seccomp = Seccomp::None {};
    profile.validate().unwrap();
    assert_ne!(profile.sha256().unwrap(), historical.sha256().unwrap());
    assert_eq!(
        Constraints::parse(&profile.canonical().unwrap())
            .unwrap()
            .sha256()
            .unwrap(),
        profile.sha256().unwrap()
    );
    let vector = include_bytes!("fixtures/namespace/experimental-constraints.json");
    assert_eq!(profile.canonical().unwrap(), vector);
    // Independent Python sorted-key ASCII JSON and hashlib SHA-256 vector.
    assert_eq!(
        profile.sha256().unwrap(),
        "866b2ad85e718cb1ba73527b5c088d229006ef6a24071f4e573b76ff52b1ea56"
    );
    let valid = profile.clone();
    for mutation in 0..9 {
        profile = valid.clone();
        match mutation {
            0 => profile.schema = historical.schema.clone(),
            1 => profile.profile_id = historical.profile_id.clone(),
            2 => profile.selinux.enforcing = true,
            3 => profile.selinux.context = historical.selinux.context.clone(),
            4 => profile.selinux.policy_change = "reject".into(),
            5 => profile.seccomp = historical.seccomp.clone(),
            6 => profile.capabilities = vec!["CAP_NET_BIND_SERVICE".into()],
            7 => profile.executable_model = TrustModel::DigestDirect,
            8 => profile.verify_exec_stop = false,
            _ => unreachable!(),
        }
        assert!(profile.validate().is_err(), "accepted mutation {mutation}");
    }
    let mut old = historical;
    old.selinux.enforcing = false;
    assert!(old.validate().is_err());
}

#[test]
fn selinux_profile_binds_complete_confinement_and_independent_digests() {
    use sigrund_core::host::{ExecutionBinding, Record};
    let bytes = include_bytes!("fixtures/namespace/selinux-constraints.json");
    let profile = Constraints::parse(bytes).unwrap();
    assert!(profile.is_production() && profile.executes());
    assert_eq!(profile.canonical().unwrap(), bytes);
    let hashes: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/namespace/selinux-sha256.json")).unwrap();
    assert_eq!(profile.sha256().unwrap(), hashes["constraints"]);
    let binding = ExecutionBinding::parse(include_bytes!(
        "fixtures/namespace/selinux-execution-binding.json"
    ))
    .unwrap();
    assert_eq!(
        binding.security_constraints.profile_sha256,
        profile.sha256().unwrap()
    );
    assert_eq!(binding.sha256().unwrap(), hashes["execution_binding"]);
    let raw: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    for (pointer, value) in [
        (
            "/schema",
            serde_json::json!("sigrund.constraints.namespace-selinux.v2"),
        ),
        (
            "/profile_id",
            serde_json::json!("namespace-experimental-v1"),
        ),
        ("/selinux/enforcing", serde_json::json!(false)),
        (
            "/selinux/context",
            serde_json::json!("system_u:system_r:sigrund_workload_t:s0"),
        ),
        ("/selinux/executable_context", serde_json::Value::Null),
        ("/selinux/policy_change", serde_json::json!("unmanaged")),
        ("/seccomp/syscalls", serde_json::json!([39])),
        ("/seccomp/errno", serde_json::json!(1)),
        ("/executable_model", serde_json::json!("digest_direct")),
        ("/no_new_privs", serde_json::json!(false)),
        ("/verify_exec_stop", serde_json::json!(false)),
    ] {
        let mut substituted = raw.clone();
        *substituted.pointer_mut(pointer).unwrap() = value;
        assert!(
            Constraints::parse(&serde_json::to_vec(&substituted).unwrap()).is_err(),
            "{pointer}"
        );
    }
    let mut old: serde_json::Value = serde_json::from_slice(include_bytes!(
        "fixtures/namespace/experimental-constraints.json"
    ))
    .unwrap();
    old["selinux"]["executable_context"] = serde_json::Value::Null;
    assert!(Constraints::parse(&serde_json::to_vec(&old).unwrap()).is_err());
}

#[test]
fn admin_constraints_preserve_host_capability_policy_and_old_profiles() {
    use sigrund_core::host::{Constraints as HostConstraints, Record};
    let old = Constraints::parse(include_bytes!(
        "fixtures/namespace/experimental-constraints.json"
    ))
    .unwrap();
    assert!(old.validate_execution_credentials(0, 0, &[]).is_err());
    assert!(old.validate_execution_credentials(33, 33, &[104]).is_err());
    let mut admin = old.clone();
    admin.schema = "sigrund.constraints.namespace-admin.v1".into();
    admin.profile_id = "namespace-admin-v1".into();
    admin.securebits = 0x2f;
    admin.validate().unwrap();
    assert!(admin.executes());
    admin
        .validate_execution_credentials(0, 0, &[33, 104])
        .unwrap();
    assert!(
        admin
            .validate_execution_credentials(u32::MAX, 0, &[])
            .is_err()
    );
    assert!(
        admin
            .validate_execution_credentials(0, 0, &[104, 33])
            .is_err()
    );
    let mut host =
        HostConstraints::parse(include_bytes!("fixtures/v3-host/constraints.json")).unwrap();
    for caps in [
        vec![],
        vec!["CAP_NET_BIND_SERVICE"],
        vec!["CAP_CHOWN", "CAP_SETUID"],
        vec!["CAP_SYS_ADMIN"],
        vec!["CAP_FAKE"],
        vec!["CAP_CHOWN", "CAP_CHOWN"],
        vec!["CAP_SETUID", "CAP_CHOWN"],
    ] {
        admin.capabilities = caps.iter().map(|c| (*c).to_owned()).collect();
        host.capabilities = admin.capabilities.clone();
        assert_eq!(
            admin.validate().is_ok(),
            host.validate().is_ok(),
            "{caps:?}"
        );
    }
    admin.capabilities.clear();
    for mutation in 0..5 {
        let mut bad = admin.clone();
        match mutation {
            0 => bad.securebits = 15,
            1 => bad.no_new_privs = false,
            2 => bad.selinux.enforcing = true,
            3 => bad.executable_model = sigrund_core::executable::TrustModel::DigestDirect,
            4 => bad.private_mount = false,
            _ => unreachable!(),
        }
        assert!(bad.validate().is_err());
    }
    assert_ne!(admin.sha256().unwrap(), old.sha256().unwrap());
}

#[test]
fn admin_configuration_examples_bind_the_canonical_profile() {
    let example: toml::Value = toml::from_str(include_str!(
        "../../../config/namespace-admin-profiles.toml.example"
    ))
    .unwrap();
    let profile: Constraints = example["namespace_profiles"][0].clone().try_into().unwrap();
    let frozen = include_bytes!("fixtures/namespace/admin-constraints.json");
    assert_eq!(profile.canonical().unwrap(), frozen);
    let signers: toml::Value = toml::from_str(include_str!(
        "../../../config/namespace-admin-signers.toml.example"
    ))
    .unwrap();
    for rules in [
        example["namespace_rules"].as_array().unwrap(),
        signers["signers"]["namespace_rules"].as_array().unwrap(),
    ] {
        for value in rules {
            let rule: sigrund_core::namespace::ScopedRule = value.clone().try_into().unwrap();
            rule.validate().unwrap();
            assert_eq!(rule.profile_sha256, profile.sha256().unwrap());
            assert!(rule.permits(
                1001,
                &rule.target_scope,
                0,
                0,
                &[],
                &profile.sha256().unwrap(),
                1001
            ));
            assert!(!rule.permits(
                1001,
                &rule.target_scope,
                0,
                0,
                &[104],
                &profile.sha256().unwrap(),
                1001
            ));
        }
    }
}
