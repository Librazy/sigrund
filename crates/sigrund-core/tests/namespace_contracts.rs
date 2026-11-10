use sigrund_core::namespace::{Acquisition, Constraints, Contract, Registration};

#[test]
fn production_records_match_independent_frozen_vectors() {
    let acquisition = include_bytes!("../../sigrund-phase0/tests/fixtures/acquisition.json");
    let constraints = include_bytes!("../../sigrund-phase0/tests/fixtures/constraints.json");
    let hashes: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../sigrund-phase0/tests/fixtures/sha256.json"
    ))
    .unwrap();
    let a = Acquisition::parse(acquisition).unwrap();
    let c = Constraints::parse(constraints).unwrap();
    assert_eq!(a.canonical().unwrap(), acquisition);
    assert_eq!(c.canonical().unwrap(), constraints);
    assert_eq!(a.sha256().unwrap(), hashes["acquisition"]);
    assert_eq!(c.sha256().unwrap(), hashes["constraints"]);
}

#[test]
fn registration_and_acquisition_reject_ambiguous_records() {
    let raw = include_bytes!("../../sigrund-phase0/tests/fixtures/acquisition.json");
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
    let acquisition = Acquisition::parse(include_bytes!(
        "../../sigrund-phase0/tests/fixtures/acquisition.json"
    ))
    .unwrap();
    let constraints = Constraints::parse(include_bytes!(
        "../../sigrund-phase0/tests/fixtures/constraints.json"
    ))
    .unwrap();
    let registration = Registration {
        schema: "sigrund.registration.phase0.v1".into(),
        id: acquisition.lifecycle.registration_id.clone().unwrap(),
        revision: acquisition.lifecycle.registration_revision.clone().unwrap(),
        daemon_pid: acquisition.pid,
        owner_uid: 1000,
        profile_sha256: constraints.sha256().unwrap(),
    };
    let mut review = ProcessReview {
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
    assert!(display.contains("Phase 2 private review"));
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
            "fixtures/v3-namespace/experimental-constraints.json"
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
    let historical = Constraints::parse(include_bytes!(
        "../../sigrund-phase0/tests/fixtures/constraints.json"
    ))
    .unwrap();
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
    let vector = include_bytes!("fixtures/v3-namespace/experimental-constraints.json");
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
    let bytes = include_bytes!("fixtures/v3-namespace/selinux-constraints.json");
    let profile = Constraints::parse(bytes).unwrap();
    assert!(profile.is_production() && profile.executes());
    assert_eq!(profile.canonical().unwrap(), bytes);
    let hashes: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/v3-namespace/selinux-sha256.json"))
            .unwrap();
    assert_eq!(profile.sha256().unwrap(), hashes["constraints"]);
    let binding = ExecutionBinding::parse(include_bytes!(
        "fixtures/v3-namespace/selinux-execution-binding.json"
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
        "fixtures/v3-namespace/experimental-constraints.json"
    ))
    .unwrap();
    old["selinux"]["executable_context"] = serde_json::Value::Null;
    assert!(Constraints::parse(&serde_json::to_vec(&old).unwrap()).is_err());
}
