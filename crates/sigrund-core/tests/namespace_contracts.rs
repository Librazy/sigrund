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
        registration,
        constraints,
    };
    let binding = review.binding().unwrap();
    let mut w = Warrant::parse_canonical(include_bytes!("fixtures/v3-host/warrant.json")).unwrap();
    w.intent.target = Selector::Registered {
        id: review.registration.id.clone(),
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
    let original = review.clone();
    review.registration.revision = "ff".repeat(32);
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
