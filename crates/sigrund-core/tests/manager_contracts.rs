use sigrund_core::{
    manager::{PodmanEvidence, PodmanSelector},
    namespace::Contract,
};

const SELECTOR: &[u8] = include_bytes!("fixtures/manager/podman-selector.json");
const EVIDENCE: &[u8] = include_bytes!("fixtures/manager/podman-evidence.json");

#[test]
fn manager_context_binds_evidence_and_rejects_schema_downgrade() {
    use sigrund_core::namespace::ProcessContext;
    let bytes = include_bytes!("fixtures/manager/podman-context.json");
    let original = ProcessContext::parse(bytes).unwrap();
    let hashes: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/manager/sha256.json")).unwrap();
    assert_eq!(original.canonical().unwrap(), bytes);
    assert_eq!(original.sha256().unwrap(), hashes["podman-context"]);
    use sigrund_core::host::{ExecutionBinding, Record};
    let binding = ExecutionBinding::parse(include_bytes!(
        "fixtures/manager/podman-execution-binding.json"
    ))
    .unwrap();
    assert_eq!(
        binding.target_binding.context_sha256,
        original.sha256().unwrap()
    );
    assert_eq!(
        binding.sha256().unwrap(),
        hashes["podman-execution-binding"]
    );
    let mut changed = original.clone();
    changed.manager.as_mut().unwrap().configuration_sha256 = "ff".repeat(32);
    assert_ne!(changed.sha256().unwrap(), original.sha256().unwrap());
    changed = original.clone();
    changed.schema = "sigrund.process-context.v1".into();
    assert!(changed.validate().is_err());
    changed = original.clone();
    changed.manager = None;
    assert!(changed.validate().is_err());
    changed.schema = "sigrund.process-context.v1".into();
    assert!(changed.validate().is_ok());
    assert_ne!(changed.sha256().unwrap(), original.sha256().unwrap());
}

#[test]
fn independent_manager_vectors_are_canonical_and_bind_each_scope_and_generation() {
    let hashes: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/manager/sha256.json")).unwrap();
    let selector = PodmanSelector::parse(SELECTOR).unwrap();
    let evidence = PodmanEvidence::parse(EVIDENCE).unwrap();
    assert_eq!(selector.canonical().unwrap(), SELECTOR);
    assert_eq!(evidence.canonical().unwrap(), EVIDENCE);
    assert_eq!(selector.sha256().unwrap(), hashes["podman-selector"]);
    assert_eq!(evidence.sha256().unwrap(), hashes["podman-evidence"]);
    let original: serde_json::Value = serde_json::from_slice(EVIDENCE).unwrap();
    for (key, value) in [
        ("container_id", serde_json::json!("cd".repeat(32))),
        ("init_pid", serde_json::json!(4243)),
        ("init_start_ticks", serde_json::json!("9002")),
        ("configuration_sha256", serde_json::json!("ef".repeat(32))),
        ("endpoint_inode", serde_json::json!("1235")),
        ("peer_start_ticks", serde_json::json!("124")),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        let changed = PodmanEvidence::parse(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_ne!(
            changed.sha256().unwrap(),
            evidence.sha256().unwrap(),
            "{key}"
        );
    }
    let mut changed = evidence.clone();
    changed.selector.endpoint = "/run/other/podman.sock".into();
    assert_ne!(changed.sha256().unwrap(), evidence.sha256().unwrap());
    changed = evidence.clone();
    changed.selector.container_name = "other-b".into();
    assert_ne!(changed.sha256().unwrap(), evidence.sha256().unwrap());
}

#[test]
fn unsupported_scopes_and_ambiguous_records_fail_closed() {
    let original: serde_json::Value = serde_json::from_slice(SELECTOR).unwrap();
    for (key, value) in [
        ("schema", serde_json::json!("sigrund.podman-selector.v0")),
        ("owner_uid", serde_json::json!(1000)),
        ("manager_namespace", serde_json::json!("another-tenant")),
        ("endpoint", serde_json::json!("tcp://127.0.0.1:8080")),
        ("endpoint", serde_json::json!("/run/../podman.sock")),
        ("endpoint", serde_json::json!("/run//podman.sock")),
        ("container_name", serde_json::json!("../other")),
        ("container_name", serde_json::json!("-option")),
        ("container_name", serde_json::json!("")),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        assert!(
            PodmanSelector::parse(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "{changed}"
        );
    }
    let duplicate = String::from_utf8(SELECTOR.to_vec())
        .unwrap()
        .replace("\"owner_uid\":0", "\"owner_uid\":0,\"owner_uid\":1000");
    assert!(PodmanSelector::parse(duplicate.as_bytes()).is_err());
    assert!(PodmanEvidence::parse(&vec![b' '; 65_537]).is_err());
    let mut evidence = PodmanEvidence::parse(EVIDENCE).unwrap();
    evidence.init_start_ticks = "09001".into();
    assert!(evidence.validate().is_err());
    evidence = PodmanEvidence::parse(EVIDENCE).unwrap();
    evidence.started_at = "unsafe\nreview".into();
    assert!(evidence.validate().is_err());
}
