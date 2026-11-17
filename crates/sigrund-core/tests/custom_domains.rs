use sigrund_core::{host::Record, namespace::Contract, workload::RegisteredDomain};
fn domain() -> RegisteredDomain {
    RegisteredDomain {
        schema: "sigrund.selinux-domain.v1".into(),
        id: "acme-backup".into(),
        context: "system_u:system_r:acme_backup_job_t:s0".into(),
        summary: "Read database backup source and write archive".into(),
        enforcing: true,
        policy_change: "detect_and_terminate".into(),
        policy_sha256: "a".repeat(64),
    }
}
fn host() -> sigrund_core::host::Constraints {
    let value: toml::Value = toml::from_str(include_str!(
        "../../../config/workload-profiles.toml.example"
    ))
    .unwrap();
    let mut p: sigrund_core::host::Constraints =
        value["host_profiles"][0].clone().try_into().unwrap();
    p.workload = None;
    p.custom_domain = Some(domain());
    p.schema = "sigrund.host-custom-domain.v1".into();
    p.verify_exec_stop = true;
    p
}
fn namespace() -> sigrund_core::namespace::Constraints {
    let value: toml::Value = toml::from_str(include_str!(
        "../../../config/workload-profiles.toml.example"
    ))
    .unwrap();
    let mut p: sigrund_core::namespace::Constraints =
        value["namespace_profiles"][0].clone().try_into().unwrap();
    p.custom_domain = Some(domain());
    p.schema = "sigrund.constraints.namespace-custom-domain.v1".into();
    p.selinux.context = domain().context;
    p
}
#[test]
fn signed_domain_covers_description_context_policy_and_enforcement() {
    let p = host();
    p.validate().unwrap();
    let digest = p.sha256().unwrap();
    for change in ["description", "policy", "context"] {
        let mut changed = p.clone();
        let d = changed.custom_domain.as_mut().unwrap();
        match change {
            "description" => d.summary.push_str(" updated"),
            "policy" => d.policy_sha256 = "b".repeat(64),
            _ => d.context = "system_u:system_r:other_job_t:s0".into(),
        }
        assert_ne!(digest, changed.sha256().unwrap());
    }
    let mut bad = p.clone();
    bad.custom_domain.as_mut().unwrap().enforcing = false;
    assert!(bad.validate().is_err());
    let mut bad = p.clone();
    bad.workload = Some(sigrund_core::workload::Workload::Data);
    assert!(bad.validate().is_err());
    let mut bad = p.clone();
    bad.schema = "sigrund.host-constraints.v1".into();
    assert!(bad.validate().is_err());
    let mut bad = p;
    bad.verify_exec_stop = false;
    assert!(bad.validate().is_err());
}
#[test]
fn namespace_requires_exact_context_and_separate_schema() {
    let mut p = namespace();
    p.validate().unwrap();
    assert!(p.is_admin());
    assert!(p.executes());
    p.validate_execution_credentials(0, 0, &[]).unwrap();
    let digest = p.sha256().unwrap();
    p.custom_domain
        .as_mut()
        .unwrap()
        .summary
        .push_str(" updated");
    assert_ne!(digest, p.sha256().unwrap());
    p.selinux.context = "system_u:system_r:other_job_t:s0".into();
    assert!(p.validate().is_err());
    let mut p = namespace();
    p.schema = "sigrund.constraints.namespace-admin.v1".into();
    assert!(p.validate().is_err());
    let mut p = namespace();
    p.custom_domain = None;
    assert!(p.validate().is_err());
    let mut p = namespace();
    p.capabilities = vec!["CAP_SYS_ADMIN".into()];
    assert!(p.validate().is_err());
    let mut p = namespace();
    p.schema = "sigrund.constraints.namespace-custom-domain-direct.v1".into();
    p.executable_model = sigrund_core::executable::TrustModel::DigestDirect;
    p.validate().unwrap();
    assert!(p.is_admin_direct());
}
#[test]
fn reserved_domains_and_terminal_injection_are_rejected() {
    for context in [
        "system_u:system_r:sigrund_daemon_t:s0",
        "bad",
        "system_u:system_r:acme_t:s0\n",
    ] {
        let mut d = domain();
        d.context = context.into();
        assert!(d.validate().is_err());
    }
    let mut d = domain();
    d.summary = "forged\nreview".into();
    assert!(d.validate().is_err());
    let mut d = domain();
    d.policy_sha256 = "A".repeat(64);
    assert!(d.validate().is_err());
}

#[test]
fn authorizers_must_independently_allow_the_exact_custom_digest() {
    let p = host();
    let digest = p.sha256().unwrap();
    let rule = sigrund_core::host::ScopedRule {
        requester_uids: vec![1000],
        target_scope: "host".into(),
        target_uids: vec![0],
        target_gids: vec![0],
        supplementary_gids: vec![],
        profile_sha256: digest.clone(),
        cross_owner: true,
    };
    assert!(rule.permits(1000, 0, 0, &[], &digest));
    let mut changed = p;
    changed.custom_domain.as_mut().unwrap().policy_sha256 = "b".repeat(64);
    assert!(!rule.permits(1000, 0, 0, &[], &changed.sha256().unwrap()));
    assert!(!rule.permits(1001, 0, 0, &[], &digest));
    assert!(!rule.permits(1000, 42, 0, &[], &digest));
    let mut signer_rule = rule;
    signer_rule.profile_sha256 = "c".repeat(64);
    assert!(!signer_rule.permits(1000, 0, 0, &[], &digest));
}
