use base64::{Engine as _, engine::general_purpose::STANDARD};
use sigrund_core::{config::DaemonConfig, host::Record, namespace::Contract, workload::Workload};

fn config() -> DaemonConfig {
    let source = include_str!("../../../config/sigrund.toml.example")
        .replace(
            "job_memory_max_bytes = 268435456",
            "job_memory_max_bytes = 1073741824",
        )
        .replace(
            "<strict-padded-base64-32-byte-ed25519-key>",
            &STANDARD.encode([1; 32]),
        );
    DaemonConfig::from_toml(
        format!(
            "{source}\n{}",
            include_str!("../../../config/workload-profiles.toml.example")
        )
        .as_bytes(),
    )
    .unwrap()
}

#[test]
fn shipped_tiers_have_exact_independently_authorized_digests() {
    let config = config();
    let signer_source = include_str!("../../../config/signers.toml.example");
    let source = format!(
        "{signer_source}\n{}",
        include_str!("../../../config/workload-signers.toml.example")
    );
    let signers = sigrund_core::config::SignerPolicyFile::from_toml(source.as_bytes()).unwrap();
    // Key validation is separately covered by the configured signer tests.
    for host in config
        .host_profiles
        .iter()
        .filter(|profile| profile.workload.is_some())
    {
        let digest = host.sha256().unwrap();
        assert!(
            config
                .host_rules
                .iter()
                .any(|rule| rule.profile_sha256 == digest)
        );
        assert!(
            signers.signers[0]
                .host_rules
                .iter()
                .any(|rule| rule.profile_sha256 == digest)
        );
        let mut changed = host.clone();
        changed.memory_max *= 2;
        assert_ne!(digest, changed.sha256().unwrap());
    }
    for ns in &config.namespace_profiles {
        let digest = ns.sha256().unwrap();
        assert_eq!(
            config
                .namespace_rules
                .iter()
                .filter(|rule| rule.profile_sha256 == digest)
                .count(),
            2
        );
        assert_eq!(
            signers.signers[0]
                .namespace_rules
                .iter()
                .filter(|rule| rule.profile_sha256 == digest)
                .count(),
            2
        );
        let mut changed = ns.clone();
        changed.selinux.context = Workload::Data.context().into();
        if ns.workload() == Some(Workload::Root) {
            assert!(changed.validate().is_err());
        } else if ns.workload() != Some(Workload::Data) {
            assert_ne!(digest, changed.sha256().unwrap());
        }
    }
    assert_eq!(config.host_profiles.len(), 5);
    assert_eq!(config.namespace_profiles.len(), 4);
}

#[test]
fn root_authority_requires_full_caps_root_uid_and_explicit_selinux() {
    let config = config();
    let host = config
        .host_profiles
        .iter()
        .find(|p| p.workload == Some(Workload::Root))
        .unwrap();
    let ns = config
        .namespace_profiles
        .iter()
        .find(|p| p.workload() == Some(Workload::Root))
        .unwrap();
    assert_eq!(host.capabilities, Workload::root_capabilities());
    assert_eq!(host.capabilities.len(), 41);
    assert!(host.validate_execution_uid(0).is_ok());
    assert!(host.validate_execution_uid(1000).is_err());
    assert!(ns.validate_execution_credentials(0, 0, &[]).is_ok());
    assert!(ns.validate_execution_credentials(1000, 1000, &[]).is_err());
    let mut bad = host.clone();
    bad.capabilities.pop();
    assert!(bad.validate().is_err());
    let mut bad = host.clone();
    bad.workload = Some(Workload::Maintenance);
    assert!(bad.validate().is_err());
    let mut bad = ns.clone();
    bad.selinux.enforcing = false;
    assert!(bad.validate().is_err());
    let mut bad = ns.clone();
    bad.selinux.context = "system_u:system_r:unconfined_t:s0".into();
    assert!(bad.validate().is_err());
    let mut bad = ns.clone();
    bad.selinux.policy_change = "unmanaged".into();
    assert!(bad.validate().is_err());
}

#[test]
fn lower_tier_scopes_never_authorize_root_or_changed_constraints() {
    let config = config();
    let data = config
        .host_profiles
        .iter()
        .find(|p| p.workload == Some(Workload::Data))
        .unwrap();
    let root = config
        .host_profiles
        .iter()
        .find(|p| p.workload == Some(Workload::Root))
        .unwrap();
    let rule = config
        .host_rules
        .iter()
        .find(|r| r.profile_sha256 == data.sha256().unwrap())
        .unwrap();
    assert!(rule.permits(1001, 0, 0, &[], &data.sha256().unwrap()));
    assert!(!rule.permits(1001, 0, 0, &[], &root.sha256().unwrap()));
    let mut changed = data.clone();
    changed.memory_max *= 2;
    assert!(!rule.permits(1001, 0, 0, &[], &changed.sha256().unwrap()));
    let root = config
        .namespace_profiles
        .iter()
        .find(|p| p.workload() == Some(Workload::Root))
        .unwrap();
    let data = config
        .namespace_profiles
        .iter()
        .find(|p| p.workload() == Some(Workload::Data))
        .unwrap();
    let rule = config
        .namespace_rules
        .iter()
        .find(|r| r.profile_sha256 == data.sha256().unwrap() && r.target_scope == "self")
        .unwrap();
    assert!(rule.permits(1001, "self", 0, 0, &[], &data.sha256().unwrap(), 1001));
    assert!(!rule.permits(1001, "self", 0, 0, &[], &root.sha256().unwrap(), 1001));
    assert!(!rule.permits(
        1001,
        "registered:container-b",
        0,
        0,
        &[],
        &data.sha256().unwrap(),
        1001
    ));
}
