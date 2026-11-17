use sigrund_core::host::Record;
use std::{fs, process::Command};
#[test]
fn export_resolves_a_candidate_before_its_digest_is_authorized() {
    let source: toml::Value = toml::from_str(include_str!(
        "../../../config/workload-profiles.toml.example"
    ))
    .unwrap();
    let mut profile: sigrund_core::host::Constraints =
        source["host_profiles"][0].clone().try_into().unwrap();
    let descriptor = include_str!("../../../config/selinux-domain.toml.example")
        .replace("REPLACE_WITH_CURRENT_POLICY_FINGERPRINT", &"a".repeat(64));
    profile.custom_domain = Some(sigrund::selinux_domains::parse(descriptor.as_bytes()).unwrap());
    profile.workload = None;
    profile.schema = "sigrund.host-custom-domain.v1".into();
    profile.verify_exec_stop = true;
    let temporary = tempfile::tempdir().unwrap();
    let config = temporary.path().join("candidate.toml");
    fs::write(
        &config,
        toml::to_string(&std::collections::BTreeMap::from([(
            "host_profiles",
            vec![&profile],
        )]))
        .unwrap(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sigrundctl"))
        .args(["profile", "export", &profile.profile_id, "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let exported: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        exported["profile"]["profile_sha256"],
        profile.sha256().unwrap()
    );
    assert_eq!(
        exported["profile"]["registration"]["registration_sha256"],
        profile.custom_domain.as_ref().unwrap().sha256().unwrap()
    );
    assert_eq!(exported["daemon_rules"], serde_json::json!([]));
    let output = Command::new(env!("CARGO_BIN_EXE_sigrundctl"))
        .args(["profile", "export", "missing", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!output.status.success());
}
