use super::support::*;

#[test]
fn composefs_defaults_on_can_opt_out_and_is_captured() {
    let default = config("").unwrap();
    assert!(default.digest_direct.allow_admin_trusted_composefs);
    assert!(default.admin_trusted_composefs_mounts.is_empty());
    let disabled = config("[digest_direct]\nallow_admin_trusted_composefs = false").unwrap();
    assert!(!disabled.digest_direct.allow_admin_trusted_composefs);
    let store = sigrund_core::config::PolicyStore::new(default);
    let captured = store.capture();
    store.reload(disabled).unwrap();
    assert!(captured.allow_admin_trusted_composefs);
    assert!(!store.capture().allow_admin_trusted_composefs);
    assert!(config("[digest_direct]\nallow_admin_trusted_composefs = 'true'").is_err());
    assert!(config("[digest_direct]\nunknown = true").is_err());
    assert!(config("admin_trusted_composefs_mounts = [46]").is_err());
}

#[test]
fn executable_models_are_ordered_nonempty_and_captured() {
    use sigrund_core::executable::{TrustModel, default_models};
    let mut cfg = config("").unwrap();
    assert_eq!(cfg.executable_trust_models, default_models());
    cfg.executable_trust_models = vec![TrustModel::DigestMemfd, TrustModel::Ctime];
    cfg.validate().unwrap();
    let store = sigrund_core::config::PolicyStore::new(cfg.clone());
    let captured = store.capture();
    cfg.executable_trust_models = vec![TrustModel::FsVerity, TrustModel::DigestMemfd];
    store.reload(cfg.clone()).unwrap();
    assert_eq!(
        captured.executable_trust_models,
        vec![TrustModel::DigestMemfd, TrustModel::Ctime]
    );
    assert_eq!(
        store.capture().executable_trust_models,
        vec![TrustModel::FsVerity, TrustModel::DigestMemfd]
    );
    cfg.executable_trust_models.clear();
    assert!(cfg.validate().is_err());
    cfg.executable_trust_models = vec![TrustModel::Ctime; 2];
    assert!(cfg.validate().is_err());
    assert!(serde_json::from_str::<TrustModel>("\"unknown\"").is_err());
}

#[test]
fn mvp_profile_is_opt_in_and_rejects_expansion_at_load_and_reload() {
    assert!(config("").unwrap().mvp.is_none());
    let cfg = config("[mvp]").unwrap();
    assert_eq!(cfg.mvp, Some(MvpProfile::default()));
    let store = sigrund_core::config::PolicyStore::new(cfg);
    assert_eq!(store.capture().mvp, Some(MvpProfile::default()));
    for settings in [
        "tty_mode = 'pty'",
        "hooks_enabled = true",
        "pty_enabled = true",
        "max_active_approval_requests = 0",
        "max_active_approval_requests = 2",
        "extra = true",
    ] {
        assert!(config(&format!("[mvp]\n{settings}")).is_err(), "{settings}");
    }
    let mut replacement = config("[mvp]").unwrap();
    replacement.require_remote_audit_ack = true;
    assert!(store.reload(replacement).is_err());
    assert_eq!(store.current().number, 1);
    let profile = MvpProfile::default();
    profile.validate_hello(&unsigned()).unwrap();
    let mut pty = unsigned();
    pty.tty_mode = "pty".into();
    let command = pty.requested_command.as_mut().unwrap();
    command.tty_mode = "pty".into();
    command.stdin_policy = "unrestricted_interactive".into();
    assert!(profile.validate_hello(&pty).is_err());
}

#[test]
fn mvp_signer_policy_rejects_nonssh_adapters() {
    let mut policy =
        SignerPolicyFile::from_toml(include_bytes!("../../../../config/signers.toml.example"))
            .unwrap();
    let key = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    ));
    policy.signers[0].signature_type = "ssh-ed25519".into();
    policy.signers[0].require_user_presence = false;
    policy.signers[0].public_key = key.to_openssh().unwrap();
    policy.validate_against(&config("[mvp]").unwrap()).unwrap();
    policy.signers[0].signature_type = "raw-ed25519".into();
    policy.signers[0].public_key =
        STANDARD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes());
    policy.validate_against(&config("").unwrap()).unwrap();
    assert!(policy.validate_against(&config("[mvp]").unwrap()).is_err());
}

#[test]
fn profile_restrictions_apply_to_signed_and_unsigned_requests() {
    let profile = MvpProfile::default();
    let signed_hello = |warrant| -> ClientHello {
        parse_strict(&serde_json::to_vec(&json!({
            "version":"3.0", "mode": "signed", "tty_mode": "stdio", "caller_env": {}, "dsse_envelope": signed(warrant)
        })).unwrap()).unwrap()
    };
    for mode in ["null", "sha256"] {
        let mut warrant = fixture();
        warrant.command.stdin_policy = mode.into();
        warrant.command.stdin_sha256 = (mode == "sha256").then(|| "00".repeat(32));
        profile
            .validate_for_peer(&signed_hello(warrant), 1001)
            .unwrap();
        let mut hello = unsigned();
        hello.requested_command.as_mut().unwrap().stdin_policy = mode.into();
        profile.validate_for_peer(&hello, 1001).unwrap();
    }
    for field in [
        "script",
        "stdin",
        "allowlist",
        "time_range",
        "permanent",
        "same_uid",
    ] {
        let mut warrant = fixture();
        match field {
            "script" => warrant.command.allow_interpreted_script = true,
            "stdin" => warrant.command.stdin_policy = "unrestricted_interactive".into(),
            "allowlist" => warrant
                .execution_context
                .caller_env_allowlist
                .push("LANG".into()),
            "time_range" => warrant.policy.mode = "time_range".into(),
            "permanent" => {
                warrant.policy.mode = "permanent".into();
                warrant.policy.not_after = None;
            }
            "same_uid" => warrant.execution_context.target_uid = 1001,
            _ => unreachable!(),
        }
        // Keep allowlisted names disjoint from exact names so rejection proves
        // the profile restriction rather than a generic schema failure.
        if field == "allowlist" {
            warrant.execution_context.env_exact.remove("LANG");
        }
        let mut hello = unsigned();
        hello.requested_command = Some(warrant.command.requested());
        hello.requested_execution_context = Some(warrant.execution_context.requested());
        hello.requested_policy.as_mut().unwrap().mode = warrant.policy.mode.clone();
        if warrant.policy.mode == "permanent" {
            hello.requested_policy.as_mut().unwrap().ttl_secs = 0;
        }
        hello.validate_request().unwrap();
        assert!(
            profile.validate_for_peer(&hello, 1001).is_err(),
            "unsigned {field}"
        );
        let hello = signed_hello(warrant);
        hello.validate_request().unwrap();
        assert!(
            profile.validate_for_peer(&hello, 1001).is_err(),
            "signed {field}"
        );
    }
    // Same-UID gating uses the actual peer, even if signed requester_uid lies.
    assert!(
        profile
            .validate_for_peer(&signed_hello(fixture()), 0)
            .is_err()
    );
    for mut hello in [unsigned(), signed_hello(fixture())] {
        hello.caller_env.insert("LANG".into(), "C".into());
        assert!(profile.validate_for_peer(&hello, 1001).is_err());
    }
}

#[test]
fn approval_signer_selection_is_explicit_bounded_and_unambiguous() {
    let mut policy =
        SignerPolicyFile::from_toml(include_bytes!("../../../../config/signers.toml.example"))
            .unwrap();
    policy.signers[0].signature_type = "ssh-ed25519".into();
    policy.signers[0].require_user_presence = false;
    policy.signers[0].public_key = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    ))
    .to_openssh()
    .unwrap();
    let selected = format!(
        "[mvp]\napproval_signer_id = {:?}",
        policy.signers[0].signer_id
    );
    let cfg = config(&selected).unwrap();
    policy.validate_against(&cfg).unwrap();
    assert!(
        policy
            .validate_against(&config("[mvp]\napproval_signer_id = 'absent'").unwrap())
            .is_err()
    );
    policy.signers.push(policy.signers[0].clone());
    assert!(policy.validate_against(&cfg).is_err());
    for id in ["x".repeat(129), "λ".into(), "bad\nidentity".into()] {
        let profile = MvpProfile {
            approval_signer_id: id,
            ..MvpProfile::default()
        };
        assert!(profile.validate().is_err());
    }
}

#[test]
fn direct_digest_limits_are_independent_bounded_and_captured() {
    let mut cfg = config("").unwrap();
    assert_eq!(cfg.max_direct_digest_bytes, 268_435_456);
    assert_eq!(cfg.direct_digest_timeout_ms, 5000);
    cfg.max_executable_bytes = 1;
    cfg.max_direct_digest_bytes = 1_073_741_824;
    cfg.direct_digest_timeout_ms = 30_000;
    cfg.validate().unwrap();
    let store = sigrund_core::config::PolicyStore::new(cfg.clone());
    let captured = store.capture();
    assert_eq!(captured.max_direct_digest_bytes, 1_073_741_824);
    assert_eq!(captured.direct_digest_timeout_ms, 30_000);
    for limit in [0, 1_073_741_825] {
        cfg.max_direct_digest_bytes = limit;
        assert!(cfg.validate().is_err());
    }
    cfg.max_direct_digest_bytes = 1;
    for timeout in [0, 30_001] {
        cfg.direct_digest_timeout_ms = timeout;
        assert!(cfg.validate().is_err());
    }
}

#[test]
fn unresolved_named_thin_account_is_not_the_internal_numeric_placeholder() {
    let profile = MvpProfile::default();
    let mut named = unsigned();
    named.original_intent.as_mut().unwrap().account = sigrund_core::host::Account::Name {
        name: "target".into(),
    };
    named
        .requested_execution_context
        .as_mut()
        .unwrap()
        .target_uid = 0;
    profile.validate_for_peer(&named, 0).unwrap();
    let mut numeric = unsigned();
    numeric
        .requested_execution_context
        .as_mut()
        .unwrap()
        .target_uid = 0;
    assert!(profile.validate_for_peer(&numeric, 0).is_err());
}
