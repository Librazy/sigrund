use super::support::*;

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
            "mode": "signed", "tty_mode": "stdio", "caller_env": {}, "dsse_envelope": signed(warrant)
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
        hello.requested_execution_context = Some(warrant.execution_context.clone());
        hello.requested_policy.as_mut().unwrap().mode = warrant.policy.mode.clone();
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
