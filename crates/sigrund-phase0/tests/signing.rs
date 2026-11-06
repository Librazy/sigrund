//! Independent OpenSSH fixture; it is not a warrant usable by the v2 runtime.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use sigrund_core::crypto::{pae, verify_ssh_signature};
use sigrund_phase0::contracts::{BindingBundle, Contract};
use ssh_key::{HashAlg, PublicKey, SshSig, encoding::Encode};

#[test]
fn v3_openssh_fixture_binds_intent_target_and_profile_and_rejects_v2() {
    let payload = include_bytes!("fixtures/warrant.json");
    let expected_pae = include_bytes!("fixtures/warrant.pae");
    let payload_type = "application/vnd.sigrun.warrant.v3+json";
    assert_eq!(payload_type.len(), 38);
    assert_eq!(pae(payload_type, payload), expected_pae);
    let key_text = include_str!("fixtures/signer.pub");
    let key = PublicKey::from_openssh(key_text).unwrap();
    let signature = SshSig::from_pem(include_bytes!("fixtures/warrant.sshsig")).unwrap();
    assert_eq!(signature.hash_alg(), HashAlg::Sha512);
    assert!(signature.reserved().is_empty());
    key.verify("sigrun.warrant.v3", expected_pae, &signature)
        .unwrap();
    assert!(
        key.verify("sigrun.warrant.v2", expected_pae, &signature)
            .is_err()
    );
    assert!(
        key.verify(
            "sigrun.warrant.v3",
            &pae(sigrund_core::crypto::WARRANT_PAYLOAD_TYPE, payload),
            &signature
        )
        .is_err()
    );
    assert!(
        verify_ssh_signature(
            "ssh-ed25519",
            key_text,
            &STANDARD.encode(signature.encode_vec().unwrap()),
            payload_type,
            payload,
            false,
            false
        )
        .is_err()
    );
    assert!(sigrund_core::warrant::CanonicalWarrant::parse(payload).is_err());

    let warrant: serde_json::Value = serde_json::from_slice(payload).unwrap();
    let binding = serde_json::json!({"target_binding": warrant["target_binding"], "security_constraints": warrant["security_constraints"]});
    let bytes = sigrund_core::json::canonical_bytes(&binding).unwrap();
    assert_eq!(bytes, include_bytes!("fixtures/execution-binding.json"));
    let hashes: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/sha256.json")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        hashes["execution-binding"]
    );
    let intent = sigrund_core::json::canonical_bytes(&warrant["intent"]).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(intent)),
        warrant["intent_sha256"]
    );
    let bundle = BindingBundle::parse(include_bytes!("fixtures/bundle.json")).unwrap();
    assert_eq!(
        warrant["target_binding"],
        serde_json::to_value(bundle.target_binding).unwrap()
    );
    assert_eq!(
        warrant["security_constraints"]["profile_sha256"],
        bundle.profile_sha256
    );
    for pointer in [
        "/target_binding/instance_id",
        "/target_binding/daemon_epoch",
        "/target_binding/context_sha256",
        "/security_constraints/profile_sha256",
        "/intent/security_profile",
    ] {
        let mut changed = warrant.clone();
        *changed.pointer_mut(pointer).unwrap() = serde_json::json!("substitution");
        let bytes = sigrund_core::json::canonical_bytes(&changed).unwrap();
        assert!(
            key.verify("sigrun.warrant.v3", &pae(payload_type, &bytes), &signature)
                .is_err()
        );
    }
}
