pub(super) use base64::{Engine as _, engine::general_purpose::STANDARD};
pub(super) use ed25519_dalek::{Signer as _, SigningKey};
pub(super) use serde_json::{Value, json};
pub(super) use sigrund_core::{
    approval::{ApprovalRequest, ApprovalResponse},
    config::{DaemonConfig, MvpProfile, SignerPolicyFile},
    crypto::{WARRANT_PAYLOAD_TYPE, pae, verify_raw_ed25519},
    json::canonical_bytes,
    protocol::{ClientHello, DsseEnvelope, DsseSignature, parse_strict},
    warrant::{CanonicalWarrant, Csr, CsrIdentity, MAX_TIMESTAMP, SnapshotDigests, Warrant},
};

pub(super) const EXEC_ID: &str = "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f";
pub(super) const GOLDEN: &[u8] = br#"{"command":{"allow_interpreted_script":false,"argv":["/usr/bin/id"],"cwd":"/","executable_path":"/usr/bin/id","executable_sha256":"0000000000000000000000000000000000000000000000000000000000000000","stdin_policy":"null","stdin_sha256":null,"tty_mode":"stdio"},"execution_context":{"caller_env_allowlist":[],"capabilities":[],"env_exact":{"LANG":"C.UTF-8","PATH":"/usr/bin"},"supplementary_gids":[],"target_gid":0,"target_uid":0,"umask":63},"grant_id":"0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f","host_id":"sigrun-host:sha256:0000000000000000000000000000000000000000000000000000000000000000","policy":{"mode":"one_time","not_after":1900,"not_before":1000},"requester_gid":1001,"requester_uid":1001,"version":"1.0"}"#;

pub(super) fn fixture() -> Warrant {
    parse_strict(GOLDEN).unwrap()
}
pub(super) fn unsigned() -> ClientHello {
    let w = fixture();
    parse_strict(
        &serde_json::to_vec(&json!({
            "caller_env": {}, "mode": "unsigned_csr_request", "tty_mode": "stdio",
            "requested_command": w.command.requested(),
            "requested_execution_context": w.execution_context,
            "requested_policy": {"mode": "one_time", "ttl_secs": 900},
        }))
        .unwrap(),
    )
    .unwrap()
}
pub(super) fn identity(now: i64) -> CsrIdentity {
    CsrIdentity {
        grant_id: EXEC_ID.into(),
        host_id: fixture().host_id,
        requester_uid: 1001,
        requester_gid: 1001,
        now,
    }
}
pub(super) fn snapshots() -> SnapshotDigests {
    SnapshotDigests {
        executable_sha256: "00".repeat(32),
        stdin_sha256: None,
    }
}
pub(super) fn signed(warrant: Warrant) -> DsseEnvelope {
    let canonical = CanonicalWarrant::new(warrant).unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let signature = key.sign(&pae(WARRANT_PAYLOAD_TYPE, canonical.as_bytes()));
    let envelope = DsseEnvelope::from_warrant(
        &canonical,
        vec![DsseSignature {
            keyid: "root-test".into(),
            sig: STANDARD.encode(signature.to_bytes()),
        }],
    )
    .unwrap();
    verify_raw_ed25519(
        &STANDARD.encode(key.verifying_key().to_bytes()),
        &envelope.signatures[0].sig,
        WARRANT_PAYLOAD_TYPE,
        canonical.as_bytes(),
    )
    .unwrap();
    envelope
}
pub(super) fn parse_value(value: &Value) -> sigrund_core::Result<CanonicalWarrant> {
    CanonicalWarrant::parse(&canonical_bytes(value)?)
}

pub(super) fn config(profile: &str) -> sigrund_core::Result<DaemonConfig> {
    let text = include_str!("../../../../config/sigrund.toml.example").replace(
        "<strict-padded-base64-32-byte-ed25519-key>",
        &STANDARD.encode([1; 32]),
    );
    DaemonConfig::from_toml(format!("{text}\n{profile}").as_bytes())
}
