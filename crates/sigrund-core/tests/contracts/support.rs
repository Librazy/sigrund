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
pub(super) const GOLDEN: &[u8] = include_bytes!("../fixtures/v2-warrant.json");

pub(super) fn fixture() -> Warrant {
    parse_strict(GOLDEN).unwrap()
}
pub(super) fn unsigned() -> ClientHello {
    let w = fixture();
    ClientHello {
        csr_payload: None,
        caller_env: Default::default(),
        mode: "thin_csr".into(),
        tty_mode: "stdio".into(),
        dsse_envelope: None,
        requested_command: Some(w.command.requested()),
        requested_execution_context: Some(w.execution_context.requested()),
        requested_policy: Some(sigrund_core::protocol::RequestedPolicy {
            mode: "one_time".into(),
            ttl_secs: 900,
        }),
    }
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
        post_exec_capabilities: None,
        executable_sha256: Some("00".repeat(32)),
        executable_trust: None,
        stdin_sha256: None,
    }
}
pub(super) fn signed(mut warrant: Warrant) -> DsseEnvelope {
    warrant.intent_sha256 = warrant.intent().unwrap().sha256().unwrap();
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
