//! Offline CSR/SSHSIG packaging. These helpers never authorize or consume grants.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sigrund_core::{
    CoreError, Result,
    crypto::{WARRANT_PAYLOAD_TYPE, pae, verify_ssh_signature},
    protocol::{Decision, DsseEnvelope, DsseSignature, parse_strict},
    warrant::CanonicalWarrant,
};
use ssh_key::{Algorithm, PublicKey, SshSig, encoding::Encode};

pub fn extract_csr(status: &[u8]) -> Result<CanonicalWarrant> {
    // Exactly one denial record; concatenated status objects are not a CSR.
    let decision: Decision = parse_strict(status)?;
    decision.validate()?;
    if decision.status != "TIMEOUT_CSR" {
        return Err(CoreError::Value(
            "expected a TIMEOUT_CSR status record".into(),
        ));
    }
    CanonicalWarrant::parse(decision.csr_payload.as_deref().unwrap().as_bytes())
}

pub fn csr_pae(csr: &CanonicalWarrant) -> Vec<u8> {
    pae(WARRANT_PAYLOAD_TYPE, csr.as_bytes())
}

pub fn pack_warrant(csr: &[u8], armor: &[u8], signer_id: &str) -> Result<Vec<u8>> {
    let warrant = CanonicalWarrant::parse(csr)?;
    let signature = SshSig::from_pem(armor)
        .map_err(|e| CoreError::Value(format!("invalid armored SSHSIG: {e}")))?;
    let public_key = PublicKey::new(signature.public_key().clone(), "");
    let signature_type = match public_key.algorithm() {
        Algorithm::Ed25519 => "ssh-ed25519",
        Algorithm::SkEd25519 => "sk-ssh-ed25519",
        _ => return Err(CoreError::Value("unsupported SSH signing algorithm".into())),
    };
    let mut raw = Vec::new();
    signature
        .encode(&mut raw)
        .map_err(|e| CoreError::Value(format!("encode SSHSIG: {e}")))?;
    let encoded = STANDARD.encode(raw);
    // Check binding and signature here. Only the daemon decides whether the
    // embedded public key is trusted for this signer ID and request.
    verify_ssh_signature(
        signature_type,
        &public_key
            .to_openssh()
            .map_err(|e| CoreError::Value(e.to_string()))?,
        &encoded,
        WARRANT_PAYLOAD_TYPE,
        warrant.as_bytes(),
        false,
        false,
    )?;
    DsseEnvelope::from_warrant(
        &warrant,
        vec![DsseSignature {
            keyid: signer_id.into(),
            sig: encoded,
        }],
    )?
    .to_jcs()
}
