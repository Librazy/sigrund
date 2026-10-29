use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{CoreError, Result};

pub const WARRANT_PAYLOAD_TYPE: &str = "application/vnd.sigrun.warrant.v1+json";

pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload_type.len() + payload.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn validate_uuidv7(value: &str) -> Result<Uuid> {
    if value.len() != 36 || value.to_ascii_lowercase() != value {
        return Err(CoreError::Value(
            "UUID must be lowercase canonical text".into(),
        ));
    }
    let uuid =
        Uuid::parse_str(value).map_err(|e| CoreError::Value(format!("invalid UUID: {e}")))?;
    if uuid.get_version_num() != 7 || uuid.get_variant() != uuid::Variant::RFC4122 {
        return Err(CoreError::Value(
            "UUID must use version 7 and RFC 4122 variant".into(),
        ));
    }
    Ok(uuid)
}

pub fn new_uuidv7() -> Uuid {
    Uuid::now_v7()
}

pub fn strict_base64(value: &str, max_decoded: usize) -> Result<Vec<u8>> {
    if value.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(CoreError::Value("base64 contains whitespace".into()));
    }
    let decoded = STANDARD
        .decode(value)
        .map_err(|e| CoreError::Value(format!("invalid base64: {e}")))?;
    if decoded.len() > max_decoded || STANDARD.encode(&decoded) != value {
        return Err(CoreError::Value("non-canonical or oversized base64".into()));
    }
    Ok(decoded)
}

pub fn verify_raw_ed25519(
    public_key_b64: &str,
    signature_b64: &str,
    payload_type: &str,
    payload: &[u8],
) -> Result<()> {
    let public_key = strict_base64(public_key_b64, 32)?;
    let signature = strict_base64(signature_b64, 64)?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| CoreError::Value("Ed25519 public key must be 32 bytes".into()))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| CoreError::Value("Ed25519 signature must be 64 bytes".into()))?;
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|e| CoreError::Value(format!("invalid Ed25519 public key: {e}")))?;
    key.verify_strict(
        &pae(payload_type, payload),
        &Signature::from_bytes(&signature),
    )
    .map_err(|e| CoreError::Value(format!("Ed25519 verification failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_spec_vector_prefix() {
        let payload = br#"{"grant_id":"0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f","version":"1.0"}"#;
        let encoded = pae(WARRANT_PAYLOAD_TYPE, payload);
        assert!(encoded.starts_with(b"DSSEv1 38 application/vnd.sigrun.warrant.v1+json "));
        assert_eq!(encoded.len(), 119);
    }

    #[test]
    fn base64_requires_canonical_padding() {
        let encoded = STANDARD.encode([1u8, 2, 3]);
        assert_eq!(strict_base64(&encoded, 3).unwrap(), vec![1, 2, 3]);
        assert!(strict_base64("AQI", 3).is_err());
    }

    #[test]
    fn uuid_validation_enforces_version_variant_and_case() {
        let value = new_uuidv7().to_string();
        assert!(validate_uuidv7(&value).is_ok());
        assert!(validate_uuidv7(&value.to_ascii_uppercase()).is_err());
        assert!(validate_uuidv7("0192d8f4-7c1b-6000-8a01-9f8b3c4d5e6f").is_err());
    }
}
