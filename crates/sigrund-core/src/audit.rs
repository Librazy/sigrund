use crate::crypto::sha256_hex;
use crate::{CoreError, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RATCHET_DOMAIN: &[u8] = b"sigrun-ratchet-v1";

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RatchetState {
    pub key_hex: String,
    pub last_record_sha256: String,
    pub remote_acked_seq: u64,
    pub seq: u64,
}

pub fn next_ratchet_key(key: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(key);
    digest.update(RATCHET_DOMAIN);
    digest.finalize().into()
}

pub fn entry_hmac(key: &[u8], body_jcs: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary key length");
    mac.update(body_jcs);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn record_hash(record_without_newline: &[u8]) -> String {
    sha256_hex(record_without_newline)
}

pub fn validate_record_bytes(record: &[u8]) -> Result<()> {
    if record.is_empty() || record.len() > 65_536 || record.contains(&b'\n') {
        return Err(CoreError::Value(
            "audit record must be one bounded line".into(),
        ));
    }
    Ok(())
}

pub fn append_line_bytes(record: &[u8]) -> Result<Vec<u8>> {
    validate_record_bytes(record)?;
    let mut line = record.to_vec();
    line.push(b'\n');
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratchet_and_hmac_are_deterministic() {
        let key = [7u8; 32];
        assert_ne!(next_ratchet_key(&key), key);
        assert_eq!(entry_hmac(&key, b"{}"), entry_hmac(&key, b"{}"));
        assert_eq!(record_hash(b"{}\n"), record_hash(b"{}\n"));
    }
}
