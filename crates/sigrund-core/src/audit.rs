use crate::crypto::sha256_hex;
use crate::{CoreError, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

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

pub struct AuditLog {
    state_path: PathBuf,
    log: File,
    state: RatchetState,
    key: [u8; 32],
}

impl AuditLog {
    pub fn open(log_path: impl AsRef<Path>, state_path: impl AsRef<Path>) -> Result<Self> {
        let log_path = log_path.as_ref().to_owned();
        let state_path = state_path.as_ref().to_owned();
        let state_bytes = std::fs::read(&state_path)
            .map_err(|e| CoreError::Database(format!("read audit state: {e}")))?;
        let state: RatchetState = serde_json::from_slice(&state_bytes)
            .map_err(|e| CoreError::Database(format!("parse audit state: {e}")))?;
        let key = decode_hex_32(&state.key_hex)?;
        let log = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| CoreError::Database(format!("open audit log: {e}")))?;
        Ok(Self {
            state_path,
            log,
            state,
            key,
        })
    }

    pub fn state(&self) -> &RatchetState {
        &self.state
    }

    /// Appends exactly one record line and advances the durable ratchet state.
    /// Any failure while compensating a partial write is reported as fatal so
    /// the daemon can stop accepting requests.
    pub fn append_raw(&mut self, record: &[u8]) -> Result<u64> {
        let line = append_line_bytes(record)?;
        let eof_before = self
            .log
            .seek(SeekFrom::End(0))
            .map_err(|e| CoreError::Database(format!("audit seek: {e}")))?;
        if let Err(error) = self.log.write_all(&line).and_then(|_| self.log.sync_all()) {
            let rollback = self
                .log
                .set_len(eof_before)
                .and_then(|_| self.log.sync_all());
            if let Err(rollback_error) = rollback {
                return Err(CoreError::Database(format!(
                    "fatal audit rollback failure after {error}: {rollback_error}"
                )));
            }
            return Err(CoreError::Database(format!(
                "audit append rolled back: {error}"
            )));
        }
        let seq = self.state.seq;
        let next_key = next_ratchet_key(&self.key);
        let next_state = RatchetState {
            key_hex: encode_hex(&next_key),
            last_record_sha256: record_hash(record),
            remote_acked_seq: self.state.remote_acked_seq,
            seq: seq
                .checked_add(1)
                .ok_or_else(|| CoreError::Value("audit sequence overflow".into()))?,
        };
        let temp_path = self.state_path.with_extension("state.tmp");
        let state_bytes = serde_json::to_vec(&next_state)
            .map_err(|e| CoreError::Database(format!("serialize audit state: {e}")))?;
        let mut temp = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp_path)
            .map_err(|e| CoreError::Database(format!("open audit state temporary file: {e}")))?;
        temp.write_all(&state_bytes)
            .and_then(|_| temp.sync_all())
            .map_err(|e| CoreError::Database(format!("flush audit state: {e}")))?;
        drop(temp);
        std::fs::rename(&temp_path, &self.state_path)
            .map_err(|e| CoreError::Database(format!("rename audit state: {e}")))?;
        if let Some(parent) = self.state_path.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|e| CoreError::Database(format!("sync audit state directory: {e}")))?;
        }
        self.state = next_state;
        self.key = next_key;
        Ok(seq)
    }
}

fn decode_hex_32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(CoreError::Value(
            "ratchet key must be 64 hex characters".into(),
        ));
    }
    let mut bytes = [0u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| CoreError::Value("ratchet key contains non-hex data".into()))?;
    }
    Ok(bytes)
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
