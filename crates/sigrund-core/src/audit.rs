use crate::crypto::sha256_hex;
use crate::{CoreError, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub const RATCHET_DOMAIN: &[u8] = b"sigrun-ratchet-v1";

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RatchetState {
    pub key_hex: String,
    #[serde(default)]
    pub initial_key_hex: Option<String>,
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
    host_id: String,
    usable: bool,
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
        let initial_key = state
            .initial_key_hex
            .as_deref()
            .map(decode_hex_32)
            .transpose()?;
        let log = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| CoreError::Database(format!("open audit log: {e}")))?;
        let mut writer = Self {
            state_path,
            log,
            state,
            key,
            host_id: String::new(),
            usable: true,
        };
        let recovery = recover_log_state(&mut writer.log, &writer.state, initial_key.as_ref())?;
        writer.host_id = recovery.host_id;
        match recovery.action {
            RecoveryAction::None => {}
            RecoveryAction::Truncate { offset } => {
                writer
                    .log
                    .set_len(offset)
                    .and_then(|_| writer.log.sync_all())
                    .map_err(|e| {
                        CoreError::Database(format!("truncate partial audit record: {e}"))
                    })?;
                writer.append_recovery("RATCHET_PARTIAL_WRITE_TRUNCATED")?;
            }
            RecoveryAction::Forward {
                last_hash,
                truncate_offset,
            } => {
                if let Some(offset) = truncate_offset {
                    writer
                        .log
                        .set_len(offset)
                        .and_then(|_| writer.log.sync_all())
                        .map_err(|e| {
                            CoreError::Database(format!("truncate partial audit record: {e}"))
                        })?;
                }
                let next_key = next_ratchet_key(&writer.key);
                writer.state.seq = writer
                    .state
                    .seq
                    .checked_add(1)
                    .ok_or_else(|| CoreError::Database("audit sequence overflow".into()))?;
                writer.state.last_record_sha256 = last_hash;
                writer.key = next_key;
                writer.state.key_hex = encode_hex(&next_key);
                writer.persist_state()?;
                writer.append_recovery("RATCHET_FORWARD_RECOVERY")?;
            }
        }
        Ok(writer)
    }

    pub fn state(&self) -> &RatchetState {
        &self.state
    }

    /// Appends exactly one record line and advances the durable ratchet state.
    /// Any failure while compensating a partial write is reported as fatal so
    /// the daemon can stop accepting requests.
    pub fn append_raw(&mut self, record: &[u8]) -> Result<u64> {
        if !self.usable {
            return Err(CoreError::Database(
                "audit writer requires reconciliation before reuse".into(),
            ));
        }
        let line = append_line_bytes(record)?;
        let (record_seq, previous) = record_metadata(record)?;
        if record_seq != self.state.seq || previous != self.state.last_record_sha256 {
            return Err(CoreError::Database(
                "audit record does not extend current state".into(),
            ));
        }
        if record_host_id(record)? != self.host_id {
            return Err(CoreError::Database(
                "audit record host_id does not match local host".into(),
            ));
        }
        verify_record_hmac(record, &self.key)?;
        let seq = self.state.seq;
        let next_key = next_ratchet_key(&self.key);
        let next_state = RatchetState {
            key_hex: encode_hex(&next_key),
            initial_key_hex: self.state.initial_key_hex.clone(),
            last_record_sha256: record_hash(record),
            remote_acked_seq: self.state.remote_acked_seq,
            seq: seq
                .checked_add(1)
                .ok_or_else(|| CoreError::Value("audit sequence overflow".into()))?,
        };
        let state_bytes = serde_json::to_vec(&next_state)
            .map_err(|e| CoreError::Database(format!("serialize audit state: {e}")))?;
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
                self.usable = false;
                return Err(CoreError::Database(format!(
                    "fatal audit rollback failure after {error}: {rollback_error}"
                )));
            }
            return Err(CoreError::Database(format!(
                "audit append rolled back: {error}"
            )));
        }
        // Once the log is durable, any failure leaves disk potentially one
        // record ahead of state. Do not reuse the key/sequence on this writer.
        self.usable = false;
        let temp_path = self.state_path.with_extension("state.tmp");
        let mut temp = OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp_path)
            .map_err(|e| CoreError::Database(format!("open audit state temporary file: {e}")))?;
        // mode() applies only to a new file. Secure a stale temporary inode
        // before truncating or putting a ratchet key in it.
        temp.set_permissions(std::fs::Permissions::from_mode(0o600))
            .and_then(|_| temp.set_len(0))
            .map_err(|e| CoreError::Database(format!("secure audit state temporary file: {e}")))?;
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
        self.usable = true;
        Ok(seq)
    }
}

impl AuditLog {
    fn append_recovery(&mut self, event_type: &str) -> Result<()> {
        let mut body = std::collections::BTreeMap::new();
        body.insert("event_type", serde_json::Value::String(event_type.into()));
        body.insert("host_id", serde_json::Value::String(self.host_id.clone()));
        body.insert("seq", serde_json::Value::from(self.state.seq));
        body.insert(
            "prev_record_sha256",
            serde_json::Value::String(self.state.last_record_sha256.clone()),
        );
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| CoreError::Database(format!("serialize audit recovery: {e}")))?;
        let mut record = body;
        record.insert(
            "entry_hmac",
            serde_json::Value::String(entry_hmac(&self.key, &body_bytes)),
        );
        let record_bytes = serde_json::to_vec(&record)
            .map_err(|e| CoreError::Database(format!("serialize audit recovery record: {e}")))?;
        self.append_raw(&record_bytes).map(|_| ())
    }

    fn persist_state(&self) -> Result<()> {
        let temp_path = self.state_path.with_extension("state.tmp");
        let state_bytes = serde_json::to_vec(&self.state)
            .map_err(|e| CoreError::Database(format!("serialize audit state: {e}")))?;
        let mut temp = OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp_path)
            .map_err(|e| CoreError::Database(format!("open audit state temporary file: {e}")))?;
        temp.set_permissions(std::fs::Permissions::from_mode(0o600))
            .and_then(|_| temp.set_len(0))
            .map_err(|e| CoreError::Database(format!("secure audit state temporary file: {e}")))?;
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
        Ok(())
    }
}

/// Only a synchronized log/state pair is writable through this primitive.
/// Crash recovery must reconcile other pairs before opening a new writer.
enum RecoveryAction {
    None,
    Truncate {
        offset: u64,
    },
    Forward {
        last_hash: String,
        truncate_offset: Option<u64>,
    },
}

struct RecoveryResult {
    action: RecoveryAction,
    host_id: String,
}

fn recover_log_state(
    log: &mut File,
    state: &RatchetState,
    initial_key: Option<&[u8; 32]>,
) -> Result<RecoveryResult> {
    if state.seq == 0 || state.remote_acked_seq >= state.seq {
        return Err(CoreError::Database(
            "AUDIT_TAMPER_OR_CORRUPTION: invalid state sequence".into(),
        ));
    }
    let mut bytes = Vec::new();
    log.seek(SeekFrom::Start(0))
        .map_err(|e| CoreError::Database(format!("seek audit log: {e}")))?;
    log.read_to_end(&mut bytes)
        .map_err(|e| CoreError::Database(format!("read audit log: {e}")))?;
    let last_newline = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|position| position + 1)
        .unwrap_or(0);
    let complete = &bytes[..last_newline];
    let partial = last_newline < bytes.len();
    let records: Vec<&[u8]> = complete
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    if records.is_empty() || (records.len() as u64) < state.seq.saturating_sub(1) {
        return Err(CoreError::Database(
            "AUDIT_TAMPER_OR_CORRUPTION: log is missing history".into(),
        ));
    }
    let initial = initial_key.ok_or_else(|| {
        CoreError::Database("AUDIT_TAMPER_OR_CORRUPTION: state has no initial ratchet key".into())
    })?;
    let mut key = *initial;
    let mut key_at_state = None;
    let mut previous_hash = "0".repeat(64);
    let mut host_id: Option<String> = None;
    for (index, record) in records.iter().enumerate() {
        if index as u64 == state.seq {
            key_at_state = Some(key);
        }
        let (seq, previous) = record_metadata(record)?;
        if seq != index as u64 || previous != previous_hash {
            return Err(CoreError::Database(
                "AUDIT_TAMPER_OR_CORRUPTION: audit chain mismatch".into(),
            ));
        }
        let record_host = record_host_id(record)?;
        if let Some(expected_host) = host_id.as_deref() {
            if record_host != expected_host {
                return Err(CoreError::Database(
                    "AUDIT_TAMPER_OR_CORRUPTION: audit host_id mismatch".into(),
                ));
            }
        } else {
            host_id = Some(record_host);
        }
        verify_record_hmac(record, &key)?;
        previous_hash = record_hash(record);
        key = next_ratchet_key(&key);
    }
    let complete_count = records.len() as u64;
    if complete_count == state.seq {
        if previous_hash != state.last_record_sha256 || key != decode_hex_32(&state.key_hex)? {
            return Err(CoreError::Database(
                "AUDIT_TAMPER_OR_CORRUPTION: log/state mismatch".into(),
            ));
        }
        if partial {
            return Ok(RecoveryResult {
                action: RecoveryAction::Truncate {
                    offset: last_newline as u64,
                },
                host_id: host_id.expect("audit log has at least one record"),
            });
        }
        return Ok(RecoveryResult {
            action: RecoveryAction::None,
            host_id: host_id.expect("audit log has at least one record"),
        });
    }
    if complete_count == state.seq + 1 {
        if records
            .get(records.len() - 2)
            .map(|record| record_hash(record))
            != Some(state.last_record_sha256.clone())
        {
            return Err(CoreError::Database(
                "AUDIT_TAMPER_OR_CORRUPTION: forward recovery hash mismatch".into(),
            ));
        }
        let state_key = decode_hex_32(&state.key_hex)?;
        if key_at_state != Some(state_key) {
            return Err(CoreError::Database(
                "AUDIT_TAMPER_OR_CORRUPTION: state key mismatch before forward recovery".into(),
            ));
        }
        return Ok(RecoveryResult {
            action: RecoveryAction::Forward {
                last_hash: record_hash(records.last().unwrap()),
                truncate_offset: partial.then_some(last_newline as u64),
            },
            host_id: host_id.expect("audit log has at least one record"),
        });
    }
    Err(CoreError::Database(
        "AUDIT_TAMPER_OR_CORRUPTION: log/state mismatch".into(),
    ))
}

fn verify_record_hmac(record: &[u8], key: &[u8; 32]) -> Result<()> {
    let mut value: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(record)
        .map_err(|e| CoreError::Database(format!("parse audit record for HMAC: {e}")))?;
    let signature = value
        .remove("entry_hmac")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| {
            CoreError::Database("AUDIT_TAMPER_OR_CORRUPTION: missing entry_hmac".into())
        })?;
    let signature_bytes = decode_hex(&signature)?;
    let body = serde_json::to_vec(&value)
        .map_err(|e| CoreError::Database(format!("serialize audit HMAC body: {e}")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts fixed key");
    mac.update(&body);
    mac.verify_slice(&signature_bytes)
        .map_err(|_| CoreError::Database("AUDIT_TAMPER_OR_CORRUPTION: invalid entry_hmac".into()))
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CoreError::Database(
            "invalid lowercase hexadecimal digest".into(),
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| CoreError::Database("invalid hexadecimal digest".into()))
        })
        .collect()
}

fn record_metadata(record: &[u8]) -> Result<(u64, String)> {
    validate_record_bytes(record)?;
    crate::json::preflight(record, 8, 65_536)?;
    let value: serde_json::Value = serde_json::from_slice(record)
        .map_err(|e| CoreError::Database(format!("parse audit record: {e}")))?;
    if serde_json::to_vec(&value)
        .map_err(|e| CoreError::Database(format!("serialize audit record: {e}")))?
        != record
    {
        return Err(CoreError::Database(
            "AUDIT_TAMPER_OR_CORRUPTION: non-canonical audit record".into(),
        ));
    }
    let seq = value
        .get("seq")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| CoreError::Database("audit record missing integer seq".into()))?;
    let previous = value
        .get("prev_record_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CoreError::Database("audit record missing previous hash".into()))?;
    decode_hex_32(previous)?;
    Ok((seq, previous.to_owned()))
}

fn record_host_id(record: &[u8]) -> Result<String> {
    let value: serde_json::Value = serde_json::from_slice(record)
        .map_err(|e| CoreError::Database(format!("parse audit record host_id: {e}")))?;
    value
        .get("host_id")
        .and_then(serde_json::Value::as_str)
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| CoreError::Database("audit record missing host_id".into()))
}

fn decode_hex_32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
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

    struct Fixture {
        _dir: tempfile::TempDir,
        log: PathBuf,
        state: PathBuf,
        genesis: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("audit.jsonl");
            let state = dir.path().join("audit_ratchet.state");
            let genesis_body = serde_json::to_vec(&serde_json::json!({
                "event_type": "AUDIT_INIT", "host_id": "host", "seq": 0,
                "prev_record_sha256": "0".repeat(64),
            }))
            .unwrap();
            let key = [7u8; 32];
            let mut genesis_map: serde_json::Map<String, serde_json::Value> =
                serde_json::from_slice(&genesis_body).unwrap();
            genesis_map.insert(
                "entry_hmac".into(),
                serde_json::Value::String(entry_hmac(&key, &genesis_body)),
            );
            let genesis = serde_json::to_vec(&genesis_map).unwrap();
            std::fs::write(&log, append_line_bytes(&genesis).unwrap()).unwrap();
            let initial = RatchetState {
                key_hex: encode_hex(&next_ratchet_key(&key)),
                initial_key_hex: Some(encode_hex(&key)),
                last_record_sha256: record_hash(&genesis),
                remote_acked_seq: 0,
                seq: 1,
            };
            std::fs::write(&state, serde_json::to_vec(&initial).unwrap()).unwrap();
            Self {
                _dir: dir,
                log,
                state,
                genesis,
            }
        }

        fn record(&self) -> Vec<u8> {
            let body = serde_json::to_vec(&serde_json::json!({
                "event_type": "TEST", "host_id": "host", "seq": 1,
                "prev_record_sha256": record_hash(&self.genesis),
            }))
            .unwrap();
            let mut record: serde_json::Map<String, serde_json::Value> =
                serde_json::from_slice(&body).unwrap();
            record.insert(
                "entry_hmac".into(),
                serde_json::Value::String(entry_hmac(&next_ratchet_key(&[7u8; 32]), &body)),
            );
            serde_json::to_vec(&record).unwrap()
        }
    }

    #[test]
    fn temporary_state_is_private_for_new_and_reused_files() {
        for reuse in [false, true] {
            let fixture = Fixture::new();
            let temp = fixture.state.with_extension("state.tmp");
            if reuse {
                std::fs::write(&temp, b"stale state").unwrap();
                std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            let mut writer = AuditLog::open(&fixture.log, &fixture.state).unwrap();
            assert_eq!(writer.append_raw(&fixture.record()).unwrap(), 1);
            assert_eq!(
                std::fs::metadata(&fixture.state)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            let reopened = AuditLog::open(&fixture.log, &fixture.state).unwrap();
            assert_eq!(reopened.state().seq, 2);
            assert_eq!(
                reopened.state().last_record_sha256,
                record_hash(&fixture.record())
            );
        }
    }

    #[test]
    fn missing_or_unsynchronized_log_cannot_be_opened_for_append() {
        let fixture = Fixture::new();
        std::fs::remove_file(&fixture.log).unwrap();
        assert!(AuditLog::open(&fixture.log, &fixture.state).is_err());
        assert!(!fixture.log.exists());
        for bytes in [Vec::new(), b"{}\n".to_vec()] {
            std::fs::write(&fixture.log, &bytes).unwrap();
            assert!(AuditLog::open(&fixture.log, &fixture.state).is_err());
            assert_eq!(std::fs::read(&fixture.log).unwrap(), bytes);
        }
        let partial = [
            append_line_bytes(&fixture.genesis).unwrap(),
            b"partial".to_vec(),
        ]
        .concat();
        std::fs::write(&fixture.log, &partial).unwrap();
        assert!(AuditLog::open(&fixture.log, &fixture.state).is_ok());
        let recovered = std::fs::read_to_string(&fixture.log).unwrap();
        let recovery_record: serde_json::Value = recovered
            .lines()
            .last()
            .and_then(|line| serde_json::from_str(line).ok())
            .unwrap();
        assert_eq!(recovery_record["host_id"], "host");
        let mut wrong_hash = fixture.genesis.clone();
        wrong_hash.extend_from_slice(b" \n");
        std::fs::write(&fixture.log, wrong_hash).unwrap();
        assert!(AuditLog::open(&fixture.log, &fixture.state).is_err());
    }

    #[test]
    fn validates_entire_sequence_and_hash_chain() {
        let fixture = Fixture::new();
        let record = fixture.record();
        let mut writer = AuditLog::open(&fixture.log, &fixture.state).unwrap();
        writer.append_raw(&record).unwrap();
        drop(writer);
        let corrupt_genesis = serde_json::to_vec(&serde_json::json!({
            "event_type": "AUDIT_INIT", "host_id": "host", "seq": 0,
            "prev_record_sha256": "0".repeat(64), "extra": "tampered",
        }))
        .unwrap();
        std::fs::write(
            &fixture.log,
            [
                append_line_bytes(&corrupt_genesis).unwrap(),
                append_line_bytes(&record).unwrap(),
            ]
            .concat(),
        )
        .unwrap();
        // The last record still matches state; its predecessor no longer does.
        assert!(AuditLog::open(&fixture.log, &fixture.state).is_err());
    }

    #[test]
    fn persistence_failure_poisoned_writer_cannot_append_again() {
        let fixture = Fixture::new();
        let mut writer = AuditLog::open(&fixture.log, &fixture.state).unwrap();
        let temp = fixture.state.with_extension("state.tmp");
        std::fs::create_dir(&temp).unwrap();
        assert!(writer.append_raw(&fixture.record()).is_err());
        let after_first = std::fs::read(&fixture.log).unwrap();
        std::fs::remove_dir(&temp).unwrap();
        assert!(writer.append_raw(&fixture.record()).is_err());
        assert_eq!(std::fs::read(&fixture.log).unwrap(), after_first);
        assert_eq!(writer.state().seq, 1);
        // Reopening forward-recovers the durable record and persists state.
        assert!(AuditLog::open(&fixture.log, &fixture.state).is_ok());
    }

    #[test]
    fn rename_failure_also_poisoned_writer() {
        let fixture = Fixture::new();
        let mut writer = AuditLog::open(&fixture.log, &fixture.state).unwrap();
        std::fs::remove_file(&fixture.state).unwrap();
        std::fs::create_dir(&fixture.state).unwrap();
        // Writing and flushing the temporary state succeeds, but rename
        // cannot replace a directory with a regular file.
        assert!(writer.append_raw(&fixture.record()).is_err());
        let after_first = std::fs::read(&fixture.log).unwrap();
        assert!(fixture.state.with_extension("state.tmp").is_file());
        std::fs::remove_dir(&fixture.state).unwrap();
        assert!(writer.append_raw(&fixture.record()).is_err());
        assert_eq!(std::fs::read(&fixture.log).unwrap(), after_first);
    }

    #[test]
    fn ratchet_and_hmac_are_deterministic() {
        let key = [7u8; 32];
        assert_ne!(next_ratchet_key(&key), key);
        assert_eq!(entry_hmac(&key, b"{}"), entry_hmac(&key, b"{}"));
        assert_eq!(record_hash(b"{}\n"), record_hash(b"{}\n"));
    }
}
