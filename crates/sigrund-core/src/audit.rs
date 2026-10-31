use crate::crypto::sha256_hex;
use crate::{CoreError, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    path::{Path, PathBuf},
};

pub const RATCHET_DOMAIN: &[u8] = b"sigrun-ratchet-v1";
const MAX_RECORD_BYTES: usize = 65_536;

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
    if record.is_empty() || record.len() > MAX_RECORD_BYTES || record.contains(&b'\n') {
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
    state_directory: File,
    state_name: PathBuf,
    log: File,
    state: RatchetState,
    key: [u8; 32],
    host_id: String,
    usable: bool,
}

impl AuditLog {
    pub fn open(log_path: impl AsRef<Path>, state_path: impl AsRef<Path>) -> Result<Self> {
        Self::open_checked(log_path.as_ref(), state_path.as_ref(), None)
    }

    /// Verify the recovered history belongs to the provisioned host before
    /// making any recovery writes.
    pub fn open_for_host(
        log_path: impl AsRef<Path>,
        state_path: impl AsRef<Path>,
        host_id: &str,
    ) -> Result<Self> {
        Self::open_checked(log_path.as_ref(), state_path.as_ref(), Some(host_id))
    }

    fn open_checked(
        log_path: &Path,
        state_path: &Path,
        expected_host: Option<&str>,
    ) -> Result<Self> {
        let state_directory = File::open(
            state_path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )
        .map_err(|e| CoreError::Database(format!("open audit state directory: {e}")))?;
        let state_file = File::open(state_path)
            .map_err(|e| CoreError::Database(format!("read audit state: {e}")))?;
        let log = OpenOptions::new()
            .read(true)
            .append(true)
            .open(log_path)
            .map_err(|e| CoreError::Database(format!("open audit log: {e}")))?;
        Self::from_verified_files(
            log,
            state_file,
            state_directory,
            Path::new(
                state_path
                    .file_name()
                    .ok_or_else(|| CoreError::Value("audit state needs a filename".into()))?,
            ),
            expected_host,
        )
    }

    /// Recover using the exact files and directory checked by the caller.
    /// The directory must be readable for fsync and trusted against entry
    /// replacement. No original pathname is resolved during recovery/appends.
    pub fn from_verified_files(
        log: File,
        mut state_file: File,
        state_directory: File,
        state_name: &Path,
        expected_host: Option<&str>,
    ) -> Result<Self> {
        if state_name.as_os_str().is_empty()
            || state_name.as_os_str().as_bytes().contains(&b'/')
            || matches!(state_name.to_str(), Some("." | ".."))
        {
            return Err(CoreError::Value(
                "audit state must be a single filename".into(),
            ));
        }
        let mut state_bytes = Vec::new();
        state_file
            .read_to_end(&mut state_bytes)
            .map_err(|e| CoreError::Database(format!("read audit state: {e}")))?;
        let state: RatchetState = serde_json::from_slice(&state_bytes)
            .map_err(|e| CoreError::Database(format!("parse audit state: {e}")))?;
        let key = decode_hex_32(&state.key_hex)?;
        let initial_key = state
            .initial_key_hex
            .as_deref()
            .map(decode_hex_32)
            .transpose()?;
        let mut writer = Self {
            state_directory,
            state_name: state_name.to_owned(),
            log,
            state,
            key,
            host_id: String::new(),
            usable: true,
        };
        let recovery = recover_log_state(&mut writer.log, &writer.state, initial_key.as_ref())?;
        if expected_host.is_some_and(|host| host != recovery.host_id) {
            return Err(CoreError::Database(
                "audit history does not match host identity".into(),
            ));
        }
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
            RecoveryAction::Forward { last_hash } => {
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

    /// Authenticates an event using the current sequencer-owned ratchet key.
    /// Callers cannot override host, sequence, chain link or authentication.
    /// The captured policy limit is checked before any append is attempted.
    pub fn append_event(
        &mut self,
        event_type: &str,
        fields: serde_json::Value,
        max_record_bytes: usize,
    ) -> Result<u64> {
        if max_record_bytes == 0 || max_record_bytes > MAX_RECORD_BYTES {
            return Err(CoreError::Value(
                "audit record limit outside protocol bounds".into(),
            ));
        }
        let serde_json::Value::Object(mut body) = fields else {
            return Err(CoreError::Value(
                "audit event fields must be an object".into(),
            ));
        };
        if event_type.is_empty()
            || event_type.len() > 128
            || !event_type.is_ascii()
            || [
                "event_type",
                "host_id",
                "seq",
                "prev_record_sha256",
                "entry_hmac",
            ]
            .iter()
            .any(|name| body.contains_key(*name))
        {
            return Err(CoreError::Value(
                "invalid event type or reserved audit field".into(),
            ));
        }
        body.insert("event_type".into(), event_type.into());
        body.insert("host_id".into(), self.host_id.clone().into());
        body.insert("seq".into(), self.state.seq.into());
        body.insert(
            "prev_record_sha256".into(),
            self.state.last_record_sha256.clone().into(),
        );
        let body_bytes = crate::json::canonical_bytes(&body)?;
        body.insert(
            "entry_hmac".into(),
            entry_hmac(&self.key, &body_bytes).into(),
        );
        let record = crate::json::canonical_bytes(&body)?;
        if record.len() > max_record_bytes {
            return Err(CoreError::Value(
                "audit event exceeds captured record limit".into(),
            ));
        }
        self.append_raw(&record)
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
        self.publish_state(&state_bytes)?;
        self.state = next_state;
        self.key = next_key;
        self.usable = true;
        Ok(seq)
    }
}

impl AuditLog {
    fn append_recovery(&mut self, event_type: &str) -> Result<()> {
        self.append_event(event_type, serde_json::json!({}), MAX_RECORD_BYTES)
            .map(|_| ())
    }

    fn persist_state(&self) -> Result<()> {
        let state_bytes = serde_json::to_vec(&self.state)
            .map_err(|e| CoreError::Database(format!("serialize audit state: {e}")))?;
        self.publish_state(&state_bytes)
    }

    fn publish_state(&self, state_bytes: &[u8]) -> Result<()> {
        let temp_name = self.state_name.with_extension("state.tmp");
        let temp_name = CString::new(temp_name.as_os_str().as_bytes())
            .map_err(|_| CoreError::Value("NUL in audit state filename".into()))?;
        let state_name = CString::new(self.state_name.as_os_str().as_bytes())
            .map_err(|_| CoreError::Value("NUL in audit state filename".into()))?;
        let directory = self.state_directory.as_raw_fd();
        let fd = unsafe {
            libc::openat(
                directory,
                temp_name.as_ptr(),
                libc::O_CREAT
                    | libc::O_WRONLY
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(CoreError::Database(format!(
                "open audit state temporary file: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut temp = unsafe { File::from_raw_fd(fd) };
        if !temp
            .metadata()
            .map_err(|e| CoreError::Database(format!("stat audit temporary file: {e}")))?
            .is_file()
        {
            return Err(CoreError::Database(
                "audit temporary file is not regular".into(),
            ));
        }
        // mode applies only on creation; secure stale temporary files too.
        temp.set_permissions(std::fs::Permissions::from_mode(0o600))
            .and_then(|_| temp.set_len(0))
            .map_err(|e| CoreError::Database(format!("secure audit state temporary file: {e}")))?;
        temp.write_all(state_bytes)
            .and_then(|_| temp.sync_all())
            .map_err(|e| CoreError::Database(format!("flush audit state: {e}")))?;
        drop(temp);
        if unsafe {
            libc::renameat(
                directory,
                temp_name.as_ptr(),
                directory,
                state_name.as_ptr(),
            )
        } != 0
        {
            return Err(CoreError::Database(format!(
                "rename audit state: {}",
                std::io::Error::last_os_error()
            )));
        }
        self.state_directory
            .sync_all()
            .map_err(|e| CoreError::Database(format!("sync audit state directory: {e}")))
    }
}

/// A partial tail and one complete unratcheted record are distinct recovery
/// cases. No action may combine truncation with a forward ratchet transition.
enum RecoveryAction {
    None,
    Truncate { offset: u64 },
    Forward { last_hash: String },
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
    log.seek(SeekFrom::Start(0))
        .map_err(|e| CoreError::Database(format!("seek audit log: {e}")))?;
    scan_log_state(&mut BufReader::new(log), state, initial_key)
}

fn scan_log_state(
    reader: &mut impl BufRead,
    state: &RatchetState,
    initial_key: Option<&[u8; 32]>,
) -> Result<RecoveryResult> {
    if state.seq == 0 || state.remote_acked_seq >= state.seq {
        return Err(CoreError::Database(
            "AUDIT_TAMPER_OR_CORRUPTION: invalid state sequence".into(),
        ));
    }
    let initial = initial_key.ok_or_else(|| {
        CoreError::Database("AUDIT_TAMPER_OR_CORRUPTION: state has no initial ratchet key".into())
    })?;
    let mut key = *initial;
    let state_key = decode_hex_32(&state.key_hex)?;
    let mut previous_hash = "0".repeat(64);
    let mut host_id: Option<String> = None;
    let mut complete_count = 0u64;
    let mut valid_eof = 0u64;
    let mut record = Vec::with_capacity(MAX_RECORD_BYTES + 1);
    let partial = loop {
        record.clear();
        // read_until alone is unbounded on a corrupt/unterminated line. Take
        // at most one record plus its delimiter, reusing this buffer for the
        // entire history, and verify it before reading the next record.
        let read = Read::by_ref(reader)
            .take((MAX_RECORD_BYTES + 1) as u64)
            .read_until(b'\n', &mut record)
            .map_err(|e| CoreError::Database(format!("read audit log: {e}")))?;
        if read == 0 {
            break false;
        }
        if record.last() != Some(&b'\n') {
            if record.len() > MAX_RECORD_BYTES {
                return Err(CoreError::Database(
                    "AUDIT_TAMPER_OR_CORRUPTION: oversized audit record".into(),
                ));
            }
            break true;
        }
        record.pop();
        if complete_count > state.seq {
            return Err(CoreError::Database(
                "AUDIT_TAMPER_OR_CORRUPTION: log ahead of state".into(),
            ));
        }
        let (seq, previous) = record_metadata(&record)?;
        if seq != complete_count || previous != previous_hash {
            return Err(CoreError::Database(
                "AUDIT_TAMPER_OR_CORRUPTION: audit chain mismatch".into(),
            ));
        }
        let record_host = record_host_id(&record)?;
        if let Some(expected_host) = host_id.as_deref() {
            if record_host != expected_host {
                return Err(CoreError::Database(
                    "AUDIT_TAMPER_OR_CORRUPTION: audit host_id mismatch".into(),
                ));
            }
        } else {
            host_id = Some(record_host);
        }
        verify_record_hmac(&record, &key)?;
        previous_hash = record_hash(&record);
        key = next_ratchet_key(&key);
        complete_count = complete_count
            .checked_add(1)
            .ok_or_else(|| CoreError::Database("audit sequence overflow".into()))?;
        valid_eof = valid_eof
            .checked_add(read as u64)
            .ok_or_else(|| CoreError::Database("audit offset overflow".into()))?;
        // Check the persisted checkpoint as soon as we reach it. Only the
        // current key/hash and final byte offset need survive the next read.
        if complete_count == state.seq
            && (previous_hash != state.last_record_sha256 || key != state_key)
        {
            return Err(CoreError::Database(
                "AUDIT_TAMPER_OR_CORRUPTION: log/state mismatch".into(),
            ));
        }
    };
    let host_id = host_id.ok_or_else(|| {
        CoreError::Database("AUDIT_TAMPER_OR_CORRUPTION: log is missing history".into())
    })?;
    if complete_count == state.seq {
        if partial {
            return Ok(RecoveryResult {
                action: RecoveryAction::Truncate { offset: valid_eof },
                host_id,
            });
        }
        return Ok(RecoveryResult {
            action: RecoveryAction::None,
            host_id,
        });
    }
    if complete_count.checked_sub(state.seq) == Some(1) {
        if partial {
            return Err(CoreError::Database(
                "AUDIT_TAMPER_OR_CORRUPTION: partial tail after unratcheted record".into(),
            ));
        }
        return Ok(RecoveryResult {
            action: RecoveryAction::Forward {
                last_hash: previous_hash,
            },
            host_id,
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
    if !value.len().is_multiple_of(2)
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
    fn event_builder_authenticates_sequence_host_and_fields_and_checks_bounds_before_writing() {
        let fixture = Fixture::new();
        let mut writer = AuditLog::open(&fixture.log, &fixture.state).unwrap();
        let original_log = std::fs::read(&fixture.log).unwrap();
        let original_state = writer.state().clone();
        for name in [
            "event_type",
            "host_id",
            "seq",
            "prev_record_sha256",
            "entry_hmac",
        ] {
            let fields = serde_json::json!({ name: "spoofed" });
            assert!(
                writer
                    .append_event("AUTH_REJECTED", fields, MAX_RECORD_BYTES)
                    .is_err()
            );
        }
        assert!(
            writer
                .append_event("AUTH_COMMIT", serde_json::json!({"exec_id":"fixture"}), 1)
                .is_err()
        );
        assert_eq!(writer.state(), &original_state);
        assert_eq!(std::fs::read(&fixture.log).unwrap(), original_log);
        assert_eq!(writer.append_event("AUTH_COMMIT", serde_json::json!({"exec_id":"fixture","grant_id":"test","payload_sha256":"f".repeat(64)}), MAX_RECORD_BYTES).unwrap(), 1);
        assert_eq!(
            writer
                .append_event(
                    "AUTH_ABORTED_POST_COMMIT",
                    serde_json::json!({"exec_id":"fixture","reason":"phase5 unavailable"}),
                    MAX_RECORD_BYTES
                )
                .unwrap(),
            2
        );
        drop(writer);
        let reopened = AuditLog::open(&fixture.log, &fixture.state).unwrap();
        assert_eq!(reopened.state().seq, 3);
        let records: Vec<serde_json::Value> = std::fs::read_to_string(&fixture.log)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records[1]["event_type"], "AUTH_COMMIT");
        assert_eq!(records[2]["event_type"], "AUTH_ABORTED_POST_COMMIT");
        assert_eq!(records[1]["host_id"], records[0]["host_id"]);
    }

    #[test]
    fn appends_and_state_publication_retain_the_open_directory_after_rename() {
        let fixture = Fixture::new();
        let mut writer = AuditLog::open(&fixture.log, &fixture.state).unwrap();
        let relocated = tempfile::tempdir().unwrap();
        let pinned = relocated.path().join("verified");
        std::fs::rename(fixture._dir.path(), &pinned).unwrap();
        std::fs::create_dir(fixture._dir.path()).unwrap();
        std::fs::write(&fixture.log, b"replacement log").unwrap();
        std::fs::write(&fixture.state, b"replacement state").unwrap();
        writer.append_raw(&fixture.record()).unwrap();
        assert_eq!(std::fs::read(&fixture.log).unwrap(), b"replacement log");
        assert_eq!(std::fs::read(&fixture.state).unwrap(), b"replacement state");
        assert!(!fixture.state.with_extension("state.tmp").exists());
        let reopened = AuditLog::open(
            pinned.join("audit.jsonl"),
            pinned.join("audit_ratchet.state"),
        )
        .unwrap();
        assert_eq!(reopened.state().seq, 2);
        assert_eq!(
            reopened.state().last_record_sha256,
            record_hash(&fixture.record())
        );
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
    fn partial_tail_after_unratcheted_record_is_corruption_and_remains_untouched() {
        let fixture = Fixture::new();
        let state_before = std::fs::read(&fixture.state).unwrap();
        let log_before = [
            append_line_bytes(&fixture.genesis).unwrap(),
            append_line_bytes(&fixture.record()).unwrap(),
            b"partial next record".to_vec(),
        ]
        .concat();
        std::fs::write(&fixture.log, &log_before).unwrap();
        assert!(AuditLog::open(&fixture.log, &fixture.state).is_err());
        assert_eq!(std::fs::read(&fixture.log).unwrap(), log_before);
        assert_eq!(std::fs::read(&fixture.state).unwrap(), state_before);
    }

    #[test]
    fn streaming_scan_authenticates_each_record_before_reading_more_history() {
        struct FailAfterRecord(std::io::Cursor<Vec<u8>>);
        impl Read for FailAfterRecord {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.0.position() == self.0.get_ref().len() as u64 {
                    return Err(std::io::Error::other("later history must not be read"));
                }
                self.0.read(buffer)
            }
        }
        let fixture = Fixture::new();
        let state: RatchetState =
            serde_json::from_slice(&std::fs::read(&fixture.state).unwrap()).unwrap();
        let mut record: serde_json::Value = serde_json::from_slice(&fixture.genesis).unwrap();
        record["entry_hmac"] = "00".repeat(32).into();
        let bytes = append_line_bytes(&serde_json::to_vec(&record).unwrap()).unwrap();
        let mut reader = BufReader::new(FailAfterRecord(std::io::Cursor::new(bytes)));
        let error = scan_log_state(&mut reader, &state, Some(&[7; 32]))
            .err()
            .unwrap();
        assert!(error.to_string().contains("invalid entry_hmac"), "{error}");
    }

    #[test]
    fn streaming_scan_bounds_unterminated_records_and_rejects_blank_lines() {
        let fixture = Fixture::new();
        let state: RatchetState =
            serde_json::from_slice(&std::fs::read(&fixture.state).unwrap()).unwrap();
        let source_limit = (MAX_RECORD_BYTES * 2) as u64;
        let mut source = std::io::repeat(b'x').take(source_limit);
        let mut reader = BufReader::with_capacity(8192, &mut source);
        let error = scan_log_state(&mut reader, &state, Some(&[7; 32]))
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("oversized audit record"),
            "{error}"
        );
        drop(reader);
        assert!(source_limit - source.limit() <= (MAX_RECORD_BYTES + 1 + 8192) as u64);
        let bytes = [append_line_bytes(&fixture.genesis).unwrap(), b"\n".to_vec()].concat();
        std::fs::write(&fixture.log, &bytes).unwrap();
        assert!(AuditLog::open(&fixture.log, &fixture.state).is_err());
        assert_eq!(std::fs::read(&fixture.log).unwrap(), bytes);
    }

    #[test]
    fn streaming_recovery_handles_history_larger_than_its_record_buffer() {
        let fixture = Fixture::new();
        let mut state: RatchetState =
            serde_json::from_slice(&std::fs::read(&fixture.state).unwrap()).unwrap();
        let mut key = decode_hex_32(&state.key_hex).unwrap();
        let mut log = OpenOptions::new().append(true).open(&fixture.log).unwrap();
        for seq in 1..=512 {
            let mut record = serde_json::json!({
                "event_type": "TEST", "host_id": "host", "seq": seq,
                "prev_record_sha256": state.last_record_sha256, "data": "x".repeat(4096),
            });
            record["entry_hmac"] = entry_hmac(&key, &serde_json::to_vec(&record).unwrap()).into();
            let bytes = serde_json::to_vec(&record).unwrap();
            log.write_all(&append_line_bytes(&bytes).unwrap()).unwrap();
            key = next_ratchet_key(&key);
            state.key_hex = encode_hex(&key);
            state.last_record_sha256 = record_hash(&bytes);
            state.seq = seq + 1;
        }
        log.sync_all().unwrap();
        assert!(log.metadata().unwrap().len() > 2_000_000);
        std::fs::write(&fixture.state, serde_json::to_vec(&state).unwrap()).unwrap();
        let reopened = AuditLog::open(&fixture.log, &fixture.state).unwrap();
        assert_eq!(reopened.state(), &state);
        // Corruption in old history must still fail, even when the final
        // record and persisted checkpoint remain unchanged.
        use std::os::unix::fs::FileExt;
        OpenOptions::new()
            .write(true)
            .open(&fixture.log)
            .unwrap()
            .write_at(b"!", 10)
            .unwrap();
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
