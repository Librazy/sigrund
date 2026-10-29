use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::crypto::{WARRANT_PAYLOAD_TYPE, strict_base64, validate_uuidv7};
use crate::{CoreError, Result};

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ChildExit {
    pub exit_code: Option<u8>,
    pub signal: Option<u8>,
}

impl ChildExit {
    pub fn validate(&self) -> Result<()> {
        if self.exit_code.is_some() == self.signal.is_some() {
            return Err(CoreError::Protocol(
                "exactly one child exit field must be non-null".into(),
            ));
        }
        if self
            .signal
            .is_some_and(|signal| !(1..=64).contains(&signal))
        {
            return Err(CoreError::Protocol(
                "signal is outside Linux signal bounds".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub csr_payload: Option<String>,
    pub exec_id: String,
    pub message: String,
    pub status: String,
}

impl Decision {
    pub fn validate(&self) -> Result<()> {
        const STATUSES: &[&str] = &[
            "READY_TO_EXEC",
            "REJECTED",
            "TIMEOUT_CSR",
            "INVALID_REQUEST",
            "INVALID_TTY_STDIN_COMBINATION",
            "POLICY_VIOLATION",
            "EXPIRED_OR_NOT_YET_VALID",
            "REVOKED",
            "REPLAY_DETECTED",
            "EXECUTABLE_MUTATED_OR_TOO_LARGE",
            "STDIN_HASH_MISMATCH",
            "REMOTE_AUDIT_FAILED",
            "REQUEST_TIMEOUT",
            "RESOURCE_EXHAUSTED",
            "SPAWN_FAILED",
        ];
        if !STATUSES.contains(&self.status.as_str()) || self.message.len() > 4096 {
            return Err(CoreError::Protocol(
                "invalid authorization decision bounds".into(),
            ));
        }
        validate_uuidv7(&self.exec_id)?;
        if self.status == "TIMEOUT_CSR" {
            if self
                .csr_payload
                .as_ref()
                .is_none_or(|payload| payload.len() > 65_536)
            {
                return Err(CoreError::Protocol(
                    "TIMEOUT_CSR requires bounded csr_payload".into(),
                ));
            }
        } else if self.csr_payload.is_some() {
            return Err(CoreError::Protocol(
                "csr_payload is only valid for TIMEOUT_CSR".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelope {
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequestedCommand {
    pub allow_interpreted_script: bool,
    pub argv: Vec<String>,
    pub cwd: String,
    pub executable_path: String,
    pub stdin_policy: String,
    pub tty_mode: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequestedExecutionContext {
    pub capabilities: Vec<String>,
    pub env_exact: BTreeMap<String, String>,
    pub caller_env_allowlist: Vec<String>,
    pub supplementary_gids: Vec<u32>,
    pub target_gid: u32,
    pub target_uid: u32,
    pub umask: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequestedPolicy {
    pub mode: String,
    pub ttl_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientHello {
    pub caller_env: BTreeMap<String, String>,
    pub mode: String,
    pub tty_mode: String,
    pub dsse_envelope: Option<DsseEnvelope>,
    pub requested_command: Option<RequestedCommand>,
    pub requested_execution_context: Option<RequestedExecutionContext>,
    pub requested_policy: Option<RequestedPolicy>,
}

impl ClientHello {
    pub fn validate_shape(&self) -> Result<()> {
        if !matches!(self.tty_mode.as_str(), "stdio" | "pty") {
            return Err(CoreError::Protocol("invalid tty_mode".into()));
        }
        match self.mode.as_str() {
            "signed" if self.dsse_envelope.is_some() && self.requested_command.is_none() => {
                let envelope = self.dsse_envelope.as_ref().unwrap();
                if envelope.payload_type != WARRANT_PAYLOAD_TYPE
                    || envelope.signatures.is_empty()
                    || envelope.signatures.len() > 4
                {
                    return Err(CoreError::Protocol("invalid DSSE envelope shape".into()));
                }
                strict_base64(&envelope.payload, 65_536)?;
                for signature in &envelope.signatures {
                    if signature.keyid.is_empty()
                        || signature.keyid.len() > 128
                        || !signature.keyid.is_ascii()
                    {
                        return Err(CoreError::Protocol("invalid signer keyid".into()));
                    }
                    strict_base64(&signature.sig, 32_768)?;
                }
            }
            "unsigned_csr_request"
                if self.dsse_envelope.is_none()
                    && self.requested_command.is_some()
                    && self.requested_execution_context.is_some()
                    && self.requested_policy.is_some() =>
            {
                let command = self.requested_command.as_ref().unwrap();
                if command.tty_mode != self.tty_mode {
                    return Err(CoreError::Protocol(
                        "unsigned tty_mode fields differ".into(),
                    ));
                }
            }
            _ => {
                return Err(CoreError::Protocol(
                    "CLIENT_HELLO mode fields are inconsistent".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TargetAuth {
    pub auth_commit_seq: u64,
    pub exec_id: String,
    pub grant_id: String,
    pub host_id: String,
    pub not_after: Option<i64>,
    pub not_before: i64,
    pub payload_sha256: String,
    pub policy_mode: String,
    pub signer_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RemoteAuditBatchRequest {
    pub first_seq: u64,
    pub last_seq: u64,
    pub host_id: String,
    pub records_jcs: Vec<String>,
    pub target_auth: Option<TargetAuth>,
}

impl RemoteAuditBatchRequest {
    pub fn validate(&self) -> Result<()> {
        if self.host_id.is_empty() || self.first_seq > self.last_seq {
            return Err(CoreError::Protocol("invalid audit batch bounds".into()));
        }
        let expected = self
            .last_seq
            .checked_sub(self.first_seq)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| CoreError::Protocol("audit sequence overflow".into()))?;
        if self.records_jcs.len() != expected as usize
            || self.records_jcs.is_empty()
            || self.records_jcs.len() > 256
        {
            return Err(CoreError::Protocol(
                "audit batch record count mismatch".into(),
            ));
        }
        if self.records_jcs.iter().any(|record| record.len() > 65_536) {
            return Err(CoreError::Protocol(
                "audit record exceeds 65536 bytes".into(),
            ));
        }
        if self.records_jcs.iter().map(String::len).sum::<usize>() > 1_048_576 {
            return Err(CoreError::Protocol("audit batch exceeds 1 MiB".into()));
        }
        if let Some(target) = &self.target_auth {
            validate_uuidv7(&target.exec_id)?;
            validate_uuidv7(&target.grant_id)?;
            if target.payload_sha256.len() != 64
                || !target
                    .payload_sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(CoreError::Protocol(
                    "payload_sha256 must be lowercase hex".into(),
                ));
            }
            if target.not_before < 0
                || target
                    .not_after
                    .is_some_and(|value| value < target.not_before)
            {
                return Err(CoreError::Protocol("invalid target validity bounds".into()));
            }
            if !matches!(
                target.policy_mode.as_str(),
                "one_time" | "time_range" | "permanent"
            ) {
                return Err(CoreError::Protocol("unknown target policy mode".into()));
            }
            if target.policy_mode == "permanent" && target.not_after.is_some() {
                return Err(CoreError::Protocol(
                    "permanent target must have null not_after".into(),
                ));
            }
            if target.policy_mode != "permanent" && target.not_after.is_none() {
                return Err(CoreError::Protocol(
                    "bounded target must have not_after".into(),
                ));
            }
        }
        Ok(())
    }
}

pub fn parse_strict<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    crate::json::preflight(bytes, 8, 4096)?;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer).map_err(|e| CoreError::Json(e.to_string()))?;
    deserializer
        .end()
        .map_err(|e| CoreError::Json(format!("trailing JSON: {e}")))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_exit_fields_are_exclusive() {
        assert!(
            ChildExit {
                exit_code: Some(0),
                signal: None
            }
            .validate()
            .is_ok()
        );
        assert!(
            ChildExit {
                exit_code: None,
                signal: Some(9)
            }
            .validate()
            .is_ok()
        );
        assert!(
            ChildExit {
                exit_code: None,
                signal: None
            }
            .validate()
            .is_err()
        );
    }
}
