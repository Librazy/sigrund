//! Root approval broker documents. Transport/peer authentication is Phase 1.
//!
//! Broker frames are a four-byte big-endian body length followed by one JCS
//! document. Both directions share the bounded body size below; no SCM_RIGHTS
//! is permitted on this socket. Authentication precedes parsing in the runtime.
use serde::{Deserialize, Serialize};

use crate::{
    CoreError, Result,
    crypto::validate_uuidv7,
    json::canonical_bytes,
    protocol::{DsseEnvelope, ProtocolSchema, parse_strict},
    warrant::{CanonicalWarrant, Csr},
};

pub const MAX_APPROVAL_MESSAGE_BYTES: usize = 524_288;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub exec_id: String,
    pub signer_id: String,
    pub csr_payload: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalResponse {
    Approved {
        exec_id: String,
        dsse_envelope: DsseEnvelope,
    },
    Rejected {
        exec_id: String,
        reason: String,
    },
}

impl ProtocolSchema for ApprovalRequest {
    fn string_limit(path: &[String]) -> usize {
        match path.last().map(String::as_str) {
            Some("csr_payload") if path.len() == 1 => 65_536,
            Some("signer_id") if path.len() == 1 => 128,
            _ => 4096,
        }
    }
}

impl ProtocolSchema for ApprovalResponse {
    fn string_limit(path: &[String]) -> usize {
        if path.first().is_some_and(|field| field == "dsse_envelope") {
            DsseEnvelope::string_limit(&path[1..])
        } else if path.len() == 1 && path[0] == "reason" {
            1024
        } else {
            4096
        }
    }
}

impl ApprovalRequest {
    pub fn new(exec_id: String, signer_id: String, csr: &Csr) -> Result<Self> {
        let request = Self {
            exec_id,
            signer_id,
            csr_payload: String::from_utf8(csr.as_bytes().to_vec()).expect("JCS is UTF-8"),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        check_bounds(self)?;
        validate_uuidv7(&self.exec_id)?;
        if self.signer_id.is_empty() || !self.signer_id.is_ascii() {
            return Err(invalid("invalid approval signer_id"));
        }
        Csr::parse(self.csr_payload.as_bytes())?;
        Ok(())
    }

    pub fn to_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical_bytes(self)
    }
    pub fn parse_jcs(bytes: &[u8]) -> Result<Self> {
        let request: Self = parse_canonical(bytes)?;
        request.validate()?;
        Ok(request)
    }

    /// Binds the response to this execution, selected signer, and every CSR
    /// byte. This is not cryptographic verification or execution authorization.
    pub fn bind_response(&self, response: &ApprovalResponse) -> Result<Option<CanonicalWarrant>> {
        self.validate()?;
        response.validate()?;
        let exec_id = match response {
            ApprovalResponse::Approved { exec_id, .. }
            | ApprovalResponse::Rejected { exec_id, .. } => exec_id,
        };
        if self.exec_id != *exec_id {
            return Err(invalid("approval execution ID mismatch"));
        }
        match response {
            ApprovalResponse::Approved { dsse_envelope, .. } => {
                if dsse_envelope.signatures.len() != 1
                    || dsse_envelope.signatures[0].keyid != self.signer_id
                {
                    return Err(invalid("approval signer mismatch"));
                }
                Csr::parse(self.csr_payload.as_bytes())?
                    .bind_envelope(dsse_envelope)
                    .map(Some)
            }
            ApprovalResponse::Rejected { .. } => Ok(None),
        }
    }
}

impl ApprovalResponse {
    pub fn validate(&self) -> Result<()> {
        check_bounds(self)?;
        match self {
            Self::Approved {
                exec_id,
                dsse_envelope,
            } => {
                validate_uuidv7(exec_id)?;
                dsse_envelope.warrant()?;
            }
            Self::Rejected { exec_id, reason } => {
                validate_uuidv7(exec_id)?;
                if reason.is_empty() {
                    return Err(invalid("empty approval rejection reason"));
                }
            }
        }
        Ok(())
    }
    pub fn to_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical_bytes(self)
    }
    pub fn parse_jcs(bytes: &[u8]) -> Result<Self> {
        let response: Self = parse_canonical(bytes)?;
        response.validate()?;
        Ok(response)
    }
}

fn parse_canonical<T: for<'de> Deserialize<'de> + Serialize + ProtocolSchema>(
    bytes: &[u8],
) -> Result<T> {
    if bytes.len() > MAX_APPROVAL_MESSAGE_BYTES {
        return Err(invalid("approval message too large"));
    }
    let value: T = parse_strict(bytes)?;
    if canonical_bytes(&value)? != bytes {
        return Err(invalid("approval message is not canonical JCS"));
    }
    Ok(value)
}

fn check_bounds<T: Serialize + ProtocolSchema>(value: &T) -> Result<()> {
    let bytes = canonical_bytes(value)?;
    if bytes.len() > MAX_APPROVAL_MESSAGE_BYTES {
        return Err(invalid("approval message too large"));
    }
    crate::json::preflight_with_string_limits(&bytes, 8, &T::string_limit)
}

fn invalid(message: &str) -> CoreError {
    CoreError::Protocol(message.into())
}
