//! Canonical warrant/CSR contracts. These checks establish syntax and binding;
//! they do not replace signature, peer, policy, or sealed-FD authorization.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{
    CoreError, Result,
    crypto::{WARRANT_PAYLOAD_TYPE, strict_base64},
    json::canonical_bytes,
    protocol::{
        ClientHello, DsseEnvelope, ProtocolSchema, RequestedCommand, RequestedExecutionContext,
        parse_strict,
    },
};

pub const MAX_WARRANT_BYTES: usize = 65_536;
pub const MAX_TIMESTAMP: i64 = 253_402_300_799;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub allow_interpreted_script: bool,
    pub argv: Vec<String>,
    pub cwd: String,
    pub executable_path: String,
    #[serde(skip)]
    pub executable_sha256: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub executable_trust: Option<crate::executable::ExecutableTrust>,
    pub stdin_policy: String,
    #[serde(deserialize_with = "required_nullable")]
    pub stdin_sha256: Option<String>,
    pub tty_mode: String,
}

impl Command {
    pub fn requested(&self) -> RequestedCommand {
        RequestedCommand {
            allow_interpreted_script: self.allow_interpreted_script,
            argv: self.argv.clone(),
            cwd: self.cwd.clone(),
            executable_path: self.executable_path.clone(),
            stdin_policy: self.stdin_policy.clone(),
            tty_mode: self.tty_mode.clone(),
        }
    }
}

/// Signed context includes daemon-derived state, absent from unsigned input.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionContext {
    pub capabilities: Vec<String>,
    pub env_exact: std::collections::BTreeMap<String, String>,
    pub caller_env_allowlist: Vec<String>,
    pub supplementary_gids: Vec<u32>,
    pub target_gid: u32,
    pub target_uid: u32,
    pub umask: u32,
    #[serde(deserialize_with = "required_nullable")]
    pub post_exec_capabilities: Option<crate::executable::CapabilitySets>,
}
impl From<RequestedExecutionContext> for ExecutionContext {
    fn from(context: RequestedExecutionContext) -> Self {
        Self {
            capabilities: context.capabilities,
            env_exact: context.env_exact,
            caller_env_allowlist: context.caller_env_allowlist,
            supplementary_gids: context.supplementary_gids,
            target_gid: context.target_gid,
            target_uid: context.target_uid,
            umask: context.umask,
            post_exec_capabilities: None,
        }
    }
}
impl ExecutionContext {
    pub fn requested(&self) -> RequestedExecutionContext {
        RequestedExecutionContext {
            capabilities: self.capabilities.clone(),
            env_exact: self.env_exact.clone(),
            caller_env_allowlist: self.caller_env_allowlist.clone(),
            supplementary_gids: self.supplementary_gids.clone(),
            target_gid: self.target_gid,
            target_uid: self.target_uid,
            umask: self.umask,
        }
    }
    pub fn expected_capabilities(&self) -> crate::executable::CapabilitySets {
        self.post_exec_capabilities
            .clone()
            .unwrap_or_else(|| crate::executable::CapabilitySets::ordinary(&self.capabilities))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GrantPolicy {
    pub mode: String,
    #[serde(deserialize_with = "required_nullable")]
    pub not_after: Option<i64>,
    pub not_before: i64,
}

pub use crate::v3::Warrant;
impl ProtocolSchema for Warrant {}
impl ProtocolSchema for Command {}
impl ProtocolSchema for GrantPolicy {}
impl Warrant {
    /// Resolved internal view. The complete original selection remains signed
    /// in `intent`, including a named account before numeric resolution.
    pub fn intent(&self) -> Result<crate::protocol::ResolvedIntent> {
        use crate::host::Record;
        self.intent.validate()?;
        Ok(crate::protocol::ResolvedIntent {
            command: self.intent.command.clone(),
            execution_context: self.execution_context.requested(),
            policy: self.intent.policy.clone(),
            caller_env: self.intent.caller_env.clone(),
        })
    }
}

/// Retains the exact bytes verified/signed, with no mutable access to fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalWarrant {
    warrant: Warrant,
    bytes: Vec<u8>,
}

impl CanonicalWarrant {
    pub fn new(warrant: Warrant) -> Result<Self> {
        crate::host::Record::validate(&warrant)?;
        let bytes = crate::host::Record::canonical(&warrant)?;
        Ok(Self { warrant, bytes })
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_WARRANT_BYTES {
            return Err(invalid("warrant exceeds 65536 bytes"));
        }
        let canonical = Self::new(parse_strict(bytes)?)?;
        if canonical.bytes != bytes {
            return Err(invalid("warrant is not canonical JCS"));
        }
        Ok(canonical)
    }

    pub fn warrant(&self) -> &Warrant {
        &self.warrant
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Completed CSR: the warrant schema filled with measured snapshots and
/// daemon-provided identity. No field may change when approval comes back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Csr(CanonicalWarrant);

pub struct CsrIdentity {
    pub grant_id: String,
    pub host_id: String,
    pub requester_uid: u32,
    pub requester_gid: u32,
    pub now: i64,
    pub binding: Option<crate::host::BindingBundle>,
}

pub struct SnapshotDigests {
    pub post_exec_capabilities: Option<crate::executable::CapabilitySets>,
    pub executable_sha256: Option<String>,
    pub executable_trust: Option<crate::executable::ExecutableTrust>,
    pub stdin_sha256: Option<String>,
}

impl Csr {
    pub fn new(warrant: Warrant) -> Result<Self> {
        CanonicalWarrant::new(warrant).map(Self)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        CanonicalWarrant::parse(bytes).map(Self)
    }
    pub fn warrant(&self) -> &Warrant {
        self.0.warrant()
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The coordinator must supply kernel peer credentials, provisioned host,
    /// a fresh grant, and digests of the retained sealed FDs, never client claims.
    pub fn from_unsigned(
        hello: &ClientHello,
        identity: CsrIdentity,
        snapshots: SnapshotDigests,
        max_ttl_secs: u64,
    ) -> Result<Self> {
        hello.validate_request()?;
        if hello.mode != "thin_csr" {
            return Err(invalid("CSR requires unsigned request"));
        }
        let command = hello
            .requested_command
            .as_ref()
            .expect("validated unsigned request");
        let policy = hello
            .requested_policy
            .as_ref()
            .expect("validated unsigned request");
        if policy.ttl_secs > max_ttl_secs {
            return Err(invalid("TTL exceeds captured policy"));
        }
        let not_after = if policy.mode == "permanent" {
            None
        } else {
            let ttl = i64::try_from(policy.ttl_secs).map_err(|_| invalid("TTL overflow"))?;
            Some(
                identity
                    .now
                    .checked_add(ttl)
                    .ok_or_else(|| invalid("timestamp overflow"))?,
            )
        };
        let version = "3.0";
        let bundle = identity
            .binding
            .ok_or_else(|| invalid("live v3 host binding required"))?;
        use crate::host::Record;
        bundle.validate()?;
        let mut execution_context: ExecutionContext = hello
            .requested_execution_context
            .clone()
            .expect("validated unsigned request")
            .into();
        execution_context.post_exec_capabilities =
            Some(snapshots.post_exec_capabilities.unwrap_or_else(|| {
                crate::executable::CapabilitySets::ordinary(&execution_context.capabilities)
            }));
        let resolved = hello.intent()?;
        let original = hello
            .original_intent
            .clone()
            .ok_or_else(|| invalid("explicit v3 intent required"))?;
        if original.command != resolved.command
            || original.policy != resolved.policy
            || original.caller_env != resolved.caller_env
        {
            return Err(invalid("resolved intent differs from original"));
        }
        Self::new(Warrant {
            intent: original.clone(),
            target_binding: bundle.target_binding.clone(),
            security_constraints: bundle.binding()?.security_constraints,
            request_origin: "client_full".into(),
            intent_sha256: original.sha256()?,
            approval_exec_id: None,
            caller_env: hello.caller_env.clone(),
            command: Command {
                allow_interpreted_script: command.allow_interpreted_script,
                argv: command.argv.clone(),
                cwd: command.cwd.clone(),
                executable_path: command.executable_path.clone(),
                executable_sha256: None,
                executable_trust: snapshots.executable_trust.or_else(|| {
                    snapshots
                        .executable_sha256
                        .map(|sha256| crate::executable::ExecutableTrust::DigestMemfd { sha256 })
                }),
                stdin_policy: command.stdin_policy.clone(),
                stdin_sha256: snapshots.stdin_sha256,
                tty_mode: command.tty_mode.clone(),
            },
            execution_context,
            grant_id: identity.grant_id,
            host_id: identity.host_id,
            policy: GrantPolicy {
                mode: policy.mode.clone(),
                not_before: identity.now,
                not_after,
            },
            requester_uid: identity.requester_uid,
            requester_gid: identity.requester_gid,
            version: version.into(),
        })
    }

    /// Field/byte binding only; the caller must also verify the signature and
    /// run the full authorization gate against the retained snapshot FDs.
    pub fn bind_envelope(&self, envelope: &DsseEnvelope) -> Result<CanonicalWarrant> {
        let warrant = envelope.warrant()?;
        if self.as_bytes() != warrant.as_bytes() {
            return Err(invalid("approved warrant differs from CSR"));
        }
        Ok(warrant)
    }
}

impl DsseEnvelope {
    pub fn to_jcs(&self) -> Result<Vec<u8>> {
        self.warrant()?;
        canonical_bytes(self)
    }

    pub fn parse_jcs(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 524_288 {
            return Err(invalid("DSSE envelope exceeds frame ceiling"));
        }
        let envelope: Self = parse_strict(bytes)?;
        if envelope.to_jcs()? != bytes {
            return Err(invalid("DSSE envelope is not canonical JCS"));
        }
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<()> {
        // Apply the outer schema's string limits even to programmatically
        // constructed envelopes, and retain its larger Base64 field limits.
        let bytes = canonical_bytes(self)?;
        if bytes.len() > 524_288 {
            return Err(invalid("DSSE envelope exceeds frame ceiling"));
        }
        crate::json::preflight_with_string_limits(&bytes, 8, &Self::string_limit)?;
        if self.payload_type != WARRANT_PAYLOAD_TYPE || !(1..=4).contains(&self.signatures.len()) {
            return Err(invalid("invalid DSSE envelope shape"));
        }
        strict_base64(&self.payload, MAX_WARRANT_BYTES)?;
        for signature in &self.signatures {
            if signature.keyid.is_empty()
                || signature.keyid.len() > 128
                || !signature.keyid.is_ascii()
            {
                return Err(invalid("invalid signer keyid"));
            }
            if strict_base64(&signature.sig, 24_576)?.is_empty() {
                return Err(invalid("empty signature"));
            }
        }
        Ok(())
    }

    pub fn warrant(&self) -> Result<CanonicalWarrant> {
        self.validate()?;
        CanonicalWarrant::parse(&strict_base64(&self.payload, MAX_WARRANT_BYTES)?)
    }

    pub fn from_warrant(
        warrant: &CanonicalWarrant,
        signatures: Vec<crate::protocol::DsseSignature>,
    ) -> Result<Self> {
        let envelope = Self {
            payload: STANDARD.encode(warrant.as_bytes()),
            payload_type: WARRANT_PAYLOAD_TYPE.into(),
            signatures,
        };
        envelope.validate()?;
        Ok(envelope)
    }
}

pub(crate) fn required_nullable<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn invalid(message: &str) -> CoreError {
    CoreError::Protocol(message.into())
}
