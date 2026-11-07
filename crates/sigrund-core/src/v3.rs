//! Strict v3 host-only wire and signed-byte contracts. Runtime support must be
//! gated separately: parsing a valid document grants no execution authority.
use crate::{
    CoreError, Result,
    host::{self, Record},
    protocol::{RequestedCommand, RequestedPolicy},
    warrant::{Command, ExecutionContext, GrantPolicy, required_nullable},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
fn invalid(message: &str) -> CoreError {
    CoreError::Protocol(message.into())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentContext {
    pub capabilities: Vec<String>,
    pub env_exact: BTreeMap<String, String>,
    pub caller_env_allowlist: Vec<String>,
    pub umask: u32,
}
impl IntentContext {
    pub fn resolve(
        &self,
        uid: u32,
        gid: u32,
        groups: Vec<u32>,
    ) -> crate::protocol::RequestedExecutionContext {
        crate::protocol::RequestedExecutionContext {
            capabilities: self.capabilities.clone(),
            env_exact: self.env_exact.clone(),
            caller_env_allowlist: self.caller_env_allowlist.clone(),
            umask: self.umask,
            target_uid: uid,
            target_gid: gid,
            supplementary_gids: groups,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub command: RequestedCommand,
    pub execution_context: IntentContext,
    pub policy: RequestedPolicy,
    pub caller_env: BTreeMap<String, String>,
    pub target: host::Selector,
    pub account: host::Account,
    pub security_profile: String,
}
impl Record for Intent {
    fn validate(&self) -> Result<()> {
        self.target.validate_host()?;
        self.account.validate()?;
        host::identifier(&self.security_profile)?;
        let (uid, gid, groups) = match &self.account {
            host::Account::Numeric {
                uid,
                gid,
                supplementary_gids,
            } => (*uid, *gid, supplementary_gids.clone()),
            host::Account::Name { .. } => (0, 0, vec![]),
        };
        crate::protocol::validate_unsigned_request(
            &self.command,
            &self.execution_context.resolve(uid, gid, groups),
            &self.policy,
            &self.caller_env,
        )?;
        if self.policy.mode == "permanent" && self.policy.ttl_secs != 0 {
            return Err(invalid("permanent intent requires zero TTL"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Warrant {
    pub version: String,
    pub request_origin: String,
    pub intent_sha256: String,
    #[serde(deserialize_with = "required_nullable")]
    pub approval_exec_id: Option<String>,
    pub caller_env: BTreeMap<String, String>,
    pub command: Command,
    pub execution_context: ExecutionContext,
    pub grant_id: String,
    pub host_id: String,
    pub policy: GrantPolicy,
    pub requester_uid: u32,
    pub requester_gid: u32,
    pub intent: Intent,
    pub target_binding: host::TargetBinding,
    pub security_constraints: host::SecurityConstraints,
}
impl Record for Warrant {
    fn validate(&self) -> Result<()> {
        self.intent.validate()?;
        self.target_binding.validate()?;
        self.security_constraints.validate()?;
        if self.version != "3.0"
            || self.intent_sha256 != self.intent.sha256()?
            || self.security_constraints.profile_id != self.intent.security_profile
            || self.command.requested() != self.intent.command
            || self.caller_env != self.intent.caller_env
            || self.policy.mode != self.intent.policy.mode
        {
            return Err(invalid("v3 version or original intent mismatch"));
        }
        crate::crypto::validate_uuidv7(&self.grant_id)?;
        if !self
            .host_id
            .strip_prefix("sigrun-host:sha256:")
            .is_some_and(crate::warrant::valid_digest)
            || self.requester_uid == u32::MAX
            || self.requester_gid == u32::MAX
        {
            return Err(invalid("invalid warrant authority"));
        }
        match (self.request_origin.as_str(), &self.approval_exec_id) {
            ("client_full", None) => (),
            ("daemon_expanded_thin", Some(id)) => {
                crate::crypto::validate_uuidv7(id)?;
            }
            _ => return Err(invalid("invalid provenance")),
        }
        let ttl = match (self.policy.mode.as_str(), self.policy.not_after) {
            ("permanent", None) => 0,
            ("one_time" | "time_range", Some(end)) if end <= crate::warrant::MAX_TIMESTAMP => end
                .checked_sub(self.policy.not_before)
                .and_then(|n| u64::try_from(n).ok())
                .ok_or_else(|| invalid("invalid warrant validity"))?,
            _ => return Err(invalid("invalid warrant validity")),
        };
        if !(0..=crate::warrant::MAX_TIMESTAMP).contains(&self.policy.not_before)
            || ttl != self.intent.policy.ttl_secs
            || (self.request_origin == "daemon_expanded_thin" && self.policy.mode != "one_time")
        {
            return Err(invalid("validity or provenance does not match intent"));
        }
        let c = &self.execution_context;
        host::credentials(c.target_uid, c.target_gid, &c.supplementary_gids)?;
        if c.requested()
            != self.intent.execution_context.resolve(
                c.target_uid,
                c.target_gid,
                c.supplementary_gids.clone(),
            )
        {
            return Err(invalid("resolved context overrides intent"));
        }
        if let host::Account::Numeric {
            uid,
            gid,
            supplementary_gids,
        } = &self.intent.account
            && (*uid != c.target_uid
                || *gid != c.target_gid
                || *supplementary_gids != c.supplementary_gids)
        {
            return Err(invalid("resolved credentials override numeric account"));
        }
        if self.command.executable_sha256.is_some()
            || self
                .command
                .executable_trust
                .as_ref()
                .is_none_or(|t| !t.valid())
            || c.post_exec_capabilities
                .as_ref()
                .is_none_or(|sets| !sets.valid(&c.capabilities))
        {
            return Err(invalid("incomplete executable or capability evidence"));
        }
        match (
            self.command.stdin_policy.as_str(),
            &self.command.stdin_sha256,
        ) {
            ("null" | "unrestricted_interactive", None) => (),
            ("sha256", Some(d)) if crate::warrant::valid_digest(d) => (),
            _ => return Err(invalid("invalid stdin evidence")),
        }
        Ok(())
    }
}
impl Warrant {
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self> {
        Ok(crate::warrant::CanonicalWarrant::parse(bytes)?
            .warrant()
            .clone())
    }
    pub fn execution_binding(&self) -> Result<host::ExecutionBinding> {
        self.validate()?;
        Ok(host::ExecutionBinding {
            target_binding: self.target_binding.clone(),
            security_constraints: self.security_constraints.clone(),
        })
    }
    pub fn require_client_full(&self) -> Result<()> {
        self.validate()?;
        if self.request_origin != "client_full" {
            return Err(invalid("standalone thin approval forbidden"));
        }
        Ok(())
    }
    /// Verify the private record content used by the trusted approver. A valid
    /// bundle still needs a live retained instance and captured policy checks.
    pub fn verify_bundle(&self, bundle: &host::BindingBundle) -> Result<()> {
        self.validate()?;
        bundle.validate()?;
        let c = &bundle.constraints;
        if self.host_id != bundle.host_id
            || self.execution_binding()? != bundle.binding()?
            || self.execution_context.capabilities != c.capabilities
            || self.command.executable_trust.as_ref().map(|t| t.model()) != Some(c.executable_model)
        {
            return Err(invalid("approval bundle differs from warrant"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", deny_unknown_fields)]
pub enum Hello {
    #[serde(rename = "thin_csr")]
    Thin {
        version: String,
        tty_mode: String,
        caller_env: BTreeMap<String, String>,
        intent: Box<Intent>,
    },
    #[serde(rename = "full_csr")]
    Full {
        version: String,
        tty_mode: String,
        caller_env: BTreeMap<String, String>,
        csr_payload: String,
    },
    #[serde(rename = "signed")]
    Signed {
        version: String,
        tty_mode: String,
        caller_env: BTreeMap<String, String>,
        dsse_envelope: crate::protocol::DsseEnvelope,
    },
}
impl Hello {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 524_288 {
            return Err(invalid("hello exceeds frame ceiling"));
        }
        let hello: Self = crate::protocol::parse_strict(bytes)?;
        hello.validate()?;
        Ok(hello)
    }
    pub fn validate(&self) -> Result<()> {
        let (version, tty, caller, intent) = match self {
            Self::Thin {
                version,
                tty_mode,
                caller_env,
                intent,
            } => {
                intent.validate()?;
                (version, tty_mode, caller_env, (**intent).clone())
            }
            Self::Full {
                version,
                tty_mode,
                caller_env,
                csr_payload,
            } => {
                let w = Warrant::parse_canonical(csr_payload.as_bytes())?;
                w.require_client_full()?;
                (version, tty_mode, caller_env, w.intent)
            }
            Self::Signed {
                version,
                tty_mode,
                caller_env,
                dsse_envelope,
            } => {
                let w = envelope_warrant(dsse_envelope)?;
                w.require_client_full()?;
                (version, tty_mode, caller_env, w.intent)
            }
        };
        if version != "3.0" || tty != &intent.command.tty_mode || caller != &intent.caller_env {
            return Err(invalid("hello version or intent mismatch"));
        }
        Ok(())
    }
}
pub fn envelope_warrant(envelope: &crate::protocol::DsseEnvelope) -> Result<Warrant> {
    Ok(envelope.warrant()?.warrant().clone())
}

/// Verifies v3 bytes using only the v3 SSH namespace and payload type. The
/// caller must independently apply one signer's policy and live-instance gate.
pub fn verify_ssh_signature(
    signature_type: &str,
    public_key: &str,
    signature: &str,
    payload: &[u8],
    require_user_presence: bool,
    require_user_verification: bool,
) -> Result<()> {
    Warrant::parse_canonical(payload)?;
    crate::crypto::verify_ssh_signature_in_namespace(
        signature_type,
        public_key,
        signature,
        host::PAYLOAD_TYPE,
        payload,
        require_user_presence,
        require_user_verification,
        host::SSH_NAMESPACE,
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextQuery {
    pub version: String,
}
impl Record for ContextQuery {
    fn validate(&self) -> Result<()> {
        if self.version != "3.0" {
            return Err(invalid("unsupported context version"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextFeatures {
    pub direct_exec_checkpoint: bool,
    pub host_file_capabilities: bool,
    pub tty_modes: Vec<String>,
    pub stdin_policies: Vec<String>,
    pub grant_modes: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicContext {
    pub version: String,
    pub host_id: String,
    pub policy_generation: u64,
    pub executable_trust_models: Vec<crate::executable::TrustModel>,
    pub limits: crate::protocol::ContextLimits,
    pub features: ContextFeatures,
}
impl Record for PublicContext {
    fn validate(&self) -> Result<()> {
        let f = &self.features;
        if self.version != "3.0"
            || self.policy_generation == 0
            || !self
                .host_id
                .strip_prefix("sigrun-host:sha256:")
                .is_some_and(crate::warrant::valid_digest)
            || self.executable_trust_models.is_empty()
            || self.executable_trust_models.len() > 4
            || f.tty_modes != ["stdio"]
            || f.grant_modes != ["one_time"]
            || !matches!(f.stdin_policies.as_slice(), [null] if null == "null")
                && f.stdin_policies != ["null", "sha256"]
            || (f.host_file_capabilities && !f.direct_exec_checkpoint)
        {
            return Err(invalid("unsupported public host context"));
        }
        for (i, model) in self.executable_trust_models.iter().enumerate() {
            if self.executable_trust_models[..i].contains(model) {
                return Err(invalid("unsupported or duplicate context trust model"));
            }
        }
        let l = &self.limits;
        if !(1..=67_108_864).contains(&l.max_executable_bytes)
            || !(1..=1_073_741_824).contains(&l.max_direct_digest_bytes)
            || !(1..=30_000).contains(&l.direct_digest_timeout_ms)
            || !(1..=16_777_216).contains(&l.max_stdin_bytes)
            || l.max_ttl_secs == 0
            || l.max_onetime_window_secs == 0
            || !(1_000..=300_000).contains(&l.authorization_timeout_ms)
        {
            return Err(invalid("invalid public context limits"));
        }
        Ok(())
    }
}

/// Full private evidence for approval rendering. It is never a public response.
/// Rendering happens only after both record digests and the warrant match.
pub fn approval_evidence(warrant: &Warrant, bundle: &host::BindingBundle) -> Result<String> {
    warrant.verify_bundle(bundle)?;
    serde_json::to_string_pretty(&serde_json::json!({
        "authority": warrant.host_id,
        "provenance": warrant.request_origin,
        "intent_sha256": warrant.intent_sha256,
        "approval_exec_id": warrant.approval_exec_id,
        "target_binding": warrant.target_binding,
        "acquisition": bundle.acquisition,
        "security_constraints": bundle.constraints,
        "original_intent": warrant.intent,
        "resolved_execution_context": warrant.execution_context,
        "command_and_evidence": warrant.command,
        "requester_uid": warrant.requester_uid,
        "requester_gid": warrant.requester_gid,
        "grant_id": warrant.grant_id,
        "policy": warrant.policy,
    }))
    .map_err(|e| invalid(&e.to_string()))
}
