use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::crypto::validate_uuidv7;
use crate::{CoreError, Result};

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct ChildExit {
    pub exit_code: Option<u8>,
    pub signal: Option<u8>,
}

impl<'de> Deserialize<'de> for ChildExit {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ChildExitVisitor;
        impl<'de> serde::de::Visitor<'de> for ChildExitVisitor {
            type Value = ChildExit;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object with exit_code and signal")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut exit_code = None;
                let mut signal = None;
                let mut exit_seen = false;
                let mut signal_seen = false;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "exit_code" => {
                            if exit_seen {
                                return Err(serde::de::Error::duplicate_field("exit_code"));
                            }
                            exit_seen = true;
                            exit_code = Some(map.next_value::<Option<u8>>()?);
                        }
                        "signal" => {
                            if signal_seen {
                                return Err(serde::de::Error::duplicate_field("signal"));
                            }
                            signal_seen = true;
                            signal = Some(map.next_value::<Option<u8>>()?);
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                &key,
                                &["exit_code", "signal"],
                            ));
                        }
                    }
                }
                if !exit_seen {
                    return Err(serde::de::Error::missing_field("exit_code"));
                }
                if !signal_seen {
                    return Err(serde::de::Error::missing_field("signal"));
                }
                Ok(ChildExit {
                    exit_code: exit_code.expect("presence tracked"),
                    signal: signal.expect("presence tracked"),
                })
            }
        }
        deserializer.deserialize_map(ChildExitVisitor)
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dsse_envelope: Option<DsseEnvelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_command: Option<RequestedCommand>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_execution_context: Option<RequestedExecutionContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_policy: Option<RequestedPolicy>,
}

impl ClientHello {
    /// Entry point for an untrusted hello body. Wire bounds apply to the
    /// original JSON bytes, including whitespace and alternative escapes.
    pub fn parse_request(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 196_608 {
            return Err(CoreError::Protocol(
                "CLIENT_HELLO exceeds frame ceiling".into(),
            ));
        }
        let hello: Self = parse_strict(bytes)?;
        if hello.mode == "unsigned_csr_request" && bytes.len() > 65_536 {
            return Err(CoreError::Protocol(
                "unsigned request exceeds 65536 bytes".into(),
            ));
        }
        hello.validate_request()?;
        Ok(hello)
    }

    /// Full privilege-independent validation. Signature verification, peer and
    /// policy ceilings, and retained snapshot checks follow in authorization.
    pub fn validate_request(&self) -> Result<()> {
        let bytes = serde_json::to_vec(self).map_err(|error| CoreError::Json(error.to_string()))?;
        if bytes.len() > 196_608 || self.mode == "unsigned_csr_request" && bytes.len() > 65_536 {
            return Err(CoreError::Protocol(
                "CLIENT_HELLO exceeds request size limit".into(),
            ));
        }
        crate::json::preflight_with_string_limits(&bytes, 8, &Self::string_limit)?;
        self.validate_shape()?;
        if let Some(envelope) = &self.dsse_envelope {
            let warrant = envelope.warrant()?;
            if warrant.warrant().command.tty_mode != self.tty_mode {
                return Err(CoreError::Protocol("signed tty_mode fields differ".into()));
            }
            validate_unsigned_request(
                &warrant.warrant().command.requested(),
                &warrant.warrant().execution_context,
                &RequestedPolicy {
                    mode: warrant.warrant().policy.mode.clone(),
                    ttl_secs: 0,
                },
                &self.caller_env,
            )?;
        }
        Ok(())
    }

    pub fn validate_shape(&self) -> Result<()> {
        if !matches!(self.tty_mode.as_str(), "stdio" | "pty") {
            return Err(CoreError::Protocol("invalid tty_mode".into()));
        }
        match self.mode.as_str() {
            "signed"
                if self.dsse_envelope.is_some()
                    && self.requested_command.is_none()
                    && self.requested_execution_context.is_none()
                    && self.requested_policy.is_none() =>
            {
                let envelope = self.dsse_envelope.as_ref().unwrap();
                envelope.validate()?;
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
                validate_unsigned_request(
                    command,
                    self.requested_execution_context.as_ref().unwrap(),
                    self.requested_policy.as_ref().unwrap(),
                    &self.caller_env,
                )?;
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

pub(crate) fn validate_unsigned_request(
    command: &RequestedCommand,
    context: &RequestedExecutionContext,
    policy: &RequestedPolicy,
    caller_env: &BTreeMap<String, String>,
) -> Result<()> {
    if command.argv.is_empty()
        || command.argv.len() > 256
        || !valid_absolute_path(&command.executable_path, false)
        || !valid_absolute_path(&command.cwd, true)
    {
        return Err(CoreError::Protocol(
            "unsigned command path or argv bounds are invalid".into(),
        ));
    }
    let valid_stdin = match command.tty_mode.as_str() {
        "stdio" => matches!(
            command.stdin_policy.as_str(),
            "null" | "sha256" | "unrestricted_interactive"
        ),
        "pty" => command.stdin_policy == "unrestricted_interactive",
        _ => false,
    };
    if !valid_stdin
        || !matches!(
            policy.mode.as_str(),
            "one_time" | "time_range" | "permanent"
        )
    {
        return Err(CoreError::Protocol(
            "unsigned stdin or policy mode is invalid".into(),
        ));
    }
    if context.umask > 511
        || context.target_uid == u32::MAX
        || context.target_gid == u32::MAX
        || context.supplementary_gids.len() > 64
        || context.supplementary_gids.contains(&u32::MAX)
        || !sorted_unique(&context.supplementary_gids)
        || context.capabilities.len() > 64
        || !sorted_unique(&context.capabilities)
        || context
            .capabilities
            .iter()
            .any(|cap| !valid_capability(cap))
        || context.env_exact.len() > 128
        || context.caller_env_allowlist.len() > 128
        || !sorted_unique(&context.caller_env_allowlist)
        || context.env_exact.keys().any(|name| !valid_env_name(name))
        || context
            .caller_env_allowlist
            .iter()
            .any(|name| !valid_env_name(name))
        || context
            .env_exact
            .keys()
            .any(|name| context.caller_env_allowlist.binary_search(name).is_ok())
        || caller_env.len() > 128
        || caller_env.keys().any(|name| {
            !valid_env_name(name) || context.caller_env_allowlist.binary_search(name).is_err()
        })
    {
        return Err(CoreError::Protocol(
            "unsigned execution context bounds are invalid".into(),
        ));
    }
    if context
        .caller_env_allowlist
        .iter()
        .any(|name| is_denied_env_name(name))
    {
        return Err(CoreError::Protocol(
            "unsigned caller environment contains a denied name".into(),
        ));
    }
    Ok(())
}

fn valid_absolute_path(path: &str, allow_root: bool) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    if path == "/" {
        return allow_root;
    }
    if path.ends_with('/') {
        return false;
    }
    path[1..]
        .split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_env_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 || !(bytes[0].is_ascii_uppercase() || bytes[0] == b'_')
    {
        return false;
    }
    bytes
        .iter()
        .skip(1)
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn is_denied_env_name(name: &str) -> bool {
    const PREFIXES: &[&str] = &["LD_", "DYLD_", "GIT_", "BASH_FUNC_", "GLIBC_"];
    const EXACT: &[&str] = &[
        "PATH",
        "IFS",
        "CDPATH",
        "ENV",
        "BASH_ENV",
        "PROMPT_COMMAND",
        "SHELLOPTS",
        "BASHOPTS",
        "PS4",
        "GLOBIGNORE",
        "EXECIGNORE",
        "TMPDIR",
        "TMP",
        "TEMP",
        "TZ",
        "LOCPATH",
        "GCONV_PATH",
        "GETCONF_DIR",
        "HOSTALIASES",
        "LOCALDOMAIN",
        "NLSPATH",
        "RES_OPTIONS",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "PYTHONUSERBASE",
        "PERLLIB",
        "PERL5LIB",
        "PERL5OPT",
        "PERL5DB",
        "RUBYLIB",
        "RUBYOPT",
        "DLN_LIBRARY_PATH",
        "NODE_OPTIONS",
        "NODE_PATH",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "CLASSPATH",
        "GOFLAGS",
        "CGO_CFLAGS",
        "CGO_LDFLAGS",
        "RUSTFLAGS",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "OPENSSL_CONF",
        "OPENSSL_ENGINES",
        "OPENSSL_MODULES",
        "NSS_DEFAULT_DB_TYPE",
        "KRB5_CONFIG",
        "KRB5CCNAME",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_CONFIG_DIRS",
        "XDG_DATA_DIRS",
        "XAUTHORITY",
    ];
    PREFIXES.iter().any(|prefix| name.starts_with(prefix)) || EXACT.contains(&name)
}

fn valid_capability(capability: &str) -> bool {
    const CAPS: &[&str] = &[
        "CAP_AUDIT_CONTROL",
        "CAP_AUDIT_READ",
        "CAP_AUDIT_WRITE",
        "CAP_BLOCK_SUSPEND",
        "CAP_BPF",
        "CAP_CHECKPOINT_RESTORE",
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",
        "CAP_KILL",
        "CAP_LEASE",
        "CAP_LINUX_IMMUTABLE",
        "CAP_MAC_ADMIN",
        "CAP_MAC_OVERRIDE",
        "CAP_MKNOD",
        "CAP_NET_ADMIN",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_BROADCAST",
        "CAP_NET_RAW",
        "CAP_PERFMON",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT",
        "CAP_SYS_CHROOT",
        "CAP_SYS_MODULE",
        "CAP_SYS_NICE",
        "CAP_SYS_PACCT",
        "CAP_SYS_PTRACE",
        "CAP_SYS_RAWIO",
        "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME",
        "CAP_SYS_TTY_CONFIG",
        "CAP_SYSLOG",
        "CAP_WAKE_ALARM",
    ];
    CAPS.contains(&capability)
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
        let expected_len = usize::try_from(expected)
            .map_err(|_| CoreError::Protocol("audit batch count exceeds platform bounds".into()))?;
        if self.records_jcs.len() != expected_len
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
        let mut parsed_records = Vec::with_capacity(self.records_jcs.len());
        for (offset, record) in self.records_jcs.iter().enumerate() {
            crate::json::preflight(record.as_bytes(), 8, 65_536)?;
            let value: serde_json::Value = serde_json::from_slice(record.as_bytes())
                .map_err(|e| CoreError::Protocol(format!("invalid audit record JSON: {e}")))?;
            if serde_json::to_vec(&value)
                .map_err(|e| CoreError::Protocol(format!("serialize audit record: {e}")))?
                != record.as_bytes()
            {
                return Err(CoreError::Protocol(
                    "audit record is not canonical JCS".into(),
                ));
            }
            let seq = value
                .get("seq")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| CoreError::Protocol("audit record is missing seq".into()))?;
            let expected_seq = self
                .first_seq
                .checked_add(offset as u64)
                .ok_or_else(|| CoreError::Protocol("audit sequence overflow".into()))?;
            if seq != expected_seq
                || value.get("host_id").and_then(serde_json::Value::as_str)
                    != Some(self.host_id.as_str())
            {
                return Err(CoreError::Protocol(
                    "audit batch is non-contiguous or host-mismatched".into(),
                ));
            }
            parsed_records.push(value);
        }
        if let Some(target) = &self.target_auth {
            if target.auth_commit_seq != self.last_seq || target.host_id != self.host_id {
                return Err(CoreError::Protocol(
                    "target_auth must bind to the final batch sequence and host".into(),
                ));
            }
            let final_record = parsed_records.last().unwrap();
            if final_record
                .get("event_type")
                .and_then(serde_json::Value::as_str)
                != Some("AUTH_COMMIT")
            {
                return Err(CoreError::Protocol(
                    "target_auth requires a final AUTH_COMMIT record".into(),
                ));
            }
            for (field, target_value) in [
                ("exec_id", serde_json::Value::String(target.exec_id.clone())),
                (
                    "grant_id",
                    serde_json::Value::String(target.grant_id.clone()),
                ),
                ("host_id", serde_json::Value::String(target.host_id.clone())),
                (
                    "payload_sha256",
                    serde_json::Value::String(target.payload_sha256.clone()),
                ),
                (
                    "policy_mode",
                    serde_json::Value::String(target.policy_mode.clone()),
                ),
                (
                    "signer_id",
                    serde_json::Value::String(target.signer_id.clone()),
                ),
            ] {
                if final_record.get(field) != Some(&target_value) {
                    return Err(CoreError::Protocol(
                        "target_auth does not match AUTH_COMMIT".into(),
                    ));
                }
            }
            if final_record.get("seq") != Some(&serde_json::Value::from(target.auth_commit_seq)) {
                return Err(CoreError::Protocol(
                    "target_auth sequence does not match AUTH_COMMIT".into(),
                ));
            }
            if final_record.get("not_before") != Some(&serde_json::Value::from(target.not_before)) {
                return Err(CoreError::Protocol(
                    "target_auth numeric field does not match AUTH_COMMIT".into(),
                ));
            }
            let final_not_after = final_record
                .get("not_after")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let target_not_after = target
                .not_after
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null);
            if final_not_after != target_not_after {
                return Err(CoreError::Protocol(
                    "target_auth not_after does not match AUTH_COMMIT".into(),
                ));
            }
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

/// A protocol schema supplies decoded string ceilings without weakening the
/// inner-request limit. Duplicate keys and nesting are checked before serde.
pub trait ProtocolSchema {
    fn string_limit(_path: &[String]) -> usize {
        4096
    }
}

impl ProtocolSchema for ClientHello {
    fn string_limit(path: &[String]) -> usize {
        let path: Vec<_> = path.iter().map(String::as_str).collect();
        match path.as_slice() {
            ["dsse_envelope", "payload"] => 87_384,
            ["dsse_envelope", "signatures", "*", "sig"] => 32_768,
            ["dsse_envelope", "signatures", "*", "keyid"] => 128,
            _ => 4096,
        }
    }
}

impl ProtocolSchema for DsseEnvelope {
    fn string_limit(path: &[String]) -> usize {
        let path: Vec<_> = path.iter().map(String::as_str).collect();
        match path.as_slice() {
            ["payload"] => 87_384,
            ["signatures", "*", "sig"] => 32_768,
            ["signatures", "*", "keyid"] => 128,
            _ => 4096,
        }
    }
}

impl ProtocolSchema for Decision {
    fn string_limit(path: &[String]) -> usize {
        if path.len() == 1 && path[0] == "csr_payload" {
            65_536
        } else {
            4096
        }
    }
}

impl ProtocolSchema for RemoteAuditBatchRequest {
    fn string_limit(path: &[String]) -> usize {
        if path.len() == 2 && path[0] == "records_jcs" && path[1] == "*" {
            65_536
        } else {
            4096
        }
    }
}

impl ProtocolSchema for ChildExit {}
impl ProtocolSchema for TargetAuth {}
impl ProtocolSchema for RequestedCommand {}
impl ProtocolSchema for RequestedExecutionContext {}
impl ProtocolSchema for RequestedPolicy {}
impl ProtocolSchema for DsseSignature {
    fn string_limit(path: &[String]) -> usize {
        if path.len() == 1 && path[0] == "sig" {
            32_768
        } else if path.len() == 1 && path[0] == "keyid" {
            128
        } else {
            4096
        }
    }
}

impl ProtocolSchema for serde_json::Value {
    fn string_limit(_path: &[String]) -> usize {
        65_536
    }
}

pub fn parse_strict<T: for<'de> Deserialize<'de> + ProtocolSchema>(bytes: &[u8]) -> Result<T> {
    crate::json::preflight_with_string_limits(bytes, 8, &T::string_limit)?;
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
    use crate::crypto::WARRANT_PAYLOAD_TYPE;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    #[test]
    fn child_exit_requires_both_keys_even_when_one_is_null() {
        for json in [
            r#"{"exit_code":0}"#,
            r#"{"signal":9}"#,
            "{}",
            r#"{"exit_code":0,"signal":null,"extra":0}"#,
            r#"{"exit_code":0,"signal":null,"signal":null}"#,
        ] {
            assert!(
                parse_strict::<ChildExit>(json.as_bytes()).is_err(),
                "{json}"
            );
            if !json.contains("\"signal\":null,\"signal\"") {
                assert!(serde_json::from_str::<ChildExit>(json).is_err(), "{json}");
            }
        }
        for json in [
            r#"{"exit_code":0,"signal":null}"#,
            r#"{"exit_code":null,"signal":9}"#,
        ] {
            parse_strict::<ChildExit>(json.as_bytes())
                .unwrap()
                .validate()
                .unwrap();
        }
        for json in [
            r#"{"exit_code":null,"signal":null}"#,
            r#"{"exit_code":0,"signal":9}"#,
        ] {
            assert!(
                parse_strict::<ChildExit>(json.as_bytes())
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }

    #[test]
    fn hello_accepts_outer_envelope_limits_and_rejects_oversized_fields() {
        let mut hello = serde_json::json!({
            "mode": "signed", "tty_mode": "stdio", "caller_env": {},
            "dsse_envelope": {
                "payloadType": WARRANT_PAYLOAD_TYPE,
                "payload": STANDARD.encode(vec![0; 65_536]),
                "signatures": [{"keyid": "k".repeat(128), "sig": STANDARD.encode(vec![0; 24_576])}],
            },
        });
        parse_strict::<ClientHello>(&serde_json::to_vec(&hello).unwrap())
            .unwrap()
            .validate_shape()
            .unwrap();
        let valid = hello.clone();
        hello["dsse_envelope"]["payload"] = "x".repeat(87_385).into();
        assert!(parse_strict::<ClientHello>(&serde_json::to_vec(&hello).unwrap()).is_err());
        hello = valid.clone();
        hello["dsse_envelope"]["signatures"][0]["sig"] = "x".repeat(32_769).into();
        assert!(parse_strict::<ClientHello>(&serde_json::to_vec(&hello).unwrap()).is_err());
        hello = valid.clone();
        hello["dsse_envelope"]["signatures"][0]["keyid"] = "x".repeat(129).into();
        assert!(parse_strict::<ClientHello>(&serde_json::to_vec(&hello).unwrap()).is_err());
        hello = valid;
        hello["caller_env"]["TERM"] = "x".repeat(4097).into();
        assert!(parse_strict::<ClientHello>(&serde_json::to_vec(&hello).unwrap()).is_err());
    }

    #[test]
    fn unsigned_hello_accepts_absolute_executable_and_root_cwd() {
        let hello = serde_json::json!({
            "caller_env": {},
            "mode": "unsigned_csr_request",
            "requested_command": {
                "allow_interpreted_script": false,
                "argv": ["/usr/bin/probe"],
                "cwd": "/",
                "executable_path": "/usr/bin/probe",
                "stdin_policy": "null",
                "tty_mode": "stdio"
            },
            "requested_execution_context": {
                "capabilities": [],
                "env_exact": {},
                "caller_env_allowlist": [],
                "supplementary_gids": [],
                "target_gid": 0,
                "target_uid": 0,
                "umask": 63
            },
            "requested_policy": {"mode": "one_time", "ttl_secs": 900},
            "tty_mode": "stdio"
        });
        parse_strict::<ClientHello>(&serde_json::to_vec(&hello).unwrap())
            .unwrap()
            .validate_shape()
            .unwrap();
        assert!(!valid_absolute_path("/usr/bin/", false));
        assert!(!valid_absolute_path("/usr//bin/probe", false));
        assert!(!valid_absolute_path("/usr/../bin/probe", false));
        assert!(valid_absolute_path("/", true));
    }

    #[test]
    fn target_auth_binds_to_final_record_sequence_field() {
        let exec_id = "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f";
        let grant_id = "0192d8f4-9a00-7000-8000-112233445566";
        let digest = "00".repeat(32);
        let record = serde_json::json!({
            "event_type": "AUTH_COMMIT",
            "exec_id": exec_id,
            "grant_id": grant_id,
            "host_id": "host",
            "not_after": 1900,
            "not_before": 1000,
            "payload_sha256": digest,
            "policy_mode": "one_time",
            "seq": 1,
            "signer_id": "signer"
        });
        let target = TargetAuth {
            auth_commit_seq: 1,
            exec_id: exec_id.into(),
            grant_id: grant_id.into(),
            host_id: "host".into(),
            not_after: Some(1900),
            not_before: 1000,
            payload_sha256: "00".repeat(32),
            policy_mode: "one_time".into(),
            signer_id: "signer".into(),
        };
        let batch = RemoteAuditBatchRequest {
            first_seq: 1,
            last_seq: 1,
            host_id: "host".into(),
            records_jcs: vec![serde_json::to_string(&record).unwrap()],
            target_auth: Some(target),
        };
        batch.validate().unwrap();
    }

    #[test]
    fn decision_csr_and_batch_records_have_their_own_string_limits() {
        let mut decision = serde_json::json!({
            "csr_payload": "x".repeat(65_536), "message": "x".repeat(4096),
            "status": "TIMEOUT_CSR", "exec_id": "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f",
        });
        parse_strict::<Decision>(&serde_json::to_vec(&decision).unwrap())
            .unwrap()
            .validate()
            .unwrap();
        decision["csr_payload"] = "x".repeat(65_537).into();
        assert!(parse_strict::<Decision>(&serde_json::to_vec(&decision).unwrap()).is_err());
        decision["csr_payload"] = "{}".into();
        decision["message"] = "x".repeat(4097).into();
        assert!(parse_strict::<Decision>(&serde_json::to_vec(&decision).unwrap()).is_err());
        let prefix = "{\"data\":\"";
        let suffix = "\",\"host_id\":\"host\",\"seq\":1}";
        let record = format!(
            "{prefix}{}{suffix}",
            "x".repeat(65_536 - prefix.len() - suffix.len())
        );
        assert_eq!(record.len(), 65_536);
        let mut batch = serde_json::json!({
            "first_seq": 1, "last_seq": 1, "host_id": "host",
            "records_jcs": [record], "target_auth": null,
        });
        parse_strict::<RemoteAuditBatchRequest>(&serde_json::to_vec(&batch).unwrap())
            .unwrap()
            .validate()
            .unwrap();
        batch["records_jcs"][0] = "x".repeat(65_537).into();
        assert!(
            parse_strict::<RemoteAuditBatchRequest>(&serde_json::to_vec(&batch).unwrap()).is_err()
        );
    }

    #[test]
    fn schema_limits_preserve_duplicate_and_depth_checks() {
        assert!(
            parse_strict::<ClientHello>(
                br#"{"mode":"signed","caller_env":{"TERM":"a","TERM":"b"},"tty_mode":"stdio"}"#
            )
            .is_err()
        );
        let nested = format!("{}0{}", "[".repeat(9), "]".repeat(9));
        assert!(parse_strict::<ClientHello>(nested.as_bytes()).is_err());
        let command = serde_json::json!({
            "allow_interpreted_script": false, "argv": ["x".repeat(4097)],
            "cwd": "/", "executable_path": "/usr/bin/probe", "stdin_policy": "null", "tty_mode": "stdio",
        });
        assert!(parse_strict::<RequestedCommand>(&serde_json::to_vec(&command).unwrap()).is_err());
    }

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
