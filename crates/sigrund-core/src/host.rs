//! V3 host contracts. Serialized bindings never substitute for live resources.
use crate::{
    CoreError, Result,
    crypto::{sha256_hex, validate_uuidv7},
    json,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;

pub const MAX_RECORD_BYTES: usize = 65_536;
pub const PAYLOAD_TYPE: &str = "application/vnd.sigrun.warrant.v3+json";
pub const SSH_NAMESPACE: &str = "sigrun.warrant.v3";

fn invalid(message: &str) -> CoreError {
    CoreError::Protocol(message.into())
}
pub trait Record: Serialize + DeserializeOwned {
    fn validate(&self) -> Result<()>;
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("host record exceeds 64 KiB"));
        }
        json::preflight(bytes, 16, 4096)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|e| invalid(&e.to_string()))?;
        value.validate()?;
        Ok(value)
    }
    fn canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = json::canonical_bytes(self)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("host record exceeds 64 KiB"));
        }
        Ok(bytes)
    }
    fn sha256(&self) -> Result<String> {
        Ok(sha256_hex(&self.canonical()?))
    }
}
fn text(value: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(|c| c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')) {
        return Err(invalid("invalid display text"));
    }
    Ok(())
}
pub fn identifier(value: &str) -> Result<()> {
    text(value, 128)?;
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(invalid("invalid identifier"));
    }
    Ok(())
}
fn digest(value: &str) -> Result<()> {
    if !crate::warrant::valid_digest(value) {
        return Err(invalid("invalid lowercase SHA-256"));
    }
    Ok(())
}
fn host_id(value: &str) -> Result<()> {
    digest(
        value
            .strip_prefix("sigrun-host:sha256:")
            .ok_or_else(|| invalid("invalid host authority"))?,
    )
}
fn decimal(value: &str) -> Result<u64> {
    let n: u64 = value
        .parse()
        .map_err(|_| invalid("invalid kernel identity"))?;
    if value != n.to_string() {
        return Err(invalid("noncanonical kernel identity"));
    }
    Ok(n)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Selector {
    Host {},
    #[serde(rename = "self")]
    Self_ {},
    Registered {
        id: String,
    },
    Process {
        pid: u32,
        pid_scope: String,
    },
}
impl Selector {
    pub fn validate_host(&self) -> Result<()> {
        if !matches!(self, Self::Host {}) {
            return Err(invalid("only host targets are supported"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Account {
    Numeric {
        uid: u32,
        gid: u32,
        supplementary_gids: Vec<u32>,
    },
    Name {
        name: String,
    },
}
impl Account {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Numeric {
                uid,
                gid,
                supplementary_gids,
            } => credentials(*uid, *gid, supplementary_gids),
            Self::Name { name } => identifier(name),
        }
    }
}
pub fn credentials(uid: u32, gid: u32, groups: &[u32]) -> Result<()> {
    if uid == u32::MAX
        || gid == u32::MAX
        || groups.len() > 64
        || groups.contains(&u32::MAX)
        || groups.windows(2).any(|p| p[0] >= p[1])
    {
        return Err(invalid("invalid resolved credentials"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectIdentity {
    pub device: String,
    pub inode: String,
}
impl ObjectIdentity {
    fn validate(&self) -> Result<()> {
        decimal(&self.device)?;
        decimal(&self.inode)?;
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MapExtent {
    pub inside: u32,
    pub outside: u32,
    pub length: u64,
}
fn identity_map(map: &[MapExtent]) -> bool {
    map.len() == 1
        && map[0].inside == 0
        && map[0].outside == 0
        && map[0].length == u64::from(u32::MAX)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acquisition {
    pub schema: String,
    pub daemon_epoch: String,
    pub instance_id: String,
    pub boot_id: String,
    pub root: ObjectIdentity,
    pub executable_roots: BTreeMap<String, ObjectIdentity>,
    pub namespaces: BTreeMap<String, ObjectIdentity>,
    pub uid_map: Vec<MapExtent>,
    pub gid_map: Vec<MapExtent>,
    pub setgroups: String,
}
impl Record for Acquisition {
    fn validate(&self) -> Result<()> {
        if self.schema != "sigrund.host-acquisition.v1"
            || self.setgroups != "allow"
            || !identity_map(&self.uid_map)
            || !identity_map(&self.gid_map)
        {
            return Err(invalid("unsupported host mapping or acquisition version"));
        }
        validate_uuidv7(&self.daemon_epoch)?;
        validate_uuidv7(&self.instance_id)?;
        let boot = uuid::Uuid::parse_str(&self.boot_id).map_err(|_| invalid("invalid boot ID"))?;
        if boot.to_string() != self.boot_id {
            return Err(invalid("noncanonical boot ID"));
        }
        self.root.validate()?;
        if self.executable_roots.is_empty() || self.executable_roots.len() > 64 {
            return Err(invalid("invalid pinned roots"));
        }
        for (path, object) in &self.executable_roots {
            if !path.starts_with('/')
                || path == "/"
                || path.len() > 4096
                || path[1..]
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == "..")
            {
                return Err(invalid("invalid pinned root path"));
            }
            object.validate()?;
        }
        let names: Vec<_> = self.namespaces.keys().map(String::as_str).collect();
        if names != ["cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"] {
            return Err(invalid("incomplete host namespace evidence"));
        }
        for object in self.namespaces.values() {
            object.validate()?;
        }
        Ok(())
    }
}

/// Describes only the existing native host setup. Required LSM transitions and
/// inherited seccomp equivalence cannot be expressed by this profile version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    pub schema: String,
    pub profile_id: String,
    pub join_namespaces: Vec<String>,
    pub private_mount: bool,
    pub private_cgroup: bool,
    pub capabilities: Vec<String>,
    pub securebits: u32,
    pub no_new_privs: bool,
    pub memory_max: u64,
    pub memory_swap_max: u64,
    pub pids_max: u32,
    pub lsm: String,
    pub seccomp: String,
    pub executable_model: crate::executable::TrustModel,
    pub verify_exec_stop: bool,
}
impl Record for Constraints {
    fn validate(&self) -> Result<()> {
        identifier(&self.profile_id)?;
        let direct = self.executable_model != crate::executable::TrustModel::DigestMemfd;
        if self.schema != "sigrund.host-constraints.v1"
            || !self.join_namespaces.is_empty()
            || !self.private_mount
            || !self.private_cgroup
            || self.securebits != 0x2f
            || !self.no_new_privs
            || self.memory_max == 0
            || self.memory_max > (1 << 40)
            || self.memory_swap_max > self.memory_max
            || !(1..=128).contains(&self.pids_max)
            || self.lsm != "no_transition_required"
            || self.seccomp != "no_filter_required"
            || self.verify_exec_stop != direct
            || self.capabilities.iter().any(|c| c == "CAP_SYS_ADMIN")
            || self.capabilities.len() > 41
            || self.capabilities.windows(2).any(|p| p[0] >= p[1])
            || self
                .capabilities
                .iter()
                .any(|c| !crate::protocol::valid_capability(c))
        {
            return Err(invalid("unsupported host security constraints"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetBinding {
    pub kind: String,
    pub daemon_epoch: String,
    pub instance_id: String,
    pub description: String,
    pub context_sha256: String,
}
impl Record for TargetBinding {
    fn validate(&self) -> Result<()> {
        if self.kind != "host" {
            return Err(invalid("unsupported target binding"));
        }
        validate_uuidv7(&self.daemon_epoch)?;
        validate_uuidv7(&self.instance_id)?;
        text(&self.description, 1024)?;
        digest(&self.context_sha256)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConstraints {
    pub profile_id: String,
    pub profile_sha256: String,
}
impl Record for SecurityConstraints {
    fn validate(&self) -> Result<()> {
        identifier(&self.profile_id)?;
        digest(&self.profile_sha256)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBinding {
    pub target_binding: TargetBinding,
    pub security_constraints: SecurityConstraints,
}
impl Record for ExecutionBinding {
    fn validate(&self) -> Result<()> {
        self.target_binding.validate()?;
        self.security_constraints.validate()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingBundle {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admin_trusted_composefs_mounts: Vec<u64>,
    pub schema: String,
    pub host_id: String,
    pub target_binding: TargetBinding,
    pub acquisition: Acquisition,
    pub constraints: Constraints,
    pub profile_sha256: String,
}
impl Record for BindingBundle {
    fn validate(&self) -> Result<()> {
        if self.schema != "sigrund.host-binding-bundle.v1"
            || self.admin_trusted_composefs_mounts.len() > 1
            || self.admin_trusted_composefs_mounts.contains(&0)
        {
            return Err(invalid("invalid host bundle version"));
        }
        host_id(&self.host_id)?;
        self.target_binding.validate()?;
        if self.acquisition.daemon_epoch != self.target_binding.daemon_epoch
            || self.acquisition.instance_id != self.target_binding.instance_id
            || self.acquisition.sha256()? != self.target_binding.context_sha256
            || self.constraints.sha256()? != self.profile_sha256
        {
            return Err(invalid("host bundle digest or instance mismatch"));
        }
        Ok(())
    }
}
impl BindingBundle {
    pub fn binding(&self) -> Result<ExecutionBinding> {
        self.validate()?;
        Ok(ExecutionBinding {
            target_binding: self.target_binding.clone(),
            security_constraints: SecurityConstraints {
                profile_id: self.constraints.profile_id.clone(),
                profile_sha256: self.profile_sha256.clone(),
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedRule {
    pub requester_uids: Vec<u32>,
    pub target_scope: String,
    pub target_uids: Vec<u32>,
    pub target_gids: Vec<u32>,
    pub supplementary_gids: Vec<u32>,
    pub profile_sha256: String,
    pub cross_owner: bool,
}
impl Record for ScopedRule {
    fn validate(&self) -> Result<()> {
        if self.target_scope != "host" {
            return Err(invalid("unsupported policy scope"));
        }
        for ids in [
            &self.requester_uids,
            &self.target_uids,
            &self.target_gids,
            &self.supplementary_gids,
        ] {
            if ids.len() > 1024 || ids.contains(&u32::MAX) || ids.windows(2).any(|p| p[0] >= p[1]) {
                return Err(invalid("invalid policy ceiling"));
            }
        }
        if self.requester_uids.is_empty()
            || self.target_uids.is_empty()
            || self.target_gids.is_empty()
        {
            return Err(invalid("empty policy ceiling"));
        }
        digest(&self.profile_sha256)
    }
}
impl ScopedRule {
    pub fn permits(
        &self,
        requester: u32,
        uid: u32,
        gid: u32,
        groups: &[u32],
        profile: &str,
    ) -> bool {
        self.validate().is_ok()
            && credentials(uid, gid, groups).is_ok()
            && self.requester_uids.contains(&requester)
            && self.target_uids.contains(&uid)
            && self.target_gids.contains(&gid)
            && groups.iter().all(|g| self.supplementary_gids.contains(g))
            && self.profile_sha256 == profile
            && (requester == 0 || self.cross_owner)
    }
}
