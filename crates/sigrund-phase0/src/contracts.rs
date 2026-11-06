use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sigrund_core::{CoreError, Result, json};
use std::collections::BTreeMap;

pub const MAX_RECORD_BYTES: usize = 65_536;
pub const MAX_MAP_LAYERS: usize = 8;
pub const MAX_MAP_EXTENTS: usize = 64;
pub const NAMESPACES: [&str; 8] = ["cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"];

fn invalid(message: &str) -> CoreError {
    CoreError::Value(message.into())
}
pub trait Contract: Serialize + DeserializeOwned {
    fn validate(&self) -> Result<()>;
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("phase0 contract exceeds 64 KiB"));
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
            return Err(invalid("phase0 contract exceeds 64 KiB"));
        }
        Ok(bytes)
    }
    fn sha256(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(self.canonical()?)))
    }
}
fn text(value: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(|c| c.is_control()
        || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')) {
        return Err(invalid("invalid bounded display string"));
    }
    Ok(())
}
pub fn identifier(value: &str) -> Result<()> {
    text(value, 128)?;
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(invalid(
            "identifier must use ASCII letters, digits, -, _ or .",
        ));
    }
    Ok(())
}
fn hex(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("expected lowercase SHA-256"));
    }
    Ok(())
}
fn uuid7(value: &str) -> Result<()> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| invalid("invalid UUIDv7"))?;
    if id.get_version_num() != 7
        || id.to_string() != value
        || id.get_variant() != uuid::Variant::RFC4122
    {
        return Err(invalid("expected canonical RFC4122 UUIDv7"));
    }
    Ok(())
}
/// Kernel u64 identifiers use canonical decimal strings, avoiding JCS rounding.
fn decimal(value: &str) -> Result<u64> {
    let number: u64 = value.parse().map_err(|_| invalid("invalid u64 decimal"))?;
    if number.to_string() != value {
        return Err(invalid("noncanonical u64 decimal"));
    }
    Ok(number)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsIdentity {
    pub device: String,
    pub inode: String,
    pub mount_id: String,
}
impl FsIdentity {
    fn validate(&self) -> Result<()> {
        decimal(&self.device)?;
        if decimal(&self.inode)? == 0 || decimal(&self.mount_id)? == 0 {
            return Err(invalid("zero filesystem identity"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceIdentity {
    pub device: String,
    pub inode: String,
    pub owner_userns_device: String,
    pub owner_userns_inode: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Extent {
    pub inside: u32,
    pub outside: u32,
    pub count: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MapLayer {
    pub userns_inode: String,
    pub uid: Vec<Extent>,
    pub gid: Vec<Extent>,
    pub setgroups: Setgroups,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Setgroups {
    Allow,
    Deny,
}

fn validate_map(map: &[Extent]) -> Result<()> {
    if map.is_empty() || map.len() > MAX_MAP_EXTENTS {
        return Err(invalid("unsupported mapping extent count"));
    }
    let mut end = 0u64;
    for extent in map {
        let next = u64::from(extent.inside) + u64::from(extent.count);
        if extent.count == 0
            || u64::from(extent.inside) < end
            || next > u64::from(u32::MAX)
            || u64::from(extent.outside) + u64::from(extent.count) > u64::from(u32::MAX)
        {
            return Err(invalid("overlapping, unsorted, empty or overflowing map"));
        }
        end = next;
    }
    for (i, a) in map.iter().enumerate() {
        for b in &map[i + 1..] {
            if u64::from(a.outside) < u64::from(b.outside) + u64::from(b.count)
                && u64::from(b.outside) < u64::from(a.outside) + u64::from(a.count)
            {
                return Err(invalid("overlapping outside mapping"));
            }
        }
    }
    Ok(())
}
/// Compose one ID through target-to-host ancestry. No unmapped/overflow fallback.
pub fn compose(id: u32, maps: &[Vec<Extent>]) -> Result<u32> {
    if maps.is_empty() || maps.len() > MAX_MAP_LAYERS || id == u32::MAX {
        return Err(invalid("invalid mapping ancestry or ID"));
    }
    let mut id = id;
    for map in maps {
        validate_map(map)?;
        let e = map
            .iter()
            .find(|e| id >= e.inside && u64::from(id) < u64::from(e.inside) + u64::from(e.count))
            .ok_or_else(|| invalid("unmapped ID"))?;
        id = e.outside + (id - e.inside);
    }
    Ok(id)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acquisition {
    pub schema: String,
    pub daemon_epoch: String,
    pub instance_id: String,
    pub pid: u32,
    pub start_ticks: String,
    pub boot_id: String,
    pub capture: Capture,
    pub anchor: AnchorObservation,
    pub namespaces: BTreeMap<String, NamespaceIdentity>,
    pub root: FsIdentity,
    pub cwd: FsIdentity,
    /// Ordered target userns toward initial userns. Maps are relative to parent.
    pub mappings: Vec<MapLayer>,
    pub lifecycle: Lifecycle,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorObservation {
    pub host_uid: u32,
    pub host_gid: u32,
    pub host_groups: Vec<u32>,
    pub connector_label: Option<String>,
    pub process_label: String,
    pub no_new_privs: bool,
    pub seccomp: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capture {
    TracedPrivateFsV1,
    ConfiguredHostV1,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    pub anchor_required: bool,
    pub registration_id: Option<String>,
    pub registration_revision: Option<String>,
    pub resolver: Option<String>,
}
impl Contract for Acquisition {
    fn validate(&self) -> Result<()> {
        if self.schema != "sigrund.acquisition.phase0.v1"
            || self.pid == 0
            || self.pid > i32::MAX as u32
        {
            return Err(invalid("invalid acquisition schema or daemon-scope PID"));
        }
        uuid7(&self.daemon_epoch)?;
        uuid7(&self.instance_id)?;
        if self.anchor.host_uid == u32::MAX
            || self.anchor.host_gid == u32::MAX
            || self.anchor.seccomp != 0
            || self.anchor.host_groups.len() > 256
            || self.anchor.host_groups.contains(&u32::MAX)
            || self.anchor.host_groups.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(invalid("invalid or unsupported anchor observations"));
        }
        text(&self.anchor.process_label, 4096)?;
        if let Some(label) = &self.anchor.connector_label {
            text(label, 4096)?;
        }
        let boot = uuid::Uuid::parse_str(&self.boot_id).map_err(|_| invalid("invalid boot ID"))?;
        if boot.to_string() != self.boot_id || decimal(&self.start_ticks)? == 0 {
            return Err(invalid("invalid boot ID or start ticks"));
        }
        if self
            .namespaces
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != NAMESPACES
        {
            return Err(invalid("exact namespace set required"));
        }
        for ns in self.namespaces.values() {
            decimal(&ns.device)?;
            decimal(&ns.owner_userns_device)?;
            if decimal(&ns.inode)? == 0 || decimal(&ns.owner_userns_inode)? == 0 {
                return Err(invalid("zero namespace identity"));
            }
        }
        self.root.validate()?;
        self.cwd.validate()?;
        if self.mappings.is_empty() || self.mappings.len() > MAX_MAP_LAYERS {
            return Err(invalid("unsupported mapping depth"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for layer in &self.mappings {
            if decimal(&layer.userns_inode)? == 0 || !seen.insert(&layer.userns_inode) {
                return Err(invalid("invalid/cyclic mapping ancestry"));
            }
            validate_map(&layer.uid)?;
            validate_map(&layer.gid)?;
        }
        if self.mappings[0].userns_inode != self.namespaces["user"].inode {
            return Err(invalid("mapping ancestry starts in the wrong userns"));
        }
        if !self.lifecycle.anchor_required || self.lifecycle.resolver.is_some() {
            return Err(invalid(
                "phase0 requires a live anchor; resolvers are deferred",
            ));
        }
        match (
            &self.lifecycle.registration_id,
            &self.lifecycle.registration_revision,
        ) {
            (Some(id), Some(revision)) => {
                identifier(id)?;
                hex(revision)?;
            }
            (None, None) => (),
            _ => return Err(invalid("incomplete registration dependency")),
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Registered { id } => identifier(id),
            Self::Process { pid, pid_scope }
                if *pid == 0 || *pid > i32::MAX as u32 || pid_scope != "daemon" =>
            {
                Err(invalid("invalid daemon-scope process selector"))
            }
            _ => Ok(()),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
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
            Self::Name { name } => text(name, 128),
            Self::Numeric {
                uid,
                gid,
                supplementary_gids,
            } => {
                if *uid == u32::MAX
                    || *gid == u32::MAX
                    || supplementary_gids.len() > 256
                    || supplementary_gids.contains(&u32::MAX)
                    || supplementary_gids.windows(2).any(|w| w[0] >= w[1])
                {
                    return Err(invalid("invalid or noncanonical numeric account"));
                }
                Ok(())
            }
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub target: Selector,
    pub account: Account,
    pub security_profile: String,
}
impl Contract for Intent {
    fn validate(&self) -> Result<()> {
        self.target.validate()?;
        self.account.validate()?;
        identifier(&self.security_profile)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub selinux: Selinux,
    pub apparmor: String,
    pub seccomp: Seccomp,
    pub executable_model: String,
    pub verify_exec_stop: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selinux {
    pub context: String,
    pub enforcing: bool,
    pub policy_change: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Seccomp {
    None {},
    DenySyscalls {
        audit_arch: u32,
        errno: u16,
        syscalls: Vec<u32>,
    },
}
impl Contract for Constraints {
    fn validate(&self) -> Result<()> {
        if self.schema != "sigrund.constraints.phase0.v1" {
            return Err(invalid("wrong constraint schema"));
        }
        identifier(&self.profile_id)?;
        if self
            .join_namespaces
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != NAMESPACES
            || !self.private_mount
            || !self.private_cgroup
            || !self.no_new_privs
            || !self.verify_exec_stop
            || self.securebits != 15
            || self.memory_max == 0
            || self.memory_max > (1 << 40)
            || self.memory_swap_max > self.memory_max
            || !(2..=128).contains(&self.pids_max)
            || self
                .capabilities
                .iter()
                .any(|c| c != "CAP_NET_BIND_SERVICE")
            || self.capabilities.len() > 1
            || !self.selinux.enforcing
            || self.selinux.policy_change != "reject"
            || self.apparmor != "unsupported"
            || !["digest_direct", "digest_memfd"].contains(&self.executable_model.as_str())
        {
            return Err(invalid("unsupported phase0 constraint combination"));
        }
        text(&self.selinux.context, 4096)?;
        if self.selinux.context.splitn(4, ':').count() != 4 {
            return Err(invalid("complete SELinux context required"));
        }
        if let Seccomp::DenySyscalls {
            audit_arch,
            errno,
            syscalls,
        } = &self.seccomp
            && (*audit_arch != 0xc000003e
                || !(1..=4095).contains(errno)
                || syscalls.is_empty()
                || syscalls.len() > 256
                || syscalls.iter().any(|n| *n > 1023)
                || syscalls.windows(2).any(|w| w[0] >= w[1]))
        {
            return Err(invalid("unsupported seccomp rule"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetBinding {
    pub kind: String,
    pub daemon_epoch: String,
    pub instance_id: String,
    pub description: String,
    pub context_sha256: String,
}
impl Contract for TargetBinding {
    fn validate(&self) -> Result<()> {
        if !["host", "process_environment"].contains(&self.kind.as_str()) {
            return Err(invalid("invalid target kind"));
        }
        uuid7(&self.daemon_epoch)?;
        uuid7(&self.instance_id)?;
        text(&self.description, 1024)?;
        hex(&self.context_sha256)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingBundle {
    pub schema: String,
    pub host_id: String,
    pub target_binding: TargetBinding,
    pub constraints: Constraints,
    pub profile_sha256: String,
}
impl Contract for BindingBundle {
    fn validate(&self) -> Result<()> {
        if self.schema != "sigrund.binding-bundle.phase0.v1" {
            return Err(invalid("wrong bundle schema"));
        }
        let host_digest = self
            .host_id
            .strip_prefix("sigrun-host:sha256:")
            .ok_or_else(|| invalid("invalid host authority"))?;
        hex(host_digest)?;
        self.target_binding.validate()?;
        self.constraints.validate()?;
        if self.profile_sha256 != self.constraints.sha256()? {
            return Err(invalid("immutable profile mismatch"));
        }
        Ok(())
    }
}
/// Daemon and signer each evaluate their own rule; both must authorize.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
impl Contract for ScopedRule {
    fn validate(&self) -> Result<()> {
        if self.target_scope != "host" && self.target_scope != "self" {
            let id = self
                .target_scope
                .strip_prefix("registered:")
                .ok_or_else(|| invalid("unscoped target policy"))?;
            identifier(id)?;
        }
        for ids in [
            &self.requester_uids,
            &self.target_uids,
            &self.target_gids,
            &self.supplementary_gids,
        ] {
            if ids.len() > 256 || ids.contains(&u32::MAX) || ids.windows(2).any(|w| w[0] >= w[1]) {
                return Err(invalid("invalid scoped ID ceiling"));
            }
        }
        if self.requester_uids.is_empty()
            || self.target_uids.is_empty()
            || self.target_gids.is_empty()
        {
            return Err(invalid("empty scoped authority"));
        }
        hex(&self.profile_sha256)
    }
}
impl ScopedRule {
    #[allow(clippy::too_many_arguments)]
    pub fn permits(
        &self,
        requester: u32,
        scope: &str,
        uid: u32,
        gid: u32,
        groups: &[u32],
        profile: &str,
        owner: u32,
    ) -> bool {
        self.validate().is_ok()
            && self.requester_uids.contains(&requester)
            && self.target_scope == scope
            && self.target_uids.contains(&uid)
            && self.target_gids.contains(&gid)
            && groups.iter().all(|g| self.supplementary_gids.contains(g))
            && self.profile_sha256 == profile
            && (requester == owner || self.cross_owner)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub registrations: u32,
    pub targets_global: u32,
    pub targets_per_uid: u32,
    pub target_fds_global: u32,
    pub target_fds_per_uid: u32,
    pub helpers_global: u32,
    pub helpers_per_uid: u32,
    pub reviews_global: u32,
    pub reviews_per_uid: u32,
    pub launchers_per_job: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            registrations: 64,
            targets_global: 64,
            targets_per_uid: 4,
            target_fds_global: 2048,
            target_fds_per_uid: 128,
            helpers_global: 16,
            helpers_per_uid: 2,
            reviews_global: 16,
            reviews_per_uid: 2,
            launchers_per_job: 1,
        }
    }
}
impl Contract for Limits {
    fn validate(&self) -> Result<()> {
        let max = Self::default();
        for (value, ceiling) in [
            (self.registrations, max.registrations),
            (self.targets_global, max.targets_global),
            (self.targets_per_uid, max.targets_per_uid),
            (self.target_fds_global, max.target_fds_global),
            (self.target_fds_per_uid, max.target_fds_per_uid),
            (self.helpers_global, max.helpers_global),
            (self.helpers_per_uid, max.helpers_per_uid),
            (self.reviews_global, max.reviews_global),
            (self.reviews_per_uid, max.reviews_per_uid),
            (self.launchers_per_job, 1),
        ] {
            if value == 0 || value > ceiling {
                return Err(invalid("phase0 quota outside hard ceiling"));
            }
        }
        if self.targets_per_uid > self.targets_global
            || self.target_fds_per_uid > self.target_fds_global
            || self.helpers_per_uid > self.helpers_global
            || self.reviews_per_uid > self.reviews_global
        {
            return Err(invalid("per-UID quota exceeds global quota"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub schema: String,
    pub id: String,
    pub revision: String,
    pub daemon_pid: u32,
    pub owner_uid: u32,
    pub profile_sha256: String,
}
impl Contract for Registration {
    fn validate(&self) -> Result<()> {
        if self.schema != "sigrund.registration.phase0.v1" || self.owner_uid == u32::MAX {
            return Err(invalid("invalid registration schema/owner"));
        }
        identifier(&self.id)?;
        hex(&self.revision)?;
        hex(&self.profile_sha256)?;
        Selector::Process {
            pid: self.daemon_pid,
            pid_scope: "daemon".into(),
        }
        .validate()
    }
}

/// Render every constraint as data as well as its binding; a digest is insufficient.
pub fn approval_description(
    bundle: &BindingBundle,
    intent: &Intent,
    resolved: &Account,
    acquisition: &Acquisition,
) -> Result<String> {
    bundle.validate()?;
    intent.validate()?;
    resolved.validate()?;
    acquisition.validate()?;
    if acquisition.sha256()? != bundle.target_binding.context_sha256
        || acquisition.daemon_epoch != bundle.target_binding.daemon_epoch
        || acquisition.instance_id != bundle.target_binding.instance_id
    {
        return Err(invalid("approval acquisition binding mismatch"));
    }
    if intent.security_profile != bundle.constraints.profile_id
        || !matches!(resolved, Account::Numeric { .. })
    {
        return Err(invalid("approval profile/account mismatch"));
    }
    serde_json::to_string_pretty(&serde_json::json!({
        "authority": bundle.host_id,
        "target_binding": bundle.target_binding,
        "intent": intent,
        "resolved_numeric_account": resolved,
        "verified_acquisition": acquisition,
        "security_constraints": bundle.constraints,
        "profile_sha256": bundle.profile_sha256,
        "mapping_notice": "IDs are destination-userns relative; host authority requires composed mapping evidence"
    })).map_err(|e| invalid(&e.to_string()))
}
