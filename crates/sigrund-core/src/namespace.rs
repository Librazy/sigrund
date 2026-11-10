//! Production process-environment records, compatible with the frozen G-05 schemas.
//! Records describe evidence. Only a retained live owner can authorize their use.
use crate::{CoreError, Result, json};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
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
            return Err(invalid("namespace record exceeds 64 KiB"));
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
            return Err(invalid("namespace record exceeds 64 KiB"));
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
pub use crate::host::Selector;
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
    pub executable_model: crate::executable::TrustModel,
    pub verify_exec_stop: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selinux {
    pub context: String,
    pub enforcing: bool,
    pub policy_change: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_executable_context"
    )]
    pub executable_context: Option<String>,
}
fn present_executable_context<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
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
impl Constraints {
    pub fn is_production(&self) -> bool {
        self.schema == "sigrund.constraints.namespace-selinux.v1"
    }
    pub fn executes(&self) -> bool {
        self.is_production() || self.schema == "sigrund.constraints.namespace-experimental.v1"
    }
}
impl Contract for Constraints {
    fn validate(&self) -> Result<()> {
        if !matches!(
            self.schema.as_str(),
            "sigrund.constraints.phase0.v1"
                | "sigrund.constraints.namespace-experimental.v1"
                | "sigrund.constraints.namespace-selinux.v1"
        ) {
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
            || self.apparmor != "unsupported"
            || !matches!(
                self.executable_model,
                crate::executable::TrustModel::DigestDirect
                    | crate::executable::TrustModel::DigestMemfd
            )
        {
            return Err(invalid("unsupported phase0 constraint combination"));
        }
        if self.is_production() {
            if self.profile_id != "namespace-selinux-v1"
                || !self.capabilities.is_empty()
                || self.executable_model != crate::executable::TrustModel::DigestMemfd
                || !self.selinux.enforcing
                || self.selinux.context != "system_u:system_r:sigrund_workload_t:s0:c1,c2"
                || self.selinux.executable_context.as_deref()
                    != Some("system_u:object_r:sigrund_workload_exec_t:s0")
                || self.selinux.policy_change != "detect_and_terminate"
                || !matches!(&self.seccomp, Seccomp::DenySyscalls { audit_arch: 0xc000003e, errno: 13, syscalls } if syscalls == &[110])
            {
                return Err(invalid(
                    "unsupported production namespace constraint combination",
                ));
            }
        } else if self.schema == "sigrund.constraints.namespace-experimental.v1" {
            if self.profile_id != "namespace-experimental-v1"
                || !self.capabilities.is_empty()
                || self.executable_model != crate::executable::TrustModel::DigestMemfd
                || self.selinux.executable_context.is_some()
                || self.selinux.enforcing
                || !self.selinux.context.is_empty()
                || self.selinux.policy_change != "unmanaged"
                || !matches!(self.seccomp, Seccomp::None {})
            {
                return Err(invalid("unsupported experimental constraint combination"));
            }
        } else {
            text(&self.selinux.context, 4096)?;
            if self.selinux.executable_context.is_some()
                || !self.selinux.enforcing
                || self.selinux.policy_change != "reject"
                || self.selinux.context.splitn(4, ':').count() != 4
            {
                return Err(invalid("complete enforcing SELinux context required"));
            }
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
        .validate_selection()
    }
}

/// Destination-relative credentials and their composed host kernel identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub host_uid: u32,
    pub host_gid: u32,
    pub host_groups: Vec<u32>,
}
impl Acquisition {
    pub fn compose_credentials(&self, uid: u32, gid: u32, groups: Vec<u32>) -> Result<Credentials> {
        self.validate()?;
        crate::host::credentials(uid, gid, &groups)?;
        fn mapped(id: u32, extents: &[Extent]) -> Result<u32> {
            extents
                .iter()
                .find_map(|extent| {
                    let offset = id.checked_sub(extent.inside)?;
                    (offset < extent.count)
                        .then(|| extent.outside.checked_add(offset))
                        .flatten()
                })
                .filter(|value| *value != u32::MAX)
                .ok_or_else(|| invalid("unmapped destination identity"))
        }
        let mut host_uid = uid;
        let mut host_gid = gid;
        let mut host_groups = groups.clone();
        for layer in &self.mappings {
            host_uid = mapped(host_uid, &layer.uid)?;
            host_gid = mapped(host_gid, &layer.gid)?;
            for group in &mut host_groups {
                *group = mapped(*group, &layer.gid)?;
            }
        }
        host_groups.sort_unstable();
        Ok(Credentials {
            uid,
            gid,
            groups,
            host_uid,
            host_gid,
            host_groups,
        })
    }
}

/// The production acquisition record also fixes executable root objects for
/// the instance. The nested G-01 observations retain their frozen schema.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessContext {
    pub schema: String,
    pub acquisition: Acquisition,
    pub executable_roots: BTreeMap<String, FsIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_source: Option<ConnectorObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<crate::manager::PodmanEvidence>,
}
impl Contract for ProcessContext {
    fn validate(&self) -> Result<()> {
        if !matches!(
            self.schema.as_str(),
            "sigrund.process-context.v1" | "sigrund.self-context.v1" | "sigrund.podman-context.v1"
        ) || self.executable_roots.is_empty()
            || self.executable_roots.len() > 64
        {
            return Err(invalid(
                "invalid process context schema or executable roots",
            ));
        }
        self.acquisition.validate()?;
        match (&self.manager, self.schema.as_str()) {
            (Some(evidence), "sigrund.podman-context.v1")
                if self.acquisition.lifecycle.registration_id.is_some() =>
            {
                evidence.validate()?
            }
            (None, "sigrund.process-context.v1" | "sigrund.self-context.v1") => (),
            _ => return Err(invalid("manager evidence and context schema differ")),
        }
        match (&self.authenticated_source, self.schema.as_str()) {
            (None, "sigrund.process-context.v1" | "sigrund.podman-context.v1") => (),
            (Some(source), "sigrund.self-context.v1")
                if self.acquisition.lifecycle.registration_id.is_none() =>
            {
                source.verify_capture(&self.acquisition)?
            }
            _ => return Err(invalid("context schema differs from source attribution")),
        }
        for (path, identity) in &self.executable_roots {
            if !path.starts_with('/')
                || path == "/"
                || path.contains('\0')
                || path[1..]
                    .split('/')
                    .any(|part| matches!(part, "" | "." | ".."))
            {
                return Err(invalid("invalid pinned executable root path"));
            }
            identity.validate()?;
        }
        Ok(())
    }
}

/// Kernel credentials from the public request connection and its SO_PEERSEC
/// observation at capture. Live process attributes remain in Acquisition::anchor.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorObservation {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub supplementary_gids: Vec<u32>,
    #[serde(deserialize_with = "required_option")]
    pub security_label: Option<String>,
}
impl ConnectorObservation {
    pub fn verify_capture(&self, acquisition: &Acquisition) -> Result<()> {
        if self.pid != acquisition.pid
            || self.uid != acquisition.anchor.host_uid
            || self.gid != acquisition.anchor.host_gid
            || self.supplementary_gids != acquisition.anchor.host_groups
        {
            return Err(invalid("capture differs from public connector credentials"));
        }
        if let Some(label) = &self.security_label {
            text(label, 4096)?;
        }
        Ok(())
    }
}

/// Root-controlled review evidence for a single prepared process request.
/// Its references are checked against the exact canonical CSR before rendering.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessReview {
    pub schema: String,
    pub exec_id: String,
    pub csr_sha256: String,
    pub acquisition: Acquisition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_source: Option<ConnectorObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<crate::manager::PodmanEvidence>,
    #[serde(deserialize_with = "required_option")]
    pub registration: Option<Registration>,
    pub constraints: Constraints,
    pub executable_roots: BTreeMap<String, FsIdentity>,
    pub prepared_cwd: FsIdentity,
    pub prepared_executable: FsIdentity,
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}
impl Contract for ProcessReview {
    fn validate(&self) -> Result<()> {
        if !matches!(
            self.schema.as_str(),
            "sigrund.process-review.v1" | "sigrund.self-review.v1" | "sigrund.podman-review.v1"
        ) {
            return Err(invalid("unsupported process review schema"));
        }
        uuid7(&self.exec_id)?;
        hex(&self.csr_sha256)?;
        self.context().validate()?;
        self.constraints.validate()?;
        self.prepared_cwd.validate()?;
        self.prepared_executable.validate()?;
        if !matches!(self.acquisition.capture, Capture::TracedPrivateFsV1) {
            return Err(invalid("process review requires a captured connector"));
        }
        match (&self.registration, self.schema.as_str()) {
            (Some(registration), "sigrund.process-review.v1" | "sigrund.podman-review.v1") => {
                registration.validate()?;
                if registration.profile_sha256 != self.constraints.sha256()?
                    || registration.daemon_pid != self.acquisition.pid
                    || self.acquisition.lifecycle.registration_id.as_deref()
                        != Some(&registration.id)
                    || self.acquisition.lifecycle.registration_revision.as_deref()
                        != Some(&registration.revision)
                {
                    return Err(invalid("process review records differ"));
                }
            }
            (None, "sigrund.self-review.v1")
                if self.acquisition.lifecycle.registration_id.is_none()
                    && self.acquisition.lifecycle.registration_revision.is_none()
                    && self.constraints.executes() => {}
            _ => return Err(invalid("review schema and registration dependency differ")),
        }
        Ok(())
    }
}
impl ProcessReview {
    pub fn context(&self) -> ProcessContext {
        ProcessContext {
            schema: if self.schema == "sigrund.podman-review.v1" {
                "sigrund.podman-context.v1"
            } else if self.schema == "sigrund.self-review.v1" {
                "sigrund.self-context.v1"
            } else {
                "sigrund.process-context.v1"
            }
            .into(),
            acquisition: self.acquisition.clone(),
            authenticated_source: self.authenticated_source.clone(),
            manager: self.manager.clone(),
            executable_roots: self.executable_roots.clone(),
        }
    }

    pub fn binding(&self) -> Result<crate::host::ExecutionBinding> {
        self.validate()?;
        Ok(crate::host::ExecutionBinding {
            target_binding: crate::host::TargetBinding {
                kind: "process_environment".into(),
                daemon_epoch: self.acquisition.daemon_epoch.clone(),
                instance_id: self.acquisition.instance_id.clone(),
                description: self.registration.as_ref().map_or_else(
                    || "Authenticated connector process environment".into(),
                    |registration| format!("Registered process environment {}", registration.id),
                ),
                context_sha256: self.context().sha256()?,
            },
            security_constraints: crate::host::SecurityConstraints {
                profile_id: self.constraints.profile_id.clone(),
                profile_sha256: self.constraints.sha256()?,
            },
        })
    }
    pub fn verify_csr(&self, csr: &crate::warrant::Csr) -> Result<()> {
        self.validate()?;
        use crate::host::Record;
        let w = csr.warrant();
        self.acquisition.compose_credentials(
            w.execution_context.target_uid,
            w.execution_context.target_gid,
            w.execution_context.supplementary_gids.clone(),
        )?;
        let target_matches = match (&w.intent.target, &self.registration) {
            (crate::host::Selector::Registered { id }, Some(registration)) => {
                id == &registration.id
            }
            (crate::host::Selector::Process { pid, pid_scope }, Some(registration)) => {
                *pid == registration.daemon_pid && pid_scope == "daemon"
            }
            (crate::host::Selector::Self_ {}, None) => {
                w.requester_uid == self.acquisition.anchor.host_uid
                    && w.requester_gid == self.acquisition.anchor.host_gid
            }
            _ => false,
        };
        if self.constraints.executes()
            && (w.execution_context.target_uid == 0
                || !w.execution_context.supplementary_gids.is_empty())
        {
            return Err(invalid(
                "experimental execution requires non-root UID and empty groups",
            ));
        }
        if !target_matches
            || self.csr_sha256 != crate::crypto::sha256_hex(csr.as_bytes())
            || w.request_origin != "daemon_expanded_thin"
            || w.approval_exec_id.as_deref() != Some(&self.exec_id)
            || w.execution_binding()? != self.binding()?
            || w.execution_context.capabilities != self.constraints.capabilities
            || w.command
                .executable_trust
                .as_ref()
                .map(|model| model.model())
                != Some(self.constraints.executable_model)
        {
            return Err(invalid("process review differs from exact CSR"));
        }
        w.validate()
    }
    pub fn render(&self, csr: &crate::warrant::Csr) -> Result<String> {
        self.verify_csr(csr)?;
        let w = csr.warrant();
        let credentials = self.acquisition.compose_credentials(
            w.execution_context.target_uid,
            w.execution_context.target_gid,
            w.execution_context.supplementary_gids.clone(),
        )?;
        let mut evidence = serde_json::json!({
            "authority": w.host_id,
            "target_binding": w.target_binding,
            "declared_registration": self.registration,
            "authenticated_source": self.authenticated_source,
            "verified_acquisition": self.acquisition,
            "pinned_executable_roots": self.executable_roots,
            "requested_account": w.intent.account,
            "resolved_numeric_account": {
                "uid": w.execution_context.target_uid,
                "gid": w.execution_context.target_gid,
                "supplementary_gids": w.execution_context.supplementary_gids,
            },
            "mapped_host_credentials": {
                "uid": credentials.host_uid,
                "gid": credentials.host_gid,
                "supplementary_gids": credentials.host_groups,
            },
            "request_origin": w.request_origin,
            "intent_sha256": w.intent_sha256,
            "command": w.command,
            "prepared_cwd": self.prepared_cwd,
            "prepared_executable": self.prepared_executable,
            "security_constraints": self.constraints,
            "execution_availability": if self.constraints.is_production() {
                "SELinux-constrained execution; final-child checkpoint required"
            } else if self.constraints.schema == "sigrund.constraints.namespace-experimental.v1" {
                "Experimental execution; final-child checkpoint required"
            } else { "Phase 2 private review; execution is disabled" },
            "workload_lsm_transition": if self.constraints.schema == "sigrund.constraints.namespace-experimental.v1" {
                "none requested; ambient LSM policy still applies"
            } else {
                "required by security_constraints"
            },
        });
        if let Some(manager) = &self.manager {
            evidence["manager"] = serde_json::json!({
                "evidence": manager,
                "generation_contract": "Rootful Podman; systemd cgroup membership and private PID-1 init required; configuration must remain unchanged",
                "loss_contract": "Invalidate pending approval and terminate supervised jobs; recovery requires fresh acquisition and approval",
                "execution_contract": "Native retained-resource execution under the displayed security constraints; no Podman exec-policy equivalence",
            });
        }
        serde_json::to_string_pretty(&evidence).map_err(|error| invalid(&error.to_string()))
    }
}
