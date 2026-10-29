use serde::Deserialize;
use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use crate::{CoreError, Result};

const MAX_SOCKETS_GLOBAL: u32 = 64;
const MAX_SOCKETS_UID: u32 = 4;
const MAX_WORKERS_GLOBAL: u32 = 16;
const MAX_WORKERS_UID: u32 = 2;
const MAX_REQUEST_DEADLINE_MS: u32 = 5_000;
const MAX_HOOK_TIMEOUT_MS: u32 = 25_000;
const MAX_COLLECTOR_TIMEOUT_MS: u32 = 3_000;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    #[serde(default)]
    pub allow_same_uid_elevation: bool,
    #[serde(default)]
    pub require_remote_audit_ack: bool,
    pub csr_allowed_executable_dirs: Vec<PathBuf>,
    #[serde(default = "default_hook_uid")]
    pub sigrun_hook_uid: u32,
    #[serde(default = "default_hook_gid")]
    pub sigrun_hook_gid: u32,
    #[serde(default = "one")]
    pub max_active_hooks_per_uid: u32,
    #[serde(default = "eight")]
    pub max_active_hooks_global: u32,
    #[serde(default = "five")]
    pub hook_invocations_per_uid: u32,
    #[serde(default = "sixty")]
    pub hook_window_secs: u32,
    #[serde(default = "default_hook_timeout")]
    pub hook_timeout_ms: u32,
    #[serde(default = "sixty_four")]
    pub max_active_sockets_global: u32,
    #[serde(default = "four")]
    pub max_active_sockets_per_uid: u32,
    #[serde(default = "sixteen")]
    pub max_io_workers_global: u32,
    #[serde(default = "two")]
    pub max_io_workers_per_uid: u32,
    #[serde(default = "default_snapshot_global")]
    pub snapshot_ram_global_bytes: u64,
    #[serde(default = "default_snapshot_uid")]
    pub snapshot_ram_per_uid_bytes: u64,
    #[serde(default = "default_executable")]
    pub max_executable_bytes: u64,
    #[serde(default = "default_stdin")]
    pub max_stdin_bytes: u64,
    #[serde(default = "default_request_deadline")]
    pub request_deadline_ms: u32,
    #[serde(default = "default_memory")]
    pub job_memory_max_bytes: u64,
    #[serde(default)]
    pub job_memory_swap_max_bytes: u64,
    #[serde(default = "default_pids")]
    pub job_pids_max: u64,
    pub collector_base_url: String,
    pub collector_server_name: String,
    pub collector_ca_file: PathBuf,
    pub collector_client_cert_file: PathBuf,
    pub collector_client_key_file: PathBuf,
    pub collector_key_id: String,
    pub collector_public_key: String,
    #[serde(default = "default_collector_timeout")]
    pub collector_rpc_timeout_ms: u32,
    #[serde(default = "audit_max")]
    pub audit_record_max_bytes: u64,
    #[serde(default = "default_onetime_window")]
    pub max_onetime_window_secs: u64,
    #[serde(default = "default_ttl")]
    pub max_ttl_secs: u64,
}

#[derive(Clone, Debug)]
pub struct PolicyGeneration {
    pub number: u64,
    pub config: Arc<DaemonConfig>,
}

#[derive(Clone, Debug)]
pub struct CapturedPolicy {
    pub generation: u64,
    pub max_active_hooks_per_uid: u32,
    pub max_active_hooks_global: u32,
    pub hook_invocations_per_uid: u32,
    pub hook_window_secs: u32,
    pub hook_timeout_ms: u32,
    pub max_active_sockets_global: u32,
    pub max_active_sockets_per_uid: u32,
    pub max_io_workers_global: u32,
    pub max_io_workers_per_uid: u32,
    pub snapshot_ram_global_bytes: u64,
    pub snapshot_ram_per_uid_bytes: u64,
    pub max_executable_bytes: u64,
    pub max_stdin_bytes: u64,
    pub request_deadline_ms: u32,
    pub job_memory_max_bytes: u64,
    pub job_memory_swap_max_bytes: u64,
    pub job_pids_max: u64,
    pub collector_rpc_timeout_ms: u32,
}

impl PolicyGeneration {
    pub fn capture(&self) -> CapturedPolicy {
        let c = &self.config;
        CapturedPolicy {
            generation: self.number,
            max_active_hooks_per_uid: c.max_active_hooks_per_uid,
            max_active_hooks_global: c.max_active_hooks_global,
            hook_invocations_per_uid: c.hook_invocations_per_uid,
            hook_window_secs: c.hook_window_secs,
            hook_timeout_ms: c.hook_timeout_ms,
            max_active_sockets_global: c.max_active_sockets_global,
            max_active_sockets_per_uid: c.max_active_sockets_per_uid,
            max_io_workers_global: c.max_io_workers_global,
            max_io_workers_per_uid: c.max_io_workers_per_uid,
            snapshot_ram_global_bytes: c.snapshot_ram_global_bytes,
            snapshot_ram_per_uid_bytes: c.snapshot_ram_per_uid_bytes,
            max_executable_bytes: c.max_executable_bytes,
            max_stdin_bytes: c.max_stdin_bytes,
            request_deadline_ms: c.request_deadline_ms,
            job_memory_max_bytes: c.job_memory_max_bytes,
            job_memory_swap_max_bytes: c.job_memory_swap_max_bytes,
            job_pids_max: c.job_pids_max,
            collector_rpc_timeout_ms: c.collector_rpc_timeout_ms,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignerPolicyFile {
    pub signers: Vec<SignerConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerConfig {
    pub signer_id: String,
    #[serde(rename = "type")]
    pub signature_type: String,
    pub public_key: String,
    #[serde(default)]
    pub require_user_presence: bool,
    #[serde(default)]
    pub require_user_verification: bool,
    pub allowed_requester_uids: Vec<u32>,
    pub allowed_target_uids: Vec<u32>,
    pub allowed_target_gids: Vec<u32>,
    pub allowed_supplementary_gids: Vec<u32>,
    #[serde(default)]
    pub allow_same_uid_elevation: bool,
    pub allowed_capabilities: Vec<String>,
    pub allowed_modes: Vec<String>,
    pub max_ttl_secs: u64,
    #[serde(default)]
    pub allow_unrestricted_stdin: bool,
    #[serde(default)]
    pub allow_pty: bool,
    #[serde(default)]
    pub allow_interpreted_scripts: bool,
    pub allowed_executable_dirs: Vec<PathBuf>,
}

impl SignerPolicyFile {
    pub fn from_toml(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|e| CoreError::Config(e.to_string()))?;
        let policy: Self = toml::from_str(text).map_err(|e| CoreError::Config(e.to_string()))?;
        if policy.signers.is_empty() {
            return Err(CoreError::Config("at least one signer is required".into()));
        }
        Ok(policy)
    }

    pub fn validate_against(&self, daemon: &DaemonConfig) -> Result<()> {
        for signer in &self.signers {
            if signer.signer_id.is_empty()
                || signer.allowed_executable_dirs != daemon.csr_allowed_executable_dirs
            {
                return Err(CoreError::Config(format!(
                    "signer {} executable roots differ from daemon roots",
                    signer.signer_id
                )));
            }
            if signer
                .allowed_executable_dirs
                .iter()
                .any(|path| !safe_root_path(path))
                || signer
                    .allowed_executable_dirs
                    .windows(2)
                    .any(|w| w[0] >= w[1])
            {
                return Err(CoreError::Config(format!(
                    "signer {} has non-canonical executable roots",
                    signer.signer_id
                )));
            }
            if signer
                .allowed_requester_uids
                .iter()
                .any(|uid| *uid == u32::MAX)
                || signer
                    .allowed_target_uids
                    .iter()
                    .any(|uid| *uid == u32::MAX)
                || signer
                    .allowed_target_gids
                    .iter()
                    .any(|gid| *gid == u32::MAX)
                || signer
                    .allowed_supplementary_gids
                    .iter()
                    .any(|gid| *gid == u32::MAX)
            {
                return Err(CoreError::Config(format!(
                    "signer {} contains overflow UID/GID",
                    signer.signer_id
                )));
            }
        }
        Ok(())
    }
}

impl DaemonConfig {
    pub fn from_toml(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| CoreError::Config(format!("configuration is not UTF-8: {e}")))?;
        let config: Self = toml::from_str(text).map_err(|e| CoreError::Config(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.csr_allowed_executable_dirs.is_empty()
            || self
                .csr_allowed_executable_dirs
                .iter()
                .any(|p| !safe_root_path(p))
            || self
                .csr_allowed_executable_dirs
                .windows(2)
                .any(|w| w[0] >= w[1])
            || self.sigrun_hook_uid == u32::MAX
            || self.sigrun_hook_gid == u32::MAX
        {
            return Err(CoreError::Config(
                "invalid executable roots or hook identity".into(),
            ));
        }
        if self.max_active_sockets_global == 0
            || self.max_active_sockets_global > MAX_SOCKETS_GLOBAL
            || self.max_active_sockets_per_uid == 0
            || self.max_active_sockets_per_uid > MAX_SOCKETS_UID
            || self.max_io_workers_global == 0
            || self.max_io_workers_global > MAX_WORKERS_GLOBAL
            || self.max_io_workers_per_uid == 0
            || self.max_io_workers_per_uid > MAX_WORKERS_UID
            || self.request_deadline_ms == 0
            || self.request_deadline_ms > MAX_REQUEST_DEADLINE_MS
            || self.hook_timeout_ms == 0
            || self.hook_timeout_ms > MAX_HOOK_TIMEOUT_MS
            || self.collector_rpc_timeout_ms == 0
            || self.collector_rpc_timeout_ms > MAX_COLLECTOR_TIMEOUT_MS
        {
            return Err(CoreError::Config(
                "value exceeds immutable protocol ceiling".into(),
            ));
        }
        if self.max_executable_bytes == 0
            || self.max_executable_bytes > 67_108_864
            || self.max_stdin_bytes == 0
            || self.max_stdin_bytes > 16_777_216
            || self.snapshot_ram_global_bytes == 0
            || self.snapshot_ram_global_bytes > 536_870_912
            || self.snapshot_ram_per_uid_bytes == 0
            || self.snapshot_ram_per_uid_bytes > 134_217_728
            || self.job_memory_max_bytes == 0
            || self.job_pids_max == 0
            || self.audit_record_max_bytes != 65_536
            || self.collector_key_id.is_empty()
            || self.collector_key_id.len() > 128
            || !self.collector_base_url.starts_with("https://")
            || self.collector_base_url.contains(['#', '@'])
            || self.collector_server_name.is_empty()
            || self.collector_server_name.len() > 255
            || !self.collector_server_name.is_ascii()
            || !self.collector_ca_file.is_absolute()
            || !self.collector_client_cert_file.is_absolute()
            || !self.collector_client_key_file.is_absolute()
        {
            return Err(CoreError::Config(
                "invalid quota or collector bounds".into(),
            ));
        }
        let mut unique = BTreeSet::new();
        if self
            .csr_allowed_executable_dirs
            .iter()
            .any(|p| !unique.insert(p))
        {
            return Err(CoreError::Config("duplicate executable root".into()));
        }
        Ok(())
    }
}

fn safe_root_path(path: &Path) -> bool {
    let Some(raw) = path.to_str() else {
        return false;
    };
    if !path.is_absolute() || path == Path::new("/") || raw.ends_with('/') || raw.contains("//") {
        return false;
    }
    path.components()
        .skip(1)
        .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> DaemonConfig {
        DaemonConfig {
            allow_same_uid_elevation: false,
            require_remote_audit_ack: false,
            csr_allowed_executable_dirs: vec![
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/sbin"),
            ],
            sigrun_hook_uid: 65534,
            sigrun_hook_gid: 65534,
            max_active_hooks_per_uid: 1,
            max_active_hooks_global: 8,
            hook_invocations_per_uid: 5,
            hook_window_secs: 60,
            hook_timeout_ms: 25_000,
            max_active_sockets_global: 64,
            max_active_sockets_per_uid: 4,
            max_io_workers_global: 16,
            max_io_workers_per_uid: 2,
            snapshot_ram_global_bytes: 536_870_912,
            snapshot_ram_per_uid_bytes: 134_217_728,
            max_executable_bytes: 67_108_864,
            max_stdin_bytes: 16_777_216,
            request_deadline_ms: 5_000,
            job_memory_max_bytes: 268_435_456,
            job_memory_swap_max_bytes: 0,
            job_pids_max: 128,
            collector_base_url: "https://collector.example.invalid".into(),
            collector_server_name: "collector.example.invalid".into(),
            collector_ca_file: "/etc/sigrund/collector-ca.pem".into(),
            collector_client_cert_file: "/etc/sigrund/collector-client.crt".into(),
            collector_client_key_file: "/etc/sigrund/collector-client.key".into(),
            collector_key_id: "collector-v1".into(),
            collector_public_key: "key".into(),
            collector_rpc_timeout_ms: 3_000,
            audit_record_max_bytes: 65_536,
            max_onetime_window_secs: 3_600,
            max_ttl_secs: 31_536_000,
        }
    }

    #[test]
    fn rejects_unsafe_roots_and_ceilings() {
        let mut cfg = valid();
        cfg.csr_allowed_executable_dirs = vec![PathBuf::from("/usr/../bin")];
        assert!(cfg.validate().is_err());
        let mut cfg = valid();
        cfg.max_io_workers_global = 17;
        assert!(cfg.validate().is_err());
    }
}

fn one() -> u32 {
    1
}
fn two() -> u32 {
    2
}
fn four() -> u32 {
    4
}
fn five() -> u32 {
    5
}
fn eight() -> u32 {
    8
}
fn sixteen() -> u32 {
    16
}
fn sixty() -> u32 {
    60
}
fn sixty_four() -> u32 {
    64
}
fn default_hook_uid() -> u32 {
    65_534
}
fn default_hook_gid() -> u32 {
    65_534
}
fn default_hook_timeout() -> u32 {
    25_000
}
fn default_snapshot_global() -> u64 {
    536_870_912
}
fn default_snapshot_uid() -> u64 {
    134_217_728
}
fn default_executable() -> u64 {
    67_108_864
}
fn default_stdin() -> u64 {
    16_777_216
}
fn default_request_deadline() -> u32 {
    5_000
}
fn default_memory() -> u64 {
    268_435_456
}
fn default_pids() -> u64 {
    128
}
fn default_collector_timeout() -> u32 {
    3_000
}
fn audit_max() -> u64 {
    65_536
}
fn default_onetime_window() -> u64 {
    3_600
}
fn default_ttl() -> u64 {
    31_536_000
}
