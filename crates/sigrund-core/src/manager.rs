//! Versioned manager evidence. Metadata never replaces retained kernel resources.
use crate::{CoreError, Result, namespace::Contract};
use serde::{Deserialize, Serialize};

fn invalid(message: &str) -> CoreError {
    CoreError::Value(message.into())
}
fn digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid manager digest or full container ID"));
    }
    Ok(())
}
fn decimal(value: &str) -> Result<()> {
    let number: u64 = value
        .parse()
        .map_err(|_| invalid("invalid manager kernel identity"))?;
    if number == 0 || number.to_string() != value {
        return Err(invalid("noncanonical manager kernel identity"));
    }
    Ok(())
}

/// Root-selected authority domain. The first adapter supports a local rootful
/// service in the default Libpod namespace; other scopes reject explicitly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PodmanSelector {
    pub schema: String,
    pub endpoint: String,
    pub owner_uid: u32,
    pub manager_namespace: String,
    pub container_name: String,
}
impl Contract for PodmanSelector {
    fn validate(&self) -> Result<()> {
        if self.schema != "sigrund.podman-selector.v1"
            || self.owner_uid != 0
            || self.manager_namespace != "default"
        {
            return Err(invalid("unsupported Podman selector scope"));
        }
        crate::namespace::identifier(&self.container_name)?;
        if !self.container_name.as_bytes()[0].is_ascii_alphanumeric() {
            return Err(invalid(
                "Podman name must start with an alphanumeric character",
            ));
        }
        if self.endpoint.len() > 4096
            || !self.endpoint.starts_with('/')
            || self.endpoint[1..].split('/').any(|part| {
                part.is_empty() || matches!(part, "." | "..") || part.chars().any(char::is_control)
            })
        {
            return Err(invalid("invalid local Podman socket path"));
        }
        Ok(())
    }
}

/// Immutable observation bound to one retained stream and init pidfd. Endpoint
/// and process numbers describe observations, not independently usable authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PodmanEvidence {
    pub schema: String,
    pub manager_version: String,
    pub selector: PodmanSelector,
    pub container_id: String,
    pub init_pid: u32,
    pub init_start_ticks: String,
    pub started_at: String,
    pub configuration_sha256: String,
    pub endpoint_device: String,
    pub endpoint_inode: String,
    pub peer_pid: u32,
    pub peer_start_ticks: String,
}
impl Contract for PodmanEvidence {
    fn validate(&self) -> Result<()> {
        self.selector.validate()?;
        let version: Vec<_> = self.manager_version.split('.').collect();
        if version.len() != 3
            || version[0] != "5"
            || version.iter().any(|part| {
                part.parse::<u32>().is_err() || part.parse::<u32>().unwrap().to_string() != *part
            })
        {
            return Err(invalid("unsupported Podman API version"));
        }
        if self.schema != "sigrund.podman-evidence.v1"
            || self.init_pid == 0
            || self.init_pid > i32::MAX as u32
            || self.peer_pid == 0
            || self.peer_pid > i32::MAX as u32
            || self.started_at.is_empty()
            || self.started_at.len() > 64
            || !self
                .started_at
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-: .+".contains(&b))
        {
            return Err(invalid("invalid Podman generation observation"));
        }
        digest(&self.container_id)?;
        digest(&self.configuration_sha256)?;
        decimal(&self.init_start_ticks)?;
        decimal(&self.endpoint_device)?;
        decimal(&self.endpoint_inode)?;
        decimal(&self.peer_start_ticks)?;
        Ok(())
    }
}
