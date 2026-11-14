//! Administrator-selected, signed SELinux workload authority.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Workload {
    Data,
    Network,
    Maintenance,
    Root,
}

impl Workload {
    pub fn authority(self) -> &'static str {
        match self {
            Self::Data => "Service data read/write; no IP networking; ordinary files readable",
            Self::Network => {
                "Service data read/write and TCP/UDP networking; ordinary files readable"
            }
            Self::Maintenance => {
                "Trusted system maintenance and package installation; broad host filesystem writes"
            }
            Self::Root => {
                "FULL HOST ROOT AUTHORITY: may change policy, replace the daemon and escape namespace containment"
            }
        }
    }
    pub fn context(self) -> &'static str {
        match self {
            Self::Data => "system_u:system_r:sigrund_data_workload_t:s0",
            Self::Network => "system_u:system_r:sigrund_network_workload_t:s0",
            Self::Maintenance => "system_u:system_r:sigrund_maintenance_workload_t:s0",
            Self::Root => "system_u:system_r:sigrund_root_workload_t:s0",
        }
    }

    pub fn from_context(context: &str) -> Option<Self> {
        [Self::Data, Self::Network, Self::Maintenance, Self::Root]
            .into_iter()
            .find(|policy| policy.context() == context)
    }

    pub fn validate_capabilities(self, capabilities: &[String]) -> crate::Result<()> {
        if capabilities.iter().any(|cap| cap == "CAP_SYS_ADMIN") && self != Self::Root {
            return Err(crate::CoreError::Protocol(
                "CAP_SYS_ADMIN requires the explicit root workload policy".into(),
            ));
        }
        if self == Self::Root && capabilities != Self::root_capabilities() {
            return Err(crate::CoreError::Protocol(
                "root workload requires the complete explicit capability set".into(),
            ));
        }
        Ok(())
    }

    /// Linux capabilities through CAP_CHECKPOINT_RESTORE. New kernel authority
    /// requires a reviewed protocol update, never an implicit wildcard grant.
    pub fn root_capabilities() -> Vec<String> {
        let mut capabilities = vec![
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
            "CAP_PERFMON",
            "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
        capabilities.sort();
        capabilities
    }
}
