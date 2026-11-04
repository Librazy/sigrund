//! Signed executable evidence. Verity digests are not hashes of file bytes.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum TrustModel {
    FsVerity,
    Ctime,
    DigestDirect,
    DigestMemfd,
}

pub fn default_models() -> Vec<TrustModel> {
    vec![
        TrustModel::FsVerity,
        TrustModel::Ctime,
        TrustModel::DigestDirect,
        TrustModel::DigestMemfd,
    ]
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "model", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutableTrust {
    DigestMemfd {
        sha256: String,
    },
    DigestDirect {
        sha256: String,
    },
    FsVerity {
        algorithm: String,
        digest: String,
    },
    Ctime {
        device: String,
        inode: String,
        size: String,
        ctime_sec: i64,
        ctime_nsec: u32,
    },
}

impl ExecutableTrust {
    pub fn model(&self) -> TrustModel {
        match self {
            Self::DigestDirect { .. } => TrustModel::DigestDirect,
            Self::DigestMemfd { .. } => TrustModel::DigestMemfd,
            Self::FsVerity { .. } => TrustModel::FsVerity,
            Self::Ctime { .. } => TrustModel::Ctime,
        }
    }

    pub fn valid(&self) -> bool {
        fn decimal(text: &str) -> Option<u64> {
            let n: u64 = text.parse().ok()?;
            (n.to_string() == text).then_some(n)
        }
        match self {
            Self::DigestDirect { sha256 } | Self::DigestMemfd { sha256 } => {
                sha256.len() == 64
                    && sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }
            Self::FsVerity { algorithm, digest } => {
                let length = match algorithm.as_str() {
                    "sha256" => 64,
                    "sha512" => 128,
                    _ => return false,
                };
                digest.len() == length
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }
            Self::Ctime {
                device,
                inode,
                size,
                ctime_sec,
                ctime_nsec,
            } => {
                decimal(device).is_some()
                    && decimal(inode).is_some_and(|n| n > 0)
                    && decimal(size).is_some_and(|n| n > 0 && n <= i64::MAX as u64)
                    && (0..=crate::warrant::MAX_TIMESTAMP).contains(ctime_sec)
                    && *ctime_nsec < 1_000_000_000
            }
        }
    }
}

/// Exact capability state approved for the first user instruction.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySets {
    pub permitted: Vec<String>,
    pub effective: Vec<String>,
    pub inheritable: Vec<String>,
    pub ambient: Vec<String>,
    pub bounding: Vec<String>,
}
impl CapabilitySets {
    pub fn ordinary(authority: &[String]) -> Self {
        Self {
            permitted: authority.to_vec(),
            effective: authority.to_vec(),
            inheritable: authority.to_vec(),
            ambient: authority.to_vec(),
            bounding: authority.to_vec(),
        }
    }
    pub fn valid(&self, authority: &[String]) -> bool {
        let sets = [
            &self.permitted,
            &self.effective,
            &self.inheritable,
            &self.ambient,
            &self.bounding,
        ];
        sets.iter().all(|set| {
            set.len() <= 64
                && set.windows(2).all(|w| w[0] < w[1])
                && set.iter().all(|c| authority.contains(c))
        }) && self.bounding == authority
            && self.inheritable == authority
            && self.effective.iter().all(|c| self.permitted.contains(c))
            && self
                .ambient
                .iter()
                .all(|c| self.permitted.contains(c) && self.inheritable.contains(c))
    }
}
