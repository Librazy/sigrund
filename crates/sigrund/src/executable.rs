//! Worker-owned executable selection and evidence verification.
use crate::{
    snapshot::{self, SealedSnapshot, SnapshotBudget},
    transport::invalid,
};
use sigrund_core::{
    config::DaemonConfig,
    executable::{ExecutableTrust, TrustModel},
    protocol::RequestedExecutionContext,
    snapshot::SnapshotDigest,
    warrant::Command,
};
use std::{
    fs::File,
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::fs::{FileExt, MetadataExt},
    },
};

pub struct Executable {
    // Keep descriptors ahead of quota-owning snapshots in destruction order.
    source: Option<File>,
    sealed: Option<SealedSnapshot>,
    pub digest: SnapshotDigest,
    pub trust: Option<ExecutableTrust>,
}
impl From<SealedSnapshot> for Executable {
    fn from(sealed: SealedSnapshot) -> Self {
        Self {
            digest: sealed.digest.clone(),
            sealed: Some(sealed),
            source: None,
            trust: None,
        }
    }
}
impl AsFd for Executable {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match (&self.source, &self.sealed) {
            (Some(file), None) => file.as_fd(),
            (None, Some(sealed)) => sealed.as_fd(),
            _ => unreachable!("executable owner invariant"),
        }
    }
}
impl Executable {
    pub fn matches_command(&self, command: &Command) -> bool {
        use subtle::ConstantTimeEq;
        let digest_matches = match (&command.executable_sha256, self.sha256()) {
            (None, None) => true,
            (Some(expected), Some(actual)) => {
                bool::from(expected.as_bytes().ct_eq(actual.as_bytes()))
            }
            _ => false,
        };
        digest_matches && command.executable_trust == self.trust
    }
    pub fn model(&self) -> TrustModel {
        self.trust
            .as_ref()
            .map_or(TrustModel::DigestMemfd, ExecutableTrust::model)
    }
    pub fn sha256(&self) -> Option<String> {
        self.sealed.as_ref().map(|_| self.digest.sha256.clone())
    }
    pub fn sealed(&self) -> Option<&SealedSnapshot> {
        self.sealed.as_ref()
    }
    pub fn needs_checkpoint(&self) -> bool {
        self.model() == TrustModel::Ctime
    }
    pub fn verify_direct(&self) -> io::Result<()> {
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| invalid("not a direct executable"))?;
        let trust = self
            .trust
            .as_ref()
            .ok_or_else(|| invalid("missing executable evidence"))?;
        let observed = match trust {
            ExecutableTrust::FsVerity { .. } => {
                verity(source)?.ok_or_else(|| invalid("verity no longer available"))?
            }
            ExecutableTrust::Ctime { .. } => {
                let m = source.metadata()?;
                if !ctime_eligible(source, &m)? {
                    return Err(invalid("ctime executable no longer trusted"));
                }
                ctime(&m)
            }
        };
        if &observed != trust {
            return Err(invalid("executable evidence changed"));
        }
        Ok(())
    }
    /// Called off-loop with the tracee stopped before its first user instruction.
    pub fn verify_exec(&self, pid: i32, context: &RequestedExecutionContext) -> io::Result<()> {
        self.verify_direct()?;
        let actual = std::fs::metadata(format!("/proc/{pid}/exe"))?;
        let source = self
            .source
            .as_ref()
            .expect("direct executable")
            .metadata()?;
        if (actual.dev(), actual.ino()) != (source.dev(), source.ino()) {
            return Err(invalid("exec loaded a different inode"));
        }
        // A direct file must not change the credentials/capabilities established
        // by the trusted setup stub. Read a bounded proc status while stopped.
        use std::io::Read;
        let mut status = String::new();
        File::open(format!("/proc/{pid}/status"))?
            .take(65537)
            .read_to_string(&mut status)?;
        if status.len() > 65536 {
            return Err(invalid("oversized process status"));
        }
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
        };
        for (name, expected) in [("Uid:", context.target_uid), ("Gid:", context.target_gid)] {
            let ids = field(name)
                .ok_or_else(|| invalid("missing credentials"))?
                .split_whitespace()
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| invalid("invalid credentials"))?;
            if ids != vec![expected; 4] {
                return Err(invalid("exec changed credentials"));
            }
        }
        let expected = context
            .capabilities
            .iter()
            .try_fold(0u64, |bits, name| {
                crate::authorization::capability_number(name).map(|n| bits | (1u64 << n))
            })
            .ok_or_else(|| invalid("invalid capabilities"))?;
        for name in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:", "CapBnd:"] {
            let bits = u64::from_str_radix(
                field(name).ok_or_else(|| invalid("missing capabilities"))?,
                16,
            )
            .map_err(|_| invalid("invalid process capabilities"))?;
            if bits != expected {
                return Err(invalid("exec changed capabilities"));
            }
        }
        if field("NoNewPrivs:") != Some("1") {
            return Err(invalid("exec lost no_new_privs"));
        }
        Ok(())
    }
}

pub struct Selection<'a> {
    pub signed: Option<&'a Command>,
    pub context: &'a RequestedExecutionContext,
    pub trace_available: bool,
}

pub fn prepare(
    source: File,
    selection: Selection<'_>,
    budget: &SnapshotBudget,
    uid: u32,
    config: &DaemonConfig,
    check: impl Fn() -> io::Result<()>,
) -> io::Result<Executable> {
    check()?;
    let metadata = source.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(invalid("invalid executable type or size"));
    }
    let required = selection.signed.map(|c| {
        c.executable_trust
            .as_ref()
            .map_or(TrustModel::DigestMemfd, ExecutableTrust::model)
    });
    for model in &config.executable_trust_models {
        if required.is_some_and(|required| required != *model) {
            continue;
        }
        check()?;
        if *model == TrustModel::DigestMemfd {
            return snapshot::executable(source, budget, uid, config, check).map(Into::into);
        }
        if !direct_eligible(&source, &metadata, selection.context)? {
            continue;
        }
        let trust = match model {
            TrustModel::FsVerity => verity(&source)?,
            TrustModel::Ctime
                if selection.trace_available && ctime_eligible(&source, &metadata)? =>
            {
                Some(ctime(&metadata))
            }
            _ => None,
        };
        if let Some(trust) = trust {
            let mut magic = [0u8; 4];
            source.read_exact_at(&mut magic, 0)?;
            check()?;
            if magic != *b"\x7fELF" {
                return Err(invalid("direct executable is not ELF"));
            }
            let executable = Executable {
                source: Some(source),
                sealed: None,
                digest: SnapshotDigest {
                    bytes: metadata.len(),
                    sha256: String::new(),
                },
                trust: Some(trust),
            };
            executable.verify_direct()?;
            return Ok(executable);
        }
    }
    Err(invalid("no enabled executable trust model applies"))
}

fn filesystem(source: &File) -> io::Result<u64> {
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(source.as_raw_fd(), &mut stat) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat.f_type as u64)
}
fn no_xattr(source: &File, name: &std::ffi::CStr) -> io::Result<bool> {
    let result =
        unsafe { libc::fgetxattr(source.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if result >= 0 {
        return Ok(false);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENODATA | libc::EOPNOTSUPP) => Ok(true),
        _ => Err(error),
    }
}
fn direct_eligible(
    source: &File,
    m: &std::fs::Metadata,
    c: &RequestedExecutionContext,
) -> io::Result<bool> {
    let mut mount: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(source.as_raw_fd(), &mut mount) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if m.mode() & 0o6000 != 0 || mount.f_flag & libc::ST_NOEXEC != 0 {
        return Ok(false);
    }
    // The setup stub sets SECBIT_NOROOT and grants only requested
    // capabilities, so UID 0 does not imply DAC override.
    let execute = if c.target_uid == m.uid() {
        m.mode() & 0o100 != 0
    } else if c.target_gid == m.gid() || c.supplementary_gids.contains(&m.gid()) {
        m.mode() & 0o010 != 0
    } else {
        m.mode() & 0o001 != 0
    };
    Ok(execute
        && no_xattr(source, c"security.capability")?
        && no_xattr(source, c"system.posix_acl_access")?)
}
fn ctime_eligible(source: &File, m: &std::fs::Metadata) -> io::Result<bool> {
    Ok(m.is_file()
        && m.uid() == 0
        && m.mode() & 0o6022 == 0
        && m.len() > 0
        && matches!(
            filesystem(source)?,
            0xef53 | 0xf2f52010 | 0x9123683e | 0x58465342 | 0x01021994
        )
        && no_xattr(source, c"security.capability")?
        && no_xattr(source, c"system.posix_acl_access")?)
}
fn ctime(m: &std::fs::Metadata) -> ExecutableTrust {
    ExecutableTrust::Ctime {
        device: m.dev().to_string(),
        inode: m.ino().to_string(),
        size: m.len().to_string(),
        ctime_sec: m.ctime(),
        ctime_nsec: m.ctime_nsec() as u32,
    }
}
fn verity(source: &File) -> io::Result<Option<ExecutableTrust>> {
    if !matches!(filesystem(source)?, 0xef53 | 0xf2f52010 | 0x9123683e) {
        return Ok(None);
    }
    #[repr(C)]
    struct Digest {
        algorithm: u16,
        size: u16,
        bytes: [u8; 64],
    }
    let mut digest = Digest {
        algorithm: 0,
        size: 64,
        bytes: [0; 64],
    };
    if unsafe { libc::ioctl(source.as_raw_fd(), 0xc0046686 as libc::c_ulong, &mut digest) } < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENODATA | libc::ENOTTY | libc::EOPNOTSUPP) => Ok(None),
            _ => Err(error),
        };
    }
    let algorithm = match (digest.algorithm, digest.size) {
        (1, 32) => "sha256",
        (2, 64) => "sha512",
        _ => return Err(invalid("unsupported verity digest")),
    };
    Ok(Some(ExecutableTrust::FsVerity {
        algorithm: algorithm.into(),
        digest: digest.bytes[..digest.size as usize]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    }))
}
