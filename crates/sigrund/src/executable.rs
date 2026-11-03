//! Worker-owned executable selection and evidence verification.
use crate::{
    snapshot::{self, SealedSnapshot, SnapshotBudget},
    transport::invalid,
};
use sigrund_core::{
    config::DaemonConfig,
    executable::{CapabilitySets, ExecutableTrust, TrustModel},
    protocol::RequestedExecutionContext,
    snapshot::SnapshotDigest,
    warrant::{Command, ExecutionContext},
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
    pub post_exec_capabilities: Option<CapabilitySets>,
}
impl From<SealedSnapshot> for Executable {
    fn from(sealed: SealedSnapshot) -> Self {
        Self {
            digest: sealed.digest.clone(),
            sealed: Some(sealed),
            source: None,
            trust: None,
            post_exec_capabilities: None,
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
        self.trust.is_some()
    }
    pub fn verify_direct(&self, context: &ExecutionContext) -> io::Result<()> {
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| invalid("not a direct executable"))?;
        let trust = self
            .trust
            .as_ref()
            .ok_or_else(|| invalid("missing executable evidence"))?;
        let metadata = source.metadata()?;
        let observed_profile = direct_profile(
            source,
            &metadata,
            &context.requested(),
            context.post_exec_capabilities.is_some(),
        )?;
        if observed_profile.as_ref() != Some(&context.expected_capabilities()) {
            return Err(invalid("direct executable is no longer eligible"));
        }
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
    pub fn verify_exec(&self, pid: i32, context: &ExecutionContext) -> io::Result<()> {
        self.verify_direct(context)?;
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
        let groups = field("Groups:")
            .ok_or_else(|| invalid("missing supplementary groups"))?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid("invalid supplementary groups"))?;
        if groups != context.supplementary_gids {
            return Err(invalid("exec changed supplementary groups"));
        }
        let expected = context.expected_capabilities();
        for (name, set) in [
            ("CapInh:", &expected.inheritable),
            ("CapPrm:", &expected.permitted),
            ("CapEff:", &expected.effective),
            ("CapAmb:", &expected.ambient),
            ("CapBnd:", &expected.bounding),
        ] {
            let bits = u64::from_str_radix(
                field(name).ok_or_else(|| invalid("missing capabilities"))?,
                16,
            )
            .map_err(|_| invalid("invalid process capabilities"))?;
            if bits != capability_bits(set)? {
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
    pub allow_file_capabilities: bool,
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
        if !selection.trace_available {
            continue;
        }
        let Some(profile) = direct_profile(
            &source,
            &metadata,
            selection.context,
            selection.allow_file_capabilities,
        )?
        else {
            continue;
        };
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
                post_exec_capabilities: selection.allow_file_capabilities.then_some(profile),
            };
            let mut context: ExecutionContext = selection.context.clone().into();
            context.post_exec_capabilities = executable.post_exec_capabilities.clone();
            executable.verify_direct(&context)?;
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
fn direct_profile(
    source: &File,
    m: &std::fs::Metadata,
    c: &RequestedExecutionContext,
    allow_file_capabilities: bool,
) -> io::Result<Option<CapabilitySets>> {
    let mut mount: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(source.as_raw_fd(), &mut mount) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if m.mode() & 0o6000 != 0 || mount.f_flag & libc::ST_NOEXEC != 0 {
        return Ok(None);
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
    if !execute || !no_xattr(source, c"system.posix_acl_access")? {
        return Ok(None);
    }
    let mut bytes = [0u8; 24];
    let count = unsafe {
        libc::fgetxattr(
            source.as_raw_fd(),
            c"security.capability".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if count < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENODATA | libc::EOPNOTSUPP) => {
                Ok(Some(CapabilitySets::ordinary(&c.capabilities)))
            }
            Some(libc::ERANGE) => Ok(None),
            _ => Err(error),
        };
    }
    if !allow_file_capabilities
        || mount.f_flag & libc::ST_NOSUID != 0
        || !host_capability_mount(source)?
    {
        return Ok(None);
    }
    file_capability_profile(&bytes[..count as usize], &c.capabilities)
}

fn capability_bits(names: &[String]) -> io::Result<u64> {
    names.iter().try_fold(0, |bits, name| {
        crate::authorization::capability_number(name)
            .map(|n| bits | (1u64 << n))
            .ok_or_else(|| invalid("unknown capability"))
    })
}
fn file_capability_profile(
    bytes: &[u8],
    authority: &[String],
) -> io::Result<Option<CapabilitySets>> {
    // v2 host-namespace file capabilities: two little-endian 32-bit words.
    if bytes.len() != 20 {
        return Ok(None);
    }
    let word = |n| u32::from_le_bytes(bytes[n..n + 4].try_into().unwrap());
    let flags = word(0);
    if flags & !1 != 0x0200_0000 {
        return Ok(None);
    }
    let permitted = u64::from(word(4)) | (u64::from(word(12)) << 32);
    let inheritable = u64::from(word(8)) | (u64::from(word(16)) << 32);
    let ceiling = capability_bits(authority)?;
    if (permitted | inheritable) & !ceiling != 0 {
        return Ok(None);
    }
    let mut profile = CapabilitySets::ordinary(authority);
    profile.permitted = authority
        .iter()
        .filter(|name| {
            let bit = 1u64
                << crate::authorization::capability_number(name).expect("validated capability");
            (permitted | inheritable) & bit != 0
        })
        .cloned()
        .collect();
    profile.effective = if flags & 1 != 0 {
        profile.permitted.clone()
    } else {
        vec![]
    };
    profile.ambient.clear();
    Ok(Some(profile))
}
fn host_capability_mount(source: &File) -> io::Result<bool> {
    use std::io::Read;
    let mut map = String::new();
    File::open("/proc/self/uid_map")?
        .take(4097)
        .read_to_string(&mut map)?;
    if map.split_whitespace().collect::<Vec<_>>() != ["0", "0", "4294967295"] {
        return Ok(false);
    }
    // Establish that the retained mount is not idmapped. Older kernels lacking
    // these queries keep the ordinary direct models but decline file caps.
    let mut stat: libc::statx = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::statx(
            source.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            0x4000,
            &mut stat,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP | libc::EPERM) => Ok(false),
            _ => Err(error),
        };
    }
    if stat.stx_mask & 0x4000 == 0 {
        return Ok(false);
    }
    #[repr(C)]
    struct Request {
        size: u32,
        spare: u32,
        id: u64,
        mask: u64,
    }
    let request = Request {
        size: 24,
        spare: 0,
        id: stat.stx_mnt_id,
        mask: 2,
    };
    let mut mount = [0u64; 64];
    // __NR_statmount on the supported x86_64 and aarch64 Linux ABIs.
    const SYS_STATMOUNT: libc::c_long = 457;
    if unsafe {
        libc::syscall(
            SYS_STATMOUNT,
            &request,
            mount.as_mut_ptr(),
            std::mem::size_of_val(&mount),
            0,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP | libc::EPERM) => Ok(false),
            _ => Err(error),
        };
    }
    Ok(mount[1] & 2 != 0 && mount[8] & 0x0010_0000 == 0)
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_caps_are_explicit_authority_with_exact_kernel_sets() {
        let authority = vec!["CAP_CHOWN".into(), "CAP_NET_BIND_SERVICE".into()];
        let mut bytes = [0u8; 20];
        bytes[..4].copy_from_slice(&0x0200_0001u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&(1u32 << 10).to_le_bytes());
        let profile = file_capability_profile(&bytes, &authority)
            .unwrap()
            .unwrap();
        assert_eq!(profile.permitted, ["CAP_NET_BIND_SERVICE"]);
        assert_eq!(profile.effective, profile.permitted);
        assert!(profile.ambient.is_empty());
        assert_eq!(profile.inheritable, authority);
        assert_eq!(profile.bounding, authority);
        assert!(profile.valid(&authority));
        bytes[0] = 0;
        assert!(
            file_capability_profile(&bytes, &authority)
                .unwrap()
                .unwrap()
                .effective
                .is_empty()
        );
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            file_capability_profile(&bytes, &authority)
                .unwrap()
                .unwrap()
                .permitted,
            authority
        );
        assert!(file_capability_profile(&bytes, &[]).unwrap().is_none());
        bytes[3] = 3;
        assert!(
            file_capability_profile(&bytes, &authority)
                .unwrap()
                .is_none()
        );
        assert!(
            file_capability_profile(&bytes[..19], &authority)
                .unwrap()
                .is_none()
        );
    }
}
