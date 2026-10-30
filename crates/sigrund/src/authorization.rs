//! Final local authorization of retained snapshots. No source path is reopened.
use crate::{
    preparation::{self, Context, Document},
    snapshot::SealedSnapshot,
    workers::ValidatedRequest,
};
use sha2::{Digest, Sha256};
use sigrund_core::{paths::select_root, warrant::CanonicalWarrant};
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
};
use subtle::ConstantTimeEq;

#[derive(Clone, Debug)]
pub(crate) struct Denial {
    pub status: &'static str,
    pub message: &'static str,
}
impl Denial {
    pub fn new(status: &'static str, message: &'static str) -> Self {
        Self { status, message }
    }
}
type Result<T> = std::result::Result<T, Denial>;
fn policy() -> Denial {
    Denial::new(
        "POLICY_VIOLATION",
        "request does not satisfy captured authorization policy",
    )
}

/// Includes immutable command bytes and the deterministic environment for the
/// later child setup. Success is not a durable grant or readiness decision.
pub(crate) struct Authorized {
    pub warrant: CanonicalWarrant,
    pub signer_id: String,
    pub envp: Vec<CString>,
}

pub(crate) fn verify(
    request: &ValidatedRequest,
    context: &Context,
    gid: u32,
) -> Result<Authorized> {
    request
        .check()
        .map_err(|_| Denial::new("REQUEST_TIMEOUT", "authorization cancelled"))?;
    request
        .policy
        .mvp
        .as_ref()
        .ok_or_else(policy)?
        .validate_for_peer(&request.hello, request.requester_uid)
        .map_err(|_| policy())?;
    let prepared = request.prepared.as_ref().ok_or_else(policy)?;
    let Document::Signed { warrant, signer_id } = &prepared.document else {
        return Err(policy());
    };
    let w = warrant.warrant();
    w.validate().map_err(|_| policy())?;
    let signer = context
        .signers
        .signers
        .iter()
        .find(|s| s.signer_id == *signer_id)
        .ok_or_else(policy)?;
    if !preparation::static_policy(
        signer,
        w,
        request.requester_uid,
        gid,
        &context.host_id,
        &request.policy,
    ) || w.command.tty_mode != request.hello.tty_mode
    {
        return Err(policy());
    }
    // The profile forbids same-UID elevation, scripts, PTY and unsigned caller
    // environment inheritance, even if a broader signer policy allows them.
    let selected = select_root(
        std::path::Path::new(&w.command.executable_path),
        &signer.allowed_executable_dirs,
    )
    .map_err(|_| policy())?;
    let pinned = context
        .roots
        .iter()
        .find(|r| r.path == selected.root)
        .ok_or_else(policy)?;
    let identity = pinned.directory.metadata().map_err(|_| policy())?;
    if selected.root != prepared.root_path
        || identity.dev() != prepared.root_identity.device
        || identity.ino() != prepared.root_identity.inode
    {
        return Err(policy());
    }
    let snapshots = request.snapshots.as_ref().ok_or_else(policy)?;
    verify_snapshot(
        &snapshots.executable,
        &w.command.executable_sha256,
        request.policy.max_executable_bytes,
        true,
    )
    .map_err(|_| {
        Denial::new(
            "EXECUTABLE_MUTATED_OR_TOO_LARGE",
            "executable snapshot verification failed",
        )
    })?;
    match (
        w.command.stdin_policy.as_str(),
        &w.command.stdin_sha256,
        &snapshots.stdin,
        &prepared.null_stdin,
    ) {
        ("sha256", Some(digest), Some(snapshot), None) => {
            verify_snapshot(snapshot, digest, request.policy.max_stdin_bytes, false).map_err(
                |_| Denial::new("STDIN_HASH_MISMATCH", "stdin snapshot verification failed"),
            )?;
        }
        ("null", None, None, Some(fd)) => {
            let file = File::from(fd.try_clone().map_err(|_| policy())?);
            let m = file.metadata().map_err(|_| policy())?;
            if m.mode() & libc::S_IFMT != libc::S_IFCHR || m.rdev() != libc::makedev(1, 3) {
                return Err(policy());
            }
        }
        _ => {
            return Err(Denial::new(
                "INVALID_TTY_STDIN_COMBINATION",
                "stdin does not match retained input",
            ));
        }
    }
    // Existing schema validation establishes sorted, unique Linux names. Also
    // verify that every requested capability exists on this running kernel.
    let last: u32 = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|_| policy())?
        .trim()
        .parse()
        .map_err(|_| policy())?;
    for name in &w.execution_context.capabilities {
        if capability_number(name).is_none_or(|n| n > last) {
            return Err(policy());
        }
    }
    let mut environment = w.execution_context.env_exact.clone();
    for (name, value) in &request.hello.caller_env {
        if environment.insert(name.clone(), value.clone()).is_some() {
            return Err(policy());
        }
    }
    let envp = environment
        .into_iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")).map_err(|_| policy()))
        .collect::<Result<Vec<_>>>()?;
    request
        .check()
        .map_err(|_| Denial::new("REQUEST_TIMEOUT", "authorization cancelled"))?;
    Ok(Authorized {
        warrant: warrant.clone(),
        signer_id: signer_id.clone(),
        envp,
    })
}

fn verify_snapshot(
    snapshot: &SealedSnapshot,
    expected: &str,
    maximum: u64,
    executable: bool,
) -> io::Result<()> {
    let file = File::from(snapshot.as_fd().try_clone_to_owned()?);
    let m = file.metadata()?;
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if !m.is_file()
        || m.uid() != 0
        || m.gid() != 0
        || m.mode() & 0o7777 != if executable { 0o111 } else { 0o400 }
        || seals < 0
        || seals & 0x1f != 0x1f
        || m.len() != snapshot.digest.bytes
        || m.len() > maximum
        || executable && m.len() < 4
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut hasher = Sha256::new();
    let mut offset = 0;
    let mut chunk = [0u8; 32768];
    while offset < m.len() {
        let length = chunk.len().min((m.len() - offset) as usize);
        let n = match file.read_at(&mut chunk[..length], offset) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if executable && offset == 0 && (n < 4 || &chunk[..4] != b"\x7fELF") {
            return Err(io::ErrorKind::InvalidData.into());
        }
        hasher.update(&chunk[..n]);
        offset += n as u64;
    }
    let digest = hasher.finalize();
    let actual: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    if !bool::from(actual.as_bytes().ct_eq(expected.as_bytes())) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

fn capability_number(name: &str) -> Option<u32> {
    const NAMES: &[&str] = &[
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
    ];
    NAMES.iter().position(|n| *n == name).map(|n| n as u32)
}
