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
        fd::{AsFd, AsRawFd, BorrowedFd},
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
    pub signer_ids: Vec<String>,
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
    let Document::Signed {
        warrant,
        signer_ids,
    } = &prepared.document
    else {
        return Err(policy());
    };
    let w = warrant.warrant();
    w.validate().map_err(|_| policy())?;
    if w.command.tty_mode != request.hello.tty_mode {
        return Err(policy());
    }
    // The profile forbids same-UID elevation, scripts, PTY and unsigned caller
    // environment inheritance, even if a broader signer policy allows them.
    // Retain only independently eligible signers. Snapshot checks below are
    // common to the payload; no ceiling may be satisfied by combining keys.
    let signer_ids: Vec<_> = signer_ids
        .iter()
        .filter(|id| {
            let Some(signer) = context.signers.signers.iter().find(|s| s.signer_id == **id) else {
                return false;
            };
            if !preparation::static_policy(
                signer,
                w,
                request.requester_uid,
                gid,
                &context.host_id,
                &request.policy,
            ) {
                return false;
            }
            let Ok(selected) = select_root(
                std::path::Path::new(&w.command.executable_path),
                &signer.allowed_executable_dirs,
            ) else {
                return false;
            };
            let Some(pinned) = context.roots.iter().find(|r| r.path == selected.root) else {
                return false;
            };
            let Ok(identity) = pinned.directory.metadata() else {
                return false;
            };
            selected.root == prepared.root_path
                && identity.dev() == prepared.root_identity.device
                && identity.ino() == prepared.root_identity.inode
        })
        .cloned()
        .collect();
    if signer_ids.is_empty() {
        return Err(policy());
    }
    let snapshots = request.snapshots.as_ref().ok_or_else(policy)?;
    verify_snapshot(
        &snapshots.executable,
        &w.command.executable_sha256,
        request.policy.max_executable_bytes,
        true,
        || request.check(),
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
            verify_snapshot(
                snapshot,
                digest,
                request.policy.max_stdin_bytes,
                false,
                || request.check(),
            )
            .map_err(|_| {
                Denial::new("STDIN_HASH_MISMATCH", "stdin snapshot verification failed")
            })?;
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
        signer_ids,
        envp,
    })
}

fn verify_snapshot(
    snapshot: &SealedSnapshot,
    expected: &str,
    maximum: u64,
    executable: bool,
    check: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    verify_fd(
        snapshot.as_fd(),
        snapshot.digest.bytes,
        expected,
        maximum,
        executable,
        check,
    )
}

fn verify_fd(
    fd: BorrowedFd<'_>,
    bytes: u64,
    expected: &str,
    maximum: u64,
    executable: bool,
    check: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    check()?;
    let file = File::from(fd.try_clone_to_owned()?);
    let m = file.metadata()?;
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if !m.is_file()
        || m.uid() != 0
        || m.gid() != 0
        || m.mode() & 0o7777 != if executable { 0o111 } else { 0o400 }
        || seals < 0
        || seals & 0x1f != 0x1f
        || m.len() != bytes
        || m.len() > maximum
        || executable && m.len() < 4
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if executable {
        let mut magic = [0; 4];
        file.read_exact_at(&mut magic, 0)?;
        if &magic != b"\x7fELF" {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    let mut hasher = Sha256::new();
    let mut offset = 0;
    let mut chunk = [0u8; 32768];
    while offset < m.len() {
        check()?;
        let length = chunk.len().min((m.len() - offset) as usize);
        let n = match file.read_at(&mut chunk[..length], offset) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        check()?;
        hasher.update(&chunk[..n]);
        offset += n as u64;
    }
    check()?;
    let digest = hasher.finalize();
    let actual: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    if !bool::from(actual.as_bytes().ct_eq(expected.as_bytes())) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

pub(crate) fn capability_number(name: &str) -> Option<u32> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Seek, SeekFrom, Write},
        process::Command,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn final_snapshot_gate() {
        let output = Command::new("unshare")
            .args(["--user", "--map-auto", "--map-root-user"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "authorization::tests::snapshot_namespace_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("SIGRUND_SNAPSHOT_GATE", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    #[ignore = "invoked by the namespace gate"]
    fn snapshot_namespace_fixture() {
        assert_eq!(std::env::var("SIGRUND_SNAPSHOT_GATE").unwrap(), "1");
        let bytes = b"\x7fELFsealed test command";
        let digest = sigrund_core::crypto::sha256_hex(bytes);
        let fd = crate::memfd::create_sealed("gate", bytes, true, 0o111).unwrap();
        let verify = |expected: &str, maximum, executable| {
            verify_fd(
                fd.as_fd(),
                bytes.len() as u64,
                expected,
                maximum,
                executable,
                || Ok(()),
            )
        };
        assert!(verify(&digest, bytes.len() as u64, true).is_ok());
        assert!(verify(&"0".repeat(64), bytes.len() as u64, true).is_err());
        assert!(verify(&digest, bytes.len() as u64 - 1, true).is_err());
        assert!(
            verify_fd(
                fd.as_fd(),
                bytes.len() as u64 + 1,
                &digest,
                100,
                true,
                || Ok(())
            )
            .is_err()
        );
        assert_eq!(unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_CUR) }, 0);
        // Seal bits alone are insufficient: enforce execute-only root ownership.
        assert_eq!(unsafe { libc::fchmod(fd.as_raw_fd(), 0o555) }, 0);
        assert!(verify(&digest, 100, true).is_err());
        assert_eq!(unsafe { libc::fchmod(fd.as_raw_fd(), 0o111) }, 0);
        // A rootless user namespace may map only its namespace root. In that
        // environment the kernel correctly refuses an ownership mutation;
        // the production predicate is still covered by the successful root
        // path and the explicit mode checks above.
        let chown = unsafe { libc::fchown(fd.as_raw_fd(), 1, 1) };
        if chown != 0 {
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            return;
        }
        assert!(verify(&digest, 100, true).is_err());
        let mut unsealed = crate::memfd::create("unsealed", true).unwrap();
        unsealed.write_all(bytes).unwrap();
        assert_eq!(unsafe { libc::fchmod(unsealed.as_raw_fd(), 0o111) }, 0);
        assert!(
            verify_fd(
                unsealed.as_fd(),
                bytes.len() as u64,
                &digest,
                100,
                true,
                || Ok(())
            )
            .is_err()
        );
        let bad = crate::memfd::create_sealed("not-elf", b"#!script", true, 0o111).unwrap();
        assert!(
            verify_fd(
                bad.as_fd(),
                8,
                &sigrund_core::crypto::sha256_hex(b"#!script"),
                100,
                true,
                || Ok(())
            )
            .is_err()
        );
        let empty = crate::memfd::create_sealed("stdin", b"", false, 0o400).unwrap();
        verify_fd(
            empty.as_fd(),
            0,
            &sigrund_core::crypto::sha256_hex(b""),
            100,
            false,
            || Ok(()),
        )
        .unwrap();
        let calls = AtomicUsize::new(0);
        let fd = crate::memfd::create_sealed("cancel", &vec![0; 65536], false, 0o400).unwrap();
        assert_eq!(
            verify_fd(fd.as_fd(), 65536, &"0".repeat(64), 65536, false, || {
                if calls.fetch_add(1, Ordering::Relaxed) >= 2 {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
        // Ordinary files cannot stand in for sealed memfds.
        let mut ordinary = tempfile::tempfile().unwrap();
        ordinary.write_all(bytes).unwrap();
        ordinary.seek(SeekFrom::Start(0)).unwrap();
        assert!(
            verify_fd(
                ordinary.as_fd(),
                bytes.len() as u64,
                &digest,
                100,
                true,
                || Ok(())
            )
            .is_err()
        );
    }
}
