//! Phase 5 child-start primitives.
//!
//! The coordinator owns the handoff, while this module contains the bounded
//! syscall-only child transition and its parent-side sync-pipe classifier.
//! Live authorization integration is deliberately a later wiring step; these
//! primitives are usable by both job and hook launchers.
use std::{
    ffi::{CStr, CString},
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    path::Path,
    time::{Duration, Instant},
};

const CLONE_INTO_CGROUP: u64 = 0x200000000;
const CLONE_PIDFD: u64 = 0x00001000;
const SYNC_FRAME: usize = 8;

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SyncOutcome {
    ReadyToExec,
    SetupFailed { step: u32, errno: i32 },
    SpawnFailed,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SyncReadError {
    Io(io::ErrorKind),
    Malformed,
    TimedOut,
}

/// A fixed descriptor plan.  The sync writer is duplicated first and is
/// tracked independently from its eventual descriptor number (FD 4).
pub struct DescriptorPlan {
    pub stdin: OwnedFd,
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
    pub executable: OwnedFd,
    pub sync: OwnedFd,
    pub exec_cloexec: bool,
}

impl DescriptorPlan {
    pub fn duplicate(&self) -> io::Result<TemporaryDescriptors> {
        let sync = duplicate_at_least(self.sync.as_raw_fd(), 5)?;
        let stdin = duplicate_at_least(self.stdin.as_raw_fd(), 5)?;
        let stdout = duplicate_at_least(self.stdout.as_raw_fd(), 5)?;
        let stderr = duplicate_at_least(self.stderr.as_raw_fd(), 5)?;
        let executable = duplicate_at_least(self.executable.as_raw_fd(), 5)?;
        Ok(TemporaryDescriptors {
            sync,
            stdin,
            stdout,
            stderr,
            executable,
            exec_cloexec: self.exec_cloexec,
        })
    }

    /// Install directly from the inherited sources.  This is the child path:
    /// the sync source is duplicated first and remains the error writer until
    /// FD 4 has been installed successfully.
    ///
    /// # Safety
    ///
    /// The caller must invoke this only in the child returned by `clone3`.
    /// The source descriptors must remain open and refer to the intended
    /// request-owned files; this function never returns.
    pub unsafe fn install_in_child(&self) -> ! {
        let mut tracked = self.sync.as_raw_fd();
        let duplicate = |source: RawFd| duplicate_at_least(source, 5);
        if unsafe { libc::syscall(libc::SYS_unshare, libc::CLONE_FILES as libc::c_ulong) } < 0 {
            let errno = io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            let _ = write_setup_frame(tracked, 1, errno);
            unsafe { libc::_exit(127) }
        }
        let sync = match duplicate(tracked) {
            Ok(fd) => fd,
            Err(error) => {
                let _ = write_setup_frame(tracked, 1, error.raw_os_error().unwrap_or(libc::EIO));
                unsafe { libc::_exit(127) }
            }
        };
        tracked = sync.as_raw_fd();
        let stdin = match duplicate(self.stdin.as_raw_fd()) {
            Ok(fd) => fd,
            Err(error) => {
                let _ = write_setup_frame(tracked, 1, error.raw_os_error().unwrap_or(libc::EIO));
                unsafe { libc::_exit(127) }
            }
        };
        let stdout = match duplicate(self.stdout.as_raw_fd()) {
            Ok(fd) => fd,
            Err(error) => {
                let _ = write_setup_frame(tracked, 1, error.raw_os_error().unwrap_or(libc::EIO));
                unsafe { libc::_exit(127) }
            }
        };
        let stderr = match duplicate(self.stderr.as_raw_fd()) {
            Ok(fd) => fd,
            Err(error) => {
                let _ = write_setup_frame(tracked, 1, error.raw_os_error().unwrap_or(libc::EIO));
                unsafe { libc::_exit(127) }
            }
        };
        let executable = match duplicate(self.executable.as_raw_fd()) {
            Ok(fd) => fd,
            Err(error) => {
                let _ = write_setup_frame(tracked, 1, error.raw_os_error().unwrap_or(libc::EIO));
                unsafe { libc::_exit(127) }
            }
        };
        let temporary = TemporaryDescriptors {
            sync,
            stdin,
            stdout,
            stderr,
            executable,
            exec_cloexec: self.exec_cloexec,
        };
        unsafe { install_descriptors(temporary) }
    }
}

pub struct TemporaryDescriptors {
    sync: OwnedFd,
    stdin: OwnedFd,
    stdout: OwnedFd,
    stderr: OwnedFd,
    executable: OwnedFd,
    exec_cloexec: bool,
}

fn duplicate_at_least(fd: RawFd, minimum: i32) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
    if raw < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}

fn write_all_raw(fd: RawFd, mut bytes: &[u8]) -> bool {
    while !bytes.is_empty() {
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n > 0 {
            bytes = &bytes[n as usize..];
        } else if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else {
            return false;
        }
    }
    true
}

/// Emit one native-endian setup frame.  This helper never allocates and is
/// safe to call after clone3 in the child path.
pub fn write_setup_frame(fd: RawFd, step: u32, errno: i32) -> bool {
    let mut frame = [0u8; SYNC_FRAME];
    frame[..4].copy_from_slice(&step.to_ne_bytes());
    frame[4..].copy_from_slice(&errno.to_ne_bytes());
    write_all_raw(fd, &frame)
}

pub fn classify_sync(bytes: &[u8], eof: bool) -> SyncOutcome {
    if !eof {
        return SyncOutcome::SpawnFailed;
    }
    if bytes.is_empty() {
        return SyncOutcome::SpawnFailed;
    }
    if bytes.len() != SYNC_FRAME {
        return SyncOutcome::SpawnFailed;
    }
    let step = u32::from_ne_bytes(bytes[..4].try_into().unwrap());
    let errno = i32::from_ne_bytes(bytes[4..].try_into().unwrap());
    if step == 0 && errno == 0 {
        SyncOutcome::ReadyToExec
    } else if (1..=10).contains(&step) && errno > 0 {
        SyncOutcome::SetupFailed { step, errno }
    } else {
        SyncOutcome::SpawnFailed
    }
}

/// Read until EOF, bounded by the two-second setup deadline and 16 bytes of
/// storage. Any partial, excess, or late frame is a spawn failure.
pub fn read_sync(fd: RawFd, deadline: Instant) -> Result<SyncOutcome, SyncReadError> {
    let mut bytes = [0u8; 16];
    let mut used = 0usize;
    loop {
        if Instant::now() >= deadline {
            return Err(SyncReadError::TimedOut);
        }
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(50))
            .as_millis()
            .max(1) as i32;
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let polled = unsafe { libc::poll(&mut pollfd, 1, timeout) };
        if polled < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SyncReadError::Io(error.kind()));
        }
        if polled == 0 {
            continue;
        }
        let mut chunk = [0u8; 16];
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if n == 0 {
            return Ok(classify_sync(&bytes[..used], true));
        }
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SyncReadError::Io(error.kind()));
        }
        let n = n as usize;
        if used.saturating_add(n) > bytes.len() {
            return Ok(SyncOutcome::SpawnFailed);
        }
        bytes[used..used + n].copy_from_slice(&chunk[..n]);
        used += n;
    }
}

/// Minimal clone3 wrapper.  The child transition itself is kept in a small
/// syscall-only function so it can be audited independently of request
/// parsing and durable state.
pub fn clone3_job(cgroup_fd: RawFd, pidfd: &mut RawFd) -> io::Result<libc::pid_t> {
    let mut args = CloneArgs {
        flags: CLONE_INTO_CGROUP | CLONE_PIDFD,
        pidfd: (pidfd as *mut RawFd) as u64,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cgroup_fd as u64,
        ..CloneArgs::default()
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            (&mut args as *mut CloneArgs).cast::<libc::c_void>(),
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as libc::pid_t)
    }
}

pub fn clone3_job_isolated(
    cgroup_fd: RawFd,
    pidfd: &mut RawFd,
    isolate_mounts: bool,
) -> io::Result<libc::pid_t> {
    let mut args = CloneArgs {
        flags: CLONE_INTO_CGROUP
            | CLONE_PIDFD
            | if isolate_mounts {
                libc::CLONE_NEWNS as u64 | libc::CLONE_NEWCGROUP as u64
            } else {
                0
            },
        pidfd: (pidfd as *mut RawFd) as u64,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cgroup_fd as u64,
        ..CloneArgs::default()
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            (&mut args as *mut CloneArgs).cast::<libc::c_void>(),
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as libc::pid_t)
    }
}

/// Child-side descriptor installation used by the clone3 caller.  The
/// tracked sync descriptor is switched to FD 4 only after that dup3 succeeds.
///
/// # Safety
///
/// This must run only in the child branch of `clone3`; it exits with `_exit`
/// on every path and assumes the descriptor set is still the inherited one.
pub unsafe fn install_descriptors(temporary: TemporaryDescriptors) -> ! {
    let fail = |step: u32| -> ! {
        let errno = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        let _ = write_setup_frame(temporary.sync.as_raw_fd(), step, errno);
        unsafe { libc::_exit(127) }
    };
    if unsafe { libc::syscall(libc::SYS_unshare, libc::CLONE_FILES as libc::c_ulong) } < 0 {
        fail(1);
    }
    if unsafe { libc::dup2(temporary.stdin.as_raw_fd(), 0) } < 0 {
        fail(1);
    }
    if unsafe { libc::dup2(temporary.stdout.as_raw_fd(), 1) } < 0 {
        fail(1);
    }
    if unsafe { libc::dup2(temporary.stderr.as_raw_fd(), 2) } < 0 {
        fail(1);
    }
    let exec_flags = if temporary.exec_cloexec {
        libc::O_CLOEXEC
    } else {
        0
    };
    if unsafe { libc::dup3(temporary.executable.as_raw_fd(), 3, exec_flags) } < 0 {
        fail(1);
    }
    if unsafe { libc::dup3(temporary.sync.as_raw_fd(), 4, libc::O_CLOEXEC) } < 0 {
        fail(1);
    }
    if unsafe { libc::syscall(libc::SYS_close_range, 5u32, u32::MAX, 0u32) } < 0 {
        fail(1);
    }
    unsafe { libc::_exit(127) }
}

pub fn cwd(path: &str) -> io::Result<CString> {
    CString::new(path).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in cwd"))
}

pub fn validate_cwd(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cwd must be absolute",
        ));
    }
    Ok(())
}

pub struct ExecSpec<'a> {
    pub cwd: &'a CStr,
    pub target_uid: libc::uid_t,
    pub target_gid: libc::gid_t,
    pub supplementary_gids: &'a [libc::gid_t],
    pub umask: libc::mode_t,
    pub argv: &'a [*const libc::c_char],
    pub envp: &'a [*const libc::c_char],
}

/// Complete the parent-prepared, syscall-only transition after descriptor
/// installation.  All pointers and arrays must have been built before
/// clone3; this function performs no allocation and exits on every failure.
///
/// # Safety
///
/// Call only in the child branch after FD 3 (the executable) and FD 4 (the
/// sync writer) have been installed. The C strings and pointer arrays must be
/// valid for the duration of this call.
pub unsafe fn setup_and_exec(spec: &ExecSpec<'_>) -> ! {
    let fail = |step: u32| -> ! {
        let errno = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        let _ = write_setup_frame(4, step, errno);
        unsafe { libc::_exit(127) }
    };
    if unsafe { libc::setsid() } < 0 {
        fail(1);
    }
    if unsafe { libc::chdir(spec.cwd.as_ptr()) } < 0 {
        fail(2);
    }
    unsafe { libc::umask(spec.umask) };
    if unsafe {
        libc::setgroups(
            spec.supplementary_gids.len(),
            spec.supplementary_gids.as_ptr(),
        )
    } < 0
    {
        fail(5);
    }
    if unsafe { libc::setresgid(spec.target_gid, spec.target_gid, spec.target_gid) } < 0 {
        fail(5);
    }
    if unsafe { libc::setresuid(spec.target_uid, spec.target_uid, spec.target_uid) } < 0 {
        fail(6);
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        fail(9);
    }
    if !write_setup_frame(4, 0, 0) {
        unsafe { libc::_exit(127) }
    }
    let empty = b"\0";
    let result = unsafe {
        libc::syscall(
            libc::SYS_execveat,
            3,
            empty.as_ptr(),
            spec.argv.as_ptr(),
            spec.envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    if result < 0 {
        fail(10);
    }
    unsafe { libc::_exit(127) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn sync_classifier_requires_exact_eof_framing() {
        assert_eq!(classify_sync(&[], true), SyncOutcome::SpawnFailed);
        assert_eq!(classify_sync(&[0; 7], true), SyncOutcome::SpawnFailed);
        assert_eq!(classify_sync(&[0; 8], false), SyncOutcome::SpawnFailed);
        let mut ready = [0u8; 8];
        assert_eq!(classify_sync(&ready, true), SyncOutcome::ReadyToExec);
        ready[..4].copy_from_slice(&1u32.to_ne_bytes());
        ready[4..].copy_from_slice(&libc::EPERM.to_ne_bytes());
        assert_eq!(
            classify_sync(&ready, true),
            SyncOutcome::SetupFailed {
                step: 1,
                errno: libc::EPERM
            }
        );
    }

    #[test]
    fn setup_frame_round_trips_native_fields() {
        let mut pair = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pair.as_mut_ptr()) }, 0);
        assert!(write_setup_frame(pair[1], 10, libc::EACCES));
        let mut frame = [0u8; 8];
        assert_eq!(
            unsafe { libc::read(pair[0], frame.as_mut_ptr().cast(), 8) },
            8
        );
        assert_eq!(u32::from_ne_bytes(frame[..4].try_into().unwrap()), 10);
        assert_eq!(
            i32::from_ne_bytes(frame[4..].try_into().unwrap()),
            libc::EACCES
        );
        unsafe {
            libc::close(pair[0]);
            libc::close(pair[1]);
        }
    }

    #[test]
    fn descriptor_duplication_starts_at_safe_range() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let plan = DescriptorPlan {
            stdin: file.try_clone().unwrap().into(),
            stdout: file.try_clone().unwrap().into(),
            stderr: file.try_clone().unwrap().into(),
            executable: file.try_clone().unwrap().into(),
            sync: file.into(),
            exec_cloexec: true,
        };
        let temporary = plan.duplicate().unwrap();
        for fd in [
            temporary.sync.as_raw_fd(),
            temporary.stdin.as_raw_fd(),
            temporary.stdout.as_raw_fd(),
            temporary.stderr.as_raw_fd(),
            temporary.executable.as_raw_fd(),
        ] {
            assert!(fd >= 5);
        }
    }
}
