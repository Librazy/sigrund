//! Phase 5 child-start primitives.
//!
//! The coordinator owns the handoff, while this module contains the bounded
//! syscall-only child transition and its parent-side sync-pipe classifier.
//! Live authorization integration is deliberately a later wiring step; these
//! primitives are usable by both job and hook launchers.
use crate::startup::CgroupLayout;
use std::{
    ffi::CString,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    time::{Duration, Instant},
};

use crate::sequencer::CommittedJob;

pub(crate) struct JobSupervisor {
    layout: Option<CgroupLayout>,
    startup_error: Option<String>,
}

pub(crate) enum SpawnOutcome {
    Failed { job: CommittedJob, message: String },
}

impl JobSupervisor {
    pub(crate) fn new(layout: Option<CgroupLayout>, startup_error: Option<String>) -> Self {
        Self {
            layout,
            startup_error,
        }
    }

    pub(crate) fn spawn(&self, job: CommittedJob) -> SpawnOutcome {
        let Some(layout) = &self.layout else {
            return SpawnOutcome::Failed {
                job,
                message: self
                    .startup_error
                    .clone()
                    .unwrap_or_else(|| "delegated cgroup hierarchy unavailable".into()),
            };
        };
        let _ = (
            job.gid,
            job.authorized.signer_ids.len(),
            job.authorized.envp.len(),
        );
        let request = job.lease.request();
        match layout.create_job(
            &job.exec_id,
            request.policy.job_memory_max_bytes,
            request.policy.job_memory_swap_max_bytes,
            request.policy.job_pids_max,
        ) {
            Ok(cgroup) => {
                // The clone3 handoff is supplied by Phase 5B's syscall
                // primitives. Keep the cgroup owner attached to this result
                // until the coordinator has a real child outcome.
                drop(cgroup);
                SpawnOutcome::Failed {
                    job,
                    message: "child setup failed before clone3 handoff".into(),
                }
            }
            Err(error) => SpawnOutcome::Failed {
                job,
                message: format!("job cgroup setup failed: {error}"),
            },
        }
    }
}

/// Exact parent-owned storage used by the C-only clone/exec transition.
/// Pointer tables are built immediately before dispatch and remain live until
/// clone returns; the child receives independent copies (no CLONE_VM/FILES).
pub struct PreparedChild {
    argv: Vec<CString>,
    envp: Vec<CString>,
    cwd: CString,
    groups: Vec<u32>,
    uid: u32,
    gid: u32,
    mask: u32,
    capabilities: u64,
    last_cap: u32,
    mountinfo: Vec<u8>,
    group_check: Vec<u32>,
}

#[repr(C)]
struct ChildSpec {
    input: i32,
    output: i32,
    error: i32,
    executable: i32,
    sync: i32,
    uid: u32,
    gid: u32,
    mask: u32,
    last_cap: u32,
    capabilities: u64,
    groups: *const u32,
    groups_len: usize,
    cwd: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
    mountinfo: *mut u8,
    mountinfo_capacity: usize,
    group_check: *mut u32,
    isolated: i32,
}
unsafe extern "C" {
    fn sigrund_spawn(spec: *const ChildSpec, cgroup: i32, pidfd: *mut i32) -> i32;
}

#[must_use = "register and reap every returned child; dropping pidfd does not stop it"]
pub struct ChildProcess {
    pub pid: libc::pid_t,
    pub pidfd: OwnedFd,
    pub sync: OwnedFd,
    pub deadline: Instant,
}

impl PreparedChild {
    pub fn new(warrant: &sigrund_core::warrant::Warrant, envp: Vec<CString>) -> io::Result<Self> {
        let last_cap: u32 = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
            .trim()
            .parse()
            .map_err(|_| io::Error::other("invalid cap_last_cap"))?;
        if last_cap >= 64
            || warrant.command.tty_mode != "stdio"
            || warrant.command.allow_interpreted_script
        {
            return Err(io::Error::other("unsupported child execution profile"));
        }
        let mut capabilities = 0u64;
        for name in &warrant.execution_context.capabilities {
            let cap = crate::authorization::capability_number(name)
                .filter(|cap| *cap <= last_cap)
                .ok_or_else(|| io::Error::other("unsupported capability"))?;
            capabilities |= 1u64 << cap;
        }
        Ok(Self {
            argv: warrant
                .command
                .argv
                .iter()
                .map(|arg| CString::new(arg.as_str()).map_err(|_| io::Error::other("NUL in argv")))
                .collect::<io::Result<_>>()?,
            envp,
            cwd: CString::new(warrant.command.cwd.as_str())
                .map_err(|_| io::Error::other("NUL in cwd"))?,
            groups: warrant.execution_context.supplementary_gids.clone(),
            uid: warrant.execution_context.target_uid,
            gid: warrant.execution_context.target_gid,
            mask: warrant.execution_context.umask,
            capabilities,
            last_cap,
            mountinfo: vec![0; 1_048_576],
            group_check: vec![0; warrant.execution_context.supplementary_gids.len()],
        })
    }

    /// Both returned descriptors have a single parent owner. No Rust code
    /// runs in the child, including when clone succeeds but setup fails early.
    /// Call only on a reserved executor after cancellation/expiry/liveness
    /// checks and after establishing the coordinator's registration barrier.
    /// Startup probes instead run before admission, with no concurrent reaper.
    pub fn spawn(&mut self, cgroup_fd: RawFd, fds: [RawFd; 4]) -> io::Result<ChildProcess> {
        self.spawn_inner(cgroup_fd, fds)
    }

    fn spawn_inner(&mut self, cgroup_fd: RawFd, fds: [RawFd; 4]) -> io::Result<ChildProcess> {
        let (sync, writer) = sync_pipe()?;
        let mut argv: Vec<_> = self.argv.iter().map(|v| v.as_ptr()).collect();
        argv.push(std::ptr::null());
        let mut envp: Vec<_> = self.envp.iter().map(|v| v.as_ptr()).collect();
        envp.push(std::ptr::null());
        let spec = ChildSpec {
            input: fds[0],
            output: fds[1],
            error: fds[2],
            executable: fds[3],
            sync: writer.as_raw_fd(),
            uid: self.uid,
            gid: self.gid,
            mask: self.mask,
            last_cap: self.last_cap,
            capabilities: self.capabilities,
            groups: self.groups.as_ptr(),
            groups_len: self.groups.len(),
            cwd: self.cwd.as_ptr(),
            argv: argv.as_ptr(),
            envp: envp.as_ptr(),
            mountinfo: self.mountinfo.as_mut_ptr(),
            mountinfo_capacity: self.mountinfo.len(),
            group_check: self.group_check.as_mut_ptr(),
            isolated: i32::from(self.capabilities & (1 << 21) == 0),
        };
        let mut pidfd = -1;
        let deadline = Instant::now() + Duration::from_secs(2);
        let pid = unsafe { sigrund_spawn(&spec, cgroup_fd, &mut pidfd) };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        // CLONE_PIDFD guarantees a descriptor on success. A violation is an
        // internal/kernel ABI failure; do not pretend that no child exists.
        assert!(pid > 0 && pidfd >= 0, "clone3 violated pidfd contract");
        drop(writer);
        Ok(ChildProcess {
            pid,
            pidfd: unsafe { OwnedFd::from_raw_fd(pidfd) },
            sync,
            deadline,
        })
    }
}

pub fn sync_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    if unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((read, write))
}

#[derive(Debug, Eq, PartialEq)]
pub enum SyncOutcome {
    ReadyToExec,
    SetupFailed { step: u32, errno: i32 },
    ExecFailed { errno: i32 },
    SpawnFailed,
}

/// The reader is finite even if an erroneous child never closes its pipe.
/// Classify only on EOF and reject excess/partial bytes immediately.
#[derive(Default)]
pub struct Handshake {
    bytes: [u8; 16],
    used: usize,
}
impl Handshake {
    pub fn read(
        &mut self,
        fd: RawFd,
        now: Instant,
        deadline: Instant,
    ) -> io::Result<Option<SyncOutcome>> {
        if now >= deadline {
            return Ok(Some(SyncOutcome::SpawnFailed));
        }
        let mut buf = [0u8; 17];
        for _ in 0..4 {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n == 0 {
                return Ok(Some(classify_sync(&self.bytes[..self.used], true)));
            }
            if n < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let n = n as usize;
            if self.used + n > 16 {
                return Ok(Some(SyncOutcome::SpawnFailed));
            }
            self.bytes[self.used..self.used + n].copy_from_slice(&buf[..n]);
            self.used += n;
        }
        Ok(None)
    }
}

pub fn classify_sync(bytes: &[u8], eof: bool) -> SyncOutcome {
    if !eof || !matches!(bytes.len(), 8 | 16) {
        return SyncOutcome::SpawnFailed;
    }
    let step = u32::from_ne_bytes(bytes[..4].try_into().unwrap());
    let errno = i32::from_ne_bytes(bytes[4..8].try_into().unwrap());
    if bytes.len() == 8 {
        if step == 0 && errno == 0 {
            return SyncOutcome::ReadyToExec;
        }
        if (1..=10).contains(&step) && errno > 0 {
            return SyncOutcome::SetupFailed { step, errno };
        }
    } else if step == 0 && errno == 0 && u32::from_ne_bytes(bytes[8..12].try_into().unwrap()) == 11
    {
        let errno = i32::from_ne_bytes(bytes[12..].try_into().unwrap());
        if errno > 0 {
            return SyncOutcome::ExecFailed { errno };
        }
    }
    SyncOutcome::SpawnFailed
}

/// Exercise actual clone3 + cgroup placement, pidfds, unshare, close_range,
/// recursive mount_setattr and mountinfo verification before listeners exist.
/// The child always exits inside its new namespaces; parent mounts are never
/// modified and no weaker-flags fallback exists.
pub fn startup_probe(layout: &CgroupLayout) -> io::Result<()> {
    let id = sigrund_core::crypto::new_uuidv7().to_string();
    let cgroup = layout.create_job(&id, 67_108_864, 0, 32)?;
    // Exercise execveat and the complete credential path, not just namespace
    // creation. Pin a trusted, bounded ELF and execute only its sealed bytes.
    let result = (|| {
        use std::io::Read;
        let file = crate::startup::open_pinned(std::path::Path::new("/usr/bin/true"))?;
        crate::startup::check_root_metadata(&file, false, None)?;
        let mut bytes = Vec::new();
        file.take(67_108_865).read_to_end(&mut bytes)?;
        if bytes.len() > 67_108_864 || !bytes.starts_with(b"\x7fELF") {
            return Err(io::Error::other(
                "startup probe requires a bounded trusted ELF /usr/bin/true",
            ));
        }
        let executable = crate::memfd::create_sealed("startup-probe", &bytes, true, 0o111)?;
        let null = std::fs::File::open("/dev/null")?;
        let last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|cap| *cap < 64)
            .ok_or_else(|| io::Error::other("invalid cap_last_cap"))?;
        let mut command = PreparedChild {
            argv: vec![CString::new("/usr/bin/true").unwrap()],
            envp: vec![],
            cwd: CString::new("/").unwrap(),
            groups: vec![],
            uid: 0,
            gid: 0,
            mask: 0o077,
            capabilities: 0,
            last_cap,
            mountinfo: vec![0; 1_048_576],
            group_check: vec![],
        };
        let child = command.spawn(
            cgroup.fd(),
            [
                null.as_raw_fd(),
                null.as_raw_fd(),
                null.as_raw_fd(),
                executable.as_raw_fd(),
            ],
        )?;
        let mut handshake = Handshake::default();
        let outcome = loop {
            if let Some(outcome) =
                handshake.read(child.sync.as_raw_fd(), Instant::now(), child.deadline)?
            {
                break outcome;
            }
            let mut p = libc::pollfd {
                fd: child.sync.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut p, 1, 10) } < 0
                && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
            {
                return Err(io::Error::last_os_error());
            }
        };
        if outcome != SyncOutcome::ReadyToExec {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    child.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    0usize,
                    0,
                )
            };
        }
        // Only this known probe is reaped; startup has no other children.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            if unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    child.pidfd.as_raw_fd() as u32,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            if unsafe { info.si_pid() } != 0 {
                break;
            }
            if Instant::now() >= child.deadline + Duration::from_secs(2) {
                return Err(io::Error::other("startup clone/mount probe did not exit"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if outcome != SyncOutcome::ReadyToExec
            || info.si_code != libc::CLD_EXITED
            || unsafe { info.si_status() } != 0
        {
            return Err(io::Error::other(format!(
                "startup clone/mount probe failed: {outcome:?}"
            )));
        }
        Ok(())
    })();
    match cgroup.cleanup() {
        Ok(()) => result,
        Err((_owner, error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_accepts_only_documented_evidence() {
        for n in 0..=24 {
            assert_eq!(
                classify_sync(&vec![0; n], true),
                if n == 8 {
                    SyncOutcome::ReadyToExec
                } else {
                    SyncOutcome::SpawnFailed
                }
            );
            assert_eq!(classify_sync(&vec![0; n], false), SyncOutcome::SpawnFailed);
        }
        for step in 1u32..=11 {
            let mut b = step.to_ne_bytes().to_vec();
            b.extend(libc::EPERM.to_ne_bytes());
            assert_eq!(
                classify_sync(&b, true),
                if step <= 10 {
                    SyncOutcome::SetupFailed {
                        step,
                        errno: libc::EPERM,
                    }
                } else {
                    SyncOutcome::SpawnFailed
                }
            );
            let mut two = vec![0; 8];
            two.extend(&b);
            assert_eq!(
                classify_sync(&two, true),
                if step == 11 {
                    SyncOutcome::ExecFailed { errno: libc::EPERM }
                } else {
                    SyncOutcome::SpawnFailed
                }
            );
        }
    }
    #[test]
    fn nonblocking_handshake_keeps_original_deadline() {
        let (r, w) = sync_pipe().unwrap();
        let mut h = Handshake::default();
        let now = Instant::now();
        assert_eq!(
            h.read(r.as_raw_fd(), now, now + Duration::from_secs(2))
                .unwrap(),
            None
        );
        assert_eq!(
            unsafe { libc::write(w.as_raw_fd(), [0u8; 8].as_ptr().cast(), 8) },
            8
        );
        assert_eq!(
            h.read(r.as_raw_fd(), now, now + Duration::from_secs(2))
                .unwrap(),
            None
        );
        drop(w);
        assert_eq!(
            h.read(r.as_raw_fd(), now, now + Duration::from_secs(2))
                .unwrap(),
            Some(SyncOutcome::ReadyToExec)
        );
        assert_eq!(
            h.read(r.as_raw_fd(), now, now).unwrap(),
            Some(SyncOutcome::SpawnFailed)
        );
    }
}
