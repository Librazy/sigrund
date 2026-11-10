//! Child setup, execution and readiness primitives.
//!
//! The coordinator owns the handoff, while this module contains the bounded
//! syscall-only child transition and its parent-side sync-pipe classifier.
//! The runtime coordinator dispatches these primitives only after durable
//! authorization and registration-barrier reservation.
use crate::startup::CgroupLayout;
use std::{
    ffi::CString,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    time::{Duration, Instant},
};

static TRACE_AVAILABLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub fn trace_available() -> bool {
    TRACE_AVAILABLE.load(std::sync::atomic::Ordering::Acquire)
}

/// Called by the coordinator (which consequently owns the ptrace relation).
pub fn attach_checkpoint(pid: i32, gate: &OwnedFd) -> io::Result<()> {
    if unsafe {
        libc::ptrace(
            libc::PTRACE_SEIZE,
            pid,
            0usize,
            (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as usize,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::write(gate.as_raw_fd(), b"x".as_ptr().cast(), 1) } != 1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub fn release_checkpoint(pid: i32) -> io::Result<()> {
    if unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0usize, 0usize) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Exact parent-owned storage used by the C-only clone/exec transition.
/// Pointer tables are built immediately before dispatch and remain live until
/// clone returns; the child receives independent copies (no CLONE_VM/FILES).
pub struct PreparedChild {
    argv: Vec<CString>,
    envp: Vec<CString>,
    cwd: CString,
    direct_path: Option<CString>,
    groups: Vec<u32>,
    uid: u32,
    gid: u32,
    mask: u32,
    capabilities: u64,
    last_cap: u32,
    mountinfo: Vec<u8>,
    group_check: Vec<u32>,
}

include!(concat!(env!("OUT_DIR"), "/launcher_abi.rs"));
unsafe extern "C" {
    fn sigrund_spawn(spec: *const ChildSpec, cgroup: i32, pidfd: *mut i32) -> i32;
    fn sigrund_spawn_namespace_launcher(
        spec: *const ChildSpec,
        namespace: *const NamespaceSpec,
        payload: i32,
        cgroup: i32,
        pidfd: *mut i32,
    ) -> i32;
    fn sigrund_run_namespace_launcher(spec: *const ChildSpec, namespace: *const NamespaceSpec);
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespacePayload {
    version: u32,
    uid: u32,
    gid: u32,
    mask: u32,
    last_cap: u32,
    enter_mask: u32,
    cwd: String,
    argv: Vec<String>,
    envp: Vec<String>,
    constraints: sigrund_core::namespace::Constraints,
    producer_guard: bool,
}

/// Internal fresh-exec entry, reached before loading daemon configuration or
/// keys. Descriptor 27 carries only a sealed, bounded configuration for one job.
pub fn namespace_launcher_main() -> io::Result<()> {
    use std::{fs::File, io::Read};
    crate::access::domain()?;
    if unsafe { libc::geteuid() } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let file = unsafe { File::from_raw_fd(27) };
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    let actual = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if actual < 0 || actual & seals != seals || file.metadata()?.len() > 1_048_576 {
        return Err(io::Error::other("invalid namespace launcher payload"));
    }
    let mut bytes = Vec::new();
    file.take(1_048_577).read_to_end(&mut bytes)?;
    // Drop the payload FD before entering the destination; only the fixed
    // allowlist survives. Reinstall CLOEXEC removed by the bootstrap exec.
    if bytes.len() > 1_048_576 {
        return Err(io::Error::other("oversize namespace launcher payload"));
    }
    let payload: NamespacePayload = serde_json::from_slice(&bytes)?;
    if payload.version != SG_PAYLOAD_VERSION
        || payload.uid == 0
        || payload.uid == u32::MAX
        || payload.gid == u32::MAX
        || payload.mask > 0o777
        || payload.last_cap >= 64
        || payload.enter_mask > 255
        || payload.argv.is_empty()
        || !payload.cwd.starts_with('/')
    {
        return Err(io::Error::other("unsupported namespace launcher payload"));
    }
    for fd in 10..=26 {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    use sigrund_core::namespace::Contract;
    payload.constraints.validate().map_err(io::Error::other)?;
    if !payload.constraints.executes() {
        return Err(io::Error::other("nonexecuting launcher profile"));
    }
    let production = i32::from(payload.constraints.is_production());
    let strings = |values: Vec<String>| -> io::Result<Vec<CString>> {
        values
            .into_iter()
            .map(|value| CString::new(value).map_err(io::Error::other))
            .collect()
    };
    let arguments = strings(payload.argv)?;
    let environment = strings(payload.envp)?;
    let mut argv: Vec<_> = arguments.iter().map(|v| v.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<_> = environment.iter().map(|v| v.as_ptr()).collect();
    envp.push(std::ptr::null());
    let cwd = CString::new(payload.cwd).map_err(io::Error::other)?;
    let spec = ChildSpec {
        input: 10,
        output: 11,
        error: 12,
        executable: 13,
        sync: 14,
        uid: payload.uid,
        gid: payload.gid,
        mask: payload.mask,
        last_cap: payload.last_cap,
        capabilities: 0,
        groups: std::ptr::null(),
        groups_len: 0,
        cwd: cwd.as_ptr(),
        direct_path: std::ptr::null(),
        argv: argv.as_ptr(),
        envp: envp.as_ptr(),
        mountinfo: std::ptr::null_mut(),
        mountinfo_capacity: 0,
        group_check: std::ptr::null_mut(),
        isolated: 1,
        gate_read: 15,
        gate_write: -1,
        checkpoint: 1,
        namespace_mode: 1,
        production,
        producer_guard: i32::from(payload.producer_guard),
    };
    let namespace = NamespaceSpec {
        namespaces: [16, 17, 18, 19, 20, 21, 22, 23],
        enter_mask: payload.enter_mask,
        root: 24,
        cwd: 25,
        control: 26,
    };
    // The syscall-only runner never returns and never executes Rust after setns.
    unsafe { sigrund_run_namespace_launcher(&spec, &namespace) };
    Err(io::Error::other("namespace launcher unexpectedly returned"))
}

#[must_use = "register and reap every returned child; dropping pidfd does not stop it"]
pub struct ChildProcess {
    pub pid: libc::pid_t,
    pub pidfd: OwnedFd,
    pub sync: OwnedFd,
    pub deadline: Instant,
    pub gate: Option<OwnedFd>,
}

pub(crate) struct NamespaceTarget<'a> {
    pub namespaces: &'a [std::fs::File],
    pub constraints: &'a sigrund_core::namespace::Constraints,
    pub root: i32,
    pub cwd: i32,
}
pub(crate) enum Spawned {
    Child(ChildProcess),
    Launcher(NamespaceLauncher),
}
pub(crate) struct NamespaceLauncher {
    pub pid: i32,
    pub pidfd: Option<OwnedFd>,
    control: OwnedFd,
    sync: Option<OwnedFd>,
    gate: Option<OwnedFd>,
    pub deadline: Instant,
    pub ready: bool,
    pub granted: bool,
    protected: bool,
}
pub(crate) enum NamespaceEvent {
    Bootstrap,
    Ready,
    Child(ChildProcess),
}
impl NamespaceLauncher {
    /// The coordinator owns this ptrace relation before permitting any target
    /// userns or credential transition. EXITKILL covers daemon death throughout.
    pub fn protect(&mut self) -> io::Result<()> {
        if self.protected || self.ready || Instant::now() >= self.deadline {
            return Err(io::Error::other("namespace bootstrap gate unavailable"));
        }
        if unsafe {
            libc::ptrace(
                libc::PTRACE_SEIZE,
                self.pid,
                0usize,
                libc::PTRACE_O_EXITKILL as usize,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if unsafe {
            libc::send(
                self.control.as_raw_fd(),
                b"B".as_ptr().cast(),
                1,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } != 1
        {
            return Err(io::Error::last_os_error());
        }
        self.protected = true;
        Ok(())
    }
    pub fn grant(&mut self) -> io::Result<()> {
        if !self.ready || self.granted || Instant::now() >= self.deadline {
            return Err(io::Error::other("namespace clone gate unavailable"));
        }
        if unsafe {
            libc::send(
                self.control.as_raw_fd(),
                b"C".as_ptr().cast(),
                1,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } != 1
        {
            return Err(io::Error::last_os_error());
        }
        self.granted = true;
        Ok(())
    }
    pub fn poll(&mut self) -> io::Result<Option<NamespaceEvent>> {
        if Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut bytes = [0u8; 9];
        let mut ancillary = [0usize; 8];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&ancillary);
        let count = unsafe {
            libc::recvmsg(
                self.control.as_raw_fd(),
                &mut message,
                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            return if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if count == 0 {
            let mut frame = [0u32; 2];
            if let Some(sync) = &self.sync {
                let read = unsafe { libc::read(sync.as_raw_fd(), frame.as_mut_ptr().cast(), 8) };
                if read == 8 {
                    return Err(io::Error::other(format!(
                        "namespace setup stage {} errno {}",
                        frame[0], frame[1]
                    )));
                }
            }
            return Err(io::Error::other("namespace launcher closed before handoff"));
        }
        let mut rights = Vec::new();
        let mut valid = true;
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                if (*header).cmsg_level != libc::SOL_SOCKET
                    || (*header).cmsg_type != libc::SCM_RIGHTS
                {
                    valid = false;
                } else {
                    let length = (*header)
                        .cmsg_len
                        .saturating_sub(libc::CMSG_LEN(0) as usize);
                    valid &= length.is_multiple_of(std::mem::size_of::<i32>());
                    for index in 0..length / std::mem::size_of::<i32>() {
                        rights.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<i32>().add(index),
                        )));
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        if count != SG_EVENT_BYTES as isize
            || !valid
            || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        {
            return Err(io::Error::other("malformed namespace launcher response"));
        }
        let kind = u32::from_ne_bytes(bytes[..4].try_into().unwrap());
        let value = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
        match kind {
            SG_EVENT_BOOTSTRAP
                if value == 0 && rights.is_empty() && !self.protected && !self.ready =>
            {
                Ok(Some(NamespaceEvent::Bootstrap))
            }
            SG_EVENT_READY
                if value == 0
                    && rights.is_empty()
                    && self.protected
                    && !self.ready
                    && !self.granted =>
            {
                self.ready = true;
                Ok(Some(NamespaceEvent::Ready))
            }
            SG_EVENT_CHILD
                if self.granted && rights.len() == 1 && value > 0 && value <= i32::MAX as u32 =>
            {
                let pidfd = rights.remove(0);
                let info =
                    std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))?;
                if !info.lines().any(|line| {
                    line.strip_prefix("Pid:")
                        .is_some_and(|pid| pid.trim() == value.to_string())
                }) {
                    return Err(io::Error::other("namespace child pidfd mismatch"));
                }
                Ok(Some(NamespaceEvent::Child(ChildProcess {
                    pid: value as i32,
                    pidfd,
                    sync: self
                        .sync
                        .take()
                        .ok_or_else(|| io::Error::other("duplicate namespace child"))?,
                    gate: self.gate.take(),
                    deadline: self.deadline,
                })))
            }
            _ => Err(io::Error::other("unexpected namespace launcher response")),
        }
    }
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
            direct_path: if warrant.command.executable_trust.is_some()
                && warrant.execution_context.expected_capabilities().ambient
                    != warrant.execution_context.capabilities
            {
                Some(
                    CString::new(warrant.command.executable_path.as_str())
                        .map_err(|_| io::Error::other("NUL in executable path"))?,
                )
            } else {
                None
            },
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
        self.spawn_checkpoint(cgroup_fd, fds, false)
    }

    pub fn spawn_checkpoint(
        &mut self,
        cgroup_fd: RawFd,
        fds: [RawFd; 4],
        checkpoint: bool,
    ) -> io::Result<ChildProcess> {
        match self.spawn_inner(cgroup_fd, fds, checkpoint, None)? {
            Spawned::Child(child) => Ok(child),
            Spawned::Launcher(_) => unreachable!(),
        }
    }

    pub(crate) fn spawn_namespace(
        &mut self,
        cgroup: RawFd,
        fds: [RawFd; 4],
        target: NamespaceTarget<'_>,
    ) -> io::Result<NamespaceLauncher> {
        match self.spawn_inner(cgroup, fds, true, Some(target))? {
            Spawned::Launcher(launcher) => Ok(launcher),
            Spawned::Child(_) => unreachable!(),
        }
    }

    fn spawn_inner(
        &mut self,
        cgroup_fd: RawFd,
        fds: [RawFd; 4],
        checkpoint: bool,
        target: Option<NamespaceTarget<'_>>,
    ) -> io::Result<Spawned> {
        let (sync, writer) = sync_pipe()?;
        let gate = if checkpoint {
            let mut fds = [-1; 2];
            if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Some(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
        } else {
            None
        };
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
            direct_path: self
                .direct_path
                .as_ref()
                .map_or(std::ptr::null(), |p| p.as_ptr()),
            argv: argv.as_ptr(),
            envp: envp.as_ptr(),
            mountinfo: self.mountinfo.as_mut_ptr(),
            mountinfo_capacity: self.mountinfo.len(),
            group_check: self.group_check.as_mut_ptr(),
            isolated: i32::from(self.capabilities & (1 << 21) == 0),
            gate_read: gate.as_ref().map_or(-1, |g| g.0.as_raw_fd()),
            gate_write: gate.as_ref().map_or(-1, |g| g.1.as_raw_fd()),
            checkpoint: i32::from(checkpoint),
            namespace_mode: i32::from(target.is_some()),
            production: i32::from(
                target
                    .as_ref()
                    .is_some_and(|target| target.constraints.is_production()),
            ),
            producer_guard: i32::from(crate::lsm::producer_active()),
        };
        let mut pidfd = -1;
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut sockets = None;
        let pid = if let Some(target) = target {
            crate::access::domain()?;
            use std::os::unix::fs::MetadataExt;
            if target.namespaces.len() != 8
                || !self.groups.is_empty()
                || self.capabilities != 0
                || self.uid == 0
            {
                return Err(io::Error::other("unsupported namespace child profile"));
            }
            let mut pair = [-1; 2];
            if unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            let parent = unsafe { OwnedFd::from_raw_fd(pair[0]) };
            let child = unsafe { OwnedFd::from_raw_fd(pair[1]) };
            let mut namespace = NamespaceSpec {
                namespaces: [-1; 8],
                enter_mask: 0,
                root: target.root,
                cwd: target.cwd,
                control: child.as_raw_fd(),
            };
            for (index, name) in ["cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"]
                .iter()
                .enumerate()
            {
                namespace.namespaces[index] = target.namespaces[index].as_raw_fd();
                let own = std::fs::metadata(format!("/proc/self/ns/{name}"))?;
                let selected = target.namespaces[index].metadata()?;
                if own.dev() != selected.dev() || own.ino() != selected.ino() {
                    namespace.enter_mask |= 1 << index;
                }
            }
            let as_strings = |values: &[CString]| -> io::Result<Vec<String>> {
                values
                    .iter()
                    .map(|value| value.to_str().map(str::to_owned).map_err(io::Error::other))
                    .collect()
            };
            let payload = NamespacePayload {
                version: SG_PAYLOAD_VERSION,
                uid: self.uid,
                gid: self.gid,
                mask: self.mask,
                last_cap: self.last_cap,
                enter_mask: namespace.enter_mask,
                cwd: self.cwd.to_str().map_err(io::Error::other)?.to_owned(),
                argv: as_strings(&self.argv)?,
                envp: as_strings(&self.envp)?,
                constraints: target.constraints.clone(),
                producer_guard: crate::lsm::producer_active(),
            };
            let bytes = serde_json::to_vec(&payload)?;
            if bytes.len() > 1_048_576 {
                return Err(io::Error::other("oversize namespace launcher payload"));
            }
            let payload = crate::memfd::create_sealed("namespace-launcher", &bytes, false, 0o400)?;
            let pid = unsafe {
                sigrund_spawn_namespace_launcher(
                    &spec,
                    &namespace,
                    payload.as_raw_fd(),
                    cgroup_fd,
                    &mut pidfd,
                )
            };
            drop(child);
            sockets = Some(parent);
            pid
        } else {
            unsafe { sigrund_spawn(&spec, cgroup_fd, &mut pidfd) }
        };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        // CLONE_PIDFD guarantees a descriptor on success. A violation is an
        // internal/kernel ABI failure; do not pretend that no child exists.
        assert!(pid > 0 && pidfd >= 0, "clone3 violated pidfd contract");
        drop(writer);
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
        let gate = gate.map(|(_, writer)| writer);
        if let Some(control) = sockets {
            Ok(Spawned::Launcher(NamespaceLauncher {
                pid,
                pidfd: Some(pidfd),
                control,
                sync: Some(sync),
                gate,
                deadline,
                ready: false,
                granted: false,
                protected: false,
            }))
        } else {
            Ok(Spawned::Child(ChildProcess {
                pid,
                pidfd,
                sync,
                deadline,
                gate,
            }))
        }
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
    TRACE_AVAILABLE.store(false, std::sync::atomic::Ordering::Release);
    let id = sigrund_core::crypto::new_uuidv7().to_string();
    let cgroup = layout.create_job(&id, 67_108_864, 0, 32)?;
    // Exercise execveat and the complete credential path, not just namespace
    // creation. Pin a trusted, bounded ELF and execute only its sealed bytes.
    let result = (|| {
        use std::io::Read;
        // Distributions may install true as a symlink (for example to
        // gnutrue or a multicall binary). Resolve this fixed probe alias,
        // then pin its target without following any further links. Keep
        // argv[0] as true for multicall implementations.
        let probe_path = std::fs::canonicalize("/usr/bin/true")?;
        let file = crate::startup::open_pinned(&probe_path)?;
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
            direct_path: None,
            groups: vec![],
            uid: 0,
            gid: 0,
            mask: 0o077,
            capabilities: 0,
            last_cap,
            mountinfo: vec![0; 1_048_576],
            group_check: vec![],
        };
        let mut child = command.spawn_checkpoint(
            cgroup.fd(),
            [
                null.as_raw_fd(),
                null.as_raw_fd(),
                null.as_raw_fd(),
                executable.as_raw_fd(),
            ],
            true,
        )?;
        let gate = child.gate.take().expect("probe gate");
        let tracing = attach_checkpoint(child.pid, &gate).is_ok();
        if !tracing {
            // Unsupported tracing disables the direct models. The ordinary
            // mandatory startup exec probe must still pass independently.
            let _ = unsafe { libc::write(gate.as_raw_fd(), b"x".as_ptr().cast(), 1) };
        }
        drop(gate);
        if tracing {
            loop {
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let result = unsafe {
                    libc::waitid(
                        libc::P_PIDFD,
                        child.pidfd.as_raw_fd() as u32,
                        &mut info,
                        libc::WSTOPPED | libc::WNOHANG | libc::__WALL,
                    )
                };
                if result < 0 {
                    return Err(io::Error::last_os_error());
                }
                if unsafe { info.si_pid() } != 0 {
                    if info.si_code != libc::CLD_TRAPPED
                        || unsafe { info.si_status() }
                            != (libc::SIGTRAP | (libc::PTRACE_EVENT_EXEC << 8))
                    {
                        return Err(io::Error::other("unexpected startup trace stop"));
                    }
                    release_checkpoint(child.pid)?;
                    let status = std::fs::read_to_string("/proc/self/status")?;
                    let can_inspect = status
                        .lines()
                        .find_map(|line| line.strip_prefix("CapEff:"))
                        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
                        .is_some_and(|bits| bits & (1 << 19) != 0);
                    TRACE_AVAILABLE.store(can_inspect, std::sync::atomic::Ordering::Release);
                    break;
                }
                let mut poll = libc::pollfd {
                    fd: child.pidfd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut poll, 1, 5) } > 0 || Instant::now() >= child.deadline {
                    break;
                }
            }
        }
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
    fn launcher_fixture() -> (NamespaceLauncher, OwnedFd) {
        let mut pair = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            },
            0
        );
        let (sync, writer) = sync_pipe().unwrap();
        (
            NamespaceLauncher {
                pid: 1,
                pidfd: None,
                control: unsafe { OwnedFd::from_raw_fd(pair[0]) },
                sync: Some(sync),
                gate: Some(writer),
                deadline: Instant::now() + Duration::from_secs(2),
                ready: false,
                granted: false,
                protected: false,
            },
            unsafe { OwnedFd::from_raw_fd(pair[1]) },
        )
    }
    fn launcher_message(peer: &OwnedFd, kind: u32, value: u32) {
        let words = [kind, value];
        assert_eq!(
            unsafe {
                libc::send(
                    peer.as_raw_fd(),
                    words.as_ptr().cast(),
                    8,
                    libc::MSG_NOSIGNAL,
                )
            },
            8
        );
    }
    #[test]
    fn namespace_clone_grant_requires_ready_and_cannot_be_repeated() {
        let (mut launcher, peer) = launcher_fixture();
        assert!(launcher.grant().is_err());
        assert!(launcher.poll().unwrap().is_none());
        launcher_message(&peer, 3, 0);
        assert!(matches!(
            launcher.poll().unwrap(),
            Some(NamespaceEvent::Bootstrap)
        ));
        // This socket fixture tests framing; production sets this only after
        // successful coordinator-owned PTRACE_SEIZE and the bootstrap write.
        launcher.protected = true;
        launcher_message(&peer, 1, 0);
        assert!(matches!(
            launcher.poll().unwrap(),
            Some(NamespaceEvent::Ready)
        ));
        launcher.grant().unwrap();
        let mut byte = [0];
        assert_eq!(
            unsafe { libc::recv(peer.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) },
            1
        );
        assert_eq!(byte, *b"C");
        assert!(launcher.grant().is_err());
        launcher_message(&peer, 1, 0);
        assert!(launcher.poll().is_err());
    }
    #[test]
    fn namespace_handoff_rejects_wrong_order_truncation_and_expiry() {
        let (mut launcher, peer) = launcher_fixture();
        launcher_message(&peer, 1, 0);
        assert!(
            launcher.poll().is_err(),
            "setup cannot precede tracer protection"
        );
        let (mut launcher, peer) = launcher_fixture();
        launcher_message(&peer, 2, 10);
        assert!(launcher.poll().is_err());
        let (mut launcher, peer) = launcher_fixture();
        assert_eq!(
            unsafe {
                libc::send(
                    peer.as_raw_fd(),
                    b"short".as_ptr().cast(),
                    5,
                    libc::MSG_NOSIGNAL,
                )
            },
            5
        );
        assert!(launcher.poll().is_err());
        let (mut launcher, _peer) = launcher_fixture();
        launcher.deadline = Instant::now();
        assert!(launcher.poll().is_err());
        assert!(launcher.grant().is_err());
    }

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
