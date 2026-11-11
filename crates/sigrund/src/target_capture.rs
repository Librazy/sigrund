//! Fresh-exec owner of the constrained G-01 anchor. The daemon never changes its
//! own namespace or root. Private IPC transfers the pinned root, not a root path.
use crate::{
    target_registry::CapturedAnchor,
    transport::{ControlReader, FrameWriter},
};
use sigrund_core::{
    host_budget::{Budget, Charge, Reservation},
    namespace::{Acquisition, Contract, FsIdentity, ProcessContext, Registration},
};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}

fn verify_namespace(
    file: &File,
    name: &str,
    expected: &sigrund_core::namespace::NamespaceIdentity,
) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let kind = match name {
        "cgroup" => libc::CLONE_NEWCGROUP,
        "ipc" => libc::CLONE_NEWIPC,
        "mnt" => libc::CLONE_NEWNS,
        "net" => libc::CLONE_NEWNET,
        "pid" => libc::CLONE_NEWPID,
        "time" => 0x80,
        "user" => libc::CLONE_NEWUSER,
        "uts" => libc::CLONE_NEWUTS,
        _ => return Err(invalid("unknown namespace type")),
    };
    let stat = file.metadata()?;
    if stat.dev().to_string() != expected.device
        || stat.ino().to_string() != expected.inode
        || unsafe { libc::ioctl(file.as_raw_fd(), 0xb703) } != kind
    {
        return Err(invalid("captured namespace identity or type differs"));
    }
    Ok(())
}

unsafe extern "C" {
    fn sigrund_capture_begin(socket: i32, pid: i32, uid: u32) -> *mut libc::c_void;
    fn sigrund_capture_print(target: *mut libc::c_void);
    fn sigrund_capture_check(target: *mut libc::c_void);
    fn sigrund_capture_root(target: *mut libc::c_void) -> i32;
    fn sigrund_capture_namespace(target: *mut libc::c_void, index: u32) -> i32;
    fn sigrund_capture_dispose(target: *mut libc::c_void);
}

struct Worker {
    failed: bool,
    helper_pidfd: Arc<OwnedFd>,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    control: UnixStream,
    pidfd: Arc<OwnedFd>,
    _child_fds: Reservation,
    _target_fds: Option<Reservation>,
}
impl Worker {
    fn line(&mut self, check: impl Fn() -> io::Result<()>) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        loop {
            check()?;
            let buffer = match self.output.fill_buf() {
                Ok(buffer) => buffer,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut descriptor = libc::pollfd {
                        fd: self.output.get_ref().as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    unsafe {
                        libc::poll(&mut descriptor, 1, 10);
                    }
                    continue;
                }
                Err(error) => return Err(error),
            };
            if buffer.is_empty() {
                return Err(invalid("capture helper closed its response"));
            }
            let newline = buffer.iter().position(|byte| *byte == b'\n');
            let count = newline.map_or(buffer.len(), |position| position + 1);
            if bytes.len() + count > 65_536 {
                return Err(invalid("capture response exceeds bound"));
            }
            bytes.extend_from_slice(&buffer[..count]);
            self.output.consume(count);
            if newline.is_some() {
                return Ok(bytes);
            }
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        // The peer PID and UID were authenticated before spawning. Disposal
        // owns this dedicated anchor through actual exit, even when acquisition
        // or the helper fails partway. Signal only the original pidfd.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                0,
                0,
            );
        }
        // The coordinator may already have reaped the helper as an unknown
        // descendant. Never signal or wait using its reusable numeric PID.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.helper_pidfd.as_raw_fd(),
                libc::SIGKILL,
                0,
                0,
            );
        }
        loop {
            let mut information = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.helper_pidfd.as_raw_fd() as u32,
                    &mut information,
                    libc::WEXITED,
                )
            };
            if result == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                break;
            }
            std::process::abort();
        }
        let mut helper = libc::pollfd {
            fd: self.helper_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        while unsafe { libc::poll(&mut helper, 1, 1000) } <= 0 {}

        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut descriptor, 1, 1000) };
            if result > 0 && descriptor.revents & libc::POLLIN != 0 {
                break;
            }
            if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                // A retained, valid pidfd cannot become EBADF while owned here.
                std::process::abort();
            }
        }
    }
}

pub(crate) struct CaptureIdentity<'a> {
    pub pid: u32,
    pub uid: u32,
    pub registration: Option<&'a Registration>,
}

pub struct TargetCapture {
    worker: Mutex<Worker>,
    // Shared ownership adds no descriptors; lifecycle checks never need the
    // capture IPC lock, even while a destination filesystem exchange stalls.
    helper_pidfd: Arc<OwnedFd>,
    pidfd: Arc<OwnedFd>,
    root: File,
    namespaces: Vec<File>,
    acquisition: Acquisition,
    roots: Vec<PathBuf>,
    executable_roots: BTreeMap<String, FsIdentity>,
    _parent_fds: Reservation,
    _namespace_resources: Option<Reservation>,
}
impl TargetCapture {
    /// The caller holds a pre-acquisition registry reservation and must retain it
    /// until this result, or every failed capture resource, has been disposed.
    pub(crate) fn acquire(
        peer: impl AsRawFd,
        identity: CaptureIdentity<'_>,
        epoch: &str,
        budget: &Budget,
        roots: &[PathBuf],
        check: impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        if let Some(registration) = identity.registration {
            registration.validate().map_err(io::Error::other)?;
            if registration.daemon_pid != identity.pid || registration.owner_uid != identity.uid {
                return Err(invalid("capture identity differs from registration"));
            }
        }
        if identity.pid == 0 || identity.pid > i32::MAX as u32 || identity.uid == u32::MAX {
            return Err(invalid("invalid capture identity"));
        }
        sigrund_core::crypto::validate_uuidv7(epoch).map_err(io::Error::other)?;
        check()?;
        if roots.is_empty() || roots.len() > 64 {
            return Err(invalid("missing executable roots"));
        }
        // Includes the parent's peer pidfd, pipe/socket ends, high-numbered
        // duplicates, received root and the worker's transient observation FDs.
        let parent_fds = budget
            .reserve(
                identity.uid,
                Charge {
                    target_fds: 6,
                    ..Default::default()
                },
            )
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "capture parent capacity exhausted",
                )
            })?;
        // Declare this owner before Worker so failed transfers close/reap the
        // worker and its queued SCM_RIGHTS before refunding their reservation.
        let mut namespace_resources = Some(
            budget
                .reserve_child_resources(
                    identity.uid,
                    Charge {
                        target_fds: 8,
                        ..Default::default()
                    },
                )
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "capture queued namespaces capacity exhausted",
                    )
                })?,
        );
        let temporary = budget
            .reserve(
                identity.uid,
                Charge {
                    // Six spawn pipe ends, including the exec-error pipe.
                    target_fds: 6,
                    ..Default::default()
                },
            )
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "capture temporary capacity exhausted",
                )
            })?;
        let child_fds = budget
            .reserve_child_resources(
                identity.uid,
                Charge {
                    target_fds: 4,
                    ..Default::default()
                },
            )
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "capture child IPC capacity exhausted",
                )
            })?;
        let transient_child = budget
            .reserve_child_resources(
                identity.uid,
                Charge {
                    target_fds: 4,
                    ..Default::default()
                },
            )
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "capture transient child capacity exhausted",
                )
            })?;
        let mut credentials = unsafe { std::mem::zeroed::<libc::ucred>() };
        let mut size = size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                peer.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut size,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if size as usize != size_of::<libc::ucred>()
            || credentials.pid != identity.pid as i32
            || credentials.uid != identity.uid
        {
            return Err(invalid("registration differs from authenticated connector"));
        }
        let mut pidfd = -1;
        let mut length = size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                peer.as_raw_fd(),
                libc::SOL_SOCKET,
                77,
                (&mut pidfd as *mut i32).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if pidfd < 0 || length as usize != size_of::<i32>() {
            return Err(invalid("missing original connector pidfd"));
        }
        let pidfd = Arc::new(unsafe { OwnedFd::from_raw_fd(pidfd) });
        let (parent, child) = UnixStream::pair()?;
        parent.set_nonblocking(true)?;
        let duplicate = |fd| -> io::Result<OwnedFd> {
            let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        };
        let peer_copy = duplicate(peer.as_raw_fd())?;
        let control_copy = duplicate(child.as_raw_fd())?;
        let peer_raw = peer_copy.as_raw_fd();
        let control_raw = control_copy.as_raw_fd();
        let reaper = crate::reaper::HelperGuard::new();
        let instance = sigrund_core::crypto::new_uuidv7().to_string();
        let mut command = Command::new("/proc/self/exe");
        command
            .arg("--internal-target-helper")
            .env_clear()
            .env("SIGRUND_DAEMON_EPOCH", epoch)
            .env("SIGRUND_TARGET_INSTANCE", &instance)
            .env("SIGRUND_TARGET_PID", identity.pid.to_string())
            .env("SIGRUND_TARGET_UID", identity.uid.to_string())
            .env("SIGRUND_TARGET_ROOTS", serde_json::to_string(roots)?)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let parent_pid = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::getppid() != parent_pid
                {
                    return Err(io::Error::other("capture parent exited"));
                }
                if libc::dup2(peer_raw, 3) < 0
                    || libc::dup2(control_raw, 4) < 0
                    || libc::syscall(
                        libc::SYS_close_range,
                        5u32,
                        u32::MAX,
                        libc::CLOSE_RANGE_CLOEXEC,
                    ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        // Command::spawn completes the exec handshake. close_range(CLOEXEC)
        // has then closed every inherited parent target descriptor. The passed
        // IPC/peer and stdio descriptors have their separate child charge.
        let mut child_process = budget
            .with_transient_fd_copies(identity.uid, || command.spawn())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "capture fork FD capacity exhausted: {:?}",
                        budget.usage(identity.uid)
                    ),
                )
            })??;
        drop(peer_copy);
        drop(control_copy);
        drop(child);
        // The short registration barrier prevents PID reuse before pidfd_open.
        let helper_fd =
            unsafe { libc::syscall(libc::SYS_pidfd_open, child_process.id(), 0) } as i32;
        if helper_fd < 0 {
            let error = io::Error::last_os_error();
            let _ = child_process.kill();
            let _ = child_process.wait();
            return Err(error);
        }
        let helper_pidfd = Arc::new(unsafe { OwnedFd::from_raw_fd(helper_fd) });
        drop(reaper);
        let input = child_process.stdin.take().expect("capture stdin");
        let output = child_process.stdout.take().expect("capture stdout");
        let mut worker = Worker {
            failed: false,
            helper_pidfd,
            input,
            output: BufReader::new(output),
            control: parent,
            pidfd,
            _child_fds: child_fds,
            _target_fds: None,
        };
        // Command::spawn completed its exec handshake, and all parent spawn
        // duplicates closed above. Only now admit the helper's target pins.
        drop(temporary);
        worker._target_fds = Some(
            budget
                .reserve_child_resources(
                    identity.uid,
                    Charge {
                        target_fds: 20 + roots.len() as u32,
                        ..Default::default()
                    },
                )
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "capture target capacity exhausted",
                    )
                })?,
        );
        worker.input.write_all(b"B")?;
        if unsafe {
            libc::fcntl(
                worker.output.get_ref().as_raw_fd(),
                libc::F_SETFL,
                libc::O_NONBLOCK,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut acquisition =
            Acquisition::parse(&worker.line(&check)?).map_err(io::Error::other)?;
        if acquisition.pid != identity.pid
            || acquisition.anchor.host_uid != identity.uid
            || acquisition.daemon_epoch != epoch
            || acquisition.instance_id != instance
        {
            return Err(invalid("capture reply differs from selected anchor"));
        }
        // Before any SCM_RIGHTS receive, transfer the pre-reserved namespace
        // references to parent ownership. The helper fork has already execed.
        namespace_resources = namespace_resources.take().map(Reservation::into_parent);
        let mut reader = ControlReader::new(true);
        let (root, executable_roots) = loop {
            check()?;
            if let Some(mut frame) = reader.read(worker.control.as_raw_fd(), Instant::now())? {
                if frame.rights.len() != 1 {
                    return Err(invalid("invalid captured root descriptor"));
                }
                sigrund_core::json::preflight(&frame.payload, 16, 4096)
                    .map_err(io::Error::other)?;
                let identities: BTreeMap<String, FsIdentity> =
                    serde_json::from_slice(&frame.payload)?;
                if identities.len() != roots.len()
                    || roots
                        .iter()
                        .any(|path| !identities.contains_key(path.to_str().unwrap_or("")))
                {
                    return Err(invalid("capture returned different executable roots"));
                }
                break (File::from(frame.rights.remove(0)), identities);
            }
            let mut descriptor = libc::pollfd {
                fd: worker.control.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe {
                libc::poll(&mut descriptor, 1, 10);
            }
        };
        if crate::destination_helper::identity(&root)? != acquisition.root
            || !root.metadata()?.is_dir()
        {
            return Err(invalid("captured root identity differs"));
        }
        let mut namespaces = Vec::new();
        for name in ["cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"] {
            let mut reader = ControlReader::new(true);
            loop {
                check()?;
                if let Some(mut frame) = reader.read(worker.control.as_raw_fd(), Instant::now())? {
                    if frame.payload != name.as_bytes() || frame.rights.len() != 1 {
                        return Err(invalid("invalid captured namespace transfer"));
                    }
                    let namespace = File::from(frame.rights.remove(0));
                    verify_namespace(&namespace, name, &acquisition.namespaces[name])?;
                    namespaces.push(namespace);
                    break;
                }
                let mut descriptor = libc::pollfd {
                    fd: worker.control.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                unsafe {
                    libc::poll(&mut descriptor, 1, 10);
                }
            }
        }
        acquisition.lifecycle.registration_id = identity
            .registration
            .map(|registration| registration.id.clone());
        acquisition.lifecycle.registration_revision = identity
            .registration
            .map(|registration| registration.revision.clone());
        acquisition.validate().map_err(io::Error::other)?;
        ProcessContext {
            schema: "sigrund.process-context.v1".into(),
            manager: None,
            authenticated_source: None,
            acquisition: acquisition.clone(),
            executable_roots: executable_roots.clone(),
        }
        .canonical()
        .map_err(io::Error::other)?;
        if worker.line(&check)? != b"{\"ready\":true}\n" {
            return Err(invalid("capture did not finish descriptor transfer"));
        }
        // The child confirms its peer and transfer duplicates have closed.
        // Socket disposal may shut down the shared endpoint only after this.
        drop(peer);
        drop(transient_child);

        let result = Self {
            helper_pidfd: worker.helper_pidfd.clone(),
            pidfd: worker.pidfd.clone(),
            worker: Mutex::new(worker),
            root,
            namespaces,
            acquisition,
            roots: roots.to_vec(),
            executable_roots,
            _parent_fds: parent_fds,
            _namespace_resources: namespace_resources,
        };
        result.revalidate()?;
        Ok(result)
    }
    pub fn root(&self) -> &File {
        &self.root
    }
}
impl CapturedAnchor for TargetCapture {
    fn namespace_files(&self) -> &[File] {
        &self.namespaces
    }
    fn executable_roots(&self) -> BTreeMap<String, FsIdentity> {
        self.executable_roots.clone()
    }
    fn directory(&self, path: &Path, check: &dyn Fn() -> io::Result<()>) -> io::Result<File> {
        let index = self
            .roots
            .iter()
            .position(|root| root == path)
            .ok_or_else(|| invalid("executable root was not pinned for this instance"))?;
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| invalid("capture worker poisoned"))?;
        if worker.failed {
            return Err(invalid("capture stream retired"));
        }
        worker.failed = true;
        worker.input.write_all(&[b'R', index as u8])?;
        let mut reader = ControlReader::new(true);
        loop {
            check()?;
            if let Some(mut frame) = reader.read(worker.control.as_raw_fd(), Instant::now())? {
                if frame.payload != b"{}" || frame.rights.len() != 1 {
                    return Err(invalid("invalid pinned executable root response"));
                }
                let directory = File::from(frame.rights.remove(0));
                if self.executable_roots.get(path.to_str().unwrap_or(""))
                    != Some(&crate::destination_helper::identity(&directory)?)
                {
                    return Err(invalid("pinned executable root identity changed"));
                }
                worker.failed = false;
                return Ok(directory);
            }
            let mut descriptor = libc::pollfd {
                fd: worker.control.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe {
                libc::poll(&mut descriptor, 1, 10);
            }
        }
    }

    fn alive(&self) -> bool {
        if !pidfds_live(&self.pidfd, &self.helper_pidfd) {
            return false;
        }
        let worker = match self.worker.try_lock() {
            Ok(worker) => worker,
            Err(std::sync::TryLockError::WouldBlock) => return true,
            Err(_) => return false,
        };
        if worker.failed {
            return false;
        }
        true
    }

    fn root(&self) -> &File {
        &self.root
    }
    fn acquisition(&self) -> &Acquisition {
        &self.acquisition
    }
    fn revalidate(&self) -> io::Result<()> {
        if !pidfds_live(&self.pidfd, &self.helper_pidfd) {
            return Err(invalid("capture process exited"));
        }
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| invalid("capture worker poisoned"))?;
        if worker.failed {
            return Err(invalid("capture stream retired"));
        }
        worker.failed = true;
        worker.input.write_all(b"L")?;
        let deadline = Instant::now() + Duration::from_secs(1);
        let line = worker.line(|| {
            if Instant::now() >= deadline {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Ok(())
            }
        })?;
        if line != b"{\"live\":true}\n" || !pidfds_live(&self.pidfd, &self.helper_pidfd) {
            return Err(invalid("anchor no longer live"));
        }
        worker.failed = false;
        Ok(())
    }
}

fn pidfds_live(anchor: &OwnedFd, helper: &OwnedFd) -> bool {
    let mut descriptors = [
        libc::pollfd {
            fd: anchor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: helper.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    unsafe { libc::poll(descriptors.as_mut_ptr(), 2, 0) == 0 }
}

/// Internal entry before configuration, secrets or listeners.
pub fn helper_main() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let pid = std::env::var("SIGRUND_TARGET_PID")
        .map_err(io::Error::other)?
        .parse::<i32>()
        .map_err(io::Error::other)?;
    let uid = std::env::var("SIGRUND_TARGET_UID")
        .map_err(io::Error::other)?
        .parse::<u32>()
        .map_err(io::Error::other)?;
    // Acquisition is bounded independently of the requester's admission timer.
    unsafe {
        libc::alarm(10);
    }
    let roots: Vec<PathBuf> =
        serde_json::from_str(&std::env::var("SIGRUND_TARGET_ROOTS").map_err(io::Error::other)?)?;
    if roots.is_empty() || roots.len() > 64 {
        return Err(invalid("invalid target executable roots"));
    }
    let mut begin = [0];
    io::stdin().read_exact(&mut begin)?;
    if begin != *b"B" {
        return Err(invalid("invalid target acquisition grant"));
    }
    let target = unsafe { sigrund_capture_begin(3, pid, uid) };
    unsafe {
        libc::close(3);
    }
    let mut pinned = Vec::<File>::new();
    let mut identities = BTreeMap::new();
    for path in &roots {
        crate::linux::validate_absolute_path(path)?;
        let relative = path.strip_prefix("/").map_err(io::Error::other)?;
        if relative.as_os_str().is_empty() {
            return Err(invalid("executable root cannot be /"));
        }
        let directory: File =
            crate::linux::openat2_root(unsafe { sigrund_capture_root(target) }, relative)?.into();
        identities.insert(
            path.to_str()
                .ok_or_else(|| invalid("non-UTF8 executable root"))?
                .to_owned(),
            crate::destination_helper::identity(&directory)?,
        );
        pinned.push(directory);
    }

    unsafe {
        sigrund_capture_print(target);
    }
    let socket = unsafe { UnixStream::from_raw_fd(4) };
    socket.set_nonblocking(true)?;
    let root = unsafe { libc::fcntl(sigrund_capture_root(target), libc::F_DUPFD_CLOEXEC, 10) };
    if root < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut writer = FrameWriter::private_rights(
        &serde_json::to_vec(&identities)?,
        vec![unsafe { OwnedFd::from_raw_fd(root) }],
        Instant::now(),
    )?;
    while !writer.write(socket.as_raw_fd(), Instant::now())? {
        let mut descriptor = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        unsafe {
            libc::poll(&mut descriptor, 1, 10);
        }
    }
    for (index, name) in ["cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"]
        .iter()
        .enumerate()
    {
        let fd = unsafe {
            libc::fcntl(
                sigrund_capture_namespace(target, index as u32),
                libc::F_DUPFD_CLOEXEC,
                10,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut writer = FrameWriter::private_rights(
            name.as_bytes(),
            vec![unsafe { OwnedFd::from_raw_fd(fd) }],
            Instant::now(),
        )?;
        while !writer.write(socket.as_raw_fd(), Instant::now())? {
            let mut descriptor = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            unsafe {
                libc::poll(&mut descriptor, 1, 10);
            }
        }
    }
    io::stdout().write_all(b"{\"ready\":true}\n")?;
    io::stdout().flush()?;
    unsafe {
        libc::alarm(0);
    }
    let mut byte = [0];
    while io::stdin().read(&mut byte)? == 1 {
        unsafe {
            sigrund_capture_check(target);
        }
        match byte[0] {
            b'L' => {
                io::stdout().write_all(b"{\"live\":true}\n")?;
                io::stdout().flush()?;
            }
            b'R' => {
                let mut index = [0];
                io::stdin().read_exact(&mut index)?;
                let directory = pinned
                    .get(index[0] as usize)
                    .ok_or_else(|| invalid("invalid executable root index"))?;
                let duplicate = directory.try_clone()?.into();
                let mut writer =
                    FrameWriter::private_rights(b"{}", vec![duplicate], Instant::now())?;
                while !writer.write(socket.as_raw_fd(), Instant::now())? {
                    let mut descriptor = libc::pollfd {
                        fd: socket.as_raw_fd(),
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    unsafe {
                        libc::poll(&mut descriptor, 1, 10);
                    }
                }
            }
            _ => break,
        }
    }
    unsafe {
        sigrund_capture_dispose(target);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_handoff_rejects_other_namespace_types_and_inodes() {
        use std::os::unix::fs::MetadataExt;
        let file = File::open("/proc/self/ns/mnt").unwrap();
        let stat = file.metadata().unwrap();
        let mut expected = sigrund_core::namespace::NamespaceIdentity {
            device: stat.dev().to_string(),
            inode: stat.ino().to_string(),
            owner_userns_device: "0".into(),
            owner_userns_inode: "0".into(),
        };
        verify_namespace(&file, "mnt", &expected).unwrap();
        assert!(verify_namespace(&file, "user", &expected).is_err());
        expected.inode = "0".into();
        assert!(verify_namespace(&file, "mnt", &expected).is_err());
        let ordinary = File::open("/dev/null").unwrap();
        let stat = ordinary.metadata().unwrap();
        expected.device = stat.dev().to_string();
        expected.inode = stat.ino().to_string();
        assert!(verify_namespace(&ordinary, "mnt", &expected).is_err());
    }

    fn capture_fixture() -> (TargetCapture, std::process::Child, std::process::Child) {
        let budget = Budget::new(Default::default()).unwrap();
        let mut helper = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let anchor = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pidfd = |pid: u32| {
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
            assert!(fd >= 0);
            unsafe { OwnedFd::from_raw_fd(fd) }
        };
        let helper_pidfd = Arc::new(pidfd(helper.id()));
        let anchor_pidfd = Arc::new(pidfd(anchor.id()));
        let capture = TargetCapture {
            helper_pidfd: helper_pidfd.clone(),
            pidfd: anchor_pidfd.clone(),
            worker: Mutex::new(Worker {
                failed: false,
                helper_pidfd,
                pidfd: anchor_pidfd,
                input: helper.stdin.take().unwrap(),
                output: BufReader::new(helper.stdout.take().unwrap()),
                control: UnixStream::pair().unwrap().0,
                _target_fds: None,
                _child_fds: budget
                    .reserve(
                        1000,
                        Charge {
                            target_fds: 1,
                            ..Default::default()
                        },
                    )
                    .unwrap(),
            }),
            root: File::open("/").unwrap(),
            namespaces: Vec::new(),
            _namespace_resources: None,
            acquisition: Acquisition::parse(include_bytes!(
                "../../sigrund-core/tests/fixtures/namespace/acquisition.json"
            ))
            .unwrap(),
            roots: vec![PathBuf::from("/usr/bin")],
            executable_roots: BTreeMap::new(),
            _parent_fds: budget
                .reserve(
                    1000,
                    Charge {
                        target_fds: 1,
                        ..Default::default()
                    },
                )
                .unwrap(),
        };
        (capture, helper, anchor)
    }

    #[test]
    fn anchor_and_helper_death_remain_visible_during_a_blocked_directory_exchange() {
        for kill_anchor in [true, false] {
            let (capture, mut helper, mut anchor) = capture_fixture();
            let capture = Arc::new(capture);
            let (entered, arrived) = std::sync::mpsc::sync_channel(1);
            let (release, wait) = std::sync::mpsc::sync_channel(1);
            let request = capture.clone();
            let exchange = std::thread::spawn(move || {
                request.directory(Path::new("/usr/bin"), &|| {
                    entered.send(()).unwrap();
                    wait.recv().unwrap();
                    Err(io::ErrorKind::Interrupted.into())
                })
            });
            arrived.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(capture.worker.try_lock().is_err());
            assert!(capture.alive());
            let victim = if kill_anchor {
                &mut anchor
            } else {
                &mut helper
            };
            victim.kill().unwrap();
            victim.wait().unwrap();
            assert!(!capture.alive(), "IPC contention cannot hide process exit");
            release.send(()).unwrap();
            assert!(exchange.join().unwrap().is_err());
            drop(capture);
            let _ = helper.wait();
            let _ = anchor.wait();
        }
    }

    #[test]
    fn interrupted_root_exchange_permanently_retires_stream() {
        let (capture, mut helper, mut anchor) = capture_fixture();
        assert!(
            capture
                .directory(Path::new("/usr/bin"), &|| Err(
                    io::ErrorKind::Interrupted.into()
                ))
                .is_err()
        );
        assert!(!capture.alive());
        assert!(
            capture
                .revalidate()
                .unwrap_err()
                .to_string()
                .contains("retired")
        );
        drop(capture);
        let _ = helper.wait();
        let _ = anchor.wait();
    }

    #[test]
    fn disposal_uses_pidfds_after_the_helper_has_already_been_reaped() {
        fn pidfd(pid: u32) -> OwnedFd {
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
            assert!(raw >= 0);
            unsafe { OwnedFd::from_raw_fd(raw) }
        }
        let budget = Budget::new(Default::default()).unwrap();
        let mut helper = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut anchor = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let worker = Worker {
            _target_fds: None,
            failed: false,
            helper_pidfd: Arc::new(pidfd(helper.id())),
            input: helper.stdin.take().unwrap(),
            output: BufReader::new(helper.stdout.take().unwrap()),
            control: UnixStream::pair().unwrap().0,
            pidfd: Arc::new(pidfd(anchor.id())),
            _child_fds: budget
                .reserve(
                    1000,
                    Charge {
                        target_fds: 5,
                        ..Default::default()
                    },
                )
                .unwrap(),
        };
        helper.kill().unwrap();
        helper.wait().unwrap();
        // Simulate the coordinator's P_ALL sweep consuming an unknown helper
        // exit before the target owner disposes its retained process references.
        drop(worker);
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(anchor.wait().unwrap().signal(), Some(libc::SIGKILL));
        assert!(
            budget
                .reserve(
                    1000,
                    Charge {
                        target_fds: 128,
                        ..Default::default()
                    }
                )
                .is_some()
        );
    }
}
