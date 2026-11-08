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
    sync::Mutex,
    time::{Duration, Instant},
};

fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}

unsafe extern "C" {
    fn sigrund_capture_begin(socket: i32, pid: i32, uid: u32) -> *mut libc::c_void;
    fn sigrund_capture_print(target: *mut libc::c_void);
    fn sigrund_capture_check(target: *mut libc::c_void);
    fn sigrund_capture_root(target: *mut libc::c_void) -> i32;
    fn sigrund_capture_dispose(target: *mut libc::c_void);
}

struct Worker {
    failed: bool,
    helper_pidfd: OwnedFd,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    control: UnixStream,
    pidfd: OwnedFd,
    _child_fds: Reservation,
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

pub struct TargetCapture {
    worker: Mutex<Worker>,
    root: File,
    acquisition: Acquisition,
    roots: Vec<PathBuf>,
    executable_roots: BTreeMap<String, FsIdentity>,
    _parent_fds: Reservation,
}
impl TargetCapture {
    /// The caller holds a pre-acquisition registry reservation and must retain it
    /// until this result, or every failed capture resource, has been disposed.
    pub(crate) fn acquire(
        peer: impl AsRawFd,
        registration: &Registration,
        epoch: &str,
        budget: &Budget,
        roots: &[PathBuf],
        check: impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        registration.validate().map_err(io::Error::other)?;
        sigrund_core::crypto::validate_uuidv7(epoch).map_err(io::Error::other)?;
        check()?;
        if roots.is_empty() || roots.len() > 64 {
            return Err(invalid("missing executable roots"));
        }
        // Includes the parent's peer pidfd, pipe/socket ends, high-numbered
        // duplicates, received root and the worker's transient observation FDs.
        let temporary = budget
            .reserve(
                registration.owner_uid,
                Charge {
                    target_fds: 14,
                    ..Default::default()
                },
            )
            .ok_or(io::ErrorKind::WouldBlock)?;
        let child_fds = budget
            .reserve_child_resources(
                registration.owner_uid,
                Charge {
                    target_fds: 4,
                    ..Default::default()
                },
            )
            .ok_or(io::ErrorKind::WouldBlock)?;
        let transient_child = budget
            .reserve_child_resources(
                registration.owner_uid,
                Charge {
                    target_fds: 4,
                    ..Default::default()
                },
            )
            .ok_or(io::ErrorKind::WouldBlock)?;
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
            || credentials.pid != registration.daemon_pid as i32
            || credentials.uid != registration.owner_uid
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
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
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
            .env("SIGRUND_TARGET_PID", registration.daemon_pid.to_string())
            .env("SIGRUND_TARGET_UID", registration.owner_uid.to_string())
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
            .with_transient_fd_copies(registration.owner_uid, || command.spawn())
            .ok_or(io::ErrorKind::WouldBlock)??;
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
        let helper_pidfd = unsafe { OwnedFd::from_raw_fd(helper_fd) };
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
        };
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
        if acquisition.pid != registration.daemon_pid
            || acquisition.anchor.host_uid != registration.owner_uid
            || acquisition.daemon_epoch != epoch
            || acquisition.instance_id != instance
        {
            return Err(invalid("capture reply differs from selected anchor"));
        }
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
        acquisition.lifecycle.registration_id = Some(registration.id.clone());
        acquisition.lifecycle.registration_revision = Some(registration.revision.clone());
        acquisition.validate().map_err(io::Error::other)?;
        ProcessContext {
            schema: "sigrund.process-context.v1".into(),
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

        let parent_fds = budget
            .reserve(
                registration.owner_uid,
                Charge {
                    target_fds: 6,
                    ..Default::default()
                },
            )
            .ok_or(io::ErrorKind::WouldBlock)?;
        drop(temporary);
        let result = Self {
            worker: Mutex::new(worker),
            root,
            acquisition,
            roots: roots.to_vec(),
            executable_roots,
            _parent_fds: parent_fds,
        };
        result.revalidate()?;
        Ok(result)
    }
    pub fn root(&self) -> &File {
        &self.root
    }
}
impl CapturedAnchor for TargetCapture {
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
        let worker = match self.worker.try_lock() {
            Ok(worker) => worker,
            Err(std::sync::TryLockError::WouldBlock) => return true,
            Err(_) => return false,
        };
        if worker.failed {
            return false;
        }
        let mut descriptors = [
            libc::pollfd {
                fd: worker.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: worker.helper_pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        unsafe { libc::poll(descriptors.as_mut_ptr(), 2, 0) == 0 }
    }

    fn root(&self) -> &File {
        &self.root
    }
    fn acquisition(&self) -> &Acquisition {
        &self.acquisition
    }
    fn revalidate(&self) -> io::Result<()> {
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
        if line != b"{\"live\":true}\n" {
            return Err(invalid("anchor no longer live"));
        }
        worker.failed = false;
        Ok(())
    }
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
    fn interrupted_root_exchange_permanently_retires_stream() {
        let budget = Budget::new(Default::default()).unwrap();
        let mut helper = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut anchor = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pidfd = |pid: u32| {
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
            assert!(fd >= 0);
            unsafe { OwnedFd::from_raw_fd(fd) }
        };
        let capture = TargetCapture {
            worker: Mutex::new(Worker {
                failed: false,
                helper_pidfd: pidfd(helper.id()),
                pidfd: pidfd(anchor.id()),
                input: helper.stdin.take().unwrap(),
                output: BufReader::new(helper.stdout.take().unwrap()),
                control: UnixStream::pair().unwrap().0,
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
            acquisition: Acquisition::parse(include_bytes!(
                "../../sigrund-phase0/tests/fixtures/acquisition.json"
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
            failed: false,
            helper_pidfd: pidfd(helper.id()),
            input: helper.stdin.take().unwrap(),
            output: BufReader::new(helper.stdout.take().unwrap()),
            control: UnixStream::pair().unwrap().0,
            pidfd: pidfd(anchor.id()),
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
