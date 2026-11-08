//! Fresh-exec preparation against one retained destination root.
use crate::{
    destination::{self, Credentials},
    target_registry::TargetLease,
    transport::{ControlReader, FrameWriter},
};
use serde::{Deserialize, Serialize};
use sigrund_core::{
    host::Account,
    host_budget::{Charge, Reservation},
    namespace::{Acquisition, FsIdentity},
};
use std::{
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    path::PathBuf,
    process::{Command, Stdio},
    time::Instant,
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    account: Account,
    acquisition: Acquisition,
    roots: Vec<PathBuf>,
    executable: PathBuf,
    cwd: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub credentials: Credentials,
    pub executable: FsIdentity,
    pub cwd: FsIdentity,
}
pub struct Prepared {
    pub directory: File,
    pub source: File,
    pub cwd: File,
    pub evidence: Evidence,
    pub resources: Reservation,
}
fn invalid(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}
fn pause(fd: i32, events: i16) {
    let mut descriptor = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    unsafe {
        libc::poll(&mut descriptor, 1, 10);
    }
}
pub fn identity(file: &File) -> io::Result<FsIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    let mut stat = unsafe { std::mem::zeroed::<libc::statx>() };
    if unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID,
            &mut stat,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if stat.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(invalid("missing destination mount identity"));
    }
    Ok(FsIdentity {
        device: metadata.dev().to_string(),
        inode: metadata.ino().to_string(),
        mount_id: stat.stx_mnt_id.to_string(),
    })
}
pub fn prepare(
    target: &TargetLease,
    account: Account,
    roots: Vec<PathBuf>,
    executable: PathBuf,
    cwd: PathBuf,
    authorize: impl Fn(&Credentials) -> io::Result<()>,
    check: impl Fn() -> io::Result<()>,
) -> io::Result<Prepared> {
    check()?;
    target.revalidate()?;
    let resources = target.reserve_resources(Charge {
        target_fds: 6,
        ..Default::default()
    })?;
    let _helper = target.reserve_resources(Charge {
        helpers: 1,
        target_fds: 16,
        ..Default::default()
    })?;
    let request = Request {
        account,
        acquisition: target.acquisition().clone(),
        roots,
        executable,
        cwd,
    };
    let selected =
        sigrund_core::paths::select_root(&request.executable, &request.roots).map_err(invalid)?;
    let directory = target.directory(&selected.root, &check)?;
    let directory_identity = identity(&directory)?;
    let (parent, child) = UnixStream::pair()?;
    parent.set_nonblocking(true)?;
    let duplicate = |fd| -> io::Result<OwnedFd> {
        let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
        if raw < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(raw) })
        }
    };
    let root = duplicate(target.root().as_raw_fd())?;
    let socket = duplicate(child.as_raw_fd())?;
    let directory_copy = duplicate(directory.as_raw_fd())?;
    let root_raw = root.as_raw_fd();
    let socket_raw = socket.as_raw_fd();
    let directory_raw = directory_copy.as_raw_fd();
    let reaper = crate::reaper::HelperGuard::new();
    let mut command = Command::new("/proc/self/exe");
    command
        .arg("--internal-destination-helper")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let parent_pid = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != parent_pid
                || libc::dup2(root_raw, 3) < 0
                || libc::dup2(socket_raw, 4) < 0
                || libc::dup2(directory_raw, 5) < 0
                || libc::syscall(
                    libc::SYS_close_range,
                    6u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let (spawned, _copies) = target.with_fd_copies(|| command.spawn())?;
    let mut helper = spawned?;
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, helper.id(), 0) } as i32;
    if raw < 0 {
        let error = io::Error::last_os_error();
        let _ = helper.kill();
        let _ = helper.wait();
        return Err(error);
    }
    let helper_pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    drop(reaper);
    drop(root);
    drop(socket);
    drop(directory_copy);
    drop(child);
    let result = (|| {
        let mut writer = FrameWriter::control(
            sigrund_core::framing::FrameType::ClientHello,
            &serde_json::to_vec(&request)?,
            Instant::now(),
        )?;
        while !writer.write(parent.as_raw_fd(), Instant::now())? {
            check()?;
            pause(parent.as_raw_fd(), libc::POLLOUT);
        }
        let mut reader = ControlReader::new(false);
        loop {
            check()?;
            if let Some(frame) = reader.read(parent.as_raw_fd(), Instant::now())? {
                let credentials: Credentials = serde_json::from_slice(&frame.payload)?;
                if request
                    .acquisition
                    .compose_credentials(
                        credentials.uid,
                        credentials.gid,
                        credentials.groups.clone(),
                    )
                    .map_err(invalid)?
                    != credentials
                {
                    return Err(invalid("credential mapping mismatch"));
                }
                authorize(&credentials)?;
                break;
            }
            pause(parent.as_raw_fd(), libc::POLLIN);
        }
        let mut ack = FrameWriter::control(
            sigrund_core::framing::FrameType::ClientHello,
            b"{}",
            Instant::now(),
        )?;
        while !ack.write(parent.as_raw_fd(), Instant::now())? {
            check()?;
            pause(parent.as_raw_fd(), libc::POLLOUT);
        }
        let mut reader = ControlReader::new(true);
        loop {
            check()?;
            if let Some(mut frame) = reader.read(parent.as_raw_fd(), Instant::now())? {
                if frame.rights.len() != 2 {
                    return Err(invalid(
                        "destination helper returned wrong descriptor count",
                    ));
                }
                sigrund_core::json::preflight(&frame.payload, 16, 4096).map_err(invalid)?;
                let evidence: Evidence = serde_json::from_slice(&frame.payload)?;
                let numeric = &evidence.credentials;
                let composed = request
                    .acquisition
                    .compose_credentials(numeric.uid, numeric.gid, numeric.groups.clone())
                    .map_err(invalid)?;
                if composed != evidence.credentials {
                    return Err(invalid(
                        "destination credential mapping differs from captured ancestry",
                    ));
                }
                let source = File::from(frame.rights.remove(0));
                let cwd = File::from(frame.rights.remove(0));
                if !directory.metadata()?.is_dir()
                    || identity(&directory)? != directory_identity
                    || !source.metadata()?.is_file()
                    || !cwd.metadata()?.is_dir()
                    || identity(&source)? != evidence.executable
                    || identity(&cwd)? != evidence.cwd
                {
                    return Err(invalid("destination descriptor evidence differs"));
                }
                return Ok(Prepared {
                    directory,
                    source,
                    cwd,
                    evidence,
                    resources,
                });
            }
            pause(parent.as_raw_fd(), libc::POLLIN);
        }
    })();
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            helper_pidfd.as_raw_fd(),
            libc::SIGKILL,
            0,
            0,
        );
    }
    loop {
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        if unsafe {
            libc::waitid(
                libc::P_PIDFD,
                helper_pidfd.as_raw_fd() as u32,
                &mut info,
                libc::WEXITED,
            )
        } == 0
        {
            break;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ECHILD) {
            break;
        }
        if error.kind() != io::ErrorKind::Interrupted {
            std::process::abort();
        }
    }
    let mut exited = libc::pollfd {
        fd: helper_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    while unsafe { libc::poll(&mut exited, 1, 100) } <= 0 {}
    check()?;
    target.revalidate()?;
    result
}
pub fn helper_main() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let root = unsafe { File::from_raw_fd(3) };
    let directory = unsafe { File::from_raw_fd(5) };
    let socket = unsafe { UnixStream::from_raw_fd(4) };
    socket.set_nonblocking(true)?;
    let mut reader = ControlReader::new(true);
    let request: Request = loop {
        if let Some(frame) = reader.read(socket.as_raw_fd(), Instant::now())? {
            if !frame.rights.is_empty() {
                return Err(invalid("unexpected destination helper rights"));
            }
            sigrund_core::json::preflight(&frame.payload, 16, 4096).map_err(invalid)?;
            break serde_json::from_slice(&frame.payload)?;
        }
        pause(socket.as_raw_fd(), libc::POLLIN);
    };
    if request.roots.is_empty() || request.roots.len() > 64 {
        return Err(invalid("invalid destination executable roots"));
    }
    let credentials = destination::resolve(&root, &request.account, &request.acquisition)?;
    let mut resolved = FrameWriter::control(
        sigrund_core::framing::FrameType::ClientHello,
        &serde_json::to_vec(&credentials)?,
        Instant::now(),
    )?;
    while !resolved.write(socket.as_raw_fd(), Instant::now())? {
        pause(socket.as_raw_fd(), libc::POLLOUT);
    }
    let mut accepted = ControlReader::new(false);
    loop {
        if let Some(frame) = accepted.read(socket.as_raw_fd(), Instant::now())? {
            if frame.payload != b"{}" {
                return Err(invalid("invalid policy acknowledgement"));
            }
            break;
        }
        pause(socket.as_raw_fd(), libc::POLLIN);
    }
    let selected =
        sigrund_core::paths::select_root(&request.executable, &request.roots).map_err(invalid)?;
    let source = destination::executable(&directory, &selected.relative_path)?;
    let cwd = destination::cwd(&root, &request.cwd)?;
    let evidence = Evidence {
        credentials,
        executable: identity(&source)?,
        cwd: identity(&cwd)?,
    };
    let mut writer = FrameWriter::private_rights(
        &serde_json::to_vec(&evidence)?,
        vec![source.into(), cwd.into()],
        Instant::now(),
    )?;
    while !writer.write(socket.as_raw_fd(), Instant::now())? {
        pause(socket.as_raw_fd(), libc::POLLOUT);
    }
    Ok(())
}
