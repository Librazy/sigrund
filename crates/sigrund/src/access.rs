//! Fresh-exec, requester-credential file opening. Private IPC carries only one
//! request and one retained readable FD. No daemon directory FD or secret crosses exec.
use crate::{
    linux,
    transport::{self, ControlReader, FrameWriter},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::MetadataExt, net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    root: String,
    relative: String,
    device: u64,
    inode: u64,
}
impl sigrund_core::protocol::ProtocolSchema for Request {}
fn pause(fd: i32, events: i16) -> io::Result<()> {
    let mut p = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    if unsafe { libc::poll(&mut p, 1, 10) } < 0
        && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn domain() -> io::Result<()> {
    // A credential change must never enable same-UID tracing before the final
    // PR_SET_DUMPABLE(0). Both SUID_DUMP_DISABLE (0) and SUID_DUMP_ROOT (2)
    // reject unprivileged ptrace access; SUID_DUMP_USER (1) is unsafe.
    // User namespace mappings must be exact.
    if !matches!(
        std::fs::read_to_string("/proc/sys/fs/suid_dumpable")?.trim(),
        "0" | "2"
    ) || std::fs::read_to_string("/proc/self/uid_map")?
        .split_whitespace()
        .collect::<Vec<_>>()
        != ["0", "0", "4294967295"]
        || std::fs::read_to_string("/proc/self/gid_map")?
            .split_whitespace()
            .collect::<Vec<_>>()
            != ["0", "0", "4294967295"]
    {
        return Err(transport::invalid("unsupported requester access domain"));
    }
    Ok(())
}
pub(crate) fn open(
    root: &Path,
    relative: &Path,
    identity: &crate::preparation::FileIdentity,
    uid: u32,
    gid: u32,
    groups: &[u32],
    check: impl Fn() -> io::Result<()>,
) -> io::Result<File> {
    check()?;
    domain()?;
    if groups.len() > 256 {
        return Err(transport::invalid("requester groups exceed helper bound"));
    }
    let request = Request {
        uid,
        gid,
        groups: groups.to_vec(),
        root: root
            .to_str()
            .ok_or_else(|| transport::invalid("non-UTF8 root"))?
            .into(),
        relative: relative
            .to_str()
            .ok_or_else(|| transport::invalid("non-UTF8 path"))?
            .into(),
        device: identity.device,
        inode: identity.inode,
    };
    let (parent, child) = UnixStream::pair()?;
    parent.set_nonblocking(true)?;
    // Duplicate away from stdio/IPC positions before the syscall-only pre_exec.
    let raw = unsafe { libc::fcntl(child.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let inherited = unsafe { OwnedFd::from_raw_fd(raw) };
    let _registration = crate::reaper::HelperGuard::new();
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--internal-access-helper")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(raw, 3) < 0
                || libc::syscall(
                    libc::SYS_close_range,
                    4u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut helper = command.spawn()?;
    drop(inherited);
    drop(child);
    let result = (|| {
        let mut writer = FrameWriter::control(
            sigrund_core::framing::FrameType::ClientHello,
            &serde_json::to_vec(&request)?,
            Instant::now(),
        )?;
        while !writer.write(parent.as_raw_fd(), Instant::now())? {
            check()?;
            pause(parent.as_raw_fd(), libc::POLLOUT)?;
        }
        let mut reader = ControlReader::new(true);
        loop {
            check()?;
            if let Some(mut frame) = reader.read(parent.as_raw_fd(), Instant::now())? {
                if frame.payload != b"{}" || frame.rights.len() != 1 {
                    return Err(transport::invalid("invalid access helper result"));
                }
                let source: File = frame.rights.remove(0).into();
                if !source.metadata()?.is_file() {
                    return Err(transport::invalid("access helper returned nonregular file"));
                }
                return Ok(source);
            }
            pause(parent.as_raw_fd(), libc::POLLIN)?;
        }
    })();
    // ChildExit belongs to this reserved task, not the daemon's P_ALL sweep.
    // Kill/reap even on cancelled, malformed, or disconnected helper paths.
    let _ = helper.kill();
    let status = helper.wait();
    check()?;
    status?;
    result
}

/// Internal entrypoint, before daemon configuration, secrets, threads or listeners.
pub fn helper_main() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    domain()?;
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { UnixStream::from_raw_fd(3) };
    socket.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut reader = ControlReader::new(true);
    let frame = loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if let Some(frame) = reader.read(socket.as_raw_fd(), Instant::now())? {
            break frame;
        }
        pause(socket.as_raw_fd(), libc::POLLIN)?;
    };
    if !frame.rights.is_empty() {
        return Err(transport::invalid("unexpected helper input rights"));
    }
    let request: Request = sigrund_core::protocol::parse_strict(&frame.payload)
        .map_err(|e| transport::invalid(e.to_string()))?;
    linux::validate_absolute_path(Path::new(&request.root))?;
    if request.uid == u32::MAX || request.gid == u32::MAX || request.groups.contains(&u32::MAX) {
        return Err(transport::invalid("unmapped identity"));
    }
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x20080522,
        pid: 0,
    };
    let empty = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // Identity transitions reset dumpability to the verified protected system
    // value (0 or 2); clear it explicitly before any requester file access.
    if unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::setgroups(request.groups.len(), request.groups.as_ptr()) != 0
            || libc::setresgid(request.gid, request.gid, request.gid) != 0
            || libc::setresuid(request.uid, request.uid, request.uid) != 0
            || libc::syscall(libc::SYS_capset, &header, empty.as_ptr()) != 0
            || libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
            || libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) != 0
    } {
        return Err(io::Error::last_os_error());
    }
    use std::os::unix::fs::OpenOptionsExt;
    let slash = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open("/")?;
    let root = if request.root == "/" {
        slash.into()
    } else {
        linux::openat2_root(
            slash.as_raw_fd(),
            Path::new(request.root.trim_start_matches('/')),
        )?
    };
    let metadata = File::from(root.try_clone()?).metadata()?;
    if metadata.dev() != request.device || metadata.ino() != request.inode {
        return Err(transport::invalid("requester root identity mismatch"));
    }
    let source = linux::openat2_executable(root.as_raw_fd(), Path::new(&request.relative))?;
    let mut writer = FrameWriter::private_rights(b"{}", vec![source], Instant::now())?;
    while !writer.write(socket.as_raw_fd(), Instant::now())? {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        pause(socket.as_raw_fd(), libc::POLLOUT)?;
    }
    Ok(())
}
