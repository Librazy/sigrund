use std::{
    ffi::CString,
    io,
    os::fd::{FromRawFd, OwnedFd, RawFd},
    path::Path,
};

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

pub fn validate_absolute_path(path: &Path) -> io::Result<()> {
    let raw = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not UTF-8"))?;
    if !raw.starts_with('/')
        || raw.contains('\0')
        || (raw != "/"
            && raw[1..]
                .split('/')
                .any(|part| matches!(part, "" | "." | "..")))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be canonical absolute text",
        ));
    }
    Ok(())
}

pub fn openat2_root(root_fd: RawFd, relative_path: &Path) -> io::Result<OwnedFd> {
    open_relative(
        root_fd,
        relative_path,
        libc::O_PATH | libc::O_DIRECTORY,
        false,
    )
}

/// Read a configured file without following links, permitting mount crossing.
pub fn openat2_file(root_fd: RawFd, relative_path: &Path) -> io::Result<OwnedFd> {
    open_relative(
        root_fd,
        relative_path,
        libc::O_RDONLY | libc::O_NONBLOCK,
        false,
    )
}

/// Executable sources are resolved beneath a pinned directory, on its mount.
pub fn openat2_executable(root_fd: RawFd, relative_path: &Path) -> io::Result<OwnedFd> {
    open_relative(
        root_fd,
        relative_path,
        libc::O_RDONLY | libc::O_NONBLOCK,
        true,
    )
}

fn open_relative(
    root_fd: RawFd,
    relative_path: &Path,
    flags: i32,
    no_xdev: bool,
) -> io::Result<OwnedFd> {
    let text = relative_path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "relative path is not UTF-8"))?;
    if text.is_empty()
        || text.starts_with('/')
        || text
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe relative path",
        ));
    }
    let path = CString::new(text)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        // Root pinning must cross mount boundaries (for example a separate
        // /usr mount). NO_XDEV is reserved for executable-relative opens.
        resolve: RESOLVE_BENEATH
            | RESOLVE_NO_SYMLINKS
            | RESOLVE_NO_MAGICLINKS
            | if no_xdev { 0x01 } else { 0 },
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        ) as libc::c_int
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
