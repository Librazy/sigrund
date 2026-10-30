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

pub fn openat2_root(root_fd: RawFd, relative_path: &Path) -> io::Result<OwnedFd> {
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
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) as u64,
        mode: 0,
        // Root pinning must cross mount boundaries (for example a separate
        // /usr mount). NO_XDEV is reserved for executable-relative opens.
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
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
