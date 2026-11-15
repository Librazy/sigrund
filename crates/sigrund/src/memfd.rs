use std::{
    fs::File,
    io::{self, Seek, SeekFrom, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const MFD_CLOEXEC: libc::c_uint = 0x0001;
const MFD_ALLOW_SEALING: libc::c_uint = 0x0002;
const MFD_EXEC: libc::c_uint = 0x0010;
const F_ADD_SEALS: libc::c_int = 1033;
const F_GET_SEALS: libc::c_int = 1034;
const F_SEAL_SEAL: libc::c_int = 0x0001;
const F_SEAL_SHRINK: libc::c_int = 0x0002;
const F_SEAL_GROW: libc::c_int = 0x0004;
const F_SEAL_WRITE: libc::c_int = 0x0008;
const F_SEAL_FUTURE_WRITE: libc::c_int = 0x0010;

pub fn create_sealed(
    name: &str,
    bytes: &[u8],
    executable: bool,
    mode: libc::mode_t,
) -> io::Result<OwnedFd> {
    let mut file = create(name, executable)?;
    file.write_all(bytes)?;
    seal(file, mode)
}

pub(crate) fn create(name: &str, executable: bool) -> io::Result<File> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in memfd name"))?;
    let flags = MFD_CLOEXEC | MFD_ALLOW_SEALING | if executable { MFD_EXEC } else { 0 };
    let raw = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) as libc::c_int };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}

pub(crate) fn seal(mut file: File, mode: libc::mode_t) -> io::Result<OwnedFd> {
    file.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    let fd: OwnedFd = file.into();
    if unsafe { libc::fchown(fd.as_raw_fd(), libc::geteuid(), libc::getegid()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fchmod(fd.as_raw_fd(), mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;
    if unsafe { libc::fcntl(fd.as_raw_fd(), F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let actual = unsafe { libc::fcntl(fd.as_raw_fd(), F_GET_SEALS) };
    if actual < 0 || actual & seals != seals {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "kernel did not install all memfd seals",
        ));
    }
    Ok(fd)
}

/// Send finite input with read-only descriptor authority as well as inode seals.
/// chmod and F_SEAL_WRITE do not clear FMODE_WRITE on the original memfd, so
/// SELinux would still require write access when another domain receives it.
pub(crate) fn seal_input(file: File) -> io::Result<OwnedFd> {
    let sealed = seal(file, 0o400)?;
    // The live descriptor pins this procfd link to the sealed inode. Reopening
    // creates an O_RDONLY description; dup would retain the original O_RDWR.
    Ok(File::open(format!("/proc/self/fd/{}", sealed.as_raw_fd()))?.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};

    #[test]
    fn executable_memfd_uses_normal_pages_and_rejects_writes() {
        let fd = create_sealed("executable-test", b"\x7fELFsmall-payload", true, 0o111).unwrap();
        let mut file = File::from(fd);
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"\x7fELFsmall-payload");
        assert_eq!(
            file.write(b"x").unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(MFD_EXEC, libc::MFD_EXEC);
    }

    #[test]
    fn sealed_input_is_read_only_and_retains_content_and_seals() {
        use std::os::unix::fs::MetadataExt;

        for bytes in [b"".as_slice(), b"finite input\0with binary bytes\xff"] {
            let mut source = create("input-test", false).unwrap();
            source.write_all(bytes).unwrap();
            let inode = source.metadata().unwrap().ino();
            let fd = seal_input(source).unwrap();
            assert_eq!(
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
                libc::O_RDONLY
            );
            assert_ne!(
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            let seals =
                F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;
            assert_eq!(
                unsafe { libc::fcntl(fd.as_raw_fd(), F_GET_SEALS) } & seals,
                seals
            );
            let mut input = File::from(fd);
            assert_eq!(input.metadata().unwrap().ino(), inode);
            assert_eq!(input.metadata().unwrap().mode() & 0o777, 0o400);
            let mut observed = Vec::new();
            input.read_to_end(&mut observed).unwrap();
            assert_eq!(observed, bytes);
            assert_eq!(
                input.write(b"x").unwrap_err().raw_os_error(),
                Some(libc::EBADF)
            );
        }
    }
}
