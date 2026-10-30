use std::{
    fs::File,
    io::{self, Write},
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
    let mut name_bytes = name.as_bytes().to_vec();
    name_bytes.push(0);
    let flags = MFD_CLOEXEC | MFD_ALLOW_SEALING | if executable { MFD_EXEC } else { 0 };
    let raw_fd =
        unsafe { libc::syscall(libc::SYS_memfd_create, name_bytes.as_ptr(), flags) as libc::c_int };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Keep a single owner on every error path, including failed writes/seals.
    let mut file = unsafe { File::from_raw_fd(raw_fd) };
    file.write_all(bytes)?;
    file.sync_all()?;
    let fd: OwnedFd = file.into();
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
}
