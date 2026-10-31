use sigrund::{
    linux::{openat2_executable, openat2_root},
    startup::pin_directory,
};
use std::{os::fd::AsRawFd, path::Path};

#[test]
fn directory_pinning_and_executable_resolution_have_distinct_flags() {
    let root = pin_directory(Path::new("/")).unwrap();
    let proc = openat2_root(root.as_raw_fd(), Path::new("proc")).unwrap();
    let flags = unsafe { libc::fcntl(proc.as_raw_fd(), libc::F_GETFL) };
    assert_ne!(flags & libc::O_PATH, 0);
    assert_ne!(flags & libc::O_DIRECTORY, 0);
    assert_ne!(
        unsafe { libc::fcntl(proc.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    // /proc is an actual mount crossing; pinning permits it, relative executable
    // resolution does not. This needs no privileged mount or host modification.
    assert_eq!(
        openat2_executable(root.as_raw_fd(), Path::new("proc/version"))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("regular"), b"ELF").unwrap();
    assert_eq!(
        pin_directory(&temp.path().join("regular"))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOTDIR)
    );
    std::os::unix::fs::symlink("regular", temp.path().join("link")).unwrap();
    let pinned = pin_directory(temp.path()).unwrap();
    let file = openat2_executable(pinned.as_raw_fd(), Path::new("regular")).unwrap();
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } & libc::O_PATH,
        0
    );
    assert_eq!(
        openat2_executable(pinned.as_raw_fd(), Path::new("link"))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ELOOP)
    );
    for path in ["", "/regular", "./regular", "../regular", "x//regular"] {
        assert!(openat2_executable(pinned.as_raw_fd(), Path::new(path)).is_err());
    }
}
