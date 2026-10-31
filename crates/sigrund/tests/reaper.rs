//! This separate test process exclusively owns its children and P_ALL sweeps.
use sigrund::reaper::Reaper;
use std::{
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

fn child(exit: u8) -> (libc::pid_t, OwnedFd, OwnedFd) {
    let mut pipe = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            libc::close(pipe[1]);
            let mut byte = 0u8;
            libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1);
            libc::_exit(exit as i32);
        }
    }
    drop(read);
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(raw >= 0);
    (pid, unsafe { OwnedFd::from_raw_fd(raw as i32) }, write)
}
fn release(gate: OwnedFd) {
    assert_eq!(
        unsafe { libc::write(gate.as_raw_fd(), b"x".as_ptr().cast(), 1) },
        1
    );
}
fn ready(pidfd: &OwnedFd) {
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 2000) }, 1);
}

#[test]
fn unpublished_child_cannot_be_swept_and_known_primary_stays_serviceable() {
    let mut reaper = Reaper::default();
    assert!(reaper.reserve(1));
    let (known, kfd, kgate) = child(17);
    assert!(reaper.complete(1, Some((known, kfd))).is_ok());
    assert!(!reaper.reserve(2));
    assert!(reaper.sweep_required());
    assert!(reaper.poll().unwrap().is_empty());
    assert!(reaper.reserve(2));
    let (unpublished, ufd, ugate) = child(23);
    release(ugate);
    ready(&ufd);
    release(kgate);
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        let statuses = reaper.poll().unwrap();
        if !statuses.is_empty() {
            assert_eq!(statuses.len(), 1);
            break statuses[0];
        }
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    };
    assert_eq!(
        (status.pid, status.token, status.code, status.status),
        (known, Some(1), libc::CLD_EXITED, 17)
    );
    // The pending child must still be waitable: polling known pidfds may not
    // consume it as an orphan even though its SIGCHLD has already arrived.
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                ufd.as_raw_fd() as u32,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        },
        0
    );
    assert_eq!(unsafe { info.si_pid() }, unpublished);
    assert!(!reaper.reserve(3));
    assert!(reaper.complete(2, Some((unpublished, ufd))).is_ok());
    assert!(!reaper.reserve(3));
    let status = reaper.poll().unwrap();
    assert_eq!(status.len(), 1);
    assert_eq!(
        (status[0].pid, status[0].token, status[0].status),
        (unpublished, Some(2), 23)
    );
    assert!(reaper.poll().unwrap().is_empty());
    assert!(reaper.reserve(3));
    assert!(reaper.complete(3, None).is_ok());
    assert!(!reaper.reserve(4));
    assert!(reaper.poll().unwrap().is_empty());
    assert!(reaper.reserve(4));
    assert!(reaper.complete(4, None).is_ok());
    assert!(reaper.poll().unwrap().is_empty());
}
