//! A continuous read lease protects an online approval until exec write exclusion.
use crate::transport::invalid;
use sigrund_core::executable::ExecutableTrust;
use std::{
    fs::File,
    io,
    os::fd::AsRawFd,
    sync::atomic::{AtomicU8, Ordering},
    time::{Duration, Instant},
};

const HELD: u8 = 0;
const INVALID: u8 = 1;
const EXEC_PROTECTED: u8 = 2;

pub(crate) struct CtimeGuard {
    // The duplicate shares the source's open file description and owns cleanup
    // even if preparation fails before the Executable takes ownership.
    file: File,
    state: AtomicU8,
}

impl CtimeGuard {
    pub(crate) fn acquire(
        source: &File,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Option<Self>> {
        let file = source.try_clone()?;
        // SIGIO is blocked in every daemon thread and consumed by SignalSource.
        // Notification is only a wakeup: F_GETLEASE also detects pending breaks
        // and forced revocation when notifications coalesce or are delayed.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETOWN, libc::getpid()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let deadline = Instant::now() + Duration::from_millis(250);
        loop {
            check()?;
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_RDLCK) } == 0 {
                return Ok(Some(Self {
                    file,
                    state: AtomicU8::new(HELD),
                }));
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EAGAIN) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        check()?;
                        return Ok(None);
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(10)));
                }
                Some(libc::EINTR) => {
                    if Instant::now() >= deadline {
                        check()?;
                        return Ok(None);
                    }
                }
                Some(
                    libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP | libc::EPERM | libc::EACCES,
                ) => {
                    return Ok(None);
                }
                _ => return Err(error),
            }
        }
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        match self.state.load(Ordering::Acquire) {
            EXEC_PROTECTED => return Ok(()),
            INVALID => return Err(invalid("ctime read lease was invalidated")),
            HELD => (),
            _ => unreachable!(),
        }
        let observed = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETLEASE) };
        if observed != libc::F_RDLCK {
            self.state.store(INVALID, Ordering::Release);
            return Err(invalid("ctime read lease broken, revoked or unavailable"));
        }
        Ok(())
    }

    pub(crate) fn establish(
        &self,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<ExecutableTrust> {
        check()?;
        self.check()?;
        let before = self.fingerprint()?;
        self.file.sync_all()?;
        let after = self.fingerprint()?;
        self.check()?;
        check()?;
        if before != after {
            return Err(invalid("ctime executable changed during synchronization"));
        }
        Ok(after)
    }

    fn fingerprint(&self) -> io::Result<ExecutableTrust> {
        let mut stat: libc::statx = unsafe { std::mem::zeroed() };
        let required = libc::STATX_INO | libc::STATX_SIZE | libc::STATX_CTIME;
        if unsafe {
            libc::statx(
                self.file.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_STATX_FORCE_SYNC,
                required,
                &mut stat,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if stat.stx_mask & required != required {
            return Err(invalid("incomplete ctime executable statx evidence"));
        }
        Ok(ExecutableTrust::Ctime {
            device: libc::makedev(stat.stx_dev_major, stat.stx_dev_minor).to_string(),
            inode: stat.stx_ino.to_string(),
            size: stat.stx_size.to_string(),
            ctime_sec: stat.stx_ctime.tv_sec,
            ctime_nsec: stat.stx_ctime.tv_nsec,
        })
    }

    /// Only after successful inode, metadata and credential checks at exec stop.
    pub(crate) fn handoff_to_exec(&self) -> io::Result<()> {
        self.check()?;
        if self.state.load(Ordering::Acquire) != HELD {
            return Err(invalid("ctime lease already handed off"));
        }
        if unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_SETLEASE, libc::F_UNLCK) } < 0 {
            self.state.store(INVALID, Ordering::Release);
            return Err(io::Error::last_os_error());
        }
        self.state.store(EXEC_PROTECTED, Ordering::Release);
        Ok(())
    }
}

impl Drop for CtimeGuard {
    fn drop(&mut self) {
        // Always run on the owning worker. Closing the last reference also
        // releases the lease if explicit unlocking fails.
        unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_SETLEASE, libc::F_UNLCK) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::OpenOptions,
        os::unix::{fs::OpenOptionsExt, process::CommandExt},
        process::Command,
    };

    #[test]
    fn lease_lifecycle() {
        // Isolate process-directed SIGIO and its mask from the test harness.
        let mut command = Command::new(std::env::current_exe().unwrap());
        // The mask must precede the harness's own thread creation too.
        unsafe {
            command.pre_exec(|| {
                let mut mask = std::mem::zeroed();
                libc::sigemptyset(&mut mask);
                libc::sigaddset(&mut mask, libc::SIGIO);
                let result = libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());
                if result == 0 {
                    Ok(())
                } else {
                    Err(io::Error::from_raw_os_error(result))
                }
            });
        }
        let output = command
            .args([
                "--exact",
                "ctime_guard::tests::lease_lifecycle_fixture",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "invoked in a separate process with SIGIO blocked"]
    fn lease_lifecycle_fixture() {
        unsafe {
            let mut mask = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGIO);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()),
                0
            );
        }
        let directory = tempfile::tempdir().unwrap();
        let data_directory = tempfile::tempdir_in("/dev/shm").unwrap();
        let path = data_directory.path().join("file");
        std::fs::write(&path, [0u8; 4096]).unwrap();
        let source = File::open(&path).unwrap();

        // A mapping retains write access after its original descriptor closes.
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                writer.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        drop(writer);
        let started = Instant::now();
        assert!(CtimeGuard::acquire(&source, &|| Ok(())).unwrap().is_none());
        assert!(started.elapsed() >= Duration::from_millis(250));
        let calls = std::cell::Cell::new(0);
        let error = CtimeGuard::acquire(&source, &|| {
            calls.set(calls.get() + 1);
            if calls.get() >= 3 {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);

        // Two stores to the same writable page can share one timestamp, and
        // neither unmap nor a later guarded fsync reconstructs that history.
        unsafe { mapping.cast::<u8>().write_volatile(65) };
        let baseline = source.metadata().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        unsafe { mapping.cast::<u8>().write_volatile(66) };
        assert_eq!(unsafe { libc::munmap(mapping, 4096) }, 0);
        let guard = CtimeGuard::acquire(&source, &|| Ok(())).unwrap().unwrap();
        let evidence = guard.establish(&|| Ok(())).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            evidence,
            ExecutableTrust::Ctime {
                device: baseline.dev().to_string(),
                inode: baseline.ino().to_string(),
                size: baseline.len().to_string(),
                ctime_sec: baseline.ctime(),
                ctime_nsec: baseline.ctime_nsec() as u32,
            }
        );
        assert_eq!(std::fs::read(&path).unwrap()[0], 66);

        // Independent read leases coexist. A break request invalidates both
        // without changing bytes, even though SIGIO remains unconsumed.
        let other_source = File::open(&path).unwrap();
        let other = CtimeGuard::acquire(&other_source, &|| Ok(()))
            .unwrap()
            .unwrap();
        guard.check().unwrap();
        other.check().unwrap();
        let error = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EWOULDBLOCK));
        assert!(guard.check().is_err());
        assert!(other.check().is_err());
        assert_eq!(guard.fingerprint().unwrap(), evidence);
        drop(guard);
        drop(other);
        drop(OpenOptions::new().write(true).open(&path).unwrap());

        // A cancelled/expired lease cannot be restored by reacquisition.
        let guard = CtimeGuard::acquire(&source, &|| Ok(())).unwrap().unwrap();
        assert_eq!(
            unsafe { libc::fcntl(source.as_raw_fd(), libc::F_SETLEASE, libc::F_UNLCK) },
            0
        );
        assert!(guard.check().is_err());
        assert_eq!(
            unsafe { libc::fcntl(source.as_raw_fd(), libc::F_SETLEASE, libc::F_RDLCK) },
            0
        );
        assert!(guard.check().is_err());
        drop(guard);

        // Contention can resolve within the retry budget, and cleanup unblocks
        // writers even when the original read-only source stays open.
        let writer = OpenOptions::new().write(true).open(&path).unwrap();
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            drop(writer);
        });
        let guard = CtimeGuard::acquire(&source, &|| Ok(())).unwrap().unwrap();
        thread.join().unwrap();
        drop(guard);
        drop(OpenOptions::new().write(true).open(&path).unwrap());

        // A real exec supplies write exclusion before lease release.
        let program = directory.path().join("sleep");
        std::fs::copy("/bin/sleep", &program).unwrap();
        let executable = File::open(&program).unwrap();
        let guard = CtimeGuard::acquire(&executable, &|| Ok(()))
            .unwrap()
            .unwrap();
        let mut child = Command::new(&program).arg("30").spawn().unwrap();
        guard.handoff_to_exec().unwrap();
        guard.check().unwrap();
        let result = OpenOptions::new().write(true).open(&program);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ETXTBSY));
        assert!(guard.handoff_to_exec().is_err());
        drop(OpenOptions::new().write(true).open(&program).unwrap());
    }
}
