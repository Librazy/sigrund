//! Coordinator-owned registration barrier for off-loop clone completion.
//!
//! A pending clone blocks P_ALL sweeps, while registered primary pidfds remain
//! serviceable. Completing a clone requires a deferred sweep before the next
//! reservation. The runtime coordinator owns this barrier for every job clone.
use std::{
    collections::HashMap,
    io,
    os::fd::{AsRawFd, OwnedFd},
};

// A fresh-exec access helper is waited by its reserved I/O task. Prevent P_ALL
// from stealing its exit between spawn and registration or while it is alive.
static HELPERS: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
pub(crate) struct HelperGuard;
impl HelperGuard {
    pub fn new() -> Self {
        *HELPERS.lock().expect("helper registry") += 1;
        Self
    }
}
impl Drop for HelperGuard {
    fn drop(&mut self) {
        *HELPERS.lock().expect("helper registry") -= 1;
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ChildExit {
    pub pid: libc::pid_t,
    pub token: Option<u64>,
    pub code: i32,
    pub status: i32,
}

#[derive(Debug)]
pub struct ReapError {
    pub exits: Vec<ChildExit>,
    pub error: io::Error,
}
impl std::fmt::Display for ReapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for ReapError {}

#[derive(Default)]
pub struct Reaper {
    pending: Option<u64>,
    needs_sweep: bool,
    primaries: HashMap<libc::pid_t, (u64, OwnedFd)>,
    launchers: HashMap<libc::pid_t, (u64, OwnedFd)>,
    launcher_exits: Vec<ChildExit>,
    traced: std::collections::HashSet<libc::pid_t>,
    stops: Vec<ChildExit>,
}

impl Reaper {
    pub fn complete_launcher(&mut self, token: u64, pid: i32, pidfd: OwnedFd) {
        assert!(
            pid > 0 && !self.launchers.contains_key(&pid) && !self.primaries.contains_key(&pid)
        );
        assert!(self.complete(token, None).is_ok());
        self.launchers.insert(pid, (token, pidfd));
    }
    pub fn take_launcher_exits(&mut self) -> Vec<ChildExit> {
        std::mem::take(&mut self.launcher_exits)
    }
    pub fn traced(&mut self, pid: libc::pid_t) {
        self.traced.insert(pid);
    }
    pub fn detached(&mut self, pid: libc::pid_t) {
        self.traced.remove(&pid);
    }
    pub fn take_stops(&mut self) -> Vec<ChildExit> {
        std::mem::take(&mut self.stops)
    }
    pub fn reserve(&mut self, token: u64) -> bool {
        if self.pending.is_some() || self.needs_sweep {
            return false;
        }
        self.pending = Some(token);
        true
    }

    /// Register a returned child before clearing its pending context. A clone
    /// error calls this with None only after confirming no child was returned.
    /// An invalid completion returns descriptor ownership to the caller.
    pub fn complete(
        &mut self,
        token: u64,
        child: Option<(libc::pid_t, OwnedFd)>,
    ) -> Result<(), Option<(libc::pid_t, OwnedFd)>> {
        if self.pending != Some(token)
            || child
                .as_ref()
                .is_some_and(|(pid, _)| *pid <= 0 || self.primaries.contains_key(pid))
        {
            return Err(child);
        }
        if let Some((pid, pidfd)) = child {
            self.primaries.insert(pid, (token, pidfd));
        }
        self.pending = None;
        self.needs_sweep = true;
        Ok(())
    }

    /// The coordinator consumes every returned status exactly once. Known
    /// primaries use P_PIDFD even while a different clone result is pending.
    /// This method is the only P_ALL entrypoint after startup.
    pub fn poll(&mut self) -> Result<Vec<ChildExit>, ReapError> {
        let mut exits = Vec::new();
        let pids: Vec<_> = self.primaries.keys().copied().collect();
        for pid in pids {
            let (token, pidfd) = &self.primaries[&pid];
            match wait(
                libc::P_PIDFD,
                pidfd.as_raw_fd() as u32,
                self.traced.contains(&pid),
            ) {
                Ok(Some(info)) => {
                    if matches!(info.si_code, libc::CLD_TRAPPED | libc::CLD_STOPPED) {
                        self.stops.push(ChildExit {
                            pid,
                            token: Some(*token),
                            code: info.si_code,
                            status: unsafe { info.si_status() },
                        });
                        continue;
                    }
                    exits.push(ChildExit {
                        pid,
                        token: Some(*token),
                        code: info.si_code,
                        status: unsafe { info.si_status() },
                    });
                    self.primaries.remove(&pid);
                    self.traced.remove(&pid);
                }
                Ok(None) => (),
                Err(error) => return Err(ReapError { exits, error }),
            }
        }
        let launchers: Vec<_> = self.launchers.keys().copied().collect();
        for pid in launchers {
            let (token, fd) = &self.launchers[&pid];
            match wait(libc::P_PIDFD, fd.as_raw_fd() as u32, true) {
                Ok(Some(info)) => {
                    if matches!(info.si_code, libc::CLD_TRAPPED | libc::CLD_STOPPED) {
                        // A protected launcher has no expected ptrace stops.
                        // Keep its pidfd registered until actual terminal exit.
                        unsafe {
                            libc::syscall(
                                libc::SYS_pidfd_send_signal,
                                fd.as_raw_fd(),
                                libc::SIGKILL,
                                0,
                                0,
                            );
                        }
                        continue;
                    }
                    self.launcher_exits.push(ChildExit {
                        pid,
                        token: Some(*token),
                        code: info.si_code,
                        status: unsafe { info.si_status() },
                    });
                    self.launchers.remove(&pid);
                }
                Ok(None) => (),
                Err(error) => return Err(ReapError { exits, error }),
            }
        }
        let helpers = HELPERS.lock().expect("helper registry");
        if *helpers != 0 || self.pending.is_some() {
            return Ok(exits);
        }
        // A bounded sweep cannot monopolize socket deadlines. Keep admission
        // closed until a later dispatch finishes the remaining deferred work.
        self.needs_sweep = true;
        for _ in 0..256 {
            match wait(libc::P_ALL, 0, false) {
                Ok(Some(info)) => {
                    let pid = unsafe { info.si_pid() };
                    // ptrace stops can be returned by P_ALL even without
                    // WSTOPPED. An exec event may arrive between the pidfd
                    // pass and this sweep: never retire its live owner.
                    if matches!(info.si_code, libc::CLD_TRAPPED | libc::CLD_STOPPED) {
                        if let Some((_, fd)) = self.launchers.get(&pid) {
                            unsafe {
                                libc::syscall(
                                    libc::SYS_pidfd_send_signal,
                                    fd.as_raw_fd(),
                                    libc::SIGKILL,
                                    0,
                                    0,
                                );
                            }
                            continue;
                        }
                        self.stops.push(ChildExit {
                            pid,
                            token: self.primaries.get(&pid).map(|(token, _)| *token),
                            code: info.si_code,
                            status: unsafe { info.si_status() },
                        });
                        continue;
                    }
                    if let Some((token, _)) = self.launchers.remove(&pid) {
                        self.launcher_exits.push(ChildExit {
                            pid,
                            token: Some(token),
                            code: info.si_code,
                            status: unsafe { info.si_status() },
                        });
                        continue;
                    }
                    let token = self.primaries.remove(&pid).map(|(token, _)| token);
                    self.traced.remove(&pid);
                    exits.push(ChildExit {
                        pid,
                        token,
                        code: info.si_code,
                        status: unsafe { info.si_status() },
                    });
                }
                Ok(None) => {
                    self.needs_sweep = false;
                    break;
                }
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                    self.needs_sweep = false;
                    break;
                }
                Err(error) => return Err(ReapError { exits, error }),
            }
        }
        Ok(exits)
    }
    pub fn registered_fd(&self, pid: libc::pid_t) -> Option<i32> {
        self.primaries.get(&pid).map(|(_, fd)| fd.as_raw_fd())
    }
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
    pub fn is_idle(&self) -> bool {
        self.pending.is_none()
            && self.primaries.is_empty()
            && self.launchers.is_empty()
            && !self.needs_sweep
    }
    pub fn sweep_required(&self) -> bool {
        self.needs_sweep
    }
}
fn wait(
    kind: libc::idtype_t,
    id: libc::id_t,
    stopped: bool,
) -> io::Result<Option<libc::siginfo_t>> {
    loop {
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        if unsafe {
            libc::waitid(
                kind,
                id,
                &mut info,
                libc::WEXITED
                    | libc::WNOHANG
                    | if stopped {
                        libc::WSTOPPED | libc::__WALL
                    } else {
                        0
                    },
            )
        } == 0
        {
            return Ok((unsafe { info.si_pid() } != 0).then_some(info));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
