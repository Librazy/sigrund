//! Coordinator-owned registration barrier for off-loop clone completion.
//!
//! A pending clone blocks P_ALL sweeps, while registered primary pidfds remain
//! serviceable. Completing a clone requires a deferred sweep before the next
//! reservation. Request execution wires these operations in Phase 5C.
use std::{
    collections::HashMap,
    io,
    os::fd::{AsRawFd, OwnedFd},
};

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
}

impl Reaper {
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
            match wait(libc::P_PIDFD, pidfd.as_raw_fd() as u32) {
                Ok(Some(info)) => {
                    exits.push(ChildExit {
                        pid,
                        token: Some(*token),
                        code: info.si_code,
                        status: unsafe { info.si_status() },
                    });
                    self.primaries.remove(&pid);
                }
                Ok(None) => (),
                Err(error) => return Err(ReapError { exits, error }),
            }
        }
        if self.pending.is_some() {
            return Ok(exits);
        }
        // A bounded sweep cannot monopolize socket deadlines. Keep admission
        // closed until a later dispatch finishes the remaining deferred work.
        self.needs_sweep = true;
        for _ in 0..256 {
            match wait(libc::P_ALL, 0) {
                Ok(Some(info)) => {
                    let pid = unsafe { info.si_pid() };
                    let token = self.primaries.remove(&pid).map(|(token, _)| token);
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
    pub fn sweep_required(&self) -> bool {
        self.needs_sweep
    }
}
fn wait(kind: libc::idtype_t, id: libc::id_t) -> io::Result<Option<libc::siginfo_t>> {
    loop {
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        if unsafe { libc::waitid(kind, id, &mut info, libc::WEXITED | libc::WNOHANG) } == 0 {
            return Ok((unsafe { info.si_pid() } != 0).then_some(info));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
