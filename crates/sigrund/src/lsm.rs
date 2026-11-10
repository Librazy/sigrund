//! Host-owned SELinux policy dependency; hot-path checks perform no filesystem I/O.
use sigrund_core::namespace::Constraints;
use std::{
    ffi::CString,
    io,
    os::fd::{AsFd, AsRawFd},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

pub(crate) const DAEMON_CONTEXT: &str = "system_u:system_r:sigrund_daemon_t:s0";
pub(crate) const REQUESTER_CONTEXT: &str = "system_u:system_r:sigrund_requester_t:s0";
pub(crate) const HOST_WORKLOAD_CONTEXT: &str = "system_u:system_r:sigrund_host_workload_t:s0";
static PRODUCER: AtomicBool = AtomicBool::new(false);
pub(crate) fn producer_active() -> bool {
    PRODUCER.load(Ordering::Acquire)
}
unsafe extern "C" {
    fn sigrund_probe_namespace_filter() -> i32;
    fn sigrund_verify_namespace_filter(pid: i32) -> i32;
    fn sigrund_lsm_allowed(
        source: *const libc::c_char,
        target: *const libc::c_char,
        class: *const libc::c_char,
        permissions: *const libc::c_char,
    ) -> i32;
    fn sigrund_domain_enforcing(context: *const libc::c_char) -> i32;
    fn sigrund_policy_map() -> *mut libc::c_void;
    fn sigrund_policy_token(page: *const u32, token: *mut u64) -> i32;
}
static POLICY: OnceLock<Arc<PolicyGuard>> = OnceLock::new();
pub(crate) struct PolicyGuard {
    page: usize,
    token: u64,
}
impl Drop for PolicyGuard {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.page as *mut _, 4096);
        }
    }
}
impl PolicyGuard {
    fn open(context: &str) -> io::Result<Self> {
        let page = unsafe { sigrund_policy_map() };
        if page == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let mut guard = Self {
            page: page as usize,
            token: 0,
        };
        guard.token = guard.current()?;
        guard.verify_domain(context)?;
        Ok(guard)
    }
    fn current(&self) -> io::Result<u64> {
        let mut token = 0;
        if unsafe { sigrund_policy_token(self.page as *const _, &mut token) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(token)
    }
    pub fn check(&self) -> io::Result<()> {
        if self.current()? != self.token {
            return Err(io::Error::other(
                "SELinux policy changed; drain and restart required",
            ));
        }
        Ok(())
    }
    pub fn verify_domain(&self, context: &str) -> io::Result<()> {
        self.check()?;
        let context = CString::new(context).map_err(io::Error::other)?;
        if unsafe { sigrund_domain_enforcing(context.as_ptr()) } != 1 {
            return Err(io::Error::other(
                "SELinux domain is unavailable or permissive",
            ));
        }
        self.check()
    }
    pub fn token(&self) -> String {
        format!("{:016x}", self.token)
    }
}
pub(crate) fn startup(profiles: &[Constraints]) -> io::Result<()> {
    let actual = match std::fs::read_to_string("/proc/self/attr/current") {
        Ok(value) => value,
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOENT | libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
            ) =>
        {
            String::new()
        }
        Err(error) => return Err(error),
    };
    let context = actual.trim_end_matches(['\0', '\n']);
    let producer = context.split(':').nth(2) == Some("sigrund_daemon_t");
    if producer {
        if context != DAEMON_CONTEXT {
            return Err(io::Error::other(
                "reserved producer requires its exact packaged SELinux context",
            ));
        }
        let host = PolicyGuard::open(HOST_WORKLOAD_CONTEXT)?;
        host.verify_domain(DAEMON_CONTEXT)?;
        for (class, permissions) in [
            ("process", "transition,ptrace"),
            ("process2", "nnp_transition,nosuid_transition"),
        ] {
            allowed(DAEMON_CONTEXT, HOST_WORKLOAD_CONTEXT, class, permissions)?;
        }
        host.check()?;
    }
    PRODUCER.store(producer, Ordering::Release);
    let Some(profile) = profiles.iter().find(|profile| profile.is_production()) else {
        return Ok(());
    };
    if context != DAEMON_CONTEXT {
        return Err(io::Error::other(
            "production profile requires the packaged daemon SELinux domain",
        ));
    }
    let guard = Arc::new(PolicyGuard::open(&profile.selinux.context)?);
    guard.verify_domain(DAEMON_CONTEXT)?;
    guard.verify_domain(REQUESTER_CONTEXT)?;
    guard.verify_domain(HOST_WORKLOAD_CONTEXT)?;
    for (source, target, class, permissions) in [
        (
            DAEMON_CONTEXT,
            profile.selinux.context.as_str(),
            "process",
            "transition,ptrace",
        ),
        (
            DAEMON_CONTEXT,
            profile.selinux.context.as_str(),
            "process2",
            "nnp_transition,nosuid_transition",
        ),
        (
            profile.selinux.context.as_str(),
            profile.selinux.executable_context.as_deref().unwrap(),
            "file",
            "entrypoint,execute,read,open,map",
        ),
    ] {
        guard.check()?;
        allowed(source, target, class, permissions)?;
        guard.check()?;
    }
    if unsafe { sigrund_probe_namespace_filter() } != 0 {
        return Err(io::Error::other(format!(
            "production seccomp verification unavailable: {}",
            io::Error::last_os_error()
        )));
    }
    POLICY
        .set(guard)
        .map_err(|_| io::Error::other("SELinux epoch already initialized"))
}
fn allowed(source: &str, target: &str, class: &str, permissions: &str) -> io::Result<()> {
    let values = [source, target, class, permissions].map(|value| CString::new(value).unwrap());
    if unsafe {
        sigrund_lsm_allowed(
            values[0].as_ptr(),
            values[1].as_ptr(),
            values[2].as_ptr(),
            values[3].as_ptr(),
        )
    } != 0
    {
        return Err(io::Error::other(
            "SELinux policy does not permit the required traced NNP transition",
        ));
    }
    Ok(())
}
pub(crate) fn for_profile(profile: &Constraints) -> io::Result<Option<Arc<PolicyGuard>>> {
    if !profile.is_production() {
        return Ok(None);
    }
    let guard = POLICY
        .get()
        .ok_or_else(|| io::Error::other("production SELinux dependency is unavailable"))?
        .clone();
    guard.check()?;
    Ok(Some(guard))
}
pub(crate) fn image_label(
    image: impl AsFd,
    profile: &Constraints,
    install: bool,
) -> io::Result<()> {
    let Some(label) = &profile.selinux.executable_context else {
        return Ok(());
    };
    let fd = image.as_fd().as_raw_fd();
    let expected = CString::new(label.as_str()).map_err(io::Error::other)?;
    if install
        && unsafe {
            libc::fsetxattr(
                fd,
                c"security.selinux".as_ptr(),
                expected.as_ptr().cast(),
                expected.as_bytes_with_nul().len(),
                0,
            )
        } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut observed = [0u8; 4096];
    let length = unsafe {
        libc::fgetxattr(
            fd,
            c"security.selinux".as_ptr(),
            observed.as_mut_ptr().cast(),
            observed.len(),
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    let actual = observed[..length as usize]
        .strip_suffix(&[0])
        .unwrap_or(&observed[..length as usize]);
    if actual != expected.as_bytes() {
        return Err(io::Error::other("sealed executable SELinux label differs"));
    }
    Ok(())
}

/// Only the coordinator thread owns the ptrace relationship. This syscall is
/// bounded kernel inspection, with no target filesystem access.
pub(crate) fn verify_filter(pid: i32) -> io::Result<()> {
    if unsafe { sigrund_verify_namespace_filter(pid) } != 0 {
        return Err(io::Error::other(
            "final child seccomp program differs from the approved production profile",
        ));
    }
    Ok(())
}

/// A thread-scoped sockcreate label is cleared before any other socket can be
/// created. Failure to restore it aborts listener publication, closing the FD.
pub(crate) fn public_socket(role: crate::client::PeerRole) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    unsafe extern "C" {
        fn sigrund_socket_label(context: *const libc::c_char) -> i32;
    }
    let labeled = if let Some(guard) = POLICY.get() {
        guard.check()?;
        let label = match role {
            crate::client::PeerRole::Execution => {
                c"system_u:object_r:sigrund_execution_socket_t:s0"
            }
            crate::client::PeerRole::Context => c"system_u:object_r:sigrund_context_socket_t:s0",
            crate::client::PeerRole::Anchor => c"system_u:object_r:sigrund_anchor_socket_t:s0",
            crate::client::PeerRole::HostOnly => {
                return Err(io::Error::other(
                    "administrative endpoint cannot use a public label",
                ));
            }
        };
        if unsafe { sigrund_socket_label(label.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        true
    } else {
        false
    };
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    let error = io::Error::last_os_error();
    let fd = (raw >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) });
    if labeled && unsafe { sigrund_socket_label(std::ptr::null()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    fd.ok_or(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_dependency_rejects_reload_permissive_and_unstable_status() {
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        let words = page.cast::<u32>();
        for (index, value) in [1, 2, 1, 3, 0].into_iter().enumerate() {
            unsafe {
                words.add(index).write(value);
            }
        }
        let guard = PolicyGuard {
            page: page as usize,
            token: (2u64 << 32) | 3,
        };
        guard.check().unwrap();
        assert_eq!(guard.token(), "0000000200000003");
        for (index, changed, original) in [(3, 4, 3), (1, 4, 2), (2, 0, 1), (0, 2, 1), (1, 3, 2)] {
            unsafe {
                words.add(index).write(changed);
            }
            assert!(guard.check().is_err());
            unsafe {
                words.add(index).write(original);
            }
            guard.check().unwrap();
        }
    }
}
