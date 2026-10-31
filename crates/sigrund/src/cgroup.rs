//! Trusted cgroup filesystem ownership. All methods that touch cgroupfs run
//! before threads/listeners start, or on a bounded off-loop executor.
use crate::{
    startup::{check_root_metadata, open_pinned},
    transport::invalid,
};
use std::{
    ffi::{CStr, CString},
    fs::{self, File},
    io::{self, Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

#[derive(Debug)]
struct Directories {
    root: File,
    jobs: File,
    hooks: File,
}
#[derive(Clone, Debug)]
pub struct CgroupLayout {
    pub root: PathBuf,
    pub supervisor: PathBuf,
    pub jobs: PathBuf,
    pub hooks: PathBuf,
    pinned: Arc<OnceLock<Directories>>,
}
fn name(text: &str) -> io::Result<CString> {
    CString::new(text).map_err(|_| invalid("NUL in cgroup name"))
}
fn open_dir(parent: &File, name: &CStr) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    check_root_metadata(&file, true, None)?;
    Ok(file)
}
fn directory(parent: &File, name: &CStr) -> io::Result<File> {
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) } < 0
        && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
    {
        return Err(io::Error::last_os_error());
    }
    let file = open_dir(parent, name)?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o755) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}
fn control(dir: &File, entry: &str, flags: i32) -> io::Result<File> {
    let name = name(entry)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn read(dir: &File, entry: &str) -> io::Result<String> {
    let mut s = String::new();
    control(dir, entry, libc::O_RDONLY)?
        .take(65537)
        .read_to_string(&mut s)?;
    if s.len() > 65536 {
        return Err(invalid("cgroup control exceeds bound"));
    }
    Ok(s)
}
fn write(dir: &File, entry: &str, bytes: &[u8]) -> io::Result<()> {
    control(dir, entry, libc::O_WRONLY)?.write_all(bytes)
}
fn accepted(dir: &File, entry: &str, bytes: &[u8]) -> io::Result<()> {
    write(dir, entry, bytes)?;
    if read(dir, entry)?.as_bytes() != bytes {
        return Err(invalid(format!("kernel rejected {entry}")));
    }
    Ok(())
}
fn rm(parent: &File, name: &CStr) -> io::Result<()> {
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl CgroupLayout {
    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            supervisor: root.join("supervisor"),
            jobs: root.join("jobs"),
            hooks: root.join("hooks"),
            root,
            pinned: Arc::new(OnceLock::new()),
        }
    }
    pub fn discover() -> io::Result<Self> {
        Self::discover_from(
            &fs::read_to_string("/proc/self/cgroup")?,
            &fs::read_to_string("/proc/self/mountinfo")?,
        )
    }
    fn discover_from(membership: &str, mounts: &str) -> io::Result<Self> {
        let member = membership
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .ok_or_else(|| invalid("unified cgroup membership missing"))?;
        crate::linux::validate_absolute_path(Path::new(member))?;
        // A visible cgroup2 mount can expose a subtree, including cgroup
        // namespaces. Strip its mount root using component boundaries.
        let mut root = None;
        for line in mounts.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 10 || fields[4] != "/sys/fs/cgroup" {
                continue;
            }
            let sep = fields
                .iter()
                .position(|s| *s == "-")
                .ok_or_else(|| invalid("malformed mountinfo"))?;
            if fields.get(sep + 1) != Some(&"cgroup2") {
                continue;
            }
            crate::linux::validate_absolute_path(Path::new(fields[3]))?;
            let relative = Path::new(member)
                .strip_prefix(fields[3])
                .map_err(|_| invalid("service cgroup is outside the visible cgroup2 mount"))?;
            root = Some(Path::new("/sys/fs/cgroup").join(relative));
        }
        Ok(Self::from_root(
            root.ok_or_else(|| invalid("cgroup2 mount missing"))?,
        ))
    }
    pub fn register_subreaper() -> io::Result<()> {
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn initialize(&self) -> io::Result<()> {
        if self.pinned.get().is_some() {
            return Err(invalid("execution hierarchy already initialized"));
        }
        Self::register_subreaper()?;
        let root = open_pinned(&self.root)?;
        check_root_metadata(&root, true, None)?;
        let mut stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(root.as_raw_fd(), &mut stat) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if stat.f_type != 0x63677270 {
            return Err(invalid("delegated root is not cgroup2"));
        }
        let pid = std::process::id().to_string();
        if read(&root, "cgroup.procs")?
            .split_whitespace()
            .any(|p| p != pid)
        {
            return Err(invalid("execution requires a dedicated service cgroup"));
        }
        let supervisor = directory(&root, c"supervisor")?;
        let jobs = directory(&root, c"jobs")?;
        let hooks = directory(&root, c"hooks")?;
        write(&supervisor, "cgroup.procs", pid.as_bytes())?;
        let controllers = read(&root, "cgroup.controllers")?;
        for required in ["memory", "pids"] {
            if !controllers.split_whitespace().any(|c| c == required) {
                return Err(invalid(format!("missing {required} controller")));
            }
        }
        for dir in [&root, &jobs, &hooks] {
            write(dir, "cgroup.subtree_control", b"+memory +pids\n")?;
            let enabled = read(dir, "cgroup.subtree_control")?;
            if !["memory", "pids"]
                .iter()
                .all(|c| enabled.split_whitespace().any(|s| s == *c))
            {
                return Err(invalid("controllers were not enabled"));
            }
        }
        self.pinned
            .set(Directories { root, jobs, hooks })
            .map_err(|_| invalid("duplicate initialization"))?;
        self.verify_required_controls()
    }
    pub fn verify_required_controls(&self) -> io::Result<()> {
        let dirs = self
            .pinned
            .get()
            .ok_or_else(|| invalid("hierarchy is not pinned"))?;
        for dir in [&dirs.jobs, &dirs.hooks] {
            for entry in [
                "memory.max",
                "memory.swap.max",
                "memory.oom.group",
                "pids.max",
                "cgroup.kill",
            ] {
                drop(control(dir, entry, libc::O_WRONLY)?);
            }
        }
        let probe = directory(&dirs.hooks, c"startup-probe")?;
        let result = (|| {
            limits(&probe, 67_108_864, 0, 32)?;
            write(&probe, "cgroup.kill", b"1\n")
        })();
        let remove = rm(&dirs.hooks, c"startup-probe");
        result.and(remove)
    }
    pub fn cleanup_orphans(&self) -> io::Result<usize> {
        let dirs = self
            .pinned
            .get()
            .ok_or_else(|| invalid("hierarchy is not pinned"))?;
        let mut count = 0;
        for (dir, prefix) in [(&dirs.jobs, "job-"), (&dirs.hooks, "hook-")] {
            for entry in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let text = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| invalid("bad cgroup name"))?;
                let id = text
                    .strip_prefix(prefix)
                    .ok_or_else(|| invalid("unexpected cgroup directory"))?;
                sigrund_core::crypto::validate_uuidv7(id).map_err(|e| invalid(e.to_string()))?;
                let name = name(&text)?;
                let child = open_dir(dir, &name)?;
                kill_wait(&child, Instant::now() + Duration::from_secs(10))?;
                rm(dir, &name)?;
                count += 1;
            }
        }
        Ok(count)
    }
    pub fn create_job(
        &self,
        id: &str,
        memory: u64,
        swap: u64,
        pids: u64,
    ) -> Result<JobCgroup, JobCgroupError> {
        sigrund_core::crypto::validate_uuidv7(id).map_err(|e| invalid(e.to_string()))?;
        if memory == 0 || pids == 0 {
            return Err(invalid("finite positive job limits required").into());
        }
        let dirs = self
            .pinned
            .get()
            .ok_or_else(|| invalid("hierarchy is not pinned"))?;
        let entry = name(&format!("job-{id}"))?;
        let parent = dirs.jobs.try_clone()?;
        // No AlreadyExists reuse: consumption identifies one invocation only.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), entry.as_ptr(), 0o755) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut owner = JobCgroup {
            directory: None,
            parent,
            name: entry,
        };
        let setup = (|| {
            owner.directory = Some(open_dir(&owner.parent, &owner.name)?);
            limits(
                owner.directory.as_ref().expect("opened"),
                memory,
                swap,
                pids,
            )
        })();
        match setup {
            Ok(()) => Ok(owner),
            Err(error) => Err(JobCgroupError {
                error,
                owner: Some(owner),
            }),
        }
    }
    pub fn pinned_root_fd(&self) -> io::Result<i32> {
        Ok(self
            .pinned
            .get()
            .ok_or_else(|| invalid("hierarchy is not pinned"))?
            .root
            .as_raw_fd())
    }
}
fn limits(dir: &File, memory: u64, swap: u64, pids: u64) -> io::Result<()> {
    for (entry, value) in [
        ("memory.max", memory),
        ("memory.swap.max", swap),
        ("memory.oom.group", 1),
        ("pids.max", pids),
    ] {
        accepted(dir, entry, format!("{value}\n").as_bytes())?;
    }
    Ok(())
}
fn kill_wait(dir: &File, deadline: Instant) -> io::Result<()> {
    // Watch before killing to avoid losing an empty-transition notification.
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let notifications = unsafe { File::from_raw_fd(fd) };
    let path = name(&format!("/proc/self/fd/{}/cgroup.events", dir.as_raw_fd()))?;
    if unsafe { libc::inotify_add_watch(fd, path.as_ptr(), libc::IN_MODIFY) } < 0 {
        return Err(io::Error::last_os_error());
    }
    write(dir, "cgroup.kill", b"1\n")?;
    loop {
        if read(dir, "cgroup.events")?
            .lines()
            .any(|l| l == "populated 0")
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "cgroup teardown stalled",
            ));
        }
        let mut event = libc::pollfd {
            fd: notifications.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(100) as i32;
        if unsafe { libc::poll(&mut event, 1, remaining) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            return Err(io::Error::last_os_error());
        }
        let mut events = [0u8; 4096];
        // Drain bounded notifications; populated is always read back above.
        unsafe {
            libc::read(fd, events.as_mut_ptr().cast(), events.len());
        }
    }
}
#[must_use = "explicit cleanup is required even when no child was created"]
#[derive(Debug)]
pub struct JobCgroup {
    directory: Option<File>,
    parent: File,
    name: CString,
}
#[derive(Debug)]
pub struct JobCgroupError {
    pub error: io::Error,
    pub owner: Option<JobCgroup>,
}
impl From<io::Error> for JobCgroupError {
    fn from(error: io::Error) -> Self {
        Self { error, owner: None }
    }
}
impl std::fmt::Display for JobCgroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for JobCgroupError {}
impl From<JobCgroupError> for io::Error {
    fn from(error: JobCgroupError) -> Self {
        io::Error::new(error.error.kind(), error)
    }
}
impl JobCgroup {
    pub fn fd(&self) -> i32 {
        self.directory
            .as_ref()
            .expect("successfully opened job")
            .as_raw_fd()
    }
    pub fn kill(&self) -> io::Result<()> {
        write(
            self.directory.as_ref().expect("successfully opened job"),
            "cgroup.kill",
            b"1\n",
        )
    }
    /// Failure returns the owner. A stalled cleanup may never free its quota
    /// or silently orphan its cgroup through a destructor.
    pub fn cleanup(self) -> Result<(), (Self, io::Error)> {
        let result = match &self.directory {
            Some(directory) => kill_wait(directory, Instant::now() + Duration::from_secs(2))
                .and_then(|_| rm(&self.parent, &self.name)),
            // Opening the brand-new directory failed; no clone was possible.
            None => rm(&self.parent, &self.name),
        };
        if let Err(error) = result {
            return Err((self, error));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn membership_is_resolved_relative_to_mount_root() {
        let mounts = "1 0 0:1 /slice /sys/fs/cgroup rw - cgroup2 cgroup rw\n";
        assert_eq!(
            CgroupLayout::discover_from("0::/slice/service\n", mounts)
                .unwrap()
                .root,
            Path::new("/sys/fs/cgroup/service")
        );
        for bad in [
            "/sliceevil/job",
            "/slice/../service",
            "relative",
            "/slice//x",
        ] {
            assert!(CgroupLayout::discover_from(&format!("0::{bad}"), mounts).is_err());
        }
        assert!(
            CgroupLayout::discover_from(
                "0::/slice/job",
                "1 0 0:1 / /sys/fs/cgroup rw - tmpfs none rw"
            )
            .is_err()
        );
    }
}
