use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::{
    fd::AsRawFd,
    unix::fs::{MetadataExt, OpenOptionsExt},
};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::{
    linux::{openat2_audit_log, openat2_file, openat2_root, validate_absolute_path},
    transport::invalid,
};
use sigrund_core::{audit::AuditLog, config::DaemonConfig, crypto::sha256_hex, state::StateStore};

/// Pin a no-symlink path below /, allowing configured roots on other mounts.
pub fn open_pinned(path: &Path) -> io::Result<fs::File> {
    open_pinned_with(path, false)
}

pub fn pin_directory(path: &Path) -> io::Result<fs::File> {
    open_pinned_with(path, true)
}

fn open_pinned_with(path: &Path, directory: bool) -> io::Result<fs::File> {
    validate_absolute_path(path)?;
    if path == Path::new("/") {
        return fs::OpenOptions::new()
            .read(true)
            .custom_flags(if directory {
                libc::O_PATH | libc::O_DIRECTORY
            } else {
                0
            })
            .open("/");
    }
    let relative = path
        .strip_prefix("/")
        .map_err(|_| invalid("path must be absolute"))?;
    let root = fs::File::open("/")?;
    if directory {
        openat2_root(root.as_raw_fd(), relative)
    } else {
        openat2_file(root.as_raw_fd(), relative)
    }
    .map(Into::into)
}

pub fn check_root_metadata(file: &fs::File, directory: bool, mode: Option<u32>) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.uid() != 0
        || metadata.gid() != 0
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
        || metadata.mode() & 0o022 != 0
        || mode.is_some_and(|mode| metadata.mode() & 0o777 != mode)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "path must have trusted root:root ownership, type, and permissions",
        ));
    }
    Ok(())
}

pub fn read_root_file(path: &Path, mode: Option<u32>, max: u64) -> io::Result<Vec<u8>> {
    read_root_descriptor(open_pinned(path)?, mode, max)
}

fn read_root_descriptor(mut file: fs::File, mode: Option<u32>, max: u64) -> io::Result<Vec<u8>> {
    check_root_metadata(&file, false, mode)?;
    let mut bytes = Vec::new();
    (&mut file).take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(invalid("startup file exceeds size limit"));
    }
    Ok(bytes)
}

/// Retained startup resources. Recovery and all filesystem checks finish before
/// either listener is published. No filesystem I/O is needed on the event loop.
pub struct StartupResources {
    pub host_id: String,
    pub audit: AuditLog,
    pub store: StateStore,
    pub roots: Vec<fs::File>,
    pub(crate) storage: crate::storage::StoragePressure,
    /// The delegated execution hierarchy is optional only for hosts that do
    /// not expose one.  Authorization may still run for audit/rejection
    /// testing, but execution remains fail-closed without this resource.
    pub(crate) execution: Option<CgroupLayout>,
    pub(crate) execution_error: Option<String>,
    _collector_files: Vec<fs::File>,
    _lock: fs::File,
}

impl StartupResources {
    pub fn execution_layout(&self) -> Option<&CgroupLayout> {
        self.execution.as_ref()
    }

    pub fn execution_startup_error(&self) -> Option<&str> {
        self.execution_error.as_deref()
    }

    pub fn prepare(config: &DaemonConfig, state_dir: &Path, log_path: &Path) -> io::Result<Self> {
        if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "foreground daemon requires UID/GID 0",
            ));
        }
        if config.mvp.is_none() || config.require_remote_audit_ack {
            return Err(invalid("Phase 1 requires the local-audit [mvp] profile"));
        }
        let state_directory = open_pinned(state_dir)?;
        check_root_metadata(&state_directory, true, None)?;
        let log_directory = open_pinned(
            log_path
                .parent()
                .ok_or_else(|| invalid("log has no parent"))?,
        )?;
        check_root_metadata(&log_directory, true, None)?;
        let lock_path = PathBuf::from(format!(
            "/proc/self/fd/{}/daemon.lock",
            state_directory.as_raw_fd()
        ));
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(lock_path)?;
        check_root_metadata(&lock, false, Some(0o600))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "host state is already in use",
            ));
        }
        let mut identity = read_root_descriptor(
            openat2_file(state_directory.as_raw_fd(), Path::new("host_identity.key"))?.into(),
            Some(0o400),
            64,
        )?;
        if identity.len() != 64 {
            return Err(invalid(
                "host identity must contain a 32-byte secret and public key",
            ));
        }
        let mut secret: [u8; 32] = identity[..32].try_into().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&secret);
        secret.fill(0);
        let public = key.verifying_key().to_bytes();
        if identity[32..] != public {
            identity.fill(0);
            return Err(invalid("host identity keypair mismatch"));
        }
        identity.fill(0);
        let host_id = format!("sigrun-host:sha256:{}", sha256_hex(&public));
        let state_name = Path::new("audit_ratchet.state");
        let state_file: fs::File = openat2_file(state_directory.as_raw_fd(), state_name)?.into();
        check_root_metadata(&state_file, false, Some(0o600))?;
        validate_absolute_path(log_path)?;
        let log_name = Path::new(
            log_path
                .file_name()
                .ok_or_else(|| invalid("log needs a filename"))?,
        );
        let log_file: fs::File = openat2_audit_log(log_directory.as_raw_fd(), log_name)?.into();
        check_root_metadata(&log_file, false, Some(0o600))?;
        // All state entry access stays relative to the checked directory,
        // including stale temporary cleanup and future state publication.
        match openat2_file(
            state_directory.as_raw_fd(),
            Path::new("audit_ratchet.state.tmp"),
        ) {
            Ok(temporary) => {
                check_root_metadata(&temporary.into(), false, Some(0o600))?;
                if unsafe {
                    libc::unlinkat(
                        state_directory.as_raw_fd(),
                        c"audit_ratchet.state.tmp".as_ptr(),
                        0,
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error());
                }
                state_directory.sync_all()?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut roots = Vec::new();
        for path in &config.csr_allowed_executable_dirs {
            let root = pin_directory(path)?;
            check_root_metadata(&root, true, None)?;
            roots.push(root);
        }
        let mut collector_files = Vec::new();
        for path in [
            &config.collector_ca_file,
            &config.collector_client_cert_file,
            &config.collector_client_key_file,
        ] {
            let file = open_pinned(path)?;
            check_root_metadata(&file, false, None)?;
            collector_files.push(file);
        }
        // SQLite and its sidecars stay below this verified directory even if
        // an ancestor is renamed. Pre-create privately instead of changing
        // the multithreaded process umask. SQLite copies this mode to sidecars.
        let database_path = PathBuf::from(format!(
            "/proc/self/fd/{}/state.sqlite",
            state_directory.as_raw_fd()
        ));
        let database = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&database_path)?;
        check_root_metadata(&database, false, Some(0o600))?;
        // POSIX record locks are process-wide: closing any independently
        // opened FD for the database after SQLite locks it drops those locks.
        // Finish verification and close this descriptor before opening SQLite.
        drop(database);
        for name in [
            "state.sqlite-wal",
            "state.sqlite-shm",
            "state.sqlite-journal",
        ] {
            match openat2_file(state_directory.as_raw_fd(), Path::new(name)) {
                Ok(file) => check_root_metadata(&file.into(), false, Some(0o600))?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
        }
        let store = StateStore::open_in_directory(state_directory.try_clone()?)
            .map_err(|e| invalid(format!("database startup failed: {e}")))?;
        state_directory.sync_all()?;
        let storage = crate::storage::StoragePressure::new(
            log_file.try_clone()?,
            vec![log_directory, state_directory.try_clone()?],
        );
        let audit = AuditLog::from_verified_files(
            log_file,
            state_file,
            state_directory,
            state_name,
            Some(&host_id),
        )
        .map_err(|e| invalid(format!("audit recovery failed: {e}")))?;
        if !storage.check(config)? {
            return Err(invalid(
                "audit storage pressure; remediation and restart required",
            ));
        }
        let (execution, execution_error) = match CgroupLayout::discover().and_then(|layout| {
            layout.initialize()?;
            Ok(layout)
        }) {
            Ok(layout) => (Some(layout), None),
            Err(error) => (None, Some(error.to_string())),
        };
        Ok(Self {
            storage,
            execution,
            execution_error,
            host_id,
            audit,
            store,
            roots,
            _collector_files: collector_files,
            _lock: lock,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CgroupLayout {
    pub root: PathBuf,
    pub supervisor: PathBuf,
    pub jobs: PathBuf,
    pub hooks: PathBuf,
}

impl CgroupLayout {
    /// Discover the cgroup v2 directory containing the daemon from the
    /// kernel's membership record.  Unit/service names are deliberately not
    /// assumed: systemd may place the service below any delegated slice.
    pub fn discover() -> io::Result<Self> {
        let membership = fs::read_to_string("/proc/self/cgroup")?;
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "cgroup v2 is unavailable")
            })?;
        let relative = relative.trim_start_matches('/');
        let root = if relative.is_empty() {
            PathBuf::from("/sys/fs/cgroup")
        } else {
            PathBuf::from("/sys/fs/cgroup").join(relative)
        };
        let metadata = fs::metadata(root.join("cgroup.controllers"))?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "delegated cgroup is not a cgroup v2 hierarchy",
            ));
        }
        Ok(Self::from_root(root))
    }

    /// Register the daemon as a subreaper before any worker is started.
    pub fn register_subreaper() -> io::Result<()> {
        let result = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            supervisor: root.join("supervisor"),
            jobs: root.join("jobs"),
            hooks: root.join("hooks"),
            root,
        }
    }

    pub fn initialize(&self) -> io::Result<()> {
        create_cgroup_directory(&self.supervisor)?;
        create_cgroup_directory(&self.jobs)?;
        create_cgroup_directory(&self.hooks)?;
        write_exact(
            self.supervisor.join("cgroup.procs"),
            std::process::id().to_string().as_bytes(),
        )?;
        let controllers = fs::read_to_string(self.root.join("cgroup.controllers"))?;
        if !controllers.split_whitespace().any(|v| v == "memory")
            || !controllers.split_whitespace().any(|v| v == "pids")
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "memory and pids controllers are required",
            ));
        }
        for directory in [&self.root, &self.jobs, &self.hooks] {
            write_exact(directory.join("cgroup.subtree_control"), b"+memory +pids\n")?;
        }
        self.verify_required_controls()
    }

    pub fn verify_required_controls(&self) -> io::Result<()> {
        for directory in [&self.root, &self.jobs, &self.hooks] {
            for name in [
                "memory.max",
                "memory.swap.max",
                "memory.oom.group",
                "pids.max",
                "cgroup.kill",
            ] {
                let path = directory.join(name);
                if !path.exists() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("missing {}", path.display()),
                    ));
                }
            }
        }
        let probe = self.hooks.join("startup-probe");
        fs::create_dir(&probe)?;
        let result = (|| {
            write_and_verify(&probe.join("memory.max"), b"67108864\n")?;
            write_and_verify(&probe.join("memory.swap.max"), b"0\n")?;
            write_and_verify(&probe.join("memory.oom.group"), b"1\n")?;
            write_and_verify(&probe.join("pids.max"), b"32\n")?;
            write_exact(probe.join("cgroup.kill"), b"1\n")
        })();
        let remove = fs::remove_dir(&probe);
        result.and(remove)
    }

    /// Remove stale job/hook leaves after killing their cgroups.  Processes
    /// reparented to a previous init/subreaper are intentionally not waited
    /// for here; `populated=0` is the authoritative cleanup condition.
    pub fn cleanup_orphans(&self) -> io::Result<usize> {
        let mut removed = 0;
        for parent in [&self.jobs, &self.hooks] {
            let entries = match fs::read_dir(parent) {
                Ok(entries) => entries,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let kill = path.join("cgroup.kill");
                if kill.exists() {
                    write_exact(&kill, b"1\n")?;
                }
                let events = path.join("cgroup.events");
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                loop {
                    let populated = fs::read_to_string(&events).ok().and_then(|text| {
                        text.lines().find_map(|line| {
                            line.strip_prefix("populated ")
                                .and_then(|v| v.parse::<u8>().ok())
                        })
                    });
                    if populated == Some(0) || std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                let populated = fs::read_to_string(&events)
                    .ok()
                    .is_some_and(|text| text.lines().any(|line| line.trim() == "populated 0"));
                if !populated {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("cgroup cleanup stalled: {}", path.display()),
                    ));
                }
                fs::remove_dir(&path)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub fn create_job(
        &self,
        exec_id: &str,
        memory: u64,
        swap: u64,
        pids: u64,
    ) -> io::Result<JobCgroup> {
        if exec_id.is_empty()
            || exec_id
                .bytes()
                .any(|b| !(b.is_ascii_alphanumeric() || b == b'-'))
            || memory == 0
            || pids == 0
        {
            return Err(invalid("invalid job cgroup identity or limits"));
        }
        let path = self.jobs.join(format!("job-{exec_id}"));
        fs::create_dir(&path)?;
        if let Err(error) = (|| {
            write_and_verify(&path.join("memory.max"), format!("{memory}\n").as_bytes())?;
            write_and_verify(
                &path.join("memory.swap.max"),
                format!("{swap}\n").as_bytes(),
            )?;
            write_and_verify(&path.join("memory.oom.group"), b"1\n")?;
            write_and_verify(&path.join("pids.max"), format!("{pids}\n").as_bytes())?;
            Ok::<_, io::Error>(())
        })() {
            let _ = fs::remove_dir(&path);
            return Err(error);
        }
        let fd = fs::File::open(&path)?;
        Ok(JobCgroup { path, fd })
    }
}

pub struct JobCgroup {
    path: PathBuf,
    fd: fs::File,
}

impl JobCgroup {
    pub fn fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for JobCgroup {
    fn drop(&mut self) {
        let _ = write_exact(self.path.join("cgroup.kill"), b"1\n");
        let _ = fs::remove_dir(&self.path);
    }
}

fn create_cgroup_directory(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

fn write_exact(path: impl AsRef<Path>, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

fn write_and_verify(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_exact(path, bytes)?;
    let actual = fs::read(path)?;
    if actual != bytes {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("kernel rejected {}", path.display()),
        ));
    }
    Ok(())
}
