use std::io::Read;
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
    pub(crate) execution: Option<CgroupLayout>,
    _collector_files: Vec<fs::File>,
    _lock: fs::File,
}

impl StartupResources {
    pub fn execution_layout(&self) -> Option<&CgroupLayout> {
        self.execution.as_ref()
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
        Ok(Self {
            storage,
            execution: None,
            host_id,
            audit,
            store,
            roots,
            _collector_files: collector_files,
            _lock: lock,
        })
    }
}

pub use crate::cgroup::{CgroupLayout, JobCgroup};
