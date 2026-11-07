//! Retained resources for the v3 host target. This owner does not perform
//! namespace entry. It must be created after recovery/startup qualification and
//! retained by each request until its resources and descendants are cleaned up.
use sigrund_core::{
    crypto::new_uuidv7,
    host::{
        Acquisition, BindingBundle, Constraints, MapExtent, ObjectIdentity, Record, TargetBinding,
    },
    host_budget::{Budget, Charge, Reservation},
};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
};

pub struct HostTarget {
    root: File,
    roots: BTreeMap<PathBuf, Arc<File>>,
    namespaces: BTreeMap<String, File>,
    acquisition: Acquisition,
    budget: Budget,
    // Accounting follows every actual FD close, including transferred roots.
    _fds: Reservation,
    _pinned_roots: Option<PinnedRoots>,
}
/// Startup roots are charged before their first open. Move this aggregate into
/// the live host owner; error paths close files before releasing the charge.
pub(crate) struct PinnedRoots {
    files: Vec<File>,
    _reservation: Reservation,
}
impl PinnedRoots {
    pub(crate) fn acquire(paths: &[PathBuf], budget: &Budget) -> io::Result<Self> {
        let count = u32::try_from(paths.len() + 1).map_err(invalid)?;
        let reservation = budget
            .reserve(
                0,
                Charge {
                    target_fds: count,
                    ..Default::default()
                },
            )
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        // pin_directory opens one transient traversal root in addition to the
        // retained descriptor. The reservation covers that duplicate as well.
        let mut files = Vec::new();
        for path in paths {
            let file = crate::startup::pin_directory(path)?;
            crate::startup::check_root_metadata(&file, true, None)?;
            files.push(file);
        }
        Ok(Self {
            files,
            _reservation: reservation,
        })
    }
}

pub struct HostLease {
    target: Arc<HostTarget>,
    // The resource owner is released before the request's quota reservation.
    uid: u32,
    _reservation: Reservation,
}
fn invalid(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}
fn identity(file: &File) -> io::Result<ObjectIdentity> {
    let metadata = file.metadata()?;
    Ok(ObjectIdentity {
        device: metadata.dev().to_string(),
        inode: metadata.ino().to_string(),
    })
}
fn read_small(path: &str) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(invalid("host observation exceeds bound"));
    }
    String::from_utf8(bytes).map_err(invalid)
}
fn map(path: &str) -> io::Result<Vec<MapExtent>> {
    let raw = read_small(path)?;
    let mut result = Vec::new();
    for line in raw.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3 || result.len() == 64 {
            return Err(invalid("invalid host mapping"));
        }
        result.push(MapExtent {
            inside: fields[0].parse().map_err(invalid)?,
            outside: fields[1].parse().map_err(invalid)?,
            length: fields[2].parse().map_err(invalid)?,
        });
    }
    Ok(result)
}
fn directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}
pub(crate) fn qualify_profiles(
    profiles: &[Constraints],
    checkpoint: bool,
    last_cap: u32,
) -> io::Result<()> {
    for profile in profiles {
        profile.validate().map_err(invalid)?;
        if profile.verify_exec_stop && !checkpoint {
            return Err(invalid("host profile requires unavailable exec checkpoint"));
        }
        if last_cap >= 64
            || profile
                .capabilities
                .iter()
                .any(|c| crate::authorization::capability_number(c).is_none_or(|n| n > last_cap))
        {
            return Err(invalid(
                "host profile requires unavailable kernel capabilities",
            ));
        }
    }
    Ok(())
}

impl HostTarget {
    /// Every FD is reserved before opening. This startup owner uses host UID 0;
    /// request leases and transient duplicates need their own UID reservations.
    pub fn acquire(paths: &[PathBuf], budget: &Budget) -> io::Result<Arc<Self>> {
        Self::acquire_with(paths, None, budget)
    }
    pub(crate) fn acquire_pinned(
        paths: &[PathBuf],
        roots: PinnedRoots,
        budget: &Budget,
    ) -> io::Result<Arc<Self>> {
        Self::acquire_with(paths, Some(roots), budget)
    }
    fn acquire_with(
        paths: &[PathBuf],
        mut pinned: Option<PinnedRoots>,
        budget: &Budget,
    ) -> io::Result<Arc<Self>> {
        if paths.is_empty() || paths.len() > 64 || paths.windows(2).any(|p| p[0] >= p[1]) {
            return Err(invalid("invalid host executable roots"));
        }
        // root + eight namespace FDs. Observation reads below open one temporary
        // FD at a time, also covered until acquisition finishes.
        let count = if pinned.is_some() {
            10
        } else {
            u32::try_from(paths.len() + 10).map_err(invalid)?
        };
        let charge = budget
            .reserve(
                0,
                Charge {
                    target_fds: count,
                    ..Charge::default()
                },
            )
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        let root = directory(Path::new("/"))?;
        let mut roots = BTreeMap::new();
        let mut pinned_files = match &mut pinned {
            Some(roots) if roots.files.len() == paths.len() => {
                Some(std::mem::take(&mut roots.files).into_iter())
            }
            Some(_) => return Err(invalid("incomplete pinned root set")),
            None => None,
        };
        for path in paths {
            let text = path.to_str().ok_or_else(|| invalid("non-UTF8 host root"))?;
            if !text.starts_with('/')
                || text == "/"
                || text[1..]
                    .split('/')
                    .any(|s| s.is_empty() || s == "." || s == "..")
            {
                return Err(invalid("invalid host executable root"));
            }
            let file = match &mut pinned_files {
                Some(files) => files.next().expect("complete pinned roots"),
                None => crate::linux::openat2_root(root.as_raw_fd(), Path::new(&text[1..]))?.into(),
            };
            if !file.metadata()?.is_dir() {
                return Err(invalid("pinned executable root is not a directory"));
            }
            roots.insert(path.clone(), Arc::new(file));
        }
        let mut namespaces = BTreeMap::new();
        for name in ["cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"] {
            namespaces.insert(
                name.to_owned(),
                File::open(format!("/proc/self/ns/{name}"))?,
            );
        }
        let acquisition = Acquisition {
            schema: "sigrund.host-acquisition.v1".into(),
            daemon_epoch: new_uuidv7().to_string(),
            instance_id: new_uuidv7().to_string(),
            boot_id: read_small("/proc/sys/kernel/random/boot_id")?
                .trim()
                .to_owned(),
            root: identity(&root)?,
            executable_roots: roots
                .iter()
                .map(|(p, f)| Ok((p.to_str().unwrap().to_owned(), identity(f)?)))
                .collect::<io::Result<_>>()?,
            namespaces: namespaces
                .iter()
                .map(|(n, f)| Ok((n.clone(), identity(f)?)))
                .collect::<io::Result<_>>()?,
            uid_map: map("/proc/self/uid_map")?,
            gid_map: map("/proc/self/gid_map")?,
            setgroups: read_small("/proc/self/setgroups")?.trim().to_owned(),
        };
        acquisition.validate().map_err(invalid)?;
        let target = Arc::new(Self {
            root,
            roots,
            namespaces,
            acquisition,
            budget: budget.clone(),
            _fds: charge,
            _pinned_roots: pinned,
        });
        target.revalidate()?;
        Ok(target)
    }
    /// Only the retained instance can mint a binding. Neither a pathname nor a
    /// previously signed instance ID can recreate this owner.
    pub fn bundle(&self, host_id: String, constraints: Constraints) -> io::Result<BindingBundle> {
        self.revalidate()?;
        let bundle = BindingBundle {
            schema: "sigrund.host-binding-bundle.v1".into(),
            host_id,
            target_binding: TargetBinding {
                kind: "host".into(),
                daemon_epoch: self.acquisition.daemon_epoch.clone(),
                instance_id: self.acquisition.instance_id.clone(),
                description: "Host execution environment".into(),
                context_sha256: self.acquisition.sha256().map_err(invalid)?,
            },
            acquisition: self.acquisition.clone(),
            profile_sha256: constraints.sha256().map_err(invalid)?,
            constraints,
        };
        bundle.validate().map_err(invalid)?;
        Ok(bundle)
    }
    pub fn lease(self: &Arc<Self>, uid: u32) -> io::Result<HostLease> {
        self.lease_for_review(uid, false)
    }
    pub fn lease_for_review(self: &Arc<Self>, uid: u32, review: bool) -> io::Result<HostLease> {
        let reservation = self
            .budget
            .reserve(
                uid,
                Charge {
                    targets: 1,
                    target_fds: 4,
                    reviews: u32::from(review),
                    ..Charge::default()
                },
            )
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        self.revalidate_for(uid)?;
        Ok(HostLease {
            target: self.clone(),
            uid,
            _reservation: reservation,
        })
    }
    pub(crate) fn pinned_roots(&self) -> Vec<(PathBuf, Arc<File>)> {
        self.roots
            .iter()
            .map(|(path, file)| (path.clone(), file.clone()))
            .collect()
    }
    pub fn revalidate(&self) -> io::Result<()> {
        self.revalidate_for(0)
    }
    fn revalidate_for(&self, uid: u32) -> io::Result<()> {
        let _transient = self
            .budget
            .reserve(
                uid,
                Charge {
                    target_fds: 1,
                    ..Charge::default()
                },
            )
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        if identity(&directory(Path::new("/"))?)? != self.acquisition.root {
            return Err(invalid("coordinator root changed"));
        }
        if identity(&self.root)? != self.acquisition.root
            || map("/proc/self/uid_map")? != self.acquisition.uid_map
            || map("/proc/self/gid_map")? != self.acquisition.gid_map
            || read_small("/proc/self/setgroups")?.trim() != self.acquisition.setgroups
            || read_small("/proc/sys/kernel/random/boot_id")?.trim() != self.acquisition.boot_id
        {
            return Err(invalid("host acquisition changed"));
        }
        for (path, file) in &self.roots {
            if self
                .acquisition
                .executable_roots
                .get(path.to_str().unwrap())
                != Some(&identity(file)?)
            {
                return Err(invalid("retained host root identity changed"));
            }
        }
        for (name, file) in &self.namespaces {
            if self.acquisition.namespaces.get(name) != Some(&identity(file)?) {
                return Err(invalid("retained namespace identity changed"));
            }
            let current = File::open(format!("/proc/self/ns/{name}"))?;
            if identity(&current)? != identity(file)? {
                return Err(invalid("coordinator namespace changed"));
            }
        }
        Ok(())
    }
}
/// Unprivileged full preparation checks local observations against an explicitly
/// trusted bundle. This grants no execution ownership or instance acquisition.
/// The selected root stays pinned for source traversal after validation.
pub(crate) fn preparation_root(
    bundle: &BindingBundle,
    executable: &Path,
) -> io::Result<(File, PathBuf)> {
    bundle.validate().map_err(invalid)?;
    let a = &bundle.acquisition;
    if identity(&directory(Path::new("/"))?)? != a.root
        || map("/proc/self/uid_map")? != a.uid_map
        || map("/proc/self/gid_map")? != a.gid_map
        || read_small("/proc/self/setgroups")?.trim() != a.setgroups
        || read_small("/proc/sys/kernel/random/boot_id")?.trim() != a.boot_id
    {
        return Err(invalid(
            "local host preparation domain differs from binding",
        ));
    }
    for (name, expected) in &a.namespaces {
        if identity(&File::open(format!("/proc/self/ns/{name}"))?)? != *expected {
            return Err(invalid("local namespace differs from host binding"));
        }
    }
    let roots: Vec<PathBuf> = a.executable_roots.keys().map(PathBuf::from).collect();
    let selected = sigrund_core::paths::select_root(executable, &roots).map_err(invalid)?;
    let root = crate::startup::pin_directory(&selected.root)?;
    if a.executable_roots.get(selected.root.to_str().unwrap()) != Some(&identity(&root)?) {
        return Err(invalid("local executable root differs from host binding"));
    }
    Ok((root, selected.relative_path))
}

impl HostLease {
    pub(crate) fn reserve_resources(&self, charge: Charge) -> io::Result<Reservation> {
        self.target
            .budget
            .reserve(self.uid, charge)
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
    }

    pub(crate) fn with_retained_fd_copies<T>(
        &self,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<(T, Reservation)> {
        let (result, copies) = self
            .target
            .budget
            .with_retained_fd_copies(self.uid, operation)
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        Ok((result?, copies))
    }
    pub(crate) fn with_transient_fd_copies<T>(
        &self,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        self.target
            .budget
            .with_transient_fd_copies(self.uid, operation)
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?
    }

    pub fn verify(&self, bundle: &BindingBundle) -> io::Result<()> {
        bundle.validate().map_err(invalid)?;
        self.target.revalidate_for(self.uid)?;
        if bundle.acquisition != self.target.acquisition {
            return Err(invalid("stale host target binding"));
        }
        Ok(())
    }
    pub fn target(&self) -> &HostTarget {
        &self.target
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profiles_require_available_checkpoint_and_kernel_capabilities() {
        let mut p = Constraints::parse(include_bytes!(
            "../../sigrund-core/tests/fixtures/v3-host/constraints.json"
        ))
        .unwrap();
        qualify_profiles(&[p.clone()], false, 40).unwrap();
        p.capabilities = vec!["CAP_NET_BIND_SERVICE".into()];
        assert!(qualify_profiles(&[p.clone()], false, 9).is_err());
        qualify_profiles(&[p.clone()], false, 40).unwrap();
        p.executable_model = sigrund_core::executable::TrustModel::DigestDirect;
        p.verify_exec_stop = true;
        assert!(qualify_profiles(&[p.clone()], false, 40).is_err());
        qualify_profiles(&[p], true, 40).unwrap();
    }
    #[test]
    fn startup_roots_reserve_before_open_and_release_failed_partial_acquisition() {
        let mut limits = sigrund_core::host_budget::Limits::default();
        limits.per_uid.target_fds = 1;
        let budget = Budget::new(limits).unwrap();
        let error = match PinnedRoots::acquire(&[PathBuf::from("/never-open-this-root")], &budget) {
            Ok(_) => panic!("opened a target without capacity"),
            Err(e) => e,
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        let budget = Budget::new(Default::default()).unwrap();
        assert!(
            PinnedRoots::acquire(
                &[
                    PathBuf::from("/"),
                    PathBuf::from("/nonexistent-sigrund-root")
                ],
                &budget
            )
            .is_err()
        );
        assert!(
            budget
                .reserve(
                    0,
                    Charge {
                        target_fds: 128,
                        ..Default::default()
                    }
                )
                .is_some()
        );
    }
    #[test]
    fn local_preparation_requires_matching_domain_and_retains_the_selected_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("executables");
        std::fs::create_dir(&path).unwrap();
        let target = HostTarget::acquire(
            std::slice::from_ref(&path),
            &Budget::new(Default::default()).unwrap(),
        )
        .unwrap();
        let constraints = Constraints::parse(include_bytes!(
            "../../sigrund-core/tests/fixtures/v3-host/constraints.json"
        ))
        .unwrap();
        let bundle = target
            .bundle(
                format!("sigrun-host:sha256:{}", "1".repeat(64)),
                constraints,
            )
            .unwrap();
        let executable = path.join("program");
        let (retained, relative) = preparation_root(&bundle, &executable).unwrap();
        assert_eq!(relative, Path::new("program"));
        assert!(preparation_root(&bundle, Path::new("/outside/program")).is_err());
        let mut other = bundle.clone();
        let ns = other.acquisition.namespaces.get_mut("mnt").unwrap();
        ns.inode = (ns.inode.parse::<u64>().unwrap() + 1).to_string();
        other.target_binding.context_sha256 = other.acquisition.sha256().unwrap();
        other.validate().unwrap();
        assert!(preparation_root(&other, &executable).is_err());
        std::fs::rename(&path, dir.path().join("old")).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            identity(&retained).unwrap(),
            *bundle
                .acquisition
                .executable_roots
                .get(path.to_str().unwrap())
                .unwrap()
        );
        assert!(preparation_root(&bundle, &executable).is_err());
    }
}
