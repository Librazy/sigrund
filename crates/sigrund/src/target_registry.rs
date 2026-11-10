//! Epoch-local registrations. Names select retained owners and never reconstruct
//! them from a signed identifier, PID or pathname.
use sigrund_core::{
    host_budget::{Budget, Charge, Reservation},
    namespace::{Acquisition, Constraints, Contract, Registration, Selector},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}

/// Implementations own a capture helper and all retained descriptors. Disposal
/// must close/reap before returning, including on cancellation.
pub trait CapturedAnchor: Send + Sync {
    fn manager_evidence(&self) -> Option<&sigrund_core::manager::PodmanEvidence> {
        None
    }
    fn acquisition(&self) -> &Acquisition;
    fn root(&self) -> &std::fs::File;
    fn alive(&self) -> bool;
    fn executable_roots(&self) -> BTreeMap<String, sigrund_core::namespace::FsIdentity> {
        BTreeMap::new()
    }
    fn directory(
        &self,
        _path: &std::path::Path,
        _check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<std::fs::File> {
        Err(invalid("pinned executable roots unavailable"))
    }

    fn namespace_files(&self) -> &[std::fs::File] {
        &[]
    }
    fn revalidate(&self) -> io::Result<()>;
}

struct Instance {
    // Close/reap the capture before refunding the resource reservation.
    anchor: Box<dyn CapturedAnchor>,
    registration: Option<Registration>,
    authenticated_source: Option<sigrund_core::namespace::ConnectorObservation>,
    owner_uid: u32,
    constraints: Constraints,
    policy: Option<Arc<crate::lsm::PolicyGuard>>,
    revoked: AtomicBool,
    _resources: Reservation,
    // Separate from the outer Arc: stay live while field destructors close/reap.
    cleanup_lifetime: Arc<()>,
}
impl Instance {
    fn registration(&self) -> &Registration {
        self.registration.as_ref().expect("registered owner")
    }
    fn check(&self) -> io::Result<()> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(invalid("target registration revoked"));
        }
        if let Some(policy) = &self.policy {
            policy.check()?;
        }
        self.anchor.revalidate()?;
        if self.revoked.load(Ordering::Acquire) {
            return Err(invalid("target registration revoked"));
        }
        Ok(())
    }
}

struct Retired {
    owner: std::sync::Weak<()>,
    revision: String,
    instance_id: String,
    daemon_pid: u32,
}
impl Retired {
    fn new(owner: &Arc<Instance>) -> Self {
        Self {
            owner: Arc::downgrade(&owner.cleanup_lifetime),
            revision: owner.registration().revision.clone(),
            instance_id: owner.anchor.acquisition().instance_id.clone(),
            daemon_pid: owner.registration().daemon_pid,
        }
    }
}

struct Entries {
    by_id: BTreeMap<String, Arc<Instance>>,
    // Retired owners still count until their last lease and actual cleanup end.
    retired: Vec<Retired>,
    reserved: usize,
    acquiring: BTreeSet<u32>,
}

pub struct TargetRegistry {
    disposal: std::sync::mpsc::SyncSender<Arc<Instance>>,
    disposing: Arc<std::sync::atomic::AtomicUsize>,
    epoch: String,
    budget: Budget,
    roots: Vec<std::path::PathBuf>,
    self_capture: Mutex<Option<crate::target_management::SelfCapture>>,
    entries: Mutex<Entries>,
}

struct CaptureSlot<'a> {
    registry: &'a TargetRegistry,
    pid: u32,
}
impl Drop for CaptureSlot<'_> {
    fn drop(&mut self) {
        self.registry
            .entries
            .lock()
            .expect("registry poisoned")
            .acquiring
            .remove(&self.pid);
    }
}

/// Acquire this before starting capture. Dropping a failed operation releases
/// the slot only after its owned capture has been disposed.
pub struct RegistrationSlot {
    registry: Arc<TargetRegistry>,
    resources: Option<Reservation>,
    owner: u32,
}

pub struct TargetLease {
    instance: Arc<Instance>,
    // Drop the instance and its actual resources before releasing the lease.
    _reservation: Reservation,
}
pub(crate) struct TargetWatch(std::sync::Weak<Instance>);
impl TargetWatch {
    // Called while the committed request lease still owns this instance.
    pub fn valid(&self) -> bool {
        self.0.upgrade().is_some_and(|instance| {
            !instance.revoked.load(Ordering::Acquire)
                && instance
                    .policy
                    .as_ref()
                    .is_none_or(|policy| policy.check().is_ok())
                && instance.anchor.alive()
        })
    }
}
impl TargetLease {
    pub(crate) fn manager_evidence(&self) -> Option<&sigrund_core::manager::PodmanEvidence> {
        self.instance.anchor.manager_evidence()
    }
    pub(crate) fn watch(&self) -> TargetWatch {
        TargetWatch(Arc::downgrade(&self.instance))
    }
    pub(crate) fn reserve_child_resources(&self, charge: Charge) -> io::Result<Reservation> {
        self._reservation
            .budget_reserve_child(charge)
            .ok_or(io::ErrorKind::WouldBlock.into())
    }
    pub fn executable_roots(&self) -> BTreeMap<String, sigrund_core::namespace::FsIdentity> {
        self.instance.anchor.executable_roots()
    }
    pub fn directory(
        &self,
        path: &std::path::Path,
        check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<std::fs::File> {
        self.check_lifecycle()?;
        self.instance.anchor.directory(path, check)
    }

    pub fn check_lifecycle(&self) -> io::Result<()> {
        if let Some(policy) = &self.instance.policy {
            policy.check()?;
        }
        if self.instance.revoked.load(Ordering::Acquire) {
            return Err(invalid("target registration revoked"));
        }
        if !self.instance.anchor.alive() {
            return Err(invalid("target anchor or capture worker exited"));
        }
        Ok(())
    }

    pub(crate) fn namespace_files(&self) -> io::Result<&[std::fs::File]> {
        self.check_lifecycle()?;
        let files = self.instance.anchor.namespace_files();
        if files.len() != 8 {
            return Err(invalid("incomplete namespace handoff"));
        }
        Ok(files)
    }

    pub fn root(&self) -> &std::fs::File {
        self.instance.anchor.root()
    }
    pub fn reserve_resources(&self, charge: Charge) -> io::Result<Reservation> {
        self._reservation
            .budget_reserve(charge)
            .ok_or(io::ErrorKind::WouldBlock.into())
    }
    pub fn with_fd_copies<T>(&self, operation: impl FnOnce() -> T) -> io::Result<(T, Reservation)> {
        self._reservation
            .with_retained_fd_copies(operation)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "launcher inherited descriptor capacity exhausted: {:?}",
                        self._reservation.usage()
                    ),
                )
            })
    }

    pub fn revalidate(&self) -> io::Result<()> {
        self.instance.check()
    }
    pub fn registration(&self) -> &Registration {
        self.instance.registration()
    }
    pub(crate) fn authenticated_source(
        &self,
    ) -> Option<&sigrund_core::namespace::ConnectorObservation> {
        self.instance.authenticated_source.as_ref()
    }
    pub(crate) fn registration_record(&self) -> Option<&Registration> {
        self.instance.registration.as_ref()
    }
    pub(crate) fn policy_guard(&self) -> Option<&crate::lsm::PolicyGuard> {
        self.instance.policy.as_deref()
    }
    pub(crate) fn owner_uid(&self) -> u32 {
        self.instance.owner_uid
    }
    pub(crate) fn scope(&self) -> String {
        self.registration_record().map_or_else(
            || "self".into(),
            |registration| format!("registered:{}", registration.id),
        )
    }
    pub fn acquisition(&self) -> &Acquisition {
        self.instance.anchor.acquisition()
    }
    pub fn constraints(&self) -> &Constraints {
        &self.instance.constraints
    }
    /// Check an exact pending binding, including both opaque generation tokens.
    pub fn verify(&self, epoch: &str, instance: &str, revision: &str) -> io::Result<()> {
        self.revalidate()?;
        let a = self.acquisition();
        if a.daemon_epoch != epoch
            || a.instance_id != instance
            || self
                .registration_record()
                .is_none_or(|registration| registration.revision != revision)
        {
            return Err(invalid("stale target binding"));
        }
        Ok(())
    }
}

impl TargetRegistry {
    pub fn new(epoch: String, budget: Budget) -> io::Result<Self> {
        sigrund_core::crypto::validate_uuidv7(&epoch).map_err(io::Error::other)?;
        let (disposal, retired) = std::sync::mpsc::sync_channel::<Arc<Instance>>(64);
        let disposing = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pending = disposing.clone();
        std::thread::Builder::new()
            .name("target-disposal".into())
            .spawn(move || {
                while let Ok(owner) = retired.recv() {
                    drop(owner);
                    pending.fetch_sub(1, Ordering::AcqRel);
                }
            })?;
        Ok(Self {
            disposal,
            disposing,
            epoch,
            budget,
            roots: Vec::new(),
            self_capture: Mutex::new(None),
            entries: Mutex::new(Entries {
                by_id: BTreeMap::new(),
                retired: Vec::new(),
                reserved: 0,
                acquiring: BTreeSet::new(),
            }),
        })
    }

    pub fn new_with_roots(
        epoch: String,
        budget: Budget,
        roots: Vec<std::path::PathBuf>,
    ) -> io::Result<Self> {
        if roots.is_empty() || roots.len() > 64 || roots.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(invalid("invalid target executable roots"));
        }
        for path in &roots {
            crate::linux::validate_absolute_path(path)?;
            if path == std::path::Path::new("/") {
                return Err(invalid("executable root cannot be /"));
            }
        }
        let mut registry = Self::new(epoch, budget)?;
        registry.roots = roots;
        Ok(registry)
    }

    pub fn capture_fd_count(&self) -> u32 {
        20 + self.roots.len() as u32
    }

    fn reserve_capture(&self, pid: u32) -> io::Result<CaptureSlot<'_>> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| invalid("registry poisoned"))?;
        if entries.acquiring.contains(&pid)
            || entries
                .by_id
                .values()
                .any(|owner| owner.registration().daemon_pid == pid)
            || entries
                .retired
                .iter()
                .any(|owner| owner.daemon_pid == pid && owner.owner.strong_count() != 0)
        {
            return Err(invalid(
                "anchor already captured; create a fresh dedicated anchor",
            ));
        }
        entries.acquiring.insert(pid);
        Ok(CaptureSlot {
            registry: self,
            pid,
        })
    }

    pub(crate) fn reserve_source_reference(&self, uid: u32) -> io::Result<Reservation> {
        self.budget
            .reserve(
                uid,
                Charge {
                    target_fds: 1,
                    ..Default::default()
                },
            )
            .ok_or(io::ErrorKind::WouldBlock.into())
    }
    pub(crate) fn reserve_self_lease(&self, uid: u32) -> io::Result<Reservation> {
        self.budget
            .reserve(
                uid,
                Charge {
                    targets: 1,
                    reviews: 1,
                    ..Default::default()
                },
            )
            .ok_or(io::ErrorKind::WouldBlock.into())
    }
    pub fn reserve_registration(
        self: &Arc<Self>,
        owner: u32,
        retained_fds: u32,
    ) -> io::Result<RegistrationSlot> {
        // Capture's base bundle contains twenty descriptors, with additional
        // transport/transient copies reserved by the acquisition worker.
        if retained_fds < self.capture_fd_count() {
            return Err(invalid("capture descriptor reservation is too small"));
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| invalid("registry poisoned"))?;
        entries
            .retired
            .retain(|owner| owner.owner.strong_count() != 0);
        if entries.by_id.len() + entries.retired.len() + entries.reserved >= 64 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let resources = self
            .budget
            .reserve_child_resources(
                owner,
                Charge {
                    target_fds: retained_fds,
                    helpers: 1,
                    ..Default::default()
                },
            )
            .ok_or(io::ErrorKind::WouldBlock)?;
        entries.reserved += 1;
        Ok(RegistrationSlot {
            registry: self.clone(),
            resources: Some(resources),
            owner,
        })
    }

    /// The process selector resolves only existing captured registrations.
    /// Policy still evaluates the registration's scope independently.
    pub fn lease(
        &self,
        selector: &Selector,
        requester: u32,
        review: bool,
    ) -> io::Result<TargetLease> {
        selector.validate_selection().map_err(io::Error::other)?;
        let reservation = self
            .budget
            .reserve(
                requester,
                Charge {
                    targets: 1,
                    reviews: u32::from(review),
                    ..Default::default()
                },
            )
            .ok_or(io::ErrorKind::WouldBlock)?;
        let entries = self
            .entries
            .lock()
            .map_err(|_| invalid("registry poisoned"))?;
        let instance = match selector {
            Selector::Registered { id } => entries.by_id.get(id).cloned(),
            Selector::Process { pid, .. } => {
                let mut matches = entries
                    .by_id
                    .values()
                    .filter(|entry| entry.registration().daemon_pid == *pid);
                let first = matches.next().cloned();
                if matches.next().is_some() {
                    return Err(invalid("ambiguous retained process selector"));
                }
                first
            }
            _ => return Err(invalid("selector is outside the process registry")),
        }
        .ok_or_else(|| invalid("target unavailable"))?;
        drop(entries);
        if instance.revoked.load(Ordering::Acquire) || !instance.anchor.alive() {
            return Err(invalid("target invalidated"));
        }
        Ok(TargetLease {
            instance,
            _reservation: reservation,
        })
    }

    pub fn disposal_idle(&self) -> bool {
        self.disposing.load(Ordering::Acquire) == 0
    }
    fn retire(&self, owner: Arc<Instance>) {
        self.disposing.fetch_add(1, Ordering::AcqRel);
        // Capacity is bounded by the 64 active/acquiring/retired generations.
        if self.disposal.try_send(owner).is_err() {
            std::process::abort();
        }
    }
    pub fn revoke(&self, id: &str) -> io::Result<()> {
        sigrund_core::namespace::identifier(id).map_err(io::Error::other)?;
        let owner = {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| invalid("registry poisoned"))?;
            let owner = entries
                .by_id
                .remove(id)
                .ok_or_else(|| invalid("target unavailable"))?;
            owner.revoked.store(true, Ordering::Release);
            entries.retired.push(Retired::new(&owner));
            owner
        };
        // Potentially blocked disposal must never hold the registry mutex.
        self.retire(owner);
        Ok(())
    }

    /// Poll retained lifecycle references without resolving a name or PID again.
    pub fn monitor(&self) {
        let instances = self
            .entries
            .lock()
            .expect("registry poisoned")
            .by_id
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for instance in instances {
            if instance.anchor.alive() {
                continue;
            }
            instance.revoked.store(true, Ordering::Release);
            let removed = {
                let mut entries = self.entries.lock().expect("registry poisoned");
                let id = &instance.registration().id;
                if entries
                    .by_id
                    .get(id)
                    .is_some_and(|current| Arc::ptr_eq(current, &instance))
                {
                    let removed = entries.by_id.remove(id).expect("current registration");
                    entries.retired.push(Retired::new(&removed));
                    Some(removed)
                } else {
                    None
                }
            };
            if removed.is_some() {
                drop(removed);
                self.retire(instance);
            }
        }
    }

    pub fn revoke_all(&self) {
        let ids = self
            .entries
            .lock()
            .expect("registry poisoned")
            .by_id
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for id in ids {
            let _ = self.revoke(&id);
        }
    }

    pub(crate) fn set_self_capture(&self, service: Option<crate::target_management::SelfCapture>) {
        *self.self_capture.lock().expect("self capture service") = service;
    }
    pub(crate) fn capture_self(
        self: &Arc<Self>,
        source: crate::socket_disposal::Socket,
        constraints: Constraints,
        deadline: std::time::Instant,
        cancelled: Arc<AtomicBool>,
        check: impl Fn() -> io::Result<()>,
    ) -> io::Result<TargetLease> {
        loop {
            check()?;
            let service = self
                .self_capture
                .lock()
                .map_err(|_| invalid("self capture service poisoned"))?
                .clone();
            if let Some(service) = service {
                return service.capture(
                    self.clone(),
                    source,
                    constraints,
                    deadline,
                    cancelled,
                    check,
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    pub fn epoch(&self) -> &str {
        &self.epoch
    }
}

impl RegistrationSlot {
    /// Capture the authenticated dedicated anchor before publishing its name.
    /// All failure paths dispose it before releasing this slot's reservation.
    pub fn capture_and_publish(
        self,
        id: String,
        pid: u32,
        constraints: Constraints,
        peer: impl std::os::fd::AsRawFd,
        check: impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        self.capture_and_publish_managed(id, pid, constraints, peer, None, check)
    }
    pub(crate) fn capture_and_publish_managed(
        mut self,
        id: String,
        pid: u32,
        constraints: Constraints,
        peer: impl std::os::fd::AsRawFd,
        manager: Option<sigrund_core::manager::PodmanSelector>,
        check: impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let _policy_guard = crate::lsm::for_profile(&constraints)?;
        let manager = manager
            .map(|selector| {
                crate::podman::Guard::acquire(selector, self.owner, &self.registry.budget, &check)
            })
            .transpose()?;
        let registration = Registration {
            schema: "sigrund.registration.phase0.v1".into(),
            id,
            revision: fresh_revision()?,
            daemon_pid: pid,
            owner_uid: self.owner,
            profile_sha256: constraints.sha256().map_err(io::Error::other)?,
        };
        registration.validate().map_err(io::Error::other)?;
        let registry = self.registry.clone();
        let _capture = registry.reserve_capture(pid)?;
        // No target descriptors exist yet. The fresh helper reserves these
        // after exec has closed inherited copies, before its acquisition gate.
        drop(
            self.resources
                .as_mut()
                .expect("capture resources")
                .take_target_fds(),
        );
        let anchor = crate::target_capture::TargetCapture::acquire(
            peer,
            crate::target_capture::CaptureIdentity {
                pid,
                uid: self.owner,
                registration: Some(&registration),
            },
            &self.registry.epoch,
            &self.registry.budget,
            &self.registry.roots,
            &check,
        )?;
        check()?;
        let anchor: Box<dyn CapturedAnchor> = if let Some(guard) = manager {
            guard.verify_anchor(&anchor)?;
            Box::new(crate::podman::ManagedAnchor {
                anchor: Box::new(anchor),
                guard,
            })
        } else {
            Box::new(anchor)
        };
        self.publish_checked(registration, constraints, anchor, &check)
    }

    pub(crate) fn capture_self(
        mut self,
        source: sigrund_core::namespace::ConnectorObservation,
        constraints: Constraints,
        peer: crate::socket_disposal::Socket,
        lease: Reservation,
        check: impl Fn() -> io::Result<()>,
    ) -> io::Result<TargetLease> {
        constraints.validate().map_err(io::Error::other)?;
        let pid = source.pid;
        let registry = self.registry.clone();
        let _capture = registry.reserve_capture(pid)?;
        drop(
            self.resources
                .as_mut()
                .expect("self capture resources")
                .take_target_fds(),
        );
        let anchor = crate::target_capture::TargetCapture::acquire(
            peer,
            crate::target_capture::CaptureIdentity {
                pid,
                uid: self.owner,
                registration: None,
            },
            &registry.epoch,
            &registry.budget,
            &registry.roots,
            &check,
        )?;
        check()?;
        source
            .verify_capture(anchor.acquisition())
            .map_err(io::Error::other)?;
        Ok(TargetLease {
            instance: Arc::new(Instance {
                anchor: Box::new(anchor),
                registration: None,
                authenticated_source: Some(source),
                owner_uid: self.owner,
                policy: crate::lsm::for_profile(&constraints)?,
                constraints,
                revoked: AtomicBool::new(false),
                _resources: self.resources.take().expect("self capture resources"),
                cleanup_lifetime: Arc::new(()),
            }),
            _reservation: lease,
        })
    }

    /// Publish only coherent live resources. A replacement atomically revokes
    /// its predecessor while old leases retain that predecessor for cleanup.
    pub fn publish(
        self,
        registration: Registration,
        constraints: Constraints,
        anchor: Box<dyn CapturedAnchor>,
    ) -> io::Result<()> {
        self.publish_checked(registration, constraints, anchor, &|| Ok(()))
    }
    fn publish_checked(
        mut self,
        registration: Registration,
        constraints: Constraints,
        anchor: Box<dyn CapturedAnchor>,
        check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        check()?;
        registration.validate().map_err(io::Error::other)?;
        constraints.validate().map_err(io::Error::other)?;
        let acquisition = anchor.acquisition();
        acquisition.validate().map_err(io::Error::other)?;
        if registration.owner_uid != self.owner
            || !matches!(
                acquisition.capture,
                sigrund_core::namespace::Capture::TracedPrivateFsV1
            )
            || registration.profile_sha256 != constraints.sha256().map_err(io::Error::other)?
            || acquisition.daemon_epoch != self.registry.epoch
            || acquisition.pid != registration.daemon_pid
            || acquisition.lifecycle.registration_id.as_deref() != Some(&registration.id)
            || acquisition.lifecycle.registration_revision.as_deref()
                != Some(&registration.revision)
        {
            return Err(invalid("registration differs from captured owner"));
        }
        let policy = crate::lsm::for_profile(&constraints)?;
        anchor.revalidate()?;
        // Resolver revalidation performs bounded I/O. Expiry/shutdown during
        // that work must veto publication, even when its snapshot was valid.
        check()?;
        // The caller must generate a fresh unpredictable revision before capture
        // so the acquisition digest binds that same value.
        let mut entries = self
            .registry
            .entries
            .lock()
            .map_err(|_| invalid("registry poisoned"))?;
        if entries.by_id.values().any(|entry| {
            entry.registration().revision == registration.revision
                || entry.anchor.acquisition().instance_id == acquisition.instance_id
        }) || entries.retired.iter().any(|entry| {
            entry.revision == registration.revision || entry.instance_id == acquisition.instance_id
        }) {
            return Err(invalid("registration generation reused"));
        }
        let id = registration.id.clone();
        let instance = Arc::new(Instance {
            anchor,
            owner_uid: registration.owner_uid,
            registration: Some(registration),
            authenticated_source: None,
            policy,
            constraints,
            revoked: AtomicBool::new(false),
            _resources: self.resources.take().expect("registration resource owner"),
            cleanup_lifetime: Arc::new(()),
        });
        if let Some(old) = entries.by_id.insert(id, instance) {
            old.revoked.store(true, Ordering::Release);
            entries.retired.push(Retired::new(&old));
            // Release the registry lock before a possible synchronous disposal.
            drop(entries);
            self.registry.retire(old);
        }
        Ok(())
    }
}
impl Drop for RegistrationSlot {
    fn drop(&mut self) {
        let mut entries = self.registry.entries.lock().expect("registry poisoned");
        entries.reserved = entries
            .reserved
            .checked_sub(1)
            .expect("registration slot underflow");
    }
}
impl Drop for TargetRegistry {
    fn drop(&mut self) {
        if let Ok(entries) = self.entries.get_mut() {
            let owners = std::mem::take(&mut entries.by_id);
            for instance in owners.into_values() {
                instance.revoked.store(true, Ordering::Release);
                self.disposing.fetch_add(1, Ordering::AcqRel);
                if self.disposal.try_send(instance).is_err() {
                    std::process::abort();
                }
            }
        }
    }
}

/// Generate the revision independently of record content and before acquisition.
pub fn fresh_revision() -> io::Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    fn wait_disposal(registry: &TargetRegistry) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !registry.disposal_idle() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
    }
    struct Anchor {
        acquisition: Acquisition,
        closed: Arc<AtomicUsize>,
        root: std::fs::File,
        cancel_on_revalidate: Option<Arc<AtomicBool>>,
    }
    impl CapturedAnchor for Anchor {
        fn alive(&self) -> bool {
            true
        }
        fn root(&self) -> &std::fs::File {
            &self.root
        }
        fn acquisition(&self) -> &Acquisition {
            &self.acquisition
        }
        fn revalidate(&self) -> io::Result<()> {
            if let Some(cancelled) = &self.cancel_on_revalidate {
                cancelled.store(true, Ordering::Release);
            }
            Ok(())
        }
    }
    impl Drop for Anchor {
        fn drop(&mut self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn fixture(
        registry: &TargetRegistry,
        closed: &Arc<AtomicUsize>,
    ) -> (Registration, Constraints, Box<dyn CapturedAnchor>) {
        let mut a = Acquisition::parse(include_bytes!(
            "../../sigrund-phase0/tests/fixtures/acquisition.json"
        ))
        .unwrap();
        let c = Constraints::parse(include_bytes!(
            "../../sigrund-phase0/tests/fixtures/constraints.json"
        ))
        .unwrap();
        let revision = fresh_revision().unwrap();
        a.daemon_epoch = registry.epoch().into();
        a.instance_id = sigrund_core::crypto::new_uuidv7().to_string();
        a.lifecycle.registration_id = Some("B".into());
        a.lifecycle.registration_revision = Some(revision.clone());
        let r = Registration {
            schema: "sigrund.registration.phase0.v1".into(),
            id: "B".into(),
            revision,
            daemon_pid: a.pid,
            owner_uid: 1000,
            profile_sha256: c.sha256().unwrap(),
        };
        (
            r,
            c,
            Box::new(Anchor {
                acquisition: a,
                closed: closed.clone(),
                root: std::fs::File::open("/").unwrap(),
                cancel_on_revalidate: None,
            }),
        )
    }
    #[test]
    fn cancellation_during_revalidation_vetoes_publication_and_releases_resources() {
        let budget = Budget::new(Default::default()).unwrap();
        let registry = Arc::new(
            TargetRegistry::new(
                sigrund_core::crypto::new_uuidv7().to_string(),
                budget.clone(),
            )
            .unwrap(),
        );
        let closed = Arc::new(AtomicUsize::new(0));
        let (registration, constraints, original) = fixture(&registry, &closed);
        let cancelled = Arc::new(AtomicBool::new(false));
        let anchor = Anchor {
            acquisition: original.acquisition().clone(),
            closed: closed.clone(),
            root: std::fs::File::open("/").unwrap(),
            cancel_on_revalidate: Some(cancelled.clone()),
        };
        drop(original);
        let result = registry
            .reserve_registration(1000, 20)
            .unwrap()
            .publish_checked(registration, constraints, Box::new(anchor), &|| {
                if cancelled.load(Ordering::Acquire) {
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    Ok(())
                }
            });
        assert!(result.is_err());
        assert!(
            registry
                .lease(&Selector::Registered { id: "B".into() }, 1001, true)
                .is_err()
        );
        assert_eq!(closed.load(Ordering::SeqCst), 2);
        assert_eq!(budget.usage(1000).0, Charge::default());
    }
    #[test]
    fn replacement_and_revocation_never_redirect_pending_leases() {
        let registry = Arc::new(
            TargetRegistry::new(
                sigrund_core::crypto::new_uuidv7().to_string(),
                Budget::new(Default::default()).unwrap(),
            )
            .unwrap(),
        );
        let closed = Arc::new(AtomicUsize::new(0));
        let (r, c, a) = fixture(&registry, &closed);
        registry
            .reserve_registration(1000, 20)
            .unwrap()
            .publish(r, c, a)
            .unwrap();
        let old = registry
            .lease(&Selector::Registered { id: "B".into() }, 1001, true)
            .unwrap();
        let old_instance = old.acquisition().instance_id.clone();
        let (r, c, a) = fixture(&registry, &closed);
        registry
            .reserve_registration(1000, 20)
            .unwrap()
            .publish(r, c, a)
            .unwrap();
        assert!(old.revalidate().is_err());
        assert_eq!(closed.load(Ordering::SeqCst), 0);
        let new = registry
            .lease(&Selector::Registered { id: "B".into() }, 1001, true)
            .unwrap();
        assert_ne!(new.acquisition().instance_id, old_instance);
        assert!(
            new.verify(
                registry.epoch(),
                &old_instance,
                &old.registration().revision
            )
            .is_err()
        );
        registry.revoke("B").unwrap();
        assert!(new.revalidate().is_err());
        assert_eq!(closed.load(Ordering::SeqCst), 0);
        drop(old);
        wait_disposal(&registry);
        assert_eq!(closed.load(Ordering::SeqCst), 1);
        drop(new);
        wait_disposal(&registry);
        assert_eq!(closed.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn reservation_is_retained_by_retired_owners() {
        let registry = Arc::new(
            TargetRegistry::new(
                sigrund_core::crypto::new_uuidv7().to_string(),
                Budget::new(Default::default()).unwrap(),
            )
            .unwrap(),
        );
        let closed = Arc::new(AtomicUsize::new(0));
        let (r, c, a) = fixture(&registry, &closed);
        registry
            .reserve_registration(1000, 20)
            .unwrap()
            .publish(r, c, a)
            .unwrap();
        let lease = registry
            .lease(&Selector::Registered { id: "B".into() }, 1001, true)
            .unwrap();
        registry.revoke("B").unwrap();
        let second = registry.reserve_registration(1000, 20).unwrap();
        assert!(registry.reserve_registration(1000, 20).is_err());
        drop(lease);
        wait_disposal(&registry);
        let third = registry.reserve_registration(1000, 20).unwrap();
        drop(second);
        drop(third);
    }
    struct BlockingAnchor {
        acquisition: Acquisition,
        root: std::fs::File,
        entered: std::sync::mpsc::Sender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    // Receiver is only used by Drop, after the last registry/lease owner is
    // released. A mutex permits the shared capture interface before disposal.

    impl CapturedAnchor for BlockingAnchor {
        fn acquisition(&self) -> &Acquisition {
            &self.acquisition
        }
        fn root(&self) -> &std::fs::File {
            &self.root
        }
        fn alive(&self) -> bool {
            true
        }
        fn revalidate(&self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Drop for BlockingAnchor {
        fn drop(&mut self) {
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
        }
    }
    #[test]
    fn blocked_disposal_keeps_actual_fd_and_helper_charges() {
        let mut limits = sigrund_core::host_budget::Limits::default();
        limits.per_uid.target_fds = 20;
        let budget = Budget::new(limits).unwrap();
        let registry = Arc::new(
            TargetRegistry::new(
                sigrund_core::crypto::new_uuidv7().to_string(),
                budget.clone(),
            )
            .unwrap(),
        );
        let closed = Arc::new(AtomicUsize::new(0));
        let (r, c, a) = fixture(&registry, &closed);
        let (entered, seen) = std::sync::mpsc::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let captured_pid = r.daemon_pid;
        let anchor = BlockingAnchor {
            acquisition: a.acquisition().clone(),
            root: std::fs::File::open("/").unwrap(),
            entered,
            release: Mutex::new(blocked),
        };
        drop(a);
        registry
            .reserve_registration(1000, 20)
            .unwrap()
            .publish(r, c, Box::new(anchor))
            .unwrap();
        let worker_registry = registry.clone();
        let worker = std::thread::spawn(move || worker_registry.revoke("B").unwrap());
        seen.recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(
            budget
                .reserve(
                    1000,
                    Charge {
                        target_fds: 1,
                        ..Default::default()
                    }
                )
                .is_none()
        );
        assert!(
            budget
                .reserve(
                    1000,
                    Charge {
                        helpers: 2,
                        ..Default::default()
                    }
                )
                .is_none()
        );
        worker.join().unwrap(); // revoke returned although actual close is blocked
        let (mut second, constraints, anchor) = fixture(&registry, &closed);
        second.id = "C".into();
        second.owner_uid = 1002;
        let mut observed = anchor.acquisition().clone();
        observed.lifecycle.registration_id = Some("C".into());
        let other = Anchor {
            acquisition: observed,
            closed: closed.clone(),
            root: std::fs::File::open("/").unwrap(),
            cancel_on_revalidate: None,
        };
        registry
            .reserve_registration(1002, 20)
            .unwrap()
            .publish(second, constraints, Box::new(other))
            .unwrap();
        registry.revoke("C").unwrap();
        assert!(
            registry
                .lease(&Selector::Registered { id: "C".into() }, 1001, false)
                .is_err()
        );
        assert!(registry.reserve_capture(captured_pid).is_err());
        assert!(registry.reserve_registration(1000, 20).is_err());
        assert_eq!(registry.entries.lock().unwrap().retired.len(), 2);
        release.send(()).unwrap();
        wait_disposal(&registry);
        assert!(
            budget
                .reserve(
                    1000,
                    Charge {
                        target_fds: 20,
                        helpers: 2,
                        ..Default::default()
                    }
                )
                .is_some()
        );
    }

    #[test]
    fn target_and_review_leases_compose_global_and_per_uid_limits() {
        let registry = Arc::new(
            TargetRegistry::new(
                sigrund_core::crypto::new_uuidv7().to_string(),
                Budget::new(Default::default()).unwrap(),
            )
            .unwrap(),
        );
        let closed = Arc::new(AtomicUsize::new(0));
        let (r, c, a) = fixture(&registry, &closed);
        registry
            .reserve_registration(1000, 20)
            .unwrap()
            .publish(r, c, a)
            .unwrap();
        let selector = Selector::Registered { id: "B".into() };
        let mut leases = Vec::new();
        for uid in 0..16 {
            for _ in 0..4 {
                leases.push(registry.lease(&selector, uid, false).unwrap());
            }
            assert!(registry.lease(&selector, uid, false).is_err());
        }
        assert!(registry.lease(&selector, 17, false).is_err());
        drop(leases.pop());
        assert!(registry.lease(&selector, 17, false).is_ok());
        drop(leases);
        let first = registry.lease(&selector, 17, true).unwrap();
        let second = registry.lease(&selector, 17, true).unwrap();
        assert!(registry.lease(&selector, 17, true).is_err());
        drop(first);
        assert!(registry.lease(&selector, 17, true).is_ok());
        drop(second);
    }
    #[test]
    fn duplicate_capture_is_rejected_before_touching_a_live_anchor() {
        let registry = Arc::new(
            TargetRegistry::new(
                sigrund_core::crypto::new_uuidv7().to_string(),
                Budget::new(Default::default()).unwrap(),
            )
            .unwrap(),
        );
        let closed = Arc::new(AtomicUsize::new(0));
        let (r, c, a) = fixture(&registry, &closed);
        let pid = r.daemon_pid;
        registry
            .reserve_registration(1000, 20)
            .unwrap()
            .publish(r, c.clone(), a)
            .unwrap();
        let (peer, _other) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(
            registry
                .reserve_registration(1000, 20)
                .unwrap()
                .capture_and_publish("second-label".into(), pid, c, peer, || Ok(()))
                .is_err()
        );
        assert!(
            registry
                .lease(&Selector::Registered { id: "B".into() }, 1001, true)
                .is_ok()
        );
        assert_eq!(closed.load(Ordering::SeqCst), 0);
        let first = registry.reserve_capture(pid + 1).unwrap();
        assert!(registry.reserve_capture(pid + 1).is_err());
        drop(first);
        assert!(registry.reserve_capture(pid + 1).is_ok());
    }
}
