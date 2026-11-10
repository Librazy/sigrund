//! Optional Podman identity/lifecycle dependency around a normal captured anchor.
use crate::{
    podman_api::{Endpoint, Response},
    target_registry::CapturedAnchor,
};
use sigrund_core::{
    crypto::sha256_hex,
    host_budget::{Budget, Charge, Reservation},
    manager::{PodmanEvidence, PodmanSelector},
    namespace::{Contract, FsIdentity},
};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const CHECK_INTERVAL: Duration = Duration::from_millis(200);
const MAX_STALENESS: Duration = Duration::from_secs(3);
fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}
fn live(fd: &OwnedFd) -> bool {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut poll, 1, 0) == 0 }
}
fn stream_live(fd: &OwnedFd) -> bool {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLRDHUP,
        revents: 0,
    };
    (unsafe { libc::poll(&mut poll, 1, 0) >= 0 })
        && poll.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) == 0
}
fn pidfd(pid: u32) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if raw < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}
fn start_ticks(pid: u32) -> io::Result<String> {
    let mut text = String::new();
    File::open(format!("/proc/{pid}/stat"))?
        .take(8193)
        .read_to_string(&mut text)?;
    if text.len() > 8192 {
        return Err(invalid("process stat exceeds bound"));
    }
    text.rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .filter(|v| v.parse::<u64>().is_ok_and(|n| n > 0 && n.to_string() == *v))
        .map(str::to_owned)
        .ok_or_else(|| invalid("invalid process start identity"))
}
fn manager_membership(pid: u32, id: &str) -> io::Result<()> {
    // A stale numeric PID must not associate an unrelated live task with the
    // manager. The qualified rootful profile owns this systemd scope and its
    // init is PID 1 in a private PID namespace. Container metadata alone does
    // not establish either property.
    let mut cgroup = String::new();
    File::open(format!("/proc/{pid}/cgroup"))?
        .take(8193)
        .read_to_string(&mut cgroup)?;
    let expected = format!("0::/machine.slice/libpod-{id}.scope/container\n");
    if cgroup.len() > 8192 || cgroup != expected {
        return Err(invalid(
            "Podman init cgroup does not match the manager object",
        ));
    }
    let mut status = String::new();
    File::open(format!("/proc/{pid}/status"))?
        .take(65537)
        .read_to_string(&mut status)?;
    let ids = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .map(|line| line.split_whitespace().collect::<Vec<_>>());
    if status.len() > 65536 || ids.is_none_or(|ids| ids.len() != 2 || ids[1] != "1") {
        return Err(invalid(
            "Podman init requires a private, single-level PID namespace",
        ));
    }
    Ok(())
}
struct Snapshot {
    id: String,
    pid: u32,
    started: String,
    configuration: String,
}
impl Snapshot {
    fn parse(value: serde_json::Value, name: &str) -> io::Result<Self> {
        let string = |key: &str| {
            value
                .get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| invalid("missing Podman inspect string"))
        };
        if string("Name")? != name || !string("Namespace")?.is_empty() {
            return Err(invalid("Podman name or namespace differs"));
        }
        let state = value
            .get("State")
            .ok_or_else(|| invalid("missing Podman running state"))?;
        if value
            .pointer("/HostConfig/CgroupManager")
            .and_then(|v| v.as_str())
            != Some("systemd")
            || value
                .pointer("/HostConfig/PidMode")
                .and_then(|v| v.as_str())
                != Some("private")
        {
            return Err(invalid(
                "Podman resolver requires the qualified systemd/private-PID profile",
            ));
        }
        if state.get("Running").and_then(|v| v.as_bool()) != Some(true)
            || state.get("Paused").and_then(|v| v.as_bool()) != Some(false)
            || state.get("Restarting").and_then(|v| v.as_bool()) != Some(false)
            || state.get("Dead").and_then(|v| v.as_bool()) != Some(false)
        {
            return Err(invalid(
                "Podman container is not a stable running generation",
            ));
        }
        let pid = state
            .get("Pid")
            .and_then(|v| v.as_u64())
            .filter(|n| *n > 0 && *n <= i32::MAX as u64)
            .ok_or_else(|| invalid("invalid manager init PID"))? as u32;
        let mut config = BTreeMap::new();
        for key in [
            "Config",
            "HostConfig",
            "Mounts",
            "ProcessLabel",
            "MountLabel",
            "AppArmorProfile",
            "Namespace",
            "Image",
            "Rootfs",
            "Dependencies",
        ] {
            let record = value
                .get(key)
                .ok_or_else(|| invalid("missing required Podman configuration"))?;
            let available = match key {
                "Config" | "HostConfig" => record.is_object(),
                "Mounts" | "Dependencies" => record.is_array(),
                _ => record.is_string(),
            };
            if !available {
                return Err(invalid("unavailable required Podman configuration"));
            }
            config.insert(key, record);
        }
        Ok(Self {
            id: string("Id")?.into(),
            pid,
            started: state
                .get("StartedAt")
                .and_then(|v| v.as_str())
                .ok_or_else(|| invalid("missing Podman start time"))?
                .into(),
            configuration: sha256_hex(
                &sigrund_core::json::canonical_bytes(&config).map_err(io::Error::other)?,
            ),
        })
    }
}
struct Shared {
    endpoint: Endpoint,
    evidence: PodmanEvidence,
    init: OwnedFd,
    peer: OwnedFd,
    event_watch: OwnedFd,
    events: Mutex<Response>,
    event_rate: Mutex<(Instant, u32)>,
    valid: AtomicBool,
    stop: AtomicBool,
    last_ok: Mutex<Instant>,
    query: Mutex<()>,
    association: Mutex<Option<Association>>,
}
#[derive(Clone)]
struct Association {
    root: (u64, u64),
    namespaces: BTreeMap<String, (u64, u64)>,
}
impl Association {
    fn check(&self, pid: u32) -> io::Result<()> {
        let root = std::fs::metadata(format!("/proc/{pid}/root"))?;
        if (root.dev(), root.ino()) != self.root {
            return Err(invalid("Podman init root changed"));
        }
        for (name, expected) in &self.namespaces {
            let stat = std::fs::metadata(format!("/proc/{pid}/ns/{name}"))?;
            if (stat.dev(), stat.ino()) != *expected {
                return Err(invalid("Podman init namespace changed"));
            }
        }
        Ok(())
    }
}
impl Shared {
    fn valid(&self) -> bool {
        if self
            .last_ok
            .lock()
            .is_ok_and(|last| last.elapsed() <= MAX_STALENESS)
            && live(&self.init)
            && live(&self.peer)
            && stream_live(&self.event_watch)
        {
            self.valid.load(Ordering::Acquire)
        } else {
            self.valid.store(false, Ordering::Release);
            false
        }
    }
    fn check(&self, outer: &dyn Fn() -> io::Result<()>) -> io::Result<()> {
        let result = (|| {
            if !self.valid() {
                return Err(invalid("Podman lifecycle evidence lost"));
            }
            let deadline = Instant::now() + QUERY_TIMEOUT;
            let check = || {
                outer()?;
                if self.stop.load(Ordering::Acquire)
                    || !self.valid.load(Ordering::Acquire)
                    || Instant::now() >= deadline
                {
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    Ok(())
                }
            };
            // Never queue indefinitely behind a resolver operation.
            let _query = loop {
                check()?;
                match self.query.try_lock() {
                    Ok(lock) => break lock,
                    Err(std::sync::TryLockError::WouldBlock) => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => return Err(invalid("Podman query lock poisoned")),
                }
            };
            self.drain_events(&check)?;
            let response = self.endpoint.get(
                &format!(
                    "/v5.0.0/libpod/containers/{}/json",
                    self.evidence.selector.container_name
                ),
                &check,
            )?;
            if response.api_version != self.evidence.manager_version
                || response.peer.pid as u32 != self.evidence.peer_pid
            {
                return Err(invalid("Podman service generation changed"));
            }
            let snapshot = Snapshot::parse(
                response.json(&check)?,
                &self.evidence.selector.container_name,
            )?;
            if snapshot.id != self.evidence.container_id
                || snapshot.pid != self.evidence.init_pid
                || snapshot.started != self.evidence.started_at
                || snapshot.configuration != self.evidence.configuration_sha256
                || start_ticks(snapshot.pid)? != self.evidence.init_start_ticks
                || start_ticks(self.evidence.peer_pid)? != self.evidence.peer_start_ticks
                || !live(&self.init)
                || !live(&self.peer)
            {
                return Err(invalid("Podman generation or configuration changed"));
            }
            self.endpoint.check()?;
            self.drain_events(&check)?;
            manager_membership(self.evidence.init_pid, &self.evidence.container_id)?;
            if let Some(association) = self
                .association
                .lock()
                .map_err(|_| invalid("Podman association poisoned"))?
                .as_ref()
            {
                association.check(self.evidence.init_pid)?;
            }
            check()?;
            if !self.valid() {
                return Err(invalid("Podman lifecycle invalidated"));
            }
            *self
                .last_ok
                .lock()
                .map_err(|_| invalid("Podman monitor poisoned"))? = Instant::now();
            Ok(())
        })();
        if result.is_err() {
            self.valid.store(false, Ordering::Release);
        }
        result
    }
    fn drain_events(&self, check: &dyn Fn() -> io::Result<()>) -> io::Result<()> {
        if !stream_live(&self.event_watch) {
            return Err(invalid("Podman event stream disconnected"));
        }
        let mut events = loop {
            check()?;
            match self.events.try_lock() {
                Ok(events) => break events,
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err(invalid("Podman event parser poisoned")),
            }
        };
        loop {
            check()?;
            let mut poll = libc::pollfd {
                fd: self.event_watch.as_raw_fd(),
                events: libc::POLLIN | libc::POLLRDHUP,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, 0) } < 0
                || poll.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                    != 0
            {
                return Err(invalid("Podman event stream lost"));
            }
            if !events.pending() && poll.revents & libc::POLLIN == 0 {
                return Ok(());
            }
            let event = match events.event(check) {
                Ok(event) => event,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if events.pending() {
                        continue;
                    }
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let mut rate = self
                .event_rate
                .lock()
                .map_err(|_| invalid("Podman event limiter poisoned"))?;
            if rate.0.elapsed() >= Duration::from_secs(1) {
                *rate = (Instant::now(), 0);
            }
            rate.1 += 1;
            if rate.1 > 256 {
                return Err(invalid("Podman event stream exceeds rate bound"));
            }
            let kind = event
                .get("Type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| invalid("malformed Podman event"))?;
            if kind == "container" {
                let (Some(id), Some(name), Some(status)) = (
                    event.get("ID").and_then(|v| v.as_str()),
                    event.get("Name").and_then(|v| v.as_str()),
                    event.get("Status").and_then(|v| v.as_str()),
                ) else {
                    return Err(invalid("malformed Podman container event"));
                };
                if id.len() != 64
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || name.len() > 128
                    || status.is_empty()
                    || status.len() > 64
                {
                    return Err(invalid("invalid Podman event identity"));
                }
                if id == self.evidence.container_id {
                    return Err(invalid("Podman lifecycle event invalidated the binding"));
                }
            }
        }
    }
}
pub(crate) struct Guard {
    state: Arc<Shared>,
    monitor: Option<JoinHandle<()>>,
    // Close/join actual resources before refunding their accounting.
    _resources: Reservation,
}
impl Guard {
    pub(crate) fn acquire(
        selector: PodmanSelector,
        owner: u32,
        budget: &Budget,
        outer: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        selector.validate().map_err(io::Error::other)?;
        let resources = budget
            .reserve_child_resources(
                owner,
                Charge {
                    target_fds: 20,
                    helpers: 1,
                    ..Default::default()
                },
            )
            .ok_or(io::ErrorKind::WouldBlock)?;
        let endpoint = Endpoint::open(Path::new(&selector.endpoint))?;
        let deadline = Instant::now() + QUERY_TIMEOUT;
        let check = || {
            outer()?;
            if Instant::now() >= deadline {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Ok(())
            }
        };
        // The provisional lookup supplies only a filter hint. Events must be
        // scoped by full object ID: the journal backend can contain equal names
        // from other engines/namespaces. No evidence or process pins are issued
        // until the filtered stream is acknowledged and a fresh lookup agrees.
        let hint = Snapshot::parse(
            endpoint
                .get(
                    &format!("/v5.0.0/libpod/containers/{}/json", selector.container_name),
                    &check,
                )?
                .json(&check)?,
            &selector.container_name,
        )?;
        if hint.id.len() != 64
            || !hint
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("invalid Podman object filter hint"));
        }
        let events = endpoint.get(
            &format!(
                "/v5.0.0/libpod/events?stream=true&filters=%7B%22container%22%3A%5B%22{}%22%5D%7D",
                hint.id
            ),
            &check,
        )?;
        events.require_event_stream()?;
        let peer_pid = events.peer.pid as u32;
        let peer = pidfd(peer_pid)?;
        let peer_ticks = start_ticks(peer_pid)?;
        let response = endpoint.get(
            &format!("/v5.0.0/libpod/containers/{}/json", selector.container_name),
            &check,
        )?;
        if response.api_version != events.api_version || response.peer.pid as u32 != peer_pid {
            return Err(invalid("incoherent Podman service acquisition"));
        }
        let snapshot = Snapshot::parse(response.json(&check)?, &selector.container_name)?;
        if snapshot.id != hint.id {
            return Err(invalid("Podman generation changed during subscription"));
        }
        let init = pidfd(snapshot.pid)?;
        let init_ticks = start_ticks(snapshot.pid)?;
        if !live(&init) || !live(&peer) {
            return Err(invalid("Podman acquisition process exited"));
        }
        let (device, inode) = endpoint.identity();
        let evidence = PodmanEvidence {
            schema: "sigrund.podman-evidence.v1".into(),
            manager_version: events.api_version.clone(),
            selector,
            container_id: snapshot.id,
            init_pid: snapshot.pid,
            init_start_ticks: init_ticks,
            started_at: snapshot.started,
            configuration_sha256: snapshot.configuration,
            endpoint_device: device.to_string(),
            endpoint_inode: inode.to_string(),
            peer_pid,
            peer_start_ticks: peer_ticks,
        };
        evidence.validate().map_err(io::Error::other)?;
        let event_watch = events.watch()?;
        let state = Arc::new(Shared {
            endpoint,
            evidence,
            init,
            peer,
            event_watch,
            events: Mutex::new(events),
            event_rate: Mutex::new((Instant::now(), 0)),
            valid: AtomicBool::new(true),
            stop: AtomicBool::new(false),
            last_ok: Mutex::new(Instant::now()),
            query: Mutex::new(()),
            association: Mutex::new(None),
        });
        state.check(outer)?;
        let monitor_state = state.clone();
        let monitor = std::thread::Builder::new()
            .name("podman-lifecycle".into())
            .spawn(move || monitor(monitor_state))?;
        Ok(Self {
            state,
            monitor: Some(monitor),
            _resources: resources,
        })
    }
    pub(crate) fn verify_anchor(&self, anchor: &dyn CapturedAnchor) -> io::Result<()> {
        let result = (|| {
            self.state.check(&|| Ok(()))?;
            // Supplementary association only: G-01 owns the destination.
            let root = anchor.root().metadata()?;
            let namespaces = anchor
                .acquisition()
                .namespaces
                .iter()
                .map(|(name, identity)| {
                    Ok((
                        name.clone(),
                        (
                            identity
                                .device
                                .parse()
                                .map_err(|_| invalid("invalid namespace device"))?,
                            identity
                                .inode
                                .parse()
                                .map_err(|_| invalid("invalid namespace inode"))?,
                        ),
                    ))
                })
                .collect::<io::Result<BTreeMap<_, _>>>()?;
            let association = Association {
                root: (root.dev(), root.ino()),
                namespaces,
            };
            association.check(self.state.evidence.init_pid)?;
            *self
                .state
                .association
                .lock()
                .map_err(|_| invalid("Podman association poisoned"))? = Some(association);
            self.state.check(&|| Ok(()))
        })();
        if result.is_err() {
            self.state.valid.store(false, Ordering::Release);
        }
        result
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::Release);
        self.state.valid.store(false, Ordering::Release);
        if let Some(thread) = self.monitor.take() {
            let _ = thread.join();
        }
    }
}
fn monitor(state: Arc<Shared>) {
    let check = || {
        if state.stop.load(Ordering::Acquire) || !state.valid.load(Ordering::Acquire) {
            Err(io::ErrorKind::Interrupted.into())
        } else {
            Ok(())
        }
    };
    let mut next = Instant::now();
    while check().is_ok() {
        if Instant::now() >= next {
            if state.check(&check).is_err() {
                break;
            }
            next = Instant::now() + CHECK_INTERVAL;
        } else {
            let deadline = Instant::now() + QUERY_TIMEOUT;
            let bounded = || {
                check()?;
                if Instant::now() >= deadline {
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    Ok(())
                }
            };
            if state.drain_events(&bounded).is_err() {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    state.valid.store(false, Ordering::Release);
}
/// Adapter owns both dependencies; all normal acquisition/execution operations
/// continue using the captured anchor, and every fast watch sees manager loss.
pub(crate) struct ManagedAnchor {
    pub(crate) anchor: Box<dyn CapturedAnchor>,
    pub(crate) guard: Guard,
}
impl CapturedAnchor for ManagedAnchor {
    fn manager_evidence(&self) -> Option<&PodmanEvidence> {
        Some(&self.guard.state.evidence)
    }
    fn acquisition(&self) -> &sigrund_core::namespace::Acquisition {
        self.anchor.acquisition()
    }
    fn root(&self) -> &File {
        self.anchor.root()
    }
    fn alive(&self) -> bool {
        self.guard.state.valid() && self.anchor.alive()
    }
    fn executable_roots(&self) -> BTreeMap<String, FsIdentity> {
        self.anchor.executable_roots()
    }
    fn directory(&self, path: &Path, check: &dyn Fn() -> io::Result<()>) -> io::Result<File> {
        if !self.guard.state.valid() {
            return Err(invalid("Podman dependency invalidated"));
        }
        self.anchor.directory(path, check)
    }
    fn namespace_files(&self) -> &[File] {
        self.anchor.namespace_files()
    }
    fn revalidate(&self) -> io::Result<()> {
        self.guard.verify_anchor(self.anchor.as_ref())?;
        self.anchor.revalidate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_watch_rejects_disconnect_even_with_unread_bytes() {
        use std::io::Write;
        let (stream, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let descriptor: OwnedFd = stream.into();
        assert!(stream_live(&descriptor));
        writer.write_all(b"queued event bytes").unwrap();
        drop(writer);
        assert!(!stream_live(&descriptor));
        let process = pidfd(std::process::id()).unwrap();
        assert!(
            live(&process),
            "live peer process cannot prove stream continuity"
        );
    }
    fn inspect() -> serde_json::Value {
        serde_json::json!({"Id":"a1".repeat(32),"Name":"service-b","Namespace":"", "State":{"Running":true,"Paused":false,"Restarting":false,"Dead":false,"Pid":4242,"StartedAt":"2026-11-10T12:00:00Z"},"Config":{"Env":["MODE=original"],"Labels":{"owner":"untrusted"}},"HostConfig":{"CgroupManager":"systemd","PidMode":"private"},"Mounts":[],"ProcessLabel":"container_t","MountLabel":"container_file_t","AppArmorProfile":"","Image":"abc","Rootfs":"","Dependencies":[]})
    }
    #[test]
    fn snapshots_reject_scope_and_state_substitution_and_bind_configuration() {
        let original = inspect();
        let before = Snapshot::parse(original.clone(), "service-b").unwrap();
        for (pointer, value) in [
            ("/Name", serde_json::json!("other")),
            ("/Namespace", serde_json::json!("other-tenant")),
            ("/State/Pid", serde_json::json!(0)),
            ("/State/Running", serde_json::json!(false)),
            ("/State/Paused", serde_json::json!(true)),
            ("/Config", serde_json::Value::Null),
            ("/Mounts", serde_json::Value::Null),
            ("/HostConfig/PidMode", serde_json::json!("host")),
            ("/HostConfig/CgroupManager", serde_json::json!("cgroupfs")),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(Snapshot::parse(changed, "service-b").is_err(), "{pointer}");
        }
        for pointer in ["/Config/Labels/owner", "/Config/Env/0", "/ProcessLabel"] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = serde_json::json!("changed");
            assert_ne!(
                before.configuration,
                Snapshot::parse(changed, "service-b").unwrap().configuration,
                "{pointer}"
            );
        }
    }
    #[test]
    #[ignore = "requires initial-userns root and the disposable Podman probe container"]
    fn installed_manager_generation_gate() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let selector = PodmanSelector {
            schema: "sigrund.podman-selector.v1".into(),
            endpoint: "/run/podman/podman.sock".into(),
            owner_uid: 0,
            manager_namespace: "default".into(),
            container_name: "sigrund-phase5b-probe".into(),
        };
        let budget = Budget::new(Default::default()).unwrap();
        assert!(
            Guard::acquire(selector.clone(), 0, &budget, &|| Err(
                io::ErrorKind::Interrupted.into()
            ))
            .is_err()
        );
        assert_eq!(budget.usage(0).0, Charge::default());
        let guard = Guard::acquire(selector.clone(), 0, &budget, &|| Ok(())).unwrap();
        guard.state.check(&|| Ok(())).unwrap();
        assert!(guard.state.valid());
        let status = std::process::Command::new("podman")
            .args([
                "rename",
                "sigrund-phase5b-probe",
                "sigrund-phase5b-probe-old",
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let deadline = Instant::now() + Duration::from_secs(4);
        while guard.state.valid() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !guard.state.valid(),
            "old manager generation survived name replacement"
        );
        assert!(
            live(&guard.state.init),
            "the surviving init is the replacement negative control"
        );
        assert!(
            std::process::Command::new("podman")
                .args([
                    "rename",
                    "sigrund-phase5b-probe-old",
                    "sigrund-phase5b-probe"
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            !guard.state.valid(),
            "name restoration revived an old binding"
        );
        drop(guard);
        assert_eq!(budget.usage(0).0, Charge::default());
        let fresh = Guard::acquire(selector, 0, &budget, &|| Ok(())).unwrap();
        fresh.state.check(&|| Ok(())).unwrap();
        drop(fresh);
        assert_eq!(budget.usage(0).0, Charge::default());
        // Replacing the configured directory must invalidate even when the
        // pinned old endpoint and its server remain live.
        let directory =
            std::env::temp_dir().join(format!("sigrund-podman-endpoint-{}", std::process::id()));
        let retired = directory.with_extension("retired");
        std::fs::create_dir(&directory).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(directory.join("api.sock")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            directory.join("api.sock"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let endpoint = Endpoint::open(&directory.join("api.sock")).unwrap();
        endpoint.check().unwrap();
        std::fs::rename(&directory, &retired).unwrap();
        std::fs::create_dir(&directory).unwrap();
        assert!(endpoint.check().is_err());
        drop(endpoint);
        drop(listener);
        std::fs::remove_dir_all(retired).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
