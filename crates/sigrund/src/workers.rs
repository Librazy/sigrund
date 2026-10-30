//! Shared, reserved I/O workers. Caller rights are received and destroyed only
//! here. A validated request can return to the same worker without releasing
//! its reservation or transferring raw descriptor ownership to the coordinator.
use crate::transport::{ApprovalReader, ControlReader, invalid, validate_stdio_checked};
use sigrund_core::{config::DaemonConfig, protocol::ClientHello};
use std::{
    collections::HashMap,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    time::{Duration, Instant},
};

pub(crate) struct ValidationHandle(Arc<AtomicBool>);
impl Drop for ValidationHandle {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Available only while executing on a reserved worker. Caller rights precede
/// snapshots so their possibly blocking close cannot release snapshot RAM early.
pub(crate) struct ValidatedRequest {
    pub hello: ClientHello,
    pub rights: Vec<OwnedFd>,
    pub snapshots: Option<MeasuredSnapshots>,
    pub prepared: Option<crate::preparation::Prepared>,
    pub policy: Arc<DaemonConfig>,
    pub requester_uid: u32,
    pub deadline: Instant,
    pub cancelled: Arc<AtomicBool>,
}
pub(crate) struct MeasuredSnapshots {
    pub executable: crate::snapshot::SealedSnapshot,
    pub stdin: Option<crate::snapshot::SealedSnapshot>,
}
impl ValidatedRequest {
    pub fn check(&self) -> io::Result<()> {
        check(&self.cancelled, self.deadline)?;
        if self.snapshots.as_ref().is_some_and(|snapshots| {
            snapshots.executable.digest.bytes > self.policy.max_executable_bytes
                || snapshots
                    .stdin
                    .as_ref()
                    .is_some_and(|stdin| stdin.digest.bytes > self.policy.max_stdin_bytes)
        }) {
            return Err(invalid("snapshot exceeds captured policy"));
        }
        Ok(())
    }
}

type Continuation = Box<dyn FnOnce(&mut ValidatedRequest) -> io::Result<()> + Send>;
/// The coordinator may inspect syntax, schedule a continuation, or dispose of
/// this lease. Its destructor enqueues cleanup; it never closes caller FDs.
pub(crate) struct RequestLease {
    token: u64,
    request: Option<Box<ValidatedRequest>>,
    sender: SyncSender<Work>,
}
impl RequestLease {
    pub fn matches_admission(&self, uid: u32, policy: &Arc<DaemonConfig>) -> bool {
        let request = self.request.as_ref().expect("live lease");
        request.requester_uid == uid && Arc::ptr_eq(&request.policy, policy)
    }
    pub fn hello(&self) -> &ClientHello {
        &self.request.as_ref().expect("live lease").hello
    }
    pub fn prepared(&self) -> Option<&crate::preparation::Prepared> {
        self.request.as_ref().expect("live lease").prepared.as_ref()
    }
    pub fn continue_on_worker(
        mut self,
        operation: impl FnOnce(&mut ValidatedRequest) -> io::Result<()> + Send + 'static,
    ) {
        let request = self.request.take().expect("live lease");
        enqueue(
            &self.sender,
            Work::Continue {
                token: self.token,
                request,
                operation: Box::new(operation),
                sender: self.sender.clone(),
            },
        );
    }
}
impl Drop for RequestLease {
    fn drop(&mut self) {
        if let Some(request) = self.request.take() {
            enqueue(
                &self.sender,
                Work::Dispose {
                    token: self.token,
                    request,
                },
            );
        }
    }
}

// Exclusivity of a reservation permits exactly one outstanding command: its
// task or lease owns the request. Workers catch operation panics and keep their
// receiver alive until all leases are returned, even after pool shutdown.
fn enqueue(sender: &SyncSender<Work>, work: Work) {
    if let Err(error) = sender.try_send(work) {
        // An internal ownership invariant failed. Do not run arbitrary-FD
        // destructors on this thread while unwinding the channel error.
        std::mem::forget(error);
        std::process::abort();
    }
}

enum Work {
    Read {
        token: u64,
        socket: OwnedFd,
        uid: u32,
        policy: Arc<DaemonConfig>,
        broker: bool,
        deadline: Instant,
        cancelled: Arc<AtomicBool>,
        sender: SyncSender<Work>,
    },
    Continue {
        token: u64,
        request: Box<ValidatedRequest>,
        operation: Continuation,
        sender: SyncSender<Work>,
    },
    Dispose {
        token: u64,
        request: Box<ValidatedRequest>,
    },
}

pub(crate) enum Completion {
    Validated {
        token: u64,
        result: io::Result<RequestLease>,
    },
    Released {
        token: u64,
    },
}
struct Reservation {
    uid: u32,
    slot: usize,
    cancelled: Arc<AtomicBool>,
}
pub(crate) struct IoWorkers {
    senders: Vec<SyncSender<Work>>,
    completions: Receiver<Completion>,
    reservations: HashMap<u64, Reservation>,
    wake: Arc<OwnedFd>,
    per_uid: usize,
}

fn check(cancelled: &AtomicBool, deadline: Instant) -> io::Result<()> {
    if cancelled.load(Ordering::Acquire) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "request cancelled",
        ))
    } else if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "request deadline expired",
        ))
    } else {
        Ok(())
    }
}
fn wait_readable(fd: i32, cancelled: &AtomicBool, deadline: Instant) -> io::Result<()> {
    check(cancelled, deadline)?;
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_millis(20))
        .as_millis()
        .max(1) as i32;
    let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
    if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
        return Err(io::Error::last_os_error());
    }
    check(cancelled, deadline)
}
fn read_request(
    socket: OwnedFd,
    uid: u32,
    policy: Arc<DaemonConfig>,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
) -> io::Result<ValidatedRequest> {
    let mut reader = ControlReader::new(true);
    let frame = loop {
        check(&cancelled, deadline)?;
        if let Some(frame) = reader.read(socket.as_raw_fd(), Instant::now())? {
            break frame;
        }
        wait_readable(
            socket.as_raw_fd(),
            &cancelled,
            reader.deadline().unwrap_or(deadline).min(deadline),
        )?;
    };
    drop(socket);
    let hello = ClientHello::parse_request(&frame.payload).map_err(|e| invalid(e.to_string()))?;
    policy
        .mvp
        .as_ref()
        .expect("startup requires MVP")
        .validate_for_peer(&hello, uid)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;
    let request = ValidatedRequest {
        hello,
        rights: frame.rights,
        snapshots: None,
        prepared: None,
        policy,
        requester_uid: uid,
        deadline,
        cancelled,
    };
    validate_stdio_checked(&request.hello, &request.rights, || request.check())?;
    request.check()?;
    Ok(request)
}
fn read_broker(
    socket: OwnedFd,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> io::Result<ValidatedRequest> {
    let mut reader = ApprovalReader::default();
    loop {
        check(cancelled, deadline)?;
        if reader.read(socket.as_raw_fd(), Instant::now())?.is_some() {
            return Err(invalid("unsolicited approval response"));
        }
        wait_readable(socket.as_raw_fd(), cancelled, deadline)?;
    }
}
fn notify(completed: &SyncSender<Completion>, wake: &OwnedFd, completion: Completion) {
    // On coordinator shutdown, dropping a failed successful result schedules
    // disposal back onto this worker; its receiver remains live.
    let _ = completed.send(completion);
    let one = 1u64;
    loop {
        if unsafe { libc::write(wake.as_raw_fd(), (&one as *const u64).cast(), 8) } >= 0
            || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            break;
        }
    }
}
fn publish(
    token: u64,
    result: io::Result<Box<ValidatedRequest>>,
    sender: SyncSender<Work>,
    completed: &SyncSender<Completion>,
    wake: &OwnedFd,
) {
    let result = result.map(|request| RequestLease {
        token,
        request: Some(request),
        sender,
    });
    notify(completed, wake, Completion::Validated { token, result });
}

impl IoWorkers {
    pub fn new(config: &DaemonConfig) -> io::Result<Self> {
        let count = config.max_io_workers_global as usize;
        let raw = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let wake = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
        let (completed, completions) = sync_channel(count * 2);
        let mut senders = Vec::with_capacity(count);
        for slot in 0..count {
            let (sender, tasks) = sync_channel::<Work>(1);
            let completed = completed.clone();
            let wake = wake.clone();
            std::thread::Builder::new()
                .name(format!("request-io-{slot}"))
                .spawn(move || {
                    for work in tasks {
                        match work {
                            Work::Read {
                                token,
                                socket,
                                uid,
                                policy,
                                broker,
                                deadline,
                                cancelled,
                                sender,
                            } => {
                                let result = catch_unwind(AssertUnwindSafe(|| {
                                    if broker {
                                        read_broker(socket, &cancelled, deadline)
                                    } else {
                                        read_request(socket, uid, policy, deadline, cancelled)
                                    }
                                }))
                                .unwrap_or_else(|_| Err(invalid("request worker panicked")));
                                publish(token, result.map(Box::new), sender, &completed, &wake);
                            }
                            Work::Continue {
                                token,
                                mut request,
                                operation,
                                sender,
                            } => {
                                let result = catch_unwind(AssertUnwindSafe(|| {
                                    request.check()?;
                                    operation(&mut request)?;
                                    request.check()
                                }))
                                .unwrap_or_else(|_| Err(invalid("request continuation panicked")));
                                let result = match result {
                                    Ok(()) => Ok(request),
                                    Err(error) => {
                                        drop(request);
                                        Err(error)
                                    }
                                };
                                publish(token, result, sender, &completed, &wake);
                            }
                            Work::Dispose { token, request } => {
                                drop(request);
                                notify(&completed, &wake, Completion::Released { token });
                            }
                        }
                    }
                })?;
            senders.push(sender);
        }
        Ok(Self {
            senders,
            completions,
            reservations: HashMap::new(),
            wake,
            per_uid: config.max_io_workers_per_uid as usize,
        })
    }
    pub fn fd(&self) -> i32 {
        self.wake.as_raw_fd()
    }
    pub fn submit(
        &mut self,
        token: u64,
        uid: u32,
        socket: &OwnedFd,
        policy: Arc<DaemonConfig>,
        broker: bool,
        deadline: Instant,
    ) -> io::Result<ValidationHandle> {
        if self
            .reservations
            .values()
            .filter(|task| task.uid == uid)
            .count()
            >= self.per_uid
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "per-UID I/O worker quota exhausted",
            ));
        }
        let slot = (0..self.senders.len())
            .find(|slot| !self.reservations.values().any(|task| task.slot == *slot))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "global I/O worker quota exhausted",
                )
            })?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let socket = socket.try_clone()?;
        enqueue(
            &self.senders[slot],
            Work::Read {
                token,
                uid,
                socket,
                policy,
                broker,
                deadline,
                cancelled: cancelled.clone(),
                sender: self.senders[slot].clone(),
            },
        );
        self.reservations.insert(
            token,
            Reservation {
                uid,
                slot,
                cancelled: cancelled.clone(),
            },
        );
        Ok(ValidationHandle(cancelled))
    }
    pub fn drain(&mut self) -> Vec<Completion> {
        let mut value = 0u64;
        loop {
            if unsafe { libc::read(self.fd(), (&mut value as *mut u64).cast(), 8) } >= 0
                || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
            {
                break;
            }
        }
        let mut results = Vec::new();
        while let Ok(result) = self.completions.try_recv() {
            match &result {
                Completion::Released { token }
                | Completion::Validated {
                    token,
                    result: Err(_),
                } => {
                    self.reservations.remove(token);
                }
                _ => {}
            }
            results.push(result);
        }
        results
    }
}
impl Drop for IoWorkers {
    fn drop(&mut self) {
        for reservation in self.reservations.values() {
            reservation.cancelled.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sigrund_core::framing::{FrameType, encode_frame};
    use std::{
        fs::OpenOptions,
        io::Write,
        mem::{size_of, zeroed},
        os::unix::net::UnixStream,
    };

    fn config() -> Arc<DaemonConfig> {
        let mut config = DaemonConfig::from_toml(
            include_str!("../../../config/sigrund.toml.example")
                .replace(
                    "<strict-padded-base64-32-byte-ed25519-key>",
                    &STANDARD.encode([1; 32]),
                )
                .as_bytes(),
        )
        .unwrap();
        config.mvp = Some(Default::default());
        config.max_io_workers_global = 1;
        config.max_io_workers_per_uid = 1;
        Arc::new(config)
    }
    fn send(socket: &mut UnixStream, fd: i32) {
        let body=serde_json::to_vec(&serde_json::json!({
            "mode":"unsigned_csr_request", "tty_mode":"stdio", "caller_env":{},
            "requested_command":{"allow_interpreted_script":false,"argv":["id"],"cwd":"/",
                "executable_path":"/usr/bin/id","stdin_policy":"null","tty_mode":"stdio"},
            "requested_execution_context":{"capabilities":[],"env_exact":{},"caller_env_allowlist":[],
                "supplementary_gids":[],"target_gid":0,"target_uid":0,"umask":63},
            "requested_policy":{"mode":"one_time","ttl_secs":60}
        })).unwrap();
        let encoded = encode_frame(FrameType::ClientHello, &body).unwrap();
        let mut control = [0usize; 8];
        let mut vector = libc::iovec {
            iov_base: encoded.as_ptr().cast_mut().cast(),
            iov_len: 1,
        };
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = unsafe { libc::CMSG_SPACE((2 * size_of::<i32>()) as _) } as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN((2 * size_of::<i32>()) as _) as _;
            std::ptr::write(libc::CMSG_DATA(header).cast::<i32>(), fd);
            std::ptr::write(libc::CMSG_DATA(header).cast::<i32>().add(1), fd);
            assert_eq!(
                libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                1
            );
        }
        socket.write_all(&encoded[1..]).unwrap();
    }
    fn next(workers: &mut IoWorkers) -> Completion {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let mut results = workers.drain();
            if !results.is_empty() {
                // Each test requests exactly one transition at a time.
                assert_eq!(results.len(), 1);
                return results.pop().unwrap();
            }
            assert!(Instant::now() < deadline, "worker completion timed out");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn lease(completion: Completion) -> RequestLease {
        match completion {
            Completion::Validated { result, .. } => result.unwrap(),
            _ => panic!("unexpected release"),
        }
    }
    #[test]
    fn validated_owner_retains_identity_policy_and_one_worker_across_continuations() {
        let policy = config();
        let mut workers = IoWorkers::new(&policy).unwrap();
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).unwrap();
        let receiver: OwnedFd = receiver.into();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let handle = workers
            .submit(10, 1001, &receiver, policy.clone(), false, deadline)
            .unwrap();
        send(&mut sender, file.as_raw_fd());
        let request = lease(next(&mut workers));
        assert!(request.matches_admission(1001, &policy));
        assert_eq!(request.hello().mode, "unsigned_csr_request");
        assert!(
            workers
                .submit(11, 1001, &receiver, policy.clone(), false, deadline)
                .is_err()
        );
        let coordinator = std::thread::current().id();
        let budget = crate::snapshot::SnapshotBudget::default();
        let measured_budget = budget.clone();
        let (sent, seen) = std::sync::mpsc::channel();
        request.continue_on_worker(move |request| {
            assert_eq!(request.rights.len(), 2);
            assert_eq!(request.requester_uid, 1001);
            assert_eq!(request.deadline, deadline);
            assert!(request.policy.mvp.is_some());
            let mut metadata: libc::stat = unsafe { zeroed() };
            assert_eq!(
                unsafe { libc::fstat(request.rights[0].as_raw_fd(), &mut metadata) },
                0
            );
            assert_eq!(metadata.st_rdev, libc::makedev(1, 3));
            assert_ne!(std::thread::current().id(), coordinator);
            let mut source = tempfile::tempfile()?;
            source.write_all(b"\x7fELFtest")?;
            use std::io::{Seek, SeekFrom};
            source.seek(SeekFrom::Start(0))?;
            request.snapshots = Some(MeasuredSnapshots {
                executable: crate::snapshot::executable(
                    source,
                    &measured_budget,
                    request.requester_uid,
                    &request.policy,
                    || request.check(),
                )?,
                stdin: None,
            });
            sent.send((std::thread::current().id(), request.rights[0].as_raw_fd()))
                .unwrap();
            Ok(())
        });
        let first = seen.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(budget.usage(1001), (8, 8));
        let request = lease(next(&mut workers));
        let (sent, seen) = std::sync::mpsc::channel();
        request.continue_on_worker(move |request| {
            assert_eq!(
                request.snapshots.as_ref().unwrap().executable.digest.bytes,
                8
            );
            sent.send((std::thread::current().id(), request.rights[0].as_raw_fd()))
                .unwrap();
            Ok(())
        });
        assert_eq!(first, seen.recv_timeout(Duration::from_secs(3)).unwrap());
        let request = lease(next(&mut workers));
        assert_eq!(workers.reservations.len(), 1);
        drop(handle);
        let (sent, seen) = std::sync::mpsc::channel();
        request.continue_on_worker(move |_| {
            sent.send(()).unwrap();
            Ok(())
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut rejected = false;
        while !workers.reservations.is_empty() {
            for completion in workers.drain() {
                if let Completion::Validated { result, .. } = completion {
                    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::Interrupted);
                    rejected = true;
                }
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(rejected);
        assert!(seen.try_recv().is_err());
        assert_eq!(budget.usage(1001), (0, 0));
    }
}
