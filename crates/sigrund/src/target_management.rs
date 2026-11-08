//! Bounded host-administrator management and dedicated-anchor rendezvous.
//! Neither endpoint returns target information to ordinary requesters.
use crate::{daemon::BoundSocket, target_registry::TargetRegistry};
use serde::{Deserialize, Serialize};
use sigrund_core::{
    host_budget::{Budget, Charge, Reservation},
    namespace::Constraints,
};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::net::UnixStream,
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub fn management_path(socket: &Path) -> PathBuf {
    let mut path = socket.as_os_str().to_owned();
    path.push(".management");
    path.into()
}
pub fn anchor_path(socket: &Path) -> PathBuf {
    let mut path = socket.as_os_str().to_owned();
    path.push(".anchor");
    path.into()
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Register {
        id: String,
        daemon_pid: u32,
        owner_uid: u32,
        security_profile: String,
    },
    Revoke {
        id: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub success: bool,
    pub message: String,
}
fn invalid(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}
fn parse_request(bytes: &[u8]) -> io::Result<Request> {
    sigrund_core::json::preflight(bytes, 16, 4096).map_err(invalid)?;
    serde_json::from_slice(bytes).map_err(invalid)
}

fn credentials(socket: &impl AsRawFd) -> io::Result<libc::ucred> {
    let mut peer = unsafe { std::mem::zeroed::<libc::ucred>() };
    let mut size = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != size_of::<libc::ucred>()
        || peer.pid <= 0
        || peer.uid == u32::MAX
        || peer.gid == u32::MAX
    {
        return Err(invalid("invalid management peer credentials"));
    }
    Ok(peer)
}
fn line(socket: &mut UnixStream, check: impl Fn() -> io::Result<()>) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut byte = [0];
    loop {
        check()?;
        match socket.read(&mut byte) {
            Ok(1) if byte == *b"\n" => return Ok(result),
            Ok(1) if result.len() < 65_536 => result.push(byte[0]),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(_) => return Err(invalid("management request exceeds bound")),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                let mut descriptor = libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                unsafe {
                    libc::poll(&mut descriptor, 1, 10);
                }
            }
            Err(error) => return Err(error),
        }
    }
}
fn send(socket: &mut UnixStream, response: &Response) -> io::Result<()> {
    socket.set_nonblocking(false)?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    socket.write_all(&serde_json::to_vec(response)?)?;
    socket.write_all(b"\n")
}

struct Pending {
    socket: crate::socket_disposal::Socket,
    uid: u32,
    expires: Instant,
}
pub struct Management {
    control: BoundSocket,
    anchors: BoundSocket,
    registry: Arc<TargetRegistry>,
    profiles: Vec<Constraints>,
    budget: Budget,
    disposal: crate::socket_disposal::SocketDisposal,
    _resources: Arc<Reservation>,
}
pub struct Serving {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Management {
    /// Called before any public listener is published. Existing pathnames are
    /// refused using the same pinned-directory contract as the client sockets.
    pub fn bind(
        socket: &Path,
        registry: Arc<TargetRegistry>,
        profiles: Vec<Constraints>,
        budget: Budget,
    ) -> io::Result<Self> {
        let resources = Arc::new(
            budget
                .reserve(
                    0,
                    Charge {
                        target_fds: 5,
                        ..Default::default()
                    },
                )
                .ok_or(io::ErrorKind::WouldBlock)?,
        );
        let disposal = crate::socket_disposal::SocketDisposal::new()?;
        let control = BoundSocket::bind(&management_path(socket), 0o600)?;
        let mut anchors = BoundSocket::bind(&anchor_path(socket), 0o666)?;
        anchors.protect_close(
            disposal
                .reserve()
                .expect("new anchor disposal pool")
                .with_resources(resources.clone()),
        );
        control.listen()?;
        anchors.listen()?;
        Ok(Self {
            control,
            anchors,
            registry,
            profiles,
            budget,
            disposal,
            _resources: resources,
        })
    }
    pub fn start(self) -> io::Result<Serving> {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::Builder::new()
            .name("target-management".into())
            .spawn(move || self.run(&stopping))?;
        Ok(Serving {
            stop,
            thread: Some(thread),
        })
    }
    fn accept(&self, listener: &BoundSocket) -> io::Result<Option<(UnixStream, Reservation)>> {
        let Some(reservation) = self.budget.reserve(
            0,
            Charge {
                target_fds: 1,
                ..Default::default()
            },
        ) else {
            return Ok(None);
        };
        let raw = unsafe {
            libc::accept4(
                listener.fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };
        if raw < 0 {
            let error = io::Error::last_os_error();
            return if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        Ok(Some((unsafe { UnixStream::from_raw_fd(raw) }, reservation)))
    }
    fn run(self, stopping: &Arc<AtomicBool>) {
        let mut pending = BTreeMap::<u32, Pending>::new();
        let mut monitor_at = Instant::now();
        let (acquire_tx, acquire_rx) = std::sync::mpsc::sync_channel::<Box<dyn FnOnce() + Send>>(1);
        let acquiring = Arc::new(AtomicBool::new(false));
        let busy = acquiring.clone();
        // Keep the launching thread alive: PDEATHSIG is tied to its lifetime,
        // even while the daemon process itself remains alive.
        let acquisition = std::thread::Builder::new()
            .name("target-acquisition".into())
            .spawn(move || {
                while let Ok(job) = acquire_rx.recv() {
                    job();
                    busy.store(false, Ordering::Release);
                }
            })
            .unwrap_or_else(|_| std::process::abort());
        while !stopping.load(Ordering::Acquire) {
            self.disposal.drain();
            if Instant::now() >= monitor_at {
                self.registry.monitor();
                monitor_at = Instant::now() + Duration::from_millis(100);
            }
            pending.retain(|_, peer| {
                let mut fd = libc::pollfd {
                    fd: peer.socket.as_raw_fd(),
                    events: libc::POLLRDHUP,
                    revents: 0,
                };
                unsafe {
                    libc::poll(&mut fd, 1, 0);
                }
                peer.expires > Instant::now()
                    && fd.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) == 0
            });
            if pending.len() < 16
                && let Some(permit) = self.disposal.reserve()
                && let Ok(Some((socket, temporary))) = self.accept(&self.anchors)
            {
                let mut socket = permit
                    .with_resources(Arc::new(temporary))
                    .socket(socket.into());
                if let Ok(peer) = credentials(&socket)
                    && let Some(resources) = self.budget.reserve(
                        peer.uid,
                        Charge {
                            target_fds: 1,
                            ..Default::default()
                        },
                    )
                {
                    socket.set_resources(resources);
                    if pending.values().filter(|p| p.uid == peer.uid).count() < 4 {
                        // One authenticated connector per daemon PID. Do not
                        // overwrite a retained rendezvous with a second socket.
                        pending.entry(peer.pid as u32).or_insert(Pending {
                            socket,
                            uid: peer.uid,
                            expires: Instant::now() + Duration::from_secs(10),
                        });
                    }
                }
            }
            if let Ok(Some((mut socket, resources))) = self.accept(&self.control) {
                if credentials(&socket).is_ok_and(|peer| peer.uid == 0) {
                    let deadline = Instant::now() + Duration::from_secs(10);
                    let check = || {
                        if stopping.load(Ordering::Acquire) || Instant::now() >= deadline {
                            Err(io::ErrorKind::TimedOut.into())
                        } else {
                            Ok(())
                        }
                    };
                    let result = (|| {
                        let bytes = line(&mut socket, check)?;
                        let request = parse_request(&bytes)?;
                        match request {
                            Request::Revoke { id } => self.registry.revoke(&id).map(|_| false),
                            Request::Register {
                                id,
                                daemon_pid,
                                owner_uid,
                                security_profile,
                            } => {
                                let profile = self
                                    .profiles
                                    .iter()
                                    .find(|p| p.profile_id == security_profile)
                                    .ok_or_else(|| {
                                        invalid("namespace security profile unavailable")
                                    })?
                                    .clone();
                                if acquiring.load(Ordering::Acquire) {
                                    return Err(io::ErrorKind::WouldBlock.into());
                                }
                                let slot = self.registry.reserve_registration(
                                    owner_uid,
                                    self.registry.capture_fd_count(),
                                )?;
                                let connection_charge = self
                                    .budget
                                    .reserve(
                                        0,
                                        Charge {
                                            target_fds: 1,
                                            ..Default::default()
                                        },
                                    )
                                    .ok_or(io::ErrorKind::WouldBlock)?;
                                let mut reply = socket.try_clone()?;
                                let peer = pending
                                    .remove(&daemon_pid)
                                    .filter(|peer| {
                                        peer.uid == owner_uid && peer.expires > Instant::now()
                                    })
                                    .ok_or_else(|| {
                                        invalid("matching dedicated anchor has not connected")
                                    })?;
                                let stop = stopping.clone();
                                acquiring.store(true, Ordering::Release);
                                if acquire_tx
                                    .try_send(Box::new(move || {
                                        let result = slot.capture_and_publish(
                                            id,
                                            daemon_pid,
                                            profile,
                                            peer.socket,
                                            || {
                                                if stop.load(Ordering::Acquire)
                                                    || Instant::now() >= deadline
                                                {
                                                    Err(io::ErrorKind::TimedOut.into())
                                                } else {
                                                    Ok(())
                                                }
                                            },
                                        );
                                        let response = match result {
                                            Ok(()) => Response {
                                                success: true,
                                                message: "completed".into(),
                                            },
                                            Err(error) => Response {
                                                success: false,
                                                message: error.to_string(),
                                            },
                                        };
                                        let _ = send(&mut reply, &response);
                                        drop(reply);
                                        drop(connection_charge);
                                    }))
                                    .is_err()
                                {
                                    std::process::abort();
                                }
                                Ok(true)
                            }
                        }
                    })();
                    let response = match result {
                        Ok(true) => None,
                        Ok(false) => Some(Response {
                            success: true,
                            message: "completed".into(),
                        }),
                        Err(error) => Some(Response {
                            success: false,
                            message: error.to_string(),
                        }),
                    };
                    if let Some(response) = response {
                        let _ = send(&mut socket, &response);
                    }
                }
                drop(socket);
                drop(resources);
            }
            let mut descriptors = [
                libc::pollfd {
                    fd: self.control.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.anchors.fd(),
                    events: if pending.len() < 16 && self.disposal.available() {
                        libc::POLLIN
                    } else {
                        0
                    },
                    revents: 0,
                },
            ];
            unsafe {
                libc::poll(descriptors.as_mut_ptr(), 2, 10);
            }
        }
        drop(pending);
        while self.disposal.used() > 1 {
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(acquire_tx);
        let _ = acquisition.join();
        self.registry.revoke_all();
        while !self.registry.disposal_idle() {
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(self.anchors);
        while self.disposal.used() != 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Serving {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub fn is_idle(&self) -> bool {
        self.thread
            .as_ref()
            .is_none_or(|thread| thread.is_finished())
    }
}
impl Drop for Serving {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
/// Root CLI request. The endpoint authenticates the caller independently.
pub fn execute(path: &Path, request: &Request) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut socket = UnixStream::connect(path)?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    socket.write_all(&serde_json::to_vec(request)?)?;
    socket.write_all(b"\n")?;
    socket.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let bytes = line(&mut socket, || {
        if Instant::now() >= deadline {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(())
        }
    })?;
    sigrund_core::json::preflight(&bytes, 16, 4096).map_err(invalid)?;
    let response: Response = serde_json::from_slice(&bytes)?;
    if response.success {
        Ok(())
    } else {
        Err(invalid(response.message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn management_requests_are_strict_and_separate_from_submission() {
        assert!(
            matches!(parse_request(br#"{"operation":"revoke","id":"B"}"#).unwrap(), Request::Revoke { id } if id == "B")
        );
        assert!(parse_request(br#"{"operation":"revoke","id":"B","id":"C"}"#).is_err());
        assert!(parse_request(br#"{"operation":"revoke","id":"B","owner_uid":1000}"#).is_err());
        assert!(parse_request(br#"{"operation":"register","id":"B","daemon_pid":10,"owner_uid":1000,"security_profile":"service"}"#).is_ok());
        assert!(parse_request(br#"{"operation":"register","id":"B","daemon_pid":10,"security_profile":"service"}"#).is_err());
        assert!(parse_request(br#"{"mode":"thin_csr","version":"3.0"}"#).is_err());
        assert_eq!(
            management_path(Path::new("/run/sigrund.sock")),
            Path::new("/run/sigrund.sock.management")
        );
        assert_eq!(
            anchor_path(Path::new("/run/sigrund.sock")),
            Path::new("/run/sigrund.sock.anchor")
        );
    }
}
