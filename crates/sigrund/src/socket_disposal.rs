//! Bounded final-close ownership for Unix sockets, including unread SCM_RIGHTS.
//! Reserve before accept: even rejecting an unparsed socket can block in close.
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc::{SyncSender, sync_channel},
    },
};

// Includes listeners, admitted sockets, worker-retained sockets and rejected
// sockets awaiting close. Fixed across policy reloads; never spawn replacements.
const CAPACITY: usize = 128;
const WORKERS: usize = 2;

struct Shared {
    sender: SyncSender<Closing>,
    used: AtomicUsize,
    wake: Arc<OwnedFd>,
}

pub(crate) struct Permit(Arc<Shared>);
impl Permit {
    pub fn socket(self, fd: OwnedFd) -> Socket {
        Socket(Arc::new(SocketInner {
            fd: Some(fd),
            permit: Some(self),
        }))
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::AcqRel);
        let one = 1u64;
        loop {
            if unsafe { libc::write(self.0.wake.as_raw_fd(), (&one as *const u64).cast(), 8) } >= 0
                || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
            {
                break;
            }
        }
    }
}

// Drop the descriptor before releasing capacity or waking the coordinator.
struct Closing {
    _fd: OwnedFd,
    _permit: Permit,
}
struct SocketInner {
    fd: Option<OwnedFd>,
    permit: Option<Permit>,
}
impl Drop for SocketInner {
    fn drop(&mut self) {
        let permit = self.permit.take().expect("socket permit");
        let sender = permit.0.sender.clone();
        // UNIX shutdown marks the endpoint closed without releasing its queued
        // rights. Notify the peer promptly even when final disposal is stalled.
        unsafe {
            libc::shutdown(
                self.fd.as_ref().expect("socket descriptor").as_raw_fd(),
                libc::SHUT_RDWR,
            );
        }
        let closing = Closing {
            _fd: self.fd.take().expect("socket descriptor"),
            _permit: permit,
        };
        if let Err(error) = sender.try_send(closing) {
            // Every socket has reserved a queue slot. Never unwind a failed
            // send (and hence close a caller-controlled socket) on this thread.
            std::mem::forget(error);
            std::process::abort();
        }
    }
}

/// Clones share one descriptor and its disposal reservation. The final owner
/// only enqueues; only a disposal worker performs the actual close.
#[derive(Clone)]
pub(crate) struct Socket(Arc<SocketInner>);
impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.0.fd.as_ref().expect("live socket").as_raw_fd()
    }
}

pub(crate) struct SocketDisposal(Arc<Shared>);
impl SocketDisposal {
    pub fn new() -> io::Result<Self> {
        let raw = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let wake = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
        let (sender, receiver) = sync_channel::<Closing>(CAPACITY);
        let receiver = Arc::new(Mutex::new(receiver));
        for slot in 0..WORKERS {
            let receiver = receiver.clone();
            std::thread::Builder::new()
                .name(format!("socket-disposal-{slot}"))
                .spawn(move || {
                    loop {
                        let closing = receiver.lock().expect("socket disposal queue").recv();
                        match closing {
                            Ok(closing) => drop(closing),
                            Err(_) => break,
                        }
                    }
                })?;
        }
        Ok(Self(Arc::new(Shared {
            sender,
            used: AtomicUsize::new(0),
            wake,
        })))
    }
    pub fn reserve(&self) -> Option<Permit> {
        let mut used = self.used();
        while used < CAPACITY {
            match self.0.used.compare_exchange_weak(
                used,
                used + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Permit(self.0.clone())),
                Err(actual) => used = actual,
            }
        }
        None
    }
    pub fn used(&self) -> usize {
        self.0.used.load(Ordering::Acquire)
    }
    pub fn available(&self) -> bool {
        self.used() < CAPACITY
    }
    pub fn fd(&self) -> RawFd {
        self.0.wake.as_raw_fd()
    }
    pub fn drain(&self) {
        let mut value = 0u64;
        loop {
            if unsafe { libc::read(self.fd(), (&mut value as *mut u64).cast(), 8) } >= 0
                || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
            {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::net::UnixStream,
        time::{Duration, Instant},
    };

    #[test]
    fn reserve_before_accept_bounds_all_pending_disposal() {
        let pool = SocketDisposal::new().unwrap();
        let permits: Vec<_> = (0..CAPACITY).map(|_| pool.reserve().unwrap()).collect();
        assert_eq!(pool.used(), CAPACITY);
        assert!(!pool.available());
        assert!(pool.reserve().is_none());
        drop(permits);
        assert_eq!(pool.used(), 0);
        assert!(pool.reserve().is_some());
    }

    #[test]
    fn shared_owners_retain_one_descriptor_and_one_disposal_reservation() {
        let pool = SocketDisposal::new().unwrap();
        let (local, _peer) = UnixStream::pair().unwrap();
        let socket = pool.reserve().unwrap().socket(local.into());
        let other = socket.clone();
        assert_eq!(socket.as_raw_fd(), other.as_raw_fd());
        drop(socket);
        assert_eq!(pool.used(), 1);
        drop(other);
        let deadline = Instant::now() + Duration::from_secs(3);
        while pool.used() != 0 {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
