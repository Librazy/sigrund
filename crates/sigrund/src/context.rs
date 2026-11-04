//! Target-independent context I/O has its own bounded pool. In particular,
//! malformed ancillary descriptors are received and closed off the coordinator.
use crate::{
    socket_disposal::Socket,
    transport::{self, ControlReader, FrameWriter},
};
use sigrund_core::{framing::FrameType, protocol::ContextQuery};
use std::{
    collections::HashMap,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    time::Instant,
};

struct Task {
    socket: Socket,
    uid: u32,
    deadline: Instant,
}
pub(crate) struct ContextWorkers {
    sender: SyncSender<Task>,
    completed: Receiver<u32>,
    wake: Arc<OwnedFd>,
    stopping: Arc<AtomicBool>,
    active: HashMap<u32, usize>,
}
impl ContextWorkers {
    pub fn new(payload: Arc<Vec<u8>>) -> io::Result<Self> {
        let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let wake = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
        let stopping = Arc::new(AtomicBool::new(false));
        let (sender, tasks) = sync_channel::<Task>(8);
        let tasks = Arc::new(Mutex::new(tasks));
        let (completed, receiver) = sync_channel(8);
        for slot in 0..2 {
            let (tasks, completed, wake, stopping, payload) = (
                tasks.clone(),
                completed.clone(),
                wake.clone(),
                stopping.clone(),
                payload.clone(),
            );
            std::thread::Builder::new()
                .name(format!("context-io-{slot}"))
                .spawn(move || {
                    loop {
                        let Ok(task) = tasks.lock().expect("context queue").recv() else {
                            break;
                        };
                        let uid = task.uid;
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let _ = serve(&task, &payload, &stopping);
                            drop(task);
                        }));
                        if completed.send(uid).is_err() {
                            break;
                        }
                        let one = 1u64;
                        loop {
                            if unsafe {
                                libc::write(wake.as_raw_fd(), (&one as *const u64).cast(), 8)
                            } >= 0
                                || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                            {
                                break;
                            }
                        }
                    }
                })?;
        }
        Ok(Self {
            sender,
            completed: receiver,
            wake,
            stopping,
            active: HashMap::new(),
        })
    }
    pub fn fd(&self) -> i32 {
        self.wake.as_raw_fd()
    }
    pub fn is_idle(&self) -> bool {
        self.active.is_empty()
    }
    pub fn submit(&mut self, socket: Socket, uid: u32, accepted: Instant) -> bool {
        if self.active.values().sum::<usize>() >= 8
            || self.active.get(&uid).copied().unwrap_or(0) >= 2
        {
            return false;
        }
        if self
            .sender
            .try_send(Task {
                socket,
                uid,
                deadline: accepted + transport::FRAME_TIMEOUT,
            })
            .is_err()
        {
            return false;
        }
        *self.active.entry(uid).or_default() += 1;
        true
    }
    pub fn drain(&mut self) {
        let mut value = 0u64;
        unsafe {
            libc::read(self.fd(), (&mut value as *mut u64).cast(), 8);
        }
        for uid in self.completed.try_iter() {
            let count = self.active.get_mut(&uid).expect("context reservation");
            *count -= 1;
            if *count == 0 {
                self.active.remove(&uid);
            }
        }
    }
    pub fn shutdown(&self) {
        self.stopping.store(true, Ordering::Release);
    }
}
fn serve(task: &Task, payload: &[u8], stopping: &AtomicBool) -> io::Result<()> {
    let mut reader = ControlReader::context_query();
    let mut writer = None;
    loop {
        let now = Instant::now();
        if stopping.load(Ordering::Acquire) || now >= task.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let events = if let Some(output) = &mut writer {
            let output: &mut FrameWriter = output;
            if output.write(task.socket.as_raw_fd(), now)? {
                return Ok(());
            }
            libc::POLLOUT
        } else {
            if let Some(frame) = reader.read(task.socket.as_raw_fd(), now)? {
                let query: ContextQuery = sigrund_core::protocol::parse_strict(&frame.payload)
                    .map_err(|e| transport::invalid(e.to_string()))?;
                if query.version != "2.0" {
                    return Err(transport::invalid("unsupported context version"));
                }
                writer = Some(FrameWriter::control(
                    FrameType::ServerContext,
                    payload,
                    now,
                )?);
                continue;
            }
            libc::POLLIN
        };
        let mut poll = libc::pollfd {
            fd: task.socket.as_raw_fd(),
            events,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 20) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            return Err(io::Error::last_os_error());
        }
    }
}
