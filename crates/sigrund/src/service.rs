//! Optional systemd readiness/watchdog notifications. No filesystem work.
use std::{
    io,
    os::{
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            net::{SocketAddr, UnixDatagram},
        },
    },
    time::{Duration, Instant},
};

pub(crate) struct Service {
    socket: Option<(UnixDatagram, SocketAddr)>,
    interval: Option<Duration>,
    last: Instant,
}
impl Service {
    pub fn new() -> io::Result<Self> {
        let socket = std::env::var_os("NOTIFY_SOCKET")
            .map(|path| {
                let raw = path.as_bytes();
                let address = if raw.first() == Some(&b'@') {
                    SocketAddr::from_abstract_name(&raw[1..])?
                } else {
                    SocketAddr::from_pathname(path)?
                };
                let socket = UnixDatagram::unbound()?;
                socket.set_nonblocking(true)?;
                Ok::<_, io::Error>((socket, address))
            })
            .transpose()?;
        let own_pid = std::env::var("WATCHDOG_PID")
            .ok()
            .is_none_or(|pid| pid.parse::<u32>().ok() == Some(std::process::id()));
        let interval = own_pid
            .then(|| {
                std::env::var("WATCHDOG_USEC")
                    .ok()?
                    .parse::<u64>()
                    .ok()
                    .filter(|n| *n > 0)
                    .map(|n| Duration::from_micros((n / 3).max(1)))
            })
            .flatten();
        Ok(Self {
            socket,
            interval,
            last: Instant::now(),
        })
    }
    pub fn ready(&self) {
        self.send(b"READY=1\nSTATUS=Accepting requests");
    }
    pub fn stopping(&self) {
        self.send(b"STOPPING=1\nSTATUS=Reconciling and cleaning up; admission closed");
    }
    pub fn tick(&mut self) {
        if self
            .interval
            .is_some_and(|interval| self.last.elapsed() >= interval)
        {
            self.send(b"WATCHDOG=1");
            self.last = Instant::now();
        }
    }
    fn send(&self, message: &[u8]) {
        if let Some((socket, address)) = &self.socket {
            let _ = socket.send_to_addr(message, address);
        }
    }
}
