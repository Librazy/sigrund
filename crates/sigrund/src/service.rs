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
    pub fn ready(&self) -> io::Result<()> {
        self.send(b"READY=1\nSTATUS=Accepting requests")
    }
    pub fn stopping(&self) {
        let _ = self.send(b"STOPPING=1\nSTATUS=Reconciling and cleaning up; admission closed");
    }
    pub fn watchdog_wait(&self, now: Instant) -> Option<Duration> {
        self.interval
            .map(|interval| interval.saturating_sub(now.saturating_duration_since(self.last)))
    }
    pub fn tick(&mut self) {
        if self
            .interval
            .is_some_and(|interval| self.last.elapsed() >= interval)
        {
            let _ = self.send(b"WATCHDOG=1");
            self.last = Instant::now();
        }
    }
    fn send(&self, message: &[u8]) -> io::Result<()> {
        if let Some((socket, address)) = &self.socket {
            let sent = socket.send_to_addr(message, address)?;
            if sent != message.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "incomplete service notification",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_fails_when_configured_delivery_fails() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify");
        let service = Service {
            socket: Some((
                UnixDatagram::unbound().unwrap(),
                SocketAddr::from_pathname(&path).unwrap(),
            )),
            interval: None,
            last: Instant::now(),
        };
        assert!(service.ready().is_err());
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        service.ready().unwrap();
        let mut bytes = [0u8; 128];
        let size = receiver.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..size], b"READY=1\nSTATUS=Accepting requests");
    }

    #[test]
    fn watchdog_wait_tracks_remaining_interval() {
        let now = Instant::now();
        let mut service = Service {
            socket: None,
            interval: None,
            last: now,
        };
        assert_eq!(service.watchdog_wait(now), None);
        service.interval = Some(Duration::from_millis(100));
        assert_eq!(service.watchdog_wait(now), service.interval);
        assert_eq!(
            service.watchdog_wait(now + Duration::from_millis(40)),
            Some(Duration::from_millis(60))
        );
        for elapsed in [100, 150] {
            assert_eq!(
                service.watchdog_wait(now + Duration::from_millis(elapsed)),
                Some(Duration::ZERO)
            );
        }
    }
}
