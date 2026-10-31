use super::*;

pub(super) fn verify_short_watchdog() {
    let fixture = Fixture::new();
    let path = fixture.directory.path().join("notify.sock");
    let notify = UnixDatagram::bind(&path).unwrap();
    let watchdog = Duration::from_millis(300);
    notify.set_read_timeout(Some(watchdog)).unwrap();
    let mut command = fixture.command();
    command
        .env("NOTIFY_SOCKET", &path)
        .env("WATCHDOG_USEC", "300000")
        .env_remove("WATCHDOG_PID");
    let daemon = fixture.launch_command(command);
    let mut message = [0; 128];
    let count = notify.recv(&mut message).unwrap();
    assert!(message[..count].starts_with(b"READY=1\n"));
    // With no connections or other events, epoll must still wake up for each
    // heartbeat before systemd's deadline, including the first after READY.
    for _ in 0..3 {
        let start = Instant::now();
        let count = notify.recv(&mut message).expect("watchdog deadline missed");
        assert_eq!(&message[..count], b"WATCHDOG=1");
        assert!(start.elapsed() < watchdog, "late watchdog heartbeat");
    }
    daemon.stop();
}
