use sigrund::transport::{ControlReader, FRAME_TIMEOUT, FrameWriter};
use std::{
    fs::File,
    mem::size_of,
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::Instant,
};

#[test]
fn hello_rights_are_sent_once_on_the_first_byte_through_backpressure() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let small = 4096i32;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                sender.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&small as *const i32).cast(),
                size_of::<i32>() as _,
            )
        },
        0
    );
    let now = Instant::now();
    let payload = vec![b' '; 131072];
    let rights = (0..3)
        .map(|_| File::open("/dev/null").unwrap().into())
        .collect();
    let mut writer = FrameWriter::hello(&payload, rights, now).unwrap();
    // Exactly one byte plus rights, then header/body writes. Fill the send
    // buffer before reading again to force the nonblocking retry path.
    assert!(!writer.write(sender.as_raw_fd(), now).unwrap());
    let mut reader = ControlReader::new(true);
    assert!(reader.read(receiver.as_raw_fd(), now).unwrap().is_none());
    for _ in 0..64 {
        assert!(!writer.write(sender.as_raw_fd(), now).unwrap());
    }
    assert_eq!(
        writer
            .write(sender.as_raw_fd(), now + FRAME_TIMEOUT)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    let mut received = None;
    let mut sent = false;
    for _ in 0..1000 {
        if !sent {
            sent = writer.write(sender.as_raw_fd(), now).unwrap();
        }
        if received.is_none() {
            received = reader.read(receiver.as_raw_fd(), now).unwrap();
        }
        if sent && received.is_some() {
            break;
        }
    }
    assert!(sent);
    let frame = received.expect("complete bounded frame");
    assert_eq!(frame.payload, payload);
    assert_eq!(frame.rights.len(), 3);
    for right in &frame.rights {
        assert_ne!(
            unsafe { libc::fcntl(right.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
}
