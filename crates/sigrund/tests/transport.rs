use sigrund::transport::{
    ApprovalReader, ControlReader, FRAME_TIMEOUT, FrameWriter, disable_ancillary_credentials,
    peer_credentials, validate_stdio,
};
use sigrund_core::{
    framing::{FrameType, encode_frame},
    protocol::ClientHello,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    mem::{size_of, zeroed},
    os::{
        fd::{AsRawFd, RawFd},
        unix::{fs::OpenOptionsExt, net::UnixStream},
    },
    time::{Duration, Instant},
};

fn send_rights(socket: &UnixStream, bytes: &[u8], rights: &[RawFd]) {
    let mut control = [0usize; 64];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    if !rights.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE(std::mem::size_of_val(rights) as _) } as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(rights) as _) as _;
            std::ptr::copy_nonoverlapping(
                rights.as_ptr(),
                libc::CMSG_DATA(header).cast(),
                rights.len(),
            );
        }
    }
    assert_eq!(
        unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) },
        bytes.len() as isize
    );
}

fn pair() -> (UnixStream, UnixStream) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    receiver.set_nonblocking(true).unwrap();
    disable_ancillary_credentials(receiver.as_raw_fd()).unwrap();
    (sender, receiver)
}

fn fd_count() -> usize {
    fs::read_dir("/proc/self/fd").unwrap().count()
}

fn hello(policy: &str) -> ClientHello {
    ClientHello::parse_request(serde_json::json!({
        "mode":"unsigned_csr_request", "tty_mode":"stdio", "caller_env":{},
        "requested_command":{"allow_interpreted_script":false,"argv":["id"],"cwd":"/",
            "executable_path":"/usr/bin/id","stdin_policy":policy,"tty_mode":"stdio"},
        "requested_execution_context":{"capabilities":[],"env_exact":{},"caller_env_allowlist":[],
            "supplementary_gids":[],"target_gid":0,"target_uid":0,"umask":18},
        "requested_policy":{"mode":"one_time","ttl_secs":60}
    }).to_string().as_bytes()).unwrap()
}

// Kept in one test so descriptor-count evidence is not affected by parallel
// tests opening unrelated sockets in this process.
#[test]
fn bounded_transport_fragmentation_ancillary_ownership_and_deadlines() {
    let now = Instant::now();
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    let rights = [null.as_raw_fd(), null.as_raw_fd()];
    let encoded = encode_frame(
        FrameType::ClientHello,
        &serde_json::to_vec(&hello("null")).unwrap(),
    )
    .unwrap();
    let (mut sender, receiver) = pair();
    let peer = peer_credentials(receiver.as_raw_fd()).unwrap();
    assert_eq!(peer.uid, unsafe { libc::getuid() });
    assert_eq!(peer.gid, unsafe { libc::getgid() });
    assert_eq!(peer.pid, std::process::id() as i32);
    let mut reader = ControlReader::new(true);
    send_rights(&sender, &encoded[..1], &rights);
    assert!(reader.read(receiver.as_raw_fd(), now).unwrap().is_none());
    let deadline = reader.deadline().unwrap();
    assert_eq!(deadline, now + FRAME_TIMEOUT);
    for byte in &encoded[1..5] {
        sender.write_all(&[*byte]).unwrap();
        assert!(
            reader
                .read(receiver.as_raw_fd(), now + Duration::from_millis(100))
                .unwrap()
                .is_none()
        );
        assert_eq!(reader.deadline(), Some(deadline));
    }
    // Queue a later frame too. The receiver must stop exactly at hello EOF.
    sender.write_all(&encoded[5..]).unwrap();
    sender
        .write_all(&encode_frame(FrameType::ClientSignal, br#"{"signal":15}"#).unwrap())
        .unwrap();
    let frame = reader.read(receiver.as_raw_fd(), now).unwrap().unwrap();
    assert_eq!(frame.kind, FrameType::ClientHello);
    assert_eq!(frame.rights.len(), 2);
    for fd in &frame.rights {
        assert_ne!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
    validate_stdio(&hello("null"), &frame.rights).unwrap();
    let mut next = ControlReader::new(false);
    assert_eq!(
        next.read(receiver.as_raw_fd(), now).unwrap().unwrap().kind,
        FrameType::ClientSignal
    );
    drop(frame);
    // Both the padding-sized fourth FD and control-truncated fifth FD must
    // be rejected, with every actually delivered descriptor closed.
    for count in [4, 5, 12] {
        let (sender, receiver) = pair();
        let baseline = fd_count();
        for _ in 0..20 {
            let (sender, receiver) = pair();
            let before = fd_count();
            send_rights(&sender, &[1], &vec![null.as_raw_fd(); count]);
            assert!(
                ControlReader::new(true)
                    .read(receiver.as_raw_fd(), now)
                    .is_err()
            );
            assert_eq!(fd_count(), before, "leaked rights from count {count}");
        }
        assert_eq!(fd_count(), baseline);
        drop((sender, receiver));
    }
    // Ancillary data on length/payload, later frames, or the broker is fatal.
    for prefix in [1, 5] {
        let (mut sender, receiver) = pair();
        let mut reader = ControlReader::new(true);
        sender.write_all(&encoded[..prefix]).unwrap();
        assert!(reader.read(receiver.as_raw_fd(), now).unwrap().is_none());
        let before = fd_count();
        send_rights(&sender, &encoded[prefix..prefix + 1], &rights);
        assert!(reader.read(receiver.as_raw_fd(), now).is_err());
        assert_eq!(fd_count(), before);
    }
    let (sender, receiver) = pair();
    let before = fd_count();
    send_rights(&sender, &[3], &rights);
    assert!(
        ControlReader::new(false)
            .read(receiver.as_raw_fd(), now)
            .is_err()
    );
    assert_eq!(fd_count(), before);
    let (sender, receiver) = pair();
    let before = fd_count();
    send_rights(&sender, &[0], &rights);
    assert!(
        ApprovalReader::default()
            .read(receiver.as_raw_fd(), now)
            .is_err()
    );
    assert_eq!(fd_count(), before);
    // A reader with partial progress keeps its original deadline.
    let (mut sender, receiver) = pair();
    let mut reader = ControlReader::new(true);
    sender.write_all(&[1]).unwrap();
    assert!(reader.read(receiver.as_raw_fd(), now).unwrap().is_none());
    assert_eq!(
        reader
            .read(receiver.as_raw_fd(), now + FRAME_TIMEOUT)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    // Human waiting precedes the first broker byte. Once framing starts,
    // additional bytes cannot extend the independent five-second deadline.
    let (mut sender, receiver) = pair();
    let mut reader = ApprovalReader::default();
    assert!(reader.read(receiver.as_raw_fd(), now).unwrap().is_none());
    assert!(reader.deadline().is_none());
    sender.write_all(&[0]).unwrap();
    assert!(reader.read(receiver.as_raw_fd(), now).unwrap().is_none());
    sender.write_all(&[0]).unwrap();
    assert!(
        reader
            .read(receiver.as_raw_fd(), now + Duration::from_secs(1))
            .unwrap()
            .is_none()
    );
    assert_eq!(reader.deadline(), Some(now + FRAME_TIMEOUT));
    assert_eq!(
        reader
            .read(receiver.as_raw_fd(), now + FRAME_TIMEOUT)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    // Hostile advertised sizes are rejected without waiting for the body.
    for header in [[1, 0, 3, 0, 1], [1, 0, 0, 0, 0], [255, 0, 0, 0, 1]] {
        let (mut sender, receiver) = pair();
        sender.write_all(&header).unwrap();
        assert!(
            ControlReader::new(true)
                .read(receiver.as_raw_fd(), now)
                .is_err()
        );
    }
    for header in [[0, 8, 0, 1], [0, 0, 0, 0]] {
        let (mut sender, receiver) = pair();
        sender.write_all(&header).unwrap();
        assert!(
            ApprovalReader::default()
                .read(receiver.as_raw_fd(), now)
                .is_err()
        );
    }
    // Bounded send retries do not reset the deadline under backpressure.
    let (sender, receiver) = pair();
    let small: libc::c_int = 1024;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                sender.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&small as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as _,
            )
        },
        0
    );
    let mut writer = FrameWriter::approval(&vec![b'x'; 524_288], now).unwrap();
    assert!(!writer.write(sender.as_raw_fd(), now).unwrap());
    assert!(
        !writer
            .write(sender.as_raw_fd(), now + Duration::from_secs(1))
            .unwrap()
    );
    assert_eq!(writer.deadline(), now + FRAME_TIMEOUT);
    assert_eq!(
        writer
            .write(sender.as_raw_fd(), now + FRAME_TIMEOUT)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    drop(receiver);
    // A full broker exchange works with the separate four-byte framing.
    let (sender, receiver) = pair();
    let payload = br#"{"status":"rejected"}"#;
    assert!(
        FrameWriter::approval(payload, now)
            .unwrap()
            .write(sender.as_raw_fd(), now)
            .unwrap()
    );
    assert_eq!(
        ApprovalReader::default()
            .read(receiver.as_raw_fd(), now)
            .unwrap()
            .unwrap(),
        payload
    );
    // Metadata validation rejects O_PATH, directories, sockets, and stdin
    // /dev/null for sha256. It does not read any of these descriptors.
    let directory = File::open("/").unwrap();
    let path = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH)
        .open("/dev/null")
        .unwrap();
    let (socket, _) = pair();
    for bad in [directory.as_raw_fd(), path.as_raw_fd(), socket.as_raw_fd()] {
        let (sender, receiver) = pair();
        send_rights(&sender, &encoded[..1], &[bad, null.as_raw_fd()]);
        let mut reader = ControlReader::new(true);
        reader.read(receiver.as_raw_fd(), now).unwrap();
        sender.set_nonblocking(false).unwrap();
        (&sender).write_all(&encoded[1..]).unwrap();
        let frame = reader.read(receiver.as_raw_fd(), now).unwrap().unwrap();
        assert!(validate_stdio(&hello("null"), &frame.rights).is_err());
    }
    let (sender, receiver) = pair();
    let body = serde_json::to_vec(&hello("sha256")).unwrap();
    let encoded = encode_frame(FrameType::ClientHello, &body).unwrap();
    send_rights(&sender, &encoded[..1], &[null.as_raw_fd(); 3]);
    (&sender).write_all(&encoded[1..]).unwrap();
    let frame = ControlReader::new(true)
        .read(receiver.as_raw_fd(), now)
        .unwrap()
        .unwrap();
    assert!(validate_stdio(&hello("sha256"), &frame.rights).is_err());
    // EOF closes pending FDs when the request owner is dropped.
    let (sender, receiver) = pair();
    let before = fd_count();
    let mut reader = ControlReader::new(true);
    send_rights(&sender, &[1], &rights);
    reader.read(receiver.as_raw_fd(), now).unwrap();
    assert_eq!(fd_count(), before + 2);
    sender.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(
        reader.read(receiver.as_raw_fd(), now).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    drop(reader);
    assert_eq!(fd_count(), before);
    let mut remaining = Vec::new();
    drop(sender);
    (&receiver).read_to_end(&mut remaining).unwrap();
}

#[path = "transport/writer.rs"]
mod writer;
