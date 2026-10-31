//! Nonblocking, bounded Unix-stream framing. Every receive inspects ancillary
//! data; received rights become owned immediately, including on error paths.
use std::{
    io,
    mem::{size_of, zeroed},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    time::{Duration, Instant},
};

use sigrund_core::{
    approval::MAX_APPROVAL_MESSAGE_BYTES,
    framing::{FrameAssembler, FrameType, decode_header, encode_frame},
};

pub const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const READ_CHUNK: usize = 8192;

pub fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

pub fn peer_credentials(fd: RawFd) -> io::Result<PeerCredentials> {
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::ucred>() || credentials.pid <= 0 {
        return Err(invalid("invalid SO_PEERCRED result"));
    }
    Ok(PeerCredentials {
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

pub fn disable_ancillary_credentials(fd: RawFd) -> io::Result<()> {
    let disabled: libc::c_int = 0;
    // SO_PASSPIDFD is Linux UAPI 76; older kernels return ENOPROTOOPT.
    for option in [libc::SO_PASSCRED, 76] {
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&disabled as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as _,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            if option == 76
                && matches!(error.raw_os_error(), Some(libc::ENOPROTOOPT | libc::EINVAL))
            {
                continue;
            }
            return Err(error);
        }
    }
    Ok(())
}

struct Received {
    length: usize,
    rights: Vec<OwnedFd>,
}

fn receive(fd: RawFd, bytes: &mut [u8], allow_rights: bool) -> io::Result<Option<Received>> {
    // usize storage supplies cmsghdr alignment. Expose exactly CMSG_SPACE(3
    // ints), including padding in which a fourth delivered FD can fit.
    let mut control = [0usize; 8];
    let control_len = unsafe { libc::CMSG_SPACE((3 * size_of::<libc::c_int>()) as _) } as usize;
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_len;
    let count = unsafe {
        libc::recvmsg(
            fd,
            &mut message,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if count < 0 {
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
    let mut rights = Vec::new();
    let mut malformed = message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0;
    let mut messages = 0;
    let mut offset = 0;
    let available = message.msg_controllen.min(control_len);
    let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
    while offset + size_of::<libc::cmsghdr>() <= available {
        let header = unsafe {
            &*(control
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<libc::cmsghdr>())
        };
        messages += 1;
        let length = header.cmsg_len;
        if length < minimum || length > available - offset {
            malformed = true;
            break;
        }
        let payload = length - minimum;
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            if payload == 0 || !payload.is_multiple_of(size_of::<libc::c_int>()) {
                malformed = true;
            }
            // Collect every safely traversable descriptor before rejecting.
            for index in 0..payload / size_of::<libc::c_int>() {
                let raw = unsafe {
                    std::ptr::read_unaligned(
                        control
                            .as_ptr()
                            .cast::<u8>()
                            .add(offset + minimum + index * size_of::<libc::c_int>())
                            .cast::<libc::c_int>(),
                    )
                };
                if raw < 0 {
                    malformed = true;
                } else {
                    rights.push(unsafe { OwnedFd::from_raw_fd(raw) });
                }
            }
        } else {
            malformed = true;
        }
        let alignment = size_of::<usize>();
        offset += (length + alignment - 1) & !(alignment - 1);
    }
    if malformed || messages > 1 || rights.len() > 3 || (!allow_rights && messages != 0) {
        return Err(invalid("invalid or misplaced ancillary data"));
    }
    if count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "control peer disconnected",
        ));
    }
    Ok(Some(Received {
        length: count as usize,
        rights,
    }))
}

#[derive(Debug)]
pub struct ControlFrame {
    pub kind: FrameType,
    pub payload: Vec<u8>,
    pub rights: Vec<OwnedFd>,
}

/// A single-frame receiver. Header and payload reads never span boundaries.
pub struct ControlReader {
    assembler: FrameAssembler,
    header: [u8; 5],
    received: usize,
    expected: usize,
    first_frame: bool,
    expected_kind: Option<FrameType>,
    reject_frames: bool,
    rights: Vec<OwnedFd>,
    deadline: Option<Instant>,
}

impl ControlReader {
    pub fn new(first_frame: bool) -> Self {
        Self {
            assembler: FrameAssembler::new(),
            header: [0; 5],
            received: 0,
            expected: 5,
            first_frame,
            expected_kind: None,
            reject_frames: false,
            rights: Vec::new(),
            deadline: None,
        }
    }

    /// Stdio clients accept only the exact next server frame, rejecting a
    /// wrong direction/state on its type byte before collecting its length.
    pub fn server(kind: FrameType) -> Self {
        assert!(matches!(
            kind,
            FrameType::ServerAuthDecision | FrameType::ServerChildExit
        ));
        Self {
            expected_kind: Some(kind),
            ..Self::new(false)
        }
    }

    pub fn client_signal() -> Self {
        Self {
            expected_kind: Some(FrameType::ClientSignal),
            ..Self::new(false)
        }
    }
    pub fn server_finished() -> Self {
        Self {
            reject_frames: true,
            ..Self::new(false)
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn read(&mut self, fd: RawFd, now: Instant) -> io::Result<Option<ControlFrame>> {
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "frame assembly expired",
            ));
        }
        // Bound per-dispatch work as well as retained memory.
        for _ in 0..8 {
            let remaining = if self.received == 0 {
                1
            } else if self.received < 5 {
                5 - self.received
            } else {
                self.expected - self.received
            };
            let mut buffer = [0u8; READ_CHUNK];
            let Some(chunk) = receive(
                fd,
                &mut buffer[..remaining.min(READ_CHUNK)],
                self.first_frame && self.received == 0,
            )?
            else {
                return Ok(None);
            };
            if self.received == 0 {
                if self.reject_frames
                    || self
                        .expected_kind
                        .is_some_and(|kind| buffer[0] != kind as u8)
                {
                    return Err(invalid("unexpected server frame type or state"));
                }
                self.deadline = Some(now + FRAME_TIMEOUT);
                if self.first_frame && buffer[0] != FrameType::ClientHello as u8 {
                    return Err(invalid("first client frame must be CLIENT_HELLO"));
                }
                self.rights = chunk.rights;
            }
            if self.received < 5 {
                self.header[self.received..self.received + chunk.length]
                    .copy_from_slice(&buffer[..chunk.length]);
            }
            self.received += chunk.length;
            let frame = self
                .assembler
                .push(&buffer[..chunk.length])
                .map_err(|e| invalid(e.to_string()))?;
            if self.received == 5 {
                let (_, length) = decode_header(self.header).map_err(|e| invalid(e.to_string()))?;
                self.expected = 5 + length;
            }
            if let Some((kind, payload)) = frame {
                return Ok(Some(ControlFrame {
                    kind,
                    payload,
                    rights: std::mem::take(&mut self.rights),
                }));
            }
        }
        Ok(None)
    }
}

/// Approval frames have no type byte and never carry ancillary data.
#[derive(Default)]
pub struct ApprovalReader {
    header: [u8; 4],
    received: usize,
    payload: Vec<u8>,
    deadline: Option<Instant>,
}

impl ApprovalReader {
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn read(&mut self, fd: RawFd, now: Instant) -> io::Result<Option<Vec<u8>>> {
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "approval frame expired",
            ));
        }
        for _ in 0..8 {
            let remaining = if self.received < 4 {
                4 - self.received
            } else {
                self.payload.len() + 4 - self.received
            };
            let mut buffer = [0u8; READ_CHUNK];
            let Some(chunk) = receive(fd, &mut buffer[..remaining.min(READ_CHUNK)], false)? else {
                return Ok(None);
            };
            self.deadline.get_or_insert(now + FRAME_TIMEOUT);
            if self.received < 4 {
                self.header[self.received..self.received + chunk.length]
                    .copy_from_slice(&buffer[..chunk.length]);
                self.received += chunk.length;
                if self.received == 4 {
                    let length = u32::from_be_bytes(self.header) as usize;
                    if length == 0 || length > MAX_APPROVAL_MESSAGE_BYTES {
                        return Err(invalid("approval frame length exceeds bound"));
                    }
                    self.payload.resize(length, 0);
                }
            } else {
                let offset = self.received - 4;
                self.payload[offset..offset + chunk.length]
                    .copy_from_slice(&buffer[..chunk.length]);
                self.received += chunk.length;
                if self.received == 4 + self.payload.len() {
                    return Ok(Some(std::mem::take(&mut self.payload)));
                }
            }
        }
        Ok(None)
    }
}

pub struct FrameWriter {
    bytes: Vec<u8>,
    rights: Vec<OwnedFd>,
    offset: usize,
    deadline: Instant,
}

impl FrameWriter {
    pub fn control(kind: FrameType, payload: &[u8], now: Instant) -> io::Result<Self> {
        Ok(Self {
            bytes: encode_frame(kind, payload).map_err(|e| invalid(e.to_string()))?,
            rights: Vec::new(),
            offset: 0,
            deadline: now + FRAME_TIMEOUT,
        })
    }

    pub fn hello(payload: &[u8], rights: Vec<OwnedFd>, now: Instant) -> io::Result<Self> {
        if !matches!(rights.len(), 2 | 3) {
            return Err(invalid("invalid hello rights count"));
        }
        let mut writer = Self::control(FrameType::ClientHello, payload, now)?;
        writer.rights = rights;
        Ok(writer)
    }

    pub fn approval(payload: &[u8], now: Instant) -> io::Result<Self> {
        if payload.is_empty() || payload.len() > MAX_APPROVAL_MESSAGE_BYTES {
            return Err(invalid("invalid approval output length"));
        }
        let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(payload);
        Ok(Self {
            bytes,
            rights: Vec::new(),
            offset: 0,
            deadline: now + FRAME_TIMEOUT,
        })
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn write(&mut self, fd: RawFd, now: Instant) -> io::Result<bool> {
        if now >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "frame send expired",
            ));
        }
        let count = if self.offset == 0 && !self.rights.is_empty() {
            let mut control = [0usize; 8];
            let mut iov = libc::iovec {
                iov_base: self.bytes.as_ptr().cast_mut().cast(),
                iov_len: 1,
            };
            let mut message: libc::msghdr = unsafe { zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen =
                unsafe { libc::CMSG_SPACE((self.rights.len() * size_of::<i32>()) as _) } as _;
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len =
                    libc::CMSG_LEN((self.rights.len() * size_of::<i32>()) as _) as _;
                for (index, right) in self.rights.iter().enumerate() {
                    std::ptr::write(
                        libc::CMSG_DATA(header).cast::<i32>().add(index),
                        right.as_raw_fd(),
                    );
                }
                libc::sendmsg(fd, &message, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
            }
        } else {
            unsafe {
                libc::send(
                    fd,
                    self.bytes[self.offset..].as_ptr().cast(),
                    (self.bytes.len() - self.offset).min(65_536),
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            }
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            return if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(false)
            } else {
                Err(error)
            };
        }
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "socket send returned zero",
            ));
        }
        self.rights.clear();
        self.offset += count as usize;
        Ok(self.offset == self.bytes.len())
    }
}

/// Potentially blocking descriptor validation. Call only on an I/O worker:
/// even fstat() can block on FUSE or remote filesystems.
pub fn validate_stdio(
    hello: &sigrund_core::protocol::ClientHello,
    rights: &[OwnedFd],
) -> io::Result<()> {
    validate_stdio_checked(hello, rights, || Ok(()))
}

pub(crate) fn validate_stdio_checked(
    hello: &sigrund_core::protocol::ClientHello,
    rights: &[OwnedFd],
    check_cancelled: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    check_cancelled()?;
    let policy = if let Some(command) = &hello.requested_command {
        command.stdin_policy.clone()
    } else {
        hello
            .dsse_envelope
            .as_ref()
            .ok_or_else(|| invalid("missing warrant"))?
            .warrant()
            .map_err(|e| invalid(e.to_string()))?
            .warrant()
            .command
            .stdin_policy
            .clone()
    };
    let expected = if hello.tty_mode == "pty" {
        0
    } else if policy == "null" {
        2
    } else {
        3
    };
    if rights.len() != expected {
        return Err(invalid("incorrect stdio descriptor count"));
    }
    for (index, fd) in rights.iter().enumerate() {
        check_cancelled()?;
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_PATH != 0 {
            return Err(invalid("O_PATH stdio descriptor"));
        }
        let mut metadata: libc::stat = unsafe { zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut metadata) } != 0 {
            return Err(io::Error::last_os_error());
        }
        check_cancelled()?;
        let kind = metadata.st_mode & libc::S_IFMT;
        let stdin = expected == 3 && index == 0;
        let character = kind == libc::S_IFCHR
            && (policy == "unrestricted_interactive"
                || (!stdin && metadata.st_rdev == libc::makedev(1, 3)));
        if !matches!(kind, libc::S_IFREG | libc::S_IFIFO) && !character {
            return Err(invalid("forbidden stdio descriptor type"));
        }
        let access = flags & libc::O_ACCMODE;
        if (stdin && access == libc::O_WRONLY) || (!stdin && access == libc::O_RDONLY) {
            return Err(invalid("incorrect stdio descriptor access mode"));
        }
    }
    check_cancelled()
}
