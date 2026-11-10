//! Bounded Unix HTTP transport for the local, root-owned Podman resolver.
//! This module performs no execution or target authorization.
use std::{
    fs::{File, Metadata},
    io::{self, BufReader, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(crate) const MAX_BODY: usize = 1_048_576;
const MAX_HEADER: usize = 16_384;
const MAX_LINE: usize = 65_536;
fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}

pub(crate) struct Endpoint {
    parent: File,
    configured_parent: PathBuf,
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Endpoint {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        crate::linux::validate_absolute_path(path)?;
        let configured_parent = path
            .parent()
            .ok_or_else(|| invalid("missing socket parent"))?
            .to_path_buf();
        let parent = crate::startup::pin_directory(&configured_parent)?;
        crate::startup::check_root_metadata(&parent, true, None)?;
        let path = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(
            path.file_name()
                .ok_or_else(|| invalid("missing socket name"))?,
        );
        let stat = std::fs::symlink_metadata(&path)?;
        Self::check_metadata(&stat)?;
        Ok(Self {
            parent,
            configured_parent,
            path,
            device: stat.dev(),
            inode: stat.ino(),
        })
    }
    fn check_metadata(stat: &Metadata) -> io::Result<()> {
        if stat.uid() != 0
            || stat.gid() != 0
            || !stat.file_type().is_socket()
            || stat.mode() & 0o007 != 0
        {
            return Err(invalid(
                "Podman socket must be root:root and inaccessible to other users",
            ));
        }
        Ok(())
    }
    pub(crate) fn identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }
    pub(crate) fn check(&self) -> io::Result<()> {
        crate::startup::check_root_metadata(&self.parent, true, None)?;
        let current = crate::startup::pin_directory(&self.configured_parent)?;
        crate::startup::check_root_metadata(&current, true, None)?;
        let retained = self.parent.metadata()?;
        let current = current.metadata()?;
        if (current.dev(), current.ino()) != (retained.dev(), retained.ino()) {
            return Err(invalid("Podman endpoint directory replaced"));
        }
        let stat = std::fs::symlink_metadata(&self.path)?;
        Self::check_metadata(&stat)?;
        if (stat.dev(), stat.ino()) != (self.device, self.inode) {
            return Err(invalid("Podman endpoint replaced"));
        }
        Ok(())
    }
    pub(crate) fn get(
        &self,
        target: &str,
        check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<Response> {
        self.check()?;
        if !target.starts_with('/') || !target.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(invalid("invalid Podman API request target"));
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let bounded = || {
            check()?;
            if Instant::now() >= deadline {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Ok(())
            }
        };
        let mut stream = connect(&self.path, &bounded)?;
        let peer = peer(&stream)?;
        self.check()?;
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes())?;
        let mut response = Response {
            reader: BufReader::new(stream),
            kind: Body::Length(0),
            raw_line: Vec::new(),
            payload_line: Vec::new(),
            peer,
            api_version: String::new(),
        };
        let status = response.raw_line(&bounded)?;
        if status != b"HTTP/1.1 200 OK" && status != b"HTTP/1.0 200 OK" {
            return Err(invalid("Podman API request rejected"));
        }
        let mut total = status.len();
        let mut length = None;
        let mut chunked = false;
        loop {
            let line = response.raw_line(&bounded)?;
            total += line.len() + 2;
            if total > MAX_HEADER {
                return Err(invalid("Podman HTTP headers exceed bound"));
            }
            if line.is_empty() {
                break;
            }
            let line = std::str::from_utf8(&line).map_err(|_| invalid("non-UTF8 Podman header"))?;
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| invalid("invalid Podman HTTP header"))?;
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                if length.is_some()
                    || value.is_empty()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(invalid("duplicate Content-Length"));
                }
                length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| invalid("invalid Content-Length"))?,
                );
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                if chunked || !value.eq_ignore_ascii_case("chunked") {
                    return Err(invalid("unsupported Transfer-Encoding"));
                }
                chunked = true;
            } else if name.eq_ignore_ascii_case("content-encoding")
                && !value.eq_ignore_ascii_case("identity")
            {
                return Err(invalid("unsupported Content-Encoding"));
            } else if name.eq_ignore_ascii_case("libpod-api-version") {
                if !response.api_version.is_empty() || value.len() > 32 {
                    return Err(invalid("ambiguous Podman API version"));
                }
                response.api_version = value.into();
            }
        }
        response.kind = match (length, chunked) {
            (None, true) => Body::ChunkHeader,
            (Some(n), false) if n <= MAX_BODY => Body::Length(n),
            _ => {
                return Err(invalid(
                    "missing, ambiguous or excessive Podman body framing",
                ));
            }
        };
        let version: Vec<_> = response.api_version.split('.').collect();
        if version.len() != 3
            || version[0] != "5"
            || version.iter().any(|part| {
                part.parse::<u32>().is_err() || part.parse::<u32>().unwrap().to_string() != *part
            })
        {
            return Err(invalid("unsupported Podman API version"));
        }
        Ok(response)
    }
}
fn peer(stream: &UnixStream) -> io::Result<libc::ucred> {
    let mut peer = unsafe { std::mem::zeroed::<libc::ucred>() };
    let mut size = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != size_of::<libc::ucred>() || peer.uid != 0 || peer.gid != 0 || peer.pid <= 0
    {
        return Err(invalid("Podman API peer is not host root"));
    }
    Ok(peer)
}
fn connect(path: &Path, check: &dyn Fn() -> io::Result<()>) -> io::Result<UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    address.sun_family = libc::AF_UNIX as _;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= address.sun_path.len() {
        return Err(invalid("Podman socket path exceeds Unix ABI"));
    }
    for (to, from) in address.sun_path.iter_mut().zip(bytes) {
        *to = *from as _;
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let result = unsafe {
        libc::connect(
            raw,
            (&address as *const libc::sockaddr_un).cast(),
            size_of::<libc::sockaddr_un>() as _,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        loop {
            check()?;
            let mut poll = libc::pollfd {
                fd: raw,
                events: libc::POLLOUT,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut poll, 1, 10) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            let mut error = 0i32;
            let mut size = size_of::<i32>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut error as *mut i32).cast(),
                    &mut size,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            break;
        }
    }
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    stream.set_write_timeout(Some(Duration::from_millis(100)))?;
    Ok(stream)
}
#[derive(Clone, Copy)]
enum Body {
    Length(usize),
    ChunkHeader,
    Chunk(usize),
    ChunkEnd(u8),
    Trailer,
    Finished,
}
pub(crate) struct Response {
    reader: BufReader<UnixStream>,
    kind: Body,
    raw_line: Vec<u8>,
    payload_line: Vec<u8>,
    pub(crate) peer: libc::ucred,
    pub(crate) api_version: String,
}
impl Response {
    pub(crate) fn require_event_stream(&self) -> io::Result<()> {
        if !matches!(self.kind, Body::ChunkHeader) {
            return Err(invalid(
                "Podman lifecycle subscription requires a streaming body",
            ));
        }
        Ok(())
    }
    pub(crate) fn watch(&self) -> io::Result<OwnedFd> {
        Ok(self.reader.get_ref().try_clone()?.into())
    }
    pub(crate) fn pending(&self) -> bool {
        !self.reader.buffer().is_empty()
            || !self.raw_line.is_empty()
            || !self.payload_line.is_empty()
            || matches!(
                self.kind,
                Body::Chunk(_) | Body::ChunkEnd(_) | Body::Trailer
            )
    }
    fn raw_byte(&mut self, check: &dyn Fn() -> io::Result<()>) -> io::Result<u8> {
        check()?;
        let mut byte = [0];
        self.reader.read_exact(&mut byte)?;
        Ok(byte[0])
    }
    fn raw_line(&mut self, check: &dyn Fn() -> io::Result<()>) -> io::Result<Vec<u8>> {
        loop {
            let byte = self.raw_byte(check)?;
            self.raw_line.push(byte);
            if self.raw_line.len() > MAX_LINE {
                return Err(invalid("Podman line exceeds bound"));
            }
            if byte == b'\n' {
                if !self.raw_line.ends_with(b"\r\n") {
                    return Err(invalid("invalid Podman HTTP newline"));
                }
                self.raw_line.truncate(self.raw_line.len() - 2);
                return Ok(std::mem::take(&mut self.raw_line));
            }
        }
    }
    fn byte(&mut self, check: &dyn Fn() -> io::Result<()>) -> io::Result<Option<u8>> {
        loop {
            match self.kind {
                Body::Length(0) | Body::Finished => return Ok(None),
                Body::Length(n) => {
                    let byte = self.raw_byte(check)?;
                    self.kind = Body::Length(n - 1);
                    return Ok(Some(byte));
                }
                Body::ChunkHeader => {
                    let line = self.raw_line(check)?;
                    if line.is_empty() || line.len() > 8 || !line.iter().all(u8::is_ascii_hexdigit)
                    {
                        return Err(invalid("invalid Podman HTTP chunk length"));
                    }
                    let length = usize::from_str_radix(
                        std::str::from_utf8(&line).map_err(|_| invalid("invalid chunk"))?,
                        16,
                    )
                    .map_err(|_| invalid("invalid chunk"))?;
                    if length > MAX_BODY {
                        return Err(invalid("Podman chunk exceeds bound"));
                    }
                    self.kind = if length == 0 {
                        Body::Trailer
                    } else {
                        Body::Chunk(length)
                    };
                }
                Body::Chunk(n) => {
                    let byte = self.raw_byte(check)?;
                    self.kind = if n == 1 {
                        Body::ChunkEnd(0)
                    } else {
                        Body::Chunk(n - 1)
                    };
                    return Ok(Some(byte));
                }
                Body::ChunkEnd(n) => {
                    let byte = self.raw_byte(check)?;
                    if byte != b"\r\n"[n as usize] {
                        return Err(invalid("invalid chunk terminator"));
                    }
                    self.kind = if n == 0 {
                        Body::ChunkEnd(1)
                    } else {
                        Body::ChunkHeader
                    };
                }
                Body::Trailer => {
                    if !self.raw_line(check)?.is_empty() {
                        return Err(invalid("Podman trailers unsupported"));
                    }
                    self.kind = Body::Finished;
                }
            }
        }
    }
    pub(crate) fn json(
        mut self,
        check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<serde_json::Value> {
        let mut bytes = Vec::new();
        while let Some(byte) = self.byte(check)? {
            if bytes.len() == MAX_BODY {
                return Err(invalid("Podman response exceeds bound"));
            }
            bytes.push(byte);
        }
        sigrund_core::json::preflight(&bytes, 32, 65_536).map_err(io::Error::other)?;
        serde_json::from_slice(&bytes).map_err(io::Error::other)
    }
    /// Preserve partial framing/payload state across idle read timeouts.
    pub(crate) fn event(
        &mut self,
        check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<serde_json::Value> {
        loop {
            let byte = self
                .byte(check)?
                .ok_or_else(|| invalid("Podman event stream ended"))?;
            if byte == b'\n' {
                let line = std::mem::take(&mut self.payload_line);
                sigrund_core::json::preflight(&line, 16, MAX_LINE).map_err(io::Error::other)?;
                return serde_json::from_slice(&line).map_err(io::Error::other);
            }
            if self.payload_line.len() == MAX_LINE {
                return Err(invalid("Podman event exceeds bound"));
            }
            self.payload_line.push(byte);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(stream: UnixStream, kind: Body) -> Response {
        stream
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        Response {
            reader: BufReader::new(stream),
            kind,
            raw_line: Vec::new(),
            payload_line: Vec::new(),
            peer: unsafe { std::mem::zeroed() },
            api_version: "5.8.1".into(),
        }
    }
    #[test]
    fn event_framing_survives_partial_chunk_headers_and_idle_timeouts() {
        let (stream, mut writer) = UnixStream::pair().unwrap();
        let thread = std::thread::spawn(move || {
            writer.write_all(b"1").unwrap();
            std::thread::sleep(Duration::from_millis(60));
            writer.write_all(b"5\r\n{\"Type\":").unwrap();
            std::thread::sleep(Duration::from_millis(60));
            writer.write_all(b"\"container\"}\n\r\n0\r\n\r\n").unwrap();
        });
        let mut response = response(stream, Body::ChunkHeader);
        let deadline = Instant::now() + Duration::from_secs(2);
        let check = || {
            if Instant::now() < deadline {
                Ok(())
            } else {
                Err(io::ErrorKind::TimedOut.into())
            }
        };
        let value = loop {
            match response.event(&check) {
                Ok(value) => break value,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    check().unwrap();
                }
                Err(error) => panic!("{error}"),
            }
        };
        assert_eq!(value, serde_json::json!({"Type":"container"}));
        assert!(response.event(&check).is_err());
        thread.join().unwrap();
    }
    #[test]
    fn finite_body_rejects_duplicates_truncation_and_oversized_chunks() {
        for body in [
            b"7\r\n{\"a\":1}\r\n0\r\n\r\n".as_slice(),
            b"d\r\n{\"a\":1,\"a\":2}\r\n0\r\n\r\n",
            b"100001\r\n",
            b"7\r\n{\"a\":",
        ] {
            let (stream, mut writer) = UnixStream::pair().unwrap();
            writer.write_all(body).unwrap();
            drop(writer);
            let result = response(stream, Body::ChunkHeader).json(&|| Ok(()));
            if body == b"7\r\n{\"a\":1}\r\n0\r\n\r\n" {
                assert_eq!(result.unwrap(), serde_json::json!({"a":1}));
            } else {
                assert!(result.is_err());
            }
        }
    }
    #[test]
    fn event_subscription_rejects_finite_body_even_without_socket_eof() {
        let (stream, _writer) = UnixStream::pair().unwrap();
        let response = response(stream, Body::Length(0));
        assert!(response.require_event_stream().is_err());
    }
}
