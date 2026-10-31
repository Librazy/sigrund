use base64::{Engine as _, engine::general_purpose::STANDARD};
use sigrund::snapshot::{self, SnapshotBudget};
use sigrund_core::{config::DaemonConfig, crypto::sha256_hex, snapshot::copy_stream};
use std::{
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    os::fd::{AsFd, AsRawFd},
    sync::atomic::{AtomicBool, Ordering},
};
fn config() -> DaemonConfig {
    let mut config = DaemonConfig::from_toml(
        include_str!("../../../config/sigrund.toml.example")
            .replace(
                "<strict-padded-base64-32-byte-ed25519-key>",
                &STANDARD.encode([1; 32]),
            )
            .as_bytes(),
    )
    .unwrap();
    config.max_executable_bytes = 4096;
    config.max_stdin_bytes = 4096;
    config.snapshot_ram_global_bytes = 8192;
    config.snapshot_ram_per_uid_bytes = 4096;
    config
}
fn source(bytes: &[u8]) -> File {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file
}
#[test]
fn snapshots_are_sealed_rewound_and_accounted_until_owner_cleanup() {
    let config = config();
    let budget = SnapshotBudget::default();
    let mut elf = vec![7; 4096];
    elf[..4].copy_from_slice(b"\x7fELF");
    let executable = snapshot::executable(source(&elf), &budget, 1001, &config, || Ok(())).unwrap();
    assert_eq!(executable.digest.sha256, sha256_hex(&elf));
    assert_eq!(budget.usage(1001), (4096, 4096));
    assert_eq!(
        unsafe { libc::lseek(executable.as_fd().as_raw_fd(), 0, libc::SEEK_CUR) },
        0
    );
    assert_eq!(
        unsafe { libc::fcntl(executable.as_fd().as_raw_fd(), libc::F_GET_SEALS) } & 0x1f,
        0x1f
    );
    assert_eq!(
        snapshot::stdin(source(b"x"), &budget, 1001, &config, || Ok(()))
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let stdin = snapshot::stdin(source(b"hello"), &budget, 1002, &config, || Ok(())).unwrap();
    assert_eq!(budget.usage(1002), (4101, 5));
    let mut readable = File::from(stdin.as_fd().try_clone_to_owned().unwrap());
    let mut contents = Vec::new();
    readable.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, b"hello");
    drop(readable);
    assert_eq!(
        unsafe { libc::write(stdin.as_fd().as_raw_fd(), b"x".as_ptr().cast(), 1) },
        -1
    );
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    let (send, recv) = std::sync::mpsc::channel();
    std::thread::spawn(move || send.send(executable).unwrap())
        .join()
        .unwrap();
    let transferred = recv.recv().unwrap();
    assert_eq!(budget.usage(1001), (4101, 4096));
    drop(transferred);
    drop(stdin);
    assert_eq!(budget.usage(1001), (0, 0));
    let first = snapshot::stdin(source(b""), &budget, 1001, &config, || Ok(())).unwrap();
    let second = snapshot::stdin(source(b""), &budget, 1001, &config, || Ok(())).unwrap();
    assert_eq!(first.digest.sha256, sha256_hex(b""));
    assert_eq!(first.digest.bytes, 0);
    drop(first);
    drop(second);
    assert_eq!(budget.usage(1001), (0, 0));
}
#[test]
fn snapshot_failures_release_reservations_and_enforce_bounds() {
    let config = config();
    let budget = SnapshotBudget::default();
    for bytes in [&b""[..], &b"script"[..], &vec![0; 4097][..]] {
        assert!(snapshot::executable(source(bytes), &budget, 1001, &config, || Ok(())).is_err());
        assert_eq!(budget.usage(1001), (0, 0));
    }
    assert!(snapshot::stdin(source(&vec![0; 4097]), &budget, 1001, &config, || Ok(())).is_err());
    assert_eq!(budget.usage(1001), (0, 0));
    let cancelled = AtomicBool::new(false);
    let error = snapshot::stdin(source(b"hello"), &budget, 1001, &config, || {
        if cancelled.swap(true, Ordering::Relaxed) {
            Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"))
        } else {
            Ok(())
        }
    })
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(budget.usage(1001), (0, 0));
    let mut low = config.clone();
    low.snapshot_ram_global_bytes = 4096;
    let held = snapshot::stdin(source(&vec![0; 4096]), &budget, 1001, &low, || Ok(())).unwrap();
    assert!(snapshot::stdin(source(b"x"), &budget, 1002, &low, || Ok(())).is_err());
    drop(held);
    assert_eq!(budget.usage(1001), (0, 0));
}
struct InterruptedReader {
    inner: Cursor<Vec<u8>>,
    interrupt: bool,
    largest: usize,
}
impl Read for InterruptedReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.largest = self.largest.max(bytes.len());
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let size = bytes.len().min(997);
        self.inner.read(&mut bytes[..size])
    }
}
struct InterruptedWriter {
    bytes: Vec<u8>,
    interrupt: bool,
}
impl Write for InterruptedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let size = bytes.len().min(113);
        self.bytes.extend_from_slice(&bytes[..size]);
        Ok(size)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn streaming_copy_handles_short_interrupted_io_and_size_changes() {
    let bytes = vec![42; 3 * 65536 + 127];
    let mut reader = InterruptedReader {
        inner: Cursor::new(bytes.clone()),
        interrupt: false,
        largest: 0,
    };
    let mut writer = InterruptedWriter {
        bytes: Vec::new(),
        interrupt: false,
    };
    let digest = copy_stream(
        &mut reader,
        &mut writer,
        Some(bytes.len() as u64),
        bytes.len() as u64,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(digest.sha256, sha256_hex(&bytes));
    assert_eq!(writer.bytes, bytes);
    assert!(reader.largest <= 65536);
    for (input, expected, max) in [
        (b"abc".as_slice(), Some(4), 4),
        (b"abc", Some(2), 4),
        (b"abc", None, 2),
    ] {
        assert!(
            copy_stream(
                &mut Cursor::new(input),
                &mut io::sink(),
                expected,
                max,
                || Ok(())
            )
            .is_err()
        );
    }
}

// The helper runs the production snapshot function while its final source
// close is stalled by the interposer. Its main thread can inspect accounting.
#[test]
#[ignore = "subprocess of snapshot_source_close_retains_ram_reservation"]
fn snapshot_close_helper() {
    let budget = SnapshotBudget::default();
    let worker_budget = budget.clone();
    let path = std::env::var_os("SIGRUND_SNAPSHOT_SOURCE").unwrap();
    let worker = std::thread::spawn(move || {
        snapshot::executable(
            File::open(path).unwrap(),
            &worker_budget,
            1001,
            &config(),
            || Ok(()),
        )
    });
    let mut commands = io::stdin();
    let mut command = [0];
    commands.read_exact(&mut command).unwrap();
    assert_eq!(command[0], b'u');
    assert!(!worker.is_finished());
    println!(
        "SNAPSHOT_USAGE {}",
        serde_json::to_string(&budget.usage(1001)).unwrap()
    );
    io::stdout().flush().unwrap();
    commands.read_exact(&mut command).unwrap();
    assert_eq!(command[0], b'j');
    let snapshot = worker.join().unwrap().unwrap();
    println!(
        "SNAPSHOT_JOINED {}",
        serde_json::to_string(&budget.usage(1001)).unwrap()
    );
    io::stdout().flush().unwrap();
    drop(snapshot);
    assert_eq!(budget.usage(1001), (0, 0));
}
#[test]
fn snapshot_source_close_retains_ram_reservation() {
    use std::{
        io::{BufRead, BufReader},
        os::unix::{fs::MetadataExt, net::UnixStream, process::CommandExt},
        process::{Command, Stdio},
        time::Duration,
    };
    let directory = tempfile::tempdir().unwrap();
    let interposer = directory.path().join("close_gate.so");
    let output = Command::new("cc")
        .args(["-shared", "-fPIC", "-Wall", "-Werror", "-o"])
        .arg(&interposer)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/transport/metadata.c"
        ))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = directory.path().join("source");
    std::fs::write(&path, b"\x7fELFtest").unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    let (mut entered, worker_entered) = UnixStream::pair().unwrap();
    entered
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (mut release, worker_release) = UnixStream::pair().unwrap();
    let entered_fd = worker_entered.as_raw_fd();
    let release_fd = worker_release.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "snapshot_close_helper",
            "--nocapture",
        ])
        .env("LD_PRELOAD", &interposer)
        .env("SIGRUND_GATE_CLOSE", "1")
        .env("SIGRUND_GATE_INODE", metadata.ino().to_string())
        .env("SIGRUND_GATE_DEVICE", metadata.dev().to_string())
        .env("SIGRUND_GATE_ENTERED_FD", entered_fd.to_string())
        .env("SIGRUND_GATE_RELEASE_FD", release_fd.to_string())
        .env("SIGRUND_SNAPSHOT_SOURCE", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            for fd in [entered_fd, release_fd] {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    drop((worker_entered, worker_release));
    let mut tid = [0; 8];
    entered.read_exact(&mut tid).unwrap();
    assert_ne!(u64::from_ne_bytes(tid), child.id() as u64);
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    child.stdin.as_mut().unwrap().write_all(b"u").unwrap();
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(stdout.read_line(&mut line).unwrap(), 0);
        if line.starts_with("SNAPSHOT_USAGE ") {
            break;
        }
    }
    assert_eq!(line.trim(), "SNAPSHOT_USAGE [8,8]");
    release.write_all(b"x").unwrap();
    child.stdin.as_mut().unwrap().write_all(b"j").unwrap();
    loop {
        line.clear();
        assert_ne!(stdout.read_line(&mut line).unwrap(), 0);
        if line.starts_with("SNAPSHOT_JOINED ") {
            break;
        }
    }
    assert_eq!(line.trim(), "SNAPSHOT_JOINED [8,8]");
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
