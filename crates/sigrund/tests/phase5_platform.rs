//! Privileged Phase 5A/B platform gate. Invoke through scripts/verify-phase5.py;
//! never move a developer shell or an existing system service into this tree.
use sigrund::{
    cli::RequestOptions,
    execution::{Handshake, PreparedChild, SyncOutcome},
    startup::CgroupLayout,
};
use sigrund_core::{
    crypto::new_uuidv7,
    warrant::{Csr, CsrIdentity, SnapshotDigests},
};
use std::{
    fs::{self, File},
    os::fd::{AsRawFd, OwnedFd},
    path::Path,
    time::{Duration, Instant},
};

#[test]
#[ignore = "requires root in the dedicated scope created by scripts/verify-phase5.py"]
fn delegated_platform_gate() {
    assert_eq!(
        std::env::var("SIGRUND_PHASE5_DELEGATED_TEST").as_deref(),
        Ok("1")
    );
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let layout = CgroupLayout::discover().unwrap();
    layout.initialize().unwrap();
    assert!(
        fs::read_to_string(layout.supervisor.join("cgroup.procs"))
            .unwrap()
            .split_whitespace()
            .any(|s| s == std::process::id().to_string())
    );
    let mut parent_flags = unsafe { std::mem::zeroed::<libc::statvfs>() };
    assert_eq!(
        unsafe { libc::statvfs(c"/sys/fs/cgroup".as_ptr(), &mut parent_flags) },
        0
    );
    let parent_mounts = fs::read("/proc/self/mountinfo").unwrap();
    sigrund::execution::startup_probe(&layout).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("child-probe");
    let compile = std::process::Command::new("cc")
        .args(["-std=gnu11", "-O2", "-Wall", "-Werror"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/phase5_child.c"
        ))
        .arg("-o")
        .arg(&probe)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    for uid in [0, 33] {
        for capability in [false, true] {
            let id = new_uuidv7().to_string();
            let cgroup = layout.create_job(&id, 268_435_456, 0, 128).unwrap();
            for (entry, value) in [
                ("memory.max", "268435456"),
                ("memory.swap.max", "0"),
                ("memory.oom.group", "1"),
                ("pids.max", "128"),
            ] {
                assert_eq!(
                    fs::read_to_string(layout.jobs.join(format!("job-{id}/{entry}")))
                        .unwrap()
                        .trim(),
                    value
                );
            }
            let options = RequestOptions {
                target_uid: uid,
                target_gid: uid,
                supplementary_gids: vec![uid],
                capabilities: if capability {
                    vec!["CAP_NET_BIND_SERVICE".into()]
                } else {
                    vec![]
                },
                cwd: Some("/".into()),
                umask: 0o027,
                ..Default::default()
            };
            let hello = options
                .hello(
                    &["/usr/bin/phase5-probe".into(), "--probe".into()],
                    Path::new("/"),
                )
                .unwrap();
            let csr = Csr::from_unsigned(
                &hello,
                CsrIdentity {
                    grant_id: id.clone(),
                    host_id: format!("sigrun-host:sha256:{}", "0".repeat(64)),
                    requester_uid: 1001,
                    requester_gid: 1001,
                    now: 1,
                },
                SnapshotDigests {
                    executable_sha256: "0".repeat(64),
                    stdin_sha256: None,
                },
                3600,
            )
            .unwrap();
            let env = vec![
                std::ffi::CString::new("P5_ISOLATED=1").unwrap(),
                std::ffi::CString::new(format!("P5_UID={uid}")).unwrap(),
                std::ffi::CString::new(format!("P5_CAPS={}", if capability { 1 << 10 } else { 0 }))
                    .unwrap(),
            ];
            let mut command = PreparedChild::new(csr.warrant(), env).unwrap();
            let exe = sigrund::memfd::create_sealed(
                "phase5-platform",
                &fs::read(&probe).unwrap(),
                true,
                0o111,
            )
            .unwrap();
            let null = File::open("/dev/null").unwrap();
            let (read, write) = sigrund::execution::sync_pipe().unwrap();
            let write: OwnedFd = write;
            let child = command
                .spawn(
                    cgroup.fd(),
                    [null.as_raw_fd(), write.as_raw_fd(), 2, exe.as_raw_fd()],
                )
                .unwrap();
            drop(write);
            // Reap the registered primary before reading its setup result: fast
            // exit must retain both status and the buffered readiness evidence.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                assert_eq!(
                    unsafe {
                        libc::waitid(
                            libc::P_PIDFD,
                            child.pidfd.as_raw_fd() as u32,
                            &mut info,
                            libc::WEXITED | libc::WNOHANG,
                        )
                    },
                    0
                );
                if unsafe { info.si_pid() } != 0 {
                    break;
                }
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(2));
            }
            let mut handshake = Handshake::default();
            assert_eq!(
                handshake
                    .read(child.sync.as_raw_fd(), Instant::now(), deadline)
                    .unwrap(),
                Some(SyncOutcome::ReadyToExec)
            );
            assert_eq!(info.si_code, libc::CLD_EXITED);
            assert_eq!(unsafe { info.si_status() }, 0);
            let mut bytes = [0; 32];
            assert_eq!(
                unsafe { libc::read(read.as_raw_fd(), bytes.as_mut_ptr().cast(), 32) },
                9
            );
            assert_eq!(&bytes[..9], b"probe-ok\n");
            assert!(cgroup.cleanup().is_ok());
        }
    }
    assert_eq!(layout.cleanup_orphans().unwrap(), 0);
    let mut after = unsafe { std::mem::zeroed::<libc::statvfs>() };
    assert_eq!(
        unsafe { libc::statvfs(c"/sys/fs/cgroup".as_ptr(), &mut after) },
        0
    );
    assert_eq!(after.f_flag, parent_flags.f_flag);
    assert_eq!(fs::read("/proc/self/mountinfo").unwrap(), parent_mounts);
    drop(
        fs::OpenOptions::new()
            .write(true)
            .open("/sys/fs/cgroup/supervisor/cgroup.procs")
            .unwrap(),
    );
}
