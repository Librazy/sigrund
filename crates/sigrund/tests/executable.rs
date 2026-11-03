use base64::{Engine as _, engine::general_purpose::STANDARD};
use sigrund::{executable, execution, reaper::Reaper, snapshot::SnapshotBudget};
use sigrund_core::{
    config::DaemonConfig, executable::TrustModel, protocol::RequestedExecutionContext,
};
use std::{
    fs::File,
    io::Write,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    time::{Duration, Instant},
};

fn config() -> DaemonConfig {
    DaemonConfig::from_toml(
        include_str!("../../../config/sigrund.toml.example")
            .replace(
                "<strict-padded-base64-32-byte-ed25519-key>",
                &STANDARD.encode([1; 32]),
            )
            .as_bytes(),
    )
    .unwrap()
}
fn context() -> RequestedExecutionContext {
    RequestedExecutionContext {
        capabilities: vec![],
        env_exact: Default::default(),
        caller_env_allowlist: vec![],
        supplementary_gids: vec![],
        target_uid: unsafe { libc::getuid() },
        target_gid: unsafe { libc::getgid() },
        umask: 0o077,
    }
}
fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

#[test]
fn selection_limits_and_cross_thread_exec_checkpoint() {
    let mut cfg = config();
    let budget = SnapshotBudget::default();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("program");
    let code = dir.path().join("probe.c");
    std::fs::write(
        &code,
        "#include <unistd.h>\n#include <signal.h>\nint main(void){raise(SIGSTOP);return write(1,\"target-entered\",14)==14?0:1;}\n",
    )
    .unwrap();
    assert!(
        std::process::Command::new("cc")
            .arg(&code)
            .arg("-o")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Lack of tracing and non-root-owned sources leave the original fallback.
    let prepared = executable::prepare(
        File::open(&path).unwrap(),
        executable::Selection {
            signed: None,
            context: &context(),
            trace_available: false,
            allow_file_capabilities: false,
        },
        &budget,
        1001,
        &cfg,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(prepared.model(), TrustModel::DigestMemfd);
    assert!(prepared.sha256().is_some());
    assert!(budget.usage(1001).0 > 0);
    drop(prepared);
    assert_eq!(budget.usage(1001), (0, 0));
    cfg.max_executable_bytes = 4;
    assert!(
        executable::prepare(
            File::open(&path).unwrap(),
            executable::Selection {
                signed: None,
                context: &context(),
                trace_available: false,
                allow_file_capabilities: false,
            },
            &budget,
            1001,
            &cfg,
            || Ok(())
        )
        .is_err()
    );
    cfg.executable_trust_models = vec![TrustModel::FsVerity];
    assert!(
        executable::prepare(
            File::open(&path).unwrap(),
            executable::Selection {
                signed: None,
                context: &context(),
                trace_available: false,
                allow_file_capabilities: false,
            },
            &budget,
            1001,
            &cfg,
            || Ok(())
        )
        .is_err()
    );

    let source = File::open(&path).unwrap();
    let output = tempfile::tempfile().unwrap();
    let (gate_read, gate_write) = pipe();
    let input_fd = source.as_raw_fd();
    let output_fd = output.as_raw_fd();
    let (send, receive) = std::sync::mpsc::channel();
    let (done, wait) = std::sync::mpsc::channel::<()>();
    // The creator stays alive: the coordinator must become the tracer itself,
    // rather than relying on TRACEME's relationship to a different thread.
    let creator = std::thread::spawn(move || {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::close(gate_write.as_raw_fd());
                let mut byte = 0u8;
                if libc::read(gate_read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) != 1 {
                    libc::_exit(120);
                }
                libc::dup2(output_fd, 1);
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                let args = [
                    c"printf".as_ptr(),
                    c"target-entered".as_ptr(),
                    std::ptr::null(),
                ];
                let env: [*const libc::c_char; 1] = [std::ptr::null()];
                libc::syscall(
                    libc::SYS_execveat,
                    input_fd,
                    c"".as_ptr(),
                    args.as_ptr(),
                    env.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
                libc::_exit(121);
            }
        }
        drop(gate_read);
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0);
        send.send((pid, unsafe { OwnedFd::from_raw_fd(fd as i32) }, gate_write))
            .unwrap();
        wait.recv().unwrap();
    });
    let (pid, pidfd, gate) = receive.recv().unwrap();
    let mut reaper = Reaper::default();
    assert!(reaper.reserve(1));
    assert!(reaper.complete(1, Some((pid, pidfd))).is_ok());
    execution::attach_checkpoint(pid, &gate).unwrap();
    drop(gate);
    reaper.traced(pid);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let exits = reaper.poll().unwrap();
        assert!(exits.is_empty(), "unexpected early exit: {exits:?}");
        let stops = reaper.take_stops();
        if !stops.is_empty() {
            assert_eq!(stops.len(), 1);
            assert_eq!(
                stops[0].status,
                libc::SIGTRAP | (libc::PTRACE_EVENT_EXEC << 8)
            );
            break;
        }
        assert!(Instant::now() < deadline, "exec event missing");
        std::thread::yield_now();
    }
    assert_eq!(
        output.metadata().unwrap().len(),
        0,
        "entry code ran before release"
    );
    let error = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ETXTBSY));
    execution::release_checkpoint(pid).unwrap();
    reaper.detached(pid);
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as u32,
                    &mut info,
                    libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
                )
            },
            0
        );
        if unsafe { info.si_pid() } != 0 {
            assert_eq!(info.si_code, libc::CLD_STOPPED);
            assert_eq!(unsafe { info.si_status() }, libc::SIGSTOP);
            break;
        }
        assert!(Instant::now() < deadline, "normal suspension missing");
        std::thread::yield_now();
    }
    // After detach ordinary suspension must neither retire the child nor
    // produce a ptrace stop for the coordinator to reject.
    assert!(reaper.poll().unwrap().is_empty());
    assert!(reaper.take_stops().is_empty());
    assert!(reaper.registered_fd(pid).is_some());
    assert_eq!(unsafe { libc::kill(pid, libc::SIGCONT) }, 0);
    loop {
        let exits = reaper.poll().unwrap();
        if !exits.is_empty() {
            assert_eq!((exits[0].code, exits[0].status), (libc::CLD_EXITED, 0));
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert_eq!(output.metadata().unwrap().len(), 14);
    done.send(()).unwrap();
    creator.join().unwrap();
    assert!(reaper.is_idle());

    let run = std::process::Command::new("timeout")
        .arg("20s")
        .arg("unshare")
        .args(["--user", "--map-auto", "--map-root-user", "--mount"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "ctime_namespace_fixture",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
#[ignore = "invoked in a root-mapped mount namespace"]
fn ctime_namespace_fixture() {
    let mut cfg = config();
    cfg.max_executable_bytes = 4;
    cfg.snapshot_ram_per_uid_bytes = 4;
    cfg.snapshot_ram_global_bytes = 4;
    let budget = SnapshotBudget::default();
    // Mount our own executable tmpfs: the system /dev/shm may be noexec.
    let dir = tempfile::tempdir().unwrap();
    let mountpoint = std::ffi::CString::new(dir.path().as_os_str().as_bytes()).unwrap();
    assert_eq!(
        unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                mountpoint.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                std::ptr::null(),
            )
        },
        0
    );
    let path = dir.path().join("large-elf");
    let mut file = File::create(&path).unwrap();
    file.write_all(b"\x7fELF").unwrap();
    file.set_len(67_108_865).unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(0o755))
        .unwrap();
    drop(file);
    let prepared = executable::prepare(
        File::open(&path).unwrap(),
        executable::Selection {
            signed: None,
            context: &context(),
            trace_available: true,
            allow_file_capabilities: false,
        },
        &budget,
        1001,
        &cfg,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(prepared.model(), TrustModel::Ctime);
    assert_eq!(prepared.digest.bytes, 67_108_865);
    assert_eq!(prepared.sha256(), None);
    assert_eq!(budget.usage(1001), (0, 0));
    prepared.verify_direct(&context().into()).unwrap();
    cfg.executable_trust_models = vec![TrustModel::DigestMemfd, TrustModel::Ctime];
    assert!(
        executable::prepare(
            File::open(&path).unwrap(),
            executable::Selection {
                signed: None,
                context: &context(),
                trace_available: true,
                allow_file_capabilities: false,
            },
            &budget,
            1001,
            &cfg,
            || Ok(())
        )
        .is_err()
    );
    cfg.executable_trust_models = vec![TrustModel::Ctime];
    assert!(
        executable::prepare(
            File::open(&path).unwrap(),
            executable::Selection {
                signed: None,
                context: &context(),
                trace_available: false,
                allow_file_capabilities: false,
            },
            &budget,
            1001,
            &cfg,
            || Ok(())
        )
        .is_err()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(prepared.verify_direct(&context().into()).is_err());
    assert!(
        executable::prepare(
            File::open(&path).unwrap(),
            executable::Selection {
                signed: None,
                context: &context(),
                trace_available: true,
                allow_file_capabilities: false,
            },
            &budget,
            1001,
            &cfg,
            || Ok(())
        )
        .is_err()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(100)
        .unwrap();
    assert!(prepared.verify_direct(&context().into()).is_err());
    assert_eq!(budget.usage(1001), (0, 0));

    // noexec must force fallback before approval, for the same otherwise
    // ctime-eligible inode. The sealed copy must remain executable.
    let code = dir.path().join("noexec.c");
    let path = dir.path().join("noexec-elf");
    std::fs::write(&code, "int main(void){return 42;}\n").unwrap();
    assert!(
        std::process::Command::new("cc")
            .arg(&code)
            .arg("-o")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    cfg = config();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let select = |cfg: &DaemonConfig| {
        executable::prepare(
            File::open(&path).unwrap(),
            executable::Selection {
                signed: None,
                context: &context(),
                trace_available: true,
                allow_file_capabilities: false,
            },
            &budget,
            1001,
            cfg,
            || Ok(()),
        )
    };
    assert_eq!(select(&cfg).unwrap().model(), TrustModel::Ctime);
    // UID 0 with no capabilities uses the owner permission class, even if
    // group and other execute bits are set. Select the working snapshot path.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o655)).unwrap();
    let fallback = select(&cfg).unwrap();
    assert_eq!(fallback.model(), TrustModel::DigestMemfd);
    assert_eq!(
        std::process::Command::new(format!("/proc/self/fd/{}", fallback.as_fd().as_raw_fd()))
            .status()
            .unwrap()
            .code(),
        Some(42)
    );
    drop(fallback);
    let mut direct_only = cfg.clone();
    direct_only.executable_trust_models = vec![TrustModel::Ctime];
    assert!(select(&direct_only).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(select(&cfg).unwrap().model(), TrustModel::Ctime);
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                mountpoint.as_ptr(),
                std::ptr::null(),
                libc::MS_REMOUNT | libc::MS_NOEXEC | libc::MS_NOSUID | libc::MS_NODEV,
                std::ptr::null(),
            )
        },
        0
    );
    assert_eq!(
        std::process::Command::new(&path)
            .status()
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EACCES)
    );
    let fallback = select(&cfg).unwrap();
    assert_eq!(fallback.model(), TrustModel::DigestMemfd);
    assert_eq!(
        std::process::Command::new(format!("/proc/self/fd/{}", fallback.as_fd().as_raw_fd()))
            .status()
            .unwrap()
            .code(),
        Some(42)
    );
    drop(fallback);
    cfg.max_executable_bytes = 4;
    assert!(select(&cfg).is_err());
    cfg = config();
    cfg.executable_trust_models = vec![TrustModel::Ctime];
    assert!(select(&cfg).is_err());
    assert_eq!(budget.usage(1001), (0, 0));
    assert_eq!(
        unsafe { libc::umount2(mountpoint.as_ptr(), libc::MNT_DETACH) },
        0
    );
}
