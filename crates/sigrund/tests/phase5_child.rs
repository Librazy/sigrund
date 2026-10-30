//! Child-path gates use production C source in a separate test translation
//! unit. Fault switches never enter the daemon/library build.
use std::process::Command;
#[test]
fn syscall_child_transition_and_descriptor_faults() {
    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("phase5-child");
    let build = Command::new("cc")
        .args(["-std=gnu11", "-O2", "-Wall", "-Werror"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/phase5_child.c"
        ))
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let run = Command::new("timeout")
        .arg("30s")
        .arg("unshare")
        .args(["--user", "--map-auto", "--map-root-user"])
        .arg(executable)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.stdout, b"phase5-child-ok\n");
}
