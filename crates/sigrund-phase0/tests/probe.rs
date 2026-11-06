#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::process::Command;

#[test]
#[ignore = "requires cc, timeout, unshare --map-auto, subordinate ID maps and user/mount namespace permissions"]
fn pinned_root_entry_preserves_the_private_mount_tree() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    std::fs::create_dir_all(root.join("run")).unwrap();
    let executable = directory.path().join("mount-isolation");
    let build = Command::new("cc")
        .args([
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/mount-isolation.c"
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
    let output = Command::new("timeout")
        .args(["15s", "unshare", "--user", "--map-auto", "--map-root-user"])
        .arg(&executable)
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observation: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(observation["private_mount_visible"], true);
    assert_eq!(observation["anchor_mount_unchanged"], true);
    assert!(!root.join("run/sigrund-phase0-private-mount").exists());
}

#[test]
#[ignore = "requires cc, timeout and a Linux kernel supporting SO_PEERPIDFD"]
fn kernel_connector_identity_survives_socket_passing_and_detects_exit() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("probe");
    let build = Command::new("cc")
        .args([
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/namespace-phase0/probe.c"
        ))
        .args(["-o"])
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let output = Command::new("timeout")
        .arg("10s")
        .arg(executable)
        .arg("peer")
        .arg(directory.path().join("peer.sock"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observation: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(observation["passed_socket_keeps_connector"], true);
    assert_eq!(observation["connector_exit_detected"], true);
}
