use std::process::Command;

#[test]
fn pinned_root_entry_preserves_the_private_mount_tree() {
    if std::env::consts::ARCH != "x86_64" {
        return;
    }
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
fn kernel_connector_identity_survives_socket_passing_and_detects_exit() {
    if std::env::consts::ARCH != "x86_64" {
        return; // x86-64 register ABI in the experimental acquisition helper.
    }
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
