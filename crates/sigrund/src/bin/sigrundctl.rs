use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::ExitCode,
};

use ed25519_dalek::SigningKey;
use sigrund_core::{
    audit::{entry_hmac, next_ratchet_key},
    crypto::{new_uuidv7, sha256_hex, validate_uuidv7},
};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.get(1).is_some_and(|arg| arg == "uuidv7") {
        println!("{}", new_uuidv7());
        return ExitCode::SUCCESS;
    }
    if args.get(1).is_some_and(|arg| arg == "init-host") {
        return init_host(&args);
    }
    if let Some(index) = args.iter().position(|arg| arg == "--validate-uuid") {
        let Some(value) = args.get(index + 1) else {
            eprintln!("sigrundctl: --validate-uuid requires a UUID");
            return ExitCode::from(64);
        };
        return match validate_uuidv7(value) {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("sigrundctl: invalid UUID: {error}");
                ExitCode::from(65)
            }
        };
    }
    eprintln!("sigrundctl: provisioning commands are not enabled in this build");
    ExitCode::from(78)
}

fn init_host(args: &[String]) -> ExitCode {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("sigrundctl: init-host requires effective UID 0");
        return ExitCode::from(77);
    }
    let state_dir =
        option_path(args, "--state-dir").unwrap_or_else(|| PathBuf::from("/var/lib/sigrund"));
    let log_path = option_path(args, "--log-path")
        .unwrap_or_else(|| PathBuf::from("/var/log/sigrund/audit.jsonl"));
    let key_path = state_dir.join("host_identity.key");
    let state_path = state_dir.join("audit_ratchet.state");
    if key_path.exists() || state_path.exists() || log_path.exists() {
        eprintln!("sigrundctl: refusing to overwrite existing host identity, state, or log");
        return ExitCode::from(73);
    }
    if let Err(error) = create_dir_all_durable(&state_dir).and_then(|_| {
        log_path
            .parent()
            .map(create_dir_all_durable)
            .unwrap_or_else(|| Ok(()))
    }) {
        eprintln!("sigrundctl: cannot create provisioning directories: {error}");
        return ExitCode::from(73);
    }
    let log_parent = log_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let directories = trusted_directory(&state_dir)
        .and_then(|state| trusted_directory(log_parent).map(|log| (state, log)));
    let (state_directory, log_directory) = match directories {
        Ok(directories) => directories,
        Err(error) => {
            eprintln!("sigrundctl: untrusted provisioning directory: {error}");
            return ExitCode::from(73);
        }
    };
    // Keep checked directories alive and address their entries through those
    // descriptors, even if an ancestor is renamed during provisioning.
    let state_dir = PathBuf::from(format!("/proc/self/fd/{}", state_directory.as_raw_fd()));
    let log_path = PathBuf::from(format!("/proc/self/fd/{}", log_directory.as_raw_fd()))
        .join(log_path.file_name().expect("log path has a filename"));
    let key_path = state_dir.join("host_identity.key");
    let state_path = state_dir.join("audit_ratchet.state");
    let mut host_secret = [0u8; 32];
    let mut ratchet_key = [0u8; 32];
    if let Err(error) =
        getrandom::fill(&mut host_secret).and_then(|_| getrandom::fill(&mut ratchet_key))
    {
        eprintln!("sigrundctl: secure random generation failed: {error}");
        return ExitCode::from(74);
    }
    let signing_key = SigningKey::from_bytes(&host_secret);
    let public_key = signing_key.verifying_key().to_bytes();
    let host_id = format!("sigrun-host:sha256:{}", sha256_hex(&public_key));
    let zero_digest = "0".repeat(64);
    let mut body = BTreeMap::new();
    body.insert("event_type", serde_json::Value::String("AUDIT_INIT".into()));
    body.insert("host_id", serde_json::Value::String(host_id.clone()));
    body.insert("prev_record_sha256", serde_json::Value::String(zero_digest));
    body.insert("seq", serde_json::Value::Number(0.into()));
    let body_jcs = match serde_json::to_vec(&body) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("sigrundctl: cannot serialize genesis: {error}");
            return ExitCode::from(74);
        }
    };
    let mut record = body;
    record.insert(
        "entry_hmac",
        serde_json::Value::String(entry_hmac(&ratchet_key, &body_jcs)),
    );
    let record_bytes = match serde_json::to_vec(&record) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("sigrundctl: cannot serialize genesis record: {error}");
            return ExitCode::from(74);
        }
    };
    let next_key = next_ratchet_key(&ratchet_key);
    let state = serde_json::json!({
        "key_hex": next_key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "initial_key_hex": ratchet_key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "last_record_sha256": sha256_hex(&record_bytes),
        "remote_acked_seq": 0,
        "seq": 1
    });
    let result = (|| -> std::io::Result<()> {
        write_provisioning_files(
            &state_dir,
            &log_path,
            &host_secret,
            &public_key,
            &record_bytes,
            &state,
            sync_directory,
        )?;
        if !root_owned(&key_path) || !root_owned(&log_path) || !root_owned(&state_path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "provisioned output is not root:root",
            ));
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            println!(
                "{}",
                serde_json::json!({
                    "host_id": host_id,
                    "initial_seq": 0,
                    "anchor_key_hex": ratchet_key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                    "genesis_record_sha256": sha256_hex(&record_bytes)
                })
            );
            host_secret.fill(0);
            ratchet_key.fill(0);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("sigrundctl: provisioning failed: {error}");
            ExitCode::from(74)
        }
    }
}

fn write_provisioning_files(
    state_dir: &Path,
    log_path: &Path,
    host_secret: &[u8; 32],
    public_key: &[u8; 32],
    record: &[u8],
    state: &serde_json::Value,
    mut sync_dir: impl FnMut(&Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let key_path = state_dir.join("host_identity.key");
    let state_path = state_dir.join("audit_ratchet.state");
    let mut key_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&key_path)?;
    key_file.write_all(host_secret)?;
    key_file.write_all(public_key)?;
    key_file.sync_all()?;
    let mut log_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(log_path)?;
    log_file.write_all(record)?;
    log_file.write_all(b"\n")?;
    log_file.sync_all()?;
    // Persist the genesis directory entry before publishing state that
    // depends on it, including when log and state live in different dirs.
    sync_dir(log_path.parent().unwrap_or_else(|| Path::new(".")))?;
    let state_tmp_path = state_path.with_extension("state.tmp");
    let mut state_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&state_tmp_path)?;
    state_file.write_all(&serde_json::to_vec(state).expect("state serialization"))?;
    state_file.sync_all()?;
    drop(state_file);
    fs::rename(&state_tmp_path, &state_path)?;
    sync_dir(state_dir)
}

/// Persist every link of a newly created directory hierarchy. Syncing only
/// the final directory cannot make its name durable in its parent. Walking
/// from the leaf through the filesystem root also handles existing ancestors
/// whose entries may have just been created by this provisioning invocation.
fn create_dir_all_durable(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let absolute = std::path::absolute(path)?;
    sync_directory_chain(&absolute, sync_directory)
}

fn sync_directory_chain(
    path: &Path,
    mut sync: impl FnMut(&Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    for directory in path.ancestors() {
        sync(directory)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn root_owned(path: &std::path::Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.uid() == 0 && metadata.gid() == 0)
        .unwrap_or(false)
}

fn trusted_directory(path: &Path) -> std::io::Result<File> {
    let directory = sigrund::startup::open_pinned(path)?;
    sigrund::startup::check_root_metadata(&directory, true, None)?;
    Ok(directory)
}

fn option_path(args: &[String], name: &str) -> Option<PathBuf> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_sync_includes_every_ancestor_from_leaf_to_root() {
        let mut synced = Vec::new();
        sync_directory_chain(Path::new("/var/log/sigrund"), |path| {
            synced.push(path.to_path_buf());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            synced,
            ["/var/log/sigrund", "/var/log", "/var", "/"].map(PathBuf::from)
        );
    }

    #[test]
    fn directory_sync_failure_prevents_success() {
        let mut synced = Vec::new();
        let result = sync_directory_chain(Path::new("/var/log/sigrund"), |path| {
            synced.push(path.to_path_buf());
            if path == Path::new("/var/log") {
                return Err(std::io::Error::other("injected sync failure"));
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(synced, ["/var/log/sigrund", "/var/log"].map(PathBuf::from));
    }

    #[test]
    fn durable_creation_supports_separate_nested_log_and_state_directories() {
        let temp = tempfile::tempdir().unwrap();
        for directory in [
            temp.path().join("lib/host/state"),
            temp.path().join("log/host/audit"),
        ] {
            create_dir_all_durable(&directory).unwrap();
            assert!(directory.is_dir());
            // The already-existing hierarchy remains valid on reuse.
            create_dir_all_durable(&directory).unwrap();
        }
    }

    #[test]
    fn genesis_directory_is_synced_before_state_publication() {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let log_dir = temp.path().join("log");
        let log_path = log_dir.join("audit.jsonl");
        create_dir_all_durable(&state_dir).unwrap();
        create_dir_all_durable(&log_dir).unwrap();
        let state = serde_json::json!({"seq": 1});
        let state_path = state_dir.join("audit_ratchet.state");
        let mut barriers = Vec::new();
        write_provisioning_files(
            &state_dir,
            &log_path,
            &[7; 32],
            &[8; 32],
            br#"{"seq":0}"#,
            &state,
            |path| {
                if path == log_dir {
                    assert_eq!(std::fs::read(&log_path).unwrap(), b"{\"seq\":0}\n");
                    assert!(!state_path.exists());
                    assert!(!state_path.with_extension("state.tmp").exists());
                } else {
                    assert_eq!(path, state_dir);
                    assert_eq!(barriers, vec![log_dir.clone()]);
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(
                            &std::fs::read(&state_path).unwrap()
                        )
                        .unwrap(),
                        state
                    );
                    assert!(!state_path.with_extension("state.tmp").exists());
                }
                barriers.push(path.to_path_buf());
                sync_directory(path)
            },
        )
        .unwrap();
        assert_eq!(barriers, vec![log_dir, state_dir]);
    }

    #[test]
    fn log_directory_sync_failure_leaves_ratchet_state_unpublished() {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let log_dir = temp.path().join("log");
        let log_path = log_dir.join("audit.jsonl");
        create_dir_all_durable(&state_dir).unwrap();
        create_dir_all_durable(&log_dir).unwrap();
        let error = write_provisioning_files(
            &state_dir,
            &log_path,
            &[7; 32],
            &[8; 32],
            br#"{"seq":0}"#,
            &serde_json::json!({"seq": 1}),
            |path| {
                assert_eq!(path, log_dir);
                Err(std::io::Error::other(
                    "injected log directory fsync failure",
                ))
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected log directory fsync failure")
        );
        assert!(!state_dir.join("audit_ratchet.state").exists());
        assert!(!state_dir.join("audit_ratchet.state.tmp").exists());
    }
}
