use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
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
    if args.get(1).is_some_and(|arg| arg == "--help") {
        println!(
            "Usage: sigrundctl init-host --state-dir PATH --log-path PATH\n       sigrundctl target register ID --pid DAEMON_PID --owner-uid HOST_UID --security-profile ID [--socket PATH]\n       sigrundctl target register-podman ID --pid DAEMON_PID --owner-uid HOST_UID --security-profile ID --podman-endpoint PATH --podman-owner-uid 0 --podman-namespace default --podman-container NAME [--socket PATH]\n       sigrundctl target revoke ID [--socket PATH]\n       sigrundctl target export-binding host --security-profile ID [--epoch-file PATH] --output PATH\n       sigrundctl csr-pae --csr PATH --pae PATH\n       sigrundctl pack-warrant --csr PATH --signature PATH --signer-id ID --output PATH\n       sigrundctl uuidv7 | --validate-uuid UUID\nOffline helpers preserve the exact canonical CSR bytes. Outputs are new private files; existing files are never overwritten. Packaging verifies signature binding; the daemon enforces trust and policy."
        );
        return ExitCode::SUCCESS;
    }
    if args
        .get(1)
        .is_some_and(|arg| matches!(arg.as_str(), "csr-pae" | "pack-warrant"))
    {
        return match offline_warrant(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("sigrundctl: {error}");
                ExitCode::from(65)
            }
        };
    }
    if args.get(1).is_some_and(|arg| arg == "target") {
        return match target_command(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("sigrundctl: {error}");
                ExitCode::from(65)
            }
        };
    }
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

fn target_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use sigrund::target_management::{Request, execute, management_path};
    if args.get(1).is_some_and(|value| value == "export-binding") {
        return export_binding(args);
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err("target management requires effective UID 0".into());
    }
    let operation = args.get(1).ok_or("missing target operation")?;
    let id = args.get(2).ok_or("missing target registration ID")?.clone();
    sigrund_core::namespace::identifier(&id)?;
    let mut options = BTreeMap::new();
    for pair in args[3..].chunks(2) {
        if pair.len() != 2
            || pair[1].is_empty()
            || ![
                "--pid",
                "--owner-uid",
                "--security-profile",
                "--socket",
                "--podman-endpoint",
                "--podman-owner-uid",
                "--podman-namespace",
                "--podman-container",
            ]
            .contains(&pair[0].as_str())
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("invalid or duplicate target management option".into());
        }
    }
    let socket = Path::new(options.remove("--socket").unwrap_or("/run/sigrund.sock"));
    sigrund::linux::validate_absolute_path(socket)?;
    let request = match operation.as_str() {
        "register" | "register-podman" => {
            let managed = operation == "register-podman";
            if options.len() != if managed { 7 } else { 3 } {
                return Err("register requires --pid, --owner-uid and --security-profile".into());
            }
            let daemon_pid = options.get("--pid").ok_or("--pid required")?.parse()?;
            let owner_uid = options
                .get("--owner-uid")
                .ok_or("--owner-uid required")?
                .parse()?;
            let security_profile = options
                .get("--security-profile")
                .ok_or("--security-profile required")?
                .to_string();
            if managed {
                use sigrund_core::namespace::Contract;
                let selector = sigrund_core::manager::PodmanSelector {
                    schema: "sigrund.podman-selector.v1".into(),
                    endpoint: options
                        .get("--podman-endpoint")
                        .ok_or("--podman-endpoint required")?
                        .to_string(),
                    owner_uid: options
                        .get("--podman-owner-uid")
                        .ok_or("--podman-owner-uid required")?
                        .parse()?,
                    manager_namespace: options
                        .get("--podman-namespace")
                        .ok_or("--podman-namespace required")?
                        .to_string(),
                    container_name: options
                        .get("--podman-container")
                        .ok_or("--podman-container required")?
                        .to_string(),
                };
                selector.validate()?;
                Request::RegisterPodmanV1 {
                    id,
                    daemon_pid,
                    owner_uid,
                    security_profile,
                    selector,
                }
            } else {
                Request::Register {
                    id,
                    daemon_pid,
                    owner_uid,
                    security_profile,
                }
            }
        }
        "revoke" if options.is_empty() => Request::Revoke { id },
        _ => return Err("invalid target management operation".into()),
    };
    execute(&management_path(socket), &request)?;
    Ok(())
}

fn export_binding(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use sigrund_core::host::Record;
    if unsafe { libc::geteuid() } != 0 {
        return Err("binding export requires effective UID 0".into());
    }
    if args.len() < 3 || args[1] != "export-binding" || args[2] != "host" {
        return Err("expected target export-binding host".into());
    }
    let mut options = BTreeMap::new();
    for pair in args[3..].chunks(2) {
        if pair.len() != 2
            || !["--security-profile", "--epoch-file", "--output"].contains(&pair[0].as_str())
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("invalid or duplicate binding export option".into());
        }
    }
    let profile = options
        .get("--security-profile")
        .ok_or("--security-profile is required")?;
    let output = Path::new(options.get("--output").ok_or("--output is required")?);
    sigrund::linux::validate_absolute_path(output)?;
    let epoch = Path::new(
        options
            .get("--epoch-file")
            .copied()
            .unwrap_or(sigrund::host_registry::DEFAULT_EPOCH_FILE),
    );
    let bundle = sigrund::host_registry::live_bundle(epoch, profile)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(&bundle.canonical()?)?;
    file.sync_all()?;
    File::open(
        output
            .parent()
            .ok_or("output requires a parent directory")?,
    )?
    .sync_all()?;
    Ok(())
}

fn offline_warrant(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use sigrund::warrant_tools::{csr_pae, pack_warrant};
    let expected: &[&str] = if args[0] == "csr-pae" {
        &["--csr", "--pae"]
    } else {
        &["--csr", "--signature", "--signer-id", "--output"]
    };
    let mut options = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        if pair.len() != 2
            || !expected.contains(&pair[0].as_str())
            || pair[1].is_empty()
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("invalid, duplicate or incomplete offline option; see --help".into());
        }
    }
    if options.len() != expected.len() {
        return Err("missing offline option; see --help".into());
    }
    let bounded_read = |path: &str, max: u64| -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(path)?.take(max + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "input exceeds size bound",
            ));
        }
        Ok(bytes)
    };
    let write_new = |path: &str, bytes: &[u8]| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    };
    if args[0] == "csr-pae" {
        let csr = sigrund_core::warrant::CanonicalWarrant::parse(&bounded_read(
            options["--csr"],
            65_536,
        )?)?;
        csr.warrant().require_client_full()?;
        write_new(options["--pae"], &csr_pae(&csr))?;
    } else {
        let envelope = pack_warrant(
            &bounded_read(options["--csr"], 65_536)?,
            &bounded_read(options["--signature"], 34_000)?,
            options["--signer-id"],
        )?;
        write_new(options["--output"], &envelope)?;
    }
    Ok(())
}

fn init_host(args: &[String]) -> ExitCode {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("sigrundctl: init-host requires effective UID 0");
        return ExitCode::from(77);
    }
    let mut options = BTreeMap::new();
    for pair in args[2..].chunks(2) {
        if pair.len() != 2
            || !["--state-dir", "--log-path"].contains(&pair[0].as_str())
            || options
                .insert(pair[0].as_str(), PathBuf::from(&pair[1]))
                .is_some()
        {
            eprintln!("sigrundctl: invalid, duplicate or incomplete provisioning option");
            return ExitCode::from(64);
        }
    }
    let Some(state_dir) = options.remove("--state-dir") else {
        eprintln!("sigrundctl: init-host requires explicit --state-dir");
        return ExitCode::from(64);
    };
    let Some(log_path) = options.remove("--log-path") else {
        eprintln!("sigrundctl: init-host requires explicit --log-path");
        return ExitCode::from(64);
    };
    if [&state_dir, &log_path]
        .iter()
        .any(|path| sigrund::linux::validate_absolute_path(path).is_err())
    {
        eprintln!("sigrundctl: provisioning paths must be canonical absolute paths");
        return ExitCode::from(64);
    }
    let key_path = state_dir.join("host_identity.key");
    let state_path = state_dir.join("audit_ratchet.state");
    if key_path.exists()
        || state_path.exists()
        || log_path.exists()
        || state_dir.join("state.sqlite").exists()
        || state_dir.read_dir().is_ok_and(|mut d| d.next().is_some())
        || log_path
            .parent()
            .is_some_and(|parent| parent.read_dir().is_ok_and(|mut d| d.next().is_some()))
    {
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
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("state directory {}: {error}", state_dir.display()),
            )
        })
        .and_then(|state| {
            trusted_directory(log_parent)
                .map(|log| (state, log))
                .map_err(|error| {
                    std::io::Error::new(
                        error.kind(),
                        format!("log directory {}: {error}", log_parent.display()),
                    )
                })
        });
    let (state_directory, log_directory) = match directories {
        Ok(directories) => directories,
        Err(error) => {
            eprintln!("sigrundctl: untrusted provisioning directory: {error}");
            return ExitCode::from(73);
        }
    };
    // Keep checked directories alive and address their entries through those
    // descriptors, even if an ancestor is renamed during provisioning.
    for directory in [&state_directory, &log_directory] {
        match fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map(|mut entries| entries.next().is_none())
        {
            Ok(true) => (),
            _ => {
                eprintln!("sigrundctl: provisioning requires empty state and log directories");
                return ExitCode::from(73);
            }
        }
    }
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
    body.insert("schema_version", serde_json::json!(3));
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
        "schema_version":3,
        "key_hex": next_key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "initial_key_hex": ratchet_key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "last_record_sha256": sha256_hex(&record_bytes),
        "remote_acked_seq": 0,
        "seq": 1
    });
    let result = (|| -> std::io::Result<()> {
        let _database =
            sigrund_core::state::StateStore::create_in_directory(state_directory.try_clone()?)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
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
                    "schema_version": 3,
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
