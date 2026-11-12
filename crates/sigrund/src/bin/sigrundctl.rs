use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use sigrund::cli::{absolute_path, parse_exit};
use sigrund_core::{
    audit::{entry_hmac, next_ratchet_key},
    crypto::{new_uuidv7, sha256_hex, validate_uuidv7},
};

#[derive(Parser)]
#[command(
    name = "sigrundctl",
    version,
    about = "Provision hosts, manage targets and package offline warrants",
    arg_required_else_help = true,
    args_conflicts_with_subcommands = true,
    after_help = "Offline helpers preserve exact canonical CSR bytes. Outputs are new private files; existing files are never overwritten. The daemon enforces trust and policy."
)]
struct Cli {
    /// Validate a UUIDv7 (also available as the validate-uuid subcommand)
    #[arg(long, value_name = "UUID", exclusive = true)]
    validate_uuid: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Create a fresh host identity, audit log and state database (root only)
    InitHost {
        /// Empty persistent state directory
        #[arg(long, value_name = "PATH", value_parser = absolute_path)]
        state_dir: PathBuf,
        /// New audit log in an empty directory
        #[arg(long, value_name = "PATH", value_parser = absolute_path)]
        log_path: PathBuf,
    },
    /// Manage registered execution targets and export host bindings
    Target {
        #[command(subcommand)]
        command: TargetCommand,
    },
    /// Extract signing bytes from an exact canonical full CSR
    CsrPae {
        /// Input canonical CSR
        #[arg(long, value_name = "PATH")]
        csr: PathBuf,
        /// New output file for DSSE pre-authentication encoding
        #[arg(long, value_name = "PATH")]
        pae: PathBuf,
    },
    /// Package a CSR and OpenSSH signature into a signed envelope
    PackWarrant {
        /// Input canonical CSR
        #[arg(long, value_name = "PATH")]
        csr: PathBuf,
        /// OpenSSH signature file
        #[arg(long, value_name = "PATH")]
        signature: PathBuf,
        /// Configured signer identity
        #[arg(long, value_name = "ID", value_parser = clap::builder::NonEmptyStringValueParser::new())]
        signer_id: String,
        /// New signed envelope file
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Generate a UUIDv7
    Uuidv7,
    /// Validate a UUIDv7
    ValidateUuid { uuid: String },
}

#[derive(Subcommand)]
enum TargetCommand {
    /// Register a process environment using a daemon-visible PID (root only)
    Register(RegistrationArgs),
    /// Register a target bound to a local Podman container (root only)
    RegisterPodman {
        #[command(flatten)]
        registration: RegistrationArgs,
        /// Root-owned local Podman Unix socket
        #[arg(long, value_name = "PATH", value_parser = absolute_path)]
        podman_endpoint: PathBuf,
        /// Podman manager owner (must be 0)
        #[arg(long, value_name = "UID")]
        podman_owner_uid: u32,
        /// Libpod namespace (must be default)
        #[arg(long, value_name = "NAMESPACE")]
        podman_namespace: String,
        /// Container name
        #[arg(long, value_name = "NAME")]
        podman_container: String,
    },
    /// Revoke a registered target (root only)
    Revoke {
        #[arg(value_parser = identifier)]
        id: String,
        /// Client socket; management socket is derived from this path
        #[arg(long, default_value = sigrund::cli::CLIENT_SOCKET, value_name = "PATH", value_parser = absolute_path)]
        socket: PathBuf,
    },
    /// Export a live host binding bundle (root only)
    ExportBinding {
        #[command(subcommand)]
        target: BindingTarget,
    },
}

#[derive(Subcommand)]
enum BindingTarget {
    /// Export the current host and security profile binding
    Host {
        #[arg(long, value_name = "ID", value_parser = identifier)]
        security_profile: String,
        #[arg(long, default_value = sigrund::host_registry::DEFAULT_EPOCH_FILE, value_name = "PATH", value_parser = absolute_path)]
        epoch_file: PathBuf,
        #[arg(long, value_name = "PATH", value_parser = absolute_path)]
        output: PathBuf,
    },
}

#[derive(Args)]
struct RegistrationArgs {
    /// Target registration ID
    #[arg(value_parser = identifier)]
    id: String,
    /// PID as seen by the daemon
    #[arg(long, value_name = "DAEMON_PID", value_parser = clap::value_parser!(u32).range(1..=2147483647))]
    pid: u32,
    /// Host UID allowed to use this registration
    #[arg(long, value_name = "HOST_UID")]
    owner_uid: u32,
    /// Configured destination security profile
    #[arg(long, value_name = "ID", value_parser = identifier)]
    security_profile: String,
    /// Client socket; management socket is derived from this path
    #[arg(long, default_value = sigrund::cli::CLIENT_SOCKET, value_name = "PATH", value_parser = absolute_path)]
    socket: PathBuf,
}

fn identifier(value: &str) -> sigrund_core::Result<String> {
    sigrund_core::namespace::identifier(value)?;
    Ok(value.into())
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return parse_exit(error),
    };
    let command = match (cli.command, cli.validate_uuid) {
        (Some(command), _) => command,
        (_, Some(uuid)) => Command::ValidateUuid { uuid },
        _ => unreachable!("clap requires a command or --validate-uuid"),
    };
    let result = match command {
        Command::InitHost {
            state_dir,
            log_path,
        } => return init_host(state_dir, log_path),
        Command::Target { command } => target_command(command),
        Command::CsrPae { csr, pae } => offline_pae(&csr, &pae),
        Command::PackWarrant {
            csr,
            signature,
            signer_id,
            output,
        } => offline_pack(&csr, &signature, &signer_id, &output),
        Command::Uuidv7 => {
            println!("{}", new_uuidv7());
            return ExitCode::SUCCESS;
        }
        Command::ValidateUuid { uuid } => validate_uuidv7(&uuid).map(|_| ()).map_err(Into::into),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sigrundctl: {error}");
            ExitCode::from(65)
        }
    }
}

fn target_command(command: TargetCommand) -> Result<(), Box<dyn std::error::Error>> {
    use sigrund::target_management::{Request, execute, management_path};
    if let TargetCommand::ExportBinding {
        target:
            BindingTarget::Host {
                security_profile,
                epoch_file,
                output,
            },
    } = command
    {
        return export_binding(&security_profile, &epoch_file, &output);
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err("target management requires effective UID 0".into());
    }
    let (socket, request) = match command {
        TargetCommand::Register(args) => (
            args.socket,
            Request::Register {
                id: args.id,
                daemon_pid: args.pid,
                owner_uid: args.owner_uid,
                security_profile: args.security_profile,
            },
        ),
        TargetCommand::RegisterPodman {
            registration: args,
            podman_endpoint,
            podman_owner_uid,
            podman_namespace,
            podman_container,
        } => {
            use sigrund_core::namespace::Contract;
            let selector = sigrund_core::manager::PodmanSelector {
                schema: "sigrund.podman-selector.v1".into(),
                endpoint: podman_endpoint
                    .to_str()
                    .expect("validated UTF-8 path")
                    .into(),
                owner_uid: podman_owner_uid,
                manager_namespace: podman_namespace,
                container_name: podman_container,
            };
            selector.validate()?;
            (
                args.socket,
                Request::RegisterPodmanV1 {
                    id: args.id,
                    daemon_pid: args.pid,
                    owner_uid: args.owner_uid,
                    security_profile: args.security_profile,
                    selector,
                },
            )
        }
        TargetCommand::Revoke { id, socket } => (socket, Request::Revoke { id }),
        TargetCommand::ExportBinding { .. } => unreachable!(),
    };
    execute(&management_path(&socket), &request)?;
    Ok(())
}

fn export_binding(
    profile: &str,
    epoch: &Path,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use sigrund_core::host::Record;
    if unsafe { libc::geteuid() } != 0 {
        return Err("binding export requires effective UID 0".into());
    }
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

fn bounded_read(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "input exceeds size bound",
        ));
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn offline_pae(csr: &Path, pae: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let csr = sigrund_core::warrant::CanonicalWarrant::parse(&bounded_read(csr, 65_536)?)?;
    csr.warrant().require_client_full()?;
    write_new(pae, &sigrund::warrant_tools::csr_pae(&csr))?;
    Ok(())
}

fn offline_pack(
    csr: &Path,
    signature: &Path,
    signer_id: &str,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = sigrund::warrant_tools::pack_warrant(
        &bounded_read(csr, 65_536)?,
        &bounded_read(signature, 34_000)?,
        signer_id,
    )?;
    write_new(output, &envelope)?;
    Ok(())
}

fn init_host(state_dir: PathBuf, log_path: PathBuf) -> ExitCode {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("sigrundctl: init-host requires effective UID 0");
        return ExitCode::from(77);
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
