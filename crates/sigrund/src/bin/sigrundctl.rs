use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
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
    if let Err(error) = fs::create_dir_all(&state_dir).and_then(|_| {
        log_path
            .parent()
            .map(fs::create_dir_all)
            .unwrap_or_else(|| Ok(()))
    }) {
        eprintln!("sigrundctl: cannot create provisioning directories: {error}");
        return ExitCode::from(73);
    }
    let log_parent = log_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    if !root_owned_dir(&state_dir) || !root_owned_dir(log_parent) {
        eprintln!("sigrundctl: provisioning directories must be owned by root:root");
        return ExitCode::from(73);
    }
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
        let mut key_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&key_path)?;
        key_file.write_all(&host_secret)?;
        key_file.write_all(&public_key)?;
        key_file.sync_all()?;
        let mut log_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&log_path)?;
        log_file.write_all(&record_bytes)?;
        log_file.write_all(b"\n")?;
        log_file.sync_all()?;
        let state_tmp_path = state_path.with_extension("state.tmp");
        let mut state_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&state_tmp_path)?;
        state_file.write_all(&serde_json::to_vec(&state).expect("state serialization"))?;
        state_file.sync_all()?;
        drop(state_file);
        fs::rename(&state_tmp_path, &state_path)?;
        if let Some(parent) = state_path.parent() {
            File::open(parent)?.sync_all()?;
        }
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

fn root_owned(path: &std::path::Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.uid() == 0 && metadata.gid() == 0)
        .unwrap_or(false)
}

fn root_owned_dir(path: &std::path::Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_dir() && metadata.uid() == 0 && metadata.gid() == 0)
        .unwrap_or(false)
}

fn option_path(args: &[String], name: &str) -> Option<PathBuf> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .map(PathBuf::from)
}
