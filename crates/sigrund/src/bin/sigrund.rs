use std::{env, fs, process::ExitCode};

use sigrund::startup::CgroupLayout;
use sigrund_core::config::{DaemonConfig, SignerPolicyFile};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let config_path = env::var_os("SIGRUND_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/etc/sigrund/config.toml".into());
    let bytes = match fs::read(&config_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("sigrund: cannot read {}: {error}", config_path.display());
            return ExitCode::from(78);
        }
    };
    let config = match DaemonConfig::from_toml(&bytes) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("sigrund: refusing invalid configuration: {error}");
            return ExitCode::from(78);
        }
    };
    let signer_path = env::var_os("SIGRUND_SIGNERS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/etc/sigrund/signers.toml".into());
    let signer_bytes = match fs::read(&signer_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("sigrund: cannot read {}: {error}", signer_path.display());
            return ExitCode::from(78);
        }
    };
    if let Err(error) = SignerPolicyFile::from_toml(&signer_bytes)
        .and_then(|signers| signers.validate_against(&config))
    {
        eprintln!("sigrund: refusing invalid configuration: {error}");
        return ExitCode::from(78);
    }
    if let Some(index) = args.iter().position(|arg| arg == "--check-cgroup") {
        let Some(root) = args.get(index + 1) else {
            eprintln!("sigrund: --check-cgroup requires a delegated cgroup path");
            return ExitCode::from(64);
        };
        return match CgroupLayout::from_root(root).initialize() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("sigrund: cgroup startup gate failed: {error}");
                ExitCode::from(78)
            }
        };
    }
    if args.iter().any(|arg| arg == "--check-config") {
        return ExitCode::SUCCESS;
    }
    eprintln!("sigrund: configuration validated; privileged runtime is not enabled in this build");
    ExitCode::from(78)
}
