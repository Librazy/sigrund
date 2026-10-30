use std::{env, fs, process::ExitCode};

use sigrund::cli::{DAEMON_HELP, DaemonArgs, DaemonMode};
use sigrund::startup::CgroupLayout;
use sigrund::{daemon::ForegroundDaemon, startup::read_root_file};
use sigrund_core::config::{DaemonConfig, SignerPolicyFile};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let args = match DaemonArgs::parse(&args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("sigrund: {error}\n{DAEMON_HELP}");
            return ExitCode::from(64);
        }
    };
    if args.mode == DaemonMode::Help {
        println!("{DAEMON_HELP}");
        return ExitCode::SUCCESS;
    }
    let config_path = args
        .config
        .or_else(|| env::var_os("SIGRUND_CONFIG").map(Into::into))
        .unwrap_or_else(|| "/etc/sigrund/config.toml".into());
    let read_config = |path: &std::path::Path| {
        if args.mode == DaemonMode::Foreground {
            read_root_file(path, None, 1_048_576)
        } else {
            fs::read(path)
        }
    };
    let bytes = match read_config(&config_path) {
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
    let signer_path = args
        .signers
        .or_else(|| env::var_os("SIGRUND_SIGNERS").map(Into::into))
        .unwrap_or_else(|| "/etc/sigrund/signers.toml".into());
    let signer_bytes = match read_config(&signer_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("sigrund: cannot read {}: {error}", signer_path.display());
            return ExitCode::from(78);
        }
    };
    let signers = match SignerPolicyFile::from_toml(&signer_bytes) {
        Ok(signers) => signers,
        Err(error) => {
            eprintln!("sigrund: refusing invalid configuration: {error}");
            return ExitCode::from(78);
        }
    };
    if let Err(error) = signers.validate_against(&config) {
        eprintln!("sigrund: refusing invalid configuration: {error}");
        return ExitCode::from(78);
    }
    if let DaemonMode::CheckCgroup(root) = args.mode {
        return match CgroupLayout::from_root(root).initialize() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("sigrund: cgroup startup gate failed: {error}");
                ExitCode::from(78)
            }
        };
    }
    if args.mode == DaemonMode::CheckConfig {
        return ExitCode::SUCCESS;
    }
    match ForegroundDaemon::prepare(
        config,
        signers,
        &args.state_dir,
        &args.log_path,
        &args.socket,
        &args.approval_socket,
    )
    .and_then(ForegroundDaemon::run)
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sigrund: foreground runtime failed closed: {error}");
            ExitCode::from(78)
        }
    }
}
