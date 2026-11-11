use clap::Parser;
use std::{fs, path::PathBuf, process::ExitCode};

use sigrund_core::protocol::{RemoteAuditBatchRequest, parse_strict};

#[derive(Parser)]
#[command(
    name = "sigrund-collector",
    version,
    about = "Validate audit batches diagnostically",
    after_help = "The network collector service is not enabled in this build."
)]
struct Cli {
    /// Validate a remote audit batch JSON file
    #[arg(long, value_name = "PATH")]
    validate_batch: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return sigrund::cli::parse_exit(error),
    };
    if let Some(path) = cli.validate_batch {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("sigrund-collector: {error}");
                return ExitCode::from(66);
            }
        };
        return match parse_strict::<RemoteAuditBatchRequest>(&bytes)
            .and_then(|batch| batch.validate())
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("sigrund-collector: invalid batch: {error}");
                ExitCode::from(65)
            }
        };
    }
    eprintln!("sigrund-collector: network service is not enabled in this build");
    ExitCode::from(78)
}
