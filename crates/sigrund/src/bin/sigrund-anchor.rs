//! Disposable, single-threaded anchor for an already running environment.
use clap::Parser;
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "sigrund-anchor",
    version,
    about = "Supply a disposable capture anchor inside an existing environment",
    after_help = "Run inside the existing destination, then register its host-visible PID.\nThis disposable process is held until revocation or daemon shutdown.\nThe anchor requires an unfiltered, single-threaded supported environment."
)]
struct Cli {
    /// Absolute rendezvous socket path
    #[arg(long, value_name = "PATH", value_parser = sigrund::cli::absolute_path)]
    socket: PathBuf,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return sigrund::cli::parse_exit(error),
    };
    match sigrund::client::run_dedicated_anchor(&cli.socket) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sigrund-anchor: {error}");
            ExitCode::from(1)
        }
    }
}
