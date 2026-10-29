use std::{env, fs, process::ExitCode};

use sigrund_core::protocol::{RemoteAuditBatchRequest, parse_strict};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if let Some(index) = args.iter().position(|arg| arg == "--validate-batch") {
        let Some(path) = args.get(index + 1) else {
            eprintln!("sigrund-collector: --validate-batch requires a JSON path");
            return ExitCode::from(64);
        };
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
