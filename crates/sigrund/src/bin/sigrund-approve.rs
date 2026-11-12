use clap::Parser;
use sigrund::cli::{ApprovalArgs, parse_exit};
use std::process::ExitCode;

fn main() -> ExitCode {
    let parsed = match ApprovalArgs::try_parse() {
        Ok(parsed) => parsed,
        Err(error) => return parse_exit(error),
    };
    match sigrund::approver::run(&parsed) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("sigrund-approve: {error}");
            ExitCode::from(if error.kind() == std::io::ErrorKind::InvalidInput {
                64
            } else {
                78
            })
        }
    }
}
