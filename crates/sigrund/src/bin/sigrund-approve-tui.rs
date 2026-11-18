use clap::{CommandFactory, FromArgMatches};
use sigrund::cli::{ApprovalArgs, parse_exit};
use std::{io, process::ExitCode};

fn main() -> ExitCode {
    let parsed = ApprovalArgs::command()
        .name("sigrund-approve-tui")
        .about("Inspect and decide approval requests in a terminal interface")
        .try_get_matches()
        .and_then(|matches| ApprovalArgs::from_arg_matches(&matches));
    let args = match parsed {
        Ok(args) => args,
        Err(error) => return parse_exit(error),
    };
    match sigrund::approver::run_tui(&args) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("sigrund-approve-tui: {error}");
            ExitCode::from(if error.kind() == io::ErrorKind::InvalidInput {
                64
            } else {
                78
            })
        }
    }
}
