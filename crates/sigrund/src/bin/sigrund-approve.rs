use sigrund::cli::{APPROVAL_HELP, ApprovalArgs};
use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args == ["--help"] {
        println!("{APPROVAL_HELP}");
        return ExitCode::SUCCESS;
    }
    let parsed = match ApprovalArgs::parse(&args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("sigrund-approve: {error}\n{APPROVAL_HELP}");
            return ExitCode::from(64);
        }
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
