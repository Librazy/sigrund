use sigrund::cli::{APPROVAL_HELP, ApprovalArgs};
use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args == ["--help"] {
        println!("{APPROVAL_HELP}");
        return ExitCode::SUCCESS;
    }
    if let Err(error) = ApprovalArgs::parse(&args) {
        eprintln!("sigrund-approve: {error}\n{APPROVAL_HELP}");
        return ExitCode::from(64);
    }
    eprintln!(
        "sigrund-approve: TTY approval and SSH signing are not enabled; see MVP_ROADMAP.md Phase 3"
    );
    ExitCode::from(78)
}
