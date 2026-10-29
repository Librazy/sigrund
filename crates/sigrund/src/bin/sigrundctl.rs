use std::{env, process::ExitCode};

use sigrund_core::crypto::{new_uuidv7, validate_uuidv7};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.get(1).is_some_and(|arg| arg == "uuidv7") {
        println!("{}", new_uuidv7());
        return ExitCode::SUCCESS;
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
