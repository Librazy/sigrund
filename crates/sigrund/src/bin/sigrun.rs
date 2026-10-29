use std::{env, fs, process::ExitCode};

use sigrund_core::{
    framing::{FrameType, encode_frame},
    protocol::{ClientHello, parse_strict},
};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if let Some(index) = args.iter().position(|arg| arg == "--validate-hello") {
        let Some(path) = args.get(index + 1) else {
            eprintln!("sigrun: --validate-hello requires a JSON path");
            return ExitCode::from(64);
        };
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("sigrun: {error}");
                return ExitCode::from(66);
            }
        };
        return match parse_strict::<ClientHello>(&bytes).and_then(|hello| hello.validate_shape()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("sigrun: invalid CLIENT_HELLO: {error}");
                ExitCode::from(65)
            }
        };
    }
    if let Some(index) = args.iter().position(|arg| arg == "--encode-signal") {
        let Some(signal) = args
            .get(index + 1)
            .and_then(|value| value.parse::<u8>().ok())
        else {
            eprintln!("sigrun: --encode-signal requires an integer");
            return ExitCode::from(64);
        };
        let payload = format!(r#"{{"signal":{signal}}}"#);
        match encode_frame(FrameType::ClientSignal, payload.as_bytes()) {
            Ok(frame) => println!(
                "{}",
                frame
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
            Err(error) => {
                eprintln!("sigrun: {error}");
                return ExitCode::from(65);
            }
        }
        return ExitCode::SUCCESS;
    }
    eprintln!("sigrun: client transport is not enabled in this build");
    ExitCode::from(78)
}
