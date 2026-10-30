use sigrund::cli::{CLIENT_HELP, ClientArgs};
use std::{env, fs, process::ExitCode};

use sigrund_core::{
    framing::{FrameType, encode_frame},
    protocol::ClientHello,
};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = match ClientArgs::parse(&args) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("sigrun: {error}\n{CLIENT_HELP}");
            return ExitCode::from(64);
        }
    };
    if command == ClientArgs::Help {
        println!("{CLIENT_HELP}");
        return ExitCode::SUCCESS;
    }
    if let ClientArgs::ValidateHello(path) = &command {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("sigrun: {error}");
                return ExitCode::from(66);
            }
        };
        return match ClientHello::parse_request(&bytes) {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("sigrun: invalid CLIENT_HELLO: {error}");
                ExitCode::from(65)
            }
        };
    }
    if let ClientArgs::EncodeSignal(signal) = command {
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
