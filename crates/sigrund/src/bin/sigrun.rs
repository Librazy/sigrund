use sigrund::cli::{ClientArgs, parse_exit};
use std::{fs, process::ExitCode};

use sigrund_core::{
    framing::{FrameType, encode_frame},
    protocol::ClientHello,
};

fn main() -> ExitCode {
    let command = match ClientArgs::parse_env() {
        Ok(command) => command,
        Err(error) => return parse_exit(error),
    };
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
    let ClientArgs::Run {
        socket,
        command,
        options,
    } = command
    else {
        unreachable!()
    };
    match sigrund::client::run(&socket, &command, &options) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("sigrun: {error}");
            ExitCode::from(if error.kind() == std::io::ErrorKind::InvalidInput {
                64
            } else {
                254
            })
        }
    }
}
