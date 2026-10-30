//! Frozen command forms for the thin MVP. Parsing has no privileged effects.
use sigrund_core::{CoreError, Result};
use std::{collections::BTreeSet, path::PathBuf};

pub const CLIENT_SOCKET: &str = "/run/sigrund.sock";
pub const APPROVAL_SOCKET: &str = "/run/sigrund-approve.sock";
pub const DAEMON_HELP: &str = "Usage: sigrund --foreground [--socket PATH] [--approval-socket PATH] [--config PATH] [--signers PATH]\n       sigrund --check-config [--config PATH] [--signers PATH]\n       sigrund --check-cgroup PATH [--config PATH] [--signers PATH]\nThe foreground runtime is scheduled for roadmap Phases 1–5.";
pub const CLIENT_HELP: &str = "Usage: sigrun [--socket PATH] -- /ABSOLUTE/COMMAND ARG...\n       sigrun --validate-hello PATH\n       sigrun --encode-signal NUMBER\nCommand execution is scheduled for roadmap Phases 2–5.";
pub const APPROVAL_HELP: &str = "Usage: sigrund-approve [--socket PATH] [--tty PATH]\nDefaults: /run/sigrund-approve.sock and /dev/tty.\nTTY approval and SSH signing are scheduled for roadmap Phase 3.";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonMode {
    Foreground,
    CheckConfig,
    CheckCgroup(PathBuf),
    Help,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonArgs {
    pub mode: DaemonMode,
    pub socket: PathBuf,
    pub approval_socket: PathBuf,
    pub config: Option<PathBuf>,
    pub signers: Option<PathBuf>,
}

impl DaemonArgs {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut result = Self {
            mode: DaemonMode::Foreground,
            socket: CLIENT_SOCKET.into(),
            approval_socket: APPROVAL_SOCKET.into(),
            config: None,
            signers: None,
        };
        let mut mode_set = false;
        let mut seen = BTreeSet::new();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            if !seen.insert(arg) {
                return Err(invalid("duplicate option"));
            }
            match arg.as_str() {
                "--socket" => result.socket = path_value(&mut args)?,
                "--approval-socket" => result.approval_socket = path_value(&mut args)?,
                "--config" => result.config = Some(path_value(&mut args)?),
                "--signers" => result.signers = Some(path_value(&mut args)?),
                "--foreground" | "--check-config" | "--check-cgroup" | "--help" => {
                    if mode_set {
                        return Err(invalid("conflicting daemon modes"));
                    }
                    mode_set = true;
                    result.mode = match arg.as_str() {
                        "--foreground" => DaemonMode::Foreground,
                        "--check-config" => DaemonMode::CheckConfig,
                        "--check-cgroup" => DaemonMode::CheckCgroup(path_value(&mut args)?),
                        _ => DaemonMode::Help,
                    };
                }
                _ => return Err(invalid("unknown daemon option")),
            }
        }
        if result.socket == result.approval_socket {
            return Err(invalid("client and approval sockets must differ"));
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientArgs {
    Help,
    ValidateHello(PathBuf),
    EncodeSignal(u8),
    Run {
        socket: PathBuf,
        command: Vec<String>,
    },
}

impl ClientArgs {
    pub fn parse(args: &[String]) -> Result<Self> {
        match args {
            [flag] if flag == "--help" => return Ok(Self::Help),
            [flag, path] if flag == "--validate-hello" && !path.is_empty() => {
                return Ok(Self::ValidateHello(path.into()));
            }
            [flag, signal] if flag == "--encode-signal" => {
                let signal: u8 = signal
                    .parse()
                    .map_err(|_| invalid("signal must be an integer"))?;
                if ![1, 2, 10, 12, 15].contains(&signal) {
                    return Err(invalid("signal is outside the protocol allowlist"));
                }
                return Ok(Self::EncodeSignal(signal));
            }
            _ => (),
        }
        let (socket, command) = match args {
            [separator, command @ ..] if separator == "--" => (CLIENT_SOCKET.into(), command),
            [flag, socket, separator, command @ ..] if flag == "--socket" && separator == "--" => {
                (absolute_path(socket)?, command)
            }
            _ => return Err(invalid("expected [--socket PATH] -- COMMAND ARG...")),
        };
        let Some(executable) = command.first() else {
            return Err(invalid("missing command"));
        };
        absolute_path(executable)?;
        if command.len() > 256 {
            return Err(invalid("too many command arguments"));
        }
        Ok(Self::Run {
            socket,
            command: command.to_vec(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalArgs {
    pub socket: PathBuf,
    pub tty: PathBuf,
}

impl ApprovalArgs {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut result = Self {
            socket: APPROVAL_SOCKET.into(),
            tty: "/dev/tty".into(),
        };
        let mut seen = BTreeSet::new();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            if !seen.insert(arg) {
                return Err(invalid("duplicate option"));
            }
            match arg.as_str() {
                "--socket" => result.socket = path_value(&mut args)?,
                "--tty" => result.tty = path_value(&mut args)?,
                _ => return Err(invalid("unknown approval option")),
            }
        }
        Ok(result)
    }
}

fn path_value<'a>(args: &mut impl Iterator<Item = &'a String>) -> Result<PathBuf> {
    absolute_path(
        args.next()
            .ok_or_else(|| invalid("missing path after option"))?,
    )
}
fn absolute_path(value: &str) -> Result<PathBuf> {
    if !value.starts_with('/') || value.contains('\0') {
        return Err(invalid("path must be absolute and NUL-free"));
    }
    Ok(value.into())
}
fn invalid(message: &str) -> CoreError {
    CoreError::Value(message.into())
}
