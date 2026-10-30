//! Frozen command forms for the thin MVP. Parsing has no privileged effects.
use sigrund_core::protocol::{
    ClientHello, RequestedCommand, RequestedExecutionContext, RequestedPolicy,
};
use sigrund_core::{CoreError, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

pub const CLIENT_SOCKET: &str = "/run/sigrund.sock";
pub const APPROVAL_SOCKET: &str = "/run/sigrund-approve.sock";
pub const DAEMON_HELP: &str = "Usage: sigrund --foreground [--socket PATH] [--approval-socket PATH] [--config PATH] [--signers PATH] [--state-dir PATH] [--log-path PATH]\n       sigrund --check-config [--config PATH] [--signers PATH]\n       sigrund --check-cgroup PATH [--config PATH] [--signers PATH]\nPhase 3 verifies snapshots and root approval; execution requires roadmap Phases 4–5.";
pub const CLIENT_HELP: &str = "Usage: sigrun [OPTIONS] -- /ABSOLUTE/COMMAND ARG...\nOptions: --socket PATH --target-uid UID --target-gid GID --supplementary-gid GID\n         --capability CAP --cwd PATH --env NAME=VALUE --umask OCTAL\n         --stdin null|sha256 --ttl-secs SECONDS --status-fd N --auth-fail-exit-code CODE\nDefaults: target 0:0, cwd=current, LANG=C.UTF-8, PATH=/usr/sbin:/usr/bin,\n          umask=077, stdin=null, ttl=900, denial exit=255.\n       sigrun --validate-hello PATH\n       sigrun --encode-signal NUMBER\nPhase 3 supports root approval; execution requires Phases 4–5.";
pub const APPROVAL_HELP: &str = "Usage: sigrund-approve [--socket PATH] [--tty PATH] [--signers PATH] --identity PATH\nDefaults: /run/sigrund-approve.sock, /dev/tty and /etc/sigrund/signers.toml.\nOnly UID 0 with a controlling TTY may approve and sign.";

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
    pub state_dir: PathBuf,
    pub log_path: PathBuf,
}

impl DaemonArgs {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut result = Self {
            mode: DaemonMode::Foreground,
            socket: CLIENT_SOCKET.into(),
            approval_socket: APPROVAL_SOCKET.into(),
            config: None,
            signers: None,
            state_dir: "/var/lib/sigrund".into(),
            log_path: "/var/log/sigrund/audit.jsonl".into(),
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
                "--state-dir" => result.state_dir = path_value(&mut args)?,
                "--log-path" => result.log_path = path_value(&mut args)?,
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
        options: RequestOptions,
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
        let mut socket = PathBuf::from(CLIENT_SOCKET);
        let mut options = RequestOptions::default();
        let mut seen = BTreeSet::new();
        let mut env_seen = BTreeSet::new();
        let mut arguments = args.iter();
        let mut command = Vec::new();
        while let Some(flag) = arguments.next() {
            if flag == "--" {
                command = arguments.cloned().collect();
                break;
            }
            if !matches!(
                flag.as_str(),
                "--env" | "--supplementary-gid" | "--capability"
            ) && !seen.insert(flag)
            {
                return Err(invalid("duplicate client option"));
            }
            let value = arguments
                .next()
                .ok_or_else(|| invalid("missing option value"))?;
            match flag.as_str() {
                "--socket" => socket = absolute_path(value)?,
                "--target-uid" => options.target_uid = identity(value)?,
                "--target-gid" => options.target_gid = identity(value)?,
                "--supplementary-gid" => options.supplementary_gids.push(identity(value)?),
                "--capability" => options.capabilities.push(value.clone()),
                "--cwd" => options.cwd = Some(absolute_path(value)?),
                "--env" => {
                    let (name, value) = value
                        .split_once('=')
                        .ok_or_else(|| invalid("environment entry must be NAME=VALUE"))?;
                    if !env_seen.insert(name.to_owned()) {
                        return Err(invalid("duplicate explicit environment name"));
                    }
                    options.env_exact.insert(name.to_owned(), value.to_owned());
                }
                "--umask" => {
                    if value.is_empty() || !value.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                        return Err(invalid("umask must be octal"));
                    }
                    options.umask =
                        u32::from_str_radix(value, 8).map_err(|_| invalid("invalid umask"))?;
                }
                "--stdin" if matches!(value.as_str(), "null" | "sha256") => {
                    options.stdin_policy = value.clone()
                }
                "--ttl-secs" => {
                    options.ttl_secs = decimal(value)?;
                    if options.ttl_secs == 0 {
                        return Err(invalid("TTL must be positive"));
                    }
                }
                "--status-fd" => {
                    let fd = i32::try_from(decimal(value)?)
                        .map_err(|_| invalid("status FD outside bounds"))?;
                    if matches!(fd, 1 | 2) {
                        return Err(invalid("status FD must be separate from stdout/stderr"));
                    }
                    options.status_fd = Some(fd);
                }
                "--auth-fail-exit-code" => {
                    options.auth_fail_exit_code = u8::try_from(decimal(value)?)
                        .map_err(|_| invalid("exit code outside 0..255"))?
                }
                _ => return Err(invalid("unknown or unsupported client option")),
            }
        }
        if command.is_empty() {
            return Err(invalid("missing -- and absolute command"));
        }
        absolute_path(&command[0])?;
        options.capabilities.sort();
        if options.capabilities.windows(2).any(|p| p[0] == p[1]) {
            return Err(invalid("duplicate capability"));
        }
        options.supplementary_gids.sort_unstable();
        if options.supplementary_gids.windows(2).any(|p| p[0] == p[1]) {
            return Err(invalid("duplicate supplementary GID"));
        }
        // Validate all schema bounds before connecting, without depending on
        // cwd capture (which belongs to request construction).
        options.hello(&command, std::path::Path::new("/"))?;
        Ok(Self::Run {
            socket,
            command,
            options,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestOptions {
    pub target_uid: u32,
    pub target_gid: u32,
    pub supplementary_gids: Vec<u32>,
    pub capabilities: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env_exact: BTreeMap<String, String>,
    pub umask: u32,
    pub stdin_policy: String,
    pub ttl_secs: u64,
    pub status_fd: Option<i32>,
    pub auth_fail_exit_code: u8,
}
impl Default for RequestOptions {
    fn default() -> Self {
        Self {
            target_uid: 0,
            target_gid: 0,
            supplementary_gids: vec![],
            capabilities: vec![],
            cwd: None,
            env_exact: BTreeMap::from([
                ("LANG".into(), "C.UTF-8".into()),
                ("PATH".into(), "/usr/sbin:/usr/bin".into()),
            ]),
            umask: 0o77,
            stdin_policy: "null".into(),
            ttl_secs: 900,
            status_fd: None,
            auth_fail_exit_code: 255,
        }
    }
}
impl RequestOptions {
    pub fn hello(&self, command: &[String], current: &std::path::Path) -> Result<ClientHello> {
        let cwd = self
            .cwd
            .as_deref()
            .unwrap_or(current)
            .to_str()
            .ok_or_else(|| invalid("cwd is not UTF-8"))?;
        let hello = ClientHello {
            caller_env: BTreeMap::new(),
            mode: "unsigned_csr_request".into(),
            tty_mode: "stdio".into(),
            dsse_envelope: None,
            requested_command: Some(RequestedCommand {
                allow_interpreted_script: false,
                argv: command.to_vec(),
                cwd: cwd.into(),
                executable_path: command
                    .first()
                    .ok_or_else(|| invalid("missing command"))?
                    .clone(),
                stdin_policy: self.stdin_policy.clone(),
                tty_mode: "stdio".into(),
            }),
            requested_execution_context: Some(RequestedExecutionContext {
                capabilities: self.capabilities.clone(),
                env_exact: self.env_exact.clone(),
                caller_env_allowlist: vec![],
                supplementary_gids: self.supplementary_gids.clone(),
                target_gid: self.target_gid,
                target_uid: self.target_uid,
                umask: self.umask,
            }),
            requested_policy: Some(RequestedPolicy {
                mode: "one_time".into(),
                ttl_secs: self.ttl_secs,
            }),
        };
        hello.validate_request()?;
        Ok(hello)
    }
}
fn decimal(value: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("expected unsigned decimal integer"));
    }
    value.parse().map_err(|_| invalid("integer overflow"))
}
fn identity(value: &str) -> Result<u32> {
    u32::try_from(decimal(value)?)
        .ok()
        .filter(|v| *v != u32::MAX)
        .ok_or_else(|| invalid("UID/GID outside bounds"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalArgs {
    pub socket: PathBuf,
    pub tty: PathBuf,
    pub signers: PathBuf,
    pub identity: Option<PathBuf>,
}

impl ApprovalArgs {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut result = Self {
            socket: APPROVAL_SOCKET.into(),
            tty: "/dev/tty".into(),
            signers: "/etc/sigrund/signers.toml".into(),
            identity: None,
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
                "--signers" => result.signers = path_value(&mut args)?,
                "--identity" => result.identity = Some(path_value(&mut args)?),
                _ => return Err(invalid("unknown approval option")),
            }
        }
        if result.identity.is_none() {
            return Err(invalid("--identity is required"));
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
    crate::linux::validate_absolute_path(std::path::Path::new(value))
        .map_err(|_| invalid("path must be canonical absolute text and NUL-free"))?;
    Ok(value.into())
}
fn invalid(message: &str) -> CoreError {
    CoreError::Value(message.into())
}
