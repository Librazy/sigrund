//! Command-line definitions and effect-free request validation.
use clap::{Args, CommandFactory, Parser, error::ErrorKind};
use sigrund_core::protocol::{
    ClientHello, RequestedCommand, RequestedExecutionContext, RequestedPolicy,
};
use sigrund_core::{CoreError, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    process::ExitCode,
};

pub const CLIENT_SOCKET: &str = "/run/sigrund/client.sock";
pub const APPROVAL_SOCKET: &str = "/run/sigrund/approve.sock";

/// Print generated help/version to stdout, or a usage error to stderr.
/// Preserve EX_USAGE (64) for invalid command lines.
pub fn parse_exit(error: clap::Error) -> ExitCode {
    let code = if error.use_stderr() { 64 } else { 0 };
    let _ = error.print();
    ExitCode::from(code)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonMode {
    Foreground,
    CheckConfig,
    CheckCgroup(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonArgs {
    pub mode: DaemonMode,
    pub authorization_only: bool,
    pub socket: PathBuf,
    pub approval_socket: PathBuf,
    pub config: Option<PathBuf>,
    pub signers: Option<PathBuf>,
    pub state_dir: PathBuf,
    pub log_path: PathBuf,
}

#[derive(Parser)]
#[command(
    name = "sigrund",
    version,
    about = "Authorize and supervise signed commands",
    after_help = "Execution startup requires a dedicated delegated cgroup service."
)]
#[command(group(clap::ArgGroup::new("mode").args(["foreground", "check_config", "check_cgroup"])))]
struct DaemonCli {
    /// Run the daemon in the foreground (default)
    #[arg(long)]
    foreground: bool,
    /// Validate configuration without starting the daemon
    #[arg(long)]
    check_config: bool,
    /// Check the delegated cgroup at PATH
    #[arg(long, value_name = "PATH", value_parser = absolute_path)]
    check_cgroup: Option<PathBuf>,
    /// Use the non-executing authorization diagnostic profile
    #[arg(long, conflicts_with_all = ["check_config", "check_cgroup"])]
    authorization_only: bool,
    /// Client Unix socket
    #[arg(long, default_value = CLIENT_SOCKET, value_name = "PATH", value_parser = absolute_path)]
    socket: PathBuf,
    /// Approval Unix socket
    #[arg(long, default_value = APPROVAL_SOCKET, value_name = "PATH", value_parser = absolute_path)]
    approval_socket: PathBuf,
    /// Configuration file (otherwise SIGRUND_CONFIG or /etc/sigrund/config.toml)
    #[arg(long, value_name = "PATH", value_parser = absolute_path)]
    config: Option<PathBuf>,
    /// Signer policy (otherwise SIGRUND_SIGNERS or /etc/sigrund/signers.toml)
    #[arg(long, value_name = "PATH", value_parser = absolute_path)]
    signers: Option<PathBuf>,
    /// Persistent daemon state directory
    #[arg(long, default_value = "/var/lib/sigrund", value_name = "PATH", value_parser = absolute_path)]
    state_dir: PathBuf,
    /// Local audit log
    #[arg(long, default_value = "/var/log/sigrund/audit.jsonl", value_name = "PATH", value_parser = absolute_path)]
    log_path: PathBuf,
}

impl DaemonArgs {
    pub fn parse(args: &[String]) -> clap::error::Result<Self> {
        let cli = DaemonCli::try_parse_from(
            std::iter::once("sigrund").chain(args.iter().map(String::as_str)),
        )?;
        Self::from_cli(cli)
    }

    pub fn parse_env() -> clap::error::Result<Self> {
        Self::from_cli(DaemonCli::try_parse()?)
    }

    fn from_cli(cli: DaemonCli) -> clap::error::Result<Self> {
        if cli.socket == cli.approval_socket {
            return Err(DaemonCli::command().error(
                ErrorKind::ValueValidation,
                "client and approval sockets must differ",
            ));
        }
        Ok(Self {
            mode: if cli.check_config {
                DaemonMode::CheckConfig
            } else if let Some(path) = cli.check_cgroup {
                DaemonMode::CheckCgroup(path)
            } else {
                DaemonMode::Foreground
            },
            authorization_only: cli.authorization_only,
            socket: cli.socket,
            approval_socket: cli.approval_socket,
            config: cli.config,
            signers: cli.signers,
            state_dir: cli.state_dir,
            log_path: cli.log_path,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientArgs {
    ValidateHello(PathBuf),
    EncodeSignal(u8),
    Run {
        socket: PathBuf,
        command: Vec<String>,
        options: Box<RequestOptions>,
    },
}

#[derive(Parser)]
#[command(
    name = "sigrun",
    version,
    about = "Request a signed command with explicit credentials and security policy",
    after_help = "Arguments after -- are passed exactly, without shell evaluation or PATH lookup.\nAPPROVED confirms durable authorization; readiness and execution results follow separately."
)]
struct ClientCli {
    /// Validate a CLIENT_HELLO JSON file without connecting
    #[arg(long, value_name = "PATH", exclusive = true)]
    validate_hello: Option<PathBuf>,
    /// Encode an allowed protocol signal (1, 2, 10, 12, 15)
    #[arg(long, value_name = "NUMBER", value_parser = signal, exclusive = true)]
    encode_signal: Option<u8>,
    /// Submit an existing signed envelope without command construction
    #[arg(long, value_name = "PATH", value_parser = absolute_path, conflicts_with = "request")]
    warrant: Option<PathBuf>,
    /// Client Unix socket
    #[arg(long, default_value = CLIENT_SOCKET, value_name = "PATH", value_parser = absolute_path)]
    socket: PathBuf,
    /// Write machine-readable status to this FD (separate from stdout/stderr)
    #[arg(long, value_name = "N", value_parser = status_fd)]
    status_fd: Option<i32>,
    /// Exit code for authorization denial
    #[arg(long, default_value = "255", value_name = "CODE", value_parser = exit_code)]
    auth_fail_exit_code: u8,
    #[command(flatten)]
    request: RequestCli,
}

#[derive(Args)]
#[group(id = "request", multiple = true)]
struct RequestCli {
    /// Execution target: host, self, registered:ID or process:DAEMON_PID
    #[arg(long, value_name = "SELECTOR", value_parser = target, required_unless_present_any = ["warrant", "validate_hello", "encode_signal"])]
    target: Option<String>,
    /// Configured security profile
    #[arg(long, value_name = "ID", required_unless_present_any = ["warrant", "validate_hello", "encode_signal"])]
    security_profile: Option<String>,
    /// Destination account name, as an alternative to numeric UID/GID
    #[arg(long, value_name = "NAME", conflicts_with_all = ["target_uid", "target_gid", "supplementary_gid"], required_unless_present_any = ["target_uid", "warrant", "validate_hello", "encode_signal"])]
    account: Option<String>,
    /// Destination user ID
    #[arg(long, value_name = "UID", value_parser = identity, requires = "target_gid")]
    target_uid: Option<u32>,
    /// Destination primary group ID
    #[arg(long, value_name = "GID", value_parser = identity, requires = "target_uid")]
    target_gid: Option<u32>,
    /// Destination supplementary group ID (repeatable)
    #[arg(long, value_name = "GID", value_parser = identity)]
    supplementary_gid: Vec<u32>,
    /// Requested capability (repeatable)
    #[arg(long, value_name = "CAP")]
    capability: Vec<String>,
    /// Host binding bundle for full preparation
    #[arg(long, value_name = "PATH", value_parser = absolute_path)]
    binding_bundle: Option<PathBuf>,
    /// Require host full preparation
    #[arg(long)]
    full_only: bool,
    /// Export a host CSR; implies --full-only
    #[arg(long, value_name = "PATH", value_parser = absolute_path)]
    export_csr: Option<PathBuf>,
    /// Destination working directory (default: current directory)
    #[arg(long, value_name = "PATH", value_parser = absolute_path)]
    cwd: Option<PathBuf>,
    /// Exact environment entry (repeatable; defaults: LANG=C.UTF-8, PATH=/usr/sbin:/usr/bin)
    #[arg(long = "env", value_name = "NAME=VALUE", value_parser = environment)]
    env: Vec<(String, String)>,
    /// Destination file creation mask in octal
    #[arg(long, default_value = "077", value_name = "OCTAL", value_parser = umask)]
    umask: u32,
    /// Null input or digest-bound finite input
    #[arg(long, default_value = "null", value_parser = ["null", "sha256"])]
    stdin: String,
    /// Requested authorization lifetime in seconds
    #[arg(long, default_value = "900", value_name = "SECONDS", value_parser = ttl)]
    ttl_secs: u64,
    /// Absolute executable path followed by its arguments
    #[arg(last = true, num_args = 1.., value_name = "COMMAND", required_unless_present_any = ["warrant", "validate_hello", "encode_signal"])]
    command: Vec<String>,
}

impl ClientArgs {
    pub fn parse(args: &[String]) -> clap::error::Result<Self> {
        let cli = ClientCli::try_parse_from(
            std::iter::once("sigrun").chain(args.iter().map(String::as_str)),
        )?;
        Self::from_cli(cli)
            .map_err(|error| ClientCli::command().error(ErrorKind::ValueValidation, error))
    }

    pub fn parse_env() -> clap::error::Result<Self> {
        Self::from_cli(ClientCli::try_parse()?)
            .map_err(|error| ClientCli::command().error(ErrorKind::ValueValidation, error))
    }

    fn from_cli(cli: ClientCli) -> Result<Self> {
        if let Some(path) = cli.validate_hello {
            return Ok(Self::ValidateHello(path));
        }
        if let Some(signal) = cli.encode_signal {
            return Ok(Self::EncodeSignal(signal));
        }
        let request = cli.request;
        let mut options = RequestOptions {
            target: request.target,
            security_profile: request.security_profile,
            account: request.account,
            binding_bundle: request.binding_bundle,
            warrant: cli.warrant,
            full_only: request.full_only || request.export_csr.is_some(),
            export_csr: request.export_csr,
            target_uid: request.target_uid.unwrap_or(0),
            target_gid: request.target_gid.unwrap_or(0),
            supplementary_gids: request.supplementary_gid,
            capabilities: request.capability,
            cwd: request.cwd,
            umask: request.umask,
            stdin_policy: request.stdin,
            ttl_secs: request.ttl_secs,
            status_fd: cli.status_fd,
            auth_fail_exit_code: cli.auth_fail_exit_code,
            ..RequestOptions::default()
        };
        let mut env_seen = BTreeSet::new();
        for (name, value) in request.env {
            if !env_seen.insert(name.clone()) {
                return Err(invalid("duplicate explicit environment name"));
            }
            options.env_exact.insert(name, value);
        }
        if options.warrant.is_some() {
            return Ok(Self::Run {
                socket: cli.socket,
                command: request.command,
                options: Box::new(options),
            });
        }
        let selected_target = parse_target(options.target.as_deref().unwrap())?;
        if !matches!(selected_target, sigrund_core::host::Selector::Host {})
            && (options.full_only || options.binding_bundle.is_some())
        {
            return Err(invalid(
                "cross-domain full preparation, binding bundles and CSR export are unavailable",
            ));
        }
        absolute_path(&request.command[0])?;
        options.capabilities.sort();
        if options.capabilities.windows(2).any(|p| p[0] == p[1]) {
            return Err(invalid("duplicate capability"));
        }
        options.supplementary_gids.sort_unstable();
        if options.supplementary_gids.windows(2).any(|p| p[0] == p[1]) {
            return Err(invalid("duplicate supplementary GID"));
        }
        // Validate schema bounds before connecting; cwd capture belongs to request construction.
        options.hello(&request.command, std::path::Path::new("/"))?;
        Ok(Self::Run {
            socket: cli.socket,
            command: request.command,
            options: Box::new(options),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestOptions {
    pub target: Option<String>,
    pub security_profile: Option<String>,
    pub account: Option<String>,
    pub binding_bundle: Option<PathBuf>,
    pub warrant: Option<PathBuf>,
    pub full_only: bool,
    pub export_csr: Option<PathBuf>,
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
            target: None,
            security_profile: None,
            account: None,
            binding_bundle: None,
            warrant: None,
            full_only: false,
            export_csr: None,
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
        if self.warrant.is_some() {
            return Err(invalid(
                "signed requests cannot construct an unsigned command",
            ));
        }
        let cwd = self
            .cwd
            .as_deref()
            .unwrap_or(current)
            .to_str()
            .ok_or_else(|| invalid("cwd is not UTF-8"))?;
        let mut hello = ClientHello {
            original_intent: None,
            csr_payload: None,
            caller_env: BTreeMap::new(),
            mode: "thin_csr".into(),
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
        let requested = hello.requested_execution_context.as_ref().unwrap();
        hello.original_intent = Some(sigrund_core::v3::Intent {
            target: parse_target(
                self.target
                    .as_deref()
                    .ok_or_else(|| invalid("explicit target required"))?,
            )?,
            account: match &self.account {
                Some(name) => sigrund_core::host::Account::Name { name: name.clone() },
                None => sigrund_core::host::Account::Numeric {
                    uid: self.target_uid,
                    gid: self.target_gid,
                    supplementary_gids: self.supplementary_gids.clone(),
                },
            },
            security_profile: self
                .security_profile
                .clone()
                .ok_or_else(|| invalid("explicit security profile required"))?,
            command: hello.requested_command.clone().unwrap(),
            execution_context: sigrund_core::v3::IntentContext {
                capabilities: requested.capabilities.clone(),
                env_exact: requested.env_exact.clone(),
                caller_env_allowlist: requested.caller_env_allowlist.clone(),
                umask: requested.umask,
            },
            policy: hello.requested_policy.clone().unwrap(),
            caller_env: hello.caller_env.clone(),
        });
        hello.validate_request()?;
        Ok(hello)
    }
}
fn parse_target(value: &str) -> Result<sigrund_core::host::Selector> {
    use sigrund_core::host::Selector;
    let target = if value == "host" {
        Selector::Host {}
    } else if value == "self" {
        Selector::Self_ {}
    } else if let Some(id) = value.strip_prefix("registered:") {
        Selector::Registered { id: id.into() }
    } else if let Some(pid) = value.strip_prefix("process:") {
        Selector::Process {
            pid: u32::try_from(decimal(pid)?).map_err(|_| invalid("invalid daemon-scope PID"))?,
            pid_scope: "daemon".into(),
        }
    } else {
        return Err(invalid("unsupported target selector"));
    };
    target.validate_selection()?;
    Ok(target)
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

#[derive(Clone, Debug, Eq, PartialEq, Parser)]
#[command(
    name = "sigrund-approve",
    version,
    about = "Review and sign requests on root's controlling terminal",
    after_help = "Only UID 0 with a controlling TTY may approve and sign. Private evidence must match the live daemon epoch and exact CSR."
)]
pub struct ApprovalArgs {
    /// Approval Unix socket
    #[arg(long, default_value = APPROVAL_SOCKET, value_name = "PATH", value_parser = absolute_path)]
    pub socket: PathBuf,
    /// Operator's controlling terminal
    #[arg(long, default_value = "/dev/tty", value_name = "PATH", value_parser = absolute_path)]
    pub tty: PathBuf,
    /// Signer policy file
    #[arg(long, default_value = "/etc/sigrund/signers.toml", value_name = "PATH", value_parser = absolute_path)]
    pub signers: PathBuf,
    /// Trusted live daemon epoch
    #[arg(long, default_value = crate::host_registry::DEFAULT_EPOCH_FILE, value_name = "PATH", value_parser = absolute_path)]
    pub epoch_file: PathBuf,
    /// SSH signing identity
    #[arg(long, required = true, value_name = "PATH", value_parser = absolute_path)]
    pub identity: Option<PathBuf>,
}

impl ApprovalArgs {
    pub fn parse(args: &[String]) -> clap::error::Result<Self> {
        Self::try_parse_from(
            std::iter::once("sigrund-approve").chain(args.iter().map(String::as_str)),
        )
    }
}

pub fn absolute_path(value: &str) -> Result<PathBuf> {
    crate::linux::validate_absolute_path(std::path::Path::new(value))
        .map_err(|_| invalid("path must be canonical absolute text and NUL-free"))?;
    Ok(value.into())
}
fn target(value: &str) -> Result<String> {
    parse_target(value)?;
    Ok(value.into())
}
fn environment(value: &str) -> Result<(String, String)> {
    let (name, value) = value
        .split_once('=')
        .ok_or_else(|| invalid("environment entry must be NAME=VALUE"))?;
    Ok((name.into(), value.into()))
}
fn umask(value: &str) -> Result<u32> {
    if value.is_empty() || !value.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err(invalid("umask must be octal"));
    }
    u32::from_str_radix(value, 8).map_err(|_| invalid("invalid umask"))
}
fn ttl(value: &str) -> Result<u64> {
    decimal(value).and_then(|v| {
        if v > 0 {
            Ok(v)
        } else {
            Err(invalid("TTL must be positive"))
        }
    })
}
fn status_fd(value: &str) -> Result<i32> {
    i32::try_from(decimal(value)?)
        .ok()
        .filter(|v| !matches!(v, 1 | 2))
        .ok_or_else(|| invalid("status FD must be nonnegative and separate from stdout/stderr"))
}
fn exit_code(value: &str) -> Result<u8> {
    u8::try_from(decimal(value)?).map_err(|_| invalid("exit code outside 0..255"))
}
fn signal(value: &str) -> Result<u8> {
    exit_code(value).and_then(|v| {
        if [1, 2, 10, 12, 15].contains(&v) {
            Ok(v)
        } else {
            Err(invalid("signal is outside the protocol allowlist"))
        }
    })
}
fn invalid(message: &str) -> CoreError {
    CoreError::Value(message.into())
}
