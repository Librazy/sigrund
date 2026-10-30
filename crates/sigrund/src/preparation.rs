//! Common request preparation on the request's existing reserved I/O worker.
//! These results bind bytes and identity; they never authorize, commit or spawn.
use crate::{
    linux::openat2_executable,
    snapshot::{self, SnapshotBudget},
    workers::{MeasuredSnapshots, ValidatedRequest},
};
use sigrund_core::{
    approval::{ApprovalRequest, ApprovalResponse},
    config::{SignerConfig, SignerPolicyFile},
    crypto::{new_uuidv7, verify_ssh_signature},
    paths::select_root,
    warrant::{CanonicalWarrant, Csr, CsrIdentity, SnapshotDigests},
};
use std::{
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

pub(crate) struct PinnedRoot {
    pub path: PathBuf,
    pub directory: File,
}
pub(crate) struct Context {
    pub roots: Vec<PinnedRoot>,
    pub host_id: String,
    pub signers: SignerPolicyFile,
}
#[derive(Debug)]
pub(crate) struct Failure {
    pub status: &'static str,
    message: String,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Failure {}
fn fail(status: &'static str, message: impl Into<String>) -> io::Error {
    io::Error::other(Failure {
        status,
        message: message.into(),
    })
}
fn snapshot_error(error: io::Error, status: &'static str) -> io::Error {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => error,
        io::ErrorKind::WouldBlock => fail("RESOURCE_EXHAUSTED", "snapshot RAM quota exhausted"),
        _ => fail(status, "snapshot source, size, or sealing failed"),
    }
}
#[derive(Debug)]
pub(crate) struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}
impl FileIdentity {
    fn read(file: &File) -> io::Result<Self> {
        let m = file.metadata()?;
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
        })
    }
}
pub(crate) enum Document {
    Unsigned(Csr),
    Signed {
        warrant: CanonicalWarrant,
        signer_id: String,
    },
}
pub(crate) struct Prepared {
    pub document: Document,
    pub root_path: PathBuf,
    pub root_identity: FileIdentity,
    pub source_identity: FileIdentity,
    pub null_stdin: Option<OwnedFd>,
}

pub(crate) fn check_unsigned_policy(
    request: &mut ValidatedRequest,
    context: &Context,
    gid: u32,
) -> io::Result<()> {
    request.check()?;
    if request
        .hello
        .requested_policy
        .as_ref()
        .is_some_and(|p| p.ttl_secs > request.policy.max_ttl_secs)
    {
        return Err(fail("POLICY_VIOLATION", "TTL exceeds captured policy"));
    }
    if request.hello.mode == "unsigned_csr_request"
        && let Some(profile) = &request.policy.mvp
        && !profile.approval_signer_id.is_empty()
    {
        let now = realtime()?;
        let candidate = Csr::from_unsigned(
            &request.hello,
            CsrIdentity {
                grant_id: new_uuidv7().to_string(),
                host_id: context.host_id.clone(),
                requester_uid: request.requester_uid,
                requester_gid: gid,
                now,
            },
            SnapshotDigests {
                executable_sha256: "0".repeat(64),
                stdin_sha256: request
                    .hello
                    .requested_command
                    .as_ref()
                    .filter(|c| c.stdin_policy == "sha256")
                    .map(|_| "0".repeat(64)),
            },
            request.policy.max_ttl_secs,
        )
        .map_err(|_| fail("POLICY_VIOLATION", "request exceeds policy bounds"))?;
        let signer = context
            .signers
            .signers
            .iter()
            .find(|s| s.signer_id == profile.approval_signer_id)
            .ok_or_else(|| fail("POLICY_VIOLATION", "approval signer unavailable"))?;
        select_root(
            std::path::Path::new(&candidate.warrant().command.executable_path),
            &signer.allowed_executable_dirs,
        )
        .map_err(|_| {
            fail(
                "POLICY_VIOLATION",
                "executable outside approval signer roots",
            )
        })?;
        if !static_policy(
            signer,
            candidate.warrant(),
            request.requester_uid,
            gid,
            &context.host_id,
            &request.policy,
        ) {
            return Err(fail(
                "POLICY_VIOLATION",
                "request exceeds approval signer policy",
            ));
        }
    }
    request.unsigned_policy_checked = true;
    request.check()
}

pub(crate) fn prepare(
    request: &mut ValidatedRequest,
    context: &Context,
    budget: &SnapshotBudget,
    gid: u32,
) -> io::Result<()> {
    request.check()?;
    if request.hello.mode == "unsigned_csr_request" && !request.unsigned_policy_checked {
        check_unsigned_policy(request, context, gid)?;
    }
    let signed = if let Some(envelope) = &request.hello.dsse_envelope {
        let warrant = envelope
            .warrant()
            .map_err(|_| fail("INVALID_REQUEST", "invalid canonical warrant"))?;
        let signer = context
            .signers
            .signers
            .iter()
            .find(|signer| {
                static_policy(
                    signer,
                    warrant.warrant(),
                    request.requester_uid,
                    gid,
                    &context.host_id,
                    &request.policy,
                ) && envelope.signatures.iter().any(|signature| {
                    signature.keyid == signer.signer_id
                        && verify_ssh_signature(
                            &signer.signature_type,
                            &signer.public_key,
                            &signature.sig,
                            &envelope.payload_type,
                            warrant.as_bytes(),
                            signer.require_user_presence,
                            signer.require_user_verification,
                        )
                        .is_ok()
                })
            })
            .ok_or_else(|| {
                fail(
                    "POLICY_VIOLATION",
                    "no verified signer satisfies static policy",
                )
            })?;
        Some((warrant, signer.signer_id.clone()))
    } else {
        None
    };
    let command = signed
        .as_ref()
        .map(|(w, _)| w.warrant().command.requested())
        .or_else(|| request.hello.requested_command.clone())
        .expect("validated request");
    let selected = select_root(
        std::path::Path::new(&command.executable_path),
        &request.policy.csr_allowed_executable_dirs,
    )
    .map_err(|_| fail("POLICY_VIOLATION", "executable is outside configured roots"))?;
    let root = context
        .roots
        .iter()
        .find(|root| root.path == selected.root)
        .ok_or_else(|| fail("POLICY_VIOLATION", "captured executable root unavailable"))?;
    let root_identity = FileIdentity::read(&root.directory)?;
    request.check()?;
    let source: File = openat2_executable(root.directory.as_raw_fd(), &selected.relative_path)
        .map_err(|_| {
            fail(
                "EXECUTABLE_MUTATED_OR_TOO_LARGE",
                "executable resolution failed",
            )
        })?
        .into();
    request.check()?;
    let source_identity = FileIdentity::read(&source)?;
    request.check()?;
    let executable = snapshot::executable(
        source,
        budget,
        request.requester_uid,
        &request.policy,
        || request.check(),
    )
    .map_err(|e| snapshot_error(e, "EXECUTABLE_MUTATED_OR_TOO_LARGE"))?;
    request.snapshots = Some(MeasuredSnapshots {
        executable,
        stdin: None,
    });
    let null_stdin = if command.stdin_policy == "sha256" {
        let source = File::from(request.rights.remove(0));
        let stdin = snapshot::stdin(
            source,
            budget,
            request.requester_uid,
            &request.policy,
            || request.check(),
        )
        .map_err(|e| snapshot_error(e, "STDIN_HASH_MISMATCH"))?;
        request
            .snapshots
            .as_mut()
            .expect("executable snapshot")
            .stdin = Some(stdin);
        None
    } else {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open("/dev/null")?;
        let metadata = file.metadata()?;
        if metadata.mode() & libc::S_IFMT != libc::S_IFCHR || metadata.rdev() != libc::makedev(1, 3)
        {
            return Err(fail("INVALID_REQUEST", "invalid null stdin device"));
        }
        Some(file.into())
    };
    request.check()?;
    let snapshots = request.snapshots.as_ref().expect("snapshot owner");
    let stdin_digest = snapshots.stdin.as_ref().map(|s| s.digest.sha256.clone());
    let document = if let Some((warrant, signer_id)) = signed {
        if !bool::from(
            warrant
                .warrant()
                .command
                .executable_sha256
                .as_bytes()
                .ct_eq(snapshots.executable.digest.sha256.as_bytes()),
        ) {
            return Err(fail(
                "EXECUTABLE_MUTATED_OR_TOO_LARGE",
                "signed executable digest differs",
            ));
        }
        let stdin_matches = match (&warrant.warrant().command.stdin_sha256, &stdin_digest) {
            (None, None) => true,
            (Some(a), Some(b)) => bool::from(a.as_bytes().ct_eq(b.as_bytes())),
            _ => false,
        };
        if !stdin_matches {
            return Err(fail("STDIN_HASH_MISMATCH", "signed stdin digest differs"));
        }
        Document::Signed { warrant, signer_id }
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .ok_or_else(|| fail("INVALID_REQUEST", "clock outside timestamp bounds"))?;
        let csr = Csr::from_unsigned(
            &request.hello,
            CsrIdentity {
                grant_id: new_uuidv7().to_string(),
                host_id: context.host_id.clone(),
                requester_uid: request.requester_uid,
                requester_gid: gid,
                now,
            },
            SnapshotDigests {
                executable_sha256: snapshots.executable.digest.sha256.clone(),
                stdin_sha256: stdin_digest,
            },
            request.policy.max_ttl_secs,
        )
        .map_err(|_| {
            fail(
                "POLICY_VIOLATION",
                "CSR exceeds captured policy or document bounds",
            )
        })?;
        Document::Unsigned(csr)
    };
    request.prepared = Some(Prepared {
        document,
        root_path: selected.root,
        root_identity,
        source_identity,
        null_stdin,
    });
    request.check()
}

pub(crate) fn static_policy(
    signer: &SignerConfig,
    warrant: &sigrund_core::warrant::Warrant,
    uid: u32,
    gid: u32,
    host: &str,
    config: &sigrund_core::config::DaemonConfig,
) -> bool {
    let context = &warrant.execution_context;
    let window = warrant
        .policy
        .not_after
        .and_then(|end| end.checked_sub(warrant.policy.not_before))
        .and_then(|v| u64::try_from(v).ok());
    warrant.host_id == host
        && warrant.requester_uid == uid
        && warrant.requester_gid == gid
        && signer.allowed_requester_uids.contains(&uid)
        && signer.allowed_target_uids.contains(&context.target_uid)
        && signer.allowed_target_gids.contains(&context.target_gid)
        && context.target_uid != uid
        && context
            .supplementary_gids
            .iter()
            .all(|g| signer.allowed_supplementary_gids.contains(g))
        && context
            .capabilities
            .iter()
            .all(|c| signer.allowed_capabilities.contains(c))
        && signer.allowed_modes.contains(&warrant.policy.mode)
        && window.is_some_and(|window| {
            window <= signer.max_ttl_secs
                && window <= config.max_ttl_secs
                && window <= config.max_onetime_window_secs
        })
}

fn realtime() -> io::Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .ok_or_else(|| fail("INVALID_REQUEST", "clock outside timestamp bounds"))
}

/// Broker transport, parsing and crypto remain on the original reserved worker.
/// The coordinator owns the slot, deadline and cancellation handle.
pub(crate) fn approve(
    request: &mut ValidatedRequest,
    context: &Context,
    gid: u32,
    approval: ApprovalRequest,
    socket: OwnedFd,
) -> io::Result<()> {
    use crate::transport::{ApprovalReader, FrameWriter};
    let exchange = (|| -> io::Result<ApprovalResponse> {
        let mut writer = FrameWriter::approval(
            &approval
                .to_jcs()
                .map_err(|e| io::Error::other(e.to_string()))?,
            std::time::Instant::now(),
        )?;
        loop {
            request.check()?;
            if writer.write(socket.as_raw_fd(), std::time::Instant::now())? {
                break;
            }
            broker_poll(socket.as_raw_fd(), libc::POLLOUT)?;
        }
        let mut reader = ApprovalReader::default();
        loop {
            request.check()?;
            if let Some(bytes) = reader.read(socket.as_raw_fd(), std::time::Instant::now())? {
                request.check()?;
                return ApprovalResponse::parse_jcs(&bytes)
                    .map_err(|e| io::Error::other(e.to_string()));
            }
            broker_poll(socket.as_raw_fd(), libc::POLLIN)?;
        }
    })()
    .map_err(|_| {
        fail(
            "TIMEOUT_CSR",
            "approval connection lost, expired or malformed",
        )
    })?;
    request
        .check()
        .map_err(|_| fail("TIMEOUT_CSR", "approval deadline expired"))?;
    let warrant = approval
        .bind_response(&exchange)
        .map_err(|_| fail("POLICY_VIOLATION", "approval differs from retained request"))?;
    let Some(warrant) = warrant else {
        let ApprovalResponse::Rejected { reason, .. } = exchange else {
            unreachable!()
        };
        return Err(fail("REJECTED", crate::client::escaped(&reason)));
    };
    let ApprovalResponse::Approved { dsse_envelope, .. } = exchange else {
        unreachable!()
    };
    let signer = context
        .signers
        .signers
        .iter()
        .find(|s| s.signer_id == approval.signer_id)
        .ok_or_else(|| fail("POLICY_VIOLATION", "approval signer unavailable"))?;
    if !static_policy(
        signer,
        warrant.warrant(),
        request.requester_uid,
        gid,
        &context.host_id,
        &request.policy,
    ) {
        return Err(fail(
            "POLICY_VIOLATION",
            "approved request exceeds captured signer policy",
        ));
    }
    let sig = &dsse_envelope.signatures[0];
    verify_ssh_signature(
        &signer.signature_type,
        &signer.public_key,
        &sig.sig,
        &dsse_envelope.payload_type,
        warrant.as_bytes(),
        signer.require_user_presence,
        signer.require_user_verification,
    )
    .map_err(|_| fail("POLICY_VIOLATION", "approval signature verification failed"))?;
    let now = realtime()?;
    if now < warrant.warrant().policy.not_before
        || warrant
            .warrant()
            .policy
            .not_after
            .is_none_or(|end| now > end)
    {
        return Err(fail(
            "EXPIRED_OR_NOT_YET_VALID",
            "approved warrant expired or not yet valid",
        ));
    }
    request.check()?;
    let prepared = request
        .prepared
        .as_mut()
        .expect("retained snapshots and CSR");
    prepared.document = Document::Signed {
        warrant,
        signer_id: signer.signer_id.clone(),
    };
    Ok(())
}

fn broker_poll(fd: i32, events: i16) -> io::Result<()> {
    let mut descriptor = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    if unsafe { libc::poll(&mut descriptor, 1, 20) } < 0
        && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha512};
    use sigrund_core::{
        config::DaemonConfig,
        crypto::{WARRANT_PAYLOAD_TYPE, pae},
        protocol::ClientHello,
    };
    use std::{
        io::Read,
        os::fd::AsFd,
        sync::{Arc, atomic::AtomicBool},
        time::{Duration, Instant},
    };

    fn string(bytes: &[u8], output: &mut Vec<u8>) {
        output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        output.extend_from_slice(bytes);
    }
    fn signed_hello(warrant: &CanonicalWarrant, namespace: &str, key: u8) -> ClientHello {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[key; 32]);
        let mut public = Vec::new();
        string(b"ssh-ed25519", &mut public);
        string(&signing.verifying_key().to_bytes(), &mut public);
        let mut message = b"SSHSIG".to_vec();
        string(namespace.as_bytes(), &mut message);
        string(b"", &mut message);
        string(b"sha512", &mut message);
        string(
            &Sha512::digest(pae(WARRANT_PAYLOAD_TYPE, warrant.as_bytes())),
            &mut message,
        );
        let mut signature = Vec::new();
        string(b"ssh-ed25519", &mut signature);
        string(&signing.sign(&message).to_bytes(), &mut signature);
        let mut envelope = b"SSHSIG".to_vec();
        envelope.extend_from_slice(&1u32.to_be_bytes());
        for bytes in [
            &public[..],
            namespace.as_bytes(),
            b"",
            b"sha512",
            &signature,
        ] {
            string(bytes, &mut envelope);
        }
        ClientHello::parse_request(&serde_json::to_vec(&serde_json::json!({
            "mode":"signed", "tty_mode":"stdio", "caller_env":{},
            "dsse_envelope":{"payloadType":WARRANT_PAYLOAD_TYPE,
                "payload":STANDARD.encode(warrant.as_bytes()),
                "signatures":[{"keyid":"mandator-alice-yubikey", "sig":STANDARD.encode(envelope)}]}
        })).unwrap()).unwrap()
    }

    struct Fixture {
        dir: tempfile::TempDir,
        context: Context,
        config: Arc<DaemonConfig>,
        budget: SnapshotBudget,
        hello: ClientHello,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("program");
            std::fs::write(&path, b"\x7fELFsealed-program").unwrap();
            let mut config = DaemonConfig::from_toml(
                include_str!("../../../config/sigrund.toml.example")
                    .replace(
                        "<strict-padded-base64-32-byte-ed25519-key>",
                        &STANDARD.encode([1; 32]),
                    )
                    .as_bytes(),
            )
            .unwrap();
            config.csr_allowed_executable_dirs = vec![dir.path().to_owned()];
            config.max_stdin_bytes = 4096;
            let mut public = Vec::new();
            string(b"ssh-ed25519", &mut public);
            string(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                    .verifying_key()
                    .to_bytes(),
                &mut public,
            );
            let signers = SignerPolicyFile::from_toml(
                include_str!("../../../config/signers.toml.example")
                    .replace("type = \"sk-ssh-ed25519\"", "type = \"ssh-ed25519\"")
                    .replace(
                        "require_user_presence = true",
                        "require_user_presence = false",
                    )
                    .replace(
                        "sk-ssh-ed25519@openssh.com AAAA...",
                        &format!("ssh-ed25519 {}", STANDARD.encode(public)),
                    )
                    .replace(
                        "[\"/usr/bin\", \"/usr/sbin\"]",
                        &format!("[\"{}\"]", dir.path().display()),
                    )
                    .as_bytes(),
            )
            .unwrap();
            signers.validate_against(&config).unwrap();
            let context = Context {
                roots: vec![PinnedRoot {
                    path: dir.path().to_owned(),
                    directory: crate::startup::pin_directory(dir.path()).unwrap(),
                }],
                host_id: format!("sigrun-host:sha256:{}", "a".repeat(64)),
                signers,
            };
            let hello = crate::cli::RequestOptions::default()
                .hello(
                    &[path.to_str().unwrap().to_owned(), "".into()],
                    std::path::Path::new("/"),
                )
                .unwrap();
            Self {
                dir,
                context,
                config: Arc::new(config),
                budget: SnapshotBudget::default(),
                hello,
            }
        }
        fn request(&self, hello: ClientHello, input: Option<&[u8]>) -> ValidatedRequest {
            let mut rights = Vec::new();
            if let Some(bytes) = input {
                use std::io::{Seek, Write};
                let mut file = tempfile::tempfile().unwrap();
                file.write_all(bytes).unwrap();
                file.rewind().unwrap();
                rights.push(file.into());
            }
            for _ in 0..2 {
                rights.push(File::open("/dev/null").unwrap().into());
            }
            ValidatedRequest {
                hello,
                rights,
                snapshots: None,
                unsigned_policy_checked: false,
                prepared: None,
                policy: self.config.clone(),
                requester_uid: 1001,
                deadline: Instant::now() + Duration::from_secs(5),
                deadline_active: true,
                cancelled: Arc::new(AtomicBool::new(false)),
            }
        }
        fn warrant(&self) -> CanonicalWarrant {
            let mut request = self.request(self.hello.clone(), None);
            prepare(&mut request, &self.context, &self.budget, 1001).unwrap();
            let Document::Unsigned(csr) = &request.prepared.as_ref().unwrap().document else {
                panic!()
            };
            CanonicalWarrant::parse(csr.as_bytes()).unwrap()
        }
    }

    #[test]
    fn common_preparation_retains_sealed_bytes_identities_and_stdin_bindings() {
        let fixture = Fixture::new();
        for input in [None, Some(b"".as_slice()), Some(b"input\0\xff".as_slice())] {
            let mut hello = fixture.hello.clone();
            if input.is_some() {
                hello.requested_command.as_mut().unwrap().stdin_policy = "sha256".into();
            }
            let mut request = fixture.request(hello, input);
            prepare(&mut request, &fixture.context, &fixture.budget, 1001).unwrap();
            let prepared = request.prepared.as_ref().unwrap();
            let Document::Unsigned(csr) = &prepared.document else {
                panic!()
            };
            assert_eq!(Csr::parse(csr.as_bytes()).unwrap(), *csr);
            assert_eq!(
                (csr.warrant().requester_uid, csr.warrant().requester_gid),
                (1001, 1001)
            );
            assert_eq!(csr.warrant().host_id, fixture.context.host_id);
            assert_eq!(
                csr.warrant().command.stdin_sha256,
                input.map(sigrund_core::crypto::sha256_hex)
            );
            assert_eq!(prepared.null_stdin.is_some(), input.is_none());
            assert_eq!(
                prepared.root_identity.inode,
                fixture.context.roots[0].directory.metadata().unwrap().ino()
            );
            assert_eq!(
                prepared.source_identity.inode,
                std::fs::metadata(fixture.dir.path().join("program"))
                    .unwrap()
                    .ino()
            );
            let snapshots = request.snapshots.as_ref().unwrap();
            for snapshot in [Some(&snapshots.executable), snapshots.stdin.as_ref()]
                .into_iter()
                .flatten()
            {
                let fd = snapshot.as_fd().as_raw_fd();
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } & 0x1f, 0x1f);
                assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }, 0);
            }
            // Once captured, changing/replacing the source cannot change the CSR or memfd.
            let source = fixture.dir.path().join("program");
            let original = std::fs::read(&source).unwrap();
            std::fs::write(&source, b"changed-source").unwrap();
            let mut bytes = Vec::new();
            File::from(snapshots.executable.as_fd().try_clone_to_owned().unwrap())
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(bytes, original);
            assert_eq!(
                csr.warrant().command.executable_sha256,
                sigrund_core::crypto::sha256_hex(&bytes)
            );
            std::fs::write(&source, &original).unwrap();
            drop(request);
            assert_eq!(fixture.budget.usage(1001), (0, 0));
        }
    }

    #[test]
    fn final_authorization_rechecks_retained_policy_and_identity() {
        let output = std::process::Command::new("unshare")
            .args(["--user", "--map-auto", "--map-root-user"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "preparation::tests::final_authorization_namespace_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("SIGRUND_FINAL_GATE", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    #[ignore = "invoked by the namespace gate"]
    fn final_authorization_namespace_fixture() {
        assert_eq!(std::env::var("SIGRUND_FINAL_GATE").unwrap(), "1");
        let mut fixture = Fixture::new();
        Arc::make_mut(&mut fixture.config).mvp = Some(Default::default());
        let canonical = fixture.warrant();
        for case in [
            "valid",
            "root_path",
            "root_inode",
            "root_device",
            "signer",
            "cached_digest",
            "caller_env",
            "stdin",
            "peer_gid",
            "same_uid",
        ] {
            let mut request =
                fixture.request(signed_hello(&canonical, "sigrun.warrant.v1", 7), None);
            prepare(&mut request, &fixture.context, &fixture.budget, 1001).unwrap();
            let prepared = request.prepared.as_mut().unwrap();
            match case {
                "valid" => (),
                "root_path" => prepared.root_path = "/different-root".into(),
                "root_inode" => prepared.root_identity.inode ^= 1,
                "root_device" => prepared.root_identity.device ^= 1,
                "signer" => {
                    let Document::Signed { signer_id, .. } = &mut prepared.document else {
                        panic!()
                    };
                    *signer_id = "unconfigured".into();
                }
                "cached_digest" => {
                    let Document::Signed { warrant, .. } = &mut prepared.document else {
                        panic!()
                    };
                    let mut changed = warrant.warrant().clone();
                    changed.command.executable_sha256 = "0".repeat(64);
                    *warrant = CanonicalWarrant::new(changed).unwrap();
                    request.snapshots.as_mut().unwrap().executable.digest.sha256 = "0".repeat(64);
                }
                "caller_env" => {
                    request
                        .hello
                        .caller_env
                        .insert("PATH".into(), "/attacker".into());
                }
                "stdin" => {
                    prepared.null_stdin = None;
                }
                "peer_gid" => (),
                "same_uid" => {
                    let Document::Signed { warrant, .. } = &mut prepared.document else {
                        panic!()
                    };
                    let mut changed = warrant.warrant().clone();
                    changed.execution_context.target_uid = 1001;
                    *warrant = CanonicalWarrant::new(changed).unwrap();
                }
                _ => unreachable!(),
            }
            let result = crate::authorization::verify(
                &request,
                &fixture.context,
                if case == "peer_gid" { 1002 } else { 1001 },
            );
            if case == "valid" {
                let result = result.unwrap();
                let environment: Vec<_> = result.envp.iter().map(|s| s.to_str().unwrap()).collect();
                assert_eq!(environment, ["LANG=C.UTF-8", "PATH=/usr/sbin:/usr/bin"]);
            } else {
                assert!(result.is_err(), "{case}");
            }
        }
    }

    #[test]
    fn signed_preparation_verifies_candidate_before_open_and_binds_both_digests() {
        let fixture = Fixture::new();
        let warrant = fixture.warrant();
        let mut request = fixture.request(signed_hello(&warrant, "sigrun.warrant.v1", 7), None);
        prepare(&mut request, &fixture.context, &fixture.budget, 1001).unwrap();
        assert!(
            matches!(&request.prepared.as_ref().unwrap().document, Document::Signed { signer_id, .. } if signer_id=="mandator-alice-yubikey")
        );
        drop(request);
        // Digest failures happen after authenticated candidate selection.
        for stdin in [false, true] {
            let mut w = warrant.warrant().clone();
            if stdin {
                w.command.stdin_policy = "sha256".into();
                w.command.stdin_sha256 = Some("0".repeat(64));
            } else {
                w.command.executable_sha256 = "0".repeat(64);
            }
            let w = CanonicalWarrant::new(w).unwrap();
            let mut request = fixture.request(
                signed_hello(&w, "sigrun.warrant.v1", 7),
                stdin.then_some(b"input".as_slice()),
            );
            let error = prepare(&mut request, &fixture.context, &fixture.budget, 1001).unwrap_err();
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<Failure>()
                    .unwrap()
                    .status,
                if stdin {
                    "STDIN_HASH_MISMATCH"
                } else {
                    "EXECUTABLE_MUTATED_OR_TOO_LARGE"
                }
            );
            drop(request);
            assert_eq!(fixture.budget.usage(1001), (0, 0));
        }
        std::fs::remove_file(fixture.dir.path().join("program")).unwrap();
        let mut bad = Vec::new();
        bad.push(signed_hello(&warrant, "wrong-namespace", 7));
        bad.push(signed_hello(&warrant, "sigrun.warrant.v1", 8));
        for field in ["host", "uid", "gid", "target", "ttl", "capability", "root"] {
            let mut w = warrant.warrant().clone();
            match field {
                "host" => w.host_id = format!("sigrun-host:sha256:{}", "b".repeat(64)),
                "uid" => w.requester_uid = 1002,
                "gid" => w.requester_gid = 1002,
                "target" => w.execution_context.target_uid = 44,
                "ttl" => w.policy.not_after = Some(w.policy.not_before + 3601),
                "capability" => w.execution_context.capabilities = vec!["CAP_SYS_ADMIN".into()],
                "root" => w.command.executable_path = "/outside/program".into(),
                _ => unreachable!(),
            }
            bad.push(signed_hello(
                &CanonicalWarrant::new(w).unwrap(),
                "sigrun.warrant.v1",
                7,
            ));
        }
        for hello in bad {
            let mut request = fixture.request(hello, None);
            let error = prepare(&mut request, &fixture.context, &fixture.budget, 1001).unwrap_err();
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<Failure>()
                    .unwrap()
                    .status,
                "POLICY_VIOLATION"
            );
            assert!(request.snapshots.is_none());
            drop(request);
            assert_eq!(fixture.budget.usage(1001), (0, 0));
        }
    }
}
