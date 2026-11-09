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
    pub directory: std::sync::Arc<File>,
}
pub(crate) struct Context {
    pub targets: Option<std::sync::Arc<crate::target_registry::TargetRegistry>>,
    pub epoch: Option<std::sync::Arc<crate::host_registry::EpochOwner>>,
    pub host_target: Option<std::sync::Arc<crate::host_target::HostTarget>>,
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
pub(crate) fn fail(status: &'static str, message: impl Into<String>) -> io::Error {
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
    pub(crate) fn read(file: &File) -> io::Result<Self> {
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
        signer_ids: Vec<String>,
    },
}
pub(crate) struct Prepared {
    pub document: Document,
    pub root_path: PathBuf,
    pub root_identity: FileIdentity,
    pub source_identity: FileIdentity,
    pub null_stdin: Option<OwnedFd>,
}

/// Retained preparation state handed back before the coordinator starts hashing.
pub(crate) struct Pending {
    pub(crate) signed: Option<(CanonicalWarrant, Vec<String>)>,
    pub(crate) root_path: PathBuf,
    pub(crate) root_identity: FileIdentity,
    pub(crate) source_identity: FileIdentity,
    pub(crate) null_stdin: Option<OwnedFd>,
}

/// Pin the host null device before any destination transition. Output rights
/// are never an alternative source of unsigned input.
pub(crate) fn null_stdin(policy: &str) -> io::Result<Option<OwnedFd>> {
    if policy == "sha256" {
        return Ok(None);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/null")?;
    let fd = file.into();
    verify_null_stdin(&fd)?;
    Ok(Some(fd))
}

pub(crate) fn verify_null_stdin(fd: &OwnedFd) -> io::Result<()> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFCHR
        || stat.st_rdev != libc::makedev(1, 3)
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE != libc::O_RDONLY
    {
        return Err(fail("INVALID_REQUEST", "invalid null device"));
    }
    Ok(())
}

fn verify_full_account(csr: &Csr) -> io::Result<()> {
    let w = csr.warrant();
    let (uid, gid, groups) = crate::accounts::resolve(&w.intent.account)?;
    let c = &w.execution_context;
    if (uid, gid, &groups) != (c.target_uid, c.target_gid, &c.supplementary_gids) {
        return Err(fail(
            "POLICY_VIOLATION",
            "resolved account differs from full CSR",
        ));
    }
    Ok(())
}

fn capture_target(request: &mut ValidatedRequest, context: &Context) -> io::Result<()> {
    let original = request.hello.original_intent().map_err(io::Error::other)?;
    if !matches!(original.target, sigrund_core::host::Selector::Host {}) {
        return Err(fail(
            "POLICY_VIOLATION",
            "destination preparation is not yet connected",
        ));
    }

    if request.host_lease.is_none() {
        request.host_lease = Some(
            context
                .host_target
                .as_ref()
                .ok_or_else(|| fail("INVALID_REQUEST", "host target unavailable"))?
                .lease_for_review(request.requester_uid, request.hello.mode != "signed")
                .map_err(|e| {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        fail(
                            "RESOURCE_EXHAUSTED",
                            "host target/review/FD capacity exhausted",
                        )
                    } else {
                        e
                    }
                })?,
        );

        if request.hello.mode == "thin_csr" {
            let original = request
                .hello
                .original_intent
                .as_ref()
                .ok_or_else(|| fail("INVALID_REQUEST", "missing explicit intent"))?;
            let (uid, gid, groups) = crate::accounts::resolve(&original.account)?;
            request.hello.requested_execution_context =
                Some(original.execution_context.resolve(uid, gid, groups));
        }
        if request.hello.mode == "full_csr" {
            let csr = Csr::parse(
                request
                    .hello
                    .csr_payload
                    .as_ref()
                    .expect("validated full CSR")
                    .as_bytes(),
            )
            .map_err(io::Error::other)?;
            verify_full_account(&csr)?;
        }
        let original = if let Some(intent) = &request.hello.original_intent {
            intent.clone()
        } else {
            request
                .hello
                .dsse_envelope
                .as_ref()
                .ok_or_else(|| fail("INVALID_REQUEST", "missing intent"))?
                .warrant()
                .map_err(io::Error::other)?
                .warrant()
                .intent
                .clone()
        };
        let profile = request
            .policy
            .host_profiles
            .iter()
            .find(|p| p.profile_id == original.security_profile)
            .ok_or_else(|| fail("POLICY_VIOLATION", "unavailable security profile"))?;
        if profile.capabilities != original.execution_context.capabilities {
            return Err(fail("POLICY_VIOLATION", "profile capability mismatch"));
        }
        request.host_profile = Some(profile.clone());
    }
    Ok(())
}

pub(crate) fn check_unsigned_policy(
    request: &mut ValidatedRequest,
    context: &Context,
    gid: u32,
) -> io::Result<()> {
    capture_target(request, context)?;
    request.check()?;
    let intent = request
        .hello
        .intent()
        .map_err(|e| fail("INVALID_REQUEST", e.to_string()))?;
    let c = &intent.execution_context;
    let signer = context
        .signers
        .signers
        .iter()
        .find(|s| {
            request
                .policy
                .mvp
                .as_ref()
                .is_some_and(|p| p.approval_signer_id == s.signer_id)
        })
        .ok_or_else(|| fail("POLICY_VIOLATION", "approval signer unavailable"))?;
    use sigrund_core::host::Record;
    let profile = request
        .policy
        .host_profiles
        .iter()
        .find(|p| {
            request
                .hello
                .original_intent
                .as_ref()
                .is_some_and(|i| i.security_profile == p.profile_id)
        })
        .ok_or_else(|| fail("POLICY_VIOLATION", "profile unavailable"))?;
    let profile_hash = profile.sha256().map_err(io::Error::other)?;
    let permits = |rule: &sigrund_core::host::ScopedRule| {
        rule.permits(
            request.requester_uid,
            c.target_uid,
            c.target_gid,
            &c.supplementary_gids,
            &profile_hash,
        )
    };
    if !request.policy.host_rules.iter().any(permits) || !signer.host_rules.iter().any(permits) {
        return Err(fail("POLICY_VIOLATION", "scoped host policy denied"));
    }
    let ttl = intent.policy.ttl_secs;
    if intent.policy.mode != "one_time"
        || ttl > request.policy.max_ttl_secs
        || ttl > request.policy.max_onetime_window_secs
        || ttl > signer.max_ttl_secs
        || !signer
            .allowed_requester_uids
            .contains(&request.requester_uid)
        || !signer.allowed_target_uids.contains(&c.target_uid)
        || !signer.allowed_target_gids.contains(&c.target_gid)
        || c.target_uid == request.requester_uid
        || !c
            .supplementary_gids
            .iter()
            .all(|g| signer.allowed_supplementary_gids.contains(g))
        || !c
            .capabilities
            .iter()
            .all(|c| signer.allowed_capabilities.contains(c))
        || !signer.allowed_modes.contains(&intent.policy.mode)
        || select_root(
            std::path::Path::new(&intent.command.executable_path),
            &signer.allowed_executable_dirs,
        )
        .is_err()
    {
        return Err(fail("POLICY_VIOLATION", "intent exceeds static policy"));
    }
    if let Some(payload) = &request.hello.csr_payload {
        let csr =
            Csr::parse(payload.as_bytes()).map_err(|e| fail("INVALID_REQUEST", e.to_string()))?;
        let w = csr.warrant();
        let now = realtime()?;
        if !static_policy(
            signer,
            w,
            request.requester_uid,
            gid,
            &context.host_id,
            &request.policy,
        ) || now < w.policy.not_before
            || w.policy.not_after.is_none_or(|end| now > end)
        {
            return Err(fail("POLICY_VIOLATION", "full CSR exceeds static policy"));
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
    crate::transport::validate_stdio_checked(&request.hello, &request.rights, || request.check())?;
    // Complete finite input before the first private target observation. Never
    // remove the original endpoint from the outcome owner's descriptor table.
    let stdin = if request
        .hello
        .intent()
        .map_err(|e| fail("INVALID_REQUEST", e.to_string()))?
        .command
        .stdin_policy
        == "sha256"
    {
        let source: File = request
            .rights
            .first()
            .ok_or_else(|| fail("INVALID_REQUEST", "missing stdin"))?
            .try_clone()?
            .into();
        Some(
            snapshot::stdin(
                source,
                budget,
                request.requester_uid,
                &request.policy,
                || request.check(),
            )
            .map_err(|e| snapshot_error(e, "STDIN_HASH_MISMATCH"))?,
        )
    } else {
        None
    };
    if !matches!(
        request
            .hello
            .original_intent()
            .map_err(io::Error::other)?
            .target,
        sigrund_core::host::Selector::Host {}
    ) {
        return crate::process_request::prepare(request, context, budget, gid, stdin);
    }
    capture_target(request, context)?;
    if request.hello.mode != "signed" && !request.unsigned_policy_checked {
        check_unsigned_policy(request, context, gid)?;
    }
    let signed = if let Some(envelope) = &request.hello.dsse_envelope {
        let warrant = envelope
            .warrant()
            .map_err(|_| fail("INVALID_REQUEST", "invalid canonical warrant"))?;
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
                "warrant outside validity window",
            ));
        }
        let signer_ids: Vec<_> = context
            .signers
            .signers
            .iter()
            .filter(|signer| {
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
            .map(|signer| signer.signer_id.clone())
            .collect();
        if signer_ids.is_empty() {
            return Err(fail(
                "POLICY_VIOLATION",
                "no verified signer satisfies static policy",
            ));
        }
        if matches!(
            warrant.warrant().command.executable_trust,
            Some(sigrund_core::executable::ExecutableTrust::Ctime { .. })
        ) {
            return Err(fail(
                "POLICY_VIOLATION",
                "ctime warrants require a live online approval read lease",
            ));
        }
        Some((warrant, signer_ids))
    } else if let Some(payload) = &request.hello.csr_payload {
        Some((
            CanonicalWarrant::parse(payload.as_bytes())
                .map_err(|e| fail("INVALID_REQUEST", e.to_string()))?,
            vec![],
        ))
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
    if let Some((warrant, _)) = &signed {
        let observed = stdin.as_ref().map(|input| &input.digest.sha256);
        if observed != warrant.warrant().command.stdin_sha256.as_ref() {
            return Err(fail("STDIN_HASH_MISMATCH", "signed stdin digest differs"));
        }
    }
    let root = context
        .roots
        .iter()
        .find(|root| root.path == selected.root)
        .ok_or_else(|| fail("POLICY_VIOLATION", "captured executable root unavailable"))?;
    let root_identity = FileIdentity::read(&root.directory)?;
    request.check()?;
    let source: File = if request.hello.mode == "full_csr" {
        let groups = request.requester_groups.as_deref().ok_or_else(|| {
            fail(
                "REQUESTER_ACCESS",
                "authenticated supplementary groups unavailable",
            )
        })?;
        // Bound the fresh-exec helper and its IPC/stdio/transient duplicates
        // through the synchronous kill/reap path, including cancellation.
        let _helper = request
            .host_lease
            .as_ref()
            .ok_or_else(|| fail("INVALID_REQUEST", "missing target owner"))?
            .reserve_resources(sigrund_core::host_budget::Charge {
                helpers: 1,
                target_fds: 16,
                ..Default::default()
            })
            .map_err(|e| {
                if e.kind() == io::ErrorKind::WouldBlock {
                    fail("RESOURCE_EXHAUSTED", "host helper/FD capacity exhausted")
                } else {
                    e
                }
            })?;
        crate::access::open(
            &selected.root,
            &selected.relative_path,
            &root_identity,
            request.requester_uid,
            gid,
            groups,
            (|| request.check(), request.host_lease.as_ref().unwrap()),
        )
        .map_err(|e| {
            if e.kind() == io::ErrorKind::WouldBlock {
                fail(
                    "RESOURCE_EXHAUSTED",
                    "host helper transient FD capacity exhausted",
                )
            } else {
                e
            }
        })?
    } else {
        openat2_executable(root.directory.as_raw_fd(), &selected.relative_path)?.into()
    };
    request.check()?;
    let source_identity = FileIdentity::read(&source)?;
    request.check()?;
    let execution_context = signed
        .as_ref()
        .map(|(w, _)| w.warrant().execution_context.requested())
        .or_else(|| request.hello.requested_execution_context.clone())
        .expect("execution context");
    let mut executable_policy = (*request.policy).clone();
    executable_policy.executable_trust_models = vec![
        request
            .host_profile
            .as_ref()
            .ok_or_else(|| fail("INVALID_REQUEST", "missing captured host profile"))?
            .executable_model,
    ];
    let executable = crate::executable::prepare(
        source,
        crate::executable::Selection {
            signed: signed
                .as_ref()
                .filter(|_| request.hello.mode == "signed")
                .map(|(w, _)| &w.warrant().command),
            context: &execution_context,
            allow_file_capabilities: true,
            trace_available: crate::execution::trace_available(),
        },
        budget,
        request.requester_uid,
        &executable_policy,
        || request.check(),
    )
    .map_err(|e| snapshot_error(e, "EXECUTABLE_MUTATED_OR_TOO_LARGE"))?;
    request.snapshots = Some(MeasuredSnapshots { executable, stdin });
    let null_stdin = null_stdin(&command.stdin_policy)?;
    request.check()?;
    request.pending_preparation = Some(Pending {
        signed,
        root_path: selected.root,
        root_identity,
        source_identity,
        null_stdin,
    });
    if request
        .snapshots
        .as_ref()
        .expect("snapshot owner")
        .executable
        .needs_digest()
    {
        return Ok(());
    }
    finish_document(request, context, gid)
}

pub(crate) fn hash_and_finish(
    request: &mut ValidatedRequest,
    context: &Context,
    gid: u32,
) -> io::Result<()> {
    request.check()?;
    let mut snapshots = request.snapshots.take().expect("snapshot owner");
    let result = snapshots.executable.finish_digest(|| request.check());
    request.snapshots = Some(snapshots);
    result.map_err(|e| snapshot_error(e, "EXECUTABLE_MUTATED_OR_TOO_LARGE"))?;
    if request.process.is_some() {
        return crate::process_request::finish(request, context, gid);
    }
    finish_document(request, context, gid)
}

fn finish_document(request: &mut ValidatedRequest, context: &Context, gid: u32) -> io::Result<()> {
    request.check()?;
    use sigrund_core::host::Record;
    let original = match &request.hello.original_intent {
        Some(intent) => intent.clone(),
        None => request
            .hello
            .dsse_envelope
            .as_ref()
            .ok_or_else(|| fail("INVALID_REQUEST", "missing v3 intent"))?
            .warrant()
            .map_err(io::Error::other)?
            .warrant()
            .intent
            .clone(),
    };
    let model = request
        .snapshots
        .as_ref()
        .ok_or_else(|| fail("INVALID_REQUEST", "missing executable"))?
        .executable
        .model();
    let constraints = request
        .policy
        .host_profiles
        .iter()
        .find(|p| p.profile_id == original.security_profile)
        .ok_or_else(|| fail("POLICY_VIOLATION", "unavailable security profile"))?
        .clone();
    if constraints.executable_model != model
        || constraints.capabilities != original.execution_context.capabilities
    {
        return Err(fail("POLICY_VIOLATION", "measured profile differs"));
    }
    constraints.validate().map_err(io::Error::other)?;
    let lease = request
        .host_lease
        .as_ref()
        .ok_or_else(|| fail("INVALID_REQUEST", "missing host lease"))?;
    request.host_bundle = Some(
        lease
            .target()
            .bundle(context.host_id.clone(), constraints)?,
    );
    let Pending {
        signed,
        root_path,
        root_identity,
        source_identity,
        null_stdin,
    } = request
        .pending_preparation
        .take()
        .expect("pending preparation");
    let snapshots = request.snapshots.as_ref().expect("snapshot owner");
    let stdin_digest = snapshots.stdin.as_ref().map(|s| s.digest.sha256.clone());
    let document = if let Some((warrant, signer_ids)) = signed {
        if !snapshots
            .executable
            .matches_command(&warrant.warrant().command)
            || snapshots.executable.post_exec_capabilities
                != warrant.warrant().execution_context.post_exec_capabilities
        {
            return Err(fail(
                "EXECUTABLE_MUTATED_OR_TOO_LARGE",
                "signed executable evidence differs",
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
        if request.hello.mode == "full_csr" {
            Document::Unsigned(
                Csr::parse(warrant.as_bytes())
                    .map_err(|e| fail("INVALID_REQUEST", e.to_string()))?,
            )
        } else {
            Document::Signed {
                warrant,
                signer_ids,
            }
        }
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .ok_or_else(|| fail("INVALID_REQUEST", "clock outside timestamp bounds"))?;
        let csr = Csr::from_unsigned(
            &request.hello,
            CsrIdentity {
                binding: request.host_bundle.clone(),
                grant_id: new_uuidv7().to_string(),
                host_id: context.host_id.clone(),
                requester_uid: request.requester_uid,
                requester_gid: gid,
                now,
            },
            SnapshotDigests {
                post_exec_capabilities: snapshots.executable.post_exec_capabilities.clone(),
                executable_sha256: snapshots.executable.sha256(),
                executable_trust: snapshots.executable.trust.clone(),
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
        let mut w = csr.warrant().clone();
        w.request_origin = "daemon_expanded_thin".into();
        w.approval_exec_id = Some(request.exec_id.clone());
        Document::Unsigned(Csr::new(w).map_err(|e| fail("INVALID_REQUEST", e.to_string()))?)
    };
    let canonical = match &document {
        Document::Unsigned(csr) => csr.warrant(),
        Document::Signed { warrant, .. } => warrant.warrant(),
    };
    let bundle = request.host_bundle.as_ref().unwrap();
    canonical.verify_bundle(bundle).map_err(io::Error::other)?;
    request.host_lease.as_ref().unwrap().verify(bundle)?;
    let now = realtime()?;
    if now < canonical.policy.not_before || canonical.policy.not_after.is_none_or(|end| now > end) {
        return Err(fail(
            "EXPIRED_OR_NOT_YET_VALID",
            "prepared request expired before review",
        ));
    }
    if let (Document::Unsigned(csr), Some(epoch)) = (&document, &context.epoch) {
        request.check()?;
        epoch.publish_review(
            &request.exec_id,
            csr,
            snapshots.executable.admin_trusted_composefs(),
        )?;
        request.check()?;
    }
    request.prepared = Some(Prepared {
        document,
        root_path,
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
    let permits = |rule: &sigrund_core::host::ScopedRule| {
        rule.permits(
            uid,
            warrant.execution_context.target_uid,
            warrant.execution_context.target_gid,
            &warrant.execution_context.supplementary_gids,
            &warrant.security_constraints.profile_sha256,
        )
    };
    if !config.host_rules.iter().any(permits) || !signer.host_rules.iter().any(permits) {
        return false;
    }

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
        && select_root(
            std::path::Path::new(&warrant.command.executable_path),
            &signer.allowed_executable_dirs,
        )
        .is_ok()
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
    socket: crate::socket_disposal::Socket,
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
    .map_err(|error| {
        fail(
            "APPROVAL_FAILED",
            format!("approval connection lost, expired or malformed: {error}"),
        )
    })?;
    request
        .check()
        .map_err(|error| fail("APPROVAL_FAILED", format!("approval check failed: {error}")))?;
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
    if request.process.is_some() {
        crate::process_request::policy(request, context, signer)?;
    } else {
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
        signer_ids: vec![signer.signer_id.clone()],
    };
    let verified = request
        .process
        .as_ref()
        .map(|_| crate::process_request::verify_final(request, context))
        .transpose()?;
    if let Some(process) = &mut request.process {
        process.verified = verified;
    }
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
            "version":"3.0","mode":"signed", "tty_mode":"stdio", "caller_env":{},
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
            config.mvp = Some(sigrund_core::config::MvpProfile {
                approval_signer_id: "mandator-alice-yubikey".into(),
                ..Default::default()
            });
            config.executable_trust_models =
                vec![sigrund_core::executable::TrustModel::DigestMemfd];
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
                epoch: None,
                targets: None,
                host_target: Some(
                    crate::host_target::HostTarget::acquire(
                        &[dir.path().to_owned()],
                        &sigrund_core::host_budget::Budget::new(Default::default()).unwrap(),
                    )
                    .unwrap(),
                ),
                roots: vec![PinnedRoot {
                    path: dir.path().to_owned(),
                    directory: std::sync::Arc::new(
                        crate::startup::pin_directory(dir.path()).unwrap(),
                    ),
                }],
                host_id: format!("sigrun-host:sha256:{}", "a".repeat(64)),
                signers,
            };
            let hello = crate::cli::RequestOptions {
                target: Some("host".into()),
                security_profile: Some("host-baseline".into()),
                ..crate::cli::RequestOptions::default()
            }
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
                rights.push(
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open("/dev/null")
                        .unwrap()
                        .into(),
                );
            }
            ValidatedRequest {
                source: None,
                host_profile: None,
                host_bundle: None,
                host_lease: None,
                process: None,
                failure: None,
                exec_id: new_uuidv7().to_string(),
                requester_gid: 1001,
                requester_groups: Some(vec![]),
                deferred_cleanup: vec![],
                hello,
                rights,
                snapshots: None,
                unsigned_policy_checked: false,
                prepared: None,
                pending_preparation: None,
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
            let mut w = csr.warrant().clone();
            w.request_origin = "client_full".into();
            w.approval_exec_id = None;
            CanonicalWarrant::new(w).unwrap()
        }
    }

    #[test]
    fn finite_input_precedes_private_account_and_profile_failures() {
        let fixture = Fixture::new();
        let input = b"finite input before any private target observation";
        for failure in ["account", "profile"] {
            let mut hello = fixture.hello.clone();
            hello.requested_command.as_mut().unwrap().stdin_policy = "sha256".into();
            let original = hello.original_intent.as_mut().unwrap();
            original.command.stdin_policy = "sha256".into();
            if failure == "account" {
                original.account = sigrund_core::host::Account::Name {
                    name: format!("missing-{}", new_uuidv7()),
                };
            } else {
                original.security_profile = "missing-profile".into();
            }
            let mut request = fixture.request(hello, Some(input));
            assert!(prepare(&mut request, &fixture.context, &fixture.budget, 1001).is_err());
            assert_eq!(
                unsafe { libc::lseek(request.rights[0].as_raw_fd(), 0, libc::SEEK_CUR) },
                input.len() as i64,
                "{failure}"
            );
        }
    }
    #[test]
    fn common_preparation_retains_sealed_bytes_identities_and_stdin_bindings() {
        let fixture = Fixture::new();
        for input in [None, Some(b"".as_slice()), Some(b"input\0\xff".as_slice())] {
            let mut hello = fixture.hello.clone();
            if input.is_some() {
                hello.requested_command.as_mut().unwrap().stdin_policy = "sha256".into();
                hello.original_intent.as_mut().unwrap().command.stdin_policy = "sha256".into();
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
            for snapshot in [snapshots.executable.sealed(), snapshots.stdin.as_ref()]
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
                csr.warrant().command.executable_trust,
                Some(sigrund_core::executable::ExecutableTrust::DigestMemfd {
                    sha256: sigrund_core::crypto::sha256_hex(&bytes)
                })
            );
            std::fs::write(&source, &original).unwrap();
            drop(request);
            assert_eq!(fixture.budget.usage(1001), (0, 0));
        }
    }

    #[test]
    #[ignore = "requires root in the initial user namespace; included in the privileged Phase 1 gate"]
    fn final_authorization_rechecks_retained_policy_and_identity() {
        let mut fixture = Fixture::new();
        Arc::make_mut(&mut fixture.config)
            .mvp
            .as_mut()
            .unwrap()
            .approval_signer_id = "mandator-alice-yubikey".into();
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
                fixture.request(signed_hello(&canonical, "sigrun.warrant.v3", 7), None);
            prepare(&mut request, &fixture.context, &fixture.budget, 1001).unwrap();
            let prepared = request.prepared.as_mut().unwrap();
            match case {
                "valid" => (),
                "root_path" => prepared.root_path = "/different-root".into(),
                "root_inode" => prepared.root_identity.inode ^= 1,
                "root_device" => prepared.root_identity.device ^= 1,
                "signer" => {
                    let Document::Signed { signer_ids, .. } = &mut prepared.document else {
                        panic!()
                    };
                    *signer_ids = vec!["unconfigured".into()];
                }
                "cached_digest" => {
                    let Document::Signed { warrant, .. } = &mut prepared.document else {
                        panic!()
                    };
                    let mut changed = warrant.warrant().clone();
                    changed.command.executable_trust =
                        Some(sigrund_core::executable::ExecutableTrust::DigestMemfd {
                            sha256: "0".repeat(64),
                        });
                    crate::synchronize_test_intent(&mut changed);
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
                    crate::synchronize_test_intent(&mut changed);
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
        let mut request = fixture.request(signed_hello(&warrant, "sigrun.warrant.v3", 7), None);
        prepare(&mut request, &fixture.context, &fixture.budget, 1001).unwrap();
        assert!(
            matches!(&request.prepared.as_ref().unwrap().document, Document::Signed { signer_ids, .. } if signer_ids==&["mandator-alice-yubikey"])
        );
        drop(request);
        // A valid signature cannot establish a lease back to signing time.
        // Reject this before opening the source, independently of model policy.
        let mut ctime = warrant.warrant().clone();
        ctime.command.executable_trust = Some(sigrund_core::executable::ExecutableTrust::Ctime {
            device: "1".into(),
            inode: "1".into(),
            size: "1".into(),
            ctime_sec: 1,
            ctime_nsec: 0,
        });
        let ctime = CanonicalWarrant::new(ctime).unwrap();
        let mut request = fixture.request(signed_hello(&ctime, "sigrun.warrant.v3", 7), None);
        let error = prepare(&mut request, &fixture.context, &fixture.budget, 1001).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("live online approval read lease")
        );
        assert!(request.snapshots.is_none());
        // Digest failures happen after authenticated candidate selection.
        for stdin in [false, true] {
            let mut w = warrant.warrant().clone();
            if stdin {
                w.command.stdin_policy = "sha256".into();
                w.command.stdin_sha256 = Some("0".repeat(64));
            } else {
                w.command.executable_trust =
                    Some(sigrund_core::executable::ExecutableTrust::DigestMemfd {
                        sha256: "0".repeat(64),
                    });
            }
            crate::synchronize_test_intent(&mut w);
            let w = CanonicalWarrant::new(w).unwrap();
            let mut request = fixture.request(
                signed_hello(&w, "sigrun.warrant.v3", 7),
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
        bad.push(signed_hello(&warrant, "sigrun.warrant.v3", 8));
        for field in ["host", "uid", "gid", "target", "ttl", "capability", "root"] {
            let mut w = warrant.warrant().clone();
            match field {
                "host" => w.host_id = format!("sigrun-host:sha256:{}", "b".repeat(64)),
                "uid" => w.requester_uid = 1002,
                "gid" => w.requester_gid = 1002,
                "target" => w.execution_context.target_uid = 44,
                "ttl" => w.policy.not_after = Some(w.policy.not_before + 3601),
                "capability" => {
                    w.execution_context.capabilities = vec!["CAP_SYS_ADMIN".into()];
                    w.execution_context.post_exec_capabilities =
                        Some(sigrund_core::executable::CapabilitySets::ordinary(
                            &w.execution_context.capabilities,
                        ));
                }
                "root" => w.command.executable_path = "/outside/program".into(),
                _ => unreachable!(),
            }
            crate::synchronize_test_intent(&mut w);
            bad.push(signed_hello(
                &CanonicalWarrant::new(w).unwrap(),
                "sigrun.warrant.v3",
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

#[cfg(test)]
mod full_account_tests {
    use super::*;
    #[test]
    fn full_named_account_must_match_host_credentials() {
        let mut w = Csr::parse(include_bytes!(
            "../../sigrund-core/tests/fixtures/v3-host/warrant.json"
        ))
        .unwrap()
        .warrant()
        .clone();
        w.intent.account = sigrund_core::host::Account::Name {
            name: "root".into(),
        };
        use sigrund_core::host::Record;
        w.intent_sha256 = w.intent.sha256().unwrap();
        assert!(verify_full_account(&Csr::new(w.clone()).unwrap()).is_err());
        let (uid, gid, groups) = crate::accounts::resolve(&w.intent.account).unwrap();
        w.execution_context.target_uid = uid;
        w.execution_context.target_gid = gid;
        w.execution_context.supplementary_gids = groups;
        verify_full_account(&Csr::new(w).unwrap()).unwrap();
    }
}
