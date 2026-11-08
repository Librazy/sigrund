//! Thin process-environment preparation and the Phase 2 authorization boundary.
use crate::{
    destination_helper::{self, Evidence},
    preparation::{self, Context, Document, FileIdentity, Pending, Prepared},
    snapshot::{SealedSnapshot, SnapshotBudget},
    target_registry::TargetLease,
    workers::{MeasuredSnapshots, ValidatedRequest},
};
use sigrund_core::{
    config::SignerConfig,
    crypto::{new_uuidv7, sha256_hex},
    host::Selector,
    host_budget::Reservation,
    namespace::ProcessReview,
    warrant::{Csr, CsrIdentity, SnapshotDigests},
};
use std::{
    fs::File,
    io,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) struct ProcessState {
    pub final_verified: bool,
    pub directory: File,
    pub cwd: File,
    pub evidence: Evidence,
    pub review: Option<ProcessReview>,
    pub lease: TargetLease,
    _resources: Reservation,
}
fn invalid(message: impl Into<String>) -> io::Error {
    preparation::fail("POLICY_VIOLATION", message)
}
pub(crate) fn prepare(
    request: &mut ValidatedRequest,
    context: &Context,
    budget: &SnapshotBudget,
    gid: u32,
    stdin: Option<SealedSnapshot>,
) -> io::Result<()> {
    if request.hello.mode != "thin_csr" {
        return Err(invalid("cross-domain requests require thin intent"));
    }
    let original = request.hello.original_intent().map_err(io::Error::other)?;
    if !matches!(
        original.target,
        Selector::Registered { .. } | Selector::Process { .. }
    ) {
        return Err(invalid("unsupported process target selector"));
    }
    let registry = context
        .targets
        .as_ref()
        .ok_or_else(|| invalid("target registry unavailable"))?;
    let lease = registry.lease(&original.target, request.requester_uid, true)?;
    if original.security_profile != lease.constraints().profile_id
        || original.execution_context.capabilities != lease.constraints().capabilities
    {
        return Err(invalid(
            "requested profile differs from target registration",
        ));
    }
    let signer = context
        .signers
        .signers
        .iter()
        .find(|s| {
            request
                .policy
                .mvp
                .as_ref()
                .is_some_and(|m| m.approval_signer_id == s.signer_id)
        })
        .ok_or_else(|| invalid("approval signer unavailable"))?;
    let numeric = if let sigrund_core::host::Account::Numeric {
        uid,
        gid,
        supplementary_gids,
    } = &original.account
    {
        Some(
            lease
                .acquisition()
                .compose_credentials(*uid, *gid, supplementary_gids.clone())
                .map_err(io::Error::other)?,
        )
    } else {
        None
    };
    scoped_policy(request, context, signer, &lease, numeric.as_ref())?;
    let result = destination_helper::prepare(
        &lease,
        original.account.clone(),
        request.policy.csr_allowed_executable_dirs.clone(),
        PathBuf::from(&original.command.executable_path),
        PathBuf::from(&original.command.cwd),
        |credentials| scoped_policy(request, context, signer, &lease, Some(credentials)),
        || request.check(),
    )?;
    let credentials = &result.evidence.credentials;
    request.hello.requested_execution_context = Some(original.execution_context.resolve(
        credentials.uid,
        credentials.gid,
        credentials.groups.clone(),
    ));
    let selected = sigrund_core::paths::select_root(
        std::path::Path::new(&original.command.executable_path),
        &request.policy.csr_allowed_executable_dirs,
    )
    .map_err(io::Error::other)?;
    let root_identity = FileIdentity::read(&result.directory)?;
    let source_identity = FileIdentity::read(&result.source)?;
    request.process = Some(ProcessState {
        final_verified: false,
        directory: result.directory,
        cwd: result.cwd,
        evidence: result.evidence,
        review: None,
        lease,
        _resources: result.resources,
    });
    let model = request
        .process
        .as_ref()
        .expect("process owner")
        .lease
        .constraints()
        .executable_model;
    if !request.policy.executable_trust_models.contains(&model) {
        return Err(invalid(
            "destination executable model disabled by daemon policy",
        ));
    }
    let mut policy = (*request.policy).clone();
    policy.executable_trust_models = vec![model];
    policy.admin_trusted_composefs_mounts.clear();
    let numeric = &request.process.as_ref().unwrap().evidence.credentials;
    let mut kernel_context = request.hello.requested_execution_context.clone().unwrap();
    kernel_context.target_uid = numeric.host_uid;
    kernel_context.target_gid = numeric.host_gid;
    kernel_context.supplementary_gids = numeric.host_groups.clone();
    let executable = crate::executable::prepare(
        result.source,
        crate::executable::Selection {
            signed: None,
            context: &kernel_context,
            allow_file_capabilities: false,
            trace_available: crate::execution::trace_available(),
        },
        budget,
        request.requester_uid,
        &policy,
        || request.check(),
    )?;
    request.snapshots = Some(MeasuredSnapshots { executable, stdin });
    request.pending_preparation = Some(Pending {
        signed: None,
        root_path: selected.root,
        root_identity,
        source_identity,
        null_stdin: None,
    });
    if request
        .snapshots
        .as_ref()
        .unwrap()
        .executable
        .needs_digest()
    {
        return Ok(());
    }
    finish(request, context, gid)
}

pub(crate) fn policy(
    request: &ValidatedRequest,
    context: &Context,
    signer: &SignerConfig,
) -> io::Result<()> {
    let state = request
        .process
        .as_ref()
        .ok_or_else(|| invalid("missing process owner"))?;
    scoped_policy(
        request,
        context,
        signer,
        &state.lease,
        Some(&state.evidence.credentials),
    )
}
fn scoped_policy(
    request: &ValidatedRequest,
    context: &Context,
    signer: &SignerConfig,
    lease: &TargetLease,
    credentials: Option<&crate::destination::Credentials>,
) -> io::Result<()> {
    let intent = request.hello.original_intent().map_err(io::Error::other)?;
    let constraints = lease.constraints();
    let registration = lease.registration();
    let scope = format!("registered:{}", registration.id);
    let permits = |rule: &sigrund_core::namespace::ScopedRule| {
        rule.requester_uids.contains(&request.requester_uid)
            && rule.target_scope == scope
            && rule.profile_sha256 == registration.profile_sha256
            && (request.requester_uid == registration.owner_uid || rule.cross_owner)
            && credentials.is_none_or(|c| {
                rule.permits(
                    request.requester_uid,
                    &scope,
                    c.uid,
                    c.gid,
                    &c.groups,
                    &registration.profile_sha256,
                    registration.owner_uid,
                )
            })
    };
    if !request
        .policy
        .executable_trust_models
        .contains(&constraints.executable_model)
        || !request.policy.namespace_rules.iter().any(permits)
        || !signer.namespace_rules.iter().any(permits)
        || credentials.is_some_and(|c| c.host_uid == request.requester_uid)
        || !signer
            .allowed_requester_uids
            .contains(&request.requester_uid)
        || intent.security_profile != constraints.profile_id
        || intent.execution_context.capabilities != constraints.capabilities
        || !intent
            .execution_context
            .capabilities
            .iter()
            .all(|cap| signer.allowed_capabilities.contains(cap))
        || !signer.allowed_modes.contains(&intent.policy.mode)
        || intent.policy.ttl_secs > signer.max_ttl_secs
        || intent.policy.ttl_secs > request.policy.max_ttl_secs
        || intent.policy.ttl_secs > request.policy.max_onetime_window_secs
        || sigrund_core::paths::select_root(
            std::path::Path::new(&intent.command.executable_path),
            &signer.allowed_executable_dirs,
        )
        .is_err()
        || context.host_id.is_empty()
    {
        return Err(invalid(
            "destination request exceeds daemon or signer scope",
        ));
    }
    Ok(())
}

pub(crate) fn finish(
    request: &mut ValidatedRequest,
    context: &Context,
    gid: u32,
) -> io::Result<()> {
    request.check()?;
    let state = request
        .process
        .as_ref()
        .ok_or_else(|| invalid("missing process owner"))?;
    state.lease.revalidate()?;
    let mut review = ProcessReview {
        schema: "sigrund.process-review.v1".into(),
        exec_id: request.exec_id.clone(),
        csr_sha256: "00".repeat(32),
        acquisition: state.lease.acquisition().clone(),
        registration: state.lease.registration().clone(),
        constraints: state.lease.constraints().clone(),
        executable_roots: state.lease.executable_roots(),
        prepared_cwd: state.evidence.cwd.clone(),
        prepared_executable: state.evidence.executable.clone(),
    };
    let snapshots = request
        .snapshots
        .as_ref()
        .ok_or_else(|| invalid("missing destination snapshots"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    let csr = Csr::from_unsigned_binding(
        &request.hello,
        CsrIdentity {
            grant_id: new_uuidv7().to_string(),
            host_id: context.host_id.clone(),
            requester_uid: request.requester_uid,
            requester_gid: gid,
            now: i64::try_from(now).map_err(io::Error::other)?,
            binding: None,
        },
        SnapshotDigests {
            post_exec_capabilities: snapshots.executable.post_exec_capabilities.clone(),
            executable_sha256: snapshots.executable.sha256(),
            executable_trust: snapshots.executable.trust.clone(),
            stdin_sha256: snapshots.stdin.as_ref().map(|s| s.digest.sha256.clone()),
        },
        request.policy.max_ttl_secs,
        review.binding().map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)?;
    let mut warrant = csr.warrant().clone();
    warrant.request_origin = "daemon_expanded_thin".into();
    warrant.approval_exec_id = Some(request.exec_id.clone());
    let csr = Csr::new(warrant).map_err(io::Error::other)?;
    review.csr_sha256 = sha256_hex(csr.as_bytes());
    review.verify_csr(&csr).map_err(io::Error::other)?;
    state.lease.revalidate()?;
    context
        .epoch
        .as_ref()
        .ok_or_else(|| invalid("private epoch unavailable"))?
        .publish_process_review(&review, &csr)?;
    request.process.as_mut().unwrap().review = Some(review);
    let pending = request
        .pending_preparation
        .take()
        .ok_or_else(|| invalid("missing destination preparation"))?;
    request.prepared = Some(Prepared {
        document: Document::Unsigned(csr),
        root_path: pending.root_path,
        root_identity: pending.root_identity,
        source_identity: pending.source_identity,
        null_stdin: pending.null_stdin,
    });
    request.check()
}

/// A successful result proves final private authorization checks. The caller
/// still must enforce Phase 2's stop before consumption or public approval.
pub(crate) fn verify_final(request: &ValidatedRequest, context: &Context) -> io::Result<()> {
    request.check()?;
    let state = request
        .process
        .as_ref()
        .ok_or_else(|| invalid("missing process owner"))?;
    state.lease.revalidate()?;
    let prepared = request
        .prepared
        .as_ref()
        .ok_or_else(|| invalid("missing prepared process request"))?;
    let Document::Signed {
        warrant,
        signer_ids,
    } = &prepared.document
    else {
        return Err(invalid("missing approved process warrant"));
    };
    let csr = Csr::parse(warrant.as_bytes()).map_err(io::Error::other)?;
    state
        .review
        .as_ref()
        .ok_or_else(|| invalid("missing verified process review"))?
        .verify_csr(&csr)
        .map_err(io::Error::other)?;
    if warrant.warrant().host_id != context.host_id
        || warrant.warrant().requester_uid != request.requester_uid
        || warrant.warrant().requester_gid != request.requester_gid
        || warrant.warrant().intent != request.hello.original_intent().map_err(io::Error::other)?
        || !signer_ids.iter().any(|id| {
            context
                .signers
                .signers
                .iter()
                .any(|signer| signer.signer_id == *id && policy(request, context, signer).is_ok())
        })
    {
        return Err(invalid("process approval no longer satisfies policy"));
    }
    let snapshots = request
        .snapshots
        .as_ref()
        .ok_or_else(|| invalid("missing destination snapshots"))?;
    let root_identity = destination_helper::identity(&state.directory)?;
    let roots = &state.review.as_ref().unwrap().executable_roots;
    if roots.get(
        prepared
            .root_path
            .to_str()
            .ok_or_else(|| invalid("non-UTF8 executable root"))?,
    ) != Some(&root_identity)
    {
        return Err(invalid(
            "prepared executable root differs from signed process context",
        ));
    }
    if !snapshots
        .executable
        .matches_command(&warrant.warrant().command)
        || destination_helper::identity(&state.cwd)? != state.evidence.cwd
        || FileIdentity::read(&state.directory)?.inode != prepared.root_identity.inode
        || FileIdentity::read(&state.directory)?.device != prepared.root_identity.device
    {
        return Err(invalid("retained destination evidence differs"));
    }
    let w = warrant.warrant();
    if let Some(sealed) = snapshots.executable.sealed() {
        let hash = snapshots
            .executable
            .sha256()
            .ok_or_else(|| invalid("missing sealed executable digest"))?;
        crate::authorization::verify_snapshot(
            sealed,
            &hash,
            request.policy.max_executable_bytes,
            true,
            || request.check(),
        )?;
    } else {
        let mut kernel_context = w.execution_context.clone();
        kernel_context.target_uid = state.evidence.credentials.host_uid;
        kernel_context.target_gid = state.evidence.credentials.host_gid;
        kernel_context.supplementary_gids = state.evidence.credentials.host_groups.clone();
        snapshots
            .executable
            .verify_direct_checked(&kernel_context, || request.check())?;
    }
    match (&snapshots.stdin, &w.command.stdin_sha256) {
        (Some(input), Some(hash)) => crate::authorization::verify_snapshot(
            input,
            hash,
            request.policy.max_stdin_bytes,
            false,
            || request.check(),
        )?,
        (None, None) if w.command.stdin_policy == "null" => (),
        _ => return Err(invalid("retained stdin differs")),
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    if now < w.policy.not_before as u64 || w.policy.not_after.is_none_or(|end| now > end as u64) {
        return Err(invalid("process warrant expired"));
    }
    state.lease.revalidate()
}
