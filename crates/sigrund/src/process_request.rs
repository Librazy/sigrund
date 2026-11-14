//! Thin process-environment preparation and namespace authorization boundaries.
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
    namespace::{Contract, ProcessReview},
    warrant::{Csr, CsrIdentity, SnapshotDigests},
};
use std::{
    fs::File,
    io,
    os::fd::AsRawFd,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

/// Worker-produced verification of one exact signed warrant and retained owner.
/// Private fields prevent admission or sequencer code from fabricating proof.
pub(crate) struct VerifiedProcess {
    pub(crate) authorized: crate::authorization::Authorized,
    warrant_sha256: String,
    instance_id: String,
    registration_revision: Option<String>,
    _launcher_resources: Option<Reservation>,
}
impl VerifiedProcess {
    /// This check is deliberately free of destination filesystem I/O and helper
    /// exchanges. The sequencer may only inspect the retained lifecycle state.
    pub(crate) fn matches(&self, request: &ValidatedRequest) -> bool {
        let Some(state) = &request.process else {
            return false;
        };
        let Some(prepared) = &request.prepared else {
            return false;
        };
        let Document::Signed { warrant, .. } = &prepared.document else {
            return false;
        };
        let namespace_plan =
            !state.lease.constraints().executes() || state.lease.namespace_files().is_ok();
        namespace_plan
            && state.lease.check_lifecycle().is_ok()
            && self.warrant_sha256 == sha256_hex(warrant.as_bytes())
            && self.instance_id == state.lease.acquisition().instance_id
            && self.registration_revision.as_deref()
                == state
                    .lease
                    .registration_record()
                    .map(|registration| registration.revision.as_str())
    }
}

pub(crate) struct ProcessState {
    pub verified: Option<VerifiedProcess>,
    pub directory: File,
    pub cwd: File,
    pub evidence: Evidence,
    pub review: Option<ProcessReview>,
    pub lease: TargetLease,
    _resources: Reservation,
    _null_resources: Option<Reservation>,
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
    if matches!(original.target, Selector::Process { .. })
        && request.policy.namespace_profiles.iter().any(|profile| {
            profile.profile_id == original.security_profile
                && (profile.is_production() || profile.is_admin())
        })
    {
        return Err(invalid(
            "production namespace execution requires a registered or authenticated self target",
        ));
    }

    if request
        .policy
        .namespace_profiles
        .iter()
        .any(|profile| profile.profile_id == original.security_profile && profile.executes())
    {
        crate::access::domain()
            .map_err(|error| invalid(format!("namespace access domain: {error}")))?;
        if std::path::Path::new(&original.command.cwd).starts_with("/run") {
            return Err(invalid("cwd would be covered by the private runtime mount"));
        }
    }
    if !matches!(
        original.target,
        Selector::Registered { .. } | Selector::Process { .. } | Selector::Self_ {}
    ) {
        return Err(invalid("unsupported process target selector"));
    }
    let registry = context
        .targets
        .as_ref()
        .ok_or_else(|| invalid("target registry unavailable"))?;
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
    let lease = if matches!(original.target, Selector::Self_ {}) {
        let profile = request
            .policy
            .namespace_profiles
            .iter()
            .find(|profile| profile.profile_id == original.security_profile)
            .ok_or_else(|| invalid("self profile unavailable"))?
            .clone();
        if !profile.executes() {
            return Err(invalid("self requires an executable namespace profile"));
        }
        check_scoped_policy(
            request,
            context,
            signer,
            &profile,
            "self",
            request.requester_uid,
            None,
        )?;
        let source = request
            .source
            .as_ref()
            .ok_or_else(|| invalid("missing authenticated source socket"))?
            .clone();
        let _policy_guard = crate::lsm::for_profile(&profile)?;
        registry.capture_self(
            source,
            profile,
            request.deadline,
            request.cancelled.clone(),
            || request.check(),
        )?
    } else {
        registry.lease(&original.target, request.requester_uid, true)?
    };
    if original.security_profile != lease.constraints().profile_id
        || original.execution_context.capabilities != lease.constraints().capabilities
    {
        return Err(invalid("requested profile differs from target owner"));
    }
    if lease.constraints().is_admin() {
        let namespaces = lease.namespace_files()?;
        crate::execution::validate_admin_userns(
            namespaces
                .get(6)
                .ok_or_else(|| invalid("missing target user namespace"))?,
        )?;
    }
    // Different mapped workload UIDs do not exclude namespace-owner ptrace
    // authority. Until a workload LSM guard is qualified, reject that authority
    // before any destination account/path operation or private approval.
    if lease.constraints().schema == "sigrund.constraints.namespace-experimental.v1" {
        let namespaces = lease.namespace_files()?;
        let userns = namespaces
            .get(6)
            .ok_or_else(|| invalid("missing target user namespace"))?;
        let mut owner = u32::MAX;
        if unsafe { libc::ioctl(userns.as_raw_fd(), 0xb704, &mut owner) } != 0 {
            return Err(invalid("cannot establish target user namespace owner"));
        }
        reject_namespace_owner(request.requester_uid, owner, lease.owner_uid())?;
    }
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
    )
    .map_err(|error| invalid(format!("destination preparation: {error}")))?;
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
    let null_resources = if original.command.stdin_policy == "null" {
        Some(lease.reserve_resources(sigrund_core::host_budget::Charge {
            target_fds: 1,
            ..Default::default()
        })?)
    } else {
        None
    };
    request.process = Some(ProcessState {
        verified: None,
        directory: result.directory,
        cwd: result.cwd,
        evidence: result.evidence,
        review: None,
        lease,
        _resources: result.resources,
        _null_resources: null_resources,
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
    let selection = crate::executable::Selection {
        signed: None,
        context: &kernel_context,
        allow_file_capabilities: false,
        trace_available: crate::execution::trace_available(),
    };
    let lease = &request.process.as_ref().unwrap().lease;
    let executable =
        if lease.constraints().is_admin_direct() && crate::overlay::is_overlay(&result.source)? {
            let overlay = crate::overlay::Enrollment::discover(
                &result.source,
                std::path::Path::new(&original.command.executable_path),
                lease,
                &|| request.check(),
            )?;
            crate::executable::prepare_overlay(result.source, selection, &policy, overlay, || {
                request.check()
            })?
        } else {
            crate::executable::prepare(
                result.source,
                selection,
                budget,
                request.requester_uid,
                &policy,
                || request.check(),
            )?
        };
    request.snapshots = Some(MeasuredSnapshots { executable, stdin });
    request.pending_preparation = Some(Pending {
        signed: None,
        root_path: selected.root,
        root_identity,
        source_identity,
        null_stdin: preparation::null_stdin(&original.command.stdin_policy)?,
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
    check_scoped_policy(
        request,
        context,
        signer,
        lease.constraints(),
        &lease.scope(),
        lease.owner_uid(),
        credentials,
    )
}
fn check_scoped_policy(
    request: &ValidatedRequest,
    context: &Context,
    signer: &SignerConfig,
    constraints: &sigrund_core::namespace::Constraints,
    scope: &str,
    owner_uid: u32,
    credentials: Option<&crate::destination::Credentials>,
) -> io::Result<()> {
    let intent = request.hello.original_intent().map_err(io::Error::other)?;
    let profile_sha256 = constraints.sha256().map_err(io::Error::other)?;
    if let sigrund_core::host::Account::Numeric {
        uid,
        gid,
        supplementary_gids,
    } = &intent.account
    {
        constraints
            .validate_execution_credentials(*uid, *gid, supplementary_gids)
            .map_err(|error| invalid(error.to_string()))?;
    }
    if let Some(c) = credentials {
        constraints
            .validate_execution_credentials(c.uid, c.gid, &c.groups)
            .map_err(|error| invalid(error.to_string()))?;
    }
    let permits = |rule: &sigrund_core::namespace::ScopedRule| {
        rule.requester_uids.contains(&request.requester_uid)
            && rule.target_scope == scope
            && rule.profile_sha256 == profile_sha256
            && (request.requester_uid == owner_uid || rule.cross_owner)
            && (credentials.is_some()
                || match &intent.account {
                    sigrund_core::host::Account::Numeric {
                        uid,
                        gid,
                        supplementary_gids,
                    } => {
                        rule.target_uids.contains(uid)
                            && rule.target_gids.contains(gid)
                            && supplementary_gids
                                .iter()
                                .all(|gid| rule.supplementary_gids.contains(gid))
                    }
                    _ => true,
                })
            && credentials.is_none_or(|c| {
                rule.permits(
                    request.requester_uid,
                    scope,
                    c.uid,
                    c.gid,
                    &c.groups,
                    &profile_sha256,
                    owner_uid,
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
    if let Some(guard) = state.lease.policy_guard() {
        guard.verify_domain(&state.lease.constraints().selinux.context)?;
        let image = &request
            .snapshots
            .as_ref()
            .ok_or_else(|| invalid("missing executable"))?
            .executable;
        crate::lsm::image_label(image, state.lease.constraints(), true)
            .map_err(|error| invalid(format!("sealed executable SELinux label: {error}")))?;
    }
    let mut review = ProcessReview {
        schema: if state.lease.manager_evidence().is_some() {
            "sigrund.podman-review.v1"
        } else if state.lease.registration_record().is_some() {
            "sigrund.process-review.v1"
        } else {
            "sigrund.self-review.v1"
        }
        .into(),
        exec_id: request.exec_id.clone(),
        csr_sha256: "00".repeat(32),
        acquisition: state.lease.acquisition().clone(),
        authenticated_source: state.lease.authenticated_source().cloned(),
        manager: state.lease.manager_evidence().cloned(),
        registration: state.lease.registration_record().cloned(),
        constraints: state.lease.constraints().clone(),
        executable_roots: state.lease.executable_roots(),
        prepared_cwd: state.evidence.cwd.clone(),
        prepared_executable: state.evidence.executable.clone(),
        executable_storage: if state.lease.constraints().is_admin_direct() {
            Some(
                request
                    .snapshots
                    .as_ref()
                    .and_then(|s| s.executable.storage_evidence())
                    .cloned()
                    .unwrap_or_else(|| sigrund_core::namespace::ExecutableStorage {
                        kind: "local_filesystem".into(),
                        mount_id: state.evidence.executable.mount_id.clone(),
                        layout_sha256: sha256_hex(b"sigrund.native-direct-filesystem.v1"),
                        backing: state.evidence.executable.clone(),
                        administrator_maintained: false,
                    }),
            )
        } else {
            None
        },
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
/// still must enforce the preview stop before consumption or public approval.
pub(crate) fn verify_final(
    request: &ValidatedRequest,
    context: &Context,
) -> io::Result<VerifiedProcess> {
    request.check()?;
    let state = request
        .process
        .as_ref()
        .ok_or_else(|| invalid("missing process owner"))?;
    state.lease.revalidate()?;
    if state.lease.constraints().executes() {
        crate::access::domain()?;
        use std::os::fd::AsRawFd;
        let mut stat = unsafe { std::mem::zeroed::<libc::statx>() };
        if unsafe {
            libc::statx(
                state.lease.root().as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                libc::STATX_BASIC_STATS,
                &mut stat,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let flag = libc::STATX_ATTR_MOUNT_ROOT as u64;
        if stat.stx_attributes_mask & flag == 0 || stat.stx_attributes & flag == 0 {
            return Err(invalid("namespace execution requires a mount-point root"));
        }
    }
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
    match (
        w.command.stdin_policy.as_str(),
        &snapshots.stdin,
        &w.command.stdin_sha256,
        &prepared.null_stdin,
    ) {
        ("sha256", Some(input), Some(hash), None) => crate::authorization::verify_snapshot(
            input,
            hash,
            request.policy.max_stdin_bytes,
            false,
            || request.check(),
        )?,
        ("null", None, None, Some(fd)) => preparation::verify_null_stdin(fd)?,
        _ => return Err(invalid("retained stdin differs")),
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    if now < w.policy.not_before as u64 || w.policy.not_after.is_none_or(|end| now > end as u64) {
        return Err(invalid("process warrant expired"));
    }
    if state.lease.constraints().is_production() {
        crate::lsm::image_label(&snapshots.executable, state.lease.constraints(), false)?;
    }
    state.lease.revalidate()?;
    request.check()?;
    let mut environment = w.execution_context.env_exact.clone();
    for (name, value) in &request.hello.caller_env {
        if environment.insert(name.clone(), value.clone()).is_some() {
            return Err(invalid("caller environment overlaps exact environment"));
        }
    }
    let envp = environment
        .iter()
        .map(|(name, value)| {
            std::ffi::CString::new(format!("{name}={value}")).map_err(io::Error::other)
        })
        .collect::<io::Result<Vec<_>>>()?;
    let signer_ids =
        signer_ids
            .iter()
            .filter(|id| {
                context.signers.signers.iter().any(|signer| {
                    signer.signer_id == **id && policy(request, context, signer).is_ok()
                })
            })
            .cloned()
            .collect();
    let launcher_resources = if state.lease.constraints().executes() {
        state.lease.namespace_files()?;
        Some(
            state
                .lease
                .reserve_resources(sigrund_core::host_budget::Charge {
                    helpers: 1,
                    ..Default::default()
                })?,
        )
    } else {
        None
    };
    Ok(VerifiedProcess {
        authorized: crate::authorization::Authorized {
            warrant: warrant.clone(),
            signer_ids,
            envp,
        },
        warrant_sha256: sha256_hex(warrant.as_bytes()),
        instance_id: state.lease.acquisition().instance_id.clone(),
        registration_revision: state
            .lease
            .registration_record()
            .map(|registration| registration.revision.clone()),
        _launcher_resources: launcher_resources,
    })
}

/// Runs on the bounded job worker while the actual final child is at exec stop.
pub(crate) fn verify_execution(
    request: &ValidatedRequest,
    pid: i32,
    cgroup: &crate::startup::JobCgroup,
    check: impl Fn() -> io::Result<()>,
) -> io::Result<serde_json::Value> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    };
    let state = request
        .process
        .as_ref()
        .ok_or_else(|| invalid("missing namespace owner"))?;
    state.lease.revalidate()?;
    let acquisition = state.lease.acquisition();
    let mut observed = std::collections::BTreeMap::new();
    for name in ["cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"] {
        check()?;
        let file = File::open(format!("/proc/{pid}/ns/{name}"))?;
        let metadata = file.metadata()?;
        let expected = &acquisition.namespaces[name];
        let equal = metadata.dev().to_string() == expected.device
            && metadata.ino().to_string() == expected.inode;
        if equal == matches!(name, "mnt" | "cgroup") {
            return Err(invalid("final child namespace differs from approved plan"));
        }
        if matches!(name, "mnt" | "cgroup") {
            let fd = unsafe { libc::ioctl(file.as_raw_fd(), 0xb701) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let owner = unsafe { File::from_raw_fd(fd) }.metadata()?;
            let user = &acquisition.namespaces["user"];
            if owner.dev().to_string() != user.device || owner.ino().to_string() != user.inode {
                return Err(invalid("private namespace has the wrong owner"));
            }
        }
        observed.insert(name, serde_json::json!({"device":metadata.dev().to_string(),"inode":metadata.ino().to_string()}));
    }
    let pin = |suffix: &str| -> io::Result<File> {
        let path =
            std::ffi::CString::new(format!("/proc/{pid}/{suffix}")).map_err(io::Error::other)?;
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    };
    let root = destination_helper::identity(&pin("root")?)?;
    let cwd = destination_helper::identity(&pin("cwd")?)?;
    if root.device != acquisition.root.device
        || root.inode != acquisition.root.inode
        || root.mount_id == acquisition.root.mount_id
        || cwd.device != state.evidence.cwd.device
        || cwd.inode != state.evidence.cwd.inode
        || cwd.mount_id == state.evidence.cwd.mount_id
    {
        return Err(invalid(
            "final child root or cwd differs from private pinned tree",
        ));
    }
    if !cgroup.contains_pid(pid)? {
        return Err(invalid("final child escaped job placement"));
    }
    // Before loader instructions, every setup-only descriptor must have closed.
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        let name = entry?.file_name();
        if !matches!(name.to_str(), Some("0" | "1" | "2")) {
            return Err(invalid("final child retained a setup descriptor"));
        }
    }
    // Every exposed cgroup mount must be recursively private and restrictive.
    use std::io::Read;
    let mut mounts = String::new();
    File::open(format!("/proc/{pid}/mountinfo"))?
        .take(1_048_577)
        .read_to_string(&mut mounts)?;
    if mounts.len() > 1_048_576 {
        return Err(invalid("oversized child mount table"));
    }
    let run = destination_helper::identity(&pin("root/run")?)?;
    let mut private_run = false;
    for line in mounts.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let separator = fields
            .iter()
            .position(|field| *field == "-")
            .ok_or_else(|| invalid("invalid child mount table"))?;
        if separator < 6 || fields.len() < separator + 4 {
            return Err(invalid("invalid child mount fields"));
        }
        if fields[6..separator].iter().any(|tag| {
            tag.starts_with("shared:")
                || tag.starts_with("master:")
                || tag.starts_with("propagate_from:")
        }) {
            return Err(invalid("child mount propagation is not private"));
        }
        // mountinfo also lists a covered host /run mount. Verify the mount
        // actually visible through the stopped child's root, not that shadow.
        if fields[0] == run.mount_id {
            let flags: Vec<_> = fields[5].split(',').collect();
            if fields[4] != "/run"
                || fields[separator + 1] != "tmpfs"
                || ["nosuid", "nodev", "noexec"]
                    .iter()
                    .any(|flag| !flags.contains(flag))
            {
                return Err(invalid("child private run mount differs from setup"));
            }
            private_run = true;
        }
        if matches!(fields[separator + 1], "cgroup" | "cgroup2") {
            // The trusted launcher mounts a fresh, empty tmpfs at /run after
            // cloning the private tree. Distrobox's /run/host cgroup aliases
            // remain listed even though that mount hides them. The visible
            // /run mount is independently verified above and required below;
            // cwd and setup FD checks exclude retained access beneath it.
            if fields[4] == "/run" || fields[4].starts_with("/run/") {
                continue;
            }
            // A runtime can also mount its delegated cgroup over an inherited
            // mount at the same path. Only the object visible to this child
            // must carry the restrictions applied by the launcher.
            if fields[4] == "/sys/fs/cgroup"
                && fields[0] != destination_helper::identity(&pin("root/sys/fs/cgroup")?)?.mount_id
            {
                continue;
            }
            let flags: Vec<_> = fields[5].split(',').collect();
            if ["ro", "nosuid", "nodev", "noexec"]
                .iter()
                .any(|flag| !flags.contains(flag))
            {
                return Err(invalid("child cgroup mount is insufficiently restricted"));
            }
        }
    }
    if !private_run {
        return Err(invalid("child private run mount is missing"));
    }
    let mut status = String::new();
    File::open(format!("/proc/{pid}/status"))?
        .take(65537)
        .read_to_string(&mut status)?;
    let production = state.lease.constraints().is_production();
    let seccomp = if production { "2" } else { "0" };
    if status.len() > 65536
        || !status.lines().any(|line| {
            line.strip_prefix("Seccomp:")
                .is_some_and(|value| value.trim() == seccomp)
        })
        || (production
            && !status.lines().any(|line| {
                line.strip_prefix("Seccomp_filters:")
                    .is_some_and(|value| value.trim() == "1")
            }))
    {
        return Err(invalid(
            "final child seccomp state differs from the approved profile",
        ));
    }
    let mut label = String::new();
    let lsm = match File::open(format!("/proc/{pid}/attr/current"))
        .and_then(|file| file.take(4097).read_to_string(&mut label))
    {
        Ok(_) if label.len() <= 4096 => {
            serde_json::json!({"state":"observed", "context":label.trim_end_matches(['\0', '\n'])})
        }
        Ok(_) => return Err(invalid("oversized observed LSM context")),
        Err(error) => serde_json::json!({"state":"unreadable", "errno":error.raw_os_error()}),
    };
    if state.lease.constraints().is_admin()
        && crate::lsm::producer_active()
        && lsm.get("context").and_then(|value| value.as_str())
            != Some(crate::lsm::HOST_WORKLOAD_CONTEXT)
    {
        return Err(invalid(
            "admin workload did not enter the host workload SELinux context",
        ));
    }
    if let Some(guard) = state.lease.policy_guard() {
        if lsm.get("context").and_then(|value| value.as_str())
            != Some(state.lease.constraints().selinux.context.as_str())
        {
            return Err(invalid(
                "actual workload SELinux context differs from the approved profile",
            ));
        }
        guard.verify_domain(&state.lease.constraints().selinux.context)?;
    }
    state.lease.revalidate()?;
    check()?;
    Ok(
        serde_json::json!({"child_pid":pid,"namespaces":observed,"root":root,"cwd":cwd,"host_credentials":state.evidence.credentials,"job_placement_verified":true,"setup_descriptors_closed":true,"private_run_verified":true,"seccomp":if production {2} else {0},"exact_seccomp_program_verified":production,"ambient_lsm":lsm,"selinux_policy_token":state.lease.policy_guard().map(|guard|guard.token())}),
    )
}

fn reject_namespace_owner(
    requester: u32,
    namespace_owner: u32,
    declared_owner: u32,
) -> io::Result<()> {
    // Host root is the trusted administrative authority, outside requester
    // isolation. All nonroot requesters need an independently verified guard.
    if namespace_owner == u32::MAX
        || (requester != 0 && (requester == namespace_owner || requester == declared_owner))
    {
        return Err(invalid(
            "requester namespace-owner injection authority is not confined",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod injection_tests {
    use super::reject_namespace_owner;
    #[test]
    fn different_workload_uid_does_not_remove_namespace_owner_authority() {
        assert!(reject_namespace_owner(1000, 1000, 2000).is_err());
        assert!(reject_namespace_owner(1000, 2000, 1000).is_err());
        assert!(reject_namespace_owner(1000, u32::MAX, 2000).is_err());
        assert!(reject_namespace_owner(3000, 1000, 2000).is_ok());
        assert!(reject_namespace_owner(0, 1000, 2000).is_ok());
    }
}
