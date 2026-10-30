//! One bounded, off-loop SQLite/audit owner. Request leases keep their original
//! worker/FD/RAM reservation until the original worker actually disposes them.
use crate::{
    authorization::{self, Denial},
    preparation::Context,
    startup::StartupResources,
    workers::RequestLease,
};
use sigrund_core::{
    crypto::sha256_hex,
    lifecycle::{Lifecycle, Phase},
    state::{AuthorizationRequest, AuthorizationResult, GrantMode},
};
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::Ordering,
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) struct AuthorizationTask {
    pub token: u64,
    pub exec_id: String,
    pub gid: u32,
    pub lifecycle: Arc<Lifecycle>,
    pub lease: RequestLease,
    pub control: OwnedFd,
}
pub(crate) enum Work {
    Authorize(AuthorizationTask),
    Event {
        token: u64,
        event_type: &'static str,
        fields: serde_json::Value,
        limit: usize,
    },
}
pub(crate) enum Completion {
    Reserve {
        token: u64,
        permit: SyncSender<bool>,
    },
    Finished {
        token: u64,
        lease: RequestLease,
        denial: Denial,
    },
    Audited {
        token: u64,
    },
    Fatal(String),
}
pub(crate) struct Sequencer {
    tasks: SyncSender<Work>,
    completions: Receiver<Completion>,
    wake: Arc<OwnedFd>,
}
impl Sequencer {
    pub fn new(
        mut resources: StartupResources,
        context: Arc<Context>,
        capacity: usize,
    ) -> io::Result<Self> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let wake = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
        let (tasks, receiver) = sync_channel::<Work>(capacity);
        let (completed, completions) = sync_channel(capacity * 2);
        let thread_wake = wake.clone();
        std::thread::Builder::new()
            .name("authorization-audit".into())
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    for task in receiver {
                        let result = match task {
                            Work::Authorize(task) => {
                                let outcome = authorize(
                                    &mut resources,
                                    &context,
                                    &task,
                                    &completed,
                                    &thread_wake,
                                );
                                // A disconnected coordinator may have marked
                                // cancellation during COMMIT's reservation.
                                // Once its result and audit are reconciled,
                                // finish that transition even without a live
                                // connection to consume the completion.
                                if task.lifecycle.cancelled.load(Ordering::Acquire) {
                                    task.lifecycle.cancel();
                                }
                                match outcome {
                                    Ok(denial) => notify(
                                        &completed,
                                        &thread_wake,
                                        Completion::Finished {
                                            token: task.token,
                                            lease: task.lease,
                                            denial,
                                        },
                                    ),
                                    Err(error) => {
                                        notify(&completed, &thread_wake, Completion::Fatal(error));
                                        false
                                    }
                                }
                            }
                            Work::Event {
                                token,
                                event_type,
                                fields,
                                limit,
                            } => match resources.audit.append_event(event_type, fields, limit) {
                                Ok(_) => {
                                    notify(&completed, &thread_wake, Completion::Audited { token })
                                }
                                Err(error) => {
                                    notify(
                                        &completed,
                                        &thread_wake,
                                        Completion::Fatal(error.to_string()),
                                    );
                                    false
                                }
                            },
                        };
                        if !result {
                            break;
                        }
                    }
                }));
                if result.is_err() {
                    notify(
                        &completed,
                        &thread_wake,
                        Completion::Fatal(
                            "durable executor panicked; reconciliation required".into(),
                        ),
                    );
                }
            })?;
        Ok(Self {
            tasks,
            completions,
            wake,
        })
    }
    pub fn fd(&self) -> i32 {
        self.wake.as_raw_fd()
    }
    pub fn sender(&self) -> SyncSender<Work> {
        self.tasks.clone()
    }
    pub fn drain(&self) -> Vec<Completion> {
        let mut value = 0u64;
        loop {
            if unsafe { libc::read(self.fd(), (&mut value as *mut u64).cast(), 8) } >= 0
                || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
            {
                break;
            }
        }
        self.completions.try_iter().collect()
    }
}
fn notify(sender: &SyncSender<Completion>, wake: &OwnedFd, completion: Completion) -> bool {
    if sender.send(completion).is_err() {
        return false;
    }
    let one = 1u64;
    loop {
        if unsafe { libc::write(wake.as_raw_fd(), (&one as *const u64).cast(), 8) } >= 0
            || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            break;
        }
    }
    true
}
/// Peeking creates no userspace descriptors, even for unexpected rights.
/// A stdio client must stay quiet after its hello until the decision.
pub(crate) fn connection_live(fd: i32) -> bool {
    let mut byte = 0u8;
    loop {
        let n = unsafe {
            libc::recv(
                fd,
                (&mut byte as *mut u8).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if n >= 0 {
            return false;
        }
        match io::Error::last_os_error().kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => return true,
            _ => return false,
        }
    }
}
fn realtime() -> sigrund_core::Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| d.as_secs().try_into().ok())
        .ok_or_else(|| sigrund_core::CoreError::Value("invalid realtime clock".into()))
}
fn authorize(
    resources: &mut StartupResources,
    context: &Context,
    task: &AuthorizationTask,
    completed: &SyncSender<Completion>,
    wake: &OwnedFd,
) -> std::result::Result<Denial, String> {
    let request = task.lease.request();
    let verified = match authorization::verify(request, context, task.gid) {
        Ok(verified) => verified,
        Err(denial) => {
            resources
                .audit
                .append_event(
                    "AUTH_REJECTED",
                    serde_json::json!({"exec_id":task.exec_id,
                "requester_uid":request.requester_uid, "status":denial.status}),
                    request.policy.audit_record_max_bytes as usize,
                )
                .map_err(|e| e.to_string())?;
            return Ok(denial);
        }
    };
    let w = verified.warrant.warrant();
    let candidates: Vec<_> = verified.signer_ids.iter().map(String::as_str).collect();
    let (result, signer_id) = resources
        .store
        .authorize_candidates_guarded(
            AuthorizationRequest {
                grant_id: &w.grant_id,
                payload: verified.warrant.as_bytes(),
                signer_id: candidates[0],
                requester_uid: request.requester_uid,
                mode: match w.policy.mode.as_str() {
                    "one_time" => GrantMode::OneTime,
                    "time_range" => GrantMode::TimeRange,
                    "permanent" => GrantMode::Permanent,
                    _ => return Err("unsupported grant mode".into()),
                },
                not_before: w.policy.not_before,
                not_after: w.policy.not_after,
                now: 0,
            },
            &candidates[1..],
            realtime,
            || {
                let (permit, reply) = sync_channel(1);
                if !notify(
                    completed,
                    wake,
                    Completion::Reserve {
                        token: task.token,
                        permit,
                    },
                ) {
                    return Ok(false);
                }
                Ok(reply.recv().unwrap_or(false))
            },
            || {
                Ok(request.check().is_ok()
                    && !task.lifecycle.cancelled.load(Ordering::Acquire)
                    && connection_live(task.control.as_raw_fd()))
            },
        )
        .map_err(|e| format!("authorization database failed; reconciliation required: {e}"))?;
    let limit = request.policy.audit_record_max_bytes as usize;
    let fields = serde_json::json!({"exec_id":task.exec_id, "grant_id":w.grant_id,
        "payload_sha256":sha256_hex(verified.warrant.as_bytes()), "signer_id":signer_id,
        "policy_mode":w.policy.mode,"not_before":w.policy.not_before,"not_after":w.policy.not_after,
        "requester_uid":w.requester_uid,"requester_gid":w.requester_gid,
        "target_uid":w.execution_context.target_uid,"target_gid":w.execution_context.target_gid,
        "executable_sha256":w.command.executable_sha256,
        "stdin_sha256":w.command.stdin_sha256,
        "tty_mode":w.command.tty_mode,"environment_entries":verified.envp.len()});
    if result == AuthorizationResult::Allowed {
        if !task
            .lifecycle
            .transition(Phase::Committing, Phase::Committed)
        {
            return Err("lost commit reservation after durable consumption".into());
        }
        resources
            .audit
            .append_event("AUTH_COMMIT", fields.clone(), limit)
            .map_err(|e| e.to_string())?;
        let cancelled = request.check().is_err()
            || task.lifecycle.cancelled.load(Ordering::Acquire)
            || !connection_live(task.control.as_raw_fd());
        let now = realtime().map_err(|e| e.to_string())?;
        let expired = now < w.policy.not_before || w.policy.not_after.is_none_or(|end| now > end);
        let denial = if cancelled {
            Denial::new(
                "REQUEST_TIMEOUT",
                "Authorization committed before cancellation; one-time grant remains consumed",
            )
        } else if expired {
            Denial::new(
                "EXPIRED_OR_NOT_YET_VALID",
                "Warrant expired after authorization commit; one-time grant remains consumed",
            )
        } else {
            Denial::new(
                "SPAWN_FAILED",
                "Authorization committed; execution requires Phase 5; one-time grant remains consumed",
            )
        };
        let mut fields = fields;
        fields["status"] = denial.status.into();
        fields["reason"] = denial.message.into();
        resources
            .audit
            .append_event("AUTH_ABORTED_POST_COMMIT", fields, limit)
            .map_err(|e| e.to_string())?;
        Ok(denial)
    } else {
        if task.lifecycle.state().0 == Phase::Committing && !task.lifecycle.rolled_back_commit() {
            return Err("lost rollback reservation".into());
        }
        let denial = match result {
            AuthorizationResult::ExpiredOrNotYetValid => Denial::new(
                "EXPIRED_OR_NOT_YET_VALID",
                "warrant expired or not yet valid",
            ),
            AuthorizationResult::Revoked => Denial::new("REVOKED", "warrant is revoked"),
            AuthorizationResult::ReplayDetected => Denial::new(
                "REPLAY_DETECTED",
                "one-time warrant has already been consumed",
            ),
            AuthorizationResult::Cancelled => {
                Denial::new("REQUEST_TIMEOUT", "authorization cancelled before commit")
            }
            AuthorizationResult::Allowed => unreachable!(),
        };
        let mut fields = fields;
        fields["status"] = denial.status.into();
        resources
            .audit
            .append_event("AUTH_REJECTED", fields, limit)
            .map_err(|e| e.to_string())?;
        Ok(denial)
    }
}
