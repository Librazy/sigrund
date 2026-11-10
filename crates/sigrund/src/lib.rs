pub mod access;
pub mod accounts;
mod admission;
pub mod approver;
mod authorization;
mod cgroup;
pub mod cli;
pub mod client;
mod composefs;
mod context;
mod ctime_guard;
pub mod daemon;
pub mod executable;
pub mod execution;
pub mod host_registry;
pub mod host_target;
mod jobs;
pub mod linux;
mod lsm;
pub mod memfd;
mod preparation;
pub mod reaper;
mod runtime;
mod sequencer;
mod service;
pub mod snapshot;
mod socket_disposal;
pub mod startup;
mod storage;
pub mod transport;
pub mod warrant_tools;
mod workers;

#[cfg(test)]
pub(crate) fn synchronize_test_intent(w: &mut sigrund_core::warrant::Warrant) {
    use sigrund_core::host::Record;
    let context = &w.execution_context;
    w.intent.command = w.command.requested();
    w.intent.execution_context = sigrund_core::v3::IntentContext {
        capabilities: context.capabilities.clone(),
        env_exact: context.env_exact.clone(),
        caller_env_allowlist: context.caller_env_allowlist.clone(),
        umask: context.umask,
    };
    w.intent.account = sigrund_core::host::Account::Numeric {
        uid: context.target_uid,
        gid: context.target_gid,
        supplementary_gids: context.supplementary_gids.clone(),
    };
    w.intent.policy = sigrund_core::protocol::RequestedPolicy {
        mode: w.policy.mode.clone(),
        ttl_secs: w
            .policy
            .not_after
            .map(|end| (end - w.policy.not_before) as u64)
            .unwrap_or(0),
    };
    w.intent.caller_env = w.caller_env.clone();
    w.intent_sha256 = w.intent.sha256().unwrap();
}

pub mod target_registry;

pub mod destination;

pub mod target_capture;

pub mod target_management;

pub mod destination_helper;

mod podman;
mod podman_api;
mod process_request;
