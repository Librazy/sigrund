//! Read-only Phase 1.5 fixture renderer using the frozen experiment contracts.
//! This binary has no production registry, signing or execution entry point.
use sigrund_phase0::contracts::{
    Account, Acquisition, BindingBundle, Constraints, Contract, Intent, Registration, Selector,
    TargetBinding, approval_description,
};
use std::{fs::File, io::Read, path::Path};

fn record<T: Contract>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(65_537).read_to_end(&mut bytes)?;
    Ok(T::parse(&bytes)?)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [authority, registration, acquisition, constraints] = args.as_slice() else {
        return Err(
            "usage: sigrund-phase15-review HOST_ID REGISTRATION ACQUISITION CONSTRAINTS".into(),
        );
    };
    let registration: Registration = record(Path::new(registration))?;
    let acquisition: Acquisition = record(Path::new(acquisition))?;
    let constraints: Constraints = record(Path::new(constraints))?;
    if registration.daemon_pid != acquisition.pid
        || acquisition.lifecycle.registration_id.as_deref() != Some(&registration.id)
        || acquisition.lifecycle.registration_revision.as_deref() != Some(&registration.revision)
        || registration.profile_sha256 != constraints.sha256()?
    {
        return Err("registration, acquisition and profile differ".into());
    }
    let bundle = BindingBundle {
        schema: "sigrund.binding-bundle.phase0.v1".into(),
        host_id: authority.clone(),
        target_binding: TargetBinding {
            kind: "process_environment".into(),
            daemon_epoch: acquisition.daemon_epoch.clone(),
            instance_id: acquisition.instance_id.clone(),
            description: "Fixture B retained process environment".into(),
            context_sha256: acquisition.sha256()?,
        },
        profile_sha256: registration.profile_sha256.clone(),
        constraints,
    };
    let review = approval_description(
        &bundle,
        &Intent {
            target: Selector::Registered {
                id: registration.id.clone(),
            },
            account: Account::Name {
                name: "phase15_service".into(),
            },
            security_profile: bundle.constraints.profile_id.clone(),
        },
        &Account::Numeric {
            uid: 12001,
            gid: 12001,
            supplementary_gids: vec![],
        },
        &acquisition,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "qualification": "fixture review only; requested constraints await executor qualification",
            "operator_label": registration.id,
            "administrator_declared_owner_uid": registration.owner_uid,
            "registration_revision": registration.revision,
            "verified_process_environment": serde_json::from_str::<serde_json::Value>(&review)?,
        }))?
    );
    Ok(())
}
