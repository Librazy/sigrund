use sigrund::host_target::HostTarget;
use sigrund_core::{
    host::{Constraints, Record},
    host_budget::{Budget, Limits},
};
#[test]
fn pinned_host_owner_survives_path_replacement_and_rejects_restart_bindings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("root");
    std::fs::create_dir(&path).unwrap();
    let budget = Budget::new(Limits::default()).unwrap();
    let target = HostTarget::acquire(std::slice::from_ref(&path), &budget).unwrap();
    let constraints = Constraints::parse(include_bytes!(
        "../../sigrund-core/tests/fixtures/v3-host/constraints.json"
    ))
    .unwrap();
    let bundle = target
        .bundle(
            format!("sigrun-host:sha256:{}", "1".repeat(64)),
            constraints.clone(),
        )
        .unwrap();
    let leases: Vec<_> = (0..4).map(|_| target.lease(1000).unwrap()).collect();
    assert!(target.lease(1000).is_err());
    std::fs::rename(&path, dir.path().join("old")).unwrap();
    std::fs::create_dir(&path).unwrap();
    for lease in &leases {
        lease.verify(&bundle).unwrap();
    }
    let restarted = HostTarget::acquire(std::slice::from_ref(&path), &budget).unwrap();
    let new_bundle = restarted
        .bundle(bundle.host_id.clone(), constraints)
        .unwrap();
    assert_ne!(
        new_bundle.target_binding.daemon_epoch,
        bundle.target_binding.daemon_epoch
    );
    assert!(leases[0].verify(&new_bundle).is_err());
    drop(target);
    leases[0].verify(&bundle).unwrap();
    assert!(restarted.lease(1000).is_err());
    drop(leases);
    assert!(restarted.lease(1000).is_ok());
}
