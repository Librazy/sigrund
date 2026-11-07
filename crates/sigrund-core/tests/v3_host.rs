use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sigrund_core::{
    host::{Acquisition, BindingBundle, Constraints, Record},
    v3::{self, Hello, Warrant},
};
use ssh_key::{SshSig, encoding::Encode};
const PAYLOAD: &[u8] = include_bytes!("fixtures/v3-host/warrant.json");
const BUNDLE: &[u8] = include_bytes!("fixtures/v3-host/bundle.json");
fn changed(pointer: &str, value: Value) -> Vec<u8> {
    let mut w: Value = serde_json::from_slice(PAYLOAD).unwrap();
    *w.pointer_mut(pointer).unwrap() = value;
    sigrund_core::json::canonical_bytes(&w).unwrap()
}
#[test]
fn independent_host_records_bind_original_intent_and_two_different_digests() {
    let hashes: Value =
        serde_json::from_slice(include_bytes!("fixtures/v3-host/sha256.json")).unwrap();
    let a = Acquisition::parse(include_bytes!("fixtures/v3-host/acquisition.json")).unwrap();
    let c = Constraints::parse(include_bytes!("fixtures/v3-host/constraints.json")).unwrap();
    let b = BindingBundle::parse(BUNDLE).unwrap();
    let w = Warrant::parse_canonical(PAYLOAD).unwrap();
    assert_eq!(a.sha256().unwrap(), hashes["acquisition"]);
    assert_eq!(c.sha256().unwrap(), hashes["constraints"]);
    assert_eq!(b.sha256().unwrap(), hashes["bundle"]);
    assert_eq!(w.sha256().unwrap(), hashes["warrant"]);
    assert_eq!(w.intent.sha256().unwrap(), hashes["intent"]);
    assert_eq!(
        w.execution_binding().unwrap().canonical().unwrap(),
        include_bytes!("fixtures/v3-host/execution-binding.json")
    );
    assert_eq!(
        w.execution_binding().unwrap().sha256().unwrap(),
        hashes["execution-binding"]
    );
    assert_ne!(
        w.sha256().unwrap(),
        w.execution_binding().unwrap().sha256().unwrap()
    );
    w.verify_bundle(&b).unwrap();
    let changed = Warrant::parse_canonical(&changed("/execution_context/target_uid", json!(99)));
    assert!(changed.is_err());
    assert!(sigrund_core::warrant::CanonicalWarrant::parse(PAYLOAD).is_ok());
}
#[test]
fn v3_openssh_signature_rejects_other_domains_and_signed_substitutions() {
    let sig = SshSig::from_pem(include_bytes!("fixtures/v3-host/warrant.sshsig")).unwrap();
    let key = include_str!("fixtures/v3-host/signer.pub");
    let encoded = STANDARD.encode(sig.encode_vec().unwrap());
    assert_eq!(
        sigrund_core::crypto::pae(sigrund_core::host::PAYLOAD_TYPE, PAYLOAD),
        include_bytes!("fixtures/v3-host/warrant.pae")
    );
    v3::verify_ssh_signature("ssh-ed25519", key, &encoded, PAYLOAD, false, false).unwrap();
    assert!(
        sigrund_core::crypto::verify_ssh_signature(
            "ssh-ed25519",
            key,
            &encoded,
            "application/vnd.sigrun.warrant.v2+json",
            PAYLOAD,
            false,
            false
        )
        .is_err()
    );
    for (path, value) in [
        (
            "/target_binding/instance_id",
            json!("0192d8f4-0000-7000-8000-000000000003"),
        ),
        (
            "/target_binding/daemon_epoch",
            json!("0192d8f4-0000-7000-8000-000000000003"),
        ),
        (
            "/security_constraints/profile_sha256",
            json!("f".repeat(64)),
        ),
        ("/requester_uid", json!(1002)),
        ("/command/executable_trust/sha256", json!("f".repeat(64))),
    ] {
        assert!(
            v3::verify_ssh_signature(
                "ssh-ed25519",
                key,
                &encoded,
                &changed(path, value),
                false,
                false
            )
            .is_err(),
            "{path}"
        );
    }
}
#[test]
fn strict_host_contracts_reject_version_shape_intent_and_numeric_overrides() {
    for (path, value) in [
        ("/version", json!("2.0")),
        ("/version", json!("4.0")),
        ("/intent/target/kind", json!("self")),
        (
            "/intent/target",
            json!({"kind":"process","pid":1,"pid_scope":"daemon"}),
        ),
        (
            "/intent/account",
            json!({"kind":"numeric","uid":1001,"gid":1001,"supplementary_gids":[],"name":"root"}),
        ),
        ("/execution_context/target_gid", json!(0)),
        ("/execution_context/env_exact", json!({"PATH":"/tmp"})),
        ("/execution_context/post_exec_capabilities", Value::Null),
        (
            "/approval_exec_id",
            json!("0192d8f4-0000-7000-8000-000000000003"),
        ),
        ("/intent_sha256", json!("f".repeat(64))),
        ("/policy/not_after", json!(1)),
    ] {
        assert!(
            Warrant::parse_canonical(&changed(path, value)).is_err(),
            "{path}"
        );
    }
    let mut w: Value = serde_json::from_slice(PAYLOAD).unwrap();
    w.as_object_mut().unwrap().remove("approval_exec_id");
    assert!(Warrant::parse(&serde_json::to_vec(&w).unwrap()).is_err());
    let duplicate =
        String::from_utf8(PAYLOAD.to_vec())
            .unwrap()
            .replacen('{', "{\"version\":\"3.0\",", 1);
    assert!(Warrant::parse(duplicate.as_bytes()).is_err());
    assert!(Warrant::parse_canonical(&[PAYLOAD, b"\n"].concat()).is_err());
}
#[test]
fn approval_bundle_rejects_stale_instance_profile_and_unavailable_enforcement() {
    let w = Warrant::parse_canonical(PAYLOAD).unwrap();
    let mut bundle = BindingBundle::parse(BUNDLE).unwrap();
    bundle.acquisition.instance_id = "0192d8f4-0000-7000-8000-000000000003".into();
    bundle.target_binding.instance_id = bundle.acquisition.instance_id.clone();
    bundle.target_binding.context_sha256 = bundle.acquisition.sha256().unwrap();
    bundle.validate().unwrap();
    assert!(w.verify_bundle(&bundle).is_err());
    for (key, value) in [
        ("securebits", json!(15)),
        ("capabilities", json!(["CAP_SYS_ADMIN"])),
        ("verify_exec_stop", json!(true)),
        ("lsm", json!("enforcing_selinux")),
        ("seccomp", json!("inherited")),
        ("join_namespaces", json!(["user"])),
    ] {
        let mut c: Value =
            serde_json::from_slice(include_bytes!("fixtures/v3-host/constraints.json")).unwrap();
        c[key] = value;
        assert!(Constraints::parse(&serde_json::to_vec(&c).unwrap()).is_err());
    }
}
#[test]
fn thin_wire_is_strict_and_cannot_carry_resolved_evidence_or_legacy_context() {
    let w = Warrant::parse_canonical(PAYLOAD).unwrap();
    let mut hello = json!({"version":"3.0","mode":"thin_csr","tty_mode":"stdio","caller_env":{},"intent":w.intent});
    Hello::parse(&serde_json::to_vec(&hello).unwrap()).unwrap();
    hello["intent"]["execution_context"]["target_uid"] = json!(0);
    assert!(Hello::parse(&serde_json::to_vec(&hello).unwrap()).is_err());
    hello["intent"]["execution_context"]
        .as_object_mut()
        .unwrap()
        .remove("target_uid");
    hello["version"] = json!("2.0");
    assert!(Hello::parse(&serde_json::to_vec(&hello).unwrap()).is_err());
}

#[test]
fn context_is_target_independent_and_approval_display_includes_complete_records() {
    use sigrund_core::v3::{ContextQuery, PublicContext};
    ContextQuery::parse(br#"{"version":"3.0"}"#).unwrap();
    for raw in [
        br#"{"version":"2.0"}"#.as_slice(),
        br#"{"version":"3.0","target":{"kind":"host"}}"#,
        br#"{"version":"3.0","path":"/usr/bin/id"}"#,
    ] {
        assert!(ContextQuery::parse(raw).is_err());
    }
    let context = json!({"version":"3.0","host_id":format!("sigrun-host:sha256:{}", "1".repeat(64)),"policy_generation":1,"executable_trust_models":["digest_memfd"],"limits":{"max_executable_bytes":67108864,"max_direct_digest_bytes":268435456,"direct_digest_timeout_ms":5000,"max_stdin_bytes":16777216,"max_ttl_secs":3600,"max_onetime_window_secs":3600,"authorization_timeout_ms":120000},"features":{"direct_exec_checkpoint":false,"host_file_capabilities":false,"tty_modes":["stdio"],"stdin_policies":["null","sha256"],"grant_modes":["one_time"]}});
    PublicContext::parse(&serde_json::to_vec(&context).unwrap()).unwrap();
    let w = Warrant::parse_canonical(PAYLOAD).unwrap();
    let bundle = BindingBundle::parse(BUNDLE).unwrap();
    let display = v3::approval_evidence(&w, &bundle).unwrap();
    let shown: Value = serde_json::from_str(&display).unwrap();
    assert_eq!(
        shown["security_constraints"],
        serde_json::to_value(&bundle.constraints).unwrap()
    );
    assert_eq!(
        shown["acquisition"],
        serde_json::to_value(&bundle.acquisition).unwrap()
    );
    assert_eq!(
        shown["original_intent"],
        serde_json::to_value(&w.intent).unwrap()
    );
    assert_eq!(
        shown["resolved_execution_context"],
        serde_json::to_value(&w.execution_context).unwrap()
    );
    let mut changed = bundle.clone();
    changed.constraints.memory_max /= 2;
    assert!(v3::approval_evidence(&w, &changed).is_err());
}

#[test]
fn host_scope_and_cross_owner_permission_are_independent_of_numeric_ceilings() {
    use sigrund_core::host::{Account, ScopedRule};
    let mut rule = ScopedRule {
        requester_uids: vec![1000],
        target_scope: "host".into(),
        target_uids: vec![0],
        target_gids: vec![0],
        supplementary_gids: vec![],
        profile_sha256: "a".repeat(64),
        cross_owner: false,
    };
    assert!(!rule.permits(1000, 0, 0, &[], &"a".repeat(64)));
    rule.cross_owner = true;
    assert!(rule.permits(1000, 0, 0, &[], &"a".repeat(64)));
    assert!(!rule.permits(1000, 0, 0, &[1], &"a".repeat(64)));
    assert!(!rule.permits(1000, 0, 0, &[], &"b".repeat(64)));
    rule.target_scope = "registered:container".into();
    assert!(!rule.permits(1000, 0, 0, &[], &"a".repeat(64)));
    assert!(
        Account::Numeric {
            uid: 1,
            gid: 1,
            supplementary_gids: vec![2, 2]
        }
        .validate()
        .is_err()
    );
    assert!(
        Account::Name {
            name: "root\nforged approval".into()
        }
        .validate()
        .is_err()
    );
}
