use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use sigrund_core::{
    approval::{ApprovalRequest, ApprovalResponse},
    config::{DaemonConfig, MvpProfile, SignerPolicyFile},
    crypto::{WARRANT_PAYLOAD_TYPE, pae, verify_raw_ed25519},
    json::canonical_bytes,
    protocol::{ClientHello, DsseEnvelope, DsseSignature, parse_strict},
    warrant::{CanonicalWarrant, Csr, CsrIdentity, MAX_TIMESTAMP, SnapshotDigests, Warrant},
};

const EXEC_ID: &str = "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f";
const GOLDEN: &[u8] = br#"{"command":{"allow_interpreted_script":false,"argv":["/usr/bin/id"],"cwd":"/","executable_path":"/usr/bin/id","executable_sha256":"0000000000000000000000000000000000000000000000000000000000000000","stdin_policy":"null","stdin_sha256":null,"tty_mode":"stdio"},"execution_context":{"caller_env_allowlist":[],"capabilities":[],"env_exact":{"LANG":"C.UTF-8","PATH":"/usr/bin"},"supplementary_gids":[],"target_gid":0,"target_uid":0,"umask":63},"grant_id":"0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f","host_id":"sigrun-host:sha256:0000000000000000000000000000000000000000000000000000000000000000","policy":{"mode":"one_time","not_after":1900,"not_before":1000},"requester_gid":1001,"requester_uid":1001,"version":"1.0"}"#;

fn fixture() -> Warrant {
    parse_strict(GOLDEN).unwrap()
}
fn unsigned() -> ClientHello {
    let w = fixture();
    parse_strict(
        &serde_json::to_vec(&json!({
            "caller_env": {}, "mode": "unsigned_csr_request", "tty_mode": "stdio",
            "requested_command": w.command.requested(),
            "requested_execution_context": w.execution_context,
            "requested_policy": {"mode": "one_time", "ttl_secs": 900},
        }))
        .unwrap(),
    )
    .unwrap()
}
fn identity(now: i64) -> CsrIdentity {
    CsrIdentity {
        grant_id: EXEC_ID.into(),
        host_id: fixture().host_id,
        requester_uid: 1001,
        requester_gid: 1001,
        now,
    }
}
fn snapshots() -> SnapshotDigests {
    SnapshotDigests {
        executable_sha256: "00".repeat(32),
        stdin_sha256: None,
    }
}
fn signed(warrant: Warrant) -> DsseEnvelope {
    let canonical = CanonicalWarrant::new(warrant).unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let signature = key.sign(&pae(WARRANT_PAYLOAD_TYPE, canonical.as_bytes()));
    let envelope = DsseEnvelope::from_warrant(
        &canonical,
        vec![DsseSignature {
            keyid: "root-test".into(),
            sig: STANDARD.encode(signature.to_bytes()),
        }],
    )
    .unwrap();
    verify_raw_ed25519(
        &STANDARD.encode(key.verifying_key().to_bytes()),
        &envelope.signatures[0].sig,
        WARRANT_PAYLOAD_TYPE,
        canonical.as_bytes(),
    )
    .unwrap();
    envelope
}
fn parse_value(value: &Value) -> sigrund_core::Result<CanonicalWarrant> {
    CanonicalWarrant::parse(&canonical_bytes(value)?)
}

#[test]
fn canonical_documents_round_trip_against_golden_bytes() {
    let warrant = CanonicalWarrant::new(fixture()).unwrap();
    assert_eq!(warrant.as_bytes(), GOLDEN);
    assert_eq!(CanonicalWarrant::parse(GOLDEN).unwrap(), warrant);
    let csr = Csr::from_unsigned(&unsigned(), identity(1000), snapshots(), 900).unwrap();
    assert_eq!(csr.as_bytes(), GOLDEN);
    assert_eq!(Csr::parse(GOLDEN).unwrap(), csr);
    let envelope = signed(fixture());
    assert_eq!(
        DsseEnvelope::parse_jcs(&envelope.to_jcs().unwrap()).unwrap(),
        envelope
    );
    assert_eq!(csr.bind_envelope(&envelope).unwrap(), warrant);
    let request = ApprovalRequest::new(EXEC_ID.into(), "root-test".into(), &csr).unwrap();
    assert_eq!(
        ApprovalRequest::parse_jcs(&request.to_jcs().unwrap()).unwrap(),
        request
    );
    let response = ApprovalResponse::Approved {
        exec_id: EXEC_ID.into(),
        dsse_envelope: envelope,
    };
    assert_eq!(
        ApprovalResponse::parse_jcs(&response.to_jcs().unwrap()).unwrap(),
        response
    );
    assert_eq!(request.bind_response(&response).unwrap(), Some(warrant));
    let rejected = ApprovalResponse::Rejected {
        exec_id: EXEC_ID.into(),
        reason: "operator refused".into(),
    };
    assert_eq!(
        ApprovalResponse::parse_jcs(&rejected.to_jcs().unwrap()).unwrap(),
        rejected
    );
    assert!(request.bind_response(&rejected).unwrap().is_none());
}

#[test]
fn maximum_canonical_warrant_and_outer_documents_round_trip() {
    let mut warrant = fixture();
    warrant.command.argv = vec!["x".repeat(4096); 15];
    let remaining = 65_536 - canonical_bytes(&warrant).unwrap().len() - 3;
    assert!(remaining <= 4096);
    warrant.command.argv.push("x".repeat(remaining));
    let canonical = CanonicalWarrant::new(warrant.clone()).unwrap();
    assert_eq!(canonical.as_bytes().len(), 65_536);
    CanonicalWarrant::parse(canonical.as_bytes()).unwrap();
    let envelope = signed(warrant.clone());
    assert_eq!(envelope.payload.len(), 87_384);
    DsseEnvelope::parse_jcs(&envelope.to_jcs().unwrap()).unwrap();
    let csr = Csr::new(warrant.clone()).unwrap();
    let request = ApprovalRequest::new(EXEC_ID.into(), "root-test".into(), &csr).unwrap();
    ApprovalRequest::parse_jcs(&request.to_jcs().unwrap()).unwrap();
    let response = ApprovalResponse::Approved {
        exec_id: EXEC_ID.into(),
        dsse_envelope: envelope,
    };
    ApprovalResponse::parse_jcs(&response.to_jcs().unwrap()).unwrap();
    warrant.command.argv.last_mut().unwrap().push('x');
    assert!(CanonicalWarrant::new(warrant).is_err());
    let mut warrant = fixture();
    warrant.command.argv = vec!["x"; 256].into_iter().map(String::from).collect();
    CanonicalWarrant::new(warrant).unwrap();
}

#[test]
fn dsse_rejects_invalid_outer_schema_base64_and_inner_structure() {
    let original = signed(fixture());
    for pointer in ["", "/signatures/0"] {
        let mut value = serde_json::to_value(&original).unwrap();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!(0));
        assert!(DsseEnvelope::parse_jcs(&canonical_bytes(&value).unwrap()).is_err());
    }
    let mut duplicate = original.to_jcs().unwrap();
    duplicate.splice(1..1, br#""payloadType":"ignored","#.iter().copied());
    assert!(DsseEnvelope::parse_jcs(&duplicate).is_err());
    for payload in [
        "not base64".into(),
        format!("{}\n", original.payload),
        STANDARD.encode(vec![0; 65_537]),
        STANDARD.encode(format!("{}0{}", "[".repeat(9), "]".repeat(9))),
        STANDARD.encode(br#"{"command":{"argv":[1.5]}}"#),
    ] {
        let mut envelope = original.clone();
        envelope.payload = payload;
        assert!(envelope.warrant().is_err());
    }
    for signatures in [vec![], vec![original.signatures[0].clone(); 5]] {
        let mut envelope = original.clone();
        envelope.signatures = signatures;
        assert!(envelope.warrant().is_err());
    }
    let mut envelope = original;
    envelope.signatures[0].sig.clear();
    assert!(envelope.warrant().is_err());
}

#[test]
fn jcs_sorts_utf16_keys_recursively_and_rejects_noninteger_numbers() {
    let input = json!({"\u{e000}": 1, "\u{1f600}": [{"z": 0, "a": 1}]});
    assert_eq!(
        String::from_utf8(canonical_bytes(&input).unwrap()).unwrap(),
        "{\"😀\":[{\"a\":1,\"z\":0}],\"\u{e000}\":1}"
    );
    assert!(canonical_bytes(&json!(1.5)).is_err());
    assert!(canonical_bytes(&json!(9_007_199_254_740_992u64)).is_err());
}

#[test]
fn canonical_warrants_reject_alternate_encodings_duplicates_and_unknown_fields() {
    let text = std::str::from_utf8(GOLDEN).unwrap();
    for invalid in [
        format!("{text}\n"),
        format!(" {text}"),
        text.replacen("\"command\":", "\"command\": ", 1),
        text.replace("1900", "1.9e3"),
        text.replace("1900", "1900.0"),
        text.replace(
            "\"version\":\"1.0\"",
            "\"version\":\"1.0\",\"version\":\"1.0\"",
        ),
        text.replace("\"cwd\":\"/\"", "\"cwd\":\"/\",\"cwd\":\"/\""),
        text.replace("/usr/bin/id", "\\/usr/bin/id"),
        text.replace("\"target_uid\":0", "\"target_uid\":-0"),
    ] {
        assert!(
            CanonicalWarrant::parse(invalid.as_bytes()).is_err(),
            "{invalid}"
        );
    }
    let original: Value = serde_json::from_slice(GOLDEN).unwrap();
    for pointer in ["", "/command", "/execution_context", "/policy"] {
        let mut value = original.clone();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(true));
        assert!(parse_value(&value).is_err(), "{pointer}");
    }
    for (parent, key) in [("/command", "stdin_sha256"), ("/policy", "not_after")] {
        let mut value = original.clone();
        value
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(parse_value(&value).is_err(), "missing {key}");
    }
    let mut invalid_utf8 = GOLDEN.to_vec();
    invalid_utf8[0] = 0xff;
    assert!(CanonicalWarrant::parse(&invalid_utf8).is_err());
}

#[test]
fn warrant_schema_rejects_invalid_bounds_controls_and_compatibility() {
    let original: Value = serde_json::from_slice(GOLDEN).unwrap();
    for (path, replacement) in [
        ("/requester_uid", json!(u32::MAX)),
        ("/requester_gid", json!(-1)),
        ("/execution_context/supplementary_gids", json!([u32::MAX])),
        ("/execution_context/supplementary_gids", json!([2, 1])),
        ("/execution_context/capabilities", json!(["CAP_UNKNOWN"])),
        (
            "/execution_context/capabilities",
            json!(["CAP_CHOWN", "CAP_CHOWN"]),
        ),
        ("/execution_context/umask", json!(512)),
        (
            "/execution_context/caller_env_allowlist",
            json!(["LD_PRELOAD"]),
        ),
        ("/execution_context/caller_env_allowlist", json!(["PATH"])),
        ("/execution_context/caller_env_allowlist", json!(["LC_*"])),
        ("/command/argv", json!(vec!["x"; 257])),
        ("/command/argv", json!([])),
        ("/command/cwd", json!("/usr/./bin")),
        ("/command/argv", json!(["\u{1b}"])),
        ("/command/argv", json!(["\u{202e}"])),
        ("/command/argv", json!(["x".repeat(4097)])),
        ("/command/tty_mode", json!("pty")),
        ("/command/stdin_policy", json!("sha256")),
        ("/command/stdin_sha256", json!("00".repeat(32))),
        ("/command/executable_sha256", json!("AA".repeat(32))),
        ("/policy/mode", json!("permanent")),
        ("/policy/not_after", Value::Null),
        ("/policy/not_after", json!(999)),
        ("/policy/not_after", json!(MAX_TIMESTAMP + 1)),
        ("/policy/not_before", json!(-1)),
        ("/host_id", json!("wrong-host")),
        ("/grant_id", json!("0192d8f4-7c1b-6000-8a01-9f8b3c4d5e6f")),
    ] {
        let mut value = original.clone();
        *value.pointer_mut(path).unwrap() = replacement;
        assert!(parse_value(&value).is_err(), "accepted {path}: {value}");
    }
    for field in ["env_exact", "caller_env_allowlist", "supplementary_gids"] {
        let mut value = original.clone();
        value["execution_context"][field] = if field == "env_exact" {
            Value::Object(
                (0..129)
                    .map(|i| (format!("VAR_{i:03}"), json!("v")))
                    .collect(),
            )
        } else if field == "caller_env_allowlist" {
            json!((0..129).map(|i| format!("VAR_{i:03}")).collect::<Vec<_>>())
        } else {
            json!((0..65).collect::<Vec<_>>())
        };
        assert!(parse_value(&value).is_err(), "{field}");
    }
    let mut value = original.clone();
    value["execution_context"]["env_wildcard_allowlist"] = json!([]);
    assert!(parse_value(&value).is_err());
    let mut value = original;
    value["command"]["argv"] = json!(vec!["x".repeat(4096); 17]);
    assert!(parse_value(&value).is_err());
}

#[test]
fn every_warrant_field_is_bound_to_the_csr_even_with_a_valid_signature() {
    let csr = Csr::new(fixture()).unwrap();
    let original: Value = serde_json::from_slice(GOLDEN).unwrap();
    for (path, replacement) in [
        ("/command/allow_interpreted_script", json!(true)),
        ("/command/argv", json!(["/usr/bin/id", "-u"])),
        ("/command/cwd", json!("/tmp")),
        ("/command/executable_path", json!("/usr/bin/true")),
        ("/command/executable_sha256", json!("11".repeat(32))),
        ("/execution_context/capabilities", json!(["CAP_CHOWN"])),
        ("/execution_context/caller_env_allowlist", json!(["TERM"])),
        ("/execution_context/env_exact", json!({"PATH": "/usr/bin"})),
        ("/execution_context/supplementary_gids", json!([33])),
        ("/execution_context/target_gid", json!(33)),
        ("/execution_context/target_uid", json!(33)),
        ("/execution_context/umask", json!(7)),
        ("/grant_id", json!("0192d8f4-7c1b-7000-8a01-9f8b3c4d5e60")),
        (
            "/host_id",
            json!(format!("sigrun-host:sha256:{}", "11".repeat(32))),
        ),
        ("/policy/mode", json!("time_range")),
        ("/policy/not_before", json!(1001)),
        ("/policy/not_after", json!(1901)),
        ("/requester_gid", json!(1002)),
        ("/requester_uid", json!(1002)),
    ] {
        let mut value = original.clone();
        *value.pointer_mut(path).unwrap() = replacement;
        let envelope = signed(serde_json::from_value(value).unwrap());
        assert!(csr.bind_envelope(&envelope).is_err(), "changed {path}");
    }
    // These coupled fields must change together to remain schema-valid.
    for (tty, stdin, digest) in [
        ("stdio", "sha256", Some("11".repeat(32))),
        ("stdio", "unrestricted_interactive", None),
        ("pty", "unrestricted_interactive", None),
    ] {
        let mut warrant = fixture();
        warrant.command.tty_mode = tty.into();
        warrant.command.stdin_policy = stdin.into();
        warrant.command.stdin_sha256 = digest;
        assert!(csr.bind_envelope(&signed(warrant)).is_err());
    }
    let mut permanent = fixture();
    permanent.policy.mode = "permanent".into();
    permanent.policy.not_after = None;
    assert!(csr.bind_envelope(&signed(permanent)).is_err());
    let mut wrong_version = fixture();
    wrong_version.version = "2.0".into();
    assert!(CanonicalWarrant::new(wrong_version).is_err());
}

#[test]
fn approval_rejects_wrong_execution_signer_extra_fields_and_noncanonical_documents() {
    let request = ApprovalRequest::new(
        EXEC_ID.into(),
        "root-test".into(),
        &Csr::new(fixture()).unwrap(),
    )
    .unwrap();
    for (exec_id, keyid) in [
        ("0192d8f4-7c1b-7000-8a01-9f8b3c4d5e60", "root-test"),
        (EXEC_ID, "other-root"),
    ] {
        let mut envelope = signed(fixture());
        envelope.signatures[0].keyid = keyid.into();
        let response = ApprovalResponse::Approved {
            exec_id: exec_id.into(),
            dsse_envelope: envelope,
        };
        assert!(request.bind_response(&response).is_err());
    }
    for value in [
        json!({"status":"abstain", "exec_id":EXEC_ID}),
        json!({"status":"rejected", "exec_id":EXEC_ID, "reason":"no", "extra":true}),
        json!({"status":"rejected", "exec_id":EXEC_ID, "reason":""}),
        json!({"status":"rejected", "exec_id":EXEC_ID, "reason":"x".repeat(1025)}),
        json!({"status":"approved", "exec_id":EXEC_ID}),
    ] {
        assert!(ApprovalResponse::parse_jcs(&canonical_bytes(&value).unwrap()).is_err());
    }
    let response = ApprovalResponse::Rejected {
        exec_id: EXEC_ID.into(),
        reason: "x".repeat(1024),
    };
    let bytes = response.to_jcs().unwrap();
    ApprovalResponse::parse_jcs(&bytes).unwrap();
    let mut trailing = bytes.clone();
    trailing.push(b'\n');
    assert!(ApprovalResponse::parse_jcs(&trailing).is_err());
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replace("\"status\":", "\"status\":\"rejected\",\"status\":");
    assert!(ApprovalResponse::parse_jcs(duplicate.as_bytes()).is_err());
    let mut request_value = serde_json::to_value(&request).unwrap();
    request_value["csr_payload"] = "x".repeat(65_537).into();
    assert!(ApprovalRequest::parse_jcs(&canonical_bytes(&request_value).unwrap()).is_err());
    let mut envelope = signed(fixture());
    envelope.payload_type = "other".into();
    assert!(envelope.to_jcs().is_err());
    let mut envelope = signed(fixture());
    envelope.signatures.push(envelope.signatures[0].clone());
    assert!(
        request
            .bind_response(&ApprovalResponse::Approved {
                exec_id: EXEC_ID.into(),
                dsse_envelope: envelope
            })
            .is_err()
    );
}

#[test]
fn csr_checks_captured_ttl_timestamp_arithmetic_and_stdin_bindings() {
    assert!(Csr::from_unsigned(&unsigned(), identity(1000), snapshots(), 899).is_err());
    assert!(
        Csr::from_unsigned(&unsigned(), identity(MAX_TIMESTAMP - 899), snapshots(), 900).is_err()
    );
    assert!(Csr::from_unsigned(&unsigned(), identity(i64::MAX), snapshots(), 900).is_err());
    let mut hello = unsigned();
    hello.requested_policy.as_mut().unwrap().ttl_secs = u64::MAX;
    assert!(Csr::from_unsigned(&hello, identity(1000), snapshots(), u64::MAX).is_err());
    let mut hello = unsigned();
    hello.requested_policy.as_mut().unwrap().ttl_secs = 0;
    assert_eq!(
        Csr::from_unsigned(&hello, identity(1000), snapshots(), 0)
            .unwrap()
            .warrant()
            .policy
            .not_after,
        Some(1000)
    );
    hello.requested_policy.as_mut().unwrap().mode = "permanent".into();
    assert_eq!(
        Csr::from_unsigned(&hello, identity(1000), snapshots(), 0)
            .unwrap()
            .warrant()
            .policy
            .not_after,
        None
    );
    let mut hello = unsigned();
    hello.requested_command.as_mut().unwrap().stdin_policy = "sha256".into();
    assert!(Csr::from_unsigned(&hello, identity(1000), snapshots(), 900).is_err());
    let mut digests = snapshots();
    digests.stdin_sha256 = Some("11".repeat(32));
    assert!(Csr::from_unsigned(&hello, identity(1000), digests, 900).is_ok());
}

fn config(profile: &str) -> sigrund_core::Result<DaemonConfig> {
    let text = include_str!("../../../config/sigrund.toml.example").replace(
        "<strict-padded-base64-32-byte-ed25519-key>",
        &STANDARD.encode([1; 32]),
    );
    DaemonConfig::from_toml(format!("{text}\n{profile}").as_bytes())
}

#[test]
fn mvp_profile_is_opt_in_and_rejects_expansion_at_load_and_reload() {
    assert!(config("").unwrap().mvp.is_none());
    let cfg = config("[mvp]").unwrap();
    assert_eq!(cfg.mvp, Some(MvpProfile::default()));
    let store = sigrund_core::config::PolicyStore::new(cfg);
    assert_eq!(store.capture().mvp, Some(MvpProfile::default()));
    for settings in [
        "tty_mode = 'pty'",
        "hooks_enabled = true",
        "pty_enabled = true",
        "max_active_approval_requests = 0",
        "max_active_approval_requests = 2",
        "extra = true",
    ] {
        assert!(config(&format!("[mvp]\n{settings}")).is_err(), "{settings}");
    }
    let mut replacement = config("[mvp]").unwrap();
    replacement.require_remote_audit_ack = true;
    assert!(store.reload(replacement).is_err());
    assert_eq!(store.current().number, 1);
    let profile = MvpProfile::default();
    profile.validate_hello(&unsigned()).unwrap();
    let mut pty = unsigned();
    pty.tty_mode = "pty".into();
    let command = pty.requested_command.as_mut().unwrap();
    command.tty_mode = "pty".into();
    command.stdin_policy = "unrestricted_interactive".into();
    assert!(profile.validate_hello(&pty).is_err());
}

#[test]
fn signed_hello_validates_canonical_inner_payload_and_caller_environment() {
    let mut hello: ClientHello = parse_strict(&serde_json::to_vec(&json!({
        "caller_env": {}, "mode": "signed", "tty_mode": "stdio", "dsse_envelope": signed(fixture()),
    })).unwrap()).unwrap();
    hello.validate_request().unwrap();
    hello.caller_env.insert("TERM".into(), "xterm".into());
    assert!(hello.validate_request().is_err());
    hello.caller_env.clear();
    hello.requested_policy = unsigned().requested_policy;
    assert!(hello.validate_request().is_err());
    hello.requested_policy = None;
    hello.dsse_envelope.as_mut().unwrap().payload = STANDARD.encode([GOLDEN, b"\n"].concat());
    assert!(hello.validate_request().is_err());
}

#[test]
fn hello_wire_limits_use_original_bytes_and_preserve_omitted_fields() {
    let hello = unsigned();
    let bytes = serde_json::to_vec(&hello).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("dsse_envelope"));
    let mut boundary = bytes.clone();
    boundary.resize(65_536, b' ');
    ClientHello::parse_request(&boundary).unwrap();
    boundary.push(b' ');
    assert!(ClientHello::parse_request(&boundary).is_err());
    // Fill the unsigned document itself to the exact ceiling; serialization
    // must not add absent mode-specific keys when validating it again.
    let mut hello = unsigned();
    hello.requested_command.as_mut().unwrap().argv = vec!["x".repeat(4096); 15];
    let remaining = 65_536 - serde_json::to_vec(&hello).unwrap().len() - 3;
    assert!(remaining <= 4096);
    hello
        .requested_command
        .as_mut()
        .unwrap()
        .argv
        .push("x".repeat(remaining));
    let bytes = serde_json::to_vec(&hello).unwrap();
    assert_eq!(bytes.len(), 65_536);
    ClientHello::parse_request(&bytes).unwrap();

    let mut signed_bytes = serde_json::to_vec(&json!({"caller_env": {}, "mode": "signed",
        "tty_mode": "stdio", "dsse_envelope": signed(fixture())}))
    .unwrap();
    signed_bytes.resize(196_608, b' ');
    ClientHello::parse_request(&signed_bytes).unwrap();
    signed_bytes.push(b' ');
    assert!(ClientHello::parse_request(&signed_bytes).is_err());
}

#[test]
fn mvp_signer_policy_rejects_nonssh_adapters() {
    let mut policy =
        SignerPolicyFile::from_toml(include_bytes!("../../../config/signers.toml.example"))
            .unwrap();
    let key = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    ));
    policy.signers[0].signature_type = "ssh-ed25519".into();
    policy.signers[0].require_user_presence = false;
    policy.signers[0].public_key = key.to_openssh().unwrap();
    policy.validate_against(&config("[mvp]").unwrap()).unwrap();
    policy.signers[0].signature_type = "raw-ed25519".into();
    policy.signers[0].public_key =
        STANDARD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes());
    policy.validate_against(&config("").unwrap()).unwrap();
    assert!(policy.validate_against(&config("[mvp]").unwrap()).is_err());
}

#[test]
fn phase15_profile_restrictions_apply_to_signed_and_unsigned_requests() {
    let profile = MvpProfile::default();
    let signed_hello = |warrant| -> ClientHello {
        parse_strict(&serde_json::to_vec(&json!({
            "mode": "signed", "tty_mode": "stdio", "caller_env": {}, "dsse_envelope": signed(warrant)
        })).unwrap()).unwrap()
    };
    for mode in ["null", "sha256"] {
        let mut warrant = fixture();
        warrant.command.stdin_policy = mode.into();
        warrant.command.stdin_sha256 = (mode == "sha256").then(|| "00".repeat(32));
        profile
            .validate_for_peer(&signed_hello(warrant), 1001)
            .unwrap();
        let mut hello = unsigned();
        hello.requested_command.as_mut().unwrap().stdin_policy = mode.into();
        profile.validate_for_peer(&hello, 1001).unwrap();
    }
    for field in [
        "script",
        "stdin",
        "allowlist",
        "time_range",
        "permanent",
        "same_uid",
    ] {
        let mut warrant = fixture();
        match field {
            "script" => warrant.command.allow_interpreted_script = true,
            "stdin" => warrant.command.stdin_policy = "unrestricted_interactive".into(),
            "allowlist" => warrant
                .execution_context
                .caller_env_allowlist
                .push("LANG".into()),
            "time_range" => warrant.policy.mode = "time_range".into(),
            "permanent" => {
                warrant.policy.mode = "permanent".into();
                warrant.policy.not_after = None;
            }
            "same_uid" => warrant.execution_context.target_uid = 1001,
            _ => unreachable!(),
        }
        // Keep allowlisted names disjoint from exact names so rejection proves
        // the profile restriction rather than a generic schema failure.
        if field == "allowlist" {
            warrant.execution_context.env_exact.remove("LANG");
        }
        let mut hello = unsigned();
        hello.requested_command = Some(warrant.command.requested());
        hello.requested_execution_context = Some(warrant.execution_context.clone());
        hello.requested_policy.as_mut().unwrap().mode = warrant.policy.mode.clone();
        hello.validate_request().unwrap();
        assert!(
            profile.validate_for_peer(&hello, 1001).is_err(),
            "unsigned {field}"
        );
        let hello = signed_hello(warrant);
        hello.validate_request().unwrap();
        assert!(
            profile.validate_for_peer(&hello, 1001).is_err(),
            "signed {field}"
        );
    }
    // Same-UID gating uses the actual peer, even if signed requester_uid lies.
    assert!(
        profile
            .validate_for_peer(&signed_hello(fixture()), 0)
            .is_err()
    );
    for mut hello in [unsigned(), signed_hello(fixture())] {
        hello.caller_env.insert("LANG".into(), "C".into());
        assert!(profile.validate_for_peer(&hello, 1001).is_err());
    }
}

#[test]
fn approval_signer_selection_is_explicit_bounded_and_unambiguous() {
    let mut policy =
        SignerPolicyFile::from_toml(include_bytes!("../../../config/signers.toml.example"))
            .unwrap();
    policy.signers[0].signature_type = "ssh-ed25519".into();
    policy.signers[0].require_user_presence = false;
    policy.signers[0].public_key = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(
        SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
    ))
    .to_openssh()
    .unwrap();
    let selected = format!(
        "[mvp]\napproval_signer_id = {:?}",
        policy.signers[0].signer_id
    );
    let cfg = config(&selected).unwrap();
    policy.validate_against(&cfg).unwrap();
    assert!(
        policy
            .validate_against(&config("[mvp]\napproval_signer_id = 'absent'").unwrap())
            .is_err()
    );
    policy.signers.push(policy.signers[0].clone());
    assert!(policy.validate_against(&cfg).is_err());
    for id in ["x".repeat(129), "λ".into(), "bad\nidentity".into()] {
        let profile = MvpProfile {
            approval_signer_id: id,
            ..MvpProfile::default()
        };
        assert!(profile.validate().is_err());
    }
}
