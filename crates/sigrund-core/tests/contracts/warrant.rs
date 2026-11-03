use super::support::*;

#[test]
fn direct_executable_evidence_is_versioned_canonical_and_signed() {
    use sigrund_core::executable::ExecutableTrust;
    let ctime = ExecutableTrust::Ctime {
        device: u64::MAX.to_string(),
        inode: u64::MAX.to_string(),
        size: "67108865".into(),
        ctime_sec: 1000,
        ctime_nsec: 999_999_999,
    };
    for evidence in [
        ctime,
        ExecutableTrust::FsVerity {
            algorithm: "sha256".into(),
            digest: "ab".repeat(32),
        },
        ExecutableTrust::FsVerity {
            algorithm: "sha512".into(),
            digest: "cd".repeat(64),
        },
    ] {
        let mut w = fixture();
        w.version = "1.1".into();
        w.command.executable_sha256 = None;
        w.command.executable_trust = Some(evidence.clone());
        let canonical = CanonicalWarrant::new(w.clone()).unwrap();
        assert_eq!(
            CanonicalWarrant::parse(canonical.as_bytes()).unwrap(),
            canonical
        );
        let csr = Csr::new(w.clone()).unwrap();
        assert_eq!(csr.bind_envelope(&signed(w.clone())).unwrap(), canonical);
        let mut changed = w.clone();
        changed.command.executable_trust = Some(ExecutableTrust::FsVerity {
            algorithm: "sha256".into(),
            digest: "ef".repeat(32),
        });
        assert!(csr.bind_envelope(&signed(changed)).is_err());
        w.command.executable_sha256 = Some("00".repeat(32));
        assert!(CanonicalWarrant::new(w.clone()).is_err());
        w.command.executable_sha256 = None;
        w.version = "1.0".into();
        assert!(CanonicalWarrant::new(w).is_err());
    }
    for value in [
        json!({"model":"ctime","device":"01","inode":"1","size":"1","ctime_sec":1000,"ctime_nsec":0}),
        json!({"model":"ctime","device":"1","inode":"0","size":"1","ctime_sec":1000,"ctime_nsec":0}),
        json!({"model":"ctime","device":"1","inode":"1","size":"0","ctime_sec":1000,"ctime_nsec":0}),
        json!({"model":"ctime","device":"1","inode":"1","size":"1","ctime_sec":1000,"ctime_nsec":1000000000}),
        json!({"model":"fs_verity","algorithm":"sha256","digest":"AB".repeat(32)}),
        json!({"model":"fs_verity","algorithm":"sha512","digest":"ab".repeat(32)}),
        json!({"model":"fs_verity","algorithm":"sha1","digest":"ab".repeat(20)}),
    ] {
        let evidence: ExecutableTrust = serde_json::from_value(value).unwrap();
        assert!(!evidence.valid());
    }
    assert!(
        serde_json::from_value::<ExecutableTrust>(
            json!({"model":"fs_verity","algorithm":"sha256","digest":"ab".repeat(32),"extra":true})
        )
        .is_err()
    );
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

#[test]
fn direct_v12_binds_exact_capability_sets_without_changing_legacy_bytes() {
    use sigrund_core::executable::{CapabilitySets, ExecutableTrust};
    let mut w = fixture();
    w.version = "1.2".into();
    w.command.executable_sha256 = None;
    w.command.executable_trust = Some(ExecutableTrust::FsVerity {
        algorithm: "sha256".into(),
        digest: "12".repeat(32),
    });
    w.execution_context.capabilities = vec!["CAP_NET_BIND_SERVICE".into()];
    let mut sets = CapabilitySets::ordinary(&w.execution_context.capabilities);
    sets.ambient.clear();
    w.execution_context.post_exec_capabilities = Some(sets);
    let csr = Csr::new(w.clone()).unwrap();
    let envelope = signed(w.clone());
    csr.bind_envelope(&envelope).unwrap();
    for field in [
        "permitted",
        "effective",
        "inheritable",
        "ambient",
        "bounding",
    ] {
        let mut value = serde_json::to_value(&w).unwrap();
        value["execution_context"]["post_exec_capabilities"][field] = json!(["CAP_SYS_ADMIN"]);
        assert!(
            parse_value(&value).is_err(),
            "accepted unauthorized {field}"
        );
        value["execution_context"]["post_exec_capabilities"][field] = json!([]);
        if let Ok(changed) = parse_value(&value)
            && changed.warrant() != &w
        {
            assert!(
                csr.bind_envelope(&signed(changed.warrant().clone()))
                    .is_err()
            );
        }
    }
    w.execution_context.post_exec_capabilities = None;
    assert!(Csr::new(w.clone()).is_err());
    w.version = "1.1".into();
    assert!(Csr::new(w.clone()).is_ok());
    w.execution_context.post_exec_capabilities = Some(CapabilitySets::ordinary(&[]));
    assert!(Csr::new(w).is_err());
    let mut hello = serde_json::to_value(unsigned()).unwrap();
    hello["requested_execution_context"]["post_exec_capabilities"] = json!({});
    assert!(parse_strict::<ClientHello>(&serde_json::to_vec(&hello).unwrap()).is_err());
}
