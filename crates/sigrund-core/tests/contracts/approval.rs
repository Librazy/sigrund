use super::support::*;

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
