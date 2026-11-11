use super::support::*;
use sigrund_core::{crypto::sha256_hex, protocol::Decision, state::StateStore};

#[test]
fn normative_pae_vector_and_intent_hash_match_independent_bytes() {
    let payload = br#"{"grant_id":"0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f","version":"3.0"}"#;
    let expected = br#"DSSEv1 38 application/vnd.sigrun.warrant.v3+json 67 {"grant_id":"0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f","version":"3.0"}"#;
    assert_eq!(WARRANT_PAYLOAD_TYPE.len(), 38);
    assert_eq!(payload.len(), 67);
    assert_eq!(pae(WARRANT_PAYLOAD_TYPE, payload), expected);
    assert_eq!(expected.len(), 119);
    assert_eq!(
        {
            use sigrund_core::host::Record;
            fixture().intent.sha256().unwrap()
        },
        "4ef88db2456d8730ebe668c2927a0d20dde8a665d8b419cfd1cb479ce060aa46"
    );
}

#[test]
fn provenance_is_immutable_and_thin_approvals_are_not_standalone_warrants() {
    let original = fixture();
    let mut changed = original.clone();
    changed.command.argv.push("changed".into());
    assert!(CanonicalWarrant::new(changed).is_err());
    let mut thin = original.clone();
    thin.request_origin = "daemon_expanded_thin".into();
    assert!(CanonicalWarrant::new(thin.clone()).is_err());
    thin.approval_exec_id = Some(EXEC_ID.into());
    let csr = Csr::new(thin.clone()).unwrap();
    assert!(csr.warrant().require_client_full().is_err());
    let approval = ApprovalRequest::new(EXEC_ID.into(), "root-test".into(), &csr).unwrap();
    let envelope = signed(thin.clone());
    assert!(
        approval
            .bind_response(&ApprovalResponse::Approved {
                exec_id: EXEC_ID.into(),
                dsse_envelope: envelope.clone()
            })
            .is_ok()
    );
    for mode in ["full_csr", "signed"] {
        let value = if mode == "full_csr" {
            json!({"version":"3.0","mode":mode,"tty_mode":"stdio","caller_env":{},"csr_payload":String::from_utf8(csr.as_bytes().to_vec()).unwrap()})
        } else {
            json!({"version":"3.0","mode":mode,"tty_mode":"stdio","caller_env":{},"dsse_envelope":envelope})
        };
        assert!(ClientHello::parse_request(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    thin.policy.mode = "time_range".into();
    thin.intent_sha256 = sigrund_core::host::Record::sha256(&thin.intent).unwrap();
    assert!(CanonicalWarrant::new(thin).is_err());
    let mut full = original;
    full.approval_exec_id = Some(EXEC_ID.into());
    assert!(CanonicalWarrant::new(full).is_err());
}

#[test]
fn v2_versions_and_decision_schemas_never_negotiate_legacy_behavior() {
    let hello = serde_json::to_value(unsigned()).unwrap();
    for version in [
        Value::Null,
        json!("1.0"),
        json!("1.2"),
        json!("2.0"),
        json!(2),
    ] {
        let mut value = hello.clone();
        value["version"] = version;
        assert!(ClientHello::parse_request(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut value = hello;
    value.as_object_mut().unwrap().remove("version");
    assert!(ClientHello::parse_request(&serde_json::to_vec(&value).unwrap()).is_err());
    for status in ["APPROVED", "REJECTED", "TIMEOUT"] {
        let value = json!({"exec_id":EXEC_ID,"status":status});
        let decision: Decision = parse_strict(&serde_json::to_vec(&value).unwrap()).unwrap();
        decision.validate().unwrap();
        for key in ["csr_payload", "message", "reason"] {
            let mut extra = value.clone();
            extra[key] = json!("private");
            assert!(parse_strict::<Decision>(&serde_json::to_vec(&extra).unwrap()).is_err());
        }
    }
    for status in ["TIMEOUT_CSR", "READY_TO_EXEC", "POLICY_VIOLATION"] {
        assert!(
            Decision {
                exec_id: EXEC_ID.into(),
                status: status.into()
            }
            .validate()
            .is_err()
        );
    }
    for version in ["1.0", "1.1", "1.2", "2.0", "4.0"] {
        let mut w = fixture();
        w.version = version.into();
        assert!(CanonicalWarrant::new(w).is_err());
    }
}

#[test]
fn legacy_and_unknown_database_versions_remain_untouched() {
    for version in [0, 1, 2, 4] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch(&format!("CREATE TABLE legacy(value TEXT); PRAGMA user_version={version}; INSERT INTO legacy VALUES ('preserve');")).unwrap();
        drop(db);
        let before = sha256_hex(&std::fs::read(&path).unwrap());
        assert!(StateStore::open(&path).is_err());
        assert_eq!(before, sha256_hex(&std::fs::read(&path).unwrap()));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(StateStore::create(&path).is_err());
        assert_eq!(before, sha256_hex(&std::fs::read(&path).unwrap()));
    }
}
