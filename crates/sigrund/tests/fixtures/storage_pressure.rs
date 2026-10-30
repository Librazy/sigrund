//! Exercise the sequencer's pressure latch through the real socket admission path.
use super::*;

#[test]
fn exit_gate() {
    let output = Command::new("unshare")
        .args(["--user", "--map-auto", "--map-root-user"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "storage_pressure::namespace_fixture",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SIGRUND_STORAGE_PRESSURE_NAMESPACE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "storage pressure namespace gate:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "invoked by the namespace exit gate"]
fn namespace_fixture() {
    assert_eq!(
        std::env::var("SIGRUND_STORAGE_PRESSURE_NAMESPACE").unwrap(),
        "1"
    );
    let fixture = Fixture::new();
    let high_water = 65_536;
    fs::write(
        &fixture.config,
        fs::read_to_string(&fixture.config).unwrap().replace(
            "audit_log_high_water_bytes = 1073741824",
            &format!("audit_log_high_water_bytes = {high_water}"),
        ),
    )
    .unwrap();

    // Start one byte below the limit with an authenticated, recoverable log.
    // The first actual rejection must cross the limit and close admission.
    let genesis: serde_json::Value =
        serde_json::from_str(fs::read_to_string(&fixture.log).unwrap().trim()).unwrap();
    let mut audit = sigrund_core::audit::AuditLog::open(
        &fixture.log,
        fixture.state.join("audit_ratchet.state"),
    )
    .unwrap();
    let overhead = serde_json::to_vec(&serde_json::json!({
        "entry_hmac": "0".repeat(64),
        "event_type": "PRESSURE_FIXTURE",
        "host_id": genesis["host_id"],
        "padding": "",
        "prev_record_sha256": audit.state().last_record_sha256,
        "seq": audit.state().seq,
    }))
    .unwrap()
    .len()
        + 1;
    let padding = high_water - 1 - fs::metadata(&fixture.log).unwrap().len() as usize - overhead;
    audit
        .append_event(
            "PRESSURE_FIXTURE",
            serde_json::json!({"padding": "x".repeat(padding)}),
            65_536,
        )
        .unwrap();
    drop(audit);
    assert_eq!(
        fs::metadata(&fixture.log).unwrap().len(),
        (high_water - 1) as u64
    );

    let daemon = fixture.launch();
    let before = fixture.diagnostic_count();
    let mut client = connect(&fixture.socket);
    send_rights(
        &client,
        &encode_frame(FrameType::ClientHello, b"{}").unwrap(),
        2,
    );
    assert_eq!(decision(&mut client).status, "INVALID_REQUEST");
    expect_closed(&mut client);
    fixture.wait_for_cleanup(before);
    wait_for(|| fs::metadata(&fixture.log).unwrap().len() >= high_water as u64);
    // Response delivery intentionally precedes durable auditing. Give its
    // state publication and capacity check time to finish without submitting
    // another durable operation that could mask a missing post-append check.
    thread::sleep(Duration::from_millis(100));
    let admissions = || {
        fs::read_to_string(&fixture.diagnostics)
            .unwrap()
            .lines()
            .filter(|line| line.contains("SOCKET_ADMITTED"))
            .count()
    };
    let admitted = admissions();
    let mut refused = connect(&fixture.socket);
    expect_closed(&mut refused);
    assert_eq!(admissions(), admitted, "pressure admitted a new request");
    daemon.stop();

    // The record which crossed the threshold must remain durable and valid.
    let recovered = sigrund_core::audit::AuditLog::open(
        &fixture.log,
        fixture.state.join("audit_ratchet.state"),
    )
    .unwrap();
    assert!(recovered.state().seq >= 3);
    assert!(
        fs::read_to_string(&fixture.log)
            .unwrap()
            .lines()
            .any(|line| {
                let record: serde_json::Value = serde_json::from_str(line).unwrap();
                record["event_type"] == "AUTH_REJECTED" && record["status"] == "INVALID_REQUEST"
            })
    );
}
