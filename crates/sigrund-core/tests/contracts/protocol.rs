use super::support::*;

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
