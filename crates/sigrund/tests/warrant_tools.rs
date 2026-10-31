use base64::{Engine as _, engine::general_purpose::STANDARD};
use sigrund::{cli::RequestOptions, warrant_tools::pack_warrant};
use sigrund_core::{
    crypto::{WARRANT_PAYLOAD_TYPE, pae, verify_ssh_signature},
    protocol::DsseEnvelope,
    warrant::{Csr, CsrIdentity, SnapshotDigests},
};
use std::{fs, path::Path, process::Command};

fn csr() -> Csr {
    let hello = RequestOptions::default()
        .hello(&["/usr/bin/id".into(), "-u".into()], Path::new("/"))
        .unwrap();
    Csr::from_unsigned(
        &hello,
        CsrIdentity {
            grant_id: "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f".into(),
            host_id: format!("sigrun-host:sha256:{}", "0".repeat(64)),
            requester_uid: 1001,
            requester_gid: 1001,
            now: 1000,
        },
        SnapshotDigests {
            executable_sha256: "0".repeat(64),
            stdin_sha256: None,
        },
        3600,
    )
    .unwrap()
}

#[test]
fn offline_cli_preserves_daemon_csr_and_openssh_signature_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let path = |name| temp.path().join(name);
    let csr = csr();
    let status = serde_json::json!({"exec_id":csr.warrant().grant_id,"status":"TIMEOUT_CSR",
        "message":"No approver", "csr_payload":std::str::from_utf8(csr.as_bytes()).unwrap()});
    fs::write(path("status"), serde_json::to_vec(&status).unwrap()).unwrap();
    let ctl = env!("CARGO_BIN_EXE_sigrundctl");
    let prepare = || {
        Command::new(ctl)
            .args(["csr-pae", "--status"])
            .arg(path("status"))
            .arg("--csr")
            .arg(path("csr"))
            .arg("--pae")
            .arg(path("pae"))
            .output()
            .unwrap()
    };
    assert!(prepare().status.success());
    assert_eq!(fs::read(path("csr")).unwrap(), csr.as_bytes());
    assert_eq!(
        fs::read(path("pae")).unwrap(),
        pae(WARRANT_PAYLOAD_TYPE, csr.as_bytes())
    );
    assert!(
        !prepare().status.success(),
        "must not overwrite existing files"
    );
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(path("key"))
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("ssh-keygen")
            .args([
                "-Y",
                "sign",
                "-n",
                "sigrun.warrant.v1",
                "-O",
                "hashalg=sha512",
                "-f"
            ])
            .arg(path("key"))
            .arg(path("pae"))
            .output()
            .unwrap()
            .status
            .success()
    );
    let packed = Command::new(ctl)
        .arg("pack-warrant")
        .arg("--csr")
        .arg(path("csr"))
        .arg("--signature")
        .arg(path("pae.sig"))
        .args(["--signer-id", "mvp-root", "--output"])
        .arg(path("envelope"))
        .output()
        .unwrap();
    assert!(
        packed.status.success(),
        "{}",
        String::from_utf8_lossy(&packed.stderr)
    );
    let envelope = DsseEnvelope::parse_jcs(&fs::read(path("envelope")).unwrap()).unwrap();
    assert_eq!(STANDARD.decode(envelope.payload).unwrap(), csr.as_bytes());
    verify_ssh_signature(
        "ssh-ed25519",
        &fs::read_to_string(path("key.pub")).unwrap(),
        &envelope.signatures[0].sig,
        WARRANT_PAYLOAD_TYPE,
        csr.as_bytes(),
        false,
        false,
    )
    .unwrap();
    assert!(
        Command::new("ssh-keygen")
            .args([
                "-Y",
                "sign",
                "-n",
                "wrong-namespace",
                "-O",
                "hashalg=sha512",
                "-f"
            ])
            .arg(path("key"))
            .arg(path("csr"))
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        pack_warrant(
            csr.as_bytes(),
            &fs::read(path("csr.sig")).unwrap(),
            "mvp-root"
        )
        .is_err()
    );
    let mut changed = csr.warrant().clone();
    changed.command.argv.push("extra".into());
    let changed = Csr::new(changed).unwrap();
    assert!(
        pack_warrant(
            changed.as_bytes(),
            &fs::read(path("pae.sig")).unwrap(),
            "mvp-root"
        )
        .is_err()
    );
}

#[test]
fn offline_extraction_rejects_ambiguous_status_and_noncanonical_csr() {
    use sigrund::warrant_tools::extract_csr;
    let csr = csr();
    for status in ["REJECTED", "READY_TO_EXEC"] {
        let bytes = serde_json::to_vec(&serde_json::json!({"exec_id":csr.warrant().grant_id,
            "status":status,"message":"", "csr_payload":null}))
        .unwrap();
        assert!(extract_csr(&bytes).is_err());
    }
    let payload = std::str::from_utf8(csr.as_bytes()).unwrap();
    let bytes = serde_json::to_vec(&serde_json::json!({"exec_id":csr.warrant().grant_id,
        "status":"TIMEOUT_CSR","message":"", "csr_payload":format!("{payload}\n")}))
    .unwrap();
    assert!(extract_csr(&bytes).is_err());
    assert!(extract_csr(br#"{"status":"TIMEOUT_CSR","status":"TIMEOUT_CSR"}"#).is_err());
    assert!(extract_csr(br#"{}{}"#).is_err());
}
