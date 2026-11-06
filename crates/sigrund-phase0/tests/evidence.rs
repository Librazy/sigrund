//! Synthetic checker inputs exercise completeness; they are not platform evidence.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn fixture(directory: &Path) -> Value {
    let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/namespace-phase0");
    let mut hashes = serde_json::Map::new();
    for entry in fs::read_dir(&sources).unwrap() {
        let entry = entry.unwrap();
        if entry.path().is_file() {
            hashes.insert(
                entry.file_name().into_string().unwrap(),
                json!(digest(&fs::read(entry.path()).unwrap())),
            );
        }
    }
    let acquisition = include_bytes!("fixtures/acquisition.json");
    let record: Value = serde_json::from_slice(acquisition).unwrap();
    let names: Vec<String> = serde_json::from_str(include_str!(
        "../../../scripts/namespace-phase0/required-cases.json"
    ))
    .unwrap();
    let cases: Vec<_> = names
        .into_iter()
        .map(|name| {
            fs::write(
                directory.join(format!("{name}.acquisition.json")),
                acquisition,
            )
            .unwrap();
            json!({"name": name, "result": "passed", "acquisition_sha256": digest(acquisition)})
        })
        .collect();
    for name in ["probe", "workload"] {
        fs::write(directory.join(name), b"synthetic binary").unwrap();
    }
    json!({
        "schema": "sigrund.phase0-evidence.v1", "result": "passed",
        "source_unchanged": true, "source_sha256": hashes,
        "runner_sha256": digest(&fs::read(sources.join("../verify-namespace-phase0.py")).unwrap()),
        "daemon_epoch": record["daemon_epoch"], "cases": cases,
        "binaries": {"probe": digest(b"synthetic binary"), "workload": digest(b"synthetic binary")}
    })
}

fn check(directory: &Path, manifest: &Value) -> std::process::Output {
    fs::write(
        directory.join("evidence.json"),
        serde_json::to_vec(manifest).unwrap(),
    )
    .unwrap();
    Command::new(env!("CARGO_BIN_EXE_sigrund-phase0-contract"))
        .arg("evidence")
        .arg(directory)
        .output()
        .unwrap()
}

#[test]
fn incomplete_or_modified_evidence_cannot_pass_independent_validation() {
    let directory = tempfile::tempdir().unwrap();
    let original = fixture(directory.path());
    let output = check(directory.path(), &original);
    assert!(output.status.success(), "{:?}", output);

    for mutation in [
        "missing sources",
        "missing source",
        "changed source",
        "changed runner",
        "missing case",
        "duplicate case",
        "failed case",
        "missing acquisition",
        "invalid acquisition digest",
        "wrong epoch",
        "changed binary",
        "changed acquisition",
    ] {
        let mut manifest = original.clone();
        match mutation {
            "missing sources" => manifest["source_sha256"] = json!({}),
            "missing source" => {
                manifest["source_sha256"]
                    .as_object_mut()
                    .unwrap()
                    .remove("probe.c");
            }
            "changed source" => manifest["source_sha256"]["probe.c"] = json!("00".repeat(32)),
            "changed runner" => manifest["runner_sha256"] = json!("00".repeat(32)),
            "missing case" => {
                manifest["cases"].as_array_mut().unwrap().pop();
            }
            "duplicate case" => manifest["cases"][1] = manifest["cases"][0].clone(),
            "failed case" => manifest["cases"][0]["result"] = json!("failed"),
            "missing acquisition" => {
                for case in manifest["cases"].as_array_mut().unwrap() {
                    case.as_object_mut().unwrap().remove("acquisition_sha256");
                }
            }
            "invalid acquisition digest" => {
                manifest["cases"][4]["acquisition_sha256"] = Value::Null
            }
            "wrong epoch" => {
                manifest["daemon_epoch"] = json!("0192d8f4-0000-7000-8000-000000000003")
            }
            "changed binary" => manifest["binaries"]["probe"] = json!("00".repeat(32)),
            "changed acquisition" => {
                manifest["cases"][0]["acquisition_sha256"] = json!("00".repeat(32))
            }
            _ => unreachable!(),
        }
        assert!(
            !check(directory.path(), &manifest).status.success(),
            "accepted {mutation}"
        );
    }
}
