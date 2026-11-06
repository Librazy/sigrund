//! Offline experiment checker. It neither issues nor redeems a target binding.
use sha2::{Digest, Sha256};
use sigrund_phase0::contracts::{Acquisition, BindingBundle, Constraints, Contract, Intent};
use std::{collections::BTreeSet, fs::File, io::Read, path::Path};

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = vec![];
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("input exceeds checker bound".into());
    }
    Ok(bytes)
}
fn evidence(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = read(&path.join("evidence.json"), 1_048_576)?;
    // Evidence includes multiline OS/diagnostic strings. Protocol preflight
    // deliberately forbids those; only embedded acquisition records use it.
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value["schema"] != "sigrund.phase0-evidence.v1"
        || value["result"] != "passed"
        || value["source_unchanged"] != true
    {
        return Err("evidence is incomplete, failed or from changed sources".into());
    }
    let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/namespace-phase0");
    let recorded = value["source_sha256"]
        .as_object()
        .ok_or("missing source hashes")?;
    let source_names = std::fs::read_dir(&sources)?
        .filter_map(|entry| match entry {
            Ok(entry) if entry.path().is_file() => Some(Ok(entry.file_name())),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if source_names != recorded.keys().map(std::ffi::OsString::from).collect() {
        return Err("missing or unexpected prototype source hashes".into());
    }
    for (name, expected) in recorded {
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err("invalid source filename".into());
        }
        let bytes = read(&sources.join(name), 1_048_576)?;
        if format!("{:x}", Sha256::digest(bytes)) != *expected {
            return Err("prototype sources differ from evidence".into());
        }
    }
    let runner = read(&sources.join("../verify-namespace-phase0.py"), 1_048_576)?;
    if format!("{:x}", Sha256::digest(runner)) != value["runner_sha256"] {
        return Err("runner differs from evidence".into());
    }
    let expected: Vec<String> = serde_json::from_str(include_str!(
        "../../../../scripts/namespace-phase0/required-cases.json"
    ))?;
    let cases = value["cases"].as_array().ok_or("missing cases")?;
    let names: BTreeSet<_> = cases.iter().filter_map(|c| c["name"].as_str()).collect();
    if cases.len() != expected.len() || names != expected.iter().map(String::as_str).collect() {
        return Err("missing, duplicate or unexpected prototype cases".into());
    }
    for case in cases {
        if case["result"] != "passed" {
            return Err("failed case".into());
        }
        let name = case["name"].as_str().ok_or("invalid case name")?;
        // Rejected acquisition and anchor-loss cases intentionally have no
        // retained record. Successful captures and later setup faults must.
        let requires_acquisition = name.starts_with("route-")
            || name.starts_with("selinux-namespace-")
            || (name.starts_with("namespace-")
                && ((name.contains("-filtered0-") && !name.ends_with("-fault9"))
                    || name.contains("-filtered5-")));
        if requires_acquisition && case["acquisition_sha256"].as_str().is_none() {
            return Err("missing required acquisition digest".into());
        }
        if let Some(hash) = case["acquisition_sha256"].as_str() {
            let bytes = read(&path.join(format!("{name}.acquisition.json")), 65_536)?;
            let acquisition = Acquisition::parse(&bytes)?;
            if acquisition.canonical()? != bytes
                || acquisition.sha256()? != hash
                || acquisition.daemon_epoch != value["daemon_epoch"]
            {
                return Err("acquisition bytes/digest/epoch mismatch".into());
            }
        }
    }
    for name in ["probe", "workload"] {
        let bytes = read(&path.join(name), 16_777_216)?;
        if format!("{:x}", Sha256::digest(bytes)) != value["binaries"][name] {
            return Err("prototype binary digest mismatch".into());
        }
    }
    println!(
        "{} prototype cases and canonical acquisition records verified; no runtime qualification",
        cases.len()
    );
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [kind, path] = args.as_slice() else {
        return Err("usage: sigrund-phase0-contract acquisition|constraints|intent|bundle FILE | evidence DIRECTORY".into());
    };
    let path = Path::new(path);
    if kind == "evidence" {
        return evidence(path);
    }
    let bytes = read(path, 65_536)?;
    let hash = match kind.as_str() {
        "acquisition" => Acquisition::parse(&bytes)?.sha256()?,
        "constraints" => Constraints::parse(&bytes)?.sha256()?,
        "intent" => Intent::parse(&bytes)?.sha256()?,
        "bundle" => BindingBundle::parse(&bytes)?.sha256()?,
        _ => return Err("unknown contract type".into()),
    };
    println!("{hash}");
    Ok(())
}
