//! Root-controlled epoch records. The daemon retains an exclusive lock on the
//! same inode for its lifetime. Consumers reject unlocked or replaced records.
use serde::{Deserialize, Serialize};
use sigrund_core::{
    crypto::{sha256_hex, validate_uuidv7},
    host::{BindingBundle, Record},
    json,
    warrant::Csr,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
    sync::{Arc, Mutex},
};
const MAX_BYTES: u64 = 1_048_576;
pub const DEFAULT_EPOCH_FILE: &str = "/var/lib/sigrund/host-epoch.json";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Epoch {
    version: String,
    bundles: Vec<BindingBundle>,
    review: Option<ReviewEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_review: Option<sigrund_core::namespace::ProcessReview>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewEvidence {
    exec_id: String,
    csr_sha256: String,
    admin_trusted_composefs: bool,
}
fn invalid(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}
fn validate(epoch: &Epoch) -> io::Result<()> {
    if epoch.version != "3.0" || epoch.bundles.is_empty() || epoch.bundles.len() > 16 {
        return Err(invalid("invalid epoch registry"));
    }
    if let Some(review) = &epoch.review {
        validate_uuidv7(&review.exec_id).map_err(invalid)?;
        if review.csr_sha256.len() != 64
            || !review
                .csr_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("invalid review digest"));
        }
    }
    if let Some(review) = &epoch.process_review {
        use sigrund_core::namespace::Contract;
        review.validate().map_err(invalid)?;
        if epoch.review.is_some()
            || review.acquisition.daemon_epoch != epoch.bundles[0].acquisition.daemon_epoch
        {
            return Err(invalid("mixed process review epoch"));
        }
    }
    for (i, bundle) in epoch.bundles.iter().enumerate() {
        bundle.validate().map_err(invalid)?;
        if bundle.host_id != epoch.bundles[0].host_id
            || bundle.acquisition != epoch.bundles[0].acquisition
            || epoch.bundles[..i]
                .iter()
                .any(|b| b.constraints.profile_id == bundle.constraints.profile_id)
        {
            return Err(invalid("mixed epoch or duplicate profile"));
        }
    }
    Ok(())
}
pub struct EpochOwner {
    data: Mutex<(File, Epoch)>,
}
impl EpochOwner {
    pub fn publish(parent: &File, bundles: Vec<BindingBundle>) -> io::Result<Arc<Self>> {
        crate::startup::check_root_metadata(parent, true, None)?;
        let pinned =
            Path::new(&format!("/proc/self/fd/{}", parent.as_raw_fd())).join("host-epoch.json");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(pinned)?;
        crate::startup::check_root_metadata(&file, false, Some(0o600))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let epoch = Epoch {
            version: "3.0".into(),
            bundles,
            review: None,
            process_review: None,
        };
        validate(&epoch)?;
        let bytes = json::canonical_bytes(&epoch).map_err(invalid)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(invalid("epoch record exceeds bound"));
        }
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(format!("/proc/self/fd/{}", parent.as_raw_fd()))?.sync_all()?;
        Ok(Arc::new(Self {
            data: Mutex::new((file, epoch)),
        }))
    }
    /// Worker-only publication before dispatch; no extra fields enter the
    /// broker wire document. A single bounded record matches its exact CSR.
    pub fn publish_review(
        &self,
        exec_id: &str,
        csr: &Csr,
        admin_trusted_composefs: bool,
    ) -> io::Result<()> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| invalid("epoch owner poisoned"))?;
        let (file, epoch) = &mut *data;
        let bundle = epoch
            .bundles
            .iter()
            .find(|b| b.constraints.profile_id == csr.warrant().intent.security_profile)
            .ok_or_else(|| invalid("review profile unavailable"))?;
        csr.warrant().verify_bundle(bundle).map_err(invalid)?;
        if admin_trusted_composefs
            && bundle.constraints.executable_model
                != sigrund_core::executable::TrustModel::DigestDirect
        {
            return Err(invalid("ComposeFS review requires direct digest"));
        }
        epoch.process_review = None;
        epoch.review = Some(ReviewEvidence {
            exec_id: exec_id.into(),
            csr_sha256: sha256_hex(csr.as_bytes()),
            admin_trusted_composefs,
        });
        validate(epoch)?;
        let bytes = json::canonical_bytes(epoch).map_err(invalid)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(invalid("epoch record exceeds bound"));
        }
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.set_len(bytes.len() as u64)?;
        file.sync_all()
    }
    pub fn publish_process_review(
        &self,
        review: &sigrund_core::namespace::ProcessReview,
        csr: &Csr,
    ) -> io::Result<()> {
        review.verify_csr(csr).map_err(invalid)?;
        let mut data = self
            .data
            .lock()
            .map_err(|_| invalid("epoch owner poisoned"))?;
        let (file, epoch) = &mut *data;
        if csr.warrant().host_id != epoch.bundles[0].host_id
            || review.acquisition.daemon_epoch != epoch.bundles[0].acquisition.daemon_epoch
        {
            return Err(invalid("process review authority differs from live epoch"));
        }
        epoch.review = None;
        epoch.process_review = Some(review.clone());
        validate(epoch)?;
        let bytes = json::canonical_bytes(epoch).map_err(invalid)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(invalid("epoch record exceeds bound"));
        }
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.set_len(bytes.len() as u64)?;
        file.sync_all()
    }
}
fn live_epoch(path: &Path) -> io::Result<Epoch> {
    let mut file = crate::startup::open_pinned(path)?;
    crate::startup::check_root_metadata(&file, false, Some(0o600))?;
    require_live(&file)?;
    let mut bytes = Vec::new();
    (&mut file).take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("epoch record exceeds bound"));
    }
    json::preflight(&bytes, 16, 4096).map_err(invalid)?;
    let epoch: Epoch = serde_json::from_slice(&bytes).map_err(invalid)?;
    validate(&epoch)?;
    require_live(&file)?;
    Ok(epoch)
}
pub fn live_bundle(path: &Path, profile: &str) -> io::Result<BindingBundle> {
    live_epoch(path)?
        .bundles
        .into_iter()
        .find(|b| b.constraints.profile_id == profile)
        .ok_or_else(|| invalid("profile unavailable in live epoch"))
}
pub fn live_review(path: &Path, exec_id: &str, csr: &Csr) -> io::Result<(BindingBundle, bool)> {
    let epoch = live_epoch(path)?;
    let review = epoch
        .review
        .ok_or_else(|| invalid("missing private review evidence"))?;
    if review.exec_id != exec_id || review.csr_sha256 != sha256_hex(csr.as_bytes()) {
        return Err(invalid("private review evidence does not match CSR"));
    }
    let bundle = epoch
        .bundles
        .into_iter()
        .find(|b| b.constraints.profile_id == csr.warrant().intent.security_profile)
        .ok_or_else(|| invalid("review profile unavailable"))?;
    csr.warrant().verify_bundle(&bundle).map_err(invalid)?;
    if review.admin_trusted_composefs
        && bundle.constraints.executable_model != sigrund_core::executable::TrustModel::DigestDirect
    {
        return Err(invalid("invalid review storage basis"));
    }
    Ok((bundle, review.admin_trusted_composefs))
}

pub fn live_process_review(
    path: &Path,
    exec_id: &str,
    csr: &Csr,
) -> io::Result<sigrund_core::namespace::ProcessReview> {
    let epoch = live_epoch(path)?;
    if csr.warrant().host_id != epoch.bundles[0].host_id {
        return Err(invalid("process review authority differs"));
    }
    let review = epoch
        .process_review
        .ok_or_else(|| invalid("missing process review"))?;
    if review.exec_id != exec_id {
        return Err(invalid("process review execution ID differs"));
    }
    review.verify_csr(csr).map_err(invalid)?;
    Ok(review)
}

fn require_live(file: &File) -> io::Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        return Err(invalid("daemon epoch is no longer live"));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires initial-userns root; included in the privileged Phase 1 gate"]
    fn epoch_registry_requires_live_owner_and_exact_private_review() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let dir = tempfile::tempdir().unwrap();
        let roots = vec![dir.path().to_path_buf()];
        let target = crate::host_target::HostTarget::acquire(
            &roots,
            &sigrund_core::host_budget::Budget::new(Default::default()).unwrap(),
        )
        .unwrap();
        let constraints = sigrund_core::host::Constraints::parse(include_bytes!(
            "../../sigrund-core/tests/fixtures/v3-host/constraints.json"
        ))
        .unwrap();
        let bundle = target
            .bundle(
                format!("sigrun-host:sha256:{}", "1".repeat(64)),
                constraints,
            )
            .unwrap();
        let epoch =
            EpochOwner::publish(&File::open(dir.path()).unwrap(), vec![bundle.clone()]).unwrap();
        let path = dir.path().join("host-epoch.json");
        assert_eq!(live_bundle(&path, "host-baseline").unwrap(), bundle);
        let mut w = sigrund_core::v3::Warrant::parse_canonical(include_bytes!(
            "../../sigrund-core/tests/fixtures/v3-host/warrant.json"
        ))
        .unwrap();
        w.host_id = bundle.host_id.clone();
        w.target_binding = bundle.target_binding.clone();
        let csr = Csr::new(w).unwrap();
        let exec_id = sigrund_core::crypto::new_uuidv7().to_string();
        assert!(live_review(&path, &exec_id, &csr).is_err());
        epoch.publish_review(&exec_id, &csr, false).unwrap();
        assert_eq!(
            live_review(&path, &exec_id, &csr).unwrap(),
            (bundle.clone(), false)
        );
        assert!(live_review(&path, &sigrund_core::crypto::new_uuidv7().to_string(), &csr).is_err());
        let mut changed = csr.warrant().clone();
        changed
            .command
            .argv
            .push("changed after publication".into());
        changed.intent.command.argv = changed.command.argv.clone();
        changed.intent_sha256 = changed.intent.sha256().unwrap();
        assert!(live_review(&path, &exec_id, &Csr::new(changed).unwrap()).is_err());
        assert!(epoch.publish_review(&exec_id, &csr, true).is_err());
        let original = std::fs::read(&path).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["bundles"][0]["constraints"]["pids_max"] = 64.into();
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(live_review(&path, &exec_id, &csr).is_err());
        std::fs::write(&path, original).unwrap();
        drop(epoch);
        assert!(live_bundle(&path, "host-baseline").is_err());
        assert!(live_review(&path, &exec_id, &csr).is_err());
    }
}
