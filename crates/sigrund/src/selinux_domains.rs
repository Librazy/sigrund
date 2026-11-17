//! Host-administered domain registrations. Runtime uses immutable startup state.
use sigrund_core::{json::canonical_bytes, workload::RegisteredDomain};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
};

pub const REGISTRY: &str = "/etc/sigrund/selinux-domains.d";
fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}
fn secure_file(path: &Path, directory: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(
            libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | if directory {
                    libc::O_DIRECTORY
                } else {
                    libc::O_NONBLOCK
                },
        )
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Err(invalid(
            "registry paths must be root-owned and not group/other writable",
        ));
    }
    Ok(file)
}
fn registry() -> io::Result<PathBuf> {
    let path = Path::new(REGISTRY);
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        secure_file(ancestor, true)?;
    }
    Ok(path.into())
}
pub fn parse(bytes: &[u8]) -> io::Result<RegisteredDomain> {
    if bytes.len() > 65536 {
        return Err(invalid("oversized domain descriptor"));
    }
    let domain: RegisteredDomain =
        toml::from_str(std::str::from_utf8(bytes).map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
    domain.validate().map_err(io::Error::other)?;
    Ok(domain)
}
fn kernel_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { stat.assume_init() }.f_type != 0xf97cff8c {
        return Err(invalid("expected genuine selinuxfs"));
    }
    Ok(file)
}
pub fn policy_fingerprint(context: &str) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let guard = crate::lsm::PolicyGuard::open(context)?;
    let mut digest = Sha256::new();
    digest.update(b"sigrund.loaded-policy-snapshot.v1\0");
    let mut policy = kernel_file(Path::new("/sys/fs/selinux/policy"))?;
    let mut buffer = [0u8; 65536];
    loop {
        let count = policy.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let mut booleans = BTreeMap::new();
    for entry in fs::read_dir("/sys/fs/selinux/booleans")? {
        let entry = entry?;
        let mut text = String::new();
        kernel_file(&entry.path())?
            .take(128)
            .read_to_string(&mut text)?;
        let active = match text.split_whitespace().next() {
            Some("0") => false,
            Some("1") => true,
            _ => return Err(invalid("invalid active SELinux boolean")),
        };
        booleans.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("invalid boolean name"))?,
            active,
        );
    }
    digest.update(b"\0active-booleans\0");
    digest.update(canonical_bytes(&booleans).map_err(io::Error::other)?);
    guard.check()?;
    Ok(format!("{:x}", digest.finalize()))
}
pub fn check(domain: &RegisteredDomain) -> io::Result<()> {
    domain.validate().map_err(io::Error::other)?;
    let guard = crate::lsm::PolicyGuard::open(&domain.context)?;
    guard.verify_domain(crate::lsm::DAEMON_CONTEXT)?;
    for (source, target, class, permissions) in [
        (
            domain.context.as_str(),
            "system_u:object_r:sigrund_runtime_t:s0",
            "file",
            "entrypoint,execute,read,open,getattr,map",
        ),
        (
            crate::lsm::DAEMON_CONTEXT,
            domain.context.as_str(),
            "process",
            "transition,ptrace,signal,sigkill,sigstop,getattr",
        ),
        (
            crate::lsm::DAEMON_CONTEXT,
            domain.context.as_str(),
            "process2",
            "nnp_transition,nosuid_transition",
        ),
        (
            domain.context.as_str(),
            crate::lsm::DAEMON_CONTEXT,
            "fd",
            "use",
        ),
        (
            domain.context.as_str(),
            crate::lsm::DAEMON_CONTEXT,
            "file",
            "entrypoint,execute,read,open,map",
        ),
        (
            domain.context.as_str(),
            crate::lsm::REQUESTER_CONTEXT,
            "fd",
            "use",
        ),
        (
            domain.context.as_str(),
            crate::lsm::REQUESTER_CONTEXT,
            "fifo_file",
            "read,write,open,getattr",
        ),
    ] {
        crate::lsm::allowed(source, target, class, permissions).map_err(|error| io::Error::other(format!("required SELinux permission {source} -> {target}:{class} {{{permissions}}}: {error}")))?;
    }
    for (source, target, class, permissions) in [
        (
            crate::lsm::DAEMON_CONTEXT,
            domain.context.as_str(),
            "dir",
            "search,read,open,getattr",
        ),
        (
            crate::lsm::DAEMON_CONTEXT,
            domain.context.as_str(),
            "file",
            "read,open,getattr",
        ),
        (
            crate::lsm::DAEMON_CONTEXT,
            domain.context.as_str(),
            "lnk_file",
            "read,getattr",
        ),
        (
            domain.context.as_str(),
            crate::lsm::DAEMON_CONTEXT,
            "process",
            "sigchld",
        ),
        (
            domain.context.as_str(),
            "system_u:system_r:init_t:s0",
            "process",
            "sigchld",
        ),
        (
            domain.context.as_str(),
            crate::lsm::DAEMON_CONTEXT,
            "fifo_file",
            "read,write,open,getattr",
        ),
        (
            domain.context.as_str(),
            crate::lsm::REQUESTER_CONTEXT,
            "file",
            "read,write,append,getattr,ioctl",
        ),
        (
            domain.context.as_str(),
            domain.context.as_str(),
            "process",
            "fork,sigchld,signal,sigkill,sigstop,signull,getcap,getsched",
        ),
    ] {
        crate::lsm::allowed(source, target, class, permissions).map_err(|error| io::Error::other(format!("required SELinux permission {source} -> {target}:{class} {{{permissions}}}: {error}")))?;
    }
    for (source, target, class, permissions) in [
        (
            crate::lsm::REQUESTER_CONTEXT,
            domain.context.as_str(),
            "process",
            "transition,dyntransition,ptrace",
        ),
        (
            domain.context.as_str(),
            crate::lsm::DAEMON_CONTEXT,
            "process",
            "transition,dyntransition,ptrace",
        ),
    ] {
        crate::lsm::forbidden(source, target, class, permissions)?;
    }
    for socket in [
        "sigrund_execution_socket_t",
        "sigrund_context_socket_t",
        "sigrund_anchor_socket_t",
    ] {
        crate::lsm::forbidden(
            &domain.context,
            &format!("system_u:object_r:{socket}:s0"),
            "unix_stream_socket",
            "create,relabelfrom,relabelto",
        )?;
    }
    if policy_fingerprint(&domain.context)? != domain.policy_sha256 {
        return Err(invalid(
            "loaded policy fingerprint differs from registered policy",
        ));
    }
    guard.check()
}
fn administrator() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(invalid("host administrator required"));
    }
    // Initial user namespace, not a container's mapped root.
    if fs::read_to_string("/proc/self/uid_map")?
        .split_whitespace()
        .collect::<Vec<_>>()
        != ["0", "0", "4294967295"]
    {
        return Err(invalid("initial user namespace required"));
    }
    if fs::read_to_string("/proc/self/attr/current")?
        .split(':')
        .nth(2)
        == Some("sigrund_requester_t")
    {
        return Err(invalid("requester domain cannot manage registrations"));
    }
    Ok(())
}
pub fn register(domain: &RegisteredDomain, replace: bool) -> io::Result<()> {
    administrator()?;
    check(domain)?;
    if !Path::new(REGISTRY).exists() {
        fs::create_dir(REGISTRY)?;
        fs::set_permissions(REGISTRY, fs::Permissions::from_mode(0o755))?;
    }
    let directory = registry()?;
    let target = directory.join(format!("{}.toml", domain.id));
    let temporary = directory.join(format!(
        ".{}-{}",
        domain.id,
        sigrund_core::crypto::new_uuidv7()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(
            toml::to_string(domain)
                .map_err(io::Error::other)?
                .as_bytes(),
        )?;
        file.sync_all()?;
        if replace {
            fs::rename(&temporary, &target)?;
        } else {
            fs::hard_link(&temporary, &target)?;
            fs::remove_file(&temporary)?;
        }
        File::open(&directory)?.sync_all()
    })();
    let _ = fs::remove_file(temporary);
    result
}
pub fn list() -> io::Result<Vec<RegisteredDomain>> {
    let mut domains = Vec::new();
    for entry in fs::read_dir(registry()?)? {
        let path = entry?.path();
        if path.extension().is_none_or(|ext| ext.as_bytes() != b"toml") {
            continue;
        }
        let mut bytes = Vec::new();
        secure_file(&path, false)?
            .take(65537)
            .read_to_end(&mut bytes)?;
        let domain = parse(&bytes)?;
        if path.file_stem().and_then(|s| s.to_str()) != Some(&domain.id) {
            return Err(invalid("registration filename differs from ID"));
        }
        domains.push(domain);
    }
    domains.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(domains)
}
pub fn remove(id: &str) -> io::Result<()> {
    administrator()?;
    sigrund_core::host::identifier(id).map_err(io::Error::other)?;
    let directory = registry()?;
    let path = directory.join(format!("{id}.toml"));
    secure_file(&path, false)?;
    fs::remove_file(path)?;
    File::open(directory)?.sync_all()
}
pub fn export(domain: &RegisteredDomain) -> io::Result<serde_json::Value> {
    Ok(
        serde_json::json!({"descriptor":domain,"registration_sha256":domain.sha256().map_err(io::Error::other)?,"policy_sha256":domain.policy_sha256,"description_source":"administrator declaration; not a certified permission summary"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_rejects_symlinks_writable_and_nonregular_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, "test").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(secure_file(&link, false).is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(secure_file(&target, false).is_err());
        assert!(secure_file(dir.path(), false).is_err());
    }
    #[test]
    fn invalid_and_unknown_descriptors_fail_closed() {
        assert!(
            parse(include_bytes!(
                "../../../config/selinux-domain.toml.example"
            ))
            .is_err()
        );
        assert!(parse(&vec![b'x'; 65537]).is_err());
        let source = String::from_utf8(
            include_bytes!("../../../config/selinux-domain.toml.example").to_vec(),
        )
        .unwrap()
        .replace("REPLACE_WITH_CURRENT_POLICY_FINGERPRINT", &"a".repeat(64));
        let domain = parse(source.as_bytes()).unwrap();
        assert!(parse(format!("{source}\nunknown = true\n").as_bytes()).is_err());
        assert_eq!(
            export(&domain).unwrap()["registration_sha256"],
            domain.sha256().unwrap()
        );
    }
}
