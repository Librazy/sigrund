//! Administrator-maintained OSTree ComposeFS, not generic OverlayFS support.
//!
//! OSTree detaches its EROFS metadata mount after constructing the root mount.
//! Its printed lowerdir is therefore not a reopenable path. We trust the host
//! administrator's boot-created metadata mount, and inspect the entire reachable
//! data-only object store before enrolling that root mount. Administrators must
//! preserve object protection and never modify active objects in place. This is
//! not an fs-verity claim and does not provide executable write exclusion.
use crate::{linux, startup, transport::invalid};
use std::{
    fs::{self, File},
    io::{self, Read},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const OVERLAY: u64 = 0x794c7630;
const DATA: &str = "/sysroot/ostree/repo/objects";
const LOWER: &str = "/run/ostree/.private/cfsroot-lower";
const MAX_MOUNTINFO: u64 = 4 * 1024 * 1024;
const MAX_OBJECTS: usize = 250_000;

/// Retaining both trees also prevents reuse of their mount identities.
pub(crate) struct Enrollment {
    pub mount_id: u64,
    _root: File,
    _data: File,
}

pub(crate) fn mount_id(file: &File) -> io::Result<u64> {
    let mut stat: libc::statx = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID,
            &mut stat,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if stat.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(invalid("mount identity is unavailable"));
    }
    Ok(stat.stx_mnt_id)
}

fn host_namespace() -> io::Result<bool> {
    if fs::read_to_string("/proc/self/uid_map")?
        .split_whitespace()
        .collect::<Vec<_>>()
        != ["0", "0", "4294967295"]
    {
        return Ok(false);
    }
    for namespace in ["mnt", "user"] {
        let own = fs::metadata(format!("/proc/self/ns/{namespace}"))?;
        let init = fs::metadata(format!("/proc/1/ns/{namespace}"))?;
        if (own.dev(), own.ino()) != (init.dev(), init.ino()) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn root_mount(line: &str) -> Option<u64> {
    let (left, right) = line.split_once(" - ")?;
    let fields: Vec<_> = left.split_whitespace().collect();
    let tail: Vec<_> = right.split_whitespace().collect();
    if fields.len() < 6
        || tail.len() != 3
        || fields[3] != "/"
        || fields[4] != "/"
        || tail[0] != "overlay"
        || tail[1] != "composefs"
        || !fields[5].split(',').any(|v| v == "ro")
        || fields[5].split(',').any(|v| v == "rw")
    {
        return None;
    }
    let mut lower = None;
    let mut data = None;
    let mut metacopy = false;
    let mut readonly = false;
    for option in tail[2].split(',') {
        match option {
            "ro" => readonly = true,
            "metacopy=on" => metacopy = true,
            "seclabel" | "redirect_dir=on" | "index=off" | "uuid=off" | "uuid=on" | "xino=on"
            | "xino=off" | "xino=auto" | "nfs_export=off" | "verity=on" | "verity=off"
            | "verity=require" => (),
            _ => {
                if let Some(value) = option.strip_prefix("lowerdir+=") {
                    if lower.replace(value).is_some() {
                        return None;
                    }
                } else if let Some(value) = option.strip_prefix("datadir+=") {
                    if data.replace(value).is_some() {
                        return None;
                    }
                } else {
                    // Reject rw, upperdir, workdir, userxattr and unknown options.
                    let value = option.strip_prefix("lowerdir=")?;
                    let (l, d) = value.split_once("::")?;
                    if lower.replace(l).is_some() || data.replace(d).is_some() {
                        return None;
                    }
                }
            }
        }
    }
    if !readonly || !metacopy || lower != Some(LOWER) || data != Some(DATA) {
        return None;
    }
    fields[0].parse().ok().filter(|id| *id > 0)
}

fn trusted(file: &File) -> io::Result<bool> {
    let m = file.metadata()?;
    if m.uid() != 0 || m.mode() & 0o022 != 0 || !(m.is_dir() || m.is_file()) {
        return Ok(false);
    }
    // Reject extended ACLs, including default directory ACLs that could grant
    // access to newly installed objects. SELinux labels are unaffected.
    for name in [c"system.posix_acl_access", c"system.posix_acl_default"] {
        let n =
            unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if n >= 0 {
            return Ok(false);
        }
        if !matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENODATA | libc::EOPNOTSUPP)
        ) {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(true)
}

fn local_storage(file: &File) -> io::Result<bool> {
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut s) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(matches!(
        s.f_type as u64,
        0xef53 | 0xf2f52010 | 0x9123683e | 0x58465342
    ))
}

fn inspect_store(root: &File, deadline: Instant) -> io::Result<bool> {
    let id = mount_id(root)?;
    let mut pending = vec![(root.try_clone()?, 0usize)];
    let mut count = 0usize;
    while let Some((directory, depth)) = pending.pop() {
        if depth > 8 || !trusted(&directory)? || mount_id(&directory)? != id {
            return Ok(false);
        }
        for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
            count += 1;
            if count > MAX_OBJECTS || Instant::now() >= deadline {
                return Ok(false);
            }
            let entry = entry?;
            // Data-only layer lookup uses LOOKUP_NO_SYMLINKS and only accepts
            // regular files. OSTree also stores symlink objects in this tree.
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                continue;
            }
            if !kind.is_dir() && !kind.is_file() {
                return Ok(false);
            }
            let name = PathBuf::from(entry.file_name());
            let file: File = linux::openat2_executable(directory.as_raw_fd(), &name)?.into();
            if !trusted(&file)? || mount_id(&file)? != id {
                return Ok(false);
            }
            if file.metadata()?.is_dir() {
                pending.push((file, depth + 1));
            }
        }
    }
    Ok(true)
}

pub(crate) fn discover() -> io::Result<Option<Enrollment>> {
    if !host_namespace()? {
        return Ok(None);
    }
    let mut mounts = String::new();
    File::open("/proc/self/mountinfo")?
        .take(MAX_MOUNTINFO + 1)
        .read_to_string(&mut mounts)?;
    if mounts.len() as u64 > MAX_MOUNTINFO {
        return Ok(None);
    }
    let ids: Vec<_> = mounts.lines().filter_map(root_mount).collect();
    if ids.len() != 1 {
        return Ok(None);
    }
    let root = File::open("/")?;
    if mount_id(&root)? != ids[0] || !trusted(&root)? {
        return Ok(None);
    }
    // Inspect every ancestor, rather than just the final object-store directory.
    for path in ["/sysroot", "/sysroot/ostree", "/sysroot/ostree/repo"] {
        let directory = startup::open_pinned(Path::new(path))?;
        if !trusted(&directory)? || !local_storage(&directory)? {
            return Ok(None);
        }
    }
    let data = startup::open_pinned(Path::new(DATA))?;
    if !local_storage(&data)? || !inspect_store(&data, Instant::now() + Duration::from_secs(10))? {
        return Ok(None);
    }
    Ok(Some(Enrollment {
        mount_id: ids[0],
        _root: root,
        _data: data,
    }))
}

pub(crate) fn eligible(source: &File, mounts: &[u64]) -> io::Result<bool> {
    if mounts.is_empty() {
        return Ok(false);
    }
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(source.as_raw_fd(), &mut s) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut mount: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(source.as_raw_fd(), &mut mount) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if s.f_type as u64 != OVERLAY || mount.f_flag & libc::ST_RDONLY == 0 {
        return Ok(false);
    }
    if !mounts.contains(&mount_id(source)?) || !trusted(source)? {
        return Ok(false);
    }
    // Start with ordinary binaries. Overlay file-capability transitions need
    // their own validation before this eligibility path may admit them.
    let n = unsafe {
        libc::fgetxattr(
            source.as_raw_fd(),
            c"security.capability".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if n >= 0 {
        return Ok(false);
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ENODATA | libc::EOPNOTSUPP) => Ok(true),
        _ => Err(io::Error::last_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MOUNT: &str = "46 1 0:34 / / ro,relatime shared:1 - overlay composefs ro,seclabel,lowerdir+=/run/ostree/.private/cfsroot-lower,datadir+=/sysroot/ostree/repo/objects,redirect_dir=on,metacopy=on";

    #[test]
    fn recognizes_ostree_root_but_not_generic_or_writable_overlays() {
        assert_eq!(root_mount(MOUNT), Some(46));
        assert_eq!(
            root_mount(&MOUNT.replace(
                "lowerdir+=/run/ostree/.private/cfsroot-lower,datadir+=",
                "lowerdir=/run/ostree/.private/cfsroot-lower::"
            )),
            Some(46)
        );
        for bad in [
            MOUNT.replace("ro,", "rw,"),
            MOUNT.replace(" / / ", " / /mnt "),
            MOUNT.replace("overlay composefs", "overlay overlay"),
            MOUNT.replace(DATA, "/home/user/objects"),
            MOUNT.replace("metacopy=on", "metacopy=off"),
            format!("{MOUNT},upperdir=/tmp/upper"),
            format!("{MOUNT},userxattr"),
            format!("{MOUNT},datadir+=/tmp/data"),
            format!("{MOUNT},lowerdir+=/tmp/lower"),
        ] {
            assert_eq!(root_mount(&bad), None, "{bad}");
        }
    }

    #[test]
    fn unenrolled_files_never_qualify() {
        assert!(!eligible(&File::open("/usr/bin/env").unwrap(), &[]).unwrap());
    }

    #[test]
    fn writable_backing_objects_are_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let file = tempfile::tempfile().unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o666))
            .unwrap();
        assert!(!trusted(&file).unwrap());
    }

    #[test]
    #[ignore = "requires real root; exercised on the immutable guest"]
    fn privileged_store_protection_and_bounds() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let dir = tempfile::tempdir().unwrap();
        let directory = File::open(dir.path()).unwrap();
        let path = dir.path().join("object");
        fs::write(&path, b"content").unwrap();
        let object = File::open(&path).unwrap();
        let inspect =
            || inspect_store(&directory, Instant::now() + Duration::from_secs(2)).unwrap();
        assert!(inspect());
        object
            .set_permissions(fs::Permissions::from_mode(0o666))
            .unwrap();
        assert!(!inspect());
        object
            .set_permissions(fs::Permissions::from_mode(0o644))
            .unwrap();
        assert_eq!(unsafe { libc::fchown(object.as_raw_fd(), 1000, 1000) }, 0);
        assert!(!inspect());
        assert_eq!(unsafe { libc::fchown(object.as_raw_fd(), 0, 0) }, 0);
        // Even a read-only named ACL is excluded: metadata is intentionally
        // limited to ordinary POSIX modes for enrollment.
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (1u16, 6u16, u32::MAX),
            (2, 4, 1000),
            (4, 4, u32::MAX),
            (16, 4, u32::MAX),
            (32, 4, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&perm.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    object.as_raw_fd(),
                    c"system.posix_acl_access".as_ptr(),
                    acl.as_ptr().cast(),
                    acl.len(),
                    0,
                )
            },
            0
        );
        assert!(!inspect());
        assert_eq!(
            unsafe { libc::fremovexattr(object.as_raw_fd(), c"system.posix_acl_access".as_ptr()) },
            0
        );
        symlink("/does/not/exist", dir.path().join("symlink-object")).unwrap();
        assert!(inspect()); // Data-only lookup cannot use this symlink.
        directory
            .set_permissions(fs::Permissions::from_mode(0o777))
            .unwrap();
        assert!(!inspect());
        directory
            .set_permissions(fs::Permissions::from_mode(0o700))
            .unwrap();
        assert!(!inspect_store(&directory, Instant::now()).unwrap());
        assert!(inspect());
    }
}
