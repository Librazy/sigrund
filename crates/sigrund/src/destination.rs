//! Bounded destination-file preparation primitives for the isolated target helper.
use sigrund_core::{
    host::{Account, credentials},
    namespace::{Acquisition, Contract},
};
use std::{
    fs::File,
    io::{self, Read},
    os::fd::AsRawFd,
    path::Path,
};

fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}

pub use sigrund_core::namespace::Credentials;

pub fn resolve(
    root: &File,
    account: &Account,
    acquisition: &Acquisition,
) -> io::Result<Credentials> {
    account.validate().map_err(io::Error::other)?;
    acquisition.validate().map_err(io::Error::other)?;
    let (uid, gid, groups) = match account {
        Account::Numeric {
            uid,
            gid,
            supplementary_gids,
        } => (*uid, *gid, supplementary_gids.clone()),
        Account::Name { name } => {
            let passwd = account_file(root, "etc/passwd")?;
            let group = account_file(root, "etc/group")?;
            crate::accounts::parse(name, &passwd, &group)?
        }
    };
    credentials(uid, gid, &groups).map_err(io::Error::other)?;
    acquisition
        .compose_credentials(uid, gid, groups)
        .map_err(io::Error::other)
}

fn regular(directory: &File, relative: &Path, no_xdev: bool) -> io::Result<File> {
    let pinned: File =
        crate::linux::open_relative(directory.as_raw_fd(), relative, libc::O_PATH, no_xdev)?.into();
    if !pinned.metadata()?.is_file() {
        return Err(invalid("destination source must be regular"));
    }
    // procfd follows this retained file object, never the target pathname.
    File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
}

fn account_file(root: &File, relative: &str) -> io::Result<String> {
    let file: File = regular(root, Path::new(relative), false)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("destination account source must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(1_048_577).read_to_end(&mut bytes)?;
    if bytes.len() > 1_048_576 {
        return Err(invalid("destination account file exceeds bound"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("destination account file is not UTF-8"))
}

/// Open only beneath the executable root already pinned by the instance owner.
pub fn executable(directory: &File, relative: &Path) -> io::Result<File> {
    let source: File = regular(directory, relative, true)?;
    if !source.metadata()?.is_file() {
        return Err(invalid("destination executable must be regular"));
    }
    Ok(source)
}

pub fn cwd(root: &File, path: &Path) -> io::Result<File> {
    crate::linux::validate_absolute_path(path)?;
    let relative = if path == Path::new("/") {
        return root.try_clone();
    } else {
        path.strip_prefix("/").map_err(io::Error::other)?
    };
    crate::linux::openat2_root(root.as_raw_fd(), relative).map(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn rejects_fifo_before_readable_open() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let path = std::ffi::CString::new(dir.path().join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let root = File::open(dir.path()).unwrap();
        assert!(regular(&root, Path::new("fifo"), false).is_err());
        let devices = File::open("/dev").unwrap();
        assert!(regular(&devices, Path::new("null"), false).is_err());
        assert!(executable(&root, Path::new("fifo")).is_err());
    }

    #[test]
    fn destination_account_and_paths_use_the_pinned_root() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("etc")).unwrap();
        std::fs::create_dir(directory.path().join("bin")).unwrap();
        std::fs::create_dir(directory.path().join("work")).unwrap();
        std::fs::write(
            directory.path().join("etc/passwd"),
            "destination_only:x:12001:12001::/work:/bin/tool\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("etc/group"),
            "extra:x:12002:destination_only\n",
        )
        .unwrap();
        std::fs::write(directory.path().join("bin/tool"), b"destination bytes").unwrap();
        let root = File::open(directory.path()).unwrap();
        let acquisition = Acquisition::parse(include_bytes!(
            "../../sigrund-phase0/tests/fixtures/acquisition.json"
        ))
        .unwrap();
        let account = Account::Name {
            name: "destination_only".into(),
        };
        let resolved = resolve(&root, &account, &acquisition).unwrap();
        assert_eq!(
            (resolved.uid, resolved.gid, resolved.groups.as_slice()),
            (12001, 12001, &[12002][..])
        );
        assert_ne!(resolved.host_uid, resolved.uid);
        let pinned_directory: File = crate::linux::openat2_root(root.as_raw_fd(), Path::new("bin"))
            .unwrap()
            .into();
        let mut source = executable(&pinned_directory, Path::new("tool")).unwrap();
        let mut bytes = Vec::new();
        source.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"destination bytes");
        assert!(
            cwd(&root, Path::new("/work"))
                .unwrap()
                .metadata()
                .unwrap()
                .is_dir()
        );
        assert!(
            resolve(
                &root,
                &Account::Numeric {
                    uid: 4_000_000_000,
                    gid: 1,
                    supplementary_gids: vec![]
                },
                &acquisition
            )
            .is_err()
        );
        std::fs::remove_file(directory.path().join("etc/passwd")).unwrap();
        symlink("/etc/passwd", directory.path().join("etc/passwd")).unwrap();
        assert!(resolve(&root, &account, &acquisition).is_err());
        assert!(
            cwd(&root, Path::new("/"))
                .unwrap()
                .metadata()
                .unwrap()
                .is_dir()
        );
        assert!(cwd(&root, Path::new("/../work")).is_err());
        assert!(executable(&pinned_directory, Path::new("../etc/passwd")).is_err());
    }
}
