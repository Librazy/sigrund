//! Initial-userns administrator-maintained container OverlayFS.
//!
//! This is a scoped digest_direct exception, never a claim of kernel write
//! exclusion on backing files. Trusted administrators must preserve layer
//! identities and prevent untrusted aliases/retained writers and in-place writes
//! to active backing objects. Printed layer names are discovery hints under that
//! contract, not a kernel-authenticated export of the backing paths.
use crate::{composefs::mount_id, destination_helper::identity, transport::invalid};
use sigrund_core::{
    host_budget::{Charge, Reservation},
    namespace::{ExecutableStorage, FsIdentity},
};
use std::{
    collections::VecDeque,
    ffi::CString,
    fs::File,
    io::{self},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, FileTypeExt, MetadataExt},
    },
    path::{Component, Path, PathBuf},
};

const OVERLAY: u64 = 0x794c7630;
const MAX_MOUNTINFO: usize = 4 * 1024 * 1024;
const MAX_LAYERS: usize = 128;
const MAX_LINKS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Layout {
    line: String,
    // Ordinary layers in lookup order; upper first, when present.
    layers: Vec<PathBuf>,
    data: Vec<PathBuf>,
    work: Option<PathBuf>,
    relative: PathBuf,
}
fn unescape(value: &str) -> io::Result<String> {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
        } else {
            let code = bytes
                .get(i + 1..i + 4)
                .ok_or_else(|| invalid("short mount escape"))?;
            let n = match code {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                b"072" => b':',
                b"054" => b',',
                _ => return Err(invalid("unsupported mount escape")),
            };
            out.push(n);
            i += 4;
        }
    }
    String::from_utf8(out).map_err(io::Error::other)
}
fn absolute(value: &str) -> io::Result<PathBuf> {
    let path = PathBuf::from(unescape(value)?);
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid("noncanonical overlay layer path"));
    }
    Ok(path)
}
fn mount_options(value: &str) -> io::Result<Vec<&str>> {
    // SELinux mount contexts may contain quoted commas (MCS categories).
    let mut quoted = false;
    let mut start = 0;
    let mut options = Vec::new();
    for (i, byte) in value.bytes().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                options.push(&value[start..i]);
                start = i + 1;
            }
            _ => (),
        }
    }
    if quoted {
        return Err(invalid("unterminated mount context"));
    }
    options.push(&value[start..]);
    Ok(options)
}
impl Layout {
    fn parse(text: &str, id: u64, executable: &Path) -> io::Result<Self> {
        let mut matches = text.lines().filter(|line| {
            line.split_whitespace()
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                == Some(id)
        });
        let line = matches
            .next()
            .ok_or_else(|| invalid("source mount missing from captured target"))?;
        if matches.next().is_some() {
            return Err(invalid("duplicate mount identity"));
        }
        let (head, tail) = line
            .split_once(" - ")
            .ok_or_else(|| invalid("invalid mount record"))?;
        let h: Vec<_> = head.split_whitespace().collect();
        let t: Vec<_> = tail.split_whitespace().collect();
        if h.len() < 6 || t.len() != 3 || t[0] != "overlay" || unescape(h[3])? != "/" {
            return Err(invalid("unsupported overlay mount root"));
        }
        let mountpoint = absolute(h[4])?;
        let relative = executable
            .strip_prefix(&mountpoint)
            .map_err(|_| invalid("executable outside source mount"))?
            .to_owned();
        if relative.as_os_str().is_empty() {
            return Err(invalid("empty executable path"));
        }
        let mut lower = Vec::new();
        let mut data = Vec::new();
        let mut upper = None;
        let mut work = None;
        let mut legacy = false;
        for option in mount_options(t[2])? {
            if let Some(value) = option.strip_prefix("lowerdir=") {
                if legacy || !lower.is_empty() || !data.is_empty() {
                    return Err(invalid("duplicate lower layers"));
                }
                legacy = true;
                let (ordinary, data_only) = value
                    .split_once("::")
                    .map_or((value, None), |(a, b)| (a, Some(b)));
                for name in ordinary.split(':') {
                    lower.push(absolute(name)?);
                }
                if let Some(names) = data_only {
                    for name in names.split("::") {
                        // Every data-only separator is double-colon. Literal
                        // colons in layer paths must be escaped by mountinfo.
                        if name.contains(':') {
                            return Err(invalid("invalid data-only boundary"));
                        }
                        data.push(absolute(name)?);
                    }
                }
            } else if let Some(value) = option.strip_prefix("lowerdir+=") {
                if legacy || !data.is_empty() {
                    return Err(invalid("ambiguous lower layer ordering"));
                }
                lower.push(absolute(value)?);
            } else if let Some(value) = option.strip_prefix("datadir+=") {
                if legacy || lower.is_empty() {
                    return Err(invalid("ambiguous data layers"));
                }
                data.push(absolute(value)?);
            } else if let Some(value) = option.strip_prefix("upperdir=") {
                if upper.replace(absolute(value)?).is_some() {
                    return Err(invalid("duplicate upper"));
                }
            } else if let Some(value) = option.strip_prefix("workdir=") {
                if work.replace(absolute(value)?).is_some() {
                    return Err(invalid("duplicate workdir"));
                }
            } else if ["context=", "fscontext=", "defcontext=", "rootcontext="]
                .iter()
                .any(|key| option.starts_with(key))
            {
                let (_, value) = option.split_once('=').expect("context option");
                let value = value
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .unwrap_or(value);
                if value.is_empty() || value.contains('"') {
                    return Err(invalid("invalid SELinux mount context"));
                }
                // Preserve the context in the layout digest. The ordinary LSM
                // execution checks still apply; no relabeling is performed.
            } else if !matches!(
                option,
                "ro" | "rw"
                    | "seclabel"
                    | "sync"
                    | "async"
                    | "dirsync"
                    | "index=on"
                    | "index=off"
                    | "metacopy=on"
                    | "metacopy=off"
                    | "redirect_dir=on"
                    | "redirect_dir=off"
                    | "redirect_dir=follow"
                    | "redirect_dir=nofollow"
                    | "redirect_always_follow=on"
                    | "redirect_always_follow=off"
                    | "xino=on"
                    | "xino=off"
                    | "xino=auto"
                    | "uuid=on"
                    | "uuid=off"
                    | "nfs_export=on"
                    | "nfs_export=off"
                    | "verity=on"
                    | "verity=off"
                    | "verity=require"
                    | "volatile"
                    | "nouserxattr"
            ) {
                return Err(invalid(format!("unsupported overlay option: {option}")));
            }
        }
        if lower.is_empty()
            || upper.is_some() != work.is_some()
            || lower.len() + data.len() + usize::from(upper.is_some()) > MAX_LAYERS
        {
            return Err(invalid(
                "unsupported overlay layer count or upper/work pair",
            ));
        }
        let mut layers = Vec::new();
        if let Some(upper) = upper {
            layers.push(upper);
        }
        layers.extend(lower);
        Ok(Self {
            line: line.to_owned(),
            layers,
            data,
            work,
            relative,
        })
    }
}

fn bounded(file: &File, max: usize) -> io::Result<String> {
    let mut text = String::new();
    // pread avoids sharing offsets between authorization and cleanup owners.
    let mut bytes = vec![0; max + 1];
    let mut used = 0;
    loop {
        let n = file.read_at(&mut bytes[used..], used as u64)?;
        used += n;
        if used > max {
            return Err(invalid("overlay evidence exceeds bound"));
        }
        if n == 0 {
            break;
        }
    }
    text.push_str(std::str::from_utf8(&bytes[..used]).map_err(io::Error::other)?);
    Ok(text)
}
fn xattr(file: &File, name: &str) -> io::Result<Option<Vec<u8>>> {
    let name = CString::new(name).map_err(io::Error::other)?;
    let mut bytes = vec![0; 4097];
    let count = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if count < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENODATA | libc::EOPNOTSUPP) => Ok(None),
            _ => Err(error),
        };
    }
    if count > 4096 {
        return Err(invalid("overlay xattr exceeds bound"));
    }
    bytes.truncate(count as usize);
    Ok(Some(bytes))
}
fn trusted(file: &File) -> io::Result<()> {
    if !crate::composefs::trusted(file)? {
        return Err(invalid("overlay backing is not root-managed"));
    }
    Ok(())
}
fn local(file: &File) -> io::Result<()> {
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if !matches!(
        s.f_type as u64,
        0xef53 | 0xf2f52010 | 0x9123683e | 0x58465342 | 0x01021994
    ) {
        return Err(invalid("unsupported overlay backing filesystem"));
    }
    if !crate::executable::host_capability_mount(file)? {
        return Err(invalid(
            "overlay backing idmapping is unavailable or unsupported",
        ));
    }
    Ok(())
}
pub(crate) fn is_overlay(file: &File) -> io::Result<bool> {
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut s) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(s.f_type as u64 == OVERLAY)
}

/// Open a management path with protected symlink traversal. Target file lookup
/// below a layer uses NO_SYMLINKS instead. Every relative symlink is resolved
/// from its pinned parent; absolute symlinks restart at the trusted host root.
fn management_path(
    path: &Path,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<(File, PathBuf)> {
    let mut todo: VecDeque<_> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(v) => Some(v.to_owned()),
            _ => None,
        })
        .collect();
    let mut current = File::open("/")?;
    trusted(&current)?;
    let mut canonical = PathBuf::from("/");
    let mut links = 0;
    while let Some(name) = todo.pop_front() {
        check()?;
        if name == "." {
            continue;
        }
        if name == ".." {
            let raw = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    c"..".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            current = unsafe { File::from_raw_fd(raw) };
            trusted(&current)?;
            canonical.pop();
            continue;
        }
        let name = CString::new(name.as_encoded_bytes()).map_err(io::Error::other)?;
        let raw = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let entry = unsafe { File::from_raw_fd(raw) };
        let m = entry.metadata()?;
        if m.file_type().is_symlink() {
            let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatfs(current.as_raw_fd(), &mut filesystem) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if filesystem.f_type as u64 == 0x9fa0 {
                return Err(invalid("magic management link"));
            }
            links += 1;
            if links > MAX_LINKS || m.uid() != 0 {
                return Err(invalid("untrusted management symlink"));
            }
            let mut buffer = [0u8; 4097];
            let n = unsafe {
                libc::readlinkat(
                    entry.as_raw_fd(),
                    c"".as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n as usize >= buffer.len() {
                return Err(invalid("management symlink exceeds bound"));
            }
            let target = PathBuf::from(
                std::str::from_utf8(&buffer[..n as usize]).map_err(io::Error::other)?,
            );
            if target.is_absolute() {
                current = File::open("/")?;
                canonical = PathBuf::from("/");
            }
            for component in target.components().rev() {
                match component {
                    Component::Normal(v) => todo.push_front(v.to_owned()),
                    Component::RootDir | Component::CurDir => (),
                    Component::ParentDir => todo.push_front("..".into()),
                    _ => return Err(invalid("noncanonical management symlink")),
                }
            }
        } else {
            let raw = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let opened = unsafe { File::from_raw_fd(raw) };
            if (opened.metadata()?.dev(), opened.metadata()?.ino()) != (m.dev(), m.ino()) {
                return Err(invalid("management path changed"));
            }
            trusted(&opened)?;
            canonical.push(std::str::from_utf8(name.as_bytes()).map_err(io::Error::other)?);
            current = opened;
        }
    }
    Ok((current, canonical))
}
struct Layer {
    file: File,
    path: PathBuf,
    identity: FsIdentity,
}
impl Layer {
    fn open(path: &Path, check: &impl Fn() -> io::Result<()>) -> io::Result<Self> {
        let (file, _) = management_path(path, check)?;
        local(&file)?;
        if !file.metadata()?.is_dir() {
            return Err(invalid("overlay layer is not a directory"));
        }
        let identity = identity(&file)?;
        Ok(Self {
            file,
            path: path.to_owned(),
            identity,
        })
    }
    fn revalidate(&self, check: &impl Fn() -> io::Result<()>) -> io::Result<()> {
        let (current, _) = management_path(&self.path, check)?;
        if identity(&current)? != self.identity {
            return Err(invalid("overlay layer identity changed"));
        }
        trusted(&self.file)?;
        local(&self.file)
    }
}
struct Found {
    file: Option<File>,
    next_path: PathBuf,
    opaque: bool,
}
fn safe_relative(path: &Path) -> io::Result<()> {
    if path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(invalid("invalid overlay redirect/path"));
    }
    Ok(())
}
fn redirected(value: &[u8], parent: &Path, suffix: &Path) -> io::Result<PathBuf> {
    let text = std::str::from_utf8(value).map_err(io::Error::other)?;
    let path = Path::new(text);
    let relative = path.strip_prefix("/").unwrap_or(path);
    safe_relative(relative)?;
    let result = if path.is_absolute() {
        relative.to_owned()
    } else {
        parent.join(relative)
    }
    .join(suffix);
    safe_relative(&result)?;
    Ok(result)
}
fn lookup(
    layer: &Layer,
    path: &Path,
    redirects: &mut usize,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<Found> {
    safe_relative(path)?;
    let parts: Vec<_> = path.components().map(|c| c.as_os_str()).collect();
    let mut directory = layer.file.try_clone()?;
    let mut prefix = PathBuf::new();
    let mut next_path = path.to_owned();
    let mut opaque = false;
    for (index, name) in parts.iter().enumerate() {
        check()?;
        let name = Path::new(name);
        let file = match crate::linux::openat2_executable(directory.as_raw_fd(), name) {
            Ok(fd) => File::from(fd),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                return Ok(Found {
                    file: None,
                    next_path,
                    opaque,
                });
            }
            Err(e) => return Err(e),
        };
        // O_NONBLOCK in openat2 prevents malicious special files from stalling.
        let m = file.metadata()?;
        if m.file_type().is_char_device() || xattr(&file, "trusted.overlay.whiteout")?.is_some() {
            return Err(invalid("overlay whiteout hides requested executable"));
        }
        trusted(&file)?;
        if mount_id(&file)?
            != layer
                .identity
                .mount_id
                .parse::<u64>()
                .map_err(io::Error::other)?
        {
            return Err(invalid("nested mount in overlay layer"));
        }
        if m.is_dir() {
            if let Some(value) = xattr(&file, "trusted.overlay.opaque")? {
                if value == b"y" {
                    opaque = true;
                } else if value != b"x" {
                    return Err(invalid("unknown overlay opaque marker"));
                }
            }
            if let Some(value) = xattr(&file, "trusted.overlay.redirect")? {
                *redirects += 1;
                if *redirects > MAX_LINKS {
                    return Err(invalid("overlay redirect limit"));
                }
                let suffix: PathBuf = parts[index + 1..].iter().collect();
                next_path = redirected(&value, &prefix, &suffix)?;
            }
            prefix.push(name);
            directory = file;
        } else if index + 1 == parts.len() && m.is_file() {
            return Ok(Found {
                file: Some(file),
                next_path,
                opaque,
            });
        } else {
            return Err(invalid("invalid overlay path component"));
        }
    }
    Err(invalid("executable resolved to a directory"))
}
fn resolve(
    layers: &[Layer],
    data: &[Layer],
    path: &Path,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<(File, File)> {
    let mut metadata = None;
    let mut current = path.to_owned();
    let mut redirects = 0;
    let mut data_redirect = false;
    for layer in layers {
        let found = lookup(layer, &current, &mut redirects, check)?;
        current = found.next_path;
        if let Some(file) = found.file {
            if metadata.is_none() {
                metadata = Some(file.try_clone()?);
            }
            if xattr(&file, "trusted.overlay.metacopy")?.is_none() {
                return Ok((metadata.expect("found metadata"), file));
            }
            if let Some(value) = xattr(&file, "trusted.overlay.redirect")? {
                redirects += 1;
                if redirects > MAX_LINKS {
                    return Err(invalid("overlay redirect limit"));
                }
                current = redirected(
                    &value,
                    current.parent().unwrap_or(Path::new("")),
                    Path::new(""),
                )?;
                data_redirect = true;
            }
        }
        if found.opaque {
            return Err(invalid("opaque overlay path has no data source"));
        }
    }
    if data_redirect {
        for layer in data {
            let found = lookup(layer, &current, &mut redirects, check)?;
            if let Some(file) = found.file {
                if xattr(&file, "trusted.overlay.metacopy")?.is_some() {
                    return Err(invalid("metacopy in data-only layer"));
                }
                return Ok((
                    metadata.ok_or_else(|| invalid("missing overlay metadata"))?,
                    file,
                ));
            }
        }
    }
    Err(invalid("overlay data source unavailable"))
}

struct MountView {
    info: File,
    // The target lease already pins this namespace. Retain its kernel ID
    // instead of duplicating the namespace FD for every executable.
    namespace: Option<u64>,
}
pub(crate) struct Enrollment {
    // Descriptors precede their budget reservation in destruction order.
    mount: MountView,
    layers: Vec<Layer>,
    data: Vec<Layer>,
    work: Option<Layer>,
    metadata: File,
    backing: File,
    layout: Layout,
    source_mount: u64,
    executable: PathBuf,
    evidence: ExecutableStorage,
    _reservation: Reservation,
}
impl Enrollment {
    pub(crate) fn discover(
        source: &File,
        executable: &Path,
        target: &crate::target_registry::TargetLease,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        crate::access::domain()?;
        crate::execution::validate_admin_userns(&target.namespace_files()?[6])?;
        let _discovery = target.reserve_resources(Charge {
            target_fds: 1,
            ..Default::default()
        })?;
        let mountinfo = File::open(format!("/proc/{}/mountinfo", target.acquisition().pid))?;
        let mut namespace_id = 0u64;
        // NS_GET_MNTNS_ID. statmount otherwise searches only the daemon's
        // current namespace, which cannot resolve a captured container mount.
        if unsafe {
            libc::ioctl(
                target.namespace_files()?[2].as_raw_fd(),
                0x8008_b705 as libc::c_ulong,
                &mut namespace_id,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if namespace_id == 0 {
            return Err(invalid("missing target mount namespace identity"));
        }
        let source_mount = mount_id(source)?;
        let layout = Layout::parse(
            &bounded(&mountinfo, MAX_MOUNTINFO)?,
            source_mount,
            executable,
        )?;
        let reservation = target.reserve_resources(Charge {
            target_fds: (layout.layers.len()
                + layout.data.len()
                + usize::from(layout.work.is_some())
                + 3) as u32,
            ..Default::default()
        })?;
        Self::open(
            source,
            executable,
            MountView {
                info: mountinfo,
                namespace: Some(namespace_id),
            },
            source_mount,
            layout,
            reservation,
            check,
        )
    }
    fn open(
        source: &File,
        executable: &Path,
        mount: MountView,
        source_mount: u64,
        layout: Layout,
        reservation: Reservation,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        let transient = reservation
            .budget_reserve(Charge {
                target_fds: 8,
                ..Default::default()
            })
            .ok_or(io::ErrorKind::WouldBlock)?;
        trusted(source)?;
        if !crate::executable::unmapped_mount(source, mount.namespace)? {
            return Err(invalid("idmapped overlay mount"));
        }
        let layers: Vec<_> = layout
            .layers
            .iter()
            .map(|p| Layer::open(p, check))
            .collect::<io::Result<_>>()?;
        let data: Vec<_> = layout
            .data
            .iter()
            .map(|p| Layer::open(p, check))
            .collect::<io::Result<_>>()?;
        let work = layout
            .work
            .as_ref()
            .map(|p| Layer::open(p, check))
            .transpose()?;
        let (metadata, backing) = resolve(&layers, &data, &layout.relative, check)?;
        let observed = source.metadata()?;
        let selected = metadata.metadata()?;
        if (observed.uid(), observed.gid(), observed.mode())
            != (selected.uid(), selected.gid(), selected.mode())
        {
            return Err(invalid("overlay metadata source differs"));
        }
        let evidence = ExecutableStorage {
            kind: "admin_trusted_overlayfs".into(),
            mount_id: source_mount.to_string(),
            layout_sha256: sigrund_core::crypto::sha256_hex(layout.line.as_bytes()),
            backing: identity(&backing)?,
            administrator_maintained: true,
        };
        let result = Self {
            mount,
            layers,
            data,
            work,
            metadata,
            backing,
            layout,
            source_mount,
            executable: executable.to_owned(),
            evidence,
            _reservation: reservation,
        };
        drop(transient);
        result.revalidate(source, check)?;
        Ok(result)
    }
    pub(crate) fn evidence(&self) -> &ExecutableStorage {
        &self.evidence
    }
    pub(crate) fn backing(&self) -> &File {
        &self.backing
    }
    pub(crate) fn verify_loaded(
        &self,
        pid: i32,
        source: &File,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let _transient = self
            ._reservation
            .budget_reserve(Charge {
                target_fds: 2,
                ..Default::default()
            })
            .ok_or(io::ErrorKind::WouldBlock)?;
        verify_loaded(pid, source, &self.backing, check)
    }
    pub(crate) fn revalidate(
        &self,
        source: &File,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let _transient = self
            ._reservation
            .budget_reserve(Charge {
                target_fds: 8,
                ..Default::default()
            })
            .ok_or(io::ErrorKind::WouldBlock)?;
        check()?;
        if mount_id(source)? != self.source_mount
            || Layout::parse(
                &bounded(&self.mount.info, MAX_MOUNTINFO)?,
                self.source_mount,
                &self.executable,
            )? != self.layout
        {
            return Err(invalid("overlay source layout changed"));
        }
        trusted(source)?;
        if !crate::executable::unmapped_mount(source, self.mount.namespace)? {
            return Err(invalid("overlay mount idmapping changed"));
        }
        for layer in self.layers.iter().chain(&self.data).chain(self.work.iter()) {
            layer.revalidate(check)?;
        }
        let (metadata, backing) = resolve(&self.layers, &self.data, &self.layout.relative, check)?;
        if identity(&metadata)? != identity(&self.metadata)?
            || identity(&backing)? != self.evidence.backing
        {
            return Err(invalid("overlay metadata/data object changed"));
        }
        trusted(&self.metadata)?;
        trusted(&self.backing)?;
        check()
    }
}

// Access to mmap backing identities is deliberately not inferred from maps or
// map_files: modern kernels expose file_user_inode/path there. Verify actual
// PT_LOAD bytes while the tracee is stopped, before any loader instructions.
pub(crate) fn verify_loaded(
    pid: i32,
    source: &File,
    backing: &File,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let mut header = [0u8; 64];
    backing.read_exact_at(&mut header, 0)?;
    if header[..6] != *b"\x7fELF\x02\x01" {
        return Err(invalid("overlay requires little-endian ELF64"));
    }
    let u16_at = |i| u16::from_le_bytes(header[i..i + 2].try_into().unwrap());
    let u64_at = |i| u64::from_le_bytes(header[i..i + 8].try_into().unwrap());
    if !matches!(u16_at(16), 2 | 3) || u16_at(54) != 56 || !(1..=256).contains(&u16_at(56)) {
        return Err(invalid("unsupported overlay ELF headers"));
    }
    let phoff = u64_at(32);
    let phnum = u16_at(56) as u64;
    let size = backing.metadata()?.len();
    if phoff.checked_add(phnum * 56).is_none_or(|n| n > size) {
        return Err(invalid("ELF program table out of bounds"));
    }
    let mut segments = Vec::new();
    for i in 0..phnum {
        check()?;
        let mut p = [0u8; 56];
        backing.read_exact_at(&mut p, phoff + i * 56)?;
        if u32::from_le_bytes(p[..4].try_into().unwrap()) != 1 {
            continue;
        }
        let get = |i| u64::from_le_bytes(p[i..i + 8].try_into().unwrap());
        let (offset, address, bytes, memory) = (get(8), get(16), get(32), get(40));
        if bytes > memory
            || offset.checked_add(bytes).is_none_or(|n| n > size)
            || address.checked_add(memory).is_none()
        {
            return Err(invalid("invalid ELF load segment"));
        }
        if bytes != 0 {
            segments.push((offset, address, bytes));
        }
    }
    let maps = bounded(&File::open(format!("/proc/{pid}/maps"))?, MAX_MOUNTINFO)?;
    let source_metadata = source.metadata()?;
    let mut mappings = Vec::new();
    for line in maps.lines() {
        let f: Vec<_> = line.split_whitespace().take(5).collect();
        if f.len() != 5 {
            return Err(invalid("invalid child mapping"));
        }
        let parse_hex = |s| u64::from_str_radix(s, 16).map_err(io::Error::other);
        let (start, end) = f[0]
            .split_once('-')
            .ok_or_else(|| invalid("invalid mapping range"))?;
        let (major, minor) = f[3]
            .split_once(':')
            .ok_or_else(|| invalid("invalid mapping device"))?;
        if libc::makedev(parse_hex(major)? as _, parse_hex(minor)? as _) == source_metadata.dev()
            && f[4].parse::<u64>().map_err(io::Error::other)? == source_metadata.ino()
        {
            mappings.push((parse_hex(start)?, parse_hex(end)?, parse_hex(f[2])?));
        }
    }
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    if !page.is_power_of_two() {
        return Err(invalid("invalid host page size"));
    }
    let first = segments
        .iter()
        .find(|(offset, _, _)| *offset == 0)
        .ok_or_else(|| invalid("ELF lacks initial load segment"))?;
    let bases: Vec<_> = mappings
        .iter()
        .filter(|(_, _, offset)| *offset == 0)
        .filter_map(|(start, _, _)| start.checked_sub(first.1 & !(page - 1)))
        .collect();
    if bases.len() != 1 {
        return Err(invalid("ambiguous executable load address"));
    }
    let memory = File::open(format!("/proc/{pid}/mem"))?;
    let mut actual = [0u8; 65536];
    let mut expected = [0u8; 65536];
    for (offset, address, bytes) in segments {
        let start = bases[0]
            .checked_add(address)
            .ok_or_else(|| invalid("ELF load address overflow"))?;
        let mut done = 0;
        while done < bytes {
            check()?;
            let position = start
                .checked_add(done)
                .ok_or_else(|| invalid("ELF range overflow"))?;
            let (_, end, _) = mappings
                .iter()
                .find(|(begin, end, map_offset)| {
                    position >= *begin
                        && position < *end
                        && map_offset.checked_add(position - begin) == offset.checked_add(done)
                })
                .ok_or_else(|| invalid("ELF load mapping differs from approved source"))?;
            let n = (bytes - done).min(*end - position).min(actual.len() as u64) as usize;
            memory.read_exact_at(&mut actual[..n], position)?;
            backing.read_exact_at(&mut expected[..n], offset + done)?;
            if actual[..n] != expected[..n] {
                return Err(invalid("loaded ELF bytes differ from approved backing"));
            }
            done += n as u64;
        }
    }
    check()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink, process::Command};

    const RECORD: &str = "46 1 0:34 / /container rw,relatime - overlay overlay rw,seclabel,lowerdir=/layers/l/a:/layers/b::/layers/data,upperdir=/layers/upper,workdir=/layers/work,metacopy=on,redirect_dir=on";

    #[test]
    fn mount_layout_preserves_order_and_rejects_ambiguous_options() {
        let layout = Layout::parse(RECORD, 46, Path::new("/container/usr/bin/id")).unwrap();
        assert_eq!(
            layout.layers,
            ["/layers/upper", "/layers/l/a", "/layers/b"].map(PathBuf::from)
        );
        assert_eq!(layout.data, [PathBuf::from("/layers/data")]);
        assert_eq!(layout.relative, Path::new("usr/bin/id"));
        let multiple = RECORD.replace("/layers/data", "/layers/data::/layers/data2");
        assert_eq!(
            Layout::parse(&multiple, 46, Path::new("/container/id"))
                .unwrap()
                .data
                .len(),
            2
        );
        let labeled = format!("{RECORD},context=\"system_u:object_r:container_file_t:s0:c1,c2\"");
        assert!(Layout::parse(&labeled, 46, Path::new("/container/id")).is_ok());
        let escaped = RECORD.replace("/layers/b", "/layers/a\\040b\\072c");
        assert_eq!(
            Layout::parse(&escaped, 46, Path::new("/container/id"))
                .unwrap()
                .layers[2],
            Path::new("/layers/a b:c")
        );
        for record in [
            format!("{RECORD},userxattr"),
            format!("{RECORD},unknown=on"),
            format!("{RECORD},context=\"unterminated"),
            RECORD.replace("::/layers/data", "::/layers/data:/bad"),
            RECORD.replace("/layers/work", "/layers/../work"),
            RECORD.replace("workdir=", "workdir+=bogus,workdir="),
            RECORD.replace(" / /container ", " /subtree /container "),
            format!("{RECORD},lowerdir=/extra"),
            format!("{RECORD}\n{RECORD}"),
        ] {
            assert!(
                Layout::parse(&record, 46, Path::new("/container/id")).is_err(),
                "{record}"
            );
        }
        assert!(Layout::parse(RECORD, 47, Path::new("/container/id")).is_err());
        assert!(Layout::parse(RECORD, 46, Path::new("/outside/id")).is_err());
        let modern = RECORD.replace(
            "lowerdir=/layers/l/a:/layers/b::/layers/data",
            "lowerdir+=/layers/l/a,lowerdir+=/layers/b,datadir+=/layers/data",
        );
        assert_eq!(
            Layout::parse(&modern, 46, Path::new("/container/id"))
                .unwrap()
                .layers,
            layout.layers
        );
        let excessive = RECORD.replace(
            "/layers/l/a:/layers/b",
            &vec!["/layer"; MAX_LAYERS].join(":"),
        );
        assert!(Layout::parse(&excessive, 46, Path::new("/container/id")).is_err());
        assert!(redirected(b"../escape", Path::new("dir"), Path::new("id")).is_err());
        assert_eq!(
            redirected(b"/old", Path::new("dir"), Path::new("id")).unwrap(),
            Path::new("old/id")
        );
        assert_eq!(
            redirected(b"old", Path::new("dir"), Path::new("id")).unwrap(),
            Path::new("dir/old/id")
        );
    }

    struct Fixture {
        base: tempfile::TempDir,
        mounted: PathBuf,
    }
    impl Fixture {
        fn new(data_only: bool) -> Self {
            assert_eq!(unsafe { libc::geteuid() }, 0);
            assert_eq!(
                fs::read_to_string("/proc/self/uid_map")
                    .unwrap()
                    .split_whitespace()
                    .collect::<Vec<_>>(),
                ["0", "0", "4294967295"]
            );
            assert_ne!(
                fs::metadata("/proc/self/ns/mnt").unwrap().ino(),
                fs::metadata("/proc/1/ns/mnt").unwrap().ino(),
                "use unshare --mount --propagation private"
            );
            let base = tempfile::tempdir_in("/run").unwrap();
            for name in ["lower", "lower2", "data", "upper", "work", "merged", "l"] {
                fs::create_dir(base.path().join(name)).unwrap();
            }
            fs::copy("/usr/bin/id", base.path().join("lower/id")).unwrap();
            symlink("../lower", base.path().join("l/link")).unwrap();
            let lower = if data_only {
                fs::copy("/usr/bin/id", base.path().join("data/object")).unwrap();
                let file = File::open(base.path().join("lower/id")).unwrap();
                for (name, value) in [
                    (c"trusted.overlay.metacopy", &b""[..]),
                    (c"trusted.overlay.redirect", &b"/object"[..]),
                ] {
                    assert_eq!(
                        unsafe {
                            libc::fsetxattr(
                                file.as_raw_fd(),
                                name.as_ptr(),
                                value.as_ptr().cast(),
                                value.len(),
                                0,
                            )
                        },
                        0
                    );
                }
                format!(
                    "{}::{}",
                    base.path().join("l/link").display(),
                    base.path().join("data").display()
                )
            } else {
                format!(
                    "{}:{}",
                    base.path().join("l/link").display(),
                    base.path().join("lower2").display()
                )
            };
            let mounted = base.path().join("merged");
            assert!(
                Command::new("mount")
                    .args(["-t", "overlay", "overlay", "-o"])
                    .arg(format!(
                        "lowerdir={lower},upperdir={},workdir={},metacopy=on,redirect_dir=on",
                        base.path().join("upper").display(),
                        base.path().join("work").display()
                    ))
                    .arg(&mounted)
                    .status()
                    .unwrap()
                    .success()
            );
            Self { base, mounted }
        }
        fn source(&self) -> File {
            File::open(self.mounted.join("id")).unwrap()
        }
        fn enroll(&self) -> io::Result<Enrollment> {
            let source = self.source();
            let id = mount_id(&source)?;
            let mountinfo = File::open("/proc/self/mountinfo")?;
            let executable = self.mounted.join("id");
            let layout = Layout::parse(&bounded(&mountinfo, MAX_MOUNTINFO)?, id, &executable)?;
            let budget = sigrund_core::host_budget::Budget::new(Default::default()).unwrap();
            let reservation = budget
                .reserve(
                    1000,
                    Charge {
                        target_fds: 20,
                        ..Default::default()
                    },
                )
                .unwrap();
            Enrollment::open(
                &source,
                &executable,
                MountView {
                    info: mountinfo,
                    namespace: None,
                },
                id,
                layout,
                reservation,
                &|| Ok(()),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            assert!(
                Command::new("umount")
                    .arg(&self.mounted)
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }

    #[test]
    #[ignore = "requires initial-userns root in a private mount namespace"]
    fn rootful_overlay_storage_and_exec_gate() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new(false);
        let source = fixture.source();
        let enrollment = fixture.enroll().unwrap();
        enrollment.revalidate(&source, &|| Ok(())).unwrap();
        assert_eq!(
            enrollment.backing.metadata().unwrap().ino(),
            fs::metadata(fixture.base.path().join("lower/id"))
                .unwrap()
                .ino()
        );
        // True backing changes remain possible; root writers are governed by
        // the maintenance contract, not ETXTBSY. Full hashes must detect them.
        let text = include_str!("../../../config/sigrund.toml.example").replace(
            "<strict-padded-base64-32-byte-ed25519-key>",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        );
        let mut config = sigrund_core::config::DaemonConfig::from_toml(text.as_bytes()).unwrap();
        config.executable_trust_models = vec![sigrund_core::executable::TrustModel::DigestDirect];
        let context = sigrund_core::protocol::RequestedExecutionContext {
            target_uid: 1000,
            target_gid: 1000,
            supplementary_gids: vec![],
            capabilities: vec![],
            env_exact: Default::default(),
            caller_env_allowlist: vec![],
            umask: 0o077,
        };
        let mut image = crate::executable::prepare_overlay(
            source,
            crate::executable::Selection {
                signed: None,
                context: &context,
                trace_available: true,
                allow_file_capabilities: false,
            },
            &config,
            enrollment,
            || Ok(()),
        )
        .unwrap();
        image.finish_digest(|| Ok(())).unwrap();
        image.verify_direct(&context.clone().into()).unwrap();
        let backing = fs::OpenOptions::new()
            .write(true)
            .open(fixture.base.path().join("lower/id"))
            .unwrap();
        let end = backing.metadata().unwrap().len() - 1;
        let mut original = [0];
        File::open(fixture.base.path().join("lower/id"))
            .unwrap()
            .read_exact_at(&mut original, end)
            .unwrap();
        backing.write_all_at(&[original[0] ^ 1], end).unwrap();
        assert!(image.verify_direct(&context.clone().into()).is_err());
        backing.write_all_at(&original, end).unwrap();
        drop(backing);
        image.verify_direct(&context.clone().into()).unwrap();
        // A descriptor cannot silently follow a different copy-up object.
        fs::set_permissions(
            fixture.mounted.join("id"),
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        assert!(image.verify_direct(&context.clone().into()).is_err());
        drop(image);
        let meta = fixture.enroll().unwrap();
        assert_eq!(
            meta.backing.metadata().unwrap().ino(),
            fs::metadata(fixture.base.path().join("lower/id"))
                .unwrap()
                .ino()
        );
        assert_eq!(
            meta.metadata.metadata().unwrap().ino(),
            fs::metadata(fixture.base.path().join("upper/id"))
                .unwrap()
                .ino()
        );
        // Verify loaded PT_LOAD memory before the dynamic loader starts.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
                libc::raise(libc::SIGSTOP);
                let path = CString::new(fixture.mounted.join("id").as_os_str().as_encoded_bytes())
                    .unwrap();
                let args = [path.as_ptr(), std::ptr::null()];
                libc::execv(path.as_ptr(), args.as_ptr());
                libc::_exit(127);
            }
        }
        struct Tracee(i32);
        impl Drop for Tracee {
            fn drop(&mut self) {
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                    libc::waitpid(self.0, std::ptr::null_mut(), 0);
                }
            }
        }
        let _tracee = Tracee(pid);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(
            unsafe {
                libc::ptrace(
                    libc::PTRACE_SETOPTIONS,
                    pid,
                    0,
                    libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL,
                )
            },
            0
        );
        assert_eq!(unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) }, 0);
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status >> 16, libc::PTRACE_EVENT_EXEC);
        verify_loaded(pid, &fixture.source(), meta.backing(), &|| Ok(())).unwrap();
        assert_eq!(
            fs::OpenOptions::new()
                .write(true)
                .open(fixture.mounted.join("id"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ETXTBSY)
        );
        // The real backing remains writable even while merged exec is stopped.
        // This is covered by the administrator contract, never kernel exclusion.
        let writable = fs::OpenOptions::new()
            .write(true)
            .open(fixture.base.path().join("lower/id"))
            .unwrap();
        drop(writable);
        let address = bounded(
            &File::open(format!("/proc/{pid}/maps")).unwrap(),
            MAX_MOUNTINFO,
        )
        .unwrap()
        .lines()
        .find(|l| l.contains("/id"))
        .unwrap()
        .split('-')
        .next()
        .unwrap()
        .to_owned();
        let mut byte = [0];
        let memory = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{pid}/mem"))
            .unwrap();
        let address = u64::from_str_radix(&address, 16).unwrap();
        memory.read_exact_at(&mut byte, address).unwrap();
        memory.write_all_at(&[byte[0] ^ 1], address).unwrap();
        assert!(verify_loaded(pid, &fixture.source(), meta.backing(), &|| Ok(())).is_err());
    }

    #[test]
    #[ignore = "requires initial-userns root in a private mount namespace"]
    fn rootful_overlay_data_only_and_permission_gate() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new(true);
        let source = fixture.source();
        let enrollment = fixture.enroll().unwrap();
        assert_eq!(
            identity(enrollment.backing()).unwrap(),
            identity(&File::open(fixture.base.path().join("data/object")).unwrap()).unwrap()
        );
        enrollment.revalidate(&source, &|| Ok(())).unwrap();
        fs::set_permissions(
            fixture.base.path().join("data/object"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(enrollment.revalidate(&source, &|| Ok(())).is_err());
        assert!(fixture.enroll().is_err());
        fs::set_permissions(
            fixture.base.path().join("data/object"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::set_permissions(
            fixture.base.path().join("l"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(fixture.enroll().is_err());
    }

    fn set_xattr(file: &File, name: &std::ffi::CStr, value: &[u8]) {
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
    }

    #[test]
    #[ignore = "requires initial-userns root in a private mount namespace"]
    fn rootful_overlay_resolution_and_replacement() {
        let fixture = Fixture::new(false);
        let base = fixture.base.path();
        let source = fixture.source();
        let enrolled = fixture.enroll().unwrap();
        // A protected runtime abbreviation must be rechecked by its original
        // name, not just by the canonical name used at enrollment.
        fs::remove_file(base.join("l/link")).unwrap();
        symlink("../lower2", base.join("l/link")).unwrap();
        assert!(enrolled.revalidate(&source, &|| Ok(())).is_err());
        fs::remove_file(base.join("l/link")).unwrap();
        symlink("../lower", base.join("l/link")).unwrap();
        enrolled.revalidate(&source, &|| Ok(())).unwrap();

        fs::rename(base.join("lower/id"), base.join("lower/saved")).unwrap();
        fs::copy(base.join("lower/saved"), base.join("lower/id")).unwrap();
        assert!(enrolled.revalidate(&source, &|| Ok(())).is_err());
        fs::remove_file(base.join("lower/id")).unwrap();
        fs::rename(base.join("lower/saved"), base.join("lower/id")).unwrap();
        enrolled.revalidate(&source, &|| Ok(())).unwrap();

        // Directory redirect, whiteout, opacity and metadata/data separation.
        fs::create_dir(base.join("lower/old")).unwrap();
        fs::copy("/usr/bin/id", base.join("lower/old/tool")).unwrap();
        fs::create_dir(base.join("upper/new")).unwrap();
        let upper = File::open(base.join("upper/new")).unwrap();
        set_xattr(&upper, c"trusted.overlay.redirect", b"/old");
        let (metadata, data) =
            resolve(&enrolled.layers, &[], Path::new("new/tool"), &|| Ok(())).unwrap();
        assert_eq!(identity(&metadata).unwrap(), identity(&data).unwrap());
        assert_eq!(
            data.metadata().unwrap().ino(),
            fs::metadata(base.join("lower/old/tool")).unwrap().ino()
        );
        let whiteout = File::create(base.join("upper/new/tool")).unwrap();
        set_xattr(&whiteout, c"trusted.overlay.whiteout", b"y");
        assert!(resolve(&enrolled.layers, &[], Path::new("new/tool"), &|| Ok(())).is_err());
        fs::remove_file(base.join("upper/new/tool")).unwrap();
        set_xattr(&upper, c"trusted.overlay.opaque", b"y");
        assert!(resolve(&enrolled.layers, &[], Path::new("new/tool"), &|| Ok(())).is_err());
        assert_eq!(
            unsafe { libc::fremovexattr(upper.as_raw_fd(), c"trusted.overlay.opaque".as_ptr()) },
            0
        );
        let metacopy = File::create(base.join("upper/new/tool")).unwrap();
        set_xattr(&metacopy, c"trusted.overlay.metacopy", b"");
        let (metadata, data) =
            resolve(&enrolled.layers, &[], Path::new("new/tool"), &|| Ok(())).unwrap();
        assert_eq!(
            metadata.metadata().unwrap().ino(),
            metacopy.metadata().unwrap().ino()
        );
        assert_ne!(identity(&metadata).unwrap(), identity(&data).unwrap());
        assert!(
            resolve(&enrolled.layers, &[], Path::new("new/tool"), &|| Err(
                invalid("cancelled")
            ))
            .is_err()
        );
    }

    #[test]
    #[ignore = "requires initial-userns root in a private mount namespace"]
    fn rootful_overlay_upper_acl_and_nested_mounts() {
        let fixture = Fixture::new(false);
        let source = fixture.source();
        let old = fixture.enroll().unwrap();
        let writer = fs::OpenOptions::new()
            .write(true)
            .open(fixture.mounted.join("id"))
            .unwrap();
        writer.write_all_at(b"\x7f", 0).unwrap();
        drop(writer);
        assert!(old.revalidate(&source, &|| Ok(())).is_err());
        let upper = fixture.enroll().unwrap();
        assert_eq!(
            upper.backing.metadata().unwrap().ino(),
            fs::metadata(fixture.base.path().join("upper/id"))
                .unwrap()
                .ino()
        );
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (1u16, 7u16, u32::MAX),
            (2, 4, 1000),
            (4, 5, u32::MAX),
            (16, 5, u32::MAX),
            (32, 5, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&perm.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        set_xattr(upper.backing(), c"system.posix_acl_access", &acl);
        assert!(fixture.enroll().is_err());
        assert_eq!(
            unsafe {
                libc::fremovexattr(
                    upper.backing.as_raw_fd(),
                    c"system.posix_acl_access".as_ptr(),
                )
            },
            0
        );
        let directory = fixture.base.path().join("upper/nested");
        fs::create_dir(&directory).unwrap();
        assert!(
            Command::new("mount")
                .args(["--bind"])
                .arg(fixture.base.path().join("lower"))
                .arg(&directory)
                .status()
                .unwrap()
                .success()
        );
        let resolved = resolve(&upper.layers, &[], Path::new("nested/id"), &|| Ok(()));
        assert!(
            Command::new("umount")
                .arg(&directory)
                .status()
                .unwrap()
                .success()
        );
        assert!(resolved.is_err());
    }

    #[test]
    #[ignore = "requires initial-userns root in a private mount namespace"]
    fn rootful_overlay_write_exclusion_boundaries() {
        let fixture = Fixture::new(false);
        let path = CString::new(fixture.mounted.join("id").as_os_str().as_encoded_bytes()).unwrap();
        let run = || {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                unsafe {
                    let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
                    libc::dup2(null, 1);
                    libc::close(null);
                    libc::execv(path.as_ptr(), [c"id".as_ptr(), std::ptr::null()].as_ptr());
                    libc::_exit(*libc::__errno_location());
                }
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status));
            libc::WEXITSTATUS(status)
        };
        let writer = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(fixture.mounted.join("id"))
            .unwrap();
        assert_eq!(run(), libc::ETXTBSY);
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                writer.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapped, libc::MAP_FAILED);
        drop(writer);
        let merged_mapping_result = run();
        assert_eq!(unsafe { libc::munmap(mapped, 4096) }, 0);
        assert_eq!(
            merged_mapping_result, 0,
            "merged mmap retains the real backing file after the merged writer closes"
        );

        let backing = fixture.base.path().join("upper/id");
        let writer = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&backing)
            .unwrap();
        assert_eq!(run(), 0, "backing writers are outside merged ETXTBSY");
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                writer.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapped, libc::MAP_FAILED);
        drop(writer);
        let backing_mapping_result = run();
        assert_eq!(unsafe { libc::munmap(mapped, 4096) }, 0);
        assert_eq!(
            backing_mapping_result, 0,
            "backing mappings require administrator maintenance"
        );

        let alias = fixture.base.path().join("alias");
        File::create(&alias).unwrap();
        assert!(
            Command::new("mount")
                .arg("--bind")
                .arg(&backing)
                .arg(&alias)
                .status()
                .unwrap()
                .success()
        );
        let writer = fs::OpenOptions::new().write(true).open(&alias).unwrap();
        let alias_result = run();
        drop(writer);
        assert!(
            Command::new("umount")
                .arg(&alias)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            alias_result, 0,
            "writable aliases require administrator maintenance"
        );
    }
}
