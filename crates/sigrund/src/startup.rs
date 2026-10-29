use std::{
    fs, io,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct CgroupLayout {
    pub root: PathBuf,
    pub supervisor: PathBuf,
    pub jobs: PathBuf,
    pub hooks: PathBuf,
}

impl CgroupLayout {
    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            supervisor: root.join("supervisor"),
            jobs: root.join("jobs"),
            hooks: root.join("hooks"),
            root,
        }
    }

    pub fn initialize(&self) -> io::Result<()> {
        fs::create_dir_all(&self.supervisor)?;
        fs::create_dir_all(&self.jobs)?;
        fs::create_dir_all(&self.hooks)?;
        let controllers = fs::read_to_string(self.root.join("cgroup.controllers"))?;
        if !controllers.split_whitespace().any(|v| v == "memory")
            || !controllers.split_whitespace().any(|v| v == "pids")
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "memory and pids controllers are required",
            ));
        }
        for directory in [&self.root, &self.jobs, &self.hooks] {
            write_exact(directory.join("cgroup.subtree_control"), b"+memory +pids\n")?;
        }
        self.verify_required_controls()
    }

    pub fn verify_required_controls(&self) -> io::Result<()> {
        for directory in [&self.root, &self.hooks] {
            for name in [
                "memory.max",
                "memory.swap.max",
                "memory.oom.group",
                "pids.max",
                "cgroup.kill",
            ] {
                let path = directory.join(name);
                if !path.exists() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("missing {}", path.display()),
                    ));
                }
            }
        }
        let probe = self.hooks.join("startup-probe");
        fs::create_dir(&probe)?;
        let result = (|| {
            write_and_verify(&probe.join("memory.max"), b"67108864\n")?;
            write_and_verify(&probe.join("memory.swap.max"), b"0\n")?;
            write_and_verify(&probe.join("memory.oom.group"), b"1\n")?;
            write_and_verify(&probe.join("pids.max"), b"32\n")?;
            write_exact(&probe.join("cgroup.kill"), b"1\n")
        })();
        let remove = fs::remove_dir(&probe);
        result.and(remove)
    }
}

fn write_exact(path: impl AsRef<Path>, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

fn write_and_verify(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_exact(path, bytes)?;
    let actual = fs::read(path)?;
    if actual != bytes {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("kernel rejected {}", path.display()),
        ));
    }
    Ok(())
}
