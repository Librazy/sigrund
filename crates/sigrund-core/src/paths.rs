use std::path::{Path, PathBuf};

use crate::{CoreError, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedRoot {
    pub root: PathBuf,
    pub relative_path: PathBuf,
}

/// Selects the longest complete-component root and strips exactly one
/// separator. The returned path is always relative and traversal-free.
pub fn select_root(executable: &Path, roots: &[PathBuf]) -> Result<SelectedRoot> {
    let raw = executable
        .to_str()
        .ok_or_else(|| CoreError::Value("executable path is not UTF-8".into()))?;
    if !raw.starts_with('/') || raw.ends_with('/') || raw.contains("//") {
        return Err(CoreError::Value(
            "executable path is not canonical absolute text".into(),
        ));
    }
    let mut selected: Option<&PathBuf> = None;
    for root in roots {
        let root_text = root
            .to_str()
            .ok_or_else(|| CoreError::Value("configured root is not UTF-8".into()))?;
        if raw
            .strip_prefix(root_text)
            .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1)
            && selected.is_none_or(|current| root_text.len() > current.to_string_lossy().len())
        {
            selected = Some(root);
        }
    }
    let root =
        selected.ok_or_else(|| CoreError::Value("executable is outside allowed roots".into()))?;
    let root_text = root.to_str().unwrap();
    let relative = raw
        .strip_prefix(root_text)
        .and_then(|suffix| suffix.strip_prefix('/'))
        .ok_or_else(|| CoreError::Value("root prefix stripping failed".into()))?;
    if relative.is_empty()
        || relative.starts_with('/')
        || relative
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(CoreError::Value(
            "relative executable path is unsafe".into(),
        ));
    }
    Ok(SelectedRoot {
        root: root.clone(),
        relative_path: PathBuf::from(relative),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_longest_component_prefix() {
        let selected = select_root(
            Path::new("/usr/bin/systemctl"),
            &[PathBuf::from("/usr"), PathBuf::from("/usr/bin")],
        )
        .unwrap();
        assert_eq!(selected.root, PathBuf::from("/usr/bin"));
        assert_eq!(selected.relative_path, PathBuf::from("systemctl"));
        assert!(select_root(Path::new("/usr/bin-evil/x"), &[PathBuf::from("/usr/bin")]).is_err());
    }
}
