use crate::read_files::{self, Entry};
use std::{
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

pub type Entries = BTreeMap<PathBuf, Entry>;
pub type Error = Box<dyn std::error::Error>;

/// Complete inventory, including dotfiles and special entries, without following links.
pub fn scan(root: &Path) -> Result<Entries, Error> {
    let root_before = std::fs::symlink_metadata(root)?;
    if !root_before.is_dir() {
        return Err(format!("Not a directory: {}", root.display()).into());
    }
    let mut entries = Entries::new();
    for item in WalkDir::new(root).follow_links(false).min_depth(1) {
        let item = item?;
        let entry = read_files::read_entry(item.path())
            .map_err(|error| format!("{}: {error}", item.path().display()))?;
        entries.insert(item.path().strip_prefix(root)?.to_path_buf(), entry);
    }
    let root_after = std::fs::symlink_metadata(root)?;
    if !root_after.is_dir()
        || root_before.dev() != root_after.dev()
        || root_before.ino() != root_after.ino()
    {
        return Err("Monitored root changed during scan".into());
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::symlink,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let id = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!("fim-scan-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn scans_regular_dot_hidden_nested_empty_symlink_and_fifo_entries() {
        let temp = Temp::new();
        let root = &temp.0;
        fs::write(root.join(".hidden"), b"secret").unwrap();
        fs::create_dir(root.join(".config")).unwrap();
        fs::write(root.join(".config/nested"), b"nested").unwrap();
        fs::create_dir(root.join("empty")).unwrap();
        symlink("missing-target", root.join("broken-link")).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(root.join("pipe"))
            .status()
            .unwrap();
        assert!(status.success());

        let entries = scan(root).unwrap();
        assert_eq!(entries.len(), 6);
        assert_eq!(
            entries[Path::new(".hidden")].kind,
            crate::read_files::Kind::File
        );
        assert_eq!(
            entries[Path::new(".config")].kind,
            crate::read_files::Kind::Directory
        );
        assert_eq!(
            entries[Path::new(".config/nested")].kind,
            crate::read_files::Kind::File
        );
        assert_eq!(
            entries[Path::new("empty")].kind,
            crate::read_files::Kind::Directory
        );
        assert_eq!(
            entries[Path::new("broken-link")].kind,
            crate::read_files::Kind::Symlink
        );
        assert_eq!(
            entries[Path::new("pipe")].kind,
            crate::read_files::Kind::Fifo
        );
        assert!(entries[Path::new("pipe")].hash.is_none());
    }

    #[test]
    fn rejects_missing_file_and_non_directory_roots() {
        let temp = Temp::new();
        assert!(scan(&temp.0.join("missing")).is_err());
        let file = temp.0.join("regular");
        fs::write(&file, b"not a directory").unwrap();
        assert!(
            scan(&file)
                .unwrap_err()
                .to_string()
                .contains("Not a directory")
        );
    }
}
