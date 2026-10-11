use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

type Error = Box<dyn std::error::Error>;

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub max_age: Duration,
    pub max_bytes: u64,
}

#[derive(Debug)]
struct StoredFile {
    path: PathBuf,
    modified: SystemTime,
    size: u64,
}

pub fn prune_jsonl(
    directory: &Path,
    policy: Policy,
    protected: Option<&Path>,
) -> Result<usize, Error> {
    if !directory.exists() {
        return Ok(0);
    }
    let now = SystemTime::now();
    let mut files = Vec::new();
    let mut removed = 0;
    for item in fs::read_dir(directory)? {
        let path = item?.path();
        if path
            .extension()
            .is_none_or(|extension| extension != "jsonl")
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.uid() != crate::private_store::uid() {
            continue;
        }
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let is_protected = protected.is_some_and(|protected| protected == path);
        let expired = now
            .duration_since(modified)
            .is_ok_and(|age| age > policy.max_age);
        if expired && !is_protected {
            fs::remove_file(path)?;
            removed += 1;
        } else {
            files.push(StoredFile {
                path,
                modified,
                size: metadata.len(),
            });
        }
    }

    files.sort_by_key(|file| file.modified);
    let mut total: u64 = files.iter().map(|file| file.size).sum();
    for file in files {
        if total <= policy.max_bytes {
            break;
        }
        if protected.is_some_and(|protected| protected == file.path) {
            continue;
        }
        fs::remove_file(&file.path)?;
        total = total.saturating_sub(file.size);
        removed += 1;
    }
    Ok(removed)
}

pub fn rotated_path(path: &Path) -> PathBuf {
    let now = crate::read_files::Timestamp::now();
    let stem = path
        .file_stem()
        .map_or_else(|| "history".into(), |stem| stem.to_string_lossy());
    path.with_file_name(format!(
        "{stem}-{}-{:09}-{}.jsonl",
        now.seconds,
        now.nanos,
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, time::UNIX_EPOCH};

    #[test]
    fn prunes_oldest_files_to_total_size_and_keeps_protected_file() {
        let root = std::env::temp_dir().join(format!(
            "sentinel-retention-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        crate::private_store::ensure_private_directory(&root, true, "test").unwrap();
        let old = root.join("old.jsonl");
        let current = root.join("current.jsonl");
        fs::write(&old, vec![0; 8]).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        fs::write(&current, vec![0; 8]).unwrap();
        let removed = prune_jsonl(
            &root,
            Policy {
                max_age: Duration::from_secs(3600),
                max_bytes: 8,
            },
            Some(&current),
        )
        .unwrap();
        assert_eq!(removed, 1);
        assert!(!old.exists() && current.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prunes_files_past_the_age_limit() {
        let root = std::env::temp_dir().join(format!(
            "sentinel-retention-age-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        crate::private_store::ensure_private_directory(&root, true, "test").unwrap();
        let expired = root.join("expired.jsonl");
        fs::write(&expired, b"event\n").unwrap();
        std::thread::sleep(Duration::from_millis(2));
        let removed = prune_jsonl(
            &root,
            Policy {
                max_age: Duration::ZERO,
                max_bytes: 1024,
            },
            None,
        )
        .unwrap();
        assert_eq!(removed, 1);
        assert!(!expired.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
