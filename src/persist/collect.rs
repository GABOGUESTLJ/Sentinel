use super::{ScopeSelection, cron, model::*, ssh, systemd, xdg};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct Options {
    pub root: PathBuf,
    pub scope: ScopeSelection,
    pub offline: bool,
}

pub fn collect(options: &Options) -> Snapshot {
    let mut snapshot = Snapshot::new();
    snapshot.extend(systemd::collect(options));
    snapshot.extend(cron::collect(options));
    snapshot.extend(ssh::collect(options));
    snapshot.extend(xdg::collect(options));
    snapshot
}

pub fn rooted(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

pub fn user_homes(root: &Path) -> Vec<(String, PathBuf)> {
    if root == Path::new("/") {
        let owner = std::env::var("USER").unwrap_or_else(|_| "current-user".into());
        if let Some(home) = std::env::var_os("HOME") {
            return vec![(owner, PathBuf::from(home))];
        }
        return Vec::new();
    }

    let mut homes = Vec::new();
    let home_root = rooted(root, "/home");
    if let Ok(items) = fs::read_dir(home_root) {
        for item in items.flatten() {
            if item.file_type().is_ok_and(|kind| kind.is_dir()) {
                homes.push((item.file_name().to_string_lossy().into_owned(), item.path()));
            }
        }
    }
    let root_home = rooted(root, "/root");
    if root_home.is_dir() {
        homes.push(("root".into(), root_home));
    }
    homes.sort_by(|a, b| a.0.cmp(&b.0));
    homes
}

pub fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

pub fn regular_files(directory: &Path) -> Result<Vec<PathBuf>, String> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    let items =
        fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?;
    for item in items {
        let item = item.map_err(|error| format!("{}: {error}", directory.display()))?;
        let kind = item
            .file_type()
            .map_err(|error| format!("{}: {error}", item.path().display()))?;
        if kind.is_file() || kind.is_symlink() {
            files.push(item.path());
        }
    }
    files.sort();
    Ok(files)
}

pub fn display_origin(root: &Path, path: &Path) -> String {
    if root == Path::new("/") {
        path.display().to_string()
    } else {
        path.strip_prefix(root)
            .map(|relative| format!("/{}", relative.display()))
            .unwrap_or_else(|_| path.display().to_string())
    }
}
