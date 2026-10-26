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
    snapshot.warnings.push(format!(
        "COVERAGE population={}",
        if options.root == Path::new("/") {
            "live HOME/USER only; no account-wide discovery"
        } else {
            "alternate-root immediate /home directories and /root only; no account-wide discovery"
        }
    ));
    for source in Source::ALL {
        for scope in [Scope::User, Scope::System] {
            let selected = match scope {
                Scope::User => options.scope.includes_user(),
                Scope::System => options.scope.includes_system(),
            };
            let status = if !selected {
                "skipped"
            } else if snapshot.coverage.contains(&Coverage { source, scope }) {
                "complete"
            } else {
                "incomplete"
            };
            snapshot.warnings.push(format!(
                "COVERAGE source={} scope={} status={status}",
                source.label(),
                scope.label()
            ));
        }
    }
    snapshot
}

pub fn rooted(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

pub fn user_homes(
    root: &Path,
    output: &mut CollectorOutput,
    source: Source,
) -> Vec<(String, PathBuf)> {
    if root == Path::new("/") {
        let owner = std::env::var("USER").unwrap_or_else(|_| "current-user".into());
        if let Some(home) = std::env::var_os("HOME") {
            return vec![(owner, PathBuf::from(home))];
        }
        output.fail(
            source,
            Scope::User,
            "HOME is unset; current-user home was not inspected",
        );
        return Vec::new();
    }

    let mut homes = Vec::new();
    let home_root = rooted(root, "/home");
    match fs::read_dir(&home_root) {
        Ok(items) => {
            for item in items {
                match item.and_then(|item| item.file_type().map(|kind| (item, kind))) {
                    Ok((item, kind)) if kind.is_dir() => {
                        homes.push((item.file_name().to_string_lossy().into_owned(), item.path()));
                    }
                    Ok(_) => (),
                    Err(error) => output.fail(
                        source,
                        Scope::User,
                        format!("{}: {error}", home_root.display()),
                    ),
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => output.fail(
            source,
            Scope::User,
            format!("{}: {error}", home_root.display()),
        ),
    }
    let root_home = rooted(root, "/root");
    match fs::metadata(&root_home) {
        Ok(metadata) if metadata.is_dir() => homes.push(("root".into(), root_home)),
        Ok(_) => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => output.fail(
            source,
            Scope::User,
            format!("{}: {error}", root_home.display()),
        ),
    }
    homes.sort_by(|a, b| a.0.cmp(&b.0));
    homes
}

pub fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

pub fn path_exists(path: &Path) -> Result<bool, String> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

pub fn regular_files(directory: &Path) -> Result<Vec<PathBuf>, String> {
    if !path_exists(directory)? {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = Path::new("/tmp/opencode").join(format!(
                "persist-coverage-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn collect(&self) -> Snapshot {
            collect(&Options {
                root: self.0.clone(),
                scope: ScopeSelection::All,
                offline: true,
            })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn coverage_failure_is_sticky_across_neighboring_homes() {
        let fixture = Fixture::new();
        let bad = fixture.0.join("home/alice/.config/systemd/user");
        fs::create_dir_all(&bad).unwrap();
        fs::write(bad.join("broken.service"), [0xff]).unwrap();
        fs::create_dir_all(fixture.0.join("home/zoe")).unwrap();
        let snapshot = fixture.collect();
        assert!(!snapshot.coverage.contains(&Coverage {
            source: Source::Systemd,
            scope: Scope::User,
        }));
        assert!(
            snapshot
                .warnings
                .iter()
                .any(|line| line.contains("broken.service"))
        );
    }

    #[test]
    fn coverage_home_enumeration_failure_is_not_an_empty_population() {
        let fixture = Fixture::new();
        fs::write(fixture.0.join("home"), "not a directory").unwrap();
        let snapshot = fixture.collect();
        for source in [Source::Systemd, Source::Ssh, Source::Xdg] {
            assert!(!snapshot.coverage.contains(&Coverage {
                source,
                scope: Scope::User,
            }));
        }
        assert!(snapshot.warnings.iter().any(|line| line.contains("/home")));
    }

    #[test]
    fn coverage_inaccessible_parent_is_not_a_missing_source() {
        let fixture = Fixture::new();
        let home = fixture.0.join("home/alice");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join(".ssh"), "not a directory").unwrap();
        let snapshot = fixture.collect();
        assert!(!snapshot.coverage.contains(&Coverage {
            source: Source::Ssh,
            scope: Scope::User,
        }));
        assert!(
            snapshot
                .warnings
                .iter()
                .any(|line| line.contains("authorized_keys"))
        );
    }

    #[test]
    fn coverage_evidence_names_empty_homes_and_unselected_scopes() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.0.join("home/alice")).unwrap();
        let snapshot = collect(&Options {
            root: fixture.0.clone(),
            scope: ScopeSelection::User,
            offline: true,
        });
        assert!(snapshot.warnings.iter().any(|line| {
            line.contains("COVERAGE source=ssh scope=user owner=\"alice\" status=inspected")
        }));
        assert!(
            snapshot
                .warnings
                .iter()
                .any(|line| { line == "COVERAGE source=ssh scope=system status=skipped" })
        );
        assert_eq!(snapshot.coverage.len(), 4);
        assert!(snapshot.entries.is_empty());
    }
}
