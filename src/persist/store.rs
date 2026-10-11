use super::{
    ScopeSelection,
    compare::{EVENT_SCHEMA_VERSION, PersistEvent},
    model::{Coverage, PersistenceEntry, Snapshot},
};
use crate::{hash_files, private_store, retention};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
};

type Error = Box<dyn std::error::Error>;

#[derive(Debug)]
pub struct Paths {
    pub baseline: PathBuf,
    pub history: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineDocument {
    version: u32,
    root_hex: String,
    scope: ScopeSelection,
    created_at: String,
    entries: BTreeMap<String, PersistenceEntry>,
    coverage: BTreeSet<Coverage>,
}

fn profile_key(root: &Path, scope: ScopeSelection) -> String {
    let mut bytes = root.as_os_str().as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(scope.label().as_bytes());
    hex::encode(hash_files::hash_bytes(&bytes))
}

impl Paths {
    pub fn discover(root: &Path, scope: ScopeSelection) -> Result<Self, Error> {
        Self::under(&private_store::state_home()?, root, scope)
    }

    fn under(state_home: &Path, root: &Path, scope: ScopeSelection) -> Result<Self, Error> {
        let directory = state_home
            .join("sentinel/persist")
            .join(profile_key(root, scope));
        private_store::ensure_private_directory(&directory, true, "persist state")?;
        Ok(Self {
            baseline: directory.join("baseline.json"),
            history: directory.join("history.jsonl"),
        })
    }
}

pub fn save_baseline(
    path: &Path,
    root: &Path,
    scope: ScopeSelection,
    snapshot: &Snapshot,
    replace: bool,
) -> Result<(), Error> {
    let document = BaselineDocument {
        version: 1,
        root_hex: hex::encode(root.as_os_str().as_bytes()),
        scope,
        created_at: snapshot.observed_at.clone(),
        entries: snapshot.entries.clone(),
        coverage: snapshot.coverage.clone(),
    };
    let mut bytes = serde_json::to_vec_pretty(&document)?;
    bytes.push(b'\n');
    private_store::atomic_write(path, &bytes, replace)
}

pub fn load_baseline(path: &Path, root: &Path, scope: ScopeSelection) -> Result<Snapshot, Error> {
    let file = private_store::open_private_read(path, "persist baseline").map_err(|error| {
        format!(
            "Could not load persist baseline {}: {error}. Use --init-baseline first",
            path.display()
        )
    })?;
    let document: BaselineDocument = serde_json::from_reader(file)?;
    if document.version != 1
        || document.root_hex != hex::encode(root.as_os_str().as_bytes())
        || document.scope != scope
    {
        return Err("Persist baseline belongs to another root, scope, or schema version".into());
    }
    if document.entries.iter().any(|(id, entry)| id != &entry.id) {
        return Err("Persist baseline contains an invalid entry identity".into());
    }
    Ok(Snapshot {
        observed_at: document.created_at,
        entries: document.entries,
        coverage: document.coverage,
        warnings: Vec::new(),
    })
}

pub fn append_history(
    path: &Path,
    events: &[PersistEvent],
    policy: retention::Policy,
) -> Result<(), Error> {
    if events.is_empty() {
        return Ok(());
    }
    let directory = path.parent().ok_or("persist history has no parent")?;
    retention::prune_jsonl(directory, policy, Some(path))?;
    let mut batch = Vec::new();
    for event in events {
        serde_json::to_writer(&mut batch, event)?;
        batch.push(b'\n');
    }
    if path.exists()
        && fs::metadata(path)?.len().saturating_add(batch.len() as u64) > policy.max_bytes
    {
        fs::rename(path, retention::rotated_path(path))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    private_store::validate_private_file(&file, "persist history")?;
    file.write_all(&batch)?;
    file.sync_all()?;
    retention::prune_jsonl(directory, policy, Some(path))?;
    Ok(())
}

pub fn read_history(
    path: &Path,
    policy: retention::Policy,
) -> Result<(Vec<PersistEvent>, Vec<String>), Error> {
    let directory = path.parent().ok_or("persist history has no parent")?;
    retention::prune_jsonl(directory, policy, None)?;
    if !directory.exists() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut files: Vec<_> = fs::read_dir(directory)?
        .filter_map(Result::ok)
        .map(|item| item.path())
        .filter(|item| {
            item.extension()
                .is_some_and(|extension| extension == "jsonl")
                && item
                    .file_stem()
                    .is_some_and(|stem| stem.to_string_lossy().starts_with("history"))
        })
        .collect();
    files.sort();
    if files.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut events = Vec::new();
    let mut warnings = Vec::new();
    for history_file in files {
        let file = private_store::open_private_read(&history_file, "persist history")?;
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let label = format!("{}:{}", history_file.display(), index + 1);
            let line = match line {
                Ok(line) => line,
                Err(error) => {
                    warnings.push(format!("history {label}: {error}"));
                    continue;
                }
            };
            match serde_json::from_str::<PersistEvent>(&line) {
                Ok(event) if event.schema_version == EVENT_SCHEMA_VERSION => events.push(event),
                Ok(_) => warnings.push(format!("history {label} has another schema")),
                Err(error) => warnings.push(format!("history {label}: {error}")),
            }
        }
    }
    Ok((events, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::model::{EntrySpec, Evidence, Scope, Source};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn baseline_round_trip_refuses_overwrite_and_wrong_profile() {
        let temp = std::env::temp_dir().join(format!(
            "sentinel-persist-store-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = temp.join("root");
        fs::create_dir_all(&root).unwrap();
        let paths = Paths::under(&temp.join("state"), &root, ScopeSelection::All).unwrap();
        let mut snapshot = Snapshot::new();
        let entry = PersistenceEntry::new(EntrySpec {
            source: Source::Xdg,
            scope: Scope::User,
            owner: "alice",
            locator: "agent.desktop",
            origins: vec!["/home/alice/.config/autostart/agent.desktop".into()],
            location_hint: None,
            trigger: "desktop login".into(),
            command: "/usr/bin/agent".into(),
            enabled: Some(true),
            active: None,
            evidence: Evidence::Static,
            semantic_config: b"agent",
        });
        snapshot.entries.insert(entry.id.clone(), entry);
        snapshot.coverage.insert(Coverage {
            source: Source::Xdg,
            scope: Scope::User,
        });
        save_baseline(
            &paths.baseline,
            &root,
            ScopeSelection::All,
            &snapshot,
            false,
        )
        .unwrap();
        assert!(
            save_baseline(
                &paths.baseline,
                &root,
                ScopeSelection::All,
                &snapshot,
                false
            )
            .is_err()
        );
        assert_eq!(
            load_baseline(&paths.baseline, &root, ScopeSelection::All)
                .unwrap()
                .entries
                .len(),
            1
        );
        assert!(load_baseline(&paths.baseline, &root, ScopeSelection::User).is_err());
        fs::remove_dir_all(temp).unwrap();
    }
}
