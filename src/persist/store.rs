use super::{
    ScopeSelection,
    compare::{EVENT_SCHEMA_VERSION, PersistEvent},
    model::{Coverage, PersistenceEntry, Snapshot},
};
use crate::{auth, hash_files, private_store, retention};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
};

type Error = Box<dyn std::error::Error>;

const AUTH_VERSION: u32 = 1;
const ALGORITHM: &str = "HMAC-SHA256";
const BASELINE_VERSION: u32 = 2;
const HISTORY_VERSION: u32 = 1;
const HISTORY_STATE_VERSION: u32 = 1;
const BASELINE_DOMAIN: &[u8] = b"sentinel:persist:baseline:hmac-sha256:v1\0";
const HISTORY_DOMAIN: &[u8] = b"sentinel:persist:history:hmac-sha256:v1\0";
const HISTORY_STATE_DOMAIN: &[u8] = b"sentinel:persist:history-state:hmac-sha256:v1\0";

#[derive(Debug)]
pub struct Paths {
    pub baseline: PathBuf,
    pub history: PathBuf,
    history_state: PathBuf,
    profile: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authentication {
    version: u32,
    algorithm: String,
    key_id: String,
    tag_hex: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedDocument<T> {
    authentication: Authentication,
    payload: T,
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryPayload {
    version: u32,
    profile: String,
    sequence: u64,
    previous_tag_hex: String,
    event: PersistEvent,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryState {
    version: u32,
    profile: String,
    first_sequence: u64,
    first_previous_tag_hex: String,
    last_sequence: u64,
    last_tag_hex: String,
}

struct VerifiedRecord {
    payload: HistoryPayload,
    tag_hex: String,
    file: PathBuf,
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
        let profile = profile_key(root, scope);
        let directory = state_home.join("sentinel/persist").join(&profile);
        private_store::ensure_private_directory(&directory, true, "persist state")?;
        Ok(Self {
            baseline: directory.join("baseline.json"),
            history: directory.join("history.jsonl"),
            history_state: directory.join("history-state.json"),
            profile,
        })
    }
}

fn read_bytes(path: &Path, label: &str) -> Result<Vec<u8>, Error> {
    let mut file = private_store::open_private_read(path, label)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn authentication(key: &auth::Key, tag: Vec<u8>) -> Authentication {
    Authentication {
        version: AUTH_VERSION,
        algorithm: ALGORITHM.into(),
        key_id: auth::key_id(key),
        tag_hex: hex::encode(tag),
    }
}

fn verify_document<T: Serialize>(
    document: &AuthenticatedDocument<T>,
    key: &auth::Key,
    domain: &[u8],
    label: &str,
) -> Result<(), Error> {
    if document.authentication.version != AUTH_VERSION
        || document.authentication.algorithm != ALGORITHM
    {
        return Err(format!("Unsupported {label} authentication format").into());
    }
    if document.authentication.key_id != auth::key_id(key) {
        return Err(format!("The {label} was signed with a different HMAC key").into());
    }
    let tag = hex::decode(&document.authentication.tag_hex)
        .map_err(|_| format!("Invalid hexadecimal HMAC tag in {label}"))?;
    auth::verify(key, domain, &serde_json::to_vec(&document.payload)?, &tag)
        .map_err(|error| format!("{label}: {error}").into())
}

fn signed_document<T: Serialize>(
    payload: T,
    key: &auth::Key,
    domain: &[u8],
) -> Result<AuthenticatedDocument<T>, Error> {
    let tag = auth::sign(key, domain, &serde_json::to_vec(&payload)?);
    Ok(AuthenticatedDocument {
        authentication: authentication(key, tag),
        payload,
    })
}

fn parse_signed<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    key: &auth::Key,
    domain: &[u8],
    label: &str,
) -> Result<T, Error> {
    let document: AuthenticatedDocument<T> = serde_json::from_slice(bytes)
        .map_err(|error| format!("Unsigned, corrupt, or incompatible {label}: {error}"))?;
    verify_document(&document, key, domain, label)?;
    Ok(document.payload)
}

fn validate_baseline(
    document: BaselineDocument,
    root: &Path,
    scope: ScopeSelection,
    expected_version: u32,
) -> Result<Snapshot, Error> {
    if document.version != expected_version
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

pub fn save_baseline(
    path: &Path,
    root: &Path,
    scope: ScopeSelection,
    snapshot: &Snapshot,
    key_path: &Path,
    replace: bool,
) -> Result<(), Error> {
    let payload = BaselineDocument {
        version: BASELINE_VERSION,
        root_hex: hex::encode(root.as_os_str().as_bytes()),
        scope,
        created_at: snapshot.observed_at.clone(),
        entries: snapshot.entries.clone(),
        coverage: snapshot.coverage.clone(),
    };
    let key = auth::load(key_path)?;
    let document = signed_document(payload, &key, BASELINE_DOMAIN)?;
    let mut bytes = serde_json::to_vec_pretty(&document)?;
    bytes.push(b'\n');
    private_store::atomic_write(path, &bytes, replace)
}

pub fn load_baseline(
    path: &Path,
    root: &Path,
    scope: ScopeSelection,
    key_path: &Path,
) -> Result<Snapshot, Error> {
    let bytes = read_bytes(path, "persist baseline").map_err(|error| {
        format!(
            "Could not load persist baseline {}: {error}. Use --init-baseline first",
            path.display()
        )
    })?;
    let key = auth::load(key_path)
        .map_err(|error| format!("Could not load the Persist HMAC key: {error}"))?;
    let payload = parse_signed(&bytes, &key, BASELINE_DOMAIN, "persist baseline")?;
    validate_baseline(payload, root, scope, BASELINE_VERSION)
}

pub fn load_baseline_for_update(
    path: &Path,
    root: &Path,
    scope: ScopeSelection,
    key_path: &Path,
) -> Result<Snapshot, Error> {
    let bytes = read_bytes(path, "persist baseline")?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value.get("authentication").is_some() || value.get("payload").is_some() {
        let key = auth::load(key_path)
            .map_err(|error| format!("Could not load the Persist HMAC key: {error}"))?;
        let payload = parse_signed(&bytes, &key, BASELINE_DOMAIN, "persist baseline")?;
        return validate_baseline(payload, root, scope, BASELINE_VERSION);
    }
    let legacy: BaselineDocument = serde_json::from_value(value)?;
    validate_baseline(legacy, root, scope, 1)
}

fn save_history_state(
    path: &Path,
    state: &HistoryState,
    key: &auth::Key,
    replace: bool,
) -> Result<(), Error> {
    let document = signed_document(state, key, HISTORY_STATE_DOMAIN)?;
    let mut bytes = serde_json::to_vec_pretty(&document)?;
    bytes.push(b'\n');
    private_store::atomic_write(path, &bytes, replace)
}

fn load_history_state(paths: &Paths, key: &auth::Key) -> Result<Option<HistoryState>, Error> {
    if !paths.history_state.exists() {
        return Ok(None);
    }
    let bytes = read_bytes(&paths.history_state, "persist history state")?;
    let state: HistoryState =
        parse_signed(&bytes, key, HISTORY_STATE_DOMAIN, "persist history state")?;
    if state.version != HISTORY_STATE_VERSION || state.profile != paths.profile {
        return Err("Persist history state belongs to another profile or schema".into());
    }
    Ok(Some(state))
}

fn history_files(path: &Path) -> Result<Vec<PathBuf>, Error> {
    let directory = path.parent().ok_or("persist history has no parent")?;
    let mut files = Vec::new();
    for item in fs::read_dir(directory)? {
        let item_path = item?.path();
        if item_path
            .extension()
            .is_some_and(|extension| extension == "jsonl")
            && item_path
                .file_stem()
                .is_some_and(|stem| stem.to_string_lossy().starts_with("history"))
        {
            files.push(item_path);
        }
    }
    files.sort();
    Ok(files)
}

fn read_records(paths: &Paths, key: &auth::Key) -> Result<Vec<VerifiedRecord>, Error> {
    let mut records = Vec::new();
    for history_file in history_files(&paths.history)? {
        let file = private_store::open_private_read(&history_file, "persist history")?;
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            let label = format!("persist history {}:{}", history_file.display(), index + 1);
            let document: AuthenticatedDocument<HistoryPayload> = serde_json::from_str(&line)
                .map_err(|error| format!("Unsigned, corrupt, or incompatible {label}: {error}"))?;
            verify_document(&document, key, HISTORY_DOMAIN, &label)?;
            let tag_hex = document.authentication.tag_hex.clone();
            if document.payload.version != HISTORY_VERSION
                || document.payload.profile != paths.profile
                || document.payload.event.schema_version != EVENT_SCHEMA_VERSION
            {
                return Err(format!("{label} belongs to another profile or schema").into());
            }
            records.push(VerifiedRecord {
                payload: document.payload,
                tag_hex,
                file: history_file.clone(),
            });
        }
    }
    Ok(records)
}

fn empty_history_state(profile: &str) -> HistoryState {
    HistoryState {
        version: HISTORY_STATE_VERSION,
        profile: profile.into(),
        first_sequence: 1,
        first_previous_tag_hex: String::new(),
        last_sequence: 0,
        last_tag_hex: String::new(),
    }
}

fn verify_chain(
    paths: &Paths,
    key: &auth::Key,
) -> Result<(HistoryState, Vec<VerifiedRecord>), Error> {
    let records = read_records(paths, key)?;
    let Some(mut state) = load_history_state(paths, key)? else {
        if records.is_empty() {
            return Ok((empty_history_state(&paths.profile), records));
        }
        return Err("Persist history exists without its authenticated state".into());
    };

    let selected: Vec<_> = records
        .iter()
        .filter(|record| record.payload.sequence >= state.first_sequence)
        .collect();
    if selected.is_empty() {
        if state.last_sequence == 0 {
            return Ok((state, records));
        }
        return Err("Persist history was truncated or deleted".into());
    }
    let mut expected_sequence = state.first_sequence;
    let mut previous = state.first_previous_tag_hex.clone();
    let mut recorded_tail_seen = state.last_sequence == 0;
    for record in &selected {
        if record.payload.sequence != expected_sequence
            || record.payload.previous_tag_hex != previous
        {
            return Err("Persist history chain is incomplete or reordered".into());
        }
        if record.payload.sequence == state.last_sequence {
            if record.tag_hex != state.last_tag_hex {
                return Err("Persist history state does not match its recorded tail".into());
            }
            recorded_tail_seen = true;
        }
        previous = record.tag_hex.clone();
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or("Persist history sequence overflow")?;
    }
    if !recorded_tail_seen {
        return Err("Persist history was truncated or its state was rolled forward".into());
    }
    let tail = selected.last().expect("selected history is non-empty");
    if tail.payload.sequence > state.last_sequence {
        state.last_sequence = tail.payload.sequence;
        state.last_tag_hex = tail.tag_hex.clone();
        save_history_state(&paths.history_state, &state, key, true)?;
    }
    Ok((state, records))
}

fn apply_history_retention(
    paths: &Paths,
    policy: retention::Policy,
    key: &auth::Key,
    state: &mut HistoryState,
    records: &[VerifiedRecord],
) -> Result<(), Error> {
    let directory = paths
        .history
        .parent()
        .ok_or("persist history has no parent")?;
    let remove = retention::jsonl_to_prune(directory, policy, Some(&paths.history))?;
    if remove.is_empty() {
        return Ok(());
    }
    let files = history_files(&paths.history)?;
    let first_kept = files
        .iter()
        .position(|file| !remove.contains(file))
        .unwrap_or(files.len());
    if files[first_kept..].iter().any(|file| remove.contains(file)) {
        return Err("History retention selected a non-prefix segment set".into());
    }
    let first = records
        .iter()
        .find(|record| !remove.contains(&record.file))
        .ok_or("History retention cannot remove the active history")?;
    state.first_sequence = first.payload.sequence;
    state.first_previous_tag_hex = first.payload.previous_tag_hex.clone();
    save_history_state(&paths.history_state, state, key, true)?;
    for path in remove {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn append_history(
    paths: &Paths,
    events: &[PersistEvent],
    policy: retention::Policy,
    key_path: &Path,
) -> Result<(), Error> {
    let key = auth::load(key_path)?;
    let (mut state, existing_records) = verify_chain(paths, &key)?;
    if events.is_empty() {
        return apply_history_retention(paths, policy, &key, &mut state, &existing_records);
    }
    if !paths.history_state.exists() {
        save_history_state(&paths.history_state, &state, &key, false)?;
    }

    let mut previous = state.last_tag_hex.clone();
    let mut sequence = state
        .last_sequence
        .checked_add(1)
        .ok_or("Persist history sequence overflow")?;
    let mut batch = Vec::new();
    for event in events {
        let payload = HistoryPayload {
            version: HISTORY_VERSION,
            profile: paths.profile.clone(),
            sequence,
            previous_tag_hex: previous,
            event: event.clone(),
        };
        let document = signed_document(payload, &key, HISTORY_DOMAIN)?;
        previous = document.authentication.tag_hex.clone();
        serde_json::to_writer(&mut batch, &document)?;
        batch.push(b'\n');
        sequence = sequence
            .checked_add(1)
            .ok_or("Persist history sequence overflow")?;
    }
    if paths.history.exists()
        && fs::metadata(&paths.history)?
            .len()
            .saturating_add(batch.len() as u64)
            > policy.max_bytes
    {
        fs::rename(&paths.history, retention::rotated_path(&paths.history))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&paths.history)?;
    private_store::validate_private_file(&file, "persist history")?;
    file.write_all(&batch)?;
    file.sync_all()?;

    state.last_sequence = sequence - 1;
    state.last_tag_hex = previous;
    save_history_state(&paths.history_state, &state, &key, true)?;
    let (_, records) = verify_chain(paths, &key)?;
    apply_history_retention(paths, policy, &key, &mut state, &records)
}

pub fn read_history(
    paths: &Paths,
    policy: retention::Policy,
    key_path: &Path,
) -> Result<(Vec<PersistEvent>, Vec<String>), Error> {
    let key = auth::load(key_path)?;
    let (mut state, records) = verify_chain(paths, &key)?;
    apply_history_retention(paths, policy, &key, &mut state, &records)?;
    let events = records
        .into_iter()
        .filter(|record| record.payload.sequence >= state.first_sequence)
        .map(|record| record.payload.event)
        .collect();
    Ok((events, Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::model::{EntrySpec, Evidence, Scope, Source};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct Fixture {
        temp: PathBuf,
        root: PathBuf,
        paths: Paths,
        key: PathBuf,
        snapshot: Snapshot,
    }

    impl Fixture {
        fn new() -> Self {
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
            let key = temp.join("key");
            private_store::atomic_write(&key, &[7; 32], false).unwrap();
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
            Self {
                temp,
                root,
                paths,
                key,
                snapshot,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.temp);
        }
    }

    fn policy() -> retention::Policy {
        retention::Policy {
            max_age: Duration::from_secs(3600),
            max_bytes: 1024 * 1024,
        }
    }

    fn event(fixture: &Fixture) -> PersistEvent {
        let entry = fixture.snapshot.entries.values().next().unwrap().clone();
        PersistEvent {
            schema_version: EVENT_SCHEMA_VERSION,
            kind: super::super::compare::EventKind::Added,
            detected_at: "now".into(),
            entry_id: entry.id.clone(),
            changed_fields: vec!["entry".into()],
            before: None,
            after: Some(entry),
        }
    }

    #[test]
    fn signed_baseline_round_trip_refuses_tampering_and_wrong_profile() {
        let fixture = Fixture::new();
        save_baseline(
            &fixture.paths.baseline,
            &fixture.root,
            ScopeSelection::All,
            &fixture.snapshot,
            &fixture.key,
            false,
        )
        .unwrap();
        assert_eq!(
            load_baseline(
                &fixture.paths.baseline,
                &fixture.root,
                ScopeSelection::All,
                &fixture.key,
            )
            .unwrap()
            .entries
            .len(),
            1
        );
        assert!(
            load_baseline(
                &fixture.paths.baseline,
                &fixture.root,
                ScopeSelection::User,
                &fixture.key,
            )
            .is_err()
        );
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.paths.baseline).unwrap()).unwrap();
        value["payload"]["created_at"] = "tampered".into();
        fs::write(&fixture.paths.baseline, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            load_baseline(
                &fixture.paths.baseline,
                &fixture.root,
                ScopeSelection::All,
                &fixture.key,
            )
            .is_err()
        );
    }

    #[test]
    fn signed_history_rejects_record_tampering() {
        let fixture = Fixture::new();
        let event = event(&fixture);
        append_history(
            &fixture.paths,
            &[event.clone(), event],
            policy(),
            &fixture.key,
        )
        .unwrap();
        assert_eq!(
            read_history(&fixture.paths, policy(), &fixture.key)
                .unwrap()
                .0
                .len(),
            2
        );
        let original = fs::read_to_string(&fixture.paths.history).unwrap();
        let mut lines: Vec<_> = original.lines().collect();
        lines.reverse();
        fs::write(&fixture.paths.history, format!("{}\n", lines.join("\n"))).unwrap();
        assert!(read_history(&fixture.paths, policy(), &fixture.key).is_err());
        let tampered = original.replace("desktop login", "tampered login");
        fs::write(&fixture.paths.history, tampered).unwrap();
        assert!(read_history(&fixture.paths, policy(), &fixture.key).is_err());
    }

    #[test]
    fn history_recovers_state_tail_and_retains_a_verifiable_suffix() {
        let fixture = Fixture::new();
        let event = event(&fixture);
        append_history(
            &fixture.paths,
            std::slice::from_ref(&event),
            policy(),
            &fixture.key,
        )
        .unwrap();
        let old_state = fs::read(&fixture.paths.history_state).unwrap();
        append_history(
            &fixture.paths,
            std::slice::from_ref(&event),
            policy(),
            &fixture.key,
        )
        .unwrap();
        fs::write(&fixture.paths.history_state, old_state).unwrap();
        assert_eq!(
            read_history(&fixture.paths, policy(), &fixture.key)
                .unwrap()
                .0
                .len(),
            2
        );

        let small = retention::Policy {
            max_age: Duration::from_secs(3600),
            max_bytes: 1,
        };
        append_history(
            &fixture.paths,
            std::slice::from_ref(&event),
            small,
            &fixture.key,
        )
        .unwrap();
        assert_eq!(
            read_history(&fixture.paths, small, &fixture.key)
                .unwrap()
                .0
                .len(),
            1
        );
    }
}
