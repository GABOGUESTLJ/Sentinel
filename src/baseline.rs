use crate::{
    auth, hash_files, private_store,
    read_files::{Entry, Kind, Timestamp},
    scan_files::Entries,
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Component, Path, PathBuf},
};

type Error = Box<dyn std::error::Error>;
const AUTH_VERSION: u32 = 1;
const BASELINE_VERSION: u32 = 3;
const ALGORITHM: &str = "HMAC-SHA256";
const DOMAIN: &[u8] = b"sentinel:fim:baseline:hmac-sha256:v1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEntry {
    path_hex: String,
    info: Entry,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    root_hex: String,
    created_at: String,
    entries: Vec<StoredEntry>,
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
struct AuthenticatedDocument {
    authentication: Authentication,
    payload: Document,
}

pub struct Baseline {
    pub entries: Entries,
}

pub fn location(root: &Path) -> Result<PathBuf, Error> {
    let root = root.canonicalize()?;
    let override_path = std::env::var_os("SENTINEL_STATE_DIR");
    let state = override_path
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from("/var/lib/sentinel").join(private_store::uid().to_string())
        });
    if !state.is_absolute()
        || state
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("SENTINEL_STATE_DIR must be an absolute path without '..' components".into());
    }
    let directory = state.join("fim/baselines");
    if directory.starts_with(&root) {
        return Err(format!(
            "The baseline directory {} is inside the monitored tree; set SENTINEL_STATE_DIR to an external private state directory",
            directory.display()
        ).into());
    }
    // Check all ancestors before creation: recursive create_dir would otherwise
    // follow an existing symlink, including above the private state root.
    reject_symlink_components(&directory)?;
    if override_path.is_none() && !state.try_exists()? {
        return Err(format!(
            "Baseline state directory {} is not provisioned; ask an administrator to create it private and owned by uid {}, or set SENTINEL_STATE_DIR to an absolute writable private directory",
            state.display(), private_store::uid()
        ).into());
    }
    let prepare = || -> Result<(), Error> {
        if override_path.is_some() {
            let mut ancestor = PathBuf::new();
            for component in state.components() {
                ancestor.push(component.as_os_str());
                if !ancestor.try_exists()? {
                    private_store::ensure_private_directory(&ancestor, false, "baseline state")?;
                }
            }
        }
        private_store::ensure_private_directory(&state, false, "baseline state")?;
        private_store::ensure_private_directory(&state.join("fim"), false, "baseline")?;
        private_store::ensure_private_directory(&directory, false, "baseline")
    };
    prepare().map_err(|error| format!(
        "Could not prepare baseline state {}: {error}. Provision a private writable directory owned by uid {}, or set SENTINEL_STATE_DIR; temporary storage is not used as a fallback",
        state.display(), private_store::uid()
    ))?;
    Ok(directory.join(baseline_name(&root)))
}

fn baseline_name(root: &Path) -> String {
    let key = hex::encode(hash_files::hash_bytes(root.as_os_str().as_bytes()));
    format!("{key}.json")
}

fn reject_symlink_components(path: &Path) -> Result<(), Error> {
    let mut ancestor = PathBuf::new();
    for component in path.components() {
        ancestor.push(component.as_os_str());
        match std::fs::symlink_metadata(&ancestor) {
            Ok(metadata) if !metadata.is_dir() => return Err(format!(
                "Unsafe baseline directory component {}: expected a directory, not a symlink or file",
                ancestor.display()
            ).into()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Locate legacy storage without creating it or changing its permissions.
pub fn legacy_location(root: &Path) -> Result<PathBuf, Error> {
    let temp = std::env::temp_dir();
    reject_symlink_components(&temp)?;
    Ok(temp
        .canonicalize()?
        .join(format!("fim-baselines-{}", private_store::uid()))
        .join(baseline_name(&root.canonicalize()?)))
}

/// Authenticate a single read, then publish those exact bytes without replacement.
pub fn migrate(root: &Path, key_path: &Path) -> Result<PathBuf, Error> {
    use std::os::unix::fs::MetadataExt;
    let root = root.canonicalize()?;
    let source = legacy_location(&root)?;
    let directory = source.parent().ok_or("Legacy baseline has no parent")?;
    reject_symlink_components(directory)?;
    // ensure_private_directory creates missing paths, so it cannot be used for
    // this strictly read-only legacy directory validation.
    let metadata = std::fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.uid() != private_store::uid() || metadata.mode() & 0o077 != 0
    {
        return Err("Unsafe legacy baseline directory: expected a private directory owned by the current user".into());
    }
    let bytes = read_bytes(&source)?;
    load_bytes(&bytes, &root, key_path)?;
    let destination = location(&root)?;
    private_store::atomic_write(&destination, &bytes, false)?;
    Ok(destination)
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    let mut file = private_store::open_private_read(path, "baseline").map_err(|error| {
        format!(
            "Could not load baseline {}: {error}. Use --init-baseline to create it explicitly",
            path.display()
        )
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn verify_envelope(envelope: AuthenticatedDocument, key_path: &Path) -> Result<Document, Error> {
    if envelope.authentication.version != AUTH_VERSION
        || envelope.authentication.algorithm != ALGORITHM
    {
        return Err("Unsupported baseline authentication format".into());
    }
    let key = auth::load(key_path).map_err(|error| {
        format!(
            "Could not load the HMAC key {}: {error}",
            key_path.display()
        )
    })?;
    if envelope.authentication.key_id != auth::key_id(&key) {
        return Err("The baseline was signed with a different HMAC key".into());
    }
    let tag = hex::decode(&envelope.authentication.tag_hex)
        .map_err(|_| "Invalid hexadecimal HMAC tag in baseline")?;
    let payload = serde_json::to_vec(&envelope.payload)?;
    auth::verify(&key, DOMAIN, &payload, &tag)?;
    Ok(envelope.payload)
}

fn validate(document: Document, root: &Path) -> Result<Baseline, Error> {
    if !matches!(document.version, 1 | 2 | BASELINE_VERSION)
        || document.root_hex != hex::encode(root.as_os_str().as_bytes())
    {
        return Err("Incompatible baseline or baseline for a different path".into());
    }
    let mut entries = Entries::new();
    for stored in document.entries {
        let path = PathBuf::from(OsString::from_vec(hex::decode(stored.path_hex)?));
        if path.as_os_str().is_empty()
            || !path
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            || path.as_os_str().as_bytes().contains(&0)
        {
            return Err("Invalid path in baseline".into());
        }
        let entry = stored.info;
        if (document.version >= 2 && entry.identity().is_none())
            || entry.filesystem_device.is_some() != entry.inode.is_some()
        {
            return Err("Baseline entry has incomplete filesystem identity".into());
        }
        if (entry.kind == Kind::File) != entry.hash.is_some()
            || (entry.kind == Kind::File) != entry.size.is_some()
            || (entry.kind == Kind::Symlink) != entry.target.is_some()
            || (entry.kind != Kind::Directory) != entry.modified.is_some()
            || matches!(entry.kind, Kind::BlockDevice | Kind::CharDevice) != entry.device.is_some()
            || entry
                .modified
                .is_some_and(|time| time.nanos >= 1_000_000_000)
            || entry.mode > 0o7777
        {
            return Err("Invalid entry in baseline".into());
        }
        if entries.insert(path, entry).is_some() {
            return Err("Duplicate path in baseline".into());
        }
    }
    Ok(Baseline { entries })
}

pub fn load(path: &Path, root: &Path, key_path: &Path) -> Result<Baseline, Error> {
    let bytes = read_bytes(path)?;
    load_bytes(&bytes, root, key_path)
}

fn load_bytes(bytes: &[u8], root: &Path, key_path: &Path) -> Result<Baseline, Error> {
    let envelope: AuthenticatedDocument = serde_json::from_slice(bytes).map_err(|error| {
        format!(
            "Baseline is unsigned, corrupt, or incompatible ({error}); use --update-baseline to migrate a valid legacy baseline"
        )
    })?;
    validate(verify_envelope(envelope, key_path)?, root)
}

pub fn load_for_update(path: &Path, root: &Path, key_path: &Path) -> Result<Baseline, Error> {
    let bytes = read_bytes(path)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value.get("authentication").is_some() || value.get("payload").is_some() {
        let envelope: AuthenticatedDocument = serde_json::from_value(value)?;
        return validate(verify_envelope(envelope, key_path)?, root);
    }
    let document: Document = serde_json::from_value(value)?;
    if !matches!(document.version, 1 | 2) {
        return Err("Only valid version 1 or 2 unsigned baselines can be migrated".into());
    }
    validate(document, root)
}

pub fn save(
    path: &Path,
    root: &Path,
    entries: &Entries,
    key_path: &Path,
    replace: bool,
) -> Result<(), Error> {
    let payload = Document {
        version: BASELINE_VERSION,
        root_hex: hex::encode(root.as_os_str().as_bytes()),
        created_at: Timestamp::now().utc(),
        entries: entries
            .iter()
            .map(|(path, info)| StoredEntry {
                path_hex: hex::encode(path.as_os_str().as_bytes()),
                info: info.clone(),
            })
            .collect(),
    };
    let key = auth::load(key_path)?;
    let tag = auth::sign(&key, DOMAIN, &serde_json::to_vec(&payload)?);
    let envelope = AuthenticatedDocument {
        authentication: Authentication {
            version: AUTH_VERSION,
            algorithm: ALGORITHM.into(),
            key_id: auth::key_id(&key),
            tag_hex: hex::encode(tag),
        },
        payload,
    };
    let mut bytes = serde_json::to_vec_pretty(&envelope)?;
    bytes.push(b'\n');
    private_store::atomic_write(path, &bytes, replace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::{ffi::OsStringExt, fs::PermissionsExt},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let id = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("fim-baseline-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn key(&self, value: u8) -> PathBuf {
            let path = self.0.join(format!("key-{value}"));
            fs::write(&path, [value; 32]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            path
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn file(hash: u8) -> Entry {
        Entry {
            kind: Kind::File,
            hash: Some([hash; 32]),
            target: None,
            size: Some(3),
            modified: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 123,
            }),
            mode: 0o640,
            uid: private_store::uid(),
            gid: 100,
            device: None,
            filesystem_device: Some(7),
            inode: Some(8),
        }
    }

    #[test]
    fn authenticated_round_trip_supports_non_utf8_paths() {
        let temp = Temp::new();
        let root = temp.0.join("watched");
        fs::create_dir(&root).unwrap();
        let path = temp.0.join("reference.json");
        let key = temp.key(7);
        let name = PathBuf::from(OsString::from_vec(b"dot-\xff".to_vec()));
        let entries = Entries::from([(name, file(42))]);
        save(&path, &root, &entries, &key, false).unwrap();
        let envelope: AuthenticatedDocument =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(envelope.payload.version, BASELINE_VERSION);
        assert_eq!(envelope.authentication.algorithm, ALGORITHM);
        assert_eq!(load(&path, &root, &key).unwrap().entries, entries);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn detects_payload_tag_and_key_tampering() {
        let temp = Temp::new();
        let root = temp.0.join("watched");
        fs::create_dir(&root).unwrap();
        let path = temp.0.join("reference.json");
        let key = temp.key(1);
        let wrong_key = temp.key(2);
        save(&path, &root, &Entries::new(), &key, false).unwrap();
        assert!(load(&path, &root, &wrong_key).is_err());
        let original = fs::read(&path).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["payload"]["created_at"] = "changed".into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load(&path, &root, &key).is_err());
        fs::write(&path, original).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["authentication"]["tag_hex"] = "00".repeat(32).into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load(&path, &root, &key).is_err());
    }

    #[test]
    fn only_explicit_update_accepts_a_valid_legacy_baseline() {
        let temp = Temp::new();
        let root = temp.0.join("watched");
        fs::create_dir(&root).unwrap();
        let path = temp.0.join("reference.json");
        let key = temp.key(3);
        let legacy = Document {
            version: 2,
            root_hex: hex::encode(root.as_os_str().as_bytes()),
            created_at: Timestamp::now().utc(),
            entries: vec![StoredEntry {
                path_hex: hex::encode(b"file"),
                info: file(4),
            }],
        };
        private_store::atomic_write(&path, &serde_json::to_vec(&legacy).unwrap(), false).unwrap();
        assert!(load(&path, &root, &key).is_err());
        assert!(load_for_update(&path, &root, &key).is_ok());
    }

    #[test]
    fn refuses_overwrite_and_signed_corruption_during_update() {
        let temp = Temp::new();
        let root = temp.0.join("watched");
        fs::create_dir(&root).unwrap();
        let path = temp.0.join("reference.json");
        let key = temp.key(5);
        save(&path, &root, &Entries::new(), &key, false).unwrap();
        let trusted = fs::read(&path).unwrap();
        assert!(save(&path, &root, &Entries::new(), &key, false).is_err());
        assert_eq!(fs::read(&path).unwrap(), trusted);
        let mut value: serde_json::Value = serde_json::from_slice(&trusted).unwrap();
        value["payload"]["root_hex"] = "00".into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load_for_update(&path, &root, &key).is_err());
    }

    // Environment-dependent APIs run in a child so parallel tests never mutate
    // the process-wide environment or access the default system destination.
    #[test]
    fn durable_storage_contract() {
        let temp = Temp::new();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "baseline::tests::durable_storage_child",
                "--nocapture",
            ])
            .env("BASELINE_CONTRACT_CHILD", "1")
            .env("TMPDIR", &temp.0)
            .env("SENTINEL_STATE_DIR", temp.0.join("state"))
            .status()
            .unwrap();
        assert!(status.success());

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "baseline::tests::default_location_child",
                "--nocapture",
            ])
            .env("BASELINE_CONTRACT_CHILD", "1")
            .env_remove("SENTINEL_STATE_DIR")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );

        let watched = temp.0.join("watched");
        fs::create_dir(&watched).unwrap();
        let linked = temp.0.join("linked");
        std::os::unix::fs::symlink(&watched, &linked).unwrap();
        for (state, expected_error) in [
            (PathBuf::from("relative-state"), "must be an absolute path"),
            (watched.join("new/state"), "inside the monitored tree"),
            (linked.join("state"), "not a symlink"),
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "baseline::tests::location_rejection_child",
                    "--nocapture",
                ])
                .env("BASELINE_CONTRACT_CHILD", "1")
                .env("BASELINE_TEST_ROOT", &watched)
                .env("BASELINE_EXPECTED_ERROR", expected_error)
                .env("SENTINEL_STATE_DIR", state)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert_eq!(fs::read_dir(&watched).unwrap().count(), 0);
        }
        if private_store::uid() != 0 {
            let locked = temp.0.join("locked");
            fs::create_dir(&locked).unwrap();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "baseline::tests::location_rejection_child",
                    "--nocapture",
                ])
                .env("BASELINE_CONTRACT_CHILD", "1")
                .env("BASELINE_TEST_ROOT", &watched)
                .env(
                    "BASELINE_EXPECTED_ERROR",
                    "Provision a private writable directory",
                )
                .env("SENTINEL_STATE_DIR", &locked)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert_eq!(
                fs::metadata(&locked).unwrap().permissions().mode() & 0o777,
                0o500
            );
            assert_eq!(fs::read_dir(&locked).unwrap().count(), 0);
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[test]
    fn location_rejection_child() {
        if std::env::var_os("BASELINE_CONTRACT_CHILD").is_none() {
            return;
        }
        let root = PathBuf::from(std::env::var_os("BASELINE_TEST_ROOT").unwrap());
        let expected = std::env::var("BASELINE_EXPECTED_ERROR").unwrap();
        let error = location(&root).unwrap_err().to_string();
        assert!(error.contains(&expected), "{error}");
    }

    #[test]
    fn default_location_child() {
        if std::env::var_os("BASELINE_CONTRACT_CHILD").is_none() {
            return;
        }
        // Root covers every possible destination: rejection must precede writes.
        let error = location(Path::new("/")).unwrap_err().to_string();
        assert!(error.contains("inside the monitored tree"), "{error}");
        assert!(
            error.contains(&format!("/var/lib/sentinel/{}", private_store::uid())),
            "{error}"
        );
    }

    #[test]
    fn durable_storage_child() {
        use std::os::unix::fs::{MetadataExt, symlink};
        if std::env::var_os("BASELINE_CONTRACT_CHILD").is_none() {
            return;
        }
        let temp = Temp::new();
        let root = temp.0.join("watched");
        fs::create_dir(&root).unwrap();
        let state = PathBuf::from(std::env::var_os("SENTINEL_STATE_DIR").unwrap());
        let digest = hex::encode(hash_files::hash_bytes(root.as_os_str().as_bytes()));
        let expected = state.join("fim/baselines").join(format!("{digest}.json"));
        let source = legacy_location(&root).unwrap();
        assert!(!source.parent().unwrap().exists());
        assert_eq!(
            source,
            std::env::temp_dir()
                .join(format!("fim-baselines-{}", private_store::uid()))
                .join(format!("{digest}.json"))
        );
        assert!(!state.exists());
        let absent_key = temp.0.join("not-created-key");
        assert!(migrate(&root, &absent_key).is_err());
        assert!(!source.parent().unwrap().exists());
        assert!(!state.exists());
        assert!(!absent_key.exists());

        let destination = location(&root).unwrap();
        assert_eq!(destination, expected);
        for directory in [&state, &state.join("fim"), destination.parent().unwrap()] {
            let metadata = fs::symlink_metadata(directory).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o700);
            assert_eq!(metadata.uid(), private_store::uid());
        }
        assert_eq!(location(&root.join(".")).unwrap(), destination);
        assert!(location(temp.0.parent().unwrap()).is_err());

        private_store::ensure_private_directory(source.parent().unwrap(), false, "test").unwrap();
        let key = temp.key(11);
        let key_bytes = fs::read(&key).unwrap();
        let entries = Entries::from([(PathBuf::from("trusted"), file(7))]);
        save(&source, &root, &entries, &key, false).unwrap();
        // Valid noncanonical JSON whitespace must survive migration exactly.
        let mut original = fs::read(&source).unwrap();
        original.extend_from_slice(b" \n\t");
        fs::write(&source, &original).unwrap();
        fs::write(root.join("trusted"), b"untrusted current content").unwrap();
        assert_eq!(migrate(&root, &key).unwrap(), destination);
        assert_eq!(fs::read(&destination).unwrap(), original);
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read(&key).unwrap(), key_bytes);
        assert_eq!(load(&destination, &root, &key).unwrap().entries, entries);
        let metadata = fs::metadata(&destination).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), private_store::uid());
        assert_eq!(metadata.nlink(), 1);
        assert!(migrate(&root, &key).is_err());
        assert_eq!(fs::read(&destination).unwrap(), original);
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read(&key).unwrap(), key_bytes);
        fs::set_permissions(source.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(migrate(&root, &key).is_err());
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read(&destination).unwrap(), original);
        assert_eq!(fs::read(&key).unwrap(), key_bytes);
        fs::set_permissions(source.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();

        for variant in [
            "tamper",
            "wrong-root",
            "unsigned",
            "wrong-key",
            "missing-key",
            "public",
            "symlink",
        ] {
            let other = temp.0.join(variant);
            fs::create_dir(&other).unwrap();
            let legacy = legacy_location(&other).unwrap();
            let target = location(&other).unwrap();
            let signing_root = if variant == "wrong-root" {
                &root
            } else {
                &other
            };
            save(&legacy, signing_root, &entries, &key, false).unwrap();
            let mut value: serde_json::Value =
                serde_json::from_slice(&fs::read(&legacy).unwrap()).unwrap();
            match variant {
                "tamper" => {
                    value["payload"]["created_at"] = "changed".into();
                    fs::write(&legacy, serde_json::to_vec(&value).unwrap()).unwrap();
                }
                "unsigned" => {
                    value["payload"]["version"] = 2.into();
                    fs::write(&legacy, serde_json::to_vec(&value["payload"]).unwrap()).unwrap();
                }
                "public" => {
                    fs::set_permissions(&legacy, fs::Permissions::from_mode(0o644)).unwrap()
                }
                "symlink" => {
                    let moved = temp.0.join("linked-source");
                    fs::rename(&legacy, &moved).unwrap();
                    symlink(moved, &legacy).unwrap();
                }
                _ => {}
            }
            let supplied_key = match variant {
                "wrong-key" => temp.key(12),
                "missing-key" => temp.0.join("absent-key"),
                _ => key.clone(),
            };
            let before = fs::read(&legacy).unwrap();
            let directory_before = fs::read_dir(target.parent().unwrap()).unwrap().count();
            assert!(migrate(&other, &supplied_key).is_err(), "{variant}");
            assert!(!target.exists(), "{variant}");
            assert_eq!(fs::read(&legacy).unwrap(), before, "{variant}");
            assert_eq!(fs::read(&key).unwrap(), key_bytes, "{variant}");
            assert_eq!(
                fs::read_dir(target.parent().unwrap()).unwrap().count(),
                directory_before
            );
            if variant == "missing-key" {
                assert!(!supplied_key.exists());
            }
        }

        // Unsafe existing state is rejected without changing its permissions.
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(location(&root).is_err());
        assert_eq!(fs::metadata(&state).unwrap().mode() & 0o777, 0o755);
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(state.join("fim"), state.join("real-fim")).unwrap();
        symlink(state.join("real-fim"), state.join("fim")).unwrap();
        assert!(location(&root).is_err());
        assert_eq!(fs::read(&destination).unwrap(), original);
    }
}
