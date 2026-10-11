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
    let temp = std::env::temp_dir().canonicalize()?;
    let directory = temp.join(format!("fim-baselines-{}", private_store::uid()));
    if directory.starts_with(root) {
        return Err("The temporary baseline directory is inside the monitored tree; set TMPDIR to an external temporary directory".into());
    }
    private_store::ensure_private_directory(&directory, false, "baseline")?;
    let key = hex::encode(hash_files::hash_bytes(root.as_os_str().as_bytes()));
    Ok(directory.join(format!("{key}.json")))
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
    let envelope: AuthenticatedDocument = serde_json::from_slice(&bytes).map_err(|error| {
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
}
