use crate::event::{AuditEvent, SCHEMA_VERSION};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Seek, SeekFrom, Write},
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
};

type Error = Box<dyn std::error::Error>;

pub fn directory(root: &Path) -> Result<PathBuf, Error> {
    let root_key = hex::encode(crate::hash_files::hash_bytes(root.as_os_str().as_bytes()));
    let directory = crate::private_store::state_home()?
        .join("sentinel")
        .join("fim")
        .join(root_key)
        .join("history");
    if directory.starts_with(root) {
        return Err("The history directory is inside the monitored tree; set XDG_STATE_HOME to an external directory".into());
    }
    Ok(directory)
}

fn run_id() -> String {
    let now = crate::read_files::Timestamp::now();
    format!("{}-{:09}-{}", now.seconds, now.nanos, std::process::id())
}

pub struct Writer {
    file: File,
    path: PathBuf,
    root_hex: String,
    run_id: String,
    directory: PathBuf,
    policy: crate::retention::Policy,
    segment: u32,
}

impl Writer {
    pub fn open(root: &Path, policy: crate::retention::Policy) -> Result<Self, Error> {
        let directory = directory(root)?;
        crate::private_store::ensure_private_directory(&directory, true, "history")?;
        crate::retention::prune_jsonl(&directory, policy, None)?;
        let run_id = run_id();
        let path = directory.join(format!("{run_id}.jsonl"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        Ok(Self {
            file,
            path,
            root_hex: hex::encode(root.as_os_str().as_bytes()),
            run_id,
            directory,
            policy,
            segment: 0,
        })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn root_hex(&self) -> &str {
        &self.root_hex
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&mut self, events: &[AuditEvent]) -> Result<(), Error> {
        if events.is_empty() {
            return Ok(());
        }
        let mut batch = Vec::new();
        for event in events {
            serde_json::to_writer(&mut batch, event)?;
            batch.push(b'\n');
        }
        let current_size = self.file.seek(SeekFrom::End(0))?;
        if current_size > 0
            && current_size.saturating_add(batch.len() as u64) > self.policy.max_bytes
        {
            self.segment = self.segment.saturating_add(1);
            self.path = self
                .directory
                .join(format!("{}-{}.jsonl", self.run_id, self.segment));
            self.file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&self.path)?;
        }
        let start = self.file.seek(SeekFrom::End(0))?;
        let result = (|| -> Result<(), Error> {
            self.file.write_all(&batch)?;
            self.file.flush()?;
            self.file.sync_data()?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = self.file.set_len(start);
            let _ = self.file.seek(SeekFrom::End(0));
            return Err(error);
        }
        crate::retention::prune_jsonl(&self.directory, self.policy, Some(&self.path))?;
        Ok(())
    }
}

pub struct ReadResult {
    pub events: Vec<AuditEvent>,
    pub warnings: Vec<String>,
}

pub fn read(
    root: &Path,
    path_filter_hex: Option<&str>,
    policy: crate::retention::Policy,
) -> Result<ReadResult, Error> {
    read_with_policy(root, path_filter_hex, Some(policy))
}

/// Inspect available records without pruning, creating storage, or repairing it.
pub fn read_only(root: &Path, path_filter_hex: Option<&str>) -> Result<ReadResult, Error> {
    read_with_policy(root, path_filter_hex, None)
}

fn read_with_policy(
    root: &Path,
    path_filter_hex: Option<&str>,
    policy: Option<crate::retention::Policy>,
) -> Result<ReadResult, Error> {
    let directory = directory(root)?;
    if !directory.try_exists()? {
        return Ok(ReadResult {
            events: Vec::new(),
            warnings: Vec::new(),
        });
    }
    crate::private_store::ensure_private_directory(&directory, false, "history")?;
    if let Some(policy) = policy {
        crate::retention::prune_jsonl(&directory, policy, None)?;
    }
    let expected_root = hex::encode(root.as_os_str().as_bytes());
    let mut files = Vec::new();
    for item in fs::read_dir(&directory)? {
        let path = item?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "jsonl")
        {
            files.push(path);
        }
    }
    files.sort();

    let mut events = Vec::new();
    let mut warnings = Vec::new();
    let mut seen = BTreeSet::new();
    for path in files {
        let file = crate::private_store::open_private_read(&path, "history file")?;
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event: AuditEvent = match serde_json::from_str(&line) {
                Ok(event) => event,
                Err(error) => {
                    warnings.push(format!("{}:{}: {error}", path.display(), index + 1));
                    continue;
                }
            };
            if event.schema_version != SCHEMA_VERSION || event.root_hex != expected_root {
                warnings.push(format!(
                    "{}:{}: incompatible history event",
                    path.display(),
                    index + 1
                ));
                continue;
            }
            if path_filter_hex.is_some_and(|filter| !event.matches_path_hex(filter)) {
                continue;
            }
            if seen.insert((event.run_id.clone(), event.sequence)) {
                events.push(event);
            }
        }
    }
    events.sort_by(|left, right| {
        (&left.detected_at, &left.run_id, left.sequence).cmp(&(
            &right.detected_at,
            &right.run_id,
            right.sequence,
        ))
    });
    Ok(ReadResult { events, warnings })
}
