use crate::{
    monitor::{self, Change},
    read_files::{Entry, Kind},
    scan_files::Entries,
};
use serde::{Deserialize, Serialize};
use std::{os::unix::ffi::OsStrExt, path::PathBuf};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPath {
    pub display: String,
    pub hex: String,
}

impl StoredPath {
    fn new(path: &std::path::Path) -> Self {
        Self {
            display: path.to_string_lossy().into_owned(),
            hex: hex::encode(path.as_os_str().as_bytes()),
        }
    }

    pub fn quoted(&self) -> String {
        format!("{:?}", self.display)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntrySnapshot {
    pub kind: Kind,
    pub sha256: Option<String>,
    pub target_display: Option<String>,
    pub target_hex: Option<String>,
    pub size: Option<u64>,
    pub modified: Option<String>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub device: Option<u64>,
    pub filesystem_device: Option<u64>,
    pub inode: Option<u64>,
}

impl From<&Entry> for EntrySnapshot {
    fn from(entry: &Entry) -> Self {
        Self {
            kind: entry.kind.clone(),
            sha256: entry.hash.as_ref().map(hex::encode),
            target_display: entry
                .target
                .as_deref()
                .map(|target| String::from_utf8_lossy(target).into_owned()),
            target_hex: entry.target.as_deref().map(hex::encode),
            size: entry.size,
            modified: entry.modified.map(|time| time.utc()),
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            device: entry.device,
            filesystem_device: entry.filesystem_device,
            inode: entry.inode,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventKind {
    Created,
    Modified,
    Deleted,
    Renamed,
}

impl EventKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::Modified => "MODIFIED",
            Self::Deleted => "DELETED",
            Self::Renamed => "RENAMED",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Origin {
    Startup,
    Reconciliation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub schema_version: u32,
    pub root_hex: String,
    pub run_id: String,
    pub sequence: u64,
    pub detected_at: String,
    pub origin: Origin,
    pub kind: EventKind,
    pub baseline_status: String,
    pub previous_path: Option<StoredPath>,
    pub current_path: Option<StoredPath>,
    pub changed_fields: Vec<String>,
    pub before: Option<EntrySnapshot>,
    pub after: Option<EntrySnapshot>,
    pub baseline: Option<EntrySnapshot>,
    pub content_changed: Option<bool>,
    pub replaced: bool,
    pub replaced_before: Option<EntrySnapshot>,
}

impl AuditEvent {
    pub fn matches_path_hex(&self, path_hex: &str) -> bool {
        self.previous_path
            .as_ref()
            .is_some_and(|path| path.hex == path_hex)
            || self
                .current_path
                .as_ref()
                .is_some_and(|path| path.hex == path_hex)
    }
}

fn changed_fields(before: Option<&Entry>, after: Option<&Entry>, renamed: bool) -> Vec<String> {
    let mut fields = Vec::new();
    if renamed {
        fields.push("path".to_owned());
    }
    let (Some(before), Some(after)) = (before, after) else {
        fields.push(
            if before.is_none() {
                "created"
            } else {
                "deleted"
            }
            .to_owned(),
        );
        return fields;
    };
    let comparisons = [
        (before.kind != after.kind, "type"),
        (before.hash != after.hash, "content"),
        (before.target != after.target, "target"),
        (before.size != after.size, "size"),
        (before.modified != after.modified, "mtime"),
        (before.mode != after.mode, "mode"),
        (before.uid != after.uid, "uid"),
        (before.gid != after.gid, "gid"),
        (before.device != after.device, "device"),
        (
            before.filesystem_device != after.filesystem_device,
            "filesystem-device",
        ),
        (before.inode != after.inode, "inode"),
    ];
    fields.extend(
        comparisons
            .into_iter()
            .filter(|(changed, _)| *changed)
            .map(|(_, field)| field.to_owned()),
    );
    fields
}

pub struct BuildContext<'a> {
    pub root_hex: &'a str,
    pub run_id: &'a str,
    pub next_sequence: &'a mut u64,
    pub origin: Origin,
}

pub fn build(
    previous: &Entries,
    current: &Entries,
    trusted: &Entries,
    context: &mut BuildContext<'_>,
) -> Vec<AuditEvent> {
    let baseline_changes = monitor::compare(trusted, current);
    let detected_at = crate::read_files::Timestamp::now().utc();
    monitor::compare(previous, current)
        .into_iter()
        .map(|change| {
            *context.next_sequence = context.next_sequence.saturating_add(1);
            let old = change.previous_path().and_then(|path| previous.get(path));
            let new = change.current_path().and_then(|path| current.get(path));
            let baseline_status = monitor::baseline_status(trusted, &baseline_changes, &change);
            let baseline = match &change {
                Change::Renamed { from, to, .. } => trusted.get(from).or_else(|| trusted.get(to)),
                _ => change
                    .current_path()
                    .and_then(|path| trusted.get(path))
                    .or_else(|| change.previous_path().and_then(|path| trusted.get(path))),
            };
            let (kind, content_changed, replaced, replaced_before) = match &change {
                Change::Created { .. } => (EventKind::Created, None, false, None),
                Change::Modified { .. } => (EventKind::Modified, None, false, None),
                Change::Deleted { .. } => (EventKind::Deleted, None, false, None),
                Change::Renamed {
                    to,
                    content_changed,
                    ..
                } => (
                    EventKind::Renamed,
                    Some(*content_changed),
                    previous.contains_key(to),
                    previous.get(to).map(EntrySnapshot::from),
                ),
            };
            AuditEvent {
                schema_version: SCHEMA_VERSION,
                root_hex: context.root_hex.to_owned(),
                run_id: context.run_id.to_owned(),
                sequence: *context.next_sequence,
                detected_at: detected_at.clone(),
                origin: context.origin,
                kind,
                baseline_status: baseline_status.to_owned(),
                previous_path: change.previous_path().map(StoredPath::new),
                current_path: change.current_path().map(StoredPath::new),
                changed_fields: changed_fields(old, new, matches!(change, Change::Renamed { .. })),
                before: old.map(EntrySnapshot::from),
                after: new.map(EntrySnapshot::from),
                baseline: baseline.map(EntrySnapshot::from),
                content_changed,
                replaced,
                replaced_before,
            }
        })
        .collect()
}

pub fn normalize_filter(root: &std::path::Path, value: PathBuf) -> Result<String, String> {
    use std::path::Component;

    let relative = if value.is_absolute() {
        value
            .strip_prefix(root)
            .map_err(|_| "The history file filter must be inside the monitored root")?
            .to_path_buf()
    } else {
        value
    };
    let mut normalized = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            _ => {
                return Err(
                    "The history file filter must be a path inside the monitored root".into(),
                );
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err("The history file filter cannot be empty".into());
    }
    Ok(hex::encode(normalized.as_os_str().as_bytes()))
}
