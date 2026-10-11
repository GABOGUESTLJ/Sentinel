use crate::{
    read_files::{Entry, Identity},
    scan_files::Entries,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Created {
        path: PathBuf,
    },
    Modified {
        path: PathBuf,
    },
    Deleted {
        path: PathBuf,
    },
    Renamed {
        from: PathBuf,
        to: PathBuf,
        content_changed: bool,
    },
}

impl Change {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Created { .. } => "CREATED",
            Self::Modified { .. } => "MODIFIED",
            Self::Deleted { .. } => "DELETED",
            Self::Renamed { .. } => "RENAMED",
        }
    }

    pub fn current_path(&self) -> Option<&Path> {
        match self {
            Self::Created { path } | Self::Modified { path } => Some(path),
            Self::Renamed { to, .. } => Some(to),
            Self::Deleted { .. } => None,
        }
    }

    pub fn previous_path(&self) -> Option<&Path> {
        match self {
            Self::Modified { path } | Self::Deleted { path } => Some(path),
            Self::Renamed { from, .. } => Some(from),
            Self::Created { .. } => None,
        }
    }
}

fn unique_identities<'a>(
    entries: impl Iterator<Item = (&'a PathBuf, &'a Entry)>,
) -> BTreeMap<Identity, &'a PathBuf> {
    let mut unique = BTreeMap::new();
    let mut ambiguous = BTreeSet::new();
    for (path, entry) in entries {
        let Some(identity) = entry.identity() else {
            continue;
        };
        if unique.insert(identity, path).is_some() {
            ambiguous.insert(identity);
        }
    }
    for identity in ambiguous {
        unique.remove(&identity);
    }
    unique
}

fn same_entry(previous: &Entry, current: &Entry) -> bool {
    if previous.identity().is_none() {
        // Version 1 baselines contain no identity. Their other trusted fields
        // still remain authoritative at the original path.
        let mut current_without_identity = current.clone();
        current_without_identity.filesystem_device = None;
        current_without_identity.inode = None;
        previous == &current_without_identity
    } else {
        previous == current
    }
}

pub fn compare(previous: &Entries, current: &Entries) -> Vec<Change> {
    let previous_unique = unique_identities(previous.iter());
    let current_unique = unique_identities(current.iter());
    let renamed: BTreeMap<&PathBuf, &PathBuf> = current_unique
        .iter()
        .filter_map(|(identity, to)| {
            previous_unique
                .get(identity)
                .filter(|from| *from != to)
                .map(|from| (*to, *from))
        })
        .collect();
    let renamed_from: BTreeSet<&PathBuf> = renamed.values().copied().collect();

    let mut changes = Vec::new();
    for (path, entry) in current {
        if let Some(from) = renamed.get(path) {
            changes.push(Change::Renamed {
                from: (*from).clone(),
                to: path.clone(),
                content_changed: previous[*from].hash != entry.hash,
            });
        } else {
            match previous.get(path) {
                Some(old) if !same_entry(old, entry) => {
                    changes.push(Change::Modified { path: path.clone() });
                }
                Some(_) => {}
                None => changes.push(Change::Created { path: path.clone() }),
            }
        }
    }
    for path in previous.keys() {
        if !current.contains_key(path) && !renamed_from.contains(path) {
            changes.push(Change::Deleted { path: path.clone() });
        }
    }
    changes
}

pub fn baseline_status(
    reference: &Entries,
    baseline_changes: &[Change],
    change: &Change,
) -> &'static str {
    if let Some(path) = change.current_path() {
        return baseline_changes
            .iter()
            .find(|candidate| candidate.current_path() == Some(path))
            .map_or("COMPLIANT", |candidate| candidate.label());
    }
    let path = change
        .previous_path()
        .expect("a deletion has a previous path");
    if reference.contains_key(path) {
        "DELETED"
    } else {
        "COMPLIANT"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read_files::{Kind, Timestamp};

    fn file(hash: u8, inode: u64) -> Entry {
        Entry {
            kind: Kind::File,
            hash: Some([hash; 32]),
            target: None,
            size: Some(1),
            modified: Some(Timestamp {
                seconds: 0,
                nanos: 0,
            }),
            mode: 0o600,
            uid: 1000,
            gid: 1000,
            device: None,
            filesystem_device: Some(7),
            inode: Some(inode),
        }
    }

    #[test]
    fn classifies_created_modified_deleted_and_unchanged() {
        let previous = Entries::from([
            ("same".into(), file(0, 1)),
            ("edited".into(), file(1, 2)),
            ("gone".into(), file(2, 3)),
        ]);
        let current = Entries::from([
            ("same".into(), file(0, 1)),
            ("edited".into(), file(3, 2)),
            ("new".into(), file(4, 4)),
        ]);
        assert_eq!(
            compare(&previous, &current),
            vec![
                Change::Modified {
                    path: "edited".into()
                },
                Change::Created { path: "new".into() },
                Change::Deleted {
                    path: "gone".into()
                }
            ]
        );
        assert!(compare(&current, &current).is_empty());
    }

    #[test]
    fn detects_unique_identity_rename_and_reports_reference_status() {
        let reference = Entries::from([("old".into(), file(1, 8))]);
        let current = Entries::from([("new".into(), file(1, 8))]);
        let changes = compare(&reference, &current);
        assert_eq!(
            changes,
            vec![Change::Renamed {
                from: "old".into(),
                to: "new".into(),
                content_changed: false,
            }]
        );
        assert_eq!(
            baseline_status(&reference, &changes, &changes[0]),
            "RENAMED"
        );
    }

    #[test]
    fn rename_uses_identity_and_hash_reports_content_change() {
        let previous = Entries::from([("old".into(), file(1, 8))]);
        let current = Entries::from([("new".into(), file(2, 8))]);
        assert_eq!(
            compare(&previous, &current),
            vec![Change::Renamed {
                from: "old".into(),
                to: "new".into(),
                content_changed: true,
            }]
        );
    }

    #[test]
    fn legacy_reference_identity_does_not_create_false_modifications() {
        let mut trusted = file(1, 8);
        trusted.filesystem_device = None;
        trusted.inode = None;
        let previous = Entries::from([("file".into(), trusted)]);
        let current = Entries::from([("file".into(), file(1, 8))]);
        assert!(compare(&previous, &current).is_empty());
    }

    #[test]
    fn ambiguous_hard_links_are_not_claimed_as_renames() {
        let previous = Entries::from([("one".into(), file(1, 9)), ("two".into(), file(1, 9))]);
        let current = Entries::from([("three".into(), file(1, 9))]);
        assert_eq!(
            compare(&previous, &current),
            vec![
                Change::Created {
                    path: "three".into()
                },
                Change::Deleted { path: "one".into() },
                Change::Deleted { path: "two".into() }
            ]
        );
    }

    #[test]
    fn retained_hard_link_keeps_other_paths_ambiguous() {
        let previous = Entries::from([("one".into(), file(1, 9)), ("shared".into(), file(1, 9))]);
        let current = Entries::from([("shared".into(), file(1, 9)), ("three".into(), file(1, 9))]);
        assert_eq!(
            compare(&previous, &current),
            vec![
                Change::Created {
                    path: "three".into()
                },
                Change::Deleted { path: "one".into() }
            ]
        );
    }

    #[test]
    fn copied_identical_content_is_not_a_rename() {
        let previous = Entries::from([("old".into(), file(1, 10))]);
        let current = Entries::from([("new".into(), file(1, 11))]);
        assert_eq!(
            compare(&previous, &current),
            vec![
                Change::Created { path: "new".into() },
                Change::Deleted { path: "old".into() }
            ]
        );
    }

    #[test]
    fn rename_over_existing_destination_is_classified_by_identity() {
        let previous = Entries::from([
            ("source".into(), file(1, 10)),
            ("destination".into(), file(2, 11)),
        ]);
        let current = Entries::from([("destination".into(), file(1, 10))]);
        assert_eq!(
            compare(&previous, &current),
            vec![Change::Renamed {
                from: "source".into(),
                to: "destination".into(),
                content_changed: false,
            }]
        );
    }
}
