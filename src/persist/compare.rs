use super::model::{Coverage, Evidence, PersistenceEntry, Snapshot, Source};
use crate::read_files::Timestamp;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const EVENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventKind {
    Added,
    Modified,
    Removed,
    Enabled,
    Disabled,
    RiskChanged,
}

impl EventKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Added => "ADDED",
            Self::Modified => "MODIFIED",
            Self::Removed => "REMOVED",
            Self::Enabled => "ENABLED",
            Self::Disabled => "DISABLED",
            Self::RiskChanged => "RISK_CHANGED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistEvent {
    pub schema_version: u32,
    pub kind: EventKind,
    pub detected_at: String,
    pub entry_id: String,
    pub changed_fields: Vec<String>,
    pub before: Option<PersistenceEntry>,
    pub after: Option<PersistenceEntry>,
}

fn changed_fields(before: &PersistenceEntry, after: &PersistenceEntry) -> Vec<String> {
    let mut fields = Vec::new();
    if before.origins != after.origins {
        fields.push("origins".into());
    }
    if before.trigger != after.trigger {
        fields.push("trigger".into());
    }
    if before.command != after.command || before.config_sha256 != after.config_sha256 {
        fields.push("configuration".into());
    }
    if before.evidence == after.evidence {
        if before.enabled != after.enabled {
            fields.push("enabled".into());
        }
        if before.evidence == Evidence::Effective && before.active != after.active {
            fields.push("active".into());
        }
    }
    if before.risk != after.risk || before.risk_reasons != after.risk_reasons {
        fields.push("risk".into());
    }
    fields
}

fn classify(before: &PersistenceEntry, after: &PersistenceEntry, fields: &[String]) -> EventKind {
    if !before.static_fields_equal(after) {
        EventKind::Modified
    } else if before.evidence == after.evidence {
        match (before.enabled, after.enabled) {
            (Some(false), Some(true)) => EventKind::Enabled,
            (Some(true), Some(false)) => EventKind::Disabled,
            _ if fields.iter().any(|field| field == "active") => EventKind::Modified,
            _ if fields.iter().any(|field| field == "risk") => EventKind::RiskChanged,
            _ => EventKind::Modified,
        }
    } else {
        EventKind::RiskChanged
    }
}

pub fn compare(baseline: &Snapshot, current: &Snapshot) -> Vec<PersistEvent> {
    let detected_at = Timestamp::now().utc();
    let mut events = Vec::new();
    let mut before_left: BTreeSet<_> = baseline.entries.keys().cloned().collect();
    let mut after_left: BTreeSet<_> = current.entries.keys().cloned().collect();

    for id in baseline.entries.keys() {
        let Some(after) = current.entries.get(id) else {
            continue;
        };
        let before = &baseline.entries[id];
        before_left.remove(id);
        after_left.remove(id);
        let fields = changed_fields(before, after);
        if !fields.is_empty() {
            push_modified(&mut events, &detected_at, id, before, after, fields);
        }
    }

    // Cron identities are semantic. Pair a changed schedule by command, or a
    // changed command by schedule, only when both sides have one clear match.
    for match_trigger in [true, false] {
        let pairs = unique_cron_pairs(baseline, current, &before_left, &after_left, match_trigger);
        for (before_id, after_id) in pairs {
            let before = &baseline.entries[&before_id];
            let after = &current.entries[&after_id];
            before_left.remove(&before_id);
            after_left.remove(&after_id);
            let fields = changed_fields(before, after);
            if !fields.is_empty() {
                push_modified(&mut events, &detected_at, &after_id, before, after, fields);
            }
        }
    }

    for id in after_left {
        let after = &current.entries[&id];
        events.push(PersistEvent {
            schema_version: EVENT_SCHEMA_VERSION,
            kind: EventKind::Added,
            detected_at: detected_at.clone(),
            entry_id: id,
            changed_fields: vec!["entry".into()],
            before: None,
            after: Some(after.clone()),
        });
    }
    for id in before_left {
        let before = &baseline.entries[&id];
        if !current.coverage.contains(&Coverage {
            source: before.source,
            scope: before.scope,
        }) {
            continue;
        }
        events.push(PersistEvent {
            schema_version: EVENT_SCHEMA_VERSION,
            kind: EventKind::Removed,
            detected_at: detected_at.clone(),
            entry_id: id.clone(),
            changed_fields: vec!["entry".into()],
            before: Some(before.clone()),
            after: None,
        });
    }
    events
}

fn push_modified(
    events: &mut Vec<PersistEvent>,
    detected_at: &str,
    id: &str,
    before: &PersistenceEntry,
    after: &PersistenceEntry,
    fields: Vec<String>,
) {
    events.push(PersistEvent {
        schema_version: EVENT_SCHEMA_VERSION,
        kind: classify(before, after, &fields),
        detected_at: detected_at.into(),
        entry_id: id.into(),
        changed_fields: fields,
        before: Some(before.clone()),
        after: Some(after.clone()),
    });
}

fn cron_candidate(left: &PersistenceEntry, right: &PersistenceEntry, match_trigger: bool) -> bool {
    left.source == Source::Cron
        && right.source == Source::Cron
        && left.scope == right.scope
        && left.owner == right.owner
        && left.origins == right.origins
        && if match_trigger {
            left.trigger == right.trigger
        } else {
            left.command == right.command
        }
}

fn unique_cron_pairs(
    baseline: &Snapshot,
    current: &Snapshot,
    before_left: &BTreeSet<String>,
    after_left: &BTreeSet<String>,
    match_trigger: bool,
) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for before_id in before_left {
        let before = &baseline.entries[before_id];
        let candidates: Vec<_> = after_left
            .iter()
            .filter(|after_id| cron_candidate(before, &current.entries[*after_id], match_trigger))
            .collect();
        if candidates.len() != 1 {
            continue;
        }
        let after_id = candidates[0];
        let reverse = before_left
            .iter()
            .filter(|candidate| {
                cron_candidate(
                    &baseline.entries[*candidate],
                    &current.entries[after_id],
                    match_trigger,
                )
            })
            .count();
        if reverse == 1 {
            pairs.push((before_id.clone(), after_id.clone()));
        }
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::model::{EntrySpec, Evidence, Risk, Scope, Source};
    use std::collections::{BTreeMap, BTreeSet};

    fn entry(command: &str) -> PersistenceEntry {
        entry_with("@reboot", command)
    }

    fn entry_with(trigger: &str, command: &str) -> PersistenceEntry {
        let locator = format!("/etc/crontab\0{trigger}\0{command}");
        let semantic = format!("{trigger} root {command}");
        PersistenceEntry::new(EntrySpec {
            source: Source::Cron,
            scope: Scope::System,
            owner: "root",
            locator: &locator,
            origins: vec!["/etc/crontab".into()],
            location_hint: Some("line 1".into()),
            trigger: trigger.into(),
            command: command.into(),
            enabled: Some(true),
            active: None,
            evidence: Evidence::Static,
            semantic_config: semantic.as_bytes(),
        })
    }

    fn snapshot(entry: Option<PersistenceEntry>, covered: bool) -> Snapshot {
        let mut entries = BTreeMap::new();
        if let Some(entry) = entry {
            entries.insert(entry.id.clone(), entry);
        }
        Snapshot {
            observed_at: "time".into(),
            entries,
            coverage: if covered {
                BTreeSet::from([Coverage {
                    source: Source::Cron,
                    scope: Scope::System,
                }])
            } else {
                BTreeSet::new()
            },
            warnings: Vec::new(),
        }
    }

    #[test]
    fn reports_semantic_change_and_its_new_risk() {
        let before = entry("/usr/bin/ok");
        let after = entry("/tmp/payload");
        assert_eq!(after.risk, Risk::High);
        let events = compare(&snapshot(Some(before), true), &snapshot(Some(after), true));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::Modified);
        assert!(events[0].changed_fields.contains(&"configuration".into()));
    }

    #[test]
    fn incomplete_coverage_never_reports_removal() {
        let baseline = snapshot(Some(entry("/usr/bin/ok")), true);
        assert!(compare(&baseline, &snapshot(None, false)).is_empty());
        assert_eq!(
            compare(&baseline, &snapshot(None, true))[0].kind,
            EventKind::Removed
        );
    }

    #[test]
    fn static_enablement_changes_are_classified() {
        let before = entry("/usr/bin/ok");
        let mut after = before.clone();
        after.enabled = Some(false);
        let events = compare(&snapshot(Some(before), true), &snapshot(Some(after), true));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::Disabled);
        assert_eq!(events[0].changed_fields, ["enabled"]);
    }

    #[test]
    fn pairs_unique_cron_command_and_schedule_changes_as_modified() {
        let command_change = compare(
            &snapshot(Some(entry("/usr/bin/old")), true),
            &snapshot(Some(entry("/usr/bin/new")), true),
        );
        assert_eq!(command_change.len(), 1);
        assert_eq!(command_change[0].kind, EventKind::Modified);

        let schedule_change = compare(
            &snapshot(Some(entry_with("0 1 * * *", "/usr/bin/job")), true),
            &snapshot(Some(entry_with("0 2 * * *", "/usr/bin/job")), true),
        );
        assert_eq!(schedule_change.len(), 1);
        assert_eq!(schedule_change[0].kind, EventKind::Modified);
    }

    #[test]
    fn location_hint_alone_is_not_a_change() {
        let before = entry("/usr/bin/job");
        let mut after = before.clone();
        after.location_hint = Some("line 90".into());
        assert!(compare(&snapshot(Some(before), true), &snapshot(Some(after), true)).is_empty());
    }

    #[test]
    fn old_line_based_cron_identity_migrates_without_a_false_change() {
        let command = "/usr/bin/job";
        let before = PersistenceEntry::new(EntrySpec {
            source: Source::Cron,
            scope: Scope::System,
            owner: "root",
            locator: "/etc/crontab:7",
            origins: vec!["/etc/crontab".into()],
            location_hint: None,
            trigger: "@reboot".into(),
            command: command.into(),
            enabled: Some(true),
            active: None,
            evidence: Evidence::Static,
            semantic_config: b"@reboot root /usr/bin/job",
        });
        let after = entry(command);
        assert_ne!(before.id, after.id);
        assert!(compare(&snapshot(Some(before), true), &snapshot(Some(after), true)).is_empty());
    }
}
