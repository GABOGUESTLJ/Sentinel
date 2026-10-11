use crate::{
    event::{AuditEvent, EntrySnapshot, EventKind},
    read_files::Kind,
    scan_files::Entries,
};
use std::{collections::BTreeMap, path::Path};

const CONSOLE_EVENT_LIMIT: usize = 20;

fn short_hash(hash: Option<&str>) -> &str {
    hash.map_or("absent", |value| value.get(..12).unwrap_or(value))
}

fn path_text(event: &AuditEvent) -> String {
    match event.kind {
        EventKind::Renamed => format!(
            "{} -> {} content_changed={} replaced={}",
            event
                .previous_path
                .as_ref()
                .map_or_else(|| "<unknown>".into(), |path| path.quoted()),
            event
                .current_path
                .as_ref()
                .map_or_else(|| "<unknown>".into(), |path| path.quoted()),
            event.content_changed.unwrap_or(false),
            event.replaced
        ),
        EventKind::Deleted => event
            .previous_path
            .as_ref()
            .map_or_else(|| "<unknown>".into(), |path| path.quoted()),
        EventKind::Created | EventKind::Modified => event
            .current_path
            .as_ref()
            .map_or_else(|| "<unknown>".into(), |path| path.quoted()),
    }
}

fn changed_values(before: Option<&EntrySnapshot>, after: Option<&EntrySnapshot>) -> Vec<String> {
    let mut values = Vec::new();
    if before.and_then(|entry| entry.size) != after.and_then(|entry| entry.size) {
        values.push(format!(
            "size={:?}->{:?}",
            before.and_then(|entry| entry.size),
            after.and_then(|entry| entry.size)
        ));
    }
    if before.and_then(|entry| entry.sha256.as_deref())
        != after.and_then(|entry| entry.sha256.as_deref())
    {
        values.push(format!(
            "sha256={}…->{}…",
            short_hash(before.and_then(|entry| entry.sha256.as_deref())),
            short_hash(after.and_then(|entry| entry.sha256.as_deref()))
        ));
    }
    values
}

fn full_entry(prefix: &str, entry: Option<&EntrySnapshot>) {
    let Some(entry) = entry else {
        println!("    {prefix}: absent");
        return;
    };
    println!(
        "    {prefix}: type={:?} size={:?} mode={:04o} uid={} gid={} mtime={} sha256={} target={:?} fs-device={:?} inode={:?}",
        entry.kind,
        entry.size,
        entry.mode,
        entry.uid,
        entry.gid,
        entry.modified.as_deref().unwrap_or("unavailable"),
        entry.sha256.as_deref().unwrap_or("no-hash"),
        entry.target_display,
        entry.filesystem_device,
        entry.inode
    );
}

pub fn event(event: &AuditEvent, verbose: bool) {
    let mtime = event
        .after
        .as_ref()
        .and_then(|entry| entry.modified.as_deref())
        .unwrap_or("unavailable");
    println!(
        "{} {} detected={} mtime={} baseline={}",
        event.kind.label(),
        path_text(event),
        event.detected_at,
        mtime,
        event.baseline_status
    );
    let mut details = vec![format!("changed={}", event.changed_fields.join(","))];
    details.extend(changed_values(event.before.as_ref(), event.after.as_ref()));
    println!("  {}", details.join("  "));
    if verbose {
        full_entry("before", event.before.as_ref());
        full_entry("after", event.after.as_ref());
        full_entry("baseline", event.baseline.as_ref());
        if event.replaced {
            full_entry("replaced-before", event.replaced_before.as_ref());
        }
    }
}

pub fn events(events: &[AuditEvent], verbose: bool, limit: Option<usize>) {
    let shown = limit.map_or(events.len(), |limit| events.len().min(limit));
    for event_to_print in &events[..shown] {
        event(event_to_print, verbose);
    }
    if shown < events.len() {
        println!(
            "SCAN changes={} showing={}; use --history to inspect the complete record",
            events.len(),
            shown
        );
    }
}

pub fn initial(
    root: &Path,
    baseline_path: &Path,
    history_path: &Path,
    current: &Entries,
    hardscan: bool,
) {
    let mut kinds = BTreeMap::<&'static str, usize>::new();
    for entry in current.values() {
        let name = match entry.kind {
            Kind::File => "files",
            Kind::Directory => "directories",
            Kind::Symlink => "symlinks",
            _ => "special",
        };
        *kinds.entry(name).or_default() += 1;
    }
    println!(
        "Monitoring {} ({} entries; {}). Baseline: {}. History: {}. Press Ctrl+C to stop. Enter --silent or -d/--desilent to control output.",
        root.display(),
        current.len(),
        if hardscan {
            "PollWatcher"
        } else {
            "native watcher"
        },
        baseline_path.display(),
        history_path.display()
    );
    println!(
        "INITIAL SCAN files={} directories={} symlinks={} special={}",
        kinds.get("files").copied().unwrap_or(0),
        kinds.get("directories").copied().unwrap_or(0),
        kinds.get("symlinks").copied().unwrap_or(0),
        kinds.get("special").copied().unwrap_or(0)
    );
}

pub fn live_events(events_to_print: &[AuditEvent], verbose: bool) {
    events(events_to_print, verbose, Some(CONSOLE_EVENT_LIMIT));
}

pub fn history(events_to_print: &[AuditEvent], verbose: bool, filter: Option<&str>) {
    println!(
        "HISTORY events={} filter={}",
        events_to_print.len(),
        filter.unwrap_or("all files")
    );
    events(events_to_print, verbose, None);
}
