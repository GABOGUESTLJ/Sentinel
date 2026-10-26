use crate::{
    event::{AuditEvent, EntrySnapshot, EventKind},
    presentation::{self, Mode, Options, Style},
    read_files::Kind,
    scan_files::Entries,
};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};

const CONSOLE_EVENT_LIMIT: usize = 20;

fn short_hash(hash: Option<&str>) -> &str {
    hash.map_or("absent", |value| value.get(..12).unwrap_or(value))
}

fn path_text(event: &AuditEvent) -> String {
    let paths = human_paths(event, true);
    if event.kind == EventKind::Renamed {
        format!(
            "{paths} content_changed={} replaced={}",
            event.content_changed.unwrap_or(false),
            event.replaced
        )
    } else {
        paths
    }
}

/// Human wording for changed fields; creation, deletion and rename markers are
/// already conveyed by the event indicator and are not repeated as changes.
fn human_changes(event: &AuditEvent) -> Vec<&str> {
    event
        .changed_fields
        .iter()
        .filter_map(|field| match field.as_str() {
            "created" | "deleted" | "path" => None,
            "mode" => Some("permissions"),
            "uid" => Some("owner"),
            "gid" => Some("group"),
            "target" => Some("symlink target"),
            "mtime" => Some("modification time"),
            "type" => Some("file type"),
            "inode" | "filesystem-device" | "device" => Some("identity replacement"),
            field => Some(field),
        })
        .collect()
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

fn full_entry(
    out: &mut impl Write,
    options: &Options,
    prefix: &str,
    entry: Option<&EntrySnapshot>,
) -> io::Result<()> {
    let Some(entry) = entry else {
        return options.line_to(out, &format!("    {prefix}: absent"));
    };
    if options.mode == Mode::Human {
        // Verbose keeps every field but prints absent values plainly.
        let number = |value: Option<u64>| {
            value.map_or_else(|| "absent".to_owned(), |number| number.to_string())
        };
        let target = entry.target_display.as_deref().map_or_else(
            || "absent".to_owned(),
            |target| format!("{:?}", presentation::safe(target)),
        );
        options.line_to(out, &presentation::safe(&format!(
            "    {prefix}: type={:?} size={} mode={:04o} uid={} gid={} mtime={} sha256={} target={} fs-device={} inode={} device={}",
            entry.kind,
            number(entry.size),
            entry.mode,
            entry.uid,
            entry.gid,
            presentation::date(entry.modified.as_deref().unwrap_or("unavailable")),
            entry.sha256.as_deref().unwrap_or("no-hash"),
            target,
            number(entry.filesystem_device),
            number(entry.inode),
            number(entry.device)
        )))?;
        return options.line_to(
            out,
            &format!(
                "      target_hex={}",
                presentation::safe(entry.target_hex.as_deref().unwrap_or("absent"))
            ),
        );
    }
    options.line_to(out, &presentation::safe(&format!(
        "    {prefix}: type={:?} size={:?} mode={:04o} uid={} gid={} mtime={} sha256={} target={:?} fs-device={:?} inode={:?}",
        entry.kind,
        entry.size,
        entry.mode,
        entry.uid,
        entry.gid,
        presentation::safe(entry.modified.as_deref().unwrap_or("unavailable")),
        entry.sha256.as_deref().unwrap_or("no-hash"),
        entry.target_display,
        entry.filesystem_device,
        entry.inode
    )))?;
    if entry.target_hex.as_deref().is_some_and(|value| {
        hex::decode(value).is_ok_and(|bytes| std::str::from_utf8(&bytes).is_err())
    }) {
        options.line_to(
            out,
            &format!(
                "      target-bytes={}",
                presentation::safe(entry.target_hex.as_deref().unwrap_or("absent"))
            ),
        )?;
    }
    Ok(())
}

fn stored_path(path: Option<&crate::event::StoredPath>, legacy: bool) -> String {
    path.map_or_else(
        || "<unknown>".into(),
        |path| {
            if legacy {
                let quoted = presentation::safe(&path.quoted());
                if hex::decode(&path.hex).is_ok_and(|bytes| std::str::from_utf8(&bytes).is_err()) {
                    format!("{quoted} [path-bytes:{}]", presentation::safe(&path.hex))
                } else {
                    quoted
                }
            } else {
                presentation::path_hex(&path.hex)
            }
        },
    )
}

fn human_paths(event: &AuditEvent, legacy: bool) -> String {
    match event.kind {
        EventKind::Renamed => format!(
            "{} {} {}",
            stored_path(event.previous_path.as_ref(), legacy),
            if legacy { "->" } else { "→" },
            stored_path(event.current_path.as_ref(), legacy)
        ),
        EventKind::Deleted => stored_path(event.previous_path.as_ref(), legacy),
        _ => stored_path(event.current_path.as_ref(), legacy),
    }
}

pub fn event(
    out: &mut impl Write,
    options: &Options,
    event: &AuditEvent,
    verbose: bool,
    timestamps: bool,
) -> io::Result<()> {
    if options.mode == Mode::Json {
        return presentation::write_json(out, "fim", "event", event);
    }
    if options.mode == Mode::Human {
        let (label, style) = match event.kind {
            EventKind::Created => ("[+] CREATED", Style::Green),
            EventKind::Modified => ("[~] MODIFIED", Style::Yellow),
            EventKind::Deleted => ("[-] DELETED", Style::Red),
            EventKind::Renamed => ("[↪] RENAMED", Style::Purple),
        };
        options.line_to(
            out,
            &format!(
                "{}  {}",
                options.styled(label, style),
                human_paths(event, false)
            ),
        )?;
        let changes = human_changes(event);
        if !changes.is_empty() {
            options.line_to(
                out,
                &format!(
                    "  Changed: {} · baseline: {}",
                    presentation::safe(&changes.join(", ")),
                    presentation::safe(&event.baseline_status.to_lowercase())
                ),
            )?;
        }
        if let Some(changed) = event.content_changed {
            options.line_to(
                out,
                &format!(
                    "  Rename content changed: {changed}; destination replaced: {}",
                    event.replaced
                ),
            )?;
        }
        if timestamps {
            options.line_to(
                out,
                &format!(
                    "  Detected: {}",
                    presentation::date_short(&event.detected_at)
                ),
            )?;
        }
    } else {
        let mtime = event
            .after
            .as_ref()
            .and_then(|entry| entry.modified.as_deref())
            .unwrap_or("unavailable");
        // Debug-quoted paths are already escaped; only escape remaining controls.
        let paths = path_text(event);
        options.line_to(
            out,
            &presentation::safe(&format!(
                "{} {} detected={} mtime={} baseline={}",
                event.kind.label(),
                paths,
                event.detected_at,
                mtime,
                event.baseline_status
            )),
        )?;
        let mut details = vec![format!("changed={}", event.changed_fields.join(","))];
        details.extend(changed_values(event.before.as_ref(), event.after.as_ref()));
        options.line_to(
            out,
            &presentation::safe(&format!("  {}", details.join("  "))),
        )?;
    }
    if verbose {
        if options.mode == Mode::Human {
            options.line_to(
                out,
                &format!(
                    "  run_id={} sequence={} origin={:?} root_hex={}",
                    presentation::safe(&event.run_id),
                    event.sequence,
                    event.origin,
                    presentation::safe(&event.root_hex)
                ),
            )?;
            for (label, path) in [
                ("previous", event.previous_path.as_ref()),
                ("current", event.current_path.as_ref()),
            ] {
                if let Some(path) = path {
                    let full_hex = format!("{}2f{}", event.root_hex, path.hex);
                    options.line_to(
                        out,
                        &format!(
                            "    {label}_hex={} full_path={}",
                            presentation::safe(&path.hex),
                            presentation::path_hex(&full_hex)
                        ),
                    )?;
                }
            }
        }
        full_entry(out, options, "before", event.before.as_ref())?;
        full_entry(out, options, "after", event.after.as_ref())?;
        full_entry(out, options, "baseline", event.baseline.as_ref())?;
        if event.replaced {
            full_entry(
                out,
                options,
                "replaced-before",
                event.replaced_before.as_ref(),
            )?;
        }
    }
    Ok(())
}

pub fn events(
    out: &mut impl Write,
    options: &Options,
    events: &[AuditEvent],
    verbose: bool,
    limit: Option<usize>,
    timestamps: bool,
) -> io::Result<()> {
    let limit = if options.mode == Mode::Json {
        None
    } else {
        limit
    };
    let shown = limit.map_or(events.len(), |limit| events.len().min(limit));
    for event_to_print in &events[..shown] {
        event(out, options, event_to_print, verbose, timestamps)?;
    }
    if options.mode == Mode::Json {
        presentation::write_json(
            out,
            "fim",
            "summary",
            &serde_json::json!({"detected":events.len(),"shown":shown}),
        )?;
    } else if options.mode == Mode::Human {
        options.line_to(out, &if shown < events.len() {
            format!("{} changes detected; {shown} shown; use --history to inspect the complete record", events.len())
        } else { format!("{} changes detected", events.len()) })?;
    } else if shown < events.len() {
        options.line_to(
            out,
            &format!(
                "SCAN changes={} showing={}; use --history to inspect the complete record",
                events.len(),
                shown
            ),
        )?;
    }
    Ok(())
}

fn count(count: usize, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}

pub fn initial(
    out: &mut impl Write,
    options: &Options,
    root: &Path,
    baseline_path: &Path,
    history_path: &Path,
    current: &Entries,
    hardscan: bool,
    verbose: bool,
) -> io::Result<()> {
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
    if options.mode == Mode::Json {
        return presentation::write_json(
            out,
            "fim",
            "initial",
            &serde_json::json!({
                "root": root.to_string_lossy(), "root_hex": hex::encode(root.as_os_str().as_bytes()),
                "baseline_hex":hex::encode(baseline_path.as_os_str().as_bytes()),
                "history_hex":hex::encode(history_path.as_os_str().as_bytes()),
                "entries":current.len(), "counts":kinds, "hardscan":hardscan
            }),
        );
    }
    if options.mode == Mode::Human {
        options.line_to(out, "SENTINEL / FIM")?;
        options.line_to(out, &format!("Root: {}", presentation::path(root)))?;
        options.line_to(
            out,
            &format!(
                "Watcher: {} · {} entries",
                if hardscan { "polling" } else { "native" },
                current.len()
            ),
        )?;
        options.line_to(
            out,
            &format!(
                "Contents: {} · {} · {} · {}",
                count(kinds.get("files").copied().unwrap_or(0), "file", "files"),
                count(
                    kinds.get("directories").copied().unwrap_or(0),
                    "directory",
                    "directories"
                ),
                count(
                    kinds.get("symlinks").copied().unwrap_or(0),
                    "symlink",
                    "symlinks"
                ),
                count(
                    kinds.get("special").copied().unwrap_or(0),
                    "special file",
                    "special files"
                )
            ),
        )?;
        if verbose {
            options.line_to(
                out,
                &format!("Baseline: {}", presentation::path(baseline_path)),
            )?;
            options.line_to(
                out,
                &format!("History: {}", presentation::path(history_path)),
            )?;
        }
        options.line_to(
            out,
            "Press Ctrl+C to stop. Enter --silent or -d/--desilent to control output.",
        )?;
        return options.line_to(out, "");
    }
    options.line_to(out, &format!(
        "Monitoring {} ({} entries; {}). Baseline: {}. History: {}. Press Ctrl+C to stop. Enter --silent or -d/--desilent to control output.",
        legacy_path(root),
        current.len(),
        if hardscan {
            "PollWatcher"
        } else {
            "native watcher"
        },
        legacy_path(baseline_path),
        legacy_path(history_path)
    ))?;
    options.line_to(
        out,
        &format!(
            "INITIAL SCAN files={} directories={} symlinks={} special={}",
            kinds.get("files").copied().unwrap_or(0),
            kinds.get("directories").copied().unwrap_or(0),
            kinds.get("symlinks").copied().unwrap_or(0),
            kinds.get("special").copied().unwrap_or(0)
        ),
    )
}

/// Keep ordinary legacy paths unchanged, but never collapse invalid bytes.
pub fn legacy_path(path: &Path) -> String {
    path.to_str()
        .map_or_else(|| presentation::path(path), presentation::safe)
}

pub fn live_events(
    out: &mut impl Write,
    options: &Options,
    events_to_print: &[AuditEvent],
    verbose: bool,
) -> io::Result<()> {
    if events_to_print.is_empty() {
        return Ok(());
    }
    events(
        out,
        options,
        events_to_print,
        verbose,
        Some(CONSOLE_EVENT_LIMIT),
        false,
    )
}

pub fn history(
    out: &mut impl Write,
    options: &Options,
    root: &Path,
    events_to_print: &[AuditEvent],
    verbose: bool,
    filter: Option<&str>,
) -> io::Result<()> {
    if options.mode == Mode::Json {
        presentation::write_json(
            out,
            "fim",
            "history",
            &serde_json::json!({"root_hex":hex::encode(root.as_os_str().as_bytes()),"events":events_to_print.len(), "filter":filter}),
        )?;
    } else if options.mode == Mode::Human {
        options.line_to(out, "SENTINEL / FIM — History")?;
        options.line_to(out, &format!("Root: {}", presentation::path(root)))?;
        options.line_to(
            out,
            &format!(
                "Events: {}; filter: {}",
                events_to_print.len(),
                presentation::safe(filter.unwrap_or("all files"))
            ),
        )?;
    } else {
        options.line_to(
            out,
            &format!(
                "HISTORY events={} filter={}",
                events_to_print.len(),
                presentation::safe(filter.unwrap_or("all files"))
            ),
        )?;
    }
    let mut ordered: Vec<_> = events_to_print.to_vec();
    if options.mode != Mode::Legacy {
        ordered.sort_by(|a, b| {
            (&a.detected_at, &a.run_id, a.sequence).cmp(&(&b.detected_at, &b.run_id, b.sequence))
        });
    }
    events(out, options, &ordered, verbose, None, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{self, BuildContext, Origin};

    fn fixture() -> Vec<AuditEvent> {
        let before = Entries::new();
        let mut current = Entries::new();
        // Reuse the filesystem reader and event builder, not a parallel event model.
        current.insert(
            "first".into(),
            crate::read_files::read_entry(Path::new("Cargo.toml")).unwrap(),
        );
        current.insert(
            "second".into(),
            crate::read_files::read_entry(Path::new("Cargo.toml")).unwrap(),
        );
        let mut sequence = 0;
        event::build(
            &before,
            &current,
            &before,
            &mut BuildContext {
                root_hex: "2f726f6f74",
                run_id: "run",
                next_sequence: &mut sequence,
                origin: Origin::Startup,
            },
        )
    }

    #[test]
    fn history_is_chronological_without_changing_legacy_order() {
        let mut events = fixture();
        events[0].detected_at = "2026-10-26T12:00:00Z".into();
        events[1].detected_at = "2026-10-25T12:00:00Z".into();
        for mode in [Mode::Human, Mode::Legacy, Mode::Json] {
            let mut out = Vec::new();
            history(
                &mut out,
                &Options::plain(mode),
                Path::new("/root"),
                &events,
                false,
                None,
            )
            .unwrap();
            let text = String::from_utf8(out).unwrap();
            assert_eq!(
                text.find("first").unwrap() < text.find("second").unwrap(),
                mode == Mode::Legacy
            );
        }
    }

    #[test]
    fn render_errors_are_propagated() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("closed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        for mode in [Mode::Human, Mode::Json, Mode::Legacy] {
            assert!(
                events(
                    &mut Broken,
                    &Options::plain(mode),
                    &fixture(),
                    true,
                    None,
                    false,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn owner_group_changes_are_visible_and_paths_are_not_colored() {
        let mut event = fixture().remove(0);
        event.kind = EventKind::Modified;
        event.changed_fields = vec!["uid".into(), "gid".into(), "mode".into()];
        let mut options = Options::plain(Mode::Human);
        options.color = true;
        options.width = Some(24);
        let mut out = Vec::new();
        super::event(&mut out, &options, &event, false, false).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("\x1b[33m[~] MODIFIED\x1b[0m"));
        assert!(text.contains("first"));
        assert!(text.contains("Changed:"));
        for label in ["owner", "group", "permissions"] {
            assert!(text.contains(label), "missing {label} in {text:?}");
        }
        assert!(!text.contains("sha256="));
        assert!(!text.contains("uid="));
        assert!(!text.contains("gid="));
    }

    #[test]
    fn legacy_quotes_once_and_retains_invalid_path_bytes() {
        let mut event = fixture().remove(0);
        event.current_path = Some(crate::event::StoredPath {
            display: "a\n\x1b[2J".into(),
            hex: hex::encode(b"a\n\x1b[2J"),
        });
        let options = Options::plain(Mode::Legacy);
        let mut out = Vec::new();
        super::event(&mut out, &options, &event, false, false).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("CREATED \"a\\n\\u{1b}[2J\" detected="));
        assert!(!text.contains("\\\\n"));
        assert!(!text.contains('\x1b'));
        event.current_path = Some(crate::event::StoredPath {
            display: "a�".into(),
            hex: "61ff".into(),
        });
        let mut out = Vec::new();
        super::event(&mut out, &options, &event, false, false).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("[path-bytes:61ff]")
        );
    }
}
