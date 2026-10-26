//! Presentation only: never changes collected evidence, risk, or audit status.
use super::{
    ScopeSelection,
    compare::{EventKind, PersistEvent},
    model::{PersistenceEntry, Risk, Scope, Snapshot, Source},
};
use crate::presentation::{self, Mode, Options, Style, safe};
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    path::Path,
};

fn entry(event: &PersistEvent) -> Option<&PersistenceEntry> {
    event.after.as_ref().or(event.before.as_ref())
}

fn count_label(count: usize, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}

fn scope_title(scope: ScopeSelection) -> &'static str {
    match scope {
        ScopeSelection::User => "user",
        ScopeSelection::System => "system",
        ScopeSelection::All => "user + system",
    }
}

/// Default inventory highlights this many findings; the rest stay reachable
/// through --verbose and JSON, never dropped from the audit.
const FINDINGS_LIMIT: usize = 40;

fn status_label(entry: &PersistenceEntry) -> &'static str {
    match entry.enabled {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "unknown",
    }
}

fn active_label(entry: &PersistenceEntry) -> &'static str {
    match entry.active {
        Some(true) => "active",
        Some(false) => "inactive",
        None => "unknown",
    }
}

/// Enablement is not runtime activity: systemd rows state both, and an
/// uninspected runtime state is reported as unknown, never as inactive.
fn state_line(entry: &PersistenceEntry) -> String {
    if entry.source == Source::Systemd {
        format!("Status: {} · Active: {}", status_label(entry), active_label(entry))
    } else {
        format!("Status: {}", status_label(entry))
    }
}

fn risk_label(options: &Options, risk: Risk) -> String {
    match risk {
        Risk::High => options.styled("HIGH", Style::Red),
        Risk::Medium => options.styled("MEDIUM", Style::Yellow),
        Risk::Low => "LOW".to_owned(),
    }
}

/// Human heading for a changed field; the identifier stays visible in verbose.
fn human_key(key: &str) -> String {
    match key {
        "command" => "Command".into(),
        "risk" => "Risk".into(),
        "risk_reasons" => "Reasons".into(),
        "enabled" => "Status".into(),
        "active" => "Active".into(),
        "evidence" => "Evidence".into(),
        "origins" => "Origins".into(),
        "location_hint" => "Location".into(),
        "config_sha256" => "Config hash".into(),
        "id" | "entry_id" => "ID".into(),
        other => {
            let mut text = other.replace('_', " ");
            if let Some(first) = text.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            text
        }
    }
}

fn human_value(key: &str, value: &Value) -> String {
    match value {
        Value::String(text) => safe(text),
        Value::Array(items) => {
            let items: Vec<_> = items
                .iter()
                .map(|item| match item {
                    Value::String(text) => safe(text),
                    other => safe(&other.to_string()),
                })
                .collect();
            if items.is_empty() {
                "none".into()
            } else {
                items.join(", ")
            }
        }
        Value::Bool(enabled) if key == "enabled" => {
            if *enabled { "enabled" } else { "disabled" }.into()
        }
        Value::Null => "none".into(),
        other => safe(&other.to_string()),
    }
}

fn compact(out: &mut impl Write, e: &PersistenceEntry) -> io::Result<()> {
    writeln!(
        out,
        "  source={} scope={} owner={} risk={} enabled={} trigger={:?} command={:?}",
        e.source.label(),
        e.scope.label(),
        safe(&e.owner),
        e.risk.label(),
        e.enabled.map_or("unknown".into(), |v| v.to_string()),
        e.trigger,
        e.command
    )
}

fn legacy_details(
    out: &mut impl Write,
    prefix: &str,
    e: Option<&PersistenceEntry>,
) -> io::Result<()> {
    match e {
        None => writeln!(out, "    {prefix}: absent"),
        Some(e) => writeln!(
            out,
            "    {prefix}: id={} evidence={:?} active={:?} sha256={} origins={:?} location={:?} reasons={:?}",
            safe(&e.id),
            e.evidence,
            e.active,
            safe(&e.config_sha256),
            e.origins,
            e.location_hint,
            e.risk_reasons
        ),
    }
}

fn identity(e: &PersistenceEntry) -> String {
    let base = e
        .origins
        .first()
        .filter(|s| !s.is_empty())
        .map(String::as_str)
        .or_else(|| (!e.trigger.is_empty()).then_some(e.trigger.as_str()))
        .map(safe)
        .unwrap_or_else(|| format!("ID fallback: {}", safe(&e.id)));
    match e.location_hint.as_deref().filter(|s| !s.is_empty()) {
        Some(location) => format!("{base} ({})", safe(location)),
        None => base,
    }
}

fn details(
    out: &mut impl Write,
    p: &Options,
    prefix: &str,
    e: Option<&PersistenceEntry>,
) -> io::Result<()> {
    // Serializing the real entry includes every field, including future metadata.
    let text = e
        .map(|e| serde_json::to_string(e).expect("entry serialization"))
        .unwrap_or_else(|| "absent".into());
    p.line_to(out, &format!("    {prefix}: {}", safe(&text)))
}

fn human_entry(
    out: &mut impl Write,
    p: &Options,
    e: &PersistenceEntry,
    verbose: bool,
) -> io::Result<()> {
    p.line_to(out, &format!("  {}  {}", risk_label(p, e.risk), identity(e)))?;
    p.line_to(
        out,
        &format!(
            "    Owner: {} · {} · Trigger: {}",
            safe(&e.owner),
            state_line(e),
            safe(&e.trigger)
        ),
    )?;
    risk_details(out, p, e, verbose)
}

fn risk_details(
    out: &mut impl Write,
    p: &Options,
    e: &PersistenceEntry,
    verbose: bool,
) -> io::Result<()> {
    p.line_to(out, &format!("    Command: {}", safe(&e.command)))?;
    for reason in &e.risk_reasons {
        if e.risk != Risk::Low || verbose {
            p.line_to(out, &format!("    Reason: {}", safe(reason)))?;
        }
    }
    if verbose {
        details(out, p, "details", Some(e))?;
    }
    Ok(())
}

/// A finding keeps only what default review needs: identity, state, reason.
fn finding(out: &mut impl Write, p: &Options, e: &PersistenceEntry) -> io::Result<()> {
    p.line_to(out, &format!("  {}  {}", risk_label(p, e.risk), identity(e)))?;
    p.line_to(out, &format!("    {}", state_line(e)))?;
    for reason in &e.risk_reasons {
        p.line_to(out, &format!("    Reason: {}", safe(reason)))?;
    }
    Ok(())
}

/// A changed entry already prints its identity on the event line, so this block
/// starts with context instead of repeating the path.
fn change_entry(
    out: &mut impl Write,
    p: &Options,
    e: &PersistenceEntry,
    event: &PersistEvent,
    grouped: bool,
    verbose: bool,
) -> io::Result<()> {
    let (indicator, style) = match event.kind {
        EventKind::Added => ("[+] ADDED", Style::Cyan),
        EventKind::Removed => ("[-] REMOVED", Style::Red),
        EventKind::Enabled => ("[+] ENABLED", Style::Cyan),
        EventKind::Disabled => ("[-] DISABLED", Style::Yellow),
        EventKind::RiskChanged => ("[~] RISK_CHANGED", Style::Yellow),
        EventKind::Modified => ("[~] MODIFIED", Style::Yellow),
    };
    p.line_to(
        out,
        &format!(
            "  {} {} · {}",
            p.styled(indicator, style),
            identity(e),
            presentation::date_short(&event.detected_at)
        ),
    )?;
    let source = if grouped {
        String::new()
    } else {
        format!("{} / {} · ", e.source.label(), e.scope.label())
    };
    let (risk_text, command_changed) = match (&event.before, &event.after) {
        (Some(before), Some(after)) => (
            if before.risk == after.risk {
                risk_label(p, after.risk)
            } else {
                format!(
                    "{} → {}",
                    risk_label(p, before.risk),
                    risk_label(p, after.risk)
                )
            },
            before.command != after.command,
        ),
        _ => (risk_label(p, e.risk), false),
    };
    p.line_to(
        out,
        &format!(
            "    {source}Risk: {risk_text} · Status: {} · Owner: {} · Trigger: {}",
            status_label(e),
            safe(&e.owner),
            safe(&e.trigger)
        ),
    )?;
    if !command_changed {
        p.line_to(out, &format!("    Command: {}", safe(&e.command)))?;
    }
    for reason in &e.risk_reasons {
        if e.risk != Risk::Low || verbose {
            p.line_to(out, &format!("    Reason: {}", safe(reason)))?;
        }
    }
    let changed: Vec<_> = event
        .changed_fields
        .iter()
        .map(String::as_str)
        .filter(|field| *field != "entry")
        .collect();
    if !changed.is_empty() {
        p.line_to(
            out,
            &format!("    Changed: {}", safe(&changed.join(", ").replace('_', " "))),
        )?;
    }
    if let (Some(before), Some(after)) = (&event.before, &event.after) {
        let before = serde_json::to_value(before).expect("entry serialization");
        let after = serde_json::to_value(after).expect("entry serialization");
        for (key, value) in before.as_object().expect("entry object") {
            if value == &after[key] || (!verbose && matches!(key.as_str(), "id" | "config_sha256")) {
                continue;
            }
            // Reason lines above already show the current reasons; risk is
            // rendered as a transition in the context line.
            if key == "risk" || (!verbose && key == "risk_reasons") {
                continue;
            }
            p.line_to(
                out,
                &format!(
                    "    {}: {} → {}",
                    human_key(key),
                    human_value(key, value),
                    human_value(key, &after[key])
                ),
            )?;
        }
    }
    if verbose {
        details(out, p, "before", event.before.as_ref())?;
        details(out, p, "after", event.after.as_ref())?;
    }
    Ok(())
}

fn summary(snapshot: &Snapshot, scope: ScopeSelection) -> serde_json::Value {
    let missing: Vec<_> = super::expected_coverage(scope)
        .difference(&snapshot.coverage)
        .cloned()
        .collect();
    let categories: Vec<_> = Source::ALL.into_iter().flat_map(|source| [Scope::User, Scope::System].into_iter().map(move |scope| (source, scope)))
        .map(|(source, scope)| json!({"source":source,"scope":scope,"total":snapshot.entries.values().filter(|e| e.source == source && e.scope == scope).count()})).collect();
    json!({"observed_at":snapshot.observed_at,"total":snapshot.entries.len(),"scope":scope,
        "coverage":snapshot.coverage,"missing_coverage":missing,"categories":categories,
        "warnings":snapshot.warnings.iter().filter(|w| !w.starts_with("COVERAGE ")).count()})
}

pub fn inventory_to(
    out: &mut impl Write,
    root: &Path,
    snapshot: &Snapshot,
    scope: ScopeSelection,
    verbose: bool,
    p: &Options,
) -> io::Result<()> {
    if p.mode == Mode::Legacy {
        writeln!(
            out,
            "PERSISTENCE INVENTORY entries={} coverage={} warnings={}",
            snapshot.entries.len(),
            snapshot.coverage.len(),
            snapshot
                .warnings
                .iter()
                .filter(|w| !w.starts_with("COVERAGE "))
                .count()
        )?;
        for e in snapshot.entries.values() {
            writeln!(out, "ENTRY {}", safe(&e.id))?;
            compact(out, e)?;
            if verbose {
                legacy_details(out, "details", Some(e))?;
            }
        }
        return Ok(());
    }
    let data = summary(snapshot, scope);
    if p.mode == Mode::Json {
        presentation::write_json(out, "persist", "inventory_summary", &data)?;
        let mut entries: Vec<_> = snapshot.entries.values().collect();
        entries.sort_by_key(|e| {
            (
                e.source,
                e.scope,
                std::cmp::Reverse(e.risk),
                identity(e),
                &e.id,
            )
        });
        for e in entries {
            presentation::write_json(out, "persist", "entry", e)?;
        }
        return Ok(());
    }

    p.line_to(out, "SENTINEL / PERSIST")?;
    p.line_to(out, &format!("Root: {}", presentation::path(root)))?;
    p.line_to(out, &format!("Scope: {}", scope_title(scope)))?;
    p.line_to(out, "")?;
    p.line_to(out, "Inventory")?;
    for source in Source::ALL {
        let count = snapshot
            .entries
            .values()
            .filter(|e| e.source == source)
            .count();
        p.line_to(
            out,
            &format!(
                "  {:<9} {}",
                source.label(),
                count_label(count, "entry", "entries")
            ),
        )?;
    }
    p.line_to(out, "")?;
    p.line_to(out, "Risk Summary")?;
    for (risk, style) in [
        (Risk::High, Some(Style::Red)),
        (Risk::Medium, Some(Style::Yellow)),
        (Risk::Low, None),
    ] {
        let count = snapshot.entries.values().filter(|e| e.risk == risk).count();
        let label = format!("{:<9}", risk.label());
        let label = match style {
            Some(style) => p.styled(&label, style),
            None => label,
        };
        p.line_to(out, &format!("  {label}{count:>5}"))?;
    }

    if verbose {
        let mut entries: Vec<_> = snapshot.entries.values().collect();
        entries.sort_by_key(|e| {
            (
                e.source,
                e.scope,
                std::cmp::Reverse(e.risk),
                identity(e),
                &e.id,
            )
        });
        let mut group = None;
        for e in entries {
            if group != Some((e.source, e.scope)) {
                group = Some((e.source, e.scope));
                let count = snapshot
                    .entries
                    .values()
                    .filter(|v| v.source == e.source && v.scope == e.scope)
                    .count();
                p.line_to(out, "")?;
                p.line_to(
                    out,
                    &format!(
                        "{} / {} · {}",
                        e.source.label(),
                        e.scope.label(),
                        count_label(count, "entry", "entries")
                    ),
                )?;
            }
            human_entry(out, p, e, verbose)?;
        }
        p.line_to(out, "")?;
        p.line_to(
            out,
            &format!(
                "Total: {} · observed {}",
                count_label(snapshot.entries.len(), "entry", "entries"),
                presentation::date_short(&snapshot.observed_at)
            ),
        )?;
        return Ok(());
    }

    let mut findings: Vec<_> = snapshot
        .entries
        .values()
        .filter(|e| e.risk != Risk::Low)
        .collect();
    findings.sort_by_key(|e| {
        (
            std::cmp::Reverse(e.risk),
            e.source,
            e.scope,
            identity(e),
            &e.id,
        )
    });
    p.line_to(out, "")?;
    if findings.is_empty() {
        p.line_to(
            out,
            "No HIGH or MEDIUM findings. Absence of findings is not a safety verdict.",
        )?;
    } else {
        p.line_to(out, "Findings requiring attention")?;
        for e in findings.iter().take(FINDINGS_LIMIT) {
            p.line_to(out, "")?;
            finding(out, p, e)?;
        }
        if findings.len() > FINDINGS_LIMIT {
            p.line_to(out, "")?;
            p.line_to(
                out,
                &format!(
                    "  ... {} more findings not shown; the audit keeps all of them",
                    findings.len() - FINDINGS_LIMIT
                ),
            )?;
        }
    }
    p.line_to(out, "")?;
    p.line_to(
        out,
        &format!(
            "{} found · {}",
            count_label(snapshot.entries.len(), "entry", "entries"),
            if findings.is_empty() {
                "no HIGH or MEDIUM findings".to_owned()
            } else {
                count_label(findings.len(), "finding highlighted", "findings highlighted")
            }
        ),
    )?;
    let missing: Vec<_> = super::expected_coverage(scope)
        .difference(&snapshot.coverage)
        .map(|c| format!("{} / {}", c.source.label(), c.scope.label()))
        .collect();
    if !missing.is_empty() {
        p.line_to(
            out,
            &p.styled(
                &format!("Coverage incomplete: {}", missing.join(", ")),
                Style::Yellow,
            ),
        )?;
    }
    p.line_to(out, "Use --verbose to inspect the complete inventory.")?;
    Ok(())
}

pub fn events_to(
    out: &mut impl Write,
    root: &Path,
    scope: ScopeSelection,
    events: &[PersistEvent],
    verbose: bool,
    p: &Options,
    history: bool,
) -> io::Result<()> {
    let mut items: Vec<_> = events.iter().collect();
    if p.mode != Mode::Legacy {
        if history {
            items.sort_by_key(|e| &e.detected_at);
        } else {
            items.sort_by_key(|e| {
                entry(e).map(|v| (v.source, v.scope, std::cmp::Reverse(v.risk), identity(v)))
            });
        }
        if p.mode == Mode::Human {
            p.line_to(
                out,
                if history {
                    "SENTINEL / PERSIST — History"
                } else {
                    "SENTINEL / PERSIST"
                },
            )?;
            p.line_to(out, &format!("Root: {}", presentation::path(root)))?;
            p.line_to(
                out,
                &format!(
                    "{} · Scope: {}",
                    if history {
                        format!("Events: {}", count_label(events.len(), "event", "events"))
                    } else {
                        "Changes since baseline".to_owned()
                    },
                    scope_title(scope)
                ),
            )?;
            p.line_to(out, "")?;
        }
    }
    if items.is_empty() && p.mode != Mode::Json {
        return p.line_to(
            out,
            if history {
                "No persistence history."
            } else {
                "No persistence changes detected."
            },
        );
    }
    let mut group = None;
    for event in items {
        if p.mode == Mode::Json {
            presentation::write_json(out, "persist", "event", event)?;
            continue;
        }
        let Some(e) = entry(event) else {
            continue;
        };
        if p.mode == Mode::Legacy {
            writeln!(
                out,
                "{} {} detected={} changed={}",
                event.kind.label(),
                safe(&e.id),
                safe(&event.detected_at),
                safe(&event.changed_fields.join(","))
            )?;
            compact(out, e)?;
            if verbose {
                legacy_details(out, "before", event.before.as_ref())?;
                legacy_details(out, "after", event.after.as_ref())?;
            }
            continue;
        }
        if !history && group != Some((e.source, e.scope)) {
            if group.is_some() {
                p.line_to(out, "")?;
            }
            group = Some((e.source, e.scope));
            p.line_to(
                out,
                &format!("{} / {}", e.source.label(), e.scope.label()),
            )?;
        }
        change_entry(out, p, e, event, !history, verbose)?;
    }
    let high = events
        .iter()
        .filter(|e| entry(e).is_some_and(|v| v.risk == Risk::High))
        .count();
    let after_high = events
        .iter()
        .filter(|e| e.after.as_ref().is_some_and(|v| v.risk == Risk::High))
        .count();
    match p.mode {
        Mode::Legacy => writeln!(out, "AUDIT SUMMARY changes={} high_risk={high}", events.len()),
        Mode::Human => {
            p.line_to(out, "")?;
            if history {
                p.line_to(
                    out,
                    &format!(
                        "{} · {} at detection",
                        count_label(events.len(), "event", "events"),
                        count_label(high, "high-risk entry", "high-risk entries")
                    ),
                )
            } else {
                let mut line = format!(
                    "{} detected · {} in the current state",
                    count_label(events.len(), "change", "changes"),
                    count_label(after_high, "high-risk entry", "high-risk entries")
                );
                if high != after_high {
                    line.push_str(&format!(" · {} involved", count_label(high, "high-risk entry", "high-risk entries")));
                }
                p.line_to(out, &line)
            }
        }
        Mode::Json => presentation::write_json(out, "persist", if history {"history_summary"} else {"changes_summary"}, &json!({"changes":events.len(),"changed_high_risk":high,"after_high_risk":after_high})),
    }
}

/// Only aggregate, incomplete coverage is actionable in the human default;
/// per-path visits stay available through --verbose.
fn incomplete_coverage(warning: &str) -> Option<String> {
    let fields: Vec<&str> = warning.split_whitespace().collect();
    if fields
        .iter()
        .any(|field| field.starts_with("owner=") || field.starts_with("path="))
    {
        return None;
    }
    if fields
        .iter()
        .find_map(|field| field.strip_prefix("status="))?
        != "incomplete"
    {
        return None;
    }
    let source = fields
        .iter()
        .find_map(|field| field.strip_prefix("source="))?;
    let scope = fields.iter().find_map(|field| field.strip_prefix("scope="))?;
    Some(format!("Coverage incomplete: {source} / {scope}"))
}

pub fn warnings_to(
    out: &mut impl Write,
    err: &mut impl Write,
    warnings: &[String],
    verbose: bool,
    defer_coverage: bool,
    p: &Options,
) -> io::Result<()> {
    if p.mode == Mode::Human && !verbose {
        let mut incomplete = Vec::new();
        for warning in warnings {
            if warning.starts_with("COVERAGE ") {
                if !defer_coverage {
                    if let Some(line) = incomplete_coverage(warning) {
                        incomplete.push(line);
                    }
                }
            } else {
                writeln!(err, "Audit warning: {}", safe(warning))?;
            }
        }
        if !incomplete.is_empty() {
            for line in incomplete {
                p.line_to(out, &p.styled(&line, Style::Yellow))?;
            }
            p.line_to(out, "")?;
        }
        return Ok(());
    }
    for warning in warnings {
        if warning.starts_with("COVERAGE ") {
            // Per-path messages record visits; only aggregate coverage establishes
            // successful inspection of a source/scope pair.
            let visited = if p.mode == Mode::Legacy {
                warning.clone()
            } else {
                warning.replace("status=inspected", "status=visited")
            };
            match p.mode {
                Mode::Json => {
                    presentation::write_json(
                        out,
                        "persist",
                        "coverage",
                        &json!({"message":visited}),
                    )?;
                }
                Mode::Legacy => p.line_to(out, &safe(&visited))?,
                Mode::Human => p.line_to(out, &safe(&visited))?,
            }
        } else if p.mode == Mode::Json {
            presentation::write_json(err, "persist", "warning", &json!({"message":warning}))?;
        } else {
            writeln!(err, "Audit warning: {}", safe(warning))?;
        }
    }
    Ok(())
}

pub fn warnings(
    warnings: &[String],
    verbose: bool,
    defer_coverage: bool,
    p: &Options,
) -> io::Result<()> {
    warnings_to(
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
        warnings,
        verbose,
        defer_coverage,
        p,
    )
}
pub fn inventory(
    root: &Path,
    snapshot: &Snapshot,
    scope: ScopeSelection,
    verbose: bool,
    p: &Options,
) -> io::Result<()> {
    inventory_to(&mut io::stdout().lock(), root, snapshot, scope, verbose, p)
}
pub fn events(
    root: &Path,
    scope: ScopeSelection,
    events: &[PersistEvent],
    verbose: bool,
    p: &Options,
    history: bool,
) -> io::Result<()> {
    events_to(
        &mut io::stdout().lock(),
        root,
        scope,
        events,
        verbose,
        p,
        history,
    )
}
pub fn check_summary(snapshot: &Snapshot, scope: ScopeSelection, p: &Options) -> io::Result<()> {
    if p.mode == Mode::Json {
        p.record("persist", "check_summary", &summary(snapshot, scope))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::model::{EntrySpec, Evidence};
    use super::*;

    fn sample() -> PersistenceEntry {
        PersistenceEntry::new(EntrySpec {
            source: Source::Cron,
            scope: Scope::System,
            owner: "root\x1b[2J",
            locator: "fixture",
            origins: vec!["/etc/cron.d/a\nfile".into()],
            location_hint: Some("line 7".into()),
            trigger: "@reboot".into(),
            command: "/tmp/job\x1b[2J".into(),
            enabled: Some(true),
            active: None,
            evidence: Evidence::Static,
            semantic_config: b"fixture",
        })
    }

    #[test]
    fn renderers_preserve_raw_json_and_escape_human_and_legacy() {
        let e = sample();
        let mut snapshot = Snapshot::new();
        snapshot.entries.insert(e.id.clone(), e.clone());
        for mode in [Mode::Human, Mode::Legacy, Mode::Json] {
            let mut out = Vec::new();
            let mut p = Options::plain(mode);
            p.width = Some(24);
            inventory_to(
                &mut out,
                Path::new("/audit"),
                &snapshot,
                ScopeSelection::All,
                true,
                &p,
            )
            .unwrap();
            let text = String::from_utf8(out).unwrap();
            assert!(!text.contains('\x1b'));
            if mode == Mode::Json {
                let records: Vec<serde_json::Value> = text
                    .lines()
                    .map(|s| serde_json::from_str(s).unwrap())
                    .collect();
                assert_eq!(records[1]["data"], serde_json::to_value(&e).unwrap());
            } else {
                assert!(text.contains("line 7"));
                assert!(text.contains("/etc/cron.d/a"));
                assert!(text.contains("/tmp/job"));
            }
        }
    }

    #[test]
    fn history_sorts_stably_and_legacy_preserves_input_order() {
        let make = |date: &str, id: &str| PersistEvent {
            schema_version: 1,
            kind: EventKind::Removed,
            detected_at: date.into(),
            entry_id: id.into(),
            changed_fields: vec!["entry".into()],
            before: Some(sample()),
            after: None,
        };
        let events = [
            make("2026-03-02T00:00:00Z", "late"),
            make("2026-03-01T00:00:00Z", "first"),
            make("2026-03-01T00:00:00Z", "second"),
        ];
        let mut out = Vec::new();
        events_to(
            &mut out,
            Path::new("/audit"),
            ScopeSelection::All,
            &events,
            false,
            &Options::plain(Mode::Json),
            true,
        )
        .unwrap();
        let records: Vec<serde_json::Value> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(records[0]["data"]["entry_id"], "first");
        assert_eq!(records[1]["data"]["entry_id"], "second");
        assert_eq!(records[2]["data"]["entry_id"], "late");
        let mut out = Vec::new();
        events_to(
            &mut out,
            Path::new("/audit"),
            ScopeSelection::All,
            &events,
            false,
            &Options::plain(Mode::Legacy),
            true,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.find("2026-03-02").unwrap() < text.find("2026-03-01").unwrap());
        assert!(text.ends_with("AUDIT SUMMARY changes=3 high_risk=3\n"));
    }

    #[test]
    fn human_inventory_discloses_findings_instead_of_every_low_entry() {
        let e = sample();
        let mut snapshot = Snapshot::new();
        snapshot.entries.insert(e.id.clone(), e.clone());
        let mut p = Options::plain(Mode::Human);
        p.width = Some(200);
        let mut out = Vec::new();
        inventory_to(
            &mut out,
            Path::new("/audit"),
            &snapshot,
            ScopeSelection::All,
            false,
            &p,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Root: /audit"));
        assert!(text.contains("Scope: user + system"));
        assert!(text.contains("  cron"));
        assert!(text.contains("Risk Summary"));
        assert!(text.contains("Findings requiring attention"));
        assert!(text.contains("1 entry found · 1 finding highlighted"));
        assert!(text.contains("Use --verbose to inspect the complete inventory."));
        assert!(!text.contains("cron / system · 1 entry"));
        assert!(!text.contains("Owner:"));
    }

    fn entry_at(locator: &str) -> PersistenceEntry {
        PersistenceEntry::new(EntrySpec {
            source: Source::Systemd,
            scope: Scope::System,
            owner: "root",
            locator,
            origins: vec![format!("/etc/systemd/system/{locator}")],
            location_hint: None,
            trigger: "systemd service".into(),
            command: "/tmp/payload".into(),
            enabled: Some(false),
            active: None,
            evidence: Evidence::Static,
            semantic_config: locator.as_bytes(),
        })
    }

    #[test]
    fn default_inventory_caps_findings_without_losing_them() {
        let mut snapshot = Snapshot::new();
        for i in 0..FINDINGS_LIMIT + 5 {
            let mut e = entry_at(&format!("high-{i}.service"));
            e.risk = Risk::High;
            e.risk_reasons = vec!["reason-HIGH".into()];
            snapshot.entries.insert(e.id.clone(), e);
        }
        for i in 0..2 {
            let mut e = entry_at(&format!("medium-{i}.service"));
            e.risk = Risk::Medium;
            e.risk_reasons = vec!["reason-MEDIUM".into()];
            snapshot.entries.insert(e.id.clone(), e);
        }
        for i in 0..3 {
            let mut e = entry_at(&format!("low-{i}.service"));
            e.risk = Risk::Low;
            e.risk_reasons.clear();
            snapshot.entries.insert(e.id.clone(), e);
        }
        let mut p = Options::plain(Mode::Human);
        p.width = Some(400);
        let mut out = Vec::new();
        inventory_to(
            &mut out,
            Path::new("/audit"),
            &snapshot,
            ScopeSelection::All,
            false,
            &p,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.matches("Reason: reason-HIGH").count(), FINDINGS_LIMIT);
        assert!(text.contains("... 7 more findings not shown"));
        assert!(text.contains("50 entries found · 47 findings highlighted"));
        assert!(!text.contains("/etc/systemd/system/low-0.service"));
        assert!(text.contains(&format!("  {:<9}{:>5}", "LOW", 3)));

        let mut out = Vec::new();
        inventory_to(
            &mut out,
            Path::new("/audit"),
            &snapshot,
            ScopeSelection::All,
            true,
            &p,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.matches("Reason: reason-HIGH").count(), FINDINGS_LIMIT + 5);
        for i in 0..3 {
            assert!(text.contains(&format!("/etc/systemd/system/low-{i}.service")));
        }
        assert!(text.contains("systemd / system · 50 entries"));
        assert!(text.contains("Total: 50 entries"));
    }

    #[test]
    fn human_change_prints_identity_once_and_readable_values() {
        let mut before = sample();
        before.risk = Risk::Low;
        before.risk_reasons.clear();
        let mut after = before.clone();
        after.risk = Risk::High;
        after.risk_reasons = vec!["transient location".into()];
        after.command = "/usr/bin/job".into();
        let event = PersistEvent {
            schema_version: 1,
            kind: EventKind::RiskChanged,
            detected_at: "2026-03-01T10:00:00.123456789Z".into(),
            entry_id: after.id.clone(),
            changed_fields: vec!["risk".into(), "command".into()],
            before: Some(before),
            after: Some(after.clone()),
        };
        let mut p = Options::plain(Mode::Human);
        p.width = Some(400);
        let mut out = Vec::new();
        events_to(
            &mut out,
            Path::new("/audit"),
            ScopeSelection::All,
            &[event],
            false,
            &p,
            false,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.matches(&identity(&after)).count(), 1);
        assert!(text.contains("Risk: LOW → HIGH"));
        assert!(text.contains("Command: /tmp/job"));
        assert!(text.contains("Reason: transient location"));
        assert!(!text.contains("\"LOW\""));
        assert!(!text.contains("123456789"));
        assert!(text.contains("2026-03-01 10:00:00 UTC"));
        assert!(text.contains("1 change detected · 1 high-risk entry in the current state"));
    }

    #[test]
    fn failures_propagate_and_warning_streams_stay_separate() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let snapshot = Snapshot::new();
        for mode in [Mode::Human, Mode::Legacy, Mode::Json] {
            let p = Options::plain(mode);
            assert!(
                inventory_to(
                    &mut Broken,
                    Path::new("/audit"),
                    &snapshot,
                    ScopeSelection::All,
                    false,
                    &p
                )
                .is_err()
            );
            assert!(
                events_to(
                    &mut Broken,
                    Path::new("/audit"),
                    ScopeSelection::All,
                    &[],
                    false,
                    &p,
                    true
                )
                .is_err()
            );
            let (mut out, mut err) = (Vec::new(), Vec::new());
            warnings_to(
                &mut out,
                &mut err,
                &[
                    "COVERAGE source=systemd scope=user status=complete".into(),
                    "COVERAGE source=systemd scope=user status=incomplete".into(),
                    "bad\x1b[2J\nwarning".into(),
                ],
                false,
                false,
                &p,
            )
            .unwrap();
            let stdout = String::from_utf8(out).unwrap();
            let stderr = String::from_utf8(err).unwrap();
            assert!(!stdout.contains("bad"));
            assert!(!stderr.contains('\x1b'));
            assert_eq!(stderr.lines().count(), 1);
            match mode {
                Mode::Human => {
                    let lines: Vec<_> = stdout.lines().filter(|line| !line.is_empty()).collect();
                    assert_eq!(lines.len(), 1);
                    assert!(lines[0].contains("Coverage incomplete: systemd / user"));
                }
                Mode::Legacy => {
                    assert!(stdout.contains("status=complete"));
                    assert!(stdout.contains("status=incomplete"));
                }
                Mode::Json => {
                    assert!(stdout.contains("\"coverage\""));
                    assert!(stdout.contains("status=incomplete"));
                }
            }
        }
    }
}
