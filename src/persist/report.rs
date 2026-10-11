use super::{
    compare::PersistEvent,
    model::{PersistenceEntry, Risk, Snapshot},
};

fn entry(event: &PersistEvent) -> Option<&PersistenceEntry> {
    event.after.as_ref().or(event.before.as_ref())
}

fn compact_entry(entry: &PersistenceEntry) {
    println!(
        "  source={} scope={} owner={} risk={} enabled={} trigger={:?} command={:?}",
        entry.source.label(),
        entry.scope.label(),
        entry.owner,
        entry.risk.label(),
        entry
            .enabled
            .map_or("unknown".into(), |value| value.to_string()),
        entry.trigger,
        entry.command
    );
}

fn verbose_entry(prefix: &str, entry: Option<&PersistenceEntry>) {
    let Some(entry) = entry else {
        println!("    {prefix}: absent");
        return;
    };
    println!(
        "    {prefix}: id={} evidence={:?} active={:?} sha256={} origins={:?} location={:?} reasons={:?}",
        entry.id,
        entry.evidence,
        entry.active,
        entry.config_sha256,
        entry.origins,
        entry.location_hint,
        entry.risk_reasons
    );
}

pub fn events(events: &[PersistEvent], verbose: bool) {
    if events.is_empty() {
        println!("No persistence changes detected.");
        return;
    }
    for event in events {
        let entry = entry(event).expect("persist events always carry an entry");
        println!(
            "{} {} detected={} changed={}",
            event.kind.label(),
            entry.id,
            event.detected_at,
            event.changed_fields.join(",")
        );
        compact_entry(entry);
        if verbose {
            verbose_entry("before", event.before.as_ref());
            verbose_entry("after", event.after.as_ref());
        }
    }
    let high = events
        .iter()
        .filter(|event| entry(event).is_some_and(|entry| entry.risk == Risk::High))
        .count();
    println!("AUDIT SUMMARY changes={} high_risk={high}", events.len());
}

pub fn inventory(snapshot: &Snapshot, verbose: bool) {
    println!(
        "PERSISTENCE INVENTORY entries={} coverage={} warnings={}",
        snapshot.entries.len(),
        snapshot.coverage.len(),
        snapshot.warnings.len()
    );
    for entry in snapshot.entries.values() {
        println!("ENTRY {}", entry.id);
        compact_entry(entry);
        if verbose {
            verbose_entry("details", Some(entry));
        }
    }
}

pub fn warnings(warnings: &[String]) {
    for warning in warnings {
        eprintln!("Audit warning: {warning}");
    }
}

pub fn history(items: &[PersistEvent], verbose: bool) {
    if items.is_empty() {
        println!("No persistence history.");
        return;
    }
    events(items, verbose);
}
