//! FIM action orchestration; CLI parsing stays in main and scheduling in runtime.

use crate::{auth, baseline, event, history, presentation, report, runtime, scan_files, FimArgs};
use std::time::Duration;
use std::{io, os::unix::ffi::OsStrExt};

pub fn run(args: FimArgs) -> Result<(), Box<dyn std::error::Error>> {
    let output = args.output.options();
    let root = args.scan.canonicalize()?;
    if !std::fs::symlink_metadata(&root)?.is_dir() {
        return Err(format!("Not a directory: {}", presentation::path(&root)).into());
    }
    let export = args.export.request()?;
    if let Some(filter) = args.history {
        let filter_label = (!filter.as_os_str().is_empty()).then(|| {
            if output.mode == presentation::Mode::Legacy {
                report::legacy_path(&filter)
            } else {
                presentation::path(&filter)
            }
        });
        let filter_hex = if filter.as_os_str().is_empty() {
            None
        } else {
            Some(event::normalize_filter(&root, filter).map_err(|error| error.to_string())?)
        };
        let result = if export.is_some() {
            history::read_only(&root, filter_hex.as_deref())?
        } else {
            history::read(&root, filter_hex.as_deref(), args.history_policy.policy())?
        };
        for warning in &result.warnings {
            output.diagnostic("fim", "warning", &format!("History warning: {warning}"))?;
        }
        if let Some(export) = export {
            if !result.warnings.is_empty() {
                return Err("History contains invalid records; export was not written".into());
            }
            let count = export.write("fim", &result.events, &history::directory(&root)?)?;
            let message = format!(
                "History exported: {count} event(s) to {}",
                presentation::path(&export.destination)
            );
            let legacy = format!(
                "History exported: {count} event(s) to {}",
                report::legacy_path(&export.destination)
            );
            output.message("fim", "export", &message, &legacy, &serde_json::json!({"events":count,"destination_hex":hex::encode(export.destination.as_os_str().as_bytes())}))?;
        } else {
            report::history(
                &mut io::stdout().lock(),
                &output,
                &root,
                &result.events,
                args.verbose,
                filter_label.as_deref(),
            )?;
        }
        return Ok(());
    }
    let key_path = auth::key_path(args.hmac_key.as_deref())?;
    if args.migrate_baseline {
        let destination = baseline::migrate(&root, &key_path)?;
        if !args.silent {
            output.message("fim", "baseline", &format!("Baseline migrated to {}; original preserved.", presentation::path(&destination)), &format!("Baseline migrated to {}; original preserved.", report::legacy_path(&destination)), &serde_json::json!({"action":"migrated","path_hex":hex::encode(destination.as_os_str().as_bytes())}))?;
        }
        return Ok(());
    }
    let baseline_path = baseline::location(&root)?;
    if args.init_baseline || args.update_baseline {
        if args.update_baseline {
            baseline::load_for_update(&baseline_path, &root, &key_path)?;
        } else if std::fs::symlink_metadata(&baseline_path).is_ok() {
            return Err(
                "The baseline already exists; use --update-baseline to accept changes".into(),
            );
        }
        let key_path = auth::ensure_key(args.hmac_key.as_deref())?;
        let entries = scan_files::scan(&root)?;
        baseline::save(
            &baseline_path,
            &root,
            &entries,
            &key_path,
            args.update_baseline,
        )?;
        if !args.silent {
            let action = if args.update_baseline {
                "updated"
            } else {
                "created"
            };
            output.message("fim", "baseline", &format!("Baseline {action}: {} ({} entries).", presentation::path(&baseline_path), entries.len()), &format!("Baseline saved at {} ({} entries).", report::legacy_path(&baseline_path), entries.len()), &serde_json::json!({"action":action,"entries":entries.len(),"path_hex":hex::encode(baseline_path.as_os_str().as_bytes())}))?;
        }
        return Ok(());
    }
    let trusted = baseline::load(&baseline_path, &root, &key_path)?;
    runtime::run(
        &root,
        &baseline_path,
        trusted.entries,
        runtime::Options {
            interval: Duration::from_secs(args.interval.get()),
            hardscan: args.hardscan,
            verbose: args.verbose,
            silent: args.silent,
            history_policy: args.history_policy.policy(),
            output,
        },
    )
}
