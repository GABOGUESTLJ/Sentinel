mod collect;
mod compare;
mod cron;
mod model;
mod report;
mod ssh;
mod store;
mod systemd;
mod xdg;

use clap::ValueEnum;
use model::{Coverage, Risk, Scope, Source};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, os::unix::ffi::OsStrExt, path::PathBuf};

type Error = Box<dyn std::error::Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScopeSelection {
    User,
    System,
    All,
}

impl ScopeSelection {
    pub fn includes_user(self) -> bool {
        matches!(self, Self::User | Self::All)
    }

    pub fn includes_system(self) -> bool {
        matches!(self, Self::System | Self::All)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::System => "system",
            Self::All => "all",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Action {
    InitBaseline,
    UpdateBaseline,
    Check,
    List,
    History,
}

#[derive(Debug)]
pub struct Options {
    pub root: PathBuf,
    pub scope: ScopeSelection,
    pub offline: bool,
    pub verbose: bool,
    pub output: crate::presentation::Options,
    pub hmac_key: Option<PathBuf>,
    pub action: Action,
    pub history_policy: crate::retention::Policy,
    pub export: Option<crate::history_export::Request>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Success,
    Changes,
    HighRisk,
    Incomplete,
}

fn expected_coverage(scope: ScopeSelection) -> BTreeSet<Coverage> {
    let mut expected = BTreeSet::new();
    for source in Source::ALL {
        if scope.includes_user() {
            expected.insert(Coverage {
                source,
                scope: Scope::User,
            });
        }
        if scope.includes_system() {
            expected.insert(Coverage {
                source,
                scope: Scope::System,
            });
        }
    }
    expected
}

pub fn run(options: Options) -> Result<RunStatus, Error> {
    let root = options.root.canonicalize()?;
    if !std::fs::symlink_metadata(&root)?.is_dir() {
        return Err(format!("Not a directory: {}", root.display()).into());
    }
    let paths = if options.export.is_some() {
        store::Paths::read_only(&root, options.scope)?
    } else {
        store::Paths::discover(&root, options.scope)?
    };

    if matches!(options.action, Action::History) {
        let key_path =
            crate::auth::key_path_for(options.hmac_key.as_deref(), crate::auth::PERSIST_KEY_FILE)?;
        if let Some(export) = options.export {
            let events = store::read_history_only(&paths, &key_path)?;
            let count = export.write(
                "persist",
                &events,
                paths
                    .history
                    .parent()
                    .ok_or("Persist history has no directory")?,
            )?;
            let message = format!(
                "History exported: {} to {}",
                if count == 1 {
                    "1 event".to_owned()
                } else {
                    format!("{count} events")
                },
                crate::presentation::path(&export.destination)
            );
            let legacy = format!(
                "History exported: {count} event(s) to {}",
                export
                    .destination
                    .to_str()
                    .map(crate::presentation::safe)
                    .unwrap_or_else(|| crate::presentation::path(&export.destination))
            );
            options.output.message(
                "persist",
                "export",
                &message,
                &legacy,
                &serde_json::json!({"count":count,"destination":export.destination.to_str(),
                    "destination_bytes":hex::encode(export.destination.as_os_str().as_bytes())}),
            )?;
            return Ok(RunStatus::Success);
        }
        let (events, warnings) = store::read_history(&paths, options.history_policy, &key_path)?;
        report::warnings(&warnings, options.verbose, false, &options.output)?;
        report::events(
            &root,
            options.scope,
            &events,
            options.verbose,
            &options.output,
            true,
        )?;
        return Ok(RunStatus::Success);
    }

    if matches!(options.action, Action::UpdateBaseline) {
        let key_path =
            crate::auth::key_path_for(options.hmac_key.as_deref(), crate::auth::PERSIST_KEY_FILE)?;
        store::load_baseline_for_update(&paths.baseline, &root, options.scope, &key_path)?;
    }

    let snapshot = collect::collect(&collect::Options {
        root: root.clone(),
        scope: options.scope,
        offline: options.offline || root != std::path::Path::new("/"),
    });
    // Human list prints incomplete coverage after the findings section.
    report::warnings(
        &snapshot.warnings,
        options.verbose,
        matches!(options.action, Action::List),
        &options.output,
    )?;

    match options.action {
        Action::List => {
            report::inventory(
                &root,
                &snapshot,
                options.scope,
                options.verbose,
                &options.output,
            )?;
        }
        Action::InitBaseline | Action::UpdateBaseline => {
            let missing: Vec<_> = expected_coverage(options.scope)
                .difference(&snapshot.coverage)
                .map(|coverage| format!("{}:{}", coverage.source.label(), coverage.scope.label()))
                .collect();
            if !missing.is_empty() {
                return Err(format!(
                    "Incomplete persistence audit; baseline was not changed. Missing coverage: {}",
                    missing.join(", ")
                )
                .into());
            }
            let replace = matches!(options.action, Action::UpdateBaseline);
            let key_path = crate::auth::ensure_key_for(
                options.hmac_key.as_deref(),
                crate::auth::PERSIST_KEY_FILE,
            )?;
            store::save_baseline(
                &paths.baseline,
                &root,
                options.scope,
                &snapshot,
                &key_path,
                replace,
            )?;
            let location = crate::presentation::path(&paths.baseline);
            let legacy_location = paths
                .baseline
                .to_str()
                .map(crate::presentation::safe)
                .unwrap_or_else(|| location.clone());
            let verb = if replace { "updated" } else { "created" };
            let count = if snapshot.entries.len() == 1 {
                "1 mechanism".to_owned()
            } else {
                format!("{} mechanisms", snapshot.entries.len())
            };
            let scope = match options.scope {
                ScopeSelection::User => "user",
                ScopeSelection::System => "system",
                ScopeSelection::All => "user + system",
            };
            let confirmation = if options.verbose {
                format!("SENTINEL / PERSIST\nBaseline {verb}: {location} ({count} · scope: {scope}).")
            } else {
                format!("SENTINEL / PERSIST\nBaseline {verb} · {count} · scope: {scope}.")
            };
            options.output.message("persist", "baseline",
                &confirmation,
                &format!("Persist baseline saved at {legacy_location} ({} mechanisms, scope={}).", snapshot.entries.len(), options.scope.label()),
                &serde_json::json!({"action":if replace {"update"} else {"init"},"path":paths.baseline.to_str(),
                    "path_bytes":hex::encode(paths.baseline.as_os_str().as_bytes()),"total":snapshot.entries.len(),"scope":options.scope,"observed_at":snapshot.observed_at}))?;
        }
        Action::Check => {
            let key_path = crate::auth::key_path_for(
                options.hmac_key.as_deref(),
                crate::auth::PERSIST_KEY_FILE,
            )?;
            let baseline = store::load_baseline(&paths.baseline, &root, options.scope, &key_path)?;
            let events = compare::compare(&baseline, &snapshot);
            store::append_history(&paths, &events, options.history_policy, &key_path)?;
            report::events(
                &root,
                options.scope,
                &events,
                options.verbose,
                &options.output,
                false,
            )?;
            report::check_summary(&snapshot, options.scope, &options.output)?;
            let missing: Vec<_> = expected_coverage(options.scope)
                .difference(&snapshot.coverage)
                .map(|coverage| format!("{}:{}", coverage.source.label(), coverage.scope.label()))
                .collect();
            if !missing.is_empty() {
                options.output.diagnostic(
                    "persist",
                    "warning",
                    &format!(
                        "Audit incomplete; removals from uncovered sources were suppressed: {}",
                        missing.join(", ")
                    ),
                )?;
                return Ok(RunStatus::Incomplete);
            }
            if events.iter().any(|event| {
                event
                    .after
                    .as_ref()
                    .is_some_and(|entry| entry.risk == Risk::High)
            }) {
                return Ok(RunStatus::HighRisk);
            }
            if !events.is_empty() {
                return Ok(RunStatus::Changes);
            }
        }
        Action::History => unreachable!(),
    }
    Ok(RunStatus::Success)
}
