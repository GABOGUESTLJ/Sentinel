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
use std::{collections::BTreeSet, path::PathBuf};

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
    pub action: Action,
    pub history_policy: crate::retention::Policy,
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
    let paths = store::Paths::discover(&root, options.scope)?;

    if matches!(options.action, Action::History) {
        let (events, warnings) = store::read_history(&paths.history, options.history_policy)?;
        report::warnings(&warnings);
        report::history(&events, options.verbose);
        return Ok(RunStatus::Success);
    }

    if matches!(options.action, Action::UpdateBaseline) {
        store::load_baseline(&paths.baseline, &root, options.scope)?;
    }

    let snapshot = collect::collect(&collect::Options {
        root: root.clone(),
        scope: options.scope,
        offline: options.offline || root != std::path::Path::new("/"),
    });
    report::warnings(&snapshot.warnings);

    match options.action {
        Action::List => report::inventory(&snapshot, options.verbose),
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
            store::save_baseline(&paths.baseline, &root, options.scope, &snapshot, replace)?;
            println!(
                "Persist baseline saved at {} ({} mechanisms, scope={}).",
                paths.baseline.display(),
                snapshot.entries.len(),
                options.scope.label()
            );
        }
        Action::Check => {
            let baseline = store::load_baseline(&paths.baseline, &root, options.scope)?;
            let events = compare::compare(&baseline, &snapshot);
            store::append_history(&paths.history, &events, options.history_policy)?;
            report::events(&events, options.verbose);
            let missing: Vec<_> = expected_coverage(options.scope)
                .difference(&snapshot.coverage)
                .map(|coverage| format!("{}:{}", coverage.source.label(), coverage.scope.label()))
                .collect();
            if !missing.is_empty() {
                eprintln!(
                    "Audit incomplete; removals from uncovered sources were suppressed: {}",
                    missing.join(", ")
                );
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
