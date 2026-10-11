mod auth;
mod baseline;
mod event;
mod hash_files;
mod history;
mod monitor;
mod persist;
mod private_store;
mod read_files;
mod report;
mod retention;
mod runtime;
mod scan_files;

use clap::{Parser, Subcommand};
use std::{
    ffi::{OsStr, OsString},
    num::NonZeroU64,
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

#[derive(Parser, Debug)]
#[command(
    about = "Security tools for the terminal",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Monitor file integrity.
    Fim(FimArgs),
    /// Audit Linux persistence mechanisms.
    Persist(PersistArgs),
}

#[derive(clap::Args, Debug)]
struct FimArgs {
    /// Directory to scan and monitor recursively (default: current directory).
    #[arg(short = 's', long, default_value = ".", value_name = "PATH")]
    scan: PathBuf,
    /// Use PollWatcher for change detection; -hs is an alias. Costs more I/O.
    #[arg(long)]
    hardscan: bool,
    /// Seconds between full scans (and PollWatcher checks in --hardscan mode).
    #[arg(short, long, default_value = "5", value_name = "SECONDS")]
    interval: NonZeroU64,
    /// Show complete before, after, and baseline metadata for displayed changes.
    #[arg(short, long)]
    verbose: bool,
    /// Hide routine output; errors remain visible. Type --desilent while running.
    #[arg(long, conflicts_with = "desilent")]
    silent: bool,
    /// Enable output at startup or by typing -d in the running terminal.
    #[arg(short, long)]
    desilent: bool,
    /// Create the trusted baseline and exit; never overwrite an existing baseline.
    #[arg(long, conflicts_with = "update_baseline")]
    init_baseline: bool,
    /// Explicitly accept the current state and replace an existing baseline.
    #[arg(long)]
    update_baseline: bool,
    /// Absolute path to a private 32-byte HMAC key (default: Sentinel config directory).
    #[arg(long, value_name = "FILE")]
    hmac_key: Option<PathBuf>,
    #[command(flatten)]
    history_policy: HistoryPolicyArgs,
    /// Show persistent history and exit; use --history=<FILE> to filter one file.
    #[arg(
        long,
        value_name = "FILE",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        conflicts_with_all = [
            "hardscan",
            "interval",
            "silent",
            "desilent",
            "init_baseline",
            "update_baseline"
        ]
    )]
    history: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
#[group(required = true, multiple = false)]
struct PersistActionArgs {
    /// Create the trusted persistence baseline and exit.
    #[arg(long)]
    init_baseline: bool,
    /// Explicitly replace an existing persistence baseline.
    #[arg(long)]
    update_baseline: bool,
    /// Compare the current persistence state with the baseline.
    #[arg(long)]
    check: bool,
    /// List the current normalized persistence inventory without comparing it.
    #[arg(long)]
    list: bool,
    /// Show the persistent audit history and exit.
    #[arg(long)]
    history: bool,
}

impl PersistActionArgs {
    fn action(&self) -> persist::Action {
        if self.init_baseline {
            persist::Action::InitBaseline
        } else if self.update_baseline {
            persist::Action::UpdateBaseline
        } else if self.check {
            persist::Action::Check
        } else if self.list {
            persist::Action::List
        } else {
            debug_assert!(self.history);
            persist::Action::History
        }
    }
}

#[derive(clap::Args, Debug)]
struct PersistArgs {
    /// Filesystem root to audit; alternate roots use static evidence only.
    #[arg(short, long, default_value = "/", value_name = "PATH")]
    root: PathBuf,
    /// Audit user, system, or all persistence sources.
    #[arg(short = 'S', long, value_enum, default_value = "all")]
    scope: persist::ScopeSelection,
    /// Skip D-Bus and audit configuration files only.
    #[arg(short, long)]
    offline: bool,
    /// Show full evidence, origins, hashes, and risk reasons.
    #[arg(short, long)]
    verbose: bool,
    #[command(flatten)]
    history_policy: HistoryPolicyArgs,
    #[command(flatten)]
    action: PersistActionArgs,
}

#[derive(clap::Args, Debug, Clone, Copy)]
struct HistoryPolicyArgs {
    /// Delete history older than this many days.
    #[arg(long, default_value = "90", value_name = "DAYS")]
    history_days: NonZeroU64,
    /// Keep at most this many MiB of history per monitored profile.
    #[arg(long, default_value = "100", value_name = "MIB")]
    history_max_mib: NonZeroU64,
}

impl HistoryPolicyArgs {
    fn policy(self) -> retention::Policy {
        retention::Policy {
            max_age: Duration::from_secs(self.history_days.get().saturating_mul(86_400)),
            max_bytes: self.history_max_mib.get().saturating_mul(1024 * 1024),
        }
    }
}

// Clap short options contain one character. Translate the requested -hs alias.
fn normalize_args(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    args.into_iter()
        .map(|arg| {
            if arg == OsStr::new("-hs") {
                OsString::from("--hardscan")
            } else {
                arg
            }
        })
        .collect()
}

fn run_fim(args: FimArgs) -> Result<(), Box<dyn std::error::Error>> {
    let root = args.scan.canonicalize()?;
    if !std::fs::symlink_metadata(&root)?.is_dir() {
        return Err(format!("Not a directory: {}", root.display()).into());
    }
    if let Some(filter) = args.history {
        let filter_label =
            (!filter.as_os_str().is_empty()).then(|| filter.to_string_lossy().into_owned());
        let filter_hex = if filter.as_os_str().is_empty() {
            None
        } else {
            Some(event::normalize_filter(&root, filter).map_err(|error| error.to_string())?)
        };
        let result = history::read(&root, filter_hex.as_deref(), args.history_policy.policy())?;
        for warning in result.warnings {
            eprintln!("History warning: {warning}");
        }
        report::history(&result.events, args.verbose, filter_label.as_deref());
        return Ok(());
    }
    let baseline_path = baseline::location(&root)?;
    let key_path = auth::key_path(args.hmac_key.as_deref())?;
    if args.init_baseline || args.update_baseline {
        if args.update_baseline {
            // Refuse to replace corrupt, incompatible, or unsafe references implicitly.
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
            println!(
                "Baseline saved at {} ({} entries).",
                baseline_path.display(),
                entries.len()
            );
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
        },
    )
}

fn run_persist(args: PersistArgs) -> Result<persist::RunStatus, Box<dyn std::error::Error>> {
    persist::run(persist::Options {
        root: args.root,
        scope: args.scope,
        offline: args.offline,
        verbose: args.verbose,
        action: args.action.action(),
        history_policy: args.history_policy.policy(),
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(normalize_args(std::env::args_os()));
    let result = match cli.command {
        Command::Fim(args) => run_fim(args).map(|()| ExitCode::SUCCESS),
        Command::Persist(args) => run_persist(args).map(|status| match status {
            persist::RunStatus::Success => ExitCode::SUCCESS,
            persist::RunStatus::Changes => ExitCode::from(3),
            persist::RunStatus::HighRisk => ExitCode::from(4),
            persist::RunStatus::Incomplete => ExitCode::from(5),
        }),
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_fim<'a>(args: impl IntoIterator<Item = &'a str>) -> Result<FimArgs, clap::Error> {
        Cli::try_parse_from(args).map(|cli| match cli.command {
            Command::Fim(args) => args,
            Command::Persist(_) => panic!("expected fim"),
        })
    }

    fn parse_persist<'a>(
        args: impl IntoIterator<Item = &'a str>,
    ) -> Result<PersistArgs, clap::Error> {
        Cli::try_parse_from(args).map(|cli| match cli.command {
            Command::Persist(args) => args,
            Command::Fim(_) => panic!("expected persist"),
        })
    }

    #[test]
    fn parses_each_short_and_long_cli_flag() {
        let cases: &[&[&str]] = &[
            &["sentinel", "fim", "-s", "/tmp/watch"],
            &["sentinel", "fim", "--scan", "/tmp/watch"],
            &["sentinel", "fim", "--hardscan"],
            &["sentinel", "fim", "-i", "3"],
            &["sentinel", "fim", "--interval", "3"],
            &["sentinel", "fim", "-v"],
            &["sentinel", "fim", "--verbose"],
            &["sentinel", "fim", "--silent"],
            &["sentinel", "fim", "-d"],
            &["sentinel", "fim", "--desilent"],
            &["sentinel", "fim", "--init-baseline"],
            &["sentinel", "fim", "--update-baseline"],
            &["sentinel", "fim", "--hmac-key", "/tmp/key"],
            &["sentinel", "fim", "--history-days", "7"],
            &["sentinel", "fim", "--history-max-mib", "8"],
        ];
        for args in cases {
            parse_fim(args.iter().copied()).unwrap_or_else(|error| panic!("{args:?}: {error}"));
        }
        let alias = normalize_args(["sentinel".into(), "fim".into(), "-hs".into()]);
        let args = match Cli::try_parse_from(alias).unwrap().command {
            Command::Fim(args) => args,
            Command::Persist(_) => panic!("expected fim"),
        };
        assert!(args.hardscan);
    }

    #[test]
    fn defaults_and_combined_output_flags_are_explicit() {
        let args = parse_fim(["sentinel", "fim"]).unwrap();
        assert_eq!(args.scan, PathBuf::from("."));
        assert_eq!(args.interval.get(), 5);
        assert!(!args.verbose && !args.silent && !args.desilent && !args.hardscan);
        let args = parse_fim([
            "sentinel", "fim", "-s", "/watch", "-i", "4", "-v", "--silent",
        ])
        .unwrap();
        assert_eq!(args.scan, PathBuf::from("/watch"));
        assert_eq!(args.interval.get(), 4);
        assert!(args.verbose && args.silent);
    }

    #[test]
    fn rejects_invalid_and_conflicting_flags() {
        for args in [
            vec!["sentinel", "fim", "--interval", "0"],
            vec!["sentinel", "fim", "--interval", "1.5"],
            vec!["sentinel", "fim", "--silent", "--desilent"],
            vec!["sentinel", "fim", "--path", "/watch"],
            vec!["sentinel", "fim", "-s"],
            vec!["sentinel", "fim", "--init-baseline", "--update-baseline"],
            vec!["sentinel", "fim", "--verbose=true"],
            vec!["sentinel", "fim", "--unknown"],
            vec!["sentinel", "fim", "--history-days", "0"],
            vec!["sentinel", "fim", "--history-max-mib", "0"],
        ] {
            assert!(parse_fim(args).is_err());
        }
    }

    #[test]
    fn subcommand_is_required_and_fim_flags_do_not_belong_to_root() {
        assert!(Cli::try_parse_from(["sentinel"]).is_err());
        assert!(Cli::try_parse_from(["sentinel", "--scan", "/watch"]).is_err());
        assert!(Cli::try_parse_from(["sentinel", "unknown"]).is_err());
    }

    #[test]
    fn persist_requires_one_action_and_parses_common_flags() {
        assert!(parse_persist(["sentinel", "persist"]).is_err());
        assert!(parse_persist(["sentinel", "persist", "--check", "--list"]).is_err());
        let args = parse_persist([
            "sentinel",
            "persist",
            "--check",
            "--root",
            "/mnt/image",
            "--scope",
            "system",
            "--offline",
            "--verbose",
        ])
        .unwrap();
        assert_eq!(args.root, PathBuf::from("/mnt/image"));
        assert_eq!(args.scope, persist::ScopeSelection::System);
        assert!(args.offline && args.verbose && args.action.check);
        assert_eq!(args.history_policy.history_days.get(), 90);
    }
}
