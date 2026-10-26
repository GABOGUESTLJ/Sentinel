//! Command-line entry point for Sentinel.
//!
//! # English
//!
//! ## Overview
//!
//! Sentinel is a security CLI for monitoring filesystem integrity and
//! auditing Linux persistence mechanisms. It requires one of two subcommands:
//!
//! - `fim` monitors a filesystem tree and compares it with an
//!   HMAC-authenticated baseline.
//! - `persist` inventories systemd, cron, SSH and XDG persistence mechanisms
//!   and compares them with an HMAC-authenticated persistence baseline.
//!
//! ## FIM workflow
//!
//! 1. Canonicalize and validate the scan root.
//! 2. Load or create the private HMAC key.
//! 3. Load, initialize or update the trusted baseline.
//! 4. Scan regular files, directories, symbolic links and special files.
//! 5. Compare the current state with the previous state and baseline.
//! 6. Report changes and append structured events to persistent history.
//!
//! ## Persist workflow
//!
//! 1. Collect persistence entries from the selected Linux sources.
//! 2. Normalize entries into stable identities.
//! 3. Verify and compare the inventory with its authenticated baseline.
//! 4. Append changes to an HMAC-chained history.
//! 5. Report changes, risk levels and coverage failures.
//!
//! ## Exit codes
//!
//! | Code | Meaning |
//! | ---: | --- |
//! | `0` | Successful operation or audit without changes. |
//! | `1` | Operational error. |
//! | `2` | Invalid command-line usage. |
//! | `3` | Persistence changes detected. |
//! | `4` | High-risk persistence change detected. |
//! | `5` | Persistence audit completed with incomplete coverage. |
//!
//! ## Examples
//!
//! ```text
//! sentinel fim --scan /srv/application --init-baseline
//! sentinel fim --scan /srv/application
//! sentinel persist --scope all --check
//! ```
//!
//! # Español
//!
//! ## Descripción
//!
//! Sentinel es una CLI de seguridad para vigilar la integridad del sistema de
//! archivos y auditar mecanismos de persistencia de Linux. Requiere uno de dos
//! subcomandos:
//!
//! - `fim` vigila un árbol de archivos y lo compara con una baseline
//!   autenticada mediante HMAC.
//! - `persist` crea un inventario de mecanismos de persistencia de systemd,
//!   cron, SSH y XDG, y lo compara con una baseline autenticada mediante HMAC.
//!
//! ## Flujo de FIM
//!
//! 1. Canoniza y valida la raíz que se vigilará.
//! 2. Carga o crea la clave HMAC privada.
//! 3. Carga, inicializa o actualiza la baseline confiable.
//! 4. Escanea archivos regulares, directorios, enlaces simbólicos y archivos
//!    especiales.
//! 5. Compara el estado actual con el estado anterior y la baseline.
//! 6. Informa los cambios y agrega eventos estructurados al historial.
//!
//! ## Flujo de Persist
//!
//! 1. Recolecta entradas de persistencia de las fuentes Linux seleccionadas.
//! 2. Normaliza las entradas en identidades estables.
//! 3. Verifica y compara el inventario con su baseline autenticada.
//! 4. Agrega los cambios a un historial HMAC encadenado.
//! 5. Informa cambios, niveles de riesgo y fallos de cobertura.
//!
//! ## Códigos de salida
//!
//! | Código | Significado |
//! | ---: | --- |
//! | `0` | Operación correcta o auditoría sin cambios. |
//! | `1` | Error operativo. |
//! | `2` | Uso incorrecto de la línea de comandos. |
//! | `3` | Se detectaron cambios de persistencia. |
//! | `4` | Se detectó un cambio de persistencia de riesgo alto. |
//! | `5` | La auditoría terminó con cobertura incompleta. |
//!
//! ## Ejemplos
//!
//! ```text
//! sentinel fim --scan /srv/aplicacion --init-baseline
//! sentinel fim --scan /srv/aplicacion
//! sentinel persist --scope all --check
//! ```

#![warn(rustdoc::broken_intra_doc_links)]

mod auth;
mod baseline;
mod event;
mod fim;
mod hash_files;
mod history;
mod history_export;
mod history_queue;
mod monitor;
mod persist;
mod presentation;
mod private_store;
mod read_files;
mod report;
mod retention;
mod runtime;
mod scan_files;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, builder::TypedValueParser};
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
/// Represents Sentinel's top-level command-line interface.
///
/// A subcommand is mandatory. Options belonging to `fim` or `persist` must be
/// placed after the corresponding subcommand.
///
/// # Español
///
/// Representa la interfaz principal de línea de comandos de Sentinel.
///
/// Es obligatorio seleccionar un subcomando. Las opciones de `fim` o
/// `persist` deben escribirse después del subcomando correspondiente.
struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    fn validate_actions(&self) -> Result<(), clap::Error> {
        match &self.command {
            Command::Fim(args) => args.export.validate_action(args.history.is_some()),
            Command::Persist(args) => args.export.validate_action(args.action.history),
        }
    }
}

#[derive(Subcommand, Debug)]
/// Selects the security tool executed by Sentinel.
///
/// # Español
///
/// Selecciona la herramienta de seguridad que ejecutará Sentinel.
enum Command {
    /// Monitor file integrity.
    Fim(FimArgs),
    /// Audit Linux persistence mechanisms.
    Persist(PersistArgs),
}

#[derive(clap::Args, Debug)]
/// Configures a file-integrity monitoring operation.
///
/// These arguments control the monitored root, watcher implementation,
/// authenticated baseline, console output and history retention.
///
/// # Español
///
/// Configura una operación de vigilancia de integridad de archivos.
///
/// Estos argumentos controlan la raíz vigilada, la implementación del
/// watcher, la baseline autenticada, la salida de consola y la retención del
/// historial.
struct FimArgs {
    #[command(flatten)]
    output: presentation::Args,
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
    #[arg(long, conflicts_with_all = ["update_baseline", "migrate_baseline"])]
    init_baseline: bool,
    /// Explicitly accept the current state and replace an existing baseline.
    #[arg(long, conflicts_with = "migrate_baseline")]
    update_baseline: bool,
    /// Copy a signed legacy TMPDIR baseline to durable storage; keep the original.
    #[arg(long)]
    migrate_baseline: bool,
    /// Absolute path to a private 32-byte HMAC key (default: Sentinel config directory).
    #[arg(long, value_name = "FILE")]
    hmac_key: Option<PathBuf>,
    /// History retention limits used by monitoring and history queries.
    ///
    /// Límites de retención usados por la vigilancia y las consultas de
    /// historial.
    #[command(flatten)]
    history_policy: HistoryPolicyArgs,
    /// Show persistent history and exit; use `--history=<FILE>` to filter one file.
    #[arg(
        long,
        help = "Show persistent history and exit; use --history=<FILE> to filter one file.",
        value_name = "FILE",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "",
        value_parser = clap::builder::OsStringValueParser::new().map(PathBuf::from),
        conflicts_with_all = [
            "hardscan",
            "interval",
            "silent",
            "desilent",
            "init_baseline",
            "update_baseline",
            "migrate_baseline"
        ]
    )]
    history: Option<PathBuf>,
    #[command(flatten)]
    export: HistoryExportArgs,
}

#[derive(clap::Args, Debug)]
#[group(required = true, multiple = false)]
/// Selects exactly one persistence operation.
///
/// Clap validates the required, mutually exclusive action before Sentinel
/// converts it into a domain-level persistence action.
///
/// # Español
///
/// Selecciona exactamente una operación de persistencia.
///
/// Clap valida la acción obligatoria y mutuamente excluyente antes de que
/// Sentinel la convierta en una acción del dominio de persistencia.
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
    /// Converts the validated CLI flags into a persistence action.
    ///
    /// # Español
    ///
    /// Convierte las flags validadas de la CLI en una acción de persistencia.
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
/// Configures a Linux persistence audit operation.
///
/// These arguments select the filesystem root, evidence scope, collection
/// mode, output detail, history retention and action.
///
/// # Español
///
/// Configura una operación de auditoría de persistencia de Linux.
///
/// Estos argumentos seleccionan la raíz del sistema, el alcance de evidencia,
/// el modo de recolección, el detalle de salida, la retención y la acción.
struct PersistArgs {
    #[command(flatten)]
    output: presentation::Args,
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
    /// Absolute path to Persist's private 32-byte HMAC key.
    #[arg(long, value_name = "FILE")]
    hmac_key: Option<PathBuf>,
    /// History retention limits for this persistence profile.
    ///
    /// Límites de retención del historial para este perfil de persistencia.
    #[command(flatten)]
    history_policy: HistoryPolicyArgs,
    /// Baseline, comparison, inventory or history action to execute.
    ///
    /// Acción de baseline, comparación, inventario o historial que se
    /// ejecutará.
    #[command(flatten)]
    action: PersistActionArgs,
    #[command(flatten)]
    export: HistoryExportArgs,
}

#[derive(clap::Args, Debug)]
struct HistoryExportArgs {
    /// Export retained history without pruning or modifying it; never overwrite FILE.
    #[arg(long, requires = "history", value_name = "FILE")]
    export: Option<PathBuf>,
    /// Export format (default: markdown); requires --export.
    #[arg(long, requires = "export", value_enum)]
    format: Option<history_export::Format>,
    /// Include events from this UTC calendar day (YYYY-MM-DD), inclusive.
    #[arg(long, requires = "export", value_parser = history_export::parse_day)]
    since: Option<String>,
    /// Include events through this UTC calendar day (YYYY-MM-DD), inclusive.
    #[arg(long, requires = "export", value_parser = history_export::parse_day)]
    until: Option<String>,
}

impl HistoryExportArgs {
    fn validate_action(&self, history: bool) -> Result<(), clap::Error> {
        let modifiers = self.format.is_some() || self.since.is_some() || self.until.is_some();
        // Clap can waive a `requires` relation when a conflicting action is
        // present. Enforce this cross-action invariant before any filesystem I/O.
        if (!history && (self.export.is_some() || modifiers))
            || (self.export.is_none() && modifiers)
        {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::ArgumentConflict,
                "History export options require --history and --export; they cannot be combined with another action",
            ));
        }
        Ok(())
    }

    fn request(self) -> Result<Option<history_export::Request>, Box<dyn std::error::Error>> {
        let Some(destination) = self.export else {
            return Ok(None);
        };
        let request = history_export::Request {
            destination,
            format: self.format.unwrap_or(history_export::Format::Markdown),
            since: self.since,
            until: self.until,
        };
        request.validate()?;
        Ok(Some(request))
    }
}

#[derive(clap::Args, Debug, Clone, Copy)]
/// Defines user-configurable history retention limits.
///
/// # Español
///
/// Define los límites configurables de retención del historial.
struct HistoryPolicyArgs {
    /// Prune history segments older than this many days; baseline and keys never expire.
    #[arg(long, default_value = "14", value_name = "DAYS")]
    history_days: NonZeroU64,
    /// Keep at most this many MiB of history per monitored profile.
    #[arg(long, default_value = "100", value_name = "MIB")]
    history_max_mib: NonZeroU64,
}

impl HistoryPolicyArgs {
    /// Converts CLI retention values into the runtime retention policy.
    ///
    /// Days are converted to seconds and MiB to bytes. Saturating arithmetic
    /// prevents overflowing values from wrapping into unexpectedly small
    /// limits.
    ///
    /// # Español
    ///
    /// Convierte los valores de retención de la CLI en la política de
    /// ejecución. Los días se convierten en segundos y los MiB en bytes. La
    /// aritmética saturada evita que valores demasiado grandes se conviertan
    /// en límites inesperadamente pequeños.
    fn policy(self) -> retention::Policy {
        retention::Policy {
            max_age: Duration::from_secs(self.history_days.get().saturating_mul(86_400)),
            max_bytes: self.history_max_mib.get().saturating_mul(1024 * 1024),
        }
    }
}

/// Normalizes compatibility aliases before Clap parses the arguments.
///
/// Clap short options contain one character. Sentinel accepts the requested
/// `-hs` spelling by translating an argument that exactly matches `-hs` into
/// `--hardscan`. All other arguments remain unchanged. Keeping `OsString`
/// preserves paths and arguments that are not valid UTF-8.
///
/// # Español
///
/// Normaliza alias de compatibilidad antes de que Clap analice los argumentos.
///
/// Las opciones cortas de Clap contienen un carácter. Sentinel acepta la forma
/// `-hs` convirtiendo el argumento exacto en `--hardscan`. Los demás argumentos
/// permanecen sin cambios. Mantener `OsString` conserva rutas y argumentos que
/// no sean UTF-8 válido.
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

/// Executes the selected file-integrity operation.
///
/// The function selects one of three mutually exclusive flows: display
/// history, initialize or update the authenticated baseline, or load the
/// trusted baseline and start live monitoring. The scan root is canonicalized
/// and validated before any flow begins.
///
/// # Errors
///
/// Returns an error when the scan root, private storage, HMAC key, baseline,
/// initial scan or watcher cannot be validated or initialized.
///
/// # Español
///
/// Ejecuta la operación seleccionada del monitor de integridad.
///
/// La función selecciona uno de tres flujos mutuamente excluyentes: mostrar el
/// historial, inicializar o actualizar la baseline autenticada, o cargar la
/// baseline confiable e iniciar la vigilancia. La raíz se canoniza y valida
/// antes de comenzar.
///
/// ## Errores
///
/// Devuelve un error cuando no puede validar o inicializar la raíz, el
/// almacenamiento privado, la clave HMAC, la baseline, el escaneo inicial o
/// el watcher.
fn run_fim(args: FimArgs) -> Result<(), Box<dyn std::error::Error>> {
    fim::run(args)
}

/// Executes the selected Linux persistence operation.
///
/// This adapter translates CLI values into domain options and returns a
/// semantic audit status that `main` converts into a process exit code.
///
/// # Errors
///
/// Returns an error when the audit root, baseline or private state storage
/// cannot be validated or accessed.
///
/// # Español
///
/// Ejecuta la operación seleccionada de auditoría de persistencia de Linux.
///
/// Este adaptador convierte los valores de la CLI en opciones del dominio y
/// devuelve un estado semántico que `main` transforma en código de salida.
///
/// ## Errores
///
/// Devuelve un error cuando no puede validar o acceder a la raíz, la baseline
/// o el almacenamiento privado.
fn run_persist(args: PersistArgs) -> Result<persist::RunStatus, Box<dyn std::error::Error>> {
    persist::run(persist::Options {
        root: args.root,
        scope: args.scope,
        offline: args.offline,
        verbose: args.verbose,
        output: args.output.options(),
        hmac_key: args.hmac_key,
        action: args.action.action(),
        history_policy: args.history_policy.policy(),
        export: args.export.request()?,
    })
}

/// Parses the command line, dispatches the selected tool and returns its exit code.
///
/// Clap handles invalid syntax with exit code `2`. Operational failures are
/// written to standard error and return code `1`. Persistence audit outcomes
/// use codes `3`, `4` and `5`.
///
/// # Español
///
/// Analiza la línea de comandos, ejecuta la herramienta seleccionada y devuelve
/// su código de salida.
///
/// Clap maneja la sintaxis inválida con código `2`. Los errores operativos se
/// escriben en la salida de error y devuelven código `1`. Los resultados de
/// Persist utilizan los códigos `3`, `4` y `5`.
fn main() -> ExitCode {
    let args = normalize_args(std::env::args_os());
    let mut command = Cli::command();
    if std::env::var_os("NO_COLOR").is_some() || args.iter().any(|arg| arg == "--no-color") {
        command = command.color(clap::ColorChoice::Never);
    }
    let matches = command.get_matches_from(args);
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    if let Err(error) = cli.validate_actions() {
        error.exit();
    }
    let (module, output) = match &cli.command {
        Command::Fim(args) => ("fim", args.output.options()),
        Command::Persist(args) => ("persist", args.output.options()),
    };
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
            let _ = output.diagnostic(module, "error", &format!("Error: {error}"));
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
        assert_eq!(args.history_policy.history_days.get(), 14);
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
            "--hmac-key",
            "/tmp/persist-key",
        ])
        .unwrap();
        assert_eq!(args.root, PathBuf::from("/mnt/image"));
        assert_eq!(args.scope, persist::ScopeSelection::System);
        assert!(args.offline && args.verbose && args.action.check);
        assert_eq!(args.hmac_key, Some(PathBuf::from("/tmp/persist-key")));
        assert_eq!(args.history_policy.history_days.get(), 14);
    }

    #[test]
    fn parses_explicit_migration_and_history_export_actions() {
        assert!(parse_fim(["sentinel", "fim", "--migrate-baseline"]).is_ok());
        for tool in ["fim", "persist"] {
            assert!(
                Cli::try_parse_from([
                    "sentinel",
                    tool,
                    "--history",
                    "--export",
                    "/exports/audit.md",
                    "--format",
                    "markdown",
                    "--since",
                    "2026-01-01",
                    "--until",
                    "2026-01-31",
                ])
                .is_ok()
            );
            assert!(
                Cli::try_parse_from(["sentinel", tool, "--export", "/exports/audit.txt",]).is_err()
            );
            assert!(
                Cli::try_parse_from(["sentinel", tool, "--history", "--format", "text",]).is_err()
            );
        }
    }

    #[test]
    fn validates_export_action_invariants_after_clap_conflict_resolution() {
        for (tool, action) in [
            ("fim", "--init-baseline"),
            ("fim", "--update-baseline"),
            ("fim", "--migrate-baseline"),
            ("persist", "--list"),
            ("persist", "--init-baseline"),
            ("persist", "--update-baseline"),
            ("persist", "--check"),
        ] {
            let result = Cli::try_parse_from([
                "sentinel",
                tool,
                action,
                "--export",
                "/exports/audit.txt",
                "--format",
                "text",
            ])
            .and_then(|cli| cli.validate_actions());
            assert!(
                result.is_err(),
                "{tool} {action} must not ignore export options"
            );
        }
    }
}
