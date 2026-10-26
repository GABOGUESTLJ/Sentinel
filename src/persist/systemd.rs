use super::{
    collect::{Options, display_origin, path_exists, read_text, rooted, user_homes},
    model::{CollectorOutput, EntrySpec, Evidence, PersistenceEntry, Scope, Source},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;
use zbus::{blocking::Connection, proxy, zvariant::OwnedObjectPath};

type ListedUnit = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait SystemdManager {
    fn list_unit_files(&self) -> zbus::Result<Vec<(String, String)>>;
    fn list_units(&self) -> zbus::Result<Vec<ListedUnit>>;
}

#[derive(Default)]
struct RuntimeState {
    units: BTreeMap<String, (Option<bool>, Option<bool>)>,
}

fn runtime_state(scope: Scope) -> Result<RuntimeState, String> {
    let connection = match scope {
        Scope::System => Connection::system(),
        Scope::User => Connection::session(),
    }
    .map_err(|error| format!("{} systemd D-Bus: {error}", scope.label()))?;
    let proxy = SystemdManagerProxyBlocking::new(&connection)
        .map_err(|error| format!("{} systemd D-Bus proxy: {error}", scope.label()))?;

    let mut state = RuntimeState::default();
    for (path, unit_state) in proxy
        .list_unit_files()
        .map_err(|error| format!("{} systemd ListUnitFiles: {error}", scope.label()))?
    {
        let name = Path::new(&path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or(path);
        let enabled = matches!(unit_state.as_str(), "enabled" | "enabled-runtime");
        state.units.entry(name).or_default().0 = Some(enabled);
    }
    for unit in proxy
        .list_units()
        .map_err(|error| format!("{} systemd ListUnits: {error}", scope.label()))?
    {
        state.units.entry(unit.0).or_default().1 =
            Some(matches!(unit.3.as_str(), "active" | "activating"));
    }
    Ok(state)
}

fn system_directories(root: &Path) -> Vec<PathBuf> {
    [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/local/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ]
    .into_iter()
    .map(|path| rooted(root, path))
    .collect()
}

fn user_directories(root: &Path, home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".config/systemd/user"),
        rooted(root, "/etc/systemd/user"),
        rooted(root, "/usr/lib/systemd/user"),
    ]
}

fn unit_files(directories: &[PathBuf]) -> Result<BTreeMap<String, PathBuf>, String> {
    let mut units = BTreeMap::new();
    for directory in directories {
        if !path_exists(directory)? {
            continue;
        }
        let items = std::fs::read_dir(directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        for item in items {
            let item = item.map_err(|error| format!("{}: {error}", directory.display()))?;
            let name = item.file_name().to_string_lossy().into_owned();
            if name.ends_with(".service") || name.ends_with(".timer") {
                units.entry(name).or_insert_with(|| item.path());
            }
        }
    }
    Ok(units)
}

fn statically_enabled(directories: &[PathBuf], unit: &str) -> Result<bool, String> {
    let mut enabled = false;
    for directory in directories {
        if !path_exists(directory)? {
            continue;
        }
        for item in WalkDir::new(directory)
            .min_depth(2)
            .max_depth(2)
            .follow_links(false)
        {
            let item = item.map_err(|error| format!("{}: {error}", directory.display()))?;
            if item.file_name() == unit
                && item
                    .path()
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|name| {
                        let name = name.to_string_lossy();
                        name.ends_with(".wants") || name.ends_with(".requires")
                    })
            {
                enabled = true;
            }
        }
    }
    Ok(enabled)
}

fn parse_unit(
    root: &Path,
    directories: &[PathBuf],
    unit: &str,
    main_path: &Path,
    scope: Scope,
    owner: &str,
    runtime: Option<&RuntimeState>,
) -> Result<PersistenceEntry, String> {
    let mut paths = vec![main_path.to_path_buf()];
    let mut dropins = Vec::new();
    for directory in directories.iter().rev() {
        let path = directory.join(format!("{unit}.d"));
        if !path_exists(&path)? {
            continue;
        }
        let mut directory_dropins = Vec::new();
        for item in
            std::fs::read_dir(&path).map_err(|error| format!("{}: {error}", path.display()))?
        {
            let item = item.map_err(|error| format!("{}: {error}", path.display()))?;
            if item
                .path()
                .extension()
                .is_some_and(|extension| extension == "conf")
            {
                directory_dropins.push(item.path());
            }
        }
        directory_dropins.sort();
        dropins.extend(directory_dropins);
    }
    paths.extend(dropins);

    const EXEC_KEYS: [&str; 6] = [
        "ExecCondition",
        "ExecStartPre",
        "ExecStart",
        "ExecStartPost",
        "ExecReload",
        "ExecStopPost",
    ];
    const CONFIG_KEYS: [&str; 9] = [
        "User",
        "Group",
        "Type",
        "WorkingDirectory",
        "Environment",
        "EnvironmentFile",
        "RemainAfterExit",
        "Persistent",
        "Unit",
    ];
    let mut commands = BTreeMap::<String, Vec<String>>::new();
    let mut triggers = Vec::new();
    let mut semantic = Vec::new();
    for path in &paths {
        let text = read_text(path)?;
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            if EXEC_KEYS.contains(&key) {
                semantic.extend_from_slice(format!("{key}={value}\n").as_bytes());
                let values = commands.entry(key.to_owned()).or_default();
                if value.is_empty() {
                    values.clear();
                } else {
                    values.push(if key == "ExecStart" {
                        value.to_owned()
                    } else {
                        format!("{key}:{value}")
                    });
                }
            }
            if ["OnCalendar", "OnBootSec", "OnStartupSec", "OnUnitActiveSec"].contains(&key) {
                semantic.extend_from_slice(format!("{key}={value}\n").as_bytes());
                if value.is_empty() {
                    triggers.clear();
                } else {
                    triggers.push(format!("{key}={value}"));
                }
            }
            if CONFIG_KEYS.contains(&key) {
                semantic.extend_from_slice(format!("{key}={value}\n").as_bytes());
            }
        }
    }

    let inferred_enabled = statically_enabled(directories, unit)?;
    let runtime_values = runtime.and_then(|state| state.units.get(unit).copied());
    let enabled = runtime_values
        .and_then(|value| value.0)
        .or(Some(inferred_enabled));
    let active = runtime_values.and_then(|value| value.1);
    let trigger = if unit.ends_with(".timer") {
        if triggers.is_empty() {
            "systemd timer".into()
        } else {
            triggers.join(", ")
        }
    } else {
        "systemd service".into()
    };
    let commands: Vec<String> = EXEC_KEYS
        .iter()
        .filter_map(|key| commands.get(*key))
        .flatten()
        .cloned()
        .collect();
    let command = if unit.ends_with(".timer") {
        format!("activate {}.service", unit.trim_end_matches(".timer"))
    } else if commands.is_empty() {
        "<no ExecStart in inspected fragments>".into()
    } else {
        commands.join(" ; ")
    };
    Ok(PersistenceEntry::new(EntrySpec {
        source: Source::Systemd,
        scope,
        owner,
        locator: unit,
        origins: paths
            .iter()
            .map(|path| display_origin(root, path))
            .collect(),
        location_hint: None,
        trigger,
        command,
        enabled,
        active,
        evidence: if runtime.is_some() {
            Evidence::Effective
        } else {
            Evidence::Static
        },
        semantic_config: &semantic,
    }))
}

fn collect_scope(
    output: &mut CollectorOutput,
    options: &Options,
    scope: Scope,
    owner: &str,
    directories: Vec<PathBuf>,
    runtime: Option<&RuntimeState>,
) {
    output.covered(Source::Systemd, scope);
    match unit_files(&directories) {
        Ok(units) => {
            for directory in &directories {
                output.inspected(Source::Systemd, scope, owner, directory);
            }
            for (unit, path) in units {
                match parse_unit(
                    &options.root,
                    &directories,
                    &unit,
                    &path,
                    scope,
                    owner,
                    runtime,
                ) {
                    Ok(entry) => output.entries.push(entry),
                    Err(error) => output.fail(Source::Systemd, scope, error),
                }
            }
        }
        Err(error) => output.fail(Source::Systemd, scope, error),
    }
}

pub fn collect(options: &Options) -> CollectorOutput {
    let mut output = CollectorOutput::default();
    let live_dbus = options.root == Path::new("/") && !options.offline;
    let mut runtime_warnings = BTreeSet::new();

    if options.scope.includes_system() {
        let runtime = live_dbus
            .then(|| runtime_state(Scope::System))
            .transpose()
            .unwrap_or_else(|error| {
                runtime_warnings.insert(error);
                None
            });
        collect_scope(
            &mut output,
            options,
            Scope::System,
            "root",
            system_directories(&options.root),
            runtime.as_ref(),
        );
    }
    if options.scope.includes_user() {
        let runtime = live_dbus
            .then(|| runtime_state(Scope::User))
            .transpose()
            .unwrap_or_else(|error| {
                runtime_warnings.insert(error);
                None
            });
        let homes = user_homes(&options.root, &mut output, Source::Systemd);
        if homes.is_empty() {
            output.covered(Source::Systemd, Scope::User);
        }
        for (owner, home) in homes {
            collect_scope(
                &mut output,
                options,
                Scope::User,
                &owner,
                user_directories(&options.root, &home),
                runtime.as_ref(),
            );
        }
    }
    output.warnings.extend(
        runtime_warnings
            .into_iter()
            .map(|warning| format!("{warning}; using static systemd evidence for this audit")),
    );
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::ScopeSelection;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn parses_service_dropins_and_static_enablement() {
        let root = std::env::temp_dir().join(format!(
            "sentinel-systemd-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let units = root.join("etc/systemd/system");
        fs::create_dir_all(units.join("demo.service.d")).unwrap();
        fs::create_dir_all(units.join("multi-user.target.wants")).unwrap();
        fs::write(
            units.join("demo.service"),
            "[Service]\nExecStart=/usr/bin/old\n",
        )
        .unwrap();
        fs::write(
            units.join("demo.service.d/override.conf"),
            "[Service]\nExecStart=\nExecStart=/tmp/new\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../demo.service",
            units.join("multi-user.target.wants/demo.service"),
        )
        .unwrap();
        let output = collect(&Options {
            root: root.clone(),
            scope: ScopeSelection::System,
            offline: true,
        });
        assert_eq!(output.entries.len(), 1);
        assert_eq!(output.entries[0].command, "/tmp/new");
        assert_eq!(output.entries[0].enabled, Some(true));
        assert_eq!(output.entries[0].risk, super::super::model::Risk::High);
        let hash = output.entries[0].config_sha256.clone();
        fs::write(
            units.join("demo.service"),
            "# changed comment\n[Service]\nExecStart=/usr/bin/old\n",
        )
        .unwrap();
        let rescanned = collect(&Options {
            root: root.clone(),
            scope: ScopeSelection::System,
            offline: true,
        });
        assert_eq!(rescanned.entries[0].config_sha256, hash);
        fs::remove_dir_all(root).unwrap();
    }
}
