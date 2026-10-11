use super::{
    collect::{Options, display_origin, read_text, regular_files, rooted},
    model::{CollectorOutput, EntrySpec, Evidence, PersistenceEntry, Scope, Source},
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

fn parse_line(
    root: &Path,
    path: &Path,
    line_number: usize,
    line: &str,
    scope: Scope,
    default_owner: &str,
    system_format: bool,
) -> Option<PersistenceEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let first = trimmed.split_whitespace().next()?;
    if first.contains('=') {
        return None;
    }

    let (trigger, owner, command) = if first.starts_with('@') {
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        let command_index = if system_format { 2 } else { 1 };
        if fields.len() <= command_index {
            return None;
        }
        let trigger = fields[0].to_owned();
        let owner = if system_format {
            fields[1].to_owned()
        } else {
            default_owner.to_owned()
        };
        let command = fields[command_index..].join(" ");
        (trigger, owner, command)
    } else {
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        let command_index = if system_format { 6 } else { 5 };
        if fields.len() <= command_index {
            return None;
        }
        let trigger = fields[..5].join(" ");
        let owner = if system_format {
            fields[5].to_owned()
        } else {
            default_owner.to_owned()
        };
        let command = fields[command_index..].join(" ");
        (trigger, owner, command)
    };
    let origin = display_origin(root, path);
    let locator = format!("{origin}\0{trigger}\0{command}");
    Some(PersistenceEntry::new(EntrySpec {
        source: Source::Cron,
        scope,
        owner: &owner,
        locator: &locator,
        origins: vec![origin],
        location_hint: Some(format!("line {line_number}")),
        trigger,
        command,
        enabled: Some(true),
        active: None,
        evidence: Evidence::Static,
        semantic_config: trimmed.as_bytes(),
    }))
}

fn collect_file(
    output: &mut CollectorOutput,
    root: &Path,
    path: &Path,
    scope: Scope,
    owner: &str,
    system_format: bool,
) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let text = read_text(path)?;
    let mut occurrences = BTreeMap::<String, u32>::new();
    for mut entry in text.lines().enumerate().filter_map(|(index, line)| {
        parse_line(root, path, index + 1, line, scope, owner, system_format)
    }) {
        let occurrence = occurrences.entry(entry.id.clone()).or_default();
        if *occurrence > 0 {
            let identity = format!("{}\0{}", entry.id, occurrence);
            entry.id = hex::encode(crate::hash_files::hash_bytes(identity.as_bytes()));
        }
        *occurrence = occurrence.saturating_add(1);
        output.entries.push(entry);
    }
    Ok(())
}

fn collect_periodic(
    output: &mut CollectorOutput,
    root: &Path,
    directory: &Path,
    trigger: &str,
) -> Result<(), String> {
    for path in regular_files(directory)? {
        let origin = display_origin(root, &path);
        let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        output.entries.push(PersistenceEntry::new(EntrySpec {
            source: Source::Cron,
            scope: Scope::System,
            owner: "root",
            locator: &origin,
            origins: vec![origin.clone()],
            location_hint: None,
            trigger: trigger.into(),
            command: origin.clone(),
            enabled: Some(true),
            active: None,
            evidence: Evidence::Static,
            semantic_config: &bytes,
        }));
    }
    Ok(())
}

fn system_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = vec![rooted(root, "/etc/crontab")];
    files.extend(regular_files(&rooted(root, "/etc/cron.d"))?);
    Ok(files)
}

pub fn collect(options: &Options) -> CollectorOutput {
    let mut output = CollectorOutput::default();
    if options.scope.includes_system() {
        output.covered(Source::Cron, Scope::System);
        let result = (|| -> Result<(), String> {
            for path in system_files(&options.root)? {
                collect_file(
                    &mut output,
                    &options.root,
                    &path,
                    Scope::System,
                    "root",
                    true,
                )?;
            }
            for (directory, trigger) in [
                ("/etc/cron.hourly", "hourly"),
                ("/etc/cron.daily", "daily"),
                ("/etc/cron.weekly", "weekly"),
                ("/etc/cron.monthly", "monthly"),
            ] {
                collect_periodic(
                    &mut output,
                    &options.root,
                    &rooted(&options.root, directory),
                    trigger,
                )?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            output.fail(Source::Cron, Scope::System, error);
        }
    }

    if options.scope.includes_user() {
        output.covered(Source::Cron, Scope::User);
        for spool in ["/var/spool/cron", "/var/spool/cron/crontabs"] {
            let directory = rooted(&options.root, spool);
            match regular_files(&directory) {
                Ok(files) => {
                    for path in files {
                        let owner = path
                            .file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "unknown".into());
                        if let Err(error) = collect_file(
                            &mut output,
                            &options.root,
                            &path,
                            Scope::User,
                            &owner,
                            false,
                        ) {
                            output.fail(Source::Cron, Scope::User, error);
                        }
                    }
                }
                Err(error) => output.fail(Source::Cron, Scope::User, error),
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_system_and_user_cron_without_environment_lines() {
        let root = Path::new("/sandbox");
        let system = parse_line(
            root,
            Path::new("/sandbox/etc/crontab"),
            2,
            "@reboot root /tmp/start",
            Scope::System,
            "root",
            true,
        )
        .unwrap();
        assert_eq!(system.trigger, "@reboot");
        assert_eq!(system.command, "/tmp/start");
        assert_eq!(system.risk, super::super::model::Risk::High);
        assert!(
            parse_line(
                root,
                Path::new("/sandbox/spool/gabo"),
                1,
                "SHELL=/bin/bash",
                Scope::User,
                "gabo",
                false,
            )
            .is_none()
        );
    }

    #[test]
    fn line_numbers_are_evidence_not_identity() {
        let root = Path::new("/sandbox");
        let first = parse_line(
            root,
            Path::new("/sandbox/etc/crontab"),
            1,
            "@reboot root /usr/bin/job",
            Scope::System,
            "root",
            true,
        )
        .unwrap();
        let shifted = parse_line(
            root,
            Path::new("/sandbox/etc/crontab"),
            20,
            "@reboot root /usr/bin/job",
            Scope::System,
            "root",
            true,
        )
        .unwrap();
        assert_eq!(first.id, shifted.id);
        assert_ne!(first.location_hint, shifted.location_hint);
    }

    #[test]
    fn identical_cron_entries_keep_distinct_deterministic_identities() {
        let root = std::env::temp_dir().join(format!(
            "sentinel-cron-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("crontab");
        std::fs::write(
            &path,
            "@reboot root /usr/bin/job\n@reboot root /usr/bin/job\n",
        )
        .unwrap();
        let mut output = CollectorOutput::default();
        collect_file(&mut output, &root, &path, Scope::System, "root", true).unwrap();
        assert_eq!(output.entries.len(), 2);
        assert_ne!(output.entries[0].id, output.entries[1].id);
        std::fs::remove_dir_all(root).unwrap();
    }
}
