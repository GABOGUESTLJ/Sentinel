use super::{
    collect::{Options, display_origin, read_text, regular_files, rooted, user_homes},
    model::{CollectorOutput, EntrySpec, Evidence, PersistenceEntry, Scope, Source},
};
use std::{collections::BTreeMap, path::Path};

fn parse_desktop(
    root: &Path,
    path: &Path,
    scope: Scope,
    owner: &str,
) -> Result<Option<PersistenceEntry>, String> {
    let text = read_text(path)?;
    let mut in_desktop_entry = false;
    let mut values = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            in_desktop_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_desktop_entry || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key.trim(), value.trim());
        }
    }
    if values.get("Type").copied().unwrap_or("Application") != "Application" {
        return Ok(None);
    }
    let Some(command) = values.get("Exec") else {
        return Ok(None);
    };
    let enabled = !values
        .get("Hidden")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        && !values
            .get("X-GNOME-Autostart-enabled")
            .is_some_and(|value| value.eq_ignore_ascii_case("false"));
    let origin = display_origin(root, path);
    let locator = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| origin.clone());
    let semantic = format!(
        "Exec={}\0Hidden={}\0Enabled={}",
        command,
        values.get("Hidden").copied().unwrap_or("false"),
        values
            .get("X-GNOME-Autostart-enabled")
            .copied()
            .unwrap_or("true")
    );
    Ok(Some(PersistenceEntry::new(EntrySpec {
        source: Source::Xdg,
        scope,
        owner,
        locator: &locator,
        origins: vec![origin],
        location_hint: None,
        trigger: "desktop login".into(),
        command: (*command).into(),
        enabled: Some(enabled),
        active: None,
        evidence: Evidence::Static,
        semantic_config: semantic.as_bytes(),
    })))
}

fn collect_directory(
    output: &mut CollectorOutput,
    root: &Path,
    directory: &Path,
    scope: Scope,
    owner: &str,
) -> Result<(), String> {
    let files = regular_files(directory)?;
    output.inspected(Source::Xdg, scope, owner, directory);
    for path in files {
        if path
            .extension()
            .is_none_or(|extension| extension != "desktop")
        {
            continue;
        }
        if let Some(entry) = parse_desktop(root, &path, scope, owner)? {
            output.entries.push(entry);
        }
    }
    Ok(())
}

pub fn collect(options: &Options) -> CollectorOutput {
    let mut output = CollectorOutput::default();
    if options.scope.includes_system() {
        output.covered(Source::Xdg, Scope::System);
        let directory = rooted(&options.root, "/etc/xdg/autostart");
        if let Err(error) = collect_directory(
            &mut output,
            &options.root,
            &directory,
            Scope::System,
            "root",
        ) {
            output.fail(Source::Xdg, Scope::System, error);
        }
    }
    if options.scope.includes_user() {
        output.covered(Source::Xdg, Scope::User);
        for (owner, home) in user_homes(&options.root, &mut output, Source::Xdg) {
            if owner == "root" {
                output.warnings.push("COVERAGE source=xdg scope=user owner=\"root\" status=skipped reason=existing-collector-boundary".into());
                continue;
            }
            if let Err(error) = collect_directory(
                &mut output,
                &options.root,
                &home.join(".config/autostart"),
                Scope::User,
                &owner,
            ) {
                output.fail(Source::Xdg, Scope::User, error);
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn parses_enabled_and_hidden_desktop_entries() {
        let root = std::env::temp_dir().join(format!(
            "sentinel-xdg-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let directory = root.join("etc/xdg/autostart");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("agent.desktop");
        fs::write(
            &path,
            "[Desktop Entry]\nType=Application\nExec=/usr/bin/agent\nHidden=true\n",
        )
        .unwrap();
        let entry = parse_desktop(&root, &path, Scope::System, "root")
            .unwrap()
            .unwrap();
        assert_eq!(entry.enabled, Some(false));
        assert_eq!(entry.command, "/usr/bin/agent");
        fs::remove_dir_all(root).unwrap();
    }
}
