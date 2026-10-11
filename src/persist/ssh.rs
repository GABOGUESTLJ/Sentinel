use super::{
    collect::{Options, display_origin, read_text, rooted, user_homes},
    model::{CollectorOutput, EntrySpec, Evidence, PersistenceEntry, Scope, Source},
};
use crate::hash_files;
use std::path::Path;

fn key_index(fields: &[&str]) -> Option<usize> {
    fields.iter().position(|field| {
        field.starts_with("ssh-")
            || field.starts_with("ecdsa-")
            || field.starts_with("sk-ssh-")
            || field.starts_with("sk-ecdsa-")
    })
}

fn forced_command(options: &str) -> Option<String> {
    let start = options.find("command=\"")? + "command=\"".len();
    let rest = &options[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

fn parse_line(
    root: &Path,
    path: &Path,
    line_number: usize,
    line: &str,
    scope: Scope,
    owner: &str,
) -> Option<PersistenceEntry> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let fields: Vec<&str> = trimmed.split_whitespace().collect();
    let index = key_index(&fields)?;
    let key_data = *fields.get(index + 1)?;
    let options = fields[..index].join(" ");
    let fingerprint = hex::encode(hash_files::hash_bytes(key_data.as_bytes()));
    let command = forced_command(&options)
        .unwrap_or_else(|| format!("authorize {} SHA256:{}", fields[index], &fingerprint[..16]));
    let semantic = format!("{}\0{}\0{}", options, fields[index], key_data);
    let origin = display_origin(root, path);
    Some(PersistenceEntry::new(EntrySpec {
        source: Source::Ssh,
        scope,
        owner,
        locator: &fingerprint,
        origins: vec![origin],
        location_hint: Some(format!("line {line_number}")),
        trigger: "SSH authentication".into(),
        command,
        enabled: Some(true),
        active: None,
        evidence: Evidence::Static,
        semantic_config: semantic.as_bytes(),
    }))
}

fn collect_home(
    output: &mut CollectorOutput,
    root: &Path,
    home: &Path,
    owner: &str,
    scope: Scope,
) -> Result<(), String> {
    let path = home.join(".ssh/authorized_keys");
    if !path.exists() {
        return Ok(());
    }
    let text = read_text(&path)?;
    output.entries.extend(
        text.lines()
            .enumerate()
            .filter_map(|(index, line)| parse_line(root, &path, index + 1, line, scope, owner)),
    );
    Ok(())
}

pub fn collect(options: &Options) -> CollectorOutput {
    let mut output = CollectorOutput::default();
    if options.scope.includes_system() {
        output.covered(Source::Ssh, Scope::System);
        let root_home = rooted(&options.root, "/root");
        if let Err(error) = collect_home(
            &mut output,
            &options.root,
            &root_home,
            "root",
            Scope::System,
        ) {
            output.fail(Source::Ssh, Scope::System, error);
        }
    }
    if options.scope.includes_user() {
        output.covered(Source::Ssh, Scope::User);
        for (owner, home) in user_homes(&options.root) {
            if owner == "root" {
                continue;
            }
            if let Err(error) = collect_home(&mut output, &options.root, &home, &owner, Scope::User)
            {
                output.fail(Source::Ssh, Scope::User, error);
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_and_forced_command_without_storing_comment() {
        let entry = parse_line(
            Path::new("/sandbox"),
            Path::new("/sandbox/home/alice/.ssh/authorized_keys"),
            1,
            "command=\"/tmp/persist\",no-pty ssh-ed25519 AAAATEST alice@host",
            Scope::User,
            "alice",
        )
        .unwrap();
        assert_eq!(entry.command, "/tmp/persist");
        assert_eq!(entry.risk, super::super::model::Risk::High);
        assert!(!entry.config_sha256.contains("alice@host"));
    }
}
