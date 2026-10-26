use crate::{hash_files, read_files::Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Source {
    Systemd,
    Cron,
    Ssh,
    Xdg,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::Cron => "cron",
            Self::Ssh => "ssh",
            Self::Xdg => "xdg",
        }
    }

    pub const ALL: [Self; 4] = [Self::Systemd, Self::Cron, Self::Ssh, Self::Xdg];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Scope {
    User,
    System,
}

impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::System => "system",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Evidence {
    Static,
    Effective,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl Risk {
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Coverage {
    pub source: Source,
    pub scope: Scope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistenceEntry {
    pub id: String,
    pub source: Source,
    pub scope: Scope,
    pub owner: String,
    pub origins: Vec<String>,
    #[serde(default)]
    pub location_hint: Option<String>,
    pub trigger: String,
    pub command: String,
    pub enabled: Option<bool>,
    pub active: Option<bool>,
    pub evidence: Evidence,
    pub config_sha256: String,
    pub risk: Risk,
    pub risk_reasons: Vec<String>,
}

pub struct EntrySpec<'a> {
    pub source: Source,
    pub scope: Scope,
    pub owner: &'a str,
    pub locator: &'a str,
    pub origins: Vec<String>,
    pub location_hint: Option<String>,
    pub trigger: String,
    pub command: String,
    pub enabled: Option<bool>,
    pub active: Option<bool>,
    pub evidence: Evidence,
    pub semantic_config: &'a [u8],
}

impl PersistenceEntry {
    pub fn new(spec: EntrySpec<'_>) -> Self {
        let owner = spec.owner.to_owned();
        let identity = format!(
            "{}\0{}\0{}\0{}",
            spec.source.label(),
            spec.scope.label(),
            owner,
            spec.locator
        );
        let mut entry = Self {
            id: hex::encode(hash_files::hash_bytes(identity.as_bytes())),
            source: spec.source,
            scope: spec.scope,
            owner,
            origins: spec.origins,
            location_hint: spec.location_hint,
            trigger: spec.trigger,
            command: spec.command,
            enabled: spec.enabled,
            active: spec.active,
            evidence: spec.evidence,
            config_sha256: hex::encode(hash_files::hash_bytes(spec.semantic_config)),
            risk: Risk::Low,
            risk_reasons: Vec::new(),
        };
        entry.assess_risk();
        entry
    }

    fn assess_risk(&mut self) {
        let command = self.command.to_ascii_lowercase();
        if ["/tmp/", "/var/tmp/", "/dev/shm/", "curl ", "wget "]
            .iter()
            .any(|needle| command.contains(needle))
        {
            self.risk = Risk::High;
            self.risk_reasons
                .push("command references a transient or download location".into());
        }
        if self.scope == Scope::System && command.contains("/home/") {
            self.risk = self.risk.max(Risk::Medium);
            self.risk_reasons
                .push("system mechanism executes content from a user home".into());
        }
        if self.source == Source::Ssh {
            self.risk = self.risk.max(Risk::Medium);
            self.risk_reasons
                .push("SSH authorization grants remote access".into());
        }
        if self.source == Source::Cron && self.trigger == "@reboot" {
            self.risk = self.risk.max(Risk::Medium);
            self.risk_reasons
                .push("cron command runs at system or user startup".into());
        }
        if self.enabled == Some(true) && self.risk == Risk::Low {
            self.risk_reasons
                .push("mechanism is enabled for automatic execution".into());
        }
    }

    pub fn static_fields_equal(&self, other: &Self) -> bool {
        self.source == other.source
            && self.scope == other.scope
            && self.owner == other.owner
            && self.origins == other.origins
            && self.trigger == other.trigger
            && self.command == other.command
            && self.config_sha256 == other.config_sha256
    }
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub observed_at: String,
    pub entries: BTreeMap<String, PersistenceEntry>,
    pub coverage: BTreeSet<Coverage>,
    pub warnings: Vec<String>,
}

impl Snapshot {
    pub fn new() -> Self {
        Self {
            observed_at: Timestamp::now().utc(),
            entries: BTreeMap::new(),
            coverage: BTreeSet::new(),
            warnings: Vec::new(),
        }
    }

    pub fn extend(&mut self, output: CollectorOutput) {
        self.coverage.extend(output.coverage);
        self.warnings.extend(output.warnings);
        for entry in output.entries {
            if self.entries.insert(entry.id.clone(), entry).is_some() {
                self.warnings
                    .push("collector produced a duplicate persistence identity".into());
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct CollectorOutput {
    pub entries: Vec<PersistenceEntry>,
    pub coverage: BTreeSet<Coverage>,
    pub warnings: Vec<String>,
    failed: BTreeSet<Coverage>,
}

impl CollectorOutput {
    pub fn covered(&mut self, source: Source, scope: Scope) {
        let coverage = Coverage { source, scope };
        if !self.failed.contains(&coverage) {
            self.coverage.insert(coverage);
        }
    }

    pub fn fail(&mut self, source: Source, scope: Scope, message: impl Into<String>) {
        let coverage = Coverage { source, scope };
        self.coverage.remove(&coverage);
        self.failed.insert(coverage);
        self.warnings.push(format!(
            "source={} scope={}: {}",
            source.label(),
            scope.label(),
            message.into()
        ));
    }

    pub fn inspected(&mut self, source: Source, scope: Scope, owner: &str, path: &std::path::Path) {
        // Transient report evidence only; never part of the authenticated schema.
        self.warnings.push(format!(
            "COVERAGE source={} scope={} owner={owner:?} status=inspected path={:?}",
            source.label(),
            scope.label(),
            path.to_string_lossy()
        ));
    }
}
