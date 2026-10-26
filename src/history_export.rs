//! Readable, private derivatives of retained evidence; never a retention operation.

use serde::Serialize;
use std::path::{Path, PathBuf};

type Error = Box<dyn std::error::Error>;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Format {
    Markdown,
    Text,
}

#[derive(Debug)]
pub struct Request {
    pub destination: PathBuf,
    pub format: Format,
    pub since: Option<String>,
    pub until: Option<String>,
}

pub fn parse_day(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
    {
        return Err("Expected a UTC calendar date in YYYY-MM-DD format".into());
    }
    let year: u32 = value[..4].parse().map_err(|_| "Invalid year")?;
    let month: usize = value[5..7].parse().map_err(|_| "Invalid month")?;
    let day: u32 = value[8..].parse().map_err(|_| "Invalid day")?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if year == 0 || !(1..=12).contains(&month) || day == 0 || day > days[month - 1] {
        return Err("Invalid calendar date".into());
    }
    Ok(value.into())
}

impl Request {
    pub fn validate(&self) -> Result<(), Error> {
        for day in [self.since.as_deref(), self.until.as_deref()]
            .into_iter()
            .flatten()
        {
            parse_day(day)?;
        }
        if matches!((&self.since, &self.until), (Some(since), Some(until)) if since > until) {
            return Err("--since must not be later than --until".into());
        }
        Ok(())
    }

    pub fn write<T: Serialize>(
        &self,
        tool: &str,
        events: &[T],
        source: &Path,
    ) -> Result<usize, Error> {
        self.validate()?;
        let destination = if self.destination.is_absolute() {
            self.destination.clone()
        } else {
            std::env::current_dir()?.join(&self.destination)
        };
        let parent = destination
            .parent()
            .ok_or("Export destination has no directory")?
            .canonicalize()?;
        let destination = parent.join(
            destination
                .file_name()
                .ok_or("Export destination has no filename")?,
        );
        // Never add an apparent segment to the evidence store we are exporting.
        let source = if source.try_exists()? {
            source.canonicalize()?
        } else {
            source.to_path_buf()
        };
        if parent.starts_with(&source) {
            return Err("Export destination must be outside the source history directory".into());
        }
        if std::fs::symlink_metadata(&destination).is_ok() {
            return Err("Export destination already exists; refusing to overwrite".into());
        }
        let mut selected = Vec::new();
        for event in events {
            let value = serde_json::to_value(event)?;
            let detected = value
                .get("detected_at")
                .and_then(|v| v.as_str())
                .ok_or("History event has no detection timestamp")?;
            let day = detected.get(..10).ok_or("Invalid history timestamp")?;
            parse_day(day)?;
            if self.since.as_deref().is_some_and(|since| day < since)
                || self.until.as_deref().is_some_and(|until| day > until)
            {
                continue;
            }
            selected.push(serde_json::to_string_pretty(&value)?);
        }
        let markdown = matches!(self.format, Format::Markdown);
        let mut output = format!(
            "{}Sentinel history export\n\nTool: {tool}\nEvents: {}\nSince (UTC, inclusive): {}\nUntil (UTC, inclusive): {}\nEvidence: {}\nExport: human-readable derivative, not an authenticated archive.\n\n",
            if markdown { "# " } else { "" },
            selected.len(),
            self.since.as_deref().unwrap_or("unbounded"),
            self.until.as_deref().unwrap_or("unbounded"),
            if tool == "persist" {
                "HMAC chain verified without repair"
            } else {
                "FIM history is not HMAC authenticated"
            }
        );
        for (index, json) in selected.iter().enumerate() {
            if markdown {
                let longest = json.split(|c| c != '`').map(str::len).max().unwrap_or(0);
                let fence = "`".repeat(3.max(longest + 1));
                output.push_str(&format!(
                    "## Event {}\n\n{fence}json\n{json}\n{fence}\n\n",
                    index + 1
                ));
            } else {
                output.push_str(&format!("Event {}\n{json}\n\n", index + 1));
            }
        }
        crate::private_store::atomic_write(&destination, output.as_bytes(), false)?;
        Ok(selected.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_use_real_utc_calendar_days() {
        for date in ["2024-02-29", "2000-02-29", "2026-12-31"] {
            assert!(parse_day(date).is_ok());
        }
        for date in [
            "2026-02-29",
            "1900-02-29",
            "2026-04-31",
            "0000-01-01",
            "2026-1-01",
            "2026-01-01T00:00:00Z",
        ] {
            assert!(parse_day(date).is_err(), "{date}");
        }
    }
}
