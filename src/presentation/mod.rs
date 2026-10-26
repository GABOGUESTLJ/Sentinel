//! Console policy only; persisted evidence and detection stay in their domains.

use std::{
    io::{self, IsTerminal, Write},
    path::Path,
};
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    Human,
    Json,
    Legacy,
}

#[derive(Debug, Clone, clap::Args)]
pub struct Args {
    /// Console output: human, versioned JSON Lines, or transitional legacy text.
    #[arg(long, value_enum, default_value = "human")]
    pub output: Mode,
    /// Disable colors, including on terminals (also respects NO_COLOR).
    #[arg(long)]
    pub no_color: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum Style {
    Green,
    Yellow,
    Red,
    Purple,
    Cyan,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub mode: Mode,
    pub width: Option<usize>,
    pub color: bool,
    pub stderr_color: bool,
}

impl Args {
    pub fn options(&self) -> Options {
        Options::detect(self.output, self.no_color)
    }
}

impl Options {
    pub fn detect(mode: Mode, no_color: bool) -> Self {
        let stdout = io::stdout();
        let stderr = io::stderr();
        let permitted = !no_color
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM").is_ok_and(|term| !term.is_empty() && term != "dumb")
            && mode == Mode::Human;
        Self {
            mode,
            width: if stdout.is_terminal() {
                terminal_size::terminal_size_of(&stdout)
                    .map(|(w, _)| usize::from(w.0))
                    .filter(|&w| w > 0)
            } else {
                None
            },
            color: permitted && stdout.is_terminal(),
            stderr_color: permitted && stderr.is_terminal(),
        }
    }

    #[cfg(test)]
    pub fn plain(mode: Mode) -> Self {
        Self {
            mode,
            width: None,
            color: false,
            stderr_color: false,
        }
    }

    /// Only trusted, fixed labels may receive terminal styling.
    pub fn styled(&self, label: &str, style: Style) -> String {
        if !self.color {
            return label.to_owned();
        }
        let code = match style {
            Style::Green => 32,
            Style::Yellow => 33,
            Style::Red => 31,
            Style::Purple => 35,
            Style::Cyan => 36,
        };
        format!("\x1b[{code}m{label}\x1b[0m")
    }

    /// Text must have its external fields escaped before trusted styles are added.
    /// Explicit line breaks are preserved; each line wraps independently.
    pub fn line_to(&self, out: &mut impl Write, text: &str) -> io::Result<()> {
        let width = (self.mode == Mode::Human).then_some(self.width).flatten();
        for explicit in text.split('\n') {
            for line in wrap(explicit, width) {
                writeln!(out, "{line}")?;
            }
        }
        Ok(())
    }

    pub fn line(&self, text: &str) -> io::Result<()> {
        self.line_to(&mut io::stdout().lock(), text)
    }

    pub fn record(&self, module: &str, kind: &str, data: &impl serde::Serialize) -> io::Result<()> {
        write_json(&mut io::stdout().lock(), module, kind, data)
    }

    pub fn message(
        &self,
        module: &str,
        kind: &str,
        human: &str,
        legacy: &str,
        data: &impl serde::Serialize,
    ) -> io::Result<()> {
        match self.mode {
            Mode::Human => self.line(human),
            Mode::Legacy => self.line(legacy),
            Mode::Json => self.record(module, kind, data),
        }
    }

    pub fn diagnostic(&self, module: &str, kind: &str, message: &str) -> io::Result<()> {
        let mut out = io::stderr().lock();
        if self.mode == Mode::Json {
            write_json(
                &mut out,
                module,
                kind,
                &serde_json::json!({"message":message}),
            )
        } else {
            let label = if self.stderr_color { "\x1b[33m" } else { "" };
            let reset = if self.stderr_color { "\x1b[0m" } else { "" };
            writeln!(out, "{label}{}{reset}", safe(message))
        }
    }
}

pub fn safe(text: &str) -> String {
    let mut result = String::new();
    for c in text.chars() {
        match c {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if needs_escape(c) => {
                use std::fmt::Write as _;
                write!(result, "\\u{{{:x}}}", c as u32).expect("writing to String cannot fail");
            }
            c => result.push(c),
        }
    }
    result
}

fn needs_escape(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

pub fn path(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    match path.to_str() {
        Some(text)
            if !text
                .chars()
                .any(|c| c.is_whitespace() || c == '\\' || c == '"' || c.is_control())
                && safe(text) == text =>
        {
            text.to_owned()
        }
        Some(text) => safe(&format!("{text:?}")),
        None => format!("<path-bytes:{}>", hex::encode(path.as_os_str().as_bytes())),
    }
}

pub fn path_hex(value: &str) -> String {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
    match hex::decode(value) {
        Ok(bytes) => path(Path::new(OsStr::from_bytes(&bytes))),
        Err(_) => format!("<invalid-path-hex:{}>", safe(value)),
    }
}

pub fn date(value: &str) -> String {
    if let Some(utc) = value.strip_suffix('Z') {
        safe(&format!("{} UTC", utc.replace('T', " ")))
    } else {
        safe(value)
    }
}

/// Readable clock time for the human default; `date` keeps full precision.
pub fn date_short(value: &str) -> String {
    let utc = value.strip_suffix('Z').unwrap_or(value);
    let whole = utc.split('.').next().unwrap_or(utc);
    safe(&format!("{} UTC", whole.replace('T', " ")))
}

fn visible_width(text: &str) -> usize {
    // Only our fixed SGR sequences are permitted in formatted text.
    let mut plain = String::new();
    let mut sgr = false;
    for c in text.chars() {
        if c == '\x1b' {
            sgr = true;
        } else if sgr {
            if c == 'm' {
                sgr = false;
            }
        } else {
            plain.push(c);
        }
    }
    plain.width()
}

pub fn wrap(text: &str, width: Option<usize>) -> Vec<String> {
    let Some(width) = width.filter(|&w| w > 0) else {
        return vec![text.to_owned()];
    };
    if visible_width(text) <= width {
        return vec![text.to_owned()];
    }
    // Break only at whitespace: never split UTF-8, grapheme clusters, escapes or
    // path tokens. Oversized tokens remain complete and wrap in the terminal.
    let indent_len = text
        .chars()
        .take_while(|&c| c == ' ')
        .count()
        .min(width / 4);
    let indent = " ".repeat(indent_len);
    let continuation = " ".repeat((indent_len + 2).min(width / 3));
    let mut lines = Vec::new();
    let mut current = indent.clone();
    for word in text.split_whitespace() {
        let separator = if current.trim().is_empty() { "" } else { " " };
        if !current.trim().is_empty()
            && visible_width(&current) + separator.len() + visible_width(word) > width
        {
            lines.push(current);
            current = continuation.clone();
        } else {
            current.push_str(separator);
        }
        current.push_str(word);
    }
    lines.push(current);
    lines
}
pub fn write_json(
    out: &mut impl Write,
    module: &str,
    kind: &str,
    data: &impl serde::Serialize,
) -> io::Result<()> {
    let encoded = serde_json::to_string(
        &serde_json::json!({"schema_version":1,"module":module,"type":kind,"data":data}),
    )?;
    // serde_json escapes JSON controls, but C1 controls and bidi overrides also
    // need escaping when the JSONL stream itself is viewed in a terminal.
    for c in encoded.chars() {
        if needs_escape(c) {
            write!(out, "\\u{:04x}", c as u32)?;
        } else {
            write!(out, "{c}")?;
        }
    }
    writeln!(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    #[test]
    fn external_controls_cannot_create_terminal_commands_or_lines() {
        let escaped = safe("x\x1b[2J\n\r\t\u{202e}y");
        assert!(!escaped.chars().any(char::is_control));
        assert!(!escaped.contains('\u{202e}'));
        assert!(escaped.contains("\\n"));
        assert!(escaped.contains("\\u{1b}"));
    }

    #[test]
    fn filesystem_paths_remain_distinct_even_when_not_utf8() {
        let invalid = Path::new(OsStr::from_bytes(b"file\xff"));
        let valid = Path::new("file�");
        assert_ne!(path(invalid), path(valid));
        assert!(path(invalid).contains("ff"));
        assert_ne!(
            path(Path::new("file\nname")),
            path(Path::new("file\\nname"))
        );
    }

    #[test]
    fn narrow_layout_keeps_all_text_and_uses_unicode_column_width() {
        let lines = wrap("界界 abcd efgh", Some(8));
        assert!(lines.len() > 1);
        assert!(
            lines
                .iter()
                .all(|line| unicode_width::UnicodeWidthStr::width(line.as_str()) <= 8)
        );
        assert_eq!(
            lines.join(" ").split_whitespace().collect::<Vec<_>>(),
            ["界界", "abcd", "efgh"]
        );
        assert_eq!(wrap("unchanged text", None), ["unchanged text"]);
    }

    #[test]
    fn jsonl_is_versioned_and_preserves_raw_values() {
        let mut out = Vec::new();
        write_json(
            &mut out,
            "fim",
            "event",
            &serde_json::json!({"path":"a\n\u{001b}"}),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["data"]["path"], "a\n\u{001b}");
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);
    }

    #[test]
    fn jsonl_escapes_unicode_terminal_controls_without_changing_data() {
        let mut out = Vec::new();
        write_json(&mut out, "persist", "entry", &"a\u{009b}\u{202e}b").unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains('\u{009b}'));
        assert!(!text.contains('\u{202e}'));
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["data"], "a\u{009b}\u{202e}b");
    }

    #[test]
    fn narrow_layout_keeps_explicit_headings_on_their_own_line() {
        let mut p = Options::plain(Mode::Human);
        p.width = Some(12);
        let mut out = Vec::new();
        p.line_to(&mut out, "HEADER\nA longer body").unwrap();
        assert!(String::from_utf8(out).unwrap().starts_with("HEADER\n"));
    }
}
