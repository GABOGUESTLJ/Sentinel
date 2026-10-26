# Read a Persist audit

Persist defaults to human-readable output. Use an isolated audit root for offline inspection; output mode never changes collection, risk, baseline schemas, or exit codes.

## Quick path

```sh
sentinel persist --root /path/to/root --offline --scope all --list
sentinel persist --root /path/to/root --offline --scope all --init-baseline
sentinel persist --root /path/to/root --offline --scope all --check
```

Inventory reports the audited root, requested scope, per-source counts and a HIGH/MEDIUM/LOW risk summary. The default view then lists only HIGH and MEDIUM findings, each with its identity, state and recorded reasons, followed by the total and an explicit pointer to the complete inventory. LOW entries are counted but not printed by default; LOW is neutral, not a safety verdict.

The default list highlights at most 40 findings, HIGH first. When more exist it prints the first 40 and an explicit `... N more findings not shown; the audit keeps all of them` line. Nothing is discarded: `--verbose` prints every entry grouped by source and scope with owner, state, trigger, command, reasons and full evidence, and `--output json` emits every record. Those modes have no display cap.

`Status` reports recorded enablement; for systemd entries `Active` reports runtime activity when observed. `Active: unknown` means the audit did not observe it, and a disabled unit is not thereby proven inactive.

Checks show added, removed, modified, enabled, disabled, and risk-change events. Each event prints the entry identity once, its current state, and before/after values for changed fields; a risk change reads as `LOW → HIGH` and a changed command as `before → after`. Internal field tokens are humanized, and the generic `entry` token is omitted from the changed list. Configuration hashes and internal IDs are hidden by default, except explicitly labeled identity fallbacks. `--verbose` includes every entry field, both event sides, and per-path coverage visits.

`--init-baseline` confirms creation; `--update-baseline` explicitly confirms updating. Neither accepts incomplete coverage. No-change output reports only that no persistence changes were detected.

## Output contracts

| Mode | Contract |
|---|---|
| `--output human` | Default; per-source and risk summary with HIGH/MEDIUM findings, UTC timestamps and change indicators; `--verbose` adds the grouped full inventory |
| `--output json` | Versioned JSON Lines; raw full entries and events, unaffected by `--verbose` |
| `--output legacy` | Transitional original text and ordering, with dangerous external controls escaped |

JSON lines contain `schema_version: 1`, `module: "persist"`, `type`, and `data`. Types include `entry` (full `PersistenceEntry`), `event` (full `PersistEvent`), `inventory_summary`, `check_summary`, `changes_summary`, `history_summary`, `baseline`, `coverage`, and `export`. Inventory/check summaries include observation time, total entries, scope, category counts, covered pairs and missing pairs. Coverage evidence uses a `message` field. Warnings are JSON records on stderr, never mixed into stdout records.

`--history` sorts chronologically with stable ordering for equal timestamps in human and JSON modes. Legacy retains stored order. `--history --export PATH` and `--format` retain the existing export document format; only the console confirmation follows output mode.

## Coverage and status

Coverage results go to stdout; audit warnings and errors go to stderr. In `--list`, incomplete source/scope pairs appear after the findings summary; in checks they appear before the report. `--verbose` adds the bounded per-path visits and the discovery population note. A missing source/scope pair is not a successful empty audit. Missing pairs remain visible even when no entries were collected. Inspected paths describe bounded discovery, not account-wide discovery.

| Check result | Exit code |
|---|---|
| No changes | 0 |
| Changes without HIGH after-entries | 3 |
| At least one HIGH after-entry | 4 |
| Incomplete coverage | 5 (takes priority) |

List retains exit 0 for incomplete coverage. A removed HIGH entry counts as a high-risk entry involved, but not as a high-risk entry in the current state for the check exit criterion. Baseline acceptance errors retain exit 1.

Colors are labels only, disabled for redirected output, `NO_COLOR`, and `--no-color`. External controls are escaped in text modes. Narrow layouts wrap at whitespace without truncating long tokens. JSON preserves raw values through JSON escaping.

Baseline/export confirmations include hexadecimal `path_bytes`/`destination_bytes`; their text path field is null for non-UTF-8 paths. Collected entry origins and owners retain the collector's existing string representation: bytes already replaced during collection cannot be recovered by presentation.
