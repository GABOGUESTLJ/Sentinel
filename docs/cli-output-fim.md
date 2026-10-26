# Read FIM results without losing evidence

FIM defaults to concise human output. Detection, baseline acceptance, reconciliation,
and stored history are unchanged. Creation is an event, not a claim of safety.

## Quick path

```sh
sentinel fim --scan ./watched --init-baseline
sentinel fim --scan ./watched
sentinel fim --scan ./watched --history --verbose
```

The startup header identifies the root, entry counts, baseline, history location,
and watcher. Events use `[+] CREATED`, `[~] MODIFIED`, `[-] DELETED`, and
`[↪] RENAMED`. Changed fields come directly from the audit event; rename details
state whether content changed and whether the destination was replaced.

## Choose the console contract

| Option | Contract |
|---|---|
| `--output human` | Default; readable UTC timestamps, actual changed fields, no full hashes or internal IDs unless verbose. |
| `--verbose` | Before, after, baseline, and replaced-destination metadata; full hashes, identities, path bytes, and full paths. |
| `--output json` | Versioned JSON Lines on stdout; full audit events, without the live display cap. Diagnostics remain on stderr. |
| `--output legacy` | Transitional previous normal text and ordering; dangerous external controls are escaped and invalid path bytes remain distinguishable. |
| `--no-color` | Disable color; `NO_COLOR` and redirected output also disable ANSI styling. |

Human and legacy live batches show at most 20 events. A capped batch reports both
detected and shown counts and points to `--history` for the complete record.
History is uncapped and chronological in human/JSON modes; legacy retains its
original ordering. Silent monitoring still records events and reports errors.
Interactive `--silent`, `-d`, and `--desilent` keep their existing behavior.

## Automate with JSON Lines

```sh
sentinel fim --scan ./watched --history --output json > events.jsonl
```

Every line has `schema_version: 1`, `module: "fim"`, `type`, and `data`.
Record types are `initial`, `event`, `summary`, `history`, `baseline`, `export`,
`status`, and `activity`; stderr uses diagnostic types such as `warning` and
`error`. An `event` contains the entire unchanged `AuditEvent`, including
`root_hex`, relative path hex, snapshots, run ID, and sequence. `summary` contains
`detected` and `shown`. Initial metadata includes lossless root/baseline/history
path bytes and entry counts. Baseline records distinguish `created`, `updated`,
and `migrated` actions. Interactive status records contain the `silent` state.

`--format` still controls the exported history file, independently of `--output`,
which controls only the console confirmation. Exported evidence is not wrapped,
styled, or changed by console formatting.

## Path and terminal safety

External control characters and bidirectional controls cannot inject terminal
commands or extra output lines. Invalid UTF-8 paths use explicit hexadecimal
bytes instead of ambiguous replacement characters. Long path tokens remain
complete, even when wider than the terminal. Color applies to fixed event labels,
not filenames. JSON preserves raw values using JSON escaping and lossless hex
identities; consumers should not print decoded external data directly to a terminal.
