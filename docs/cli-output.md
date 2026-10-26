# Sentinel console output

Human-readable output is the default. Use `--output json` for automation or
`--output legacy` while migrating a consumer of the previous text format.
These options affect presentation, not detection, risk assessment or stored evidence.

## Quick path

```sh
sentinel fim --scan /srv/app
sentinel fim --scan /srv/app --verbose
sentinel persist --offline --scope system --list
sentinel persist --offline --scope system --check --output json
sentinel persist --scope system --history --output legacy
```

Do not initialize or update a baseline merely to change the output format.
Baseline updates explicitly accept the current state as trusted evidence.

## Human output

- FIM uses `[+] CREATED`, `[~] MODIFIED`, `[-] DELETED` and `[↪] RENAMED`.
  Color is limited primarily to these labels; paths remain readable without it.
- Persist defaults to per-source counts, a HIGH/MEDIUM/LOW risk summary and the
  HIGH/MEDIUM findings; `--verbose` shows every entry grouped by source and
  scope, risk-ordered. HIGH is red, MEDIUM is yellow, and LOW is neutral. LOW is
  not a safety verdict.
- Dates identify UTC explicitly. Paths are relative only when their root is known.
- `--verbose` exposes full metadata, identities, hashes and evidence. Paths remain
  safely escaped even in verbose mode.
- A live FIM display limit is distinct from the number of detected events. Use
  history for the complete record; structured output does not apply that limit.
- Empty results and unchanged results do not prove that a system is safe.
  Inspect coverage and diagnostics as well as findings.

Text wraps at whitespace using Unicode display columns when stdout is a terminal.
Unbreakable tokens, including long paths and hashes, remain complete rather than
being truncated or split inside Unicode clusters. The terminal may wrap such a
token itself. Redirected text is not artificially reflowed.

Colors require a compatible terminal on the destination channel. `--no-color`,
`NO_COLOR`, an unknown or dumb terminal, redirection and JSON output disable ANSI.
stdout and stderr capabilities are detected separately.

External terminal controls and bidirectional overrides are escaped. FIM paths use
their original filesystem bytes, not lossy display text; a non-UTF-8 path is shown
as `<path-bytes:HEX>`. Structured FIM records retain the original hex identity.
Persist's existing string-based evidence remains unchanged: this renderer cannot
recover bytes that its model did not preserve.

## JSON Lines contract, version 1

Every emitted application record occupies one line with this envelope:

```json
{"schema_version":1,"module":"fim","type":"event","data":{}}
```

The example shows the envelope only; a real event contains its full domain data.

| Field | Meaning |
| --- | --- |
| `schema_version` | Console envelope version, currently `1` |
| `module` | `fim` or `persist` |
| `type` | Record discriminator, such as `event`, `entry`, a summary or diagnostic |
| `data` | Payload for that record type |

- `event` contains a full existing domain event. Its own `schema_version` is
  independent of the console envelope version.
- Persist `entry` records contain complete normalized inventory entries.
- Status, coverage, summaries and administrative confirmations are records too;
  consumers must select the record types they need rather than treating every
  line as an event. Ignore unknown record types and additive fields.
- `--verbose` does not remove or add technical fields to structured events or
  entries. There are no human display limits, colors, banners or width wrapping.
- Results go to stdout. Operational warnings and errors go to stderr as JSONL;
  application error records use type `error` and `data.message`.
- JSON escaping preserves decoded external values; do not send decoded values
  directly to a terminal without sanitizing them.
- Argument errors and help are owned by Clap and remain ordinary CLI text.
  Invalid usage still exits with code `2`, before any audit is performed.
- FIM is a continuous stream. Process complete lines as they arrive; do not wait
  for a closing JSON array. EOF can also mean interruption, so inspect process
  status and diagnostics rather than assuming a final summary is guaranteed.

The console protocol never serializes HMAC keys or replaces authenticated storage.
Baseline formats, history formats and export document formats are unchanged.

## History export is a separate interface

`--output` selects the console protocol. `--format` continues to select the
exported history document (`markdown` or `text`) and requires `--export`.

```sh
sentinel fim --scan /srv/app --history \
  --export /safe/destination/history.txt --format text --output json
```

This creates the same text history export and emits a JSONL console confirmation.
It does not turn the destination file into a console JSONL stream.

## Migration and exit codes

The human layout is not a parsing contract. Existing `grep`/`awk` consumers should
temporarily request `--output legacy`, then migrate to JSONL. Legacy preserves
normal previous text, but dangerous external control characters are escaped;
byte-for-byte compatibility with unsafe terminal output is intentionally not provided.

Exit codes retain their existing meaning: `0` success, `1` operational failure,
`2` invalid CLI usage; Persist additionally uses `3` changes, `4` an after-state
high-risk change and `5` incomplete check coverage. Presentation does not change
the precedence of these statuses. A removed HIGH entry can be reported without
causing code `4`, because that code examines the after-state. An incomplete list
still retains the existing list exit behavior; check coverage records and warnings.

See [FIM output](cli-output-fim.md) and [Persist output](cli-output-persist.md)
for module-specific details.

## Verification

```sh
cargo test --offline --locked
cargo build --offline --locked
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Integration fixtures use isolated roots and state directories. Output tests cover
real pseudo-terminals and pipes, not a live-host persistence audit.
