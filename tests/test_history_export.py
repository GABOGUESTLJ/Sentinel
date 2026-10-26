"""Public CLI regressions for durable baselines and read-only history exports."""

import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import tempfile
import unittest

from test_runtime import BINARY


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sentinel-evidence-", dir="/tmp/opencode")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "root"
        self.root.mkdir()
        self.legacy = self.base / "legacy"
        self.legacy.mkdir()
        self.env = dict(os.environ, TMPDIR=str(self.legacy),
                        SENTINEL_STATE_DIR=str(self.base / "durable"),
                        XDG_STATE_HOME=str(self.base / "state"),
                        XDG_CONFIG_HOME=str(self.base / "config"))
        self.root_hash = hashlib.sha256(os.fsencode(self.root)).hexdigest()
        self.baseline = self.base / "durable/fim/baselines" / f"{self.root_hash}.json"

    def run_cli(self, tool, *args, code=0, **kwargs):
        root_flag = "--scan" if tool == "fim" else "--root"
        result = subprocess.run([str(BINARY), tool, "--output", "legacy", root_flag, str(self.root), *args],
                                env=self.env, capture_output=True, text=True,
                                timeout=10, **kwargs)
        self.assertEqual(result.returncode, code, result.stderr)
        return result

    def snapshot(self):
        return {str(path.relative_to(self.base)): (path.read_bytes(), path.stat().st_mtime_ns,
                                                   path.stat().st_mode)
                for parent in [self.base / "state", self.base / "config", self.base / "durable"]
                if parent.exists() for path in parent.rglob("*") if path.is_file()}

    def fim_history(self):
        directory = self.base / "state/sentinel/fim" / self.root_hash / "history"
        directory.mkdir(parents=True, mode=0o700)
        path = directory / "run.jsonl"
        events = []
        for sequence, day in enumerate(["2026-01-09", "2026-01-10", "2026-01-11"], 1):
            display = "unsafe ```\n# forged heading\x1b[31m" if sequence == 2 else "normal"
            events.append(dict(schema_version=1, root_hex=os.fsencode(self.root).hex(),
                               run_id="run", sequence=sequence, detected_at=day + "T23:59:59.999999999Z",
                               origin="RECONCILIATION", kind="CREATED", baseline_status="ADDED",
                               previous_path=None, current_path=dict(display=display,
                                                                    hex=os.fsencode(display).hex()),
                               changed_fields=["created"], before=None, after=None, baseline=None,
                               content_changed=None, replaced=False, replaced_before=None))
        path.write_text("".join(json.dumps(event) + "\n" for event in events))
        path.chmod(0o600)
        os.utime(path, (1, 1))  # Export must not apply the normal age-pruning path.
        return path, events

    def test_fim_export_filters_dates_preserves_history_and_escapes_untrusted_paths(self):
        path, events = self.fim_history()
        before = self.snapshot()
        for format_name, suffix in [("markdown", "md"), ("text", "txt")]:
            output = self.base / f"audit.{suffix}"
            result = self.run_cli("fim", "--history", "--export", str(output),
                                  "--format", format_name, "--since", "2026-01-10",
                                  "--until", "2026-01-10", "--history-days", "1")
            text = output.read_text()
            self.assertIn('"sequence": 2', text)
            self.assertNotIn('"sequence": 1', text)
            self.assertNotIn('"sequence": 3', text)
            self.assertIn(events[1]["current_path"]["hex"], text)
            self.assertNotIn("\x1b", text)
            self.assertNotIn("\n# forged heading", text)
            self.assertIn("1 event(s)", result.stdout)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.snapshot(), before)
        self.assertTrue(path.exists())

    def test_export_rejections_leave_sources_and_existing_destination_unchanged(self):
        path, _ = self.fim_history()
        output = self.base / "existing.txt"
        output.write_text("keep me")
        before = self.snapshot()
        self.run_cli("fim", "--history", "--export", str(output), code=1)
        self.assertEqual(output.read_text(), "keep me")
        for flags in [("--since", "2026-02-30"), ("--since", "bad")]:
            self.run_cli("fim", "--history", "--export", str(self.base / "new.md"),
                         *flags, code=2)
        self.run_cli("fim", "--history", "--export", str(self.base / "new.md"),
                     "--since", "2026-01-12", "--until", "2026-01-10", code=1)
        self.run_cli("fim", "--history", "--export", str(path.parent / "new.jsonl"), code=1)
        self.assertFalse((self.base / "new.md").exists())
        self.assertFalse((path.parent / "new.jsonl").exists())
        self.assertEqual(self.snapshot(), before)

    def test_missing_history_export_does_not_create_state_or_keys(self):
        output = self.base / "empty.md"
        self.run_cli("fim", "--history", "--export", str(output))
        self.assertIn("Events: 0", output.read_text())
        self.assertEqual(self.snapshot(), {})

    def test_migration_preserves_signed_bytes_source_and_key_and_refuses_overwrite(self):
        (self.root / "file").write_text("trusted")
        self.run_cli("fim", "--init-baseline")
        signed = self.baseline.read_bytes()
        old = self.legacy / f"fim-baselines-{os.geteuid()}" / self.baseline.name
        old.parent.mkdir(mode=0o700)
        self.baseline.rename(old)
        key = self.base / "config/sentinel/keys/fim-hmac.key"
        key_bytes = key.read_bytes()
        (self.root / "file").write_text("not implicitly trusted")
        self.run_cli("fim", "--migrate-baseline")
        self.assertEqual(self.baseline.read_bytes(), signed)
        self.assertEqual(old.read_bytes(), signed)
        self.assertEqual(key.read_bytes(), key_bytes)
        self.run_cli("fim", "--migrate-baseline", code=1)
        self.assertEqual(self.baseline.read_bytes(), signed)
        self.assertEqual(old.read_bytes(), signed)
        self.baseline.unlink()
        document = json.loads(signed)
        document["payload"]["created_at"] = "tampered"
        old.write_text(json.dumps(document))
        before = old.read_bytes()
        self.run_cli("fim", "--migrate-baseline", code=1)
        self.assertFalse(self.baseline.exists())
        self.assertEqual(old.read_bytes(), before)
        self.assertEqual(key.read_bytes(), key_bytes)

    def test_persist_export_does_not_prune_repair_or_bypass_authentication(self):
        service = self.root / "etc/systemd/system/demo.service"
        service.parent.mkdir(parents=True)
        service.write_text("[Service]\nExecStart=/usr/bin/true\n")
        self.run_cli("persist", "--offline", "--scope", "system", "--init-baseline")
        service.write_text("[Service]\nExecStart=/usr/bin/false\n")
        self.run_cli("persist", "--offline", "--scope", "system", "--check", code=3)
        profile = next((self.base / "state/sentinel/persist").iterdir())
        history = profile / "history.jsonl"
        state = profile / "history-state.json"
        lagging_state = state.read_bytes()
        service.write_text("[Service]\nExecStart=/usr/bin/sleep 1\n")
        self.run_cli("persist", "--offline", "--scope", "system", "--check", code=3)
        state.write_bytes(lagging_state)
        before = self.snapshot()
        output = self.base / "persist.md"
        self.run_cli("persist", "--scope", "system", "--history", "--export", str(output))
        self.assertIn("MODIFIED", output.read_text())
        self.assertEqual(self.snapshot(), before)
        # The lagging state is authenticated; export must not repair it.
        history_bytes = history.read_bytes()
        signed_state = state.read_bytes()
        # A corrupt record must fail without publishing an output or touching sources.
        history.write_bytes(history_bytes.replace(b"MODIFIED", b"REMOVED", 1))
        tampered = self.snapshot()
        self.run_cli("persist", "--scope", "system", "--history", "--export",
                     str(self.base / "invalid.txt"), code=1)
        self.assertFalse((self.base / "invalid.txt").exists())
        self.assertEqual(self.snapshot(), tampered)
        self.assertEqual(state.read_bytes(), signed_state)

    def test_failed_startup_history_write_stops_at_backlog_limit(self):
        for number in range(4097):
            (self.root / str(number)).write_text("x")
        self.run_cli("fim", "--init-baseline")
        for file in self.root.iterdir():
            file.unlink()
        baseline = self.baseline.read_bytes()

        def deny_writes():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (1, 1))

        result = self.run_cli("fim", code=1, preexec_fn=deny_writes)
        self.assertIn("History backlog limit exceeded", result.stderr)
        self.assertIn("monitoring stopped", result.stderr)
        self.assertEqual(self.baseline.read_bytes(), baseline)


if __name__ == "__main__":
    unittest.main()
