"""Public, cross-module output contracts; fixtures never audit the live host."""

import hashlib
import json
import os
import fcntl
from pathlib import Path
import pty
import select
import struct
import subprocess
import tempfile
import termios
import time
import unittest

from test_runtime import BINARY


class ConsoleContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sentinel-console-", dir="/tmp/opencode")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "root"
        self.root.mkdir()
        self.env = dict(os.environ, HOME=str(self.base / "home"),
                        SENTINEL_STATE_DIR=str(self.base / "durable"),
                        XDG_STATE_HOME=str(self.base / "state"),
                        XDG_CONFIG_HOME=str(self.base / "config"),
                        TMPDIR=str(self.base), TERM="xterm-256color",
                        PYTHONDONTWRITEBYTECODE="1")

    def run_cli(self, tool, *args):
        flag = "--scan" if tool == "fim" else "--root"
        return subprocess.run([str(BINARY), tool, flag, str(self.root), *args],
                              env=self.env, capture_output=True, text=True, timeout=10)

    def records(self, text, module):
        self.assertNotIn("\x1b", text)
        records = [json.loads(line) for line in text.splitlines()]
        for record in records:
            self.assertEqual(record["schema_version"], 1)
            self.assertEqual(record["module"], module)
            self.assertIsInstance(record["type"], str)
            self.assertIn("data", record)
        return records

    def test_help_documents_modes_and_separate_export_format(self):
        for tool in ("fim", "persist"):
            with self.subTest(tool=tool):
                result = self.run_cli(tool, "--help", "--no-color")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("--output", result.stdout)
                self.assertIn("human", result.stdout)
                self.assertIn("legacy", result.stdout)
                self.assertIn("--no-color", result.stdout)
                self.assertIn("--format", result.stdout)
                self.assertNotIn("\x1b", result.stdout + result.stderr)

    def test_invalid_output_and_export_format_leave_state_unchanged(self):
        for tool in ("fim", "persist"):
            action = "--init-baseline" if tool == "fim" else "--list"
            for extra in (("--output", "xml"), ("--format", "json")):
                with self.subTest(tool=tool, extra=extra):
                    result = self.run_cli(tool, action, *extra)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(list(self.base.iterdir()), [self.root])

    def test_operational_errors_are_jsonl_on_stderr_only(self):
        self.root.rmdir()
        for tool in ("fim", "persist"):
            args = ["--output", "json"]
            if tool == "persist":
                args += ["--list", "--offline"]
            result = self.run_cli(tool, *args)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            records = self.records(result.stderr, tool)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["type"], "error")
            self.assertIn("message", records[0]["data"])

    def test_all_modes_keep_persist_signed_evidence_unchanged_when_listing(self):
        service = self.root / "etc/systemd/system/demo.service"
        service.parent.mkdir(parents=True)
        service.write_text("[Service]\nExecStart=/usr/bin/true\n")
        result = self.run_cli("persist", "--offline", "--scope", "system", "--init-baseline")
        self.assertEqual(result.returncode, 0, result.stderr)

        def evidence():
            return {str(path.relative_to(self.base)): (path.read_bytes(), path.stat().st_mtime_ns)
                    for directory in (self.base / "state", self.base / "config")
                    for path in directory.rglob("*") if path.is_file()}

        before = evidence()
        self.assertTrue(before)
        for mode in ("human", "json", "legacy"):
            result = self.run_cli("persist", "--offline", "--scope", "system", "--list",
                                  "--output", mode)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(evidence(), before)
            self.assertNotIn("\x1b", result.stdout + result.stderr)
            if mode == "json":
                records = self.records(result.stdout, "persist")
                self.assertTrue(records)
                self.assertTrue(any(r["type"] == "entry" for r in records))

    def test_json_console_and_text_history_export_are_independent(self):
        root_hash = hashlib.sha256(os.fsencode(self.root)).hexdigest()
        directory = self.base / "state/sentinel/fim" / root_hash / "history"
        directory.mkdir(parents=True, mode=0o700)
        path = directory / "run.jsonl"
        event = dict(schema_version=1, root_hex=os.fsencode(self.root).hex(), run_id="run",
                     sequence=1, detected_at="2026-10-25T23:59:59.000000000Z",
                     origin="RECONCILIATION", kind="CREATED", baseline_status="ADDED",
                     previous_path=None, current_path=dict(display="a", hex="61"),
                     changed_fields=["created"], before=None, after=None, baseline=None,
                     content_changed=None, replaced=False, replaced_before=None)
        path.write_text(json.dumps(event) + "\n")
        path.chmod(0o600)
        before = path.read_bytes()
        output = self.base / "audit.txt"
        result = self.run_cli("fim", "--history", "--export", str(output),
                              "--format", "text", "--output", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.records(result.stdout, "fim"))
        self.assertEqual(path.read_bytes(), before)
        self.assertIn("Events: 1", output.read_text())
        self.assertNotIn('"module":', output.read_text())

    def tty_list(self, width, extra=(), no_color=False):
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, width, 0, 0))
        env = self.env.copy()
        env.pop("NO_COLOR", None)
        if no_color:
            env["NO_COLOR"] = "1"
        process = subprocess.Popen([str(BINARY), "persist", "--root", str(self.root),
                                    "--offline", "--scope", "system", "--list", *extra],
                                   env=env, stdin=subprocess.DEVNULL, stdout=slave,
                                   stderr=subprocess.PIPE)
        os.close(slave)
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        block = os.read(master, 65536)
                    except OSError:
                        break
                    if not block:
                        break
                    output.extend(block)
            else:
                self.fail("terminal subprocess did not finish")
            _, error = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, error)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stderr.close()
            os.close(master)
        return output.decode().replace("\r\n", "\n")

    def test_real_tty_width_color_and_color_opt_out(self):
        service = self.root / "etc/systemd/system/example.service"
        service.parent.mkdir(parents=True)
        service.write_text("[Service]\nExecStart=/tmp/payload\n")
        narrow = self.tty_list(32)
        wide = self.tty_list(120)
        self.assertIn("\x1b[31mHIGH\x1b[0m", narrow)
        self.assertIn("\x1b[31mHIGH\x1b[0m", wide)
        for output in (narrow, wide):
            self.assertIn("transient or download location", " ".join(output.split()))
        verbose = self.tty_list(120, ("--verbose",))
        self.assertIn("/tmp/payload", verbose)
        self.assertNotEqual(narrow, wide)
        for output in (self.tty_list(32, no_color=True), self.tty_list(120, ("--no-color",))):
            self.assertNotIn("\x1b", output)
            self.assertIn("HIGH", output)

    def test_json_tty_stays_unstyled_and_unwrapped(self):
        output = self.tty_list(24, ("--output", "json"))
        self.assertTrue(self.records(output, "persist"))


if __name__ == "__main__":
    unittest.main()
