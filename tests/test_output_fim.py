"""Public FIM presentation contracts; all filesystem fixtures are temporary."""
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import time
import unittest

from test_runtime import BINARY


class OutputFimTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fim-output-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "watched"
        self.root.mkdir()
        self.env = dict(os.environ, HOME=self.temp.name,
                        SENTINEL_STATE_DIR=str(Path(self.temp.name) / "state"),
                        XDG_CONFIG_HOME=str(Path(self.temp.name) / "config"), NO_COLOR="1")

    def cli(self, *args):
        result = subprocess.run([str(BINARY), "fim", "-s", str(self.root), *args],
                                env=self.env, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return result.stdout

    def startup(self, mode="human", verbose=False):
        import threading
        process = subprocess.Popen(
            [str(BINARY), "fim", "-s", str(self.root), "--output", mode,
             *(["--verbose"] if verbose else [])], env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE,
            text=True)
        lines = queue.Queue()
        def read():
            for line in process.stdout:
                lines.put(line)
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        output = []
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    line = lines.get(timeout=0.2)
                except queue.Empty:
                    if process.poll() is not None:
                        break
                    continue
                output.append(line)
                if ('"type":"summary"' in line or "changes detected" in line):
                    break
        finally:
            process.terminate()
            process.wait(timeout=3)
            reader.join(timeout=3)
            error = process.stderr.read()
            process.stdout.close()
            process.stderr.close()
            process.stdin.close()
        self.assertEqual(error, "")
        return "".join(output)

    def test_baseline_modes_and_legacy_confirmation(self):
        created = self.cli("--init-baseline")
        self.assertIn("Baseline created", created)
        updated = self.cli("--update-baseline")
        self.assertIn("Baseline updated", updated)
        record = json.loads(self.cli("--update-baseline", "--output", "json"))
        self.assertEqual((record["schema_version"], record["module"], record["type"]),
                         (1, "fim", "baseline"))
        self.assertEqual(record["data"]["action"], "updated")
        self.assertIn("Baseline saved at ", self.cli("--update-baseline", "--output", "legacy"))

    def test_human_changed_fields_paths_verbose_and_history(self):
        (self.root / "old").write_text("old")
        (self.root / "gone").write_text("gone")
        self.cli("--init-baseline")
        (self.root / "old").write_text("longer content")
        (self.root / "old").chmod(0o700)
        (self.root / "gone").unlink()
        (self.root / "ñ\n\x1b[2J").touch()
        raw = os.fsencode(self.root) + b"/bad\xff"
        with open(raw, "wb") as stream:
            stream.write(b"x")
        human = self.startup(verbose=True)
        for text in ("SENTINEL / FIM", "Root:", "[+] CREATED", "[~] MODIFIED",
                     "[-] DELETED", "content", "size", "mode", "before:",
                     "after:", "baseline:", "run_id", "root_hex", "626164ff"):
            self.assertIn(text, human)
        self.assertNotIn("\x1b", human)
        self.assertIn("\\n", human)
        self.assertIn("UTC", human)
        records = [json.loads(line) for line in self.cli("--history", "--output", "json").splitlines()]
        self.assertEqual(records[0]["type"], "history")
        self.assertEqual(records[-1]["type"], "summary")
        events = [record["data"] for record in records if record["type"] == "event"]
        self.assertEqual(len(events), 4)
        self.assertTrue(any(e["current_path"] and e["current_path"]["hex"] == "626164ff" for e in events))
        self.assertIn("4 changes detected", self.cli("--history"))

    def test_json_is_uncapped_and_human_reports_limit(self):
        self.cli("--init-baseline")
        for number in range(24):
            (self.root / f"item-{number}").touch()
        human = self.startup()
        self.assertEqual(human.count("[+] CREATED"), 20)
        self.assertIn("24 changes detected; 20 shown", human)
        records = [json.loads(line) for line in self.startup("json").splitlines()]
        self.assertEqual(len([r for r in records if r["type"] == "event"]), 24)
        self.assertEqual(records[-1]["data"], {"detected": 24, "shown": 24})
        initial = records[0]["data"]
        self.assertEqual(initial["entries"], 24)
        self.assertEqual(bytes.fromhex(initial["root_hex"]), os.fsencode(self.root))
        event = next(r["data"] for r in records if r["type"] == "event")
        for field in ("before", "after", "baseline", "run_id", "sequence", "root_hex", "changed_fields"):
            self.assertIn(field, event)

    def test_rename_replacement_keeps_content_and_destination_evidence(self):
        source = self.root / "source"
        destination = self.root / "destination"
        source.write_text("original")
        destination.write_text("replaced")
        self.cli("--init-baseline")
        source.replace(destination)
        destination.write_text("changed content")
        human = self.startup(verbose=True)
        for text in ("[↪] RENAMED", "source → destination", "content changed: true",
                     "destination replaced: true", "replaced-before:"):
            self.assertIn(text, human)
        records = [json.loads(line) for line in self.cli("--history", "--output", "json").splitlines()]
        event = next(r["data"] for r in records if r["type"] == "event")
        self.assertEqual(event["kind"], "RENAMED")
        self.assertTrue(event["content_changed"])
        self.assertTrue(event["replaced"])
        self.assertIsNotNone(event["replaced_before"])

    def test_empty_root_with_invalid_bytes_keeps_startup_identity(self):
        self.root = Path(os.fsdecode(os.fsencode(self.root) + b"-\xff\n\x1b[2J"))
        self.root.mkdir()
        self.cli("--init-baseline")
        human = self.startup()
        self.assertIn("<path-bytes:", human)
        self.assertIn("0 changes detected", human)
        self.assertNotIn("\x1b", human)
        records = [json.loads(line) for line in self.startup("json").splitlines()]
        self.assertEqual(bytes.fromhex(records[0]["data"]["root_hex"]), os.fsencode(self.root))
        self.assertEqual(records[-1]["data"], {"detected": 0, "shown": 0})

    def test_json_commands_and_unknown_command_keep_streams_separate(self):
        import threading
        self.cli("--init-baseline")
        process = subprocess.Popen(
            [str(BINARY), "fim", "-s", str(self.root), "--output", "json", "--silent"],
            env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        lines = queue.Queue()
        def read():
            for line in process.stdout:
                lines.put(json.loads(line))
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        try:
            process.stdin.write("unknown\n--silent\n--desilent\n")
            process.stdin.flush()
            silenced = lines.get(timeout=5)
            enabled = lines.get(timeout=5)
            self.assertEqual(silenced["type"], "status")
            self.assertEqual(silenced["data"], {"silent": True})
            self.assertEqual(enabled["data"], {"silent": False})
            self.assertIsNone(process.poll())
        finally:
            process.terminate()
            process.wait(timeout=3)
            reader.join(timeout=3)
            error = process.stderr.read()
            process.stdout.close()
            process.stderr.close()
            process.stdin.close()
        warning = json.loads(error)
        self.assertEqual(warning["type"], "warning")
        self.assertEqual(warning["data"]["message"],
                         "Unknown command. Enter --silent or -d/--desilent.")
