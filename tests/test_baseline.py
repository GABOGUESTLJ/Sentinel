"""Persistent reference, filesystem types, and timestamp regression tests (Unix)."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

from test_runtime import BINARY, Monitor


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fim-baseline-tests-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "watched"
        self.root.mkdir()
        self.state = self.base / "temp-store"
        self.state.mkdir()
        self.env = dict(
            os.environ,
            TMPDIR=str(self.state),
            XDG_STATE_HOME=str(self.base / "xdg-state"),
            XDG_CONFIG_HOME=str(self.base / "xdg-config"),
        )
        key = hashlib.sha256(os.fsencode(self.root.resolve())).hexdigest()
        self.baseline = self.state / f"fim-baselines-{os.geteuid()}" / f"{key}.json"

    def run_cli(self, *args, success=True, env=None):
        result = subprocess.run([str(BINARY), "fim", "-s", str(self.root), *args],
                                env=self.env if env is None else env,
                                capture_output=True, text=True, timeout=5)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(result.stderr)
            self.assertNotIn("panicked", result.stderr)
        return result

    def initialize(self):
        self.run_cli("--init-baseline")

    def start(self, *args):
        monitor = Monitor(self.root, args=args, env=self.env)
        self.addCleanup(monitor.close)
        monitor.expect("Monitoring")
        monitor.expect("INITIAL SCAN")
        return monitor

    def entries(self):
        return {bytes.fromhex(e["path_hex"]): e["info"]
                for e in json.loads(self.baseline.read_text())["payload"]["entries"]}

    def test_missing_baseline_requires_explicit_creation(self):
        error = self.run_cli(success=False)
        self.assertIn("--init-baseline", error.stderr)
        self.assertFalse(self.baseline.exists())

    def test_persists_privately_outside_root_and_never_auto_accepts(self):
        file = self.root / "file"
        file.write_text("trusted")
        self.initialize()
        self.assertFalse(self.baseline.is_relative_to(self.root))
        self.assertEqual(self.baseline.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.baseline.parent.stat().st_mode & 0o777, 0o700)
        original = self.baseline.read_bytes()
        file.write_text("changed while stopped")
        monitor = self.start()
        self.assertIn("baseline=MODIFIED", monitor.expect('MODIFIED "file"'))
        monitor.quiet(1.2)
        file.write_text("changed again")
        monitor.expect('MODIFIED "file"')
        self.assertEqual(self.baseline.read_bytes(), original)
        monitor.process.terminate()
        monitor.process.wait(timeout=3)
        restarted = self.start()
        restarted.expect('MODIFIED "file"')
        self.assertEqual(self.baseline.read_bytes(), original)

    def test_explicit_update_accepts_current_state(self):
        file = self.root / "file"
        file.write_text("old")
        self.initialize()
        original = self.baseline.read_bytes()
        file.write_text("new")
        self.run_cli("--init-baseline", success=False)
        self.assertEqual(self.baseline.read_bytes(), original)
        self.run_cli("--update-baseline")
        self.assertNotEqual(self.baseline.read_bytes(), original)
        self.assertEqual(bytes(self.entries()[b"file"]["hash"]), hashlib.sha256(b"new").digest())
        self.start().quiet(1.2)
        self.assertEqual(list(self.baseline.parent.glob("*.tmp")), [])

    def test_missing_update_and_conflicting_flags_fail(self):
        self.run_cli("--update-baseline", success=False)
        self.run_cli("--init-baseline", "--update-baseline", success=False)
        self.assertFalse(self.baseline.exists())

    def test_deleted_temporary_baseline_requires_new_explicit_creation(self):
        result = self.run_cli("--init-baseline", "--silent")
        self.assertEqual(result.stdout, "")
        self.baseline.unlink()
        self.run_cli(success=False)
        self.assertFalse(self.baseline.exists())

    def test_concurrent_initializers_publish_only_one_reference(self):
        processes = [subprocess.Popen(
            [str(BINARY), "fim", "-s", str(self.root), "--init-baseline"], env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        try:
            for process in processes:
                process.communicate(timeout=5)
            self.assertEqual(sorted(p.returncode for p in processes), [0, 1])
            self.assertEqual(self.entries(), {})
            self.assertEqual(list(self.baseline.parent.glob("*.tmp")), [])
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=3)

    def test_corrupt_baseline_is_not_recreated_or_updated(self):
        self.initialize()
        self.baseline.write_bytes(b"{invalid json")
        for flags in ((), ("--init-baseline",), ("--update-baseline",)):
            with self.subTest(flags=flags):
                self.run_cli(*flags, success=False)
                self.assertEqual(self.baseline.read_bytes(), b"{invalid json")

    def test_hmac_rejects_payload_wrong_key_and_public_key(self):
        (self.root / "file").write_text("trusted")
        self.initialize()
        key = self.base / "xdg-config/sentinel/keys/fim-hmac.key"
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        original_baseline = self.baseline.read_bytes()
        original_key = key.read_bytes()

        document = json.loads(original_baseline)
        document["payload"]["created_at"] = "tampered"
        self.baseline.write_text(json.dumps(document))
        self.assertIn("HMAC verification failed", self.run_cli(success=False).stderr)

        self.baseline.write_bytes(original_baseline)
        key.write_bytes(b"x" * 32)
        self.assertIn("different HMAC key", self.run_cli(success=False).stderr)

        key.write_bytes(original_key)
        key.chmod(0o644)
        self.assertIn("Unsafe HMAC key", self.run_cli(success=False).stderr)

    def test_schema_root_duplicate_paths_and_invalid_entry_rejected(self):
        (self.root / "file").touch()
        self.initialize()
        original = json.loads(self.baseline.read_text())
        variants = []
        for field, value in (("version", 99), ("root_hex", "00"), ("unexpected", 1)):
            doc = copy.deepcopy(original)
            doc["payload"][field] = value
            variants.append(doc)
        doc = copy.deepcopy(original)
        doc["payload"]["entries"].append(doc["payload"]["entries"][0])
        variants.append(doc)
        for path in ("../escape", "/absolute", ""):
            doc = copy.deepcopy(original)
            doc["payload"]["entries"][0]["path_hex"] = path.encode().hex()
            variants.append(doc)
        doc = copy.deepcopy(original)
        doc["payload"]["entries"][0]["info"]["hash"] = None
        variants.append(doc)
        for index, doc in enumerate(variants):
            with self.subTest(index=index):
                self.baseline.write_text(json.dumps(doc))
                self.run_cli(success=False)

    def test_unsafe_storage_and_baseline_rejected(self):
        self.initialize()
        self.baseline.chmod(0o644)
        self.run_cli(success=False)
        self.baseline.chmod(0o600)
        self.baseline.parent.chmod(0o755)
        self.run_cli(success=False)
        self.baseline.parent.chmod(0o700)
        saved = self.state / "saved.json"
        self.baseline.rename(saved)
        self.baseline.symlink_to(saved)
        self.run_cli(success=False)
        self.run_cli("--update-baseline", success=False)

    def test_storage_symlink_is_rejected(self):
        target = self.state / "other"
        target.mkdir(mode=0o700)
        self.baseline.parent.symlink_to(target, target_is_directory=True)
        self.run_cli("--init-baseline", success=False)
        self.assertEqual(list(target.iterdir()), [])

    def test_temp_inside_watched_tree_rejected(self):
        env = dict(self.env, TMPDIR=str(self.root))
        result = self.run_cli("--init-baseline", success=False, env=env)
        self.assertIn("inside the monitored tree", result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_dotfiles_hidden_directories_and_non_utf8_names(self):
        folder = self.root / ".config"
        folder.mkdir()
        file = folder / ".secreto"
        file.write_text("old")
        raw_name = os.fsencode(self.root) + b"/raw-\xff"
        with open(raw_name, "wb") as stream:
            stream.write(b"data")
        self.initialize()
        entries = self.entries()
        self.assertIn(b".config/.secreto", entries)
        self.assertIn(b"raw-\xff", entries)
        monitor = self.start()
        file.write_text("new")
        monitor.expect('MODIFIED ".config/.secreto"')
        with open(raw_name, "wb") as stream:
            stream.write(b"changed")
        monitor.expect("MODIFIED")

    def test_symlink_target_changes_broken_links_and_cycles(self):
        external = self.base / "external"
        external.write_text("outside")
        link = self.root / "link"
        link.symlink_to(external)
        (self.root / "broken").symlink_to("missing")
        (self.root / "cycle").symlink_to(self.root, target_is_directory=True)
        self.initialize()
        entries = self.entries()
        self.assertEqual(entries[b"link"]["kind"], "Symlink")
        self.assertIsNone(entries[b"link"]["hash"])
        self.assertEqual(len(entries), 3)
        monitor = self.start()
        external.write_text("do not follow")
        monitor.quiet(1.2)
        link.unlink()
        link.symlink_to("new-missing-target")
        monitor.expect('MODIFIED "link"')
        link.unlink()
        monitor.expect('DELETED "link"')

    def test_fifo_socket_and_empty_directory_inventory_without_opening(self):
        os.mkfifo(self.root / "pipe")
        sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(sock.close)
        sock.bind(str(self.root / "socket"))
        (self.root / "empty").mkdir()
        self.initialize()
        entries = self.entries()
        self.assertEqual(entries[b"pipe"]["kind"], "Fifo")
        self.assertEqual(entries[b"socket"]["kind"], "Socket")
        self.assertEqual(entries[b"empty"]["kind"], "Directory")
        self.assertTrue(all(entry["hash"] is None for entry in entries.values()))
        monitor = self.start()
        os.chmod(self.root / "pipe", 0o600)
        monitor.expect('MODIFIED "pipe"')
        (self.root / "socket").unlink()
        monitor.expect('DELETED "socket"')
        (self.root / "empty").rmdir()
        monitor.expect('DELETED "empty"')

    def test_type_replacement_is_modified(self):
        file = self.root / "entry"
        file.touch()
        self.initialize()
        monitor = self.start()
        file.unlink()
        os.mkfifo(file)
        monitor.expect('MODIFIED "entry"')

    def test_utc_dates_metadata_changes_and_return_to_baseline(self):
        file = self.root / "file"
        file.write_text("trusted")
        original = file.stat()
        self.initialize()
        monitor = self.start("-v")
        file.write_text("changed")
        line = monitor.expect('MODIFIED "file"')
        self.assertRegex(line, r"detected=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z")
        self.assertRegex(line, r"mtime=\d{4}-\d{2}-\d{2}T")
        monitor.expect("sha256=" + hashlib.sha256(b"trusted").hexdigest())
        file.write_text("trusted")
        os.utime(file, ns=(original.st_atime_ns, original.st_mtime_ns))
        self.assertIn("baseline=COMPLIANT", monitor.expect('MODIFIED "file"'))
        os.chmod(file, 0o600)
        self.assertIn("baseline=MODIFIED", monitor.expect('MODIFIED "file"'))
        file.unlink()
        line = monitor.expect('DELETED "file"')
        self.assertIn("mtime=unavailable", line)
        self.assertIn("baseline=DELETED", line)

    @unittest.skipIf(os.geteuid() == 0, "requires non-root permissions")
    def test_failed_update_keeps_previous_baseline_bytes(self):
        file = self.root / "file"
        file.write_text("trusted")
        self.initialize()
        original = self.baseline.read_bytes()
        file.chmod(0)
        self.addCleanup(file.chmod, 0o600)
        self.run_cli("--update-baseline", success=False)
        self.assertEqual(self.baseline.read_bytes(), original)
        self.assertEqual(list(self.baseline.parent.glob("*.tmp")), [])
