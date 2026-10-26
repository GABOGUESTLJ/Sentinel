"""Offline public CLI regressions for bounded persistence coverage."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_runtime import BINARY


class PersistCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="persist-coverage-", dir="/tmp/opencode"
        )
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "root"
        self.root.mkdir()
        self.state = self.base / "state"
        self.config = self.base / "config"
        self.env = dict(
            os.environ,
            SENTINEL_STATE_DIR=str(self.state),
            XDG_STATE_HOME=str(self.state),
            XDG_CONFIG_HOME=str(self.config),
            TMPDIR=str(self.base),
        )
        for owner in ("alice", "zoe"):
            (self.root / "home" / owner).mkdir(parents=True)

    def run_cli(self, *args, code=0):
        result = subprocess.run(
            [str(BINARY), "persist", "--output", "legacy", "--root", str(self.root), "--offline", *args],
            env=self.env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertNotIn("panicked", result.stderr)
        return result

    def saved_files(self):
        """Capture all public state artifacts without depending on their schema."""
        return {
            str(path.relative_to(self.base)): (path.read_bytes(), path.stat().st_mtime_ns)
            for directory in (self.state, self.config)
            if directory.exists()
            for path in directory.rglob("*") if path.is_file()
        }

    def service(self, owner, content):
        path = self.root / "home" / owner / ".config/systemd/user/demo.service"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_failed_home_stays_incomplete_after_later_success(self):
        bad = self.service("alice", b"[Service]\nExecStart=/usr/bin/agent\n")
        self.service("zoe", b"[Service]\nExecStart=/usr/bin/neighbor\n")
        self.run_cli("--scope", "user", "--init-baseline")
        before = self.saved_files()
        bad.write_bytes(b"\xff")

        checked = self.run_cli("--scope", "user", "--check", code=5)
        self.assertIn("COVERAGE source=systemd scope=user status=incomplete\n", checked.stdout)
        self.assertIn("No persistence changes detected.\n", checked.stdout)
        self.assertNotIn("REMOVED", checked.stdout)
        self.assertIn("demo.service", checked.stderr)
        self.assertIn("systemd:user", checked.stderr)
        self.assertEqual(self.saved_files(), before)

        rejected = self.run_cli("--scope", "user", "--update-baseline", code=1)
        self.assertIn("Incomplete persistence audit; baseline was not changed.", rejected.stderr)
        self.assertIn("Missing coverage: systemd:user", rejected.stderr)
        self.assertEqual(self.saved_files(), before)

    def test_failed_enumeration_is_not_a_successful_empty_inventory(self):
        # ENOTDIR is deterministic even when the test runner is privileged.
        self.root.joinpath("home").rename(self.root / "unused-homes")
        self.root.joinpath("home").write_text("not a directory")
        before = self.saved_files()
        rejected = self.run_cli("--scope", "user", "--init-baseline", code=1)
        self.assertEqual(rejected.stdout.count("status=incomplete\n"), 3)
        for source in ("systemd", "ssh", "xdg"):
            self.assertIn(f"COVERAGE source={source} scope=user status=incomplete\n", rejected.stdout)
            self.assertIn(f"{source}:user", rejected.stderr)
        self.assertIn("/home", rejected.stderr)
        self.assertEqual(self.saved_files(), before)

    def test_source_lookup_errors_are_not_missing_files(self):
        for source, relative in (
            ("ssh", ".ssh"),
            ("xdg", ".config"),
            ("systemd", ".config"),
        ):
            with self.subTest(source=source):
                obstacle = self.root / "home/alice" / relative
                if not obstacle.exists():
                    obstacle.write_text("not a directory")
                before = self.saved_files()
                rejected = self.run_cli("--scope", "user", "--init-baseline", code=1)
                self.assertIn(f"{source}:user", rejected.stderr)
                self.assertIn("Not a directory", rejected.stderr)
                self.assertEqual(self.saved_files(), before)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses fixture permissions")
    def test_permission_denied_is_reported_and_rejects_acceptance(self):
        home = self.root / "home/alice"
        home.chmod(0)
        self.addCleanup(home.chmod, 0o700)
        before = self.saved_files()
        rejected = self.run_cli("--scope", "user", "--init-baseline", code=1)
        self.assertIn("Permission denied", rejected.stderr)
        for source in ("systemd", "ssh", "xdg"):
            self.assertIn(f"{source}:user", rejected.stderr)
        self.assertEqual(self.saved_files(), before)

    def test_empty_known_homes_are_visible_without_claiming_all_accounts(self):
        (self.root / "root").mkdir()
        result = self.run_cli("--scope", "user", "--list")
        self.assertEqual(result.stderr, "")
        self.assertIn("PERSISTENCE INVENTORY entries=0 coverage=4 warnings=0\n", result.stdout)
        self.assertIn("no account-wide discovery", result.stdout)
        for owner in ("alice", "zoe"):
            self.assertIn(f'COVERAGE source=ssh scope=user owner="{owner}" status=inspected', result.stdout)
            self.assertIn(f'COVERAGE source=xdg scope=user owner="{owner}" status=inspected', result.stdout)
        self.assertIn('source=ssh scope=user owner="root" status=skipped', result.stdout)
        self.assertIn("COVERAGE source=ssh scope=system status=skipped\n", result.stdout)
        self.assertEqual(self.saved_files(), {})

    def test_complete_inventory_and_unchanged_check_preserve_previous_behavior(self):
        self.service("alice", b"[Service]\nExecStart=/usr/bin/agent\n")
        listed = self.run_cli("--scope", "all", "--list", "--verbose")
        self.assertEqual(listed.stderr, "")
        self.assertIn("PERSISTENCE INVENTORY entries=1 coverage=8 warnings=0\n", listed.stdout)
        self.assertIn("command=\"/usr/bin/agent\"", listed.stdout)
        self.assertEqual(self.saved_files(), {})
        self.run_cli("--scope", "all", "--init-baseline")
        before = self.saved_files()
        checked = self.run_cli("--scope", "all", "--check")
        self.assertEqual(checked.stderr, "")
        self.assertTrue(checked.stdout.endswith("No persistence changes detected.\n"))
        self.assertEqual(self.saved_files(), before)


if __name__ == "__main__":
    unittest.main()
