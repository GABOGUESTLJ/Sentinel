"""Sandboxed persistence audit and FIM integration tests (Linux/Unix)."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_runtime import BINARY, Monitor


class PersistTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sentinel-persist-tests-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "audit-root"
        self.state = self.base / "state"
        self.fim_temp = self.base / "fim-temp"
        self.root.mkdir()
        self.state.mkdir()
        self.fim_temp.mkdir()
        self.env = dict(os.environ, XDG_STATE_HOME=str(self.state),
                        XDG_CONFIG_HOME=str(self.base / "config"), TMPDIR=str(self.fim_temp))
        self.service = self.root / "etc/systemd/system/demo.service"
        self.service.parent.mkdir(parents=True)
        self.service.write_text("[Service]\nExecStart=/usr/bin/trusted-agent\n")
        wants = self.service.parent / "multi-user.target.wants"
        wants.mkdir()
        (wants / "demo.service").symlink_to("../demo.service")

        cron = self.root / "etc/cron.d"
        cron.mkdir(parents=True)
        (cron / "backup").write_text("0 3 * * * root /usr/bin/backup\n")

        autostart = self.root / "home/alice/.config/autostart"
        autostart.mkdir(parents=True)
        self.desktop = autostart / "agent.desktop"
        self.desktop.write_text(
            "[Desktop Entry]\nType=Application\nExec=/usr/bin/user-agent\n"
        )

        ssh = self.root / "home/alice/.ssh"
        ssh.mkdir()
        (ssh / "authorized_keys").write_text("ssh-ed25519 AAAATEST alice@test\n")

    def run_persist(self, *args, success=True, expected_code=None):
        result = subprocess.run(
            [str(BINARY), "persist", "--root", str(self.root), "--offline", *args],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if expected_code is not None:
            self.assertEqual(result.returncode, expected_code, result.stderr)
        elif success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("panicked", result.stderr)
        return result

    def test_baseline_check_history_and_explicit_update(self):
        created = self.run_persist("--scope", "all", "--init-baseline")
        self.assertIn("4 mechanisms", created.stdout)
        unchanged = self.run_persist("--scope", "all", "--check")
        self.assertIn("No persistence changes", unchanged.stdout)

        self.service.write_text("[Service]\nExecStart=/tmp/payload\n")
        self.desktop.unlink()
        with (self.root / "etc/cron.d/backup").open("a") as cron:
            cron.write("@reboot root /usr/bin/startup\n")
        changed = self.run_persist("--scope", "all", "--check", "--verbose",
                                   expected_code=4)
        self.assertIn("MODIFIED", changed.stdout)
        self.assertIn("ADDED", changed.stdout)
        self.assertIn("REMOVED", changed.stdout)
        self.assertIn("risk=HIGH", changed.stdout)
        self.assertIn("changes=3", changed.stdout)

        history = self.run_persist("--scope", "all", "--history")
        self.assertIn("MODIFIED", history.stdout)
        history_file = next(self.state.glob("sentinel/persist/*/history.jsonl"))
        records = [json.loads(line) for line in history_file.read_text().splitlines()]
        self.assertEqual(len(records), 3)

        self.run_persist("--scope", "all", "--update-baseline")
        accepted = self.run_persist("--scope", "all", "--check")
        self.assertIn("No persistence changes", accepted.stdout)

    def test_clap_actions_scope_and_errors(self):
        help_result = subprocess.run(
            [str(BINARY), "persist", "--help"], capture_output=True, text=True, timeout=5
        )
        self.assertEqual(help_result.returncode, 0)
        for flag in (
            "--init-baseline",
            "--update-baseline",
            "--check",
            "--list",
            "--history",
            "--scope",
            "--root",
            "--offline",
            "--verbose",
            "--history-days",
            "--history-max-mib",
        ):
            self.assertIn(flag, help_result.stdout)
        self.run_persist(success=False)
        self.run_persist("--check", "--list", success=False)
        self.run_persist("--scope", "invalid", "--list", success=False)
        missing = self.run_persist("--check", success=False)
        self.assertIn("--init-baseline", missing.stderr)

    def test_list_inventory_does_not_create_baseline(self):
        result = self.run_persist("--scope", "all", "--list", "--verbose")
        self.assertIn("PERSISTENCE INVENTORY entries=4", result.stdout)
        self.assertIn("source=systemd", result.stdout)
        self.assertIn("source=cron", result.stdout)
        self.assertIn("source=ssh", result.stdout)
        self.assertIn("source=xdg", result.stdout)
        self.assertEqual(list(self.state.glob("sentinel/persist/*/baseline.json")), [])

    def test_fim_and_persist_explain_the_same_persistence_change(self):
        self.run_persist("--scope", "all", "--init-baseline")
        fim_init = subprocess.run(
            [str(BINARY), "fim", "--scan", str(self.root), "--init-baseline"],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(fim_init.returncode, 0, fim_init.stderr)

        self.service.write_text("[Service]\nExecStart=/tmp/audit-payload\n")
        persist = self.run_persist("--scope", "all", "--check", expected_code=4)
        self.assertIn("MODIFIED", persist.stdout)
        self.assertIn("source=systemd", persist.stdout)
        self.assertIn("risk=HIGH", persist.stdout)

        monitor = Monitor(self.root, args=("--interval", "30"), env=self.env)
        self.addCleanup(monitor.close)
        monitor.expect("Monitoring")
        monitor.expect("INITIAL SCAN")
        event = monitor.expect('MODIFIED "etc/systemd/system/demo.service"')
        self.assertIn("baseline=MODIFIED", event)

    def test_cron_line_shift_is_stable_and_command_change_is_modified(self):
        cron = self.root / "etc/cron.d/backup"
        self.run_persist("--scope", "all", "--init-baseline")
        cron.write_text("# inserted comment\n\n0 3 * * * root /usr/bin/backup\n")
        stable = self.run_persist("--scope", "all", "--check")
        self.assertIn("No persistence changes", stable.stdout)

        cron.write_text("# inserted comment\n0 3 * * * root /usr/bin/backup-v2\n")
        changed = self.run_persist("--scope", "all", "--check", expected_code=3)
        self.assertEqual(changed.stdout.count("MODIFIED"), 1)
        self.assertNotIn("ADDED", changed.stdout)
        self.assertNotIn("REMOVED", changed.stdout)


if __name__ == "__main__":
    unittest.main()
