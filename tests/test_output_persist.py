"""Public, offline Persist presentation contracts."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_runtime import BINARY


class PersistOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="persist-output-", dir="/tmp/opencode")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "root"
        self.root.mkdir()
        self.env = dict(os.environ, HOME=str(self.base / "home"),
                        XDG_STATE_HOME=str(self.base / "state"),
                        XDG_CONFIG_HOME=str(self.base / "config"),
                        SENTINEL_STATE_DIR=str(self.base / "state"), TMPDIR=str(self.base))

    def cli(self, *args, code=0):
        result = subprocess.run([str(BINARY), "persist", "--root", str(self.root),
                                 "--offline", "--scope", "all", *args], env=self.env,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertNotIn("\x1b", result.stdout + result.stderr)
        return result

    def service(self, name="demo", command="/usr/bin/agent"):
        path = self.root / f"etc/systemd/system/{name}.service"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"[Service]\nExecStart={command}\n")
        return path

    def records(self, result):
        records = [json.loads(line) for line in result.stdout.splitlines()]
        for record in records:
            self.assertEqual(record["schema_version"], 1)
            self.assertEqual(record["module"], "persist")
        return records

    def test_empty_and_large_inventory_are_complete(self):
        empty = self.cli("--list")
        self.assertIn("SENTINEL / PERSIST", empty.stdout)
        self.assertIn("0 entries found", empty.stdout)
        self.assertIn("No HIGH or MEDIUM findings", empty.stdout)
        self.assertIn("Use --verbose", empty.stdout)
        self.assertEqual(empty.stderr, "")
        for i in range(105):
            self.service(f"agent-{i:03}")
        listed = self.cli("--list")
        self.assertIn("105 entries found", listed.stdout)
        self.assertNotIn("agent-000.service", listed.stdout)
        verbose = self.cli("--list", "--verbose")
        self.assertIn("systemd / system", verbose.stdout)
        self.assertIn("Total: 105 entries", verbose.stdout)
        for i in range(105):
            self.assertIn(f"agent-{i:03}.service", verbose.stdout)
        records = self.records(self.cli("--list", "--output", "json"))
        self.assertEqual(sum(r["type"] == "entry" for r in records), 105)
        summary = next(r["data"] for r in records if r["type"] == "inventory_summary")
        self.assertEqual(summary["total"], 105)
        self.assertEqual(summary["missing_coverage"], [])
        self.assertIn("observed_at", summary)

    def test_baselines_changes_reasons_and_full_json(self):
        path = self.service()
        self.assertIn("Baseline created", self.cli("--init-baseline").stdout)
        unchanged = self.cli("--check")
        self.assertIn("No persistence changes detected.", unchanged.stdout)
        self.assertNotIn("safe", unchanged.stdout.lower())
        path.write_text("[Service]\nExecStart=/tmp/payload\n")
        changed = self.cli("--check", code=4)
        for text in ("[~] MODIFIED", "/usr/bin/agent", "/tmp/payload", "HIGH",
                     "transient or download location", "UTC", "configuration"):
            self.assertIn(text, changed.stdout)
        structured = self.records(self.cli("--check", "--output", "json", code=4))
        event = next(r["data"] for r in structured if r["type"] == "event")
        self.assertEqual(event["before"]["command"], "/usr/bin/agent")
        self.assertEqual(event["after"]["command"], "/tmp/payload")
        self.assertIn("config_sha256", event["after"])
        verbose = self.cli("--check", "--verbose", code=4)
        for field in ("before:", "after:", "config_sha256", "evidence", "active", "origins"):
            self.assertIn(field, verbose.stdout)
        self.assertIn("Baseline updated", self.cli("--update-baseline").stdout)
        self.assertIn("No persistence changes", self.cli("--check").stdout)
        history = self.records(self.cli("--history", "--output", "json"))
        dates = [r["data"]["detected_at"] for r in history if r["type"] == "event"]
        self.assertEqual(dates, sorted(dates))
        destination = self.base / "export.txt"
        export = self.records(self.cli("--history", "--export", str(destination),
                                       "--format", "text", "--output", "json"))
        self.assertEqual(export[0]["type"], "export")
        self.assertEqual(export[0]["data"]["destination"], str(destination))
        self.assertTrue(destination.is_file())

    def test_incomplete_is_visible_and_list_still_succeeds(self):
        path = self.service()
        self.cli("--init-baseline")
        path.write_bytes(b"\xff")
        listed = self.cli("--list", "--output", "json")
        summary = next(r["data"] for r in self.records(listed) if r["type"] == "inventory_summary")
        self.assertIn({"source": "SYSTEMD", "scope": "SYSTEM"}, summary["missing_coverage"])
        self.assertTrue(all(json.loads(line)["type"] == "warning" for line in listed.stderr.splitlines()))
        self.cli("--check", code=5)

    def test_legacy_and_unsafe_command(self):
        self.service(command="/usr/bin/agent\x1b[2J")
        legacy = self.cli("--list", "--output", "legacy")
        self.assertIn("PERSISTENCE INVENTORY entries=1", legacy.stdout)
        human = self.cli("--list", "--verbose")
        self.assertIn("\\u{1b}", human.stdout)
        records = self.records(self.cli("--list", "--output", "json"))
        entry = next(r["data"] for r in records if r["type"] == "entry")
        self.assertEqual(entry["command"], "/usr/bin/agent\x1b[2J")

    def test_all_categories_risk_order_and_changed_exit_priorities(self):
        self.service("low")
        self.service("high", "/tmp/payload")
        fixtures = {
            "home/alice/.config/systemd/user/user.service": "[Service]\nExecStart=/usr/bin/user-agent\n",
            "etc/cron.d/backup": "@reboot root /usr/bin/backup\n",
            "var/spool/cron/alice": "0 3 * * * /usr/bin/user-backup\n",
            "root/.ssh/authorized_keys": "ssh-ed25519 AAAATEST root@test\n",
            "home/alice/.ssh/authorized_keys": "ssh-ed25519 AAAATEST alice@test\n",
            "etc/xdg/autostart/system.desktop": "[Desktop Entry]\nType=Application\nExec=/usr/bin/system-agent\n",
            "home/alice/.config/autostart/user.desktop": "[Desktop Entry]\nType=Application\nExec=/usr/bin/user-agent\n",
        }
        for relative, content in fixtures.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        verbose = self.cli("--list", "--verbose")
        for source in ("systemd", "cron", "ssh", "xdg"):
            for scope in ("user", "system"):
                self.assertIn(f"{source} / {scope}", verbose.stdout)
        self.assertLess(verbose.stdout.index("high.service"), verbose.stdout.index("low.service"))
        self.assertIn("SSH authorization grants remote access", verbose.stdout)
        default = self.cli("--list")
        self.assertIn("Risk Summary", default.stdout)
        self.assertIn("Findings requiring attention", default.stdout)
        self.assertIn("high.service", default.stdout)
        self.assertNotIn("low.service", default.stdout)
        self.assertIn("Use --verbose to inspect the complete inventory.", default.stdout)
        self.cli("--init-baseline")
        self.service("low", "/usr/bin/changed")
        self.cli("--check", code=3)
        self.cli("--update-baseline")
        (self.root / "etc/systemd/system/high.service").unlink()
        removed = self.cli("--check", code=3)
        self.assertIn("[-] REMOVED", removed.stdout)
        self.assertIn("1 change detected", removed.stdout)
        self.assertIn("0 high-risk entries in the current state", removed.stdout)
        self.assertIn("1 high-risk entry involved", removed.stdout)


if __name__ == "__main__":
    unittest.main()
