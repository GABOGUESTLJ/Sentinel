"""Reject incompatible history-export actions before any filesystem mutation."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_runtime import BINARY


class ExportActionValidationTests(unittest.TestCase):
    def test_export_requires_history_before_any_action(self):
        for tool, action in [
            ("fim", "--init-baseline"),
            ("fim", "--update-baseline"),
            ("fim", "--migrate-baseline"),
            ("persist", "--list"),
            ("persist", "--init-baseline"),
            ("persist", "--update-baseline"),
            ("persist", "--check"),
        ]:
            with self.subTest(tool=tool, action=action):
                with tempfile.TemporaryDirectory(prefix="export-actions-", dir="/tmp/opencode") as temp:
                    base = Path(temp)
                    root = base / "root"
                    root.mkdir()
                    (root / "file").write_text("trusted")
                    legacy = base / "legacy"
                    legacy.mkdir()
                    env = dict(os.environ, HOME=str(base / "home"), TMPDIR=str(legacy),
                               SENTINEL_STATE_DIR=str(base / "durable"),
                               XDG_STATE_HOME=str(base / "state"),
                               XDG_CONFIG_HOME=str(base / "config"),
                               PYTHONDONTWRITEBYTECODE="1")
                    command = [str(BINARY), tool,
                               "--scan" if tool == "fim" else "--root", str(root)]
                    if tool == "persist":
                        command += ["--offline", "--scope", "system"]

                    def snapshot():
                        return {str(path.relative_to(base)): (
                            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
                            path.stat().st_mtime_ns, path.stat().st_mode,
                        ) for path in base.rglob("*")}

                    if action in ("--update-baseline", "--check"):
                        seeded = subprocess.run(command + ["--init-baseline"], env=env,
                                                capture_output=True, timeout=10)
                        self.assertEqual(seeded.returncode, 0, seeded.stderr)
                        (root / "file").write_text("must not be accepted")

                    before = snapshot()
                    output = base / "audit.txt"
                    for options in [
                        ["--export", str(output), "--format", "text"],
                        ["--format", "text"],
                        ["--since", "2026-01-01"],
                        ["--until", "2026-01-31"],
                    ]:
                        result = subprocess.run(command + [action, *options], env=env,
                                                capture_output=True, timeout=10)
                        self.assertEqual(result.returncode, 2, result.stderr)
                        self.assertFalse(output.exists())
                        self.assertEqual(snapshot(), before)


if __name__ == "__main__":
    unittest.main()
