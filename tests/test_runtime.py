"""Executable tests: cargo build --offline && python3 -m unittest discover -s tests -v."""

import os
import hashlib
from pathlib import Path
import queue
import select
import subprocess
import sys
import tempfile
import threading
import time
import unittest


BINARY = Path(__file__).resolve().parents[1] / "target/debug/sentinel"


class Monitor:
    def __init__(self, path, cwd=None, args=(), env=None):
        self.process = subprocess.Popen(
            [str(BINARY), "fim", "--output", "legacy", "--scan", str(path), *args], cwd=cwd, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.events = queue.Queue()
        self.threads = []
        for stream in (self.process.stdout, self.process.stderr):
            thread = threading.Thread(target=self.read, args=(stream,), daemon=True)
            thread.start()
            self.threads.append(thread)

    def read(self, stream):
        for line in stream:
            self.events.put(line.strip())

    def expect(self, text):
        deadline = time.monotonic() + 10
        while True:
            line = self.events.get(timeout=max(0.01, deadline - time.monotonic()))
            if text in line:
                return line
            if self.is_detail(line):
                continue
            raise AssertionError(f"Expected {text!r}, got {line!r}")

    @staticmethod
    def is_detail(line):
        return line.lstrip().startswith(
            ("changed=", "before:", "after:", "baseline:", "replaced-before:")
        )

    def close(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
        for thread in self.threads:
            thread.join(timeout=3)
        self.process.stdout.close()
        self.process.stderr.close()
        self.process.stdin.close()

    def command(self, command):
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()

    def quiet(self, seconds=2.2):
        deadline = time.monotonic() + seconds
        while True:
            try:
                line = self.events.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty:
                return
            if self.is_detail(line):
                continue
            raise AssertionError(f"Unexpected output: {line!r}")


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fim-tests-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "carpeta con espacios ñ"
        self.root.mkdir()
        self.state = self.base / "baseline-temp"
        self.state.mkdir()
        self.env = dict(
            os.environ,
            TMPDIR=str(self.state),
            SENTINEL_STATE_DIR=str(self.base / "durable-state"),
            XDG_STATE_HOME=str(self.base / "xdg-state"),
            XDG_CONFIG_HOME=str(self.base / "xdg-config"),
        )

    def initialize(self):
        result = subprocess.run([str(BINARY), "fim", "--scan", str(self.root), "--init-baseline"],
                                capture_output=True, text=True, timeout=5, env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)

    def start(self, path=None, cwd=None, args=()):
        self.initialize()
        monitor = Monitor(self.root if path is None else path, cwd, args, self.env)
        self.addCleanup(monitor.close)
        if "--silent" not in args:
            monitor.expect("Monitoring")
            monitor.expect("INITIAL SCAN")
        else:
            monitor.command("--silent")
            monitor.expect("Output silenced")
        return monitor

    def test_live_silent_desilent_commands(self):
        monitor = self.start()
        file = self.root / "cambio"
        for silent, desilent in (("--silent", "-d"), ("--silent", "--desilent")):
            monitor.command(silent)
            monitor.expect("Output silenced")
            file.write_text(silent)
            monitor.quiet()
            monitor.command(desilent)
            monitor.expect("Output enabled")
            monitor.quiet(1.2)  # Hidden changes are not replayed.
            file.write_text(desilent)
            monitor.expect('MODIFIED "cambio"')

    def test_start_silent_verbose_then_resume(self):
        monitor = self.start(args=("--silent", "--verbose"))
        file = self.root / "archivo"
        file.write_text("before")
        monitor.quiet()
        monitor.command("--desilent")
        monitor.expect("Output enabled")
        file.write_text("after")
        monitor.expect('MODIFIED "archivo"')
        monitor.expect("sha256=" + hashlib.sha256(b"before").hexdigest())
        monitor.expect("sha256=" + hashlib.sha256(b"after").hexdigest())

    def test_verbose_initial_created_modified_deleted_hashes(self):
        file = self.root / "archivo"
        file.write_text("before")
        monitor = self.start(args=("-v", "-d"))
        file.write_text("after")
        monitor.expect('MODIFIED "archivo"')
        monitor.expect("sha256=" + hashlib.sha256(b"before").hexdigest())
        monitor.expect("sha256=" + hashlib.sha256(b"after").hexdigest())
        file.unlink()
        monitor.expect('DELETED "archivo"')
        monitor.expect("sha256=" + hashlib.sha256(b"after").hexdigest())
        monitor.expect("after: absent")
        file.touch()
        monitor.expect('CREATED "archivo"')
        monitor.expect("before: absent")
        monitor.expect("sha256=" + hashlib.sha256(b"").hexdigest())

    def test_silent_errors_remain_visible(self):
        monitor = self.start(args=("--silent",))
        monitor.command("-d")
        monitor.expect("Output enabled")
        monitor.command("--silent")
        monitor.expect("Output silenced")
        self.root.rename(self.base / "moved")
        monitor.expect("Incomplete scan")

    def test_commands_do_not_wait_for_scan_interval(self):
        monitor = self.start(args=("--interval", "30"))
        monitor.command("--silent")
        monitor.expect("Output silenced")  # The assertion expires before the scan interval.
        monitor.command("-d")
        monitor.expect("Output enabled")

    def test_native_events_trigger_scan_before_reconciliation_interval(self):
        monitor = self.start(args=("-i", "30"))
        (self.root / "early").write_text("event")
        monitor.expect('CREATED "early"')

    @unittest.skipUnless(sys.platform.startswith("linux"), "Requires Linux inotify events")
    def test_transient_creation_reports_activity_without_state_difference(self):
        monitor = self.start(args=("-i", "30"))
        transient = self.root / "temporary"
        transient.write_text("short lived")
        transient.unlink()
        monitor.expect("ACTIVITY")

    def test_hardscan_alias_uses_pollwatcher(self):
        monitor = self.start(args=("-hs", "-i", "1"))
        (self.root / "polled").write_text("content")
        monitor.expect('CREATED "polled"')

    def test_hardscan_rehashes_when_size_and_mtime_are_unchanged(self):
        file = self.root / "same-metadata"
        file.write_bytes(b"aaaa")
        original = file.stat()
        monitor = self.start(args=("-hs", "-i", "1", "-v"))
        file.write_bytes(b"bbbb")
        os.utime(file, ns=(original.st_atime_ns, original.st_mtime_ns))
        monitor.expect('MODIFIED "same-metadata"')
        monitor.expect("sha256=" + hashlib.sha256(b"aaaa").hexdigest())
        monitor.expect("sha256=" + hashlib.sha256(b"bbbb").hexdigest())

    def test_stdin_eof_does_not_stop_monitoring(self):
        monitor = self.start()
        monitor.process.stdin.close()
        (self.root / "nuevo").touch()
        monitor.expect('CREATED "nuevo"')

    def test_invalid_command_does_not_stop_monitoring(self):
        monitor = self.start()
        monitor.command("--scan otra-ruta")
        monitor.expect("Unknown command")
        (self.root / "nuevo").touch()
        monitor.expect('CREATED "nuevo"')

    def test_conflicting_startup_output_flags(self):
        for flags in (("--silent", "--desilent"), ("--silent", "-d"),
                      ("-d", "--silent"), ("-sd",), ("--desilent", "--silent")):
            with self.subTest(flags=flags):
                self.assertEqual(self.fails("--scan", self.root, *flags).returncode, 2)

    def test_boolean_flags_reject_values_duplicates_and_unknown_flags(self):
        for flags in (("--verbose=true",), ("--silent=false",),
                      ("--desilent=1",), ("--verbose", "yes"),
                      ("-vv",), ("--silent", "--silent"), ("--silnet",)):
            with self.subTest(flags=flags):
                self.assertEqual(self.fails("--scan", self.root, *flags).returncode, 2)

    def test_help_lists_new_flags_and_exits(self):
        for flag in ("-h", "--help"):
            result = subprocess.run([str(BINARY), "fim", flag], capture_output=True,
                                    text=True, timeout=5)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
            for option in ("--scan", "--hardscan", "-hs", "--interval", "--verbose", "--silent", "--desilent", "--hmac-key", "--history-days", "--history-max-mib"):
                self.assertIn(option, result.stdout)

    def test_root_help_requires_fim_subcommand(self):
        for args in ((), ("-h",), ("--help",)):
            with self.subTest(args=args):
                result = subprocess.run([str(BINARY), *args], capture_output=True,
                                        text=True, timeout=5)
                help_text = result.stderr if not args else result.stdout
                self.assertEqual(result.returncode, 2 if not args else 0)
                self.assertIn("fim", help_text)
                self.assertIn("Usage: sentinel", help_text)
                self.assertNotIn("--scan", help_text)
                self.assertNotIn("Monitoring", help_text)
        result = subprocess.run([str(BINARY), "--scan", str(self.root)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn("unexpected argument", result.stderr)

    def test_startup_errors_visible_in_all_output_modes(self):
        for flags in (("--silent",), ("-v", "--silent"), ("-v",), ("-d",)):
            with self.subTest(flags=flags):
                result = self.fails("--scan", self.base / "missing", *flags)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Error:", result.stderr)

    def test_repeated_commands_whitespace_and_empty_lines(self):
        monitor = self.start()
        for command, expected in (("  --silent  ", "silenced"),
                                  ("--silent\r", "silenced"),
                                  ("\t-d\t", "enabled"),
                                  ("--desilent", "enabled")):
            monitor.command(command)
            monitor.expect(expected)
        monitor.command("")
        monitor.command("  \t")
        (self.root / "nuevo").touch()
        self.assertTrue(monitor.expect('CREATED "nuevo"').startswith('CREATED "nuevo" detected='))

    def test_invalid_commands_preserve_silent_state(self):
        monitor = self.start()
        monitor.command("--silent")
        monitor.expect("Output silenced")
        for command in ("--silent -d", "--verbose", "--desilent=true", "desilent", "ñ"):
            monitor.command(command)
            monitor.expect("Unknown command")
        (self.root / "oculto").touch()
        monitor.quiet()
        monitor.command("-d")
        monitor.expect("Output enabled")
        monitor.quiet(1.2)
        (self.root / "visible").touch()
        monitor.expect('CREATED "visible"')

    def test_command_burst_beyond_channel_capacity(self):
        monitor = self.start()
        monitor.process.stdin.write("--silent\n-d\n" * 40)
        monitor.process.stdin.flush()
        for _ in range(40):
            monitor.expect("Output silenced")
            monitor.expect("Output enabled")
        (self.root / "nuevo").touch()
        monitor.expect('CREATED "nuevo"')
        self.assertIsNone(monitor.process.poll())

    def test_invalid_utf8_input_reports_error_and_monitor_continues(self):
        monitor = self.start()
        os.write(monitor.process.stdin.fileno(), b"\xff\n")
        monitor.expect("Failed to read commands")
        (self.root / "nuevo").touch()
        monitor.expect('CREATED "nuevo"')

    def test_hidden_create_modify_delete_are_not_replayed(self):
        file = self.root / "original"
        file.write_text("before")
        monitor = self.start(args=("--silent",))
        # Synchronize with startup before changing the initial state.
        monitor.command("--silent")
        monitor.expect("Output silenced")
        file.write_text("after")
        monitor.quiet()
        file.unlink()
        (self.root / "creado").touch()
        monitor.quiet()
        monitor.command("-d")
        monitor.expect("Output enabled")
        monitor.quiet(1.2)
        (self.root / "creado").write_text("changed")
        monitor.expect('MODIFIED "creado"')

    @unittest.skipUnless(os.name == "posix", "Requires a Unix PTY")
    def test_same_terminal_commands_require_enter_and_keep_process(self):
        import pty
        self.initialize()
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        try:
            process = subprocess.Popen([str(BINARY), "fim", "--output", "legacy", "-s", str(self.root)],
                                       stdin=slave, stdout=slave, stderr=slave, env=self.env)
        finally:
            os.close(slave)

        def stop():
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        self.addCleanup(stop)
        pending = b""

        def read_until(expected):
            nonlocal pending
            deadline = time.monotonic() + 10
            while expected not in pending:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0, pending)
                ready, _, _ = select.select([master], [], [], remaining)
                self.assertTrue(ready, pending)
                pending += os.read(master, 65536)
            before, pending = pending.split(expected, 1)
            return before

        read_until(b"Monitoring")
        os.write(master, b"--silent\n")
        read_until(b"Output silenced")
        (self.root / "oculto").touch()
        time.sleep(2.2)
        os.write(master, b"--desilent")  # La terminal espera Enter.
        time.sleep(0.2)
        while select.select([master], [], [], 0)[0]:
            pending += os.read(master, 65536)
        self.assertNotIn(b"Output enabled", pending)
        self.assertNotIn(b"CREATED", pending)
        os.write(master, b"\n")
        read_until(b"Output enabled")
        (self.root / "visible").touch()
        before = read_until(b'CREATED "visible"')
        self.assertNotIn(b'CREATED "oculto"', before)
        self.assertIsNone(process.poll())

    def fails(self, *args):
        result = subprocess.run([str(BINARY), "fim", *map(str, args)],
                                capture_output=True, text=True, timeout=5, env=self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr)
        self.assertNotIn("Monitoring", result.stdout)
        self.assertNotIn("panicked", result.stderr)
        return result

    def test_nonexistent_paths(self):
        for name in ("inexistente", "no existe ñ", "missing/child"):
            with self.subTest(name=name):
                result = self.fails("--scan", self.base / name)
                self.assertIn("Error:", result.stderr)

    def test_file_instead_of_directory(self):
        file = self.root / "archivo.txt"
        file.write_text("contenido")
        self.assertIn("Not a directory", self.fails("--scan", file).stderr)

    def test_invalid_arguments(self):
        for args in (("--scan", ""), ("--scan",), ("--interval", "0"),
                     ("--interval", "-1"), ("--interval", "abc"),
                     ("--interval", "1.5"), ("--interval", "18446744073709551616")):
            with self.subTest(args=args):
                self.fails(*args)

    def test_relative_path_with_dot_and_parent(self):
        monitor = self.start("./carpeta con espacios ñ/../carpeta con espacios ñ/", self.base)
        (self.root / "nuevo").touch()
        monitor.expect('CREATED "nuevo"')

    def test_names_nested_binary_empty_and_rename(self):
        monitor = self.start()
        names = ["espacios aquí.txt", "日本語.txt", ".oculto", "-opcion",
                 "a;b$(x).txt", "MAYUS", "mayus", "sin extension", "sub/archivo.bin"]
        for name in names:
            with self.subTest(name=name):
                file = self.root / name
                file.parent.mkdir(exist_ok=True)
                file.touch()
                if name == "sub/archivo.bin":
                    monitor.expect('CREATED "sub"')
                monitor.expect(f'CREATED "{name}"')
        file = self.root / names[-1]
        file.write_bytes(bytes(range(256)) * 1024)
        monitor.expect(f'MODIFIED "{names[-1]}"')
        file.rename(self.root / "renombrado")
        monitor.expect(f'RENAMED "{names[-1]}" -> "renombrado" content_changed=false')
        (self.root / "renombrado").unlink()
        monitor.expect('DELETED "renombrado"')

    def test_rename_then_change_content_between_scans(self):
        file = self.root / "before"
        file.write_text("original")
        monitor = self.start(args=("--verbose",))
        renamed = self.root / "after"
        file.rename(renamed)
        renamed.write_text("changed")
        monitor.expect('RENAMED "before" -> "after" content_changed=true')
        monitor.expect("sha256=" + hashlib.sha256(b"original").hexdigest())
        monitor.expect("sha256=" + hashlib.sha256(b"changed").hexdigest())

    def test_copy_with_identical_hash_is_not_reported_as_rename(self):
        file = self.root / "before"
        file.write_text("same bytes")
        monitor = self.start()
        (self.root / "after").write_text("same bytes")
        file.unlink()
        monitor.expect('CREATED "after"')
        monitor.expect('DELETED "before"')

    def test_rename_over_existing_destination(self):
        source = self.root / "source"
        destination = self.root / "destination"
        source.write_text("source content")
        destination.write_text("replaced content")
        monitor = self.start(args=("--verbose",))
        source.replace(destination)
        line = monitor.expect('RENAMED "source" -> "destination" content_changed=false')
        self.assertIn("baseline=RENAMED", line)
        self.assertIn("replaced=true", line)
        monitor.expect("sha256=" + hashlib.sha256(b"source content").hexdigest())
        monitor.expect("sha256=" + hashlib.sha256(b"replaced content").hexdigest())

    @unittest.skipUnless(os.name == "posix", "Unix filesystem semantics")
    def test_symlinks_fifo_and_empty_directories_remain_stable(self):
        outside = self.base / "outside"
        outside.write_text("outside")
        (self.root / "link").symlink_to(outside)
        (self.root / "broken").symlink_to(self.base / "missing")
        (self.root / "cycle").symlink_to(self.root, target_is_directory=True)
        (self.root / "empty").mkdir()
        os.mkfifo(self.root / "pipe")
        monitor = self.start()
        (self.root / "regular").touch()
        monitor.expect('CREATED "regular"')
        monitor.quiet(2)

    def test_missing_root_and_recovery_retains_snapshot(self):
        file = self.root / "original"
        file.write_text("before")
        monitor = self.start()
        moved = self.base / "moved"
        self.root.rename(moved)
        monitor.expect("Incomplete scan")
        (moved / "original").write_text("after")
        moved.rename(self.root)
        monitor.expect('MODIFIED "original"')

    def test_root_replaced_by_file_and_recovery(self):
        (self.root / "original").touch()
        monitor = self.start()
        moved = self.base / "moved"
        self.root.rename(moved)
        self.root.touch()
        monitor.expect("Incomplete scan")
        self.root.unlink()
        moved.rename(self.root)
        (self.root / "original").unlink()
        monitor.expect('DELETED "original"')

    @unittest.skipUnless(os.name == "posix" and os.geteuid() != 0,
                         "Permission checks require a non-root Unix user")
    def test_unreadable_file_startup(self):
        file = self.root / "privado"
        file.touch()
        file.chmod(0)
        self.addCleanup(file.chmod, 0o600)
        self.assertIn("Error:", self.fails("--scan", self.root, "--init-baseline").stderr)

    @unittest.skipUnless(os.name == "posix" and os.geteuid() != 0,
                         "Permission checks require a non-root Unix user")
    def test_unreadable_directory_runtime_and_recovery(self):
        folder = self.root / "privado"
        folder.mkdir()
        original_mode = folder.stat().st_mode & 0o7777
        file = folder / "original"
        file.write_text("before")
        monitor = self.start()
        folder.chmod(0)
        self.addCleanup(folder.chmod, original_mode)
        monitor.expect("Incomplete scan")
        folder.chmod(original_mode)
        file.write_text("after")
        monitor.expect('MODIFIED "privado/original"')


if __name__ == "__main__":
    unittest.main()
