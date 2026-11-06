# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""An agent in its own sandbox: no writable home, no terminal. The tool must not crash, and must not leave the host's package list behind.
Each case runs the real script in a child process with an empty environment, so the home folder is the one the case builds. Standard library only."""
import json, os, stat, subprocess, sys, tempfile, unittest
from pathlib import Path

SRC = str(Path(__file__).resolve().parent.parent / "src")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_lattice_scan import INV  # noqa: E402   the suite's own fixed inventory: invented packages, reserved values


def run(home: str, *argv, extra=None):
    """The CLI as a child with a clean environment, stdin and stderr not a terminal. LATTICE_SCAN_INVENTORY keeps it off the real host."""
    inv = Path(tempfile.mkdtemp()) / "inv.json"
    inv.write_text(json.dumps(INV))
    env = {"PATH": os.environ["PATH"], "HOME": home, "PYTHONPATH": SRC, "LATTICE_SCAN_INVENTORY": str(inv), "XDG_CACHE_HOME": tempfile.mkdtemp(),
           "LATTICE_URL": "http://127.0.0.1:9/mcp"}   # nothing listens there: a run that tries the network fails fast, and none of these should
    env.update(extra or {})
    p = subprocess.run([sys.executable, "-m", "lattice_scan.cli", *argv], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    return p


class RecordsMode(unittest.TestCase):
    def test_records_mode_unwritable_home_does_not_crash(self):
        home = tempfile.mkdtemp(); os.chmod(home, 0o555)
        try:
            p = run(home, "--refresh", "--inventory", "-q")
            self.assertNotIn("Traceback", p.stderr)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(os.listdir(home), [])
        finally:
            os.chmod(home, 0o755)

    def test_records_mode_missing_home_does_not_crash(self):
        p = run("/nonexistent-home-for-test", "--refresh", "--inventory", "-q")
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_records_mode_named_dir_that_cannot_be_used_is_one_line(self):
        home = tempfile.mkdtemp(); os.chmod(home, 0o555)
        try:
            p = run(home, "--refresh", "--inventory", "-q", extra={"LATTICE_SCAN_DIR": f"{home}/records"})
            self.assertEqual(p.returncode, 1)
            self.assertNotIn("Traceback", p.stderr)
            self.assertEqual(len(p.stderr.strip().splitlines()), 1, p.stderr)
            self.assertIn("LATTICE_SCAN_DIR", p.stderr)
        finally:
            os.chmod(home, 0o755)

    def test_records_mode_no_terminal_and_no_folder_leaves_nothing_under_home(self):
        home = tempfile.mkdtemp()
        p = run(home, "--refresh", "--inventory", "-q")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(os.listdir(home), [])

    def test_records_mode_keep_writes_the_default_folder_with_private_files(self):
        home = tempfile.mkdtemp()
        p = run(home, "--refresh", "--inventory", "-q", "--keep")
        self.assertEqual(p.returncode, 0, p.stderr)
        d = Path(home) / ".lattice-scan"
        files = [f for f in d.iterdir() if f.is_file()]
        self.assertTrue(files)
        self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700)
        for f in files:
            self.assertEqual(f.stat().st_mode & 0o077, 0, f.name)   # no group or world bit on any record

    def test_records_mode_an_existing_folder_is_still_used(self):
        home = tempfile.mkdtemp()
        (Path(home) / ".lattice-scan").mkdir(mode=0o700)
        p = run(home, "--refresh", "--inventory", "-q")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue((Path(home) / ".lattice-scan" / "inventory.json").exists())

    def test_records_mode_named_dir_is_used_and_private(self):
        home, d = tempfile.mkdtemp(), Path(tempfile.mkdtemp()) / "mine"
        p = run(home, "--refresh", "--inventory", "-q", extra={"LATTICE_SCAN_DIR": str(d)})
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(os.listdir(home), [])
        for f in d.iterdir():
            self.assertEqual(f.stat().st_mode & 0o077, 0, f.name)

    def test_records_mode_loose_files_from_an_older_run_are_tightened(self):
        home = tempfile.mkdtemp(); d = Path(home) / ".lattice-scan"; d.mkdir(mode=0o700)
        old = d / "scan.log"; old.write_text("x"); os.chmod(old, 0o664)
        run(home, "--refresh", "--inventory", "-q")
        self.assertEqual(old.stat().st_mode & 0o077, 0)

    def test_records_mode_project_needs_no_home_at_all(self):
        proj = Path(tempfile.mkdtemp()); (proj / "requirements.txt").write_text("examplepkg==1.0\n")
        p = run("/nonexistent-home-for-test", "project", str(proj), "--cve", "CVE-2099-0001", "-q")
        self.assertNotIn("Traceback", p.stderr)


if __name__ == "__main__":
    unittest.main()
