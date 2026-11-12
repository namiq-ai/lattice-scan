# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""A project scan builds the same payload from package and version only, never prompts in a pipeline, and writes the local file (OCO-6057). Synthetic data only."""
import io, os, stat, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli, scan_report as sr, scan_report_flow as flow  # noqa: E402

RESULTS = [{"root": "/home/canary-user/proj", "candidates": [
    {"cve": "CVE-2030-0001", "listed": "2026-10-01", "due": "2026-10-22", "versionCheck": {"verdict": "in-range", "why": "x"},
     "declared": [{"name": "left-pad2", "version": "1.3.0", "file": "/home/canary-user/proj/package-lock.json", "line": 42, "ecosystem": "npm", "spec": "^1.3.0"}]}]}]


class Project(unittest.TestCase):
    def test_the_payload_holds_package_version_and_verdict_and_no_file_path(self):
        items = flow.project_items(RESULTS)
        p = sr.build_payload(items, "quick", "Debian")
        self.assertEqual(p["items"], [{"cve": "CVE-2030-0001", "product": "left-pad2", "version": "1.3.0", "verdict": "in-range"}])
        text = str(p)
        for leak in ("canary-user", "package-lock", "/home", "42"):
            self.assertNotIn(leak, text.replace("CVE-2030-0001", ""))

    def test_in_a_pipeline_no_question_is_asked_and_a_private_file_is_written(self):
        with tempfile.TemporaryDirectory() as d:
            err = io.StringIO()
            old = cli.OUT, sys.stderr
            cli.OUT = Path(d)
            sys.stderr = err
            try:
                cli.report_flow("project", RESULTS, None, type("A", (), {"deep": False, "format": "table"})())
            finally:
                cli.OUT, sys.stderr = old
            files = list((Path(d) / "reports").glob("report-*.txt"))
            self.assertEqual(len(files), 1)
            self.assertEqual(stat.S_IMODE(os.stat(files[0]).st_mode), 0o600)
            self.assertNotIn("canary-user", files[0].read_text())

    def test_a_failure_to_write_the_report_never_changes_the_scan(self):
        with tempfile.TemporaryDirectory() as d:
            old = cli.OUT
            cli.OUT = Path(d)
            try:
                cli.report_flow("project", [{"candidates": [{"cve": "x"}]}], None, type("A", (), {})())      # a malformed result: no exception escapes
            finally:
                cli.OUT = old


if __name__ == "__main__":
    unittest.main()
