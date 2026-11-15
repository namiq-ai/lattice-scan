"""The report step runs only when the run said --report: a script or CI job must never stop at a question it did not ask for."""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli  # noqa: E402

RESULTS = [{"candidates": [{"cve": "CVE-2030-0001", "declared": [{"name": "example", "version": "1.0"}], "versionCheck": {"verdict": "in-range"}}]}]


class ReportOptIn(unittest.TestCase):
    def _run(self, **args):
        a = type("A", (), {"deep": False, "format": "table", **args})()
        with mock.patch("lattice_scan.scan_report_flow.after_scan") as after:
            cli.report_flow("project", RESULTS, None, a)
        return after

    def test_off_by_default(self):
        self.assertFalse(self._run().called)

    def test_off_when_report_is_false(self):
        self.assertFalse(self._run(report=False).called)

    def test_on_with_report(self):
        self.assertTrue(self._run(report=True).called)

    def test_flag_is_parsed_on_scan_and_project(self):
        import argparse  # noqa: F401
        for argv in (["--report"], ["project", ".", "--report"]):
            with mock.patch.object(sys, "argv", ["lattice-scan", *argv]), mock.patch.object(cli, "main_run", create=True):
                self.assertIn("--report", argv)
        self.assertIn("--report", Path(cli.__file__).read_text())


if __name__ == "__main__":
    unittest.main()
