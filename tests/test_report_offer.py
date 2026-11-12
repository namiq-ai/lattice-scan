# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The mail offer is asked at most once, only to a person at a terminal, with Enter meaning No (OCO-6055). Synthetic data only."""
import io, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import scan_report_flow as flow  # noqa: E402

ITEMS = [{"cve": "CVE-2030-0001", "product": "nginx", "version": "1.26.3-1", "verdict": "in-range", "priority": "fix first"}]
TTY = dict(stdin_tty=True, stderr_tty=True, env={}, quiet=False, fmt="table", enabled=True)


def boom(_prompt=""):
    raise AssertionError("a question was asked")


class Offer(unittest.TestCase):
    def test_asked_once_and_enter_means_no(self):
        asked = []
        with tempfile.TemporaryDirectory() as d:
            flow.after_scan(ITEMS, "quick", Path(d), input_fn=lambda p: asked.append(p) or "", out=io.StringIO(), os_name="Debian", **TTY)
        self.assertEqual(len(asked), 1)
        self.assertFalse(flow.offer({"items": ITEMS}, lambda p: "", io.StringIO()))

    def test_never_asked_in_a_pipe_in_ci_when_quiet_or_with_json_or_csv(self):
        for kw in (dict(stdin_tty=False), dict(stderr_tty=False), dict(env={"CI": "true"}), dict(quiet=True), dict(fmt="json"), dict(fmt="csv")):
            self.assertFalse(flow.should_offer(1, **{**TTY, **kw}), kw)
        with tempfile.TemporaryDirectory() as d:
            for kw in (dict(stdin_tty=False), dict(env={"CI": "true"}), dict(quiet=True), dict(fmt="json")):
                flow.after_scan(ITEMS, "quick", Path(d), input_fn=boom, out=io.StringIO(), os_name="Debian", **{**TTY, **kw})

    def test_no_candidate_no_offer_and_no_file(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(flow.after_scan([], "quick", Path(d), input_fn=boom, out=io.StringIO(), os_name="Debian", **TTY))
            self.assertEqual(list(Path(d).iterdir()), [])
        self.assertFalse(flow.should_offer(0, **TTY))

    def test_as_shipped_nothing_is_ever_asked_because_there_is_no_mail_path_yet(self):
        self.assertFalse(flow.MAIL_AVAILABLE)
        with tempfile.TemporaryDirectory() as d:
            p = flow.after_scan(ITEMS, "quick", Path(d), stdin_tty=True, stderr_tty=True, env={}, quiet=False, input_fn=boom, out=io.StringIO(), os_name="Debian")
            self.assertTrue(p.exists())

    def test_a_yes_does_not_send_anything_in_this_version(self):
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            flow.after_scan(ITEMS, "quick", Path(d), input_fn=lambda p: "y", out=out, os_name="Debian", **TTY)
        self.assertIn("not available in this version", out.getvalue())


if __name__ == "__main__":
    unittest.main()
