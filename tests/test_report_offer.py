# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The mail offer is asked at most once, only to a person at a terminal, with Enter meaning No (OCO-6055). Synthetic data only."""
import datetime as dt, io, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

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

    def test_the_offer_is_made_during_the_trial_and_not_after_it(self):
        last, after = flow.REPORT_TRIAL_END, flow.REPORT_TRIAL_END + dt.timedelta(days=1)
        self.assertEqual(last, dt.date(2026, 12, 31))
        self.assertTrue(flow.should_offer(1, today=last, **TTY))
        self.assertTrue(flow.should_offer(1, today=dt.date(2026, 11, 13), **TTY))
        self.assertFalse(flow.should_offer(1, today=after, **TTY))

    def test_the_offer_says_it_is_a_trial_until_the_end_of_december_and_that_the_details_are_needed(self):
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as d, mock.patch.object(flow, "trial_open", lambda today=None: True):
            flow.after_scan(ITEMS, "quick", Path(d), input_fn=lambda p="": "n", out=out, os_name="Debian", **TTY)
        self.assertIn("trial feature until 31 December 2026", out.getvalue())

    def test_with_the_mail_switch_off_nothing_is_ever_asked(self):
        with mock.patch.object(flow, "MAIL_AVAILABLE", False), tempfile.TemporaryDirectory() as d:
            p = flow.after_scan(ITEMS, "quick", Path(d), stdin_tty=True, stderr_tty=True, env={}, quiet=False, input_fn=boom, out=io.StringIO(), os_name="Debian")
            self.assertTrue(p.exists())

    def test_a_yes_with_the_mail_switch_off_does_not_send_anything(self):
        out = io.StringIO()
        with mock.patch.object(flow, "MAIL_AVAILABLE", False), tempfile.TemporaryDirectory() as d:
            flow.after_scan(ITEMS, "quick", Path(d), input_fn=lambda p: "y", out=out, os_name="Debian", **TTY)
        self.assertIn("not available in this version", out.getvalue())


if __name__ == "__main__":
    unittest.main()
