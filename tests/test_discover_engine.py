# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""`--discover` on the host is the `recent` engine for everyone, with no key; its windows match `recent`'s; one --max-read default (20 keyless, 200
keyed) caps reads from Lattice while every id is still checked against the host locally. Invented products and reserved ids only."""
import sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli  # noqa: E402
from test_agent_entry import Entry, EntryBase, exp, feed  # noqa: E402


def many(n):
    return [exp(f"CVE-2099-{i:04d}") for i in range(1, n + 1)]


class DiscoverEngine(EntryBase):
    def fresh(self):
        """A run records what it finds; the next run would print RECORDED. Start each compared run from an empty records folder."""
        import shutil
        shutil.rmtree(cli.OUT, ignore_errors=True)

    def twice(self, first, second):
        self.fresh(); _, a, _ = self.run_cli(*first)
        self.fresh(); _, b, _ = self.run_cli(*second)
        return a, b

    def test_discover_and_recent_give_the_same_rows_for_each_window(self):
        Entry.feed = feed([exp("CVE-2099-0001")], daily=([exp("CVE-2099-0005", vendor="Otherco", product="Otherthing")], []), open_=[exp("CVE-2099-0009", vendor="Oldco", product="Oldthing")])
        for window in ("daily", "weekly", "open"):
            a, b = self.twice(("recent", f"--{window}"), ("--discover", f"--{window}"))
            self.assertEqual(a, b, window)

    def test_monthly_is_the_whole_thirty_day_list_that_recent_all_reads(self):
        Entry.feed = feed([exp("CVE-2099-0001")], open_=[exp("CVE-2099-0009", vendor="Oldco", product="Oldthing")])
        a, b = self.twice(("recent", "--all"), ("--discover", "--monthly"))
        _, c = self.twice(("recent", "--all"), ("recent", "--monthly"))
        self.assertEqual(a.replace("(all,", "(monthly,"), b); self.assertEqual(a, c)
        self.assertIn("CVE-2099-0001", b); self.assertIn("CVE-2099-0009", b)

    def test_weekly_is_the_default_window_of_discover(self):
        Entry.feed = feed([exp("CVE-2099-0001")], daily=([exp("CVE-2099-0005", vendor="Otherco", product="Otherthing")], []))
        a, b = self.twice(("--discover",), ("--discover", "--weekly"))
        self.assertEqual(a, b); self.assertIn("(weekly,", a)

    def test_keyless_reads_at_most_twenty_and_lists_the_rest_as_not_read(self):
        Entry.feed = feed(many(30))
        rc, out, err = self.run_cli("--discover")
        self.assertEqual(rc, 0, err)
        self.assertLessEqual(self.lattice_reads(), 40)                     # 20 ids, a lookup and a detail read each, at most
        self.assertIn("10 may match but were not read (--max-read 20)", out)
        self.assertEqual(out.count("not read: over --max-read 20"), 10)

    def test_max_read_is_one_flag_on_the_host_and_every_id_is_still_checked_locally(self):
        Entry.feed = feed(many(5))
        rc, out, err = self.run_cli("--discover", "--max-read", "2")
        self.assertEqual(rc, 0, err)
        self.assertIn("3 may match but were not read (--max-read 2)", out)
        self.assertIn("exploited 0 ruled out, 5 may match", out)          # all five were matched against the host locally

    def test_project_keyless_default_is_twenty_too(self):
        import inspect
        self.assertIn("200 if KEY else 20", inspect.getsource(cli.cmd_project))


if __name__ == "__main__":
    unittest.main()


class WindowsDoNotDependOnTheLocalClock(EntryBase):
    """The windows are the list's own UTC days; the same list gives the same rows whatever time zone the process runs in (UTC+13 and UTC-11 are the extremes)."""

    def rows_in(self, tz):
        import os, time, shutil
        old = os.environ.get("TZ")
        os.environ["TZ"] = tz; time.tzset()
        try:
            shutil.rmtree(cli.OUT, ignore_errors=True)
            _, out, _ = self.run_cli("--discover", "--daily")
            return [l for l in out.splitlines() if l.startswith("CVE-")]
        finally:
            if old is None: os.environ.pop("TZ", None)
            else: os.environ["TZ"] = old
            time.tzset()

    def test_same_rows_at_utc_plus_13_and_utc_minus_11(self):
        Entry.feed = feed([exp("CVE-2099-0001")], daily=([exp("CVE-2099-0005", vendor="Exampleco", product="Examplelib")], []))
        east, west, utc = self.rows_in("Pacific/Auckland"), self.rows_in("Etc/GMT+11"), self.rows_in("UTC")
        self.assertTrue(utc); self.assertEqual(east, utc); self.assertEqual(west, utc)
