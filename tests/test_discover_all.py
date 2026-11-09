# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""0.6.1: the features that needed a published dataset are switched off. Each says so on stderr, exits 2, fetches nothing, and points at what still works."""
import sys, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli  # noqa: E402
from test_agent_entry import EntryBase  # noqa: E402


class Withdrawn(EntryBase):
    def run_none_fetched(self, *argv):
        with mock.patch.object(cli, "fetch_bytes", side_effect=AssertionError("must not fetch")), mock.patch.object(cli, "fetch_json", side_effect=AssertionError("must not fetch")):
            return self.run_cli(*argv)

    def test_discover_all_on_the_host_says_it_is_not_available(self):
        rc, out, err = self.run_none_fetched("--discover", "--all")
        self.assertEqual(rc, 2); self.assertEqual(out, "")
        self.assertIn("not available in this version", err); self.assertIn("--discover --monthly", err)
        self.assertEqual(self.lattice_reads(), 0)

    def test_project_discover_all_says_it_is_not_available(self):
        rc, out, err = self.run_none_fetched("project", ".", "--discover", "--all")
        self.assertEqual((rc, out), (2, "")); self.assertIn("not available in this version", err)

    def test_index_command_says_it_is_not_available(self):
        rc, out, err = self.run_none_fetched("index")
        self.assertEqual((rc, out), (2, "")); self.assertIn("no longer published", err)

    def test_posture_attack_says_it_is_not_available_and_does_not_scan(self):
        from lattice_scan import posture
        with mock.patch.object(posture, "collect", side_effect=AssertionError("must not scan")):
            rc, out, err = self.run_none_fetched("posture", "--attack")
        self.assertEqual((rc, out), (2, "")); self.assertIn("not available in this version", err)

    def test_recent_all_is_the_thirty_day_list_and_still_works(self):
        from test_agent_entry import Entry, exp, feed
        Entry.feed = feed([exp("CVE-2099-0001")])
        rc, out, err = self.run_cli("recent", "--all")
        self.assertEqual(rc, 0, err); self.assertIn("CVE-2099-0001", out)

    def test_the_downloader_is_not_reachable_from_the_command_line(self):
        import inspect
        src = inspect.getsource(cli.main)
        for name in ("cmd_all", "cmd_project_all", "cmd_index"):
            self.assertNotIn(name + "(", src)


if __name__ == "__main__":
    unittest.main()
