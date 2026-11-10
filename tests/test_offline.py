"""With no network the tool goes on with what an earlier run saved, says how old it is, and never reads a saved 'not listed' as 'clear'."""
import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_agent_entry import EntryBase, feed, exp   # noqa: E402
from lattice_scan import cli   # noqa: E402

DEAD = "http://127.0.0.1:9"   # the discard port: nothing listens, so a connection is refused at once
IDS = "CVE-2099-0001,CVE-2099-0002"   # 0001 is exploited in the stub, 0002 is not listed


class Offline(EntryBase):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {"LATTICE_SCAN_READ_CACHE": "on"})   # another test's --refresh leaves it "off" in the process
        env.start(); self.addCleanup(env.stop)
        self.addCleanup(lambda: [f.unlink(missing_ok=True) for f in (cli.read_cache_path(), cli.feed_cache_path())])
        self.live = (cli.URL, cli.FEED_URL)

    def go_offline(self):
        cli.URL, cli.FEED_URL = f"{DEAD}/mcp", f"{DEAD}/recent.json"

    def age_saved(self, hours):
        """Saved answers younger than the 6-hour reuse limit are simply fresh; to reach the saved path they must be older."""
        f = cli.read_cache_path(); d = json.loads(f.read_text())
        for e in d["entries"].values():
            e["at"] = time.time() - hours * 3600
        f.write_text(json.dumps(d))
        g = cli.feed_cache_path()
        if g.exists():
            s = json.loads(g.read_text()); s["at"] = time.time() - hours * 3600; g.write_text(json.dumps(s))

    def prime(self, aged_hours=7):
        rc, out, _ = self.run_cli("enrich", "--cve", IDS)
        self.assertEqual(rc, 0, out)
        Entry_feed = feed([exp("CVE-2099-0001")])
        from test_agent_entry import Entry
        Entry.feed = Entry_feed
        self.run_cli("recent")
        cli.URL, cli.FEED_URL = self.live
        self.age_saved(aged_hours)

    def test_saved_answers_are_used_and_labelled_when_the_network_is_down(self):
        self.prime(); self.go_offline()
        rc, out, err = self.run_cli("enrich", "--cve", IDS)
        self.assertEqual(rc, 0, out + err)
        self.assertTrue(out.startswith("OFFLINE:"), out[:80])
        self.assertIn("EXPLOITED", out)
        self.assertIn("not listed as of", out); self.assertIn("not rechecked", out)
        self.assertNotIn("allowance", out + err); self.assertNotIn("get-key", out)

    def test_an_id_with_no_saved_answer_is_listed_unread_and_exits_3(self):
        self.prime(); self.go_offline()
        rc, out, err = self.run_cli("enrich", "--cve", "CVE-2099-0001,CVE-2099-0777")
        self.assertEqual(rc, 3)
        self.assertIn("CVE-2099-0777", out); self.assertIn("not read", out)
        self.assertIn("could not be reached", out)

    def test_a_dead_network_is_tried_once_not_once_per_id(self):
        self.go_offline()
        ids = ",".join(f"CVE-2099-{n:04d}" for n in range(1, 11))
        calls = []
        real = cli._OPENER.open
        def counting(req, timeout=None):
            calls.append(req.full_url); return real(req, timeout=timeout)
        with mock.patch.object(cli._OPENER, "open", counting):
            rc, _, _ = self.run_cli("enrich", "--cve", ids, "--max-read", "10")
        self.assertEqual(rc, 3)
        self.assertEqual(len(calls), 1, calls)

    def test_offline_flag_opens_no_connection_at_all(self):
        self.prime()
        def forbidden(*a, **k):
            raise AssertionError("a connection was attempted")
        with mock.patch.object(cli._OPENER, "open", forbidden):
            rc, out, err = self.run_cli("--offline", "enrich", "--cve", IDS)
            rc2, out2, _ = self.run_cli("--offline", "enrich", "--cve", "CVE-2099-0777")
        self.assertEqual(rc, 0, out + err); self.assertIn("OFFLINE:", out)
        self.assertEqual(rc2, 3); self.assertIn("not read", out2)

    def test_recent_uses_the_saved_list_and_says_so(self):
        self.prime(); self.go_offline()
        rc, out, err = self.run_cli("recent")
        self.assertNotIn("stopped:", err)
        self.assertIn("OFFLINE:", out); self.assertIn("recent-CVE list", out)

    def test_offline_with_nothing_saved_stops_with_a_clear_reason(self):
        rc, out, err = self.run_cli("--offline", "recent")
        self.assertEqual(rc, 3)
        self.assertIn("stopped:", err); self.assertIn("offline mode", err)

    def test_data_older_than_thirty_days_is_a_warning_not_a_refusal(self):
        self.prime(aged_hours=40 * 24)
        self.go_offline()
        rc, out, _ = self.run_cli("enrich", "--cve", IDS)
        self.assertEqual(rc, 0)
        self.assertIn("WARNING", out); self.assertIn("40 day(s) old", out)

    def test_the_run_report_is_never_sent_offline(self):
        env = {"LATTICE_SCAN_REPORT_FORCE": "1"}
        with mock.patch.dict(os.environ, env), mock.patch.object(cli, "URL", "https://lattice.namiq.io/mcp"), \
                mock.patch.object(cli, "FEED_URL", "https://namiq.io/lattice/recent.json"), mock.patch.object(cli, "RUN_URL", "https://namiq.io/lattice/run"):
            with mock.patch.object(cli, "OFFLINE", False):
                self.assertTrue(cli.report_enabled())
            with mock.patch.object(cli, "OFFLINE", True):
                self.assertFalse(cli.report_enabled())


if __name__ == "__main__":
    unittest.main()
