# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""0.3.3: what an agent that runs the tool again and again needs. The keyless limit across runs, a 429 waited out, one record per finding under a race,
and the run with no arguments. Standard library only; invented products and reserved ids (CVE-2099-*)."""
import json, sys, threading, time, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli  # noqa: E402
from test_agent_entry import Entry, EntryBase, exp, feed  # noqa: E402


class Stability(EntryBase):
    """Reuses the stub servers and the per-test records folder of the agent-entry tests."""

    def setUp(self):
        super().setUp()
        mock.patch.stopall()                        # the parent patched time.sleep to a no-op; these tests want to see what is asked
        self.sleeps = []
        p = mock.patch.object(cli.time, "sleep", lambda s: self.sleeps.append(s)); p.start(); self.addCleanup(p.stop)

    # ---- 429
    def test_a_429_that_asks_for_a_short_wait_is_waited_out_and_retried(self):
        Entry.rate_left = 1
        rc, out, err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 0, err); self.assertIn("CVE-2099-0001", out)
        self.assertEqual(Entry.rate_seen, 3)                              # the refused call, the retry, and the candidate's detail read
        self.assertTrue(any(s >= 3 for s in self.sleeps), self.sleeps)    # it waited what Lattice asked, plus a second
        self.assertIn("waiting 3s as it asked", err)

    def test_the_retry_after_header_is_used_when_the_message_has_no_number(self):
        Entry.rate_left, Entry.rate_header = 1, "5"
        Entry.rate_body = '{"jsonrpc": "2.0", "id": 1, "error": {"code": -32002, "message": "Too many keyless requests."}}'
        rc, _, err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 0, err); self.assertTrue(any(5 <= s <= 7 for s in self.sleeps), self.sleeps)

    def test_a_429_gives_up_after_two_retries_and_says_what_lattice_said(self):
        Entry.rate_left = 9
        rc, _, err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 3); self.assertEqual(Entry.rate_seen, 3)     # the first try and two retries, no more
        self.assertIn("HTTP 429", err); self.assertIn("Too many keyless requests", err)

    def test_a_429_that_asks_for_a_long_wait_stops_at_once(self):
        Entry.rate_left = 9
        Entry.rate_body = '{"jsonrpc": "2.0", "id": 1, "error": {"code": -32002, "message": "Too many keyless requests. Retry after 2400 seconds, or get a key"}}'
        rc, _, err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 3); self.assertEqual(Entry.rate_seen, 1)
        self.assertFalse([s for s in self.sleeps if s > 70], self.sleeps); self.assertIn("2400", err)

    def test_retry_after_reads_a_header_a_message_or_nothing(self):
        self.assertEqual(cli.retry_after("7", ""), 7.0)
        self.assertEqual(cli.retry_after(None, "Too many keyless requests. Retry after 43 seconds, or get a key"), 43.0)
        self.assertIsNone(cli.retry_after("Wed, 04 Nov 2026 06:00:00 GMT", "nothing here"))   # an HTTP date is not a number of seconds
        self.assertIsNone(cli.retry_after(None, ""))

    # ---- pacing across runs
    def write_pace(self, ages):
        now = time.time()
        cli.pace_path().write_text(json.dumps([now - a for a in ages]))

    def test_five_calls_in_the_last_minute_make_the_next_run_wait_for_the_oldest_to_age_out(self):
        self.write_pace([50, 40, 30, 20, 10])
        rc, _, err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 0, err)
        self.assertTrue(any(5 < s < 12 for s in self.sleeps), self.sleeps)     # the oldest is 50 s old: about 10 s to go
        self.assertIn("5 calls a minute, so waiting", err)

    def test_fewer_than_five_recent_calls_or_old_ones_or_a_broken_file_cost_no_wait(self):
        for ages in ([30, 20, 10], [200, 150, 120, 100, 90]):
            with self.subTest(ages):
                self.sleeps.clear(); self.write_pace(ages)
                self.assertEqual(self.run_cli("--cve", "CVE-2099-0001")[0], 0); self.assertEqual(self.sleeps, [])
        self.sleeps.clear(); cli.pace_path().write_text("not json"); self.assertEqual(self.run_cli("--cve", "CVE-2099-0001")[0], 0); self.assertEqual(self.sleeps, [])

    def test_each_call_leaves_its_time_for_the_next_run_and_the_file_stays_short(self):
        for _ in range(7):
            self.run_cli("--cve", "CVE-2099-0001", "-q"); self.sleeps.clear(); self.write_pace([])   # no wait wanted here: only the bookkeeping
        self.run_cli("--cve", "CVE-2099-0001", "-q")
        times = json.loads(cli.pace_path().read_text())
        self.assertGreaterEqual(len(times), 1); self.assertLessEqual(len(times), cli.PACE_CALLS)

    def test_with_a_key_there_is_no_pacing(self):
        cli.KEY = "lat_test_not_a_real_key"
        self.write_pace([50, 40, 30, 20, 10])
        self.run_cli("--cve", "CVE-2099-0001", "-q"); self.assertEqual(self.sleeps, [])

    def test_a_project_run_writes_nothing_into_the_records_folder_for_pacing(self):
        root = Path(self.tmp.name) / "proj"; root.mkdir(); (root / "requirements.txt").write_text("unrelated==1.0\n")
        rec = Path(self.tmp.name) / "fresh-records"; cli.OUT = rec
        self.assertEqual(self.run_cli("project", str(root), "--cve", "CVE-2099-0001", "-q")[0], 0)
        self.assertFalse(rec.exists()); self.assertTrue(cli.pace_path().exists())

    # ---- one record under a race
    def test_a_finding_is_written_once_when_eight_runs_race_to_record_it(self):
        rec = {"event": "found", "ref": "CVE-2099-0009", "on": "2026-11-04", "title": "t", "why": "w", "kind": "kev"}
        wrote = []
        ts = [threading.Thread(target=lambda: wrote.append(cli.append_found_once(dict(rec)))) for _ in range(8)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(sum(wrote), 1)
        self.assertEqual(len((cli.OUT / "findings.jsonl").read_text().splitlines()), 1)

    def test_a_manual_or_different_finding_does_not_block_a_new_one(self):
        self.assertTrue(cli.append_found_once({"event": "found", "ref": "CVE-2099-0010"}))
        self.assertTrue(cli.append_found_once({"event": "found", "ref": "CVE-2099-0011"}))
        self.assertFalse(cli.append_found_once({"event": "found", "ref": "CVE-2099-0010"}))

    # ---- no arguments
    def test_no_arguments_runs_discover_weekly(self):
        # owner decision 2026-11-08: the bare command is --discover --weekly (it was the daily list)
        Entry.feed = feed([exp("CVE-2099-0001")], daily=([exp("CVE-2099-0005", vendor="Otherco", product="Otherthing")], []))
        rc, out, err = self.run_cli()
        self.assertEqual(rc, 0, err)
        self.assertIn("--discover --weekly", err); self.assertIn("(weekly, 2026-10-29 to 2026-11-04)", out)
        self.assertIn("CVE-2099-0001", out)
        self.assertEqual(self.lattice_reads(), 2)                        # the one candidate: a lookup and a detail read

    def test_only_a_quiet_flag_still_means_no_arguments(self):
        Entry.feed = feed([exp("CVE-2099-0001")], daily=([exp("CVE-2099-0001")], []))
        rc, out, err = self.run_cli("-q")
        self.assertEqual(rc, 0, err); self.assertIn("CANDIDATE", out); self.assertEqual(err, "")

    def test_any_argument_still_does_what_it_names(self):
        Entry.feed = feed([exp("CVE-2099-0001")])
        _, out, _ = self.run_cli("recent")                                # explicit recent is still weekly
        self.assertIn("CANDIDATE", out)
        Stub_seen_before = len(__import__("test_lattice_scan").Stub.seen)
        rc, out, _ = self.run_cli("--refresh", "--inventory")                            # inventory only: no feed, no Lattice call
        self.assertEqual(rc, 0); self.assertEqual(len(__import__("test_lattice_scan").Stub.seen), Stub_seen_before)
        rc, out, err = self.run_cli("--discover", "--daily")              # no key needed: the same engine as `recent --daily`
        self.assertEqual(rc, 0, err); self.assertNotIn("needs a key", err); self.assertIn("(daily,", out)


if __name__ == "__main__":
    unittest.main()
