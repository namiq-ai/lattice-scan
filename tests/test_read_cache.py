# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The read cache, server-driven pacing, most-urgent-first order and the estimate line (OCO-5881, ADR-LATTICE-ANON-002 section 6). Invented ids; no network."""
import json, sys, tempfile, time, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli  # noqa: E402

ANSWER = {"snapshot": "s1", "items": [{"id": "CVE-2099-0001", "uid": "u1", "source": "kev", "title": "t"}]}


def reply(data, access=None):
    body = dict(data, **({"access": access} if access else {}))
    return {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": json.dumps(body)}]}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.patches = [mock.patch.object(cli, "CACHE_FILE", t / "read-cache.json"), mock.patch.object(cli, "PACE_FILE", t / "pace.json"),
                        mock.patch.object(cli, "KEY", ""), mock.patch.dict("os.environ", {"LATTICE_SCAN_READ_CACHE": "on"}, clear=False)]
        for p in self.patches:
            p.start()
        self.posts = []

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def lat(self, answers):
        """A Lattice whose server answers from `answers` (a list, one per call) and records what it was asked."""
        it = iter(answers)

        def post(body):
            self.posts.append(body)
            return next(it)
        l = cli.Lattice()
        l._post = post
        return l


class ReadCache(Base):
    def test_the_same_lookup_twice_asks_the_server_once(self):
        l = self.lat([reply(ANSWER)])
        with mock.patch.object(cli, "pace_wait", lambda *a: 0.0):
            first = l.call("graph_lookup", id="CVE-2099-0001")
            second = l.call("graph_lookup", id="cve-2099-0001")        # the id is compared in upper case
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(first, second)
        self.assertEqual(l.cached, 1)

    def test_a_node_read_is_cached_by_uid_and_other_tools_are_not(self):
        l = self.lat([reply({"properties": {"x": 1}}), reply({"properties": {"x": 1}}), reply({"snapshot": "s"}), reply({"snapshot": "s"})])
        with mock.patch.object(cli, "pace_wait", lambda *a: 0.0):
            l.call("graph_node", uid="u1"); l.call("graph_node", uid="u1")
            l.call("graph_meta"); l.call("graph_meta")
        self.assertEqual([p["params"]["name"] for p in self.posts], ["graph_node", "graph_meta", "graph_meta"])

    def test_an_old_answer_is_asked_again(self):
        l = self.lat([reply(ANSWER), reply(ANSWER)])
        with mock.patch.object(cli, "pace_wait", lambda *a: 0.0):
            l.call("graph_lookup", id="CVE-2099-0001")
            d = json.loads(cli.read_cache_path().read_text())
            d["entries"]["lookup:CVE-2099-0001"]["at"] = time.time() - 7 * 3600     # older than the 6 hours
            cli.read_cache_path().write_text(json.dumps(d))
            l.call("graph_lookup", id="CVE-2099-0001")
        self.assertEqual(len(self.posts), 2)

    def test_off_and_the_hours_setting_are_followed(self):
        l = self.lat([reply(ANSWER), reply(ANSWER)])
        with mock.patch.object(cli, "pace_wait", lambda *a: 0.0), mock.patch.dict("os.environ", {"LATTICE_SCAN_READ_CACHE": "off"}):
            l.call("graph_lookup", id="CVE-2099-0001"); l.call("graph_lookup", id="CVE-2099-0001")
        self.assertEqual(len(self.posts), 2)
        self.assertFalse(cli.read_cache_path().exists())
        with mock.patch.dict("os.environ", {"LATTICE_SCAN_READ_CACHE_HOURS": "0"}):
            self.assertEqual(cli.read_cache_hours(), 0.0)

    def test_an_error_answer_is_never_kept(self):
        l = self.lat([reply({"error": "quota_exceeded", "message": "later"}), reply(ANSWER)])
        with mock.patch.object(cli, "pace_wait", lambda *a: 0.0):
            with self.assertRaises(cli.LatticeError):
                l.call("graph_lookup", id="CVE-2099-0001")
            self.assertEqual(l.call("graph_lookup", id="CVE-2099-0001")["items"][0]["uid"], "u1")
        self.assertEqual(len(self.posts), 2)

    def test_a_cached_answer_costs_no_waiting_and_no_pace_note(self):
        l = self.lat([reply(ANSWER)])
        with mock.patch.object(cli, "pace_wait", lambda *a: 0.0):
            l.call("graph_lookup", id="CVE-2099-0001")
        with mock.patch.object(cli, "pace_wait", side_effect=AssertionError("waited")), mock.patch.object(cli, "pace_note", side_effect=AssertionError("noted")):
            l.call("graph_lookup", id="CVE-2099-0001")

    def test_the_cache_is_bounded_and_returns_a_copy(self):
        for i in range(cli.READ_CACHE_MAX + 20):
            cli.read_cache_put("graph_lookup", {"id": f"CVE-2099-{i:05d}"}, {"snapshot": "s", "items": []})
        self.assertLessEqual(len(json.loads(cli.read_cache_path().read_text())["entries"]), cli.READ_CACHE_MAX)
        l = self.lat([reply(ANSWER)])
        with mock.patch.object(cli, "pace_wait", lambda *a: 0.0):
            a = l.call("graph_lookup", id="CVE-2099-0001")
            a["items"].clear()                                         # a caller changing its copy must not change the cache
            self.assertTrue(l.call("graph_lookup", id="CVE-2099-0001")["items"])

    def test_a_damaged_cache_file_is_ignored(self):
        cli.read_cache_path().write_text("{not json")
        l = self.lat([reply(ANSWER)])
        with mock.patch.object(cli, "pace_wait", lambda *a: 0.0):
            self.assertTrue(l.call("graph_lookup", id="CVE-2099-0001")["items"])


class ServerPacing(Base):
    def test_the_default_is_five_until_the_server_says_otherwise(self):
        self.assertEqual(cli.pace_calls(), 5)

    def test_a_reported_limit_is_remembered_and_followed(self):
        l = self.lat([reply(ANSWER, access={"limits": {"calls_per_minute": 10, "units_per_hour": 60}})])
        with mock.patch.object(cli, "pace_wait", lambda *a: 0.0):
            l.call("graph_lookup", id="CVE-2099-0001")
        self.assertEqual(cli.pace_calls(), 10)
        now = 1000.0
        times = [now - i for i in range(1, 10)]                         # nine calls in the last nine seconds
        with mock.patch.object(cli, "pace_times", lambda: times):
            self.assertEqual(cli.pace_wait(now), 0.0)                   # a tenth is allowed at 10 a minute ...
        times.append(now - 0.5)
        with mock.patch.object(cli, "pace_times", lambda: times):
            self.assertGreater(cli.pace_wait(now), 0.0)                 # ... an eleventh waits

    def test_nonsense_or_a_stale_limit_is_ignored(self):
        for bad in (0, -3, 100000, "many", None, True):
            cli.pace_learn({"limits": {"calls_per_minute": bad}})
        self.assertEqual(cli.pace_calls(), 5 if not cli.limits_path().exists() else cli.pace_calls())
        cli.limits_path().write_text(json.dumps({"calls_per_minute": 12, "seen": time.time() - 8 * 86400}))
        self.assertEqual(cli.pace_calls(), 5)                           # older than a week
        cli.limits_path().write_text("garbage")
        self.assertEqual(cli.pace_calls(), 5)


class Order(Base):
    def test_ransomware_then_overdue_then_priority_then_epss(self):
        rows = {"a": {"id": "a", "priority": "cycle", "epss": 0.9},
                "b": {"id": "b", "priority": "today", "epss": 0.1},
                "c": {"id": "c", "priority": "today", "epss": 0.5, "overdue": True},
                "d": {"id": "d", "priority": "week", "ransomware": "Known"},
                "e": {"id": "e", "priority": "today", "epss": 0.9}}
        self.assertEqual(sorted(rows, key=lambda k: cli.read_order(rows[k])), ["d", "c", "e", "b", "a"])

    def test_missing_or_odd_fields_do_not_raise(self):
        cli.read_order({}); cli.read_order({"epss": "x", "priority": 5, "overdue": None})

    def test_estimate_counts_cached_ids_and_the_minutes(self):
        cli.read_cache_put("graph_lookup", {"id": "CVE-2099-0001"}, ANSWER)
        line = cli.estimate_line("[recent]", ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"])
        self.assertIn("3 id(s)", line); self.assertIn("1 already cached", line); self.assertIn("up to 4 call(s)", line); self.assertIn("about 1 minute", line)
        self.assertIn("0 call(s)", cli.estimate_line("[recent]", ["CVE-2099-0001"]).replace("up to ", ""))

    def test_a_run_reads_the_most_urgent_id_first(self):
        feed = {"from": "a", "to": "b", "asOf": "c", "exploited": [
            {"id": "CVE-2099-0001", "vendor": "Exampleco", "product": "Examplelib", "priority": "cycle", "epss": 0.1},
            {"id": "CVE-2099-0002", "vendor": "Exampleco", "product": "Examplelib", "priority": "today", "ransomware": "Known"}], "critical": []}
        asked = []

        def fake_run(a):
            asked.extend(a.cve)
            return 0
        a = cli.argparse.Namespace(period="all", max_read=10, no_critical=True, refresh=False, list=False)
        inv = {"packages": {"libexamplelib2": "1"}, "snaps": {}, "images": [], "kernel": "", "os": "", "hash": "h", "restartRequired": False}
        with mock.patch.object(cli, "read_feed", lambda p: feed), mock.patch.object(cli, "inventory", lambda: inv), mock.patch.object(cli, "private_dir", lambda *a, **k: None), \
             mock.patch.object(cli, "cmd_run", fake_run), mock.patch.object(cli, "candidate", lambda e, i: ("matches", "libexamplelib2", "1")):
            cli.cmd_recent(a)
        self.assertEqual(asked, ["CVE-2099-0002", "CVE-2099-0001"])
        self.assertTrue(a.keep_order)


if __name__ == "__main__":
    unittest.main()
