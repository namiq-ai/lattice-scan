# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The run note keeps while namiq.io cannot be reached and is sent with the next online run: bounded, expiring, the same three fields plus the day, silent on failure."""
import datetime as dt, json, os, socket, stat, sys, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli  # noqa: E402

GOT: list[dict] = []


class Sink(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        GOT.append(json.loads(self.rfile.read(n) or b"{}"))
        self.send_response(204); self.end_headers()

    def log_message(self, *a):
        pass


def day(back=0):
    return (dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=back)).isoformat()


class Queue(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Sink)
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}/lattice/run"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        GOT.clear()
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        for p in (mock.patch.dict(os.environ, {"LATTICE_SCAN_NO_REPORT": "", "LATTICE_SCAN_TEST": ""}),
                  mock.patch.object(cli, "cache_dir", lambda: Path(self.tmp.name)),
                  mock.patch.object(cli, "report_enabled", return_value=True),
                  mock.patch.object(cli, "RUN_URL", self.url),
                  mock.patch.object(cli, "note_report_once", lambda: None),
                  mock.patch.object(cli, "LOOKUPS", 3)):
            p.start(); self.addCleanup(p.stop)

    def queue(self):
        return cli.queue_load()

    def test_offline_makes_no_connection_and_keeps_the_note(self):
        with mock.patch.object(cli, "OFFLINE", True), mock.patch.object(socket, "socket", side_effect=AssertionError("connection")):
            self.assertFalse(cli.report_run("recent", 0))
        self.assertEqual(GOT, [])
        self.assertEqual(self.queue(), [{"command": "recent", "result": "ok", "lookups": "1-5", "day": day()}])
        self.assertEqual(stat.S_IMODE(cli.report_queue_path().stat().st_mode), 0o600)

    def test_the_next_online_run_sends_the_kept_notes_oldest_first_then_its_own(self):
        cli.queue_save([{"command": "scan", "result": "ok", "lookups": "0", "day": day(2)}, {"command": "enrich", "result": "stopped", "lookups": "1-5", "day": day(1)}])
        self.assertTrue(cli.report_run("recent", 1))
        self.assertEqual(GOT, [{"command": "scan", "result": "ok", "lookups": "0", "day": day(2)},
                               {"command": "enrich", "result": "stopped", "lookups": "1-5", "day": day(1)},
                               {"command": "recent", "result": "matched", "lookups": "1-5"}])   # today's own note carries no day
        self.assertEqual(self.queue(), [])
        self.assertFalse(cli.report_queue_path().exists())

    def test_a_failed_send_keeps_everything_and_never_raises(self):
        cli.queue_save([{"command": "scan", "result": "ok", "lookups": "0", "day": day(1)}])
        with mock.patch.object(cli, "RUN_URL", "http://127.0.0.1:9/lattice/run"):
            self.assertFalse(cli.report_run("recent", 0))
        self.assertEqual([e["command"] for e in self.queue()], ["scan", "recent"])

    def test_after_a_network_failure_in_the_run_the_note_is_kept(self):
        with mock.patch.object(cli, "NET_DOWN", True):
            cli.report_run("project", 3)
        self.assertEqual(GOT, []); self.assertEqual(self.queue()[0]["result"], "stopped")

    def test_bounded_in_number_and_age_and_junk_is_ignored(self):
        old = {"command": "scan", "result": "ok", "lookups": "0", "day": day(31)}
        rows = [json.dumps(old), "{damaged", json.dumps({"command": "scan", "result": "ok", "lookups": "0", "day": day(), "host": "x"}),
                json.dumps({"command": "rm -rf", "result": "ok", "lookups": "0", "day": day()}), json.dumps({"command": "scan", "result": "ok", "lookups": "7", "day": day()})]
        cli.report_queue_path().write_text("\n".join(rows))
        self.assertEqual(len(self.queue()), 1)                       # the old, damaged, unknown-command and bad-band rows are dropped; the extra field is not kept
        self.assertNotIn("host", self.queue()[0])
        cli.queue_save([{"command": "scan", "result": "ok", "lookups": "0", "day": day()}] * 80)
        self.assertEqual(len(self.queue()), cli.QUEUE_MAX)

    def test_a_long_gap_sends_at_most_a_few_late_notes_per_run(self):
        cli.queue_save([{"command": "scan", "result": "ok", "lookups": "0", "day": day(1)}] * 40)
        cli.report_run("recent", 0)
        self.assertEqual(len(GOT), cli.QUEUE_SEND_MAX + 1)
        self.assertEqual(len(self.queue()), 41 - (cli.QUEUE_SEND_MAX + 1))

    def test_switched_off_keeps_nothing(self):
        with mock.patch.object(cli, "report_enabled", return_value=False), mock.patch.object(cli, "OFFLINE", True):
            cli.report_run("recent", 0)
        self.assertEqual(self.queue(), [])


if __name__ == "__main__":
    unittest.main()
