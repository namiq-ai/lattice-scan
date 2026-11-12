# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The one report a run makes: that a scan ran. Its whole content, when it is off, and that it never breaks a run. A local server stands in for namiq.io."""
import json, os, sys, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import __version__, cli  # noqa: E402

GOT: list[tuple[str, dict]] = []


class Sink(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        GOT.append((self.headers.get("User-Agent", ""), json.loads(self.rfile.read(n) or b"{}")))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):
        pass


class RunReport(unittest.TestCase):
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
        self.env = mock.patch.dict(os.environ, {"LATTICE_SCAN_NO_REPORT": "", "LATTICE_SCAN_TEST": ""})
        self.env.start()
        self.on = mock.patch.object(cli, "report_enabled", return_value=True)
        self.url_patch = mock.patch.object(cli, "RUN_URL", self.url)
        self.marker = mock.patch.object(cli, "note_report_once", lambda: None)
        self.tmp = tempfile.TemporaryDirectory()   # the kept-note file must never be the real cache folder's
        self.cache = mock.patch.object(cli, "cache_dir", lambda: Path(self.tmp.name))
        for p in (self.on, self.url_patch, self.marker, self.cache):
            p.start()

    def tearDown(self):
        mock.patch.stopall()
        self.tmp.cleanup()

    def test_the_body_is_three_fields_and_names_nothing_of_the_host(self):
        with mock.patch.object(cli, "LOOKUPS", 12):
            self.assertTrue(cli.report_run("recent", 0))
        ua, body = GOT[0]
        self.assertEqual(body, {"command": "recent", "result": "ok", "lookups": "6-20"})
        self.assertEqual(ua, f"lattice-scan/{__version__}")

    def test_results_and_bands_and_an_unknown_command(self):
        for rc, want in ((0, "ok"), (1, "matched"), (3, "stopped"), (2, "failed"), (130, "failed")):
            self.assertEqual(cli.report_body("scan", rc)["result"], want)
        for n, want in ((0, "0"), (1, "1-5"), (5, "1-5"), (6, "6-20"), (21, "21-100"), (101, "100+")):
            self.assertEqual(cli.lookup_band(n), want)
        self.assertEqual(cli.report_body("some-private-subcommand", 0)["command"], "other")   # a name we did not list is never sent as typed

    def test_a_test_run_is_marked_in_the_user_agent(self):
        with mock.patch.dict(os.environ, {"LATTICE_SCAN_TEST": "1"}):
            cli.report_run("scan", 0)
        self.assertEqual(GOT[0][0], f"lattice-scan/{__version__} (test)")

    def test_a_dead_server_is_silent_and_fast(self):
        with mock.patch.object(cli, "RUN_URL", "http://127.0.0.1:9/lattice/run"):
            self.assertFalse(cli.report_run("scan", 0, timeout=1))

    def test_the_body_never_holds_what_the_tool_found(self):
        with mock.patch.object(cli, "LOOKUPS", 3):
            text = json.dumps(cli.report_body("project", 1))
        for word in ("CVE-", "/home", "etc", "192.", "key", "package"):
            self.assertNotIn(word, text)


class SwitchedOff(unittest.TestCase):
    def check(self, env: dict, **patch):
        patch = patch or {"LOOKUPS": cli.LOOKUPS}   # patch.multiple needs at least one name
        merged = {"LATTICE_SCAN_NO_REPORT": "", "LATTICE_SCAN_REPORT_FORCE": "1", **env}
        with mock.patch.dict(os.environ, merged), mock.patch.multiple(cli, **patch):
            return cli.report_enabled()

    def test_on_by_default_when_nothing_says_otherwise(self):
        self.assertTrue(self.check({}))

    def test_off_by_the_tools_own_switch_only(self):
        self.assertFalse(self.check({"LATTICE_SCAN_NO_REPORT": "1"}))
        self.assertTrue(self.check({"DO_NOT_TRACK": "1"}))   # not read: the tool has its own switch

    def test_off_for_a_self_hosted_lattice_or_feed(self):
        self.assertFalse(self.check({}, URL="https://lattice.corp.example.test/mcp"))
        self.assertFalse(self.check({}, FEED_URL="https://feeds.corp.example.test/recent.json"))

    def test_off_under_a_test_runner_unless_forced(self):
        with mock.patch.dict(os.environ, {"LATTICE_SCAN_NO_REPORT": "", "LATTICE_SCAN_REPORT_FORCE": ""}):
            self.assertFalse(cli.report_enabled())          # unittest is imported here


if __name__ == "__main__":
    unittest.main()


class OsFamily(unittest.TestCase):
    def test_the_note_carries_only_the_family_word(self):
        for plat, want in (("linux", "linux"), ("darwin", "macos")):
            with mock.patch.object(cli.sys, "platform", plat):
                self.assertEqual(cli.report_body("scan", 0)["os"], want)
        with mock.patch.object(cli.sys, "platform", "win32"):
            self.assertNotIn("os", cli.report_body("scan", 0))   # any other system sends no os field at all
        self.assertEqual(set(cli.report_body("scan", 0)), {"command", "result", "lookups", "os"})

    def test_a_kept_note_keeps_only_a_valid_family(self):
        cli.queue_save([{"command": "scan", "result": "ok", "lookups": "0", "day": cli.dt.datetime.now(cli.dt.timezone.utc).date().isoformat(), "os": "macOS 15.3"}])
        self.assertNotIn("os", cli.queue_load()[0])
