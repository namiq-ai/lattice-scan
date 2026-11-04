# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""0.3.0: how an agent with no CVE id gets started (`recent`), how it checks ids it already holds (`enrich`), and how a real person's key is requested (`get-key`).
Standard library only; invented products and reserved ids (CVE-2099-*); no real name, mailbox or key."""
import contextlib, io, json, os, stat, sys, tempfile, threading, unittest
from http.server import HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli  # noqa: E402
from test_lattice_scan import INV, Stub, lookup  # noqa: E402

cli.RETRY_DELAYS = (0.0, 0.0)
FAKE_KEY = "lat_test_0000000000000000"


class Entry(Stub):
    feed: object = None
    key_status = 201
    key_bodies: list = []

    def do_GET(self):
        if self.path == "/recent.json":
            body = json.dumps(Entry.feed).encode()
        elif self.path == "/openapi.json":
            body = json.dumps({"components": {"schemas": {"AgentKeyRequest": {"properties": {"terms": {"properties": {"version": {"const": "terms-test-1"}}}}}}}}).encode()
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)

    rate_left = 0                                    # answer this many tools/call requests with HTTP 429 first
    rate_body = '{"jsonrpc": "2.0", "id": 1, "error": {"code": -32002, "message": "Too many keyless requests. Retry after 3 seconds, or get a key"}}'
    rate_header = None
    rate_seen = 0                                    # how many tools/call requests reached the server

    def do_POST(self):
        if self.path == "/mcp":
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            is_call = b'"tools/call"' in raw
            if is_call:
                Entry.rate_seen += 1
            if is_call and Entry.rate_left > 0:
                Entry.rate_left -= 1
                self.send_response(429); self.send_header("Content-Type", "application/json")
                if Entry.rate_header: self.send_header("Retry-After", Entry.rate_header)
                self.end_headers(); self.wfile.write(Entry.rate_body.encode()); return
            import io   # answer it as the normal stub would, from the bytes already read
            self.rfile = io.BytesIO(raw); self.headers.replace_header("Content-Length", str(len(raw)))
            return super().do_POST()
        if self.path != "/keys":
            return super().do_POST()
        Entry.key_bodies.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        resp = {201: {"ok": True, "key": FAKE_KEY, "key_id": "k-test", "tier": "beta", "expires_at": "2027-01-01T00:00:00Z", "next": ["Open the email."]},
                202: {"ok": True, "queued": True},
                400: {"ok": False, "error": "email_not_accepted", "message": "use a mailbox a person reads", "issues": [{"path": "principal.email", "message": "role address"}]}}[Entry.key_status]
        raw = json.dumps(resp).encode()
        self.send_response(Entry.key_status); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(raw)


def feed(exploited=(), critical=(), schema="lattice-recent/3", daily=None, open_=None):
    """A weekly list of everything given; the daily list is `daily` (an (exploited, critical) pair) or empty; `open_` is the list of older exploited entries (schema 3)."""
    d_e, d_c = daily if daily is not None else ((), ())
    f = {"schema": schema, "generatedAt": "2026-11-04T00:00:00+00:00", "builtAt": "2026-11-04T01:00:00Z", "exploitedAsOf": "2026-11-03", "note": "n",
         "daily": {"from": "2026-11-03", "to": "2026-11-04", "exploited": list(d_e), "critical": list(d_c)},
         "weekly": {"from": "2026-10-29", "to": "2026-11-04", "exploited": list(exploited), "critical": list(critical)}}
    if open_ is not None:
        f["open"] = {"windowDays": 30, "from": "2026-10-06", "to": "2026-11-04", "exploited": list(open_)}
    return f


def exp(cve, vendor="Exampleco", product="Examplelib", **kw):
    return {"id": cve, "vendor": vendor, "product": product, "added": "2026-11-03", "due": "2026-11-06", "ransomware": "Unknown", "cvss": 9.8, "epss": 0.1, "priority": "today", **kw}


class EntryBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Entry)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (cli.URL, cli.KEY, cli.OUT, cli.TODAY, cli.WINDOW, cli.inventory, cli.PROGRESS, cli.FEED_URL, cli.KEY_API, cli.TERMS_DOC)
        cli.URL, cli.KEY, cli.OUT, cli.TODAY, cli.WINDOW = f"{self.base}/mcp", "", Path(self.tmp.name), "2026-11-04", 6
        self.saved_pace, cli.PACE_FILE = cli.PACE_FILE, Path(self.tmp.name + ".pace.json")   # call times are remembered per test, not shared
        cli.FEED_URL, cli.KEY_API, cli.TERMS_DOC = f"{self.base}/recent.json", f"{self.base}/keys", f"{self.base}/openapi.json"
        cli.inventory = lambda: dict(INV)
        Stub.mode, Stub.seen, Stub.tier = "json", [], "keyless"
        Stub.answers = {"CVE-2099-0001": lookup("CVE-2099-0001"), "CVE-2099-0005": lookup("CVE-2099-0005", product="Otherthing", vendor="Otherco")}
        Entry.feed, Entry.key_status, Entry.key_bodies = feed(), 201, []
        Entry.rate_left, Entry.rate_header, Entry.rate_seen = 0, None, 0
        Entry.rate_body = '{"jsonrpc": "2.0", "id": 1, "error": {"code": -32002, "message": "Too many keyless requests. Retry after 3 seconds, or get a key"}}'
        cli.Lattice.last_gap = 0.0
        p = mock.patch.object(cli.time, "sleep")   # the keyless pacing (12.5 s a call) is not what these tests are about
        p.start(); self.addCleanup(p.stop)

    def tearDown(self):
        (cli.URL, cli.KEY, cli.OUT, cli.TODAY, cli.WINDOW, cli.inventory, cli.PROGRESS, cli.FEED_URL, cli.KEY_API, cli.TERMS_DOC) = self.saved
        cli.PACE_FILE = self.saved_pace; Path(self.tmp.name + ".pace.json").unlink(missing_ok=True)
        self.tmp.cleanup()

    def run_cli(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        sys.argv = ["lattice-scan", *argv]
        old_in = sys.stdin
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = cli.main()
        finally:
            sys.stdin = old_in
        return rc, out.getvalue(), err.getvalue()

    def lattice_reads(self):
        return sum(1 for m, _, _ in Stub.seen if m == "tools/call")


class AgentEntry(EntryBase):
    # ---- recent
    def test_recent_reads_only_what_may_match_this_host(self):
        Entry.feed = feed([exp("CVE-2099-0001"), exp("CVE-2099-0005", vendor="Otherco", product="Otherthing")],
                          [{"id": "CVE-2099-0003", "vendor": "Exampleco", "product": "Examplelib", "cvss": 9.8, "published": "2026-11-04"},
                           {"id": "CVE-2099-0004", "vendor": "Zzzco", "product": "Zzzthing", "cvss": 9.9, "published": "2026-11-04"}])
        rc, out, err = self.run_cli("recent")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.lattice_reads(), 1)                       # only the id that may match was sent to Lattice
        row = {l.split()[0]: l for l in out.splitlines() if l.startswith("CVE-2099")}
        self.assertIn("CANDIDATE", row["CVE-2099-0001"])
        self.assertIn("unmatch", row["CVE-2099-0005"]); self.assertIn("not sent to Lattice", row["CVE-2099-0005"])
        self.assertIn("WATCH", row["CVE-2099-0003"]); self.assertIn("not known exploited", row["CVE-2099-0003"])
        self.assertNotIn("CVE-2099-0004", out)                          # a critical id that cannot match this host is not listed
        self.assertIn("weekly list 2026-10-29 to 2026-11-04: 2 exploited and 2 critical ids", err)

    def test_recent_with_no_match_sends_nothing_to_lattice_and_says_it_is_not_safe(self):
        Entry.feed = feed([exp("CVE-2099-0005", vendor="Otherco", product="Otherthing")])
        rc, out, _ = self.run_cli("recent")
        self.assertEqual(rc, 0)
        self.assertEqual(self.lattice_reads(), 0)
        self.assertEqual([m for m, _, _ in Stub.seen], [])
        self.assertIn("nothing was sent to Lattice", out); self.assertIn("not the same as safe", out)

    def test_recent_daily_reads_only_the_daily_list(self):
        Entry.feed = feed([exp("CVE-2099-0001"), exp("CVE-2099-0005", vendor="Otherco", product="Otherthing")], daily=([exp("CVE-2099-0005", vendor="Otherco", product="Otherthing")], []))
        rc, out, err = self.run_cli("recent", "--daily")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.lattice_reads(), 0)                       # the id that matches this host is only in the weekly list
        self.assertIn("(daily, 2026-11-03 to 2026-11-04)", out); self.assertNotIn("CVE-2099-0001", out)
        rc, out, _ = self.run_cli("recent", "--period", "weekly")
        self.assertIn("CANDIDATE", out); self.assertEqual(self.lattice_reads(), 1)

    def test_recent_defaults_to_the_weekly_list(self):
        Entry.feed = feed([exp("CVE-2099-0001")])
        rc, out, _ = self.run_cli("recent")
        self.assertEqual(rc, 0); self.assertIn("CANDIDATE", out)

    def test_recent_refuses_the_first_version_of_the_list(self):
        Entry.feed = {"schema": "lattice-recent/1", "exploited": [], "critical": []}
        rc, _, err = self.run_cli("recent")
        self.assertEqual(rc, 1); self.assertIn("lattice-recent/2 and later", err)

    def test_recent_refuses_a_list_that_is_not_one(self):
        for bad in ("something-else/3", "lattice-recent/x", None):
            with self.subTest(bad):
                Entry.feed = feed(schema=bad)
                rc, _, err = self.run_cli("recent")
                self.assertEqual(rc, 1); self.assertIn("Upgrade lattice-scan", err)

    def test_recent_reads_version_2_and_3_and_a_later_version_that_only_adds_fields(self):
        for schema in ("lattice-recent/2", "lattice-recent/3", "lattice-recent/7"):
            with self.subTest(schema):
                Entry.feed = feed([exp("CVE-2099-0001")], schema=schema)
                Entry.feed["somethingNew"] = {"later": True}
                Stub.seen.clear()
                rc, out, err = self.run_cli("recent")
                self.assertEqual(rc, 0, err); self.assertRegex(out, r"CANDIDATE|RECORDED")   # the second pass sees the first one's record

    def test_recent_open_reads_the_older_overdue_exploited_entries(self):
        older = exp("CVE-2099-0001", added="2026-10-20", due="2026-10-23", overdue=True, daysOverdue=12)
        Entry.feed = feed([exp("CVE-2099-0005", vendor="Otherco", product="Otherthing")], open_=[older])
        rc, out, err = self.run_cli("recent", "--open")
        self.assertEqual(rc, 0, err)
        self.assertIn("open list 2026-10-06 to 2026-11-04: 1 exploited", err)
        row = {l.split()[0]: l for l in out.splitlines() if l.startswith("CVE-2099")}
        self.assertIn("CANDIDATE", row["CVE-2099-0001"])
        self.assertNotIn("CVE-2099-0005", out)                          # the weekly list is not mixed in
        self.assertEqual(self.lattice_reads(), 1)
        rc, _, _ = self.run_cli("recent", "--period", "open")
        self.assertEqual(rc, 0)

    def test_recent_open_with_nothing_that_matches_shows_the_feeds_dates_and_the_period(self):
        Entry.feed = feed(open_=[exp("CVE-2099-0005", vendor="Otherco", product="Otherthing", added="2026-10-20", due="2026-10-23")])
        rc, out, _ = self.run_cli("recent", "--open")
        self.assertEqual(rc, 0); self.assertEqual(self.lattice_reads(), 0)
        self.assertIn("(open, 2026-10-06 to 2026-11-04)", out); self.assertIn("2026-10-23", out)

    def test_recent_open_on_a_list_without_it_says_to_upgrade_or_use_daily_or_weekly(self):
        Entry.feed = feed([exp("CVE-2099-0001")], schema="lattice-recent/2")     # version 2 has no open list
        rc, _, err = self.run_cli("recent", "--open")
        self.assertEqual(rc, 1); self.assertIn("has no open list", err); self.assertIn("daily or weekly", err)

    def test_recent_refuses_a_plain_http_list_from_elsewhere(self):
        cli.FEED_URL = "http://example.invalid/recent.json"
        rc, _, err = self.run_cli("recent")
        self.assertEqual(rc, 1); self.assertIn("not https", err)

    def test_recent_treats_feed_text_as_data(self):
        Entry.feed = feed([exp("CVE-2099-0005", vendor="Evil\x1b[31mco", product="Otherthing")])
        _, out, err = self.run_cli("recent")
        self.assertNotIn("\x1b", out + err)

    def test_recent_ignores_rows_that_are_not_cve_ids(self):
        Entry.feed = feed([exp("not-a-cve"), exp("CVE-2099-0005", vendor="Otherco", product="Otherthing")])
        _, out, _ = self.run_cli("recent")
        self.assertNotIn("not-a-cve", out)

    # ---- enrich
    def test_enrich_finds_ids_in_any_text_and_reads_each_once(self):
        text = "npm audit: cve-2099-0001 high; see also CVE-2099-0001 and CVE-2099-0002 (not listed). Ref CVE-2099-12."
        rc, out, _ = self.run_cli("enrich", stdin=text)
        self.assertEqual(rc, 0)
        self.assertEqual(self.lattice_reads(), 2)                       # CVE-2099-12 is too short to be an id; the repeat is read once
        rows = [l for l in out.splitlines() if l.startswith("CVE-2099")]
        self.assertIn("EXPLOITED", rows[0]); self.assertIn("CVE-2099-0001", rows[0])      # exploited first
        self.assertIn("unlisted", rows[1])
        self.assertFalse((cli.OUT / "findings.jsonl").exists())          # enrich writes no records about this host
        self.assertNotIn("INV", out)

    def test_enrich_fail_on_exploited(self):
        rc, _, _ = self.run_cli("enrich", "--cve", "CVE-2099-0001", "--fail-on", "exploited")
        self.assertEqual(rc, 1)

    def test_enrich_with_no_ids_is_a_usage_error_and_does_not_wait_for_stdin(self):
        rc, _, err = self.run_cli("enrich", "--cve", "nothing here", stdin="CVE-2099-0001")   # stdin is ignored when --cve was given
        self.assertEqual(rc, 2); self.assertIn("no CVE ids found", err); self.assertEqual(self.lattice_reads(), 0)

    def test_enrich_stops_at_the_quota_and_lists_what_it_did_not_read(self):
        Stub.mode = "quota"
        rc, out, err = self.run_cli("enrich", "--cve", "CVE-2099-0001,CVE-2099-0002")
        self.assertEqual(rc, 3)
        self.assertIn("stopped:", err); self.assertIn("not read", out); self.assertIn("get-key", out)

    def test_enrich_caps_a_keyless_run(self):
        ids = ",".join(f"CVE-2099-{n:04d}" for n in range(1, 26))
        _, out, _ = self.run_cli("enrich", "--cve", ids, "--max-read", "2")
        self.assertEqual(self.lattice_reads(), 2)
        self.assertEqual(out.count("over the limit for one run"), 23)

    # ---- get-key
    ARGS = ("get-key", "--name", "Ana Example", "--position", "Engineer", "--company", "Example Co", "--email", "ana@example.com",
            "--purpose", "Check our servers against exploited CVEs.")

    def test_get_key_sends_nothing_without_the_terms_being_accepted(self):
        rc, _, err = self.run_cli(*self.ARGS)
        self.assertEqual(rc, 2); self.assertEqual(Entry.key_bodies, [])
        self.assertIn("--accept-terms", err); self.assertIn("ana@example.com", err)

    def test_get_key_stores_the_key_privately_and_never_prints_it(self):
        rc, out, err = self.run_cli(*self.ARGS, "--accept-terms")
        self.assertEqual(rc, 0, err)
        body = Entry.key_bodies[0]
        self.assertEqual(body["terms"], {"version": "terms-test-1", "accepted": True})
        self.assertEqual(body["principal"]["email"], "ana@example.com"); self.assertTrue(body["consent"])
        self.assertEqual(body["agent"]["name"], "lattice-scan")
        f = cli.OUT / "key"
        self.assertEqual(f.read_text().strip(), FAKE_KEY)
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
        self.assertNotIn(FAKE_KEY, out + err)
        self.assertIn("k-test", out); self.assertIn("confirmation email", out)

    def test_get_key_does_not_ask_twice_for_the_same_person(self):
        self.run_cli(*self.ARGS, "--accept-terms")
        rc, _, err = self.run_cli(*self.ARGS, "--accept-terms")
        self.assertEqual(rc, 2); self.assertEqual(len(Entry.key_bodies), 1); self.assertIn("already stored", err)

    def test_get_key_reports_a_refusal_and_stores_nothing(self):
        Entry.key_status = 400
        rc, out, err = self.run_cli(*self.ARGS, "--accept-terms")
        self.assertEqual(rc, 1); self.assertFalse((cli.OUT / "key").exists())
        self.assertIn("email_not_accepted", err); self.assertIn("principal.email", err)

    def test_get_key_stops_when_the_address_asked_not_to_be_contacted(self):
        Entry.key_status = 202
        rc, _, err = self.run_cli(*self.ARGS, "--accept-terms")
        self.assertEqual(rc, 1); self.assertIn("do not try again", err); self.assertFalse((cli.OUT / "key").exists())

    def test_a_stored_key_is_used_only_while_it_is_private(self):
        (cli.OUT / "key").write_text(FAKE_KEY + "\n"); os.chmod(cli.OUT / "key", 0o600)
        self.assertEqual(cli.saved_key(), FAKE_KEY)
        os.chmod(cli.OUT / "key", 0o644)
        self.assertEqual(cli.saved_key(), "")


if __name__ == "__main__":
    unittest.main()
