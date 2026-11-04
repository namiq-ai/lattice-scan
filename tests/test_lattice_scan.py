"""Tests for lattice-scan. Standard library only (unittest), like the tool.

Fixtures use invented products and reserved values: CVE-2099-*, example.invalid. No real host's package list appears here. The server is a local stub
that speaks the MCP JSON-RPC shapes the tool reads, so no test touches the network or spends anyone's allowance.
"""
import contextlib, io, json, os, sys, tempfile, threading, unittest, urllib.error
from unittest import mock
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli  # noqa: E402
cli.RETRY_DELAYS = (0.0, 0.0)   # no real waiting between tries in tests

INV = {"kernel": "6.1.0-99-example", "os": "Example OS", "node": "", "restartRequired": False, "hash": "t",
       "packages": {"libexamplelib2": "2.17.1-1", "acl": "2.3"}, "snaps": {}, "images": []}


def lookup(cve, product="Examplelib", vendor="Exampleco", ranges=None, kev=True, title="Exampleco Examplelib Remote Code Execution Vulnerability"):
    items = [{"id": cve, "source": "nvd", "uid": "u-nvd", "primary": True, "title": "nvd",
              "affected_products": f"{vendor.lower()}/{product.lower()}",
              "affected_ranges": ranges if ranges is not None else [{"product": f"{vendor.lower()}/{product.lower()}", "start_including": "2.0.1", "end_excluding": "2.15.0"}]}]
    if kev:
        items.append({"id": cve, "source": "kev", "uid": "u-kev", "title": title, "vendor_project": vendor, "product": product,
                      "date_added": "2026-10-30", "due_date": "2026-11-20", "required_action": "Apply updates."})
    return {"snapshot": "s1", "items": items, "access": {"tier": "keyless", "remaining_units_this_hour": 10, "limits": {}}}


class Stub(BaseHTTPRequestHandler):
    mode = "json"           # json | sse | quota | http500
    answers: dict = {}
    seen: list = []
    other_port = 0
    tier = "keyless"

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Stub.seen.append((body.get("method"), self.headers.get("X-API-Key"), self.headers.get("User-Agent")))
        if Stub.mode == "redirect":
            self.send_response(302); self.send_header("Location", f"http://127.0.0.1:{Stub.other_port}/mcp"); self.end_headers(); return
        if Stub.mode == "http500":
            self.send_response(500); self.end_headers(); self.wfile.write(b"boom"); return
        if "id" not in body:
            self.send_response(202); self.end_headers(); return
        if body["method"] == "initialize":
            res = {"serverInfo": {"name": "stub"}}
        else:
            a = body["params"]["arguments"]
            if body["params"].get("name") == "graph_meta":
                data = {"snapshot": "s1", "access": {"tier": Stub.tier}}
            else:
                data = {"error": "quota_exceeded", "message": "daily limit reached"} if Stub.mode == "quota" else Stub.answers.get(a.get("id"), {"items": []})
            res = {"content": [{"type": "text", "text": json.dumps(data)}], "isError": False}
        payload = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": res})
        if Stub.mode == "sse":
            self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
            self.wfile.write(f"event: message\ndata: {payload}\n\n".encode()); return
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(payload.encode())


class Versions(unittest.TestCase):
    def test_upstream(self):
        self.assertEqual(cli.upstream("1:2.17.1-1ubuntu3"), (2, 17, 1))
        self.assertEqual(cli.upstream("7.0.0-41-cix"), (7, 0, 0))
        self.assertEqual(cli.upstream("v22.22.1"), (22, 22, 1))
        self.assertEqual(cli.upstream("1.33-5.fc44"), (1, 33))
        self.assertIsNone(cli.upstream("abc"))

    def test_compare_pads_zeros(self):
        self.assertEqual(cli.cmp((2, 15), (2, 15, 0)), 0)
        self.assertEqual(cli.cmp((2, 15, 1), (2, 15)), 1)

    def test_range_bounds(self):
        r = {"start_including": "6.19", "end_excluding": "7.0.10"}
        self.assertTrue(cli.in_range((6, 19), r))        # inclusive start
        self.assertTrue(cli.in_range((7, 0, 9), r))
        self.assertFalse(cli.in_range((7, 0, 10), r))    # exclusive end
        self.assertFalse(cli.in_range((6, 18, 99), r))
        self.assertTrue(cli.in_range((1, 1, 3), {"end_including": "1.1.3"}))
        self.assertFalse(cli.in_range((1, 1, 4), {"end_including": "1.1.3"}))

    def test_unjudgeable_ranges_are_none_not_false(self):
        self.assertIsNone(cli.in_range((7, 0), {"end_excluding": "2021-12-13"}))   # a date is not a version
        self.assertIsNone(cli.in_range((7, 0), {}))                                # no bounds at all

    def check(self, vers, ranges, product="Kernel", vendor="Linux"):
        return cli.version_check({"product": product, "vendor": vendor, "ranges": ranges}, vers)["verdict"]

    def test_verdicts(self):
        R = [{"product": "linux/linux_kernel", "start_including": "6.19", "end_excluding": "7.0.10"}]
        self.assertEqual(self.check(["7.0.0-41-cix"], R), "in-range")
        self.assertEqual(self.check(["7.0.10-1"], R), "outside-range")
        self.assertEqual(self.check(["abc"], R), "undetermined")
        self.assertEqual(self.check(["7.0.0"], []), "undetermined")
        self.assertEqual(self.check(["7.0.0"], R, vendor="Microsoft"), "undetermined")   # another vendor's ranges are not ours
        self.assertEqual(self.check(["7.0.0"], [{"product": "linux/linux_kernel", "end_excluding": "2021-12-13"}]), "undetermined")

    def test_one_unusable_range_prevents_outside(self):
        R = [{"product": "linux/linux_kernel", "end_excluding": "5.0"}, {"product": "linux/linux_kernel", "end_excluding": "2021-12-13"}]
        self.assertEqual(self.check(["9.0"], R), "undetermined")    # must not say 'outside' when a range could not be read


class Matching(unittest.TestCase):
    def entry(self, **k):
        return {"cve": "CVE-2099-0001", "title": "", "vendor": "", "product": "", **k}

    def test_product_match_returns_installed_versions(self):
        why, installed, vers = cli.candidate(self.entry(vendor="Exampleco", product="Examplelib2"), INV)
        self.assertEqual(installed, ["libexamplelib2 2.17.1-1"])
        self.assertEqual(vers, ["2.17.1-1"])

    def test_every_product_word_must_be_installed(self):
        self.assertIsNone(cli.candidate(self.entry(vendor="Exampleco", product="Examplelib Otherthing"), INV))

    def test_kernel(self):
        why, installed, vers = cli.candidate(self.entry(vendor="Linux", product="Kernel"), INV)
        self.assertEqual(vers, [INV["kernel"]])

    def test_title_fallback_drops_leading_vendor(self):
        self.assertIsNotNone(cli.candidate(self.entry(title="Exampleco Examplelib2 Remote Code Execution Vulnerability"), INV))

    def test_unrelated_is_none(self):
        self.assertIsNone(cli.candidate(self.entry(vendor="Other", product="Nothinginstalled"), INV))


class Inventory(unittest.TestCase):
    def collect(self, outputs):
        real = cli.run
        cli.run = lambda cmd: outputs.get(cmd[0], "")
        try:
            os.environ.pop("LATTICE_SCAN_INVENTORY", None); os.environ.pop("HOST_SCAN_INVENTORY", None)
            return cli.inventory()
        finally:
            cli.run = real

    def test_dpkg(self):
        inv = self.collect({"dpkg-query": "acl\t2.3\nexample\t1:1.0-2\n", "uname": "6.1\n"})
        self.assertEqual(inv["packages"], {"acl": "2.3", "example": "1:1.0-2"})

    def test_rpm_when_no_dpkg(self):
        inv = self.collect({"rpm": "bash\t5.2-3.fc44\n"})
        self.assertEqual(inv["packages"], {"bash": "5.2-3.fc44"})

    def test_apk_when_neither(self):
        inv = self.collect({"apk": "musl-1.2.5-r1\nssl_client-1.36.1-r31\n"})
        self.assertEqual(inv["packages"], {"musl": "1.2.5-r1", "ssl_client": "1.36.1-r31"})

    def test_hash_changes_with_packages(self):
        a = self.collect({"dpkg-query": "acl\t2.3\n"})["hash"]
        b = self.collect({"dpkg-query": "acl\t2.4\n"})["hash"]
        self.assertNotEqual(a, b)


class Client(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}/mcp"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (cli.URL, cli.KEY, cli.OUT, cli.TODAY, cli.WINDOW)
        cli.URL, cli.KEY, cli.OUT, cli.TODAY, cli.WINDOW = self.url, "", Path(self.tmp.name), "2026-11-01", 6
        self.saved_pace, cli.PACE_FILE = cli.PACE_FILE, Path(self.tmp.name + ".pace.json")   # call times are remembered per test, not shared
        Stub.mode, Stub.seen = "json", []
        Stub.answers = {"CVE-2099-0001": lookup("CVE-2099-0001")}
        self.inv = cli.inventory
        cli.inventory = lambda: dict(INV)
        cli.Lattice.last_gap = 0.0

    def tearDown(self):
        cli.URL, cli.KEY, cli.OUT, cli.TODAY, cli.WINDOW = self.saved
        cli.PACE_FILE = self.saved_pace; Path(self.tmp.name + ".pace.json").unlink(missing_ok=True)
        cli.inventory = self.inv
        self.tmp.cleanup()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        sys.argv = ["lattice-scan", *argv]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main()
        return rc, out.getvalue(), err.getvalue()

    def test_lookup_and_impact(self):
        rc, out, _ = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 0)
        self.assertIn("libexamplelib2 2.17.1-1", out)
        self.assertIn("version check: outside-range", out)         # 2.17.1 is above the listed < 2.15.0
        self.assertTrue(all(ua and ua.startswith("lattice-scan/") for _, _, ua in Stub.seen))

    def test_sse_reply_is_read(self):
        Stub.mode = "sse"
        rc, out, _ = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 0); self.assertIn("1 candidates", out)

    def test_not_listed_is_not_called_safe(self):
        rc, out, _ = self.run_cli("--cve", "CVE-2099-9999")
        self.assertIn("not 'safe'", out)

    def test_known_finding_is_shown_again_not_hidden(self):
        self.run_cli("--cve", "CVE-2099-0001")
        rc, out, _ = self.run_cli("--cve", "CVE-2099-0001", "--again")
        self.assertIn("0 candidates", out)
        self.assertIn("matches again", out)                         # the first version printed only '0 candidates' here

    def test_an_id_you_name_is_read_every_time_even_if_read_before(self):
        # Found by running the installed tool: two named ids printed '0 exploited entries read' because an earlier run had seen them.
        self.run_cli("--cve", "CVE-2099-0001")
        n = len(Stub.seen)
        _, out, _ = self.run_cli("--cve", "CVE-2099-0001")
        self.assertIn("1 exploited entries read", out)
        self.assertGreater(len(Stub.seen), n)

    def test_quota_error_stops_with_the_servers_message_and_exit_1(self):
        Stub.mode = "quota"
        rc, _, err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 1); self.assertIn("daily limit reached", err)
        self.assertIn("STOPPED", (cli.OUT / "scan.log").read_text())

    def test_server_error_is_reported_not_raised(self):
        Stub.mode = "http500"
        rc, _, err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 1); self.assertIn("HTTP 500", err)

    def _flaky(self, fails, exc):
        """Make the first `fails` network opens raise `exc`, then behave normally."""
        real, calls = cli._OPENER.open, []
        def open_(req, timeout=None):
            calls.append(1)
            if len(calls) <= fails:
                raise exc
            return real(req, timeout=timeout)
        return mock.patch.object(cli._OPENER, "open", open_), calls

    def test_a_handshake_timeout_is_retried_and_the_run_goes_on(self):
        patch, calls = self._flaky(2, urllib.error.URLError("_ssl.c:1063: The handshake operation timed out"))
        with patch:
            rc, _, err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 0, err)
        self.assertIn("trying again", err); self.assertGreater(len(calls), 2)

    def test_gives_up_after_three_tries_and_says_so(self):
        patch, calls = self._flaky(99, urllib.error.URLError("handshake timed out"))
        with patch:
            rc, _, err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 1); self.assertEqual(len(calls), 3)
        self.assertIn("cannot reach Lattice after 3 tries", err)

    def test_a_rate_limit_or_client_error_is_not_retried(self):
        Stub.mode = "http500"
        patch, calls = self._flaky(0, None)
        with patch:
            rc, _, err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 1); self.assertIn("HTTP 500", err); self.assertEqual(len(calls), 1)

    def test_unreachable_server(self):
        cli.URL = "http://127.0.0.1:1/mcp"
        rc, _, err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 1); self.assertIn("cannot reach Lattice", err)

    def test_key_is_sent_only_when_set_and_never_logged(self):
        cli.KEY = "secret-key-value"
        try:
            _, out, err = self.run_cli("--debug", "--cve", "CVE-2099-0001")
        finally:
            cli.DEBUG = False
        self.assertTrue(any(k == "secret-key-value" for _, k, _ in Stub.seen))
        self.assertNotIn("secret-key-value", err + out + (cli.OUT / "debug.log").read_text())

    def test_discover_needs_a_key(self):
        rc, _, err = self.run_cli("--discover")
        self.assertEqual(rc, 2); self.assertIn("needs a key", err)

    def test_missing_cve_file_is_a_message_not_a_traceback(self):
        rc, _, err = self.run_cli("--cve-file", "/nonexistent/ids.txt")
        self.assertEqual(rc, 2); self.assertIn("cannot read --cve-file", err)

    def test_resolve_needs_proof_and_never_happens_by_itself(self):
        self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(cli.state()["CVE-2099-0001"]["status"], "open")
        rc, _, err = self.run_cli("resolve", "CVE-2099-0001", "--status", "fixed")
        self.assertEqual(rc, 2); self.assertIn("proof is required", err)

    def test_records_directory_is_private(self):
        self.run_cli("--cve", "CVE-2099-0001")
        sub = Path(self.tmp.name) / "sub"
        cli.OUT = sub
        self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(oct(sub.stat().st_mode & 0o777), "0o700")


class Hardening(Client):
    """Each of these was a way to leak a key or be fooled by the network, found in review before any release."""

    def test_key_not_sent_to_cleartext_remote(self):
        cli.KEY = "k"; cli.URL = "http://lattice.example.invalid/mcp"
        rc, _, err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(rc, 1); self.assertIn("refusing to use", err)

    def test_redirect_is_not_followed_so_the_key_goes_nowhere_else(self):
        other = HTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=other.serve_forever, daemon=True).start()
        Stub.other_port = other.server_port
        Stub.mode = "redirect"; cli.KEY = "secret-key-value"
        try:
            rc, _, err = self.run_cli("--cve", "CVE-2099-0001")
        finally:
            other.shutdown(); other.server_close()
        self.assertEqual(rc, 1)
        self.assertEqual(len(Stub.seen), 1)           # only the first server was ever asked

    def test_control_characters_from_the_server_are_neutralised(self):
        a = lookup("CVE-2099-0001")
        a["items"][1]["required_action"] = "Apply updates.\x1b]0;owned\x07\x1b[2J"
        a["items"][1]["title"] = "Exampleco Examplelib2 \x1b[31mred"
        Stub.answers = {"CVE-2099-0001": a}
        _, out, _ = self.run_cli("--cve", "CVE-2099-0001")
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x1b", (cli.OUT / "findings.jsonl").read_text())

    def test_existing_loose_directory_is_tightened(self):
        d = Path(self.tmp.name) / "loose"; d.mkdir(mode=0o755); os.chmod(d, 0o755)
        cli.OUT = d
        self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(oct(d.stat().st_mode & 0o777), "0o700")


for _n in [n for n in dir(Client) if n.startswith("test_") and n not in Hardening.__dict__]:
    setattr(Hardening, _n, None)   # Hardening reuses Client's setup only; its inherited tests already run under Client


class Contract(unittest.TestCase):
    """Run by hand against the live server before a release:  LATTICE_CONTRACT=1 python3 -m unittest tests.test_lattice_scan.Contract
    It spends one keyless lookup. It checks that the fields the client reads are still there, so a server change is caught before a release, not by a user."""

    @unittest.skipUnless(os.environ.get("LATTICE_CONTRACT") == "1", "set LATTICE_CONTRACT=1 to spend one live lookup")
    def test_live_fields(self):
        lat = cli.Lattice(); lat.start()
        e = cli.kev_entry(lat, "CVE-2021-44228")
        for k in ("vendor", "product", "added", "due", "action"):
            self.assertTrue(e[k], f"kev field {k} is empty")
        self.assertTrue(e["ranges"], "nvd affected_ranges missing")
        self.assertTrue(all("product" in r for r in e["ranges"]))


if __name__ == "__main__":
    unittest.main()
