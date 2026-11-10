# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The user agent the tool sends, and the one mark that sets our own runs apart. No network: a local server records what it was sent."""
import json, os, sys, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import __version__, cli  # noqa: E402

SEEN: list[str] = []


class Echo(BaseHTTPRequestHandler):
    def _reply(self):
        SEEN.append(self.headers.get("User-Agent", ""))
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"nodes": [], "rows": []}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _reply

    def log_message(self, *a):  # keep the test output clean
        pass


class UserAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Echo)
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}/mcp"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        SEEN.clear()

    def test_plain_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LATTICE_SCAN_TEST", None)
            self.assertEqual(cli.user_agent(), f"lattice-scan/{__version__}")

    def test_marked_when_testing(self):
        for v in ("1", "true", "YES"):
            with mock.patch.dict(os.environ, {"LATTICE_SCAN_TEST": v}):
                self.assertEqual(cli.user_agent(), f"lattice-scan/{__version__} (test)")

    def test_other_values_do_not_mark(self):
        for v in ("", "0", "no", "false"):
            with mock.patch.dict(os.environ, {"LATTICE_SCAN_TEST": v}):
                self.assertEqual(cli.user_agent(), f"lattice-scan/{__version__}")

    def test_sent_on_the_wire_by_the_client_request(self):
        """The mark has to be on the request itself, not only in the helper: the client's POST goes to a local double."""
        with mock.patch.dict(os.environ, {"LATTICE_SCAN_TEST": "1"}), mock.patch.object(cli, "URL", self.url):
            cli.Lattice()._post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(SEEN, [f"lattice-scan/{__version__} (test)"])


if __name__ == "__main__":
    unittest.main()
