# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The signature check on namiq.io's recent-CVE list: the certificate chain, every way it can be wrong, and how read_feed treats each outcome.
Keys here are made from fixed test seeds; they are not NamiQ's keys."""
import json, os, sys, tempfile, threading, time, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ed25519_signer as signer  # noqa: E402
from lattice_scan import cli, ed25519, feedsig  # noqa: E402

ROOT_SEED, FEED_SEED, OTHER_SEED = bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 32
ROOT_PUB, FEED_PUB, OTHER_PUB = (signer.public_key(s) for s in (ROOT_SEED, FEED_SEED, OTHER_SEED))
NOW = time.time()
DAY = 86400
FEED = {"schema": "lattice-recent/3", "exploitedAsOf": "2026-11-09", "builtAt": "2026-11-09T10:00:00Z",
        "weekly": {"from": "2026-11-02", "to": "2026-11-09", "exploited": [{"id": "CVE-2099-0001", "vendor": "Exampleco", "product": "Examplelib"}], "critical": []},
        "open": {"exploited": []}}
BODY = (json.dumps(FEED, indent=1) + "\n").encode()


def iso(t): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def cert(seed=ROOT_SEED, key=FEED_PUB, serial=1, start=NOW - DAY, days=60, **over) -> bytes:
    c = {"v": 1, "key": key.hex(), "serial": serial, "notBefore": iso(start), "notAfter": iso(start + days * DAY)}
    c.update({k: v for k, v in over.items() if k in c})
    c["sig"] = signer.sign(seed, feedsig.cert_message(c)).hex()
    return json.dumps(c).encode()


def sig(body=BODY, seed=FEED_SEED) -> bytes:
    return signer.sign(seed, body)


class Chain(unittest.TestCase):
    def check(self, body=BODY, s=None, c=None, **kw):
        return feedsig.check(body, sig() if s is None else s, cert() if c is None else c, now=NOW, root=ROOT_PUB, **kw)

    def test_the_test_signer_matches_the_rfc_8032_vector(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.assertEqual(signer.sign(seed, b"").hex(), "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

    def test_a_good_list_is_verified_and_reports_the_serial_and_end_date(self):
        r = self.check(c=cert(serial=4))
        self.assertEqual((r.status, r.serial), ("verified", 4)); self.assertEqual(r.not_after, iso(NOW - DAY + 60 * DAY))

    def test_one_changed_byte_in_the_list_or_the_signature_is_refused(self):
        self.assertEqual(self.check(body=BODY.replace(b"Exampleco", b"Examplecp")).status, "refused")
        bad = bytearray(sig()); bad[5] ^= 1
        self.assertEqual(self.check(s=bytes(bad)).status, "refused")
        self.assertEqual(self.check(s=sig(seed=OTHER_SEED)).status, "refused")            # signed by a key the certificate does not name

    def test_every_certificate_fault_is_refused_with_its_own_reason(self):
        cases = [("expired", cert(start=NOW - 100 * DAY, days=60)), ("not valid yet", cert(start=NOW + 2 * DAY)), ("more than 90", cert(days=91)),
                 ("root key", cert(seed=OTHER_SEED)), ("ends before", cert(days=-1))]
        for word, c in cases:
            r = self.check(c=c)
            self.assertEqual(r.status, "refused", word); self.assertIn(word, r.reason, word)

    def test_a_lower_serial_than_the_release_accepts_is_refused(self):
        self.assertEqual(self.check(c=cert(serial=2), min_serial=3).status, "refused")
        self.assertEqual(self.check(c=cert(serial=3), min_serial=3).status, "verified")

    def test_a_certificate_for_another_key_cannot_vouch_for_this_signature(self):
        self.assertEqual(self.check(c=cert(key=OTHER_PUB)).status, "refused")             # the root signs it fine, but the list was signed by another key

    def test_malformed_certificates_are_refused_and_never_raise(self):
        base = json.loads(cert())
        bad = [dict(base, extra=1), {k: v for k, v in base.items() if k != "sig"}, dict(base, serial=0), dict(base, serial=True), dict(base, serial="1"), dict(base, v=2),
               dict(base, key=base["key"].upper()), dict(base, sig="00" * 63), dict(base, notBefore="2026-02-30T00:00:00Z"), dict(base, notAfter="2026-11-09"), dict(base, notAfter=None), [1, 2]]
        for b in bad:
            self.assertEqual(self.check(c=json.dumps(b).encode()).status, "refused", b)

    def test_nothing_offered_is_unsigned_and_half_offered_or_a_web_page_is_judged_apart(self):
        self.assertEqual(feedsig.check(BODY, None, None, now=NOW, root=ROOT_PUB).status, "unsigned")
        self.assertEqual(feedsig.check(BODY, sig(), None, now=NOW, root=ROOT_PUB).status, "refused")
        self.assertEqual(feedsig.check(BODY, None, cert(), now=NOW, root=ROOT_PUB).status, "refused")
        self.assertEqual(feedsig.check(BODY, b"x" * 64, b"<!DOCTYPE html><html>not found</html>", now=NOW, root=ROOT_PUB).status, "unsigned")

    def test_the_built_in_root_key_is_a_valid_32_byte_key_and_the_verifier_is_the_package_one(self):
        self.assertEqual(len(feedsig.ROOT_PUBLIC_KEY), 32)
        self.assertIs(feedsig.ed25519, ed25519)


class Served(unittest.TestCase):
    """read_feed against a local server that stands in for namiq.io."""
    files: dict = {}
    hits: list = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            Served.hits.append(self.path)
            f = Served.files.get(self.path)
            f = f() if callable(f) else f
            if f is None:
                self.send_response(404); self.end_headers(); return
            self.send_response(200); self.end_headers(); self.wfile.write(f)

        def log_message(self, *a): pass

    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), cls.H)
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}/recent.json"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def setUp(self):
        Served.hits = []
        Served.files = {"/recent.json": BODY, "/recent.json.sig": sig(), "/recent.json.cert": cert()}
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        for p in (mock.patch.object(cli, "FEED_URL", self.base), mock.patch.object(feedsig, "ROOT_PUBLIC_KEY", ROOT_PUB), mock.patch.object(cli, "OFFLINE", False),
                  mock.patch.object(cli, "NET_DOWN", False), mock.patch.dict(os.environ, {"LATTICE_SCAN_READ_CACHE": "on"}),
                  mock.patch.object(cli, "read_cache_path", lambda: Path(self.tmp.name) / "read-cache.json")):
            p.start(); self.addCleanup(p.stop)
        self.notes = []
        q = mock.patch.object(cli, "progress", lambda m: self.notes.append(m)); q.start(); self.addCleanup(q.stop)

    def saved(self): return json.loads(cli.feed_cache_path().read_text())

    def test_verified_list_is_read_labelled_and_saved_as_verified(self):
        out = cli.read_feed("weekly")
        self.assertEqual([r["id"] for r in out["exploited"]], ["CVE-2099-0001"])
        self.assertTrue(any("signature verified (certificate serial 1" in n for n in self.notes))
        self.assertEqual(self.saved()["sig"], "verified")
        self.assertEqual(sorted(Served.hits), ["/recent.json", "/recent.json.cert", "/recent.json.sig"])   # the whole of what was asked for

    def test_a_list_with_no_signature_is_still_read_labelled_not_verified_and_saved_as_unsigned(self):
        del Served.files["/recent.json.sig"], Served.files["/recent.json.cert"]
        out = cli.read_feed("weekly")
        self.assertEqual(len(out["exploited"]), 1)
        self.assertTrue(any("not signed" in n and "not verified" in n for n in self.notes))
        self.assertEqual(self.saved()["sig"], "unsigned")

    def test_a_wrong_signature_is_refused_nothing_is_saved_and_the_message_says_why(self):
        bad = bytearray(sig()); bad[3] ^= 1
        Served.files["/recent.json.sig"] = bytes(bad)
        with self.assertRaises(cli.LatticeError) as cm:
            cli.read_feed("weekly")
        self.assertIn("failed its signature check", str(cm.exception)); self.assertIn("not used", str(cm.exception))
        self.assertFalse(cli.feed_cache_path().exists())

    def test_a_new_list_with_an_old_cached_signature_is_asked_again_once(self):
        calls = {"n": 0}
        good = sig()
        def sig_file():
            calls["n"] += 1
            return sig(body=b"an older list") if calls["n"] == 1 else good
        Served.files["/recent.json.sig"] = sig_file
        self.assertEqual(len(cli.read_feed("weekly")["exploited"]), 1)
        self.assertEqual(calls["n"], 2)

    def test_the_signature_files_failing_to_load_does_not_stop_the_list_or_mark_the_network_down(self):
        Served.files["/recent.json.sig"] = lambda: (_ for _ in ()).throw(RuntimeError("boom"))   # the handler errors: the connection drops
        with mock.patch.object(cli, "RETRY_DELAYS", ()):
            out = cli.read_feed("weekly")
        self.assertEqual(len(out["exploited"]), 1)
        self.assertFalse(cli.NET_DOWN)

    def test_offline_reads_the_saved_copy_and_asks_for_no_signature(self):
        cli.read_feed("weekly"); Served.hits.clear()
        with mock.patch.object(cli, "OFFLINE", True):
            out = cli.read_feed("weekly")
        self.assertEqual(len(out["exploited"]), 1); self.assertEqual(Served.hits, [])


if __name__ == "__main__":
    unittest.main()
