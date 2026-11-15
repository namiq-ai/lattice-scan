# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The report request does not wait at the command line: it is kept in a private file, and `report finish` sends it after the mailbox owner confirmed. Synthetic data."""
import io, json, os, stat, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import scan_report_send as send  # noqa: E402
from test_report_send import KEY, RECORD, Clock, Server  # noqa: E402


class NoWait(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "rec"

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, server):
        out = io.StringIO()
        ok = send.send_report(RECORD, KEY, "1.1.1", lambda p="": "", out, post=server, interactive=True, wait_s=0, pending_dir=self.dir)
        return ok, out.getvalue()

    def test_it_says_received_masks_the_address_and_never_polls_or_submits(self):
        s = Server(prefill="person@example.org")
        ok, out = self.request(s)
        self.assertTrue(ok)
        self.assertIn("Report request received", out)
        self.assertIn("p***@e***.org", out)
        self.assertNotIn("person@example.org", out)
        self.assertIn("lattice-scan report finish", out)
        self.assertEqual(s.names(), ["address", "request"])          # no claim poll, no submit: nothing about the machine was sent

    def test_the_pending_file_is_private_and_holds_the_record_for_finish(self):
        self.request(Server(prefill="person@example.org"))
        f = self.dir / send.PENDING_NAME
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
        self.assertEqual(json.loads(f.read_text())["record"], RECORD)

    def test_finish_before_confirming_sends_nothing_and_keeps_the_request(self):
        self.request(Server(prefill="person@example.org"))
        s = Server(claims=("pending",))
        out = io.StringIO()
        self.assertFalse(send.finish_report(self.dir, KEY, "1.1.1", post=s, out=out))
        self.assertIn("Not confirmed yet", out.getvalue())
        self.assertNotIn("submit", s.names())
        self.assertTrue((self.dir / send.PENDING_NAME).is_file())

    def test_finish_after_confirming_sends_once_shows_the_code_and_clears_the_file(self):
        self.request(Server(prefill="person@example.org"))
        s = Server(claims=("confirmed",))
        out = io.StringIO()
        self.assertTrue(send.finish_report(self.dir, KEY, "1.1.1", post=s, out=out, bold=False))
        self.assertEqual(s.names(), ["claim", "submit"])
        self.assertIn("Report code:", out.getvalue())
        self.assertFalse((self.dir / send.PENDING_NAME).exists())
        self.assertFalse(send.finish_report(self.dir, KEY, "1.1.1", post=Server(), out=io.StringIO()))   # a second finish has nothing to send

    def test_a_refused_or_expired_request_is_dropped(self):
        for state in ("refused", "expired"):
            self.request(Server(prefill="person@example.org"))
            out = io.StringIO()
            self.assertFalse(send.finish_report(self.dir, KEY, "1.1.1", post=Server(claims=(state,)), out=out))
            self.assertFalse((self.dir / send.PENDING_NAME).exists())
            self.assertIn("Nothing was sent", out.getvalue())

    def test_an_old_request_is_dropped_without_a_call(self):
        self.request(Server(prefill="person@example.org"))
        s = Server()
        out = io.StringIO()
        far = lambda: 10 ** 12   # noqa: E731
        self.assertFalse(send.finish_report(self.dir, KEY, "1.1.1", post=s, out=out, clock=far))
        self.assertEqual(s.calls, [])
        self.assertFalse((self.dir / send.PENDING_NAME).exists())

    def test_the_mask(self):
        self.assertEqual(send.mask_address("hung@namiq.io"), "h***@n***.io")
        self.assertEqual(send.mask_address("nonsense"), "your mailbox")


class WaitThenFinish(unittest.TestCase):
    """The default: wait a few minutes while the person confirms, and go on by itself; fall back to `report finish`."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "rec"

    def tearDown(self):
        self.tmp.cleanup()

    def run_it(self, server, wait_s=180, sleep=None):
        c = Clock()
        out = io.StringIO()
        ok = send.send_report(RECORD, KEY, "1.1.3", lambda p="": "", out, post=server, sleep=sleep or c.sleep, clock=c, interactive=True, wait_s=wait_s, pending_dir=self.dir, bold=False)
        return ok, out.getvalue()

    def test_confirming_during_the_wait_finishes_the_run_by_itself(self):
        s = Server(claims=("pending", "pending", "confirmed"), prefill="person@example.org", submit=(200, {"message": "Your report was requested.", "code": "482913", "order_id": "RO-0123456789"}))
        ok, out = self.run_it(s)
        self.assertTrue(ok)
        self.assertEqual(s.names()[-1], "submit")
        self.assertIn("Report code: 482913", out)
        self.assertIn("Request id: RO-0123456789", out)
        self.assertIn("p***@e***.org", out)
        self.assertIn("What happens next", out)
        self.assertNotIn("person@example.org", out)
        self.assertFalse((self.dir / send.PENDING_NAME).exists())

    def test_not_confirmed_in_time_keeps_the_request_and_says_how_to_finish(self):
        s = Server(claims=(), prefill="person@example.org")          # always pending
        ok, out = self.run_it(s, wait_s=30)
        self.assertTrue(ok)
        self.assertNotIn("submit", s.names())
        self.assertIn("lattice-scan report finish", out)
        self.assertTrue((self.dir / send.PENDING_NAME).is_file())

    def test_ctrl_c_keeps_the_request(self):
        def stop(_s):
            raise KeyboardInterrupt
        s = Server(claims=(), prefill="person@example.org")
        ok, out = self.run_it(s, sleep=stop)
        self.assertTrue(ok)
        self.assertNotIn("submit", s.names())
        self.assertIn("Stopped waiting", out)
        self.assertTrue((self.dir / send.PENDING_NAME).is_file())

    def test_a_refused_request_is_dropped(self):
        s = Server(claims=("refused",), prefill="person@example.org")
        ok, out = self.run_it(s)
        self.assertFalse(ok)
        self.assertIn("not them", out)
        self.assertFalse((self.dir / send.PENDING_NAME).exists())


if __name__ == "__main__":
    unittest.main()
