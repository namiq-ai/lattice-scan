# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The record is sent only after the mailbox is proved; the tool waits holding it in memory, and any stop sends nothing. Synthetic data and a fake server."""
import io, os, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import scan_report_flow as flow  # noqa: E402
from lattice_scan import scan_report_send as send  # noqa: E402

RECORD = {"schema": 2, "level": "quick", "os": "Debian", "items": [{"cve": "CVE-2030-0001"}], "inventory": {"packages": {"nginx": "1.26.3-1"}}, "cut": 0}
ITEMS = [{"cve": "CVE-2030-0001", "product": "nginx", "version": "1.26.3-1", "verdict": "in-range", "priority": "fix first", "installed": ["nginx"]}]
INV = {"kernel": "7.0", "os": "Debian", "manager": "dpkg", "packages": {"nginx": "1.26.3-1"}, "snaps": {}, "images": [], "imageDetails": {}, "host": {}}
KEY = "lat_" + "Q7x" * 8


class Server:
    def __init__(self, claims=("pending", "pending", "confirmed"), claim="c" * 40, submit=(200, {"message": "Your report was requested. It arrives by email within 4 hours, after a person has reviewed it."}), prefill=""):
        self.calls, self.claims, self.claim, self.submit, self.prefill = [], list(claims), claim, submit, prefill

    def __call__(self, url, body, headers=None, timeout=30):
        name = url.rsplit("/", 1)[-1]
        self.calls.append((name, body, headers or {}))
        if name == "address":
            return (200, {"address": self.prefill}) if self.prefill else (404, {})
        if name == "request":
            return 200, {"claim": self.claim, "message": send.NEUTRAL}
        if name == "claim":
            st = self.claims.pop(0) if self.claims else "pending"
            return 200, ({"state": "confirmed", "token": "tok"} if st == "confirmed" else {"state": st})
        if name == "submit":
            return self.submit
        raise AssertionError(name)

    def names(self):
        return [c[0] for c in self.calls]


class Clock:
    t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def run(server, answers=("me@example.org",), key=KEY, **kw):
    c = Clock()
    out = io.StringIO()
    seq = list(answers)
    ok = send.send_report(RECORD, key, "0.9.2", lambda p="": seq.pop(0) if seq else "", out, post=server, sleep=c.sleep, clock=c, **kw)
    return ok, out.getvalue()


class SendFlow(unittest.TestCase):
    def test_the_record_goes_only_after_the_claim_is_confirmed(self):
        s = Server()
        ok, text = run(s)
        self.assertTrue(ok)
        self.assertEqual(s.names(), ["address", "request", "claim", "claim", "claim", "submit"])
        self.assertNotIn("record", s.calls[1][1])                       # the request for the mail carries the address only
        self.assertEqual(s.calls[-1][1]["token"], "tok")
        self.assertEqual(s.calls[-1][2]["Authorization"], "Bearer " + KEY)
        self.assertIn("within 4 hours", text)
        self.assertIn("Nothing about this machine has been sent yet", text)

    def test_no_key_nothing_is_sent_and_nothing_is_asked(self):
        s = Server()
        ok, text = run(s, key=None)
        self.assertFalse(ok)
        self.assertEqual(s.calls, [])
        self.assertIn("needs a Lattice key", text)

    def test_the_prefilled_address_is_used_on_enter_and_another_address_is_sent_as_the_delivery_address(self):
        s = Server(prefill="key@example.org")
        run(s, answers=("",))
        self.assertEqual(s.calls[1][1]["address"], "key@example.org")
        self.assertNotIn("delivery_address", s.calls[-1][1])
        s2 = Server(prefill="key@example.org")
        run(s2, answers=("team@example.org",))
        self.assertEqual(s2.calls[-1][1]["delivery_address"], "team@example.org")

    def test_a_refusal_a_not_me_an_expiry_and_a_timeout_send_nothing(self):
        for claims, word in ((("refused",), "not them"), (("expired",), "expired")):
            s = Server(claims=claims)
            ok, text = run(s)
            self.assertFalse(ok)
            self.assertNotIn("submit", s.names())
            self.assertIn(word, text)
        s = Server(claims=())                                           # never confirmed
        ok, text = run(s)
        self.assertFalse(ok)
        self.assertNotIn("submit", s.names())
        self.assertIn("Stopped waiting. Nothing was sent.", text)
        s = Server(claim=None)                                          # the server mailed nothing
        ok, _ = run(s)
        self.assertFalse(ok)
        self.assertNotIn("claim", s.names())

    def test_ctrl_c_while_waiting_sends_nothing(self):
        s = Server()
        out = io.StringIO()

        def stop(_s):
            raise KeyboardInterrupt
        ok = send.send_report(RECORD, KEY, "0.9.2", lambda p="": "me@example.org", out, post=s, sleep=stop, clock=Clock())
        self.assertFalse(ok)
        self.assertNotIn("submit", s.names())
        self.assertIn("Stopped. Nothing was sent.", out.getvalue())

    def test_a_server_refusal_is_reported_and_the_tool_writes_no_file(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.getcwd()
            os.chdir(d)
            try:
                ok, text = run(Server(submit=(400, {"error": "field not allowed in the record: hostname"})))
                self.assertEqual(list(Path(d).iterdir()), [])
            finally:
                os.chdir(old)
        self.assertFalse(ok)
        self.assertIn("not accepted", text)

    def test_the_offer_runs_the_whole_sequence_only_when_a_sender_is_wired_and_never_in_this_version_otherwise(self):
        answers = iter(["y", "n", "me@example.org"])          # report yes, posture no, address
        s = Server()
        with tempfile.TemporaryDirectory() as d:
            c = Clock()
            flow.after_scan(ITEMS, "quick", Path(d), stdin_tty=True, stderr_tty=True, env={}, quiet=False, input_fn=lambda p="": next(answers), out=io.StringIO(), os_name="Debian", inv=INV,
                            posture={"scope": "user", "level": "quick", "ports": [], "firewall": {"readable": False, "managers": []}, "ssh": {"installed": False, "settings": {}}},
                            enabled=True, secrets_fn=lambda: [], post=s, key=KEY)
        self.assertEqual(s.names()[0:2], ["address", "request"])
        self.assertFalse(flow.MAIL_AVAILABLE)
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            flow.after_scan(ITEMS, "quick", Path(d), stdin_tty=True, stderr_tty=True, env={}, quiet=False, input_fn=lambda p="": "y", out=out, os_name="Debian", enabled=True)
        self.assertIn("not available in this version", out.getvalue())


if __name__ == "__main__":
    unittest.main()
