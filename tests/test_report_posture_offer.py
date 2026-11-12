# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""After a yes to the mailed report the tool asks a second question about the runtime posture: default No, its own details, this run only. Synthetic data only."""
import io, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import scan_report_flow as flow  # noqa: E402
from lattice_scan import scan_record as rec  # noqa: E402

ITEMS = [{"cve": "CVE-2030-0001", "product": "nginx", "version": "1.26.3-1", "verdict": "in-range", "priority": "fix first", "installed": ["nginx"]}]
INV = {"kernel": "7.0.0-1", "os": "Debian GNU/Linux 13", "manager": "dpkg", "packages": {"nginx": "1.26.3-1"}, "snaps": {}, "images": [], "imageDetails": {}, "host": {}}
POSTURE = {"scope": "user", "level": "quick", "ports": [{"proto": "tcp", "addr": "192.0.2.5", "port": 80, "bind": "all interfaces", "process": "nginx", "package": "nginx", "where": ""}],
           "firewall": {"readable": False, "managers": []}, "ssh": {"installed": False, "settings": {}}, "unreadable": ["firewall rules (need root)"]}
NONE = lambda: []   # noqa: E731 - the host's own history and processes are not read by these tests
TTY = dict(stdin_tty=True, stderr_tty=True, env={}, quiet=False, fmt="table", enabled=True)


def answers(*given):
    seq, asked = list(given), []

    def fn(prompt=""):
        asked.append(prompt)
        return seq.pop(0) if seq else ""
    fn.asked = asked
    return fn


def run(fn, **kw):
    with tempfile.TemporaryDirectory() as d:
        out = io.StringIO()
        flow.after_scan(ITEMS, "quick", Path(d), input_fn=fn, out=out, os_name="Debian", inv=INV, posture=POSTURE, secrets_fn=NONE, **{**TTY, **kw})
    return out.getvalue()


class PostureOffer(unittest.TestCase):
    def test_the_second_question_is_asked_only_after_a_yes_to_the_report(self):
        fn = answers("")                                   # No to the report
        run(fn)
        self.assertEqual(len(fn.asked), 1)
        fn = answers("y", "")                              # yes, then Enter on the posture
        text = run(fn)
        self.assertEqual(len(fn.asked), 2)
        self.assertIn("Also include this machine's runtime posture?", text)
        self.assertIn("Submit for making the report:", text)
        self.assertIn("Not submitted: addresses, user names, file paths, command lines,", text)

    def test_enter_means_no_and_the_record_has_no_posture_key(self):
        r = flow.record_after_yes(INV, ITEMS, "quick", "Debian", {"items": ITEMS}, POSTURE, answers(""), io.StringIO(), secrets_fn=NONE)
        self.assertNotIn("posture", r)
        self.assertEqual(r["schema"], 2)

    def test_a_yes_adds_the_declared_block_and_details_show_it(self):
        out = io.StringIO()
        r = flow.record_after_yes(INV, ITEMS, "quick", "Debian", {"items": ITEMS}, POSTURE, answers("d", "y"), out, secrets_fn=NONE)
        self.assertEqual(r["posture"], rec.posture_block(POSTURE))      # the preview, the details and the bytes come from one block
        self.assertEqual(r["schema"], 3)
        self.assertIn('"port": 80', out.getvalue())
        self.assertNotIn("192.0.2.5", out.getvalue())                  # even the details never show an address

    def test_a_run_that_cannot_ask_never_asks(self):
        def boom(_p=""):
            raise AssertionError("a question was asked")
        with tempfile.TemporaryDirectory() as d:
            for kw in (dict(stdin_tty=False), dict(stderr_tty=False), dict(env={"CI": "true"}), dict(quiet=True), dict(fmt="json"), dict(fmt="csv")):
                flow.after_scan(ITEMS, "quick", Path(d), input_fn=boom, out=io.StringIO(), os_name="Debian", inv=INV, posture=POSTURE, **{**TTY, **kw})

    def test_a_project_scan_or_an_unread_posture_has_no_second_question(self):
        fn = answers("y")
        with tempfile.TemporaryDirectory() as d:
            flow.after_scan(ITEMS, "quick", Path(d), input_fn=fn, out=io.StringIO(), os_name="Debian", inv={"os": "project manifests", "packages": {"x": "1"}}, posture=POSTURE, **TTY)
        self.assertEqual(len(fn.asked), 1)
        fn = answers("y")
        with tempfile.TemporaryDirectory() as d:
            flow.after_scan(ITEMS, "quick", Path(d), input_fn=fn, out=io.StringIO(), os_name="Debian", inv=INV, posture=None, **TTY)
        self.assertEqual(len(fn.asked), 1)

    def test_nothing_is_remembered_between_runs_and_nothing_is_sent_in_this_version(self):
        self.assertFalse(flow.MAIL_AVAILABLE)
        a = flow.record_after_yes(INV, ITEMS, "quick", "Debian", {"items": ITEMS}, POSTURE, answers("y"), io.StringIO(), secrets_fn=NONE)
        b = flow.record_after_yes(INV, ITEMS, "quick", "Debian", {"items": ITEMS}, POSTURE, answers(""), io.StringIO(), secrets_fn=NONE)
        self.assertIn("posture", a)
        self.assertNotIn("posture", b)

    def test_the_tool_never_calls_sudo_for_the_posture(self):
        src = Path(flow.__file__).read_text()
        self.assertNotIn("sudo", src.replace("never runs sudo", ""))


if __name__ == "__main__":
    unittest.main()
