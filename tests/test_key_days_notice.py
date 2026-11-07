# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The one-line notice when a keyed answer says the key ends soon (ADR-LATTICE-ANON-003 D3). No network."""
import io, sys, tempfile, unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli  # noqa: E402


class Notice(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patches = [mock.patch.object(cli, "PACE_FILE", Path(self.tmp.name) / "pace.json"), mock.patch.object(cli, "PROGRESS", True)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def say(self, value, today="2026-11-07"):
        err = io.StringIO()
        with redirect_stderr(err):
            r = cli.key_days_notice(value, today)
        return r, err.getvalue()

    def test_a_key_with_fourteen_days_or_fewer_gets_one_line(self):
        r, out = self.say("9")
        self.assertTrue(r)
        self.assertIn("ends in 9 days", out)
        self.assertIn("renewal link was mailed", out)

    def test_it_is_said_once_a_day_not_on_every_call(self):
        self.assertTrue(self.say("9")[0])
        self.assertFalse(self.say("9")[0])
        self.assertFalse(self.say("8")[0])
        self.assertTrue(self.say("8", today="2026-11-08")[0])

    def test_a_key_with_more_time_or_no_header_says_nothing(self):
        for v in ("15", "30", "90", None, "", "soon", "-3"):
            r, out = self.say(v)
            self.assertFalse(r, v)
            self.assertEqual(out, "")

    def test_the_last_day_and_zero_are_said_in_the_singular_and_plural(self):
        self.assertIn("ends in 1 day.", self.say("1")[1])
        self.assertIn("ends in 0 days.", self.say("0", today="2026-11-08")[1])

    def test_nothing_is_printed_with_progress_off(self):
        with mock.patch.object(cli, "PROGRESS", False):
            r, out = self.say("3")
        self.assertEqual(out, "")                       # --quiet: the line is a progress line

    def test_an_unwritable_folder_does_not_stop_the_notice(self):
        blocker = Path(self.tmp.name) / "afile"
        blocker.write_text("x")
        with mock.patch.object(cli, "PACE_FILE", blocker / "sub" / "pace.json"):
            r, out = self.say("5")
        self.assertTrue(r)
        self.assertIn("ends in 5 days", out)

    def test_only_a_keyed_run_reads_the_header(self):
        class R:
            headers = {"X-Lattice-Key-Days-Left": "3", "Mcp-Session-Id": ""}
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n): return b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{}"}]}}'
        for key, expect in (("", False), ("lat_x", True)):
            err = io.StringIO()
            with mock.patch.object(cli, "KEY", key), mock.patch.object(cli._OPENER, "open", lambda *a, **k: R()), redirect_stderr(err), \
                 mock.patch.object(cli, "pace_wait", lambda *a: 0.0):
                cli.Lattice()._post({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "graph_meta", "arguments": {}}})
            self.assertEqual("ends in 3 days" in err.getvalue(), expect, key)
            (Path(self.tmp.name) / "pace.json.key-notice.json").unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
