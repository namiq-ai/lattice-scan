# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The release gate: a build that would refuse the live list fails; an unsigned or unreachable site only warns."""
import sys, unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "packaging"), str(ROOT / "tests")]
import check_feed_signature as gate  # noqa: E402
import test_feedsig as t  # noqa: E402
from lattice_scan import feedsig  # noqa: E402


def site(**files):
    return lambda url: files[url.rsplit("/", 1)[-1]] if url.rsplit("/", 1)[-1] in files else None


class Gate(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(feedsig, "ROOT_PUBLIC_KEY", t.ROOT_PUB); p.start(); self.addCleanup(p.stop)

    def test_a_signed_live_list_passes(self):
        code, msg = gate.judge(site(**{"recent.json": t.BODY, "recent.json.sig": t.sig(), "recent.json.cert": t.cert()}))
        self.assertEqual(code, 0); self.assertTrue(msg.startswith("OK"))

    def test_a_build_with_another_root_key_is_stopped(self):
        with mock.patch.object(feedsig, "ROOT_PUBLIC_KEY", t.OTHER_PUB):
            code, msg = gate.judge(site(**{"recent.json": t.BODY, "recent.json.sig": t.sig(), "recent.json.cert": t.cert()}))
        self.assertEqual(code, 1); self.assertIn("REFUSE", msg)

    def test_unsigned_and_unreachable_only_warn(self):
        self.assertEqual(gate.judge(site(**{"recent.json": t.BODY}))[0], 0)
        self.assertTrue(gate.judge(site(**{"recent.json": t.BODY}))[1].startswith("WARN"))
        def down(url): raise OSError("no route")
        self.assertEqual(gate.judge(down)[0], 0); self.assertTrue(gate.judge(down)[1].startswith("WARN"))


if __name__ == "__main__":
    unittest.main()
