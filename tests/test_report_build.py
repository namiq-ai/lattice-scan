# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The code-written report: its parts in order, its wording rules and its private file (OCO-6054). Synthetic ids and products only."""
import datetime as dt, io, os, stat, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import scan_report as sr, scan_report_text as rt  # noqa: E402

ITEMS = [
    {"cve": "CVE-2030-0001", "product": "nginx", "version": "1.26.3", "verdict": "in-range", "priority": "fix first", "why": ["CISA records ransomware use"], "listed": "2026-10-01", "due": "2026-10-22", "due_status": "overdue by 20 days"},
    {"cve": "CVE-2030-0002", "product": "openssl", "version": "3.4.1", "verdict": "undetermined", "priority": "fix soon", "why": ["EPSS 0.62"], "attack": [{"id": "T1190", "inferred": True}]},
    {"cve": "CVE-2030-0003", "product": "bash", "version": "5.2", "verdict": "outside-range", "priority": "read"},
]
PAYLOAD = sr.build_payload(ITEMS, "quick", "Debian")
DAY = dt.date(2026, 11, 12)


class Report(unittest.TestCase):
    def test_the_parts_come_in_order(self):
        t = rt.build_report(ITEMS, PAYLOAD, DAY)
        pos = [t.index(f"{i}. {name}") for i, name in enumerate(rt.SECTIONS, 1)]
        self.assertEqual(pos, sorted(pos), "a section is out of order")

    def test_items_are_grouped_most_urgent_first_with_their_reasons(self):
        t = rt.build_report(ITEMS, PAYLOAD, DAY)
        self.assertLess(t.index("Fix first (1)"), t.index("Fix soon (1)")); self.assertLess(t.index("Fix soon (1)"), t.index("Read (1)"))
        self.assertIn("why: CISA records ransomware use", t); self.assertIn("overdue by 20 days", t)

    def test_never_says_vulnerable_safe_or_compromised_and_keeps_likely(self):
        t = rt.build_report(ITEMS, PAYLOAD, DAY)
        self.assertFalse(rt.BANNED.search(t))
        self.assertIn("likely linked to ATT&CK T1190", t); self.assertNotIn("is linked to", t)
        with self.assertRaisesRegex(ValueError, "safe"):
            rt.check_wording("this host is safe")
        rt.check_wording("the Safe product", [{"product": "Safe"}])            # a product's own name is not the report's wording

    def test_a_scan_with_no_candidate_is_not_called_an_all_clear(self):
        t = rt.build_report([], sr.build_payload([], "deep", "Alpine"), DAY)
        self.assertIn("not an all-clear", t); self.assertIn("deep scan also opened", t.lower())

    def test_a_quick_scan_says_what_it_did_not_cover(self):
        self.assertIn("Quick scan: running images only", rt.build_report(ITEMS, PAYLOAD, DAY))

    def test_the_file_is_private_the_path_is_printed_and_nothing_is_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            out = io.StringIO()
            p = rt.save_report("hello", Path(d) / "reports", out, dt.datetime(2026, 11, 12, 1, 2, 3))
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(p.parent).st_mode), 0o700)
            self.assertIn(str(p), out.getvalue())
            q = rt.save_report("again", p.parent, io.StringIO(), dt.datetime(2026, 11, 12, 1, 2, 3))
            self.assertNotEqual(p, q); self.assertEqual(p.read_text(), "hello")

    def test_no_host_field_in_the_scan_result_reaches_the_report(self):
        t = rt.build_report([{**ITEMS[0], "hostname": "canary-host-7f3a", "path": "/home/canary/x"}], PAYLOAD, DAY)
        self.assertNotIn("canary", t)


if __name__ == "__main__":
    unittest.main()
