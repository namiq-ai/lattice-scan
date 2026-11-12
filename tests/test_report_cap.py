# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The report payload is capped, keeps the highest priority and says how much it cut (OCO-6053, ADR-LATTICE-SCAN-REPORT-001 D1). Synthetic ids only."""
import json, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import scan_report as sr  # noqa: E402


def many(n, priority="read", start=1):
    return [{"cve": f"CVE-2030-{start + i:04d}", "product": f"pkg{start + i}", "version": "1.0", "verdict": "in-range", "priority": priority} for i in range(n)]


class Cap(unittest.TestCase):
    def test_above_the_item_cap_the_payload_holds_the_cap_and_the_cut_count(self):
        p = sr.build_payload(many(sr.MAX_ITEMS + 30), "quick", "Debian")
        self.assertEqual((len(p["items"]), p["cut"]), (sr.MAX_ITEMS, 30))

    def test_fix_first_is_kept_before_fix_soon_before_read(self):
        c = many(40, "read", 1) + many(40, "fix soon", 100) + many(10, "fix first", 200)
        p = sr.build_payload(c, "quick", "Debian")
        ids = [i["cve"] for i in p["items"]]
        self.assertTrue(all(f"CVE-2030-{n:04d}" in ids for n in range(200, 210)), "a fix-first item was cut")
        self.assertTrue(all(f"CVE-2030-{n:04d}" in ids for n in range(100, 140)), "a fix-soon item was cut while read items were kept")
        self.assertEqual((len(ids), p["cut"]), (50, 40))
        self.assertFalse(any(f"CVE-2030-{n:04d}" in ids for n in range(1, 41)), "a read item was kept while the cap cut something more urgent")

    def test_the_byte_cap_cuts_from_the_end_and_counts_it(self):
        c = [{"cve": f"CVE-2030-{i:04d}", "product": "p" * 120, "version": "1.0", "verdict": "in-range", "priority": "read"} for i in range(1, 41)]
        p = sr.build_payload(c, "quick", "Debian", max_items=100, max_bytes=2000)
        self.assertLessEqual(len(json.dumps(p, separators=(",", ":")).encode()), 2000)
        self.assertEqual(len(p["items"]) + p["cut"], 40)
        self.assertGreater(p["cut"], 0)

    def test_nothing_is_cut_below_the_cap_and_cut_says_zero(self):
        p = sr.build_payload(many(5), "deep", "Alpine")
        self.assertEqual((len(p["items"]), p["cut"]), (5, 0))

    def test_the_default_payload_of_the_maximum_size_fits_the_byte_cap(self):
        c = [{"cve": f"CVE-2030-{i:04d}", "product": "p" * 120, "version": "10.20.30p1", "verdict": "undetermined", "priority": "fix first"} for i in range(1, 80)]
        self.assertLessEqual(len(json.dumps(sr.build_payload(c, "deep", "Debian"), separators=(",", ":")).encode()), sr.MAX_BYTES)


if __name__ == "__main__":
    unittest.main()
