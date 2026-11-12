# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Defects found by running the deep scan on a real host with the merged report code (2026-11-12). Synthetic data only."""
import datetime as dt, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import scan_record as rec, scan_report as sr, scan_report_flow as flow, scan_report_text as rt  # noqa: E402

INV = {"packages": {"libsynth1": "1.2.0-3ubuntu0.1"}, "snaps": {"synthsnap": "9.1"}, "images": ["redis:alpine"],
       "imageDetails": {f"img{i}:latest": {"id": f"sha256:{i}", "os": "alpine", "osVersion": "3.20", "packages": {}} for i in range(25)}}
E1 = {"cve": "CVE-2030-0001", "title": "Synth Library", "product": "Synth", "added": "2026-10-27", "due": "2026-11-10"}
IMP = {"installed": ["libsynth1 1.2.0-3ubuntu0.1"], "versionCheck": {"verdict": "in-range"}, "dueStatus": "overdue by 2 days",
       "priority": {"level": "fix first", "reasons": ["CISA patch-due date passed (overdue by 2 days)", "EPSS 0.83"]}}


class Dogfood(unittest.TestCase):
    def test_the_matched_package_string_gives_the_name_and_the_upstream_version(self):
        it = flow.host_items([(E1, "why", IMP)], INV)[0]
        self.assertEqual((it["installed"], it["matched"]), (["libsynth1"], ["libsynth1 1.2.0-3ubuntu0.1"]))
        self.assertEqual(sr.build_payload([it], "deep", "Debian")["items"][0]["version"], "1.2.0")

    def test_a_kernel_entry_has_its_version_too(self):
        it = flow.host_items([(E1, "why", {**IMP, "installed": ["kernel 7.0.0-41-cix"]})], INV)[0]
        self.assertEqual((it["installed"], sr.upstream_version("7.0.0-41-cix")), (["kernel"], "7.0.0"))

    def test_a_bare_name_falls_back_to_the_inventory_version(self):
        self.assertEqual(flow.host_items([(E1, "why", {**IMP, "installed": ["libsynth1"]})], INV)[0]["matched"], ["libsynth1 1.2.0-3ubuntu0.1"])

    def test_the_report_shows_the_version_the_match_and_the_due_date_once(self):
        items = flow.host_items([(E1, "why", IMP)], INV)
        t = rt.build_report(items, sr.build_payload(items, "deep", "Debian"), dt.date(2026, 11, 12))
        self.assertIn("Synth 1.2.0", t); self.assertIn("matched: libsynth1 1.2.0-3ubuntu0.1", t)
        self.assertEqual(t.count("2026-11-10"), 1); self.assertEqual(t.count("overdue by 2 days"), 1)

    def test_the_preview_counts_every_image_name_the_record_sends(self):
        r = rec.build_record(INV, [], "deep", "Debian")
        names = set(r["inventory"]["images"]) | set(r["inventory"]["imageDetails"])
        self.assertEqual(len(names), 26)
        self.assertIn("26 container image name(s)", flow.preview(r))


if __name__ == "__main__":
    unittest.main()
