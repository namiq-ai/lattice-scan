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
        self.assertIn("Synth", t); self.assertIn("libsynth1 1.2.0-3ubuntu0.1 in host", t)
        self.assertEqual(t.count("2026-11-10"), 1); self.assertEqual(t.count("overdue by 2 days"), 1)

    def test_the_preview_counts_every_image_name_the_record_sends(self):
        r = rec.build_record(INV, [], "deep", "Debian")
        names = set(r["inventory"]["images"]) | set(r["inventory"]["imageDetails"])
        self.assertEqual(len(names), 26)
        self.assertIn("26 container image name(s)", flow.preview(r))


if __name__ == "__main__":
    unittest.main()


POSTURE = {"scope": "user", "level": "deep", "ports": [{"proto": "tcp", "port": 22, "bind": "all interfaces"}, {"proto": "tcp", "port": 5432, "bind": "loopback only"}],
           "observations": [{"level": "note", "topic": "ports", "text": "1 port(s) listen on all interfaces: tcp/22. That is normal for a server."},
                            {"level": "attention", "topic": "ssh", "text": "SSH accepts passwords (a safe choice only behind a firewall); it may be harmless."}],
           "unreadable": ["firewall rules (needs root)"]}


class PostureSection(unittest.TestCase):
    def build(self, posture):
        items = flow.host_items([(E1, "why", IMP)], INV)
        return rt.build_report(items, sr.build_payload(items, "deep", "Debian"), dt.date(2026, 11, 12), posture=posture)

    def test_the_section_comes_after_what_to_check_and_before_the_sources_with_the_signals_attention_first(self):
        t = self.build(POSTURE)
        self.assertLess(t.index("4. What to check"), t.index("5. " + rt.POSTURE_TITLE)); self.assertLess(t.index("5. " + rt.POSTURE_TITLE), t.index("6. Sources"))
        self.assertLess(t.index("[attention]"), t.index("[note]")); self.assertIn("2 listening sockets (TCP and UDP, IPv4 and IPv6 counted separately): 1 on all interfaces, 1 on loopback only", t)
        self.assertIn("Not read: firewall rules (needs root)", t); self.assertIn("never sent", t); self.assertIn("8. Limits", t)

    def test_without_a_posture_reading_the_report_is_unchanged(self):
        t = self.build(None)
        self.assertNotIn(rt.POSTURE_TITLE, t); self.assertIn("7. Limits", t)

    def test_the_machines_own_signal_text_is_quoted_not_judged_by_the_wording_guard_but_the_reports_own_words_still_are(self):
        self.build(POSTURE)                                   # a signal that says 'safe' does not stop the report: it is quoted
        with self.assertRaisesRegex(ValueError, "safe"):
            rt.check_wording("this machine is safe", [], [])

    def test_posture_never_enters_the_record(self):
        r = rec.build_record({**INV, "posture": POSTURE, "ports": POSTURE["ports"]}, [], "deep", "Debian")
        self.assertNotIn("22", str(r["inventory"].get("host", {}))); self.assertNotIn("SSH accepts", str(r)); self.assertNotIn("posture", r["inventory"])
