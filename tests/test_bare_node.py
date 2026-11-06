# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""A CVE the graph holds only as a bare node (no NVD record yet): the scan says so, uses namiq.io's list when it has the id, and never calls the CVE safe."""
import sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_agent_entry import Entry, EntryBase, feed  # noqa: E402
from test_lattice_scan import Stub, INV  # noqa: E402

BARE = {"snapshot": "s1", "notices": [], "note": "n", "items": [{"id": "CVE-2099-5555", "uid": "sha256:stub", "labels": ["CVE", "ThreatIntel"], "source": "materialised",
                                                              "title": "CVE-2099-5555", "primary": True}]}
ROW = {"id": "CVE-2099-5555", "vendor": "Examplevendor", "product": "Examplelib", "cvss": 10, "published": "2026-11-04", "cvssSource": "cna"}


class Bare(EntryBase):
    def setUp(self):
        super().setUp()
        Stub.answers["CVE-2099-5555"] = BARE

    def test_the_scan_says_the_graph_holds_only_a_bare_node(self):
        Entry.feed = feed()
        rc, out, err = self.run_cli("--cve", "CVE-2099-5555")
        self.assertEqual(rc, 0, err)
        self.assertIn("Lattice holds only a bare node for it", out)
        self.assertIn("no NVD record, description, EPSS", out)
        self.assertIn("says nothing about risk", out)
        self.assertNotRegex(out, r"(?i)\b(is|are|looks|considered) safe\b|no risk|not exploited")
        self.assertIn("does not have it either", out)
        self.assertIn("nvd.nist.gov/vuln/detail/CVE-2099-5555", out)

    def test_namiq_list_fills_in_what_it_knows_and_whether_it_may_match(self):
        Entry.feed = feed(critical=[ROW])
        rc, out, _ = self.run_cli("--cve", "CVE-2099-5555")
        self.assertEqual(rc, 0)
        self.assertIn("namiq.io's list of recent CVEs has it: Examplelib (vendor Examplevendor), critical, not known to be exploited; published 2026-11-04; CVSS 10 (cna).", out)
        self.assertIn("something installed may match this product", out)          # INV has libexamplelib2

    def test_a_product_nothing_installed_has_says_so(self):
        Entry.feed = feed(critical=[dict(ROW, product="Nothingware", vendor="Nowhere")])
        _, out, _ = self.run_cli("--cve", "CVE-2099-5555")
        self.assertIn("nothing installed matches this product by name", out)

    def test_an_unreachable_list_does_not_hide_the_bare_node_notice(self):
        Entry.feed = feed(schema="lattice-recent/1")                              # refused: too old
        rc, out, _ = self.run_cli("--cve", "CVE-2099-5555")
        self.assertEqual(rc, 0)
        self.assertIn("Lattice holds only a bare node", out)
        self.assertIn("does not have it either", out)


if __name__ == "__main__":
    unittest.main()
