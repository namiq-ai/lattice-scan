# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The default scan shows what it knows of every CVE it lists and the findings still open from earlier runs; --refresh runs the scan; a CVE CISA does not list
is related to what is installed, images included. Invented products and reserved ids only."""
import copy, sys, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli  # noqa: E402
from test_agent_entry import Entry, EntryBase, exp, feed  # noqa: E402
from test_lattice_scan import Stub  # noqa: E402

OPEN = {"event": "found", "ref": "CVE-2099-7777", "on": "2026-11-01", "listed": "2026-10-20", "why": "product widgetq matches widgetq-server", "title": "Widgetq Server RCE",
        "due": "2026-10-23", "kind": "kev", "ransomware": "Unknown", "cvss": 9.8,
        "impact": {"installed": ["widgetq-server 1.0"], "listed": "2026-10-20", "due": "2026-10-23", "action": "Apply updates.", "versionCheck": {"verdict": "in-range", "why": "1.0 inside < 2.0"},
                   "changelogNamesCve": []}}
DAILY = ((exp("CVE-2099-1001", vendor="Nowhere", product="Nothingware"),), ({"id": "CVE-2099-2002", "vendor": "Exampleco", "product": "Examplelib", "cvss": 9.1, "published": "2026-11-04"},))


def with_open(test):
    def inner(self):
        cli.private_dir()
        cli.append("findings.jsonl", copy.deepcopy(OPEN))
        return test(self)
    return inner


class Recent(EntryBase):
    def setUp(self):
        super().setUp()
        Entry.feed = feed(daily=DAILY)

    @with_open
    def test_open_findings_are_listed_even_when_nothing_on_the_list_matches(self):
        rc, out, err = self.run_cli()
        self.assertEqual(rc, 0, err)
        self.assertIn("CVE-2099-7777", out)                                   # the table row
        self.assertIn("Widgetq Server RCE", out)                              # and its saved detail
        self.assertIn("version check: in-range", out)
        self.assertIn("not read in this run", out)

    def test_every_row_of_the_table_has_a_detail_block(self):
        rc, out, _ = self.run_cli()
        self.assertEqual(rc, 0)
        self.assertIn("  CVE-2099-1001  Nowhere Nothingware  [", out)
        self.assertIn("  CVE-2099-2002  Exampleco Examplelib  [", out)           # the watched critical one, which does match
        for cve in ("CVE-2099-1001", "CVE-2099-2002"):
            self.assertIn(f"lattice-scan --cve {cve}", out)
        self.assertIn("why no match: needs all of: nothingware", out)
        self.assertIn("this machine has none of them", out)
        self.assertIn("listed 2026-11-03; due 2026-11-06 (in 2 days)", out)
        self.assertIn("EPSS 0.100", out)
        self.assertIn("critical, not known exploited", out)

    def test_refresh_runs_the_scan_after_showing_the_inventory(self):
        rc, out, err = self.run_cli("--refresh")
        self.assertEqual(rc, 0, err)
        self.assertIn("inventory ", out.splitlines()[0])                      # the inventory comes first
        self.assertIn("packages:", out)
        self.assertIn("recent 2026-11-04", out)                               # then the scan
        self.assertIn("CVE-2099-1001", out)

    def test_refresh_with_inventory_makes_no_network_call(self):
        seen = len(Stub.seen)
        rc, out, _ = self.run_cli("--refresh", "--inventory")
        self.assertEqual(rc, 0)
        self.assertNotIn("recent 2026", out)
        self.assertEqual(len(Stub.seen), seen)


class Leads(unittest.TestCase):
    INV = {"kernel": "7", "os": "x", "node": "", "restartRequired": False, "snaps": {}, "images": ["a:1"], "host": {},
           "packages": {"openssh-server": "1:10.0p1-5", "openssh-client": "1:10.0p1-5", "bash": "5.2"},
           "imageDetails": {"alp:1": {"name": "alp", "os": "alpine", "osName": "Alpine Linux v3.21", "packages": {"musl": "1.2.5-r8", "busybox": "1.37"}},
                            "deb:1": {"name": "deb", "os": "debian", "packages": {"bash": "5.2", "libc6": "2.36"}}}}
    TEXT = "sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass."

    def test_description_words_are_related_to_the_host_and_each_image(self):
        lead = cli.installed_leads(self.TEXT, self.INV)
        self.assertEqual(lead["words"], ["musl", "openssh"])
        self.assertEqual(lead["host"]["openssh"], ["openssh-client 1:10.0p1-5", "openssh-server 1:10.0p1-5"])
        self.assertNotIn("musl", lead["host"])
        self.assertEqual(lead["images"], {"musl": ["alp:1"]})
        self.assertEqual(lead["allIn"], [])                                    # no opened image has both

    def test_printed_lead_block_says_which_side_has_what_and_that_no_image_has_both(self):
        import contextlib, io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.print_leads(self.TEXT, self.INV)
        t = out.getvalue()
        self.assertIn("a lead for a person to read, not a match", t)
        self.assertIn("openssh: on the host openssh-client", t)
        self.assertIn("in no opened image", t)
        self.assertIn("musl: not on the host; in 1 opened image: alp:1", t)
        self.assertIn("images that have all of musl, openssh: none of the 2 opened", t)
        self.assertIn("before 10.6p2", t)

    def test_an_image_with_all_the_words_is_named(self):
        inv = copy.deepcopy(self.INV)
        inv["imageDetails"]["alp:1"]["packages"]["openssh"] = "10.0_p1-r5"
        lead = cli.installed_leads(self.TEXT, inv)
        self.assertEqual(lead["allIn"], ["alp:1"])

    def test_nothing_installed_named_is_said_plainly(self):
        import contextlib, io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.print_leads("A flaw in Zorblax before 2.0 allows attackers to crash it.", self.INV)
        self.assertIn("none (no word of the description", out.getvalue())


if __name__ == "__main__":
    unittest.main()
