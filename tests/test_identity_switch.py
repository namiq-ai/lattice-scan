# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The host matcher uses the signed identity list where it has a row for the CVE, and names everywhere else. Invented packages, reserved CVE ids."""
import os, sys, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli, identities, lattice_identity as li  # noqa: E402

ROWS = {
    "CVE-2099-0001": li.Row("CVE-2099-0001", ("deb:examplessh",), li.Component("server", ("examplessh-server",)), "osv-debian"),
    "CVE-2099-0002": li.Row("CVE-2099-0002", ("deb:examplessl",), None, "osv-debian"),
    "CVE-2099-0003": li.Row("CVE-2099-0003", ("pypi:exampleword",), None, "osv-pypi"),
    "CVE-2099-0006": li.Row("CVE-2099-0006", ("deb:linux",), None, "osv-debian"),
    "CVE-2099-0005": li.Row("CVE-2099-0005", ("apk:examplezip",), None, "osv-alpine"),
}
INV = {"kernel": "6.1.0", "os": "Example OS", "manager": "dpkg", "node": "", "restartRequired": False, "hash": "x", "host": {},
       "packages": {"examplessh-client": "1:9.2p1-2", "libexssl3": "3.0.11-1", "node-exampleword": "2.0.0-1", "exampletool": "1.0-1", "linux-libc-dev": "6.12.1-1"},
       "sources": {"examplessh-client": "examplessh", "libexssl3": "examplessl", "linux-libc-dev": "linux"},
       "snaps": {}, "images": ["examplebox:1"],
       "imageDetails": {"examplebox:1": {"packageManager": "apk", "packages": {"examplezip-libs": "1.2-r0"}, "sources": {"examplezip-libs": "examplezip"}}}}


def entry(cve, product, vendor="Exampleco"):
    return {"cve": cve, "vendor": vendor, "product": product, "title": "", "added": "2099-01-02", "due": "2099-01-23", "action": "", "affected": [], "ranges": []}


class WithList(unittest.TestCase):
    def setUp(self):
        self.p = mock.patch.object(cli, "IDENTITY", {"rows": ROWS, "aliases": {}, "note": "test"})
        self.p.start()

    def tearDown(self):
        self.p.stop()

    def test_a_client_package_does_not_match_a_server_flaw_when_the_server_package_is_absent(self):
        e = entry("CVE-2099-0001", "Examplessh")
        self.assertIsNone(cli.candidate(e, INV))
        self.assertEqual(e["matchBasis"], "component-absent")

    def test_the_server_package_present_makes_it_a_match(self):
        inv = {**INV, "packages": {**INV["packages"], "examplessh-server": "1:9.2p1-2"}, "sources": {**INV["sources"], "examplessh-server": "examplessh"}}
        e = entry("CVE-2099-0001", "Examplessh")
        why, installed, vers = cli.candidate(e, inv)
        self.assertEqual(e["matchBasis"], "identity")
        self.assertIn("examplessh-server 1:9.2p1-2", installed)

    def test_a_library_named_unlike_its_product_now_matches_through_its_source(self):
        e = entry("CVE-2099-0002", "ExampleSSL")
        self.assertIsNone(cli.name_candidate(dict(e), INV))   # names alone never found it
        why, installed, vers = cli.candidate(e, INV)
        self.assertEqual((installed, vers, e["matchBasis"]), (["libexssl3 3.0.11-1"], ["3.0.11-1"], "identity"))
        self.assertIn("deb:examplessl", why)

    def test_a_name_match_the_list_does_not_support_is_a_lead_with_no_range_compared(self):
        e = entry("CVE-2099-0003", "Exampleword")
        m = cli.candidate(e, INV)
        self.assertEqual(e["matchBasis"], "lead")
        imp = cli.impact(e, INV, m[1], m[2])
        self.assertEqual((imp["versionCheck"]["verdict"], imp["matchBasis"]), ("lead", "lead"))

    def test_a_package_inside_an_image_joins_too(self):
        e = entry("CVE-2099-0005", "Examplezip")
        why, installed, vers = cli.candidate(e, INV)
        self.assertEqual(installed, ["examplezip-libs (image examplebox:1) 1.2-r0"])

    def test_a_kernel_flaw_is_the_running_kernel_not_the_kernel_headers_package(self):
        e = entry("CVE-2099-0006", "Kernel", vendor="Linux")
        why, installed, vers = cli.candidate(e, INV)
        self.assertEqual((vers, e["matchBasis"]), (["6.1.0"], "names"))

    def test_a_cve_without_a_row_is_matched_by_names_as_before(self):
        e = entry("CVE-2099-0004", "Exampletool")
        self.assertEqual(cli.candidate(e, INV), cli.name_candidate(dict(e), INV))
        self.assertEqual(e["matchBasis"], "names")


class Loading(unittest.TestCase):
    def setUp(self):
        self.p = mock.patch.object(cli, "IDENTITY", None)
        self.p.start()

    def tearDown(self):
        self.p.stop()

    def test_no_list_for_a_test_or_private_lattice_server_unless_named(self):
        with mock.patch.object(cli, "URL", "http://127.0.0.1:9/mcp"), mock.patch.dict(os.environ, {"LATTICE_SCAN_IDENTITIES_URL": ""}):
            self.assertEqual(cli.identities_url(), "")
        with mock.patch.object(cli, "URL", cli.PROD_LATTICE_URL), mock.patch.dict(os.environ, {"LATTICE_SCAN_IDENTITIES_URL": ""}):
            self.assertEqual(cli.identities_url(), identities.LIST_URL)
        with mock.patch.object(cli, "URL", cli.PROD_LATTICE_URL), mock.patch.dict(os.environ, {"LATTICE_SCAN_IDENTITIES_URL": "0"}):
            self.assertEqual(cli.identities_url(), "")

    def test_a_refused_list_leaves_names_in_charge_and_says_so(self):
        with mock.patch.object(cli, "identities_url", return_value="https://identities.example.test/identities.json"), \
             mock.patch.object(identities, "load", side_effect=identities.IdentitiesRefused("the list signature does not verify")):
            st = cli.use_identities()
        self.assertIsNone(st["rows"])
        self.assertIn("does not verify", st["note"])
        e = entry("CVE-2099-0002", "Exampletool")
        self.assertEqual(cli.candidate(e, INV), cli.name_candidate(dict(e), INV))


if __name__ == "__main__":
    unittest.main()
