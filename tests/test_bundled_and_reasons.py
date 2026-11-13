# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Runtimes bundled inside packages (read, never run), the partial-name lead rule, and the receipt's undetermined causes and data line.
Invented names and reserved CVE ids; the fake binaries are a few bytes with an executable header, never a real program."""
import os, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
import tmpfold  # noqa: E402  (one temp root per test run, removed at exit)
from lattice_scan import bundled, cli  # noqa: E402

ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 64


def fake(path: Path, body: bytes, mode: int = 0o755) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    os.chmod(path, mode)


class Bundled(unittest.TestCase):
    def test_reads_the_release_mark_of_a_bundled_node_without_running_it(self):
        site = Path(tmpfold.mkdtemp())
        fake(site / "exampledriver" / "driver" / "node", ELF + b"x" * (bundled.CHUNK - 30) + b"https://nodejs.org/download/release/v24.17.0/node.tar.gz")
        got = bundled.find_node([str(site)])        # the mark straddles a chunk boundary
        self.assertEqual([(g["version"], g["package"]) for g in got], [("24.17.0", "exampledriver")])

    def test_a_script_or_a_text_file_named_node_is_not_read_as_a_runtime(self):
        site = Path(tmpfold.mkdtemp())
        fake(site / "examplecli" / "bin" / "node", b"#!/bin/sh\n# https://nodejs.org/download/release/v1.2.3\n")
        self.assertEqual(bundled.find_node([str(site)]), [])

    def test_a_bundled_node_is_matched_with_its_own_version(self):
        inv = {"packages": {}, "snaps": {}, "images": [], "node": "v22.22.1",
               "bundledNode": [{"version": "24.17.0", "where": "exampledriver in ~/.venv"}]}
        m = cli.name_candidate({"cve": "CVE-2099-0101", "vendor": "Nodejs", "product": "Node.js"}, inv)
        self.assertEqual(m[2], ["v22.22.1", "24.17.0"])
        self.assertIn("bundled in exampledriver", m[0])

    def test_without_bundled_runtimes_the_wording_is_unchanged(self):
        m = cli.name_candidate({"cve": "CVE-2099-0101", "vendor": "Nodejs", "product": "Node.js"}, {"packages": {}, "snaps": {}, "images": [], "node": "v22.22.1"})
        self.assertEqual(m[0], "Node.js v22.22.1 is installed")


class PartialName(unittest.TestCase):
    INV = {"packages": {"libexamplecanberra-pulse": "0.30-1", "bash": "5.3-2", "libexamplezip1": "1.1.0-2"}, "snaps": {}, "images": [], "imageDetails": {},
           "sources": {}, "kernel": "", "node": ""}

    def run_one(self, vendor: str, product: str):
        e = {"cve": "CVE-2099-0201", "vendor": vendor, "product": product, "ranges": []}
        return cli.candidate(e, self.INV), e.get("matchBasis")

    def test_a_product_word_only_inside_a_longer_name_is_a_lead(self):
        m, basis = self.run_one("Examplevendor", "Pulse Connect Secure")
        self.assertTrue(m)
        self.assertEqual(basis, "lead")
        self.assertIn("only part of a longer name", m[0])

    def test_a_package_named_like_the_product_stays_a_candidate(self):
        self.assertEqual(self.run_one("GNU", "Bash")[1], "names")

    def test_a_lib_prefixed_name_is_only_a_lead_for_a_name_only_match(self):
        # libpulse0 is not Ivanti Pulse and libcamera is not an IP camera. A real library CVE (Brotli, libwebp) has an identity row and joins by
        # identity before names are consulted, so for a name-only match the lib-stripped word is not evidence.
        saved = cli.IDENTITY
        try:
            cli.IDENTITY = {"list": {"generation": 1}}           # a list in use, with no row for this CVE
            self.assertEqual(self.run_one("Exampleco", "Examplezip")[1], "lead")
            e = {"cve": "CVE-2099-0203", "vendor": "Examplecanberra Secure", "product": "Pulse Connect Secure", "ranges": []}
            cli.candidate(e, self.INV)
            self.assertEqual(e["matchBasis"], "lead")             # libexamplecanberra-pulse is not the vendor either
            cli.IDENTITY = None                                   # no list (offline, an older server): the library name is still evidence
            self.assertEqual(self.run_one("Exampleco", "Examplezip")[1], "names")
        finally:
            cli.IDENTITY = saved

    def test_a_vendor_word_inside_another_name_is_not_the_vendor(self):
        inv = {**self.INV, "packages": {**self.INV["packages"], "exampleavahi-daemon": "0.8-1", "daemon-exampletools": "1.0"}}
        e = {"cve": "CVE-2099-0202", "vendor": "Daemon", "product": "Daemon Tools Lite", "ranges": []}
        cli.candidate(e, inv)
        self.assertNotEqual(e.get("matchBasis"), "names")

    def test_an_installed_vendor_keeps_the_match(self):
        m, basis = self.run_one("Examplecanberra", "Pulse")
        self.assertEqual(basis, "names")


class Reasons(unittest.TestCase):
    def test_server_codes_win_and_the_client_fills_in_the_rest(self):
        self.assertEqual(cli.undetermined_reason({"versionCheck": {"verdict": "undetermined", "reason": "investigating"}}, ""), "investigating")
        self.assertEqual(cli.undetermined_reason({"versionCheck": {"verdict": "undetermined", "why": "x"}}, "kernel in use is 7.0.0"), "kernel")
        self.assertEqual(cli.undetermined_reason({"versionCheck": {"verdict": "undetermined", "basis": "distribution",
                                                                  "why": "no fixed-version data for release 13 of this package"}}, ""), "release-not-covered")
        self.assertEqual(cli.undetermined_reason({"versionCheck": {"verdict": "undetermined", "why": "Lattice listed no version range for this product name"}}, ""), "no-range")
        self.assertEqual(cli.undetermined_reason({"versionCheck": {"verdict": "undetermined", "why": "a range bound is a date"}}, "product x matches y"), "names")

    def test_the_receipt_breaks_undetermined_down_and_names_its_data(self):
        rows = [["CVE-2099-0301", "", "", "", "", "", "", "CANDIDATE", "kernel in use is 7.0.0"],
                ["CVE-2099-0302", "", "", "", "", "", "", "CANDIDATE", "product examplezip matches libexamplezip1"],
                ["CVE-2099-0303", "", "", "", "", "", "", "FIXED", "fixed"]]
        imps = {"CVE-2099-0301": {"versionCheck": {"verdict": "undetermined", "why": "a range could not be compared"}},
                "CVE-2099-0302": {"versionCheck": {"verdict": "undetermined", "basis": "distribution", "reason": "release-not-covered"}},
                "CVE-2099-0303": {"versionCheck": {"verdict": "outside-range"}}}
        cli.SEEN.update({"snapshot": "0123abcd", "indexAsOf": "2099-01-02"})
        try:
            rec = cli.receipt({"packages": {}}, rows, 3, imps)
        finally:
            cli.SEEN.clear()
        self.assertEqual(rec["undetermined"], {"kernel": 1, "release-not-covered": 1})
        self.assertEqual(rec["data"]["graphSnapshot"], "0123abcd")
        self.assertEqual(sum(rec["undetermined"].values()), 2)


if __name__ == "__main__":
    unittest.main()


class Runtime(unittest.TestCase):
    E = {"cve": "CVE-2099-0401", "vendor": "Exampleco", "product": "Examplezip",
         "ranges": [{"product": "exampleco/examplezip", "start_including": "1.1.0", "end_excluding": "1.1.1"},
                    {"product": "nodejs/node.js", "start_including": "23.0.0", "end_excluding": "24.22.1"}]}

    def inv(self, **kw):
        return {"packages": {}, "snaps": {}, "images": [], "imageDetails": {}, "sources": {}, "kernel": "", "node": "", **kw}

    def test_a_bundled_node_inside_nvds_node_range_is_a_candidate_for_a_library_cve(self):
        e = dict(self.E)
        m = cli.candidate(e, self.inv(bundledNode=[{"version": "24.17.0", "where": "exampledriver in ~/.venv"}]))
        self.assertEqual(e["matchBasis"], "runtime")
        self.assertEqual(m[2], ["24.17.0"])
        self.assertIn("inside its range", m[0])

    def test_a_node_past_the_fix_is_not_a_runtime_match(self):
        e = dict(self.E)
        self.assertIsNone(cli.runtime_match(e, self.inv(node="v24.22.1", bundledNode=[{"version": "24.22.1", "where": "x in ~"}])))

    def test_no_node_range_no_runtime_match(self):
        e = {**self.E, "ranges": self.E["ranges"][:1]}
        self.assertIsNone(cli.runtime_match(e, self.inv(node="v24.17.0")))

    def test_the_distributions_own_node_is_left_to_the_distribution(self):
        e = dict(self.E)
        packaged = self.inv(node="v24.17.0", packages={"nodejs": "24.17.0+dfsg-1ubuntu1"})
        self.assertIsNone(cli.runtime_match(e, packaged))                          # linked against the system library: the package verdict decides
        self.assertTrue(cli.runtime_match(e, self.inv(node="v24.17.0", packages={"nodejs": "22.1.0+dfsg-1"})))   # an nvm node beside an older package
