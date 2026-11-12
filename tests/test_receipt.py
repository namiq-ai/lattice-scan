# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The receipt: what a host scan covered, written once and shown twice (console and JSON) with the same numbers. Invented names, reserved ids."""
import json, re, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import tmpfold  # noqa: E402  (one temp root per test run, removed at exit)
from lattice_scan import cli  # noqa: E402
from test_lattice_scan import Client  # noqa: E402


class Receipt(unittest.TestCase):
    setUpClass = classmethod(Client.setUpClass.__func__)
    tearDownClass = classmethod(Client.tearDownClass.__func__)
    setUp, tearDown, run_cli = Client.setUp, Client.tearDown, Client.run_cli

    def test_the_console_and_the_json_report_the_same_counts(self):
        f = Path(tmpfold.mkdtemp()) / "r.json"
        rc, out, _ = self.run_cli("--cve", "CVE-2099-0001,CVE-2099-9999", "--json", str(f))   # one run: the console text and the JSON file
        self.assertIn("WHAT THIS RUN COVERED", out)
        line = next(l for l in out.splitlines() if l.strip().startswith("CVEs read:"))
        console = dict((k, int(v)) for k, v in re.findall(r"([A-Za-z]+) (\d+)", line.split("results:", 1)[1]))
        doc = json.loads(f.read_text())
        self.assertEqual(doc["receipt"]["results"], console)
        self.assertEqual(doc["receipt"]["results"], doc["counts"])              # the receipt counts the very table the JSON rows hold
        self.assertEqual(doc["receipt"]["cvesRead"], int(re.search(r"CVEs read: (\d+)", line).group(1)))

    def test_it_says_what_a_clean_result_does_not_cover(self):
        _, js, _ = self.run_cli("--cve", "CVE-2099-9999", "--format", "json")
        nc = " ".join(json.loads(js)["receipt"]["notCovered"])
        for words in ("not read in this run", "Windows", "--python", "--node"):
            self.assertIn(words, nc)

    def test_without_an_identity_list_it_says_so(self):
        _, js, _ = self.run_cli("--cve", "CVE-2099-9999", "--format", "json")
        self.assertEqual(json.loads(js)["receipt"]["identityList"]["used"], False)   # a test server is not the public one: no list


del Client


if __name__ == "__main__":
    unittest.main()
