# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The precision and recall gate on the synthetic host corpus (packaging/corpus_score.py). Invented names, reserved CVE ids."""
import json, os, re, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))
os.environ.setdefault("LATTICE_SCAN_DIR", tempfile.mkdtemp())   # the matcher may write a debug line; never into the user's records
import corpus_score  # noqa: E402

EXPECTED = json.loads((ROOT / "tests" / "corpus" / "hosts-expected.json").read_text())


class Gate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ident, cls.names, cls.verd = corpus_score.score("identity"), corpus_score.score("names"), corpus_score.score("verdict")

    def test_each_case_gives_its_frozen_result(self):
        for mode, s in (("identity", self.ident), ("verdict", self.verd)):
            got = {d["id"]: d["result"] for d in s["detail"]}
            changed = {k: (EXPECTED[mode].get(k), v) for k, v in got.items() if EXPECTED[mode].get(k) != v}
            self.assertEqual(changed, {}, f"{mode}: case results changed (expected, now): review, then update tests/corpus/hosts-expected.json and its floor")

    def test_precision_and_recall_do_not_drop_below_the_floor(self):
        for mode, s in (("identity", self.ident), ("verdict", self.verd)):
            self.assertGreaterEqual(s["precision"], EXPECTED["floor"][mode]["precision"], mode)
            self.assertGreaterEqual(s["recall"], EXPECTED["floor"][mode]["recall"], mode)

    def test_each_step_is_never_worse_than_the_one_before(self):
        for a, b in ((self.names, self.ident), (self.ident, self.verd)):
            self.assertGreaterEqual(b["precision"], a["precision"], b["mode"])
            self.assertGreaterEqual(b["recall"], a["recall"], b["mode"])

    def test_the_stand_in_server_was_asked_only_about_joined_packages(self):
        case = next(c for c in corpus_score.cases() if c["id"] == "F8")
        srv = corpus_score.StandInServer("CVE-2099-1008", case["fixes"])
        srv.call("graph_affects", product="examplezip", ecosystem="deb", version="1.1.0-2+deb13u1", os="Debian 13", kind="package")
        self.assertEqual(srv.call("graph_affects", product="examplezip", ecosystem="deb", version="1.1.0-2", os="Debian 13")["results"][0]["verdict"], "in-range")

    def test_every_case_is_synthetic_and_carries_its_reason(self):
        for c in corpus_score.cases():
            self.assertRegex(c["entry"]["cve"], r"^CVE-2099-\d{4}$", c["id"])
            self.assertTrue(c["why"] and c["mirrors"] and isinstance(c["truth"], bool), c["id"])

    def test_the_release_check_wants_the_exact_figures(self):
        line = corpus_score.notes_line(self.verd)
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
            f.write("# notes\n\nno figures here\n")
        self.assertEqual(corpus_score.main(["--check-notes", f.name]), 1)
        Path(f.name).write_text(f"# notes\n\n{line}\n")
        self.assertEqual(corpus_score.main(["--check-notes", f.name]), 0)
        self.assertRegex(line, r"^Corpus: precision \d\.\d\d, recall \d\.\d\d on \d+ synthetic host cases \(without the distribution verdict: \d\.\d\d, \d\.\d\d\)$")


if __name__ == "__main__":
    unittest.main()
