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
        cls.ident, cls.names = corpus_score.score("identity"), corpus_score.score("names")

    def test_each_case_gives_its_frozen_result(self):
        got = {d["id"]: d["result"] for d in self.ident["detail"]}
        changed = {k: (EXPECTED["identity"].get(k), v) for k, v in got.items() if EXPECTED["identity"].get(k) != v}
        self.assertEqual(changed, {}, "case results changed (expected, now): review, then update tests/corpus/hosts-expected.json and its floor")

    def test_precision_and_recall_do_not_drop_below_the_floor(self):
        self.assertGreaterEqual(self.ident["precision"], EXPECTED["floor"]["precision"])
        self.assertGreaterEqual(self.ident["recall"], EXPECTED["floor"]["recall"])

    def test_the_identity_join_is_never_worse_than_names_alone(self):
        self.assertGreaterEqual(self.ident["precision"], self.names["precision"])
        self.assertGreaterEqual(self.ident["recall"], self.names["recall"])

    def test_every_case_is_synthetic_and_carries_its_reason(self):
        for c in corpus_score.cases():
            self.assertRegex(c["entry"]["cve"], r"^CVE-2099-\d{4}$", c["id"])
            self.assertTrue(c["why"] and c["mirrors"] and isinstance(c["truth"], bool), c["id"])

    def test_the_release_check_wants_the_exact_figures(self):
        line = corpus_score.notes_line(self.ident)
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
            f.write("# notes\n\nno figures here\n")
        self.assertEqual(corpus_score.main(["--check-notes", f.name]), 1)
        Path(f.name).write_text(f"# notes\n\n{line}\n")
        self.assertEqual(corpus_score.main(["--check-notes", f.name]), 0)
        self.assertRegex(line, r"^Corpus: precision \d\.\d\d, recall \d\.\d\d on \d+ synthetic host cases$")


if __name__ == "__main__":
    unittest.main()
