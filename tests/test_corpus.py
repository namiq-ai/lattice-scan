"""The (pid, CVE, verdict) corpus: the project matcher on fixed synthetic fixtures must give exactly the stored set. Invented names and reserved ids only."""
import contextlib, io, json, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import tmpfold  # noqa: E402  (one temp root per test run, removed at exit)
from lattice_scan import cli  # noqa: E402
from test_lattice_scan import Client, Stub, lookup  # noqa: E402

CORPUS = ROOT / "tests" / "corpus"


class Corpus(unittest.TestCase):
    setUpClass = classmethod(Client.setUpClass.__func__)
    tearDownClass = classmethod(Client.tearDownClass.__func__)
    setUp = Client.setUp
    tearDown = Client.tearDown

    def pairs(self, project: Path):
        out = Path(tmpfold.mkdtemp()) / "r.json"
        sys.argv = ["lattice-scan", "project", str(project), "--kev-catalogue", str(CORPUS / "catalogue.json"), "--json", str(out), "--quiet"]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main()
        self.assertEqual(rc, 0, project.name)
        doc = json.loads(out.read_text())
        return {(d["pid"], c["cve"], d["verdict"]) for r in doc["projects"] for c in r["candidates"] for d in c["declared"]}

    def test_the_matcher_gives_exactly_the_stored_pairs(self):
        cli.KEY, Stub.tier = "k", "trial_accepted"
        rows = json.loads((CORPUS / "ranges.json").read_text())
        Stub.answers = {c: lookup(c, product=v["product"], vendor=v["vendor"], ranges=v["ranges"]) for c, v in rows.items()}
        expected = json.loads((CORPUS / "expected.json").read_text())
        projects = sorted(p for p in (CORPUS / "projects").iterdir() if p.is_dir())
        self.assertEqual([p.name for p in projects], sorted(k for k in expected if not k.startswith("_")))
        for proj in projects:
            got, want = self.pairs(proj), {tuple(x) for x in expected[proj.name]}
            self.assertEqual((sorted(got - want), sorted(want - got)), ([], []), f"{proj.name}: (added, removed) against corpus/expected.json")


del Client   # imported only to borrow its stub server set-up; unittest must not run its tests again here


if __name__ == "__main__":
    unittest.main()
