"""OCO-5837: lattice-scan says what it is doing, on stderr only. Standard library only; invented products and reserved ids (CVE-2099-*)."""
import contextlib, io, sys, tempfile, threading, unittest
from http.server import HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli, manifests  # noqa: E402
from test_lattice_scan import INV, Stub, lookup  # noqa: E402


class Progress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}/mcp"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (cli.URL, cli.KEY, cli.OUT, cli.TODAY, cli.WINDOW, cli.inventory, cli.PROGRESS)
        cli.URL, cli.KEY, cli.OUT, cli.TODAY, cli.WINDOW = self.url, "", Path(self.tmp.name), "2026-11-01", 6
        cli.inventory = lambda: dict(INV)
        Stub.mode, Stub.seen = "json", []
        Stub.answers = {"CVE-2099-0001": lookup("CVE-2099-0001"), "CVE-2099-0002": lookup("CVE-2099-0002", product="Otherthing", vendor="Otherco")}
        cli.Lattice.last_gap = 0.0

    def tearDown(self):
        cli.URL, cli.KEY, cli.OUT, cli.TODAY, cli.WINDOW, cli.inventory, cli.PROGRESS = self.saved
        self.tmp.cleanup()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        sys.argv = ["lattice-scan", *argv]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main()
        return rc, out.getvalue(), err.getvalue()

    def test_host_scan_names_each_cve_and_what_it_compares(self):
        rc, out, err = self.run_cli("--progress", "--cve", "CVE-2099-0001", "--cve", "CVE-2099-0002", "--cve", "CVE-2099-0003")
        self.assertEqual(rc, 0)
        for want in ("[1/3] CVE-2099-0001  asking Lattice", "CISA lists Exampleco Examplelib; comparing with 2 packages, 0 snaps, 0 container image names and the kernel (6.1.0-99-example)",
                     "[1/3] CVE-2099-0001  CANDIDATE:", "[2/3] CVE-2099-0002  no installed package, snap, image or kernel matches",
                     "[3/3] CVE-2099-0003  not in CISA's exploited list in this snapshot (that is not the same as safe)"):
            self.assertIn(want, err)
        self.assertNotIn("[1/3]", out)                      # progress never reaches stdout

    def test_stdout_is_identical_with_and_without_progress(self):
        _, quiet_out, quiet_err = self.run_cli("--quiet", "--cve", "CVE-2099-0001")
        self.assertEqual(quiet_err, "")
        (cli.OUT / "findings.jsonl").unlink(); (cli.OUT / "seen.json").unlink()
        _, loud_out, loud_err = self.run_cli("--cve", "CVE-2099-0001")   # no flag: progress is the default
        self.assertEqual(quiet_out, loud_out)
        self.assertIn("asking Lattice", loud_err)

    def test_on_by_default_and_off_with_quiet_or_the_environment(self):
        _, _, err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertIn("asking Lattice", err)               # no flag, not a terminal: still shown
        for argv, env in ((["-q"], None), (["--quiet", "--progress"], None), ([], "0")):
            with mock.patch.dict("os.environ", {"LATTICE_SCAN_PROGRESS": env} if env else {}):
                _, _, err = self.run_cli(*argv, "--again", "--cve", "CVE-2099-0001")
            self.assertEqual(err, "", (argv, env))

    def test_inventory_parts_are_named_with_counts_and_no_package_names(self):
        cli.inventory = self.saved[5]
        outs = {"dpkg-query": "acl\t2.3\nsecretpkg\t9.9\n", "snap": "Name Version\ncore 1\n", "docker": "registry.example.invalid/app:1\n", "uname": "6.1.0-99-example\n"}
        with mock.patch.object(cli, "run", lambda cmd: outs.get(cmd[0], "")), mock.patch.object(cli, "PROGRESS", True):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                cli.inventory()
        text = err.getvalue()
        for want in ("[host] packages: 2 installed (dpkg)", "[host] snaps: 1", "[host] container images running (names only): 1", "[host] kernel: 6.1.0-99-example"):
            self.assertIn(want, text)
        self.assertNotIn("secretpkg", text)

    def test_project_scan_names_each_file_with_its_kind(self):
        root = Path(self.tmp.name) / "proj"
        root.mkdir()
        (root / "requirements.txt").write_text("examplelib==2.14.0\n")
        (root / "Dockerfile").write_text("FROM registry.example.invalid/base:1\n")
        rc, out, err = self.run_cli("project", str(root), "--progress", "--cve", "CVE-2099-0001")
        self.assertIn(rc, (0, 1))
        for want in ("[project] read requirements.txt  (Python requirements, 1 component)", "[project] read Dockerfile  (Docker image file, 1 component)",
                     "[project] proj: 2 file(s) read, 2 declared component(s)", "[1/1] CVE-2099-0001  asking Lattice", "comparing with 2 declared component(s) in 2 file(s)",
                     "[1/1] CVE-2099-0001  CANDIDATE:"):
            self.assertIn(want, err)
        self.assertNotIn("[project] read", out)

    def test_project_csv_on_stdout_is_untouched_by_progress(self):
        root = Path(self.tmp.name) / "p2"
        root.mkdir()
        (root / "requirements.txt").write_text("examplelib==2.14.0\n")
        _, with_p, _ = self.run_cli("project", str(root), "--format", "csv", "--progress", "--cve", "CVE-2099-0001")
        _, without, err = self.run_cli("project", str(root), "--format", "csv", "--quiet", "--cve", "CVE-2099-0001")
        self.assertEqual(with_p, without); self.assertEqual(err, "")

    def test_kind_names(self):
        self.assertEqual(manifests._kind("package-lock.json"), "JavaScript lockfile")
        self.assertEqual(manifests._kind("pom.xml"), "Java Maven file")

    def test_host_result_table_and_detail_files(self):
        rc, out, _ = self.run_cli("--quiet", "--cve", "CVE-2099-0001", "--cve", "CVE-2099-0002", "--cve", "CVE-2099-0003")
        self.assertEqual(rc, 0)
        self.assertIn("RESULT BY CVE", out)
        for want in ("CVE-2099-0001", "Exampleco Examplelib", "CANDIDATE", "CVE-2099-0002", "unmatch", "CVE-2099-0003", "unlisted"):
            self.assertIn(want, out)
        self.assertIn("DETAILED RESULT FILES", out)
        for want in (str(cli.OUT), "findings.jsonl", "scan.log", "inventory.json", "lattice-scan impact CVE-..."):
            self.assertIn(want, out)

    def test_open_finding_from_an_earlier_run_is_in_the_same_table(self):
        self.run_cli("--cve", "CVE-2099-0001")                     # run 1 records the finding
        rc, out, _ = self.run_cli("--cve", "CVE-2099-0002")        # run 2 names a different id
        self.assertEqual(rc, 0)
        self.assertEqual(out.count("RESULT BY CVE"), 1)
        table = out.split("RESULT BY CVE")[1].split("DETAILED RESULT FILES")[0]
        self.assertNotIn("not yet fixed", out)                     # said once, in the table, not again below it
        self.assertIn("CVE-2099-0002", table)                      # this run's result
        self.assertIn("CVE-2099-0001", table)                      # the earlier open finding, same table
        self.assertRegex(table, r"\bOPEN\b"); self.assertNotIn("(open)", table)
        self.assertIn("not read in this run", table)

    def test_project_result_table_and_detail_files(self):
        root = Path(self.tmp.name) / "p3"
        root.mkdir()
        (root / "requirements.txt").write_text("examplelib==2.14.0\n")
        csv_path = Path(self.tmp.name) / "f.csv"
        _, out, _ = self.run_cli("project", str(root), "--quiet", "--cve", "CVE-2099-0001,CVE-2099-0003", "--csv", str(csv_path))
        self.assertIn("RESULT BY CVE", out)
        self.assertIn("CVE-2099-0001", out); self.assertIn("IN RANGE", out); self.assertIn("examplelib2.14.0(requirements.txt)", "".join(out.split()))
        self.assertIn("CVE-2099-0003", out); self.assertIn("not listed", out)
        self.assertIn("DETAILED RESULT FILES", out); self.assertIn(str(csv_path), out)
        _, out2, _ = self.run_cli("project", str(root), "--quiet", "--cve", "CVE-2099-0001")
        self.assertIn("No detail file was written", out2)

    def test_ransomware_column_reads_the_cisa_field(self):
        Stub.answers["CVE-2099-0001"]["items"][1]["known_ransomware_use"] = "Known"
        Stub.answers["CVE-2099-0002"]["items"][1]["known_ransomware_use"] = "Unknown"
        _, out, _ = self.run_cli("--cve", "CVE-2099-0001", "--cve", "CVE-2099-0002")
        rows = {l.split()[0]: l for l in out.splitlines() if l.startswith("CVE-2099")}
        self.assertIn("known", rows["CVE-2099-0001"]); self.assertRegex(rows["CVE-2099-0001"], r"\bknown\b")
        self.assertNotRegex(rows["CVE-2099-0002"], r"\bknown\b")   # CISA's "Unknown" is a '-', never "no ransomware"
        _, out2, _ = self.run_cli("--cve", "CVE-2099-0003")          # an earlier finding keeps its ransomware cell
        self.assertRegex(out2, r"CVE-2099-0001\s+yes\s+-\s+2026-10-30\s+2026-11-20\s+known\s+-\s+OPEN")

    def test_table_carries_exploited_cvss_dates_and_patch_due(self):
        Stub.answers["CVE-2099-0001"]["items"][0]["cvss_score"] = 9.8
        _, out, _ = self.run_cli("--cve", "CVE-2099-0001", "--cve", "CVE-2099-0003")
        head = next(l for l in out.splitlines() if l.startswith("CVE "))
        for col in ("EXPLOIT", "CVSS", "LISTED", "PATCH DUE", "RANSOM", "PRODUCT", "RESULT"):
            self.assertIn(col, head)
        rows = {l.split()[0]: l for l in out.splitlines() if l.startswith("CVE-2099")}
        self.assertNotIn("(in ", rows["CVE-2099-0001"])             # the date only, no days left or late
        self.assertRegex(rows["CVE-2099-0001"], r"yes\s+9\.8\s+2026-10-30\s+2026-11-20\b")
        self.assertRegex(rows["CVE-2099-0003"], r"\bno\b")

    def test_table_is_one_line_per_row_without_a_rule_line(self):
        from lattice_scan import report
        long = "word " * 40
        lines, hid = report.table(["CVE", "NOTE"], [["x", long]], 60, fit=False)
        self.assertEqual(len(lines), 2, lines)                    # header + one row: no wrapping, no dashed rule
        self.assertEqual(lines[0].split(), ["CVE", "NOTE"])
        self.assertTrue(lines[1].endswith(long.strip()))          # piped output keeps the whole cell for grep/awk
        cut, hid = report.table(["CVE", "NOTE"], [["x", long]], 60)
        self.assertEqual(hid, [])
        wide = [["x", "2026-10-30", "p" * 20, "a long match note " * 3]]
        lines2, hid2 = report.table(["CVE", "LISTED", "PRODUCT", "MATCH"], wide, 60, drop=("LISTED", "PRODUCT"), min_last=30)
        self.assertEqual(hid2, ["LISTED"])                         # hiding one column was enough
        self.assertNotIn("LISTED", lines2[0]); self.assertLessEqual(max(map(len, lines2)), 60)
        _, hid3 = report.table(["CVE", "LISTED", "PRODUCT", "MATCH"], wide, 60, fit=False, drop=("LISTED", "PRODUCT"), min_last=30)
        self.assertEqual(hid3, [])                                 # piped output always keeps every column
        self.assertLessEqual(len(cut[1]), 60)                     # with a width to hold the last column is cut with an ellipsis
        self.assertTrue(cut[1].endswith("\u2026"), cut)


if __name__ == "__main__":
    unittest.main()
