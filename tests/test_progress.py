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
        _, quiet_out, quiet_err = self.run_cli("--cve", "CVE-2099-0001")
        self.assertEqual(quiet_err, "")                     # not a terminal, no flag: nothing extra
        (cli.OUT / "findings.jsonl").unlink(); (cli.OUT / "seen.json").unlink()
        _, loud_out, _ = self.run_cli("--progress", "--cve", "CVE-2099-0001")
        self.assertEqual(quiet_out, loud_out)

    def test_quiet_wins_even_on_a_terminal(self):
        with mock.patch.object(sys.stderr, "isatty", create=True, return_value=True):
            pass
        class Tty(io.StringIO):
            def isatty(self): return True
        out, err = io.StringIO(), Tty()
        sys.argv = ["lattice-scan", "-q", "--cve", "CVE-2099-0001"]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cli.main()
        self.assertEqual(err.getvalue(), "")
        out, err = io.StringIO(), Tty()
        sys.argv = ["lattice-scan", "--again", "--cve", "CVE-2099-0001"]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cli.main()
        self.assertIn("asking Lattice", err.getvalue())    # a terminal shows it by default

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
        _, without, err = self.run_cli("project", str(root), "--format", "csv", "--cve", "CVE-2099-0001")
        self.assertEqual(with_p, without); self.assertEqual(err, "")

    def test_kind_names(self):
        self.assertEqual(manifests._kind("package-lock.json"), "JavaScript lockfile")
        self.assertEqual(manifests._kind("pom.xml"), "Java Maven file")


if __name__ == "__main__":
    unittest.main()
