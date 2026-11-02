"""Tests for `lattice-scan project` and the manifest readers. Standard library only. Invented products and reserved ids (CVE-2099-*, examplelib), no real project."""
import contextlib, io, json, sys, tempfile, threading, unittest
from http.server import HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli, manifests  # noqa: E402
from test_lattice_scan import Stub, lookup  # noqa: E402


def write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


class Manifests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def by(self, comps):
        return {(c.name, c.ecosystem): c for c in comps}

    def test_requirements_pins_ranges_markers_hashes_and_includes(self):
        write(self.root, "requirements.txt", "# comment\nExampleLib==2.14.0 ; python_version>='3.9'\nother_lib>=1.0,<2  # why\n"
              "hashed==1.2.3 \\\n    --hash=sha256:aaaa\n-r base.txt\n-e .\ngit+https://example.invalid/x.git\nstar==1.*\n")
        write(self.root, "base.txt", "basedep==9.9\n")   # not a requirements*.txt name: reached only through -r
        comps, files, cut = manifests.read_project(self.root)
        c = self.by(comps)
        self.assertEqual(c[("examplelib", "pypi")].version, "2.14.0")
        self.assertIsNone(c[("other-lib", "pypi")].version)          # a range is not a version
        self.assertEqual(c[("other-lib", "pypi")].spec, ">=1.0,<2")
        self.assertEqual(c[("hashed", "pypi")].version, "1.2.3")
        self.assertIsNone(c[("star", "pypi")].version)               # ==1.* is a pattern
        self.assertEqual(c[("basedep", "pypi")].version, "9.9")
        self.assertEqual(c[("examplelib", "pypi")].line, 2)
        self.assertFalse(cut)

    def test_pyproject_project_optional_and_poetry(self):
        write(self.root, "pyproject.toml", '[project]\nname = "x"\ndependencies = ["examplelib==2.14.0", "loose>=1"]\n'
              '[project.optional-dependencies]\ndev = ["devtool==3.0"]\n[tool.poetry.dependencies]\npython = "^3.9"\npoetrydep = "1.4.2"\nranged = "^2.0"\n')
        c = self.by(manifests.read_project(self.root)[0])
        self.assertEqual(c[("examplelib", "pypi")].version, "2.14.0")
        self.assertEqual(c[("devtool", "pypi")].version, "3.0")
        self.assertIsNone(c[("loose", "pypi")].version)
        self.assertEqual(c[("poetrydep", "pypi")].version, "1.4.2")
        self.assertIsNone(c[("ranged", "pypi")].version)
        self.assertNotIn(("python", "pypi"), c)

    def test_package_json_and_lock(self):
        write(self.root, "package.json", json.dumps({"dependencies": {"examplejs": "^4.2.0", "exact": "1.0.0"}, "devDependencies": {"t": "~1"}}))
        write(self.root, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "x"}, "node_modules/examplejs": {"version": "4.2.7"}, "node_modules/a/node_modules/nested": {"version": "0.1.0"}}}))
        comps = manifests.read_project(self.root)[0]
        c = {(x.name, x.spec): x for x in comps}
        self.assertIsNone(c[("examplejs", "^4.2.0")].version)
        self.assertEqual(c[("examplejs", "==4.2.7")].version, "4.2.7")     # the lock says what is installed
        self.assertEqual(c[("exact", "1.0.0")].version, "1.0.0")
        self.assertEqual(c[("nested", "==0.1.0")].version, "0.1.0")

    def test_dockerfile_and_compose(self):
        write(self.root, "Dockerfile", "ARG V=16.2\nFROM exampledb:${V} AS build\nFROM build AS final\nFROM scratch\nFROM registry.example.invalid/team/svc:latest\n"
              "RUN pip install --no-cache-dir examplelib==2.14.0 loose && apt-get install -y curl=7.1.0 vim\n")
        write(self.root, "docker-compose.yml", "services:\n  db:\n    image: \"exampledb:15.1\"   # pinned\n  app:\n    image: ${APP_IMAGE:-appimg:3.2}\n  x:\n    build: .\n")
        c = manifests.read_project(self.root)[0]
        d = {(x.name, x.ecosystem, x.file): x for x in c}
        self.assertEqual(d[("exampledb", "image", "Dockerfile")].version, "16.2")      # ARG default substituted
        self.assertIsNone(d[("svc", "image", "Dockerfile")].version)                    # latest is not a version
        self.assertNotIn(("build", "image", "Dockerfile"), d)                           # a stage name is not an image
        self.assertNotIn(("scratch", "image", "Dockerfile"), d)
        self.assertEqual(d[("examplelib", "pypi", "Dockerfile")].version, "2.14.0")
        self.assertEqual(d[("curl", "apt", "Dockerfile")].version, "7.1.0")
        self.assertIsNone(d[("vim", "apt", "Dockerfile")].version)
        self.assertEqual(d[("exampledb", "image", "docker-compose.yml")].version, "15.1")
        self.assertEqual(d[("appimg", "image", "docker-compose.yml")].version, "3.2")

    def test_vendored_and_agent_trees_are_skipped_and_a_cut_is_reported(self):
        write(self.root, "node_modules/x/package.json", json.dumps({"dependencies": {"nope": "1.0.0"}}))
        write(self.root, ".claude/worktrees/w/requirements.txt", "nope==1\n")
        write(self.root, "requirements.txt", "yes==1\n")
        comps, files, cut = manifests.read_project(self.root)
        self.assertEqual([c.name for c in comps], ["yes"])
        old = manifests.MAX_FILES
        manifests.MAX_FILES = 1
        try:
            write(self.root, "sub/requirements.txt", "also==2\n")
            self.assertTrue(manifests.read_project(self.root)[2])
        finally:
            manifests.MAX_FILES = old


class ProjectMatching(unittest.TestCase):
    def inv(self, **pk):
        return {"packages": dict(pk), "snaps": {}, "images": [], "kernel": "", "node": ""}

    def hit(self, vendor, product, **pk):
        return cli.project_candidate({"cve": "CVE-2099-1", "vendor": vendor, "product": product, "title": ""}, self.inv(**pk))

    def test_the_product_must_be_the_package_not_share_a_word_with_it(self):
        self.assertIsNone(self.hit("WordPress", "Core", **{"@babel/core": "7.0.0"}))
        self.assertIsNone(self.hit("Google", "Chromium", **{"electron-to-chromium": "1.0.0"}))
        self.assertIsNone(self.hit("ISC", "BIND", **{"call-bind": "1.0.0"}))

    def test_exact_scope_and_prefix_matches(self):
        self.assertIsNotNone(self.hit("Kludex", "Starlette", starlette="0.30.0"))
        self.assertIsNotNone(self.hit("TanStack", "TanStack", **{"@tanstack/query-core": "5.0.0"}))
        self.assertIsNotNone(self.hit("PostgreSQL", "PostgreSQL", postgres="16.2"))
        self.assertIsNotNone(self.hit("Pallets", "Flask", **{"flask": "3.0.0", "flask#2": "2.0.0"}))

    def test_short_names_never_prefix_match(self):
        self.assertIsNone(self.hit("Example", "Corefoo", core="1.0"))
        self.assertIsNone(self.hit("Example", "Go", go="1.0"))      # under 4 characters: no match at all
        self.assertIsNone(self.hit("Example", "Core", core="1.0"))  # a generic one-word product needs its vendor in the name
        self.assertIsNotNone(self.hit("Example", "Core", **{"example-core": "1.0"}))
        self.assertIsNotNone(self.hit("Google", "Angular", **{"@angular/core": "17.0.0"}))   # the scope is the product

    def test_every_declared_version_of_the_name_is_returned(self):
        why, installed, vers = self.hit("Example", "Examplelib", **{"examplelib": "2.14.0", "examplelib#2": "2.17.1"})
        self.assertEqual(sorted(vers), ["2.14.0", "2.17.1"])


class ProjectCommand(unittest.TestCase):
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
        self.root = Path(self.tmp.name) / "proj"
        self.root.mkdir()
        self.saved = (cli.URL, cli.KEY, cli.OUT, cli.TODAY)
        cli.URL, cli.KEY, cli.OUT, cli.TODAY = self.url, "", Path(self.tmp.name) / "records", "2026-11-01"
        Stub.mode, Stub.seen = "json", []
        Stub.answers = {"CVE-2099-0001": lookup("CVE-2099-0001")}   # examplelib, affected 2.0.1 up to (not including) 2.15.0
        cli.Lattice.last_gap = 0.0

    def tearDown(self):
        cli.URL, cli.KEY, cli.OUT, cli.TODAY = self.saved
        self.tmp.cleanup()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        sys.argv = ["lattice-scan", *argv]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main()
        return rc, out.getvalue(), err.getvalue()

    def test_pinned_version_inside_the_range_is_in_range_with_file_and_line(self):
        write(self.root, "requirements.txt", "# c\nexamplelib==2.14.0\n")
        rc, out, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001")
        self.assertEqual(rc, 0)
        self.assertIn("version check: in-range", out)
        self.assertIn("[requirements.txt:2]", out)
        self.assertIn("what is deployed may differ", out)

    def test_pinned_version_above_the_range_is_outside(self):
        write(self.root, "requirements.txt", "examplelib==2.17.1\n")
        _, out, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001")
        self.assertIn("version check: outside-range", out)

    def test_a_declared_range_is_undetermined_never_outside(self):
        write(self.root, "requirements.txt", "examplelib>=2.0\n")
        _, out, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001")
        self.assertIn("version check: undetermined", out)
        self.assertNotIn("outside-range", out)

    def test_unpinned_image_is_undetermined_too(self):
        write(self.root, "docker-compose.yml", "services:\n  a:\n    image: examplelib:latest\n")
        _, out, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001")
        self.assertIn("version check: undetermined", out)

    def test_nothing_declared_means_no_candidate_and_no_host_records(self):
        write(self.root, "requirements.txt", "unrelated==1.0\n")
        rc, out, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001")
        self.assertEqual(rc, 0)
        self.assertIn("0 candidate(s)", out)
        self.assertFalse((cli.OUT).exists(), "a project scan must not write host records")

    def test_catalogue_chooses_ids_and_only_matches_are_sent(self):
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        cat = write(Path(self.tmp.name), "kev.json", json.dumps({"vulnerabilities": [
            {"cveID": "CVE-2099-0001", "vendorProject": "Exampleco", "product": "Examplelib", "vulnerabilityName": "x"},
            {"cveID": "CVE-2099-0002", "vendorProject": "Other", "product": "Nothingdeclared", "vulnerabilityName": "y"}]}))
        rc, out, _ = self.run_cli("project", str(self.root), "--kev-catalogue", str(cat))
        calls = [m for m, _, _ in Stub.seen if m == "tools/call"]
        self.assertEqual(len(calls), 1)                                    # CVE-2099-0002 was never read: its product is not declared here
        self.assertIn("CVE-2099-0001", out)

    def test_max_read_says_what_was_not_read(self):
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        cve = Path(self.tmp.name) / "ids.txt"
        cve.write_text("CVE-2099-0001\nCVE-2099-0005\nCVE-2099-0006\n")
        rc, out, _ = self.run_cli("project", str(self.root), "--cve-file", str(cve), "--max-read", "1")
        self.assertIn("NOT READ (2)", out)

    def test_one_read_per_id_across_folders(self):
        other = self.root.parent / "proj2"
        other.mkdir()
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        write(other, "requirements.txt", "examplelib==2.16.0\n")
        rc, out, _ = self.run_cli("project", str(self.root), str(other), "--cve", "CVE-2099-0001")
        self.assertEqual(len([m for m, _, _ in Stub.seen if m == "tools/call"]), 1)
        self.assertIn("version check: in-range", out)         # the first folder
        self.assertIn("version check: outside-range", out)    # the second, from the same single read

    def test_json_and_fail_on(self):
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        j = Path(self.tmp.name) / "r.json"
        rc, _, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001", "--json", str(j), "--fail-on", "in-range")
        self.assertEqual(rc, 1)
        d = json.loads(j.read_text())["projects"][0]
        self.assertEqual(d["candidates"][0]["versionCheck"]["verdict"], "in-range")
        self.assertEqual(d["candidates"][0]["declared"][0]["file"], "requirements.txt")
        self.assertEqual(self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001")[0], 0)   # default: report only

    def test_quota_stop_is_reported_and_exit_3(self):
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        Stub.mode = "quota"
        rc, out, err = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001")
        self.assertEqual(rc, 3)
        self.assertIn("NOT READ (1)", out)
        self.assertIn("stopped", err)


if __name__ == "__main__":
    unittest.main()
