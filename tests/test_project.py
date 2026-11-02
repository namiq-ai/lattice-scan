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
        why, installed, vers, comparable, matches = self.hit("Example", "Examplelib", **{"examplelib": "2.14.0", "examplelib#2": "2.17.1"})
        self.assertEqual(sorted(vers), ["2.14.0", "2.17.1"])


class Report(unittest.TestCase):
    def result(self, **over):
        h = {"cve": "CVE-2099-7", "title": "=HYPERLINK(\"http://example.invalid\")", "why": "w", "listed": "2026-10-30", "due": "2026-11-20", "action": "+cmd|' /C calc'!A0",
             "versionCheck": {"verdict": "in-range", "why": "inside"}, "declared": [{"name": "a", "spec": "==1", "version": "1", "file": "-f.txt", "line": 3, "ecosystem": "pypi"}]}
        r = {"root": "/p/demo", "files": ["a"], "filesCut": False, "components": 1, "pinned": 1, "read": 1, "candidates": [h], "notListed": [], "unread": ["CVE-2099-8"], "stopped": ""}
        r.update(over)
        return [r]

    def test_spreadsheet_formulas_in_third_party_text_are_defused(self):
        import csv as _csv
        from lattice_scan import report
        rows = list(_csv.reader(report.to_csv(self.result(), "2026-11-02").splitlines()))
        row = dict(zip(rows[0], rows[1]))
        for col in ("title", "action", "file", "declared"):
            self.assertTrue(row[col].startswith("'"), col)
        self.assertEqual(row["version"], "1")                       # the clean copy for a parser

    def test_rows_are_ordered_in_range_first_and_not_read_last(self):
        from lattice_scan import report
        r = self.result()
        r[0]["candidates"].append({**r[0]["candidates"][0], "cve": "CVE-2099-6", "versionCheck": {"verdict": "outside-range", "why": "x"}})
        order = [f["verdict"] for f in report.findings(r)]
        self.assertEqual(order, ["in-range", "outside-range", "not-read"])

    def test_console_total_row_only_with_several_projects(self):
        from lattice_scan import report
        one = report.console(self.result(), "2026-11-02", "t", 100)
        two = report.console(self.result() + self.result(root="/p/other"), "2026-11-02", "t", 100)
        self.assertNotIn("Total", one); self.assertIn("Total", two)


class MoreEcosystems(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def comps(self):
        return {(c.name, c.ecosystem): c for c in manifests.read_project(self.root)[0]}

    def test_maven_pom_resolves_properties_and_leaves_unresolved_unpinned(self):
        write(self.root, "pom.xml", """<project xmlns="http://maven.apache.org/POM/4.0.0"><version>3.1.0</version>
          <properties><log.v>2.14.1</log.v></properties>
          <dependencies>
            <dependency><groupId>org.example.logging</groupId><artifactId>examplelog-core</artifactId><version>${log.v}</version></dependency>
            <dependency><groupId>org.example</groupId><artifactId>other</artifactId><version>${missing}</version></dependency>
            <dependency><groupId>org.example</groupId><artifactId>managed</artifactId></dependency>
          </dependencies></project>""")
        c = self.comps()
        self.assertEqual(c[("org.example.logging:examplelog-core", "maven")].version, "2.14.1")
        self.assertIsNone(c[("org.example:other", "maven")].version)
        self.assertIsNone(c[("org.example:managed", "maven")].version)

    def test_gradle_build_lockfile_and_catalog(self):
        write(self.root, "build.gradle", "dependencies {\n  implementation 'org.example:lib:1.2.3'\n  api(\"org.example:ranged:1.+\")\n  testImplementation 'org.example:noversion'\n}\n")
        write(self.root, "gradle.lockfile", "org.example:locked:4.5.6=compileClasspath,runtimeClasspath\nempty=\n")
        write(self.root, "gradle/libs.versions.toml", '[versions]\nv = "9.9.9"\n[libraries]\nviaref = { module = "org.example:viaref", version.ref = "v" }\n')
        c = self.comps()
        self.assertEqual(c[("org.example:lib", "maven")].version, "1.2.3")
        self.assertIsNone(c[("org.example:ranged", "maven")].version)
        self.assertEqual(c[("org.example:locked", "maven")].version, "4.5.6")
        self.assertEqual(c[("org.example:viaref", "maven")].version, "9.9.9")

    def test_cargo_toml_and_lock(self):
        write(self.root, "Cargo.toml", '[dependencies]\nexactcrate = "=1.4.2"\ncaret = "1.4.2"\nfull = { version = "0.9", features = ["x"] }\nlocal = { path = "../x" }\n'
              '[dev-dependencies]\ndevcrate = "2"\n')
        write(self.root, "Cargo.lock", '[[package]]\nname = "caret"\nversion = "1.4.9"\n\n[[package]]\nname = "openssl-sys"\nversion = "0.9.1"\n')
        c = self.comps()
        self.assertEqual(c[("exactcrate", "cargo")].version, "1.4.2")
        self.assertIsNone(c[("caret", "cargo")].version if ("caret", "cargo") in c and c[("caret", "cargo")].spec == "1.4.2" else None)
        self.assertNotIn(("local", "cargo"), c)
        self.assertEqual(c[("openssl-sys", "cargo")].version, "0.9.1")      # the lock says what is built

    def test_cmake_find_package_fetchcontent_cpm_and_pkgconfig(self):
        write(self.root, "CMakeLists.txt", "# find_package(Ignored 9.9)\nfind_package(OpenSSL 1.1.1 REQUIRED)\nfind_package(Exact 2.0 EXACT)\n"
              "FetchContent_Declare(\n  examplelib\n  GIT_REPOSITORY https://example.invalid/x.git\n  GIT_TAG v2.14.0\n)\n"
              "FetchContent_Declare(floaty GIT_REPOSITORY https://example.invalid/y.git GIT_TAG main)\n"
              "CPMAddPackage(NAME cpmlib VERSION 3.4.5 GITHUB_REPOSITORY example/cpmlib)\n"
              "pkg_check_modules(ZL REQUIRED zlib>=1.2.8)\n"
              "ExternalProject_Add(zdep URL https://example.invalid/zlib-1.2.11.tar.gz)\n")
        c = self.comps()
        self.assertEqual(c[("openssl", "cmake")].spec, ">=1.1.1"); self.assertIsNone(c[("openssl", "cmake")].version)   # a minimum, not a pin
        self.assertEqual(c[("exact", "cmake")].version, "2.0")
        self.assertEqual(c[("examplelib", "cmake")].version, "2.14.0")
        self.assertIsNone(c[("floaty", "cmake")].version)                                                              # a branch is not a version
        self.assertEqual(c[("cpmlib", "cmake")].version, "3.4.5")
        self.assertIsNone(c[("zl", "cmake")].version if ("zl", "cmake") in c else None)
        self.assertEqual(c[("zlib", "cmake")].version, "1.2.11")      # the name comes from the tarball, not from the target name zdep
        self.assertNotIn(("ignored", "cmake"), c)

    def test_makefile_versions_tarballs_pkgconfig_and_link_flags(self):
        write(self.root, "Makefile", "ZLIB_VERSION = 1.2.11  # pinned\nLDLIBS += -lssl -lcrypto -lm\nPKG := $(shell pkg-config --atleast-version=1.0 libfoo)\n"
              "fetch:\n\tcurl -O https://example.invalid/curl-7.88.1.tar.gz\nPYTHON_VERSION ?= 3.12.1\n")
        c = self.comps()
        self.assertEqual(c[("zlib", "make")].version, "1.2.11")
        self.assertEqual(c[("curl", "c")].version, "7.88.1")
        self.assertEqual(c[("python", "make")].version, "3.12.1")
        self.assertIn(("openssl", "make"), c); self.assertIsNone(c[("openssl", "make")].version)    # -lssl names a library, never a version
        self.assertNotIn(("m", "make"), c)

    def test_conan_and_vcpkg(self):
        write(self.root, "conanfile.txt", "[requires]\nzlib/1.2.13\nboost/[>=1.70]\nfmt/9.1.0@user/channel\n[generators]\nCMakeDeps\n")
        write(self.root, "conanfile.py", 'class P:\n    requires = "openssl/3.0.8"\n    def requirements(self):\n        self.requires("sqlite3/3.40.1")\n')
        write(self.root, "vcpkg.json", json.dumps({"dependencies": ["zlib", {"name": "curl", "version>=": "7.80"}], "overrides": [{"name": "zlib", "version": "1.2.13"}]}))
        c = self.comps()
        self.assertEqual(c[("zlib", "conan")].version, "1.2.13")
        self.assertIsNone(c[("boost", "conan")].version)
        self.assertEqual(c[("fmt", "conan")].version, "9.1.0")
        self.assertEqual(c[("openssl", "conan")].version, "3.0.8")
        self.assertEqual(c[("sqlite3", "conan")].version, "3.40.1")
        self.assertEqual(c[("zlib", "vcpkg")].version, "1.2.13")
        self.assertIsNone(c[("curl", "vcpkg")].version)

    def test_docker_tags(self):
        write(self.root, "docker-compose.yml", "services:\n  a:\n    image: exampledb:16\n  b:\n    image: exampledb:13.0.1-security-01\n  c:\n    image: tool:2.4-alpine\n  d:\n    image: ex:v1.4.1\n")
        v = {c.spec: c.version for c in manifests.read_project(self.root)[0]}
        self.assertIsNone(v["exampledb:16"])                # a major-only tag floats
        self.assertEqual(v["exampledb:13.0.1-security-01"], "13.0.1")
        self.assertEqual(v["tool:2.4-alpine"], "2.4")
        self.assertEqual(v["ex:v1.4.1"], "1.4.1")


class _NoTomllib:
    """Run a test class again as Python 3.9 / 3.10 see it: no tomllib. CI found the fallback could not read Cargo.toml or libs.versions.toml; a 3.12 developer machine never would."""
    def setUp(self):
        super().setUp()
        self._saved_toml = manifests.tomllib
        manifests.tomllib = None

    def tearDown(self):
        manifests.tomllib = self._saved_toml
        super().tearDown()


class ManifestsWithoutTomllib(_NoTomllib, Manifests):
    pass


class MoreEcosystemsWithoutTomllib(_NoTomllib, MoreEcosystems):
    pass


class MiniToml(unittest.TestCase):
    DOCS = [
        '[project]\nname = "x"\ndependencies = ["a==1", "b>=2,<3",\n  "c"]  # trailing\n[project.optional-dependencies]\ndev = ["d==4"]\n',
        '[package]\nname = "p"\n[dependencies]\nplain = "1.2.3"\nfull = { version = "0.9", features = ["x", "y"] }\nlocal = { path = "../x" }\n'
        '[target.\'cfg(unix)\'.dependencies]\nunixonly = "=2.0.0"\n[dev-dependencies]\ndevc = "2"\n',
        '[versions]\nv = "9.9.9"\nstrict = { strictly = "1.0" }\n[libraries]\na = { module = "g:a", version.ref = "v" }\nb = "g:b:1.2"\n'
        'c = { group = "g", name = "c", version = "3" }\n',
        '[tool.poetry.dependencies]\npython = "^3.9"\nrequests = { version = "^2.0", extras = ["socks"] }\nflat = "1.4.2"\n[build-system]\nrequires = ["setuptools>=77", "wheel"]\n',
        '[[package]]\nname = "skipme"\nversion = "1"\n[workspace.dependencies]\nw = "3"\nn = 5\nflag = true\n',
    ]

    def test_it_reads_what_tomllib_reads_for_the_tables_that_matter(self):
        try:
            import tomllib
        except ImportError:
            self.skipTest("no tomllib to compare with")
        for doc in self.DOCS:
            expected = tomllib.loads(doc)
            got = manifests._mini_toml(doc)
            for key in ("project", "dependencies", "dev-dependencies", "versions", "libraries", "tool", "build-system", "workspace", "target"):
                self.assertEqual(got.get(key), expected.get(key), f"{key} in {doc[:40]!r}")

    def test_a_line_it_does_not_understand_is_skipped_not_fatal(self):
        self.assertEqual(manifests._mini_toml("not toml at all\n[a]\nk = \"v\"\n"), {"a": {"k": "v"}})


class FamilyAndRanges(unittest.TestCase):
    def inv(self, eco, **pk):
        return {"packages": dict(pk), "ecosystems": {k: eco for k in pk}, "snaps": {}, "images": [], "kernel": "", "node": ""}

    def hit(self, vendor, product, eco, **pk):
        return cli.project_candidate({"cve": "CVE-2099-1", "vendor": vendor, "product": product, "title": ""}, self.inv(eco, **pk))

    def test_a_maven_coordinate_carries_the_product_as_a_token(self):
        m = self.hit("Apache", "Log4j2", "maven", **{"org.apache.logging.log4j:log4j-core": "2.14.1"})
        self.assertTrue(m and m[3])                                    # same family: its version is comparable
        self.assertTrue(self.hit("VMware", "Spring Framework", "maven", **{"org.springframework:spring-core": "5.3.0"}))
        self.assertIsNone(self.hit("Apache", "Log4j2", "pypi", **{"log4j-core": "2.14.1"}))     # the family rule is not for pypi/npm
        self.assertTrue(self.hit("OpenSSL", "OpenSSL", "cargo", **{"openssl-sys": "0.9.1"}))
        self.assertIsNone(self.hit("Example", "Core", "maven", **{"org.example:core-utils": "1"}))   # a generic product never matches by token

    def test_a_scope_only_match_is_a_lead_and_its_version_is_not_compared(self):
        m = self.hit("Vite", "Vitejs", "npm", **{"@vitejs/plugin-react": "6.0.3"})
        self.assertTrue(m)
        self.assertFalse(m[3])
        self.assertTrue(self.hit("Vite", "Vitejs", "npm", vite="5.4.0")[3])           # the product's own package is compared (js suffix dropped)

    def test_vendor_difference_does_not_hide_the_same_product_name(self):
        R = [{"product": "encode/starlette", "end_excluding": "1.0.1", "start_including": "0.8.3"}]
        self.assertEqual(cli.version_check({"vendor": "Kludex", "product": "Starlette", "ranges": R}, ["0.9.0"])["verdict"], "in-range")
        self.assertEqual(cli.version_check({"vendor": "Sudo", "product": "Sudo", "ranges": [{"product": "sudo_project/sudo", "end_excluding": "1.9.5"}]}, ["1.8.0"])["verdict"], "in-range")
        self.assertEqual(cli.version_check({"vendor": "Microsoft", "product": "Kernel", "ranges": [{"product": "linux/linux_kernel", "end_excluding": "9"}]}, ["1"])["verdict"], "undetermined")
        self.assertEqual(cli.version_check({"vendor": "Vite", "product": "Vitejs", "ranges": [{"product": "vitejs/vite", "end_excluding": "5.4.16"}]}, ["5.4.0"])["verdict"], "in-range")


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
        Stub.mode, Stub.seen, Stub.tier = "json", [], "keyless"
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
        self.assertIn("[IN RANGE]", out)
        self.assertIn("requirements.txt:2", out)
        self.assertIn("what is deployed may differ", " ".join(out.split()))

    def test_pinned_version_above_the_range_is_outside(self):
        write(self.root, "requirements.txt", "examplelib==2.17.1\n")
        _, out, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001")
        self.assertIn("[OUTSIDE RANGE]", out)

    def test_a_declared_range_is_undetermined_never_outside(self):
        write(self.root, "requirements.txt", "examplelib>=2.0\n")
        _, out, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001")
        self.assertIn("[UNDETERMINED]", out)
        self.assertNotIn("[OUTSIDE RANGE]", out)

    def test_unpinned_image_is_undetermined_too(self):
        write(self.root, "docker-compose.yml", "services:\n  a:\n    image: examplelib:latest\n")
        _, out, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001")
        self.assertIn("[UNDETERMINED]", out)

    def test_nothing_declared_means_no_candidate_and_no_host_records(self):
        write(self.root, "requirements.txt", "unrelated==1.0\n")
        rc, out, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001")
        self.assertEqual(rc, 0)
        self.assertIn("No dependency declared here matches", " ".join(out.split()))
        self.assertFalse((cli.OUT).exists(), "a project scan must not write host records")

    def test_catalogue_chooses_ids_and_only_matches_are_sent(self):
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        cat = write(Path(self.tmp.name), "kev.json", json.dumps({"vulnerabilities": [
            {"cveID": "CVE-2099-0001", "vendorProject": "Exampleco", "product": "Examplelib", "vulnerabilityName": "x"},
            {"cveID": "CVE-2099-0002", "vendorProject": "Other", "product": "Nothingdeclared", "vulnerabilityName": "y"}]}))
        cli.KEY, Stub.tier = "k", "trial_accepted"
        rc, out, _ = self.run_cli("project", str(self.root), "--kev-catalogue", str(cat))
        reads = [m for m, _, _ in Stub.seen if m == "tools/call"]
        self.assertEqual(len(reads), 2)                                    # one graph_meta (the tier check) and ONE id: CVE-2099-0002's product is not declared here
        self.assertIn("CVE-2099-0001", out)

    def _catalogue(self):
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        return write(Path(self.tmp.name), "kev.json", json.dumps({"vulnerabilities": [
            {"cveID": "CVE-2099-0001", "vendorProject": "Exampleco", "product": "Examplelib", "vulnerabilityName": "x"}]}))

    def test_the_catalogue_needs_a_key_and_asks_nothing_without_one(self):
        cat = self._catalogue()
        rc, out, err = self.run_cli("project", str(self.root), "--kev-catalogue", str(cat))
        self.assertEqual(rc, 2)
        self.assertIn("needs a Lattice key", err)
        self.assertIn("--cve CVE-2026-46300,CVE-2021-44228", err)          # and says what to do instead
        self.assertEqual(Stub.seen, [])                                    # not one request was made

    def test_a_key_whose_email_is_not_confirmed_cannot_use_the_catalogue(self):
        cat = self._catalogue()
        cli.KEY, Stub.tier = "k", "trial"
        rc, out, err = self.run_cli("project", str(self.root), "--kev-catalogue", str(cat))
        self.assertEqual(rc, 2)
        self.assertIn("not confirmed", err); self.assertIn("'trial'", err)
        self.assertEqual(len([m for m, _, _ in Stub.seen if m == "tools/call"]), 1)      # only the tier check: no id was read
        self.assertNotIn("CVE-2099-0001", out)

    def test_a_confirmed_key_can_use_the_catalogue(self):
        cat = self._catalogue()
        for tier in ("trial_accepted", "commercial"):
            cli.KEY, Stub.tier, Stub.seen = "k", tier, []
            rc, out, err = self.run_cli("project", str(self.root), "--kev-catalogue", str(cat))
            self.assertEqual((rc, err), (0, ""), tier)
            self.assertIn("CVE-2099-0001", out)

    def test_without_a_key_named_ids_work_and_may_be_comma_separated(self):
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        Stub.answers["CVE-2099-0002"] = lookup("CVE-2099-0002", product="Other", vendor="Otherco")
        cli.Lattice.last_gap = 0.0
        orig = cli.time.sleep
        cli.time.sleep = lambda s: None            # the keyless pacing is not what is tested here
        try:
            rc, out, err = self.run_cli("project", str(self.root), "--cve", "cve-2099-0001, CVE-2099-0002", "--format", "csv")
        finally:
            cli.time.sleep = orig
        self.assertEqual(rc, 0, err)
        self.assertEqual(len([m for m, _, _ in Stub.seen if m == "tools/call"]), 2)
        self.assertIn("CVE-2099-0001", out)

    def test_a_malformed_id_is_refused_before_anything_is_asked(self):
        rc, _, err = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001,not-an-id")
        self.assertEqual(rc, 2)
        self.assertIn("not a CVE id: NOT-AN-ID", err)
        self.assertEqual(Stub.seen, [])

    def test_nothing_named_and_no_catalogue_is_refused(self):
        rc, _, err = self.run_cli("project", str(self.root))
        self.assertEqual(rc, 2); self.assertIn("name CVEs with --cve CVE-A,CVE-B", err)

    def test_max_read_says_what_was_not_read(self):
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        cve = Path(self.tmp.name) / "ids.txt"
        cve.write_text("CVE-2099-0001, CVE-2099-0005  # two on one line\nCVE-2099-0006\n")
        rc, out, _ = self.run_cli("project", str(self.root), "--cve-file", str(cve), "--max-read", "1")
        self.assertIn("NOT READ (2)", out)

    def test_one_read_per_id_across_folders(self):
        other = self.root.parent / "proj2"
        other.mkdir()
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        write(other, "requirements.txt", "examplelib==2.16.0\n")
        rc, out, _ = self.run_cli("project", str(self.root), str(other), "--cve", "CVE-2099-0001")
        self.assertEqual(len([m for m, _, _ in Stub.seen if m == "tools/call"]), 1)
        self.assertIn("[IN RANGE]", out)         # the first folder
        self.assertIn("[OUTSIDE RANGE]", out)    # the second, from the same single read

    def test_json_and_fail_on(self):
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        j = Path(self.tmp.name) / "r.json"
        rc, _, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001", "--json", str(j), "--fail-on", "in-range")
        self.assertEqual(rc, 1)
        d = json.loads(j.read_text())["projects"][0]
        self.assertEqual(d["candidates"][0]["versionCheck"]["verdict"], "in-range")
        self.assertEqual(d["candidates"][0]["declared"][0]["file"], "requirements.txt")
        self.assertEqual(self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001")[0], 0)   # default: report only

    def test_a_lead_never_changes_the_verdict_of_the_products_own_package(self):
        """The dogfood run showed it: @vitejs/plugin-react in the same project made vite's own pinned version 'undetermined' instead of 'outside-range'."""
        write(self.root, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"node_modules/vite": {"version": "5.4.21"}, "node_modules/@vitejs/plugin-react": {"version": "4.7.0"}}}))
        Stub.answers = {"CVE-2099-0007": lookup("CVE-2099-0007", product="Vitejs", vendor="Vite", ranges=[{"product": "vitejs/vite", "end_excluding": "5.4.16"}])}
        rc, out_text, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0007", "--format", "csv")
        import csv as _csv
        rows = {r["component"].lstrip("'"): r for r in _csv.DictReader(out_text.splitlines())}
        self.assertEqual(rows["vite"]["verdict"], "outside-range")                  # its own version, judged on its own
        self.assertEqual(rows["@vitejs/plugin-react"]["verdict"], "lead")    # the lead stays a lead, ranked below every real comparison

    def test_a_client_library_with_the_servers_name_is_a_lead(self):
        """OCO-5828: the PyPI minio is the Python SDK, not the MinIO server; its 7.2.7 must not be compared with the server's ranges."""
        write(self.root, "requirements.txt", "minio==7.2.7\n")
        Stub.answers = {"CVE-2099-0008": lookup("CVE-2099-0008", product="MinIO", vendor="MinIO", ranges=[{"product": "minio/minio", "end_excluding": "9.0.0"}])}
        rc, out_text, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0008", "--format", "csv")
        import csv as _csv
        rows = list(_csv.DictReader(out_text.splitlines()))
        self.assertEqual([r["verdict"] for r in rows], ["lead"])
        self.assertIn("client library", rows[0]["why"])
        rc, text, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0008")
        self.assertIn("[LEAD]", text)
        self.assertIn("Leads", text)                  # its own column in the summary, not counted as undetermined

    def test_csv_to_stdout_has_a_fixed_header_and_one_row_per_finding(self):
        import csv as _csv
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        rc, out, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001", "--format", "csv", "--name", "DEMO")
        self.assertEqual(rc, 0)
        rows = list(_csv.reader(out.splitlines()))
        self.assertEqual(rows[0], ["project", "cve", "title", "verdict", "component", "ecosystem", "declared", "version", "file", "line", "listed", "due", "due_status", "action", "why"])
        self.assertEqual(len(rows), 2)
        r = dict(zip(rows[0], rows[1]))
        self.assertEqual((r["project"], r["cve"], r["verdict"], r["component"], r["version"], r["file"], r["line"]), ("DEMO", "CVE-2099-0001", "in-range", "examplelib", "2.14.0", "requirements.txt", "1"))
        self.assertEqual(r["due"], "2026-11-20"); self.assertIn("due in", r["due_status"])

    def test_csv_with_nothing_found_is_just_the_header(self):
        write(self.root, "requirements.txt", "unrelated==1.0\n")
        _, out, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001", "--format", "csv")
        self.assertEqual(len(out.splitlines()), 1)

    def test_csv_file_and_json_file_alongside_the_console_report(self):
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        c, j = Path(self.tmp.name) / "f.csv", Path(self.tmp.name) / "f.json"
        _, out, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001", "--csv", str(c), "--json", str(j))
        self.assertIn("SUMMARY", out); self.assertIn("HOW TO READ THIS", out)
        self.assertEqual(c.read_text().splitlines()[0].split(",")[0], "project")
        self.assertEqual(json.loads(j.read_text())["projects"][0]["candidates"][0]["cve"], "CVE-2099-0001")

    def test_json_format_is_valid_json_on_stdout(self):
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        _, out, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001", "--format", "json")
        self.assertEqual(json.loads(out)["projects"][0]["pinned"], 1)

    def test_colour_only_when_asked_and_width_is_respected(self):
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        _, plain, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001", "--color", "never", "--width", "80")
        self.assertNotIn("\033[", plain)
        self.assertLessEqual(max(len(l) for l in plain.splitlines()), 80)
        Stub.seen = []; cli.Lattice.last_gap = 0.0
        _, coloured, _ = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001", "--color", "always")
        self.assertIn("\033[", coloured)

    def test_quota_stop_is_reported_and_exit_3(self):
        write(self.root, "requirements.txt", "examplelib==2.14.0\n")
        Stub.mode = "quota"
        rc, out, err = self.run_cli("project", str(self.root), "--cve", "CVE-2099-0001")
        self.assertEqual(rc, 3)
        self.assertIn("NOT READ (1)", out)
        self.assertIn("INCOMPLETE", out)
        self.assertEqual(out.count("daily limit reached"), 1)      # the stop is said once, not under every project
        self.assertIn("stopped", err)


if __name__ == "__main__":
    unittest.main()
