"""The manual page and --help must say what the tool does. Standard library only."""
import re, subprocess, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from lattice_scan import __version__, cli, report  # noqa: E402

MAN = (ROOT / "man" / "lattice-scan.1").read_text().replace("\\-", "-").replace("\\fB", "").replace("\\fR", "").replace("\\fI", "")
README = (ROOT / "README.md").read_text()
SOURCE = (ROOT / "src" / "lattice_scan" / "cli.py").read_text()


class Manual(unittest.TestCase):
    def test_every_long_option_is_in_the_manual(self):
        opts = set(re.findall(r'"(--[a-z][a-z-]+)"', SOURCE)) - {"--version", "--help", "--qf"}
        self.assertEqual(sorted(o for o in opts if o not in MAN), [])

    def test_the_docs_name_only_options_the_parser_defines(self):
        """The reverse of the test above: a skill or README line that shows a lattice-scan command must not promise a flag it lacks (the skill once named --format for the host check)."""
        defined = set(re.findall(r'"(--[a-z][a-z-]+)"', SOURCE)) | {"--version", "--help"}
        defined |= {f"--{f}" for f in ("name", "position", "company", "email", "purpose")}     # get-key builds these in a loop
        defined |= {"--show-keys", "--marketplace"}                                             # gpg's and Claude Code's, shown beside our commands
        bad = []
        for name in ("README.md", "skills/lattice-scan/SKILL.md"):
            for n, line in enumerate((ROOT / name).read_text().splitlines(), 1):
                if "lattice-scan" not in line and ".pyz" not in line:
                    continue
                for opt in re.findall(r"(?<![\w-])(--[a-z][a-z-]+)", line):
                    if opt not in defined:
                        bad.append(f"{name}:{n} {opt}")
        self.assertEqual(bad, [])

    def test_every_subcommand_is_in_the_manual(self):
        for name in re.findall(r'sub\.add_parser\("([a-z]+)"', SOURCE):
            self.assertRegex(MAN, rf"\b{name}\b", name)

    def test_every_csv_column_and_verdict_is_in_the_manual(self):
        for c in report.CSV_COLUMNS:
            self.assertIn(c, MAN, c)
        for v in report.VERDICT_ORDER:
            self.assertIn(v, MAN, v)

    def test_every_environment_variable_is_in_the_manual(self):
        envs = set(re.findall(r'env\("([A-Z_]+)"', SOURCE))
        for e in envs:
            self.assertIn(f"LATTICE_SCAN_{e}", MAN, e)
        for e in ("LATTICE_API_KEY", "LATTICE_URL", "NO_COLOR"):
            self.assertIn(e, MAN, e)

    def test_every_manifest_file_kind_is_in_the_manual_and_the_readme(self):
        for name in ("requirements", "pyproject.toml", "package.json", "package-lock.json", "pom.xml", "build.gradle", "gradle.lockfile", "Cargo.toml", "Cargo.lock",
                     "CMakeLists.txt", "conanfile", "vcpkg.json", "Makefile", "Dockerfile", "compose"):
            self.assertIn(name, MAN, name)
            self.assertIn(name, README, name)

    def test_exit_statuses_are_documented(self):
        section = MAN.split("EXIT STATUS", 1)[1].split(".SH ENVIRONMENT", 1)[0]
        for code in ("0", "1", "2", "3"):
            self.assertIn(f".B {code}\n", section, code)

    def test_it_is_valid_roff_and_names_the_version_the_package_will_carry(self):
        self.assertTrue((ROOT / "man" / "lattice-scan.1").read_text().startswith(".\\\" SPDX-License-Identifier: Apache-2.0"))
        self.assertIn(f'"lattice-scan {__version__}"', (ROOT / "man" / "lattice-scan.1").read_text(), "bump the .TH line with the version")

    def test_no_published_text_claims_what_the_list_cannot_know_about_other_peoples_machines(self):
        """The recent list says what CISA lists and when its due date falls. It cannot know whether any machine is patched, so no text may say machines are 'still unfixed'."""
        out = subprocess.run([sys.executable, "-m", "lattice_scan", "recent", "--help"], capture_output=True, text=True, cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"}).stdout
        texts = {"manual": MAN, "README": README, "recent --help": out, "SKILL.md": (ROOT / "skills/lattice-scan/SKILL.md").read_text(),
                 **{p.name: p.read_text() for p in (ROOT / "release-notes").glob("*.md")}}
        for name, text in texts.items():
            self.assertNotRegex(" ".join(text.split()), r"(?i)many machines|still unfixed|still have unfixed", name)

    def test_the_changelog_has_a_section_for_this_version(self):
        text = (ROOT / "CHANGELOG.md").read_text()
        self.assertRegex(text, rf"(?m)^## {re.escape(__version__)} ")
        self.assertIn("man lattice-scan", text)

    def test_help_for_project_shows_examples_and_the_csv_columns(self):
        out = subprocess.run([sys.executable, "-m", "lattice_scan", "project", "--help"], capture_output=True, text=True, cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"}).stdout
        for needle in ("examples:", "--format csv", "csv columns", "exit status", "man lattice-scan"):
            self.assertIn(needle, out, needle)


if __name__ == "__main__":
    unittest.main()
