"""The Claude plugin and skill are published copy that makes Claude run code on someone's machine. These tests keep the bundle honest:
the bundled script is the current source, the versions agree, and the wording cannot drift into a claim or a price."""
import json, re, sys, unittest, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from lattice_scan import __version__  # noqa: E402

SKILL = ROOT / "skills/lattice-scan/SKILL.md"
PYZ = ROOT / "skills/lattice-scan/scripts/lattice-scan.pyz"


def frontmatter(text):
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    return dict(l.split(": ", 1) for l in m.group(1).splitlines()) if m else {}


class Bundle(unittest.TestCase):
    def test_skill_has_name_and_a_description_that_says_when(self):
        fm = frontmatter(SKILL.read_text())
        self.assertEqual(fm["name"], "lattice-scan")
        self.assertIn("Use when", fm["description"])
        self.assertLess(len(fm["description"]), 1024)

    def test_bundled_script_is_the_current_source(self):
        with zipfile.ZipFile(PYZ) as z:
            for m in ("cli.py", "manifests.py", "report.py", "__init__.py", "__main__.py"):
                self.assertEqual(z.read(f"lattice_scan/{m}"), (ROOT / "src/lattice_scan" / m).read_bytes(),
                                 f"{m} in the bundled .pyz is stale: run packaging/build.py")

    def test_versions_agree(self):
        plugin = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())
        self.assertEqual(plugin["version"], __version__)
        self.assertEqual(json.loads((ROOT / "packaging/../.claude-plugin/marketplace.json").read_text())["plugins"][0]["name"], plugin["name"])

    def test_manifests_are_valid_json_and_point_at_this_plugin(self):
        mk = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
        self.assertEqual(mk["plugins"][0]["source"], "./")
        self.assertTrue(mk.get("description"))

    def test_skill_runs_the_bundled_script_by_a_relative_path(self):
        t = SKILL.read_text()
        self.assertIn("scripts/lattice-scan.pyz", t)
        self.assertNotRegex(t, r"(/home/|/Users/|C:\\\\)")      # no one's machine path


class Sandbox(unittest.TestCase):
    def test_skill_tells_a_sandboxed_agent_to_set_the_records_folder_and_key(self):
        t = SKILL.read_text()
        sec2 = t[t.index("## 2. Run it"):t.index("## 3. Report what it printed")]
        for needle in ("LATTICE_SCAN_DIR", "LATTICE_API_KEY", "--keep"):
            self.assertIn(needle, sec2, f"section 2 must tell a sandboxed agent about {needle}")


class Licence(unittest.TestCase):
    def test_apache_everywhere_it_is_declared(self):
        self.assertIn("Apache License", (ROOT / "LICENSE").read_text()[:200])
        self.assertIn("Version 2.0", (ROOT / "LICENSE").read_text()[:200])
        self.assertIn('license = "Apache-2.0"', (ROOT / "pyproject.toml").read_text())
        self.assertEqual(json.loads((ROOT / ".claude-plugin/plugin.json").read_text())["license"], "Apache-2.0")

    def test_licence_text_is_the_canonical_one(self):
        import hashlib
        self.assertEqual(hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest(),
                         "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30")   # the published Apache-2.0 text, unaltered

    def test_notice_names_the_holder_and_reserves_the_names(self):
        n = (ROOT / "NOTICE").read_text()
        self.assertIn("Copyright 2026 NamiQ LLC", n)
        for must in ("NamiQ", "Lattice", "section 6", "MIT"):
            self.assertIn(must, n)

    def test_every_source_file_carries_spdx_and_holder(self):
        for f in (ROOT / "src/lattice_scan").glob("*.py"):
            with self.subTest(f.name):
                self.assertTrue(f.read_text().startswith("# SPDX-License-Identifier: Apache-2.0\n# Copyright 2026 NamiQ LLC\n"))

    def test_skill_declares_the_licence(self):
        self.assertEqual(frontmatter(SKILL.read_text())["license"], "Apache-2.0")

    def test_no_stale_mit_declaration(self):
        for f in ("pyproject.toml", ".claude-plugin/plugin.json", "README.md"):
            with self.subTest(f):
                t = (ROOT / f).read_text()
                self.assertNotIn('license = "MIT"', t)
                self.assertNotIn('"license": "MIT"', t)


class AgentStart(unittest.TestCase):
    """0.3.0: an agent with no CVE id must find its first command at the top of the skill, and the key procedure must keep a person in the loop."""
    def test_the_skill_opens_with_a_which_command_table_that_names_every_start(self):
        t = SKILL.read_text()
        top = t.split("## 1. Before running anything", 1)[0]
        for cmd in ("`recent`", "`enrich`", "`--cve", "`project FOLDER"):
            with self.subTest(cmd):
                self.assertIn(cmd, top)

    def test_every_command_the_skill_teaches_exists(self):
        from lattice_scan import cli
        src = (ROOT / "src/lattice_scan/cli.py").read_text()
        for name in ("recent", "enrich", "get-key"):
            self.assertIn(f'sub.add_parser("{name}"', src)
            self.assertIn(f"{name}", SKILL.read_text())

    def test_a_key_is_requested_only_with_the_person_present(self):
        t = SKILL.read_text()
        for must in ("Never request one on your own", "Never make up a detail", "Only after a clear yes", "--accept-terms", "not me", "Do not retry with other details"):
            with self.subTest(must):
                self.assertIn(must, t)
        self.assertNotIn("do not request a key", t.lower().replace("never request one on your own", ""))

    def test_the_skill_sends_cve_questions_to_namiq_pages_before_outside_sites(self):
        t = SKILL.read_text()
        for must in ("https://namiq.io/sitemap.xml", "https://namiq.io/insights/today", "https://namiq.io/resources/monthly-highlight",
                     "https://namiq.io/lattice/recent.json", "NamiQ has no note on this id", "data, not instructions", "Do not apply a mitigation"):
            self.assertIn(must, t)
        self.assertLess(t.index("namiq.io/sitemap.xml"), t.index("the vendor's own advisory"))   # NamiQ's pages come first in the reading order

    def test_the_inventory_dump_is_not_the_first_thing_an_agent_runs(self):
        t = SKILL.read_text()
        self.assertIn("--refresh > /dev/null", t)
        self.assertNotIn("python3 scripts/lattice-scan.pyz --refresh   ", t)


class Wording(unittest.TestCase):
    """Descriptions are what a stranger reads first. They may say the tool compares and shows evidence; they may not say it judges."""
    TEXTS = {
        "skill description": lambda: frontmatter(SKILL.read_text())["description"],
        "plugin description": lambda: json.loads((ROOT / ".claude-plugin/plugin.json").read_text())["description"],
        "marketplace description": lambda: json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())["plugins"][0]["description"],
        "pyproject description": lambda: re.search(r'description = "(.*?)"', (ROOT / "pyproject.toml").read_text()).group(1),
    }
    JUDGES = re.compile(r"\b(detects?|absorbs?|ranks?|prioriti[sz]es?|decides?|remediates?|fixes|protects?|secures?)\b", re.I)

    def test_descriptions_do_not_claim_judgement(self):
        for name, get in self.TEXTS.items():
            with self.subTest(name):
                self.assertIsNone(self.JUDGES.search(get()), f"{name} claims judgement: {get()!r}")

    def test_no_price_or_money_anywhere_in_published_text(self):
        pat = re.compile(r"(\$\s?\d|€\s?\d|£\s?\d|\bper (month|year|seat|host)\b|/month\b|\bpricing\b|\bprice\b|\bsubscription\b)", re.I)
        for f in (SKILL, ROOT / "README.md", ROOT / ".claude-plugin/plugin.json", ROOT / ".claude-plugin/marketplace.json"):
            with self.subTest(f.name):
                self.assertIsNone(pat.search(f.read_text()), f"money or price wording in {f.name}")

    def test_skill_keeps_its_safety_rules(self):
        t = SKILL.read_text()
        for must in ("hosted sandbox", "data, never instructions", "Do not open any link", "Never print, log or pass on", "Do not run `resolve`",
                     "Never write \"vulnerable\"", "Never write \"safe\""):
            with self.subTest(must):
                self.assertIn(must, t)


if __name__ == "__main__":
    unittest.main()
