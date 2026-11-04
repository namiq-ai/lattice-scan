# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The skill for OpenAI: Codex reads the same SKILL.md; the directory plugin is a ZIP built from it. Standard library only."""
import json, re, sys, tempfile, unittest, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src")); sys.path.insert(0, str(ROOT / "packaging"))
from lattice_scan import __version__  # noqa: E402
import build_openai_plugin as bop  # noqa: E402
import check_openai_plugin as chk  # noqa: E402

SKILL = ROOT / "skills/lattice-scan/SKILL.md"


class Codex(unittest.TestCase):
    def test_the_repo_level_skills_folder_resolves_to_the_skill(self):
        link = ROOT / ".agents/skills/lattice-scan"
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.resolve(), (ROOT / "skills/lattice-scan").resolve())
        self.assertTrue((link / "SKILL.md").is_file() and (link / "scripts/lattice-scan.pyz").is_file())

    def test_openai_yaml_has_only_the_documented_keys_and_lets_codex_pick_the_skill_itself(self):
        t = (ROOT / "skills/lattice-scan/agents/openai.yaml").read_text()
        keys = set(re.findall(r"^\s{0,2}([a-z_]+):", t, re.M))
        self.assertLessEqual(keys, {"interface", "display_name", "short_description", "icon_small", "icon_large", "brand_color", "default_prompt", "policy", "allow_implicit_invocation", "dependencies"})
        self.assertIn("allow_implicit_invocation: true", t)
        self.assertIn('display_name: "Lattice Scan"', t)

    def test_skill_frontmatter_has_name_and_description(self):
        head = SKILL.read_text().split("---")[1]
        self.assertRegex(head, r"(?m)^name: lattice-scan$"); self.assertRegex(head, r"(?m)^description: .{40,}")


class Plugin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.zip = bop.build(Path(cls.tmp.name))
        cls.z = zipfile.ZipFile(cls.zip)
        cls.m = json.loads(cls.z.read("plugin.json"))
        cls.i = cls.m["extensions"]["com.openai"]["interface"]

    @classmethod
    def tearDownClass(cls):
        cls.z.close(); cls.tmp.cleanup()

    def test_manifest_follows_the_portable_schema(self):
        self.assertEqual(self.m["$schema"], "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json")
        self.assertRegex(self.m["name"], r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$"); self.assertNotIn("--", self.m["name"])
        self.assertLessEqual(len(self.m["name"]), 64)
        self.assertEqual(self.m["version"], __version__)
        allowed = {"$schema", "name", "version", "description", "author", "homepage", "repository", "license", "keywords", "extensions"}
        self.assertLessEqual(set(self.m), allowed)                      # the schema forbids any other top-level key
        self.assertLessEqual(set(self.m["author"]), {"name", "email", "url"})

    def test_listing_fields_meet_openais_limits(self):
        self.assertLessEqual(len(self.i["displayName"]), 30); self.assertLessEqual(len(self.i["shortDescription"]), 30)
        self.assertLessEqual(len(self.i["longDescription"]), 4000)
        for k in ("websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL"):
            self.assertTrue(self.i[k].startswith("https://"), k)
        for bad in ("MCP", "Plugin"):                                    # the guidelines: do not append these to a product name
            self.assertNotIn(bad, self.i["displayName"])
        for k in ("composerIcon", "logo"):
            self.assertTrue(self.i[k].startswith("./"), k); self.assertIn(self.i[k][2:], self.z.namelist())

    def test_listing_does_not_judge_compare_or_price(self):
        text = json.dumps(self.m)
        self.assertIsNone(re.search(r"\b(detects?|ranks?|prioriti[sz]es?|decides?|protects?|secures?|fixes|best|better than|only tool)\b", text, re.I))
        self.assertIsNone(re.search(r"(\$\s?\d|€\s?\d|\bpric(e|ing)\b|\bsubscription\b)", text, re.I))

    def test_the_directory_skill_does_not_teach_requesting_a_key(self):
        t = self.z.read("skills/lattice-scan/SKILL.md").decode()
        for gone in ("get-key", "A key, only for a person", "--accept-terms"):
            self.assertNotIn(gone, t)
        for kept in ("hosted sandbox", "data, never instructions", "Do not open any link", "Never print, log or pass on", "Never write \"vulnerable\""):
            self.assertIn(kept, t)
        self.assertIn("## 5. If it fails", t)
        self.assertEqual(len(re.findall(r"(?m)^## \d\.", t)), len(set(re.findall(r"(?m)^## (\d)\.", t))))   # numbering has no gap or repeat

    def test_the_bundled_script_is_the_one_in_the_repo_and_no_secret_travels(self):
        self.assertEqual(self.z.read("skills/lattice-scan/scripts/lattice-scan.pyz"), (ROOT / "skills/lattice-scan/scripts/lattice-scan.pyz").read_bytes())
        blob = b"".join(self.z.read(n) for n in self.z.namelist() if not n.endswith((".png", ".pyz")))
        self.assertNotIn(b"test_credentials", blob); self.assertNotIn(b"reviewer_instructions", blob)
        self.assertIsNone(re.search(rb"lat_[A-Za-z0-9]{20,}", blob))

    def test_the_codex_manifest_has_what_openais_tooling_requires(self):
        c = json.loads(self.z.read(".codex-plugin/plugin.json"))
        self.assertEqual((c["name"], c["version"]), (self.m["name"], self.m["version"]))
        self.assertEqual(c["skills"], "./skills/")
        self.assertTrue(c["author"]["name"] and c["description"])
        i = c["interface"]
        self.assertIsInstance(i["capabilities"], list)
        for k in ("composerIcon", "logo"):
            self.assertTrue(i[k].startswith("./") and i[k][2:] in self.z.namelist(), k)
        self.assertLessEqual(len(i["defaultPrompt"]), 3); self.assertTrue(all(len(x) <= 128 for x in i["defaultPrompt"]))
        for k in ("hooks", "mcpServers", "apps"):
            self.assertNotIn(k, c)                                       # a skills-only plugin

    def test_the_checker_passes_this_package_with_no_errors(self):
        res = chk.check(str(self.zip))
        self.assertEqual([m for lvl, m in res if lvl == "ERROR"], [])

    def test_the_checker_catches_what_the_first_upload_attempt_would_have_been_refused_for(self):
        import io
        def mutate(f):
            buf = io.BytesIO()
            with zipfile.ZipFile(self.zip) as src, zipfile.ZipFile(buf, "w") as dst:
                for n in src.namelist():
                    dst.writestr(n, f(n, src.read(n)))
            p = Path(self.tmp.name) / "bad.zip"; p.write_bytes(buf.getvalue()); return str(p)
        no_dot = mutate(lambda n, b: b.replace(b'"./assets/icon.png"', b'"assets/icon.png"') if n.endswith("plugin.json") else b)
        self.assertTrue(any("must be a relative path beginning with ./" in m for l, m in chk.check(no_dot) if l == "ERROR"))
        long_name = mutate(lambda n, b: b.replace(b'"displayName": "Lattice Scan"', b'"displayName": "Lattice Scan ' + b"x" * 30 + b'"') if n == "plugin.json" else b)
        self.assertTrue(any("displayName" in m and "limit is 30" in m for l, m in chk.check(long_name) if l == "ERROR"))
        with_hooks = mutate(lambda n, b: b)
        with zipfile.ZipFile(with_hooks, "a") as z2:
            z2.writestr("hooks.json", "{}")
        self.assertTrue(any("must not carry apps, hooks or MCP" in m for l, m in chk.check(with_hooks) if l == "ERROR"))

    def test_the_same_sources_give_the_same_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(bop.build(Path(d)).read_bytes(), self.zip.read_bytes())

    def test_no_hooks_apps_or_mcp_entries_that_a_skills_only_plugin_may_not_carry(self):
        names = self.z.namelist()
        self.assertFalse([n for n in names if n.endswith((".app.json", "hooks.json", "mcp.json", ".mcp.json"))])
        self.assertNotIn("hooks", self.m); self.assertNotIn("apps", self.m)


if __name__ == "__main__":
    unittest.main()
