# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The Claude Code plugin ZIP that every release attaches. Standard library only."""
import json, shutil, sys, tempfile, unittest, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src")); sys.path.insert(0, str(ROOT / "packaging"))
from lattice_scan import __version__  # noqa: E402
import build_claude_plugin as bcp  # noqa: E402


class ClaudePlugin(unittest.TestCase):
    def test_current_tree_passes_its_own_check(self):
        self.assertEqual(bcp.problems(), [])

    def test_zip_holds_the_files_claude_loads_and_the_same_bytes_each_time(self):
        with tempfile.TemporaryDirectory() as d:
            a = bcp.build(Path(d) / "a"); b = bcp.build(Path(d) / "b")
            self.assertEqual(a.name, f"lattice-scan-claude-plugin-{__version__}.zip")
            self.assertEqual(a.read_bytes(), b.read_bytes())
            with zipfile.ZipFile(a) as z:
                self.assertEqual(sorted(z.namelist()), sorted(bcp.FILES))
                self.assertEqual(json.loads(z.read(".claude-plugin/plugin.json"))["version"], __version__)

    def test_a_version_mismatch_or_stale_script_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for f in bcp.FILES:
                (root / f).parent.mkdir(parents=True, exist_ok=True); shutil.copy(ROOT / f, root / f)
            pj = root / ".claude-plugin/plugin.json"
            pj.write_text(json.dumps({**json.loads(pj.read_text()), "version": "0.0.1"}))
            self.assertTrue(any("0.0.1" in p for p in bcp.problems(root)))
            (root / "skills/lattice-scan/SKILL.md").write_text("no front matter")
            self.assertTrue(any("front matter" in p for p in bcp.problems(root)))


if __name__ == "__main__":
    unittest.main()
