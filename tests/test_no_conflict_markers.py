# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""No tracked text file holds a merge-conflict marker. A changelog once went into a commit with one after `git add -A` on a conflicted merge."""
import re, subprocess, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = re.compile(r"^(<{7} |={7}$|>{7} )", re.M)


class NoMarkers(unittest.TestCase):
    def test_tracked_text_files_have_no_conflict_markers(self):
        try:
            files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("not a git checkout")
        bad = []
        for f in files:
            if f.endswith((".md", ".py", ".json", ".toml", ".yml", ".yaml", ".1", ".txt")):
                try:
                    if MARK.search((ROOT / f).read_text(errors="replace")):
                        bad.append(f)
                except OSError:
                    continue
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
