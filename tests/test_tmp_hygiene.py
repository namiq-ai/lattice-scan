# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Tests make temporary folders only through tests/tmpfold.py, which removes them when the run ends (see that module for why)."""
import re, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


class TmpHygiene(unittest.TestCase):
    def test_no_test_calls_tempfile_mkdtemp_or_mktemp_directly(self):
        bad = [f"{p.name}:{n}" for p in sorted(HERE.glob("*.py")) if p.name != "tmpfold.py"
               for n, line in enumerate(p.read_text().splitlines(), 1) if re.search(r"tempfile\.(mkdtemp|mktemp)\(", line)]
        self.assertEqual(bad, [], "use tmpfold.mkdtemp()/mktemp(): a folder made here is never removed")


if __name__ == "__main__":
    unittest.main()
