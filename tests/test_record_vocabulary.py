# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The words the client puts in a record are the words the owner accepted (allowlist change A1 to A6): the service enforces the same closed lists, so a word outside them
is refused after the mailbox was confirmed. Synthetic data."""
import sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli  # noqa: E402
from lattice_scan import scan_record as rec  # noqa: E402

ACCEPTED = {
    "notChecked": {"php", "java", "ruby", "go", "dotnet", "browser"},
    "notRead": {"python-global", "node-global", "host-browser"},
    "distro.verdict": {"fixed", "before-fix", "no-fix-yet", "not-affected", "unknown"},
    "distro.source": {"debian", "ubuntu", "alpine"},
    "basis": {"identity", "name", "range"},
    "changelog": {"names", "none", "unchecked"},
}


class Vocabulary(unittest.TestCase):
    def test_every_word_the_client_can_send_is_an_accepted_word(self):
        self.assertTrue(set(rec.NOT_CHECKED_WORDS) <= ACCEPTED["notChecked"])
        self.assertTrue(set(rec.NOT_CHECKED_SENT) <= ACCEPTED["notChecked"])
        self.assertTrue(set(rec.NOT_READ_WORDS) <= ACCEPTED["notRead"])
        self.assertTrue(set(rec.DISTRO_VERDICTS) <= ACCEPTED["distro.verdict"])
        self.assertTrue(set(rec.DISTRO_SOURCES) <= ACCEPTED["distro.source"])
        self.assertTrue(set(rec.BASIS_WORDS) <= ACCEPTED["basis"])
        self.assertTrue(set(rec.CHANGELOG_WORDS) <= ACCEPTED["changelog"])

    def test_the_coverage_the_cli_builds_uses_only_accepted_words(self):
        c = cli.report_coverage({"packages": {}, "images": []})
        self.assertTrue(set(c["notChecked"]) <= ACCEPTED["notChecked"])
        self.assertTrue(set(c["notRead"]) <= ACCEPTED["notRead"])
        self.assertNotIn("browser", c["notChecked"])      # the browser is checked


if __name__ == "__main__":
    unittest.main()
