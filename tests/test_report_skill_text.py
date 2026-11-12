# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The skill, and so every plugin built from it, tells an agent to leave the report question to the person (OCO-6067)."""
import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SENTENCE = "An agent never answers it, never consents on anyone's behalf and never reads or opens a mailbox"


def carries(text: str) -> bool:
    return SENTENCE in " ".join(text.split())


class SkillText(unittest.TestCase):
    def test_the_skill_carries_the_sentence(self):
        self.assertTrue(carries((ROOT / "skills/lattice-scan/SKILL.md").read_text()))

    def test_the_plugins_are_built_from_that_file(self):
        for script in ("packaging/build_claude_plugin.py", "packaging/build_openai_plugin.py"):
            self.assertIn("skills/lattice-scan/SKILL.md", (ROOT / script).read_text().replace("SKILL_DIR / \"SKILL.md\"", "skills/lattice-scan/SKILL.md"), script)

    def test_removing_the_sentence_fails_the_check(self):
        text = (ROOT / "skills/lattice-scan/SKILL.md").read_text()
        self.assertFalse(carries(text.replace(SENTENCE, "")))

    def test_the_skill_tells_an_agent_to_leave_the_question_to_the_person(self):
        t = " ".join((ROOT / "skills/lattice-scan/SKILL.md").read_text().split())
        self.assertIn("leave it unanswered and tell the person it was offered", t)


if __name__ == "__main__":
    unittest.main()
