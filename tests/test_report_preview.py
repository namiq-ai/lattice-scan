# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The offer shows exactly what would be sent, and a yes counts for this run only (OCO-6056). Synthetic data only."""
import io, json, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import scan_report as sr, scan_report_flow as flow  # noqa: E402

ITEMS = [{"cve": f"CVE-2030-{i:04d}", "product": f"pkg{i}", "version": "1.0", "verdict": "in-range", "priority": "read", "hostname": "canary-host-7f3a", "path": "/home/canary/x"} for i in range(1, 4)]
PAYLOAD = sr.build_payload(ITEMS, "deep", "Alpine")


class Preview(unittest.TestCase):
    def test_lists_the_six_field_names_and_the_item_count(self):
        t = flow.preview(PAYLOAD)
        for name in flow.FIELD_NAMES:
            self.assertIn(name, t)
        self.assertIn("3 item(s)", t)
        self.assertIn("no hostname, address, port, path or user name", t)

    def test_d_shows_every_value_that_would_be_sent_and_nothing_else(self):
        out = io.StringIO()
        answers = iter(["d", ""])
        self.assertFalse(flow.offer(PAYLOAD, lambda p: next(answers), out))
        text = out.getvalue()
        shown = json.loads(text[text.index("{"):text.rindex("}") + 1])
        self.assertEqual(shown, PAYLOAD)                                 # exactly the payload: the same object that would be sent
        self.assertNotIn("canary", text)

    def test_a_cut_payload_says_how_many_were_left_out(self):
        big = sr.build_payload([{**ITEMS[0], "cve": f"CVE-2030-{i:04d}"} for i in range(1, 70)], "quick", "Debian")
        self.assertIn(f"{big['cut']} lower-priority item(s) left out", flow.preview(big))

    def test_a_yes_is_for_this_run_only(self):
        asked = []
        with tempfile.TemporaryDirectory() as d:
            for _ in range(2):                                           # two separate runs
                flow.after_scan(ITEMS, "quick", Path(d), stdin_tty=True, stderr_tty=True, env={}, quiet=False, fmt="table", enabled=True,
                                input_fn=lambda p: asked.append(1) or "y", out=io.StringIO(), os_name="Debian")
        self.assertEqual(len(asked), 2)                                  # asked again; nothing was remembered
        self.assertFalse((Path.home() / ".lattice-scan" / "consent-report.json").exists())


if __name__ == "__main__":
    unittest.main()
