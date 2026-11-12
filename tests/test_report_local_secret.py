# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""A secret-looking value found on this machine is shown on the screen as a kind and a place, and is in no record, report, log or file. Synthetic values built at run time."""
import io, json, os, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import local_secrets as ls  # noqa: E402
from lattice_scan import scan_record as rec  # noqa: E402
from lattice_scan import scan_report_flow as flow  # noqa: E402
from lattice_scan import scan_report_text as rt  # noqa: E402
from lattice_scan import posture  # noqa: E402

KEY = "lat_" + "Q7x" * 8                       # shaped like a key; built here so the file holds no key-shaped literal
PWD = "pass" + "word=" + "correct-horse-staple"
FRAGMENTS = (KEY, KEY[:10], KEY[4:16], "correct-horse", "staple")
ITEMS = [{"cve": "CVE-2030-0001", "product": "nginx", "version": "1.26.3-1", "verdict": "in-range", "priority": "fix first", "installed": ["nginx"]}]
INV = {"kernel": "7.0.0-1", "os": "Debian GNU/Linux 13", "manager": "dpkg", "packages": {"nginx": "1.26.3-1"}, "snaps": {}, "images": [], "imageDetails": {}, "host": {}}


def fake_machine(tmp: Path):
    proc = tmp / "proc"
    (proc / "123").mkdir(parents=True)
    (proc / "123" / "cmdline").write_bytes(("sudo\0env\0LATTICE_API_KEY=" + KEY + "\0lattice-scan\0").encode())
    (proc / "124").mkdir()
    (proc / "124" / "cmdline").write_bytes(b"ls\0-la\0--password-file\0/x\0")          # benign: a flag that names a file
    (proc / "self").mkdir()
    home = tmp / "home"
    home.mkdir()
    (home / ".bash_history").write_text("cd /srv\nmysql -u app --" + PWD + "\nls\n")
    return home, str(proc)


class LocalSecret(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home, self.proc = fake_machine(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_found_with_kind_and_place_and_never_the_value(self):
        found = ls.find(self.home, self.proc)
        self.assertEqual({(f["kind"], f["where"]) for f in found},
                         {("Lattice API key", ls.CMDLINE), ("password, token or key on a command line", ls.HISTORY)})
        text = json.dumps(found) + ls.notice(found)
        for frag in FRAGMENTS:
            self.assertNotIn(frag, text)
        self.assertIn("kept on this machine and never sent", ls.notice(found).lower())

    def test_benign_command_lines_and_empty_machines_give_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(ls.find(Path(d), str(Path(d) / "none")), [])
        self.assertEqual(ls.notice([]), "")

    def test_the_screen_shows_the_notice_before_the_question_and_the_value_is_nowhere(self):
        found = ls.find(self.home, self.proc)
        posture_result = {"scope": "user", "level": "quick", "ports": [], "firewall": {"readable": False, "managers": []}, "ssh": {"installed": False, "settings": {}}}
        out = io.StringIO()
        r = flow.record_after_yes(INV, ITEMS, "quick", "Debian", {"items": ITEMS}, posture_result, lambda p="": "y", out, secrets_fn=lambda: found)
        screen = out.getvalue()
        self.assertLess(screen.index("Secret-looking value(s) found"), screen.index("Include the posture?") if "Include the posture?" in screen else len(screen))
        self.assertEqual(r["posture"]["secretsFound"], 2)
        blob = json.dumps(r) + screen
        for frag in FRAGMENTS:
            self.assertNotIn(frag, blob)

    def test_the_local_report_and_the_posture_text_never_hold_it(self):
        found = ls.find(self.home, self.proc)
        d = {"scope": "user", "level": "quick", "euid": 1000, "ports": [], "firewall": {"readable": False, "managers": []}, "ssh": {"installed": False, "settings": {}},
             "services": {"units": []}, "unreadable": [], "packageManager": "dpkg", "localSecrets": found}
        d["observations"] = posture.observe(d)
        text = posture.render(d) + posture.dump(d) + rt.build_report(ITEMS, {"items": ITEMS, "level": "quick", "os": "Debian", "cut": 0}, posture=d)
        for frag in FRAGMENTS:
            self.assertNotIn(frag, text)
        self.assertIn("secret", text.lower())

    def test_nothing_is_written_by_the_search(self):
        before = sorted(str(p) for p in Path(self.tmp.name).rglob("*"))
        ls.find(self.home, self.proc)
        self.assertEqual(before, sorted(str(p) for p in Path(self.tmp.name).rglob("*")))

    def test_the_exposure_labels_of_a_scan_do_not_read_history(self):
        import inspect
        self.assertIn("secrets: bool = False", inspect.getsource(posture.collect))


if __name__ == "__main__":
    unittest.main()
