# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Each host run stores a local snapshot and prints what is new, changed or gone since the last one; the snapshot is private, pruned by count and never sent.
Invented software and reserved ids only."""
import json, os, stat, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli, snapshot  # noqa: E402
from test_agent_entry import Entry, EntryBase, exp, feed  # noqa: E402
from test_exposure import port, post  # noqa: E402


def snap(at, listeners=(), services=(), ssh=None, findings=None, inv="h1"):
    return {"schema": snapshot.SCHEMA, "on": at[:10], "at": at, "inventory": inv, "findings": findings or {}, "scope": "root", "deep": False,
            "listeners": list(listeners), "services": list(services), "ssh": ssh, "persistence": None}


class Diff(unittest.TestCase):
    def test_new_changed_and_gone(self):
        a = snap("2026-11-01T10:00:00", ["tcp/22 all interfaces openssh"], ["a.service", "b.service"], {"permitrootlogin": "no"}, {"CVE-2099-0001": {"installed": "x 1", "found": "2026-11-01"}})
        b = snap("2026-11-08T10:00:00", ["tcp/22 all interfaces openssh", "tcp/9090 all interfaces examplelib"], ["a.service"], {"permitrootlogin": "yes"},
                 {"CVE-2099-0002": {"installed": "y 2", "found": "2026-11-08"}})
        d = snapshot.diff(a, b)
        self.assertEqual(d["parts"]["listeners"], {"new": ["tcp/9090 all interfaces examplelib"], "gone": [], "changed": []})
        self.assertEqual(d["parts"]["services"]["gone"], ["b.service"])
        self.assertEqual(d["parts"]["ssh"]["changed"], ["permitrootlogin: no -> yes"])
        self.assertEqual((d["parts"]["findings"]["new"], d["parts"]["findings"]["gone"]), (["CVE-2099-0002"], ["CVE-2099-0001"]))
        text = snapshot.render(d, b)
        self.assertIn("new     findings: CVE-2099-0002 (first seen 2026-11-08)", text)
        self.assertIn("gone    running services: b.service", text)

    def test_identical_runs_say_nothing_changed(self):
        a = snap("2026-11-01T10:00:00", ["tcp/22 all interfaces openssh"])
        self.assertTrue(snapshot.empty(snapshot.diff(a, snap("2026-11-02T10:00:00", ["tcp/22 all interfaces openssh"]))))

    def test_a_part_read_in_only_one_run_is_not_called_gone(self):
        a = snap("2026-11-01T10:00:00", ssh={"permitrootlogin": "no"})
        b = snap("2026-11-02T10:00:00", ssh=None)
        d = snapshot.diff(a, b)
        self.assertNotIn("ssh", d["parts"]); self.assertTrue(any("SSH" in n for n in d["notes"]))
        b2 = snap("2026-11-02T10:00:00"); b2["listeners"] = None
        self.assertTrue(any("listening ports" in n for n in snapshot.diff(snap("2026-11-01T10:00:00", ["tcp/22 x y"]), b2)["notes"]))

    def test_save_is_private_and_pruned_by_count(self):
        with tempfile.TemporaryDirectory() as t:
            for i in range(5):
                snapshot.save(Path(t), snap(f"2026-11-0{i + 1}T10:00:00"), keep=3)
            files = sorted((Path(t) / "snapshots").glob("*.json"))
            self.assertEqual(len(files), 3)
            self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
            self.assertEqual(snapshot.latest(Path(t))["on"], "2026-11-05")


class TwoRuns(EntryBase):
    def setUp(self):
        super().setUp()
        cli._POSTURE.clear()
        self.pf = Path(self.tmp.name + ".posture.json")
        os.environ["LATTICE_SCAN_POSTURE"] = str(self.pf)
        self.addCleanup(lambda: (os.environ.pop("LATTICE_SCAN_POSTURE", None), cli._POSTURE.clear(), self.pf.unlink(missing_ok=True)))
        Entry.feed = feed([exp("CVE-2099-0001")])

    def run_with(self, p, *argv):
        cli._POSTURE.clear(); self.pf.write_text(json.dumps(p))
        return self.run_cli(*argv)

    def test_first_run_stores_a_snapshot_and_the_second_prints_exactly_what_changed(self):
        rc, out, err = self.run_with(post([port("all interfaces", "libexamplelib2", 8080)]), "--discover")
        self.assertEqual(rc, 0, err)
        self.assertIn("this is the first stored snapshot", out)
        self.assertIn("COVERAGE: listeners and services were read", out)
        rc, out, err = self.run_with(post([port("all interfaces", "libexamplelib2", 9090)], units=[{"unit": "example.service", "package": "libexamplelib2"}]), "--discover")
        self.assertEqual(rc, 0, err)
        block = out.split("CHANGE SINCE THE LAST RUN", 1)[1]
        self.assertIn("new     listening ports: tcp/9090 all interfaces libexamplelib2", block)
        self.assertIn("gone    listening ports: tcp/8080 all interfaces libexamplelib2", block)
        self.assertIn("new     running services: example.service", block)
        self.assertEqual(len(list((cli.OUT / "snapshots").glob("*.json"))), 2)

    def test_json_output_carries_the_change_and_stays_one_document(self):
        self.run_with(post([port("all interfaces", "libexamplelib2", 8080)]), "--discover")
        rc, out, err = self.run_with(post(), "--discover", "--format", "json")
        doc = json.loads(out)
        self.assertEqual(doc["change"]["parts"]["listeners"]["gone"], ["tcp/8080 all interfaces libexamplelib2"])

    def test_posture_since_last_compares_with_the_stored_run(self):
        self.run_with(post([port("all interfaces", "libexamplelib2", 8080)]), "--discover")
        from lattice_scan import posture
        orig = posture.collect
        posture.collect = lambda deep=False, **k: post([port("loopback only", "libexamplelib2", 8080, "127.0.0.1")]) | {"ssh": {"settings": {}}, "firewall": {"managers": []}, "observations": [], "unreadable": [], "packageManager": "dpkg"}
        try:
            rc, out, err = self.run_cli("posture", "--since", "last")
        finally:
            posture.collect = orig
        self.assertEqual(rc, 0, err)
        self.assertIn("CHANGE SINCE THE LAST RUN", out)
        self.assertIn("tcp/8080 loopback only libexamplelib2", out)


if __name__ == "__main__":
    unittest.main()
