# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""After consent, a host scan asks Lattice for the distribution's own verdict on the packages that joined a CVE by identity, and nothing else.
Invented packages, reserved CVE ids; the Lattice connection is a recording fake, so the test shows exactly what would be sent."""
import io, os, sys, tempfile, types, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import tmpfold  # noqa: E402  (one temp root per test run, removed at exit)
from lattice_scan import cli, lattice_identity as li  # noqa: E402

ROWS = {"CVE-2099-0001": li.Row("CVE-2099-0001", ("deb:examplezip", "apk:examplezip"), None, "osv-debian"),
        "CVE-2099-0002": li.Row("CVE-2099-0002", ("pypi:examplewheel",), None, "osv-pypi")}
INV = {"kernel": "6.1.0", "os": "Debian GNU/Linux 13 (trixie)", "osRelease": "Debian 13", "manager": "dpkg", "node": "", "restartRequired": False, "hash": "x", "host": {},
       "packages": {"libexamplezip1": "1.1.0-2+deb13u1", "secret-inhouse-tool": "4.2-1", "bash": "5.2-1"}, "sources": {"libexamplezip1": "examplezip"},
       "snaps": {}, "images": ["exampleorg/app:1"],
       "imageDetails": {"exampleorg/app:1": {"packageManager": "apk", "os": "alpine", "osVersion": "3.21.3", "packages": {"examplezip-libs": "1.1.0-r0"}, "sources": {"examplezip-libs": "examplezip"}}},
       "python": {"/home/example/env/lib/python3.12/site-packages": {"examplewheel": "1.2.0"}}}


class FakeLattice:
    def __init__(self, answers):
        self.sent, self.answers = [], answers

    def call(self, tool, **args):
        self.sent.append((tool, dict(args)))
        return {"results": self.answers(args)}


def entry(cve):
    return {"cve": cve, "vendor": "Exampleco", "product": "Examplezip", "title": "", "added": "2099-01-02", "due": "2099-01-23", "action": "", "affected": [],
            "ranges": [{"product": "exampleco/examplezip", "start_including": "1.1.0", "end_excluding": "1.1.1"}]}


def server(args):
    """Debian 13 and Alpine 3.21 fixed CVE-2099-0001; the registry has not fixed CVE-2099-0002 below 1.2.1."""
    if args["product"] == "examplezip" and args.get("os") == "Debian 13":
        return [{"cve": "CVE-2099-0001", "verdict": "outside-range", "why": "release 13 fixed this in 1.1.0-2+deb13u1", "basis": "distribution"}]
    if args["product"] == "examplezip" and args.get("os") == "Alpine 3.21.3":
        return [{"cve": "CVE-2099-0001", "verdict": "outside-range", "why": "release v3.21 fixed this in 1.1.0-r0", "basis": "distribution"}]
    if args["product"] == "examplewheel":
        return [{"cve": "CVE-2099-0002", "verdict": "in-range", "why": "1.2.0 is before the fix in the registry (1.2.1)", "basis": "registry"}]
    return []


class Verdict(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpfold.mkdtemp()
        for p in (mock.patch.object(cli, "OUT", Path(self.tmp)), mock.patch.object(cli, "IDENTITY", {"rows": ROWS, "aliases": {}, "note": ""}),
                  mock.patch.object(cli, "JOINED", {}), mock.patch.object(cli, "PROGRESS", True), mock.patch.dict(os.environ, {"LATTICE_SCAN_ITEM_VERDICT": ""})):
            p.start()
            self.addCleanup(p.stop)

    def scan(self, yes=True, tty=False, answer="y\n"):
        found, rows = [], []
        for cve in ("CVE-2099-0001", "CVE-2099-0002"):
            e = entry(cve)
            if cve == "CVE-2099-0002":
                e.update(product="Examplewheel", ranges=[{"product": "exampleco/examplewheel", "start_including": "1.1.0", "end_excluding": "1.1.1"}])
            m = cli.candidate(e, INV)
            imp = cli.impact(e, INV, m[1], m[2])
            found.append((e, m[0], imp))
            rows.append([cve, "yes", "-", "-", "-", "-", e["product"], "CANDIDATE", m[0]])
        lat = FakeLattice(server)
        stdin = types.SimpleNamespace(isatty=lambda: tty, readline=io.StringIO(answer).readline)
        with mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "stderr", io.StringIO()) as err:
            cli.distribution_verdicts(types.SimpleNamespace(yes=yes), lat, INV, found, rows)
        return lat, found, rows, err.getvalue()

    def test_only_the_joined_packages_are_sent_with_their_release_and_nothing_else(self):
        lat, _, _, _ = self.scan()
        sent = sorted((a["product"], a["ecosystem"], a["version"], a.get("os", "")) for _, a in lat.sent)
        self.assertEqual(sent, [("examplewheel", "pypi", "1.2.0", ""), ("examplezip", "apk", "1.1.0-r0", "Alpine 3.21.3"), ("examplezip", "deb", "1.1.0-2+deb13u1", "Debian 13")])
        self.assertTrue(all(t == "graph_affects" and set(a) <= {"product", "ecosystem", "version", "os", "kind"} for t, a in lat.sent))
        flat = repr(lat.sent)
        for never in ("secret-inhouse-tool", "bash", "/home/example", "libexamplezip1", "exampleorg/app"):
            self.assertNotIn(never, flat)

    def test_a_backported_fix_becomes_fixed_and_the_upstream_comparison_is_kept_beside_it(self):
        _, found, rows, _ = self.scan()
        e, _, imp = found[0]
        self.assertEqual(imp["versionCheckUpstream"]["verdict"], "in-range")            # NVD's upstream range alone said affected
        self.assertEqual((imp["versionCheck"]["verdict"], imp["versionCheck"]["basis"]), ("outside-range", "distribution"))
        self.assertEqual(rows[0][7], "FIXED")
        self.assertIn("1.1.0-2+deb13u1", rows[0][8])

    def test_a_wheel_the_upstream_range_misses_becomes_in_range_from_the_registry(self):
        _, found, rows, _ = self.scan()
        imp = found[1][2]
        self.assertEqual(imp["versionCheckUpstream"]["verdict"], "outside-range")
        self.assertEqual((imp["versionCheck"]["verdict"], imp["versionCheck"]["basis"]), ("in-range", "registry"))
        self.assertEqual(rows[1][7], "CANDIDATE")

    def test_nothing_is_sent_without_a_terminal_and_without_yes(self):
        lat, found, rows, err = self.scan(yes=False, tty=False)
        self.assertEqual(lat.sent, [])
        self.assertNotIn("versionCheckUpstream", found[0][2])
        self.assertIn("--yes sends them", err)

    def test_nothing_is_sent_when_the_person_says_no(self):
        lat, _, rows, err = self.scan(yes=False, tty=True, answer="n\n")
        self.assertEqual(lat.sent, [])
        self.assertEqual(rows[0][7], "CANDIDATE")

    def test_the_person_sees_what_will_be_sent_before_saying_yes(self):
        lat, _, _, err = self.scan(yes=False, tty=True, answer="d\ny\n")
        self.assertIn("ecosystem=deb", err)
        self.assertIn("os=Debian 13", err)
        self.assertEqual(len(lat.sent), 3)

    def test_it_can_be_turned_off(self):
        with mock.patch.dict(os.environ, {"LATTICE_SCAN_ITEM_VERDICT": "off"}):
            lat, _, _, _ = self.scan()
        self.assertEqual(lat.sent, [])

    def test_an_item_the_rules_refuse_is_not_sent(self):
        bad = li.Artefact("maven:org.example:examplezip", "1.0", "maven", "maven", "host-packages", "x")
        self.assertIsNone(cli.verdict_item(bad, INV))
        odd = li.Artefact("deb:examplezip", "1.0 with space", "dpkg", "dpkg", "host-packages", "x")
        self.assertIsNone(cli.verdict_item(odd, INV))

    def test_release_name(self):
        self.assertEqual(cli.release_name("debian", "13"), "Debian 13")
        self.assertEqual(cli.release_name("ubuntu", "26.04"), "Ubuntu 26.04")
        self.assertEqual(cli.release_name("", "13"), "")


if __name__ == "__main__":
    unittest.main()
