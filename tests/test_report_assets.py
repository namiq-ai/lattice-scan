# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The report keeps one verdict per package, puts running assets first and cuts none of them off; a changelog line cannot turn a distribution's 'before the fix' into
'likely fixed'. Synthetic ids, images and versions only."""
import datetime as dt, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli, scan_report as sr, scan_report_flow as srf, scan_report_text as rt  # noqa: E402

DAY = dt.date(2026, 11, 12)
INV = {"images": ["app-a:1", "app-b:2"], "imageDetails": {r: {"running": r in ("app-a:1", "app-b:2")} for r in ("app-a:1", "app-b:2", "tool:old", "tool:older", "tool:oldest", "tool:ancient", "tool:prehistoric")},
       "packages": {"libwidget1": "1.0-2"}}
INSTALLED = [
    "libwidget (image tool:old) 1.0-r2", "libwidget (image tool:older) 1.0-r2", "libwidget (image tool:oldest) 1.0-r2", "libwidget (image tool:ancient) 1.0-r2",
    "libwidget (image tool:prehistoric) 1.0-r2", "libwidget (image app-a:1) 1.0-2+b7", "libwidget (image app-b:2) 1.0-2+b7", "libwidget1 1.0-2+deb13u1"]
DIST = [{"verdict": "unknown", "fixedIn": "", "source": ""}] * 5 + [
    {"verdict": "before-fix", "fixedIn": "1.0-2+deb13u1", "source": "debian"}, {"verdict": "before-fix", "fixedIn": "1.0-2+deb13u1", "source": "debian"},
    {"verdict": "fixed", "fixedIn": "", "source": "debian"}]


def item(**kw):
    base = {"cve": "CVE-2030-0100", "product": "Widget", "version": "1.0-r2", "verdict": "in-range", "priority": "fix first", "installed": [], "rows": srf.asset_rows(INSTALLED, INV)}
    return {**base, **kw}


class Assets(unittest.TestCase):
    def text(self, **kw):
        it = item(**kw)
        return rt.build_report([it], sr.build_payload([it], "deep", "Debian"), DAY)

    def test_rows_know_what_runs(self):
        rows = {r["asset"] or "host": r["running"] for r in srf.asset_rows(INSTALLED, INV)}
        self.assertTrue(rows["app-a:1"]); self.assertTrue(rows["host"]); self.assertFalse(rows["tool:old"])

    def test_running_assets_lead_and_none_is_cut_off(self):
        t = self.text(distro=DIST)
        run = [l for l in t.splitlines() if l.strip().startswith("running:")]
        self.assertEqual(len(run), 3)                                           # both containers and the host package
        self.assertIn("app-a:1", run[0]); self.assertIn("app-b:2", run[1])      # the open ones before the fixed one
        self.assertIn("host", run[2]); self.assertIn("FIXED", run[2])
        self.assertLess(t.index("running:"), t.index("idle:"))

    def test_idle_images_are_collapsed(self):
        t = self.text(distro=DIST)
        self.assertEqual(len([l for l in t.splitlines() if l.strip().startswith("idle:")]), rt.IDLE_SHOWN + 1)
        self.assertIn("+2 more idle image(s)", t)

    def test_status_is_the_worst_running_package(self):
        self.assertIn("2 running package(s) are before the distribution's fix", self.text(distro=DIST))
        fixed = [{"verdict": "fixed", "fixedIn": "", "source": "debian"}] * 8
        self.assertIn("every running package is fixed", self.text(distro=fixed))

    def test_without_the_distribution_the_range_is_named_as_all_there_is(self):
        t = self.text()
        self.assertIn("version range only: in-range", t); self.assertIn("no running package is confirmed fixed", t)

    def test_an_item_without_rows_renders_as_before(self):
        it = {"cve": "CVE-2030-0101", "product": "x", "version": "1", "verdict": "undetermined", "priority": "read"}
        self.assertIn("version check: undetermined", rt.build_report([it], sr.build_payload([it], "quick", "Debian"), DAY))

    def test_rows_never_reach_the_payload(self):
        self.assertNotIn("rows", str(sr.build_payload([item()], "deep", "Debian")))


class Refine(unittest.TestCase):
    def test_a_changelog_line_does_not_override_the_distribution(self):
        imp = {"installed": ["libwidget1 1.0-2+deb13u1"], "changelogNamesCve": ["libwidget1"], "versionCheck": {"verdict": "in-range", "why": "x", "basis": "distribution"}}
        self.assertIsNone(cli.refine(imp))
        imp["versionCheck"]["basis"] = "nvd"
        self.assertEqual(cli.refine(imp)[0], "LIKELY FIXED")


if __name__ == "__main__":
    unittest.main()
