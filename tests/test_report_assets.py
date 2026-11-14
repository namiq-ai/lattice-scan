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


class Wording(unittest.TestCase):
    def build(self, **kw):
        it = item(distro=DIST)
        return rt.build_report([it], sr.build_payload([it], "deep", "Debian"), DAY, **kw)

    def test_the_host_os_is_the_hosts_own_name(self):
        self.assertIn("scan on a Ubuntu 26.04.1 LTS system", self.build(os_label="a Ubuntu 26.04.1 LTS system"))
        self.assertIn("scan on a Debian system", self.build())

    def test_coverage_and_the_restart_note_reach_the_report(self):
        t = self.build(coverage={"identity": 23, "name": 77}, restart=True)
        self.assertIn("23% of the exploited CVEs", t); self.assertIn("waiting for a restart", t)

    def test_one_action_line_per_open_running_package(self):
        t = self.build()
        acts = [l for l in t.splitlines() if l.strip().startswith("- CVE-2030-0100")]
        self.assertEqual(len(acts), 2)
        self.assertIn("pull or rebuild app-a:1", acts[0]); self.assertIn("1.0-2+deb13u1 or later", acts[0])

    def test_each_item_says_how_firm_its_evidence_is(self):
        self.assertIn("confidence: distribution record", self.build())

    def test_the_caution_is_said_once_not_beside_every_item(self):
        t = self.build()
        self.assertEqual(t.count("not a finding"), 1)

    def test_no_section_is_empty(self):
        lines = self.build().splitlines()
        for i, l in enumerate(lines):
            if l[:1].isdigit() and ". " in l[:4]:
                nxt = next((x for x in lines[i + 1:] if x.strip()), "")
                self.assertTrue(nxt and not (nxt[:1].isdigit() and ". " in nxt[:4]), f"section {l!r} has no body")

    def test_sockets_are_counted_by_kind(self):
        d = {"scope": "user", "level": "quick", "ports": [{"proto": "tcp", "port": 80, "bind": "all interfaces"}, {"proto": "tcp", "port": 80, "bind": "all interfaces"},
                                                         {"proto": "udp", "port": 5353, "bind": "all interfaces"}, {"proto": "udp", "port": 40000, "bind": "all interfaces"}]}
        t = "\n".join(rt.posture_lines(d))
        self.assertIn("4 on all interfaces", t); self.assertIn("1 distinct TCP port(s) and 1 UDP port(s), plus 1 UDP port(s) from 32768 up", t)


class NotChecked(unittest.TestCase):
    INV = {"packages": {"bind9": "1"}, "snaps": {}, "images": [], "imageDetails": {}, "host": {}}

    def test_a_product_with_no_word_to_compare_is_not_checked_unless_the_vendor_is_absent(self):
        self.assertTrue(cli.not_checked({"vendor": "Cisco", "product": "Secure Firewall ASA Software"}, self.INV))      # no word, and no vendor word either
        self.assertFalse(cli.not_checked({"vendor": "GitLab", "product": "Community Edition"}, self.INV))              # the vendor's name is nowhere on this machine
        self.assertTrue(cli.not_checked({"vendor": "Bind", "product": "Community Edition"}, self.INV))                 # the vendor's name is installed: might be here
        self.assertFalse(cli.not_checked({"vendor": "Ivanti", "product": "Connect Secure", "matchBasis": "component-absent"}, self.INV))

    def test_php_is_a_product_name_that_is_compared(self):
        self.assertEqual(cli.words("php"), {"php"}); self.assertIn("php", cli.stems("php8.3-cli"))
        self.assertNotIn("cli", cli.words("cli"))     # other short words are still ignored


class Refine(unittest.TestCase):
    def test_a_changelog_line_does_not_override_the_distribution(self):
        imp = {"installed": ["libwidget1 1.0-2+deb13u1"], "changelogNamesCve": ["libwidget1"], "versionCheck": {"verdict": "in-range", "why": "x", "basis": "distribution"}}
        self.assertIsNone(cli.refine(imp))
        imp["versionCheck"]["basis"] = "nvd"
        self.assertEqual(cli.refine(imp)[0], "LIKELY FIXED")


if __name__ == "__main__":
    unittest.main()


class Exposure(unittest.TestCase):
    from lattice_scan import exposure as ex
    POST = {"scope": "user", "ports": [{"proto": "tcp", "port": 3000, "addr": "::", "bind": "all interfaces", "package": "nodejs"},
                                       {"proto": "udp", "port": 5353, "addr": "224.0.0.251", "bind": "one address", "package": "browser"}]}

    def test_only_the_package_that_owns_the_port_is_named(self):
        lbl = self.ex.label(["nodejs 22.1", "nodejs-doc 22.1"], {"nodejs": "22.1", "nodejs-doc": "22.1"}, self.POST)
        self.assertIn("owned by nodejs", lbl["text"]); self.assertNotIn("nodejs-doc", lbl["text"])

    def test_a_multicast_listener_does_not_count_as_exposure(self):
        lbl = self.ex.label(["browser 1.0"], {"browser": "1.0"}, self.POST)
        self.assertNotEqual(lbl["class"], "all")
