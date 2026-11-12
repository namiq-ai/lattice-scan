"""Reading a Mac from files, and judging the Mac's own version against NVD's apple/macos ranges (release lines, security-improvement letters)."""
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli, macos   # noqa: E402

RANGES = [{"product": "apple/macos", "start_including": "13.0", "end_excluding": "13.7.5"},
          {"product": "apple/macos", "start_including": "14.0", "end_excluding": "14.7.5"},
          {"product": "apple/macos", "start_including": "15.0", "end_excluding": "15.3"},
          {"product": "apple/watchos", "end_excluding": "11.3"}]
ENTRY = {"cve": "CVE-2099-0100", "vendor": "Apple", "product": "Multiple Products", "title": "Apple Multiple Products Use-After-Free Vulnerability",
         "ranges": RANGES, "affected": ["apple/macos", "apple/watchos"]}


def tree(version="14.7.4", extra="", apps=None, brew=None):
    root = tempfile.mkdtemp()
    sv = Path(root) / "System/Library/CoreServices"
    sv.mkdir(parents=True)
    d = {"ProductName": "macOS", "ProductVersion": version, "ProductBuildVersion": "23H420"}
    if extra:
        d["ProductVersionExtra"] = extra
    (sv / "SystemVersion.plist").write_bytes(plistlib.dumps(d))
    for name, v in (apps or {}).items():
        b = Path(root) / "Applications" / f"{name}.app/Contents"
        b.mkdir(parents=True)
        info = {"CFBundleIdentifier": "x." + name} | ({"CFBundleShortVersionString": v} if v else {})
        (b / "Info.plist").write_bytes(plistlib.dumps(info))
    for f, v in (brew or {}).items():
        (Path(root) / "opt/homebrew/Cellar" / f / v).mkdir(parents=True)
    return root


def mac(root):
    return macos.collect(root)


class ReadAMac(unittest.TestCase):
    def test_reads_version_apps_and_cellar_from_files(self):
        inv = mac(tree("15.3", apps={"Firefox": "159.0", "Odd": ""}, brew={"openssl@3": "3.4.1", "wget": "1.25.0"}))
        self.assertEqual(inv["osInfo"]["version"], "15.3")
        self.assertEqual(inv["family"], "macos")
        self.assertEqual(inv["packages"]["firefox"], "159.0")
        self.assertEqual(inv["packages"]["openssl@3"], "3.4.1")
        self.assertEqual(inv["appsUnread"], 1)

    def test_no_program_is_run(self):
        root = tree("15.3", apps={"Firefox": "159.0"}, brew={"wget": "1.25.0"})
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("a program was run")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("a program was run")), \
             mock.patch.object(os, "system", side_effect=AssertionError("a program was run")):
            mac(root)
        self.assertNotIn("subprocess", vars(macos))

    def test_the_letter_is_kept(self):
        self.assertEqual(macos.read_os(tree("15.3", extra="(a)"))["extra"], "(a)")
        self.assertEqual(macos.read_os(tree("15.3"))["extra"], "")

    def test_a_mac_without_the_version_file_reads_nothing_and_says_so(self):
        self.assertEqual(macos.read_os(tempfile.mkdtemp()), {})


class Verdicts(unittest.TestCase):
    def verdict(self, version, extra=""):
        inv = mac(tree(version, extra=extra))
        why = cli.candidate(ENTRY, inv)
        self.assertIsNotNone(why, "a CVE filed under apple/macos is about the operating system")
        self.assertTrue(why[1][0].startswith("macOS "))
        return cli.mac_version_check(ENTRY, inv)

    def test_a_14_7_4_mac_is_in_range_of_a_fix_in_14_7_5(self):
        self.assertEqual(self.verdict("14.7.4")["verdict"], "in-range")

    def test_14_7_5_is_outside_the_range(self):
        self.assertEqual(self.verdict("14.7.5")["verdict"], "outside-range")

    def test_a_newer_line_is_outside(self):
        self.assertEqual(self.verdict("15.8.2")["verdict"], "outside-range")

    def test_a_line_with_no_listed_range_is_undetermined_not_fixed(self):
        v = self.verdict("12.7.6")
        self.assertEqual(v["verdict"], "undetermined")
        self.assertIn("not shown as fixed", v["why"])

    def test_a_security_improvement_letter_stops_a_fixed_conclusion(self):
        v = self.verdict("14.7.5", extra="(a)")
        self.assertEqual(v["verdict"], "undetermined")
        self.assertIn("(a)", v["why"])

    def test_the_letter_does_not_hide_an_in_range_mac(self):
        self.assertEqual(self.verdict("14.7.4", extra="(a)")["verdict"], "in-range")

    def test_a_cve_with_no_apple_macos_range_is_not_a_macos_candidate(self):
        e = dict(ENTRY, ranges=[RANGES[3]], product="Safari")
        self.assertIsNone(cli.candidate(e, mac(tree("14.7.4"))))

    def test_a_darwin_kernel_never_meets_a_linux_kernel_entry(self):
        e = {"cve": "CVE-2099-0101", "vendor": "Linux", "product": "Kernel", "title": "Linux Kernel", "ranges": []}
        self.assertIsNone(cli.candidate(e, mac(tree("14.7.4"))))

    def test_an_installed_app_is_matched_by_name_like_a_package(self):
        e = {"cve": "CVE-2099-0102", "vendor": "Mozilla", "product": "Firefox", "title": "Mozilla Firefox", "ranges": []}
        why = cli.candidate(e, mac(tree("15.3", apps={"Firefox": "159.0"})))
        self.assertIsNotNone(why)
        self.assertIn("159.0", why[2])


if __name__ == "__main__":
    unittest.main()
