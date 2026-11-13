# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The accuracy fields of a scan record: which container image or the host holds each package, the installed versions, how each match was made, whether a changelog
names the CVE, the distribution's status and the run's coverage. They are switched off in released clients (`REPORT_FIELDS_AVAILABLE`); these tests prove the record is
unchanged while it is off and that every field stays inside fixed lists when it is on. Synthetic data only."""
import io, json, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli  # noqa: E402
from lattice_scan import scan_record as rec  # noqa: E402
from lattice_scan import scan_report_flow as flow  # noqa: E402

IMG = "registry.example.test/web:1.4"
INV = {"kernel": "7.0.0-1", "os": "Debian GNU/Linux 13", "manager": "dpkg", "node": "", "restartRequired": False, "host": {},
       "packages": {"libfoo1": "1.1.0-2", "nginx": "1.26.3-1"}, "snaps": {}, "images": [IMG],
       "imageDetails": {IMG: {"id": "sha256:aaaa", "os": "debian", "osVersion": "13", "packages": {"libfoo1": "1.0.0-1"}}}}
EXTRAS = {"assets": ["host", IMG], "installedVersions": ["1.1.0-2", "1.0.0-1"], "basis": "identity", "changelog": "unchecked",
          "distro": [{"verdict": "fixed", "fixedIn": "1.1.0-2+deb13u1", "source": "debian"}, {"verdict": "before-fix", "fixedIn": "1.0.0-2", "source": "debian"}]}
BASE_ITEM = {"cve": "CVE-2030-0001", "product": "Foo", "version": "1.1.0", "verdict": "in-range", "priority": "fix first", "why": ["listed"],
             "installed": ["libfoo1", "libfoo1"], "listed": "2030-01-01", "due": "2030-01-22"}
COVERAGE = {"identity": 22, "name": 78, "notChecked": ["firmware", "windows"], "notRead": ["node-global"]}


def record(item_extra=None, coverage=None, **kw):
    return rec.build_record(INV, [{**BASE_ITEM, **(item_extra or {})}], "deep", "Debian", coverage=coverage, **kw)


class On(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(rec, "REPORT_FIELDS_AVAILABLE", True)
        p.start()
        self.addCleanup(p.stop)


class Off(unittest.TestCase):
    def test_the_switch_is_off_in_this_build(self):
        self.assertIs(rec.REPORT_FIELDS_AVAILABLE, False)

    def test_the_record_is_byte_identical_whatever_the_items_carry(self):
        plain = json.dumps(record(), sort_keys=True)
        loaded = json.dumps(record(EXTRAS, COVERAGE), sort_keys=True)
        self.assertEqual(plain, loaded)
        for k in rec.ITEM_FIELDS_NEW + rec.TOP_FIELDS_NEW:
            self.assertNotIn(f'"{k}"', loaded)

    def test_check_record_refuses_the_new_fields_while_off(self):
        r = record()
        for extra in ({"assets": ["host", "host"]}, {"basis": "name"}, {"distro": []}):
            with self.assertRaisesRegex(ValueError, "not allowed in a scan record item"):
                rec.check_record({**r, "items": [{**r["items"][0], **extra}]})
        with self.assertRaisesRegex(ValueError, "not allowed in the scan record"):
            rec.check_record({**r, "coverage": COVERAGE})

    def test_host_items_carry_no_new_keys_while_off(self):
        hit = ({"cve": "CVE-2030-0001", "product": "Foo", "added": "", "due": ""}, "why", {"installed": ["libfoo1 1.1.0-2"], "versionCheck": {"verdict": "in-range"}})
        for k in rec.ITEM_FIELDS_NEW:
            self.assertNotIn(k, flow.host_items([hit], INV)[0])

    def test_the_offer_text_is_unchanged_while_off(self):
        with tempfile.TemporaryDirectory() as d:
            out = io.StringIO()
            flow.after_scan([BASE_ITEM], "deep", Path(d), quiet=False, stdin_tty=True, stderr_tty=True, env={}, enabled=True, input_fn=lambda _p="": "", out=out,
                            os_name="Debian", inv=INV, distro_pending=5, distro_fn=lambda: self.fail("asked while off"))
        self.assertNotIn("distribution", out.getvalue())
        self.assertNotIn("Nothing is asked before your yes", out.getvalue())


class Fields(On):
    def test_every_field_is_in_the_record(self):
        r = record(EXTRAS, COVERAGE)
        it = r["items"][0]
        self.assertEqual((it["assets"], it["installedVersions"], it["basis"], it["changelog"]), (["host", IMG], ["1.1.0-2", "1.0.0-1"], "identity", "unchecked"))
        self.assertEqual(it["distro"][1], {"verdict": "before-fix", "fixedIn": "1.0.0-2", "source": "debian"})
        self.assertEqual(r["coverage"], COVERAGE)

    def test_without_the_distribution_check_the_record_has_no_distro(self):
        extras = {k: v for k, v in EXTRAS.items() if k != "distro"}
        self.assertNotIn("distro", record(extras)["items"][0])

    def test_lists_must_run_parallel_to_installed(self):
        short = record({"assets": ["host"]})["items"][0]
        self.assertNotIn("assets", short)                                 # one entry for two packages is dropped, not guessed
        r = record(EXTRAS)
        r["items"][0]["assets"] = ["host"]
        with self.assertRaisesRegex(ValueError, "not parallel"):
            rec.check_record(r)

    def test_an_asset_is_the_host_or_an_image_the_record_holds(self):
        self.assertNotIn("assets", record({"assets": ["host", "registry.example.test/other:9"]})["items"][0])   # an image the record does not hold is dropped
        r = record(EXTRAS)
        r["items"][0]["assets"] = ["host", "registry.example.test/other:9"]
        with self.assertRaisesRegex(ValueError, "neither the host nor an image"):
            rec.check_record(r)

    def test_words_outside_the_lists_are_not_sent(self):
        it = record({"basis": "guess", "changelog": "maybe"})["items"][0]
        self.assertNotIn("basis", it)
        self.assertNotIn("changelog", it)
        r = record(EXTRAS)
        for k, bad in (("basis", "guess"), ("changelog", "maybe")):
            with self.assertRaisesRegex(ValueError, "not on the list"):
                rec.check_record({**r, "items": [{**r["items"][0], k: bad}]})

    def test_a_distribution_status_is_one_of_five_words_from_three_sources(self):
        d = record({**EXTRAS, "distro": [{"verdict": "fixed", "fixedIn": "1.2", "source": "fedora"}, {"verdict": "bogus", "fixedIn": "x", "source": "debian"}]})["items"][0]["distro"]
        self.assertEqual(d, [{"verdict": "unknown", "fixedIn": "", "source": ""}] * 2)
        r = record(EXTRAS)
        r["items"][0]["distro"][0] = {"verdict": "unknown", "fixedIn": "", "source": "debian"}
        with self.assertRaisesRegex(ValueError, "unknown distribution status"):
            rec.check_record(r)

    def test_a_fixed_in_value_is_a_version_not_a_sentence(self):
        e = record({**EXTRAS, "distro": [{"verdict": "fixed", "fixedIn": "see the file /etc/passwd", "source": "debian"}] * 2})["items"][0]["distro"][0]
        self.assertEqual(e["fixedIn"], "")

    def test_a_path_or_mac_in_a_new_field_is_refused(self):
        r = record(EXTRAS)
        r["items"][0]["installedVersions"][0] = "1.0 /home/someone/x"
        with self.assertRaisesRegex(ValueError, "file path"):
            rec.check_record(r)
        r = record(EXTRAS)
        r["items"][0]["installedVersions"][0] = "00:00:5E:00:53:01"
        with self.assertRaisesRegex(ValueError, "MAC"):
            rec.check_record(r)

    def test_coverage_holds_percentages_and_words_from_fixed_lists(self):
        c = record(coverage={"identity": 250, "name": -3, "notChecked": ["firmware", "my-secret-project"], "notRead": ["node-global", "/home/x"]})["coverage"]
        self.assertEqual(c, {"identity": 100, "name": 0, "notChecked": ["firmware"], "notRead": ["node-global"]})
        r = record(coverage=COVERAGE)
        for bad in ({**COVERAGE, "extra": 1}, {**COVERAGE, "identity": "22"}, {**COVERAGE, "notRead": ["somewhere"]}):
            with self.assertRaises(ValueError):
                rec.check_record({**r, "coverage": bad})

    def test_a_cut_record_drops_assets_for_an_image_it_no_longer_holds(self):
        big = {**INV, "packages": {f"pkg{i}": "1.0" for i in range(5000)}}
        r = rec.build_record(big, [{**BASE_ITEM, **EXTRAS}], "deep", "Debian", max_bytes=2000)
        self.assertGreater(r["cut"], 0)
        rec.check_record(r)                                              # still valid after the cut


class Contract(unittest.TestCase):
    """The lists the service's field check must accept, as they were accepted. A change here is a change to the field list and needs a review of what leaves the machine."""

    def test_the_vocabularies_are_the_accepted_ones(self):
        self.assertEqual(rec.ITEM_FIELDS_NEW, ("assets", "distro", "basis", "changelog", "installedVersions"))
        self.assertEqual(rec.TOP_FIELDS_NEW, ("coverage",))
        self.assertEqual(rec.DISTRO_VERDICTS, ("fixed", "before-fix", "no-fix-yet", "not-affected", "unknown"))
        self.assertEqual(rec.DISTRO_SOURCES, ("debian", "ubuntu", "alpine"))
        self.assertEqual(rec.DISTRO_FIELDS, ("verdict", "fixedIn", "source"))
        self.assertEqual(rec.BASIS_WORDS, ("identity", "name", "range"))
        self.assertEqual(rec.CHANGELOG_WORDS, ("names", "none", "unchecked"))
        self.assertEqual(rec.NOT_READ_WORDS, ("python-global", "node-global", "host-browser"))
        self.assertEqual(rec.COVERAGE_FIELDS, ("identity", "name", "notChecked", "notRead"))

    def test_the_old_field_lists_are_unchanged(self):
        self.assertEqual(rec.ITEM_FIELDS, ("cve", "product", "version", "verdict", "priority", "why", "installed", "listed", "due"))
        self.assertEqual(rec.TOP_FIELDS, ("schema", "level", "os", "inventory", "items", "cut", "posture"))

    def test_the_service_check_accepts_a_client_record_when_it_is_importable(self):
        try:
            from graph_mcp.report_service import validate_record   # the service lives in another repository; this runs only where both are installed
        except ImportError:
            self.skipTest("the service's field check is not installed here")
        with mock.patch.object(rec, "REPORT_FIELDS_AVAILABLE", True):
            validate_record(json.loads(json.dumps(record(EXTRAS, COVERAGE))))


class HostItems(On):
    HIT = ({"cve": "CVE-2030-0001", "product": "Foo", "added": "2030-01-01", "due": "2030-01-22"}, "why",
           {"installed": ["libfoo1 1.1.0-2", f"libfoo1 1.0.0-1 (image {IMG})", "nginx"], "versionCheck": {"verdict": "in-range"}, "matchBasis": "identity"})

    def test_entries_are_split_into_name_version_and_image(self):
        self.assertEqual(flow.entry_parts(f"libfoo1 1.0.0-1 (image {IMG})"), ("libfoo1", "1.0.0-1", IMG))
        self.assertEqual(flow.entry_parts("libfoo1 1.1.0-2"), ("libfoo1", "1.1.0-2", ""))
        self.assertEqual(flow.entry_parts("kernel 7.0.0-1"), ("kernel", "7.0.0-1", ""))

    def test_an_identity_joined_image_package_keeps_its_image_out_of_the_version(self):
        self.assertEqual(flow.entry_parts(f"libfoo1 (image {IMG}) 1.0.0-1"), ("libfoo1", "1.0.0-1", IMG))
        self.assertEqual(flow.entry_parts(f"libfoo1 (image {IMG})"), ("libfoo1", "", IMG))

    def test_assets_and_versions_for_the_identity_join_format(self):
        hit = ({"cve": "CVE-2030-0001", "product": "Foo", "added": "2030-01-01", "due": "2030-01-22"}, "why",
               {"installed": ["libfoo1 1.1.0-2", f"libfoo1 (image {IMG}) 1.0.0-1"], "versionCheck": {"verdict": "in-range"}, "matchBasis": "identity"})
        it = flow.host_items([hit], INV)[0]
        self.assertEqual(it["assets"], ["host", IMG])
        self.assertEqual(it["installedVersions"], ["1.1.0-2", "1.0.0-1"])

    def test_assets_versions_basis_and_changelog(self):
        it = flow.host_items([self.HIT], INV)[0]
        self.assertEqual(it["assets"], ["host", IMG, "host"])
        self.assertEqual(it["installedVersions"], ["1.1.0-2", "1.0.0-1", "1.26.3-1"])      # a host package without a version in the entry takes the inventory's
        self.assertEqual((it["basis"], it["changelog"]), ("identity", "unchecked"))

    def test_basis_words(self):
        imp = {"versionCheck": {"verdict": "undetermined"}}
        self.assertEqual(flow.match_basis({**imp, "matchBasis": "identity"}), "identity")
        self.assertEqual(flow.match_basis({"matchBasis": "names", "versionCheck": {"verdict": "in-range"}}), "range")
        self.assertEqual(flow.match_basis({"matchBasis": "names", "versionCheck": {"verdict": "outside-range"}}), "range")
        self.assertEqual(flow.match_basis({**imp, "matchBasis": "lead"}), "name")
        self.assertEqual(flow.match_basis({}), "name")

    def test_changelog_words(self):
        base = {"installed": ["libfoo1 1.1.0-2"]}
        self.assertEqual(flow.report_extras({**base, "changelogNamesCve": ["libfoo1"]}, INV)["changelog"], "names")
        self.assertEqual(flow.report_extras(base, INV, lambda _i, _v: True)["changelog"], "none")      # a changelog was read and does not name it
        self.assertEqual(flow.report_extras(base, INV, lambda _i, _v: False)["changelog"], "unchecked")
        self.assertEqual(flow.report_extras(base, INV)["changelog"], "unchecked")


class DistroWords(unittest.TestCase):
    def answer(self, verdict, why, reason="range", basis="distribution"):
        return {"verdict": verdict, "why": why, "reason": reason, "basis": basis}

    def test_the_distribution_answers_in_the_records_words(self):
        e = flow.distro_entry
        self.assertEqual(e(self.answer("outside-range", "Debian 13 fixed this in 1.1.0-2+deb13u1"), "Debian 13"), {"verdict": "fixed", "fixedIn": "1.1.0-2+deb13u1", "source": "debian"})
        self.assertEqual(e(self.answer("outside-range", "the distribution marks release Debian 13 not affected", "not-affected"), "Debian 13"),
                         {"verdict": "not-affected", "fixedIn": "", "source": "debian"})
        self.assertEqual(e(self.answer("in-range", "1.0.0-1 is before the fix in Ubuntu 24.04 (1.0.0-2ubuntu1)"), "Ubuntu 24.04"),
                         {"verdict": "before-fix", "fixedIn": "1.0.0-2ubuntu1", "source": "ubuntu"})
        self.assertEqual(e(self.answer("in-range", "Alpine Linux v3.24 records no fix yet"), "Alpine Linux v3.24"), {"verdict": "no-fix-yet", "fixedIn": "", "source": "alpine"})

    def test_what_it_cannot_place_is_unknown(self):
        unknown = {"verdict": "unknown", "fixedIn": "", "source": ""}
        e = flow.distro_entry
        self.assertEqual(e(self.answer("undetermined", "the distribution is still investigating release 13", "investigating"), "Debian 13"), unknown)
        self.assertEqual(e(self.answer("outside-range", "x fixed this in 1.2", basis="registry"), "Debian 13"), unknown)      # a registry answer is not a distribution's
        self.assertEqual(e(self.answer("outside-range", "x fixed this in 1.2"), "Fedora 41"), unknown)                       # not one of the three sources
        self.assertEqual(e(self.answer("outside-range", "x fixed this in 1.2"), ""), unknown)
        self.assertEqual(e(self.answer("in-range", "something else entirely"), "Debian 13"), unknown)

    def test_merge_adds_distro_only_where_it_was_asked(self):
        items = [{**BASE_ITEM, **{k: v for k, v in EXTRAS.items() if k != "distro"}}, {**BASE_ITEM, "cve": "CVE-2030-0002", **{k: v for k, v in EXTRAS.items() if k != "distro"}}]
        got = {"CVE-2030-0001": {("libfoo1", "host"): {"verdict": "fixed", "fixedIn": "1.1.0-2+deb13u1", "source": "debian"}}}
        out = flow.merge_distro(items, got)
        self.assertEqual(out[0]["distro"], [{"verdict": "fixed", "fixedIn": "1.1.0-2+deb13u1", "source": "debian"}, {"verdict": "unknown", "fixedIn": "", "source": ""}])
        self.assertNotIn("distro", out[1])                                  # not asked: the row says "version range only"


class OneYes(On):
    """One confirmation covers the report and the distribution check; nothing is asked before it, and a run without a terminal never asks."""

    def run_flow(self, answers, distro_pending=3, **kw):
        asked, calls, sent = [], [], []

        def fn(prompt=""):
            asked.append(prompt)
            return answers.pop(0) if answers else ""

        def distro():
            calls.append(1)
            return {"CVE-2030-0001": {("libfoo1", "host"): {"verdict": "fixed", "fixedIn": "1.1.0-2+deb13u1", "source": "debian"}}}

        with tempfile.TemporaryDirectory() as d, mock.patch.object(flow.send, "send_report", lambda r, *a, **k: sent.append(r)):
            out = io.StringIO()
            flow.after_scan([{**BASE_ITEM, **{k: v for k, v in EXTRAS.items() if k != "distro"}}], "deep", Path(d), quiet=False, fmt="table", env={}, input_fn=fn, out=out,
                            os_name="Debian", inv=INV, enabled=True, post=lambda *a, **k: None, coverage=COVERAGE, distro_pending=distro_pending, distro_fn=distro,
                            **{**dict(stdin_tty=True, stderr_tty=True), **kw})
        return out.getvalue(), asked, calls, sent

    def test_the_confirmation_names_the_count_and_says_nothing_is_asked_before_the_yes(self):
        text, asked, calls, _ = self.run_flow([""])                         # Enter is No
        self.assertIn("3 package name(s)", text)
        self.assertIn("Nothing is asked before your yes", text)
        self.assertEqual((len(asked), calls), (1, []))                      # one question, and the check did not run

    def test_a_yes_runs_the_check_once_and_the_record_carries_its_answer(self):
        _, asked, calls, sent = self.run_flow(["y"])
        self.assertEqual((len(asked), len(calls)), (1, 1))                  # no second question for the distribution check
        self.assertEqual(sent[0]["items"][0]["distro"][0]["verdict"], "fixed")
        self.assertEqual(sent[0]["coverage"], COVERAGE)

    def test_details_show_the_new_fields_and_no_status_yet(self):
        text, _, calls, _ = self.run_flow(["d", ""])
        self.assertIn('"assets"', text)
        self.assertIn('"basis"', text)
        self.assertIn('"coverage"', text)
        self.assertNotIn('"distro"', text)                                  # added only after the yes
        self.assertEqual(calls, [])

    def test_no_terminal_no_offer_and_no_check(self):
        text, asked, calls, sent = self.run_flow(["y"], stdin_tty=False)
        self.assertEqual((asked, calls, sent), ([], [], []))
        self.assertNotIn("Nothing is asked before your yes", text)

    def test_nothing_pending_means_no_distribution_sentence(self):
        text, _, calls, sent = self.run_flow(["y"], distro_pending=0)
        self.assertNotIn("package name(s)", text)
        self.assertEqual(calls, [])
        self.assertNotIn("distro", sent[0]["items"][0])


class CliHelpers(unittest.TestCase):
    def test_coverage_is_a_share_and_fixed_words(self):
        with mock.patch.object(cli, "IDENTITY", {"list": {"cvesWithIdentity": 411, "catalogueRows": 1779}}):
            c = cli.report_coverage({"packages": {}, "python": {}})
        self.assertEqual((c["identity"], c["name"]), (23, 77))
        self.assertEqual(c["notRead"], ["node-global"])
        self.assertTrue(set(c["notChecked"]) <= set(rec.NOT_CHECKED_WORDS))

    def test_coverage_without_an_identity_list_is_zero_identity(self):
        with mock.patch.object(cli, "IDENTITY", None):
            c = cli.report_coverage({"python": {}, "nodeGlobal": {}})
        self.assertEqual((c["identity"], c["name"], c["notRead"]), (0, 100, []))

    def test_the_plan_counts_package_names_and_asks_nothing(self):
        self.assertIsNone(cli.distro_plan([], INV))
        self.assertIsNone(cli.distro_plan([({"cve": "CVE-2030-0001", "matchBasis": "names"}, "w", {})], INV))      # only identity joins are asked about


if __name__ == "__main__":
    unittest.main()
