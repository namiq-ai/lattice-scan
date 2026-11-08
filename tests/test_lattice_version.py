"""The reference module: golden tables per scheme, NVD range boundaries, scheme mismatch, product ids, windows and the vendored hash. Standard library only."""
import hashlib, json, os, sys, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from lattice_scan import lattice_version as lv  # noqa: E402

GOLDEN = ROOT / "tests" / "golden"


class Golden(unittest.TestCase):
    def test_every_scheme_has_a_table_of_at_least_200_cases_and_reproduces_it(self):
        for scheme in lv.SCHEMES:
            doc = json.loads((GOLDEN / f"version_{scheme}.json").read_text())
            self.assertEqual(doc["scheme"], scheme)
            self.assertGreaterEqual(len(doc["cases"]), 200, scheme)
            for a, b, want in doc["cases"]:
                self.assertEqual(lv.compare(a, b, scheme), want, f"{scheme}: compare({a!r}, {b!r}) with oracle {doc['oracle']}")

    def test_tables_cover_order_equality_and_unparsable_input(self):
        for scheme in lv.SCHEMES:
            wants = {c[2] for c in json.loads((GOLDEN / f"version_{scheme}.json").read_text())["cases"]}
            self.assertTrue({-1, 1, None} <= wants, scheme)
            self.assertIn(0, wants, scheme)

    def test_an_unknown_scheme_compares_nothing(self):
        self.assertIsNone(lv.compare("1.0", "1.1", "nonsense"))


class Ranges(unittest.TestCase):
    def test_nvd_bounds_are_inclusive_and_exclusive_exactly(self):
        for scheme, lo, hi, below, above in (("generic", "2.0.1", "2.15.0", "2.0.0", "2.15.1"), ("semver", "2.0.1", "2.15.0", "2.0.0", "2.15.1"),
                                             ("pep440", "2.0.1", "2.15.0", "2.0.0", "2.15.1"), ("dpkg", "2.0.1", "2.15.0", "2.0.0", "2.15.1")):
            def r(**k):
                return dict(scheme=scheme, **k)
            self.assertIs(lv.in_range(lo, scheme, r(start_including=lo, end_excluding=hi)), True, scheme)          # startIncluding: the bound itself is inside
            self.assertIs(lv.in_range(lo, scheme, r(start_excluding=lo, end_excluding=hi)), False, scheme)         # startExcluding: it is not
            self.assertIs(lv.in_range(hi, scheme, r(start_including=lo, end_excluding=hi)), False, scheme)         # endExcluding: the bound itself is outside
            self.assertIs(lv.in_range(hi, scheme, r(start_including=lo, end_including=hi)), True, scheme)          # endIncluding: it is inside
            self.assertIs(lv.in_range(below, scheme, r(start_including=lo, end_including=hi)), False, scheme)
            self.assertIs(lv.in_range(above, scheme, r(start_including=lo, end_including=hi)), False, scheme)

    def test_camel_case_bounds_are_accepted(self):
        self.assertIs(lv.in_range("1.5", "generic", {"startIncluding": "1.0", "endExcluding": "2.0"}), True)

    def test_a_scheme_mismatch_is_undetermined_never_outside_range(self):
        self.assertIsNone(lv.in_range("2.14.0", "dpkg", {"scheme": "pep440", "start_including": "2.0", "end_excluding": "2.15"}))
        self.assertIsNone(lv.in_range("2.14.0", "semver", {"scheme": "maven", "end_excluding": "2.15"}))
        self.assertEqual(lv.verdict("2.14.0", "dpkg", [{"scheme": "pep440", "end_excluding": "2.15"}]), "undetermined")

    def test_a_generic_range_is_compared_with_any_versions_upstream_numbers(self):
        for scheme, v in (("dpkg", "1:2.14.0-1ubuntu3"), ("semver", "2.14.0"), ("pep440", "2.14.0"), ("apk", "2.14.0-r2"), ("generic", "v2.14.0")):
            self.assertIs(lv.in_range(v, scheme, {"start_including": "2.0.1", "end_excluding": "2.15.0"}), True, scheme)

    def test_a_date_or_build_id_as_a_bound_or_an_unparsable_version_is_undetermined(self):
        self.assertIsNone(lv.in_range("2.14.0", "generic", {"end_excluding": "2026-01-01"}))
        self.assertIsNone(lv.in_range("2.14.0", "generic", {"end_excluding": "build7"}))
        self.assertIsNone(lv.in_range("not-a-version", "generic", {"end_excluding": "2.15.0"}))
        self.assertIsNone(lv.in_range("2.14.0", "generic", {}))

    def test_verdict_over_several_ranges(self):
        rs = [{"start_including": "1.0", "end_excluding": "1.5"}, {"start_including": "2.0", "end_excluding": "2.5"}]
        self.assertEqual(lv.verdict("2.1", "generic", rs), "in-range")
        self.assertEqual(lv.verdict("1.7", "generic", rs), "outside-range")
        self.assertEqual(lv.verdict("1.7", "generic", rs + [{"end_excluding": "date"}]), "undetermined")     # one unjudgeable range hides no result
        self.assertEqual(lv.verdict("1.7", "generic", []), "undetermined")
        self.assertEqual(lv.verdict("1.2", "generic", rs + [{"end_excluding": "date"}]), "in-range")         # but a hit still wins


class Ladder(unittest.TestCase):
    def test_a_lead_never_hides_a_real_comparison(self):
        self.assertEqual(lv.strongest(["lead", "outside-range", "undetermined"]), "undetermined")
        self.assertEqual(lv.strongest(["lead", "in-range"]), "in-range")
        self.assertEqual(lv.strongest([]), "unmatch")
        self.assertEqual(list(lv.VERDICTS), sorted(lv.VERDICTS, key=lambda v: lv.VERDICT_RANK[v]))


class ProductIdentity(unittest.TestCase):
    def test_one_name_has_one_pid(self):
        self.assertEqual(lv.pid("Django_Rest.Framework", "pypi"), "pypi:django-rest-framework")
        self.assertEqual(lv.pid("django-rest-framework", "pypi"), lv.pid("Django_Rest_Framework", "pypi"))
        self.assertEqual(lv.pid("@Scope/Pkg", "npm"), "npm:@scope/pkg")
        self.assertEqual(lv.pid("Org.Example/Lib", "maven"), "maven:org.example:lib")
        self.assertEqual(lv.pid("Libbrotli1", "deb"), "deb:libbrotli1")
        self.assertEqual(lv.pid("serde_json", "cargo"), "cargo:serde-json")
        self.assertEqual(lv.pid("Some Product!", "nonsense"), "generic:some-product")

    def test_a_near_name_is_a_different_pid(self):
        self.assertNotEqual(lv.pid("examplelib", "pypi"), lv.pid("examplelib2", "pypi"))
        self.assertNotEqual(lv.pid("examplelib", "pypi"), lv.pid("examplelib-client", "pypi"))
        self.assertNotEqual(lv.pid("examplelib", "pypi"), lv.pid("examplelib", "npm"))


class CrossLanguage(unittest.TestCase):
    def test_the_shared_pid_table_matches_this_module(self):
        """tests/golden/pid_cases.json is copied into the website repository, whose TypeScript port of pid() must reproduce every row."""
        for name, eco, want in json.loads((GOLDEN / "pid_cases.json").read_text())["cases"]:
            self.assertEqual(lv.pid(name, eco), want, (name, eco))


class Windows(unittest.TestCase):
    def test_windows_are_utc_calendar_days_on_the_anchor_whatever_the_process_time_zone(self):
        saved = os.environ.get("TZ")
        try:
            for tz in ("Pacific/Auckland", "Etc/GMT+11", "UTC"):          # UTC+13 in summer and UTC-11
                os.environ["TZ"] = tz
                time.tzset()
                self.assertEqual(lv.window_days("2026-11-08", "daily"), ("2026-11-07", "2026-11-08"), tz)
                self.assertEqual(lv.window_days("2026-11-08", "weekly"), ("2026-11-02", "2026-11-08"), tz)
                self.assertEqual(lv.window_days("2026-11-08", "monthly"), ("2026-10-10", "2026-11-08"), tz)
                self.assertEqual(lv.window_days("2026-03-01T23:59:59+13:00", "daily"), ("2026-02-28", "2026-03-01"), tz)      # only the date part is used
        finally:
            if saved is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = saved
            time.tzset()

    def test_open_and_all_have_no_first_day_here(self):
        self.assertIsNone(lv.window_days("2026-11-08", "open"))
        self.assertIsNone(lv.window_days("2026-11-08", "all"))


class Vendoring(unittest.TestCase):
    def test_the_recorded_hash_matches_the_module(self):
        src = ROOT / "src" / "lattice_scan" / "lattice_version.py"
        want = (ROOT / "src" / "lattice_scan" / "VENDORED.sha256").read_text().split()[0]
        self.assertEqual(hashlib.sha256(src.read_bytes()).hexdigest(), want, "lattice_version.py changed: update VENDORED.sha256 and every consumer's copy (python3 packaging/vendor_hash.py)")


if __name__ == "__main__":
    unittest.main()
