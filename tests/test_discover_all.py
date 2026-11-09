# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""`--discover --all`: the whole signed exploited index matched against the host locally. It reads nothing from Lattice and its free output is statistics only
(counts by verdict and year, a count under 3 as `<3`) in the console, `--format json`, `--format csv` and `--json FILE`: no CVE id and no product name. A refused or
unreachable index stops the run with exit 2 or 3. Invented products and reserved ids only."""
import json, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli, exploited  # noqa: E402
from test_agent_entry import Entry, EntryBase  # noqa: E402

RANGE = lambda start, end: [{"scheme": "generic", "product": "exampleco/examplelib", "startIncluding": start, "endExcluding": end}]


def row(cve, added="2024-05-01", vendor="Exampleco", product="Examplelib", ranges=None, status="ranges"):
    return {"id": cve, "vendor": vendor, "product": product, "pid": "generic:examplelib", "aliases": [], "ranges": ranges if ranges is not None else RANGE("2.0.1", "2.15.0"),
            "versions": [], "rangeStatus": status, "added": added, "due": "2024-05-22", "ransomware": "not recorded"}


def index(rows, age=1):
    return {"rows": rows, "generation": 7, "exploitedAsOf": "2026-11-06", "ageDays": age, "stale": False, "source": "test", "note": ""}


class DiscoverAll(EntryBase):
    def run_all(self, rows, *extra):
        with mock.patch.object(cli.exploited, "load", return_value=index(rows)):
            return self.run_cli("--discover", "--all", *extra)

    def test_counts_by_verdict_and_year_and_nothing_is_read(self):
        rows = [row(f"CVE-2099-{i:04d}", added="2023-03-03", ranges=RANGE("2.0.1", "2.15.0")) for i in range(1, 6)]          # 2.17.1 is above: outside-range
        rows += [row(f"CVE-2099-{i:04d}", added="2022-02-02", ranges=RANGE("2.0.1", "3.0.0")) for i in range(10, 14)]          # inside: in-range
        rows += [row("CVE-2099-0100", added="2022-04-04", status="none", ranges=[])]                                          # no range: undetermined
        rows += [row("CVE-2099-0200", vendor="Nowhere", product="Nothingware")]                                                # not installed: unmatch
        rc, out, err = self.run_all(rows)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.lattice_reads(), 0)
        import re
        for line in (r"in-range\s+4", r"outside-range\s+5", r"undetermined\s+<3"):
            self.assertRegex(out, line)
        self.assertIn("2023  outside-range 5", out); self.assertIn("2022  in-range 4  undetermined <3", out)
        self.assertIn("0 reads from Lattice", out)

    def test_no_cve_id_and_no_product_name_in_any_format(self):
        rows = [row(f"CVE-2099-{i:04d}") for i in range(1, 8)]
        with tempfile.TemporaryDirectory() as d:
            jf = str(Path(d) / "all.json")
            outs = [self.run_all(rows)[1], self.run_all(rows, "--format", "json")[1], self.run_all(rows, "--format", "csv")[1]]
            self.run_all(rows, "--json", jf)
            outs.append(Path(jf).read_text())
        for text in outs:
            self.assertNotIn("CVE-2099", text); self.assertNotIn("Examplelib", text); self.assertNotIn("Exampleco", text); self.assertNotIn("libexamplelib2", text)
        doc = json.loads(outs[1])
        self.assertEqual(doc["window"], "all"); self.assertEqual(doc["rows"], []); self.assertEqual(doc["statistics"]["index"]["generation"], 7)
        self.assertTrue(outs[2].startswith("verdict,year,count\n"))

    def test_a_bucket_under_three_is_shown_as_less_than_three(self):
        rows = [row("CVE-2099-0001", ranges=RANGE("2.0.1", "3.0.0")), row("CVE-2099-0002", ranges=RANGE("2.0.1", "3.0.0"))]
        _, out, _ = self.run_all(rows, "--format", "json")
        doc = json.loads(out)
        self.assertEqual(doc["statistics"]["byVerdict"]["in-range"], "<3"); self.assertEqual(doc["statistics"]["byYear"]["2024"]["in-range"], "<3")

    def test_refused_index_exits_2_and_unreachable_exits_3(self):
        with mock.patch.object(cli.exploited, "load", side_effect=exploited.IndexRefused("bad signature")):
            rc, _, err = self.run_cli("--discover", "--all")
        self.assertEqual(rc, 2); self.assertIn("refused: bad signature", err)
        with mock.patch.object(cli.exploited, "load", side_effect=exploited.IndexUnavailable("cannot reach")):
            rc, _, err = self.run_cli("--discover", "--all")
        self.assertEqual(rc, 3); self.assertIn("stopped: cannot reach", err)

    def test_all_asks_the_index_to_be_fresh(self):
        with mock.patch.object(cli.exploited, "load", return_value=index([])) as m:
            self.run_cli("--discover", "--all")
        self.assertTrue(m.call_args.kwargs.get("require_fresh"))

    def test_fail_on_in_range_exits_1_only_when_something_is_in_range(self):
        inside = [row("CVE-2099-0001", ranges=RANGE("2.0.1", "3.0.0"))]
        outside = [row("CVE-2099-0002")]
        self.assertEqual(self.run_all(inside, "--fail-on", "in-range")[0], 1)
        self.assertEqual(self.run_all(outside, "--fail-on", "in-range")[0], 0)
        self.assertEqual(self.run_all(outside)[0], 0)

    def test_recent_all_keeps_its_old_meaning(self):
        # `recent --all` is still the whole thirty-day feed; only `--discover --all` is the index
        Entry.feed = __import__("test_agent_entry").feed([__import__("test_agent_entry").exp("CVE-2099-0001")])
        with mock.patch.object(cli.exploited, "load", side_effect=AssertionError("recent --all must not load the index")):
            rc, out, _ = self.run_cli("recent", "--all")
        self.assertEqual(rc, 0); self.assertIn("CVE-2099-0001", out)


if __name__ == "__main__":
    unittest.main()
