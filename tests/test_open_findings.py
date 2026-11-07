# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""open findings are re-checked on every run, their ages are counted from today, the report splits today's list from earlier findings, and a name match is
read more finely (outside range, likely fixed by the distro, kernel to verify). Invented products only."""
import copy, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli  # noqa: E402
from test_candidate_context import Base, NODE, with_links, Stub  # noqa: E402

INV = {"packages": {"armv8crc-support": "27ubuntu2", "libexample1": "1.2.0-3ubuntu0.1"}, "snaps": {}, "images": [], "imageDetails": {}, "kernel": "7.0.0-41-cix",
       "host": {}, "node": "", "restartRequired": False}


class Findings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.p = [mock.patch.object(cli, "OUT", Path(self.tmp.name)), mock.patch.object(cli, "TODAY", "2026-11-06")]
        for p in self.p:
            p.start()

    def tearDown(self):
        for p in self.p:
            p.stop()
        self.tmp.cleanup()

    def found(self, ref, why, title, **k):
        cli.append("findings.jsonl", {"event": "found", "ref": ref, "on": "2026-11-03", "listed": "2026-10-08", "due": "2026-10-11", "title": title, "why": why, "kind": "kev", **k})

    def test_a_finding_from_the_old_matcher_is_withdrawn_when_its_product_is_only_ordinary_words(self):
        self.found("CVE-2099-0100", "product support matches armv8crc-support", "BeyondTrust Remote Support Authentication Bypass")   # recorded without vendor or product
        w = cli.recheck_open(INV)
        self.assertEqual([x["ref"] for x in w], ["CVE-2099-0100"])
        self.assertEqual(cli.state()["CVE-2099-0100"]["status"], "withdrawn")
        self.assertIn("not installed", w[0]["reason"])
        self.assertEqual(cli.earlier_findings(set())[0], [])                       # it is no longer listed as open
        self.assertEqual(cli.recheck_open(INV), [])                                # and is withdrawn once

    def test_a_legacy_finding_whose_vendor_is_installed_is_kept(self):
        inv = copy.deepcopy(INV); inv["packages"]["beyondtrust-agent"] = "1"
        self.found("CVE-2099-0100", "product support matches armv8crc-support", "BeyondTrust Remote Support Authentication Bypass")
        self.assertEqual(cli.recheck_open(inv), [])
        self.assertEqual(cli.state()["CVE-2099-0100"]["status"], "open")

    def test_a_distinctive_product_is_kept_and_a_finding_that_stored_its_product_is_matched_again(self):
        self.found("CVE-2099-0101", "product example matches libexample1", "Exampleco Example Flaw")
        self.assertEqual(cli.recheck_open(INV), [])
        self.found("CVE-2099-0102", "product media matches armv8crc-support", "Plex Media Server Flaw", vendor="Plex", product="Media Server")
        w = cli.recheck_open(INV)
        self.assertEqual([x["ref"] for x in w], ["CVE-2099-0102"]); self.assertIn("no longer matches", w[0]["reason"])

    def test_manual_findings_are_never_withdrawn(self):
        cli.append("findings.jsonl", {"event": "found", "ref": "CVE-2099-0103", "on": "2026-11-03", "listed": "", "title": "n", "why": "recorded by hand", "kind": "manual"})
        self.assertEqual(cli.recheck_open(INV), [])

    def test_ages_are_counted_from_today_not_from_the_day_it_was_recorded(self):
        self.assertEqual(cli.age_text("2026-10-08", "2026-10-11"), " (29 days ago), due 2026-10-11, overdue by 26 days")
        self.assertIn("due in 14 days", cli.age_text("2026-11-06", "2026-11-20")); self.assertIn("due today", cli.age_text("2026-10-30", "2026-11-06"))
        self.assertEqual(cli.age_text("", ""), ", due -")
        imp = {"installed": ["x 1"], "listed": "2026-10-08", "due": "2026-10-11", "daysSinceListed": 26, "dueStatus": "overdue by 23 days"}   # as saved on 11-03
        with mock.patch("builtins.print") as pr:
            cli.print_impact(imp)
        text = " ".join(str(c.args[0]) for c in pr.call_args_list)
        self.assertIn("29 days ago", text); self.assertIn("overdue by 26 days", text); self.assertNotIn("26 days ago", text)

    def test_refine_reads_a_name_match_more_finely_and_never_closes_it(self):
        out = cli.refine({"installed": ["bind9 1:9.20.24-1ubuntu0.4"], "versionCheck": {"verdict": "outside-range", "why": "x"}})
        self.assertEqual(out[0], "OUTSIDE RANGE")
        fixed = {"installed": ["libexample1 1.2.0-3ubuntu0.1"], "versionCheck": {"verdict": "in-range", "why": "x"}, "changelogNamesCve": ["libexample1"]}
        self.assertEqual(cli.refine(fixed)[0], "LIKELY FIXED"); self.assertIn("resolve", cli.refine(fixed)[1])
        no_changelog = {**fixed, "changelogNamesCve": []}
        self.assertIsNone(cli.refine(no_changelog))                                # in range, nothing says it was patched: stays plain
        upstream_only = {"installed": ["examplelib 1.2.0"], "versionCheck": {"verdict": "in-range", "why": "x"}, "changelogNamesCve": ["examplelib"]}
        self.assertIsNone(cli.refine(upstream_only))                               # no distro revision: a changelog line alone is not enough
        kernel = {"installed": ["kernel 7.0.0-41-cix"], "versionCheck": {"verdict": "in-range", "why": "x"}}
        self.assertEqual(cli.refine(kernel)[0], "VERIFY")
        self.assertIsNone(cli.refine(None)); self.assertIsNone(cli.refine({"installed": ["a 1"], "versionCheck": {"verdict": "undetermined", "why": "x"}}))

    def test_earlier_rows_come_back_separately_with_the_refined_label(self):
        self.found("CVE-2099-0104", "product example matches libexample1", "Exampleco Example Flaw",
                   impact={"installed": ["libexample1 1.2.0-3ubuntu0.1"], "versionCheck": {"verdict": "in-range", "why": "x"}, "changelogNamesCve": ["libexample1"]})
        cli.append("findings.jsonl", {"event": "impact", "ref": "CVE-2099-0104", "on": "2026-11-03", "impact": {"installed": ["libexample1 1.2.0-3ubuntu0.1"],
                  "versionCheck": {"verdict": "in-range", "why": "x"}, "changelogNamesCve": ["libexample1"]}})
        earlier, rows = cli.earlier_findings({"CVE-2099-9999"})
        self.assertEqual(len(earlier), 1); self.assertEqual(rows[0][0], "CVE-2099-0104"); self.assertEqual(rows[0][7], "LIKELY FIXED")
        self.assertEqual(cli.earlier_findings({"CVE-2099-0104"}), ([], []))        # read in this run: it belongs to today's table
        with mock.patch("builtins.print") as pr:
            cli.print_table(rows, cli.EARLIER_TITLE)
        self.assertIn("STILL OPEN FROM EARLIER RUNS", " ".join(str(c.args[0]) for c in pr.call_args_list if c.args))

    def test_withdrawn_findings_are_not_counted_as_touching_the_host(self):
        self.found("CVE-2099-0100", "product support matches armv8crc-support", "BeyondTrust Remote Support Authentication Bypass")
        cli.recheck_open(INV)
        s = cli.stats()
        self.assertEqual((s["touchedHost"], s["open"]), (0, 0))


class Stored(Base):
    def setUp(self):
        super().setUp()
        Stub.answers = {"CVE-2099-0001": with_links()}
        Stub.nodes = {"u-nvd": copy.deepcopy(NODE)}

    def tearDown(self):
        Stub.nodes = {}
        super().tearDown()

    def test_a_new_finding_stores_the_vendor_and_product_it_was_matched_on(self):
        self.run_cli("--cve", "CVE-2099-0001")
        f = cli.state()["CVE-2099-0001"]
        self.assertTrue(f["vendor"] and f["product"])

    def test_a_run_prints_today_and_earlier_findings_in_separate_tables(self):
        self.run_cli("--cve", "CVE-2099-0001")                                      # recorded
        Stub.answers["CVE-2099-0002"] = with_links("CVE-2099-0002", product="Nothinginstalled", vendor="Other", title="Other Nothinginstalled flaw")
        rc, out, _ = self.run_cli("--cve", "CVE-2099-0002")
        self.assertEqual(rc, 0)
        self.assertLess(out.index("RESULT BY CVE"), out.index("STILL OPEN FROM EARLIER RUNS")); self.assertEqual(out.count("RESULT BY CVE"), 1)
        today = out[out.index("RESULT BY CVE"):out.index("STILL OPEN FROM EARLIER RUNS")]
        self.assertIn("CVE-2099-0002", today); self.assertNotIn("CVE-2099-0001", today)


if __name__ == "__main__":
    unittest.main()
