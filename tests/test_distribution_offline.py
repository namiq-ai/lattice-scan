# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The distribution verdict with no connection: the run goes on, nothing is asked (nothing can be sent), a saved verdict is used and labelled, and a package with
no saved verdict keeps the upstream comparison. Invented package names; no network."""
import json, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli  # noqa: E402

ITEM_A = {"product": "examplelib", "ecosystem": "deb", "version": "1.0-1", "os": "Debian 13"}
ITEM_B = {"product": "otherlib", "ecosystem": "deb", "version": "2.0-1", "os": "Debian 13"}
ANSWER = {"results": [{"cve": "CVE-2030-0001", "verdict": "outside-range", "why": "fixed in 1.0-1", "basis": "distribution"}]}


class Offline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.patches = [mock.patch.object(cli, "CACHE_FILE", t / "read-cache.json"), mock.patch.object(cli, "PACE_FILE", t / "pace.json"),
                        mock.patch.object(cli, "KEY", ""), mock.patch.dict("os.environ", {"LATTICE_SCAN_READ_CACHE": "on"}, clear=False),
                        mock.patch.object(cli, "SAVED_USED", {}), mock.patch.object(cli, "NET_DOWN", False)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def down(self):
        lat = cli.Lattice()
        def post(_body):
            raise cli.LatticeUnreachable("no route to host")
        lat._post = post
        return lat

    def test_cache_key_covers_distribution_verdicts(self):
        self.assertIsNotNone(cli._cache_key("graph_affects", ITEM_A))
        self.assertNotEqual(cli._cache_key("graph_affects", ITEM_A), cli._cache_key("graph_affects", ITEM_B))

    def age(self, days=3):
        f = cli.read_cache_path()
        d = json.loads(f.read_text())
        for e in d["entries"].values():
            e["at"] -= days * 86400
        f.write_text(json.dumps(d))

    def test_saved_verdict_is_used_offline_and_labelled(self):
        cli.read_cache_put("graph_affects", ITEM_A, ANSWER)
        self.age()                                       # older than the cache hours: only the offline fallback may use it
        got = cli.ask_distro(self.down(), {tuple(sorted(ITEM_A.items())): ITEM_A})
        self.assertEqual(got[tuple(sorted(ITEM_A.items()))][0]["verdict"], "outside-range")
        self.assertIn("distribution verdicts", cli.SAVED_USED)

    def test_a_missing_one_does_not_stop_the_others(self):
        cli.read_cache_put("graph_affects", ITEM_B, ANSWER)
        self.age()
        unique = {tuple(sorted(ITEM_A.items())): ITEM_A, tuple(sorted(ITEM_B.items())): ITEM_B}
        got = cli.ask_distro(self.down(), unique)
        self.assertNotIn(tuple(sorted(ITEM_A.items())), got)
        self.assertIn(tuple(sorted(ITEM_B.items())), got)

    def test_nothing_saved_returns_empty_without_raising(self):
        self.assertEqual(cli.ask_distro(self.down(), {tuple(sorted(ITEM_A.items())): ITEM_A}), {})

    def test_no_question_is_asked_when_there_is_no_connection(self):
        lat = self.down()
        lat.down = True
        found = [({"cve": "CVE-2030-0001", "matchBasis": "identity"}, "why", {})]
        with mock.patch.object(cli, "distro_plan", return_value=([found[0][:1] + ({},)], {"CVE-2030-0001": [ITEM_A]}, {tuple(sorted(ITEM_A.items())): ITEM_A}, [ITEM_A])), \
             mock.patch.object(cli, "confirm_send") as ask, mock.patch.object(cli, "ask_distro", return_value={}) as lookups:
            cli.distribution_verdicts(type("A", (), {})(), lat, {}, found, [])
        self.assertFalse(ask.called)
        self.assertTrue(lookups.called)


if __name__ == "__main__":
    unittest.main()
