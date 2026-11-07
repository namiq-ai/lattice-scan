# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Inline urgency fields and batch lookups (ADR-LATTICE-API-001 C1 and C2) in the client: a new server is asked once for ten ids and never asked for a
second detail read; an older server is never asked for a batch. Invented ids, no network."""
import json, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli  # noqa: E402

INLINE = {"epss": {"score": 0.5, "percentile": 0.9, "date": "2026-11-06"}, "ssvc": {"exploitation": "active", "automatable": "yes", "technical_impact": "total"},
          "cwe": ["CWE-502"], "description": "A flaw. " * 80, "references": ["https://example.test/a"], "status": "Analyzed",
          "date_created": "2026-10-01", "date_modified": "2026-10-05"}


def items_for(cve, inline=True, listed=True):
    nvd = {"id": cve, "uid": f"u-nvd-{cve}", "source": "nvd", "primary": True, "affected_products": "exampleco/examplelib; other/thing", "cvss_score": 9.8,
           **(INLINE if inline else {})}
    kev = {"id": cve, "uid": f"u-kev-{cve}", "source": "kev", "title": "Examplelib RCE", "vendor_project": "Exampleco", "product": "Examplelib",
           "date_added": "2026-11-01", "due_date": "2026-11-22", "known_ransomware_use": "Unknown"}
    return [kev, nvd] if listed else [nvd]


class Server:
    """What Lattice answers. `new` has the inline fields and takes ids; an older one has neither (and rejects ids as an unknown argument)."""

    def __init__(self, new=True, batch_error=False, bad=()):
        self.new, self.batch_error, self.bad = new, batch_error, set(bad)
        self.log = []

    def __call__(self, body):
        p = body.get("params") or {}
        name, args = p.get("name"), p.get("arguments") or {}
        self.log.append((name, dict(args)))
        if name == "graph_lookup" and "ids" in args:
            if not self.new or self.batch_error:
                return {"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": [{"type": "text", "text": "Unexpected keyword argument ids"}]}}
            res = [{"id": i, "error": "invalid_input", "detail": "bad"} if i in self.bad else {"id": i, "items": items_for(i)} for i in args["ids"]]
            return reply({"snapshot": "s1", "notices": [], "results": res, "access": {"limits": {"calls_per_minute": 10}}})
        if name == "graph_lookup":
            return reply({"snapshot": "s1", "notices": [], "items": items_for(args["id"], inline=self.new)})
        if name == "graph_node":
            return reply({"properties": {"description": "A flaw.", "cwe_refs": ["CWE-502"], "status": "Analyzed", "metadata": {"epss": {"score": 0.5}, "affected_products": ["a", "b"]}}})
        return reply({})

    def lookups(self):
        return [(n, a) for n, a in self.log if n == "graph_lookup"]


def reply(d):
    return {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": json.dumps(d)}]}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.patches = [mock.patch.object(cli, "CACHE_FILE", t / "c.json"), mock.patch.object(cli, "PACE_FILE", t / "pace.json"), mock.patch.object(cli, "KEY", ""),
                        mock.patch.object(cli, "pace_wait", lambda *a: 0.0), mock.patch.dict("os.environ", {"LATTICE_SCAN_READ_CACHE": "on"})]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def lat(self, server):
        l = cli.Lattice()
        l._post = server
        return l

    def ids(self, n, start=0):
        return [f"CVE-2099-{start + i:04d}" for i in range(n)]


class Batch(Base):
    def test_twelve_ids_on_a_new_server_take_three_lookups_not_twelve(self):
        s, ids = Server(), self.ids(12)
        l = self.lat(s)
        l.hint(ids)
        for c in ids:
            self.assertIsNotNone(cli.kev_entry(l, c))
        sizes = [len(a["ids"]) if "ids" in a else 1 for _, a in s.lookups()]
        self.assertEqual(sizes, [1, 10, 1])                                        # the first learns the server is new, then ten together, then the last alone
        self.assertEqual([n for n, _ in s.log].count("graph_node"), 0)

    def test_an_older_server_is_never_asked_for_a_batch(self):
        s, ids = Server(new=False), self.ids(5)
        l = self.lat(s)
        l.hint(ids)
        for c in ids:
            cli.kev_entry(l, c)
        self.assertTrue(all("ids" not in a for _, a in s.lookups()))
        self.assertEqual(len(s.lookups()), 5)

    def test_a_batch_that_fails_turns_batching_off_and_single_lookups_finish_the_job(self):
        s, ids = Server(batch_error=True), self.ids(6)
        l = self.lat(s)
        l.hint(ids)
        for c in ids:
            self.assertIsNotNone(cli.kev_entry(l, c))
        self.assertFalse(l.batch_ok)
        self.assertEqual(sum(1 for _, a in s.lookups() if "ids" in a), 1)           # tried once, then never again
        self.assertEqual(sum(1 for _, a in s.lookups() if "id" in a), 6)

    def test_an_id_that_errors_in_the_batch_is_looked_up_on_its_own(self):
        ids = self.ids(4)
        s = Server(bad=[ids[2]])
        l = self.lat(s)
        l.hint(ids)
        for c in ids:
            self.assertIsNotNone(cli.kev_entry(l, c))
        singles = [a["id"] for _, a in s.lookups() if "id" in a]
        self.assertEqual(singles, [ids[0], ids[2]])                               # the first, and the one the batch could not answer

    def test_ids_already_cached_are_left_out_of_the_batch(self):
        ids = self.ids(5)
        cli.read_cache_put("graph_lookup", {"id": ids[3]}, {"snapshot": "s", "items": items_for(ids[3])})
        s = Server()
        l = self.lat(s)
        l.hint(ids)
        for c in ids:
            cli.kev_entry(l, c)
        batched = [a["ids"] for _, a in s.lookups() if "ids" in a]
        self.assertEqual(batched, [[ids[1], ids[2], ids[4]]])

    def test_a_second_run_asks_nothing(self):
        ids = self.ids(11)
        s = Server()
        l = self.lat(s)
        l.hint(ids)
        for c in ids:
            cli.kev_entry(l, c)
        n = len(s.log)
        l2 = self.lat(s)
        l2.hint(ids)
        for c in ids:
            cli.kev_entry(l2, c)
        self.assertEqual(len(s.log), n)

    def test_with_the_cache_off_the_batch_still_serves_the_loop(self):
        ids = self.ids(8)
        s = Server()
        with mock.patch.dict("os.environ", {"LATTICE_SCAN_READ_CACHE": "off"}):
            l = self.lat(s)
            l.hint(ids)
            for c in ids:
                cli.kev_entry(l, c)
        self.assertEqual([len(a["ids"]) if "ids" in a else 1 for _, a in s.lookups()], [1, 7])

    def test_duplicates_in_the_hint_are_one_id_and_a_lone_id_is_never_batched(self):
        l = self.lat(Server())
        l.hint(["CVE-2099-0001", "cve-2099-0001", "CVE-2099-0001"])
        self.assertEqual(l.pending, ["CVE-2099-0001"])
        s = Server(); l = self.lat(s); l.hint(["CVE-2099-0001"])
        cli.kev_entry(l, "CVE-2099-0001")
        self.assertEqual(len(s.lookups()), 1)


class Inline(Base):
    def test_context_is_built_from_the_lookup_with_no_node_read(self):
        s = Server()
        l = self.lat(s)
        e = cli.kev_entry(l, "CVE-2099-0001")
        ctx = cli.context(l, e)
        self.assertEqual(ctx["epss"]["score"], 0.5)
        self.assertEqual(ctx["ssvc"], {"exploitation": "active", "automatable": "yes", "technical_impact": "total"})
        self.assertEqual(ctx["cwe"], ["CWE-502"])
        self.assertLessEqual(len(ctx["description"]), cli.CONTEXT_DESC)
        self.assertEqual(ctx["references"], ["https://example.test/a"])
        self.assertEqual(ctx["record"], {"status": "Analyzed", "created": "2026-10-01", "modified": "2026-10-05", "products": 2})
        self.assertEqual([n for n, _ in s.log].count("graph_node"), 0)

    def test_an_older_server_still_gets_its_detail_from_graph_node(self):
        s = Server(new=False)
        l = self.lat(s)
        e = cli.kev_entry(l, "CVE-2099-0001")
        ctx = cli.context(l, e)
        self.assertEqual(ctx["cwe"], ["CWE-502"])
        self.assertEqual([n for n, _ in s.log].count("graph_node"), 1)

    def test_a_named_cve_that_cisa_does_not_list_carries_the_inline_fields_too(self):
        class Unlisted(Server):
            def __call__(self, body):
                a = (body.get("params") or {}).get("arguments") or {}
                if "id" in a:
                    self.log.append(("graph_lookup", dict(a)))
                    return reply({"snapshot": "s1", "items": items_for(a["id"], listed=False)})
                return super().__call__(body)
        s = Unlisted()
        l = self.lat(s)
        self.assertIsNone(cli.kev_entry(l, "CVE-2099-0007"))
        ctx = cli.context(l, l.last_unlisted)
        self.assertEqual(ctx["record"]["products"], 2)
        self.assertEqual(ctx["epss"]["score"], 0.5)
        self.assertEqual([n for n, _ in s.log].count("graph_node"), 0)


if __name__ == "__main__":
    unittest.main()
