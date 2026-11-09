# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""0.7.0: `--discover --all` and `posture --attack` send items to Lattice one at a time, after showing exactly what, and only after a yes. Invented names, reserved ids."""
import io, json, sys, threading, unittest
from http.server import HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli  # noqa: E402
from test_agent_entry import Entry, EntryBase  # noqa: E402
from test_lattice_scan import INV  # noqa: E402


class Items(Entry):
    sent: list = []                  # (tool, arguments) of every item request
    answers: dict = {}               # product -> list of result rows
    fail_after = None                # answer a quota error once this many items were asked
    signals = {"ssh.password-auth": ["T1110"], "listen.all-interfaces": ["T1190", "T1133"]}

    def do_POST(self):
        n = int(self.headers["Content-Length"]); raw = self.rfile.read(n)
        body = json.loads(raw)
        p = body.get("params") or {}
        if body.get("method") == "tools/call" and p.get("name") in ("graph_affects", "graph_exposure"):
            a = p["arguments"]; Items.sent.append((p["name"], a))
            if Items.fail_after is not None and len(Items.sent) > Items.fail_after:
                data = {"error": "quota_exceeded", "message": "daily limit reached"}
            elif p["name"] == "graph_affects":
                data = {"schema": "lattice-affects/1", "item": a, "count": len(Items.answers.get(a["product"], [])), "results": Items.answers.get(a["product"], [])}
            else:
                t = Items.signals.get(a["signal"])
                data = {"schema": "lattice-exposure/1", "signal": a["signal"], "known": t is not None, "count": len(t or []), "results": [{"technique": x} for x in t or []]}
            out = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": {"content": [{"type": "text", "text": json.dumps(data)}], "isError": False}}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(out); return
        self.rfile = io.BytesIO(raw)
        return super().do_POST()


ROW = {"cve": "CVE-2099-0001", "vendor": "Exampleco", "product": "Examplelib", "verdict": "in-range", "why": "the version lies inside a listed range", "added": "2026-11-03", "due": "2026-11-06", "ransomware": "Unknown"}
POST = {"scope": "root", "ports": [{"proto": "tcp", "port": 8443, "addr": "0.0.0.0", "bind": "all interfaces", "package": "examplelib-server"}],
        "services": {"units": [{"unit": "otherd.service", "package": "otherd"}]}, "observations": [{"code": "ssh.password-auth", "level": "attention", "topic": "ssh", "text": "x"},
                                                                                              {"code": "process.stale-binary", "level": "note", "topic": "p", "text": "y"}]}
HOST = {"manufacturer": "Examplecorp", "model": "Box 9", "biosVersion": "F.12"}
INV2 = dict(INV, os="Example Linux 12.4 (bookworm)", manager="dpkg", host=HOST,
            packages={"examplelib-server": "2.4.1-1", "otherd": "1.0-2", "nginx": "1.24.0-1", "libsmall:amd64": "1.1", "rarething": "9.9", "bad name": "1"})


class AllItems(EntryBase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Items)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}"

    def setUp(self):
        super().setUp()
        cli.inventory = lambda: json.loads(json.dumps(INV2))
        Items.sent, Items.fail_after = [], None
        Items.answers = {"examplelib-server": [ROW]}
        self.post = mock.patch.object(cli, "posture_data", lambda: POST); self.post.start(); self.addCleanup(self.post.stop)

    def test_it_shows_the_items_and_sends_nothing_without_a_yes(self):
        rc, out, err = self.run_cli("--discover", "--all", stdin="n\n")
        self.assertEqual(rc, 2); self.assertEqual(Items.sent, [])
        self.assertIn("examplelib-server", err); self.assertIn("Nothing was sent", err)

    def test_no_terminal_and_no_yes_sends_nothing(self):
        rc, out, err = self.run_cli("--discover", "--all")
        self.assertEqual((rc, Items.sent), (2, [])); self.assertIn("Add --yes", err)

    def test_the_selected_items_are_what_listens_runs_is_well_known_and_the_kernel(self):
        rc, out, err = self.run_cli("--discover", "--all", "--yes")
        self.assertEqual(rc, 0, err)
        names = [a["product"] for t, a in Items.sent]
        self.assertEqual(names, ["examplelib-server", "otherd", "nginx", "linux"])      # listener, service, curated, kernel
        self.assertNotIn("rarething", names)                                              # merely installed: only with --all-installed
        self.assertEqual({t for t, _ in Items.sent}, {"graph_affects"})
        first = Items.sent[0][1]
        self.assertEqual(first, {"product": "examplelib-server", "version": "2.4.1-1", "ecosystem": "deb", "os": "Example Linux 12.4"})
        self.assertEqual(Items.sent[-1][1], {"product": "linux", "version": "6.1.0-99-example", "os": "Example Linux 12.4", "kind": "kernel"})

    def test_nothing_that_names_the_machine_is_ever_sent(self):
        self.run_cli("--discover", "--all", "--yes", "--all-installed", "--with-hardware")
        blob = json.dumps(Items.sent)
        for secret in ("bad name", "0.0.0.0", "8443", "127.0.0.1", "root", "bookworm"):
            self.assertNotIn(secret, blob)
        for _t, a in Items.sent:
            self.assertLessEqual(set(a), {"product", "version", "vendor", "ecosystem", "os", "kind"})
        self.assertIn("libsmall", blob)                                                  # the architecture suffix is dropped, the name kept
        self.assertNotIn(":amd64", blob)

    def test_all_installed_and_hardware_are_opt_in(self):
        self.run_cli("--discover", "--all", "--yes", "--all-installed", "--with-hardware")
        names = [a["product"] for _t, a in Items.sent]
        self.assertIn("rarething", names); self.assertIn("Box-9", names)
        hw = next(a for _t, a in Items.sent if a.get("kind") == "hardware")
        self.assertEqual(hw, {"product": "Box-9", "version": "F.12", "vendor": "Examplecorp", "kind": "hardware"})

    def test_the_result_joins_the_local_exposure_label(self):
        rc, out, err = self.run_cli("--discover", "--all", "--yes")
        row = next(l for l in out.splitlines() if l.startswith("CVE-2099-0001"))
        self.assertIn("in-range", row); self.assertIn("listens on all interfaces", row)
        self.assertNotIn("0.0.0.0:8443", "\n".join(Items.sent[0][1].values()))       # the address stays here; only the label is printed locally

    def test_max_items_cuts_the_list_and_says_so(self):
        rc, out, err = self.run_cli("--discover", "--all", "--yes", "--max-items", "2")
        self.assertEqual(len(Items.sent), 2); self.assertIn("left out by --max-items", err)

    def test_a_limit_stops_the_run_with_a_partial_result_and_exit_3(self):
        Items.fail_after = 1
        rc, out, err = self.run_cli("--discover", "--all", "--yes")
        self.assertEqual(rc, 3); self.assertIn("were not sent", err); self.assertIn("CVE-2099-0001", out)

    def test_format_json_keeps_the_question_on_stderr(self):
        rc, out, err = self.run_cli("--discover", "--all", "--yes", "--format", "json")
        doc = json.loads(out); self.assertEqual(doc["rows"][0]["cve"], "CVE-2099-0001")
        self.assertIn("will be sent", err)

    def test_fail_on_in_range_exits_1(self):
        rc, _o, _e = self.run_cli("--discover", "--all", "--yes", "--fail-on", "in-range")
        self.assertEqual(rc, 1)

    def test_posture_attack_sends_signal_codes_only(self):
        from lattice_scan import posture
        d = {"ports": [], "observations": POST["observations"], "services": {}, "scope": "user", "level": "quick"}
        with mock.patch.object(posture, "collect", return_value=d), mock.patch.object(posture, "render", lambda x: json.dumps([o.get("techniques") for o in x["observations"]])):
            rc, out, err = self.run_cli("posture", "--attack", "--yes")
        self.assertEqual(rc, 0, err)
        self.assertEqual(sorted(a["signal"] for _t, a in Items.sent), ["process.stale-binary", "ssh.password-auth"])
        self.assertEqual({t for t, _ in Items.sent}, {"graph_exposure"})
        self.assertIn("T1110", out)

    def test_posture_attack_without_a_yes_sends_nothing(self):
        from lattice_scan import posture
        with mock.patch.object(posture, "collect", return_value={"ports": [], "observations": POST["observations"], "services": {}, "scope": "user", "level": "quick"}), \
                mock.patch.object(posture, "render", lambda x: "rendered"):
            rc, out, err = self.run_cli("posture", "--attack", stdin="n\n")
        self.assertEqual(Items.sent, []); self.assertIn("signal=ssh.password-auth", err)


class Withdrawn(EntryBase):
    def test_project_discover_all_stays_off_and_sends_nothing(self):
        rc, out, err = self.run_cli("project", ".", "--discover", "--all")
        self.assertEqual((rc, out), (2, "")); self.assertIn("not available in this version", err)
        self.assertEqual(self.lattice_reads(), 0)

    def test_index_command_is_gone(self):
        with self.assertRaises(SystemExit):
            self.run_cli("index")

    def test_nothing_downloads_a_dataset_any_more(self):
        import inspect
        src = inspect.getsource(cli)
        for name in ("fetch_bytes", "exploited.load", "observations.load", "cmd_index"):
            self.assertNotIn(name, src)

    def test_recent_all_is_the_thirty_day_list_and_still_works(self):
        from test_agent_entry import feed
        Entry.feed = feed([{"id": "CVE-2099-0001", "vendor": "Exampleco", "product": "Examplelib", "added": "2026-11-03", "due": "2026-11-06", "ransomware": "Unknown", "cvss": 9.8, "epss": 0.1, "priority": "today"}])
        rc, out, err = self.run_cli("recent", "--all")
        self.assertEqual(rc, 0, err); self.assertIn("CVE-2099-0001", out)


class Select(unittest.TestCase):
    def test_os_label_keeps_family_and_version_only(self):
        from lattice_scan import items
        self.assertEqual(items.os_label("Ubuntu 26.04 LTS (Resolute)"), "Ubuntu 26.04")
        self.assertEqual(items.os_label("Alpine Linux v3.12"), "Alpine Linux 3.12")
        self.assertEqual(items.os_label("???"), "")

    def test_make_refuses_what_does_not_fit(self):
        from lattice_scan import items
        for bad in ("host.example.com/x", "a b", "a@b", "x=1"):
            self.assertIsNone(items.make(bad, "1.0"))
        self.assertIsNone(items.make("ok", "1.0 beta"))
        self.assertIsNone(items.make("ok", "1.0", vendor="a/b"))


if __name__ == "__main__":
    unittest.main()
