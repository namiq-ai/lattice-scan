# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The scan record: a declared field list, no host identifier, a stated cap (ADR-LATTICE-SCAN-REPORT-001 D1). Synthetic data only; RFC 5737 and RFC 7042 values."""
import json, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import scan_record as rec  # noqa: E402

CANARY = {"hostname": "canary-host-7f3a.example.test", "ip": "198.51.100.7", "mac": "00:00:5E:00:53:01", "user": "canary-user-91", "path": "/home/canary-user-91/app/x.conf",
          "secret": "canary-secret-xx", "proc": "canary-proc-cmdline --token=abc", "debug": "canary-debug-line", "env": "CANARY_ENV=1"}
INV = {"kernel": "7.0.0-41", "os": "Ubuntu 26.04 LTS", "manager": "dpkg", "node": "v22.1.0", "restartRequired": False,
       "host": {"manufacturer": "Synthco", "model": "Synth 1000", "version": "1", "biosVersion": "9.9", "arch": "x86_64", "serial": CANARY["secret"], "hostname": CANARY["hostname"]},
       "packages": {"nginx": "1.26.3-1", "openssl": "3.4.1-1"}, "snaps": {"firefox": "134.0"},
       "images": ["registry.internal.example.test/team/app:1.2", "redis:alpine"],
       "imageDetails": {"redis:alpine": {"id": "sha256:abcd", "os": "alpine", "osVersion": "3.20", "packages": {"redis": "7.2"}, "env": CANARY["env"], "cmd": CANARY["proc"]}},
       # keys that are not on the list, at the top and nested: they must never get in
       "hostname": CANARY["hostname"], "ip": CANARY["ip"], "mac": CANARY["mac"], "user": CANARY["user"], "path": CANARY["path"], "posture": {"ports": [CANARY["ip"]]},
       "processes": [CANARY["proc"]], "debug": CANARY["debug"], "env": CANARY["env"], "imageScan": {"opened": 3}, "hash": "deadbeef"}
ITEMS = [{"cve": "CVE-2030-0001", "product": "nginx", "version": "1.26.3-1", "verdict": "in-range", "priority": "fix first", "why": ["CISA records ransomware use"], "installed": ["nginx"],
          "listed": "2026-10-01", "due": "2026-10-22", **{k: v for k, v in CANARY.items()}}]


class Record(unittest.TestCase):
    def test_no_canary_value_appears_anywhere_in_the_serialized_record(self):
        text = json.dumps(rec.build_record(INV, ITEMS, "deep", "Debian"))
        for k, v in CANARY.items():
            self.assertNotIn(v, text, f"{k} reached the record")

    def test_only_the_declared_keys_exist(self):
        r = rec.build_record(INV, ITEMS, "deep", "Debian")
        self.assertEqual(set(r), set(rec.TOP_FIELDS) - {"posture"}); self.assertLessEqual(set(r["inventory"]), set(rec.INVENTORY_FIELDS))
        self.assertLessEqual(set(r["inventory"]["host"]), set(rec.HOST_FIELDS)); self.assertLessEqual(set(r["items"][0]), set(rec.ITEM_FIELDS))
        self.assertEqual(set(r["inventory"]["imageDetails"]["redis:alpine"]), {"id", "os", "osVersion", "packages"})

    def test_image_names_are_sent_including_an_internal_registry(self):
        r = rec.build_record(INV, ITEMS, "quick", "Debian")
        self.assertIn("registry.internal.example.test/team/app:1.2", r["inventory"]["images"])

    def test_the_inventory_and_the_items_come_through(self):
        r = rec.build_record(INV, ITEMS, "quick", "Debian")
        self.assertEqual(r["inventory"]["packages"]["nginx"], "1.26.3-1"); self.assertEqual(r["inventory"]["host"]["model"], "Synth 1000")
        self.assertEqual((r["items"][0]["cve"], r["items"][0]["priority"], r["items"][0]["installed"]), ("CVE-2030-0001", "fix first", ["nginx"]))
        self.assertEqual((r["schema"], r["os"], r["cut"]), (2, "Debian", 0))

    def test_a_field_added_to_the_record_fails_and_names_the_field(self):
        for edit, name in ((lambda r: r.update(hostname="x"), "hostname"), (lambda r: r["inventory"].update(posture={}), "posture"),
                           (lambda r: r["inventory"]["host"].update(serial="x"), "serial"), (lambda r: r["items"][0].update(path="x"), "path"),
                           (lambda r: r["inventory"]["imageDetails"]["redis:alpine"].update(env="x"), "env")):
            r = rec.build_record(INV, ITEMS, "quick", "Debian")
            edit(r)
            with self.assertRaisesRegex(ValueError, name):
                rec.check_record(r)

    def test_a_mac_or_a_path_that_got_into_a_value_fails(self):
        r = rec.build_record(INV, ITEMS, "quick", "Debian")
        r["inventory"]["os"] = "Ubuntu 00:00:5E:00:53:01"
        with self.assertRaisesRegex(ValueError, "MAC"):
            rec.check_record(r)
        r = rec.build_record(INV, ITEMS, "quick", "Debian")
        r["inventory"]["kernel"] = "see /home/canary-user-91/x"
        with self.assertRaisesRegex(ValueError, "path"):
            rec.check_record(r)

    def test_over_the_cap_the_record_keeps_what_the_items_name_and_says_how_much_it_left_out(self):
        big = {**INV, "packages": {f"pkg{i}": "1.0" for i in range(4000)} | {"nginx": "1.26.3-1"}}
        r = rec.build_record(big, ITEMS, "quick", "Debian", max_bytes=20_000)
        self.assertEqual(list(r["inventory"]["packages"]), ["nginx"]); self.assertEqual(r["cut"] >= 4000, True)
        self.assertEqual(r["inventory"]["host"]["model"], "Synth 1000")        # the hardware and OS fields stay
        self.assertEqual(rec.build_record(big, ITEMS, "quick", "Debian")["cut"], 0)           # under the real 1 MiB cap nothing is reduced

    def test_a_bad_id_or_verdict_is_dropped_from_the_items_and_the_os_is_a_closed_word(self):
        r = rec.build_record(INV, [{"cve": "nope", "verdict": "in-range"}, {"cve": "CVE-2030-0002", "verdict": "safe"}], "other", "Ubuntu (canary)")
        self.assertEqual((r["items"], r["level"], r["os"]), ([], "quick", "Other"))


if __name__ == "__main__":
    unittest.main()


class Preview(unittest.TestCase):
    def test_the_preview_of_a_record_counts_what_would_be_sent_and_names_the_exclusions(self):
        from lattice_scan import scan_report_flow as flow
        t = flow.preview(rec.build_record(INV, ITEMS, "quick", "Debian"))
        self.assertIn("2 package(s), 1 snap(s) and 2 container image name(s)", t); self.assertIn("1 finding(s)", t); self.assertIn("internal registry", t)
        self.assertIn("no hostname, address, port, path, user name or process list", t); self.assertIn("asked separately about the runtime posture", t)

    def test_d_shows_exactly_the_record_that_would_be_sent(self):
        import io
        from lattice_scan import scan_report_flow as flow
        r = rec.build_record(INV, ITEMS, "quick", "Debian"); out = io.StringIO(); a = iter(["d", ""])
        self.assertFalse(flow.offer(r, lambda p: next(a), out))
        text = out.getvalue(); self.assertEqual(json.loads(text[text.index("\n{") + 1:text.rindex("}") + 1]), r)
        for v in CANARY.values():
            self.assertNotIn(v, text)

    def test_a_project_inventory_holds_package_and_version_only(self):
        from lattice_scan import scan_report_flow as flow
        pi = flow.project_inventory([{"candidates": [{"declared": [{"name": "left-pad2", "version": "1.3.0", "file": "/home/canary-user-91/p/package-lock.json", "line": 4}]}]}])
        self.assertEqual(pi, {"os": "project manifests", "packages": {"left-pad2": "1.3.0"}})
