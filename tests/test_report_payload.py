# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The report payload holds six fields and nothing else (OCO-6052, ADR-LATTICE-SCAN-REPORT-001 D1). Synthetic hosts only; RFC 5737 and RFC 7042 values."""
import json, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import scan_report as sr  # noqa: E402

HOST = {"hostname": "canary-host-7f3a.example.test", "address": "198.51.100.7", "port": 2222, "mac": "00:00:5E:00:53:01", "user": "canary-user-91", "path": "/home/canary-user-91/app/nginx.conf",
        "image": "registry.example.test/team/redis:alpine", "kernel": "7.0.0-41-canary", "codename": "canarysid", "password": "canary-secret-xx"}


def cand(cve="CVE-2030-0001", **kw):
    c = {"cve": cve, "product": "nginx", "version": "1.26.3-1", "verdict": "in-range", "priority": "fix first", **HOST}
    c.update(kw)
    return c


class Payload(unittest.TestCase):
    def test_none_of_the_host_fields_appears_in_any_field_or_value(self):
        p = sr.build_payload([cand(), cand("CVE-2030-0002", product="openssl", version="3.4.1-1ubuntu2")], "quick", "Debian")
        text = json.dumps(p)
        for k, v in HOST.items():
            self.assertNotIn(str(v), text, f"{k} reached the payload")
            self.assertNotIn(k, p["items"][0], f"{k} became a payload field")

    def test_only_the_six_fields_and_the_structure_keys(self):
        p = sr.build_payload([cand()], "deep", "Alpine")
        self.assertEqual(set(p), set(sr.TOP_FIELDS))
        self.assertEqual(set(p["items"][0]), set(sr.ITEM_FIELDS))
        self.assertEqual((p["level"], p["os"], p["items"][0]["verdict"]), ("deep", "Alpine", "in-range"))

    def test_a_distribution_string_with_a_build_host_keeps_only_the_upstream_version(self):
        for raw, want in (("3.0.2-0ubuntu1.12+build.canary-host.example.test", "3.0.2"), ("1:9.18.18-0ubuntu0.22.04.2", "9.18.18"), ("1.1.1f-1ubuntu2", "1.1.1f"),
                          ("8.2p1-4ubuntu0.5", "8.2p1"), ("2.4.52", "2.4.52"), ("10.0p1-5", "10.0p1"), ("", ""), ("canary-host-only", "")):
            self.assertEqual(sr.upstream_version(raw), want, raw)
        self.assertNotIn("canary-host", json.dumps(sr.build_payload([cand(version="3.0.2-0ubuntu1+build.canary-host.example.test")], "quick", "Debian")))

    def test_a_field_added_to_the_payload_fails_and_names_the_field(self):
        p = sr.build_payload([cand()], "quick", "Debian")
        p["hostname"] = "canary-host-7f3a"
        with self.assertRaisesRegex(ValueError, "hostname"):
            sr.check_payload(p)
        q = sr.build_payload([cand()], "quick", "Debian")
        q["items"][0]["path"] = "/etc/x"
        with self.assertRaisesRegex(ValueError, "path"):
            sr.check_payload(q)

    def test_the_os_family_is_one_word_from_a_closed_list(self):
        self.assertEqual(sr.os_family("ubuntu", "debian"), "Debian")
        self.assertEqual(sr.os_family("alpine"), "Alpine")
        self.assertEqual(sr.os_family("rocky", "rhel centos fedora"), "RedHat")
        self.assertEqual(sr.os_family(system="Windows"), "Windows")
        self.assertEqual(sr.os_family(system="Darwin"), "macOS")
        self.assertEqual(sr.os_family("plan9"), "Other")
        self.assertEqual(sr.build_payload([cand()], "quick", "Ubuntu 26.04 LTS (canary)")["os"], "Other")      # not on the list: never passed through

    def test_a_bad_id_or_verdict_is_dropped_and_markup_in_a_product_name_is_removed(self):
        p = sr.build_payload([cand("not-a-cve"), cand("CVE-2030-0003", verdict="vulnerable"), cand("CVE-2030-0004", product="ng<script>inx`x`")], "quick", "Debian")
        self.assertEqual([i["cve"] for i in p["items"]], ["CVE-2030-0004"])
        self.assertEqual(p["items"][0]["product"], "ngscriptinxx")

    def test_the_same_product_and_id_is_listed_once(self):
        self.assertEqual(len(sr.build_payload([cand(), cand()], "quick", "Debian")["items"]), 1)


if __name__ == "__main__":
    unittest.main()
