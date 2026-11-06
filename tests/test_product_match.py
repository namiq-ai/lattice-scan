# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""A product made of ordinary words does not match an unrelated installed package; real product matches stay. The package names are real Debian names
(they are public); the vendors and products are the CISA wording of the collisions seen on a real host."""
import sys, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli, report  # noqa: E402

PACKAGES = {n: "1.0" for n in ("gnome-user-docs", "armv8crc-support", "gnome-control-center", "media-player-info", "libhtml-form-perl", "libre2-11", "libbrotli1",
                               "bind9-dnsutils", "openssl", "docs-extra-tools", "python3", "apache2", "unattended-upgrades")}
INV = {"kernel": "7.0.0", "os": "x", "node": "", "restartRequired": False, "snaps": {"firefox": "1"}, "images": [], "host": {}, "packages": PACKAGES}


def match(vendor, product, inv=INV):
    return cli.candidate({"cve": "CVE-2099-0001", "vendor": vendor, "product": product, "title": "t"}, inv)


class Collisions(unittest.TestCase):
    def test_the_five_collisions_seen_on_a_real_host_no_longer_match(self):
        for vendor, product in (("ONLYOFFICE", "Docs Server"), ("BeyondTrust", "Remote Support"), ("Siemens", "Software Center"), ("Plex", "Media Server"),
                                ("Unknown", "WP Libre Form")):
            with self.subTest(product):
                self.assertIsNone(match(vendor, product))

    def test_real_matches_stay(self):
        self.assertIn("libbrotli1", match("Google", "Brotli")[0])
        self.assertIn("bind9-dnsutils", match("ISC", "BIND")[0])
        self.assertIn("openssl", match("OpenSSL", "OpenSSL")[0])
        self.assertIn("apache2", match("Apache", "Apache2")[0])
        self.assertIn("snap firefox", match("Mozilla", "Firefox")[0])

    def test_an_ordinary_word_product_matches_when_the_vendor_is_installed_too(self):
        inv = dict(INV, packages=dict(PACKAGES, **{"onlyoffice-documentserver": "8.0"}))
        self.assertIsNotNone(match("ONLYOFFICE", "Docs Server", inv))

    def test_two_words_in_two_different_packages_do_not_match_without_the_vendor(self):
        inv = dict(INV, packages={"zebra-ssl": "1", "quark-tools": "1"})
        self.assertIsNone(match("Nobody", "Zebra Quark", inv))
        inv["packages"]["zebra-quark-server"] = "2"                       # both words in one package: a match
        self.assertIn("zebra-quark-server", match("Nobody", "Zebra Quark", inv)[0])

    def test_two_words_in_two_packages_match_when_the_vendor_is_installed(self):
        inv = dict(INV, packages={"zebra": "1", "quark": "1", "acmeco-agent": "1"})
        self.assertIsNotNone(match("Acmeco", "Zebra Quark", inv))

    def test_an_ordinary_word_inside_an_opened_image_needs_the_vendor_there(self):
        inv = dict(INV, imageDetails={"a:1": {"name": "a", "os": "alpine", "packages": {"docs": "1.0"}}})
        self.assertIsNone(match("ONLYOFFICE", "Docs Server", inv))
        inv["imageDetails"]["a:1"]["packages"]["onlyoffice"] = "8"
        self.assertIsNotNone(match("ONLYOFFICE", "Docs Server", inv))


class Width(unittest.TestCase):
    def test_the_table_may_use_160_columns(self):
        with mock.patch.object(report.shutil, "get_terminal_size", lambda d=None: mock.Mock(columns=200)):
            self.assertEqual(report.width_for(None), 160)
        with mock.patch.object(report.shutil, "get_terminal_size", lambda d=None: mock.Mock(columns=130)):
            self.assertEqual(report.width_for(None), 130)
        with mock.patch.object(report.shutil, "get_terminal_size", lambda d=None: mock.Mock(columns=40)):
            self.assertEqual(report.width_for(None), 72)


if __name__ == "__main__":
    unittest.main()
