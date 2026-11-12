# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Files and images that someone else controls cannot crash the scan or write to the terminal."""
import io, json, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import tmpfold  # noqa: E402  (one temp root per test run, removed at exit)
from lattice_scan import cli, manifests  # noqa: E402
from test_image_inventory import FakeDocker, rpm_sqlite, tar_of, IMAGES  # noqa: E402

POM = """<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>"""


class Manifests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tmpfold.mkdtemp())
        manifests.SKIPPED.clear()

    def test_a_pom_with_entities_is_skipped_and_named(self):
        (self.d / "pom.xml").write_text('<?xml version="1.0"?><!DOCTYPE p [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>' + POM)
        self.assertEqual(manifests.pom_xml(self.d / "pom.xml", self.d), [])
        self.assertTrue(any("DOCTYPE or entities" in x for x in manifests.SKIPPED))

    def test_a_plain_pom_still_reads(self):
        (self.d / "pom.xml").write_text(POM)
        self.assertEqual([c.name for c in manifests.pom_xml(self.d / "pom.xml", self.d)], ["g:a"])
        self.assertEqual(manifests.SKIPPED, [])

    def test_a_huge_manifest_is_not_read_and_is_named(self):
        (self.d / "requirements.txt").write_text("flask==1.0\n")
        with mock.patch.object(manifests, "MAX_BYTES", 5):
            self.assertEqual(manifests._text(self.d / "requirements.txt"), "")
        self.assertTrue(any("larger than" in x for x in manifests.SKIPPED))
        self.assertEqual(manifests._text(self.d / "requirements.txt"), "flask==1.0\n")

    def test_a_missing_file_reads_as_empty(self):
        self.assertEqual(manifests._text(self.d / "nope"), "")


class Images(unittest.TestCase):
    def test_control_characters_from_an_image_never_reach_the_screen(self):
        evil = dict(IMAGES["redis:7-alpine"])
        evil["Config"] = {"Env": [], "Labels": {"org.opencontainers.image.title": "t\x1b]0;pwned\x07itle"}}
        evil["files"] = {"etc/os-release": 'ID=alpine\nPRETTY_NAME="Alp\x1b[2Jine"\n', "lib/apk/db/installed": "P:mu\x1b[31msl\nV:1.0\x1b[0m\n"}
        fd = FakeDocker()
        with mock.patch.dict(IMAGES, {"redis:7-alpine": evil}), mock.patch.object(cli, "run", fd.run), \
                mock.patch.object(cli, "run_bytes", fd.run_bytes), mock.patch.object(cli.shutil, "which", lambda c: "/x/docker"), \
                mock.patch.dict("os.environ", {"LATTICE_SCAN_LEVEL": "quick", "LATTICE_SCAN_IMAGES_LANG": "off"}):
            d = cli.image_details(["redis:7-alpine"])
        self.assertNotIn("\x1b", json.dumps(d, ensure_ascii=False))
        self.assertNotIn("\x07", json.dumps(d, ensure_ascii=False))
        self.assertIn("mu?[31msl", json.dumps(d))

    def test_an_image_reference_starting_with_a_dash_is_never_passed_to_docker(self):
        fd = FakeDocker()
        with mock.patch.object(cli, "run", fd.run), mock.patch.object(cli, "run_bytes", fd.run_bytes), mock.patch.object(cli.shutil, "which", lambda c: "/x/docker"):
            cli.image_details(["--privileged", "redis:7-alpine"])
        self.assertFalse([c for c in fd.calls if "--privileged" in c])

    def test_the_rpm_database_is_read_query_only_with_a_row_limit(self):
        seen = []
        import sqlite3
        orig = sqlite3.connect

        class Spy:
            def __init__(self, con): self.con = con
            def execute(self, sql, *a):
                seen.append(sql)
                return self.con.execute(sql, *a)
            def close(self): self.con.close()
        db = rpm_sqlite([("bash", "5", "1")])
        with mock.patch.object(sqlite3, "connect", lambda *a, **k: Spy(orig(*a, **k))):
            cli.parse_rpm_sqlite(db)
        self.assertIn("PRAGMA trusted_schema=OFF", seen)
        self.assertIn("PRAGMA query_only=ON", seen)
        self.assertTrue(any("LIMIT 50000" in s for s in seen))

    def test_firmware_strings_are_scrubbed(self):
        real = Path.read_text

        def fake(self, *a, **k):
            if str(self).endswith("sys_vendor"):
                return "Evil\x1b[31mcorp\n"
            if str(self).startswith("/sys/class/dmi/id/"):
                raise OSError
            return real(self, *a, **k)
        with mock.patch.object(Path, "read_text", fake), mock.patch.object(cli, "run", lambda c: ""):
            self.assertNotIn("\x1b", cli.hardware()["manufacturer"])

    def test_scrub_reaches_keys_values_and_lists(self):
        self.assertEqual(cli.scrub({"a\x1b": ["b\x07", {"c": "d\x00e"}]}), {"a?": ["b?", {"c": "d?e"}]})


if __name__ == "__main__":
    unittest.main()
