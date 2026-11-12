# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The inventory records which source package each binary package was built from, so a binary such as examplessh-client can join a flaw listed
against its source examplessh. Invented packages only."""
import os, struct, sys, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli, lattice_identity as li  # noqa: E402
import test_image_inventory as img  # noqa: E402


def rpm_header_with_source(name, version, release, srpm):
    data, idx = b"", []
    for tag, val in ((1000, name), (1001, version), (1002, release), (1044, srpm)):
        idx.append((tag, 6, len(data), 1))
        data += val.encode() + b"\0"
    return struct.pack(">II", len(idx), len(data)) + b"".join(struct.pack(">IIII", *i) for i in idx) + data


class Parsing(unittest.TestCase):
    def test_source_of_rpm(self):
        self.assertEqual(cli.source_of_rpm("examplessh-9.3p1-1.el9.src.rpm"), "examplessh")
        self.assertEqual(cli.source_of_rpm("example-lib-ng-2.0-3.fc40.src.rpm"), "example-lib-ng")
        self.assertEqual(cli.source_of_rpm("(none)"), "")
        self.assertEqual(cli.source_of_rpm(""), "")

    def test_dpkg_status_source_field_keeps_only_differing_names(self):
        text = ("Package: examplessh-client\nStatus: install ok installed\nSource: examplessh (1:9.2p1-2)\nVersion: 1:9.2p1-2+b1\n\n"
                "Package: examplessh\nStatus: install ok installed\nSource: examplessh\nVersion: 1\n\n"
                "Package: zlib1g\nStatus: install ok installed\nVersion: 1:1.3.dfsg-1\n")
        self.assertEqual(cli.package_sources(text, "dpkg"), {"examplessh-client": "examplessh"})

    def test_apk_origin(self):
        self.assertEqual(cli.package_sources("P:libexamplessl3\nV:3.3.2-r0\no:examplessl\n\nP:musl\nV:1.2.5-r8\no:musl\n", "apk"), {"libexamplessl3": "examplessl"})

    def test_rpm_header_source_tag(self):
        self.assertEqual(cli.parse_rpm_header(rpm_header_with_source("examplessh-clients", "9.3p1", "1.el9", "examplessh-9.3p1-1.el9.src.rpm"))["source"], "examplessh")


class HostCollection(unittest.TestCase):
    def collect(self, outputs):
        with mock.patch.object(cli, "run", lambda cmd: outputs.get(cmd[0], "")):
            os.environ.pop("LATTICE_SCAN_INVENTORY", None)
            return cli.inventory()

    def test_dpkg_query_reads_the_source_column(self):
        inv = self.collect({"dpkg-query": "examplessh-client\t1:9.2p1-2\texamplessh\nacl\t2.3\tacl\n"})
        self.assertEqual(inv["packages"], {"examplessh-client": "1:9.2p1-2", "acl": "2.3"})
        self.assertEqual(inv["sources"], {"examplessh-client": "examplessh"})

    def test_rpm_reads_sourcerpm(self):
        inv = self.collect({"rpm": "examplessh-clients\t9.3p1-1.el9\texamplessh-9.3p1-1.el9.src.rpm\nbash\t5.2-3\tbash-5.2-3.src.rpm\n"})
        self.assertEqual(inv["sources"], {"examplessh-clients": "examplessh"})

    def test_sources_do_not_change_the_inventory_hash(self):
        a = self.collect({"dpkg-query": "examplessh-client\t1\texamplessh\n"})["hash"]
        b = self.collect({"dpkg-query": "examplessh-client\t1\n"})["hash"]
        self.assertEqual(a, b)

    def test_the_source_is_the_identity_that_joins(self):
        inv = self.collect({"dpkg-query": "examplessh-client\t1:9.2p1-2\texamplessh\n"})
        arts = li.host_artefacts({"manager": inv["manager"], "packages": inv["packages"], "sources": inv["sources"]})
        self.assertEqual([a.pid for a in arts if a.source == "host-packages"], ["deb:examplessh"])


class Images(unittest.TestCase):
    def test_rpm_sqlite_sources(self):
        import sqlite3, tempfile
        f = tempfile.mktemp(suffix=".sqlite")
        con = sqlite3.connect(f)
        con.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)")
        con.execute("INSERT INTO Packages (blob) VALUES (?)", (rpm_header_with_source("examplessh-clients", "9.3p1", "1.el9", "examplessh-9.3p1-1.el9.src.rpm"),))
        con.execute("INSERT INTO Packages (blob) VALUES (?)", (img.rpm_header("bash", "5.2", "3"),))
        con.commit(); con.close()
        db = Path(f).read_bytes(); os.unlink(f)
        self.assertEqual(cli.rpm_sources(db), {"examplessh-clients": "examplessh"})
        self.assertEqual(cli.parse_rpm_sqlite(db), {"examplessh-clients": "9.3p1-1.el9", "bash": "5.2-3"})


if __name__ == "__main__":
    unittest.main()
