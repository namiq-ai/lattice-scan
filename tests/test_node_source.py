# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""--node reads globally installed npm packages and their nested dependencies from package.json only, opens no connection, and joins on npm:NAME.
Invented packages, reserved CVE ids, temporary folders only."""
import json, socket, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli, nodeenv, lattice_identity as li  # noqa: E402


def pkg(folder: Path, name: str, version: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "package.json").write_text(json.dumps({"name": name, "version": version, "scripts": {"postinstall": "never run"}}))
    return folder


class Reading(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        root = self.home / ".npm-global" / "lib" / "node_modules"
        cli_pkg = pkg(root / "example-cli", "example-cli", "3.1.0")
        pkg(cli_pkg / "node_modules" / "examplezip", "examplezip", "1.1.0")
        pkg(cli_pkg / "node_modules" / "@exampleorg" / "parser", "@exampleorg/parser", "2.0.0")
        pkg(root / "other" / "node_modules" / "examplezip", "examplezip", "1.2.1")
        pkg(root / "other", "other", "1.0.0")
        self.root = str(root)
        p = mock.patch.object(nodeenv, "global_roots", lambda home=None: [self.root])
        p.start(); self.addCleanup(p.stop)

    def test_globals_and_nested_dependencies_are_read_with_every_version(self):
        got = nodeenv.collect(self.home)
        self.assertEqual(got, {self.root: {"example-cli": "3.1.0", "examplezip": "1.1.0|1.2.1", "@exampleorg/parser": "2.0.0", "other": "1.0.0"}})

    def test_no_connection_is_opened(self):
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network")):
            self.assertEqual(len(nodeenv.collect(self.home)[self.root]), 4)

    def test_each_installed_version_joins_on_its_npm_identity(self):
        inv = {"kernel": "6.1", "os": "x", "manager": "dpkg", "node": "", "packages": {}, "sources": {}, "snaps": {}, "images": [], "imageDetails": {},
               "nodeGlobal": nodeenv.collect(self.home)}
        rows = {"CVE-2099-0021": li.Row("CVE-2099-0021", ("npm:examplezip",), None, "osv-npm")}
        e = {"cve": "CVE-2099-0021", "vendor": "Exampleco", "product": "Examplezip", "title": ""}
        with mock.patch.object(cli, "IDENTITY", {"rows": rows, "aliases": {}, "note": ""}), mock.patch.object(cli, "JOINED", {}):
            why, installed, vers = cli.candidate(e, inv)
            joined = cli.JOINED["CVE-2099-0021"]
        self.assertEqual(sorted(installed), ["examplezip (npm global) 1.1.0", "examplezip (npm global) 1.2.1"])
        self.assertEqual(sorted(cli.verdict_item(a, inv)["version"] for a in joined), ["1.1.0", "1.2.1"])

    def test_a_scoped_package_is_matched_but_never_sent(self):
        a = li.Artefact("npm:@exampleorg/parser", "2.0.0", "semver", "npm", "node", "x")
        self.assertIsNone(cli.verdict_item(a, {}))   # the item rules allow no @ or /: it keeps the upstream comparison


if __name__ == "__main__":
    unittest.main()
