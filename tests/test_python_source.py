# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""--python reads pip/uv/conda installs from their metadata files, leaves distribution packages to dpkg/rpm, opens no connection, and joins on pypi:NAME.
Invented package names, reserved CVE ids, temporary folders only."""
import os, socket, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import cli, pyenv, lattice_identity as li  # noqa: E402


def dist(site: Path, name: str, version: str, installer="pip", folder: str = "") -> None:
    d = site / (folder or f"{name.replace('-', '_')}-{version}.dist-info")
    d.mkdir(parents=True)
    (d / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: test\n\nbody\n")
    if installer is not None:
        (d / "INSTALLER").write_text(installer + "\n")


class Reading(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())

    def test_a_virtual_environment_in_home_is_found_with_its_packages(self):
        venv = self.home / "work" / "env1"
        (venv).mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
        site = venv / "lib" / "python3.12" / "site-packages"
        dist(site, "Example_Brotli", "1.2.0")
        found = pyenv.collect(home=self.home)
        self.assertEqual(found, {str(site): {"Example_Brotli": "1.2.0"}})
        self.assertEqual(pyenv.label(str(site), self.home), "~/work/env1")

    def test_a_distribution_package_under_usr_lib_is_left_to_the_package_manager(self):
        site = self.home / "s"
        dist(site, "exampledeb", "1.0", installer="debian")
        with mock.patch.object(pyenv, "distro_owned", lambda s, i: (i / "INSTALLER").read_text().strip() == "debian"):
            self.assertEqual(pyenv.read_site(str(site)), {})
        self.assertTrue(pyenv.distro_owned("/usr/lib/python3/dist-packages", site / "exampledeb-1.0.dist-info"))
        self.assertFalse(pyenv.distro_owned("/usr/local/lib/python3.12/site-packages", site / "exampledeb-1.0.dist-info"))

    def test_an_egg_info_and_a_folder_without_metadata_are_read(self):
        site = self.home / "lib" / "site-packages"
        (site / "exampleegg-0.9.egg-info").mkdir(parents=True)
        (site / "exampleegg-0.9.egg-info" / "PKG-INFO").write_text("Name: exampleegg\nVersion: 0.9\n")
        (site / "examplebare-2.1.dist-info").mkdir()
        self.assertEqual(pyenv.read_site(str(site)), {"exampleegg": "0.9", "examplebare": "2.1"})

    def test_hidden_folders_and_depth_are_respected(self):
        for p in (self.home / ".hidden" / "venv", self.home / "a" / "b" / "c" / "d"):
            p.mkdir(parents=True)
            (p / "pyvenv.cfg").write_text("")
        self.assertEqual(pyenv.venv_site_dirs(self.home), [])

    def test_no_connection_is_opened(self):
        venv = self.home / "env"
        venv.mkdir()
        (venv / "pyvenv.cfg").write_text("")
        dist(venv / "lib" / "python3.11" / "site-packages", "examplepkg", "1.0")
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network")), mock.patch.object(socket, "create_connection", side_effect=AssertionError("network")):
            self.assertEqual(len(pyenv.collect(home=self.home)), 1)


class Joining(unittest.TestCase):
    def test_a_pip_installed_wheel_joins_its_pypi_identity_and_is_a_match(self):
        inv = {"kernel": "6.1", "os": "Example OS", "manager": "dpkg", "node": "", "packages": {}, "sources": {}, "snaps": {}, "images": [], "imageDetails": {},
               "python": {str(Path.home() / "env1" / "lib" / "python3.12" / "site-packages"): {"Example_Brotli": "1.2.0"}}}
        rows = {"CVE-2099-0007": li.Row("CVE-2099-0007", ("pypi:example-brotli",), None, "osv-pypi")}
        e = {"cve": "CVE-2099-0007", "vendor": "Exampleco", "product": "Examplebrotli", "title": ""}
        with mock.patch.object(cli, "IDENTITY", {"rows": rows, "aliases": {}, "note": ""}):
            why, installed, vers = cli.candidate(e, inv)
        self.assertEqual((installed, vers, e["matchBasis"]), (["Example_Brotli (python ~/env1) 1.2.0"], ["1.2.0"], "identity"))

    def test_without_the_flag_nothing_is_read_and_the_hash_is_unchanged(self):
        real = cli.run
        cli.run = lambda cmd: {"dpkg-query": "acl\t2.3\tacl\n"}.get(cmd[0], "")
        try:
            os.environ.pop("LATTICE_SCAN_INVENTORY", None)
            with mock.patch.dict(os.environ, {"LATTICE_SCAN_PYTHON": ""}):
                a = cli.inventory()
            with mock.patch.dict(os.environ, {"LATTICE_SCAN_PYTHON": "1"}), mock.patch.object(pyenv, "collect", return_value={}):
                b = cli.inventory()
        finally:
            cli.run = real
        self.assertNotIn("python", a)
        self.assertEqual(a["hash"], b["hash"])


if __name__ == "__main__":
    unittest.main()
