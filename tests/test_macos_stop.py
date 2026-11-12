"""The parts of the host scan that cannot read a Mac yet (--discover --all, posture, inventory --share) stop with a plain message (exit 3) instead of reporting 'no match'."""
import io
import os
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_agent_entry import EntryBase   # noqa: E402
from lattice_scan import cli   # noqa: E402


class MacosStop(EntryBase):
    def darwin(self):
        cli.inventory = self.saved[5]   # the base class swaps in a stub; these tests need the real gate (tearDown puts the stub back)
        p = mock.patch.object(cli.sys, "platform", "darwin")
        p.start(); self.addCleanup(p.stop)
        e = mock.patch.dict(os.environ); e.start(); self.addCleanup(e.stop)
        os.environ.pop("LATTICE_SCAN_INVENTORY", None); os.environ.pop("HOST_SCAN_INVENTORY", None)

    def test_inventory_stops_with_exit_3_and_says_why(self):
        self.darwin()
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            cli.stop_on_macos()
        self.assertEqual(cm.exception.code, 3)
        self.assertIn("runs macOS", err.getvalue())
        self.assertIn("would not mean safe", err.getvalue())
        self.assertIn("project <folder>", err.getvalue())

    def test_every_host_command_stops_and_never_prints_a_result(self):
        self.darwin()
        for argv in (("--discover", "--all", "--yes"), ("posture",), ("inventory", "--share")):
            with self.subTest(argv=argv):
                out, err = io.StringIO(), io.StringIO()
                sys.argv = ["lattice-scan", *argv]
                with redirect_stderr(err), mock.patch.object(sys, "stdout", out), self.assertRaises(SystemExit) as cm:
                    cli.main()
                self.assertEqual(cm.exception.code, 3)
                self.assertIn("runs macOS", err.getvalue())
                self.assertNotIn("no match", out.getvalue().lower())

    def test_commands_that_do_not_read_the_host_still_work(self):
        self.darwin()
        rc, out, err = self.run_cli("enrich", "--cve", "CVE-2099-0001")
        self.assertEqual(rc, 0, err)
        self.assertNotIn("runs macOS", err)

    def test_a_fixed_inventory_file_is_not_stopped(self):
        # tests and agents that hand the tool an inventory read nothing from the machine, so nothing is missed
        self.darwin()
        f = Path(self.tmp.name) / "inv.json"
        f.write_text('{"kernel": "", "os": "x", "packages": {}, "snaps": {}, "images": []}')
        with mock.patch.dict(os.environ, {"LATTICE_SCAN_INVENTORY": str(f)}):
            self.assertEqual(cli.inventory()["os"], "x")

    def test_a_mac_kernel_number_is_never_compared_with_linux_kernel_entries(self):
        entry = {"cve": "CVE-2099-0009", "vendor": "Linux", "product": "Kernel", "title": "Linux Kernel Use-After-Free"}
        linux = {"kernel": "6.8.0", "packages": {}, "snaps": {}, "images": [], "os": "Ubuntu"}
        mac = dict(linux, kernel="24.3.0", family="macos")
        self.assertIsNotNone(cli.candidate(entry, linux))
        self.assertIsNone(cli.candidate(entry, mac))


if __name__ == "__main__":
    unittest.main()
