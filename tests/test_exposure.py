# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""A finding says what the machine does with the matched software: listens on all interfaces, loopback only, runs as a service, or is only installed. The label
is a fact from the local listeners and services; it never says "reachable from the internet". Invented products and reserved ids only."""
import json, os, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import cli, exposure  # noqa: E402
from test_agent_entry import Entry, EntryBase, exp, feed  # noqa: E402

PKGS = {"libexamplelib2": "2.17.1-1", "acl": "2.3"}


def post(ports=(), units=(), scope="root"):
    return {"scope": scope, "level": "quick", "ports": list(ports), "services": {"available": True, "units": list(units)}}


def port(bind, package, n=8080, addr="0.0.0.0"):
    return {"proto": "tcp", "addr": addr, "port": n, "bind": bind, "package": package, "process": "p", "where": ""}


class Label(unittest.TestCase):
    def lab(self, p, installed=("libexamplelib2 2.17.1-1",)):
        return exposure.label(list(installed), PKGS, p)

    def test_listener_on_all_interfaces_names_address_port_and_owner(self):
        r = self.lab(post([port("all interfaces", "libexamplelib2")]))
        self.assertEqual(r["class"], "all")
        self.assertEqual(r["text"], "listens on all interfaces: 0.0.0.0:8080, owned by libexamplelib2")

    def test_without_root_the_firewall_is_said_not_read_and_internet_is_never_claimed(self):
        r = self.lab(post([port("all interfaces", "libexamplelib2")], scope="user"))
        self.assertIn("firewall rules not read: needs root", r["text"])
        for c in (self.lab(post([port("all interfaces", "libexamplelib2")])), r):
            self.assertNotIn("internet", c["text"].lower())

    def test_loopback_only(self):
        r = self.lab(post([port("loopback only", "libexamplelib2", addr="127.0.0.1")]))
        self.assertEqual((r["class"], r["text"]), ("loopback", "listens on loopback only"))

    def test_a_running_service_without_a_listener(self):
        r = self.lab(post(units=[{"unit": "example.service", "package": "libexamplelib2"}]))
        self.assertEqual(r["class"], "service"); self.assertIn("example.service", r["text"])

    def test_installed_with_nothing_running(self):
        r = self.lab(post([port("all interfaces", "acl")]))   # another package's listener does not count
        self.assertEqual(r["class"], "installed")

    def test_image_only_match_and_unreadable_posture(self):
        self.assertEqual(self.lab(None, ("container image redis",))["class"], "image")
        self.assertEqual(self.lab(None)["class"], "unknown")
        self.assertIn("not read", self.lab(None)["text"])

    def test_more_exposed_sorts_first(self):
        order = [exposure.sort_key({"class": c}) for c in ("all", "service", "loopback", "installed", "image", "unknown")]
        self.assertEqual(order, sorted(order))


class HostRun(EntryBase):
    def setUp(self):
        super().setUp()
        cli._POSTURE.clear()
        self.pf = Path(self.tmp.name + ".posture.json")
        os.environ["LATTICE_SCAN_POSTURE"] = str(self.pf)
        self.addCleanup(lambda: (os.environ.pop("LATTICE_SCAN_POSTURE", None), cli._POSTURE.clear(), self.pf.unlink(missing_ok=True)))
        Entry.feed = feed([exp("CVE-2099-0001")])

    def with_post(self, p):
        self.pf.write_text(json.dumps(p))

    def test_a_candidate_prints_its_exposure_label(self):
        self.with_post(post([port("all interfaces", "libexamplelib2")]))
        rc, out, err = self.run_cli("--discover")
        self.assertEqual(rc, 0, err)
        self.assertIn("exposure: listens on all interfaces: 0.0.0.0:8080, owned by libexamplelib2", out)

    def test_exposed_lists_only_listening_or_running_software(self):
        self.with_post(post())
        rc, out, _ = self.run_cli("--discover", "--exposed")
        self.assertEqual(rc, 0)
        self.assertIn("--exposed: 1 candidate(s) not listed", out)
        self.assertNotIn("exposure:", out)
        cli.OUT.joinpath("findings.jsonl").unlink(missing_ok=True)   # the first run recorded it; start clean
        for f in cli.OUT.glob("*.json*"):
            f.unlink()
        cli._POSTURE.clear()
        self.with_post(post([port("all interfaces", "libexamplelib2")]))
        rc, out, _ = self.run_cli("--discover", "--exposed")
        self.assertIn("exposure: listens on all interfaces", out)

    def test_fail_on_exposed_needs_in_range_and_a_wide_listener(self):
        self.with_post(post([port("all interfaces", "libexamplelib2")]))
        Entry.feed = feed([exp("CVE-2099-0001")])
        rc, _, err = self.run_cli("--discover", "--fail-on", "exposed")
        self.assertIn(rc, (0, 1), err)
        self.assertEqual(cli.fail_on_exit("exposed", [{"versionCheck": {"verdict": "in-range"}, "exposure": {"class": "all"}}]), 1)
        self.assertEqual(cli.fail_on_exit("exposed", [{"versionCheck": {"verdict": "in-range"}, "exposure": {"class": "loopback"}}]), 0)
        self.assertEqual(cli.fail_on_exit("exposed", [{"versionCheck": {"verdict": "outside-range"}, "exposure": {"class": "all"}}]), 0)


if __name__ == "__main__":
    unittest.main()
