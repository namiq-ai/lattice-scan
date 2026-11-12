# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The optional posture block holds only declared fields and none of the values the posture result carries (an address, a path, a pid, a container name, a rule). Synthetic data only."""
import json, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import scan_record as rec  # noqa: E402

CANARIES = ("192.0.2.77", "2001:db8::77", "canaryuser", "/home/", "hunter2", "canary-registry.example", "00:00:5e:00:53:af", "ALLOW 203.0.113.9", "pid", "listenaddress")
POSTURE = {
    "scope": "user", "level": "deep", "euid": 1000, "packageManager": "dpkg",
    "ports": [{"proto": "tcp", "addr": "192.0.2.77", "port": 3000, "bind": "all interfaces", "process": "next-server", "pid": 4242, "package": None, "where": "", "exe": "/home/canaryuser/app/node"},
              {"proto": "tcp6", "addr": "2001:db8::77", "port": 9000, "bind": "all interfaces", "process": "docker-proxy", "pid": 7, "package": None,
               "where": "container canary-registry.example/auth:1", "exe": "/usr/bin/docker-proxy"},
              {"proto": "udp", "addr": "127.0.0.1", "port": 5353, "bind": "loopback only", "process": "avahi-daemon", "pid": 9, "package": "avahi-daemon", "where": "", "exe": "/usr/sbin/avahi-daemon"}],
    "firewall": {"readable": False, "managers": [{"name": "ufw", "enabled": True, "defaultIncoming": "deny", "rules": 20, "ruleText": "ALLOW 203.0.113.9"}], "kernelTables": ["filter"],
                 "iptables": {"rules": 118, "inputPolicy": "drop", "text": "-A INPUT -s 203.0.113.9"}},
    "ssh": {"installed": True, "files": ["/etc/ssh/sshd_config"], "settings": {"passwordauthentication": "yes", "permitrootlogin": "no", "port": "22", "listenaddress": "192.0.2.10"}},
    "services": {"units": [{"name": "canaryuser-backup.service"}]},
    "processes": {"readable": 400, "unreadable": 2, "flagged": [
        {"name": "cloudflared", "exe": "/home/canaryuser/.local/bin/cloudflared", "reasons": ["no package owns its program (under a home folder)"], "kind": "attention", "pids": [4760], "package": None, "where": "",
         "outbound": [{"remote": "192.0.2.77", "port": 443}]},
        {"name": "chrome", "exe": "/opt/google/chrome/chrome", "reasons": ["a package update replaced its program"], "kind": "stale", "pids": [1], "package": "google-chrome-stable", "where": ""}]},
    "persistence": {"ldPreload": [], "extraUid0Users": [], "cronFilesNoPackage": ["/etc/cron.d/canaryuser"], "timers": 31, "suidNoPackage": []},
    "unreadable": ["firewall rules (needs root)", "the executable of 2 process(es) of other users"],
    "localSecrets": [{"kind": "api key", "where": "shell history"}],
    "observations": [{"text": "password hunter2 on a command line"}],
}


class PostureBlock(unittest.TestCase):
    def test_no_canary_value_survives(self):
        block = rec.posture_block(POSTURE)
        text = json.dumps(block)
        for c in CANARIES:
            self.assertNotIn(c, text, c)

    def test_the_fields_are_the_declared_ones(self):
        b = rec.posture_block(POSTURE)
        self.assertEqual(set(b), set(rec.POSTURE_FIELDS))
        self.assertEqual(set(b["ports"][0]), set(rec.PORT_FIELDS))
        self.assertEqual(b["ports"][1]["where"], "container")
        self.assertEqual([p["bind"] for p in b["ports"]], ["all interfaces", "all interfaces", "loopback only"])
        self.assertEqual(b["ports"][0]["packaged"], False)
        self.assertEqual(b["ports"][2]["packaged"], True)
        self.assertEqual(b["firewall"], {"readable": False, "managers": [{"name": "ufw", "enabled": True, "defaultIncoming": "deny", "rules": 20}], "iptables": {"rules": 118, "inputPolicy": "drop"}})
        self.assertEqual(b["ssh"], {"installed": True, "passwordauthentication": "yes", "permitrootlogin": "no", "port": "22"})
        self.assertEqual(b["programs"], [{"name": "cloudflared", "location": "home", "kind": "attention"}])
        self.assertEqual(b["persistence"], {"ldPreload": 0, "extraUid0Users": 0, "cronFilesNoPackage": 1, "suidNoPackage": 0, "timers": 31})
        self.assertEqual((b["notRead"], b["secretsFound"], b["scope"], b["level"]), (2, 1, "user", "deep"))

    def test_quick_has_no_deep_parts(self):
        b = rec.posture_block({**POSTURE, "level": "quick"})
        self.assertNotIn("programs", b)
        self.assertNotIn("persistence", b)

    def test_an_undeclared_key_fails_naming_it(self):
        r = rec.build_record({}, [], "quick", "Debian", posture=POSTURE)
        for path, key in ((("posture",), "extra"), (("posture", "ports", 0), "addr"), (("posture", "firewall"), "rules"), (("posture", "ssh"), "files"),
                          (("posture", "programs", 0), "exe"), (("posture", "persistence"), "suid")):
            bad = json.loads(json.dumps(r))
            node = bad
            for k in path:
                node = node[k]
            node[key] = "x"
            with self.assertRaises(ValueError) as cm:
                rec.check_record(bad)
            self.assertIn(key, str(cm.exception), path)

    def test_a_value_that_looks_like_an_address_a_mac_or_a_path_is_refused(self):
        r = rec.build_record({}, [], "quick", "Debian", posture=POSTURE)
        for val in ("192.0.2.77", "2001:db8::1", "00:00:5e:00:53:af", "/home/x/app"):
            bad = json.loads(json.dumps(r))
            bad["posture"]["ports"][0]["process"] = val
            with self.assertRaises(ValueError):
                rec.check_record(bad)

    def test_without_a_yes_there_is_no_posture_key_and_with_one_the_block_is_in_the_record(self):
        self.assertNotIn("posture", rec.build_record({}, [], "quick", "Debian"))
        self.assertIn("posture", rec.build_record({}, [], "quick", "Debian", posture=POSTURE))
        self.assertEqual((rec.build_record({}, [], 'quick', 'Debian')['schema'], rec.build_record({}, [], 'quick', 'Debian', posture=POSTURE)['schema']), (2, 3))

    def test_ports_are_capped(self):
        many = {**POSTURE, "ports": [{"proto": "tcp", "port": i % 65535, "bind": "all interfaces", "process": "p", "package": "x"} for i in range(1000)]}
        self.assertEqual(len(rec.posture_block(many)["ports"]), rec.MAX_PORTS)

    def test_a_non_posture_input_gives_an_empty_block_not_a_crash(self):
        b = rec.posture_block(None)
        self.assertEqual(b["ports"], [])
        rec.check_record(rec.build_record({}, [], "quick", "Debian", posture={}))


if __name__ == "__main__":
    unittest.main()
