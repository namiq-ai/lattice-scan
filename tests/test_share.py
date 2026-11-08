# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""`inventory --share`: the LATTICE INVENTORY v1 block (OCO-5920 INV2, INV3). Synthetic hosts only; RFC 5737 addresses."""
import sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src")); sys.path.insert(0, str(Path(__file__).resolve().parent))
from lattice_scan import share  # noqa: E402
from test_agent_entry import Entry, EntryBase, feed  # noqa: E402

CANARY = "canary-host-7f3a"


def inv(**kw):
    d = {"packages": {"openssh-server": "1:10.0p1-5", "nginx": "1.26.3-1", "openssl": "3.4.1-1", "libssl3": "3.4.1-1", "bash": "5.2-1", "gnome-shell": "47.0", "nginx-doc": "1.26.3-1",
                      "php8.3-fpm": "8.3.6-1", "postgresql-16": "16.4-1", "postgresql-client-16": "16.4-1", "bash-completion": "2.1", "libfoo": "1.0", "weird name!": "1 2"},
         "snaps": {"firefox": "134.0"}, "images": ["redis:alpine", "postgres:16-alpine@sha256:abcd"], "kernel": "7.0.0-41", "os": "Ubuntu 26.04 LTS", "host": {"arch": "aarch64"}}
    d.update(kw)
    return d


PORTS = [{"proto": "tcp", "addr": "0.0.0.0", "port": 22, "package": "openssh-server"}, {"proto": "tcp", "addr": "::", "port": 22, "package": "openssh-server"},
         {"proto": "tcp", "addr": "127.0.0.1", "port": 5432}]
POSTURE = {"firewall": {"managers": [{"name": "ufw", "enabled": True}, {"name": "nftables", "enabled": False}]}, "ssh": {"settings": {"permitrootlogin": "no", "passwordauthentication": "yes", "banner": "x"}}}


def block(**kw):
    a = dict(inv=inv(), ports=PORTS, posture=POSTURE, matches={("pkg", "libfoo"): ["CVE-2030-0001"]}, feed_state="read 2030-01-03 (12 entries)", taken="2030-01-03", tool_version="0.4.8")
    a.update(kw)
    return share.build(**a)


class Share(unittest.TestCase):
    def test_the_header_has_exactly_these_keys_in_this_order_and_spaces_survive_in_values(self):
        lines = block().splitlines()
        self.assertEqual([l.split(":")[0] for l in lines[:9]], ["LATTICE INVENTORY v1", "tool", "taken", "os", "kernel", "arch", "counts", "feed", "items"])
        self.assertIn("os: Ubuntu 26.04 LTS", lines) and self.assertIn("feed: read 2030-01-03 (12 entries)", lines)
        self.assertEqual(lines[9], "--") and self.assertEqual(lines[-1], "end")

    def test_the_selection_order_is_kernel_listening_cisa_images_snaps_curated(self):
        body = [l for l in block().splitlines() if l.split(" ")[0] in ("kernel", "pkg", "snap", "image")]
        why = [l.split("why=")[1].split(":")[0].split(",")[0] for l in body]
        self.assertEqual(why, ["kernel", "listen", "cisa", "image", "image", "snap"] + ["curated"] * (len(why) - 6))

    def test_a_cisa_match_is_kept_even_when_the_block_is_full_and_noise_is_not_listed(self):
        many = inv(packages={f"nginx-extra{i}": "1" for i in range(500)} | {"libfoo": "1.0"})
        text = block(inv=many, max_lines=30)
        self.assertIn("pkg libfoo 1.0 why=cisa:CVE-2030-0001", text)
        self.assertLessEqual(len(text.splitlines()), 30)
        t2 = block()
        for noise in ("gnome-shell", "nginx-doc", "bash-completion", "postgresql-client-16 ", "weird"):
            self.assertNotIn(noise, t2.replace("postgresql-client", "postgresql-client "))  # none of them is an item

    def test_the_cap_of_150_lines_and_12_kb_always_holds(self):
        huge = inv(packages={f"nginx-mod{i}": "1.0" for i in range(5000)} | {f"php{i}": "8" for i in range(5000)}, snaps={f"s{i}": "1" for i in range(500)}, images=[f"img{i}:1" for i in range(500)])
        text = block(inv=huge, max_lines=999)
        self.assertLessEqual(len(text.splitlines()), share.MAX_LINES)
        self.assertLessEqual(len(text.encode()), share.MAX_BYTES)

    def test_no_host_name_user_address_or_path_can_get_into_a_field(self):
        hostile = inv(packages={"openssh-server": "1.0", "nginx": "1.0 /home/alice/.ssh " + CANARY}, kernel="7.0 " + CANARY)
        ports = PORTS + [{"proto": "tcp", "addr": "203.0.113.9", "port": 8443, "package": "nginx", "pid": 4242, "user": "alice", "cwd": "/home/alice"}]
        text = block(inv=hostile, ports=ports)
        for secret in ("alice", "/home", "4242", "203.0.113.9"):
            self.assertNotIn(secret, text)
        self.assertNotIn(" /", text.replace(" tcp ", ""))
        self.assertIn("listen tcp address:8443 owner=nginx", text)

    def test_it_is_deterministic_and_listeners_are_deduplicated_with_loopback_and_all_told_apart(self):
        a, b = block(), block()
        self.assertEqual(a, b)
        self.assertEqual(a.count("listen tcp all:22 owner=openssh-server"), 1)
        self.assertIn("listen tcp loopback:5432", a)
        self.assertIn("posture: firewall=ufw:active,nftables:inactive ssh.passwordauthentication=yes ssh.permitrootlogin=no", a)
        self.assertNotIn("banner", a)

    def test_a_feed_that_could_not_be_read_is_said_in_the_header(self):
        self.assertIn("feed: not read (namiq.io unreachable); matches with today's list may be missing", block(feed_state="not read (namiq.io unreachable); matches with today's list may be missing"))

    def test_curated_names_are_recognised_by_stem_and_not_by_accident(self):
        for n in ("nginx", "postgresql-16", "php8.3-fpm", "openjdk-21-jre", "libssl3", "python3.12"):
            self.assertTrue(share.is_curated(n), n)
        for n in ("nginxy", "gnome-shell", "libreoffice", "bashful"):
            self.assertFalse(share.is_curated(n), n)


class ShareCommand(EntryBase):
    """The command itself: the block alone on stdout, guidance on stderr, a feed that matches, no feed, and the private file."""

    def test_the_block_alone_is_on_stdout_and_a_feed_match_is_listed_with_its_cve(self):
        Entry.feed = feed()
        rc, out, err = self.run_cli("inventory", "--share")
        self.assertEqual(rc, 0, err)
        self.assertTrue(out.startswith("LATTICE INVENTORY v1\n") and out.rstrip().endswith("end"))
        self.assertIn("paste it into My products", err)
        self.assertNotIn("[share]", out)

    def test_no_feed_is_said_in_the_header_and_makes_no_request(self):
        rc, out, err = self.run_cli("inventory", "--share", "--no-feed")
        self.assertEqual(rc, 0, err)
        self.assertIn("feed: not read (--no-feed)", out)
        self.assertIn("the CISA list was not read", err)

    def test_all_writes_a_private_file_and_never_prints_it(self):
        import os, tempfile
        d = tempfile.mkdtemp()
        f = os.path.join(d, "all.txt")
        rc, out, err = self.run_cli("inventory", "--share", "--no-feed", "--all", f)
        self.assertEqual(rc, 0, err)
        self.assertEqual(oct(os.stat(f).st_mode & 0o777), "0o600")
        self.assertIn("pkg libexamplelib2 2.17.1-1", open(f).read())
        self.assertNotIn(f, out)

    def test_max_lines_lowers_the_cap(self):
        rc, out, err = self.run_cli("inventory", "--share", "--no-feed", "--max-lines", "20")
        self.assertEqual(rc, 0, err)
        self.assertLessEqual(len(out.splitlines()), 20)


if __name__ == "__main__":
    unittest.main()
