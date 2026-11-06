# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""posture on a fake /proc and /etc tree: ports, firewall, ssh, services, processes no package owns, scope. Invented names and RFC 5737 addresses only."""
import json, os, shutil, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import posture  # noqa: E402

ROOTS = []   # the temporary trees of this module; removed once, at the end (an implicit clean-up of a TemporaryDirectory is a ResourceWarning)
HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def sock(local, remote, state, inode, uid=0):
    return f"   0: {local} {remote} {state} 00000000:00000000 00:00000000 00000000 {uid:>5} 0 {inode} 1 0000000000000000 100 0 0 10 0\n"


class Fake:
    """A tree under a temporary folder that posture reads as if it were /."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp())
        ROOTS.append(self.root)
        self.calls = []

    def file(self, path, text=""):
        p = self.root / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def proc(self, pid, exe, comm, sockets=(), cmdline="", cgroup="0::/user.slice"):
        base = f"/proc/{pid}"
        self.file(f"{base}/comm", comm + "\n")
        self.file(f"{base}/cmdline", cmdline)
        self.file(f"{base}/cgroup", cgroup + "\n")
        (self.root / f"proc/{pid}/fd").mkdir(parents=True, exist_ok=True)
        if exe:
            os.symlink(exe, self.root / f"proc/{pid}/exe")
        for i, inode in enumerate(sockets):
            os.symlink(f"socket:[{inode}]", self.root / f"proc/{pid}/fd/{3 + i}")

    def owned(self, pkg, *paths):
        self.file(f"/var/lib/dpkg/info/{pkg}.list", "\n".join(paths) + "\n")

    def runner(self, answers=None):
        answers = answers or {}

        def run(cmd, timeout=30):
            self.calls.append(cmd)
            for k, v in answers.items():
                if cmd[:len(k)] == list(k):
                    return v
            return -1, ""
        return run

    def collect(self, deep=False, euid=1000, answers=None):
        return posture.collect(deep=deep, base=str(self.root), euid=euid, runner=self.runner(answers))


def server():
    f = Fake()
    f.file("/proc/net/tcp", HEAD + sock("00000000:0016", "00000000:0000", "0A", 111) + sock("0100007F:1F90", "00000000:0000", "0A", 222))
    f.file("/proc/net/tcp6", HEAD)
    f.file("/proc/net/udp", HEAD)
    f.file("/proc/net/udp6", HEAD)
    f.proc(100, "/usr/sbin/sshd", "sshd", [111])
    f.proc(200, "/opt/acme/bin/acmed", "acmed", [222])
    f.owned("openssh-server", "/usr/sbin/sshd")
    return f


class Ports(unittest.TestCase):
    def test_all_interfaces_and_loopback_with_process_and_package(self):
        d = server().collect()
        by = {p["port"]: p for p in d["ports"]}
        self.assertEqual((by[22]["bind"], by[22]["process"], by[22]["package"]), ("all interfaces", "sshd", "openssh-server"))
        self.assertEqual((by[8080]["bind"], by[8080]["process"], by[8080]["package"]), ("loopback only", "acmed", None))
        self.assertEqual(d["ports"][0]["port"], 22)                       # exposed ones first

    def test_hex_addresses(self):
        self.assertEqual(posture.hex_addr("0100007F"), "127.0.0.1")
        self.assertEqual(posture.hex_addr("00000000000000000000000001000000"), "::1")
        self.assertEqual(posture.hex_addr("0000000000000000FFFF00000100007F"), "127.0.0.1")
        self.assertEqual(posture.bind_class("::"), "all interfaces")

    def test_a_container_process_is_attributed_to_its_image(self):
        f = server()
        cid = "ab" * 32
        f.proc(300, "/usr/local/bin/redis-server", "redis-server", [], cgroup=f"0::/system.slice/docker-{cid}.scope")
        d = f.collect(answers={("docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Image}}"): (0, f"{cid} redis:7-alpine\n")})
        # no socket for pid 300 here; ask proc_info directly
        h = posture.Host(str(f.root), 1000, f.runner())
        info = posture.proc_info(h, "300", posture.Owners(h), {cid: "redis:7-alpine"})
        self.assertEqual(info["where"], "container redis:7-alpine")
        self.assertIsNone(info["package"])


class Ssh(unittest.TestCase):
    def test_first_value_wins_include_is_followed_and_defaults_fill_in(self):
        f = server()
        f.file("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nPermitRootLogin no\nMatch User bob\n  PasswordAuthentication no\n")
        f.file("/etc/ssh/sshd_config.d/10-local.conf", "PasswordAuthentication no\nPort 2222\n")
        d = f.collect()
        s = d["ssh"]["settings"]
        self.assertEqual((s["passwordauthentication"], s["permitrootlogin"], s["port"], s["maxauthtries"]), ("no", "no", "2222", "6"))
        self.assertEqual(d["ssh"]["source"], "config files")

    def test_password_login_on_an_exposed_sshd_is_a_signal_that_says_it_can_be_a_choice(self):
        f = server()
        f.file("/etc/ssh/sshd_config", "PasswordAuthentication yes\nPermitRootLogin yes\n")
        obs = f.collect()["observations"]
        texts = " ".join(o["text"] for o in obs if o["topic"] == "ssh")
        self.assertIn("accepts passwords and listens on all interfaces", texts)
        self.assertIn("can be a choice", texts)
        self.assertIn("allows root to log in with a password", texts)

    def test_no_sshd_config_and_no_sshd_means_no_ssh_signal(self):
        f = Fake()
        for n in ("tcp", "tcp6", "udp", "udp6"):
            f.file(f"/proc/net/{n}", HEAD)
        d = f.collect()
        self.assertFalse(d["ssh"]["installed"])
        self.assertFalse([o for o in d["observations"] if o["topic"] == "ssh"])

    def test_root_reads_the_effective_values(self):
        f = server()
        f.file("/etc/ssh/sshd_config", "PasswordAuthentication yes\n")
        d = f.collect(euid=0, answers={("sshd", "-T"): (0, "passwordauthentication no\nport 22\npermitrootlogin no\n")})
        self.assertEqual((d["ssh"]["source"], d["ssh"]["settings"]["passwordauthentication"]), ("sshd -T", "no"))


class Scope(unittest.TestCase):
    def test_a_normal_user_runs_no_privileged_command_and_is_told_what_was_not_read(self):
        f = server()
        d = f.collect(euid=1000)
        self.assertEqual(d["scope"], "user")
        cmds = [c[0] for c in f.calls]
        self.assertNotIn("nft", cmds); self.assertNotIn("iptables", cmds); self.assertNotIn("sshd", cmds)
        self.assertTrue(any("firewall rules" in x for x in d["unreadable"]))
        self.assertIn("Run as root", posture.render(d))
        self.assertIn("run as a normal user", posture.render(d))

    def test_root_reads_firewall_rules(self):
        f = server()
        d = f.collect(euid=0, answers={("nft", "list", "ruleset"): (0, "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t\ttcp dport 22 accept\n\t}\n}\n"),
                                       ("iptables", "-S"): (0, "-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n")})
        self.assertEqual(d["scope"], "root")
        self.assertEqual(d["firewall"]["nftables"]["inputPolicy"], "drop")
        self.assertEqual(d["firewall"]["iptables"]["rules"], 1)
        self.assertFalse([o for o in d["observations"] if o["topic"] == "firewall"])
        self.assertIn("run as root", posture.render(d))

    def test_root_with_no_firewall_at_all_is_an_attention_signal_that_names_the_exception(self):
        d = server().collect(euid=0)
        o = [o for o in d["observations"] if o["topic"] == "firewall"][0]
        self.assertEqual(o["level"], "attention")
        self.assertIn("network firewall in front", o["text"])


class Processes(unittest.TestCase):
    def deep(self, f, **k):
        return f.collect(deep=True, **k)

    def tree(self):
        f = server()
        f.file("/proc/net/tcp", HEAD + sock("00000000:0016", "00000000:0000", "0A", 111) + sock("0200A8C0:D431", "0100A8C0:01BB", "01", 333))
        f.proc(400, "/tmp/.x/payload", "payload", [333], cmdline="payload\0--password\0hunter2")
        f.proc(401, "/usr/bin/oldprog (deleted)", "oldprog")
        f.proc(402, "/tmp/gone (deleted)", "gone")
        f.proc(403, "/memfd:evil (deleted)", "evil")
        f.proc(404, "/opt/vendor/bin/tool", "tool")
        f.proc(405, "/usr/bin/ls", "ls")
        f.owned("coreutils", "/usr/bin/ls")
        f.owned("oldprog", "/usr/bin/oldprog")
        f.proc(406, None, "kworker")
        return f

    def test_quick_does_not_look_at_processes(self):
        self.assertNotIn("processes", self.tree().collect())

    def test_deep_lists_what_no_package_owns_and_why(self):
        d = self.deep(self.tree())
        by = {g["name"]: g for g in d["processes"]["flagged"]}
        self.assertEqual(set(by), {"payload", "oldprog", "gone", "evil", "tool", "acmed"})   # acmed is the server fixture's own unowned program
        self.assertEqual(by["payload"]["kind"], "attention")
        self.assertIn("temporary folder", " ".join(by["payload"]["reasons"]))
        self.assertTrue(by["payload"]["outbound"])
        self.assertEqual(by["oldprog"]["kind"], "stale")                    # replaced by a package update: restart, not suspicion
        self.assertEqual(by["gone"]["kind"], "attention")                   # deleted and no package owns it
        self.assertEqual(by["evil"]["kind"], "attention")
        self.assertEqual(by["tool"]["kind"], "note")
        self.assertNotIn("ls", by)                                          # owned by coreutils
        self.assertNotIn("kworker", by)                                     # a kernel thread

    def test_stale_programs_are_one_restart_signal_not_one_per_process(self):
        obs = self.deep(self.tree())["observations"]
        self.assertEqual(len([o for o in obs if o["topic"] == "restart"]), 1)
        self.assertIn("still run the old version", [o for o in obs if o["topic"] == "restart"][0]["text"])

    def test_command_line_arguments_are_never_recorded(self):
        d = self.deep(self.tree())
        self.assertNotIn("hunter2", json.dumps(d))
        self.assertNotIn("--password", json.dumps(d))

    def test_every_signal_says_it_can_be_harmless(self):
        text = posture.render(self.deep(self.tree()))
        self.assertIn("signals, not verdicts: each can be harmless", text)
        self.assertNotRegex(text, r"(?i)malware|compromised|infected|hacked|malicious")

    def test_control_characters_from_the_host_never_reach_the_screen(self):
        f = self.tree()
        f.file("/proc/405/comm", "l\x1b[31ms\n")
        d = self.deep(f)
        self.assertNotIn("\x1b", json.dumps(d, ensure_ascii=False))
        self.assertNotIn("\x1b", posture.render(d))


class Persistence(unittest.TestCase):
    def test_preload_extra_uid0_and_unowned_cron(self):
        f = server()
        f.file("/etc/ld.so.preload", "/usr/lib/libhide.so\n")
        f.file("/etc/passwd", "root:x:0:0::/root:/bin/sh\ntoor:x:0:0::/:/bin/sh\nbob:x:1000:1000::/home/bob:/bin/sh\n")
        f.file("/etc/cron.d/local", "* * * * * root /opt/x\n")
        f.file("/etc/cron.d/logrotate", "")
        f.owned("logrotate", "/etc/cron.d/logrotate")
        d = f.collect(deep=True)
        p = d["persistence"]
        self.assertEqual((p["ldPreload"], p["extraUid0Users"], p["cronFilesNoPackage"]), (["/usr/lib/libhide.so"], ["toor"], ["/etc/cron.d/local"]))
        topics = [o["topic"] for o in d["observations"]]
        self.assertEqual(topics.count("persistence"), 3)


def tearDownModule():
    for r in ROOTS:
        shutil.rmtree(r, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
