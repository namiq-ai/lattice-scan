# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""What a host exposes and what runs on it, beyond what is installed: listening ports, firewall, SSH settings, services, and (deep) processes that no package owns.

Read only. It changes, kills and installs nothing, and nothing it finds leaves the machine. It reports signals for a person to read; a signal is not a verdict, and
each one says why it can be harmless. Everything is read under `base` (default /) so that tests can use a fake tree; commands go through `run`, which tests replace.
Scope follows the effective user: as root it reads firewall rules and every process, as anyone else it reads what it may and lists what it could not.
"""
from __future__ import annotations
import glob, ipaddress, json, os, re, shutil, subprocess
from pathlib import Path

CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
CONTAINER_ID = re.compile(r"(?:docker[-/]|libpod[-/]|crio-|containerd[-/])([0-9a-f]{12,64})")
TMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/run/shm/")
SSH_DEFAULTS = {"port": "22", "permitrootlogin": "prohibit-password", "passwordauthentication": "yes", "pubkeyauthentication": "yes", "permitemptypasswords": "no",
                "kbdinteractiveauthentication": "no", "x11forwarding": "no", "maxauthtries": "6", "usepam": "yes"}
SSH_KEYS = tuple(SSH_DEFAULTS) + ("allowusers", "allowgroups", "denyusers", "denygroups", "authenticationmethods", "listenaddress")


def clean(v):
    return CTRL.sub("?", v) if isinstance(v, str) else v


def scrub(v):
    if isinstance(v, str):
        return clean(v)
    if isinstance(v, dict):
        return {scrub(k): scrub(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [scrub(x) for x in v]
    return v


def run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    """(exit code, stdout) or (-1, '') when the command is missing or fails to start; never raises."""
    if not shutil.which(cmd[0]):
        return -1, ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""
    return p.returncode, p.stdout


class Host:
    """Where to read from (base), who is asking (root or not) and how to run a command, in one object a test can build."""

    def __init__(self, base: str = "/", euid: int | None = None, runner=None):
        self.base = Path(base)
        self.euid = os.geteuid() if euid is None else euid
        self.run = runner or run
        self.unreadable: set[str] = set()   # what could not be read, for the report to say so

    @property
    def is_root(self) -> bool:
        return self.euid == 0

    def p(self, path: str) -> Path:
        return self.base / path.lstrip("/")

    def read(self, path: str, limit: int = 4_000_000) -> str:
        try:
            with open(self.p(path), "rb") as fh:
                return fh.read(limit).decode("utf-8", "replace")
        except OSError:
            return ""

    def link(self, path: str) -> str | None:
        try:
            return os.readlink(self.p(path))
        except OSError:
            return None


# ---------------------------------------------------------------- who owns a file

class Owners:
    """Which package owns a path: dpkg file lists, an apk database or `rpm -qf`. Built lazily; one dictionary for the whole run."""

    def __init__(self, host: Host):
        self.h, self.dpkg, self.apk, self.loaded = host, {}, {}, False
        self.rpm_cache: dict[str, str | None] = {}
        self.manager = ""

    def load(self) -> None:
        if self.loaded:
            return
        self.loaded = True
        for f in glob.glob(str(self.h.p("/var/lib/dpkg/info/*.list"))):
            pkg = os.path.basename(f)[:-5].split(":")[0]
            try:
                with open(f, errors="replace") as fh:
                    for line in fh:
                        self.dpkg[line.rstrip("\n")] = pkg
            except OSError:
                continue
        if self.dpkg:
            self.manager = "dpkg"
            return
        db = self.h.read("/lib/apk/db/installed", 60_000_000)
        if db:
            self.manager = "apk"
            for block in db.split("\n\n"):
                pkg, d = "", ""
                for l in block.splitlines():
                    if l.startswith("P:"):
                        pkg = l[2:]
                    elif l.startswith("F:"):
                        d = l[2:]
                    elif l.startswith("R:") and pkg:
                        self.apk["/" + (d + "/" if d else "") + l[2:]] = pkg
            return
        if shutil.which("rpm"):
            self.manager = "rpm"

    def owner(self, path: str) -> str | None:
        self.load()
        cands = {path, os.path.realpath(self.h.p(path)).replace(str(self.h.base).rstrip("/"), "", 1) or path}
        for c in list(cands):   # merged /usr: /bin/ls and /usr/bin/ls are one file
            for a, b in (("/usr/bin/", "/bin/"), ("/usr/sbin/", "/sbin/"), ("/usr/lib/", "/lib/")):
                if c.startswith(a):
                    cands.add(b + c[len(a):])
                elif c.startswith(b):
                    cands.add(a + c[len(b):])
        for c in cands:
            if c in self.dpkg:
                return self.dpkg[c]
            if c in self.apk:
                return self.apk[c]
        if self.manager == "rpm":
            if path not in self.rpm_cache:
                rc, out = self.h.run(["rpm", "-qf", "--qf", "%{NAME}\n", path])
                self.rpm_cache[path] = out.strip().splitlines()[0] if rc == 0 and out.strip() else None
            return self.rpm_cache[path]
        return None


# ---------------------------------------------------------------- ports

def hex_addr(h: str) -> str:
    raw = bytes.fromhex(h)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    words = [raw[i:i + 4][::-1] for i in range(0, 16, 4)]
    a = ipaddress.IPv6Address(b"".join(words))
    return str(a.ipv4_mapped) if a.ipv4_mapped else str(a)


def bind_class(addr: str) -> str:
    a = ipaddress.ip_address(addr)
    if a.is_unspecified:
        return "all interfaces"
    if a.is_loopback:
        return "loopback only"
    return "one address"


def parse_net(text: str, proto: str, listening: bool) -> list[dict]:
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        state = f[3]
        if listening and not ((proto.startswith("tcp") and state == "0A") or (proto.startswith("udp") and state == "07")):
            continue
        if not listening and not (proto.startswith("tcp") and state == "01"):
            continue
        try:
            la, lp = f[1].rsplit(":", 1)
            ra, rp = f[2].rsplit(":", 1)
            out.append({"proto": proto, "addr": hex_addr(la), "port": int(lp, 16), "remote": hex_addr(ra), "rport": int(rp, 16), "inode": f[9], "uid": f[7]})
        except ValueError:
            continue
    return out


def pid_list(h: Host) -> list[str]:
    try:
        return sorted((p for p in os.listdir(h.p("/proc")) if p.isdigit()), key=int)
    except OSError:
        return []


def socket_pids(h: Host) -> dict[str, str]:
    """socket inode -> pid, from /proc/PID/fd. Another user's processes cannot be read without root; they are counted, not guessed."""
    if getattr(h, "_sockets", None) is not None:
        return h._sockets   # read once per run
    m: dict[str, str] = {}
    h._sockets = m
    denied = 0
    for pid in pid_list(h):
        d = h.p(f"/proc/{pid}/fd")
        try:
            names = os.listdir(d)
        except OSError:
            denied += 1
            continue
        for n in names:
            t = h.link(f"/proc/{pid}/fd/{n}") or ""
            if t.startswith("socket:["):
                m.setdefault(t[8:-1], pid)
    if denied:
        h.unreadable.add(f"the open sockets of {denied} process(es) of other users")
    return m


def container_of(h: Host, pid: str, images: dict[str, str]) -> str:
    m = CONTAINER_ID.search(h.read(f"/proc/{pid}/cgroup", 20000))
    if not m:
        return ""
    cid = m.group(1)
    for full, img in images.items():
        if full.startswith(cid[:12]):
            return f"container {img}"
    return f"container {cid[:12]}"


def docker_images(h: Host) -> dict[str, str]:
    rc, out = h.run(["docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Image}}"])
    return dict(l.split(" ", 1) for l in out.splitlines() if " " in l) if rc == 0 else {}


def proc_info(h: Host, pid: str, owners: Owners, images: dict[str, str]) -> dict:
    exe = h.link(f"/proc/{pid}/exe")
    comm = h.read(f"/proc/{pid}/comm", 100).strip()
    info = {"pid": int(pid), "name": comm or "?", "exe": None, "package": None, "where": ""}
    if exe is None:
        return info
    deleted = exe.endswith(" (deleted)")
    path = exe[:-10] if deleted else exe
    info["exe"], info["deleted"] = path, deleted
    cont = container_of(h, pid, images)
    if cont:
        info["where"] = cont
    elif path.startswith("/snap/"):
        info["where"] = "snap"
    elif path.startswith(("/var/lib/flatpak/", "/app/")):
        info["where"] = "flatpak"
    else:
        info["package"] = owners.owner(path)
    return info


def listening(h: Host, owners: Owners, images: dict[str, str]) -> list[dict]:
    socks = []
    for proto, f in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"), ("udp", "/proc/net/udp"), ("udp6", "/proc/net/udp6")):
        socks += parse_net(h.read(f), proto, True)
    by_inode = socket_pids(h)
    rows, seen = [], set()
    for s in socks:
        key = (s["proto"][:3], s["addr"], s["port"])
        if key in seen:
            continue
        seen.add(key)
        row = {"proto": s["proto"][:3], "addr": s["addr"], "port": s["port"], "bind": bind_class(s["addr"])}
        pid = by_inode.get(s["inode"])
        if pid:
            p = proc_info(h, pid, owners, images)
            row.update({"process": p["name"], "pid": p["pid"], "package": p["package"], "where": p["where"], "exe": p["exe"]})
        rows.append(row)
    return sorted(rows, key=lambda r: (r["bind"] != "all interfaces", r["port"], r["proto"]))


# ---------------------------------------------------------------- firewall

def firewall(h: Host) -> dict:
    """Which host firewall is on and its default for incoming traffic. Rules need root; as anyone else the manager's own service state and config are read."""
    out: dict = {"readable": h.is_root, "managers": []}
    ufw_conf = h.read("/etc/ufw/ufw.conf")
    if h.read("/etc/ufw/ufw.conf") or shutil.which("ufw"):
        m = {"name": "ufw", "enabled": None}
        if re.search(r"^ENABLED=yes", ufw_conf, re.M):
            m["enabled"] = True
        elif re.search(r"^ENABLED=no", ufw_conf, re.M):
            m["enabled"] = False
        if h.is_root:
            rc, txt = h.run(["ufw", "status", "verbose"])
            if rc == 0:
                m["enabled"] = "Status: active" in txt
                d = re.search(r"Default:\s*(\w+) \(incoming\)", txt)
                m["defaultIncoming"] = d.group(1) if d else ""
                m["rules"] = len([l for l in txt.splitlines() if re.search(r"\b(ALLOW|DENY|REJECT|LIMIT)\b", l) and "Default" not in l])
        out["managers"].append(m)
    for svc in ("firewalld", "nftables"):
        if not h.run(["systemctl", "list-unit-files", f"{svc}.service", "--no-legend", "--no-pager"])[1].strip():
            continue   # the service is not installed: say nothing about it
        rc, txt = h.run(["systemctl", "is-active", svc])
        out["managers"].append({"name": svc, "enabled": txt.strip() == "active" if rc >= 0 else None})
    if h.is_root:
        rc, txt = h.run(["nft", "list", "ruleset"])
        if rc == 0:
            pol = re.findall(r"hook input.*?policy (\w+)", txt, re.S)
            out["nftables"] = {"rules": txt.count("\n\t\t") , "inputPolicy": pol[0] if pol else "", "ruleset": bool(txt.strip())}
        rc, txt = h.run(["iptables", "-S"])
        if rc == 0:
            pol = re.search(r"^-P INPUT (\w+)", txt, re.M)
            out["iptables"] = {"rules": len([l for l in txt.splitlines() if l.startswith("-A")]), "inputPolicy": pol.group(1) if pol else ""}
    else:
        h.unreadable.add("firewall rules (ufw, nft, iptables need root)")
        names = h.read("/proc/net/ip_tables_names").split()
        if names:
            out["kernelTables"] = names
    return out


# ---------------------------------------------------------------- ssh

def addr_port(o: dict) -> str:
    return f"[{o['remote']}]:{o['port']}" if ":" in o["remote"] else f"{o['remote']}:{o['port']}"


def sshd_config(h: Host) -> dict:
    """Effective-looking sshd settings from the config files: the first value of a keyword wins (Include is followed), unset keywords take OpenSSH's default."""
    seen: dict[str, str] = {}
    files: list[str] = []

    def load(path: str, depth: int = 0) -> None:
        if depth > 4:
            return
        text = h.read(path)
        if not text:
            return
        files.append(path)
        stop = False
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if stop:
                continue
            k, _, v = line.partition(" ")
            if not v:
                k, _, v = line.partition("=")
            k, v = k.lower(), v.strip().strip('"')
            if k == "match":
                stop = True   # settings under Match apply to some connections only; the global part has been read
                continue
            if k == "include":
                for pat in v.split():
                    pat = pat if pat.startswith("/") else "/etc/ssh/" + pat
                    for f in sorted(glob.glob(str(h.p(pat)))):
                        load("/" + os.path.relpath(f, str(h.base)), depth + 1)
                continue
            if k in SSH_KEYS and k not in seen:
                seen[k] = v
    load("/etc/ssh/sshd_config")
    if not files:
        return {"files": [], "settings": {}, "setExplicitly": [], "source": "none", "installed": False}
    eff = {k: seen.get(k, SSH_DEFAULTS.get(k, "")) for k in SSH_KEYS if k in seen or k in SSH_DEFAULTS}
    out = {"files": files, "settings": eff, "setExplicitly": sorted(seen), "source": "config files", "installed": True}
    if h.is_root:
        rc, txt = h.run(["sshd", "-T"])
        if rc == 0:
            real = {l.split(" ", 1)[0]: l.split(" ", 1)[1] for l in txt.splitlines() if " " in l}
            out["settings"] = {k: real.get(k, eff.get(k, "")) for k in eff}
            out["source"] = "sshd -T"
    else:
        h.unreadable.add("sshd -T (the effective values, with Match blocks and defaults, need root)")
    return out


# ---------------------------------------------------------------- services

def services(h: Host, owners: Owners) -> dict:
    rc, txt = h.run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain", "--no-pager"])
    if rc != 0:
        return {"available": False, "units": []}
    units = [l.split()[0] for l in txt.splitlines() if l.split()]
    rc, show = h.run(["systemctl", "show", "--no-pager", "-p", "Id", "-p", "FragmentPath", "-p", "ExecStart", "-p", "MainPID", *units]) if units else (0, "")
    out = []
    for block in show.split("\n\n"):
        kv = dict(l.split("=", 1) for l in block.splitlines() if "=" in l)
        if not kv.get("Id"):
            continue
        m = re.search(r"path=(\S+)", kv.get("ExecStart", ""))
        prog = m.group(1) if m else ""
        frag = kv.get("FragmentPath", "")
        pkg = owners.owner(prog) if prog.startswith("/") else None
        out.append({"unit": kv["Id"], "program": prog, "package": pkg, "unitFile": frag, "unitIsLocal": frag.startswith("/etc/systemd/system/") and not os.path.islink(h.p(frag)),
                    "mainPid": int(kv["MainPID"]) if kv.get("MainPID", "0").isdigit() else 0})
    enabled = h.run(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--plain", "--no-pager"])[1]
    return {"available": True, "running": len(units), "enabled": len([l for l in enabled.splitlines() if l.strip()]), "units": out}


# ---------------------------------------------------------------- processes (deep)

def processes(h: Host, owners: Owners, images: dict[str, str]) -> dict:
    """Every readable process: where its executable lives and whether a package owns it. Command line arguments are never recorded (they carry passwords)."""
    est: dict[str, list[dict]] = {}
    by_inode = socket_pids(h)
    for proto, f in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6")):
        for s in parse_net(h.read(f), proto, False):
            pid = by_inode.get(s["inode"])
            if pid and not ipaddress.ip_address(s["remote"]).is_loopback:
                est.setdefault(pid, []).append({"remote": s["remote"], "port": s["rport"]})
    groups: dict[tuple, dict] = {}
    unreadable, total = 0, 0
    for pid in pid_list(h):
        if h.link(f"/proc/{pid}/exe") is None:
            if not (h.read(f"/proc/{pid}/cmdline", 10) or ""):
                continue   # a kernel thread has no executable and no command line
            unreadable += 1
            continue
        total += 1
        p = proc_info(h, pid, owners, images)
        exe = p["exe"] or ""
        reasons, kind = [], "note"
        if p.get("deleted"):
            if owners.owner(exe):
                reasons.append(f"a package update replaced its program ({owners.owner(exe)}) after it started: it still runs the old version until restarted")
                kind = "stale"
            else:
                reasons.append("its program was deleted from disk while it runs and no package owns that path")
                kind = "attention"
        if exe.lstrip("/").startswith("memfd:"):
            reasons.append("it runs from memory only (memfd)")
            kind = "attention"
        if exe.startswith(TMP_DIRS):
            reasons.append("it runs from a temporary folder")
            kind = "attention"
        if not p["where"] and not p["package"] and kind != "stale":
            where = " (under a home folder)" if exe.startswith(("/home/", "/root/")) else ""
            if not any("no package owns" in r for r in reasons):
                reasons.append("no package owns its program" + where)
            if any(part.startswith(".") and part not in (".local", ".cache", ".config", ".cargo", ".nvm", ".npm", ".pyenv", ".venv") for part in exe.split("/")[1:-1]):
                kind = "attention"   # a hidden folder is a favourite hiding place and rarely a package's
        if not reasons:
            continue
        key = (exe, tuple(reasons))
        g = groups.setdefault(key, {"name": p["name"], "exe": exe, "reasons": reasons, "kind": kind, "pids": [], "package": p["package"], "where": p["where"], "outbound": []})
        g["pids"].append(p["pid"])
        for o in est.get(pid, []):
            if o not in g["outbound"] and len(g["outbound"]) < 4:
                g["outbound"].append(o)
    if unreadable:
        h.unreadable.add(f"the executable of {unreadable} process(es) of other users")
    order = {"attention": 0, "note": 1, "stale": 2}
    rows = sorted(groups.values(), key=lambda g: (order[g["kind"]], not g["outbound"], g["exe"]))
    for g in rows:
        if g["outbound"] and g["kind"] == "attention":
            g["reasons"] = g["reasons"] + ["it has outbound connections"]
    return {"readable": total, "unreadable": unreadable, "flagged": rows}


def persistence(h: Host, owners: Owners) -> dict:
    out: dict = {}
    pre = h.read("/etc/ld.so.preload").strip()
    out["ldPreload"] = [l for l in pre.splitlines() if l.strip() and not l.startswith("#")]
    users = []
    for line in h.read("/etc/passwd").splitlines():
        f = line.split(":")
        if len(f) > 3 and f[2] == "0" and f[0] != "root":
            users.append(f[0])
    out["extraUid0Users"] = users
    cron = sorted(set(glob.glob(str(h.p("/etc/cron.d/*"))) + glob.glob(str(h.p("/etc/cron.*/*")))))
    local_cron = []
    for f in cron:
        rel = "/" + os.path.relpath(f, str(h.base))
        if not owners.owner(rel):
            local_cron.append(rel)
    out["cronFilesNoPackage"] = sorted(local_cron)
    rc, timers = h.run(["systemctl", "list-timers", "--all", "--no-legend", "--plain", "--no-pager"])
    out["timers"] = len([l for l in timers.splitlines() if l.strip()]) if rc == 0 else None
    suid: list[str] = []
    if True:
        rc, txt = h.run(["find", "/usr", "/opt", "/home", "/tmp", "/var/tmp", "/srv", "-xdev", "-perm", "-4000", "-type", "f"], timeout=60)
        for path in txt.splitlines():
            if not owners.owner(path):
                suid.append(path)
    out["suidNoPackage"] = suid[:40]
    return out


# ---------------------------------------------------------------- the report

def observe(d: dict) -> list[dict]:
    """Signals for a person. Each says what was seen and why it can be harmless. None is a verdict."""
    obs: list[dict] = []

    def add(level: str, topic: str, text: str) -> None:
        obs.append({"level": level, "topic": topic, "text": text})
    ports = d["ports"]
    wide = [p for p in ports if p["bind"] == "all interfaces"]
    fw = d["firewall"]
    active = [m["name"] for m in fw["managers"] if m.get("enabled")]
    if "nftables" in fw and fw["nftables"].get("ruleset"):
        active.append("nftables rules")
    if "iptables" in fw and fw["iptables"].get("rules"):
        active.append("iptables rules")
    if wide:
        names = sorted({f"{p['proto']}/{p['port']}" for p in wide if not (p["proto"] == "udp" and p["port"] >= 32768)}, key=lambda x: (x.split("/")[0], int(x.split("/")[1])))
        add("note", "ports", f"{len(names)} port(s) listen on all interfaces: {', '.join(names[:12])}{' ...' if len(names) > 12 else ''}. That is normal for a server; it matters when the firewall does not limit who can connect.")
    if not active:
        if d["scope"] == "root":
            add("attention", "firewall", "no host firewall is active (no ufw, firewalld or nftables service, and no nftables or iptables rules were found). A network firewall in front of this host may still protect it.")
        else:
            add("note", "firewall", "no firewall manager reported active, but the rules could not be read without root; run as root for the answer.")
    else:
        for m in fw["managers"]:
            if m["name"] == "ufw" and m.get("enabled") and m.get("defaultIncoming") in ("allow",):
                add("attention", "firewall", "ufw is on but its default for incoming traffic is allow.")
    s = d["ssh"]["settings"]
    if not d["ssh"].get("installed", True) and not any(p.get("process") == "sshd" for p in ports):
        s = {}   # no sshd_config and no sshd listening: there is no SSH server to describe
    exposed_ssh = [p for p in wide if p.get("process") == "sshd" or (s and p["port"] == int(s.get("port", "22") or 22))]
    if s and s.get("passwordauthentication") == "yes":
        add("attention" if exposed_ssh else "note", "ssh", "SSH accepts passwords" + (" and listens on all interfaces" if exposed_ssh else "") + ". Keys only is safer; passwords can be guessed. (It can be a choice: check Match blocks and who may log in.)")
    if s.get("permitrootlogin") == "yes":
        add("attention", "ssh", "SSH allows root to log in with a password.")
    elif s.get("permitrootlogin") in ("prohibit-password", "without-password"):
        add("note", "ssh", "SSH lets root log in with a key (the OpenSSH default).")
    if s.get("permitemptypasswords") == "yes":
        add("attention", "ssh", "SSH allows accounts with empty passwords.")
    for u in d["services"].get("units", []):
        if not u["package"] and u["program"] and not u["program"].startswith(("/snap/", "/opt/")) and u["unitIsLocal"]:
            add("note", "services", f"service {u['unit']} was added locally and its program {u['program']} belongs to no package. Usual for software you installed yourself; confirm you did.")
    pr = d.get("processes")
    if pr:
        stale = [g for g in pr["flagged"] if g["kind"] == "stale"]
        if stale:
            names = sorted({g["name"] for g in stale})
            pk = sorted({re.search(r"\((.+?)\)", g["reasons"][0]).group(1) for g in stale if re.search(r"\((.+?)\)", g["reasons"][0])})
            add("note", "restart", f"{len(stale)} running program(s) were replaced by a package update after they started and still run the old version: {', '.join(names[:8])}{' ...' if len(names) > 8 else ''} "
                f"(packages: {', '.join(pk[:6])}{' ...' if len(pk) > 6 else ''}). A restart or reboot loads the new version; until then a fix in the update does not protect them.")
        for g in pr["flagged"]:
            if g["kind"] == "stale":
                continue
            pids = ",".join(str(x) for x in g["pids"][:4]) + (" ..." if len(g["pids"]) > 4 else "")
            many = f", {len(g['pids'])} processes" if len(g["pids"]) > 1 else ""
            where = f"{g['name']} ({g['exe']}, pid {pids}{many})"
            out = f" Outbound: {', '.join(addr_port(o) for o in g['outbound'][:2])}." if g["outbound"] else ""
            add("attention" if g["kind"] == "attention" else "note", "process", f"{where}: {'; '.join(g['reasons'])}.{out}")
    pe = d.get("persistence")
    if pe:
        if pe["ldPreload"]:
            add("attention", "persistence", f"/etc/ld.so.preload lists {len(pe['ldPreload'])} library(ies): {', '.join(pe['ldPreload'][:3])}. It loads into every program; some security tools do this, most hosts have none.")
        if pe["extraUid0Users"]:
            add("attention", "persistence", f"account(s) other than root with user id 0: {', '.join(pe['extraUid0Users'])}.")
        if pe["suidNoPackage"]:
            add("note", "persistence", f"{len(pe['suidNoPackage'])} setuid file(s) that no package owns, for example {pe['suidNoPackage'][0]}.")
        if pe["cronFilesNoPackage"]:
            add("note", "persistence", f"{len(pe['cronFilesNoPackage'])} scheduled-job file(s) that no package owns: {', '.join(pe['cronFilesNoPackage'][:4])}.")
    return obs


def collect(deep: bool = False, base: str = "/", euid: int | None = None, runner=None) -> dict:
    h = Host(base, euid, runner)
    owners = Owners(h)
    images = docker_images(h)
    d: dict = {"scope": "root" if h.is_root else "user", "level": "deep" if deep else "quick", "euid": h.euid}
    for name, fn in (("ports", lambda: listening(h, owners, images)), ("firewall", lambda: firewall(h)), ("ssh", lambda: sshd_config(h)),
                     ("services", lambda: services(h, owners))):
        try:
            d[name] = fn()
        except Exception as e:  # noqa: BLE001 - one unreadable part must not hide the others
            d[name] = {"error": f"{type(e).__name__}: {e}"} if name != "ports" else []
            d.setdefault("errors", []).append(f"{name}: {type(e).__name__}")
    d["ssh"].setdefault("settings", {})
    d["firewall"].setdefault("managers", [])
    d["services"].setdefault("units", [])
    if deep:
        for name, fn in (("processes", lambda: processes(h, owners, images)), ("persistence", lambda: persistence(h, owners))):
            try:
                d[name] = fn()
            except Exception as e:  # noqa: BLE001
                d.setdefault("errors", []).append(f"{name}: {type(e).__name__}")
    d["packageManager"] = owners.manager or "none found"
    d["unreadable"] = sorted(h.unreadable)
    d["observations"] = observe(d)
    return scrub(d)


def render(d: dict) -> str:
    L: list[str] = []
    who = "root" if d["scope"] == "root" else "a normal user"
    L.append(f"posture ({d['level']}, run as {who}; read only, nothing is sent anywhere)")
    L.append("")
    ports = d["ports"]
    wide = [p for p in ports if p["bind"] == "all interfaces"]
    eph = [p for p in wide if p["proto"] == "udp" and p["port"] >= 32768]   # clients (name lookups, media) bind a random high UDP port; they are not services
    shown, seen = [], {}
    for p in wide:
        if p in eph:
            continue
        k = (p["proto"], p["port"])
        if k in seen:   # the same port on IPv4 and IPv6 is one line
            seen[k]["addr"] = "0.0.0.0 and ::"
            continue
        q = dict(p)
        seen[k] = q
        shown.append(q)
    L.append(f"LISTENING PORTS  {len(ports)} sockets: {len(wide)} on all interfaces, {len([p for p in ports if p['bind'] == 'loopback only'])} on loopback only (not reachable from other machines), "
             f"{len([p for p in ports if p['bind'] == 'one address'])} on one address")
    L.append(f"  {'PROTO':<5} {'PORT':<6} {'ADDRESS':<16} {'PROCESS':<17} PACKAGE / WHERE")
    for p in shown[:40]:
        who_ = p.get("package") or p.get("where") or ("no package" if p.get("exe") else "(owner not readable without root)")
        L.append(f"  {p['proto']:<5} {p['port']:<6} {p['addr']:<16} {str(p.get('process', '-')):<17} {who_}")
    if len(shown) > 40:
        L.append(f"  ... {len(shown) - 40} more ports on all interfaces (--format json lists all)")
    if eph:
        L.append(f"  ({len(eph)} UDP socket(s) on random ports from 32768 up are not listed: programs that look things up bind one of those)")
    L.append("")
    fw = d["firewall"]
    L.append("FIREWALL")
    if not fw["managers"] and "nftables" not in fw and "iptables" not in fw:
        L.append("  no ufw, firewalld or nftables found" + ("" if d["scope"] == "root" else " (rules need root to read)"))
    for m in fw["managers"]:
        L.append(f"  {m['name']}: " + ("on" if m.get("enabled") else "off" if m.get("enabled") is False else "unknown")
                 + (f", default incoming {m['defaultIncoming']}" if m.get("defaultIncoming") else "") + (f", {m['rules']} rule(s)" if "rules" in m else ""))
    if "nftables" in fw:
        L.append(f"  nftables ruleset: {'present' if fw['nftables']['ruleset'] else 'empty'}" + (f", input policy {fw['nftables']['inputPolicy']}" if fw["nftables"].get("inputPolicy") else ""))
    if "iptables" in fw:
        L.append(f"  iptables: {fw['iptables']['rules']} rule(s)" + (f", INPUT policy {fw['iptables']['inputPolicy']}" if fw["iptables"].get("inputPolicy") else ""))
    L.append("")
    s = d["ssh"]
    if not s.get("installed", True):
        L.append("SSH  no sshd_config found: no SSH server is configured here")
    else:
        L.append(f"SSH  ({s.get('source', 'config files')}; {', '.join(s.get('files', []))})")
    for k in ("port", "permitrootlogin", "passwordauthentication", "pubkeyauthentication", "permitemptypasswords", "kbdinteractiveauthentication", "x11forwarding", "maxauthtries", "allowusers", "allowgroups"):
        if k in s.get("settings", {}):
            L.append(f"  {k:<30} {s['settings'][k]}" + ("" if k in s.get("setExplicitly", []) or s.get("source") == "sshd -T" else "  (OpenSSH default)"))
    L.append("")
    sv = d["services"]
    if sv.get("available"):
        loc = [u for u in sv["units"] if not u["package"] and u["program"]]
        L.append(f"SERVICES  {sv.get('running', 0)} running, {sv.get('enabled', 0)} enabled; {len(loc)} run a program that no package owns")
        for u in loc[:15]:
            L.append(f"  {u['unit']:<34} {u['program']}" + ("  (unit file added locally)" if u["unitIsLocal"] else ""))
    else:
        L.append("SERVICES  systemctl is not available here")
    pr = d.get("processes")
    if pr:
        L.append("")
        L.append(f"PROCESSES  {pr['readable']} readable, {pr['unreadable']} not readable; {len(pr['flagged'])} flagged")
        for g in pr["flagged"][:30]:
            L.append(f"  {g['name']:<16} x{len(g['pids']):<3} {g['exe'] or '?'}  [{'; '.join(g['reasons'])}]" + (f"  outbound: {', '.join(addr_port(o) for o in g['outbound'][:3])}" if g["outbound"] else ""))
    pe = d.get("persistence")
    if pe:
        L.append("")
        L.append(f"PERSISTENCE  ld.so.preload: {len(pe['ldPreload'])}; extra uid 0 accounts: {len(pe['extraUid0Users'])}; setuid files no package owns: {len(pe['suidNoPackage'])}; "
                 f"job files no package owns: {len(pe['cronFilesNoPackage'])}; timers: {pe['timers'] if pe['timers'] is not None else '?'}")
    L.append("")
    L.append("FOR A PERSON TO READ  (signals, not verdicts: each can be harmless)")
    if not d["observations"]:
        L.append("  nothing stood out in what could be read")
    for o in d["observations"]:
        L.append(f"  [{o['level']}] {o['topic']}: {o['text']}")
    if d["unreadable"]:
        L.append("")
        L.append(f"NOT READ ({d['scope']} scope): " + "; ".join(d["unreadable"]) + ("." if d["scope"] == "root" else ". Run as root to read them (sudo lattice-scan posture)."))
    if d["level"] == "quick":
        L.append("")
        L.append("Quick scan: processes, deleted or temporary executables and persistence points were not checked. `lattice-scan posture --deep` reads them (about a minute).")
    if d.get("errors"):
        L.append("")
        L.append("could not complete: " + ", ".join(d["errors"]))
    return "\n".join(L)


def dump(d: dict) -> str:
    return json.dumps(d, indent=1, sort_keys=True)
