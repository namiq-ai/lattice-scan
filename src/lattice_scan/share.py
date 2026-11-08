# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""`lattice-scan inventory --share`: the host's important software as one block to copy (INV2, INV3 of the Lattice inventory initiative, OCO-5920).

The block is what a person pastes into My products in the Lattice Analyst. It names installed software and versions only: no host name, address, user name,
serial, MAC, path or process id. It is the contract of the format `LATTICE INVENTORY v1`; the Analyst reads it with a parser written to the same definition.

The block is short on purpose (at most 150 lines, 12 KB). So the choice of what goes in matters for accuracy: an item left out can never match, and "no match" would then
be wrong. The rule is: the kernel; whatever owns a listening socket; anything that the tool's own matcher links to an entry of the CISA feed (so nothing that today's
exploited list could concern is dropped); running container images; snaps; then a curated list of server, edge and admin software. When the feed cannot be read the
header says so, and the person is told that matches may be missing.
"""
from __future__ import annotations

import re

VERSION = 1
MAX_LINES = 150
MAX_BYTES = 12_000
MAX_FIELD = 80
_SAFE = re.compile(r"[^A-Za-z0-9._+:~@/=-]")
_TEXT = re.compile(r"[^A-Za-z0-9._+:~@/=(),;' -]")
# parts of a package name that mark documentation, data or a development file: never what an exposure question is about
_SKIP_SUFFIX = ("-doc", "-docs", "-common", "-completion", "-dev", "-dbg", "-dbgsym", "-data", "-locales", "-l10n", "-examples", "-man", "-i18n", "-tests", "-headers")
PER_STEM = 3
CURATED_BUDGET = 60

# Server, edge and admin software that matters to an exposure question. A package is curated when its name equals a stem or starts with it followed by a digit,
# a dot or a dash (postgresql-16, php8.3-fpm, openjdk-21-jre). Reviewed like the Analyst's hunt catalogue: add a stem with its reason, never a host-specific name.
CURATED = (
    "nginx", "apache2", "httpd", "lighttpd", "caddy", "haproxy", "traefik", "envoy", "squid", "varnish", "tomcat", "jetty", "openssh-server", "openssh-client", "openssl", "libssl",
    "gnutls", "sudo", "polkit", "policykit-1", "bash", "libc6", "glibc", "systemd", "dbus", "postgresql", "mysql-server", "mariadb-server", "mongodb", "redis", "memcached", "elasticsearch",
    "kibana", "grafana", "prometheus", "php", "python3", "nodejs", "openjdk", "ruby", "perl", "samba", "vsftpd", "proftpd", "pure-ftpd", "exim4", "postfix", "dovecot", "sendmail", "bind9",
    "unbound", "dnsmasq", "openvpn", "wireguard", "strongswan", "libreswan", "docker", "containerd", "runc", "kubelet", "kubectl", "kubeadm", "cups", "curl", "libcurl", "wget", "git", "rsync",
    "zlib1g", "libxml2", "sqlite3", "libwebp", "imagemagick", "ghostscript", "slapd", "krb5", "unzip", "p7zip", "tar", "gitlab", "jenkins", "gitea", "nextcloud", "wordpress", "zabbix",
    "snmpd", "fail2ban", "ufw", "iptables", "nftables", "cloudflared", "tailscale", "vim", "screen", "tmux",
)


def clean_field(v: object) -> str:
    """A name or a version: no space, nothing outside a small safe set."""
    return _SAFE.sub("", str(v))[:MAX_FIELD]


def clean_version(v: object) -> str:
    """A version or a kernel release: the first word only, and only characters a version has. A path, an address or a second word is dropped, not kept."""
    first = (str(v).split() or [""])[0]
    return re.sub(r"[^A-Za-z0-9.+:~_-]", "", first)[:MAX_FIELD]


def clean_name(v: object) -> str:
    """A package or snap name: the first word, no slash."""
    first = (str(v).split() or [""])[0]
    return re.sub(r"[^A-Za-z0-9.+:~_-]", "", first)[:MAX_FIELD]


def clean_text(v: object) -> str:
    """A header value (the OS name, the feed state): spaces and commas allowed."""
    return " ".join(_TEXT.sub("", str(v)).split())[:MAX_FIELD * 2]


def is_curated(name: str) -> bool:
    n = name.lower()
    for s in CURATED:
        if n == s:
            return True
        if n.startswith(s) and len(n) > len(s) and (n[len(s)] in "-." or n[len(s)].isdigit()):
            return True
    return False


def _kind_of_installed(label: str, inv: dict) -> tuple[str, str] | None:
    """('pkg', name) | ('snap', name) | ('image', ref) for the strings candidate() returns, or None for the kernel and other special cases."""
    if label.startswith("snap "):
        return "snap", label[5:].split()[0]
    if label.startswith("container image "):
        return "image", label[len("container image "):].split()[0]
    n = label.split(" ")[0]
    if n in inv["packages"]:
        return "pkg", n
    return None


def feed_matches(inv: dict, entries: list[dict], candidate) -> dict[tuple[str, str], list[str]]:
    """Which installed items (kind, name) the CISA feed links to, with the CVE ids: the tool's own matcher decides, so the block and a scan agree."""
    out: dict[tuple[str, str], list[str]] = {}
    for r in entries:
        m = candidate({"cve": r["id"], "vendor": r.get("vendor", ""), "product": r.get("product", "")}, inv)
        if not m:
            continue
        for label in m[1]:
            k = _kind_of_installed(label, inv)
            if k:
                out.setdefault(k, [])
                if r["id"] not in out[k] and len(out[k]) < 3:
                    out[k].append(r["id"])
    return out


def build(inv: dict, ports: list[dict], posture: dict | None, matches: dict[tuple[str, str], list[str]] | None, feed_state: str, taken: str,
          tool_version: str, max_lines: int = MAX_LINES) -> str:
    """The block. Deterministic: the same inventory gives the same text."""
    pk, snaps, images = inv.get("packages", {}), inv.get("snaps", {}), list(inv.get("images", []))
    matches = matches or {}
    cand: list[tuple[int, str, str]] = []          # (priority, sort key, line)

    def add(prio: int, key: str, line: str) -> None:
        cand.append((prio, key, line))

    kernel = clean_version(inv.get("kernel", ""))
    if kernel:
        add(0, "kernel", f"kernel {kernel} why=kernel")
    listeners = sorted({(p.get("proto", "tcp"), p.get("addr", ""), int(p.get("port", 0))) for p in ports if isinstance(p.get("port"), int)})
    owners = {(p.get("proto", "tcp"), p.get("addr", ""), int(p["port"])): clean_name(p.get("package") or p.get("owner") or "") for p in ports if isinstance(p.get("port"), int)}
    listen_pkgs = {o for o in owners.values() if o in pk}
    for name in sorted(listen_pkgs):
        ports_of = sorted({f"{proto}/{port}" for (proto, _a, port), o in owners.items() if o == name})
        why = ",".join(f"listen:{x}" for x in ports_of[:3]) + (f",+{len(ports_of) - 3}" if len(ports_of) > 3 else "")
        add(1, "pkg " + name, f"pkg {clean_name(name)} {clean_version(pk[name])} why={why}")
    for (kind, name), ids in sorted(matches.items()):
        if kind == "pkg" and name in pk and name not in listen_pkgs:
            add(2, "pkg " + name, f"pkg {clean_name(name)} {clean_version(pk[name])} why=cisa:{ids[0]}")
        elif kind == "snap" and name in snaps:
            add(2, "snap " + name, f"snap {clean_name(name)} {clean_version(snaps[name])} why=cisa:{ids[0]}")
        elif kind == "image":
            add(2, "image " + name, f"image {clean_field(name.split('@')[0])} why=cisa:{ids[0]}")
    for ref in sorted(images):
        r = clean_field(ref.split("@")[0])
        if ("image", ref) not in matches:
            add(3, "image " + r, f"image {r} why=image")
    for name in sorted(snaps):
        if ("snap", name) not in matches:
            add(4, "snap " + name, f"snap {clean_name(name)} {clean_version(snaps[name])} why=snap")
    per_stem: dict[str, int] = {}
    curated_n = 0
    for name in sorted(pk, key=lambda n: (len(n), n)):                   # the shortest name of a family first: nginx before nginx-extras
        if name in listen_pkgs or ("pkg", name) in matches or not is_curated(name) or name.lower().endswith(_SKIP_SUFFIX):
            continue
        stem = next((s for s in CURATED if name.lower() == s or (name.lower().startswith(s) and len(name) > len(s) and (name[len(s)] in "-." or name[len(s)].isdigit()))), name)
        if per_stem.get(stem, 0) >= PER_STEM or curated_n >= CURATED_BUDGET:
            continue
        per_stem[stem] = per_stem.get(stem, 0) + 1
        curated_n += 1
        add(5, "pkg " + name, f"pkg {clean_name(name)} {clean_version(pk[name])} why=curated")
    seen: set[str] = set()
    lines: list[str] = []
    cap = max(10, min(max_lines, MAX_LINES))
    listen_cap = min(20, max(2, (cap - 14) // 3))                # the listening lines share the cap with the items: a small cap keeps fewer of both
    for _p, _k, line in sorted(cand):
        if line in seen:
            continue
        seen.add(line)
        lines.append(line)
    total_known = len(pk) + len(snaps) + len(images) + (1 if kernel else 0)
    head = [
        "LATTICE INVENTORY v1", f"tool: lattice-scan {clean_field(tool_version)}", f"taken: {clean_field(taken)}", f"os: {clean_text(inv.get('os', '')) or 'unknown'}",
        f"kernel: {kernel or 'unknown'}", f"arch: {clean_text((inv.get('host') or {}).get('arch', '')) or 'unknown'}",
        f"counts: packages {len(pk)}, snaps {len(snaps)}, images {len(images)}, listening {len(listeners)}", f"feed: {clean_text(feed_state)}",
        f"items: 0 of {total_known} shown (kernel, listening, CISA-feed matches, images, snaps, curated, in that order)", "--"]
    tail = ["--"]
    shown_listen: set[str] = set()
    for proto, addr, port in listeners:
        bind = "all" if addr in ("0.0.0.0", "::", "") else "loopback" if addr.startswith("127.") or addr == "::1" else "address"
        o = owners.get((proto, addr, port), "")
        line = f"listen {proto} {bind}:{port}" + (f" owner={o}" if o else "")
        if line in shown_listen or len(shown_listen) >= listen_cap:
            continue
        shown_listen.add(line)
        tail.append(line)
    if posture:
        fw = ",".join(f"{clean_field(m['name'])}:{'active' if m.get('enabled') else 'inactive'}" for m in (posture.get("firewall") or {}).get("managers", []) if isinstance(m, dict) and m.get("name"))
        st = (posture.get("ssh") or {}).get("settings") or {}
        bits = [f"firewall={fw or 'unknown'}"] + [f"ssh.{k}={clean_field(v)}" for k, v in sorted(st.items()) if k in ("permitrootlogin", "passwordauthentication", "port")]
        tail.append("posture: " + " ".join(bits))
    tail.append("end")
    shown = lines[:max(0, cap - len(head) - len(tail))]
    head[8] = f"items: {len(shown)} of {total_known} shown (kernel, listening, CISA-feed matches, images, snaps, curated, in that order)"
    text = "\n".join(head + shown + tail) + "\n"
    while len(text.encode()) > MAX_BYTES and shown:           # the byte cap wins over the line count
        shown.pop()
        head[8] = f"items: {len(shown)} of {total_known} shown (kernel, listening, CISA-feed matches, images, snaps, curated, in that order)"
        text = "\n".join(head + shown + tail) + "\n"
    return text
