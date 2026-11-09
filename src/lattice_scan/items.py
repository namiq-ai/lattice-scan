# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Which items of this machine are sent to Lattice, one at a time, to be checked (lattice-scan 0.7.0).

An item is a product name, a version, and optionally an ecosystem and the operating-system family. Nothing else leaves the machine: no hostname, path, address, port,
MAC address, user name or password, and not the package list as a whole. The server refuses anything outside the same patterns, and this module applies them first so
that a name that does not fit is dropped here, not sent.

What is selected (the owner-approved proposal): the software that listens or runs as a service on this machine (the posture layer, tens of items), a short list of
well-known server software that is installed, and the running kernel. Packages that are merely installed are sent only when the person asks (`--all-installed`); the
machine's hardware only with `--with-hardware`. Pure functions: nothing here reads the host or sends anything.
"""
from __future__ import annotations

import re

# The same patterns as the server (graph_mcp/affects.py, lattice-item/1).
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
VERSION = re.compile(r"^[0-9A-Za-z.+~:_-]{1,64}$")
OS = re.compile(r"^[A-Za-z][A-Za-z0-9 ._-]{0,31}$")

# Well-known server software, matched against package names. Short on purpose: a person adds more with --also.
CURATED = frozenset("""
apache2 httpd nginx lighttpd caddy haproxy squid varnish tomcat tomcat9 tomcat10 jetty
openssh-server openssh-server-common openssl libssl3 libssl1.1 sudo
postgresql postgresql-16 postgresql-15 postgresql-14 mysql-server mysql-community-server mariadb-server redis-server redis mongodb-org-server memcached elasticsearch
exim4 exim4-daemon-light postfix dovecot-core sendmail
bind9 named unbound dnsmasq nsd powerdns
samba smbd vsftpd proftpd pure-ftpd openvpn wireguard-tools strongswan
docker-ce docker.io containerd runc kubelet
php php-fpm php8.3-fpm php8.2-fpm php8.1-fpm nodejs python3 perl ruby
cups cups-daemon avahi-daemon
""".split())

ECOSYSTEM_OF_MANAGER = {"dpkg": "deb", "rpm": "rpm", "apk": "apk"}


def os_label(pretty: str) -> str:
    """'Ubuntu 26.04 LTS (Resolute)' -> 'Ubuntu 26.04': the family and the version number, nothing that names the machine."""
    m = re.match(r"^\s*([A-Za-z][A-Za-z ]{0,24}?)\s+v?(\d+(?:\.\d+){0,2})", pretty or "")
    out = f"{m.group(1).strip()} {m.group(2)}" if m else ""
    return out if OS.fullmatch(out) else ""


def clean_name(name: str) -> str:
    """A package name as the server accepts it. The architecture suffix of dpkg ('libssl3:amd64') goes; a name that still does not fit is refused ('')."""
    n = (name or "").split(":", 1)[0]
    return n if NAME.fullmatch(n) else ""


def make(product: str, version: str, ecosystem: str = "", os_name: str = "", kind: str = "", vendor: str = "") -> dict | None:
    """One item, or None when any part does not fit the patterns."""
    p = clean_name(product)
    if not p:
        return None
    it = {"product": p}
    if version:
        if not VERSION.fullmatch(version):
            return None
        it["version"] = version
    if vendor:
        v = clean_name(vendor.replace(" ", "-"))
        if not v:
            return None
        it["vendor"] = v
    if ecosystem:
        it["ecosystem"] = ecosystem
    if os_name and OS.fullmatch(os_name):
        it["os"] = os_name
    if kind:
        it["kind"] = kind
    return it


def listening_packages(post: dict | None) -> tuple[list[str], list[str]]:
    """(packages that own a listener, packages that run as a service) from posture.collect(); snaps are 'snap NAME'. Both lists are sorted and unique."""
    if not post:
        return [], []
    listen, svc = set(), set()
    for p in post.get("ports") or []:
        if isinstance(p, dict):
            if p.get("package"):
                listen.add(str(p["package"]))
            elif p.get("where") == "snap" and p.get("process"):
                listen.add("snap " + str(p["process"]))
    for u in (post.get("services") or {}).get("units") or []:
        if isinstance(u, dict) and u.get("package"):
            svc.add(str(u["package"]))
    return sorted(listen), sorted(svc - listen)


def select(inv: dict, post: dict | None, *, all_installed: bool = False, with_hardware: bool = False, also: tuple[str, ...] = (), limit: int = 60) -> dict:
    """{'items': [...], 'skipped': n, 'why': {...}, 'cut': n}. Order (most useful first): what listens, what runs as a service, well-known server software, the kernel,
    then (only when asked) every other package and the hardware. The same product is never listed twice. `cut` counts items left out by `limit`."""
    pk = {clean_name(n): v for n, v in (inv.get("packages") or {}).items() if clean_name(n)}
    snaps = inv.get("snaps") or {}
    eco = ECOSYSTEM_OF_MANAGER.get(inv.get("manager") or "", "")
    osn = os_label(inv.get("os") or "")
    listen, svc = listening_packages(post)
    plan: list[tuple[str, str, str]] = []     # (name, version, reason)
    for n in listen:
        plan.append((n, "", "listens on this machine"))
    for n in svc:
        plan.append((n, "", "runs as a service"))
    for n in sorted(pk):
        if n in CURATED or n in also:
            plan.append((n, "", "well-known server software"))
    if all_installed:
        for n in sorted(pk):
            plan.append((n, "", "installed"))
    items: list[dict] = []
    why: dict[str, str] = {}
    seen: set[str] = set()
    skipped = 0
    for name, _v, reason in plan:
        if name.startswith("snap "):
            n, ver, e = clean_name(name[5:]), snaps.get(name[5:], ""), ""
        else:
            n, ver, e = clean_name(name), pk.get(clean_name(name), ""), eco
        if not n or n in seen:
            continue
        seen.add(n)
        it = make(n, ver, e, osn)
        if it is None:
            skipped += 1
            continue
        items.append(it)
        why[n] = reason
    k = inv.get("kernel") or ""
    if k and "linux" not in seen:
        it = make("linux", k, "", osn, "kernel")
        if it:
            items.append(it)
            why["linux"] = "the running kernel"
        else:
            skipped += 1
    if with_hardware:
        h = inv.get("host") or {}
        model, maker = str(h.get("model") or ""), str(h.get("manufacturer") or "")
        if model and maker:
            it = make(model.replace(" ", "-"), str(h.get("biosVersion") or h.get("version") or ""), "", "", "hardware", maker)
            if it:
                items.append(it)
                why[it["product"]] = "this machine's model"
            else:
                skipped += 1
    cut = max(0, len(items) - limit)
    return {"items": items[:limit], "skipped": skipped, "why": why, "cut": cut}


def describe(it: dict) -> str:
    """One line of exactly what is sent for an item."""
    return " ".join(f"{k}={it[k]}" for k in ("product", "version", "ecosystem", "os", "kind", "vendor") if k in it)


# The posture signals (stable codes of posture.py) are sent one at a time to `graph_exposure`.
SIGNAL = re.compile(r"^[a-z]{2,12}\.[a-z0-9]+(-[a-z0-9]+){0,4}$")


def signals(post_data: dict) -> list[str]:
    """The distinct signal codes found in a posture report, sorted. A code that does not look like one is dropped."""
    return sorted({str(o["code"]) for o in post_data.get("observations") or [] if isinstance(o, dict) and SIGNAL.fullmatch(str(o.get("code") or ""))})
