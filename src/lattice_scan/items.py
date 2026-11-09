# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Which items of this machine are sent to Lattice, one at a time, to be checked (lattice-scan 0.7.0).

An item is a product name, a version, and optionally an ecosystem and the operating-system family. Nothing else leaves the machine: no hostname, path, address, port,
MAC address, user name or password, and not the package list as a whole. The server refuses anything outside the same patterns, and this module applies them first so
that a name that does not fit is dropped here, not sent.

Three levels (owner decision 2026-11-09):
  1. quick, no key: the machine itself (operating system, kernel, maker/model/firmware), the operating system of each image, and the posture layer (software that
     listens or runs as a service).
  2. with a key: the quick items, then the foundational packages (C library, TLS, SSH, systemd, sudo ...), then well-known server software, then every other package
     in name order, until the key's allowance ends. What was not sent is only counted: the packages left on the host and the packages inside images (only an image's
     operating system is sent).
  3. everything, in depth: the paid report. Not on sale yet.
Pure functions: nothing here reads the host or sends anything.
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


FOUNDATIONAL = ("libc6", "glibc", "libc-bin", "musl", "libssl3", "libssl1.1", "libssl-dev", "openssl", "openssh-server", "openssh-client", "openssh", "systemd", "udev", "dbus",
                "sudo", "bash", "zlib1g", "zlib", "libcurl4", "curl", "coreutils", "util-linux", "apt", "dpkg", "rpm", "libxml2", "libgnutls30", "gnutls", "gnupg", "gpg",
                "polkitd", "policykit-1", "polkit", "pkexec", "libgcrypt20", "libsqlite3-0", "sqlite", "python3", "perl", "glib2", "libglib2.0-0", "shadow", "login", "passwd",
                "busybox", "ncurses-base", "libpam0g", "pam", "grub-common", "grub2", "linux-base")


def _item_os(pretty: str) -> dict | None:
    """The operating system itself as an item: 'ubuntu' 26.04 (name lowercase, number only). Used for the host and for the base of an image."""
    lbl = os_label(pretty)
    if not lbl:
        return None
    fam, _, num = lbl.rpartition(" ")
    return make(fam.split()[0].lower(), num, "", lbl)


def select(inv: dict, post: dict | None, *, level: str = "quick", also: tuple[str, ...] = (), limit: int = 60) -> dict:
    """{'items': [...], 'why': {...}, 'skipped': n, 'cut': n, 'unscanned': {'host': n, 'images': n}}.

    level 'quick' (no key): operating system, kernel, hardware, image operating systems, then what listens or runs as a service.
    level 'key': those, then foundational packages, well-known server software, `also`, then every other package in name order. `limit` cuts the list; whatever is
    not in it is counted in `unscanned`, never sent. The same product is never listed twice."""
    pk = {clean_name(n): v for n, v in (inv.get("packages") or {}).items() if clean_name(n)}
    snaps = inv.get("snaps") or {}
    eco = ECOSYSTEM_OF_MANAGER.get(inv.get("manager") or "", "")
    osn = os_label(inv.get("os") or "")
    listen, svc = listening_packages(post)
    items: list[dict] = []
    why: dict[str, str] = {}
    seen: set[str] = set()
    skipped = 0

    def add(it: dict | None, reason: str) -> None:
        nonlocal skipped
        if it is None:
            skipped += 1
            return
        key = it["product"] + "|" + it.get("kind", "") + "|" + it.get("version", "")
        if key in seen:
            return
        seen.add(key)
        items.append(it)
        why[describe(it)] = reason

    add(_item_os(inv.get("os") or ""), "this machine's operating system") if inv.get("os") else None
    k = inv.get("kernel") or ""
    if k:
        add(make("linux", k, "", osn, "kernel"), "the running kernel")
    h = inv.get("host") or {}
    model, maker = str(h.get("model") or ""), str(h.get("manufacturer") or "")
    if model and maker:
        ver = str(h.get("biosVersion") or h.get("version") or "")
        # the maker's full name often does not fit the plain-name rule ("Example Corp (HK) Ltd"); then only the model is sent, never a cleaned-up guess of the maker
        add(make(model.replace(" ", "-"), ver, "", "", "hardware", maker) or make(model.replace(" ", "-"), ver, "", "", "hardware"), "this machine's maker and model")
    for ref, d in sorted((inv.get("imageDetails") or {}).items()):
        if isinstance(d, dict) and d.get("os"):
            add(_item_os(f"{d.get('os')} {d.get('osVersion') or ''}"), "the operating system of a container image")

    def pkg(name: str, reason: str) -> None:
        if name.startswith("snap "):
            n, ver, e = clean_name(name[5:]), snaps.get(name[5:], ""), ""
        else:
            n, ver, e = clean_name(name), pk.get(clean_name(name), ""), eco
        if n:
            add(make(n, ver, e, osn), reason)

    for n in listen:
        pkg(n, "listens on this machine")
    for n in svc:
        pkg(n, "runs as a service")
    if level == "key":
        for n in FOUNDATIONAL:
            if n in pk:
                pkg(n, "foundational package")
        for n in sorted(pk):
            if n in CURATED or n in also:
                pkg(n, "well-known server software")
        for n in sorted(pk):
            pkg(n, "installed")
    cut = max(0, len(items) - limit)
    sent = items[:limit]
    sent_pk = {it["product"] for it in sent if "kind" not in it}
    unscanned_host = sum(1 for n in pk if n not in sent_pk) + sum(1 for n in snaps if clean_name(n) not in sent_pk)
    unscanned_images = sum(len((d or {}).get("packages") or {}) for d in (inv.get("imageDetails") or {}).values() if isinstance(d, dict))
    return {"items": sent, "skipped": skipped, "why": why, "cut": cut, "unscanned": {"host": unscanned_host, "images": unscanned_images}}


def describe(it: dict) -> str:
    """One line of exactly what is sent for an item."""
    return " ".join(f"{k}={it[k]}" for k in ("product", "version", "ecosystem", "os", "kind", "vendor") if k in it)


# The posture signals (stable codes of posture.py) are sent one at a time to `graph_exposure`.
SIGNAL = re.compile(r"^[a-z]{2,12}\.[a-z0-9]+(-[a-z0-9]+){0,4}$")


def signals(post_data: dict) -> list[str]:
    """The distinct signal codes found in a posture report, sorted. A code that does not look like one is dropped."""
    return sorted({str(o["code"]) for o in post_data.get("observations") or [] if isinstance(o, dict) and SIGNAL.fullmatch(str(o.get("code") or ""))})
