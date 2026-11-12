# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The scan record a person may choose to send with a report request (ADR-LATTICE-SCAN-REPORT-001 D1, owner decision U1 = C of 2026-11-12).

One function, `build_record`, makes the only object that describes a scan to anything outside the machine: the preview, the local copy and (once
the gates are answered) the bytes sent all come from it. It holds the inventory the tool already writes (image names included) and the items of the run.
It never holds a hostname, address, port, MAC, user name, password or key, a file path, environment variables, process lists, posture data or the debug
log: the inventory is read by picking declared keys, so a key that is not on the list cannot get in, and `check_record` fails, naming the field, if one did.
Nothing here talks to the network and nothing here sends anything.
"""
from __future__ import annotations

import json
import re

from . import scan_report as sr

SCHEMA = 2                       # a record without a posture block
SCHEMA_POSTURE = 3               # a record with one: the server reads the schema to know which field list applies
MAX_BYTES = 1024 * 1024
TOP_FIELDS = ("schema", "level", "os", "inventory", "items", "cut", "posture")
INVENTORY_FIELDS = ("kernel", "os", "manager", "node", "restartRequired", "host", "packages", "snaps", "images", "imageDetails")
HOST_FIELDS = ("manufacturer", "model", "version", "family", "boardVendor", "board", "boardVersion", "biosVendor", "biosVersion", "biosDate", "chassis", "cpu", "arch")
IMAGE_FIELDS = ("id", "os", "osVersion", "packages")
ITEM_FIELDS = ("cve", "product", "version", "verdict", "priority", "why", "installed", "listed", "due")
POSTURE_FIELDS = ("scope", "level", "ports", "firewall", "ssh", "programs", "persistence", "notRead", "secretsFound")
PORT_FIELDS = ("proto", "port", "bind", "process", "packaged", "where")
FIREWALL_FIELDS = ("readable", "managers", "iptables", "nftables")
MANAGER_FIELDS = ("name", "enabled", "defaultIncoming", "rules")
POLICY_FIELDS = ("rules", "inputPolicy")
SSH_OUT_FIELDS = ("installed", "passwordauthentication", "permitrootlogin", "port")
PROGRAM_FIELDS = ("name", "location", "kind")
PERSISTENCE_FIELDS = ("ldPreload", "extraUid0Users", "cronFilesNoPackage", "suidNoPackage", "timers")
BINDS = ("all interfaces", "loopback only", "one address")
WHERE = ("", "container", "snap", "flatpak")
MAX_PORTS = 300
MAX_PROGRAMS = 100
MAX_STR = 300
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
_PATH = re.compile(r"(?:^|[\s\"'=])/(?:home|root|etc|usr|var|tmp|opt|mnt|srv|proc|sys|run)/")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,}\b")
_WORD = re.compile(r"[a-z0-9-]{0,24}")
_NAME = re.compile(r"[\w.+@ -]{1,40}")


def _s(v) -> str:
    return _CONTROL.sub("", str(v if v is not None else ""))[:MAX_STR].strip()


def _versions(d) -> dict[str, str]:
    return {_s(k): _s(v) for k, v in (d or {}).items() if isinstance(d, dict) and _s(k)}


def _item(c: dict) -> dict | None:
    base = sr._item(c)                                   # id, product, upstream version and verdict, as in the six-field payload
    if base is None:
        return None
    base["priority"] = _s(c.get("priority", "read")) if _s(c.get("priority", "read")) in sr.PRIORITY_RANK else "read"
    base["why"] = [_s(w) for w in (c.get("why") or [])][:8]
    base["installed"] = [_s(n) for n in (c.get("installed") or [])][:10]
    base["listed"] = _s(c.get("listed"))[:10]
    base["due"] = _s(c.get("due"))[:10]
    return base


def _inventory(inv: dict) -> dict:
    host = inv.get("host") if isinstance(inv.get("host"), dict) else {}
    details = inv.get("imageDetails") if isinstance(inv.get("imageDetails"), dict) else {}
    out = {"kernel": _s(inv.get("kernel")), "os": _s(inv.get("os")), "manager": _s(inv.get("manager")), "node": _s(inv.get("node")),
           "restartRequired": bool(inv.get("restartRequired")),
           "host": {k: _s(host[k]) for k in HOST_FIELDS if host.get(k)},
           "packages": _versions(inv.get("packages")), "snaps": _versions(inv.get("snaps")),
           "images": [_s(r) for r in (inv.get("images") or []) if _s(r)],
           "imageDetails": {_s(r): {"id": _s(d.get("id")), "os": _s(d.get("os")), "osVersion": _s(d.get("osVersion")), "packages": _versions(d.get("packages"))}
                            for r, d in details.items() if isinstance(d, dict) and _s(r)}}
    return out


def _word(v) -> str:
    w = _s(v).lower()
    return w if _WORD.fullmatch(w) else ""


def _int(v) -> int:
    try:
        return max(0, min(int(v), 10_000_000))
    except (TypeError, ValueError):
        return 0


def _where(w) -> str:
    w = _s(w)
    return "" if not w else "snap" if w == "snap" else "flatpak" if w == "flatpak" else "container"


def _location(exe: str) -> str:
    if exe.startswith(("/home/", "/root/")):
        return "home"
    if exe.startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/run/shm/")):
        return "temporary"
    return "other"


def posture_block(p: dict) -> dict:
    """The optional posture block (owner decision of 2026-11-12), built by picking declared keys from `posture.collect()`'s result.
    It holds no address (a listening socket says only how widely it is open), no pid, no path, no command line, no user name, no container name, no firewall rule,
    no history and no secret: the posture result holds some of those, so every value is copied by name and `check_record` refuses anything else."""
    p = p if isinstance(p, dict) else {}
    ports = []
    for r in (p.get("ports") or [])[:MAX_PORTS]:
        if not isinstance(r, dict) or r.get("bind") not in BINDS:
            continue
        name = _s(r.get("process"))
        ports.append({"proto": "udp" if str(r.get("proto", "")).startswith("udp") else "tcp", "port": min(_int(r.get("port")), 65535), "bind": r["bind"],
                      "process": name if _NAME.fullmatch(name) else ("?" if name else ""), "packaged": bool(r.get("package")), "where": _where(r.get("where"))})
    fw = p.get("firewall") if isinstance(p.get("firewall"), dict) else {}
    managers = [{"name": _word(m.get("name")), "enabled": m.get("enabled") if isinstance(m.get("enabled"), bool) else None,
                 "defaultIncoming": _word(m.get("defaultIncoming")), "rules": _int(m.get("rules"))} for m in (fw.get("managers") or []) if isinstance(m, dict)][:8]
    firewall = {"readable": bool(fw.get("readable")), "managers": managers}
    for k in ("iptables", "nftables"):
        if isinstance(fw.get(k), dict):
            firewall[k] = {"rules": _int(fw[k].get("rules")), "inputPolicy": _word(fw[k].get("inputPolicy"))}
    ssh_in = p.get("ssh") if isinstance(p.get("ssh"), dict) else {}
    st = ssh_in.get("settings") if isinstance(ssh_in.get("settings"), dict) else {}
    ssh = {"installed": bool(ssh_in.get("installed")), "passwordauthentication": _word(st.get("passwordauthentication")),
           "permitrootlogin": _word(st.get("permitrootlogin")), "port": _word(st.get("port"))}
    out = {"scope": "root" if p.get("scope") == "root" else "user", "level": "deep" if p.get("level") == "deep" else "quick", "ports": ports, "firewall": firewall, "ssh": ssh,
           "notRead": len(p.get("unreadable") or []), "secretsFound": len(p.get("localSecrets") or [])}
    if p.get("level") == "deep":
        progs = []
        for g in ((p.get("processes") or {}).get("flagged") or []):
            if isinstance(g, dict) and not g.get("package") and not g.get("where"):
                name = _s(g.get("name"))
                progs.append({"name": name if _NAME.fullmatch(name) else "?", "location": _location(str(g.get("exe") or "")), "kind": _word(g.get("kind"))})
        pe = p.get("persistence") if isinstance(p.get("persistence"), dict) else {}
        out["programs"] = progs[:MAX_PROGRAMS]
        out["persistence"] = {"ldPreload": len(pe.get("ldPreload") or []), "extraUid0Users": len(pe.get("extraUid0Users") or []),
                              "cronFilesNoPackage": len(pe.get("cronFilesNoPackage") or []), "suidNoPackage": len(pe.get("suidNoPackage") or []), "timers": _int(pe.get("timers"))}
    return out


def _size(r: dict) -> int:
    return len(json.dumps(r, separators=(",", ":")).encode())


def _keys(d, allowed: tuple, what: str) -> None:
    if not isinstance(d, dict):
        raise ValueError(f"the scan record {what} is not an object")
    for k in d:
        if k not in allowed:
            raise ValueError(f"field not allowed in the scan record {what}: {k}")


def _check_posture(ps: dict) -> None:
    """Every key of the posture block is on a declared list, and no value looks like an address, a MAC or a file path."""
    _keys(ps, POSTURE_FIELDS, "posture")
    for row in ps.get("ports", []):
        _keys(row, PORT_FIELDS, "posture port")
    fw = ps.get("firewall", {})
    _keys(fw, FIREWALL_FIELDS, "posture firewall")
    for m in fw.get("managers", []):
        _keys(m, MANAGER_FIELDS, "posture firewall manager")
    for k in ("iptables", "nftables"):
        if k in fw:
            _keys(fw[k], POLICY_FIELDS, f"posture {k}")
    _keys(ps.get("ssh", {}), SSH_OUT_FIELDS, "posture ssh")
    for g in ps.get("programs", []):
        _keys(g, PROGRAM_FIELDS, "posture program")
    if "persistence" in ps:
        _keys(ps["persistence"], PERSISTENCE_FIELDS, "posture persistence")
    text = json.dumps(ps, ensure_ascii=False)
    for what, rx in (("a MAC address", _MAC), ("a file path", _PATH), ("an address", _IPV4), ("an address", _IPV6)):
        m = rx.search(text)
        if m:
            raise ValueError(f"the posture block holds {what}: {m.group(0).strip()[:40]}")


def check_record(r: dict) -> None:
    """Raise ValueError naming the first field not on the declared lists, or the first forbidden value (MAC, path, address) outside image names."""
    for k in r:
        if k not in TOP_FIELDS:
            raise ValueError(f"field not allowed in the scan record: {k}")
    inv = r.get("inventory", {})
    for k in inv:
        if k not in INVENTORY_FIELDS:
            raise ValueError(f"field not allowed in the scan record inventory: {k}")
    for k in inv.get("host", {}):
        if k not in HOST_FIELDS:
            raise ValueError(f"field not allowed in the scan record host data: {k}")
    for ref, d in inv.get("imageDetails", {}).items():
        for k in d:
            if k not in IMAGE_FIELDS:
                raise ValueError(f"field not allowed in a scan record image entry: {k}")
    for it in r.get("items", []):
        for k in it:
            if k not in ITEM_FIELDS:
                raise ValueError(f"field not allowed in a scan record item: {k}")
    ps = r.get("posture")
    if ps is not None:
        _check_posture(ps)
    scrubbed = json.loads(json.dumps({k: v for k, v in r.items() if k != "posture"}))
    scrubbed.get("inventory", {}).pop("images", None)                      # image names may name an internal registry: sent by the owner's decision
    for d in scrubbed.get("inventory", {}).get("imageDetails", {}).values():
        d.pop("packages", None)
    scrubbed.get("inventory", {})["imageDetails"] = {}
    text = json.dumps(scrubbed, ensure_ascii=False)
    for what, rx in (("a MAC address", _MAC), ("a file path", _PATH)):
        m = rx.search(text)
        if m:
            raise ValueError(f"the scan record holds {what}: {m.group(0).strip()[:40]}")


def build_record(inv: dict, items: list[dict], level: str, os_name: str, max_bytes: int = MAX_BYTES, posture: dict | None = None) -> dict:
    """`inv` is the scan's inventory; `items` the candidates (cve, product, version, verdict, priority, why, installed, listed, due; other keys are ignored).

    Above `max_bytes` the record keeps the hardware and OS fields, the items and only the packages, snaps and images the items name, and `cut` says how many entries
    were left out; nothing is cut silently and the preview says so."""
    built = [i for i in (_item(c) for c in sorted((c for c in items if isinstance(c, dict)), key=sr._rank)) if i]
    seen, its = set(), []
    for i in built:
        if (i["cve"], i["product"]) not in seen:
            seen.add((i["cve"], i["product"]))
            its.append(i)
    r = {"schema": SCHEMA, "level": level if level in sr.LEVELS else "quick", "os": os_name if os_name in sr.OS_FAMILIES else "Other",
         "inventory": _inventory(inv or {}), "items": its, "cut": 0}
    if posture is not None:
        r["schema"] = SCHEMA_POSTURE
        r["posture"] = posture_block(posture)         # only when the person said yes to the second question; without it the key is absent
    if _size(r) > max_bytes:
        named = {n for i in its for n in i["installed"]}
        inv2 = r["inventory"]
        before = len(inv2["packages"]) + len(inv2["snaps"]) + len(inv2["images"]) + len(inv2["imageDetails"])
        inv2["packages"] = {k: v for k, v in inv2["packages"].items() if k in named}
        inv2["snaps"] = {k: v for k, v in inv2["snaps"].items() if k in named}
        inv2["images"] = [x for x in inv2["images"] if any(x in n or n in x for n in named)]
        inv2["imageDetails"] = {k: d for k, d in inv2["imageDetails"].items() if k in inv2["images"]}
        r["cut"] = before - (len(inv2["packages"]) + len(inv2["snaps"]) + len(inv2["images"]) + len(inv2["imageDetails"]))
    check_record(r)
    return r
