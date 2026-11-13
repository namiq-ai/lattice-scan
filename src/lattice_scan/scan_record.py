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

# Report accuracy fields (an accepted change to the field list). They are on together with the mailed report (`scan_report_flow.MAIL_AVAILABLE`): the report is made from them.
# With it False the record is byte-identical to what earlier versions built, and check_record refuses the new fields.
REPORT_FIELDS_AVAILABLE = True
ITEM_FIELDS_NEW = ("assets", "distro", "basis", "changelog", "installedVersions")
TOP_FIELDS_NEW = ("coverage",)
ASSET_HOST = "host"
DISTRO_VERDICTS = ("fixed", "before-fix", "no-fix-yet", "not-affected", "unknown")
DISTRO_SOURCES = ("debian", "ubuntu", "alpine")
DISTRO_FIELDS = ("verdict", "fixedIn", "source")
BASIS_WORDS = ("identity", "name", "range")
CHANGELOG_WORDS = ("names", "none", "unchecked")
NOT_READ_WORDS = ("python-global", "node-global", "host-browser")
# what the run's own "not covered" statement says about software no package database lists; fixed words, never read from the host
NOT_CHECKED_WORDS = ("hand-built-software", "vendor-appliances", "firmware", "windows", "network-devices")
COVERAGE_FIELDS = ("identity", "name", "notChecked", "notRead")
_FIXED_IN = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+~:_-]{0,79}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
_PATH = re.compile(r"(?:^|[\s\"'=])/(?:home|root|etc|usr|var|tmp|opt|mnt|srv|proc|sys|run)/")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,}\b")
_WORD = re.compile(r"[a-z0-9-]{0,24}")
_NAME = re.compile(r"[\w.+@ -]{1,40}")


def _item_fields() -> tuple:
    return ITEM_FIELDS + ITEM_FIELDS_NEW if REPORT_FIELDS_AVAILABLE else ITEM_FIELDS


def _top_fields() -> tuple:
    return TOP_FIELDS + TOP_FIELDS_NEW if REPORT_FIELDS_AVAILABLE else TOP_FIELDS


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
    if REPORT_FIELDS_AVAILABLE:
        _item_report_fields(base, c)
    return base


def _parallel(c: dict, key: str, n: int) -> list | None:
    v = c.get(key)
    return v[:n] if isinstance(v, list) and n and len(v) >= n else None


def _distro_entry(e) -> dict:
    """One package's distribution status from the fixed vocabularies; anything else is 'unknown' with nothing else in it."""
    e = e if isinstance(e, dict) else {}
    v = _s(e.get("verdict"))
    src = _s(e.get("source"))
    fixed = _s(e.get("fixedIn"))
    if v not in DISTRO_VERDICTS or v == "unknown" or src not in DISTRO_SOURCES:
        return {"verdict": "unknown", "fixedIn": "", "source": ""}
    return {"verdict": v, "fixedIn": fixed if _FIXED_IN.fullmatch(fixed) else "", "source": src}


def _item_report_fields(base: dict, c: dict) -> None:
    n = len(base["installed"])
    assets = _parallel(c, "assets", n)
    if assets is not None:
        base["assets"] = [_s(a) for a in assets]
    versions = _parallel(c, "installedVersions", n)
    if versions is not None:
        base["installedVersions"] = [_s(v) for v in versions]
    distro = _parallel(c, "distro", n)
    if distro is not None:                       # present only after the person's yes to the distribution check; without it the key is absent
        base["distro"] = [_distro_entry(d) for d in distro]
    if _s(c.get("basis")) in BASIS_WORDS:
        base["basis"] = _s(c.get("basis"))
    if _s(c.get("changelog")) in CHANGELOG_WORDS:
        base["changelog"] = _s(c.get("changelog"))


def _coverage(c) -> dict | None:
    if not isinstance(c, dict):
        return None
    ident = max(0, min(100, _int(c.get("identity"))))
    return {"identity": ident, "name": max(0, min(100, _int(c.get("name", 100 - ident)))),
            "notChecked": [w for w in NOT_CHECKED_WORDS if w in (c.get("notChecked") or [])],
            "notRead": [w for w in NOT_READ_WORDS if w in (c.get("notRead") or [])]}


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
           "notRead": len(p.get("unreadable") or []), "secretsFound": sum(_int(x.get("count", 1)) for x in (p.get("localSecrets") or []) if isinstance(x, dict))}
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


def _check_item_report_fields(it: dict, details: dict) -> None:
    n = len(it.get("installed", []))
    for k in ("assets", "installedVersions", "distro"):
        if k in it and (not isinstance(it[k], list) or len(it[k]) != n):
            raise ValueError(f"a scan record item field is not parallel to installed: {k}")
    for a in it.get("assets", []):
        if a != ASSET_HOST and a not in details:
            raise ValueError("a scan record item asset is neither the host nor an image in the inventory")
    for d in it.get("distro", []):
        if not isinstance(d, dict) or set(d) != set(DISTRO_FIELDS):
            raise ValueError("a scan record distribution status has the wrong fields")
        if d["verdict"] not in DISTRO_VERDICTS:
            raise ValueError(f"a scan record distribution verdict is not on the list: {d['verdict']}")
        if d["verdict"] == "unknown":
            if d["source"] or d["fixedIn"]:
                raise ValueError("an unknown distribution status carries a source or version")
        elif d["source"] not in DISTRO_SOURCES or (d["fixedIn"] and not _FIXED_IN.fullmatch(d["fixedIn"])):
            raise ValueError("a scan record distribution status has a source or version that is not allowed")
    for k, words in (("basis", BASIS_WORDS), ("changelog", CHANGELOG_WORDS)):
        if k in it and it[k] not in words:
            raise ValueError(f"a scan record item {k} is not on the list: {it[k]}")


def _check_coverage(c: dict) -> None:
    if not isinstance(c, dict) or set(c) != set(COVERAGE_FIELDS):
        raise ValueError("the scan record coverage has the wrong fields")
    for k in ("identity", "name"):
        if not isinstance(c[k], int) or isinstance(c[k], bool) or not 0 <= c[k] <= 100:
            raise ValueError(f"the scan record coverage {k} is not a percentage")
    for k, words in (("notChecked", NOT_CHECKED_WORDS), ("notRead", NOT_READ_WORDS)):
        if not isinstance(c[k], list) or any(w not in words for w in c[k]):
            raise ValueError(f"the scan record coverage {k} holds a word that is not on the list")


def check_record(r: dict) -> None:
    """Raise ValueError naming the first field not on the declared lists, or the first forbidden value (MAC, path, address) outside image names."""
    for k in r:
        if k not in _top_fields():
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
            if k not in _item_fields():
                raise ValueError(f"field not allowed in a scan record item: {k}")
        if REPORT_FIELDS_AVAILABLE:
            _check_item_report_fields(it, inv.get("imageDetails", {}))
    if REPORT_FIELDS_AVAILABLE and "coverage" in r:
        _check_coverage(r["coverage"])
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


def build_record(inv: dict, items: list[dict], level: str, os_name: str, max_bytes: int = MAX_BYTES, posture: dict | None = None, coverage: dict | None = None) -> dict:
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
    if REPORT_FIELDS_AVAILABLE and coverage is not None and _coverage(coverage) is not None:
        r["coverage"] = _coverage(coverage)           # counts and words from fixed lists; absent when the run gave none
    if _size(r) > max_bytes:
        named = {n for i in its for n in i["installed"]}
        inv2 = r["inventory"]
        before = len(inv2["packages"]) + len(inv2["snaps"]) + len(inv2["images"]) + len(inv2["imageDetails"])
        inv2["packages"] = {k: v for k, v in inv2["packages"].items() if k in named}
        inv2["snaps"] = {k: v for k, v in inv2["snaps"].items() if k in named}
        inv2["images"] = [x for x in inv2["images"] if any(x in n or n in x for n in named)]
        inv2["imageDetails"] = {k: d for k, d in inv2["imageDetails"].items() if k in inv2["images"]}
        r["cut"] = before - (len(inv2["packages"]) + len(inv2["snaps"]) + len(inv2["images"]) + len(inv2["imageDetails"]))
    if REPORT_FIELDS_AVAILABLE:
        for i in its:                                  # an asset must be the host or an image the record still holds; after a cut, an item whose image was left out loses its assets
            if "assets" in i and any(a != ASSET_HOST and a not in r["inventory"]["imageDetails"] for a in i["assets"]):
                del i["assets"]
    check_record(r)
    return r
