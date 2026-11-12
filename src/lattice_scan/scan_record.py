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

SCHEMA = 2
MAX_BYTES = 1024 * 1024
TOP_FIELDS = ("schema", "level", "os", "inventory", "items", "cut")
INVENTORY_FIELDS = ("kernel", "os", "manager", "node", "restartRequired", "host", "packages", "snaps", "images", "imageDetails")
HOST_FIELDS = ("manufacturer", "model", "version", "family", "boardVendor", "board", "boardVersion", "biosVendor", "biosVersion", "biosDate", "chassis", "cpu", "arch")
IMAGE_FIELDS = ("id", "os", "osVersion", "packages")
ITEM_FIELDS = ("cve", "product", "version", "verdict", "priority", "why", "installed", "listed", "due")
MAX_STR = 300
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
_PATH = re.compile(r"(?:^|[\s\"'=])/(?:home|root|etc|usr|var|tmp|opt|mnt|srv|proc|sys|run)/")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


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


def _size(r: dict) -> int:
    return len(json.dumps(r, separators=(",", ":")).encode())


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
    scrubbed = json.loads(json.dumps(r))
    scrubbed.get("inventory", {}).pop("images", None)                      # image names may name an internal registry: sent by the owner's decision
    for d in scrubbed.get("inventory", {}).get("imageDetails", {}).values():
        d.pop("packages", None)
    scrubbed.get("inventory", {})["imageDetails"] = {}
    text = json.dumps(scrubbed, ensure_ascii=False)
    for what, rx in (("a MAC address", _MAC), ("a file path", _PATH)):
        m = rx.search(text)
        if m:
            raise ValueError(f"the scan record holds {what}: {m.group(0).strip()[:40]}")


def build_record(inv: dict, items: list[dict], level: str, os_name: str, max_bytes: int = MAX_BYTES) -> dict:
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
