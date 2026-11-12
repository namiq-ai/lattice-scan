# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The scan report payload (ADR-LATTICE-SCAN-REPORT-001 D1; OCO-6052 and OCO-6053).

One function, `build_payload`, makes the only object that may ever describe a scan to anything outside the machine: the
preview the person reads, the file written locally and (later, once the gates are answered) the bytes sent all come from it.
Nothing here talks to the network and nothing here sends anything.

The payload holds the CVE id, the product name as the graph names it, the installed UPSTREAM version, the tool's verdict word,
the scan level and the operating-system family. Never a hostname, address, port, MAC, user, path, image name, release
codename, kernel build or a distribution version string that can carry a build host. The field list is declared below and
`check_payload` fails, naming the field, when anything else is there, so a convenient extra field cannot be added quietly.
"""
from __future__ import annotations

import json
import re

SCHEMA = 1
MAX_ITEMS = 50          # starting values of D1; changed only together with a test and the ADR
MAX_BYTES = 32 * 1024
TOP_FIELDS = ("schema", "level", "os", "items", "cut")          # level and os are two of the six fields; schema and cut are structure, not host data
ITEM_FIELDS = ("cve", "product", "version", "verdict")          # with level and os: the six fields
VERDICTS = ("in-range", "undetermined", "outside-range", "lead", "not-read")
LEVELS = ("quick", "deep")
OS_FAMILIES = ("Debian", "RedHat", "SUSE", "Alpine", "Arch", "Windows", "macOS", "Other")
PRIORITY_RANK = {"fix first": 0, "fix soon": 1, "read": 2}      # the tool's own ordering words; used to choose what to keep, never sent
VERDICT_RANK = {v: i for i, v in enumerate(VERDICTS)}

_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_UPSTREAM = re.compile(r"^(?:\d+:)?(\d+(?:\.\d+)*(?:p\d+|rc\d+|[ab]\d+|[a-z](?![a-z]))?)")
_CONTROL = re.compile(r"[\x00-\x1f\x7f<>`]")


def upstream_version(raw: str) -> str:
    """The upstream number of a package version: no epoch, and nothing after the first '-', '+', '~' or '_'. A build host in a
    distribution string (3.0.2-0ubuntu1+build.host.example) goes with the part that is cut. Empty when no number is found."""
    m = _UPSTREAM.match((raw or "").strip())
    return m.group(1) if m else ""


def os_family(os_id: str = "", id_like: str = "", system: str = "") -> str:
    """One word from a closed list, from the os-release ID and ID_LIKE or the platform name. The release, codename and kernel never go in."""
    s = (system or "").lower()
    if s == "windows":
        return "Windows"
    if s == "darwin":
        return "macOS"
    ids = set((os_id or "").lower().split()) | set((id_like or "").lower().split())
    for fam, keys in (("Alpine", {"alpine"}), ("Debian", {"debian", "ubuntu", "raspbian"}), ("RedHat", {"rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn"}),
                      ("SUSE", {"suse", "sles", "opensuse", "opensuse-leap", "opensuse-tumbleweed"}), ("Arch", {"arch", "manjaro"})):
        if ids & keys:
            return fam
    return "Other"


def _item(c: dict) -> dict | None:
    cve = str(c.get("cve", "")).strip().upper()
    verdict = str(c.get("verdict", "")).strip().lower()
    if not _CVE.match(cve) or verdict not in VERDICTS:
        return None
    return {"cve": cve, "product": _CONTROL.sub("", str(c.get("product", "")))[:120].strip(),
            "version": upstream_version(str(c.get("version", ""))), "verdict": verdict}


def _rank(c: dict) -> tuple[int, int]:
    return (PRIORITY_RANK.get(str(c.get("priority", "")).strip().lower(), 3), VERDICT_RANK.get(str(c.get("verdict", "")).strip().lower(), 9))


def check_payload(p: dict) -> None:
    """Raise ValueError naming the first field that is not on the declared list. Called by build_payload and by the tests."""
    extra = [k for k in p if k not in TOP_FIELDS]
    if extra:
        raise ValueError(f"field not allowed in the report payload: {extra[0]}")
    for it in p.get("items", []):
        extra = [k for k in it if k not in ITEM_FIELDS]
        if extra:
            raise ValueError(f"field not allowed in a report payload item: {extra[0]}")


def build_payload(candidates: list[dict], level: str, os_name: str, max_items: int = MAX_ITEMS, max_bytes: int = MAX_BYTES) -> dict:
    """From scan candidates (each a dict with at least cve, product, version, verdict, and optionally the tool's `priority` word; any other key is ignored).

    Above the cap the highest-priority items are kept (fix first, then fix soon, then read, then by verdict) and `cut` says how many were dropped.
    """
    ranked = sorted((c for c in candidates if isinstance(c, dict)), key=_rank)       # stable: equal rank keeps the scan's own order
    items, seen = [], set()
    for c in ranked:
        it = _item(c)
        key = (it["cve"], it["product"]) if it else None
        if it and key not in seen:
            seen.add(key)
            items.append(it)
    total = len(items)
    items = items[:max(0, max_items)]
    p = {"schema": SCHEMA, "level": level if level in LEVELS else "quick", "os": os_name if os_name in OS_FAMILIES else "Other", "items": items, "cut": total - len(items)}
    while p["items"] and len(json.dumps(p, separators=(",", ":")).encode()) > max_bytes:
        p["items"].pop()
        p["cut"] += 1
    check_payload(p)
    return p
