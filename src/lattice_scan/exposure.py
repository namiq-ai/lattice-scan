# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The exposure label of a finding: what the machine does with the matched software, as a fact. Pure functions over the posture data; nothing here reads
the host or sends anything.

A label is never "reachable from the internet": NAT, upstream firewalls and cloud rules are unknown. It says what this machine shows locally.
"""
from __future__ import annotations

import re

# Order is the ranking order (most exposed first). The class is what `--exposed` and `--fail-on exposed` compare.
CLASSES = ("all", "service", "loopback", "installed", "image", "unknown")
RANK = {c: i for i, c in enumerate(CLASSES)}
EXPOSED = {"all", "service"}   # --exposed keeps software that listens on all interfaces or runs as a service


def package_names(installed: list[str], packages: dict) -> list[str]:
    """Package names behind the 'name version' strings a candidate lists, found by the longest installed name that starts the string."""
    out = []
    for s in installed:
        if s.startswith(("snap ", "container image ", "kernel ")):
            continue
        best = max((n for n in packages if s == n or s.startswith(n + " ")), key=len, default="")
        if best:
            out.append(best)
    return sorted(set(out))


def label(installed: list[str], packages: dict, post: dict | None) -> dict:
    """{'class', 'text', 'listeners'} for one finding. `post` is posture.collect() output, or None when it could not be read."""
    if any(s.startswith("container image ") for s in installed) and not any(not s.startswith("container image ") for s in installed):
        return {"class": "image", "text": "inside a container image", "listeners": []}
    if post is None:
        return {"class": "unknown", "text": "not read: the running layer could not be collected", "listeners": []}
    names = set(package_names(installed, packages))
    snaps = {s[5:].split(" ")[0] for s in installed if s.startswith("snap ")}
    if not names and not snaps:
        return {"class": "installed", "text": "no package to join with the running layer", "listeners": []}
    ports = [p for p in post.get("ports") or [] if isinstance(p, dict)]
    mine = [p for p in ports if (p.get("package") in names) or (snaps and p.get("where") == "snap" and p.get("process") in snaps)]
    wide = [p for p in mine if p.get("bind") in ("all interfaces", "one address")]
    root = post.get("scope") == "root"
    fw = "" if root else " (firewall rules not read: needs root)"
    if wide:
        w = sorted(wide, key=lambda p: (p["bind"] != "all interfaces", p["port"]))[0]
        where = "all interfaces" if w["bind"] == "all interfaces" else "one address"
        owner = ", ".join(sorted(names)) or ", ".join(sorted(snaps))
        return {"class": "all", "text": f"listens on {where}: {w['addr']}:{w['port']}, owned by {owner}{fw}",
                "listeners": [f"{p['proto']}/{p['port']}" for p in wide]}
    if mine:
        return {"class": "loopback", "text": "listens on loopback only", "listeners": [f"{p['proto']}/{p['port']}" for p in mine]}
    units = [u for u in (post.get("services") or {}).get("units") or [] if isinstance(u, dict) and u.get("package") in names]
    if units:
        return {"class": "service", "text": "service running, no listener found (" + ", ".join(sorted(u["unit"] for u in units)) + ")", "listeners": []}
    return {"class": "installed", "text": "installed, no service or listener found", "listeners": []}


def sort_key(lbl: dict | None) -> int:
    return RANK.get((lbl or {}).get("class", "unknown"), len(CLASSES))


def coverage(post: dict | None) -> dict:
    """Blind spots as counts: processes and persistence entries no package owns cannot be matched by name. Only a deep posture run has them."""
    if post is None:
        return {"read": False}
    procs = [r for r in (post.get("processes") or {}).get("flagged") or [] if isinstance(r, dict) and not r.get("package") and not r.get("where")]
    pers = post.get("persistence") or {}
    unowned_pers = len(pers.get("cronFilesNoPackage") or []) + len(pers.get("suidNoPackage") or []) + len(pers.get("ldPreload") or [])
    return {"read": True, "scope": post.get("scope"), "deep": post.get("level") == "deep", "unownedProcesses": len(procs), "unownedPersistence": unowned_pers,
            "firewallRead": post.get("scope") == "root"}


def clean(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()
