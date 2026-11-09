# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Local snapshots of what a host run saw, and the difference between two of them: what is new, changed or gone since the last run.

A snapshot names this host's listeners and software, so it lives in the private records folder (0600), is never sent anywhere, and is pruned by count.
Pure functions except `save` and `latest`, which take the folder."""
from __future__ import annotations

import json
import os
from pathlib import Path

SCHEMA = "lattice-snapshot/1"
KEEP = 30


def build(on: str, at: str, inv_hash: str, post: dict | None, findings: dict[str, dict]) -> dict:
    """`findings` maps a CVE id to {'installed': 'name version; ...', 'found': 'YYYY-MM-DD'}. A part the run could not read is None, not empty: nothing can
    be said to be gone from a part that was never read."""
    snap: dict = {"schema": SCHEMA, "on": on, "at": at, "inventory": inv_hash, "findings": findings, "scope": None, "deep": False,
                  "listeners": None, "services": None, "ssh": None, "persistence": None}
    if post is None:
        return snap
    snap["scope"], snap["deep"] = post.get("scope"), post.get("level") == "deep"
    snap["listeners"] = sorted({f"{p.get('proto')}/{p.get('port')} {p.get('bind')} {p.get('package') or p.get('process') or '?'}" for p in post.get("ports") or [] if isinstance(p, dict)})
    units = (post.get("services") or {}).get("units")
    snap["services"] = sorted({u["unit"] for u in units if isinstance(u, dict) and u.get("unit")}) if (post.get("services") or {}).get("available") else None
    st = (post.get("ssh") or {}).get("settings")
    snap["ssh"] = dict(sorted((str(k), str(v)) for k, v in st.items())) if st and snap["scope"] == "root" else None
    if post.get("level") == "deep" and isinstance(post.get("persistence"), dict):
        p = post["persistence"]
        snap["persistence"] = sorted([f"ld.so.preload {x}" for x in p.get("ldPreload") or []] + [f"uid0 {x}" for x in p.get("extraUid0Users") or []]
                                     + [f"cron {x}" for x in p.get("cronFilesNoPackage") or []] + [f"suid {x}" for x in p.get("suidNoPackage") or []])
    return snap


def diff(old: dict, new: dict) -> dict:
    """new / changed / gone per part, plus notes for parts that could not be compared (read in only one of the two runs)."""
    out: dict = {"since": old.get("on"), "parts": {}, "notes": []}
    for key, label in (("listeners", "listening ports"), ("services", "running services"), ("persistence", "persistence entries")):
        a, b = old.get(key), new.get(key)
        if a is None or b is None:
            if (a is None) != (b is None):
                out["notes"].append(f"{label}: read in only one of the two runs, not compared")
            continue
        out["parts"][key] = {"new": sorted(set(b) - set(a)), "gone": sorted(set(a) - set(b)), "changed": []}
    a, b = old.get("ssh"), new.get("ssh")
    if a is None or b is None:
        if (a is None) != (b is None):
            out["notes"].append("effective SSH settings: read in only one of the two runs (they need root), not compared")
    else:
        out["parts"]["ssh"] = {"new": sorted(k for k in b if k not in a), "gone": sorted(k for k in a if k not in b),
                               "changed": sorted(f"{k}: {a[k]} -> {b[k]}" for k in a if k in b and a[k] != b[k])}
    fa, fb = old.get("findings") or {}, new.get("findings") or {}
    out["parts"]["findings"] = {"new": sorted(fb.keys() - fa.keys()), "gone": sorted(fa.keys() - fb.keys()),
                                "changed": sorted(f"{k}: {fa[k].get('installed')} -> {fb[k].get('installed')}" for k in fa.keys() & fb.keys() if fa[k].get("installed") != fb[k].get("installed"))}
    if "posture" not in (old.get("inventory"), new.get("inventory")) and old.get("inventory") != new.get("inventory"):
        out["inventoryChanged"] = True
    return out


def empty(d: dict) -> bool:
    return not any(p["new"] or p["gone"] or p["changed"] for p in d["parts"].values())


def render(d: dict, new: dict) -> str:
    names = {"listeners": "listening ports", "services": "running services", "persistence": "persistence entries", "ssh": "effective SSH settings", "findings": "findings"}
    first = {k: v.get("found") for k, v in (new.get("findings") or {}).items()}
    lines = [f"CHANGE SINCE THE LAST RUN ({d['since']})"]
    if empty(d):
        lines.append("  nothing new, changed or gone in the parts both runs read.")
    for key, p in d["parts"].items():
        for tag in ("new", "changed", "gone"):
            for item in p[tag]:
                extra = f" (first seen {first[item]})" if key == "findings" and tag == "new" and first.get(item) else ""
                lines.append(f"  {tag:<7} {names[key]}: {item}{extra}")
    if d.get("inventoryChanged"):
        lines.append("  the installed software changed (inventory hash differs)")
    lines += [f"  note: {n}" for n in d["notes"]]
    return "\n".join(lines)


def save(folder: Path, snap: dict, keep: int = KEEP) -> Path:
    """Write the snapshot 0600 under <folder>/snapshots and delete the oldest beyond `keep`."""
    d = folder / "snapshots"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    path = d / (snap["at"].replace(":", "").replace("-", "") + ".json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(snap, sort_keys=True))
    for old in sorted(d.glob("*.json"))[:-keep]:
        old.unlink(missing_ok=True)
    return path


def latest(folder: Path) -> dict | None:
    for f in sorted((folder / "snapshots").glob("*.json"), reverse=True):
        try:
            s = json.loads(f.read_text())
            if s.get("schema") == SCHEMA:
                return s
        except (OSError, ValueError):
            continue
    return None
