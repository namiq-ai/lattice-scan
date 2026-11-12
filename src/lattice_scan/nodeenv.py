# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Node packages installed globally on this machine, outside the OS package manager: `npm install -g` into the system prefix, /usr/local, a user
prefix (~/.npm-global) or an nvm-managed Node.

Why: a globally installed CLI and everything it pulled in sit on the host and run, and dpkg cannot see them. This reads each package's own
`package.json` (name and version) inside those node_modules folders, including the dependencies nested below a global package. Nothing is run
(not `npm`, not `node`), nothing is fetched. A project's own node_modules is not read here: that is `lattice-scan project`, from its lockfile.

Bounded: at most MAX_PACKAGES per root, MAX_DEPTH nested node_modules levels, and package.json files over MAX_BYTES are skipped. The folders stay in the
local inventory.json; only a package's name and version can ever be matched or sent.
"""
from __future__ import annotations

import glob
import json
import os
from pathlib import Path

MAX_PACKAGES = 20000
MAX_DEPTH = 8
MAX_BYTES = 256 * 1024


def global_roots(home: Path | None = None) -> list:
    home = home or Path.home()
    pats = ["/usr/lib/node_modules", "/usr/local/lib/node_modules", str(home / ".npm-global/lib/node_modules"), str(home / ".local/lib/node_modules"),
            str(home / ".nvm/versions/node/*/lib/node_modules"), str(home / ".volta/tools/image/packages/*/lib/node_modules")]
    out = []
    for p in pats:
        out += sorted(glob.glob(p))
    return [p for p in dict.fromkeys(out) if os.path.isdir(p)]


def _read_pkg(p: Path):
    try:
        if p.stat().st_size > MAX_BYTES:
            return None
        d = json.loads(p.read_text(errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict):
        return None
    n, v = d.get("name"), d.get("version")
    return (n[:214], v[:100]) if isinstance(n, str) and isinstance(v, str) and n and v else None


def read_root(root: str) -> dict:
    """{name: "v1|v2"} for every package under one node_modules folder, nested dependencies included (one name can be installed at several versions)."""
    found: dict = {}

    def walk(nm: Path, depth: int) -> None:
        if depth > MAX_DEPTH or len(found) >= MAX_PACKAGES:
            return
        try:
            entries = sorted(nm.iterdir())
        except OSError:
            return
        for e in entries:
            if e.name.startswith(".") or not e.is_dir() or e.is_symlink():
                continue
            pkgs = sorted(x for x in e.iterdir() if x.is_dir() and not x.is_symlink()) if e.name.startswith("@") else [e]
            for pk in pkgs:
                got = _read_pkg(pk / "package.json")
                if got:
                    found.setdefault(got[0], set()).add(got[1])
                if (pk / "node_modules").is_dir():
                    walk(pk / "node_modules", depth + 1)
    walk(Path(root), 0)
    return {n: "|".join(sorted(v)) for n, v in found.items()}


def collect(home: Path | None = None) -> dict:
    """{node_modules folder: {name: versions}} for every global install root that holds packages."""
    out = {}
    for r in global_roots(home):
        pk = read_root(r)
        if pk:
            out[r] = pk
    return out
