#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Build the Claude Code plugin package and check it.

    python3 packaging/build_claude_plugin.py      -> dist/lattice-scan-claude-plugin-<version>.zip

The ZIP holds exactly what Claude Code loads: .claude-plugin/plugin.json and its icon, skills/lattice-scan/ (SKILL.md and the bundled script), LICENSE and
NOTICE. Unzip it and run `claude --plugin-dir <folder>` to try it without the marketplace. Installing from the marketplace (`source: "./"`) reads the
repository at the release tag, so this ZIP is the same files as a checked, versioned asset, with a hash in SHA256SUMS.
The build fails, and so does the release, when the plugin version is not the package version, when SKILL.md lacks its name and description, or when a module
inside the bundled script differs from the source (a skill that runs an old script is the failure this guards; rebuild with packaging/build.py).
"""
from __future__ import annotations
import json, re, sys, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from lattice_scan import __version__  # noqa: E402

SKILL = ROOT / "skills" / "lattice-scan"
FIXED_TIME = (2026, 1, 1, 0, 0, 0)   # the same sources always give the same bytes
FILES = [".claude-plugin/plugin.json", ".claude-plugin/icon.png", "skills/lattice-scan/SKILL.md",
         "skills/lattice-scan/scripts/lattice-scan.pyz", "LICENSE", "NOTICE"]


def problems(root: Path = ROOT, version: str = __version__) -> list[str]:
    out = []
    plugin = json.loads((root / ".claude-plugin/plugin.json").read_text())
    if plugin.get("version") != version:
        out.append(f"plugin.json says {plugin.get('version')}, the package is {version}")
    head = (root / "skills/lattice-scan/SKILL.md").read_text().split("---")
    if len(head) < 3 or not re.search(r"^name: lattice-scan$", head[1], re.M) or not re.search(r"^description: .{40,}", head[1], re.M):
        out.append("SKILL.md has no front matter with name: lattice-scan and a description")
    for f in FILES:
        if not (root / f).is_file():
            out.append(f"missing {f}")
    pyz = root / "skills/lattice-scan/scripts/lattice-scan.pyz"
    if pyz.is_file():
        with zipfile.ZipFile(pyz) as z:
            for m in sorted(z.namelist()):
                src = root / "src" / m
                if m.startswith("lattice_scan/") and m.endswith(".py") and src.is_file() and z.read(m) != src.read_bytes():
                    out.append(f"{m} in the bundled script is stale: run packaging/build.py")
    return out


def build(out_dir: Path | None = None) -> Path:
    bad = problems()
    if bad:
        raise SystemExit("Claude plugin check failed:\n  " + "\n  ".join(bad))
    out_dir = out_dir or ROOT / "dist"
    out_dir.mkdir(exist_ok=True)
    target = out_dir / f"lattice-scan-claude-plugin-{__version__}.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for name in FILES:
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, (ROOT / name).read_bytes())
    return target


if __name__ == "__main__":
    print("wrote", build())
