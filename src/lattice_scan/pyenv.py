# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Python packages installed on this machine outside the OS package manager: pip, uv or conda installs in system, user and virtual environments.

Why: exploited code lives there too. A pip-installed brotli wheel is invisible to dpkg, so a host scan never saw it, while the CVE that names
`pypi:brotli` is on CISA's list. This reads the metadata each installer leaves (`*.dist-info/METADATA`, `*.egg-info/PKG-INFO`) and nothing else:
no interpreter is started, no import is made, nothing is fetched. A package the distribution installed (a dist-info under /usr/lib with no installer
or a distribution installer) is left to dpkg or rpm, which own it and already report it.

Where it looks: the standard system and user site directories, and virtual environments (a folder holding pyvenv.cfg) in the home folder up to
MAX_DEPTH levels down, plus any folder named with --python-path. Bounded: at most MAX_ENVS environments and MAX_PACKAGES packages each.
The paths stay in the local inventory.json; only a package's name and version can ever be matched or sent.
"""
from __future__ import annotations

import glob
import os
import re
from pathlib import Path

MAX_DEPTH = 3
MAX_ENVS = 64
MAX_PACKAGES = 5000
MAX_METADATA = 64 * 1024
DISTRO_INSTALLERS = {"", "debian", "dpkg", "rpm", "apk", "distutils"}   # an empty INSTALLER file or none: the distribution's own packaging
SKIP = {".git", "node_modules", ".cache", "proc", "snap", ".local/share/Trash", "__pycache__"}

_NAME = re.compile(r"^Name:\s*(.+?)\s*$", re.M)
_VERSION = re.compile(r"^Version:\s*(.+?)\s*$", re.M)


def system_site_dirs(home: Path | None = None) -> list:
    """Site directories that exist on this machine, system first. Globs only: no interpreter is asked."""
    home = home or Path.home()
    pats = ["/usr/lib/python3*/site-packages", "/usr/lib/python3*/dist-packages", "/usr/lib/python3/dist-packages", "/usr/lib64/python3*/site-packages",
            "/usr/local/lib/python3*/site-packages", "/usr/local/lib/python3*/dist-packages", str(home / ".local/lib/python3*/site-packages")]
    out = []
    for p in pats:
        out += sorted(glob.glob(p))
    return list(dict.fromkeys(out))


def venv_site_dirs(root: Path, depth: int = MAX_DEPTH) -> list:
    """Site directories of the virtual environments under root (a folder with pyvenv.cfg), at most `depth` levels down; hidden folders and caches skipped."""
    out: list = []

    def walk(d: Path, level: int) -> None:
        if len(out) >= MAX_ENVS:
            return
        try:
            if (d / "pyvenv.cfg").is_file():
                out.extend(sorted(glob.glob(str(d / "lib" / "python3*" / "site-packages"))) + sorted(glob.glob(str(d / "Lib" / "site-packages"))))
                return
            if level >= depth:
                return
            for c in sorted(d.iterdir()):
                if c.is_dir() and not c.is_symlink() and not c.name.startswith(".") and c.name not in SKIP:
                    walk(c, level + 1)
        except OSError:
            return
    walk(root, 0)
    return out[:MAX_ENVS]


def _read(p: Path) -> str:
    try:
        with open(p, "rb") as f:
            return f.read(MAX_METADATA).decode("utf-8", "replace")
    except OSError:
        return ""


def distro_owned(site: str, info: Path) -> bool:
    """True when the OS package manager installed this distribution: it lives under /usr/lib and its INSTALLER is missing or a distribution's."""
    if not (site.startswith("/usr/lib/") or site.startswith("/usr/lib64/")):
        return False
    return _read(info / "INSTALLER").strip().lower() in DISTRO_INSTALLERS


def read_site(site: str) -> dict:
    """{name: version} for one site directory, name as the metadata spells it. A distribution-owned package is skipped (dpkg or rpm reports it)."""
    out: dict = {}
    try:
        entries = sorted(os.listdir(site))
    except OSError:
        return out
    for e in entries:
        if len(out) >= MAX_PACKAGES:
            break
        if not e.endswith((".dist-info", ".egg-info")):
            continue
        info = Path(site) / e
        if distro_owned(site, info):
            continue
        meta = _read(info / ("METADATA" if e.endswith(".dist-info") else "PKG-INFO")) if info.is_dir() else _read(info)
        n, v = _NAME.search(meta), _VERSION.search(meta)
        if n and v:
            out[n.group(1)[:200]] = v.group(1)[:100]
            continue
        stem = re.sub(r"-py\d[\d.]*$", "", e.rsplit(".", 1)[0])     # no metadata file: the folder name carries name-version
        name, _, ver = stem.rpartition("-")
        if name and ver[:1].isdigit():
            out[name] = ver
    return out


def collect(extra: list | None = None, home: Path | None = None) -> dict:
    """{site directory: {name: version}} for every place a Python package was installed outside the OS package manager. Empty sites are left out."""
    home = home or Path.home()
    sites = system_site_dirs(home) + venv_site_dirs(home)
    for x in extra or []:
        p = Path(x).expanduser()
        sites += [str(p)] if p.name in ("site-packages", "dist-packages") else venv_site_dirs(p, 0) or sorted(glob.glob(str(p / "lib" / "python3*" / "site-packages")))
    found = {}
    for s in list(dict.fromkeys(sites))[:MAX_ENVS * 2]:
        pk = read_site(s)
        if pk:
            found[s] = pk
    return found


def label(site: str, home: Path | None = None) -> str:
    """A short place name for a person: the environment folder with the home folder as ~ (".../lib/python3.12/site-packages" dropped)."""
    home = str(home or Path.home())
    env = re.sub(r"/lib(64)?/python3[\d.]*/(site|dist)-packages$|/Lib/site-packages$", "", site)
    return "~" + env[len(home):] if env.startswith(home + "/") or env == home else env
