# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Reading a Mac, from files only. Nothing here runs a program (so `brew` is never run), writes anything, or opens a folder macOS protects with a permission dialog
(Desktop, Documents, Downloads, iCloud, Photos, ~/Library). The sources are the system version file, the Info.plist of each app bundle in /Applications and
/System/Applications, and the Homebrew Cellar folder names."""
from __future__ import annotations

import os
import plistlib
import sys
from pathlib import Path

SYSTEM_VERSION = "/System/Library/CoreServices/SystemVersion.plist"
APP_FOLDERS = ("/Applications", "/System/Applications", "/System/Applications/Utilities", "/Applications/Utilities")
BREW_PREFIXES = ("/opt/homebrew", "/usr/local")


def _plist(path: str | Path) -> dict:
    try:
        with open(path, "rb") as f:
            d = plistlib.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:   # missing, unreadable or not a plist: that source is simply not read
        return {}


def read_os(root: str = "") -> dict:
    """{'family','product','version','extra','build'}. extra is the letter of a background security improvement, for example '(a)'; empty when none."""
    p = _plist(root + SYSTEM_VERSION)
    if not p.get("ProductVersion"):
        return {}
    return {"family": "macos", "product": str(p.get("ProductName") or "macOS"), "version": str(p["ProductVersion"]),
            "extra": str(p.get("ProductVersionExtra") or ""), "build": str(p.get("ProductBuildVersion") or "")}


def read_apps(root: str = "") -> tuple[dict[str, str], int]:
    """({lower-case app name: version}, apps whose version could not be read)."""
    out: dict[str, str] = {}
    unread = 0
    for folder in APP_FOLDERS:
        try:
            names = sorted(n for n in os.listdir(root + folder) if n.endswith(".app"))
        except OSError:
            continue
        for n in names:
            p = _plist(f"{root}{folder}/{n}/Contents/Info.plist")
            v = str(p.get("CFBundleShortVersionString") or p.get("CFBundleVersion") or "")
            if v:
                out.setdefault(n[:-4].lower(), v)
            else:
                unread += 1
    return out, unread


def read_cellar(root: str = "") -> dict[str, str]:
    """{formula: newest installed version} from the Cellar folder names. The folder name can carry a revision (1.2.3_1); it is kept as written."""
    out: dict[str, str] = {}
    for prefix in BREW_PREFIXES:
        c = f"{root}{prefix}/Cellar"
        try:
            formulae = sorted(os.listdir(c))
        except OSError:
            continue
        for f in formulae:
            try:
                vs = sorted(os.listdir(f"{c}/{f}"))
            except OSError:
                continue
            vs = [v for v in vs if not v.startswith(".")]
            if vs:
                out.setdefault(f, vs[-1])
    return out


def release_line(version: str) -> int | None:
    """The macOS release line: 15 for 15.8.2, 26 for 26.7. Old 10.x numbers are not covered (the support range starts at 12)."""
    try:
        n = int(version.split(".")[0])
    except ValueError:
        return None
    return n if n >= 11 else None


def collect(root: str = "", progress=lambda s: None) -> dict:
    """The inventory of this Mac in the shape the matcher already reads (see cli.inventory). `root` is only for tests with a captured folder tree."""
    osr = read_os(root)
    apps, unread = read_apps(root)
    brew = read_cellar(root)
    progress(f"[host] macOS {osr.get('version', 'unknown')}{' ' + osr['extra'] if osr.get('extra') else ''}, {len(apps)} apps read" + (f" ({unread} without a version)" if unread else "")
             + f", {len(brew)} Homebrew formulae (folder names only; brew is never run)")
    pk = {**{f: v for f, v in brew.items()}, **{a: v for a, v in apps.items() if a not in brew}}
    return {"kernel": "", "os": f"{osr.get('product', 'macOS')} {osr.get('version', '')}".strip(), "family": "macos", "osInfo": osr, "manager": "macos",
            "host": {}, "packages": pk, "snaps": {}, "images": [], "imageDetails": {}, "node": "", "restartRequired": False, "appsUnread": unread}


def covered_lines(ranges: list[dict]) -> set[int]:
    """Release lines Apple names a range for: the line of each range's lower bound, or of its upper bound when it has no lower one."""
    out: set[int] = set()
    for r in ranges:
        for k in ("start_including", "start_excluding", "end_excluding", "end_including"):
            if r.get(k):
                ln = release_line(str(r[k]))
                if ln:
                    out.add(ln)
    return out


def macos_ranges(entry: dict) -> list[dict]:
    return [r for r in entry.get("ranges", []) if r.get("product", "").lower() == "apple/macos"]


def judge(version: str, extra: str, ranges: list[dict], check) -> dict:
    """The verdict for the Mac's own version. `check(version, ranges)` is the ordinary range comparison. Two rules on top (ADR MA-7, MA-8): a release line with
    no listed range is 'undetermined', never 'outside' (Apple lists fixes only for the lines it still patches); and when a security-improvement letter is
    installed, 'outside the range' cannot be concluded, because the letter may or may not carry the fix."""
    res = check(version, ranges)
    ln = release_line(version)
    if res["verdict"] == "outside-range":
        if ln is None or ln not in covered_lines(ranges):
            return {"verdict": "undetermined", "why": f"macOS {version}: Apple lists no range for release {ln if ln else '?'} of this CVE; that is not shown as fixed. " + res["why"]}
        if extra:
            return {"verdict": "undetermined", "why": f"macOS {version} {extra}: a background security improvement is installed, so 'fixed in the base version' cannot be concluded. " + res["why"]}
    return res


def is_mac() -> bool:
    return sys.platform == "darwin"
