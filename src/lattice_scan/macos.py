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


def _line_of(v) -> tuple[int | None, bool]:
    """(release line, whole-number bound) of a range bound such as '14.7.5' or '15.0'."""
    parts = str(v).split(".")
    try:
        nums = [int(x) for x in parts]
    except ValueError:
        return None, False
    return (nums[0] if nums[0] >= 11 else None), all(n == 0 for n in nums[1:])


def span(r: dict) -> set[int]:
    """The macOS release lines one NVD range belongs to. A range with both bounds covers the lines between them; a range with only an upper bound belongs to the line of
    that bound alone (NVD's literal 'everything before' is not credited to older lines: Apple fixes each line on its own, ADR MA-7); one with only a lower bound,
    to that line. 'Before 15.0' belongs to line 14."""
    lo = r.get("start_including") or r.get("start_excluding")
    hi = r.get("end_excluding") or r.get("end_including")
    lo_l = _line_of(lo)[0] if lo else None
    hi_l, whole = _line_of(hi) if hi else (None, False)
    if hi_l is not None and r.get("end_excluding") and whole:
        hi_l = hi_l - 1 if hi_l - 1 >= 11 else None
    if lo_l is not None and hi_l is not None:
        return set(range(lo_l, max(lo_l, hi_l) + 1))
    one = lo_l if lo_l is not None else hi_l
    return {one} if one is not None else set()


def covered_lines(ranges: list[dict]) -> set[int]:
    """Release lines Apple names a range for."""
    out: set[int] = set()
    for r in ranges:
        out |= span(r)
    return out


def ranges_for(ranges: list[dict], line: int | None) -> list[dict]:
    return [r for r in ranges if line is not None and line in span(r)]


NOT_ON_A_MAC = {"iphone_os", "ipados", "watchos", "tvos", "visionos", "mac_os_x", "mac_os", "os_x"}   # NVD names for other systems; mac_os_x is OS X 10.x, below the supported range


def apple_parts(entry: dict, inv: dict) -> list[dict]:
    """What on this Mac an Apple CVE is about, from NVD's own product names (no hand-kept list of Apple's product wording, which varies: 'Multiple Products',
    'iOS, iPadOS, and macOS', 'WebKit'). apple/macos means the operating system; any other apple/<name> counts when an app of that name is installed (apple/safari:
    the Safari app). iOS, iPadOS, watchOS, tvOS, visionOS and the old OS X names are skipped: they are not on this Mac."""
    o = inv.get("osInfo") or {}
    by: dict[str, list[dict]] = {}
    for r in entry.get("ranges", []):
        vendor, _, name = str(r.get("product", "")).lower().partition("/")
        if vendor == "apple" and name and name not in NOT_ON_A_MAC:
            by.setdefault(name, []).append(r)
    out = []
    for name, rs in sorted(by.items()):
        if name == "macos":
            if o.get("version"):
                out.append({"name": "macos", "label": f"macOS {o['version']}" + (f" {o['extra']}" if o.get("extra") else ""), "version": o["version"], "extra": o.get("extra", ""), "ranges": rs, "os": True})
            continue
        app = name.replace("_", " ")
        if app in (inv.get("packages") or {}):
            out.append({"name": name, "label": f"{app} {inv['packages'][app]}", "version": inv["packages"][app], "extra": "", "ranges": rs, "os": False})
    return out


def judge(version: str, extra: str, ranges: list[dict], check) -> dict:
    """The verdict for the Mac's own version. `check(version, ranges)` is the ordinary range comparison. Two rules on top (ADR MA-7, MA-8): only ranges that belong to
    the Mac's own release line are compared, and a line with none is 'undetermined', never 'outside' (Apple lists fixes only for the lines it still patches); and
    when a security-improvement letter is installed, 'outside the range' cannot be concluded, because the letter may or may not carry the fix."""
    ln = release_line(version)
    mine = ranges_for(ranges, ln)
    if not mine:
        return {"verdict": "undetermined", "why": f"macOS {version}: Apple lists no range for release {ln if ln else '?'} of this CVE; that is not shown as fixed"}
    res = check(version, mine)
    if res["verdict"] == "outside-range" and extra:
        return {"verdict": "undetermined", "why": f"macOS {version} {extra}: a background security improvement is installed, so 'fixed in the base version' cannot be concluded. " + res["why"]}
    return res


def is_mac() -> bool:
    return sys.platform == "darwin"
