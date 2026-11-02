# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Reports for `lattice-scan project`: a console view for a person, CSV for a spreadsheet or a script, JSON for a program.

All three are built from the same list of per-project results, so they cannot disagree. Nothing here talks to the network.

CSV is one row per finding and declared component, in a fixed column order (CSV_COLUMNS), UTF-8, LF line ends, a header row even when there are no findings. Text that came from a
third party (a CVE title, CISA's required action, a file name) can start with =, +, - or @, which a spreadsheet would run as a formula, so such a cell is written with a leading
apostrophe; a parser that wants the raw text strips one leading ' from a cell.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import os
import shutil
import sys
import textwrap

VERDICT_ORDER = {"in-range": 0, "undetermined": 1, "outside-range": 2, "not-read": 3}
VERDICT_LABEL = {"in-range": "IN RANGE", "undetermined": "UNDETERMINED", "outside-range": "OUTSIDE RANGE", "not-read": "NOT READ"}
CSV_COLUMNS = ["project", "cve", "title", "verdict", "component", "ecosystem", "declared", "version", "file", "line", "listed", "due", "due_status", "action", "why"]

MEANING = [
    ("in-range", "a declared, pinned version lies inside a range NVD lists as affected. Check what is really deployed: a distribution can backport a fix under the same number."),
    ("undetermined", "the declaration is a range, a minimum, a floating tag or no version at all, or NVD's bounds are dates or build ids, or the package is not the product itself. It could not be judged."),
    ("outside-range", "every pinned version declared lies outside every usable range NVD lists. This does not close a finding; a person does."),
    ("not-read", "an exploited id that name-matches a dependency was not read from Lattice (a limit or a stop). It is neither safe nor affected."),
]


def _day(s: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat(s[:10])
    except (ValueError, TypeError):
        return None


def _rel(d: str, today: str) -> str:
    """'3 days ago' / 'in 18 days' / 'today' for a date, '' when there is none."""
    a, t = _day(d), _day(today)
    if not a or not t:
        return ""
    n = (a - t).days
    return "today" if n == 0 else f"in {n} day{'s' if n != 1 else ''}" if n > 0 else f"{-n} day{'s' if n != -1 else ''} ago"


def due_status(due: str, today: str) -> str:
    a, t = _day(due), _day(today)
    if not a or not t:
        return ""
    n = (a - t).days
    return f"overdue by {-n} days" if n < 0 else "due today" if n == 0 else f"due in {n} days"


def findings(results: list[dict]) -> list[dict]:
    """Every finding as one flat dict per (candidate, declared component), plus one per id that was not read, sorted most pressing first within each project."""
    out = []
    for r in results:
        name = r.get("name") or r["root"].rstrip("/").rsplit("/", 1)[-1]
        for h in r["candidates"]:
            decl = h["declared"] or [{}]
            for d in decl:
                out.append({"project": name, "cve": h["cve"], "title": h["title"], "verdict": h["versionCheck"]["verdict"], "component": d.get("name", ""),
                            "ecosystem": d.get("ecosystem", ""), "declared": d.get("spec", ""), "version": d.get("version") or "", "file": d.get("file", ""),
                            "line": d.get("line") or "", "listed": h["listed"], "due": h["due"], "action": h["action"], "why": h["versionCheck"]["why"]})
        for cve in r["unread"]:
            out.append({"project": name, "cve": cve, "title": "", "verdict": "not-read", "component": "", "ecosystem": "", "declared": "", "version": "", "file": "", "line": "",
                        "listed": "", "due": "", "action": "", "why": "not read from Lattice" + (f": {r['stopped']}" if r.get("stopped") else " (over the read limit)")})
    out.sort(key=lambda f: (f["project"], VERDICT_ORDER[f["verdict"]], f["cve"], f["component"]))
    return out


def _cell(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(results: list[dict], today: str) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for f in findings(results):
        f = {**f, "due_status": due_status(f["due"], today)}
        w.writerow([_cell(f[c]) for c in CSV_COLUMNS])
    return buf.getvalue()


def counts(r: dict) -> dict[str, int]:
    c = {"in-range": 0, "undetermined": 0, "outside-range": 0}
    for h in r["candidates"]:
        c[h["versionCheck"]["verdict"]] += 1
    c["not-read"] = len(r["unread"])
    return c


def use_color(mode: str, stream) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def width_for(requested: int | None) -> int:
    if requested:
        return max(60, requested)
    return max(72, min(shutil.get_terminal_size((100, 24)).columns, 110))


def console(results: list[dict], today: str, tool: str, width: int = 100, color: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    def wrap(text: str, first: str = "", rest: str = "") -> list[str]:
        return textwrap.wrap(text, width, initial_indent=first, subsequent_indent=rest, break_long_words=False, break_on_hyphens=False) or [first.rstrip()]

    tag_color = {"in-range": "1;31", "undetermined": "33", "outside-range": "32", "not-read": "2"}
    bar, thin = "=" * width, "-" * width
    L: list[str] = []
    L += [paint(f"{tool}  |  dependency report  |  {today}", "1"), bar]
    L += textwrap.wrap("Declared dependencies checked against CISA's list of exploited vulnerabilities, read through Lattice. "
                       "Evidence for a person to read; nothing here says what is deployed.", width)
    L += ["", paint("SUMMARY", "1"), thin]
    wide = width >= 92
    cols = [("Project", 14, "<"), ("Files", 6 if wide else 5, ">"), ("Components" if wide else "Comp.", 11 if wide else 6, ">"), ("Pinned" if wide else "Pin", 8 if wide else 5, ">"),
            ("Candidates" if wide else "Cand.", 11 if wide else 6, ">"), ("In range" if wide else "In", 9 if wide else 4, ">"),
            ("Undetermined" if wide else "Und.", 13 if wide else 5, ">"), ("Outside" if wide else "Out", 8 if wide else 5, ">"), ("Not read" if wide else "NR", 9 if wide else 4, ">")]

    def line(vals: list) -> str:
        return "".join(f"{str(v):{a}{w}}" for v, (_, w, a) in zip(vals, cols))
    L.append(line([c[0] for c in cols]))
    tot = {"files": 0, "components": 0, "pinned": 0, "cand": 0, "in-range": 0, "undetermined": 0, "outside-range": 0, "not-read": 0}
    for r in results:
        c = counts(r)
        name = (r.get("name") or r["root"].rstrip("/").rsplit("/", 1)[-1])[:13]
        row = line([name, len(r["files"]), r["components"], r["pinned"], len(r["candidates"]), c["in-range"], c["undetermined"], c["outside-range"], c["not-read"]])
        L.append(paint(row, "1;31") if c["in-range"] else row)
        for k, v in (("files", len(r["files"])), ("components", r["components"]), ("pinned", r["pinned"]), ("cand", len(r["candidates"]))):
            tot[k] += v
        for k in ("in-range", "undetermined", "outside-range", "not-read"):
            tot[k] += c[k]
    if len(results) > 1:
        L.append(thin[:sum(w for _, w, _ in cols)])
        L.append(line(["Total", tot["files"], tot["components"], tot["pinned"], tot["cand"], tot["in-range"], tot["undetermined"], tot["outside-range"], tot["not-read"]]))
    for r in results:
        if r["filesCut"]:
            L += wrap(f"! {r.get('name') or r['root']}: the file search stopped at its limit, so not every manifest was read.")
    stops = [r["stopped"] for r in results if r["stopped"]]
    if stops:
        n_unread = sum(len(r["unread"]) for r in results)
        L += ["", paint("! INCOMPLETE", "1;33")]
        L += wrap(f"Lattice stopped this run: {stops[0]} {n_unread} id(s) were not read; they are listed under each project and are neither safe nor affected. "
                  "Run it again after the limit resets, or use a key.", "  ", "  ")
    L.append("")
    for r in results:
        name = r.get("name") or r["root"].rstrip("/").rsplit("/", 1)[-1]
        L += [paint(f"PROJECT {name}", "1"), thin]
        L += wrap(r["root"])
        L += wrap(f"{len(r['files'])} manifest file(s), {r['components']} declared component(s), {r['pinned']} pinned to a version; "
                  f"{r['read']} exploited entr{'y' if r['read'] == 1 else 'ies'} read from Lattice.")
        fs = [f for f in findings([r]) if f["verdict"] != "not-read"]
        if not fs:
            L += wrap("No dependency declared here matches an exploited entry that was read. That is not the same as safe: only ids that name-match a declared package are read.")
        by_cve: dict[str, list[dict]] = {}
        for f in fs:
            by_cve.setdefault(f["cve"], []).append(f)
        n = 0
        for cve, group in by_cve.items():
            n += 1
            v = group[0]["verdict"]
            L += ["", f"{n}. {cve}  " + paint(f"[{VERDICT_LABEL[v]}]", tag_color[v])]
            L += textwrap.wrap(group[0]["title"], width - 3, initial_indent="   ", subsequent_indent="   ")
            for g in group:
                d = f"{g['component']} {g['declared'] or '(no version)'}".strip()
                loc = f"{g['file']}:{g['line']}" if g["line"] else g["file"]
                L += textwrap.wrap(f"{d}  [{g['ecosystem']}]  {loc}", width - 14, initial_indent="   Declared   ", subsequent_indent="              ", break_long_words=False, break_on_hyphens=False)
            listed, due = group[0]["listed"], group[0]["due"]
            if listed or due:
                L += textwrap.wrap(f"listed {listed or '-'}" + (f" ({_rel(listed, today)})" if _rel(listed, today) else "") + f", due {due or '-'}"
                                   + (f" ({due_status(due, today).removeprefix('due ')})" if due_status(due, today) else ""), width - 14, initial_indent="   CISA       ", subsequent_indent="              ")
            L += textwrap.wrap(group[0]["why"], width - 14, initial_indent="   Check      ", subsequent_indent="              ")
            if group[0]["action"]:
                L += textwrap.wrap(group[0]["action"], width - 14, initial_indent="   Required   ", subsequent_indent="              ", max_lines=3, placeholder=" ...")
            if v == "in-range":
                L += textwrap.wrap("Declared version only: what is deployed may differ, and a distribution may have backported the fix.", width - 14, initial_indent="   Note       ", subsequent_indent="              ")
        if r["unread"]:
            L += ["", paint(f"NOT READ ({len(r['unread'])})", "2")]
            L += wrap("not read because Lattice stopped the run (see INCOMPLETE above)" if r["stopped"] else "over the read limit; raise --max-read or use a key", "   ", "   ")
            L += textwrap.wrap(", ".join(r["unread"]), width - 3, initial_indent="   ", subsequent_indent="   ", max_lines=6, placeholder=" ...")
        if r["notListed"]:
            L += ["", "Not in the graph's CISA list (not 'safe', only 'not listed in this snapshot'):"]
            L += textwrap.wrap(", ".join(r["notListed"]), width - 3, initial_indent="   ", subsequent_indent="   ", max_lines=4, placeholder=" ...")
        L.append("")
    L += [paint("HOW TO READ THIS", "1"), thin]
    for k, text in MEANING:
        L += textwrap.wrap(f"{VERDICT_LABEL[k]:<14}{text}", width, subsequent_indent=" " * 14)
    L += textwrap.wrap("Matching is by product identity against what is declared. Only CVE ids leave this machine: package names and versions are never sent.", width)
    return "\n".join(L) + "\n"


def emit(text: str, path: str | None) -> None:
    if path:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
