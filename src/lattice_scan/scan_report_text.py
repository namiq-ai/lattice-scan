# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The code-written scan report (OCO-6054, epic OCO-6045). Built on the machine from the scan result and the payload, written to a private file.

Every sentence here is written by code. Nothing is sent anywhere and nothing is read from the network. The words "vulnerable", "safe" and
"compromised" are never written: a candidate is a lead for a person to check, and the report says so. Inferred links are written "likely".
The local report may use more of the scan result than the payload does (the reasons and dates the tool already printed); what leaves the
machine, if the person ever asks for that, is only the payload (scan_report.build_payload).
"""
from __future__ import annotations

import datetime as dt
import os
import re
import sys
from pathlib import Path

from . import scan_report as sr

SECTIONS = ("Summary", "Items to read, most urgent first", "What was compared", "What to check", "Sources", "What was not covered", "Limits")
BANNED = re.compile(r"\b(vulnerable|safe|compromised)\b", re.I)
PRIORITY_ORDER = ("fix first", "fix soon", "read")
PRIORITY_TITLE = {"fix first": "Fix first", "fix soon": "Fix soon", "read": "Read"}
VERDICT_TEXT = {
    "in-range": "an installed version number lies inside a range NVD lists (a lead to check, not a finding)",
    "undetermined": "the tool could not compare the version with a listed range",
    "outside-range": "every readable range excludes the installed version (this does not close the item)",
    "lead": "the package only shares a name or scope with the product (no range was compared)",
    "not-read": "this id was not read from Lattice (a limit or a stop); it is not cleared",
}
CHECK_TEXT = {
    "in-range": "Read the vendor advisory for {cve}. Compare the fixed version it names with the installed one, and look in the package changelog for the id: a distribution can fix it under the same version number.",
    "undetermined": "Read the vendor advisory for {cve} and compare the installed version by hand.",
    "outside-range": "Keep the item open until a person has read the vendor advisory for {cve}; a range comparison does not close it.",
    "lead": "Check whether {product} on this machine is the product the advisory for {cve} names.",
    "not-read": "Run the scan again later, or read the advisory for {cve} directly.",
}
SOURCES = ("CISA Known Exploited Vulnerabilities catalog (which ids are listed, when, the due date, ransomware use as CISA records it)",
           "NVD (descriptions and the version ranges compared)", "FIRST EPSS (an estimate of exploitation, where shown)", "Lattice (namiq.io), which serves the three")


def _why(it: dict) -> list[str]:
    out = [str(w) for w in (it.get("why") or []) if str(w).strip()]
    if it.get("due"):                                       # the due line below carries the date and the status: do not list the same fact twice
        out = [w for w in out if "patch-due date" not in w]
    if it.get("listed"):
        out.append(f"listed by CISA on {it['listed']}")
    if it.get("due"):
        out.append(f"CISA patch-due date {it['due']}" + (f" ({it['due_status']})" if it.get("due_status") else ""))
    for t in it.get("attack") or []:
        out.append(("likely linked to ATT&CK " if t.get("inferred") else "linked to ATT&CK ") + str(t.get("id", "")))
    return out


DISTRO_TEXT = {"before-fix": "before the distribution's fix", "no-fix-yet": "the distribution has no fix yet", "fixed": "FIXED (the distribution's own record)",
               "not-affected": "FIXED: the distribution lists this release as not affected", "unknown": "the distribution gave no answer for it"}
OPEN_VERDICTS = ("before-fix", "no-fix-yet")
IDLE_SHOWN = 3


def _row_rank(row: dict) -> tuple:
    """Running first; then the distribution's word (open ones, then no answer, then fixed); then the name."""
    word = (row.get("distro") or {}).get("verdict")
    order = 0 if word in OPEN_VERDICTS else 2 if word in ("fixed", "not-affected") else 1
    return (0 if row.get("running") else 1, order, 0 if word == "before-fix" else 1, row.get("asset", ""), row.get("name", ""))


def _row_text(row: dict, range_verdict: str) -> str:
    where = row.get("asset") or "host"
    version = (" " + row["version"]) if row.get("version") else ""
    d = row.get("distro")
    if d:
        word = DISTRO_TEXT.get(d.get("verdict"), DISTRO_TEXT["unknown"])
        if d.get("verdict") == "before-fix" and d.get("fixedIn"):
            word += f" ({d['fixedIn']})"
        basis = f"{word} [{d.get('source') or 'distribution'}]"
    else:
        basis = f"version range only: {range_verdict}"
    return f"{row.get('name', '')}{version} in {where}: {basis}"


def asset_lines(it: dict) -> list[str]:
    """The per-package part of one item. Each package keeps its own verdict; the item's status is that of its worst running package, never an average. Running packages are
    all listed and none is cut off; idle images are collapsed after IDLE_SHOWN lines. [] when the item has no per-package rows (a project scan, an older item)."""
    rows = [dict(r) for r in (it.get("rows") or []) if isinstance(r, dict)]
    if not rows:
        return []
    dist = it.get("distro") or []
    for i, r in enumerate(rows):
        if i < len(dist) and isinstance(dist[i], dict):
            r["distro"] = dist[i]
    rows.sort(key=_row_rank)
    run, idle = [r for r in rows if r.get("running")], [r for r in rows if not r.get("running")]
    rv = str(it.get("verdict", "undetermined"))
    open_run = [r for r in run if (r.get("distro") or {}).get("verdict") in OPEN_VERDICTS]
    if open_run:
        status = f"{len(open_run)} running package(s) are before the distribution's fix or have none yet"
    elif run and all((r.get("distro") or {}).get("verdict") in ("fixed", "not-affected") for r in run):
        status = "every running package is fixed by the distribution's own record"
    elif run:
        status = "no running package is confirmed fixed; a person has to check them"
    else:
        status = "no package is running now (idle images only)"
    out = [f"     status: {status}"]
    if len({str(r.get("distro")) for r in rows if r.get("distro")}) == 0:
        out.append(f"     version check: {rv}: {VERDICT_TEXT.get(rv, VERDICT_TEXT['undetermined'])}")
    out += [f"     running: {_row_text(r, rv)}" for r in run]
    out += [f"     idle: {_row_text(r, rv)}" for r in idle[:IDLE_SHOWN]]
    if len(idle) > IDLE_SHOWN:
        out.append(f"     idle: +{len(idle) - IDLE_SHOWN} more idle image(s)")
    return out


def build_report(items: list[dict], payload: dict, generated: dt.date | None = None, posture: dict | None = None) -> str:
    """`items` are the scan's candidates (cve, product, version, verdict, priority, and optionally why, listed, due, due_status, attack);
    `payload` is scan_report.build_payload of the same items. `posture` is the host's posture reading (posture.collect): when given, a section on what listens and
    what runs is added after "What to check". It names ports and programs, so it stays in the local file and is never part of the payload or the record.
    Returns the report text; raises ValueError if a banned word got in."""
    day = (generated or dt.date.today()).isoformat()
    shown = [i for i in items if isinstance(i, dict) and i.get("cve")]
    by_p = {p: [i for i in shown if str(i.get("priority", "read")).lower() == p] for p in PRIORITY_ORDER}
    other = [i for i in shown if str(i.get("priority", "read")).lower() not in PRIORITY_ORDER]
    by_p["read"] += other
    lines = [f"Lattice scan report, {day}", "", f"1. {SECTIONS[0]}",
             f"{len(shown)} candidate(s) from a {payload.get('level', 'quick')} scan on a {payload.get('os', 'Other')} system: "
             + ", ".join(f"{len(by_p[p])} {p}" for p in PRIORITY_ORDER) + ".",
             "A candidate is a product CISA lists as exploited that is installed here. It is something for a person to check, not a finding that this machine is affected.", ""]
    lines += [f"2. {SECTIONS[1]}"]
    n = 0
    for p in PRIORITY_ORDER:
        if not by_p[p]:
            continue
        lines += ["", f"{PRIORITY_TITLE[p]} ({len(by_p[p])})"]
        for it in by_p[p]:
            n += 1
            rows = asset_lines(it)
            if rows:
                lines.append(f"  {n}. {it['cve']}  {it.get('product', '')}".rstrip())
                lines += rows
            else:
                lines.append(f"  {n}. {it['cve']}  {it.get('product', '')} {it.get('version', '')}".rstrip())
                lines.append(f"     version check: {it.get('verdict', 'undetermined')}: {VERDICT_TEXT.get(str(it.get('verdict')), VERDICT_TEXT['undetermined'])}")
                if it.get("matched"):
                    lines.append("     matched: " + "; ".join(str(m) for m in it["matched"][:5]))
            lines += [f"     why: {w}" for w in _why(it)]
    if not shown:
        lines.append("No candidate was found by this scan. That is not an all-clear: see what was not covered.")
    if payload.get("cut"):
        lines += ["", f"{payload['cut']} lower-priority item(s) are left out of the payload that a mailed report would use; this file lists every candidate."]
    lines += ["", f"3. {SECTIONS[2]}",
              "The installed upstream version of each matching product, against the version ranges NVD lists, for ids CISA lists as exploited. A match by product name is a candidate; the range check is evidence, not a verdict.", "",
              f"4. {SECTIONS[3]}", "These are things to read or look at yourself. This report runs nothing."]
    for v in dict.fromkeys(str(i.get("verdict")) for i in shown):
        ex = next(i for i in shown if str(i.get("verdict")) == v)
        lines.append(f"  - {CHECK_TEXT.get(v, CHECK_TEXT['undetermined']).format(cve=ex['cve'], product=ex.get('product', 'the package'))}")
    off = 1 if posture else 0
    masked = []
    if posture:
        block = posture_lines(posture)
        masked = block[1:]                                            # the machine's own signals are quoted, not written by this report: the wording check masks them
        lines += ["", f"5. {POSTURE_TITLE}"] + block
    lines += ["", f"{5 + off}. {SECTIONS[4]}"] + [f"  - {s}" for s in SOURCES] + [f"  Read from Lattice on {day}.", "", f"{6 + off}. {SECTIONS[5]}"]
    if payload.get("level") == "deep":
        lines.append("A deep scan also opened local container images. Packages that this tool does not read (firmware beyond what the machine reports, software installed outside a package manager, anything not on this machine) were not checked.")
    else:
        lines.append("Quick scan: running images only; stopped images and the packages inside images were not checked. Software installed outside a package manager was not checked either.")
    lines += ["A scan with no candidate, or a version outside a range, is not an all-clear.", "", f"{7 + off}. {SECTIONS[6]}",
              "A candidate is not a finding. A distribution can fix a flaw under an unchanged version number. CISA lists exploitation it has seen; an id it does not list may still be exploited. This report makes no claim about accuracy.", ""]
    text = "\n".join(lines)
    check_wording(text, shown, masked)
    return text


POSTURE_TITLE = "What listens and what runs on this machine"


def posture_lines(d: dict) -> list[str]:
    """The posture reading as report lines: the scope, the socket counts, the signals the posture module wrote (attention first) and what could not be read.
    The first line is this report's own notice; the rest is quoted from the posture module. Names ports and programs: local file only."""
    who = "root" if d.get("scope") == "root" else "a normal user"
    ports = d.get("ports") or []
    cnt = lambda b: len([p for p in ports if p.get("bind") == b])      # noqa: E731
    out = ["This section names ports and programs on this machine. It stays in this file and is never sent.",
           f"Read as {who} ({d.get('level', 'quick')}). {len(ports)} listening sockets: {cnt('all interfaces')} on all interfaces, {cnt('loopback only')} on loopback only, {cnt('one address')} on one address."]
    obs = sorted((o for o in d.get("observations") or [] if o.get("text")), key=lambda o: 0 if o.get("level") == "attention" else 1)
    if obs:
        out.append("Signals for a person to read (each can be harmless; none is a verdict):")
        out += [f"  [{o.get('level', 'note')}] {o['text']}" for o in obs]
    else:
        out.append("No signal was raised. That is not an all-clear.")
    if d.get("unreadable"):
        out.append("Not read: " + "; ".join(str(u) for u in d["unreadable"][:10]) + ". Running as root would read them; this tool never runs sudo.")
    return out


def check_wording(text: str, items: list[dict] = (), masked_lines: list[str] = ()) -> None:
    """Raise ValueError naming a banned word. Product names are masked first: a product called 'Safe' is not the report calling a machine safe."""
    masked = text
    for ln in masked_lines:
        masked = masked.replace(ln, "·")
    for it in items:
        for field in ("product", "version"):
            v = str(it.get(field, ""))
            if v:
                masked = masked.replace(v, "·")
    m = BANNED.search(masked)
    if m:
        raise ValueError(f"the report must not say '{m.group(0).lower()}'")


def save_report(text: str, directory: Path, out=None, now: dt.datetime | None = None) -> Path:
    """Write the report to a new file in `directory` (created 0700 if missing), mode 0600, and print the path. Never overwrites."""
    d = Path(directory)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = (now or dt.datetime.now()).strftime("%Y%m%d-%H%M%S")
    p = d / f"report-{stamp}.txt"
    i = 1
    while True:
        try:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            i += 1
            p = d / f"report-{stamp}-{i}.txt"
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"[report] written to {p}", file=out if out is not None else sys.stderr)
    return p
