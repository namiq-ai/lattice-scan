# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""What happens at the end of a scan: the local report file, and the once-per-run offer to have it mailed (OCO-6054 to OCO-6057, epic OCO-6045).

The local report is always built from the scan result and written to a private file when there is at least one candidate. The
OFFER to mail it is not shipped yet: sending needs the mailbox proof and the gates of the report ADR, so `MAIL_AVAILABLE` is False
and no question is asked until that path exists. The offer logic is here, tested, so it can be switched on with that path.
Nothing in this module talks to the network.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from . import scan_report as sr
from . import scan_report_text as rt

MAIL_AVAILABLE = False      # set True only with the Confirm path of the report ADR (D2); until then the tool never asks to mail anything
FIELD_NAMES = ("CVE id", "product", "installed upstream version", "verdict", "scan level", "operating-system family")


def _os_here() -> str:
    import platform
    info: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            k, _, v = line.partition("=")
            info[k] = v.strip('"')
    except OSError:
        pass
    return sr.os_family(info.get("ID", ""), info.get("ID_LIKE", ""), platform.system())


def host_items(hits: list, inv: dict) -> list[dict]:
    """From the host scan's (entry, why, impact) tuples. The product is CISA's product name; the version is the installed package's own."""
    out = []
    for e, _why, imp in hits:
        names = list(imp.get("installed") or [])
        ver = next((str(inv.get("packages", {}).get(n) or inv.get("snaps", {}).get(n) or "") for n in names if inv.get("packages", {}).get(n) or inv.get("snaps", {}).get(n)), "")
        pr = imp.get("priority") or {}
        out.append({"cve": e["cve"], "product": e.get("product") or e.get("title", "")[:60], "version": ver, "verdict": (imp.get("versionCheck") or {}).get("verdict", "undetermined"),
                    "priority": pr.get("level", "read"), "why": list(pr.get("reasons") or []), "listed": e.get("added", ""), "due": e.get("due", ""), "due_status": imp.get("dueStatus", "")})
    return out


def project_items(results: list[dict]) -> list[dict]:
    """From the project scan: the package name and its declared version and the verdict. A file name or line never goes in."""
    out = []
    for r in results:
        for h in r.get("candidates", []):
            d = (h.get("declared") or [{}])[0]
            out.append({"cve": h["cve"], "product": d.get("name", ""), "version": d.get("version") or "", "verdict": (h.get("versionCheck") or {}).get("verdict", "undetermined"),
                        "priority": "read", "listed": h.get("listed", ""), "due": h.get("due", "")})
    return out


def should_offer(n_items: int, *, stdin_tty: bool, stderr_tty: bool, env: dict, quiet: bool, fmt: str = "table", enabled: bool | None = None) -> bool:
    """Only a person at a terminal, with at least one candidate, outside CI, not quiet, in the plain table format."""
    if not (MAIL_AVAILABLE if enabled is None else enabled):
        return False
    ci = str(env.get("CI", "")).strip().lower() not in ("", "0", "false")
    return n_items > 0 and stdin_tty and stderr_tty and not ci and not quiet and fmt not in ("json", "csv")


def preview(payload: dict) -> str:
    n = len(payload["items"])
    return (f"A report of this scan can be mailed to you. For this run only, this would be sent: {n} item(s), each with its {', '.join(FIELD_NAMES[:4])}; "
            f"and for the run, the {FIELD_NAMES[4]} and the {FIELD_NAMES[5]}"
            + (f" ({payload['cut']} lower-priority item(s) left out)." if payload.get("cut") else ".")
            + "\nNothing else leaves this machine: no hostname, address, port, path or user name.")


def offer(payload: dict, input_fn=input, out=None) -> bool:
    """Ask once for this run. Enter means No. 'd' shows every value that would be sent, then asks again. Nothing is remembered."""
    out = out if out is not None else sys.stderr
    print(preview(payload), file=out)
    while True:
        a = (input_fn("Send a report by email? [y/N/d(etails)] ") or "").strip().lower()
        if a in ("y", "yes"):
            return True
        if a in ("d", "details"):
            print(json.dumps(payload, indent=1), file=out)
            continue
        return False


def after_scan(items: list[dict], level: str, directory: Path, *, quiet: bool, fmt: str = "table", env: dict | None = None, stdin_tty: bool = False, stderr_tty: bool = False,
               input_fn=input, out=None, enabled: bool | None = None, os_name: str | None = None) -> Path | None:
    """Build the payload and the report, write the private file (unless there is no candidate), then offer a mail where allowed."""
    if not items:
        return None
    payload = sr.build_payload(items, level, os_name or _os_here())
    text = rt.build_report(items, payload)
    path = rt.save_report(text, directory, out if not quiet else _Null())
    if should_offer(len(payload["items"]), stdin_tty=stdin_tty, stderr_tty=stderr_tty, env=env if env is not None else {}, quiet=quiet, fmt=fmt, enabled=enabled):
        if offer(payload, input_fn, out):
            print("Mailing a report is not available in this version. Your report is saved at " + str(path), file=out if out is not None else sys.stderr)
    return path


class _Null:
    def write(self, _s: str) -> int:
        return 0

    def flush(self) -> None:
        pass
