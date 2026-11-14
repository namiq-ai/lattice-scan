# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""What happens at the end of a scan: the local report file, and the once-per-run offer to have it mailed (OCO-6054 to OCO-6057, epic OCO-6045).

The local report is always built from the scan result and written to a private file when there is at least one candidate. The
OFFER to mail it is made to a person at a terminal during the trial (`REPORT_TRIAL_END`), and only when the report accuracy fields are on too: the report is made from
them, so the two switches are one decision (`MAIL_AVAILABLE` and `scan_record.REPORT_FIELDS_AVAILABLE`). Nothing in this module talks to the network.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
from pathlib import Path

from . import scan_record as rec
from . import scan_report_send as send
from . import scan_report as sr
from . import scan_report_text as rt

MAIL_AVAILABLE = True       # the Confirm path of the report ADR (D2); the offer is made only while the trial runs
REPORT_TRIAL_END = dt.date(2026, 12, 31)   # the report is a trial feature up to and including this day (UTC); after it this version makes no offer
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


def _split_installed(entry: str, inv: dict) -> tuple[str, str]:
    """The scan's matched-package strings carry the version ('libbrotli1 1.2.0-3ubuntu0.1', 'kernel 7.0.0-41'): split on the first space, and fall back to the inventory."""
    name, _, ver = str(entry).partition(" ")
    ver = ver.strip() or str(inv.get("packages", {}).get(name) or inv.get("snaps", {}).get(name) or "")
    return name, ver


_IMAGE_MARK = re.compile(r" \(image (?P<ref>[^()]+)\)")


def entry_parts(entry: str) -> tuple[str, str, str]:
    """One matched-package string as (name, version, image). The scan writes an image package two ways: 'libbrotli1 1.1.0-2 (image web:1)' (found by name) and
    'libbrotli1 (image web:1) 1.1.0-2' (joined by identity); both give ('libbrotli1', '1.1.0-2', 'web:1'). A host package has image ''."""
    text = str(entry)
    m = _IMAGE_MARK.search(text)
    label, ref = (text[:m.start()] + text[m.end():], m.group("ref")) if m else (text, "")
    name, _, ver = label.strip().partition(" ")
    return name, ver.strip(), ref


def match_basis(imp: dict) -> str:
    """How this candidate was matched, as one word: 'identity' when the package joined through the signed identity list, 'range' when it matched by name and a version
    range was compared, otherwise 'name'."""
    if imp.get("matchBasis") == "identity":
        return "identity"
    return "range" if (imp.get("versionCheck") or {}).get("verdict") in ("in-range", "outside-range") else "name"


def report_extras(imp: dict, inv: dict, changelog_read=None) -> dict:
    """The accuracy fields of one item (assets, installedVersions, basis, changelog). The distribution status is added later, only after the person's yes."""
    parts = [entry_parts(n) for n in (imp.get("installed") or [])][:10]
    packages = inv.get("packages") or {}
    if imp.get("changelogNamesCve"):
        changelog = "names"
    else:
        changelog = "none" if changelog_read is not None and changelog_read(list(imp.get("installed") or []), inv) else "unchecked"
    return {"assets": [ref or rec.ASSET_HOST for _n, _v, ref in parts],
            "installedVersions": [v or ("" if ref else str(packages.get(n) or (inv.get("snaps") or {}).get(n) or "")) for n, v, ref in parts],
            "basis": match_basis(imp), "changelog": changelog}


def distro_entry(answer: dict, os_name: str) -> dict:
    """One distribution answer (graph_affects: verdict, why, reason, basis) in the record's words. Anything it cannot place is 'unknown'."""
    unknown = {"verdict": "unknown", "fixedIn": "", "source": ""}
    osn = (os_name or "").strip().lower()
    src = next((k for k in rec.DISTRO_SOURCES if osn.startswith(k)), "")
    if not src or answer.get("basis") != "distribution":
        return unknown
    why = str(answer.get("why") or "")
    verdict, reason = answer.get("verdict"), answer.get("reason")
    fixed = ""
    if verdict == "outside-range":
        m = re.search(r"fixed this in ([^\s,;()]+)", why)
        fixed = m.group(1) if m else ""
        word = "not-affected" if reason == "not-affected" else "fixed"
    elif verdict == "in-range":
        m = re.search(r"before the fix in .*?\(([^)]+)\)", why)
        fixed = m.group(1).split(",")[0].strip() if m else ""
        word = "before-fix" if fixed else ("no-fix-yet" if "no fix yet" in why else "unknown")
    else:
        return unknown
    if word == "unknown":
        return unknown
    return {"verdict": word, "fixedIn": fixed if rec._FIXED_IN.fullmatch(fixed) else "", "source": src}


def merge_distro(items: list[dict], answers: dict) -> list[dict]:
    """Add `distro` to each item the distribution was asked about: `answers` is {cve: {(name, asset): entry}}. An entry the answers do not cover is 'unknown'.
    Items the question did not cover are returned unchanged, so a row without the status says 'version range only'."""
    out = []
    for it in items:
        got = answers.get(it.get("cve"))
        if got is None or "assets" not in it:
            out.append(it)
            continue
        unknown = {"verdict": "unknown", "fixedIn": "", "source": ""}
        out.append({**it, "distro": [got.get((n, a), unknown) for n, a in zip(it.get("installed") or [], it["assets"])]})
    return out


def asset_rows(installed: list, inv: dict) -> list[dict]:
    """One row per matched package for the local report: name, version, the asset ('' for the host, else the image reference) and whether it runs now (the host does; an
    image does when a container is using it). Local only: the record and the payload never read this key."""
    details = inv.get("imageDetails") or {}
    running = set(inv.get("images") or [])
    rows = []
    for entry in installed:
        name, ver, ref = entry_parts(entry)
        rows.append({"name": name, "version": ver, "asset": ref, "running": True if not ref else bool((details.get(ref) or {}).get("running", ref in running))})
    return rows


def host_items(hits: list, inv: dict, changelog_read=None) -> list[dict]:
    """From the host scan's (entry, why, impact) tuples. The product is CISA's product name; the name and version are the matched package's own."""
    out = []
    for e, _why, imp in hits:
        parts = [_split_installed(n, inv) for n in (imp.get("installed") or [])]
        pr = imp.get("priority") or {}
        out.append({**(report_extras(imp, inv, changelog_read) if rec.REPORT_FIELDS_AVAILABLE else {}), "cve": e["cve"], "product": e.get("product") or e.get("title", "")[:60], "version": next((v for _, v in parts if v), ""),
                    "verdict": (imp.get("versionCheck") or {}).get("verdict", "undetermined"),
                    "priority": pr.get("level", "read"), "why": list(pr.get("reasons") or []), "installed": [n for n, _ in parts][:10], "rows": asset_rows(imp.get("installed") or [], inv),
                    "matched": [f"{n} {v}".strip() for n, v in parts][:5], "listed": e.get("added", ""), "due": e.get("due", ""), "due_status": imp.get("dueStatus", "")})
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


def project_inventory(results: list[dict]) -> dict:
    """The inventory of a project scan: the declared package names and versions, never a file name or line."""
    pk: dict[str, str] = {}
    for r in results:
        for h in r.get("candidates", []):
            for d in h.get("declared") or []:
                if d.get("name"):
                    pk[str(d["name"])] = str(d.get("version") or "")
    return {"os": "project manifests", "packages": pk}


def trial_open(today: dt.date | None = None) -> bool:
    return (today or dt.datetime.now(dt.timezone.utc).date()) <= REPORT_TRIAL_END


def should_offer(n_items: int, *, stdin_tty: bool, stderr_tty: bool, env: dict, quiet: bool, fmt: str = "table", enabled: bool | None = None, today: dt.date | None = None) -> bool:
    """Only a person at a terminal, with at least one candidate, outside CI, not quiet, in the plain table format, while the trial runs."""
    if not (MAIL_AVAILABLE if enabled is None else enabled) or not trial_open(today):
        return False
    ci = str(env.get("CI", "")).strip().lower() not in ("", "0", "false")
    return n_items > 0 and stdin_tty and stderr_tty and not ci and not quiet and fmt not in ("json", "csv")


TRIAL_LINE = f"The emailed report is a trial feature until {REPORT_TRIAL_END.day} {REPORT_TRIAL_END.strftime('%B %Y')}.\n"


def preview(p: dict) -> str:
    """What would be sent, in words. A scan record (with an inventory) or the items view alone."""
    n = len(p["items"])
    if "inventory" in p:
        inv = p["inventory"]
        return (TRIAL_LINE + f"A report of this scan can be mailed to you. For this run only, this would be sent: {n} finding(s) (CVE id, product, installed version, verdict, priority, reasons, dates); "
                f"and the inventory of this machine: {len(inv['packages'])} package(s), {len(inv['snaps'])} snap(s) and {len(set(inv['images']) | set(inv.get('imageDetails', {})))} container image name(s) "
                f"(an image name can name an internal registry), the kernel and OS names, the hardware maker and model, and the scan level and operating-system family"
                + (f". The record was reduced to what the findings name: {p['cut']} entr(ies) left out." if p.get("cut") else ".")
                + "\nNothing else leaves this machine: no hostname, address, port, path, user name or process list. You are asked separately about the runtime posture.")
    return (TRIAL_LINE + f"A report of this scan can be mailed to you. For this run only, this would be sent: {n} item(s), each with its {', '.join(FIELD_NAMES[:4])}; "
            f"and for the run, the {FIELD_NAMES[4]} and the {FIELD_NAMES[5]}"
            + (f" ({p['cut']} lower-priority item(s) left out)." if p.get("cut") else ".")
            + "\nNothing else leaves this machine: no hostname, address, port, path or user name.")


FIELDS_NOTE = ("These details are needed to make the report; without them no report is made. Each finding also says which container image or the host holds the package, the installed versions, how it was matched (identity list, name, "
               "version range) and whether a package changelog names the CVE; the report states what this run covered and did not check (counts and fixed words).")


def distro_note(n: int) -> str:
    """The one confirmation's words for the distribution check: what is asked, how many, and that nothing is asked before the yes."""
    if n <= 0:
        return FIELDS_NOTE
    return (FIELDS_NOTE + f"\nThis one yes also covers the check of the distribution's own data: {n} package name(s) with their versions are asked of Lattice, one at a time. "
            "Nothing is asked before your yes, and not the host name, address, path or user. Without the check, rows say \"version range only\". "
            "The distribution status values are added to the record after your yes; 'd' shows the record without them.")


def offer(payload: dict, input_fn=input, out=None, note: str = "") -> bool:   # `payload` is the record or the items view
    """Ask once for this run. Enter means No. 'd' shows every value that would be sent, then asks again. Nothing is remembered."""
    out = out if out is not None else sys.stderr
    print(preview(payload) + (("\n" + note) if note else ""), file=out)
    while True:
        a = (input_fn("Send a report by email? [y/N/d(etails)] ") or "").strip().lower()
        if a in ("y", "yes"):
            return True
        if a in ("d", "details"):
            print(json.dumps(payload, indent=1), file=out)
            continue
        return False


POSTURE_QUESTION = """Also include this machine's runtime posture?
Submit for making the report:
  - listening ports (number, protocol, program name, how widely open),
    firewall and SSH settings (not the rules), programs no package owns
Not submitted: addresses, user names, file paths, command lines,
history, firewall rules, secrets.
This lets the report cover exposure. Without it, it covers software only.
Read with your current permissions only."""


def ask_posture(block: dict, input_fn=input, out=None) -> bool:
    """The second question, asked only after a yes to the report. Default No, its own details ('d' shows the block that would be sent), this run only, nothing remembered."""
    out = out if out is not None else sys.stderr
    print(POSTURE_QUESTION, file=out)
    while True:
        a = (input_fn("Include the posture? [y/N/d(etails)] ") or "").strip().lower()
        if a in ("y", "yes"):
            return True
        if a in ("d", "details"):
            print(json.dumps(block, indent=1), file=out)
            continue
        return False


def record_after_yes(inv: dict | None, items: list[dict], level: str, os_name: str, payload: dict, posture: dict | None, input_fn=input, out=None, secrets_fn=None,
                     coverage: dict | None = None) -> dict:
    """What a yes to the report would send: the record, with the posture block only when the person also says yes to the second question.
    A project scan (no machine inventory) or a posture that could not be read has no second question; the record then has no posture key."""
    if inv is None:
        return payload
    if posture is None:
        return rec.build_record(inv, items, level, os_name, coverage=coverage)
    from . import local_secrets
    if "localSecrets" not in posture:                  # looked for only now, when the person is about to be asked; kind, place and count, never the value
        try:
            posture = {**posture, "localSecrets": (secrets_fn or local_secrets.find)()}
        except Exception:  # noqa: BLE001 - a missing check must not stop the question
            posture = {**posture, "localSecrets": []}
    block = rec.posture_block(posture)
    note = local_secrets.notice(posture.get("localSecrets") or [])
    if note:
        print(note, file=out if out is not None else sys.stderr)      # shown before the question; the value is not in the posture result and never in the record
    return (rec.build_record(inv, items, level, os_name, posture=posture, coverage=coverage) if ask_posture(block, input_fn, out)
            else rec.build_record(inv, items, level, os_name, coverage=coverage))


def after_scan(items: list[dict], level: str, directory: Path, *, quiet: bool, fmt: str = "table", env: dict | None = None, stdin_tty: bool = False, stderr_tty: bool = False,
               input_fn=input, out=None, enabled: bool | None = None, os_name: str | None = None, inv: dict | None = None, posture: dict | None = None, secrets_fn=None, post=None, key: str | None = None, terms_version=None, store_key=None, interactive=None,
               coverage: dict | None = None, distro_pending: int = 0, distro_fn=None) -> Path | None:
    """Build the payload and the report, write the private file (unless there is no candidate), then offer a mail where allowed.

    With the report accuracy fields switched on (scan_record.REPORT_FIELDS_AVAILABLE), the one confirmation also says how many package names the distribution check
    (`distro_fn`) will ask of Lattice; the check runs only after the person's yes, and never for a run without a terminal, because no offer is made there."""
    if not items:
        return None
    os_w = os_name or _os_here()
    payload = sr.build_payload(items, level, os_w)
    text = rt.build_report(items, payload, posture=posture)
    path = rt.save_report(text, directory, out if not quiet else _Null())      # the local report never depends on the record or the offer
    if should_offer(len(payload["items"]), stdin_tty=stdin_tty, stderr_tty=stderr_tty, env=env if env is not None else {}, quiet=quiet, fmt=fmt, enabled=enabled):
        first = rec.build_record(inv, items, level, os_w, coverage=coverage) if inv is not None else payload      # what a yes would send: the record when the scan has an inventory
        fields_on = rec.REPORT_FIELDS_AVAILABLE and inv is not None
        if offer(first, input_fn, out, distro_note(distro_pending if distro_fn is not None else 0) if fields_on else ""):
            if fields_on and distro_pending > 0 and distro_fn is not None:
                items = merge_distro(items, distro_fn())          # the one yes covers this; the answers are added to the findings before the record is built
            sendable = record_after_yes(inv, items, level, os_w, payload, posture if kind_is_host(inv) else None, input_fn, out, secrets_fn, coverage=coverage)
            if post is not None or MAIL_AVAILABLE:
                from . import __version__
                send.send_report(sendable, key, __version__, input_fn, out, post=post or send.default_post, terms_version=terms_version, store_key=store_key, interactive=interactive)
            else:
                print("Mailing a report is not available in this version. Your report is saved at " + str(path), file=out if out is not None else sys.stderr)
    return path


def kind_is_host(inv: dict | None) -> bool:
    """A project scan's inventory is the declared packages only (`os` is 'project manifests'); the runtime posture belongs to a host scan."""
    return isinstance(inv, dict) and inv.get("os") != "project manifests"


class _Null:
    def write(self, _s: str) -> int:
        return 0

    def flush(self) -> None:
        pass
