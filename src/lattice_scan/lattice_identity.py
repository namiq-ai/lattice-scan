# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The one identity join: installed items become Artefacts, and an Artefact meets an exploited product only through a package identity.

Why this exists (ADR-LATTICE-SCAN-004, AD-1/AD-2/AD-6/AD-7): the CLI and the server matched CISA's product WORDS to installed package NAMES, so
`openssh-client` matched a server-side OpenSSH flaw and `node-electron-to-chromium` matched Chromium. Here a word match can still be shown to a person,
but only as a Lead; a Candidate needs an identity join (exact or through a reviewed alias), a version inside the range, and a component that is not
proven absent.

Source and binary. OSV's distribution data (Debian, Alpine, Red Hat) names the SOURCE package (`openssh`); a host has BINARY packages
(`openssh-client`). An Artefact therefore carries its source identity, which is what joins, and its binary name, which is evidence about the component:
an OpenSSH flaw in the server joins `openssh-client` through `deb:openssh`, and the missing `openssh-server` binary is what rules it out.

Standard library only; Python 3.9 and later. Like lattice_version.py, this file is copied unchanged into graph-mcp, and a hash check fails on drift.
"""
from __future__ import annotations

import re
from typing import Iterable, Mapping, NamedTuple, Optional, Sequence

try:                                    # inside a package (lattice_scan, or graph_mcp where it is vendored), beside lattice_version.py
    from .lattice_version import in_range, pid as make_pid, verdict as range_verdict
except ImportError:                     # loaded as a top-level module next to lattice_version.py
    from lattice_version import in_range, pid as make_pid, verdict as range_verdict  # type: ignore[no-redef]

# Strongest first. Only the first two can make a Candidate (AD-7).
CONFIDENCES = ("exact", "alias", "vendor", "word")
CANDIDATE_CONFIDENCE = frozenset(("exact", "alias"))

# The package manager that installed an item owns it (AD-6), and its ecosystem decides the version scheme.
MANAGER_ECOSYSTEM = {"dpkg": ("deb", "dpkg"), "rpm": ("rpm", "rpm"), "apk": ("apk", "apk")}


class Artefact(NamedTuple):
    """One installed thing, in the one shape every Source produces: {pid, version, scheme, owner, source}.

    pid      the identity that joins: `<ecosystem>:<normalised name>`, the SOURCE package for a distribution package
    version  as the owner reports it (dpkg keeps its epoch and revision)
    scheme   a lattice_version scheme
    owner    who installed it: dpkg, rpm, apk, pip, npm, snap, kernel, runtime
    source   which Source read it (host-packages, python, node, ...)
    name     what the person sees: the binary package or file name
    """
    pid: str
    version: str
    scheme: str
    owner: str
    source: str
    name: str


class Component(NamedTuple):
    """Where in a product the flaw sits, as an identity row states it. `binaries` are the distribution binary packages that ship that component
    (`openssh-server`); when the owner's package database is read and none of them is installed, the component is proven absent."""
    role: str                        # server, client, library, plugin, daemon, ... ("" when the row does not say)
    binaries: tuple = ()


class Row(NamedTuple):
    """One exploited CVE with the product identities it affects (the published Identity List row: never ranges, fixed versions or verdicts)."""
    cve: str
    pids: tuple
    component: Optional[Component] = None
    origin: str = ""                 # osv-debian, osv-pypi, alias, ...


class Join(NamedTuple):
    cve: str
    artefact: Artefact
    pid: str                         # the row's pid it met
    confidence: str                  # exact | alias | vendor | word
    via: str                         # a sentence for the person: why these two meet


class Outcome(NamedTuple):
    """What one join amounts to. kind: candidate | component-absent | outside-range | undetermined | lead."""
    kind: str
    join: Join
    evidence: str


# ---------------------------------------------------------------- Sources -> Artefacts
def host_artefacts(inv: Mapping) -> list:
    """Artefacts from the CLI's host inventory dict (`inventory()` in cli.py).

    `packages` maps a binary name to its version. When the inventory also has `sources` (binary -> source package, from dpkg's ${source:Package} or
    rpm's SOURCERPM), the source is the identity; without it the binary name is, which joins only where the binary and source names agree.
    """
    out = []
    manager = inv.get("manager") or ""
    eco, scheme = MANAGER_ECOSYSTEM.get(manager, ("generic", "generic"))
    sources = inv.get("sources") or {}
    for name, version in sorted((inv.get("packages") or {}).items()):
        src = sources.get(name) or name
        out.append(Artefact(make_pid(src, eco), str(version), scheme, manager or "unknown", "host-packages", name))
    for name, version in sorted((inv.get("snaps") or {}).items()):
        out.append(Artefact(make_pid(name, "generic"), str(version), "generic", "snap", "host-snaps", f"snap {name}"))
    node = str(inv.get("node") or "").lstrip("v")
    if node:
        out.append(Artefact(make_pid("node.js", "generic"), node, "semver", "runtime", "node-runtime", f"node {node}"))
    kernel = str(inv.get("kernel") or "")
    if kernel and inv.get("family") != "macos":
        out.append(Artefact(make_pid("linux-kernel", "generic"), kernel, "generic", "kernel", "kernel", f"kernel {kernel}"))
    return out


def installed_binaries(artefacts: Iterable) -> set:
    return {a.name for a in artefacts if a.source == "host-packages"}


# ---------------------------------------------------------------- the join
def join(artefacts: Sequence, rows: Iterable, aliases: Optional[Mapping] = None) -> list:
    """Every (row, artefact) pair that meets by identity: exact when the artefact's pid is one of the row's, alias when a reviewed alias maps the
    artefact's pid onto one of them. `aliases` maps an installed pid to a product pid (the Alias Table, ADR-004 AD-9); only reviewed entries belong here."""
    aliases = aliases or {}
    by_pid: dict = {}
    for a in artefacts:
        by_pid.setdefault(a.pid, []).append(a)
    alias_from: dict = {}
    for frm, to in aliases.items():
        alias_from.setdefault(to, []).append(frm)
    out = []
    for r in rows:
        for p in r.pids:
            for a in by_pid.get(p, ()):
                out.append(Join(r.cve, a, p, "exact", f"{a.name} is {p}"))
            for frm in alias_from.get(p, ()):
                for a in by_pid.get(frm, ()):
                    out.append(Join(r.cve, a, p, "alias", f"{a.name} ({frm}) is known as {p} (Alias Table)"))
    return out


_WORD = re.compile(r"[a-z][a-z0-9]+")


def word_leads(cve: str, product_words: Iterable, artefacts: Sequence, already: Iterable = ()) -> list:
    """Leads from words, for a person to read and never a Candidate: an installed name holding every distinctive word of the product.
    Artefacts that already joined by identity for this CVE are skipped, so a lead never repeats a stronger join."""
    want = {w.lower() for w in product_words if len(w) >= 3}
    if not want:
        return []
    joined = {j.artefact for j in already if j.cve == cve}
    out = []
    for a in artefacts:
        if a in joined:
            continue
        have = set(_WORD.findall(a.name.lower()))
        if want <= have:
            out.append(Join(cve, a, "", "word", f"the name {a.name} holds the words {' '.join(sorted(want))}"))
    return out


# ---------------------------------------------------------------- what a join amounts to
def component_absent(row: Row, j: Join, binaries: set) -> Optional[str]:
    """Evidence that the vulnerable component is not on this host, or None. Proof needs the row to name the component's binaries and the artefact to
    come from the package database that would list them; a missing process or listener is never proof."""
    c = row.component
    if not c or not c.binaries or j.artefact.source != "host-packages":
        return None
    if any(b in binaries for b in c.binaries):
        return None
    role = f"{c.role} " if c.role else ""
    return f"the {role}component ships in {', '.join(c.binaries)}, which {'is' if len(c.binaries) == 1 else 'are'} not installed ({j.artefact.owner} database read)"


def assess(row: Row, j: Join, ranges: Optional[Sequence], binaries: set) -> Outcome:
    """The verdict ladder for one join (AD-7). A Candidate needs an identity join, a version in range and a component not proven absent.
    `ranges` are the server's (or a fixture's) ranges for j.pid; None means no version verdict was obtained, which is undetermined, never a Candidate."""
    if j.confidence not in CANDIDATE_CONFIDENCE:
        return Outcome("lead", j, j.via + "; a name match is a lead for a person, not a candidate")
    gone = component_absent(row, j, binaries)
    if gone:
        return Outcome("component-absent", j, gone)
    if ranges is None:
        return Outcome("undetermined", j, j.via + "; no version verdict was obtained")
    v = range_verdict(j.artefact.version, j.artefact.scheme, list(ranges))
    if v == "in-range":
        # A generic comparison is never stronger than undetermined (AD-5): a distribution can fix a flaw under an unchanged upstream number, so only a
        # range in the artefact's own scheme (a distribution fixed version, a PyPI range) can make a Candidate.
        own = [r for r in ranges if (r.get("scheme") or "generic") != "generic" and in_range(j.artefact.version, j.artefact.scheme, r) is True]
        if not own or j.artefact.scheme == "generic":
            return Outcome("undetermined", j, j.via + f"; {j.artefact.version} falls inside the range only by upstream numbers, which a distribution fix can leave unchanged")
        return Outcome("candidate", j, j.via + f"; {j.artefact.version} is inside the affected range")
    if v == "outside-range":
        return Outcome("outside-range", j, j.via + f"; {j.artefact.version} is outside the affected range")
    return Outcome("undetermined", j, j.via + f"; {j.artefact.version} cannot be compared with the range")
