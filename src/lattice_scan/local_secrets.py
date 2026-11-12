# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Secret-looking values on this machine, found by the posture scan and kept here.

The posture scan reads the command lines of the running programs it may read and the person's shell history files, looks for values shaped like a
key, token or password, and reports only the KIND of value and WHERE it was seen, with a count. The value is matched and dropped in the same step:
it is never stored in a variable that outlives the match, never written to a file, a record, a log or a report, and never sent. Nothing here talks to
the network. A match is a lead for a person (a harmless test value matches too), never a verdict.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

CMDLINE = "a running program's command line"
HISTORY = "shell history"
HISTORY_FILES = (".bash_history", ".zsh_history", ".local/share/fish/fish_history", ".history")
MAX_READ = 4_000_000
# (kind, pattern). Kinds are words for a person; the pattern is shaped like the secret and is never printed.
PATTERNS = (
    ("Lattice API key", re.compile(r"\blat_[A-Za-z0-9_-]{16,}")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("API key (sk- style)", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("password, token or key on a command line", re.compile(r"(?i)(?:\bpass(?:word|wd)?|\bpwd|\btoken|\bsecret|\bapi[_-]?key)=\S{4,}|--password[= ]\S{4,}")),
)


def _kinds(text: str) -> set[str]:
    """The kinds of secret-looking value in `text`; the values themselves are not returned."""
    return {kind for kind, rx in PATTERNS if rx.search(text)}


def _read(path: Path) -> str:
    try:
        with open(path, "rb") as f:
            return f.read(MAX_READ).decode("utf-8", "replace")
    except OSError:
        return ""


def find(home: Path | None = None, proc_root: str = "/proc") -> list[dict]:
    """[{'kind', 'where', 'count'}]: what kind of value, in which kind of place, and how many lines or programs hold one. Never the value, a path or a user name."""
    found: dict[tuple[str, str], int] = {}
    try:
        pids = [p for p in os.listdir(proc_root) if p.isdigit()]
    except OSError:
        pids = []
    for pid in pids:
        text = _read(Path(proc_root) / pid / "cmdline").replace("\0", " ")
        for kind in _kinds(text):
            found[(kind, CMDLINE)] = found.get((kind, CMDLINE), 0) + 1
    home = home if home is not None else Path(os.path.expanduser("~"))
    for rel in HISTORY_FILES:
        for line in _read(home / rel).splitlines():
            for kind in _kinds(line):
                found[(kind, HISTORY)] = found.get((kind, HISTORY), 0) + 1
    return [{"kind": k, "where": w, "count": n} for (k, w), n in sorted(found.items())]


def notice(found: list[dict]) -> str:
    """The line the screen shows: what was found and where, and that it stays here. Empty when nothing was found."""
    if not found:
        return ""
    parts = [f"{f['kind']} ({f['where']})" for f in found]
    return ("Secret-looking value(s) found on this machine: " + "; ".join(parts)
            + ". Kept on this machine and never sent; the report may say that one was found, never what it was. Rotate it and remove it from your history.")
