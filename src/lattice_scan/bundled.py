# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Node.js runtimes bundled inside other packages, read from the file and never run.

Why: a Python or Node package can ship its own Node binary (Playwright's driver/node), which no package manager lists and `node -v` never sees. On one
host it was the only exploited exposure every other reader missed: Node 24.17.0 inside a pip-installed Playwright, below the fix in 24.22.1.

How: the official Node build carries its release URL ("https://nodejs.org/download/release/v24.17.0") as plain text in the binary (process.release).
The file is read in chunks for that pattern only; it is never executed, so a hostile file cannot run anything. Only files named `node` (or node.exe)
that start like an executable (ELF, Mach-O or PE) are read, at a few fixed places inside the environments --python and --node already found, so the
cost is bounded: at most MAX_FILES files and MAX_BYTES each.
"""
from __future__ import annotations

import glob
import os
import re
from collections import Counter
from pathlib import Path

MARK = re.compile(rb"nodejs\.org/download/release/v(\d{1,3}\.\d{1,3}\.\d{1,3})\b")
MAGIC = (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"MZ")
MAX_FILES = 40
MAX_BYTES = 400_000_000
CHUNK = 1 << 20
# Where packages put a Node binary, relative to a Python site directory or a global node_modules folder. Fixed patterns, never a recursive walk.
PATTERNS = ("*/driver/node", "*/driver/node.exe", "*/bin/node", "*/node/bin/node", "*/vendor/node", "*/.bin/node-bin/node")


def node_version(path: str) -> str:
    """The Node release a binary was built as ("24.17.0"), or "" when it is not an executable or carries no release mark."""
    try:
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > MAX_BYTES:
            return ""
        with open(path, "rb") as f:
            head = f.read(4)
            if not any(head.startswith(m) for m in MAGIC):
                return ""
            f.seek(0)
            seen: Counter = Counter()
            tail = b""
            while chunk := f.read(CHUNK):
                buf = tail + chunk
                seen.update(m.group(1).decode() for m in MARK.finditer(buf))
                tail = buf[-80:]
    except OSError:
        return ""
    return seen.most_common(1)[0][0] if seen else ""


def find_node(roots: list[str]) -> list[dict[str, str]]:
    """[{version, where}] for each bundled Node binary under the given site or node_modules folders; `where` is the owning package's folder name
    and the place, never more of the path than the folder the caller already reports."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for root in roots:
        for pat in PATTERNS:
            for p in sorted(glob.glob(os.path.join(glob.escape(root), pat))):
                real = os.path.realpath(p)
                if real in seen or len(seen) >= MAX_FILES:
                    continue
                seen.add(real)
                v = node_version(p)
                if v:
                    rel = Path(p).relative_to(root).parts
                    out.append({"version": v, "package": rel[0], "root": root})
    return out
