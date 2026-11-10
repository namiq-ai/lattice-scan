#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Release gate: would THIS build accept namiq.io's live recent-CVE list?

A build carries NamiQ's root public key (src/lattice_scan/feedsig.py). If that key is not the one the live certificate was signed with, every installed copy of
this release would refuse the live list. This reads the live list, signature and certificate and runs the build's own check on them.

  exit 0  verified, or not signed yet (a warning), or namiq.io could not be reached (a warning: the gate does not fail a release on an outage)
  exit 1  a signature or certificate is offered and this build would refuse it: do not release
"""
from __future__ import annotations

import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from lattice_scan import feedsig  # noqa: E402

BASE = "https://namiq.io/lattice/recent.json"


def get(url: str):
    """The bytes, None for HTTP 404, and an exception for anything else."""
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "lattice-scan-release-check"}), timeout=30) as r:
            return r.read(2_000_000)
    except urllib.error.HTTPError as e:
        e.close()
        if e.code == 404:
            return None
        raise


def judge(fetch=get, base: str = BASE) -> tuple[int, str]:
    try:
        body = fetch(base)
        if body is None:
            return 0, f"WARN: {base} not found; nothing to check"
        r = feedsig.check(body, fetch(base + ".sig"), fetch(base + ".cert"))
    except Exception as e:  # noqa: BLE001
        return 0, f"WARN: namiq.io could not be read ({e}); the signature was not checked"
    if r.status == "refused":
        return 1, f"FAIL: this build would REFUSE the live list: {r.reason}. Do not release it (is ROOT_PUBLIC_KEY the key that signs the live certificate?)"
    if r.status == "unsigned":
        return 0, f"WARN: the live list is not signed ({r.reason}); this build reads it labelled 'not signed'"
    return 0, f"OK: this build verifies the live list (certificate serial {r.serial}, ends {r.not_after})"


if __name__ == "__main__":
    code, msg = judge()
    print(msg)
    sys.exit(code)
