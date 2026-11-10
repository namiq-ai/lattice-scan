# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Check the signature on namiq.io's recent-CVE list: the standard library plus the verify-only Ed25519 in this package.

namiq.io serves recent.json together with recent.json.sig (64 raw bytes, an Ed25519 signature over the exact bytes of recent.json) and recent.json.cert (a
short certificate for the feed key). The certificate carries the feed key's public key, a serial and an expiry of at most 90 days, and is signed by a root
key whose public half is ROOT_PUBLIC_KEY below, fixed at build time. The root private key is kept offline by NamiQ. The certificate is signed over exactly
these lines, each ending in a newline: lattice-feed-cert/1, key, serial, notBefore, notAfter (key and signature are lower-case hex).

Three outcomes, never a guess: "verified" (every check passed), "unsigned" (namiq.io offered no signature or certificate: the list is read as before and
labelled), "refused" (a signature or certificate was offered and is wrong, expired, from an older serial or the wrong key: the list is not used).
"""
from __future__ import annotations

import calendar
import re
import time
from typing import NamedTuple

from lattice_scan import ed25519

ROOT_PUBLIC_KEY = bytes.fromhex("eaf7b44936b1613c2c113f2cb3945263ea68e6604e3796f2a8869ce71f8390c1")
MIN_SERIAL = 1            # raised in a release to revoke every certificate below it
MAX_CERT_DAYS = 90
CERT_TAG = "lattice-feed-cert/1"

_KEYS = {"v", "key", "serial", "notBefore", "notAfter", "sig"}
_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z")


class Result(NamedTuple):
    status: str          # verified | unsigned | refused
    reason: str          # why, in a sentence (empty when verified)
    serial: int = 0
    not_after: str = ""


def _epoch(text: object) -> float | None:
    m = _TIME.fullmatch(text) if isinstance(text, str) else None
    if not m:
        return None
    y, mo, d, h, mi, s = (int(x) for x in m.groups())
    if not (1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 61):
        return None
    try:
        t = calendar.timegm((y, mo, d, h, mi, s))
        return t if time.gmtime(t)[:3] == (y, mo, d) else None    # 30 February and the like
    except (OverflowError, ValueError):
        return None


def parse_cert(raw: bytes) -> dict | None:
    """The certificate as a dict, or None unless it has exactly the six expected fields in the expected shapes."""
    import json
    try:
        c = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(c, dict) or set(c) != _KEYS or c["v"] != 1 or isinstance(c["v"], bool):
        return None
    if not (isinstance(c["key"], str) and re.fullmatch(r"[0-9a-f]{64}", c["key"]) and isinstance(c["sig"], str) and re.fullmatch(r"[0-9a-f]{128}", c["sig"])):
        return None
    if not isinstance(c["serial"], int) or isinstance(c["serial"], bool) or c["serial"] < 1:
        return None
    if _epoch(c["notBefore"]) is None or _epoch(c["notAfter"]) is None:
        return None
    return c


def cert_message(c: dict) -> bytes:
    return f"{CERT_TAG}\n{c['key']}\n{c['serial']}\n{c['notBefore']}\n{c['notAfter']}\n".encode()


def cert_problem(c: dict, now: float, root: bytes | None = None, min_serial: int | None = None) -> str:
    """Why the certificate cannot be trusted now, or "" when it can. The root key and lowest serial are read at call time, so a test can pass others."""
    root = ROOT_PUBLIC_KEY if root is None else root
    min_serial = MIN_SERIAL if min_serial is None else min_serial
    if not ed25519.verify(root, cert_message(c), bytes.fromhex(c["sig"])):
        return "the certificate was not signed by NamiQ's root key"
    start, end = _epoch(c["notBefore"]), _epoch(c["notAfter"])
    if end <= start:
        return "the certificate ends before it starts"
    if end - start > MAX_CERT_DAYS * 86400:
        return f"the certificate is valid for more than {MAX_CERT_DAYS} days"
    if now < start:
        return "the certificate is not valid yet (is this machine's clock right?)"
    if now >= end:
        return "the certificate has expired"
    if c["serial"] < min_serial:
        return f"the certificate's serial {c['serial']} is older than the lowest this version accepts ({min_serial})"
    return ""


def check(body: bytes, sig: bytes | None, cert: bytes | None, now: float | None = None, root: bytes | None = None, min_serial: int | None = None) -> Result:
    """Judge a downloaded list. `sig` and `cert` are None when namiq.io offered none (not found); anything offered must be right."""
    if sig is None and cert is None:
        return Result("unsigned", "namiq.io offered no signature for this list")
    if sig is None or cert is None:
        return Result("refused", "a signature was offered without its certificate, or the other way round")
    c = parse_cert(cert)
    if c is None:
        import json
        try:
            json.loads(cert.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return Result("unsigned", "namiq.io answered the certificate request with something that is not a certificate")   # e.g. a web page where nothing is published
        return Result("refused", "the certificate is damaged")
    t = time.time() if now is None else now
    bad = cert_problem(c, t, root, min_serial)
    if bad:
        return Result("refused", bad)
    if not ed25519.verify(bytes.fromhex(c["key"]), body, sig):
        return Result("refused", "the signature does not match the list")
    return Result("verified", "", c["serial"], c["notAfter"])
