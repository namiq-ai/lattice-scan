# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Ed25519 signature VERIFICATION in pure Python, after the reference code in RFC 8032 section 6.

lattice-scan uses only the Python standard library, which has no Ed25519, and the exploited index and its signature must be checkable on any machine. This
module only verifies: it holds no private key and signs nothing. It is not constant-time, which does not matter here because everything it reads (a public
key, a public file, a public signature) is public. It takes about a few tens of milliseconds for one verification. It is checked against the RFC 8032 test
vector and signatures made by OpenSSL (tests/test_ed25519.py), and refuses malformed input with False, never an exception, so a damaged download cannot crash a run.
"""
from __future__ import annotations

import hashlib

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _add(a, b):
    A, B = (a[1] - a[0]) * (b[1] - b[0]) % _P, (a[1] + a[0]) * (b[1] + b[0]) % _P
    C, D = 2 * a[3] * b[3] * _D % _P, 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return E * F % _P, G * H % _P, F * G % _P, E * H % _P


def _mul(s, point):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, point)
        point = _add(point, point)
        s >>= 1
    return q


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(s):
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True only for a valid Ed25519 signature of `message` by `public`. Any malformed input is False."""
    try:
        if len(public) != 32 or len(signature) != 64:
            return False
        a = _decompress(public)
        r = _decompress(signature[:32])
        if a is None or r is None:
            return False
        s = int.from_bytes(signature[32:], "little")
        if s >= _Q:
            return False
        h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _Q
        return _equal(_mul(s, _G), _add(r, _mul(h, a)))
    except Exception:   # a damaged download must never crash a run
        return False
