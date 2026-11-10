"""A TEST-ONLY Ed25519 signer (RFC 8032 section 6) built on the verifier's own primitives, so the tests can make signed indexes without OpenSSL.
It is validated in test_exploited.py against the RFC 8032 test 1 signature. It is never imported by the program."""
import hashlib
from lattice_scan import ed25519 as e


def _compress(point):
    X, Y, Z, _ = point
    zi = e._inv(Z)
    x, y = X * zi % e._P, Y * zi % e._P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def public_key(seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _compress(e._mul(a, e._G))


def sign(seed: bytes, msg: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    A = _compress(e._mul(a, e._G))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % e._Q
    R = _compress(e._mul(r, e._G))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % e._Q
    return R + ((r + k * a) % e._Q).to_bytes(32, "little")
