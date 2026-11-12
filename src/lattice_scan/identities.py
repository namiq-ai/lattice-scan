# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The signed identity list, on the client: fetch, check, cache, and turn into join rows.

What the list is: for each CISA-listed CVE, the package identities it affects (`deb:openssh`, `pypi:brotli`). It carries no version ranges, fixed
versions or verdicts. The client joins its own inventory against it on this machine and asks Lattice only about the items that joined.

Why every check fails closed. The list decides what this tool looks for and what it sends. A copy with entries removed would hide real findings; a
copy with entries added would make it send more. So, unlike the recent-CVE feed, there is no "unsigned" fallback here:

    unreachable, a verified cached copy           use the cache and say so
    unreachable, nothing cached                   the copy bundled in this release, verified the same way, with its age said
    unreachable, no usable copy at all            IdentitiesUnavailable (the caller says the identity join could not run)
    no signature, bad signature, unknown key      IdentitiesRefused; the previous cache is left as it was
    a lower generation than one already accepted  IdentitiesRefused (a replayed older copy would hide newer entries)
    larger than MAX_BYTES, wrong schema, a row with range or verdict fields, a malformed id
                                                  IdentitiesRefused
    older than MAX_AGE_DAYS                       used, flagged stale; `require_fresh` makes it a refusal

Checks run on the raw bytes before parsing: size, the manifest's sha256, the pinned key, the signature. generation and exploitedAsOf are read from the
SIGNED document, never from the manifest. The requests carry no data about this machine.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path

from lattice_scan import ed25519
from lattice_scan.lattice_identity import Component, Row

LIST_URL = "https://namiq.io/lattice/identities.json"
MANIFEST_URL = "https://namiq.io/lattice/identities.manifest.json"
# The keys the list may be signed with: key id -> 32 raw public key bytes in hex. A rotation adds a key in a new release; an older client then refuses the
# new key's list with "upgrade lattice-scan" rather than trusting a key it has never seen.
PINNED_KEYS = {"b89358b971c965b4": "434b5277dcd8bff9ba8e213e87744d6747347892834fbe20d79cacc4b95fd501"}
SCHEMA = "lattice-identities/1"
MAX_BYTES = 32 * 1024 * 1024     # a hard ceiling before anything is parsed; the real list is a few hundred kilobytes
MAX_AGE_DAYS = 7                 # past this a run says its exploited data is out of date
REFRESH_AFTER_HOURS = 12         # the cached copy is used without a request for this long (the list is rebuilt twice a day)
STATE = "identities.state.json"
CACHE = "identities.json"

_PID = re.compile(r"^(deb|apk|rpm|pypi|npm|maven|cargo|generic):[a-z0-9@:/.+_-]{1,200}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
# A row holding any of these would be carrying the data that is deliberately not published. Refuse the whole list rather than read around it.
_FORBIDDEN = {"ranges", "range", "versions", "version", "fixed", "fixes", "fixedIn", "introduced", "verdict", "cvss", "epss", "ssvc", "score", "priority"}


class IdentitiesRefused(Exception):
    """The list must not be used. The previous cache is left untouched."""


class IdentitiesUnavailable(Exception):
    """No verified list could be had: unreachable and nothing cached."""


def _age_days(as_of: str, now: dt.datetime) -> int:
    return (now.astimezone(dt.timezone.utc).date() - dt.date.fromisoformat(as_of[:10])).days


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def _check_rows(doc: dict) -> None:
    for r in doc["rows"]:
        if not isinstance(r, dict) or not _CVE.match(str(r.get("cve", ""))) or not isinstance(r.get("pids"), list):
            raise IdentitiesRefused("the list has a malformed row")
        bad = _FORBIDDEN & set(r)
        if bad:
            raise IdentitiesRefused(f"a row carries {', '.join(sorted(bad))}, which this list must never hold: not using it")
        if not all(isinstance(p, str) and _PID.match(p) for p in r["pids"]):
            raise IdentitiesRefused(f"{r['cve']} has a malformed package id")
        c = r.get("component")
        if c is not None and not (isinstance(c, dict) and isinstance(c.get("role"), str) and isinstance(c.get("binaries"), list)):
            raise IdentitiesRefused(f"{r['cve']} has a malformed component")
    for a in doc.get("aliases") or []:
        if not (isinstance(a, dict) and _PID.match(str(a.get("from", ""))) and _PID.match(str(a.get("to", "")))):
            raise IdentitiesRefused("the list has a malformed alias")


def verify_document(raw: bytes, signature_b64: str, key_id: str, expected_sha256: str | None = None) -> dict:
    """The parsed list when `raw` carries a valid signature by a pinned key and passes the schema checks; IdentitiesRefused otherwise."""
    if len(raw) > MAX_BYTES:
        raise IdentitiesRefused("the list is larger than the limit; refusing it")
    if expected_sha256 and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise IdentitiesRefused("the list does not match its manifest (a damaged or partial download)")
    if not signature_b64:
        raise IdentitiesRefused("the list came without a signature; an unsigned list is never used")
    pub = PINNED_KEYS.get(key_id)
    if pub is None:
        raise IdentitiesRefused(f"the list is signed with key {key_id!r}, which this lattice-scan does not know: upgrade lattice-scan")
    try:
        sig = base64.b64decode(signature_b64, validate=True)
    except ValueError:
        raise IdentitiesRefused("the list signature is not valid base64")
    if not ed25519.verify(bytes.fromhex(pub), raw, sig):
        raise IdentitiesRefused("the list signature does not verify: not using it")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise IdentitiesRefused("the signed list is not JSON")
    schema = str(doc.get("schema", "")) if isinstance(doc, dict) else ""
    if not (schema == SCHEMA or schema.startswith(SCHEMA + ".")):      # a later minor only adds fields; a new major is a new file
        raise IdentitiesRefused(f"the list has schema {schema[:40]!r}; this lattice-scan reads {SCHEMA}: upgrade lattice-scan")
    if not isinstance(doc.get("generation"), int) or not isinstance(doc.get("rows"), list) or not isinstance(doc.get("exploitedAsOf"), str):
        raise IdentitiesRefused("the signed list is missing generation, rows or exploitedAsOf")
    _check_rows(doc)
    return doc


def _result(doc: dict, source: str, now: dt.datetime, note: str = "") -> dict:
    age = _age_days(doc["exploitedAsOf"], now)
    return {"doc": doc, "generation": doc["generation"], "exploitedAsOf": doc["exploitedAsOf"], "ageDays": age, "stale": age > MAX_AGE_DAYS,
            "kevRows": doc.get("kevRows"), "source": source, "note": note}


def _read_cache(folder: Path):
    """The cached list re-verified (a cache file edited on disk is refused like any other), or None."""
    try:
        state = json.loads((folder / STATE).read_text())
        return verify_document((folder / CACHE).read_bytes(), state["signature"], state["keyId"], state.get("sha256")), state
    except (OSError, ValueError, KeyError, IdentitiesRefused):
        return None


def load(folder: Path, get, now: dt.datetime | None = None, *, force: bool = False, require_fresh: bool = False) -> dict:
    """The list to use. `get(url, limit)` returns bytes or raises OSError, so this runs without a network in tests."""
    now = now or dt.datetime.now(dt.timezone.utc)
    cached = _read_cache(folder)
    last_gen = -1
    try:
        last_gen = int(json.loads((folder / STATE).read_text()).get("generation", -1))
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    if cached is not None:
        last_gen = max(last_gen, cached[0]["generation"])
        fetched = dt.datetime.fromtimestamp(cached[1].get("fetchedAt", 0), dt.timezone.utc)
        if not force and (now - fetched) < dt.timedelta(hours=REFRESH_AFTER_HOURS):
            return _finish(_result(cached[0], "cache", now), require_fresh)
    try:
        manifest = json.loads(get(MANIFEST_URL, 64 * 1024).decode("utf-8"))
        if not isinstance(manifest, dict) or not isinstance(manifest.get("generation"), int) or not manifest.get("sha256"):
            raise IdentitiesRefused("the manifest is not valid")
        if cached is not None and manifest["generation"] == cached[0]["generation"] and manifest.get("sha256") == cached[1].get("sha256"):
            _write(folder / STATE, json.dumps({**cached[1], "fetchedAt": now.timestamp()}).encode())   # unchanged: only the clock moves
            return _finish(_result(cached[0], "cache (unchanged)", now), require_fresh)
        raw = get(LIST_URL, MAX_BYTES + 1)
        doc = verify_document(raw, str(manifest.get("signature") or ""), str(manifest.get("keyId", "")), manifest["sha256"])
    except IdentitiesRefused:
        raise
    except (OSError, ValueError) as err:
        if cached is not None:
            return _finish(_result(cached[0], "cache", now, f"could not reach namiq.io ({str(err)[:80]}); using generation {cached[0]['generation']}"), require_fresh)
        bundled = _bundled()
        if bundled is not None and bundled["generation"] >= last_gen:
            res = _result(bundled, "bundled", now)
            res["note"] = f"could not reach namiq.io ({str(err)[:80]}); using the copy bundled in this release, {res['ageDays']} days old"
            return _finish(res, require_fresh)
        raise IdentitiesUnavailable(f"could not read the identity list ({str(err)[:80]}) and there is no verified copy")
    if doc["generation"] < last_gen:
        raise IdentitiesRefused(f"the list is generation {doc['generation']}, older than the {last_gen} already accepted: refusing a rolled-back copy")
    _write(folder / CACHE, raw)
    _write(folder / STATE, json.dumps({"generation": doc["generation"], "sha256": manifest["sha256"], "signature": manifest["signature"],
                                       "keyId": manifest.get("keyId", ""), "fetchedAt": now.timestamp()}).encode())
    return _finish(_result(doc, "network", now), require_fresh)


def _bundled():
    """The copy shipped in this release (identities_bundled.py), verified exactly like a download; None when absent or when it does not verify."""
    import importlib, zlib
    try:
        b = importlib.import_module("lattice_scan.identities_bundled")
        m = json.loads(b.MANIFEST)
        return verify_document(zlib.decompress(base64.b64decode("".join(b.LIST))), m.get("signature", ""), m.get("keyId", ""), m.get("sha256"))
    except (ImportError, ValueError, KeyError, AttributeError, zlib.error, IdentitiesRefused):
        return None


def _finish(res: dict, require_fresh: bool) -> dict:
    if res["stale"] and require_fresh:
        raise IdentitiesRefused(f"the identity list is {res['ageDays']} days old (limit {MAX_AGE_DAYS}); this run needs a current one")
    return res


def join_inputs(doc: dict) -> tuple:
    """(rows, aliases) in the shapes lattice_identity.join() takes."""
    rows = []
    for r in doc["rows"]:
        c = r.get("component")
        rows.append(Row(r["cve"], tuple(r["pids"]), Component(c["role"], tuple(c["binaries"])) if c else None, ",".join(r.get("origin") or [])))
    return rows, {a["from"]: a["to"] for a in doc.get("aliases") or []}
