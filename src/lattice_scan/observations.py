# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""The observation-to-technique table, from namiq.io: which ATT&CK techniques a posture observation relates to.

One source of truth: the table is published and signed beside the exploited index (same pinned key) and is downloaded here, never copied into the client.
Only a plain GET of public files is made; no host data goes with it. Checked on the raw bytes: size, sha256 against the manifest, key, signature, then parsed."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from lattice_scan import ed25519, exploited

TABLE_URL = "https://namiq.io/lattice/observations.json"
MANIFEST_URL = "https://namiq.io/lattice/observations.manifest.json"
SCHEMA = "lattice-observations/1"
MAX_BYTES = 256 * 1024
CACHE = "observations.json"
STATE = "observations.state.json"


class TableRefused(Exception):
    """The table must not be used (bad signature, unknown key, damaged, rolled back)."""


def verify(raw: bytes, signature_b64: str, key_id: str, sha256: str) -> dict:
    if len(raw) > MAX_BYTES:
        raise TableRefused("the observation table is larger than the limit")
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise TableRefused("the observation table does not match its manifest")
    pub = exploited.PINNED_KEYS.get(key_id)
    if pub is None:
        raise TableRefused(f"the table is signed with key {key_id!r}, which this lattice-scan does not know: upgrade lattice-scan")
    try:
        sig = base64.b64decode(signature_b64, validate=True)
    except ValueError:
        raise TableRefused("the table signature is not valid base64")
    if not ed25519.verify(bytes.fromhex(pub), raw, sig):
        raise TableRefused("the table signature does not verify: not using it")
    try:
        doc = json.loads(raw)
    except ValueError:
        raise TableRefused("the signed table is not JSON")
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(doc.get("generation"), int) or not isinstance(doc.get("observations"), list):
        raise TableRefused("the signed table has the wrong schema")
    return doc


def load(folder: Path, get) -> dict:
    """{'generation', 'map': {code: [technique ids]}, 'source'}. Falls back to the verified cached copy when namiq.io cannot be reached; TableRefused on a bad one."""
    last = -1
    try:
        last = int(json.loads((folder / STATE).read_text()).get("generation", -1))
    except (OSError, ValueError, TypeError):
        pass
    try:
        m = json.loads(get(MANIFEST_URL, 64 * 1024).decode("utf-8"))
        raw = get(TABLE_URL, MAX_BYTES + 1)
        doc = verify(raw, str(m.get("signature", "")), str(m.get("keyId", "")), str(m.get("sha256", "")))
        if doc["generation"] < last:
            raise TableRefused(f"the table is generation {doc['generation']}, older than the {last} already accepted")
        exploited._write(folder / CACHE, raw)
        exploited._write(folder / STATE, json.dumps({"generation": doc["generation"], "sha256": m["sha256"], "signature": m["signature"], "keyId": m.get("keyId", "")}).encode())
        source = "network"
    except TableRefused:
        raise
    except (OSError, ValueError, AttributeError) as err:
        try:
            st = json.loads((folder / STATE).read_text())
            doc = verify((folder / CACHE).read_bytes(), st["signature"], st["keyId"], st["sha256"])
            source = f"cache (namiq.io unreachable: {str(err)[:60]})"
        except (OSError, ValueError, KeyError, TableRefused):
            raise OSError(f"could not read the observation table ({str(err)[:80]}) and there is no usable copy")
    return {"generation": doc["generation"], "map": {o["code"]: list(o.get("techniques") or []) for o in doc["observations"] if isinstance(o, dict) and "code" in o}, "source": source}
