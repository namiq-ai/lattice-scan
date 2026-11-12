#!/usr/bin/env python3
"""Refresh the identity list bundled in the release (src/lattice_scan/identities_bundled.py) from namiq.io. Run before a release; local only.

The bundled copy is the first-run fallback when namiq.io cannot be reached and nothing is cached. It holds the exact signed bytes and the manifest, and the
client verifies it at load time exactly like a downloaded copy (pinned key, signature, schema, no version data) and prints its age; a bad bundled copy is
refused, never trusted for having shipped. This script refuses to write a copy that does not verify.

  python3 packaging/bundle_identities.py                 fetch https://namiq.io/lattice/identities.json and its manifest
  python3 packaging/bundle_identities.py LIST MANIFEST   use two local files instead
"""
import base64, json, sys, urllib.request, zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from lattice_scan import identities  # noqa: E402

OUT = ROOT / "src" / "lattice_scan" / "identities_bundled.py"


def fetch(url: str, limit: int) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "lattice-scan-release (test)"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read(limit + 1)


def main() -> int:
    if len(sys.argv) == 3:
        raw, manifest = Path(sys.argv[1]).read_bytes(), Path(sys.argv[2]).read_bytes()
    else:
        manifest = fetch(identities.MANIFEST_URL, 64 * 1024)
        raw = fetch(identities.LIST_URL, identities.MAX_BYTES)
    m = json.loads(manifest)
    doc = identities.verify_document(raw, m.get("signature", ""), m.get("keyId", ""), m.get("sha256"))
    body = base64.b64encode(zlib.compress(raw, 9)).decode()
    lines = [body[i:i + 120] for i in range(0, len(body), 120)]
    OUT.write_text(
        "# SPDX-License-Identifier: Apache-2.0\n# Copyright 2026 NamiQ LLC\n"
        '"""The signed identity list as it stood when this release was built (packaging/bundle_identities.py writes this file; do not edit it).\n\n'
        "Used only when namiq.io cannot be reached and nothing is cached, and verified at load time like a downloaded copy. MANIFEST is the manifest as\n"
        'served; LIST is the signed bytes, zlib-compressed and base64-encoded."""\n'
        f"MANIFEST = {json.dumps({k: m[k] for k in ('schema', 'generation', 'exploitedAsOf', 'sha256', 'keyId', 'signature')}, sort_keys=True)!r}\n"
        "LIST = (\n" + "".join(f'    "{l}"\n' for l in lines) + ")\n")
    print(f"bundled generation {doc['generation']}, CISA as of {doc['exploitedAsOf']}, {len(doc['rows'])} rows, {len(raw)} bytes -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
