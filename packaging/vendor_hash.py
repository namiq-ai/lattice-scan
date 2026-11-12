"""Rewrites src/lattice_scan/VENDORED.sha256 after lattice_version.py or lattice_identity.py changes. A consumer that copies a module (the index build,
graph-mcp, the report service) copies this file's hash too and fails its CI when its copy differs: `sha256sum lattice_version.py` against the first field
of the line naming it. lattice_version.py stays on the first line, because older consumers read only the first field of the file."""
import hashlib
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "lattice_scan"
lines = []
for name in ("lattice_version.py", "lattice_identity.py"):
    digest = hashlib.sha256((SRC / name).read_bytes()).hexdigest()
    lines.append(f"{digest}  {name}\n")
    print(digest, name)
(SRC / "VENDORED.sha256").write_text("".join(lines))
