"""Rewrites src/lattice_scan/VENDORED.sha256 after lattice_version.py changes. A consumer that copies the module (the index build, graph-mcp, the report
service) copies this file's hash too and fails its CI when its copy differs: `sha256sum lattice_version.py` against the first field of VENDORED.sha256."""
import hashlib
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "lattice_scan"
digest = hashlib.sha256((SRC / "lattice_version.py").read_bytes()).hexdigest()
(SRC / "VENDORED.sha256").write_text(f"{digest}  lattice_version.py\n")
print(digest)
